#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""forensics-check.py -- 纯标准库取证对象初检（镜像/pcap/目录/应用包）。

用法:
    python forensics-check.py --file mem.raw
    python forensics-check.py --file capture.pcap --json
    python forensics-check.py --file disk.img --no-hash
    python forensics-check.py --file ./case-evidence --out out/

输出：类型识别、时间线字段、可提取对象清单、证据完整性提示。
只做只读识别，不挂载、不运行、不修改原件；仅用于自有或授权证据。
"""

from __future__ import annotations

import argparse
import datetime as _dt
import gzip
import hashlib
import json
import os
import re
import sqlite3
import struct
import sys
import zipfile

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000, "pcap"),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000, "pcap"),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000, "pcap"),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000, "pcap"),
}
LINKTYPE_NAMES = {0: "NULL/LOOP", 1: "EN10MB/Ethernet", 101: "RAW/IP",
                   113: "LINUX_SLL", 228: "IPV4", 229: "IPV6", 276: "LINUX_SLL2"}
MAX_HASH = 256 * 1024 * 1024
MAX_ITEMS = 300


class CheckError(Exception):
    pass


def iso(ts):
    if ts is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(float(ts), _dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def sha256_file(path, limit=None):
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            total += len(chunk)
            if limit and total >= limit:
                break
    return h.hexdigest() + ("" if not limit or total < limit else " (partial)")


def read_head(path, n=4096):
    with open(path, "rb") as fh:
        return fh.read(n)


def identify(path):
    if os.path.isdir(path):
        return {"kind": "directory", "format": "directory", "confidence": "observed"}
    if not os.path.isfile(path):
        raise CheckError("路径不存在")
    head = read_head(path, 8192)
    if not head:
        return {"kind": "empty", "format": "empty", "confidence": "observed"}
    if head[:4] in PCAP_MAGICS:
        return {"kind": "pcap", "format": "pcap", "confidence": "observed"}
    if head[:4] == b"\x0a\x0d\x0d\x0a":
        return {"kind": "pcap", "format": "pcapng", "confidence": "observed"}
    if head[:4] == b"PK\x03\x04":
        ext = os.path.splitext(path)[1].lower()
        return {"kind": "zip", "format": {".ipa": "ipa", ".vsix": "vsix", ".crx": "crx",
                                           ".jar": "jar", ".apk": "apk"}.get(ext, "zip"),
                "confidence": "observed"}
    if head.startswith(b"Cr24"):
        return {"kind": "zip", "format": "crx", "confidence": "observed"}
    if head[:16] == b"SQLite format 3\x00":
        return {"kind": "sqlite", "format": "sqlite", "confidence": "observed"}
    if head[:4] == b"\x04\x00\x00\x00":
        return {"kind": "asar", "format": "asar", "confidence": "observed"}
    if head[:4] == b"MZ":
        return {"kind": "pe", "format": "PE", "confidence": "observed"}
    if head[:4] == b"\x7fELF":
        return {"kind": "elf", "format": "ELF", "confidence": "observed"}
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                    b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return {"kind": "macho", "format": "Mach-O/Fat", "confidence": "observed"}
    if head[:2] == b"\x1f\x8b":
        return {"kind": "archive", "format": "gzip", "confidence": "observed"}
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return {"kind": "archive", "format": "7z", "confidence": "observed"}
    if head[:4] == b"Rar!":
        return {"kind": "archive", "format": "rar", "confidence": "observed"}
    if len(head) >= 1082 and head[1080:1082] == b"\x53\xef":
        return {"kind": "disk", "format": "ext2/3/4", "confidence": "observed"}
    if head[3:11] == b"NTFS    ":
        return {"kind": "disk", "format": "NTFS", "confidence": "observed"}
    if len(head) >= 512 and head[510:512] == b"\x55\xaa":
        return {"kind": "disk", "format": "MBR disk image", "confidence": "inferred"}
    if len(head) >= 520 and head[512:520] == b"EFI PART":
        return {"kind": "disk", "format": "GPT disk image", "confidence": "observed"}
    ext = os.path.splitext(path)[1].lower()
    if ext in (".raw", ".mem", ".dmp", ".vmem", ".core", ".hiberfil"):
        return {"kind": "memory", "format": "raw/crash memory", "confidence": "inferred"}
    if ext in (".img", ".dd", ".e01", ".vhd", ".vhdx", ".qcow2"):
        return {"kind": "disk", "format": ext.lstrip("."), "confidence": "inferred"}
    return {"kind": "data", "format": "unknown", "confidence": "unverified"}


def pcap_meta(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw[:4] == b"\x0a\x0d\x0d\x0a":
        return _pcapng_meta(raw)
    endian, frac, _ = PCAP_MAGICS[raw[:4]]
    if len(raw) < 24:
        raise CheckError("pcap 全局头不足 24 字节")
    _, _, _, _, _, _, network = struct.unpack(endian + "IHHIIII", raw[:24])
    pos = 24
    count = 0
    first = last = None
    truncated = False
    while pos + 16 <= len(raw):
        ts_sec, ts_frac, incl, _orig = struct.unpack_from(endian + "IIII", raw, pos)
        if pos + 16 + incl > len(raw):
            truncated = True
            break
        ts = ts_sec + ts_frac / frac
        first = ts if first is None else min(first, ts)
        last = ts if last is None else max(last, ts)
        count += 1
        pos += 16 + incl
    return {"format": "pcap", "packet_count": count, "first_ts": first, "last_ts": last,
            "linktype": network, "linktype_name": LINKTYPE_NAMES.get(network, "unknown"),
            "truncated": truncated}


def _pcapng_meta(raw):
    pos = 0
    endian = "little"
    ifaces = []
    count = 0
    first = last = None
    truncated = False
    while pos + 12 <= len(raw):
        btype = int.from_bytes(raw[pos:pos + 4], "little")
        if btype == 0x0A0D0D0A:
            bom = raw[pos + 8:pos + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "little"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = "big"
        blen = int.from_bytes(raw[pos + 4:pos + 8], endian)
        if blen < 12 or pos + blen > len(raw):
            truncated = True
            break
        body = raw[pos + 8:pos + blen - 4]
        if btype == 1 and len(body) >= 8:
            ifaces.append(int.from_bytes(body[:2], endian))
        elif btype == 6 and len(body) >= 20:
            ts_hi = int.from_bytes(body[4:8], endian)
            ts_lo = int.from_bytes(body[8:12], endian)
            ts = ((ts_hi << 32) | ts_lo) / 1e6
            first = ts if first is None else min(first, ts)
            last = ts if last is None else max(last, ts)
            count += 1
        pos += blen
    return {"format": "pcapng", "packet_count": count, "first_ts": first, "last_ts": last,
            "linktype": ifaces[0] if ifaces else None,
            "linktype_name": LINKTYPE_NAMES.get(ifaces[0], "unknown") if ifaces else "unknown",
            "truncated": truncated}


def zip_meta(path, max_items):
    raw = open(path, "rb").read()
    if raw.startswith(b"Cr24"):
        i = raw.find(b"PK\x03\x04")
        if i < 0:
            raise CheckError("CRX 头后无 PK")
        raw = raw[i:]
    zf = zipfile.ZipFile(__import__("io").BytesIO(raw))
    names = zf.namelist()
    interesting = [n for n in names if re.search(
        r"(^|/)(manifest\.json|Info\.plist|package\.json|plugin\.xml|keychain-2\.db|app\.db|"
        r"[^/]+\.(sqlite|db|plist|mobileprovision|node|jsc|dll|so|dylib|framework|bundle|assets))$",
        n, re.I)]
    latest = None
    for info in zf.infolist()[:max_items]:
        try:
            dt = _dt.datetime(*info.date_time, tzinfo=_dt.timezone.utc)
            latest = dt if latest is None else max(latest, dt)
        except Exception:
            pass
    return {"format": "zip", "file_count": len(names), "top_level": sorted(
        {n.split("/", 1)[0] for n in names})[:40], "interesting_files": interesting[:max_items],
        "latest_entry_utc": latest.isoformat().replace("+00:00", "Z") if latest else None}


def sqlite_meta(path):
    try:
        con = sqlite3.connect("file:%s?mode=ro&immutable=1" % path.replace("\\", "/"), uri=True)
        try:
            tables = [r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY name").fetchall()]
            integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            con.close()
        return {"format": "sqlite", "tables": tables[:120], "table_count": len(tables),
                "integrity": integrity,
                "sidecars": [s for s in ("-wal", "-shm", "-journal") if os.path.exists(path + s)]}
    except Exception as exc:
        return {"format": "sqlite", "error": str(exc)}


def find_strings(path, needles, limit=32 * 1024 * 1024):
    found = {}
    with open(path, "rb") as fh:
        data = fh.read(limit)
    for n in needles:
        if n in data:
            found[n.decode("latin-1")] = data.find(n)
    return found


def dir_meta(path, max_items, do_hash):
    rows = []
    total = 0
    count = 0
    latest = None
    earliest = None
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, path).replace("\\", "/")
            try:
                st = os.stat(full)
            except OSError:
                continue
            count += 1
            total += st.st_size
            latest = st.st_mtime if latest is None else max(latest, st.st_mtime)
            earliest = st.st_mtime if earliest is None else min(earliest, st.st_mtime)
            if len(rows) < max_items:
                row = {"path": rel, "size": st.st_size, "mtime_utc": iso(st.st_mtime)}
                if do_hash and st.st_size <= MAX_HASH:
                    try:
                        row["sha256"] = sha256_file(full)
                    except OSError:
                        row["sha256"] = None
                rows.append(row)
    return {"format": "directory", "file_count": count, "total_size": total,
            "first_mtime_utc": iso(earliest), "last_mtime_utc": iso(latest),
            "files": rows, "truncated": count > len(rows)}


def extractables(kind, fmt, path):
    common = [
        "原件副本与 SHA256（封存）",
        "采集记录：人/时间/工具/授权范围",
        "统一 UTC 时间线（保留原时区与时钟偏差）",
    ]
    table = {
        "memory": ["进程树/命令行/PID/PPID", "网络连接与监听端口", "已加载模块与未签名 DLL",
                   "可执行私有内存页/injected pages", "注册表 hive/服务/持久化项",
                   "明文凭据线索（脱敏后）", "崩溃转储与 strings/carve 结果"],
        "pcap": ["TCP/UDP 会话五元组与字节数", "HTTP 请求/响应与导出对象",
                 "DNS/TLS SNI", "凭据/Token 线索（脱敏）", "明文片段与文件 carve",
                 "时间范围与丢包/截断说明"],
        "disk": ["分区表与文件系统类型", "目录树/inode/已删除文件", "mactime 时间线",
                 "注册表/事件日志/浏览器/邮件", "未分配空间 carve", "哈希与镜像完整性"],
        "zip": ["manifest/Info.plist/package.json/plugin.xml", "权限与签名/entitlements",
                "keychain-2.db/app.db 等数据文件", "框架/插件/资源清单",
                "内嵌二进制（Mach-O/DEX/PE）", "远程 URL 与配置"],
        "sqlite": ["表结构/行数", "WAL/SHM/journal 残留", "已删除记录恢复",
                   "时间字段与写入进程", "敏感字段（脱敏）"],
        "macho": ["架构/LC_UUID/加密信息 cryptid", "依赖库与 rpath", "符号/字符串",
                  "entitlements/签名 Team ID", "与数据文件/网络端点的对应"],
        "pe": ["节区/熵/导入导出", "资源与 overlay", "PDB/版本信息", "字符串与配置"],
        "elf": ["节区/架构/动态依赖", "导入导出符号", "编译路径/字符串", "配置与证书"],
        "asar": ["package.json/main/preload", "IPC channel 与原生模块", "asar 完整性/签名",
                 "app.asar.unpacked 内容"],
        "data": ["file/strings/entropy", "文件 carve", "哈希与来源说明"],
    }.get(kind, [])
    return common + table


def timeline_fields(ident, meta, st):
    if ident["kind"] == "pcap" and meta:
        start, end = meta.get("first_ts"), meta.get("last_ts")
        return {"start_utc": iso(start), "end_utc": iso(end),
                "basis": "pcap packet timestamps (epoch)", "timezone": "UTC",
                "clock_skew": "unknown; align with host logs/NTP",
                "precision": "microsecond/nanosecond per file magic"}
    if ident["kind"] == "directory" and meta:
        return {"start_utc": meta.get("first_mtime_utc"), "end_utc": meta.get("last_mtime_utc"),
                "basis": "filesystem mtime (not content time)", "timezone": "UTC",
                "clock_skew": "unknown; compare with acquisition record",
                "precision": "filesystem dependent"}
    if ident["kind"] == "zip" and meta:
        return {"start_utc": None, "end_utc": meta.get("latest_entry_utc"),
                "basis": "zip entry timestamps (often local time)", "timezone": "unknown",
                "clock_skew": "unknown; ZIP timestamps are not reliable evidence",
                "precision": "2 seconds (DOS time)"}
    return {"start_utc": iso(st.st_mtime), "end_utc": iso(st.st_mtime),
            "basis": "filesystem mtime only; content time requires acquisition record",
            "timezone": "UTC display of local mtime", "clock_skew": "unknown",
            "precision": "filesystem dependent"}


def integrity(path, ident, meta, do_hash):
    st = os.stat(path)
    warnings = []
    if not os.access(path, os.R_OK):
        warnings.append("不可读：检查权限/介质")
    if os.access(path, os.W_OK):
        warnings.append("文件可写：分析前应设为只读或使用副本")
    if ident["kind"] == "pcap" and meta and meta.get("truncated"):
        warnings.append("pcap 包数据截断：结论可能缺会话")
    if ident["kind"] == "zip" and meta and meta.get("file_count", 0) == 0:
        warnings.append("zip 为空或不可读")
    if ident["kind"] == "memory" and st.st_size < 64 * 1024 * 1024:
        warnings.append("内存镜像较小：可能不完整或仅崩溃转储")
    if ident["kind"] == "disk" and st.st_size < 1024 * 1024:
        warnings.append("磁盘镜像较小：确认是否为分区/引导扇区片段")
    if ident["kind"] == "data":
        warnings.append("类型未确认：不要直接挂载/执行")
    return {
        "sha256": sha256_file(path) if do_hash and st.st_size <= MAX_HASH else None,
        "size": st.st_size,
        "mtime_utc": iso(st.st_mtime),
        "readonly": not os.access(path, os.W_OK),
        "warnings": warnings,
        "recommendation": "原件只读封存；在副本上分析；每次导出记录输入/输出哈希",
    }


def analyze(path, do_hash=True, max_items=MAX_ITEMS):
    ident = identify(path)
    st = os.stat(path)
    meta = {}
    if ident["kind"] == "pcap":
        meta = pcap_meta(path)
    elif ident["kind"] == "zip":
        meta = zip_meta(path, max_items)
    elif ident["kind"] == "sqlite":
        meta = sqlite_meta(path)
    elif ident["kind"] == "directory":
        meta = dir_meta(path, max_items, do_hash)
    elif ident["kind"] == "memory":
        meta = {"hints": find_strings(path, [b"KDBG", b"Volatility", b"Windows", b"Linux version", b"Darwin Kernel"])}
    elif ident["kind"] == "asar":
        head = read_head(path, 64)
        meta = {"header_hex": head[:16].hex(), "asar_header_size": int.from_bytes(head[4:8], "little") if len(head) >= 8 else None}

    timeline = timeline_fields(ident, meta, st)
    result = {
        "ok": True, "path": os.path.abspath(path), "type": ident["kind"],
        "format": ident["format"], "confidence": ident["confidence"],
        "meta": meta, "timeline": timeline,
        "extractables": extractables(ident["kind"], ident["format"], path),
        "integrity": integrity(path, ident, meta, do_hash),
        "conclusion": "类型与可提取对象已列出；四要素与证据链需结合采集记录人工闭合",
    }
    if ident["kind"] == "data":
        result["conclusion"] = "类型未确认：先 file/strings/entropy，再决定是否进入内存/磁盘/包分析"
    if ident["kind"] == "memory" and not meta.get("hints"):
        result["conclusion"] = "未命中常见内存特征：可能是加密/压缩/不完整镜像，先取采集记录与符号"
    return result


def print_human(r):
    print("== forensics check ==")
    print("path      : %s" % r["path"])
    print("type      : %s / %s (%s)" % (r["type"], r["format"], r["confidence"]))
    m = r.get("meta") or {}
    if r["type"] == "pcap":
        print("pcap      : packets=%s linktype=%s(%s) truncated=%s" % (
            m.get("packet_count"), m.get("linktype"), m.get("linktype_name"), m.get("truncated")))
    elif r["type"] == "zip":
        print("zip       : files=%s latest=%s" % (m.get("file_count"), m.get("latest_entry_utc")))
        print("top       : %s" % ", ".join(m.get("top_level") or []))
        print("interesting: %s" % ", ".join((m.get("interesting_files") or [])[:20]))
    elif r["type"] == "sqlite":
        print("sqlite    : integrity=%s tables=%s" % (m.get("integrity"), ", ".join((m.get("tables") or [])[:20])))
    elif r["type"] == "directory":
        print("directory : files=%s size=%s first=%s last=%s" % (
            m.get("file_count"), m.get("total_size"), m.get("first_mtime_utc"), m.get("last_mtime_utc")))
        print("files     : %s" % ", ".join(x["path"] for x in (m.get("files") or [])[:20]))
    elif r["type"] == "memory":
        print("memory    : hints=%s" % json.dumps(m.get("hints") or {}, ensure_ascii=False))
    print("\n-- timeline --")
    for k, v in (r.get("timeline") or {}).items():
        print("%-12s: %s" % (k, v))
    print("\n-- extractables --")
    for x in r.get("extractables") or []:
        print("  - %s" % x)
    print("\n-- integrity --")
    for k, v in (r.get("integrity") or {}).items():
        print("%-14s: %s" % (k, v))
    print("\nconclusion: %s" % r.get("conclusion"))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="纯标准库取证初检：镜像/pcap/目录/应用包的类型、时间线、可提取对象与完整性提示")
    ap.add_argument("--file", "-f", required=True, help="镜像、pcap、目录或应用包路径")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--out", help="写出 forensics-check.json 的目录")
    ap.add_argument("--no-hash", action="store_true", help="跳过 SHA256（大镜像快速初检）")
    ap.add_argument("--max-items", type=int, default=MAX_ITEMS, help="目录/zip 列出的最大条目数")
    args = ap.parse_args(argv)
    if not os.path.exists(args.file):
        err = {"ok": False, "error": "not_found", "file": args.file,
               "hint": "确认路径；目录/文件均可，原件请只读"}
        print(json.dumps(err, ensure_ascii=False) if args.json else "[FAIL] %s" % err["hint"])
        return 2
    try:
        result = analyze(args.file, do_hash=not args.no_hash, max_items=max(1, args.max_items))
    except (CheckError, OSError, zipfile.BadZipFile) as exc:
        err = {"ok": False, "error": "check_failed", "file": args.file, "detail": str(exc),
               "hint": "先 file/xxd 确认类型；损坏镜像/包用副本重试，不要改原件"}
        print(json.dumps(err, ensure_ascii=False) if args.json else "[FAIL] %s" % exc)
        return 2
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        out = os.path.join(args.out, "forensics-check.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
        print("wrote: %s" % out)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_human(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
