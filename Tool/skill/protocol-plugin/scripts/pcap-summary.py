#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pcap-summary.py -- 纯标准库 pcap/pcapng 会话聚合、字节流导出与明文片段提取。

用途
----
协议复刻的第一步是「谁和谁、说了什么、每个方向有多少字节」。本脚本不依赖 tshark：
自行解析 pcap 全局头/包记录与 pcapng 的 SHB/IDB/EPB/SPB，按**方向性五元组**聚合，
导出每个会话的字节流（供分帧脚本续接），并提取可疑明文片段。

用法
----
    python pcap-summary.py --file capture.pcap
    python pcap-summary.py --file capture.pcapng --json --out out/
    python pcap-summary.py --file capture.pcap --extract streams/
    python pcap-summary.py --file capture.pcap --tshark-check
    python pcap-summary.py --self-test

输入：本地 pcap / pcapng（EN10MB / RAW-IP / LINUX_SLL / LINUX_SLL2 / NULL）。
输出：人类可读摘要或 JSON；`--out` 写 pcap-summary.json + snippets.txt；
      `--extract` 写 `<session>.bin` 双向字节流 + frames.jsonl（逐包 hex）。
退出码：0 成功（含 tshark 缺失的降级）；2 输入/解析失败（结构化 JSON `ok:false`）。

边界：只做包级解析与方向性聚合，不做 TCP 重传去重/乱序重排；需要严格重组时用
tshark `-z follow,tcp,raw`。仅用于自有或明确授权的流量，导出物按敏感数据处置。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
from collections import OrderedDict

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000, "pcap"),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000, "pcap"),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000, "pcap"),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000, "pcap"),
}

LINKTYPE_NAMES = {
    0: "NULL/LOOP",
    1: "EN10MB/Ethernet",
    101: "RAW/IP",
    105: "IEEE802_11",
    113: "LINUX_SLL",
    228: "IPV4",
    229: "IPV6",
    276: "LINUX_SLL2",
}

KEYWORDS = (
    b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"HTTP/",
    b"Host:", b"Authorization", b"Bearer ", b"Cookie:", b"Set-Cookie",
    b"password", b"passwd", b"token", b"secret", b"api_key", b"apikey",
    b"admin", b"login", b"select ", b"insert ", b"update ",
    b"<html", b"<?xml", b"{\"", b"ws://", b"wss://", b"http://", b"https://",
)
TEXT_RE = re.compile(rb"[\x20-\x7e]{4,}")
MAX_HEX = 4096


class PcapError(Exception):
    pass


def _u16(buf, off, endian):
    return struct.unpack_from(endian + "H", buf, off)[0]


def _u32(buf, off, endian):
    return struct.unpack_from(endian + "I", buf, off)[0]


def iter_pcap(path):
    """Yield (ts_float, linktype, raw_packet). Raises PcapError."""
    with open(path, "rb") as fh:
        head = fh.read(4)
        if not head:
            raise PcapError("空文件")
        if head == b"\x0a\x0d\x0d\x0a":
            fh.seek(0)
            yield from _iter_pcapng(fh)
            return
        if head not in PCAP_MAGICS:
            raise PcapError("不是 pcap/pcapng（magic=%s）" % head.hex())
        endian, frac, _kind = PCAP_MAGICS[head]
        rest = fh.read(20)
        if len(rest) < 20:
            raise PcapError("pcap 全局头不足 24 字节")
        _m, _a, _b, _tz, _sig, _snap, network = struct.unpack(
            endian + "IHHiIII", head + rest)
        while True:
            rec = fh.read(16)
            if not rec:
                break
            if len(rec) < 16:
                raise PcapError("包记录头被截断")
            ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", rec)
            data = fh.read(incl)
            if len(data) < incl:
                raise PcapError("包数据被截断（需 %d，得 %d）" % (incl, len(data)))
            yield ts_sec + ts_frac / frac, network, data


def _iter_pcapng(fh):
    raw = fh.read()
    pos = 0
    endian = "<"
    interfaces = []
    while pos + 12 <= len(raw):
        btype = _u32(raw, pos, endian)
        if btype == 0x0A0D0D0A:
            bom = raw[pos + 8:pos + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise PcapError("pcapng SHB BOM 非法")
        blen = _u32(raw, pos + 4, endian)
        if blen < 12 or pos + blen > len(raw):
            raise PcapError("pcapng 块长度非法（offset=%d, len=%d）" % (pos, blen))
        body = raw[pos + 8:pos + blen - 4]
        if btype == 1:  # IDB
            if len(body) < 8:
                raise PcapError("pcapng IDB 过短")
            linktype = _u16(body, 0, endian)
            # if_tsresol (option 9)：默认 1e-6，值为 10 的负幂次（高位置 1 时为 2 的负幂次）
            exp = 6
            rest = body[8:]
            while len(rest) >= 4:
                code, olen = struct.unpack_from(endian + "HH", rest, 0)
                if code == 0:
                    break
                val = rest[4:4 + olen]
                if code == 9 and val:
                    if val[0] & 0x80:
                        exp = None  # 2 的幂次，少见；退化为原始值
                    else:
                        exp = val[0]
                rest = rest[4 + olen + ((-olen) % 4):]
            interfaces.append((linktype, exp))
        elif btype == 6:  # EPB
            if len(body) < 20:
                raise PcapError("pcapng EPB 过短")
            iface, ts_hi, ts_lo, cap, _orig = struct.unpack_from(
                endian + "IIIII", body, 0)
            linktype, exp = interfaces[iface] if iface < len(interfaces) else (1, 6)
            raw_ts = (ts_hi << 32) | ts_lo
            ts = raw_ts if exp is None else raw_ts / float(10 ** exp)
            yield ts, linktype, body[20:20 + cap]
        elif btype == 3:  # SPB (no timestamp)
            if len(body) < 4:
                raise PcapError("pcapng SPB 过短")
            lt0 = interfaces[0][0] if interfaces else 1
            yield 0.0, lt0, body[4:]
        pos += blen


def _ipv4(buf):
    if len(buf) < 20:
        return None
    ihl = (buf[0] & 0x0F) * 4
    if ihl < 20 or len(buf) < ihl:
        return None
    total = _u16(buf, 2, "!")
    if total and total < ihl:
        return None
    frag = _u16(buf, 6, "!")
    if frag & 0x1FFF:
        return None  # 非首片，端口不可见
    proto = buf[9]
    src = socket.inet_ntoa(buf[12:16])
    dst = socket.inet_ntoa(buf[16:20])
    payload = buf[ihl:total] if total else buf[ihl:]
    return 4, src, dst, proto, payload


def _ipv6(buf):
    if len(buf) < 40:
        return None
    nxt = buf[6]
    src = socket.inet_ntop(socket.AF_INET6, buf[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, buf[24:40])
    off = 40
    while nxt in (0, 43, 60):
        if len(buf) < off + 2:
            return None
        nxt = buf[off]
        off += (buf[off + 1] + 1) * 8
    if nxt == 44:
        if len(buf) < off + 8:
            return None
        nxt = buf[off]
        off += 8
    if nxt == 51:
        if len(buf) < off + 2:
            return None
        nxt = buf[off]
        off += (buf[off + 1] + 2) * 4
    return 6, src, dst, nxt, buf[off:]


def parse_packet(data, linktype):
    off = 0
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        etype = struct.unpack_from("!H", data, 12)[0]
        off = 14
        while etype in (0x8100, 0x88A8) and len(data) >= off + 4:
            etype = struct.unpack_from("!H", data, off + 2)[0]
            off += 4
        if etype == 0x0800:
            ip = _ipv4(data[off:])
        elif etype == 0x86DD:
            ip = _ipv6(data[off:])
        else:
            return None
    elif linktype == 113:  # LINUX_SLL
        if len(data) < 16:
            return None
        etype = struct.unpack_from("!H", data, 14)[0]
        ip = _ipv4(data[16:]) if etype == 0x0800 else _ipv6(data[16:]) if etype == 0x86DD else None
    elif linktype == 276:  # LINUX_SLL2
        if len(data) < 20:
            return None
        etype = struct.unpack_from("!H", data, 0)[0]
        ip = _ipv4(data[20:]) if etype == 0x0800 else _ipv6(data[20:]) if etype == 0x86DD else None
    elif linktype in (101, 228, 229) or (data and data[0] >> 4 in (4, 6)):
        ip = _ipv4(data) if data[0] >> 4 == 4 else _ipv6(data)
        if ip is None and linktype == 1:
            return None
    elif linktype == 0:  # NULL/LOOP
        if len(data) < 4:
            return None
        fam = struct.unpack_from("<I", data, 0)[0]
        ip = _ipv4(data[4:]) if fam in (2, 24, 28, 30) else _ipv6(data[4:]) if fam in (10, 23, 24) else None
    else:
        return None

    if not ip:
        return None
    ver, src, dst, proto, payload = ip
    if proto == 6:
        if len(payload) < 20:
            return None
        sport, dport, seq, ack, off_flags = struct.unpack_from("!HHIIH", payload, 0)
        doff = (off_flags >> 12) * 4
        if doff < 20 or len(payload) < doff:
            return None
        return {
            "ipver": ver, "proto": "TCP", "src": src, "sport": sport,
            "dst": dst, "dport": dport, "payload": payload[doff:],
            "flags": off_flags & 0x1FF, "seq": seq, "ack": ack,
        }
    if proto == 17:
        if len(payload) < 8:
            return None
        sport, dport, ulen = struct.unpack_from("!HHH", payload, 0)
        body = payload[8:ulen] if ulen >= 8 and ulen <= len(payload) else payload[8:]
        return {
            "ipver": ver, "proto": "UDP", "src": src, "sport": sport,
            "dst": dst, "dport": dport, "payload": body,
            "flags": 0, "seq": 0, "ack": 0,
        }
    return {"ipver": ver, "proto": "IP/%d" % proto, "src": src, "sport": 0,
            "dst": dst, "dport": 0, "payload": payload, "flags": 0, "seq": 0, "ack": 0}


def _snippets(payload, limit=8):
    out = []
    for m in TEXT_RE.finditer(payload):
        chunk = m.group(0)
        if not any(k in chunk for k in KEYWORDS) and not re.search(rb"[A-Za-z]{4,}", chunk):
            continue
        text = chunk.decode("latin-1").strip()
        if len(text) < 4:
            continue
        out.append(text[:180])
        if len(out) >= limit:
            break
    return out


def summarize(path, top=20, min_len=4, extract=None):
    sessions = OrderedDict()
    packet_count = 0
    first_ts = None
    last_ts = None
    linktype = None
    frame_rows = []

    for ts, lt, data in iter_pcap(path):
        packet_count += 1
        linktype = lt if linktype is None else linktype
        if ts and ts > 0:
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
        p = parse_packet(data, lt)
        if not p:
            continue
        key = (p["proto"], p["src"], p["sport"], p["dst"], p["dport"])
        s = sessions.get(key)
        if s is None:
            s = sessions[key] = {
                "proto": p["proto"], "src": p["src"], "sport": p["sport"],
                "dst": p["dst"], "dport": p["dport"], "packets": 0,
                "payload_bytes": 0, "first_ts": ts, "last_ts": ts,
                "flags": set(), "snippets": [], "snippet_total": 0,
                "_blob": bytearray(), "_frames": [],
            }
        s["packets"] += 1
        s["payload_bytes"] += len(p["payload"])
        s["first_ts"] = ts if s["first_ts"] in (None, 0) else min(s["first_ts"], ts) if ts else s["first_ts"]
        s["last_ts"] = ts if s["last_ts"] in (None, 0) else max(s["last_ts"], ts) if ts else s["last_ts"]
        if p["flags"]:
            s["flags"].add(p["flags"])
        if p["payload"]:
            s["_blob"] += p["payload"]
            for text in _snippets(p["payload"]):
                if len(text) < min_len:
                    continue
                s["snippet_total"] += 1
                if len(s["snippets"]) < 8 and text not in s["snippets"]:
                    s["snippets"].append(text)
        s["_frames"].append(len(p["payload"]))
        frame_rows.append({
            "frame": packet_count, "ts": ts, "proto": p["proto"],
            "src": p["src"], "sport": p["sport"], "dst": p["dst"], "dport": p["dport"],
            "payload_len": len(p["payload"]),
            "payload_hex": p["payload"][:MAX_HEX].hex(),
            "truncated": len(p["payload"]) > MAX_HEX,
        })

    rows = []
    blobs = {}
    for idx, s in enumerate(sessions.values()):
        s["stream_idx"] = idx
        s["flags"] = sorted(s["flags"])
        s["frame_payload_lens"] = s.pop("_frames")
        blobs[idx] = bytes(s.pop("_blob", b""))
        rows.append(s)
    rows.sort(key=lambda x: (x["payload_bytes"], x["packets"]), reverse=True)
    suspicious = [s for s in rows if s["snippet_total"]]
    summary = {
        "ok": True,
        "file": path.replace(os.sep, "/"),
        "sha256": _sha256(path),
        "size": os.path.getsize(path),
        "format": "pcapng" if _is_pcapng(path) else "pcap",
        "linktype": linktype,
        "linktype_name": LINKTYPE_NAMES.get(linktype, "unknown"),
        "packet_count": packet_count,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "duration_s": (last_ts - first_ts) if first_ts and last_ts else None,
        "session_count": len(rows),
        "sessions": rows[:top],
        "sessions_total": len(rows),
        "suspicious_session_count": len(suspicious),
        "suspicious_snippet_count": sum(s["snippet_total"] for s in suspicious),
    }
    if extract:
        summary["extract"] = _write_extract(extract, rows, blobs, frame_rows)
    return summary


def _write_extract(outdir, rows, blobs, frame_rows):
    os.makedirs(outdir, exist_ok=True)
    written = []
    for s in rows:
        blob = blobs.get(s["stream_idx"], b"")
        if not blob:
            continue
        name = "s%02d_%s_%s-%s_%s.bin" % (
            s["stream_idx"], s["src"].replace(":", "_"), s["sport"],
            s["dst"].replace(":", "_"), s["dport"])
        p = os.path.join(outdir, name)
        with open(p, "wb") as fh:
            fh.write(blob)
        written.append({"path": name, "bytes": len(blob), "sha256": _sha256(p)})
    fpath = os.path.join(outdir, "frames.jsonl")
    with open(fpath, "w", encoding="utf-8", newline="\n") as fh:
        for row in frame_rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    written.append({"path": "frames.jsonl", "lines": len(frame_rows)})
    return {"dir": outdir, "files": written}


def tshark_probe(path):
    """结构化探测 tshark；缺失时返回降级结论而不是抛异常。"""
    exe = _which("tshark")
    if not exe:
        return {"available": False, "blocked_at": "tool-missing",
                "reason": "未找到 tshark；已用标准库解析降级",
                "degraded_to": "stdlib-pcap-parser"}
    try:
        r = subprocess.run([exe, "-r", path, "-q", "-z", "io,phs"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=120)
    except Exception as exc:  # noqa: BLE001
        return {"available": True, "error": str(exc)[:120]}
    lines = [ln for ln in (r.stdout or "").splitlines() if ln.strip()]
    return {"available": True, "rc": r.returncode,
            "protocol_hierarchy": lines[:12]}


def _which(name):
    for p in os.environ.get("PATH", "").split(os.pathsep):
        cand = os.path.join(p, name + ".exe")
        if os.path.isfile(cand):
            return cand
        cand = os.path.join(p, name)
        if os.path.isfile(cand):
            return cand
    return ""


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_pcapng(path):
    with open(path, "rb") as fh:
        return fh.read(4) == b"\x0a\x0d\x0d\x0a"


def _print_human(summary):
    print("== pcap summary ==")
    print("file      : %s" % summary["file"])
    print("format    : %s  linktype=%s(%s)" % (
        summary["format"], summary["linktype"], summary["linktype_name"]))
    print("sha256    : %s" % summary["sha256"])
    print("packets   : %d  sessions=%d" % (summary["packet_count"], summary["sessions_total"]))
    if summary["first_ts"]:
        print("time range: %.6f .. %.6f  (%.3fs)" % (
            summary["first_ts"], summary["last_ts"], summary["duration_s"]))
    print("\n-- top sessions (5-tuple, directional) --")
    for s in summary["sessions"]:
        print("%-4s %s:%s -> %s:%s  pkts=%-5d bytes=%-7d snippets=%d" % (
            s["proto"], s["src"], s["sport"], s["dst"], s["dport"],
            s["packets"], s["payload_bytes"], s["snippet_total"]))
        for text in s["snippets"][:4]:
            print("     | %s" % text.replace("\r", "\\r"))
    print("\n-- suspicious plaintext --")
    for s in summary["sessions"]:
        if not s["snippets"]:
            continue
        print("[%s:%s -> %s:%s]" % (s["src"], s["sport"], s["dst"], s["dport"]))
        for text in s["snippets"]:
            print("  %s" % text.replace("\r", "\\r"))
    if not summary["suspicious_session_count"]:
        print("(no keyword-bearing plaintext snippets)")


# ------------------------------------------------------------------ self-test
def _mk_eth_ip_tcp(src, dst, sport, dport, payload=b"", seq=1, flags=0x18):
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, 0,
                       (5 << 12) | flags, 8192, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    return eth + ip + tcp + payload


def _mk_pcap(packets):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, (ts, data) in enumerate(packets):
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        out += struct.pack("<IIII", sec, usec, len(data), len(data)) + data
    return out


def _mk_pcapng(packets):
    def block(btype, body):
        body += b"\x00" * ((-len(body)) % 4)
        total = 12 + len(body)
        return struct.pack("<II", btype, total) + body + struct.pack("<I", total)

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 1, 0, 65535))
    out = shb + idb
    for ts, data in packets:
        us = int(ts * 1_000_000)
        body = struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF,
                           len(data), len(data)) + data
        out += block(6, body)
    return out


def self_test():
    checks = []
    tmp = tempfile.mkdtemp(prefix="pcap-self-test-")
    req = b"GET /selftest HTTP/1.1\r\nHost: selftest.invalid\r\n\r\n"
    rsp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    packets = [(1700000000.100000, _mk_eth_ip_tcp("10.0.0.1", "10.0.0.2", 40001, 80, req)),
               (1700000000.200000, _mk_eth_ip_tcp("10.0.0.2", "10.0.0.1", 80, 40001, rsp))]

    pcap_path = os.path.join(tmp, "min.pcap")
    with open(pcap_path, "wb") as fh:
        fh.write(_mk_pcap(packets))
    s = summarize(pcap_path)
    checks.append(("pcap 解析包数=2", s["packet_count"] == 2 and s["format"] == "pcap"))
    checks.append(("方向性会话=2", s["sessions_total"] == 2))
    got = " ".join(x for sess in s["sessions"] for x in sess["snippets"])
    checks.append(("明文片段含 GET /selftest", "GET /selftest" in got))

    png_path = os.path.join(tmp, "min.pcapng")
    with open(png_path, "wb") as fh:
        fh.write(_mk_pcapng(packets))
    s2 = summarize(png_path)
    checks.append(("pcapng 解析包数=2", s2["packet_count"] == 2 and s2["format"] == "pcapng"))

    exdir = os.path.join(tmp, "ex")
    s3 = summarize(pcap_path, extract=exdir)
    files = [f["path"] for f in (s3.get("extract") or {}).get("files", [])]
    ok_ext = any(f.endswith(".bin") for f in files) and "frames.jsonl" in files
    checks.append(("--extract 导出字节流+frames.jsonl", ok_ext))

    bad = os.path.join(tmp, "bad.bin")
    with open(bad, "wb") as fh:
        fh.write(b"NOTAPCAP" * 4)
    try:
        summarize(bad)
        checks.append(("非 pcap 被拒", False))
    except PcapError as exc:
        checks.append(("非 pcap 被拒", "不是 pcap" in str(exc)))

    probe = tshark_probe(pcap_path)
    checks.append(("tshark 探测结构化降级", isinstance(probe, dict) and "available" in probe))

    bad_checks = [n for n, ok in checks if not ok]
    print(json.dumps({
        "ok": not bad_checks,
        "self_test": True,
        "checks": len(checks),
        "passed": len(checks) - len(bad_checks),
        "failed": bad_checks,
        "tmp": tmp,
    }, ensure_ascii=False))
    return 0 if not bad_checks else 1


def _write_out(summary, outdir):
    os.makedirs(outdir, exist_ok=True)
    clean = {k: v for k, v in summary.items() if k != "extract"}
    with open(os.path.join(outdir, "pcap-summary.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(clean, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(outdir, "snippets.txt"), "w", encoding="utf-8", newline="\n") as fh:
        for s in summary["sessions"]:
            for text in s["snippets"]:
                fh.write("%s:%s -> %s:%s\t%s\n" % (
                    s["src"], s["sport"], s["dst"], s["dport"], text))
    print("wrote: %s" % os.path.join(outdir, "pcap-summary.json").replace(os.sep, "/"))
    print("wrote: %s" % os.path.join(outdir, "snippets.txt").replace(os.sep, "/"))


def _fail(code, error, detail="", blocked_at="input", **extra):
    """统一失败形状：ok / blocked_at / reason 三件套必填（DOMAIN-SPEC §3）。

    历史 bug：这里的 JSON 只有 error/detail，与其它域不一致，自动化无法判断卡点。
    """
    err = {"ok": False, "blocked_at": blocked_at,
           "reason": error if not detail else "%s: %s" % (error, detail),
           "error": error, "detail": detail}
    err.update(extra)
    print(json.dumps(err, ensure_ascii=False))
    return code


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="纯标准库 pcap/pcapng 会话聚合、字节流导出与明文片段提取（无需 tshark）",
        epilog="退出码：0 成功/降级；2 输入或解析失败（JSON ok:false）。")
    ap.add_argument("--file", "-f", help="pcap/pcapng 文件（--self-test 时可省略）")
    ap.add_argument("--top", type=int, default=20, help="输出会话数（默认 20）")
    ap.add_argument("--min-len", type=int, default=4, help="明文片段最小长度（默认 4）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--out", help="写出 pcap-summary.json 与 snippets.txt 的目录")
    ap.add_argument("--extract", metavar="DIR",
                    help="导出每个方向性会话的 .bin 字节流与 frames.jsonl")
    ap.add_argument("--tshark-check", action="store_true",
                    help="用 tshark 交叉验证协议分层；缺失则结构化降级")
    ap.add_argument("--self-test", action="store_true",
                    help="离线自检：内置最小 pcap/pcapng 字节流")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.file:
        return _fail(2, "missing_argument", "--file 必填（或使用 --self-test）")
    if not os.path.isfile(args.file):
        return _fail(2, "file_not_found", "确认路径；支持 pcap/pcapng", file=args.file)

    try:
        summary = summarize(args.file, top=max(1, args.top),
                            min_len=max(1, args.min_len), extract=args.extract)
    except PcapError as exc:
        return _fail(2, "pcap_parse_error", str(exc), file=args.file,
                     hint="先 file/xxd 确认 magic；损坏包可用 editcap 切片后重试")
    except OSError as exc:
        return _fail(2, "io_error", str(exc), file=args.file)

    if args.tshark_check:
        summary["tshark"] = tshark_probe(args.file)

    if args.out:
        _write_out(summary, args.out)
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        _print_human(summary)
        if args.extract:
            print("\n-- extract --")
            for f in summary["extract"]["files"]:
                print("  %s" % f)
        if args.tshark_check:
            t = summary["tshark"]
            print("\n-- tshark --")
            print("  available=%s %s" % (t.get("available"), t.get("blocked_at", "")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
