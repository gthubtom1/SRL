#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""proto-repro.py -- 按字段表解析二进制帧，并**离线重新构造**一条新请求。

用途
----
协议复刻的终点不是"看懂"，而是"能生成服务端会接受的新帧"。本脚本把帧格式外置成
**字段表（schema JSON）**：头部字段的 offset/size/endian、长度字段的覆盖范围、
校验算法的覆盖范围、载荷编码。解析与构造共用同一张表，避免"解析器能读、构造器写错"。

字段表（schema）最小结构::

    {
      "name": "sprx", "endian": "big",
      "header": [
        {"name": "magic",   "offset": 0, "size": 4, "type": "bytes"},
        {"name": "version", "offset": 4, "size": 1, "type": "u8"},
        {"name": "type",    "offset": 5, "size": 1, "type": "u8"},
        {"name": "length",  "offset": 6, "size": 2, "type": "u16",
         "role": "length", "covers": "payload"},
        {"name": "seq",     "offset": 8, "size": 4, "type": "u32"}
      ],
      "header_len": 12,
      "payload": {"encoding": "json"},
      "tail": [{"name": "crc32", "size": 4, "type": "u32",
                "role": "checksum", "algo": "crc32", "covers": "header+payload"}]
    }

`covers` 取值：`payload`（长度只含载荷）/ `frame`（长度含整帧）；
校验 `covers`：`header+payload` / `payload` / `header`。

用法
----
    python proto-repro.py --input frames.bin --json
    python proto-repro.py --pcap capture.pcapng --stream 0 --json
    python proto-repro.py --input frames.bin --rebuild --set type=4 --set seq=99 \
        --payload-text '{"temp":22.0,"status":"ok"}' --out new.bin --json
    python proto-repro.py --emit-schema schema.json
    python proto-repro.py --self-test

输入：本地帧文件 / pcap（经 tshark 取 tcp.payload）/ 内置 schema。
输出：JSON（帧表、字段、校验结论、重建字节的 sha256）；`--out` 写重建后的帧。
退出码：0 成功；2 失败（`{"ok": false, "blocked_at": ..., "reason": ...}`）。
tshark 缺失时 `--pcap` 走 `blocked_at: "tool-missing"` 降级，其余模式仍可离线运行。

边界：只做单流、单 schema 的解析/构造；不做 TCP 重传去重；加密段需先解出明文
（见 references/07-crypto-and-checksum.md）。仅用于授权环境。
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import struct
import subprocess
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

BUILTIN_SCHEMA = {
    "name": "sprx",
    "endian": "big",
    "header": [
        {"name": "magic", "offset": 0, "size": 4, "type": "bytes", "value": "SPRX"},
        {"name": "version", "offset": 4, "size": 1, "type": "u8"},
        {"name": "type", "offset": 5, "size": 1, "type": "u8"},
        {"name": "length", "offset": 6, "size": 2, "type": "u16",
         "role": "length", "covers": "payload"},
        {"name": "seq", "offset": 8, "size": 4, "type": "u32"},
    ],
    "header_len": 12,
    "payload": {"encoding": "json"},
    "tail": [{"name": "crc32", "size": 4, "type": "u32",
              "role": "checksum", "algo": "crc32", "covers": "header+payload"}],
}

INT_TYPES = {"u8": (1, "B"), "u16": (2, "H"), "u32": (4, "I")}
DEMO_PAYLOADS = [
    {"sensor": "lab-01", "proto": "sprx/1"},
    {"token": "abc", "nonce": "7f3a"},
    {"temp": 21.5, "status": "ok"},
]


class ReproError(Exception):
    def __init__(self, blocked_at, reason):
        super().__init__(reason)
        self.blocked_at = blocked_at
        self.reason = reason


# ------------------------------------------------------------------ schema
def load_schema(path):
    if not path:
        return json.loads(json.dumps(BUILTIN_SCHEMA))
    if not os.path.isfile(path):
        raise ReproError("schema", "schema 文件不存在: %s" % path)
    with open(path, encoding="utf-8-sig") as fh:
        sch = json.load(fh)
    for key in ("header", "header_len", "tail"):
        if key not in sch:
            raise ReproError("schema", "schema 缺字段 %s" % key)
    return sch


def _crc32(data):
    return binascii.crc32(data) & 0xFFFFFFFF


ALGOS = {
    "crc32": _crc32,
    "crc32-iso-hdlc": _crc32,
}


def _crc16_modbus(data):
    c = 0xFFFF
    for x in data:
        c ^= x
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c


ALGOS["crc16-modbus"] = _crc16_modbus


def _endian(sch):
    return ">" if (sch.get("endian") or "big").lower().startswith("b") else "<"


def _field_header(sch, name):
    for f in sch["header"]:
        if f["name"] == name:
            return f
    return None


def _length_field(sch):
    for f in sch["header"]:
        if f.get("role") == "length":
            return f
    raise ReproError("schema", "header 中没有 role=length 的字段")


def _tail_len(sch):
    return sum(int(f.get("size", 4)) for f in sch.get("tail") or [])


# ------------------------------------------------------------------ parse
def parse_frames(blob, sch, max_frames=10000):
    """按字段表分帧；坏 magic 时向前滑动重同步。返回 (frames, stats)。"""
    endian = _endian(sch)
    hlen = int(sch["header_len"])
    tlen = _tail_len(sch)
    length_f = _length_field(sch)
    magic = None
    for f in sch["header"]:
        if f.get("type") == "bytes" and f.get("value"):
            magic = f["value"].encode("latin-1")
            msize = int(f.get("size", len(magic)))
            magic = magic[:msize].ljust(msize, b"\x00")
            break
    frames = []
    skipped = 0
    errors = []
    pos = 0
    n = len(blob)
    while pos < n and len(frames) < max_frames:
        if magic and blob[pos:pos + len(magic)] != magic:
            nxt = blob.find(magic, pos + 1)
            if nxt < 0:
                skipped += n - pos
                pos = n
                break
            skipped += nxt - pos
            pos = nxt
            continue
        if pos + hlen > n:
            skipped += n - pos
            break
        header = blob[pos:pos + hlen]
        fields = {}
        ok = True
        for f in sch["header"]:
            off, size, ftype = int(f["offset"]), int(f["size"]), f.get("type")
            raw = header[off:off + size]
            if len(raw) < size:
                ok = False
                break
            if ftype == "bytes":
                fields[f["name"]] = raw.decode("latin-1")
            elif ftype in INT_TYPES:
                fields[f["name"]] = int.from_bytes(raw, "big" if endian == ">" else "little")
            else:
                fields[f["name"]] = raw.hex()
        if not ok:
            errors.append({"offset": pos, "reason": "header_truncated"})
            break
        plen = int(fields.get(length_f["name"], 0))
        if length_f.get("covers", "payload") == "frame":
            plen = plen - hlen - tlen
        if plen < 0 or pos + hlen + plen + tlen > n:
            errors.append({"offset": pos, "reason": "truncated",
                           "need": hlen + plen + tlen, "have": n - pos})
            break
        payload = blob[pos + hlen:pos + hlen + plen]
        tail = blob[pos + hlen + plen:pos + hlen + plen + tlen]
        checks = []
        for f in sch.get("tail") or []:
            if f.get("role") != "checksum":
                continue
            size = int(f.get("size", 4))
            want = int.from_bytes(tail[:size], "big" if endian == ">" else "little")
            algo = ALGOS.get(str(f.get("algo", "crc32")).lower())
            if not algo:
                checks.append({"name": f["name"], "algo": f.get("algo"), "ok": None,
                               "reason": "unknown-algo"})
                continue
            cover = f.get("covers", "header+payload")
            material = {"header+payload": header + payload,
                        "payload": payload,
                        "header": header}[cover]
            got = algo(material)
            checks.append({"name": f["name"], "algo": f.get("algo"), "ok": got == want,
                           "want": "0x%08x" % want, "got": "0x%08x" % got,
                           "covers": cover})
        decoded = _decode_payload(payload, sch)
        frames.append({
            "index": len(frames), "offset": pos, "frame_len": hlen + plen + tlen,
            "header_len": hlen, "payload_len": plen, "fields": fields,
            "payload_hex": payload.hex(), "payload": decoded,
            "checks": checks,
            "crc_ok": all(c.get("ok") is not False for c in checks),
            "sha256": hashlib.sha256(blob[pos:pos + hlen + plen + tlen]).hexdigest(),
        })
        pos += hlen + plen + tlen
    stats = {"bytes": n, "consumed": pos, "skipped_bytes": skipped,
             "trailing_bytes": max(0, n - pos), "errors": errors}
    return frames, stats


def _decode_payload(payload, sch):
    enc = (sch.get("payload") or {}).get("encoding", "raw")
    if enc == "json":
        try:
            return json.loads(payload.decode("utf-8"))
        except Exception:  # noqa: BLE001
            return {"_decode_error": "json", "_hex": payload[:64].hex()}
    if enc == "utf8":
        return payload.decode("utf-8", "replace")
    return {"_hex": payload.hex()}


# ------------------------------------------------------------------ build
def build_frame(sch, fields, payload):
    """按字段表构造一条新帧；长度与校验一律重算，忽略表中的旧值。"""
    endian = _endian(sch)
    hlen = int(sch["header_len"])
    tlen = _tail_len(sch)
    if isinstance(payload, (dict, list)):
        payload = _payload_bytes(payload, sch)
    elif isinstance(payload, str):
        payload = payload.encode("utf-8")
    header = bytearray(hlen)
    length_f = _length_field(sch)
    for f in sch["header"]:
        off, size, ftype = int(f["offset"]), int(f["size"]), f.get("type")
        name = f["name"]
        if f.get("role") == "length":
            val = (hlen + len(payload) + tlen) if f.get("covers") == "frame" else len(payload)
            header[off:off + size] = int(val).to_bytes(size, "big" if endian == ">" else "little")
            continue
        if name in fields and fields[name] is not None:
            val = fields[name]
        elif f.get("value") is not None:
            val = f["value"]
        else:
            continue
        if ftype == "bytes":
            raw = str(val).encode("latin-1")[:size].ljust(size, b"\x00")
            header[off:off + size] = raw
        elif ftype in INT_TYPES:
            header[off:off + size] = int(val).to_bytes(size, "big" if endian == ">" else "little")
        else:
            header[off:off + size] = bytes.fromhex(str(val))[:size].ljust(size, b"\x00")
    tail = b""
    for f in sch.get("tail") or []:
        size = int(f.get("size", 4))
        if f.get("role") != "checksum":
            tail += b"\x00" * size
            continue
        algo = ALGOS.get(str(f.get("algo", "crc32")).lower())
        if not algo:
            raise ReproError("build", "未知校验算法: %s" % f.get("algo"))
        cover = f.get("covers", "header+payload")
        material = {"header+payload": bytes(header) + payload,
                    "payload": payload, "header": bytes(header)}[cover]
        got = algo(material)
        tail += got.to_bytes(size, "big" if endian == ">" else "little")
    return bytes(header) + payload + tail


def _payload_bytes(payload, sch):
    if payload is None:
        return b""
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    enc = (sch.get("payload") or {}).get("encoding", "raw")
    if enc == "json":
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return str(payload).encode("utf-8")


def _apply_sets(fields, pairs):
    for pair in pairs or []:
        if "=" not in pair:
            raise ReproError("cli", "--set 需要 k=v 形式: %s" % pair)
        k, v = pair.split("=", 1)
        try:
            fields[k] = int(v, 0)
        except ValueError:
            fields[k] = v
    return fields


# ------------------------------------------------------------------ tshark
def _which(name):
    for p in os.environ.get("PATH", "").split(os.pathsep):
        for cand in (os.path.join(p, name + ".exe"), os.path.join(p, name)):
            if os.path.isfile(cand):
                return cand
    return ""


def extract_stream(path, stream):
    exe = _which("tshark")
    if not exe:
        raise ReproError("tool-missing",
                         "未找到 tshark；改用 pcap-summary.py --extract 导出字节流后 --input 解析")
    cmd = [exe, "-r", path, "-Y", "tcp.stream==%d && tcp.len>0" % stream,
           "-T", "fields", "-e", "tcp.payload"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=120)
    except Exception as exc:  # noqa: BLE001
        raise ReproError("tshark", str(exc)[:160])
    if r.returncode != 0:
        raise ReproError("tshark", (r.stderr or "tshark rc=%d" % r.returncode)[:160])
    blob = bytearray()
    for line in (r.stdout or "").splitlines():
        line = line.strip().replace(":", "")
        if not line:
            continue
        try:
            blob += bytes.fromhex(line)
        except ValueError:
            continue
    if not blob:
        raise ReproError("tshark", "stream %s 没有应用层字节（试 tcp.stream 编号或确认非 TLS）" % stream)
    shown = "tshark " + " ".join(cmd[1:])
    return bytes(blob), {"tool": "tshark", "stream": stream, "cmd": shown[:300]}


# ------------------------------------------------------------------ self-test
def self_test():
    checks = []
    sch = load_schema(None)
    frames = [build_frame(sch, {"version": 1, "type": i + 1, "seq": i + 1}, p)
              for i, p in enumerate(DEMO_PAYLOADS)]
    blob = b"".join(frames)

    parsed, stats = parse_frames(blob, sch)
    checks.append(("3 帧可解析", len(parsed) == 3 and not stats["errors"]))
    checks.append(("三帧 CRC 全部通过", all(f["crc_ok"] for f in parsed)))
    checks.append(("payload 解回 JSON", parsed[0]["payload"] == DEMO_PAYLOADS[0]))
    checks.append(("length 只覆盖 payload",
                   all(f["payload_len"] == f["frame_len"] - 16 for f in parsed)))

    new_payload = {"sensor": "lab-02", "proto": "sprx/1", "seq": 42}
    new = build_frame(sch, {"version": 1, "type": 4, "seq": 99}, new_payload)
    parsed_new, _ = parse_frames(new, sch)
    ok_new = (len(parsed_new) == 1 and parsed_new[0]["crc_ok"]
              and parsed_new[0]["fields"]["type"] == 4
              and parsed_new[0]["fields"]["seq"] == 99
              and parsed_new[0]["payload"] == new_payload
              and parsed_new[0]["fields"]["length"] == len(_payload_bytes(new_payload, sch)))
    checks.append(("重建新帧可被同一张表解析", bool(ok_new)))

    corrupt = bytearray(new)
    corrupt[13] ^= 0xFF
    parsed_bad, _ = parse_frames(bytes(corrupt), sch)
    checks.append(("改 1 字节载荷 → CRC 失败",
                   len(parsed_bad) == 1 and parsed_bad[0]["crc_ok"] is False))

    noisy = b"\x00\x01junk" + frames[0] + b"\xde\xad\xbe\xef\xff" + b"".join(frames[1:])
    parsed_noisy, stats_noisy = parse_frames(noisy, sch)
    checks.append(("垃圾字节后能重同步",
                   len(parsed_noisy) == 3 and stats_noisy["skipped_bytes"] >= 9))

    partial, stats_partial = parse_frames(blob[:20], sch)
    checks.append(("半包不崩溃且报 truncated",
                   len(partial) == 0 and any(e["reason"] == "truncated"
                                             for e in stats_partial["errors"])))

    schema_rt = json.loads(json.dumps(sch))
    checks.append(("schema 可序列化往返", schema_rt["header_len"] == 12))

    bad = [n for n, ok in checks if not ok]
    print(json.dumps({
        "ok": not bad, "self_test": True, "checks": len(checks),
        "passed": len(checks) - len(bad), "failed": bad,
        "frames": len(parsed), "rebuilt_sha256": hashlib.sha256(new).hexdigest(),
    }, ensure_ascii=False))
    return 0 if not bad else 1


# ------------------------------------------------------------------ main
def _fail(err):
    print(json.dumps({"ok": False, "blocked_at": err.blocked_at,
                      "reason": err.reason}, ensure_ascii=False))
    return 2


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="按字段表解析二进制帧并离线重新构造新请求（无需 tshark）",
        epilog="退出码：0 成功；2 失败（JSON ok:false + blocked_at）。")
    ap.add_argument("--schema", help="字段表 JSON（缺省用内置 SPRX 表）")
    ap.add_argument("--input", "-i", help="原始帧文件（可多帧拼接）")
    ap.add_argument("--pcap", help="从 pcap 取某个 TCP 流的载荷（需要 tshark）")
    ap.add_argument("--stream", type=int, default=0, help="配合 --pcap 的 tcp.stream 编号")
    ap.add_argument("--frame-index", type=int, default=0, help="重建时的基线帧下标")
    ap.add_argument("--rebuild", action="store_true", help="按基线帧重建一条新帧")
    ap.add_argument("--set", action="append", default=[], metavar="K=V",
                    help="覆盖头字段，可重复（数值自动转 int）")
    ap.add_argument("--payload-text", help="新载荷（JSON 文本或原文字符串）")
    ap.add_argument("--payload-file", help="从文件读新载荷")
    ap.add_argument("--out", help="写出重建帧的路径")
    ap.add_argument("--emit-schema", help="把当前字段表写到文件后退出")
    ap.add_argument("--json", action="store_true", help="输出 JSON（默认也输出 JSON）")
    ap.add_argument("--max-frames", type=int, default=200, help="最多解析帧数")
    ap.add_argument("--self-test", action="store_true", help="离线自检：构造→解析→重建→拒错")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        sch = load_schema(args.schema)
        if args.emit_schema:
            with open(args.emit_schema, "w", encoding="utf-8") as fh:
                json.dump(sch, fh, ensure_ascii=False, indent=2)
            print(json.dumps({"ok": True, "schema": args.emit_schema,
                              "header_len": sch["header_len"]}, ensure_ascii=False))
            return 0

        source = {}
        if args.pcap:
            blob, source = extract_stream(args.pcap, args.stream)
        elif args.input:
            if not os.path.isfile(args.input):
                raise ReproError("input", "文件不存在: %s" % args.input)
            with open(args.input, "rb") as fh:
                blob = fh.read()
            source = {"file": args.input.replace(os.sep, "/"),
                      "sha256": hashlib.sha256(blob).hexdigest(),
                      "bytes": len(blob)}
        else:
            raise ReproError("cli", "需要 --input 或 --pcap（或 --self-test）")

        frames, stats = parse_frames(blob, sch, max_frames=max(1, args.max_frames))
        result = {"ok": True, "schema": sch.get("name"), "source": source,
                  "stats": stats, "frame_count": len(frames),
                  "frames": frames[:max(1, args.max_frames)]}

        if args.rebuild:
            if not frames:
                raise ReproError("rebuild", "没有可作基线的帧")
            base = frames[min(args.frame_index, len(frames) - 1)]
            fields = dict(base["fields"])
            if args.payload_file:
                with open(args.payload_file, "rb") as fh:
                    payload = fh.read()
            elif args.payload_text is not None:
                txt = args.payload_text
                if (sch.get("payload") or {}).get("encoding") == "json":
                    try:
                        payload = json.loads(txt)
                    except ValueError:
                        payload = txt.encode("utf-8")
                else:
                    payload = txt.encode("utf-8")
            else:
                payload = base["payload"]
            _apply_sets(fields, args.set)
            # 长度/校验字段由构造器重算，不接受手工覆盖
            for f in sch["header"]:
                if f.get("role") == "length":
                    fields.pop(f["name"], None)
            new_bytes = build_frame(sch, fields, _payload_bytes(payload, sch))
            check, _ = parse_frames(new_bytes, sch)
            result["rebuild"] = {
                "base_index": base["index"],
                "base_sha256": base["sha256"],
                "new_sha256": hashlib.sha256(new_bytes).hexdigest(),
                "new_len": len(new_bytes),
                "fields": {k: v for k, v in fields.items()},
                "payload": payload if isinstance(payload, (dict, list, str)) else payload.hex(),
                "verify": {"parsed": bool(check), "crc_ok": bool(check and check[0]["crc_ok"])},
                "hex": new_bytes.hex(),
            }
            if args.out:
                with open(args.out, "wb") as fh:
                    fh.write(new_bytes)
                result["rebuild"]["out"] = args.out.replace(os.sep, "/")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except ReproError as err:
        return _fail(err)
    except OSError as exc:
        return _fail(ReproError("io", str(exc)[:200]))
    except Exception as exc:  # noqa: BLE001
        return _fail(ReproError("internal", "%s: %s" % (type(exc).__name__, str(exc)[:200])))


if __name__ == "__main__":
    sys.exit(main())
