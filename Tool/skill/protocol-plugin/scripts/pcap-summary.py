#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pcap-summary.py -- 纯标准库 pcap/pcapng 会话聚合与明文片段导出。

用法:
    python pcap-summary.py --file capture.pcap
    python pcap-summary.py --file capture.pcapng --json --out out/
    python pcap-summary.py --file capture.pcap --top 30 --min-len 8

不依赖 tshark：解析 pcap 全局头/包记录或 pcapng 的 IDB/EPB/SPB，
按五元组聚合会话，并提取可疑明文片段（HTTP、认证、SQL、JSON、URL 等）。
仅用于自有或明确授权的流量。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import struct
import sys
from collections import OrderedDict

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
        endian, frac, kind = PCAP_MAGICS[head]
        rest = fh.read(20)
        if len(rest) < 20:
            raise PcapError("pcap 全局头不足 24 字节")
        _, _, _, _, _, _, network = struct.unpack(endian + "IHHIIII", head + rest)
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
            interfaces.append(_u16(body, 0, endian))
        elif btype == 6:  # EPB
            if len(body) < 20:
                raise PcapError("pcapng EPB 过短")
            iface, ts_hi, ts_lo, cap, _orig = struct.unpack_from(endian + "IIIII", body, 0)
            linktype = interfaces[iface] if iface < len(interfaces) else 1
            yield ((ts_hi << 32) | ts_lo) / 1_000_000.0, linktype, body[20:20 + cap]
        elif btype == 3:  # SPB (no timestamp)
            if len(body) < 4:
                raise PcapError("pcapng SPB 过短")
            _orig = _u32(body, 0, endian)
            yield 0.0, interfaces[0] if interfaces else 1, body[4:]
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


def summarize(path, top=20, min_len=4):
    sessions = OrderedDict()
    packet_count = 0
    first_ts = None
    last_ts = None
    linktype = None

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
            }
        s["packets"] += 1
        s["payload_bytes"] += len(p["payload"])
        s["first_ts"] = ts if s["first_ts"] in (None, 0) else min(s["first_ts"], ts) if ts else s["first_ts"]
        s["last_ts"] = ts if s["last_ts"] in (None, 0) else max(s["last_ts"], ts) if ts else s["last_ts"]
        if p["flags"]:
            s["flags"].add(p["flags"])
        if p["payload"]:
            for text in _snippets(p["payload"]):
                if len(text) < min_len:
                    continue
                s["snippet_total"] += 1
                if len(s["snippets"]) < 8 and text not in s["snippets"]:
                    s["snippets"].append(text)

    rows = []
    for s in sessions.values():
        s["flags"] = sorted(s["flags"])
        rows.append(s)
    rows.sort(key=lambda x: (x["payload_bytes"], x["packets"]), reverse=True)
    suspicious = [s for s in rows if s["snippet_total"]]
    return {
        "ok": True,
        "file": os.path.abspath(path),
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


def _write_out(summary, outdir):
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "pcap-summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(outdir, "snippets.txt"), "w", encoding="utf-8") as fh:
        for s in summary["sessions"]:
            for text in s["snippets"]:
                fh.write("%s:%s -> %s:%s\t%s\n" % (
                    s["src"], s["sport"], s["dst"], s["dport"], text))
    print("wrote: %s" % os.path.join(outdir, "pcap-summary.json"))
    print("wrote: %s" % os.path.join(outdir, "snippets.txt"))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="纯标准库 pcap/pcapng 会话聚合与可疑明文片段导出（无需 tshark）")
    ap.add_argument("--file", "-f", required=True, help="pcap/pcapng 文件")
    ap.add_argument("--top", type=int, default=20, help="输出会话数（默认 20）")
    ap.add_argument("--min-len", type=int, default=4, help="明文片段最小长度（默认 4）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--out", help="写出 pcap-summary.json 与 snippets.txt 的目录")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.file):
        err = {"ok": False, "error": "file_not_found", "file": args.file,
               "hint": "确认路径；支持 pcap/pcapng，不支持 pcapng 的加密/压缩封装"}
        print(json.dumps(err, ensure_ascii=False) if args.json else "[FAIL] %s" % err["hint"])
        return 2
    try:
        summary = summarize(args.file, top=max(1, args.top), min_len=max(1, args.min_len))
    except PcapError as exc:
        err = {"ok": False, "error": "pcap_parse_error", "file": args.file,
               "detail": str(exc), "hint": "先 file/xxd 确认 magic；损坏包可用 editcap 切片后重试"}
        if args.json:
            print(json.dumps(err, ensure_ascii=False))
        else:
            print("[FAIL] %s" % exc)
            print("hint: %s" % err["hint"])
        return 2
    except OSError as exc:
        err = {"ok": False, "error": "io_error", "file": args.file, "detail": str(exc)}
        print(json.dumps(err, ensure_ascii=False) if args.json else "[FAIL] %s" % exc)
        return 2

    if args.out:
        _write_out(summary, args.out)
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        _print_human(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
