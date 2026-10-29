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
    python proto-repro.py --pcap capture.pcapng --stream 0 --direction forward --json
    python proto-repro.py --input frames.bin --rebuild --set type=4 --set seq=99 \
        --payload-text '{"temp":22.0,"status":"ok"}' --out new.bin --json
    python proto-repro.py --emit-schema schema.json
    python proto-repro.py --self-test

输入：本地帧文件 / pcap（经 tshark 取 tcp.payload）/ 内置 schema。
输出：JSON（帧表、字段、校验结论、重建字节的 sha256）；`--out` 写重建后的帧。
退出码：0 成功；2 失败（`{"ok": false, "blocked_at": ..., "reason": ...}`）。
tshark 缺失时 `--pcap` 走 `blocked_at: "tool-missing"` 降级，其余模式仍可离线运行。

边界：pcap 模式按 SYN 确定连接与方向，按序号有界重组，缺 SYN/FIN、缺口、截断或冲突时拒绝分帧；抓包完整区间不证明对端接收。加密段需先解出明文
（见 references/07-crypto-and-checksum.md）。仅用于授权环境。
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import ipaddress
import json
import os
import struct
import subprocess
import sys
import tempfile
import threading

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
    def __init__(self, blocked_at, reason, code=None):
        super().__init__(reason)
        self.blocked_at = blocked_at
        self.reason = reason
        self.code = code


# ------------------------------------------------------------------ schema
def _validate_schema(sch):
    if not isinstance(sch, dict):
        raise ReproError("schema", "schema 顶层必须是对象")
    if (sch.get("endian") or "big").lower() not in ("big", "little", "be", "le"):
        raise ReproError("schema", "endian 必须是 big/little")
    try:
        hlen = int(sch.get("header_len"))
    except (TypeError, ValueError):
        raise ReproError("schema", "header_len 必须是正整数")
    if not 1 <= hlen <= 1024 * 1024:
        raise ReproError("schema", "header_len 必须在 1..1048576")
    header = sch.get("header")
    if not isinstance(header, list) or not header:
        raise ReproError("schema", "header 必须是非空数组")
    names = set()
    length_fields = []
    for i, field in enumerate(header):
        if not isinstance(field, dict):
            raise ReproError("schema", "header[%d] 不是对象" % i)
        name = field.get("name")
        if not isinstance(name, str) or not name.strip() or name in names:
            raise ReproError("schema", "header[%d] name 缺失、为空或重复" % i)
        names.add(name)
        try:
            off, size = int(field.get("offset")), int(field.get("size"))
        except (TypeError, ValueError):
            raise ReproError("schema", "header[%d] offset/size 必须是整数" % i)
        if off < 0 or size <= 0 or off + size > hlen:
            raise ReproError("schema", "header[%d] 越出 header_len" % i)
        if field.get("type") not in set(INT_TYPES) | {"bytes"}:
            raise ReproError("schema", "header[%d].type 不受支持" % i)
        if field.get("role") == "length":
            length_fields.append(field)
            if field.get("covers", "payload") not in ("payload", "frame"):
                raise ReproError("schema", "length.covers 只能是 payload/frame")
    if len(length_fields) != 1:
        raise ReproError("schema", "header 必须恰有一个 role=length 字段")
    tail = sch.get("tail")
    if not isinstance(tail, list):
        raise ReproError("schema", "tail 必须是数组（可为空）")
    for i, field in enumerate(tail):
        if not isinstance(field, dict):
            raise ReproError("schema", "tail[%d] 不是对象" % i)
        name = field.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ReproError("schema", "tail[%d] 缺 name" % i)
        try:
            size = int(field.get("size", 4))
        except (TypeError, ValueError):
            raise ReproError("schema", "tail[%d].size 必须是整数" % i)
        if not 1 <= size <= 64:
            raise ReproError("schema", "tail[%d].size 必须在 1..64" % i)
        if field.get("role") == "checksum":
            if str(field.get("algo", "crc32")).lower() not in ALGOS:
                raise ReproError("schema", "tail[%d] 校验算法不受支持" % i)
            if field.get("covers", "header+payload") not in (
                    "header+payload", "payload", "header"):
                raise ReproError("schema", "tail[%d].covers 非法" % i)
    encoding = (sch.get("payload") or {}).get("encoding", "raw")
    if encoding not in ("raw", "json", "utf8"):
        raise ReproError("schema", "payload.encoding 只能是 raw/json/utf8")
    return sch


def load_schema(path):
    if not path:
        return _validate_schema(json.loads(json.dumps(BUILTIN_SCHEMA)))
    if not os.path.isfile(path):
        raise ReproError("schema", "schema 文件不存在: %s" % path)
    try:
        with open(path, encoding="utf-8-sig") as fh:
            sch = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ReproError("schema", "schema 不可读或不是 JSON: %s" % str(exc)[:160])
    if not isinstance(sch, dict):
        raise ReproError("schema", "schema 顶层必须是对象")
    for key in ("header", "header_len", "tail"):
        if key not in sch:
            raise ReproError("schema", "schema 缺字段 %s" % key)
    return _validate_schema(sch)


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
        tail_offset = 0
        for f in sch.get("tail") or []:
            size = int(f.get("size", 4))
            if f.get("role") != "checksum":
                tail_offset += size
                continue
            want = int.from_bytes(tail[tail_offset:tail_offset + size], "big" if endian == ">" else "little")
            tail_offset += size
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
            "crc_ok": (False if any(c.get("ok") is False for c in checks)
                       else True if checks and all(c.get("ok") is True for c in checks)
                       else None),
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


def verify_rebuilt(blob, sch):
    """Require the constructor's bytes to parse as exactly one schema-valid frame."""
    parsed, stats = parse_frames(blob, sch)
    parsed_one = len(parsed) == 1 and not stats["errors"]
    crc_ok = parsed[0]["crc_ok"] if parsed_one else None
    digest_ok = bool(parsed_one and parsed[0]["sha256"] == hashlib.sha256(blob).hexdigest())
    valid = parsed_one and digest_ok and crc_ok is not False
    return valid, {"parsed": parsed_one, "frame_count": len(parsed),
                   "crc_ok": crc_ok, "sha256_ok": digest_ok,
                   "stats": stats}


def _payload_bytes(payload, sch):
    if payload is None:
        return b""
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    enc = (sch.get("payload") or {}).get("encoding", "raw")
    if enc == "json":
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return str(payload).encode("utf-8")


def _apply_sets(fields, pairs, sch):
    for pair in pairs or []:
        if "=" not in pair:
            raise ReproError("cli", "--set 需要 k=v 形式: %s" % pair)
        k, v = pair.split("=", 1)
        field = _field_header(sch, k)
        if not field or field.get("role") == "length":
            raise ReproError("cli", "--set 字段不存在或由构造器重算: %s" % k)
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


MAX_REASSEMBLY_BYTES = 16 * 1024 * 1024
MAX_TSHARK_OUTPUT = 128 * 1024 * 1024
MAX_TCP_PACKETS = 100000
TCP_MODULUS = 1 << 32


def _reassembly_error(code, reason):
    raise ReproError("tcp-reassembly", reason, code)


def _tcp_flag(value):
    value = value.strip().lower()
    if value in ("true", "1", "0x01", "0x1"):
        return 1
    if value in ("false", "0", "0x00", "0x0"):
        return 0
    raise ValueError("invalid TCP flag")


def _tcp_records(text):
    records = []
    for line in text.splitlines():
        if len(records) >= MAX_TCP_PACKETS:
            _reassembly_error("packet-limit", "TCP 包数超过上限")
        columns = line.split("\t")
        if len(columns) != 14:
            _reassembly_error("invalid-fields", "tshark 字段缺失或格式不明确")
        try:
            number = int(columns[0])
            src = (columns[1] or columns[2], int(columns[3]))
            dst = (columns[4] or columns[5], int(columns[6]))
            seq, length = int(columns[7]), int(columns[8])
            flags = [_tcp_flag(value) for value in columns[9:13]]
            payload = bytes.fromhex(columns[13].replace(":", ""))
            if ((columns[1] and columns[2]) or (columns[4] and columns[5]) or
                    ipaddress.ip_address(src[0]).version != ipaddress.ip_address(dst[0]).version or src == dst or
                    not 0 <= seq < TCP_MODULUS or not 0 <= length <= 65535 or
                    not 0 <= src[1] <= 65535 or not 0 <= dst[1] <= 65535 or
                    any(flag not in (0, 1) for flag in flags)):
                raise ValueError("invalid TCP fields")
        except ValueError:
            _reassembly_error("invalid-fields", "tshark TCP 字段或载荷无效")
        if len(payload) != length:
            _reassembly_error("truncated-packet", "帧 %s 的载荷与 tcp.len 不一致" % number)
        records.append((number, src, dst, seq, payload, *flags))
    return records


def reassemble_tcp(records, direction):
    # SYN 不带 ACK 的端点定义 forward；SYN/FIN 均消耗一个序号。
    initiators = {(r[1], r[2], r[3]) for r in records if r[5] and not r[6]}
    if len(initiators) != 1:
        _reassembly_error("missing-or-ambiguous-syn", "缺少唯一连接起始 SYN，无法确定前缀或方向")
    client, server, client_seq = next(iter(initiators))
    if any((r[1], r[2]) not in ((client, server), (server, client)) for r in records):
        _reassembly_error("ambiguous-flow", "同一 stream 包含其他端点")
    responder_syns = {r[3] for r in records if r[1] == server and r[2] == client and r[5] and r[6]}
    if len(responder_syns) != 1:
        _reassembly_error("missing-or-ambiguous-synack", "缺少唯一 SYN/ACK，不能确认连接边界")
    src, dst = (client, server) if direction == "forward" else (server, client)
    initial_seq = client_seq if direction == "forward" else next(iter(responder_syns))
    start = (initial_seq + 1) % TCP_MODULUS
    segments, fins = [], set()
    if any(r[8] for r in records):
        _reassembly_error("reset", "捕获到 TCP RST，不能按完整流验收")
    for number, a, b, seq, payload, syn, ack, fin, rst in records:
        if (a, b) != (src, dst):
            continue
        if syn and seq != initial_seq:
            _reassembly_error("ambiguous-syn", "方向内 SYN 序号不一致")
        data_seq = (seq + syn) % TCP_MODULUS
        offset = (data_seq - start) % TCP_MODULUS
        if offset >= TCP_MODULUS // 2:
            offset -= TCP_MODULUS
        if payload or fin:
            if offset < 0:
                _reassembly_error("before-syn", "载荷或 FIN 出现在 SYN 起始序号之前")
            if offset + len(payload) > MAX_REASSEMBLY_BYTES:
                _reassembly_error("byte-limit", "重组区间超过字节上限")
        if payload:
            segments.append((offset, payload, number))
        if fin:
            fins.add(offset + len(payload))
    if len(fins) != 1:
        _reassembly_error("missing-or-ambiguous-fin", "缺少唯一 FIN，无法确认捕获末尾")
    end = next(iter(fins))
    if end > MAX_REASSEMBLY_BYTES:
        _reassembly_error("byte-limit", "FIN 位置超过字节上限")
    blob = bytearray()
    overlap_bytes = 0
    for offset, payload, number in sorted(segments, key=lambda item: item[0]):
        if offset > len(blob):
            _reassembly_error("gap", "TCP 字节缺口从偏移 %s 开始" % len(blob))
        if offset + len(payload) > end:
            _reassembly_error("after-fin", "帧 %s 载荷超出 FIN" % number)
        overlap = min(len(payload), len(blob) - offset)
        if blob[offset:offset + overlap] != payload[:overlap]:
            _reassembly_error("conflicting-overlap", "帧 %s 的重叠载荷冲突" % number)
        overlap_bytes += overlap
        blob.extend(payload[overlap:])
    if len(blob) != end:
        _reassembly_error("gap", "TCP 字节缺口从偏移 %s 到 FIN" % len(blob))
    if not blob:
        _reassembly_error("empty", "选定方向没有载荷")
    return bytes(blob), {"status": "complete", "direction": direction,
        "src": {"ip": src[0], "port": src[1]}, "dst": {"ip": dst[0], "port": dst[1]},
        "initial_seq": initial_seq, "bytes": len(blob), "overlap_bytes": overlap_bytes,
        "boundary": "observed SYN to FIN; capture does not prove peer receipt"}


def _tshark_output(cmd):
    # Drain stdout concurrently, terminating the subprocess as soon as its output
    # exceeds the bound. stderr uses a temporary file to avoid a pipe deadlock.
    output, errors = bytearray(), []
    with tempfile.TemporaryFile() as stderr:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr)
        def stop():
            try:
                if proc.poll() is None:
                    proc.kill()
            except OSError:
                pass
        def drain():
            try:
                while True:
                    chunk = proc.stdout.read(min(65536, MAX_TSHARK_OUTPUT + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > MAX_TSHARK_OUTPUT:
                        stop()
                        break
            except (OSError, ValueError) as exc:
                errors.append(str(exc))
                stop()
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            stop()
            proc.wait()
            reader.join()
            raise ReproError("tshark", "tshark 超时")
        reader.join()
        proc.stdout.close()
        if len(output) > MAX_TSHARK_OUTPUT:
            _reassembly_error("output-limit", "tshark 输出超过上限")
        if errors:
            raise ReproError("tshark", errors[0][:160])
        if proc.returncode != 0:
            stderr.seek(0)
            reason = stderr.read(160).decode("utf-8", "replace")
            raise ReproError("tshark", reason or "tshark rc=%d" % proc.returncode)
    return output.decode("utf-8", "strict")


def extract_stream(path, stream, direction):
    exe = _which("tshark")
    if not exe:
        raise ReproError("tool-missing",
                         "未找到 tshark；先发现和接入工具，或提供经独立验证的单向重组文件")
    fields = ("frame.number", "ip.src", "ipv6.src", "tcp.srcport", "ip.dst", "ipv6.dst",
              "tcp.dstport", "tcp.seq_raw", "tcp.len", "tcp.flags.syn", "tcp.flags.ack",
              "tcp.flags.fin", "tcp.flags.reset", "tcp.payload")
    cmd = [exe, "-n", "-r", path, "-Y", "tcp.stream==%d" % stream,
           "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
    for field in fields:
        cmd.extend(("-e", field))
    try:
        text = _tshark_output(cmd)
    except ReproError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ReproError("tshark", str(exc)[:160])
    blob, info = reassemble_tcp(_tcp_records(text), direction)
    shown = "tshark " + " ".join(cmd[1:])
    return blob, {"tool": "tshark", "stream": stream, "cmd": shown, "reassembly": info}


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

    valid_verify, verify_detail = verify_rebuilt(new, sch)
    checks.append(("构造器产物通过独立自校验", valid_verify and verify_detail["crc_ok"] is True))
    invalid_new = build_frame(sch, {"version": 1, "type": 4, "seq": 1, "magic": "NOPE"},
                              new_payload)
    invalid_verify, _ = verify_rebuilt(invalid_new, sch)
    checks.append(("错误 magic 的重建产物被拒", not invalid_verify))

    invalid_schema = json.loads(json.dumps(sch))
    invalid_schema["header"][0]["offset"] = invalid_schema["header_len"] - 2
    try:
        _validate_schema(invalid_schema)
        checks.append(("字段越出 header_len 被拒", False))
    except ReproError:
        checks.append(("字段越出 header_len 被拒", True))

    invalid_schema = json.loads(json.dumps(sch))
    invalid_schema["header"][0]["role"] = "length"
    try:
        _validate_schema(invalid_schema)
        checks.append(("重复 length 字段被拒", False))
    except ReproError:
        checks.append(("重复 length 字段被拒", True))

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
    result = {"ok": False, "blocked_at": err.blocked_at, "reason": err.reason}
    if err.code:
        result["code"] = err.code
    print(json.dumps(result, ensure_ascii=False))
    return 2


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="按字段表解析二进制帧并离线重新构造新请求（无需 tshark）",
        epilog="退出码：0 成功；2 失败（JSON ok:false + blocked_at）。")
    ap.add_argument("--schema", help="字段表 JSON（缺省用内置 SPRX 表）")
    ap.add_argument("--input", "-i", help="原始帧文件（可多帧拼接）")
    ap.add_argument("--pcap", help="从 pcap 取某个 TCP 流的载荷（需要 tshark）")
    ap.add_argument("--stream", type=int, help="配合 --pcap 的 tcp.stream 编号（必填）")
    ap.add_argument("--direction", choices=("forward", "reverse"), help="forward 为 SYN 发起方到对端，reverse 为反向（必填）")
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
            if args.input or args.stream is None or args.stream < 0 or not args.direction:
                raise ReproError("cli", "--pcap 需要非负 --stream 和 --direction，不能与 --input 同用")
            blob, source = extract_stream(args.pcap, args.stream, args.direction)
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
        if stats["errors"]:
            raise ReproError("parse", json.dumps(stats["errors"], ensure_ascii=False))
        result = {"ok": True, "schema": sch.get("name"), "source": source,
                  "stats": stats, "frame_count": len(frames),
                  "frames": frames[:max(1, args.max_frames)]}

        if args.rebuild:
            if not frames:
                raise ReproError("rebuild", "没有可作基线的帧")
            if not 0 <= args.frame_index < len(frames):
                raise ReproError("rebuild", "frame-index 超出已解析帧范围")
            base = frames[args.frame_index]
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
                payload = bytes.fromhex(base["payload_hex"])
            _apply_sets(fields, args.set, sch)
            # 长度/校验字段由构造器重算，不接受手工覆盖
            for f in sch["header"]:
                if f.get("role") == "length":
                    fields.pop(f["name"], None)
            new_bytes = build_frame(sch, fields, _payload_bytes(payload, sch))
            verified, verify_detail = verify_rebuilt(new_bytes, sch)
            result["rebuild"] = {
                "base_index": base["index"],
                "base_sha256": base["sha256"],
                "new_sha256": hashlib.sha256(new_bytes).hexdigest(),
                "new_len": len(new_bytes),
                "fields": {k: v for k, v in fields.items()},
                "payload": payload if isinstance(payload, (dict, list, str)) else payload.hex(),
                "verify": verify_detail,
                "hex": new_bytes.hex(),
            }
            if not verified:
                raise ReproError(
                    "rebuild-verify",
                    "构造出的帧未通过同一 schema 的唯一帧/哈希/CRC 自校验: "
                    + json.dumps(verify_detail, ensure_ascii=False, separators=(",", ":")))
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
