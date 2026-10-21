#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按 RFC 6455 构造一条新的客户端 WebSocket text 帧（掩码）。

用法（在案例目录下）：
    python input/build_ws_frame.py artifacts/new-frame.bin
输出：JSON（payload、帧长、hex、掩码键、预测响应），并把帧写入指定文件。

只用于本地回环靶场：不改原抓包，不连外部端点。
"""
import json
import os
import sys

MASK = bytes.fromhex("11223344")
PAYLOAD = {"type": "request", "data": "4242424242424242424"}


def build(payload_obj, mask=MASK):
    payload = json.dumps(payload_obj, separators=(",", ":")).encode() + b"\n"
    if len(payload) > 125:
        raise SystemExit("payload 超过单帧 125 字节，需要扩展长度编码")
    masked = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
    return bytes([0x81, 0x80 | len(payload)]) + mask + masked, payload


def main(argv):
    out = argv[1] if len(argv) > 1 else "artifacts/new-frame.bin"
    frame, payload = build(PAYLOAD)
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "wb") as fh:
        fh.write(frame)
    print(json.dumps({
        "ok": True,
        "payload": payload.decode().rstrip("\n"),
        "payload_len": len(payload),
        "frame_len": len(frame),
        "mask": MASK.hex(),
        "frame_hex": frame.hex(),
        "predicted_response": {"type": "response", "data": PAYLOAD["data"]},
        "predicted_response_frame_len": 2 + len(json.dumps(
            {"type": "response", "data": PAYLOAD["data"]},
            separators=(",", ":")).encode()) + 1,
        "out": out,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
