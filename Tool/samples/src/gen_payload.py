#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_samples.py —— 生成 samples 用的高熵 payload.bin（本仓库原创）。

resource_blob.exe 需要一个高熵二进制 blob 作为资源，用来验证 seep_pe_resources
能识别"高熵资源"。这里用确定性伪随机生成 64KB，保证可复现、不含任何外部内容。
"""
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
out = os.path.join(HERE, "payload.bin")

rng = random.Random(0x5EE9)  # 固定种子，可复现
data = bytes(rng.getrandbits(8) for _ in range(64 * 1024))
# 打一个可识别的头（模拟皮肤包魔数），其余保持高熵
data = b"XWGZDEMO" + data[8:]
with open(out, "wb") as f:
    f.write(data)
print(f"wrote {out} ({len(data)} bytes)")
