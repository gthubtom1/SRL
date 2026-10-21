#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""兼容入口：转发到 Tool/skill/protocol-plugin/scripts/pcap-summary.py。

所有参数（含 `--state-model <json>` / `--edge-threshold` / `--self-test`）原样透传，
实现只在域内那一份；本文件不复制逻辑。
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "skill", "protocol-plugin", "scripts", "pcap-summary.py")
if not os.path.isfile(TARGET):
    print("pcap-summary.py not found: %s" % TARGET, file=sys.stderr)
    sys.exit(2)
# 兼容入口必须**透传退出码**：os.execv 在 Windows 上会让调用方拿到 0，
# 失败被自动化当成成功（R4 复审实测：pcap-summary 失败 rc=0）。
sys.exit(subprocess.call([sys.executable, TARGET] + sys.argv[1:]))
