#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""兼容入口：转发到 Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py。"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "skill", "_pending", "plugin-targets", "scripts", "plugin-triage.py")
if not os.path.isfile(TARGET):
    print("plugin-triage.py not found: %s" % TARGET, file=sys.stderr)
    sys.exit(2)
# 兼容入口必须**透传退出码**：os.execv 在 Windows 上会让调用方拿到 0，
# 失败被自动化当成成功（R4 复审实测：pcap-summary 失败 rc=0）。
sys.exit(subprocess.call([sys.executable, TARGET] + sys.argv[1:]))
