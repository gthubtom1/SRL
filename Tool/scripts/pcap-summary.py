#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""兼容入口：转发到 Tool/skill/protocol-plugin/scripts/pcap-summary.py。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "skill", "protocol-plugin", "scripts", "pcap-summary.py")
if not os.path.isfile(TARGET):
    print("pcap-summary.py not found: %s" % TARGET, file=sys.stderr)
    sys.exit(2)
os.execv(sys.executable, [sys.executable, TARGET] + sys.argv[1:])
