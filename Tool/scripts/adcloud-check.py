#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""兼容入口：转发到 Tool/skill/_pending/ad-cloud/scripts/adcloud-check.py 并透传退出码。"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "skill", "_pending", "ad-cloud", "scripts", "adcloud-check.py")
if not os.path.isfile(TARGET):
    print("adcloud-check.py not found: %s" % TARGET, file=sys.stderr)
    sys.exit(2)
sys.exit(subprocess.call([sys.executable, TARGET] + sys.argv[1:]))
