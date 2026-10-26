#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apkseep witness: run java2c_probe.py on a real APK and assert its fields.

Used by Tool/skill/apkseep/pack.json `witness_tool`. Exit 0 only when the
domain tool exits 0 AND its JSON carries the APK/DEX/Java2C fields asserted
below. A green gate therefore means "apkseep can analyse an APK", not merely
"doctor.py --help loads".
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
TARGET = "Tool/cases/leaf-apk/target/diva.apk"
TOOL = os.path.join(HERE, "java2c_probe.py")


def fail(msg):
    print("[witness] apkseep FAIL: " + msg)
    return 1


def main():
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run(
        [sys.executable, TOOL, "--apk", TARGET, "--json"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=110, env=env,
    )
    if r.returncode != 0:
        return fail("java2c_probe rc=%d: %s" % (r.returncode, (r.stdout + r.stderr)[-400:]))
    try:
        data = json.loads(r.stdout)
    except Exception as exc:  # noqa: BLE001
        return fail("stdout is not JSON: %s; %s" % (exc, (r.stdout + r.stderr)[-300:]))

    problems = []
    dex = data.get("dex") or []
    cls = data.get("classification") or {}
    if TARGET not in (data.get("inputs") or []):
        problems.append("inputs 未登记目标")
    if not dex:
        problems.append("dex 为空")
    else:
        first = dex[0] or {}
        if int(first.get("classes") or 0) <= 0:
            problems.append("dex[0].classes <= 0")
        if int(first.get("total_methods") or 0) <= 0:
            problems.append("dex[0].total_methods <= 0")
        if not isinstance(first.get("native_ratio"), (int, float)):
            problems.append("dex[0].native_ratio 缺失")
    if not str(cls.get("verdict") or "").strip():
        problems.append("classification.verdict 为空")
    if not str(cls.get("confidence") or "").strip():
        problems.append("classification.confidence 为空")
    if not (cls.get("metrics") or {}):
        problems.append("classification.metrics 为空")
    if not (cls.get("evidence") or []):
        problems.append("classification.evidence 为空")
    if problems:
        return fail("; ".join(problems))

    first = dex[0]
    print("[witness] apkseep ok: dex=%s classes=%s methods=%s native=%s verdict=%s confidence=%s"
          % (first.get("name"), first.get("classes"), first.get("total_methods"),
             first.get("native_methods"), cls.get("verdict"), cls.get("confidence")))
    return 0


if __name__ == "__main__":
    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        print(__doc__)
        raise SystemExit(0)
    _selftest = "--self-test" in sys.argv[1:]
    _rc = main()
    if _selftest:
        print(json.dumps({"ok": _rc == 0, "domain": "apkseep", "witness": "real-target"},
                         ensure_ascii=False))
        _rc = 0 if _rc == 0 else 2
    raise SystemExit(_rc)
