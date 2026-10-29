#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""softseep witness: run the capability gate and a real binary classification.

Used by Tool/skill/softseep/pack.json `witness_tool`. Exit 0 only when:
  * capability-gate.py --json reports a complete registry
    (covered == capabilities, dangling == 0, cycles == 0), and
  * preflight-classify.py parses a real PE target (magic_kind/format == pe,
    bitness 64, non-empty sections, SHA256).
The second half matters because the stage-generic pack must still prove it can
classify an actual binary; the first half proves the capability layer is sound.
"""
from __future__ import annotations

# Shared locator for both source skills and installed copies.
from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parents[2] / 'softseep' / 'scripts'))
from seep_runtime import repo_root as _seep_repo_root


import json
import os
import re
import subprocess
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = _seep_repo_root(__file__)
TARGET = "Tool/cases/golden-crackme/target/a.exe"
GATE = os.path.join(HERE, "capability-gate.py")
CLASSIFY = os.path.join(HERE, "preflight-classify.py")


def fail(msg):
    print("[witness] softseep FAIL: " + msg)
    return 1


def run_json(args):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run(
        [sys.executable] + args, cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=110, env=env,
    )
    if r.returncode != 0:
        raise RuntimeError("rc=%d: %s" % (r.returncode, (r.stdout + r.stderr)[-400:]))
    try:
        return json.loads(r.stdout)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("stdout is not JSON: %s; %s" % (exc, (r.stdout + r.stderr)[-300:]))


def main():
    try:
        gate = run_json([GATE, "--json"])
    except Exception as exc:  # noqa: BLE001
        return fail("capability-gate " + str(exc))

    problems = []
    counts = gate.get("counts") or {}
    if gate.get("ok") is not True:
        problems.append("capability-gate ok != true")
    if int(counts.get("capabilities") or 0) <= 0:
        problems.append("counts.capabilities <= 0")
    if counts.get("covered") != counts.get("capabilities"):
        problems.append("counts.covered != counts.capabilities")
    if int(counts.get("dangling") or 0) != 0:
        problems.append("counts.dangling != 0")
    if int(counts.get("cycles") or 0) != 0:
        problems.append("counts.cycles != 0")
    if problems:
        return fail("; ".join(problems))

    try:
        data = run_json([CLASSIFY, TARGET])
    except Exception as exc:  # noqa: BLE001
        return fail("preflight-classify " + str(exc))

    sections = data.get("sections") or []
    if data.get("magic_kind") != "pe":
        problems.append("magic_kind != pe（得到 %r）" % data.get("magic_kind"))
    if data.get("format") != "pe":
        problems.append("format != pe（得到 %r）" % data.get("format"))
    if int(data.get("bitness") or 0) != 64:
        problems.append("bitness != 64")
    if not re.fullmatch(r"[0-9a-f]{64}", str(data.get("sha256") or "")):
        problems.append("sha256 不是 64 位 hex")
    if not sections:
        problems.append("sections 为空")
    if problems:
        return fail("; ".join(problems))

    print("[witness] softseep ok: capabilities=%s covered=%s dangling=%s cycles=%s"
          % (counts.get("capabilities"), counts.get("covered"),
             counts.get("dangling"), counts.get("cycles")))
    print("[witness] softseep classify ok: magic_kind=%s format=%s bitness=%s machine=%s sections=%d"
          % (data.get("magic_kind"), data.get("format"), data.get("bitness"),
             data.get("machine"), len(sections)))
    return 0


if __name__ == "__main__":
    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        print(__doc__)
        raise SystemExit(0)
    _selftest = "--self-test" in sys.argv[1:]
    _rc = main()
    if _selftest:
        print(json.dumps({"ok": _rc == 0, "domain": "softseep", "witness": "real-target"},
                         ensure_ascii=False))
        _rc = 0 if _rc == 0 else 2
    raise SystemExit(_rc)
