#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""firmware-iot witness: triage a real CramFS firmware image and assert fields.

Used by Tool/skill/firmware-iot/pack.json `witness_tool`. Exit 0 only when
fw-triage.py exits 0 AND reports a non-empty `containers` list (with the
expected CramFS magic), entropy metrics and suggested extraction commands.
An empty/corrupt file still makes fw-triage exit 0 with `containers: []`,
so the assertions -- not just the exit code -- are what turns the witness red.
"""
from __future__ import annotations

# Shared locator for both source skills and installed copies.
from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parents[2] / 'softseep' / 'scripts'))
try:
    from seep_runtime import repo_root as _seep_repo_root
except Exception as _runtime_error:  # noqa: BLE001 - convert missing runtime to JSON
    _seep_repo_root = None
    _RUNTIME_IMPORT_ERROR = type(_runtime_error).__name__
else:
    _RUNTIME_IMPORT_ERROR = ""


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
ROOT = None
if _seep_repo_root is not None:
    ROOT = _seep_repo_root(__file__)
else:
    for _parent in _RuntimePath(__file__).resolve().parents:
        if (_parent / "Tool" / "cases").is_dir():
            ROOT = str(_parent)
            break
TARGET = "Tool/cases/firmware-iot06/target/cramfs.bin"
TOOL = os.path.join(HERE, "fw-triage.py")


def fail(msg):
    print("[witness] firmware-iot FAIL: " + msg)
    return 1


def main():
    if not ROOT:
        return fail("runtime_missing (%s); install the softseep runtime or set "
                    "SEEP_RUNTIME_ROOT" % _RUNTIME_IMPORT_ERROR)
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    try:
        r = subprocess.run(
            [sys.executable, TOOL, "--file", TARGET, "--json"],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=110, env=env,
        )
    except subprocess.TimeoutExpired:
        return fail("fw-triage timed out after 110s")
    except OSError as exc:
        return fail("could not launch fw-triage: %s" % type(exc).__name__)
    if r.returncode != 0:
        return fail("fw-triage rc=%d: %s" % (r.returncode, (r.stdout + r.stderr)[-400:]))
    try:
        data = json.loads(r.stdout)
    except Exception as exc:  # noqa: BLE001
        return fail("stdout is not JSON: %s; %s" % (exc, (r.stdout + r.stderr)[-300:]))

    problems = []
    containers = data.get("containers") or []
    entropy = data.get("entropy") or {}
    if data.get("ok") is not True:
        problems.append("ok != true")
    if int(data.get("size") or 0) <= 0:
        problems.append("size <= 0")
    if not containers:
        problems.append("containers 为空（未识别到固件容器）")
    elif not any(str(c.get("type")) == "cramfs" for c in containers):
        problems.append("containers 未识别出 cramfs")
    if not isinstance(entropy.get("overall"), (int, float)):
        problems.append("entropy.overall 缺失")
    if not (data.get("suggested_commands") or []):
        problems.append("suggested_commands 为空")
    if not str(data.get("verdict") or "").strip():
        problems.append("verdict 为空")
    if problems:
        return fail("; ".join(problems))

    types = ",".join("%s@%s" % (c.get("type"), c.get("offset")) for c in containers[:3])
    print("[witness] firmware-iot ok: size=%s containers=[%s] entropy=%s verdict=%s"
          % (data.get("size"), types, entropy.get("overall"), str(data.get("verdict"))[:60]))
    return 0


if __name__ == "__main__":
    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        print(__doc__)
        raise SystemExit(0)
    _selftest = "--self-test" in sys.argv[1:]
    _rc = main()
    if _selftest:
        print(json.dumps({"ok": _rc == 0, "domain": "firmware-iot", "witness": "real-target"},
                         ensure_ascii=False))
        _rc = 0 if _rc == 0 else 2
    raise SystemExit(_rc)
