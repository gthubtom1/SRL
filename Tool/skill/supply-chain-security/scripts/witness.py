#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""supply-chain-security witness: reachability over a real lockfile + source.

Used by Tool/skill/supply-chain-security/pack.json `witness_tool`. Exit 0 only
when sbom-reach.py exits 0 AND the JSON proves it parsed the lockfile and
matched imports: inputs.lock true, components_total > 0, a reachable component
with entry_hit, and an unreachable component. Empty/corrupt input is red.
"""
from __future__ import annotations

# Shared locator for both source skills and installed copies.
from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parents[2] / 'softseep' / 'scripts'))
from seep_runtime import repo_root as _seep_repo_root


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
ROOT = _seep_repo_root(__file__)
LOCK = "Tool/cases/supply-chain04/input/package-lock.json"
SOURCE = "Tool/cases/supply-chain04/input/src"
TOOL = os.path.join(HERE, "sbom-reach.py")


def fail(msg):
    print("[witness] supply-chain-security FAIL: " + msg)
    return 1


def main():
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run(
        [sys.executable, TOOL, "--lock", LOCK, "--source", SOURCE],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=110, env=env,
    )
    if r.returncode != 0:
        return fail("sbom-reach rc=%d: %s" % (r.returncode, (r.stdout + r.stderr)[-400:]))
    try:
        data = json.loads(r.stdout)
    except Exception as exc:  # noqa: BLE001
        return fail("stdout is not JSON: %s; %s" % (exc, (r.stdout + r.stderr)[-300:]))

    problems = []
    inputs = data.get("inputs") or {}
    reachable = data.get("reachable") or []
    unreachable = data.get("unreachable") or []
    if data.get("ok") is not True:
        problems.append("ok != true")
    if inputs.get("lock") is not True:
        problems.append("inputs.lock != true（锁文件未解析）")
    if int(inputs.get("sources_scanned") or 0) <= 0:
        problems.append("inputs.sources_scanned <= 0")
    if int(data.get("components_total") or 0) <= 0:
        problems.append("components_total <= 0")
    if not reachable:
        problems.append("reachable 为空")
    elif not any(str(x.get("name")) == "left-pad" and x.get("entry_hit") is True
                 for x in reachable):
        problems.append("reachable 未命中 left-pad/entry_hit")
    if not unreachable:
        problems.append("unreachable 为空")
    if not (data.get("entries") or []):
        problems.append("entries 为空")
    if problems:
        return fail("; ".join(problems))

    print("[witness] supply-chain-security ok: lock=%s sources=%s components=%s reachable=%s unreachable=%s"
          % (inputs.get("lock"), inputs.get("sources_scanned"), data.get("components_total"),
             ",".join(str(x.get("name")) for x in reachable[:4]),
             ",".join(str(x.get("name")) for x in unreachable[:4])))
    return 0


if __name__ == "__main__":
    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        print(__doc__)
        raise SystemExit(0)
    _selftest = "--self-test" in sys.argv[1:]
    _rc = main()
    if _selftest:
        print(json.dumps({"ok": _rc == 0, "domain": "supply-chain-security", "witness": "real-target"},
                         ensure_ascii=False))
        _rc = 0 if _rc == 0 else 2
    raise SystemExit(_rc)
