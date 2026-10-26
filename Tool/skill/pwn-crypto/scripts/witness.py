#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pwn-crypto witness: analyse a real PE and assert protection/route fields.

Used by Tool/skill/pwn-crypto/pack.json `witness_tool`. Exit 0 only when
pwn-check.py exits 0 AND the JSON proves binary parsing plus exploit-surface
analysis: kind == PE, a populated `protections` map (NX/PIE/Canary), non-empty
sections, dangerous imports and a suggested route. An empty file exits 2.
"""
from __future__ import annotations

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
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
TARGET = "Tool/cases/pwn-crypto06/target/dvcp.exe"
TOOL = os.path.join(HERE, "pwn-check.py")


def fail(msg):
    print("[witness] pwn-crypto FAIL: " + msg)
    return 1


def main():
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run(
        [sys.executable, TOOL, "--file", TARGET, "--json"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=110, env=env,
    )
    if r.returncode != 0:
        return fail("pwn-check rc=%d: %s" % (r.returncode, (r.stdout + r.stderr)[-400:]))
    try:
        data = json.loads(r.stdout)
    except Exception as exc:  # noqa: BLE001
        return fail("stdout is not JSON: %s; %s" % (exc, (r.stdout + r.stderr)[-300:]))

    problems = []
    prot = data.get("protections") or {}
    if data.get("kind") != "PE":
        problems.append("kind != PE（得到 %r）" % data.get("kind"))
    if not re.fullmatch(r"[0-9a-f]{64}", str(data.get("sha256") or "")):
        problems.append("sha256 不是 64 位 hex")
    for key in ("NX", "PIE", "Canary", "RELRO"):
        if not str(prot.get(key) or "").strip():
            problems.append("protections.%s 缺失" % key)
    if not (data.get("sections") or []):
        problems.append("sections 为空")
    if not (data.get("dangerous_imports") or []):
        problems.append("dangerous_imports 为空")
    if not (data.get("next_routes") or []):
        problems.append("next_routes 为空")
    if problems:
        return fail("; ".join(problems))

    print("[witness] pwn-crypto ok: kind=%s arch=%s NX=%s PIE=%s Canary=%s sections=%d dangerous=%d routes=%d"
          % (data.get("kind"), data.get("arch"), prot.get("NX"), prot.get("PIE"),
             prot.get("Canary"), len(data.get("sections") or []),
             len(data.get("dangerous_imports") or []), len(data.get("next_routes") or [])))
    return 0


if __name__ == "__main__":
    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        print(__doc__)
        raise SystemExit(0)
    _selftest = "--self-test" in sys.argv[1:]
    _rc = main()
    if _selftest:
        print(json.dumps({"ok": _rc == 0, "domain": "pwn-crypto", "witness": "real-target"},
                         ensure_ascii=False))
        _rc = 0 if _rc == 0 else 2
    raise SystemExit(_rc)
