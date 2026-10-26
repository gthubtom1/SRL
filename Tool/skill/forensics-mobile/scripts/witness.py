#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""forensics-mobile witness: check a real pcap and assert forensic fields.

Used by Tool/skill/forensics-mobile/pack.json `witness_tool`. Exit 0 only when
forensics-check.py exits 0 AND its JSON proves it actually parsed the capture:
type/format == pcap, a positive packet_count, a UTC timeline and a SHA256.
An empty file returns type=unknown with no packet_count/timeline, so the
assertions turn the witness red even though the tool exits 0.
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
TARGET = "Tool/cases/forensics07/target/bgp-4byte-asn.pcap"
TOOL = os.path.join(HERE, "forensics-check.py")


def fail(msg):
    print("[witness] forensics-mobile FAIL: " + msg)
    return 1


def main():
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run(
        [sys.executable, TOOL, "--file", TARGET, "--json"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=110, env=env,
    )
    if r.returncode != 0:
        return fail("forensics-check rc=%d: %s" % (r.returncode, (r.stdout + r.stderr)[-400:]))
    try:
        data = json.loads(r.stdout)
    except Exception as exc:  # noqa: BLE001
        return fail("stdout is not JSON: %s; %s" % (exc, (r.stdout + r.stderr)[-300:]))

    problems = []
    meta = data.get("meta") or {}
    timeline = data.get("timeline") or {}
    integrity = data.get("integrity") or {}
    if data.get("ok") is not True:
        problems.append("ok != true")
    if data.get("type") != "pcap":
        problems.append("type != pcap（得到 %r）" % data.get("type"))
    if data.get("format") != "pcap":
        problems.append("format != pcap（得到 %r）" % data.get("format"))
    if int(meta.get("packet_count") or 0) <= 0:
        problems.append("meta.packet_count <= 0")
    if not str(timeline.get("start_utc") or "").strip():
        problems.append("timeline.start_utc 为空")
    if not str(timeline.get("end_utc") or "").strip():
        problems.append("timeline.end_utc 为空")
    if not re.fullmatch(r"[0-9a-f]{64}", str(integrity.get("sha256") or "")):
        problems.append("integrity.sha256 不是 64 位 hex")
    if not (data.get("extractables") or []):
        problems.append("extractables 为空")
    if problems:
        return fail("; ".join(problems))

    print("[witness] forensics-mobile ok: type=%s packets=%s timeline=%s..%s sha256=%s"
          % (data.get("type"), meta.get("packet_count"),
             timeline.get("start_utc"), timeline.get("end_utc"),
             str(integrity.get("sha256"))[:12]))
    return 0


if __name__ == "__main__":
    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        print(__doc__)
        raise SystemExit(0)
    _selftest = "--self-test" in sys.argv[1:]
    _rc = main()
    if _selftest:
        print(json.dumps({"ok": _rc == 0, "domain": "forensics-mobile", "witness": "real-target"},
                         ensure_ascii=False))
        _rc = 0 if _rc == 0 else 2
    raise SystemExit(_rc)
