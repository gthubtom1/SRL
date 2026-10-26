#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""protocol-plugin witness: summarise a real RADIUS pcap and assert fields.

Used by Tool/skill/protocol-plugin/pack.json `witness_tool`. Exit 0 only when
pcap-summary.py exits 0 AND the JSON proves packet/session parsing: positive
packet_count, non-empty sessions, the expected UDP/1812 RADIUS conversation
and a SHA256. An empty/corrupt pcap exits 2.
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
TARGET = "Tool/cases/protocol05/target/RADIUS.pcap"
TOOL = os.path.join(HERE, "pcap-summary.py")


def fail(msg):
    print("[witness] protocol-plugin FAIL: " + msg)
    return 1


def main():
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run(
        [sys.executable, TOOL, "--file", TARGET, "--json"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=110, env=env,
    )
    if r.returncode != 0:
        return fail("pcap-summary rc=%d: %s" % (r.returncode, (r.stdout + r.stderr)[-400:]))
    try:
        data = json.loads(r.stdout)
    except Exception as exc:  # noqa: BLE001
        return fail("stdout is not JSON: %s; %s" % (exc, (r.stdout + r.stderr)[-300:]))

    problems = []
    sessions = data.get("sessions") or []
    if data.get("ok") is not True:
        problems.append("ok != true")
    if int(data.get("packet_count") or 0) <= 0:
        problems.append("packet_count <= 0")
    if int(data.get("session_count") or 0) <= 0:
        problems.append("session_count <= 0")
    if not sessions:
        problems.append("sessions 为空")
    elif not any(str(s.get("proto")) == "UDP" and int(s.get("dport") or 0) == 1812
                 for s in sessions):
        problems.append("sessions 未出现 UDP/1812 RADIUS 会话")
    if not re.fullmatch(r"[0-9a-f]{64}", str(data.get("sha256") or "")):
        problems.append("sha256 不是 64 位 hex")
    if problems:
        return fail("; ".join(problems))

    pairs = ["%s/%s->%s/%s" % (s.get("proto"), s.get("sport"), s.get("dst"), s.get("dport"))
             for s in sessions[:3]]
    print("[witness] protocol-plugin ok: packets=%s sessions=%s [%s] sha256=%s"
          % (data.get("packet_count"), data.get("session_count"), ", ".join(pairs),
             str(data.get("sha256"))[:12]))
    return 0


if __name__ == "__main__":
    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        print(__doc__)
        raise SystemExit(0)
    _selftest = "--self-test" in sys.argv[1:]
    _rc = main()
    if _selftest:
        print(json.dumps({"ok": _rc == 0, "domain": "protocol-plugin", "witness": "real-target"},
                         ensure_ascii=False))
        _rc = 0 if _rc == 0 else 2
    raise SystemExit(_rc)
