#!/usr/bin/env python3
"""Task-scoped Windows flow; never replaces ordinary autonomous launch by default."""
import argparse
import json
import sys

from lib.runtime_flow import launch_flow
from lib.runtime_risk import RiskError


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", required=True)
    p.add_argument("--url", required=True)
    p.add_argument("--subject-ref", required=True)
    p.add_argument("--scope-id", required=True)
    p.add_argument("--wait-seconds", type=int, default=3)
    p.add_argument("--instance-pid", type=int, default=0)
    a = p.parse_args()
    try:
        result = launch_flow(a.target, a.url, a.subject_ref, a.scope_id, a.wait_seconds, a.instance_pid)
    except (ValueError, OSError) as exc:
        result = {"ok": False, "error": str(exc) if isinstance(exc, RiskError) else "invalid_input_or_state_unavailable"}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
