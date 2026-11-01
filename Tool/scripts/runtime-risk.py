#!/usr/bin/env python3
"""Shared CLI for bounded diagnosis and cooperating-adapter runtime risk state."""
from __future__ import annotations

import argparse
import json
import sys

from lib.runtime_diagnostics import diagnose_json
from lib.runtime_risk import RiskError, state_action


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    diag = commands.add_parser("diagnose", help="Pure observation diagnosis; no target execution")
    diag.add_argument("--facts-json", default="{}")
    for name in ("status", "grant", "extend", "pause", "resume", "resolve"):
        sub = commands.add_parser(name)
        sub.add_argument("--url", default="")
        sub.add_argument("--subject-ref", default="")
        sub.add_argument("--scope-id", default="")
        sub.add_argument("--evidence-ref", default="")
        sub.add_argument("--operation-id", default="")
        sub.add_argument("--max-attempts", type=int, default=1)
        sub.add_argument("--lifetime-seconds", type=int, default=900)
    args = parser.parse_args()
    try:
        if args.action == "diagnose":
            result = diagnose_json(args.facts_json)
        else:
            result = state_action(args.action, args.url, args.subject_ref, args.scope_id,
                                  args.max_attempts, args.lifetime_seconds,
                                  args.operation_id, args.evidence_ref)
    except (ValueError, TypeError, OSError) as exc:
        result = {"ok": False, "error": str(exc) if isinstance(exc, RiskError) else "invalid_input_or_state_unavailable"}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
