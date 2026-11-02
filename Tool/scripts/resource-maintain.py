#!/usr/bin/env python3
"""Read resources and maintain bounded knowledge; never execute or publish it."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from lib import resource_maintenance as maintenance
from lib.resource_sources import Sources, SourceError, linked, _json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("sources")
    read = sub.add_parser("read"); read.add_argument("--resource", required=True)
    inspect = sub.add_parser("inspect"); inspect.add_argument("--query", required=True)
    inspect.add_argument("--limit", type=int, default=5)
    plan = sub.add_parser("plan"); plan.add_argument("--request", required=True)
    apply = sub.add_parser("apply"); apply.add_argument("--plan", required=True); apply.add_argument("--backups")
    restore = sub.add_parser("restore"); restore.add_argument("--receipt", required=True); restore.add_argument("--backups")
    recover = sub.add_parser("recover"); recover.add_argument("--receipt", required=True); recover.add_argument("--backups")
    backups = sub.add_parser("backups"); backups.add_argument("--backups")
    args = parser.parse_args()
    try:
        if args.action == "sources":
            result = {"ok": True, "sources": Sources(args.root).view()}
        elif args.action == "read":
            result = {"ok": True, **maintenance.read_resource(args.root, args.resource)}
        elif args.action == "inspect":
            result = {"ok": True, **maintenance.inspect(args.root, args.query, limit=args.limit)}
        elif args.action in {"plan", "apply"}:
            path = Path(args.request if args.action == "plan" else args.plan)
            if linked(path) or not path.is_file() or path.stat().st_size > 1024 * 1024:
                raise SourceError("knowledge_input_budget_exceeded")
            with path.open("rb") as stream:
                content = stream.read(1024 * 1024 + 1)
            if len(content) > 1024 * 1024:
                raise SourceError("knowledge_input_budget_exceeded")
            data = _json(content.decode("utf-8-sig"))
            result = maintenance.prepare(args.root, data) if args.action == "plan" else maintenance.apply(args.root, data, backups=args.backups)
            if args.action == "plan":
                result["ok"] = result.get("action") in {"create", "update", "noop"}
        elif args.action == "restore":
            result = maintenance.restore(args.root, args.receipt, backups=args.backups)
        elif args.action == "recover":
            result = maintenance.recover(args.root, args.receipt, backups=args.backups)
        else:
            result = maintenance.backups_view(args.root, backups=args.backups)
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as exc:
        # Never echo candidate content, private roots or raw parse exceptions.
        result = {"ok": False, "error": str(exc) if isinstance(exc, SourceError) else "resource_maintenance_rejected",
                  "changed": None if args.action in {"apply", "restore", "recover"} else False,
                  "next": "Check the documented source, shape, evidence, review hashes and current state; do not force overwrite."}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
