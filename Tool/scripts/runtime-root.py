#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Small installer bridge for the public runtime-root contract.

This CLI only resolves an agent root or atomically records a config-only
runtime registration. It never installs packages, executes targets, or writes
outside the explicitly resolved agent root.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from lib.runtime_root import (  # noqa: E402
    RuntimeRootError,
    SCRIPT_REL,
    make_registration,
    read_runtime_origin,
    resolve_agent_root,
    resolve_runtime_root,
    runtime_origin_path,
)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def fail(code: str, detail: str) -> int:
    print(json.dumps({"ok": False, "code": code, "detail": str(detail)[:240]}, ensure_ascii=True))
    return 2


def resolve(args) -> int:
    agent = resolve_agent_root(args.agent_root or None, os.environ)
    print(json.dumps({"ok": True, "agent_root": str(agent.resolve())}, ensure_ascii=True))
    return 0


def atomic_registration(path: Path, data: dict) -> str | None:
    backup = None
    if path.is_file():
        backup = path.with_name(path.name + ".backup-" +
                                datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") +
                                "-" + uuid.uuid4().hex[:8])
        shutil.copy2(path, backup)
    fd, temporary = tempfile.mkstemp(prefix=".seep-runtime-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return str(backup) if backup else None


def register(args) -> int:
    agent = resolve_agent_root(args.agent_root or None, os.environ)
    runtime = Path(args.runtime_root).resolve()
    source = Path(args.entry_source).resolve()
    destination = Path(args.entry_dest).resolve()
    expected_source = (runtime / Path(SCRIPT_REL)).resolve()
    expected_dest = (agent / "skills" / "softseep" / "scripts" / "version-migrate.py").resolve()
    if source != expected_source:
        raise RuntimeRootError("runtime_mismatch", "entry_source is not the runtime migration entry")
    if destination != expected_dest:
        raise RuntimeRootError("runtime_mismatch", "entry_dest is not the agent migration deployment")
    if not source.is_file() or not destination.is_file():
        raise RuntimeRootError("runtime_missing", "source/deployed entry is missing")
    if digest(source) != digest(destination):
        raise RuntimeRootError("runtime_mismatch", "deployed entry hash differs from source")
    resolved = resolve_runtime_root(explicit_runtime=runtime, agent_root=agent, env=os.environ)
    if Path(resolved["runtime_root"]).resolve() != runtime:
        raise RuntimeRootError("runtime_mismatch", "verified runtime root differs from requested root")
    registration = make_registration(runtime, agent)
    agent.mkdir(parents=True, exist_ok=True)
    path = runtime_origin_path(agent)
    backup = atomic_registration(path, registration)
    print(json.dumps({"ok": True, "agent_root": str(agent.resolve()),
                      "runtime_root": str(runtime), "registration": str(path),
                      "backup": backup, "entry_sha256": digest(destination)},
                     ensure_ascii=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Seep runtime root installer bridge")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("resolve")
    p.add_argument("--agent-root", default="")
    p = sub.add_parser("register")
    p.add_argument("--agent-root", default="")
    p.add_argument("--runtime-root", required=True)
    p.add_argument("--entry-source", required=True)
    p.add_argument("--entry-dest", required=True)
    p = sub.add_parser("validate")
    p.add_argument("--agent-root", default="")
    p.add_argument("--runtime-root", required=True)
    args = parser.parse_args()
    try:
        if args.command == "resolve":
            return resolve(args)
        if args.command == "validate":
            agent = resolve_agent_root(args.agent_root or None, os.environ)
            runtime = Path(args.runtime_root).resolve()
            origin = read_runtime_origin(agent)
            if origin is None or Path(origin["root"]).resolve() != runtime:
                raise RuntimeRootError("runtime_mismatch", "registration does not belong to this runtime")
            resolved = resolve_runtime_root(agent_root=agent, env={})
            if Path(resolved["runtime_root"]).resolve() != runtime:
                raise RuntimeRootError("runtime_mismatch", "registered runtime root mismatch")
            print(json.dumps({"ok": True, "agent_root": str(agent.resolve()),
                              "runtime_root": str(runtime)}, ensure_ascii=True))
            return 0
        return register(args)
    except RuntimeRootError as exc:
        return fail(exc.code, exc.detail)
    except Exception as exc:
        return fail("runtime_install_failed", type(exc).__name__ + ": operation failed")


if __name__ == "__main__":
    raise SystemExit(main())
