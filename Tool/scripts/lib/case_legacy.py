"""Preserve legacy case files before removing them, with crash recovery.

Only state.json can supply active state, and only when the ledger has no state.
Other or conflicting snapshots remain historical bytes with a ledger reference.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path

from .project_lock import atomic_copy, project_lock
from .project_transaction import MAX_BYTES, file_transaction
from .typed_assets import _project_path, file_identity


def _local(root: Path, relative: str) -> Path:
    # Check the explicitly selected case itself as well as every child component.
    for path in (root, _project_path(root, relative)):
        if path.is_symlink() or (path.exists() and getattr(path.lstat(), "st_file_attributes", 0) & 1024):
            raise ValueError("legacy migration must not traverse a link/reparse point")
    return root / relative


def _snapshot(path: Path) -> tuple[bytes, dict]:
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("invalid or oversized legacy case file: %s" % path.name)
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("legacy case file exceeds migration limit")
    value = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("legacy case file must contain a JSON object: %s" % path.name)
    if path.name == "state.json":
        if value.get("schema", "seep-case/1") != "seep-case/1" \
                or not isinstance(value.get("depth"), dict) \
                or not isinstance(value.get("target"), str) \
                or value.get("stage") not in ("intake", "0a", "0b", "1", "2", "3", "4", "done") \
                or not isinstance(value.get("next_action", ""), str) \
                or not isinstance(value.get("stage_history", []), list) \
                or any(not isinstance(row, dict) for row in value.get("stage_history", [])) \
                or any(not isinstance(row, dict) for row in value["depth"].values()):
            raise ValueError("invalid legacy state snapshot")
    return raw, value


def _kind(row):
    # Match the case reader: kind has historically been case/whitespace tolerant.
    return str(row.get("kind") or "").strip().lower()


def validate_archives(case, ledger):
    """Check durable import references even after the original files were removed."""
    root, seen = Path(os.path.abspath(case)), set()
    for row in ledger:
        if not isinstance(row, dict):
            raise ValueError("case ledger contains a non-object row")
        if _kind(row) != "legacy_import":
            continue
        source, sha, size = row.get("source"), row.get("sha256"), row.get("size")
        if source not in ("state.json", "ai_manifest.json") or not isinstance(sha, str) \
                or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha) \
                or type(size) is not int or size < 0:
            raise ValueError("invalid legacy archive identity")
        key = (source, sha)
        reference = "legacy/%s.%s.json" % (source.removesuffix(".json"), sha)
        policies = ("activated", "historical") if source == "state.json" else ("metadata",)
        if key in seen or row.get("archive") != reference or row.get("state_policy") not in policies:
            raise ValueError("duplicate or conflicting legacy archive registration")
        seen.add(key)
        _local(root, reference)
        identity = file_identity(root, reference)
        if identity["sha256"] != sha or identity["size"] != size:
            raise ValueError("legacy archive fingerprint mismatch")


def update(case, *, migrate, drop, compact, load_ledger, lease_guard):
    """Validate the full write set, then atomically archive/register/optionally drop.

    A retained journal is recovered on retry. Existing state wins over old files;
    an archive reference records when a snapshot was preserved without activation.
    """
    root = Path(os.path.abspath(case))
    facts = _local(root, "facts.jsonl")
    with project_lock(root, recover=True):
        lease_guard(str(root))
        ledger = load_ledger(str(root))
        validate_archives(root, ledger)
        if any(_kind(row) == "state" and not isinstance(row.get("state"), dict) for row in ledger):
            raise ValueError("invalid state row in case ledger")
        raw_facts = facts.read_bytes() if facts.exists() else b""
        states = [row["state"] for row in ledger if _kind(row) == "state" and isinstance(row.get("state"), dict)]
        additions, plans = [], []
        stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if migrate or drop:
            for name in ("state.json", "ai_manifest.json"):
                source = _local(root, name)
                if not source.exists():
                    continue
                raw, value = _snapshot(source)
                sha = hashlib.sha256(raw).hexdigest()
                reference = "legacy/%s.%s.json" % (name.removesuffix(".json"), sha)
                archive = _local(root, reference)
                previous = [row for row in ledger if _kind(row) == "legacy_import"
                            and row.get("source") == name and row.get("sha256") == sha]
                if archive.exists() and archive.read_bytes() != raw:
                    raise ValueError("legacy archive bytes differ from their fingerprint")
                if previous:
                    if len(previous) != 1 or previous[0].get("archive") != reference \
                            or previous[0].get("size") != len(raw) or not archive.is_file():
                        raise ValueError("incomplete or conflicting legacy archive registration")
                    policy = previous[0].get("state_policy")
                else:
                    policy = "metadata"
                    if name == "state.json":
                        policy = "historical" if states else "activated"
                        if not states:
                            additions.append({"kind": "state", "ts": stamp, "state": value})
                            states.append(value)
                    additions.append({"kind": "legacy_import", "source": name, "sha256": sha,
                                      "size": len(raw), "archive": reference,
                                      "state_policy": policy, "ts": stamp})
                plans.append((source, archive, reference, raw, sha, policy))
        payload = raw_facts
        if compact:
            # Preserve the original bytes of every retained line, including events.
            lines = raw_facts.splitlines(keepends=True)
            state_lines = [index for index, line in enumerate(lines)
                           if line.strip() and _kind(json.loads(line)) == "state"]
            removed = set(state_lines[:-1])
            payload = b"".join(line for index, line in enumerate(lines) if index not in removed)
        if additions:
            if payload and not payload.endswith(b"\n"):
                payload += b"\n"
            payload += b"".join((json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8") for row in additions)
        refs = ["facts.jsonl"] + [ref for _s, _a, ref, _raw, _sha, _p in plans]
        if drop:
            refs += [source.name for source, *_rest in plans]
        if payload != raw_facts or plans:
            with file_transaction(root, refs):
                for source, archive, _reference, raw, sha, _policy in plans:
                    archive.parent.mkdir(parents=True, exist_ok=True)
                    if not archive.exists():
                        atomic_copy(source, archive, sha, len(raw))
                    if source.read_bytes() != raw or archive.read_bytes() != raw:
                        raise ValueError("legacy source/archive changed during migration")
                if payload != raw_facts:
                    from .project_transaction import _replace
                    _replace(facts, payload)
                if drop:
                    for source, _a, _r, raw, _sha, _policy in plans:
                        if source.read_bytes() != raw:
                            raise ValueError("legacy source changed before removal")
                        source.unlink()
        return [{"source": source.name, "archive": ref, "state_policy": policy, "dropped": bool(drop)}
                for source, _a, ref, _raw, _sha, policy in plans]
