"""Resolve case evidence to current local material, with bounded reference graphs.

File existence does not establish a claim's semantic truth. New claims/proofs
also bind bytes; older unbound records can only establish that material exists
now. Command strings are references, never proof of command execution.
"""
from __future__ import annotations

import os
from pathlib import Path
import re

from .case_repro import _plain, target_identity
from .typed_assets import file_identity

STRONG_AUTHORITY = {"shipped-artifact", "controlled-replay", "external-service"}
STRONG_CONFIDENCE = {"observed", "derived"}
HASH = re.compile(r"(?:sha256:)?([0-9a-f]{64})\Z", re.I)
CONTROL_FILES = {"facts.jsonl", "case.json", ".project.lock", ".project-transaction.json"}


def _file(api, case, value, *, artifact=False):
    root = _plain(Path(case))
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = _plain(candidate)
    work = _plain(Path(api._ROOT) / "work")
    if candidate.is_relative_to(root):
        scope, base, reference = "case", root, candidate.relative_to(root).as_posix()
    elif candidate.is_relative_to(work):
        scope, base, reference = "work", work, candidate.relative_to(work).as_posix()
    else:
        info = target_identity(root)
        if info["identity_scope"] != "file-bytes" or candidate != Path(info["path"]) or artifact:
            raise ValueError("evidence must belong to the case or its explicit repository work directory")
        scope, base, reference = "target", candidate.parent, candidate.name
    if scope == "case" and (reference in CONTROL_FILES or reference.startswith(".project-")):
        raise ValueError("case control metadata cannot serve as its own evidence")
    identity = file_identity(base, reference)
    if identity["size"] <= 0:
        raise ValueError("evidence file is empty")
    if artifact and api._norm_path(candidate) in api._case_target_paths(case):
        raise ValueError("command input target is not an output artifact")
    return {"scope": scope, "path": reference if scope != "target" else str(candidate),
            "sha256": identity["sha256"], "size": identity["size"]}


def _hash_file(api, case, digest):
    # Compare bytes, never grep for the digest in a claim, log or report.
    root = _plain(Path(case))
    try:
        target = target_identity(root)
        if target["identity_scope"] == "file-bytes" and target["sha256"] == digest:
            return _file(api, case, target["path"])
    except (OSError, ValueError, TypeError):
        pass
    visited = 0
    def onerror(exc):
        raise exc
    for folder, dirs, names in os.walk(root, followlinks=False, onerror=onerror):
        accepted = []
        for name in dirs:
            try:
                _plain(Path(folder) / name)
                if not name.startswith(".project-"):
                    accepted.append(name)
            except ValueError:
                continue
        dirs[:] = sorted(accepted)
        for name in sorted(names):
            if name in CONTROL_FILES or name.startswith(".tmp-") or name.startswith(".project-"):
                continue
            visited += 1
            if visited > 5000:
                raise ValueError("hash lookup exceeded 5000 files; reference an explicit evidence file")
            try:
                identity = _file(api, case, str(Path(folder) / name))
            except ValueError:
                continue
            if identity["sha256"] == digest:
                return identity
    raise ValueError("hash does not match any current evidence file")


def resolve(api, case, value, *, rows=None, seen=frozenset(), strong=False):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("evidence must be a nonempty string")
    value = value.strip()
    if not case:
        raise ValueError("evidence requires an explicit case")
    if api._evidence_is_command(value):
        for token in api._cmd_artifact_tokens(value):
            for candidate in (token, str(Path(case) / "work" / token), str(Path(api._ROOT) / "work" / token)):
                try:
                    return [_file(api, case, candidate, artifact=True)]
                except (OSError, ValueError, TypeError):
                    continue
        raise ValueError("command evidence has no nonempty local output artifact")
    match = HASH.fullmatch(value)
    if match:
        return [_hash_file(api, case, match.group(1).lower())]
    # Actual files take priority over embedded IDs, e.g. capture/E-001.log.
    for candidate in (value, str(Path(value).absolute())):
        try:
            return [_file(api, case, candidate)]
        except (OSError, ValueError, TypeError):
            pass
    ids = ["%s-%s" % pair for pair in api.EVIDENCE_ID_RE.findall(value)]
    if not ids or api.EVIDENCE_PATH_RE.search(value):
        raise ValueError("evidence does not name an existing local regular file")
    rows = api.load_ledger(case) if rows is None else rows
    indexed = {row["id"].strip().upper(): row for row in rows
               if api._is_claim(row) or api._entry_kind(row) == "repro"}
    if len(seen) >= 64:
        raise ValueError("evidence reference depth exceeded 64 records")
    files = []
    for identifier in ids:
        key = identifier.upper()
        if key in seen:
            raise ValueError("cyclic evidence reference: %s" % key)
        row = indexed.get(key)
        if row is None:
            raise ValueError("unknown evidence id: %s" % key)
        if api._entry_kind(row) == "repro":
            cross = row.get("grade") == "E3"
            valid = api._is_complete_e3(row, case=case) if cross else api._is_complete_repro(row, case=case)
            if not valid:
                raise ValueError("referenced replay has no complete current execution evidence")
            files.extend(_file(api, case, artifact["path"]) for artifact in row["artifacts"])
        else:
            files.extend(claim_files(api, case, row, rows=rows, seen=seen | {key}, strong=strong))
    return files


def claim_files(api, case, row, *, rows, seen=None, strong=True):
    if strong and (row.get("status") != "proven" or row.get("confidence") not in STRONG_CONFIDENCE
                   or row.get("authority") not in STRONG_AUTHORITY):
        raise ValueError("referenced claim is not proven with observed/derived authoritative evidence")
    seen = frozenset({row["id"].strip().upper()}) if seen is None else seen
    bindings = row.get("evidence_bindings")
    if "evidence_bindings" in row:
        if not isinstance(bindings, list) or not bindings:
            raise ValueError("invalid evidence bindings")
        files = []
        for binding in bindings:
            if not isinstance(binding, dict) or binding.get("evidence") not in row.get("evidence", []):
                raise ValueError("evidence binding is detached from claim")
            hashed = HASH.fullmatch(binding["evidence"])
            if hashed:
                # A new duplicate with the same digest must not redirect an old
                # binding to whichever path the next directory walk finds first.
                expected = binding.get("files")
                if not isinstance(expected, list) or not expected:
                    raise ValueError("missing bound hash evidence file")
                current = []
                for identity in expected:
                    if not isinstance(identity, dict) or identity.get("scope") not in ("case", "work", "target"):
                        raise ValueError("invalid bound hash evidence identity")
                    path = identity.get("path")
                    if not isinstance(path, str):
                        raise ValueError("invalid bound hash evidence path")
                    base = Path(api._ROOT) / "work" if identity["scope"] == "work" else Path(case)
                    candidate = path if identity["scope"] == "target" else str(base / path)
                    actual = _file(api, case, candidate)
                    if actual != identity or actual["sha256"] != hashed.group(1).lower():
                        raise ValueError("recorded hash evidence fingerprint changed")
                    current.append(actual)
                files.extend(current)
                continue
            current = resolve(api, case, binding["evidence"], rows=rows, seen=seen, strong=strong)
            if current != binding.get("files"):
                raise ValueError("recorded evidence fingerprint changed")
            files.extend(current)
        return files
    errors = []
    for evidence in row.get("evidence", []):
        try:
            return resolve(api, case, evidence, rows=rows, seen=seen, strong=strong)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            errors.append(str(exc))
    raise ValueError("no verifiable evidence anchor: %s" % ("; ".join(errors[:3]) or "empty evidence"))


def bind(api, case, row, evidence):
    files = resolve(api, case, evidence, seen=frozenset({row["id"].strip().upper()}))
    previous = row.get("evidence_bindings")
    if previous:
        row.setdefault("evidence_binding_history", []).append(previous)
    row["evidence_bindings"] = [{"evidence": evidence, "files": files}]
