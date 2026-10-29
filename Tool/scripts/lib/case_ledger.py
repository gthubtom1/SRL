"""Validated case ledger storage shared by readers and cooperating writers.

Explicit extension kinds remain opaque objects. They cannot masquerade as claims;
known projections are checked before replay. This is local integrity, not a signed
audit log or an atomic snapshot against unrelated filesystem writers.
"""
from __future__ import annotations

import functools
import json
import math
import os
from pathlib import Path

from .case_legacy import validate_archives
from .case_repro import _local, _plain
from .project_lock import project_lock

STATUSES = {"hypothesis", "proven", "refuted", "stale", "fail", "unknown",
            "unsupported", "truncated", "skipped"}
CONFIDENCE = {"", "observed", "derived", "inferred", "unknown"}
AUTHORITY = {"", "shipped-artifact", "controlled-replay", "external-service", "reported", "none"}
STAGES = {"intake", "0a", "0b", "1", "2", "3", "4", "done"}


def kind(row):
    value = row.get("kind", "")
    if not isinstance(value, str):
        raise ValueError("kind must be a string")
    return value.strip().lower()


def _strings(row, names, *, nullable=()):
    for name in names:
        if name in row and not (name in nullable and row[name] is None) and not isinstance(row[name], str):
            raise ValueError("%s must be a string" % name)


def _choice(row, name, choices, *, nullable=False):
    if name in row:
        value = row[name]
        if nullable and value is None:
            return
        if not isinstance(value, str) or value not in choices:
            raise ValueError("invalid %s" % name)


def _objects(value, name):
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError("%s must be an array of objects" % name)


def validate_state(state):
    if not isinstance(state, dict):
        raise ValueError("state must be an object")
    _strings(state, ("target", "next_action", "updated", "verdict_note", "goal_route"))
    _choice(state, "schema", {"seep-case/1"})
    _choice(state, "stage", STAGES)
    _choice(state, "verdict", {"可赢", "部分可赢", "不可赢"}, nullable=True)
    # Archived cases also used L0-L4 here. Preserve the original vocabulary;
    # delivery still enforces its own M-level contract and conservative cap.
    _choice(state, "max_level", {"M1", "M2", "M3", "M4", "L0", "L1", "L2", "L3", "L4"}, nullable=True)
    for name, status_field, choices in (("depth", "result", {"pass", "fail", "na"}),
                                        ("instruments", "status", {"ok", "partial", "blocked", "killed"})):
        if name not in state:
            continue  # Partial legacy state still overlays the reader's defaults.
        entries = state[name]
        if not isinstance(entries, dict):
            raise ValueError("%s must be an object" % name)
        for entry in entries.values():
            if not isinstance(entry, dict) or status_field not in entry:
                raise ValueError("invalid %s entry" % name)
            _choice(entry, status_field, choices)
            _strings(entry, ("note", "launch", "ts"))
    for name in ("stage_history", "deliveries", "asks"):
        if name in state:
            _objects(state[name], name)
    for entry in state.get("stage_history", []):
        _strings(entry, ("from", "to", "stage", "reason", "ts"))
        if "forced" in entry and type(entry["forced"]) is not bool:
            raise ValueError("forced must be a boolean")
    for entry in state.get("deliveries", []):
        _choice(entry, "level", {"M1", "M2", "M3", "M4"})
        _strings(entry, ("evidence", "note", "ts"))
    awaiting = state.get("awaiting_human")
    if awaiting is not None:
        if not isinstance(awaiting, dict):
            raise ValueError("awaiting_human must be an object")
        _strings(awaiting, ("since", "card", "stuck", "ack", "acked_at"), nullable=("ack",))
        if "acked" in awaiting and type(awaiting["acked"]) is not bool:
            raise ValueError("acked must be a boolean")
        options = awaiting.get("options", {})
        if not isinstance(options, dict) or any(not isinstance(v, str) for v in options.values()):
            raise ValueError("awaiting_human.options must be an object of strings")


def validate_row(row):
    if not isinstance(row, dict):
        raise ValueError("ledger row must be an object")
    tag = kind(row)
    if tag in ("", "claim"):
        for name in ("id", "claim", "status"):
            if not isinstance(row.get(name), str) or not row[name].strip():
                raise ValueError("claim requires nonempty %s" % name)
        _choice(row, "status", STATUSES)
        _choice(row, "confidence", CONFIDENCE)
        _choice(row, "authority", AUTHORITY)
        evidence = row.get("evidence", [])
        if not isinstance(evidence, list) or any(not isinstance(item, str) or not item.strip() for item in evidence):
            raise ValueError("claim evidence must be an array of nonempty strings")
        _strings(row, ("how", "ttl", "created", "updated", "refuted_by"), nullable=("refuted_by",))
        if "stale_history" in row:
            _objects(row["stale_history"], "stale_history")
        if "evidence_bindings" in row:
            _objects(row["evidence_bindings"], "evidence_bindings")
            for binding in row["evidence_bindings"]:
                if not isinstance(binding.get("evidence"), str):
                    raise ValueError("evidence binding requires its source reference")
                _objects(binding.get("files"), "evidence binding files")
        if "evidence_binding_history" in row:
            history = row["evidence_binding_history"]
            if not isinstance(history, list):
                raise ValueError("evidence binding history must be an array")
            for prior in history:
                _objects(prior, "previous evidence bindings")
    elif tag == "state":
        validate_state(row.get("state"))
    elif tag in ("gaps", "plan"):
        items = row.get("items")
        _objects(items, tag + ".items")
        for item in items:
            _strings(item, ("id", "level", "route", "hours", "needs", "fail_criteria",
                            "missing", "impact", "repairable", "ts"))
            if "alt" in item and (not isinstance(item["alt"], list)
                                  or any(not isinstance(value, str) for value in item["alt"])):
                raise ValueError("alt must be an array of strings")
            for name in ("p", "delta"):
                if name in item and (type(item[name]) not in (int, float) or not math.isfinite(item[name])):
                    raise ValueError("%s must be a finite number" % name)
            if "chosen" in item and type(item["chosen"]) is not bool:
                raise ValueError("chosen must be a boolean")
    elif tag == "repro":
        if not isinstance(row.get("id"), str) or not row["id"].strip():
            raise ValueError("repro requires nonempty id")
        # Historical replay records remain readable. Acceptance checks their full
        # execution contract, including schema, return codes, target and captures.
    elif "claim" in row:
        raise ValueError("claim text requires kind=claim, not an opaque extension kind")


def validate_rows(rows):
    ids = set()
    for number, row in enumerate(rows, 1):
        try:
            validate_row(row)
            if kind(row) in ("", "claim", "repro"):
                identifier = row["id"].strip().casefold()
                if identifier in ids:
                    raise ValueError("duplicate claim/repro id: %s" % row["id"])
                ids.add(identifier)
        except (ValueError, TypeError) as exc:
            raise ValueError("facts.jsonl line %d: %s" % (number, exc)) from exc


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: %s" % key)
        result[key] = value
    return result


def root_path(case):
    root = _plain(Path(os.path.abspath(case)))
    if not root.is_dir():
        raise ValueError("case directory is missing")
    _local(root, ".project.lock")
    _local(root, ".project-transaction.json")
    _local(root, "facts.jsonl")
    return root


def read(case, *, lock=True):
    """Read and validate a ledger.

    ``lock=False`` is reserved for explicit read-only compatibility views.
    Ledger replacements are atomic, so those readers still observe a complete
    old or new file.  Normal readers retain the inter-process lock.
    """
    root = root_path(case)
    if lock:
        with project_lock(root):
            return _read_rows(root)
    return _read_rows(root)


def _read_rows(root):
    path = _local(root, "facts.jsonl")
    if not path.exists():
        return []
    if not path.is_file():
        raise ValueError("facts.jsonl must be a regular file")
    rows, ids = [], set()
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line, object_pairs_hook=_unique,
                                 parse_constant=lambda value: _invalid_constant(value))
                validate_row(row)
                if kind(row) in ("", "claim", "repro"):
                    identifier = row["id"].strip().casefold()
                    if identifier in ids:
                        raise ValueError("duplicate claim/repro id: %s" % row["id"])
                    ids.add(identifier)
                rows.append(row)
            except (ValueError, TypeError) as exc:
                raise ValueError("facts.jsonl line %d: %s" % (number, exc)) from exc
    validate_archives(root, rows)
    return rows


def _invalid_constant(value):
    raise ValueError("non-finite JSON number: %s" % value)


def locked(function):
    """Serialize public storage calls too, including calls outside the CLI."""
    @functools.wraps(function)
    def invoke(case, *args, **kwargs):
        # case_state's legacy API reports invalid storage through SystemExit(2).
        try:
            root = root_path(case)
            with project_lock(root):
                return function(case, *args, **kwargs)
        except (ValueError, TypeError, TimeoutError) as exc:
            print("[ERR] case ledger refused: %s" % exc)
            raise SystemExit(2) from exc
    return invoke
