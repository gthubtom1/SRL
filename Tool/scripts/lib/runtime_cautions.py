"""Portable risk notices projected from the existing project fact ledger.

This is not a dispatch budget or authorization service. No network, process,
RiskStore access, new ledger, or automatic resume is performed here.
"""
from __future__ import annotations

import json
import re
from .runtime_risk import reference

TYPES = frozenset(("runtime_caution", "runtime_caution_resolved"))
_ID = re.compile(r"[A-Za-z0-9_.-]{1,96}\Z")
_PRIVATE = re.compile(r"\bbearer\s+\S+|(?:password|token|secret|cookie|authorization)\s*[:=]\s*\S+|"
                      r"-----BEGIN .*PRIVATE KEY|\bsk-[A-Za-z0-9_-]{12,}|"
                      r"[a-z]+://[^\s/@:]+:[^\s/@]+@", re.I)


def payload(event):
    raw = event.get("message")
    if not isinstance(raw, str) or len(raw) > 8192 or _PRIVATE.search(raw):
        raise ValueError("runtime caution requires bounded, non-secret JSON")
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate caution field")
            out[key] = value
        return out
    try:
        obj = json.loads(raw, object_pairs_hook=unique)
    except RecursionError:
        raise ValueError("runtime caution nesting too deep") from None
    common = {"caution_id", "reason", "evidence_ids"}
    opening = event.get("type") == "runtime_caution"
    fields = common | ({"scope", "subject_ref", "assessment", "affected_actions", "resume_when", "safe_next"} if opening else set())
    if not isinstance(obj, dict) or set(obj) != fields:
        raise ValueError("runtime caution fields invalid")
    if not isinstance(obj["caution_id"], str) or not _ID.fullmatch(obj["caution_id"]):
        raise ValueError("runtime caution id invalid")
    for field in ("reason", "resume_when", "safe_next") if opening else ("reason",):
        if not isinstance(obj[field], str) or not 1 <= len(obj[field].strip()) <= 1000:
            raise ValueError("runtime caution text invalid")
    evidence = obj["evidence_ids"]
    if (not isinstance(evidence, list) or not 1 <= len(evidence) <= 8 or
            any(not isinstance(v, str) or not _ID.fullmatch(v) for v in evidence) or len(set(evidence)) != len(evidence)):
        raise ValueError("runtime caution evidence ids invalid")
    if not event.get("version_id") or not event.get("run_id"):
        raise ValueError("runtime caution requires source version and run")
    if opening:
        if obj["scope"] not in {"identity", "target", "environment"} or obj["assessment"] not in {"observed", "suspected"}:
            raise ValueError("runtime caution scope or assessment invalid")
        ref = obj["subject_ref"]
        if not isinstance(ref, str) or len(ref) > 96 or (obj["scope"] == "identity" and not ref.strip()):
            raise ValueError("runtime caution identity requires a stable non-secret reference")
        if ref:
            reference(ref)
        actions = obj["affected_actions"]
        if not isinstance(actions, list) or not 1 <= len(actions) <= 12 or any(
                not isinstance(v, str) or not 1 <= len(v.strip()) <= 200 for v in actions):
            raise ValueError("runtime caution affected actions invalid")
    return obj


def project(events, current_version, check_binding):
    """Replay notices; source provenance is never a run-expiration rule."""
    active, known, errors = {}, set(), []
    for event in events:
        if event.get("type") not in TYPES:
            continue
        try:
            obj = payload(event)
            key = obj["caution_id"]
            opening = event["type"] == "runtime_caution"
            if opening and key in known:
                raise ValueError("runtime caution id already used")
            if not opening and key not in active:
                raise ValueError("runtime caution resolution has no open notice")
            if opening:
                known.add(key)
                # Broken provenance must not make the warning disappear.
                active[key] = {**obj, "source": {k: event.get(k) for k in ("project_id", "version_id", "run_id")},
                               "event_id": event["id"], "evidence_status": "unverified",
                               "applicability": "recorded_scope"}
            source = check_binding(event, obj["evidence_ids"])
            if opening:
                active[key].update(source=source, evidence_status="verified")
            else:
                del active[key]
        except (ValueError, OSError, KeyError, TypeError) as exc:
            errors.append({"event_id": event.get("id"), "reason": "runtime caution: " + str(exc)[:240]})
    for notice in active.values():
        if notice["scope"] == "target" and notice["source"]["version_id"] != current_version:
            notice["applicability"] = "requires_reassessment_for_current_target"
    return {"schema": "seep.runtime-cautions/1", "open": list(active.values()), "errors": errors,
            "external_coordination": "not_checked_query_existing_runtime_risk_before_remote_actions",
            "offline_work_allowed": True, "globally_enforced": False, "automatic_resume": False}
