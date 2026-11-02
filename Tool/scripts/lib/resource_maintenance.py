"""Bounded knowledge maintenance using existing locks, transactions and budget.

No model, network, target execution, skill installation, git commit or push.
Semantic novelty and professional validity remain caller-declared judgments.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
import uuid

from .resource_sources import (Sources, SourceError, META_PREFIX, META_SCHEMA, MAX_FILE,
                               contained, linked, metadata, article_reference, relative, read_document)
from .project_lock import project_lock
from .project_transaction import file_transaction, _replace, _load, recover as recover_transaction, pending
from .source_inventory import inventory

PLAN_SCHEMA = "seep.knowledge-plan/1"
BACKUP_SCHEMA = "seep.knowledge-backup/1"
_ID = re.compile(r"[a-z][a-z0-9_.-]{0,95}\Z")
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_PRIVATE_URL = re.compile(r"[a-z]+://[^\s/@:]+:[^\s/@]+@", re.I)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _text(value, limit=4000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise SourceError("knowledge_text_invalid")
    return value.strip()


def _secret_free(repo, text):
    # Apply the existing detector without filename exemptions or echoing matches.
    path = Path(__file__).resolve().parents[1] / "pre-upload-check.py"
    spec = importlib.util.spec_from_file_location("knowledge_upload_policy", path)
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    if _PRIVATE_URL.search(text):
        raise SourceError("knowledge_private_material_detected")
    for rule, pattern in policy.CONTENT_RULES:
        for match in pattern.finditer(text):
            if rule in {"Bearer 令牌", "凭据赋值"}:
                value = match.group(1 if rule == "Bearer 令牌" else 3)
                if policy.PLACEHOLDER.match(value) or policy._value_is_placeholder(value):
                    continue
                if rule == "凭据赋值" and (not any(c.isdigit() for c in value)
                        or not any(c.isalpha() for c in value) or policy._entropy(value) < 3.3):
                    continue
            raise SourceError("knowledge_private_material_detected")


def read_resource(repo, ident):
    if not isinstance(ident, str) or ":" not in ident:
        raise SourceError("resource_reference_invalid")
    kind, tail = ident.split(":", 1)
    if kind not in {"knowledge", "skill"} or "/" not in tail:
        raise SourceError("resource_reference_invalid")
    source_id, rel = tail.split("/", 1)
    sources = Sources(repo)
    source = sources.get(source_id)
    if source["kind"] != kind or ident in sources.disabled:
        raise SourceError("resource_reference_disabled")
    path = contained(source["root"], rel)
    if not path.is_file() or path.stat().st_size > MAX_FILE or not rel.endswith(".md"):
        raise SourceError("resource_unavailable_or_oversized")
    raw = read_document(path)
    return {"resource_id": ident, "visibility": source["visibility"], "sha256": digest(raw),
            "text": raw.decode("utf-8-sig"), "instructions_trusted": False}


def _body(text):
    return (text.split("\n", 1)[1] if text.startswith(META_PREFIX) else text).strip().replace("\r\n", "\n")


def _target(source, rel):
    relative(rel)
    protected = {"agents.md", "claude.md", "seep.md", "rules.md", "personality.md", "skill.md"}
    if (source["kind"] != "knowledge" or not rel.endswith(".md")
            or any(part.startswith(".") for part in rel.split("/"))
            or Path(rel).name.lower() in protected
            or any((source["root"] / name).exists() for name in ("project.json", "case.json"))):
        raise SourceError("knowledge_markdown_path_required")
    return contained(source["root"], rel)


def _corpus(repo):
    sources = Sources(repo)
    rows = []
    for source, rel, path, ident in sources.documents("knowledge"):
        raw = read_document(path)
        text = raw.decode("utf-8-sig")
        meta = metadata(text) or {}
        rows.append({"resource_id": ident, "sha256": digest(raw), "text": text,
                     "meta": meta, "article_path": article_reference(source["id"], rel),
                     "visibility": source["visibility"]})
    version = digest(json.dumps(sorted((r["resource_id"], r["sha256"]) for r in rows)).encode())
    return sources, rows, version


def inspect(repo, query, text="", limit=5):
    from .capability_discovery import _score, _terms
    _text(query, 2000)
    if type(limit) is not int or not 1 <= limit <= 20:
        raise SourceError("knowledge_limit_invalid")
    sources, rows, revision = _corpus(repo)
    matches = []
    for row in rows:
        meta = row["meta"]
        title = meta.get("title") or next((v[2:] for v in row["text"].splitlines() if v.startswith("# ")), "")
        score, terms = _score(str(title) + " " + str(meta.get("summary", "")) + " " + str(meta.get("tags", []))
                              + " " + _body(row["text"])[:8000], _terms(query))
        if 2 <= len(query.strip()) <= 40 and query.strip().lower() in str(title).lower():
            score += 8
        exact = bool(text.strip()) and _body(text) == _body(row["text"])
        if score or exact:
            matches.append({k: row[k] for k in ("resource_id", "sha256", "article_path", "visibility")}
                           | {"title": title, "score": score, "matched_terms": terms, "same_body": exact,
                              "maturity": meta.get("maturity", "unclassified")})
    matches.sort(key=lambda r: (not r["same_body"], -r["score"], r["resource_id"]))
    return {"schema": "seep.knowledge-comparison/1", "source_revision": sources.revision,
            "corpus_revision": revision, "candidates": matches[:limit], "total_matches": len(matches),
            "semantic_equivalence_verified": False, "next": "Read candidates and compare scope; do not blindly append."}


def _evidence(project, rows):
    if not rows:
        return []
    if not project or not isinstance(rows, list) or len(rows) > 8:
        raise SourceError("knowledge_evidence_invalid")
    root = Path(project).resolve()
    out, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"id", "path", "sha256"}:
            raise SourceError("knowledge_evidence_invalid")
        if not isinstance(row["id"], str) or not _ID.fullmatch(row["id"]) or row["id"] in seen:
            raise SourceError("knowledge_evidence_invalid")
        seen.add(row["id"])
        path = contained(root, row["path"])
        if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
            raise SourceError("knowledge_evidence_changed")
        with path.open("rb") as stream:
            raw = stream.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024 or digest(raw) != row["sha256"]:
            raise SourceError("knowledge_evidence_changed")
        out.append({"id": row["id"], "sha256": row["sha256"]})
    return out


def _validate_meta(repo, obj, evidence):
    fields = {"id", "title", "summary", "tags", "applies_to", "maturity", "sources", "counterexamples"}
    if not isinstance(obj, dict) or set(obj) != fields or not isinstance(obj["id"], str) or not _ID.fullmatch(obj["id"]):
        raise SourceError("knowledge_metadata_fields_invalid")
    for field, size in (("title", 160), ("summary", 1200), ("applies_to", 2000)):
        _text(obj[field], size)
    if (not isinstance(obj["tags"], list) or not 1 <= len(obj["tags"]) <= 12
            or any(not isinstance(v, str) or not 1 <= len(v.strip()) <= 60 for v in obj["tags"])
            or not isinstance(obj["maturity"], str) or obj["maturity"] not in {"reference", "case", "method", "retired"}
            or not isinstance(obj["sources"], list) or len(obj["sources"]) > 8
            or not isinstance(obj["counterexamples"], str) or len(obj["counterexamples"]) > 2000):
        raise SourceError("knowledge_metadata_values_invalid")
    for url in obj["sources"]:
        if not isinstance(url, str) or len(url) > 1000:
            raise SourceError("knowledge_source_url_invalid")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.query or "=" in parsed.fragment:
            raise SourceError("knowledge_source_url_invalid")
    if obj["maturity"] == "reference" and not obj["sources"]:
        raise SourceError("knowledge_reference_requires_source")
    if obj["maturity"] in {"case", "method"} and not evidence:
        raise SourceError("knowledge_case_requires_evidence")
    if obj["maturity"] == "method" and not obj["counterexamples"].strip():
        raise SourceError("knowledge_method_requires_counterexample")
    _secret_free(repo, json.dumps(obj, ensure_ascii=False))


def prepare(repo, request):
    fields = {"source_id", "path", "body", "metadata", "reason", "expected_sha256", "reviewed",
              "project", "evidence", "queries"}
    if not isinstance(request, dict) or set(request) != fields:
        raise SourceError("knowledge_request_fields_invalid")
    sources, rows, corpus_revision = _corpus(repo)
    source = sources.get(request["source_id"], writable=True)
    if source["kind"] != "knowledge":
        raise SourceError("knowledge_write_source_required")
    rel = relative(request["path"])
    path = _target(source, rel)
    expected = digest(path.read_bytes()) if path.is_file() else "absent"
    if expected != request["expected_sha256"]:
        raise SourceError("knowledge_target_changed")
    _text(request["reason"], 2000)
    _secret_free(repo, request["reason"])
    body = _text(request["body"], MAX_FILE // 2)
    if body.startswith(META_PREFIX):
        raise SourceError("knowledge_body_must_not_supply_metadata")
    evidence = _evidence(request["project"], request["evidence"])
    _validate_meta(repo, request["metadata"], evidence)
    _secret_free(repo, body)
    queries = request["queries"]
    if not isinstance(queries, list) or not 1 <= len(queries) <= 3:
        raise SourceError("knowledge_verification_queries_required")
    for query in queries:
        _text(query, 200)
    target_id = "knowledge:" + source["id"] + "/" + rel
    if target_id in sources.disabled:
        raise SourceError("knowledge_target_disabled")
    if path.is_file():
        previous = path.read_text(encoding="utf-8-sig")
        prior_meta = metadata(previous) or {}
        if prior_meta.get("id") and prior_meta["id"] != request["metadata"]["id"]:
            raise SourceError("knowledge_stable_id_changed")
        if _body(previous) == body and all(prior_meta.get(k) == v for k, v in request["metadata"].items()):
            return {"schema": PLAN_SCHEMA, "action": "noop", "duplicate_of": target_id,
                    "reason": "same_content_and_metadata", "semantic_equivalence_verified": False}
    for row in rows:
        if row["resource_id"] != target_id and row["meta"].get("id") == request["metadata"]["id"]:
            raise SourceError("knowledge_stable_id_already_exists")
        if (row["resource_id"] != target_id and _body(row["text"]) == body
                and row["meta"].get("applies_to", "") == request["metadata"]["applies_to"]):
            return {"schema": PLAN_SCHEMA, "action": "noop", "duplicate_of": row["resource_id"],
                    "reason": "same_body_and_scope", "semantic_equivalence_verified": False}
    comparison = inspect(repo, request["metadata"]["title"] + " " + " ".join(request["metadata"]["tags"]), body)
    reviewed = request["reviewed"]
    if not isinstance(reviewed, list) or len(reviewed) > 20:
        raise SourceError("knowledge_review_invalid")
    checked = {}
    for row in reviewed:
        if not isinstance(row, dict) or set(row) != {"resource_id", "sha256", "decision"}:
            raise SourceError("knowledge_review_invalid")
        _text(row["decision"], 1000)
        checked[row["resource_id"]] = row["sha256"]
    required = comparison["candidates"]
    if any(checked.get(row["resource_id"]) != row["sha256"] for row in required):
        return {"schema": PLAN_SCHEMA, "action": "review_required", "comparison": comparison,
                "next": "Read the returned candidates, then supply their hashes and comparison decisions."}
    actual = {r["resource_id"]: r["sha256"] for r in rows}
    if any(actual.get(ident) != h for ident, h in checked.items()):
        raise SourceError("knowledge_review_changed")
    meta = {"schema": META_SCHEMA, **request["metadata"], "evidence": evidence,
            "revision_reason": request["reason"], "assessment_source": "caller_declared",
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    content = META_PREFIX + json.dumps(meta, ensure_ascii=False, sort_keys=True) + " -->\n\n" + body + "\n"
    if len(content.encode()) > MAX_FILE or len(content.split("\n", 1)[0]) > 16384:
        raise SourceError("knowledge_content_budget_exceeded")
    return {"schema": PLAN_SCHEMA, "action": "create" if expected == "absent" else "update",
            "source_revision": sources.revision, "corpus_revision": corpus_revision,
            "request": request, "content": content, "content_sha256": digest(content.encode()),
            "semantic_equivalence_verified": False, "automatic_publication": False}


def _budget(repo):
    import budget
    inv = inventory(repo)
    if not inv.get("source_complete") or not inv.get("stable") or inv.get("mode") == "unverified":
        raise SourceError("knowledge_source_inventory_unverified")
    return inv["counts"]["first_party"], budget.FIRST_PARTY_LIMIT


def _backup_root(value=None):
    raw = Path(value or Path.home() / ".seep/resource-backups").expanduser().absolute()
    if raw == raw.parent or any(linked(part) for part in (raw, *raw.parents)):
        raise SourceError("knowledge_backup_root_invalid")
    return raw


def apply(repo, plan, *, backups=None):
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise SourceError("knowledge_plan_invalid")
    if plan.get("action") == "noop":
        return {"ok": True, "changed": False, "action": "noop"}
    if plan.get("action") not in {"create", "update"}:
        raise SourceError("knowledge_plan_not_ready")
    sources = Sources(repo)
    request = plan["request"]
    source = sources.get(request["source_id"], writable=True)
    folder = source["root"]
    with project_lock(folder):
        checked = prepare(repo, request)
        if (checked.get("action") != plan["action"] or sources.revision != plan["source_revision"]
                or checked.get("corpus_revision") != plan["corpus_revision"]
                or digest(plan["content"].encode()) != plan["content_sha256"]):
            raise SourceError("knowledge_plan_stale")
        # Reconstructed content may have a fresh timestamp; compare all other fields.
        proposed = metadata(plan["content"])
        fresh = metadata(checked["content"])
        if proposed is None or {k: v for k, v in proposed.items() if k != "updated_at"} != {k: v for k, v in fresh.items() if k != "updated_at"} or _body(plan["content"]) != _body(checked["content"]):
            raise SourceError("knowledge_plan_content_changed")
        if not isinstance(proposed.get("updated_at"), str) or len(proposed["updated_at"]) > 64:
            raise SourceError("knowledge_plan_timestamp_invalid")
        datetime.datetime.fromisoformat(proposed["updated_at"])
        _secret_free(repo, plan["content"])
        path = contained(folder, request["path"])
        shared = source["visibility"] == "shared"
        if shared and plan["action"] == "create":
            count, limit = _budget(repo)
            if count + 1 > limit:
                raise SourceError("knowledge_first_party_budget_exceeded")
        backup_root = _backup_root(backups)
        if backup_root.is_relative_to(Path(repo).resolve()) or any(backup_root.is_relative_to(r["root"]) for r in sources.rows):
            raise SourceError("knowledge_backup_must_be_outside_sources")
        backup_root.mkdir(parents=True, exist_ok=True)
        previous = path.read_bytes() if path.is_file() else None
        record = {"schema": BACKUP_SCHEMA, "source_id": source["id"], "relative_path": request["path"],
                  "source_revision": sources.revision, "after_sha256": plan["content_sha256"],
                  "before_sha256": digest(previous) if previous is not None else "absent",
                  "before": base64.b64encode(previous).decode() if previous is not None else None}
        receipt = backup_root / (uuid.uuid4().hex + ".json")
        _replace(receipt, (json.dumps(record) + "\n").encode())
        directories = [p.relative_to(folder).as_posix() for p in reversed(path.parent.parents)
                       if p != folder and p.is_relative_to(folder)]
        if path.parent != folder:
            directories.append(path.parent.relative_to(folder).as_posix())
        with file_transaction(folder, [request["path"]], directories=directories):
            path.parent.mkdir(parents=True, exist_ok=True)
            _replace(path, plan["content"].encode())
            restored = read_resource(repo, "knowledge:" + source["id"] + "/" + request["path"])
            if restored["sha256"] != plan["content_sha256"]:
                raise SourceError("knowledge_write_verification_failed")
            for query in request["queries"]:
                view = inspect(repo, query, limit=20)
                if proposed["maturity"] != "retired" and not any(r["resource_id"] == restored["resource_id"] for r in view["candidates"]):
                    raise SourceError("knowledge_query_verification_failed")
            if shared and plan["action"] == "create":
                count, limit = _budget(repo)
                if count > limit:
                    raise SourceError("knowledge_first_party_budget_exceeded")
        return {"ok": True, "changed": True, "action": plan["action"], "resource_id": restored["resource_id"],
                "sha256": restored["sha256"], "backup_receipt": str(receipt), "readback_verified": True,
                "query_verified": True, "professional_validity_verified": False,
                "automatic_publication": False, "visibility": source["visibility"]}


def restore(repo, receipt, *, backups=None):
    root = _backup_root(backups)
    raw = Path(receipt).absolute()
    if raw.parent != root or linked(raw) or raw.stat().st_size > MAX_FILE * 2:
        raise SourceError("knowledge_backup_reference_invalid")
    record = json.loads(raw.read_text(encoding="utf-8"))
    sources = Sources(repo)
    source = sources.get(record["source_id"], writable=True)
    if source["kind"] != "knowledge" or not relative(record["relative_path"]).endswith(".md"):
        raise SourceError("knowledge_restore_target_invalid")
    if record.get("schema") != BACKUP_SCHEMA or record["source_revision"] != sources.revision:
        raise SourceError("knowledge_backup_source_changed")
    path = _target(source, record["relative_path"])
    with project_lock(source["root"]):
        if not path.is_file() or digest(path.read_bytes()) != record["after_sha256"]:
            raise SourceError("knowledge_restore_would_overwrite_later_change")
        previous = base64.b64decode(record["before"], validate=True) if record["before"] is not None else None
        if (digest(previous) if previous is not None else "absent") != record["before_sha256"]:
            raise SourceError("knowledge_backup_fingerprint_invalid")
        with file_transaction(source["root"], [record["relative_path"]]):
            if previous is None:
                path.unlink()
            else:
                _secret_free(repo, previous.decode("utf-8-sig"))
                _replace(path, previous)
        return {"ok": True, "restored": True, "resource_id": "knowledge:" + source["id"] + "/" + record["relative_path"],
                "automatic_publication": False}


def backups_view(repo, *, backups=None):
    root = _backup_root(backups)
    sources = Sources(repo)
    rows = []
    if not root.is_dir():
        return {"ok": True, "backups": rows}
    for index, path in enumerate(sorted(root.glob("*.json"))):
        if index >= 100:
            return {"ok": True, "backups": rows, "truncated": True}
        if linked(path) or path.stat().st_size > MAX_FILE * 2:
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("schema") == BACKUP_SCHEMA and record.get("source_revision") == sources.revision:
            rows.append({"receipt": str(path), "source_id": record["source_id"],
                         "path": record["relative_path"], "after_sha256": record["after_sha256"]})
    return {"ok": True, "backups": rows, "truncated": False}


def recover(repo, receipt, *, backups=None):
    """Recover only a journal independently matched to this operation's backup."""
    root = _backup_root(backups)
    raw = Path(receipt).absolute()
    if raw.parent != root or linked(raw) or raw.stat().st_size > MAX_FILE * 2:
        raise SourceError("knowledge_backup_reference_invalid")
    record = json.loads(raw.read_text(encoding="utf-8"))
    sources = Sources(repo)
    source = sources.get(record["source_id"], writable=True)
    if (record.get("schema") != BACKUP_SCHEMA or source["kind"] != "knowledge"
            or record["source_revision"] != sources.revision):
        raise SourceError("knowledge_backup_source_changed")
    path = _target(source, record["relative_path"])
    if not record["relative_path"].endswith(".md"):
        raise SourceError("knowledge_restore_target_invalid")
    before = base64.b64decode(record["before"], validate=True) if record["before"] is not None else None
    if (digest(before) if before is not None else "absent") != record["before_sha256"]:
        raise SourceError("knowledge_backup_fingerprint_invalid")
    with project_lock(source["root"], allow_pending=True):
        if not pending(source["root"]):
            raise SourceError("knowledge_no_pending_transaction")
        files, _directories = _load(source["root"])
        if len(files) != 1 or files[0][0] != path or files[0][1] != before:
            raise SourceError("knowledge_journal_not_owned_by_receipt")
        if any(directory not in path.parents for directory in _directories):
            raise SourceError("knowledge_journal_directory_not_owned")
        current = digest(read_document(path)) if path.is_file() else "absent"
        if current not in {record["before_sha256"], record["after_sha256"]}:
            raise SourceError("knowledge_recovery_would_overwrite_later_change")
        if before is not None:
            _secret_free(repo, before.decode("utf-8-sig"))
        recover_transaction(source["root"])
        return {"ok": True, "recovered": True, "automatic_publication": False}
