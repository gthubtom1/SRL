#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Project report ledger: ``report_id`` + five-section body + tamper-evident manifest.

Scope of this module (deliberately small):

* ``generate``  - compose a five-section report from the *registered* ledger
                  (project/version/run, target fingerprint, evidence index,
                  acceptance revisions, run events) and register it.
* ``register``  - register an existing project-relative body file with exactly
                  the same binding rules (no second validator).
* ``show``      - re-verify one registered report and report ``stale`` items.
* ``status``    - list the index, the current final pointer and every stale item.

Hard boundaries (aligned with ``REQUIREMENTS.md`` and ``docs/CURRENT-STATE.md``):

* It writes **only** inside ``<explicit project>/reports/`` (plus the
  ``report_registered`` event through ``project_state.write_event`` and the
  derived ``handoff.json`` through ``project_state.write_handoff``).
* It reuses ``project_state``'s read-only helpers, its evidence-index
  cross-check and its unified closure audit instead of copying a second
  acceptance/evidence validator.  All calls are *undecorated* helpers, so the
  shared ``project_lock`` is taken exactly once (no nested lock deadlock).
* A report never invents a professional claim: exit 0, generated files, unique
  AOB matches or non-empty logs are not functional success.  Unknown/failed/
  skipped items are listed as unknowns; ``final`` only means "this run's final
  record", not "the Goal passed".
* Registered reports are immutable: the same ``report_id`` with different content
  (or a changed source binding) is refused, never silently regenerated.  A
  changed body, changed evidence, changed target, removed metadata or a broken
  index entry makes the report ``stale``.
Integration status is *detected*, not asserted (``core_handoff_status()``):

* ``core_handoff_wired``      ``project_state`` itself carries the merged hook
                              (``_report_handoff_view`` callable), so
                              ``resume``/``handoff`` really project this index.
* ``integration_pending``     the opposite (module used against a Pstate without
                              the hook).  Never claimed while the hook is absent.
* ``pending_scopes``          what is still *not* wired and must not be implied:
                              ``workflow.close_status``, ``archive_export_import``,
                              ``typed_assets``, ``report_claim_ledger``.

None of these say the Goal / nine domains are integrated; they only describe this
report layer's own wiring.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import project_state as P  # noqa: E402  (read-only helpers + unified audit)
from lib.project_lock import project_locked, project_file, verify_file  # noqa: E402
from lib.project_transaction import file_transaction  # noqa: E402
from manager_state import reject_sensitive, scrub  # noqa: E402  (conservative credential guard)

REPORT_SCHEMA = "seep-report/1"
MANIFEST_SCHEMA = "seep-report-manifest/1"
INDEX_SCHEMA = "seep-report-index/1"
FINAL_SCHEMA = "seep-report-final/1"
HANDOFF_SCHEMA = "seep-report-handoff/1"
REPORT_KINDS = ("interim", "final")
SECTIONS = ("结论", "已确认", "仍未知", "下一步", "复查")
BANNED_PHRASES = ("应该可以", "大概能", "通常没问题")
INDEX_NAME = "reports/index.jsonl"
# Values the append-only ``report_registered`` fact carries so the registration is
# witnessed outside the three report files (facts.jsonl is not writable by hand
# here without showing up as a changed cited set).  Not a signature system.
REPORT_WITNESS_KEYS = ("report_id", "report_kind", "version_id", "run_id", "project_id",
                       "body_sha256", "body_size", "manifest_sha256", "binding_sha256")
FINAL_NAME = "reports/final.json"
MAX_BODY_BYTES = 256 * 1024
MAX_CLAIM_LEDGER_BYTES = 512 * 1024
MAX_CLAIM_LEDGER_LINES = 4096
CLAIM_FIELDS = ("id", "claim", "status", "evidence", "how", "ttl", "created",
                "confidence", "authority", "refuted_by")
# Integration scopes are listed separately from the Core report hook; each
# flag describes the capability named by that row, not whole-product readiness.
PENDING_SCOPES = (
    {"scope": "workflow.close_status", "wired": True,
     "note": "project_workflow status/close 消费 project_state Core health 与报告视图"},
    {"scope": "archive_export_import", "wired": True,
     "note": "project_archive export/verify/import 已独立验收三类工程与报告的移位闭包；跨OS实机未验证"},
    {"scope": "typed_assets", "wired": True,
     "note": "报告通过 project_state.verify_target 消费 file/directory/url_descriptor 的显式身份"},
    {"scope": "report_claim_ledger", "wired": True,
     "note": "generate 可选消费已由 Core evidence 登记且同 version/run/target 绑定的 claim ledger；弱/无支持 claim 只列 unknown"},
)


def core_handoff_status() -> dict:
    """Read-only detection of the *actual* project_state hook (never asserts it).

    Integration is a fact about the source we are imported next to, so it is
    probed by capability rather than declared.  A module running beside an
    unmerged Pstate reports ``integration_pending=True``; nothing silently claims
    to be wired.
    """
    wired = callable(getattr(P, "_report_handoff_view", None))
    return {
        "core_handoff_wired": wired,
        "core_handoff_probe": "_report_handoff_view" if wired else None,
        "integration_pending": not wired,
        "pending_scopes": [dict(item) for item in PENDING_SCOPES],
        "note": ("Core 报告层已由 project_state.write_handoff 投影（resume/handoff 会读索引与"
                 "当前 final 指针）；仍 pending 的是上面 pending_scopes 各自列出的范围，"
                 "不代表整个 Goal 或九域集成完成" if wired else
                 "当前 project_state 没有报告投影钩子：报告层独立可用，但 resume/handoff 不读索引"),
    }
# The exact (undecorated) project_state surface this module consumes.  It is
# deliberately a *read* surface plus ``write_event``/``write_handoff`` (the two
# writes project_state itself already performs under the same lock).  A rename in
# a newer project_state.py is reported as an explicit refusal instead of being
# silently replaced by a second copy of the audit.
PSTATE_API = ("require_project", "require_id", "relative_ref", "load_json",
              "project_root", "now", "sha256_file", "atomic_json", "atomic_bytes",
              "append_jsonl", "write_event", "write_handoff", "read_fact_log",
              "_validate_version", "_run_record", "_asset_record", "_evidence_path",
              "_evidence_index_problems", "_acceptance_path", "load_acceptance",
              "acceptance_items", "_origin_of", "_acceptance_chain",
              "_acceptance_revision_path", "_revision_document", "_acceptance_state",
              "target_fingerprint", "verify_target", "_load_ledger", "_audit_ledger", "_audit_run", "closure_seal",
              "PROOF_LEVEL", "PROOF_LIMITS", "METADATA_NAMES", "RUN_END_STATUSES",
              "EVIDENCE_SCHEMA")


def _require_pstate_api() -> None:
    missing = [name for name in PSTATE_API if not hasattr(P, name)]
    if missing:
        raise RuntimeError("project_state 公开接口已变更，缺少：%s（本模块不复制审计，请按新版适配）"
                           % ",".join(missing))

# ---------------------------------------------------------------------------
# small shared helpers (no project writes)
# ---------------------------------------------------------------------------
def _sha(path: Path) -> str:
    return P.sha256_file(str(path))

def _canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")

def _hash_object(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()

def _text_sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _empty_claims() -> dict:
    return {"selected_evidence_ids": [], "sources": [], "records": [],
            "confirmed_ids": [], "unknown_ids": [],
            "claims_sha256": _hash_object({"selected_evidence_ids": [],
                                            "sources": [], "records": []})}


def _claim_evidence_records(root: Path, project: dict, version_id: str) -> dict[str, dict]:
    records = {}
    directory = _local_path(root, "versions/%s/evidence" % P.require_id(version_id, "version"))
    for path in sorted(directory.glob("*.json")):
        path = _local_path(root, _rel(root, path))
        record = P.load_json(path)
        evidence_id = str(record.get("evidence_id") or "")
        if record.get("schema") != P.EVIDENCE_SCHEMA or evidence_id != path.stem:
            raise ValueError("claim support evidence identity invalid: %s" % path.name)
        if record.get("project_id") != project["project_id"] or record.get("version_id") != version_id:
            raise ValueError("claim support evidence project/version mismatch: %s" % evidence_id)
        P._evidence_path(root, record)
        if evidence_id in records:
            raise ValueError("duplicate registered evidence id: %s" % evidence_id)
        records[evidence_id] = record
    return records


def _claim_ref_support(ref, records: dict[str, dict], selected: set[str]):
    if not isinstance(ref, str) or not ref.strip():
        return None, "evidence ref is not a non-empty string"
    text = ref.strip()
    if text in records:
        evidence_id, locator = text, None
    else:
        path_text, marker, locator = text.partition("#")
        if not path_text or not marker:
            return None, "evidence ref is neither a registered evidence-id nor relative path#locator"
        try:
            path_text = P.relative_ref(path_text, "claim evidence ref")
        except Exception:
            return None, "evidence ref escapes project or is not relative"
        matches = []
        for evidence_id, record in records.items():
            if path_text in (record.get("local_path"), record.get("source")):
                matches.append((evidence_id, record))
        if len(matches) != 1:
            return None, "evidence ref does not resolve to exactly one registered evidence file"
        evidence_id, record = matches[0]
    record = records[evidence_id]
    if evidence_id in selected:
        return None, "claim ledger cannot support itself"
    if record.get("kind") not in ("artifact", "evidence"):
        return None, "claim support is not a registered primary evidence record"
    return {"evidence_id": evidence_id, "local_path": record.get("local_path"),
            "source": record.get("source"), "sha256": record.get("sha256"),
            "size": record.get("size"), "run_id": record.get("run_id"),
            "locator": locator}, None


def _claim_snapshot(root: Path, project: dict, version: dict, run: dict,
                    selected_ids) -> dict:
    selected = []
    seen = set()
    for raw in selected_ids or []:
        evidence_id = P.require_id(str(raw), "claim_evidence_id")
        if evidence_id in seen:
            raise ValueError("duplicate claim-evidence-id: %s" % evidence_id)
        seen.add(evidence_id)
        selected.append(evidence_id)
    if not selected:
        return _empty_claims()
    records = _claim_evidence_records(root, project, str(version["version_id"]))
    sources = []
    claim_records = []
    claim_ids = set()
    for evidence_id in selected:
        record = records.get(evidence_id)
        if record is None:
            raise ValueError("claim evidence-id is not registered: %s" % evidence_id)
        if record.get("run_id") != run.get("run_id"):
            raise ValueError("claim evidence-id is bound to another run: %s" % evidence_id)
        if record.get("target_sha256") != (version.get("sha256") or ""):
            raise ValueError("claim evidence-id target binding differs: %s" % evidence_id)
        path = P._evidence_path(root, record)
        if path.stat().st_size > MAX_CLAIM_LEDGER_BYTES:
            raise ValueError("claim ledger evidence exceeds resource limit: %s" % evidence_id)
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raise ValueError("claim ledger evidence must be UTF-8 JSONL: %s" % evidence_id) from None
        sources.append({key: record.get(key) for key in
                        ("evidence_id", "version_id", "run_id", "target_sha256",
                         "local_path", "source", "sha256", "size", "kind")})
        for line_number, line in enumerate(text.splitlines(), 1):
            if line_number > MAX_CLAIM_LEDGER_LINES:
                raise ValueError("claim ledger JSONL exceeds line limit: %s" % evidence_id)
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                raise ValueError("claim ledger contains invalid JSON at %s:%d" %
                                 (evidence_id, line_number)) from None
            if not isinstance(value, dict):
                continue
            kind = value.get("kind")
            if kind not in (None, "claim") or not value.get("id") or not value.get("status"):
                continue
            claim_id = str(value["id"]).strip()
            if not claim_id or claim_id in claim_ids:
                raise ValueError("duplicate claim id in selected ledger: %s" % claim_id)
            claim_ids.add(claim_id)
            raw = {key: value[key] for key in CLAIM_FIELDS if key in value}
            raw["id"] = claim_id
            raw["status"] = str(raw.get("status") or "").strip().lower()
            raw["_ledger_evidence_id"] = evidence_id
            raw["_line"] = line_number
            refs = raw.get("evidence")
            reasons = []
            supports = []
            if not isinstance(refs, list) or not refs:
                reasons.append("missing evidence refs")
            else:
                for ref in refs:
                    support, reason = _claim_ref_support(ref, records, seen)
                    if reason:
                        reasons.append(reason)
                    else:
                        if support["run_id"] != run.get("run_id"):
                            reasons.append("support evidence is bound to another run")
                        else:
                            supports.append(support)
            claim_text = raw.get("claim")
            if not isinstance(claim_text, str) or not claim_text.strip():
                reasons.append("claim text is missing or not a non-empty string")
            confidence_value = raw.get("confidence")
            authority_value = raw.get("authority")
            confidence = (confidence_value.strip().lower()
                          if isinstance(confidence_value, str) else "")
            authority = (authority_value.strip().lower()
                         if isinstance(authority_value, str) else "")
            if raw["status"] != "proven":
                reasons.append("status=%s is not proven" % (raw["status"] or "missing"))
            if confidence not in ("observed", "derived"):
                reasons.append("confidence=%s is not observed/derived" % (confidence or "missing"))
            if not authority or authority in ("none", "reported", "unknown"):
                reasons.append("authority is missing, reported or unknown")
            raw["classification"] = "confirmed" if not reasons else "unknown"
            raw["unknown_reasons"] = list(dict.fromkeys(reasons))
            raw["supporting_evidence"] = supports
            claim_records.append(raw)
    claim_records.sort(key=lambda item: str(item.get("id")))
    payload = {"selected_evidence_ids": selected, "sources": sources, "records": claim_records}
    return {**payload,
            "confirmed_ids": [x["id"] for x in claim_records if x["classification"] == "confirmed"],
            "unknown_ids": [x["id"] for x in claim_records if x["classification"] != "confirmed"],
            "claims_sha256": _hash_object(payload)}

def _local_path(root: Path, relative: str) -> Path:
    """Validate a project ref and refuse links before report I/O."""
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise ValueError("report file reference must be a non-empty relative string")
    path = project_file(root, relative)
    if path.resolve() != path.absolute():
        raise ValueError("report file reference traverses a symlink/reparse point")
    return path


def _report_dir(root: Path, report_id: str) -> Path:
    return _local_path(root, "reports/%s" % P.require_id(report_id, "report_id"))

def _body_path(root: Path, report_id: str) -> Path:
    return _local_path(root, "reports/%s/report.md" % P.require_id(report_id, "report_id"))

def _manifest_path(root: Path, report_id: str) -> Path:
    return _local_path(root, "reports/%s/manifest.json" % P.require_id(report_id, "report_id"))

def _rel(root: Path, path: Path) -> str:
    return P.relative_ref(str(path.relative_to(root)))

def _refuse(stage: str, reason: str) -> int:
    """Never echo a matched credential or raw log line; position only."""
    print(json.dumps(scrub({"ok": False, "blocked_at": stage, "reason": reason}),
                     ensure_ascii=False, indent=2))
    return 2

def _emit(value: dict, rc: int = 0) -> int:
    print(json.dumps(scrub(value), ensure_ascii=False, indent=2))
    return rc

def body_problems(text: str) -> list[str]:
    """Minimal five-section structure check of *our own* body (not a validator).

    It only checks the report's own shape: five headings, at least two body lines
    each, conclusion <= 3 lines, and no hedge wording.  It never infers a
    professional claim and never re-validates project evidence.
    """
    problems: list[str] = []
    lines = [line.rstrip() for line in text.splitlines()]
    if not lines or not lines[0].startswith("# "):
        problems.append("报告首行必须是一级标题（# ...）")
    index: dict[str, int] = {}
    for number, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped.startswith("#"):
            continue
        for section in SECTIONS:
            if section in line and section not in index:
                index[section] = number
    missing = [section for section in SECTIONS if section not in index]
    if missing:
        return problems + ["缺少段落：%s" % "、".join(missing)]
    order = sorted(index.items(), key=lambda item: item[1])
    for position, (section, start) in enumerate(order):
        end = order[position + 1][1] if position + 1 < len(order) else len(lines)
        body = [x for x in lines[start + 1:end]
                if x.strip() and not x.lstrip().startswith("#")]
        if len(body) < 2:
            problems.append("%s 段内容过少：%d 行（至少 2 行）" % (section, len(body)))
        if section == "结论" and len(body) > 3:
            problems.append("结论段 %d 行（要求 <=3 行）" % len(body))
    for phrase in BANNED_PHRASES:
        if phrase in text:
            problems.append("出现禁用措辞「%s」" % phrase)
    return problems

# ---------------------------------------------------------------------------
# read-only ledger views
# ---------------------------------------------------------------------------
def _read_index(root: Path) -> tuple[list[dict], list[dict]]:
    """Read ``reports/index.jsonl``; return (entries, problems).  Never raises."""
    entries: list[dict] = []
    problems: list[dict] = []
    try:
        path = _local_path(root, INDEX_NAME)
    except (ValueError, OSError, RuntimeError):
        return entries, [{"reason": "报告索引路径无效或经过链接", "kind": "index_path_invalid"}]
    if not path.exists():
        return entries, problems
    try:
        raw_lines = path.read_bytes().splitlines()
    except OSError as exc:
        return entries, [{"reason": "报告索引不可读：%s" % exc, "kind": "index_unreadable"}]
    registered_ids = set()
    for number, raw in enumerate(raw_lines, 1):
        if not raw.strip():
            problems.append({"reason": "报告索引存在空行：第 %d 行" % number,
                             "kind": "index_blank_line"})
            continue
        try:
            value = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            problems.append({"reason": "报告索引行不可解析：第 %d 行（%s）"
                                       % (number, type(exc).__name__),
                             "kind": "index_unparsable"})
            continue
        if not isinstance(value, dict) or value.get("schema") != INDEX_SCHEMA:
            problems.append({"reason": "报告索引行 schema 无效：第 %d 行" % number,
                             "kind": "index_schema"})
            continue
        if value.get("kind") not in ("registered", "final_pointer"):
            problems.append({"reason": "报告索引行 kind 无效：第 %d 行" % number,
                             "kind": "index_kind"})
            continue
        try:
            for key in ("report_id", "version_id", "run_id", "project_id"):
                if not isinstance(value.get(key), str):
                    raise ValueError("missing identity")
                P.require_id(value[key], key)
        except ValueError:
            problems.append({"reason": "报告索引身份无效：第 %d 行" % number,
                             "kind": "index_identity"})
            continue
        if value["kind"] == "registered":
            if value["report_id"] in registered_ids:
                problems.append({"reason": "报告索引重复登记：%s" % value["report_id"],
                                 "kind": "index_duplicate"})
            registered_ids.add(value["report_id"])
        entries.append(value)
    return entries, problems

def _index_entry(entries: list[dict], report_id: str) -> dict | None:
    found = [entry for entry in entries
             if entry.get("kind") == "registered" and entry.get("report_id") == report_id]
    if not found:
        return None
    return found[-1]

def _report_fact_events(root: Path, report_id: str) -> list[dict]:
    """The append-only ``report_registered`` witness events of one report_id."""
    events, _problems = P.read_fact_log(root)
    return [event for event in events
            if isinstance(event, dict) and isinstance(event.get("id"), str)
            and event.get("type") == "report_registered"
            and event.get("report_id") == report_id]


def _witness_fields(event: dict) -> dict:
    """The registration values a report's fact event must still carry."""
    return {key: event.get(key) for key in REPORT_WITNESS_KEYS}


def _cited_events(root: Path, version_id: str, run_id: str,
                  report_id: str = "") -> tuple[list[dict], list[dict]]:
    """Events this report cites (run lifecycle + acceptance + its own witness)."""
    events, raw_problems = P.read_fact_log(root)
    wanted = []
    for event in events:
        if not isinstance(event, dict) or not isinstance(event.get("id"), str):
            continue
        if event.get("run_id") == run_id and event.get("type") in (
                "run_started", "run_finished", "evidence_registered"):
            wanted.append(event)
        elif (event.get("version_id") == version_id and event.get("run_id") in (None, "")
              and event.get("type") in ("acceptance_defined",)):
            wanted.append(event)
        elif (report_id and event.get("type") == "report_registered"
              and event.get("report_id") == report_id):
            # The report's own registration witness is cited too, so a rewrite that
            # leaves facts untouched changes the cited set (index hash mismatch).
            wanted.append(event)
    cited = []
    seen = set()
    for event in wanted:
        ident = event["id"]
        if ident in seen:
            continue
        seen.add(ident)
        cited.append({"id": ident, "type": event.get("type"),
                      "sha256": _hash_object(event)})
    cited.sort(key=lambda item: item["id"])
    return cited, raw_problems

def _snapshot(root: Path, project: dict, version_id: str, run_id: str,
              claim_evidence_ids=()) -> dict:
    """One consistent read of every binding a report claims.  Read-only.

    Raises when a binding cannot be established honestly (missing version/run,
    broken evidence index, foreign target, unreadable acceptance chain); callers
    refuse to register in that case instead of writing a half-bound manifest.
    """
    version = P._validate_version(root, version_id, project["project_id"])
    run, _run_path = P._run_record(root, version_id, run_id)
    target_check = P.target_fingerprint(root, version)
    target = {"kind": target_check["kind"], "identity_scope": target_check["identity_scope"],
              "remote_content_verified": target_check["remote_content_verified"],
              "sha256": version.get("sha256"), "size": version.get("size"),
              "target_sha256": version.get("target_sha256"),
              "target_size": version.get("target_size"),
              "local_path": version.get("local_path"),
              "snapshot_ref": version.get("snapshot_ref"),
              "snapshot_tree_ref": version.get("snapshot_tree_ref"),
              "url": version.get("url")}
    assets = []
    for asset_id in version.get("asset_ids") or []:
        record = P._asset_record(root, asset_id)
        checked = P.target_fingerprint(root, record)
        assets.append({"asset_id": asset_id, "role": record.get("role"),
                       "kind": checked["kind"], "identity_scope": checked["identity_scope"],
                       "sha256": checked["sha256"], "size": checked["size"],
                       "local_path": record.get("local_path"), "url": record.get("url")})
    evidence_problems = P._evidence_index_problems(root, version_id)
    if evidence_problems:
        raise ValueError("证据索引/登记记录不一致，拒绝报告绑定：%s"
                         % "; ".join(evidence_problems))
    evidence = {}
    evidence_directory = _local_path(root, "versions/%s/evidence" % version_id)
    for path in sorted(evidence_directory.glob("*.json")):
        path = _local_path(root, _rel(root, path))
        record = P.load_json(path)
        if record.get("schema") != P.EVIDENCE_SCHEMA or record.get("evidence_id") != path.stem:
            raise ValueError("证据登记记录身份无效：%s" % path.name)
        if record.get("project_id") != project["project_id"]:
            raise ValueError("证据 project_id 不匹配：%s" % path.stem)
        if record.get("target_sha256") != (version.get("sha256") or ""):
            raise ValueError("证据绑定的目标与版本不符：%s" % path.stem)
        P._evidence_path(root, record)  # re-verifies raw file sha256/size
        evidence[path.stem] = record
    acceptance_path = P._acceptance_path(root, version_id)
    live_sha = _sha(acceptance_path) if acceptance_path.is_file() else None
    state = P._acceptance_state(root, version, project, require_run=run_id)
    items = []
    try:
        data = P.load_acceptance(root, version_id, project["project_id"])
        for item in P.acceptance_items(data):
            origin = P._origin_of(item)
            items.append({"id": item.get("id"), "description": item.get("description"),
                          "required": bool(item.get("required")),
                          "status": item.get("status"),
                          "evidence_ids": list(item.get("evidence_ids") or []),
                          "verifier": item.get("verifier"), "how": item.get("how"),
                          "revision": item.get("revision"),
                          "origin_run_id": origin.get("run_id"),
                          "origin_version_id": origin.get("version_id")})
    except Exception as exc:
        items = []
        state.setdefault("reasons", []).append("验收清单不可读：%s: %s"
                                              % (type(exc).__name__, exc))
    closure = run.get("closure") if isinstance(run.get("closure"), dict) else None
    sealed = run.get("acceptance_snapshot") if isinstance(run.get("acceptance_snapshot"),
                                                         dict) else None
    consumed = live_sha
    seal_ok = None
    if run.get("status") == "completed" and closure and sealed:
        consumed = sealed.get("acceptance_sha256") or live_sha
        recorded_seal = closure.get("seal_sha256")
        seal_ok = bool(isinstance(recorded_seal, str)
                       and P.closure_seal(run) == recorded_seal)
    archived = None
    archived_verified = False
    if consumed:
        revision_path = P._acceptance_revision_path(root, version_id, consumed)
        if revision_path.is_file():
            archived = _rel(root, revision_path)
            archived_verified = _sha(revision_path) == consumed
        else:
            # project_state keeps the consumed revision either archived or as the
            # still-live acceptance.json; the latter is verifiable too.
            try:
                archived_verified = P._revision_document(root, version_id, consumed) is not None
            except Exception:
                archived_verified = False
    cited, fact_problems = _cited_events(root, version_id, run_id)
    claims = _claim_snapshot(root, project, version, run, claim_evidence_ids)
    ledger = P._load_ledger(root)
    audit_errors, audit_legacy = P._audit_ledger(root, ledger["project"], ledger["versions"],
                                                ledger["runs"], ledger["migrations"],
                                                ledger["copies"])
    run_errors: list[dict] = []
    run_legacy: list[dict] = []
    P._audit_run(root, project, ledger["versions"], run, run_errors, run_legacy)
    evidence_ids = sorted(
        set(evidence)
        | {str(x) for item in items for x in (item.get("evidence_ids") or [])})
    entries = [{"evidence_id": evidence_id,
                "kind": evidence[evidence_id].get("kind") if evidence_id in evidence else None,
                "sha256": evidence[evidence_id].get("sha256") if evidence_id in evidence else None,
                "size": evidence[evidence_id].get("size") if evidence_id in evidence else None,
                "local_path": evidence[evidence_id].get("local_path") if evidence_id in evidence else None,
                "target_sha256": evidence[evidence_id].get("target_sha256") if evidence_id in evidence else None,
                "run_id": evidence[evidence_id].get("run_id") if evidence_id in evidence else None}
               for evidence_id in evidence_ids]
    index = {"entries": entries, "index_sha256": _hash_object(entries),
             "unregistered": sorted(x for x in evidence_ids if x not in evidence)}
    scope_path = _local_path(root, "scope.md")
    scope = {"local_path": "scope.md",
             "sha256": _sha(scope_path) if scope_path.is_file() else None}
    return {"version": version, "run": run, "target": target, "assets": assets,
            "evidence": index, "acceptance": {
                "local_path": _rel(root, acceptance_path),
                "live_sha256": live_sha, "consumed_sha256": consumed,
                "consumed_archived": archived, "consumed_verified": archived_verified,
                "state": {key: state.get(key) for key in
                          ("defined", "complete", "counts", "pending", "failed_items",
                           "stale", "unsettled", "required_count", "reasons",
                           "chain_problems", "integrity_errors")},
                "items": items},
            "facts": {"local_path": "facts.jsonl", "cited": cited,
                      "cited_index_sha256": _hash_object(cited),
                      "corrupt_lines": [x.get("line") for x in fact_problems]},
            "claims": claims,
            "scope": scope,
            "run_audit": {"errors": [str(x.get("reason")) for x in run_errors],
                          "legacy": [str(x.get("reason")) for x in run_legacy],
                          "seal_ok": seal_ok},
            "ledger": {"errors": [str(x.get("reason")) for x in
                                   list(ledger.get("errors") or []) + audit_errors],
                       "legacy": [str(x.get("reason")) for x in audit_legacy]}}

# ---------------------------------------------------------------------------
# body composition (facts only: no semantic claim)
# ---------------------------------------------------------------------------
def _short(value) -> str:
    text = str(value or "")
    return text[:12] if text else "无"

def _kind_note(kind: str) -> str:
    if kind == "final":
        return ("final = 本 run 的最终记录（本次登记的最终事实，不是对整个 Goal 的通过结论）；"
                "不代表整个 Goal 成功，也不代表目标功能可用")
    return ("interim = 阶段性记录（可能仍有未完成/未知项）；"
            "不代表整个 Goal 成功，也不代表完成或功能可用")


def compose_body(report_id: str, project: dict, snapshot: dict, kind: str,
                 created_at: str) -> str:
    """Compose the five sections out of registered records only."""
    version = snapshot["version"]
    run = snapshot["run"]
    target = snapshot["target"]
    acceptance = snapshot["acceptance"]
    counts = acceptance["state"].get("counts") or {}
    items = acceptance["items"]
    run_status = run.get("status")
    unfinished = [item for item in items if item.get("status") not in ("pass", None)]
    evidence_entries = snapshot["evidence"]["entries"]
    claims = snapshot.get("claims") or _empty_claims()
    lines: list[str] = []
    lines.append("# 项目报告 %s" % report_id)
    lines.append("")
    lines.append("- 项目：%s" % project.get("project_id"))
    lines.append("- 版本：%s（父版本：%s）" % (version.get("version_id"),
                                            version.get("parent_version_id") or "无"))
    lines.append("- 运行批次：%s（登记状态：%s）" % (run.get("run_id"), run_status))
    lines.append("- 报告类型：%s" % _kind_note(kind))
    lines.append("- 记录时间：%s" % created_at)
    lines.append("")

    lines.append("## 1 结论")
    lines.append("- 本报告只复述已登记记录：版本 %s、批次 %s 登记状态为 %s；验收项 %d 项"
                 "（pass %d / fail %d / unknown %d / skipped %d / pending %d）。"
                 % (version.get("version_id"), run.get("run_id"), run_status,
                    len(items), counts.get("pass", 0), counts.get("fail", 0),
                    counts.get("unknown", 0), counts.get("skipped", 0),
                    counts.get("pending", 0)))
    if unfinished:
        lines.append("- 本次记录仍有 %d 项非 pass（见「仍未知」），不能当作已完成或功能可用。"
                     % len(unfinished))
    elif items:
        lines.append("- 登记清单内没有非 pass 项；这只说明登记一致，不代表目标功能被验证成功。")
    else:
        lines.append("- 本版本尚无验收清单记录，完成状态与功能可用性都未成立。")
    lines.append("- 证明上限：%s —— 只证明项目内文件存在且哈希/大小与登记一致、检查由外部登记"
                 "见证；不执行目标、不解析日志语义。" % P.PROOF_LEVEL)
    lines.append("")

    lines.append("## 2 已确认（只引用已登记记录）")
    lines.append("- 目标：kind=%s，identity_scope=%s，sha256=%s…，大小 %s（类型相关记录见 manifest），项目内路径 %s。"
                 % (target.get("kind", "file"), target.get("identity_scope", "raw-bytes"),
                    _short(target.get("sha256")), target.get("size"), target.get("local_path") or "无（URL descriptor）"))
    if snapshot["assets"]:
        lines.append("- 资产引用：%s。"
                     % "；".join("%s[%s/%s]=%s…（%s 字节）" % (asset["asset_id"],
                                                      asset.get("role") or "unassigned",
                                                      asset.get("kind", "file"),
                                                      _short(asset["sha256"]),
                                                      asset["size"])
                                for asset in snapshot["assets"]))
    else:
        lines.append("- 资产引用：该版本未登记 asset_id（目标指纹直接来自版本清单）。")
    lines.append("- 证据索引：%d 条登记证据，索引 hash=%s…，逐条复核了原始文件 sha256/大小。"
                 % (len(evidence_entries), _short(snapshot["evidence"]["index_sha256"])))
    for entry in evidence_entries:
        lines.append("- 证据 %s：文件 %s，sha256=%s…，%s 字节，登记 run=%s。"
                     % (entry.get("evidence_id"), entry.get("local_path"),
                        _short(entry.get("sha256")), entry.get("size"),
                        entry.get("run_id")))
    if claims["sources"]:
        lines.append("- 专业 claim ledger 来源：%s（只读取已登记 Core evidence，version/run/target/hash/size 绑定见 manifest）。"
                     % "；".join("%s:%s" % (x.get("evidence_id"), x.get("local_path"))
                                 for x in claims["sources"]))
    for claim in claims["records"]:
        if claim.get("classification") == "confirmed":
            public = {key: claim.get(key) for key in CLAIM_FIELDS if key in claim}
            lines.append("- 专业 claim confirmed（仅记录 witness，不等于功能验收）：%s；支持=%s。"
                         % (json.dumps(public, ensure_ascii=False, sort_keys=True),
                            ",".join(x.get("evidence_id") for x in claim.get("supporting_evidence") or [])))
    for item in items:
        lines.append("- 验收项 %s：%s；verifier=%s；how=%s；证据=%s；来源 run=%s。"
                     % (item.get("id"), item.get("status"),
                        item.get("verifier") or "未登记", item.get("how") or "未登记",
                        ",".join(item.get("evidence_ids") or []) or "无",
                        item.get("origin_run_id") or "无"))
    lines.append("- 验收清单所消费修订：sha256=%s…（%s）。"
                 % (_short(acceptance.get("consumed_sha256")),
                    "不可覆盖归档已复核" if acceptance.get("consumed_verified")
                    else "为登记时活动头，尚未归档复核"))
    lines.append("- 运行批次记录：开始 %s，结束 %s。"
                 % (run.get("started_at"), run.get("finished_at") or "未结束"))
    lines.append("- 引用事件：%s。"
                 % ("、".join("%s(%s)" % (event["id"], event["type"])
                             for event in snapshot["facts"]["cited"]) or "无"))
    if snapshot["run_audit"]["errors"]:
        lines.append("- 统一收尾审计：不通过（%s）。"
                     % "；".join(snapshot["run_audit"]["errors"]))
    else:
        lines.append("- 统一收尾审计：该 run 无收尾矛盾（%s）。"
                     % ("封条可复算" if snapshot["run_audit"].get("seal_ok")
                        else "无完成收尾" if run_status != "completed" else "未声明封条"))
    lines.append("")

    lines.append("## 3 仍未知（必须逐条列出）")
    lines.append("- exit0、生成文件、AOB unique、非空日志都不会被本报告当成功能成功；本报告不给出"
                 "「目标可用」结论。")
    if unfinished:
        for item in unfinished:
            lines.append("- 验收项 %s 当前是 %s：缺 %s。"
                         % (item.get("id"), item.get("status"),
                            "已登记的通过见证" if item.get("status") != "pass" else "记录"))
    else:
        lines.append("- 登记清单内没有 pending/fail/unknown/skipped 项；目标是否真的可用仍未验证。")
    for claim in claims["records"]:
        if claim.get("classification") != "confirmed":
            public = {key: claim.get(key) for key in CLAIM_FIELDS if key in claim}
            lines.append("- 专业 claim unknown：%s；原因=%s；支持不会被当作确认。"
                         % (json.dumps(public, ensure_ascii=False, sort_keys=True),
                            "; ".join(claim.get("unknown_reasons") or ["未满足 confirmed 判据"])))
    if not claims["records"] and claims["selected_evidence_ids"]:
        lines.append("- 已选择 claim ledger，但未解析出 claim 记录；不产生专业确认。")
    if run_status == "active":
        lines.append("- 本 run 仍为 active：还没有最终记录，收尾结论未知。")
    elif run_status in ("failed", "blocked", "cancelled"):
        lines.append("- 本 run 已收尾为 %s：这是非完成结果，恢复需要新 run 重新登记证据与验收。"
                     % run_status)
    if acceptance["state"].get("chain_problems") or acceptance["state"].get("integrity_errors"):
        lines.append("- 验收记录链/证据完整性报告了问题：%s。"
                     % "；".join(list(acceptance["state"].get("chain_problems") or [])
                                + list(acceptance["state"].get("integrity_errors") or [])))
    if snapshot["ledger"]["errors"] or snapshot["ledger"]["legacy"]:
        lines.append("- 项目层统一审计在登记时报告了 %d 条错误 / %d 条历史未验证记录：详见 manifest 的 "
                     "ledger 字段（本报告不据此改写任何状态）。"
                     % (len(snapshot["ledger"]["errors"]), len(snapshot["ledger"]["legacy"])))
    if snapshot["facts"]["corrupt_lines"]:
        lines.append("- 事件账存在不可解析行（行号 %s）：这些事实未进入本报告。"
                     % ",".join(str(x) for x in snapshot["facts"]["corrupt_lines"]))
    lines.append("- 日志语义、专业归因与领域结论未在此验证；需要专业结论时必须另行登记显式 claim 并由"
                 "主 Agent 审阅，本模板不自动生成。")
    lines.append("")

    lines.append("## 4 下一步")
    if unfinished:
        lines.append("- 处理仍未完成的验收项：%s（新 run 不继承旧 pass）。"
                     % ",".join(str(item.get("id")) for item in unfinished))
    else:
        lines.append("- 如仍需确认功能可用，请登记新的可复现检查（证据 + verifier + how），不要用本报告"
                     "代替实测。")
    if run_status == "active":
        lines.append("- 结束本 run（finish-run）后如需最终记录，请用新的 report_id 登记 final 报告。")
    elif run_status in ("failed", "blocked", "cancelled"):
        lines.append("- 新建 run 重新登记证据与验收；失败/阻塞结果不会被本报告洗白。")
    else:
        lines.append("- 若目标或证据发生变化，请用新 report_id 重新登记；已登记报告不可静默重生成。")
    lines.append("")

    lines.append("## 5 复查（从已部署的工作台根目录执行）")
    lines.append('- 将下列 `<项目目录>` 替换为本项目的当前绝对路径；归档移位后使用新位置。')
    lines.append('- `python Tool/scripts/project_report.py show --project "<项目目录>" --report-id %s`'
                 % report_id)
    lines.append('- `python Tool/scripts/project_state.py resume --project "<项目目录>"`')
    lines.append("- 期望：show 输出 `fresh=true` 且 `stale` 为空；正文与 manifest 的 sha256 与 "
                 "`reports/index.jsonl` 登记一致；mismatch 表示被篡改或来源已变。")
    lines.append('- `python Tool/scripts/project_report.py status --project "<项目目录>"`（索引/最终指针/stale 一览）')
    lines.append("")
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# registration core
# ---------------------------------------------------------------------------
def _binding(manifest: dict) -> dict:
    """Everything the registration binds, minus the registration timestamp."""
    return {key: value for key, value in manifest.items()
            if key not in ("created_at", "binding_sha256")}

# Content identity used for the duplicate/by-id check.  It deliberately excludes
# the tool hash and its parameters: re-registering the *same* body with the same
# sources is idempotent even after this script was edited, while any change of
# binding (run/version/target/evidence/acceptance/scope/facts/body/note/kind) is
# a different report and must use a new report_id.
_IDENTITY_KEYS = ("schema", "report_id", "project_id", "version_id", "run_id",
                  "kind", "body", "target", "assets", "scope", "facts",
                  "acceptance", "evidence", "claims", "run", "note")

def _identity(manifest: dict) -> dict:
    value = {key: manifest.get(key) for key in _IDENTITY_KEYS}
    if value.get("claims") is None:
        value["claims"] = _empty_claims()
    return value

def _manifest_for(report_id: str, project: dict, snapshot: dict, kind: str,
                  created_at: str, body_sha: str, body_size: int, mode: str,
                  body_source: str | None, note: str,
                  claim_evidence_ids=()) -> dict:
    params = {"mode": mode, "report_id": report_id,
              "version_id": snapshot["version"].get("version_id"),
              "run_id": snapshot["run"].get("run_id"), "kind": kind,
              "body_source": body_source, "note_sha256": _text_sha(note) if note else None,
              "claim_evidence_ids": list(claim_evidence_ids or [])}
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "report_id": report_id,
        "project_id": project["project_id"],
        "version_id": snapshot["version"].get("version_id"),
        "run_id": snapshot["run"].get("run_id"),
        "kind": kind,
        "kind_note": _kind_note(kind),
        "created_at": created_at,
        "body": {"local_path": "reports/%s/report.md" % report_id,
                 "sha256": body_sha, "size": body_size},
        "target": dict(snapshot["target"]),
        "assets": snapshot["assets"],
        "scope": snapshot["scope"],
        "facts": snapshot["facts"],
        "acceptance": snapshot["acceptance"],
        "evidence": snapshot["evidence"],
        "claims": snapshot.get("claims") or _empty_claims(),
        "run": {"run_id": snapshot["run"].get("run_id"),
                "status": snapshot["run"].get("status"),
                "started_at": snapshot["run"].get("started_at"),
                "finished_at": snapshot["run"].get("finished_at"),
                "closure_seal_sha256": (snapshot["run"].get("closure") or {}).get("seal_sha256")
                if isinstance(snapshot["run"].get("closure"), dict) else None,
                "audit": snapshot["run_audit"]},
        "ledger": snapshot["ledger"],
        "sources": {"tool": "project_report.py",
                    "tool_sha256": _sha(_SCRIPT_DIR / "project_report.py"),
                    "params": params, "params_sha256": _hash_object(params)},
        "note": note,
        "core_handoff": core_handoff_status(),
        "proof_level": P.PROOF_LEVEL,
        "proof_limits": list(P.PROOF_LIMITS),
    }
    manifest["binding_sha256"] = _hash_object(_binding(manifest))
    return manifest

def _final_pointer(root: Path) -> dict | None:
    path = _local_path(root, FINAL_NAME)
    if not path.is_file():
        return {"schema": FINAL_SCHEMA, "corrupt": True} if path.exists() else None
    try:
        value = P.load_json(path)
    except Exception:
        return {"schema": FINAL_SCHEMA, "corrupt": True}
    return value

def _write_final_pointer(root: Path, project: dict, manifest: dict, entries: list[dict],
                         stamp: str) -> tuple[bool, dict | str]:
    """Build the next final pointer, or refuse to move it backwards.

    Refusals are reported, not silently ignored: an attempt to move the pointer
    to an older run of the same version is refused (a newer final record already
    exists); the caller decides whether to write the returned pointer.
    """
    previous = _final_pointer(root)
    if previous and not previous.get("corrupt"):
        if previous.get("report_id") == manifest["report_id"]:
            return True, previous
        if previous.get("version_id") == manifest["version_id"]:
            old = _index_entry(entries, str(previous.get("report_id")))
            old_manifest = None
            if old is not None:
                try:
                    old_manifest = P.load_json(_manifest_path(root, str(old["report_id"])))
                except Exception:
                    old_manifest = None
            old_started = ((old_manifest or {}).get("run") or {}).get("started_at") or ""
            new_started = (manifest.get("run") or {}).get("started_at") or ""
            if old_started and new_started and new_started < old_started:
                return False, ("已有更新的 final 指针（report_id=%s，run 开始于 %s），拒绝回退到 %s"
                               % (previous.get("report_id"), old_started, new_started))
    pointer = {"schema": FINAL_SCHEMA, "project_id": project["project_id"],
               "version_id": manifest["version_id"], "run_id": manifest["run_id"],
               "report_id": manifest["report_id"],
               "body_sha256": manifest["body"]["sha256"],
               "manifest_sha256": None,  # filled by the caller (manifest bytes)
               "target_sha256": manifest["target"].get("sha256"),
               "recorded_at": stamp, "proof_level": P.PROOF_LEVEL}
    return True, pointer

def _register(root: Path, project: dict, *, report_id: str, version_id: str, run_id: str,
              kind: str, note: str, body_bytes: bytes, mode: str,
              body_source: str | None, declared_sha: str, declared_size,
              claim_evidence_ids=()) -> int:
    stage = "register" if mode == "register" else "generate"
    if kind not in REPORT_KINDS:
        return _refuse(stage, "非法报告类型：%s；允许值：%s" % (kind, ",".join(REPORT_KINDS)))
    if not body_bytes:
        return _refuse(stage, "报告正文为空，拒绝登记")
    if len(body_bytes) > MAX_BODY_BYTES:
        return _refuse(stage, "报告正文超过 %d 字节上限：拒绝把整份未知日志 dump 进报告"
                       % MAX_BODY_BYTES)
    try:
        text = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return _refuse(stage, "报告正文必须是 UTF-8 文本")
    actual_sha = hashlib.sha256(body_bytes).hexdigest()
    if declared_sha:
        try:
            declared = P._declared(declared_sha, "sha256", 64)
        except ValueError:
            # Never echo the supplied value: only the format rule is reported.
            return _refuse(stage, "规格声明的 sha256 不是 64 位小写十六进制（值不回显）")
        if declared != actual_sha:
            return _refuse(stage, "声明的正文 sha256 与实际文件不符（伪 hash 拒绝）")
    if declared_size not in (None, ""):
        try:
            size = int(declared_size)
        except (TypeError, ValueError):
            return _refuse(stage, "声明的正文 size 不是整数")
        if size != len(body_bytes):
            return _refuse(stage, "声明的正文 size 与实际文件不符：%d != %d"
                           % (size, len(body_bytes)))
    # Conservative credential guard (same rules the Manager uses).  The matched
    # text is never echoed, only the position.
    try:
        reject_sensitive({"report_id": report_id, "version_id": version_id,
                          "run_id": run_id, "kind": kind, "note": note,
                          "body_source": body_source, "body_text": text})
    except Exception as exc:
        return _refuse(stage, "输入/报告正文命中凭据边界检查（拒绝落盘）：%s" % exc)
    problems = body_problems(text)
    if problems:
        return _refuse(stage, "报告不符合五段结构：%s" % "; ".join(problems))
    try:
        snapshot = _snapshot(root, project, version_id, run_id, claim_evidence_ids)
    except Exception as exc:
        return _refuse(stage, "无法建立报告绑定：%s: %s" % (type(exc).__name__, exc))
    chain_problems = list(snapshot["acceptance"]["state"].get("chain_problems") or [])
    chain_problems += list(snapshot["acceptance"]["state"].get("integrity_errors") or [])
    if chain_problems:
        # REVIEW-04 / LIFECYCLE-05: a chain that cannot be recomputed is corruption
        # at every stage.  A report must not be registered on top of it (it would be
        # stale the moment it is written), and the report layer never repairs it.
        return _refuse(stage, "验收修订链不可复算/完整性报告了问题，拒绝登记报告（不得以报告洗白）：%s"
                       % "; ".join(sorted(set(chain_problems))))
    run_status = snapshot["run"].get("status")
    if kind == "final":
        if run_status not in P.RUN_END_STATUSES:
            return _refuse(stage, "final 报告要求 run 已收尾（当前 %s）：final 指本 run 最终记录，"
                                  "不能把进行中的批次写成最终记录" % run_status)
        if snapshot["run_audit"]["errors"]:
            return _refuse(stage, "final 报告要求本 run 的收尾审计通过，当前存在问题：%s"
                           % "；".join(snapshot["run_audit"]["errors"]))
        if version_id != project.get("current_version_id"):
            return _refuse(stage, "final 报告只能针对项目当前版本（当前 %s，请求 %s）；"
                                  "历史版本请用 --kind interim"
                           % (project.get("current_version_id"), version_id))
    entries, index_problems = _read_index(root)
    if index_problems:
        return _refuse(stage, "报告索引已损坏，拒绝在损坏索引上追加：%s"
                       % "; ".join(item["reason"] for item in index_problems))
    if kind == "final":
        previous_final = _final_view(root, project)
        if not previous_final["integrity_ok"]:
            return _refuse(stage, "已登记的最终指针/报告存在完整性错误，拒绝覆盖历史：%s"
                           % "; ".join(previous_final["reasons"]))
    directory = _report_dir(root, report_id)
    body_path = _body_path(root, report_id)
    manifest_path = _manifest_path(root, report_id)
    previous_entry = _index_entry(entries, report_id)
    stamp = P.now()
    manifest = _manifest_for(report_id, project, snapshot, kind, stamp, actual_sha,
                            len(body_bytes), mode, body_source, note,
                            claim_evidence_ids)
    # Credential boundary is enforced *before anything is written*: the manifest
    # copies registered fields (verifier/how/descriptions/paths).  Output scrubbing
    # is not a substitute for refusing to persist a matching value.  The refusal
    # names the position only (never the matched value).
    try:
        reject_sensitive(manifest, "manifest")
    except Exception as exc:
        return _refuse(stage, "待写入的 manifest 命中凭据边界检查，拒绝落盘：%s" % exc)
    if directory.exists() or previous_entry is not None:
        if previous_entry is None:
            return _refuse(stage, "reports/%s 已存在但索引无登记：元数据缺失，拒绝覆盖" % report_id)
        if not body_path.is_file() or body_path.read_bytes() != body_bytes:
            return _refuse(stage, "report_id %s 已登记且正文不同；历史不可覆盖，请使用新 report_id"
                           % report_id)
        try:
            old_manifest = P.load_json(manifest_path)
        except Exception as exc:
            return _refuse(stage, "report_id %s 已登记但 manifest 不可读（%s）：拒绝静默重生成"
                           % (report_id, type(exc).__name__))
        if old_manifest.get("binding_sha256") != _hash_object(_binding(old_manifest)):
            return _refuse(stage, "report_id %s 已登记但 manifest 绑定哈希不可复算（manifest 被修改）："
                                  "拒绝静默重生成" % report_id)
        if _hash_object(_identity(old_manifest)) != _hash_object(_identity(manifest)):
            return _refuse(stage, "report_id %s 已登记且来源绑定已变化：拒绝用同 ID 静默重生成"
                                  "（请用新 report_id 保留历史）" % report_id)
        view = _verify(root, project, previous_entry)
        result = {"ok": view["fresh"], "idempotent": True, "report_id": report_id,
                  "manifest": {key: old_manifest.get(key) for key in
                               ("schema", "report_id", "kind", "version_id", "run_id",
                                "created_at", "body", "binding_sha256", "sources")},
                  "head_sha256": previous_entry.get("manifest_sha256"),
                  "verification": view,
                  **core_handoff_status()}
        return _emit(result, 0 if view["fresh"] else 2)
    # Guard against a concurrent reader/mutator between snapshot and write: the
    # core bindings are re-read once; a changing project refuses the write
    # instead of pretending a multi-file transaction.
    try:
        again = _snapshot(root, project, version_id, run_id, claim_evidence_ids)
    except Exception as exc:
        return _refuse(stage, "写入前复读绑定失败：%s: %s" % (type(exc).__name__, exc))
    for key in ("target", "assets", "evidence", "claims", "facts", "scope"):
        if _hash_object(again[key]) != _hash_object(snapshot[key]):
            return _refuse(stage, "读取期间项目状态发生变化（%s），拒绝写入半绑定的报告；请重试" % key)
    if again["acceptance"].get("consumed_sha256") != snapshot["acceptance"].get("consumed_sha256"):
        return _refuse(stage, "读取期间验收清单已有新修订，拒绝写入；请重试")
    if again["run"].get("status") != run_status:
        return _refuse(stage, "读取期间 run 状态发生变化，拒绝写入；请重试")
    write_set = [manifest["body"]["local_path"], _rel(root, manifest_path),
                 INDEX_NAME, "facts.jsonl", "handoff.json"]
    if kind == "final":
        write_set.append(FINAL_NAME)
    with file_transaction(root, write_set):
        directory.mkdir(parents=True, exist_ok=False)
        P.atomic_bytes(body_path, body_bytes)
        P.atomic_json(manifest_path, manifest)
        manifest_sha = _sha(manifest_path)
        entry = {"schema": INDEX_SCHEMA, "kind": "registered", "report_id": report_id,
                 "project_id": project["project_id"], "version_id": version_id,
                 "run_id": run_id, "report_kind": kind,
                 "body_sha256": actual_sha, "body_size": len(body_bytes),
                 "manifest_sha256": manifest_sha,
                 "binding_sha256": manifest["binding_sha256"], "created_at": stamp}
        P.append_jsonl(_local_path(root, INDEX_NAME), entry)
        final_info: dict = {"set": False, "reason": "interim 报告不设置最终指针"}
        if kind == "final":
            allowed, value = _write_final_pointer(root, project, manifest, entries, stamp)
            if allowed:
                path = _local_path(root, FINAL_NAME)
                previous_id = None
                if path.is_file():
                    try:
                        previous_id = P.load_json(path).get("report_id")
                    except Exception:
                        previous_id = None
                value["manifest_sha256"] = manifest_sha
                P.atomic_json(path, value)
                P.append_jsonl(_local_path(root, INDEX_NAME),
                               {"schema": INDEX_SCHEMA, "kind": "final_pointer",
                                "report_id": report_id, "project_id": project["project_id"],
                                "version_id": version_id, "run_id": run_id,
                                "body_sha256": actual_sha, "manifest_sha256": manifest_sha,
                                "previous_report_id": previous_id,
                                "created_at": stamp})
                final_info = {"set": True, "report_id": report_id,
                              "local_path": _rel(root, path),
                              "previous_report_id": previous_id}
            else:
                final_info = {"set": False, "reason": value}
        # The registration is witnessed *outside* the three report files: the append-only
        # fact carries the identity and the exact hashes that were written.  Re-running
        # the same registration is idempotent and must not append a second witness.
        witness = {"report_id": report_id, "report_kind": kind, "version_id": version_id,
                   "run_id": run_id, "project_id": project["project_id"],
                   "body_sha256": actual_sha, "body_size": len(body_bytes),
                   "manifest_sha256": manifest_sha,
                   "binding_sha256": manifest["binding_sha256"]}
        existing = _report_fact_events(root, report_id)
        if not existing:
            P.write_event(root, "report_registered",
                          "登记报告 %s（%s/%s，%s）" % (report_id, version_id, run_id, kind),
                          version_id, run_id, extra=dict(witness))
            existing = _report_fact_events(root, report_id)
        written = [_witness_fields(event) for event in existing]
        if len(existing) != 1 or written[0] != witness:
            raise ValueError("报告登记见证不一致（facts 中的 report_registered 事件缺失、重复或"
                             "与已写入文件不符）：%s 条" % len(existing))
        P.write_handoff(root)
        view = _verify(root, project, entry)
        if not view["fresh"]:
            raise ValueError("新报告写后复验失败，回滚本次登记")
    result = {"ok": view["fresh"], "report_id": report_id, "kind": kind,
              "body": {"local_path": manifest["body"]["local_path"],
                       "sha256": actual_sha, "size": len(body_bytes)},
              "manifest": {"local_path": _rel(root, manifest_path),
                           "sha256": manifest_sha,
                           "binding_sha256": manifest["binding_sha256"]},
              "index": {"local_path": INDEX_NAME, "entry": entry},
              "final_pointer": final_info,
              "verification": view,
              "proof_level": P.PROOF_LEVEL, "proof_limits": list(P.PROOF_LIMITS),
              **core_handoff_status()}
    return _emit(result, 0 if view["fresh"] else 2)

# ---------------------------------------------------------------------------
# verification (stale detection)
# ---------------------------------------------------------------------------
def _manifest_shape_problems(manifest: dict) -> list[str]:
    problems = []
    for key in ("body", "target", "scope", "facts", "acceptance", "evidence", "run"):
        if not isinstance(manifest.get(key), dict):
            problems.append("%s must be an object" % key)
    for key in ("claims", "sources"):
        if key in manifest and not isinstance(manifest[key], dict):
            problems.append("%s must be an object" % key)
    for label, value in (("assets", manifest.get("assets")),
                         ("facts.cited", (manifest.get("facts") or {}).get("cited")
                          if isinstance(manifest.get("facts"), dict) else None),
                         ("evidence.entries", (manifest.get("evidence") or {}).get("entries")
                          if isinstance(manifest.get("evidence"), dict) else None)):
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            problems.append("%s must be an array of objects" % label)
    if isinstance(manifest.get("sources"), dict) and not isinstance(
            manifest["sources"].get("params"), dict):
        problems.append("sources.params must be an object")
    return problems


def _check_manifest_paths(root: Path, manifest: dict, entry: dict) -> None:
    """Validate untrusted refs before opening any manifest-selected file."""
    version_id = P.require_id(entry.get("version_id"), "version")
    P.require_id(entry.get("run_id"), "run_id")
    for key in ("body", "scope", "facts", "acceptance"):
        _local_path(root, manifest[key].get("local_path"))
    for row in [manifest["target"], *manifest["assets"], *manifest["evidence"]["entries"]]:
        for key in ("local_path", "snapshot_ref", "snapshot_tree_ref"):
            if row.get(key) is not None:
                _local_path(root, row[key])
    for row in manifest["evidence"]["entries"]:
        P.require_id(row.get("evidence_id"), "evidence_id")
    # The fixed slot is validated too, even when the manifest omits evidence rows.
    _local_path(root, "versions/%s/evidence" % version_id)


def _verify(root: Path, project: dict, entry: dict) -> dict:
    """Re-verify one registered report against the live project.  Read-only."""
    report_id = str(entry.get("report_id"))
    stale: list[dict] = []
    advanced: list[dict] = []
    view: dict = {"report_id": report_id, "version_id": entry.get("version_id"),
                  "run_id": entry.get("run_id"), "kind": entry.get("report_kind"),
                  "index": {"local_path": INDEX_NAME,
                            "manifest_sha256": entry.get("manifest_sha256"),
                            "body_sha256": entry.get("body_sha256")},
                  "body": None, "manifest": None, "target": None, "assets": [],
                  "acceptance": None, "evidence": None, "run": None,
                  "stale": stale, "advanced": advanced, "fresh": False}
    if entry.get("schema") != INDEX_SCHEMA or entry.get("kind") != "registered":
        stale.append({"kind": "index_entry_invalid", "detail": "索引登记项 schema/kind 无效"})
    if entry.get("project_id") != project.get("project_id"):
        stale.append({"kind": "index_project_mismatch",
                      "detail": "索引登记的 project_id 与当前项目不符"})
    try:
        report_id = P.require_id(report_id, "report_id")
    except ValueError as exc:
        stale.append({"kind": "index_report_id", "detail": str(exc)})
        return view
    directory = _report_dir(root, report_id)
    body_path = _body_path(root, report_id)
    manifest_path = _manifest_path(root, report_id)
    if not directory.is_dir():
        stale.append({"kind": "report_missing", "detail": "报告目录不存在：reports/%s" % report_id})
    if not body_path.is_file():
        stale.append({"kind": "body_missing", "detail": "报告正文缺失：reports/%s/report.md" % report_id})
    else:
        body_sha = _sha(body_path)
        size = body_path.stat().st_size
        view["body"] = {"local_path": _rel(root, body_path), "sha256": body_sha,
                        "size": size, "matches_index": body_sha == entry.get("body_sha256")}
        if body_sha != entry.get("body_sha256"):
            stale.append({"kind": "body_changed",
                          "detail": "报告正文哈希与索引登记不一致（正文被修改或重生成）"})
    manifest = None
    if not manifest_path.is_file():
        stale.append({"kind": "manifest_missing",
                      "detail": "报告 manifest 缺失：reports/%s/manifest.json" % report_id})
    else:
        manifest_sha = _sha(manifest_path)
        try:
            manifest = P.load_json(manifest_path)
        except Exception as exc:
            stale.append({"kind": "manifest_unreadable",
                          "detail": "报告 manifest 不可读：%s" % type(exc).__name__})
        view["manifest"] = {"local_path": _rel(root, manifest_path), "sha256": manifest_sha,
                            "matches_index": manifest_sha == entry.get("manifest_sha256")}
        if manifest_sha != entry.get("manifest_sha256"):
            stale.append({"kind": "index_mismatch",
                          "detail": "manifest 哈希与索引登记不一致（manifest 或索引被修改）"})
    if isinstance(manifest, dict):
        shape_problems = _manifest_shape_problems(manifest)
        if shape_problems:
            stale.append({"kind": "manifest_shape", "detail": "; ".join(shape_problems)})
            return view
        try:
            _check_manifest_paths(root, manifest, entry)
        except (ValueError, OSError, RuntimeError):
            stale.append({"kind": "manifest_path", "detail": "报告清单包含无效、越界或经过链接的引用"})
            return view
        if manifest.get("schema") != MANIFEST_SCHEMA:
            stale.append({"kind": "manifest_schema", "detail": "manifest schema 无效"})
        for key, value in (("report_id", report_id),
                           ("project_id", project.get("project_id")),
                           ("version_id", entry.get("version_id")),
                           ("run_id", entry.get("run_id"))):
            if manifest.get(key) != value:
                stale.append({"kind": "manifest_binding",
                              "detail": "manifest 的 %s 与索引/项目不一致" % key})
        if manifest.get("binding_sha256") != _hash_object(_binding(manifest)):
            stale.append({"kind": "manifest_binding_sha256",
                          "detail": "manifest 的 binding_sha256 不可复算（绑定字段被改）"})
        body_info = manifest.get("body") or {}
        if view["body"] and (body_info.get("sha256") != view["body"]["sha256"]
                             or body_info.get("size") != view["body"]["size"]):
            stale.append({"kind": "body_changed",
                          "detail": "正文与 manifest 记录的大小/哈希不符"})
        # The append-only index must agree with the manifest it points at: an edit
        # of either one is a metadata mismatch, not a "fresh" report.
        if (entry.get("body_sha256") != body_info.get("sha256")
                or entry.get("body_size") != body_info.get("size")
                or entry.get("binding_sha256") != manifest.get("binding_sha256")):
            stale.append({"kind": "index_mismatch",
                          "detail": "reports/index.jsonl 的登记与 manifest 不一致（索引被改）"})
        # ---- target / assets -------------------------------------------
        target = manifest.get("target") or {}
        try:
            version = P._validate_version(root, str(entry.get("version_id")),
                                          project["project_id"])
        except Exception as exc:
            version = None
            stale.append({"kind": "version_missing" if isinstance(exc, FileNotFoundError)
                                  else "version_invalid",
                          "detail": "报告绑定的版本不可读：%s: %s" % (type(exc).__name__, exc)})
            if isinstance(exc, P.T.TypedAssetError):
                stale.append({"kind": "target_changed",
                              "detail": "版本 typed target identity 的声明不一致或无效"})
        if version is not None:
            try:
                checked = P.target_fingerprint(root, version)
                current = {"kind": checked["kind"], "identity_scope": checked["identity_scope"],
                           "remote_content_verified": checked["remote_content_verified"],
                           "sha256": checked["sha256"], "size": checked["size"],
                           "target_sha256": version.get("target_sha256"),
                           "target_size": version.get("target_size"),
                           "local_path": version.get("local_path"),
                           "snapshot_ref": version.get("snapshot_ref"),
                           "snapshot_tree_ref": version.get("snapshot_tree_ref"),
                           "url": version.get("url")}
                view["target"] = {"recorded": target, "current": current,
                                  "matches": all(target.get(k) == current.get(k)
                                                 for k in ("kind", "sha256", "size", "local_path"))}
                if not view["target"]["matches"]:
                    stale.append({"kind": "target_changed",
                                  "detail": "版本 typed target identity 与报告登记时不同"})
            except Exception as exc:
                view["target"] = {"recorded": target,
                                  "current": {"kind": version.get("kind", "file"),
                                              "sha256": version.get("sha256"),
                                              "size": version.get("size"),
                                              "local_path": version.get("local_path")},
                                  "matches": False}
                stale.append({"kind": "target_changed",
                              "detail": "版本 typed target identity 与报告登记的实际内容不一致"})
                stale.append({"kind": "target_unreadable",
                              "detail": "版本 typed target 不可复核：%s" % type(exc).__name__})
        for asset in manifest.get("assets") or []:
            row = {"asset_id": asset.get("asset_id"), "matches": False}
            try:
                record = P._asset_record(root, str(asset.get("asset_id")))
                checked = P.target_fingerprint(root, record)
                row["matches"] = (record.get("kind", "file") == asset.get("kind", "file")
                                  and checked.get("sha256") == asset.get("sha256")
                                  and checked.get("size") == asset.get("size")
                                  and record.get("local_path") == asset.get("local_path"))
                if not row["matches"]:
                    stale.append({"kind": "asset_changed",
                                  "detail": "资产 %s 与报告登记不一致" % asset.get("asset_id")})
            except Exception as exc:
                stale.append({"kind": "asset_unreadable",
                              "detail": "资产 %s 不可复核：%s: %s"
                                        % (asset.get("asset_id"), type(exc).__name__, exc)})
            view["assets"].append(row)
        # ---- scope ------------------------------------------------------
        scope = manifest.get("scope") or {}
        scope_path = _local_path(root, scope["local_path"])
        current_scope = _sha(scope_path) if scope_path.is_file() else None
        if current_scope != scope.get("sha256"):
            stale.append({"kind": "scope_changed", "detail": "scope.md 与报告登记时不同"})
        # ---- facts (cited events only: the ledger is append-only) --------
        facts = manifest.get("facts") or {}
        try:
            events, fact_problems = P.read_fact_log(root)
        except Exception as exc:
            events, fact_problems = [], [{"line": 0, "reason": str(exc)}]
        by_id = {str(x.get("id")): x for x in events if isinstance(x, dict)}
        cited_now = []
        for cited in facts.get("cited") or []:
            event = by_id.get(str(cited.get("id")))
            if event is None:
                stale.append({"kind": "fact_missing",
                              "detail": "报告引用的事件已不在事件账中：%s" % cited.get("id")})
                continue
            digest = _hash_object(event)
            if digest != cited.get("sha256"):
                stale.append({"kind": "fact_changed",
                              "detail": "报告引用的事件内容被改：%s" % cited.get("id")})
            cited_now.append({"id": cited.get("id"), "type": event.get("type"),
                              "sha256": digest})
        cited_now.sort(key=lambda item: str(item["id"]))
        if _hash_object(cited_now) != facts.get("cited_index_sha256"):
            stale.append({"kind": "facts_index_changed",
                          "detail": "引用事件集合的索引哈希与登记不一致"})
        if fact_problems and not facts.get("corrupt_lines"):
            advanced.append({"kind": "facts_now_corrupt",
                             "detail": "事件账在报告登记后出现不可解析行（行号 %s），"
                                       "不影响已引用事实的复核"
                                       % ",".join(str(x.get("line")) for x in fact_problems)})
        # ---- registration witness (append-only facts event) -----------------
        # This is what makes a same-ID rewrite of body+manifest+index detectable
        # while facts/target/acceptance stay untouched: the values recorded at
        # registration time must still be the values on disk.
        expected = {"report_id": report_id,
                    "report_kind": manifest.get("kind"),
                    "version_id": manifest.get("version_id"),
                    "run_id": manifest.get("run_id"),
                    "project_id": project.get("project_id"),
                    "body_sha256": (manifest.get("body") or {}).get("sha256"),
                    "body_size": (manifest.get("body") or {}).get("size"),
                    "manifest_sha256": (view.get("manifest") or {}).get("sha256"),
                    "binding_sha256": manifest.get("binding_sha256")}
        witnesses = _report_fact_events(root, report_id)
        view["witness"] = {"events": len(witnesses),
                           "matches": len(witnesses) == 1
                           and _witness_fields(witnesses[0]) == expected}
        if not witnesses:
            stale.append({"kind": "witness_missing",
                          "detail": "facts.jsonl 中缺少该 report_id 的 report_registered "
                                    "登记见证（无法证明报告目录是当初登记的内容）"})
        elif len(witnesses) > 1:
            stale.append({"kind": "witness_duplicated",
                          "detail": "facts.jsonl 中该 report_id 有多条登记见证：%d 条"
                                    % len(witnesses)})
        else:
            recorded = _witness_fields(witnesses[0])
            differing = sorted(key for key in REPORT_WITNESS_KEYS
                               if recorded.get(key) != expected.get(key))
            if differing:
                stale.append({"kind": "witness_mismatch",
                              "detail": "正文/manifest/索引与 facts 登记见证不一致（登记后被改）：%s"
                                        % ",".join(differing)})
        # ---- evidence ---------------------------------------------------
        evidence = manifest.get("evidence") or {}
        problem_entries = []
        for row in evidence.get("entries") or []:
            evidence_id = str(row.get("evidence_id"))
            info = {"evidence_id": evidence_id, "ok": True, "reasons": []}
            record_path = _local_path(root, "versions/%s/evidence/%s.json" %
                                      (entry["version_id"], evidence_id))
            try:
                record = P.load_json(record_path)
                if record.get("sha256") != row.get("sha256") or record.get("size") != row.get("size"):
                    info["ok"] = False
                    info["reasons"].append("登记记录指纹与 manifest 不符")
                if record.get("local_path") != row.get("local_path"):
                    info["ok"] = False
                    info["reasons"].append("登记记录路径与 manifest 不符")
                P._evidence_path(root, record)
            except Exception as exc:
                info["ok"] = False
                info["reasons"].append("%s: %s" % (type(exc).__name__, exc))
            if not info["ok"]:
                problem_entries.append(info)
                stale.append({"kind": "evidence_changed",
                              "detail": "证据 %s 无法复核：%s"
                                        % (evidence_id, "; ".join(info["reasons"]))})
            view.setdefault("evidence_rows", []).append(info)
        try:
            index_problems = P._evidence_index_problems(root, str(entry.get("version_id")))
        except Exception as exc:
            index_problems = [str(exc)]
        if index_problems:
            stale.append({"kind": "evidence_index_changed",
                          "detail": "版本证据索引/登记记录不一致：%s" % "; ".join(index_problems)})
        current_entries = []
        for row in evidence.get("entries") or []:
            current_entries.append({"evidence_id": row.get("evidence_id"),
                                    "sha256": row.get("sha256"), "size": row.get("size"),
                                    "local_path": row.get("local_path"),
                                    "target_sha256": row.get("target_sha256"),
                                    "run_id": row.get("run_id"), "kind": row.get("kind")})
        view["evidence"] = {"index_sha256": evidence.get("index_sha256"),
                            "recomputed_sha256": _hash_object(current_entries),
                            "matches": _hash_object(current_entries) == evidence.get("index_sha256"),
                            "entries": len(current_entries),
                            "problems": problem_entries}
        if not view["evidence"]["matches"]:
            stale.append({"kind": "evidence_index_changed",
                          "detail": "证据索引哈希与登记不一致"})
        # ---- professional claim ledger -------------------------------
        recorded_claims = manifest.get("claims")
        if recorded_claims is None:
            view["claims"] = _empty_claims()
        else:
            params = (manifest.get("sources") or {}).get("params") or {}
            selected_claim_ids = list(params.get("claim_evidence_ids") or
                                      recorded_claims.get("selected_evidence_ids") or [])
            try:
                claim_run, _ = P._run_record(root, str(entry.get("version_id")),
                                             str(entry.get("run_id")))
                current_claims = _claim_snapshot(root, project, version, claim_run,
                                                 selected_claim_ids)
                view["claims"] = {"recorded": recorded_claims, "current": current_claims,
                                   "matches": current_claims.get("claims_sha256") ==
                                             recorded_claims.get("claims_sha256")}
                if not view["claims"]["matches"]:
                    stale.append({"kind": "claim_ledger_changed",
                                  "detail": "registered claim ledger 或其支持映射与报告登记不一致"})
            except Exception as exc:
                view["claims"] = {"recorded": recorded_claims, "current": None,
                                   "matches": False}
                stale.append({"kind": "claim_ledger_unreadable",
                              "detail": "registered claim ledger/support 不可复核：%s" %
                                        type(exc).__name__})
        # ---- acceptance --------------------------------------------------
        acceptance = manifest.get("acceptance") or {}
        acceptance_path = _local_path(root, acceptance["local_path"])
        live_sha = _sha(acceptance_path) if acceptance_path.is_file() else None
        consumed = acceptance.get("consumed_sha256")
        revision_ok = None
        archived = None
        if consumed:
            revision_path = P._acceptance_revision_path(root, str(entry.get("version_id")),
                                                        str(consumed))
            if revision_path.is_file():
                archived = _rel(root, revision_path)
                revision_ok = _sha(revision_path) == consumed
        info = {"recorded_sha256": consumed, "live_sha256": live_sha,
                "archived": archived, "archived_verified": revision_ok,
                "matches_live": live_sha == consumed}
        if revision_ok is False:
            stale.append({"kind": "acceptance_revision_changed",
                          "detail": "不可覆盖验收修订内容与登记哈希不符"})
        elif revision_ok is None and live_sha != consumed:
            advanced.append({"kind": "acceptance_advanced",
                             "detail": "报告登记后验收清单已有新修订；登记时消费的是活动头、"
                                       "当时未归档，无法逐字节复核（已如实标注）"})
        # The report also stands on the acceptance *lineage* it recorded.  A broken
        # chain (edited archive bytes, stripped archive_index, log/head mismatch) is
        # re-checked with project_state's own chain rule -- legal later revisions are
        # not defects and stay "advanced", never "stale".
        try:
            data = P.load_acceptance(root, str(entry.get("version_id")),
                                     project["project_id"])
            _chain, chain_problems = P._acceptance_chain(root, str(entry.get("version_id")),
                                                        data)
        except Exception as exc:
            chain_problems = ["验收清单不可读：%s: %s" % (type(exc).__name__, exc)]
        info["chain_problems"] = list(chain_problems)
        info["chain_ok"] = not chain_problems
        if chain_problems:
            stale.append({"kind": "acceptance_chain_broken",
                          "detail": "报告所依赖的验收修订链不可复算：%s"
                                    % "; ".join(chain_problems)})
        view["acceptance"] = info
        # ---- run ---------------------------------------------------------
        run_info = manifest.get("run") or {}
        try:
            run, _run_path = P._run_record(root, str(entry.get("version_id")),
                                          str(entry.get("run_id")))
        except Exception as exc:
            run = None
            stale.append({"kind": "run_missing",
                          "detail": "报告绑定的 run 不可读：%s: %s" % (type(exc).__name__, exc)})
        if run is not None:
            current_seal = (run.get("closure") or {}).get("seal_sha256") \
                if isinstance(run.get("closure"), dict) else None
            view["run"] = {"status_recorded": run_info.get("status"),
                           "status_current": run.get("status"),
                           "closure_seal_recorded": run_info.get("closure_seal_sha256"),
                           "closure_seal_current": current_seal}
            if run_info.get("status") == "completed" and run.get("status") != "completed":
                stale.append({"kind": "completion_revoked",
                              "detail": "报告登记的 completed 收尾已不被 run 记录承认"})
            elif run_info.get("closure_seal_sha256") != current_seal:
                # A run that was still *active* when the (interim) report was
                # registered legitimately gains a closure seal when it is later
                # finished; that is forward motion, not tampering.  Only a seal
                # that already existed at registration and then changed (or
                # vanished) is a rewrite.
                if run_info.get("closure_seal_sha256") is None:
                    advanced.append({"kind": "run_advanced",
                                     "detail": "报告登记后 run 已收尾（%s）：报告是当时的阶段记录，"
                                               "需以新 report_id 记录最终结果"
                                               % run.get("status")})
                else:
                    stale.append({"kind": "closure_changed",
                                  "detail": "run 收尾封条与报告登记时不同"})
            elif run_info.get("status") != run.get("status"):
                advanced.append({"kind": "run_advanced",
                                 "detail": "run 状态由 %s 变为 %s（报告登记后合法收尾）"
                                           % (run_info.get("status"), run.get("status"))})
    view["fresh"] = not stale
    return view

def _final_view(root: Path, project: dict) -> dict:
    """Current final pointer: *integrity* and *current-version applicability* apart.

    Two questions are deliberately separated:

    ``integrity_ok``  the pointer file, the ``final_pointer`` index row it names, the
                      registered report row and that report's own files/witness all
                      still agree.  A hand-edited pointer, a pointer to an
                      unregistered report, or hashes that no longer match are
                      **corruption** and always block.
    ``applicable``    the pointer names a report of the project's *current* version.
                      A pointer left on a previous version after a normal version
                      bump is **not** corruption: that report is a valid historical
                      record and the current version simply has no final report yet
                      (``pending="current_final_missing"``).  It must never be shown
                      as the current version's final report, and it must never
                      inherit the new version's acceptance.

    ``valid`` is the conjunction (a fresh, applicable, intact final report).
    """
    view: dict = {"present": False, "valid": False, "integrity_ok": True,
                  "applicable": False, "pending": "current_final_missing",
                  "report_id": None, "version_id": None, "run_id": None,
                  "local_path": FINAL_NAME, "reasons": [], "notes": [], "stale": []}
    pointer = _final_pointer(root)
    if pointer is None:
        entries, problems = _read_index(root)
        events, fact_problems = P.read_fact_log(root)
        final_witness = any(event.get("type") == "report_registered"
                            and event.get("report_kind") == "final" for event in events)
        if problems or fact_problems or final_witness or any(row.get("kind") == "final_pointer"
                           or row.get("report_kind") == "final" for row in entries):
            view["integrity_ok"] = False
            view["pending"] = ""
            view["reasons"].append("reports/final.json 缺失且存在既有登记，或索引/事实账本不可复核")
        else:
            view["notes"].append("当前版本尚无 final 报告（未完成，不是损坏）")
        return view
    view["present"] = True
    if pointer.get("corrupt"):
        view["integrity_ok"] = False
        view["pending"] = ""
        view["reasons"].append("reports/final.json 不可解析")
        return view
    view.update({"report_id": pointer.get("report_id"),
                 "version_id": pointer.get("version_id"),
                 "run_id": pointer.get("run_id"),
                 "target_sha256": pointer.get("target_sha256"),
                 "recorded_at": pointer.get("recorded_at")})
    if pointer.get("schema") != FINAL_SCHEMA or pointer.get("project_id") != project.get("project_id"):
        view["integrity_ok"] = False
        view["reasons"].append("最终指针 schema/project_id 无效")
    # Applicability is decided independently of integrity, so a pointer left on a
    # previous version after a normal version bump is never called corruption.
    view["applicable"] = pointer.get("version_id") == project.get("current_version_id")
    if not view["applicable"]:
        view["notes"].append("最终指针是历史版本 %s 的报告（当前版本 %s）：历史记录，"
                             "不是当前版本的 final 报告"
                             % (pointer.get("version_id"), project.get("current_version_id")))
    try:
        version = P._validate_version(root, str(pointer.get("version_id")),
                                      project["project_id"])
    except Exception as exc:
        version = None
        view["integrity_ok"] = False
        view["reasons"].append("最终指针版本不可读：%s" % type(exc).__name__)
    if version is not None and pointer.get("target_sha256") != version.get("sha256"):
        view["integrity_ok"] = False
        view["reasons"].append("最终指针绑定的目标与其所属版本目标不符（指针被改）")
    entries, _problems = _read_index(root)
    entry = _index_entry(entries, str(pointer.get("report_id")))
    if entry is None:
        view["integrity_ok"] = False
        view["reasons"].append("最终指针指向的报告未在索引中登记")
        view["pending"] = ""
        return view
    # The pointer must match the latest ``final_pointer`` index row for that report
    # and that row's hashes: a hand edit of either side is corruption.
    pointer_rows = [row for row in entries
                    if row.get("kind") == "final_pointer"
                    and row.get("report_id") == pointer.get("report_id")]
    if pointer_rows:
        latest = pointer_rows[-1]
        for key in ("version_id", "run_id", "body_sha256", "manifest_sha256"):
            if latest.get(key) != pointer.get(key):
                view["integrity_ok"] = False
                view["reasons"].append("最终指针与 final_pointer 索引登记不一致：%s" % key)
    else:
        view["integrity_ok"] = False
        view["reasons"].append("最终指针缺少 final_pointer 索引登记（无法复核来源）")
    for key in ("version_id", "run_id"):
        if entry.get(key) != pointer.get(key):
            view["integrity_ok"] = False
            view["reasons"].append("最终指针与报告索引登记的 %s 不一致" % key)
    if entry.get("manifest_sha256") != pointer.get("manifest_sha256"):
        view["integrity_ok"] = False
        view["reasons"].append("最终指针记录的 manifest 哈希与索引登记不一致")
    if entry.get("body_sha256") != pointer.get("body_sha256"):
        view["integrity_ok"] = False
        view["reasons"].append("最终指针记录的正文哈希与索引登记不一致")
    report = _verify(root, project, entry)
    view["stale"] = report["stale"]
    if report.get("kind") != "final":
        view["integrity_ok"] = False
        view["reasons"].append("最终指针指向的报告不是 final 类型")
    if not report["fresh"]:
        view["integrity_ok"] = False
        view["reasons"].append("最终指针指向的报告完整性已受损（见 stale）")
    view["report"] = {"kind": report.get("kind"), "fresh": report["fresh"],
                      "body": report.get("body"), "advanced": report.get("advanced")}
    if view["integrity_ok"] and view["applicable"]:
        view["valid"] = True
        view["pending"] = ""
    elif view["integrity_ok"]:
        view["pending"] = "current_final_missing"
    else:
        view["pending"] = ""
    return view

def handoff_view(root: Path) -> dict:
    """Read-only report projection for ``project_state.write_handoff``.

    The caller already holds ``project_lock``; this function must not lock, not
    write and never raise.  Report *presence* alone never makes a project ok:
    only integrity problems are surfaced as blocking errors, and a stale final
    pointer or a stale registered report is one of them.
    """
    view: dict = {"schema": HANDOFF_SCHEMA, "wired": True, "present": False,
                  "index_entries": 0,
                  "registered": [], "current_final": None, "stale": [],
                  "errors": [], "next_actions": [],
                  "blocked_priority": "报告存在本身不会让 state_health 变 ok"}
    try:
        project = P.require_project(root)
        entries, problems = _read_index(root)
        registered = [entry for entry in entries if entry.get("kind") == "registered"]
        view["present"] = bool(registered) or (_local_path(root, FINAL_NAME)).is_file()
        view["index_entries"] = len(registered)
        view["registered"] = sorted({str(entry.get("report_id")) for entry in registered})
        for problem in problems:
            view["errors"].append({"reason": problem["reason"], "kind": "report_index"})
        for entry in registered:
            report = _verify(root, project, entry)
            if report["stale"]:
                view["stale"].append({"report_id": entry.get("report_id"),
                                      "kind": entry.get("report_kind"),
                                      "stale": report["stale"]})
                view["errors"].append(
                    {"reason": "已登记报告 %s 完整性受损：%s"
                               % (entry.get("report_id"),
                                  "; ".join(item["detail"] for item in report["stale"])),
                     "kind": "report_stale",
                     "report_id": entry.get("report_id")})
            elif report["advanced"]:
                view.setdefault("advanced", []).append(
                    {"report_id": entry.get("report_id"),
                     "advanced": report["advanced"]})
        final = _final_view(root, project)
        view["current_final"] = {key: final.get(key) for key in
                                 ("present", "valid", "integrity_ok", "applicable",
                                  "pending", "report_id", "version_id", "run_id",
                                  "local_path", "target_sha256", "recorded_at")}
        view["current_final"]["reasons"] = list(final["reasons"])
        view["current_final"]["notes"] = list(final["notes"])
        # Main-agent ruling: only *report integrity* blocks.  A final pointer that
        # merely belongs to a previous version after a normal version bump is an
        # incomplete-but-healthy state ("this version has no final report yet"), so
        # it stays out of ``errors`` and never makes the project corrupt/blocked.
        if not final["integrity_ok"]:
            view["errors"].append({"reason": "当前最终报告指针完整性受损：%s"
                                             % "；".join(final["reasons"]),
                                   "kind": "report_final_invalid",
                                   "report_id": final.get("report_id")})
        elif final["present"] and not final["valid"] and final["pending"]:
            view["next_actions"].append(
                "当前版本尚无 final 报告（历史 final 指针仍指向 %s）：请用新 report_id 为当前版本"
                "登记 final；不要把它当作当前版本的最终记录，也不继承旧版本验收"
                % final.get("version_id"))
        if view["errors"]:
            view["next_actions"].append("修复 reports/ 下的报告索引/正文/证据绑定，或改用新 report_id "
                                        "重新登记（不得静默重生成）；见 project_report.py show/status")
        elif view["present"]:
            view["next_actions"].append("报告与索引可复核；报告只陈述登记事实，功能可用性仍未验证")
    except Exception as exc:  # never let the handoff hook raise
        # Fixed reason + exception *type* only: an exception message can carry a
        # path or a value, and the hook must never become a value-echo channel.
        view["errors"].append({"reason": "报告索引读取失败（project_report.handoff_view 调用失败）",
                               "kind": "report_index",
                               "exception_type": type(exc).__name__})
    return view

# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------
def _root(a) -> Path:
    _require_pstate_api()
    return P.project_root(a.project)

def _body_source(root: Path, value: str) -> Path:
    """A registered body file must be a real project-relative regular file."""
    if not value:
        raise ValueError("--body 必须是项目内相对路径（例如 reports/draft.md）")
    ref = P.relative_ref(value, "body")
    path = project_file(root, ref)
    resolved = path.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("正文路径逃逸项目目录：%s" % ref)
    if path.is_symlink():
        raise ValueError("正文不允许 symlink：%s" % ref)
    if not path.is_file():
        raise FileNotFoundError("正文文件不存在：%s" % ref)
    if path.name in P.METADATA_NAMES or path.name == ".project.lock":
        raise ValueError("项目元数据/账本不能充当报告正文：%s" % ref)
    return path

@project_locked("project", recover=True)
def cmd_generate(a) -> int:
    root = _root(a)
    try:
        project = P.require_project(root)
        report_id = P.require_id(a.report_id, "report_id")
        version_id = P.require_id(a.version, "version")
        run_id = P.require_id(a.run_id, "run_id")
        kind = a.kind
        if kind not in REPORT_KINDS:
            return _refuse("generate", "非法报告类型：%s；允许值：%s"
                           % (kind, ",".join(REPORT_KINDS)))
        claim_evidence_ids = list(a.claim_evidence_id or [])
        try:
            snapshot = _snapshot(root, project, version_id, run_id, claim_evidence_ids)
        except Exception as exc:
            return _refuse("generate", "无法建立报告绑定：%s: %s"
                           % (type(exc).__name__, exc))
        stamp = P.now()
        previous_body = _body_path(root, report_id)
        if previous_body.is_file() and previous_body.stat().st_size <= MAX_BODY_BYTES:
            # The timestamp is part of the immutable generated body. Recompose
            # from current bindings using that original time; _register still
            # refuses changed sources, modified bytes or a missing fact witness.
            prefix = "- 记录时间："
            times = [line[len(prefix):] for line in previous_body.read_text(encoding="utf-8").splitlines()
                     if line.startswith(prefix)]
            if len(times) == 1:
                stamp = times[0]
        body = compose_body(report_id, project, snapshot, kind, stamp)
        return _register(root, project, report_id=report_id, version_id=version_id,
                         run_id=run_id, kind=kind, note=a.note or "", mode="generate",
                         body_source=None, body_bytes=body.encode("utf-8"),
                         declared_sha="", declared_size=None,
                         claim_evidence_ids=claim_evidence_ids)
    except Exception as exc:
        return _refuse("generate", "%s: %s" % (type(exc).__name__, exc))

@project_locked("project", recover=True)
def cmd_register(a) -> int:
    root = _root(a)
    try:
        project = P.require_project(root)
        report_id = P.require_id(a.report_id, "report_id")
        version_id = P.require_id(a.version, "version")
        run_id = P.require_id(a.run_id, "run_id")
        if a.kind not in REPORT_KINDS:
            return _refuse("register", "非法报告类型：%s；允许值：%s"
                           % (a.kind, ",".join(REPORT_KINDS)))
        source = _body_source(root, a.body)
        if source.stat().st_size > MAX_BODY_BYTES:
            return _refuse("register", "正文超过 %d 字节上限：拒绝把整份未知日志 dump 进报告"
                           % MAX_BODY_BYTES)
        ref = P.relative_ref(str(source.relative_to(root)), "body")
        if ref == "reports" or ref.startswith("reports/"):
            return _refuse("register", "报告目录由本模块独占，不能把其中的文件当作正文再登记：%s" % ref)
        body_bytes = source.read_bytes()
        return _register(root, project, report_id=report_id, version_id=version_id,
                         run_id=run_id, kind=a.kind, note=a.note or "", mode="register",
                         body_source=ref, body_bytes=body_bytes,
                         declared_sha=a.sha256 or "", declared_size=a.size)
    except Exception as exc:
        return _refuse("register", "%s: %s" % (type(exc).__name__, exc))

@project_locked("project")
def cmd_show(a) -> int:
    root = _root(a)
    try:
        project = P.require_project(root)
        entries, problems = _read_index(root)
        if a.final:
            final = _final_view(root, project)
            # ``ok`` mirrors *integrity*: an intact historical final pointer is a
            # success with ``applicable=false`` / ``pending=current_final_missing``,
            # never a corrupt project and never a current-version final report.
            ok = final["integrity_ok"] and not problems
            result = {"ok": ok, "mode": "final",
                      "current_final_complete": bool(final["valid"]),
                      "current_final_pending": final["pending"],
                      "final": {key: final.get(key) for key in final if key != "report"},
                      "report": final.get("report"), "index_problems": problems,
                      **core_handoff_status()}
            return _emit(result, 0 if ok else 2)
        if not a.report_id:
            return _refuse("show", "需要 --report-id 或 --final")
        report_id = P.require_id(a.report_id, "report_id")
        entry = _index_entry(entries, report_id)
        if entry is None:
            result = {"ok": False, "mode": "report", "report_id": report_id,
                      "reason": "该 report_id 未在 reports/index.jsonl 登记",
                      "index_problems": problems}
            return _emit(result, 2)
        view = _verify(root, project, entry)
        ok = view["fresh"] and not problems
        result = {"ok": ok, "mode": "report", "report": view,
                  "index_problems": problems, **core_handoff_status()}
        return _emit(result, 0 if ok else 2)
    except Exception as exc:
        return _refuse("show", "%s: %s" % (type(exc).__name__, exc))

@project_locked("project")
def cmd_status(a) -> int:
    root = _root(a)
    try:
        project = P.require_project(root)
        entries, problems = _read_index(root)
        registered = [entry for entry in entries if entry.get("kind") == "registered"]
        reports = []
        for entry in registered:
            view = _verify(root, project, entry)
            reports.append({"report_id": entry.get("report_id"),
                            "kind": entry.get("report_kind"),
                            "version_id": entry.get("version_id"),
                            "run_id": entry.get("run_id"),
                            "created_at": entry.get("created_at"),
                            "fresh": view["fresh"],
                            "stale": view["stale"], "advanced": view["advanced"]})
        final = _final_view(root, project)
        # ``ok`` = everything is *intact*; a missing/stale-scope current final report
        # is reported as pending, not as damage (see _final_view).
        ok = not problems and all(row["fresh"] for row in reports) and final["integrity_ok"]
        result = {"ok": ok, "schema": REPORT_SCHEMA, "index": {
                      "local_path": INDEX_NAME, "entries": len(registered),
                      "problems": problems},
                  "reports": reports,
                  "final_pointer": {key: final.get(key) for key in final if key != "report"},
                  "current_final_complete": bool(final["valid"]),
                  "current_final_pending": final["pending"],
                  "stale_reports": [row["report_id"] for row in reports if not row["fresh"]],
                  "proof_level": P.PROOF_LEVEL, "proof_limits": list(P.PROOF_LIMITS),
                  **core_handoff_status()}
        return _emit(result, 0 if ok else 2)
    except Exception as exc:
        return _refuse("status", "%s: %s" % (type(exc).__name__, exc))

# ---------------------------------------------------------------------------
# self test (structure only; the real chain lives in test_project_report.py)
# ---------------------------------------------------------------------------
def self_test() -> int:
    checks = []

    def record(name: str, condition: bool) -> None:
        checks.append((name, bool(condition)))

    good = ("# t\n\n## 1 结论\n- a\n- b\n\n## 2 已确认\n- a\n- b\n\n## 3 仍未知\n- a\n- b\n\n"
            "## 4 下一步\n- a\n- b\n\n## 5 复查\n- a\n- b\n")
    record("five sections accepted", body_problems(good) == [])
    record("missing section rejected", bool(body_problems(good.replace("## 3 仍未知", "## 3 未知"))))
    record("long conclusion rejected",
           bool(body_problems(good.replace("- a\n- b\n\n## 2", "- a\n- b\n- c\n- d\n\n## 2"))))
    record("hedge wording rejected", bool(body_problems(good + "大概能成功\n")))
    record("kind note marks interim",
           "interim" in _kind_note("interim") and "final" in _kind_note("final"))
    record("binding ignores created_at",
           _binding({"a": 1, "created_at": "x", "binding_sha256": "y"}) == {"a": 1})
    ok = all(condition for _name, condition in checks)
    print(json.dumps({"ok": ok, "checks": len(checks),
                      "failures": [name for name, value in checks if not value],
                      "note": "结构自测；真实链路见 test_project_report.py"},
                     ensure_ascii=False))
    return 0 if ok else 2

def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="项目报告登记层（report_id + 五段报告 + 可复核 manifest）。只写 <项目>/reports/，"
                    "不执行目标、不解析日志语义、不改目标/验收/收尾；core handoff 接线状态按"
                    "实际 source 只读探测（core_handoff_wired / integration_pending + pending_scopes）。")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("generate",
                       help="从已登记记录生成五段报告并登记（--kind final 表示本 run 最终记录）")
    p.add_argument("--project", required=True, help="项目根目录（显式指定，报告只写其 reports/ 下）")
    p.add_argument("--report-id", required=True, help="唯一报告 ID（字母数字._-，已登记不可覆盖）")
    p.add_argument("--version", required=True, help="报告绑定的版本 ID（必须真实存在）")
    p.add_argument("--run-id", required=True, help="报告绑定的 run ID（必须真实存在且属于该版本）")
    p.add_argument("--kind", default="interim", choices=list(REPORT_KINDS),
                   help="interim=阶段性记录（默认）；final=本 run 最终记录（run 必须已收尾，"
                        "只针对当前版本，不代表整个 Goal 成功）")
    p.add_argument("--note", default="", help="登记备注（只存 manifest，不进正文；命中凭据模式即拒）")
    p.add_argument("--claim-evidence-id", action="append", default=[],
                   help="可重复：指定已由 Core evidence 登记的 project-relative claim ledger JSONL evidence")
    p = sub.add_parser("register",
                       help="登记已写好的五段报告正文（项目内相对路径），复用同一绑定规则")
    p.add_argument("--project", required=True, help="项目根目录")
    p.add_argument("--report-id", required=True, help="唯一报告 ID")
    p.add_argument("--version", required=True, help="报告绑定的版本 ID")
    p.add_argument("--run-id", required=True, help="报告绑定的 run ID")
    p.add_argument("--body", required=True,
                   help="正文的项目内相对路径（不得是外部/绝对/../、symlink 或项目元数据）")
    p.add_argument("--kind", default="interim", choices=list(REPORT_KINDS),
                   help="interim（默认）或 final（本 run 最终记录）")
    p.add_argument("--sha256", default="", help="可选的正文 sha256 声明；与实际不符即拒绝")
    p.add_argument("--size", default="", help="可选的正文字节数声明；与实际不符即拒绝")
    p.add_argument("--note", default="", help="登记备注（只存 manifest）")
    p = sub.add_parser("show", help="复核一份报告（正文/证据/索引/目标/收尾），报告 stale 项")
    p.add_argument("--project", required=True, help="项目根目录")
    p.add_argument("--report-id", default="", help="要复核的 report_id")
    p.add_argument("--final", action="store_true", help="复核当前 reports/final.json 指针")
    p = sub.add_parser("status", help="列出索引、最终指针与所有 stale 报告（只读）")
    p.add_argument("--project", required=True, help="项目根目录")
    ap.add_argument("--self-test", action="store_true", help="内部结构自测（不含真实链路）")
    return ap

def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    ap = parser()
    try:
        reject_sensitive(raw, "argv")
        a = ap.parse_args(raw)
        reject_sensitive(vars(a), "arguments")
    except Exception as exc:
        return _refuse("args", "参数/输入未通过凭据或格式检查：%s" % exc)
    if a.self_test:
        return self_test()
    if not a.cmd:
        ap.print_help()
        return 4
    if a.cmd == "generate":
        return cmd_generate(a)
    if a.cmd == "register":
        return cmd_register(a)
    if a.cmd == "show":
        return cmd_show(a)
    if a.cmd == "status":
        return cmd_status(a)
    ap.print_help()
    return 4

if __name__ == "__main__":
    raise SystemExit(main())
