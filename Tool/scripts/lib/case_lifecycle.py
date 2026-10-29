"""Bounded case creation and question-card transactions.

Cooperating writers hold the case lock. Local files commit together; the user's
current-case pointer is a separate convenience marker and is reported separately.
"""
from __future__ import annotations

import json
import functools
import os
from pathlib import Path
import re
import uuid

from .case_repro import _local, _plain
from .project_lock import project_lock
from .project_transaction import file_transaction


def recovering(function):
    """A lifecycle writer may recover under the lock before opening the ledger."""
    @functools.wraps(function)
    def invoke(args):
        try:
            root = _plain(Path(os.path.abspath(args.case)))
            if not root.is_dir():
                raise ValueError("case directory is missing")
            with project_lock(root, recover=True):
                return function(args)
        except (OSError, ValueError, TypeError, TimeoutError) as exc:
            print("[ERR] case lifecycle refused: %s" % exc)
            return 2
    return invoke


def _target_key(api, root, value):
    if not isinstance(value, str):
        raise ValueError("case target must be a string")
    if not value or api.URL_RE.match(value):
        return value
    return os.path.normcase(os.path.abspath(root / value))


def _registered_targets(api, root, meta):
    """Validate and normalize the legacy target_files identity ledger."""
    entries = meta.get("target_files", [])
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise ValueError("case.json target_files must be an array of objects")
    rows = []
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("case.json target_files must be an array of objects")
        raw = item.get("path")
        if raw in (None, ""):
            continue
        key = _target_key(api, root, raw)
        sha = item.get("sha256")
        if sha is not None:
            if not isinstance(sha, str) or (
                    sha and re.fullmatch(r"[0-9a-fA-F]{64}", sha) is None):
                raise ValueError("case.json target_files sha256 must be empty or a full SHA-256")
            sha = sha.lower()
        size = item.get("size")
        if size is not None and (
                not isinstance(size, int) or isinstance(size, bool) or size < 0):
            raise ValueError("case.json target_files size must be a non-negative integer")
        rows.append({"raw": raw, "key": key, "sha256": sha or "", "size": size})
    return rows


def initialize(args, api):
    root = _plain(Path(os.path.abspath(args.case)))
    root.mkdir(parents=True, exist_ok=True)
    with project_lock(root, recover=True):
        api.lease_guard(str(root))
        rows = api.load_ledger(str(root))
        existing = [row["state"] for row in rows if api._entry_kind(row) == "state"]
        metadata = _local(root, "case.json")
        meta = {}
        if metadata.exists():
            meta = json.loads(metadata.read_text(encoding="utf-8"), object_pairs_hook=api._case_ledger._unique)
            if not isinstance(meta, dict):
                raise ValueError("case.json must be an object")
        if (existing or metadata.exists() or api._legacy_files(str(root))) and not args.force:
            raise ValueError("case already exists; inspect it or use --force for the same target")
        registered = _registered_targets(api, root, meta)
        old_target = meta.get("target", {})
        if not isinstance(old_target, (dict, str)):
            raise ValueError("invalid registered case target")
        prior = old_target.get("path", "") if isinstance(old_target, dict) else old_target
        state_target = existing[-1].get("target", "") if existing else ""
        if prior and state_target and _target_key(api, root, prior) != _target_key(api, root, state_target):
            raise ValueError("case metadata and state target disagree; preserve and reconcile the case first")
        prior = prior or state_target
        if prior and registered and _target_key(api, root, prior) not in {
                item["key"] for item in registered}:
            raise ValueError("case metadata and target_files disagree; preserve and reconcile the case first")
        if not prior and registered:
            # Older cases have only target_files.  Their first entry is the
            # primary identity; init must not silently create a second one.
            prior = registered[0]["raw"]
        requested = api.store_target(args.target) if str(args.target or "").strip() else ""
        if prior and requested and _target_key(api, root, prior) != _target_key(api, root, requested):
            raise ValueError("--force cannot replace a case target; create a separate case")
        target = requested or prior
        if target and not api.URL_RE.match(target):
            target = os.path.abspath(root / target)
        fingerprint = api._fingerprint_target(target)
        if isinstance(old_target, dict) and old_target.get("sha256"):
            if old_target["sha256"] != fingerprint.get("sha256") or (
                    old_target.get("size") is not None and old_target["size"] != fingerprint.get("size")):
                raise ValueError("registered target bytes changed; --force cannot rewrite their history")
        if prior and registered:
            row = next(item for item in registered
                       if item["key"] == _target_key(api, root, prior))
            if row["sha256"] and row["sha256"] != str(fingerprint.get("sha256") or "").lower():
                raise ValueError("registered target bytes changed; --force cannot rewrite their history")
            if row["size"] is not None and row["size"] != fingerprint.get("size"):
                raise ValueError("registered target bytes changed; --force cannot rewrite their history")
        # A recovery init repairs identity/metadata; it must not erase a live
        # state and leave the separate plan/gaps/claims ledgers out of sync.
        state = json.loads(json.dumps(existing[-1], ensure_ascii=False)) if existing else api._state_default()
        state["target"] = target
        if not str(state.get("next_action") or "").strip():
            state["next_action"] = "跑 D0 结构 + D1 存活"
        row = {"kind": "state", "ts": state["updated"], "state": state}
        api._case_ledger.validate_rows(rows + [row])
        facts = _local(root, "facts.jsonl")
        scope = _local(root, "scope.md")
        with file_transaction(root, ["facts.jsonl", "case.json", "scope.md"]):
            api._atomic_append_line(str(facts), json.dumps(row, ensure_ascii=False, allow_nan=False))
            api._ensure_case_meta(str(root), state, getattr(args, "evidence_kind", "unknown"),
                                  fingerprint, domain=getattr(args, "domain", "") or "")
            if not scope.exists():
                api._atomic_write_text(str(scope), "\n".join([
                    "# 范围记录", "", "## 目标", "", "- 目标：" + (target or "（未指定）"), "",
                    "## 边界与环境", "", "- 记录当前任务的边界、运行环境和交付预期。",
                    "- 根据用户要求和实际环境补充，不把模板当成已核实的事实。", "",
                ]))
        try:
            pointer = Path(os.path.expanduser("~")) / ".seep/current-case"
            api._atomic_write_text(str(pointer), str(root))
            print("[OK] 当前案例指针已更新：%s" % pointer)
        except OSError as exc:
            print("[WARN] 案例已提交，当前案例指针更新失败：%s" % exc)
        print("[OK] 案例状态、元数据和范围记录已提交：%s" % root)
        print("[INFO] 目标指纹：%s" % (fingerprint.get("sha256") or "未登记；目标尚未就位或为 URL"))
    return 0


def publish_question(case, state, lines, awaiting, api):
    """Commit a unique card and its awaiting state, or restore both on failure."""
    root = _plain(Path(os.path.abspath(case)))
    reference = "ask/%s-%s.md" % (api.now().replace(":", "").replace("-", ""), uuid.uuid4().hex)
    card = _local(root, reference)
    state["awaiting_human"] = dict(awaiting, card=str(card))
    state["updated"] = api.now()
    row = {"kind": "state", "ts": state["updated"], "state": state}
    api._case_ledger.validate_rows(api.load_ledger(case) + [row])
    with file_transaction(root, [reference, "facts.jsonl"]):
        card.parent.mkdir(exist_ok=True)
        api._atomic_write_text(str(card), "\n".join(lines) + "\n")
        api._atomic_append_line(str(root / "facts.jsonl"), json.dumps(row, ensure_ascii=False, allow_nan=False))
    return str(card)
