#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Manager Mode: auditable, resumable orchestration state.

The manager ledger is append-only JSONL.  Every command replays the ledger
before validating or applying a transition; the derived handoff is never the
source of truth.  This layer deliberately does not replace case_state.py.
"""
from __future__ import annotations

import argparse
import ast
import copy
import contextlib
import hashlib
import io
import json
import math
import os
import re
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

try:
    from project_state import PROJECT_SCHEMA, RUN_SCHEMA, VERSION_SCHEMA, require_project
    import project_state as project_reader
except ImportError:  # pragma: no cover - useful when imported outside Tool/scripts
    from Tool.scripts.project_state import PROJECT_SCHEMA, RUN_SCHEMA, VERSION_SCHEMA, require_project
    from Tool.scripts import project_state as project_reader

MANAGER_SCHEMA = "seep-manager/1"
STATE_SCHEMA = "seep-manager-state/1"
HANDOFF_SCHEMA = "seep-manager-handoff/1"
LEDGER_NAME = "manager-events.jsonl"
LOCK_NAME = ".project.lock"
REPO_ROOT = Path(__file__).resolve().parents[2]
HANDOFF_NAME = "manager-handoff.json"
ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie|"
    r"credential|private[_-]?key|client[_-]?secret|refresh[_-]?token|bearer)", re.I)

# 主对话裁定：以下**精确键名**是公开的非凭据数值参数（输出/预算上限），
# 不能因为键名里含 "token" 就被当成凭据。只有这三个精确键名 + 合法有限非负整数（或
# 合法 CLI int 字符串）才豁免**键名**判定；**值**仍然照常跑 SENSITIVE_VALUE_RE，
# 所以 `{"limit_tokens": "Bearer xxx"}` / PEM / `sk-…` 依旧被拒。
# 注意：`token` / `refresh_token` / `access_token` / `api_key` / `password` 一律不豁免。
PUBLIC_NUMERIC_TOKEN_KEYS = frozenset(("limit_tokens", "max_tokens", "token_budget"))
# 只承认**十进制整数**字符串（不接受 `1.0` / `1e3` / `0x10`：那些不是 CLI int）。
NUMERIC_TOKEN_STRING_RE = re.compile(r"^\s*[+-]?\d{1,20}\s*$")


def public_numeric_value(value: Any) -> bool:
    """合法有限非负 int / 合法 CLI int 字符串 → True（bool、float、负数、其它都 False）。"""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value >= 0
    if isinstance(value, str):
        return bool(NUMERIC_TOKEN_STRING_RE.match(value)) and int(value) >= 0
    return False


SENSITIVE_VALUE_RE = re.compile(
    r"(?:\b(?:password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie|"
    r"credential|client[_-]?secret|refresh[_-]?token)\b[\"']?\s*[:=]\s*\S+|"
    r"\bbearer\s+\S+|-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----|"
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|"
    r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b|"
    r"[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@)", re.I)


def reject_sensitive(value: Any, position: str = "input") -> None:
    """Reject the entire event before serialization. Never echo a matched value/key.

    唯一例外：`PUBLIC_NUMERIC_TOKEN_KEYS` 里的**精确**键名 + 合法有限非负 int（或合法
    CLI int 字符串）时，不因**键名**拒 —— 但该值仍要过 SENSITIVE_VALUE_RE，
    防止 `limit_tokens` 被拿来装真 secret。值不合法（NaN/Inf/小数/非数字串）不在这里
    报凭据错误：交给工具 validator 做结构化参数拒（本层不替它下结论）。
    """
    if isinstance(value, dict):
        for index, (key, item) in enumerate(value.items()):
            location = "%s.field[%d]" % (position, index)
            # 这三个**精确**键名是公开的参数名，键名启发式对它不适用（不是凭据）。
            # 但**值**仍要扫凭据模式；值本身不合法（NaN/Inf/小数/非数字串）不在这里
            # 报凭据，留给工具 validator 结构化拒 —— Manager 不替它下结论、也不假报凭据。
            named_public = str(key) in PUBLIC_NUMERIC_TOKEN_KEYS
            if not named_public and SENSITIVE_KEY_RE.search(str(key)):
                raise ManagerError("sensitive-key at " + location)
            reject_sensitive(item, location)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            reject_sensitive(item, "%s[%d]" % (position, index))
    elif isinstance(value, str):
        if SENSITIVE_VALUE_RE.search(value):
            raise ManagerError("sensitive-value at " + position)
        # JSON arguments must receive the same nested-key checks as Python callers.
        if value.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(value)
            except (ValueError, TypeError):
                return
            reject_sensitive(parsed, position + ".json")



class ManagerError(Exception):
    pass


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def require_id(value: str, label: str) -> str:
    value = str(value or "").strip()
    if not value or value in (".", "..") or not ID_RE.fullmatch(value):
        raise ManagerError("%s 无效：只能包含字母、数字、点、连字符和下划线" % label)
    return value


def project_root(value: str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(value))))


def ledger_path(root: Path) -> Path:
    return root / LEDGER_NAME


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".manager-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(value, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        try:
            dfd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _append_event(root: Path, event_type: str, payload: dict, refs: dict) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    if ledger_path(root).is_symlink():
        raise ManagerError("manager ledger path invalid")
    event = {
        "schema": MANAGER_SCHEMA,
        "event_id": "ME-" + uuid.uuid4().hex[:16],
        "event_type": event_type,
        "created_at": now(),
        "references": refs,
        "payload": payload,
    }
    reject_sensitive(event, "event")
    raw = (json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    path = ledger_path(root)
    fd, temporary = tempfile.mkstemp(prefix=".manager-ledger-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as output:
            last_block = b""
            if path.is_file():
                with path.open("rb") as source:
                    while True:
                        block = source.read(1 << 20)
                        if not block:
                            break
                        output.write(block)
                        last_block = block
            # A valid final JSON event may omit its line terminator. Preserve
            # its bytes and delimit the next event instead of joining objects.
            if last_block and not last_block.endswith(b"\n"):
                output.write(b"\n")
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        try:
            directory = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            pass
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return event


def _payload_shape(kind: str, payload: dict) -> None:
    """Validate stored/request shapes without re-resolving historical sources."""
    if not isinstance(payload, dict):
        raise ManagerError("manager payload must be an object")
    def text(key, data=payload):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise ManagerError("manager payload missing/invalid " + key)
    def strings(key, data=payload):
        value = data.get(key)
        if value is not None and (not isinstance(value, list) or
                                  any(not isinstance(x, str) for x in value)):
            raise ManagerError("manager payload invalid list " + key)
    def route(value):
        if not isinstance(value, dict):
            raise ManagerError("manager route must be an object")
        text("route_id", value)
        require_id(value["route_id"], "route_id")
        rate = value.get("success_rate")
        if isinstance(rate, bool) or not isinstance(rate, (int, float)):
            raise ManagerError("manager route success_rate invalid")
        if not math.isfinite(float(rate)) or not 0 <= float(rate) <= 1:
            raise ManagerError("manager route success_rate invalid")
        for key in ("estimated_hours", "fail_criteria", "evidence_goal"):
            text(key, value)
        strings("needs", value)
    def optional_text(key, data=payload):
        value = data.get(key)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ManagerError("manager payload invalid " + key)
    def optional_sha(key, data=payload):
        value = data.get(key)
        if value is not None and (
                not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None):
            raise ManagerError("manager payload invalid " + key)
    if kind == "intake":
        for key in ("user_quote", "primary_domain", "target_version"):
            text(key)
        strings("auxiliary_domains")
        started = payload.get("generation_started_ns", 0)
        if type(started) is not int or started < 0:
            raise ManagerError("manager generation timestamp invalid")
        optional_text("generation_id")
        optional_text("target_kind")
        optional_text("generation_reason")
        optional_sha("target_sha256")
        if "new_generation" in payload and type(payload["new_generation"]) is not bool:
            raise ManagerError("manager new_generation invalid")
        previous = payload.get("previous_generation")
        if previous is not None:
            if not isinstance(previous, dict):
                raise ManagerError("manager previous_generation invalid")
            text("generation_id", previous)
            require_id(previous["generation_id"], "generation_id")
            references = previous.get("references")
            _references_shape(references)
            optional_sha("target_sha256", previous)
            if type(previous.get("replan_required")) is not bool:
                raise ManagerError("manager previous_generation replan flag invalid")
            optional_text("replan_reason", previous)
    elif kind == "plan":
        route(payload.get("route"))
    elif kind == "choose":
        text("route_id")
        require_id(payload["route_id"], "route_id")
    elif kind == "wait":
        options = payload.get("options")
        if not isinstance(options, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in options.items()):
            raise ManagerError("manager wait options invalid")
        strings("monitor")
        strings("guarantee")
        text("expected_input")
    elif kind == "answer":
        text("choice")
    elif kind == "attempt":
        attempt = payload.get("attempt")
        if not isinstance(attempt, dict):
            raise ManagerError("manager attempt must be an object")
        for key in ("route_id", "outcome", "result"):
            text(key, attempt)
        require_id(attempt["route_id"], "route_id")
        if attempt["outcome"] not in {"succeeded", "success", "failed", "fail", "blocked", "partial"}:
            raise ManagerError("manager attempt outcome invalid")
        for key in ("evidence", "evidence_refs"):
            if key in attempt and not isinstance(attempt[key], list):
                raise ManagerError("manager attempt evidence must be a list")
        for key in ("evidence", "evidence_refs"):
            for item in attempt.get(key) or []:
                if not isinstance(item, (str, dict)):
                    raise ManagerError("manager attempt evidence element invalid")
        if "capability_sources" in attempt and (
                not isinstance(attempt["capability_sources"], list)
                or any(not isinstance(item, dict) for item in attempt["capability_sources"])):
            raise ManagerError("manager attempt capability_sources invalid")
    elif kind == "replan":
        text("reason")
        text("new_route_id")
        require_id(payload["new_route_id"], "new_route_id")
        if payload.get("route") is not None:
            route(payload["route"])
    else:
        raise ManagerError("manager event type invalid")


def _references_shape(references: object) -> None:
    if not isinstance(references, dict) or set(references) != {"project_id", "version_id", "run_id"}:
        raise ManagerError("manager references structure invalid")
    for key in ("project_id", "version_id"):
        if not isinstance(references[key], str):
            raise ManagerError("manager references invalid " + key)
        require_id(references[key], key)
    if references.get("run_id") is not None:
        if not isinstance(references["run_id"], str):
            raise ManagerError("manager references invalid run_id")
        require_id(references.get("run_id"), "run_id")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManagerError("manager event contains duplicate JSON keys")
        result[key] = value
    return result


def read_events(root: Path) -> list[dict]:
    path = ledger_path(root)
    if path.is_symlink():
        raise ManagerError("manager ledger path invalid")
    if not path.exists():
        return []
    events = []
    seen = set()
    for line_no, raw in enumerate(path.read_bytes().splitlines(), 1):
        if not raw.strip():
            raise ManagerError("%s 第 %d 行为空，账本不可重放" % (path, line_no))
        try:
            event = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ManagerError("manager ledger invalid JSON/UTF-8 at line %d" % line_no)
        if not isinstance(event, dict) or event.get("schema") != MANAGER_SCHEMA:
            raise ManagerError("%s 第 %d 行 schema 无效" % (path, line_no))
        if (not isinstance(event.get("event_id"), str) or not event["event_id"]
                or not isinstance(event.get("event_type"), str)
                or not isinstance(event.get("created_at"), str) or not event["created_at"]
                or not isinstance(event.get("references"), dict)):
            raise ManagerError("manager event structure invalid at line %d" % line_no)
        require_id(event["event_id"], "event_id")
        _references_shape(event["references"])
        if event["event_id"] in seen:
            raise ManagerError("manager duplicate event id at line %d" % line_no)
        seen.add(event["event_id"])
        _payload_shape(event["event_type"], event.get("payload"))
        events.append(event)
    return events


def default_state() -> dict:
    return {
        "generation_id": None,
        "generation_started_ns": 0,
        "target_sha256": None,
        "target_kind": None,
        "evidence_errors": [],
        "schema": STATE_SCHEMA,
        "status": "uninitialized",
        "phase": "intake",
        "user_input": {"quote": "", "primary_domain": "", "auxiliary_domains": [], "target_version": ""},
        "references": {"project_id": "", "version_id": "", "run_id": None},
        "routes": {},
        "selected_route_id": None,
        "retired_route_ids": [],
        "waiting": None,
        "attempts": [],
        "replan_required": False,
        "replan_reason": None,
        "next_actions": [],
        "updated_at": None,
    }


def _failed_attempt(attempt: dict) -> bool:
    return str(attempt.get("outcome") or "").lower() in {"failed", "fail", "blocked"}


def replay(events: list[dict]) -> dict:
    state = default_state()
    for index, event in enumerate(events):
        t = event["event_type"]
        p = event["payload"]
        _payload_shape(t, p)
        if t == "intake":
            if not state.get("generation_id") and index != 0:
                raise ManagerError("manager replay has no prior intake")
            if state.get("generation_id") and p.get("new_generation"):
                previous = p.get("previous_generation") or {}
                if (previous.get("generation_id") != state["generation_id"]
                        or previous.get("references") != state["references"]):
                    raise ManagerError("manager replay previous_generation does not match current state")
            generation_id = p.get("generation_id")
            if generation_id is not None:
                require_id(generation_id, "generation_id")
                if state.get("generation_id") == generation_id:
                    raise ManagerError("manager replay reuses an active generation id")
            # Every accepted intake starts an isolated generation. Legacy intakes
            # are isolated too; their unbound evidence will subsequently be stale.
            state = default_state()
            state["generation_id"] = generation_id or event["event_id"]
            state["target_sha256"] = p.get("target_sha256")
            state["target_kind"] = p.get("target_kind")
            state["generation_started_ns"] = p.get("generation_started_ns", 0)
            state["user_input"] = {
                "quote": p.get("user_quote", ""),
                "primary_domain": p.get("primary_domain", ""),
                "auxiliary_domains": list(p.get("auxiliary_domains") or []),
                "target_version": p.get("target_version", ""),
            }
            state["references"] = dict(event.get("references") or {})
            state["status"], state["phase"] = "active", "intake"
            state["next_actions"] = ["登记并评估候选路线"]
        else:
            if not state.get("generation_id"):
                raise ManagerError("manager replay transition precedes intake")
            if event["references"] != state["references"]:
                raise ManagerError("manager replay references change without intake")
            if (state.get("waiting") or {}).get("status") == "WAIT_USER" and t != "answer":
                raise ManagerError("manager replay performs %s while WAIT_USER is active" % t)

            if t == "plan":
                route = dict(p["route"])
                if route["route_id"] in state["routes"]:
                    raise ManagerError("manager replay duplicates route_id")
                state["routes"][route["route_id"]] = route
                state["phase"] = "plan"
                state["status"] = "active"
                state["next_actions"] = ["选择一条候选路线"]
            elif t == "choose":
                rid = p["route_id"]
                if rid not in state["routes"]:
                    raise ManagerError("manager replay chooses an unknown route")
                if rid in state["retired_route_ids"]:
                    raise ManagerError("manager replay chooses a retired route")
                if state.get("replan_required"):
                    raise ManagerError("manager replay chooses before replan")
                state["selected_route_id"] = rid
                state["phase"], state["status"] = "choose", "active"
                state["next_actions"] = ["执行最小尝试，或在需要用户输入时登记 WAIT_USER"]
            elif t == "wait":
                if not state.get("selected_route_id"):
                    raise ManagerError("manager replay waits before route selection")
                if len(p["options"]) < 2 or not all(
                        p.get(k) for k in ("monitor", "guarantee", "expected_input")):
                    raise ManagerError("manager replay WAIT_USER incomplete")
                state["waiting"] = {
                    "status": "WAIT_USER", "options": dict(p["options"]),
                    "monitor": list(p.get("monitor") or []),
                    "guarantee": list(p.get("guarantee") or []),
                    "expected_input": p.get("expected_input", ""),
                    "created_at": event["created_at"], "answer": None,
                }
                state["status"], state["phase"] = "blocked", "wait"
                state["next_actions"] = ["等待用户选择后执行 answer"]
            elif t == "answer":
                waiting = state.get("waiting") or {}
                if waiting.get("status") != "WAIT_USER":
                    raise ManagerError("manager replay answers without WAIT_USER")
                if p["choice"] not in waiting.get("options", {}):
                    raise ManagerError("manager replay answer not in options")
                state["waiting"]["answer"] = {"choice": p["choice"], "at": event["created_at"]}
                state["waiting"]["status"] = "answered"
                state["status"], state["phase"] = "active", "answer"
                state["next_actions"] = ["按用户选择继续当前路线"]
            elif t == "attempt":
                attempt = dict(p["attempt"])
                if not state.get("selected_route_id") or attempt.get("route_id") != state["selected_route_id"]:
                    raise ManagerError("manager replay attempt route is not selected")
                if state.get("replan_required"):
                    raise ManagerError("manager replay attempt precedes required replan")
                state["attempts"].append(attempt)
                if _failed_attempt(attempt):
                    failures = 0
                    for old in reversed(state["attempts"]):
                        if old.get("route_id") != attempt.get("route_id"):
                            continue
                        if not _failed_attempt(old):
                            break
                        failures += 1
                    if failures >= 2:
                        state["replan_required"] = True
                        state["replan_reason"] = "路线 %s 连续失败 %d 次" % (attempt["route_id"], failures)
                        state["status"], state["phase"] = "blocked", "replan"
                        state["next_actions"] = ["先执行 replan，第三次尝试已阻止"]
                    else:
                        state["status"] = "active"
                        state["next_actions"] = ["继续验证路线 %s；再次失败前应检查失败判据" % attempt["route_id"]]
                else:
                    state["status"], state["phase"] = "active", "attempt"
                    state["next_actions"] = ["检查结果与证据，决定继续、等待或换路"]
            elif t == "replan":
                new_id = p["new_route_id"]
                if new_id == state.get("selected_route_id") or any(
                        old.get("route_id") == new_id for old in state["attempts"]):
                    raise ManagerError("manager replay replan reuses an attempted route")
                route = p.get("route")
                if route:
                    if route["route_id"] != new_id or new_id in state["routes"]:
                        raise ManagerError("manager replay replan route conflicts")
                elif new_id not in state["routes"]:
                    raise ManagerError("manager replay replan route is missing")
                if state.get("selected_route_id"):
                    state["retired_route_ids"].append(state["selected_route_id"])
                if route:
                    state["routes"][route["route_id"]] = dict(route)
                state["selected_route_id"] = new_id
                state["replan_required"] = False
                state["replan_reason"] = None
                state["status"], state["phase"] = "active", "replan"
                state["next_actions"] = ["执行新路线 %s 的最小尝试" % new_id]
        state["updated_at"] = event["created_at"]
    return derive_status(state)


def derive_status(state: dict) -> dict:
    if (state.get("waiting") or {}).get("status") == "WAIT_USER":
        state["status"] = "blocked"
        state["next_actions"] = ["等待用户选择后执行 answer"]
    elif state.get("replan_required"):
        state["status"] = "blocked"
        state["next_actions"] = ["先 replan：新路线及换路解释必填"]
    elif state.get("evidence_errors"):
        state["status"] = "blocked"
        state["next_actions"] = ["证据 stale：核对文件或显式开始新 generation"]
    elif state.get("generation_id"):
        state["status"] = "active"
    return state


def _validate_version(root: Path, project_id: str, version_id: str) -> dict:
    require_id(version_id, "version_id")
    path = root / "versions" / version_id / "version.json"
    if not path.is_file():
        raise ManagerError("版本不存在：%s" % version_id)
    try:
        return project_reader._validate_version(root, version_id, project_id)
    except (OSError, ValueError, KeyError):
        raise ManagerError("version.json 身份或路径无效")


def validate_refs(root: Path, project_ref: str, version_id: str, run_id: str | None = None) -> dict:
    try:
        project = require_project(root)
    except Exception as exc:
        raise ManagerError(str(exc))
    project_id = str(project.get("project_id") or "")
    if project_ref and project_ref != project_id:
        raise ManagerError("project 引用不匹配：%s != %s" % (project_ref, project_id))
    version = _validate_version(root, project_id, version_id)
    run = None
    if run_id:
        require_id(run_id, "run_id")
        path = contained_file(root, "versions/%s/runs/%s/run.json" % (version_id, run_id))
        try:
            run = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
        except (OSError, ValueError) as exc:
            raise ManagerError("run.json 无法读取") from exc
        if not isinstance(run, dict):
            raise ManagerError("run.json must be an object")
        if (run.get("schema"), run.get("run_id"), run.get("version_id")) != (RUN_SCHEMA, run_id, version_id):
            raise ManagerError("run 身份或 version 引用无效：%s" % run_id)
        if run.get("project_id") != project_id:
            raise ManagerError("run project_id 不匹配：%s" % run_id)
    return {"project_id": project_id, "version_id": version_id, "run_id": run_id}


def parse_items(values: list[str] | None) -> list[str]:
    out = []
    for value in values or []:
        text = str(value).strip()
        if not text:
            continue
        if text.startswith("["):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    out.extend(str(x).strip() for x in parsed if str(x).strip())
                    continue
            except json.JSONDecodeError:
                pass
        out.extend(x.strip() for x in text.split(",") if x.strip())
    return out


def parse_options(values: list[str] | None, raw: str = "") -> dict[str, str]:
    if raw:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ManagerError("--options 必须是 JSON 对象或数组：%s" % exc)
        if isinstance(value, dict):
            return {str(k).strip().upper(): str(v).strip() for k, v in value.items() if str(k).strip() and str(v).strip()}
        if isinstance(value, list):
            values = [str(x) for x in value]
        else:
            raise ManagerError("--options 顶层必须是对象或数组")
    result = {}
    for value in values or []:
        text = str(value).strip()
        m = re.match(r"^([A-Za-z])\s*(?:[:=]|[.)、：])\s*(.+)$", text)
        if not m:
            m = re.match(r"^([A-Za-z])\s+(.+)$", text)
        if not m:
            raise ManagerError("选项必须写成 A:内容 或 A 内容：%s" % text)
        result[m.group(1).upper()] = m.group(2).strip()
    return result


def contained_file(root: Path, relative: str) -> Path:
    text = str(relative).replace("\\", "/")
    p = Path(text)
    if not text or p.is_absolute() or ":" in text or ".." in p.parts:
        raise ManagerError("file-ref invalid or outside project")
    resolved = (root / p).resolve()
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ManagerError("file-ref missing or outside project")
    return resolved


@contextlib.contextmanager
def manager_lock(root: Path):
    """Serialize Manager snapshots/transitions with project lifecycle writes."""
    try:
        with project_reader.project_lock(root, timeout=15):
            yield
    except TimeoutError as exc:
        raise ManagerError("project/manager lock timeout") from exc


def target_identity(root: Path, refs: dict, active_run: bool = False) -> str:
    checked = validate_refs(root, refs.get("project_id", ""), refs.get("version_id", ""), refs.get("run_id"))
    project = require_project(root)
    if project.get("current_version_id") != checked["version_id"]:
        raise ManagerError("current version reference stale")
    version = _validate_version(root, checked["project_id"], checked["version_id"])
    try:
        fingerprint = project_reader.target_fingerprint(root, version)
    except Exception as exc:
        raise ManagerError("target identity stale: %s" % type(exc).__name__)
    if not version.get("sha256") or fingerprint["sha256"] != version.get("sha256") \
            or fingerprint["size"] != version.get("size"):
        raise ManagerError("target hash/size stale")
    if active_run:
        if not checked["run_id"]:
            raise ManagerError("active run required")
        run = json.loads(contained_file(root, "versions/%s/runs/%s/run.json" %
                                       (checked["version_id"], checked["run_id"])).read_text(encoding="utf-8"))
        if run.get("status") != "active":
            raise ManagerError("active run required")
    return fingerprint["sha256"]


def evidence_record(root: Path, state: dict, ref: Any) -> dict:
    supplied = ref if isinstance(ref, dict) else {"path": ref}
    path = contained_file(root, supplied.get("path", ""))
    refs = state["references"]
    run_root = root / "versions" / refs["version_id"] / "runs" / str(refs["run_id"])
    if not path.is_relative_to(run_root.resolve()):
        raise ManagerError("evidence must belong to current run directory")
    relative = path.relative_to(root.resolve()).as_posix()
    if path.name == "run.json":
        raise ManagerError("run metadata is not attempt evidence")
    if path.stat().st_mtime_ns < state.get("generation_started_ns", 0):
        raise ManagerError("evidence predates current generation")
    record = {"path": relative, **project_reader.file_fingerprint(path),
              "references": dict(refs), "generation_id": state["generation_id"],
              "target_sha256": state["target_sha256"]}
    if record["size"] == 0:
        raise ManagerError("empty evidence file")
    # Structured references are assertions, not an invitation to refresh old hashes.
    for key in ("sha256", "size", "references", "generation_id", "target_sha256"):
        if key in supplied and supplied[key] != record[key]:
            raise ManagerError("evidence reference stale at " + key)
    return record


def capability_sources(attempt: dict) -> list[dict]:
    """Repository registration only; never read host or credential configuration.

    Builtins bind to source; external MCPs and tools bind to their declarations.
    Neither registration proves availability, a live connection or execution.
    """
    sources = []
    root = REPO_ROOT.resolve()
    tables = {}
    registered = None

    def repository_file(relative: str) -> Path:
        source = (root / relative).resolve()
        if not source.is_relative_to(root) or not source.is_file():
            raise ManagerError("capability registry missing or outside repository: " + relative)
        return source

    def declaration(relative: str, key: str, name: str) -> Path | None:
        if relative not in tables:
            source = repository_file(relative)
            try:
                doc = json.loads(source.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError) as exc:
                raise ManagerError("capability registry unreadable: " + relative) from exc
            if not isinstance(doc, dict) or not isinstance(doc.get(key), dict):
                raise ManagerError("capability registry table invalid: " + relative)
            tables[relative] = (source, doc[key])
        source, table = tables[relative]
        if name not in table:
            return None
        entry = table[name]
        if not isinstance(entry, dict) or not entry:
            raise ManagerError("capability declaration invalid: " + relative)
        if key == "servers" and not any(isinstance(entry.get(k), str) and entry[k].strip()
                                        for k in ("command", "url")):
            raise ManagerError("MCP declaration requires command or url")
        return source

    def builtin_tools() -> tuple[Path, set]:
        nonlocal registered
        server = repository_file("Tool/mcp/seep_mcp_server.py")
        if registered is not None:
            return server, registered
        registered = set()
        try:
            tree = ast.parse(server.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError, SyntaxError) as exc:
            raise ManagerError("builtin capability registry unreadable") from exc
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    call = decorator.func if isinstance(decorator, ast.Call) else decorator
                    if (isinstance(call, ast.Attribute) and call.attr == "tool"
                            and isinstance(call.value, ast.Name) and call.value.id == "server"):
                        registered.add(node.name)
        return server, registered

    for field in ("skills", "mcps", "tools"):
        names = attempt.get(field, [])
        if not isinstance(names, list):
            raise ManagerError("capability declaration must be a list")
        for name in names:
            if not isinstance(name, str):
                raise ManagerError("capability name must be a string")
            name = require_id(name, "capability")
            verification = "registered-source-only"
            registration_path = None
            if field == "skills":
                source = repository_file("Tool/skill/%s/SKILL.md" % name)
            elif field == "mcps" and name == "seep":
                source, builtins = builtin_tools()
                if not builtins:
                    raise ManagerError("unregistered builtin MCP")
            else:
                relative, key = (("Tool/config/mcp-servers.json", "servers") if field == "mcps"
                                 else ("Tool/config/tool-capabilities.json", "tools"))
                source = declaration(relative, key, name)
                if source is not None:
                    verification = "registered-config-only"
                    registration_path = "%s.%s" % (key, name)
                elif field == "tools":
                    source, builtins = builtin_tools()
                    if name not in builtins:
                        raise ManagerError("unregistered capability at attempt.tools")
                else:
                    raise ManagerError("unregistered capability at attempt.mcps")
            record = {"kind": field, "name": name, "source": source.relative_to(root).as_posix(),
                      **project_reader.file_fingerprint(source), "verification": verification}
            if registration_path:
                record["registration_path"] = registration_path
            sources.append(record)
    return sources


def current_context(root: Path) -> tuple[list[dict], dict]:
    with manager_lock(root):
        return _current_context_locked(root)


def _current_context_locked(root: Path) -> tuple[list[dict], dict]:
    events = read_events(root)
    state = replay(events)
    errors = []
    for index, attempt in enumerate(state["attempts"]):
        evidence = attempt.get("evidence")
        if not evidence:
            errors.append({"attempt_index": index, "type": "unbound-legacy-evidence"})
            continue
        for evidence_index, record in enumerate(evidence):
            try:
                evidence_record(root, state, record)
            except (ManagerError, OSError, ValueError):
                errors.append({"attempt_index": index, "evidence_index": evidence_index, "type": "stale-evidence"})
    state["evidence_errors"] = errors
    if state["generation_id"]:
        try:
            if target_identity(root, state["references"]) != state["target_sha256"]:
                raise ManagerError("stale target")
        except (ManagerError, OSError, ValueError):
            state["evidence_errors"].append({"type": "stale-context-or-target"})
    return events, derive_status(state)


def require_ready(root: Path, state: dict, allow_replan: bool = False) -> None:
    if state["status"] == "uninitialized":
        raise ManagerError("尚未 intake：先登记用户原话和项目引用")
    if (state.get("waiting") or {}).get("status") == "WAIT_USER":
        raise ManagerError("当前 WAIT_USER 未 answer，状态 blocked")
    if state.get("replan_required") and not allow_replan:
        raise ManagerError("replan_required：必须新路线及解释")
    if state.get("evidence_errors"):
        raise ManagerError("stale evidence/context：核对后重试或显式新 generation")


def validate_route(route: dict) -> None:
    require_id(route.get("route_id"), "route_id")
    try:
        rate = float(route.get("success_rate"))
    except (ValueError, TypeError):
        raise ManagerError("route success_rate required")
    if not 0 <= rate <= 1:
        raise ManagerError("route success_rate invalid")
    for key in ("estimated_hours", "fail_criteria", "evidence_goal"):
        if not str(route.get(key) or "").strip():
            raise ManagerError("route missing field " + key)
    route["capability_sources"] = capability_sources(route)


def check_action(root: Path, refs: dict, route_id: str, target_sha256: str, generation_id: str) -> dict:
    """Snapshot authorization check only. Host must call immediately before action.

    It does not execute targets, reserve a run, or enforce other entry points.
    """
    reject_sensitive({"references": refs, "route_id": route_id,
                      "target_sha256": target_sha256, "generation_id": generation_id})
    with manager_lock(root):
        events, state = current_context(root)
        require_ready(root, state)
        if refs != state["references"] or generation_id != state["generation_id"]:
            raise ManagerError("action current references/generation stale")
        if not route_id or route_id != state["selected_route_id"] or route_id not in state["routes"]:
            raise ManagerError("action route is not selected")
        actual = target_identity(root, refs, active_run=True)
        if actual != target_sha256 or actual != state["target_sha256"]:
            raise ManagerError("action target hash stale")
        return {"ok": True, "allowed": True, "status": state["status"], "references": refs,
                "generation_id": generation_id, "route_id": route_id, "target_sha256": actual,
                "ledger_head": events[-1]["event_id"], "checked_at": now(),
                "scope": "manager-snapshot-only", "host_wiring_required": True,
                "globally_enforced": False, "executes_target": False}


def transition(root: Path, event_type: str, payload: dict, refs: dict) -> tuple[dict, dict]:
    reject_sensitive({"event_type": event_type, "payload": payload, "references": refs}, "event")
    _references_shape(refs)
    _payload_shape(event_type, payload)
    payload, refs = copy.deepcopy(payload), dict(refs)
    if event_type not in {"intake", "plan", "choose", "wait", "answer", "attempt", "replan"}:
        raise ManagerError("unsupported event type")
    with manager_lock(root):
        events, state = current_context(root)
        if event_type == "intake":
            if (state.get("waiting") or {}).get("status") == "WAIT_USER":
                raise ManagerError("WAIT_USER blocks intake, including new generation")
            if state["generation_id"] and refs == state["references"]:
                raise ManagerError("same-context intake rejected; generation cannot reset current route/attempts")
            if state["generation_id"] and not payload.get("new_generation"):
                raise ManagerError("intake already exists; explicit --new-generation required")
            if not str(payload.get("user_quote") or "").strip() or payload.get("target_version") != refs.get("version_id"):
                raise ManagerError("intake quote/version required")
            if payload.get("new_generation") and not str(payload.get("generation_reason") or "").strip():
                raise ManagerError("new generation requires explanation")
            payload["target_sha256"] = target_identity(root, refs)
            if state.get("replan_required"):
                if (refs.get("version_id") == state["references"].get("version_id")
                        or payload["target_sha256"] == state["target_sha256"]):
                    raise ManagerError("replan_required blocks resetting the same target; replan first")
            if state["generation_id"]:
                payload["previous_generation"] = {
                    "generation_id": state["generation_id"], "references": dict(state["references"]),
                    "target_sha256": state["target_sha256"], "replan_required": state["replan_required"],
                    "replan_reason": state["replan_reason"],
                }
            payload["target_kind"] = project_reader._validate_version(
                root, refs["version_id"], refs["project_id"]).get("kind", "file")
            payload["generation_id"] = "GEN-" + uuid.uuid4().hex
            payload["generation_started_ns"] = time.time_ns()
        else:
            if refs != state["references"]:
                raise ManagerError("transition current references stale")
            if event_type == "answer":
                waiting = state.get("waiting") or {}
                if waiting.get("status") != "WAIT_USER":
                    raise ManagerError("当前没有未解除的 WAIT_USER")
                if payload["choice"] not in waiting.get("options", {}):
                    raise ManagerError("用户选择不在选项中")
            else:
                require_ready(root, state, allow_replan=event_type == "replan")
                if target_identity(root, refs) != state["target_sha256"]:
                    raise ManagerError("target identity stale")
            if event_type == "plan":
                route = payload["route"]
                validate_route(route)
                if route["route_id"] in state["routes"]:
                    raise ManagerError("route_id already exists")
            elif event_type == "choose":
                if payload["route_id"] not in state["routes"]:
                    raise ManagerError("候选路线不存在")
                if payload["route_id"] in state["retired_route_ids"]:
                    raise ManagerError("retired route cannot be selected in this generation")
            elif event_type == "wait":
                if not state.get("selected_route_id"):
                    raise ManagerError("wait 前必须先 choose 一条路线")
                if len(payload.get("options", {})) < 2 or not all(payload.get(k) for k in ("monitor", "guarantee", "expected_input")):
                    raise ManagerError("WAIT_USER requires options/monitor/guarantee/expected_input")
            elif event_type == "attempt":
                attempt = payload["attempt"]
                if not state.get("selected_route_id") or attempt.get("route_id") != state["selected_route_id"]:
                    raise ManagerError("attempt route_id 必须是当前选定路线")
                if target_identity(root, refs, active_run=True) != state["target_sha256"]:
                    raise ManagerError("attempt target stale")
                if attempt.get("outcome") not in {"succeeded", "success", "failed", "fail", "blocked", "partial"}:
                    raise ManagerError("attempt outcome invalid")
                if not str(attempt.get("result") or "").strip() or not attempt.get("evidence_refs"):
                    raise ManagerError("attempt requires result and real evidence; failures require an error file too")
                attempt["evidence"] = [evidence_record(root, state, ref) for ref in attempt["evidence_refs"]]
                attempt["capability_sources"] = capability_sources(attempt)
                attempt["references"] = dict(refs)
                attempt["generation_id"] = state["generation_id"]
                attempt["target_sha256"] = state["target_sha256"]
                attempt["outcome_scope"] = "recorded-evidence-only"
                attempt["project_pass"] = False
            elif event_type == "replan":
                if not str(payload.get("reason") or "").strip():
                    raise ManagerError("replan 必须写换路原因")
                new_id = require_id(payload.get("new_route_id"), "new_route_id")
                if new_id == state["selected_route_id"] or any(a.get("route_id") == new_id for a in state["attempts"]):
                    raise ManagerError("replan requires an unattempted different route")
                route = payload.get("route")
                if route:
                    validate_route(route)
                    if route["route_id"] != new_id or new_id in state["routes"]:
                        raise ManagerError("replan route definition conflicts")
                elif new_id not in state["routes"]:
                    raise ManagerError("replan requires a new route definition")
                candidate = route or state["routes"][new_id]
                previous = state["routes"].get(state["selected_route_id"], {})
                # A renamed copy of the failed route is not a new strategy.
                keys = ("needs", "fail_criteria", "evidence_goal")
                if all(candidate.get(k) == previous.get(k) for k in keys):
                    raise ManagerError("replan must change strategy, failure criteria or evidence goal")
        event = _append_event(root, event_type, payload, refs)
        _, new_state = current_context(root)
        return event, new_state


def append_event(root: Path, event_type: str, payload: dict, refs: dict) -> dict:
    """Public append uses exactly the same locked validation as transitions."""
    return transition(root, event_type, payload, refs)[0]


def scrub(value: Any, key: str = "") -> Any:
    exempt = str(key) in PUBLIC_NUMERIC_TOKEN_KEYS and public_numeric_value(value)
    if not exempt and SENSITIVE_KEY_RE.search(key or ""):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): scrub(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, key) for v in value]
    if isinstance(value, str):
        return SENSITIVE_VALUE_RE.sub("[REDACTED]", value)
    return value


def build_handoff(root: Path) -> dict:
    with manager_lock(root):
        return _build_handoff_locked(root)


def _build_handoff_locked(root: Path) -> dict:
    events, state = current_context(root)
    refs = scrub(state.get("references") or {})
    status = state.get("status", "uninitialized")
    actions = list(state.get("next_actions") or [])
    if state.get("replan_required"):
        actions = ["先 replan：%s" % state.get("replan_reason", "路线失败")]
    if state.get("waiting") and state["waiting"].get("status") == "WAIT_USER":
        status = "blocked"
        actions = ["等待用户从 %s 中选择并执行 answer" % ", ".join(state["waiting"].get("options", {}))]
    handoff = {
        "schema": HANDOFF_SCHEMA,
        "project": refs,
        "status": status,
        "blocked": status == "blocked",
        "state": scrub(state),
        "next_actions": actions,
        "event_count": len(events),
        "ledger": LEDGER_NAME,
        "host_wiring_required": True,
        "globally_enforced": False,
        "outcome_scope": "recorded-evidence-only",
        "updated_at": now(),
    }
    atomic_json(root / HANDOFF_NAME, handoff)
    return handoff


def emit(value: dict, as_json: bool = False, human: str = "") -> int:
    if as_json:
        print(json.dumps(scrub(value), ensure_ascii=False, indent=2))
    else:
        print(human or json.dumps(scrub(value), ensure_ascii=False))
    return 0


def cmd_intake(a) -> int:
    root = project_root(a.project)
    target_version = a.target_version or a.version_ref
    if not target_version:
        raise ManagerError("需要 --target-version（或 --version）")
    refs = validate_refs(root, a.project_ref, target_version, a.run_ref or None)
    payload = {"user_quote": a.user_quote, "primary_domain": a.primary_domain.strip(),
               "auxiliary_domains": parse_items(a.auxiliary_domain), "target_version": target_version,
               "new_generation": a.new_generation,
               # An omitted CLI option arrives as "".  Keep that optional
               # field absent from the durable intake shape unless it was
               # explicitly supplied; new generations are still rejected
               # later when the resulting value is empty.
               "generation_reason": a.generation_reason or None}
    event, state = transition(root, "intake", payload, refs)
    return emit({"ok": True, "event": event, "state": state}, a.json,
                "[OK] intake 已登记：%s / %s" % (refs["project_id"], refs["version_id"]))


def route_from_args(a) -> dict:
    if a.route_json:
        try:
            route = json.loads(a.route_json)
        except json.JSONDecodeError as exc:
            raise ManagerError("--route-json 不是合法 JSON：%s" % exc)
        if not isinstance(route, dict):
            raise ManagerError("--route-json 顶层必须是对象")
    else:
        route = {}
    route.update({"route_id": a.route_id or route.get("route_id", ""),
                  "success_rate": a.success_rate if a.success_rate is not None else route.get("success_rate"),
                  "estimated_hours": a.estimated_hours or route.get("estimated_hours", ""),
                  "needs": parse_items(a.needs) or route.get("needs", []),
                  "fail_criteria": a.fail_criteria or route.get("fail_criteria", ""),
                  "evidence_goal": a.evidence_goal or route.get("evidence_goal", "")})
    route["route_id"] = require_id(route.get("route_id", ""), "route_id")
    try:
        rate = float(route.get("success_rate"))
    except (TypeError, ValueError):
        raise ManagerError("预计成功率必须是 0 到 1 的数字")
    if not 0 <= rate <= 1:
        raise ManagerError("预计成功率必须在 0 到 1 之间")
    route["success_rate"] = rate
    if not str(route.get("estimated_hours") or "").strip():
        raise ManagerError("预计工时不能为空")
    for key in ("fail_criteria", "evidence_goal"):
        if not str(route.get(key) or "").strip():
            raise ManagerError("路线必须填写 %s" % key)
    route["needs"] = route.get("needs") if isinstance(route.get("needs"), list) else [str(route.get("needs"))]
    route["created_at"] = now()
    return route


def cmd_plan(a) -> int:
    root = project_root(a.project)
    events, state = current_context(root)
    require_ready(root, state)
    refs = state["references"]
    route = route_from_args(a)
    event, new_state = transition(root, "plan", {"route": route}, refs)
    return emit({"ok": True, "event": event, "state": new_state}, a.json,
                "[OK] 已登记路线 %s" % route["route_id"])


def cmd_choose(a) -> int:
    root = project_root(a.project)
    events, state = current_context(root)
    require_ready(root, state)
    rid = require_id(a.route_id, "route_id")
    event, new_state = transition(root, "choose", {"route_id": rid}, state["references"])
    return emit({"ok": True, "event": event, "state": new_state}, a.json, "[OK] 已选择路线 %s" % rid)


def cmd_wait(a) -> int:
    root = project_root(a.project)
    events, state = current_context(root)
    require_ready(root, state)
    options = parse_options(a.option, a.options)
    if len(options) < 2:
        raise ManagerError("WAIT_USER 至少需要两个选项")
    payload = {"options": options, "monitor": parse_items(a.monitor),
               "guarantee": parse_items(a.guarantee), "expected_input": a.expected_input.strip()}
    event, new_state = transition(root, "wait", payload, state["references"])
    return emit({"ok": True, "event": event, "state": new_state}, a.json, "[WAIT_USER] 已阻塞，等待用户选择")


def cmd_answer(a) -> int:
    root = project_root(a.project)
    events, state = current_context(root)
    choice = a.choice.strip().upper()
    event, new_state = transition(root, "answer", {"choice": choice}, state["references"])
    return emit({"ok": True, "event": event, "state": new_state}, a.json, "[OK] 已记录用户选择 %s，解除等待" % choice)


def cmd_attempt(a) -> int:
    root = project_root(a.project)
    events, state = current_context(root)
    outcome = a.status
    if a.failed:
        outcome = "failed"
    attempt = {"attempt_id": "ATT-" + uuid.uuid4().hex[:12], "route_id": require_id(a.route_id, "route_id"),
               "skills": parse_items(a.skill), "mcps": parse_items(a.mcp), "tools": parse_items(a.tool),
               "outcome": outcome, "result": a.result.strip(), "evidence_refs": parse_items(a.evidence),
               "created_at": now()}
    if not attempt["result"]:
        raise ManagerError("attempt 必须填写 result")
    event, new_state = transition(root, "attempt", {"attempt": attempt}, state["references"])
    human = "[OK] attempt %s：%s" % (attempt["route_id"], outcome)
    if new_state.get("replan_required"):
        human += "；replan_required，已阻止第三次尝试"
    return emit({"ok": True, "event": event, "state": new_state}, a.json, human)


def cmd_replan(a) -> int:
    root = project_root(a.project)
    events, state = current_context(root)
    require_ready(root, state, allow_replan=True)
    new_id = require_id(a.new_route_id, "new_route_id")
    route = route_from_args(a) if a.route_id else None
    if route and route["route_id"] != new_id:
        raise ManagerError("新路线定义的 route_id 必须等于 new_route_id")
    payload = {"reason": a.reason.strip(), "new_route_id": new_id, "route": route}
    event, new_state = transition(root, "replan", payload, state["references"])
    return emit({"ok": True, "event": event, "state": new_state}, a.json, "[OK] 已换路到 %s" % new_id)


def cmd_check_action(a) -> int:
    root = project_root(a.project)
    refs = {"project_id": a.project_ref, "version_id": a.version_ref, "run_id": a.run_ref}
    return emit(check_action(root, refs, a.route_id, a.target_sha256, a.generation_id), True)


def cmd_handoff(a, resume: bool = False) -> int:
    root = project_root(a.project)
    handoff = build_handoff(root)
    # handoff/resume are continuation interfaces: always emit one machine-readable object.
    return emit({"ok": True, "handoff": handoff}, True)


def _make_project(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    atomic_json(root / "project.json", {"schema": PROJECT_SCHEMA, "project_id": "demo",
                                         "title": "demo", "status": "active",
                                         "created_at": now(), "updated_at": now(), "current_version_id": "1.0"})
    version_root = root / "versions" / "1.0"
    (version_root / "runs" / "run-1").mkdir(parents=True, exist_ok=True)
    target = version_root / "target"
    target.write_bytes(b"SYNTHETIC MANAGER TARGET - NEVER EXECUTE")
    atomic_json(version_root / "version.json", {"schema": VERSION_SCHEMA, "project_id": "demo",
                                                  "version_id": "1.0", "local_path": "versions/1.0/target",
                                                  **project_reader.file_fingerprint(target), "status": "active"})
    atomic_json(version_root / "runs" / "run-1" / "run.json",
                {"schema": RUN_SCHEMA, "project_id": "demo", "version_id": "1.0",
                 "run_id": "run-1", "status": "active"})


def self_test() -> int:
    checks = []
    def check(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError(name)
        checks.append(name)
    def quiet(fn, *args):
        with contextlib.redirect_stdout(io.StringIO()):
            return fn(*args)
    try:
        import tempfile as _tempfile
        with _tempfile.TemporaryDirectory(prefix="manager-state-") as td:
            root = Path(td) / "project"
            _make_project(root)
            refs = validate_refs(root, "demo", "1.0", "run-1")
            event, state = transition(root, "intake", {"user_quote": "我要验证接口", "primary_domain": "web",
                "auxiliary_domains": ["protocol"], "target_version": "1.0"}, refs)
            check("intake", state["status"] == "active" and state["user_input"]["quote"] == "我要验证接口")
            r1 = {"route_id": "route-a", "success_rate": .7, "estimated_hours": "2h", "needs": ["capture"],
                  "fail_criteria": "无响应", "evidence_goal": "response.json"}
            r2 = {"route_id": "route-b", "success_rate": .4, "estimated_hours": "1h", "needs": [],
                  "fail_criteria": "无静态线索", "evidence_goal": "static.md"}
            _, state = transition(root, "plan", {"route": r1}, refs)
            _, state = transition(root, "plan", {"route": r2}, refs)
            check("plan", set(state["routes"]) == {"route-a", "route-b"})
            _, state = transition(root, "choose", {"route_id": "route-a"}, refs)
            check("choose", state["selected_route_id"] == "route-a")
            _, state = transition(root, "wait", {"options": {"A": "继续", "B": "停下"},
                "monitor": ["状态"], "guarantee": ["不动系统"], "expected_input": "回 A 或 B"}, refs)
            check("wait", state["status"] == "blocked" and state["waiting"]["status"] == "WAIT_USER")
            try:
                transition(root, "attempt", {"attempt": {"route_id": "route-a", "outcome": "failed", "result": "x", "evidence_refs": ["x.log"]}}, refs)
                raise AssertionError("wait should block attempt")
            except ManagerError:
                check("wait blocks attempt", True)
            _, state = transition(root, "answer", {"choice": "A"}, refs)
            check("answer", state["status"] == "active" and state["waiting"]["status"] == "answered")
            error_file = root / "versions/1.0/runs/run-1/error.log"
            error_file.write_text("synthetic failure record", encoding="utf-8")
            attempt = {"route_id": "route-a", "outcome": "failed", "result": "no response", "evidence_refs": ["versions/1.0/runs/run-1/error.log"]}
            _, state = transition(root, "attempt", {"attempt": attempt}, refs)
            check("first failure", not state["replan_required"])
            attempt2 = dict(attempt, result="still no response")
            _, state = transition(root, "attempt", {"attempt": attempt2}, refs)
            check("second failure replan", state["replan_required"] and state["status"] == "blocked")
            try:
                transition(root, "attempt", {"attempt": dict(attempt, result="third")}, refs)
                raise AssertionError("third attempt should block")
            except ManagerError as exc:
                check("third failure blocked", "replan_required" in str(exc))
            _, state = transition(root, "replan", {"reason": "失败判据已满足，换静态路线", "new_route_id": "route-b", "route": None}, refs)
            check("replan", state["selected_route_id"] == "route-b" and not state["replan_required"])
            handoff = build_handoff(root)
            check("handoff", handoff["status"] == "active" and handoff["next_actions"])
            check("replay", replay(read_events(root))["selected_route_id"] == "route-b")
            check("fsynced ledger", ledger_path(root).read_text(encoding="utf-8").count("\n") == len(read_events(root)))
            check("credential scrub", scrub({"token": "secret", "text": "password=abc"})["token"] == "[REDACTED]"
                  and "[REDACTED]" in scrub({"text": "password=abc"})["text"])
        print(json.dumps({"ok": True, "checks": len(checks), "conclusion": "manager state self-test passed"}, ensure_ascii=True))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "checks": len(checks), "failed_check": str(exc)}, ensure_ascii=True))
        return 1


def add_common(p):
    p.add_argument("--json", action="store_true", help="输出 JSON")


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse otherwise echoes arbitrary invalid input, including credentials.
        raise ManagerError("invalid CLI arguments (see --help)")


def parser() -> argparse.ArgumentParser:
    ap = SafeArgumentParser(description="Manager Mode 可验证、可续接的事件状态层")
    ap.add_argument("--self-test", action="store_true", help="运行内置状态层自测")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("init", aliases=["intake"], help="登记用户原话、领域和 project/version/run 引用")
    p.add_argument("--project", required=True); p.add_argument("--user-quote", "--quote", dest="user_quote", required=True)
    p.add_argument("--primary-domain", "--main-domain", dest="primary_domain", required=True)
    p.add_argument("--aux-domain", "--auxiliary-domain", dest="auxiliary_domain", action="append", default=[])
    p.add_argument("--target-version", "--goal-version", dest="target_version", default="")
    p.add_argument("--project-ref", "--project-id", dest="project_ref", default="")
    p.add_argument("--version", "--version-ref", dest="version_ref", default="")
    p.add_argument("--run", "--run-ref", dest="run_ref", default="")
    p.add_argument("--new-generation", action="store_true", help="显式隔离旧路线及尝试；WAIT_USER/replan 时拒绝")
    p.add_argument("--generation-reason", default="", help="新 generation 原因")
    add_common(p)
    p = sub.add_parser("plan", help="登记一条候选路线")
    p.add_argument("--project", required=True); p.add_argument("--route-id", default="")
    p.add_argument("--success-rate", "--p", dest="success_rate", type=float, default=None)
    p.add_argument("--estimated-hours", "--hours", dest="estimated_hours", default="")
    p.add_argument("--needs", action="append", default=[]); p.add_argument("--fail-criteria", "--fail", dest="fail_criteria", default="")
    p.add_argument("--evidence-goal", dest="evidence_goal", default=""); p.add_argument("--route-json", default=""); add_common(p)
    p = sub.add_parser("choose", help="选择路线")
    p.add_argument("--project", required=True); p.add_argument("--route-id", required=True); add_common(p)
    p = sub.add_parser("wait", help="登记 WAIT_USER 和 A/B/C 选项")
    p.add_argument("--project", required=True); p.add_argument("--option", action="append", default=[]); p.add_argument("--options", default="")
    p.add_argument("--monitor", action="append", default=[]); p.add_argument("--guarantee", action="append", default=[])
    p.add_argument("--expected-input", "--expect", dest="expected_input", default=""); add_common(p)
    p = sub.add_parser("answer", help="记录用户选择并解除等待")
    p.add_argument("--project", required=True); p.add_argument("--choice", "--answer", dest="choice", required=True); add_common(p)
    p = sub.add_parser("attempt", help="记录路线尝试和证据")
    p.add_argument("--project", required=True); p.add_argument("--route-id", required=True); p.add_argument("--skill", "--skills", action="append", default=[])
    p.add_argument("--mcp", "--mcps", action="append", default=[]); p.add_argument("--tool", "--tools", action="append", default=[])
    p.add_argument("--status", choices=["succeeded", "success", "failed", "blocked", "partial"], default="succeeded")
    p.add_argument("--failed", action="store_true"); p.add_argument("--result", required=True); p.add_argument("--evidence", "--evidence-ref", dest="evidence", action="append", default=[]); add_common(p)
    p = sub.add_parser("replan", help="登记换路原因和新路线")
    p.add_argument("--project", required=True); p.add_argument("--reason", required=True); p.add_argument("--new-route-id", required=True)
    p.add_argument("--route-id", default="", help="新路线尚未 plan 时，附带完整路线定义")
    p.add_argument("--success-rate", "--p", dest="success_rate", type=float, default=None); p.add_argument("--estimated-hours", "--hours", dest="estimated_hours", default="")
    p.add_argument("--needs", action="append", default=[]); p.add_argument("--fail-criteria", "--fail", dest="fail_criteria", default=""); p.add_argument("--evidence-goal", default=""); p.add_argument("--route-json", default=""); add_common(p)
    p = sub.add_parser("check-action", help="执行前快照验证；不执行目标；宿主仍需接线")
    p.add_argument("--project", required=True); p.add_argument("--project-ref", required=True)
    p.add_argument("--version", dest="version_ref", required=True); p.add_argument("--run", dest="run_ref", required=True)
    p.add_argument("--route-id", required=True); p.add_argument("--target-sha256", required=True)
    p.add_argument("--generation-id", required=True); add_common(p)
    for name in ("handoff", "resume"):
        p = sub.add_parser(name, help="输出机器可读状态和 next_actions"); p.add_argument("--project", required=True); add_common(p)
    return ap


def main(argv: list[str] | None = None) -> int:
    import sys
    a = None
    try:
        raw_args = list(sys.argv[1:] if argv is None else argv)
        reject_sensitive(raw_args, "argv")
        ap = parser()
        a = ap.parse_args(raw_args)
        reject_sensitive(vars(a), "arguments")
        if a.self_test:
            return self_test()
        if not a.cmd:
            ap.print_help(); return 4
        if a.cmd in ("init", "intake"): return cmd_intake(a)
        if a.cmd == "plan": return cmd_plan(a)
        if a.cmd == "choose": return cmd_choose(a)
        if a.cmd == "wait": return cmd_wait(a)
        if a.cmd == "answer": return cmd_answer(a)
        if a.cmd == "attempt": return cmd_attempt(a)
        if a.cmd == "replan": return cmd_replan(a)
        if a.cmd == "check-action": return cmd_check_action(a)
        if a.cmd == "handoff": return cmd_handoff(a)
        if a.cmd == "resume": return cmd_handoff(a, resume=True)
        raise ManagerError("未知命令：%s" % a.cmd)
    except (ManagerError, OSError, ValueError, KeyError, TypeError) as exc:
        # OS/JSON exceptions can include file contents or untrusted path strings.
        reason = str(exc) if isinstance(exc, ManagerError) else type(exc).__name__
        result = {"ok": False, "blocked_at": getattr(a, "cmd", "args"), "reason": reason}
        print(json.dumps(scrub(result), ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
