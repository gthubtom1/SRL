#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synthetic Manager integration tests. No credentials, targets or services run.

The only subprocesses are this file's attempt workers, for an actual OS-lock
race. Fixtures use first-party schemas and the project reader, but never write
project lifecycle/facts through production commands.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import manager_state as M


def route(rid="a", strategy="capture"):
    return {"route_id": rid, "success_rate": .5, "estimated_hours": "1",
            "needs": [strategy], "fail_criteria": strategy + " failed",
            "evidence_goal": strategy + " output"}


class ManagerIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="manager-integration-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        M._make_project(self.root)
        self.refs = M.validate_refs(self.root, "demo", "1.0", "run-1")
        self.intake = {"user_quote": "synthetic project request", "primary_domain": "web",
                       "target_version": "1.0"}
        M.transition(self.root, "intake", self.intake, self.refs)
        M.transition(self.root, "plan", {"route": route()}, self.refs)
        M.transition(self.root, "choose", {"route_id": "a"}, self.refs)
        self.evidence = "versions/1.0/runs/run-1/output.log"
        (self.root / self.evidence).write_text("synthetic reviewable output\n", encoding="utf-8")

    def state(self):
        return M.current_context(self.root)[1]

    def ledger(self):
        return M.ledger_path(self.root).read_bytes()

    def cli(self, *args):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = M.main([*map(str, args), "--json"])
        return code, json.loads(stream.getvalue())

    def attempt(self, **changes):
        attempt = {"route_id": "a", "outcome": "failed", "result": "synthetic error record",
                   "evidence_refs": [self.evidence]}
        attempt.update(changes)
        return M.transition(self.root, "attempt", {"attempt": attempt}, self.refs)

    def denied(self, callback):
        before = self.ledger()
        with self.assertRaises(M.ManagerError):
            callback()
        self.assertEqual(before, self.ledger())

    def action(self, **changes):
        state = self.state()
        params = {"refs": self.refs, "route_id": "a", "target_sha256": state["target_sha256"],
                  "generation_id": state["generation_id"]}
        params.update(changes)
        return M.check_action(self.root, **params)

    def new_run(self, rid="run-2"):
        refs = dict(self.refs, run_id=rid)
        M.atomic_json(self.root / ("versions/1.0/runs/%s/run.json" % rid),
                      {"schema": M.RUN_SCHEMA, "project_id": "demo", "version_id": "1.0",
                       "run_id": rid, "status": "active"})
        return refs

    def wait(self):
        M.transition(self.root, "wait", {"options": {"A": "continue", "B": "stop"},
                     "monitor": ["synthetic status"], "guarantee": ["synthetic boundary"],
                     "expected_input": "A or B"}, self.refs)

    def test_wait_user_blocks_api_and_all_cli_paths(self):
        self.wait()
        next_refs = self.new_run()
        callbacks = [
            lambda: M.transition(self.root, "plan", {"route": route("b", "static")}, self.refs),
            lambda: M.transition(self.root, "choose", {"route_id": "a"}, self.refs),
            lambda: M.transition(self.root, "intake", self.intake, self.refs),
            lambda: M.transition(self.root, "intake", dict(self.intake, new_generation=True,
                                    generation_reason="cross run"), next_refs),
            self.action, self.attempt,
            lambda: M.transition(self.root, "replan", {"reason": "new strategy", "new_route_id": "b",
                                                       "route": route("b", "static")}, self.refs),
        ]
        for callback in callbacks:
            self.denied(callback)
        state = self.state()
        commands = [
            ["plan", "--route-id", "b", "--p", ".5", "--hours", "1", "--fail", "x", "--evidence-goal", "y"],
            ["choose", "--route-id", "a"],
            ["intake", "--quote", "synthetic", "--main-domain", "web", "--version", "1.0", "--run", "run-1"],
            ["check-action", "--project-ref", "demo", "--version", "1.0", "--run", "run-1",
             "--route-id", "a", "--generation-id", state["generation_id"], "--target-sha256", state["target_sha256"]],
        ]
        before = self.ledger()
        for command in commands:
            code, output = self.cli(*command, "--project", self.root)
            self.assertEqual(2, code)
            self.assertFalse(output["ok"])
        self.assertEqual(before, self.ledger())
        for name in ("handoff", "resume"):
            code, output = self.cli(name, "--project", self.root)
            self.assertEqual(0, code)
            handoff = output["handoff"]
            self.assertTrue(handoff["blocked"])
            self.assertEqual("blocked", handoff["state"]["status"])
            self.assertEqual(handoff["status"], handoff["state"]["status"])
        _, answered = M.transition(self.root, "answer", {"choice": "A"}, self.refs)
        self.assertEqual("active", answered["status"])
        self.assertTrue(self.action()["allowed"])

    def test_replan_requires_different_strategy_and_cannot_reselect_retired_route(self):
        self.attempt()
        self.attempt()
        state = self.state()
        self.assertTrue(state["replan_required"])
        self.assertEqual("blocked", state["status"])
        for callback in (
            self.attempt, self.action,
            lambda: M.transition(self.root, "plan", {"route": route("b")}, self.refs),
            lambda: M.transition(self.root, "choose", {"route_id": "a"}, self.refs),
            lambda: M.transition(self.root, "intake", dict(self.intake, new_generation=True,
                                   generation_reason="reset"), self.new_run()),
            lambda: M.transition(self.root, "replan", {"reason": "reset", "new_route_id": "a"}, self.refs),
            lambda: M.transition(self.root, "replan", {"reason": "rename", "new_route_id": "b",
                                                       "route": route("b")}, self.refs),
            lambda: M.transition(self.root, "replan", {"reason": "", "new_route_id": "b",
                                                       "route": route("b", "static")}, self.refs),
        ):
            self.denied(callback)
        handoff = M.build_handoff(self.root)
        self.assertEqual("blocked", handoff["status"])
        self.assertEqual(handoff["status"], handoff["state"]["status"])
        _, state = M.transition(self.root, "replan", {"reason": "capture failed; inspect static artifact",
                            "new_route_id": "b", "route": route("b", "static")}, self.refs)
        self.assertFalse(state["replan_required"])
        self.denied(lambda: M.transition(self.root, "choose", {"route_id": "a"}, self.refs))
        self.assertTrue(self.action(route_id="b")["allowed"])

    def test_interleaved_routes_do_not_erase_route_failures(self):
        M.transition(self.root, "plan", {"route": route("b", "static")}, self.refs)
        self.attempt()
        M.transition(self.root, "choose", {"route_id": "b"}, self.refs)
        self.attempt(route_id="b")
        M.transition(self.root, "choose", {"route_id": "a"}, self.refs)
        self.attempt()
        self.assertTrue(self.state()["replan_required"])
        self.denied(self.attempt)

    def test_success_binds_real_nonempty_files_and_registered_sources(self):
        _, state = self.attempt(outcome="succeeded", tools=["seep_r2_cmd"], skills=["softseep"], mcps=["seep"])
        attempt = state["attempts"][-1]
        self.assertEqual("recorded-evidence-only", attempt["outcome_scope"])
        self.assertFalse(attempt["project_pass"])
        evidence = attempt["evidence"][0]
        self.assertEqual(self.refs, evidence["references"])
        self.assertEqual(state["generation_id"], evidence["generation_id"])
        self.assertEqual(state["target_sha256"], evidence["target_sha256"])
        self.assertEqual(M.project_reader.file_fingerprint(self.root / self.evidence),
                         {k: evidence[k] for k in ("sha256", "size")})
        self.assertEqual(3, len(attempt["capability_sources"]))
        self.assertTrue(all(x["verification"] == "registered-source-only" for x in attempt["capability_sources"]))
        self.assertFalse(M.build_handoff(self.root)["globally_enforced"])

    def test_external_mcp_and_cli_can_combine_with_builtin_capabilities(self):
        declared = dict(route("mixed", "web protocol analysis"),
                        tools=["httpx", "nmap", "seep_r2_cmd"],
                        mcps=["js-reverse", "playwright", "seep"], skills=["web-pentest", "protocol-plugin"])
        _, state = M.transition(self.root, "plan", {"route": declared}, self.refs)
        registrations = state["routes"]["mixed"]["capability_sources"]
        self.assertEqual(8, len(registrations))
        external = [s for s in registrations if s["name"] in {"httpx", "nmap", "js-reverse", "playwright"}]
        self.assertEqual(4, len(external))
        self.assertTrue(all(s["verification"] == "registered-config-only" for s in external))
        self.assertTrue(all(s["source"].startswith("Tool/config/") for s in external))
        M.transition(self.root, "choose", {"route_id": "mixed"}, self.refs)
        self.assertTrue(self.action(route_id="mixed")["allowed"])
        _, state = self.attempt(route_id="mixed", outcome="partial", tools=declared["tools"],
                                mcps=declared["mcps"], skills=declared["skills"])
        self.assertEqual(registrations, state["attempts"][-1]["capability_sources"])
        self.assertFalse(state["attempts"][-1]["project_pass"])

    def test_invalid_capability_container_and_elements_are_structured_rejections(self):
        for field in ("skills", "mcps", "tools"):
            for names in ({}, "httpx", [None], [["httpx"]], [1]):
                with self.subTest(field=field, names=names):
                    self.denied(lambda: self.attempt(**{field: names}))

    def test_registered_config_must_have_a_real_declaration(self):
        fixture_repo = Path(self.temp.name) / "capability-repo"
        cfg = fixture_repo / "Tool/config"
        cfg.mkdir(parents=True)
        server = fixture_repo / "Tool/mcp/seep_mcp_server.py"
        server.parent.mkdir()
        server.write_text("# no builtin tools\n", encoding="utf-8")
        with mock.patch.object(M, "REPO_ROOT", fixture_repo):
            for filename, table, entry, field in (
                    ("mcp-servers.json", "servers", {"command": "synthetic-server"}, "mcps"),
                    ("tool-capabilities.json", "tools", {"display": "Synthetic tool"}, "tools")):
                path = cfg / filename
                for value in ([], {table: []}, {table: {"synthetic": None}}, {table: {"synthetic": {}}}):
                    path.write_text(json.dumps(value), encoding="utf-8")
                    with self.subTest(value=value, field=field):
                        self.denied(lambda: self.attempt(**{field: ["synthetic"]}))
                path.write_text(json.dumps({table: {"synthetic": entry}}), encoding="utf-8")
                records = M.capability_sources({field: ["synthetic"]})
                self.assertEqual("registered-config-only", records[0]["verification"])

    def test_missing_empty_escape_expired_and_unknown_declarations_rejected(self):
        empty = self.root / "versions/1.0/runs/run-1/empty.log"
        empty.touch()
        old = self.root / "versions/1.0/runs/run-1/old.log"
        old.write_text("synthetic old output", encoding="utf-8")
        os.utime(old, (1, 1))
        outside = Path(self.temp.name) / "outside.log"
        outside.write_text("synthetic outside output", encoding="utf-8")
        for ref in ("absent.log", "../outside.log", str(outside),
                    empty.relative_to(self.root).as_posix(), old.relative_to(self.root).as_posix(),
                    "versions/1.0/runs/run-1/run.json"):
            self.denied(lambda ref=ref: self.attempt(outcome="succeeded", evidence_refs=[ref]))
        for field in ("skills", "mcps", "tools"):
            self.denied(lambda field=field: self.attempt(**{field: ["NONEXISTENT_SYNTHETIC_CAPABILITY"]}))
        self.denied(lambda: self.attempt(evidence_refs=[]))
        self.denied(lambda: self.attempt(result=""))
        self.denied(lambda: M.transition(self.root, "plan", {"route": dict(route("b"),
                                            tools=["NONEXISTENT_SYNTHETIC_CAPABILITY"])}, self.refs))
        link = self.root / "versions/1.0/runs/run-1/link.log"
        try:
            link.symlink_to(outside)
        except OSError:
            pass  # Windows may deny unprivileged symlink creation.
        else:
            self.denied(lambda: self.attempt(evidence_refs=[link.relative_to(self.root).as_posix()]))

    def test_tamper_is_stale_in_handoff_and_blocks_action_and_append(self):
        _, state = self.attempt(outcome="success")
        previous = state["attempts"][0]["evidence"][0]
        (self.root / self.evidence).write_text("synthetic tampered output", encoding="utf-8")
        before = self.ledger()
        code, output = self.cli("resume", "--project", self.root)
        self.assertEqual(0, code)
        self.assertTrue(output["handoff"]["blocked"])
        self.assertEqual("stale-evidence", output["handoff"]["state"]["evidence_errors"][0]["type"])
        self.denied(self.action)
        self.denied(lambda: self.attempt(evidence_refs=[previous]))
        self.assertEqual(before, self.ledger())

    def test_public_numeric_token_params_are_not_credentials(self):
        """`limit_tokens` / `max_tokens` / `token_budget` 是非凭据数值参数。

        口径（主对话裁定）：只有这三个**精确**键名，且值为合法有限非负 int 或合法
        CLI int 字符串时，才不因键名含 "token" 被拒；值仍扫凭据模式。
        **不得不报参数类型**：NaN/Inf/小数/非数字串由工具 validator 结构化拒，
        Manager 不把它假报成凭据（这里只断言“不被当成 key 错误”）。
        """
        before = self.ledger()
        legal = [{"limit_tokens": 8000}, {"max_tokens": 1200},
                 {"token_budget": 0}, {"limit_tokens": "8000"},
                 {"max_tokens": "1200"}, {"token_budget": "0"},
                 {"nested": {"limit_tokens": 4096}}]
        for value in legal:
            with self.subTest(value=value):
                M.reject_sensitive(value)          # 不抛 = 通过
                self.assertEqual(value, M.scrub(value))  # 不入账、不涂红
        # 值层仍要拦：豁免键名不等于能用它装真 secret
        marker = "SYNTHETIC_MANAGER_PLACEHOLDER"
        for value in ("Bearer " + marker, "-----BEGIN " + "PRIVATE KEY-----", "sk-" + marker,
                      "https://synthetic:" + marker + "@invalid.example/",
                      "password=" + marker):
            with self.subTest(value=value):
                with self.assertRaises(M.ManagerError) as caught:
                    M.reject_sensitive({"limit_tokens": value})
                self.assertIn("sensitive-", str(caught.exception))
                self.assertNotIn(marker, str(caught.exception))
        # 非白名单的 token 类键名仍然拒（精确匹配，不做宽泛包含）
        for value in ({"token": 1}, {"access_token": 1}, {"refresh_token": 1},
                      {"api_key": "1"}, {"password": "1"}, {"LIMIT_TOKENS": 1},
                      {"limit_tokens_extra": 1}, {"user_token": 1}):
            with self.subTest(value=value):
                with self.assertRaises(M.ManagerError):
                    M.reject_sensitive(value)
        # 类型不合法不在这里变成凭据错误（交给工具 validator）
        for value in (float("nan"), float("inf"), 1.5, -1, "many"):
            with self.subTest(value=value):
                try:
                    M.reject_sensitive({"limit_tokens": value})
                except M.ManagerError as exc:
                    self.assertNotIn("sensitive-key", str(exc))
        self.assertEqual(before, self.ledger())

    def test_public_numeric_params_still_scan_values_and_keep_ledger_bytes(self):
        """入账字节不变：合法数值键能走完整流程，真 secret 仍拒绝且账本不动。"""
        before = self.ledger()
        attempt = {"route_id": "a", "outcome": "failed", "result": "synthetic",
                   "evidence_refs": [self.evidence], "limit_tokens": 8000}
        M.transition(self.root, "attempt", {"attempt": attempt}, self.refs)
        after = self.ledger()
        self.assertNotEqual(before, after)
        self.assertIn(b"\"limit_tokens\":8000", after)
        # 真 secret 在同一位置仍然被拒，且拒绝发生在 append 之前
        sealed = self.ledger()
        for value in ("Bearer " + "SYNTHETIC_MANAGER_PLACEHOLDER",
                      "-----BEGIN " + "PRIVATE KEY-----"):
            with self.subTest(value=value):
                self.denied(lambda value=value: self.attempt(
                    result="synthetic", limit_tokens=value))
        self.assertEqual(sealed, self.ledger())

    def test_structured_reference_cannot_be_refreshed_silently(self):
        expected = {"path": self.evidence, "sha256": "0" * 64}
        self.denied(lambda: self.attempt(evidence_refs=[expected]))
        expected = {"path": self.evidence, "references": dict(self.refs, run_id="old-run")}
        self.denied(lambda: self.attempt(evidence_refs=[expected]))

    def test_all_sensitive_entries_reject_before_append_without_echo(self):
        # These are deliberate fake markers, never real credentials.
        marker = "SYNTHETIC_MANAGER_PLACEHOLDER"
        values = ["token=" + marker, "password: " + marker, "Bearer " + marker,
                  '{"nested":{"api_key":"' + marker + '"}}',
                  "https://synthetic:" + marker + "@invalid.example/", "-----BEGIN " + "PRIVATE KEY-----"]
        before = self.ledger()
        for name in ("intake", "plan", "choose", "wait", "answer", "attempt", "replan", "check-action", "handoff", "resume"):
            for value in values:
                code, output = self.cli(name, "--project", self.root, "--synthetic-extra", value)
                self.assertEqual(2, code)
                text = json.dumps(output)
                self.assertNotIn(marker, text)
                self.assertIn("sensitive-", output["reason"])
                self.assertEqual(before, self.ledger())
        for name in ("intake", "plan", "choose", "wait", "answer", "attempt", "replan"):
            for entry in (M.transition, M.append_event, M._append_event):
                self.denied(lambda entry=entry, name=name: entry(self.root, name,
                            {"nested": {"password": marker}}, self.refs))
        self.denied(lambda: M.append_event(self.root, "attempt", {"safe": "synthetic"},
                                           dict(self.refs, user_token=marker)))
        # A credential-looking JSON key can itself contain a value: never echo it.
        with self.assertRaises(M.ManagerError) as caught:
            M.reject_sensitive({"token=" + marker: "synthetic"})
        self.assertNotIn(marker, str(caught.exception))
        self.assertNotIn(marker.encode(), self.ledger())

    def test_corrupt_ledger_shapes_fail_structurally_without_rewriting_history(self):
        valid = self.ledger()
        event = {"schema": M.MANAGER_SCHEMA, "event_id": "ME-corrupt", "event_type": "plan",
                 "created_at": M.now(), "references": self.refs, "payload": {}}
        cases = [("plan", {}), ("plan", {"route": []}), ("plan", {"route": {"route_id": []}}),
                 ("attempt", {"attempt": []}), ("attempt", {"attempt": {"route_id": "a", "evidence": 1}}),
                 ("wait", {"options": 1}), ("choose", {"route_id": []}), ("unknown", {})]
        try:
            for kind, payload in cases:
                with self.subTest(kind=kind, payload=payload):
                    broken = dict(event, event_type=kind, payload=payload)
                    M.ledger_path(self.root).write_bytes(valid + (json.dumps(broken) + "\n").encode())
                    before = self.ledger()
                    with self.assertRaises(M.ManagerError):
                        M.current_context(self.root)
                    code, output = self.cli("resume", "--project", self.root)
                    self.assertEqual(code, 2, output)
                    self.assertFalse(output["ok"])
                    self.assertEqual(self.ledger(), before)
            duplicate = json.loads(valid.splitlines()[0])
            M.ledger_path(self.root).write_bytes(valid + (json.dumps(duplicate) + "\n").encode())
            with self.assertRaises(M.ManagerError):
                M.current_context(self.root)
            duplicate_key = (b'{"schema":"' + M.MANAGER_SCHEMA.encode() +
                             b'","event_id":"ME-duplicate-key","event_type":"unknown",'
                             b'"event_type":"plan","created_at":"now","references":{},'
                             b'"payload":{"route":{"route_id":"b"}}}\n')
            M.ledger_path(self.root).write_bytes(valid + duplicate_key)
            with self.assertRaises(M.ManagerError):
                M.current_context(self.root)
        finally:
            M.ledger_path(self.root).write_bytes(valid)

    def test_replay_rejects_impossible_or_malformed_history(self):
        valid = self.ledger()
        base = {"schema": M.MANAGER_SCHEMA, "event_id": "ME-semantic",
                "event_type": "answer", "created_at": M.now(),
                "references": self.refs, "payload": {"choice": "A"}}
        impossible = [
            dict(base, event_type="answer", payload={"choice": "A"}),
            dict(base, event_type="choose", payload={"route_id": "does-not-exist"}),
            dict(base, event_type="plan", payload={"route": {"route_id": "partial"}}),
            dict(base, references={"project_id": [], "version_id": "1.0", "run_id": "run-1"}),
        ]
        try:
            for event in impossible:
                with self.subTest(kind=event["event_type"]):
                    M.ledger_path(self.root).write_bytes(
                        valid + (json.dumps(event) + "\n").encode("utf-8"))
                    before = self.ledger()
                    with self.assertRaises(M.ManagerError):
                        M.current_context(self.root)
                    self.assertEqual(before, self.ledger())

            first = json.loads(valid.splitlines()[0])
            for payload in (
                    dict(first["payload"], target_sha256={"bad": "shape"},
                         new_generation=True, generation_reason="malformed target"),
                    dict(first["payload"], previous_generation={"generation_id": []})):
                broken = dict(first, event_id="ME-bad-intake", payload=payload)
                M.ledger_path(self.root).write_bytes(
                    (json.dumps(broken) + "\n").encode("utf-8"))
                with self.assertRaises(M.ManagerError):
                    M.current_context(self.root)
        finally:
            M.ledger_path(self.root).write_bytes(valid)

    def test_legacy_sensitive_ledger_is_never_rewritten_or_printed(self):
        # Only a synthetic historical event; no existing repository ledger opened.
        legacy = {"schema": M.MANAGER_SCHEMA, "event_id": "legacy", "event_type": "intake",
                  "created_at": M.now(), "references": self.refs,
                  "payload": dict(self.intake, user_quote="token=SYNTHETIC_LEGACY_PLACEHOLDER")}
        with M.ledger_path(self.root).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(legacy) + "\n")
        before = self.ledger()
        code, output = self.cli("handoff", "--project", self.root)
        self.assertEqual(0, code)
        self.assertNotIn("SYNTHETIC_LEGACY_PLACEHOLDER", json.dumps(output))
        self.assertEqual(before, self.ledger())

    def test_fresh_generation_requires_context_change_and_isolates_everything(self):
        _, old = self.attempt(outcome="success")
        for payload in (self.intake, dict(self.intake, new_generation=True, generation_reason="reset")):
            self.denied(lambda payload=payload: M.transition(self.root, "intake", payload, self.refs))
        next_refs = self.new_run()
        self.denied(lambda: M.transition(self.root, "intake", self.intake, next_refs))
        _, fresh = M.transition(self.root, "intake", dict(self.intake, new_generation=True,
                                 generation_reason="new run"), next_refs)
        self.assertNotEqual(old["generation_id"], fresh["generation_id"])
        self.assertEqual({}, fresh["routes"])
        self.assertEqual([], fresh["attempts"])
        self.assertIsNone(fresh["selected_route_id"])
        self.assertIsNone(fresh["waiting"])
        self.denied(lambda: M.check_action(self.root, self.refs, "a", old["target_sha256"], old["generation_id"]))
        M.transition(self.root, "plan", {"route": route()}, next_refs)
        M.transition(self.root, "choose", {"route_id": "a"}, next_refs)
        old_record = copy.deepcopy(old["attempts"][0]["evidence"][0])
        self.denied(lambda: M.transition(self.root, "attempt", {"attempt": {"route_id": "a", "outcome": "success",
                                "result": "synthetic", "evidence_refs": [old_record]}}, next_refs))
        new_path = "versions/1.0/runs/run-2/output.log"
        (self.root / new_path).write_text("fresh synthetic output", encoding="utf-8")
        old_record["path"] = new_path
        self.denied(lambda: M.transition(self.root, "attempt", {"attempt": {"route_id": "a", "outcome": "success",
                                "result": "synthetic", "evidence_refs": [old_record]}}, next_refs))
        event, state = M.transition(self.root, "attempt", {"attempt": {"route_id": "a", "outcome": "success",
                           "result": "synthetic", "evidence_refs": [new_path]}}, next_refs)
        self.assertEqual(1, len(state["attempts"]))
        self.assertEqual(fresh["generation_id"], event["payload"]["attempt"]["generation_id"])

    def test_current_refs_active_run_generation_route_and_target_checked(self):
        before = self.ledger()
        result = self.action()
        self.assertTrue(result["allowed"])
        self.assertFalse(result["executes_target"])
        self.assertFalse(result["globally_enforced"])
        self.assertTrue(result["host_wiring_required"])
        self.assertEqual(before, self.ledger())  # preflight is read-only
        for changes in ({"refs": dict(self.refs, run_id="other")}, {"target_sha256": "0" * 64},
                        {"route_id": "other"}, {"generation_id": "old"}):
            self.denied(lambda changes=changes: self.action(**changes))
        runfile = self.root / "versions/1.0/runs/run-1/run.json"
        run = json.loads(runfile.read_text(encoding="utf-8"))
        M.atomic_json(runfile, dict(run, status="failed"))
        self.denied(self.action)
        self.denied(self.attempt)
        M.atomic_json(runfile, run)
        (self.root / "versions/1.0/target").write_bytes(b"SYNTHETIC CHANGED TARGET")
        self.denied(self.action)
        self.assertTrue(M.build_handoff(self.root)["blocked"])

    def new_version(self, content=b"SYNTHETIC NEXT VERSION - NEVER EXECUTE"):
        v = self.root / "versions/2"
        v.mkdir()
        target = v / "target"
        target.write_bytes(content)
        M.atomic_json(v / "version.json", {"schema": M.VERSION_SCHEMA, "project_id": "demo",
                      "version_id": "2", "local_path": "versions/2/target", **M.project_reader.file_fingerprint(target)})
        M.atomic_json(v / "runs/run-next/run.json", {"schema": M.RUN_SCHEMA, "project_id": "demo",
                      "version_id": "2", "run_id": "run-next", "status": "active"})
        project = M.require_project(self.root)
        M.atomic_json(self.root / "project.json", dict(project, current_version_id="2"))
        return {"project_id": "demo", "version_id": "2", "run_id": "run-next"}

    def test_new_version_explicit_generation_and_stale_current_version(self):
        old = self.state()
        refs = self.new_version()
        self.denied(self.action)
        payload = dict(self.intake, target_version="2", new_generation=True, generation_reason="version changed")
        _, fresh = M.transition(self.root, "intake", payload, refs)
        self.assertEqual({}, fresh["routes"])
        self.assertEqual([], fresh["attempts"])
        self.assertNotEqual(old["target_sha256"], fresh["target_sha256"])

    def test_changed_target_can_start_new_version_after_previous_route_failed(self):
        self.attempt()
        self.attempt()
        old = self.state()
        old_events = M.read_events(self.root)
        refs = self.new_version()
        payload = dict(self.intake, target_version="2", new_generation=True, generation_reason="new target version")
        self.denied(lambda: M.transition(self.root, "intake", dict(payload, new_generation=False), refs))
        self.denied(lambda: M.transition(self.root, "intake", dict(payload, generation_reason=""), refs))
        event, fresh = M.transition(self.root, "intake", payload, refs)
        self.assertFalse(fresh["replan_required"])
        self.assertEqual([], fresh["attempts"])
        self.assertEqual(old_events, M.read_events(self.root)[:-1])
        self.assertEqual(old["generation_id"], event["payload"]["previous_generation"]["generation_id"])
        self.assertTrue(event["payload"]["previous_generation"]["replan_required"])
        self.assertNotEqual(old["target_sha256"], fresh["target_sha256"])
        M.transition(self.root, "plan", {"route": route()}, refs)
        M.transition(self.root, "choose", {"route_id": "a"}, refs)
        self.assertTrue(M.check_action(self.root, refs, "a", fresh["target_sha256"], fresh["generation_id"])["allowed"])

    def test_renamed_version_cannot_erase_failed_routes_on_the_same_target(self):
        self.attempt()
        self.attempt()
        original = (self.root / "versions/1.0/target").read_bytes()
        refs = self.new_version(content=original)
        payload = dict(self.intake, target_version="2", new_generation=True, generation_reason="rename only")
        self.denied(lambda: M.transition(self.root, "intake", payload, refs))

    def test_two_real_processes_accept_at_most_one_failure_at_threshold(self):
        self.attempt()
        gate = Path(self.temp.name) / "gate"
        workers = []
        with M.manager_lock(self.root):
            try:
                for index in range(2):
                    ready = Path(self.temp.name) / ("worker-%d" % index)
                    workers.append((subprocess.Popen([sys.executable, "-B", "-X", "utf8", str(Path(__file__).resolve()),
                        "--attempt-worker", str(self.root), str(ready), str(gate)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8"), ready))
                wait_until(lambda: all(ready.exists() for _, ready in workers))
                gate.touch()
                wait_until(lambda: all(Path(str(ready) + ".enter").exists() for _, ready in workers))
                self.assertTrue(all(process.poll() is None for process, _ in workers))
            except BaseException:
                for process, _ in workers:
                    process.kill()
                    process.communicate()
                raise
        codes = []
        try:
            for process, _ in workers:
                stdout, stderr = process.communicate(timeout=20)
                self.assertFalse(stderr, stderr)
                self.assertEqual(process.returncode == 0, json.loads(stdout)["ok"])
                codes.append(process.returncode)
        finally:
            for process, _ in workers:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
        self.assertEqual([0, 2], sorted(codes))
        state = self.state()
        self.assertEqual(2, len(state["attempts"]))
        self.assertTrue(state["replan_required"])
        self.assertEqual("blocked", state["status"])
        events = M.read_events(self.root)
        self.assertEqual(len(events), len({e["event_id"] for e in events}))
        self.assertEqual(2, sum(e["event_type"] == "attempt" for e in events))
        self.denied(self.attempt)

    def test_lifecycle_lock_delays_manager_and_closed_run_is_rechecked(self):
        from lib.project_lock import project_lock
        gate = Path(self.temp.name) / "lifecycle-gate"
        ready = Path(self.temp.name) / "lifecycle-ready"
        before = self.ledger()
        process = None
        try:
            with project_lock(self.root):
                process = subprocess.Popen([sys.executable, "-B", "-X", "utf8", str(Path(__file__).resolve()),
                    "--attempt-worker", str(self.root), str(ready), str(gate)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
                wait_until(ready.exists)
                gate.touch()
                wait_until(lambda: Path(str(ready) + ".enter").exists())
                with self.assertRaises(subprocess.TimeoutExpired):
                    process.communicate(timeout=.5)
                self.assertEqual(before, self.ledger())
                run_path = self.root / "versions/1.0/runs/run-1/run.json"
                run = json.loads(run_path.read_text(encoding="utf-8"))
                M.atomic_json(run_path, dict(run, status="blocked"))
            out, err = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 2, (out, err))
            self.assertFalse(err, err)
            self.assertFalse(json.loads(out)["ok"])
            self.assertEqual(before, self.ledger())
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()

    def test_manager_snapshot_can_share_an_existing_project_transaction(self):
        from lib.project_lock import project_lock
        with project_lock(self.root, timeout=.2):
            self.assertTrue(self.action()["allowed"])
            self.assertEqual(self.state()["references"], self.refs)

    def test_manager_ledger_replace_failure_preserves_old_bytes(self):
        before = self.ledger()
        original = M.os.replace

        def fail_replace(source, destination, *args, **kwargs):
            if Path(destination) == M.ledger_path(self.root):
                raise OSError("ledger replace refused")
            return original(source, destination, *args, **kwargs)

        with mock.patch.object(M.os, "replace", side_effect=fail_replace):
            with self.assertRaises(OSError):
                M.transition(self.root, "plan", {"route": route("b", "static")}, self.refs)
        self.assertEqual(self.ledger(), before)

    def test_invalid_transition_references_never_enter_ledger(self):
        for refs in (dict(self.refs, extra="x"), dict(self.refs, run_id=""),
                     dict(self.refs, project_id=123), None):
            with self.subTest(refs=refs):
                self.denied(lambda: M.transition(self.root, "plan",
                            {"route": route("b", "static")}, refs))
        fresh = Path(self.temp.name) / "fresh"
        M._make_project(fresh)
        with self.assertRaises(M.ManagerError):
            M.transition(fresh, "intake", self.intake, dict(self.refs, extra="x"))
        self.assertFalse(M.ledger_path(fresh).exists())

    def test_valid_final_event_without_newline_can_be_extended(self):
        path = M.ledger_path(self.root)
        original = self.ledger().rstrip(b"\n")
        path.write_bytes(original)
        M.transition(self.root, "plan", {"route": route("b", "static")}, self.refs)
        self.assertTrue(self.ledger().startswith(original + b"\n"))
        self.assertEqual(4, len(M.read_events(self.root)))
        self.assertIn("b", self.state()["routes"])

    def test_invalid_run_metadata_is_blocked_without_traceback_or_ledger_write(self):
        run_path = self.root / "versions/1.0/runs/run-1/run.json"
        for value in ([], None, "invalid", 3):
            with self.subTest(value=value):
                M.atomic_json(run_path, value)
                self.denied(self.attempt)
                code, output = self.cli("handoff", "--project", self.root)
                self.assertEqual(0, code)
                self.assertTrue(output["handoff"]["blocked"])
                self.assertIn({"type": "stale-context-or-target"},
                              output["handoff"]["state"]["evidence_errors"])


def wait_until(predicate):
    deadline = time.monotonic() + 10
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("synthetic worker synchronization timeout")
        time.sleep(.01)


def worker(root, ready, gate):
    Path(ready).touch()
    wait_until(lambda: Path(gate).exists())
    Path(ready + ".enter").touch()
    return M.main(["attempt", "--project", root, "--route-id", "a", "--failed", "--result",
                   "synthetic concurrent error", "--evidence", "versions/1.0/runs/run-1/output.log", "--json"])


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--attempt-worker":
        raise SystemExit(worker(*sys.argv[2:]))
    unittest.main(verbosity=2)
