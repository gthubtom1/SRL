#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synthetic tests for project_workflow.py (the coordination entry).

Everything runs in TemporaryDirectory: no user target is executed, no network, no
install, no repository mutation. Subprocesses are this repo's own CLIs
(project_state / manager_state / project_workflow) plus one real read-only MCP
function (seep_apk_info) as a positive control on a synthetic APK built in-test.

Usage: python -B -X utf8 Tool/scripts/test_project_workflow.py
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

WF = os.path.join(HERE, "project_workflow.py")
MANAGER = os.path.join(HERE, "manager_state.py")
CHILD_ENV = dict(os.environ, PYTHONIOENCODING="utf-8")

# External tool probes. When a parser/binary is absent the test MUST report an explicit
# UNVERIFIED skip instead of counting a missing capability as success.
def r2_binary() -> str:
    candidate = Path(ROOT, "Tool", "mcp", "Tool", "safe", "radare2", "bin",
                     "radare2.exe" if os.name == "nt" else "radare2")
    if candidate.is_file():
        return str(candidate)
    import shutil
    return shutil.which("radare2") or ""


def r2_error_markers(text: str) -> list:
    markers = ("Cannot find 'Unknown or unsupported arch'", "ERROR: Cannot",
               "-- Your radare2 is outdated", "WARN: Cannot find")
    return [m for m in markers if m in (text or "")]


def child_python() -> str:
    return sys.executable


def run_cli(script: str, args, timeout=180):
    proc = subprocess.run([child_python(), "-B", "-X", "utf8", script] + [str(a) for a in args],
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, env=CHILD_ENV, shell=False, cwd=ROOT)
    payload = {}
    text = (proc.stdout or "").strip()
    if text.startswith("{"):
        try:
            payload = json.loads(text)
        except ValueError:
            payload = {}
    return proc.returncode, payload, text, (proc.stderr or "")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(directory: Path) -> dict:
    if not directory.exists():
        return {}
    return {p.relative_to(directory).as_posix(): digest(p) if p.is_file() else "dir"
            for p in sorted(directory.rglob("*"))}


def make_elf() -> bytes:
    """Minimal-but-valid ELF64 with one RX program header and a code stub.

    A random byte blob makes radare2 report `Unknown or unsupported arch`, which the
    old test happily accepted as a successful parse. This header lets r2 enter
    entry0 without executing anything (the file is never run, only parsed).
    """
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400000 + 0x40, 64, 0, 0,
                         64, 56, 1, 64, 0, 0)
    program = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0x100, 0x100, 0x1000)
    return ident + header + program + b"\x90" * 0x80


def make_apk(path: Path, marker: str = "com.example.synthetic") -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml",
                    b"\x03\x00\x08\x00" + b"android:package=" + marker.encode() + b"\x00"
                    + b"android.permission.INTERNET\x00")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 32)
    return path


class WorkflowEntry(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="workflow-entry-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.project = self.base / "project"
        self.apk = make_apk(self.base / "sample.apk")

    # ---- helpers ---------------------------------------------------------
    def wf(self, *args):
        return run_cli(WF, list(args) + ["--json"])

    def wf_ok(self, *args):
        rc, payload, text, err = self.wf(*args)
        self.assertEqual(rc, 0, "unexpected rc=%s payload=%s stderr=%s"
                         % (rc, text[:800], err[:400]))
        return payload

    def start(self, quote="帮我看看这个安卓 APK 有没有加固", target=None,
              extra=(), route=True):
        args = ["start", "--project", self.project, "--quote", quote,
                "--allow-ambiguous", "--json"]
        if target is not None:
            args += ["--target", str(target)]
        if route:
            args += ["--route-id", "R1", "--p", "0.4", "--hours", "2-4h",
                     "--fail", "原件被改动或目标被运行", "--evidence-goal",
                     "结构画像 + 哈希"]
        return self.wf_ok(*args, *extra)

    def capture_dir(self, run_id):
        return self.project / "versions" / "1.0" / "runs" / run_id / "capture"

    def test_invalid_start_parameters_leave_no_project_and_allow_retry(self):
        common = ["--route-id", "R1", "--p", "0.4", "--hours", "1h",
                  "--fail", "parse error", "--evidence-goal", "metadata"]
        for i, invalid in enumerate((["--p=1.5"], ["--p=nan"], ["--p=inf"],
                                     ["--route-id", "../bad"], ["--run-id", "../bad"],
                                     ["--hours", " "], ["--quote", " "])):
            with self.subTest(invalid=invalid):
                project = self.base / ("invalid-" + str(i))
                args = ["start", "--project", project, "--target", self.apk,
                        "--quote", "inspect APK", "--primary-domain", "apkseep", *common]
                rc, result, text, err = self.wf(*args, *invalid)
                self.assertEqual(rc, 2, (text, err))
                self.assertFalse(project.exists(), result)
                self.wf_ok(*args)
        partial = self.base / "partial-route"
        rc, result, _, _ = self.wf("start", "--project", partial, "--quote", "inspect APK",
                                   "--primary-domain", "apkseep", "--route-id", "R1")
        self.assertEqual(rc, 2, result)
        self.assertFalse(partial.exists())

    def test_start_midflight_failure_returns_executable_recovery(self):
        import project_workflow as W
        from unittest.mock import patch
        original = W.run_cli
        stages = [(W.P_SCRIPT, "init", "project_state init"),
                  (W.P_SCRIPT, "run", "project_state run"),
                  (W.M_SCRIPT, "init", "manager intake"),
                  (W.M_SCRIPT, "plan", "manager plan"),
                  (W.M_SCRIPT, "choose", "manager choose")]
        for index, (script, action, stage) in enumerate(stages):
            with self.subTest(stage=stage):
                project = self.base / ("recover-" + str(index))
                def fail_step(command):
                    if command[:2] == [script, action]:
                        return {"ok": False, "reason": "fixture transient failure"}
                    return original(command)
                args = ["start", "--project", str(project), "--quote", "inspect APK",
                        "--primary-domain", "apkseep", "--target", str(self.apk),
                        "--route-id", "R1", "--p", "0.4", "--hours", "1h",
                        "--fail", "parse error", "--evidence-goal", "metadata", "--json"]
                output = io.StringIO()
                with patch.object(W, "run_cli", side_effect=fail_step), contextlib.redirect_stdout(output):
                    self.assertEqual(W.main(args), 2)
                result = json.loads(output.getvalue())
                self.assertEqual(result["completed_steps"], [s[2] for s in stages[:index]])
                self.assertEqual(len(result["recovery_commands"]), len(stages) - index)
                for recovery in result["recovery_commands"]:
                    self.assertEqual(recovery[0], sys.executable)
                    self.assertTrue(original(recovery[1:])["ok"])
                self.assertTrue(self.wf_ok("status", "--project", project)["ok"])

    def test_knowledge_is_shared_but_still_requires_readonly_effects(self):
        import project_workflow as W
        from unittest.mock import patch
        effects = W.load_effects()
        domains = [p.parent.name for p in Path(ROOT, "Tool", "skill").glob("*/pack.json")]
        self.assertEqual(len(domains), 9)
        for domain in domains:
            for action in ("kb.search", "kb.read"):
                with self.subTest(domain=domain, action=action):
                    admitted = W.admit_action(action, [domain], effects)
                    self.assertIsNotNone(admitted["effects"])
                    tool = W.ACTIONS[action]["tool"]
                    for changed in ({}, {**effects[tool], "touches_network": True}):
                        with self.assertRaises(W.WorkflowError):
                            W.admit_action(action, [domain], {**effects, tool: changed})
        # Child execution must re-read effects, including for shared knowledge.
        self.start(target=self.apk)
        context = W.derive_context(self.project, "kb.search")
        args = {"query": "APK"}
        payload = {"envelope": W._mint_envelope(context, args), "args": args}
        with patch.object(W, "load_effects", return_value={}):
            with self.assertRaises(W.ContextError):
                W.verify_action_context(payload)

    def test_auxiliary_file_is_bound_checked_and_refused_after_change(self):
        import project_workflow as W
        from unittest.mock import patch
        self.start(quote="检查网站及 Android 辅助材料", target="http://127.0.0.1:9/",
                   extra=("--primary-domain", "web-pentest", "--aux-domain", "apkseep"))
        rc, _, out, err = run_cli(W.P_SCRIPT, ["asset", "--project", self.project,
            "--version", "1.0", "--asset-id", "mobile", "--role", "auxiliary",
            "--target", self.apk])
        self.assertEqual(rc, 0, out + err)
        p = self.wf_ok("act", "--project", self.project, "--action", "apk.info",
                       "--asset-id", "mobile")
        capture = json.loads((self.project / p["capture"]).read_text(encoding="utf-8"))
        binding = capture["input_asset"]
        self.assertEqual(binding["asset_id"], "mobile")
        self.assertEqual(capture["params"]["apk_path"], str(self.project / binding["local_path"]))
        evidence = json.loads((self.evidence_dir() / (p["evidence_id"] + ".json"))
                              .read_text(encoding="utf-8"))
        self.assertEqual(evidence["input_asset"], binding)
        self.assertNotEqual(binding["sha256"], evidence["target_sha256"])
        context = W.derive_context(self.project, "apk.info")
        context["input_asset"] = binding
        args = {"apk_path": str(self.project / binding["local_path"])}
        payload = {"envelope": W._mint_envelope(context, args), "args": args}
        # Rebind in the child; a path cannot be substituted with a self-consistent envelope.
        substituted = {"apk_path": str(self.apk)}
        with self.assertRaises(W.ContextError):
            W.verify_action_context({"envelope": W._mint_envelope(context, substituted),
                                     "args": substituted})
        (self.project / binding["local_path"]).write_bytes(b"changed")
        with patch.object(W, "load_mcp", side_effect=AssertionError("must refuse before MCP")):
            with self.assertRaises(W.ContextError):
                W.verify_action_context(payload)
        with self.assertRaises(ValueError):
            W.P._evidence_path(self.project, evidence)
        before = snapshot(self.project)
        self.assertNotEqual(self.wf("act", "--project", self.project, "--action", "apk.info",
                                   "--asset-id", "mobile")[0], 0)
        self.assertEqual(before, snapshot(self.project))

    def test_unregistered_auxiliary_selection_never_runs(self):
        self.start(target=self.apk)
        before = snapshot(self.project)
        for asset in ("unknown", "../asset-main", str(self.apk)):
            self.assertNotEqual(self.wf("act", "--project", self.project, "--action", "apk.info",
                                       "--asset-id", asset)[0], 0)
        self.assertEqual(before, snapshot(self.project))

    def test_soft_domain_declares_its_existing_static_tools(self):
        import project_workflow as W
        elf = self.base / "sample.elf"
        elf.write_bytes(make_elf())
        self.start(quote="只读分析 ELF 结构", target=elf,
                   extra=("--primary-domain", "softseep"))
        result = self.wf_ok("act", "--project", self.project, "--action", "r2.info")
        capture = json.loads((self.project / result["capture"]).read_text(encoding="utf-8"))
        self.assertEqual(capture["admission"]["owner_domains"], ["softseep"])
        self.assertIn("ELF", capture["stdout"])
        for action in ("r2.strings", "r2.disasm", "r2.decompile", "packer.detect"):
            self.assertEqual(W.admit_action(action, ["softseep"], W.load_effects())["owner_domains"],
                             ["softseep"])
        with self.assertRaises(W.WorkflowError):
            W.admit_action("apk.info", ["softseep"], W.load_effects())

    def test_auxiliary_change_during_execution_is_not_accepted(self):
        import project_workflow as W
        from unittest.mock import patch
        self.start(target=self.apk)
        other = make_apk(self.base / "other.apk", "com.example.auxiliary")
        rc, _, out, err = run_cli(W.P_SCRIPT, ["asset", "--project", self.project,
            "--version", "1.0", "--asset-id", "other", "--role", "auxiliary",
            "--target", other])
        self.assertEqual(rc, 0, out + err)
        binding = W.P.asset_binding(self.project, "1.0", "other")
        real = W.run_action
        def changed(root, action, args, timeout, context=None):
            result = real(root, action, args, timeout, context=context)
            (root / binding["local_path"]).write_bytes(b"changed during execution")
            return result
        buf = io.StringIO()
        with patch.object(W, "run_action", side_effect=changed), contextlib.redirect_stdout(buf):
            rc = W.main(["act", "--project", str(self.project), "--action", "apk.info",
                         "--asset-id", "other", "--json"])
        result = json.loads(buf.getvalue())
        self.assertEqual(rc, 5, result)
        self.assertFalse(result["evidence_accepted"])
        self.assertTrue(result["toctou"])
        self.assertEqual(list(self.evidence_dir().glob("*.json")), [])

    def target_file(self) -> Path:
        version = self.version()
        return self.project / version["local_path"]

    def version(self) -> dict:
        return json.loads((self.project / "versions" / "1.0" / "version.json")
                          .read_text(encoding="utf-8"))

    def evidence_dir(self) -> Path:
        return self.project / "versions" / "1.0" / "evidence"

    def test_sensitive_tool_result_never_becomes_evidence(self):
        if not r2_binary():
            self.fail("UNVERIFIED: real r2 required for output-boundary regression")
        marker = "Bea" + "rer " + "synthetic-output-boundary-0123456789"
        elf = self.base / "sensitive.elf"
        elf.write_bytes(make_elf() + b"\x00" + marker.encode() + b"\x00")
        self.start("分析这个恶意样本的静态字符串", elf,
                   extra=("--primary-domain", "malware-analysis"))
        before = snapshot(self.project)
        rc, result, text, err = self.wf("act", "--project", self.project,
                                      "--action", "r2.strings", "--args-json",
                                      json.dumps({"all_sections": True, "limit": 1000}))
        self.assertEqual(rc, 5, text + err)
        self.assertFalse(result.get("evidence_accepted"))
        self.assertNotIn(marker, text + err)
        self.assertEqual(snapshot(self.project), before)
        for path in self.project.rglob("*"):
            if path.is_file() and path.suffix in (".json", ".jsonl", ".md", ".log", ".txt"):
                self.assertNotIn(marker, path.read_text(encoding="utf-8", errors="replace"))

    # ---- 1. dynamic pack, no hardcoded nine domains ----------------------
    def test_classify_uses_dynamic_pack_not_hardcoded_domains(self):
        skill_dir = self.base / "skills"
        pack_dir = skill_dir / "quantum-foo"
        pack_dir.mkdir(parents=True)
        (pack_dir / "SKILL.md").write_text("# quantum-foo\n", encoding="utf-8")
        (pack_dir / "pack.json").write_text(json.dumps({
            "schema": "seep.pack/1", "id": "quantum-foo", "l1": "synthetic quantum domain",
            "routes": [{"label": "quantum target", "must": ["(?i)量子\\s*靶机"],
                        "priority": 900}],
            "tools": ["seep_kb_search", "seep_kb_read"],
        }, ensure_ascii=False), encoding="utf-8")
        payload = self.wf_ok("classify", "--quote", "帮我拆量子靶机", "--skill-dir", str(skill_dir))
        self.assertEqual(payload["primary_candidate"], "quantum-foo")
        self.assertEqual(payload["pack_tools"]["quantum-foo"]["tools"],
                         ["seep_kb_search", "seep_kb_read"])
        self.assertFalse(payload["unclassified"])
        self.assertEqual(payload["enforcement_scope"], "workflow-entry-only")
        self.assertFalse(payload["globally_enforced"])

    # ---- 2. unclassified => no project, zero disk writes -----------------
    def test_unclassified_writes_nothing(self):
        rc, payload, text, _err = self.wf("classify", "--quote", "今天天气不错", "--json")
        self.assertEqual(rc, 2, text[:400])
        self.assertTrue(payload.get("unclassified"))
        self.assertIsNone(payload.get("primary_candidate"))
        rc, payload, text, _err = self.wf("start", "--project", str(self.project),
                                          "--quote", "今天天气不错", "--json")
        self.assertEqual(rc, 2, text[:400])
        self.assertFalse(self.project.exists(), "unclassified start must not create a project")

    # ---- 3. ambiguity is handed to the main agent ------------------------
    def test_ambiguous_classification_requires_main_agent_decision(self):
        payload = self.wf_ok("classify", "--quote", "帮我看看这个安卓 APK 有没有加固")
        self.assertTrue(payload["ambiguity"])
        self.assertTrue(payload["requires_main_agent_decision"])
        rc, refused, text, _err = self.wf("start", "--project", str(self.project),
                                          "--quote", "帮我看看这个安卓 APK 有没有加固",
                                          "--json")
        self.assertEqual(rc, 2)
        self.assertIn("ambiguity", refused.get("reason", ""))
        self.assertFalse(self.project.exists())

    # ---- 4. start only registers lifecycle ------------------------------
    def test_start_registers_lifecycle_without_running_target(self):
        before = digest(self.apk)
        payload = self.start(target=self.apk)
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["executed_target"])
        self.assertFalse(payload["ran_any_action"])
        run_id = payload.get("run") or ""
        self.assertTrue(run_id, "start must return a concrete run id")
        run_path = (self.project / "versions" / "1.0" / "runs" / run_id / "run.json")
        self.assertTrue(run_path.is_file(), "start must register the run it reports")
        run_record = json.loads(run_path.read_text(encoding="utf-8"))
        self.assertEqual(run_record.get("run_id"), run_id)
        self.assertEqual(run_record.get("status"), "active")
        self.assertEqual(run_record.get("executor"), "workflow-entry")
        self.assertEqual(digest(self.target_file()), before,
                         "the project copy must be byte-identical to the source target")
        self.assertTrue((self.project / "project.json").is_file())
        self.assertTrue((self.project / "versions" / "1.0" / "version.json").is_file())
        self.assertTrue((self.project / "manager-events.jsonl").is_file())
        self.assertEqual(digest(self.apk), before, "source target must not be executed or modified")
        cap = self.capture_dir(payload["run"])
        self.assertEqual(sorted(cap.glob("*.json")), [], "start must not run any action")

    def test_start_rejects_existing_project(self):
        self.start(target=self.apk)
        rc, payload, text, _err = self.wf("start", "--project", str(self.project),
                                          "--quote", "安卓APK", "--allow-ambiguous", "--json")
        self.assertEqual(rc, 2)
        self.assertIn("项目已存在", payload.get("reason", ""))

    def test_status_does_not_rewrite_project_metadata(self):
        import project_workflow as W
        from unittest.mock import patch
        self.start(target=self.apk)
        before = snapshot(self.project)
        output = io.StringIO()
        with patch.object(W.P, "now", return_value="2000-01-01T00:00:00Z"), contextlib.redirect_stdout(output):
            self.assertEqual(W.main(["status", "--project", str(self.project), "--json"]), 0)
        self.assertTrue(json.loads(output.getvalue())["ok"])
        self.assertEqual(snapshot(self.project), before)

    def test_invalid_close_is_checked_before_defining_acceptance(self):
        for index, extra in enumerate((("--accept", "malformed"), ("--accept", "ac=pass:any"),
                      ("--finish", "completed"), ("--run", "../outside"))):
            with self.subTest(extra=extra):
                self.project = self.base / ("close-invalid-" + str(index))
                self.start(target=self.apk)
                before = snapshot(self.project)
                rc, result, text, err = self.wf("close", "--project", self.project,
                    "--version", "1.0", "--define", "ac:fixture", *extra)
                self.assertEqual(rc, 2, (text, err))
                self.assertFalse(result["ok"])
                self.assertEqual(snapshot(self.project), before)

    def test_cli_nonzero_exit_cannot_be_reported_as_ok(self):
        import project_workflow as W
        from unittest.mock import patch
        proc = subprocess.CompletedProcess([], 2, '{"ok":true}', "fixture failure")
        with patch.object(W.subprocess, "run", return_value=proc):
            result = W.run_cli(["fixture"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["rc"], 2)

    def test_bad_effects_container_is_a_structured_gap(self):
        import project_workflow as W
        from unittest.mock import patch
        effects = self.base / "effects.json"
        effects.write_text("[]", encoding="utf-8")
        with patch.object(W, "EFFECTS_PATH", str(effects)):
            self.assertEqual(W.load_effects(), {})
        for value in (None, [], "declared"):
            with self.subTest(value=value), self.assertRaises(W.WorkflowError):
                W.admit_action("kb.search", ["apkseep"], {"seep_kb_search": value})

    # ---- 5. WAIT_USER blocks act with zero capture ----------------------
    def test_act_refused_under_wait_user_writes_no_capture(self):
        started = self.start(target=self.apk)
        run_id = started["run"]
        cap = self.capture_dir(run_id)
        before = snapshot(cap)
        run_cli(MANAGER,
                ["wait", "--project", str(self.project), "--option", "A=继续",
                 "--option", "B=停", "--monitor", "m", "--guarantee", "g",
                 "--expected-input", "A/B", "--json"])
        after_wait = snapshot(cap)
        self.assertEqual(before, after_wait)
        rc, payload, text, _err = self.wf("act", "--project", str(self.project),
                                          "--action", "meta.fingerprint")
        self.assertEqual(rc, 2, text[:600])
        self.assertIn("WAIT_USER", payload.get("reason", ""))
        self.assertEqual(payload.get("waiting", {}).get("status"), "WAIT_USER")
        self.assertEqual(snapshot(cap), after_wait, "refused act must not write capture")
        self.assertFalse(payload.get("executed"))
        self.assertNotIn("evidence_id", payload)
        self.assertEqual(list(self.evidence_dir().glob("*.json"))
                         if self.evidence_dir().exists() else [], [])
        self.assertNotIn('"event_type": "attempt"',
                         (self.project / "manager-events.jsonl").read_text(encoding="utf-8"))

    def test_refusals_happen_before_the_action_runner_is_reached(self):
        """Every pre-execution refusal must leave run_action uncalled (no side effects)."""
        import project_workflow as W

        calls = []
        real = W.run_action
        W.run_action = lambda *a, **k: calls.append(a) or real(*a, **k)
        try:
            # (a) unregistered action
            self.assertEqual(self.wf("act", "--project", str(self.project),
                                      "--action", "shell")[0], 2)
            self.start(target=self.apk)
            # (b) action missing from this domain's pack.tools
            firmware = self.base / "firmware"
            self.wf_ok("start", "--project", str(firmware), "--quote", "路由器固件",
                       "--target", str(self.apk), "--primary-domain", "firmware-iot",
                       "--route-id", "R1", "--p", "0.4", "--hours", "2-4h",
                       "--fail", "原件被改", "--evidence-goal", "画像")
            self.assertEqual(self.wf("act", "--project", str(firmware),
                                      "--action", "apk.info")[0], 3)
            # (c) WAIT_USER
            run_cli(MANAGER, ["wait", "--project", str(self.project), "--option", "A=a",
                              "--option", "B=b", "--monitor", "m", "--guarantee", "g",
                              "--expected-input", "A/B", "--json"])
            self.assertEqual(self.wf("act", "--project", str(self.project),
                                      "--action", "meta.fingerprint")[0], 2)
            # (d) stale target hash
            target = self.target_file()
            target.write_bytes(target.read_bytes() + b"drift")
            self.assertEqual(self.wf("act", "--project", str(self.project),
                                      "--action", "meta.fingerprint")[0], 2)
        finally:
            W.run_action = real
        self.assertEqual(calls, [], "no refusal path may reach the action runner")

    # ---- 6. two failures => third act refused; replan unblocks ----------
    def test_two_failures_block_third_attempt_until_replan(self):
        # malware-analysis declares seep_packer_detect; on a non-PE target the real
        # function refuses ("仅支持 PE 文件") -> a genuine failed attempt recorded
        # from real output, never a fabricated success.
        started = self.wf_ok("start", "--project", str(self.project),
                             "--quote", "这个样本是不是加壳了", "--target", str(self.apk),
                             "--primary-domain", "malware-analysis", "--route-id", "R1",
                             "--p", "0.4", "--hours", "2-4h", "--fail", "无法读目标",
                             "--evidence-goal", "加壳/画像", "--json")
        run_id = started["run"]
        for _ in range(2):
            failed = self.wf_ok("act", "--project", str(self.project), "--action",
                                "packer.detect")
            self.assertEqual(failed["outcome"], "failed")
            self.assertTrue(failed["evidence_registered"], "failures must keep real evidence")
        cap = self.capture_dir(run_id)
        before = snapshot(cap)
        evidence_before = snapshot(self.evidence_dir()) if self.evidence_dir().exists() else {}
        rc, payload, text, _err = self.wf("act", "--project", str(self.project),
                                         "--action", "meta.fingerprint")
        self.assertEqual(rc, 2, text[:600])
        self.assertTrue(payload.get("replan_required"))
        self.assertEqual(snapshot(cap), before, "3rd attempt must be blocked before capture")
        self.assertEqual(snapshot(self.evidence_dir()) if self.evidence_dir().exists() else {},
                         evidence_before, "3rd attempt must not register evidence")
        self.assertFalse(payload.get("executed"))
        rc, payload, text, _err = wf_replan(self.project)
        self.assertEqual(rc, 0, text[:600])
        payload = self.wf_ok("act", "--project", str(self.project),
                             "--action", "meta.fingerprint")
        self.assertTrue(payload["evidence_registered"])
        self.assertEqual(payload["outcome"], "succeeded")

    # ---- 7. unknown / shell / arbitrary-command sentinels ----------------
    def test_unknown_and_shell_actions_rejected_without_sentinel(self):
        self.start(target=self.apk)
        sentinel = self.base / "sentinel.txt"
        for args in (
            ["--action", "shell"],
            ["--action", "seep_r2_cmd"],
            ["--action", "seep_r2_cmd", "--args-json",
             json.dumps({"command": "cmd /c echo pwned > %s" % sentinel})],
            ["--action", "kb.search", "--args-json",
             json.dumps({"query": "x", "command": "cmd /c echo pwned > %s" % sentinel})],
            ["--action", "tool-run", "--args-json",
             json.dumps({"argv": ["cmd", "/c", "echo", "pwned"]})],
        ):
            rc, payload, text, _err = self.wf("act", "--project", str(self.project), *args,
                                              "--json")
            self.assertEqual(rc, 4, "%s -> rc=%s %s" % (args[0], rc, text[:400]))
            self.assertFalse(sentinel.exists(), "no arbitrary command may ever run")
        self.assertIn("allowed", json.loads((self.wf("act", "--project", str(self.project),
                                                     "--action", "shell", "--json")[2])))

    # ---- 8. domain-specific action must be declared by the pack ---------
    def test_domain_specific_action_requires_pack_tools(self):
        started = self.wf_ok("start", "--project", str(self.project),
                             "--quote", "路由器固件里有什么", "--target", str(self.apk),
                             "--primary-domain", "firmware-iot", "--route-id", "R1",
                             "--p", "0.4", "--hours", "2-4h", "--fail", "原件被改",
                             "--evidence-goal", "结构画像", "--json")
        cap = self.capture_dir(started["run"])
        before = snapshot(cap)
        rc, payload, text, _err = self.wf("act", "--project", str(self.project),
                                          "--action", "apk.info", "--json")
        self.assertEqual(rc, 3, text[:600])
        self.assertIn("capability_gap", payload.get("reason", ""))
        self.assertIn("pack.tools", payload.get("reason", ""))
        self.assertEqual(snapshot(cap), before)
        # The shared pre-action does not require a pack.tools declaration.
        self.wf_ok("act", "--project", str(self.project), "--action", "meta.fingerprint")

    # ---- 9. real capture -> evidence -> attempt chain -------------------
    def test_repeated_action_in_one_second_preserves_each_raw_capture(self):
        import project_workflow as W
        from unittest.mock import patch
        self.start(target=self.apk)
        results = [dict(method="fixture-readonly", argv=["fixture"], params={}, rc=0,
                        timeout=False, stdout='{"ok":true,"probe":%d}' % index,
                        stderr="", tool_ok=True, tool_payload_ok=True,
                        tool_has_result=True, tool_status="ok") for index in (1, 2)]
        captures = []
        with patch.object(W, "utc_slug", return_value="fixed-second"), \
                patch.object(W, "run_action", side_effect=results):
            for index in range(2):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    rc = W.main(["act", "--project", str(self.project),
                                 "--action", "meta.fingerprint", "--json"])
                self.assertEqual(rc, 0, output.getvalue())
                result = json.loads(output.getvalue())
                path = self.project / result["capture"]
                capture = json.loads(path.read_text(encoding="utf-8"))
                raw = path.with_name(capture["raw_capture"])
                captures.append((raw, raw.read_bytes()))
        self.assertNotEqual(captures[0][0], captures[1][0])
        for raw, original in captures:
            self.assertEqual(raw.read_bytes(), original)
        self.wf_ok("status", "--project", self.project)

    def test_raw_output_tamper_or_loss_blocks_close_and_resume(self):
        started = self.start(target=self.apk)
        payload = self.wf_ok("act", "--project", str(self.project), "--action", "meta.fingerprint")
        capture_path = self.project / payload["capture"]
        capture = json.loads(capture_path.read_text(encoding="utf-8"))
        raw = capture_path.with_name(capture["raw_capture"])
        original = raw.read_bytes()
        raw.write_bytes(b"different raw execution output\n")
        rc, refused, text, _ = self.wf("close", "--project", self.project,
            "--version", "1.0", "--run", started["run"], "--define", "ac:fixture capture",
            "--accept", "ac=pass:" + payload["evidence_id"],
            "--verifier", "fixture reader", "--how", "synthetic read-only check",
            "--finish", "completed")
        self.assertEqual(rc, 2, text)
        self.assertFalse(refused["ok"])
        run_path = self.project / "versions/1.0/runs" / started["run"] / "run.json"
        self.assertEqual(json.loads(run_path.read_text(encoding="utf-8"))["status"], "active")
        raw.write_bytes(original)
        self.wf_ok("close", "--project", self.project, "--version", "1.0",
            "--run", started["run"], "--accept", "ac=pass:" + payload["evidence_id"],
            "--verifier", "fixture reader", "--how", "synthetic read-only check",
            "--finish", "completed")
        self.wf_ok("status", "--project", self.project)
        raw.unlink()
        rc, status, text, _ = self.wf("status", "--project", self.project)
        self.assertEqual(rc, 2, text)
        self.assertFalse(status["ok"])
        raw.write_bytes(original)
        self.wf_ok("status", "--project", self.project)

    def test_legacy_capture_still_rechecks_raw_output_without_new_index_fields(self):
        self.start(target=self.apk)
        payload = self.wf_ok("act", "--project", str(self.project), "--action", "meta.fingerprint")
        evidence_path = self.project / "versions/1.0/evidence" / (payload["evidence_id"] + ".json")
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence.pop("raw_output", None)
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        manifest_path = self.project / "versions/1.0/manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for entry in manifest["evidence"]:
            entry.pop("raw_output", None)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.wf_ok("status", "--project", self.project)
        capture_path = self.project / payload["capture"]
        capture = json.loads(capture_path.read_text(encoding="utf-8"))
        capture_path.with_name(capture["raw_capture"]).unlink()
        rc, status, text, _ = self.wf("status", "--project", self.project)
        self.assertEqual(rc, 2, text)
        self.assertFalse(status["ok"])

    def test_real_capture_chain_binds_evidence_and_attempt(self):
        started = self.start(target=self.apk)
        run_id = started["run"]
        payload = self.wf_ok("act", "--project", str(self.project),
                             "--action", "meta.fingerprint")
        self.assertEqual(payload["outcome"], "succeeded")
        self.assertTrue(payload["evidence_registered"])
        self.assertTrue(payload["attempt_recorded"])
        self.assertIn("pending", payload["acceptance"])
        cap_path = self.project / payload["capture"]
        capture = json.loads(cap_path.read_text(encoding="utf-8"))
        for key in ("argv", "params", "rc", "method", "target_sha256", "generation_id",
                    "references", "pre_check_ledger_head", "raw_sha256", "raw_size"):
            self.assertIn(key, capture, key)
        self.assertEqual(capture["generation_id"], payload["generation_id"])
        self.assertEqual(capture["target_sha256"], payload["target_sha256"])
        raw = cap_path.with_name(capture["raw_capture"])
        self.assertTrue(raw.is_file())
        self.assertEqual(raw.stat().st_size, capture["raw_size"])
        self.assertEqual(digest(raw), capture["raw_sha256"])

        version = json.loads((self.project / "versions" / "1.0" / "version.json")
                             .read_text(encoding="utf-8"))
        events = [json.loads(x) for x in
                  (self.project / "manager-events.jsonl").read_text(encoding="utf-8").splitlines()
                  if x.strip()]
        attempt = [e for e in events if e["event_type"] == "attempt"][-1]["payload"]["attempt"]
        self.assertEqual(attempt["generation_id"], payload["generation_id"])
        self.assertEqual(attempt["target_sha256"], version["sha256"])
        self.assertEqual(attempt["references"]["run_id"], run_id)
        self.assertEqual([e["path"] for e in attempt["evidence"]], [payload["capture"]])
        self.assertFalse(attempt.get("project_pass"))

        evidence = json.loads((self.project / "versions" / "1.0" / "evidence" /
                               (payload["evidence_id"] + ".json")).read_text(encoding="utf-8"))
        self.assertEqual(evidence["run_id"], run_id)
        self.assertEqual(evidence["target_sha256"], version["sha256"])
        self.assertEqual(evidence["sha256"], digest(cap_path))
        # exit0/method return never records acceptance by itself.
        acceptance = json.loads((self.project / "versions" / "1.0" / "acceptance.json")
                                .read_text(encoding="utf-8"))
        self.assertEqual(acceptance.get("items"), [])
        rc, refused, text, _err = self.wf("close", "--project", str(self.project),
                                          "--version", "1.0", "--run", run_id,
                                          "--define", "ac1:结构画像完整",
                                          "--finish", "completed", "--json")
        self.assertEqual(rc, 2, text[:600])
        self.assertEqual(refused["refused_at"], "finish-run")
        self.assertFalse(refused["acceptance"]["complete"])
        self.assertFalse(refused["wrote_pass_itself"])

    # ---- 11. strict positive control: full chain must really complete ---
    def test_full_cli_chain_completes_with_real_closure(self):
        """start -> act (real read-only parse) -> evidence -> acceptance -> close.

        This is a REQUIRED green: a refusal here is a failure, not an acceptable
        alternative. Unknown/missing-capability cases live in the expected-gap test
        below and never satisfy this positive control.
        """
        started = self.start(target=self.apk)
        run_id = started["run"]
        act = self.wf_ok("act", "--project", str(self.project), "--action", "apk.info")
        self.assertEqual(act["outcome"], "succeeded")
        ev = act["evidence_id"]
        cap_path = self.project / act["capture"]
        cap_sha = digest(cap_path)
        rc, closed, text, err = self.wf("close", "--project", str(self.project),
                                        "--version", "1.0", "--run", run_id,
                                        "--define", "ac1:结构画像完整",
                                        "--accept", "ac1=pass:%s" % ev,
                                        "--verifier", "synthetic-test",
                                        "--how", "合成 APK 只读解析 + 哈希现算",
                                        "--finish", "completed")
        self.assertEqual(rc, 0, "real gate must complete the chain: rc=%s %s %s"
                         % (rc, text[:900], err[:400]))
        self.assertFalse(closed["wrote_pass_itself"], "close must never write pass itself")
        self.assertIsNone(closed["refused_at"])
        self.assertEqual(closed["run_status"], "completed")
        self.assertTrue(closed["acceptance"]["complete"])
        self.assertTrue(all(step["ok"] for step in closed["steps"]))
        self.assertEqual([step["step"] for step in closed["steps"]],
                         ["acceptance-define", "acceptance-record:ac1",
                          "finish-run:completed"])

        run = json.loads((self.project / "versions" / "1.0" / "runs" / run_id /
                          "run.json").read_text(encoding="utf-8"))
        closure = run.get("closure") or {}
        self.assertEqual(run["status"], "completed")
        self.assertEqual(closure.get("kind"), "run-completed")
        self.assertEqual(closure.get("target_sha256"), self.version()["sha256"])
        self.assertEqual(closure.get("evidence_sha256"), {ev: cap_sha},
                         "closure must bind the real capture file hash")
        self.assertEqual(closure.get("acceptance_sha256"),
                         digest(self.project / "versions" / "1.0" / "acceptance.json"))
        self.assertEqual(closure.get("required_count"), 1)
        snapshot = run.get("acceptance_snapshot") or {}
        self.assertEqual(snapshot.get("target_sha256"), self.version()["sha256"])
        self.assertEqual(snapshot.get("run_id"), run_id)
        self.assertEqual(snapshot.get("counts", {}).get("pass"), 1)

        evidence = json.loads((self.evidence_dir() / (ev + ".json"))
                              .read_text(encoding="utf-8"))
        self.assertEqual(evidence["sha256"], cap_sha)
        self.assertEqual(evidence["run_id"], run_id)
        self.assertEqual(evidence["target_sha256"], self.version()["sha256"])

        rc, handoff, text, _err = run_cli(os.path.join(HERE, "project_state.py"),
                                          ["resume", "--project", str(self.project)])
        self.assertEqual(rc, 0, text[:900])
        data = handoff["handoff"]
        self.assertEqual(data["status"], "active")
        self.assertTrue(data["acceptance_complete"])
        self.assertEqual(data["closure_errors"], [])
        self.assertEqual(data["completed_runs"], [run_id])

        # A pass with no evidence still has to be refused (negative control).
        rc, refused, text, _err = self.wf("close", "--project", str(self.project),
                                          "--version", "1.0", "--run", run_id,
                                          "--accept", "ac1=pass:")
        self.assertEqual(rc, 2, "pass without evidence must be refused: " + text[:200])

        # Post-completion checklist drift must break the recomputed closure.
        acceptance_path = self.project / "versions" / "1.0" / "acceptance.json"
        original = acceptance_path.read_bytes()
        acceptance_path.write_bytes(original.replace(b"\n", b"\n ", 1))
        rc, broken, text, _err = run_cli(os.path.join(HERE, "project_state.py"),
                                         ["resume", "--project", str(self.project)])
        self.assertEqual(rc, 2, "edited checklist after completion must be detected")
        self.assertTrue(broken["handoff"]["closure_errors"], text[:600])
        acceptance_path.write_bytes(original)
        rc, restored, _t, _e = run_cli(os.path.join(HERE, "project_state.py"),
                                       ["resume", "--project", str(self.project)])
        self.assertEqual(rc, 0, "restoring the original bytes must restore the closure")
        self.assertEqual(restored["handoff"]["closure_errors"], [])

    # ---- 11b. expected gap: unknown/missing capability is a separate case -
    def test_expected_gap_actions_refused_without_touching_disk(self):
        started = self.wf_ok("start", "--project", str(self.project),
                             "--quote", "路由器固件里有什么", "--target", str(self.apk),
                             "--primary-domain", "firmware-iot", "--route-id", "R1",
                             "--p", "0.4", "--hours", "2-4h", "--fail", "原件被改",
                             "--evidence-goal", "结构画像", "--json")
        cap = self.capture_dir(started["run"])
        before = snapshot(cap)
        for action, expected_rc in (("seep_r2_cmd", 4), ("seep_packer_detect", 4),
                                    ("shell", 4), ("metasploit.console", 4)):
            rc, payload, text, _err = self.wf("act", "--project", str(self.project),
                                              "--action", action)
            self.assertEqual(rc, expected_rc, "%s -> rc=%s %s" % (action, rc, text[:400]))
            self.assertIn("capability_gap", payload.get("reason", ""), action)
            self.assertFalse(payload.get("executed"))
            self.assertNotIn("evidence_id", payload)
        self.assertEqual(snapshot(cap), before, "expected gaps must not write capture")
        self.assertEqual(list(self.evidence_dir().glob("*.json"))
                         if self.evidence_dir().exists() else [], [])

    # ---- 11c. exec channel: target cannot be overridden, MCP never loaded ----
    def test_exec_channel_refuses_overridden_target_before_loading_mcp(self):
        """FIXED (was refuted): the exec channel re-verifies context and rebinds target.

        Previously `project_workflow.py _exec` re-checked parameter *names* only, so
        `binary_path` could point at any file while evidence bound the project hash.
        Now the channel proves: (a) no project => refused with load_mcp/`_run_cmd`
        calls = 0; (b) a target override in the args payload is refused (not silently
        ignored) before the loader; (c) a hand-built envelope with a stale/altered
        digest is refused. No payload is executed: spies only record calls.
        """
        import project_workflow as W

        seen = {}
        loaded = []

        class FakeMCP:
            def seep_r2_info(self, **kwargs):
                seen.update(kwargs)
                return "{\"ok\": true}"

        outside = self.base / "outside-target.bin"
        outside.write_bytes(b"not the project target")
        real_loader = W.load_mcp

        def loader():
            loaded.append(True)
            return FakeMCP()

        def run_main(argv, payload=None):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = W.child_main(payload) if payload is not None else W.main(argv)
            return rc, buf.getvalue()

        W.load_mcp = loader
        try:
            # (a) the CLI no longer exposes any argument-driven exec entry point.
            rc, out = run_main(["child", "--action", "r2.info", "--args-json",
                                json.dumps({"binary_path": str(outside)})])
            self.assertNotEqual(rc, 0, out[:400])
            self.assertIn("invalid CLI arguments", out)
            rc, out = run_main(["_exec", "--action", "r2.info", "--args-json",
                                json.dumps({"binary_path": str(outside)})])
            self.assertEqual(rc, 2, "_exec must no longer be an accepted subcommand")
            # (b) a bare payload without a controlled context is refused.
            rc, out = run_main(None, {"args": {"binary_path": str(outside)}})
            self.assertEqual(rc, 4, out[:400])
            # (c) a project-less context is refused (no project => no execution).
            ctx = {"project": "", "action": "r2.info"}
            env = {"nonce": "x", "digest": "y", "context": ctx}
            rc, out = run_main(None, {"envelope": env, "args": {}})
            self.assertEqual(rc, 4, out[:400])
        finally:
            W.load_mcp = real_loader
        self.assertEqual(loaded, [], "the MCP module must not load for refused calls")
        self.assertEqual(seen, {}, "no tool function may be reached for refused calls")

    def test_r2_target_injection_is_refused_by_the_mcp_entry(self):
        """FIXED (was refuted): target is validated at the MCP entry; spy sees 0 calls.

        `seep_r2_disasm`/`seep_r2_decompile` used to splice `target` into the r2 `-c`
        command string, so `;` started a new r2 command and `!` a shell command.
        Now the tool rejects any command/expression separator *before* building the
        command line: `_run_cmd` is spied and must record nothing, and the returned
        payload must be a structured refusal. Legitimate syntax still works (the
        positive control is asserted through the same spy).
        """
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "seep_mcp_server_probe", os.path.join(ROOT, "Tool", "mcp", "seep_mcp_server.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        recorded = []
        real_run_cmd = module._run_cmd

        def spy(cmd, **_kwargs):
            recorded.append(list(cmd))
            return "fake-parser-output"

        module._run_cmd = spy
        payloads = [
            "entry0; !echo injected-not-executed",
            "main\n!cmd",
            "main && calc",
            "main | more",
            "main > out",
            "main `id`",
            "$(id)",
            "main $(whoami)",
            "main+0x10",
            "../outside",
            "main;wx 90",
        ]
        try:
            for bad in payloads:
                for fn in (module.seep_r2_disasm, module.seep_r2_decompile):
                    out = fn(binary_path=str(self.apk), target=bad)
                    self.assertIn("invalid_parameters", out, (fn.__name__, bad, out[:200]))
                    self.assertNotIn(bad, out, "the refusal must not echo the raw target")
        finally:
            module._run_cmd = real_run_cmd
        self.assertEqual(recorded, [], "a rejected target must never build an r2 argv")

        # Positive control through the same spy: legitimate syntax still reaches r2.
        module._run_cmd = spy
        try:
            for good in ("main", "sym.imp.puts", "sub_123", "0x123"):
                module.seep_r2_disasm(binary_path=str(self.apk), target=good)
        finally:
            module._run_cmd = real_run_cmd
        self.assertTrue(recorded, "legitimate targets must still reach the parser")
        command_string = recorded[0][recorded[0].index("-c") + 1]
        self.assertEqual(command_string, "aaa; pdf @ main", command_string)

        # Integer parameters are range/type checked at the MCP entry as well.
        for kwargs in ({"lines": "abc"}, {"lines": 0}, {"lines": 10 ** 9},
                       {"limit_tokens": -1}, {"output_mode": "nope"}):
            out = module.seep_r2_disasm(binary_path=str(self.apk), **kwargs)
            self.assertIn("invalid_parameters", out, (kwargs, out[:200]))

    def test_public_exec_entry_is_gone_and_requires_project_gate(self):
        """FIXED (was refuted): `_exec` is no longer a public CLI subcommand.

        Previously `project_workflow.py _exec` validated parameter *names* only, then
        loaded the MCP module and ran the tool: no `check_action`, no project, no
        target binding. Reaching it through the normal CLI gave read-only capability
        without any of the entry's stated pre/post conditions.

        Now: no project => refused before the loader; the sentinel outside the
        project is never read. The positive control (`act` on a real project) still
        succeeds and keeps its pre/post checks.
        """
        sentinel_dir = self.base / "outside-project"
        sentinel_dir.mkdir()
        marker = "SENTINEL_EXEC_BYPASS_TOKEN"
        (sentinel_dir / "probe.smali").write_text(".method x\n%s\n" % marker,
                                                  encoding="utf-8")
        # (a) the old public flag-driven path is simply not a subcommand any more.
        proc = subprocess.run([child_python(), "-B", "-X", "utf8", WF, "_exec",
                               "--action", "apk.smali_search", "--args-json",
                               json.dumps({"directory": str(sentinel_dir),
                                           "pattern": marker})],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", env=CHILD_ENV, cwd=ROOT)
        self.assertNotEqual(proc.returncode, 0, proc.stdout[:400])
        self.assertNotIn(marker, proc.stdout, "the sentinel must never be read")

        # (b) the child entry refuses a bare project-less payload with 0 loader calls.
        import project_workflow as W
        loaded, check_calls = [], []
        real_loader, real_check = W.load_mcp, W.M.check_action
        W.load_mcp = lambda: loaded.append(True) or object()
        W.M.check_action = lambda *a, **k: check_calls.append(a)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = W.child_main({"args": {"directory": str(sentinel_dir),
                                            "pattern": marker}})
            self.assertEqual(rc, 4, buf.getvalue()[:400])
            self.assertIn("受控", buf.getvalue())
            self.assertNotIn(marker, buf.getvalue())
            rc = W.child_main({"envelope": {"nonce": "n", "digest": "d",
                                            "context": {"project": "",
                                                        "action": "kb.search"}},
                               "args": {"query": "x"}})
            self.assertEqual(rc, 4, "a project-less context must be refused")
        finally:
            W.load_mcp, W.M.check_action = real_loader, real_check
        self.assertEqual(loaded, [], "refused payloads must not load the MCP module")
        self.assertEqual(check_calls, [], "refused payloads must not reach check-action")
        self.assertFalse((self.project / "project.json").exists())

        # (c) sentinel outside the project stays unread even on the normal act path.
        self.start(target=self.apk)
        rc, payload, text, _err = self.wf("act", "--project", str(self.project),
                                          "--action", "apk.smali_search", "--args-json",
                                          json.dumps({"directory": str(sentinel_dir),
                                                      "pattern": marker}))
        self.assertEqual(rc, 4, text[:400])
        self.assertIn("项目内相对路径", payload.get("reason", ""))
        self.assertNotIn(marker, text)
        self.assertEqual(payload.get("blocked_at"), "act")
        self.assertFalse(payload.get("executed"))

    # ---- 11d. FIXED: 子进程真实重新 admit_action（域/pack.tools/effects） ----
    def test_child_re_admits_current_domain_pack_and_effects(self):
        """FIXED (was refuted §3.2): the exec channel re-runs `admit_action`.

        Before: the child only did `check_action` + params + target rebind. A forged
        envelope therefore executed `apk.info` inside a `firmware-iot` project, while
        the parent `act` correctly refused rc=3 (pack.tools lacks `seep_apk_info`).

        Now the child re-derives the Manager's *current* primary/aux domains from disk,
        recomputes pack.tools from `Tool/skill/*/pack.json`, re-reads
        `Tool/config/tool-effects.json`, and re-runs `validate_args`. This test asserts
        (a) act and child now agree (rc=3, loader=0), (b) a tampered `effects` table
        cannot be smuggled through the envelope, (c) an out-of-domain action is refused
        with the loader never called. No payload is executed: `load_mcp` is a recorder.
        """
        import project_workflow as W

        # firmware-iot pack declares only KB tools: apk.info must be a capability gap.
        self.wf_ok("start", "--project", self.project, "--quote", "路由器固件",
                   "--target", str(self.apk), "--primary-domain", "firmware-iot",
                   "--route-id", "R1", "--p", "0.4", "--hours", "2-4h",
                   "--fail", "原件被改", "--evidence-goal", "画像", "--json")
        loaded, seen = [], {}
        real_loader = W.load_mcp

        class FakeMCP:
            def __getattr__(self, name):
                def fn(**kwargs):
                    seen[name] = kwargs
                    return json.dumps({"ok": True, "tool": name})
                return fn

        W.load_mcp = lambda: loaded.append(True) or FakeMCP()
        try:
            # (a) parent act refuses rc=3 for the out-of-domain action.
            rc_act, pay_act, txt_act, _ = self.wf("act", "--project", str(self.project),
                                                  "--action", "apk.info")
            self.assertEqual(rc_act, 3, txt_act[:600])
            self.assertIn("capability_gap", pay_act.get("reason", ""))
            # (b) the same forged envelope must be refused by the child as well.
            ctx = W.derive_context(self.project, "apk.info")
            digest = W._payload_digest(ctx, {})
            envelope = {"schema": "seep-workflow-envelope/1",
                        "nonce": W._envelope_digest(digest),
                        "digest": digest, "context": ctx}
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_child = W.child_main({"envelope": envelope, "args": {}})
            self.assertEqual(rc_child, 3, buf.getvalue()[:600])
            self.assertIn("pack.tools", buf.getvalue())
            self.assertEqual(loaded, [], "a domain-gap refusal must not load the MCP module")
            self.assertEqual(seen, {}, "no tool function may be reached")
            # (c) the child always validates against the *Manager* domain set, never
            #     against a domain claim carried in the envelope.
            ctx_other = dict(ctx, action="r2.disasm")
            args_other = {"target": "main"}
            digest = W._payload_digest(ctx_other, args_other)
            envelope_other = {"schema": "seep-workflow-envelope/1",
                              "nonce": W._envelope_digest(digest), "digest": digest,
                              "context": ctx_other}
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_other = W.child_main({"envelope": envelope_other,
                                         "args": args_other})
            self.assertEqual(rc_other, 3, buf.getvalue()[:600])
            self.assertEqual(loaded, [], "r2.disasm is not in firmware-iot pack.tools")
        finally:
            W.load_mcp = real_loader

    def test_child_re_reads_effects_and_refuses_unregistered_tools(self):
        """子进程现读 tool-effects.json：放宽 effects 也不能解锁未登记动作。

        `seep_r2_cmd` 在 effects 里是 `mutates_target=true`（上界），且在 ACTIONS 里
        未登记（capability_gap）。这里断言：即使把伪造动作硬塞进信封 + 把 effects
        全改成 false，child 也不会执行 —— 因为 `admit_action` 用的是磁盘上的 effects
        与 ACTIONS，而不是信封里的任何声明。
        """
        import project_workflow as W

        self.start(target=self.apk)
        loaded = []
        real_loader, real_effects = W.load_mcp, W.load_effects
        W.load_mcp = lambda: loaded.append(True) or object()
        # 模拟“effects 被改宽”：所有五项全 false —— 仍不能把未登记动作变成可执行。
        W.load_effects = lambda: {k: {f: False for f in
                                      ("mutates_target", "writes_filesystem",
                                       "executes_foreign_code", "touches_network",
                                       "may_discard_data")}
                                  for k in ("seep_r2_cmd", "seep_apk_info",
                                            "seep_r2_disasm")}
        try:
            ctx = W.derive_context(self.project, "r2.cmd")
            digest = W._payload_digest(ctx, {"command": "afl"})
            envelope = {"schema": "seep-workflow-envelope/1",
                        "nonce": W._envelope_digest(digest), "digest": digest,
                        "context": ctx}
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = W.child_main({"envelope": envelope, "args": {"command": "afl"}})
            self.assertEqual(rc, 4, buf.getvalue()[:600])
            self.assertIn("不在审核映射表内", buf.getvalue())
            self.assertEqual(loaded, [], "an unregistered action must never load MCP")
        finally:
            W.load_mcp, W.load_effects = real_loader, real_effects

    def test_replay_after_state_change_is_refused_and_repeat_is_recheckable(self):
        """主对话裁定 §2：信封不是凭据，也不声明“一次性”。

        * 同一状态下的重复只读动作**允许** —— 但每次都重新 check/admit，并产生
          **独立 capture**（不是同一个 capture 被复用）。
        * 状态变 WAIT_USER / refs / route / generation 后，同一信封重放必须拒。
        """
        import project_workflow as W

        started = self.start(target=self.apk)
        cap = self.capture_dir(started["run"])
        ctx = W.derive_context(self.project, "meta.fingerprint")
        digest = W._payload_digest(ctx, {})
        envelope = {"schema": "seep-workflow-envelope/1",
                    "nonce": W._envelope_digest(digest), "digest": digest,
                    "context": ctx}
        payload = {"envelope": envelope, "args": {}}
        results = []
        for _ in range(2):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = W.child_main(json.loads(json.dumps(payload)))
            body = json.loads(buf.getvalue())
            results.append((rc, body.get("status")))
        self.assertEqual(results, [(0, "ok"), (0, "ok")],
                         "same-state repeat must be re-admitted, not blocked by a nonce")
        # Each `act` (parent path) writes its own capture: two independent captures.
        before = len(list(cap.glob("*.json")))
        self.wf_ok("act", "--project", str(self.project), "--action", "meta.fingerprint")
        self.wf_ok("act", "--project", str(self.project), "--action", "meta.fingerprint")
        self.assertEqual(len(list(cap.glob("*.json"))), before + 2,
                         "every repeat produces its own capture")
        # Now change the Manager state (WAIT_USER) and replay the *same* envelope.
        run_cli(MANAGER, ["wait", "--project", str(self.project), "--option", "A=继续",
                          "--option", "B=停", "--monitor", "m", "--guarantee", "g",
                          "--expected-input", "A/B", "--json"])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = W.child_main(json.loads(json.dumps(payload)))
        self.assertEqual(rc, 2, buf.getvalue()[:600])
        self.assertIn("WAIT_USER", buf.getvalue())

    def test_non_finite_and_oversized_integers_are_structured_refusals(self):
        """FIXED (was refuted §3.3): inf/NaN/1e999/10**400 are structured, no traceback.

        `int_in_range` only caught `(TypeError, ValueError)`, so `int(float('inf'))`
        raised `OverflowError` out of the MCP tool and out of `act` (rc=1 + traceback).
        Now both entries share one implementation (`seep_contract.int_range_error`) and
        every non-finite/oversized value is a structured `invalid_parameters` / rc=4.
        """
        import importlib.util as _ilu
        spec = _ilu.spec_from_file_location(
            "seep_mcp_server_ints", os.path.join(ROOT, "Tool", "mcp", "seep_mcp_server.py"))
        module = _ilu.module_from_spec(spec)
        spec.loader.exec_module(module)
        recorded = []
        real_run_cmd = module._run_cmd
        module._run_cmd = lambda cmd, **_k: (recorded.append(list(cmd)), "spy")[1]
        odd_values = [float("inf"), float("-inf"), float("nan"), 1e309,
                      10 ** 400, -(10 ** 400)]
        try:
            for value in odd_values:
                for kwargs in ({"lines": value}, {"limit_tokens": value}):
                    out = module.seep_r2_disasm(binary_path=str(self.apk), **kwargs)
                    payload = json.loads(out)
                    self.assertEqual(payload.get("error"), "invalid_parameters",
                                     (value, kwargs, out[:200]))
            # positive control: normal ints and numeric strings still reach r2.
            for good in (60, "60", 10000):
                recorded.clear()
                module.seep_r2_disasm(binary_path=str(self.apk), lines=good)
                self.assertEqual(len(recorded), 1, good)
        finally:
            module._run_cmd = real_run_cmd
        self.assertEqual(recorded[-1][recorded[-1].index("-c") + 1],
                         "aaa; pdf @ main")
        # workflow entry: the same values must be rc=4 + structured JSON, no traceback.
        self.wf_ok("start", "--project", self.project, "--quote", "协议插件逆向",
                   "--target", str(self.apk), "--primary-domain", "protocol-plugin",
                   "--route-id", "R1", "--p", "0.4", "--hours", "2-4h",
                   "--fail", "原件被改", "--evidence-goal", "画像", "--json")
        # `lines` is a plain int: non-finite/oversized values must be rc=4 + 整数原因.
        for raw in ('{"target": "main", "lines": 1e999}',
                    '{"target": "main", "lines": Infinity}',
                    '{"target": "main", "lines": -Infinity}',
                    '{"target": "main", "lines": NaN}'):
            rc, payload, text, err = self.wf("act", "--project", str(self.project),
                                             "--action", "r2.disasm",
                                             "--args-json", raw)
            self.assertEqual(rc, 4, "%s -> rc=%s %s" % (raw, rc, text[:400]))
            self.assertNotIn("Traceback", err or "")
            self.assertNotIn("OverflowError", err or "")
            self.assertIn("整数", payload.get("reason", ""), text[:400])
        # `limit_tokens` 是公开整数参数，不能按凭据键拒绝。
        # 主对话裁定：NaN 应在执行前按参数错误结构化拒绝（rc=4）。
        # 此判据更正须由另一只读会话独立验证，不能据编辑者自测签绿。
        rc, payload, text, err = self.wf("act", "--project", str(self.project),
                                         "--action", "r2.disasm", "--args-json",
                                         '{"target": "main", "limit_tokens": NaN}')
        self.assertEqual(rc, 4, text[:400])
        self.assertIn("整数", payload.get("reason", ""), text[:400])
        self.assertNotIn("Traceback", err or "")
        self.assertNotIn("OverflowError", err or "")
        self.assertFalse(payload.get("ok"))
        self.assertNotIn("executed", payload)

    def test_shared_validators_are_the_single_source(self):
        """两侧校验器必须**同一份实现**（不是"两份看起来一样"）。

        `project_workflow.r2_target_error` / `kb_path_error` / `int_arg_error` /
        `r2_command_error` 都委托 `Tool/mcp/seep_contract.py`；契约模块里的
        `r2_readonly_command_check` 是 `seep_r2_cmd` 的唯一判定来源。
        """
        import importlib.util as _ilu
        import project_workflow as W
        contract = W.contract_module()
        self.assertIsNotNone(contract, "the contract module must be importable")
        self.assertTrue(hasattr(contract, "int_range_error"))
        self.assertTrue(hasattr(contract, "r2_readonly_command_check"))
        # workflow must not carry its own copy of the r2 command grammar
        self.assertFalse(hasattr(W, "R2_READONLY_HEADS"),
                         "the command grammar lives in seep_contract only")
        for target in ("main", "a;b", "main+0x10", "0x123", ".", "a" * 200):
            self.assertEqual(W.r2_target_error(target),
                             contract.r2_target_error(target), target)
        for value in (60, "60", 1.5, float("inf"), float("nan"), 10 ** 400, True):
            self.assertEqual(W.int_arg_error("lines", value, 1, 10000),
                             contract.int_range_error("lines", value, 1, 10000), value)
        spec = _ilu.spec_from_file_location(
            "seep_mcp_server_shared",
            os.path.join(ROOT, "Tool", "mcp", "seep_mcp_server.py"))
        module = _ilu.module_from_spec(spec)
        spec.loader.exec_module(module)
        for command in ("afl", "!id", "pd 20 > out.txt", "aaa; C*", "w hello",
                        "iS.", "afl~sym", "r 100"):
            self.assertEqual(module._r2_write_tokens(command) != [],
                             contract.r2_readonly_command_check(command)[0] != "",
                             command)

    def test_act_rejects_overridden_target_parameter_names(self):
        """The public `act` path refuses target-parameter overrides (positive control)."""
        started = self.start(target=self.apk)
        cap = self.capture_dir(started["run"])
        before = snapshot(cap)
        victim = self.base / "victim.txt"
        victim.write_bytes(b"outside")
        victim_sha = digest(victim)
        for extra in ({"binary_path": str(victim)}, {"apk_path": str(victim)},
                      {"file_path": str(victim)}, {"target_path": str(victim)}):
            rc, payload, text, _err = self.wf("act", "--project", str(self.project),
                                              "--action", "apk.info", "--args-json",
                                              json.dumps(extra))
            self.assertEqual(rc, 4, "%s -> rc=%s %s" % (list(extra), rc, text[:400]))
            self.assertIn("未知参数", payload.get("reason", ""))
        self.assertEqual(snapshot(cap), before)
        self.assertEqual(digest(victim), victim_sha, "no file may be parsed/modified")

    # ---- 10. real read-only MCP function as positive control ------------
    def test_real_readonly_mcp_action_on_synthetic_apk(self):
        self.start(target=self.apk)
        payload = self.wf_ok("act", "--project", str(self.project), "--action", "apk.info")
        self.assertTrue(payload["evidence_registered"])
        capture = json.loads((self.project / payload["capture"]).read_text(encoding="utf-8"))
        self.assertEqual(capture["method"], "seep_mcp_server.seep_apk_info")
        self.assertEqual(capture["rc"], 0)
        self.assertTrue(capture["stdout"] and capture["raw_size"] > 0,
                        "full stdout/raw capture must be kept")
        self.assertTrue(capture["argv"] and capture["argv"][0].endswith(("python", "python.exe",
                                                                        "python3")))
        self.assertIn("classes.dex", capture["stdout"])
        self.assertEqual(Path(capture["params"].get("apk_path")),
                         self.target_file().resolve())
        self.assertEqual(payload["outcome"], "succeeded")
        self.assertIn("pending", payload["acceptance"])

    def test_kb_route_works_without_external_binary(self):
        # firmware-iot only declares KB tools: the KB route stays available even
        # though there is no external binary for that domain. A hit must be a real
        # hit: `hits` non-empty, not merely a `near_miss` suggestion.
        self.wf_ok("start", "--project", str(self.project),
                   "--quote", "路由器固件怎么脱壳", "--target", str(self.apk),
                   "--primary-domain", "firmware-iot", "--route-id", "R1",
                   "--p", "0.4", "--hours", "2-4h", "--fail", "原件被改",
                   "--evidence-goal", "KB 命中路径", "--json")
        payload = self.wf_ok("act", "--project", str(self.project), "--action", "kb.search",
                             "--args-json", json.dumps({"query": "固件 脱壳", "limit": 3}))
        self.assertTrue(payload["evidence_registered"])
        capture = json.loads((self.project / payload["capture"]).read_text(encoding="utf-8"))
        self.assertEqual(capture["method"], "seep_mcp_server.seep_kb_search")
        self.assertEqual(capture["rc"], 0)
        body = json.loads(json.loads(capture["stdout"])["text"])
        self.assertIsInstance(body, list, "kb.search returns a hit list")
        self.assertTrue(body, "KB route must produce a real hit, not near_miss only")
        self.assertTrue(body[0].get("path"))
        self.assertTrue(body[0].get("matched_terms") or body[0].get("matched_bigrams"),
                        "a real hit must report why it matched")

    def test_kb_zero_match_is_not_succeeded_and_cannot_back_a_route(self):
        """FIXED (was refuted): a zero-hit KB search is no longer `succeeded`.

        `seep_kb_search` used to return `ok` for an empty hit list, so the entry
        recorded outcome=succeeded with evidence that proves nothing about the
        question. Now the tool returns status=zero_match (ok=false) and the entry
        records outcome=failed with outcome_reason=zero_match: the action *executed*
        (raw evidence kept) but it is not counted as a route result. The hit list is
        checked through the real MCP call, not by looking for a stdout substring.
        """
        self.wf_ok("start", "--project", str(self.project),
                   "--quote", "路由器固件怎么脱壳", "--target", str(self.apk),
                   "--primary-domain", "firmware-iot", "--route-id", "R1",
                   "--p", "0.4", "--hours", "2-4h", "--fail", "原件被改",
                   "--evidence-goal", "KB 命中路径", "--json")
        rc, payload, text, _err = self.wf("act", "--project", str(self.project),
                                          "--action", "kb.search", "--args-json",
                                          json.dumps({"query": "synthetic-no-hit-zqxv-<&>-000",
                                                      "limit": 1}))
        self.assertEqual(rc, 2, text[:600])
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["executed"])
        self.assertFalse(payload["has_result"])
        self.assertEqual(payload["outcome"], "failed")
        self.assertEqual(payload["outcome_reason"], "zero_match")
        capture = json.loads((self.project / payload["capture"])
                             .read_text(encoding="utf-8"))
        self.assertEqual(capture["outcome"], "failed")
        self.assertEqual(capture["outcome_reason"], "zero_match")
        self.assertFalse(capture["has_result"])
        self.assertTrue(capture["raw_size"] > 0, "raw evidence is still kept")
        inner = json.loads(json.loads(capture["stdout"])["text"])
        self.assertIsInstance(inner, dict)
        self.assertEqual(inner.get("status"), "zero_match")
        self.assertFalse(inner.get("ok"))
        self.assertEqual(inner.get("hits"), [])
        events = [json.loads(x) for x in
                  (self.project / "manager-events.jsonl").read_text(encoding="utf-8")
                  .splitlines() if x.strip()]
        attempts = [e for e in events if e["event_type"] == "attempt"]
        self.assertTrue(attempts, "the executed-but-no-result step is still recorded")
        self.assertEqual(attempts[-1]["payload"]["attempt"]["outcome"], "failed")

    def test_r2_readonly_analysis_is_available_not_permanently_refused(self):
        # Requirement B: read-only r2 analysis is a first-class mapped action, not a
        # blanket ban. r2.disasm only runs radare2 read commands; r2.cmd (arbitrary
        # r2 command strings) stays unregistered.
        r2 = r2_binary()
        if not r2:
            self.skipTest("UNVERIFIED: radare2 absent — r2 read-only admission not exercised")
        elf = self.base / "sample.elf"
        elf.write_bytes(make_elf())
        self.wf_ok("start", "--project", str(self.project), "--quote", "分析这个 ELF",
                   "--target", str(elf), "--primary-domain", "pwn-crypto", "--route-id", "R1",
                   "--p", "0.5", "--hours", "1h", "--fail", "读不出结构",
                   "--evidence-goal", "二进制只读画像", "--json")
        payload = self.wf_ok("act", "--project", str(self.project), "--action", "r2.disasm",
                             "--args-json", json.dumps({"target": "entry0",
                                                        "output_mode": "full"}))
        capture = json.loads((self.project / payload["capture"]).read_text(encoding="utf-8"))
        self.assertEqual(capture["method"], "seep_mcp_server.seep_r2_disasm")
        self.assertEqual(capture["admission"]["coverage"],
                         "reviewed-readonly-mapping+effects-declared")
        self.assertTrue(capture["admission"]["executes_foreign_code"])
        stdout = capture["stdout"].lower()
        self.assertNotIn("unknown or unsupported arch", stdout,
                         "a bogus synthetic ELF must not be reported as a successful parse")
        self.assertNotIn("[error]", stdout)
        self.assertEqual(payload["outcome"], "succeeded")
        self.assertTrue(capture["stdout"].strip())
        rc, payload, text, _err = self.wf("act", "--project", str(self.project),
                                          "--action", "r2.cmd")
        self.assertEqual(rc, 4, "arbitrary r2 command strings must stay unregistered")
        self.assertIn("capability_gap", payload.get("reason", ""))

    # ---- 11. stale target/refs/generation refused before execution ------
    def test_stale_target_refused_before_execution(self):
        started = self.start(target=self.apk)
        cap = self.capture_dir(started["run"])
        before = snapshot(cap)
        target = self.target_file()
        target.write_bytes(target.read_bytes() + b"tampered")
        rc, payload, text, _err = self.wf("act", "--project", str(self.project),
                                          "--action", "meta.fingerprint")
        self.assertEqual(rc, 2, text[:600])
        self.assertIn("哈希", payload.get("reason", ""))
        self.assertEqual(snapshot(cap), before)
        self.assertFalse(payload.get("executed"))
        self.assertNotIn("evidence_id", payload)
        self.assertEqual(list(self.evidence_dir().glob("*.json"))
                         if self.evidence_dir().exists() else [], [])

    def test_wrong_refs_and_generation_are_refused_by_the_gate_before_execution(self):
        started = self.start(target=self.apk)
        cap = self.capture_dir(started["run"])
        before = snapshot(cap)
        import manager_state as M
        events, state = M.current_context(self.project)
        refs = dict(state["references"])
        good_sha = state["target_sha256"]
        route_id = state["selected_route_id"]
        cases = (
            ("wrong generation", refs, route_id, good_sha, "GEN-not-current"),
            ("wrong target hash", refs, route_id, "0" * 64, state["generation_id"]),
            ("wrong refs", dict(refs, run_id="run-not-this-one"), route_id, good_sha,
             state["generation_id"]),
            ("wrong route", refs, "R-not-selected", good_sha, state["generation_id"]),
        )
        for label, r, route, sha, gen in cases:
            with self.assertRaises(M.ManagerError, msg=label):
                M.check_action(self.project, r, route, sha, gen)
        self.assertEqual(snapshot(cap), before, "gate-only refusals write no capture")
        # The entry always passes the live refs/generation, so the same act succeeds
        # and produces exactly one capture + one attempt.
        payload = self.wf_ok("act", "--project", str(self.project),
                             "--action", "meta.fingerprint")
        self.assertEqual(payload["generation_id"], state["generation_id"])
        self.assertEqual(payload["references"], refs)
        self.assertEqual(len(list(cap.glob("*.json"))), len(before) + 1)

    # ---- 12. post-execution target change => rc=5, not accepted ---------
    def test_target_changed_after_execution_is_not_accepted(self):
        self.start(target=self.apk)
        import project_workflow as W
        real = W.run_action
        target_file = self.target_file()

        def tampering(root, action, args, timeout):
            result = real(root, action, args, timeout)
            target_file.write_bytes(target_file.read_bytes() + b"post-execution change")
            return result

        argv = ["act", "--project", str(self.project), "--action", "meta.fingerprint", "--json"]
        buf = io.StringIO()
        W.run_action = tampering
        try:
            with contextlib.redirect_stdout(buf):
                rc = W.main(argv)
        finally:
            W.run_action = real
        payload = json.loads(buf.getvalue())
        self.assertEqual(rc, 5, buf.getvalue()[:600])
        self.assertTrue(payload["executed"])
        self.assertFalse(payload["evidence_accepted"])
        self.assertTrue(payload.get("toctou"))
        self.assertTrue((self.project / payload["capture"]).is_file(), "capture is kept")
        evidence_dir = self.project / "versions" / "1.0" / "evidence"
        self.assertEqual(list(evidence_dir.glob("*.json")) if evidence_dir.exists() else [], [],
                         "an unacceptable capture must never become evidence")
        events = (self.project / "manager-events.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("version target stale", events)
        self.assertNotIn('"attempt"', events)
        self.assertNotIn("evidence_id", payload)
        # The post-execution capture must record the *actual* (changed) hash, not the
        # declared one, so the retained artefact is honest about what happened.
        capture = json.loads((self.project / payload["capture"]).read_text(encoding="utf-8"))
        self.assertNotEqual(capture["target_sha256"], capture["pre_target_sha256"])
        self.assertEqual(capture["target_sha256"], digest(target_file))
        self.assertEqual(capture["outcome"], "failed")
        self.assertTrue(capture["toctou"])

    def test_manager_head_change_during_execution_is_not_accepted(self):
        """If a manager ledger event lands *during* execution, the result is rc=5."""
        self.start(target=self.apk)
        import project_workflow as W

        real = W.run_action

        def racing(root, action, args, timeout):
            result = real(root, action, args, timeout)
            # A second candidate route is a legitimate append-only manager event: it
            # advances ledger_head without touching refs/route/generation/target.
            proc = subprocess.run([child_python(), "-B", "-X", "utf8", MANAGER, "plan",
                                   "--project", str(self.project), "--route-id", "R2",
                                   "--p", "0.5", "--hours", "1h", "--fail", "x",
                                   "--evidence-goal", "y", "--json"],
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", env=CHILD_ENV, cwd=ROOT)
            self.assertEqual(proc.returncode, 0, proc.stdout[:400] + proc.stderr[:400])
            return result

        buf = io.StringIO()
        W.run_action = racing
        try:
            with contextlib.redirect_stdout(buf):
                rc = W.main(["act", "--project", str(self.project),
                             "--action", "meta.fingerprint", "--json"])
        finally:
            W.run_action = real
        payload = json.loads(buf.getvalue())
        self.assertEqual(rc, 5, buf.getvalue()[:800])
        self.assertFalse(payload["evidence_accepted"])
        self.assertTrue(payload.get("toctou"))
        self.assertTrue(any("ledger_head" in item for item in payload["toctou"]),
                        payload["toctou"])
        capture = json.loads((self.project / payload["capture"]).read_text(encoding="utf-8"))
        self.assertTrue(capture["ledger_diverged"])
        self.assertEqual(list(self.evidence_dir().glob("*.json"))
                         if self.evidence_dir().exists() else [], [])

    def test_dry_run_admits_without_executing_or_writing(self):
        started = self.start(target=self.apk)
        cap = self.capture_dir(started["run"])
        before = snapshot(cap)
        payload = self.wf_ok("act", "--project", str(self.project), "--action", "apk.info",
                             "--dry-run")
        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["admission"]["coverage"],
                         "reviewed-readonly-mapping+effects-declared")
        self.assertEqual(payload["check_action"]["scope"], "manager-snapshot-only")
        self.assertFalse(payload["check_action"]["globally_enforced"])
        self.assertEqual(snapshot(cap), before, "dry-run must not write capture")
        self.assertNotIn("evidence_id", payload)

    # ---- 13. status merges project + manager ---------------------------
    def test_status_blocked_when_manager_or_project_blocked(self):
        self.start(target=self.apk)
        ok = self.wf_ok("status", "--project", str(self.project))
        self.assertTrue(ok["ok"])
        self.assertFalse(ok["blocked"])
        run_cli(os.path.join(HERE, "manager_state.py"),
                ["wait", "--project", str(self.project), "--option", "A=继续",
                 "--option", "B=停", "--monitor", "m", "--guarantee", "g",
                 "--expected-input", "A/B", "--json"])
        rc, blocked, text, _err = self.wf("status", "--project", str(self.project), "--json")
        self.assertEqual(rc, 2, text[:400])
        self.assertFalse(blocked["ok"])
        self.assertTrue(blocked["blocked"])
        self.assertTrue(blocked["manager"]["blocked"])
        # project-side block: tamper the target file
        run_cli(os.path.join(HERE, "manager_state.py"),
                ["answer", "--project", str(self.project), "--choice", "A", "--json"])
        self.target_file().write_bytes(b"changed")
        rc, blocked, text, _err = self.wf("status", "--project", str(self.project), "--json")
        self.assertEqual(rc, 2, text[:400])
        self.assertFalse(blocked["ok"])
        self.assertTrue(blocked["project"]["blocked"])
        self.assertTrue(blocked["project"]["reasons"])

    # ---- 14. legacy case is read-only -----------------------------------
    def test_legacy_case_remains_byte_identical(self):
        started = self.start(target=self.apk)
        case_dir = self.base / "old-case"
        case_dir.mkdir()
        facts = case_dir / "facts.jsonl"
        facts.write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in [
            {"id": "F-1", "kind": "state", "state": {"target": "legacy.bin"}},
            {"id": "F-2", "kind": "claim", "claim": "legacy claim", "status": "hypothesis",
             "confidence": "inferred", "authority": "self-built", "evidence": ["log.txt"]},
        ]) + "\n", encoding="utf-8")
        (case_dir / "case.json").write_text(json.dumps({"id": "old-case"}), encoding="utf-8")
        before = snapshot(case_dir)
        payload = self.wf_ok("status", "--project", str(self.project), "--case", str(case_dir))
        legacy = payload["legacy_case"]
        self.assertTrue(legacy["read_only"])
        self.assertFalse(legacy["migrated"])
        self.assertTrue(legacy["bytes_unchanged"])
        self.assertEqual(snapshot(case_dir), before, "legacy case must not be migrated/overwritten")
        self.assertEqual(started["run"], payload["project"]["active_runs"][0])

    # ---- 15. enforcement scope is self-reported -------------------------
    def test_enforcement_scope_is_entry_only(self):
        started = self.start(target=self.apk)
        for payload in (self.wf_ok("status", "--project", str(self.project)),
                        self.wf_ok("classify", "--quote", "安卓APK 加固")):
            self.assertEqual(payload["enforcement_scope"], "workflow-entry-only")
            self.assertFalse(payload["globally_enforced"])
        act = self.wf_ok("act", "--project", str(self.project), "--action", "apk.info")
        self.assertEqual(act["enforcement_scope"], "workflow-entry-only")
        self.assertFalse(act["globally_enforced"])
        self.assertIn("globally_enforced=false", act["scope_note"])
        self.assertIn("host_wiring_required=true", act["scope_note"])
        self.assertIn("不经过它", act["scope_note"])
        capture = json.loads((self.project / act["capture"]).read_text(encoding="utf-8"))
        self.assertEqual(capture["enforcement_scope"], "workflow-entry-only")
        self.assertFalse(capture["globally_enforced"])
        self.assertEqual(capture["proof_level"], "structural+recorded_witness")
        help_text = subprocess.run([child_python(), "-B", "-X", "utf8", WF, "--help"],
                                   capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", env=CHILD_ENV).stdout
        help_flat = " ".join(help_text.split())
        help_compact = help_flat.replace(" ", "")
        self.assertIn("globally_enforced=false", help_flat)
        self.assertIn("--help", help_text)
        self.assertIn("workflow-entry-only", help_compact)
        self.assertIn("不执行目标", help_flat)
        # The entry never claims a host-wide lock or a global lease.
        self.assertNotIn("globally_enforced=true", help_flat)
        self.assertTrue(started["run"])

    # ---- 16. result vocabulary: zero_results / partial / error are distinct ----
    def test_workflow_outcome_vocabulary_separates_zero_partial_and_error(self):
        """主对话裁定 §3：zero_results 归“无结果”，partial 归“部分结果”，
        error/invalid/resource_constraint 保留真实原因；partial 绝不算 succeeded/完整验收。

        直接跑真实 `classify_outcome()`（不是字典断言），并确认 Manager attempt 仍用
        现 succeeded/failed 接口（不加 schema）。
        """
        import project_workflow as W

        spec = {"kind": "mcp", "tool": "seep_pcap_extract"}
        cases = {
            # status              rc  ok     has_result  outcome      class
            "zero_results": (0, False, False, "failed", "no_result"),
            "zero_match": (0, False, False, "failed", "no_result"),
            "partial": (0, False, True, "failed", "partial"),
            "error": (1, False, False, "failed", "error"),
            "invalid": (1, False, False, "failed", "error"),
            "resource_constraint": (0, False, False, "failed", "no_result"),
            "unknown": (0, False, False, "failed", "no_result"),
            "ok": (0, True, True, "succeeded", "ok"),
        }
        for status, (rc, tool_ok, has_result, outcome, klass) in cases.items():
            with self.subTest(status=status):
                result = {"tool_status": status, "rc": rc, "tool_ok": tool_ok,
                          "tool_payload_ok": tool_ok, "tool_has_result": has_result}
                got_outcome, reason = W.classify_outcome(spec, result)
                self.assertEqual(got_outcome, outcome, (status, reason))
                if status in ("error", "invalid"):
                    # 工具/参数错误的真实原因必须原样保留（前缀 tool_error: 是既有格式）
                    self.assertEqual(reason, "tool_error:%s" % status, status)
                else:
                    self.assertEqual(reason, status, status)
                self.assertEqual(W.outcome_class(got_outcome, reason), klass, status)
                if status == "partial":
                    # 部分结果：有真实已解析 data 时 has_result 可 true，但绝不是 succeeded
                    self.assertTrue(W.action_has_result(got_outcome, reason, result))
                    self.assertNotEqual(got_outcome, "succeeded")
                    self.assertTrue(W.outcome_is_partial(reason))
                    self.assertFalse(W.outcome_is_no_result(reason))
                if status == "zero_results":
                    self.assertTrue(W.outcome_is_no_result(reason))
                    self.assertFalse(W.action_has_result(got_outcome, reason, result))
                if status in ("error", "invalid"):
                    self.assertFalse(W.outcome_is_no_result(reason),
                                     "工具错误不能被记成零命中")
                    self.assertFalse(W.outcome_is_partial(reason))
        # Manager attempt 状态接口不变（仍是既有 5 个词，不新增 schema）
        import manager_state as M
        self.assertIn("partial", "succeeded failed blocked partial".split())
        self.assertTrue(hasattr(M, "current_context"))

    def test_result_shapes_share_one_classification_rule(self):
        """同一个 `ok`/`status` 的结果，包在 str / list / tuple / TextContent 里判据一致。

        跑真实 `child_main()`（子进程入口函数本体），只把 `load_mcp` 换成返回这几种
        形状的 spy；不执行任何外部工具、不联网。
        """
        import project_workflow as W

        class TextContent(object):
            def __init__(self, text):
                self.text = text

        class FakeMCP(object):
            def __init__(self, value):
                self.value = value

            def seep_kb_search(self, **_kwargs):
                return self.value

        body_ok = json.dumps({"ok": True, "status": "ok", "has_result": True})
        body_zero = json.dumps({"ok": False, "status": "zero_results", "has_result": False})
        body_partial = json.dumps({"ok": False, "status": "partial", "has_result": True})
        shapes = {
            "str": lambda text: text,
            "list[str]": lambda text: [text],
            "tuple[str]": lambda text: (text,),
            "TextContent": lambda text: TextContent(text),
            "list[TextContent]": lambda text: [TextContent(text)],
        }
        self.wf_ok("start", "--project", str(self.project),
                   "--quote", "路由器固件怎么脱壳", "--target", str(self.apk),
                   "--primary-domain", "firmware-iot", "--route-id", "R1",
                   "--p", "0.4", "--hours", "2-4h", "--fail", "原件被改",
                   "--evidence-goal", "KB 命中", "--json")
        ctx = W.derive_context(self.project, "kb.search")
        args = {"query": "固件 脱壳"}
        envelope = {"schema": "seep-workflow-envelope/1",
                    "digest": W._payload_digest(ctx, args), "context": ctx}
        envelope["nonce"] = W._envelope_digest(envelope["digest"])
        real_loader = W.load_mcp

        def child_status(value):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                W.child_main({"envelope": envelope, "args": args})
            return json.loads(buf.getvalue())

        try:
            for label, wrap in shapes.items():
                for text, expect_ok, expect_status, expect_has in (
                        (body_ok, True, "ok", True),
                        (body_zero, False, "zero_results", False),
                        (body_partial, False, "partial", True)):
                    with self.subTest(shape=label, status=expect_status):
                        W.load_mcp = lambda value=wrap(text): FakeMCP(value)
                        payload = child_status(text)
                        self.assertEqual(payload["ok"], expect_ok, (label, payload))
                        self.assertEqual(payload["status"], expect_status, (label, payload))
                        self.assertEqual(payload.get("has_result"), expect_has,
                                         (label, payload))
                # ok=false 优先：同一个 body 里再塞一个成功状态也不得变成功。
                with self.subTest(shape=label, status="ok-false-priority"):
                    mixed = json.dumps({"ok": False, "status": "ok", "has_result": True})
                    W.load_mcp = lambda value=wrap(mixed): FakeMCP(value)
                    payload = child_status(mixed)
                    self.assertIs(payload["ok"], False, (label, payload))
                    # ok=false 优先：结构化 ok 为 false 时不得把状态改写成成功态
                    self.assertIsNot(payload.get("status"), "ok", (label, payload))
            marker = "Bea" + "rer " + "synthetic-diagnostic-0123456789"
            for channel in ("stdout", "stderr", "exception"):
                class DiagnosticMCP:
                    def seep_kb_search(self, **kwargs):
                        if channel == "exception":
                            raise ValueError("x" * 500 + " " + marker)
                        print(marker, file=sys.stderr if channel == "stderr" else sys.stdout)
                        return body_ok
                W.load_mcp = lambda: DiagnosticMCP()
                outer_err = io.StringIO()
                with contextlib.redirect_stderr(outer_err):
                    payload = child_status(None)
                self.assertEqual(payload["status"], "sensitive_output_blocked")
                self.assertFalse(payload["ok"])
                self.assertNotIn(marker, json.dumps(payload) + outer_err.getvalue())
        finally:
            W.load_mcp = real_loader

    def test_partial_capture_chain_keeps_raw_trace_and_is_not_full_acceptance(self):
        """partial 走**真实** workflow 分类 + 真实 capture/evidence/attempt 链。

        用真实 `seep_pcap_extract`（只读本地合成 pcap，不联网、不 spawn 真 tshark），
        只把 `_process_tree.run` 换成“第 1 次 rc=0、第 2 次 rc=1”的 spy；summary 模式因此
        产生 status=partial。子进程边界用 in-process 的 `child_main`（同样的受控信封 +
        同样的 `_action_result`/capture/evidence/attempt 代码），因此断言的是真实链路：
        executed=true、has_result=true（真有已解析 data）、outcome≠succeeded、
        capture 保留原 pcap 的 stdout/stderr/argv/rc，且 partial 不算完整验收。
        """
        import project_workflow as W

        pcap = self.base / "synthetic.pcap"
        pcap.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.wf_ok("start", "--project", str(self.project),
                   "--quote", "分析这个 pcap 抓包里的协议流量", "--target", str(pcap),
                   "--primary-domain", "protocol-plugin", "--route-id", "R1",
                   "--p", "0.4", "--hours", "2-4h", "--fail", "原件被改",
                   "--evidence-goal", "TCP 会话画像", "--json")

        import importlib.util as _ilu
        spec = _ilu.spec_from_file_location(
            "seep_mcp_server_partial",
            os.path.join(ROOT, "Tool", "mcp", "seep_mcp_server.py"))
        module = _ilu.module_from_spec(spec)
        spec.loader.exec_module(module)

        conv = ("10.0.0.1:1234  <-> 10.0.0.2:80   5   3   1200   800   1.5\n")
        calls = []

        class Proc(object):
            def __init__(self, rc, out, err):
                self.returncode, self.stdout, self.stderr = rc, out, err

        def fake_run(argv, **kwargs):
            calls.append(list(argv))
            if len(calls) == 1:
                return Proc(0, conv, "")
            return Proc(1, "", "tshark: read error")

        class FakeMCP(object):
            seep_pcap_extract = staticmethod(module.seep_pcap_extract)

        real_which = module.shutil.which
        real_spawn = W._spawn_child
        real_loader = W.load_mcp

        def inprocess_spawn(envelope, args, timeout):
            """子进程边界的 spy：跑真实 child_main，只把 stdout 当子进程输出收回。"""
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = W.child_main({"envelope": envelope, "args": args})
            out = buf.getvalue()
            payload = {}
            for line in reversed(out.splitlines()):
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    payload = json.loads(line)
                    break
            return {"rc": rc, "timeout": False, "stdout": out, "stderr": "",
                    "elapsed_s": 0.0, "payload": payload}

        class FakeProcessTree(object):
            """Replace the MCP execution boundary without changing global subprocess."""

            def __init__(self, runner):
                self.run = runner

        real_process_tree = module._process_tree
        module._process_tree = FakeProcessTree(fake_run)
        module.shutil.which = lambda name: "/usr/bin/tshark" if name == "tshark" else None
        W.load_mcp = lambda: FakeMCP()
        W._spawn_child = inprocess_spawn
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = W.main(["act", "--project", str(self.project),
                              "--action", "pcap.extract", "--args-json",
                              json.dumps({"mode": "summary", "max_rows": 10}), "--json"])
            text = buf.getvalue()
        finally:
            module._process_tree = real_process_tree
            module.shutil.which = real_which
            W._spawn_child = real_spawn
            W.load_mcp = real_loader

        payload = json.loads(text)
        self.assertEqual(rc, 2, text[:800])
        self.assertTrue(payload["executed"])
        self.assertNotEqual(payload["outcome"], "succeeded")
        self.assertEqual(payload["outcome_reason"], "partial")
        self.assertEqual(payload["outcome_class"], "partial")
        # pcap 契约把 partial 的 has_result 定为 false（部分结果不等于“有可用结果”）；
        # workflow **不替它把 false 改成 true**，只把“部分是部分”如实分类。
        self.assertIs(payload["has_result"], False)
        self.assertFalse(payload["ok"], "partial 不能算成功/完整验收")
        self.assertIn("pending", payload["acceptance"])
        self.assertTrue(payload["attempt_recorded"])
        self.assertEqual(len(calls), 2, "summary 走两次 tshark（spy 记录）")
        capture = json.loads((self.project / payload["capture"])
                             .read_text(encoding="utf-8"))
        # 子进程 rc 原样保留：工具 ok=false → child rc=1（partial 不会被包装成 rc=0 成功）
        self.assertEqual(capture["rc"], 1)
        self.assertEqual(capture["outcome"], "failed")
        self.assertEqual(capture["outcome_reason"], "partial")
        self.assertEqual(capture["outcome_class"], "partial")
        self.assertIs(capture["has_result"], False)
        self.assertTrue(capture["stdout"] and capture["raw_size"] > 0,
                        "原始执行流必须保留")
        inner = json.loads(json.loads(capture["stdout"])["text"])
        self.assertEqual(inner["status"], "partial")
        self.assertEqual(len(inner["executions"]), 2)
        self.assertEqual(inner["executions"][0]["rc"], 0)
        self.assertEqual(inner["executions"][1]["rc"], 1)
        self.assertEqual(inner["executions"][1]["stderr"], "tshark: read error")
        self.assertEqual(inner["executions"][0]["argv"][:2], ["/usr/bin/tshark", "-n"])
        self.assertTrue(inner["executions"][0]["argv"][3].endswith(".pcap"))
        self.assertTrue(inner["tcp_conversations"], "部分数据仍要能看见")
        raw = (self.project / payload["capture"]).with_name(capture["raw_capture"])
        self.assertIn("tshark: read error", raw.read_text(encoding="utf-8"))
        # partial 不得自动通过验收
        acceptance = json.loads((self.project / "versions" / "1.0" / "acceptance.json")
                                .read_text(encoding="utf-8"))
        self.assertEqual(acceptance.get("items"), [])


def wf_replan(project: Path):
    return run_cli(os.path.join(HERE, "manager_state.py"),
                   ["replan", "--project", str(project), "--reason",
                    "换成只读哈希路线，避免依赖外部解析器", "--new-route-id", "R2",
                    "--route-id", "R2", "--p", "0.6", "--hours", "1h",
                    "--fail", "目标读不出或哈希不稳", "--evidence-goal",
                    "目标哈希与大小（只读）", "--json"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
