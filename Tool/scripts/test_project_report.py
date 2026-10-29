#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""End-to-end regression for ``project_report.py`` (report_id / five-section report).
Run: python -B Tool/scripts/test_project_report.py

Everything happens in a TemporaryDirectory through the *real* CLIs
(``project_state.py`` and ``project_report.py``).  No target is executed, no
network, no install, no git commit.

The core handoff hook is now **merged into the real project_state.py**, so these
tests drive the real CLI directly (no staged patch, no dependency on any
gitignored ``work/`` artifact).  Damage/wiring probes copy the *wired* source into
a temporary tree instead of writing the real file; the only source assertion is
"unchanged before vs after this run".
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "Tool/scripts/project_state.py"
REPORT = ROOT / "Tool/scripts/project_report.py"
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
SECTIONS = ("结论", "已确认", "仍未知", "下一步", "复查")
OLD = b"MZ-old-target-A" * 8
NEW = b"MZ-new-target-B" * 8
LAST = b"MZ-last-target-C" * 8
# Synthetic sentinel strings only: never a real credential.
SENTINEL_PASSWORD = "synthetic-sentinel-9f3a"
SENTINEL_BEARER = "synthetic-bearer-value-0001"


def read(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))

def write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

def sha(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def cli(script: Path, *args) -> tuple[int, dict, str]:
    result = subprocess.run([sys.executable, "-B", str(script), *map(str, args)],
                            cwd=str(ROOT), env=ENV, capture_output=True, text=True,
                            encoding="utf-8", timeout=120)
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        raise AssertionError((script.name, result.returncode,
                              result.stdout[-3000:], result.stderr[-3000:]))
    if result.stderr:
        raise AssertionError((script.name, result.stderr[-3000:]))
    return result.returncode, payload, result.stdout


def cli_raw(script: Path, *args) -> subprocess.CompletedProcess:
    """Run without requiring JSON on stdout (argparse rejections are rc2 + usage)."""
    return subprocess.run([sys.executable, "-B", str(script), *map(str, args)],
                          cwd=str(ROOT), env=ENV, capture_output=True, text=True,
                          encoding="utf-8", timeout=120)

class ReportChain(unittest.TestCase):
    """One temporary project: version 1.0, 1.1 (and 1.2 on demand)."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="seep-report-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.old = self.base / "old.bin"
        self.new = self.base / "new.bin"
        self.last = self.base / "last.bin"
        self.old.write_bytes(OLD)
        self.new.write_bytes(NEW)
        self.last.write_bytes(LAST)
        self.ok(self.p("init", "--project-id", "synthetic", "--target", self.old))
        self.ok(self.p("version", "--version", "1.1", "--parent", "1.0", "--target", self.new))
        self.capture("1.1", "probe.log", b"synthetic probe response: rc=0 (content is NOT success)\n")
        self.capture("1.1", "source.txt", b"synthetic verifier source note\n")
    # -- CLI wrappers -----------------------------------------------------
    def p(self, command, *args):
        return cli(STATE, command, "--project", self.project, *args)[:2]
    def r(self, command, *args):
        return cli(REPORT, command, "--project", self.project, *args)[:2]
    def r_full(self, command, *args):
        return cli(REPORT, command, "--project", self.project, *args)
    def ok(self, result):
        self.assertEqual(result[0], 0, result)
        self.assertTrue(result[1]["ok"], result)
        return result[1]
    def refused(self, result, needle=""):
        self.assertEqual(result[0], 2, result)
        self.assertFalse(result[1]["ok"], result)
        if needle:
            self.assertIn(needle, json.dumps(result[1], ensure_ascii=False), result)
        return result[1]
    # -- fixtures ---------------------------------------------------------
    def capture(self, version: str, name: str, payload: bytes) -> Path:
        path = self.project / "versions" / version / "capture" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path
    def start_run(self, version: str, run_id: str):
        return self.ok(self.p("run", "--version", version, "--run-id", run_id))
    def evidence(self, version: str, run_id: str, evidence_id: str, name: str):
        path = self.project / "versions" / version / "capture" / name
        return self.ok(self.p("evidence", "--version", version, "--run-id", run_id,
                              "--evidence-id", evidence_id,
                              "--target-sha256", read(self.project / "versions" / version
                                                      / "version.json")["sha256"],
                              "--path", "versions/%s/capture/%s" % (version, name),
                              "--sha256", sha(path), "--size", path.stat().st_size,
                              "--source", "versions/%s/capture/source.txt" % version,
                              "--how", "synthetic CLI probe"))
    def complete_run(self, version="1.1", run_id="run-a", evidence_id="ev-1"):
        self.start_run(version, run_id)
        self.evidence(version, run_id, evidence_id, "probe.log")
        self.ok(self.p("acceptance-define", "--version", version,
                       "--item", "probe:只读探测响应可逐条核对"))
        self.ok(self.p("acceptance-record", "--version", version, "--item-id", "probe",
                       "--result", "pass", "--evidence-ids", evidence_id,
                       "--verifier", "synthetic-verifier", "--how", "read-only probe",
                       "--run", run_id))
        self.ok(self.p("finish-run", "--version", version, "--run-id", run_id,
                       "--status", "completed", "--note", "synthetic"))
    def report_body(self, marker: str, extra_unknown: tuple[str, ...] = ()) -> bytes:
        lines = ["# 人工报告 %s" % marker, "",
                 "## 1 结论", "- 只写登记事实，不声称功能可用。", "- 证明上限见 manifest。", "",
                 "## 2 已确认", "- 证据 ev-1 已登记且原始文件哈希一致。",
                 "- 验收项 probe 由 synthetic-verifier 登记为 pass。", "",
                 "## 3 仍未知"]
        lines += ["- 未知项 %d：%s" % (i + 1, text)
                  for i, text in enumerate(extra_unknown or ("目标是否真的可用未验证",))]
        lines += ["", "## 4 下一步", "- 需要新的可复现检查。", "- 用新 report_id 记录新结果。", "",
                  "## 5 复查", "- `python Tool/scripts/project_report.py status --project .`",
                  "- 期望 fresh=true 且 stale 为空。", ""]
        return "\n".join(lines).encode("utf-8")
    def put_body(self, name: str, payload: bytes) -> str:
        path = self.project / "drafts" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return "drafts/%s" % name

class ReportBasics(ReportChain):
    def test_01_empty_project_has_no_report_state(self):
        self.refused(self.r("show", "--report-id", "r1"), "未在 reports/index.jsonl 登记")
        status = self.ok(self.r("status"))
        self.assertFalse(status["final_pointer"]["present"])
        self.assertEqual(status["reports"], [])
        self.assertFalse((self.project / "reports/final.json").exists())
    def test_02_generate_interim_then_final_and_show_consistency(self):
        self.complete_run()
        run_before = (self.project / "versions/1.1/runs/run-a/run.json").read_bytes()
        acceptance_before = (self.project / "versions/1.1/acceptance.json").read_bytes()
        old_manifest_before = (self.project / "versions/1.0/manifest.json").read_bytes()
        target_path = self.project / read(self.project / "versions/1.0/version.json")["local_path"]
        target_before = target_path.read_bytes()
        generated = self.ok(self.r("generate", "--report-id", "r1", "--version", "1.1",
                                   "--run-id", "run-a", "--kind", "interim",
                                   "--note", "synthetic interim"))
        self.assertTrue(generated["verification"]["fresh"], generated)
        body_path = self.project / "reports/r1/report.md"
        manifest_path = self.project / "reports/r1/manifest.json"
        self.assertEqual(generated["body"]["local_path"], "reports/r1/report.md")
        self.assertEqual(generated["body"]["sha256"], sha(body_path))
        # Integration facts are detected from the real source, not asserted.
        self.assertTrue(generated["core_handoff_wired"])
        self.assertFalse(generated["integration_pending"])
        self.assertTrue(generated["pending_scopes"])
        scopes = {row["scope"]: row["wired"] for row in generated["pending_scopes"]}
        self.assertEqual(scopes, {"workflow.close_status": True, "typed_assets": True,
                                  "archive_export_import": True,
                                  "report_claim_ledger": True})
        body = body_path.read_text(encoding="utf-8")
        for section in SECTIONS:
            self.assertIn(section, body)
        unknown = body.split("## 3 仍未知")[1].split("## 4 下一步")[0]
        self.assertGreaterEqual(len([x for x in unknown.splitlines() if x.strip()]), 2)
        self.assertIn("不代表整个 Goal 成功", body)
        self.assertIn("interim", body)
        manifest = read(manifest_path)
        self.assertEqual(manifest["body"]["sha256"], sha(body_path))
        self.assertEqual(manifest["body"]["size"], body_path.stat().st_size)
        self.assertEqual(manifest["target"]["sha256"],
                         read(self.project / "versions/1.1/version.json")["sha256"])
        self.assertEqual(len(manifest["target"]["sha256"]), 64)
        self.assertEqual(manifest["version_id"], "1.1")
        self.assertEqual(manifest["run_id"], "run-a")
        self.assertEqual(manifest["evidence"]["entries"][0]["evidence_id"], "ev-1")
        self.assertEqual(manifest["sources"]["tool"], "project_report.py")
        self.assertEqual(manifest["sources"]["params"]["run_id"], "run-a")
        self.assertTrue(manifest["sources"]["params_sha256"])
        self.assertEqual(manifest["acceptance"]["consumed_verified"], True)
        self.assertTrue(manifest["core_handoff"]["core_handoff_wired"])
        self.assertFalse(manifest["core_handoff"]["integration_pending"])
        self.assertNotIn("staged_handoff_hook", manifest)
        shown = self.ok(self.r("show", "--report-id", "r1"))
        self.assertTrue(shown["report"]["fresh"], shown)
        self.assertEqual(shown["report"]["stale"], [])
        self.assertEqual(shown["report"]["body"]["sha256"], sha(body_path))
        # interim never sets the final pointer.  A project with no final report at
        # all is *intact but incomplete*: `show --final` succeeds and says
        # current_final_complete=false / pending=current_final_missing.  It is not
        # corruption and must not block the project (main-agent ruling).
        self.assertFalse((self.project / "reports/final.json").exists())
        absent = self.ok(self.r("show", "--final"))
        self.assertFalse(absent["current_final_complete"])
        self.assertEqual(absent["current_final_pending"], "current_final_missing")
        self.assertTrue(absent["final"]["integrity_ok"])
        self.assertFalse(absent["final"]["present"])
        final = self.ok(self.r("generate", "--report-id", "r2", "--version", "1.1",
                               "--run-id", "run-a", "--kind", "final"))
        pointer = read(self.project / "reports/final.json")
        self.assertEqual(pointer["report_id"], "r2")
        self.assertEqual(pointer["manifest_sha256"], sha(self.project / "reports/r2/manifest.json"))
        self.assertEqual(pointer["target_sha256"],
                         read(self.project / "versions/1.1/version.json")["sha256"])
        self.assertTrue(final["final_pointer"]["set"])
        self.ok(self.r("show", "--final"))
        status = self.ok(self.r("status"))
        self.assertEqual(status["stale_reports"], [])
        self.assertEqual(len(status["reports"]), 2)
        self.assertTrue(status["final_pointer"]["valid"])
        # The report chain never rewrites the run/acceptance/old version closure.
        self.assertEqual(run_before, (self.project / "versions/1.1/runs/run-a/run.json").read_bytes())
        self.assertEqual(acceptance_before,
                         (self.project / "versions/1.1/acceptance.json").read_bytes())
        self.assertEqual(old_manifest_before,
                         (self.project / "versions/1.0/manifest.json").read_bytes())
        self.assertEqual(target_before, target_path.read_bytes())
        # An interim report on an older version is allowed and must not move final.
        self.ok(self.p("run", "--version", "1.0", "--run-id", "run-old"))
        self.ok(self.r("generate", "--report-id", "r-old", "--version", "1.0",
                       "--run-id", "run-old", "--kind", "interim"))
        self.assertEqual(read(self.project / "reports/final.json")["report_id"], "r2")
        # final for a non-current version is refused (even once its run has ended).
        self.ok(self.p("finish-run", "--version", "1.0", "--run-id", "run-old",
                       "--status", "blocked", "--note", "synthetic"))
        self.refused(self.r("generate", "--report-id", "r-old-final", "--version", "1.0",
                            "--run-id", "run-old", "--kind", "final"), "当前版本")
        self.assertFalse((self.project / "reports/r-old-final").exists())
    def test_03_unfinished_and_failed_project_still_reports_unknowns(self):
        self.ok(self.p("version", "--version", "1.2", "--parent", "1.1", "--target", self.last))
        self.capture("1.2", "probe.log", b"synthetic 1.2 probe log\n")
        self.capture("1.2", "source.txt", b"synthetic 1.2 source\n")
        self.start_run("1.2", "run-c")
        self.evidence("1.2", "run-c", "ev-c", "probe.log")
        self.ok(self.p("acceptance-define", "--version", "1.2",
                       "--item", "probe:只读探测响应可逐条核对",
                       "--item", "semantic:目标功能是否可用"))
        self.ok(self.p("acceptance-record", "--version", "1.2", "--item-id", "probe",
                       "--result", "pass", "--evidence-ids", "ev-c",
                       "--verifier", "synthetic-verifier", "--how", "read-only probe",
                       "--run", "run-c"))
        self.ok(self.p("acceptance-record", "--version", "1.2", "--item-id", "semantic",
                       "--result", "unknown", "--verifier", "synthetic-verifier",
                       "--how", "no functional check was run", "--run", "run-c"))
        state_before = (self.project / "project.json").read_bytes()
        acceptance_before = (self.project / "versions/1.2/acceptance.json").read_bytes()
        generated = self.ok(self.r("generate", "--report-id", "r-mid", "--version", "1.2",
                                   "--run-id", "run-c", "--kind", "interim"))
        self.assertTrue(generated["verification"]["fresh"], generated)
        body = (self.project / "reports/r-mid/report.md").read_text(encoding="utf-8")
        self.assertIn("验收项 semantic 当前是 unknown", body)
        self.assertIn("仍未知", body)
        self.assertIn("本 run 仍为 active", body)
        manifest = read(self.project / "reports/r-mid/manifest.json")
        self.assertEqual(manifest["kind"], "interim")
        self.assertEqual(manifest["run"]["status"], "active")
        self.assertFalse(manifest["acceptance"]["state"]["complete"])
        self.assertEqual(manifest["acceptance"]["state"]["counts"]["unknown"], 1)
        # final requires an ended run: an active run cannot be the final record.
        self.refused(self.r("generate", "--report-id", "r-mid-final", "--version", "1.2",
                            "--run-id", "run-c", "--kind", "final"), "已收尾")
        self.assertEqual(state_before, (self.project / "project.json").read_bytes())
        self.assertEqual(acceptance_before,
                         (self.project / "versions/1.2/acceptance.json").read_bytes())
        # A legitimately failed run may still get an unfinished/final report.
        self.ok(self.p("finish-run", "--version", "1.2", "--run-id", "run-c",
                       "--status", "failed", "--note", "synthetic failure"))
        failed_final = self.ok(self.r("generate", "--report-id", "r-failed-final",
                                      "--version", "1.2", "--run-id", "run-c",
                                      "--kind", "final"))
        self.assertTrue(failed_final["final_pointer"]["set"])
        body = (self.project / "reports/r-failed-final/report.md").read_text(encoding="utf-8")
        self.assertIn("非完成结果", body)
        self.assertIn("不代表整个 Goal 成功", body)
        pointer = read(self.project / "reports/final.json")
        self.assertEqual(pointer["report_id"], "r-failed-final")
        handoff = self.ok(self.p("resume"))["handoff"]
        # Report presence must never be read as business completion.
        self.assertFalse(handoff["acceptance_complete"])
        self.assertNotEqual(handoff["last_run_status"], "completed")

class ReportRejections(ReportChain):
    def test_04_binding_rejections_leave_no_trace(self):
        self.complete_run()
        reports_before = sorted(str(p) for p in (self.project / "reports").rglob("*"))
        # version/run/target binding
        self.refused(self.r("generate", "--report-id", "bad", "--version", "9.9",
                            "--run-id", "run-a"), "版本")
        self.refused(self.r("generate", "--report-id", "bad", "--version", "1.1",
                            "--run-id", "run-missing"), "run")
        self.refused(self.r("generate", "--report-id", "bad", "--version", "1.0",
                            "--run-id", "run-a"), "run 不存在")
        arbitrary = cli_raw(REPORT, "generate", "--project", self.project,
                            "--report-id", "bad", "--version", "1.1",
                            "--run-id", "run-a", "--kind", "provisional")
        self.assertEqual(arbitrary.returncode, 2, "unknown --kind must be refused")
        self.assertFalse((self.project / "reports/bad").exists())
        self.refused(self.r("generate", "--report-id", "../escape", "--version", "1.1",
                            "--run-id", "run-a"), "report_id")
        # external / escaping / metadata body paths
        outside = self.base / "outside.md"
        outside.write_bytes(self.report_body("outside"))
        self.refused(self.r("register", "--report-id", "bad", "--version", "1.1",
                            "--run-id", "run-a", "--body", str(outside)),
                     "project-relative")
        escape = self.base / "escape.md"
        escape.write_bytes(self.report_body("escape"))
        self.refused(self.r("register", "--report-id", "bad", "--version", "1.1",
                            "--run-id", "run-a", "--body", "../escape.md"), "相对路径")
        self.refused(self.r("register", "--report-id", "bad", "--version", "1.1",
                            "--run-id", "run-a", "--body", "handoff.json"), "元数据")
        # declared hash/size must match the real bytes (no fake hash)
        body_ref = self.put_body("ok.md", self.report_body("ok"))
        self.refused(self.r("register", "--report-id", "bad", "--version", "1.1",
                            "--run-id", "run-a", "--body", body_ref,
                            "--sha256", "0" * 64), "伪 hash")
        self.refused(self.r("register", "--report-id", "bad", "--version", "1.1",
                            "--run-id", "run-a", "--body", body_ref,
                            "--size", "17"), "size")
        # non five-section body refused
        bad_body = self.put_body(
            "bad.md", ("# t\n\n## 1 \u7ed3\u8bba\n- only one line\n").encode("utf-8"))
        self.refused(self.r("register", "--report-id", "bad", "--version", "1.1",
                            "--run-id", "run-a", "--body", bad_body), "\u4e94\u6bb5")
        # missing evidenced source blocks a new registration binding
        (self.project / "versions/1.1/capture/probe.log").write_bytes(b"tampered\n")
        self.refused(self.r("generate", "--report-id", "bad", "--version", "1.1",
                            "--run-id", "run-a"), "证据")
        self.capture("1.1", "probe.log", b"synthetic probe response: rc=0 (content is NOT success)\n")
        self.ok(self.r("generate", "--report-id", "r1", "--version", "1.1",
                       "--run-id", "run-a", "--kind", "interim"))
        # same id + different content refused; same id + same content idempotent
        other = self.put_body("other.md", self.report_body(
            "other", ("另一份报告的不同未知项", "第二行未知项")))
        self.refused(self.r("register", "--report-id", "r1", "--version", "1.1",
                            "--run-id", "run-a", "--body", other), "已登记")
        same = self.put_body("same.md", (self.project / "reports/r1/report.md").read_bytes())
        idempotent = self.ok(self.r("register", "--report-id", "r1", "--version", "1.1",
                                   "--run-id", "run-a", "--body", same))
        self.assertTrue(idempotent["idempotent"])
        # a registered body cannot be re-registered from inside its own directory
        self.refused(self.r("register", "--report-id", "r1x", "--version", "1.1",
                            "--run-id", "run-a", "--body", "reports/r1/report.md"),
                     "报告目录")
        after = sorted(str(x) for x in (self.project / "reports").rglob("*"))
        new_paths = [x for x in after if x not in reports_before]
        self.assertTrue(all((("reports" + os.sep + "r1") in x)
                            or x.endswith("reports" + os.sep + "index.jsonl")
                            for x in new_paths), new_paths)
        self.assertEqual([x.name for x in (self.project / "reports").iterdir()
                          if x.is_dir()], ["r1"])
    def test_05_credentials_are_never_echoed(self):
        self.complete_run()
        self.ok(self.r("generate", "--report-id", "r1", "--version", "1.1",
                       "--run-id", "run-a", "--kind", "interim"))
        edited_original = (self.project / "reports/r1/manifest.json").read_bytes()
        body = self.report_body("secret", ("password: %s" % SENTINEL_PASSWORD,))
        ref = self.put_body("secret.md", body)
        code, payload, stdout = self.r_full("register", "--report-id", "r-secret",
                                            "--version", "1.1", "--run-id", "run-a",
                                            "--body", ref)
        self.assertEqual(code, 2, payload)
        self.assertFalse(payload["ok"])
        self.assertIn("凭据", payload["reason"])
        self.assertNotIn(SENTINEL_PASSWORD, stdout)
        self.assertFalse((self.project / "reports/r-secret").exists())
        token = self.report_body("token", ("Bearer %s" % SENTINEL_BEARER,))
        code, payload, stdout = self.r_full(
            "register", "--report-id", "r-token", "--version", "1.1", "--run-id", "run-a",
            "--body", self.put_body("token.md", token))
        self.assertEqual(code, 2, payload)
        self.assertNotIn(SENTINEL_BEARER, stdout)
        # A credential that only reaches the *manifest* (an acceptance item
        # description, which the composed body never prints) must also be refused
        # before anything is written: output scrubbing is not a substitute for a
        # pre-write refusal.
        self.ok(self.p("version", "--version", "1.2", "--parent", "1.1",
                       "--target", self.last))
        self.capture("1.2", "probe.log", b"synthetic 1.2 probe\n")
        self.start_run("1.2", "run-manifest")
        self.ok(self.p("acceptance-define", "--version", "1.2",
                       "--item", "leaky:desc token=%s" % SENTINEL_PASSWORD))
        code, payload, stdout = self.r_full("generate", "--report-id", "r-manifest",
                                            "--version", "1.2", "--run-id", "run-manifest",
                                            "--kind", "interim")
        self.assertEqual(code, 2, payload)
        self.assertIn("manifest", payload["reason"])
        self.assertNotIn(SENTINEL_PASSWORD, stdout)
        self.assertFalse((self.project / "reports/r-manifest").exists())
        # A credential already present in a registered manifest (edited outside the
        # CLI) is shown redacted and makes it stale -- never echoed, never repaired.
        manifest = self.project / "reports/r1/manifest.json"
        edited = read(manifest)
        edited["note"] = "authorization: Bearer %s" % SENTINEL_BEARER
        write(manifest, edited)
        code, payload, stdout = self.r_full("show", "--report-id", "r1")
        self.assertEqual(code, 2, payload)
        self.assertNotIn(SENTINEL_BEARER, stdout)
        self.assertIn(SENTINEL_BEARER, manifest.read_text(encoding="utf-8"))  # untouched
        manifest.write_bytes(edited_original)
        self.ok(self.r("show", "--report-id", "r1"))
        # A public numeric token limit is not a credential.
        self.ok(self.r("generate", "--report-id", "r-limit", "--version", "1.1",
                       "--run-id", "run-a", "--note", "limit_tokens=128"))
        self.assertIn("limit_tokens=128",
                      (self.project / "reports/r-limit/manifest.json").read_text(encoding="utf-8"))

class ReportTamper(ReportChain):
    def test_06_tamper_makes_stale_and_restore_is_a_positive_control(self):
        self.complete_run()
        self.ok(self.r("generate", "--report-id", "r1", "--version", "1.1",
                       "--run-id", "run-a", "--kind", "final"))
        self.ok(self.r("show", "--final"))
        body = self.project / "reports/r1/report.md"
        manifest = self.project / "reports/r1/manifest.json"
        index = self.project / "reports/index.jsonl"
        evidence = self.project / "versions/1.1/capture/probe.log"
        pointer = self.project / "reports/final.json"
        originals = {p: p.read_bytes() for p in (body, manifest, index, evidence, pointer)}
        def stale_case(path: Path, payload: bytes, kind: str, target_id="r1"):
            path.write_bytes(payload)
            shown = self.refused(self.r("show", "--report-id", target_id))
            kinds = [item["kind"] for item in shown["report"]["stale"]]
            self.assertIn(kind, kinds, shown)
            self.refused(self.r("status"), "stale")
            self.refused(self.r("show", "--final"))
            path.write_bytes(originals[path])
            self.ok(self.r("show", "--report-id", target_id))     # positive control
            self.ok(self.r("show", "--final"))
        stale_case(body, originals[body] + "补充一行（篡改正文）\n".encode("utf-8"),
                   "body_changed")
        stale_case(manifest, originals[manifest] + b"\n", "index_mismatch")
        stale_case(evidence, b"tampered evidence bytes\n", "evidence_changed")
        # Silent regeneration with the same id is refused after a body edit.
        body.write_bytes(originals[body] + "再改一次\n".encode("utf-8"))
        self.refused(self.r("generate", "--report-id", "r1", "--version", "1.1",
                            "--run-id", "run-a", "--kind", "final"), "已登记")
        body.write_bytes(originals[body])
        self.ok(self.r("show", "--report-id", "r1"))
        # Index tamper: the registered body hash no longer matches the index.
        lines = [json.loads(line) for line in originals[index].decode().splitlines()]
        lines[0]["body_sha256"] = "0" * 64
        index.write_bytes(("\n".join(json.dumps(x, ensure_ascii=False)
                                     for x in lines) + "\n").encode("utf-8"))
        shown = self.refused(self.r("show", "--report-id", "r1"))
        kinds = [item["kind"] for item in shown["report"]["stale"]]
        self.assertIn("index_mismatch", kinds, shown)
        self.assertIn("body_changed", kinds, shown)
        index.write_bytes(originals[index])
        self.ok(self.r("show", "--report-id", "r1"))
        # Unparsable index blocks new registrations but is reported, not hidden.
        index.write_bytes(originals[index] + b"{not json}\n")
        self.refused(self.r("generate", "--report-id", "r2", "--version", "1.1",
                            "--run-id", "run-a", "--kind", "interim"), "索引")
        self.assertFalse((self.project / "reports/r2").exists())
        index.write_bytes(originals[index])
        # Manifest binding edit (recomputed body, old binding) is caught.
        altered = read(manifest)
        altered["run_id"] = "run-other"
        write(manifest, altered)
        shown = self.refused(self.r("show", "--report-id", "r1"))
        kinds = [item["kind"] for item in shown["report"]["stale"]]
        self.assertIn("manifest_binding", kinds, shown)
        manifest.write_bytes(originals[manifest])
        self.ok(self.r("show", "--report-id", "r1"))
        # Final pointer tamper invalidates the final view (and only that).
        altered = read(pointer)
        altered["report_id"] = "r-unknown"
        write(pointer, altered)
        self.refused(self.r("show", "--final"), "未在索引中登记")
        pointer.write_bytes(originals[pointer])
        self.ok(self.r("show", "--final"))
        self.ok(self.r("status"))
        # Metadata deletion (manifest) is stale, not "fresh".
        manifest.unlink()
        shown = self.refused(self.r("show", "--report-id", "r1"))
        self.assertIn("manifest_missing",
                      [item["kind"] for item in shown["report"]["stale"]])
        manifest.write_bytes(originals[manifest])
        self.ok(self.r("show", "--report-id", "r1"))
        # Target change after registration makes the report stale.
        version_path = self.project / "versions/1.1/version.json"
        version_bytes = version_path.read_bytes()
        altered = read(version_path)
        altered["sha256"] = "a" * 64
        altered["target_sha256"] = "a" * 64
        write(version_path, altered)
        shown = self.refused(self.r("show", "--report-id", "r1"))
        self.assertIn("target_changed",
                      [item["kind"] for item in shown["report"]["stale"]])
        version_path.write_bytes(version_bytes)
        self.ok(self.r("show", "--report-id", "r1"))

class ReportChainHealth(ReportChain):
    """REVIEW-04 §2: a broken acceptance chain is corruption at every stage.

    Legal pending/failed is *not* corruption, so its report stays fresh; a chain
    that cannot be recomputed must make the report stale, refuse new
    registrations and keep the project blocked -- the report layer never repairs
    or launders it (and never turns it into success).
    """

    def _broken_chain(self):
        """Break the archived predecessor of the consumed revision (bytes edit)."""
        revisions = sorted((self.project / "versions/1.1/acceptance-revisions").glob("rev-*.json"))
        self.assertTrue(revisions, "fixture must have archived revisions")
        revisions[0].write_bytes(revisions[0].read_bytes() + b" ")
        return revisions[0]

    def test_09_legal_pending_and_failed_reports_stay_fresh(self):
        self.ok(self.p("acceptance-define", "--version", "1.1",
                       "--item", "probe:只读探测响应可逐条核对",
                       "--item", "semantic:目标功能是否可用"))
        self.start_run("1.1", "run-pending")
        generated = self.ok(self.r("generate", "--report-id", "r-pending", "--version", "1.1",
                                   "--run-id", "run-pending", "--kind", "interim"))
        self.assertTrue(generated["verification"]["fresh"], generated)
        self.assertEqual(generated["verification"]["acceptance"]["chain_problems"], [])
        self.ok(self.p("finish-run", "--version", "1.1", "--run-id", "run-pending",
                       "--status", "failed", "--note", "synthetic failure"))
        self.ok(self.r("generate", "--report-id", "r-failed", "--version", "1.1",
                       "--run-id", "run-pending", "--kind", "final"))
        status = self.ok(self.r("status"))
        self.assertEqual(status["stale_reports"], [])
        # The interim report taken while the run was still active stays a valid
        # stage record after the run legitimately failed (forward motion, not
        # tampering); it is not silently rewritten to a "final" claim.
        self.ok(self.r("show", "--report-id", "r-pending"))
        self.assertEqual(read(self.project / "reports/r-pending/manifest.json")["kind"],
                         "interim")
        body = (self.project / "reports/r-failed/report.md").read_text(encoding="utf-8")
        self.assertIn("非完成结果", body)
        # The project may still be ok/active; the report only says what is recorded.
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertFalse(handoff["acceptance_complete"])
        self.assertNotEqual(handoff["last_run_status"], "completed")

    def test_10_broken_chain_makes_report_stale_and_blocks_new_registration(self):
        self.complete_run()
        self.ok(self.r("generate", "--report-id", "r1", "--version", "1.1",
                       "--run-id", "run-a", "--kind", "final"))
        self.ok(self.r("show", "--final"))
        self._broken_chain()
        # Pstate now reports the broken chain as blocked (REVIEW-04 §2 mapping).
        code, payload = self.p("resume")
        self.assertEqual(code, 2, payload)
        self.assertEqual(payload["handoff"]["state_health"], "blocked")
        self.assertTrue(payload["handoff"]["integrity_errors"], payload["handoff"])
        # The existing report must not stay fresh, and the final pointer is invalid.
        shown = self.refused(self.r("show", "--report-id", "r1"))
        self.assertIn("acceptance_chain_broken",
                      [item["kind"] for item in shown["report"]["stale"]], shown)
        self.refused(self.r("show", "--final"))
        status = self.refused(self.r("status"))
        self.assertEqual(status["stale_reports"], ["r1"])
        # No new report may be registered on top of a broken chain.
        refused = self.refused(self.r("generate", "--report-id", "r2", "--version", "1.1",
                                      "--run-id", "run-a", "--kind", "interim"), "验收修订链")
        self.assertFalse((self.project / "reports/r2").exists())
        # Nothing was repaired or laundered: the report chain did not touch state.
        self.assertEqual(refused["blocked_at"], "generate")


    def test_11_consistent_report_file_rewrite_cannot_replace_fact_witness(self):
        """Report-local hashes cannot replace the original registration event."""
        import project_report as report_module

        self.complete_run()
        self.ok(self.r("generate", "--report-id", "r-rewrite", "--version", "1.1",
                       "--run-id", "run-a", "--kind", "interim"))
        directory = self.project / "reports" / "r-rewrite"
        body_path = directory / "report.md"
        manifest_path = directory / "manifest.json"
        index_path = self.project / "reports" / "index.jsonl"
        originals = {path: path.read_bytes()
                     for path in (body_path, manifest_path, index_path)}
        facts_before = (self.project / "facts.jsonl").read_bytes()
        body_path.write_bytes(originals[body_path] + b"\nModified report-local content.\n")
        manifest = read(manifest_path)
        manifest["body"]["sha256"] = sha(body_path)
        manifest["body"]["size"] = body_path.stat().st_size
        manifest["binding_sha256"] = report_module._hash_object(
            report_module._binding(manifest))
        write(manifest_path, manifest)
        rows = [json.loads(line) for line in originals[index_path].decode("utf-8").splitlines()
                if line.strip()]
        for row in rows:
            if row.get("kind") == "registered" and row.get("report_id") == "r-rewrite":
                row.update(body_sha256=sha(body_path), body_size=body_path.stat().st_size,
                           manifest_sha256=sha(manifest_path),
                           binding_sha256=manifest["binding_sha256"])
        index_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        self.assertEqual((self.project / "facts.jsonl").read_bytes(), facts_before)
        self.refused(self.r("show", "--report-id", "r-rewrite"), "witness_mismatch")
        for path, payload in originals.items():
            path.write_bytes(payload)
        self.ok(self.r("show", "--report-id", "r-rewrite"))
        self.assertEqual((self.project / "facts.jsonl").read_bytes(), facts_before)


class ReportHandoffWiring(ReportChain):
    """The merged core hook, verified through the *real* CLI (no staged patch).

    The integration claim is checked behaviourally: ``project_state.py resume``
    must really project this report index (report fields, final pointer states,
    blocked priority).  Destructive probes run against a *temporary copy* of the
    wired source so the real file is never written.
    """

    def _temp_tree(self) -> Path:
        """Copy the real (already wired) sources into a scratch tree."""
        tree = self.base / "scratch/Tool/scripts"
        (tree / "lib").mkdir(parents=True)
        for name in ("project_state.py", "project_report.py", "manager_state.py"):
            shutil.copy2(ROOT / "Tool/scripts" / name, tree / name)
        for name in ("__init__.py", "project_lock.py", "project_transaction.py", "typed_assets.py"):
            source = ROOT / "Tool/scripts/lib" / name
            if source.is_file():
                shutil.copy2(source, tree / "lib" / name)
        (tree / "lib" / "__init__.py").touch()
        return tree

    def test_07_core_handoff_wiring_on_real_source(self):
        real_before = sha(STATE)
        self.complete_run()
        self.ok(self.r("generate", "--report-id", "r1", "--version", "1.1",
                       "--run-id", "run-a", "--kind", "final"))
        # (1) The real source carries the hook: `resume` really returns a report
        # projection for this project, and the integration status is detected from
        # the source rather than declared.
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertIn("report", handoff, "core hook is not wired into project_state.py")
        self.assertTrue(handoff["report"]["wired"])
        self.assertTrue(handoff["report"]["present"])
        self.assertTrue(handoff["acceptance_complete"])
        # (2) The CLI reports the *actual* wiring facts, with the unwired scopes named.
        generated = self.ok(self.r("show", "--report-id", "r1"))
        self.assertTrue(generated["core_handoff_wired"], generated)
        self.assertFalse(generated["integration_pending"], generated)
        self.assertEqual(generated["core_handoff_probe"], "_report_handoff_view")
        pending = {row["scope"] for row in generated["pending_scopes"] if not row["wired"]}
        self.assertEqual(pending, set())
        status = self.ok(self.r("status"))
        self.assertTrue(status["core_handoff_wired"])
        self.assertFalse(status["integration_pending"])
        # (3) The manifest records the same detected fact (not a hard-coded "staged").
        manifest = read(self.project / "reports/r1/manifest.json")
        self.assertTrue(manifest["core_handoff"]["core_handoff_wired"])
        self.assertFalse(manifest["core_handoff"]["integration_pending"])
        self.assertNotIn("staged_handoff_hook", manifest)

        tree = self._temp_tree()
        scratch_state = tree / "project_state.py"
        # The wired source still passes its own self-test on the scratch copy.
        selftest = subprocess.run([sys.executable, "-B", str(scratch_state), "--self-test"],
                                  cwd=str(tree.parents[1]), env=ENV, capture_output=True,
                                  text=True, encoding="utf-8", timeout=120)
        self.assertEqual(selftest.returncode, 0, (selftest.stdout[-2000:],
                                                  selftest.stderr[-2000:]))
        self.assertTrue(json.loads(selftest.stdout)["ok"])

        def resume(script=scratch_state, project=None):
            return cli(script, "resume", "--project", project or self.project)
        code, payload, _stdout = resume()
        self.assertEqual(code, 0, payload)
        handoff = payload["handoff"]
        self.assertTrue(handoff["report"]["wired"])
        self.assertEqual(handoff["report"]["current_final"]["report_id"], "r1")
        self.assertTrue(handoff["report"]["current_final"]["valid"])
        self.assertEqual(handoff["report"]["errors"], [])
        self.assertEqual(handoff["state_health"], "ok")
        # Tampered report makes resume blocked (blocked priority kept).
        body = self.project / "reports/r1/report.md"
        original = body.read_bytes()
        body.write_bytes(original + b"tampered\n")
        code, payload, _stdout = resume()
        self.assertEqual(code, 2, payload)
        handoff = payload["handoff"]
        self.assertEqual(handoff["state_health"], "blocked")
        self.assertIn("report_stale", [x.get("kind") for x in handoff["report"]["errors"]])
        self.assertTrue(any("报告" in x for x in handoff["next_actions"]))
        body.write_bytes(original)
        self.assertEqual(resume()[0], 0)
        # Report presence alone never turns an unfinished project into ok/completed:
        # a new version with no acceptance at all plus a fresh interim report.
        self.ok(self.p("version", "--version", "1.2", "--parent", "1.1", "--target", self.last))
        self.capture("1.2", "probe.log", b"synthetic 1.2 probe\n")
        self.capture("1.2", "source.txt", b"synthetic 1.2 source\n")
        self.start_run("1.2", "run-open")
        self.ok(self.r("generate", "--report-id", "r-open", "--version", "1.2",
                       "--run-id", "run-open", "--kind", "interim"))
        code, payload, _stdout = resume()
        handoff = payload["handoff"]
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(handoff["report"]["wired"], True)
        self.assertEqual(handoff["report"]["stale"], [])
        # MAIN-AGENT RULING (legit forward motion): a normal version bump that leaves
        # the final pointer on the previous version is NOT corruption.  The old final
        # report stays a readable historical record (integrity_ok=true) that is simply
        # not applicable to the new current version, so the state is healthy and the
        # new version is reported as "no final report yet" (pending), not blocked.
        # This is what lets the project keep collecting evidence for v1.2.
        self.assertEqual(code, 0, handoff["report"])
        self.assertEqual(handoff["state_health"], "ok")
        final = handoff["report"]["current_final"]
        self.assertEqual(final["report_id"], "r1")
        self.assertEqual(final["version_id"], "1.1")
        self.assertTrue(final["integrity_ok"])
        self.assertFalse(final["applicable"])
        self.assertFalse(final["valid"])
        self.assertEqual(final["pending"], "current_final_missing")
        self.assertEqual([x.get("kind") for x in handoff["report"]["errors"]], [])
        # ... and it must never be presented as the current version's final report,
        # while the agent is still told (as a *report* hint, not a blocking error)
        # that the current version needs its own final report.
        self.assertNotEqual(final["version_id"], "1.2")
        self.assertTrue(any("final 报告" in x for x in handoff["report"]["next_actions"]),
                        handoff["report"]["next_actions"])
        # The new version can still collect evidence and register reports normally.
        self.ok(self.r("generate", "--report-id", "r-open2", "--version", "1.2",
                       "--run-id", "run-open", "--kind", "interim"))
        # MAIN-AGENT RULING, part 2: the *normal* continuation must remain possible.
        # The bumped version keeps collecting evidence/acceptance and finally gets its
        # own final report; only then does the current final become valid.  The old
        # v1.1 final stays a historical record and never inherits the new acceptance.
        self.evidence("1.2", "run-open", "ev-12", "probe.log")
        self.ok(self.p("acceptance-define", "--version", "1.2",
                       "--item", "probe:只读探测响应可逐条核对"))
        self.ok(self.p("acceptance-record", "--version", "1.2", "--item-id", "probe",
                       "--result", "pass", "--evidence-ids", "ev-12",
                       "--verifier", "synthetic-verifier", "--how", "read-only probe",
                       "--run", "run-open"))
        self.ok(self.p("finish-run", "--version", "1.2", "--run-id", "run-open",
                       "--status", "completed", "--note", "synthetic"))
        code, payload, _stdout = resume()
        handoff = payload["handoff"]
        # no final report for v1.2 yet: intact, healthy, but not complete
        self.assertEqual(code, 0, handoff["report"])
        self.assertEqual(handoff["state_health"], "ok")
        self.assertFalse(handoff["report"]["current_final"]["applicable"])
        self.assertEqual(handoff["report"]["current_final"]["pending"],
                         "current_final_missing")
        self.ok(self.r("generate", "--report-id", "r-open-final", "--version", "1.2",
                       "--run-id", "run-open", "--kind", "final"))
        code, payload, _stdout = resume()
        handoff = payload["handoff"]
        self.assertEqual(code, 0, handoff["report"])
        self.assertEqual(handoff["report"]["current_final"]["report_id"], "r-open-final")
        self.assertTrue(handoff["report"]["current_final"]["valid"])
        self.assertTrue(handoff["report"]["current_final"]["applicable"])
        self.assertEqual(handoff["report"]["current_final"]["pending"], "")
        self.assertEqual(handoff["last_run_status"], "completed")
        text = (self.project / "reports/r-open-final/report.md").read_text(encoding="utf-8")
        self.assertIn("仍未知", text)
        # The old v1.1 final report is still readable as history, still fresh.
        self.ok(self.r("show", "--report-id", "r1"))
        # --- negative control: a hand-edited pointer is still corruption ---
        pointer_path = self.project / "reports/final.json"
        pointer_bytes = pointer_path.read_bytes()
        pointer = read(pointer_path)
        pointer["manifest_sha256"] = "0" * 64
        write(pointer_path, pointer)
        code, payload, _stdout = resume()
        self.assertEqual(code, 2, payload)
        handoff = payload["handoff"]
        self.assertEqual(handoff["state_health"], "blocked")
        self.assertFalse(handoff["report"]["current_final"]["integrity_ok"])
        self.assertIn("report_final_invalid",
                      [x.get("kind") for x in handoff["report"]["errors"]])
        self.refused(self.r("show", "--final"))
        pointer_path.write_bytes(pointer_bytes)
        self.assertEqual(resume()[0], 0)
        # --- 既有损坏 + 新鲜报告：报告不得盖掉已有 blocked/acceptance 错误 ---
        facts = self.project / "facts.jsonl"
        facts_bytes = facts.read_bytes()
        facts.write_bytes(facts_bytes + b"{corrupt synthetic line\n")
        code, payload, _stdout = resume()
        self.assertEqual(code, 2, payload)
        handoff = payload["handoff"]
        self.assertEqual(handoff["state_health"], "blocked")
        self.assertEqual(handoff["facts_status"], "corrupt")
        self.assertTrue(handoff["corrupt_fact_lines"])
        # the report itself is still fresh, and its (empty) error list did not
        # replace or hide the pre-existing fact error: the fact error survives in
        # state_errors and the healthy-report projection did not clear it.
        self.assertEqual(handoff["report"]["stale"], [])
        self.assertEqual(handoff["report"]["errors"], [])
        self.assertTrue(handoff["state_errors"],
                        "pre-existing fact error must survive the report hook")
        facts.write_bytes(facts_bytes)
        self.assertEqual(resume()[0], 0)
        # --- 合法未完成（链可复算）+ 新鲜报告：仍 ok，但绝不 complete ---
        # A *legal* unknown result on a new active run keeps the checklist
        # legitimately unfinished without breaking the revision chain.
        self.start_run("1.2", "run-pend")
        self.ok(self.p("acceptance-record", "--version", "1.2", "--item-id", "probe",
                       "--result", "unknown", "--verifier", "synthetic-verifier",
                       "--how", "no functional check was run", "--run", "run-pend"))
        self.ok(self.r("generate", "--report-id", "r-pend", "--version", "1.2",
                       "--run-id", "run-pend", "--kind", "interim"))
        code, payload, _stdout = resume()
        handoff = payload["handoff"]
        self.assertEqual(code, 0, handoff["report"])
        self.assertEqual(handoff["state_health"], "ok")
        self.assertEqual(handoff["report"]["errors"], [])
        self.assertFalse(handoff["acceptance_complete"])
        # an `unknown` result is unfinished (not pending), and is listed as such
        self.assertIn("probe", handoff["acceptance_unfinished"])
        # --- 链真坏 + 已有新鲜报告：两侧都必须报，且不得互相掩盖 ---
        revisions = sorted((self.project / "versions/1.2/acceptance-revisions").glob("rev-*.json"))
        self.assertTrue(revisions, "fixture must have archived a genesis revision")
        revision_bytes = revisions[0].read_bytes()
        revisions[0].write_bytes(revision_bytes + b" ")
        code, payload, _stdout = resume()
        self.assertEqual(code, 2, payload)
        handoff = payload["handoff"]
        self.assertEqual(handoff["state_health"], "blocked")
        self.assertTrue(handoff["integrity_errors"])
        report_kinds = [x.get("kind") for x in handoff["report"]["errors"]]
        self.assertIn("report_stale", report_kinds)
        stale_kinds = {x["kind"] for row in handoff["report"]["stale"]
                       for x in row["stale"]}
        self.assertIn("acceptance_chain_broken", stale_kinds)
        # both families survive in state_errors (neither displaces the other)
        merged = json.dumps(handoff["state_errors"], ensure_ascii=False)
        self.assertIn("验收", merged)
        self.assertIn("报告", merged)
        revisions[0].write_bytes(revision_bytes)
        self.assertEqual(resume()[0], 0)
        # --- 模块不可用：hook 只报固定原因 + 异常类型，不回显 str(exc) ---
        stub = scratch_state.with_name("project_report.py")
        real_module = stub.read_bytes()
        stub.write_text("raise ImportError(%r)\n" % ("synthetic-leak-" + SENTINEL_BEARER),
                        encoding="utf-8")
        code, payload, stdout = resume()
        self.assertEqual(code, 2, payload)
        hook = payload["handoff"]["report"]
        self.assertFalse(hook["wired"])
        self.assertEqual([x["kind"] for x in hook["errors"]], ["report_index"])
        self.assertIn("exception_type", hook["errors"][0])
        self.assertNotIn(SENTINEL_BEARER, stdout)
        self.assertNotIn("synthetic-leak", stdout)
        stub.write_bytes(real_module)
        # A stale register entry in the index is a blocking error, not a warning.
        index = self.project / "reports/index.jsonl"
        original_index = index.read_bytes()
        index.write_bytes(original_index + b"{broken\n")
        code, payload, _stdout = resume()
        self.assertEqual(code, 2, payload)
        self.assertIn("report_index",
                      [x.get("kind") for x in payload["handoff"]["report"]["errors"]])
        index.write_bytes(original_index)
        # The real project_state.py is byte-identical before/after the whole test.
        self.assertEqual(real_before, sha(STATE))
        self.assertFalse((ROOT / "reports").exists())

class ReportBoundaryRegressions(ReportChain):
    def interim(self):
        self.start_run("1.1", "run-a")
        return self.ok(self.r("generate", "--report-id", "r1", "--version", "1.1",
                              "--run-id", "run-a"))

    def test_nonobject_manifest_never_skips_verification(self):
        self.interim()
        path = self.project / "reports/r1/manifest.json"
        index = self.project / "reports/index.jsonl"
        original = path.read_bytes()
        rows = [json.loads(line) for line in index.read_text(encoding="utf-8").splitlines()]
        for value in ([], None, 5, "invalid"):
            with self.subTest(value=value):
                path.write_text(json.dumps(value), encoding="utf-8")
                rows[0]["manifest_sha256"] = sha(path)
                index.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                code, result = self.r("show", "--report-id", "r1")
                self.assertEqual(code, 2, result)
                self.assertFalse(result["report"]["fresh"])
                self.assertTrue(result["report"]["stale"])
        path.write_bytes(original)

    def test_nested_manifest_shapes_are_reported_as_stale(self):
        self.interim()
        path = self.project / "reports/r1/manifest.json"
        original = read(path)
        for key, value in (("body", ["bad"]), ("target", ["bad"]), ("assets", [None]),
                           ("scope", ["bad"]), ("facts", {"cited": [None]}),
                           ("evidence", {"entries": [None]}), ("claims", ["bad"]),
                           ("acceptance", ["bad"]), ("run", ["bad"])):
            with self.subTest(key=key):
                write(path, dict(original, **{key: value}))
                code, result = self.r("show", "--report-id", "r1")
                self.assertEqual(code, 2, result)
                self.assertIn("report", result, "must retain the per-report verification view")
                self.assertTrue(result["report"]["stale"])

    def test_report_directory_and_index_cannot_write_through_external_links(self):
        self.start_run("1.1", "run-a")
        outside = self.base / "outside-reports"
        outside.mkdir()
        outside_index = outside / "index.jsonl"
        outside_index.write_bytes(b"")
        reports = self.project / "reports"
        reports.rmdir()
        try:
            os.symlink(outside, reports, target_is_directory=True)
        except (OSError, NotImplementedError):
            reports.mkdir()
            self.skipTest("host cannot create symlink; case unverified")
        try:
            code, result = self.r("generate", "--report-id", "r1", "--version", "1.1",
                                  "--run-id", "run-a")
            self.assertEqual(code, 2, result)
            self.assertEqual(list(outside.iterdir()), [outside_index])
            self.assertEqual(outside_index.read_bytes(), b"")
        finally:
            reports.unlink()
            reports.mkdir()
        os.symlink(outside_index, reports / "index.jsonl")
        code, result = self.r("generate", "--report-id", "r2", "--version", "1.1",
                              "--run-id", "run-a")
        self.assertEqual(code, 2, result)
        self.assertEqual(outside_index.read_bytes(), b"")
        self.assertFalse((reports / "r2").exists())

    def test_manifest_paths_are_validated_before_reading_external_files(self):
        import project_report as R
        from unittest.mock import patch
        self.interim()
        outside = self.base / "outside.txt"
        outside.write_bytes(b"outside fixture")
        path = self.project / "reports/r1/manifest.json"
        original = read(path)
        rows, _ = R._read_index(self.project)
        real_sha = R._sha
        seen = []
        def guarded(candidate):
            candidate = Path(candidate)
            if not candidate.resolve().is_relative_to(self.project.resolve()):
                seen.append(candidate)
            return real_sha(candidate)
        for key in ("scope", "acceptance"):
            with self.subTest(key=key):
                broken = json.loads(json.dumps(original))
                broken[key]["local_path"] = str(outside)
                write(path, broken)
                with patch.object(R, "_sha", side_effect=guarded):
                    view = R._verify(self.project, R.P.require_project(self.project), rows[0])
                self.assertFalse(view["fresh"])
        self.assertEqual(seen, [], "untrusted manifest paths must never be opened")

    def test_show_does_not_claim_success_with_a_corrupt_or_duplicate_index(self):
        self.interim()
        path = self.project / "reports/index.jsonl"
        original = path.read_bytes()
        for suffix in (b"{broken\n", original):
            with self.subTest(suffix=suffix[:20]):
                path.write_bytes(original + suffix)
                for args in (("--report-id", "r1"), ("--final",)):
                    code, result = self.r("show", *args)
                    self.assertEqual(code, 2, result)
                    self.assertFalse(result["ok"])
                    self.assertTrue(result["index_problems"])
                path.write_bytes(original)

    def test_report_keeps_unreadable_sibling_ledger_errors_visible(self):
        self.start_run("1.1", "run-a")
        broken = self.project / "versions/1.1/runs/broken/run.json"
        broken.parent.mkdir(parents=True)
        broken.write_bytes(b"{broken")
        result = self.ok(self.r("generate", "--report-id", "r1", "--version", "1.1",
                                "--run-id", "run-a"))
        manifest = read(self.project / "reports/r1/manifest.json")
        self.assertTrue(manifest["ledger"]["errors"], result)
        self.assertIn("项目层统一审计", (self.project / "reports/r1/report.md").read_text(encoding="utf-8"))
        self.assertEqual(broken.read_bytes(), b"{broken")

    def test_generate_retry_uses_original_timestamp_without_rewriting_history(self):
        import contextlib
        import io
        import project_report as R
        from unittest.mock import patch
        self.interim()
        before = {p.relative_to(self.project): p.read_bytes()
                  for p in self.project.rglob("*") if p.is_file() and p.name != ".project.lock"}
        output = io.StringIO()
        with patch.object(R.P, "now", return_value="2099-01-01T00:00:00Z"), \
                contextlib.redirect_stdout(output):
            code = R.main(["generate", "--project", str(self.project), "--report-id", "r1",
                           "--version", "1.1", "--run-id", "run-a"])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 0, result)
        self.assertTrue(result["idempotent"])
        after = {p.relative_to(self.project): p.read_bytes()
                 for p in self.project.rglob("*") if p.is_file() and p.name != ".project.lock"}
        self.assertEqual(after, before)


class ReportSelfTest(unittest.TestCase):
    def test_08_help_and_self_test(self):
        for args in (["--help"], ["generate", "--help"], ["register", "--help"],
                     ["show", "--help"], ["status", "--help"]):
            result = subprocess.run([sys.executable, "-B", str(REPORT), *args],
                                    cwd=str(ROOT), env=ENV, capture_output=True,
                                    text=True, encoding="utf-8", timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr[-2000:])
            output = result.stdout + result.stderr
            self.assertIn("--help", output)
            if args != ["--help"]:
                self.assertIn("--project", output)
                if args[0] != "status":
                    self.assertIn("--report-id", output)
            else:
                for command in ("generate", "register", "show", "status"):
                    self.assertIn(command, output)
        result = subprocess.run([sys.executable, "-B", str(REPORT), "--self-test"],
                                cwd=str(ROOT), env=ENV, capture_output=True, text=True,
                                encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["ok"])
if __name__ == "__main__":
    unittest.main(verbosity=2)

