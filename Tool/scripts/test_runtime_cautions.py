"""Project-owned cautions survive restoration without changing dispatch state."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import project_state as P
import manager_state as M
from lib.runtime_risk import RiskStore

ROOT = Path(__file__).resolve().parents[2]


class PortableCautions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="seep-cautions-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "project"
        target = self.base / "fixture.bin"
        target.write_bytes(b"SYNTHETIC STATIC INPUT; NEVER EXECUTE")
        self.cli("init", "--project-id", "fixture", "--target", target)
        self.cli("run", "--version", "1.0", "--run-id", "run-1")
        self.evidence = self.root / "versions/1.0/runs/run-1/observation.txt"
        self.evidence.write_text("Static observation; runtime effect still suspected.\n", encoding="utf-8")
        self.register_evidence("ev-1", "run-1", self.evidence)
        self.notice = {"caution_id": "risk-a", "scope": "identity", "subject_ref": "fixture/account-a",
                       "assessment": "suspected", "reason": "Static material mentions device binding",
                       "affected_actions": ["launch target", "authenticate"],
                       "resume_when": "Reconcile prior activity and confirm the appropriate test environment",
                       "safe_next": "Continue static inspection", "evidence_ids": ["ev-1"]}

    def cli(self, *args, expected=0):
        output = io.StringIO()
        with patch.object(sys, "argv", ["project_state.py", str(args[0]), "--project", str(self.root),
                                        *map(str, args[1:])]), contextlib.redirect_stdout(output):
            code = P.main()
        self.assertEqual(code, expected, output.getvalue())
        return json.loads(output.getvalue())

    def register_evidence(self, ident, run, file):
        fp = P.file_fingerprint(file)
        target = P.load_json(self.root / "versions/1.0/version.json")["sha256"]
        self.cli("evidence", "--version", "1.0", "--run-id", run, "--evidence-id", ident,
                 "--target-sha256", target, "--path", file.relative_to(self.root),
                 "--sha256", fp["sha256"], "--size", fp["size"], "--source", file.relative_to(self.root),
                 "--how", "synthetic static observation")

    def event(self, obj=None, kind="runtime_caution", run="run-1", expected=0):
        return self.cli("event", "--type", kind, "--message", json.dumps(obj or self.notice),
                        "--version", "1.0", "--run", run, expected=expected)

    def test_handoff_exposes_notice_without_wait_user_or_automatic_resume(self):
        self.event()
        handoff = P.write_handoff(self.root)
        self.assertEqual(handoff["status"], "active")
        view = handoff["runtime_cautions"]
        self.assertEqual(view["open"][0]["subject_ref"], "fixture/account-a")
        self.assertEqual(view["open"][0]["evidence_status"], "verified")
        self.assertIn("not_checked", view["external_coordination"])
        self.assertFalse(view["automatic_resume"])
        self.assertFalse(view["globally_enforced"])
        self.assertTrue(view["offline_work_allowed"])
        self.assertIn("runtime_cautions", handoff["next_actions"][0])
        manager = M.build_handoff(self.root)
        self.assertEqual(manager["runtime_cautions"]["open"], view["open"])

    def test_new_run_does_not_expire_identity_caution(self):
        self.event()
        self.cli("run", "--version", "1.0", "--run-id", "run-2")
        self.assertEqual(len(P.write_handoff(self.root)["runtime_cautions"]["open"]), 1)

    def test_new_version_reassesses_target_but_does_not_erase_identity_risk(self):
        self.event()
        other = dict(self.notice, caution_id="risk-b", scope="target", subject_ref="")
        self.event(other)
        target = self.base / "next.bin"
        target.write_bytes(b"NEXT SYNTHETIC STATIC INPUT")
        self.cli("version", "--version", "2.0", "--parent", "1.0", "--target", target)
        view = P.write_handoff(self.root)["runtime_cautions"]
        self.assertEqual(len(view["open"]), 2)
        self.assertEqual(view["open"][0]["applicability"], "recorded_scope")
        self.assertIn("reassessment", view["open"][1]["applicability"])
        self.assertEqual(view["open"][1]["source"]["version_id"], "1.0")

    def test_resolving_one_notice_retains_other_and_dispatch_pause(self):
        self.event()
        self.event(dict(self.notice, caution_id="risk-b"))
        store = RiskStore(self.base / "risk-state")
        store.pause("https://fixture.invalid", "fixture/account-a")
        db = (store.root / "state.sqlite3").read_bytes()
        self.event({"caution_id": "risk-a", "reason": "Local review completed", "evidence_ids": ["ev-1"]},
                   kind="runtime_caution_resolved")
        view = P.write_handoff(self.root)["runtime_cautions"]
        self.assertEqual([x["caution_id"] for x in view["open"]], ["risk-b"])
        self.assertEqual(db, (store.root / "state.sqlite3").read_bytes())
        self.assertTrue(store.status("https://fixture.invalid", "fixture/account-a")["paused"])

    def test_bad_reference_or_duplicate_is_rejected_before_append(self):
        self.event()
        before = (self.root / "facts.jsonl").read_bytes()
        for obj in [self.notice, dict(self.notice, caution_id="risk-x", evidence_ids=["missing"]),
                    dict(self.notice, caution_id="risk-x", reason="password=private-fixture")]:
            self.event(obj, expected=2)
            self.assertEqual(before, (self.root / "facts.jsonl").read_bytes())

    def test_cross_run_evidence_is_not_adopted(self):
        self.cli("run", "--version", "1.0", "--run-id", "run-2")
        self.event(run="run-2", expected=2)

    def test_tampered_evidence_blocks_resolution_and_handoff_health(self):
        self.event()
        before = (self.root / "facts.jsonl").read_bytes()
        self.evidence.write_text("tampered\n", encoding="utf-8")
        self.event({"caution_id": "risk-a", "reason": "No longer relevant", "evidence_ids": ["ev-1"]},
                   kind="runtime_caution_resolved", expected=2)
        self.assertEqual(before, (self.root / "facts.jsonl").read_bytes())
        handoff = P.write_handoff(self.root)
        self.assertEqual(handoff["state_health"], "blocked")
        self.assertTrue(handoff["runtime_cautions"]["errors"])

    def test_archive_import_keeps_warning_and_requires_coordination_recheck(self):
        self.event()
        archive = self.base / "portable.zip"
        restored = self.base / "restored"
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        for args in [["export", "--project", str(self.root), "--out", str(archive)],
                     ["import", "--archive", str(archive), "--project", str(restored)]]:
            result = subprocess.run([sys.executable, str(ROOT / "Tool/scripts/project_archive.py"), *args],
                                    cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        view = P.write_handoff(restored)["runtime_cautions"]
        self.assertEqual(view["open"][0]["caution_id"], "risk-a")
        self.assertIn("not_checked", view["external_coordination"])
        self.assertFalse((restored / "state.sqlite3").exists())
        foreign = self.base / "unrelated"
        M._make_project(foreign)
        self.assertEqual(P.runtime_cautions(foreign)["open"], [])


if __name__ == "__main__":
    unittest.main()
