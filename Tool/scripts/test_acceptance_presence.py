#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D06 regression for acceptance presence and immutable history.

The fixture is made only through the real project_state.py CLI.  Missing slots
are moved into a per-test backup before the damage is simulated; no customer
project is touched and no old work/ report is imported as evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "Tool/scripts/project_state.py"
TMP_ROOT = ROOT / "work/final-delivery/tmp"
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1",
           PYTHONDONTWRITEBYTECODE="1", TEMP=str(TMP_ROOT), TMP=str(TMP_ROOT),
           TMPDIR=str(TMP_ROOT))
TARGET = b"synthetic D06 target\n"
TARGET_V2 = b"synthetic D06 target v2\n"
WITNESS = b"synthetic D06 witness\n"


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def cli(*args) -> tuple[int, dict]:
    result = subprocess.run([sys.executable, "-B", "-X", "utf8", str(STATE),
                             *map(str, args)], cwd=str(ROOT), env=ENV,
                            capture_output=True, text=True, encoding="utf-8",
                            timeout=50)
    if result.stderr:
        raise AssertionError(result.stderr[-2000:])
    try:
        return result.returncode, json.loads(result.stdout)
    except ValueError as exc:
        raise AssertionError((result.returncode, result.stdout[-3000:])) from exc


class PresenceBase(unittest.TestCase):
    def setUp(self):
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="d06-acceptance-presence-",
                                                 dir=str(TMP_ROOT))
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.project = self.base / "project"
        self.target = self.base / "target.bin"
        self.target.write_bytes(TARGET)
        self.assertEqual(cli("init", "--project", self.project,
                             "--project-id", "d06-presence", "--target", self.target)[0], 0)

    def p(self, command, *args):
        return cli(command, "--project", self.project, *args)

    def ok(self, result):
        self.assertEqual(result[0], 0, result)
        self.assertTrue(result[1].get("ok"), result)
        return result[1]

    def refused(self, result):
        self.assertEqual(result[0], 2, result)
        self.assertFalse(result[1].get("ok"), result)
        return result[1]

    def version_path(self, version="1.0"):
        return self.project / "versions" / version

    def live(self, version="1.0"):
        return self.version_path(version) / "acceptance.json"

    def history(self, version="1.0"):
        return self.version_path(version) / "acceptance-revisions"

    def define(self, version="1.0"):
        return self.p("acceptance-define", "--version", version,
                       "--item", "check:synthetic presence check")

    def start(self, run="run-1", version="1.0"):
        return self.p("run", "--version", version, "--run-id", run,
                       "--executor", "d06-test")

    def defined_pending(self):
        self.ok(self.start())
        self.ok(self.define())

    def completed(self):
        self.defined_pending()
        witness = self.version_path() / "artifacts" / "probe.log"
        witness.parent.mkdir(parents=True, exist_ok=True)
        witness.write_bytes(WITNESS)
        target_sha = read(self.version_path() / "version.json")["sha256"]
        self.ok(self.p("evidence", "--version", "1.0", "--run-id", "run-1",
                        "--evidence-id", "ev-1", "--target-sha256", target_sha,
                        "--path", "versions/1.0/artifacts/probe.log",
                        "--sha256", sha_bytes(WITNESS), "--size", len(WITNESS),
                        "--source", "versions/1.0/artifacts/probe.log",
                        "--how", "synthetic D06 witness", "--recorded-by", "test"))
        self.ok(self.p("acceptance-record", "--version", "1.0", "--item-id", "check",
                        "--result", "pass", "--evidence-ids", "ev-1",
                        "--verifier", "d06-test", "--how", "read synthetic witness",
                        "--run", "run-1"))
        self.ok(self.p("finish-run", "--version", "1.0", "--run-id", "run-1",
                        "--status", "completed", "--note", "synthetic"))

    def snapshot(self):
        """Bytes that a refused resume/write must preserve (handoff is projection)."""
        result = {}
        for path in sorted(self.project.rglob("*")):
            if not path.is_file() or path.name in ("handoff.json", ".project.lock"):
                continue
            result[path.relative_to(self.project).as_posix()] = path.read_bytes()
        return result

    def move_slot(self, name, version="1.0"):
        backup = self.base / "backup" / version
        backup.mkdir(parents=True, exist_ok=True)
        source = self.version_path(version) / name
        self.assertTrue(source.exists(), source)
        shutil.move(str(source), str(backup / name))
        return backup / name

    def restore_slot(self, name, version="1.0"):
        backup = self.base / "backup" / version / name
        if backup.exists():
            shutil.move(str(backup), str(self.version_path(version) / name))

    def assert_damaged(self, write_entry=True):
        before = self.snapshot()
        resumed = self.refused(self.p("resume"))
        handoff = resumed["handoff"]
        self.assertEqual(handoff["state_health"], "blocked", handoff)
        self.assertTrue(handoff["state_errors"], handoff)
        self.assertTrue(handoff["integrity_errors"], handoff)
        self.assertTrue(handoff["acceptance_errors"], handoff)
        self.assertTrue(handoff["acceptance"]["integrity_errors"], handoff)
        self.assertTrue(handoff["acceptance"]["defined"], handoff)
        self.assertEqual(before, self.snapshot())
        if write_entry:
            self.refused(self.define())
            self.refused(self.p("acceptance-record", "--version", "1.0",
                                "--item-id", "check", "--result", "unknown",
                                "--verifier", "d06-test", "--how", "presence probe",
                                "--run", "run-1"))
            self.assertEqual(before, self.snapshot())
        return handoff


class AcceptancePresence(PresenceBase):
    def test_new_project_placeholder_is_legal_unborn_pending(self):
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertFalse(handoff["acceptance"]["defined"])
        self.assertEqual(handoff["state_health"], "ok")
        self.assertEqual(handoff["state_errors"], [])
        self.assertEqual(handoff["acceptance_errors"], [])

    def test_single_live_delete_is_integrity_error_and_write_safe(self):
        self.defined_pending()
        self.move_slot("acceptance.json")
        self.assert_damaged()

    def test_single_history_delete_is_integrity_error_and_write_safe(self):
        self.defined_pending()
        self.move_slot("acceptance-revisions")
        self.assert_damaged()

    def test_double_delete_is_detected_from_append_only_facts(self):
        self.defined_pending()
        self.move_slot("acceptance.json")
        self.move_slot("acceptance-revisions")
        self.assert_damaged()

    def test_live_bad_json_and_identity_are_integrity_errors(self):
        self.defined_pending()
        original = self.live().read_bytes()
        for payload in (b"{not-json\n", json.dumps({
                "schema": "seep-acceptance/1", "project_id": "other",
                "version_id": "1.0", "target_sha256": "0" * 64,
                "items": []}).encode("utf-8")):
            with self.subTest(payload=payload[:10]):
                self.live().write_bytes(payload)
                self.assert_damaged()
                self.live().write_bytes(original)

    def test_defined_without_record_result_is_not_reborn_when_live_missing(self):
        self.defined_pending()
        self.move_slot("acceptance.json")
        handoff = self.assert_damaged()
        self.assertEqual(handoff["acceptance"]["pending"], [])
        self.assertNotIn("定义当前版本", " ".join(handoff["next_actions"]))

    def test_completed_history_survives_double_slot_loss(self):
        self.completed()
        self.move_slot("acceptance.json")
        self.move_slot("acceptance-revisions")
        handoff = self.assert_damaged()
        self.assertIn("run-1", handoff["completed_runs"])
        self.assertFalse(handoff["acceptance_complete"])

    def test_corruption_of_prior_version_does_not_contaminate_new_current_version(self):
        self.defined_pending()
        target2 = self.base / "target-v2.bin"
        target2.write_bytes(TARGET_V2)
        self.ok(self.p("version", "--version", "2.0", "--parent", "1.0",
                        "--target", target2))
        self.move_slot("acceptance.json", "1.0")
        self.move_slot("acceptance-revisions", "1.0")
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertEqual(handoff["current_version_id"], "2.0")
        self.assertEqual(handoff["acceptance"]["version_id"], "2.0")
        self.assertFalse(handoff["acceptance"]["defined"])
        self.assertEqual(handoff["state_health"], "ok", handoff)
        self.assertEqual(handoff["state_errors"], [], handoff)


class AcceptanceIdempotence(PresenceBase):
    def record_unknown(self):
        return self.p("acceptance-record", "--version", "1.0", "--item-id", "check",
                      "--result", "unknown", "--verifier", "d06-test",
                      "--how", "presence probe", "--run", "run-1")

    def prepare_record(self):
        self.defined_pending()
        self.ok(self.record_unknown())

    def assert_healthy_replay(self):
        self.ok(self.p("resume"))
        before = self.snapshot()
        replay = self.ok(self.record_unknown())
        self.assertTrue(replay.get("idempotent"), replay)
        self.assertEqual(before, self.snapshot())

    def test_healthy_unknown_replay_is_write_free(self):
        self.prepare_record()
        self.assert_healthy_replay()

    def test_missing_history_refuses_same_value_replay(self):
        self.prepare_record()
        self.assert_healthy_replay()
        self.move_slot("acceptance-revisions")
        self.refused(self.p("resume"))
        before = self.snapshot()
        self.refused(self.record_unknown())
        self.assertEqual(before, self.snapshot())
        self.restore_slot("acceptance-revisions")
        self.assert_healthy_replay()

    def test_changed_description_refuses_same_value_replay(self):
        self.prepare_record()
        self.assert_healthy_replay()
        original = self.live().read_bytes()
        damaged = read(self.live())
        damaged["items"][0]["description"] = "changed outside the recorded revision"
        self.live().write_text(json.dumps(damaged, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
        self.refused(self.p("resume"))
        before = self.snapshot()
        self.refused(self.record_unknown())
        self.assertEqual(before, self.snapshot())
        self.live().write_bytes(original)
        self.assert_healthy_replay()


if __name__ == "__main__":
    unittest.main(verbosity=2)
