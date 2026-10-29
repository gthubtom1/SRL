#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LIFECYCLE-05 A2: a pending draft is not corrupt, but a broken chain always is.

Ruling (``work/goal-recovery/REVIEW-04-DECISIONS.md`` §2-3, evidence in
``work/goal-recovery/run-failure-independent.md`` A1/A2/A3):

* Incomplete completion *eligibility* (pending / failed / cancelled / blocked /
  unsettled) is not corruption.
* A checklist chain whose hash / head / revision relation cannot be recomputed is
  corruption **at every stage**.  Rule C only ever meant "an in-progress draft
  must not block *work*"; it never meant "report a broken chain as ``ok``".
* Therefore real ``chain_problems`` must be projected into
  ``integrity_errors`` / ``acceptance_errors`` with ``state_health=blocked``,
  ``ok=false``, ``resume`` rc=2 -- exactly matching the three write entries that
  are already refusing (``acceptance-record`` / ``finish-run`` / ``migration``).
* The rest is unchanged: a legal pending draft stays ``ok``,
  ``acceptance_complete=false``; a legal non-completing run stays ``ok`` with an
  ``unsettled`` draft; a failed origin never skips the real file/hash checks;
  the completed r1 closure (fixed revision) and the whole-ledger write gate do
  not move.

Run: python -B -X utf8 Tool/scripts/test_pending_chain_health.py
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "Tool/scripts/project_state.py"
MIGRATE = ROOT / "Tool/skill/softseep/scripts/version-migrate.py"
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
OLD = b"AAAA\x85\xc0\x74\x12BBBB"
NEW = b"ZZZZZZ\x85\xc0\x74\x22CCCC"
WITNESS = b"synthetic witness line\n"


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run_script(script, *args):
    result = subprocess.run([sys.executable, "-B", str(script), *map(str, args)],
                            cwd=ROOT, env=ENV, capture_output=True, text=True,
                            encoding="utf-8", timeout=180)
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        raise AssertionError((result.returncode, result.stdout[-2000:], result.stderr[-2000:]))
    if result.stderr:
        raise AssertionError(result.stderr[-2000:])
    return result.returncode, payload


class HealthBase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="seep-pending-health-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.old = self.base / "old.bin"
        self.new = self.base / "new.bin"
        self.old.write_bytes(OLD)
        self.new.write_bytes(NEW)
        self.ok(self.p("init", "--project-id", "synthetic-pending-health",
                       "--target", self.old))
        self.ok(run_script(MIGRATE, "init", "--case", self.project,
                           "--version", "1.0", "--file", self.old))
        self.ok(self.p("version", "--version", "1.1", "--parent", "1.0",
                       "--target", self.new))
        self.version = read(self.project / "versions/1.1/version.json")
        self.target = self.version["sha256"]
        self.acceptance = self.project / "versions/1.1/acceptance.json"
        self.revisions = self.project / "versions/1.1/acceptance-revisions"

    # ---- plumbing ------------------------------------------------------
    def p(self, command, *args):
        return run_script(PROJECT, command, "--project", self.project, *args)

    def ok(self, result):
        self.assertEqual(result[0], 0, result)
        self.assertTrue(result[1]["ok"], result)
        return result[1]

    def rejected(self, result):
        self.assertEqual(result[0], 2, result)
        self.assertFalse(result[1]["ok"], result)
        return result[1]

    def start(self, run="r1"):
        return self.p("run", "--version", "1.1", "--run-id", run, "--executor", "test")

    def register(self, run="r1"):
        path = self.project / "versions/1.1/artifacts" / ("%s.log" % run)
        path.write_bytes(WITNESS + run.encode("utf-8") + b"\n")
        relative = path.relative_to(self.project).as_posix()
        body = path.read_bytes()
        return self.p("evidence", "--version", "1.1", "--run-id", run,
                      "--evidence-id", "ev-" + run, "--target-sha256", self.target,
                      "--path", relative, "--sha256", digest(body), "--size", len(body),
                      "--source", relative, "--how", "synthetic", "--recorded-by", "test")

    def define(self):
        return self.p("acceptance-define", "--version", "1.1",
                      "--item", "probe:synthetic probe executed")

    def record(self, run="r1"):
        return self.p("acceptance-record", "--version", "1.1", "--item-id", "probe",
                      "--result", "pass", "--evidence-ids", "ev-" + run,
                      "--verifier", "test harness", "--how", "ran synthetic probe",
                      "--run", run)

    def finish(self, run="r1", status="completed"):
        return self.p("finish-run", "--version", "1.1", "--run-id", run,
                      "--status", status, "--note", "synthetic")


class LegalPendingStaysHealthy(HealthBase):
    """Ruling: incomplete eligibility is not corruption (A1 / normal failed run)."""

    def test_a1_pending_draft_is_ok_and_never_complete(self):
        self.ok(self.define())
        self.ok(self.start())
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertEqual(handoff["status"], "active")
        self.assertEqual(handoff["state_health"], "ok")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(handoff["acceptance_pending"], ["probe"])
        self.assertEqual(handoff["acceptance_errors"], [])
        self.assertEqual(handoff["integrity_errors"], [])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["acceptance"]["chain_problems"], [])
        # A purely pending draft still cannot complete (no pass recorded).
        self.rejected(self.finish())

    def test_legal_non_completing_run_keeps_unsettled_not_corrupt(self):
        self.ok(self.define())
        self.ok(self.start())
        self.ok(self.register())
        self.ok(self.record())
        self.ok(self.finish(status="failed"))
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertEqual(handoff["state_health"], "ok")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(handoff["acceptance_unsettled"], ["probe"])
        self.assertEqual(handoff["acceptance_stale"], [])
        self.assertEqual(handoff["acceptance_errors"], [])
        self.assertEqual(handoff["integrity_errors"], [])

    def test_target_binding_defect_is_damage_even_when_only_pending(self):
        """The other half of A2: a real chain/binding defect is never ``ok``."""
        self.ok(self.define())
        self.ok(self.start())
        original = self.acceptance.read_bytes()
        data = json.loads(original.decode("utf-8"))
        data["target_sha256"] = "3" * 64
        write(self.acceptance, data)
        handoff = self.rejected(self.p("resume"))["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertEqual(handoff["state_health"], "blocked")
        self.assertTrue(handoff["integrity_errors"])
        self.assertTrue(handoff["acceptance_errors"])
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(handoff["acceptance_pending"], ["probe"])
        self.acceptance.write_bytes(original)
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertEqual(handoff["state_health"], "ok")
        self.assertEqual(handoff["integrity_errors"], [])


class A2PendingWithBrokenChain(HealthBase):
    """The closed gap: pending + hand-edited head must not report ok/rc0."""

    def test_a2_hand_edited_head_on_pending_draft_is_blocked(self):
        self.ok(self.define())
        self.ok(self.start())
        original = self.acceptance.read_bytes()
        data = json.loads(original.decode("utf-8"))
        data["items"][0]["description"] = "rewritten by hand while still pending"
        write(self.acceptance, data)
        result = self.p("resume")
        self.assertEqual(result[0], 2, result)
        handoff = result[1]["handoff"]
        self.assertFalse(result[1]["ok"])
        self.assertEqual(handoff["status"], "blocked")
        self.assertEqual(handoff["state_health"], "blocked")
        self.assertTrue(handoff["integrity_errors"])
        self.assertTrue(handoff["acceptance_errors"])
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(handoff["acceptance_pending"], ["probe"])
        self.assertTrue(handoff["acceptance"]["chain_problems"])
        # Health now agrees with the write entries instead of disagreeing.
        self.rejected(self.record())
        self.rejected(self.finish())
        self.assertEqual(data, read(self.acceptance))
        # Restoring the real bytes is the positive control.
        self.acceptance.write_bytes(original)
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertEqual(handoff["status"], "active")
        self.assertEqual(handoff["state_health"], "ok")
        self.assertEqual(handoff["integrity_errors"], [])
        self.assertEqual(handoff["acceptance_pending"], ["probe"])

    def test_stripped_revision_history_on_pending_draft_is_blocked(self):
        self.ok(self.define())
        self.ok(self.start())
        original = self.acceptance.read_bytes()
        data = json.loads(original.decode("utf-8"))
        for key in ("archive_index", "revision_history", "revisions"):
            data.pop(key, None)
        write(self.acceptance, data)
        handoff = self.rejected(self.p("resume"))["handoff"]
        self.assertEqual(handoff["state_health"], "blocked")
        self.assertTrue(handoff["integrity_errors"])
        self.assertFalse(handoff["acceptance_complete"])
        self.acceptance.write_bytes(original)
        self.assertEqual(self.ok(self.p("resume"))["handoff"]["state_health"], "ok")


class HealthAgreesWithWriteGate(HealthBase):
    """The projection and the three write entries can never disagree."""

    def test_damaged_chain_blocks_and_legal_chain_advances(self):
        self.ok(self.define())
        self.ok(self.start())
        self.ok(self.register())
        # Legal record: head moves through the append-only log, health stays ok.
        self.ok(self.record())
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertEqual(handoff["state_health"], "ok")
        self.assertEqual(handoff["integrity_errors"], [])
        self.assertEqual(handoff["acceptance"]["chain_problems"], [])
        self.assertTrue(handoff["acceptance"]["complete"])
        # The completed-run closure consumed a fixed revision; a later legal
        # revision archives those exact bytes, so r1 keeps re-verifying against
        # them instead of against the moved head.
        self.ok(self.finish())
        completed = read(self.project / "versions/1.1/runs/r1/run.json")
        consumed = completed["closure"]["acceptance_sha256"]
        self.ok(self.start("r2"))
        self.ok(self.register("r2"))
        self.ok(self.record("r2"))
        archived = self.revisions / ("rev-%s.json" % consumed)
        self.assertTrue(archived.is_file())
        self.assertEqual(consumed, digest(archived.read_bytes()))
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertEqual(handoff["state_health"], "ok")
        self.assertEqual(handoff["closure_errors"], [])
        # Now break an archived revision: health must go blocked, bytes frozen.
        archived_bytes = archived.read_bytes()
        data = json.loads(archived_bytes.decode("utf-8"))
        data["note"] = "rewritten inside an immutable revision"
        write(archived, data)
        handoff = self.rejected(self.p("resume"))["handoff"]
        self.assertEqual(handoff["state_health"], "blocked")
        self.assertTrue(handoff["integrity_errors"] or handoff["closure_errors"])
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(completed, read(self.project / "versions/1.1/runs/r1/run.json"))
        archived.write_bytes(archived_bytes)
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertEqual(handoff["state_health"], "ok")
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["closure_errors"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
