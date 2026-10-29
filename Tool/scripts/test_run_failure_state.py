#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LIFECYCLE-03 §5: a legal non-completing terminal state is not corruption.

Independent evidence: ``work/goal-recovery/run-acceptance-independent.md`` §5 and
``work/goal-recovery/independent-probes/run3-repro-failed-run-stale.py``.

Original reproducer (only legal CLI calls, fresh fixture):

    resume_before              = 0 (active)
    finish-run --status failed = 0            <- write accepted
    resume_after               = 2 (blocked)  <- "已完成验收证据失效"
    closure_errors             = []           <- no completion record exists at all

The write was accepted (rc=0) and the very next read turned the project red with
a message that only makes sense for *tampered* evidence.  Main-agent ruling
(not just wording):

1  Raw-evidence **integrity** and completion **eligibility** are different
   things.  A run that ended failed/cancelled/blocked makes its unconsumed
   draft pass unusable for ``completed``, but it does not tamper with any file
   and does not break the hash chain.  History and the pass record stay, the
   live draft is reported unfinished/ineligible (``acceptance_unsettled``),
   ``acceptance_complete=false``, and ``resume`` rebuilds that state with **no**
   acceptance/closure/integrity errors.  ``status``/``state_health`` = ok means
   "readable and self-consistent", never "the goal passed"; the failure is
   explained by ``last_run_status`` + ``next_actions``.
2  Completed closure is still verified against the immutable revision / original
   evidence / hash chain / whole-ledger audit.  A failed draft (ineligible
   origin) does **not** exempt anyone from that verification: real tampering of
   the original evidence or of the chain still blocks.
3  A failed/cancelled/blocked run keeps refusing ``acceptance-record`` (old
   bytes frozen); a new run never inherits the old pass nor borrows the old
   evidence, and ``migration`` may not consume a pass of a failed run.
4  After a normal non-completing finish ``resume`` is structurally consistent
   and readable, ``acceptance_complete=false``, ``closure_errors`` and
   ``integrity_errors`` empty; the same holds for fail/unknown/pending results.
   Business failure is never renamed "completed" and ``project.status`` never
   becomes ``completed``.

Run: python -B -X utf8 Tool/scripts/test_run_failure_state.py
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
NON_COMPLETING = ("failed", "cancelled", "blocked")
# Wording that must never appear for a legal non-completing finish: it claims
# tampering / a broken chain, which is exactly what ruling 1 forbids.
CORRUPTION_WORDS = ("验收证据已失效", "篡改", "数据损坏", "写链日志", "不可复核", "stale")


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


def cli(*args):
    return run_script(PROJECT, *args)


class FailureStateBase(unittest.TestCase):
    """One project / one version (1.1); runs are started as each test needs."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="seep-run-failure-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.old = self.base / "old.bin"
        self.new = self.base / "new.bin"
        self.old.write_bytes(OLD)
        self.new.write_bytes(NEW)
        self.ok(self.p("init", "--project-id", "synthetic-run-failure", "--target", self.old))
        self.ok(run_script(MIGRATE, "init", "--case", self.project,
                           "--version", "1.0", "--file", self.old))
        self.ok(self.p("version", "--version", "1.1", "--parent", "1.0", "--target", self.new))
        self.version = read(self.project / "versions/1.1/version.json")
        self.target = self.version["sha256"]
        self.acceptance = self.project / "versions/1.1/acceptance.json"
        self.revisions = self.project / "versions/1.1/acceptance-revisions"
        self.facts = self.project / "facts.jsonl"
        self.manifest = self.project / "versions/1.1/manifest.json"

    # ---- plumbing ------------------------------------------------------
    def p(self, command, *args):
        return cli(command, "--project", self.project, *args)

    def ok(self, result):
        self.assertEqual(result[0], 0, result)
        self.assertTrue(result[1]["ok"], result)
        return result[1]

    def rejected(self, result):
        self.assertEqual(result[0], 2, result)
        self.assertFalse(result[1]["ok"], result)
        return result[1]

    def run_json(self, run):
        return self.project / "versions/1.1/runs" / run / "run.json"

    def start(self, run):
        return self.p("run", "--version", "1.1", "--run-id", run, "--executor", "test")

    def witness(self, run):
        path = self.project / "versions/1.1/artifacts" / ("%s.log" % run)
        path.write_bytes(WITNESS + run.encode("utf-8") + b"\n")
        return path

    def register(self, run, evidence_id=None):
        evidence_id = evidence_id or ("ev-" + run)
        path = self.witness(run)
        relative = path.relative_to(self.project).as_posix()
        body = path.read_bytes()
        return self.p("evidence", "--version", "1.1", "--run-id", run,
                      "--evidence-id", evidence_id, "--target-sha256", self.target,
                      "--path", relative, "--sha256", digest(body), "--size", len(body),
                      "--source", relative, "--how", "synthetic", "--recorded-by", "test")

    def define(self):
        return self.p("acceptance-define", "--version", "1.1",
                      "--item", "probe:synthetic probe executed")

    def record(self, run, evidence_id=None, result="pass", item_id="probe"):
        return self.p("acceptance-record", "--version", "1.1", "--item-id", item_id,
                      "--result", result,
                      "--evidence-ids", evidence_id or ("ev-" + run),
                      "--verifier", "test harness", "--how", "ran synthetic probe",
                      "--run", run)

    def finish(self, run, status="completed"):
        return self.p("finish-run", "--version", "1.1", "--run-id", run,
                      "--status", status, "--note", "synthetic")

    def resume(self):
        return self.p("resume")

    def events(self, event_type):
        rows = [json.loads(line) for line in
                self.facts.read_text(encoding="utf-8").splitlines() if line.strip()]
        return [row for row in rows if row.get("type") == event_type]

    # ---- fixtures ------------------------------------------------------
    def prepare(self):
        self.ok(self.define())
        return self

    def complete_run(self, run):
        self.ok(self.start(run))
        self.ok(self.register(run))
        self.ok(self.record(run))
        self.ok(self.finish(run))
        return read(self.run_json(run))

    def draft_pass_then_finish(self, run, status):
        """Record a real pass bound to ``run``, then end the run non-completed."""
        self.ok(self.start(run))
        self.ok(self.register(run))
        self.ok(self.record(run))
        self.ok(self.finish(run, status=status))
        return read(self.run_json(run))

    def prepared_alignment(self):
        self.assertEqual(run_script(MIGRATE, "add-site", "--case", self.project,
                                    "--version", "1.0", "--file", self.old, "--id", "gate",
                                    "--sem", "synthetic branch candidate",
                                    "--aob", "85 C0 74 ??", "--offset", "4",
                                    "--original", "85 C0 74 12")[0], 0)
        self.assertEqual(run_script(MIGRATE, "align", "--case", self.project,
                                    "--old", "1.0", "--new-version", "1.1",
                                    "--new", self.new)[0], 0)
        align = self.project / "versions/1.1/align.json"
        self.assertTrue(align.is_file(), "fixture must produce a real align file")
        return align

    # ---- shared assertions --------------------------------------------
    def assert_readable_unfinished(self, handoff, status, run):
        """Ruling 1/4: readable, self-consistent, business-unfinished."""
        self.assertEqual(handoff["status"], "active", handoff["status"])
        self.assertEqual(handoff["state_health"], "ok")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertFalse(handoff["acceptance_eligible"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["acceptance_errors"], [])
        self.assertEqual(handoff["integrity_errors"], [])
        self.assertEqual(handoff["acceptance_stale"], [])
        self.assertEqual(handoff["last_run_status"], status)
        self.assertEqual(handoff["last_run_id"], run)
        self.assertIn("probe", handoff["acceptance_unsettled"])
        self.assertIn("probe", handoff["acceptance_unfinished"])
        self.assertNotEqual(handoff["status"], "completed")
        # The legal failure is explained as a new-run path, not as "restore data".
        actions = " ".join(handoff["next_actions"])
        self.assertIn("新建 run", actions)
        self.assertNotIn("恢复被篡改或丢失的验收证据", actions)
        # Nothing in the report claims corruption / a broken chain.
        blob = json.dumps([handoff["acceptance_errors"], handoff["closure_errors"],
                           handoff["state_errors"], handoff["next_actions"]],
                          ensure_ascii=False)
        for word in CORRUPTION_WORDS:
            self.assertNotIn(word, blob, (word, blob))


class NonCompletingRunIsNotCorruption(FailureStateBase):
    """Ruling 1/4: finish failed/cancelled/blocked then resume must stay readable."""

    def test_failed_run_then_resume_no_longer_reports_invalidated_evidence(self):
        """The exact §5 reproducer, now asserted in the fixed direction."""
        self.prepare()
        self.assertEqual(self.ok(self.resume())["handoff"]["status"], "active")
        self.ok(self.start("r1"))
        self.ok(self.register("r1"))
        self.ok(self.record("r1"))
        self.ok(self.finish("r1", status="failed"))
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["status"], "active")
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["acceptance_errors"], [])
        self.assertEqual(handoff["completed_runs"], [])
        self.assert_readable_unfinished(handoff, "failed", "r1")
        # The pass record itself is preserved (history is not deleted).
        acceptance = read(self.acceptance)
        self.assertEqual(acceptance["items"][0]["status"], "pass")
        self.assertEqual(acceptance["items"][0]["origin"]["run_id"], "r1")
        self.assertEqual(read(self.run_json("r1"))["status"], "failed")

    def test_all_non_completing_terminal_states_are_readable(self):
        self.prepare()
        for index, status in enumerate(NON_COMPLETING, start=1):
            run = "r%d" % index
            with self.subTest(status=status):
                self.ok(self.start(run))
                self.ok(self.register(run))
                self.ok(self.record(run))
                self.ok(self.finish(run, status=status))
                handoff = self.ok(self.resume())["handoff"]
                self.assert_readable_unfinished(handoff, status, run)
                # Byte-level: no file was rewritten by resume, and the write
                # entries stay frozen for the closed run.
                run_bytes = self.run_json(run).read_bytes()
                checklist_bytes = self.acceptance.read_bytes()
                self.rejected(self.record(run, result="unknown"))
                self.assertEqual(run_bytes, self.run_json(run).read_bytes())
                self.assertEqual(checklist_bytes, self.acceptance.read_bytes())
                self.assertEqual(read(self.run_json(run))["status"], status)
                # A new run is the way forward; the old draft is not reused.
                fresh = "f%d" % index
                self.ok(self.start(fresh))
                self.ok(self.register(fresh))
                handoff = self.ok(self.resume())["handoff"]
                self.assertFalse(handoff["acceptance_complete"])
                self.rejected(self.finish(fresh))
                self.assertEqual(read(self.run_json(fresh))["status"], "active")
                self.assertEqual(self.run_json(run).read_bytes(), run_bytes)

    def test_non_pass_results_and_pending_stay_unfinished_without_integrity_noise(self):
        self.prepare()
        # pending: nothing recorded at all, then a failed finish.
        self.ok(self.start("r1"))
        self.ok(self.register("r1"))
        self.ok(self.finish("r1", status="failed"))
        handoff = self.ok(self.resume())["handoff"]
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["acceptance_errors"], [])
        self.assertEqual(handoff["integrity_errors"], [])
        self.assertEqual(handoff["acceptance_pending"], ["probe"])
        self.assertIn("probe", handoff["acceptance_unfinished"])
        self.assertEqual(handoff["last_run_status"], "failed")

        for index, (result, status) in enumerate((("fail", "failed"),
                                                  ("unknown", "cancelled")), start=2):
            run = "r%d" % index
            with self.subTest(result=result, status=status):
                self.ok(self.start(run))
                self.ok(self.register(run))
                self.ok(self.record(run, result=result))
                self.ok(self.finish(run, status=status))
                handoff = self.ok(self.resume())["handoff"]
                self.assertFalse(handoff["acceptance_complete"])
                self.assertEqual(handoff["closure_errors"], [])
                self.assertEqual(handoff["acceptance_errors"], [])
                self.assertEqual(handoff["integrity_errors"], [])
                self.assertEqual(handoff["acceptance_stale"], [])
                self.assertIn("probe", handoff["acceptance_failed"] + handoff["acceptance_pending"])
                self.assertNotEqual(handoff["status"], "completed")
                self.assertEqual(read(self.project / "project.json")["status"], "active")

    def test_failed_second_run_keeps_completed_first_run_green(self):
        """Variant B of the reproducer: r1 completed, then r2 passes and fails."""
        self.prepare()
        first = self.complete_run("r1")
        first_seal = first["closure"]["seal_sha256"]
        r1_bytes = self.run_json("r1").read_bytes()
        r2 = self.draft_pass_then_finish("r2", "failed")
        self.assertEqual(r2["status"], "failed")
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["status"], "active")
        self.assertEqual(handoff["completed_runs"], ["r1"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["acceptance_errors"], [])
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(handoff["acceptance_unsettled"], ["probe"])
        self.assertEqual(handoff["last_run_status"], "failed")
        self.assertEqual(r1_bytes, self.run_json("r1").read_bytes())
        self.assertEqual(first_seal, read(self.run_json("r1"))["closure"]["seal_sha256"])
        # Ruling 3: the frozen r2 keeps refusing writes, and its pass is not
        # inheritable by a new run, nor consumable by a migration.
        self.rejected(self.record("r2"))
        self.ok(self.start("r3"))
        self.ok(self.register("r3"))
        self.rejected(self.finish("r3"))
        self.assertEqual(read(self.run_json("r3"))["status"], "active")
        align = self.prepared_alignment()
        refused = self.rejected(self.p("migration", "--source", "1.0", "--target", "1.1",
                                       "--align", str(align), "--status", "completed",
                                       "--migration-id", "mig-1"))
        self.assertIn("验收未完成", json.dumps(refused, ensure_ascii=False))
        self.assertFalse((self.project / "versions/1.1/migration.json").exists())
        self.assertEqual(handoff["completed_migrations"], [])

    def test_full_chain_still_completes_after_a_failed_run(self):
        """Ruling 5: the new run walks the whole real chain and stays green."""
        self.prepare()
        self.complete_run("r1")
        r1 = read(self.run_json("r1"))
        r1_bytes = self.run_json("r1").read_bytes()
        self.draft_pass_then_finish("r2", "failed")
        self.ok(self.resume())
        completed = self.complete_run("r3")
        self.assertEqual(completed["status"], "completed")
        self.assertNotEqual(completed["closure"]["seal_sha256"], r1["closure"]["seal_sha256"])
        self.assertEqual(completed["closure"]["acceptance_sha256"],
                         digest(self.acceptance.read_bytes()))
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["status"], "active")
        self.assertTrue(handoff["acceptance_complete"])
        self.assertTrue(handoff["acceptance_eligible"])
        self.assertEqual(handoff["completed_runs"], ["r1", "r3"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["acceptance_errors"], [])
        self.assertEqual(handoff["acceptance_unsettled"], [])
        self.assertEqual(handoff["last_run_status"], "completed")
        self.assertEqual(r1_bytes, self.run_json("r1").read_bytes())
        self.assertEqual(self.events("run_finished")[-1]["status"], "completed")


class FailedDraftStillFailsClosed(FailureStateBase):
    """Ruling 2: an ineligible draft never exempts the ledger from verification."""

    def test_original_evidence_tamper_under_a_failed_run_is_still_blocked(self):
        self.prepare()
        self.draft_pass_then_finish("r1", "failed")
        self.assertEqual(self.ok(self.resume())["handoff"]["acceptance_unsettled"], ["probe"])
        witness = self.project / "versions/1.1/artifacts/r1.log"
        original = witness.read_bytes()
        witness.write_bytes(b"tampered after the run failed\n")
        result = self.resume()
        self.assertEqual(result[0], 2, result)
        handoff = result[1]["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertTrue(handoff["acceptance_errors"] or handoff["evidence_errors"])
        self.assertEqual(handoff["acceptance_stale"], ["probe"])
        self.assertTrue(handoff["integrity_errors"])
        blob = json.dumps([handoff["acceptance_errors"], handoff["state_errors"]],
                          ensure_ascii=False)
        self.assertIn("完整性", blob)
        # The closed run stays frozen, and completion of a new run is refused
        # while the raw evidence disagrees with its record (the completion gate
        # reuses the same evidence core).  Recording a *new* run's pass is still
        # allowed by the documented minimal gate face (record is not a
        # completion witness); what it can never do is open a completion.
        self.rejected(self.record("r1"))
        self.ok(self.start("r3"))
        self.ok(self.register("r3"))
        self.ok(self.record("r3"))
        self.rejected(self.finish("r3"))
        self.assertEqual(read(self.run_json("r3"))["status"], "active")
        # Restoring the byte restores the readable unfinished state.
        witness.write_bytes(original)
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["acceptance_errors"], [])
        self.assertEqual(handoff["integrity_errors"], [])
        # The restored bytes plus r3's own pass make the draft eligible again:
        # restoring real data recovers the completion path (not a permanent red).
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["acceptance_unsettled"], [])
        self.ok(self.finish("r3"))
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["completed_runs"], ["r3"])
        self.assertEqual(handoff["closure_errors"], [])

    def test_broken_checklist_header_under_a_failed_run_is_still_blocked(self):
        self.prepare()
        self.draft_pass_then_finish("r1", "failed")
        original = self.acceptance.read_bytes()
        data = json.loads(original.decode("utf-8"))
        data["items"][0]["description"] = "rewritten by hand after the failure"
        write(self.acceptance, data)
        result = self.resume()
        self.assertEqual(result[0], 2, result)
        handoff = result[1]["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertFalse(handoff["acceptance_complete"])
        blob = json.dumps([handoff["acceptance_errors"], handoff["state_errors"]],
                          ensure_ascii=False)
        self.assertIn("写链日志", blob)
        self.assertTrue(handoff["acceptance"]["chain_problems"])
        # A hand edit of the live head is never laundered into a revision: the
        # bytes stay exactly as written and the checklist cannot be advanced.
        self.ok(self.start("r2"))
        self.ok(self.register("r2"))
        self.rejected(self.record("r2"))
        self.assertEqual(data, read(self.acceptance))
        self.acceptance.write_bytes(original)
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["acceptance_errors"], [])
        self.assertEqual(handoff["acceptance_unsettled"], ["probe"])

    def test_completed_closure_still_verified_while_a_failed_draft_exists(self):
        """Ruling 2: the failed draft never turns r1's closure verification off."""
        self.prepare()
        self.complete_run("r1")
        self.completed_r1 = read(self.run_json("r1"))
        self.draft_pass_then_finish("r2", "failed")
        self.assertEqual(self.ok(self.resume())["handoff"]["closure_errors"], [])
        target = self.revisions / ("rev-%s.json" % self.completed_r1["closure"]["acceptance_sha256"])
        original = target.read_bytes()
        data = json.loads(original.decode("utf-8"))
        data["note"] = "rewritten inside an immutable revision"
        target.write_bytes(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))
        result = self.resume()
        self.assertEqual(result[0], 2, result)
        handoff = result[1]["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertTrue(handoff["closure_errors"])
        self.assertIn("修订归档", json.dumps(handoff["closure_errors"], ensure_ascii=False))
        self.assertEqual(self.completed_r1, read(self.run_json("r1")))
        target.write_bytes(original)
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["acceptance_unsettled"], ["probe"])

    def test_failed_run_cannot_launder_its_pass_into_a_completion(self):
        """Ruling 3: a new run cannot complete on the failed run's pass bytes."""
        self.prepare()
        self.draft_pass_then_finish("r1", "failed")
        checklist_before = self.acceptance.read_bytes()
        revisions_before = sorted(p.name for p in self.revisions.glob("*.json"))
        events_before = len(self.events("run_finished"))
        self.ok(self.start("r2"))
        self.ok(self.register("r2"))
        self.rejected(self.finish("r2"))
        self.assertEqual(read(self.run_json("r2"))["status"], "active")
        self.assertNotIn("closure", read(self.run_json("r2")))
        self.assertEqual(checklist_before, self.acceptance.read_bytes())
        self.assertEqual(revisions_before,
                         sorted(p.name for p in self.revisions.glob("*.json")))
        self.assertEqual(events_before, len(self.events("run_finished")))
        # Recording r2's own pass makes its own completion legal again.
        self.ok(self.record("r2"))
        self.ok(self.finish("r2"))
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["completed_runs"], ["r2"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertTrue(handoff["acceptance_complete"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
