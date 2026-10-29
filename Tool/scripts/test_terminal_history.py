#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Terminal-history monotonicity: run / migration final states must agree with
*every* residual formal witness, not only with the current status projection.

Background (independent acceptance, work/goal-recovery/lifecycle-independent-acceptance.md
§4 R-A / R-B, minimal repro in independent-probes/probe_laundering.py):
deleting the append-only ``run_finished`` / ``migration_recorded`` event *and*
rewriting the projection status was enough to make a prior completion look like
"never happened": ``resume`` returned rc=0 with ``completed_runs=[]`` and the same
run could be completed a second time (overwriting the recorded closure).

Rules exercised here (all through the real CLIs, real files, real facts.jsonl):

  T1  A residual ``closure``/``acceptance_snapshot`` is a formal witness on its
      own: status rewrites to active/partial/failed/blocked/cancelled are reported
      as contradictions, never laundered into "never completed" (rc=2, blocked).
  T2  Neither ``finish-run`` nor ``migration`` may write while such a conflict
      exists: both share one pre-write validation with ``resume``.
  T3  A completion is never overwritten in place: repeated requests are refused
      with no new event, no new closure, and byte-identical history files.
  T4  An immutable migration revision copy that still says ``completed`` cannot be
      hidden behind a mutable ``migration.json`` projection, and registering a
      *new* revision is not an accepted way to launder that conflict.
  T5  A run/migration with no witness at all stays readable but unverified (rc=2).
  T6  Positive controls: a complete, honest run and migration both stay rc=0, and
      concurrency still has exactly one winner.

Every negative case snapshots the relevant bytes and asserts they are unchanged.

Run: python -B -X utf8 Tool/scripts/test_terminal_history.py
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "Tool/scripts/project_state.py"
MIGRATE = ROOT / "Tool/skill/softseep/scripts/version-migrate.py"
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
OLD = b"AAAA\x85\xc0\x74\x12BBBB"
NEXT = b"ZZZZZZ\x85\xc0\x74\x22CCCC"
WITNESS = b"synthetic witness\n"


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run_script(script, *args, cwd=ROOT):
    result = subprocess.run([sys.executable, "-B", str(script), *map(str, args)],
                            cwd=cwd, env=ENV, capture_output=True, text=True,
                            encoding="utf-8", timeout=120)
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        raise AssertionError((result.returncode, result.stdout[-2000:], result.stderr[-2000:]))
    if result.stderr:
        raise AssertionError(result.stderr[-2000:])
    return result.returncode, payload


def cli(*args, cwd=ROOT):
    return run_script(PROJECT, *args, cwd=cwd)


class TerminalHistoryBase(unittest.TestCase):
    """One honest, completed fixture, plus helpers to erase/rewrite history."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="seep-terminal-history-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.old = self.base / "old.bin"
        self.new = self.base / "new.bin"
        self.old.write_bytes(OLD)
        self.new.write_bytes(NEXT)
        self.ok(self.p("init", "--project-id", "synthetic-terminal", "--target", self.old))
        self.ok(run_script(MIGRATE, "init", "--case", self.project,
                           "--version", "1.0", "--file", self.old))
        self.ok(self.p("version", "--version", "1.1", "--parent", "1.0", "--target", self.new))
        self.version = read(self.project / "versions/1.1/version.json")
        self.target = self.version["sha256"]
        self.witness = self.project / "versions/1.1/artifacts/probe.log"
        self.witness.parent.mkdir(parents=True, exist_ok=True)
        self.witness.write_bytes(WITNESS)
        self.run_json = self.project / "versions/1.1/runs/run-1/run.json"
        self.migration_json = self.project / "versions/1.1/migration.json"
        self.migration_dir = self.project / "versions/1.1/migrations"
        self.manifest = self.project / "versions/1.1/manifest.json"
        self.acceptance = self.project / "versions/1.1/acceptance.json"
        self.revisions = self.project / "versions/1.1/acceptance-revisions"
        self.facts = self.project / "facts.jsonl"

    # ---- plumbing ------------------------------------------------------
    def p(self, command, *args):
        # Every child process writes only below this test's TemporaryDirectory.
        # Some Windows shell helpers interpret ``$null`` as a literal filename;
        # using ROOT here could leak that artifact into the repository.
        return cli(command, "--project", self.project, *args, cwd=self.base)

    def ok(self, result):
        self.assertEqual(result[0], 0, result)
        self.assertTrue(result[1]["ok"], result)
        return result[1]

    def rejected(self, result):
        self.assertEqual(result[0], 2, result)
        self.assertFalse(result[1]["ok"], result)
        return result[1]

    def start(self, run="run-1"):
        return self.p("run", "--version", "1.1", "--run-id", run, "--executor", "test")

    def register(self, evidence_id="ev-1"):
        body = self.witness.read_bytes()
        relative = self.witness.relative_to(self.project).as_posix()
        return self.p("evidence", "--version", "1.1", "--run-id", "run-1",
                      "--evidence-id", evidence_id, "--target-sha256", self.target,
                      "--path", relative, "--sha256", digest(body), "--size", len(body),
                      "--source", relative, "--how", "synthetic", "--recorded-by", "test")

    def define(self):
        return self.p("acceptance-define", "--version", "1.1",
                      "--item", "probe:synthetic probe executed")

    def record(self, item_id="probe", result="pass", evidence_ids="ev-1"):
        return self.p("acceptance-record", "--version", "1.1", "--item-id", item_id,
                      "--result", result, "--evidence-ids", evidence_ids,
                      "--verifier", "test harness", "--how", "ran synthetic probe",
                      "--run", "run-1")

    def complete(self):
        return self.p("finish-run", "--version", "1.1", "--run-id", "run-1",
                      "--status", "completed", "--note", "synthetic")

    def resume(self):
        return self.p("resume")

    def events(self, event_type):
        rows = [json.loads(line) for line in
                self.facts.read_text(encoding="utf-8").splitlines() if line.strip()]
        return [row for row in rows if row.get("type") == event_type]

    def prepared(self):
        self.ok(self.start())
        self.ok(self.define())
        self.ok(self.register())
        self.ok(self.record())

    def completed_run(self):
        self.prepared()
        self.ok(self.complete())
        handoff = self.ok(self.resume())["handoff"]
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["closure_errors"], [])
        return handoff

    # ---- history erasure / rewriting -----------------------------------
    def erase_events(self, event_type):
        """Delete every event of one type; returns how many were removed."""
        keep = []
        removed = 0
        for line in self.facts.read_bytes().splitlines():
            if not line.strip():
                continue
            if json.loads(line.decode("utf-8")).get("type") == event_type:
                removed += 1
                continue
            keep.append(line)
        self.facts.write_bytes(b"\n".join(keep) + b"\n")
        return removed

    def rewrite_status(self, path, status):
        value = read(path)
        value["status"] = status
        write(path, value)
        return value

    def strip_closure(self, path):
        value = read(path)
        value.pop("closure", None)
        value.pop("acceptance_snapshot", None)
        write(path, value)
        return value

    def guard_bytes(self, *paths):
        """Snapshot bytes that a refused write must never touch."""
        return {path: path.read_bytes() for path in paths}

    def assert_unchanged(self, snapshot):
        for path, body in snapshot.items():
            self.assertEqual(body, path.read_bytes(),
                             "refused operation modified %s" % path)

    def history_paths(self):
        paths = [self.manifest, self.acceptance]
        paths += sorted(self.revisions.glob("*.json"))
        paths += sorted(self.migration_dir.glob("*.json"))
        if self.migration_json.is_file():
            paths.append(self.migration_json)
        if self.run_json.is_file():
            paths.append(self.run_json)
        return paths

    # ---- migration fixture ---------------------------------------------
    def prepared_alignment(self):
        result = run_script(MIGRATE, "add-site", "--case", self.project,
                            "--version", "1.0", "--file", self.old, "--id", "gate",
                            "--sem", "synthetic branch candidate", "--aob", "85 C0 74 ??",
                            "--offset", "4", "--original", "85 C0 74 12",
                            cwd=self.base)
        self.assertEqual(result[0], 0, result)
        result = run_script(MIGRATE, "align", "--case", self.project, "--old", "1.0",
                            "--new-version", "1.1", "--new", self.new,
                            cwd=self.base)
        self.assertEqual(result[0], 0, result)
        align = self.project / "versions/1.1/align.json"
        self.assertTrue(align.is_file(), "fixture must produce a real align file")
        return align

    def migration(self, status="completed", align=None, migration_id="up", note=""):
        args = ["--source", "1.0", "--target", "1.1", "--status", status,
                "--migration-id", migration_id, "--align", str(align or self.align)]
        if note:
            args.extend(("--note", note))
        return self.p("migration", *args)

    def completed_migration(self):
        self.prepared()
        self.align = self.prepared_alignment()
        self.ok(self.migration())
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["completed_migrations"], ["up"])
        self.assertEqual(handoff["closure_errors"], [])
        return handoff

    def residual_witness_reported(self, handoff, ident):
        blob = json.dumps(handoff.get("closure_errors"), ensure_ascii=False)
        self.assertIn("残留收尾记录", blob, blob)
        self.assertIn(ident, blob, blob)


class RunTerminalMonotonicity(TerminalHistoryBase):
    """T1: a run's terminal state may not be rewritten away from its witnesses."""

    def test_deleted_event_plus_active_status_is_blocked(self):
        self.completed_run()
        before = self.guard_bytes(*self.history_paths())
        events_before = len(self.events("run_finished"))
        self.erase_events("run_finished")
        self.rewrite_status(self.run_json, "active")
        run_after_rewrite = self.run_json.read_bytes()
        handoff = self.rejected(self.resume())["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertNotIn("r1", handoff["completed_runs"])
        self.assertEqual(handoff["closure_legacy"], [],
                         "a residual closure must never be re-styled as legacy")
        self.residual_witness_reported(handoff, "run-1")
        # T2 + T3: the write gate refuses, and nothing (history, closure, event)
        # is created or overwritten.
        rejected = self.rejected(self.complete())
        self.assertIn("共用校验", json.dumps(rejected, ensure_ascii=False))
        self.assertEqual(len(self.events("run_finished")), events_before - 1)
        self.assertEqual(run_after_rewrite, self.run_json.read_bytes())
        untouched = {k: v for k, v in before.items() if k != self.run_json}
        self.assert_unchanged(untouched)

    def test_deleted_event_plus_failed_blocked_cancelled_are_blocked(self):
        self.completed_run()
        original = self.run_json.read_bytes()
        facts = self.facts.read_bytes()
        for status in ("failed", "blocked", "cancelled", "active"):
            with self.subTest(status=status):
                # Restore the completed fixture, then erase the event once.
                self.run_json.write_bytes(original)
                self.facts.write_bytes(facts)
                self.assertEqual(self.erase_events("run_finished"), 1,
                                 "fixture must really drop the completion event")
                self.rewrite_status(self.run_json, status)
                frozen = self.run_json.read_bytes()
                handoff = self.rejected(self.resume())["handoff"]
                self.assertEqual(handoff["status"], "blocked")
                self.assertFalse(handoff["acceptance_complete"])
                self.assertEqual(handoff["closure_legacy"], [])
                self.residual_witness_reported(handoff, "run-1")
                self.rejected(self.complete())
                self.assertEqual(frozen, self.run_json.read_bytes())
                self.assertEqual(self.events("run_finished"), [])

    def test_deleted_event_only_is_blocked(self):
        """Even without any status rewrite the erasure is a contradiction."""
        self.completed_run()
        self.erase_events("run_finished")
        handoff = self.rejected(self.resume())["handoff"]
        self.assertFalse(handoff["acceptance_complete"])
        self.assertTrue(handoff["closure_errors"])
        self.assertEqual(handoff["closure_legacy"], [])
        self.rejected(self.complete())

    def test_deleted_closure_but_event_remains_is_blocked(self):
        """T1 (other direction): drop the closure, keep the sealed event."""
        self.completed_run()
        frozen = self.run_json.read_bytes()
        self.strip_closure(self.run_json)
        handoff = self.rejected(self.resume())["handoff"]
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(handoff["closure_legacy"], [])
        self.assertIn("缺少可复核收尾见证",
                      json.dumps(handoff["closure_errors"], ensure_ascii=False))
        self.assertEqual(len(self.events("run_finished")), 1)
        self.rejected(self.complete())
        self.assertEqual(1, len(self.events("run_finished")))
        self.assertNotEqual(frozen, self.run_json.read_bytes(),
                            "fixture check: the closure really was removed")

    def test_unwitnessed_completed_run_is_readable_but_rc2(self):
        """T5: no witness at all -> readable, unverified, never ok."""
        self.ok(self.start(run="historic"))
        path = self.project / "versions/1.1/runs/historic/run.json"
        value = read(path)
        value["status"] = "completed"
        value["finished_at"] = "2000-01-01T00:00:00Z"
        write(path, value)
        frozen = path.read_bytes()
        result = self.resume()
        self.assertEqual(result[0], 2, result)
        self.assertFalse(result[1]["ok"])
        handoff = result[1]["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertEqual([x["id"] for x in handoff["closure_legacy"]], ["historic"])
        self.assertFalse(handoff["closure_legacy"][0]["verified"])
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(frozen, path.read_bytes())


class MigrationTerminalMonotonicity(TerminalHistoryBase):
    """T1/T4: the same rules for migration, including immutable revision copies."""

    def test_deleted_event_plus_partial_status_is_blocked(self):
        self.completed_migration()
        revision = read(self.migration_json)["revision_id"]
        archive = self.migration_dir / (revision + ".json")
        before = self.guard_bytes(*self.history_paths())
        self.erase_events("migration_recorded")
        self.rewrite_status(self.migration_json, "partial")
        frozen = self.migration_json.read_bytes()
        handoff = self.rejected(self.resume())["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(handoff["completed_migrations"], [])
        self.assertEqual(handoff["closure_legacy"], [])
        self.residual_witness_reported(handoff, "up")
        # T4: a new revision is not a way to launder the conflict, and the
        # immutable archive is never rewritten.
        for status in ("completed", "partial", "planned", "blocked"):
            with self.subTest(status=status):
                rejected = self.rejected(self.migration(status=status))
                self.assertIn("共用校验", json.dumps(rejected, ensure_ascii=False))
                self.assertEqual(frozen, self.migration_json.read_bytes())
        self.assertEqual(len(list(self.migration_dir.glob("*.json"))), 1)
        untouched = {k: v for k, v in before.items() if k != self.migration_json}
        self.assert_unchanged(untouched)
        self.assertTrue(archive.is_file())

    def test_deleted_event_plus_blocked_status_is_blocked(self):
        self.completed_migration()
        self.erase_events("migration_recorded")
        self.rewrite_status(self.migration_json, "blocked")
        handoff = self.rejected(self.resume())["handoff"]
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(handoff["closure_legacy"], [])
        self.residual_witness_reported(handoff, "up")
        self.rejected(self.migration())

    def test_projection_downgrade_cannot_hide_completed_archive(self):
        """T4: the immutable copy still says completed -> contradiction.

        The ledger event is erased too, so the *only* remaining witness is the
        immutable ``migrations/<rev>.json`` copy.  The mutable projection must
        not be able to hide it by downgrading its own status.
        """
        self.completed_migration()
        revision = read(self.migration_json)["revision_id"]
        archive = self.migration_dir / (revision + ".json")
        archived = archive.read_bytes()
        self.assertEqual(read(archive)["status"], "completed")
        self.erase_events("migration_recorded")
        projection = read(self.migration_json)
        projection["status"] = "partial"
        projection.pop("closure", None)
        projection.pop("acceptance_snapshot", None)
        write(self.migration_json, projection)
        handoff = self.rejected(self.resume())["handoff"]
        self.assertFalse(handoff["acceptance_complete"])
        blob = json.dumps(handoff["closure_errors"], ensure_ascii=False)
        self.assertIn("不可覆盖修订副本仍记录 completed", blob, blob)
        self.assertEqual(archived, archive.read_bytes(),
                         "the immutable revision is never rewritten")
        self.rejected(self.migration(status="partial"))

    def test_deleted_archive_with_event_remaining_is_blocked(self):
        self.completed_migration()
        revision = read(self.migration_json)["revision_id"]
        archive = self.migration_dir / (revision + ".json")
        # A later revision archives the completed one, so the completed record
        # exists independently of the live migration.json projection.
        self.ok(self.migration(status="partial", note="second revision"))
        self.assertNotEqual(read(self.migration_json)["status"], "completed")
        archive.unlink()
        handoff = self.rejected(self.resume())["handoff"]
        self.assertFalse(handoff["acceptance_complete"])
        self.assertIn("不可覆盖修订记录缺失",
                      json.dumps(handoff["closure_errors"], ensure_ascii=False))
        self.assertEqual(len([x for x in self.events("migration_recorded")
                              if x.get("status") == "completed"]), 1,
                         "the refused audit must not touch the ledger")

    def test_repeat_completion_archives_without_overwriting(self):
        """T3: revisiting the same migration id never overwrites history."""
        self.completed_migration()
        first = self.migration_json.read_bytes()
        first_revision = read(self.migration_json)["revision_id"]
        archive = self.migration_dir / (first_revision + ".json")
        frozen_archive = archive.read_bytes()
        self.ok(self.migration(status="partial", note="second revision"))
        second = read(self.migration_json)
        self.assertNotEqual(first_revision, second["revision_id"])
        self.assertEqual(second["status"], "partial")
        self.assertEqual(frozen_archive, archive.read_bytes(),
                         "the earlier completed revision stays byte-identical")
        self.assertEqual(1, len([x for x in self.migration_dir.glob("*.json")
                                 if read(x)["status"] == "completed"]))
        self.assertNotEqual(first, self.migration_json.read_bytes())
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["completed_migrations"], ["up"])


class RepeatCompletionIsNotAnOverwrite(TerminalHistoryBase):
    """T3: completion is written once; repeated requests change nothing."""

    def test_repeat_completion_preserves_every_byte(self):
        self.completed_run()
        run_before = self.run_json.read_bytes()
        closure = read(self.run_json)["closure"]
        revisions_before = sorted((p.name, p.read_bytes()) for p in self.revisions.glob("*.json"))
        manifest_before = self.manifest.read_bytes()
        events_before = self.events("run_finished")
        self.assertEqual(len(events_before), 1)
        # Straight repeat (status already completed): refused, no new event.
        self.rejected(self.complete())
        # Hand-rolled re-open (status active, event intact): refused as contradictory.
        self.rewrite_status(self.run_json, "active")
        reopened = self.run_json.read_bytes()
        result = self.rejected(self.complete())
        self.assertIn("completed 完成事件", json.dumps(result, ensure_ascii=False))
        self.assertEqual(reopened, self.run_json.read_bytes())
        # A same-id run with genuinely new content is not "idempotent" either.
        self.run_json.write_bytes(run_before)
        self.assertEqual(run_before, self.run_json.read_bytes())
        self.assertEqual(events_before, self.events("run_finished"))
        self.assertEqual(closure["seal_sha256"],
                         read(self.run_json)["closure"]["seal_sha256"])
        self.assertEqual(manifest_before, self.manifest.read_bytes())
        self.assertEqual(revisions_before,
                         sorted((p.name, p.read_bytes()) for p in self.revisions.glob("*.json")))
        self.ok(self.resume())


class FormalPositiveControls(TerminalHistoryBase):
    """T6: honest completions must stay green (no "always red" regression)."""

    def test_honest_run_completion_is_rc0(self):
        handoff = self.completed_run()
        self.assertEqual(handoff["completed_runs"], ["run-1"])
        self.assertEqual(handoff["closure_legacy"], [])
        run = read(self.run_json)
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["closure"]["target_sha256"], self.target)
        events = self.events("run_finished")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["closure_sha256"], run["closure"]["seal_sha256"])
        self.assertEqual(self.ok(self.resume())["handoff"]["closure_errors"], [])

    def test_honest_migration_completion_is_rc0(self):
        handoff = self.completed_migration()
        migration = read(self.migration_json)
        self.assertEqual(migration["status"], "completed")
        self.assertIn("seal_sha256", migration["closure"])
        completed = [x for x in self.events("migration_recorded")
                     if x.get("status") == "completed"]
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]["closure_sha256"], migration["closure"]["seal_sha256"])
        self.assertEqual(self.ok(self.resume())["handoff"]["closure_errors"], [])

    def test_run_and_migration_together_stay_rc0(self):
        self.completed_run()
        self.align = self.prepared_alignment()
        self.ok(self.migration())
        handoff = self.ok(self.resume())["handoff"]
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["completed_runs"], ["run-1"])
        self.assertEqual(handoff["completed_migrations"], ["up"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["closure_legacy"], [])


class ConcurrentCompletionStillSingleWinner(TerminalHistoryBase):
    """T6: the extra validation must not break the lock/single-winner property."""

    def test_concurrent_finish_has_exactly_one_success(self):
        self.prepared()
        workers = 6
        barrier = threading.Barrier(workers)

        def finish(_):
            barrier.wait(timeout=30)
            return self.complete()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(finish, range(workers)))
        self.assertEqual(sorted(rc for rc, _ in results), [0] + [2] * (workers - 1), results)
        self.assertEqual(len(self.events("run_finished")), 1)
        run = read(self.run_json)
        self.assertEqual(run["status"], "completed")
        self.assertIn("closure", run)
        self.assertTrue(self.ok(self.resume())["handoff"]["acceptance_complete"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
