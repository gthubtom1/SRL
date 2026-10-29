#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multi-run acceptance history: one immutable checklist revision per completion.

Root cause closed here (independent probe
``work/goal-recovery/independent-probes/terminal-probe-parity.py``, findings
R-L2-1 / R-L2-2):

  R-L2-1  ``acceptance-record`` after a completed run returned rc=0 and made the
          project permanently red (``resume`` rc=2, no CLI way back).
  R-L2-2  ``finish-run`` of a second run rc=0 followed by ``resume`` rc=2 with
          closure errors that all pointed at the *first* run, because the
          version-level checklist singleton was reused for every run and the
          write gate only audited the run being written.

Main-agent ruling implemented in ``project_state.py``:

  1  A completed/failed/blocked/cancelled run's acceptance is frozen:
     ``acceptance-record`` is refused and nothing (checklist / revision chain /
     events) is written.  New facts belong to a new run.
  2  A completed run/migration consumes a **fixed immutable acceptance revision**
     (``closure.acceptance_sha256`` -> ``acceptance-revisions/rev-<sha>.json``
     or the still-current live file).  The live checklist is only the active
     draft/projection; later legal revisions never make an old completion stale.
  3  Each required item's evidence origin must belong to that same run; a new run
     never inherits an earlier run's pass.
  4  A hand-edited live head (no legal appended revision) still fails the
     chain/hash check and blocks; a legal new revision may advance.
  5  The write entries audit the whole formal ledger, so an accepted write can
     never leave ``resume`` red.
  6  Targeted real-CLI coverage of the above (below).
  7  Old corruption / concurrency / migration-history tests keep their meaning:
     ``test_project_acceptance.py``, ``test_acceptance_integrity.py``,
     ``test_closure_consistency.py``, ``test_terminal_history.py``.

Data format is unchanged: same ``seep-acceptance/1`` documents, same
``acceptance-revisions/rev-<sha>.json`` archive, same ``chain.jsonl``; only the
*verification* now resolves the revision a record consumed instead of comparing
it against the current head.  Existing projects stay readable (no migration).

Run: python -B -X utf8 Tool/scripts/test_run_acceptance_history.py
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
NEXT = b"ZZZZZZ\x85\xc0\x74\x22CCCC"
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
                            encoding="utf-8", timeout=120)
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        raise AssertionError((result.returncode, result.stdout[-2000:], result.stderr[-2000:]))
    if result.stderr:
        raise AssertionError(result.stderr[-2000:])
    return result.returncode, payload


def cli(*args):
    return run_script(PROJECT, *args)


class RunHistoryBase(unittest.TestCase):
    """One project, one version (1.1), as many runs as a test needs."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="seep-run-history-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.old = self.base / "old.bin"
        self.new = self.base / "new.bin"
        self.old.write_bytes(OLD)
        self.new.write_bytes(NEXT)
        self.ok(self.p("init", "--project-id", "synthetic-run-history", "--target", self.old))
        self.ok(run_script(MIGRATE, "init", "--case", self.project,
                           "--version", "1.0", "--file", self.old))
        self.ok(self.p("version", "--version", "1.1", "--parent", "1.0", "--target", self.new))
        self.version = read(self.project / "versions/1.1/version.json")
        self.target = self.version["sha256"]
        self.acceptance = self.project / "versions/1.1/acceptance.json"
        self.revisions = self.project / "versions/1.1/acceptance-revisions"
        self.facts = self.project / "facts.jsonl"
        self.manifest = self.project / "versions/1.1/manifest.json"
        self.migration_json = self.project / "versions/1.1/migration.json"
        self.migration_dir = self.project / "versions/1.1/migrations"

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
        """Checklist defined, no result recorded yet."""
        self.ok(self.define())
        return self

    def complete_run(self, run):
        """Honest route: own run, own evidence, own pass, then completion."""
        self.ok(self.start(run))
        self.ok(self.register(run))
        self.ok(self.record(run))
        self.ok(self.finish(run))
        return read(self.run_json(run))

    def frozen_state(self):
        """Bytes a refused write must never touch."""
        frozen = {path: path.read_bytes()
                  for path in (self.acceptance, self.facts, self.manifest)}
        frozen[self.revisions] = sorted((p.name, p.read_bytes())
                                       for p in self.revisions.glob("*"))
        frozen[self.run_json("r1")] = self.run_json("r1").read_bytes()
        return frozen

    def assert_frozen(self, frozen):
        self.assertEqual(frozen[self.acceptance], self.acceptance.read_bytes())
        self.assertEqual(frozen[self.facts], self.facts.read_bytes())
        self.assertEqual(frozen[self.manifest], self.manifest.read_bytes())
        self.assertEqual(frozen[self.revisions],
                         sorted((p.name, p.read_bytes()) for p in self.revisions.glob("*")))
        self.assertEqual(frozen[self.run_json("r1")], self.run_json("r1").read_bytes())

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


class CompletedRunIsFrozen(RunHistoryBase):
    """Ruling 1: a closed run's acceptance can never be written again."""

    def test_record_on_completed_run_is_refused_and_bytes_frozen(self):
        self.prepare()
        completed = self.complete_run("r1")
        self.assertEqual(self.ok(self.resume())["handoff"]["closure_errors"], [])
        frozen = self.frozen_state()
        events_before = len(self.events("acceptance_recorded"))
        revisions_before = sorted(p.name for p in self.revisions.glob("*.json"))
        # Same values, other values, non-pass results: all refused, nothing written.
        for kwargs in ({"result": "pass"},
                       {"result": "fail"},
                       {"result": "unknown"},
                       {"result": "skipped", "item_id": "probe"}):
            with self.subTest(**kwargs):
                rejected = self.rejected(self.record("r1", **kwargs))
                self.assertIn("已收尾 run 的验收不可再修改", rejected["reason"])
        self.assert_frozen(frozen)
        self.assertEqual(events_before, len(self.events("acceptance_recorded")))
        self.assertEqual(revisions_before,
                         sorted(p.name for p in self.revisions.glob("*.json")))
        self.assertEqual(completed, read(self.run_json("r1")))
        # The project stays green: no "legal command turns it permanently red".
        handoff = self.ok(self.resume())["handoff"]
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["acceptance_stale"], [])

    def test_unbound_or_foreign_run_cannot_record(self):
        self.prepare()
        self.ok(self.start("r1"))
        self.ok(self.register("r1"))
        # No --run at all: acceptance must belong to a real run.
        unbound = self.p("acceptance-record", "--version", "1.1", "--item-id", "probe",
                         "--result", "pass", "--evidence-ids", "ev-r1",
                         "--verifier", "v", "--how", "h", "--run", "")
        self.assertIn("--run", self.rejected(unbound)["reason"])
        # A run id that does not exist is refused too.
        self.rejected(self.record("run-absent", evidence_id="ev-r1"))

    def test_failed_and_cancelled_runs_are_frozen_too(self):
        self.prepare()
        self.ok(self.start("r1"))
        self.ok(self.register("r1"))
        self.ok(self.finish("r1", status="failed"))
        frozen = {self.acceptance: self.acceptance.read_bytes(),
                  self.facts: self.facts.read_bytes(), self.run_json("r1"):
                  self.run_json("r1").read_bytes()}
        self.rejected(self.record("r1"))
        self.rejected(self.record("r1", result="fail"))
        for path, body in frozen.items():
            self.assertEqual(body, path.read_bytes(), path)
        # LIFECYCLE-03 §5: the accepted non-completing finish must not turn the
        # next read red.  ``resume`` stays readable/consistent, the draft is
        # reported unfinished (ineligible origin, no pass recorded here), and
        # nothing is described as tampered/chain-damaged.
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["status"], "active")
        self.assertEqual(handoff["state_health"], "ok")
        self.assertEqual(handoff["last_run_status"], "failed")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["acceptance_errors"], [])
        self.assertEqual(handoff["integrity_errors"], [])
        self.assertEqual(handoff["completed_runs"], [])


class SecondRunKeepsHistoryGreen(RunHistoryBase):
    """Rulings 2/3/5: a new run completes and the old completion stays valid."""

    def test_second_run_completes_and_first_run_bytes_unchanged(self):
        self.prepare()
        first = self.complete_run("r1")
        first_seal = first["closure"]["seal_sha256"]
        first_consumed = first["closure"]["acceptance_sha256"]
        r1_bytes = self.run_json("r1").read_bytes()
        r1_revisions = sorted(p.name for p in self.revisions.glob("*.json"))

        second = self.complete_run("r2")
        self.assertNotEqual(first_seal, second["closure"]["seal_sha256"])
        # finish-run rc0 must imply resume rc0 (R-L2-2).
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["status"], "active")
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["completed_runs"], ["r1", "r2"])
        self.assertEqual(r1_bytes, self.run_json("r1").read_bytes())
        self.assertEqual(first_seal, read(self.run_json("r1"))["closure"]["seal_sha256"])
        # The revision r1 consumed is archived verbatim, not re-interpreted.
        archived = self.revisions / ("rev-%s.json" % first_consumed)
        self.assertTrue(archived.is_file())
        self.assertEqual(first_consumed, digest(archived.read_bytes()))
        self.assertTrue(set(r1_revisions) <= {p.name for p in self.revisions.glob("*.json")})
        # r1's own evidence is untouched and both completions re-verify.
        self.assertEqual(read(self.project / "versions/1.1/evidence/ev-r1.json")["run_id"], "r1")
        self.assertEqual(read(self.project / "versions/1.1/evidence/ev-r2.json")["run_id"], "r2")

    def test_second_run_cannot_inherit_the_first_runs_evidence(self):
        self.prepare()
        self.complete_run("r1")
        self.ok(self.start("r2"))
        # Recording r2's pass with r1's evidence id is refused outright.
        rejected = self.rejected(self.record("r2", evidence_id="ev-r1"))
        self.assertIn("pass 证据无效", rejected["reason"])
        self.assertEqual(read(self.run_json("r2"))["status"], "active")
        # Registering r2's evidence but leaving the live pass on r1's evidence
        # cannot open completion either: the pass origin belongs to r1.
        self.ok(self.register("r2"))
        self.rejected(self.finish("r2"))
        self.assertEqual(read(self.run_json("r2"))["status"], "active")
        self.assertNotIn("closure", read(self.run_json("r2")))
        # r1 is not disturbed by the failed attempt.
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["completed_runs"], ["r1"])
        self.assertEqual(handoff["closure_errors"], [])

    def test_interleaved_runs_finish_independently(self):
        """r1 completed; r2 and r3 both active, each completes with own evidence."""
        self.prepare()
        self.complete_run("r1")
        r1_bytes = self.run_json("r1").read_bytes()
        for run in ("r2", "r3"):
            self.ok(self.start(run))
            self.ok(self.register(run))
        # r3 records first: r2 must not be able to close on r3's live witness.
        self.ok(self.record("r3"))
        self.rejected(self.finish("r2"))
        self.assertEqual(read(self.run_json("r2"))["status"], "active")
        # r2 records its own pass, closes, and r3 still closes afterwards.
        self.ok(self.record("r2"))
        self.ok(self.finish("r2"))
        self.ok(self.record("r3"))
        self.ok(self.finish("r3"))
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["completed_runs"], ["r1", "r2", "r3"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["closure_legacy"], [])
        self.assertEqual(r1_bytes, self.run_json("r1").read_bytes())
        seals = [read(self.run_json(run))["closure"]["seal_sha256"]
                 for run in ("r1", "r2", "r3")]
        self.assertEqual(len(set(seals)), 3)


class LiveHeadTampering(RunHistoryBase):
    """Ruling 4: hand edits still block; legal new revisions may advance."""

    def test_hand_edited_live_head_blocks_and_restore_recovers(self):
        self.prepare()
        self.complete_run("r1")
        original = self.acceptance.read_bytes()
        data = json.loads(original.decode("utf-8"))
        data["items"][0]["description"] = "rewritten by hand after completion"
        write(self.acceptance, data)
        result = self.resume()
        self.assertEqual(result[0], 2, result)
        handoff = result[1]["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertFalse(handoff["acceptance_complete"])
        blob = json.dumps([handoff["acceptance_errors"], handoff["closure_errors"]],
                          ensure_ascii=False)
        self.assertIn("写链日志", blob)          # live head is not the log head
        self.assertIn("stale", blob)             # consumed revision no longer live
        self.assertEqual(read(self.run_json("r1"))["status"], "completed")
        # A refused write must not launder the edited head into a revision.
        self.rejected(self.record("r1"))
        self.rejected(self.p("acceptance-define", "--version", "1.1",
                             "--item", "probe:synthetic probe executed"))
        self.acceptance.write_bytes(original)
        handoff = self.ok(self.resume())["handoff"]
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["closure_errors"], [])

    def test_legal_new_revision_advances_without_hurting_history(self):
        self.prepare()
        self.complete_run("r1")
        r1 = read(self.run_json("r1"))
        plain = self.acceptance.read_bytes()
        self.ok(self.start("r2"))
        self.ok(self.register("r2"))
        self.ok(self.record("r2"))
        # No chain error: the draft simply moved forward.
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["acceptance"]["chain_problems"], [])
        self.assertEqual(handoff["acceptance"]["counts"]["pass"], 1)
        self.assertNotEqual(plain, self.acceptance.read_bytes())
        # The revision r1 consumed is byte-identical and still re-verifiable.
        archived = self.revisions / ("rev-%s.json" % r1["closure"]["acceptance_sha256"])
        self.assertEqual(plain, archived.read_bytes())
        self.assertEqual(r1, read(self.run_json("r1")))
        self.ok(self.finish("r2"))
        self.assertEqual(read(self.run_json("r1")), r1)


class MigrationConsumesFixedRevision(RunHistoryBase):
    """Ruling 4: a completed migration keeps its own consumed revision."""

    def test_migration_completion_survives_a_later_run_revision(self):
        self.prepare()
        self.ok(self.start("r1"))
        self.ok(self.register("r1"))
        self.ok(self.record("r1"))
        align = self.prepared_alignment()
        self.ok(self.p("migration", "--source", "1.0", "--target", "1.1",
                       "--align", str(align), "--status", "completed",
                       "--migration-id", "mig-1"))
        migration = read(self.migration_json)
        consumed = migration["closure"]["acceptance_sha256"]
        self.assertEqual(consumed, digest(self.acceptance.read_bytes()))
        migration_bytes = self.migration_json.read_bytes()
        archived_copy = (self.migration_dir /
                         ((migration.get("revision_id") or "") + ".json"))
        archived_bytes = archived_copy.read_bytes()
        self.assertEqual(self.ok(self.resume())["handoff"]["completed_migrations"],
                         ["mig-1"])

        # A later run records a new revision: the migration must not go red.
        self.ok(self.start("r2"))
        self.ok(self.register("r2"))
        self.ok(self.record("r2"))
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["completed_migrations"], ["mig-1"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(migration_bytes, self.migration_json.read_bytes())
        self.assertEqual(archived_bytes, archived_copy.read_bytes())
        fixed = self.revisions / ("rev-%s.json" % consumed)
        self.assertTrue(fixed.is_file(), "consumed revision must stay archived")
        self.assertEqual(consumed, digest(fixed.read_bytes()))
        # And the new run can still close on its own evidence.
        self.ok(self.finish("r2"))
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["completed_runs"], ["r2"])
        self.assertEqual(handoff["completed_migrations"], ["mig-1"])
        self.assertEqual(handoff["closure_errors"], [])

    def test_migration_after_a_completed_run_reuses_the_same_revision(self):
        self.prepare()
        self.complete_run("r1")
        align = self.prepared_alignment()
        self.ok(self.p("migration", "--source", "1.0", "--target", "1.1",
                       "--align", str(align), "--status", "completed",
                       "--migration-id", "mig-1"))
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["completed_runs"], ["r1"])
        self.assertEqual(handoff["completed_migrations"], ["mig-1"])
        self.assertEqual(handoff["closure_errors"], [])
        # Same version-level revision: run and migration consume identical bytes.
        run = read(self.run_json("r1"))
        migration = read(self.migration_json)
        self.assertEqual(run["closure"]["acceptance_sha256"],
                         migration["closure"]["acceptance_sha256"])
        self.assertEqual(len(self.events("run_finished")), 1)
        self.assertEqual(len([e for e in self.events("migration_recorded")
                              if e.get("status") == "completed"]), 1)


class HistoricalRecordStillFailsClosed(RunHistoryBase):
    """Ruling 4: multi-run history does not switch the seal/evidence checks off."""

    def setUp(self):
        super().setUp()
        self.prepare()
        self.complete_run("r1")
        self.complete_run("r2")
        self.assertEqual(self.ok(self.resume())["handoff"]["closure_errors"], [])
        self.r1 = read(self.run_json("r1"))
        self.r2 = read(self.run_json("r2"))

    def test_tampered_old_run_evidence_is_still_stale(self):
        witness = self.project / "versions/1.1/artifacts/r1.log"
        original = witness.read_bytes()
        r2_bytes = self.run_json("r2").read_bytes()
        witness.write_bytes(b"tampered after both runs completed\n")
        result = self.resume()
        self.assertEqual(result[0], 2, result)
        handoff = result[1]["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertIn("验收证据", json.dumps(handoff["closure_errors"], ensure_ascii=False))
        # LIFECYCLE-03 §5/ruling 2: real tampering still blocks *and* is named as
        # an integrity error — it is never hidden behind a non-completing draft.
        self.assertEqual(handoff["state_health"], "blocked")
        self.assertTrue(handoff["integrity_errors"])
        # The live draft belongs to the completed r2, so the damage is reported
        # through the r1 closure audit; either way it is an integrity finding.
        blob = json.dumps([handoff["acceptance_errors"], handoff["closure_errors"]],
                          ensure_ascii=False)
        self.assertIn("验收证据", blob)
        # Neither completed record is rewritten and r2 is not collateral damage.
        self.assertEqual(self.r2, read(self.run_json("r2")))
        self.assertEqual(r2_bytes, self.run_json("r2").read_bytes())
        self.assertEqual(self.r1, read(self.run_json("r1")))
        # Writes stay refused while the ledger is broken.
        self.ok(self.start("r3"))
        self.ok(self.register("r3"))
        self.rejected(self.record("r3"))
        witness.write_bytes(original)
        self.assertEqual(self.ok(self.resume())["handoff"]["closure_errors"], [])

    def test_snapshot_or_seal_tamper_on_an_old_run_is_still_blocked(self):
        original = self.run_json("r1").read_bytes()
        for mutation in ("snapshot-field", "seal", "drop-event", "status-rewind"):
            with self.subTest(mutation=mutation):
                run = json.loads(original.decode("utf-8"))
                if mutation == "snapshot-field":
                    run["acceptance_snapshot"]["required_count"] = 99
                elif mutation == "seal":
                    run["closure"]["seal_sha256"] = "f" * 64
                elif mutation == "drop-event":
                    run.pop("closure", None)
                    run.pop("acceptance_snapshot", None)
                else:
                    run["status"] = "active"
                write(self.run_json("r1"), run)
                handoff = self.rejected(self.resume())["handoff"]
                self.assertEqual(handoff["status"], "blocked")
                self.assertFalse(handoff["acceptance_complete"])
                self.assertTrue(handoff["closure_errors"])
                self.run_json("r1").write_bytes(original)
                self.assertEqual(self.ok(self.resume())["handoff"]["closure_errors"], [])


class WriteGateSharesTheWholeLedger(RunHistoryBase):
    """Ruling 5: no write may be accepted into an already-broken ledger."""

    def test_finish_refuses_when_another_run_is_already_broken(self):
        self.prepare()
        self.complete_run("r1")
        # Corrupt r1 *outside the CLI*: drop the completion event, keep the
        # residual closure (the historical R-A bypass).
        keep = []
        for line in self.facts.read_bytes().splitlines():
            if not line.strip():
                continue
            if json.loads(line.decode("utf-8")).get("type") == "run_finished":
                continue
            keep.append(line)
        self.facts.write_bytes(b"\n".join(keep) + b"\n")
        self.ok(self.start("r2"))
        self.ok(self.register("r2"))
        r2_bytes = self.run_json("r2").read_bytes()
        facts_bytes = self.facts.read_bytes()
        checklist_bytes = self.acceptance.read_bytes()
        revisions_before = sorted((p.name, p.read_bytes())
                                  for p in self.revisions.glob("*"))
        # Both write entries refuse: the conflict is in the ledger, not in r2.
        rejected = self.rejected(self.record("r2"))
        self.assertIn("共用校验", rejected["reason"])
        rejected = self.rejected(self.finish("r2"))
        self.assertIn("共用校验", rejected["reason"])
        self.assertEqual(r2_bytes, self.run_json("r2").read_bytes())
        self.assertEqual(facts_bytes, self.facts.read_bytes())
        self.assertEqual(checklist_bytes, self.acceptance.read_bytes())
        self.assertEqual(revisions_before,
                         sorted((p.name, p.read_bytes()) for p in self.revisions.glob("*")))
        self.assertNotIn("closure", read(self.run_json("r2")))
        self.assertEqual(read(self.run_json("r2"))["status"], "active")

    def test_legal_history_stays_writable(self):
        """Positive control: the wider gate does not turn legal work red."""
        self.prepare()
        self.complete_run("r1")
        self.ok(self.start("r2"))
        self.ok(self.register("r2"))
        self.ok(self.record("r2"))
        self.ok(self.finish("r2"))
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(handoff["completed_runs"], ["r1", "r2"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["closure_legacy"], [])
        # LIFECYCLE-03 §5: multi-run history adds no integrity noise and no
        # ineligible drafts; ``ok`` still means "consistent", not "goal passed".
        self.assertEqual(handoff["state_health"], "ok")
        self.assertEqual(handoff["acceptance_errors"], [])
        self.assertEqual(handoff["integrity_errors"], [])
        self.assertEqual(handoff["acceptance_unsettled"], [])
        self.assertEqual(handoff["last_run_status"], "completed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
