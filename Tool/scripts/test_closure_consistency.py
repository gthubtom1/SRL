#!/usr/bin/env python3
"""Closure-consistency regression: the second audit's three refuted findings.

Every case drives the real ``project_state.py`` CLI in a TemporaryDirectory and
each negative case is paired with a positive control on the *same* fixture, so a
green can never come from a broken fixture.

Closed findings (work/goal-recovery/acceptance-integrity-verification.md, §四):
  R1  ``acceptance_snapshot`` display fields (``target_size`` / ``proof_level`` /
      ``proof_limits`` / ``captured_at``) were not recomputed -> resume rc=0.
  R2  An evidence file *and* its own registration record rewritten consistently
      (``manifest.evidence`` untouched) still let ``finish-run`` return rc=0 and
      write a closure; only the following ``resume`` caught it.
  R3  Deleting ``closure``/``acceptance_snapshot`` and deleting or downgrading
      the checklist re-styled a real completion as ``closure_legacy`` -> resume
      rc=0 with no error.

Design rules exercised here (main-agent rulings A-E):
  A  completion and resume share one evidence-consistency core; a violated
     precondition never writes ``run_finished`` / a completed migration.
  B  the whole closure object is sealed and bound to an append-only event; the
     recomputation never compares two fields of the same editable object.
  C  a completed record without a re-checkable witness is always blocked rc=2
     and never ``ok=true`` / ``acceptance_complete=true``; historical records
     stay readable and un-overwritten.
  D  a completion event contradicting the current status/closure is caught, and
     repeated completion events are rejected.
  E  proof ceiling unchanged: ``structural+recorded_witness``, no signature.

Run: python -B -X utf8 Tool/scripts/test_closure_consistency.py
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
WITNESS = b"synthetic witness\n"

SEAL_FIELD = "seal_sha256"


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run_script(script, *args):
    result = subprocess.run([sys.executable, "-B", str(script), *map(str, args)],
                            cwd=ROOT, env=ENV, capture_output=True, text=True,
                            encoding="utf-8", timeout=90)
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        raise AssertionError((result.returncode, result.stdout[-2000:], result.stderr[-2000:]))
    if result.stderr:
        raise AssertionError(result.stderr[-2000:])
    return result.returncode, payload


def cli(*args):
    return run_script(PROJECT, *args)


class ClosureBase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="seep-closure-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.old = self.base / "old.bin"
        self.new = self.base / "new.bin"
        self.old.write_bytes(OLD)
        self.new.write_bytes(NEXT)
        self.ok(self.p("init", "--project-id", "synthetic-closure", "--target", self.old))
        # Real reverse baseline for 1.0 so migration alignment is a genuine check.
        self.ok(run_script(MIGRATE, "init", "--case", self.project,
                           "--version", "1.0", "--file", self.old))
        self.ok(self.p("version", "--version", "1.1", "--parent", "1.0", "--target", self.new))
        self.version = read(self.project / "versions/1.1/version.json")
        self.target = self.version["sha256"]
        self.witness = self.project / "versions/1.1/artifacts/probe.log"
        self.witness.parent.mkdir(parents=True, exist_ok=True)
        self.witness.write_bytes(WITNESS)
        self.acceptance = self.project / "versions/1.1/acceptance.json"
        self.manifest = self.project / "versions/1.1/manifest.json"
        self.evidence_record = self.project / "versions/1.1/evidence/ev-1.json"
        self.run_json = self.project / "versions/1.1/runs/run-1/run.json"
        self.migration_json = self.project / "versions/1.1/migration.json"
        self.facts = self.project / "facts.jsonl"

    # ---- helpers -------------------------------------------------------
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

    def start(self, run="run-1"):
        return self.p("run", "--version", "1.1", "--run-id", run, "--executor", "test")

    def register(self, evidence_id="ev-1", run="run-1", path=None):
        path = path or self.witness
        relative = path.relative_to(self.project).as_posix()
        body = path.read_bytes()
        return self.p("evidence", "--version", "1.1", "--run-id", run,
                      "--evidence-id", evidence_id,
                      "--target-sha256", self.target, "--path", relative,
                      "--sha256", digest(body), "--size", len(body),
                      "--source", relative, "--how", "synthetic", "--recorded-by", "test")

    def define(self, *items):
        args = ["--version", "1.1"]
        for item in items or ("probe:synthetic probe executed",):
            args.extend(("--item", item))
        return self.p("acceptance-define", *args)

    def record(self, item_id="probe", result="pass", evidence_ids="ev-1",
               verifier="test harness", how="ran synthetic probe", run="run-1"):
        return self.p("acceptance-record", "--version", "1.1", "--item-id", item_id,
                      "--result", result, "--evidence-ids", evidence_ids,
                      "--verifier", verifier, "--how", how, "--run", run)

    def complete(self, run="run-1"):
        return self.p("finish-run", "--version", "1.1", "--run-id", run,
                      "--status", "completed", "--note", "synthetic")

    def resume(self):
        return self.p("resume")

    def events(self, event_type):
        rows = [json.loads(line) for line in
                self.facts.read_text(encoding="utf-8").splitlines() if line.strip()]
        return [row for row in rows if row.get("type") == event_type]

    def prepared(self):
        """Legal chain up to (but excluding) completion."""
        self.ok(self.start())
        self.ok(self.define())
        self.ok(self.register())
        self.ok(self.record())

    def completed(self):
        """Positive control: the only legal route to a completed run."""
        self.prepared()
        self.ok(self.complete())
        handoff = self.ok(self.resume())["handoff"]
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["closure_legacy"], [])
        return handoff

    def handoff(self):
        return read(self.project / "handoff.json")

    def errors(self, handoff):
        return json.dumps([handoff.get("state_errors"), handoff.get("acceptance_errors"),
                           handoff.get("closure_errors")], ensure_ascii=False)


class SnapshotWholeObject(ClosureBase):
    """R1: every snapshot field is recomputed, not a hand-written whitelist."""

    FIELDS = ("target_size", "proof_level", "proof_limits", "captured_at")

    def test_each_display_field_is_recomputed(self):
        self.completed()
        original = self.run_json.read_bytes()
        replacements = {"target_size": 123456, "proof_level": "forged-level",
                        "proof_limits": ["no limits"], "captured_at": "1999-01-01T00:00:00Z"}
        for field in self.FIELDS:
            with self.subTest(field=field):
                run = json.loads(original.decode("utf-8"))
                self.assertIn(field, run["acceptance_snapshot"], "fixture must record it")
                run["acceptance_snapshot"][field] = replacements[field]
                write(self.run_json, run)
                result = self.resume()
                self.assertEqual(result[0], 2, (field, result))
                handoff = result[1]["handoff"]
                self.assertFalse(handoff["acceptance_complete"], field)
                self.assertTrue(handoff["closure_errors"], field)
                self.assertIn('"%s"' % field, self.errors(handoff), field)
                # A tampered snapshot must also not re-open completion.
                self.rejected(self.complete())
        # Positive control restored on the same fixture.
        self.run_json.write_bytes(original)
        handoff = self.ok(self.resume())["handoff"]
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["closure_errors"], [])

    def test_seal_covers_the_whole_object(self):
        self.completed()
        original = read(self.run_json)
        closure = original["closure"]
        self.assertIn(SEAL_FIELD, closure)
        self.assertEqual(len(closure[SEAL_FIELD]), 64)
        # The sealed digest is the *reason* a display-field edit is detectable,
        # so the specific error must name an un-recomputable seal.
        run = json.loads(json.dumps(original))
        run["acceptance_snapshot"]["captured_at"] = "1999-01-01T00:00:00Z"
        write(self.run_json, run)
        handoff = self.rejected(self.resume())["handoff"]
        self.assertIn("封条不可复算", self.errors(handoff))
        # Recomputing one component hash without the seal is still refused.
        write(self.run_json, original)
        run = json.loads(json.dumps(original))
        forged = digest(json.dumps({"no": "such object"}).encode("utf-8"))
        run["closure"]["acceptance_sha256"] = forged
        run["acceptance_snapshot"]["acceptance_sha256"] = forged
        write(self.run_json, run)
        handoff = self.rejected(self.resume())["handoff"]
        self.assertFalse(handoff["acceptance_complete"])
        self.assertIn("封条不可复算", self.errors(handoff))

    def test_snapshot_object_is_exactly_reproducible(self):
        """No field may be reproducible only at completion time."""
        self.completed()
        snapshot = read(self.run_json)["acceptance_snapshot"]
        self.assertEqual(snapshot["captured_at"], read(self.run_json)["closure"]["recorded_at"])
        self.assertEqual(snapshot["target_size"], self.version["size"])
        self.assertEqual(snapshot["proof_level"], "structural+recorded_witness")
        self.assertIn("不证明日志语义", "".join(snapshot["proof_limits"]))
        self.assertNotIn("run_sha256",
                         json.dumps(snapshot["required"], ensure_ascii=False),
                         "run_sha256 is not reproducible at resume time")


class EvidenceGateParity(ClosureBase):
    """R2: the completion gate and resume share one evidence-consistency core."""

    def rewrite_self_consistently(self, body=b"replaced witness\n"):
        """Change the raw file *and* its registration record; leave manifest alone."""
        self.witness.write_bytes(body)
        record = read(self.evidence_record)
        record["sha256"] = digest(body)
        record["size"] = len(body)
        write(self.evidence_record, record)
        return digest(body)

    def test_self_consistent_edit_is_rejected_before_finish(self):
        self.prepared()
        forged = self.rewrite_self_consistently()
        # The manifest index still holds the old hash -> inconsistent.
        manifest = read(self.manifest)
        self.assertNotEqual(manifest["evidence"][0]["sha256"], forged)
        result = self.complete()
        self.assertEqual(result[0], 2, result)
        self.assertIn("manifest", json.dumps(result[1], ensure_ascii=False))
        run = read(self.run_json)
        self.assertEqual(run["status"], "active")
        self.assertNotIn("closure", run)
        self.assertNotIn("acceptance_snapshot", run)
        self.assertEqual(self.events("run_finished"), [],
                         "a rejected completion must not write run_finished")
        # The acceptance revision chain is untouched (no pass was laundered).
        archives = sorted((self.project / "versions/1.1/acceptance-revisions").glob("rev-*.json"))
        self.assertGreaterEqual(len(archives), 2)

    def test_finish_and_resume_agree_after_laundering(self):
        """If finish passes, resume must agree — never 'finish ok, resume error'."""
        self.completed()
        before = self.run_json.read_bytes()
        self.witness.write_bytes(b"replaced witness\n")
        result = self.resume()
        self.assertEqual(result[0], 2, result)
        handoff = result[1]["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertTrue(handoff["acceptance_stale"])
        # The completed record itself is never downgraded/rewritten.
        self.assertEqual(before, self.run_json.read_bytes())

    def test_manifest_edit_alone_is_detected_by_both_gates(self):
        self.prepared()
        self.witness.write_bytes(b"replaced witness\n")
        # Rewriting manifest only: record + file disagree.
        manifest = read(self.manifest)
        manifest["evidence"][0]["sha256"] = digest(b"replaced witness\n")
        manifest["evidence"][0]["size"] = len(b"replaced witness\n")
        write(self.manifest, manifest)
        self.rejected(self.complete())
        self.assertNotIn("closure", read(self.run_json))

    def test_evidence_index_and_record_agree_for_the_legal_chain(self):
        self.completed()
        manifest = read(self.manifest)
        record = read(self.evidence_record)
        entry = next(x for x in manifest["evidence"] if x["evidence_id"] == "ev-1")
        for key in ("sha256", "size", "local_path", "target_sha256", "run_id"):
            self.assertEqual(entry[key], record[key], key)
        self.assertEqual(digest(self.witness.read_bytes()), entry["sha256"])


class NoLegacyLaundering(ClosureBase):
    """R3: a real completion cannot be re-narrated as 'legacy' to clear errors."""

    def strip_closure(self):
        run = read(self.run_json)
        run.pop("closure", None)
        run.pop("acceptance_snapshot", None)
        write(self.run_json, run)

    def test_deleted_closure_stays_blocked(self):
        self.completed()
        self.strip_closure()
        result = self.resume()
        self.assertEqual(result[0], 2, result)
        handoff = result[1]["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertTrue(handoff["closure_errors"])
        # The ledger proves a new-format completion existed -> reported as
        # missing witness, NOT silently downgraded to a legacy record.
        self.assertEqual(handoff["closure_legacy"], [])
        self.assertIn("缺少可复核收尾见证", self.errors(handoff))
        self.assertIn("完成事件存在但收尾快照缺失/损坏", self.errors(handoff))
        run = read(self.run_json)
        self.assertEqual(run["status"], "completed", "history stays readable")
        self.assertEqual(self.events("run_finished")[0].get("status"), "completed")

    def test_deleted_checklist_with_closure_stripped_stays_blocked(self):
        self.completed()
        self.strip_closure()
        self.acceptance.unlink()
        result = self.resume()
        self.assertEqual(result[0], 2, result)
        handoff = result[1]["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertIn("缺少可复核收尾见证", self.errors(handoff))
        self.assertEqual(handoff["closure_legacy"], [])

    def test_downgraded_checklist_with_closure_stripped_stays_blocked(self):
        self.completed()
        self.strip_closure()
        data = read(self.acceptance)
        data["items"][0].update({"status": "pending", "result": None, "evidence_ids": []})
        write(self.acceptance, data)
        result = self.resume()
        self.assertEqual(result[0], 2, result)
        handoff = result[1]["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertIn("缺少可复核收尾见证", self.errors(handoff))
        self.assertEqual(handoff["closure_legacy"], [])

    def test_closure_kept_but_checklist_downgraded_is_reported(self):
        """Keeping the closure does not help: the snapshot must still recompute."""
        self.completed()
        data = read(self.acceptance)
        data["items"][0].update({"status": "pending", "result": None})
        write(self.acceptance, data)
        handoff = self.rejected(self.resume())["handoff"]
        self.assertFalse(handoff["acceptance_complete"])
        self.assertTrue(handoff["closure_errors"])
        self.assertEqual(handoff["completed_runs"], ["run-1"])

    def test_genuine_legacy_record_is_readable_but_never_ok(self):
        """History compatibility = readable + blocked rc2 + never verified (rule C)."""
        self.ok(self.start(run="historic"))
        path = self.project / "versions/1.1/runs/historic/run.json"
        legacy = read(path)
        legacy["status"] = "completed"
        legacy["finished_at"] = "2000-01-01T00:00:00Z"
        write(path, legacy)
        before = path.read_bytes()
        result = self.resume()
        self.assertEqual(result[0], 2, result)
        self.assertFalse(result[1]["ok"])
        handoff = result[1]["handoff"]                       # fully readable report
        self.assertEqual(handoff["status"], "blocked")
        self.assertEqual(handoff["completed_runs"], ["historic"])
        self.assertEqual([x["id"] for x in handoff["closure_legacy"]], ["historic"])
        self.assertFalse(handoff["closure_legacy"][0]["verified"])
        self.assertFalse(handoff["acceptance_complete"])
        self.assertIn("历史 completed", self.errors(handoff))
        # Legacy records are never overwritten by the audit.
        self.assertEqual(before, path.read_bytes())


class CompletionEventIsAuthority(ClosureBase):
    """D: the ledger, not the current status, decides whether completion happened."""

    def test_status_rewrite_to_non_completed_is_caught(self):
        self.completed()
        run = read(self.run_json)
        self.assertEqual(len(self.events("run_finished")), 1)
        for status in ("active", "failed", "blocked", "cancelled"):
            with self.subTest(status=status):
                mutated = dict(run)
                mutated["status"] = status
                write(self.run_json, mutated)
                result = self.resume()
                self.assertEqual(result[0], 2, (status, result))
                handoff = result[1]["handoff"]
                self.assertFalse(handoff["acceptance_complete"])
                self.assertIn("完成事件与当前状态矛盾", self.errors(handoff))
                self.assertEqual(handoff["closure_legacy"], [])
        write(self.run_json, run)
        self.ok(self.resume())

    def test_legacy_run_rewrite_with_completion_event_is_caught(self):
        """A completion event with no current completed run is never 'legacy'."""
        self.prepared()
        self.ok(self.complete())
        run = read(self.run_json)
        run["status"] = "active"
        write(self.run_json, run)
        handoff = self.rejected(self.resume())["handoff"]
        self.assertIn("完成事件与当前状态矛盾", self.errors(handoff))
        self.assertEqual(handoff["closure_legacy"], [])

    def test_repeat_completion_event_is_rejected(self):
        self.completed()
        before = self.run_json.read_bytes()
        events_before = len(self.events("run_finished"))
        run = read(self.run_json)
        run["status"] = "active"          # hand-rolled re-open attempt
        write(self.run_json, run)
        result = self.complete()
        self.assertEqual(result[0], 2, result)
        self.assertIn("completed 完成事件", json.dumps(result[1], ensure_ascii=False))
        self.assertEqual(len(self.events("run_finished")), events_before,
                         "a rejected repeat must not append a second event")
        write(self.run_json, json.loads(before.decode("utf-8")))
        self.ok(self.resume())

    def test_append_only_event_binding(self):
        self.completed()
        events = self.events("run_finished")
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["status"], "completed")
        closure = read(self.run_json)["closure"]
        self.assertEqual(event["closure_sha256"], closure["seal_sha256"])
        self.assertEqual(event["closure_kind"], "run-completed")


class MigrationClosure(ClosureBase):
    """Rules A-D also cover migration completion (not only runs)."""

    def prepared_alignment(self):
        """Real reverse baseline + real alignment (no synthetic align file)."""
        def v(*args):
            return run_script(MIGRATE, *args, "--case", self.project)

        result = v("add-site", "--version", "1.0", "--file", self.old, "--id", "gate",
                   "--sem", "synthetic branch candidate", "--aob", "85 C0 74 ??",
                   "--offset", "4", "--original", "85 C0 74 12")
        self.assertEqual(result[0], 0, result)
        result = v("align", "--old", "1.0", "--new-version", "1.1", "--new", self.new)
        self.assertEqual(result[0], 0, result)
        align = self.project / "versions/1.1/align.json"
        self.assertTrue(align.is_file(), "fixture must produce a real align file")
        return align

    def migration(self, status="completed", align=None, migration_id="up", note=""):
        args = ["--source", "1.0", "--target", "1.1", "--status", status,
                "--migration-id", migration_id]
        align = align or self.prepared_alignment()
        args.extend(("--align", str(align)))
        if note:
            args.extend(("--note", note))
        return self.p("migration", *args)

    def complete_migration(self):
        self.prepared()
        align = self.prepared_alignment()
        self.ok(self.migration(align=align))
        handoff = self.ok(self.resume())["handoff"]
        self.assertEqual(len(handoff["completed_migrations"]), 1)
        self.assertEqual(handoff["closure_errors"], [])
        return handoff

    def test_migration_closure_is_sealed_and_bound_to_event(self):
        self.complete_migration()
        migration = read(self.migration_json)
        self.assertEqual(migration["status"], "completed")
        self.assertIn(SEAL_FIELD, migration["closure"])
        events = self.events("migration_recorded")
        completed = [x for x in events if x.get("status") == "completed"]
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]["closure_sha256"], migration["closure"]["seal_sha256"])
        self.assertEqual(completed[0]["revision_id"], migration["revision_id"])

    def test_migration_snapshot_display_field_is_recomputed(self):
        self.complete_migration()
        original = self.migration_json.read_bytes()
        for field, value in (("target_size", 4242), ("proof_level", "forged"),
                             ("proof_limits", []), ("captured_at", "1999-01-01T00:00:00Z")):
            with self.subTest(field=field):
                migration = json.loads(original.decode("utf-8"))
                migration["acceptance_snapshot"][field] = value
                write(self.migration_json, migration)
                result = self.resume()
                self.assertEqual(result[0], 2, (field, result))
                handoff = result[1]["handoff"]
                self.assertFalse(handoff["acceptance_complete"])
                self.assertIn("封条不可复算", self.errors(handoff))
        self.migration_json.write_bytes(original)
        self.assertEqual(self.ok(self.resume())["handoff"]["closure_errors"], [])

    def test_deleted_migration_closure_stays_blocked(self):
        self.complete_migration()
        migration = read(self.migration_json)
        migration.pop("closure", None)
        migration.pop("acceptance_snapshot", None)
        write(self.migration_json, migration)
        result = self.resume()
        self.assertEqual(result[0], 2, result)
        handoff = result[1]["handoff"]
        self.assertFalse(handoff["acceptance_complete"])
        self.assertIn("缺少可复核收尾见证", self.errors(handoff))
        self.assertEqual(handoff["closure_legacy"], [])

    def test_finish_rejects_inconsistent_evidence_before_migration(self):
        self.prepared()
        witness = self.witness
        witness.write_bytes(b"replaced witness\n")
        record = read(self.evidence_record)
        record["sha256"] = digest(b"replaced witness\n")
        record["size"] = len(b"replaced witness\n")
        write(self.evidence_record, record)
        align = self.prepared_alignment()
        result = self.migration(align=align)
        self.assertEqual(result[0], 2, result)
        self.assertFalse(self.migration_json.exists(),
                         "a rejected completion must not create migration.json")
        self.assertEqual([x for x in self.events("migration_recorded")
                          if x.get("status") == "completed"], [])

    def test_deleted_completed_revision_is_caught(self):
        """Rule D for migrations: the event proves a completion whose record is gone."""
        self.complete_migration()
        align = self.project / "versions/1.1/align.json"
        # A later revision archives the completed one, so it exists independently
        # of the live migration.json projection.
        self.ok(self.migration(status="partial", align=align, note="second revision"))
        archives = sorted((self.project / "versions/1.1/migrations").glob("*.json"))
        completed = [x for x in archives if read(x).get("status") == "completed"]
        self.assertEqual(len(completed), 1, "fixture must archive the completed revision")
        completed[0].unlink()
        self.assertNotEqual(read(self.migration_json).get("status"), "completed")
        result = self.resume()
        self.assertEqual(result[0], 2, result)
        handoff = result[1]["handoff"]
        self.assertFalse(handoff["acceptance_complete"])
        self.assertIn("不可覆盖修订记录缺失", self.errors(handoff))
        self.assertEqual(handoff["closure_legacy"], [])

    def test_migration_status_rewrite_is_caught(self):
        self.complete_migration()
        original = self.migration_json.read_bytes()
        migration = json.loads(original.decode("utf-8"))
        migration["status"] = "partial"
        write(self.migration_json, migration)
        handoff = self.rejected(self.resume())["handoff"]
        self.assertIn("完成事件与当前状态矛盾", self.errors(handoff))
        self.assertFalse(handoff["acceptance_complete"])
        self.migration_json.write_bytes(original)


class TerminalHistoryIsMonotonic(ClosureBase):
    """R-A/R-B (independent acceptance §4): erasing the ledger event plus
    rewriting the status projection must not turn a completion back into
    "never completed", and must not re-open completion.

    These were refuted on the independent probes' locked hashes; the assertions
    below are the regression lock for that repair.  No old assertion is removed
    or weakened — this class only adds cases.
    """

    def erase_finish_events(self):
        rows = [json.loads(line) for line in
                self.facts.read_text(encoding="utf-8").splitlines() if line.strip()]
        keep = [row for row in rows if row.get("type") != "run_finished"]
        self.facts.write_bytes(b"".join(
            (json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8") for row in keep))
        return len(rows) - len(keep)

    def prepared_alignment(self):
        """Real reverse baseline + real alignment (no synthetic align file)."""
        def v(*args):
            return run_script(MIGRATE, *args, "--case", self.project)

        result = v("add-site", "--version", "1.0", "--file", self.old, "--id", "gate",
                   "--sem", "synthetic branch candidate", "--aob", "85 C0 74 ??",
                   "--offset", "4", "--original", "85 C0 74 12")
        self.assertEqual(result[0], 0, result)
        result = v("align", "--old", "1.0", "--new-version", "1.1", "--new", self.new)
        self.assertEqual(result[0], 0, result)
        align = self.project / "versions/1.1/align.json"
        self.assertTrue(align.is_file(), "fixture must produce a real align file")
        return align

    def migration(self, status="completed", align=None, migration_id="up", note=""):
        args = ["--source", "1.0", "--target", "1.1", "--status", status,
                "--migration-id", migration_id, "--align", str(align)]
        if note:
            args.extend(("--note", note))
        return self.p("migration", *args)

    def test_deleted_event_with_active_rewrite_stays_blocked(self):
        self.completed()
        self.assertEqual(self.erase_finish_events(), 1)
        run = read(self.run_json)
        self.assertIn("closure", run, "fixture must leave the closure behind")
        run["status"] = "active"
        write(self.run_json, run)
        frozen = self.run_json.read_bytes()
        result = self.resume()
        self.assertEqual(result[0], 2, result)
        handoff = result[1]["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertNotIn("run-1", handoff["completed_runs"])
        self.assertEqual(handoff["closure_legacy"], [])
        blob = self.errors(handoff)
        self.assertIn("残留收尾记录", blob)
        self.assertIn("缺少可复核收尾见证", blob)
        # The same run must not be re-completable (T2/T3: no overwrite).
        rejected = self.rejected(self.complete())
        self.assertIn("共用校验", json.dumps(rejected, ensure_ascii=False))
        self.assertEqual(self.events("run_finished"), [])
        self.assertEqual(frozen, self.run_json.read_bytes())

    def test_deleted_event_with_non_completed_terminal_states(self):
        """failed/blocked/cancelled are not a way to launder the conflict."""
        self.completed()
        original = read(self.run_json)
        for status in ("failed", "blocked", "cancelled"):
            with self.subTest(status=status):
                self.run_json.write_bytes(
                    (json.dumps(original, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
                self.erase_finish_events()
                mutated = dict(original)
                mutated["status"] = status
                write(self.run_json, mutated)
                frozen = self.run_json.read_bytes()
                handoff = self.rejected(self.resume())["handoff"]
                self.assertFalse(handoff["acceptance_complete"], status)
                self.assertEqual(handoff["closure_legacy"], [], status)
                self.assertIn("残留收尾记录", self.errors(handoff), status)
                self.rejected(self.complete())
                self.assertEqual(frozen, self.run_json.read_bytes(), status)

    def test_manifest_and_revision_bytes_survive_a_refused_write(self):
        self.completed()
        watched = [self.manifest, self.acceptance]
        watched += sorted((self.project / "versions/1.1/acceptance-revisions").glob("*.json"))
        before = {path: path.read_bytes() for path in watched}
        self.erase_finish_events()
        run = read(self.run_json)
        run["status"] = "active"
        write(self.run_json, run)
        frozen_run = self.run_json.read_bytes()
        self.rejected(self.complete())
        self.assertEqual(frozen_run, self.run_json.read_bytes())
        self.assertEqual(before, {path: path.read_bytes() for path in watched})

    def test_deleted_migration_event_with_partial_rewrite_stays_blocked(self):
        """R-B: the same手法 on migration must also be refused."""
        self.prepared()
        align = self.prepared_alignment()
        self.ok(self.migration(align=align))
        self.ok(self.resume())
        rows = self.facts.read_text(encoding="utf-8").splitlines()
        keep = [line for line in rows
                if json.loads(line).get("type") != "migration_recorded"]
        self.facts.write_bytes(b"".join((line + "\n").encode("utf-8") for line in keep))
        migration = read(self.migration_json)
        self.assertIn("closure", migration)
        migration["status"] = "partial"
        write(self.migration_json, migration)
        frozen = self.migration_json.read_bytes()
        handoff = self.rejected(self.resume())["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(handoff["completed_migrations"], [])
        self.assertEqual(handoff["closure_legacy"], [])
        self.assertIn("残留收尾记录", self.errors(handoff))
        # Re-registering a new revision is not a way to wash the conflict away.
        rejected = self.rejected(self.migration(align=align, status="partial"))
        self.assertIn("共用校验", json.dumps(rejected, ensure_ascii=False))
        self.assertEqual(frozen, self.migration_json.read_bytes())

    def test_positive_controls_still_green(self):
        """Guard against \"always red\": the honest chains stay rc=0."""
        handoff = self.completed()
        self.assertEqual(handoff["completed_runs"], ["run-1"])
        align = self.prepared_alignment()
        self.ok(self.migration(align=align))
        handoff = self.ok(self.resume())["handoff"]
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["completed_migrations"], ["up"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["closure_legacy"], [])


class PositiveControl(ClosureBase):
    """The formal CLI chain still completes rc=0 with a sealed, bound closure."""

    def test_full_cli_chain_still_returns_rc0(self):
        handoff = self.completed()
        self.assertEqual(handoff["status"], "active")
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["completed_runs"], ["run-1"])
        run = read(self.run_json)
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["closure"]["target_sha256"], self.target)
        self.assertEqual(run["closure"]["evidence_sha256"],
                         {"ev-1": digest(WITNESS)})
        self.assertEqual(run["acceptance_snapshot"]["acceptance_sha256"],
                         digest(self.acceptance.read_bytes()))
        self.assertEqual(run["acceptance_snapshot"]["target_size"], self.version["size"])
        self.assertEqual(run["acceptance_snapshot"]["captured_at"],
                         run["closure"]["recorded_at"])
        events = self.events("run_finished")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["closure_sha256"], run["closure"]["seal_sha256"])
        # Proof ceiling unchanged.
        self.assertEqual(handoff["proof_level"], "structural+recorded_witness")
        self.assertIn("不承诺抵御有意的一致多文件重写", "".join(handoff["proof_limits"]))
        # A resume after a resume stays stable (no self-invalidating audit).
        self.assertEqual(self.ok(self.resume())["handoff"]["closure_errors"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
