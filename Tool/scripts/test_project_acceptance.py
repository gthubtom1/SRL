#!/usr/bin/env python3
"""Synthetic acceptance-chain regression over the real CLI.

Every case runs `project_state.py` (and `version-migrate.py` for align) as a
subprocess against TemporaryDirectory data.  No target binary is executed and no
real log is interpreted: evidence here is synthetic witness text, so a pass only
demonstrates the structural + recorded_witness chain, not domain acceptance.

Run: python -B -X utf8 Tool/scripts/test_project_acceptance.py
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
REVERSE = ROOT / "Tool/skill/softseep/scripts/version-migrate.py"
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
PATTERN = "85 C0 74 ??"
OLD = b"AAAA\x85\xc0\x74\x12BBBB"
NEXT = b"ZZZZZZ\x85\xc0\x74\x22CCCC"


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def cli(script, *args):
    result = subprocess.run([sys.executable, "-B", str(script), *map(str, args)],
                            cwd=ROOT, env=ENV, capture_output=True, text=True,
                            encoding="utf-8", timeout=60)
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        raise AssertionError((result.returncode, result.stdout[-2000:], result.stderr[-2000:]))
    if result.stderr:
        raise AssertionError(result.stderr[-2000:])
    return result.returncode, payload


class AcceptanceChain(unittest.TestCase):
    """Positive control plus every documented rejection path."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="seep-acceptance-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.old = self.base / "old.bin"
        self.new = self.base / "new.bin"
        self.old.write_bytes(OLD)
        self.new.write_bytes(NEXT)
        self.old_sha = digest(OLD)
        self.new_sha = digest(NEXT)
        self.ok(self.p("init", "--project-id", "synthetic-acceptance", "--target", self.old))
        self.ok(self.v("init", "--version", "1.0", "--file", self.old))
        self.upgrade()

    def test_tool_run_json_is_evidence_but_lifecycle_run_is_not(self):
        self.ok(self.start_run())
        lifecycle = self.project / "versions/1.1/runs/run-1/run.json"
        before = lifecycle.read_bytes()
        self.rejected(self.register(path=lifecycle, evidence_id="ev-metadata"))
        output = self.witness("run.json", b'{"argv":["tool","--readonly"],"rc":0,"stdout":"fixture result"}\n')
        self.ok(self.register(path=output, evidence_id="ev-tool-output"))
        external_layout = self.project / "runs/live-001/run.json"
        external_layout.parent.mkdir(parents=True)
        external_layout.write_bytes(output.read_bytes())
        self.ok(self.register(path=external_layout, evidence_id="ev-domain-output"))
        self.assertEqual(lifecycle.read_bytes(), before)

    # ---- helpers -------------------------------------------------------
    def p(self, command, *args):
        return cli(PROJECT, command, "--project", self.project, *args)

    def v(self, command, *args):
        return cli(REVERSE, command, "--case", self.project, *args)

    def ok(self, result):
        self.assertEqual(result[0], 0, result)
        self.assertTrue(result[1]["ok"], result)
        return result[1]

    def rejected(self, result):
        self.assertEqual(result[0], 2, result)
        self.assertFalse(result[1]["ok"], result)
        return result[1]

    def upgrade(self, version="1.1", parent="1.0", data=None):
        if not (self.project / ("versions/%s/version.json" % version)).exists():
            self.ok(self.p("version", "--version", version, "--parent", parent, "--target", self.new))
        return self.project / ("versions/%s/version.json" % version)

    def target_sha(self, version="1.1"):
        return read(self.project / ("versions/%s/version.json" % version))["sha256"]

    def witness(self, name="probe.log", body=b"synthetic witness\n", version="1.1"):
        path = self.project / ("versions/%s/artifacts/%s" % (version, name))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return path

    def register(self, version="1.1", run="run-1", evidence_id="ev-1", path=None,
                 sha=None, size=None, kind="evidence", source=None, target=None, raw_output=None):
        path = path or self.witness()
        relative = path.relative_to(self.project).as_posix()
        extra = ["--raw-output", raw_output.relative_to(self.project).as_posix()] if raw_output else []
        return self.p("evidence", "--version", version, "--run-id", run, "--kind", kind,
                      "--evidence-id", evidence_id,
                      "--target-sha256", target or self.target_sha(version),
                      "--path", relative, "--sha256", sha or digest(path.read_bytes()),
                      "--size", path.stat().st_size if size is None else size,
                      "--source", source or relative, "--how", "synthetic check",
                      "--recorded-by", "test", *extra)

    def define(self, version="1.1", items=("probe:synthetic probe executed",)):
        args = ["--version", version]
        for item in items:
            args.extend(("--item", item))
        return self.p("acceptance-define", *args)

    def record(self, item_id="probe", result="pass", evidence_ids="", version="1.1",
               verifier="test harness", how="ran synthetic probe", run="run-1"):
        return self.p("acceptance-record", "--version", version, "--item-id", item_id,
                      "--result", result, "--evidence-ids", evidence_ids,
                      "--verifier", verifier, "--how", how, "--run", run)

    def start_run(self, run="run-1", version="1.1"):
        return self.p("run", "--version", version, "--run-id", run, "--executor", "test")

    def complete(self, run="run-1", version="1.1"):
        return self.p("finish-run", "--version", version, "--run-id", run,
                      "--status", "completed", "--note", "synthetic")

    def full_chain(self, run="run-1", version="1.1", items=("probe:synthetic probe executed",)):
        self.ok(self.start_run(run, version))
        self.ok(self.define(version, items))
        self.ok(self.register(version=version, run=run, evidence_id="ev-1"))
        self.ok(self.record(evidence_ids="ev-1", version=version, run=run))
        return self.ok(self.complete(run, version))

    def prepared_alignment(self):
        """Legal real alignment: reverse baseline site plus 1.1 target."""
        self.upgrade()
        self.ok(self.v("add-site", "--version", "1.0", "--file", self.old, "--id", "gate",
                       "--sem", "synthetic branch candidate", "--aob", PATTERN,
                       "--offset", "4", "--original", "85 C0 74 12"))
        self.ok(self.v("align", "--old", "1.0", "--new-version", "1.1", "--new", self.new))
        return self.project / "versions/1.1/align.json"

    def migration(self, status="completed", align="prepared", **kwargs):
        args = ["--source", "1.0", "--target", "1.1", "--status", status]
        if align == "prepared":
            align = self.project / "versions/1.1/align.json"
        if align is not None:
            args.extend(("--align", str(align)))
        for key, value in kwargs.items():
            args.extend(("--" + key.replace("_", "-"), str(value)))
        return self.p("migration", *args)

    # ---- positive control ---------------------------------------------
    def test_positive_control_completed_run_with_recorded_witness(self):
        result = self.full_chain()
        run = read(self.project / "versions/1.1/runs/run-1/run.json")
        self.assertEqual(result["run"]["status"], "completed")
        self.assertEqual(run["status"], "completed")
        self.assertIsNotNone(run["finished_at"])
        closure = run["closure"]
        self.assertEqual(closure["kind"], "run-completed")
        self.assertEqual(closure["target_sha256"], self.new_sha)
        self.assertEqual(closure["required_count"], 1)
        witness = self.project / "versions/1.1/artifacts/probe.log"
        self.assertEqual(closure["evidence_sha256"], {"ev-1": digest(witness.read_bytes())})
        self.assertEqual(run["acceptance_snapshot"]["acceptance_sha256"],
                         digest((self.project / "versions/1.1/acceptance.json").read_bytes()))
        self.assertEqual(run["acceptance_snapshot"]["target_sha256"], self.new_sha)
        self.assertEqual(result["proof_level"], "structural+recorded_witness")
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertEqual(handoff["status"], "active")
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["completed_runs"], ["run-1"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["proof_level"], "structural+recorded_witness")
        self.assertIn("不证明日志语义", "".join(handoff["proof_limits"]))
        evidence = read(self.project / "versions/1.1/evidence/ev-1.json")
        self.assertEqual(evidence["target_sha256"], self.new_sha)
        self.assertEqual(evidence["run_id"], "run-1")

    # ---- acceptance checklist definition ------------------------------
    def test_target_drift_refuses_new_pass_and_completion_without_writing(self):
        self.ok(self.start_run())
        self.ok(self.define())
        self.ok(self.register())
        self.ok(self.record(evidence_ids="ev-1"))
        version = read(self.project / "versions/1.1/version.json")
        target = self.project / version["local_path"]
        original = target.read_bytes()
        target.write_bytes(b"!" * len(original))
        frozen = {path: path.read_bytes() for path in (
            self.project / "versions/1.1/runs/run-1/run.json",
            self.project / "versions/1.1/acceptance.json", self.project / "facts.jsonl")}
        self.rejected(self.complete())
        self.rejected(self.record(evidence_ids="ev-1"))
        self.rejected(self.register(evidence_id="ev-drift"))
        self.assertFalse((self.project / "versions/1.1/evidence/ev-drift.json").exists())
        for path, payload in frozen.items():
            self.assertEqual(payload, path.read_bytes())
        handoff = self.rejected(self.p("resume"))["handoff"]
        self.assertFalse(handoff["acceptance_complete"])
        self.assertFalse(handoff["acceptance_eligible"])
        target.write_bytes(original)
        self.ok(self.complete())

    def test_unreadable_ledger_records_cannot_be_silently_dropped_by_completion(self):
        self.ok(self.start_run())
        self.ok(self.start_run(run="run-old", version="1.0"))
        self.ok(self.define())
        self.ok(self.register())
        self.ok(self.record(evidence_ids="ev-1"))
        frozen_paths = (self.project / "versions/1.1/runs/run-1/run.json",
                        self.project / "versions/1.1/acceptance.json", self.project / "facts.jsonl")
        for relative in ("facts.jsonl", "versions/1.0/version.json",
                         "versions/1.0/runs/run-old/run.json", "versions/1.0/migration.json"):
            path = self.project / relative
            previous = path.read_bytes() if path.exists() else None
            with self.subTest(path=relative):
                path.write_bytes(b"{synthetic invalid record\n")
                frozen = {p: p.read_bytes() for p in frozen_paths}
                self.rejected(self.complete())
                for p, payload in frozen.items():
                    self.assertEqual(payload, p.read_bytes())
            if previous is None:
                path.unlink()
            else:
                path.write_bytes(previous)
        self.ok(self.complete())

    def test_bad_manifest_is_checked_before_creating_evidence_record(self):
        self.ok(self.start_run())
        path = self.project / "versions/1.1/manifest.json"
        original = path.read_bytes()
        broken = read(path)
        broken["evidence"] = {"broken": "not a list"}
        path.write_text(json.dumps(broken), encoding="utf-8")
        before = (self.project / "facts.jsonl").read_bytes()
        self.rejected(self.register())
        self.assertFalse((self.project / "versions/1.1/evidence/ev-1.json").exists())
        self.assertEqual(before, (self.project / "facts.jsonl").read_bytes())
        path.write_bytes(original)
        self.ok(self.register())
        self.ok(self.p("resume"))

    def test_empty_checklist_and_duplicate_ids_rejected(self):
        self.ok(self.start_run())
        self.rejected(self.define(items=()))
        self.assertFalse((self.project / "versions/1.1/acceptance.json").read_text(
            encoding="utf-8").count('"required": true'))
        self.rejected(self.define(items=("dup:first", "dup:second")))
        self.rejected(self.define(items=("no-description:",)))
        self.rejected(self.define(items=("bad id with space:desc",)))
        self.assertEqual(read(self.project / "versions/1.1/acceptance.json")["items"], [])
        self.rejected(self.complete())

    def test_unknown_skipped_and_fail_block_completion(self):
        self.ok(self.start_run())
        self.ok(self.define(items=("a:first", "b:second")))
        self.ok(self.register(evidence_id="ev-a"))
        self.ok(self.record(item_id="a", evidence_ids="ev-a"))
        for status in ("unknown", "skipped", "fail", "pending"):
            with self.subTest(status=status):
                if status == "pending":
                    pass  # b stays pending; a pass alone must not complete.
                else:
                    self.ok(self.record(item_id="b", result=status, evidence_ids="ev-a"))
                self.rejected(self.complete())
                run = read(self.project / "versions/1.1/runs/run-1/run.json")
                self.assertEqual(run["status"], "active")
                self.assertIsNone(run["finished_at"])
                self.assertNotIn("closure", run)
                # Incomplete acceptance is reported, not hidden behind an ok status.
                handoff = self.ok(self.p("resume"))["handoff"]
                self.assertFalse(handoff["acceptance_complete"])
                self.assertIn("b", handoff["acceptance_pending"] + handoff["acceptance_failed"])
                self.assertEqual(sum(handoff["acceptance_counts"].values()), 2)
                self.assertTrue(any("未完成验收项" in x for x in handoff["next_actions"]))

    # ---- evidence registration rules ----------------------------------
    def test_pass_requires_verified_current_version_evidence(self):
        self.ok(self.start_run())
        self.ok(self.define())
        self.rejected(self.record(evidence_ids=""))
        self.rejected(self.record(evidence_ids="ev-absent"))
        self.rejected(self.record(verifier="", evidence_ids=""))
        self.rejected(self.record(how="", evidence_ids=""))
        self.ok(self.register(evidence_id="ev-1"))
        # Cross-version reference: evidence registered on 1.0 cannot back 1.1.
        self.ok(self.start_run(run="run-old", version="1.0"))
        old_witness = self.witness("old.log", b"old version witness\n", version="1.0")
        self.ok(self.register(version="1.0", run="run-old", evidence_id="ev-old",
                              path=old_witness, target=self.old_sha))
        self.rejected(self.record(evidence_ids="ev-old", version="1.1", run="run-1"))
        self.rejected(self.record(evidence_ids="ev-1", version="1.1", run="run-old"))
        self.ok(self.record(evidence_ids="ev-1"))
        self.ok(self.complete())

    def test_evidence_registration_rejects_fake_missing_empty_and_escaping(self):
        self.ok(self.start_run())
        witness = self.witness()
        relative = witness.relative_to(self.project).as_posix()
        size = witness.stat().st_size
        good = digest(witness.read_bytes())
        # Fake sha256 / wrong size / forged target sha.
        self.rejected(self.register(sha="0" * 64))
        self.rejected(self.register(sha=good.upper() + "00"))
        self.rejected(self.register(size=size + 1))
        self.rejected(self.register(target="1" * 64))
        self.assertFalse((self.project / "versions/1.1/evidence/ev-1.json").exists())
        # External / escaping / symlink paths and missing files.
        outside = self.base / "outside.log"
        outside.write_bytes(b"outside\n")
        for bad in ("../outside.log", str(outside).replace("\\", "/"), "versions/1.1/../1.0/version.json"):
            with self.subTest(path=bad):
                self.rejected(self.p("evidence", "--version", "1.1", "--run-id", "run-1",
                                     "--evidence-id", "ev-bad", "--target-sha256", self.new_sha,
                                     "--path", bad, "--sha256", digest(outside.read_bytes()),
                                     "--size", outside.stat().st_size))
                self.assertFalse((self.project / "versions/1.1/evidence/ev-bad.json").exists())
        link = self.project / "versions/1.1/artifacts/link.log"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            link = None  # Symlink creation may require privileges on Windows.
        if link is not None:
            self.rejected(self.register(evidence_id="ev-link", path=link))
            self.assertFalse((self.project / "versions/1.1/evidence/ev-link.json").exists())
        # Empty file is not evidence.
        empty = self.witness("empty.log", b"")
        self.rejected(self.register(evidence_id="ev-empty", path=empty))
        self.assertFalse((self.project / "versions/1.1/evidence/ev-empty.json").exists())
        self.rejected(self.p("evidence", "--version", "1.1", "--run-id", "run-absent",
                             "--evidence-id", "ev-x", "--target-sha256", self.new_sha,
                             "--path", relative, "--sha256", good, "--size", size))
        self.rejected(self.p("evidence", "--version", "9.9", "--run-id", "run-1",
                             "--evidence-id", "ev-x", "--target-sha256", self.new_sha,
                             "--path", relative, "--sha256", good, "--size", size))
        # Self-referential project bookkeeping is not a witness.
        for name in ("project.json", "facts.jsonl", "version.json", "versionalias.json"):
            candidate = self.project / name
            if candidate.is_file():
                with self.subTest(metadata=name):
                    self.rejected(self.p("evidence", "--version", "1.1", "--run-id", "run-1",
                                         "--evidence-id", "ev-meta", "--target-sha256", self.new_sha,
                                         "--path", name, "--sha256", digest(candidate.read_bytes()),
                                         "--size", candidate.stat().st_size,
                                         "--source", name))
                    self.assertFalse((self.project / "versions/1.1/evidence/ev-meta.json").exists())
        # The version target binary and other versions' files are not witnesses.
        borrowed = self.project / "versions/1.0/version.json"
        self.rejected(self.p("evidence", "--version", "1.1", "--run-id", "run-1",
                             "--evidence-id", "ev-other", "--target-sha256", self.new_sha,
                             "--path", "versions/1.0/version.json",
                             "--sha256", digest(borrowed.read_bytes()),
                             "--size", borrowed.stat().st_size))
        target_local = read(self.project / "versions/1.1/version.json")["local_path"]
        self.rejected(self.p("evidence", "--version", "1.1", "--run-id", "run-1",
                             "--evidence-id", "ev-target", "--target-sha256", self.new_sha,
                             "--path", target_local, "--sha256", self.new_sha,
                             "--size", len(NEXT)))
        self.assertFalse((self.project / "versions/1.1/evidence/ev-other.json").exists())
        self.assertFalse((self.project / "versions/1.1/evidence/ev-target.json").exists())
        self.ok(self.register())
        self.assertEqual(len(list((self.project / "versions/1.1/evidence").glob("*.json"))), 1)

    def test_duplicate_evidence_id_cannot_be_overwritten(self):
        self.ok(self.start_run())
        first = self.ok(self.register(evidence_id="ev-1"))
        record_bytes = (self.project / "versions/1.1/evidence/ev-1.json").read_bytes()
        self.assertEqual(first["evidence"]["sha256"], digest((self.project / "versions/1.1/artifacts/probe.log").read_bytes()))
        replay = self.ok(self.register(evidence_id="ev-1"))
        self.assertTrue(replay.get("idempotent"))
        self.assertEqual(record_bytes, (self.project / "versions/1.1/evidence/ev-1.json").read_bytes())
        changed = self.witness("other.log", b"different witness\n")
        self.rejected(self.register(evidence_id="ev-1", path=changed))
        self.rejected(self.register(evidence_id="ev-1", run="run-2"))
        self.assertEqual(record_bytes, (self.project / "versions/1.1/evidence/ev-1.json").read_bytes())

    def test_run_completion_requires_evidence_from_the_same_run(self):
        self.ok(self.start_run(run="run-a"))
        self.ok(self.define())
        self.ok(self.register(run="run-a", evidence_id="ev-a"))
        self.ok(self.record(evidence_ids="ev-a", run="run-a"))
        self.ok(self.start_run(run="run-b"))
        # Evidence registered under run-a cannot close run-b.
        self.rejected(self.complete(run="run-b"))
        self.assertEqual(read(self.project / "versions/1.1/runs/run-b/run.json")["status"], "active")
        self.rejected(self.record(evidence_ids="ev-a", run="run-b"))
        run_a = self.ok(self.complete(run="run-a"))["run"]
        self.assertEqual(run_a["closure"]["target_sha256"], self.new_sha)

    def test_foreign_run_capture_cannot_be_relabelled_as_current_run_evidence(self):
        self.ok(self.start_run(run="run-a"))
        self.ok(self.start_run(run="run-b"))
        self.ok(self.define())
        foreign = self.project / "versions/1.1/runs/run-a/capture/probe.log"
        foreign.write_bytes(b"output produced in run-a\n")
        own = self.project / "versions/1.1/runs/run-b/capture/probe.log"
        own.write_bytes(b"output produced in run-b\n")
        before = (self.project / "versions/1.1/manifest.json").read_bytes()
        candidates = [(foreign, None, None), (own, foreign.relative_to(self.project).as_posix(), None),
                      (own, None, foreign)]
        if os.name == "nt":
            upper = foreign.relative_to(self.project).as_posix().upper()
            candidates.extend(((self.project / upper, None, None), (own, upper, None)))
        for path, source, raw_output in candidates:
            with self.subTest(source=source, raw_output=raw_output):
                self.rejected(self.register(run="run-b", evidence_id="ev-borrowed",
                                            path=path, source=source, raw_output=raw_output))
                self.assertFalse((self.project / "versions/1.1/evidence/ev-borrowed.json").exists())
                self.assertEqual((self.project / "versions/1.1/manifest.json").read_bytes(), before)
        self.rejected(self.record(evidence_ids="ev-borrowed", run="run-b"))
        self.rejected(self.complete(run="run-b"))
        self.assertEqual(read(self.project / "versions/1.1/runs/run-b/run.json")["status"], "active")
        self.ok(self.register(run="run-b", evidence_id="ev-own", path=own))
        self.ok(self.record(evidence_ids="ev-own", run="run-b"))
        self.ok(self.complete(run="run-b"))

    def test_separate_raw_output_drift_blocks_completion_and_resume(self):
        self.ok(self.start_run())
        self.ok(self.define())
        witness = self.witness()
        raw = self.witness("raw.out", b"synthetic full raw output\n")
        original = raw.read_bytes()
        self.ok(self.register(path=witness, raw_output=raw))
        self.ok(self.record(evidence_ids="ev-1"))
        active = (self.project / "versions/1.1/runs/run-1/run.json").read_bytes()
        raw.write_bytes(b"different output\n")
        self.rejected(self.complete())
        self.assertEqual((self.project / "versions/1.1/runs/run-1/run.json").read_bytes(), active)
        self.assertFalse(self.rejected(self.p("resume"))["handoff"]["acceptance_complete"])
        raw.write_bytes(original)
        self.ok(self.complete())
        self.ok(self.p("resume"))
        raw.unlink()
        self.assertFalse(self.rejected(self.p("resume"))["handoff"]["acceptance_complete"])
        raw.write_bytes(original)
        self.ok(self.p("resume"))

    # ---- tampering after completion -----------------------------------
    def test_tampered_evidence_after_completion_becomes_stale_blocked(self):
        self.full_chain()
        witness = self.project / "versions/1.1/artifacts/probe.log"
        original = witness.read_bytes()
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertTrue(handoff["acceptance_complete"])
        witness.write_bytes(b"tampered witness content\n")
        result = self.rejected(self.p("resume"))
        handoff = result["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(handoff["acceptance_stale"], ["probe"])
        self.assertTrue(handoff["state_errors"])
        self.assertTrue(handoff["closure_errors"])
        self.assertEqual(read(self.project / "handoff.json")["status"], "blocked")
        self.rejected(self.p("handoff"))
        self.rejected(self.complete())
        self.rejected(self.migration())
        witness.write_bytes(original)
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["acceptance_stale"], [])
        witness.unlink()
        handoff = self.rejected(self.p("resume"))["handoff"]
        self.assertEqual(handoff["acceptance_stale"], ["probe"])

    def test_evidence_record_tampering_and_repeat_completion(self):
        self.full_chain()
        run_path = self.project / "versions/1.1/runs/run-1/run.json"
        completed = run_path.read_bytes()
        self.rejected(self.complete())
        self.assertEqual(completed, run_path.read_bytes())
        record_path = self.project / "versions/1.1/evidence/ev-1.json"
        record = read(record_path)
        record["target_sha256"] = "2" * 64
        record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        handoff = self.rejected(self.p("resume"))["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertEqual(handoff["acceptance_stale"], ["probe"])

    # ---- migration completion gate ------------------------------------
    def test_migration_completed_requires_alignment_and_acceptance(self):
        align = self.prepared_alignment()
        # Legal align alone (AOB unique) is not acceptance.
        self.rejected(self.migration())
        self.assertFalse((self.project / "versions/1.1/migration.json").exists())
        self.ok(self.start_run())
        self.ok(self.define())
        self.rejected(self.migration())  # checklist still pending
        # A pass with a fake evidence id must not open completion.
        self.rejected(self.record(evidence_ids="ev-absent"))
        self.ok(self.register(evidence_id="ev-1"))
        self.ok(self.record(evidence_ids="ev-1"))
        self.ok(self.migration(migration_id="upgrade", note="synthetic complete"))
        migration = read(self.project / "versions/1.1/migration.json")
        self.assertEqual(migration["status"], "completed")
        self.assertEqual(migration["closure"]["target_sha256"], self.new_sha)
        self.assertEqual(migration["acceptance_snapshot"]["acceptance_sha256"],
                         digest((self.project / "versions/1.1/acceptance.json").read_bytes()))
        revisions = list((self.project / "versions/1.1/migrations").glob("*.json"))
        self.assertEqual(len(revisions), 1)
        # History is append-only; earlier revisions stay byte-identical.
        first = revisions[0].read_bytes()
        self.ok(self.migration(migration_id="upgrade", note="second revision"))
        self.assertEqual(len(list((self.project / "versions/1.1/migrations").glob("*.json"))), 2)
        self.assertIn(first, [p.read_bytes() for p in (self.project / "versions/1.1/migrations").glob("*.json")])
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertEqual(handoff["completed_migrations"], ["upgrade"])
        self.assertEqual(handoff["closure_errors"], [])

    def test_migration_completed_rejected_without_align(self):
        self.ok(self.start_run())
        self.ok(self.define())
        self.ok(self.register(evidence_id="ev-1"))
        self.ok(self.record(evidence_ids="ev-1"))
        self.rejected(self.migration(align=None))
        self.assertFalse((self.project / "versions/1.1/migration.json").exists())
        align = self.prepared_alignment()
        broken = read(align)
        broken["sites"][0]["status"] = "multi"
        broken["summary"] = {"unique": 0, "missing": 0, "multi": 1, "needs_manual": 0}
        broken_path = self.base / "broken-align.json"
        broken_path.write_text(json.dumps(broken, indent=2) + "\n", encoding="utf-8")
        self.rejected(self.migration(align=broken_path))
        self.assertFalse((self.project / "versions/1.1/migration.json").exists())
        # Blocked/failed/cancelled endings remain available unchanged.
        self.ok(self.p("finish-run", "--version", "1.1", "--run-id", "run-1",
                       "--status", "blocked", "--note", "synthetic"))
        self.assertEqual(read(self.project / "versions/1.1/runs/run-1/run.json")["status"], "blocked")

    def test_post_completion_acceptance_regression_blocks_top_level_ok(self):
        """收紧后的正确预期（主 Agent 裁定 1）：完成后验收被**拒绝**，不再改写旧 run。

        该用例原先记录“完成后追加 fail 使旧 run 变 stale/blocked”当作 append-only
        行为。现在该行为收紧为拒绝：命令 rc=2、文件/链/事件字节不变，项目保持
        rc=0。反例保留（不再把项目变红作为“正确”），新的项目事实必须开新 run。
        """
        self.full_chain()
        self.assertTrue(self.ok(self.p("resume"))["handoff"]["acceptance_complete"])
        run_path = self.project / "versions/1.1/runs/run-1/run.json"
        acceptance = self.project / "versions/1.1/acceptance.json"
        revisions = self.project / "versions/1.1/acceptance-revisions"
        frozen = {path: path.read_bytes() for path in
                  [run_path, acceptance, self.project / "facts.jsonl"]}
        frozen[revisions] = sorted((p.name, p.read_bytes()) for p in revisions.glob("*.json"))
        rejected = self.rejected(self.record(result="fail", evidence_ids="ev-1"))
        self.assertIn("已收尾 run 的验收不可再修改", rejected["reason"])
        self.assertEqual(frozen[run_path], run_path.read_bytes())
        self.assertEqual(frozen[acceptance], acceptance.read_bytes())
        self.assertEqual(frozen[self.project / "facts.jsonl"],
                         (self.project / "facts.jsonl").read_bytes())
        self.assertEqual(frozen[revisions],
                         sorted((p.name, p.read_bytes()) for p in revisions.glob("*.json")))
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["acceptance_failed"], [])
        self.assertEqual(handoff["closure_errors"], [])
        run = read(run_path)
        self.assertEqual(run["status"], "completed")
        self.assertIn("closure", run)
        # A new run is the legal place for a new recorded result.
        self.ok(self.start_run(run="run-2"))
        self.ok(self.register(run="run-2", evidence_id="ev-2"))
        self.ok(self.record(run="run-2", result="fail", evidence_ids="ev-2"))
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertEqual(handoff["acceptance_failed"], ["probe"])
        self.assertFalse(handoff["acceptance_complete"])
        # Ruling 4: a legal new revision may move the live draft head.  The old
        # completion is still re-verified against the revision *it* consumed, so
        # it is not reported stale and no closure error appears.
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(frozen[run_path], run_path.read_bytes())
        # run-2 cannot reuse run-1's evidence for its own completion.
        self.rejected(self.p("finish-run", "--version", "1.1", "--run-id", "run-2",
                             "--status", "completed"))
        self.assertEqual(read(self.project / "versions/1.1/runs/run-2/run.json")["status"],
                         "active")

    def test_evidence_cannot_be_appended_to_a_closed_run(self):
        self.full_chain()
        extra = self.witness("late.log", b"late witness\\n")
        self.rejected(self.register(evidence_id="ev-late", path=extra))
        self.assertFalse((self.project / "versions/1.1/evidence/ev-late.json").exists())
        manifest = read(self.project / "versions/1.1/manifest.json")
        self.assertEqual([x["evidence_id"] for x in manifest["evidence"]], ["ev-1"])

    def test_acceptance_file_tampering_missing_required_and_duplicates(self):
        self.ok(self.start_run())
        self.ok(self.define(items=("a:first", "b:second")))
        self.ok(self.register(evidence_id="ev-a"))
        self.ok(self.record(item_id="a", evidence_ids="ev-a"))
        # b is still pending, so completion must fail.
        self.rejected(self.complete())
        path = self.project / "versions/1.1/acceptance.json"
        original = path.read_bytes()
        # No required items / duplicate required ids / empty list never open completion.
        for mutation in ("no-required", "duplicate", "empty", "unbound-target"):
            with self.subTest(mutation=mutation):
                data = json.loads(original.decode("utf-8"))
                if mutation == "no-required":
                    for item in data["items"]:
                        item["required"] = False
                elif mutation == "duplicate":
                    data["items"][1]["id"] = data["items"][0]["id"]
                elif mutation == "empty":
                    data["items"] = []
                else:
                    data["target_sha256"] = "3" * 64
                path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                self.rejected(self.complete())
                # LIFECYCLE-05 A2 (REVIEW-04 §2): each mutation rewrites the live
                # head without appending a revision, i.e. it is *real* chain
                # damage, so the health projection must say blocked instead of
                # ok.  Only this expectation changed; what the mutation forbids
                # (no completion, run stays active) is asserted unchanged.
                handoff = self.rejected(self.p("resume"))["handoff"]
                self.assertEqual(handoff["status"], "blocked")
                self.assertEqual(handoff["state_health"], "blocked")
                self.assertTrue(handoff["integrity_errors"])
                self.assertFalse(handoff["acceptance_complete"])
                self.assertEqual(read(self.project / "versions/1.1/runs/run-1/run.json")["status"], "active")
        path.write_bytes(original)
        self.ok(self.record(item_id="b", evidence_ids="ev-a"))
        # Deleting the evidence registration invalidates both pass claims.
        evidence = self.project / "versions/1.1/evidence/ev-a.json"
        backup = evidence.read_bytes()
        evidence.unlink()
        handoff = self.rejected(self.p("resume"))["handoff"]
        self.assertEqual(handoff["status"], "blocked")
        self.assertEqual(handoff["acceptance_stale"], ["a", "b"])
        self.assertFalse(handoff["acceptance_complete"])
        self.rejected(self.complete())
        evidence.write_bytes(backup)
        self.assertEqual(self.ok(self.p("resume"))["handoff"]["acceptance_stale"], [])
        self.ok(self.complete())

    def test_repeat_acceptance_record_is_idempotent(self):
        self.ok(self.start_run())
        self.ok(self.define())
        self.ok(self.register(evidence_id="ev-1"))
        first = self.ok(self.record(evidence_ids="ev-1"))
        snapshot = (self.project / "versions/1.1/acceptance.json").read_bytes()
        archives = len(list((self.project / "versions/1.1/acceptance-revisions").glob("*.json")))
        again = self.ok(self.record(evidence_ids="ev-1"))
        self.assertTrue(again.get("idempotent"))
        self.assertEqual(snapshot, (self.project / "versions/1.1/acceptance.json").read_bytes())
        self.assertEqual(archives, len(list((self.project / "versions/1.1/acceptance-revisions").glob("*.json"))))
        # Recording a different result still creates an append-only revision.
        self.ok(self.record(result="fail", evidence_ids="ev-1"))
        self.assertGreater(len(list((self.project / "versions/1.1/acceptance-revisions").glob("*.json"))), archives)
        self.assertIn(first["previous_sha256"], read(self.project / "versions/1.1/acceptance.json")["revision_history"])

    # ---- concurrency ---------------------------------------------------
    def test_concurrent_completion_has_exactly_one_success(self):
        self.ok(self.start_run())
        self.ok(self.define())
        self.ok(self.register(evidence_id="ev-1"))
        self.ok(self.record(evidence_ids="ev-1"))
        workers = 6
        barrier = threading.Barrier(workers)

        def finish(_):
            barrier.wait(timeout=20)
            return self.p("finish-run", "--version", "1.1", "--run-id", "run-1",
                          "--status", "completed", "--note", "concurrent")

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(finish, range(workers)))
        self.assertEqual(sorted(rc for rc, _ in results), [0] + [2] * (workers - 1), results)
        run = read(self.project / "versions/1.1/runs/run-1/run.json")
        self.assertEqual(run["status"], "completed")
        self.assertIn("closure", run)
        events = [json.loads(line) for line in
                  (self.project / "facts.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len([e for e in events if e.get("type") == "run_finished"]), 1)

    # ---- original bytes / archives preserved ---------------------------
    def test_completion_preserves_prior_bytes_and_history(self):
        manifest10 = self.project / "versions/1.0/manifest.json"
        baseline10 = self.project / "versions/1.0/reverse-baseline.json"
        before_manifest = manifest10.read_bytes()
        before_baseline = baseline10.read_bytes()
        facts_before = (self.project / "facts.jsonl").read_bytes()
        self.full_chain()
        self.assertEqual(before_manifest, manifest10.read_bytes())
        self.assertEqual(before_baseline, baseline10.read_bytes())
        facts_after = (self.project / "facts.jsonl").read_bytes()
        self.assertTrue(facts_after.startswith(facts_before))
        self.assertGreater(len(facts_after), len(facts_before))
        revisions = sorted(p.read_bytes() for p in
                           (self.project / "versions/1.1/acceptance-revisions").glob("*.json"))
        self.assertGreaterEqual(len(revisions), 2)
        # Archived revisions are distinct and never rewritten by later records.
        self.assertEqual(len(set(digest(x) for x in revisions)), len(revisions))
        for archived in revisions:
            value = json.loads(archived.decode("utf-8"))
            self.assertEqual(value["schema"], "seep-acceptance/1")
        self.assertEqual(sorted(revisions), revisions)
        acceptance = read(self.project / "versions/1.1/acceptance.json")
        self.assertEqual(acceptance["target_sha256"], self.new_sha)
        self.assertTrue(acceptance["revision_history"])
        self.assertEqual(read(self.project / "versions/1.1/evidence/ev-1.json")["target_sha256"], self.new_sha)

    def test_legacy_completed_run_without_closure_is_reported_not_trusted(self):
        """历史兼容 = 可读，不是自动认证（主 Agent 规范 C）。

        本用例原先断言 ``resume`` rc=0 / status "active"。按主 Agent 明确收紧：
        记录仍完整可读并列入 ``closure_legacy``（``verified=False``），但项目
        blocked（rc=2）、``acceptance_complete`` 为 false——无可复核见证的
        completed 声明不默认成立。这是收紧负例，不是删除负例。
        """
        self.ok(self.start_run(run="legacy"))
        path = self.project / "versions/1.1/runs/legacy/run.json"
        legacy = read(path)
        legacy["status"] = "completed"
        legacy["finished_at"] = "2000-01-01T00:00:00Z"
        path.write_text(json.dumps(legacy, indent=2) + "\n", encoding="utf-8")
        result = self.p("resume")
        self.assertEqual(result[0], 2, result)
        self.assertFalse(result[1]["ok"], "legacy completion must not be ok=true")
        handoff = result[1]["handoff"]          # 仍是完整可读的 JSON 报告
        self.assertEqual(handoff["status"], "blocked")
        self.assertEqual(handoff["completed_runs"], ["legacy"])
        self.assertEqual([x["id"] for x in handoff["closure_legacy"]], ["legacy"])
        self.assertFalse(handoff["closure_legacy"][0]["verified"])
        self.assertFalse(handoff["acceptance_complete"])
        self.assertTrue(handoff["closure_errors"])
        self.assertIn("历史 completed",
                      json.dumps(handoff["closure_errors"], ensure_ascii=False))
        self.assertTrue(any("历史 completed" in x for x in handoff["next_actions"]))


class LifecycleRegistration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="seep-registration-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.project = self.base / "project"
        self.target = self.base / "sample.bin"
        self.target.write_bytes(OLD)

    def p(self, command, *args):
        return cli(PROJECT, command, "--project", self.project, *args)

    def assert_ok(self, result):
        self.assertEqual(result[0], 0, result)
        self.assertTrue(result[1]["ok"], result)
        return result[1]

    def files(self):
        return {p.relative_to(self.project).as_posix(): p.read_bytes()
                for p in self.project.rglob("*") if p.is_file() and p.name != ".project.lock"}

    def invoke_init(self, patcher):
        import argparse
        import contextlib
        import io
        if str(PROJECT.parent) not in sys.path:
            sys.path.insert(0, str(PROJECT.parent))
        import project_state as P
        args = argparse.Namespace(project=str(self.project), project_id="registration",
            target=str(self.target), title="", domain="", version="1.0", parent="",
            asset_id="asset-main", force=False)
        output = io.StringIO()
        with patcher(P), contextlib.redirect_stdout(output):
            rc = P.cmd_init(args)
        return rc, json.loads(output.getvalue())

    def test_invalid_asset_id_leaves_no_partial_project_and_retry_succeeds(self):
        result = self.p("init", "--project-id", "registration", "--target", self.target,
                        "--asset-id", "../invalid")
        self.assertEqual(result[0], 2, result)
        self.assertEqual(self.files(), {})
        self.assert_ok(self.p("init", "--project-id", "registration", "--target", self.target))

    def test_copy_failure_preserves_existing_reverse_baseline_and_can_retry(self):
        from unittest.mock import patch
        self.assert_ok(cli(REVERSE, "init", "--case", self.project,
                           "--version", "1.0", "--file", self.target))
        before = self.files()
        result = self.invoke_init(lambda P: patch.object(P, "atomic_copy", side_effect=OSError("fixture copy failure")))
        self.assertEqual(result[0], 2, result)
        self.assertEqual(self.files(), before)
        self.assert_ok(self.p("init", "--project-id", "registration", "--target", self.target))
        for rel, value in before.items():
            self.assertEqual((self.project / rel).read_bytes(), value)

    def test_publication_failure_rolls_back_only_new_files(self):
        from unittest.mock import patch
        self.project.mkdir()
        note = self.project / "notes.txt"
        note.write_bytes(b"keep existing user material")
        before = self.files()
        publications = []
        def patcher(P):
            real_replace = P.os.replace
            def replace(source, destination):
                destination = Path(destination)
                if destination.parent == self.project and destination.name == "project.json":
                    raise OSError("fixture publication failure")
                if destination.is_relative_to(self.project) and ".seep-init-" not in str(destination):
                    publications.append(destination)
                return real_replace(source, destination)
            return patch.object(P.os, "replace", side_effect=replace)
        result = self.invoke_init(patcher)
        self.assertEqual(result[0], 2, result)
        self.assertTrue(publications, "failure must occur after some outputs were published")
        self.assertEqual(self.files(), before)
        self.assert_ok(self.p("init", "--project-id", "registration", "--target", self.target))
        self.assertEqual(note.read_bytes(), before["notes.txt"])

    def test_existing_version_metadata_is_not_overwritten_by_init(self):
        version = self.project / "versions/1.0/version.json"
        version.parent.mkdir(parents=True)
        version.write_bytes(b'{"old":"unowned metadata"}\n')
        before = self.files()
        result = self.p("init", "--project-id", "registration", "--target", self.target)
        self.assertEqual(result[0], 2, result)
        self.assertEqual(self.files(), before)

    def test_late_target_binds_only_an_untouched_acceptance_placeholder(self):
        for mode in ("version", "asset"):
            with self.subTest(mode=mode):
                self.project = self.base / mode
                self.assert_ok(self.p("init", "--project-id", "registration"))
                extra = ["--asset-id", "asset-main", "--role", "primary"] if mode == "asset" else []
                self.assert_ok(self.p(mode, "--version", "1.0", "--target", self.target, *extra))
                version = read(self.project / "versions/1.0/version.json")
                acceptance = read(self.project / "versions/1.0/acceptance.json")
                self.assertEqual(version["sha256"], digest(OLD))
                self.assertEqual(acceptance["target_sha256"], version["sha256"])
                self.assertEqual(acceptance["items"], [])
                handoff = self.assert_ok(self.p("resume"))["handoff"]
                self.assertEqual(handoff["state_errors"], [])

    def test_defined_acceptance_cannot_be_rebound_by_adding_first_target(self):
        for mode in ("version", "asset"):
            with self.subTest(mode=mode):
                self.project = self.base / ("defined-" + mode)
                self.assert_ok(self.p("init", "--project-id", "registration"))
                self.assert_ok(self.p("acceptance-define", "--version", "1.0", "--item", "ac:fixture"))
                before = self.files()
                extra = ["--asset-id", "asset-main", "--role", "primary"] if mode == "asset" else []
                result = self.p(mode, "--version", "1.0", "--target", self.target, *extra)
                self.assertEqual(result[0], 2, result)
                self.assertEqual(self.files(), before)


    def test_independent_target_accepts_multiple_auxiliary_assets_without_selecting_one_as_primary(self):
        auxiliary = self.base / "auxiliary.bin"
        auxiliary.write_bytes(b"independent synthetic supporting material")
        self.assert_ok(self.p("init", "--project-id", "registration"))
        self.assert_ok(self.p("version", "--version", "1.0", "--target", self.target))
        target_before = read(self.project / "versions/1.0/version.json")
        for asset_id in ("aux-a", "aux-b"):
            with self.subTest(asset_id=asset_id):
                self.assert_ok(self.p("asset", "--version", "1.0", "--asset-id", asset_id,
                                     "--role", "auxiliary", "--target", auxiliary))
        version = read(self.project / "versions/1.0/version.json")
        self.assertEqual(version["primary_asset_id"], "")
        self.assertEqual(version["auxiliary_asset_ids"], ["aux-a", "aux-b"])
        self.assertEqual(version["sha256"], target_before["sha256"])
        self.assertEqual(version["local_path"], target_before["local_path"])
        self.assert_ok(self.p("resume"))

    def test_reverse_baseline_checks_primary_target_but_accepts_different_auxiliary_material(self):
        auxiliary = self.base / "auxiliary.bin"
        auxiliary.write_bytes(b"different from reverse target")
        self.assert_ok(cli(REVERSE, "init", "--case", self.project,
                           "--version", "1.0", "--file", self.target))
        self.assert_ok(self.p("init", "--project-id", "registration"))
        self.assert_ok(self.p("version", "--version", "1.0", "--target", self.target))
        baseline = (self.project / "versions/1.0/reverse-baseline.json").read_bytes()
        self.assert_ok(self.p("asset", "--version", "1.0", "--asset-id", "aux-a",
                             "--role", "auxiliary", "--target", auxiliary))
        version = read(self.project / "versions/1.0/version.json")
        self.assertEqual(version["primary_asset_id"], "")
        self.assertEqual(version["sha256"], digest(OLD))
        self.assertEqual((self.project / "versions/1.0/reverse-baseline.json").read_bytes(), baseline)
        self.assert_ok(self.p("resume"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
