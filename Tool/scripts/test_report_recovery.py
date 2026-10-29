#!/usr/bin/env python3
"""Isolated report recovery checks; all project data is synthetic and temporary."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import project_report as R

import test_project_report as fixtures


class ReportRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ReportChain()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.complete_run()
        self.fixture.ok(self.fixture.r("generate", "--report-id", "final-original",
                                     "--version", "1.1", "--run-id", "run-a", "--kind", "final"))
        self.root = self.fixture.project
        self.pointer = self.root / "reports/final.json"

    def files(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes()
                for p in self.root.rglob("*") if p.is_file() and p.name != ".project.lock"}

    def attempt_replacement(self):
        return self.fixture.r("generate", "--report-id", "final-replacement",
                              "--version", "1.1", "--run-id", "run-a", "--kind", "final")

    def test_corrupt_final_pointer_refuses_replacement_without_any_write(self):
        self.pointer.write_text(json.dumps({"schema": "broken-final"}), encoding="utf-8")
        before = self.files()
        code, result = self.attempt_replacement()
        self.assertEqual(code, 2, result)
        self.assertEqual(self.files(), before)

    def test_missing_previously_registered_final_is_corruption_and_refuses_replacement(self):
        self.pointer.unlink()
        before = self.files()
        code, result = self.fixture.r("status")
        self.assertEqual(code, 2, result)
        self.assertFalse(result["final_pointer"]["integrity_ok"])
        code, result = self.attempt_replacement()
        self.assertEqual(code, 2, result)
        self.assertEqual(self.files(), before)


    def test_missing_pointer_and_index_cannot_hide_existing_final_fact_witness(self):
        self.pointer.unlink()
        (self.root / "reports/index.jsonl").unlink()
        before = self.files()
        code, result = self.fixture.r("status")
        self.assertEqual(code, 2, result)
        self.assertFalse(result["final_pointer"]["integrity_ok"])
        code, result = self.attempt_replacement()
        self.assertEqual(code, 2, result)
        self.assertEqual(self.files(), before)


    def test_deleted_pointer_and_index_are_also_blocked_in_core_resume(self):
        self.pointer.unlink()
        (self.root / "reports/index.jsonl").unlink()
        before = self.files()
        code, result = self.fixture.p("resume")
        self.assertEqual(code, 2, result)
        self.assertTrue(result["handoff"]["report"]["errors"], result)
        self.assertEqual(result["handoff"]["state_health"], "blocked", result)
        self.assertFalse(result["handoff"]["acceptance_complete"])
        self.assertEqual({k: v for k, v in self.files().items() if k != "handoff.json"},
                         {k: v for k, v in before.items() if k != "handoff.json"})

    def test_registration_failure_at_each_write_restores_previous_files_and_allows_retry(self):
        original_root = self.root
        for stage in ("body", "manifest", "index", "pointer", "pointer-index", "witness", "handoff"):
            with self.subTest(stage=stage):
                self.root = self.fixture.base / ("failure-" + stage)
                shutil.copytree(original_root, self.root)
                self.fixture.project = self.root
                before = self.files()
                if stage in ("body", "manifest", "pointer"):
                    name = "atomic_bytes" if stage == "body" else "atomic_json"
                    wanted = {"body": "report.md", "manifest": "manifest.json", "pointer": "final.json"}[stage]
                    real = getattr(R.P, name)
                    def fail_after(path, value, real=real, wanted=wanted):
                        real(path, value)
                        if path.name == wanted:
                            raise OSError("synthetic write interruption")
                elif stage in ("index", "pointer-index"):
                    name, real = "append_jsonl", R.P.append_jsonl
                    wanted = "registered" if stage == "index" else "final_pointer"
                    def fail_after(path, value, real=real, wanted=wanted):
                        real(path, value)
                        if path.name == "index.jsonl" and value.get("kind") == wanted:
                            raise OSError("synthetic append interruption")
                else:
                    name = "write_event" if stage == "witness" else "write_handoff"
                    real = getattr(R.P, name)
                    def fail_after(*args, real=real, **kwargs):
                        real(*args, **kwargs)
                        raise OSError("synthetic post-write interruption")
                output = io.StringIO()
                with mock.patch.object(R.P, name, side_effect=fail_after), contextlib.redirect_stdout(output):
                    code = R.main(["generate", "--project", str(self.root), "--report-id", "final-new",
                                   "--version", "1.1", "--run-id", "run-a", "--kind", "final"])
                self.assertEqual(code, 2, output.getvalue())
                self.assertEqual(self.files(), before, stage)
                self.fixture.ok(self.fixture.r("generate", "--report-id", "final-new",
                                             "--version", "1.1", "--run-id", "run-a", "--kind", "final"))
                self.fixture.ok(self.fixture.r("generate", "--report-id", "final-new",
                                             "--version", "1.1", "--run-id", "run-a", "--kind", "final"))
        self.root = original_root
        self.fixture.project = original_root


    def test_process_exit_after_witness_is_detected_then_retry_recovers_and_commits_once(self):
        code = """import os, sys
sys.path.insert(0, sys.argv[1])
import project_report as R
real = R.P.write_event
def interrupt(*args, **kwargs):
    real(*args, **kwargs)
    os._exit(73)
R.P.write_event = interrupt
raise SystemExit(R.main(["generate", "--project", sys.argv[2], "--report-id", "final-crashed",
                         "--version", "1.1", "--run-id", "run-a", "--kind", "final"]))
"""
        result = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", code,
                                 str(Path(R.__file__).parent), str(self.root)],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 73, result.stderr)
        interrupted = self.files()
        self.assertIn(".project-transaction.json", interrupted)
        status, payload = self.fixture.r("status")
        self.assertEqual(status, 2, payload)
        self.assertEqual(self.files(), interrupted)  # inspection does not recover by writing
        self.fixture.ok(self.fixture.r("generate", "--report-id", "final-crashed",
                                      "--version", "1.1", "--run-id", "run-a", "--kind", "final"))
        self.assertNotIn(".project-transaction.json", self.files())
        self.fixture.ok(self.fixture.r("generate", "--report-id", "final-crashed",
                                      "--version", "1.1", "--run-id", "run-a", "--kind", "final"))
        events = [json.loads(line) for line in (self.root / "facts.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(sum(e.get("type") == "report_registered" and e.get("report_id") == "final-crashed"
                             for e in events), 1)
        self.fixture.ok(self.fixture.r("show", "--report-id", "final-original"))


class MigrationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ReportChain()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.complete_run()
        self.fixture.ok(self.fixture.p("migration", "--source", "1.0", "--target", "1.1",
                                       "--migration-id", "original", "--status", "planned"))
        self.root = self.fixture.project

    def files(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes()
                for p in self.root.rglob("*") if p.is_file() and p.name != ".project.lock"}

    def test_migration_failure_after_each_write_preserves_previous_revision_and_allows_retry(self):
        original_root = self.root
        for stage in ("revision", "latest", "witness", "handoff"):
            with self.subTest(stage=stage):
                self.root = self.fixture.base / ("migration-" + stage)
                shutil.copytree(original_root, self.root)
                self.fixture.project = self.root
                before = self.files()
                if stage in ("revision", "latest"):
                    name, real = "atomic_json", R.P.atomic_json
                    def fail_after(path, value, real=real, stage=stage):
                        real(path, value)
                        if (stage == "revision" and path.parent.name == "migrations"
                                or stage == "latest" and path.name == "migration.json"):
                            raise OSError("synthetic migration interruption")
                else:
                    name = "write_event" if stage == "witness" else "write_handoff"
                    real = getattr(R.P, name)
                    def fail_after(*args, real=real, **kwargs):
                        real(*args, **kwargs)
                        raise OSError("synthetic migration interruption")
                output = io.StringIO()
                with mock.patch.object(R.P, name, side_effect=fail_after), contextlib.redirect_stdout(output):
                    with mock.patch.object(sys, "argv", ["project_state.py", "migration", "--project",
                                           str(self.root), "--source", "1.0", "--target", "1.1",
                                           "--migration-id", "new", "--status", "partial"]):
                        code = R.P.main()
                self.assertEqual(code, 2, output.getvalue())
                self.assertEqual(self.files(), before, stage)
                self.fixture.ok(self.fixture.p("migration", "--source", "1.0", "--target", "1.1",
                                               "--migration-id", "new", "--status", "partial"))
                self.assertEqual(len(list((self.root / "versions/1.1/migrations").glob("*.json"))), 2)
        self.root = original_root
        self.fixture.project = original_root


    def test_migration_process_exit_recovers_previous_projection_and_keeps_only_committed_history(self):
        previous = (self.root / "versions/1.1/migration.json").read_bytes()
        code = """import os, sys
sys.path.insert(0, sys.argv[1])
root = sys.argv[2]
import project_state as P
real = P.write_event
def interrupt(*args, **kwargs):
    real(*args, **kwargs)
    os._exit(74)
P.write_event = interrupt
sys.argv = ["project_state.py", "migration", "--project", root, "--source", "1.0",
            "--target", "1.1", "--migration-id", "interrupted", "--status", "partial"]
raise SystemExit(P.main())
"""
        result = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", code,
                                 str(Path(R.__file__).parent), str(self.root)],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 74, result.stderr)
        interrupted = self.files()
        self.assertIn(".project-transaction.json", interrupted)
        status, payload = self.fixture.p("resume")
        self.assertEqual(status, 2, payload)
        self.assertEqual(self.files(), interrupted)
        self.fixture.ok(self.fixture.p("migration", "--source", "1.0", "--target", "1.1",
                                       "--migration-id", "recovered", "--status", "partial"))
        revisions = list((self.root / "versions/1.1/migrations").glob("*.json"))
        self.assertEqual(len(revisions), 2)
        self.assertIn(previous, [p.read_bytes() for p in revisions])
        events = [json.loads(line) for line in (self.root / "facts.jsonl").read_text(encoding="utf-8").splitlines()]
        migrations = [e for e in events if e.get("type") == "migration_recorded"]
        self.assertEqual([e["migration_id"] for e in migrations], ["original", "recovered"])
        self.assertNotIn(".project-transaction.json", self.files())


    def test_legacy_projection_archive_is_restored_after_failure_or_process_exit(self):
        path = self.root / "versions/1.1/migration.json"
        legacy = json.loads(path.read_text(encoding="utf-8"))
        old_revision = legacy.pop("revision_id")
        (self.root / "versions/1.1/migrations" / (old_revision + ".json")).unlink()
        legacy_bytes = (json.dumps(legacy, ensure_ascii=False, indent=1) + "\n\n").encode("utf-8")
        path.write_bytes(legacy_bytes)
        original_root = self.root
        for mode in ("exception", "exit"):
            with self.subTest(mode=mode):
                self.root = self.fixture.base / ("legacy-" + mode)
                shutil.copytree(original_root, self.root)
                self.fixture.project = self.root
                before = self.files()
                if mode == "exception":
                    real = R.P.atomic_bytes
                    def interrupt(path, value):
                        result = real(path, value)
                        if path.name.startswith("legacy-"):
                            raise OSError("synthetic failure after real legacy archive write")
                        return result
                    output = io.StringIO()
                    with mock.patch.object(R.P, "atomic_bytes", side_effect=interrupt), \
                            mock.patch.object(sys, "argv", ["project_state.py", "migration", "--project",
                                str(self.root), "--source", "1.0", "--target", "1.1", "--status", "partial"]), \
                            contextlib.redirect_stdout(output):
                        code = R.P.main()
                    self.assertEqual(code, 2, output.getvalue())
                    self.assertEqual(self.files(), before)
                else:
                    script = """import os, sys
sys.path.insert(0, sys.argv[1])
import project_state as P
real = P.atomic_bytes
def interrupt(path, value):
    real(path, value)
    if path.name.startswith("legacy-"):
        os._exit(78)
P.atomic_bytes = interrupt
sys.argv = ["project_state.py", "migration", "--project", sys.argv[2],
            "--source", "1.0", "--target", "1.1", "--status", "partial"]
raise SystemExit(P.main())
"""
                    child = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", script,
                        str(Path(R.__file__).parent), str(self.root)], capture_output=True, timeout=30)
                    self.assertEqual(child.returncode, 78, child.stderr)
                    interrupted = self.files()
                    self.assertIn(".project-transaction.json", interrupted)
                    status, payload = self.fixture.p("resume")
                    self.assertEqual(status, 2, payload)
                    self.assertEqual(self.files(), interrupted)
                self.fixture.ok(self.fixture.p("migration", "--source", "1.0", "--target", "1.1",
                    "--migration-id", "recovered", "--status", "partial"))
                archives = list((self.root / "versions/1.1/migrations").glob("*.json"))
                self.assertEqual(len(archives), 2)
                saved = [p for p in archives if p.name.startswith("legacy-")]
                self.assertEqual(len(saved), 1)
                self.assertEqual(json.loads(saved[0].read_text(encoding="utf-8")), legacy)
                self.assertEqual(saved[0].read_bytes(), legacy_bytes)
                self.assertNotIn(".project-transaction.json", self.files())
                events = [json.loads(line) for line in (self.root / "facts.jsonl").read_text(encoding="utf-8").splitlines()]
                self.assertEqual([e.get("migration_id") for e in events if e.get("type") == "migration_recorded"],
                    ["original", "recovered"])
        self.root = original_root
        self.fixture.project = original_root


if __name__ == "__main__":
    unittest.main(verbosity=2)
