#!/usr/bin/env python3
"""Project facts and migration identity checks through the real CLI."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("project_state.py")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False) + "\n", encoding="utf-8")


class LedgerIdentity(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="seep-ledger-identity-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.project = self.base / "project"
        self.target = self.base / "input.bin"
        self.target.write_bytes(b"synthetic target\n")
        self.ok("init", "--project-id", "identity-test", "--target", self.target)
        self.ok("version", "--version", "1.1", "--parent", "1.0", "--target", self.target)
        self.ok("run", "--version", "1.1", "--run-id", "r1")
        self.facts = self.project / "facts.jsonl"
        self.run_path = self.project / "versions/1.1/runs/r1/run.json"

    def cli(self, *args):
        proc = subprocess.run([sys.executable, "-B", str(SCRIPT), str(args[0]),
                               "--project", str(self.project), *map(str, args[1:])],
                              capture_output=True, text=True, encoding="utf-8", timeout=45,
                              env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8"))
        self.assertEqual(proc.stderr, "", proc.stderr)
        return proc.returncode, json.loads(proc.stdout)

    def ok(self, *args):
        code, payload = self.cli(*args)
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["ok"], payload)
        return payload

    def assert_blocked_and_frozen(self):
        facts = self.facts.read_bytes()
        run = self.run_path.read_bytes()
        code, payload = self.cli("resume")
        self.assertEqual(code, 2, payload)
        self.assertTrue(payload["handoff"]["state_errors"], payload)
        self.assertFalse(payload["handoff"]["acceptance_complete"])
        code, payload = self.cli("finish-run", "--version", "1.1", "--run-id", "r1",
                                 "--status", "failed")
        self.assertEqual(code, 2, payload)
        self.assertFalse(payload["ok"], payload)
        self.assertEqual(facts, self.facts.read_bytes())
        self.assertEqual(run, self.run_path.read_bytes())

    def test_bad_fact_identity_or_shape_blocks_read_and_terminal_write(self):
        original = self.facts.read_bytes()
        rows = [json.loads(line) for line in original.splitlines()]
        event = next(row for row in rows if row.get("kind") == "event")
        changes = ({"project_id": "other-project"}, {"kind": "receipt"},
                   {"type": []}, {"id": None}, {"message": {}},
                   {"created_at": []}, {"version_id": "../escape"},
                   {"run_id": []}, {"type": "run_finished", "status": "success"},
                   {"type": "run_finished", "run_id": None, "status": "failed"})
        for change in changes:
            with self.subTest(change=change):
                bad = dict(event, **change)
                bad["id"] = change.get("id", "E-bad")
                self.facts.write_bytes(original + json.dumps(bad).encode("utf-8") + b"\n")
                self.assert_blocked_and_frozen()
        self.facts.write_bytes(original)
        self.ok("resume")

    def test_duplicate_event_id_and_foreign_state_are_errors(self):
        original = self.facts.read_bytes()
        rows = [json.loads(line) for line in original.splitlines()]
        for extra in (next(row for row in rows if row.get("kind") == "event"),
                      dict(rows[0], project_id="different-project")):
            with self.subTest(extra=extra):
                self.facts.write_bytes(original + json.dumps(extra).encode("utf-8") + b"\n")
                self.assert_blocked_and_frozen()
        self.facts.write_bytes(original)
        self.ok("resume")

    def migration(self):
        self.ok("migration", "--source", "1.0", "--target", "1.1", "--status", "planned",
                "--migration-id", "plan")
        path = self.project / "versions/1.1/migration.json"
        data = read(path)
        archive = path.parent / "migrations" / (data["revision_id"] + ".json")
        return path, archive, data

    def test_bad_migration_bindings_block_read_and_write(self):
        path, archive, original = self.migration()
        changes = ({"project_id": "other-project"}, {"from_version": "1.1"},
                   {"from_version": "missing"}, {"migration_id": []},
                   {"revision_id": "different-revision"}, {"revision_id": []},
                   {"source_manifest": "versions/1.1/manifest.json"},
                   {"target_manifest": "../outside.json"}, {"source_sha256": "0" * 64},
                   {"target_sha256": "1" * 64}, {"status": "success"}, {"created_at": []})
        for change in changes:
            with self.subTest(change=change):
                # Change both copies: consistency between copies alone is insufficient.
                bad = dict(original, **change)
                write(path, bad)
                write(archive, bad)
                self.assert_blocked_and_frozen()
        write(path, original)
        write(archive, original)
        self.ok("resume")

    def test_archive_filename_and_same_revision_owner_are_checked(self):
        path, archive, original = self.migration()
        wrong = archive.with_name("wrong-revision.json")
        archive.rename(wrong)
        self.assert_blocked_and_frozen()
        wrong.rename(archive)
        changed = dict(original, migration_id="another-plan")
        write(path, changed)
        self.assert_blocked_and_frozen()
        write(path, original)
        self.ok("resume")

    def test_linked_migration_archive_directory_is_refused(self):
        _, archive, original = self.migration()
        external = self.base / "outside-migrations"
        external.mkdir()
        outside = external / archive.name
        write(outside, original)
        link = archive.parent
        saved = link.with_name("saved-migrations")
        link.rename(saved)
        try:
            if os.name == "nt":
                import _winapi
                _winapi.CreateJunction(str(external), str(link))
            else:
                link.symlink_to(external, target_is_directory=True)
            before = outside.read_bytes()
            self.assert_blocked_and_frozen()
            self.assertEqual(before, outside.read_bytes())
        finally:
            if link.is_symlink():
                link.unlink()
            elif link.exists():
                os.rmdir(link)  # Remove the junction itself, never its target.
            saved.rename(link)
        self.ok("resume")

    def test_legacy_migration_without_revision_or_optional_bindings_stays_readable(self):
        path = self.project / "versions/1.1/migration.json"
        legacy = {"schema": "seep-migration/1", "project_id": "identity-test",
                  "migration_id": "legacy-plan", "from_version": "1.0", "to_version": "1.1",
                  "status": "partial", "created_at": "2000-01-01T00:00:00Z", "align": {}}
        write(path, legacy)
        self.ok("resume")
        self.ok("migration", "--source", "1.0", "--target", "1.1", "--status", "planned")
        archives = list((path.parent / "migrations").glob("legacy-*.json"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(read(archives[0]), legacy)
        self.assertEqual(archives[0].stem, "legacy-" + hashlib.sha256(archives[0].read_bytes()).hexdigest())
        self.ok("resume")

    def test_custom_event_and_legacy_message_status_remain_valid(self):
        self.ok("event", "--type", "cross-domain-observation", "--message", "HTTP observation")
        self.ok("finish-run", "--version", "1.1", "--run-id", "r1", "--status", "failed")
        rows = [json.loads(line) for line in self.facts.read_bytes().splitlines()]
        for row in rows:
            if row.get("type") == "run_finished":
                row.pop("status")  # Pre-status-field format has the status in the message.
        self.facts.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        self.ok("resume")

    def test_invalid_new_event_is_rejected_without_writing(self):
        original = self.facts.read_bytes()
        for args in (("--type", "", "--message", "empty type"),
                     ("--type", "observation", "--message", "bad version", "--version", "../outside")):
            with self.subTest(args=args):
                code, payload = self.cli("event", *args)
                self.assertEqual(code, 2, payload)
                self.assertEqual(original, self.facts.read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
