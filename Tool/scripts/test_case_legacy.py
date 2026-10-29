"""Real temporary-file and process-exit checks for legacy case preservation."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import case_state
from lib import case_legacy, project_transaction


class CaseLegacyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-case-legacy-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = {"schema": "seep-case/1", "target": "old-input.bin", "depth": {},
                      "stage": "0a", "next_action": "继续核对旧案例", "updated": "2026-10-20"}
        self.original = (json.dumps(self.state, ensure_ascii=False, indent=3) + "\r\n\r\n").encode("utf-8")
        (self.root / "state.json").write_bytes(self.original)
        self.manifest = b'{\n "old_metadata": {"notes": ["keep every field"]}\n}\n\n'
        (self.root / "ai_manifest.json").write_bytes(self.manifest)

    def run_replay(self, *, migrate=False, drop=False, compact=False):
        args = argparse.Namespace(case=str(self.root), migrate=migrate,
                                  drop_legacy=drop, compact=compact, json=False)
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                return case_state.cmd_replay(args) or 0
            except SystemExit as exc:
                return exc.code

    def registrations(self):
        return [row for row in case_state.load_ledger(str(self.root)) if row.get("kind") == "legacy_import"]

    def assert_archived(self):
        records = self.registrations()
        self.assertEqual(len(records), 2)
        for row in records:
            expected = self.original if row["source"] == "state.json" else self.manifest
            self.assertEqual((self.root / row["archive"]).read_bytes(), expected)
            self.assertEqual(row["sha256"], hashlib.sha256(expected).hexdigest())
            self.assertEqual(row["size"], len(expected))

    def test_migrate_activates_state_only_when_absent_and_retains_original_files(self):
        self.assertEqual(self.run_replay(migrate=True), 0)
        self.assert_archived()
        self.assertEqual(case_state.load_state(str(self.root))["target"], self.state["target"])
        self.assertEqual((self.root / "state.json").read_bytes(), self.original)
        self.assertEqual((self.root / "ai_manifest.json").read_bytes(), self.manifest)
        before = (self.root / "facts.jsonl").read_bytes()
        self.assertEqual(self.run_replay(migrate=True), 0)
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)

    def test_drop_archives_first_and_retry_does_not_duplicate_history(self):
        self.assertEqual(self.run_replay(drop=True), 0)
        self.assert_archived()
        self.assertFalse((self.root / "state.json").exists())
        self.assertFalse((self.root / "ai_manifest.json").exists())
        before = (self.root / "facts.jsonl").read_bytes()
        self.assertEqual(self.run_replay(drop=True), 0)
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)

    def test_old_state_never_overwrites_current_ledger_state(self):
        current = dict(self.state, target="current-input.bin", stage="2")
        case_state.save_state(str(self.root), current)
        self.assertEqual(self.run_replay(drop=True), 0)
        self.assert_archived()
        self.assertEqual(case_state.load_state(str(self.root))["target"], "current-input.bin")
        state_record = next(row for row in self.registrations() if row["source"] == "state.json")
        self.assertEqual(state_record["state_policy"], "historical")

    def test_state_kind_normalization_matches_existing_replay(self):
        current = dict(self.state, target="current-normalized.bin", stage="2")
        payload = (json.dumps({"kind": " STATE ", "state": current}) + "\n").encode()
        (self.root / "facts.jsonl").write_bytes(payload)
        self.assertEqual(case_state.load_state(str(self.root))["target"], current["target"])
        self.assertEqual(self.run_replay(drop=True), 0)
        self.assertEqual(case_state.load_state(str(self.root))["target"], current["target"])
        record = next(row for row in self.registrations() if row["source"] == "state.json")
        self.assertEqual(record["state_policy"], "historical")

    def test_invalid_snapshot_fields_refuse_before_any_files_are_changed(self):
        parent = self.root
        for field, value in (("next_action", 42), ("stage_history", {}), ("depth", {"D0": []})):
            with self.subTest(field=field):
                self.root = parent / field
                self.root.mkdir()
                (self.root / "ai_manifest.json").write_bytes(self.manifest)
                raw = json.dumps(dict(self.state, **{field: value})).encode()
                (self.root / "state.json").write_bytes(raw)
                self.assertEqual(self.run_replay(drop=True), 2)
                self.assertEqual((self.root / "state.json").read_bytes(), raw)
                self.assertEqual((self.root / "ai_manifest.json").read_bytes(), self.manifest)
                self.assertFalse((self.root / "facts.jsonl").exists())
                self.assertFalse((self.root / "legacy").exists())

    def test_bad_second_legacy_file_refuses_entire_write_set(self):
        for bad in (b"{broken", b"[]"):
            with self.subTest(payload=bad):
                (self.root / "ai_manifest.json").write_bytes(bad)
                self.assertEqual(self.run_replay(drop=True), 2)
                self.assertEqual((self.root / "state.json").read_bytes(), self.original)
                self.assertEqual((self.root / "ai_manifest.json").read_bytes(), bad)
                self.assertFalse((self.root / "facts.jsonl").exists())
                self.assertFalse((self.root / "legacy").exists())

    def test_archive_damage_is_not_hidden_by_repeating_migration(self):
        self.assertEqual(self.run_replay(migrate=True), 0)
        record = self.registrations()[0]
        archive = self.root / record["archive"]
        before = (self.root / "facts.jsonl").read_bytes()
        archive.write_bytes(b"damaged archive")
        self.assertEqual(self.run_replay(drop=True), 2)
        self.assertEqual((self.root / "state.json").read_bytes(), self.original)
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)
        archive.unlink()
        self.assertEqual(self.run_replay(drop=True), 2)
        self.assertEqual((self.root / "state.json").read_bytes(), self.original)

    def test_removed_sources_do_not_hide_damage_or_bad_archive_registration(self):
        self.assertEqual(self.run_replay(drop=True), 0)
        records = self.registrations()
        archive = self.root / records[0]["archive"]
        original = archive.read_bytes()
        archive.write_bytes(b"corruption after source removal")
        self.assertEqual(self.run_replay(), 2)
        self.assertEqual(self.run_replay(drop=True), 2)
        archive.write_bytes(original)
        self.assertEqual(self.run_replay(), 0)
        ledger = case_state.load_ledger(str(self.root))
        next(row for row in ledger if row.get("kind") == "legacy_import")["state_policy"] = "invented"
        (self.root / "facts.jsonl").write_text("".join(json.dumps(row) + "\n" for row in ledger), encoding="utf-8")
        before = (self.root / "facts.jsonl").read_bytes()
        self.assertEqual(self.run_replay(compact=True), 2)
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)

    def test_write_failures_after_real_archive_ledger_and_unlink_restore_originals(self):
        copy_real, replace_real, unlink_real = case_legacy.atomic_copy, project_transaction._replace, Path.unlink
        for checkpoint in ("archive", "ledger", "unlink"):
            with self.subTest(checkpoint=checkpoint):
                def copy_fail(*args, **kwargs):
                    copy_real(*args, **kwargs)
                    if checkpoint == "archive":
                        raise OSError("fault after archive copy")

                def replace_fail(path, payload):
                    replace_real(path, payload)
                    if checkpoint == "ledger" and path.name == "facts.jsonl":
                        raise OSError("fault after ledger replacement")

                def unlink_fail(path, *args, **kwargs):
                    unlink_real(path, *args, **kwargs)
                    if checkpoint == "unlink" and path.name == "state.json":
                        raise OSError("fault after source removal")

                with patch.object(case_legacy, "atomic_copy", copy_fail), \
                        patch.object(project_transaction, "_replace", replace_fail), \
                        patch.object(Path, "unlink", unlink_fail):
                    self.assertEqual(self.run_replay(drop=True), 2)
                self.assertEqual((self.root / "state.json").read_bytes(), self.original)
                self.assertEqual((self.root / "ai_manifest.json").read_bytes(), self.manifest)
                self.assertFalse((self.root / "facts.jsonl").exists())
                self.assertFalse((self.root / "legacy").exists())
                self.assertFalse((self.root / project_transaction.JOURNAL).exists())

    def test_process_exit_after_removal_recovers_on_real_cli_retry(self):
        program = """
import argparse, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import case_state
original = Path.unlink
def leave_after_unlink(path, *args, **kwargs):
    original(path, *args, **kwargs)
    if path.name == 'state.json':
        os._exit(81)
Path.unlink = leave_after_unlink
case_state.cmd_replay(argparse.Namespace(case=sys.argv[2], migrate=False,
    drop_legacy=True, compact=False, json=False))
"""
        result = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", program, str(HERE), str(self.root)],
                                capture_output=True, encoding="utf-8", timeout=15)
        self.assertEqual(result.returncode, 81, result.stderr)
        self.assertTrue((self.root / project_transaction.JOURNAL).is_file())
        self.assertFalse((self.root / "state.json").exists())
        self.assertEqual(self.run_replay(), 2)
        retry = subprocess.run([sys.executable, "-B", "-X", "utf8", str(HERE / "case_state.py"),
                                "replay", "--case", str(self.root), "--drop-legacy"],
                               capture_output=True, encoding="utf-8", timeout=15)
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assert_archived()
        self.assertEqual(case_state.load_state(str(self.root))["target"], self.state["target"])
        self.assertFalse((self.root / project_transaction.JOURNAL).exists())

    def test_archive_junction_is_refused_and_external_bytes_are_unchanged(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "sentinel").write_bytes(b"keep external bytes")
        link = self.root / "legacy"
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(outside), str(link))
        else:
            link.symlink_to(outside, target_is_directory=True)
        self.addCleanup(link.rmdir if os.name == "nt" else link.unlink)
        self.assertEqual(self.run_replay(drop=True), 2)
        self.assertEqual({p.name: p.read_bytes() for p in outside.iterdir()}, {"sentinel": b"keep external bytes"})
        self.assertEqual((self.root / "state.json").read_bytes(), self.original)
        self.assertFalse((self.root / "facts.jsonl").exists())

    def test_compaction_retains_exact_event_claim_and_latest_state_bytes(self):
        old = (json.dumps({"kind": "state", "state": self.state}) + "\r\n").encode()
        event = b'  {"kind":"event", "tool":"fixture", "ok":true}  \r\n'
        claim = b'{"id":"C-01","status":"hypothesis","claim":"still here"}\n'
        latest = (json.dumps({"kind": "state", "state": dict(self.state, stage="0b")}) + "\n").encode()
        (self.root / "facts.jsonl").write_bytes(old + b"\r\n" + event + claim + latest)
        self.assertEqual(self.run_replay(compact=True), 0)
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), b"\r\n" + event + claim + latest)
        self.assertEqual((self.root / "state.json").read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
