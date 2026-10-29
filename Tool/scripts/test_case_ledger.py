"""Case ledger corruption and cooperating writer regressions, in temporary cases."""
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

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import case_state as C


class CaseLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-case-ledger-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.facts = self.root / "facts.jsonl"
        self.claim = {"id": "C-001", "claim": "Fixture is readable", "status": "proven",
                      "confidence": "observed", "authority": "shipped-artifact",
                      "evidence": ["capture/review.log"], "how": "read fixture"}
        (self.root / "capture").mkdir()
        (self.root / "capture/review.log").write_text("fixture evidence\n", encoding="utf-8")

    def write(self, rows):
        self.facts.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    def call(self, function, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                result = function(*args)
                code = result if type(result) is int else 0
            except SystemExit as exc:
                code, result = exc.code, None
        return code, result, output.getvalue()

    def test_malformed_rows_are_never_filtered_out_of_a_good_case(self):
        bad = [None, [], 7, {}, {"kind": 3}, {"id": "C-002"},
               dict(self.claim, id="C-002", kind="cliam"),
               {"kind": "claim", "id": "C-002", "status": "proven"},
               dict(self.claim, id="C-002", status="invented"),
               dict(self.claim, id="C-002", authority="invented"),
               dict(self.claim, id="C-002", confidence=[]),
               dict(self.claim, id="C-002", evidence="capture/review.log"),
               dict(self.claim, id="C-002", evidence=[7])]
        for row in bad:
            with self.subTest(row=row):
                self.write([self.claim, row])
                before = self.facts.read_bytes()
                code, _, output = self.call(C.load_facts, str(self.root))
                self.assertEqual(code, 2, output)
                self.assertIn("2", output)
                self.assertEqual(self.facts.read_bytes(), before)

    def test_duplicate_ids_and_json_keys_are_rejected(self):
        for rows in ([self.claim, self.claim],
                     [self.claim, {"kind": "repro", "id": "C-001"}]):
            with self.subTest(rows=rows):
                self.write(rows)
                self.assertEqual(self.call(C.load_ledger, str(self.root))[0], 2)
        self.facts.write_text('{"kind":"event","kind":"claim"}\n', encoding="utf-8")
        self.assertEqual(self.call(C.load_ledger, str(self.root))[0], 2)

    def test_corruption_diagnostic_uses_physical_line_number(self):
        self.facts.write_text(json.dumps(self.claim) + "\n\n\n{bad\n", encoding="utf-8")
        code, _, output = self.call(C.load_ledger, str(self.root))
        self.assertEqual(code, 2)
        self.assertRegex(output, r"(?:line|第)\s*4")

    def test_state_and_list_containers_are_checked_before_projection(self):
        states = [{"depth": []}, {"depth": {"D0": []}},
                  {"depth": {"D0": {"result": "invented"}}},
                  {"instruments": []}, {"instruments": {"baseline": None}},
                  {"stage": "invented"}, {"stage_history": [7]},
                  {"awaiting_human": {"options": []}}, {"deliveries": [None]},
                  {"next_action": 4}]
        rows = [{"kind": "state", "state": state} for state in states]
        rows += [{"kind": "state", "state": []},
                 {"kind": "plan", "items": [7]},
                 {"kind": "plan", "items": [{"p": "not-a-number"}]},
                 {"kind": "gaps", "items": {}}]
        for row in rows:
            with self.subTest(row=row):
                self.write([row])
                self.assertEqual(self.call(C.load_ledger, str(self.root))[0], 2)

    def test_invalid_new_records_cannot_poison_ledger(self):
        self.write([self.claim])
        before = self.facts.read_bytes()
        for function, value in ((C.append_fact, dict(self.claim, id="C-002", evidence={})),
                                (C.append_fact, self.claim),
                                (C.save_state, {"depth": []}),
                                (C.save_plan, [7]), (C._rewrite_claims, [dict(self.claim, status="bad")])):
            with self.subTest(writer=function.__name__):
                code, _, _ = self.call(function, str(self.root), value)
                self.assertEqual(code, 2)
                self.assertEqual(self.facts.read_bytes(), before)

    def test_old_partial_state_and_explicit_extension_kinds_remain_readable(self):
        rows = [{"kind": " STATE ", "state": {"target": "old.bin", "max_level": "L1"}},
                {"kind": "custom-domain-observation", "payload": {"any": [1, 2]}},
                dict(self.claim, confidence="", authority="")]
        self.write(rows)
        self.assertEqual(C.load_state(str(self.root))["target"], "old.bin")
        self.assertEqual(C.load_ledger(str(self.root)), rows)
        self.assertEqual(C.verify_case(str(self.root))["verdict"], "unknown")

    def test_append_preserves_a_valid_last_line_without_newline(self):
        self.facts.write_text(json.dumps(self.claim), encoding="utf-8")
        C.append_fact(str(self.root), {"kind": "event", "action": "fixture-check"})
        self.assertEqual(len(C.load_ledger(str(self.root))), 2)

    def test_manifest_correct_hash_cannot_bind_files_outside_case(self):
        outside = Path(tempfile.mkdtemp(prefix="seep-case-outside-", dir=self.root.parent))
        self.addCleanup(lambda: __import__("shutil").rmtree(outside, ignore_errors=True))
        payload = outside / "material.bin"
        payload.write_bytes(b"outside case material\n")
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        manifest = self.root / "artifacts" / "MANIFEST.sha256"
        manifest.parent.mkdir()
        for reference in ("../%s/material.bin" % outside.name, str(payload)):
            with self.subTest(reference=reference):
                manifest.write_text("%s  %s\n" % (digest, reference), encoding="utf-8")
                self.assertTrue(C._chk_manifest(str(self.root), str(manifest)))
        inside = manifest.parent / "material.bin"
        inside.write_bytes(b"inside case material\n")
        inside_digest = hashlib.sha256(inside.read_bytes()).hexdigest()
        manifest.write_text("%s  material.bin\n" % inside_digest, encoding="utf-8")
        self.assertEqual(C._chk_manifest(str(self.root), str(manifest)), [])

    def test_pending_transaction_blocks_all_common_readers_without_changing_journal(self):
        self.write([self.claim])
        marker = self.root / ".project-transaction.json"
        marker.write_text('{"interrupted":true}', encoding="utf-8")
        for reader in (C.load_ledger, C.load_facts, C.load_state, C.load_plan, C.load_gaps):
            with self.subTest(reader=reader.__name__):
                code, _, output = self.call(reader, str(self.root))
                self.assertEqual(code, 2, output)
        self.assertEqual(marker.read_text(encoding="utf-8"), '{"interrupted":true}')

    def test_archive_corruption_blocks_common_readers(self):
        from lib.case_legacy import update
        (self.root / "state.json").write_text(json.dumps({"target": "old.bin", "stage": "intake", "depth": {}}), encoding="utf-8")
        update(str(self.root), migrate=True, drop=True, compact=False,
               load_ledger=C.load_ledger, lease_guard=lambda _: None)
        self.assertEqual(C.load_state(str(self.root))["target"], "old.bin")
        archive = next((self.root / "legacy").iterdir())
        archive.write_bytes(b"changed")
        for reader in (C.load_ledger, C.load_facts, C.load_state):
            with self.subTest(reader=reader.__name__):
                self.assertEqual(self.call(reader, str(self.root))[0], 2)

    def test_missing_case_and_directory_ledger_are_not_empty_success(self):
        self.assertEqual(self.call(C.load_ledger, str(self.root / "missing"))[0], 2)
        self.facts.mkdir()
        self.assertEqual(self.call(C.load_ledger, str(self.root))[0], 2)

    def test_real_writer_cannot_pass_held_transaction_lock(self):
        from lib.project_lock import project_lock
        self.write([dict(self.claim, status="hypothesis", evidence=[])])
        before = self.facts.read_bytes()
        ready = self.root / "writer-ready"
        driver = self.root / "writer.py"
        driver.write_text(
            "import sys\nfrom pathlib import Path\n"
            f"sys.path.insert(0, {str(HERE)!r})\nimport case_state\n"
            f"Path({str(ready)!r}).write_text('ready')\n"
            f"sys.argv=['case_state.py','prove','--case',{str(self.root)!r},'--id','C-001',"
            "'--evidence','capture/review.log','--confidence','observed','--authority','shipped-artifact']\n"
            "case_state.main()\n", encoding="utf-8")
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
        with project_lock(self.root):
            process = subprocess.Popen([sys.executable, "-B", str(driver)], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=env)
            try:
                # The child signals before entering the real CLI, while the lock is held.
                import time
                deadline = time.monotonic() + 5
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(ready.exists())
                try:
                    process.wait(timeout=0.4)
                except subprocess.TimeoutExpired:
                    pass
                else:
                    self.fail("writer completed while another process held the shared lock")
                self.assertEqual(self.facts.read_bytes(), before)
            except BaseException:
                process.kill()
                process.communicate(timeout=5)
                raise
        stdout, stderr = process.communicate(timeout=8)
        self.assertEqual(process.returncode, 0, (stdout, stderr))
        self.assertEqual(C.load_facts(str(self.root))[0]["status"], "proven")


if __name__ == "__main__":
    unittest.main()
