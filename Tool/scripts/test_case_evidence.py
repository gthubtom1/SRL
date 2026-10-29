"""Actual evidence files and reference graphs; no target or network execution."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import case_state as C


class CaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-case-evidence-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        isolated_home = self.base / ".isolated-home"
        isolated_agent = self.base / ".isolated-agent"
        isolated_home.mkdir()
        isolated_agent.mkdir()
        patch.dict(os.environ, {
            "HOME": str(isolated_home),
            "USERPROFILE": str(isolated_home),
            "APPDATA": str(isolated_home / "AppData" / "Roaming"),
            "LOCALAPPDATA": str(isolated_home / "AppData" / "Local"),
            "PI_CODING_AGENT_DIR": str(isolated_agent),
        }, clear=False).start()
        self.root = self.base / "case"
        self.root.mkdir()
        self.log = self.root / "capture.log"
        self.log.write_bytes(b"PASS original evidence\n")
        self.good = {"id": "C-001", "claim": "Fixture readable", "status": "proven",
                     "confidence": "observed", "authority": "shipped-artifact",
                     "evidence": ["capture.log"], "how": "fixture read"}
        self.addCleanup(patch.stopall)
        patch("subprocess.run", side_effect=AssertionError("execution forbidden")).start()

    def write(self, rows):
        (self.root / "facts.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def refused(self, value):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            try:
                C.require_evidence(value, str(self.root))
            except SystemExit as exc:
                self.assertEqual(exc.code, 2)
                self.assertIn("evidence-", output.getvalue())
                return
        self.fail("accepted invalid evidence: %r" % value)

    def test_current_file_is_required_for_strong_counts(self):
        self.write([self.good])
        self.assertEqual(C.verify_case(str(self.root))["strong"], 1)
        for mode in ("missing", "empty", "directory"):
            with self.subTest(mode=mode):
                if self.log.exists():
                    self.log.unlink()
                if mode == "empty":
                    self.log.write_bytes(b"")
                elif mode == "directory":
                    self.log.mkdir()
                result = C.verify_case(str(self.root))
                self.assertNotEqual(result["verdict"], "pass")
                self.assertEqual(result["strong"], 0)
                self.assertTrue(any("C-001" in why and "evidence" in why for why in result["reasons"]))

    def test_directories_and_unrelated_work_paths_are_not_file_evidence(self):
        directory = self.root / "notes"
        directory.mkdir()
        unrelated = self.base / "work" / "foreign.log"
        unrelated.parent.mkdir()
        unrelated.write_bytes(b"unrelated")
        for value in (str(directory), str(unrelated), "python worker.py --out %s rc=0" % unrelated):
            with self.subTest(value=value):
                self.refused(value)
        self.assertEqual(C.require_evidence(str(self.log), str(self.root)), str(self.log))

    def test_hash_must_match_current_bytes_not_its_own_ledger_text(self):
        fake = "a" * 64
        self.write([dict(self.good, evidence=[fake])])
        self.refused(fake)
        self.log.write_text("declared sha256=" + fake, encoding="utf-8")
        self.refused(fake)
        actual = hashlib.sha256(self.log.read_bytes()).hexdigest()
        self.assertEqual(C.require_evidence(actual, str(self.root)), actual)
        self.assertNotEqual(C.verify_case(str(self.root))["verdict"], "pass")

    def test_references_require_anchored_proven_claims_and_all_named_ids(self):
        self.write([self.good, dict(self.good, id="C-002", evidence=["C-001"])])
        self.assertEqual(C.verify_case(str(self.root))["strong"], 2)
        self.refused("C-001 and C-999")
        self.write([dict(self.good, status="hypothesis"), dict(self.good, id="C-002", evidence=["C-001"])])
        result = C.verify_case(str(self.root))
        self.assertEqual(result["strong"], 0)
        self.assertNotEqual(result["verdict"], "pass")

    def test_self_reference_and_two_claim_cycle_do_not_prove_anything(self):
        for rows in ([dict(self.good, evidence=["C-001"])],
                     [dict(self.good, evidence=["C-002"]), dict(self.good, id="C-002", evidence=["C-001"]) ]):
            with self.subTest(rows=rows):
                self.write(rows)
                result = C.verify_case(str(self.root))
                self.assertEqual(result["strong"], 0)
                self.assertNotEqual(result["verdict"], "pass")

    def test_reported_claim_never_counts_as_strong(self):
        self.write([dict(self.good, authority="reported")])
        self.assertEqual(C.verify_case(str(self.root))["strong"], 0)
        self.assertNotEqual(C.verify_case(str(self.root))["verdict"], "pass")

    def test_new_proof_records_fingerprint_and_detects_same_size_change(self):
        self.write([dict(self.good, status="hypothesis", evidence=[])])
        args = argparse.Namespace(case=str(self.root), id="C-001", evidence="capture.log",
                                  confidence="observed", authority="shipped-artifact")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(C.cmd_prove(args) or 0, 0)
        fact = C.load_facts(str(self.root))[0]
        self.assertTrue(fact.get("evidence_bindings"))
        self.assertEqual(C.verify_case(str(self.root))["strong"], 1)
        before = self.log.read_bytes()
        self.log.write_bytes(b"X" * len(before))
        result = C.verify_case(str(self.root))
        self.assertEqual(result["strong"], 0)
        self.assertNotEqual(result["verdict"], "pass")

    def test_empty_verify_all_never_reports_success(self):
        args = argparse.Namespace(all=True, json=True)
        with patch.object(C, "cases_root", return_value=str(self.base / "no-cases")):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertNotEqual(C.cmd_verify(args), 0)

    def test_bound_hash_keeps_its_original_file_when_a_duplicate_is_added(self):
        self.write([dict(self.good, status="hypothesis", evidence=[])])
        digest = hashlib.sha256(self.log.read_bytes()).hexdigest()
        args = argparse.Namespace(case=str(self.root), id="C-001", evidence=digest,
                                  confidence="observed", authority="shipped-artifact")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(C.cmd_prove(args) or 0, 0)
        (self.root / "aaa-duplicate.log").write_bytes(self.log.read_bytes())
        self.assertEqual(C.verify_case(str(self.root))["strong"], 1)
        self.log.unlink()
        self.assertEqual(C.verify_case(str(self.root))["strong"], 0)

    def test_pending_transaction_refuses_even_direct_file_evidence(self):
        self.write([self.good])
        (self.root / ".project-transaction.json").write_text("{}", encoding="utf-8")
        self.refused("capture.log")

    def test_verify_origin_resolves_repository_paths_independent_of_cwd(self):
        repo = self.base / "repo"
        case = repo / "Tool" / "cases" / "relative"
        target = case / "target" / "input.apk"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"APK fixture")
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        meta = {
            "id": "relative",
            "target": {
                "path": "Tool/cases/relative/target/input.apk",
                "sha256": digest,
                "size": target.stat().st_size,
            },
            "target_files": [{
                "path": "target/input.apk",
                "sha256": digest,
                "size": target.stat().st_size,
            }],
        }
        (case / "case.json").write_text(json.dumps(meta), encoding="utf-8")
        unrelated = self.base / "unrelated"
        unrelated.mkdir()

        with patch.object(C, "REPO_ROOT", str(repo)):
            first = io.StringIO()
            old = Path.cwd()
            self.addCleanup(lambda: __import__("os").chdir(old))
            __import__("os").chdir(str(unrelated))
            with contextlib.redirect_stdout(first):
                self.assertEqual(C.cmd_verify_origin(
                    argparse.Namespace(case=str(case))) or 0, 0)

            __import__("os").chdir(str(repo))
            second = io.StringIO()
            with contextlib.redirect_stdout(second):
                self.assertEqual(C.cmd_verify_origin(
                    argparse.Namespace(case=str(case))) or 0, 0)

        self.assertEqual(first.getvalue().strip(), second.getvalue().strip())
        self.assertIn("[OK] 原件未变", first.getvalue())
        self.assertEqual(
            C._resolve_registered_path(str(case), "target/input.apk")[1], "case")
        with patch.object(C, "REPO_ROOT", str(repo)):
            self.assertEqual(
                C._resolve_registered_path(
                    str(case), "Tool/cases/relative/target/input.apk")[1],
                "repository")

    def test_verify_origin_rejects_conflicting_target_fingerprints(self):
        case = self.base / "conflict"
        target = case / "target" / "input.apk"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"APK fixture")
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        meta = {
            "id": "conflict",
            "target": {
                "path": "target/input.apk",
                "sha256": digest,
                "size": target.stat().st_size,
            },
            "target_files": [{
                "path": "target/input.apk",
                "sha256": digest,
                "size": target.stat().st_size + 1,
            }],
        }
        (case / "case.json").write_text(json.dumps(meta), encoding="utf-8")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(C.cmd_verify_origin(
                argparse.Namespace(case=str(case))), 2)
        self.assertIn("conflicts", output.getvalue())

    def test_strict_evidence_contract_rejects_traceback_rc_and_missing_output(self):
        case_dir = self.base / "semantic"
        case_dir.mkdir()
        log = case_dir / "run.log"
        log.write_text("root_marker.dex=1\nroot_marker.so=0\nstatus=PASS\n",
                       encoding="utf-8")
        row = dict(
            self.good,
            evidence=["run.log"],
            evidence_contract={
                "version": 1,
                "require_text": ["root_marker.dex=1", "root_marker.so=0"],
                "allow_traceback": False,
                "allow_nonzero_rc": False,
                "allow_error_lines": False,
            },
        )
        self.write([row])
        # write() targets self.root; move the ledger beside the semantic case.
        (self.root / "facts.jsonl").replace(case_dir / "facts.jsonl")
        self.assertEqual(C.verify_case(str(case_dir))["verdict"], "pass")

        log.write_text("root_marker.dex=1\nroot_marker.so=0\n"
                       "Traceback (most recent call last):\nNameError: missing\n",
                       encoding="utf-8")
        result = C.verify_case(str(case_dir))
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("Traceback", result["semantic_errors"]["C-001"][0])

        log.write_text("root_marker.dex=1\nroot_marker.so=0\nrc=1\n",
                       encoding="utf-8")
        result = C.verify_case(str(case_dir))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("non-zero" in item
                            for item in result["semantic_errors"]["C-001"]))

        log.write_text("root_marker.dex=1\nstatus=PASS\n", encoding="utf-8")
        result = C.verify_case(str(case_dir))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("root_marker.so=0" in item
                            for item in result["semantic_errors"]["C-001"]))

        log.write_text("root_marker.dex=2\nroot_marker.so=0\n[ERROR] hidden failure\n",
                       encoding="utf-8")
        result = C.verify_case(str(case_dir))
        self.assertEqual(result["verdict"], "fail")
        errors = result["semantic_errors"]["C-001"]
        self.assertTrue(any("root_marker.dex=1" in item for item in errors))
        self.assertTrue(any("ERROR" in item for item in errors))

        row["evidence_contract"]["reject_json_ok_false"] = True
        self.write([row])
        (self.root / "facts.jsonl").replace(case_dir / "facts.jsonl")
        log.write_text(
            'root_marker.dex=1\nroot_marker.so=0\n{"ok": false}\n',
            encoding="utf-8")
        result = C.verify_case(str(case_dir))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("ok=false" in item
                            for item in result["semantic_errors"]["C-001"]))

    def test_structured_exception_can_allow_expected_diagnostic_lines(self):
        case_dir = self.base / "expected"
        case_dir.mkdir()
        (case_dir / "run.log").write_text(
            "EXPECTED_OUTPUT\n"
            "Traceback (most recent call last):\n"
            "ValueError: fixture\n"
            "EXPECTED_TRACEBACK\n"
            "expected negative control rc=2\n"
            "[ERROR] EXPECTED_ERROR\n",
            encoding="utf-8")
        row = dict(
            self.good,
            evidence=["run.log"],
            evidence_contract={
                "version": 1,
                "require_text": ["EXPECTED_OUTPUT"],
                "allow_traceback_patterns": ["EXPECTED_TRACEBACK"],
                "allow_nonzero_rc_patterns": ["expected negative control rc=2"],
                "allow_error_line_patterns": ["EXPECTED_ERROR"],
            },
        )
        (case_dir / "facts.jsonl").write_text(
            json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
        self.assertEqual(C.verify_case(str(case_dir))["verdict"], "pass")

    def test_apk_profile_requires_inside_targets_and_machine_contracts(self):
        target = self.root / "target" / "input.apk"
        target.parent.mkdir()
        target.write_bytes(b"APK fixture")
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        meta = {
            "id": "apk-profile",
            "acceptance_profile": "apk-target/1",
            "target": {
                "path": "target/input.apk",
                "sha256": digest,
                "size": target.stat().st_size,
            },
            "target_files": [{
                "path": "target/input.apk",
                "sha256": digest,
                "size": target.stat().st_size,
            }],
        }
        (self.root / "case.json").write_text(json.dumps(meta), encoding="utf-8")
        row = dict(
            self.good,
            evidence=["capture.log"],
            evidence_contract={
                "version": 1,
                "require_text": ["PASS original evidence"],
            },
        )
        self.write([row])
        self.assertEqual(C.verify_case(str(self.root))["verdict"], "pass")

        no_contract = dict(row)
        no_contract.pop("evidence_contract")
        self.write([no_contract])
        result = C.verify_case(str(self.root))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("evidence_contract" in item
                            for item in result["acceptance_profile_errors"]))

        meta["target"]["path"] = str(self.base / "outside.apk")
        (self.root / "case.json").write_text(json.dumps(meta), encoding="utf-8")
        self.write([row])
        result = C.verify_case(str(self.root))
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("case-relative" in item
                            for item in result["acceptance_profile_errors"]))

    def test_receipt_refresh_recomputes_bytes_and_preserves_audit_history(self):
        self.write([self.good])
        receipt_path = self.base / "verification" / "case-2026-10-24.json"
        receipt_path.parent.mkdir()
        old_hashes = {
            "facts.jsonl": "0" * 64,
            "capture.log": "1" * 64,
        }
        receipt = {
            "schema": "seep.verification/1",
            "case": self.root.name,
            "date": "2026-10-24",
            "problem": "preserve this problem",
            "verifier": "python Tool/scripts/case_state.py verify --case case",
            "cohorts": {
                "baseline": {
                    "claims": 0, "proven": 0, "strong": 0, "verdict": "unknown",
                },
                "final": {
                    "claims": 9, "proven": 8, "strong": 7, "verdict": "pass",
                },
            },
            "source_sha256": old_hashes,
            "interpretation": "preserve this interpretation",
            "limitations": ["no new target run"],
            "audit_corrections": [],
        }
        receipt_path.write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        args = argparse.Namespace(
            case=str(self.root),
            receipt=str(receipt_path),
            reason="fixture bytes now match the ledger",
            json=True,
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(C.cmd_receipt_refresh(args), 0)
        self.assertTrue(json.loads(output.getvalue())["refreshed"])

        updated = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(updated["problem"], receipt["problem"])
        self.assertEqual(updated["interpretation"], receipt["interpretation"])
        self.assertEqual(updated["cohorts"]["baseline"], receipt["cohorts"]["baseline"])
        self.assertEqual(updated["cohorts"]["final"]["claims"], 1)
        self.assertEqual(updated["cohorts"]["final"]["proven"], 1)
        self.assertEqual(updated["cohorts"]["final"]["strong"], 1)
        for relative in old_hashes:
            actual = hashlib.sha256((self.root / relative).read_bytes()).hexdigest()
            self.assertEqual(updated["source_sha256"][relative], actual)
        correction = updated["audit_corrections"][-1]
        self.assertEqual(correction["kind"], "receipt-byte-refresh")
        self.assertEqual(correction["previous_final"], receipt["cohorts"]["final"])
        self.assertEqual(correction["previous_source_sha256"], old_hashes)
        self.assertFalse(correction["target_executed"])
        self.assertFalse(correction["new_target_measurements"])

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(C.cmd_receipt_refresh(args), 0)
        self.assertFalse(json.loads(output.getvalue())["refreshed"])
        unchanged = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(len(unchanged["audit_corrections"]), 1)

    def test_receipt_refresh_missing_bound_file_does_not_modify_receipt(self):
        self.write([self.good])
        receipt_path = self.base / "verification" / "case-missing.json"
        receipt_path.parent.mkdir()
        receipt = {
            "schema": "seep.verification/1",
            "case": self.root.name,
            "problem": "fixture",
            "cohorts": {
                "baseline": {"claims": 0, "proven": 0, "strong": 0},
                "final": {"claims": 0, "proven": 0, "strong": 0},
            },
            "source_sha256": {
                "facts.jsonl": "0" * 64,
                "missing.log": "1" * 64,
            },
            "interpretation": "fixture",
        }
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        before = receipt_path.read_bytes()
        args = argparse.Namespace(
            case=str(self.root),
            receipt=str(receipt_path),
            reason="test",
            json=True,
        )
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                C.cmd_receipt_refresh(args)
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(receipt_path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
