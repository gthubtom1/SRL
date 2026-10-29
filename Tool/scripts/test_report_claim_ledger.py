#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CLI integration for the report claim-ledger witness boundary.

Only synthetic files are used.  Claim ledgers are consumed through Core-registered
project evidence; the report never scans an external case directory.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "Tool/scripts/project_state.py"
REPORT = ROOT / "Tool/scripts/project_report.py"
TMP = ROOT / "work/final-delivery/tmp"
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")


def call(script: Path, *args):
    proc = subprocess.run([sys.executable, "-B", "-X", "utf8", str(script),
                           *map(str, args)], cwd=str(ROOT), env=ENV,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=55)
    try:
        value = json.loads(proc.stdout)
    except ValueError:
        raise AssertionError((proc.returncode, proc.stdout[-2000:], proc.stderr[-1000:]))
    return proc.returncode, value, proc.stdout


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ClaimReportCLI(unittest.TestCase):
    def setUp(self):
        TMP.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="claim-report-", dir=str(TMP))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.project = self.base / "project"
        self.source = self.base / "target.bin"
        self.source.write_bytes(b"synthetic target")
        rc, out, text = call(STATE, "init", "--project-id", "claim-project",
                             "--target", self.source, "--project", self.project)
        self.assertEqual(rc, 0, text)
        rc, out, text = call(STATE, "run", "--project", self.project,
                             "--version", "1.0", "--run-id", "run-a")
        self.assertEqual(rc, 0, text)
        self.case_dir = self.project / "case-source"
        self.case_dir.mkdir()
        self.support_path = self.project / "versions/1.0/artifacts/support.bin"
        self.support_path.parent.mkdir(parents=True, exist_ok=True)
        self.support_path.write_bytes(b"synthetic support witness")
        (self.case_dir / "support.bin").write_bytes(self.support_path.read_bytes())
        self._register("ev-support", self.support_path, self.case_dir / "support.bin",
                       "support evidence")

    def _register(self, evidence_id: str, local_path: Path, source_path: Path,
                  kind: str = "ledger", run_id: str = "run-a"):
        # source is deliberately project-relative: report verification never reads it.
        source_ref = source_path.relative_to(self.project).as_posix()
        rc, out, text = call(STATE, "evidence", "--project", self.project,
                             "--version", "1.0", "--run-id", run_id,
                             "--kind", "evidence", "--evidence-id", evidence_id,
                             "--target-sha256", json.loads(
                                 (self.project / "versions/1.0/version.json").read_text(
                                     encoding="utf-8"))["sha256"],
                             "--path", local_path.relative_to(self.project).as_posix(),
                             "--sha256", digest(local_path), "--size", local_path.stat().st_size,
                             "--source", source_ref, "--how", kind)
        self.assertEqual(rc, 0, text)

    def _ledger(self, evidence_id: str, records, source_name="claims.jsonl",
                run_id: str = "run-a"):
        artifact = self.project / "versions/1.0/artifacts" / source_name
        artifact.parent.mkdir(parents=True, exist_ok=True)
        payload = b"".join((json.dumps(item, ensure_ascii=False) + "\n").encode("utf-8")
                            for item in records)
        artifact.write_bytes(payload)
        source = self.case_dir / source_name
        source.write_bytes(payload)
        self._register(evidence_id, artifact, source, "claim ledger", run_id=run_id)
        return artifact, payload

    def _generate(self, report_id="claims", *claim_ids, run_id="run-a"):
        args = ["generate", "--project", self.project, "--report-id", report_id,
                "--version", "1.0", "--run-id", run_id, "--kind", "interim"]
        for evidence_id in claim_ids:
            args += ["--claim-evidence-id", evidence_id]
        return call(REPORT, *args)

    def test_strong_claim_is_confirmed_and_weak_claims_remain_unknown(self):
        strong = {"id": "C-strong", "kind": "claim", "claim": "synthetic observation",
                  "status": "proven", "evidence": ["ev-support"], "how": "read-only",
                  "ttl": "2027-01-01", "created": "2026-01-01", "confidence": "observed",
                  "authority": "analyst"}
        hypothesis = {"id": "C-hyp", "claim": "not established", "status": "hypothesis",
                      "evidence": [], "confidence": "unknown", "authority": "none"}
        refuted = {"id": "C-ref", "claim": "refuted proposition", "status": "refuted",
                   "evidence": ["ev-support"], "confidence": "observed", "authority": "analyst",
                   "refuted_by": "C-strong"}
        weak = {"id": "C-weak", "claim": "weak proposition", "status": "proven",
                "evidence": ["ev-support"], "confidence": "inferred", "authority": "analyst"}
        self._ledger("ev-claims", [strong, hypothesis, refuted, weak])
        rc, generated, text = self._generate("claims", "ev-claims")
        self.assertEqual(rc, 0, text)
        claims = generated["verification"]["claims"] if "claims" in generated["verification"] else None
        manifest = json.loads((self.project / "reports/claims/manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["claims"]["confirmed_ids"], ["C-strong"])
        self.assertEqual(set(manifest["claims"]["unknown_ids"]), {"C-hyp", "C-ref", "C-weak"})
        self.assertEqual(manifest["claims"]["sources"][0]["evidence_id"], "ev-claims")
        manifest_records = {item["id"]: item for item in manifest["claims"]["records"]}
        self.assertEqual(manifest_records["C-strong"]["evidence"][0], "ev-support")
        body = (self.project / "reports/claims/report.md").read_text(encoding="utf-8")
        self.assertIn("C-strong", body)
        self.assertIn("C-hyp", body)
        self.assertIn("refuted_by", body)
        self.assertNotIn("claims", generated.get("proof_level", ""))
        self.assertTrue(generated["verification"]["claims"]["matches"])

    def test_claim_ledger_and_support_tamper_are_stale_then_restore_is_fresh(self):
        claim = {"id": "C-1", "claim": "stable synthetic claim", "status": "proven",
                 "evidence": ["ev-support"], "confidence": "derived", "authority": "reviewer"}
        ledger, original = self._ledger("ev-claims", [claim])
        rc, _, text = self._generate("claims", "ev-claims")
        self.assertEqual(rc, 0, text)
        self.case_dir.rename(self.project / "case-source-moved")
        rc, shown, text = call(REPORT, "show", "--project", self.project,
                               "--report-id", "claims")
        self.assertEqual(rc, 0, text)
        self.assertTrue(shown["report"]["fresh"], shown)
        ledger.write_bytes(original + b"\n")
        rc, stale, text = call(REPORT, "show", "--project", self.project,
                               "--report-id", "claims")
        self.assertEqual(rc, 2)
        self.assertTrue({"claim_ledger_changed", "claim_ledger_unreadable"} &
                        {x["kind"] for x in stale["report"]["stale"]})
        ledger.write_bytes(original)
        rc, _, text = call(REPORT, "show", "--project", self.project,
                           "--report-id", "claims")
        self.assertEqual(rc, 0, text)
        self.support_path.write_bytes(b"tampered support")
        rc, stale, text = call(REPORT, "show", "--project", self.project,
                               "--report-id", "claims")
        self.assertEqual(rc, 2)
        kinds = [x["kind"] for x in stale["report"]["stale"]]
        self.assertTrue({"evidence_changed", "claim_ledger_unreadable"} & set(kinds), stale)
        self.support_path.write_bytes(b"synthetic support witness")
        rc, _, text = call(REPORT, "show", "--project", self.project,
                           "--report-id", "claims")
        self.assertEqual(rc, 0, text)

    def test_cross_run_and_unsupported_refs_never_confirm(self):
        self._ledger("ev-claims", [{"id": "C-path", "claim": "path claim", "status": "proven",
                                     "evidence": ["case-source/support.bin#L1"],
                                     "confidence": "observed", "authority": "analyst"}])
        rc, generated, text = self._generate("claims", "ev-claims")
        self.assertEqual(rc, 0, text)
        manifest = json.loads((self.project / "reports/claims/manifest.json").read_text(encoding="utf-8"))
        record = manifest["claims"]["records"][0]
        self.assertEqual(record["classification"], "confirmed")
        self.assertEqual(record["supporting_evidence"][0]["evidence_id"], "ev-support")

        # The ledger itself is not a support file; a plain path without #locator is unknown.
        self._ledger("ev-self", [{"id": "C-self", "claim": "self claim", "status": "proven",
                                   "evidence": ["ev-self"], "confidence": "observed",
                                   "authority": "analyst"}], "self.jsonl")
        rc, _, text = self._generate("self-report", "ev-self")
        self.assertEqual(rc, 0, text)
        self.assertEqual(json.loads((self.project / "reports/self-report/manifest.json").read_text(
            encoding="utf-8"))["claims"]["confirmed_ids"], [])

        rc, out, text = call(STATE, "run", "--project", self.project,
                             "--version", "1.0", "--run-id", "run-b")
        self.assertEqual(rc, 0, text)
        self._ledger("ev-run-b", [{"id": "C-run", "claim": "other run", "status": "proven",
                                    "evidence": ["ev-support"], "confidence": "observed",
                                    "authority": "analyst"}], "run-b.jsonl", run_id="run-b")
        rc, _, text = self._generate("wrong-run", "ev-run-b", run_id="run-a")
        self.assertEqual(rc, 2)
        self.assertFalse((self.project / "reports/wrong-run").exists())

    def test_duplicate_bad_json_and_sensitive_claim_refuse_without_report_residue(self):
        duplicate = [{"id": "C-dup", "claim": "one", "status": "hypothesis"},
                     {"id": "C-dup", "claim": "two", "status": "hypothesis"}]
        self._ledger("ev-duplicate", duplicate, "duplicate.jsonl")
        rc, out, text = self._generate("duplicate", "ev-duplicate")
        self.assertEqual(rc, 2)
        self.assertFalse((self.project / "reports/duplicate").exists())

        bad = self.project / "versions/1.0/artifacts/bad.jsonl"
        bad.write_bytes(b'{"id":"C-bad","status":"proven"}\nnot-json\n')
        bad_source = self.case_dir / "bad.jsonl"
        bad_source.write_bytes(bad.read_bytes())
        self._register("ev-bad", bad, bad_source, "bad ledger")
        rc, _, text = self._generate("bad-json", "ev-bad")
        self.assertEqual(rc, 2)
        self.assertFalse((self.project / "reports/bad-json").exists())

        marker = "token=synthetic-sensitive-marker"
        sensitive = {"id": "C-secret", "claim": marker, "status": "hypothesis",
                     "evidence": [], "confidence": "unknown", "authority": "none"}
        self._ledger("ev-sensitive", [sensitive], "sensitive.jsonl")
        rc, _, text = self._generate("sensitive", "ev-sensitive")
        self.assertEqual(rc, 2)
        self.assertNotIn(marker, text)
        self.assertFalse((self.project / "reports/sensitive").exists())

    def test_selection_is_traceable_and_claim_scope_is_wired(self):
        self._ledger("ev-claims", [{"id": "C-1", "claim": "traceable", "status": "hypothesis",
                                     "evidence": [], "confidence": "unknown", "authority": "none"}])
        rc, generated, text = self._generate("claims", "ev-claims")
        self.assertEqual(rc, 0, text)
        manifest = json.loads((self.project / "reports/claims/manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["sources"]["params"]["claim_evidence_ids"], ["ev-claims"])
        self.assertEqual(manifest["claims"]["selected_evidence_ids"], ["ev-claims"])
        scopes = {row["scope"]: row["wired"] for row in generated["pending_scopes"]}
        self.assertTrue(scopes["report_claim_ledger"])
        rc, shown, text = call(REPORT, "status", "--project", self.project)
        self.assertEqual(rc, 0, text)
        self.assertEqual(shown["stale_reports"], [])


    def test_missing_claim_text_and_reported_authority_never_confirm(self):
        good = {"id": "C-good", "claim": "synthetic observation", "status": "proven",
                "evidence": ["ev-support"], "confidence": "observed", "authority": "analyst"}
        records = [good]
        for index, (key, value) in enumerate((("claim", ""), ("claim", 123),
                                             ("authority", "reported"), ("authority", {"name": "analyst"}))):
            records.append(dict(good, id="C-weak-" + str(index), **{key: value}))
        missing = dict(good, id="C-missing")
        del missing["claim"]
        records.append(missing)
        self._ledger("ev-claims", records)
        rc, _, text = self._generate("claims", "ev-claims")
        self.assertEqual(rc, 0, text)
        manifest = json.loads((self.project / "reports/claims/manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["claims"]["confirmed_ids"], ["C-good"])
        self.assertEqual(len(manifest["claims"]["unknown_ids"]), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
