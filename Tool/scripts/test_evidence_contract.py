#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Focused evidence regressions against real G5/G6 and case_state, without witnesses.

Run: python -B Tool/scripts/test_evidence_contract.py
Fixtures live in a temporary directory; repository cases are only read.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import case_state  # noqa: E402
import gate  # noqa: E402


class EvidenceContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-evidence-contract-")
        self.addCleanup(self.tmp.cleanup)
        self.case = Path(self.tmp.name) / "contract-case"
        self.case.mkdir()
        (self.case / "capture").mkdir()
        (self.case / "capture" / "review.log").write_bytes(b"static fixture evidence\n")
        self.contracts = []
        for name in ("apkseep", "malware-analysis"):
            pack = json.loads((ROOT / "Tool" / "skill" / name / "pack.json").read_text(encoding="utf-8"))
            self.contracts.append((name, pack["evidence_contract"]))
        self.good = {
            "id": "C-001", "claim": "The fixture log exists for review.",
            "status": "proven", "confidence": "observed",
            "authority": "shipped-artifact", "evidence": ["capture/review.log"],
        }
        # Any unexpected subprocess is a test failure, including witness execution.
        self.addCleanup(patch.stopall)
        patch("subprocess.run", side_effect=AssertionError("target/witness execution forbidden")).start()

    def write_facts(self, facts):
        text = "".join(json.dumps(f, ensure_ascii=False) + "\n" for f in facts)
        (self.case / "facts.jsonl").write_bytes(text.encode("utf-8"))

    def judge(self, contract):
        pack = {"cases": [self.case.name], "evidence_contract": contract}
        with patch.object(gate, "CASES_DIR", self.tmp.name):
            return gate.g5_evidence(pack)

    def test_valid_file_evidence_is_accepted_by_both_package_contracts(self):
        self.write_facts([self.good])
        for name, contract in self.contracts:
            with self.subTest(package=name):
                bad, info = self.judge(contract)
                self.assertEqual(bad, [])
                self.assertEqual(info, {"claims": 1, "strong": 1})

    def test_proven_inferred_is_rejected_even_with_another_strong_claim(self):
        weak = dict(self.good, id="C-002", confidence="inferred")
        self.write_facts([self.good, weak])
        for name, contract in self.contracts:
            with self.subTest(package=name):
                bad, info = self.judge(contract)
                self.assertTrue(any("C-002" in reason and "confidence" in reason for reason in bad), bad)
                self.assertEqual(info["strong"], 1)

    def test_proven_reported_and_none_are_rejected(self):
        for authority in ("reported", "none"):
            self.write_facts([self.good, dict(self.good, id="C-002", authority=authority)])
            for name, contract in self.contracts:
                with self.subTest(package=name, authority=authority):
                    bad, info = self.judge(contract)
                    self.assertTrue(any("C-002" in reason and "authority" in reason for reason in bad), bad)
                    self.assertEqual(info["strong"], 1)

    def test_missing_file_evidence_is_rejected(self):
        self.write_facts([self.good, dict(self.good, id="C-002", evidence=["capture/missing.log"])])
        for name, contract in self.contracts:
            with self.subTest(package=name):
                bad, _ = self.judge(contract)
                self.assertTrue(any("C-002" in reason and "evidence" in reason for reason in bad), bad)

    def test_empty_file_evidence_is_rejected(self):
        (self.case / "capture" / "empty.log").write_bytes(b"")
        self.write_facts([dict(self.good, evidence=["capture/empty.log"])])
        for name, contract in self.contracts:
            with self.subTest(package=name):
                bad, _ = self.judge(contract)
                self.assertTrue(any("evidence" in reason for reason in bad), bad)

    # ── G5 真执行 required_fields（本轮修复：只查 authority/confidence 时缺 claim 也能 pass）──

    def test_missing_claim_text_is_rejected_by_required_fields(self):
        fact = {k: v for k, v in self.good.items() if k != "claim"}
        self.write_facts([fact])
        for name, contract in self.contracts:
            with self.subTest(package=name):
                bad, _ = self.judge(contract)
                self.assertTrue(any("required_fields" in r and "claim" in r for r in bad), bad)

    def test_blank_or_non_string_claim_is_rejected(self):
        for value in ("", "   ", "\t\n", None, 123, ["claim"]):
            self.write_facts([dict(self.good, claim=value)])
            for name, contract in self.contracts:
                with self.subTest(package=name, claim=value):
                    bad, _ = self.judge(contract)
                    self.assertTrue(any("required_fields.claim" in r for r in bad), bad)

    def test_evidence_wrong_type_is_not_treated_as_character_array(self):
        # 单个字符串 / 非字符串元素 / 空数组 / null 都不是“非空字符串数组”。
        for value in ("capture/review.log", ["capture/review.log", 7], [], None, {"p": "capture/review.log"}):
            self.write_facts([dict(self.good, evidence=value)])
            for name, contract in self.contracts:
                with self.subTest(package=name, evidence=value):
                    bad, _ = self.judge(contract)
                    self.assertTrue(any("required_fields.evidence" in r for r in bad), bad)

    def test_blank_string_inside_evidence_array_is_rejected(self):
        self.write_facts([dict(self.good, evidence=["capture/review.log", "  "])])
        for name, contract in self.contracts:
            with self.subTest(package=name):
                bad, _ = self.judge(contract)
                self.assertTrue(any("required_fields.evidence" in r for r in bad), bad)

    def test_declared_custom_field_is_checked_not_silently_skipped(self):
        contract = dict(self.contracts[0][1], required_fields=["claim", "confidence", "authority",
                                                              "evidence", "how"])
        self.write_facts([self.good])  # good 里没有 how
        bad, info = self.judge(contract)
        self.assertTrue(any("required_fields 缺声明字段 how" in r for r in bad), bad)
        self.assertEqual(info["strong"], 1)  # 缺自定义字段不改写 strong 计数口径
        for value, ok in (("verified by hand", True), ("   ", False), ([], False), (None, False), (0, False)):
            with self.subTest(how=value):
                self.write_facts([dict(self.good, how=value)])
                bad, _ = self.judge(contract)
                self.assertEqual(not bad, ok, bad)

    def test_hypothesis_history_does_not_need_required_fields(self):
        # 历史 hypothesis/refuted 不为 pass 背书，也不因缺 claim/evidence 把整包判红。
        history = [{"id": "H-001", "status": "hypothesis", "confidence": "inferred",
                    "authority": "reported"},
                   {"id": "R-001", "status": "refuted", "evidence": "kept as history"}]
        self.write_facts([self.good] + history)
        for name, contract in self.contracts:
            with self.subTest(package=name):
                bad, info = self.judge(contract)
                self.assertEqual(bad, [])
                self.assertEqual(info, {"claims": 3, "strong": 1})

    def test_g2_rejects_null_or_invalid_required_fields(self):
        base = json.loads((ROOT / "Tool" / "skill" / "apkseep" / "pack.json").read_text(encoding="utf-8"))
        self.assertEqual(gate.g2_schema(base), [])
        for value in (None, "claim", [], [None], [""], ["  "], [1],
                      ["claim", "claim"], {"claim": True}):
            pack = copy.deepcopy(base)
            pack["evidence_contract"]["required_fields"] = value
            with self.subTest(required_fields=value):
                reasons = gate.g2_schema(pack)
                self.assertTrue(any("evidence_contract.required_fields" in r for r in reasons), reasons)

    def test_hypothesis_cannot_increase_strong_even_with_observed_confidence(self):
        self.write_facts([self.good, dict(self.good, id="C-002", status="hypothesis")])
        for name, contract in self.contracts:
            with self.subTest(package=name):
                bad, info = self.judge(contract)
                self.assertEqual(bad, [])
                self.assertEqual(info, {"claims": 2, "strong": 1})
        self.assertEqual(gate._case_cohort(str(self.case)), {"claims": 2, "proven": 1, "strong": 1})
        self.assertEqual(case_state.verify_case(str(self.case))["strong"], 1)
        self.write_facts([dict(self.good, status="hypothesis")])
        for name, contract in self.contracts:
            with self.subTest(package=name, only_hypothesis=True):
                bad, info = self.judge(contract)
                self.assertTrue(bad)
                self.assertEqual(info["strong"], 0)
        self.assertEqual(case_state.verify_case(str(self.case))["verdict"], "unknown")

    def test_receipt_cohort_strong_matches_case_state_authority_contract(self):
        self.write_facts([dict(self.good, authority="reported")])
        expected = {"claims": 1, "proven": 1, "strong": 0}
        self.assertEqual(gate._case_cohort(str(self.case)), expected)
        verified = case_state.verify_case(str(self.case))
        self.assertEqual({key: verified[key] for key in expected}, expected)

    def test_repaired_claims_remain_excluded_with_history_preserved(self):
        cases = {"leaf-apk": ("F-103", "F-105"), "leaf-pe-packed": ("F-003", "F-112", "F-114")}
        for name, ids in cases.items():
            facts = {f["id"]: f for f in case_state.load_facts(str(ROOT / "Tool" / "cases" / name))}
            for fid in ids:
                with self.subTest(case=name, claim=fid):
                    fact = facts[fid]
                    self.assertEqual(fact["status"], "hypothesis")
                    self.assertEqual(fact["confidence"], "inferred")
                    self.assertEqual(fact["authority"], "reported")
                    self.assertTrue(fact["claim"] and fact["evidence"] and fact["how"])
                    audit = fact["evidence_audit"][-1]
                    self.assertEqual(audit["previous_status"], "proven")
                    self.assertEqual(audit["previous_confidence"], "derived")
                    self.assertTrue(audit["reason"] and audit["at"] and audit["previous_updated"])
                    self.assertIs(audit["target_executed"], False)

    def test_g6_accepts_current_receipts_and_rejects_count_or_hash_drift(self):
        for name, expected in (("leaf-apk", (6, 4, 4)), ("leaf-pe-packed", (21, 15, 15))):
            with self.subTest(case=name):
                case = ROOT / "Tool" / "cases" / name
                receipt_path = ROOT / "docs" / "verification" / (name + "-2026-10-24.json")
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                counts = case_state.verify_case(str(case))
                self.assertEqual(tuple(counts[k] for k in ("claims", "proven", "strong")), expected)
                for key in ("claims", "proven", "strong"):
                    self.assertEqual(receipt["cohorts"]["final"][key], counts[key])
                pack = {"witness": {"cmd": "python case_state.py verify --case Tool/cases/" + name}}
                bad, _ = gate.g6_receipt(pack)
                self.assertEqual(bad, [])
                for rel, digest in receipt["source_sha256"].items():
                    self.assertEqual(hashlib.sha256((case / rel).read_bytes()).hexdigest(), digest)
                # Exercise content drift inside a valid isolated root, so path rejection
                # cannot hide a broken count/hash check. The repository stays read-only.
                isolated = Path(self.tmp.name) / ("receipt-" + name)
                isolated_case = isolated / "Tool" / "cases" / name
                for rel in set(receipt["source_sha256"]) | {"facts.jsonl"}:
                    destination = isolated_case / rel
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes((case / rel).read_bytes())
                fake = isolated / "docs" / "verification" / receipt_path.name
                fake.parent.mkdir(parents=True)
                fake.write_text(json.dumps(receipt), encoding="utf-8")
                with patch.object(gate, "ROOT", str(isolated)), \
                        patch.object(gate, "CASES_DIR", str(isolated / "Tool" / "cases")):
                    self.assertEqual(gate.g6_receipt(pack)[0], [])
                for field in ("count", "hash"):
                    altered = copy.deepcopy(receipt)
                    if field == "count":
                        altered["cohorts"]["final"]["claims"] += 1
                        diagnostic = "final.claims="
                    else:
                        altered["source_sha256"]["facts.jsonl"] = "0" * 64
                        diagnostic = "facts.jsonl 的哈希与回执不一致"
                    fake.write_bytes((json.dumps(altered) + "\n").encode("utf-8"))
                    with patch.object(gate, "ROOT", str(isolated)), \
                            patch.object(gate, "CASES_DIR", str(isolated / "Tool" / "cases")):
                        bad, _ = gate.g6_receipt(pack)
                    self.assertTrue(any(diagnostic in reason for reason in bad), (field, bad))


if __name__ == "__main__":
    unittest.main(verbosity=2)
