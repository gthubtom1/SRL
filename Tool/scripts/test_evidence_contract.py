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
                self.assertEqual((info["claims"], info["strong"]), (1, 1))
                self.assertEqual(info["case_source"], "pack.cases")
                self.assertEqual(info["checked_cases"], [self.case.name])
                self.assertEqual(info["unreadable_cases"], [])

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
                self.assertEqual((info["claims"], info["strong"]), (3, 1))

    def test_current_packages_check_every_declared_witness(self):
        checked_count = 0
        for path in sorted((ROOT / "Tool" / "skill").glob("*/pack.json")):
            pack = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(domain=pack["id"]):
                self.assertEqual(pack["cases"], pack["case_roles"]["witness"])
                bad, info = gate.g5_evidence(pack)
                self.assertEqual(bad, [])
                self.assertEqual(info["checked_cases"], pack["cases"])
                self.assertEqual(info["unreadable_cases"], [])
                checked_count += len(info["checked_cases"])
                for name in pack["cases"]:
                    metadata = json.loads((ROOT / "Tool" / "cases" / name /
                                           "case.json").read_text(encoding="utf-8"))
                    self.assertTrue(metadata.get("target_files"), name)
        self.assertEqual(checked_count, 11)

    def test_role_review_distinguishes_aimbot_ledger_from_47_missing_ledgers(self):
        review = json.loads((ROOT / "docs" / "verification" /
                             "case-role-review-2026-10-30.json").read_text(encoding="utf-8"))
        self.assertEqual(len(review["cases"]), 48)
        self.assertEqual(len(review["retained_declared_witnesses"]), 11)
        self.assertEqual(review["retained_identity_exceptions"], [])
        self.assertEqual(sum(r["facts_jsonl_missing"] for r in review["cases"]), 47)
        record = next(r for r in review["cases"] if r["id"] == "aimbot")
        self.assertEqual(record["decision"], "context-only")
        self.assertFalse(record["facts_jsonl_missing"])
        self.assertFalse(record["target_files_registered"])
        self.assertEqual(record["target_directory_file_count"], 0)
        self.assertEqual(record["goal_level"], "M2")
        self.assertEqual(record["original_depth_membership"], {
            "declared_in_depth_gate": False, "matched_case_globs": [],
        })
        self.assertEqual(record["current_depth_membership"], record["original_depth_membership"])
        case = ROOT / "Tool" / "cases" / "aimbot"
        for name, field in (("case.json", "case_json_sha256"),
                            ("facts.jsonl", "facts_jsonl_sha256")):
            self.assertEqual(hashlib.sha256((case / name).read_bytes()).hexdigest(), record[field])
        pack = json.loads((ROOT / "Tool" / "skill" / "malware-analysis" /
                           "pack.json").read_text(encoding="utf-8"))
        self.assertNotIn("aimbot", pack["cases"])
        self.assertNotIn("aimbot", pack["case_roles"]["witness"])

    def test_context_review_does_not_exempt_redeclared_missing_ledger_witness(self):
        review = json.loads((ROOT / "docs" / "verification" /
                             "case-role-review-2026-10-30.json").read_text(encoding="utf-8"))
        for domain, name in (("firmware-iot", "firmware-iot01"),
                             ("softseep", "项目A"), ("protocol-plugin", "plugin03")):
            with self.subTest(domain=domain, case=name):
                record = next(r for r in review["cases"] if r["domain"] == domain and r["id"] == name)
                self.assertEqual(record["decision"], "context-only")
                pack = json.loads((ROOT / "Tool" / "skill" / domain / "pack.json").read_text(encoding="utf-8"))
                self.assertNotIn(name, pack["cases"])
                self.assertEqual(gate.g5_evidence(pack)[0], [])
                # A historical review is never an exemption for an explicit declaration.
                pack["cases"].append(name)
                pack["case_roles"]["witness"].append(name)
                bad, info = gate.g5_evidence(pack)
                self.assertTrue(any(name in r and "事实账无法核验" in r for r in bad), bad)
                self.assertEqual(info["checked_cases"], pack["cases"])
                self.assertIn(name, info["unreadable_cases"])

    def test_declared_witness_missing_ledger_fails_regardless_of_identity(self):
        self.write_facts([self.good])
        other = Path(self.tmp.name) / "additional-witness"
        other.mkdir()
        (other / "artifacts").mkdir()
        (other / "artifacts" / "run.json").write_text('{"ok": true}\n', encoding="utf-8")
        pack = {
            "cases": [self.case.name, other.name],
            "case_roles": {"witness": [self.case.name, other.name], "depth_gate": [other.name]},
            "witness": {"cmd": "python verify.py --case Tool/cases/" + self.case.name},
            "evidence_contract": self.contracts[0][1],
        }
        for kind in ("historical", "fixture", "self-built", "public", "real"):
            for outcome in ("partial", "confirmed"):
                with self.subTest(evidence_kind=kind, outcome=outcome):
                    (other / "case.json").write_text(json.dumps({
                        "evidence_kind": kind, "outcome": outcome,
                        "artifacts": ["artifacts/run.json"],
                    }), encoding="utf-8")
                    with patch.object(gate, "CASES_DIR", self.tmp.name):
                        bad, info = gate.g5_evidence(pack)
                    self.assertTrue(any(other.name in r and "事实账无法核验" in r for r in bad), bad)
                    self.assertEqual(info["checked_cases"], pack["cases"])
                    self.assertEqual(info["unreadable_cases"], [other.name])
                    self.assertEqual((info["claims"], info["strong"]), (1, 1))

    def test_depth_only_and_undeclared_inventory_are_not_g5_witnesses(self):
        self.write_facts([self.good])
        other = Path(self.tmp.name) / "depth-only-history"
        other.mkdir()
        (other / "case.json").write_text('{"evidence_kind": "historical"}', encoding="utf-8")
        inventory = Path(self.tmp.name) / "undeclared-inventory"
        inventory.mkdir()
        # A corrupt, undeclared ledger must not be consumed through directory inventory.
        (inventory / "facts.jsonl").write_text('{broken\n', encoding="utf-8")
        pack = {"cases": [self.case.name],
                "case_roles": {"witness": [self.case.name], "depth_gate": [other.name]},
                "evidence_contract": self.contracts[0][1]}
        with patch.object(gate, "CASES_DIR", self.tmp.name):
            bad, info = gate.g5_evidence(pack)
        self.assertEqual(bad, [])
        self.assertEqual(info["checked_cases"], [self.case.name])
        self.assertEqual(info["unreadable_cases"], [])

    def test_empty_or_corrupt_additional_witness_cannot_hide_beside_good_witness(self):
        self.write_facts([self.good])
        other = Path(self.tmp.name) / "additional-witness"
        other.mkdir()
        pack = {"cases": [self.case.name, other.name],
                "evidence_contract": self.contracts[0][1]}
        for text in ("", '\n', '{"kind":"state","state":{}}\n', '{broken\n'):
            with self.subTest(ledger=text):
                (other / "facts.jsonl").write_text(text, encoding="utf-8")
                with patch.object(gate, "CASES_DIR", self.tmp.name):
                    bad, info = gate.g5_evidence(pack)
                self.assertTrue(any(other.name in r and "事实账" in r for r in bad), bad)
                self.assertEqual(info["checked_cases"], pack["cases"])
                self.assertEqual((info["claims"], info["strong"]), (1, 1))

    def test_additional_declared_witness_still_checks_each_proven_claim(self):
        other = Path(self.tmp.name) / "additional-witness"
        other.mkdir()
        (other / "capture").mkdir()
        (other / "capture" / "review.log").write_bytes(b"second witness evidence\n")
        pack = {"cases": [self.case.name, other.name],
                "case_roles": {"witness": [self.case.name, other.name], "depth_gate": [other.name]},
                "evidence_contract": self.contracts[0][1]}
        self.write_facts([self.good])
        mutations = [dict(self.good), dict(self.good, claim=" "),
                     dict(self.good, evidence=["capture/missing.log"]),
                     dict(self.good, confidence="inferred"), dict(self.good, authority="reported")]
        for index, claim in enumerate(mutations):
            with self.subTest(claim=claim):
                (other / "facts.jsonl").write_text(json.dumps(claim) + '\n', encoding="utf-8")
                with patch.object(gate, "CASES_DIR", self.tmp.name):
                    bad, info = gate.g5_evidence(pack)
                self.assertEqual(not bad, index == 0, bad)
                if index:
                    self.assertTrue(any(other.name in r for r in bad), bad)
                self.assertEqual(info["checked_cases"], pack["cases"])

    def test_g2_requires_command_witness_to_belong_to_declared_witness_set(self):
        pack = json.loads((ROOT / "Tool" / "skill" / "apkseep" / "pack.json").read_text(encoding="utf-8"))
        self.assertEqual(gate.g2_schema(pack), [])
        # Keep a valid declared witness but remove leaf-apk, still used by witness.cmd.
        pack["cases"] = ["apkseep08"]
        pack["case_roles"]["witness"] = ["apkseep08"]
        bad = gate.g2_schema(pack)
        self.assertTrue(any("witness --case 必须属于" in r for r in bad), bad)

    def test_g2_does_not_allow_roles_to_silently_narrow_declared_witnesses(self):
        pack = json.loads((ROOT / "Tool" / "skill" / "apkseep" / "pack.json").read_text(encoding="utf-8"))
        pack["case_roles"]["witness"] = ["leaf-apk"]
        bad = gate.g2_schema(pack)
        self.assertTrue(any("case_roles.witness 必须与 cases 一致" in r for r in bad), bad)

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
                self.assertEqual((info["claims"], info["strong"]), (2, 1))
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
