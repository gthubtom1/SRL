"""Exercise package gates against isolated damaged ledgers and real file bytes."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate


class GateIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-gate-integrity-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cases = self.root / "Tool" / "cases"
        self.case = self.cases / "simple"
        self.case.mkdir(parents=True)
        # Use the actual parser source while keeping its data root isolated.
        parser = self.root / "Tool" / "scripts" / "case_state.py"
        parser.parent.mkdir()
        parser.write_bytes((Path(__file__).parent / "case_state.py").read_bytes())
        (self.case / "capture").mkdir()
        (self.case / "capture" / "result.log").write_bytes(b"observed output\n")
        artifact_digest = hashlib.sha256(
            (self.case / "capture" / "result.log").read_bytes()).hexdigest()
        (self.case / "target").mkdir()
        (self.case / "target" / "input.bin").write_bytes(b"fixture input\n")
        self.claim = {"id": "C-1", "status": "proven", "claim": "The log exists.",
                      "confidence": "observed", "authority": "shipped-artifact",
                      "evidence": ["capture/result.log"]}
        self.write_json(self.case / "case.json", {
            "id": self.case.name, "evidence_kind": "real",
            "artifacts": [{"path": "capture/result.log", "sha256": artifact_digest}],
            "target_files": [{"path": "target/input.bin", "sha256": self.sha("target/input.bin")}],
        })
        self.write_facts([self.claim])
        witness_scripts = self.root / "Tool" / "skill" / "fixture-domain" / "scripts"
        witness_scripts.mkdir(parents=True)
        (witness_scripts / "witness.py").write_text(
            "import json\n"
            "print(json.dumps({'ok': True, 'domain': 'fixture-domain', 'witness': 'fixture'}))\n",
            encoding="utf-8",
        )
        self.pack = {
            "id": "fixture-domain", "cases": [self.case.name],
            "depth_contract": {"skill": "fixture-domain"},
            "witness": {"cmd": 'python Tool/scripts/case_state.py verify --case Tool/cases/%s' % self.case.name,
                        "expect": "exit0 + facts>=1", "budget_s": 10},
            "witness_tool": {"cmd": "Tool/skill/fixture-domain/scripts/witness.py"},
            "evidence_contract": {"required_fields": ["claim", "confidence", "authority", "evidence"],
                                  "authority_allow": ["shipped-artifact"],
                                  "pass_forbids_confidence": ["unknown", "inferred"]},
        }
        self.receipt_dir = self.root / "docs" / "verification"
        self.receipt_dir.mkdir(parents=True)
        self.receipt_path = self.receipt_dir / (self.case.name + "-2026-10-29.json")
        self.receipt = {
            "schema": "seep.verification/1", "case": self.case.name,
            "cohorts": {"baseline": {"claims": 1, "proven": 0, "strong": 0},
                        "final": {"claims": 1, "proven": 1, "strong": 1}},
            "source_sha256": {"facts.jsonl": self.sha("facts.jsonl")},
        }
        self.write_json(self.receipt_path, self.receipt)
        for name, value in (("ROOT", str(self.root)), ("CASES_DIR", str(self.cases))):
            manager = patch.object(gate, name, value)
            manager.start()
            self.addCleanup(manager.stop)

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def write_facts(self, entries):
        (self.case / "facts.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in entries), encoding="utf-8")

    def sha(self, relative):
        return hashlib.sha256((self.case / relative).read_bytes()).hexdigest()

    def test_valid_quoted_case_binds_all_read_only_gates(self):
        named = self.cases / "case with spaces"
        self.case.rename(named)
        self.case = named
        self.pack["cases"] = [named.name]
        self.pack["witness"]["cmd"] = 'python verify.py --case "Tool/cases/%s"' % named.name
        self.receipt_path.unlink()
        self.receipt_path = self.receipt_dir / (named.name + "-2026-10-29.json")
        self.receipt["case"] = named.name
        self.write_json(self.receipt_path, self.receipt)
        for check in (gate.g5_evidence, gate.g6_receipt, gate.g4b_target):
            with self.subTest(gate=check.__name__):
                bad, _ = check(self.pack)
                self.assertEqual(bad, [])

    def test_receipt_must_bind_facts_not_just_an_unrelated_file(self):
        # Counts remain unchanged: a hash of the log cannot authenticate edited claims.
        receipt = copy.deepcopy(self.receipt)
        receipt["source_sha256"] = {"capture/result.log": self.sha("capture/result.log")}
        self.write_json(self.receipt_path, receipt)
        self.assertTrue(gate.g6_receipt(self.pack)[0])
        receipt["source_sha256"]["facts.jsonl"] = self.sha("facts.jsonl")
        self.write_json(self.receipt_path, receipt)
        self.write_facts([dict(self.claim, claim="A different claim with identical counts.")])
        self.assertTrue(gate.g6_receipt(self.pack)[0])

    def test_receipt_rejects_bad_shapes_counts_and_case_identity_without_throwing(self):
        mutations = [[], {**self.receipt, "case": "another-case"},
                     {**self.receipt, "cohorts": [1]},
                     {**self.receipt, "source_sha256": [1]}]
        for value in ("1", True, 1.0, None, -1, {}):
            item = copy.deepcopy(self.receipt)
            item["cohorts"]["final"]["strong"] = value
            mutations.append(item)
        for item in mutations:
            with self.subTest(receipt=item):
                self.write_json(self.receipt_path, item)
                self.assertTrue(gate.g6_receipt(self.pack)[0])

    def test_corrupt_ledger_is_not_ignored_beside_a_good_claim(self):
        for extra in ('{broken\n', '[]\n', '{"kind":"claim","id":"broken"}\n'):
            with self.subTest(extra=extra):
                self.write_facts([self.claim])
                with (self.case / "facts.jsonl").open("a", encoding="utf-8") as stream:
                    stream.write(extra)
                self.assertTrue(gate.g5_evidence(self.pack)[0])

    def test_failed_or_unknown_claim_is_not_hidden_by_a_strong_claim(self):
        for status in ("fail", "unknown", "unsupported", "truncated", "skipped", "stale", "invented"):
            with self.subTest(status=status):
                self.write_facts([self.claim, dict(self.claim, id="C-2", status=status)])
                self.assertTrue(gate.g5_evidence(self.pack)[0])

    def test_bad_evidence_type_and_contract_produce_diagnostics(self):
        for evidence in (7, True, "capture/result.log", {"capture/result.log": True}):
            with self.subTest(evidence=evidence):
                self.write_facts([dict(self.claim, evidence=evidence)])
                self.assertTrue(gate.g5_evidence(self.pack)[0])
        self.write_facts([self.claim])
        for contract in ([1], {"required_fields": 7}):
            with self.subTest(contract=contract):
                self.assertTrue(gate.g5_evidence({**self.pack, "evidence_contract": contract})[0])

    def test_witness_case_is_not_rebound_to_another_directory_with_same_name(self):
        pack = copy.deepcopy(self.pack)
        # Existing old parsers discarded all ancestors and used only the basename.
        pack["witness"]["cmd"] = 'python verify.py --case elsewhere/%s' % self.case.name
        for check in (gate.g6_receipt, gate.g4b_target):
            with self.subTest(gate=check.__name__):
                self.assertTrue(check(pack)[0])

    def test_unquoted_case_with_simple_name_does_not_accept_omitted_facts_hash(self):
        # This positive path avoids the independent quoting bug masking the hash bug.
        self.pack["cases"] = ["simple"]
        self.pack["witness"]["cmd"] = "python verify.py --case Tool/cases/simple"
        self.receipt_path.unlink()
        self.receipt_path = self.receipt_dir / "simple-2026-10-29.json"
        self.receipt["case"] = "simple"
        self.receipt["source_sha256"] = {"capture/result.log": self.sha("capture/result.log")}
        self.write_json(self.receipt_path, self.receipt)
        self.assertTrue(gate.g6_receipt(self.pack)[0])

    def test_target_records_must_name_unique_registered_files_under_target(self):
        pack = copy.deepcopy(self.pack)
        pack["witness"]["cmd"] = "python verify.py --case Tool/cases/simple"
        good = {"path": "target/input.bin", "sha256": self.sha("target/input.bin")}
        mutations = [[], [1], {"target/input.bin": "bad"},
                     [{"path": "capture/result.log", "sha256": self.sha("capture/result.log")}],
                     [good, dict(good)], [dict(good, size=True)], [dict(good, size=999)]]
        for records in mutations:
            with self.subTest(records=records):
                self.write_json(self.case / "case.json", {"target_files": records})
                self.assertTrue(gate.g4b_target(pack)[0])
        self.write_json(self.case / "case.json", {"target_files": [good]})
        self.assertEqual(gate.g4b_target(pack)[0], [])
        (self.case / "target" / "input.bin").write_bytes(b"changed input\n")
        self.assertTrue(gate.g4b_target(pack)[0])

    def test_manifests_must_have_entries_and_stay_within_case(self):
        manifest = self.case / "artifacts" / "MANIFEST.sha256"
        manifest.parent.mkdir()
        for text in ("", "\n", self.sha("capture/result.log") + "  ../outside.log\n"):
            with self.subTest(manifest=text):
                (self.cases / "outside.log").write_bytes((self.case / "capture" / "result.log").read_bytes())
                manifest.write_text(text, encoding="utf-8")
                self.assertFalse(gate._clause_ok("artifacts/MANIFEST.sha256", 0, str(self.case))[0])
        manifest.write_text(self.sha("capture/result.log") + "  capture/result.log\n", encoding="utf-8")
        self.assertTrue(gate._clause_ok("artifacts/MANIFEST.sha256", 0, str(self.case))[0])

    def test_real_witness_handles_quoted_python_script_and_always_requires_exit_zero(self):
        script = self.root / "witness script.py"
        script.write_text("import sys\nsys.exit(int(sys.argv[1]))\n", encoding="utf-8")
        pack = copy.deepcopy(self.pack)
        for rc in (0, 7):
            with self.subTest(returncode=rc):
                pack["witness"].update(cmd='python "witness script.py" %d' % rc,
                                       expect="facts>=0")
                # The facts clause is deliberately permissive; rc=7 must still fail.
                pack["witness"]["cmd"] += ' --case "Tool/cases/%s"' % self.case.name
                bad, _ = gate.g4_witness(pack)
                self.assertEqual(not bad, rc == 0, bad)

    def test_nonzero_exit_fails_even_when_expect_omits_exit0(self):
        (self.root / "simple.py").write_text("import sys\nsys.exit(int(sys.argv[1]))\n", encoding="utf-8")
        pack = copy.deepcopy(self.pack)
        pack["witness"].update(cmd="python simple.py 7 --case Tool/cases/simple", expect="facts>=0")
        bad, info = gate.g4_witness(pack)
        self.assertEqual(info.get("rc"), 7)
        self.assertTrue(bad)
        pack["witness"]["cmd"] = "python simple.py 0 --case Tool/cases/simple"
        self.assertEqual(gate.g4_witness(pack)[0], [])

    def test_successful_inline_python_cannot_be_a_domain_witness_tool(self):
        pack = copy.deepcopy(self.pack)
        pack["witness_tool"] = {"cmd": 'python -c "raise SystemExit(0)"'}
        bad, info = gate.g4_witness(pack)
        self.assertTrue(any("唯一的当前技能脚本" in reason
                            or "witness_tool.cmd" in reason for reason in bad), bad)
        self.assertIn("witness_tool", info)

    def test_witness_tool_from_another_skill_is_rejected(self):
        other = self.root / "Tool" / "skill" / "other-domain" / "scripts" / "witness.py"
        other.parent.mkdir(parents=True)
        other.write_text(
            "import json\n"
            "print(json.dumps({'ok': True, 'domain': 'fixture-domain', 'witness': 'fixture'}))\n",
            encoding="utf-8",
        )
        pack = copy.deepcopy(self.pack)
        pack["witness_tool"] = {"cmd": "Tool/skill/other-domain/scripts/witness.py"}
        bad, _ = gate.g4_witness(pack)
        self.assertTrue(any("当前技能唯一脚本" in reason for reason in bad), bad)

    def test_schema_can_bind_witness_script_in_an_explicit_staging_root(self):
        staged = self.root / ".import-staging" / "fixture-domain-20261029"
        scripts = staged / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "witness.py").write_text(
            "import json\n"
            "print(json.dumps({'ok': True, 'domain': 'fixture-domain', 'witness': 'fixture'}))\n",
            encoding="utf-8",
        )
        bad = gate.g2_schema(self.pack, witness_root=str(staged))
        witness_errors = [reason for reason in bad if "witness_tool" in reason]
        self.assertEqual(witness_errors, [])

    def test_witness_case_accepts_string_artifacts_and_facts_only_evidence(self):
        self.write_json(self.case / "case.json", {
            "id": self.case.name, "evidence_kind": "real",
            "artifacts": ["capture/result.log"],
            "target_files": [{"path": "target/input.bin", "sha256": self.sha("target/input.bin")}],
        })
        self.assertEqual(gate._witness_tool_contract(self.pack)[1], [])

        self.write_json(self.case / "case.json", {
            "id": self.case.name, "evidence_kind": "real",
            "artifacts": [],
            "target_files": [{"path": "target/input.bin", "sha256": self.sha("target/input.bin")}],
        })
        info, bad = gate._witness_tool_contract(self.pack)
        self.assertEqual(bad, [])
        self.assertIn("facts.jsonl", info["evidence_sha256"])

        (self.case / "facts.jsonl").write_text('{"kind": "state", "state": {}}\n', encoding="utf-8")
        _info, bad = gate._witness_tool_contract(self.pack)
        self.assertTrue(any("无有效 claim" in reason for reason in bad), bad)

    def test_malformed_package_does_not_start_witnesses(self):
        # No witness process may run after the package schema has already failed.
        with patch.object(gate.subprocess, "run", side_effect=AssertionError("unexpected witness execution")):
            result = gate.judge(self.pack, {"rows": [], "problems": []})
        self.assertEqual(result["verdict"], "fail")
        self.assertIs(result["gates"]["G4 pack-witness"]["info"]["ran"], False)

    def test_summary_never_reports_usable_when_witness_was_skipped(self):
        output = io.StringIO()
        loaded = [{"id": self.pack["id"], "raw": self.pack}]
        with patch.object(sys, "argv", ["gate.py", "--all", "--json", "--no-witness"]), \
                patch.object(gate.route_mod, "load_packs", return_value=(loaded, [])), \
                patch.object(gate.route_mod, "check", return_value={"rows": [], "problems": []}), \
                contextlib.redirect_stdout(output):
            self.assertEqual(gate.main(), 1)
        result = json.loads(output.getvalue())
        self.assertGreater(result["summary"]["fail"], 0)
        self.assertIs(result["summary"]["usability"]["proven"], False)

    def test_external_case_junction_is_rejected_without_changing_external_bytes(self):
        outside = self.root / "outside"
        shutil.copytree(self.case, outside)
        before = {p.relative_to(outside): p.read_bytes() for p in outside.rglob("*") if p.is_file()}
        # Identical, complete data passes when reached through an ordinary case directory.
        control = self.cases / "ordinary"
        shutil.copytree(outside, control)
        pack = copy.deepcopy(self.pack)
        pack["cases"] = [control.name]
        self.assertEqual(gate.g5_evidence(pack)[0], [])
        junction = self.cases / "linked"
        if sys.platform == "win32":
            import _winapi
            _winapi.CreateJunction(str(outside), str(junction))
        else:
            junction.symlink_to(outside, target_is_directory=True)
        self.addCleanup(junction.rmdir if sys.platform == "win32" else junction.unlink)
        pack["cases"] = ["linked"]
        bad, _ = gate.g5_evidence(pack)
        self.assertTrue(any("symlink/reparse point" in reason for reason in bad), bad)
        self.assertEqual({p.relative_to(outside): p.read_bytes() for p in outside.rglob("*") if p.is_file()}, before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
