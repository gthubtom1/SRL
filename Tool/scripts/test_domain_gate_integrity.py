"""Isolated domain-gate regressions; execute only tiny fixture scripts."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("domain_gate_integrity", HERE / "domain-gate.py")
domain_gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(domain_gate)


class DomainGateIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-domain-gate-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        isolated_home = self.root / ".isolated-home"
        isolated_agent = self.root / ".isolated-agent"
        isolated_home.mkdir()
        isolated_agent.mkdir()
        patch.dict(os.environ, {
            "HOME": str(isolated_home),
            "USERPROFILE": str(isolated_home),
            "APPDATA": str(isolated_home / "AppData" / "Roaming"),
            "LOCALAPPDATA": str(isolated_home / "AppData" / "Local"),
            "PI_CODING_AGENT_DIR": str(isolated_agent),
        }, clear=False).start()
        self.addCleanup(patch.stopall)
        self.scripts = self.root / "Tool" / "skill" / "fixture-domain" / "scripts"
        self.scripts.mkdir(parents=True)
        self.depth = {"skill": "fixture-domain", "board": "fixture-board",
                      "matrix": "fixture-matrix.json", "case_globs": ["fixture-case*"]}
        previous = domain_gate.ROOT
        domain_gate._use_root(str(self.root))
        self.addCleanup(domain_gate._use_root, previous)
        domain_gate.results = []
        domain_gate.uncovered = []

    def script(self, name, output, rc=0):
        path = self.scripts / name
        path.write_text("import sys\nif '--help' in sys.argv:\n"
                        "    print('fixture help')\n    sys.exit(0)\n"
                        "print(%r)\nsys.exit(%d)\n" % (output, rc), encoding="utf-8")

    def check_scripts(self):
        domain_gate.results = []
        domain_gate.uncovered = []
        domain_gate.check_scripts("fixture-domain", self.depth)
        return all(r["ok"] for r in domain_gate.results), domain_gate.results

    def test_scripts_require_boolean_true_in_the_final_json_conclusion(self):
        self.script("good.py", '{"ok": true}')
        for output, accepted in (
            ('{"ok": false}', False), ('{"ok": 1}', False),
            ('{"ok": "true"}', False), ('["ok"]', False),
            ('not JSON but contains "ok"', False),
            ('{"ok": true}\ntrailing unstructured text', False),
            ('progress log\n{"ok": true, "checks": 1}', True),
            (json.dumps({"ok": True, "checks": [{"ok": True}]}, indent=2), True),
        ):
            with self.subTest(output=output):
                self.script("candidate.py", output)
                ok, records = self.check_scripts()
                self.assertEqual(ok, accepted, records)
        self.script("candidate.py", '{"ok": true}', rc=7)
        self.assertFalse(self.check_scripts()[0])

    def test_same_script_cannot_count_twice_towards_the_minimum(self):
        self.script("one.py", '{"ok": true}')
        self.depth["ext_scripts"] = ["Tool/skill/fixture-domain/scripts/one.py"]
        self.assertFalse(self.check_scripts()[0])

    def write_cases(self, kind):
        for index in range(domain_gate.LIMITS["cases_min"]):
            directory = self.root / "Tool" / "cases" / ("fixture-case%d" % index)
            directory.mkdir(parents=True, exist_ok=True)
            artifact = directory / "artifacts" / "result.txt"
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text("fixture output %d\n" % index, encoding="utf-8")
            case = {"id": directory.name, "domain": "fixture-domain",
                    "target_type": "compiled unit test binary", "evidence_kind": kind,
                    "protection": [], "authority": "local", "goal_level": "L1",
                    "outcome": "partial",
                    "artifacts": [{"path": "artifacts/result.txt",
                                   "sha256": domain_gate.sha256(artifact)}],
                    "repro": {"status": "recorded", "command": "python parse.py --case fixture",
                              "returncode": 0,
                              "evidence": "structured fixture execution"},
                    "lessons": ["fixture execution recorded"],
                    "refs": [], "updated": "2026-10-29"}
            (directory / "case.json").write_text(json.dumps(case), encoding="utf-8")

    def test_self_built_cases_do_not_satisfy_real_artifact_requirement(self):
        # The kind labels exercise classification only; these are synthetic fixtures.
        for kind, accepted in (("self-built", False), ("public", True), ("real", True)):
            with self.subTest(kind=kind):
                self.write_cases(kind)
                domain_gate.results = []
                domain_gate.check_cases("fixture-domain", self.depth)
                self.assertEqual(all(r["ok"] for r in domain_gate.results), accepted, domain_gate.results)

    def test_negated_or_experiential_rc_text_does_not_authenticate_real(self):
        self.write_cases("public")
        for directory in sorted((self.root / "Tool" / "cases").glob("fixture-case*")):
            case_file = directory / "case.json"
            case = json.loads(case_file.read_text(encoding="utf-8"))
            case["repro"] = {
                "status": "recorded",
                "evidence": "没有运行 python/tshark；凭经验写 rc=0",
            }
            case_file.write_text(json.dumps(case), encoding="utf-8")
        domain_gate.results = []
        domain_gate.check_cases("fixture-domain", self.depth)
        self.assertFalse(all(r["ok"] for r in domain_gate.results))
        detail = "\n".join(r["detail"] for r in domain_gate.results)
        self.assertIn("否定/假设/未来语义", detail)
        self.assertIn("缺结构化 command", detail)

    def test_case_artifact_cannot_escape_root_even_with_matching_hash(self):
        self.write_cases("public")
        outside = self.root / "outside.log"
        outside.write_bytes(b"outside but matching\n")
        case_file = self.root / "Tool" / "cases" / "fixture-case0" / "case.json"
        case = json.loads(case_file.read_text(encoding="utf-8"))
        case["artifacts"] = [{
            "path": "../outside.log",
            "sha256": domain_gate.sha256(outside),
        }]
        case_file.write_text(json.dumps(case), encoding="utf-8")
        domain_gate.results = []
        domain_gate.check_cases("fixture-domain", self.depth)
        self.assertFalse(all(r["ok"] for r in domain_gate.results))
        self.assertIn("产物路径越界/无效", domain_gate.results[0]["detail"])

    def test_deploy_compares_complete_trees_for_formal_and_nonformal_skills(self):
        formal = self.root / "Tool" / "skill" / "fixture-domain"
        (formal / "SKILL.md").write_text("# fixture\n", encoding="utf-8")
        for relative, data in (
                ("scripts/run.js", "console.log('good');\n"),
                ("src/Main.java", "class Main {}\n"),
                ("references/notes.txt", "good\n")):
            target = formal / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(data, encoding="utf-8")
        extra = self.root / "Tool" / "skill" / "extra-skill"
        (extra / "assets").mkdir(parents=True)
        (extra / "SKILL.md").write_text("# extra\n", encoding="utf-8")
        (extra / "assets" / "runtime.txt").write_text("good\n", encoding="utf-8")

        agent_skills = self.root / "agent" / "skills"
        for source, name in ((formal, "fixture-domain"), (extra, "extra-skill")):
            destination = agent_skills / name
            destination.mkdir(parents=True)
            for path in source.rglob("*"):
                if path.is_file():
                    target = destination / path.relative_to(source)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(path.read_bytes())

        domain_gate.results = []
        with patch.object(domain_gate, "DOMAINS", {
                "fixture-domain": {"skill": "fixture-domain"},
        }):
            domain_gate.check_deploy(agent_root=str(self.root / "agent"))
        self.assertTrue(domain_gate.results[-1]["ok"], domain_gate.results[-1])

        (agent_skills / "fixture-domain" / "scripts" / "run.js").write_text(
            "console.log('bad');\n", encoding="utf-8")
        (agent_skills / "extra-skill" / "assets" / "runtime.txt").write_text(
            "bad\n", encoding="utf-8")
        domain_gate.results = []
        with patch.object(domain_gate, "DOMAINS", {
                "fixture-domain": {"skill": "fixture-domain"},
        }):
            domain_gate.check_deploy(agent_root=str(self.root / "agent"))
        result = domain_gate.results[-1]
        self.assertFalse(result["ok"], result)
        self.assertIn("scripts/run.js", result["detail"])
        self.assertIn("assets/runtime.txt", result["detail"])

    def route_pack(self, name, priority, must="isolated-token"):
        directory = self.root / "Tool" / "skill" / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "SKILL.md").write_text("isolated fixture\n", encoding="utf-8")
        pack = {"schema": "seep.pack/1", "id": name, "l1": "isolated fixture",
                "depth_contract": {**self.depth, "skill": name},
                "routes": [{"priority": priority, "label": "isolated route", "must": [must]}]}
        (directory / "pack.json").write_text(json.dumps(pack), encoding="utf-8")

    def run_routing(self, tests):
        domain_gate.results = []
        with patch.object(domain_gate, "ROUTING_TESTS", tests):
            domain_gate.check_routing()
        self.assertEqual(len(domain_gate.results), 1, domain_gate.results)
        return domain_gate.results[0]

    def test_routing_uses_complete_deduplicated_hits_for_aux_and_ambiguity(self):
        self.route_pack("fixture-domain", 100)
        self.route_pack("aux-domain", 90)
        self.route_pack("forbidden-domain", 80)
        text = "isolated-token aux-token forbidden-token"
        self.route_pack("fixture-domain", 100, "isolated-token")
        self.route_pack("aux-domain", 90, "aux-token")
        self.route_pack("forbidden-domain", 80, "forbidden-token")

        positive = self.run_routing([{
            "text": text, "expect_any": ["fixture-domain"],
            "expect_aux": ["aux-domain", "forbidden-domain"],
            "expect_ambiguity": True, "forbid": [],
        }])
        self.assertTrue(positive["ok"], positive)

        missing_aux = self.run_routing([{
            "text": text, "expect_any": ["fixture-domain"],
            "expect_aux": ["aux-domain"], "expect_ambiguity": True,
        }])
        self.assertFalse(missing_aux["ok"], missing_aux)
        self.assertIn("辅助域", missing_aux["detail"])

        undeclared_aux = self.run_routing([{
            "text": text, "expect_any": ["fixture-domain"],
        }])
        self.assertFalse(undeclared_aux["ok"], undeclared_aux)
        self.assertIn("未登记 expect_aux", undeclared_aux["detail"])

        forbidden = self.run_routing([{
            "text": text, "expect_any": ["fixture-domain"],
            "expect_aux": ["aux-domain", "forbidden-domain"],
            "expect_ambiguity": True, "forbid": ["forbidden-domain"],
        }])
        self.assertFalse(forbidden["ok"], forbidden)
        self.assertIn("forbidden-domain", forbidden["detail"])

        no_ambiguity = self.run_routing([{
            "text": "isolated-token", "expect_any": ["fixture-domain"],
            "expect_aux": [], "expect_ambiguity": False,
        }])
        self.assertTrue(no_ambiguity["ok"], no_ambiguity)

    def test_routing_configuration_errors_are_not_discarded(self):
        self.route_pack("fixture-domain", 10)
        self.route_pack("second-domain", 10)
        result = self.run_routing([])
        self.assertFalse(result["ok"], result)
        self.assertIn("priority", result["detail"])

    def test_apk_acceptance_requires_all_four_bound_cases(self):
        domain_gate.results = []
        domain_gate.uncovered = []
        domain_gate.check_apk_acceptance("fixture-domain")
        self.assertFalse(all(r["ok"] for r in domain_gate.results))

        digest = "a" * 64
        for name in domain_gate.APK_ACCEPTANCE_CASES:
            directory = self.root / "Tool" / "cases" / name
            (directory / "target").mkdir(parents=True)
            (directory / "target" / "input.apk").write_bytes(
                ("fixture-" + name).encode("utf-8"))
            case = {
                "id": name,
                "domain": "apkseep",
                "acceptance_profile": "apk-target/1",
                "target": {
                    "path": "target/input.apk",
                    "sha256": digest,
                    "size": 123,
                },
                "target_files": [{
                    "path": "target/input.apk",
                    "sha256": digest,
                    "size": 123,
                }],
            }
            (directory / "case.json").write_text(
                json.dumps(case), encoding="utf-8")

        domain_gate.results = []
        domain_gate.uncovered = []
        ok_run = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(domain_gate, "_run_case_state", return_value=ok_run):
            domain_gate.check_apk_acceptance("fixture-domain")
        self.assertTrue(all(r["ok"] for r in domain_gate.results),
                        domain_gate.results)
        self.assertEqual(domain_gate.uncovered, [])

        external = self.base_outside_path()
        case_file = self.root / "Tool" / "cases" / "leaf-apk" / "case.json"
        case = json.loads(case_file.read_text(encoding="utf-8"))
        case["target"]["path"] = external
        case_file.write_text(json.dumps(case), encoding="utf-8")
        domain_gate.results = []
        domain_gate.uncovered = []
        with patch.object(domain_gate, "_run_case_state", return_value=ok_run):
            domain_gate.check_apk_acceptance("fixture-domain")
        self.assertFalse(all(r["ok"] for r in domain_gate.results),
                         domain_gate.results)
        self.assertIn("案例内相对路径", domain_gate.results[0]["detail"])

    def base_outside_path(self):
        outside = self.root / "outside-target.apk"
        outside.write_bytes(b"outside")
        return str(outside)

    def test_apk_script_routing_and_capability_matrix_are_consistent(self):
        skill = HERE.parent / "skill" / "apkseep"
        routing = (skill / "references" / "routing.md").read_text(encoding="utf-8")
        shipped = {
            path.name for path in (skill / "scripts").iterdir()
            if path.is_file() and path.suffix in {".py", ".js"}
        }
        listed = set(re.findall(
            r"`scripts/([^`/]+\.(?:py|js))`", routing))
        self.assertFalse(shipped - listed, sorted(shipped - listed))
        self.assertIn("witness.py", listed)
        script_table = routing.split("## Script index", 1)[1].split(
            "row(s) below the header", 1)[0]
        rows = [
            line for line in script_table.splitlines()
            if line.startswith("| `scripts/")
        ]
        self.assertIn("_%d row(s) below the header._" % len(rows), routing)

        matrix = json.loads(
            (skill / "evidence" / "capability-matrix.json").read_text(
                encoding="utf-8"))
        for row in matrix["capabilities"]:
            with self.subTest(capability=row["capability"]):
                self.assertIn(row["status"], {"ok", "partial", "blocked"})
                self.assertIn(row["strength"],
                              {"observed", "inferred", "unverified"})
                if row["status"] == "ok":
                    self.assertTrue(row["route_measured"])
                    self.assertEqual(row["strength"], "observed")
                if row["route_measured"]:
                    self.assertEqual(row["strength"], "observed")
                if row["status"] == "blocked":
                    self.assertFalse(row["route_measured"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
