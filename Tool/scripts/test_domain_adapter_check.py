#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Focused regression tests for domain-adapter-check pointer validation."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "domain-adapter-check.py")


def load_impl():
    spec = importlib.util.spec_from_file_location("seep_domain_adapter_check_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RequiredPointerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.impl = load_impl()

    def test_manager_resume_and_parent_skill_must_resolve(self):
        with tempfile.TemporaryDirectory(prefix="seep-domain-adapter-test-") as root:
            domain = "zz-adapter-pointers"
            self.impl.write_fixture(root, domain)
            pack_path = os.path.join(root, "Tool", "skill", domain, "pack.json")
            with io.open(pack_path, encoding="utf-8") as stream:
                base = json.load(stream)

            def contract(contract_name, key, invalid):
                pack = json.loads(json.dumps(base))
                pack[contract_name][key] = invalid
                with io.open(pack_path, "w", encoding="utf-8", newline="\n") as stream:
                    json.dump(pack, stream, ensure_ascii=False, indent=2)
                    stream.write("\n")
                raw, error = self.impl.load_json(pack_path)
                self.assertIsNone(error)
                return self.impl.make_row(
                    domain, {"path": pack_path, "raw": raw}, root)["contracts"][contract_name]

            clean_lifecycle = contract("project_lifecycle", "manager",
                                       "Tool/scripts/manager_state.py")
            self.assertEqual(clean_lifecycle["status"], "PASS", clean_lifecycle)
            clean_extension = contract("extension_contract", "parent_skill",
                                       "Tool/skill/zz-adapter-pointers/SKILL.md")
            self.assertEqual(clean_extension["status"], "PASS", clean_extension)

            for contract_name, key in (
                ("project_lifecycle", "manager"),
                ("project_lifecycle", "resume"),
                ("extension_contract", "parent_skill"),
            ):
                with self.subTest(contract=contract_name, key=key):
                    invalid = "not-a-real-%s-pointer" % key
                    report = contract(contract_name, key, invalid)
                    self.assertEqual(report["status"], "FAIL", report)
                    self.assertIn(invalid, report["missing"], report)


if __name__ == "__main__":
    unittest.main()
