"""Missing handoff targets and ambiguous archived names must fail the checker."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("handoffs", Path(__file__).with_name("skill-handoff-check.py"))
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)


class HandoffTests(unittest.TestCase):
    def test_explicit_source_and_deployed_name_and_missing_target(self):
        with tempfile.TemporaryDirectory(prefix="seep-handoff-") as td:
            root = Path(td)
            active = root / "Tool/skill/active/SKILL.md"
            archived_rel = "/".join(("Tool", "skill", "_pending", "old", "SKILL.md"))
            archived = root / archived_rel
            for p in (active, archived):
                p.parent.mkdir(parents=True)
                p.write_text("skill", encoding="utf-8")
            active.write_text("交 `old`", encoding="utf-8")
            self.assertFalse(H.check(root)["ok"])
            active.write_text("交 `active`，参考 `%s`" % archived_rel, encoding="utf-8")
            self.assertTrue(H.check(root)["ok"])
            archived.unlink()
            self.assertFalse(H.check(root)["ok"])

    def test_two_digit_archive_shorthand_is_resolved_and_bad_shorthand_fails(self):
        with tempfile.TemporaryDirectory(prefix="seep-handoff-short-") as td:
            root = Path(td)
            active = root / "Tool/skill/active/SKILL.md"
            archived = [
                root / ("Tool/skill/_pending/%02d-archive/SKILL.md" % number)
                for number in range(1, 6)
            ]
            for path in [active, *archived]:
                path.parent.mkdir(parents=True)
                path.write_text("skill", encoding="utf-8")

            for number in range(1, 6):
                with self.subTest(number=number):
                    active.write_text("授权旁路 → `%02d`" % number, encoding="utf-8")
                    result = H.check(root)
                    self.assertTrue(result["ok"], result)
                    self.assertEqual(result["archived_short_references"], 1, result)

            active.write_text("授权旁路 → `99`", encoding="utf-8")
            self.assertFalse(H.check(root)["ok"])

            for prefix in ("00-analysis", "00-triage"):
                path = root / "Tool/skill/_pending" / prefix / "SKILL.md"
                path.parent.mkdir(parents=True)
                path.write_text("skill", encoding="utf-8")
            active.write_text("授权旁路 → `00`", encoding="utf-8")
            result = H.check(root)
            self.assertFalse(result["ok"])
            self.assertIn("歧义", result["problems"][0]["reason"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
