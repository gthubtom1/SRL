"""Exercise the formatter in an isolated source tree."""
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class FormatTests(unittest.TestCase):
    def test_import_has_no_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            setup = root / "setup"
            setup.mkdir()
            shutil.copy2(Path(__file__).with_name("clean-format.py"), setup / "clean-format.py")
            sample = root / "sample.md"
            sample.write_bytes(b"\xef\xbb\xbfretained")
            spec = importlib.util.spec_from_file_location("format_fixture", setup / "clean-format.py")
            spec.loader.exec_module(importlib.util.module_from_spec(spec))
            self.assertEqual(sample.read_bytes(), b"\xef\xbb\xbfretained")

    def test_only_source_text_is_changed_and_bad_python_is_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            setup = root / "setup"
            setup.mkdir()
            shutil.copy2(Path(__file__).with_name("clean-format.py"), setup / "clean-format.py")
            preserved = ["binary.bin", "proj/record.md", "tmp/log.py", "Tool/upstream/x/src.py",
                         "Tool/cases/x/sample.json", "Tool/mcp/Tool/x/readme.md"]
            for name in preserved:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"\xef\xbb\xbfuntouched\r\n")
            (setup / "broken.py").write_text("def (", encoding="utf-8")
            (setup / "ok.py").write_text("x = 1\n", encoding="utf-8")
            (setup / "run.sh").write_bytes(b"\xef\xbb\xbfexit 0\r\n")
            (root / ".github").mkdir()
            (root / ".github/fixture.yml").write_bytes(b"\xef\xbb\xbfvalue: true\n")
            result = subprocess.run([sys.executable, "-X", "utf8", str(setup / "clean-format.py")],
                                    capture_output=True, text=True, encoding="utf-8", timeout=15)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("broken.py", result.stdout)
            self.assertEqual((setup / "run.sh").read_bytes(), b"exit 0\n")
            self.assertEqual((root / ".github/fixture.yml").read_bytes(), b"value: true\n")
            for name in preserved:
                self.assertEqual((root / name).read_bytes(), b"\xef\xbb\xbfuntouched\r\n", name)


if __name__ == "__main__":
    unittest.main()
