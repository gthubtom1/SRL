"""Exercise Frida wrapper argument and acquisition paths without a device."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_runtime_install_delivery import ROOT, TMP_ROOT, isolated_environment, run_ps


class FridaWrapperTests(unittest.TestCase):
    def setUp(self):
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="frida-wrapper-", dir=TMP_ROOT)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.wrapper = self.base / "Tool/scripts/apk/frida-run.ps1"
        self.wrapper.parent.mkdir(parents=True)
        shutil.copy2(ROOT / "Tool/scripts/apk/frida-run.ps1", self.wrapper)
        self.log = self.base / "argv.json"
        self.env = isolated_environment(self.base)
        self.env["FRIDA_WRAPPER_LOG"] = str(self.log)
        self.bin = self.base / "fake bin"
        self.bin.mkdir()
        self.env["PATH"] = ";".join((str(self.bin), str(Path(sys.executable).parent),
                                     str(Path(os.environ["SystemRoot"]) / "System32")))
        self.acquire = self.wrapper.parent.parent / "tool-acquire.py"
        self.acquire.write_text("raise SystemExit('unexpected acquisition')\n", encoding="utf-8")
        self.payload = self.base / "hook.js"
        self.payload.write_text("// offline fixture\n", encoding="utf-8")

    def tool(self, name, folder=None):
        folder = folder or self.bin
        folder.mkdir(exist_ok=True)
        recorder = folder / "record.py"
        recorder.write_text(
            "import json,os,sys\nfrom pathlib import Path\n"
            "Path(os.environ['FRIDA_WRAPPER_LOG']).write_text(json.dumps(sys.argv[1:]))\n"
            "raise SystemExit(7)\n", encoding="utf-8")
        cli = folder / (name + ".cmd")
        cli.write_text(f'@"{sys.executable}" "{recorder}" %*\r\n', encoding="utf-8")
        return cli

    def run_wrapper(self, *args):
        return run_ps(self.wrapper, *args, env=self.env)

    def test_list_modes_only_require_the_selected_cli_and_preserve_exit(self):
        for mode, name, expected in (
            ("-ListDevices", "frida-ls-devices", []),
            ("-ListProcesses", "frida-ps", ["-H", "127.0.0.1:27042"]),
        ):
            with self.subTest(mode=mode):
                cli = self.tool(name)
                proc = self.run_wrapper(mode)
                self.assertEqual(proc.returncode, 7, proc.stdout + proc.stderr)
                self.assertEqual(json.loads(self.log.read_text()), expected)
                cli.unlink()

    def test_attach_and_spawn_use_current_pause_arguments(self):
        self.tool("frida")
        for extra in ([], ["-Spawn", "-Pause"]):
            with self.subTest(extra=extra):
                proc = self.run_wrapper("-Package", "fixture.example", "-ScriptPath",
                                        str(self.payload), "-Usb", *extra)
                self.assertEqual(proc.returncode, 7, proc.stdout + proc.stderr)
                args = json.loads(self.log.read_text())
                self.assertNotIn("--no-pause", args)
                self.assertEqual("--pause" in args, bool(extra))
                self.assertIn("-f" if extra else "-n", args)

    def test_acquisition_uses_verified_result_outside_path(self):
        cli = self.tool("frida", self.base / "acquired tools")
        result = {"verdict": "USABLE", "identity": {"ok": True},
                  "steps": [{"level": "L3", "ok": True},
                            {"kind": "cli", "exe": str(cli), "ok": True}]}
        self.acquire.write_text("import json,sys\n"
                                "assert sys.argv[1:] == ['--tool','frida','--install','--json']\n"
                                "print(" + repr(json.dumps(result)) + ")\n", encoding="utf-8")
        proc = self.run_wrapper("-Package", "fixture.example", "-ScriptPath", str(self.payload))
        self.assertEqual(proc.returncode, 7, proc.stdout + proc.stderr)
        self.assertTrue(self.log.is_file())

    def test_failed_or_unverified_acquisition_does_not_run_cli(self):
        cli = self.tool("frida", self.base / "unverified tools")
        for returncode, verdict, identity in ((7, "USABLE", True),
                                              (0, "USABLE", False),
                                              (0, "FOUND_NO_VERIFY", True)):
            with self.subTest(returncode=returncode, verdict=verdict, identity=identity):
                result = {"verdict": verdict, "identity": {"ok": identity},
                          "steps": [{"kind": "cli", "exe": str(cli), "ok": True}]}
                self.acquire.write_text("print(" + repr(json.dumps(result)) + ")\n"
                                        "raise SystemExit(" + str(returncode) + ")\n",
                                        encoding="utf-8")
                proc = self.run_wrapper("-Package", "fixture.example", "-ScriptPath", str(self.payload))
                self.assertNotEqual(proc.returncode, 0)
                self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
