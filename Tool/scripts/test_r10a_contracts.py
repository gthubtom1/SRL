"""Isolated regressions for the R10-A web/protocol fixes."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "Tool" / "skill" / "web-pentest" / "scripts"
PROTOCOL = ROOT / "Tool" / "skill" / "protocol-plugin" / "scripts"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def child(argv, *, cwd=ROOT):
    return subprocess.run(
        [sys.executable, "-B", "-X", "utf8", *map(str, argv)],
        cwd=cwd, capture_output=True, text=True, encoding="utf-8")


def command_scripts(command, base):
    scripts = []
    for token in shlex.split(command, posix=True):
        if Path(token).suffix.lower() not in (".py", ".ps1", ".sh", ".js"):
            continue
        path = Path(token)
        scripts.append(path if path.is_absolute() else base / path)
    return [path.resolve() for path in scripts]


class R10AContracts(unittest.TestCase):
    def test_race_probe_invalid_urls_do_not_echo_credentials(self):
        secret = "R10A-INVALID-URL-SECRET"
        urls = (
            "http://127.0.0.1:bad/claim?token=" + secret,
            "ftp://127.0.0.1/claim?token=" + secret,
            "http:///claim?token=" + secret,
        )
        for url in urls:
            with self.subTest(url=url):
                proc = child([
                    WEB / "race-probe.py", "--url", url,
                    "--balance-url", "http://127.0.0.1/balance", "--json",
                ])
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertNotIn(secret, proc.stdout + proc.stderr)
                result = json.loads(proc.stdout)
                self.assertFalse(result["ok"])
                self.assertEqual(result["blocked_at"], "url")

    def test_race_probe_stdout_and_out_redact_final_target_url(self):
        race = load_module("r10a_race_probe", WEB / "race-probe.py")
        balances = iter([
            {"value": 100, "status": 200, "error": None,
             "raw_sha256": "", "text": ""},
            {"value": 100, "status": 200, "error": None,
             "raw_sha256": "", "text": ""},
        ])
        target_secret = "R10A-RACE-TARGET-SECRET"
        ledger_secret = "R10A-RACE-LEDGER-SECRET"
        with tempfile.TemporaryDirectory(prefix="r10a-race-") as tmp:
            out_path = Path(tmp) / "result.json"
            stdout = io.StringIO()
            with mock.patch.object(race, "read_balance",
                                   side_effect=lambda *_args: next(balances)), \
                 mock.patch.object(race, "fire_batch", return_value=[{
                     "status": 200, "len": 0, "sha256": "",
                     "error": None, "ms": 1}]), \
                 contextlib.redirect_stdout(stdout):
                rc = race.main([
                    "--url", "http://127.0.0.1:8123/claim?token=" + target_secret,
                    "--balance-url",
                    "http://127.0.0.1:8123/balance?session=" + ledger_secret,
                    "--n", "1", "--no-dry-run", "--json",
                    "--out", str(out_path),
                ])
            persisted = out_path.read_text(encoding="utf-8")
        self.assertEqual(rc, 0, stdout.getvalue())
        combined = stdout.getvalue() + persisted
        self.assertNotIn(target_secret, combined)
        self.assertNotIn(ledger_secret, combined)
        result = json.loads(persisted)
        self.assertEqual(result["target"]["url"],
                         "http://127.0.0.1:8123/claim?token=<redacted>")

    def test_web_repro_stdout_and_out_redact_probe_target(self):
        secret = "R10A-REPRO-PERSISTENT-SECRET"
        true_hash = "a" * 64
        false_hash = "b" * 64
        probe = {
            "schema": "seep.web-probe/1",
            "experiment": "r10a-redaction",
            "target": "http://127.0.0.1:9/a?token=" + secret,
            "observations": [
                {"group": group, "status": 200, "body_len": length,
                 "body_sha256": digest, "norm_sha256": digest,
                 "elapsed_ms": 1}
                for group, length, digest in (
                    ("true", 100, true_hash),
                    ("true", 100, true_hash),
                    ("true", 100, true_hash),
                    ("false", 50, false_hash),
                    ("false", 50, false_hash),
                    ("false", 50, false_hash),
                )
            ],
        }
        with tempfile.TemporaryDirectory(prefix="r10a-web-") as tmp:
            probe_path = Path(tmp) / "probe.json"
            out_path = Path(tmp) / "verdict.json"
            probe_path.write_text(json.dumps(probe), encoding="utf-8")
            proc = child([
                WEB / "web-repro.py", "--probe", probe_path,
                "--out", out_path,
            ])
            persisted = out_path.read_text(encoding="utf-8")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        combined = proc.stdout + proc.stderr + persisted
        self.assertNotIn(secret, combined)
        result = json.loads(persisted)
        self.assertEqual(result["probe"]["target"],
                         "http://127.0.0.1:9/a?token=<redacted>")

    def test_pcapng_rejects_unconsumed_tail_lengths(self):
        pcap = load_module("r10a_pcap_summary",
                           PROTOCOL / "pcap-summary.py")
        packet = b"not-a-complete-packet"
        base = pcap._mk_pcapng([(1700000000.0, packet)])
        with tempfile.TemporaryDirectory(prefix="r10a-pcap-") as tmp:
            for remaining in (4, 8, 11):
                with self.subTest(remaining=remaining):
                    path = Path(tmp) / ("tail-%d.pcapng" % remaining)
                    path.write_bytes(base + bytes(range(remaining)))
                    with self.assertRaises(pcap.PcapError) as caught:
                        pcap.summarize(str(path))
                    self.assertIn("未消费", str(caught.exception))
                    self.assertIn("remaining=%d" % remaining,
                                  str(caught.exception))

    def test_proto_accept_bad_routes_fail_closed_in_isolated_root(self):
        with tempfile.TemporaryDirectory(prefix="r10a-proto-") as tmp:
            fake_root = Path(tmp) / "repo"
            (fake_root / "Tool" / "cases").mkdir(parents=True)
            pack_dir = fake_root / "Tool" / "skill" / "protocol-plugin"
            pack_dir.mkdir(parents=True)
            pack = json.loads(
                (ROOT / "Tool" / "skill" / "protocol-plugin" / "pack.json")
                .read_text(encoding="utf-8"))
            pack["routes"] = "bad-string"
            (pack_dir / "pack.json").write_text(
                json.dumps(pack), encoding="utf-8")
            proc = child([
                PROTOCOL / "proto-accept.py", "--root", fake_root,
                "--routing-check", "--json",
            ])
            result = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertFalse(result["ok"])
        self.assertEqual(result["blocked_at"], "accept")
        self.assertIn("pack.json.routes", result["reason"])
        self.assertNotIn('"source": "builtin"', proc.stdout)

    def test_plugin_cases_are_active_protocol_domain_and_accept_passes(self):
        expected = ("plugin02", "plugin03", "plugin04", "plugin05", "plugin06")
        for name in expected:
            case_dir = ROOT / "Tool" / "cases" / name
            path = case_dir / "case.json"
            case = json.loads(path.read_text(encoding="utf-8-sig"))
            self.assertEqual(case["domain"], "protocol-plugin", name)
            repro = case["repro"]
            self.assertEqual(repro["status"], "recorded", name)
            self.assertEqual(repro["cwd"], ".", name)
            self.assertEqual(repro["rc"], 0, name)
            repro_base = (ROOT / repro["cwd"]).resolve()
            scripts = command_scripts(repro["command"], repro_base)
            self.assertTrue(scripts, name)
            self.assertTrue(all(path.is_file() for path in scripts), name)

            run = json.loads(
                (case_dir / "artifacts" / "run.json").read_text(encoding="utf-8-sig"))
            run_cwd = Path(run.get("cwd") or ROOT)
            if not run_cwd.is_absolute():
                run_cwd = ROOT / run_cwd
            for row in run["runs"]:
                self.assertIsInstance(row["rc"], int, name)
                run_scripts = command_scripts(row["cmd"], run_cwd.resolve())
                self.assertTrue(run_scripts, name)
                self.assertTrue(all(path.is_file() for path in run_scripts), name)
            for artifact in case_dir.rglob("*"):
                if artifact.is_file() and artifact.suffix.lower() in (
                        ".json", ".md", ".txt", ".yml", ".yaml"):
                    text = artifact.read_text(encoding="utf-8", errors="ignore")
                    self.assertNotIn("plugin-targets/scripts/", text, str(artifact))
        proc = child([PROTOCOL / "proto-accept.py", "--json"])
        result = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(result["ok"])
        self.assertEqual(result["case_count"], 10)
        self.assertTrue(all(row["ok"] for row in result["cases"]))

        proc = child([PROTOCOL / "plugin-accept.py", "--root", ROOT, "--json"])
        plugin_result = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(plugin_result["ok"])
        self.assertEqual(plugin_result["case_count"], 5)
        self.assertTrue(all(row["ok"] for row in plugin_result["cases"]))

    def test_protocol_repro_context_resolves_offline_inputs(self):
        expected = {
            "protocol03": (".py", "Tool/cases/protocol03"),
            "protocol04": (".sh", "Tool/cases/protocol04"),
        }
        for name, (suffix, expected_cwd) in expected.items():
            case = json.loads(
                (ROOT / "Tool" / "cases" / name / "case.json")
                .read_text(encoding="utf-8-sig"))
            repro = case["repro"]
            self.assertEqual(repro["cwd"], expected_cwd, name)
            self.assertEqual(repro["rc"], 0, name)
            scripts = command_scripts(repro["command"], (ROOT / repro["cwd"]).resolve())
            self.assertTrue(scripts, name)
            self.assertEqual(scripts[0].suffix.lower(), suffix, name)
            self.assertTrue(scripts[0].is_file(), name)


if __name__ == "__main__":
    unittest.main()
