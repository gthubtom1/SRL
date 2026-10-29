"""R10 firmware-iot regressions for redaction, path, and extraction limits."""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "Tool" / "skill" / "firmware-iot" / "scripts"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class R10FirmwareContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.triage = load_module("r10_fw_triage", SCRIPTS / "fw-triage.py")
        cls.repro = load_module("r10_fw_repro", SCRIPTS / "fw-repro.py")
        cls.accept = load_module("r10_fw_accept", SCRIPTS / "fw-accept.py")

    def test_triage_redacts_sparse_credential_forms(self):
        samples = {
            "header bearer BEARER_SECRET_123456": "BEARER_SECRET_123456",
            "prefix ssh-rsa AAAASECRETPUBLICKEY123": "AAAASECRETPUBLICKEY123",
            "AWS AKIAABCDEFGHIJKLMNOP value": "AKIAABCDEFGHIJKLMNOP",
            "root:$6$salt$SHADOW_SECRET:19000:0:99999:7:::": "SHADOW_SECRET",
            "root:PLAINTEXT_SECRET:0:0:root:/root:/bin/sh": "PLAINTEXT_SECRET",
            "password=PASSWORD_SECRET": "PASSWORD_SECRET",
        }
        for sample, secret in samples.items():
            with self.subTest(sample=sample):
                rendered = self.triage.redact(sample)
                self.assertNotIn(secret, rendered)
                self.assertIn("redacted", rendered.lower())

    def test_repro_redacts_shadow_and_bearer_values(self):
        samples = {
            "root:$6$salt$HASH_SECRET_VALUE:19000:0:99999:7:::": "HASH_SECRET_VALUE",
            "Authorization: bearer REPRO_BEARER_SECRET_123": "REPRO_BEARER_SECRET_123",
            "password=REPRO_PASSWORD_SECRET": "REPRO_PASSWORD_SECRET",
        }
        for sample, secret in samples.items():
            with self.subTest(sample=sample):
                rendered = self.repro.redact(sample)
                self.assertNotIn(secret, rendered)
                self.assertIn("redacted", rendered.lower())

    def test_repro_scan_tree_never_follows_file_symlink(self):
        with tempfile.TemporaryDirectory(prefix="r10-fw-symlink-") as tmp:
            base = Path(tmp)
            outside = base / "outside-shadow"
            outside.write_text(
                "root:$6$salt$OUTSIDE_HASH_SECRET:19000:0:99999:7:::\n",
                encoding="utf-8")
            tree = base / "tree"
            tree.mkdir()
            link = tree / "shadow"
            try:
                os.symlink(outside, link)
            except (OSError, NotImplementedError) as exc:
                self.skipTest("symlinks unavailable: %s" % type(exc).__name__)
            report = self.repro.scan_tree(str(tree))
        self.assertEqual(report["files"], 0)
        self.assertEqual(report["skipped_symlinks"], 1)
        self.assertEqual(report["findings"], [])

    def test_repro_stream_limit_fails_instead_of_writing_truncated_output(self):
        with tempfile.TemporaryDirectory(prefix="r10-fw-stream-") as tmp:
            base = Path(tmp)
            source = base / "payload.gz"
            with gzip.open(source, "wb") as stream:
                stream.write(b"A" * 33)
            dest = base / "out"
            with mock.patch.object(self.repro, "MAX_READ", 32):
                with self.assertRaisesRegex(ValueError, "analysis limit"):
                    self.repro.extract_stream("gzip", str(source), str(dest))
            self.assertFalse((dest / "gzip.out").exists())

    def test_accept_rejects_non_object_case_json(self):
        with tempfile.TemporaryDirectory(prefix="r10-fw-accept-json-") as tmp:
            root = Path(tmp)
            case_dir = root / "Tool" / "cases" / "firmware-iot99"
            case_dir.mkdir(parents=True)
            (case_dir / "case.json").write_text("[]", encoding="utf-8")
            result = self.accept.validate_case(str(case_dir), str(root))
        self.assertFalse(result["ok"])
        self.assertIn("JSON object", result["errors"][0])

    def test_accept_rejects_artifact_and_ref_escape(self):
        with tempfile.TemporaryDirectory(prefix="r10-fw-accept-path-") as tmp:
            root = Path(tmp)
            case_dir = root / "Tool" / "cases" / "firmware-iot99"
            case_dir.mkdir(parents=True)
            outside = root / "outside.json"
            outside.write_text('{"ok": true}', encoding="utf-8")
            digest = hashlib.sha256(outside.read_bytes()).hexdigest()
            case = {
                "id": "firmware-iot99",
                "domain": "firmware-iot",
                "target_type": "离线夹具：合成包",
                "evidence_kind": "fixture",
                "protection": [],
                "authority": "local",
                "goal_level": "J2",
                "outcome": "confirmed",
                "artifacts": [{"path": "../../../outside.json", "sha256": digest}],
                "lessons": ["ran tool, rc=0"],
                "refs": ["../../outside.json"],
                "updated": "2026-10-29",
            }
            (case_dir / "case.json").write_text(
                json.dumps(case, ensure_ascii=False), encoding="utf-8")
            result = self.accept.validate_case(str(case_dir), str(root))
        self.assertFalse(result["ok"])
        self.assertTrue(any("artifact path escapes" in item for item in result["errors"]))
        self.assertTrue(any("ref escapes" in item for item in result["errors"]))

    def test_accept_rejects_non_hex_digest(self):
        with tempfile.TemporaryDirectory(prefix="r10-fw-accept-hash-") as tmp:
            root = Path(tmp)
            case_dir = root / "Tool" / "cases" / "firmware-iot99"
            artifact_dir = case_dir / "artifacts"
            artifact_dir.mkdir(parents=True)
            artifact = artifact_dir / "run.json"
            artifact.write_text('{"ok": true}', encoding="utf-8")
            case = {
                "id": "firmware-iot99",
                "domain": "firmware-iot",
                "target_type": "离线夹具：合成包",
                "evidence_kind": "fixture",
                "protection": [],
                "authority": "local",
                "goal_level": "J2",
                "outcome": "confirmed",
                "artifacts": [{"path": "artifacts/run.json", "sha256": "g" * 64}],
                "lessons": ["ran tool, rc=0"],
                "refs": [],
                "updated": "2026-10-29",
            }
            (case_dir / "case.json").write_text(
                json.dumps(case, ensure_ascii=False), encoding="utf-8")
            result = self.accept.validate_case(str(case_dir), str(root))
        self.assertFalse(result["ok"])
        self.assertTrue(any("64-hex" in item for item in result["errors"]))


if __name__ == "__main__":
    unittest.main()
