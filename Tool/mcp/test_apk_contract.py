#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression tests for APK manifest and decompiler evidence contracts."""

from __future__ import annotations

import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

_ISOLATED = tempfile.TemporaryDirectory(prefix="seep-apk-contract-")
_HOME = os.path.abspath(_ISOLATED.name)
os.environ.update({
    "HOME": _HOME,
    "USERPROFILE": _HOME,
    "APPDATA": os.path.join(_HOME, "AppData", "Roaming"),
    "LOCALAPPDATA": os.path.join(_HOME, "AppData", "Local"),
    "XDG_CONFIG_HOME": os.path.join(_HOME, ".config"),
    "SEEP_AGENT_MCP": os.path.join(_HOME, "mcp.json"),
    "SEEP_CASE_DIR": os.path.join(_HOME, "cases"),
    "SEEP_WORKSPACE": os.path.join(_HOME, "work"),
    "SEEP_AUTOCASE": "0",
})
for _key in ("APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME"):
    os.makedirs(os.environ[_key], exist_ok=True)

import seep_apk_contract as C
import seep_mcp_server as S


class AxmlManifestContract(unittest.TestCase):
    def test_real_binary_manifest_is_parsed_as_structured_facts(self):
        apk = os.path.join(ROOT, "Tool", "cases", "apkseep09", "target", "ovaa.apk")
        with zipfile.ZipFile(apk) as archive:
            manifest = C.parse_manifest(archive.read("AndroidManifest.xml"))
        self.assertEqual(manifest["status"], "ok", manifest)
        self.assertEqual(manifest["format"], "binary")
        self.assertEqual(manifest["package"], "oversecured.ovaa")
        self.assertIn("android.permission.INTERNET", manifest["uses_permissions"])
        self.assertIn(
            "oversecured.ovaa.activities.DeeplinkActivity",
            [item["name"] for item in manifest["activities"]],
        )
        self.assertEqual(
            manifest["application_name"], "oversecured.ovaa.OversecuredApplication")

    def test_broken_binary_xml_is_an_explicit_error_not_empty_success(self):
        manifest = C.parse_manifest(b"\x03\x00\x08\x00\x10\x00\x00\x00garbage")
        self.assertEqual(manifest["status"], "error")
        self.assertTrue(manifest["detail"])
        self.assertNotIn("manifest_key_markers", manifest)

    def test_plain_xml_manifest_is_supported(self):
        raw = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="fixture.pkg" android:versionCode="7">
            <uses-permission android:name="android.permission.INTERNET"/>
            <application android:name=".App">
              <activity android:name=".Main" android:exported="true"/>
            </application>
          </manifest>"""
        manifest = C.parse_manifest(raw)
        self.assertEqual(manifest["status"], "ok")
        self.assertEqual(manifest["format"], "text")
        self.assertEqual(manifest["version_code"], 7)
        self.assertEqual(manifest["activities"][0]["exported"], True)


class ApkInfoContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="seep-apk-info-")
        cls.apk = os.path.join(cls.temp.name, "fixture.apk")
        manifest = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="fixture.pkg"><application android:name=".App"/></manifest>"""
        with zipfile.ZipFile(cls.apk, "w") as archive:
            archive.writestr("classes.dex", b"dex\n035\x00")
            archive.writestr("lib/arm64-v8a/libfixture.so", b"\x7fELF")
            archive.writestr("AndroidManifest.xml", manifest)
            archive.writestr("META-INF/FIXTURE.RSA", b"not-a-real-cert")
            archive.writestr("META-INF/FIXTURE.SF", b"signature")
            archive.writestr("META-INF/MANIFEST.MF", b"manifest")
            archive.writestr(
                "META-INF/com/android/build/gradle/app-metadata.properties",
                b"version=1",
            )
            archive.writestr("META-INF/not-a-cert/nested.RSA", b"nested")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_metadata_files_are_not_reported_as_certificates(self):
        payload = json.loads(S.seep_apk_info(self.apk))
        self.assertEqual(payload["signed_certificates"], ["META-INF/FIXTURE.RSA"])
        self.assertEqual(
            payload["signing"]["v1_certificate_blocks"], ["META-INF/FIXTURE.RSA"])
        self.assertIn(
            "META-INF/com/android/build/gradle/app-metadata.properties",
            payload["signing"]["unclassified_meta_inf_files"],
        )
        self.assertIn(
            "META-INF/not-a-cert/nested.RSA",
            payload["signing"]["unclassified_meta_inf_files"],
        )

    def test_real_diva_metadata_is_not_a_signing_certificate(self):
        apk = os.path.join(ROOT, "Tool", "cases", "leaf-apk", "target", "diva.apk")
        payload = json.loads(S.seep_apk_info(apk))
        self.assertEqual(payload["signed_certificates"], [])
        self.assertEqual(payload["signing"]["schemes"], [])
        self.assertEqual(payload["manifest"]["package"], "jakhar.aseem.diva")
        self.assertIn(
            "META-INF/com/android/build/gradle/app-metadata.properties",
            payload["signing"]["unclassified_meta_inf_files"],
        )

    def test_invalid_zip_returns_structured_error(self):
        bad = os.path.join(self.temp.name, "bad.apk")
        with open(bad, "wb") as fh:
            fh.write(b"PK\x03\x04broken")
        payload = json.loads(S.seep_apk_info(bad))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "invalid_apk")

    def test_duplicate_manifest_is_an_explicit_error(self):
        duplicate = os.path.join(self.temp.name, "duplicate-manifest.apk")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate, "w") as archive:
                archive.writestr("classes.dex", b"dex\n035\x00")
                archive.writestr(
                    "AndroidManifest.xml", b"<manifest package='one'/>")
                archive.writestr(
                    "AndroidManifest.xml", b"<manifest package='two'/>")
        payload = json.loads(S.seep_apk_info(duplicate))
        self.assertEqual(payload["manifest"]["status"], "error")
        self.assertEqual(payload["manifest"]["error"], "duplicate_manifest")
        self.assertEqual(payload["manifest_key_markers"], [])

    def test_registered_mcp_entry_accepts_the_documented_path_alias(self):
        import asyncio

        async def call():
            content, _meta = await S.server.call_tool(
                "seep_apk_info", {"target_path": self.apk})
            return json.loads(content[0].text)

        payload = asyncio.run(call())
        self.assertEqual(payload["manifest"]["package"], "fixture.pkg")

    def test_v2_signing_block_is_detected_by_pair_id(self):
        signed = os.path.join(self.temp.name, "v2-signed.apk")
        with zipfile.ZipFile(signed, "w") as archive:
            archive.writestr("classes.dex", b"dex\n035\x00")
        with open(signed, "rb") as fh:
            data = fh.read()
        eocd = data.rfind(b"PK\x05\x06")
        central_offset = struct.unpack_from("<I", data, eocd + 16)[0]
        pair = struct.pack("<QI", 0x7109871A, 0)
        block_size = len(pair) + 24
        block = (
            struct.pack("<Q", block_size)
            + pair
            + struct.pack("<Q", block_size)
            + b"APK Sig Block 42"
        )
        data = data[:central_offset] + block + data[central_offset:]
        eocd = data.rfind(b"PK\x05\x06")
        data = (
            data[:eocd + 16]
            + struct.pack("<I", central_offset + len(block))
            + data[eocd + 20:]
        )
        with open(signed, "wb") as fh:
            fh.write(data)
        evidence = C.signing_evidence(
            signed, ["classes.dex"])
        self.assertEqual(evidence["schemes"], ["v2"])
        self.assertTrue(evidence["apk_signing_block_present"])


class JadxContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="seep-jadx-contract-")
        self.addCleanup(self.temp.cleanup)
        self.apk = os.path.join(self.temp.name, "sample.apk")
        with zipfile.ZipFile(self.apk, "w") as archive:
            archive.writestr("classes.dex", b"dex\n035\x00")

    def test_nonzero_rc_with_real_sources_is_partial_not_empty(self):
        output = os.path.join(self.temp.name, "sources")

        def fake_run(command, **_kwargs):
            stage = command[command.index("-d") + 1]
            source = os.path.join(stage, "sources", "Fixture.java")
            os.makedirs(os.path.dirname(source))
            with open(source, "w", encoding="utf-8") as fh:
                fh.write("class Fixture {}\n")
            return {
                "returncode": 1,
                "stdout": "",
                "stderr": "WARN: one method failed\n",
                "timed_out": False,
                "duration_seconds": 0.1,
            }

        with patch.object(C, "run_command", side_effect=fake_run):
            result = C.run_jadx("java", "jadx.cmd", self.apk, output)
        self.assertEqual(result["status"], "partial", result)
        self.assertEqual(result["returncode"], 1)
        self.assertEqual(result["artifacts"]["java_count"], 1)
        self.assertTrue(os.path.isfile(
            os.path.join(output, "sources", "Fixture.java")))

    def test_nonzero_rc_without_artifacts_retains_complete_diagnostics(self):
        output = os.path.join(self.temp.name, "failed")

        def fake_run(_command, **_kwargs):
            return {
                "returncode": 9,
                "stdout": "",
                "stderr": "FATAL: decoder crashed\n",
                "timed_out": False,
                "duration_seconds": 0.2,
            }

        with patch.object(C, "run_command", side_effect=fake_run):
            result = C.run_jadx("java", "jadx.cmd", self.apk, output)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["returncode"], 9)
        self.assertIn("decoder crashed", result["stderr"])
        self.assertTrue(os.path.isdir(result["staging_dir"]))
        self.assertTrue(os.path.samefile(
            os.path.dirname(result["staging_dir"]), self.temp.name))

    def test_nonempty_destination_is_refused_without_spawning(self):
        output = os.path.join(self.temp.name, "existing")
        os.makedirs(output)
        marker = os.path.join(output, "user-file.txt")
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write("keep")
        with patch.object(C, "run_command") as run:
            result = C.run_jadx("java", "jadx.cmd", self.apk, output)
        self.assertEqual(result["error"], "output_exists")
        run.assert_not_called()
        self.assertTrue(os.path.isfile(marker))

    def test_server_wraps_no_artifact_failure_with_diagnostics(self):
        failed = {
            "status": "error",
            "returncode": 4,
            "stderr": "decoder failed",
            "artifacts": {"file_count": 0, "has_expected_artifacts": False},
        }
        with patch.object(S, "_find_java", return_value="java"), \
                patch.object(S.shutil, "which", return_value=None), \
                patch.object(S.os.path, "isfile", return_value=True), \
                patch.object(S, "_run_jadx", return_value=failed):
            payload = json.loads(S.seep_apk_decompile(
                self.apk, os.path.join(self.temp.name, "server-output")))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "empty_output")
        self.assertEqual(payload["diagnostics"]["returncode"], 4)
        self.assertEqual(payload["diagnostics"]["stderr"], "decoder failed")

    def test_real_bundled_jadx_publishes_partial_or_complete_sources(self):
        java = shutil.which("java")
        jadx = os.path.join(
            ROOT, "Tool", "mcp", "Tool", "safe", "jadx", "bin", "jadx.bat")
        if not java or not os.path.isfile(jadx):
            self.skipTest("bundled JADX/JDK unavailable")
        source_apk = os.path.join(
            ROOT, "Tool", "cases", "leaf-apk", "target", "diva.apk")
        output = os.path.join(self.temp.name, "real-jadx")
        result = C.run_jadx(java, jadx, source_apk, output, timeout=180)
        self.assertIn(result["status"], {"ok", "partial"}, result)
        self.assertTrue(result["artifacts"]["has_expected_artifacts"], result)
        self.assertGreater(result["artifacts"]["file_count"], 10, result)
        self.assertTrue(os.path.isdir(output))


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        _ISOLATED.cleanup()
