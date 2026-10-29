#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adversarial regressions for MCP filesystem, process, and evidence boundaries."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import seep_case_library as CL
import seep_http_security as HS
import seep_mcp_server as S
import seep_tool_verify as TV


class R2ExecutionContract(unittest.TestCase):
    def test_nonzero_process_is_not_returned_as_strings(self):
        with tempfile.NamedTemporaryFile(prefix="seep-target-", delete=False) as target:
            target.write(b"MZ")
            target_path = target.name
        self.addCleanup(lambda: os.path.exists(target_path) and os.unlink(target_path))
        failed = {
            "ok": False, "returncode": 9, "stdout": "",
            "stderr": "FAKE_FAILURE_SENTINEL", "error": "",
        }
        with patch.object(S, "RABIN2_EXE", sys.executable), \
                patch.object(S, "_run_capture", return_value=failed):
            text = S.seep_r2_strings(binary_path=target_path)
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "empty_output")
        self.assertEqual(payload["diagnostics"]["returncode"], 9)
        self.assertIn("FAKE_FAILURE_SENTINEL", payload["diagnostics"]["stderr"])

    @unittest.skipUnless(os.name == "nt", "batch fake uses Windows cmd")
    def test_version_string_alone_cannot_verify_r2(self):
        with tempfile.TemporaryDirectory(prefix="seep-fake-r2-") as temp:
            fake = os.path.join(temp, "radare2.bat")
            with open(fake, "w", encoding="ascii", newline="\r\n") as handle:
                handle.write("@echo off\r\necho radare2 5.9.8 fake-payload\r\n")
            result = TV.verify_tool("r2", fake)
        self.assertFalse(result["verified"])
        self.assertEqual(result["verdict"], "found_no_verify")


class ApkPublicationContract(unittest.TestCase):
    def test_nonempty_output_is_refused_and_preserved(self):
        with tempfile.TemporaryDirectory(prefix="seep-apk-boundary-") as temp:
            apk = os.path.join(temp, "sample.apk")
            jar = os.path.join(temp, "apktool.jar")
            out = os.path.join(temp, "out")
            os.mkdir(out)
            sentinel = os.path.join(out, "old.txt")
            for path, data in ((apk, b"PK"), (jar, b"jar"), (sentinel, b"ORIGINAL")):
                with open(path, "wb") as handle:
                    handle.write(data)
            with patch.object(S, "_find_java", return_value=sys.executable), \
                    patch.object(S, "APKTOOL_JAR", jar):
                payload = json.loads(S.seep_apk_unpack(
                    apk_path=apk, output_dir=out))
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["diagnostics"]["error"], "output_not_empty")
            with open(sentinel, "rb") as handle:
                self.assertEqual(handle.read(), b"ORIGINAL")

    def test_failed_unpack_keeps_diagnostics_and_does_not_publish(self):
        with tempfile.TemporaryDirectory(prefix="seep-apk-failure-") as temp:
            apk = os.path.join(temp, "sample.apk")
            jar = os.path.join(temp, "apktool.jar")
            out = os.path.join(temp, "out")
            for path in (apk, jar):
                with open(path, "wb") as handle:
                    handle.write(b"fixture")
            failed = {
                "ok": False, "returncode": 7, "stdout": "partial",
                "stderr": "APKTOOL_FAILURE", "error": "",
            }
            with patch.object(S, "_find_java", return_value=sys.executable), \
                    patch.object(S, "APKTOOL_JAR", jar), \
                    patch.object(S, "_run_capture", return_value=failed):
                payload = json.loads(S.seep_apk_unpack(
                    apk_path=apk, output_dir=out))
            self.assertFalse(payload["ok"])
            self.assertFalse(os.path.exists(out))
            self.assertEqual(payload["diagnostics"]["returncode"], 7)
            self.assertEqual(payload["diagnostics"]["stderr"], "APKTOOL_FAILURE")
            self.assertTrue(os.path.isdir(payload["diagnostics"]["staging"]))


class CaseAndSearchBoundary(unittest.TestCase):
    def test_case_refs_cannot_escape_case_root(self):
        with tempfile.TemporaryDirectory(prefix="seep-case-root-") as temp:
            root = os.path.join(temp, "cases")
            case_dir = os.path.join(root, "case-a")
            os.makedirs(case_dir)
            outside = os.path.join(temp, "outside.md")
            with open(outside, "w", encoding="utf-8") as handle:
                handle.write("OUTSIDE_SENTINEL")
            with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as handle:
                json.dump({"id": "case-a", "refs": ["../../outside.md"]}, handle)
            with patch.object(CL, "case_lib_dir", return_value=root):
                text = CL.read_case("case-a")
        self.assertNotIn("OUTSIDE_SENTINEL", text)
        self.assertIn("未提供 README", text)

    def test_case_json_symlink_cannot_escape_case_root(self):
        with tempfile.TemporaryDirectory(prefix="seep-case-link-") as temp:
            root = os.path.join(temp, "cases")
            case_dir = os.path.join(root, "case-a")
            os.makedirs(case_dir)
            outside = os.path.join(temp, "outside.json")
            with open(outside, "w", encoding="utf-8") as handle:
                json.dump({"id": "case-a", "target_type": "OUTSIDE_LINK_SENTINEL"}, handle)
            try:
                os.symlink(outside, os.path.join(case_dir, "case.json"))
            except OSError as exc:
                self.skipTest("UNVERIFIED: 当前环境不能创建文件符号链接：%s" % exc)
            with patch.object(CL, "case_lib_dir", return_value=root):
                text = CL.read_case("case-a")
            self.assertNotIn("OUTSIDE_LINK_SENTINEL", text)
            self.assertIn("Case not found", text)

    def test_smali_limit_is_checked_before_directory_access(self):
        payload = json.loads(S.seep_apk_smali_search(
            directory="does-not-exist", pattern="AES", limit=0))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "invalid_parameters")

    def test_smali_zero_hit_is_explicit(self):
        with tempfile.TemporaryDirectory(prefix="seep-smali-") as temp:
            with open(os.path.join(temp, "a.smali"), "w", encoding="utf-8") as handle:
                handle.write("const-string v0, 'hello'")
            payload = json.loads(S.seep_apk_smali_search(
                directory=temp, pattern="AES", limit=10))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], "zero_results")
        self.assertEqual(payload["scanned_files"], 1)

    def test_smali_page_total_counts_matches_after_the_limit(self):
        with tempfile.TemporaryDirectory(prefix="seep-smali-page-") as temp:
            with open(os.path.join(temp, "a.smali"), "w", encoding="utf-8") as handle:
                handle.write("\n".join("AES key %d" % i for i in range(5)))
            payload = json.loads(S.seep_apk_smali_search(
                directory=temp, pattern="AES", limit=2))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["count"], 2)
        self.assertEqual(payload["match_total"], 5)
        self.assertIn("本次返回 2 / 5 条", payload["matches"][-1])


class SideEffectOrdering(unittest.TestCase):
    def test_auto_triage_rejects_directory_before_case_creation(self):
        with tempfile.TemporaryDirectory(prefix="seep-triage-") as temp:
            with patch.object(S, "_attached_for") as attached:
                payload = json.loads(S.seep_auto_triage(target_path=temp))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "target_not_regular_file")
        attached.assert_not_called()

    def test_report_write_failure_leaves_no_ghost_directory(self):
        with tempfile.TemporaryDirectory(prefix="seep-report-") as temp:
            work = os.path.join(temp, "work")
            kwargs = dict(
                task_name="task", target_name="target",
                branch_location="0x401000", description="proof",
                poc_summary="fixture", case_dir="",
            )
            with patch.object(S, "_case_evidence_dir", return_value=temp), \
                    patch.object(S, "_strong_claim_ids", return_value=["F-1"]), \
                    patch.object(S, "_task_dir", return_value=work), \
                    patch.object(S, "_atomic_write_text",
                                 side_effect=OSError("disk full")):
                payload = json.loads(S.seep_gen_security_report(**kwargs))
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["error"], "report_write_failed")
            self.assertFalse(os.path.exists(os.path.join(work, "reports")))


class HttpSessionBoundary(unittest.TestCase):
    def test_session_path_cannot_escape_dedicated_root(self):
        with tempfile.TemporaryDirectory(prefix="seep-http-boundary-") as temp:
            root = os.path.join(temp, "sessions")
            outside = os.path.join(temp, "outside.json")
            os.mkdir(root)
            with open(outside, "w", encoding="utf-8") as handle:
                json.dump({"not": "a session"}, handle)
            with patch.dict(os.environ, {"SEEP_HTTP_SESSION_ROOT": root}):
                with self.assertRaises(ValueError):
                    S._http_session_path(outside)

    def test_random_existing_file_is_rejected_before_request(self):
        with tempfile.TemporaryDirectory(prefix="seep-http-random-") as temp:
            session = os.path.join(temp, "existing.json")
            with open(session, "w", encoding="utf-8") as handle:
                handle.write('{"BEFORE_PREFIX":"ORIGINAL-DATA"}')
            with patch.dict(os.environ, {"SEEP_HTTP_SESSION_ROOT": temp}):
                payload = json.loads(S.seep_http_replay(
                    url="http://127.0.0.1:9/", session_file=session, timeout=1))
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["error"], "invalid_parameters")
            with open(session, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), '{"BEFORE_PREFIX":"ORIGINAL-DATA"}')

    def test_short_cookie_and_auth_token_are_scrubbed_from_text(self):
        secrets = HS.known_secrets(
            [{"sid": "abc"}], [{"Authorization": "Bearer SECRET_ABC"}], "")
        text = HS._scrub_text("echo abc and SECRET_ABC", secrets)
        self.assertNotIn("abc", text)
        self.assertNotIn("SECRET_ABC", text)
        self.assertEqual(text, "echo [REDACTED] and [REDACTED]")
        HS.assert_redacted({"body_preview": text}, secrets, "fixture")


class MemoryParameterBoundary(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "ReadProcessMemory is Windows-only")
    def test_invalid_parameters_are_rejected(self):
        for kwargs in (
            {"pid": 1, "max_hits": 0},
            {"pid": 1, "min_len": -1},
            {"pid": True},
            {"pid": 1, "encoding": "mystery"},
        ):
            with self.subTest(kwargs=kwargs):
                payload = json.loads(S.seep_mem_strings(**kwargs))
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["error"], "invalid_parameters")


if __name__ == "__main__":
    unittest.main(verbosity=2)
