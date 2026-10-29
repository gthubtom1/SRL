#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Current extended MCP tool contracts.

This regression intentionally follows the live server registration and
``Tool/config/mcp-tool-dependencies.json``. It does not test retired tool names
that may still appear in historical notes.

All stateful discovery is redirected to a temporary directory before importing
the server. The test never installs tools, creates an automatic case in the
user's home, or sends traffic outside loopback.
"""
from __future__ import annotations

import atexit
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # pragma: no cover - presentation only
        pass


# Import-time state paths are computed by tool_autodiscover. Redirect every
# supported home/state variable before importing the server or plugin.
_ISOLATED = tempfile.TemporaryDirectory(prefix="seep-ext-assets-")
_ISOLATED_HOME = os.path.abspath(_ISOLATED.name)
os.environ.update({
    "HOME": _ISOLATED_HOME,
    "USERPROFILE": _ISOLATED_HOME,
    "APPDATA": os.path.join(_ISOLATED_HOME, "AppData", "Roaming"),
    "LOCALAPPDATA": os.path.join(_ISOLATED_HOME, "AppData", "Local"),
    "XDG_CONFIG_HOME": os.path.join(_ISOLATED_HOME, ".config"),
    "SEEP_AGENT_MCP": os.path.join(_ISOLATED_HOME, "mcp.json"),
    "SEEP_CASE_DIR": os.path.join(_ISOLATED_HOME, "cases"),
    "SEEP_WORKSPACE": os.path.join(_ISOLATED_HOME, "work"),
    "SEEP_AUTOCASE": "0",
})
for _key in ("APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME"):
    os.makedirs(os.environ[_key], exist_ok=True)


def _cleanup_isolation() -> None:
    _ISOLATED.cleanup()


atexit.register(_cleanup_isolation)

try:
    import seep_contract as C
    import seep_mcp_server as S
    import tool_autodiscover as T
except Exception as exc:  # pragma: no cover - dependency failure is a hard error
    raise RuntimeError(
        "UNVERIFIED: current MCP modules could not be imported: %s: %s"
        % (type(exc).__name__, exc)
    ) from exc


def _call_mcp(name: str, arguments: dict) -> str:
    """Call the registered MCP entry, not only its Python implementation."""
    import asyncio

    async def run():
        content, _meta = await S.server.call_tool(name, arguments)
        if not content:
            raise AssertionError("%s returned no content" % name)
        return content[0].text

    return asyncio.run(run())


def _registered_tool_names() -> set[str]:
    return {tool.name for tool in S.server._tool_manager.list_tools()}


class RegisteredSurfaceContract(unittest.TestCase):
    def test_registration_matches_dependency_manifest(self):
        manifest_path = os.path.join(ROOT, "Tool", "config", "mcp-tool-dependencies.json")
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        declared = set((manifest.get("tools") or {}).keys())
        actual = _registered_tool_names()
        self.assertEqual(actual, declared)

    def test_retired_tool_names_are_not_registered(self):
        retired = {"seep_decompile_auto", "seep_pe_resources", "seep_web_recon"}
        self.assertFalse(retired & _registered_tool_names())
        for name in retired:
            self.assertFalse(hasattr(S, name), name)

    def test_every_registered_tool_has_a_python_entrypoint(self):
        for name in sorted(_registered_tool_names()):
            self.assertTrue(callable(getattr(S, name, None)), name)


class DiscoveryAndInstallContract(unittest.TestCase):
    def test_state_writes_stay_inside_isolated_home(self):
        state_path = os.path.abspath(T.LOCAL_STATE_PATH)
        self.assertEqual(os.path.commonpath([state_path, _ISOLATED_HOME]), _ISOLATED_HOME)
        os.makedirs(os.path.dirname(state_path), exist_ok=True)
        saved = T.record("fixture-only-tool", {
            "available": False,
            "command": "",
            "via": "none",
            "arch": None,
        })
        self.assertIs(saved.get("state_saved"), True, saved)
        self.assertTrue(os.path.isfile(state_path))
        with open(state_path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        self.assertIn("fixture-only-tool", state.get("tools", {}))

    def test_ensure_tool_probe_mode_never_calls_install(self):
        calls = []

        class FakeDiscover:
            def discover(self, _tool_id):
                return {"available": False, "command": "", "via": "none"}

            def install_plan(self, _tool_id):
                return {"has_plan": True, "auto_allowed": True, "command": "not executed"}

            def propose_install(self, *_args, **_kwargs):
                calls.append("install")
                raise AssertionError("allow_install=False must not install")

        with patch.object(S, "_autodiscover", return_value=FakeDiscover()):
            payload = json.loads(S.seep_ensure_tool("fixture-only-tool", allow_install=False))
        self.assertEqual(payload.get("status"), "missing")
        self.assertEqual(payload.get("install_plan", {}).get("command"), "not executed")
        self.assertNotIn("install_attempt", payload)
        self.assertEqual(calls, [])

    def test_registered_discovery_entry_writes_only_to_isolated_state(self):
        payload = json.loads(S.seep_tool_discover("r2", record_state=False))
        self.assertIn("available", payload)
        self.assertNotIn("state_record", payload)
        self.assertEqual(
            os.path.commonpath([os.path.abspath(T.LOCAL_STATE_PATH), _ISOLATED_HOME]),
            _ISOLATED_HOME,
        )


class RoutingPersistenceContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="seep-routing-")
        self.addCleanup(self.temp.cleanup)

    def test_domain_router_keeps_primary_and_auxiliary_domains(self):
        sample = os.path.join(self.temp.name, "sample.apk")
        with open(sample, "wb") as handle:
            handle.write(b"PK\x03\x04fixture")
        routed = S._domain_for(sample, "抓包复刻私有协议")
        self.assertEqual(routed.get("primary_domain"), "apkseep", routed)
        self.assertIn("protocol-plugin", routed.get("auxiliary_domains", []), routed)
        self.assertIs(routed.get("ambiguity"), True, routed)

    def test_auto_case_persists_auxiliary_domains_and_ambiguity(self):
        sample = os.path.join(self.temp.name, "sample.apk")
        with open(sample, "wb") as handle:
            handle.write(b"PK\x03\x04fixture")
        case_root = os.path.join(self.temp.name, "cases")
        with patch.object(S, "_AUTOCASE", True), \
                patch.dict(os.environ, {"SEEP_CASE_DIR": case_root}, clear=False):
            result = S._case_for(sample, "抓包复刻私有协议")
        self.assertIs(result.get("created"), True, result)
        self.assertEqual(result.get("domain"), "apkseep", result)
        self.assertIn("protocol-plugin", result.get("auxiliary_domains", []), result)
        self.assertIs(result.get("ambiguity"), True, result)

        with open(os.path.join(result["case"], "case.json"), "r", encoding="utf-8") as handle:
            meta = json.load(handle)
        self.assertEqual(meta.get("domain"), "apkseep", meta)
        self.assertIn("protocol-plugin", meta.get("auxiliary_domains", []), meta)
        self.assertIs(meta.get("ambiguity"), True, meta)

    def test_reused_auto_case_upgrades_routing_without_overwriting_operator_domain(self):
        sample = os.path.join(self.temp.name, "sample.apk")
        with open(sample, "wb") as handle:
            handle.write(b"PK\x03\x04fixture")
        case_root = os.path.join(self.temp.name, "cases")
        with patch.object(S, "_AUTOCASE", True), \
                patch.dict(os.environ, {"SEEP_CASE_DIR": case_root}, clear=False):
            first = S._case_for(sample, "抓包复刻私有协议")
            case_file = os.path.join(first["case"], "case.json")
            with open(case_file, "r", encoding="utf-8") as handle:
                meta = json.load(handle)
            meta["domain"] = "operator-selected"
            meta.pop("auxiliary_domains", None)
            meta.pop("ambiguity", None)
            with open(case_file, "w", encoding="utf-8") as handle:
                json.dump(meta, handle)

            reused = S._case_for(sample, "抓包复刻私有协议")
            with open(case_file, "r", encoding="utf-8") as handle:
                persisted = json.load(handle)

        self.assertIs(reused.get("created"), False, reused)
        self.assertEqual(reused.get("domain"), "operator-selected", reused)
        self.assertIn("apkseep", reused.get("auxiliary_domains", []), reused)
        self.assertIn("protocol-plugin", reused.get("auxiliary_domains", []), reused)
        self.assertIs(reused.get("ambiguity"), True, reused)
        self.assertEqual(persisted.get("domain"), "operator-selected", persisted)
        self.assertIn("apkseep", persisted.get("auxiliary_domains", []), persisted)
        self.assertIn("protocol-plugin", persisted.get("auxiliary_domains", []), persisted)
        self.assertIs(persisted.get("ambiguity"), True, persisted)


class NegativeParameterContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="seep-ext-negative-")
        self.addCleanup(self.temp.cleanup)

    def test_pcap_injection_is_refused_at_registered_entry(self):
        sentinel = "summary; SENTINEL_7A1"
        missing = os.path.join(self.temp.name, "missing.pcap")
        text = _call_mcp("seep_pcap_extract", {
            "pcap_path": missing,
            "mode": sentinel,
        })
        payload = json.loads(text)
        self.assertIs(payload.get("ok"), False)
        self.assertEqual(payload.get("error"), "invalid_parameters")
        self.assertEqual(payload.get("blocked_at"), "seep_pcap_extract")
        self.assertEqual(payload.get("executions"), [])
        self.assertNotIn("SENTINEL_7A1", text)

    def test_mem_strings_requires_an_explicit_target(self):
        text = _call_mcp("seep_mem_strings", {})
        self.assertTrue(text.startswith("[ERROR]"), text[:160])
        self.assertIn("缺少", text)

    def test_packer_detect_refuses_missing_and_non_pe_without_autocase(self):
        missing = os.path.join(self.temp.name, "missing.exe")
        self.assertIn("ERROR", S.seep_packer_detect(missing))
        text_file = os.path.join(self.temp.name, "not-pe.txt")
        with open(text_file, "w", encoding="utf-8") as fh:
            fh.write("not a PE")
        self.assertIn("ERROR", S.seep_packer_detect(text_file))
        self.assertFalse(os.path.exists(os.environ["SEEP_CASE_DIR"]))

    def test_http_replay_refuses_invalid_inputs_before_backend_import(self):
        cases = (
            ({"url": "file:///etc/passwd"}, "url"),
            ({"url": "http://127.0.0.1/", "method": "GET\nPOST"}, "method"),
            ({"url": "http://127.0.0.1/", "headers": "[]"}, "headers"),
            ({"url": "http://127.0.0.1/", "cookies": "not-json"}, "cookies"),
            ({"url": "http://127.0.0.1/", "timeout": 0}, "timeout"),
        )
        for arguments, label in cases:
            text = S.seep_http_replay(**arguments)
            self.assertTrue(text.startswith("[ERROR]"), (label, text[:200]))


class AssetParserContract(unittest.TestCase):
    def test_preflight_classifier_uses_its_shipped_fixture(self):
        script = os.path.abspath(os.path.join(
            HERE, "..", "skill", "softseep", "scripts", "preflight-classify.py"))
        fixture = os.path.join(HERE, "Tool", "safe", "ida-pro-mcp", "tests",
                               "typed_fixture.elf")
        self.assertTrue(os.path.isfile(script), script)
        self.assertTrue(os.path.isfile(fixture), fixture)
        proc = subprocess.run(
            [sys.executable, "-B", script, fixture],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        payload = json.loads(proc.stdout)
        self.assertEqual(payload.get("platform"), "Linux")
        self.assertTrue(payload.get("suggested_type"))

    def test_packer_contract_uses_the_current_pe_result_shape(self):
        sample = os.path.join(HERE, "Tool", "safe", "radare2", "bin", "r2agent.exe")
        self.assertTrue(os.path.isfile(sample), sample)
        # `_detect_needs` only adds the user-input questionnaire. Stub that
        # unrelated config read so this asset-shape test stays hermetic.
        with patch.object(S, "_needs_table", return_value=[]):
            payload = json.loads(S.seep_packer_detect(sample))
        self.assertEqual(payload.get("file"), os.path.basename(sample))
        self.assertIn(payload.get("status"), {"ok", "unknown"})
        for field in ("packed", "route", "strong_signals", "weak_signals",
                      "sections", "next_actions"):
            self.assertIn(field, payload)
        if payload.get("status") == "unknown":
            self.assertIsNone(payload.get("packed"))
            self.assertTrue(payload.get("why"))
        self.assertFalse(os.path.exists(os.environ["SEEP_CASE_DIR"]))


class HttpRedactionContract(unittest.TestCase):
    URL_SECRET = "URL_SECRET_7821"
    COOKIE_SECRET = "COOKIE_SECRET_7822"
    AUTH_SECRET = "BEARER_SECRET_7823"
    RESPONSE_SECRET = "RESPONSE_SECRET_7824"

    def _serve_once(self):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({
                    "ok": True,
                    "echo": self.path,
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header(
                    "Set-Cookie", "sid=%s; Path=/" % outer.RESPONSE_SECRET)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return "http://127.0.0.1:%d" % server.server_address[1]

    def test_loopback_replay_redacts_output_and_session_snapshot(self):
        base = self._serve_once()
        with tempfile.TemporaryDirectory(prefix="seep-http-redaction-") as temp:
            session = os.path.join(temp, "session.json")
            url = base + "/check?token=" + self.URL_SECRET
            with patch.dict(os.environ, {"SEEP_HTTP_SESSION_ROOT": temp}):
                text = S.seep_http_replay(
                    url=url,
                    method="GET",
                    headers=json.dumps({"Authorization": "Bearer " + self.AUTH_SECRET}),
                    cookies=json.dumps({"sid": self.COOKIE_SECRET}),
                    impersonate="none",
                    session_file=session,
                    timeout=10,
                )
            payload = json.loads(text)
            self.assertEqual(payload.get("status"), 200, text[:300])
            self.assertIs(payload.get("cookies_redacted"), True)
            self.assertEqual(payload.get("request", {}).get("cookies", {}).get("sid"),
                             S.REDACTED)
            self.assertEqual(payload.get("set_cookies", {}).get("sid"), S.REDACTED)
            self.assertEqual(
                payload.get("request", {}).get("headers", {}).get("Authorization"),
                S.REDACTED,
            )
            self.assertTrue(os.path.isfile(session))
            with open(session, "r", encoding="utf-8") as fh:
                snapshot = fh.read()
            for secret in (self.URL_SECRET, self.COOKIE_SECRET,
                           self.AUTH_SECRET, self.RESPONSE_SECRET):
                self.assertNotIn(secret, text)
                self.assertNotIn(secret, snapshot)


class ContractReferenceSanity(unittest.TestCase):
    def test_contract_ranges_match_the_live_entry_checks(self):
        self.assertEqual(C.PCAP_MODES, ("summary", "http", "payload"))
        self.assertEqual(C.PCAP_PORT_RANGE, (0, 65535))
        self.assertEqual(C.PCAP_MAX_ROWS_RANGE, (1, 10000))
        for mode in C.PCAP_MODES:
            params, reason = C.pcap_params(mode, "0", "40", "")
            self.assertIsNotNone(params, reason)
            self.assertEqual(params.get("mode"), mode)

    def test_dependency_manifest_source_paths_exist(self):
        manifest_path = os.path.join(ROOT, "Tool", "config", "mcp-tool-dependencies.json")
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        for tool_name, entry in manifest.get("tools", {}).items():
            source = entry.get("source", {})
            source_file = source.get("file")
            if source_file:
                self.assertTrue(os.path.isfile(os.path.join(ROOT, source_file)),
                                (tool_name, source_file))


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        _cleanup_isolation()
