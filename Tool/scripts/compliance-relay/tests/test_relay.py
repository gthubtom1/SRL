#!/usr/bin/env python3
"""P0-1 relay regressions.

Old longest-match/user-only replacement assertions were incorrect: paths, code,
JSON and route hints are material too. Replaced them with exact byte equality
for all protocols and lab states. Negative transport/auth/config tests remain.
"""
from __future__ import annotations
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

RELAY_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RELAY_DIR))
sys.path.insert(0, str(RELAY_DIR.parent))
import relay
spec = importlib.util.spec_from_file_location("parity", RELAY_DIR.parent / "rewrite-route-parity.py")
parity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parity)
spec = importlib.util.spec_from_file_location("extract_rules", RELAY_DIR / "extract-rules.py")
extract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract)


class TestRuleExtraction(unittest.TestCase):
    def test_generated_json_in_sync(self):
        rules = extract.extract_rules()
        self.assertEqual(extract.validate(rules), [])
        self.assertTrue(rules)
        self.assertTrue(all("to" not in r for r in rules))
        expected = json.dumps(extract.build_payload(rules), ensure_ascii=False, indent=2) + "\n"
        self.assertEqual((RELAY_DIR / "sensitive-rules.json").read_text(encoding="utf-8"), expected)

    def test_invalid_source_is_not_replaced_with_embedded_table(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "aliases.json"
            for data in ("{bad", "[]", '{"schema":"seep.input-normalize/1","pairs":[]}'):
                path.write_text(data, encoding="utf-8")
                with self.subTest(data=data), self.assertRaises(ValueError):
                    extract.extract_rules(str(path))
            with self.assertRaises(ValueError):
                extract.extract_rules(str(path.parent / "missing.json"))

    def test_alias_validation_retains_negative_cases(self):
        for pairs in ([], [{}], [{"from": "x", "route_terms": []}],
                      [{"from": "x", "route_terms": [1]}],
                      [{"from": "x", "to": "changed", "route_terms": ["x"]}],
                      [{"from": "x", "route_terms": ["x"]}] * 2):
            with self.subTest(pairs=pairs):
                self.assertTrue(extract.validate(pairs))


class TestProtocolDetection(unittest.TestCase):
    def test_detect_by_path(self):
        for path, expected in (("/v1/messages", "anthropic-messages"),
                               ("/chat/completions?x=1", "openai-completions"),
                               ("/v1/responses", "openai-responses"),
                               ("/v1/embeddings", None), ("/v1/models", None)):
            self.assertEqual(relay.detect_protocol(path), expected)

    def test_route_and_query_preserved(self):
        self.assertEqual(relay._parse_route("/r/tok/up/v1/messages?file=%E8%84%B1&x=1"),
                         ("tok", "up", "/v1/messages?file=%E8%84%B1&x=1"))
        self.assertIsNone(relay._parse_route("/health"))
        self.assertIsNone(relay._parse_route("/r/tok"))
        self.assertEqual(relay._split_upstream("http://127.0.0.1:8000/v1"),
                         ("http", "127.0.0.1", 8000, "/v1"))


class TestLabModeGate(unittest.TestCase):
    def test_force_on_and_off_are_status_only(self):
        self.assertTrue(relay.LabModeGate("nope", True).is_active())
        self.assertFalse(relay.LabModeGate("nope", False).is_active())

    def test_live_regular_file_presence(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "lab-mode.flag"
            gate = relay.LabModeGate(str(path))
            self.assertFalse(gate.is_active())
            path.write_text("timestamp", encoding="utf-8")
            self.assertTrue(gate.is_active())
            path.unlink()
            self.assertFalse(gate.is_active())
            path.mkdir()
            self.assertFalse(gate.is_active())

    def test_old_retry_options_retired_on_load(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "config.json"
            config.write_text(json.dumps({"token": "synthetic", "refusalRetry": True,
                                          "refusalRetryAttempts": 5, "upstreams": {}}), encoding="utf-8")
            with mock.patch.object(relay, "CONFIG_FILE", str(config)):
                result = relay.load_or_init_config(None)
            self.assertNotIn("refusalRetry", result)
            self.assertNotIn("refusalRetryAttempts", json.loads(config.read_text()))
            self.assertEqual(result["token"], "synthetic")


class TestEndToEnd(unittest.TestCase):
    def test_all_protocols_and_modes_preserve_whole_body(self):
        for force in (False, True, None):
            with self.subTest(force=force), tempfile.TemporaryDirectory() as folder, parity.LoopbackChain(force) as chain:
                fixtures = parity.create_input_fixtures(folder)
                for protocol, path in (("openai-completions", "/v1/chat/completions"),
                                       ("anthropic-messages", "/v1/messages"),
                                       ("openai-responses", "/v1/responses")):
                    for text in parity.extra_probes(fixtures):
                        raw = json.dumps(parity.payload_for(protocol, text, fixtures), ensure_ascii=False, indent=2).encode() + b"\r\n"
                        status, response, _ = chain.post(raw, path)
                        self.assertEqual(status, 200)
                        self.assertEqual(response, b'{"ok":true}')
                        self.assertEqual(chain.upstream.received[-1][1], raw)
                # Unknown protocol, malformed JSON, uploads and non-UTF8 pass too.
                for raw in (b"{not json", b"\x00\xffbinary", b"", b'{"input":"raw text"}'):
                    for path in ("/v1/responses", "/v1/embeddings"):
                        self.assertEqual(chain.post(raw, path)[0], 200)
                        self.assertEqual(chain.upstream.received[-1][1], raw)

    def test_invalid_routes_do_not_reach_upstream(self):
        with parity.LoopbackChain() as chain:
            for route, expected in (("/health", 404), ("/r/wrong/mock/v1/messages", 403),
                                    ("/r/synthetic-local-test/missing/v1/messages", 502)):
                self.assertEqual(chain.post(b"{}", route=route)[0], expected)
            self.assertEqual(chain.upstream.received, [])

    def test_headers_query_and_base_path(self):
        with parity.LoopbackChain() as chain:
            chain.state.upstreams["mock"] += "/base"
            raw = b'{"input":"original"}'
            status, _, _ = chain.post(raw, "/v1/responses?file=%E8%84%B1&x=1",
                                     headers={"Authorization": "Bearer synthetic-test-only", "Content-Type": "application/json"})
            self.assertEqual(status, 200)
            path, body, headers = chain.upstream.received[-1]
            self.assertEqual(path, "/base/v1/responses?file=%E8%84%B1&x=1")
            self.assertEqual(body, raw)
            self.assertEqual(headers["Authorization"], "Bearer synthetic-test-only")

    def test_no_content_logged_or_written(self):
        with parity.LoopbackChain() as chain:
            chain.state.verbose = True
            before = {p.name: p.stat().st_mtime_ns for p in RELAY_DIR.iterdir() if p.is_file()}
            with contextlib.redirect_stdout(io.StringIO()) as output:
                chain.post(b'{"input":"private-synthetic-material"}', "/v1/responses?private-query=1")
            self.assertNotIn("private", output.getvalue())
            self.assertNotIn("synthetic-local-test", output.getvalue())
            self.assertEqual(before, {p.name: p.stat().st_mtime_ns for p in RELAY_DIR.iterdir() if p.is_file()})

    def test_bad_upstream_fails_without_false_success(self):
        with parity.LoopbackChain() as chain:
            chain.state.upstreams["mock"] = "file:///no-upstream"
            self.assertEqual(chain.post(b"{}")[0], 502)
            self.assertEqual(chain.upstream.received, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
