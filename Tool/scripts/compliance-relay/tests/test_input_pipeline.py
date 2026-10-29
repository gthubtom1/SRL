#!/usr/bin/env python3
"""Real source-hook / HTTP relay / current route integration, P0-1.

Entry for check.py: python -m unittest discover -s
Tool/scripts/compliance-relay/tests -v. The standalone --json parity entry also
runs the full chain. No authenticated host or customer target is used.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("pipeline_parity", HERE.parents[1] / "rewrite-route-parity.py")
parity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parity)

IMAGE = [{"type": "image", "mimeType": "image/png", "data": "c3ludGhldGlj"}]


class TestInputPipeline(unittest.TestCase):
    def test_input_relay_route_main_and_aux_and_raw_material(self):
        with tempfile.TemporaryDirectory() as folder:
            fixtures = parity.create_input_fixtures(folder)
            before = {name: path.read_bytes() for name, path in fixtures.items()}
            self.assertTrue(all(path.is_file() for path in fixtures.values()))
            probes = parity.extra_probes(fixtures)
            windows_path = str(parity.PureWindowsPath(fixtures["binary"]))
            self.assertIn("\\", windows_path)
            self.assertTrue(any(windows_path in text and "```python\r\n" in text for text in probes))
            self.assertTrue(any(text.startswith("{") and json.loads(text)["path"] == windows_path for text in probes))
            for protocol in ("openai-completions", "openai-responses", "anthropic-messages"):
                payload = parity.payload_for(protocol, "远控", fixtures)
                self.assertEqual(payload["tools"][0]["parameters"]["path"], str(fixtures["binary"]))
                messages = payload.get("input", payload.get("messages"))
                self.assertEqual(messages[-1]["content"][-1]["text"], "附件路径：" + str(fixtures["image"]))
            result = parity.run(fixtures=fixtures)
            self.assertEqual(before, {name: path.read_bytes() for name, path in fixtures.items()})
        self.assertTrue(result["ok"], json.dumps(result, ensure_ascii=False))
        self.assertGreater(result["summary"]["inputs"], 100)
        # No accidental all-unclassified pass or primary-only comparison.
        self.assertTrue(any(row["original"]["aux"] for row in result["rows"]))
        rat = next(row for row in result["rows"] if row["text"] == "远控")
        self.assertEqual(rat["original"]["primary"], "malware-analysis")

    def test_lab_lifecycle_preserves_task_suffix_attachments_and_reloads(self):
        with tempfile.TemporaryDirectory() as folder:
            fixtures = parity.create_input_fixtures(Path(folder) / "fixtures")
            task = f'  分析 "{fixtures["binary"]}"\r\n```json\r\n{{"会员":"订阅"}}\r\n```  '
            ops = [
                {"event": {"source": "interactive", "text": "lab：" + task, "images": IMAGE}},
                {"reload": True, "event": {"source": "rpc", "text": task, "images": IMAGE}},
                {"event": {"source": "rpc", "text": "退出实验", "images": IMAGE}},
                {"reload": True, "safe": True, "event": {"source": "rpc", "text": task, "images": IMAGE}},
                {"event": {"source": "extension", "text": "lab：" + task, "images": IMAGE}},
            ]
            rows, stderr = parity.run_hook(ops, folder)
        self.assertFalse(stderr)
        self.assertTrue(rows[0]["lab"])
        self.assertTrue(rows[0]["text"].endswith(task))
        self.assertIn("已开启", rows[0]["text"])
        self.assertEqual(rows[1]["text"], task)
        self.assertTrue(rows[1]["events"])
        self.assertIn("已关闭", rows[2]["text"])
        self.assertFalse(rows[2]["lab"])
        self.assertEqual(rows[3]["text"], task)
        self.assertFalse(rows[3]["events"])
        self.assertEqual(rows[4]["text"], "lab：" + task)
        self.assertFalse(rows[4]["lab"])
        for row in rows:
            self.assertEqual(row["images"], IMAGE)
            self.assertEqual(row["event"], row["before"])

    def test_request_layer_preserves_history_provider_fields_and_context(self):
        text = '[Safe Security Testing Flow]\n会员 = "脱壳"; use-policy).'
        fields = [{"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"}]
        context = [{"role": "user", "content": text}, {"role": "assistant", "content": [{"type": "text", "text": text}]}]
        payloads = [
            {"messages": [{"role": "system", "content": "system  "}, {"role": "user", "content": text}], "safetySettings": fields},
            {"input": [{"role": "system", "content": [{"type": "input_text", "text": "system"}]}, {"role": "user", "content": text}]},
            {"system": [{"type": "text", "text": "system"}], "messages": context},
            {"contents": [{"parts": [{"text": text}, {"inlineData": {"data": "synthetic", "mimeType": "image/png"}}]}],
             "config": {"systemInstruction": "system", "safetySettings": fields}, "generationConfig": {"temperature": 0.5}},
            {"systemInstruction": {"parts": [{"text": "system"}]}, "contents": [{"parts": [{"text": text}]}]},
            {"system_instruction": {"parts": [{"text": "system"}]}, "contents": [{"parts": [{"text": text}]}]},
            {"input": text}, {"messages": [{"role": "user", "content": text}]},
        ]
        operations = [{"lab": lab, "safe": True, "text": text, "context": context, "payload": payload,
                       "model": {"provider": "google", "api": "google-generative-ai"}} for lab in (False, True) for payload in payloads]
        with tempfile.TemporaryDirectory() as folder:
            rows, stderr = parity.run_hook(operations, folder)
        self.assertFalse(stderr)
        marker = "[BOUNDARY-ANCHOR"
        for op, row in zip(operations, rows):
            self.assertEqual(row["text"], text)
            self.assertEqual(row["context"], context)
            before = json.loads(json.dumps(op["payload"]))
            after = json.loads(json.dumps(row["request"]))
            # Remove only the allowed system suffix before comparing every field.
            def strip_boundary(value):
                if isinstance(value, dict):
                    return {key: strip_boundary(v) for key, v in value.items()}
                if isinstance(value, list):
                    return [strip_boundary(v) for v in value]
                if isinstance(value, str) and marker in value:
                    return value.split("\n\n" + marker)[0]
                return value
            self.assertEqual(strip_boundary(after), before)
            if "safetySettings" not in before:
                self.assertNotIn("safetySettings", after)
            if "config" in before:
                self.assertEqual(after["config"]["safetySettings"], fields)
                self.assertEqual(after["generationConfig"], before["generationConfig"])

    def test_bad_or_missing_alias_table_warns_without_changing_input(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "bad.json"
            fixtures = parity.create_input_fixtures(Path(folder) / "fixtures")
            text = f'远控 {fixtures["apk"]}'
            for data in ("bad json", '{"schema":"seep.input-normalize/2","pairs":[{"from":"x","route_terms":[]}]}'):
                source.write_text(data, encoding="utf-8")
                rows, stderr = parity.run_hook([{"lab": True, "text": text}], folder, normalize_path=source)
                self.assertIn("WARN", stderr)
                self.assertEqual(rows[0]["text"], text)
                self.assertEqual(rows[0]["terms"], [])
            source.unlink()
            rows, stderr = parity.run_hook([{"lab": True, "text": "脱壳"}], folder, normalize_path=source)
            self.assertIn("WARN", stderr)
            self.assertEqual(rows[0]["text"], "脱壳")
            self.assertEqual(rows[0]["terms"], [])

    def test_parity_rejects_path_mutation_even_when_route_unchanged(self):
        # Fault injection exercises the same verifier as check.py; keeping the
        # primary domain is insufficient when a tool target has been renamed.
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            ts = fixture / "mutated.ts"
            source = parity.INTERCEPTOR.read_text(encoding="utf-8")
            needle = '\t\treturn { action: "continue" };\n\t});'
            self.assertEqual(source.count(needle), 1)
            ts.write_text(source.replace(needle, '\t\treturn { action: "transform", text: event.text === "远控" ? "远控 ELF" : event.text.replaceAll("target.exe", "wrong.exe") };\n\t});'), encoding="utf-8")
            probes = fixture / "probes.json"
            fixtures = parity.create_input_fixtures(fixture / "fixtures")
            probes.write_text(json.dumps({"probes": [{"text": f'分析 "{fixtures["target"]}"'}]}), encoding="utf-8")
            original_post = parity.LoopbackChain.post
            old_attachment = json.dumps(str(fixtures["image"]), ensure_ascii=False)[1:-1].encode()
            wrong_attachment = json.dumps(str(fixtures["image"].with_name("wrong.png")), ensure_ascii=False)[1:-1].encode()

            def corrupt_attachment(chain, body, *args, **kwargs):
                return original_post(chain, body.replace(old_attachment, wrong_attachment), *args, **kwargs)

            with mock.patch.object(parity.LoopbackChain, "post", corrupt_attachment):
                result = parity.run(ts_path=ts, probes_path=probes, fixtures=fixtures)
        self.assertFalse(result["ok"])
        self.assertTrue(any("hook changed original" in " ".join(row["errors"]) for row in result["inconsistencies"]))
        # This text has no hook mutation. Its failure must come from changing
        # only the real attachment path in the HTTP body, despite stable routes.
        self.assertTrue(any(row["text"] == "普通天气预报" and
                            "HTTP changed body/result/call count" in " ".join(row["errors"]) and
                            not any("domains changed" in error for error in row["errors"])
                            for row in result["inconsistencies"]))
        # The mutated 远控 still selects malware-analysis first, but introduces
        # softseep. The verifier must reject auxiliary-only drift as well.
        self.assertTrue(any(row["text"] == "远控" and "primary/aux domains changed" in " ".join(row["errors"])
                            for row in result["inconsistencies"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
