#!/usr/bin/env python3
"""P0-1: provider refusals/errors retain status/body and cause one HTTP call.

Old 'retry recovers' and checklist generation assertions encoded task
substitution. They are replaced by one-call checks even with legacy retry=true.
Positive/negative diagnostics, normal output and malformed responses remain.
"""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

RELAY_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RELAY_DIR))
import refusal
spec = importlib.util.spec_from_file_location("parity_refusal", RELAY_DIR.parent / "rewrite-route-parity.py")
parity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parity)


def sse(*events):
    return ("\n\n".join("data: " + json.dumps(e, ensure_ascii=False) for e in events) + "\n\ndata: [DONE]\n\n").encode()


class TestJsonRefusal(unittest.TestCase):
    def test_refusal_and_empty_observations(self):
        cases = [({"choices": [], "usage": {"completion_tokens": 377}}, "empty-choices"),
                 ({"choices": [{"message": {"content": ""}}]}, "empty-content"),
                 ({"choices": [{"message": {"content": "This request was blocked by Gemini's filters."}}]}, "refusal-wording"),
                 ({"error": {"message": "content_filter triggered"}}, "upstream-error"),
                 ({"content": [{"type": "text", "text": "我很抱歉，无法提供这类内容。"}]}, "anthropic-refusal"),
                 ({"candidates": [{"content": {"parts": []}, "finishReason": "SAFETY"}]}, "SAFETY"),
                 ({"candidates": []}, "no-candidate")]
        for data, reason in cases:
            with self.subTest(reason=reason):
                found, detail = refusal.detect_json_refusal(json.dumps(data).encode())
                self.assertTrue(found)
                self.assertIn(reason, detail)

    def test_normal_reasoning_and_malformed_are_not_refusals(self):
        cases = [{"choices": [{"message": {"content": "正常结果"}}]},
                 {"choices": [{"message": {"content": "", "reasoning_content": "推理输出"}}]},
                 {"content": [{"text": "正常结果"}]},
                 {"candidates": [{"content": {"parts": [{"text": "正常结果"}]}, "finishReason": "STOP"}]}]
        for data in cases:
            self.assertFalse(refusal.detect_json_refusal(json.dumps(data).encode())[0])
        self.assertFalse(refusal.detect_json_refusal(b"not json")[0])
        self.assertFalse(refusal.detect_json_refusal(b"[]")[0])
        self.assertFalse(refusal._text_is_refusal("x" * 1300 + " cannot help"))


class TestSseRefusal(unittest.TestCase):
    def test_empty_and_safety_streams(self):
        for body in (b"", sse({"choices": [{"delta": {}, "finish_reason": "content_filter"}]}),
                     sse({"choices": [{"delta": {"role": "assistant"}, "finish_reason": "stop"}]})):
            self.assertTrue(refusal.detect_sse_refusal(body)[0])

    def test_normal_streams_and_dispatch(self):
        for body in (sse({"choices": [{"delta": {"content": "你好"}}]}),
                     sse({"candidates": [{"content": {"parts": [{"text": "你好"}]}, "finishReason": "STOP"}]})):
            self.assertFalse(refusal.detect_sse_refusal(body)[0])
            self.assertFalse(refusal.detect_refusal("text/event-stream", body)[0])
        self.assertFalse(refusal.detect_refusal("application/json", b'{"choices":[{"message":{"content":"hi"}}]}')[0])


class TestRefusalPassThrough(unittest.TestCase):
    def test_refusal_error_empty_normal_and_stream_results_once(self):
        cases = [(200, "application/json", b'{"choices":[],"usage":{"completion_tokens":377}}'),
                 (403, "application/json", b'{"error":{"message":"content_filter triggered"}}'),
                 (429, "application/json", b'{"error":{"message":"rate limited"}}'),
                 (500, "text/plain", b"upstream failed"),
                 (200, "application/json", b""),
                 (200, "text/event-stream", sse({"choices": [{"delta": {}, "finish_reason": "content_filter"}]})),
                 (200, "text/event-stream", sse({"choices": [{"delta": {"content": "normal"}}]})),
                 (200, "application/json", b'{"choices":[{"message":{"content":"normal"}}]}')]
        for force in (True, False):
            with tempfile.TemporaryDirectory() as folder, parity.LoopbackChain(force, {"refusalRetry": True, "refusalRetryAttempts": 5}) as chain:
                fixtures = parity.create_input_fixtures(folder)
                target_text = f'分析 "{fixtures["apk"]}" 是否存在后门，逆向复现并生成报告'
                for status, content_type, response in cases:
                    chain.upstream.reply = (status, content_type, response)
                    for text in (target_text, "解释 Python 装饰器"):
                        raw = json.dumps({"messages": [{"role": "user", "content": text}]}, ensure_ascii=False).encode()
                        before = len(chain.upstream.received)
                        actual_status, actual_body, _ = chain.post(raw)
                        self.assertEqual((actual_status, actual_body), (status, response))
                        self.assertEqual(len(chain.upstream.received), before + 1)
                        self.assertEqual(chain.upstream.received[-1][1], raw)

    def test_request_substitution_helpers_removed(self):
        for name in ("build_candidates", "strategy_review_checklist", "strategy_review_framed",
                     "strategy_review_en", "set_last_user_text"):
            self.assertFalse(hasattr(refusal, name), name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
