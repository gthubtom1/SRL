#!/usr/bin/env python3
"""Optional response diagnostics only. No request reshaping or retry strategies.

Empty output is not proof of a safety refusal. Reasons describe observations;
callers must retain the original provider status/body. The relay does not use
these heuristics to alter requests or results.
"""
from __future__ import annotations
import json

REFUSAL_MARKERS = (
    "blocked by gemini", "content_filter", "prohibited", "safety", "无法提供",
    "我不能", "我不能帮", "抱歉，我", "很抱歉", "作为ai", "作为人工智能",
    "cannot help", "i cannot", "i can't", "i'm unable", "i am unable",
)
MARKER_TEXT_LIMIT = 1200


def _text_is_refusal(text: str) -> bool:
    if not text or not text.strip():
        return True
    if len(text) > MARKER_TEXT_LIMIT:
        return False
    return any(m in text[:300].lower() for m in REFUSAL_MARKERS)


def detect_json_refusal(body: bytes) -> tuple[bool, str]:
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeError):
        return False, ""
    if not isinstance(data, dict):
        return False, ""
    err = data.get("error")
    if isinstance(err, dict) and _text_is_refusal(str(err.get("message", ""))):
        return True, "upstream-error"
    choices = data.get("choices")
    if isinstance(choices, list):
        if not choices:
            usage = data.get("usage")
            count = usage.get("completion_tokens", 0) if isinstance(usage, dict) else 0
            return True, f"empty-choices(tokens={count})"
        first = choices[0] if isinstance(choices[0], dict) else {}
        msg = first.get("message")
        if not isinstance(msg, dict):
            return True, "no-message"
        content = msg.get("content")
        text = content if isinstance(content, str) else "".join(
            c.get("text", "") for c in content if isinstance(c, dict)
        ) if isinstance(content, list) else ""
        if text.strip():
            return (True, "refusal-wording") if _text_is_refusal(text) else (False, "")
        reasoning = msg.get("reasoning_content") or msg.get("reasoning")
        if isinstance(reasoning, str) and reasoning.strip():
            return False, ""
        return True, "empty-content"
    blocks = data.get("content")
    if isinstance(blocks, list):
        text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
        return (True, "anthropic-refusal") if _text_is_refusal(text) else (False, "")
    if "candidates" in data:
        candidates = data.get("candidates") or []
        if not candidates:
            return True, "no-candidate"
        cand = candidates[0] if isinstance(candidates[0], dict) else {}
        parts = (cand.get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
        if text.strip():
            return False, ""
        finish = str(cand.get("finishReason", ""))
        if any(k in finish for k in ("SAFETY", "PROHIBITED", "BLOCK", "RECITATION")):
            return True, f"finishReason={finish}"
        return True, "empty-candidate"
    return False, ""


def detect_sse_refusal(body: bytes) -> tuple[bool, str]:
    text = body.decode("utf-8", "replace")
    if not text.strip():
        return True, "empty-stream"
    saw_content, collected, finish_reason = False, [], ""
    for line in text.splitlines():
        if not line.strip().startswith("data:"):
            continue
        payload = line.strip()[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            event = json.loads(payload)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        candidates = event.get("candidates")
        if isinstance(candidates, list) and candidates:
            cand = candidates[0] if isinstance(candidates[0], dict) else {}
            finish_reason = str(cand.get("finishReason") or finish_reason)
            for part in (cand.get("content") or {}).get("parts") or []:
                if isinstance(part, dict) and part.get("text"):
                    saw_content = True
                    collected.append(part["text"])
            continue
        choices = event.get("choices")
        if isinstance(choices, list) and choices:
            choice = choices[0] if isinstance(choices[0], dict) else {}
            finish_reason = str(choice.get("finish_reason") or finish_reason)
            for key in ("delta", "message"):
                item = choice.get(key)
                if not isinstance(item, dict):
                    continue
                content = item.get("content")
                if isinstance(content, str) and content:
                    saw_content = True
                    collected.append(content)
                if item.get("reasoning_content"):
                    saw_content = True
    if any(k in finish_reason.upper() for k in ("SAFETY", "PROHIBITED", "BLOCK", "RECITATION", "CONTENT_FILTER")):
        return True, f"finishReason={finish_reason}"
    if not saw_content:
        return True, "no-content-in-stream"
    return (True, "refusal-marker") if _text_is_refusal("".join(collected)) else (False, "")


def detect_refusal(content_type: str, body: bytes) -> tuple[bool, str]:
    if not body:
        return True, "empty-body"
    return detect_sse_refusal(body) if "event-stream" in (content_type or "").lower() else detect_json_refusal(body)
