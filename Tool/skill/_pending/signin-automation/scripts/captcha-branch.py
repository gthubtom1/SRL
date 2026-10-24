#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""captcha-branch.py -- 按响应特征分流验证码处置：ocr / interactive / manual。

输入是一次响应的事实描述（不重放、不爆破），输出处置分支与下一步动作。
判定只用本地特征，不联网、不调外部 OCR。

输入 response.json（字段都可选，有什么判什么）:
    {
      "status": 200,
      "url": "https://target.example/login",
      "body": "....",
      "json": {"risk": "..."},
      "image_base64": "iVBORw0KGgo...",
      "slider_token": "abc...",
      "challenge_type": "geetest",
      "attempts": 1,
      "trace_id": "trace-1"
    }

分支定义:
    ocr          图片/字符类挑战 → 本地识别后回填，一次性提交
    interactive  滑块/行为/token 类 → 走交互流程（轨迹+token 校验）
    manual       无感 200 但无挑战特征、或信号冲突/连续失败 → 人工核验一次

用法:
    python Tool/skill/_pending/signin-automation/scripts/captcha-branch.py --response resp.json
    python Tool/skill/_pending/signin-automation/scripts/captcha-branch.py --feature image_base64 --attempts 2
    python Tool/skill/_pending/signin-automation/scripts/captcha-branch.py --self-test

退出码：0 正常；2 结构化失败（`{"ok": false, "blocked_at": ..., "reason": ...}`）。
"""

from __future__ import annotations

import argparse
import json
import re
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

SCHEMA = "seep.captcha-branch/1"
BRANCHES = ("ocr", "interactive", "manual")
FEATURE_KEYS = ("image_base64", "slider_token", "slide_token", "behavior_token",
                "challenge_type", "silent_200")
CHALLENGE_HINTS = ("captcha", "验证码", "验证", "geetest", "hcaptcha", "recaptcha",
                   "slide", "滑块", "verif", "challenge", "turnstile")
ABS_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|/|\\\\)")

BRANCH_ACTIONS = {
    "ocr": {
        "next_action": "下载/解码图片 → 本地 OCR 出字符 → 单次提交，失败即升级为 interactive",
        "retry": {"max_attempts": 2, "on_exhausted": "interactive"},
        "tooling": "本地 OCR（tesseract/paddle-ocr）；字符集先用已知样本校准",
    },
    "interactive": {
        "next_action": "取滑块/行为 token → 生成自然轨迹 → 校验 token 有效期后提交",
        "retry": {"max_attempts": 1, "on_exhausted": "manual"},
        "tooling": "轨迹发生器 + token 校验；同一 device_id 连续失败即停",
    },
    "manual": {
        "next_action": "人工核验一次：确认是否静默风控、记录 trace_id 与时间，再决定继续或换号",
        "retry": {"max_attempts": 0, "on_exhausted": "换号 + 冷却"},
        "tooling": "人工通道 + 证据留存（截图/响应体 hash）",
    },
}


def fail(blocked_at: str, reason: str, code: int = 2) -> int:
    print(json.dumps({"ok": False, "blocked_at": blocked_at, "reason": reason},
                     ensure_ascii=False))
    return code


def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def detect(response: dict) -> dict:
    """从响应事实里抽挑战特征；返回有序特征列表 + 证据。"""
    found = []
    evidence = {}

    image = response.get("image_base64") or response.get("image")
    if isinstance(image, str) and len(image) >= 64:
        found.append("image_base64")
        evidence["image_base64"] = {"length": len(image),
                                    "looks_png_b64": image[:8].startswith("iVBORw0K")}

    for key in ("slider_token", "slide_token", "behavior_token"):
        value = response.get(key)
        if isinstance(value, str) and value.strip():
            found.append("slider_token")
            evidence["slider_token"] = {"field": key, "length": len(value.strip())}
            break

    challenge_type = _text(response.get("challenge_type")).lower()
    if challenge_type:
        evidence["challenge_type"] = challenge_type[:40]

    body = _text(response.get("body")).lower()
    payload = _text(response.get("json")).lower()
    hits = sorted({hint for hint in CHALLENGE_HINTS if hint in body or hint in payload})
    if hits:
        evidence["keyword_hits"] = hits[:6]

    status = response.get("status")
    if status in (200, "200") and not found and not hits:
        found.append("silent_200")
        evidence["silent_200"] = {
            "status": 200,
            "json_keys": sorted(response["json"].keys())[:8]
            if isinstance(response.get("json"), dict) else [],
        }

    attempts = response.get("attempts")
    if isinstance(attempts, int):
        evidence["attempts"] = attempts
    return {"features": found, "evidence": evidence}


def decide(features, evidence: dict, attempts: int) -> dict:
    """优先级：图片 → ocr；滑块/token → interactive；其余 → manual。"""
    if attempts >= 3:
        return BRANCHES[2], "连续 %d 次未过，触发人工核验" % attempts
    if "image_base64" in features:
        return "ocr", "响应含图片挑战（base64），走本地识别"
    if "slider_token" in features:
        return "interactive", "响应含滑块/行为 token，走交互流程"
    if "silent_200" in features:
        return "manual", "200 且无挑战特征：可能是静默风控，人工确认一次"
    if evidence.get("keyword_hits"):
        return "manual", "命中挑战关键词但缺可执行特征（图片/token），人工确认"
    return BRANCHES[2], "特征不足以自动处置，转人工"


def build_branch(response: dict) -> dict:
    if not isinstance(response, dict):
        raise ValueError("response 必须是 JSON 对象")
    detected = detect(response)
    attempts = detected["evidence"].get("attempts", 0)
    branch, reason = decide(detected["features"], detected["evidence"], attempts)
    action = BRANCH_ACTIONS[branch]
    return {
        "ok": True,
        "schema": SCHEMA,
        "branch": branch,
        "confidence": "high" if detected["features"] else "low",
        "reason": reason,
        "next_action": action["next_action"],
        "retry": action["retry"],
        "tooling": action["tooling"],
        "features": detected["features"],
        "evidence": detected["evidence"],
        "branches_considered": list(BRANCHES),
        "network_requests": 0,
        "trace_id": _text(response.get("trace_id"))[:64] or None,
        "url": _text(response.get("url"))[:200] or None,
    }


def has_abs_path(value) -> bool:
    if isinstance(value, str):
        return bool(ABS_PATH_RE.match(value))
    if isinstance(value, dict):
        return any(has_abs_path(v) for v in value.values())
    if isinstance(value, list):
        return any(has_abs_path(v) for v in value)
    return False


def self_test() -> int:
    checks = []
    img = build_branch({"status": 200, "image_base64": "iVBORw0KGgo" + "A" * 80,
                        "attempts": 1})
    checks.append((img["branch"] == "ocr", "image -> ocr"))
    checks.append((img["retry"]["on_exhausted"] == "interactive", "ocr escalation"))
    slider = build_branch({"status": 200, "slider_token": "tok-" + "b" * 40, "attempts": 0})
    checks.append((slider["branch"] == "interactive", "slider -> interactive"))
    silent = build_branch({"status": 200, "json": {"code": 0}, "attempts": 0})
    checks.append((silent["branch"] == "manual", "silent 200 -> manual"))
    checks.append(("silent_200" in silent["features"], "silent feature recorded"))
    keyword = build_branch({"status": 403, "body": "请完成验证码", "attempts": 0})
    checks.append((keyword["branch"] == "manual", "keyword only -> manual"))
    tired = build_branch({"status": 200, "image_base64": "iVBORw0KGgo" + "A" * 80,
                          "attempts": 4})
    checks.append((tired["branch"] == "manual", "attempt cap -> manual"))
    checks.append((all(b in BRANCHES for b in (img["branch"], slider["branch"],
                                               silent["branch"])), "branch enum"))
    checks.append((img["network_requests"] == 0, "offline"))
    checks.append((not has_abs_path(img), "no abs path"))
    for passed, label in checks:
        if not passed:
            return fail("self-test", "assertion failed: %s" % label)
    print(json.dumps({"ok": True, "checks": len(checks), "tool": "captcha-branch.py",
                      "branches": list(BRANCHES)}, ensure_ascii=False))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="响应特征 → 验证码处置分支(ocr/interactive/manual) + next_action（离线）")
    ap.add_argument("--response", metavar="PATH", help="response.json（响应特征描述）")
    ap.add_argument("--feature", action="append", default=[],
                    help="直接给特征：image_base64 / slider_token / silent_200")
    ap.add_argument("--attempts", type=int, default=0, help="本账号本任务已尝试次数")
    ap.add_argument("--json-out", metavar="PATH", help="把结果写入文件")
    ap.add_argument("--self-test", action="store_true", help="离线自测")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if args.response:
        if ABS_PATH_RE.match(args.response):
            return fail("input", "response 必须用相对路径")
        try:
            with open(args.response, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            return fail("read", "读取/解析失败: %s" % str(exc)[:160])
    elif args.feature:
        payload = {"attempts": args.attempts}
        for feature in args.feature:
            if feature not in FEATURE_KEYS:
                return fail("input", "未知特征: %s（可选 %s）" % (feature, "/".join(FEATURE_KEYS)))
            payload[feature] = True
    else:
        ap.error("--response 或 --feature 至少给一个（或使用 --self-test）")
    try:
        res = build_branch(payload)
    except ValueError as exc:
        return fail("validate", str(exc)[:200])
    if args.json_out:
        if ABS_PATH_RE.match(args.json_out):
            return fail("input", "json-out 必须用相对路径")
        try:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(res, fh, ensure_ascii=False, indent=2)
        except OSError as exc:
            return fail("write", "JSON 写入失败: %s" % str(exc)[:160])
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
