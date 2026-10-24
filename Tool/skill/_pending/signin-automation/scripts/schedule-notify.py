#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""schedule-notify.py -- 调度与通知载荷生成：cron 校验/生成、幂等键、重试上限、渠道模板。

只生成计划与载荷字符串，**不发网络请求**（渠道 URL 是模板，不是可执行动作）。

能力：
  1. cron  五段表达式校验 + 人类可读解释 + 时区提示
  2. 幂等键 `date|account|task`（sha1 前 16 位），同一天同账号同任务只发一次
  3. 重试策略：上限、退避序列、触发人工的阈值
  4. 通知载荷：telegram / dingtalk / wecom 三种 URL 模板 + body 骨架

用法:
    python Tool/skill/_pending/signin-automation/scripts/schedule-notify.py --validate-cron "0 9 * * 1-5"
    python Tool/skill/_pending/signin-automation/scripts/schedule-notify.py --task daily-signin \\
        --accounts acc-1,acc-2 --cron "30 8 * * *" --channel telegram --retries 2
    python Tool/skill/_pending/signin-automation/scripts/schedule-notify.py --self-test

退出码：0 正常；2 结构化失败（`{"ok": false, "blocked_at": ..., "reason": ...}`）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

SCHEMA = "seep.schedule-notify/1"
CHANNELS = ("telegram", "dingtalk", "wecom")
DOW_NAMES = ["周日", "周一", "周二", "周三", "周四", "周五", "周六"]
ABS_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|/|\\\\)")

FIELD_RANGES = [
    ("minute", 0, 59),
    ("hour", 0, 23),
    ("day-of-month", 1, 31),
    ("month", 1, 12),
    ("day-of-week", 0, 7),
]

STEP_RE = re.compile(r"^(?:\*|\d+(?:-\d+)?)(?:/\d+)?$")


def fail(blocked_at: str, reason: str, code: int = 2) -> int:
    print(json.dumps({"ok": False, "blocked_at": blocked_at, "reason": reason},
                     ensure_ascii=False))
    return code


def describe_part(part: str, name: str, lo: int, hi: int) -> str:
    if part == "*":
        return "%s 任意" % name
    if "/" in part:
        base, step = part.split("/", 1)
        step_n = int(step)
        if step_n <= 0:
            raise ValueError("%s 的步长必须 > 0: %s" % (name, part))
        if base == "*":
            return "%s 每 %d" % (name, step_n)
        start, end = (int(base), hi) if "-" in base else (int(base), int(base))
        if start < lo or end > hi:
            raise ValueError("%s 超出范围 %d-%d: %s" % (name, lo, hi, part))
        return "%s 从 %d 到 %d 每 %d" % (name, start, end, step_n)
    if "-" in part:
        start, end = part.split("-", 1)
        start_n, end_n = int(start), int(end)
        if start_n < lo or end_n > hi or start_n > end_n:
            raise ValueError("%s 区间非法 %d-%d: %s" % (name, lo, hi, part))
        return "%s %d-%d" % (name, start_n, end_n)
    value = int(part)
    if value < lo or value > hi:
        raise ValueError("%s 超出范围 %d-%d: %s" % (name, lo, hi, part))
    return "%s=%d" % (name, value)


def validate_cron(expr: str) -> dict:
    if not isinstance(expr, str) or not expr.strip():
        raise ValueError("cron 表达式为空")
    parts = expr.split()
    if len(parts) != 5:
        raise ValueError("cron 必须是 5 段（分 时 日 月 周），实际 %d 段" % len(parts))
    human = []
    for part, (name, lo, hi) in zip(parts, FIELD_RANGES):
        if not STEP_RE.match(part) and not re.match(r"^\d+(-\d+)?(,\d+(-\d+)?)*$", part):
            raise ValueError("%s 段含非法字符: %s" % (name, part))
        if "," in part:
            for chunk in part.split(","):
                if not STEP_RE.match(chunk) and not re.match(r"^\d+(-\d+)?$", chunk):
                    raise ValueError("%s 列表项非法: %s" % (name, chunk))
            human.append("%s 取 %s" % (name, part))
            continue
        human.append(describe_part(part, name, lo, hi))
    dow = parts[4]
    if dow != "*":
        days = set()
        for chunk in dow.split(","):
            if "-" in chunk:
                a, b = chunk.split("-")
                days.update(range(int(a) % 7, (int(b) % 7) + 1))
            else:
                days.add(int(chunk) % 7)
        if days and len(days) <= 5:
            human.append("仅 %s" % ",".join(DOW_NAMES[d % 7] for d in sorted(days)))
    return {
        "expr": " ".join(parts),
        "fields": parts,
        "human": "；".join(human),
        "timezone_hint": "按调度器本地时区解释；跨机部署时统一写 TZ 或改用 UTC",
        "warnings": ["日与周同时受限时，多数实现取『或』语义，需在调度器侧确认"]
        if parts[2] != "*" and parts[4] != "*" else [],
    }


def idempotency_key(date: str, account: str, task: str) -> str:
    if not date or not account or not task:
        raise ValueError("幂等键需要 date/account/task 三者齐全")
    raw = "%s|%s|%s" % (date.strip(), account.strip(), task.strip())
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
    return "%s-%s" % (date.strip(), digest)


def channel_template(channel: str) -> dict:
    if channel == "telegram":
        return {
            "url_template": "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage",
            "method": "POST",
            "content_type": "application/json",
            "body_skeleton": {"chat_id": "${TELEGRAM_CHAT_ID}", "text": "${MESSAGE}",
                              "disable_web_page_preview": True},
            "secret_names": ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"],
            "rate_limit": "每秒 1 条，同 chat 每分钟 ≤20 条",
        }
    if channel == "dingtalk":
        return {
            "url_template":
                "https://oapi.dingtalk.com/robot/send?access_token=${DINGTALK_TOKEN}",
            "method": "POST",
            "content_type": "application/json",
            "body_skeleton": {"msgtype": "text", "text": {"content": "${MESSAGE}"},
                              "at": {"isAtAll": False}},
            "secret_names": ["DINGTALK_TOKEN", "DINGTALK_SECRET"],
            "rate_limit": "每分钟 20 条；加签时 timestamp+secret 排序后再 HMAC",
        }
    if channel == "wecom":
        return {
            "url_template":
                "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=${WECOM_KEY}",
            "method": "POST",
            "content_type": "application/json",
            "body_skeleton": {"msgtype": "text", "text": {"content": "${MESSAGE}"}},
            "secret_names": ["WECOM_KEY"],
            "rate_limit": "每个机器人每分钟 20 条",
        }
    raise ValueError("未知渠道: %s（可选 %s）" % (channel, "/".join(CHANNELS)))


def build_plan(task: str, accounts, cron: str, channel: str, retries: int,
               start_date: str) -> dict:
    if not task:
        raise ValueError("--task 必填")
    accounts = [a.strip() for a in accounts if a.strip()]
    if not accounts:
        raise ValueError("--accounts 至少要一个账号 id")
    if retries < 0 or retries > 5:
        raise ValueError("--retries 必须落在 0-5（超过 5 次转人工）")
    schedule = validate_cron(cron)
    template = channel_template(channel)
    jobs = []
    for account in accounts:
        jobs.append({
            "task": task,
            "account": account,
            "cron": schedule["expr"],
            "idempotency_key": idempotency_key(start_date, account, task),
            "dedupe_scope": "date+account+task",
            "retry": {
                "max_attempts": retries + 1,
                "backoff_s": [60 * (2 ** i) for i in range(retries)],
                "escalate_after": retries + 1,
                "on_exhausted": "标记账号 manual，写回 accounts.json 的 blocked 之外的 quarantine 列表",
            },
            "notify": {
                "channel": channel,
                "send_on": ["success", "failure"],
                "payload": dict(template["body_skeleton"]),
                "url_template": template["url_template"],
                "secret_names": template["secret_names"],
            },
        })
    return {
        "ok": True,
        "schema": SCHEMA,
        "dry_run": True,
        "network_requests": 0,
        "schedule": schedule,
        "jobs": jobs,
        "channel": channel,
        "rate_limit": template["rate_limit"],
        "delivery_order": "按 jobs[].account 顺序串行，失败不阻塞后续账号",
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
    good = validate_cron("30 8 * * 1-5")
    checks.append((good["expr"] == "30 8 * * 1-5", "cron normalized"))
    checks.append(("仅" in good["human"], "cron human readable"))
    key_a = idempotency_key("2026-10-20", "acc-1", "daily")
    key_b = idempotency_key("2026-10-20", "acc-1", "daily")
    key_c = idempotency_key("2026-10-21", "acc-1", "daily")
    checks.append((key_a == key_b and key_a != key_c, "idempotency stable/date-scoped"))
    bad = ["", "* * * *", "61 * * * *", "*/0 * * * *", "* * * * 9", "* * * * 1-2-3"]
    rejected = 0
    for expr in bad:
        try:
            validate_cron(expr)
        except ValueError:
            rejected += 1
    checks.append((rejected == len(bad), "invalid cron rejected"))
    for channel in CHANNELS:
        tpl = channel_template(channel)
        checks.append((tpl["url_template"].startswith("https://")
                       and "${" in tpl["url_template"], "template %s" % channel))
    plan = build_plan("daily-signin", ["acc-1", "acc-2"], "0 9 * * *", "wecom", 2,
                      "2026-10-20")
    checks.append((len(plan["jobs"]) == 2, "job per account"))
    checks.append((plan["jobs"][0]["retry"]["max_attempts"] == 3, "retry cap"))
    checks.append((plan["dry_run"] is True and plan["network_requests"] == 0, "offline"))
    checks.append((not has_abs_path(plan), "no abs path"))
    try:
        build_plan("x", ["a"], "0 9 * * *", "carrier-pigeon", 1, "2026-10-20")
        checks.append((False, "unknown channel rejected"))
    except ValueError:
        checks.append((True, "unknown channel rejected"))
    for passed, label in checks:
        if not passed:
            return fail("self-test", "assertion failed: %s" % label)
    print(json.dumps({"ok": True, "checks": len(checks), "tool": "schedule-notify.py",
                      "channels": list(CHANNELS)}, ensure_ascii=False))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="cron 校验/生成 + 幂等键 + 重试上限 + 通知载荷模板（离线，不发请求）")
    ap.add_argument("--task", help="任务名，如 daily-signin")
    ap.add_argument("--accounts", help="逗号分隔的账号 id")
    ap.add_argument("--cron", help="五段 cron 表达式")
    ap.add_argument("--channel", default="telegram", choices=CHANNELS, help="通知渠道")
    ap.add_argument("--retries", type=int, default=2, help="重试次数上限 0-5")
    ap.add_argument("--start-date", default="2026-10-20", help="幂等键的日期（YYYY-MM-DD）")
    ap.add_argument("--validate-cron", metavar="EXPR", help="只校验 cron 并输出解释")
    ap.add_argument("--json-out", metavar="PATH", help="把计划写入文件")
    ap.add_argument("--self-test", action="store_true", help="离线自测")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    try:
        if args.validate_cron is not None:
            res = {"ok": True, "schema": SCHEMA, "schedule": validate_cron(args.validate_cron)}
        else:
            if not args.task or not args.accounts or not args.cron:
                ap.error("需要 --task --accounts --cron（或用 --validate-cron / --self-test）")
            res = build_plan(args.task, args.accounts.split(","), args.cron,
                             args.channel, args.retries, args.start_date)
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
