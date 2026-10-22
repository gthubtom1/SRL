#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""session-pool.py -- 多账号凭据池：状态分级、并发/限速、失效标记、轮转计划。

只做本地编排：读 `accounts.json`（相对路径），产出每账号状态与下一个动作。
不发网络请求、不落 cookie 明文到日志（只打印掩码）。

输入 accounts.json:
    {
      "concurrency": 2,                 # 期望并发（可选）
      "global_rate_per_min": 20,        # 全池每分钟请求数（可选）
      "accounts": [
        {"id": "acc-1", "cookie": "sid=...", "token": "", "device_id": "..."},
        {"id": "acc-2", "token": "ey...", "expires_at": "2026-10-21T00:00:00Z"},
        {"id": "acc-3", "cookie": "sid=...", "blocked": true, "cooldown_s": 900}
      ]
    }

输出:
    {"ok": true, "schema": "seep.session-pool/1", "pool": {...}, "accounts": [...]}

用法:
    python Tool/skill/signin-automation/scripts/session-pool.py --accounts accounts.json
    python Tool/skill/signin-automation/scripts/session-pool.py --accounts accounts.json --concurrency 4 --rate 30
    python Tool/skill/signin-automation/scripts/session-pool.py --accounts accounts.json --now 2026-10-20T09:00:00Z --json-out pool.json
    python Tool/skill/signin-automation/scripts/session-pool.py --self-test

退出码：0 正常；2 结构化失败（`{"ok": false, "blocked_at": ..., "reason": ...}`）。
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

SCHEMA = "seep.session-pool/1"
STATUSES = ("ok", "expired", "blocked")
CRED_FIELDS = ("cookie", "token", "device_id")
ABS_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|/|\\\\)")


def fail(blocked_at: str, reason: str, code: int = 2) -> int:
    print(json.dumps({"ok": False, "blocked_at": blocked_at, "reason": reason},
                     ensure_ascii=False))
    return code


def parse_time(value, field: str):
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError("%s 必须是 ISO8601 字符串" % field)
    text = value.strip().replace("Z", "+00:00")
    try:
        stamp = dt.datetime.fromisoformat(text)
    except ValueError:
        raise ValueError("%s 不是合法 ISO8601: %s" % (field, value[:40]))
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.timezone.utc)
    return stamp.astimezone(dt.timezone.utc)


def mask(value: str) -> str:
    """凭据只留长度与首尾 2 字符，避免明文进日志。"""
    if not value:
        return ""
    if len(value) <= 6:
        return "*" * len(value)
    return "%s***%s(len=%d)" % (value[:2], value[-2:], len(value))


def normalize_account(raw, index: int):
    if not isinstance(raw, dict):
        raise ValueError("accounts[%d] 必须是对象" % index)
    account = {
        "id": str(raw.get("id") or "acc-%d" % (index + 1)),
        "cookie": str(raw.get("cookie") or ""),
        "token": str(raw.get("token") or ""),
        "device_id": str(raw.get("device_id") or ""),
        "blocked": bool(raw.get("blocked")),
        "cooldown_s": int(raw.get("cooldown_s") or 0),
        "expires_at": raw.get("expires_at"),
    }
    return account


def classify(account: dict, now: dt.datetime) -> dict:
    """三态判定：blocked > expired > ok。"""
    missing = [f for f in CRED_FIELDS if not account[f]]
    if account["blocked"]:
        return {
            "status": "blocked",
            "reason": "账号被目标站点标记（人工确认后解锁）",
            "invalid_fields": [],
            "invalidate": True,
            "next_action": "冷却 %ds 后换 device_id 重登；连续两次 blocked 转 manual" % (
                account["cooldown_s"] or 1800),
        }
    if not account["cookie"] and not account["token"]:
        return {
            "status": "expired",
            "reason": "cookie 与 token 均为空，无可用凭据",
            "invalid_fields": ["cookie", "token"],
            "invalidate": True,
            "next_action": "重新登录拿 cookie/token，再回填 accounts.json",
        }
    expires_at = parse_time(account["expires_at"], "expires_at")
    if expires_at is not None and expires_at <= now:
        return {
            "status": "expired",
            "reason": "expires_at 已过（%s）" % expires_at.isoformat(),
            "invalid_fields": ["token"],
            "invalidate": True,
            "next_action": "刷新 token（cron 任务失败重试上限内）",
        }
    notes = []
    if missing:
        notes.append("缺 %s（部分任务需要）" % ", ".join(missing))
    return {
        "status": "ok",
        "reason": "凭据齐全" + ("；" + "；".join(notes) if notes else ""),
        "invalid_fields": [],
        "invalidate": False,
        "next_action": "入队轮转，按 per-account 间隔发请求",
    }


def build_pool(payload, concurrency=None, rate=None, now=None) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("accounts.json 顶层必须是对象")
    raw_accounts = payload.get("accounts")
    if not isinstance(raw_accounts, list) or not raw_accounts:
        raise ValueError("accounts[] 必须是非空数组")
    now = now or dt.datetime.now(dt.timezone.utc)
    want_conc = int(concurrency or payload.get("concurrency") or 1)
    want_rate = int(rate or payload.get("global_rate_per_min") or 0)
    if want_conc < 1:
        raise ValueError("concurrency 必须 >= 1")
    if want_rate < 0:
        raise ValueError("global_rate_per_min 必须 >= 0")

    accounts = []
    for idx, raw in enumerate(raw_accounts):
        account = normalize_account(raw, idx)
        verdict = classify(account, now)
        accounts.append({
            "id": account["id"],
            "status": verdict["status"],
            "reason": verdict["reason"],
            "invalid_fields": verdict["invalid_fields"],
            "invalidate": verdict["invalidate"],
            "next_action": verdict["next_action"],
            "credential_masks": {
                "cookie": mask(account["cookie"]),
                "token": mask(account["token"]),
                "device_id": mask(account["device_id"]),
            },
            "cooldown_s": account["cooldown_s"] if verdict["status"] == "blocked" else 0,
        })

    ids = [a["id"] for a in accounts]
    if len(ids) != len(set(ids)):
        raise ValueError("账号 id 重复：%s" % ",".join(sorted({i for i in ids if ids.count(i) > 1})))

    ok_ids = [a["id"] for a in accounts if a["status"] == "ok"]
    expired_ids = [a["id"] for a in accounts if a["status"] == "expired"]
    blocked_ids = [a["id"] for a in accounts if a["status"] == "blocked"]
    effective_conc = min(want_conc, max(len(ok_ids), 1))
    interval = round(60.0 / want_rate, 3) if want_rate else None
    return {
        "ok": True,
        "schema": SCHEMA,
        "generated_at": now.isoformat(),
        "pool": {
            "total": len(accounts),
            "ok": len(ok_ids),
            "expired": len(expired_ids),
            "blocked": len(blocked_ids),
            "requested_concurrency": want_conc,
            "effective_concurrency": effective_conc,
            "global_rate_per_min": want_rate or None,
            "per_account_interval_s": interval,
            "rotation_order": ok_ids,
            "quarantine": expired_ids + blocked_ids,
            "invalidated": [a["id"] for a in accounts if a["invalidate"]],
        },
        "accounts": accounts,
        "self_check": {
            "network_requests": 0,
            "credential_plaintext_logged": False,
        },
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
    fixture = {
        "concurrency": 1,
        "global_rate_per_min": 12,
        "accounts": [
            {"id": "fake-ok", "cookie": "sid=fake", "token": "tk", "device_id": "dev-a"},
            {"id": "fake-expired", "cookie": "", "token": "",
             "expires_at": "2020-01-01T00:00:00Z"},
            {"id": "fake-blocked", "cookie": "sid=fake2", "token": "tk2",
             "blocked": True, "cooldown_s": 600},
            {"id": "fake-stale", "token": "tk3", "expires_at": "2020-01-01T00:00:00Z"},
        ],
    }
    now = dt.datetime(2026, 10, 20, 9, 0, 0, tzinfo=dt.timezone.utc)
    res = build_pool(fixture, concurrency=4, rate=24, now=now)
    checks = [
        (res["ok"] is True, "ok flag"),
        ([a["status"] for a in res["accounts"]] ==
         ["ok", "expired", "blocked", "expired"], "status classification"),
        (res["pool"]["ok"] == 1 and res["pool"]["expired"] == 2
         and res["pool"]["blocked"] == 1, "pool counters"),
        (res["pool"]["effective_concurrency"] == 1, "concurrency clamped to ok accounts"),
        (res["pool"]["per_account_interval_s"] == 2.5, "rate -> interval"),
        (res["pool"]["invalidated"] == ["fake-expired", "fake-blocked", "fake-stale"],
         "invalidation markers"),
        (res["accounts"][2]["cooldown_s"] == 600, "blocked cooldown kept"),
        (res["self_check"]["network_requests"] == 0, "offline"),
        (not has_abs_path(res["self_check"]), "no abs path"),
    ]
    for passed, label in checks:
        if not passed:
            return fail("self-test", "assertion failed: %s" % label)
    print(json.dumps({"ok": True, "checks": len(checks), "tool": "session-pool.py",
                      "fixture_accounts": len(fixture["accounts"])}, ensure_ascii=False))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="多账号凭据池：状态(ok/expired/blocked)、并发/限速、失效标记（离线）")
    ap.add_argument("--accounts", metavar="PATH", help="accounts.json（cookie/token/device_id）")
    ap.add_argument("--concurrency", type=int, help="覆盖期望并发")
    ap.add_argument("--rate", type=int, help="覆盖全池每分钟请求数")
    ap.add_argument("--now", help="固定当前时间（ISO8601，便于复算）")
    ap.add_argument("--json-out", metavar="PATH", help="把结果写入文件")
    ap.add_argument("--self-test", action="store_true", help="内置假账号离线自测")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not args.accounts:
        ap.error("--accounts 必填（或使用 --self-test）")
    if ABS_PATH_RE.match(args.accounts):
        return fail("input", "accounts 必须用相对路径，避免机器绑定")
    if not os.path.isfile(args.accounts):
        return fail("input", "accounts 文件不存在: %s" % args.accounts)
    try:
        with open(args.accounts, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return fail("read", "读取/解析失败: %s" % str(exc)[:160])
    try:
        res = build_pool(payload, concurrency=args.concurrency, rate=args.rate,
                         now=parse_time(args.now, "--now"))
    except (ValueError, TypeError) as exc:
        return fail("validate", str(exc)[:200])
    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(res, fh, ensure_ascii=False, indent=2)
        except OSError as exc:
            return fail("write", "JSON 写入失败: %s" % str(exc)[:160])
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
