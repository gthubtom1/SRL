#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tls-fingerprint.py -- 目标 URL + 期望 JA3/JA4 → 请求计划（curl_cffi impersonate / 头序 / H2）。

只生成计划：不联网、不握手、不发请求。真正的指纹比对发生在执行侧（curl_cffi + 抓包）。

输入：
    --url https://target.example/api/login
    --client chrome|firefox|safari|edge|random   （目标浏览器族）
    --ja3 <32hex 或 MD5>                          （目标侧期望值，可选）
    --ja4 t13d...                                 （目标侧期望值，可选）
    --http 2|1.1                                  （强制协议，可选）

输出：curl_cffi impersonate 目标、curl_cffi 版本下限、header 顺序、ALPN、验证步骤。
若给定 JA3/JA4 与所选 profile 的已知前缀不匹配 → `needs_profile_adjust` + 建议档位。

用法:
    python Tool/skill/_pending/signin-automation/scripts/tls-fingerprint.py --url https://target.example/
    python Tool/skill/_pending/signin-automation/scripts/tls-fingerprint.py --url https://h.example/ \
        --client chrome --ja4 t13d1516h2_8daaf6152771_02713d6af862
    python Tool/skill/_pending/signin-automation/scripts/tls-fingerprint.py --self-test

退出码：0 正常；2 结构化失败（`{"ok": false, "blocked_at": ..., "reason": ...}`）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from urllib.parse import urlsplit

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

SCHEMA = "seep.tls-fingerprint/1"
ABS_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|/(?:home|Users|etc|var|tmp|opt|mnt|root|usr)/)")
JA3_HEX_RE = re.compile(r"^[0-9a-f]{32}$", re.I)
JA4_RE = re.compile(r"^t(?:12|13)[a-z0-9]{2,10}_[0-9a-f]{12}_[0-9a-f]{12}$", re.I)

COMMON_HEADERS = [
    ("user-agent", "${UA_BY_PROFILE}"),
    ("sec-ch-ua", "${SEC_CH_UA}"),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", "${PLATFORM}"),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("accept-language", "zh-CN,zh;q=0.9,en;q=0.8"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-dest", "document"),
]

PROFILES = {
    "chrome": {
        "impersonate": ["chrome124", "chrome120", "chrome110"],
        "curl_cffi_min": "0.7.0",
        "http2": True,
        "alpn": ["h2", "http/1.1"],
        "ja4_prefixes": ["t13d1516h2", "t13d1517h2", "t13d1715h2"],
        "header_order": [h for h, _ in COMMON_HEADERS],
        "cipher_note": "GREASE + AES128-GCM 优先；不要手改 cipher 列表，交给 impersonate",
        "ua_family": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    },
    "edge": {
        "impersonate": ["edge101", "chrome124"],
        "curl_cffi_min": "0.7.0",
        "http2": True,
        "alpn": ["h2", "http/1.1"],
        "ja4_prefixes": ["t13d1516h2", "t13d2014h2"],
        "header_order": [h for h, _ in COMMON_HEADERS],
        "cipher_note": "Edge 与同版本 Chrome 近似；优先 chrome124 档位",
        "ua_family": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    },
    "firefox": {
        "impersonate": ["firefox133", "firefox102"],
        "curl_cffi_min": "0.6.0",
        "http2": True,
        "alpn": ["h2", "http/1.1"],
        "ja4_prefixes": ["t13d1715h2", "t13d1717h2"],
        "header_order": ["user-agent", "accept", "accept-language", "accept-encoding",
                         "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"],
        "cipher_note": "Firefox 无 sec-ch-ua；带 sec-ch-ua 反而暴露",
        "ua_family": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) "
                     "Gecko/20100101 Firefox/133.0",
    },
    "safari": {
        "impersonate": ["safari17_0", "safari15_5"],
        "curl_cffi_min": "0.6.2",
        "http2": True,
        "alpn": ["h2", "http/1.1"],
        "ja4_prefixes": ["t13d2014h2", "t13d1811h2"],
        "header_order": ["user-agent", "accept", "accept-language", "accept-encoding"],
        "cipher_note": "Safari 的 cipher 顺序与 Chrome 差异明显；勿复用 chrome 档位",
        "ua_family": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                     "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    },
    "random": {
        "impersonate": ["random"],
        "curl_cffi_min": "0.7.0",
        "http2": True,
        "alpn": ["h2", "http/1.1"],
        "ja4_prefixes": [],
        "header_order": [h for h, _ in COMMON_HEADERS],
        "cipher_note": "random 每请求换档位；只在无指纹基线时用，不利于稳定复现",
        "ua_family": "${RANDOM}",
    },
}


def fail(blocked_at: str, reason: str, code: int = 2) -> int:
    print(json.dumps({"ok": False, "blocked_at": blocked_at, "reason": reason},
                     ensure_ascii=False))
    return code


def parse_target(url: str) -> dict:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("url 为空")
    parts = urlsplit(url.strip())
    if parts.scheme not in ("https", "http"):
        raise ValueError("url 必须是 http(s):// 开头")
    if parts.scheme == "http":
        raise ValueError("http 无 TLS 指纹可对齐；目标站点必须走 https")
    if not parts.hostname:
        raise ValueError("url 缺 hostname")
    return {
        "url": url.strip(),
        "scheme": parts.scheme,
        "host": parts.hostname,
        "port": parts.port or 443,
        "path": parts.path or "/",
        "sni": parts.hostname,
    }


def check_ja(ja3, ja4, profile) -> dict:
    notes = []
    if ja3:
        if not JA3_HEX_RE.match(ja3.strip()) and not re.match(r"^[0-9a-f]{32}$", ja3.strip(), re.I):
            raise ValueError("ja3 需为 32 位十六进制（JA3 原文 MD5）")
        notes.append("ja3 给定时需在执行侧用 tshark/curl_cffi 抓 ClientHello 复算，再与目标比对")
    if ja4:
        if not JA4_RE.match(ja4.strip()):
            raise ValueError("ja4 格式非法，期望 t13dXXXXh2_<12hex>_<12hex>")
        prefix = ja4.split("_")[0]
        known = profile["ja4_prefixes"]
        if known and not any(prefix.lower().startswith(p.lower()) for p in known):
            return {
                "status": "needs_profile_adjust",
                "expected_ja4": ja4,
                "profile_prefixes": known,
                "suggestion": "换档位：%s" % ", ".join(profile["impersonate"]),
                "note": "前缀不匹配说明该浏览器族/版本档位与目标不符，先小流量试握手再放大",
            }
        notes.append("ja4 前缀与所选档位一致，仍需一次实抓确认")
    return {"status": "plan_ready" if not notes else "verify_after_request", "notes": notes}


def build_plan(url: str, client: str = "chrome", ja3=None, ja4=None, http=None) -> dict:
    if client not in PROFILES:
        raise ValueError("未知 client: %s（可选 %s）" % (client, "/".join(PROFILES)))
    target = parse_target(url)
    profile = PROFILES[client]
    ja = check_ja(ja3, ja4, profile)
    http2 = profile["http2"]
    if http is not None:
        if str(http) not in ("2", "1.1"):
            raise ValueError("--http 只接受 2 或 1.1")
        http2 = str(http) == "2"
    headers = [{"name": n, "value": v} for n, v in COMMON_HEADERS
               if n in profile["header_order"]]
    return {
        "ok": True,
        "schema": SCHEMA,
        "network_requests": 0,
        "target": target,
        "plan": {
            "library": "curl_cffi",
            "import": "from curl_cffi import requests",
            "impersonate": profile["impersonate"][0],
            "impersonate_fallbacks": profile["impersonate"][1:],
            "curl_cffi_min_version": profile["curl_cffi_min"],
            "http2": http2,
            "alpn": profile["alpn"],
            "sni": target["sni"],
            "verify_tls": True,
            "header_order": [h["name"] for h in headers],
            "headers": headers,
            "ua_family": profile["ua_family"],
            "cipher_note": profile["cipher_note"],
            "timeout_s": 15,
            "proxy_slot": "${OPTIONAL_PROXY}",
        },
        "fingerprint_check": {
            "expected_ja3": ja3,
            "expected_ja4": ja4,
            "profile_prefixes": profile["ja4_prefixes"],
            "verdict": ja,
            "capture_cmd_template": "tshark -i <iface> -f 'tcp port 443' "
                                    "-Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja3",
            "compare": "执行侧抓一次 ClientHello，复算 JA3/JA4 后与期望值比对",
        },
        "steps": [
            "1) 固定 impersonate 档位，关闭 UA/头手工覆盖（只保留必要业务头）",
            "2) 单请求抓包确认 JA3/JA4 与目标基线一致",
            "3) 再叠加业务头（token/device_id），避免头序污染指纹",
            "4) 失败时只改一个变量（档位 或 http2），保证可归因",
        ],
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
    plan = build_plan("https://target.example/api/login", "chrome")
    checks.append((plan["ok"] is True, "ok flag"))
    checks.append((plan["plan"]["impersonate"] == "chrome124", "chrome profile"))
    checks.append((plan["plan"]["http2"] is True, "http2 on"))
    checks.append((plan["plan"]["header_order"][0] == "user-agent", "header order"))
    checks.append((plan["target"]["port"] == 443, "default port"))
    checks.append((plan["network_requests"] == 0, "offline"))
    ff = build_plan("https://target.example/", "firefox", http="1.1")
    checks.append((ff["plan"]["http2"] is False, "http1.1 override"))
    checks.append(("sec-ch-ua" not in ff["plan"]["header_order"], "firefox drops sec-ch-ua"))
    adj = build_plan("https://target.example/", "firefox",
                     ja4="t13d1516h2_8daaf6152771_02713d6af862")
    checks.append((adj["fingerprint_check"]["verdict"]["status"] == "needs_profile_adjust",
                   "ja4 mismatch flagged"))
    ok_ja4 = build_plan("https://target.example/", "chrome",
                        ja4="t13d1516h2_8daaf6152771_02713d6af862")
    checks.append((ok_ja4["fingerprint_check"]["verdict"]["status"] != "needs_profile_adjust",
                   "ja4 match accepted"))
    bad = 0
    for kwargs in ({"url": "ftp://x/"}, {"url": "http://x/"}, {"url": "https://x/",
                                                                  "client": "netscape"},
                   {"url": "https://x/", "ja4": "bogus"}):
        try:
            build_plan(**kwargs)
        except ValueError:
            bad += 1
    checks.append((bad == 4, "invalid inputs rejected"))
    checks.append((not has_abs_path(plan), "no abs path"))
    for passed, label in checks:
        if not passed:
            return fail("self-test", "assertion failed: %s" % label)
    print(json.dumps({"ok": True, "checks": len(checks), "tool": "tls-fingerprint.py",
                      "profiles": sorted(PROFILES)}, ensure_ascii=False))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="目标 URL + 期望 JA3/JA4 → curl_cffi 请求计划（离线，不握手）")
    ap.add_argument("--url", help="目标 https URL")
    ap.add_argument("--client", default="chrome", help="chrome|edge|firefox|safari|random")
    ap.add_argument("--ja3", help="期望 JA3（32 位十六进制）")
    ap.add_argument("--ja4", help="期望 JA4（t13d..._12hex_12hex）")
    ap.add_argument("--http", help="强制协议：2 或 1.1")
    ap.add_argument("--json-out", metavar="PATH", help="把计划写入文件")
    ap.add_argument("--self-test", action="store_true", help="离线自测")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not args.url:
        ap.error("--url 必填（或使用 --self-test）")
    try:
        res = build_plan(args.url, args.client, args.ja3, args.ja4, args.http)
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
