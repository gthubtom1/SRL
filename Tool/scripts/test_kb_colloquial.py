#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_kb_colloquial.py —— 知识库「口语检索」验收（12 条大白话，可复跑）

为什么单开一个脚本：
    库里 400+ 篇战术笔记，但用户是拿大白话问的（"加壳了怎么脱"、"这软件要卡密怎么
    绕过"）。旧实现是整串子串匹配 → 这类问法必然 0 命中，模型只能回头问人。
    本脚本把"口语 → 命中哪篇"钉成回归：不看实现细节，只看用户原话能不能落到文章。

判据（全部从库内真实内容核对，不猜）：
    * 每条查询的**前 3 条命中**里必须出现期望路径片段（领域对得上）；
    * 命中的条目必须回显 matched_terms（靠哪些词命中），否则算模型无法判断可信度；
    * 命中 >= 10/12 才算过；缺 KB 目录 / 缺别名表 → 直接 rc=1（不许 skip 成 PASS）。

用法：
    python Tool/scripts/test_kb_colloquial.py             # 判定用
    python Tool/scripts/test_kb_colloquial.py --verbose   # 额外打印每条的前 3
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SERVER = os.path.join(ROOT, "Tool", "mcp", "seep_mcp_server.py")

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

# (用户原话, 期望命中的路径片段（任一即可）, 领域说明)
# 期望全部来自库内真实文章：改 KB 导致落空时，这里会红，而不是悄悄放过。
CORE_QUERIES = [
    ("加壳了怎么脱",
     ["05-crypto-unpack/01-pe-unpack-dump", "07-packer"], "PE/APK 脱壳"),
    ("这软件要卡密怎么绕过",
     ["license-keygen"], "授权/卡密验证"),
    ("apk 去广告",
     ["banner-ad-removal"], "APK 去广告"),
    ("改会员",
     ["payment-subscription", "payment-bypass", "payment-logic"], "会员/订阅逻辑"),
    ("反调试怎么过",
     ["anti-debug-bypass"], "反调试绕过"),
    ("证书校验怎么过",
     ["tls-pinning-unpinning", "ssl-pin-bypass"], "证书绑定 / SSL pinning"),
    ("签名校验怎么过",
     ["signature-integrity-bypass"], "签名/完整性校验"),
    ("固件解包",
     ["01-unpack-and-filesystem", "iot-firmware-uart"], "固件解包"),
    ("弱口令爆破",
     ["brute-force-tactics"], "弱口令/爆破"),
    ("串口怎么接",
     ["uart"], "串口/UART"),
    ("游戏透视",
     ["esp-wallhack"], "游戏透视/ESP"),
    ("依赖混淆",
     ["dependency-confusion"], "供应链/依赖混淆"),
]

# 扩展覆盖（只报不计分）：证明别名表不是只对上面 12 句生效
EXTRA_QUERIES = [
    ("内存dump", ["memprocfs", "unpack-dump"], "内存转储"),
    ("域控", ["ad-cloud"], "域渗透"),
    ("提权", ["privesc"], "提权"),
    ("勒索软件", ["triage-and-ioc"], "恶意样本分析"),
    ("怎么过waf", ["waf-and-bypass"], "WAF 绕过"),
    ("越狱检测", ["jailbreak"], "iOS 越狱/root 检测"),
]

THRESHOLD = 10  # 命中 >=10/12 才过


def load_server():
    spec = importlib.util.spec_from_file_location("seep_mcp_server", SERVER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def search(mod, query, limit=5):
    """调用检索并解析；返回 (hits, raw)。"""
    fn = getattr(mod.seep_kb_search, "fn", mod.seep_kb_search)
    raw = fn(query, limit=limit)
    try:
        data = json.loads(raw)
    except Exception:  # noqa: BLE001
        return [], str(raw)
    if isinstance(data, dict):          # 空结果 → near_miss 结构
        return [], data
    return data, data


def eval_query(mod, query, expect_any, verbose=False):
    hits, raw = search(mod, query)
    top = hits[:3]
    paths = [h.get("path", "") for h in hits]
    hit = any(any(frag in p for frag in expect_any) for p in paths[:3])
    trust = bool(top) and all(h.get("matched_terms") for h in top[:1])
    if verbose:
        print("      top3: %s" % (paths[:3] or "[空]"))
        if top:
            print("      matched_terms: %s" % top[0].get("matched_terms"))
    return hit and trust, paths[:3], raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true", help="打印每条查询的前 3 条命中")
    args = ap.parse_args()

    # 依赖在不在：缺一即红，绝不 skip 成 PASS
    if not os.path.isdir(os.path.join(ROOT, "Tool", "mcp", "Tool", "reverselab", "kb")):
        print("[FAIL] KB 目录不存在：Tool/mcp/Tool/reverselab/kb")
        return 1
    if not os.path.isfile(SERVER):
        print("[FAIL] MCP 服务端不存在：%s" % SERVER)
        return 1

    mod = load_server()
    kb_dir = getattr(mod, "KB_DIR", "")
    # The shared contract owns the loader; its private constants are not server exports.
    # Check the actual source asset, then exercise the real imported loader and queries.
    syn_path = os.path.join(ROOT, "Tool", "config", "kb-synonyms.json")
    if not kb_dir or not os.path.isdir(kb_dir):
        print("[FAIL] 服务端 KB_DIR 不可用：%r" % kb_dir)
        return 1
    n_docs = len(mod._kb_article_paths()) if hasattr(mod, "_kb_article_paths") else 0
    if not syn_path or not os.path.isfile(syn_path):
        print("[FAIL] 别名表缺失：%s（seep_kb_search 退化后口语必归零）" % (syn_path or "?"))
        return 1
    groups, _sw = mod._kb_load_synonyms()
    n_say = sum(len(g.get("say", [])) for g in groups)
    if len(groups) < 40:
        print("[FAIL] 别名表只有 %d 组（要求 >=40 组高频口语）" % len(groups))
        return 1

    print("KB: %s（%d 篇）" % (os.path.relpath(kb_dir, ROOT).replace(os.sep, "/"), n_docs))
    print("别名表: %s（%d 组 / %d 个口语说法）"
          % (os.path.relpath(syn_path, ROOT).replace(os.sep, "/"), len(groups), n_say))
    print("")

    passed = 0
    failures = []
    for query, expect_any, domain in CORE_QUERIES:
        ok, paths, _raw = eval_query(mod, query, expect_any, args.verbose)
        if ok:
            passed += 1
        else:
            failures.append((query, domain, paths))
        print("  [%s] %-14s (%s) -> %s"
              % ("PASS" if ok else "FAIL", query, domain,
                 paths[0] if paths else "0 命中"))

    print("")
    # 空结果不许只回"未命中"：随机乱码也必须有 3 条近邻 + 为什么近
    _hits, raw = search(mod, "zzqqzz qwvb", limit=5)
    near = raw.get("near_miss") if isinstance(raw, dict) else None
    near_ok = isinstance(raw, dict) and bool(raw.get("hits") == []) and isinstance(near, list) \
        and len(near) == 3 and all(x.get("why") and x.get("read") for x in near)
    print("  [%s] 空结果给 3 条近邻 + 为什么近" % ("PASS" if near_ok else "FAIL"))
    if near:
        print("       例：%s" % near[0].get("why"))

    extra_ok = 0
    for query, expect_any, domain in EXTRA_QUERIES:
        ok, paths, _raw = eval_query(mod, query, expect_any, args.verbose)
        extra_ok += 1 if ok else 0
        if not ok:
            print("  [INFO] 扩展未命中：%s (%s) -> %s" % (query, domain, paths[:2] or "0 命中"))

    print("")
    print("命中 %d/%d（门槛 >=%d/%d）" % (passed, len(CORE_QUERIES), THRESHOLD, len(CORE_QUERIES)))
    print("扩展覆盖 %d/%d（只报不计分：证明别名表对新说法也生效）"
          % (extra_ok, len(EXTRA_QUERIES)))
    if failures:
        print("未命中：")
        for query, domain, paths in failures:
            print("  - %s（%s）-> 实得 %s" % (query, domain, paths or "0 命中"))
    print("结果: 命中 %d/%d（门槛 >=%d/%d）；扩展 %d/%d；空结果近邻 %s"
          % (passed, len(CORE_QUERIES), THRESHOLD, len(CORE_QUERIES),
             extra_ok, len(EXTRA_QUERIES), "PASS" if near_ok else "FAIL"))

    return 0 if (passed >= THRESHOLD and near_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
