#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kb_acceptance.py —— 知识库检索 8 条验收（纯标准库，独立于 verify 项数）

为什么单独一个脚本而不塞进 verify.ps1：
体检项数量被写进了 5 处文档（三份 README 徽章 + BASELINE-FREEZE + CHECKLIST），
每加一项就是一次链式改动。检索质量属于"能力验收"，用独立脚本 + 退出码即可。

用法：
    python Tool/scripts/kb_acceptance.py            # 全跑，exit 0 = 全过
    python Tool/scripts/kb_acceptance.py --verbose  # 打印每次查询的 top3
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
    except Exception:
        pass


def load_server():
    spec = importlib.util.spec_from_file_location("seep_mcp_server", SERVER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def search(mod, query, limit=5):
    out = mod.seep_kb_search(query, limit=limit)
    try:
        data = json.loads(out)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def first_path(hits):
    return hits[0]["path"] if hits else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    mod = load_server()
    results = []

    def check(name, ok, detail=""):
        results.append((name, bool(ok), detail))
        print(("  [PASS] " if ok else "  [FAIL] ") + name + (("  -> " + detail) if detail and not ok else ""))

    # 1-4：多词查询必须命中反作弊篇（原来整串匹配必然归零）
    for q in ("完整性校验 反作弊", "反作弊 bypass", "EAC ObRegisterCallbacks"):
        hits = search(mod, q)
        top = first_path(hits)
        if args.verbose:
            print(f"    {q!r} -> {[h['path'] for h in hits[:3]]}")
        check(f"多词检索命中: {q}", "cheating/04-anti-cheat-bypass" in top, top or "0 命中")

    # 4b：eac crc 只要求进前 3 —— attack-network 是合法路由图，同样含 EAC/CRC
    hits = search(mod, "eac crc")
    paths = [h["path"] for h in hits[:3]]
    check("多词检索命中: eac crc (前3)", any("cheating/04-anti-cheat-bypass" in p for p in paths), str(paths))

    # 5：vmp 脱壳 必须同时覆盖 PE 与 APK 两侧
    hits = search(mod, "vmp 脱壳", limit=10)
    paths = [h["path"] for h in hits]
    if args.verbose:
        print(f"    'vmp 脱壳' -> {paths[:5]}")
    # 归档（_archive/pe-reverse/）仍是 PE 知识，计入 PE 侧覆盖；否则一归档验收就假红。
    check("vmp 脱壳 覆盖 PE 侧",
          any(p.startswith("pe-reverse/") or p.startswith("_archive/pe-reverse/") for p in paths),
          str(paths[:4]))
    check("vmp 脱壳 覆盖 APK 侧", any(p.startswith("apk-reverse/") for p in paths), str(paths[:4]))

    # 6：单词查询的标题加权（"反作弊"必须压过同族噪音篇，靠 title 命中）
    hits = search(mod, "反作弊", limit=5)
    top = first_path(hits)
    if args.verbose:
        print(f"    '反作弊' -> {[h['path'] for h in hits[:3]]}")
    check("单词查询排序: 反作弊 top1 正确", "cheating/04-anti-cheat-bypass" in top, top or "0 命中")

    # 7：单字 + 长词混合时，长词必须主导（"壳 vmp" 不能被单字噪音淹没）
    hits = search(mod, "壳 vmp", limit=5)
    top = first_path(hits)
    if args.verbose:
        print(f"    '壳 vmp' -> {[h['path'] for h in hits[:3]]}")
    check("长词权重高于单字: 壳 vmp", ("vmp" in top.lower()), top or "0 命中")

    # 8：snippet 必须包含查询词（命中位置居中，而不是文件开头 300 字）
    hits = search(mod, "完整性校验 反作弊")
    if hits:
        snip = hits[0].get("snippet", "")
        check("snippet 命中位置居中", ("完整性校验" in snip) or ("反作弊" in snip), snip[:80])
    else:
        check("snippet 命中位置居中", False, "0 命中")

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"\n结果: {passed}/{total} 通过")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
