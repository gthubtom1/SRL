#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mcp-guard.py —— 「上游 MCP 服务端只许扩展、不许删改」的可执行闸。

为什么要它（审计发现）：
    项目最高原则写的是「`Tool/mcp/seep_mcp_server.py` 净删除 0 行（纯追加）」，
    但此前**没有任何脚本能验证**：
      · `fork-delta.py` 只比文件级 A/M/D，且跳过 `Tool/upstream/`；
      · `check-budget.py` 只查总行数上限；
      · 本机是 shallow clone + 没有 `upstream` ref → 连 diff 都跑不了。
    结果就是这条原则只活在两份文档的承诺里。

边界说明（诚实声明）：
    本闸校验的是「**自基线快照起只增不减**」（工具名不消失、数量不下降、扩展标记成对）。
    它**不能**回溯证明"相对上游源码净删除 0 行"——那需要 `upstream/main` ref 与行级 diff；
    本机是 shallow clone、无 upstream remote 时无法计算（`fork-delta.py` 亦如此）。要行级复核：
    `git remote add upstream <origin> && git fetch upstream && git diff upstream/main -- Tool/mcp/seep_mcp_server.py`。

它怎么查（不依赖 git、不依赖网络）：
    1. 基线快照 `Tool/mcp/.baseline/tools.json`：记录工具名清单与数量（首次 `--baseline` 生成）；
    2. 现文件里解析 `@server.tool()` 装饰的函数名；
    3. 断言：基线里的工具**一个都不许消失**；数量只许多不许少；
    4. 断言：扩展块标记 `SEEP-EXT` 的 BEGIN/END 成对（防止有人手改后忘了收尾）；
    5. 断言：`def seep_*` 里不存在 `raise NotImplementedError` 之类的"假实现占位"。

用法：
    python Tool/skill/softseep/scripts/mcp-guard.py            # 校验（CI/preflight 用），违反则 exit 1
    python Tool/skill/softseep/scripts/mcp-guard.py --baseline # 重新生成基线（只在确认上游同步后做）
    python Tool/skill/softseep/scripts/mcp-guard.py --json
"""
from __future__ import annotations

# Shared locator for both source skills and installed copies.
from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parents[2] / 'softseep' / 'scripts'))
from seep_runtime import repo_root as _seep_repo_root


import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
def _repo_root(start):
    return _seep_repo_root(__file__)


ROOT = _repo_root(HERE)
SERVER = os.path.join(ROOT, "Tool", "mcp", "seep_mcp_server.py")
BASELINE = os.path.join(ROOT, "Tool", "mcp", ".baseline", "tools.json")

TOOL_RE = re.compile(r"@(?:server|mcp)\.tool\(\)\s*\n(?:@[^\n]*\n)*\s*(?:async\s+)?def\s+([A-Za-z_]\w*)")
MARK_RE = re.compile(r"SEEP-EXT[^\n]*?(BEGIN|END)", re.I)


def parse_tools(src):
    return TOOL_RE.findall(src)


def load_baseline():
    if not os.path.isfile(BASELINE):
        return None
    with open(BASELINE, encoding="utf-8") as f:
        return json.load(f)


def check():
    problems = []
    if not os.path.isfile(SERVER):
        return ["找不到 Tool/mcp/seep_mcp_server.py"], {}
    src = open(SERVER, encoding="utf-8", errors="replace").read()
    names = parse_tools(src)
    base = load_baseline()

    # 必须用 \b 边界：注释里出现 "vendored" 时，"end" 会被 re.I 误当成 END
    begins = len(re.findall(r"SEEP-EXT[^\n]*?\bBEGIN\b", src, re.I))
    ends = len(re.findall(r"SEEP-EXT[^\n]*?\bEND\b", src, re.I))
    if base is None:
        problems.append("基线缺失：先跑 `python Tool/skill/softseep/scripts/mcp-guard.py --baseline`（当前基线为自生成，只能保证此后只增）")
    else:
        # 缩容不再一律红：BLUEPRINT §3.3 要求工具面 40→≤16，缩容是**计划内**动作。
        # 判据：消失的每个工具都必须在 reductions[].removed 里登记（带 date + reason），
        # 否则仍是 RED —— 「可以缩，但不许静默缩」。
        approved = {n for r in (base.get("reductions") or []) for n in (r.get("removed") or [])}
        lost = [n for n in base.get("tools", []) if n not in names]
        unapproved = [n for n in lost if n not in approved]
        if unapproved:
            problems.append("基线里的工具静默消失（违反『只许追加』）：" + "、".join(unapproved))
        if len(names) < int(base.get("count", 0)) and unapproved:
            problems.append("工具数量从 %s 降到 %s，且缩容未登记" % (base.get("count"), len(names)))
    if begins != ends:
        problems.append(f"SEEP-EXT 标记不成对：BEGIN {begins} / END {ends}")

    for m in re.finditer(r"def\s+(seep_\w+)\s*\([^)]*\):\s*\n(?:\s+\"\"\"[\s\S]*?\"\"\"\s*\n)?\s+raise\s+NotImplementedError", src):
        problems.append(f"{m.group(1)} 是占位假实现（raise NotImplementedError）")

    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        problems.append("工具名重复定义：" + "、".join(dup))

    info = {"tools": len(names), "baseline": (base or {}).get("count"), "marks": f"{begins}/{ends}"}
    return problems, info


def self_test():
    """自检：解析器与「只增不删」判据，纯内存，不读真实文件。"""
    failed, checks = [], 0
    src = ("@server.tool()\ndef a(x: str) -> str:\n    pass\n\n"
           "@server.tool()\n@wrapper\ndef b(y: int) -> str:\n    pass\n")
    checks += 1
    if parse_tools(src) != ["a", "b"]:
        failed.append("parse_tools")
    checks += 1
    base = {"tools": ["a", "b"], "count": 2}
    approved = {n for r in (base.get("reductions") or []) for n in (r.get("removed") or [])}
    if [n for n in base["tools"] if n not in ["a"] and n not in approved] != ["b"]:
        failed.append("lost-detect")
    checks += 1
    base2 = {"tools": ["a", "b"], "count": 2,
             "reductions": [{"date": "2026-10-24", "reason": "x", "removed": ["b"]}]}
    approved2 = {n for r in base2["reductions"] for n in r["removed"]}
    if [n for n in base2["tools"] if n not in ["a"] and n not in approved2]:
        failed.append("approved-reduction")
    print(json.dumps({"ok": not failed, "tool": "mcp-guard", "checks": checks,
                      "failed": failed}, ensure_ascii=False))
    return 0 if not failed else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", action="store_true", help="用当前文件重建基线")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", dest="self_test", action="store_true")
    a = ap.parse_args()

    if a.self_test:
        return self_test()
    if a.baseline:
        src = open(SERVER, encoding="utf-8", errors="replace").read()
        names = parse_tools(src)
        os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
        with open(BASELINE, "w", encoding="utf-8") as f:
            json.dump({"count": len(names), "tools": sorted(names),
                       "note": "seep_mcp_server.py 的扩展基线：只许在此之上追加，不许删改既有工具"},
                      f, ensure_ascii=False, indent=2)
        print(f"[OK] 基线已写入 {BASELINE}（{len(names)} 个工具）")
        return 0

    problems, info = check()
    if a.json:
        print(json.dumps({"ok": not problems, "problems": problems, "info": info},
                         ensure_ascii=False, indent=2))
    else:
        if problems:
            print("[FAIL] MCP 只增不删校验未通过：")
            for p in problems:
                print("   - " + p)
        else:
            print(f"[OK] MCP 只增不删：{info['tools']} 个工具（基线 {info['baseline']}），"
                  f"SEEP-EXT 标记 {info['marks']}")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
