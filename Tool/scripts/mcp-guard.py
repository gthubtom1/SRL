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

它怎么查（不依赖 git、不依赖网络）：
    1. 基线快照 `Tool/mcp/.baseline/tools.json`：记录工具名清单与数量（首次 `--baseline` 生成）；
    2. 现文件里解析 `@server.tool()` 装饰的函数名；
    3. 断言：基线里的工具**一个都不许消失**；数量只许多不许少；
    4. 断言：扩展块标记 `SEEP-EXT` 的 BEGIN/END 成对（防止有人手改后忘了收尾）；
    5. 断言：`def seep_*` 里不存在 `raise NotImplementedError` 之类的"假实现占位"。

用法：
    python Tool/scripts/mcp-guard.py            # 校验（CI/preflight 用），违反则 exit 1
    python Tool/scripts/mcp-guard.py --baseline # 重新生成基线（只在确认上游同步后做）
    python Tool/scripts/mcp-guard.py --json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
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

    if base is None:
        problems.append("基线缺失：先跑 `python Tool/scripts/mcp-guard.py --baseline`")
    else:
        lost = [n for n in base.get("tools", []) if n not in names]
        if lost:
            problems.append("基线里的工具消失了（违反『只许追加』）：" + "、".join(lost))
        if len(names) < int(base.get("count", 0)):
            problems.append(f"工具数量从 {base.get('count')} 降到 {len(names)}（只许增加）")

        begins = len(re.findall(r"SEEP-EXT[^\n]*?\bBEGIN\b", src, re.I))
        ends = len(re.findall(r"SEEP-EXT[^\n]*?\bEND\b", src, re.I))
    if begins != ends:
        problems.append(f"SEEP-EXT 标记不成对：BEGIN {begins} / END {ends}")

    for m in re.finditer(r"def\s+(seep_\w+)\s*\([^)]*\):\s*\n(?:\s+\"\"\"[\s\S]*?\"\"\"\s*\n)?\s+raise\s+NotImplementedError", src):
        problems.append(f"{m.group(1)} 是占位假实现（raise NotImplementedError）")

    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        problems.append("工具名重复定义：" + "、".join(dup))

    info = {"tools": len(names), "baseline": (base or {}).get("count"), "marks": f"{begins}/{ends}"}
    return problems, info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", action="store_true", help="用当前文件重建基线")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

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
