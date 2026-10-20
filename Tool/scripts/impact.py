#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""impact.py —— 改动前先问"这文件牵动谁"，只跑该跑的检查。

为什么要有它：
    以前加一个工具，得先把整个仓库读一遍才知道会不会牵连别处，一搞就是一两个小时。
    实际上依赖关系是固定的几类，可以静态算出来。

用法：
    python Tool/scripts/impact.py Tool/config/tool-capabilities.json
    python Tool/scripts/impact.py Tool/prompts/SEEP.md Tool/skill/softseep/SKILL.md

输出三段：
    ① 谁引用了它（文档 / 脚本 / 配置 / 技能）
    ② 它属于哪条链（工具 / 提示词 / 技能 / 安装 / 知识库 / 检查）
    ③ 该跑哪几条检查（可直接复制执行）
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
EXCLUDE_DIRS = {".git", "node_modules", ".next", "__pycache__", ".venv"}
TEXT_EXT = {".md", ".ps1", ".sh", ".py", ".json", ".jsonc", ".yml", ".ts", ".mjs"}
SKIP_SCAN = ("Tool/mcp/Tool/safe", "Tool/upstream", "Tool/mcp/Tool/reverselab/kb", "破甲卡生成")
SKIP_REF = ("Tool/cases", "CHANGELOG.md")

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 链 → (判定前缀, 该跑的检查)
CHAINS = [
    ("Tool/mcp/seep_mcp_server.py", "MCP 工具实现", [
        "python Tool/scripts/check-budget.py",
        "python Tool/scripts/smoke-e2e.py",
        "python Tool/scripts/preflight.py --fast",
    ]),
    ("Tool/config/mcp-servers.json", "MCP 安装清单", [
        "powershell -File setup/install-pi.ps1 -SkipPackages",
        "python Tool/scripts/preflight.py --fast",
    ]),
    ("Tool/config/tool-capabilities.json", "工具能力表", [
        "python Tool/scripts/preflight.py --fast",
    ]),
    ("Tool/config/tool-runtimes.json", "工具通道阶梯", [
        "powershell -File Tool/scripts/tool-run.ps1 -ListModes",
        "python Tool/scripts/preflight.py --fast",
    ]),
    ("Tool/scripts/routing.json", "任务路由 SSOT", [
        "python Tool/scripts/verify-routing-coherence.py",
        "python Tool/scripts/preflight.py --fast",
    ]),
    ("Tool/prompts/", "提示词层", [
        "powershell -File setup/verify.ps1",
        "（新开会话后）/rules-status 看装配",
    ]),
    ("Tool/skill/", "技能层", [
        "python Tool/scripts/verify-routing-coherence.py",
        "python Tool/scripts/check-budget.py",
        "python Tool/scripts/preflight.py --fast",
    ]),
    ("setup/", "安装/校验链", [
        "powershell -File setup/verify.ps1",
        "bash setup/verify.sh",
    ]),
    ("Tool/mcp/Tool/reverselab/kb/", "知识库（vendored 上游）", [
        "python Tool/scripts/kb_acceptance.py",
    ]),
    ("Tool/scripts/", "工具脚本", [
        "python Tool/scripts/preflight.py --fast",
    ]),
]

for d in EXCLUDE_DIRS:  # 保持与 preflight 一致
    pass


def chain_of(path: str):
    for prefix, name, cmds in CHAINS:
        if path.replace("\\", "/").startswith(prefix):
            return name, cmds
    return "其他（文档 / 配置）", ["python Tool/scripts/preflight.py"]


def refs_of(target: str):
    base = os.path.basename(target)
    hits = []
    for dp, dn, fn in os.walk(ROOT):
        dn[:] = [d for d in dn if d not in EXCLUDE_DIRS]
        rel = os.path.relpath(dp, ROOT).replace(os.sep, "/")
        rel = "" if rel == "." else rel
        for f in fn:
            p = (rel + "/" + f).lstrip("/")
            if p == target or any(p.startswith(s) for s in SKIP_SCAN + SKIP_REF):
                continue
            if os.path.splitext(f)[1].lower() not in TEXT_EXT:
                continue
            try:
                text = open(os.path.join(ROOT, p), encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            if target in text or base in text:
                hits.append(p)
    return hits


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    for arg in argv:
        t = arg.replace("\\", "/").lstrip("./")
        if not os.path.exists(os.path.join(ROOT, t)):
            print(f"\n[跳过] {t} 不存在")
            continue
        name, cmds = chain_of(t)
        hits = refs_of(t)
        print(f"\n=== {t} ===")
        print(f"所属链路: {name}")
        print(f"被 {len(hits)} 个文件引用" + ("：" if hits else ""))
        for h in hits[:15]:
            print("   -", h)
        if len(hits) > 15:
            print(f"   … 还有 {len(hits) - 15} 个")
        print("建议检查:")
        for c in cmds:
            print("   $", c)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
