#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fork-delta.py —— 刷新 Tool/docs/FORK-DELTA.md 的「自动差分清单」一节。

为什么需要它：
  手写清单一定会过期（上游一更新就废）。所以把"文件级差分"交给脚本生成，
  把"为什么/值不值得/怎么撤"留给人写（§三、§四）。

用法：
    python Tool/scripts/fork-delta.py            # 刷新文档
    python Tool/scripts/fork-delta.py --print    # 只打印，不写文件

前提：本地存在 upstream/main（git remote add upstream <原版仓库> && git fetch upstream）
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import io

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # Tool/scripts -> Tool -> 仓库根
DOC = os.path.join(ROOT, "Tool", "docs", "FORK-DELTA.md")
BEGIN = "<!-- AUTO-DELTA:BEGIN -->"
END = "<!-- AUTO-DELTA:END -->"
UPSTREAM_REF = "upstream/main"

# 分类规则：(显示名, 路径前缀列表)
GROUPS = [
    ("MCP 服务", ["Tool/mcp/"]),
    ("声明式配置", ["Tool/config/"]),
    ("技能", ["Tool/skill/"]),
    ("提示词/扩展", ["Tool/prompts/"]),
    ("脚本", ["Tool/scripts/"]),
    ("文档", ["Tool/docs/", "MANUAL/", "docs/"]),
    ("安装与校验", ["setup/"]),
    ("根目录", [""]),
]


def run(*args):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def has_upstream():
    r = run("git", "rev-parse", "--verify", UPSTREAM_REF)
    return r.returncode == 0


def changed_files():
    """返回 [(status, path)]，排除上游镜像目录（那是 vendored，不算我们的差分）。"""
    r = run("git", "-c", "core.quotepath=false", "diff", "--name-status", f"{UPSTREAM_REF}..HEAD")
    if r.returncode != 0:
        return []
    out = []
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status, path = parts[0][0], parts[-1]
        if path.startswith("Tool/upstream/"):
            continue
        out.append((status, path))
    return out


def group_of(path):
    for name, prefixes in GROUPS:
        for p in prefixes:
            if p == "":
                if "/" not in path:
                    return name
            elif path.startswith(p):
                return name
    return "其他"


def build_section(files):
    added = [p for s, p in files if s == "A"]
    modified = [p for s, p in files if s == "M"]
    deleted = [p for s, p in files if s == "D"]
    renamed = [p for s, p in files if s == "R"]

    lines = []
    lines.append("")
    lines.append(f"**统计**：新增 {len(added)} · 修改 {len(modified)} · "
                 f"删除 {len(deleted)} · 重命名 {len(renamed)}（相对 `{UPSTREAM_REF}`，已排除 `Tool/upstream/`）")
    lines.append("")
    if deleted:
        lines.append("> ⚠ **出现删除项**：纯超集原则要求 0 删除。请确认是否为有意行为并写进台账 §三。")
        lines.append("")

    for status, title in (("A", "新增文件（只有我们有）"), ("M", "修改文件（两边都有，合并上游时重点看）"),
                          ("D", "删除文件（不应出现）")):
        items = [(s, p) for s, p in files if s == status]
        if not items:
            continue
        lines.append(f"### {title}")
        lines.append("")
        lines.append("| 分类 | 文件 |")
        lines.append("|---|---|")
        by_group = {}
        for _, p in items:
            by_group.setdefault(group_of(p), []).append(p)
        for g in [g for g, _ in GROUPS] + ["其他"]:
            if g not in by_group:
                continue
            paths = sorted(by_group[g])
            shown = paths[:8]
            cell = "<br>".join(f"`{x}`" for x in shown)
            if len(paths) > len(shown):
                cell += f"<br>… 另 {len(paths) - len(shown)} 个"
            lines.append(f"| {g} | {cell} |")
        lines.append("")

    lines.append(f"> 生成时间：见本次提交；重新生成：`python Tool/scripts/fork-delta.py`")
    lines.append("")
    return "\n".join(lines)


def main(argv):
    ap = argparse.ArgumentParser(description="刷新 FORK-DELTA.md 的自动差分清单")
    ap.add_argument("--print", action="store_true", dest="print_only")
    args = ap.parse_args(argv)

    if not has_upstream():
        print(f"[fork-delta] 未找到 {UPSTREAM_REF}。请先执行：")
        print("  git remote add upstream https://github.com/angusdevgo/Seep-Reverse-Lab.git")
        print("  git fetch upstream")
        return 2

    files = changed_files()
    if not files:
        print("[fork-delta] 没有差异（或 git diff 失败）")
        return 1

    section = build_section(files)
    if args.print_only:
        print(section)
        return 0

    if not os.path.isfile(DOC):
        print(f"[fork-delta] 文档不存在：{DOC}")
        return 1

    s = io.open(DOC, encoding="utf-8", newline="").read()
    i, j = s.find(BEGIN), s.find(END)
    if i < 0 or j < 0:
        print("[fork-delta] 文档里缺少 AUTO-DELTA 标记，无法写入")
        return 1
    new = s[:i + len(BEGIN)] + "\n" + section + s[j:]
    io.open(DOC, "w", encoding="utf-8", newline="").write(new)
    print(f"[fork-delta] 已刷新：{os.path.relpath(DOC, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
