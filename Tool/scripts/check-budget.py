#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check-budget.py —— 反臃肿预算自检（对应 MANUAL/BASELINE-FREEZE.md §7）

一条命令回答："这个项目有没有在变臃肿？"
退出码：0 = 全部在预算内；1 = 有超限项。

用法：
    python Tool/scripts/check-budget.py
    python Tool/scripts/check-budget.py --json
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # Tool/scripts -> Tool


def count_tools():
    src = io.open(os.path.join(ROOT, "mcp", "seep_mcp_server.py"), encoding="utf-8").read()
    return len(re.findall(r"^@server\.tool\(\)", src, re.M))


def count_skills():
    base = os.path.join(ROOT, "skill")
    names = set()
    for d in os.listdir(base):
        p = os.path.join(base, d)
        if not os.path.isdir(p):
            continue
        if d.startswith(("_", ".")):   # S3：`_pending/` 是归档区，不索引
            continue
        if d == "safe-skills":
            for sub in os.listdir(p):
                if os.path.isdir(os.path.join(p, sub)):
                    names.add(sub)
        else:
            names.add(d)
    return len(names)


def first_party_files():
    """引擎文件计数（2026-10-22 修正：只数 git 已跟踪文件）。

    旧实现走 os.walk，会把 `.pytest_cache/`、`.pi/`、`evidence/` 这类运行时/
    忽略目录也算进去，导致同一份代码在不同机器/不同 worktree 上得出不同数字
    （实测漂移 820↔834），BASELINE 无法对账。现在优先用 `git ls-files`，
    拿不到 git（导出包/浅环境）时回退到 walk，但跳过所有点目录。
    """
    skip = ("/upstream", "/node_modules", "/__pycache__", "/mcp/Tool",
            "/破甲卡生成", "/cases", "/audit", "/work",
            "/.git/", "/.pytest_cache/", "/.pi/", "/evidence/")
    repo = os.path.dirname(ROOT)

    try:
        out = subprocess.run(["git", "-C", repo, "ls-files", "-z"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=60)
        if out.returncode == 0 and out.stdout:
            names = [p for p in out.stdout.decode("utf-8", "replace").split("\0") if p]
            total = 0
            for rel in names:
                norm = "/" + rel.replace(os.sep, "/")
                if any(s in norm for s in skip):
                    continue
                total += 1
            return total
    except Exception:
        pass

    total = 0
    for dirpath, dirs, files in os.walk(ROOT):
        norm = dirpath.replace(os.sep, "/")
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        if any(s in norm for s in skip):
            dirs[:] = []
            continue
        total += len(files)
    for name in os.listdir(repo):
        p = os.path.join(repo, name)
        if os.path.isfile(p) and not name.startswith("."):
            total += 1
    for sub in ("setup", "MANUAL", "docs"):
        d = os.path.join(repo, sub)
        if os.path.isdir(d):
            for dirpath, dirs, files in os.walk(d):
                if "__pycache__" in dirpath:
                    dirs[:] = []
                    continue
                total += len(files)
    return total


def case_files():
    """案例库文件数：证据/样本/产物，单独预算（不算引擎膨胀）。"""
    d = os.path.join(ROOT, "cases")
    n = 0
    for dirpath, dirs, files in os.walk(d):
        if "__pycache__" in dirpath:
            dirs[:] = []
            continue
        n += len(files)
    return n


def main(argv):
    ap = argparse.ArgumentParser(description="反臃肿预算自检")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    repo = os.path.dirname(ROOT)
    budget = [
        ("MCP 工具", count_tools(), 45),
        ("技能", count_skills(), None),   # 用户决定：技能数量不设上限
        ("setup 脚本", len([f for f in os.listdir(os.path.join(repo, "setup"))
                        if f.endswith((".ps1", ".sh", ".py"))]), 22),
        ("MANUAL 手册", len([f for f in os.listdir(os.path.join(repo, "MANUAL"))
                         if f.endswith(".md")]), 16),
        ("MCP 主服务行数", len(io.open(os.path.join(ROOT, "mcp", "seep_mcp_server.py"),
                                       encoding="utf-8").read().splitlines()), 3200),
        ("first-party 引擎文件", first_party_files(), 900),
        ("案例库文件", case_files(), 1500),   # 证据库：58 个案例的真实输入/产物
    ]

    rows = []
    over = []
    for name, value, limit in budget:
        if limit is None:
            rows.append({"item": name, "value": value, "limit": None, "ok": True})
            continue
        ok = value <= limit
        rows.append({"item": name, "value": value, "limit": limit, "ok": ok})
        if not ok:
            over.append(name)

    if args.json:
        print(json.dumps({"ok": not over, "budget": rows}, indent=2, ensure_ascii=False))
    else:
        print("[budget] 反臃肿预算自检")
        for r in rows:
            mark = "OK  " if r["ok"] else "OVER"
            if r["limit"] is None:
                print("  %-4s %-16s %5d / 无上限" % (mark, r["item"], r["value"]))
            else:
                print("  %-4s %-16s %5d / %d" % (mark, r["item"], r["value"], r["limit"]))
        print("  结论:", "全部在预算内" if not over else ("超限: " + ", ".join(over)))
    return 0 if not over else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
