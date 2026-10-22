#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen-playbook-index.py —— 从 intent-coverage 结果生成 Tool/playbooks/INDEX.md。"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def caps_of(playbook: str) -> list:
    p = os.path.join(ROOT, "Tool", "playbooks", playbook + ".md")
    if not os.path.isfile(p):
        return []
    text = open(p, encoding="utf-8", errors="replace").read()
    m = re.search(r"(?m)^-\s*用到的能力[^：:]*[:：]\s*(.+)$", text)
    if not m:
        return []
    return re.findall(r"`([^`]+)`", m.group(1))


def main() -> int:
    ap = argparse.ArgumentParser(description="生成 playbooks/INDEX.md")
    ap.add_argument("--check", action="store_true", help="只比对，不写")
    args = ap.parse_args()
    r = subprocess.run([sys.executable, os.path.join(HERE, "intent-coverage.py"), "--json"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print(json.dumps({"ok": False, "reason": "intent-coverage failed rc=%d" % r.returncode}))
        return 2
    data = json.loads(r.stdout[r.stdout.index("{"):])
    results = data["results"]
    groups = {}
    for item in results:
        pb = item.get("primary_playbook") or ""
        if not pb:
            continue
        groups.setdefault(pb, []).append(item)

    lines = ["# 意图 → 配方 / 能力 索引", "",
             "> 本文件由 `Tool/scripts/gen-playbook-index.py` 从 `intent-coverage.py --json` 生成；"
             "探针在 `Tool/config/intent-probes.json`，共 %d。" % len(results),
             "> 覆盖口径：触发词命中期望配方即算 covered；未命中按缺口列出，并给 2–3 个 capability 组合。",
             "",
             "- 总数：**%d**" % data["summary"]["total"],
             "- 已覆盖：**%d**" % data["summary"]["covered"],
             "- 缺口：**%d**" % data["summary"]["uncovered"],
             "- 覆盖率：**%.2f%%**" % data["summary"]["coverage_pct"],
             "- 跨域误命中：**%d**" % data["summary"].get("violations", 0),
             "",
             "## 已覆盖：按配方分组", ""]
    for pb in sorted(groups):
        items = groups[pb]
        lines.append("### `%s`（%d 条）" % (pb, len(items)))
        lines.append("")
        caps = caps_of(pb)
        if caps:
            lines.append("配方能力面：" + " ".join("`%s`" % c for c in caps))
            lines.append("")
        lines.append("| 意图 | playbook | 状态 |")
        lines.append("| :-- | :-- | :-- |")
        for it in items:
            lines.append("| %s | `%s` | %s |" % (it["text"], pb, it.get("status", "")))
        lines.append("")

    uncovered = [it for it in results if it.get("status") != "covered"]
    if uncovered:
        lines += ["## 缺口", ""]
        for it in uncovered:
            lines.append("- %s（期望 `%s`）" % (it["text"], it.get("expect")))
        lines.append("")

    out = "\n".join(lines)
    path = os.path.join(ROOT, "Tool", "playbooks", "INDEX.md")
    if args.check:
        cur = open(path, encoding="utf-8").read() if os.path.isfile(path) else ""
        ok = cur.strip() == out.strip()
        print(json.dumps({"ok": ok, "path": "Tool/playbooks/INDEX.md"}, ensure_ascii=False))
        return 0 if ok else 1
    open(path, "w", encoding="utf-8", newline="\n").write(out)
    print(json.dumps({"ok": True, "playbooks": len(groups), "probes": len(results)},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
