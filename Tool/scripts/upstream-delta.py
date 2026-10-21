#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""upstream-delta.py —— 生成「上游 vs 本仓」的内容差分（不合并、不改工作区）。

为什么不用 git merge：
    本仓与 angusdevgo/Seep-Reverse-Lab 的历史可能不共享祖先（浅克隆/重建过历史时
    merge-base 不存在），直接 merge 会把两套历史拧在一起。**先做内容差分、再按文件决策**
    才是可控做法（FORK-DELTA §四 五问评估）。

用法：
    git fetch upstream main --deepen=200
    python Tool/scripts/upstream-delta.py                 # 输出 JSON 到 work/upstream-delta/
    python Tool/scripts/upstream-delta.py --ref upstream/main --print
退出码：0 成功；2 upstream ref 不存在。
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUTDIR = os.path.join(ROOT, "work", "upstream-delta")

SKIP = ("Tool/upstream/", "Tool/mcp/Tool/", "work/", "破甲卡生成/", ".git/")


def git(*args: str) -> str:
    r = subprocess.run(["git", "-C", ROOT] + list(args), capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError((r.stderr or "").strip()[:200])
    return r.stdout


def blob(ref: str, path: str) -> bytes | None:
    try:
        r = subprocess.run(["git", "-C", ROOT, "show", "%s:%s" % (ref, path)],
                           capture_output=True)
        return r.stdout if r.returncode == 0 else None
    except Exception:  # noqa: BLE001
        return None


def sha(b: bytes | None) -> str:
    return hashlib.sha256(b).hexdigest() if b is not None else ""


def main() -> int:
    ap = argparse.ArgumentParser(description="上游 vs 本仓 内容差分")
    ap.add_argument("--ref", default="upstream/main")
    ap.add_argument("--print", action="store_true")
    a = ap.parse_args()
    try:
        up = set(x for x in git("ls-tree", "-r", "--name-only", a.ref).splitlines() if x)
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ok": False, "blocked_at": "ref", "reason": str(e)}, ensure_ascii=False))
        return 2
    ours = set(x for x in git("ls-tree", "-r", "--name-only", "HEAD").splitlines() if x)
    up = {p for p in up if not any(p.startswith(s) for s in SKIP)}
    ours = {p for p in ours if not any(p.startswith(s) for s in SKIP)}

    only_up = sorted(up - ours)
    only_us = sorted(ours - up)
    both = sorted(up & ours)
    changed = []
    for p in both:
        if sha(blob(a.ref, p)) != sha(blob("HEAD", p)):
            changed.append(p)

    report = {
        "ok": True,
        "ref": a.ref,
        "generated_at": os.environ.get("SEEP_TIMESTAMP") or "1970-01-01T00:00:00Z",
        "counts": {
            "only_upstream": len(only_up),
            "only_ours": len(only_us),
            "both_changed": len(changed),
            "both_same": len(both) - len(changed),
        },
        "only_upstream": only_up[:500],
        "only_ours": only_us[:500],
        "both_changed": changed[:500],
        "note": "按 FORK-DELTA §四 五问逐条评估后，只 cherry-pick 单文件并跑 preflight/domain-gate；不要整仓 merge。",
    }
    os.makedirs(OUTDIR, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = os.path.join(OUTDIR, "delta-%s.json" % stamp)
    io.open(path, "w", encoding="utf-8", newline="\n").write(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    if a.print:
        print(json.dumps(report["counts"], ensure_ascii=False))
        for p in only_up[:40]:
            print("  + upstream", p)
        for p in only_us[:20]:
            print("  - ours", p)
        for p in changed[:40]:
            print("  ~ changed ", p)
    print("report:", os.path.relpath(path, ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
