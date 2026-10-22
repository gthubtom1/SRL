#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""manifest.py — 为 artifacts/ 下每个文件生成 sha256 清单（MANIFEST.sha256）。

用法：python scripts/manifest.py [--json]
输出行格式：`<sha256>  <相对案例目录的路径>`，按路径排序，确定性可复算。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CASE = os.path.dirname(HERE)
ART = os.path.join(CASE, "artifacts")


def sha256(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rows = []
    for dp, _dn, fn in os.walk(ART):
        for f in sorted(fn):
            full = os.path.join(dp, f)
            rel = os.path.relpath(full, CASE).replace(os.sep, "/")
            if rel == "artifacts/MANIFEST.sha256":
                continue
            rows.append((rel, sha256(full)))
    rows.sort()

    out = os.path.join(ART, "MANIFEST.sha256")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        for rel, h in rows:
            f.write(f"{h}  {rel}\n")
    if args.json:
        print(json.dumps({"files": len(rows), "manifest": "artifacts/MANIFEST.sha256",
                          "sample": rows[:3]}, ensure_ascii=False, indent=1))
    else:
        print(f"[manifest] {len(rows)} files -> artifacts/MANIFEST.sha256")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
