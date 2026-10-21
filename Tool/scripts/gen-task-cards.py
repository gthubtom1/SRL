#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen-task-cards.py —— 从「源头提示词」生成 /reverse 任务卡（LF 换行，避免 CRLF 假 diff）。

为什么需要它（血案）：
    v1.18.5 手工从源文件重生成 `tasks/analyze.md`，源文件当时**不含**闸块 → P0-1 被静默冲掉；
    且源文件是 CRLF、任务是 LF，手工复制会产生整文件假 diff，诱发"顺手重排"式二次回退。
    所以：生成必须脚本化 + 写死 LF + 生成后由 preflight 断言闸块在场。

用法：
    python Tool/scripts/gen-task-cards.py           # 重新生成（覆盖 tasks/analyze.md）
    python Tool/scripts/gen-task-cards.py --check   # 只校验：生成结果与磁盘是否一致（rc=1 表示漂移）
"""
from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SRC = os.path.join(ROOT, "逆向分析报告提示词.md")
DST = os.path.join(ROOT, "Tool", "prompts", "tasks", "analyze.md")
FRONT = ("---\n"
         "description: 阶段零：分析透出可复现报告 + 可行性裁定（本轮不做成品）\n"
         'argument-hint: "<目标路径 / 包名 / 网址，留空则用当前工作区样本>"\n'
         "---\n")


def build() -> str:
    src = open(SRC, encoding="utf-8", newline="").read().replace("\r\n", "\n")
    if "```text" not in src:
        raise SystemExit("[ERR] 源文件缺少 ```text 代码块")
    body = src.split("```text", 1)[1]
    body = body.rsplit("```", 1)[0].strip()
    need = ["init", "claim", "prove", "depth", "instrument", "verdict", "gate"]
    missing = [k for k in need if k not in body]
    if missing or "必须返回 0" not in body:
        raise SystemExit("[ERR] 源文件闸块不完整（缺：%s%s）—— 拒绝生成，防止再回退 P0-1"
                         % (",".join(missing) or "无", "；缺『必须返回 0』" if "必须返回 0" not in body else ""))
    return FRONT + body + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    want = build().replace("\r\n", "\n")
    if a.check:
        cur = open(DST, encoding="utf-8", newline="").read().replace("\r\n", "\n") if os.path.isfile(DST) else ""
        ok = cur == want
        print(("[OK] 任务卡与源头一致（sha 相同）" if ok else "[FAIL] 任务卡与源头漂移，跑 gen-task-cards.py 重新生成"))
        return 0 if ok else 1
    open(DST, "w", encoding="utf-8", newline="\n").write(want)
    print(f"[OK] 已生成 {os.path.relpath(DST, ROOT)}（{len(want)} 字符，LF）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
