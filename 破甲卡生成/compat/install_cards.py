#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""install_cards.py —— 在 Seep 工作台内「装卡」的安全包装器

为什么需要它
------------
relab2 原版用的是 `quad/install2.py`，它把 `quad/en2-*.md` 写到
`<仓库>/04-console/cards/base/` —— 那是 **relab2 的目录布局**。
在 Seep 工作台里没有 `04-console/`，直接跑会把卡写到 `D:\\work\\seep-fork\\04-console\\`
（仓库根，未跟踪），既装错地方又污染工作区。

本包装器：
  1. **默认目标是 `破甲卡生成/人设卡/`**（与现有布局一致），可用 `--dest` 覆盖；
  2. 保守护栏：默认 dry-run；目标比源新则跳过；`--force` 才覆盖；
  3. 写完**自动跑 Seep 兼容闸门**（`--apply` 补齐 + `--check` 校验），
     保证装进去的卡一定带 Carve-out 与 Capability honesty 两条条款。

用法
----
    python compat/install_cards.py                # 只报计划（dry-run）
    python compat/install_cards.py --yes          # 真正安装（跳过比源新的目标）
    python compat/install_cards.py --yes --force  # 强制覆盖（回退，危险）
    python compat/install_cards.py --dest <目录>   # 指定目标目录
"""

from __future__ import annotations

import argparse
import io
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)                      # 破甲卡生成/
QUAD = os.path.join(BASE, "quad")
DEFAULT_DEST = os.path.join(BASE, "人设卡")

MAP = {
    "en2-gemini.md": "gemini-3.8-flash-high.md",
    "en2-mimo.md": "mimo-2.6.md",
    "en2-muse.md": "muse-1.3.md",
    "en2-spacebunny.md": "space-bunny.md",
}


def main(argv):
    ap = argparse.ArgumentParser(description="Seep 内安全装卡（quad/en2-* → 人设卡/）")
    ap.add_argument("--dest", default=DEFAULT_DEST, help="目标目录（默认 破甲卡生成/人设卡/）")
    ap.add_argument("--yes", action="store_true", help="真正写入（默认只报计划）")
    ap.add_argument("--force", action="store_true", help="连比源更新的目标也覆盖（回退，危险）")
    args = ap.parse_args(argv)

    dest = os.path.abspath(args.dest)
    print(f"[install] 源目录: {QUAD}")
    print(f"[install] 目标  : {dest}")
    print(f"[install] 模式  : {'写入' if args.yes else 'DRY-RUN（只报计划）'}"
          f"{' + FORCE' if args.force else ''}\n")

    todo, skip = [], []
    for src_name, dst_name in sorted(MAP.items()):
        src = os.path.join(QUAD, src_name)
        dst = os.path.join(dest, dst_name)
        if not os.path.isfile(src):
            skip.append((src_name, "源缺失"))
            continue
        if os.path.isfile(dst) and not args.force:
            # 护栏：quad/en2-* 是 2026-10-08 的一代，现役卡通常更新。
            # 默认**绝不覆盖已存在的目标**，要覆盖必须显式 --force。
            skip.append((dst_name, "目标已存在（默认不覆盖，--force 才覆盖）"))
            continue
        todo.append((src, dst, dst_name))

    for s, d, n in todo:
        print(f"  [WOULD] {n}  <-  quad/{os.path.basename(s)}")
    for n, why in skip:
        print(f"  [SKIP]  {n}  ({why})")

    if not args.yes:
        print("\n[install] DRY-RUN 结束。加 --yes 才会写入。")
        return 0

    if not todo:
        print("\n[install] 没有需要写入的卡。")
    else:
        os.makedirs(dest, exist_ok=True)
        for s, d, n in todo:
            shutil.copy2(s, d)
            print(f"  [OK] 已写入 {n}")

    # ---- 装完即过闸门（幂等） ----
    gate = os.path.join(HERE, "check_seep_compat.py")
    print("\n[install] 跑 Seep 兼容闸门 ...")
    r1 = subprocess.run([sys.executable, gate, "--apply"])
    r2 = subprocess.run([sys.executable, gate, "--check"])
    if r2.returncode != 0:
        print("\n[install] ✗ 闸门未通过 —— 卡不得提交")
        return 1
    print("\n[install] ✓ 装卡完成且全部通过兼容闸门")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
