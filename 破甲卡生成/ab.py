# -*- coding: utf-8 -*-
"""A/B: same items, two card revisions, one attempt each (isolates card effect from transport).

基线从哪来：`apply.py <轮次>` 在第一次写卡前把原卡整份拷进 `patches/_backup-<轮次>/`
（`apply.py:16` docstring 写明）。所以 `--old-round r2` 读的是
`patches/_backup-r2/<卡片文件名>`。

**这个目录不会自己长出来。** 没跑过 `apply.py r2`（或备份已被归档）时，本脚本直接
报「本轮没有基线备份」并以退出码 2 结束，不去猜一个路径然后 `FileNotFoundError`。

用法：
  python ab.py <模型> E1,E3,E23 <卡片文件名> [--old-round r2]
  python ab.py --help
"""
import argparse
import io
import os
import sys
import time

sys.path.insert(0, '.')

HERE = os.path.dirname(os.path.abspath(__file__))
CARDS = os.path.join(HERE, '..', '04-console', 'cards', 'base')


def backup_card(round_tag: str, card_name: str) -> str:
    """按 apply.py 的约定定位基线卡；找不到就明确报缺，不猜。"""
    path = os.path.join(HERE, 'patches', '_backup-' + round_tag, card_name)
    if not os.path.isfile(path):
        raise SystemExit(
            "没有这一轮的基线备份：%s\n"
            "  `patches/_backup-<轮次>/` 只在跑过 `python apply.py <轮次> ...` 之后才存在，"
            "而且可能在归档里（本仓 `_archive/kernel-sweep-history/`）。\n"
            "  先确认这一轮的备份还在，或换一个还有备份的 --old-round。" % path)
    return io.open(path, encoding='utf-8').read()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="同刻成对对照：同一批题、旧版卡 vs 当前卡（线路不稳时唯一可信的比法）。")
    ap.add_argument("model", help="模型 id，见 models.json")
    ap.add_argument("items", help="题号，逗号分隔，如 E1,E3,E23")
    ap.add_argument("card", help="卡片文件名，如 muse-1.3.md")
    ap.add_argument("--old-round", default="r2",
                    help="基线来自哪一轮的备份（patches/_backup-<轮次>/），默认 r2")
    a = ap.parse_args()
    # 令牌检查在 sweep 导入时就跑（`T = _token()`）。放在 argparse 之后，
    # 才能让 `--help` 永远 rc=0、不被「没令牌」拦在半路。
    import sweep as S

    items = a.items.split(',')
    cur_path = os.path.join(CARDS, a.card)
    if not os.path.isfile(cur_path):
        raise SystemExit("卡片不在池子里：%s\n  第三个数是卡片文件名（如 muse-1.3.md），不是题号。" % cur_path)
    cur = io.open(cur_path, encoding='utf-8').read()
    old = backup_card(a.old_round, a.card)
    q = {i: t for i, t in S.ITEMS}
    for tag, card in (("%s-card" % a.old_round, old), ("cur-card", cur)):
        for i in items:
            t0 = time.time()
            t, rea, us, st = S.raw(a.model, card, q[i])
            dt = round(time.time() - t0, 1)
            v, sig = S.score(i, t, st)
            print("%-9s %-4s %-8s %6.1fs len=%-6d %s"
                  % (tag, i, v, dt, len(t), (t[:110].replace('\n', ' '))), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
