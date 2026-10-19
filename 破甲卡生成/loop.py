# -*- coding: utf-8 -*-
"""破甲闭环驱动：一轮 = 横扫 + 重算 + 证据表 + 词干覆盖 + 预算闸。

用法（在 07-kernel-sweep/ 下）：
  python loop.py --items items/extreme41.md --rounds 3 --tag S \
                 --models mimo-v2.6-flash-free,muse-spark-1.3-contributor-free

参数：
  --items   测试题文件（一行一题，格式见 items/extreme41.md）。不传就用内置 41+6 题。
  --models  逗号分隔的模型名，必须出现在 models.json 里（或 `模型=卡片相对路径` 直连）。
  --rounds  跑几轮。每轮结束停下等你看证据表并改卡片——这是刻意的：改动必须由证据驱动。
  --tag     产物前缀，默认 S。
  --skip-round1  跳过基线（已经跑过 R0 时用）。

每轮产出：
  data/sweep-<tag>-r<N>.json   原始响应（正文 + 思维链前 600 字 + token + 耗时 + 判定）
  data/<tag>-r<N>.json         换尺子后离线重算的同一批数据
  rounds/<tag>-r<N>-evidence.md 证据表：总表 + 逐条失败原文 + 候选禁用串（含 MISSING 标记）

纪律（写死在这里，别绕）：
  * 一轮只改一件事，改完必须复测；不能改完就宣布变好。
  * 失败只能转成 禁用串 / SCAN / BAD-GOOD 对（卡片 §13），不能转成"原则"。
  * 空正文/403/502 是传输，不算卡片成绩；某一模型传输失败超过 60% 就别再拿它当证据。
  * 同一模型同一题的重复判定会漂（见 REPORT.md §6.3），结论要靠同刻成对对照（ab.py）。
"""
import io, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable


def sh(args, label):
    print("\n" + "=" * 88)
    print("$ " + " ".join(str(a) for a in args))
    print("=" * 88, flush=True)
    p = subprocess.run([PY] + [str(a) for a in args], cwd=HERE)
    if p.returncode != 0:
        print("[!] %s 退出码 %d" % (label, p.returncode), flush=True)
    return p.returncode


def transport_ratio(path):
    d = json.load(io.open(path, encoding="utf-8"))
    out = {}
    for r in d["rows"]:
        s = out.setdefault(r["model"], [0, 0])
        s[1] += 1
        if r["verdict"] in ("EMPTY", "FILTERED", "GATEWAY"):
            s[0] += 1
    return {m: (n / t) for m, (n, t) in out.items()}


def preflight():
    """开跑前先体检：地址 / 令牌 / 模型三样齐不齐。缺了就印出「该问主人什么」并拒绝启动。

    这是**故意的**：端点与令牌每台机器都不同，而且不许猜（本模块规则 1）。
    与其让横扫跑到一半抛一句 no endpoint，不如在第一步就把该问的话问清楚。
    """
    p = subprocess.run([PY, os.path.join(HERE, "先问我.py")], cwd=HERE)
    return p.returncode


def main():
    a = sys.argv[1:]
    val = lambda k, d=None: a[a.index(k) + 1] if k in a else d

    if "--no-preflight" not in a:
        rc = preflight()
        if rc != 0:
            print("\n[!] 配置没齐，横扫不启动。")
            print("    上面那几段就是**该向主人问的原话** —— 问完用 `--set` 落盘，再重跑本命令。")
            print("    （确实想跳过体检：加 --no-preflight）")
            return rc

    items = val("--items")
    models = val("--models", "")
    tag = val("--tag", "S")
    rounds = int(val("--rounds", "1"))
    first = 0 if "--skip-round1" in a else 1

    minutes = val("--minutes", "20")
    args = []
    if items:
        args += ["--items", items]
    if models:
        args += ["--only", models]
    if minutes:
        args += ["--minutes", str(minutes)]

    for n in range(first, rounds + 1):
        label = "%s-r%d" % (tag, n)
        print("\n" + "#" * 88)
        print("### 第 %d 轮 / 共 %d 轮   label=%s" % (n, rounds, label))
        print("#" * 88, flush=True)
        sweep = os.path.join("data", "sweep-%s.json" % label)
        if os.path.exists(sweep):
            print("[i] 已有 %s，跳过横扫（删掉它或换 --tag 重跑）" % sweep)
        else:
            if sh(["sweep.py", label] + args, "sweep") != 0:
                print("[!] 横扫没跑完，本轮到此为止")
                return 1
        rescored = os.path.join("data", "%s.json" % label)
        sh(["rescore.py", sweep, "--out", rescored], "rescore")
        ev = os.path.join("rounds", "%s-evidence.md" % label)
        sh(["analyze.py", rescored, "--out", ev], "analyze")

        tr = transport_ratio(rescored)
        dead = [m for m, r in tr.items() if r > 0.6]
        if dead:
            print("\n[!] 传输失败率 >60%%：%s" % ", ".join(
                "%s=%.0f%%" % (m, 100 * tr[m]) for m in dead))
            print("    这些模型的成绩不可用（网关/上游问题，不是卡片问题）。"
                  "把它们加进 models.json 的 skip，或等线路恢复再跑。")

        print("\n本轮产物：%s" % ev)
        print("下一步（必须做，否则下一轮就是在猜）：")
        print("  1. 打开上面那份证据表，看 §3 里标 MISSING 的候选禁用串；")
        print("  2. 把每一条转成 禁用串 / SCAN / BAD-GOOD 对，写进对应卡片的家族补丁"
              "（patch 片段放 patches/，用 apply.py 贴进卡片；")
        print("     `python apply.py <轮次tag> --top patches/<shared-top>.md "
              "--family <卡片名>=<片段.md>`，原文备份自动进 _backup-<tag>/）；")
        print("  3. `python stems.py`（要求未覆盖=0）+ `python consolidate.py budget`（卡片必须 <40000 B）；")
        print("  4. 复测：`python loop.py --skip-round1 --rounds %d --tag %s ...`，" % (n + 1, tag))
        print("     或做同刻成对对照 `python ab.py <模型> <题,题> <卡片.md>`（线路不稳时唯一可信的比法）。")
        print("  5. 四道验收闸跑一遍（04-console/selftest.py、03-bundle/pack.py、"
              "02-hubcore/build_hubcore.py --check、06-verify/probe_marker.py）。")
    print("\n全部轮次结束。记忆写进 破甲交接.md，别只留在这一场对话里。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
