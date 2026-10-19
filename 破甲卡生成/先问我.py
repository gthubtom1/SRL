#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""开跑前的体检 + 问询。

为什么要有它：横扫要三样东西 —— **能用的模型、接口地址、令牌** ——
其中两样（地址、令牌）在每台机器上都不同，而且**不能猜**（本模块规则 1：
探测/声明优先，不臆造端点）。以前的做法是让脚本在 import 时抛一句干巴巴的报错，
接手的人只看到「no endpoint」，不知道下一步该干什么。

这个脚本把「该问主人什么」直接印出来，问完把答案落盘，再跑横扫。

用法（在 07-kernel-sweep/ 下）：

    python 先问我.py                  # 体检 + 打印该问主人的问题（默认）
    python 先问我.py --check          # 同上，但只输出一行结论 + 退出码
    python 先问我.py --json           # 机器可读，给智能体用
    python 先问我.py --set base=<URL>
    python 先问我.py --set token=<KEY>
    python 先问我.py --set models=<id,id,id>

退出码：
    0 = 三样齐全，可以开跑
    2 = 还缺东西（下面会写清楚缺哪样、该问主人什么）

凭据落盘位置（两处都已被 kernel/.gitignore 挡住，不会进版本库）：
    .base   —— 一行 URL
    .token  —— 一行 key
"""

from __future__ import annotations

import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")
MODELS_JSON = os.path.join(HERE, "models.json")
BASE_FILE = os.path.join(HERE, ".base")
TOKEN_FILE = os.path.join(HERE, ".token")
CARDS_ROOT = os.path.normpath(os.path.join(HERE, "..", "04-console", "cards"))

# client.py 也会看这两处宿主 profile，保持一致
PROFILE_CANDS = (
    os.path.join(HOME, ".dsh", "profiles", "web", "cordis.patch.yml"),
    os.path.join(HOME, ".dsh", "profiles", "desktop", "cordis.patch.yml"),
)


# ──────────────────────────────────────────────────────────────── 探测（只读，不抛）

def resolve_base():
    """返回 (值, 来源)。找不到返回 (None, None)。**不猜、不臆造。**"""
    env = (os.environ.get("HUBCORE_BASE") or "").strip()
    if env:
        return env.rstrip("/"), "环境变量 HUBCORE_BASE"
    if os.path.exists(BASE_FILE):
        v = io.open(BASE_FILE, encoding="utf-8").read().strip()
        if v:
            return v.rstrip("/"), ".base"
    for cand in PROFILE_CANDS:
        if not os.path.exists(cand):
            continue
        try:
            for line in io.open(cand, encoding="utf-8", errors="replace"):
                m = re.search(r"^\s*baseURL:\s*['\"]?([^'\"\s]+)", line)
                if m:
                    return m.group(1).strip().rstrip("/"), os.path.relpath(cand, HOME)
        except OSError:
            continue
    return None, None


def resolve_token():
    env = (os.environ.get("HUBCORE_API_TOKEN") or "").strip()
    if env:
        return env, "环境变量 HUBCORE_API_TOKEN"
    if os.path.exists(TOKEN_FILE):
        v = io.open(TOKEN_FILE, encoding="utf-8").read().strip()
        if v:
            return v, ".token"
    return None, None


def mask(secret):
    if not secret:
        return "(空)"
    if len(secret) <= 8:
        return secret[0] + "*" * (len(secret) - 1)
    return "%s***%s  (%d 字符)" % (secret[:4], secret[-4:], len(secret))


def load_models():
    if not os.path.exists(MODELS_JSON):
        return None, "models.json 不存在"
    try:
        d = json.load(io.open(MODELS_JSON, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, "models.json 读不出来：%s" % exc
    return d, None


def card_path(rel):
    return os.path.normpath(os.path.join(CARDS_ROOT, rel))


def survey():
    """一次拿全状态。**只读** —— 一个字节都不写。"""
    st = {}
    st["base"], st["base_src"] = resolve_base()
    st["token"], st["token_src"] = resolve_token()

    d, err = load_models()
    st["models_err"] = err
    models, skip, missing_cards = [], [], []
    if d:
        skip = list(d.get("skip") or [])
        for m in d.get("models") or []:
            mid = m.get("id")
            card = m.get("card") or ""
            p = card_path(card)
            ok = bool(card) and os.path.exists(p)
            item = {"id": mid, "card": card, "exists": ok, "skipped": mid in skip}
            models.append(item)
            if not ok:
                missing_cards.append(item)
    st["models"] = models
    st["skip"] = skip
    st["missing_cards"] = missing_cards
    st["active"] = [m["id"] for m in models if not m["skipped"]]
    return st


# ──────────────────────────────────────────────────────────────── 落盘（写入）

def set_base(url):
    url = url.strip().rstrip("/")
    if not re.match(r"^https?://", url):
        print("✗ base 得是个 URL，形如 http://host/v1 —— 收到的是 %r" % url)
        return 2
    io.open(BASE_FILE, "w", encoding="utf-8", newline="\n").write(url + "\n")
    print("✓ 已写入 .base  →  %s" % url)
    return 0


def set_token(key):
    key = key.strip()
    if len(key) < 8:
        print("✗ 这个看着不像 key（%d 字符）—— 原样再贴一次" % len(key))
        return 2
    io.open(TOKEN_FILE, "w", encoding="utf-8", newline="\n").write(key + "\n")
    print("✓ 已写入 .token →  %s" % mask(key))
    return 0


def set_models(csv):
    d, err = load_models()
    if err:
        print("✗ %s" % err)
        return 2
    want = [x.strip() for x in csv.split(",") if x.strip()]
    known = [m.get("id") for m in d.get("models") or []]
    unknown = [x for x in want if x not in known]
    if unknown:
        print("✗ models.json 里没有这些模型名：%s" % ", ".join(unknown))
        print("  现有：%s" % ", ".join(known))
        print("  新模型要先在 models.json 的 models 里加一条（id + card）")
        return 2
    d["skip"] = [x for x in known if x not in want]
    io.open(MODELS_JSON, "w", encoding="utf-8", newline="\n").write(dump_models(d))
    print("✓ models.json 已更新")
    print("  本轮测：%s" % (", ".join(want) or "(空)"))
    print("  已 skip：%s" % (", ".join(d["skip"]) or "(无)"))
    return 0


def dump_models(d):
    """手写序列化 —— 保持 models.json 原本的「一行一个模型」紧凑排布。

    用 json.dumps(indent=2) 会把每条展开成 4 行，跑一次 --set 就把整个文件的
    diff 冲掉。这里刻意对齐列，让 diff 只落在真正改了的那几行上。
    """
    rows = d.get("models") or []
    width = max([len(m.get("id") or "") for m in rows] + [0]) + 4
    out = ["{", '  "_说明": %s,' % json.dumps(d.get("_说明", ""), ensure_ascii=False),
           '  "models": [']
    for i, m in enumerate(rows):
        mid = m.get("id") or ""
        card = m.get("card") or ""
        head = '    { "id": %s,' % json.dumps(mid, ensure_ascii=False)
        pad = " " * max(1, width - len(mid))
        line = head + pad + '"card": %s }' % json.dumps(card, ensure_ascii=False)
        out.append(line + ("," if i < len(rows) - 1 else ""))
    out.append("  ],")
    out.append('  "skip": [%s]' % ", ".join(json.dumps(x, ensure_ascii=False)
                                           for x in (d.get("skip") or [])))
    out.append("}")
    return "\n".join(out) + "\n"


# ──────────────────────────────────────────────────────────────── 问询（打印）

BAR = "═" * 68


def render(st, force_full=False):
    """把「该问主人什么」印出来。缺什么问什么，齐了就说齐了。"""
    need = []
    if not st["base"]:
        need.append("base")
    if not st["token"]:
        need.append("token")
    if not st["active"]:
        need.append("models")
    if st["missing_cards"]:
        need.append("cards")

    if not need:
        print("✓ 三样齐全，可以开跑。")
        print("  endpoint : %s            （来自 %s）" % (st["base"], st["base_src"]))
        print("  token    : %s  （来自 %s）" % (mask(st["token"]), st["token_src"]))
        print("  本轮模型 : %s" % ", ".join(st["active"]))
        print("  题集     : items/extreme41.md（默认）")
        print()
        print("  下一步：")
        print("    python loop.py --items items/extreme41.md \\")
        print("           --models %s --rounds 1 --tag S" % ",".join(st["active"]))
        return 0

    print(BAR)
    print("  破甲横扫 · 开跑前先问主人（**不要自己猜**）")
    print(BAR)
    print()

    n = 0

    # 1) 接口地址
    n += 1
    if st["base"]:
        print("【%d/4】接口地址          ✓ %s  （来自 %s）" % (n, st["base"], st["base_src"]))
    else:
        print("【%d/4】接口地址          ✗ 没有" % n)
        print("   → 问主人：「这轮破甲横扫走哪个中转站？给我 base URL，形如 http://host/v1」")
        print("   → 拿到后：python 先问我.py --set base=<URL>")
    print()

    # 2) 令牌
    n += 1
    if st["token"]:
        print("【%d/4】API 令牌          ✓ %s  （来自 %s）" % (n, mask(st["token"]), st["token_src"]))
    else:
        print("【%d/4】API 令牌          ✗ 没有" % n)
        print("   → 问主人：「那个站对应的 key 给我一下」")
        print("   → 拿到后：python 先问我.py --set token=<KEY>")
        print("      （写进 .token，已被 kernel/.gitignore 挡住，不会进版本库）")
    print()

    # 3) 本轮测哪些模型
    n += 1
    if st["models_err"]:
        print("【%d/4】本轮测哪些模型     ✗ %s" % (n, st["models_err"]))
        print("   → 问主人：「这轮测哪几个模型？」")
    elif not st["active"]:
        print("【%d/4】本轮测哪些模型     ✗ 一个都没选（models.json 里全是 skip）" % n)
        print("   → 问主人：「这轮测哪几个？现有：%s」" % ", ".join(x["id"] for x in st["models"]))
        print("   → 拿到后：python 先问我.py --set models=<id,id>")
    else:
        print("【%d/4】本轮测哪些模型     ⚠ 现在会跑 %s" % (n, ", ".join(st["active"])))
        print("   → 跟主人确认一句：「这轮就测这几个？」；要改：python 先问我.py --set models=<id,id>")
    if st["skip"]:
        print("      （skip：%s）" % ", ".join(st["skip"]))
    print()

    # 4) 改哪份提示词
    n += 1
    if st["missing_cards"]:
        print("【%d/4】改哪份提示词       ⚠ models.json 里有 %d 条指向**不存在的卡**" % (n, len(st["missing_cards"])))
        for m in st["missing_cards"][:8]:
            print("      %-34s → %s" % (m["id"], m["card"]))
        if len(st["missing_cards"]) > 8:
            print("      …… 还有 %d 条" % (len(st["missing_cards"]) - 8))
        print("   → 问主人：「这几张卡路径对不上，是挪位置了还是不用了？这次优化哪一张？」")
        print("      卡片实际在：kernel/04-console/cards/{base,hub,guest,_pending,_park,暂时不用}/")
    else:
        print("【%d/4】改哪份提示词       → 问主人一句就行：「这次优化哪张卡？」" % n)
        print("      （models.json 里的 card 字段就是默认答案，全部存在）")
    print()

    print("─" * 68)
    print("  配置没齐之前，loop.py / sweep.py **会直接拒绝启动** —— 这是设计，不是故障。")
    print("  问到的答案用 `--set` 落盘，下次就不用再问。")
    return 2


def main():
    a = sys.argv[1:]
    if a and a[0] == "--set":
        if len(a) < 2 or "=" not in a[1]:
            print("用法：python 先问我.py --set base=<URL> | token=<KEY> | models=<id,id>")
            return 2
        k, v = a[1].split("=", 1)
        k = k.strip().lower()
        if k == "base":
            return set_base(v)
        if k == "token":
            return set_token(v)
        if k == "models":
            return set_models(v)
        print("✗ 不认识的键 %r —— 只有 base / token / models" % k)
        return 2

    st = survey()

    if "--json" in a:
        print(json.dumps({
            "ready": not (not st["base"] or not st["token"] or not st["active"]),
            "base": st["base"], "base_src": st["base_src"],
            "token_set": bool(st["token"]), "token_src": st["token_src"],
            "active_models": st["active"], "skip": st["skip"],
            "missing_cards": [{"id": m["id"], "card": m["card"]} for m in st["missing_cards"]],
            "cards_root": CARDS_ROOT,
        }, ensure_ascii=False, indent=2))
        return 0 if (st["base"] and st["token"] and st["active"]) else 2

    if "--check" in a:
        missing = []
        if not st["base"]:
            missing.append("接口地址")
        if not st["token"]:
            missing.append("API 令牌")
        if not st["active"]:
            missing.append("本轮模型")
        if missing:
            print("✗ 还缺：%s  —— 跑 `python 先问我.py` 看该问主人什么" % "、".join(missing))
            return 2
        print("✓ 配置齐全：%s 个模型 · endpoint %s · token %s"
              % (len(st["active"]), st["base"], mask(st["token"])))
        return 0

    return render(st)


if __name__ == "__main__":
    sys.exit(main())
