# -*- coding: utf-8 -*-
"""架构不变量（Architecture Invariants）—— 一张矩阵覆盖全部 9 个域。

为什么要有这个（2026-10-25 用户决定）：
    "真跑每个域"不可行，也不是成熟项目的做法。真正要保证的是**逻辑闭环**：
    只要下面这些不变量在每个域都成立，那么"某个域在真实任务里接不上"这一类失败
    在结构上就不可能发生。以后只在"违反不变量"时才动，不做总攻式重写。

用法：
    python Tool/scripts/invariants.py            # 人读矩阵
    python Tool/scripts/invariants.py --json     # 机读
    python Tool/scripts/invariants.py --check    # 有不变量不成立 → 退出码 1
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SKILL = os.path.join(ROOT, "Tool", "skill")
CFG = os.path.join(ROOT, "Tool", "config")

INVARIANTS = {
    "I1": "入口唯一：判型只在一处（seep-router），域不自称总控",
    "I2": "能力可达：pack.tools 里每个工具都有落点（脚本/能力表/内置命令）",
    "I3": "交接闭包：SKILL 里指向别处的路径都存在，且不指向自己",
    "I4": "证据同构：所有域的证据契约（require / 禁止的置信度）完全一致",
    "I5": "等级唯一：M1–M4 只在 seep-router 定义，其它域只引用",
    "I6": "失败可表达：每个域都有 invalidation（什么情况判废、回哪一层）",
    "I7": "见证可跑：每个域的 witness_tool 脚本文件真实存在",
    "I8": "部署等价：仓库技能 ↔ 已部署技能 哈希一致",
    "I9": "能力有路线：声明脱壳/加壳/加固的域必须指向 unpack-loop（否则遇加固样本会直接改产物）",
}


def _domains():
    out = []
    for d in sorted(glob.glob(os.path.join(SKILL, "*", "SKILL.md"))):
        name = os.path.basename(os.path.dirname(d))
        if name == "_pending":
            continue
        out.append(name)
    return out


def _pack(name):
    p = os.path.join(SKILL, name, "pack.json")
    if not os.path.isfile(p):
        return None
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _skill_text(name):
    p = os.path.join(SKILL, name, "SKILL.md")
    try:
        return open(p, encoding="utf-8", errors="replace").read()
    except Exception:  # noqa: BLE001
        return ""


def check(name):
    """对单个域返回 {invariant_id: (ok, note)}。"""
    res = {}
    txt = _skill_text(name)
    pk = _pack(name)
    is_router = name == "seep-router"
    is_crosscut = name == "unpack-loop"

    # I1 入口唯一
    if is_router:
        res["I1"] = (pk is None, "判型层无 pack（不参与路由）" if pk is None else "判型层竟然有 pack")
    elif "总控" in txt.split("##")[0]:
        res["I1"] = (False, "域在自己的头部自称总控")
    else:
        res["I1"] = (True, "不自称总控")

    # I2 能力可达
    if pk is None:
        res["I2"] = (True, "无 pack（横切/判型层）")
    else:
        caps = {}
        try:
            caps = json.load(open(os.path.join(CFG, "tool-capabilities.json"), encoding="utf-8"))
        except Exception:  # noqa: BLE001
            pass
        cap_ids = set((caps.get("tools") or {}).keys()) if isinstance(caps, dict) else set()
        if isinstance(caps, dict) and not cap_ids:
            cap_ids = {t.get("id") for t in (caps.get("capabilities") or []) if isinstance(t, dict)}
        # MCP 工具（seep_*）在服务端注册，不在能力表里 —— 从服务端源码与副作用表里取名字
        for src in (os.path.join(ROOT, "Tool", "mcp", "seep_mcp_server.py"),
                    os.path.join(CFG, "tool-effects.json")):
            try:
                raw = open(src, encoding="utf-8", errors="replace").read()
            except Exception:  # noqa: BLE001
                continue
            cap_ids |= set(re.findall(r'name="(seep_[a-z0-9_]+)"', raw))
            cap_ids |= set(re.findall(r'"(seep_[a-z0-9_]+)"\s*:', raw))
        missing = []
        for t in pk.get("tools") or []:
            base = os.path.basename(str(t))
            local = os.path.join(SKILL, name, "scripts", base)
            in_caps = base in cap_ids or base.rstrip(".py") in cap_ids
            has_local = os.path.isfile(local)
            has_scripts = bool(glob.glob(os.path.join(ROOT, "Tool", "scripts", base))) or \
                bool(glob.glob(os.path.join(ROOT, "Tool", "scripts", "**", base), recursive=True))
            if not (in_caps or has_local or has_scripts):
                missing.append(base)
        res["I2"] = (not missing, "缺落点：%s" % "、".join(missing) if missing else "全部有落点")

    # I3 交接闭包
    refs = re.findall(r"Tool/skill/([A-Za-z0-9_.-]+)/SKILL\.md", txt)
    bad = []
    for r in set(refs):
        tgt = os.path.join(SKILL, r, "SKILL.md")
        if not os.path.isfile(tgt):
            bad.append("指向不存在的域 %s" % r)
        if r == name and not is_crosscut:
            bad.append("指向自己（%s）" % name)
    res["I3"] = (not bad, "；".join(bad) if bad else "引用 %d 个域，全部存在" % len(set(refs)))

    # I4 证据同构
    baseline = {"required_fields": ["claim", "confidence", "authority", "evidence"],
                "authority_allow": ["shipped-artifact", "controlled-replay", "external-service"],
                "pass_forbids_confidence": ["inferred", "unknown"]}
    if pk is None:
        res["I4"] = (True, "无 pack")
    else:
        ec = pk.get("evidence_contract") or {}
        same = all(sorted(ec.get(k) or []) == sorted(v) for k, v in baseline.items())
        res["I4"] = (same, "契约一致" if same else "契约与基线不同：%s" % json.dumps(ec, ensure_ascii=False)[:80])

    # I5 等级唯一
    if is_router:
        ok = all(m in txt for m in ("M1", "M2", "M3", "M4"))
        res["I5"] = (ok, "M1–M4 在此定义" if ok else "router 未定义全四级")
    else:
        mentions = re.findall(r"\bM[1-4]\b", txt)
        if not mentions:
            res["I5"] = (True, "未自造等级（不涉及）")
        else:
            points = "seep-router" in txt
            res["I5"] = (points, "引用 router 的等级" if points else "用了 M 级但没引用 seep-router")

    # I6 失败可表达
    if pk is None:
        ok = "## 什么时候停" in txt or "判废" in txt or "不适用" in txt
        res["I6"] = (ok, "有停止条件" if ok else "缺停止/判废条件")
    else:
        inv = pk.get("invalidation") or []
        res["I6"] = (bool(inv), "invalidation %d 条" % len(inv) if inv else "缺 invalidation")

    # I7 见证可跑
    wt = (pk or {}).get("witness_tool") or {}
    cmd = str(wt.get("cmd") or "")
    if not cmd:
        res["I7"] = (is_crosscut or is_router, "无 witness_tool（判型/横切层可接受）")
    else:
        base = os.path.basename(cmd.split()[0] if cmd.split() else "")
        p1 = os.path.join(SKILL, name, "scripts", base)
        p2 = os.path.join(ROOT, "Tool", "scripts", base)
        res["I7"] = (os.path.isfile(p1) or os.path.isfile(p2), base if (os.path.isfile(p1) or os.path.isfile(p2)) else "脚本不存在：%s" % base)

    # I8 部署等价
    dep = os.path.join(os.path.expanduser("~"), ".pi", "agent", "skills", name)
    if not os.path.isdir(dep):
        res["I8"] = (False, "未部署")
    else:
        import hashlib

        def h(p):
            return hashlib.sha256(open(p, "rb").read()).hexdigest()

        diffs = []
        for rel in ("SKILL.md", "pack.json"):
            src = os.path.join(SKILL, name, rel)
            dst = os.path.join(dep, rel)
            if os.path.isfile(src) and (not os.path.isfile(dst) or h(src) != h(dst)):
                diffs.append(rel)
        res["I8"] = (not diffs, "一致" if not diffs else "不一致：%s" % "、".join(diffs))
    # I9 能力有路线
    if is_crosscut or is_router:
        res["I9"] = (True, "判型/横切层不适用")
    elif re.search(r"脱壳|加壳|加固", txt):
        res["I9"] = ("unpack-loop" in txt, "有指针" if "unpack-loop" in txt else "声明了脱壳能力但没有路线指针")
    else:
        res["I9"] = (True, "未声明脱壳能力")

    return res


def main():
    doms = _domains()
    rows = {d: check(d) for d in doms}
    json_out = "--json" in sys.argv
    fails = []
    for d, r in rows.items():
        for iid, (ok, note) in r.items():
            if not ok:
                fails.append((d, iid, note))
    if json_out:
        print(json.dumps({"domains": doms, "invariants": INVARIANTS,
                          "matrix": {d: {k: {"ok": v[0], "note": v[1]} for k, v in r.items()}
                                     for d, r in rows.items()},
                          "fails": [{"domain": d, "invariant": i, "note": n} for d, i, n in fails]},
                         ensure_ascii=False, indent=1))
    else:
        ids = list(INVARIANTS)
        print("架构不变量矩阵（%d 域 × %d 条）\n" % (len(doms), len(ids)))
        print("域".ljust(22) + " ".join(ids))
        for d in doms:
            line = d.ljust(20)
            for i in ids:
                ok = rows[d][i][0]
                line += " %s " % ("✓" if ok else "✗")
            print(line)
        print()
        for i in ids:
            print("%s %s" % (i, INVARIANTS[i]))
            bad = [(d, rows[d][i][1]) for d in doms if not rows[d][i][0]]
            for d, note in bad:
                print("     ✗ %-20s %s" % (d, note))
        print()
        print("结论：%s" % ("全部不变量成立（%d 域一次覆盖）" % len(doms) if not fails
                          else "%d 处违反" % len(fails)))
    if "--check" in sys.argv:
        return 1 if fails else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
