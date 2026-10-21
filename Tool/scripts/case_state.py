#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""case_state.py —— 案子的事实账 / 深度门 / 可行性裁定 / 出口闸。

存在的原因（血案）：
    一次会话在第 20 秒就报出"权威在客户端"的结论（照抄上一轮报告），3 分 46 秒开始造交付物，
    3.5 小时后发现方向从一开始就错，中途改判 4 次且全部静默。
    问题不是"分析太少"，而是**结论没有证据、也没有任何东西拦住它往下走**。

    光在技能里写规则没用 —— 这次就把规则变成可执行的闸：
      1. 结论必须落成 claim（带 status / evidence / how / ttl）；
      2. 深度 D0–D5 必须逐级登记（做到 / 做不到 + 原因）；
      3. 可行性裁定必须显式写（可赢 / 部分可赢 / 不可赢 + 交付上限）；
      4. `gate` 子命令把上面三条合成一个退出码 —— 过了才允许进下一阶段。

用法：
    python Tool/scripts/case_state.py init    --case <目录> --target <样本>
    python Tool/scripts/case_state.py claim   --case <目录> --id C01 --text "权威在服务端" \\
                                              --status hypothesis --how "triage" 
    python Tool/scripts/case_state.py prove   --case <目录> --id C01 --evidence "procmon: 第1秒 winhttp 请求"
    python Tool/scripts/case_state.py refute  --case <目录> --id C01 --by "C05"
    python Tool/scripts/case_state.py depth   --case <目录> --level D2 --result pass --note "LoadLibrary 命中 winhttp"
    python Tool/scripts/case_state.py stale   --case <目录> --reason "换 exe:sha256 变了"
    python Tool/scripts/case_state.py gaps    --case <目录> --add --id G1 --missing "有效卡密" \
                                              --impact "拿不到合法响应" --repairable no \
                                              --delta -0.45 --alt "买真卡|旧版存档"
    python Tool/scripts/case_state.py gaps    --case <目录> --list
    python Tool/scripts/case_state.py plan    --case <目录> --level L2 --route "字节补丁" \
                                              --p 0.85 --hours "1-2" --needs "" --fail "打完仍无界面"
    python Tool/scripts/case_state.py plan    --case <目录> --list
    python Tool/scripts/case_state.py choose  --case <目录> --level L2 --route "字节补丁"
    python Tool/scripts/case_state.py advise  --case <目录> --form pe-shelled
    python Tool/scripts/case_state.py verdict --case <目录> --value 部分可赢 --note "缺有效卡密(G1)，钥匙在服务端"
    python Tool/scripts/case_state.py gate    --case <目录>
    python Tool/scripts/case_state.py show    --case <目录>
    python Tool/scripts/case_state.py resume  --case <目录>

阶段零出口物（B 批新增）：
    facts.jsonl + state.json + gaps.json + plan.json（含 chosen / goal_level）。
    gate 除原有断言外，还要求：stale 全部复验、plan ≥2 条候选、verdict 后必须 choose、
    不可补缺件要写进 verdict note 且菜单里不得有依赖它的路线。

退出码：gate 0=通过 / 1=未通过；其它命令 0=成功 / 2=参数或状态错误
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

LEVELS = ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7"]
CORE_LEVELS = ["D0", "D1", "D2", "D3", "D4", "D5"]
# 旧案扩展级：缺失只告警、不阻断；但裁定=可赢时必须至少 na + 原因（见 gate）
OPTIONAL_LEVELS = ["D6", "D7"]
LEVEL_NAME = {
    "D0": "结构（节表/资源/导入/字符串/熵）",
    "D1": "存活（能否到第一个窗口；双击与程序拉起分开测）",
    "D2": "动态依赖（运行时实际加载的网络/加密库）",
    "D3": "出站行为（DNS/TCP/明文或TLS/时间点）",
    "D4": "对照实验（断网/换目录/改时间）",
    "D5": "钥匙归属（文件/内存/授权后产生）",
    "D6": "kill-switch 层数（几层独立闸门、是否逐层验证）",
    "D7": "静默失败面（进程活着但不干活：网络/文件/窗口/API 序列四路）",
}
PLAN_LEVELS = ["L0", "L1", "L2", "L3", "L4"]
GAP_REPAIRABLE = ["yes", "no", "partial"]
# 缺件规则：repairable=no 且 delta <= 此值 → 阻断（note 必须提、菜单不得依赖）
GAP_DELTA_BLOCK = -0.3
CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")
VERDICTS = ["可赢", "部分可赢", "不可赢"]
INSTRUMENTS = ["baseline", "x64dbg", "frida-spawn", "frida-attach", "external", "network"]
INSTRUMENT_NAME = {
    "baseline": "裸启动（双击 / explorer，不挂任何仪器）",
    "x64dbg": "调试器 attach（最容易被反调试干掉）",
    "frida-spawn": "Frida spawn（-f，启动即挂）",
    "frida-attach": "Frida attach（进程起来后挂）",
    "external": "外部观测（Procmon / ETW / 文件与注册表快照 diff）",
    "network": "网络层（代理 / 抓包 / 冒充服务器）",
}
ISTATUS = ["ok", "partial", "blocked", "killed"]
MAX_LEVEL_BY_VERDICT = {"可赢": "M3", "部分可赢": "M2", "不可赢": "M1"}
# 后端档位（05-backend-rebuild 三问定档）：不可赢恒 M1；否则 T1→基准、T2→M3、T3→M4
TIERS = ["T1", "T2", "T3"]
STATUSES = ["hypothesis", "proven", "refuted"]


def paths(case):
    d = os.path.abspath(case)
    return d, os.path.join(d, "facts.jsonl"), os.path.join(d, "state.json")


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _manifest(case):
    return os.path.join(os.path.abspath(case), "ai_manifest.json")


def load_state(case):
    """案子状态。上游约定：`<case>/ai_manifest.json` 是唯一恢复点。

    因此：有 manifest 就把它里面的 `seep` 子键当状态（不另开第二份状态）；
    没有 manifest（非上游 CTF 案子）才退回 `<case>/state.json`。
    两套案子共用同一恢复协议，避免"同一目录两套状态互不知道"。
    """
    d, _, sp = paths(case)
    if not os.path.isdir(d):
        die("case 目录不存在：%s\n先跑：case_state.py init --case %s --target <样本>" % (d, case))
    mf = _manifest(case)
    if os.path.isfile(mf):
        try:
            with open(mf, encoding="utf-8") as f:
                man = json.load(f)
            if isinstance(man.get("seep"), dict):
                return man["seep"]
        except Exception:
            pass
    if os.path.isfile(sp):
        with open(sp, encoding="utf-8") as f:
            return json.load(f)
    return {"schema": "seep-case/1", "target": "", "depth": {}, "verdict": None,
            "max_level": None, "next_action": "", "updated": now()}


def save_state(case, st):
    """写回。有 ai_manifest.json 就写进它的 `seep` 子键；否则写 state.json。"""
    st["updated"] = now()
    mf = _manifest(case)
    if os.path.isfile(mf):
        try:
            with open(mf, encoding="utf-8") as f:
                man = json.load(f)
        except Exception:
            man = {}
        man["seep"] = st
        man.setdefault("schema", "reverselab.ai_manifest.v1")
        with open(mf, "w", encoding="utf-8") as f:
            json.dump(man, f, ensure_ascii=False, indent=2)
        return "ai_manifest.json#seep"
    _, _, sp = paths(case)
    with open(sp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=2)
    return "state.json"



def load_facts(case):
    _, fp, _ = paths(case)
    if not os.path.isfile(fp):
        return []
    out = []
    with open(fp, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError as e:
                    die("facts.jsonl 第 %d 行不是合法 JSON：%s（先修或备份后重写）" % (len(out) + 1, e))
    return out


def append_fact(case, fact):
    _, fp, _ = paths(case)
    with open(fp, "a", encoding="utf-8") as f:
        f.write(json.dumps(fact, ensure_ascii=False) + "\n")


def die(msg, code=2):
    print(f"[ERR] {msg}")
    sys.exit(code)


def _json_path(case, name):
    return os.path.join(os.path.abspath(case), name)


def _load_list(case, name):
    p = _json_path(case, name)
    if not os.path.isfile(p):
        return []
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        die("%s 不是合法 JSON：%s（先修或备份后重写）" % (name, e))
    if not isinstance(data, list):
        die("%s 顶层必须是数组" % name)
    return data


def _save_list(case, name, data):
    with open(_json_path(case, name), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_gaps(case):
    return _load_list(case, "gaps.json")


def save_gaps(case, gaps):
    _save_list(case, "gaps.json", gaps)


def load_plan(case):
    return _load_list(case, "plan.json")


def save_plan(case, plan):
    _save_list(case, "plan.json", plan)


def _blocking_gaps(gaps):
    """不可补且概率折损够大的缺件：会关掉整条路线。"""
    out = []
    for g in gaps:
        if str(g.get("repairable") or "").lower() != "no":
            continue
        try:
            d = float(g.get("delta") or 0)
        except (TypeError, ValueError):
            d = 0.0
        if d <= GAP_DELTA_BLOCK:
            out.append(g)
    return out


def _depends(route_item, gap):
    """路线是否显式依赖该缺件：看 needs 里有没有缺件 id 或缺少物名称。"""
    needs = str((route_item or {}).get("needs") or "").strip().lower()
    if not needs:
        return False
    gid = str(gap.get("id") or "").strip().lower()
    miss = str(gap.get("missing") or "").strip().lower()
    return bool((gid and gid in needs) or (miss and miss in needs))


def _mentions(text, gap):
    t = str(text or "").strip().lower()
    if not t:
        return False
    gid = str(gap.get("id") or "").strip().lower()
    miss = str(gap.get("missing") or "").strip().lower()
    return bool((gid and gid in t) or (miss and miss in t))


def _cfg(name):
    p = os.path.join(CONFIG_DIR, name)
    if not os.path.isfile(p):
        die("缺配置文件：%s（应随仓库分发在 Tool/config/）" % p)
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        die("配置文件 %s 不是合法 JSON：%s" % (name, e))


def _score(hay, keys):
    h = str(hay or "").lower()
    return sum(1 for k in (keys or []) if str(k).strip() and str(k).strip().lower() in h)


def print_plan(plan, title="路线菜单"):
    if not plan:
        print("  （空：还没有路线菜单）")
        return
    print("  %s（%d 条）：" % (title, len(plan)))
    print("    级   成功率  工时      选中  路线 / 失败判据")
    for x in plan:
        print("    %-4s %5.2f   %-8s  %-4s  %s" % (
            x.get("level", ""), float(x.get("p") or 0), str(x.get("hours") or "")[:8],
            "✓" if x.get("chosen") else "", x.get("route", "")))
        if (x.get("fail_criteria") or "").strip():
            print("          失败判据：%s" % x["fail_criteria"])
        if (x.get("needs") or "").strip():
            print("          依赖/缺件：%s" % x["needs"])


def print_gaps(gaps, title="缺件台账"):
    if not gaps:
        print("  （空：还没有登记缺件）")
        return
    print("  %s（%d 条）：" % (title, len(gaps)))
    for g in gaps:
        tag = "阻断" if g in _blocking_gaps(gaps) else ""
        print("    %-4s %-18s 可补性=%-7s Δ%-6s %s" % (
            g.get("id", ""), str(g.get("missing") or "")[:18],
            g.get("repairable", ""), g.get("delta", ""), tag))
        if (g.get("impact") or "").strip():
            print("          影响：%s" % g["impact"])
        if g.get("alt"):
            print("          替代：%s" % "、".join(g["alt"]))


# ---------------------------------------------------------------- commands
def cmd_init(a):
    d, fp, sp = paths(a.case)
    os.makedirs(d, exist_ok=True)
    mf = _manifest(a.case)
    # ★ 上游唯一恢复点：ai_manifest.json 里可能已有 seep 子键（甚至整份 CTF 进度）。
    #   没有 --force 就绝不覆盖 —— 否则 init 会静默清空已登记的深度/裁定（实测过的数据丢失）。
    if os.path.isfile(mf) and not a.force:
        try:
            with open(mf, encoding="utf-8") as f:
                man = json.load(f)
        except Exception:
            man = {}
        if isinstance(man.get("seep"), dict):
            die("ai_manifest.json 里已有 seep 状态；要重建加 --force（当前不会覆盖）")
    if os.path.isfile(sp) and not a.force:
        die("已有 state.json：%s（要重建加 --force）" % sp)
    st = {"schema": "seep-case/1", "target": os.path.abspath(a.target) if a.target else "",
          "depth": {}, "verdict": None, "max_level": None,
          "next_action": "跑 D0 结构 + D1 存活", "updated": now()}
    backend = save_state(a.case, st)
    open(fp, "a", encoding="utf-8").close()
    print("[OK] 案子已建：%s  facts: %s  state: %s" % (d, fp, backend))



def cmd_claim(a):
    facts = load_facts(a.case)
    if any(f["id"] == a.id for f in facts):
        die(f"claim {a.id} 已存在（要改用它自己的 prove/refute 子命令）")
    if a.status not in STATUSES:
        die(f"status 只能是 {STATUSES}")
    if not (a.text or "").strip():
        die("claim 的 --text 不能为空（一句话语义是证据索引）")
    by = (getattr(a, "by", "") or "").strip()
    if a.status == "refuted" and not by:
        die("refuted 必须带非空 --by（指向推翻它的证据/claim id），否则历史不可追溯")
    ev = (a.evidence or "").strip()
    if a.status == "proven" and not ev:
        die("proven 必须带非空 --evidence（空串/空格不算证据；没有证据只能写 hypothesis）")
    fact = {"id": a.id, "claim": a.text, "status": a.status,
            "evidence": [ev] if ev else [],
            "how": a.how or "", "ttl": (a.ttl or "").strip(), "created": now(),
            "refuted_by": (by or None)}
    append_fact(a.case, fact)
    print(f"[OK] {a.id} = {a.status}  {a.text}")


def _rewrite_facts(case, facts):
    _, fp, _ = paths(case)
    with open(fp, "w", encoding="utf-8") as f:
        for x in facts:
            f.write(json.dumps(x, ensure_ascii=False) + "\n")


def cmd_prove(a):
    ev = (a.evidence or "").strip()
    if not ev:
        die("prove 必须带非空 --evidence（空串/空格不算证据）")
    facts = load_facts(a.case)
    hit = next((f for f in facts if f["id"] == a.id), None)
    if not hit:
        die(f"没有 claim {a.id}")
    was_stale = hit.get("status") == "stale"
    if was_stale:
        # 复验复活：保留失效原因做审计，但状态回 proven、证据追加
        hit.setdefault("stale_history", []).append(
            {"reason": hit.get("stale_reason") or "", "at": hit.get("staled_at") or ""})
        hit.pop("stale_reason", None)
        hit.pop("staled_at", None)
        hit["revalidated_at"] = now()
    hit["status"] = "proven"
    hit["evidence"] = (hit.get("evidence") or []) + [ev]
    hit["updated"] = now()
    _rewrite_facts(a.case, facts)
    tail = "（原 stale 已复验复活）" if was_stale else ""
    print(f"[OK] {a.id} 已证实{tail}（证据 {len(hit['evidence'])} 条）")


def cmd_refute(a):
    by = (a.by or "").strip()
    if not by:
        die("refute 必须带非空 --by（指向推翻它的证据/claim id）")
    facts = load_facts(a.case)
    hit = next((f for f in facts if f["id"] == a.id), None)
    if not hit:
        die(f"没有 claim {a.id}")
    hit["status"] = "refuted"
    hit["refuted_by"] = by
    hit["updated"] = now()
    _rewrite_facts(a.case, facts)
    print(f"[OK] {a.id} 已标记被推翻，依据 = {a.by}（历史保留，不删）")


def cmd_stale(a):
    """TTL 失效：把当前所有 proven 降为 stale（保留证据，只改状态 + 失效原因）。

    典型触发：换了 exe（hash 变了）、目标更新、服务器换域名 —— 旧结论不再自动成立。
    复活方式：prove --id <id> --evidence "复验：..."（status 回 proven）。
    """
    reason = (a.reason or "").strip()
    facts = load_facts(a.case)
    proven = [f for f in facts if f.get("status") == "proven"]
    if not proven:
        die("没有 proven 的结论可作废（stale 只作用于已证事实）")
    ts = now()
    for f in proven:
        f["status"] = "stale"
        f["stale_reason"] = reason or "（未写原因）"
        f["staled_at"] = ts
        f["updated"] = ts
    _rewrite_facts(a.case, facts)
    print("[OK] %d 条 proven 已标为 stale，原因：%s" % (len(proven), reason or "（未写原因）"))
    print("     证据保留；复验用 prove --id <id> --evidence ...，否则 gate 拒绝")


def cmd_gaps(a):
    if not os.path.isdir(os.path.abspath(a.case)):
        die("case 目录不存在：%s" % os.path.abspath(a.case))
    gaps = load_gaps(a.case)
    if a.list_mode:
        print_gaps(gaps)
        return
    if not a.add:
        die("gaps 需要 --add（登记缺件）或 --list（查看）")
    gid = (a.id or "").strip()
    missing = (a.missing or "").strip()
    if not gid or not missing:
        die("缺件必须有 --id 与 --missing（缺什么）")
    if any(g.get("id") == gid for g in gaps):
        die(f"缺件 {gid} 已存在（要改请先手工编辑 gaps.json）")
    rep = (a.repairable or "").strip().lower()
    if rep not in GAP_REPAIRABLE:
        die(f"--repairable 只能是 {GAP_REPAIRABLE}")
    try:
        delta = float(a.delta)
    except (TypeError, ValueError):
        die("--delta 必须是数字（概率折损，如 -0.45）")
    if not (-1.0 <= delta <= 1.0):
        die("--delta 应在 -1.0 ~ 1.0 之间")
    alt = [x.strip() for x in (a.alt or "").split("|") if x.strip()]
    gap = {"id": gid, "missing": missing, "impact": (a.impact or "").strip(),
           "repairable": rep, "delta": delta, "alt": alt, "created": now()}
    gaps.append(gap)
    save_gaps(a.case, gaps)
    tag = "（阻断级：不可补且 Δ≤%.1f）" % GAP_DELTA_BLOCK if gap in _blocking_gaps([gap]) else ""
    print("[OK] 缺件 %s 已登记：%s  可补性=%s Δ%s %s" % (gid, missing, rep, delta, tag))


def cmd_plan(a):
    if not os.path.isdir(os.path.abspath(a.case)):
        die("case 目录不存在：%s" % os.path.abspath(a.case))
    if a.from_advise:
        return _plan_from_advise(a)
    plan = load_plan(a.case)
    if a.list_mode:
        print_plan(plan)
        return
    level = (a.level or "").strip().upper()
    route = (a.route or "").strip()
    if not level or not route:
        die("plan 需要 --level L0-L4 与 --route（或用 --list / --from-advise）")
    if level not in PLAN_LEVELS:
        die(f"level 只能是 {PLAN_LEVELS}")
    if a.p is None:
        die("plan 必须给 --p（成功率先验，0~1；不是拍脑袋，要写清乘出来的因子）")
    if not (0.0 <= float(a.p) <= 1.0):
        die("--p 必须在 0~1 之间")
    if any(x.get("level") == level and x.get("route") == route for x in plan):
        die(f"路线已存在：{level} {route}")
    item = {"level": level, "route": route, "p": float(a.p),
            "hours": (a.hours or "").strip(), "needs": (a.needs or "").strip(),
            "fail_criteria": (a.fail_criteria or "").strip(),
            "chosen": False, "created": now()}
    plan.append(item)
    save_plan(a.case, plan)
    print("[OK] 已登记路线 %s %s（p=%.2f，工时 %s）" % (level, route, item["p"], item["hours"] or "?"))
    print("     菜单共 %d 条；选定用 choose --level %s --route \"%s\"" % (len(plan), level, route))


def cmd_choose(a):
    level = (a.level or "").strip().upper()
    route = (a.route or "").strip()
    if level not in PLAN_LEVELS:
        die(f"level 只能是 {PLAN_LEVELS}")
    plan = load_plan(a.case)
    if not plan:
        die("还没有路线菜单（plan.json）：先 plan --add / plan --from-advise")
    hit = next((x for x in plan if x.get("level") == level and x.get("route") == route), None)
    if not hit:
        die("菜单里没有这条路线：%s %s（先 plan --list 看现有候选）" % (level, route))
    for x in plan:
        x["chosen"] = (x is hit)
    hit["chosen_at"] = now()
    save_plan(a.case, plan)
    st = load_state(a.case)
    st["goal_level"] = level
    st["goal_route"] = route
    st["next_action"] = "按 %s（%s）进 01-gate-bypass" % (level, route)
    save_state(a.case, st)
    print("[OK] 已选定 %s %s（p=%.2f，工时 %s）；state.goal_level = %s"
          % (level, route, float(hit.get("p") or 0), hit.get("hours") or "?", level))


def _pick_form(strat, form_arg, hay):
    forms = strat.get("forms") or []
    if not forms:
        die("strategy.json 里没有 forms")
    fa = (form_arg or "").strip()
    if fa:
        hit = next((f for f in forms if str(f.get("id", "")).lower() == fa.lower()), None)
        if hit:
            return hit, "explicit"
        best = max(forms, key=lambda f: _score(fa, f.get("match")))
        if _score(fa, best.get("match")) > 0:
            return best, "form-arg-match"
        die("strategy.json 没有形态 %s；可选：%s" % (fa, "、".join(str(f.get("id")) for f in forms)))
    best = max(forms, key=lambda f: _score(hay, f.get("match")))
    if _score(hay, best.get("match")) > 0:
        return best, "auto-match"
    gen = next((f for f in forms if f.get("id") == "generic"), forms[0])
    return gen, "fallback"


def _pick_family(matrix, hay):
    fams = matrix.get("families") or []
    if not fams:
        return None
    best = max(fams, key=lambda f: _score(hay, f.get("match")))
    return best if _score(hay, best.get("match")) > 0 else None


def _advise(a):
    """读 instrument-matrix + strategy，按 gaps/instruments 过滤，返回建议（不写盘）。"""
    st = load_state(a.case)
    facts = load_facts(a.case)
    gaps = load_gaps(a.case)
    inst = st.get("instruments") or {}
    matrix = _cfg("instrument-matrix.json")
    strat = _cfg("strategy.json")
    hay = " ".join([a.case, str(st.get("target") or "")]
                   + [str(f.get("claim") or "") for f in facts]
                   + [str(f.get("how") or "") for f in facts]
                   + list(inst.keys()))
    form, how = _pick_form(strat, getattr(a, "form", ""), hay)
    fam = _pick_family(matrix, hay + " " + str(form.get("id", "")) + " "
                       + " ".join(str(x) for x in (form.get("match") or [])))
    blocking = _blocking_gaps(gaps)
    banned = set(str(x) for x in ((fam or {}).get("banned") or []))
    dead = {k for k, v in inst.items() if str(v.get("status")) in ("blocked", "killed")}
    ok_routes, blocked_routes = [], []
    for r in form.get("routes") or []:
        reasons = []
        for g in blocking:
            if _depends({"needs": r.get("needs", "")}, g):
                reasons.append("依赖不可补缺件 %s（%s，Δ%s）" % (g.get("id"), g.get("missing"), g.get("delta")))
        for i in r.get("instruments") or []:
            if i in banned:
                reasons.append("仪器 %s 被壳族 %s 禁用" % (i, (fam or {}).get("id")))
            elif i in dead:
                reasons.append("仪器 %s 实测不可用（%s）" % (i, inst[i].get("status")))
        item = dict(r)
        item["reasons"] = reasons
        (blocked_routes if reasons else ok_routes).append(item)
    return {"form": form, "how": how, "family": fam, "blocking": blocking,
            "ok": ok_routes, "blocked": blocked_routes}


def _print_advise(res):
    form = res["form"]
    fam = res["family"]
    print("[建议] 形态 = %s（%s；匹配方式 %s）"
          % (form.get("id"), form.get("name") or "", res["how"]))
    if fam:
        print("  仪器族 = %s（%s）" % (fam.get("id"), fam.get("name") or ""))
        print("    可用仪器：%s" % ("、".join(fam.get("allowed") or []) or "-"))
        print("    禁用仪器：%s" % ("、".join(fam.get("banned") or []) or "-"))
        for p in (fam.get("pitfalls") or [])[:5]:
            print("    陷阱：%s" % p)
    if res["blocking"]:
        print("  阻断缺件（不可补且 Δ≤%.1f）：" % GAP_DELTA_BLOCK)
        for g in res["blocking"]:
            print("    %s %s  Δ%s  替代：%s"
                  % (g.get("id"), g.get("missing"), g.get("delta"),
                     "、".join(g.get("alt") or []) or "无"))
    print("  可选路线（%d）：" % len(res["ok"]))
    for r in res["ok"]:
        print("    %-3s %-24s p=%.2f  %-7s 失败判据：%s"
              % (r.get("level"), r.get("route"), float(r.get("p") or 0),
                 r.get("hours") or "?", r.get("fail") or ""))
    if res["blocked"]:
        print("  已剔除（%d）：" % len(res["blocked"]))
        for r in res["blocked"]:
            print("    %-3s %-24s — %s"
                  % (r.get("level"), r.get("route"), "；".join(r["reasons"])))
    print("  说明：advise 只输出建议、不写盘；确认后 plan --from-advise [--form <id>] 一次性导入")


def cmd_advise(a):
    res = _advise(a)
    _print_advise(res)
    if not res["ok"]:
        print("[WARN] 没有可行路线：缺件或仪器把菜单全关了 —— 先补缺件/换形态，别硬上")


def _plan_from_advise(a):
    res = _advise(a)
    if not res["ok"]:
        _print_advise(res)
        die("advise 没有给出可行路线，不能导入；先补缺件或换 --form")
    plan = load_plan(a.case)
    # ★ 从 advise 导入 = 以 advise 为准**重建**菜单（默认清空旧条目）。
    #   血案：只追加会让"已被缺件剔除的 L4"留在菜单里 → gate 永远因该条被拒。
    keep = bool(getattr(a, "keep", False))
    if not keep:
        plan = []
    added = 0
    for r in res["ok"]:
        if any(x.get("level") == r.get("level") and x.get("route") == r.get("route") for x in plan):
            continue
        plan.append({"level": r.get("level"), "route": r.get("route"),
                     "p": float(r.get("p") or 0), "hours": r.get("hours") or "",
                     "needs": r.get("needs") or "", "fail_criteria": r.get("fail") or "",
                     "chosen": False, "source": "advise:%s" % res["form"].get("id"),
                     "created": now()})
        added += 1
    save_plan(a.case, plan)
    print("[OK] 从 advise 导入 %d 条路线（形态 %s）；菜单共 %d 条"
          % (added, res["form"].get("id"), len(plan)))
    print_plan(plan)


def cmd_depth(a):
    if a.level not in LEVELS:
        die(f"level 只能是 {LEVELS}")
    if a.result not in ("pass", "fail", "na"):
        die("result 只能是 pass / fail / na")
    st = load_state(a.case)
    st["depth"][a.level] = {"result": a.result, "note": a.note or "", "ts": now()}
    save_state(a.case, st)
    print(f"[OK] {a.level} = {a.result}  {a.note or ''}")


def cmd_verdict(a):
    if a.value not in VERDICTS:
        die(f"verdict 只能是 {VERDICTS}")
    need = MAX_LEVEL_BY_VERDICT[a.value]
    tier = (getattr(a, "tier", "") or "").strip().upper()
    if tier and tier not in TIERS:
        die(f"tier 只能是 {TIERS}")
    # 档位规则（写明，避免"部分可赢+T2 直接跳 M4"的未定义行为）：
    #   不可赢 → 恒 M1；否则 T1 → 裁定基准（可赢 M3 / 部分可赢 M2）；T2 → M3；T3 → M4
    if a.value != "不可赢":
        if tier == "T2":
            need = "M3"
        elif tier == "T3":
            need = "M4"
    else:
        need = "M1"
    if a.max_level and a.max_level != need:
        die(f"{a.value}" + (f" + {tier}" if tier else "") + f" 对应的交付上限必须是 {need}（不能自己往上抬）")
    st = load_state(a.case)
    st["verdict"] = a.value
    st["tier"] = tier or None
    st["max_level"] = need
    st["verdict_note"] = a.note or ""
    st["next_action"] = "进 01-gate-bypass" if a.value != "不可赢" else "只交 M1 + 天花板声明，不许承诺成品"
    save_state(a.case, st)
    print(f"[OK] 裁定 = {a.value}，交付上限 = {need}")


def cmd_instrument(a):
    if a.name not in INSTRUMENTS:
        die(f"instrument 只能是 {INSTRUMENTS}")
    if a.status not in ISTATUS:
        die(f"status 只能是 {ISTATUS}")
    st = load_state(a.case)
    st.setdefault("instruments", {})[a.name] = {
        "status": a.status, "launch": a.launch or "", "note": a.note or "", "ts": now()}
    save_state(a.case, st)
    print(f"[OK] 仪器 {a.name} = {a.status}  {a.note or ''}")


def cmd_gate(a):
    st = load_state(a.case)
    facts = load_facts(a.case)
    plan = load_plan(a.case)
    gaps = load_gaps(a.case)
    depth = st.get("depth", {})
    bad = []
    warn = []

    # ---- 深度门：D0–D5 必填；D6/D7 只告警（旧案不因扩展级全红）
    missing = [lv for lv in CORE_LEVELS if lv not in depth]
    failed = [lv for lv in CORE_LEVELS if lv in depth and depth[lv].get("result") == "fail"]
    failed_opt = [lv for lv in OPTIONAL_LEVELS if depth.get(lv, {}).get("result") == "fail"]
    if missing:
        bad.append("深度未登记：" + "、".join(f"{lv}({LEVEL_NAME[lv]})" for lv in missing))
    if failed:
        bad.append("深度未通过：" + "、".join(failed))
    for lv in OPTIONAL_LEVELS:
        if lv not in depth:
            warn.append(f"{lv} 未登记（{LEVEL_NAME[lv]}）—— 老案子不阻断，但建议补；裁定=可赢时必填")
    for lv in failed_opt:
        warn.append(f"{lv} = fail（{LEVEL_NAME[lv]}）：该轴有未过的闸门，不能据此报「可赢」")

    # na 不能当洗白：D0–D5 必须写原因，且不许全 na（血案：全 na + 可赢 也能过闸）
    bare_na = [lv for lv, v in depth.items()
               if lv in CORE_LEVELS and v.get("result") == "na" and not (v.get("note") or "").strip()]
    if bare_na:
        bad.append("na 必须写原因：" + "、".join(bare_na))
    for lv in OPTIONAL_LEVELS:
        if lv in depth and depth[lv].get("result") == "na" and not (depth[lv].get("note") or "").strip():
            warn.append(f"{lv} 记了 na 但没写原因（可选级不阻断，但建议补；裁定=可赢时必填）")
    core_vals = [depth[lv] for lv in CORE_LEVELS if lv in depth]
    if core_vals and all(v.get("result") == "na" for v in core_vals):
        bad.append("D0–D5 全 na：等于什么都没做，不许出闸")
    passed = {lv for lv, v in depth.items() if v.get("result") == "pass"}
    need_by_verdict = {"可赢": {"D0", "D1", "D2", "D3", "D4"},
                       "部分可赢": {"D0", "D1", "D2", "D3"},
                       "不可赢": {"D0", "D1", "D2"}}

    proven = [f for f in facts if f["status"] == "proven"]
    if not proven:
        bad.append("没有任何已证事实（proven）：阶段零至少要有一条带证据的结论")

    naked = [f["id"] for f in facts
             if f["status"] == "proven"
             and not any(str(e).strip() for e in (f.get("evidence") or []))]
    if naked:
        bad.append("无证据的 proven：" + "、".join(naked))

    nohow = [f["id"] for f in facts
             if f["status"] == "proven" and not str(f.get("how") or "").strip()]
    if nohow:
        bad.append("proven 缺 how（怎么测的）：" + "、".join(nohow))

    # ---- TTL：stale 未复验 → 拒绝（证明可复活）
    stale = [f for f in facts if f.get("status") == "stale"]
    if stale:
        bad.append("有 %d 条结论已 stale 且未复验（%s）：先复验或说明为何仍成立 —— "
                   "prove --id <id> --evidence \"复验：...\""
                   % (len(stale), "、".join(f["id"] for f in stale)))

    if not st.get("verdict"):
        bad.append("未给可行性裁定（verdict）")
    else:
        need = need_by_verdict.get(st["verdict"], set())
        lack = sorted(need - passed)
        if lack:
            bad.append(f"裁定「{st['verdict']}」要求 {'/'.join(sorted(need))} 全部 pass，缺：" + "、".join(lack))

    # ---- 缺件经济学：不可补且 Δ≤-0.3 的缺件会关掉路线
    blocking = _blocking_gaps(gaps)
    if st.get("verdict"):
        note = st.get("verdict_note") or ""
        for g in blocking:
            if not _mentions(note, g):
                bad.append("裁定 note 必须提到不可补缺件 %s（%s，Δ%s）：它决定了哪级路线被关掉"
                           % (g.get("id"), g.get("missing"), g.get("delta")))
    for g in blocking:
        dep = [p for p in plan if _depends(p, g)]
        if dep:
            bad.append("菜单含依赖不可补缺件 %s（%s）的路线：%s —— 必须剔除"
                       % (g.get("id"), g.get("missing"),
                          "、".join("%s %s" % (p.get("level"), p.get("route")) for p in dep)))

    # ---- 路线菜单：至少 2 条候选；裁定后必须 choose
    if len(plan) < 2:
        bad.append("路线菜单（plan）不足 2 条候选（当前 %d）：先 advise 看建议，再 plan --add / plan --from-advise"
                   % len(plan))
    chosen = [p for p in plan if p.get("chosen")]
    if len(chosen) > 1:
        bad.append("菜单出现 %d 条 chosen：只能选定一条" % len(chosen))
    if st.get("verdict") and not chosen:
        bad.append("已给裁定但未 choose 路线：阶段一必须按选定等级执行（choose --level Lx --route ...）")
    if chosen and st.get("goal_level") and chosen[0].get("level") != st["goal_level"]:
        bad.append("chosen 与 state.goal_level 不一致（%s vs %s）：重跑 choose"
                   % (chosen[0].get("level"), st["goal_level"]))

    # ---- 可赢时 D6/D7 必须至少 na + 原因（防止拿「可赢」但没查 kill-switch / 静默失败）
    if st.get("verdict") == "可赢":
        lack_opt = [lv for lv in OPTIONAL_LEVELS
                    if lv not in depth or not (depth[lv].get("note") or "").strip()]
        if lack_opt:
            bad.append("裁定=可赢要求 D6/D7 至少 na 并写原因，缺：" + "、".join(lack_opt))
        if failed_opt:
            bad.append("裁定=可赢但 " + "、".join(failed_opt)
                       + " = fail（kill-switch / 静默失败面未过）")

    # I0：仪器可行性。血案——2 小时后才发现调试器一挂就自毁、Frida 早期挂载会被静默掐网络
    inst = st.get("instruments") or {}
    alive = [k for k, v in inst.items()
             if v.get("status") in ("ok", "partial") and k != "baseline"]
    if len(inst) < 2:
        bad.append("未登记仪器可行性（I0）：至少 2 种（如 frida-attach + external）")
    elif not alive:
        bad.append("所有仪器都被阻断：至少要有一种可观测手段（外部观测/网络层也算）")

    pend = [f["id"] for f in facts if f["status"] == "hypothesis"]
    if a.strict and pend:
        bad.append("仍有 hypothesis 未处理：" + "、".join(pend))

    if warn:
        print("[WARN] 不阻断的提醒：")
        for w in warn:
            print("   - " + w)

    if bad:
        print("[FAIL] 阶段零出口闸未通过：")
        for b in bad:
            print("   - " + b)
        print(f"\n事实：proven {sum(1 for f in facts if f['status']=='proven')} / "
              f"stale {len(stale)} / hypothesis {len(pend)} / "
              f"refuted {sum(1 for f in facts if f['status']=='refuted')}")
        print(f"菜单：{len(plan)} 条，chosen {len(chosen)}；缺件：{len(gaps)} 条（阻断 {len(blocking)}）")
        sys.exit(1)

    print(f"[PASS] 阶段零出口闸通过 —— 裁定 {st['verdict']}，交付上限 {st['max_level']}，"
          f"深度 {len(depth)}/{len(LEVELS)}，事实 {len(facts)} 条")
    if chosen:
        c = chosen[0]
        print(f"       选定路线：{c.get('level')} {c.get('route')}（p={float(c.get('p') or 0):.2f}，"
              f"工时 {c.get('hours') or '?'}，失败判据：{c.get('fail_criteria') or '未写'}）")
    print(f"       下一步：{st.get('next_action') or '进 01-gate-bypass'}")
    sys.exit(0)


RANK = {"M1": 1, "M2": 2, "M3": 3, "M4": 4}


def cmd_deliver(a):
    """交付分级闸：产物等级不许超过阶段零裁定的上限（血案：文件生成了就宣布可用）。"""
    st = load_state(a.case)
    if not st.get("verdict"):
        die("还没给可行性裁定（verdict），不许交付")
    cap = st.get("max_level") or "M1"
    if a.level not in RANK:
        die("level 只能是 M1 / M2 / M3 / M4")
    if RANK[a.level] > RANK.get(cap, 1):
        die(f"越级交付：裁定 {st['verdict']} 的上限是 {cap}，不接受 {a.level}")
    if not (a.evidence or "").strip():
        die("交付必须有可核对的证明（--evidence：截图路径 / 窗口标题 / 日志片段）")
    st.setdefault("deliveries", []).append(
        {"level": a.level, "evidence": a.evidence, "note": a.note or "", "ts": now()})
    st["next_action"] = {"M1": "补功能面，冲 M2", "M2": "冲 M3（UI/授权）",
                         "M3": "追版与维护", "M4": "维护"}.get(a.level, "")
    save_state(a.case, st)
    print(f"[OK] 已登记交付 {a.level}（上限 {cap}）：{a.evidence}")


def cmd_show(a):
    st = load_state(a.case)
    facts = load_facts(a.case)
    gaps = load_gaps(a.case)
    plan = load_plan(a.case)
    print(f"案子：{a.case}")
    print(f"  目标：{st.get('target') or '-'}")
    print(f"  裁定：{st.get('verdict') or '（未给）'}"
          + (f" / 后端档位 {st['tier']}" if st.get("tier") else "")
          + (f"   交付上限：{st.get('max_level') or '-'}"
             + (f"   选定等级：{st['goal_level']}"
                + (f"（{st['goal_route']}）" if st.get("goal_route") else "")
                if st.get("goal_level") else "")))
    if st.get("verdict_note"):
        print(f"  裁定理由：{st['verdict_note']}")
    inst = st.get("instruments") or {}
    if inst:
        print("  仪器（I0）：")
        for k, v in inst.items():
            print(f"    {k:<14} {v['status']:<8} {v.get('note','')}")
    print("  深度：")
    for lv in LEVELS:
        v = st.get("depth", {}).get(lv)
        optional = "（可选）" if lv in OPTIONAL_LEVELS else ""
        mark = v["result"] if v else "未登记"
        print(f"    {lv} {mark:<4} {LEVEL_NAME[lv]}{optional}"
              + (f"  — {v['note']}" if v and v.get("note") else ""))
    print_gaps(gaps)
    print_plan(plan)
    print(f"  事实（{len(facts)} 条）：")
    for f in facts:
        tag = {"proven": "已证", "hypothesis": "待验", "refuted": "已推翻",
               "stale": "失效"}.get(f["status"], f["status"])
        extra = f"  被 {f['refuted_by']} 推翻" if f.get("refuted_by") else ""
        if f.get("stale_reason"):
            extra += f"  stale: {f['stale_reason']}"
        print(f"    [{tag}] {f['id']:<6} {f['claim'][:52]}{extra}")


def cmd_resume(a):
    st = load_state(a.case)
    facts = load_facts(a.case)
    plan = load_plan(a.case)
    gaps = load_gaps(a.case)
    proven = [f for f in facts if f["status"] == "proven"]
    pend = [f for f in facts if f["status"] == "hypothesis"]
    stale = [f for f in facts if f["status"] == "stale"]
    print(f"[接续] {a.case}  裁定={st.get('verdict') or '未给'}  上限={st.get('max_level') or '-'}"
          + (f"  选定等级={st['goal_level']}"
             + (f"（{st['goal_route']}）" if st.get("goal_route") else "")
             if st.get("goal_level") else ""))
    print(f"  已证 {len(proven)} / 待验 {len(pend)} / "
          f"已推翻 {sum(1 for f in facts if f['status']=='refuted')} / stale {len(stale)}")
    if pend:
        print("  待验清单：" + "、".join(f["id"] for f in pend))
    if stale:
        print("  stale 待复验：" + "、".join(f["id"] for f in stale))
    print_gaps(gaps)
    print_plan(plan)
    dl = st.get("deliveries") or []
    if dl:
        print("  已登记交付：" + "、".join(f"{d['level']}({d['ts'][:16]})" for d in dl))
    print(f"  下一步：{st.get('next_action') or '（未写）'}")


def main():
    ap = argparse.ArgumentParser(description="案子事实账 / 深度门 / 可行性裁定 / 出口闸")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init"); p.add_argument("--case", required=True)
    p.add_argument("--target", default=""); p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("claim"); p.add_argument("--case", required=True)
    p.add_argument("--id", required=True); p.add_argument("--text", required=True)
    p.add_argument("--status", default="hypothesis"); p.add_argument("--evidence", default="")
    p.add_argument("--by", default="", help="status=refuted 时必填：谁推翻了它")
    p.add_argument("--how", default=""); p.add_argument("--ttl", default="")
    p.set_defaults(func=cmd_claim)

    p = sub.add_parser("prove"); p.add_argument("--case", required=True)
    p.add_argument("--id", required=True); p.add_argument("--evidence", required=True)
    p.set_defaults(func=cmd_prove)

    p = sub.add_parser("refute"); p.add_argument("--case", required=True)
    p.add_argument("--id", required=True); p.add_argument("--by", required=True)
    p.set_defaults(func=cmd_refute)

    p = sub.add_parser("stale", help="TTL 失效：把所有 proven 降为 stale（保留证据）")
    p.add_argument("--case", required=True)
    p.add_argument("--reason", default="", help="为何失效，如『换 exe:sha256 变了』")
    p.set_defaults(func=cmd_stale)

    p = sub.add_parser("gaps", help="缺件经济学：登记不可补/可补缺件与概率折损")
    p.add_argument("--case", required=True)
    p.add_argument("--add", action="store_true", help="登记一条缺件")
    p.add_argument("--list", dest="list_mode", action="store_true", help="列出缺件台账")
    p.add_argument("--id", default=""); p.add_argument("--missing", default="")
    p.add_argument("--impact", default="")
    p.add_argument("--repairable", default="", help="yes / no / partial")
    p.add_argument("--delta", default="0", help="概率折损（负数），如 -0.45")
    p.add_argument("--alt", default="", help="替代方案，用 | 分隔")
    p.set_defaults(func=cmd_gaps)

    p = sub.add_parser("plan", help="路线菜单（L0–L4 + 成功率 + 工时 + 失败判据）")
    p.add_argument("--case", required=True)
    p.add_argument("--level", default="", help="L0–L4")
    p.add_argument("--route", default="")
    p.add_argument("--p", type=float, default=None, help="成功率先验 0~1")
    p.add_argument("--hours", default=""); p.add_argument("--needs", default="")
    p.add_argument("--fail", dest="fail_criteria", default="", help="失败判据（什么现象就停手）")
    p.add_argument("--from-advise", action="store_true", help="把 advise 的可行路线一次性导入")
    p.add_argument("--form", default="", help="配合 --from-advise：指定形态 id")
    p.add_argument("--list", dest="list_mode", action="store_true")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("choose", help="从菜单选定一条路线，写 state.goal_level")
    p.add_argument("--case", required=True)
    p.add_argument("--level", required=True); p.add_argument("--route", required=True)
    p.set_defaults(func=cmd_choose)

    p = sub.add_parser("advise", help="按仪器/策略矩阵 + gaps 给建议菜单（不写盘）")
    p.add_argument("--case", required=True)
    p.add_argument("--form", default="", help="strategy.json 里的形态 id（如 pe-shelled）")
    p.set_defaults(func=cmd_advise)

    p = sub.add_parser("depth"); p.add_argument("--case", required=True)
    p.add_argument("--level", required=True); p.add_argument("--result", required=True)
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_depth)

    p = sub.add_parser("instrument"); p.add_argument("--case", required=True)
    p.add_argument("--name", required=True); p.add_argument("--status", required=True)
    p.add_argument("--launch", default=""); p.add_argument("--note", default="")
    p.set_defaults(func=cmd_instrument)

    p = sub.add_parser("verdict"); p.add_argument("--case", required=True)
    p.add_argument("--value", required=True)
    p.add_argument("--tier", default="", help="后端档位（见 05-backend-rebuild）：不可赢恒 M1；T1→裁定基准（可赢 M3/部分可赢 M2）；T2→M3；T3→M4")
    p.add_argument("--max-level", default="")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_verdict)

    p = sub.add_parser("gate"); p.add_argument("--case", required=True)
    p.add_argument("--strict", action="store_true", help="连 hypothesis 也不许留")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("deliver"); p.add_argument("--case", required=True)
    p.add_argument("--level", required=True); p.add_argument("--evidence", required=True)
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_deliver)

    p = sub.add_parser("show"); p.add_argument("--case", required=True); p.set_defaults(func=cmd_show)
    p = sub.add_parser("resume"); p.add_argument("--case", required=True); p.set_defaults(func=cmd_resume)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
