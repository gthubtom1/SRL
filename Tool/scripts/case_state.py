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
    python Tool/scripts/case_state.py verdict --case <目录> --value 部分可赢 --max-level M2 --note "钥匙在服务端"
    python Tool/scripts/case_state.py gate    --case <目录>
    python Tool/scripts/case_state.py show    --case <目录>
    python Tool/scripts/case_state.py resume  --case <目录>

退出码：gate 0=通过 / 1=未通过；其它命令 0=成功 / 2=参数或状态错误
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

LEVELS = ["D0", "D1", "D2", "D3", "D4", "D5"]
LEVEL_NAME = {
    "D0": "结构（节表/资源/导入/字符串/熵）",
    "D1": "存活（能否到第一个窗口；双击与程序拉起分开测）",
    "D2": "动态依赖（运行时实际加载的网络/加密库）",
    "D3": "出站行为（DNS/TCP/明文或TLS/时间点）",
    "D4": "对照实验（断网/换目录/改时间）",
    "D5": "钥匙归属（文件/内存/授权后产生）",
}
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
# 后端档位（05-backend-rebuild 的三问定档）：T2/T3 且非"不可赢"时，上限抬到 M4（客户端+后端自洽）
TIERS = ["T1", "T2", "T3"]
STATUSES = ["hypothesis", "proven", "refuted"]


def paths(case):
    d = os.path.abspath(case)
    return d, os.path.join(d, "facts.jsonl"), os.path.join(d, "state.json")


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def load_state(case):
    d, _, sp = paths(case)
    if not os.path.isdir(d):
        die(f"case 目录不存在：{d}\n先跑：case_state.py init --case {case} --target <样本>")
    if os.path.isfile(sp):
        with open(sp, encoding="utf-8") as f:
            return json.load(f)
    return {"schema": "seep-case/1", "target": "", "depth": {}, "verdict": None,
            "max_level": None, "next_action": "", "updated": now()}


def save_state(case, st):
    _, _, sp = paths(case)
    st["updated"] = now()
    with open(sp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=2)


def load_facts(case):
    _, fp, _ = paths(case)
    if not os.path.isfile(fp):
        return []
    out = []
    with open(fp, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def append_fact(case, fact):
    _, fp, _ = paths(case)
    with open(fp, "a", encoding="utf-8") as f:
        f.write(json.dumps(fact, ensure_ascii=False) + "\n")


def die(msg, code=2):
    print(f"[ERR] {msg}")
    sys.exit(code)


# ---------------------------------------------------------------- commands
def cmd_init(a):
    d, fp, sp = paths(a.case)
    os.makedirs(d, exist_ok=True)
    if os.path.isfile(sp) and not a.force:
        die(f"已有 state.json：{sp}（要重建加 --force）")
    st = {"schema": "seep-case/1", "target": os.path.abspath(a.target) if a.target else "",
          "depth": {}, "verdict": None, "max_level": None,
          "next_action": "跑 D0 结构 + D1 存活", "updated": now()}
    save_state(a.case, st)
    open(fp, "a", encoding="utf-8").close()
    print(f"[OK] 案子已建：{d}\n     facts: {fp}\n     state: {sp}")


def cmd_claim(a):
    facts = load_facts(a.case)
    if any(f["id"] == a.id for f in facts):
        die(f"claim {a.id} 已存在（要改用它自己的 prove/refute 子命令）")
    if a.status not in STATUSES:
        die(f"status 只能是 {STATUSES}")
    if a.status == "proven" and not a.evidence:
        die("proven 必须带 --evidence（没有证据的结论只能写 hypothesis）")
    if a.status == "refuted" and not a.by:
        die("refuted 必须带 --by（指向推翻它的证据/claim id），否则历史不可追溯")
    fact = {"id": a.id, "claim": a.text, "status": a.status,
            "evidence": [a.evidence] if a.evidence else [],
            "how": a.how or "", "ttl": a.ttl or "", "created": now(),
            "refuted_by": (a.by or None)}
    append_fact(a.case, fact)
    print(f"[OK] {a.id} = {a.status}  {a.text}")


def _rewrite_facts(case, facts):
    _, fp, _ = paths(case)
    with open(fp, "w", encoding="utf-8") as f:
        for x in facts:
            f.write(json.dumps(x, ensure_ascii=False) + "\n")


def cmd_prove(a):
    facts = load_facts(a.case)
    hit = next((f for f in facts if f["id"] == a.id), None)
    if not hit:
        die(f"没有 claim {a.id}")
    hit["status"] = "proven"
    hit["evidence"] = (hit.get("evidence") or []) + [a.evidence]
    hit["updated"] = now()
    _rewrite_facts(a.case, facts)
    print(f"[OK] {a.id} 已证实（证据 {len(hit['evidence'])} 条）")


def cmd_refute(a):
    facts = load_facts(a.case)
    hit = next((f for f in facts if f["id"] == a.id), None)
    if not hit:
        die(f"没有 claim {a.id}")
    hit["status"] = "refuted"
    hit["refuted_by"] = a.by
    hit["updated"] = now()
    _rewrite_facts(a.case, facts)
    print(f"[OK] {a.id} 已标记被推翻，依据 = {a.by}（历史保留，不删）")


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
    if tier in ("T2", "T3") and a.value != "不可赢":
        need = "M4"          # 后端要复刻且可行 → 允许交付到"客户端+后端自洽"
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
    bad = []

    missing = [lv for lv in LEVELS if lv not in st.get("depth", {})]
    failed = [lv for lv, v in st.get("depth", {}).items() if v.get("result") == "fail"]
    if missing:
        bad.append("深度未登记：" + "、".join(f"{lv}({LEVEL_NAME[lv]})" for lv in missing))
    if failed:
        bad.append("深度未通过：" + "、".join(failed))

    depth = st.get("depth", {})
    # na 不能当洗白：必须写原因，且不许六级全 na（血案：全 na + 可赢 也能过闸）
    bare_na = [lv for lv, v in depth.items() if v.get("result") == "na" and not (v.get("note") or "").strip()]
    if bare_na:
        bad.append("na 必须写原因：" + "、".join(bare_na))
    if depth and all(v.get("result") == "na" for v in depth.values()):
        bad.append("六级全 na：等于什么都没做，不许出闸")
    passed = {lv for lv, v in depth.items() if v.get("result") == "pass"}
    need_by_verdict = {"可赢": {"D0", "D1", "D2", "D3", "D4"},
                       "部分可赢": {"D0", "D1", "D2", "D3"},
                       "不可赢": {"D0", "D1", "D2"}}

    naked = [f["id"] for f in facts if f["status"] == "proven" and not f.get("evidence")]
    if naked:
        bad.append("无证据的 proven：" + "、".join(naked))

    nohow = [f["id"] for f in facts if f["status"] == "proven" and not f.get("how")]
    if nohow:
        bad.append("proven 缺 how（怎么测的）：" + "、".join(nohow))

    if not st.get("verdict"):
        bad.append("未给可行性裁定（verdict）")
    else:
        need = need_by_verdict.get(st["verdict"], set())
        lack = sorted(need - passed)
        if lack:
            bad.append(f"裁定「{st['verdict']}」要求 {'/'.join(sorted(need))} 全部 pass，缺：" + "、".join(lack))

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

    if bad:
        print("[FAIL] 阶段零出口闸未通过：")
        for b in bad:
            print("   - " + b)
        print(f"\n事实：proven {sum(1 for f in facts if f['status']=='proven')} / "
              f"hypothesis {len(pend)} / refuted {sum(1 for f in facts if f['status']=='refuted')}")
        sys.exit(1)

    print(f"[PASS] 阶段零出口闸通过 —— 裁定 {st['verdict']}，交付上限 {st['max_level']}，"
          f"深度 {len(st['depth'])}/{len(LEVELS)}，事实 {len(facts)} 条")
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
    print(f"案子：{a.case}")
    print(f"  目标：{st.get('target') or '-'}")
    print(f"  裁定：{st.get('verdict') or '（未给）'}"
          + (f" / 后端档位 {st['tier']}" if st.get("tier") else "")
          + f"   交付上限：{st.get('max_level') or '-'}")
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
        mark = v["result"] if v else "未登记"
        print(f"    {lv} {mark:<4} {LEVEL_NAME[lv]}" + (f"  — {v['note']}" if v and v.get("note") else ""))
    print(f"  事实（{len(facts)} 条）：")
    for f in facts:
        tag = {"proven": "已证", "hypothesis": "待验", "refuted": "已推翻"}[f["status"]]
        extra = f"  被 {f['refuted_by']} 推翻" if f.get("refuted_by") else ""
        print(f"    [{tag}] {f['id']:<6} {f['claim'][:52]}{extra}")


def cmd_resume(a):
    st = load_state(a.case)
    facts = load_facts(a.case)
    proven = [f for f in facts if f["status"] == "proven"]
    pend = [f for f in facts if f["status"] == "hypothesis"]
    print(f"[接续] {a.case}  裁定={st.get('verdict') or '未给'}  上限={st.get('max_level') or '-'}")
    print(f"  已证 {len(proven)} / 待验 {len(pend)} / 已推翻 {sum(1 for f in facts if f['status']=='refuted')}")
    if pend:
        print("  待验清单：" + "、".join(f["id"] for f in pend))
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
    p.add_argument("--tier", default="", help="后端档位 T1/T2/T3（见 05-backend-rebuild）：T2/T3 且非不可赢 → 上限 M4")
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
