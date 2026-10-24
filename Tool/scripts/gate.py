#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gate.py —— 按包判定（S3）：一份判据、可复现、unknown 永不计 pass。

判据（红 = 失败，不接受 skipped/unknown 记 pass）：
  G2 pack-schema      pack.json `.strict()`：多一个字段即红；l1 ≤140 字；limitations/invalidation/witness/cases 非空
  G3 route-parity     route.py 的解析空间与包里声明一致；0 条死路由 / 0 个重复 priority
  G4 pack-witness     真跑 witness.cmd（预算 budget_s）；exit≠0、expect 子句不满足 → 红
  G5 evidence-ledger  claim 必须带 confidence ∈ 四态 + authority；proven 必须有非空 evidence；
                      整包 0 条 observed/derived 证据 → 红（unknown 永不计 pass）

用法：
    python Tool/scripts/gate.py --all [--json] [--no-witness]
    python Tool/scripts/gate.py --pack apkseep [--json]
    python Tool/scripts/gate.py --list
退出码：0 全绿 / 1 有红 / 2 用法错误
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import route as route_mod  # noqa: E402  同一目录；路由判据与索引共用一套实现

CASES_DIR = os.path.join(ROOT, "Tool", "cases")
SERVER = os.path.join(ROOT, "Tool", "mcp", "seep_mcp_server.py")

PACK_KEYS = route_mod.PACK_KEYS
CONFIDENCE = ("observed", "derived", "inferred", "unknown")
AUTHORITY = ("shipped-artifact", "controlled-replay", "external-service", "reported", "none")
STRONG = ("observed", "derived")
MAX_L1 = 140


def _tool_names():
    """MCP 工具名集合：从 server 的 @server.tool() 定义处取，不猜。"""
    try:
        with open(SERVER, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except Exception:
        return set()
    return set(re.findall(r"^def (seep_\w+)\(", text, re.M))


def _claims(case_dir):
    """读 claim 行（与 case_state.load_facts 同口径：有 id+status 且 kind 缺省/claim）。"""
    fp = os.path.join(case_dir, "facts.jsonl")
    out = []
    if not os.path.isfile(fp):
        return out
    with open(fp, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            if not isinstance(o, dict):
                continue
            if str(o.get("kind") or "claim").strip().lower() not in ("", "claim"):
                continue
            if str(o.get("id") or "").strip() and str(o.get("status") or "").strip():
                out.append(o)
    return out


def g2_schema(pack):
    """G2：`.strict()` 语义 —— 多一个字段就是红，不做兼容。"""
    bad = []
    keys = set(pack)
    extra, miss = keys - PACK_KEYS, PACK_KEYS - keys
    if extra:
        bad.append("多出未声明字段：%s" % ",".join(sorted(extra)))
    if miss:
        bad.append("缺字段：%s" % ",".join(sorted(miss)))
    if pack.get("schema") != "seep.pack/1":
        bad.append("schema 必须是 seep.pack/1")
    l1 = str(pack.get("l1") or "")
    if not l1.strip():
        bad.append("l1 为空（进索引的唯一字符串）")
    elif len(l1) > MAX_L1:
        bad.append("l1 超长 %d > %d 字" % (len(l1), MAX_L1))
    for field in ("limitations", "invalidation", "cases", "tools", "stages"):
        v = pack.get(field)
        if not isinstance(v, list) or not v or not all(str(x).strip() for x in v):
            bad.append("%s 必须是非空字符串数组（禁空）" % field)
    for c in pack.get("cases") or []:
        if not os.path.isdir(os.path.join(CASES_DIR, str(c))):
            bad.append("案例不存在：%s" % c)
    names = _tool_names()
    for t in pack.get("tools") or []:
        if names and str(t) not in names:
            bad.append("工具不存在：%s（不在 @server.tool() 清单里）" % t)
    w = pack.get("witness")
    if not isinstance(w, dict) or not str(w.get("cmd") or "").strip():
        bad.append("witness.cmd 为空：没有可执行判据")
    elif not str(w.get("expect") or "").strip():
        bad.append("witness.expect 为空")
    elif not isinstance(w.get("budget_s"), int) or w["budget_s"] <= 0:
        bad.append("witness.budget_s 必须是正整数")
    ec = pack.get("evidence_contract")
    if not isinstance(ec, dict):
        bad.append("evidence_contract 必须是对象")
    else:
        need = {"required_fields", "authority_allow", "pass_forbids_confidence"}
        if set(ec) != need:
            bad.append("evidence_contract 字段必须恰好是 %s" % "/".join(sorted(need)))
        for k in need:
            if not isinstance(ec.get(k), list) or not ec.get(k):
                bad.append("evidence_contract.%s 必须是非空数组" % k)
        for c in ec.get("pass_forbids_confidence") or []:
            if c not in CONFIDENCE:
                bad.append("pass_forbids_confidence 里有非法值：%s" % c)
    return bad


def g3_routes(pack, route_index):
    bad = []
    if not pack.get("routes"):
        bad.append("routes 为空：该包不可路由")
    mine = [r for r in (route_index.get("rows") or []) if r[1] == pack.get("id")]
    if len(mine) != len(pack.get("routes") or []):
        bad.append("routes 数量不一致：pack.json %d / 索引 %d"
                   % (len(pack.get("routes") or []), len(mine)))
    for p in route_index.get("problems") or []:
        bad.append("route: " + p)
    return bad


def _clause_ok(clause, rc, case_dir):
    c = clause.strip().lower()
    if c in ("exit0", "exit=0"):
        return rc == 0, ("witness 退出码 %d" % rc if rc else "")
    m = re.match(r"^facts\s*>=\s*(\d+)$", c)
    if m:
        n = len(_claims(case_dir))
        need = int(m.group(1))
        return n >= need, ("facts %d < %d" % (n, need) if n < need else "")
    if c.endswith("manifest.sha256"):
        p = os.path.join(case_dir, clause.strip())
        return os.path.isfile(p), ("缺 %s" % clause.strip() if not os.path.isfile(p) else "")
    return False, "无法机检的 expect 子句：%r（不当作通过）" % clause


def g4_witness(pack, run=True):
    w = pack.get("witness") or {}
    cmd = str(w.get("cmd") or "")
    case_dir = ""
    m = re.search(r"--case\s+(\S+)", cmd)
    if m:
        case_dir = m.group(1)
        if not os.path.isabs(case_dir):
            case_dir = os.path.join(ROOT, case_dir)
    if not run:  # 跳过实跑 = skipped：按判据「skipped 不得计 pass」处理，不是通过
        return ["G4 skipped（--no-witness）：witness 未实跑，不得计 pass"], {"ran": False}
    argv = shlex.split(cmd, posix=False)
    if argv and argv[0].lower() in ("python", "python3"):
        argv[0] = sys.executable
    budget = int(w.get("budget_s") or 180)
    try:
        r = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=budget)
        rc, out = r.returncode, ((r.stdout or "") + (r.stderr or ""))[-400:]
    except subprocess.TimeoutExpired:
        return ["witness 超预算 %ds：%s" % (budget, cmd)], {"ran": True, "rc": None}
    except Exception as e:  # noqa: BLE001
        return ["witness 无法执行：%s" % str(e)[:80]], {"ran": True, "rc": None}
    bad = []
    for clause in str(w.get("expect") or "").split("+"):
        ok, why = _clause_ok(clause, rc, case_dir)
        if not ok:
            bad.append(why or ("不满足：%s" % clause.strip()))
    return bad, {"ran": True, "rc": rc, "tail": out.strip().splitlines()[-3:]}


def g5_evidence(pack):
    bad, total_claims, strong = [], 0, 0
    for cname in pack.get("cases") or []:
        cdir = os.path.join(CASES_DIR, str(cname))
        claims = _claims(cdir)
        total_claims += len(claims)
        for f in claims:
            conf = str(f.get("confidence") or "").strip().lower()
            auth = str(f.get("authority") or "").strip().lower()
            fid = f.get("id")
            if conf not in CONFIDENCE:
                bad.append("%s/%s 缺 confidence（按 unknown 计，不计 pass）" % (cname, fid))
            if auth and auth not in AUTHORITY:
                bad.append("%s/%s authority 非法：%s" % (cname, fid, auth))
            if str(f.get("status") or "").lower() == "proven":
                if conf in STRONG and auth not in ("", "none"):
                    strong += 1
                if not any(str(e).strip() for e in (f.get("evidence") or [])):
                    bad.append("%s/%s proven 但 evidence 为空" % (cname, fid))
    if total_claims == 0:
        bad.append("本包所有案例 facts 为空：0 条 claim（unknown 不得计 pass）")
    elif strong == 0:
        bad.append("本包 0 条 observed/derived 证据（%d 条 claim 全是 unknown/inferred）" % total_claims)
    return bad, {"claims": total_claims, "strong": strong}


def judge(pack, route_index, run_witness=True):
    gates = {}

    def add(name, bad, info=None):
        gates[name] = {"status": "pass" if not bad else "fail",
                       "reasons": bad[:6], "info": info or {}}

    add("G2 pack-schema", g2_schema(pack))
    add("G3 route-parity", g3_routes(pack, route_index))
    bad4, info4 = g4_witness(pack, run=run_witness)
    add("G4 pack-witness", bad4, info4)
    bad5, info5 = g5_evidence(pack)
    add("G5 evidence-ledger", bad5, info5)
    verdict = "pass" if all(g["status"] == "pass" for g in gates.values()) else "fail"
    return {"pack": pack.get("id"), "verdict": verdict, "gates": gates}


def main():
    ap = argparse.ArgumentParser(description="按包判定（G2/G3/G4/G5）：红=失败，unknown 不计 pass")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--pack", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-witness", action="store_true", help="跳过 G4 实跑（只做静态判据）")
    ap.add_argument("--skill-dir", default="")
    a = ap.parse_args()
    packs, problems = route_mod.load_packs(a.skill_dir or None)
    if problems:
        if a.json:
            print(json.dumps({"ok": False, "problems": problems}, ensure_ascii=False, indent=2))
        else:
            for p in problems:
                print("[FAIL] " + p)
        return 1

    if a.list:
        for p in packs:
            print("%-24s %s" % (p["id"], p["l1"][:60]))
        return 0

    if a.all:
        selected = packs
    elif a.pack:
        selected = [p for p in packs if p["id"] == a.pack]
        if not selected:
            print("[ERR] 没有这个包：%s（用 --list 看现有包）" % a.pack)
            return 2
    else:
        ap.print_help()
        return 2

    route_index = route_mod.check(a.skill_dir or None)
    results = [judge(p["raw"], route_index, run_witness=not a.no_witness) for p in selected]
    npass = sum(1 for r in results if r["verdict"] == "pass")
    summary = {"packs": len(results), "pass": npass, "fail": len(results) - npass,
               "unknown_as_pass": 0}  # 结构上不可能：verdict 只有 pass/fail
    if a.json:
        print(json.dumps({"schema": "seep.gate/1", "summary": summary, "results": results},
                         ensure_ascii=False, indent=2))
    else:
        for r in results:
            print("[%s] %s" % ("PASS" if r["verdict"] == "pass" else "FAIL", r["pack"]))
            for name, g in r["gates"].items():
                mark = "ok  " if g["status"] == "pass" else "FAIL"
                info = g.get("info") or {}
                extra = ""
                if name.startswith("G5") and info:
                    extra = "（claim %d / strong %d）" % (info.get("claims", 0), info.get("strong", 0))
                if name.startswith("G4") and info.get("ran"):
                    extra = "（rc=%s）" % info.get("rc")
                print("   %s %s%s" % (mark, name, extra))
                for why in g["reasons"]:
                    print("        - " + why)
        print("[GATE] %d 个包：pass %d / fail %d（unknown 记为 fail，不计 pass）"
              % (summary["packs"], summary["pass"], summary["fail"]))
    return 0 if summary["fail"] == 0 else 1


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
