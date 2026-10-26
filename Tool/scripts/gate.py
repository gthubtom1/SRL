#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gate.py —— 按包判定（S3）：一份判据、可复现、unknown 永不计 pass。

判据（红 = 失败，不接受 skipped/unknown 记 pass）：
  G2 pack-schema      pack.json `.strict()`：多一个字段即红；l1 ≤140 字；limitations/invalidation/witness/cases 非空
  G3 route-parity     route.py 的解析空间与包里声明一致；0 条死路由 / 0 个重复 priority
  G4 pack-witness     真跑 witness.cmd（预算 budget_s）；exit≠0、expect 子句不满足 → 红
  G5 evidence-ledger  claim 必须带 confidence ∈ 四态 + authority；proven 必须有非空 evidence；
                      整包 0 条 observed/derived 证据 → 红（unknown 永不计 pass）
  G6 verification-receipt / G4b target-asset（回执可核、真输入资产）

摘要的读法（第 4 轮评审 P1-2，别把两件事读成一件）：
  `[GATE] N 个包：结构 pass/fail`  = 每个包的**判据**都跑通了（这条不放宽）。
  `[GATE] 见证证据：real x / fixture y` = 这些包的 witness 案例里，多少是真实世界产物；
  fixture / self-built 案例只证明**流程可跑**，**不得**读成「该域可用」。

用法：
    python Tool/scripts/gate.py --all [--json] [--no-witness]
    python Tool/scripts/gate.py --pack apkseep [--json]
    python Tool/scripts/gate.py --list
退出码：0 全绿 / 1 有红 / 2 用法错误
"""
from __future__ import annotations

import argparse
import hashlib
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
        if not os.path.isfile(p):
            return False, "缺 %s" % clause.strip()
        # ★ 只判「文件在不在」会让假哈希永远不红（终审 4 号 F-002）。逐条核哈希。
        bad = []
        with open(p, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                parts = ln.split(None, 1)
                if len(parts) != 2:
                    bad.append("行格式坏: %r" % ln[:40])
                    continue
                want, rel = parts[0].lower(), parts[1].strip()
                fp = os.path.join(case_dir, rel) if not os.path.isabs(rel) else rel
                if not os.path.isfile(fp):
                    bad.append("缺文件 %s" % rel)
                    continue
                got = hashlib.sha256(open(fp, "rb").read()).hexdigest()
                if got != want:
                    bad.append("哈希不符 %s" % rel)
        return (not bad), ("；".join(bad[:3]) if bad else "")
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
    # ── 外部评审 C1：witness.cmd 只重算账本，不碰该域工具 → 追加"真跑该域脚本" ──
    wt = pack.get("witness_tool") or {}
    wt_cmd = str(wt.get("cmd") or "")
    if not wt_cmd:
        bad.append("缺 witness_tool：见证没有碰该域任何工具（只查账本是假绿）")
    else:
        argv2 = shlex.split(wt_cmd, posix=False)
        if argv2 and (argv2[0].lower() in ("python", "python3") or argv2[0].endswith(".py")):
            argv2[0] = sys.executable if argv2[0].lower() in ("python", "python3") else sys.executable
            if not argv2[0].endswith(".py") and len(argv2) >= 1 and wt_cmd.split()[0].endswith(".py"):
                pass
        # 形如 "Tool/x.py --help"：直接 .py 文件时也要用解释器启动
        if wt_cmd.split() and wt_cmd.split()[0].endswith(".py"):
            argv2 = [sys.executable] + shlex.split(wt_cmd, posix=False)
        try:
            r2 = subprocess.run(argv2, cwd=ROOT, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=120)
            if r2.returncode != 0:
                tail = ((r2.stdout or "") + (r2.stderr or ""))[-200:]
                bad.append("witness_tool 失败(rc=%d)：%s … %s" % (r2.returncode, wt_cmd, tail[:120]))
        except Exception as e:  # noqa: BLE001
            bad.append("witness_tool 无法执行：%s" % str(e)[:80])
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
            status = str(f.get("status") or "").strip().lower()
            if auth and auth not in AUTHORITY:
                bad.append("%s/%s authority 非法：%s" % (cname, fid, auth))
            # 证据契约只管「能替 pass 背书的 claim」（proven）；refuted / hypothesis 是历史记录，
            # 不参与 pass（verify 也不把它们当通过），因此不因缺 confidence 而红。
            if status == "proven":
                if conf not in CONFIDENCE:
                    bad.append("%s/%s proven 缺 confidence（按 unknown 计，不计 pass）" % (cname, fid))
                if conf in STRONG and auth not in ("", "none"):
                    strong += 1
                if not any(str(e).strip() for e in (f.get("evidence") or [])):
                    bad.append("%s/%s proven 但 evidence 为空" % (cname, fid))
    if total_claims == 0:
        bad.append("本包所有案例 facts 为空：0 条 claim（unknown 不得计 pass）")
    elif strong == 0:
        bad.append("本包 0 条 observed/derived 证据（%d 条 claim 全是 unknown/inferred）" % total_claims)
    return bad, {"claims": total_claims, "strong": strong}



def _receipt_paths(case):
    """docs/verification/<case>-<date>.json 里最新的一份。"""
    import glob as _glob
    pat = os.path.join(ROOT, "docs", "verification", str(case) + "-*.json")
    found = sorted(_glob.glob(pat))
    return found[-1] if found else ""


def _case_cohort(case_dir):
    """现算 cohort：claims / proven / strong。与 case_state verify 同口径。"""
    import re as _re
    fp = os.path.join(case_dir, "facts.jsonl")
    claims = proven = strong = 0
    if os.path.isfile(fp):
        with open(fp, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                if not isinstance(o, dict):
                    continue
                if str(o.get("kind") or "claim").lower() not in ("", "claim"):
                    continue
                if not str(o.get("id") or "").strip() or not str(o.get("status") or "").strip():
                    continue
                claims += 1
                if str(o.get("status")).lower() == "proven":
                    proven += 1
                    conf = str(o.get("confidence") or "").lower()
                    auth = str(o.get("authority") or "none").lower()
                    if conf in ("observed", "derived") and auth not in ("", "none"):
                        strong += 1
    return {"claims": claims, "proven": proven, "strong": strong}


def g6_receipt(pack):
    """G6：每个包的 witness 案例必须有一份可核对的 verification receipt。

    判据（三条，任一不满足即红）：
      1) docs/verification/<case>-<date>.json 存在；
      2) cohorts.baseline / cohorts.final 都在，且 final 的 claims/proven/strong 与**现算值**一致
         （不能手填一个好看的数）；
      3) source_sha256 里每个文件的哈希与当前工作树一致（改了事实账就必须更新回执）。
    """
    bad = []
    cmd = str((pack.get("witness") or {}).get("cmd") or "")
    import re as _re
    m = _re.search(r"--case\s+(\S+)", cmd)
    if not m:
        return ["witness 里没有 --case，无法定位回执对应案例"], {}
    case = os.path.basename(os.path.normpath(m.group(1)))
    case_dir = os.path.join(CASES_DIR, case)
    rp = _receipt_paths(case)
    if not rp:
        return ["缺 verification receipt：docs/verification/%s-<date>.json" % case], {"case": case}
    try:
        d = json.load(open(rp, encoding="utf-8"))
    except Exception as e:
        return ["回执解析失败：%s" % str(e)[:60]], {"case": case}
    co = d.get("cohorts") or {}
    if not isinstance(co.get("baseline"), dict) or not isinstance(co.get("final"), dict):
        bad.append("回执缺 cohorts.baseline 或 cohorts.final（前后配对是这份回执的全部意义）")
    else:
        now = _case_cohort(case_dir)
        for k in ("claims", "proven", "strong"):
            if int(co["final"].get(k, -1)) != now[k]:
                bad.append("final.%s=%s 与现算 %d 不一致（回执过期或手填）"
                           % (k, co["final"].get(k), now[k]))
        if int(co["baseline"].get("strong", -1)) >= int(co["final"].get("strong", -1)) \
                and int(co["final"].get("strong", 0)) > 0:
            bad.append("baseline.strong 不小于 final.strong：这次改动没有产生可测的差异")
    sha = d.get("source_sha256") or {}
    if not sha:
        bad.append("回执缺 source_sha256（无法证明回执对应的是当前这份事实账）")
    for rel, want in sha.items():
        fp = os.path.join(case_dir, rel)
        if not os.path.isfile(fp):
            bad.append("source_sha256 指向的文件不存在：%s" % rel)
            continue
        import hashlib as _h
        got = _h.sha256(open(fp, "rb").read()).hexdigest()
        if got != want:
            bad.append("%s 的哈希与回执不一致（事实账改过，回执需重写）" % rel)
    return bad, {"case": case, "receipt": os.path.relpath(rp, ROOT).replace(os.sep, "/")}



def g4b_target(pack):
    """G4b：witness 案例必须有**真实输入资产**（D1 的机检版）。

    判据：
      1) `<case>/target/` 存在且至少 1 个文件（不是空目录占位）；
      2) `case.json.target_files[]` 里每个文件都在、哈希与磁盘一致
         （防止"写了 sha256 但文件换过"）；
      3) target_files 至少 1 条（没登记等于没资产）。
    """
    import hashlib as _h
    import re as _re
    cmd = str((pack.get("witness") or {}).get("cmd") or "")
    m = _re.search(r"--case\s+(\S+)", cmd)
    if not m:
        return ["witness 无 --case，无法定位目标案例"], {}
    case = os.path.basename(os.path.normpath(m.group(1)))
    cdir = os.path.join(CASES_DIR, case)
    tdir = os.path.join(cdir, "target")
    bad = []
    if not os.path.isdir(tdir):
        return ["%s 缺 target/（无可复跑的真实输入）" % case], {"case": case}
    files = [f for f in os.listdir(tdir) if os.path.isfile(os.path.join(tdir, f))]
    if not files:
        bad.append("%s/target/ 为空" % case)
    cj = os.path.join(cdir, "case.json")
    rec = {}
    try:
        rec = json.load(open(cj, encoding="utf-8")).get("target_files") or {}
    except Exception:
        rec = {}
    if isinstance(rec, list):
        rec = {x.get("path"): x for x in rec if isinstance(x, dict)}
    if not rec:
        bad.append("%s：case.json 没有 target_files[]（资产未登记 sha256）" % case)
    for rel, meta in (rec or {}).items():
        fp = os.path.join(cdir, rel)
        if not os.path.isfile(fp):
            bad.append("target_files 指向不存在的文件：%s" % rel)
            continue
        want = (meta or {}).get("sha256") or ""
        got = _h.sha256(open(fp, "rb").read()).hexdigest()
        if want != got:
            bad.append("%s 的 sha256 与登记值不一致（资产被替换过）" % rel)
    return bad, {"case": case, "targets": len(files)}


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
    bad6, info6 = g6_receipt(pack)
    add("G6 verification-receipt", bad6, info6)
    bad7, info7 = g4b_target(pack)
    add("G4b target-asset", bad7, info7)
    verdict = "pass" if all(g["status"] == "pass" for g in gates.values()) else "fail"
    return {"pack": pack.get("id"), "verdict": verdict, "gates": gates}



def judge_answer(trap_id, answer):
    """对一段真实回答打分（D2 持续回归）。

    判据：`expect_tokens` 每组**至少命中一个**；`forbidden_tokens` **一个都不许出现**。
    缺任一组 / 命中任一禁忌词 → FAIL（不做"差不多就行"的模糊判定）。
    """
    import glob as _glob
    tps = []
    for f in _glob.glob(os.path.join(ROOT, "Tool", "config", "traps.json")):
        tps = json.load(open(f, encoding="utf-8")).get("traps") or []
    trap = next((t for t in tps if t.get("id") == trap_id), None)
    if not trap:
        return {"ok": False, "error": "no_such_trap", "id": trap_id}
    low = (answer or "").lower()
    missing, hit_forbidden = [], []
    for gi, group in enumerate(trap.get("expect_tokens") or [], 1):
        if not any(tok.lower() in low for tok in group):
            missing.append("第%d组缺一：%s" % (gi, " / ".join(group)))
    for tok in trap.get("forbidden_tokens") or []:
        if tok.lower() in low:
            hit_forbidden.append(tok)
    ok = not missing and not hit_forbidden
    return {"ok": ok, "id": trap_id, "pack": trap.get("pack"),
            "missing_groups": missing, "forbidden_hits": hit_forbidden,
            "chars": len(answer or "")}


def _witness_case(pack):
    """witness.cmd 里的 --case 案例名（没写就返回空）。"""
    m = re.search(r"--case\s+(\S+)", str((pack.get("witness") or {}).get("cmd") or ""))
    return os.path.basename(os.path.normpath(m.group(1))) if m else ""


def _evidence_kind(case):
    """案例的真实性类型：case.json 的 evidence_kind。

    读不到了（没 case.json / 没字段 / 解析失败）= "unknown" → **按 fixture 计**。
    宁可把真样本误报成 fixture，也不要把夹具冒充成「该域真实可用」。
    """
    if not case:
        return "unknown"
    try:
        with open(os.path.join(CASES_DIR, case, "case.json"), encoding="utf-8",
                  errors="replace") as fh:
            d = json.load(fh)
        k = str((d or {}).get("evidence_kind") or "").strip().lower()
        return k or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def witness_cohort(packs):
    """见证证据分类：real = 真实世界产物；其余（fixture / self-built / unknown）一律按 fixture 计。

    为什么要这一行：`gate --all` 9/9 只说明「每个包的判据都跑通了」，**不说明 9 个域
    都有真实生例**。fixture / self-built 案例证明的是流程可跑，**不得**读成「该域可用」。
    """
    real, fixtures = [], []
    for p in packs:
        case = _witness_case(p.get("raw") or p)
        kind = _evidence_kind(case)
        rec = {"pack": p.get("id"), "case": case, "evidence_kind": kind}
        (real if kind == "real" else fixtures).append(rec)
    return real, fixtures


def main():
    ap = argparse.ArgumentParser(description="按包判定（G2/G3/G4/G5）：红=失败，unknown 不计 pass")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--pack", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-witness", action="store_true", help="跳过 G4 实跑（只做静态判据）")
    ap.add_argument("--skill-dir", default="")
    ap.add_argument("--trap", default="", help="对一个真实回答打分（陷阱 id）")
    ap.add_argument("--answer", default="", help="回答文本文件（配合 --trap）")
    a = ap.parse_args()
    packs, problems = route_mod.load_packs(a.skill_dir or None)
    if problems:
        if a.json:
            print(json.dumps({"ok": False, "problems": problems}, ensure_ascii=False, indent=2))
        else:
            for p in problems:
                print("[FAIL] " + p)
        return 1

    if a.trap:
        if not a.answer or not os.path.isfile(a.answer):
            print("[ERR] --trap 需要 --answer <文件>")
            return 2
        res = judge_answer(a.trap, open(a.answer, encoding="utf-8", errors="replace").read())
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

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
    real, fixtures = witness_cohort(selected)
    summary["witness"] = {"real": len(real), "fixture": len(fixtures),
                          "fixture_packs": [x["pack"] for x in fixtures]}
    if a.json:
        print(json.dumps({"schema": "seep.gate/1", "summary": summary, "results": results,
                          "witness_cohort": {"real": real, "fixture": fixtures}},
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
        # ── 诚实摘要（第 4 轮评审 P1-2）──
        # 第一行：结构判定（判据未放宽，9/9 就是 9/9）。
        # 第二行：见证证据的真实性（real / fixture）—— 这是「能不能说该域可用」的边界。
        # 第三行：哪些包只是夹具，点名到位，省得把 9/9 读成「九个域都能用」。
        print("[GATE] %d 个包：结构 pass %d / fail %d（unknown 记为 fail，不计 pass）"
              % (summary["packs"], summary["pass"], summary["fail"]))
        print("[GATE] 见证证据：real %d / fixture %d（fixture 不计“该域可用”）"
              % (len(real), len(fixtures)))
        if fixtures:
            print("[GATE] fixture %d 个：%s" % (len(fixtures), "、".join(
                "%s(%s:%s)" % (x["pack"], x["case"] or "?", x["evidence_kind"])
                for x in fixtures)))
        else:
            print("[GATE] fixture 0 个：%d 个包的见证案例都是 evidence_kind=real" % len(real))
    return 0 if summary["fail"] == 0 else 1


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
