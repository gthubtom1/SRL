#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""smoke-e2e.py —— 端到端冒烟：用真实样本把「判型 → 工具链 → 报告」整条链路跑一遍。

为什么需要它（与 verify 的分工）：
  · `setup/verify.*`（60 项）+ 三套单测 = **静态资产 + 单个工具的单元正确性**；
  · 本脚本 = **链路连通性**：一份真实样本从"进来到出报告"，中间每一环是否真的能跑通。
  · 两者都过，才叫"工作台可用"；只有单测过、链路断，弱模型照样会卡住。

特点：不联网、不依赖外部商业工具（r2 用内置）、约 10~20 秒、可重复跑。

用法：
    python Tool/scripts/smoke-e2e.py                     # 自动挑样本
    python Tool/scripts/smoke-e2e.py --sample <path>     # 指定样本
    python Tool/scripts/smoke-e2e.py --keep              # 保留临时工作区（排障用）
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import time

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))          # 仓库根
MCP_DIR = os.path.join(ROOT, "Tool", "mcp")

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"
results = []


def check(name, cond, detail=""):
    results.append((PASS if cond else FAIL, name, detail))
    print("  [%s] %s%s" % (PASS if cond else FAIL, name, (" — " + detail) if detail and not cond else ""))
    return cond


def pick_sample(explicit: str) -> str:
    if explicit:
        return os.path.abspath(explicit)
    base = os.path.join(ROOT, "Tool", "samples", "real")
    cands = []
    for dirpath, dirs, files in os.walk(base):
        for f in files:
            if f.lower().endswith((".exe", ".dll", ".elf", ".so")):
                p = os.path.join(dirpath, f)
                cands.append((os.path.getsize(p), p))
    if not cands:
        return ""
    cands.sort()
    return cands[0][1]        # 最小的样本，跑得快


def main(argv):
    ap = argparse.ArgumentParser(description="Seep 端到端冒烟")
    ap.add_argument("--sample", default="")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args(argv)

    if MCP_DIR not in sys.path:
        sys.path.insert(0, MCP_DIR)

    t0 = time.time()
    print("=== Seep 端到端冒烟 (smoke-e2e) ===")

    # ---------- 0. 导入 MCP 服务 ----------
    try:
        import seep_mcp_server as S
    except Exception as exc:  # noqa: BLE001
        check("导入 seep_mcp_server", False, str(exc))
        return 1
    check("导入 seep_mcp_server", True)

    sample = pick_sample(args.sample)
    if not sample or not os.path.isfile(sample):
        check("找到可测样本", False, "Tool/samples/real/ 下没有 PE/ELF 样本，可用 --sample 指定")
        return 1
    check("找到可测样本", True, os.path.relpath(sample, ROOT))
    print("      样本: %s (%d KB)" % (os.path.relpath(sample, ROOT), os.path.getsize(sample) // 1024))

    # 工作区隔离：所有产物写到临时目录，绝不动仓库
    ws = tempfile.mkdtemp(prefix="seep-smoke-")
    os.environ["SEEP_WORKSPACE"] = ws

    try:
        # ---------- 1. 全量体检（triage） ----------
        import json as _json
        tri = S.seep_auto_triage(sample)
        try:
            tj = _json.loads(tri)
        except Exception:
            tj = {}
        check("① seep_auto_triage 出结构化结果",
              bool(tj.get("hashes", {}).get("md5")),
              str(tri)[:120])
        check("① 哈希覆盖整文件", tj.get("hashes", {}).get("hash_scope") == "full-file",
              str(tj.get("hashes")))

        # ---------- 2. 判壳 ----------
        pk = S.seep_packer_detect(sample)
        try:
            pj = _json.loads(pk)
        except Exception:
            pj = {}
        check("② seep_packer_detect 有结论", "packed" in pj, str(pk)[:120])

        # ---------- 3. 二进制画像 ----------
        info = S.seep_r2_info(sample)
        check("③ seep_r2_info 拿到架构", any(k in info.lower() for k in ("arch", "bits", "x86", "arm", "elf", "pe")),
              info[:120])

        # ---------- 4. 函数枚举 ----------
        funcs = S.seep_r2_functions(sample, limit=10)
        check("④ seep_r2_functions 有输出", bool(funcs.strip()) and "ERROR" not in funcs[:20], funcs[:120])

        # ---------- 5. 引擎降级反编译 ----------
        dec = S.seep_decompile_auto(sample, target="main")
        check("⑤ seep_decompile_auto 报告所用引擎", "engine_used" in dec, dec[:120])

        # ---------- 6. 知识库检索 ----------
        kb = S.seep_kb_search("license", limit=3)
        check("⑥ seep_kb_search 命中知识库", kb.strip().startswith("[") or "path" in kb, kb[:120])

        # ---------- 7. 任务工作区 ----------
        init = S.seep_task_init("smoke-task", "端到端冒烟")
        check("⑦ seep_task_init 建工作区", os.path.isdir(os.path.join(ws, "smoke-task")), init[:120])

        # ---------- 8. 报告生成 ----------
        rep = S.seep_gen_security_report("smoke-task", "smoke_sample")
        rp = os.path.join(ws, "smoke-task", "reports")
        has_rep = os.path.isdir(rp) and any(f.endswith(".md") for f in os.listdir(rp))
        check("⑧ seep_gen_security_report 产出报告", has_rep, rep[:120])

        # ---------- 9. 工具发现链路 ----------
        disc = S.seep_tool_discover("r2", record_state=False)
        check("⑨ 工具发现链路可用（r2）", '"available":true' in disc.replace(" ", ""), disc[:120])
    finally:
        if args.keep:
            print("      临时工作区保留:", ws)
        else:
            shutil.rmtree(ws, ignore_errors=True)

    # ---------- 汇总 ----------
    ok = sum(1 for r in results if r[0] == PASS)
    bad = sum(1 for r in results if r[0] == FAIL)
    dur = time.time() - t0
    print()
    print("结果: %d passed, %d failed  (%.1fs)" % (ok, bad, dur))
    if bad:
        print("链路断点:")
        for st, name, detail in results:
            if st == FAIL:
                print("  - %s %s" % (name, ("(" + detail + ")") if detail else ""))
        return 1
    print("端到端链路畅通 [OK]")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
