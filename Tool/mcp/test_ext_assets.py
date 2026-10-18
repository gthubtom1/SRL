#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扩展资产自测：preflight-classify + seep_ensure_tool + seep_decompile_auto。
独立文件，不改动原有 test_seep_mcp.py（保持 9/9 基线不动）。
"""
import sys
import os
import json
import subprocess

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import seep_mcp_server as S  # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def main():
    print("=== [1/4] preflight-classify 可执行 ===")
    pf = os.path.join(HERE, "..", "skill", "softseep", "scripts", "preflight-classify.py")
    pf = os.path.abspath(pf)
    check("脚本存在", os.path.isfile(pf), pf)
    elf = os.path.join(HERE, "Tool", "safe", "ida-pro-mcp", "tests", "typed_fixture.elf")
    if os.path.isfile(elf):
        p = subprocess.run([sys.executable, pf, elf], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=60)
        ok = p.returncode == 0
        check("ELF 分类 rc=0", ok, p.stderr[:200])
        if ok:
            d = json.loads(p.stdout)
            check("ELF -> platform=Linux", d.get("platform") == "Linux", str(d.get("platform")))
            check("ELF 有 suggested_type", bool(d.get("suggested_type")), "")
        p2 = subprocess.run([sys.executable, pf, elf, "--hint"], capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=60)
        check("--hint 输出含 platform=", "platform=" in p2.stdout, p2.stdout[:120])
    else:
        print("  [SKIP] 无 ELF fixture，跳过分类断言")

    print("=== [2/4] seep_ensure_tool：内置 r2 应 available ===")
    r = json.loads(S.seep_ensure_tool("r2"))
    check("r2 available", r.get("available") is True, json.dumps(r, ensure_ascii=False)[:200])
    check("r2 有 command", bool(r.get("command")), "")

    print("=== [3/4] seep_ensure_tool：不存在工具应 missing 且给建议 ===")
    m = json.loads(S.seep_ensure_tool("definitely-not-a-real-tool-xyz"))
    check("missing 状态", m.get("status") == "missing", m.get("status"))
    check("给了 install_hint", bool(m.get("install_hint")), "")

    print("=== [4/4] seep_decompile_auto：自动降级到 r2 出真伪代码 ===")
    if os.path.isfile(elf):
        out = S.seep_decompile_auto(elf, target="main", output_mode="summary")
        check("含 engine_used", "engine_used" in out, out[:120])
        check("降级到 r2", "r2" in out.splitlines()[0] if out else False, out[:120])
        check("有伪代码/摘要内容", "main" in out or "offset" in out, "")
    else:
        print("  [SKIP] 无 ELF fixture")

    print(f"\n结果: {PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
