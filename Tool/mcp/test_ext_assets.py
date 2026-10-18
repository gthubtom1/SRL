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

    print("=== [5/9] seep_pe_resources：真实 PE 资源枚举 ===")
    pe_sample = os.environ.get("SEEP_TEST_PE", r"D:/Project/瓦6.8/换肤程序点我下载6.9版本.exe")
    if not os.path.isfile(pe_sample):
        # 自包含回退：用仓库内置的 r2agent.exe（任意 PE 即可验证资源枚举路径）
        pe_sample = os.path.join(HERE, "Tool", "safe", "radare2", "bin", "r2agent.exe")
    if os.path.isfile(pe_sample):
        try:
            rp = json.loads(S.seep_pe_resources(pe_sample, min_size=256))
            check("有 sections", len(rp.get("sections", [])) >= 1, "")
            check("返回 resources 字段", "resources" in rp, "")
        except Exception as exc:
            check("seep_pe_resources 不抛异常", False, str(exc))
    else:
        print("  [SKIP] 无任何 PE 可用")

    print("=== [6/9] seep_pe_resources：非 PE 输入优雅报错 ===")
    rbad = S.seep_pe_resources(os.path.join(HERE, "seep_mcp_server.py"))
    check("非 PE 给 ERROR", "ERROR" in rbad or "not" in rbad.lower(), rbad[:80])

    print("=== [7/9] seep_pcap_extract：空 pcap 三模式 ===")
    import struct
    tmp_pcap = os.path.join(HERE, "_tmp_empty.pcap")
    with open(tmp_pcap, "wb") as f:
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    try:
        for mode in ("summary", "http", "payload"):
            r = S.seep_pcap_extract(tmp_pcap, mode=mode)
            check(f"pcap {mode} 可解析", r.strip().startswith("{"), r[:80])
    finally:
        try:
            os.remove(tmp_pcap)
        except Exception:
            pass

    print("=== [8/9] seep_pcap_extract：缺失文件优雅报错 ===")
    check("缺 pcap 给 ERROR", "ERROR" in S.seep_pcap_extract("/no/such.pcap"), "")

    print("=== [9/9] seep_mem_strings：活体进程只读扫描 ===")
    if sys.platform == "win32":
        import subprocess as _sp
        import time as _t
        proc = _sp.Popen(["notepad.exe"])
        _t.sleep(1.5)
        try:
            mm = json.loads(S.seep_mem_strings(proc.pid, min_len=8, max_hits=5, encoding="ascii"))
            check("mem_strings 返回结构", "count" in mm, str(mm)[:80])
        except Exception as exc:
            check("mem_strings 不抛异常", False, str(exc))
        finally:
            proc.terminate()
    else:
        print("  [SKIP] 非 Windows")

    print("=== [10/12] seep_packer_detect：判壳+反调试识别 ===")
    if os.path.isfile(pe_sample):
        try:
            pd = json.loads(S.seep_packer_detect(pe_sample))
            check("packed 字段存在", "packed" in pd, "")
            check("route 非空", len(pd.get("route", [])) >= 1, "")
        except Exception as exc:
            check("seep_packer_detect 不抛异常", False, str(exc))
    else:
        print("  [SKIP] 无 PE 样本")

    print("=== [11/12] seep_packer_detect：非 PE 优雅报错 ===")
    check("非 PE 给 ERROR", "ERROR" in S.seep_packer_detect(os.path.join(HERE, "seep_mcp_server.py")), "")

    print("=== [12/12] seep_http_replay：构造与重放（无网则验证优雅降级）===")
    try:
        hr = json.loads(S.seep_http_replay("https://httpbin.org/get", method="GET", timeout=15))
        check("http_replay 返回结构", "status" in hr or "backend" in hr, str(hr)[:100])
    except Exception as exc:
        # 无网络时不能崩，必须返回可读错误字符串
        r = S.seep_http_replay("http://127.0.0.1:1/", method="GET", timeout=3)
        check("http_replay 无网时优雅报错", r.strip().startswith("[ERROR]") or r.strip().startswith("{"), r[:100])

    print("=== [13/14] seep_web_recon：只读侦察（无网则优雅报错）===")
    try:
        wr = json.loads(S.seep_web_recon("https://httpbin.org", timeout=15))
        check("web_recon 返回结构", "status" in wr, str(wr)[:100])
    except Exception as exc:
        r = S.seep_web_recon("http://127.0.0.1:1/", timeout=3)
        check("web_recon 无网优雅报错", r.strip().startswith("{") or "error" in r.lower(), r[:100])

    print("=== [14/14] seep_ensure_tool：缺工具给 install_plan（P4）===")
    ep = json.loads(S.seep_ensure_tool("sqlmap"))
    if ep.get("status") == "missing":
        check("missing 带 install_plan", bool(ep.get("install_plan")), str(ep)[:120])
    else:
        print("  [SKIP] 本机已装 sqlmap，跳过 install_plan 断言")

    print(f"\n结果: {PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
