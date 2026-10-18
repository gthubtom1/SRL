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

    print("=== [12/14] seep_http_replay：构造与重放（本地回环服务，不依赖外网）===")
    # 用本地临时 HTTP 服务，零外网依赖
    import http.server
    import threading
    import socket

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"ok": true, "path": "%s"}' % self.path.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "sid=abc123; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_POST(self):
            ln = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(ln) if ln else b""
            body = b'{"ok": true, "echo_len": %d}' % len(data)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{port}"
        hr = json.loads(S.seep_http_replay(base + "/get", method="GET", timeout=10))
        check("http_replay GET 结构", "status" in hr and hr.get("status") == 200, str(hr)[:100])
        check("http_replay 拿到 Set-Cookie", bool(hr.get("set_cookies")), str(hr.get("set_cookies"))[:80])
        hp = json.loads(S.seep_http_replay(base + "/post", method="POST", body='{"a":1}', timeout=10))
        check("http_replay POST 结构", hp.get("status") == 200, str(hp)[:100])
    finally:
        srv.shutdown()

    print("=== [13/14] seep_web_recon：只读侦察（本地回环，不依赖外网）===")
    srv2 = http.server.HTTPServer(("127.0.0.1", 0), _H)
    port2 = srv2.server_address[1]
    t2 = threading.Thread(target=srv2.serve_forever, daemon=True)
    t2.start()
    try:
        wr = json.loads(S.seep_web_recon(f"http://127.0.0.1:{port2}", timeout=10))
        check("web_recon 返回结构", "status" in wr, str(wr)[:100])
        check("web_recon 有安全头字段", "security_headers_missing" in wr, "")
    finally:
        srv2.shutdown()

    print("=== [14/14] seep_ensure_tool：缺工具给 install_plan（P4）===")
    ep = json.loads(S.seep_ensure_tool("definitely-nonexistent-tool-zzz"))
    check("不存在工具 status=missing", ep.get("status") == "missing", str(ep)[:120])
    # 有声明式条目的工具（无论本机装没装）都应能构造出 install_plan
    from seep_mcp_server import _load_tool_install, _build_install_plan
    cfg = _load_tool_install()
    entry = cfg.get("installable", {}).get("sqlmap")
    plan = _build_install_plan("sqlmap", entry) if entry else None
    check("install_plan 可构造", bool(plan and plan.get("command")), str(plan)[:120])

    print("=== [15/15] 练习样本（若已构建）能用扩展工具分析 ===")
    samples_dir = os.path.join(os.path.dirname(HERE), "samples")
    ad = os.path.join(samples_dir, "antidebug_demo.exe")
    if os.path.isfile(ad):
        r = json.loads(S.seep_packer_detect(ad))
        check("packer_detect 识别反调试样本", len(r.get("antidebug_imports", [])) >= 1, str(r.get("antidebug_imports")))
    else:
        print("  [SKIP] 样本未构建（跑 Tool/samples/build.ps1 可重建）")

    print(f"\n结果: {PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
