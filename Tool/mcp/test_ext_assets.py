#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扩展资产自测：preflight-classify + seep_ensure_tool + seep_decompile_auto。
独立文件，不改动原有 test_seep_mcp.py（保持 9/9 基线不动）。
"""
import sys
import os
import json
import shutil
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

    print("=== [4/4] seep_decompile_auto：自动选引擎出真伪代码 ===")
    if os.path.isfile(elf):
        out = S.seep_decompile_auto(elf, target="main", output_mode="summary")
        check("含 engine_used", "engine_used" in out, out[:120])
        # 有 Ghidra 就用 ghidra，否则降级 r2；两者任一即可（都算真反编译）
        check("用了真引擎(ghidra 或 r2)", ("ghidra" in out.splitlines()[0]) or ("r2" in out.splitlines()[0]) if out else False, out[:120])
        check("有伪代码/摘要内容", "main" in out or "offset" in out or "int " in out, "")
    else:
        print("  [SKIP] 无 ELF fixture")

    print("=== [5/9] seep_pe_resources：真实 PE 资源枚举 ===")
    # 只认环境变量，绝不把作者本机路径写进仓库（隐私门禁要求）
    pe_sample = os.environ.get("SEEP_TEST_PE", "")
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
    import tempfile
    # 唯一文件名：并发跑 verify 时固定名会被别的进程删掉（实测 6 路并发 2/6 失败）
    tmp_pcap = os.path.join(tempfile.gettempdir(), f"_tmp_empty_{os.getpid()}.pcap")
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
        # 优化：采用 CREATE_NO_WINDOW 纯静默无窗口启动后台假靶机，绝不弹窗打扰用户
        CREATE_NO_WINDOW = 0x08000000
        proc = _sp.Popen([sys.executable, "-c", "import time; time.sleep(10)"],
                         creationflags=CREATE_NO_WINDOW)
        _t.sleep(0.5)
        try:
            mm = json.loads(S.seep_mem_strings(proc.pid, min_len=8, max_hits=5, encoding="ascii"))
            check("mem_strings 返回结构", "count" in mm, str(mm)[:80])
        except Exception as exc:
            check("mem_strings 不抛异常", False, str(exc))
        finally:
            try:
                proc.terminate()
            except Exception:
                pass
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

    print("=== [15/16] 练习样本（若已构建）能用扩展工具分析 ===")
    samples_dir = os.path.join(os.path.dirname(HERE), "samples")
    ad = os.path.join(samples_dir, "antidebug_demo.exe")
    if os.path.isfile(ad):
        r = json.loads(S.seep_packer_detect(ad))
        check("packer_detect 识别反调试样本", len(r.get("antidebug_imports", [])) >= 1, str(r.get("antidebug_imports")))
    else:
        print("  [SKIP] 样本未构建（跑 Tool/samples/build.ps1 可重建）")

    print("=== [16/16] 真实第三方样本(MIT) 能被扩展工具分析 ===")
    real = os.path.join(samples_dir, "real")
    cj = os.path.join(real, "crackerjack", "a.exe")
    mx = os.path.join(real, "maxxor-keygenme-v7", "KeygenMe V7.exe")
    if os.path.isfile(cj):
        rc = json.loads(S.seep_packer_detect(cj))
        check("crackerjack a.exe 可分析", "packed" in rc, str(rc)[:80])
    else:
        print("  [SKIP] crackerjack 样本缺失")
    if os.path.isfile(mx):
        rm = json.loads(S.seep_packer_detect(mx))
        check("KeygenMe V7 识别注入/自修改特征", len(rm.get("injection_imports", [])) >= 1, str(rm.get("injection_imports"))[:80])
    else:
        print("  [SKIP] maxxor 样本缺失")

    print("=== [17/22] 工具自动发现：插件导入 + r2 可发现 ===")
    try:
        import tool_autodiscover as T
        check("tool_autodiscover 可导入", True)
        d = T.discover("r2")
        check("r2 可发现", d.get("available") is True, json.dumps(d, ensure_ascii=False)[:120])
        check("发现带 via 层", bool(d.get("via")) and d.get("via") != "none", str(d.get("via")))
        check("发现带 layers_tried", isinstance(d.get("layers_tried"), list) and len(d["layers_tried"]) >= 1, "")
    except Exception as exc:
        check("tool_autodiscover 可导入", False, str(exc))
        T = None

    print("=== [18/22] 声明式能力表：已知工具可控 / 表外不假装 ===")
    if T:
        ri = T.research_control("ida")
        check("ida 在能力表(known)", ri.get("known") is True, "")
        check("ida 能力含 mcp/headless", "mcp" in ri.get("capabilities", {}) and "headless" in ri.get("capabilities", {}), "")
        ru = T.research_control("totally-unknown-tool-zzz")
        check("表外工具 known=False", ru.get("known") is False, "")
        check("表外工具给 research_queries", len(ru.get("research_queries", [])) >= 1, "")
    else:
        check("能力表断言", False, "插件未导入")

    print("=== [19/22] 控制计划降级链：缺失 -> 安装计划 + 自写Py兜底 ===")
    if T:
        p = T.plan_control("definitely-missing-tool-xyz")
        tiers = [f.get("tier") for f in p.get("fallbacks", [])]
        check("缺失工具给 install 兜底", "install" in tiers, str(tiers))
        check("缺失工具给 self_write_py 兜底", "self_write_py" in tiers, str(tiers))
        pg = T.plan_control("ghidra") if T.discover("ghidra").get("available") else None
        if pg:
            check("已装工具给出 how_to_control.mode", bool(pg.get("how_to_control", {}).get("mode")), "")
    else:
        check("降级链断言", False, "插件未导入")

    print("=== [20/22] MCP 增量注册：不删用户条目 + 提示重启 ===")
    if T:
        import tempfile
        tmp = os.path.join(tempfile.gettempdir(), "_seep_mcp_test_%d.json" % os.getpid())
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"mcpServers": {"user_keep": {"command": "x", "args": []}}}, f)
            old = os.environ.get("SEEP_AGENT_MCP")
            os.environ["SEEP_AGENT_MCP"] = tmp
            rr = T.register_mcp("ghidra", apply=True)
            check("注册成功", rr.get("registered") is True, json.dumps(rr, ensure_ascii=False)[:120])
            check("提示需重启", rr.get("restart_required") is True, "")
            cfg = json.load(open(tmp, encoding="utf-8"))
            check("用户既有条目保留", "user_keep" in cfg.get("mcpServers", {}), "")
            check("新条目已写入", "ghidra" in cfg.get("mcpServers", {}), "")
        finally:
            try:
                os.remove(tmp)
            except Exception:
                pass
            if old is None:
                os.environ.pop("SEEP_AGENT_MCP", None)
            else:
                os.environ["SEEP_AGENT_MCP"] = old
    else:
        check("MCP 注册断言", False, "插件未导入")

    print("=== [20b] MCP 注册条目预检：明确坏掉的拒写 / 运行时未装只告警 ===")
    if T:
        pf = T._mcp_entry_preflight({"command": "npx", "args": ["-y", "js-reverse-mcp"]})
        check("正常条目预检通过", pf.get("ok") is True, json.dumps(pf, ensure_ascii=False))
        check("缺 command 判坏", T._mcp_entry_preflight({"args": []}).get("ok") is False, "")
        bad_path = os.path.join(tempfile.gettempdir(), "no-such-seep-tool-zzz.exe")
        check("command 路径不存在判坏", T._mcp_entry_preflight({"command": bad_path, "args": []}).get("ok") is False, "")
        pf4 = T._mcp_entry_preflight({"command": "definitely-missing-runtime-zzz", "args": []})
        check("运行时未装仅告警（不阻断先注册后装）", pf4.get("ok") is True and len(pf4.get("warnings", [])) == 1, "")

        # 预检失败 → 不落盘、不创建文件、给安装提示
        orig_entry = T._mcp_entry_for
        tmp2 = os.path.join(tempfile.gettempdir(), "_seep_mcp_pre_%d.json" % os.getpid())
        old_env = os.environ.get("SEEP_AGENT_MCP")
        try:
            T._mcp_entry_for = lambda _tid: {"command": bad_path, "args": []}
            os.environ["SEEP_AGENT_MCP"] = tmp2
            rr_bad = T.register_mcp("ghidra", apply=True)
            check("坏条目拒绝落盘", rr_bad.get("registered") is False, json.dumps(rr_bad, ensure_ascii=False)[:140])
            check("坏条目未创建配置文件", not os.path.exists(tmp2), "")
            check("坏条目给安装提示", bool(rr_bad.get("hint")), "")
        finally:
            T._mcp_entry_for = orig_entry
            try:
                os.remove(tmp2)
            except Exception:
                pass
            if old_env is None:
                os.environ.pop("SEEP_AGENT_MCP", None)
            else:
                os.environ["SEEP_AGENT_MCP"] = old_env

        # 结构性保证：注册链路只写 mcpServers，绝不碰 packages / 不装 pi 扩展
        import ast as _ast
        import inspect as _inspect
        import textwrap as _textwrap
        _fn = _ast.parse(_textwrap.dedent(_inspect.getsource(T.register_mcp))).body[0]
        if _fn.body and isinstance(_fn.body[0], _ast.Expr) and isinstance(getattr(_fn.body[0], "value", None), _ast.Constant):
            _fn.body = _fn.body[1:]
        _body = _ast.unparse(_fn)
        check("注册链路不引用 settings.json", "settings.json" not in _body, "")
        check("注册链路不写 packages", "packages" not in _body, "")
        check("注册链路不安装 pi 扩展", "pi install" not in _body and "update --extensions" not in _body, "")
    else:
        check("MCP 预检断言", False, "插件未导入")

    print("=== [21/22] 架构匹配：PE machine + 32/64 位工具选择 ===")
    if T:
        pe2 = os.path.join(HERE, "Tool", "safe", "radare2", "bin", "r2agent.exe")
        if os.path.isfile(pe2):
            check("r2agent 识别为 x64", T.read_pe_machine(pe2) == "x64", str(T.read_pe_machine(pe2)))
        else:
            print("  [SKIP] 无内置 PE")
        check("x86 选 x32dbg", T._exe_candidates("x64dbg", "x86") == ["x32dbg"], str(T._exe_candidates("x64dbg", "x86")))
        check("x64 选 x64dbg", "x64dbg" in T._exe_candidates("x64dbg", "x64"), "")
        check("别名 die->diec", T.normalize_tool_id("die") == "diec", "")
        ip = T.install_plan("sqlmap")
        check("安装计划可构造", ip.get("has_plan") is True and bool(ip.get("command")), "")
        # 测试多途径安装：无 winget 场景下自动降级为 portable_zip
        orig_w = shutil.which
        try:
            shutil.which = lambda c: None if c == "winget" else orig_w(c)
            ip_die = T.install_plan("diec")
            check("无 winget 时 diec 自动降级为 portable_zip", ip_die.get("method") == "portable_zip", str(ip_die.get("method")))
            check("portable_zip 处于 auto_allowed 白名单", ip_die.get("auto_allowed") is True, "")
        finally:
            shutil.which = orig_w
        check("状态路径在 ~/.seep 下", ".seep" in T.LOCAL_STATE_PATH and "tools.local.json" in T.LOCAL_STATE_PATH, T.LOCAL_STATE_PATH)
    else:
        check("架构匹配断言", False, "插件未导入")

    print("=== [22/22] MCP 工具 wrapper 已注册 ===")
    for fn in ("seep_tool_discover", "seep_tool_control_plan", "seep_tool_research",
               "seep_tool_register_mcp", "seep_tool_install", "seep_tool_state",
               "seep_create_skill"):
        check("存在 " + fn, hasattr(S, fn) and callable(getattr(S, fn)), "")
    if hasattr(S, "seep_tool_discover"):
        try:
            dr = json.loads(S.seep_tool_discover("r2", record_state=False))
            check("seep_tool_discover 返回结构", "available" in dr, str(dr)[:80])
        except Exception as exc:
            check("seep_tool_discover 不抛异常", False, str(exc))

    print(f"\n结果: {PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
