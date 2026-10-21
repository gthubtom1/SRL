#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mcp-doctor.py —— MCP 服务「验连 + 自愈」体检器。

为什么需要它（血案）：
    会话启动时 pi 只连一次 MCP。x64dbg 没起来 → 这一次失败 → 本轮 `mcp__x64dbg__*`
    根本不存在。模型拿不到工具，就静默改用 bash 手搓十几分钟，用户只看到右上角一闪
    而过的报错弹窗 —— 「它明明在干活，可什么都没连上」。

它干什么：
    · 逐个读 mcp.json 的 server，判断是 http 还是 stdio；
    · http：`--quick` 只测端口（0.1s）；默认发 JSON-RPC initialize + tools/list，报工具数；
    · stdio：检查 command 是否存在（不真起，避免拖慢）；
    · 失败的给出**可执行的恢复命令**，`--fix` 还会按 tool-runtimes.json 自动把宿主拉起来再复验。

用法：
    python Tool/scripts/mcp-doctor.py                 # 全量体检
    python Tool/scripts/mcp-doctor.py --quick         # 只测端口（会话开头的 0.1s 自检）
    python Tool/scripts/mcp-doctor.py --fix           # 失败的尝试自动拉起
    python Tool/scripts/mcp-doctor.py --json          # 机读输出
退出码：0=全部就绪（或无可检项） / 1=有失败
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_MCP = os.path.expanduser(os.path.join("~", ".pi", "agent", "mcp.json"))
RUNTIMES = os.path.join(ROOT, "Tool", "config", "tool-runtimes.json")


def _load_servers(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("mcpServers") or data


def _port_open(host, port, timeout=0.6):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _resolve_header(value):
    """mcp.json 支持 `!命令` 形式的动态值（x64dbg 的 token 就是这么拿的）。"""
    if isinstance(value, str) and value.startswith("!"):
        try:
            out = subprocess.run(value[1:], shell=True, capture_output=True, text=True, timeout=25)
            return (out.stdout or "").strip()
        except Exception:
            return ""
    return value


def _parse_body(raw, ctype):
    """兼容 application/json 与 text/event-stream（streamable HTTP 会返回 SSE）。"""
    if "text/event-stream" in (ctype or "").lower():
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except Exception:
                    continue
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def _post(url, headers, payload, session_id=None, timeout=8):
    import urllib.request

    body = json.dumps(payload).encode()
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    h.update(headers or {})
    if session_id:
        h["Mcp-Session-Id"] = session_id
    req = urllib.request.Request(url, data=body, headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode("utf-8", "replace")
        return r.status, dict(r.headers), raw


def probe_http(cfg, quick=False):
    url = cfg.get("url") or ""
    u = urlparse(url)
    host, port = u.hostname or "127.0.0.1", u.port or (443 if u.scheme == "https" else 80)
    if not _port_open(host, port):
        return {"ok": False, "stage": "port",
                "error": f"{host}:{port} 未监听（宿主进程没起 / MCP 插件没加载 / 端口被占）"}
    if quick:
        return {"ok": True, "stage": "port", "tools": None}

    headers = {k: _resolve_header(v) for k, v in (cfg.get("headers") or {}).items()}
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "seep-mcp-doctor", "version": "1.0"}}}
    try:
        status, rh, raw = _post(url, headers, init)
    except Exception as e:
        return {"ok": False, "stage": "initialize",
                "error": f"initialize 失败：{type(e).__name__}: {e} （多半是 token 过期或 Authorization 无效）"}
    msg = _parse_body(raw, rh.get("Content-Type", ""))
    if isinstance(msg, dict) and msg.get("error"):
        return {"ok": False, "stage": "initialize", "error": f"服务端返回错误：{msg['error']}"}
    session = rh.get("Mcp-Session-Id") or rh.get("mcp-session-id")

    # notifications/initialized（部分实现要求）
    try:
        _post(url, headers, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    except Exception:
        pass

    try:
        _, rh2, raw2 = _post(url, headers,
                             {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, session)
        msg2 = _parse_body(raw2, rh2.get("Content-Type", ""))
        if isinstance(msg2, dict) and isinstance(msg2.get("result"), dict):
            n = len(msg2["result"].get("tools") or [])
            return {"ok": True, "stage": "tools", "tools": n}
        return {"ok": True, "stage": "initialize", "tools": None,
                "error": "initialize 通了但 tools/list 没解析出结果"}
    except Exception as e:
        return {"ok": False, "stage": "tools", "error": f"tools/list 失败：{type(e).__name__}: {e}"}


def probe_stdio(cfg, _quick=False):
    cmd = cfg.get("command") or ""
    if not cmd:
        return {"ok": False, "stage": "config", "error": "既没有 url 也没有 command"}
    from shutil import which
    hit = which(cmd) or (cmd if os.path.isfile(cmd) else "")
    if not hit:
        return {"ok": False, "stage": "spawn", "error": f"命令不存在：{cmd}"}
    return {"ok": True, "stage": "offline", "tools": None,
            "error": "stdio 服务：只验证了可执行文件存在（真正拉起由 pi 负责）"}


def _runtime_tools():
    try:
        with open(RUNTIMES, encoding="utf-8") as f:
            return set((json.load(f).get("tools") or {}).keys())
    except Exception:
        return set()


def _try_fix(name):
    """按 tool-runtimes.json 的 id 尝试把宿主拉起来。"""
    if name not in _runtime_tools():
        return None
    ps = "powershell"
    script = os.path.join(ROOT, "Tool", "scripts", "tool-run.ps1")
    try:
        out = subprocess.run([ps, "-NoProfile", "-ExecutionPolicy", "Bypass",
                              "-File", script, "-Tool", name],
                             capture_output=True, text=True, timeout=150)
        line = [l for l in (out.stdout or "").strip().splitlines() if l.strip()]
        return line[-1] if line else "(无输出)"
    except Exception as e:
        return f"拉起失败：{e}"


def recovery(name, cfg, res):
    stage = res.get("stage")
    if cfg.get("url"):
        port = urlparse(cfg["url"]).port
        if stage == "port":
            return (f"powershell -File Tool/scripts/tool-run.ps1 -Tool {name}"
                    f"   # 或手工启动宿主后重跑本脚本；端口 {port}")
        if stage in ("initialize", "tools"):
            return f"token/授权问题：检查 {name} 的 headers；或在 TUI 执行 /mcp reconnect {name}"
    return f"检查 mcp.json 里 {name} 的 command / 依赖是否装好（npx -y 包名 / python 模块）"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=DEFAULT_MCP)
    ap.add_argument("--quick", action="store_true", help="只测端口，不发 JSON-RPC")
    ap.add_argument("--fix", action="store_true", help="失败的尝试自动拉起宿主")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        print(f"[ERR] 找不到 {args.file}")
        return 1
    servers = _load_servers(args.file)
    rows, failed = [], 0

    for name, cfg in servers.items():
        if cfg.get("enabled") is False:
            rows.append({"server": name, "ok": True, "stage": "disabled", "tools": None})
            continue
        cfg = dict(cfg)
        res = probe_http(cfg, args.quick) if cfg.get("url") else probe_stdio(cfg, args.quick)
        fixed = None
        if not res["ok"] and args.fix:
            fixed = _try_fix(name)
            if cfg.get("url"):
                res = probe_http(cfg, args.quick)
        row = {"server": name, "ok": res["ok"], "stage": res["stage"],
               "tools": res.get("tools"), "detail": res.get("error") or ""}
        if not res["ok"]:
            row["recovery"] = recovery(name, cfg, res)
            failed += 1
        if fixed is not None:
            row["auto_fix"] = fixed
        rows.append(row)

    if args.json:
        print(json.dumps({"file": args.file, "servers": rows, "failed": failed},
                         ensure_ascii=False, indent=2))
    else:
        print(f"MCP 体检（{args.file}）")
        for r in rows:
            mark = "OK  " if r["ok"] else "FAIL"
            cnt = f"{r['tools']} tools" if r["tools"] is not None else r["stage"]
            print(f"  [{mark}] {r['server']:<12} {cnt}")
            if r["detail"]:
                print(f"         {r['detail']}")
            if r.get("auto_fix"):
                print(f"         自动拉起: {r['auto_fix']}")
            if not r["ok"]:
                print(f"         恢复: {r['recovery']}")
        print(f"结果：{len(rows) - failed}/{len(rows)} 就绪")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
