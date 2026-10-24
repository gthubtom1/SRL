#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mcp-bridge-x64dbg.py —— 把 x64dbg 的 HTTP MCP 包成 stdio MCP（根因修复）

## 为什么需要这个文件（2026-10-23 实测定位）

现象：`tool-run.ps1 -Tool x64dbg` **1.3 秒就把 x64dbg 起成 READY**，端口 9094 在听，
但**会话里永远拿不到 `mcp__x64dbg__*` 工具** —— 48 分钟那次会话只能手搓 `pydbg.py`。

根因（两条一起才成立）：
1. pi 只在**会话启动时**连接 mcp.json 里的 server。x64dbg 是唯一的 **http** 型 server
   （其余 seep / ida / playwright / js-reverse 都是 stdio，由 pi 自己 spawn，启动时必定连上）。
2. 会话启动那一刻 x64dbg 还没起 → 连接失败 → 工具**不进工具表**。
   文档说的"断线会在下次调用时重连"只对**曾经连上过**的连接有效；工具不在表里，
   就没有"下次调用"可言 → 死锁。

实测证据（同一会话内）：
  ALL_TOOLS 157 个，命名空间含 mcp__seep / mcp__ida / mcp__playwright / mcp__js_reverse，
  **不含 mcp__x64dbg**，而此时 9094 是 Listen 状态。

## 修法

把 http 换成 stdio：pi 启动时 spawn 本脚本（像 seep 一样必定被连上），
本脚本负责 **按需拉起 x64dbg 并转发** 所有 MCP 调用。

链路：pi ──stdio──> 本脚本 ──http(9094)──> x64dbg 插件

好处：
- 工具在会话启动时就注册好，不再依赖"谁先起"的顺序；
- x64dbg 没起时本脚本会自己拉（复用 tool-run.ps1，1.3 秒），不需要人工干预；
- 拉起失败时返回**明确的错误**，而不是让模型以为工具不存在。

## 用法

mcp.json 里把 x64dbg 改成 stdio：

```json
"x64dbg": {
  "command": "python",
  "args": ["<repo>/Tool/scripts/mcp-bridge-x64dbg.py"],
  "description": "x64dbg 调试器（stdio 桥接 → 9094）。由本桥自动拉起，勿手工开 GUI。"
}
```

## 自检

    python Tool/scripts/mcp-bridge-x64dbg.py --selftest
    期望：打印上游工具数（约 80）与 READY 状态，退出码 0。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TOOL_RUN = os.path.join(HERE, "tool-run.ps1")
UPSTREAM = "http://127.0.0.1:9094/mcp"
LAUNCH_TIMEOUT = 90          # 等 9094 起来的最长秒数
HTTP_TIMEOUT = 60


def x64_dir() -> str:
    """定位 x64dbg 目录（不写死盘符）：env → 工具路径缓存 → tool-runtimes → 常见位置。"""
    env = os.environ.get("SEEP_X64DBG_DIR")
    if env and os.path.isdir(env):
        return env
    # tool-run.ps1 成功后会缓存到 ~/.seep/tool-paths.json：
    #   {"x64dbg": {"exe": "...", "via": "scan", "verified": "..."}}
    # 注意两个坑：① 文件带 BOM，必须 utf-8-sig；② 值是对象，不是字符串。
    cache = os.path.join(os.path.expanduser("~"), ".seep", "tool-paths.json")
    try:
        with open(cache, encoding="utf-8-sig") as f:
            entry = (json.load(f) or {}).get("x64dbg")
        exe = entry.get("exe") if isinstance(entry, dict) else entry
        if isinstance(exe, str) and os.path.isfile(exe):
            return os.path.dirname(exe)
    except Exception:
        pass
    # 不写死盘符：用 PATH 上的可执行文件反推目录
    try:
        out = subprocess.run(["where", "x64dbg.exe"], capture_output=True, timeout=8)
        first = (out.stdout or b"").decode("utf-8", "replace").splitlines()
        if first and os.path.isfile(first[0].strip()):
            return os.path.dirname(first[0].strip())
    except Exception:
        pass
    return ""


def auth_json_path() -> str:
    d = x64_dir()
    return os.path.join(d, "mcp_config.json") if d else ""


def log(msg: str) -> None:
    """stdio 模式下 stdout 归协议，日志只能走 stderr。"""
    sys.stderr.write(f"[x64dbg-bridge] {msg}\n")
    sys.stderr.flush()


# ───────────────────────── 上游探活与拉起 ─────────────────────────

def _auth_token() -> str:
    p = auth_json_path()
    if not p:
        return ""
    try:
        with open(p, encoding="utf-8") as f:
            return str(json.load(f).get("AuthToken") or "")
    except Exception:
        return ""


def upstream_alive() -> bool:
    """401 也算活着（说明服务在听，只是要鉴权）。"""
    try:
        req = urllib.request.Request(UPSTREAM, method="POST",
                                     data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                                     headers={"Content-Type": "application/json"})
        tok = _auth_token()
        if tok:
            req.add_header("Authorization", f"Bearer {tok}")
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500          # 401/406 等都说明端口有服务
    except Exception:
        return False


def launch_upstream() -> bool:
    """用 tool-run.ps1 拉起 x64dbg（它是唯一合法启动入口，1.3 秒 READY）。"""
    if not os.path.isfile(TOOL_RUN):
        log(f"缺 {TOOL_RUN}，无法拉起 x64dbg")
        return False
    log("9094 未监听，按需拉起 x64dbg …")
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", TOOL_RUN,
             "-Tool", "x64dbg"],
            capture_output=True, timeout=LAUNCH_TIMEOUT,
        )
        out = (p.stdout or b"").decode("utf-8", "replace")
        log(f"tool-run rc={p.returncode} out={out.strip()[:300]}")
    except Exception as e:
        log(f"拉起失败：{e}")
        return False
    deadline = time.time() + LAUNCH_TIMEOUT
    while time.time() < deadline:
        if upstream_alive():
            log("9094 已就绪")
            return True
        time.sleep(1.0)
    log("等待 9094 超时")
    return False


def ensure_upstream() -> bool:
    return upstream_alive() or launch_upstream()


# ───────────────────────── stdio ↔ http 转发 ─────────────────────────

def _post(payload: dict) -> tuple[int, str, dict]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(UPSTREAM, data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Accept": "application/json, text/event-stream"})
    tok = _auth_token()
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return r.status, r.headers.get("Content-Type", ""), {"raw": r.read()}
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), {"raw": e.read()}
    except Exception as e:
        return 0, "", {"error": str(e)}


def _parse_sse(raw: bytes) -> dict | None:
    """streamable-http 可能回 SSE；取最后一条 data: 的 JSON。"""
    text = raw.decode("utf-8", "replace")
    out = None
    for line in text.splitlines():
        if line.startswith("data:"):
            frag = line[5:].strip()
            if not frag:
                continue
            try:
                out = json.loads(frag)
            except Exception:
                continue
    return out


def forward(payload: dict) -> dict | None:
    status, ctype, info = _post(payload)
    if "error" in info:
        return {"jsonrpc": "2.0", "id": payload.get("id"),
                "error": {"code": -32000, "message": f"上游不可达：{info['error']}"}}
    raw = info.get("raw", b"")
    if "text/event-stream" in (ctype or ""):
        return _parse_sse(raw)
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {"jsonrpc": "2.0", "id": payload.get("id"),
                "error": {"code": -32000, "message": f"上游返回无法解析（status={status}）"}}


# 需要转发到上游的方法；其余本地应答
FORWARD_METHODS = {
    "initialize", "notifications/initialized", "tools/list", "tools/call",
    "resources/list", "resources/read", "prompts/list", "ping",
}


def serve() -> int:
    if not ensure_upstream():
        log("上游不可用，仍以空工具集启动（模型会看到明确错误，而不是以为工具不存在）")
        upstream_ok = False
    else:
        upstream_ok = True

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        method = msg.get("method")
        mid = msg.get("id")

        # 通知类：无 id，不回包
        if mid is None:
            if method in FORWARD_METHODS and upstream_ok:
                forward(msg)
            continue

        if method == "initialize":
            resp = forward(msg) if upstream_ok else None
            if not resp or "error" in resp:
                resp = {"jsonrpc": "2.0", "id": mid, "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "x64dbg-bridge", "version": "1.0"},
                }}
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue

        if not upstream_ok:
            ensure_upstream()      # 每次调用再试一次
            upstream_ok = True

        if method in FORWARD_METHODS:
            resp = forward(msg)
        else:
            resp = {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32601, "message": f"bridge 不转发该方法：{method}"}}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
    return 0


# ───────────────────────── 自检 ─────────────────────────

def selftest() -> int:
    print(f"上游：{UPSTREAM}")
    aj = auth_json_path()
    print(f"鉴权文件：{aj or '（未定位到 x64dbg 目录，可用 SEEP_X64DBG_DIR 指定）'}（token {'有' if _auth_token() else '无'}）")
    alive = upstream_alive()
    print(f"探活：{'在听' if alive else '未监听 → 尝试拉起'}")
    if not alive:
        if not launch_upstream():
            print("FAIL：拉不起来")
            return 1
    init = forward({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "bridge-selftest", "version": "1"}}})
    print(f"initialize：{'ok' if init and 'result' in init else 'FAIL ' + json.dumps(init, ensure_ascii=False)[:200]}")
    tl = forward({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools = ((tl or {}).get("result") or {}).get("tools") or []
    print(f"tools/list：{len(tools)} 个工具")
    for t in tools[:8]:
        print("   -", t.get("name"))
    if len(tools) == 0:
        print("FAIL：0 个工具")
        return 1
    print("PASS")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    return serve()


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
