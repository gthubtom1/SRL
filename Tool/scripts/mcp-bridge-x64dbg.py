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
- x64dbg 没起时**不擅自动手**：返回一条"需要你确认"的结构化结果并打出 A/B/C 选项
  （客户可能正在远程 / 终端 / 共享屏里干活，弹一个 GUI 就是事故）；
- 默认**自动拉起**（这是"我们自己的工具"）；想禁止才设 `SEEP_GUI_NO_AUTOLAUNCH=1`
  或启动参数 `--allow-gui-launch`（能力保留，不是删功能）；
- 拉起失败时返回**明确的错误 + A/B/C 卡**，而不是让模型以为工具不存在。

## A/B/C（`ensure_upstream()` 返回的 choices）

    A  我（Agent）启动   → tool-run.ps1 -Tool x64dbg，会弹 x64dbg GUI
    B  你（用户）双击    → 你开 x64dbg，然后 /mcp reconnect x64dbg
    C  只做静态         → 不开 GUI，改用 radare2 / IDA 静态分析

## 用法

mcp.json 里把 x64dbg 改成 stdio：

```json
"x64dbg": {
  "command": "python",
  "args": ["<repo>/Tool/scripts/mcp-bridge-x64dbg.py"],
  "description": "x64dbg 调试器（stdio 桥接 → 9094）。桥不会擅自拉起 GUI：需要时返回 A/B/C 确认卡。"
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
            raw = json.load(f) or {}
        # 新结构 tools{"x64dbg"}{command} 与旧结构顶层 {"x64dbg"}{exe} 都要认
        entry = raw.get("x64dbg") or ((raw.get("tools") or {}).get("x64dbg") or {})
        exe = entry.get("exe") or entry.get("command") if isinstance(entry, dict) else entry
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
    """用 tool-run.ps1 拉起 x64dbg（它是唯一合法启动入口，1.3 秒 READY）。

    ⚠ 会弹 GUI 窗口 —— 只能由 ensure_upstream() 在**用户明确授权后**调用。
    """
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


# 自动拉起 GUI 的闸门：默认关。
# 为什么：客户可能在远程桌面 / SSH / 共享屏 / 无人值守流水线里跑会话，
# 桥静悄悄弹一个 x64dbg 窗口就是事故（而且 x64dbg 一开就接管调试端口）。
# 保留能力：显式授权（环境变量或 --allow-gui-launch 参数）仍然可以自动拉起。
ALLOW_ENV = "SEEP_ALLOW_GUI_AUTOLAUNCH"
_TRUTHY = ("1", "true", "yes", "on", "y")


# A/B/C 确认卡：桥只负责把选项**呈现**出来，由上层（Agent）出卡问用户。
CONFIRM_CHOICES = [
    {"id": "A", "label": "我启动",
     "detail": "Agent 现在跑 tool-run.ps1 -Tool x64dbg 拉起调试器（会弹 GUI）"},
    {"id": "B", "label": "你双击",
     "detail": "你自己双击 x64dbg 并加载 MCP 插件，然后在会话里 /mcp reconnect x64dbg"},
    {"id": "C", "label": "只做静态",
     "detail": "不开 GUI，改用 radare2 / IDA 做纯静态分析"},
]


DISABLE_ENV = "SEEP_GUI_NO_AUTOLAUNCH"
_FALSY = ("0", "false", "no", "off", "n")


def autolaunch_allowed(explicit: bool | None = None) -> bool:
    """默认**自动拉起**（x64dbg 是"我们自己的工具"，由 Agent 自己起、自己连、自己用）。

    ★ 2026-10-26 用户口径修正（推翻第 3 轮那次"要用户三选一"的改动）：
      只有"跑客户交给我们的目标样本"才需要用户回执；启动调试器不属于这一类。
      9094 没在听 → 直接拉起 → 连上 → 用。整个过程不问用户（无感）。

    关闭方式（仅当你确实不想要 GUI 时）：
      - 环境变量 SEEP_GUI_NO_AUTOLAUNCH=1
      - 或显式传 ensure_upstream(launch=False)
    """
    if explicit is not None:
        return bool(explicit)
    if os.environ.get(DISABLE_ENV, "").strip().lower() in _TRUTHY:
        return False
    return True


def confirm_card_text() -> str:
    """给人看的 A/B/C 卡（写 stderr 日志 / 作为 JSON-RPC error message 回给上层）。"""
    lines = ["x64dbg 未运行（9094 无监听），且本次被显式要求不自动拉起（%s=1），请三选一：" % DISABLE_ENV]
    for c in CONFIRM_CHOICES:
        lines.append("%s) %s —— %s" % (c["id"], c["label"], c["detail"]))
    lines.append(
        "（选 A：设 %s=1 后重启会话，或让 Agent 跑 tool-run.ps1 -Tool x64dbg；"
        "选 B：起来后 /mcp reconnect x64dbg；选 C：告诉我只做静态）" % ALLOW_ENV
    )
    return "\n".join(lines)


def log_confirm_card() -> None:
    log("9094 未监听：按配置不自动拉起（%s=1）；如需自动拉起，去掉该环境变量即可" % DISABLE_ENV)
    for c in CONFIRM_CHOICES:
        log("  %s) %s —— %s" % (c["id"], c["label"], c["detail"]))
    log("  授权自动拉起：环境变量 %s=1（或传 --allow-gui-launch / ensure_upstream(launch=True)）" % ALLOW_ENV)


def ensure_upstream(launch: bool | None = None) -> dict:
    """确保上游可用 —— **默认自动拉起**（9094 没在听就拉 x64dbg，再连上；不问用户）。

    返回结构化结果（上层据此出 A/B/C 卡，而不是自己去猜）：
      {"status": "ready" | "need_user_confirm" | "launched" | "launch_failed",
       "upstream": UPSTREAM,
       "need_user_confirm": "x64dbg_not_running"   # 仅 need_user_confirm 时有
       "choices": [{id,label,detail}, ...],        # 仅 need_user_confirm 时有
       "message": "..."}

    参数：
      launch 未传（None） → 按默认：自动拉起（除非 SEEP_GUI_NO_AUTOLAUNCH=1）
      launch=False        → 只探活、不拉起
      launch=True         → 强制拉起
    """
    if upstream_alive():
        return {"status": "ready", "upstream": UPSTREAM, "message": "9094 已在监听"}

    if autolaunch_allowed(launch):
        log("9094 未监听 → 自动拉起 x64dbg（自己的工具，不问用户；要禁止请设 %s=1）" % DISABLE_ENV)
        ok = launch_upstream()
        if ok:
            return {"status": "launched", "upstream": UPSTREAM, "message": "已按授权拉起 x64dbg"}
        return {"status": "launch_failed", "upstream": UPSTREAM,
                "message": "自动拉起失败，见 stderr 日志；可让用户双击 x64dbg，或改走只做静态"}

    log_confirm_card()
    return {"status": "need_user_confirm",
            "need_user_confirm": "x64dbg_not_running",
            "upstream": UPSTREAM,
            "choices": [dict(c) for c in CONFIRM_CHOICES],
            "message": "x64dbg 未运行，且被显式要求不自动拉起（%s=1）" % DISABLE_ENV}


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


def serve(allow_launch: bool | None = None) -> int:
    st = ensure_upstream(allow_launch)
    upstream_ok = st["status"] in ("ready", "launched")
    if not upstream_ok:
        log("上游不可用，仍以空工具集启动：任何 tools/call 都会回一条 A/B/C 确认卡（"
            "模型会看到明确原因，而不是以为工具不存在）")

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
            # 每次调用再探一次：用户可能刚双击开了 x64dbg（选项 B）
            st = ensure_upstream(allow_launch)
            upstream_ok = st["status"] in ("ready", "launched")
            if not upstream_ok:
                resp = {"jsonrpc": "2.0", "id": mid,
                        "error": {"code": -32000, "message": confirm_card_text()}}
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
                continue

        if method in FORWARD_METHODS:
            resp = forward(msg)
        else:
            resp = {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32601, "message": f"bridge 不转发该方法：{method}"}}
        sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    return 0


# ───────────────────────── 自检 ─────────────────────────

def selftest(allow_launch: bool | None = None) -> int:
    print(f"上游：{UPSTREAM}")
    aj = auth_json_path()
    print(f"鉴权文件：{aj or '（未定位到 x64dbg 目录，可用 SEEP_X64DBG_DIR 指定）'}（token {'有' if _auth_token() else '无'}）")
    alive = upstream_alive()
    print(f"探活：{'在听' if alive else '未监听'}")
    if not alive:
        # 自检是用户**显式**发起的动作（python … --selftest），等同于选项 A 的确认；
        # 仍然尊重显式 --allow-gui-launch / 环境变量，若都未给则默认按“已确认”处理。
        granted = True if allow_launch is None else allow_launch
        print(f"自检属显式操作 → 按已确认处理（allow_launch={granted}）")
        st = ensure_upstream(granted)
        if st["status"] not in ("ready", "launched"):
            print("未确认/未就绪：" + st.get("message", ""))
            for c in CONFIRM_CHOICES:
                print(f"  {c['id']}) {c['label']} —— {c['detail']}")
            print("FAIL：上游不可用（想自动拉起请加 --allow-gui-launch）")
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
    ap = argparse.ArgumentParser(
        description="x64dbg HTTP MCP → stdio MCP 桥（默认不自动拉起 GUI，需显式授权）")
    ap.add_argument("--selftest", action="store_true", help="自检：探活 + initialize + tools/list")
    ap.add_argument("--allow-gui-launch", dest="allow_gui_launch", action="store_true",
                    default=None,
                    help="用户明确授权后才自动拉起 x64dbg GUI（等价于设 %s=1）" % ALLOW_ENV)
    a = ap.parse_args()
    if a.selftest:
        return selftest(a.allow_gui_launch)
    return serve(a.allow_gui_launch)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
