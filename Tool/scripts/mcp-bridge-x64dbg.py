#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""x64dbg 的 stdio → Streamable HTTP MCP 桥。

宿主启动本脚本，桥按配置启动调试器，再转发初始化和工具调用。
HTTP 会话标识和协商版本沿后续请求保留，通知没有 JSON-RPC 响应。
桥支持请求与响应，不支持上游主动请求、订阅和列表变化通知；初始化不协商这些能力。
上游不可达、鉴权失败、无效响应均返回错误，不伪造远端初始化成功。
默认允许启动调试器；SEEP_GUI_NO_AUTOLAUNCH=1 禁止自动启动。
--allow-gui-launch 显式覆盖此设置，--selftest 默认尊重环境设置。
启动调试器本身不会向它传入待分析目标。

配置：python <仓库>/Tool/scripts/mcp-bridge-x64dbg.py
自检：python <仓库>/Tool/scripts/mcp-bridge-x64dbg.py --selftest
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from lib import mcp_http

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TOOL_RUN = os.path.join(HERE, "tool-run.ps1")
UPSTREAM = "http://127.0.0.1:9094/mcp"
LAUNCH_TIMEOUT = 90          # 等 9094 起来的最长秒数
HTTP_TIMEOUT = 60
_SESSION_ID = None
_PROTOCOL_VERSION = None


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
        with open(p, encoding="utf-8-sig") as f:
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

    是否启动由 ensure_upstream() 的显式参数和环境设置决定。
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


# 自动启动由 DISABLE_ENV 与显式参数控制。
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
        "（选 A：移除禁止自动启动的环境设置，或使用 --allow-gui-launch；"
        "选 B：启动后 /mcp reconnect x64dbg；选 C：只做静态）"
    )
    return "\n".join(lines)


def log_confirm_card() -> None:
    log("9094 未监听：按配置不自动拉起（%s=1）；如需自动拉起，去掉该环境变量即可" % DISABLE_ENV)
    for c in CONFIRM_CHOICES:
        log("  %s) %s —— %s" % (c["id"], c["label"], c["detail"]))
    log("  自动启动：移除禁止设置，或显式传 --allow-gui-launch / ensure_upstream(launch=True)")


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
    if payload.get("method") != "initialize":
        if _SESSION_ID:
            req.add_header("Mcp-Session-Id", _SESSION_ID)
        if _PROTOCOL_VERSION:
            req.add_header("MCP-Protocol-Version", _PROTOCOL_VERSION)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            raw = mcp_http.read_response(r, payload.get("id"), HTTP_TIMEOUT)
            return r.status, r.headers.get("Content-Type", ""), {"raw": raw, "headers": dict(r.headers)}
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), {"raw": e.read()}
    except Exception as e:
        return 0, "", {"error": str(e)}


def forward(payload: dict) -> dict | None:
    global _SESSION_ID, _PROTOCOL_VERSION
    if payload.get("method") == "initialize":
        _SESSION_ID, _PROTOCOL_VERSION = None, None
        # This synchronous bridge cannot relay server-initiated requests. Do not
        # advertise the downstream client's roots/sampling/elicitation support.
        payload = {**payload, "params": {**(payload.get("params") or {}), "capabilities": {}}}
    status, ctype, info = _post(payload)
    notification = payload.get("id") is None
    if notification:
        if "error" in info or not 200 <= status < 300:
            log("上游未接受通知 " + str(payload.get("method")))
        return None
    if "error" in info:
        return {"jsonrpc": "2.0", "id": payload.get("id"),
                "error": {"code": -32000, "message": f"上游不可达：{info['error']}"}}
    raw = info.get("raw", b"")
    if not 200 <= status < 300:
        if status == 404:
            _SESSION_ID, _PROTOCOL_VERSION = None, None
        return {"jsonrpc": "2.0", "id": payload.get("id"), "error": {
            "code": -32000, "message": "上游 HTTP %s；检查鉴权或重新初始化连接" % status}}
    try:
        result = mcp_http.parse_rpc(raw, ctype, payload["id"])
        if payload.get("method") == "initialize" and "result" in result:
            init = result["result"]
            if not isinstance(init, dict) or not isinstance(init.get("protocolVersion"), str):
                raise ValueError("initialize 缺协议版本")
            if (not isinstance(init.get("serverInfo"), dict)
                    or not isinstance(init["serverInfo"].get("name"), str)
                    or not isinstance(init["serverInfo"].get("version"), str)
                    or not isinstance(init.get("capabilities"), dict)):
                raise ValueError("initialize 缺服务身份或能力")
            capabilities = {}
            for name in ("tools", "prompts", "resources", "completions"):
                if isinstance(init["capabilities"].get(name), dict):
                    capabilities[name] = {}
            result = {**result, "result": {**init, "capabilities": capabilities}}
            _SESSION_ID = mcp_http.header_value(info.get("headers", {}), "mcp-session-id") or None
            _PROTOCOL_VERSION = init["protocolVersion"]
        return result
    except (ValueError, TypeError, UnicodeError):
        return {"jsonrpc": "2.0", "id": payload.get("id"),
                "error": {"code": -32000, "message": f"上游返回无法解析（status={status}）"}}


# 需要转发到上游的方法；其余本地应答
FORWARD_METHODS = {
    "initialize", "notifications/initialized", "tools/list", "tools/call",
    "resources/list", "resources/read", "resources/templates/list",
    "prompts/list", "prompts/get", "ping", "completion/complete", "notifications/cancelled",
}


def serve(allow_launch: bool | None = None) -> int:
    st = ensure_upstream(allow_launch)
    upstream_ok = st["status"] in ("ready", "launched")
    if not upstream_ok:
        log("上游不可用：初始化与调用将返回明确错误；上游恢复后需重新连接。")
    initialized = False

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None,
                                         "error": {"code": -32700, "message": "Invalid JSON"}}) + "\n")
            sys.stdout.flush()
            continue
        if (not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0"
                or not isinstance(msg.get("method"), str)
                or ("id" in msg and type(msg["id"]) not in (int, str))
                or ("params" in msg and not isinstance(msg["params"], dict))):
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None,
                                         "error": {"code": -32600, "message": "Invalid Request"}}) + "\n")
            sys.stdout.flush()
            continue
        method = msg.get("method")
        mid = msg.get("id")

        # 通知类：无 id，不回包
        if mid is None:
            if method in FORWARD_METHODS and upstream_ok and initialized:
                forward(msg)
            continue

        if method == "initialize":
            if not upstream_ok:
                st = ensure_upstream(allow_launch)
                upstream_ok = st["status"] in ("ready", "launched")
            resp = forward(msg) if upstream_ok else {"jsonrpc": "2.0", "id": mid, "error": {
                "code": -32000, "message": st.get("message", "x64dbg 上游不可用；恢复后重新连接")}}
            initialized = isinstance(resp, dict) and "result" in resp and "error" not in resp
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue

        if not initialized and method != "ping":
            resp = {"jsonrpc": "2.0", "id": mid, "error": {
                "code": -32000, "message": "尚未成功初始化；恢复服务后重新连接 MCP，不会自动重放调用"}}
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
            continue

        if method == "ping":
            resp = {"jsonrpc": "2.0", "id": mid, "result": {}}
        elif method in FORWARD_METHODS:
            resp = forward(msg)
            if _PROTOCOL_VERSION is None:
                initialized = False
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
        # 自检与服务使用同一环境设置；仅显式启动参数可以覆盖。
        granted = autolaunch_allowed(allow_launch)
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
    if not init or "result" not in init:
        return 1
    forward({"jsonrpc": "2.0", "method": "notifications/initialized"})
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
        description="x64dbg HTTP MCP → stdio MCP 桥（默认按需启动，环境设置可禁止）")
    ap.add_argument("--selftest", action="store_true", help="自检：探活 + initialize + tools/list")
    ap.add_argument("--allow-gui-launch", dest="allow_gui_launch", action="store_true",
                    default=None,
                    help="显式允许启动 x64dbg，覆盖 SEEP_GUI_NO_AUTOLAUNCH 设置")
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
