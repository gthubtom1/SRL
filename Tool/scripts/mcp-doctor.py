#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mcp-doctor.py —— MCP 服务「验连 + 自愈 + 会话注册」体检器。

为什么需要它（血案）：
    会话启动时 pi 只连一次 MCP。x64dbg 没起来 → 这一次失败 → 本轮 `mcp__x64dbg__*`
    根本不存在。模型拿不到工具，就静默改用 bash 手搓十几分钟，用户只看到右上角一闪
    而过的报错弹窗 —— 「它明明在干活，可什么都没连上」。

它干什么：
    · 逐个读 mcp.json 的 server，判断是 http 还是 stdio；
    · http：`--quick` 只测端口（0.1s）；默认发 JSON-RPC initialize + tools/list，报工具数；
    · stdio：检查 command 是否存在（不真起，避免拖慢）；
    · 失败的给出**可执行的恢复命令**，`--fix` 还会按 tool-runtimes.json 自动把宿主拉起来再复验；
    · `--session`：判定「哪些服务必须 /mcp reconnect 或重启会话才会注册工具」。
      关键事实：stdio 服务（seep / ida / js-reverse / playwright）随会话启动；
      x64dbg 走 streamable HTTP（9094），若宿主是在**本会话启动之后**才起来的，
      本轮 pi 不会注册 `mcp__x64dbg__*`，必须 `/mcp reconnect x64dbg` 或重启会话。

用法：
    python Tool/scripts/mcp-doctor.py                 # 全量体检
    python Tool/scripts/mcp-doctor.py --quick         # 只测端口（会话开头的 0.1s 自检）
    python Tool/scripts/mcp-doctor.py --session       # 会话注册判定（哪些服务需重连）
    python Tool/scripts/mcp-doctor.py --fix           # 失败的尝试自动拉起（x64dbg 后台拉起 + 超时）
    python Tool/scripts/mcp-doctor.py --json          # 机读输出
    python Tool/scripts/mcp-doctor.py --session --json
退出码：0=全部就绪（或无可检项；--session 属报告模式恒为 0） / 1=有失败或输入缺失
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_MCP = os.path.expanduser(os.path.join("~", ".pi", "agent", "mcp.json"))
RUNTIMES = os.path.join(ROOT, "Tool", "config", "tool-runtimes.json")
TOOL_RUN = os.path.join(ROOT, "Tool", "scripts", "tool-run.ps1")
FIX_TIMEOUT = 150          # tool-run.ps1 自带 90s 就绪轮询；留足余量
SESSION_ENV = "PI_SESSION_FILE"


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


def _iso(ts):
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return str(ts)


def _session_start():
    """会话起点：优先用 pi 注入的 PI_SESSION_FILE 首行 timestamp。"""
    path = os.environ.get(SESSION_ENV) or ""
    if not path or not os.path.isfile(path):
        return None, path
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for _ in range(4):
                line = f.readline()
                if not line:
                    break
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                ts = obj.get("timestamp")
                if not ts:
                    continue
                if isinstance(ts, (int, float)):
                    return float(ts), path
                return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp(), path
    except Exception:
        pass
    return None, path


def _listening_pid(port):
    """取监听指定端口的进程 PID（psutil 优先，失败返回 None）。"""
    try:
        import psutil  # type: ignore
        for c in psutil.net_connections(kind="tcp"):
            try:
                if c.laddr and c.laddr.port == port and c.status == psutil.CONN_LISTEN:
                    return c.pid
            except Exception:
                continue
    except Exception:
        pass
    return None


def _process_start(pid):
    """取进程启动时间（epoch seconds）；拿不到就返回 None。"""
    if not pid:
        return None
    try:
        import psutil  # type: ignore
        return float(psutil.Process(pid).create_time())
    except Exception:
        pass
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-Process -Id {int(pid)}).StartTime.ToUniversalTime().ToString('o')"],
            capture_output=True, text=True, timeout=8)
        raw = (out.stdout or "").strip().splitlines()
        if raw:
            return datetime.fromisoformat(raw[-1].replace("Z", "+00:00")).timestamp()
    except Exception:
        pass
    return None


def _fix_summary(detail):
    parts = [str(detail.get("status") or "?")]
    if detail.get("tool"):
        parts.insert(0, str(detail["tool"]))
    if detail.get("port"):
        parts.append("port=%s" % detail["port"])
    if detail.get("seconds") is not None:
        parts.append("%ss" % detail["seconds"])
    text = "：".join([parts[0], " ".join(parts[1:])]) if len(parts) > 1 else parts[0]
    if detail.get("reason"):
        text += " — " + str(detail["reason"])
    return text


def _try_fix(name, cfg=None):
    """按 tool-runtimes.json 的 id 尝试把宿主拉起来（x64dbg 走后台 WMI 拉起）。

    返回结构化 dict：attempted / status / stage / reason / next / summary。
    永不抛异常 —— 修不好也必须把原因说清楚（静默失败是血案源头）。
    """
    cfg = cfg or {}
    detail = {"attempted": False, "tool": name}
    if name not in _runtime_tools():
        detail.update(status="SKIPPED", stage="config",
                      reason="tool-runtimes.json 里没有该工具，无法自动拉起")
        detail["summary"] = _fix_summary(detail)
        return detail

    url = cfg.get("url") or ""
    host, port = "", None
    if url:
        u = urlparse(url)
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if u.scheme == "https" else 80)
        if _port_open(host, port):
            detail.update(status="ALREADY_READY", stage="port", port=port,
                          reason="端口已监听，无需拉起",)
            detail["summary"] = _fix_summary(detail)
            return detail

    detail["attempted"] = True
    if not os.path.isfile(TOOL_RUN):
        detail.update(status="FAILED", stage="config", port=port,
                      reason="找不到 Tool/scripts/tool-run.ps1")
        detail["summary"] = _fix_summary(detail)
        return detail

    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
           "-File", TOOL_RUN, "-Tool", name]
    started = time.time()
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=FIX_TIMEOUT)
    except subprocess.TimeoutExpired:
        # tool-run 用 WMI 脱离式启动宿主；即使外层超时，宿主进程通常还活着。
        if url and _port_open(host, port):
            detail.update(status="READY_AFTER_TIMEOUT", stage="port", port=port,
                          seconds=round(time.time() - started, 1),
                          reason="tool-run.ps1 外层超时，但宿主端口已就绪")
        else:
            detail.update(status="TIMEOUT", stage="spawn", port=port,
                          seconds=round(time.time() - started, 1),
                          reason="tool-run.ps1 在 %ss 内未返回，且端口仍未监听" % FIX_TIMEOUT,
                          next="看宿主窗口是否弹对话框；确认 MCP 插件已加载；必要时 -Use <另一个 exe>")
        detail["summary"] = _fix_summary(detail)
        return detail
    except Exception as e:  # noqa: BLE001
        detail.update(status="FAILED", stage="spawn", port=port,
                      reason="拉起失败：%s: %s" % (type(e).__name__, e))
        detail["summary"] = _fix_summary(detail)
        return detail

    payload = None
    for line in reversed((out.stdout or "").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            break
        except Exception:
            payload = None
    if isinstance(payload, dict):
        detail.update(payload)
    else:
        detail.update(status="FAILED", stage="spawn", port=port,
                      reason="tool-run.ps1 没有返回可解析的 JSON",
                      raw=(out.stdout or out.stderr or "").strip()[-400:])
    detail["attempted"] = True
    detail.setdefault("seconds", round(time.time() - started, 1))
    detail["summary"] = _fix_summary(detail)
    return detail


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


def _session_judge(name, cfg, session_start):
    """判定单个服务「本会话是否已经注册工具」以及需要什么动作。"""
    row = {"server": name, "transport": "stdio", "needs_reconnect": False,
           "status": "stdio", "port": None, "pid": None,
           "process_start": None, "detail": "", "next": ""}
    if cfg.get("enabled") is False:
        row.update(status="disabled", detail="配置里 disabled，pi 不会连接")
        row["next"] = "无需操作（需要时在 mcp.json 里启用）"
        return row

    url = cfg.get("url") or ""
    if not url:
        row["transport"] = cfg.get("transport") or "stdio"
        chk = probe_stdio(cfg)
        if chk["ok"]:
            row["status"] = "stdio"
            row["detail"] = "stdio 服务随会话启动，本轮应已注册（无需 /mcp reconnect）"
            row["next"] = "无需操作；若工具缺失，查 pi 的 MCP 启动日志 / 重装依赖"
        else:
            row.update(status="stdio_unavailable", detail=chk.get("error") or "命令不可用")
            row["next"] = "先装依赖（npx / python 模块），再重启会话"
        return row

    row["transport"] = cfg.get("transport") or ("sse" if url.rstrip("/").endswith("/sse") else "http")
    u = urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if u.scheme == "https" else 80)
    row["port"] = port
    if not _port_open(host, port):
        row.update(status="host_down", needs_reconnect=True,
                   detail="%s:%s 未监听 → 本轮没有 mcp__%s__* 工具" % (host, port, name))
        row["next"] = ("powershell -File Tool/scripts/tool-run.ps1 -Tool %s"
                       " ; 然后在 TUI 执行 /mcp reconnect %s" % (name, name))
        return row

    pid = _listening_pid(port)
    pstart = _process_start(pid)
    row["pid"] = pid
    row["process_start"] = _iso(pstart)
    if session_start and pstart:
        delta = pstart - session_start
        if delta > 1:
            row.update(status="started_after_session", needs_reconnect=True,
                       detail="宿主在本会话启动后 %.0fs 才起来 → 本轮 pi 不会注册 mcp__%s__*"
                              % (delta, name))
            row["next"] = "/mcp reconnect %s（或重启会话）" % name
        else:
            row["status"] = "registered"
            row["detail"] = ("宿主早于本会话启动（pid=%s，已运行 %.0fs）→ 会话启动时应已注册"
                             % (pid or "?", session_start - pstart))
            row["next"] = "若 mcp__%s__* 仍不存在，再 /mcp reconnect %s" % (name, name)
        return row

    row.update(status="unknown", needs_reconnect=True,
               detail="端口在监听，但无法比对宿主与会话的启动时间；保守按「需重连」处理")
    row["next"] = "先试 /mcp reconnect %s；仍无效再重启会话" % name
    return row


def _run_session(args, servers):
    session_start, session_file = _session_start()
    rows, fixes = [], {}
    for name, cfg in servers.items():
        cfg = dict(cfg or {})
        row = _session_judge(name, cfg, session_start)
        # --fix：只对「http 宿主没起来」做后台拉起（stdio 由 pi 负责）
        if args.fix and cfg.get("url") and row["status"] == "host_down":
            fix = _try_fix(name, cfg)
            fixes[name] = fix
            if fix.get("status") in ("READY", "ALREADY_READY", "READY_AFTER_TIMEOUT"):
                row = _session_judge(name, cfg, session_start)
                row["auto_fix"] = fix.get("summary")
        rows.append(row)

    must = [r["server"] for r in rows if r.get("needs_reconnect")]
    payload = {
        "file": args.file,
        "session": {"start": _iso(session_start), "source": session_file or "",
                    "known": bool(session_start)},
        "servers": rows,
        "needs_reconnect": must,
        "fixes": fixes,
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    print(f"MCP 会话注册判定（{args.file}）")
    if session_start:
        print(f"  会话起点：{_iso(session_start)}（{SESSION_ENV}）")
    else:
        print(f"  会话起点：未知（{SESSION_ENV} 缺失/无 timestamp）→ 按保守口径判定")
    for r in rows:
        mark = "需重连" if r.get("needs_reconnect") else "随会话"
        extra = f" pid={r['pid']}" if r.get("pid") else ""
        print(f"  [{mark}] {r['server']:<12} {r['transport']}{extra}  {r['detail']}")
        if r.get("auto_fix"):
            print(f"         自动拉起: {r['auto_fix']}")
        if r.get("next"):
            print(f"         下一步: {r['next']}")
    if must:
        print(f"结论：{len(must)} 个服务必须 /mcp reconnect 或重启会话：{', '.join(must)}")
    else:
        print("结论：无需重启会话（stdio 随会话；http 宿主在会话启动前已在线）")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=DEFAULT_MCP)
    ap.add_argument("--quick", action="store_true", help="只测端口，不发 JSON-RPC")
    ap.add_argument("--session", action="store_true",
                    help="判定哪些服务必须 /mcp reconnect 或重启会话才会注册工具")
    ap.add_argument("--fix", action="store_true", help="失败的尝试自动拉起宿主（x64dbg 后台拉起 + 超时）")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        print(f"[ERR] 找不到 {args.file}")
        return 1
    servers = _load_servers(args.file)
    if args.session:
        return _run_session(args, servers)

    rows, failed = [], 0

    for name, cfg in servers.items():
        if cfg.get("enabled") is False:
            rows.append({"server": name, "ok": True, "stage": "disabled", "tools": None})
            continue
        cfg = dict(cfg)
        res = probe_http(cfg, args.quick) if cfg.get("url") else probe_stdio(cfg, args.quick)
        fixed = None
        if not res["ok"] and args.fix:
            fixed = _try_fix(name, cfg)
            if cfg.get("url"):
                res = probe_http(cfg, args.quick)
        row = {"server": name, "ok": res["ok"], "stage": res["stage"],
               "tools": res.get("tools"), "detail": res.get("error") or ""}
        if not res["ok"]:
            row["recovery"] = recovery(name, cfg, res)
            failed += 1
        if fixed is not None:
            row["auto_fix"] = fixed.get("summary") or _fix_summary(fixed)
            row["auto_fix_detail"] = {k: v for k, v in fixed.items() if k != "summary"}
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
                d = r.get("auto_fix_detail") or {}
                if d.get("status") in ("READY", "ALREADY_READY", "READY_AFTER_TIMEOUT", "CLI_READY"):
                    print("         下一步: 在本会话 TUI 里执行 /mcp reconnect %s"
                          "（仅当宿主是在本会话启动之后起的）" % r["server"])
                elif d.get("reason"):
                    print("         修复失败: %s — %s" % (d.get("stage") or "?", d["reason"]))
                if d.get("next"):
                    print("         下一步: %s" % d["next"])
            if not r["ok"]:
                print(f"         恢复: {r['recovery']}")
        print(f"结果：{len(rows) - failed}/{len(rows)} 就绪")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
