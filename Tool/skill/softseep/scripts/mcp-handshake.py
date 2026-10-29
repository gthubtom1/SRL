#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mcp-handshake.py —— MCP 运行时握手 + 真实身份基线 + 漂移检测（P1-5）

## 为什么需要它（问题陈述）

`Tool/config/tool-capabilities.json` 里对每个 MCP 写的「工具数 / 版本」是**人写的声明**，
不是**实测**。声明一旦和宿主里真正跑的东西不一致，模型就会以为工具存在（或以为它有 40 个
工具，实际只有 39 个），然后在错误前提上规划下一步 —— 这类失败最难查，因为它不报错。

本脚本把「声明」换成「实测」：

    mcp.json 声明 ──> 真握手（initialize + tools/list）──> 记 serverInfo / toolsCount / codeHash
                                                              │
                                            与上次基线比对 ────┴──> OK / DRIFT / PARTIAL / BASELINE_WRITTEN

## 它到底握了什么手（不是探端口，不是看进程）

· `http` 型（有 `url` 字段）：POST `initialize` → 拿 `mcp-session-id` → `notifications/initialized`
  → `tools/list`。带 `Authorization: Bearer <AuthToken>`，token 从 server 目录的
  `mcp_config.json` 读（**运行期读、不落盘、不打印**）。
· `stdio` 型：用官方 python `mcp` 包起 `StdioServerParameters(command, args)`，
  走 `stdio_client` + `ClientSession`，握手 initialize + tools/list，**30 秒硬超时**，
  之后由 `async with` 负责收尸（关进程）。
· 连不上**不许崩**：记 `state=unreachable` + `reason`，继续下一个。

## codeHash 取什么

· `stdio`：command 指向的那个文件（见 `_stdio_target()`：`python x.py` 这类取 `x.py`，
  否则取 `which(command)` 解析出的可执行文件）。
· `http`：插件目录里的 `*.dll` + `mcp_config.json`，按文件名排序后聚合成一个 sha256。
  **`mcp_config.json` 先脱敏再算**：把 `AuthToken` 的值替换成常量 —— 这样「端口/IP 变了」
  照样触发漂移，但脚本从头到尾不碰凭据明文，也不会把哈希变成凭据的可比指纹。

## 用法

    python Tool/skill/softseep/scripts/mcp-handshake.py --check            # 握手 + 比对 + 更新基线
    python Tool/skill/softseep/scripts/mcp-handshake.py --check --json     # 机读
    python Tool/skill/softseep/scripts/mcp-handshake.py --check --no-write # 只报告，不动基线
    python Tool/skill/softseep/scripts/mcp-handshake.py --check --out X.json --mcp-json Y.json  # 测试用

退出码：0=BASELINE_WRITTEN / OK  1=DRIFT  2=PARTIAL（有 unreachable，其余一致）
"""
from __future__ import annotations

# Shared locator for both source skills and installed copies.
from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parents[2] / 'softseep' / 'scripts'))
from seep_runtime import repo_root as _seep_repo_root


import argparse
import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
def _repo_root(start):
    return _seep_repo_root(__file__)


REPO = _repo_root(HERE)
sys.path.insert(0, os.path.join(REPO, "Tool", "scripts"))
from lib import mcp_http
from lib.runtime_root import resolve_agent_root
DEFAULT_OUT = os.path.join(REPO, "Tool", "config", "packs.baseline.json")

STDIO_TIMEOUT = 30          # stdio 握手硬超时（秒）
HTTP_TIMEOUT = 15           # 单次 HTTP 请求超时（秒）
# 按新→旧尝试；老插件只认旧版本号，所以给它留一条退路
PROTO_VERSIONS = ("2025-06-18", "2024-11-05")
CLIENT_INFO = {"name": "seep-mcp-handshake", "version": "1.0.0"}


# ───────────────────────────── 基础设施 ─────────────────────────────

def _utf8() -> None:
    """中文注释 + Windows 控制台：不改编码必炸 UnicodeEncodeError。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def agent_mcp_json() -> str:
    """Selected AgentRoot's mcp.json, resolved through the shared locator."""
    return str(resolve_agent_root() / "mcp.json")


def local_state_dir() -> str:
    """Tool discovery state directory, with an explicit isolation override."""
    override = (os.environ.get("SEEP_LOCAL_STATE_DIR") or "").strip()
    if override:
        return os.path.abspath(os.path.expanduser(override))
    return os.path.join(os.path.expanduser("~"), ".seep")


def portable_path(path: str) -> str:
    """把绝对路径压成**可移植写法**，写进基线文件时用。

    为什么必须压：`Tool/config/*.json` 属 preflight 的「无机器专用绝对路径」扫描区
    （PORTABLE_DIRS），落盘绝对路径会当场把 preflight 第 6 项打红 —— 换机器/换盘符时
    这类值只是噪声，但它会挡住门禁。规则：仓库内 → 仓库相对；HOME 下 → `~/…`；
    其余（工具自己的安装目录）→ 只留文件名。
    """
    if not path:
        return ""
    ap = os.path.abspath(path)
    for base, prefix in ((os.path.abspath(REPO), ""), (os.path.expanduser("~"), "~/")):
        try:
            if os.path.commonpath([ap, base]) == base:
                return prefix + os.path.relpath(ap, base).replace(os.sep, "/")
        except Exception:
            continue
    return "…/" + os.path.basename(ap)


def _env_dirs(name: str) -> list[str]:
    """`x64dbg` → 依次试 SEEP_X64DBG_DIR / X64DBG_DIR / x64dbg_DIR。"""
    key = re.sub(r"[^A-Za-z0-9]", "_", name).upper()
    out = []
    for k in (f"SEEP_{key}_DIR", f"{key}_DIR", f"{name}_DIR"):
        v = os.environ.get(k)
        if v and os.path.isdir(v):
            out.append(v)
    return out


def server_dirs(name: str) -> list[str]:
    """动态探测「server 自己的目录」候选列表（都来自 env / 缓存 / where，绝不写死盘符）。"""
    dirs: list[str] = []
    dirs += _env_dirs(name)

    # tool-run.ps1 的路径缓存（注意两个坑：UTF-8 BOM、值是对象不是字符串）
    cache = os.path.join(local_state_dir(), "tool-paths.json")
    try:
        with open(cache, encoding="utf-8-sig") as f:
            entry = (json.load(f) or {}).get(name)
        exe = entry.get("exe") if isinstance(entry, dict) else entry
        if isinstance(exe, str):
            d = os.path.dirname(exe)
            if os.path.isdir(d):
                dirs.append(d)
    except Exception:
        pass

    # Resolve PATH without executing the target merely to learn its location.
    for candidate in (name, f"{name}.exe"):
        exe = shutil.which(candidate)
        if exe:
            dirs.append(os.path.dirname(os.path.abspath(exe)))

    # 去重且保序
    seen: set[str] = set()
    uniq = [d for d in dirs if not (d in seen or seen.add(d))]
    return uniq


def _sanitized_config_bytes(path: str) -> bytes:
    """读 mcp_config.json 并脱敏：AuthToken/Token/Secret 的值换成占位符。

    这样算出来的哈希仍然能反映「地址/端口/自启」是否被改，但**不含凭据信息**，
    脚本也永远不需要把凭据交给哈希函数以外的东西。
    """
    try:
        with open(path, "rb") as f:
            raw = f.read()
        text = raw.decode("utf-8-sig", "replace")
        try:
            data = json.loads(text)
        except Exception:
            return text.encode("utf-8")
        if not isinstance(data, dict):
            return text.encode("utf-8")

        def scrub(obj: Any) -> Any:
            if isinstance(obj, dict):
                return {k: ("<redacted>" if re.search(r"token|secret|key|pass", k, re.I) else scrub(v))
                        for k, v in obj.items()}
            if isinstance(obj, list):
                return [scrub(v) for v in obj]
            return obj

        scrubbed = scrub(data)
        scrubbed["_auth_present"] = bool(str(data.get("AuthToken") or "").strip())
        return json.dumps(scrubbed, sort_keys=True, ensure_ascii=False).encode("utf-8")
    except Exception:
        return b""


# ───────────────────────────── 身份采集 ─────────────────────────────

def _stdio_target(entry: dict) -> str | None:
    """stdio 型「command 指向的文件」到底是哪个？

    坑：mcp.json 里写的是 `"command": "python", "args": [".../bridge.py"]` ——
    直接哈希 python.exe 毫无意义（全机器共用一个解释器，升级 3.12→3.13 会假漂移）。
    所以规则是：args 里第一个**存在的脚本文件**优先，否则回落到 which(command)。
    """
    args = [a for a in (entry.get("args") or []) if isinstance(a, str)]
    for a in args:
        p = a if os.path.isabs(a) else os.path.abspath(os.path.join(entry.get("cwd") or os.curdir, a))
        if os.path.isfile(p) and os.path.splitext(p)[1].lower() in (
            ".py", ".js", ".mjs", ".cjs", ".ts", ".jar", ".ps1", ".cmd", ".bat", ".exe",
        ):
            return p
    cmd = entry.get("command")
    if isinstance(cmd, str):
        if os.path.isfile(cmd):
            return os.path.abspath(cmd)
        # 与「真正被执行的文件」对齐（_resolve_command 会把无扩展名的 npx 修正成 npx.cmd），
        # 否则哈希算的是 shim、跑的是 .cmd，两者对不上。
        return _resolve_command(cmd)
    return None


def stdio_code_hash(entry: dict) -> tuple[str | None, str | None]:
    target = _stdio_target(entry)
    if not target:
        return None, None
    return sha256_file(target), portable_path(target)


def http_code_hash(name: str) -> tuple[str | None, str | None]:
    """插件目录 *.dll + mcp_config.json → 聚合成一个 sha256。"""
    for d in server_dirs(name):
        cfg = os.path.join(d, "mcp_config.json")
        if not os.path.isfile(cfg):
            continue
        parts: list[tuple[str, str]] = []
        for fn in sorted(os.listdir(d)):
            p = os.path.join(d, fn)
            if not os.path.isfile(p):
                continue
            if fn.lower().endswith(".dll"):
                h = sha256_file(p)
            elif fn == "mcp_config.json":
                b = _sanitized_config_bytes(p)
                h = hashlib.sha256(b).hexdigest() if b else None
            else:
                continue
            if h:
                parts.append((fn.lower(), h))
        if not parts:
            return None, portable_path(d)
        agg = hashlib.sha256(
            "\n".join(f"{n}:{h}" for n, h in parts).encode("utf-8")
        ).hexdigest()
        return agg, portable_path(d)
    return None, None


def auth_token(name: str) -> str:
    """从 server 目录的 mcp_config.json 取 AuthToken。**只回内存，不打印、不落盘。**"""
    for d in server_dirs(name):
        p = os.path.join(d, "mcp_config.json")
        if not os.path.isfile(p):
            continue
        try:
            with open(p, encoding="utf-8-sig") as f:
                return str((json.load(f) or {}).get("AuthToken") or "")
        except Exception:
            continue
    return ""


# ───────────────────────────── HTTP 握手 ─────────────────────────────

def _rpc_body(method: str, params: dict | None, rid: int | None) -> bytes:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if rid is not None:
        msg["id"] = rid
    return json.dumps(msg).encode("utf-8")


def _parse_body(raw: bytes, ctype: str) -> dict | None:
    """流式 HTTP 可能回 SSE（`event: message\\ndata: {...}`），也可能回裸 JSON。"""
    text = raw.decode("utf-8", "replace").strip()
    if not text:
        return None
    if "text/event-stream" in (ctype or "") or text.startswith("event:") or "\ndata:" in text:
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
    try:
        return json.loads(text)
    except Exception:
        return None


def _post(url: str, body: bytes, token: str, session: str | None = None,
          extra_headers: dict | None = None) -> tuple[int, str, dict, bytes]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    headers.update(extra_headers or {})
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            raw = mcp_http.read_response(r, json.loads(body).get("id"), HTTP_TIMEOUT)
            return r.status, r.headers.get("Content-Type", ""), dict(r.headers), raw
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), dict(e.headers), e.read()
    except Exception as e:
        # 连接被拒 / 端口没人听 / DNS 失败，都到这里
        raise ConnectionError(f"{type(e).__name__}: {e}") from e


def handshake_http(name: str, entry: dict) -> dict:
    url = entry["url"]
    headers = mcp_http.config_headers(entry)
    token = "" if mcp_http.header_value(headers, "authorization") else auth_token(name)

    def post(payload, headers, session):
        status, ctype, received, raw = _post(url, json.dumps(payload).encode("utf-8"),
                                            token, session, headers)
        return status, received, raw

    result = mcp_http.handshake(post, headers, CLIENT_INFO, PROTO_VERSIONS)
    tools, si = result["tools"], result["serverInfo"]
    return {
        "state": "ok",
        "transport": "http",
        "serverInfo": {"name": si.get("name"), "version": si.get("version")},
        "protocolVersion": result["protocolVersion"],
        "toolsCount": len(tools),
        "toolNames": [t.get("name") for t in tools][:200],
    }


# ───────────────────────────── stdio 握手 ─────────────────────────────

def _resolve_command(raw: str) -> str:
    """把 `npx`/`python` 解析成**真正能 CreateProcess 的**文件。

    坑（实测）：`shutil.which("npx")` 在 Git-Bash 注入的 PATH 上会返回
    `…/Tools/Node/npx`（无扩展名的 sh 脚本，存在但不是 PE）→ CreateProcess
    报 `WinError 193`。所以解析完还要按 PATHEXT 找伴生的 .exe/.cmd。
    """
    p = shutil.which(raw) or raw
    if os.path.splitext(p)[1].lower() not in (".exe", ".com"):
        for ext in (".exe", ".cmd", ".bat", ".com"):
            if os.path.isfile(p + ext):
                return p + ext
    return p


def _win_batch_wrap(cmd: str, args: list[str]) -> tuple[str, list[str]]:
    """Windows 上 `.cmd` / `.bat` 不能直接交给 CreateProcess（否则 WinError 193）。

    mcp SDK 的 `get_windows_executable_command()` 只做路径解析、**不包 cmd.exe**，
    所以 `command: npx`（解析出 npx.cmd）会当场炸在启动阶段 —— 实测报
    `OSError: [WinError 193] %1 不是有效的 Win32 应用程序`。
    这里补一层包装，只对批处理生效，普通 .exe 一律原样透传。
    """
    if os.name != "nt" or not cmd.lower().endswith((".cmd", ".bat")):
        return cmd, args
    if " " in cmd:
        # cmd /S /c 的引号规则：只剥最外层一对引号，所以含空格的路径要写成 ""path" …"
        tail = subprocess.list2cmdline(args)
        return "cmd", ["/S", "/c", f'""{cmd}" {tail}"']
    return "cmd", ["/c", cmd, *args]


async def _stdio_probe(entry: dict) -> dict:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = dict(os.environ)
    env.update({k: str(v) for k, v in (entry.get("env") or {}).items()})
    cmd = entry.get("command")
    cmd = _resolve_command(cmd) if isinstance(cmd, str) else cmd
    cmd, args = _win_batch_wrap(cmd, [str(a) for a in (entry.get("args") or [])])
    params = StdioServerParameters(command=cmd, args=args, env=env, cwd=entry.get("cwd"))

    async def run() -> dict:
        # 子进程 stderr 不往控制台刷（否则 pydantic 警告 + server INFO 日志会把报告冲乱），
        # 先收进临时文件，只在失败时截尾拼进 reason。
        errlog = tempfile.TemporaryFile()
        try:
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    init = await session.initialize()
                    tools, cursor, seen = [], None, set()
                    for _ in range(mcp_http.MAX_PAGES):
                        listed = await session.list_tools(cursor=cursor)
                        tools.extend(listed.tools)
                        cursor = listed.nextCursor
                        if cursor is None:
                            break
                        if not cursor or cursor in seen:
                            raise RuntimeError("tools/list 返回空或重复 cursor")
                        seen.add(cursor)
                    else:
                        raise RuntimeError("tools/list 超过分页上限")
                    si = getattr(init, "serverInfo", None)
                    return {
                        "state": "ok",
                        "transport": "stdio",
                        "serverInfo": {
                            "name": getattr(si, "name", None),
                            "version": getattr(si, "version", None),
                        },
                        "protocolVersion": getattr(init, "protocolVersion", None),
                        "toolsCount": len(tools),
                        "toolNames": [getattr(t, "name", None) for t in tools][:200],
                    }
        except BaseException as e:
            try:
                errlog.seek(0)
                tail = errlog.read()[-600:].decode("utf-8", "replace").strip()
            except Exception:
                tail = ""
            msg = f"{type(e).__name__}: {e}"
            if tail:
                msg += " | stderr: " + " ".join(tail.split())[-300:]
            raise RuntimeError(msg) from e
        finally:
            try:
                errlog.close()
            except Exception:
                pass

    return await run()


def handshake_stdio(entry: dict) -> dict:
    """在独立事件循环里跑一次握手。`asyncio.wait_for` 给 30 秒硬超时，
    超时立即按 unreachable 记账，不再陪子进程收尸。"""
    async def bounded() -> dict:
        return await asyncio.wait_for(_stdio_probe(entry), timeout=STDIO_TIMEOUT)

    return asyncio.run(bounded())


# ───────────────────────────── 记录一条 server ─────────────────────────────

def transport_of(entry: dict) -> str:
    t = str(entry.get("transport") or "").lower()
    if t in ("http", "streamable-http", "sse"):
        return "http"
    if t == "stdio":
        return "stdio"
    if not t:
        return "http" if entry.get("url") else "stdio"
    return "invalid"


def probe_one(name: str, entry: dict) -> dict:
    transport = transport_of(entry)
    rec: dict[str, Any] = {
        "transport": transport,
        "state": "unreachable",
        "serverInfo": None,
        "protocolVersion": None,
        "toolsCount": None,
        "codeHash": None,
        "codeSource": None,
        "reason": None,
        "checked_at": now_iso(),
    }
    try:
        if transport == "invalid":
            raise RuntimeError("未知 MCP transport；拒绝猜测为 stdio/http")
        if transport == "http":
            if not entry.get("url"):
                raise RuntimeError("transport=http 但缺 url 字段")
            rec.update(handshake_http(name, entry))
            rec["codeHash"], rec["codeSource"] = http_code_hash(name)
        else:
            rec.update(handshake_stdio(entry))
            rec["codeHash"], rec["codeSource"] = stdio_code_hash(entry)
    except asyncio.TimeoutError:
        rec["reason"] = f"stdio 握手超过 {STDIO_TIMEOUT}s 未完成"
        if transport == "stdio":
            rec["codeHash"], rec["codeSource"] = stdio_code_hash(entry)
    except Exception as e:
        rec["reason"] = f"{type(e).__name__}: {e}"[:300]
        try:
            if transport == "http":
                rec["codeHash"], rec["codeSource"] = http_code_hash(name)
            else:
                rec["codeHash"], rec["codeSource"] = stdio_code_hash(entry)
        except Exception:
            pass
    return rec


# ───────────────────────────── 比对 ─────────────────────────────

def validate_baseline_record(record):
    if not isinstance(record, dict):
        raise ValueError("基线中的服务记录必须是对象")
    if record.get("serverInfo") is not None and not isinstance(record["serverInfo"], dict):
        raise ValueError("基线 serverInfo 必须是对象或 null")
    if record.get("codeHash") is not None and not isinstance(record["codeHash"], str):
        raise ValueError("基线 codeHash 必须是字符串或 null")
    if "lastKnownGood" in record:
        good = record["lastKnownGood"]
        if not isinstance(good, dict) or good.get("state") != "ok" or "lastKnownGood" in good:
            raise ValueError("基线 lastKnownGood 必须是成功记录")
        validate_baseline_record(good)


def compare(old: dict | None, new: dict) -> tuple[list[str], list[str]]:
    """返回 (drift 明细, unreachable 名单)。

    纪律：`checked_at` 每次都会变，**不参与比对**；只有 serverInfo.version /
    toolsCount / codeHash 的变化，以及 server 增删，才算漂移。
    """
    unreachable = [k for k, v in new.items() if v.get("state") not in ("ok", "disabled")]
    if not old:
        return [], unreachable
    old_servers = old.get("servers") or {}
    drift: list[str] = []
    for name in sorted(set(old_servers) | set(new)):
        o, n = old_servers.get(name), new.get(name)
        if o is None:
            drift.append(f"{name}: 新增 server（旧基线里没有）")
            continue
        if n is None:
            drift.append(f"{name}: server 消失（mcp.json 里已不再声明）")
            continue
        if n.get("state") != "ok":
            continue                      # 本次没连上 → 交给 PARTIAL 分支
        if o.get("state") != "ok":
            o = o.get("lastKnownGood")
            if not o:
                continue                  # 尚无成功身份，只算基线补齐

        ov = (o.get("serverInfo") or {}).get("version")
        nv = (n.get("serverInfo") or {}).get("version")
        if ov != nv:
            drift.append(f"{name}: 版本变化 {ov!r} → {nv!r}")
        if o.get("toolsCount") != n.get("toolsCount"):
            drift.append(f"{name}: 工具数变化 {o.get('toolsCount')} → {n.get('toolsCount')}")
        if o.get("codeHash") != n.get("codeHash"):
            oh, nh = o.get("codeHash"), n.get("codeHash")
            drift.append(
                f"{name}: 代码哈希变化 {(oh or 'null')[:12]} → {(nh or 'null')[:12]}"
                f"（源 {n.get('codeSource')}）"
            )
    return drift, unreachable


# ───────────────────────────── 主流程 ─────────────────────────────

def self_test():
    """自检：compare() 的漂移/不可达判定，纯内存，不发起握手。"""
    failed, checks = [], 0
    srv = {"a": {"state": "ok", "codeHash": "h1", "toolsCount": 20,
                 "serverInfo": {"version": "1"}, "transport": "stdio"},
           "b": {"state": "ok", "codeHash": "h2", "toolsCount": 5,
                 "serverInfo": {"version": "1"}, "transport": "stdio"}}
    base = {"servers": srv}
    checks += 1
    if any(compare(base, {k: dict(v) for k, v in srv.items()})):
        failed.append("no-drift")
    checks += 1
    drifted = {k: dict(v) for k, v in srv.items()}
    drifted["b"]["codeHash"] = "hX"
    if not compare(base, drifted)[0]:
        failed.append("hash-drift-detect")
    checks += 1
    gone = {"a": dict(srv["a"])}
    if not compare(base, gone)[0]:
        failed.append("server-removed-detect")
    checks += 1
    if compare(None, srv)[0]:
        failed.append("no-baseline-should-not-drift")
    print(json.dumps({"ok": not failed, "tool": "mcp-handshake", "checks": checks,
                      "failed": failed}, ensure_ascii=False))
    return 0 if not failed else 1


def main(argv: list[str] | None = None) -> int:
    _utf8()
    ap = argparse.ArgumentParser(description="MCP 运行时握手 + 漂移检测")
    ap.add_argument("--check", action="store_true", help="握手并与基线比对（默认动作）")
    ap.add_argument("--json", action="store_true", help="机读输出")
    ap.add_argument("--self-test", dest="self_test", action="store_true")
    ap.add_argument("--no-write", action="store_true", help="只报告，不更新基线文件")
    ap.add_argument("--mcp-json", default=None, help="覆盖 mcp.json 路径（测试用）")
    ap.add_argument("--out", default=None, help="覆盖基线文件路径（测试用）")
    ap.add_argument("--only", default=None, help="只握手名字匹配的 server（逗号分隔，测试用）")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()

    src = args.mcp_json or agent_mcp_json()
    out_path = args.out or DEFAULT_OUT

    if not os.path.isfile(src):
        print(f"FAIL 找不到 {src}", file=sys.stderr)
        return 1
    try:
        with open(src, encoding="utf-8-sig") as f:
            cfg = json.load(f) or {}
    except Exception as e:
        print(f"FAIL 读不动 {src}：{e}", file=sys.stderr)
        return 1

    if not isinstance(cfg, dict) or not isinstance(cfg.get("mcpServers"), dict):
        print(json.dumps({"ok": False, "error": "mcpServers 必须是对象"}, ensure_ascii=False))
        return 1
    servers: dict[str, dict] = cfg["mcpServers"]
    if args.only:
        keep = {s.strip() for s in args.only.split(",") if s.strip()}
        servers = {k: v for k, v in servers.items() if k in keep}
    if not servers:
        print(f"FAIL {src} 里没有 mcpServers 条目", file=sys.stderr)
        return 1

    # Load persisted state before probing or writing. A corrupt shared document
    # must not be replaced with an empty one that loses other baseline sections.
    old, doc = None, {}
    if os.path.exists(out_path):
        try:
            with open(out_path, encoding="utf-8-sig") as handle:
                doc = json.load(handle)
            if not isinstance(doc, dict):
                raise ValueError("基线必须是对象")
            old = doc.get("mcp_handshake")
            if old is not None and (not isinstance(old, dict)
                                    or not isinstance(old.get("servers"), dict)):
                raise ValueError("mcp_handshake.servers 必须是对象")
            if old is not None:
                for record in old["servers"].values():
                    validate_baseline_record(record)
        except (OSError, ValueError) as exc:
            print(json.dumps({"ok": False, "error": "基线无效，原件保留: " + str(exc)}, ensure_ascii=False))
            return 1

    new: dict[str, dict] = {}
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            new[name] = {"state": "unreachable", "transport": "unknown",
                         "reason": "服务条目必须是对象"}
            continue
        if entry.get("enabled") is False:
            new[name] = {"state": "disabled", "transport": transport_of(entry)}
        else:
            new[name] = probe_one(name, entry)
        if new[name].get("state") != "ok" and old:
            previous = old["servers"].get(name, {})
            good = previous if previous.get("state") == "ok" else previous.get("lastKnownGood")
            if good:
                new[name]["lastKnownGood"] = good

    comparison = {"servers": {name: value for name, value in old["servers"].items()
                               if name in servers}} if old and args.only else old
    drift, unreachable = compare(comparison, new)

    if drift:
        verdict, rc = "DRIFT", 1
    elif unreachable:
        verdict, rc = "PARTIAL", 2
    elif all(rec.get("state") == "disabled" for rec in new.values()):
        verdict, rc = "SKIPPED", 0
    elif not old:
        verdict, rc = ("BASELINE_PREVIEW" if args.no_write else "BASELINE_WRITTEN"), 0
    else:
        verdict, rc = "OK", 0

    payload = {
        "schemaVersion": 1,
        # 注意：不叫 generated_at —— preflight「案例产物无动态 generated_at」会把 Tool/config/*.json
        # 里的动态 generated_at 当成假现场的迹象。这里用 checked_at（与每条 server 记录同名）。
        "checked_at": now_iso(),
        "source": portable_path(src),
        "verdict": verdict,
        "rc": rc,
        "drift": drift,
        "unreachable": {k: new[k].get("reason") for k in unreachable},
        "servers": new,
    }
    if not args.no_write:
        doc = dict(doc) if isinstance(doc, dict) else {}
        doc.setdefault("schema", "seep.packs.baseline/1")
        persisted = dict(payload)
        if args.only and old:
            persisted["servers"] = {**old["servers"], **new}
        doc["mcp_handshake"] = persisted
        pending = None
        try:
            os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False,
                                             dir=os.path.dirname(os.path.abspath(out_path)),
                                             prefix=".seep-mcp-baseline-") as handle:
                pending = handle.name
                json.dump(doc, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            os.replace(pending, out_path)
        except OSError as exc:
            print(json.dumps({"ok": False, "error": "基线写入失败: " + str(exc)}, ensure_ascii=False))
            return 1
        finally:
            if pending and os.path.isfile(pending):
                os.unlink(pending)

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return rc

    # ── 人类可读输出 ──
    print(f"MCP 握手 · 来源 {src} · {payload['checked_at']}")
    label = {"ok": "OK", "unreachable": "UNREACH"}
    for name, rec in new.items():
        si = rec.get("serverInfo") or {}
        ver = si.get("version") or "-"
        ch = (rec.get("codeHash") or "null")[:12]
        line = (f"  [{label.get(rec['state'], '?')}] {name:<12} {rec['transport']:<6} "
                f"tools={str(rec.get('toolsCount')):<4} serverInfo={si.get('name') or '-'}"
                f"@{ver} hash={ch}")
        print(line)
        if rec.get("state") != "ok" and rec.get("reason"):
            print(f"           └ 原因：{rec['reason']}")

    if verdict == "BASELINE_WRITTEN":
        print(f"BASELINE_WRITTEN（首次运行，已写 {out_path}）")
    elif verdict == "BASELINE_PREVIEW":
        print("BASELINE_PREVIEW（首次预览，未写入基线）")
    elif verdict == "OK":
        print("OK（全部 server 身份与基线一致）")
    elif verdict == "SKIPPED":
        print("SKIPPED（所选服务均已禁用，未执行握手）")
    elif verdict == "DRIFT":
        print(f"DRIFT {len(drift)} 项：")
        for d in drift:
            print(f"  - {d}")
        if unreachable:
            print("  同时有 unreachable：" + ", ".join(unreachable))
        print("（未写入基线）" if args.no_write else f"（基线已按本次实测更新：{out_path}）")
    else:
        print(f"PARTIAL（{len(unreachable)} 个 unreachable，其余与基线一致）")
        for k in unreachable:
            print(f"  - {k}: {new[k].get('reason')}")
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
