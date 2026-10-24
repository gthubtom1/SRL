#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mcp-launch.py —— MCP stdio 启动器（把「机器专属绝对路径」从 mcp.json 里挪走）

## 为什么有这个脚本

`~/.pi/agent/mcp.json` 曾把 IDA 自带解释器与 server.py 的完整安装路径写死在里面。
后果是一换机器 / 一换盘符 / 一升 IDA 版本，MCP 就静默起不来（L8 每次报 4 处硬编码）。
本脚本把「这台机器上东西装在哪」的判断从**配置文件**搬回**代码里的解析逻辑**：
mcp.json 只留安装根（仓库自身）+ 一个 server 名字，其余全部运行期解析。

## 用法

    python <repo>/Tool/scripts/mcp-launch.py --server <ida|seep|playwright|js-reverse|x64dbg>
    python <repo>/Tool/scripts/mcp-launch.py --server ida --print    # 只打印解析结果，不启动

## 解析规则（全部动态，代码里不写任何盘符）

| server     | command                        | args                                      |
| :--------- | :----------------------------- | :---------------------------------------- |
| seep       | 当前解释器                      | `<repo>/Tool/mcp/seep_mcp_server.py`       |
| x64dbg     | 当前解释器                      | `<repo>/Tool/scripts/mcp-bridge-x64dbg.py` |
| playwright | `npx`                          | `-y @playwright/mcp@latest --headless`     |
| js-reverse | `npx`                          | `-y js-reverse-mcp`                       |
| ida        | IDA 自带 python.exe            | IDA 里的 `ida_pro_mcp/server.py`          |

`ida` 的解析顺序（找到即用，优先级从高到低）：

1. `SEEP_IDA_PYTHON`（+ 可选 `SEEP_IDA_MCP_SERVER` 显式覆盖脚本）
2. `SEEP_IDA_DIR` / `IDA_DIR` / `IDAHOME` / `IDA_PRO_DIR` 指向的安装根
3. `~/.seep/tool-paths.json` 里 `ida` 条目的 exe 反推目录（`tool-run.ps1` 的扫描缓存）
4. `where idat.exe / ida64.exe / ida.exe` 反推目录
5. 有界目录扫描：枚举本机**实际存在的盘**（不猜盘符）× `Tools` / `Tools\\disasm` /
   `Program Files` / `Program Files (x86)`，再取名字里带 `IDA` 的目录（深度 ≤2）

每条路径下再找「解释器 + 脚本」这一对：
    `<root>/python*/python.exe` + `<root>/python*/Lib/site-packages/ida_pro_mcp/server.py`
找不到就退一步深扫 `*/ida_pro_mcp/server.py`（深度 ≤4），再从祖先目录里找 `python.exe`。

## 失败纪律

解析不出来就往 stderr 打**一行**明确原因（缺什么 + 查过哪些地方），退出码 2。
绝不允许静默空转 —— 静默空转会让上游看到「进程活着但什么都没发生」，是最难查的失败形状。

退出码：被启动进程的退出码（正常 MCP 进程生命周期内不返回）；解析失败 2。
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
SERVERS = ("ida", "seep", "playwright", "js-reverse", "x64dbg")

# 只用来「找东西」的目录名（不是绝对路径，前面永远拼运行期枚举出来的根）
_TOOL_SUBDIRS = ("Tools", "Tools/disasm", "Tools/disasm/x", "Program Files",
                 "Program Files (x86)", "Program Files/IDA Pro")
_IDA_EXES = ("ida.exe", "idat.exe", "ida64.exe", "idat64.exe")


def _err(msg: str) -> None:
    sys.stderr.write("mcp-launch: " + msg + "\n")
    sys.stderr.flush()


# ─────────────────────────── 盘符 / 候选根（动态发现） ───────────────────────────

def logical_drives() -> list[str]:
    """本机真实存在的盘根（Windows 用 GetLogicalDrives，不猜 A-Z）。"""
    if os.name != "nt":
        return ["/"]
    out: list[str] = []
    try:
        import ctypes

        mask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if mask >> i & 1:
                out.append(chr(ord("A") + i) + ":\\")
    except Exception:
        pass
    return out


def _scan_roots() -> list[str]:
    """工具安装目录的候选父目录：本机每个盘的常见工具根 + 用户目录下的 Tools。"""
    roots: list[str] = []
    for d in logical_drives():
        for sub in _TOOL_SUBDIRS:
            roots.append(os.path.join(d, sub.replace("/", os.sep)))
    home = os.path.expanduser("~")
    for sub in ("Tools", "Desktop", os.path.join("AppData", "Local", "Programs")):
        roots.append(os.path.join(home, sub))
    return [r for r in roots if os.path.isdir(r)]


def _walk_bounded(root: str, max_depth: int):
    """有界遍历：产出 (目录, 文件名列表)，深度 > max_depth 立刻剪枝。"""
    root = os.path.abspath(root)
    base = root.count(os.sep)
    for dp, dn, fn in os.walk(root):
        if dp.count(os.sep) - base >= max_depth:
            dn[:] = []
        yield dp, fn


def _cache_ida_dirs() -> list[str]:
    """`~/.seep/tool-paths.json`（tool-run.ps1 的路径缓存）里 ida 的 exe → 目录。"""
    cache = os.path.join(os.path.expanduser("~"), ".seep", "tool-paths.json")
    dirs: list[str] = []
    try:
        with open(cache, encoding="utf-8-sig") as f:
            raw = json.load(f) or {}
        # 两种结构都认：顶层 {"ida":{"exe":...}}（tool-run.ps1 旧）与 tools{"ida"}{command}（autodiscover 新）
        entry = raw.get("ida") or ((raw.get("tools") or {}).get("ida") or {})
        exe = entry.get("exe") or entry.get("command") if isinstance(entry, dict) else entry
        if isinstance(exe, str):
            d = os.path.dirname(exe)
            for _ in range(2):                     # exe 可能在安装根，也可能在根下一层
                if os.path.isdir(d):
                    dirs.append(d)
                d = os.path.dirname(d)
    except Exception:
        pass
    return dirs


def _where_dirs() -> list[str]:
    """PATH 上的 IDA 可执行文件反推目录。"""
    dirs: list[str] = []
    for exe in _IDA_EXES:
        hit = shutil.which(exe)
        if hit:
            dirs.append(os.path.dirname(hit))
            dirs.append(os.path.dirname(os.path.dirname(hit)))
    return [d for d in dirs if os.path.isdir(d)]


def _ida_scan_dirs() -> list[str]:
    """有界扫描：工具根下名字带 IDA 的目录（再往里一层，兼容 `IDA Pro/App/IDA Pro`）。"""
    hits: list[str] = []
    for root in _scan_roots():
        try:
            names = [n for n in os.listdir(root) if os.path.isdir(os.path.join(root, n))]
        except OSError:
            continue
        for n in names:
            if "ida" not in n.lower():
                continue
            p = os.path.join(root, n)
            hits.append(p)
            try:
                subs = [x for x in os.listdir(p) if os.path.isdir(os.path.join(p, x))]
            except OSError:
                continue
            for s in subs:
                if "ida" in s.lower() or s.lower() == "app":
                    hits.append(os.path.join(p, s))
    return hits


def ida_candidate_dirs() -> list[tuple[str, str]]:
    """(目录, 来源) —— 保序去重；来源会写进失败信息，方便用户照着自己补。"""
    cands: list[tuple[str, str]] = []

    def push(paths, source):
        for p in paths:
            if p and os.path.isdir(p):
                cands.append((os.path.abspath(p), source))

    push([os.environ.get("SEEP_IDA_DIR"), os.environ.get("IDA_DIR"),
          os.environ.get("IDAHOME"), os.environ.get("IDA_PRO_DIR")], "env")
    push(_cache_ida_dirs(), "tool-paths 缓存")
    push(_where_dirs(), "PATH")
    push(_ida_scan_dirs(), "有界扫描")
    seen: set[str] = set()
    return [(p, s) for p, s in cands if not (p.lower() in seen or seen.add(p.lower()))]


# ─────────────────────────── IDA：解释器 + server.py 配对 ───────────────────────────

def _pair_under(root: str) -> tuple[str, str] | None:
    """在 IDA 安装根下找 (python.exe, ida_pro_mcp/server.py) 这一对。

    两种布局都要认：
      A. 直给：`<python dir>/python.exe` + 同目录 `Lib/site-packages/ida_pro_mcp/server.py`
      B. 深放：任意深度找到 `ida_pro_mcp/server.py`，再从祖先里找名叫 `python*` 的目录
    """
    # A
    for d, files in _walk_bounded(root, 2):
        if not os.path.isfile(os.path.join(d, "python.exe")):
            continue
        sp = os.path.join(d, "Lib", "site-packages", "ida_pro_mcp", "server.py")
        if os.path.isfile(sp):
            return os.path.join(d, "python.exe"), sp
    # B
    for d, files in _walk_bounded(root, 4):
        if os.path.basename(d).lower() != "ida_pro_mcp":
            continue
        sp = os.path.join(d, "server.py")
        if not os.path.isfile(sp):
            continue
        p = d
        for _ in range(4):
            if os.path.basename(p).lower().startswith("python"):
                exe = os.path.join(p, "python.exe")
                if os.path.isfile(exe):
                    return exe, sp
            p = os.path.dirname(p)
    return None


def resolve_ida() -> tuple[str, list[str]]:
    env_py = (os.environ.get("SEEP_IDA_PYTHON") or "").strip()
    env_srv = (os.environ.get("SEEP_IDA_MCP_SERVER") or "").strip()

    if env_py:
        if not os.path.isfile(env_py):
            _err(f"SEEP_IDA_PYTHON 指向的文件不存在：{portable(env_py)}")
            raise SystemExit(2)
        srv = env_srv
        if not srv:
            cand = os.path.join(os.path.dirname(env_py), "Lib", "site-packages",
                                "ida_pro_mcp", "server.py")
            srv = cand if os.path.isfile(cand) else ""
        if not srv:
            _err("SEEP_IDA_PYTHON 已给但找不到 ida_pro_mcp/server.py"
                 "（同目录 Lib/site-packages 下没有）；请再用 SEEP_IDA_MCP_SERVER 指定脚本")
            raise SystemExit(2)
        return env_py, [srv]

    if env_srv:
        # 只给了脚本：从脚本旁边的 python* 目录找解释器
        d = os.path.dirname(env_srv)
        if os.path.isfile(env_srv):
            p = d
            for _ in range(4):
                if os.path.basename(p).lower().startswith("python"):
                    exe = os.path.join(p, "python.exe")
                    if os.path.isfile(exe):
                        return exe, [env_srv]
                p = os.path.dirname(p)
        _err(f"SEEP_IDA_MCP_SERVER={portable(env_srv)} 存在性/同目录 python 检查失败")
        raise SystemExit(2)

    cands = ida_candidate_dirs()
    for root, _src in cands:
        got = _pair_under(root)
        if got:
            return got[0], [got[1]]

    looked = "；".join(f"{portable(p)}({s})" for p, s in cands[:6]) or "无任何候选目录"
    _err("解析不出 ida：缺「IDA 自带 python.exe + ida_pro_mcp/server.py」这一对。"
         f"查过 {len(cands)} 处（{looked}）。"
         "兜底：设环境变量 SEEP_IDA_PYTHON=<IDA目录>/pythonXXX/python.exe")
    raise SystemExit(2)


# ─────────────────────────── 各 server 的真实 command/args ───────────────────────────

def portable(path: str) -> str:
    """报错信息里不打印别人机器上的绝对安装路径：仓库内→相对，其余→`…/文件名`。"""
    if not path:
        return ""
    ap = os.path.abspath(path)
    try:
        if os.path.commonpath([ap, REPO]) == os.path.abspath(REPO):
            return os.path.relpath(ap, REPO).replace(os.sep, "/")
    except Exception:
        pass
    return "…/" + os.path.basename(ap)


def _need_file(path: str, what: str) -> str:
    if not os.path.isfile(path):
        _err(f"缺{what}：{portable(path)}（仓库是否完整？）")
        raise SystemExit(2)
    return path


def _npx() -> str:
    """解析出**真正能 CreateProcess 的** npx。

    坑（实测）：Git-Bash 注入的 PATH 上 `shutil.which("npx")` 先命中无扩展名的
    sh 脚本 —— 它存在、但不是 PE，直接起会报 `WinError 193 不是有效的 Win32 应用程序`。
    所以按 PATHEXT 找伴生的 .cmd / .exe。
    """
    hit = shutil.which("npx") or shutil.which("npx.cmd")
    if not hit:
        _err("找不到 npx（Node.js 未装或不在 PATH）—— playwright / js-reverse 靠它拉包")
        raise SystemExit(2)
    if os.name == "nt" and os.path.splitext(hit)[1].lower() not in (".exe", ".com", ".cmd", ".bat"):
        for ext in (".cmd", ".exe", ".bat", ".com"):
            if os.path.isfile(hit + ext):
                return hit + ext
    return hit


def resolve(name: str) -> tuple[str, list[str], dict]:
    """返回 (command, args, env 追加项)。解析失败一律 stderr 一行 + 退出 2。"""
    py = sys.executable or shutil.which("python") or "python"

    if name == "seep":
        srv = _need_file(os.path.join(REPO, "Tool", "mcp", "seep_mcp_server.py"), " seep MCP 入口")
        return py, [srv], {"PYTHONIOENCODING": "utf-8"}

    if name == "x64dbg":
        br = _need_file(os.path.join(HERE, "mcp-bridge-x64dbg.py"), "x64dbg 桥接脚本")
        return py, [br], {"PYTHONIOENCODING": "utf-8"}

    if name == "playwright":
        # 2026-10-24：`--extension` → `--headless`。
        # 旧参数要求 Chrome 里已装 “Playwright Extension”，而部署态 token 还是占位符
        # `<YOUR_PLAYWRIGHT_TOKEN>` —— 工具能列出来（25 个），一调就报
        # `Playwright Extension not found`。同一版本包用 --headless 直驱成功（能取回
        # title/body），故去掉对扩展的硬依赖。
        return _npx(), ["-y", "@playwright/mcp@latest", "--headless"], {}

    if name == "js-reverse":
        return _npx(), ["-y", "js-reverse-mcp"], {}

    if name == "ida":
        exe, args = resolve_ida()
        return exe, args, {"PYTHONIOENCODING": "utf-8"}

    _err(f"未知 server「{name}」——可选：{', '.join(SERVERS)}")
    raise SystemExit(2)


# ─────────────────────────── 启动（stdio 透传） ───────────────────────────

def launch(command: str, args: list[str], env_extra: dict) -> int:
    env = os.environ.copy()
    env.update({k: v for k, v in (env_extra or {}).items() if v is not None})

    argv = [command] + args
    # Windows 的 .cmd/.bat 不能直接 CreateProcess（WinError 193），交给 cmd /c
    if os.name == "nt" and command.lower().endswith((".cmd", ".bat")):
        argv = [os.environ.get("COMSPEC", "cmd.exe"), "/c"] + argv

    if os.name == "nt":
        # Windows 上不能用 os.execv：它走 CRT 的 _wexecv，只把 argv 用空格拼起来、
        # **不加引号** —— "IDA Pro 9.3" 这种带空格的路径会被拆成两个参数
        # （实测报错：can't open file 'D:\...\Pro'）。所以 Windows 一律用子进程转发：
        # subprocess 按 Windows 规则加引号，且不重定向 stdio（默认继承）→ stdio 原样透传。
        try:
            return subprocess.run(argv, env=env).returncode
        except OSError as e:
            _err(f"启动失败：{portable(argv[0])} —— {type(e).__name__}: {e}")
            return 2

    try:
        os.execve(argv[0], argv, env)          # POSIX：进程被替换，stdio 原样透传
    except OSError as e:
        _err(f"exec 不可用（{type(e).__name__}: {e}），改用子进程转发")
    try:
        return subprocess.run(argv, env=env).returncode
    except OSError as e:
        _err(f"启动失败：{portable(argv[0])} —— {type(e).__name__}: {e}")
        return 2


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    ap = argparse.ArgumentParser(
        prog="mcp-launch.py",
        description="MCP stdio 启动器：mcp.json 只写 server 名字，真实路径运行期解析")
    ap.add_argument("--server", required=True, choices=list(SERVERS))
    ap.add_argument("--print", dest="dry_run", action="store_true",
                    help="只打印解析出的 command/args（JSON），不启动")
    a = ap.parse_args(argv)

    command, args, env_extra = resolve(a.server)
    shown = {"server": a.server, "command": portable(command),
             "args": [portable(x) if os.path.isabs(x) else x for x in args],
             "env": env_extra}
    if a.dry_run:
        print(json.dumps(shown, ensure_ascii=False, indent=1))
        return 0

    # 一行诊断进 stderr：MCP 的 stdout 是协议通道，绝不往里写日志
    _err(f"{a.server} → {shown['command']} " + " ".join(shown["args"]))
    return launch(command, args, env_extra)


if __name__ == "__main__":
    sys.exit(main())
