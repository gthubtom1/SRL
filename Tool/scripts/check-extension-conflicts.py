#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检查已装的 pi 扩展是否会顶掉 pi 的 replaceable 内置（命名冲突自检）。

背景
----
pi 把少数内置扩展标记为 ``replaceable: true``（当前为 codemode / tool-search / mcp）。
``omitReplacedExtensions()``（``dist/core/resource-loader.js``）的判定是：

    先收集所有"不可替换"扩展占用的名字（tool:<名> / command:<名> / flag:<名>），
    再逐个检查可替换扩展——只要它的任一名字已被占用，该内置就被**静默丢弃**，
    并在启动横幅打 ``[Extension issues]``。

历史事故：``npm:pi-mcp-extension`` 注册了 ``/mcp`` 命令，把内置 MCP 顶掉，
于是内置命名 ``mcp__<server>__<tool>`` 消失、第三方命名 ``mcp_<server>_<tool>`` 上线，
所有按 ``mcp__`` 写死的外部消费者（如 pi-web 的只读策略/子代理/退出登录）静默失效。

本脚本做三件事
--------------
1. 从**已安装的 pi 本体**读出 replaceable 名单（不写死，随 pi 版本变化）；
2. 扫描已装扩展（``<agent>/npm/node_modules/*`` 与 ``<agent>/extensions/*``）注册的
   tool / command / flag 名字；
3. 报告冲突，并给出处置建议；有冲突时退出码 1（可直接挂进安装器/CI）。

用法
----
    python Tool/scripts/check-extension-conflicts.py            # 体检（有冲突则 1）
    python Tool/scripts/check-extension-conflicts.py --json     # 机器可读
    python Tool/scripts/check-extension-conflicts.py --agent-dir <目录>

设计约束
--------
* 零第三方依赖、跨平台、不写死盘符与版本号；
* 只读：不修改任何配置；
* 读不到 pi 本体 → 退出码 0 并明确说"跳过"（不制造假红）。
"""

from __future__ import annotations

import argparse
import glob
import io
import json
import os
import re
import sys

# pi 内置扩展清单文件（相对 pi 包根）
BUILTIN_INDEX = os.path.join("dist", "extensions", "index.js")

# 名字注册的常见写法（源码与编译产物）
NAME_PATTERNS = [
    re.compile(r"""registerCommand\s*\(\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""registerTool\s*\(\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""registerFlag\s*\(\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""registerTool\s*\(\s*\{\s*name\s*:\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""registerCommand\s*\(\s*\{\s*name\s*:\s*["'`]([^"'`]+)["'`]"""),
]

SCAN_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
MAX_FILE_BYTES = 2 * 1024 * 1024

# 已知的高危同类（仅用于给出更具体的建议措辞，不参与判定）
KNOWN_MCP_CLIENTS = ("pi-mcp-extension", "pi-mcp", "mcp-extension")


def log(msg: str = "") -> None:
    print(msg, flush=True)


def default_agent_dir() -> str:
    env = os.environ.get("PI_AGENT_DIR") or os.environ.get("PI_CODING_AGENT_DIR")
    if env:
        return env
    return os.path.join(os.path.expanduser("~"), ".pi", "agent")


def _version_key(text: str):
    parts = re.findall(r"\d+", text)
    return tuple(int(p) for p in parts) if parts else (0,)


def find_pi_roots(agent_dir: str):
    """返回按版本从高到低的 pi 包根目录列表（用于读取内置扩展清单）。"""
    candidates = []
    patterns = [
        os.path.join(agent_dir, "install", "releases", "*", "node_modules",
                     "@earendil-works", "pi-coding-agent"),
        os.path.join(agent_dir, "install", "current", "node_modules",
                     "@earendil-works", "pi-coding-agent"),
        os.path.join(agent_dir, "node_modules", "@earendil-works", "pi-coding-agent"),
    ]
    for pat in patterns:
        for p in glob.glob(pat):
            if os.path.isfile(os.path.join(p, BUILTIN_INDEX)):
                candidates.append(p)
    uniq = sorted(set(os.path.normpath(c) for c in candidates),
                  key=lambda p: _version_key(os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(p))))),
                  reverse=True)
    return uniq


def read_json_loose(path: str):
    try:
        with io.open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except Exception:
        return None


def pi_version(pi_root: str) -> str:
    data = read_json_loose(os.path.join(pi_root, "package.json"))
    return (data or {}).get("version", "?")


def parse_replaceable(index_path: str):
    """从 dist/extensions/index.js 解析 replaceable 内置的名字。

    不写死名字：只认 ``replaceable: true`` 附近最近的那个 ``name: "..."``。
    解析不到 → 返回空集合（调用方据此判定"跳过"而不是"通过"）。
    """
    try:
        src = io.open(index_path, encoding="utf-8", errors="replace").read()
    except Exception:
        return set()
    names = set()
    for m in re.finditer(r"replaceable\s*:\s*true", src):
        pos = m.start()
        window = src[max(0, pos - 600): pos]
        found = None
        for nm in re.finditer(r"""name\s*:\s*["']([^"']+)["']""", window):
            found = nm.group(1)          # 取最近的（窗口内最后一个）
        if found:
            names.add(found)
    return names


def iter_extension_dirs(agent_dir: str):
    """已装扩展的根目录：npm 顶层包（含 @scope/pkg）与本地 extensions 目录。"""
    out = []
    npm_root = os.path.join(agent_dir, "npm", "node_modules")
    if os.path.isdir(npm_root):
        for entry in sorted(os.listdir(npm_root)):
            if entry.startswith("."):
                continue
            full = os.path.join(npm_root, entry)
            if entry.startswith("@") and os.path.isdir(full):
                for sub in sorted(os.listdir(full)):
                    p = os.path.join(full, sub)
                    if os.path.isdir(p):
                        out.append(p)
            elif os.path.isdir(full):
                out.append(full)
    local_ext = os.path.join(agent_dir, "extensions")
    if os.path.isdir(local_ext):
        out.append(local_ext)
    return out


def scan_names(root: str):
    """扫描一个扩展目录，返回 {name: (kind, file, line)}。"""
    found = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", "test", "tests", "__tests__")]
        for fn in filenames:
            if not fn.endswith(SCAN_SUFFIXES):
                continue
            path = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
                text = io.open(path, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            for pat in NAME_PATTERNS:
                for m in pat.finditer(text):
                    name = m.group(1)
                    if name not in found:
                        line = text.count("\n", 0, m.start()) + 1
                        found[name] = (os.path.relpath(path, root), line)
    return found


def pkg_label(path: str) -> str:
    data = read_json_loose(os.path.join(path, "package.json"))
    if data and data.get("name"):
        return data["name"]
    return os.path.basename(path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="检查 pi 扩展与内置（replaceable）是否抢名")
    ap.add_argument("--agent-dir", default=default_agent_dir(), help="pi agent 目录（默认 ~/.pi/agent）")
    ap.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    ap.add_argument("--quiet", action="store_true", help="只在有冲突时输出")
    args = ap.parse_args(argv)

    agent_dir = os.path.abspath(os.path.expanduser(args.agent_dir))
    roots = find_pi_roots(agent_dir)
    result = {
        "agentDir": agent_dir,
        "piRoot": None,
        "piVersion": None,
        "replaceable": [],
        "extensions": [],
        "conflicts": [],
        "status": "ok",
    }

    if not roots:
        result["status"] = "skipped"
        if args.json:
            log(json.dumps(result, ensure_ascii=False, indent=2))
        elif not args.quiet:
            log("  [跳过] 未找到已安装的 pi 本体（未装 pi 时本项不适用）")
        return 0

    pi_root = roots[0]
    index_path = os.path.join(pi_root, BUILTIN_INDEX)
    replaceable = parse_replaceable(index_path)
    result.update({
        "piRoot": pi_root,
        "piVersion": pi_version(pi_root),
        "replaceable": sorted(replaceable),
    })

    if not replaceable:
        result["status"] = "skipped"
        if args.json:
            log(json.dumps(result, ensure_ascii=False, indent=2))
        elif not args.quiet:
            log("  [跳过] 未能从 %s 解析出 replaceable 名单（pi 版本变化？）" % index_path)
        return 0

    ext_dirs = iter_extension_dirs(agent_dir)
    for root in ext_dirs:
        names = scan_names(root)
        if not names:
            continue
        label = pkg_label(root) if os.path.basename(root) != "extensions" else "(本地 extensions)"
        hits = {n: v for n, v in names.items() if n in replaceable}
        result["extensions"].append({
            "package": label,
            "path": root,
            "registered": sorted(names),
            "hits": sorted(hits),
        })
        for name, (rel, line) in sorted(hits.items()):
            result["conflicts"].append({
                "package": label,
                "name": name,
                "where": "%s:%d" % (rel, line),
            })

    if result["conflicts"]:
        result["status"] = "conflict"

    if args.json:
        log(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if result["conflicts"] else 0

    if not args.quiet:
        log("  pi %s  @ %s" % (result["piVersion"], pi_root))
        log("  replaceable 内置（可被顶掉的）：%s" % ", ".join(result["replaceable"]))
        log("  已扫扩展：%d 个" % len(result["extensions"]))

    if not result["conflicts"]:
        if not args.quiet:
            log("  [OK] 无命名冲突：pi 内置（含 MCP）保持生效")
        return 0

    log("")
    log("  [冲突] 以下扩展注册了与 pi 内置同名的命令/工具/旗标：")
    for c in result["conflicts"]:
        log("    - %s  →  %s   (%s)" % (c["package"], c["name"], c["where"]))
    log("")
    log("  后果：pi 的 replaceable 机制会丢弃同名内置并在启动打 [Extension issues]。")
    if any(any(k in c["package"] for k in KNOWN_MCP_CLIENTS) for c in result["conflicts"]):
        log("  若被顶掉的是内置 MCP：内置命名 mcp__<server>__<tool> 会消失，改为 mcp_<server>_<tool>，")
        log("  任何按 mcp__ 写死的外部消费者（pi-web 只读策略 / 子代理 / 退出登录）会静默失效。")
    log("")
    log("  处置（任选一）：")
    log("    1) 卸载该扩展（推荐，恢复内置）：从 settings.json 的 packages 删除，再 pi update --extensions")
    log("    2) 保留该扩展：确认所有外部消费者都能识别它的命名，并接受启动横幅的 [Extension issues]")
    return 1


if __name__ == "__main__":
    sys.exit(main())
