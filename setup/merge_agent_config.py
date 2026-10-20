#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
merge_agent_config.py —— 跨平台 Agent 配置增量合并器（Linux / macOS / Windows 通用）

为什么需要它（血案背景）
--------------------------------------------------------------------------
旧版 `setup/install.sh` 用一行 sed 从 `Tool/mcp/mcp.json.template` 生成 mcp.json：

    sed "s|<SEEP_ROOT>|$ROOT|g" "$TEMPLATE" > "$AGENT_DIR/mcp.json"

三个致命后果：
  1. 模板里 seep 的参数是 Windows 反斜杠 `"<SEEP_ROOT>\\\\Tool\\\\mcp\\\\seep_mcp_server.py"`，
     在 Linux/macOS 上替换后是 `/home/x/Seep\\Tool\\mcp\\seep_mcp_server.py` —— 路径不存在，
     核心 MCP 直接起不来；
  2. `ida` 条目的 `<IDA_PYTHON>` / `<IDA_ROOT>` 占位符不会被替换，且 `lifecycle: eager`，
     每次启动都要拉一个不存在的命令；
  3. 整文件覆写，**用户已有的 MCP 条目被清空**，且没有任何备份。

本脚本取代那行 sed，提供：
  · POSIX 路径正确展开（跨平台）
  · 未探测到 IDA 时**不生成 ida 条目**（而不是塞占位符）
  · Playwright Token 占位符不落盘（保留已有配置，不存在才给条目）
  · 增量合并：绝不删除用户既有 MCP 条目
  · 写前自动备份（同名仅保留最近 3 个）
  · 顺带增量合并 settings.json 的 packages 列表
  · --dry-run / --print 只预览不落盘

用法
--------------------------------------------------------------------------
    python setup/merge_agent_config.py --root <工作台根目录> --agent-dir <~/.pi/agent>
    python setup/merge_agent_config.py --root . --agent-dir ~/.pi/agent --dry-run
"""

from __future__ import annotations

import argparse
import datetime
import io
import json
import os
import sys

# install-pi.ps1 与 install.sh 必须保持一致的包清单
WORKBENCH_PACKAGES = [
    "npm:pi-open-tui",
    "npm:pi-web-access",
    "npm:@juicesharp/rpiv-todo",
    "npm:@narumitw/pi-btw",
    "npm:@narumitw/pi-plan-mode",
    "npm:@narumitw/pi-usage",
    "npm:@smoose/pi-themes",
    "npm:pi-tool-display",
    "npm:@juicesharp/rpiv-ask-user-question",
    "npm:pi-playwright",
    "npm:pi-goal-x",
]

# 已退役条目：曾随旧版安装器写入，但与 pi 1.3+ 的内置 MCP 抢 `/mcp`
# （pi 的 replaceable 机制会把内置顶掉，启动报 [Extension issues]）。
# 合并时主动剔除，保证老用户升级后也能恢复内置。
RETIRED_PACKAGES = {
    "npm:pi-mcp-extension",
}

BACKUP_KEEP = 3


def log(msg: str) -> None:
    print(msg, flush=True)


def read_json(path: str):
    """读 JSON：兼容 UTF-8 BOM，坏文件返回 None（调用方决定是否重建）。"""
    if not os.path.isfile(path):
        return None
    try:
        raw = io.open(path, "r", encoding="utf-8-sig").read()
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def prune_backups(path: str, keep: int = BACKUP_KEEP) -> None:
    try:
        d = os.path.dirname(os.path.abspath(path)) or "."
        base = os.path.basename(path) + ".bak-"
        cands = [os.path.join(d, f) for f in os.listdir(d) if f.startswith(base)]
        cands.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        for old in cands[keep:]:
            try:
                os.remove(old)
            except Exception:
                pass
    except Exception:
        pass


def backup(path: str) -> str:
    if not os.path.isfile(path):
        return ""
    stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    dst = path + ".bak-" + stamp
    try:
        io.open(dst, "wb").write(io.open(path, "rb").read())
        prune_backups(path, BACKUP_KEEP)
        return dst
    except Exception:
        return ""


def write_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    text = json.dumps(data, indent=2, ensure_ascii=False)
    # UTF-8 无 BOM：Node / Pi 的 JSON.parse 对 BOM 敏感
    io.open(path, "w", encoding="utf-8", newline="\n").write(text + "\n")


def posix(path: str) -> str:
    return path.replace("\\", "/")


def build_mcp_entries(root: str, existing: dict, allow_ida: bool) -> dict:
    """生成工作台标准 MCP 条目（只用真实路径，绝不写占位符）。

    ★ 条目清单在 Tool/config/mcp-servers.json —— 新增 MCP 只加一条，本函数不用改。
    """
    root_posix = posix(os.path.abspath(root))
    entries = {}

    cfg_path = os.path.join(root, "Tool", "config", "mcp-servers.json")
    servers = {}
    try:
        with open(cfg_path, encoding="utf-8") as f:
            servers = (json.load(f) or {}).get("servers", {})
    except Exception:
        log("  [!!] 读不到 Tool/config/mcp-servers.json，跳过 MCP 注册")

    for name, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        if entry.get("onlyIfMissing") and existing.get(name):
            log("  mcp: 保留用户已有条目 %s" % name)
            continue
        text = json.dumps(entry, ensure_ascii=False).replace("{ROOT_POSIX}", root_posix)
        try:
            entries[name] = json.loads(text)
        except Exception:
            log("  [!!] mcp 条目 %s 模板解析失败，跳过" % name)

    # IDA：只有真探测到（环境变量显式给出，或用户已配置）才生成；
    # 否则不生成 —— 绝不把 "<IDA_PYTHON>" 这种占位符写进可执行配置。
    ida_py = os.environ.get("SEEP_IDA_PYTHON", "").strip()
    ida_root = os.environ.get("SEEP_IDA_ROOT", "").strip()
    if allow_ida and ida_py and ia_path_ok(ida_py):
        args = []
        server = os.path.join(ida_root, "Lib", "site-packages", "ida_pro_mcp", "server.py")
        if ida_root and os.path.isfile(server):
            args = [posix(server)]
        else:
            args = ["-m", "ida_pro_mcp.idalib_supervisor", "--stdio"]
        entries["ida"] = {
            "command": posix(ida_py),
            "args": args,
            "env": {"PYTHONIOENCODING": "utf-8"},
            "transport": "stdio",
            "lifecycle": "eager",
            "requestTimeoutMs": 180000,
        }
    return entries


def ia_path_ok(p: str) -> bool:
    return os.path.isfile(p) and ("python" in os.path.basename(p).lower())


def merge_mcp_json(args) -> int:
    dst = os.path.join(args.agent_dir, "mcp.json")
    cfg = read_json(dst) or {}
    servers = cfg.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
    before = set(servers.keys())

    new_entries = build_mcp_entries(args.root, servers, allow_ida=not args.no_ida)
    added, updated = [], []
    for name, entry in new_entries.items():
        if name in servers:
            if servers[name] != entry:
                updated.append(name)
            servers[name] = entry
        else:
            servers[name] = entry
            added.append(name)

    cfg["mcpServers"] = servers
    lost = sorted(before - set(servers.keys()))

    log("  mcp.json 目标: %s" % dst)
    log("    新增: %s" % (", ".join(added) or "（无）"))
    log("    刷新: %s" % (", ".join(updated) or "（无）"))
    log("    保留的用户条目: %s" % (", ".join(sorted(before - set(new_entries))) or "（无）"))
    if lost:
        # 理论上不可能发生（我们只增不删）；真发生就是 bug，必须显式暴露
        log("    [WARN] 检测到条目丢失（不应发生）: %s" % ", ".join(lost))

    if args.dry_run or args.print_only:
        log("  [DRY-RUN] 未写入。内容预览：")
        log(json.dumps(cfg, indent=2, ensure_ascii=False))
        return 0

    bak = backup(dst)
    if bak:
        log("    已备份: %s" % bak)
    write_json(dst, cfg)
    log("    [OK] 已写入（UTF-8 无 BOM，用户条目零删除）")
    return 0


def merge_settings_json(args) -> int:
    dst = os.path.join(args.agent_dir, "settings.json")
    cfg = read_json(dst) or {}
    pkgs = cfg.get("packages")
    if not isinstance(pkgs, list):
        pkgs = []
    added = [p for p in WORKBENCH_PACKAGES if p not in pkgs]
    retired = [p for p in pkgs if p in RETIRED_PACKAGES]
    merged = [p for p in pkgs if p not in RETIRED_PACKAGES] + added

    log("  settings.json 目标: %s" % dst)
    log("    packages: 原有 %d，新增 %d，退役剔除 %d，合计 %d" % (len(pkgs), len(added), len(retired), len(merged)))
    for p in retired:
        log("    [退役] %s —— 与 pi 内置 MCP 抢 /mcp，已移除（恢复内置）" % p)
    cfg["packages"] = merged

    # 重试档位默认值（仅缺失时写入，不覆盖用户已调过的档）：pi 默认 3 次，长任务易被 502/429 打断
    if "retry" not in cfg:
        cfg["retry"] = {
            "enabled": True,
            "maxRetries": 10,
            "baseDelayMs": 2000,
            "maxAgentDelayMs": 60000,
            "provider": {"maxRetries": 0, "maxRetryDelayMs": 30000},
        }
        log("    retry: 写入默认档位 maxRetries=10")

    if args.dry_run or args.print_only:
        log("  [DRY-RUN] 未写入 settings.json")
        return 0
    if not added and not retired and os.path.isfile(dst):
        log("    [OK] 已是最新，未改动文件")
        return 0
    bak = backup(dst)
    if bak:
        log("    已备份: %s" % bak)
    write_json(dst, cfg)
    log("    [OK] 已写入")
    return 0


def main(argv) -> int:
    ap = argparse.ArgumentParser(description="Seep 跨平台 Agent 配置增量合并器")
    ap.add_argument("--root", required=True, help="工作台物理根目录")
    ap.add_argument("--agent-dir", required=True, help="Agent 配置目录（如 ~/.pi/agent）")
    ap.add_argument("--dry-run", action="store_true", help="只预览，不改任何文件")
    ap.add_argument("--print", dest="print_only", action="store_true", help="只打印将生成的配置")
    ap.add_argument("--no-ida", action="store_true", help="强制不生成 ida 条目")
    args = ap.parse_args(argv)

    args.root = os.path.abspath(os.path.expanduser(args.root))
    args.agent_dir = os.path.abspath(os.path.expanduser(args.agent_dir))
    os.makedirs(args.agent_dir, exist_ok=True)

    log("  === Agent 配置增量合并（跨平台）===")
    rc = merge_mcp_json(args)
    if rc != 0:
        return rc
    rc = merge_settings_json(args)
    if rc != 0:
        return rc
    log("  === 合并完成 ===")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
