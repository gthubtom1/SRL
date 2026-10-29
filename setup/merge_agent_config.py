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
import tempfile
import uuid
from pathlib import Path

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
    """兼容 UTF-8 BOM；缺文件返回 None，坏文件报错并保留。"""
    if not os.path.isfile(path):
        if os.path.lexists(path):
            raise ValueError("configuration path is not a file: " + os.path.basename(path))
        return None
    try:
        with io.open(path, "r", encoding="utf-8-sig") as handle:
            raw = handle.read()
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("expected JSON object")
        return data
    except Exception as exc:
        raise ValueError("invalid JSON; original preserved: " + os.path.basename(path)) from exc


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
    stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f") + "-" + uuid.uuid4().hex
    dst = path + ".bak-" + stamp
    try:
        with io.open(path, "rb") as source, io.open(dst, "xb") as target:
            target.write(source.read())
        prune_backups(path, BACKUP_KEEP)
        return dst
    except Exception:
        return ""


def write_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    text = json.dumps(data, indent=2, ensure_ascii=False)
    # UTF-8 无 BOM：Node / Pi 的 JSON.parse 对 BOM 敏感
    fd, pending = tempfile.mkstemp(prefix=".seep-config-", dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text + "\n")
        os.replace(pending, path)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)


def posix(path: str) -> str:
    return path.replace("\\", "/")


def build_mcp_entries(root: str, existing: dict, allow_ida: bool) -> dict:
    """生成工作台标准 MCP 条目（只用真实路径，绝不写占位符）。

    ★ 条目清单在 Tool/config/mcp-servers.json —— 新增 MCP 只加一条，本函数不用改。
    """
    root_posix = posix(os.path.abspath(root))
    entries = {}

    cfg_path = os.path.join(root, "Tool", "config", "mcp-servers.json")
    with open(cfg_path, encoding="utf-8-sig") as f:
        manifest = json.load(f)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("servers"), dict):
        raise ValueError("Tool/config/mcp-servers.json 必须包含 servers 对象")
    servers = manifest["servers"]

    def expand(value):
        if isinstance(value, str):
            return value.replace("{ROOT_POSIX}", root_posix)
        if isinstance(value, list):
            return [expand(item) for item in value]
        if isinstance(value, dict):
            return {key: expand(item) for key, item in value.items()}
        return value

    for name, entry in servers.items():
        if not isinstance(entry, dict):
            raise ValueError("MCP 条目必须是对象: " + name)
        if entry.get("onlyIfMissing") and existing.get(name):
            log("  mcp: 保留用户已有条目 %s" % name)
            continue
        entries[name] = expand(entry)

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
    servers = cfg.get("mcpServers", {})
    if not isinstance(servers, dict):
        raise ValueError("mcpServers 必须为对象；原配置保留")
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
    if os.path.isfile(dst) and not bak:
        raise OSError("configuration backup failed; original preserved")
    if bak:
        log("    已备份: %s" % bak)
    write_json(dst, cfg)
    log("    [OK] 已写入（UTF-8 无 BOM，用户条目零删除）")
    return 0


def merge_settings_json(args) -> int:
    dst = os.path.join(args.agent_dir, "settings.json")
    cfg = read_json(dst) or {}
    pkgs = cfg.get("packages", [])
    if not isinstance(pkgs, list):
        raise ValueError("packages 必须为数组；原配置保留")
    added = [p for p in WORKBENCH_PACKAGES if p not in pkgs]
    retired = [p for p in pkgs if isinstance(p, str) and p in RETIRED_PACKAGES]
    merged = [p for p in pkgs if not (isinstance(p, str) and p in RETIRED_PACKAGES)] + added

    log("  settings.json 目标: %s" % dst)
    log("    packages: 原有 %d，新增 %d，退役剔除 %d，合计 %d" % (len(pkgs), len(added), len(retired), len(merged)))
    for p in retired:
        log("    [退役] %s —— 与 pi 内置 MCP 抢 /mcp，已移除（恢复内置）" % p)
    cfg["packages"] = merged

    # 重试档位默认值（仅缺失时写入，不覆盖用户已调过的档）：pi 默认 3 次，长任务易被 502/429 打断
    retry_missing = "retry" not in cfg
    if retry_missing:
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
    if not added and not retired and not retry_missing and os.path.isfile(dst):
        log("    [OK] 已是最新，未改动文件")
        return 0
    bak = backup(dst)
    if bak:
        log("    已备份: %s" % bak)
    if os.path.isfile(dst) and not bak:
        raise OSError("settings backup failed; original preserved")
    write_json(dst, cfg)
    log("    [OK] 已写入")
    return 0


def merge_prompts(args) -> int:
    """Update only the bounded source block; retain host/user additions."""
    begin, end = "<!-- seep:managed:begin -->", "<!-- seep:managed:end -->"
    for name in ("AGENTS.md", "SEEP.md"):
        source = Path(args.root, "Tool/prompts", name).read_text(encoding="utf-8-sig")
        dst = Path(args.agent_dir, name)
        existing = dst.read_text(encoding="utf-8-sig") if dst.exists() else ""
        block = begin + "\n" + source.rstrip() + "\n" + end
        if begin in existing or end in existing:
            if existing.count(begin) != 1 or existing.count(end) != 1 or existing.index(begin) > existing.index(end):
                raise ValueError("invalid managed prompt boundary: " + name)
            start, finish = existing.index(begin), existing.index(end) + len(end)
            merged = existing[:start] + ("" if args.remove_prompts_only else block) + existing[finish:]
        elif existing.startswith(source.rstrip()):
            merged = ("" if args.remove_prompts_only else block) + existing[len(source.rstrip()):]
        elif existing.startswith(("# AGENTS.md — 跨 Agent 通用作战协议", "# SEEP —— 层间裁决与指针")):
            raise ValueError("unmarked modified Seep prompt; preserve and reconcile before updating: " + name)
        else:
            merged = existing if args.remove_prompts_only else existing.rstrip() + ("\n\n" if existing.strip() else "") + block + "\n"
        if merged == existing or args.dry_run or args.print_only:
            continue
        if dst.exists() and not backup(str(dst)):
            raise OSError("prompt backup failed: " + name)
        if args.remove_prompts_only and not merged.strip():
            dst.unlink()
            continue
        fd, temp = tempfile.mkstemp(prefix=".seep-prompt-", dir=args.agent_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(merged)
            os.replace(temp, dst)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
        log("  [OK] prompt source updated; user/host text retained: " + name)
    return 0


def merge_agent_settings(args) -> int:
    """Create defaults once; validate and normalize legacy BOM without changing values."""
    dst = os.path.join(args.agent_dir, "agents", "settings.json")
    cfg = read_json(dst)
    if cfg is None:
        cfg = {"version": 1, "builtInEnabled": True, "maxConcurrent": 5}
    elif not Path(dst).read_bytes().startswith(b"\xef\xbb\xbf"):
        return 0
    if args.dry_run or args.print_only:
        return 0
    if os.path.isfile(dst) and not backup(dst):
        raise OSError("agent settings backup failed; original preserved")
    write_json(dst, cfg)
    log("  [OK] agents/settings.json 已验证并写入 UTF-8 无 BOM")
    return 0


def validate_configs(args) -> None:
    """Check deployment inputs without creating directories or changing assets."""
    for name, key, expected in (("mcp.json", "mcpServers", dict),
                                ("settings.json", "packages", list),
                                ("agents/settings.json", None, None)):
        cfg = read_json(os.path.join(args.agent_dir, name))
        if cfg is not None and key is not None and key in cfg and not isinstance(cfg[key], expected):
            raise ValueError(f"{name}: {key} 类型错误；原配置保留")
    existing = read_json(os.path.join(args.agent_dir, "mcp.json")) or {}
    build_mcp_entries(args.root, existing.get("mcpServers", {}), allow_ida=not args.no_ida)


def remove_config_entries(args) -> int:
    """Uninstall only selected entries, using the same lossless atomic JSON writer."""
    validate_configs(args)
    targets = []
    if args.remove_mcp:
        targets.append(("mcp.json", "mcpServers"))
    if args.remove_packages:
        targets.append(("settings.json", "packages"))
    for name, key in targets:
        dst = os.path.join(args.agent_dir, name)
        cfg = read_json(dst)
        if cfg is None:
            continue
        if key == "mcpServers":
            old = cfg.get(key, {})
            cfg[key] = {name: entry for name, entry in old.items() if name not in args.remove_mcp}
        else:
            old = cfg.get(key, [])
            removed = set(WORKBENCH_PACKAGES) | RETIRED_PACKAGES
            cfg[key] = [item for item in old if not (isinstance(item, str) and item in removed)]
        if cfg[key] == old or args.dry_run or args.print_only:
            continue
        if not backup(dst):
            raise OSError("configuration backup failed; original preserved: " + name)
        write_json(dst, cfg)
        log("  [OK] 已清理选定配置，用户字段保留: " + name)
    return 0


def main(argv) -> int:
    ap = argparse.ArgumentParser(description="Seep 跨平台 Agent 配置增量合并器")
    ap.add_argument("--root", required=True, help="工作台物理根目录")
    ap.add_argument("--agent-dir", required=True, help="Agent 配置目录（如 ~/.pi/agent）")
    ap.add_argument("--dry-run", action="store_true", help="只预览，不改任何文件")
    ap.add_argument("--print", dest="print_only", action="store_true", help="只打印将生成的配置")
    ap.add_argument("--no-ida", action="store_true", help="强制不生成 ida 条目")
    ap.add_argument("--prompts-only", action="store_true")
    ap.add_argument("--remove-prompts-only", action="store_true")
    ap.add_argument("--agents-only", action="store_true")
    ap.add_argument("--validate-only", action="store_true", help="安装前只校验配置与提示词，不写文件")
    ap.add_argument("--validate-configs-only", action="store_true", help="卸载前只校验配置，不写文件")
    ap.add_argument("--remove-mcp", nargs="+", default=[], metavar="NAME")
    ap.add_argument("--remove-packages", action="store_true")
    args = ap.parse_args(argv)
    actions = (args.prompts_only, args.remove_prompts_only, args.agents_only,
               args.validate_only, args.validate_configs_only,
               bool(args.remove_mcp or args.remove_packages))
    if sum(actions) > 1:
        ap.error("action flags cannot be combined (except --remove-mcp with --remove-packages)")

    args.root = os.path.abspath(os.path.expanduser(args.root))
    args.agent_dir = os.path.abspath(os.path.expanduser(args.agent_dir))
    try:
        if args.validate_configs_only:
            validate_configs(args)
            return 0
        if args.remove_mcp or args.remove_packages:
            return remove_config_entries(args)
        if args.validate_only:
            args.dry_run = True
            validate_configs(args)
            merge_prompts(args)
            log("  [OK] 安装输入校验通过（未写入）")
            return 0
        if not args.dry_run and not args.print_only:
            os.makedirs(args.agent_dir, exist_ok=True)
        if args.prompts_only or args.remove_prompts_only:
            return merge_prompts(args)
        if args.agents_only:
            return merge_agent_settings(args)

        validate_configs(args)
        log("  === Agent 配置增量合并（跨平台）===")
        rc = merge_mcp_json(args)
        if rc != 0:
            return rc
        rc = merge_settings_json(args)
        if rc != 0:
            return rc
        log("  === 合并完成 ===")
        return 0
    except (OSError, ValueError) as exc:
        log("  [FAIL] 配置合并未完成: " + str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
