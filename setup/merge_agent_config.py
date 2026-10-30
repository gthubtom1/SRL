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
import hashlib
import re
import tempfile
import uuid
from pathlib import Path

# 原包 persona/rewind：随仓库分发的本地包副本（不再从 git 拉整包）。
#   source 形如 "./packages/pi-seep-ext"，相对 settings.json（也就是 AgentRoot）解析，
#   所以不受仓库与 AgentRoot 不同盘符的影响。
PERSONA_REWIND_MANIFEST = json.loads(
    Path(__file__).with_name("pi-persona-rewind.package.json").read_text(encoding="utf-8")
)
PERSONA_REWIND_PACKAGE = PERSONA_REWIND_MANIFEST["source"]
PERSONA_PACKAGE_SOURCE_DIR = "Tool/prompts/packages/pi-seep-ext"
PERSONA_PACKAGE_TARGET_DIR = "packages/pi-seep-ext"
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
    PERSONA_REWIND_PACKAGE,
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


def plan_packages(pkgs: list, required: list) -> list:
    """决定要新增哪些包声明：保留用户条目，同一个 source 不重复添加。

    packages 里允许两种写法（settings.schema.json）：字符串「加载整包」，或
    {source, autoload, extensions, ...} 的对象形式「只加载筛选出的资源」。
    去重按 source 判断，所以用户已经把同一个包写成另一种形式时不会再塞一条。
    """
    sources = set()
    for item in pkgs:
        source = item.get("source") if isinstance(item, dict) else item
        if not isinstance(source, str) or not source.strip():
            raise ValueError("package source 必须为非空字符串；原配置保留")
        if isinstance(item, dict):
            for key in ("extensions", "skills", "prompts", "themes"):
                if key in item and (not isinstance(item[key], list)
                                    or any(not isinstance(p, str) for p in item[key])):
                    raise ValueError("package resource filter 必须为字符串数组；原配置保留")
        sources.add(source)
    return [item for item in required
            if (item.get("source") if isinstance(item, dict) else item) not in sources]


def merge_settings_json(args, *, pair_only: bool = False) -> int:
    dst = os.path.join(args.agent_dir, "settings.json")
    cfg = read_json(dst) or {}
    pkgs = cfg.get("packages", [])
    if not isinstance(pkgs, list):
        raise ValueError("packages 必须为数组；原配置保留")
    added = plan_packages(pkgs, [PERSONA_REWIND_PACKAGE] if pair_only else WORKBENCH_PACKAGES)
    retired = [] if pair_only else [p for p in pkgs if isinstance(p, str) and p in RETIRED_PACKAGES]
    merged = [p for p in pkgs if p not in retired] + added

    log("  settings.json 目标: %s" % dst)
    log("    packages: 原有 %d，新增 %d，退役剔除 %d，合计 %d" % (len(pkgs), len(added), len(retired), len(merged)))
    for p in retired:
        log("    [退役] %s —— 与 pi 内置 MCP 抢 /mcp，已移除（恢复内置）" % p)
    cfg["packages"] = merged

    # 重试档位默认值（仅缺失时写入，不覆盖用户已调过的档）：pi 默认 3 次，长任务易被 502/429 打断
    retry_missing = not pair_only and "retry" not in cfg
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


PERSONA_PACKAGE_FILES = ("package.json", "LICENSE", "UPSTREAM.json")


def _checked_path(base: Path, relative: str, *, directory: bool = False) -> Path:
    """Reject escapes, links/junctions and file/directory conflicts before backup."""
    parts = relative.split("/")
    if (not relative or any(p in ("", ".", "..") or ":" in p or "\\" in p for p in parts)
            or Path(relative).is_absolute()):
        raise ValueError("unsafe package path: " + relative)
    target = base.joinpath(*parts)
    for path in [*reversed(target.parents), target]:
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ValueError("linked deployment path: " + str(path))
        if os.path.lexists(path):
            is_dir = path != target or directory
            if (is_dir and not path.is_dir()) or (not is_dir and not path.is_file()):
                raise ValueError("deployment path type conflict: " + str(path))
    return target


def _persona_package_files(source_root: str):
    """Validate the bounded vendored subset, including every local dependency."""
    root = Path(source_root)
    _checked_path(root.parent, root.name, directory=True)
    paths = {name: _checked_path(root, name) for name in PERSONA_PACKAGE_FILES}
    for sub in ("extensions", "lib"):
        directory = _checked_path(root, sub, directory=True)
        if not directory.is_dir():
            raise ValueError("missing package directory: " + sub)
        for path in sorted(directory.glob("*.ts")):
            rel = sub + "/" + path.name
            if rel in PERSONA_REWIND_MANIFEST.get("excluded", []):
                continue
            paths[rel] = _checked_path(root, rel)
    if any(not path.is_file() for path in paths.values()):
        raise ValueError("missing package metadata file")
    package = read_json(str(paths["package.json"])) or {}
    pi = package.get("pi")
    extensions = pi.get("extensions") if isinstance(pi, dict) else None
    expected = PERSONA_REWIND_MANIFEST["extensions"]
    if extensions != ["./" + rel for rel in expected]:
        raise ValueError("package extension manifest does not match managed subset")
    if PERSONA_REWIND_PACKAGE != "./" + PERSONA_PACKAGE_TARGET_DIR:
        raise ValueError("package source must match managed target directory")
    for rel in expected:
        if rel not in paths:
            raise ValueError("missing package extension: " + rel)
    # Local module specifiers are literal in this vendored subset. Resolve both
    # static imports/exports and literal import()/require() before any writes.
    pattern = r'''(?:\bfrom\s*|\bimport\s*|\b(?:import|require)\s*\(\s*)["'](\.[^"']+)["']'''
    for rel, path in paths.items():
        if path.suffix != ".ts":
            continue
        for dependency in re.findall(pattern, path.read_text(encoding="utf-8-sig")):
            candidate = os.path.normpath(str(Path(rel).parent / dependency)).replace("\\", "/")
            if candidate.endswith(".js"):
                candidate = candidate[:-3] + ".ts"
            elif not Path(candidate).suffix:
                candidate += ".ts"
            _checked_path(root, candidate)
            if candidate not in paths:
                raise ValueError("missing or unmanaged package dependency: " + rel + " -> " + dependency)
    return sorted(paths.items())


def _package_manifest(args):
    agent = Path(args.agent_dir)
    path = _checked_path(agent, "seep-install-manifest.json")
    manifest = read_json(str(path))
    if manifest is None:
        manifest = {"schema": "seep-agent-install/1", "source_root": str(Path(args.root).resolve()),
                    "runtime_id": "seep-reverse-lab/softseep", "status": "incomplete", "managed_files": {}}
    if (manifest.get("schema") != "seep-agent-install/1"
            or manifest.get("source_root") != str(Path(args.root).resolve())
            or not isinstance(manifest.get("managed_files"), dict)):
        raise ValueError("unrecognized install ownership manifest; original preserved")
    for rel, recorded in manifest["managed_files"].items():
        if rel.startswith(PERSONA_PACKAGE_TARGET_DIR + "/"):
            _checked_path(agent, rel)
            if not isinstance(recorded, str) or not re.fullmatch("[0-9a-f]{64}", recorded):
                raise ValueError("invalid package ownership hash: " + rel)
    return path, manifest


def _package_plan(args, *, removing=False):
    agent = Path(args.agent_dir)
    target = _checked_path(agent, PERSONA_PACKAGE_TARGET_DIR, directory=True)
    manifest_path, manifest = _package_manifest(args)
    managed = manifest["managed_files"]
    changes = {}
    if removing:
        files = [(rel, None) for rel in managed if rel.startswith(PERSONA_PACKAGE_TARGET_DIR + "/")]
    else:
        source = os.path.join(args.root, *PERSONA_PACKAGE_SOURCE_DIR.split("/"))
        files = [(PERSONA_PACKAGE_TARGET_DIR + "/" + rel, Path(src).read_bytes())
                 for rel, src in _persona_package_files(source)]
    for rel, wanted in files:
        dst = _checked_path(agent, rel)
        original = dst.read_bytes() if dst.exists() else None
        recorded = managed.get(rel)
        owned = original is not None and hashlib.sha256(original).hexdigest() == recorded
        if removing:
            if owned:
                changes[dst] = None
            elif original is not None:
                log("    保留用户修改/无法证明归属的包文件: " + rel)
            managed.pop(rel, None)
        else:
            if original is not None and not owned:
                if original != wanted:
                    raise ValueError("package file is modified or ownership unknown; original preserved: " + rel)
                # Same bytes alone do not establish ownership.
                log("    保留未受管的同内容包文件: " + rel)
                managed.pop(rel, None)
                continue
            if original != wanted:
                changes[dst] = wanted
            managed[rel] = hashlib.sha256(wanted).hexdigest()
    return target, manifest_path, manifest, changes


def _write_package_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, pending = tempfile.mkstemp(prefix=".seep-pkg-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(pending, path)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)


def _apply_package_plan(args, plan, finalize=None):
    """Bounded package/config publication using the existing install manifest."""
    target, manifest_path, manifest, changes = plan
    if args.dry_run or args.print_only:
        log("  [DRY-RUN] package files: %d" % len(changes))
        if finalize:
            finalize()
        return 0
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if ((not manifest_path.exists() and not getattr(args, "_removing_package", False))
            or (manifest_path.exists() and manifest_path.read_bytes() != manifest_bytes)):
        changes[manifest_path] = manifest_bytes
    snapshots = dict.fromkeys([*changes, *(Path(args.agent_dir, name) for name in
                               ("mcp.json", "settings.json") if finalize)])
    for path in snapshots:
        _checked_path(Path(args.agent_dir), path.relative_to(args.agent_dir).as_posix())
        snapshots[path] = path.read_bytes() if path.exists() else None
    # Preserve evidence separately from the live files; never delete a whole tree.
    backup_root = target.with_name(target.name + ".bak-" + uuid.uuid4().hex)
    if changes or finalize:
        backup_root.mkdir(parents=True, exist_ok=False)
        for path, original in snapshots.items():
            if original is not None:
                saved = backup_root / path.relative_to(args.agent_dir)
                saved.parent.mkdir(parents=True, exist_ok=True)
                saved.write_bytes(original)
        log("  package recovery evidence: " + str(backup_root))
    missing_dirs = set()
    for path in snapshots:
        parent = path.parent
        while not parent.exists():
            missing_dirs.add(parent)
            parent = parent.parent
    try:
        for path, wanted in changes.items():
            if path == manifest_path:
                continue
            if wanted is None:
                if path.read_bytes() != snapshots[path]:
                    raise OSError("package changed during removal: " + str(path))
                path.unlink()
            else:
                _write_package_bytes(path, wanted)
        if finalize:
            finalize()
        if manifest_path in changes:
            _write_package_bytes(manifest_path, manifest_bytes)
        if getattr(args, "_removing_package", False) and target.is_dir():
            # Only prune ancestors of removed files, leaving user directories.
            parents = {p.parent for p in changes if p != manifest_path}
            parents.add(target)
            for parent in sorted(parents, key=lambda p: len(p.parts), reverse=True):
                if parent.is_dir() and not any(parent.iterdir()):
                    parent.rmdir()
    except Exception as exc:
        failures = []
        for path, original in reversed(list(snapshots.items())):
            try:
                current = path.read_bytes() if path.exists() else None
                if current == original:
                    continue
                if original is None:
                    path.unlink()
                else:
                    _write_package_bytes(path, original)
                if (path.read_bytes() if path.exists() else None) != original:
                    raise OSError("restore verification failed")
            except OSError as restore_error:
                failures.append(str(path) + ": " + str(restore_error))
        for directory in sorted(missing_dirs, key=lambda p: len(p.parts), reverse=True):
            try:
                if directory.is_dir() and not any(directory.iterdir()):
                    directory.rmdir()
            except OSError as restore_error:
                failures.append(str(directory) + ": " + str(restore_error))
        if failures:
            # A failed restoration must not leave a fresh success claim. Keep
            # the original manifest in backup and mark the live record incomplete
            # when writable; persistent locks still leave explicit evidence.
            try:
                failed_manifest = read_json(str(manifest_path))
                if failed_manifest is not None:
                    failed_manifest["status"] = "incomplete"
                    write_json(str(manifest_path), failed_manifest)
            except (OSError, ValueError) as status_error:
                failures.append("cannot mark install incomplete: " + str(status_error))
            try:
                (backup_root / "ROLLBACK-INCOMPLETE.json").write_text(
                    json.dumps({"status": "rollback-incomplete", "errors": failures}, indent=2) + "\n",
                    encoding="utf-8")
            except OSError as evidence_error:
                failures.append("cannot write failure evidence: " + str(evidence_error))
            raise OSError("package rollback incomplete; evidence: " + str(backup_root)
                          + "; " + "; ".join(failures)) from exc
        log("  package failure: originals restored and verified; evidence: " + str(backup_root))
        raise
    log("  [OK] package operation complete; user files retained")
    return 0


def deploy_persona_package(args, finalize=None) -> int:
    # Pair-only and direct callers must validate settings before touching the package.
    settings_path = _checked_path(Path(args.agent_dir), "settings.json")
    settings = read_json(str(settings_path)) or {}
    if not isinstance(settings.get("packages", []), list):
        raise ValueError("packages 必须为数组；原配置保留")
    plan_packages(settings.get("packages", []), [PERSONA_REWIND_PACKAGE])
    return _apply_package_plan(args, _package_plan(args), finalize)


def remove_persona_package(args, finalize=None) -> int:
    args._removing_package = True
    try:
        return _apply_package_plan(args, _package_plan(args, removing=True), finalize)
    finally:
        args._removing_package = False


def merge_prompts(args) -> int:
    """Update only the bounded source block; retain host/user additions."""
    begin, end = "<!-- seep:managed:begin -->", "<!-- seep:managed:end -->"
    planned = []
    for name in ("AGENTS.md", "SEEP.md"):
        source = Path(args.root, "Tool/prompts", name).read_text(encoding="utf-8-sig")
        dst = Path(args.agent_dir, name)
        existing = dst.read_text(encoding="utf-8-sig") if dst.exists() else ""
        block = begin + "\n" + source.rstrip() + "\n" + end
        markers = re.findall(r"<!--\s*seep:managed\b", existing)
        if markers:
            if (len(markers) != 2 or existing.count(begin) != 1 or existing.count(end) != 1
                    or existing.index(begin) > existing.index(end)):
                raise ValueError("invalid managed prompt boundary: " + name)
            start, finish = existing.index(begin), existing.index(end) + len(end)
            merged = existing[:start] + ("" if args.remove_prompts_only else block) + existing[finish:]
        elif existing.startswith(source.rstrip()):
            merged = ("" if args.remove_prompts_only else block) + existing[len(source.rstrip()):]
        elif existing.startswith(("# AGENTS.md — 跨 Agent 通用作战协议", "# SEEP —— 层间裁决与指针")):
            raise ValueError("unmarked modified Seep prompt; preserve and reconcile before updating: " + name)
        else:
            merged = existing if args.remove_prompts_only else existing.rstrip() + ("\n\n" if existing.strip() else "") + block + "\n"
        planned.append((name, dst, existing, merged))
    # Validate both prompts before changing either one, including direct callers.
    for name, dst, existing, merged in planned:
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
    if not args.remove_prompts_only:
        deploy_persona_package(args)
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


def validate_configs(args, *, deployment: bool = True) -> None:
    """Check deployment inputs without creating directories or changing assets."""
    for name in ("mcp.json", "settings.json", "agents/settings.json"):
        _checked_path(Path(args.agent_dir), name)
    for name, key, expected in (("mcp.json", "mcpServers", dict),
                                ("settings.json", "packages", list),
                                ("agents/settings.json", None, None)):
        cfg = read_json(os.path.join(args.agent_dir, name))
        if cfg is not None and key is not None and key in cfg and not isinstance(cfg[key], expected):
            raise ValueError(f"{name}: {key} 类型错误；原配置保留")
    settings = read_json(os.path.join(args.agent_dir, "settings.json")) or {}
    plan_packages(settings.get("packages", []), WORKBENCH_PACKAGES)
    _package_plan(args, removing=not deployment)
    if deployment:
        existing = read_json(os.path.join(args.agent_dir, "mcp.json")) or {}
        build_mcp_entries(args.root, existing.get("mcpServers", {}), allow_ida=not args.no_ida)


def remove_config_entries(args) -> int:
    """Uninstall only selected entries, using the same lossless atomic JSON writer."""
    validate_configs(args, deployment=False)
    if args.remove_packages:
        # Keep package files, ownership and declarations in the same bounded operation.
        return remove_persona_package(args, lambda: _remove_config_entries(args))
    return _remove_config_entries(args)


def _remove_config_entries(args) -> int:
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
            removed = {p for p in WORKBENCH_PACKAGES if isinstance(p, str)} | RETIRED_PACKAGES
            cfg[key] = [item for item in old
                        if (item.get("source") if isinstance(item, dict) else item) != PERSONA_REWIND_PACKAGE
                        and not (isinstance(item, str) and item in removed)]
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
    ap.add_argument("--persona-rewind-only", action="store_true",
                    help="仅增量声明原包 persona/rewind；不改 MCP、重试或其他包")
    ap.add_argument("--prompts-only", action="store_true")
    ap.add_argument("--remove-prompts-only", action="store_true")
    ap.add_argument("--agents-only", action="store_true")
    ap.add_argument("--validate-only", action="store_true", help="安装前只校验配置与提示词，不写文件")
    ap.add_argument("--validate-configs-only", action="store_true", help="卸载前只校验配置，不写文件")
    ap.add_argument("--remove-mcp", nargs="+", default=[], metavar="NAME")
    ap.add_argument("--remove-packages", action="store_true")
    args = ap.parse_args(argv)
    actions = (args.persona_rewind_only, args.prompts_only, args.remove_prompts_only, args.agents_only,
               args.validate_only, args.validate_configs_only,
               bool(args.remove_mcp or args.remove_packages))
    if sum(actions) > 1:
        ap.error("action flags cannot be combined (except --remove-mcp with --remove-packages)")

    args.root = os.path.abspath(os.path.expanduser(args.root))
    args.agent_dir = os.path.abspath(os.path.expanduser(args.agent_dir))
    try:
        if args.persona_rewind_only:
            return deploy_persona_package(args, lambda: merge_settings_json(args, pair_only=True))
        if args.validate_configs_only:
            validate_configs(args, deployment=False)
            return 0
        if args.remove_mcp or args.remove_packages:
            return remove_config_entries(args)
        if args.validate_only:
            args.dry_run = True
            validate_configs(args)
            merge_prompts(args)
            log("  [OK] 安装输入校验通过（未写入）")
            return 0
        if args.prompts_only or args.remove_prompts_only:
            validate_configs(args, deployment=not args.remove_prompts_only)
            if not args.dry_run and not args.print_only:
                os.makedirs(args.agent_dir, exist_ok=True)
            return merge_prompts(args)
        if args.agents_only:
            return merge_agent_settings(args)

        validate_configs(args)
        log("  === Agent 配置增量合并（跨平台）===")
        def merge_configs():
            merge_mcp_json(args)
            merge_settings_json(args)
        deploy_persona_package(args, merge_configs)
        log("  === 合并完成 ===")
        return 0
    except (OSError, ValueError) as exc:
        log("  [FAIL] 配置合并未完成: " + str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
