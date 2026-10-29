#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tool_autodiscover.py —— 轻量「工具自动发现 + 自动适配 MCP」插件（纯增量）。

设计哲学（务必遵守，否则又会变成臃肿的 relab2）：
  1. 逻辑进仓库（本文件 + Tool/config/tool-capabilities.json），状态留本机
     （~/.seep/tool-paths.json，在用户目录、不进仓库），绝不让 GitHub 变重。
  2. 六层递进发现：环境变量 -> PATH -> 常见安装目录 -> Windows 注册表
     -> 递归扫描(带 deny 规则) -> 别名映射。不能只查 PATH。
  3. 匹配架构/版本：读目标 PE 的 machine 字段，32 位选 x32dbg、64 位选 x64dbg。
  4. 「工具怎么控制它」靠声明式能力表（tool-capabilities.json，来自联网检索），
     ★ 绝不用 -h/--help 去现场试探二进制（有些软件没有 -h，一探就崩或返回错误码）。
     表外未知工具：只报「路径已发现」，绝不假装能控。
  5. 注册 MCP 要写当前 agent 的 mcp.json（增量合并、绝不删用户条目），并提示「重启生效」。
  6. 降级链：已注册MCP -> 现注册MCP(提示重启) -> headless/CLI直调 -> GUI(不推荐) -> 自写Py脚本。
     走不通如实报，不硬等。
  7. 按已有授权执行白名单安装：先发现，缺失时安装，装后重探；仅缺必要凭据或人工步骤时交给用户。

本模块既被 seep_mcp_server.py 以 `import tool_autodiscover` 调用（零副作用），
也可独立命令行运行（见文件末尾 __main__）。
"""
import io
import contextlib
import time
import os
import sys
import json
import shutil
import struct
import subprocess
import datetime
import tempfile
import hashlib
import stat
import uuid
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# 路径与常量
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOL_DIR = os.path.dirname(_HERE)                       # Tool/
_CONFIG_DIR = os.path.join(_TOOL_DIR, "config")
_CAP_FILE = os.path.join(_CONFIG_DIR, "tool-capabilities.json")
_INSTALL_FILE = os.path.join(_CONFIG_DIR, "tool-install.json")
sys.path.insert(0, os.path.join(_TOOL_DIR, "scripts"))
from lib import process_tree
from lib.project_lock import project_lock
from lib.runtime_root import resolve_agent_root

# 本机状态（绝不入库）
LOCAL_STATE_DIR = os.path.expanduser(os.path.join("~", ".seep"))

_PATH_CACHE_FILE = os.path.join(LOCAL_STATE_DIR, "tool-paths.json")


def _cache_read(strict=False):
    """读机器级路径缓存（与 tool-run.ps1 共用同一文件与 schema）。"""
    try:
        # utf-8-sig：tool-run.ps1 用 PowerShell 写的文件带 BOM，用 utf-8 读会解析失败，
        # 失败后整份覆盖会**丢掉已有条目**（实测踩到：r2/jadx 被新条目顶掉）。
        with io.open(_PATH_CACHE_FILE, encoding="utf-8-sig") as f:
            d = json.load(f)
        if not isinstance(d, dict) or not isinstance(d.get("tools", {}), dict):
            raise ValueError("工具缓存及 tools 必须是对象")
        return d
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, TypeError):
        if strict:
            raise
        return {}


def _cache_get(tid, exe_names):
    """缓存命中且路径仍可用才算命中（工具可能被卸载/挪走）。"""
    raw = _cache_read()
    e = raw.get("tools", {}).get(tid)
    if not isinstance(e, dict) or not e.get("available"):
        legacy = raw.get(tid)          # 旧结构：顶层 <id> = {"exe": ...}
        e = {"available": True, "command": (legacy or {}).get("exe")} if isinstance(legacy, dict) else None
    if not isinstance(e, dict) or not e.get("available"):
        return None
    cmd = e.get("command") or ""
    if not isinstance(cmd, str) or not cmd or _denied(cmd):
        return None
    if os.path.isfile(cmd):
        # 迁移：老缓存可能只有 tools{} 没有顶层 <id>.exe（bridge/launch 读的是后者）→ 补写一次
        if not isinstance(raw.get(tid), dict):
            _cache_put(tid, cmd, e.get("via") or "cache", e.get("arch"))
        return {"command": cmd, "via": "cache"}
    # 路径失效：若是 exe 名而非绝对路径（如 PATH 命中记的是命令名），交给后面各层
    base = os.path.basename(cmd).lower()
    if base in [n.lower() for n in (exe_names or [])] and shutil.which(cmd):
        return {"command": cmd, "via": "cache"}
    return None


def _cache_put(tid, command, via, arch=None):
    """命中即记住（只写用户目录，绝不写进仓库）。"""
    try:
        with project_lock(Path(_PATH_CACHE_FILE).parent):
            d = _cache_read(strict=True)
            tools = d.setdefault("tools", {})
            tools[tid] = {
                "available": True, "command": command, "via": via, "arch": arch,
                "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            # 保留 bridge/launch 使用的旧结构，以及其他工具和用户字段。
            d[tid] = {"exe": command, "via": via,
                      "verified": time.strftime("%Y-%m-%d %H:%M:%S")}
            d["schemaVersion"] = d.get("schemaVersion") or "1.0"
            pending = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                        dir=Path(_PATH_CACHE_FILE).parent, prefix=".seep-cache-", delete=False) as f:
                    pending = f.name
                    json.dump(d, f, ensure_ascii=False, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(pending, _PATH_CACHE_FILE)
            finally:
                if pending and os.path.exists(pending):
                    os.unlink(pending)
        return True
    except Exception:
        return False


LOCAL_STATE_PATH = os.path.join(LOCAL_STATE_DIR, "tools.local.json")

# ---------------------------------------------------------------------------
# 工具根目录：动态生成，绝不写死盘符/安装位置
#
# 原版（reverse-skill）的 ToolDiscovery.ps1 用的是「每工具 fallbacks 列表」，
# 路径都相对于 $USERPROFILE / $LOCALAPPDATA —— 换电脑天然可用。
# 我们把它升级成「候选根清单 + 六层探测」，规则：
#   ① 环境变量显式指定（最高优先）
#   ② 用户级目录（含本工作台自己的安装目录 ~/.seep/tools）
#   ③ Windows 用户级安装位置（LOCALAPPDATA\Programs / Android SDK / APPDATA）
#   ④ 各盘符的常见工具目录名（动态枚举存在的盘，不预设 C/D/F）
#   ⑤ POSIX 常见位置
# 只保留真实存在的目录；安装目标另算（见 _install_base()）。
# ---------------------------------------------------------------------------
_DRIVE_LETTERS = "CDEFGHIJKLMNOPQRSTUVWXYZ"
_ROOT_DIR_NAMES = ("Tools", "Tool", "Tools64", "Reverse", "Reversing", "GreenSoft", "soft", "bin")


def _user_home():
    return os.path.expanduser("~")


def candidate_roots(include_missing=False):
    """返回候选工具根目录列表（去重、保持优先级顺序）。"""
    roots = []

    # ① 环境变量
    for key in ("SEEP_TOOL_INSTALL_DIR", "SEEP_TOOL_ROOT", "REVERSE_TOOL_ROOT", "SEEP_TOOLS_DIR"):
        v = (os.environ.get(key) or "").strip()
        if v:
            roots.append(os.path.expanduser(v))

    home = _user_home()

    # ② 用户级
    roots.append(os.path.join(home, ".seep", "tools"))      # 本工作台安装目标
    roots.append(os.path.join(home, "go", "bin"))
    if os.environ.get('GOBIN'):
        roots.append(os.path.expanduser(os.environ['GOBIN']))
    roots.extend(os.path.join(os.path.expanduser(p), 'bin')
                 for p in os.environ.get('GOPATH', '').split(os.pathsep) if p)
    roots += [os.path.join(home, "Tools"), os.path.join(home, "tools"),
              os.path.join(home, "Reverse"), os.path.join(home, "soft")]

    # ③ Windows 用户级安装位置
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA") or ""
        appdata = os.environ.get("APPDATA") or ""
        if local:
            roots += [
                os.path.join(local, "Programs"),
                os.path.join(local, "Android", "Sdk"),
                os.path.join(local, "Android", "Sdk", "platform-tools"),
                local,
            ]
        if appdata:
            roots.append(appdata)

    # ④ 各盘符（动态枚举）
    if sys.platform == "win32":
        for letter in _DRIVE_LETTERS:
            drive = letter + ":" + os.sep
            if not os.path.exists(drive):
                continue
            for name in _ROOT_DIR_NAMES:
                roots.append(os.path.join(drive, name))
            # Program Files 只加浅层，且只在盘根存在时（避免 26×N 次无谓 os.path.isdir）
            roots.append(os.path.join(drive, "Program Files"))
            roots.append(os.path.join(drive, "Program Files (x86)"))

    # ⑤ POSIX
    roots += ["/opt", "/usr/local/bin", "/usr/bin", "/snap/bin",
              os.path.join(home, ".local", "bin")]

    seen = set()
    out = []
    for r in roots:
        if not r:
            continue
        key = os.path.normcase(os.path.abspath(r))
        if key in seen:
            continue
        seen.add(key)
        if include_missing or os.path.isdir(r):
            out.append(r)
    return out


def _install_base():
    """工具安装目标基目录（永远是用户级，不写死盘符）。"""
    env = (os.environ.get("SEEP_TOOL_INSTALL_DIR") or "").strip()
    if env:
        return os.path.abspath(os.path.expanduser(env))
    return os.path.join(_user_home(), ".seep", "tools")


_COMMON_ROOTS = candidate_roots()

# 扫描时需要跳过的重目录：node_modules / site-packages / WinSxS / 缓存 等。
# 为什么需要：`_layer_scan` 只有 20s / 12 万目录预算，而 D:\Tools 下含整套 Node
# 的 node_modules —— 预算会在第一个根里就耗尽，导致 `D:\Tools\disasm\IDA Pro 9.3\ida.exe`
# 这类真实安装被漏判（实测 MCP 显示 ida 不可用，而 IDA 明明装着）。
_SKIP_DIR_NAMES = frozenset({
    "node_modules", ".git", "__pycache__", "site-packages", "winsxs", "temp", "tmp",
    "cache", "caches", "logs", ".venv", "venv", "include",
})

# 递归扫描的 deny 规则（避免误命中 IDA 自带裸 python、插件目录等）
_DENY_MARKERS = [
# \u2605 只拦 IDA 自带的运行期子目录，绝不能拦「IDA Pro 9.x」安装根 ——
#   旧写法含一个裸 "ida pro" 子串，导致 D:\\Tools\\disasm\\IDA Pro 9.3\\ida.exe 本身也被拒，
#   seep_tool_discover 因此永远报 ida 不可用（而 IDA 明明装着）。见 CHANGELOG 1.10.7。
    "ida pro\\python", "ida pro/python", "ida\\python", "ida/python",
    "python27", "python3.8\\python",
    "\\plugins\\", "/plugins/", "\\sdk\\", "/sdk/", "node_modules",
    "\\windows\\winsxs", "/usr/share/doc",
]

# 别名映射（第 6 层）：把用户口语/工具族映射到规范 tool_id
_ALIAS_MAP = {
    "radare2": "r2", "r2pm": "r2", "r2pipe": "r2",
    "ida64": "ida", "idat": "ida", "idat64": "ida", "idapro": "ida", "ida pro": "ida",
    "x96dbg": "x64dbg", "x32dbg": "x32dbg", "x64dbg": "x64dbg",
    "windbg": "cdb", "windbgx": "cdb", "windbgxp": "cdb", "kd": "cdb", "ntsd": "cdb",
    "pe-sieve64": "pe-sieve", "pe_sieve": "pe-sieve", "pesieve": "pe-sieve",
    "flare-floss": "floss",
    "detect-it-easy": "diec", "detect it easy": "diec", "die": "diec",
    "analyzeheadless": "ghidra", "ghidra": "ghidra",
    "wireshark": "tshark",
    "jadx-gui": "jadx",
    "frida-tools": "frida", "frida-server": "frida",
}


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _capabilities_table():
    return _load_json(_CAP_FILE, {"tools": {}, "mcp_ecosystem": {}})


def _install_table():
    """Load the install catalog without letting malformed shapes reach callers.

    A missing catalog is a normal empty catalog.  An existing but unreadable or
    malformed catalog carries an explicit ``_config_error`` marker so every
    discovery/install entry can fail closed with a structured result.
    """
    default = {"installable": {}, "auto_allow_methods": ["pip"]}
    try:
        with open(_INSTALL_FILE, "r", encoding="utf-8") as stream:
            value = json.load(stream)
    except FileNotFoundError:
        return default
    except Exception as exc:
        return {**default, "_config_error": "安装清单无法解析: %s" % type(exc).__name__}
    if not isinstance(value, dict):
        return {**default, "_config_error": "安装清单根对象必须是对象"}
    if not isinstance(value.get("installable"), dict):
        return {**default, "_config_error": "安装清单 installable 必须是对象"}
    allowed = value.get("auto_allow_methods", [])
    if not isinstance(allowed, list) or any(not isinstance(item, str) for item in allowed):
        return {**default, "_config_error": "安装清单 auto_allow_methods 必须是字符串数组"}
    return value


def normalize_tool_id(tool_id):
    """第 6 层别名映射：把口语/变体名规范化为能力表里的 tool_id。"""
    tid = (tool_id or "").strip().lower()
    return _ALIAS_MAP.get(tid, tid)


def _exe_candidates(tool_id, arch=None):
    """返回可执行文件名候选；arch_aware 工具按目标位宽筛选。"""
    caps = _capabilities_table().get("tools", {}).get(tool_id, {})
    if caps.get("arch_aware") and arch:
        variants = caps.get("arch_variants", {})
        if arch in variants:
            return variants[arch]
    return caps.get("exe_candidates", [tool_id])


def _denied(path):
    low = path.lower()
    return (any(m in low for m in _DENY_MARKERS)
            or any(part.startswith(('.seep-install-', '.seep-previous-'))
                   for part in low.replace('\\', '/').split('/')))


# ---------------------------------------------------------------------------
# 架构/版本匹配：读目标 PE 的 machine 字段
# ---------------------------------------------------------------------------
def read_pe_machine(path):
    """读 PE 头 machine 字段，返回 'x86' / 'x64' / 'arm64' / None（非 PE 或失败）。"""
    try:
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                return None
            f.seek(0x3C)
            e_lfanew = struct.unpack("<I", f.read(4))[0]
            if e_lfanew <= 0 or e_lfanew > 0x10000000:
                return None
            f.seek(e_lfanew)
            if f.read(4) != b"PE\x00\x00":
                return None
            machine = struct.unpack("<H", f.read(2))[0]
        return {0x8664: "x64", 0x014C: "x86", 0xAA64: "arm64", 0x01C4: "arm"}.get(machine)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 六层递进发现
# ---------------------------------------------------------------------------
def _layer_env(tool_id, exe_names, caps=None):
    """第 1 层：环境变量显式指定（最高优先）。"""
    env_key = "SEEP_" + "".join(ch if ch.isalnum() else "_" for ch in tool_id.upper()) + "_PATH"
    val = os.environ.get(env_key, "")
    if val and os.path.isfile(val) and not _denied(val) and not _path_excluded(val, caps or {}):
        return {"available": True, "command": val, "via": "env", "env_key": env_key}
    return None


def _layer_path(exe_names, caps=None):
    """第 2 层：PATH 查找（系统安装优先于便携副本）。"""
    for e in exe_names:
        for directory in os.get_exec_path():
            w = shutil.which(e, path=directory)
            if w and not _denied(w) and not _path_excluded(w, caps or {}):
                return {"available": True, "command": w, "via": "PATH"}
    return None


def _layer_common_dirs(exe_names, caps=None):
    """第 3 层：常见安装根的直接子目录 / bin / cli。"""
    for root in _COMMON_ROOTS:
        if not root or not os.path.isdir(root):
            continue
        for e in exe_names:
            for sub in ("", "bin", "cli"):
                base = os.path.join(root, sub, e) if sub else os.path.join(root, e)
                for cand in (base, base + ".exe"):
                    if os.path.isfile(cand) and not _denied(cand) and not _path_excluded(cand, caps or {}):
                        return {"available": True, "command": cand, "via": "common_dir"}
    return None


def _reg_read(sk, name):
    try:
        import winreg
        v, _ = winreg.QueryValueEx(sk, name)
        return v
    except Exception:
        return ""


def _registry_install_dirs(name_hints):
    """第 4 层：Windows 注册表「已安装程序」-> InstallLocation。非 Windows 返回 []。"""
    if sys.platform != "win32":
        return []
    try:
        import winreg
    except Exception:
        return []
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    dirs = []
    for hive, path in roots:
        try:
            k = winreg.OpenKey(hive, path)
        except Exception:
            continue
        try:
            n = winreg.QueryInfoKey(k)[0]
        except Exception:
            continue
        for i in range(n):
            try:
                sub = winreg.EnumKey(k, i)
                sk = winreg.OpenKey(k, sub)
            except Exception:
                continue
            disp = str(_reg_read(sk, "DisplayName") or "")
            loc = str(_reg_read(sk, "InstallLocation") or "")
            if disp and any(h.lower() in disp.lower() for h in name_hints):
                if loc and os.path.isdir(loc):
                    dirs.append(loc)
    return dirs


def _layer_registry(tool_id, exe_names, caps):
    """第 4 层：注册表定位安装目录后再找 exe。"""
    hints = [tool_id] + ([caps.get("display")] if caps.get("display") else [])
    for d in _registry_install_dirs(hints):
        for e in exe_names:
            for cand in (os.path.join(d, e), os.path.join(d, e + ".exe"),
                         os.path.join(d, "bin", e), os.path.join(d, "bin", e + ".exe")):
                if os.path.isfile(cand) and not _denied(cand) and not _path_excluded(cand, caps):
                    return {"available": True, "command": cand, "via": "registry",
                            "install_dir": d}
    return None


def _layer_scan(tool_id, exe_names, max_depth=4, caps=None):
    """第 5 层：在常见根下递归扫描（带 deny 规则，限深度）。

    ★ 必须「按候选名优先级逐个全树扫描」，不能把它们并成一个集合一次 walk：
      x64dbg 包里同时有 `x96dbg.exe`（GUI 启动器，会弹选择框）和
      `release/x64/x64dbg.exe`（真正的调试器）。并集扫描会先撞上父目录的启动器，
      后续"怎么控制它"就会拿到一个会把自动化卡死的 GUI 壳。
    """
    # 扫描预算：多盘 + 大目录下必须限流，否则一次探测能把 MCP 拖到超时
    import time as _time
    budget_dirs = 120000
    deadline = _time.time() + 20.0
    visited = 0

    for e in exe_names:
        wanted = {e.lower()}
        if not e.lower().endswith(".exe"):
            wanted.add(e.lower() + ".exe")
        for root in _COMMON_ROOTS:
            if not root or not os.path.isdir(root):
                continue
            try:
                for dirpath, dirnames, filenames in os.walk(root):
                    dirnames[:] = [d for d in dirnames if d.lower() not in _SKIP_DIR_NAMES
                                   and not _denied(os.path.join(dirpath, d))]
                    visited += 1
                    if visited > budget_dirs or _time.time() > deadline:
                        return None
                    depth = dirpath[len(root):].count(os.sep)
                    if depth > max_depth:
                        dirnames[:] = []
                        continue
                    for fn in filenames:
                        if fn.lower() in wanted:
                            full = os.path.join(dirpath, fn)
                            if (not _denied(full) and os.path.isfile(full)
                                    and not _path_excluded(full, caps or {})):
                                return {"available": True, "command": full, "via": "scan"}
            except Exception:
                continue
    return None


def _path_excluded(path, caps):
    """按能力表的 exclude_paths 过滤「同名但不同物」的可执行文件。

    例：httpx 有两家 —— Python 的 httpx 库 CLI 与 ProjectDiscovery 的 httpx。
    PATH 上先命中的往往是前者，语义完全不同，必须按路径片段排除。
    """
    if not path:
        return False
    # 各层返回值既可能是路径字符串，也可能是 {"command": ...} 字典
    if isinstance(path, dict):
        path = path.get("command") or ""
        if not path:
            return False
    low = path.lower()
    for frag in (caps.get("exclude_paths") or []):
        if frag and frag.lower() in low:
            return True
    hints = caps.get("path_hints") or []
    if hints and not any(h.lower() in low for h in hints):
        return True
    if caps.get('identityProbe'):
        from lib import tool_identity
        results = caps.setdefault('_identity_results', {})
        key = os.path.normcase(os.path.abspath(path))
        if key not in results:
            results[key] = tool_identity.probe(caps['identityProbe'], path)
        if results[key].get('ok') is not True:
            return True
    return False



# ---------------------------------------------------------------------------
# 第 4.5 层：开始菜单 / 桌面快捷方式（零依赖，覆盖"正常安装"的软件）
# 第 4.6 层：Everything 索引（可选加速，全盘毫秒级，替代被禁掉的盲目扫盘）
# ---------------------------------------------------------------------------
_LNK_CACHE = {}
_ES_CACHE = {}


def _lnk_targets():
    """一次性解析开始菜单/桌面全部 .lnk 的 TargetPath（进程内缓存）。

    为什么放在注册表之后、递归扫描之前：正常安装的软件 90% 会建快捷方式，
    取到的是**真实 exe 路径**（比按名字猜目录准），且一次 PowerShell 批量解析
    比逐个 .lnk 起进程快一个量级。
    """
    if "v" in _LNK_CACHE:
        return _LNK_CACHE["v"]
    out = []
    if sys.platform == "win32":
        ps = shutil.which("powershell") or shutil.which("pwsh")
        roots = [
            os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs"),
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs"),
            os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
            os.path.join(os.environ.get("PUBLIC", ""), "Desktop"),
        ]
        roots = [r for r in roots if r and os.path.isdir(r)]
        if ps and roots:
            quoted = ",".join("'" + r.replace("'", "''") + "'" for r in roots)
            cmd = (
                "$s=New-Object -ComObject WScript.Shell;"
                "Get-ChildItem -Path @(" + quoted + ") -Recurse -Filter *.lnk -ErrorAction SilentlyContinue"
                " | ForEach-Object { try { $t=$s.CreateShortcut($_.FullName).TargetPath;"
                " if($t){ $t } } catch {} }"
            )
            try:
                r = process_tree.run([ps, "-NoProfile", "-NonInteractive", "-Command", cmd],
                                     capture_output=True, text=True, timeout=25)
                out = [l.strip() for l in (r.stdout or "").splitlines()
                       if l.strip().lower().endswith(".exe")]
            except Exception:
                out = []
    _LNK_CACHE["v"] = out
    return out


def _layer_startmenu(exe_names, caps):
    """第 4.5 层：从快捷方式目标里按 exe 名匹配。"""
    if sys.platform != "win32":
        return None
    want = {name.lower() for e in exe_names for name in (e, e + '.exe')}
    for t in _lnk_targets():
        if (os.path.basename(t).lower() in want and os.path.isfile(t)
                and not _denied(t) and not _path_excluded(t, caps)):
            return {"available": True, "command": t, "via": "startmenu"}
    return None


def _find_es():
    """找 Everything 的命令行版 es.exe（PATH 或 Everything 安装目录）。"""
    if "v" in _ES_CACHE:
        return _ES_CACHE["v"]
    es = shutil.which("es.exe") or shutil.which("es")
    if not es:
        roots = list(_COMMON_ROOTS) + [os.environ.get("ProgramFiles", ""),
                                       os.environ.get("ProgramFiles(x86)", ""),
                                       os.environ.get("LOCALAPPDATA", "")]
        for root in roots:
            if not root or not os.path.isdir(root):
                continue
            for sub in (("Everything",), ("Everything", "es.exe"), ("Everything", "cli")):
                cand = os.path.join(root, *sub, "es.exe") if sub[-1] != "es.exe" else os.path.join(root, *sub)
                if os.path.isfile(cand):
                    es = cand
                    break
            if es:
                break
    _ES_CACHE["v"] = es or ""
    return _ES_CACHE["v"]


def _layer_everything(exe_names, caps):
    """第 4.6 层：Everything 索引查询（毫秒级、全盘覆盖）。

    价值：把"递归扫盘"（被 AGENTS 明令禁止：会卡死会话）换成索引查询 ——
    同样覆盖全盘，但快 1000 倍，且不会把 node_modules 当候选。
    es.exe 缺失时安静跳过（并可在 discover 结果里提示可安装）。
    """
    es = _find_es()
    if not es:
        return None
    for e in exe_names:
        try:
            r = process_tree.run([es, "-n", "40", e], capture_output=True, text=True, timeout=10)
        except Exception:
            return None
        for line in (r.stdout or "").splitlines():
            p = line.strip()
            if not p or not p.lower().endswith(e.lower()):
                continue
            cands = [p]
            # Everything 可能返回不含扩展名的路径
            if not os.path.splitext(p)[1]:
                cands.insert(0, p + ".exe")
            for c in cands:
                if os.path.isfile(c) and not _denied(c) and not _path_excluded({"command": c}, caps):
                    return {"available": True, "command": c, "via": "everything"}
    return None


def _discover_python_library(raw, tid, entry):
    """Import in the same interpreter used by MCP and pip; never cache a library as an exe."""
    module = entry.get("module", "")
    out = {"tool_id": tid, "input": raw, "kind": "python_lib", "module": module,
           "interpreter": sys.executable, "available": False, "command": "",
           "via": "python-import", "known_in_table": True, "arch": None,
           "exe_candidates": [], "layers_tried": ["python-import"]}
    if not module or not all(part.isidentifier() for part in module.split(".")):
        out["note"] = "Python 库缺少有效的 module 声明"
        return out
    code = (
        "import importlib,json,sys; "
        "m=importlib.import_module(sys.argv[1]); "
        "print(json.dumps({'module_file':getattr(m,'__file__',''),"
        "'version':str(getattr(m,'__version__',''))}))"
    )
    try:
        p = process_tree.run([sys.executable, "-c", code, module], cwd=_HERE,
                             capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=30)
        if p.returncode == 0:
            metadata = json.loads(p.stdout.strip().splitlines()[-1])
            out.update(available=True, command=sys.executable,
                       module_file=metadata.get("module_file", ""),
                       version=metadata.get("version", ""))
        else:
            out["note"] = "当前解释器无法导入 " + module
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        out["note"] = "Python 库导入检查未完成：" + module
    return out


def discover(tool_id, target=None, use_registry=True, use_cache=True, exe_candidates=None):
    """六层递进发现：命中即停。返回结构化结果。

    Args:
        tool_id: 工具标识（可带别名，会自动规范化）。
        target: 可选目标文件；若为 PE 且工具 arch_aware，则按 machine 字段选 32/64 位。
        use_registry: 是否启用第 4 层注册表探测（Windows 有效）。
    """
    raw = (tool_id or "").strip()
    tid = normalize_tool_id(raw)
    install_table = _install_table()
    config_error = (install_table.get("_config_error")
                    if isinstance(install_table, dict) else "安装清单根对象必须是对象")
    if not config_error:
        try:
            entry, _, _ = _install_methods(install_table, tid)
        except (OSError, ValueError, TypeError) as exc:
            config_error = "安装配置无效: " + str(exc)
            entry = {}
    else:
        entry = {}
    if config_error:
        return {
            "tool_id": tid, "input": raw, "available": False, "command": "",
            "via": "none", "known_in_table": False, "arch": None,
            "exe_candidates": _exe_candidates(tid), "layers_tried": [],
            "config_error": config_error,
            "note": "安装清单无效；已停止发现与安装，避免按坏配置执行。",
        }
    journal = Path(_install_base()) / _PORTABLE_JOURNAL
    if journal.exists() or journal.is_symlink():
        return {'tool_id': tid, 'input': raw, 'available': False, 'command': '',
                'via': 'none', 'recovery_required': True,
                'note': '便携安装存在未完成事务；重新执行安装入口以恢复'}
    if entry.get("kind") == "python_lib":
        return _discover_python_library(raw, tid, entry)
    caps = dict(_capabilities_table().get("tools", {}).get(tid, {}))
    caps.pop('_identity_results', None)

    arch = read_pe_machine(target) if (target and os.path.isfile(target)) else None
    exe_names = _exe_candidates(tid, arch)
    if exe_candidates is not None:
        if (not isinstance(exe_candidates, list) or not exe_candidates
                or any(not isinstance(n, str) or not n or '/' in n or '\\' in n for n in exe_candidates)):
            raise ValueError('exe_candidates 必须是非空文件名数组')
        exe_names = exe_candidates

    layers = []
    # 显式路径始终优先；架构敏感工具不能沿用其他位宽的缓存。
    hit = _layer_env(tid, exe_names, caps=caps); layers.append(("env", hit))
    restricted = exe_candidates is not None or (caps.get('arch_aware') and arch)
    names = {name.lower() for e in exe_names for name in (e, e + '.exe')}
    if hit and restricted and os.path.basename(hit['command']).lower() not in names:
        directory = os.path.dirname(hit['command'])
        sibling = next((os.path.join(directory, name) for name in exe_names
                        if os.path.isfile(os.path.join(directory, name))), None)
        hit = dict(hit, command=sibling) if sibling and not _path_excluded(sibling, caps) and not _denied(sibling) else None
    if hit:
        return _discover_result(raw, tid, caps, arch, exe_names, hit, layers)
    hit = _cache_get(tid, exe_names) if use_cache else None
    if hit and restricted:
        if os.path.basename(hit['command']).lower() not in names:
            hit = None
    if hit and not _path_excluded(hit, caps):
        layers.append(("cache", hit))
        return _discover_result(raw, tid, caps, arch, exe_names, hit, layers)
    hit = _layer_path(exe_names, caps=caps); layers.append(("PATH", hit))
    if hit:
        return _discover_result(raw, tid, caps, arch, exe_names, hit, layers)
    hit = _layer_common_dirs(exe_names, caps=caps); layers.append(("common_dir", hit))
    if hit:
        return _discover_result(raw, tid, caps, arch, exe_names, hit, layers)
    if use_registry:
        hit = _layer_registry(tid, exe_names, caps); layers.append(("registry", hit)); hit = None if _path_excluded(hit, caps) else hit
        if hit:
            return _discover_result(raw, tid, caps, arch, exe_names, hit, layers)
    hit = _layer_startmenu(exe_names, caps); layers.append(("startmenu", hit)); hit = None if _path_excluded(hit, caps) else hit
    if hit:
        return _discover_result(raw, tid, caps, arch, exe_names, hit, layers)
    hit = _layer_everything(exe_names, caps); layers.append(("everything", hit)); hit = None if _path_excluded(hit, caps) else hit
    if hit:
        return _discover_result(raw, tid, caps, arch, exe_names, hit, layers)
    hit = _layer_scan(tid, exe_names, caps=caps); layers.append(("scan", hit))
    if hit:
        return _discover_result(raw, tid, caps, arch, exe_names, hit, layers)

    return {
        "tool_id": tid, "input": raw, "available": False, "command": "", "via": "none",
        "known_in_table": bool(caps), "arch": arch, "exe_candidates": exe_names,
        "layers_tried": [l[0] for l in layers],
        "note": "八层探测均未命中。若确信已安装，可设环境变量 SEEP_<TOOL>_PATH 显式指定，"
                "或把工具放进任一候选根（~/.seep/tools、~/Tools、各盘 Tools 目录），或用 SEEP_TOOL_ROOT / REVERSE_TOOL_ROOT 显式指定。",
    }


def _discover_result(raw, tid, caps, arch, exe_names, hit, layers):
    # Windows distributions often ship both an extensionless Unix launcher and
    # a native sibling. Normalize even an old cache hit before returning it to
    # every consumer; selecting a script for bash requires bash to exist.
    command = hit["command"]
    if os.name == "nt" and not os.path.splitext(command)[1]:
        for suffix in (".exe", ".bat", ".cmd"):
            native = command + suffix
            if os.path.isfile(native) and not _denied(native) and not _path_excluded(native, caps):
                hit = dict(hit, command=native)
                break
    if hit.get("via") != "cache" or hit["command"] != command:
        _cache_put(tid, hit.get("command", ""), hit.get("via", "?"), arch)
    out = {
        "tool_id": tid, "input": raw, "available": True,
        "command": hit["command"], "via": hit["via"],
        "known_in_table": bool(caps), "arch": arch, "exe_candidates": exe_names,
        "layers_tried": [l[0] for l in layers if l[1] is None] + [hit["via"]],
    }
    if caps.get('identityProbe'):
        out['identity_verified'] = True
        out['identity_probe'] = caps['identityProbe']
    if hit.get("install_dir"):
        out["install_dir"] = hit["install_dir"]
    if hit.get("env_key"):
        out["env_key"] = hit["env_key"]
    return out


# ---------------------------------------------------------------------------
# 「怎么控制它」——声明式能力（联网检索得到的静态表；绝不用 -h 试探）
# ---------------------------------------------------------------------------
def research_control(tool_id):
    """返回某工具『怎么控制』的声明式结论。

    ★ 关键：优先读 tool-capabilities.json（其内容来自联网检索 GitHub/官方文档）。
    表外未知工具：返回 control=unknown，只报路径，绝不假装能控，也不去 -h 试探二进制。
    """
    tid = normalize_tool_id(tool_id)
    caps = _capabilities_table().get("tools", {}).get(tid)
    if not caps:
        return {
            "tool_id": tid, "known": False, "control": "unknown",
            "advice": "表外未知工具：仅报『路径已发现』，不假装能控制它。"
                      "如需纳入，请联网检索其 GitHub/官方文档后，把能力补进 "
                      "Tool/config/tool-capabilities.json（不要用 -h 试探二进制）。",
            "research_queries": [
                f"{tid} MCP server github",
                f"{tid} command line headless usage official docs",
                f"{tid} automation cli vs gui",
            ],
        }
    return {
        "tool_id": tid, "known": True,
        "display": caps.get("display", tid),
        "capabilities": caps.get("capabilities", {}),
        "control": caps.get("control", {}),
        "install_hint": caps.get("install_hint", ""),
        "notes": caps.get("notes", ""),
        "source": "tool-capabilities.json (verified via web 2026-10-19)",
    }


# ---------------------------------------------------------------------------
# MCP 注册（写当前 agent 的 mcp.json，增量合并，提示重启）
# ---------------------------------------------------------------------------
def _agent_mcp_json_path():
    """Return the selected agent's MCP config, using the shared root resolver."""
    explicit_file = (os.environ.get("SEEP_AGENT_MCP") or "").strip()
    if explicit_file:
        return explicit_file
    return str(resolve_agent_root() / "mcp.json")


def _mcp_entry_for(tool_id):
    """从能力表/生态模板构造 MCP 注册片段；无则 None。"""
    tid = normalize_tool_id(tool_id)
    eco = _capabilities_table().get("mcp_ecosystem", {})
    fields = ("command", "args", "env", "cwd", "url", "headers", "transport", "enabled", "timeout")
    if tid in eco and isinstance(eco[tid], dict):
        return {key: value for key, value in eco[tid].items() if key in fields}
    caps = _capabilities_table().get("tools", {}).get(tid, {})
    reg = caps.get("control", {}).get("mcp_register")
    if isinstance(reg, dict) and (reg.get("command") or reg.get("url")):
        return {key: value for key, value in reg.items() if key in fields}
    return None


# 看起来像“本地脚本/可执行文件”的后缀（用于预检参数与命令）
_LOCAL_FILE_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".exe", ".cmd", ".bat", ".ps1", ".sh")


def _looks_like_path(value):
    """是否像本地路径（而非包名/子命令）：含分隔符、不以 `-` 开头。"""
    s = str(value or "").strip()
    return bool(s) and not s.startswith("-") and ("/" in s or "\\" in s)


def _mcp_entry_preflight(entry):
    """落盘前预检 MCP 条目：只拦“明确坏掉”，不拦“运行时尚未安装”。

    背景（两类完全不同的故障，不能混）：
      · **扩展级**：某个 pi 扩展顶掉内置（如 `/mcp`）—— 由
        `Tool/scripts/check-extension-conflicts.py` 负责；本函数**不**管，
        因为注册 MCP **服务器**只是改 `mcp.json`，永远不碰 `settings.json`
        的 `packages`，结构上就不可能顶替任何内置。
      · **条目级**：写进一条指向不存在的可执行文件/脚本的配置 → 每个会话
        都报连接失败。这是本函数防的。

    返回 ``{"ok": bool, "errors": [...], "warnings": [...]}``：
      · ``command`` 缺失、或看起来是路径但不存在 → error（拒绝落盘）；
      · ``command`` 是裸命令但不在 PATH（如尚未装 uvx/npx）→ warning
        （照写，装好运行时重启即可，不阻断“先注册后装工具”的工作流）；
      · 参数里指向本地脚本的文件不存在 → error。
    """
    errors, warnings = [], []
    if not isinstance(entry, dict):
        return {"ok": False, "errors": ["MCP 条目必须是对象"], "warnings": []}
    for field in ("env", "headers"):
        value = entry.get(field, {})
        if not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                               for k, v in value.items()):
            errors.append(field + " 必须是字符串键值对象")
    cwd = entry.get("cwd", os.curdir)
    if not isinstance(cwd, str) or not os.path.isdir(cwd):
        errors.append("cwd 必须指向现有目录")
        cwd = os.curdir
    args = entry.get("args", [])
    if not isinstance(args, list) or any(not isinstance(a, str) for a in args):
        errors.append("args 必须是字符串数组")
        args = []
    cmd = entry.get("command", "")
    if entry.get("url"):
        try:
            parsed = urlparse(entry["url"])
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise ValueError("invalid URL")
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError("invalid port")
        except (AttributeError, TypeError, ValueError):
            errors.append("url 必须是有效 HTTP(S) 地址")
    elif not isinstance(cmd, str) or not cmd.strip():
        errors.append("缺少 command")
    elif _looks_like_path(cmd) or os.path.isabs(cmd) or os.path.exists(os.path.join(cwd, cmd)):
        if not os.path.isfile(os.path.join(cwd, cmd)):
            errors.append("command 必须指向现有文件: %s" % cmd)
    elif not shutil.which(cmd):
        warnings.append("运行时不在此机 PATH: %s（装好后重启会话即可）" % cmd)
    for a in args:
        if (_looks_like_path(a) and a.lower().endswith(_LOCAL_FILE_SUFFIXES)
                and not os.path.isfile(os.path.join(cwd, a))):
            errors.append("参数指向的文件不存在: %s" % a)
    return {"ok": not errors, "errors": errors, "warnings": warnings}


def _root_mcp_sync_enabled():
    """是否把 MCP 条目同时同步到【仓库根 .mcp.json】。
    ★ 血案：旧实现无条件追加根目录 .mcp.json（这是 git **受跟踪**文件），
    即使设置了 SEEP_AGENT_MCP 做测试隔离也照样写 —— 跑一次自测就会把测试工具
    （如 ghidra）写进受跟踪文件，并在仓库根堆出几十个 .mcp.json.bak-<时间戳> 垃圾。

    现在的规则：
      · 设了 SEEP_AGENT_MCP、PI_CODING_AGENT_DIR 或 PI_AGENT_DIR
        （测试 / 多实例隔离）→ 只写选定 AgentRoot，绝不碰仓库根；
      · 环境变量 SEEP_SYNC_ROOT_MCP=0/false/off → 关闭根同步；
      · 其余情况（默认）→ 保持老行为，同步根 .mcp.json（多宿主共用项目级配置）。
    """
    if any((os.environ.get(key) or "").strip() for key in
           ("SEEP_AGENT_MCP", "PI_CODING_AGENT_DIR", "PI_AGENT_DIR")):
        return False
    v = os.environ.get("SEEP_SYNC_ROOT_MCP", "1").strip().lower()
    return v not in ("0", "false", "no", "off", "none")


def _prune_backups(path, keep=3):
    """备份文件轮转：同一目标只保留最近 keep 个 <name>.bak-<时间戳>，避免无限堆积。"""
    try:
        d = os.path.dirname(os.path.abspath(path)) or "."
        base = os.path.basename(path) + ".bak-"
        cands = [os.path.join(d, f) for f in os.listdir(d) if f.startswith(base)]
        cands.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        for old in cands[keep:]:
            try:
                os.remove(old)
            except Exception:
                pass
    except Exception:
        pass


def register_mcp(tool_id, apply=False, server_name=None):
    """注册工具对应的 MCP 到当前 agent 的 mcp.json（增量合并、绝不删用户条目）。
    支持多 Agent 宿主协同：同时同步 ~/.pi/agent/mcp.json 与项目根 .mcp.json。

    ★ 边界（防复发）：本函数**只写 `mcp.json` 的 `mcpServers` 字段**，
    永远不碰 `settings.json` 的 `packages`、也不安装任何 pi 扩展包。
    因此“注册 MCP 服务器”与“装第三方 MCP 扩展顶掉内置 /mcp”是两件事：
    前者不会触发 pi 的 replaceable 机制（启动不出 [Extension issues]）；
    后者由 `Tool/scripts/check-extension-conflicts.py` 在安装期拦截。

    apply=False 时只返回"将要写入的片段 + 目标路径 + 预检结果"，不落盘。
    写入成功后返回 restart_required=True —— 协议层死规矩：MCP 配置需重启会话才生效。
    """
    tid = normalize_tool_id(tool_id)
    name = server_name or tid
    entry = _mcp_entry_for(tid)
    primary_path = _agent_mcp_json_path()
    
    # 收集需要同步的目标文件列表（主路径 + 可选的项目根 .mcp.json）
    targets = [primary_path]
    root_mcp = os.path.join(os.path.dirname(_TOOL_DIR), ".mcp.json")
    if (_root_mcp_sync_enabled()
            and os.path.isfile(root_mcp)
            and os.path.normpath(root_mcp) != os.path.normpath(primary_path)):
        targets.append(root_mcp)

    if not isinstance(entry, dict) or not entry:
        return {"tool_id": tid, "registered": False,
                "reason": "能力表中没有该工具的 MCP 注册方式（表外未知工具不假装能注册）",
                "target": primary_path}

    # 落盘前预检（只拦“明确坏掉”的条目；运行时未装仅告警）
    pre = _mcp_entry_preflight(entry)

    if not apply:
        return {"tool_id": tid, "registered": False, "preview": True,
                "server_name": name, "entry": entry, "targets": targets,
                "preflight": pre,
                "note": "这是将要增量写入的片段；确认后以 apply=True 落盘（需重启会话生效）。"}
    if pre["errors"]:
        return {"tool_id": tid, "registered": False,
                "reason": "条目预检未通过，未写入任何文件：" + "；".join(pre["errors"]),
                "preflight": pre, "target": primary_path,
                "hint": "按 seep_tool_control_plan 的安装路线把运行时/脚本装好，或修正能力表后再注册。"}

    # Validate every target before touching any of them. A malformed/BOM document
    # must never be silently replaced with empty defaults, nor a namesake service
    # overwritten merely because a template uses the same name.
    prepared = []
    try:
        for p in targets:
            original = None
            if os.path.exists(p):
                with open(p, "rb") as handle:
                    original = handle.read()
                cfg = json.loads(original.decode("utf-8-sig"))
            else:
                cfg = {"mcpServers": {}}
            if not isinstance(cfg, dict):
                raise ValueError("MCP 配置必须是对象")
            servers = cfg.setdefault("mcpServers", {})
            if not isinstance(servers, dict) or any(not isinstance(v, dict) for v in servers.values()):
                raise ValueError("mcpServers 及每个服务条目必须是对象")
            if name in servers and servers[name] != entry:
                raise ValueError("已有同名服务 %s，保留原配置；请使用不同 server_name 或明确调整原条目" % name)
            unchanged = servers.get(name) == entry
            servers[name] = entry
            prepared.append((p, original, cfg, unchanged))
    except (OSError, ValueError, TypeError) as exc:
        return {"tool_id": tid, "registered": False, "error": str(exc),
                "targets": targets, "written_targets": []}

    written_targets, unchanged_targets, errors = [], [], {}
    for p, original, cfg, unchanged in prepared:
        if unchanged:
            unchanged_targets.append(p)
            continue
        pending = None
        try:
            directory = os.path.dirname(os.path.abspath(p))
            os.makedirs(directory, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory,
                                             prefix=".seep-mcp-", delete=False) as handle:
                pending = handle.name
                json.dump(cfg, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
            current = None
            if os.path.exists(p):
                with open(p, "rb") as handle:
                    current = handle.read()
            if current != original:
                raise ValueError("配置在检查后发生变化，未覆盖")
            if original is not None:
                shutil.copy2(p, p + ".bak-" + datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"))
                _prune_backups(p)
            os.replace(pending, p)
            written_targets.append(p)
            with open(p, encoding="utf-8-sig") as handle:
                if json.load(handle) != cfg:
                    raise ValueError("写后回读与预期配置不一致")
        except (OSError, ValueError, TypeError) as exc:
            errors[p] = str(exc)
            break
        finally:
            if pending and os.path.isfile(pending):
                try:
                    os.unlink(pending)
                except OSError as exc:
                    errors[p] = (errors.get(p, "") + "; 临时文件清理失败: " + str(exc)).lstrip("; ")
    complete = not errors
    return {"tool_id": tid, "registered": complete, "server_name": name, "entry": entry,
            "targets": targets, "written_targets": written_targets, "unchanged_targets": unchanged_targets,
            "overwrote_existing": False, "verified": complete, "connection_verified": False,
            "unverified_targets": list(errors), "errors": errors,
            "partial": bool(errors and written_targets), "preflight": pre,
            "restart_required": bool(written_targets),
            "note": ("配置已核验；新写入的服务需在宿主重新加载 MCP 或重启会话后使用。" if complete
                     else "未完成全部目标；查看 errors 和 written_targets，已写目标有备份。")}


# ---------------------------------------------------------------------------
# 半自动安装（探测 -> 给命令+来源 -> 确认 -> 装 -> 重探）
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 多途径自适应安装与便携下载引擎
# ---------------------------------------------------------------------------
def _run_tool_process(argv, **kwargs):
    """Run native argv directly; pass batch arguments through one expansion layer."""
    if (not isinstance(argv, list) or not argv
            or any(not isinstance(a, str) or '\x00' in a for a in argv)):
        raise ValueError('argv 必须是非空字符串数组，且不含 NUL')
    executable = shutil.which(argv[0]) or argv[0]
    if os.name == 'nt' and executable.lower().endswith(('.bat', '.cmd')):
        if any(any(c in a for c in ('"', '\r', '\n')) for a in [executable] + argv[1:]):
            raise ValueError('批处理参数含双引号或换行；请使用原生可执行文件或脚本文件参数')
        environment = dict(kwargs.pop('env', None) or os.environ)
        values = [executable] + argv[1:]
        for i, value in enumerate(values):
            environment['SEEP_BATCH_ARG_%d' % i] = value
        command = '"' + ' '.join('"%SEEP_BATCH_ARG_{}%"'.format(i) for i in range(len(values))) + '"'
        # Pass cmd's quoted /c expression verbatim: list2cmdline would add C
        # backslash escapes, which cmd does not interpret as quoting.
        argv = subprocess.list2cmdline([os.environ.get('ComSpec') or 'cmd.exe',
                                       '/d', '/v:off', '/s', '/c']) + ' ' + command
        kwargs['env'] = environment
    return process_tree.run(argv, **kwargs)


def _detect_local_proxy_port():
    """快速探测常见的本地 HTTP/SOCKS 代理端口（如 Clash/V2Ray/Surge）。"""
    import socket
    for p in (7897, 10808, 7890):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.15)
                s.connect(("127.0.0.1", p))
            return p
        except Exception:
            pass
    return None


def _portable_relative(value):
    if not isinstance(value, str) or not value or ':' in value or '\x00' in value:
        raise ValueError("便携路径必须是非空相对路径")
    path = PurePosixPath(value.replace('\\', '/'))
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError("便携路径不得越出安装目录")
    return path


_PORTABLE_JOURNAL = '.seep-portable-transaction.json'


def _portable_sync_dir(path):
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass  # Directory fsync is unavailable on some platforms, including Windows.


def _portable_write_journal(base, data):
    """Publish and flush a complete recovery record before changing its phase."""
    journal = base / _PORTABLE_JOURNAL
    if journal.is_symlink():
        raise ValueError('便携安装恢复记录不能是链接')
    pending = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=base,
                                         prefix='.seep-portable-journal-', delete=False) as stream:
            pending = stream.name
            json.dump(data, stream, ensure_ascii=False, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, journal)
        _portable_sync_dir(base)
    finally:
        if pending and os.path.exists(pending):
            os.unlink(pending)


def _portable_recover_locked(base):
    """Recover the recorded installation while holding the installation-root lock."""
    base = Path(base).resolve()
    journal = base / _PORTABLE_JOURNAL
    if not journal.exists() and not journal.is_symlink():
        return None
    if journal.is_symlink() or not journal.is_file() or journal.stat().st_size > 65536:
        raise ValueError('便携安装恢复记录无效')
    with journal.open(encoding='utf-8') as stream:
        data = json.load(stream)
    if not isinstance(data, dict) or data.get('schema') != 'seep-portable/1':
        raise ValueError('便携安装恢复记录格式无效')
    target_ref = _portable_relative(data.get('target'))
    if (str(target_ref) != data['target'] or any(p.startswith('.seep-') for p in target_ref.parts)
            or data.get('phase') not in ('prepared', 'committed') or type(data.get('had_old')) is not bool):
        raise ValueError('便携安装恢复目标或阶段无效')
    stage_name, backup_name = data.get('stage'), data.get('backup')
    def valid_name(value, prefix):
        return (isinstance(value, str) and value.startswith(prefix)
                and value == Path(value).name and value not in ('.', '..'))
    if not valid_name(stage_name, '.seep-install-') or not valid_name(backup_name, '.seep-previous-'):
        raise ValueError('便携安装恢复目录无效')
    final = base.joinpath(*target_ref.parts)
    stage, backup = base / stage_name, base / backup_name
    for path in (final, stage, backup):
        if not path.resolve().is_relative_to(base):
            raise ValueError('便携安装恢复路径越界')
        for parent in (path, *path.parents):
            if parent == base:
                break
            if parent.is_symlink():
                raise ValueError('便携安装恢复路径包含链接')
        if path.exists() and not path.is_dir():
            raise ValueError('便携安装恢复路径不是目录')
    tid = data.get('tool_id')
    if tid is not None and (not isinstance(tid, str) or not tid or
            data.get('cache_path') != os.path.abspath(_PATH_CACHE_FILE) or
            data.get('state_path') != os.path.abspath(LOCAL_STATE_PATH)):
        raise ValueError('便携安装恢复状态路径或工具无效')
    exe_ref = _portable_relative(data.get('exe'))
    if str(exe_ref) != data['exe']:
        raise ValueError('便携安装恢复程序路径无效')

    if data['phase'] == 'prepared':
        if not data['had_old'] and backup.exists():
            raise ValueError('首次安装出现意外备份，保留现场')
        if data['had_old'] and not backup.exists():
            if not final.exists():
                raise ValueError('旧安装与备份均不存在，无法自动恢复')
        else:
            if final.exists():
                discarded = stage / 'unpacked'
                if not stage.is_dir() or discarded.exists() or discarded.is_symlink():
                    raise ValueError('恢复暂存目录不可用，保留现有安装与备份')
                os.replace(final, discarded)
                _portable_sync_dir(final.parent)
            if data['had_old']:
                os.replace(backup, final)
                _portable_sync_dir(final.parent)
        journal.unlink()
        _portable_sync_dir(base)
        return {'recovered': 'rolled_back', 'target': str(final)}

    executable = final.joinpath(*exe_ref.parts)
    if not executable.is_file() or not executable.resolve().is_relative_to(final.resolve()):
        raise ValueError('已提交的便携安装目标不存在或越界')
    recheck = {'tool_id': tid, 'available': True, 'command': str(executable), 'via': 'portable_zip',
               'identity_verified': data.get('identity_verified') is True, 'identity': data.get('identity')}
    if tid is not None:
        cache_saved = _cache_put(tid, str(executable), 'portable_zip')
        state_saved = record(tid, recheck).get('state_saved')
        if not cache_saved or not state_saved:
            raise RuntimeError('已提交安装的缓存或状态保存失败，恢复记录已保留')
    journal.unlink()
    _portable_sync_dir(base)
    if str(final) not in _COMMON_ROOTS:
        _COMMON_ROOTS.insert(0, str(final))
    return {'recovered': 'committed', 'target': str(final), 'recheck': recheck}


@contextlib.contextmanager
def _portable_stage(base):
    stage = Path(tempfile.mkdtemp(prefix='.seep-install-', dir=base))
    try:
        yield stage
    finally:
        journal = base / _PORTABLE_JOURNAL
        if not journal.exists() and not journal.is_symlink():
            try:
                shutil.rmtree(stage)
            except OSError:
                pass


def _download_and_extract_portable(urls, target_sub, verify_exe="", expected_sha256="", tool_id=None):
    """Serialize installations sharing a root, including promotion and rollback."""
    try:
        _portable_relative(target_sub)
        _portable_relative(verify_exe)
        with project_lock(Path(_install_base()), timeout=20):
            try:
                _portable_recover_locked(_install_base())
            except (OSError, ValueError, TypeError, RuntimeError) as exc:
                return {'success': False, 'recovery_required': True, 'error': '便携安装恢复失败: ' + str(exc)}
            return _download_and_extract_portable_locked(urls, target_sub, verify_exe, expected_sha256, tool_id)
    except (OSError, TypeError, ValueError) as exc:
        return {"success": False, "error": str(exc)}


def _download_and_extract_portable_locked(urls, target_sub, verify_exe="", expected_sha256="", tool_id=None):
    """Stage and validate a ZIP before replacing a tool; retain the old installation as a backup."""
    import urllib.request
    import zipfile

    try:
        relative, expected = _portable_relative(target_sub), _portable_relative(verify_exe)
        if not isinstance(urls, list) or not urls or any(not isinstance(u, str) for u in urls):
            raise ValueError("urls 必须是非空地址数组")
        if expected_sha256 and (not isinstance(expected_sha256, str) or len(expected_sha256) != 64
                                or any(c not in '0123456789abcdefABCDEF' for c in expected_sha256)):
            raise ValueError("sha256 必须是 64 位十六进制摘要")
        base = Path(_install_base()).resolve()
        final = base.joinpath(*relative.parts)
        if (any(p.startswith('.seep-') for p in relative.parts) or final.is_symlink()
                or not final.resolve().is_relative_to(base) or final.resolve() == base):
            raise ValueError("安装目标越界或为链接")
        if final.exists() and not final.is_dir():
            raise ValueError("安装目标已存在且不是目录")
    except (OSError, TypeError, ValueError) as exc:
        return {"success": False, "error": str(exc)}

    proxy_port = _detect_local_proxy_port()
    handlers = []
    if proxy_port:
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    opener = urllib.request.build_opener(*handlers)
    failures = []
    for url in urls:
        backup = None
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ('http', 'https') or not parsed.hostname:
                raise ValueError("下载地址必须是 HTTP(S)")
            base.mkdir(parents=True, exist_ok=True)
            with _portable_stage(base) as stage:
                zipped, unpacked = stage / 'download.zip', stage / 'unpacked'
                req = urllib.request.Request(url, headers={"User-Agent": "SeepAutoDiscover"})
                digest, size, deadline = hashlib.sha256(), 0, time.monotonic() + 120
                with opener.open(req, timeout=40) as response, zipped.open('wb') as stream:
                    while True:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("便携下载超时")
                        block = response.read(1 << 20)
                        if not block:
                            break
                        size += len(block)
                        if size > 1024 * 1024 * 1024:
                            raise ValueError("便携下载超过 1GiB 上限")
                        digest.update(block)
                        stream.write(block)
                actual_sha256 = digest.hexdigest()
                if expected_sha256 and actual_sha256 != expected_sha256.lower():
                    raise ValueError("下载内容与声明 sha256 不一致")
                with zipfile.ZipFile(zipped) as archive:
                    members = archive.infolist()
                    if len(members) > 100000 or sum(m.file_size for m in members) > 2 * 1024**3:
                        raise ValueError("ZIP 成员数量或解压体积超过上限")
                    seen = set()
                    for member in members:
                        ref = _portable_relative(member.filename)
                        key = str(ref).casefold() if os.name == 'nt' else str(ref)
                        kind = stat.S_IFMT(member.external_attr >> 16)
                        if key in seen or kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                            raise ValueError("ZIP 存在重名或特殊文件")
                        seen.add(key)
                    for member in members:
                        archive.extract(member, unpacked)
                executable = unpacked.joinpath(*expected.parts)
                if not executable.is_file():
                    matches = [p for p in unpacked.rglob('*') if p.is_file()
                               and p.name.lower() == expected.name.lower()]
                    if len(matches) != 1:
                        raise ValueError("ZIP 未包含唯一的预期程序: " + str(expected))
                    executable = matches[0]
                exe_relative = executable.relative_to(unpacked)
                final.parent.mkdir(parents=True, exist_ok=True)
                had_old = final.exists()
                backup = base / ('.seep-previous-' + uuid.uuid4().hex)
                journal_data = {'schema': 'seep-portable/1', 'phase': 'prepared',
                                'target': str(relative), 'stage': stage.name, 'backup': backup.name,
                                'had_old': had_old, 'exe': exe_relative.as_posix(), 'tool_id': tool_id,
                                'cache_path': os.path.abspath(_PATH_CACHE_FILE),
                                'state_path': os.path.abspath(LOCAL_STATE_PATH)}
                try:
                    _portable_write_journal(base, journal_data)
                    if had_old:
                        os.replace(final, backup)
                        _portable_sync_dir(final.parent)
                    os.replace(unpacked, final)
                    _portable_sync_dir(final.parent)
                    installed_exe = str(final / exe_relative)
                    identity = None
                    if tool_id is not None:
                        from lib import tool_identity
                        caps = _capabilities_table().get('tools', {}).get(tool_id, {})
                        probe_id = caps.get('identityProbe') or tool_id
                        identity = tool_identity.probe(probe_id, installed_exe)
                        if identity.get('ok') is False or (caps.get('identityProbe') and identity.get('ok') is not True):
                            raise RuntimeError('新安装程序身份复验失败: ' + str(identity.get('why', 'unknown')))
                    journal_data.update(phase='committed', identity=identity,
                                        identity_verified=bool(identity and identity.get('ok') is True))
                    # The durable phase change is the commit point. Afterwards,
                    # recovery finishes publishing state rather than reverting files.
                    _portable_write_journal(base, journal_data)
                    recovered = _portable_recover_locked(base)
                except Exception as exc:
                    try:
                        recovered = _portable_recover_locked(base)
                    except (OSError, ValueError, TypeError, RuntimeError) as recovery_error:
                        return {'success': False, 'error': str(exc), 'recovery_required': True,
                                'recovery_error': str(recovery_error), 'dir': str(final),
                                'backup_dir': str(backup) if backup.exists() else '',
                                'journal': str(base / _PORTABLE_JOURNAL)}
                    if recovered and recovered.get('recovered') == 'committed':
                        return {'success': True, 'dir': str(final), 'exe': installed_exe,
                                'source': url, 'sha256': actual_sha256,
                                'checksum_verified': bool(expected_sha256),
                                'backup_dir': str(backup) if backup.exists() else '',
                                'cache_saved': True, 'state_saved': True, 'recheck': recovered['recheck']}
                    backup = None
                    raise RuntimeError(str(exc)) from exc
                out = {"success": True, "dir": str(final), "exe": installed_exe,
                        "source": url, "sha256": actual_sha256,
                        "checksum_verified": bool(expected_sha256), "backup_dir": str(backup) if backup.exists() else ""}
                if tool_id is not None:
                    out.update(cache_saved=True, state_saved=True, recheck=recovered['recheck'])
                return out
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
            failures.append(str(exc))
            if backup is not None:
                return {"success": False, "error": str(exc), "backup_dir": str(backup),
                        "recovery_required": True}
    return {"success": False, "error": "所有便携下载途径失败: " + "; ".join(failures)}


def _install_methods(cfg, tid):
    """Validate before selecting or executing any method, including fallbacks."""
    if not isinstance(cfg, dict) or not isinstance(cfg.get('installable'), dict):
        raise ValueError('安装清单及 installable 必须是对象')
    allowed = cfg.get('auto_allow_methods', [])
    if not isinstance(allowed, list) or any(not isinstance(m, str) for m in allowed):
        raise ValueError('auto_allow_methods 必须是字符串数组')
    entry = cfg['installable'].get(tid)
    if entry is None:
        return {}, [], allowed
    if not isinstance(entry, dict) or not entry:
        raise ValueError('工具安装声明必须是非空对象')
    methods = entry.get('methods', [{**entry, 'type': entry.get('method')}])
    if not isinstance(methods, list) or not methods:
        raise ValueError('安装方法必须是非空对象数组')
    supported = ('pip', 'winget', 'portable_zip', 'npm', 'go', 'manual')
    platform = 'windows' if sys.platform == 'win32' else 'macos' if sys.platform == 'darwin' else sys.platform
    eligible = []
    for method in methods:
        if not isinstance(method, dict) or method.get('type') not in supported:
            raise ValueError('安装方法声明未知或格式无效')
        kind = method['type']
        platforms = method.get('platforms', ['windows'] if kind == 'winget' else [])
        if not isinstance(platforms, list) or any(p not in ('windows', 'linux', 'macos') for p in platforms):
            raise ValueError('platforms 必须是支持的平台名称数组')
        if kind in ('pip', 'winget', 'npm', 'go'):
            package = method.get('pkg')
            if not isinstance(package, str) or not package.strip() or package.startswith('-') or '\x00' in package:
                raise ValueError('安装包标识无效')
        elif kind == 'portable_zip':
            urls = method.get('urls')
            if not isinstance(urls, list) or not urls or any(not isinstance(u, str) or not u for u in urls):
                raise ValueError('urls 必须是非空地址数组')
            for url in urls:
                parsed = urlparse(url)
                if parsed.scheme not in ('http', 'https') or not parsed.hostname:
                    raise ValueError('下载地址必须是 HTTP(S)')
            _portable_relative(method.get('target_sub', tid))
            _portable_relative(method.get('verify_exe'))
            checksum = method.get('sha256', '')
            if not isinstance(checksum, str) or (checksum and (len(checksum) != 64 or any(
                    c not in '0123456789abcdefABCDEF' for c in checksum))):
                raise ValueError('sha256 必须是64位十六进制摘要')
        elif not isinstance(method.get('url'), str) or not method['url']:
            raise ValueError('人工安装需提供来源 url')
        elif kind == 'manual':
            parsed = urlparse(method['url'])
            if parsed.scheme not in ('http', 'https') or not parsed.hostname:
                raise ValueError('人工安装来源必须是 HTTP(S) 地址')
        if not platforms or platform in platforms:
            eligible.append(dict(method))
    return entry, eligible, allowed


def install_plan(tool_id):
    """把 tool-install.json 的声明式条目转成可读安装计划（自动根据系统环境匹配最优途径）。
    支持多途径自适应：系统无 winget 时自动无缝降级为 portable_zip（绿色直下免安装）。
    """
    tid = normalize_tool_id(tool_id)
    try:
        table = _install_table()
        if not isinstance(table, dict):
            raise ValueError("安装清单根对象必须是对象")
        if table.get("_config_error"):
            raise ValueError(table["_config_error"])
        entry, methods, allowed = _install_methods(table, tid)
    except (OSError, ValueError, TypeError) as exc:
        reason = '安装配置无效: ' + str(exc)
        return {'tool_id': tid, 'has_plan': False, 'reason': reason,
                'config_error': reason}
    if not entry:
        return {"tool_id": tid, "has_plan": False,
                "reason": "tool-install.json 未收录该工具；请手动安装后加入 PATH。"}
    if not methods:
        return {'tool_id': tid, 'has_plan': False, 'reason': '当前平台没有声明的安装方法'}
    has_winget = bool(shutil.which("winget"))
    methods.sort(key=lambda m: (m['type'] not in allowed or m['type'] == 'manual',
                                m['type'] == 'winget' and not has_winget))
    chosen_method, *fallback_methods = methods

    m_type = chosen_method.get("type", "")
    pkg = chosen_method.get("pkg", "")
    url = chosen_method.get("url", "")
    urls = chosen_method.get("urls", [])
    if m_type not in ("pip", "winget", "portable_zip", "npm", "go", "manual"):
        return {"tool_id": tid, "has_plan": False, "reason": "安装方法声明未知"}

    if m_type == "pip":
        cmd = "%s -m pip install %s" % (sys.executable, pkg)
    elif m_type == "winget":
        cmd = "winget install --id %s -e" % pkg
    elif m_type == "portable_zip":
        cmd = f"[Python绿色直下] 解压至 {_install_base()} (来源: {urls[0] if urls else '官方Release'})"
    elif m_type == "npm":
        cmd = "npm install -g %s" % pkg
    elif m_type == "go":
        cmd = "go install %s" % pkg
    elif m_type == "manual":
        cmd = "手动下载：%s" % url
    else:
        cmd = ""

    auto_ok = m_type in allowed and m_type != "manual"
    return {
        "tool_id": tid,
        "has_plan": True,
        "method": m_type,
        "package": pkg or (urls[0] if urls else url),
        "command": cmd,
        "source": url or (urls[0] if urls else pkg),
        "auto_allowed": auto_ok,
        "active_method": chosen_method,
        "fallback_methods": fallback_methods,
        "has_winget_on_host": has_winget,
        "note": chosen_method.get("note", entry.get("note", "")),
        "hint": "只执行当前平台声明且在白名单内的方法；安装后重新发现，失败原因保留在 attempts。"
    }


def propose_install(tool_id, execute=False):
    """Execute allowed installation methods, then report the actual discovery result."""
    tid = normalize_tool_id(tool_id)
    # An interrupted portable transaction must be handled even when the next
    # selected method is non-portable or the current install catalog changed.
    if execute:
        base = Path(_install_base())
        journal = base / _PORTABLE_JOURNAL
        if journal.exists() or journal.is_symlink():
            try:
                with project_lock(base, timeout=20):
                    _portable_recover_locked(base)
            except (OSError, ValueError, TypeError, RuntimeError) as exc:
                return {'tool_id': tid, 'executed': False, 'success': False,
                        'recovery_required': True, 'error': '便携安装恢复失败: ' + str(exc),
                        'journal': str(journal)}
    plan = install_plan(tid)
    plan.update(executed=False, success=False)
    if not plan.get("has_plan") or not execute:
        return plan
    if not plan.get("auto_allowed"):
        plan["reason"] = "安装方法不在自动白名单"
        return plan
    try:
        _, _, allowed = _install_methods(_install_table(), tid)
    except (OSError, ValueError, TypeError) as exc:
        plan.update(has_plan=False, auto_allowed=False, reason='安装配置无效: ' + str(exc))
        return plan
    candidates = [plan.get("active_method") or {"type": plan["method"], "pkg": plan.get("package")}]
    candidates += plan.get("fallback_methods", [])
    attempts = []
    plan["attempts"] = attempts
    for method_config in candidates:
        method = method_config.get("type")
        if method not in allowed or method not in ("pip", "winget", "portable_zip", "npm", "go"):
            attempts.append({"method": method, "executed": False, "error": "方法不在自动白名单"})
            continue
        attempt = {"method": method, "executed": True, "success": False}
        attempts.append(attempt)
        plan["executed"] = True
        try:
            if method == "portable_zip":
                result = _download_and_extract_portable(method_config.get("urls", []),
                    method_config.get("target_sub", tid), method_config.get("verify_exe", ""),
                    method_config.get("sha256", ""), tool_id=tid)
                attempt["download_result"] = result
                plan["download_result"] = result
                if not result.get("success"):
                    if result.get('recovery_required'):
                        attempt['error'] = result.get('error') or '便携安装恢复失败'
                        plan.update(error=attempt['error'], recovery_required=True)
                        return plan
                    raise RuntimeError(result.get("error") or "便携安装失败")
                plan['recheck'] = result['recheck']
                attempt['success'] = True
                plan['success'] = True
                return plan
            else:
                package = method_config.get("pkg") or plan.get("package")
                if not isinstance(package, str) or not package or package.startswith('-'):
                    raise ValueError("安装包标识无效")
                commands = {
                    "pip": [sys.executable, "-m", "pip", "install", package],
                    "winget": ["winget", "install", "--id", package, "-e", "--accept-source-agreements", "--accept-package-agreements"],
                    "npm": ["npm", "install", "-g", package],
                    "go": ["go", "install", package],
                }
                argv = commands[method]
                process = _run_tool_process(argv, capture_output=True, text=True, encoding="utf-8",
                                         errors="replace", timeout=600)
                if method == "pip" and process.returncode != 0:
                    argv = [sys.executable, "-m", "pip", "install", "-i", "https://pypi.tuna.tsinghua.edu.cn/simple", package]
                    process = _run_tool_process(argv, capture_output=True, text=True, encoding="utf-8",
                                             errors="replace", timeout=600)
                attempt.update(argv=argv, returncode=process.returncode,
                               tail=((process.stdout or "") + "\n" + (process.stderr or ""))[-800:])
                plan.update(returncode=process.returncode, tail=attempt["tail"])
                if process.returncode != 0:
                    raise RuntimeError("安装器退出失败: " + str(process.returncode))
                if method == 'go':
                    # go env also respects settings persisted with `go env -w`,
                    # which need not appear in this process's environment/PATH.
                    location = _run_tool_process(['go', 'env', '-json', 'GOBIN', 'GOPATH'],
                        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=20)
                    if location.returncode == 0:
                        settings = json.loads(location.stdout)
                        directories = ([settings['GOBIN']] if settings.get('GOBIN') else
                            [os.path.join(p, 'bin') for p in settings.get('GOPATH', '').split(os.pathsep) if p])
                        caps = _capabilities_table().get('tools', {}).get(tid, {})
                        found = next((os.path.join(directory, name + suffix)
                            for directory in directories for name in _exe_candidates(tid)
                            for suffix in (('.exe', '') if os.name == 'nt' else ('',))
                            if os.path.isfile(os.path.join(directory, name + suffix))
                            and not _path_excluded(os.path.join(directory, name + suffix), caps)), None)
                        if found:
                            _cache_put(tid, found, 'go-install')
            recheck = discover(tid)
            plan["recheck"] = recheck
            attempt["success"] = bool(recheck.get("available"))
            if attempt["success"]:
                plan["success"] = True
                return plan
            raise RuntimeError("安装步骤完成，但重探未发现可用工具")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            attempt["error"] = type(exc).__name__ + ": " + str(exc)
    plan["error"] = "; ".join(a.get("error", "") for a in attempts if a.get("error")) or "没有可执行安装方法"
    return plan


# ---------------------------------------------------------------------------
# 降级链：已注册MCP -> 现注册MCP(提示重启) -> headless/CLI -> GUI -> 自写Py
# ---------------------------------------------------------------------------
def _mcp_already_registered(tool_id):
    tid = normalize_tool_id(tool_id)
    path = _agent_mcp_json_path()
    cfg = _load_json(path, {"mcpServers": {}})
    return tid in (cfg.get("mcpServers") or {})


def plan_control(tool_id, target=None, apply_mcp=False):
    """给某工具生成完整『发现 -> 控制』计划，走降级链，绝不卡住。

    返回 control_plan，含 discovery / how_to_control / fallbacks / next_action。
    """
    disc = discover(tool_id, target=target)
    cap = research_control(tool_id)
    tid = disc["tool_id"]

    plan = {"tool_id": tid, "target": target, "discovery": disc,
            "capabilities": cap, "how_to_control": None, "fallbacks": []}

    if not disc["available"]:
        # 工具不在本机 -> 给安装计划 + 自写 Py 脚本兜底建议
        plan["how_to_control"] = {"mode": "missing", "detail": "工具未发现"}
        plan["fallbacks"].append({"tier": "install", "plan": install_plan(tid)})
        plan["fallbacks"].append({"tier": "self_write_py",
                                  "detail": "无现成工具时，可由 Agent 现场写最小 Py 脚本兜底（如 pefile 解析 PE、"
                                            "struct 解析 pcap），不阻塞任务。"})
        plan["next_action"] = "工具缺失：确认安装计划，或改用自写 Py 脚本兜底。"
        return plan

    if disc.get("kind") == "python_lib":
        plan["how_to_control"] = {"mode": "python_lib", "module": disc["module"],
                                  "interpreter": disc["interpreter"],
                                  "detail": "在该 Python 解释器中导入模块使用"}
        plan["next_action"] = "使用 Python 库 API。"
        return plan

    caps = cap.get("capabilities", {}) if cap.get("known") else {}
    ctrl = cap.get("control", {}) if cap.get("known") else {}

    # 1) 已注册 MCP
    if _mcp_already_registered(tid):
        plan["how_to_control"] = {"mode": "mcp_registered", "connection_verified": False,
                                  "detail": "已发现 MCP 配置；需核对当前宿主工具表并握手，配置存在不代表服务已连接。"}
        plan["next_action"] = "先运行 MCP 握手/体检并核对宿主工具表；连接后调用，缺失时重新加载 MCP。"
        return plan

    # 2) 可现注册 MCP
    if caps.get("mcp") and _mcp_entry_for(tid):
        reg = register_mcp(tid, apply=apply_mcp)
        plan["how_to_control"] = {"mode": "mcp_register",
                                  "detail": "能力表显示该工具支持 MCP，可注册后使用。",
                                  "registration": reg}
        if reg.get("registered"):
            plan["next_action"] = "MCP 已写入，★ 重启 Agent 会话后生效。"
        else:
            plan["next_action"] = "确认后可 apply_mcp=True 增量写入并重启生效。"
        return plan

    # 3) headless / CLI 直调
    if caps.get("headless") and ctrl.get("headless_cmd"):
        plan["how_to_control"] = {"mode": "headless",
                                  "detail": "支持 headless/CLI，可直接命令行调用（优先于 GUI）。",
                                  "command": ctrl["headless_cmd"],
                                  "resolved_exe": disc["command"]}
        plan["next_action"] = "用 headless/CLI 直调，无需 MCP。"
        return plan

    # 4) GUI（不推荐）
    if caps.get("gui"):
        plan["how_to_control"] = {"mode": "gui_only",
                                  "detail": "仅有 GUI 交互（不推荐自动化），建议改走 headless 或自写脚本。",
                                  "command": ctrl.get("gui_cmd", disc["command"])}
        plan["next_action"] = "GUI 不推荐；如可 headless 优先 headless。"
        return plan

    # 5) 表外/无控制方式：如实报
    plan["how_to_control"] = {"mode": "discovered_only",
                              "detail": "已发现路径，但能力表未声明可控方式（表外未知工具不假装能控）。",
                              "resolved_exe": disc["command"]}
    plan["fallbacks"].append({"tier": "self_write_py",
                              "detail": "可现场写 Py 脚本直接调用该 exe 或解析其产物。"})
    plan["next_action"] = "如需标准化控制，先联网检索其文档再补进能力表。"
    return plan


# ---------------------------------------------------------------------------
# 本机状态（~/.seep/tools.local.json，绝不入库）
# ---------------------------------------------------------------------------
def _read_local_state(strict=False):
    try:
        with open(LOCAL_STATE_PATH, encoding='utf-8-sig') as stream:
            state = json.load(stream)
        if not isinstance(state, dict) or not isinstance(state.get('tools'), dict):
            raise ValueError('本机发现状态及 tools 必须是对象')
        return state
    except FileNotFoundError:
        return {'schemaVersion': '1.0', 'tools': {}, 'updated_at': None}
    except (OSError, ValueError):
        if strict:
            raise
        return {'schemaVersion': '1.0', 'tools': {}, 'updated_at': None,
                'load_error': '无法读取本机发现状态；原文件已保留'}


def load_state():
    return _read_local_state()


def _write_local_state(state):
    if not isinstance(state, dict) or not isinstance(state.get('tools'), dict):
        raise ValueError('本机发现状态及 tools 必须是对象')
    pending = None
    try:
        state = dict(state, updated_at=_now())
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                dir=Path(LOCAL_STATE_PATH).parent, prefix='.seep-state-', delete=False) as stream:
            pending = stream.name
            json.dump(state, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, LOCAL_STATE_PATH)
    finally:
        if pending and os.path.exists(pending):
            os.unlink(pending)


def save_state(state):
    try:
        with project_lock(Path(LOCAL_STATE_PATH).parent):
            _read_local_state(strict=True)  # do not overwrite an unreadable existing state
            _write_local_state(state)
        return True
    except Exception:
        return False


def record(tool_id, result=None):
    """把一次发现结果落本机状态（不写仓库）。"""
    tid = normalize_tool_id(tool_id)
    r = result if result is not None else discover(tid)
    entry = {
        "available": r.get("available"),
        "command": r.get("command", ""),
        "via": r.get("via", ""),
        "arch": r.get("arch"),
        "checked_at": _now(),
    }
    try:
        with project_lock(Path(LOCAL_STATE_PATH).parent):
            state = _read_local_state(strict=True)
            state['tools'][tid] = entry
            _write_local_state(state)
        return dict(entry, state_saved=True)
    except (OSError, ValueError, TimeoutError) as exc:
        return dict(entry, state_saved=False, state_error=type(exc).__name__)


def list_state():
    return load_state()


# ---------------------------------------------------------------------------
# CLI（便于人工/测试直接跑）
# ---------------------------------------------------------------------------
def _cli(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Seep 工具自动发现 + 自动适配 MCP 插件")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("discover", help="六层递进发现某工具")
    d.add_argument("tool"); d.add_argument("--target", default=None)
    d.add_argument("--no-cache", action="store_true")
    d.add_argument("--exe-candidate", action="append")
    c = sub.add_parser("cache-put", help="在共享锁内更新机器级路径缓存")
    c.add_argument("tool"); c.add_argument("command"); c.add_argument("via")
    e = sub.add_parser("execute", help="按 argv 执行工具并返回结构化结果")
    e.add_argument("--request-file", required=True)
    p = sub.add_parser("plan", help="发现 + 控制计划（降级链）")
    p.add_argument("tool"); p.add_argument("--target", default=None)
    p.add_argument("--apply-mcp", action="store_true")
    r = sub.add_parser("register", help="注册该工具 MCP（--apply 落盘）")
    r.add_argument("tool"); r.add_argument("--apply", action="store_true")
    i = sub.add_parser("install", help="半自动安装（--execute 真装）")
    i.add_argument("tool"); i.add_argument("--execute", action="store_true")
    sub.add_parser("state", help="查看本机发现状态")
    args = ap.parse_args(argv)

    if args.cmd == "discover":
        out = discover(args.tool, target=args.target, use_cache=not args.no_cache,
                       exe_candidates=args.exe_candidate)
    elif args.cmd == "cache-put":
        saved = _cache_put(normalize_tool_id(args.tool), args.command, args.via)
        print(json.dumps({"saved": saved}))
        return 0 if saved else 1
    elif args.cmd == "execute":
        context = {}
        try:
            with open(args.request_file, encoding='utf-8-sig') as stream:
                request = json.load(stream)
            if not isinstance(request, dict):
                raise ValueError('执行请求必须是对象')
            raw_context = request.get('context', {})
            if not isinstance(raw_context, dict):
                raise ValueError('context 必须是对象')
            context = {key: value for key, value in raw_context.items()
                       if key in ('tool', 'mode', 'exe', 'workDir', 'target') and isinstance(value, str)}
            if request.get('cwd') is not None and not isinstance(request['cwd'], str):
                raise ValueError('cwd 必须是目录字符串')
            timeout = request.get('timeout', 600)
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 43200:
                raise ValueError('timeout 必须在 0 到 43200 秒之间')
            process = _run_tool_process(request.get('argv'), cwd=request.get('cwd'), timeout=timeout,
                capture_output=True, text=True, encoding='utf-8', errors='replace', stdin=subprocess.DEVNULL)
            print(json.dumps({**context, 'status': 'RAN' if process.returncode == 0 else 'FAILED',
                'stage': 'execution', 'exit': process.returncode,
                'output': ((process.stdout or '') + '\n' + (process.stderr or ''))[-8000:]}, ensure_ascii=False))
            return process.returncode if 0 <= process.returncode <= 255 else 1
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            print(json.dumps({**context, 'status': 'FAILED', 'stage': 'execution', 'reason': str(exc)}, ensure_ascii=False))
            return 3
    elif args.cmd == "plan":
        out = plan_control(args.tool, target=args.target, apply_mcp=args.apply_mcp)
    elif args.cmd == "register":
        out = register_mcp(args.tool, apply=args.apply)
    elif args.cmd == "install":
        out = propose_install(args.tool, execute=args.execute)
    elif args.cmd == "state":
        out = list_state()
    else:
        out = {"error": "unknown cmd"}
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
