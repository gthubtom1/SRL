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
  7. 自动安装只做半自动：探测 -> 给安装命令+来源 -> 用户确认 -> 装 -> 重探。不做无脑全自动。

本模块既被 seep_mcp_server.py 以 `import tool_autodiscover` 调用（零副作用），
也可独立命令行运行（见文件末尾 __main__）。
"""
import io
import time
import os
import sys
import json
import shutil
import struct
import subprocess
import datetime

# ---------------------------------------------------------------------------
# 路径与常量
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOL_DIR = os.path.dirname(_HERE)                       # Tool/
_CONFIG_DIR = os.path.join(_TOOL_DIR, "config")
_CAP_FILE = os.path.join(_CONFIG_DIR, "tool-capabilities.json")
_INSTALL_FILE = os.path.join(_CONFIG_DIR, "tool-install.json")

# 本机状态（绝不入库）
LOCAL_STATE_DIR = os.path.expanduser(os.path.join("~", ".seep"))

_PATH_CACHE_FILE = os.path.join(LOCAL_STATE_DIR, "tool-paths.json")


def _cache_read():
    """读机器级路径缓存（与 tool-run.ps1 共用同一文件与 schema）。"""
    try:
        # utf-8-sig：tool-run.ps1 用 PowerShell 写的文件带 BOM，用 utf-8 读会解析失败，
        # 失败后整份覆盖会**丢掉已有条目**（实测踩到：r2/jadx 被新条目顶掉）。
        with io.open(_PATH_CACHE_FILE, encoding="utf-8-sig") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _cache_get(tid, exe_names):
    """缓存命中且路径仍可用才算命中（工具可能被卸载/挪走）。"""
    raw = _cache_read()
    e = (raw.get("tools") or {}).get(tid)
    if not isinstance(e, dict) or not e.get("available"):
        legacy = raw.get(tid)          # 旧结构：顶层 <id> = {"exe": ...}
        e = {"available": True, "command": (legacy or {}).get("exe")} if isinstance(legacy, dict) else None
    if not isinstance(e, dict) or not e.get("available"):
        return None
    cmd = e.get("command") or ""
    if not cmd:
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
        d = _cache_read()
        tools = d.setdefault("tools", {})
        tools[tid] = {
            "available": True, "command": command, "via": via, "arch": arch,
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        # 双写：mcp-bridge-x64dbg.py / mcp-launch.py 读的是**顶层** <id>.exe 旧结构。
        # 只写 tools{} 会把它们的条目覆盖掉（实测踩到：x64dbg MCP 变 401、tools/list 0 个）。
        d[tid] = {"exe": command, "via": via,
                  "verified": time.strftime("%Y-%m-%d %H:%M:%S")}
        d["schemaVersion"] = d.get("schemaVersion") or "1.0"
        os.makedirs(LOCAL_STATE_DIR, exist_ok=True)
        tmp = _PATH_CACHE_FILE + ".tmp"
        with io.open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
        os.replace(tmp, _PATH_CACHE_FILE)   # 原子替换，避免与 tool-run.ps1 并发写坏
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
    for key in ("SEEP_TOOL_ROOT", "REVERSE_TOOL_ROOT", "SEEP_TOOLS_DIR"):
        v = (os.environ.get(key) or "").strip()
        if v:
            roots.append(os.path.expanduser(v))

    home = _user_home()

    # ② 用户级
    roots.append(os.path.join(home, ".seep", "tools"))      # 本工作台安装目标
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
    return _load_json(_INSTALL_FILE, {"installable": {}, "auto_allow_methods": ["pip"]})


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
    return any(m in low for m in _DENY_MARKERS)


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
def _layer_env(tool_id, exe_names):
    """第 1 层：环境变量显式指定（最高优先）。"""
    env_key = "SEEP_" + "".join(ch if ch.isalnum() else "_" for ch in tool_id.upper()) + "_PATH"
    val = os.environ.get(env_key, "")
    if val and os.path.isfile(val) and not _denied(val):
        return {"available": True, "command": val, "via": "env", "env_key": env_key}
    return None


def _layer_path(exe_names):
    """第 2 层：PATH 查找（系统安装优先于便携副本）。"""
    for e in exe_names:
        w = shutil.which(e)
        if w and not _denied(w):
            return {"available": True, "command": w, "via": "PATH"}
    return None


def _layer_common_dirs(exe_names):
    """第 3 层：常见安装根的直接子目录 / bin / cli。"""
    for root in _COMMON_ROOTS:
        if not root or not os.path.isdir(root):
            continue
        for e in exe_names:
            for sub in ("", "bin", "cli"):
                base = os.path.join(root, sub, e) if sub else os.path.join(root, e)
                for cand in (base, base + ".exe"):
                    if os.path.isfile(cand) and not _denied(cand):
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
                if os.path.isfile(cand) and not _denied(cand):
                    return {"available": True, "command": cand, "via": "registry",
                            "install_dir": d}
    return None


def _layer_scan(tool_id, exe_names, max_depth=4):
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
                    dirnames[:] = [d for d in dirnames if d.lower() not in _SKIP_DIR_NAMES]
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
                            if not _denied(full) and os.path.isfile(full):
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
                r = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", cmd],
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
    want = {e.lower() for e in exe_names}
    for t in _lnk_targets():
        if os.path.basename(t).lower() in want and os.path.isfile(t) and not _denied(t):
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
            r = subprocess.run([es, "-n", "40", e], capture_output=True, text=True, timeout=10)
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


def discover(tool_id, target=None, use_registry=True):
    """六层递进发现：命中即停。返回结构化结果。

    Args:
        tool_id: 工具标识（可带别名，会自动规范化）。
        target: 可选目标文件；若为 PE 且工具 arch_aware，则按 machine 字段选 32/64 位。
        use_registry: 是否启用第 4 层注册表探测（Windows 有效）。
    """
    raw = (tool_id or "").strip()
    tid = normalize_tool_id(raw)
    caps = _capabilities_table().get("tools", {}).get(tid, {})

    arch = read_pe_machine(target) if (target and os.path.isfile(target)) else None
    exe_names = _exe_candidates(tid, arch)

    layers = []
    # 第 0 层：机器级缓存（上次发现的结果；每次都校验路径仍在）
    hit = _cache_get(tid, exe_names)
    if hit and not _path_excluded(hit, caps):
        layers.append(("cache", hit))
        return _discover_result(raw, tid, caps, arch, exe_names, hit, layers)
    hit = _layer_env(tid, exe_names);  layers.append(("env", hit)); hit = None if _path_excluded(hit, caps) else hit
    if hit:
        return _discover_result(raw, tid, caps, arch, exe_names, hit, layers)
    hit = _layer_path(exe_names);       layers.append(("PATH", hit)); hit = None if _path_excluded(hit, caps) else hit
    if hit:
        return _discover_result(raw, tid, caps, arch, exe_names, hit, layers)
    hit = _layer_common_dirs(exe_names); layers.append(("common_dir", hit)); hit = None if _path_excluded(hit, caps) else hit
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
    hit = _layer_scan(tid, exe_names);  layers.append(("scan", hit)); hit = None if _path_excluded(hit, caps) else hit
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
    if hit.get("via") != "cache":
        _cache_put(tid, hit.get("command", ""), hit.get("via", "?"), arch)
    out = {
        "tool_id": tid, "input": raw, "available": True,
        "command": hit["command"], "via": hit["via"],
        "known_in_table": bool(caps), "arch": arch, "exe_candidates": exe_names,
        "layers_tried": [l[0] for l in layers if l[1] is None] + [hit["via"]],
    }
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
    """定位当前 agent 的 mcp.json。优先环境变量，其次 pi 默认，再退回仓库 .mcp.json。"""
    env = os.environ.get("SEEP_AGENT_MCP", "")
    if env:
        return env
    pi = os.path.expanduser(os.path.join("~", ".pi", "agent", "mcp.json"))
    if os.path.isfile(pi) or os.path.isdir(os.path.dirname(pi)):
        return pi
    # 退路：仓库根 .mcp.json（若存在）
    root_mcp = os.path.join(os.path.dirname(_TOOL_DIR), ".mcp.json")
    return root_mcp


def _mcp_entry_for(tool_id):
    """从能力表/生态模板构造 MCP 注册片段；无则 None。"""
    tid = normalize_tool_id(tool_id)
    eco = _capabilities_table().get("mcp_ecosystem", {})
    if tid in eco:
        e = dict(eco[tid])
        entry = {"command": e.get("command"), "args": e.get("args", [])}
        if e.get("transport"):
            entry["transport"] = e["transport"]
        return entry
    caps = _capabilities_table().get("tools", {}).get(tid, {})
    reg = caps.get("control", {}).get("mcp_register")
    if reg and reg.get("command"):
        return {"command": reg["command"], "args": reg.get("args", []), "transport": "stdio"}
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
    entry = entry or {}
    cmd = str(entry.get("command") or "").strip()
    args = [str(a) for a in (entry.get("args") or [])]
    if not cmd:
        errors.append("缺少 command")
    elif _looks_like_path(cmd):
        if not (os.path.isfile(cmd) or os.path.isdir(cmd)):
            errors.append("command 指向的路径不存在: %s" % cmd)
    elif not shutil.which(cmd):
        warnings.append("运行时不在此机 PATH: %s（装好后重启会话即可）" % cmd)
    for a in args:
        if _looks_like_path(a) and a.lower().endswith(_LOCAL_FILE_SUFFIXES) and not os.path.exists(a):
            errors.append("参数指向的文件不存在: %s" % a)
    return {"ok": not errors, "errors": errors, "warnings": warnings}


def _root_mcp_sync_enabled():
    """是否把 MCP 条目同时同步到【仓库根 .mcp.json】。
    ★ 血案：旧实现无条件追加根目录 .mcp.json（这是 git **受跟踪**文件），
    即使设置了 SEEP_AGENT_MCP 做测试隔离也照样写 —— 跑一次自测就会把测试工具
    （如 ghidra）写进受跟踪文件，并在仓库根堆出几十个 .mcp.json.bak-<时间戳> 垃圾。

    现在的规则：
      · 设了 SEEP_AGENT_MCP（测试 / 多实例隔离）→ 只写该目标，绝不碰仓库根；
      · 环境变量 SEEP_SYNC_ROOT_MCP=0/false/off → 关闭根同步；
      · 其余情况（默认）→ 保持老行为，同步根 .mcp.json（多宿主共用项目级配置）。
    """
    if os.environ.get("SEEP_AGENT_MCP", "").strip():
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

    if not entry:
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

    # 增量合并所有有效目标
    written_targets = []
    unverified_targets = []
    for p in targets:
        cfg = _load_json(p, {"mcpServers": {}})
        if not isinstance(cfg, dict):
            cfg = {"mcpServers": {}}
        servers = cfg.get("mcpServers")
        if not isinstance(servers, dict):
            servers = {}
            cfg["mcpServers"] = servers
        existed = name in servers
        servers[name] = entry
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            if os.path.isfile(p):
                shutil.copy2(p, p + ".bak-" + datetime.datetime.now().strftime("%Y%m%d%H%M%S"))
                _prune_backups(p, keep=3)
            with open(p, "w", encoding="utf-8") as f:  # UTF-8 无 BOM
                json.dump(cfg, f, indent=2, ensure_ascii=False)
            written_targets.append(p)
            # 写后回读校验：确认落盘的就是这条（防编码/并发覆盖/手改成脏）
            try:
                back = (_load_json(p, {}) or {}).get("mcpServers", {}).get(name)
                if back != entry:
                    unverified_targets.append(p)
            except Exception:
                unverified_targets.append(p)
        except Exception:
            continue

    if not written_targets:
        return {"tool_id": tid, "registered": False, "error": "写入所有目标 mcp.json 均失败",
                "targets": targets}

    return {"tool_id": tid, "registered": True, "server_name": name, "entry": entry,
            "written_targets": written_targets, "overwrote_existing": existed,
            "verified": not bool(unverified_targets), "unverified_targets": unverified_targets,
            "preflight": pre,
            "restart_required": True,
            "note": "已增量写入 mcp.json（未删除任何用户既有条目，多Agent宿主已协同同步）。★ 需重启 Agent 会话后生效。"}


# ---------------------------------------------------------------------------
# 半自动安装（探测 -> 给命令+来源 -> 确认 -> 装 -> 重探）
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 多途径自适应安装与便携下载引擎
# ---------------------------------------------------------------------------
def _detect_local_proxy_port():
    """快速探测常见的本地 HTTP/SOCKS 代理端口（如 Clash/V2Ray/Surge）。"""
    import socket
    for p in (7897, 10808, 7890):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.15)
            s.connect(("127.0.0.1", p))
            s.close()
            return p
        except Exception:
            pass
    return None


def _download_and_extract_portable(urls, target_sub, verify_exe=""):
    """免包管理器绿色便携下载与解压引擎（针对无 winget 的精简版/LTSC Win10 系统）。
    自动轮询直链与国内加速镜像，使用 Python 原生 zipfile 解压到便携目录。
    """
    import urllib.request
    import zipfile
    import tempfile

    proxy_port = _detect_local_proxy_port()
    opener = None
    if proxy_port:
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    else:
        opener = urllib.request.build_opener()

    # 安装目标基目录：固定用户级（~/.seep/tools），绝不写死盘符。
    # 需要换位置就设 SEEP_TOOL_INSTALL_DIR 环境变量。
    base_target = _install_base()
    final_dir = os.path.join(base_target, target_sub)
    os.makedirs(final_dir, exist_ok=True)

    downloaded = False
    last_err = ""
    for u in urls:
        if not u:
            continue
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SeepAutoDiscover/1.8"})
            with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tf:
                tmp_zip = tf.name
            with opener.open(req, timeout=40) as resp, open(tmp_zip, "wb") as out_fp:
                shutil.copyfileobj(resp, out_fp)
            if os.path.isfile(tmp_zip) and os.path.getsize(tmp_zip) > 1024:
                with zipfile.ZipFile(tmp_zip, "r") as zf:
                    # 攻击性加固：严格防御 Zip Slip 路径穿越漏洞，保证解压出的文件绝对不会越界覆盖系统文件
                    base_resolved = os.path.realpath(final_dir)
                    for member in zf.infolist():
                        target_path = os.path.realpath(os.path.join(final_dir, member.filename))
                        if not target_path.startswith(base_resolved + os.sep) and target_path != base_resolved:
                            continue  # 忽略恶意路径穿越条目
                        zf.extract(member, final_dir)
                try:
                    os.remove(tmp_zip)
                except Exception:
                    pass
                downloaded = True
                break
        except Exception as e:
            last_err = f"{u} -> {e}"
            continue

    if not downloaded:
        return {"success": False, "error": f"所有便携下载镜像均失败: {last_err}"}

    # 递归查找 verify_exe
    found_exe = ""
    if verify_exe:
        v_low = os.path.basename(verify_exe).lower()
        for root, _, files in os.walk(final_dir):
            for fn in files:
                if fn.lower() == v_low:
                    found_exe = os.path.join(root, fn)
                    break
            if found_exe:
                break
    else:
        found_exe = final_dir

    if final_dir not in _COMMON_ROOTS:
        _COMMON_ROOTS.insert(0, final_dir)

    return {"success": True, "dir": final_dir, "exe": found_exe}


def install_plan(tool_id):
    """把 tool-install.json 的声明式条目转成可读安装计划（自动根据系统环境匹配最优途径）。
    支持多途径自适应：系统无 winget 时自动无缝降级为 portable_zip（绿色直下免安装）。
    """
    tid = normalize_tool_id(tool_id)
    cfg = _install_table()
    entry = cfg.get("installable", {}).get(tid)
    if not entry:
        return {"tool_id": tid, "has_plan": False,
                "reason": "tool-install.json 未收录该工具；请手动安装后加入 PATH。"}

    # 支持多途径列表 methods
    methods = entry.get("methods")
    has_winget = bool(shutil.which("winget"))

    chosen_method = None
    fallback_methods = []

    if methods and isinstance(methods, list):
        for m in methods:
            m_type = m.get("type", "")
            if m_type == "winget" and not has_winget:
                # 机器无 winget，跳过作为首选，留作备用
                fallback_methods.append(m)
                continue
            if chosen_method is None:
                chosen_method = m
            else:
                fallback_methods.append(m)
        if chosen_method is None and methods:
            chosen_method = methods[0]
    else:
        chosen_method = {"type": entry.get("method", ""), "pkg": entry.get("pkg", ""), "url": entry.get("url", "")}

    m_type = chosen_method.get("type", "")
    pkg = chosen_method.get("pkg", "")
    url = chosen_method.get("url", "")
    urls = chosen_method.get("urls", [])

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

    auto_ok = m_type in (cfg.get("auto_allow_methods") or ["pip", "winget", "portable_zip", "npm", "go"]) and m_type != "manual"
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
        "hint": "自适应多途径：根据当前系统环境自动匹配最佳途径（无 winget 时自动降级为绿色直下，绝不卡住）。"
    }


def propose_install(tool_id, execute=False):
    """半自动安装：默认只出计划；execute=True 且方法在白名单才真正执行并重探。
    具备错误自动降级能力：若首选包管理器失败，自动尝试绿色便携直下等备用途径。
    """
    tid = normalize_tool_id(tool_id)
    plan = install_plan(tid)
    if not plan.get("has_plan"):
        return plan
    if not execute:
        plan["executed"] = False
        return plan
    if not plan.get("auto_allowed"):
        plan["executed"] = False
        plan["reason"] = "method=%s 不在自动白名单，需人工/确认安装。" % plan.get("method")
        return plan

    method = plan["method"]
    active_cfg = plan.get("active_method", {})

    # 1. 途径：portable_zip（绿色解压，适合无包管理器的 Win10）
    if method == "portable_zip":
        urls = active_cfg.get("urls", [])
        sub = active_cfg.get("target_sub", tid)
        vexe = active_cfg.get("verify_exe", "")
        res = _download_and_extract_portable(urls, sub, vexe)
        plan["executed"] = True
        plan["download_result"] = res
        if res.get("success"):
            if res.get("exe"):
                record(tid, {"available": True, "command": res["exe"], "via": "portable_zip"})
            plan["recheck"] = discover(tid)
        else:
            plan["error"] = res.get("error")
        return plan

    # 2. 途径：pip
    if method == "pip":
        pkg = plan["package"]
        argv = [sys.executable, "-m", "pip", "install", pkg]
        p = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
        if p.returncode != 0:
            # 自动降级：使用国内清华源重试
            argv_mirror = [sys.executable, "-m", "pip", "install", "-i", "https://pypi.tuna.tsinghua.edu.cn/simple", pkg]
            p = subprocess.run(argv_mirror, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)

        plan["executed"] = True
        plan["returncode"] = p.returncode
        plan["tail"] = (p.stdout or p.stderr or "")[-400:]
        plan["recheck"] = discover(tid)
        return plan

    # 3. 途径：winget（若失败且有 portable_zip 则自动降级）
    if method == "winget":
        pkg = plan["package"]
        argv = ["winget", "install", "--id", pkg, "-e", "--accept-source-agreements", "--accept-package-agreements"]
        p = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
        
        # 关键降级：如果 winget 失败且存在 fallback_methods 中的 portable_zip
        if p.returncode != 0:
            for fb in plan.get("fallback_methods", []):
                if fb.get("type") == "portable_zip":
                    urls = fb.get("urls", [])
                    sub = fb.get("target_sub", tid)
                    vexe = fb.get("verify_exe", "")
                    res = _download_and_extract_portable(urls, sub, vexe)
                    plan["executed"] = True
                    plan["winget_failed_fallback_portable"] = res
                    if res.get("success"):
                        if res.get("exe"):
                            record(tid, {"available": True, "command": res["exe"], "via": "portable_zip"})
                        plan["recheck"] = discover(tid)
                        return plan

        plan["executed"] = True
        plan["returncode"] = p.returncode
        plan["tail"] = (p.stdout or p.stderr or "")[-400:]
        plan["recheck"] = discover(tid)
        return plan

    # 4. 其他类型 (npm / go)
    argv = []
    if method == "npm":
        argv = ["npm", "install", "-g", plan["package"]]
    elif method == "go":
        argv = ["go", "install", plan["package"]]

    if argv:
        p = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
        plan["executed"] = True
        plan["returncode"] = p.returncode
        plan["tail"] = (p.stdout or p.stderr or "")[-400:]
        plan["recheck"] = discover(tid)
    else:
        plan["executed"] = False

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

    caps = cap.get("capabilities", {}) if cap.get("known") else {}
    ctrl = cap.get("control", {}) if cap.get("known") else {}

    # 1) 已注册 MCP
    if _mcp_already_registered(tid):
        plan["how_to_control"] = {"mode": "mcp_registered",
                                  "detail": "该工具的 MCP 已在 mcp.json 注册，直接调用对应 MCP 工具即可。"}
        plan["next_action"] = "直接用已注册 MCP。"
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
def load_state():
    return _load_json(LOCAL_STATE_PATH, {"schemaVersion": "1.0", "tools": {},
                                         "updated_at": None})


def save_state(state):
    try:
        os.makedirs(LOCAL_STATE_DIR, exist_ok=True)
        state["updated_at"] = _now()
        with open(LOCAL_STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def record(tool_id, result=None):
    """把一次发现结果落本机状态（不写仓库）。"""
    tid = normalize_tool_id(tool_id)
    state = load_state()
    r = result if result is not None else discover(tid)
    state.setdefault("tools", {})[tid] = {
        "available": r.get("available"),
        "command": r.get("command", ""),
        "via": r.get("via", ""),
        "arch": r.get("arch"),
        "checked_at": _now(),
    }
    save_state(state)
    return state["tools"][tid]


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
        out = discover(args.tool, target=args.target); record(args.tool, out)
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
