#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_matrix.py —— 脱壳/反调试「仪器探针矩阵」。

回答一个具体问题：**这台机器、这个目标，哪些仪器真的能用？**
把结果写成 JSON，可直接作为 `case_state.py instrument` 的输入依据。

探针（能跑就跑，跑不了必须给出原因，绝不静默跳过）：
    baseline      直接启动：存活秒数 / 退出码 / 是否有窗口
    x64dbg        若装了 x64dbg/x32dbg：能起吗？目标进程出现吗？（是否自毁需 GUI 确认）
    frida-spawn   frida -f 目标：能拉起吗？拉起后是否自毁？
    frida-attach  对 baseline 进程 frida -p：能挂吗？
    external      OpenProcess + ReadProcessMemory：有权限外部读内存吗？
    network       是否观察到出站 TCP / tshark、dumpcap 是否可用

设计纪律：
    · 单探针超时 20s，整体不超过 90s；`--quick` 只做 baseline + external。
    · 纯标准库；工具发现走 `Tool/mcp/tool_autodiscover.py`，回退 `shutil.which`。
    · 不写死本机绝对路径；不 `-h` 试探任何工具。
    · DLL 不能直接启动是设计内卡点：明确写 blocked + 原因，不伪装成功。
    · 所有启动的子进程在探针结束/脚本退出时清理，避免留下靶机进程。

用法：
    python Tool/scripts/probe_matrix.py --target Tool/cases/项目A/v2/dist/version.dll --json
    python Tool/scripts/probe_matrix.py --target <exe> --out work/<task>/probe.json
    python Tool/scripts/probe_matrix.py --target <exe> --quick --json
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

IS_WIN = sys.platform == "win32"
PER_PROBE_TIMEOUT = 20
TOTAL_BUDGET = 90
PROBE_NAMES = ["baseline", "x64dbg", "frida-spawn", "frida-attach", "external", "network"]
QUICK_NAMES = ["baseline", "external"]

REPO_ROOT = Path(__file__).resolve().parents[2]
_AD_MODULE = None
_AD_ERROR = ""
_TOOL_CACHE = {}


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
def _out(s=""):
    try:
        print(s)
    except UnicodeEncodeError:
        print(str(s).encode("utf-8", "replace").decode("utf-8", "replace"))


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _winerr_text(code):
    """Win32 错误码 + 常见 NTSTATUS 对照。探针失败要能看懂，不是只给数字。"""
    mapping = {
        5: "ERROR_ACCESS_DENIED / STATUS_ACCESS_DENIED (0xC0000022)",
        6: "ERROR_INVALID_HANDLE / STATUS_INVALID_HANDLE (0xC0000008)",
        87: "ERROR_INVALID_PARAMETER / STATUS_INVALID_PARAMETER (0xC000000D)",
        299: "ERROR_PARTIAL_COPY / STATUS_PARTIAL_COPY (0x8000000D)",
        998: "ERROR_NOACCESS / STATUS_ACCESS_VIOLATION (0xC0000005)",
    }
    if code in mapping:
        return f"{code}: {mapping[code]}"
    try:
        return f"{code}: {ctypes.FormatError(code)}"
    except Exception:
        return str(code)


def _load_autodiscover():
    global _AD_MODULE, _AD_ERROR
    if _AD_MODULE is not None or _AD_ERROR:
        return _AD_MODULE
    mcp_dir = REPO_ROOT / "Tool" / "mcp"
    try:
        if str(mcp_dir) not in sys.path:
            sys.path.insert(0, str(mcp_dir))
        import tool_autodiscover  # type: ignore
        _AD_MODULE = tool_autodiscover
    except Exception as exc:  # 不中断探针：回退 PATH
        _AD_ERROR = f"tool_autodiscover 不可用：{exc}"
        _AD_MODULE = None
    return _AD_MODULE


def _find_tool(tool_id, target=None, exe_names=()):
    """先 tool_autodiscover，再 PATH。返回 {available, command, via, note}。"""
    key = (tool_id, target or "")
    if key in _TOOL_CACHE:
        return _TOOL_CACHE[key]

    ad = _load_autodiscover()
    result = {"available": False, "command": "", "via": "none", "note": ""}
    if ad is not None:
        try:
            r = ad.discover(tool_id, target=target, use_registry=True)
            if r.get("available"):
                result = {"available": True, "command": r.get("command", ""),
                          "via": "tool_autodiscover:" + str(r.get("via")), "note": ""}
        except Exception as exc:
            result["note"] = f"tool_autodiscover 查询失败：{exc}"

    if not result["available"]:
        for name in exe_names:
            hit = shutil.which(name)
            if hit:
                result = {"available": True, "command": hit, "via": "PATH:" + name, "note": ""}
                break
    if not result["available"] and _AD_ERROR:
        result["note"] = (result["note"] + "；" if result["note"] else "") + _AD_ERROR
    _TOOL_CACHE[key] = result
    return result


def _parse_pe(path):
    """最小 PE 解析：只取探针需要的 machine / DLL / 入口 / ImageSize。"""
    meta = {"format": "not-pe", "arch": "unknown", "is_dll": False,
            "entry_rva": None, "size_of_image": None, "machine": None}
    try:
        with open(path, "rb") as f:
            dos = f.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return meta
            e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
            f.seek(e_lfanew)
            pe = f.read(24)
            if len(pe) < 24 or pe[:4] != b"PE\0\0":
                return meta
            machine, nsect, _, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", pe, 4)
            opt = f.read(opt_size)
            if len(opt) < 0x40:
                return meta
            magic = struct.unpack_from("<H", opt, 0)[0]
            pe32p = magic == 0x20B
            meta.update({
                "format": "PE32+" if pe32p else "PE32",
                "arch": {0x8664: "x64", 0x14C: "x86", 0xAA64: "arm64"}.get(machine, hex(machine)),
                "machine": machine,
                "is_dll": bool(chars & 0x2000),
                "entry_rva": struct.unpack_from("<I", opt, 16)[0],
                "size_of_image": struct.unpack_from("<I", opt, 56)[0],
                "image_base": struct.unpack_from("<Q" if pe32p else "<I", opt, 24)[0],
                "number_of_sections": nsect,
                "size_of_headers": struct.unpack_from("<I", opt, 60)[0],
            })
    except Exception as exc:
        meta["error"] = str(exc)
    return meta


# ---------------------------------------------------------------------------
# Windows 进程辅助
# ---------------------------------------------------------------------------
def _has_window(pid):
    if not IS_WIN:
        return None
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        found = [False]
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        def _cb(hwnd, _lparam):
            owner = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
            if owner.value == pid and user32.IsWindowVisible(hwnd):
                found[0] = True
                return False
            return True

        cb = WNDENUMPROC(_cb)
        user32.EnumWindows(cb, 0)
        return found[0]
    except Exception:
        return None


def _open_process(pid, access):
    if not IS_WIN:
        return None, 0
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
        h = k32.OpenProcess(access, False, int(pid))
        if not h:
            return None, ctypes.get_last_error()
        return h, 0
    except Exception as exc:
        return None, str(exc)


def _close_handle(h):
    if not h or not IS_WIN:
        return
    try:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(ctypes.c_void_p(h))
    except Exception:
        pass


def _kill_pid(pid):
    if not pid or not IS_WIN:
        return
    h, _ = _open_process(pid, 0x0001)  # PROCESS_TERMINATE
    if h:
        try:
            ctypes.WinDLL("kernel32", use_last_error=True).TerminateProcess(ctypes.c_void_p(h), 1)
        finally:
            _close_handle(h)
    else:
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True, timeout=5)
        except Exception:
            pass


def _terminate_popen(p, timeout=3):
    if p is None:
        return
    try:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=timeout)
    except Exception:
        pass


def _pids_by_image(image_name):
    """tasklist 取同名进程 PID。用于识别 frida/x64dbg 新拉起的子进程。"""
    if not IS_WIN or not image_name:
        return set()
    try:
        r = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {image_name}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=8)
        pids = set()
        for line in (r.stdout or "").splitlines():
            parts = [x.strip().strip('"') for x in line.split(",")]
            if len(parts) >= 2 and parts[0].lower() == image_name.lower():
                try:
                    pids.add(int(parts[1]))
                except ValueError:
                    pass
        return pids
    except Exception:
        return set()


def _module_info(h):
    """取进程主模块基址/大小（psapi）。失败返回 (None, err)。"""
    try:
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        HMODULE = ctypes.c_void_p

        class MODULEINFO(ctypes.Structure):
            _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                        ("SizeOfImage", ctypes.c_ulong),
                        ("EntryPoint", ctypes.c_void_p)]

        arr = (HMODULE * 1024)()
        needed = ctypes.c_ulong(0)
        ok = False
        try:
            psapi.EnumProcessModulesEx.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(HMODULE), ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong]
            psapi.EnumProcessModulesEx.restype = ctypes.c_bool
            ok = psapi.EnumProcessModulesEx(ctypes.c_void_p(h), arr,
                                            ctypes.sizeof(arr), ctypes.byref(needed), 3)
        except Exception:
            ok = False
        if not ok:
            psapi.EnumProcessModules.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(HMODULE), ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong)]
            psapi.EnumProcessModules.restype = ctypes.c_bool
            ok = psapi.EnumProcessModules(ctypes.c_void_p(h), arr,
                                          ctypes.sizeof(arr), ctypes.byref(needed))
        if not ok:
            return None, f"EnumProcessModules 失败：{_winerr_text(ctypes.get_last_error())}"
        if not needed.value:
            return None, "EnumProcessModules 返回 0 个模块"

        mi = MODULEINFO()
        psapi.GetModuleInformation.argtypes = [
            ctypes.c_void_p, HMODULE, ctypes.POINTER(MODULEINFO), ctypes.c_ulong]
        psapi.GetModuleInformation.restype = ctypes.c_bool
        if not psapi.GetModuleInformation(ctypes.c_void_p(h), arr[0],
                                          ctypes.byref(mi), ctypes.sizeof(mi)):
            return None, f"GetModuleInformation 失败：{_winerr_text(ctypes.get_last_error())}"

        # 主模块路径（仅用于 evidence 的可读性）
        name_buf = ctypes.create_unicode_buffer(1024)
        try:
            psapi.GetModuleFileNameExW.argtypes = [ctypes.c_void_p, HMODULE,
                                                   ctypes.c_wchar_p, ctypes.c_ulong]
            psapi.GetModuleFileNameExW.restype = ctypes.c_ulong
            psapi.GetModuleFileNameExW(ctypes.c_void_p(h), arr[0], name_buf, 1024)
        except Exception:
            name_buf.value = ""
        return {"base": int(mi.lpBaseOfDll or 0), "size": int(mi.SizeOfImage or 0),
                "entry": int(mi.EntryPoint or 0), "path": name_buf.value}, ""
    except Exception as exc:
        return None, f"模块查询异常：{exc}"


def _read_remote(h, addr, size):
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_void_p, ctypes.c_size_t,
                                          ctypes.POINTER(ctypes.c_size_t)]
        k32.ReadProcessMemory.restype = ctypes.c_bool
        ok = k32.ReadProcessMemory(ctypes.c_void_p(h), ctypes.c_void_p(addr),
                                   buf, size, ctypes.byref(read))
        if not ok:
            return None, 0, _winerr_text(ctypes.get_last_error())
        return buf.raw[:read.value], read.value, ""
    except Exception as exc:
        return None, 0, str(exc)


def _net_connections(pid):
    """netstat 观察指定 PID 的 TCP 连接（不主动抓包）。"""
    if not IS_WIN:
        return [], "非 Windows，netstat 解析未实现"
    try:
        r = subprocess.run(["netstat", "-ano", "-p", "tcp"],
                           capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=8)
        conns = []
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) < 5 or parts[0].upper() != "TCP":
                continue
            if parts[-1] != str(pid):
                continue
            remote, state = parts[2], parts[3]
            if remote.startswith(("0.0.0.0", "[::]", "127.0.0.1", "[::1]")):
                continue
            conns.append(f"{parts[1]} -> {remote} {state}")
        return conns, ""
    except Exception as exc:
        return [], f"netstat 失败：{exc}"


# ---------------------------------------------------------------------------
# 探针上下文与各探针
# ---------------------------------------------------------------------------
class ProbeContext:
    def __init__(self, target, quick):
        self.target = str(Path(target).resolve())
        self.quick = quick
        self.start = time.monotonic()
        self.deadline = self.start + TOTAL_BUDGET
        self.meta = _parse_pe(self.target)
        self.proc = None
        self.pid = None
        self.tmpdir = tempfile.mkdtemp(prefix="seep_probe_")

    def remaining(self):
        return max(0.0, self.deadline - time.monotonic())

    def probe_timeout(self):
        return max(0.0, min(PER_PROBE_TIMEOUT, self.remaining()))

    def image_name(self):
        return os.path.basename(self.target)


def _status(name, status, evidence, note):
    return {"name": name, "status": status, "evidence": evidence, "note": note}


def probe_baseline(ctx):
    if not os.path.isfile(ctx.target):
        return _status("baseline", "blocked", "目标不存在", ctx.target)
    if not IS_WIN:
        return _status("baseline", "blocked", "仅支持 Windows",
                       "本探针依赖 Windows 进程/窗口 API")
    if ctx.meta.get("is_dll"):
        return _status("baseline", "blocked",
                       "目标是 DLL（IMAGE_FILE_DLL），不能直接作为进程启动",
                       "需要宿主进程（如 rundll32/host.exe）或注入场景；先确定宿主再重跑 --target。"
                       "这是设计内卡点，不是脚本失败。")

    t0 = time.monotonic()
    try:
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP") else 0
        p = subprocess.Popen([ctx.target], cwd=os.path.dirname(ctx.target) or None,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, creationflags=flags)
    except OSError as exc:
        return _status("baseline", "blocked", f"启动失败：{exc}",
                       "检查位数/依赖 DLL/权限；不要用 -h 试探目标")
    ctx.proc, ctx.pid = p, p.pid
    wait_s = min(6.0, ctx.probe_timeout())
    while time.monotonic() - t0 < wait_s:
        if p.poll() is not None:
            break
        time.sleep(0.2)
    elapsed = time.monotonic() - t0
    if p.poll() is None:
        win = _has_window(p.pid)
        ctx.pid = p.pid
        return _status("baseline", "ok",
                       f"存活 {elapsed:.1f}s，pid={p.pid}，"
                       f"窗口={'有' if win else ('无/未检测到' if win is False else '检测失败')}",
                       "进程保持运行，供 external/frida-attach/network 复用；脚本结束时会终止")
    rc = p.returncode
    ctx.pid = None
    if rc != 0:
        return _status("baseline", "killed",
                       f"启动后 {elapsed:.1f}s 退出，退出码={rc}",
                       "可能是缺依赖/反调试/自毁；用 external 或 x64dbg 对照确认，不要直接下结论")
    return _status("baseline", "partial",
                   f"启动后 {elapsed:.1f}s 正常退出，退出码=0",
                   "短命进程可能已完成任务；若要 attach/external，需换常驻参数或宿主")


def probe_external(ctx):
    if not IS_WIN:
        return _status("external", "blocked", "仅支持 Windows", "依赖 OpenProcess/ReadProcessMemory")
    if not ctx.pid:
        return _status("external", "blocked", "没有存活的 baseline 进程可供外部读取",
                       "先让 baseline 存活；DLL 需要宿主进程。不要用进程内读内存代替外部读（会触发 guard）")
    pid = ctx.pid
    rights = 0x0400 | 0x0010  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    h, err = _open_process(pid, rights)
    if not h:
        h2, err2 = _open_process(pid, 0x1000)  # PROCESS_QUERY_LIMITED_INFORMATION
        if h2:
            _close_handle(h2)
            return _status("external", "partial",
                           f"可打开查询句柄，但 VM_READ 被拒：{err if isinstance(err, str) else _winerr_text(err)}",
                           "只能看模块/命令行，不能 dump；尝试提升权限或换保护较弱的时机")
        return _status("external", "blocked",
                       f"OpenProcess 失败：{err if isinstance(err, str) else _winerr_text(err)}",
                       "可能权限不足/进程已退出/被保护；转网络层或换 dump 时机")
    try:
        mi, merr = _module_info(h)
        if not mi:
            return _status("external", "partial", f"OpenProcess 成功，但模块查询失败：{merr}",
                           "能开句柄但取不到基址，无法按模块 dump")
        data, n, rerr = _read_remote(h, mi["base"], 0x1000)
        if not data:
            return _status("external", "partial",
                           f"OpenProcess 成功，ReadProcessMemory 失败：{rerr}",
                           "句柄有 VM_READ 但读不到首部；可能 guard/保护，换时机或换页")
        mz = data[:2] == b"MZ"
        return _status("external", "ok",
                       f"OpenProcess+ReadProcessMemory 成功：pid={pid}，"
                       f"base=0x{mi['base']:X}，SizeOfImage=0x{mi['size']:X}，"
                       f"首部 MZ={'是' if mz else '否'}，读到 {n} 字节",
                       "外部 RPM 可用：优先用它 dump，避免进程内读解密页触发 PAGE_GUARD")
    finally:
        _close_handle(h)


def _frida_script(ctx, name):
    path = Path(ctx.tmpdir) / f"{name}.js"
    path.write_text(
        'console.log("[seep] probe attached: " + Process.id);\n'
        'setTimeout(function () { console.log("[seep] probe alive"); }, 1000);\n',
        encoding="utf-8")
    return str(path)


def _run_frida_attached(cmd, ctx, label):
    """跑 frida CLI：保持 stdin 打开；stdout/stderr 落临时文件，避免管道满导致假死。"""
    timeout = ctx.probe_timeout()
    log_path = os.path.join(ctx.tmpdir, f"frida_{label}.log")
    try:
        logf = open(log_path, "w+b")
        p = subprocess.Popen(cmd, cwd=os.path.dirname(ctx.target) or None,
                             stdin=subprocess.PIPE, stdout=logf, stderr=subprocess.STDOUT)
    except OSError as exc:
        return None, f"启动 frida 失败：{exc}", 0.0
    t0 = time.monotonic()
    timed_out = False
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_popen(p, timeout=4)
    elapsed = time.monotonic() - t0
    try:
        logf.flush()
        logf.seek(0)
        text = logf.read().decode("utf-8", "replace")
    except Exception:
        text = ""
    finally:
        try:
            logf.close()
        except Exception:
            pass
    return {"timed_out": timed_out, "rc": p.returncode, "elapsed": elapsed,
            "text": text.strip()}, "", elapsed


def probe_frida_spawn(ctx):
    if not IS_WIN:
        return _status("frida-spawn", "blocked", "仅支持 Windows", "Frida 探针在 Windows 上验证")
    tool = _find_tool("frida", ctx.target, ("frida.exe", "frida"))
    if not tool["available"]:
        return _status("frida-spawn", "blocked",
                       "未发现 frida CLI（tool_autodiscover/where 均未命中）",
                       (tool.get("note") or "") + "；pip install frida-tools 后重试")
    if ctx.meta.get("is_dll"):
        return _status("frida-spawn", "blocked", "目标是 DLL，frida -f 不能直接 spawn",
                       "需要宿主进程；用 frida -n/-p 附加宿主，或先做 baseline 宿主验证")
    script = _frida_script(ctx, "spawn")
    before = _pids_by_image(ctx.image_name())
    cmd = [tool["command"], "-f", ctx.target, "-l", script, "-q"]
    r, err, elapsed = _run_frida_attached(cmd, ctx, "spawn")
    if err:
        return _status("frida-spawn", "blocked", err, tool.get("via", ""))
    text = r["text"]
    live = sorted(_pids_by_image(ctx.image_name()) - before)
    for pid in live:
        _kill_pid(pid)
    brief = text[-800:] if text else "(无输出)"
    attached = "[seep] probe attached" in text
    if r["timed_out"]:
        if live:
            return _status("frida-spawn", "ok",
                           f"frida spawn 后目标存活 {r['elapsed']:.1f}s（pid={live}），超时由脚本清理",
                           "spawn 成功；若目标随后静默不联网，参照 anti-debug.md 的「网络静默失败」")
        if attached:
            return _status("frida-spawn", "partial",
                           f"frida 已注入并输出 attached，但未发现存活目标（{r['elapsed']:.1f}s）；输出：{brief}",
                           "spawn 成功但目标随后退出：对照 baseline，区分正常退出/自毁")
        return _status("frida-spawn", "killed",
                       f"frida 仍在但未发现目标进程（{r['elapsed']:.1f}s），疑似启动即自毁；输出：{brief}",
                       "把这条与 baseline 对照：baseline 活、spawn 死 = 反注入/反调试")
    if attached:
        if live:
            return _status("frida-spawn", "ok",
                           f"frida spawn 成功（输出 attached），目标存活 pid={live}；{r['elapsed']:.1f}s 后脚本退出",
                           "spawn 可用；需要持续 hook 时用交互式 frida / 自写脚本保持会话")
        return _status("frida-spawn", "partial",
                       f"frida 输出 attached，但未发现存活目标（rc={r['rc']}，{r['elapsed']:.1f}s）；输出：{brief}",
                       "spawn 成功但目标随后退出：对照 baseline，区分正常退出/自毁")
    if r["rc"] == 0:
        return _status("frida-spawn", "partial",
                       f"frida {r['elapsed']:.1f}s 内自动退出（rc=0），无法判定目标存活；输出：{brief}",
                       "可能是 stdin 关闭或脚本结束；改用交互式 frida 手工确认")
    lowered = text.lower()
    if any(k in lowered for k in ("failed to spawn", "unable to", "not found", "error")):
        return _status("frida-spawn", "killed",
                       f"frida spawn 失败（rc={r['rc']}，{r['elapsed']:.1f}s）：{brief}",
                       "目标可能拒绝被创建/被调试；对照 baseline，必要时转 external/network")
    return _status("frida-spawn", "partial",
                   f"frida 提前退出（rc={r['rc']}，{r['elapsed']:.1f}s）：{brief}",
                   "无法判定自毁还是 frida 自身参数问题；不要用 -h 试探，查 frida 文档/版本")


def probe_frida_attach(ctx):
    if not IS_WIN:
        return _status("frida-attach", "blocked", "仅支持 Windows", "Frida 探针在 Windows 上验证")
    tool = _find_tool("frida", ctx.target, ("frida.exe", "frida"))
    if not tool["available"]:
        return _status("frida-attach", "blocked",
                       "未发现 frida CLI（tool_autodiscover/where 均未命中）",
                       (tool.get("note") or "") + "；pip install frida-tools 后重试")
    if not ctx.pid:
        return _status("frida-attach", "blocked", "没有存活的 baseline 进程可供 attach",
                       "先让 baseline 存活；DLL 需要宿主进程")
    script = _frida_script(ctx, "attach")
    cmd = [tool["command"], "-p", str(ctx.pid), "-l", script, "-q"]
    r, err, elapsed = _run_frida_attached(cmd, ctx, "attach")
    if err:
        return _status("frida-attach", "blocked", err, tool.get("via", ""))
    text = r["text"]
    brief = text[-800:] if text else "(无输出)"
    attached = "[seep] probe attached" in text
    if r["timed_out"]:
        return _status("frida-attach", "ok",
                       f"frida attach 到 pid={ctx.pid} 并保持 {r['elapsed']:.1f}s（超时由脚本断开）",
                       "attach 成功；若目标此后静默不联网，说明注入/挂钩被检测（不是 attach 失败）")
    if attached:
        return _status("frida-attach", "ok",
                       f"frida attach 成功并执行脚本（pid={ctx.pid}，rc={r['rc']}，{r['elapsed']:.1f}s）；输出：{brief}",
                       "至少完成一次 attach；需要持续 hook 时用交互式 frida / 自写脚本保持会话")
    if r["rc"] == 0:
        return _status("frida-attach", "partial",
                       f"frida {r['elapsed']:.1f}s 内自动退出（rc=0），未看到 attached 标记；输出：{brief}",
                       "可能是 stdin 关闭或脚本结束；改用交互式 frida 手工确认")
    lowered = text.lower()
    if any(k in lowered for k in ("failed to attach", "unable to find", "process not found", "error")):
        return _status("frida-attach", "killed",
                       f"frida attach 失败（rc={r['rc']}，{r['elapsed']:.1f}s）：{brief}",
                       "目标可能反注入/已退出；对照 baseline，转 external 或延后 attach")
    return _status("frida-attach", "partial",
                   f"frida 提前退出（rc={r['rc']}，{r['elapsed']:.1f}s）：{brief}",
                   "无法判定是反调试还是 frida 参数问题；不要用 -h 试探")


def probe_x64dbg(ctx):
    if not IS_WIN:
        return _status("x64dbg", "blocked", "仅支持 Windows", "x64dbg 探针在 Windows 上验证")
    tool_id = "x32dbg" if ctx.meta.get("arch") == "x86" else "x64dbg"
    exe = ("x32dbg.exe", "x32dbg") if tool_id == "x32dbg" else ("x64dbg.exe", "x64dbg")
    tool = _find_tool(tool_id, ctx.target, exe)
    if not tool["available"]:
        return _status("x64dbg", "blocked",
                       f"未发现 {tool_id}（tool_autodiscover/where 均未命中）",
                       (tool.get("note") or "") + "；安装后可用 GUI 手工验证，不要用 -h 试探")
    if ctx.meta.get("is_dll"):
        return _status("x64dbg", "blocked", "目标是 DLL，调试器不能直接启动它",
                       "需要宿主进程或 loaddll 脚本；先确定宿主")
    before = _pids_by_image(ctx.image_name())
    dbg_name = os.path.basename(tool["command"])
    before_dbg = _pids_by_image(dbg_name)
    timeout = min(15.0, ctx.probe_timeout())
    try:
        p = subprocess.Popen([tool["command"], ctx.target],
                             cwd=os.path.dirname(ctx.target) or None,
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        return _status("x64dbg", "blocked", f"启动 {tool_id} 失败：{exc}", tool.get("via", ""))
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if p.poll() is not None:
            break
        time.sleep(0.3)
    elapsed = time.monotonic() - t0
    new_pids = sorted(_pids_by_image(ctx.image_name()) - before)
    new_dbg = sorted(_pids_by_image(dbg_name) - before_dbg)
    dbg_alive = p.poll() is None
    for pid in new_pids:
        _kill_pid(pid)
    _terminate_popen(p, timeout=4)
    # x64dbg 可能把 GUI 实例移交给新进程；把本次新出现的调试器实例也清掉
    for pid in new_dbg:
        _kill_pid(pid)
    if not dbg_alive and not new_pids:
        return _status("x64dbg", "blocked",
                       f"{tool_id} 在 {elapsed:.1f}s 内退出（rc={p.returncode}），目标进程未出现",
                       "可能是调试器启动失败/缺少插件/目标被拒绝；看 GUI 输出，不要 -h 试探")
    if new_pids:
        return _status("x64dbg", "partial",
                       f"{tool_id} 已启动，目标进程出现 pid={new_pids}（观察 {elapsed:.1f}s）；"
                       "是否自毁/断点是否命中需在 GUI 人工确认",
                       "探针只判断'能起+目标出现'，不自动判定自毁；完整性壳请在 GUI 用硬件断点")
    return _status("x64dbg", "killed",
                   f"{tool_id} 仍在运行，但 {elapsed:.1f}s 内未发现目标进程，疑似启动即被壳拒绝/自毁",
                   "与 baseline 对照；若 baseline 活、x64dbg 下目标不出现，优先怀疑反调试")


def probe_network(ctx):
    tshark = _find_tool("tshark", ctx.target, ("tshark.exe", "tshark"))
    dumpcap = _find_tool("dumpcap", ctx.target, ("dumpcap.exe", "dumpcap"))
    tools = []
    if tshark["available"]:
        tools.append("tshark=" + tshark["command"])
    if dumpcap["available"]:
        tools.append("dumpcap=" + dumpcap["command"])
    tool_note = "；".join(tools) if tools else "tshark/dumpcap 均未发现"

    if not ctx.pid:
        return _status("network", "blocked",
                       f"没有存活的 baseline 进程可观察；已发现工具：{tool_note}",
                       "先让 baseline 存活；或手工用 seep_pcap_extract/tshark 抓包")
    conns = []
    seen = set()
    deadline = min(time.monotonic() + 3.0, ctx.deadline)
    while time.monotonic() < deadline:
        if ctx.proc is not None and ctx.proc.poll() is not None:
            break
        cur, err = _net_connections(ctx.pid)
        for c in cur:
            if c not in seen:
                seen.add(c)
                conns.append(c)
        time.sleep(0.4)
    if conns:
        return _status("network", "ok",
                       f"观察到 pid={ctx.pid} 的 {len(conns)} 条出站 TCP：{'; '.join(conns[:5])}；{tool_note}",
                       "有出站即可用 seep_pcap_extract/代理/回放；注意区分明文/TLS")
    if tools:
        return _status("network", "partial",
                       f"已发现抓包工具（{tool_note}；未主动抓包），但 3s 内未观察到 pid={ctx.pid} 的出站 TCP",
                       "可能尚未联网/请求被掐/目标已退出；用「基线 vs 仪器」对照，必要时手工抓包")
    return _status("network", "blocked",
                   f"未观察到出站，且 {tool_note}",
                   "装 tshark/dumpcap，或改用代理/网络层观测；不要假设目标不联网")


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def _run_probe(name, fn, ctx):
    if ctx.remaining() < 2:
        return _status(name, "blocked", "整体 90s 预算耗尽，该探针未执行",
                       "不是静默跳过：预算到点会显式记录；可拆成多次运行或加 --quick")
    t0 = time.monotonic()
    try:
        return fn(ctx)
    except Exception as exc:
        return _status(name, "blocked", f"探针异常：{exc}",
                       "探针自身失败，不代表目标不可分析；查异常后重跑或换外部手段")
    finally:
        _ = time.monotonic() - t0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="probe_matrix.py",
        description="脱壳/反调试仪器探针矩阵：baseline / x64dbg / frida-spawn / frida-attach / external / network",
        epilog="示例：python Tool/scripts/probe_matrix.py --target <exe> --json")
    parser.add_argument("--target", required=True, help="目标 PE（exe/dll）路径")
    parser.add_argument("--json", action="store_true", help="打印 JSON 到 stdout")
    parser.add_argument("--out", help="把 JSON 写到指定文件")
    parser.add_argument("--quick", action="store_true", help="只做 baseline + external（更快）")
    args = parser.parse_args(argv)

    target = os.path.abspath(os.path.expanduser(args.target))
    if not os.path.isfile(target):
        _out(f"[ERR] 目标不存在：{target}")
        return 2

    ctx = ProbeContext(target, args.quick)
    results = {}
    ran = set()

    # 先跑 baseline，后续 external/attach/network 复用其进程
    results["baseline"] = _run_probe("baseline", probe_baseline, ctx); ran.add("baseline")
    if not args.quick:
        # 外部读/网络尽早做，避免后续 GUI 探针拖太久导致 baseline 已退出
        results["external"] = _run_probe("external", probe_external, ctx); ran.add("external")
        results["network"] = _run_probe("network", probe_network, ctx); ran.add("network")
        results["frida-attach"] = _run_probe("frida-attach", probe_frida_attach, ctx); ran.add("frida-attach")
        results["frida-spawn"] = _run_probe("frida-spawn", probe_frida_spawn, ctx); ran.add("frida-spawn")
        results["x64dbg"] = _run_probe("x64dbg", probe_x64dbg, ctx); ran.add("x64dbg")
    else:
        results["external"] = _run_probe("external", probe_external, ctx); ran.add("external")

    # 清理 baseline
    if ctx.proc is not None and ctx.proc.poll() is None:
        _terminate_popen(ctx.proc, timeout=4)
    elif ctx.pid:
        _kill_pid(ctx.pid)
    try:
        shutil.rmtree(ctx.tmpdir, ignore_errors=True)
    except Exception:
        pass

    wanted = QUICK_NAMES if args.quick else PROBE_NAMES
    probes = []
    for name in wanted:
        if name in results:
            probes.append(results[name])
        else:
            probes.append(_status(name, "blocked", "该探针未执行（不在本次模式内）",
                                  "使用不带 --quick 的模式可启用"))
    payload = {
        "target": target,
        "sha256": _sha256(target),
        "probes": probes,
        "meta": {
            "arch": ctx.meta.get("arch"),
            "is_dll": ctx.meta.get("is_dll"),
            "entry_rva": ctx.meta.get("entry_rva"),
            "size_of_image": ctx.meta.get("size_of_image"),
            "quick": bool(args.quick),
            "elapsed_s": round(time.monotonic() - ctx.start, 1),
            "budget_s": TOTAL_BUDGET,
            "per_probe_timeout_s": PER_PROBE_TIMEOUT,
        },
    }
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.out:
        out_path = os.path.abspath(os.path.expanduser(args.out))
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        _out(f"[OK] 已写入 {out_path}")
    if args.json:
        _out(text)
    elif not args.out:
        _out(f"target: {target}")
        _out(f"sha256: {payload['sha256']}")
        for p in probes:
            _out(f"- {p['name']:<13} {p['status']:<8} {p['evidence']}")
            if p.get("note"):
                _out(f"  note: {p['note']}")
        _out(f"elapsed: {payload['meta']['elapsed_s']}s / budget {TOTAL_BUDGET}s")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        _out("[ERR] 用户中断")
        sys.exit(130)
