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
    radio         无线/近场能力枚举：WiFi 是否可 monitor、蓝牙、SDR/802.15.4、NFC（**只读，不发射频**）

设计纪律：
    · 单探针超时 20s（radio 10s），整体不超过 90s；`--quick` 只做 baseline + external。
    · 纯标准库；工具发现走 `Tool/mcp/tool_autodiscover.py`，回退 `shutil.which`。
    · 不写死本机绝对路径；不 `-h` 试探任何工具。
    · DLL 不能直接启动是设计内卡点：明确写 blocked + 原因，不伪装成功。
    · 所有启动的子进程在探针结束/脚本退出时清理，避免留下靶机进程。
    · radio 探针只做能力枚举：绝不进入 monitor mode、绝不调用扫描/发包 API、绝不发任何射频。

用法：
    python Tool/scripts/probe_matrix.py --target Tool/cases/项目A/v2/dist/version.dll --json
    python Tool/scripts/probe_matrix.py --target <exe> --out work/<task>/probe.json
    python Tool/scripts/probe_matrix.py --target <exe> --quick --json
    python Tool/scripts/probe_matrix.py --radio-only --json      # 不需要 --target
    python Tool/scripts/probe_matrix.py --self-test              # 只测判定函数，不碰硬件
"""
from __future__ import annotations

import argparse
import ctypes
import glob
import hashlib
import json
import os
import re
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
RADIO_BUDGET = 10
PROBE_NAMES = ["baseline", "x64dbg", "frida-spawn", "frida-attach", "external", "network", "radio"]
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
        self.total_budget = TOTAL_BUDGET
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
# radio 探针：只读能力枚举（WiFi/monitor、BLE、802.15.4、sub-GHz、NFC）
#
# 纪律（硬约束）：
#   · 只读枚举：不切换 monitor mode、不调用主动扫描、不发任何射频、不改任何网卡状态。
#   · 缺命令/缺权限/超时 → 结构化 blocked（blocked_at），绝不异常穿透。
#   · 单探针 10s 预算；超预算的子命令直接放弃并显式记录。
#
# blocked_at 取值：
#   null               至少一条 802.11 monitor 路径可用
#   no-radio           未发现任何无线/近场硬件
#   no-wifi            有 BLE/SDR/802.15.4/NFC，但没有 WiFi 适配器
#   no-monitor-mode    有 WiFi 但平台/驱动不提供 monitor mode（Windows 最常见）
#   monitor-unverified 有 WiFi 但当前手段无法判定 monitor（缺 iw / 平台私有接口）
#   command-missing    枚举命令缺失，无法确认硬件
#   no-permission      枚举命令被拒（需 root/管理员）
#   timeout            10s 内未完成枚举
#   probe-error        探针内部异常（仍返回结构化字段）
# ---------------------------------------------------------------------------
RADIO_USB_WHITELIST = [
    # (vid, pid, 名称, 类别)；类别决定落到 wifi / subghz / nfc
    ("0bda", "2838", "RTL-SDR (RTL2832U+R820T2)", "sdr"),
    ("0bda", "2832", "RTL2832U DVB-T (SDR 可用)", "sdr"),
    ("1d50", "6089", "HackRF One", "sdr"),
    ("1d50", "604b", "HackRF Jawbreaker", "sdr"),
    ("1d50", "60a1", "rad1o (HackRF 变体)", "sdr"),
    ("0451", "16a8", "CC2531 Zigbee/802.15.4 sniffer", "ieee802154"),
    ("0451", "16ae", "CC2531 (alt firmware)", "ieee802154"),
    ("0451", "16a5", "CC2530", "ieee802154"),
    ("1915", "520f", "nRF52 USB dongle (BLE sniffer)", "ble-sniffer"),
    ("1915", "520a", "nRF52 DK", "ble-sniffer"),
    ("1915", "521f", "nRF52840 dongle", "ble-sniffer"),
    ("9ac4", "4b8f", "Proxmark3", "nfc"),
    ("9ac4", "4b8d", "Proxmark3 (RDV4)", "nfc"),
    ("072f", "2200", "ACS ACR122U NFC 读卡器", "nfc"),
    ("072f", "223b", "ACS ACR1252 NFC 读卡器", "nfc"),
    ("04e6", "5591", "SCM SCL3711 NFC 读卡器", "nfc"),
    ("04cc", "2533", "NXP PN533 NFC", "nfc"),
    ("0cf3", "9271", "Atheros AR9271 (ath9k_htc, 可 monitor)", "wifi-monitor"),
    ("0bda", "8812", "Realtek RTL8812AU (可 monitor)", "wifi-monitor"),
    ("0bda", "8813", "Realtek RTL8814AU (可 monitor)", "wifi-monitor"),
    ("0bda", "a811", "Realtek RTL8811AU (可 monitor)", "wifi-monitor"),
    ("0e8d", "7612", "MediaTek MT7612U (可 monitor)", "wifi-monitor"),
    ("148f", "5572", "Ralink RT5572 (可 monitor)", "wifi-monitor"),
    ("148f", "7601", "MediaTek MT7601U (可 monitor，注入受限)", "wifi-monitor"),
]

_WIFI_WORDS = ("wireless", "wi-fi", "wifi", "wlan", "802.11", "无线", "wlan0")
_BT_WORDS = ("bluetooth", "蓝牙")
# PnP 里的「蓝牙枚举器/服务设备」不是适配器，不能当成可用蓝牙硬件
_BT_SERVICE_WORDS = ("enumerator", "枚举器", "protocol tdi", "personal area network",
                     "rfcomm", "pan ")
_DENY_WORDS = ("permission denied", "operation not permitted", "must be root",
               "access is denied", "not permitted", "拒绝访问", "权限不足")


def _decode_bytes(b):
    """命令输出解码：优先 utf-8，其次 gbk/cp936（Windows netsh 中文），最后 latin-1。"""
    if not b:
        return ""
    if isinstance(b, str):
        return b
    for enc in ("utf-8", "gbk", "cp936", "latin-1"):
        try:
            return b.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return b.decode("utf-8", "replace")


def _run_cmd(cmd, timeout):
    """只读枚举命令。任何失败都转成结构化字段，不抛异常。"""
    res = {"cmd": " ".join(cmd) + " " if isinstance(cmd, (list, tuple)) else str(cmd),
           "rc": None, "out": "", "err": "", "missing": False,
           "denied": False, "timed_out": False}
    res["cmd"] = res["cmd"].strip()
    if not timeout or timeout <= 0:
        res["timed_out"] = True
        res["err"] = "预算不足，未执行"
        return res
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True,
                           timeout=timeout)
        res["rc"] = p.returncode
        res["out"] = _decode_bytes(p.stdout)
        res["err"] = _decode_bytes(p.stderr)
    except FileNotFoundError:
        res["missing"] = True
        res["err"] = "命令不存在"
    except subprocess.TimeoutExpired as exc:
        res["timed_out"] = True
        res["out"] = _decode_bytes(exc.stdout)
        res["err"] = _decode_bytes(exc.stderr) or "超时"
    except Exception as exc:  # noqa: BLE001
        res["err"] = str(exc)
    low = (res["err"] or "").lower()
    if any(k in low for k in _DENY_WORDS):
        res["denied"] = True
    return res


def _sys_glob(pattern):
    """只读 sysfs / dev 探测。"""
    try:
        return sorted(glob.glob(pattern))
    except Exception:  # noqa: BLE001
        return []


def _usb_hit(vid, pid):
    """纯判定：vid/pid（不带 0x、大小写不敏感）是否在白名单。"""
    v = str(vid or "").lower().replace("0x", "").zfill(4)
    p = str(pid or "").lower().replace("0x", "").zfill(4)
    for wv, wp, name, kind in RADIO_USB_WHITELIST:
        if v == wv and p == wp:
            return {"vid_pid": f"{wv}:{wp}", "name": name, "kind": kind}
    return None


def _usb_whitelist_hits(text):
    """从 lsusb / sysfs / PnP ID 文本里匹配白名单（去重，保持稳定顺序）。"""
    t = (text or "").lower()
    hits = []
    if not t:
        return hits
    for vid, pid, name, kind in RADIO_USB_WHITELIST:
        # 接受 lsusb 的 `0bda:2838`、sysfs 的 `0bda_2838`、PnP 的 `VID_0BDA&PID_2838`
        if (f"{vid}:{pid}" in t or f"{vid}_{pid}" in t
                or f"vid_{vid}&pid_{pid}" in t):
            hits.append({"vid_pid": f"{vid}:{pid}", "name": name, "kind": kind})
    return hits


def _parse_iw_dev(text):
    """`iw dev` → [{iface, type}]。"""
    ifaces, cur = [], None
    for line in (text or "").splitlines():
        m = re.match(r"\s*Interface\s+(\S+)", line)
        if m:
            cur = {"iface": m.group(1), "type": ""}
            ifaces.append(cur)
            continue
        m = re.match(r"\s*type\s+(\S+)", line)
        if m and cur is not None:
            cur["type"] = m.group(1).lower()
    return ifaces


def _parse_iw_list_monitor(text):
    """`iw list` 的 Supported interface modes 段是否包含 monitor。

    返回 True/False；找不到该段返回 None（不等于不支持）。
    """
    t = text or ""
    key = "Supported interface modes"
    if key not in t:
        return None
    seg = t.split(key, 1)[1]
    modes, started = [], False
    for line in seg.splitlines():
        s = line.strip()
        if s.startswith("*"):
            started = True
            modes.append(s.lstrip("* ").strip().lower())
        elif started and s:
            break
    if not modes:
        return None
    return "monitor" in modes


def _parse_iwconfig(text):
    """`iwconfig` 回退：取接口名；Mode:Monitor 直接算 monitor 可用。"""
    ifaces, cur = [], None
    for line in (text or "").splitlines():
        if not line or line[0].isspace():
            if cur is not None and "mode:monitor" in line.lower():
                cur["monitor"] = True
            continue
        m = re.match(r"(\S+)\s+(.*)", line)
        if not m:
            continue
        if "ieee 802.11" in m.group(2).lower() or "no wireless extensions" in m.group(2).lower():
            cur = {"iface": m.group(1), "type": "", "monitor": False}
            ifaces.append(cur)
        else:
            cur = None
    return ifaces


def _parse_hciconfig(text):
    """`hciconfig -a` → 适配器名列表。"""
    names = []
    for line in (text or "").splitlines():
        m = re.match(r"(hci\d+):", line.strip())
        if m and m.group(1) not in names:
            names.append(m.group(1))
    return names


def _parse_netsh_wlan(text):
    """`netsh wlan show interfaces` → {present, iface, reason}（只读查询）。"""
    t = text or ""
    low = t.lower()
    dead = ("no wireless interface", "there is no wireless interface",
            "没有无线", "无线自动配置服务", "wlansvc", "not running", "未运行", "未启动")
    if any(k in low for k in dead) and "ssid" not in low:
        return {"present": False, "iface": "", "reason": "netsh 报告无无线接口或 WLAN 服务未运行"}
    m = re.search(r"(?im)^\s*(?:name|名称)\s*:\s*(\S.*)$", t)
    iface = m.group(1).strip() if m else ""
    present = bool(iface) or "ssid" in low or "radio types" in low or "无线电类型" in t
    return {"present": present, "iface": iface,
            "reason": "" if present else "netsh 无有效无线接口行"}


def _parse_ps_json(text):
    """PowerShell ConvertTo-Json 输出 → dict（容忍前置噪声/警告）。"""
    t = (text or "").strip()
    if not t:
        return {}
    i, j = t.find("{"), t.rfind("}")
    if i < 0 or j <= i:
        return {}
    try:
        obj = json.loads(t[i:j + 1])
        return obj if isinstance(obj, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _as_list(v):
    if isinstance(v, list):
        return v
    if isinstance(v, dict):
        return [v]
    return []


def _looks_wireless(*texts):
    blob = " ".join(str(t or "") for t in texts).lower()
    if "bluetooth" in blob or "蓝牙" in blob:
        return False
    return any(w in blob for w in _WIFI_WORDS)


def _parse_ioreg_usb(text):
    """macOS `ioreg -p IOUSB -l` → 白名单命中（idVendor/idProduct 是十进制）。"""
    hits = []
    for block in re.split(r"\+-o ", text or ""):
        mv = re.search(r'"idVendor"\s*=\s*(\d+)', block)
        mp = re.search(r'"idProduct"\s*=\s*(\d+)', block)
        if not (mv and mp):
            continue
        hit = _usb_hit(f"{int(mv.group(1)):04x}", f"{int(mp.group(1)):04x}")
        if hit and hit not in hits:
            hits.append(hit)
    return hits


def _absorb_usb_hits(hits, wifi, subghz, nfc):
    """白名单命中分流：wifi-monitor → wifi.adapters；nfc → nfc；其余 → subghz。"""
    for h in hits or []:
        kind = h.get("kind")
        if kind == "wifi-monitor":
            label = f"{h['name']} [{h['vid_pid']}]"
            if label not in wifi["adapters"]:
                wifi["adapters"].append(label)
            wifi["present"] = True
            continue
        item = {"vid_pid": h["vid_pid"], "name": h["name"],
                "kind": kind, "present": True}
        bucket = nfc if kind == "nfc" else subghz
        if item not in bucket:
            bucket.append(item)


def _radio_inventory(wifi, bluetooth, subghz, nfc):
    mc = wifi.get("monitor_capable")
    mc_txt = "可 monitor" if mc is True else ("不可 monitor" if mc is False else "monitor 未判定")
    bits = [f"wifi={'有' if wifi.get('present') else '无'}({mc_txt}"
            f"{', iface=' + wifi['iface'] if wifi.get('iface') else ''})",
            f"bluetooth={'有' if bluetooth.get('present') else '无'}"]
    if subghz:
        bits.append("subghz=" + ", ".join(f"{x['name']}[{x['vid_pid']}]" for x in subghz))
    else:
        bits.append("subghz=无")
    bits.append("nfc=" + (", ".join(f"{x['name']}[{x['vid_pid']}]" for x in nfc) if nfc else "无"))
    return "；".join(bits)


def _decide_radio(wifi, bluetooth, subghz, nfc, flags=None):
    """纯判定函数：返回 (status, blocked_at, reason)。

    flags 可含 missing / denied / timeout。优先级：能力结论 > 枚举失败类型。
    """
    flags = flags or {}
    mc = wifi.get("monitor_capable")
    inv = _radio_inventory(wifi, bluetooth, subghz, nfc)
    others = bool(bluetooth.get("present")) or bool(subghz) or bool(nfc)

    if mc is True:
        return "ok", None, (
            f"WiFi 支持 monitor mode（{inv}）：802.11 抓包/握手路线可用。"
            "本探针只读枚举，未切换模式、未抓包、未发射频。")
    if wifi.get("present"):
        if mc is False:
            return ("partial" if others else "blocked"), "no-monitor-mode", (
                f"有 WiFi 适配器，但当前平台/驱动不提供 monitor mode（{inv}）："
                "Windows 原生 NDIS 驱动不向用户态暴露 monitor；需外置可 monitor 网卡"
                "（AR9271/RTL8812AU/MT7612U 等）+ Linux 侧或专用驱动。"
                "探针未尝试切换模式；无线章相关判据记 blocked_at=no-monitor-mode。")
        return "partial", "monitor-unverified", (
            f"有 WiFi 适配器，但当前枚举手段无法判定 monitor 能力（{inv}）："
            "Linux 装 iw 后重跑 `--radio-only`，或换外置可 monitor 网卡。"
            "未判定 ≠ 不支持，不能直接写成结论。")
    if others:
        return "partial", "no-wifi", (
            f"未发现 WiFi 适配器，但存在其它射频/近场硬件（{inv}）："
            "BLE/802.15.4/sub-GHz/NFC 路线可评估，802.11 相关判据记 blocked_at=no-wifi。")
    if flags.get("timeout"):
        return "blocked", "timeout", (
            "10s 预算内未完成枚举：拆开重跑或降低系统负载后重试；"
            "此时不能写“无硬件”，只记 blocked_at=timeout。")
    if flags.get("denied"):
        return "blocked", "no-permission", (
            "枚举命令存在但被拒绝（需 root/管理员）：用提权会话重跑 `--radio-only`；"
            "探针本身仍只做只读枚举，不做任何模式切换。")
    if flags.get("missing"):
        return "blocked", "command-missing", (
            "平台枚举命令缺失（iw/iwconfig/hciconfig/lsusb 等）：装 iproute2+iw+usbutils+bluez"
            "（或 Windows 用 netsh/PowerShell）后重跑；缺命令不能当成无硬件。")
    if flags.get("error"):
        return "blocked", "probe-error", (
            f"探针内部异常：{flags.get('error')}；已采集字段仍保留，看 commands/evidence 排查。"
            "这不代表目标不能分析，也不代表本机无无线硬件。")
    return "blocked", "no-radio", (
        f"未发现任何无线/近场硬件（{inv}）：无线章所有判据记 blocked_at=no-radio，"
        "改走固件侧/有线侧或外接适配器后再验证。")


_PS_ENUM = r"""
$ErrorActionPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$r = [ordered]@{}
$n = @()
$n = Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction SilentlyContinue |
  Where-Object { $_.PhysicalAdapter -eq $true } |
  ForEach-Object { [ordered]@{ name = "$($_.Name)"; net = "$($_.NetConnectionID)"; mac = "$($_.MACAddress)"; pnp = "$($_.PNPDeviceID)"; type = "$($_.AdapterType)" } }
$r.nics = @($n)
$p = @()
$p = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
  Where-Object { $_.PNPDeviceID -like 'USB\*' -or $_.PNPDeviceID -like 'BTH\*' -or $_.PNPDeviceID -like 'PCI\*' } |
  ForEach-Object { [ordered]@{ name = "$($_.Name)"; id = "$($_.PNPDeviceID)"; class = "$($_.Class)"; status = "$($_.Status)" } }
$r.pnp = @($p)
$r | ConvertTo-Json -Depth 5 -Compress
"""


def _run_powershell(script_text, timeout, tmpdir):
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return None
    path = os.path.join(tmpdir or tempfile.gettempdir(), "seep_radio_enum.ps1")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(script_text)
    except Exception:  # noqa: BLE001
        return None
    return _run_cmd([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                     "-File", path], timeout)


def _log_cmd(cmds, r, flags):
    cmds.append({"cmd": r["cmd"], "rc": r["rc"], "timed_out": r["timed_out"],
                 "missing": r["missing"], "denied": r["denied"]})
    if r["missing"]:
        flags["missing"] = True
    if r["denied"]:
        flags["denied"] = True
    if r["timed_out"]:
        flags["timeout"] = True


def _radio_windows(deadline, tmpdir, wifi, bluetooth, subghz, nfc, notes, cmds, flags):
    def left(reserve=0.2):
        return max(0.0, deadline - time.monotonic() - reserve)

    # 1) netsh：只查当前接口状态，不触发扫描
    r = _run_cmd(["netsh", "wlan", "show", "interfaces"], min(3.0, left()))
    _log_cmd(cmds, r, flags)
    nw = _parse_netsh_wlan(r["out"])
    if nw["present"]:
        wifi["present"] = True
        wifi["iface"] = nw["iface"] or wifi["iface"]
    else:
        notes.append("netsh wlan: " + (nw["reason"] or "未报告无线接口"))

    # 2) PowerShell 一次拿全：网卡 / PnP（USB/BTH/PCI）
    pr = _run_powershell(_PS_ENUM, min(6.0, left()), tmpdir)
    data = {}
    if pr is None:
        notes.append("未发现 powershell/pwsh：USB/BT 枚举降级")
        flags["missing"] = True
    else:
        _log_cmd(cmds, pr, flags)
        data = _parse_ps_json(pr["out"])
        if not data:
            notes.append("PowerShell 枚举无可用 JSON（Get-CimInstance 可能不可用）")

    nics, pnp = _as_list(data.get("nics")), _as_list(data.get("pnp"))
    # 网卡：名字/类型命中无线关键词即视为 WiFi 适配器
    for n in nics:
        name, net = str(n.get("name", "")), str(n.get("net", ""))
        if "virtual" in name.lower() or "wi-fi direct" in name.lower() or "虚拟" in name:
            continue
        if _looks_wireless(name, n.get("type", "")):
            wifi["present"] = True
            label = f"{name}（{net}）" if net else name
            if label not in wifi["adapters"]:
                wifi["adapters"].append(label)
            if not wifi["iface"] and net:
                wifi["iface"] = net
    # PnP：蓝牙适配器 + USB 白名单
    bt_adapters, usb_blob = [], []
    for e in pnp:
        name, pid, cls = str(e.get("name", "")), str(e.get("id", "")), str(e.get("class", ""))
        if cls.lower() == "bluetooth" or pid.upper().startswith("BTH\\") or any(w in name.lower() for w in _BT_WORDS):
            low_name = name.lower()
            is_service = any(w in low_name for w in _BT_SERVICE_WORDS)
            if name and not is_service and name not in bt_adapters:
                bt_adapters.append(name)
        if pid:
            usb_blob.append(pid)
        if name:
            usb_blob.append(name)
    bluetooth["adapters"] = bt_adapters
    bluetooth["present"] = bool(bt_adapters)
    sysroot = os.environ.get("SystemRoot") or r"C:\Windows"
    cpl = os.path.join(sysroot, "System32", "bthprops.cpl")
    bluetooth["stack"] = {"bthprops_cpl": os.path.isfile(cpl),
                          "pnp_bluetooth": bool(bt_adapters),
                          "source": "Get-CimInstance Win32_PnPEntity"}
    if not bluetooth["present"] and bluetooth["stack"]["bthprops_cpl"]:
        notes.append("bthprops.cpl 在场只说明蓝牙控制面板文件存在，不等于有适配器；未计为 present")

    hits = _usb_whitelist_hits(" ".join(usb_blob))
    _absorb_usb_hits(hits, wifi, subghz, nfc)
    if not hits:
        notes.append("USB 白名单（RTL-SDR/HackRF/CC2531/nRF52/Proxmark3 等）未命中")

    # 3) monitor 判定（Windows 不做任何模式切换）
    if any(h.get("kind") == "wifi-monitor" for h in hits):
        wifi["monitor_capable"] = None
        notes.append("发现疑似可 monitor 的外置网卡，但 Windows 需 Npcap/专用驱动；"
                     "探针不切换模式，monitor_capable 记 null")
    elif wifi["present"]:
        wifi["monitor_capable"] = False
        notes.append("Windows 原生 NDIS 驱动不向用户态暴露 monitor mode")


def _radio_linux(deadline, wifi, bluetooth, subghz, nfc, notes, cmds, flags):
    def left(reserve=0.2):
        return max(0.0, deadline - time.monotonic() - reserve)

    def run(cmd, t):
        r = _run_cmd(cmd, min(t, left()))
        _log_cmd(cmds, r, flags)
        return r

    # WiFi：sysfs（无需命令）+ iw dev / iwconfig 回退
    sys_ieee = _sys_glob("/sys/class/ieee80211/*")
    sys_wireless = _sys_glob("/sys/class/net/*/wireless")
    sys_phy = _sys_glob("/sys/class/net/*/phy80211")
    r = run(["iw", "dev"], 2.0)
    ifaces = _parse_iw_dev(r["out"]) if not r["missing"] else []
    if not ifaces and r["missing"]:
        r2 = run(["iwconfig"], 2.0)
        ifaces = _parse_iwconfig(r2["out"])
        if ifaces:
            notes.append("iw 缺失，退回 iwconfig（只能看 Mode:Monitor，无法判定能力位）")
            if any(i.get("monitor") for i in ifaces):
                wifi["monitor_capable"] = True
    names = [i["iface"] for i in ifaces]
    if not names:
        names = [os.path.basename(os.path.dirname(p)) for p in sys_wireless + sys_phy]
    wifi["present"] = bool(names) or bool(sys_ieee)
    if names:
        wifi["iface"] = names[0]
        wifi["adapters"] = names
    if wifi["present"] and not r["missing"]:
        rl = run(["iw", "list"], 2.5)
        mc = _parse_iw_list_monitor(rl["out"])
        if mc is not None:
            wifi["monitor_capable"] = mc
            if not mc:
                notes.append("iw list 的 Supported interface modes 不含 monitor")

    # 蓝牙：hciconfig，回退 sysfs
    rb = run(["hciconfig", "-a"], 2.0)
    bt_adapters = [] if rb["missing"] else _parse_hciconfig(rb["out"])
    sys_bt = _sys_glob("/sys/class/bluetooth/*")
    if not bt_adapters and sys_bt:
        bt_adapters = [os.path.basename(p) for p in sys_bt]
    bluetooth["adapters"] = bt_adapters
    bluetooth["present"] = bool(bt_adapters)
    bluetooth["stack"] = {"hciconfig": not rb["missing"],
                          "sysfs_bluetooth": bool(sys_bt),
                          "source": "hciconfig/sysfs"}

    # USB 白名单：lsusb，回退 /sys/bus/usb/devices
    ru = run(["lsusb"], 2.0)
    if ru["missing"] or not ru["out"]:
        ids = []
        for d in _sys_glob("/sys/bus/usb/devices/*"):
            try:
                v = Path(d, "idVendor").read_text(encoding="utf-8", errors="replace").strip()
                p = Path(d, "idProduct").read_text(encoding="utf-8", errors="replace").strip()
                ids.append(f"{v}:{p}")
            except Exception:  # noqa: BLE001
                continue
        hits = _usb_whitelist_hits(" ".join(ids))
        if ru["missing"]:
            notes.append("lsusb 缺失，改用 /sys/bus/usb/devices 只读枚举")
    else:
        hits = _usb_whitelist_hits(ru["out"])
    _absorb_usb_hits(hits, wifi, subghz, nfc)
    if not hits:
        notes.append("USB 白名单未命中（RTL-SDR/HackRF/CC2531/nRF52/Proxmark3 等）")

    # NFC：设备节点 + pcscd 套接字（都不触发读卡/射频）
    nfc_dev = _sys_glob("/dev/nfc*")
    pcsc = any(os.path.exists(p) for p in ("/run/pcscd/pcscd.comm",
                                           "/var/run/pcscd/pcscd.comm"))
    if nfc_dev or pcsc:
        notes.append(f"NFC 侧：/dev/nfc*={len(nfc_dev)}，pcscd={pcsc}（未调用读卡器）")

    if wifi["monitor_capable"] is None and wifi["present"] and \
            any(h.get("kind") == "wifi-monitor" for h in hits):
        wifi["monitor_capable"] = True
        notes.append("外置可 monitor 网卡（白名单芯片）在场；驱动未加载时仍需确认")


def _radio_macos(deadline, wifi, bluetooth, subghz, nfc, notes, cmds, flags):
    def left(reserve=0.2):
        return max(0.0, deadline - time.monotonic() - reserve)

    def run(cmd, t):
        r = _run_cmd(cmd, min(t, left()))
        _log_cmd(cmds, r, flags)
        return r

    r = run(["networksetup", "-listallhardwareports"], 2.5)
    ifaces = []
    cur_port = ""
    for line in (r["out"] or "").splitlines():
        m = re.match(r"\s*Hardware Port:\s*(.+)", line)
        if m:
            cur_port = m.group(1).strip()
            continue
        m = re.match(r"\s*Device:\s*(\S+)", line)
        if m and _looks_wireless(cur_port):
            ifaces.append(m.group(1))
    wifi["present"] = bool(ifaces)
    if ifaces:
        wifi["iface"] = ifaces[0]
        wifi["adapters"] = ifaces
        wifi["monitor_capable"] = None
        notes.append("macOS 原生用户态不直接提供 monitor 能力判定（airport 已受限）；"
                     "探针不切换模式，monitor_capable 记 null")

    rb = run(["system_profiler", "SPBluetoothDataType"], 3.0)
    low = (rb["out"] or "").lower()
    bt_present = "bluetooth controller" in low or "bluetooth power" in low or "蓝牙控制器" in (rb["out"] or "")
    bluetooth["present"] = bool(bt_present)
    bluetooth["adapters"] = []
    bluetooth["stack"] = {"system_profiler": not rb["missing"], "source": "SPBluetoothDataType"}

    ru = run(["ioreg", "-p", "IOUSB", "-w0", "-l"], 3.0)
    hits = _parse_ioreg_usb(ru["out"]) if not ru["missing"] else []
    _absorb_usb_hits(hits, wifi, subghz, nfc)
    if not hits:
        notes.append("USB 白名单未命中（ioreg IOUSB）")


def probe_radio(ctx):
    """只读枚举本机无线/近场能力。绝不切换模式、绝不发射频。"""
    t0 = time.monotonic()
    budget = min(RADIO_BUDGET, getattr(ctx, "remaining", lambda: RADIO_BUDGET)() or RADIO_BUDGET)
    deadline = t0 + max(1.0, budget)
    tmpdir = getattr(ctx, "tmpdir", None)
    owns_tmp = False
    if not tmpdir:
        tmpdir = tempfile.mkdtemp(prefix="seep_radio_")
        owns_tmp = True

    wifi = {"present": False, "monitor_capable": None, "iface": "", "adapters": []}
    bluetooth = {"present": False, "adapters": [], "stack": {}}
    subghz, nfc = [], []
    notes, cmds, flags = [], [], {}
    try:
        try:
            if sys.platform == "win32":
                _radio_windows(deadline, tmpdir, wifi, bluetooth, subghz, nfc, notes, cmds, flags)
            elif sys.platform == "darwin":
                _radio_macos(deadline, wifi, bluetooth, subghz, nfc, notes, cmds, flags)
            else:
                _radio_linux(deadline, wifi, bluetooth, subghz, nfc, notes, cmds, flags)
        except Exception as exc:  # noqa: BLE001
            # 平台枚举自身异常：保留已采集字段，显式标记，不穿透
            flags["error"] = str(exc)
            notes.append(f"枚举异常（已降级）：{exc}")

        status, blocked_at, reason = _decide_radio(wifi, bluetooth, subghz, nfc, flags)
        if flags.get("error") and blocked_at is None:
            status = "partial"
        elapsed = time.monotonic() - t0
        evidence = (f"platform={sys.platform}；{_radio_inventory(wifi, bluetooth, subghz, nfc)}；"
                    f"{elapsed:.1f}s 只读枚举（未进 monitor、未发射频）")
        if notes:
            evidence += "；" + "；".join(notes[:4])
        return {
            "name": "radio", "status": status, "evidence": evidence, "note": reason,
            "wifi": wifi, "bluetooth": bluetooth, "subghz": subghz, "nfc": nfc,
            "blocked_at": blocked_at, "reason": reason,
            "read_only": True, "platform": sys.platform,
            "elapsed_s": round(elapsed, 2),
            "commands": cmds,
        }
    finally:
        if owns_tmp:
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


class RadioContext:
    """radio-only 模式的轻量上下文：不需要 target，只需要 10s 预算和临时目录。"""

    def __init__(self):
        self.target = ""
        self.quick = False
        self.start = time.monotonic()
        self.total_budget = RADIO_BUDGET
        self.deadline = self.start + RADIO_BUDGET
        self.meta = {}
        self.proc = None
        self.pid = None
        self.tmpdir = tempfile.mkdtemp(prefix="seep_radio_")

    def remaining(self):
        return max(0.0, self.deadline - time.monotonic())

    def probe_timeout(self):
        return max(0.0, min(RADIO_BUDGET, self.remaining()))


def _self_test():
    """只测判定/解析函数：不枚举硬件、不起子进程、不发任何射频。"""
    checks = []

    def ck(name, cond, detail=""):
        checks.append({"name": name, "ok": bool(cond), "detail": detail})

    hits = _usb_whitelist_hits("Bus 001 Device 004: ID 0bda:2838 Realtek RTL2838 DVB-T")
    ck("lsusb 命中 RTL-SDR", any(h["vid_pid"] == "0bda:2838" for h in hits), str(hits))
    hits = _usb_whitelist_hits(r"USB\VID_1D50&PID_6089\0000000000")
    ck("PnP ID 命中 HackRF", any(h["vid_pid"] == "1d50:6089" for h in hits), str(hits))
    hits = _usb_whitelist_hits("0451:16a8")
    ck("CC2531 白名单命中", any(h["kind"] == "ieee802154" for h in hits), str(hits))
    hits = _usb_whitelist_hits("9ac4:4b8f")
    ck("Proxmark3 归到 nfc", any(h["kind"] == "nfc" for h in hits), str(hits))
    ck("无关设备不误报", _usb_whitelist_hits(
        "Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub") == [])
    ck("空文本不误报", _usb_whitelist_hits("") == [])

    ck("iw list 有 monitor", _parse_iw_list_monitor(
        "\tSupported interface modes:\n\t\t * IBSS\n\t\t * monitor\n\t\t * managed\n") is True)
    ck("iw list 无 monitor", _parse_iw_list_monitor(
        "\tSupported interface modes:\n\t\t * managed\n\t\t * AP\n") is False)
    ck("iw list 缺段 → None", _parse_iw_list_monitor("no modes here") is None)
    ifs = _parse_iw_dev("phy#0\n\tInterface wlan0\n\t\tifindex 3\n\t\ttype managed\n")
    ck("iw dev 解析 iface/type",
       bool(ifs) and ifs[0]["iface"] == "wlan0" and ifs[0]["type"] == "managed", str(ifs))
    ifc = _parse_iwconfig("wlan0     IEEE 802.11  ESSID:off/any\n          Mode:Monitor  Tx-Power=20 dBm\n")
    ck("iwconfig 解析 + Mode:Monitor",
       bool(ifc) and ifc[0]["iface"] == "wlan0" and ifc[0]["monitor"] is True, str(ifc))
    hci = _parse_hciconfig("hci0:   Type: Primary  Bus: USB\n\tBD Address: 00:11:22:33:44:55\n")
    ck("hciconfig 解析 hci0", hci == ["hci0"], str(hci))

    nw = _parse_netsh_wlan("Name                   : WLAN\nSSID                   : Lab\n"
                           "State                  : connected\n")
    ck("netsh 解析无线接口", nw["present"] and nw["iface"] == "WLAN", str(nw))
    nw = _parse_netsh_wlan("There is no wireless interface on the system.\n")
    ck("netsh 无接口 → present=False", nw["present"] is False, str(nw))

    st, ba, rs = _decide_radio(
        {"present": True, "monitor_capable": True, "iface": "wlan0", "adapters": []},
        {"present": False}, [], [])
    ck("monitor 可用 → ok / blocked_at=null", st == "ok" and ba is None, f"{st}/{ba} {rs[:20]}")
    st, ba, _ = _decide_radio(
        {"present": True, "monitor_capable": False, "iface": "WLAN", "adapters": []},
        {"present": False}, [], [])
    ck("有网卡无 monitor → no-monitor-mode", st == "blocked" and ba == "no-monitor-mode", f"{st}/{ba}")
    st, ba, _ = _decide_radio(
        {"present": True, "monitor_capable": None, "iface": "en0", "adapters": []},
        {"present": False}, [], [])
    ck("monitor 未判定 → monitor-unverified", st == "partial" and ba == "monitor-unverified", f"{st}/{ba}")
    st, ba, _ = _decide_radio(
        {"present": False, "monitor_capable": None, "iface": "", "adapters": []},
        {"present": False}, [], [])
    ck("无硬件 → no-radio / blocked", st == "blocked" and ba == "no-radio", f"{st}/{ba}")
    st, ba, _ = _decide_radio(
        {"present": False, "monitor_capable": None, "iface": "", "adapters": []},
        {"present": True}, [{"vid_pid": "0bda:2838", "name": "RTL-SDR"}], [])
    ck("只有 SDR → no-wifi / partial", st == "partial" and ba == "no-wifi", f"{st}/{ba}")
    st, ba, _ = _decide_radio(
        {"present": True, "monitor_capable": False, "iface": "WLAN", "adapters": []},
        {"present": True}, [], [])
    ck("网卡无 monitor 但有 BT → partial + no-monitor-mode",
       st == "partial" and ba == "no-monitor-mode", f"{st}/{ba}")
    st, ba, _ = _decide_radio(
        {"present": False, "monitor_capable": None, "iface": "", "adapters": []},
        {"present": False}, [], [], {"missing": True})
    ck("缺命令 → command-missing", ba == "command-missing", str(ba))
    st, ba, _ = _decide_radio(
        {"present": False, "monitor_capable": None, "iface": "", "adapters": []},
        {"present": False}, [], [], {"denied": True})
    ck("缺权限 → no-permission", ba == "no-permission", str(ba))
    st, ba, _ = _decide_radio(
        {"present": False, "monitor_capable": None, "iface": "", "adapters": []},
        {"present": False}, [], [], {"timeout": True})
    ck("超时 → timeout", ba == "timeout", str(ba))
    st, ba, _ = _decide_radio(
        {"present": False, "monitor_capable": None, "iface": "", "adapters": []},
        {"present": False}, [], [], {"error": "boom"})
    ck("内部异常 → probe-error", ba == "probe-error", str(ba))

    # 只读断言：文件里不得出现会切模式/发射频的命令（字符串拼接避免自命中）
    src = Path(__file__).read_text(encoding="utf-8", errors="replace")
    banned = ["airmon" + "-ng", "aireplay" + "-ng", "Wlan" + "Scan",
              "hackrf" + "_transfer", "iwconfig" + " monitor"]
    found = [b for b in banned if b in src]
    ck("radio 探针不含切模式/发射频命令", not found, ",".join(found))

    ok = all(c["ok"] for c in checks)
    _out(json.dumps({"ok": ok, "checks": checks}, ensure_ascii=False, indent=2))
    return 0 if ok else 1


def _run_probe(name, fn, ctx):
    if ctx.remaining() < 2:
        total = getattr(ctx, "total_budget", TOTAL_BUDGET)
        return _status(name, "blocked", f"整体 {total}s 预算耗尽，该探针未执行",
                       "不是静默跳过：预算到点会显式记录；可拆成多次运行或加 --quick；"
                       "radio 可单独跑 --radio-only")
    t0 = time.monotonic()
    try:
        return fn(ctx)
    except Exception as exc:
        return _status(name, "blocked", f"探针异常：{exc}",
                       "探针自身失败，不代表目标不可分析；查异常后重跑或换外部手段")
    finally:
        _ = time.monotonic() - t0


def _build_payload(target, probes, ctx, extra_meta=None):
    meta = {
        "arch": (ctx.meta or {}).get("arch"),
        "is_dll": (ctx.meta or {}).get("is_dll"),
        "entry_rva": (ctx.meta or {}).get("entry_rva"),
        "size_of_image": (ctx.meta or {}).get("size_of_image"),
        "quick": bool(getattr(ctx, "quick", False)),
        "elapsed_s": round(time.monotonic() - ctx.start, 1),
        "budget_s": getattr(ctx, "total_budget", TOTAL_BUDGET),
        "per_probe_timeout_s": PER_PROBE_TIMEOUT,
    }
    if extra_meta:
        meta.update(extra_meta)
    return {
        "target": target,
        "sha256": _sha256(target) if target else None,
        "probes": probes,
        "meta": meta,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="probe_matrix.py",
        description=("脱壳/反调试仪器探针矩阵：baseline / x64dbg / frida-spawn / frida-attach / "
                     "external / network / radio"),
        epilog=("示例：python Tool/scripts/probe_matrix.py --target <exe> --json；"
                "仅查无线能力：python Tool/scripts/probe_matrix.py --radio-only --json"))
    parser.add_argument("--target", help="目标 PE（exe/dll）路径；--radio-only 时可省略")
    parser.add_argument("--json", action="store_true", help="打印 JSON 到 stdout")
    parser.add_argument("--out", help="把 JSON 写到指定文件")
    parser.add_argument("--quick", action="store_true", help="只做 baseline + external（更快）")
    parser.add_argument("--radio-only", action="store_true",
                        help="只做 radio 探针（WiFi/蓝牙/SDR/802.15.4/NFC 只读能力枚举，≤10s）")
    parser.add_argument("--self-test", action="store_true",
                        help="只测 radio 的判定/解析函数（不碰硬件、不起子进程）")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    target = None
    if args.target:
        target = os.path.abspath(os.path.expanduser(args.target))
        if not os.path.isfile(target):
            _out(f"[ERR] 目标不存在：{target}")
            return 2
    if target is None and not args.radio_only:
        _out("[ERR] 需要 --target；只想看本机无线/近场能力用 --radio-only（不需要目标）")
        return 2

    # --radio-only：只跑 radio，不需要目标，也不碰任何靶机进程
    if args.radio_only:
        ctx = RadioContext()
        try:
            result = _run_probe("radio", probe_radio, ctx)
        finally:
            shutil.rmtree(ctx.tmpdir, ignore_errors=True)
        payload = _build_payload(target, [result], ctx, {"radio_only": True})
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
            _out(f"radio: {result['status']} blocked_at={result['blocked_at']}")
            _out(f"  evidence: {result['evidence']}")
            _out(f"  reason:   {result['reason']}")
        return 0

    ctx = ProbeContext(target, args.quick)
    results = {}

    # 先跑 baseline，后续 external/attach/network 复用其进程
    results["baseline"] = _run_probe("baseline", probe_baseline, ctx)
    if not args.quick:
        # 外部读/网络尽早做，避免后续 GUI 探针拖太久导致 baseline 已退出
        results["external"] = _run_probe("external", probe_external, ctx)
        results["network"] = _run_probe("network", probe_network, ctx)
        # radio 与目标无关，但会让目标多存活 10s；放在网络观察之后
        results["radio"] = _run_probe("radio", probe_radio, ctx)
        results["frida-attach"] = _run_probe("frida-attach", probe_frida_attach, ctx)
        results["frida-spawn"] = _run_probe("frida-spawn", probe_frida_spawn, ctx)
        results["x64dbg"] = _run_probe("x64dbg", probe_x64dbg, ctx)
    else:
        results["external"] = _run_probe("external", probe_external, ctx)

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
    payload = _build_payload(target, probes, ctx)

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
            if p.get("blocked_at"):
                _out(f"  blocked_at: {p['blocked_at']}")
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
