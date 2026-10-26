#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
seep - AI-Native Reverse Engineering & Security Analysis MCP Server
整合 Radare2 跨架构二进制逆向、JADX/Apktool/Smali 安卓逆向、
动态 Hook 生成以及 ReverseLab 183+ 攻防知识库与 CTF 战术模板。
"""

import os
import sys
import json
import re
import glob
import shutil
import signal
import zipfile
import hashlib
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    from mcp.server.fastmcp import FastMCP as MCPServer

# ---------------------------------------------------------------------------
# 基础路径定义与环境初始化
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOL_DIR = os.path.join(BASE_DIR, "Tool")
SAFE_DIR = os.path.join(TOOL_DIR, "safe")
R2_BIN_DIR = os.path.join(SAFE_DIR, "radare2", "bin")

def _resolve_binary(tool_name: str) -> str:
    """跨平台解析可执行工具路径（Windows 优先内置 exe，Linux/macOS 优先查找系统 PATH，fallback 回内置）"""
    exe_name = f"{tool_name}.exe" if sys.platform == "win32" else tool_name
    built_in = os.path.join(R2_BIN_DIR, exe_name)
    if os.path.isfile(built_in) and (sys.platform == "win32" or os.access(built_in, os.X_OK)):
        return built_in
    which_path = shutil.which(tool_name)
    if which_path:
        return which_path
    return built_in

R2_EXE = _resolve_binary("radare2")
RABIN2_EXE = _resolve_binary("rabin2")
RADIFF2_EXE = _resolve_binary("radiff2")
RASM2_EXE = _resolve_binary("rasm2")
RAHASH2_EXE = _resolve_binary("rahash2")

def _resolve_jadx() -> str:
    """跨平台解析 JADX 启动脚本"""
    if sys.platform == "win32":
        bat = os.path.join(SAFE_DIR, "jadx", "bin", "jadx.bat")
        return bat if os.path.isfile(bat) else (shutil.which("jadx") or bat)
    else:
        sh = os.path.join(SAFE_DIR, "jadx", "bin", "jadx")
        return sh if os.path.isfile(sh) else (shutil.which("jadx") or sh)

JADX_BAT = _resolve_jadx()
APKTOOL_JAR = os.path.join(SAFE_DIR, "apktool", "apktool.jar")
APKTOOL_BAT = os.path.join(SAFE_DIR, "apktool", "apktool.bat" if sys.platform == "win32" else "apktool")

KB_DIR = os.path.join(TOOL_DIR, "reverselab", "kb")
LLMS_TXT = os.path.join(TOOL_DIR, "reverselab", "docs", "llms.txt")
HOOK_TEMPLATES_DIR = os.path.join(SAFE_DIR, "hook-mcp", "templates")

# 将 r2 bin 目录添加到 PATH 中，确保子进程加载依赖 dll
if os.path.isdir(R2_BIN_DIR) and R2_BIN_DIR not in os.environ.get("PATH", ""):
    os.environ["PATH"] = R2_BIN_DIR + os.pathsep + os.environ.get("PATH", "")


# ---------------------------------------------------------------------------
# 路径参数别名层（2026-10-22 审计 P0：工具间 target_path / binary_path 命名不一致
# 曾导致模型在 184 次调用里改用 bash 手搓 strings/pefile）
#
# 契约：所有吃「一个文件/目录路径」的工具，必须同时接受
#   binary_path / target_path / apk_path / file_path / sample_path /
#   artifact_path / pcap_path / dir_path
# 任一别名，值互通；schema 里全部可见，调用方不必猜。
# ---------------------------------------------------------------------------
_PATH_ALIAS_NAMES = (
    "binary_path", "target_path", "apk_path", "file_path",
    "sample_path", "artifact_path", "pcap_path", "dir_path",
)
_PID_ALIAS_NAMES = (
    "pid_or_name", "process_name", "process", "image_name",
    "binary_path", "target_path", "file_path", "sample_path", "artifact_path",
)


def _has_value(v) -> bool:
    """参数是否「真的传了值」：空串 / 纯空白 / None 都算没传。"""
    return v is not None and (bool(v.strip()) if isinstance(v, str) else True)


def _alias_layer(fn, primary, names, coerce, hint):
    """通用参数别名层：schema 里暴露全部别名，运行期归一到主参数。

    **踩过的坑（P1-8，P0 真 bug）**：FastMCP 的 arg_model 会把 schema 里全部字段
    按默认值一起 dump 下来，所以别名总会以 `""` / `None` 的形态出现在 kwargs 里。
    旧实现只 pop「非空」别名 —— 空串别名原样漏进被包函数，被 Python 判成
    TypeError: unexpected keyword argument 'target_path'，**连正确传主参数名都必挂**。
    所以这里**无条件弹出全部别名**，只把第一个非空值归一成主参数。
    """
    import functools as _ft
    import inspect as _inspect

    sig = _inspect.signature(fn)
    extras = [a for a in names if a not in sig.parameters]
    # 全局转 keyword-only：主参数改成可选后，后面的必填位置参数（如 smali_search 的
    # pattern）会触发 "non-default argument follows default argument"；keyword-only
    # 允许「有默认值在前、无默认值在后」，且 MCP 客户端本来就按名字传参。
    params = [_inspect.Parameter(
        n, _inspect.Parameter.KEYWORD_ONLY,
        default=(None if n == primary and p.default is _inspect.Parameter.empty else p.default),
        annotation=p.annotation) for n, p in sig.parameters.items()]
    params += [_inspect.Parameter(a, _inspect.Parameter.KEYWORD_ONLY, default="", annotation=str)
               for a in extras]
    new_sig = sig.replace(parameters=params)

    @_ft.wraps(fn)
    def wrapper(*args, **kwargs):
        if args:  # 位置传参的老用法，原样透传
            return fn(*args, **kwargs)
        picked = ""
        for alias in extras:
            val = kwargs.pop(alias, "")
            if not picked and _has_value(val):
                picked = val
        if isinstance(kwargs.get(primary), str):
            kwargs[primary] = kwargs[primary].strip()
        if not _has_value(kwargs.get(primary)):
            if not _has_value(picked):
                return (f"[ERROR] {fn.__name__} 缺少{hint}参数："
                        f"{' / '.join([primary] + extras)} 任一即可（别名互通）")
            try:
                kwargs[primary] = coerce(picked)
            except ValueError as exc:  # coerce 失败：回错误正文，不抛异常
                return f"[ERROR] {fn.__name__} {exc}"
        return fn(*args, **kwargs)

    wrapper.__signature__ = new_sig
    wrapper.__annotations__ = {**getattr(fn, "__annotations__", {}), **{a: str for a in extras}}
    wrapper.__doc__ = (
        (fn.__doc__ or "")
        + f"\n\n{hint}参数：{' / '.join([primary] + extras)} 等价，任选其一。"
    )
    # 供门禁自检：运行时真的挂了别名层（而不是只把别名写进 schema）
    wrapper.__seep_alias_primary__ = primary
    wrapper.__seep_alias_names__ = (primary,) + tuple(extras)
    return wrapper


def _path_alias(fn):
    """给「吃一个文件/目录路径」的工具加路径别名能力。"""
    import inspect as _inspect

    primary = next((n for n in _inspect.signature(fn).parameters
                    if n.endswith("_path") or n == "directory" or n.startswith("file_")), None)
    if primary is None:
        return fn
    return _alias_layer(fn, primary, _PATH_ALIAS_NAMES, lambda v: v, "路径")


def _resolve_pid(value):
    """pid / 进程名 / 镜像路径 → pid:int；失败抛 ValueError（错误正文）。只读扫进程表。"""
    if isinstance(value, bool):
        raise ValueError(f"非法目标 {value!r}")
    s = str(value).strip().strip('"').strip("'")
    if s.lstrip("-").isdigit():
        if int(s) <= 0:
            raise ValueError(f"非法 pid={s}")
        return int(s)
    name = re.split(r"[\\/]", s)[-1] or s
    if sys.platform == "win32":
        rows = re.findall(r'^"([^"]+)","(\d+)"',
                          _run_cmd(["tasklist", "/fo", "csv", "/nh"], timeout=25), re.M)
        procs = [(int(pid), img) for img, pid in rows]
    else:
        rows = re.findall(r"^\s*(\d+)\s+(\S+)",
                          _run_cmd(["ps", "-eo", "pid=,comm="], timeout=25), re.M)
        procs = [(int(pid), img) for pid, img in rows]
    hits = ([(p, i) for p, i in procs if i.lower() == name.lower()]
            or [(p, i) for p, i in procs if name.lower() in i.lower()])
    if not hits:
        raise ValueError(f"无法定位目标进程：没有正在运行的进程匹配 {name!r}")
    if len(hits) > 1:
        raise ValueError("无法定位目标进程：%r 命中 %d 个进程，请用 pid 指定：%s" % (
            name, len(hits), ", ".join(f"{i}(pid={p})" for p, i in hits[:8])))
    return hits[0][0]


def _pid_alias(fn, primary: str = "pid"):
    """给「以进程为目标」的工具加别名能力（进程 ID / 进程名 / 镜像路径都可）。"""
    return _alias_layer(fn, primary, _PID_ALIAS_NAMES, _resolve_pid, "目标进程")

# ---------------------------------------------------------------------------
# MCP Server 实例
# ---------------------------------------------------------------------------
server = MCPServer(
    "seep",
    instructions="""seep 是一个专为安全分析师与 AI Agent 设计的全能逆向工程与 CTF 战术 MCP Server。
能力包含：
1. 二进制分析与逆向 (Radare2 / Rabin2 / Radiff2 / Rasm2)
2. Android APK / DEX 反编译、解包与 Smali 检索 (JADX, Apktool)
3. 动态 Hook 插件自动生成 (Frida JS, LSPilot / BeanShell)
4. ReverseLab 183+ 逆向与 Web/PE/CVE 攻防战术知识库检索与即用 Payload
"""
)

# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------
def _run_cmd(cmd: List[str], cwd: Optional[str] = None, timeout: int = 60) -> str:
    """运行外部命令并返回标准输出或捕获错误"""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout
        )
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if proc.returncode != 0 and not out:
            return f"[ERROR code {proc.returncode}]: {err}"
        if out and err:
            return f"{out}\n[STDERR]: {err}"
        return out or err
    except subprocess.TimeoutExpired:
        return f"[ERROR]: Command timed out after {timeout} seconds."
    except Exception as e:
        return f"[ERROR]: Exception executing command: {str(e)}"

def _clean_r2_output(text: str) -> str:
    """移除 ANSI 颜色控制字符"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

# ── 结果契约层（S2-3）：预算/空态/证据筛选/报告模板拆到同目录 seep_contract.py ──
# 拆的理由：主服务单文件 ≤3200 行（BASELINE-FREEZE §7）；模块是纯函数、无 IO、不注册工具。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from seep_contract import (  # noqa: E402
    RESULT_BUDGET_CHARS, budget_gate as _budget_gate, build_report_md,
    case_evidence_dir as _case_evidence_dir, empty_output as _empty_output,
    is_err_payload as _is_err_payload, missing_report_fields, page_footer as _page_footer,
    resource_constraint as _resource_constraint, strong_claim_ids as _strong_claim_ids,
    audit_tool_effects as _audit_tool_effects)


def _find_java() -> Optional[str]:
    """寻找 Java 运行时可执行路径（跨平台探测：PATH -> macOS JVM -> Linux JVM -> Windows JDK）"""
    if shutil.which("java"):
        return "java"
    candidates = []
    # JAVA_HOME 优先（跨盘、跨机器的标准做法）
    jh = os.environ.get("JAVA_HOME", "").strip()
    if jh:
        candidates.append(os.path.join(jh, "bin", "java.exe" if sys.platform == "win32" else "java"))
        candidates.append(jh)
    # Windows：由系统环境变量推导，不写死盘符
    if sys.platform == "win32":
        for env_key, sub in (("ProgramFiles", "Java"), ("ProgramFiles", "Eclipse Adoptium"),
                             ("ProgramFiles", "Microsoft"), ("ProgramFiles(x86)", "Java"),
                             ("LOCALAPPDATA", os.path.join("Programs", "Eclipse Adoptium"))):
            base = os.environ.get(env_key)
            if base:
                candidates.append(os.path.join(base, sub))
        # Android Studio 自带 JBR（位置随安装盘变化，靠候选根扫）
        for root in _tool_roots():
            candidates.append(os.path.join(root, "Android Studio", "jbr", "bin", "java.exe"))
            candidates.append(os.path.join(root, "jbr", "bin", "java.exe"))
    # macOS / Linux 标准位置
    candidates += [
        "/Library/Java/JavaVirtualMachines",
        "/System/Library/Frameworks/JavaVM.framework",
        "/opt/homebrew/opt/openjdk/bin/java",
        "/usr/local/opt/openjdk/bin/java",
        "/usr/lib/jvm",
        "/usr/java",
    ]
    for c in candidates:
        if os.path.isfile(c) and (sys.platform == "win32" or os.access(c, os.X_OK)):
            return c
        if os.path.isdir(c):
            bin_name = "java.exe" if sys.platform == "win32" else "java"
            for root, _, files in os.walk(c):
                if bin_name in files:
                    full_p = os.path.join(root, bin_name)
                    if sys.platform == "win32" or os.access(full_p, os.X_OK):
                        return full_p
    return None

# ---------------------------------------------------------------------------
# 1. 状态与环境工具
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 2. 二进制逆向分析工具 (Radare2 引擎)
# ---------------------------------------------------------------------------
@server.tool()
@_path_alias
def seep_r2_info(binary_path: str) -> str:
    """提取二进制文件 (PE/ELF/Mach-O) 的关键元信息：架构、位数、大小、大小端、编译器、语言以及关键安全防御机制 (Canary, NX, PIE, RELRO, ASLR)。

    Args:
        binary_path: 目标二进制文件的绝对路径或相对路径
    """
    if not os.path.isfile(binary_path):
        return f"[ERROR]: Target file does not exist: {binary_path}"
    if not os.path.isfile(RABIN2_EXE):
        return f"[ERROR]: rabin2.exe not found at {RABIN2_EXE}"
    
    out = _run_cmd([RABIN2_EXE, "-I", os.path.abspath(binary_path)])
    return _clean_r2_output(out)

@server.tool()
@_path_alias
def seep_r2_cmd(binary_path: str, command: str, analyze: bool = True) -> str:
    """在目标二进制文件上执行任意 radare2 命令。

    Args:
        binary_path: 目标二进制文件路径
        command: radare2 命令字符串（例如 'afl', 'pdf @ main', 'iz', 'px 64 @ 0x1000'，多条命令用分号分隔）
        analyze: 是否在执行命令前先执行基本代码分析 (aaa)。默认 True。
    """
    if not os.path.isfile(binary_path):
        return f"[ERROR]: Target file does not exist: {binary_path}"
    if not os.path.isfile(R2_EXE):
        return f"[ERROR]: radare2.exe not found at {R2_EXE}"

    full_cmd = f"aaa; {command}" if analyze else command
    cmd_args = [
        R2_EXE,
        "-q",
        "-e", "scr.color=0",
        "-c", full_cmd,
        os.path.abspath(binary_path)
    ]
    out = _run_cmd(cmd_args, timeout=90)
    cleaned = _clean_r2_output(out)
    err = _is_err_payload(cleaned)
    if err:
        return _empty_output("seep_r2_cmd", "r2 报错：%s（确认命令拼写与地址/符号是否存在）" % err)
    if not cleaned.strip():
        return _empty_output("seep_r2_cmd", "r2 无输出：确认命令拼写与地址/符号是否存在")
    return _budget_gate(
        "seep_r2_cmd", cleaned,
        "把命令拆小（afl→afl~sub、iz→iz~关键字、px 256→px 128 @ addr 与 px 128 @ addr+0x80）")

@server.tool()
@_path_alias
def seep_r2_strings(binary_path: str, filter_text: Optional[str] = None, all_sections: bool = False, limit: int = 100) -> str:
    """从二进制文件中提取字符串（包含数据段或全段字符串），支持关键词过滤。

    Args:
        binary_path: 目标二进制文件路径
        filter_text: 可选过滤关键词（不区分大小写）
        all_sections: 是否检索全段字符串 (-zz)，默认 False 只检索数据段 (-z)
        limit: 返回最大结果行数，默认 100
    """
    if not os.path.isfile(binary_path):
        return f"[ERROR]: Target file does not exist: {binary_path}"
    
    flag = "-zz" if all_sections else "-z"
    out = _run_cmd([RABIN2_EXE, flag, os.path.abspath(binary_path)])
    lines = out.splitlines()
    
    if filter_text:
        pat = filter_text.lower()
        header = lines[:2] if len(lines) >= 2 else []
        matched = [l for l in lines[2:] if pat in l.lower()]
        result = header + matched[:limit]
        if len(matched) > limit:
            result.append(_page_footer(len(result[2:]), len(matched), "seep_r2_strings",
                                       "调大 limit，或加 filter_text 收窄"))
        return "\n".join(result)
    else:
        result = lines[:limit]
        if len(lines) > limit:
            result.append(_page_footer(len(result), len(lines), "seep_r2_strings",
                                       "调大 limit，或加 filter_text 收窄"))
        return "\n".join(result)

@server.tool()
@_path_alias
def seep_r2_disasm(
    binary_path: str,
    target: str = "main",
    lines: int = 60,
    output_mode: str = "full",
    limit_tokens: int = RESULT_BUDGET_CHARS,
) -> str:
    """反汇编指定函数或地址，支持三种输出模式以控制上下文消耗（Context Budget Control）。

    Args:
        binary_path: 目标二进制文件路径
        target: 目标函数名、符号或虚拟地址（例如 'main', 'sym.imp.puts', '0x1013ef0'）
        lines: 当以地址为目标时反汇编的最大指令行数，默认 60
        output_mode: 输出模式：
            'full'   = 完整原始反汇编（默认，适合精细分析）
            'branch' = 仅保留条件跳转与调用指令（cmp/test/jcc/call/ret），聚焦控制流骨架
            'summary'= 不输出指令，只统计：函数大小、块数、调用链、导入函数列表（最省 Token）
        limit_tokens: 最大输出字符数，默认 8000；**超限返回 resource_constraint，绝不截断**（0 表示只受 64KiB 硬预算约束）
    """
    if not os.path.isfile(binary_path):
        return f"[ERROR]: Target file does not exist: {binary_path}"

    if output_mode == "summary":
        # 仅抽取函数级摘要统计，不输出原始指令
        info_cmd = f"aaa; afi @ {target}"
        xref_cmd = f"axt @ {target}"
        call_cmd = f"axf @ {target}"
        info_out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", info_cmd, os.path.abspath(binary_path)], timeout=60)
        xref_out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", xref_cmd, os.path.abspath(binary_path)], timeout=60)
        call_out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", call_cmd, os.path.abspath(binary_path)], timeout=60)
        summary = (
            f"[DISASM SUMMARY MODE — 上下文降噪 Token 节省模式]\n"
            f"Target: {target}\n"
            f"--- Function Info (afi) ---\n{_clean_r2_output(info_out)[:800]}\n"
            f"--- Callers (axt / xrefs-to) ---\n{_clean_r2_output(xref_out)[:600]}\n"
            f"--- Callees (axf / xrefs-from) ---\n{_clean_r2_output(call_out)[:600]}\n"
            f"提示: 使用 output_mode='branch' 或 'full' 获取指令级详情。"
        )
        return summary

    # 获取完整反汇编
    cmd = f"aaa; pdf @ {target}"
    out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", cmd, os.path.abspath(binary_path)], timeout=60)
    cleaned = _clean_r2_output(out)
    output_lines = [l for l in cleaned.splitlines() if not l.startswith("INFO:") and not l.startswith("WARN:")]

    if not output_lines or all(not l.strip() for l in output_lines):
        cmd = f"pd {lines} @ {target}"
        out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", cmd, os.path.abspath(binary_path)], timeout=60)
        cleaned = _clean_r2_output(out)
        output_lines = [l for l in cleaned.splitlines() if not l.startswith("INFO:") and not l.startswith("WARN:")]

    if output_mode == "branch":
        # 过滤：仅保留含有控制流关键词的行（条件跳转、调用、返回）
        branch_keywords = ("cmp ", "test ", "je ", "jne ", "jz ", "jnz ", "jb ", "jbe ",
                           "ja ", "jae ", "jl ", "jle ", "jg ", "jge ", "jmp ", "call ",
                           "ret", "jcc", "cbz ", "cbnz ", "bl ", "bne ", "beq ")
        filtered = [l for l in output_lines if any(kw in l.lower() for kw in branch_keywords)]
        total = len(output_lines)
        kept = len(filtered)
        header = (
            f"[DISASM BRANCH MODE — 控制流骨架截面，已过滤 {total - kept}/{total} 行纯数据指令]\n"
            f"Target: {target} | 保留行: {kept} | 完整输出请用 output_mode='full'\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        )
        output_lines = filtered
        result = header + "\n".join(output_lines)
    else:
        result = "\n".join(output_lines)

    err = _is_err_payload(result)
    if err:
        return _empty_output("seep_r2_disasm",
                             "r2 报错：%s（符号可能不存在，先用 seep_r2_cmd(afl) 找目标）" % err)
    if not result.strip():
        return _empty_output("seep_r2_disasm",
                             "反汇编为空：符号不存在或地址无代码，先 seep_r2_cmd(afl) 找目标")
    return _budget_gate(
        "seep_r2_disasm", result,
        "换 output_mode='fold' / 'summary'，或用 target 收窄到具体函数、lines 调小",
        budget_chars=limit_tokens)

@server.tool()
@_path_alias
def seep_r2_decompile(
    binary_path: str,
    target: str = "main",
    output_mode: str = "full",
    limit_tokens: int = 8000,
) -> str:
    """将目标函数反编译为类 C 伪代码，支持三档输出模式以控制 Token 消耗（Context Budget Control）。

    Args:
        binary_path: 目标二进制文件路径
        target: 目标函数名称或虚拟地址（例如 'main', 'sym.verify_key'）
        output_mode: 输出控制模式（默认 full）：
            'full'    = 完整伪代码（适合深度分析，默认）
            'fold'    = 折叠纯计算/赋值语句，仅保留 if/else/switch/return/API调用行（减少 ~60% Token）
            'summary' = 不输出伪代码，仅返回：函数签名、入参、出参、直接调用的 API/函数名列表（最省 Token）
        limit_tokens: 最大输出字符数，默认 8000；**超限返回 resource_constraint，绝不截断**；设 0 表示只受 64KiB 硬预算约束
    """
    if not os.path.isfile(binary_path):
        return f"[ERROR]: Target file does not exist: {binary_path}"

    if output_mode == "summary":
        # 获取函数摘要信息（不输出函数体）
        cmds = f"aaa; afi @ {target}; axf @ {target}"
        out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", cmds, os.path.abspath(binary_path)], timeout=60)
        clean = _clean_r2_output(out)
        return (
            f"[DECOMPILE SUMMARY MODE — 最省 Token 函数摘要]\n"
            f"Target: {target}\n"
            f"{clean[:1200]}\n"
            f"提示: 使用 output_mode='fold' 或 'full' 获取伪代码详情。"
        )

    cmd = f"aaa; pdc @ {target}"
    out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", cmd, os.path.abspath(binary_path)], timeout=60)
    cleaned = _clean_r2_output(out)
    output_lines = [l for l in cleaned.splitlines() if not l.startswith("INFO:") and not l.startswith("WARN:")]

    if output_mode == "fold":
        # 折叠模式：去除纯赋值/加减乘除/临时变量行，仅保留控制流与 API 调用
        def _is_control_or_call(line: str) -> bool:
            stripped = line.strip()
            keywords = ("if ", "else", "switch", "case ", "return", "while ", "for ",
                        "do {", "goto ", "break", "continue",
                        "call ", "(", "->")
            # 包含括号 = 可能是函数调用，包含关键词 = 控制流
            return any(k in stripped for k in keywords) or stripped.startswith("//")

        folded = [l for l in output_lines if _is_control_or_call(l)]
        total = len(output_lines)
        kept = len(folded)
        header = (
            f"[DECOMPILE FOLD MODE — 已折叠 {total - kept}/{total} 行纯赋值/计算语句，上下文降噪约 {int((total-kept)/max(total,1)*100)}%]\n"
            f"Target: {target} | 保留行: {kept} | 完整输出请用 output_mode='full'\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        )
        result = header + "\n".join(folded)
    else:
        result = "\n".join(output_lines)

    err = _is_err_payload(result)
    if err:
        return _empty_output("seep_r2_decompile",
                             "r2 报错：%s（符号可能不存在，先用 seep_r2_cmd(afl) 找目标）" % err)
    if not result.strip():
        return _empty_output("seep_r2_decompile",
                             "伪代码为空：符号不存在或该函数无代码，先 seep_r2_cmd(afl)")
    return _budget_gate(
        "seep_r2_decompile", result,
        "用 output_mode='branch'/'summary' 降噪，或 target 换成更小的函数",
        budget_chars=limit_tokens)

# ---------------------------------------------------------------------------
# 3. Android APK 逆向与动态 Hook 生成
# ---------------------------------------------------------------------------
@server.tool()
@_path_alias
def seep_apk_info(apk_path: str) -> str:
    """原生解析 APK 压缩包结构：统计 DEX 文件、Native .so 架构动态库、资源分布，并提取 AndroidManifest.xml 关键字符串（免 Java 环境）。

    Args:
        apk_path: 目标 APK 文件路径
    """
    if not os.path.isfile(apk_path):
        return f"[ERROR]: APK file not found: {apk_path}"

    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            namelist = z.namelist()
            dex_files = [f for f in namelist if f.endswith(".dex")]
            so_files = [f for f in namelist if f.endswith(".so")]
            meta_files = [f for f in namelist if f.startswith("META-INF/")]
            
            # 统计原生架构
            arches = set()
            for s in so_files:
                parts = s.split('/')
                if len(parts) >= 2 and parts[0] == "lib":
                    arches.add(parts[1])

            # 提取 Manifest 二进制中的可读 ASCII/UTF-8 字符串
            manifest_strings = []
            if "AndroidManifest.xml" in namelist:
                raw = z.read("AndroidManifest.xml")
                # 过滤出 4 字符以上的可打印字符串
                found = re.findall(rb'[\x20-\x7e]{4,}', raw)
                for item in found:
                    s = item.decode('ascii', errors='ignore')
                    if any(k in s.lower() for k in ["android", "permission", "activity", "service", "receiver", "provider", "package"]):
                        manifest_strings.append(s)

            summary = {
                "file_size": os.path.getsize(apk_path),
                "dex_count": len(dex_files),
                "dex_files": dex_files,
                "native_architectures": sorted(list(arches)),
                "native_libraries_count": len(so_files),
                "signed_certificates": meta_files[:5],
                "manifest_key_markers": manifest_strings[:30]
            }
            return json.dumps(summary, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"[ERROR]: Failed to parse APK zip: {str(e)}"

@server.tool()
@_path_alias
def seep_apk_decompile(apk_path: str, output_dir: Optional[str] = None, deobfuscate: bool = True) -> str:
    """使用内置 JADX 反编译器将 APK 或 DEX 文件全量反编译为 Java 源码工程。

    Args:
        apk_path: 目标 APK 或 DEX 文件路径
        output_dir: 源码输出目录（若不指定则在 APK 旁生成 <apk_name>_src 目录）
        deobfuscate: 是否启用混淆名还原 (-r/--deobf)，默认 True
    """
    if not os.path.isfile(apk_path):
        return f"[ERROR]: Target APK does not exist: {apk_path}"

    java_path = _find_java()
    if not java_path:
        return "[ERROR]: Java runtime (JDK 17 LTS) is required to run JADX. Please install JDK or set JAVA_HOME."

    if not output_dir:
        stem = Path(apk_path).stem
        output_dir = os.path.join(os.path.dirname(os.path.abspath(apk_path)), f"{stem}_jadx_src")

    os.makedirs(output_dir, exist_ok=True)

    cmd = [JADX_BAT, "-d", output_dir]
    if deobfuscate:
        cmd.append("--deobf")
    cmd.append(os.path.abspath(apk_path))

    out = _run_cmd(cmd, timeout=300)
    _bad = (_is_err_payload(out) or ("[ERROR" in (out or ""))
            or ("No classes to decompile" in (out or ""))
            or (not os.path.isdir(output_dir)) or (not os.listdir(output_dir)))
    if _bad:
        return _empty_output("seep_apk_decompile",
                             "jadx 没有产出（或目录为空）：原始输出在 out，别把「没跑成」当「跑完了」")
    return f"Decompilation finished.\nOutput directory: {output_dir}\nLog: {out[:500]}..."

@server.tool()
@_path_alias
def seep_apk_unpack(apk_path: str, output_dir: Optional[str] = None, no_src: bool = False) -> str:
    """使用内置 Apktool 解包 APK 资源文件、清晰明文 AndroidManifest.xml 以及 Smali 汇编代码。

    Args:
        apk_path: 目标 APK 文件路径
        output_dir: 解包输出目录（若不指定则在 APK 旁生成 <apk_name>_apktool 目录）
        no_src: 是否跳过 smali 反编译 (-s)，若只需提取资源可设为 True
    """
    if not os.path.isfile(apk_path):
        return f"[ERROR]: Target APK does not exist: {apk_path}"

    java_path = _find_java()
    if not java_path:
        return "[ERROR]: Java runtime (JDK 17 LTS) is required to run Apktool. Please install JDK or set JAVA_HOME."

    if not output_dir:
        stem = Path(apk_path).stem
        output_dir = os.path.join(os.path.dirname(os.path.abspath(apk_path)), f"{stem}_apktool")

    cmd = [java_path, "-jar", APKTOOL_JAR, "d", "-f"]
    if no_src:
        cmd.append("-s")
    cmd.extend(["-o", output_dir, os.path.abspath(apk_path)])

    out = _run_cmd(cmd, timeout=300)
    if _is_err_payload(out) or "[ERROR" in (out or "") or not os.path.isdir(output_dir) \
            or not os.listdir(output_dir):
        return _empty_output("seep_apk_unpack",
                             "apktool 没有产出（或目录为空）：原始输出在 out，别把「没跑成」当「跑完了」")
    return f"Apktool unpack finished.\nOutput directory: {output_dir}\nLog: {out[:500]}..."

@server.tool()
@_path_alias
def seep_apk_smali_search(directory: str, pattern: str, case_sensitive: bool = False, limit: int = 50) -> str:
    """在解包后的 Smali 代码或源码目录中进行敏感词/签名/加解密密钥快速排查。

    Args:
        directory: 解包后的 smali 或源码根目录
        pattern: 正则表达式或搜索文本（例如 'AES', 'SecretKeySpec', 'token', 'http://', 'firebase'）
        case_sensitive: 是否大小写敏感，默认 False
        limit: 最大匹配结果条数，默认 50
    """
    if not os.path.isdir(directory):
        return f"[ERROR]: Directory not found: {directory}"

    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        regex = re.compile(pattern, flags)
    except re.error as e:
        return f"[ERROR]: Invalid regex pattern: {str(e)}"

    matches = []
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith((".smali", ".java", ".xml", ".json", ".txt")):
                fpath = os.path.join(root, f)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        for idx, line in enumerate(fh, 1):
                            if regex.search(line):
                                rel = os.path.relpath(fpath, directory)
                                matches.append(f"{rel}:{idx}: {line.strip()[:200]}")
                                if len(matches) >= limit:
                                    break
                except Exception:
                    pass
        if len(matches) >= limit:
            break

    if not matches:
        return f"No matches found for '{pattern}' in {directory}"
    res = matches[:limit]
    if len(matches) >= limit:
        res.append(_page_footer(len(res), len(matches), "seep_apk_smali_search",
                                "调大 limit，或把 pattern / directory 收窄"))
    return "\n".join(res)

# ---------------------------------------------------------------------------
# 4. ReverseLab 攻防战术知识库与 CTF Payload 库
# ---------------------------------------------------------------------------
@server.tool()
def seep_kb_search(query: str, category: Optional[str] = None, limit: int = 10) -> str:
    """在 ReverseLab 183+ 逆向与 Web/PE/CVE 攻防知识库中进行全文搜索，快速定位战术指南。

    Args:
        query: 检索关键词（例如 'JWT', 'SSRF', 'vmp', 'proto pollution', 'heap', 'yara'）
        category: 可选限定目录分类（例如 'ctf-website', 'pe-reverse', 'apk-reverse', 'general'）
        limit: 最大返回文章数，默认 10
    """
    search_root = os.path.join(KB_DIR, category) if category else KB_DIR
    if not os.path.isdir(search_root):
        search_root = KB_DIR

    md_files = glob.glob(os.path.join(search_root, "**", "*.md"), recursive=True)
    # === SEEP-EXT: kb_local BEGIN === 本地覆盖层（Tool/mcp/kb_local/，不属于 vendored 上游）
    _KB_LOCAL = os.path.join(BASE_DIR, "kb_local")
    if os.path.isdir(_KB_LOCAL):
        md_files += glob.glob(os.path.join(_KB_LOCAL, "**", "*.md"), recursive=True)
    # === SEEP-EXT: kb_local END ===
    pat = query.lower()
    # === SEEP-EXT: kb-multitoken BEGIN === 多词/中文检索增强（2026-10，纯插入，不改既有逻辑）
    # 为什么需要：原实现是整串子串匹配（pat in content），"完整性校验 反作弊" 这类
    # 空格分隔的多 token 查询必然归零 —— 即使库里有 545 行反作弊内容也捞不出来。
    # 权重集中于此，后续调参不必再动函数体。
    _KB_SINGLE_WEIGHT = 0.2   # 单字 token 权重（避免"壳"淹没结果）
    _KB_TITLE_BOOST = 6       # token 出现在标题行
    _KB_PATH_BOOST = 4        # token 出现在路径
    _KB_MAX_TOKENS = 8
    _KB_MIN_COVERAGE = 0.6    # 2 token 时要求全命中；3+ token 时按比例

    def _kb_split_tokens(q: str):
        parts = re.split(r"[\s,;/|、，。；：!?()（）\[\]【】]+", q.strip())
        return [x for x in (t.strip() for t in parts) if x][:_KB_MAX_TOKENS]

    _kb_tokens = _kb_split_tokens(pat)
    _kb_multi = len(_kb_tokens) > 1
    _kb_contents = {}
    # === SEEP-EXT: kb-multitoken END ===
    
    hits = []
    for fpath in md_files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
                # === SEEP-EXT: kb-multitoken === 缓存正文，供多词打分与 snippet 定位
                _kb_rel = os.path.relpath(fpath, KB_DIR).replace("\\", "/")
                # 本地覆盖层：统一成 kb_local/<相对路径>，避免同一文件被两次打分产出两条 hit
                if fpath.startswith(_KB_LOCAL + os.sep):
                    _kb_rel = "kb_local/" + os.path.relpath(fpath, _KB_LOCAL).replace(os.sep, "/")
                _kb_contents[_kb_rel] = content
                title = ""
                for line in content.splitlines()[:5]:
                    if line.startswith("# "):
                        title = line.lstrip("# ").strip()
                        break
                
                score = 0
                if pat in Path(fpath).name.lower():
                    score += 10
                if pat in title.lower():
                    score += 8
                if pat in content.lower():
                    score += content.lower().count(pat)

                if score > 0:
                    rel = os.path.relpath(fpath, KB_DIR)
                    # 本地覆盖层文件：输出 kb_local/<相对路径>，供 seep_kb_read 正确路由
                    if fpath.startswith(_KB_LOCAL + os.sep):
                        rel = os.path.join("kb_local", os.path.relpath(fpath, _KB_LOCAL))
                    hits.append({
                        "path": rel.replace("\\", "/"),
                        "title": title or Path(fpath).stem,
                        "score": score,
                        "snippet": content[:300].strip().replace("\n", " ")
                    })
        except Exception:
            pass

    # === SEEP-EXT: kb-multitoken BEGIN === 相关性二次打分
    # 规则：ASCII token 用词边界（避免 EAC 命中 each / reach）；CJK token 用子串；
    #       IDF 降权高频词；覆盖率平方惩罚（2 token 必须全命中）；标题/路径加成。
    import math as _kb_math

    _KB_ASCII_RE = re.compile(r"^[A-Za-z0-9_\-]+$")

    def _kb_hit_count(_low: str, _tok: str) -> int:
        if _KB_ASCII_RE.match(_tok):
            _pat = r"(?<![A-Za-z0-9_])" + re.escape(_tok) + r"(?![A-Za-z0-9_])"
            return len(re.findall(_pat, _low))
        return _low.count(_tok)

    if _kb_contents and _kb_tokens and (_kb_multi or len(_kb_tokens[0]) >= 2):
        _kb_n = len(_kb_contents)
        _kb_df = {}
        for _t in _kb_tokens:
            _kb_df[_t] = sum(1 for _txt in _kb_contents.values() if _kb_hit_count(_txt.lower(), _t) > 0)
        _kb_scores = {}
        for _rel, _text in _kb_contents.items():
            _low = _text.lower()
            _hit_pairs = []
            for _t in _kb_tokens:
                _c = _kb_hit_count(_low, _t)
                if _c:
                    _hit_pairs.append((_t, _c))
            if not _hit_pairs:
                continue
            _cov = len(_hit_pairs) / len(_kb_tokens)
            if _kb_multi and _cov < _KB_MIN_COVERAGE:
                continue
            _head = " ".join(_text.splitlines()[:5]).lower()
            _rel_low = _rel.lower()
            _score = 0.0
            for _t, _c in _hit_pairs:
                _idf = _kb_math.log((_kb_n + 1) / (_kb_df.get(_t, 1) + 1)) + 1.0
                _w = 1.0 if len(_t) > 1 else _KB_SINGLE_WEIGHT
                _boost = 1.0
                if _t in _head:
                    _boost += _KB_TITLE_BOOST / 10.0
                if _t in _rel_low:
                    _boost += _KB_PATH_BOOST / 10.0
                _score += _idf * _w * _boost * min(_c, 8)
            _kb_scores[_rel] = _score * (_cov ** 2)
        if _kb_scores:
            _kb_best = max(_kb_scores.values())
            _kb_index = {h["path"]: h for h in hits}
            for _rel, _sc in _kb_scores.items():
                if _rel in _kb_index:
                    _kb_index[_rel]["score"] += _sc
                elif _sc >= _kb_best * 0.5:
                    hits.append({"path": _rel, "title": Path(_rel).stem, "score": _sc, "snippet": ""})
    # === SEEP-EXT: kb-multitoken END ===
    hits.sort(key=lambda x: x["score"], reverse=True)
    top = hits[:limit]
    # === SEEP-EXT: kb-multitoken === snippet 改为命中位置居中（原实现固定取正文开头 300 字）
    for _h in top:
        _txt = _kb_contents.get(_h.get("path", ""))
        if not _txt:
            continue
        _low = _txt.lower()
        _pos = -1
        for _t in (_kb_tokens or [pat]):
            _i = _low.find(_t)
            if _i != -1 and (_pos == -1 or _i < _pos):
                _pos = _i
        if _pos < 0:
            continue
        _start = max(0, _pos - 160)
        _end = min(len(_txt), _pos + 160)
        _h["snippet"] = _txt[_start:_end].strip().replace("\n", " ")
    if not top:
        return f"No articles found matching '{query}' in ReverseLab knowledge base."

    return json.dumps(top, indent=2, ensure_ascii=False)

def _byte_len(text: str) -> int:
    """UTF-8 字节长度（kb_read 的 max_chars 分支用；此前缺失 → 41% 的长文章会崩）。"""
    return len(str(text).encode("utf-8", "replace"))


@server.tool()
def seep_kb_read(article_path: str, max_chars: int = 6000) -> str:
    """读取 ReverseLab 知识库中某篇战术文档或技巧手册的全文内容。

    Args:
        article_path: 相对 KB 根目录的路径（可通过 seep_kb_search 获得，例如 'ctf-website/checklists/web-ctf-first-30-min.md'）
        max_chars: 最大返回字符数，默认 6000
    """
    # 本地覆盖层：kb_local/ 前缀走 Tool/mcp/kb_local/
    if article_path.replace(chr(92), "/").startswith("kb_local/"):
        _rel = article_path.replace(chr(92), "/")[len("kb_local/"):]
        target = os.path.join(BASE_DIR, "kb_local", _rel.replace("/", os.sep))
    else:
        target = os.path.join(KB_DIR, article_path)
    if not os.path.isfile(target):
        # 尝试模糊匹配
        matches = glob.glob(os.path.join(KB_DIR, "**", f"*{article_path}*"), recursive=True)
        if matches and os.path.isfile(matches[0]):
            target = matches[0]
        else:
            return f"[ERROR]: Article not found: {article_path}"

    with open(target, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
        if len(text) > max_chars:
            return _resource_constraint(
                "seep_kb_read", text,
                "把 max_chars 调到 ≥ %d 再读全文" % len(text),
                artifact_hint="全文长度 %d 字符（%d 字节）；本次未返回任何片段，避免把半篇当全篇" % (
                    len(text), _byte_len(text)))
        return text

# ---------------------------------------------------------------------------
# 5. 战术助手与安全评估增强工具 (Task Isolation, Triage, Report & IDA Bridge)
# ---------------------------------------------------------------------------

def _workspace_root() -> str:
    """任务工作区根目录（默认 <仓库根>/work，可用 SEEP_WORKSPACE 覆盖）。

    ★ 血案：旧实现把任务目录建在 BASE_DIR（= Tool/mcp/）里，分析产物直接落进
    MCP 运行时目录，既污染仓库、又可能被当成工具依赖打包，还不在 .gitignore 内。
    现在统一落到仓库根的 work/（已 gitignore），或用户显式指定的 SEEP_WORKSPACE。
    """
    env = os.environ.get("SEEP_WORKSPACE", "").strip()
    if env:
        return os.path.abspath(os.path.expanduser(env))
    repo_root = os.path.dirname(os.path.dirname(BASE_DIR))  # Tool/mcp -> Tool -> 仓库根
    return os.path.join(repo_root, "work")


def _task_dir(task_name: str) -> str:
    """任务目录绝对路径（严格防目录穿越：task_name 先做字符清洗）。"""
    clean = re.sub(r'[^\w\-]', '_', (task_name or "").strip())
    if not clean:
        raise ValueError("task_name 不能为空")
    return os.path.join(_workspace_root(), clean)


def _hash_file(path: str, chunk: int = 1 << 20):
    """流式整文件哈希（MD5 + SHA256）。

    ★ 血案：旧实现只读前 50MB 就出哈希（`f.read(1024*1024*50)`），对 >50MB 的样本
    返回的是“截断哈希”——看起来完全正常，但对 IOC / 证据链 / 样本溯源是**错误证据**。
    哈希必须覆盖整文件，所以这里用分块流式读取（1MB/块，内存恒定）。
    """
    import hashlib
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            md5.update(block)
            sha256.update(block)
    return md5.hexdigest(), sha256.hexdigest()


def _triage_next_actions(matched: List[Dict[str, Any]], bin_info: Dict[str, Any], task_name: Optional[str]) -> List[str]:
    """按实测命中生成下一步动作（不再是无条件硬编码文案）。"""
    actions: List[str] = []
    if matched:
        sample = str(matched[0].get("string", ""))[:40]
        actions.append(
            f"命中 {len(matched)} 条鉴权/密钥/网络关键词（首条：{sample}）；"
            "下一步对命中 vaddr 做 xref，找判定分支（seep_r2_xrefs）"
        )
    else:
        actions.append(
            "未命中鉴权关键词：字符串可能被加密/压缩/壳化；先 seep_packer_detect 判壳，"
            "再用 seep_r2_strings(all_sections=true) 全段重扫"
        )
    lang = str(bin_info.get("lang", "")).lower()
    if lang in ("cil", "c#", "dotnet", "msil") or "msil" in lang:
        actions.append("语言=CIL/.NET：dnSpy/ILSpy 看 IL，混淆先 de4dot，再看 license/trial 判定方法")
    if not bin_info:
        actions.append("rabin2 未能解析：文件可能截断/加壳/非标准格式，先确认完整性再继续")
    actions.append(
        "读决策逻辑：seep_r2_decompile(binary_path=…) 取伪代码；"
        "要交付补丁：按 01-gate-bypass 四路线（补丁/代理 DLL/重打包/注入器）验证"
    )
    if task_name:
        actions.append(f"报告目录：{task_name}/reports/（传 task_name 时自动落盘 triage.json）")
    return actions

# ───────────────── 自动建案 + 缺输入就问（M2 / M4） ─────────────────
_SEEP_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_AUTOCASE = os.environ.get("SEEP_AUTOCASE", "1") not in ("0", "false", "False")


def _route_module():
    """把 `Tool/scripts/route.py` 当模块加载（判型唯一入口，不复制路由表）。"""
    if "m" in _ROUTE_MOD:
        return _ROUTE_MOD["m"]
    import importlib.util as _iu
    p = os.path.join(_SEEP_ROOT, "Tool", "scripts", "route.py")
    spec = _iu.spec_from_file_location("seep_route", p)
    m = _iu.module_from_spec(spec)
    spec.loader.exec_module(m)
    _ROUTE_MOD["m"] = m
    return m


def _domain_for(binary_path: str, task_name: str = ""):
    """给自动建案判一次型：(domain, domain_note)。

    第 4 轮评审 P1：以前自动建案一律 `domain=softseep` —— 等于「没判过型」冒充「判过型」，
    后面的域深度/路由门禁全部失真。现在用 `route.route.resolve()`（唯一路由入口）对
    「目标文件名 + 任务名」判一次：命中就用该域；判不出（含只命中兜底、命中总控包）
    就返回空串 + 提示过 seep-router，**不写 domain**。
    """
    note = "未判型，先过 seep-router"
    try:
        text = "%s %s" % (os.path.basename(str(binary_path or "")), str(task_name or ""))
        hits = _route_module().resolve(text) or []
        concrete = [h for h in hits
                    if isinstance(h, dict) and not h.get("fallback")
                    and h.get("pack") and h.get("pack") != "seep-router"]
        if not concrete:
            return "", note
        return str(concrete[0].get("pack") or ""), ""
    except Exception as e:  # noqa: BLE001
        return "", "%s（判型失败：%s）" % (note, str(e)[:60])


def _case_for(binary_path: str, task_name: str = "") -> Dict[str, Any]:
    """分析类工具第一次碰到某个样本时自动建案（无账本 = 后面所有闸门失效）。

    落地位置：`SEEP_CASE_DIR`（多项目隔离）或 `~/.seep/cases/auto/`。
    **不放仓库**：放在 `Tool/cases/` 会被索引/门禁当成正式案例（实测踩到），而且会污染 git。
    实现：直接复用 `case_state.py` 的 `paths/save_state/_ensure_case_meta`（不起子进程，毫秒级）。
    域由 `route.route.resolve()` 判（第 4 轮评审 P1）：判不出就不写 domain，回包带
    `"domain": null, "domain_note": "未判型，先过 seep-router"`。
    """
    out: Dict[str, Any] = {"enabled": _AUTOCASE}
    if not _AUTOCASE:
        return out
    try:
        p = os.path.abspath(binary_path)
        if not os.path.isfile(p):
            return out
        h = hashlib.sha256(open(p, "rb").read()[:1 << 20]).hexdigest()[:8]
        stem = os.path.splitext(os.path.basename(p))[0][:28] or "target"
        base = os.environ.get("SEEP_CASE_DIR") or os.path.join(
            os.path.expanduser("~"), ".seep", "cases", "auto")
        cdir = os.path.join(base, "%s-%s" % (stem, h))
        out["case"] = cdir.replace("\\", "/")
        if os.path.isfile(os.path.join(cdir, "case.json")):
            out["created"] = False
            return out
        # 只有真要建案时才判型（route.resolve 会读全部 pack.json，别放在热路径上）
        domain, domain_note = _domain_for(p, task_name)
        out["domain"] = domain or None
        if domain_note:
            out["domain_note"] = domain_note
        mod = _case_state_module()
        os.makedirs(cdir, exist_ok=True)
        st = {"schema": "seep-case/1", "target": mod.store_target(p),
              "depth": {}, "verdict": None, "max_level": None,
              "stage": "intake", "stage_history": [],
              "next_action": "D0 结构 + D1 存活（自动建案，未给裁定）", "updated": mod.now()}
        mod.save_state(cdir, st)
        try:                       # 原件指纹块：让账本里的证据能绑到「完整路径 / 哈希」
            _fp = mod._fingerprint_target(p)
        except Exception:          # noqa: BLE001
            _fp = None
        mod._ensure_case_meta(cdir, st, "real", _fp, domain=domain)
        out["created"] = True
        out["next"] = ('python "%s/Tool/scripts/case_state.py" prove --case "%s" '
                       '--id F-001 --claim "<结论>" --evidence "<证据路径>"'
                       % (_SEEP_ROOT.replace("\\", "/"), cdir.replace("\\", "/")))
    except Exception as e:  # noqa: BLE001
        out["case_error"] = str(e)[:160]
    return out


_CS_MOD: Dict[str, Any] = {}
_ROUTE_MOD: Dict[str, Any] = {}


def _case_state_module():
    """把 case_state.py 当模块加载（同一份逻辑，不复制、不起子进程）。"""
    if "m" in _CS_MOD:
        return _CS_MOD["m"]
    import importlib.util as _iu
    p = os.path.join(_SEEP_ROOT, "Tool", "scripts", "case_state.py")
    spec = _iu.spec_from_file_location("seep_case_state", p)
    m = _iu.module_from_spec(spec)
    spec.loader.exec_module(m)
    _CS_MOD["m"] = m
    return m


_NEEDS_CACHE: Dict[str, Any] = {}


def _needs_table() -> List[Dict[str, Any]]:
    if "t" in _NEEDS_CACHE:
        return _NEEDS_CACHE["t"]
    tab: List[Dict[str, Any]] = []
    try:
        d = json.load(open(os.path.join(_SEEP_ROOT, "Tool", "config", "user-inputs.json"), encoding="utf-8"))
        tab = [x for x in (d.get("asks") or d.get("needs") or []) if isinstance(x, dict)]
    except Exception:
        tab = []
    _NEEDS_CACHE["t"] = tab
    return tab


# 内部话术（第 4 轮评审 P0-2 / R6 P1-3）：选项是给客户看的，不能出现 if_yes / if_no / 按…走。
# 与 case_state.py 的 _ANSWER_JARGON 同一套规则（那边校验首答里的选项，这边生成时就不写）。
_ASK_JARGON = re.compile(r"if[_-]?(?:yes|no)(?:[^a-z]|$)|if\s+(?:yes|no)(?:[^a-z]|$)|"
                         r"按\s*[^\s，,。；;]{0,8}\s*走", re.I)


def _ask_options(need: Dict[str, Any]) -> List[str]:
    """把 user-inputs.json 的 `if_yes` / `if_no` **中文原文**变成客户能选的 A/B/C。

    R6 P1-3：原来这里给的是 `--option "A 有，按 if_yes 走"` —— 把内部字段名直接写给客户，
    而契约自己（case_state.py 的 _ANSWER_JARGON）就把 if_yes / if_no / 按…走 列为禁用话术。
    现在三条都写成「选了会怎样」的白话，并补 C（不确定）：C 是保守路——不动目标、不联网、
    不假设「没有」，只给不依赖运行的结构说明。
    """
    yes = str(need.get("if_yes") or "").strip()
    no = str(need.get("if_no") or "").strip()
    opts: List[str] = []
    if yes:
        opts.append("A 有（可以） —— " + yes)
    if no:
        opts.append("B 没有（不行） —— " + no)
    opts.append("C 我不确定 —— 我先只做最保守的那一步（只给结构说明、只校验已到手的样本），"
                "不运行目标、不联网、也不假设「没有」；你把情况说清楚之后我再往下推进")
    # 生成即自检：万一将来 config 里的中文原文含有禁用语，就把它换成不带后果的中性说法
    return [o if not _ASK_JARGON.search(o) else re.sub(_ASK_JARGON, "（这一步）", o) for o in opts]


def _detect_needs(blob: bytes = b"", extra_text: str = "", case_dir: str = "") -> List[Dict[str, Any]]:
    """返回**固定三条**通用问句（许可/凭据、运行许可/环境、样本完整性）。

    为什么删掉信号匹配（2026-10-24 实测）：在加密/加固样本上按关键词匹配只会造假信号
    （`hasp`/`pcap` 命中的是密文里的随机子串）。而这三条覆盖 90% 场景，
    领域特有的问句写在各自 `pack.json` 的 `ask[]` 里，不在这里猜。
    """
    asks = _needs_table()
    out: List[Dict[str, Any]] = []
    for a in asks:
        # R6 P1-3：只把**客户要看的东西**发出去（问句 + 为什么问 + A/B/C 的中文选项），
        # 不把 if_yes / if_no 这些内部字段名当成话术写给客户。
        out.append({
            "id": a.get("id"),
            "title": a.get("title"),
            "question": a.get("question"),
            "why": a.get("why"),
            "options": _ask_options(a),
        })
    if out and case_dir:
        try:
            for a, n in zip(asks[:2], out[:2]):
                opts = list(n.get("options") or [])
                subprocess.run([sys.executable, os.path.join(_SEEP_ROOT, "Tool", "scripts", "case_state.py"),
                                "ask", "--case", case_dir, "--stuck", str(a.get("question"))[:120]]
                               + [x for o in opts for x in ("--option", o)],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=60)
        except Exception:
            pass
    return out


def _needs_for_gui(tool_id: str) -> List[Dict[str, Any]]:
    """GUI 工具没有 headless 时，改成请用户帮我开（而不是自己瞎试或放弃）。"""
    for n in _needs_table():
        if n.get("trigger") == "gui_required":
            return [{"id": n.get("id"),
                     "question": str(n.get("question")).replace("{tool}", tool_id),
                     "why": n.get("why"),
                     "options": _ask_options(n)}]
    return []
def _attached_for(target_path: str, matched=None, task_name: str = "") -> Dict[str, Any]:
    """给 triage 的任何返回路径挂上「自动建案 + 缺输入就问」。

    2026-10-25 外部评审 A2：原先只写在成功路径末尾，而最常见的失败路径
    （rabin2 解析不了 → no_evidence）是早返回，于是客户最常遇到的第一个动作里
    既不开案也不问人，后面整套台账/证据/复查都失去落脚点。
    2026-10-26 第 4 轮评审 P1：建案时把**任务名**一起交给判型（目标文件名 + 任务名）。
    """
    out: Dict[str, Any] = {}
    try:
        c = _case_for(target_path, task_name or "")
        if c.get("case"):
            out["case"] = c
        needs = _detect_needs(b"", " ".join(str(x) for x in (matched or [])[:200])[:20000],
                              c.get("case") if c.get("created") else "")
        if needs:
            out["need_from_user"] = needs
            out["ask_policy"] = ("先问再动手：在对话里列 A/B/C 让用户回；不许假设"
                                 "「没有」继续往下走；答完用 case_state.py ack 记进账本。")
    except Exception as e:  # noqa: BLE001
        out["case_error"] = str(e)[:120]
    return out


@server.tool()
@_path_alias
def seep_auto_triage(target_path: str, task_name: Optional[str] = None) -> str:
    """
    静态靶向侦察 (Auto Triage) —— **无证据则拒绝，不返回"看起来完整"的空壳**：
    哈希整文件流式（observed）；rabin2 可用才算二进制画像（否则 unknown）；命中才列鉴权串。
    拒绝条件：rabin2 解析失败 **且** 字符串零命中 → {ok:false,error:"no_evidence"}，wrote_files=0
    （旧实现此时会返回一份全 "unknown" 的画像并当作完成，等于把"没测"签成"测过"）。
    """
    _attached = _attached_for(target_path, task_name=task_name or "")
    if not os.path.exists(target_path):
        return json.dumps({
            "ok": False,
            "error": "target_not_found",
            "blocked_at": "seep_auto_triage",
            "target_path": target_path,
            "wrote_files": 0,
        }, indent=2, ensure_ascii=False)
    
    t_path = Path(target_path).resolve()
    file_size = os.path.getsize(t_path)
    
    # 1. 计算哈希（整文件流式，绝不截断）
    md5_val, sha256_val = _hash_file(str(t_path))

    # 2. 调用 r2 获取架构和安全缓解
    sec_info = "Unknown"
    bin_info = {}
    if os.path.exists(RABIN2_EXE):
        raw_info = _run_cmd([RABIN2_EXE, "-Ij", str(t_path)])
        try:
            bin_info = json.loads(raw_info).get("info", {})
        except Exception:
            pass
            
    # 3. 提取高价值安全关键词（License / VIP / Auth / Expire 等）
    sensitive_keywords = ["vip", "license", "auth", "expire", "token", "subscri", "register", "check", "trial", "valid"]
    matched_strings = []
    
    if os.path.exists(RABIN2_EXE):
        raw_str = _run_cmd([RABIN2_EXE, "-zj", str(t_path)])
        try:
            str_list = json.loads(raw_str).get("strings", [])
            for s in str_list:
                val = s.get("string", "")
                v_lower = val.lower()
                if any(k in v_lower for k in sensitive_keywords):
                    matched_strings.append({
                        "vaddr": hex(s.get("vaddr", 0)),
                        "string": val[:80]
                    })
                if len(matched_strings) >= 20:
                    break
        except Exception:
            pass

    rabin2_ok = bool(bin_info)
    if not rabin2_ok and not matched_strings:  # 零证据 → 拒绝，不返回全 unknown 的空壳画像
        return json.dumps({**_attached, "ok": False, "error": "no_evidence", "blocked_at": "seep_auto_triage",
                           "wrote_files": 0,
                           "observed": {"file_name": t_path.name, "file_size_bytes": file_size,
                                        "md5": md5_val, "sha256": sha256_val, "hash_scope": "full-file"},
                           "reason": "rabin2 未能解析该文件，且鉴权关键词扫描零命中：拿不到任何二进制画像",
                           "hint": "确认 rabin2 可用（seep_ensure_tool / seep_status），或改用 "
                                   "seep_r2_info(target_path=…) / seep_packer_detect(target_path=…)；"
                                   "文件可能截断、加壳或非标准格式"},
                          indent=2, ensure_ascii=False)

    _actions = _triage_next_actions(matched_strings, bin_info, task_name)
    triage_result = {
        "ok": True,
        "status": "observed" if rabin2_ok else "partial",
        "file_name": t_path.name,
        "file_size": f"{file_size / (1024 * 1024):.2f} MB",
        "hashes": {
            "md5": md5_val,
            "sha256": sha256_val,
            "hash_scope": "full-file"  # 整文件流式计算，大文件不截断
        },
        "confidence": {
            "hashes": "observed",
            "binary_profile": "observed" if rabin2_ok else "unknown",
            "auth_strings": "observed" if matched_strings else "unknown",
        },
        "authority": "shipped-artifact",
        "limitations": ["只做静态（读文件字节），不含运行期行为/内存态结论",
                        "auth_related_strings_sampled 是关键词命中抽样，不等于授权逻辑位置"]
        + ([] if rabin2_ok else ["rabin2 不可用：arch/bits/format/protection 均为 unknown"]),
        "binary_profile": {
            "arch": bin_info.get("arch", "unknown"),
            "bits": bin_info.get("bits", "unknown"),
            "format": bin_info.get("bintype", "unknown"),
            "canary": bin_info.get("canary", False),
            "nx": bin_info.get("nx", False),
            "pic": bin_info.get("pic", False),
            "stripped": bin_info.get("stripped", False),
            "compiler": bin_info.get("compiler", "unknown")
        },
        "auth_related_strings_sampled": matched_strings[:15],
        "next_actions": _actions,
        "recommended_action": _actions[0],
    }
    
    if task_name:
        report_dir = os.path.join(_task_dir(task_name), "reports")
        if os.path.exists(report_dir):
            out_file = os.path.join(report_dir, f"{t_path.stem}_triage.json")
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(triage_result, f, indent=2, ensure_ascii=False)
            triage_result["saved_report"] = out_file
    return json.dumps(triage_result, indent=2, ensure_ascii=False)


@server.tool()
def seep_gen_security_report(
    task_name: str,
    target_name: str,
    vuln_type: str = "CWE-602: 客户端鉴权与状态判定缺陷",
    branch_location: str = "",
    description: str = "",
    poc_summary: str = "",
    defense_recommendation: str = "",
    disasm_snippet: str = "",
    case_dir: str = "",
) -> str:
    """
    生成白盒安全评估报告 —— **无证据则拒绝**（不再有"缺省成功"路径）。

    缺任一条即 `ok:false`，且 reports/ 下一个文件都不写：
      1. task_name / target_name / description / poc_summary 非空；
      2. branch_location 不是占位值（0x0 / unknown / tbd / 空）；
      3. 本案 facts.jsonl 至少有 1 条 claim：status=proven + confidence∈{observed,derived} + evidence 非空。
    反汇编摘录不提供时报告写"未提供"，**绝不编造指令**。
    """
    clean_task = re.sub(r'[^\w\-]', '_', (task_name or "").strip())
    miss = missing_report_fields(clean_task, target_name, description, poc_summary, branch_location)
    if miss:  # 缺字段 = 缺证据：一个文件都不写
        return json.dumps({"ok": False, "error": "missing_evidence_fields", "fields": miss,
                           "blocked_at": "seep_gen_security_report", "wrote_files": 0,
                           "hint": "这些字段必须来自实测（反编译位点 / 跑过的 PoC / 现象）；不接受缺省模板。"},
                          indent=2, ensure_ascii=False)

    ev_dir = _case_evidence_dir(task_name, case_dir, _task_dir, _case_lib_dir)
    strong = _strong_claim_ids(ev_dir) if ev_dir else []
    if not strong:  # 无 observed/derived 证据 = 拒报告（旧文案「通过动态 Hook 成功验证」已删）
        return json.dumps({"ok": False, "error": "no_evidence", "wrote_files": 0,
                           "blocked_at": "seep_gen_security_report",
                           "case_dir": ev_dir or "(未找到含 facts.jsonl 的案例目录)",
                           "hint": "先 `case_state.py claim --case <目录> --id F-001 --text ... --status "
                                   "proven --evidence '<实测输出>' --confidence observed --authority "
                                   "shipped-artifact`，再回来出报告。"},
                          indent=2, ensure_ascii=False)

    report_dir = os.path.join(_task_dir(clean_task), "reports")
    os.makedirs(report_dir, exist_ok=True)
    report_file = os.path.join(report_dir, "%s_security_assessment_report.md"
                               % re.sub(r'[^\w\-]', '_', target_name))
    now_str = subprocess.getoutput('date /t') if sys.platform == 'win32' else subprocess.getoutput('date')
    content = build_report_md(clean_task, target_name, vuln_type, branch_location, description,
                              poc_summary, defense_recommendation, disasm_snippet,
                              ev_dir, strong, now_str)
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(content)
    return json.dumps({
        "ok": True, "status": "Reported", "report_path": report_file,
        "evidence_claims": strong, "confidence": "derived", "authority": "shipped-artifact",
        "limitations": ["只覆盖 evidence_claims 里的结论；其余未验证部分不进本报告",
                        "反汇编摘录为空表示本次未取，不代表不存在"],
        "message": f"报告已生成并归档至: {clean_task}/reports/{os.path.basename(report_file)}",
    }, indent=2, ensure_ascii=False)


# 扩展资产（relab2 / REA 适配版）：seep_ensure_tool 四级探测自愈 / seep_r2_decompile 多引擎降级 IDA→REA→R2

# 工具根：tool_autodiscover.candidate_roots()（env → 用户级 → 盘符常见目录 → POSIX），插件不可用时用下面的兜底。
_FALLBACK_ROOTS = [
    os.environ.get("SEEP_TOOL_ROOT", ""),
    os.environ.get("REVERSE_TOOL_ROOT", ""),
    os.path.join(os.path.expanduser("~"), ".seep", "tools"),
    os.path.join(os.path.expanduser("~"), "Tools"),
    "/opt", "/usr/local/bin", "/usr/bin",
]


def _tool_roots():
    """动态工具根（带缓存；插件不可用时用兜底清单）。"""
    global _TOOL_ROOTS_CACHE
    try:
        if _TOOL_ROOTS_CACHE is not None:
            return _TOOL_ROOTS_CACHE
    except NameError:
        pass
    roots = None
    tad = _autodiscover()
    if tad is not None and hasattr(tad, "candidate_roots"):
        try:
            roots = tad.candidate_roots()
        except Exception:
            roots = None
    if not roots:
        roots = [r for r in _FALLBACK_ROOTS if r]
    _TOOL_ROOTS_CACHE = roots
    return roots


_TOOL_ROOTS_CACHE = None

# 兼容旧引用点：模块级只保留兜底清单，真实探测走 _tool_roots()
_TOOL_ROOTS = _FALLBACK_ROOTS

# 已知工具别名 -> 可执行文件名候选（解决"目录名 != 工具名"）
_TOOL_ALIASES = {
    "ida": ["idat64", "idat", "ida64", "ida"],
    "ida64": ["ida64", "idat64"],
    "idat": ["idat64", "idat"],
    "x64dbg": ["x64dbg", "x96dbg"],
    "x32dbg": ["x32dbg"],
    "cdb": ["cdb"],
    "diec": ["diec"],
    "die": ["die"],
    "r2": ["radare2", "r2"],
    "rabin2": ["rabin2"],
    "ghidra": ["analyzeHeadless"],
    "floss": ["floss"],
    "capa": ["capa"],
    "pe-sieve": ["pe-sieve", "pe-sieve64"],
    "tshark": ["tshark"],
    "jadx": ["jadx", "jadx.bat"],
    "apktool": ["apktool", "apktool.bat"],
    "frida": ["frida"],
    "binwalk": ["binwalk", "binwalk.exe"],
    "unblob": ["unblob"],
    "gcc": ["gcc", "gcc.exe"],
    "python": ["python", "python3"],
}

# 缺工具时的安装提示（只给建议，不擅自联网安装）
_TOOL_INSTALL_HINTS = {
    "ida": "商业软件，需自备 IDA Pro 授权；装好后把 idat64 加入 PATH 或任一候选根（~/.seep/tools 等）。",
    "x64dbg": "winget install x64dbg.x64dbg，或从 x64dbg.com 下载便携版放进 ~/.seep/tools。",
    "cdb": "随 Windows SDK / WinDbg 安装：winget install Microsoft.WinDbg。",
    "diec": "下载 Detect It Easy (DIE) 便携版，把 diec.exe 放进 ~/.seep/tools。",
    "ghidra": "下载 Ghidra 后把 analyzeHeadless 加入 PATH。",
    "floss": "pip install flare-floss",
    "capa": "pip install flare-capa",
    "binwalk": "pip install binwalk 或使用独立可执行版。",
    "unblob": "pip install unblob（依赖 pyperscan，需编译环境）。",
    "frida": "pip install frida-tools",
    "jadx": "下载 jadx release 解压后加入 PATH。",
    "apktool": "下载 apktool.jar + 包装脚本。",
    "tshark": "随 Wireshark 安装。",
    "gcc": "安装 mingw-w64 / Zig / MSVC。",
}


def _deny_tool_path(path: str) -> bool:
    """第 4 级扫描的 deny 规则：命中即跳过。
    典型陷阱：IDA 自带裸 python 无 pip 包，误命中会让脚本跑在错解释器上。"""
    low = path.lower()
    deny_markers = [
        "ida pro", "ida\\python", "ida/python", "python27", "python3.8\\python",
        "\\plugins\\", "\\sdk\\", "node_modules",
    ]
    return any(m in low for m in deny_markers)


def _scan_tool_roots(name: str, exe_names: list) -> str:
    """第 4 级：在常见工具根下递归扫描（带 deny 规则），命中即返回。"""
    wanted = set()
    for e in exe_names:
        el = e.lower()
        wanted.add(el)
        if not el.endswith(".exe"):
            wanted.add(el + ".exe")
    for root in _tool_roots():
        if not root or not os.path.isdir(root):
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                depth = dirpath[len(root):].count(os.sep)
                if depth > 4:
                    dirnames[:] = []
                    continue
                for fn in filenames:
                    if fn.lower() in wanted:
                        full = os.path.join(dirpath, fn)
                        if not _deny_tool_path(full) and os.path.isfile(full):
                            return full
        except Exception:
            continue
    return ""


def _resolve_tool(tool_id: str) -> dict:
    """四级递进探测：env -> PATH -> map(别名) -> scan。命中即停。
    返回 {available, command, via}。"""
    exe_names = _TOOL_ALIASES.get(tool_id.lower(), [tool_id])

    # 第 1 级：环境变量（显式指定，最高优先）
    env_key = "SEEP_" + re.sub(r"[^A-Z0-9]", "_", tool_id.upper()) + "_PATH"
    env_val = os.environ.get(env_key, "")
    if env_val and os.path.isfile(env_val):
        return {"available": True, "command": env_val, "via": "env"}

    # 第 2 级：PATH（系统安装优先于便携副本）
    for e in exe_names:
        w = shutil.which(e)
        if w:
            return {"available": True, "command": w, "via": "PATH"}

    # 第 3 级：常见工具根的直接子目录/别名映射（快速命中）
    for root in _tool_roots():
        if not root or not os.path.isdir(root):
            continue
        for e in exe_names:
            for cand in (os.path.join(root, e), os.path.join(root, "cli", e),
                         os.path.join(root, "bin", e)):
                for c2 in (cand, cand + ".exe"):
                    if os.path.isfile(c2) and not _deny_tool_path(c2):
                        return {"available": True, "command": c2, "via": "map"}

    # 第 4 级：递归扫描（可信度最低，带 deny 规则）
    found = _scan_tool_roots(tool_id, exe_names)
    if found:
        return {"available": True, "command": found, "via": "scan"}

    return {"available": False, "command": "", "via": "none"}


def _load_tool_install() -> dict:
    """读声明式安装清单 Tool/config/tool-install.json；缺失返回空结构。"""
    try:
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "config", "tool-install.json")
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"installable": {}, "auto_allow_methods": ["pip"]}


def _build_install_plan(tid: str, entry: dict) -> dict:
    """把声明式条目转成可读的安装计划（命令 + 说明），供人/智能体确认后执行。"""
    method = entry.get("method", "")
    pkg = entry.get("pkg", "")
    if method == "pip":
        cmd = f"{sys.executable} -m pip install {pkg}"
    elif method == "winget":
        cmd = f"winget install --id {pkg} -e"
    elif method == "npm":
        cmd = f"npm install -g {pkg}"
    elif method == "go":
        cmd = f"go install {pkg}"
    elif method == "manual":
        cmd = f"手动下载：{entry.get('url','')}"
    else:
        cmd = ""
    return {"tool": tid, "method": method, "package": pkg, "command": cmd,
            "note": entry.get("note", "")}


def _install_cmd_for(tid: str, entry: dict) -> list:
    """把声明式条目转成实际可执行的 argv 列表（仅 pip/winget/npm/go）。"""
    method = entry.get("method", "")
    pkg = entry.get("pkg", "")
    if method == "pip":
        return [sys.executable, "-m", "pip", "install", pkg]
    if method == "winget":
        return ["winget", "install", "--id", pkg, "-e", "--accept-source-agreements",
                "--accept-package-agreements"]
    if method == "npm":
        return ["npm", "install", "-g", pkg]
    if method == "go":
        return ["go", "install", pkg]
    return []


@server.tool()
def seep_ensure_tool(tool_id: str, allow_install: bool = True) -> str:
    """探测本机某工具是否可用；缺工具时自动安装（多途径自适应），装完自动重探。

    统一复用 tool_autodiscover 六层递进发现（环境变量 -> PATH -> 常用目录 -> 注册表 -> 递归扫描 -> 别名）。
    绝不使用 -h/-v 等参数盲目试探二进制（防止特定程序崩溃或挂死）。
    支持多途径自适应安装（无 winget 时自动降级为绿色直下，绝不卡住）。

    用户 2026-10-26 口径：**工具缺了就该自动装** —— 默认 `allow_install=True`，
    不再因为「没拿到确认」而停在那里等人。这是正常开发项目，本来就联网；
    下载物仍要校验来源（只走 tool-install.json 里登记的白名单途径：pip / winget /
    portable_zip / npm / go，不接受任意 URL）。

    Args:
        tool_id: 工具标识，如 'ida' / 'x64dbg' / 'cdb' / 'diec' / 'r2' / 'ghidra' /
                 'floss' / 'capa' / 'frida' / 'jadx' / 'apktool' / 'tshark' / 'binwalk'
        allow_install: 是否尝试自动安装（**默认 True = 缺就装**；
                       只要探测结果、不要动本机时显式传 False，此时仅出安装计划）
    """
    tad = _autodiscover()
    tid = tool_id.strip().lower()
    policy = ("缺就装（默认 allow_install=True；只要探测不装时传 allow_install=False）"
              if allow_install else "只探测不装（本次显式 allow_install=False）")

    if tad is not None:
        disc = tad.discover(tid)
        out = {"tool_id": tid, "install_policy": policy}
        out.update(disc)

        if disc.get("available"):
            out["status"] = "available"
            return json.dumps(out, indent=2, ensure_ascii=False)

        # 不可用：出安装计划
        out["status"] = "missing"
        plan = tad.install_plan(tid)
        out["install_plan"] = plan
        out["install_hint"] = _TOOL_INSTALL_HINTS.get(tid, plan.get("note") or "请手动安装后加入 PATH。")

        if allow_install and plan.get("has_plan") and plan.get("auto_allowed"):
            exec_res = tad.propose_install(tid, execute=True)
            out["install_attempt"] = exec_res
            if exec_res.get("executed") and exec_res.get("recheck", {}).get("available"):
                out["status"] = "available"
                out["after_install"] = exec_res.get("recheck")
            else:
                out["install_note"] = "自动安装已尝试但未就绪：看 install_attempt 的 stderr/命令，换一种途径重试"

        return json.dumps(out, indent=2, ensure_ascii=False)

    # 兜底回退：若插件未载入
    res = _resolve_tool(tid)
    out = {"tool_id": tid, "install_policy": policy}
    out.update(res)
    out["status"] = "available" if res.get("available") else "missing"
    return json.dumps(out, indent=2, ensure_ascii=False)


def _load_engine_tiers() -> dict:
    """读声明式引擎降级链（Tool/config/engine-tiers.json）；缺失则用内置默认。"""
    default = {"chains": {"native": ["ida", "ghidra", "rea", "r2"],
                          "dotnet": ["ida", "ghidra", "r2"],
                          "android": ["jadx", "r2"]}}
    try:
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "config", "engine-tiers.json")
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data.get("chains"), dict):
            return data
    except Exception:
        pass
    return default


def _engine_order_for(binary_path: str) -> list:
    """按目标类型选降级链：.NET -> dotnet，APK/DEX -> android，其余 -> native。"""
    chains = _load_engine_tiers().get("chains", {})
    low = binary_path.lower()
    if low.endswith((".apk", ".dex", ".jar")):
        return chains.get("android", ["jadx", "r2"])
    try:
        with open(binary_path, "rb") as f:
            head = f.read(2 * 1024 * 1024)
        if b"BSJB" in head or b"mscoree" in head or b"_CorExeMain" in head:
            return chains.get("dotnet", ["ida", "ghidra", "r2"])
    except Exception:
        pass
    return chains.get("native", ["ida", "ghidra", "rea", "r2"])


def _detect_engine(engine: str) -> dict:
    """探测某反编译引擎是否可用。返回 {available, detail}。"""
    e = engine.lower()
    if e == "ida":
        r = _resolve_tool("ida")
        return {"available": r["available"], "detail": r.get("command", "")}
    if e == "ghidra":
        r = _resolve_tool("ghidra")
        return {"available": r["available"], "detail": r.get("command", "")}
    if e == "rea":
        npx = shutil.which("npx")
        rea_cli = shutil.which("rea")
        if rea_cli:
            return {"available": True, "detail": rea_cli}
        if npx:
            return {"available": True, "detail": "npx rea-agents (node=%s)" % npx}
        return {"available": False, "detail": "no npx/rea"}
    if e == "r2":
        return {"available": os.path.isfile(R2_EXE), "detail": R2_EXE}
    return {"available": False, "detail": "unknown engine"}


def _find_java_home() -> str:
    """找 JAVA_HOME（Ghidra headless 需要）。"""
    jh = os.environ.get("JAVA_HOME", "")
    if jh and os.path.isdir(jh):
        return jh
    # 常见位置（动态根 + 系统标准位置，不写死盘符）
    for base in [os.path.join(r, "runtime") for r in _tool_roots()] + ["/usr/lib/jvm"]:
        if os.path.isdir(base):
            for d in os.listdir(base):
                if d.lower().startswith("jdk"):
                    p = os.path.join(base, d)
                    if os.path.isdir(p):
                        return p
    return ""


def _ghidra_decompile(binary_path: str, target: str, output_mode: str = "fold") -> Optional[str]:
    """真驱动 Ghidra analyzeHeadless 反编译指定函数；成功返回伪代码字符串，失败返回 None。
    用本仓自带脚本 Tool/mcp/ghidra_scripts/DecompileToFile.java。"""
    det = _detect_engine("ghidra")
    if not det["available"]:
        return None
    analyze = det["detail"]
    if not analyze:
        return None
    # Windows 优先用 .bat
    if sys.platform == "win32" and not analyze.lower().endswith(".bat"):
        bat = analyze + ".bat"
        if os.path.isfile(bat):
            analyze = bat
    script = os.path.join(BASE_DIR, "ghidra_scripts", "DecompileToFile.java")
    if not os.path.isfile(script):
        return None
    import tempfile
    proj_dir = tempfile.mkdtemp(prefix="seep_ghidra_")
    out_c = os.path.join(proj_dir, "decompile_out.c")
    env = dict(os.environ)
    jh = _find_java_home()
    if jh:
        env["JAVA_HOME"] = jh
    cmd = [analyze, proj_dir, "seep_proj", "-import", os.path.abspath(binary_path),
           "-postScript", "DecompileToFile.java", target or "auto", out_c,
           "-deleteProject", "-scriptPath", os.path.dirname(script)]
    code = None
    try:
        try:
            subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=300, env=env)
        except Exception:
            return None
        if not os.path.isfile(out_c):
            return None
        try:
            with open(out_c, "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
        except Exception:
            return None
    finally:
        # 攻击性加固：无论成功、失败还是超时中断，绝不残留临时 Ghidra 工程垃圾目录
        try:
            shutil.rmtree(proj_dir, ignore_errors=True)
        except Exception:
            pass

    if not code or not code.strip() or "decompile failed" in code[:200]:
        return None
    # output_mode 粗略处理：summary 只给签名行，fold/full 给代码
    if output_mode == "summary":
        lines = [l for l in code.splitlines() if l.startswith("//") or "{" in l or "(" in l][:40]
        return "\n".join(lines)
    return code[:12000]


# ---------------------------------------------------------------------------
# 扩展资产 第二批（补 Seep 的"动态/资源/协议"盲区，2026-10 增补）
# 纯增量：不修改任何既有工具逻辑，只在末尾追加。
#   seep_pe_resources       —— PE 资源/高熵载荷剥离（治"资源里藏着真正功能"的样本）
#   seep_mem_strings        —— 活体进程内存字符串扫描（治"字符串运行期才解密"的样本）
#   seep_pcap_extract       —— pcap 协议/端点/载荷提取（治"卡密在云端、需要看回包"的样本）
# 这些正好覆盖 relab2 实战中 Seep 缺的三块：资源层 / 内存层 / 协议层。
# ---------------------------------------------------------------------------

def _entropy_bytes(b: bytes) -> float:
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    n = len(b)
    import math
    return -sum((v / n) * math.log2(v / n) for v in c if v)


def _sniff_container(b: bytes) -> str:
    """识别常见压缩/加密容器头，用于资源剥离时判断下一步怎么解。"""
    sigs = [
        (b"\x28\xb5\x2f\xfd", "zstd"),
        (b"PK\x03\x04", "zip"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"\x1f\x8b", "gzip"),
        (b"BZh", "bzip2"),
        (b"\xfd7zXZ", "xz"),
        (b"Rar!", "rar"),
        (b"MZ", "pe"),
        (b"\x7fELF", "elf"),
        (b"\x89PNG", "png"),
        (b"BM", "bmp"),
        (b"OggS", "ogg"),
    ]
    for sig, name in sigs:
        if b.startswith(sig):
            return name
    return "unknown"


@server.tool()
@_pid_alias
def seep_mem_strings(pid: Optional[int] = None, pattern: str = "", min_len: int = 5, max_hits: int = 50, encoding: str = "both") -> str:
    """扫描指定进程的内存，提取可读字符串（治"字符串运行期才解密/只有内存里才有"的样本）。

    很多加壳/反调试样本，磁盘上看不到 URL/卡密提示/密钥，因为它们运行期才解密到内存。
    本工具用 Windows ReadProcessMemory 逐块扫描（只读，不改目标），把命中的字符串
    连同所在虚拟地址一起给你，方便回填到反汇编里定位引用。

    Args:
        pid: 目标进程 ID（也接受进程名如 'a.exe'，或可执行文件路径；
             别名 pid_or_name / process_name / process / image_name /
             binary_path / target_path / file_path / sample_path / artifact_path 均可）
        pattern: 可选，只返回包含该子串的字符串（不区分大小写）
        min_len: 最短字符串长度（默认 5）
        max_hits: 最多返回多少条（默认 50）
        encoding: 'ascii' | 'utf16' | 'both'（默认 both）
    """
    if sys.platform != "win32":
        return "[ERROR]: seep_mem_strings 目前仅支持 Windows（依赖 ReadProcessMemory）。"
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    try:
        pid_int = int(pid)
    except Exception:
        return f"[ERROR]: 非法 pid={pid}，必须为正整数。"

    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid_int)
    if not h:
        return f"[ERROR]: OpenProcess 失败 pid={pid}，错误码={ctypes.get_last_error()}（需管理员权限或目标进程架构一致）"

    hits = []
    try:
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", wintypes.DWORD), ("RegionSize", ctypes.c_size_t),
                        ("State", wintypes.DWORD), ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]

        MEM_COMMIT = 0x1000
        PAGE_GUARD = 0x100
        PAGE_NOACCESS = 0x01
        readable = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}  # R/RW/COPY/W+X 等
        addr = 0
        pat = pattern.lower()
        mbi = MEMORY_BASIC_INFORMATION()
        max_addr = 0x7FFFFFFFFFFF
        while addr < max_addr and len(hits) < max_hits:
            res = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not res:
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0
            prot = mbi.Protect or 0
            # 攻击性加固：单块读取限制最大 8MB，避免超大恶意堆块导致瞬间内存暴增/OOM
            if (mbi.State == MEM_COMMIT and prot not in (PAGE_NOACCESS,) and not (prot & PAGE_GUARD)
                    and (prot & 0xFF) in readable and 0 < size <= (8 << 20)):
                buf = ctypes.create_string_buffer(size)
                nread = ctypes.c_size_t(0)
                ok = k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, size, ctypes.byref(nread))
                if ok and nread.value:
                    data = buf.raw[:nread.value]
                    # ascii
                    if encoding in ("ascii", "both"):
                        for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
                            s = m.group().decode("ascii", "replace")
                            if not pat or pat in s.lower():
                                hits.append({"addr": hex(base + m.start()), "enc": "ascii", "s": s[:200]})
                                if len(hits) >= max_hits:
                                    break
                    # utf16le
                    if encoding in ("utf16", "both") and len(hits) < max_hits:
                        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data):
                            try:
                                s = m.group().decode("utf-16le", "replace")
                            except Exception:
                                continue
                            if not pat or pat in s.lower():
                                hits.append({"addr": hex(base + m.start()), "enc": "utf16", "s": s[:200]})
                                if len(hits) >= max_hits:
                                    break
            addr = base + size
            if size == 0:
                break
    finally:
        # 攻击性加固：无论成功或异常退出，严密关闭目标进程句柄，防止句柄泄露锁死目标
        k32.CloseHandle(h)

    return json.dumps({
        "pid": pid, "pattern": pattern, "hits": hits, "count": len(hits),
        "note": "addr 为进程虚拟地址，可直接回填到反汇编/反编译里定位引用该字符串的代码。",
    }, indent=2, ensure_ascii=False)


@server.tool()
@_path_alias
def seep_pcap_extract(pcap_path: str, host_filter: str = "", mode: str = "summary",
                      port: int = 0, max_rows: int = 40) -> str:
    """从 pcap/pcapng 提取通信端点、HTTP 请求/响应、以及可选端口/主机的 TCP 载荷。

    治"卡密/授权在云端"的样本：先看它连了谁、发了什么、回了什么，
    往往比死磕本地校验更快（回包伪造 / 协议复刻）。

    Args:
        pcap_path: pcap/pcapng 文件路径
        host_filter: 可选，只看与某 IP/域名相关的流量（子串匹配）
        mode: 'summary'（端点+HTTP 概览）| 'http'（完整 HTTP 请求/响应行）| 'payload'（指定端口的 TCP 载荷）
        port: mode='payload' 时，只取该端口的 TCP 流（0=不限）
        max_rows: 最多返回行数（默认 40）
    """
    if not os.path.isfile(pcap_path):
        return f"[ERROR]: pcap not found: {pcap_path}"
    tshark = shutil.which("tshark") or ""
    if not tshark:
        cands = ["/usr/bin/tshark", "/usr/local/bin/tshark"]
        pf = os.environ.get("ProgramFiles", "")
        if pf:
            cands.append(os.path.join(pf, "Wireshark", "tshark.exe"))
        for root in _tool_roots():
            cands.append(os.path.join(root, "Wireshark", "tshark.exe"))
            cands.append(os.path.join(root, "Wireshark", "tshark.EXE"))
        for c in cands:
            if os.path.isfile(c):
                tshark = c
                break
    if not tshark:
        return ("[ERROR]: 未找到 tshark。安装 Wireshark 后重试，"
                "或运行 seep_ensure_tool('tshark') 查看安装建议。")

    def run(args):
        try:
            p = subprocess.run([tshark, "-r", pcap_path] + args, capture_output=True,
                               text=True, encoding="utf-8", errors="replace", timeout=120)
            return (p.stdout or "") + (p.stderr or "")
        except Exception as exc:  # noqa: BLE001
            return f"[ERROR]: {type(exc).__name__}: {exc}"

    if mode == "summary":
        # 会话端点
        conv = run(["-q", "-z", "conv,tcp"])
        # HTTP 主机
        http_hosts = run(["-Y", "http.host", "-T", "fields", "-e", "http.host",
                          "-e", "http.request.uri"], )
        lines = [l for l in http_hosts.splitlines() if l.strip()]
        if host_filter:
            conv = "\n".join([l for l in conv.splitlines() if host_filter in l or "===" in l or "Filter" in l])
            lines = [l for l in lines if host_filter in l]
        return json.dumps({
            "pcap": os.path.basename(pcap_path),
            "tcp_conversations": conv.strip().splitlines()[:max_rows],
            "http_hosts": lines[:max_rows],
            "note": "有外连 = 云端权威可能。下一步：mode='http' 看请求/响应，或 mode='payload' 看端口载荷。",
        }, indent=2, ensure_ascii=False)

    if mode == "http":
        out = run(["-Y", "http.request or http.response",
                   "-T", "fields", "-e", "ip.dst", "-e", "http.request.method",
                   "-e", "http.host", "-e", "http.request.uri",
                   "-e", "http.response.code", "-e", "http.content_type"])
        lines = [l for l in out.splitlines() if l.strip()]
        if host_filter:
            lines = [l for l in lines if host_filter in l]
        return json.dumps({"http_rows": lines[:max_rows]}, indent=2, ensure_ascii=False)

    if mode == "payload":
        flt = f"tcp.port=={port}" if port else "tcp.len>0"
        out = run(["-Y", flt, "-T", "fields", "-e", "ip.src", "-e", "tcp.srcport",
                   "-e", "ip.dst", "-e", "tcp.dstport", "-e", "tcp.len", "-e", "data.data"])
        lines = [l for l in out.splitlines() if l.strip()]
        if host_filter:
            lines = [l for l in lines if host_filter in l]
        return json.dumps({"payload_rows": lines[:max_rows],
                           "note": "data.data 为十六进制载荷，可据此还原协议/伪造回包。"},
                          indent=2, ensure_ascii=False)

    return f"[ERROR]: 未知 mode='{mode}'（可选 summary/http/payload）"


# ---------------------------------------------------------------------------
# 扩展资产 第三批（P1 协议重放 / P2 加壳反调试工具化，2026-10 增补）
# 纯增量：不修改任何既有工具逻辑，只在末尾追加。
#   seep_http_replay     —— 协议请求构造/重放（curl_cffi TLS 指纹伪装 + Cookie 会话管理）
#   seep_packer_detect   —— 加壳/反调试静态识别（把 MANUAL 的 ANTI-DEBUG/UNPACKING 手册工具化）
# 设计依据：MANUAL/ANTI-DEBUG.md（190 行）、MANUAL/UNPACKING.md（188 行）——
#   手册已讲清"怎么判断、怎么处理"，这里补的是"自动判出来并给路由"，不是重写手册。
# ---------------------------------------------------------------------------

# 已知壳节名（与 MANUAL/UNPACKING.md §一 对齐）
_PACKER_SECTIONS = {
    ".upx0", ".upx1", ".upx2", "UPX0", "UPX1", "UPX2",
    ".aspack", ".adata", "ASPack",
    ".nsp0", ".nsp1", ".nsp2",          # NsPack
    ".themida", ".winlice",             # Themida/WinLicense
    ".vmp0", ".vmp1", ".vmp2",          # VMProtect
    ".enigma1", ".enigma2",             # Enigma
    ".petite", ".pec1", ".pec2",
    ".mpress1", ".mpress2",             # MPRESS
    ".yP", ".y0da", ".Gogi", ".GWan",
    ".packed", ".pack", ".mackt",       # 通用/PECompact
}
_PACKER_STRINGS = [b"UPX!", b"UPX0", b"UPX1", b"ASPack", b"Themida", b"VMProtect",
                   b".vmp", b"Enigma", b"PECompact", b"MPRESS"]

# 反调试相关导入（与 MANUAL/ANTI-DEBUG.md §二 对齐）
_ANTIDEBUG_IMPORTS = {
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "NtSetInformationThread", "NtQuerySystemInformation", "NtQueryObject",
    "OutputDebugStringA", "OutputDebugStringW", "GetTickCount", "GetTickCount64",
    "QueryPerformanceCounter", "CreateToolhelp32Snapshot", "Process32FirstW",
    "Process32NextW", "FindWindowA", "FindWindowW", "GetForegroundWindow",
    "BlockInput", "NtClose", "SetUnhandledExceptionFilter", "LoadLibraryA", "LoadLibraryW",
}
# 注入/自修改/内存篡改类导入（不一定是反调试，但加壳/保护/注入型样本的强信号）
_INJECTION_IMPORTS = {
    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "VirtualProtectEx",
    "OpenProcess", "ReadProcessMemory", "GetProcAddress", "LoadLibraryW", "LoadLibraryA",
    "VirtualProtect", "VirtualAlloc", "SetThreadContext", "QueueUserAPC",
}
# 反虚拟机/沙箱字符串
_ANTIVM_STRINGS = [b"VMware", b"VirtualBox", b"VBox", b"QEMU", b"Xen", b"Hyper-V",
                   b"vbox", b"SbieDll", b"dbghelp", b"OllyDbg", b"x64dbg", b"WinDbg",
                   b"Wireshark", b"Process Hacker", b"procmon"]

# ── 强弱分层（第 5 轮评审 P1）────────────────────────────────────────────────
# 弱信号：**CRT / 标准运行时也常见**，单独出现绝不能当「反调试/注入」结论。
#   实测反例：MinGW 的伪重定位器就带 SetUnhandledExceptionFilter + VirtualProtect
#   （golden-crackme/target/a.exe 曾被误报 antidebug=[SetUnhandledExceptionFilter]
#    injection=[VirtualProtect]），而该案已证明那只是运行时启动代码。
_WEAK_RUNTIME_IMPORTS = {
    "SetUnhandledExceptionFilter", "VirtualProtect", "VirtualAlloc",
    "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
    "IsDebuggerPresent", "OutputDebugStringA", "OutputDebugStringW",
    "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
    "CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW",
    "FindWindowA", "FindWindowW", "GetForegroundWindow",
    "OpenProcess", "ReadProcessMemory",
}
# 强信号：标准 CRT 不会凭空带上的反调试/注入组合（仍需同文件 ≥2 个才判「有保护」）。
# 注意：上面两个既有集合（_ANTIDEBUG_IMPORTS / _INJECTION_IMPORTS）**全部保留**，
#   这里只决定「进 antidebug/injection 结论」还是「进 weak_signals」。


def _read_pe_imports(path: str):
    """用 pefile 读导入函数名。

    返回 list = 读取成功（可能为空表）；返回 None = **读取失败/工具不可用**。
    第 5 轮评审 P1：以前失败也返回 []，外面就把「解析失败」当成「没有反调试导入」，
    再顺着给出「可直接反编译」—— 失败必须能和「真的是空导入表」区分开。
    """
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        names = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                if imp.name:
                    names.append(imp.name.decode("latin1", "replace"))
        return names
    except Exception:
        return None


@server.tool()
@_path_alias
def seep_packer_detect(binary_path: str) -> str:
    """加壳/反调试静态识别：判壳 + 反调试导入 + 反虚拟机字符串，并给出处置路由。

    这是把 MANUAL/UNPACKING.md（壳速查/OEP/脱壳路径）与 MANUAL/ANTI-DEBUG.md
    （反调试信号→处置）两本手册**工具化**：不用人肉翻手册，一条命令给出
    "这是不是壳、什么壳、有没有反调试、下一步该走哪本手册的哪一节"。

    Args:
        binary_path: PE 文件路径
    """
    if not os.path.isfile(binary_path):
        return f"[ERROR]: file not found: {binary_path}"
    if not binary_path.lower().endswith((".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".efi")):
        return f"[ERROR]: seep_packer_detect 仅支持 PE 文件（.exe/.dll/.sys 等），当前: {os.path.basename(binary_path)}"

    result = {
        "file": os.path.basename(binary_path),
        "status": "unknown",
        "packed": None,
        "packer_hints": [],
        "strong_signals": [],
        "weak_signals": [],
        "high_entropy_sections": [],
        "antidebug_imports": [],
        "injection_imports": [],
        "antivm_strings": [],
        "why": "",
        "route": [],
        "manual": [],
    }
    sections = []
    iat_dir_size = 0
    parse_error = ""
    read_error = ""
    blob = b""
    has_clr = False

    def _unknown(why, fix):
        """第 5 轮评审 P1：**判不了 ≠ 没壳**。失败一律 packed=null + status=unknown，
        且不给「可直接反编译」这类下一步。"""
        result["status"] = "unknown"
        result["packed"] = None
        result["why"] = why
        result["route"] = ["没能判定：先解决 %s，别当成没壳" % fix]
        result["manual"] = ["MANUAL/UNPACKING.md", "MANUAL/ANTI-DEBUG.md"]
        result["sections"] = sections
        result["next_actions"] = [{"why": result["route"][0], "action": fix}]
        return json.dumps(result, indent=2, ensure_ascii=False)

    # 1) 节名/节熵（pefile）
    try:
        import pefile
    except Exception as exc:  # noqa: BLE001
        pefile = None
        parse_error = "pefile 不可用（%s: %s）" % (type(exc).__name__, exc)
    if pefile is not None:
        try:
            pe = pefile.PE(binary_path, fast_load=True)
            # CLR/.NET 检测（数据目录第 14 项）
            try:
                dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
                clr = dd[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
                has_clr = bool(clr.VirtualAddress and clr.Size)
            except Exception:
                has_clr = False
            try:
                iat_dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
                iat_dir_size = int(getattr(iat_dd, "Size", 0) or 0)
            except Exception:
                iat_dir_size = 0
            for s in pe.sections:
                name = s.Name.rstrip(b"\x00").decode("latin1", "replace")
                data = s.get_data()
                ent = _entropy_bytes(data) if data else 0.0
                sections.append({"name": name, "raw_size": s.SizeOfRawData,
                                 "entropy": round(ent, 2)})
                if name in _PACKER_SECTIONS:
                    result["packer_hints"].append(f"section:{name}")
                if ent > 7.0 and s.SizeOfRawData > 512:
                    result["high_entropy_sections"].append(f"{name}({round(ent,2)})")
        except Exception as exc:  # noqa: BLE001
            parse_error = "PE 解析失败（%s: %s）" % (type(exc).__name__, exc)
    result["has_clr"] = has_clr

    # 2) 壳字符串特征（原始字节）
    try:
        with open(binary_path, "rb") as f:
            blob = f.read(8 * 1024 * 1024)
        for sig in _PACKER_STRINGS:
            if sig in blob:
                result["packer_hints"].append(f"string:{sig.decode('latin1')}")
    except OSError as exc:
        read_error = "目标文件读不出（%s: %s）" % (type(exc).__name__, exc)

    if parse_error or read_error:
        why = "；".join(x for x in (parse_error, read_error) if x)
        if "pefile" in parse_error:
            fix = "pefile（解析工具不可用：装/修 pefile 后重跑）"
        elif read_error:
            fix = "文件权限/占用（确认这个文件现在能读）"
        else:
            fix = "解析工具/文件完整性（换 rebar/r2 交叉验证，或先解密）"
        return _unknown(why, fix)

    # 3) 导入表（失败 = None，必须与「真的是空导入表」区分）
    imports = _read_pe_imports(binary_path)
    if imports is None:
        return _unknown("导入表读不出（pefile 解析 IMAGE_DIRECTORY_ENTRY_IMPORT 异常）",
                        "导入表解析（换 rebar/r2 交叉验证，或先确认文件没被加密）")

    # 4) 强/弱分层：CRT/运行时常见符号只进 weak_signals，不参与 antidebug/injection 结论
    imported = sorted(set(imports))
    weak_imports = sorted(n for n in imported if n in _WEAK_RUNTIME_IMPORTS)
    strong_imports = sorted(
        n for n in imported
        if n not in _WEAK_RUNTIME_IMPORTS
        and (n in _ANTIDEBUG_IMPORTS or n in _INJECTION_IMPORTS))
    result["antidebug_imports"] = [n for n in strong_imports if n in _ANTIDEBUG_IMPORTS]
    result["injection_imports"] = [n for n in strong_imports if n in _INJECTION_IMPORTS]
    result["weak_signals"] = ["import:%s" % n for n in weak_imports]

    # 5) 反虚拟机字符串（不单独构成判壳结论）
    av = sorted({s.decode() for s in _ANTIVM_STRINGS if s in blob})
    result["antivm_strings"] = av

    # 6) 判定：只有同文件 ≥2 个**强特征**才判「有保护」。
    #    高熵节/弱导入只进 weak_signals（有壳通常也有高熵，但高熵本身不是壳的证明）。
    strong = list(result["packer_hints"])
    strong += ["import:%s" % n for n in strong_imports]
    if iat_dir_size > 0 and not imported:
        strong.append("iat:empty-with-directory")
    result["strong_signals"] = list(dict.fromkeys(strong))
    result["weak_signals"] += ["entropy:%s" % x for x in result["high_entropy_sections"]]
    result["status"] = "ok"
    result["packed"] = len(result["strong_signals"]) >= 2
    if result["packed"]:
        result["why"] = ("解析成功；命中 %d 个强特征（≥2 才判有保护）：%s"
                         % (len(result["strong_signals"]),
                            "、".join(result["strong_signals"][:6])))
    elif result["strong_signals"]:
        result["why"] = ("解析成功；只有 %d 个强特征（不够 ≥2 的判壳门槛）：%s"
                         % (len(result["strong_signals"]),
                            "、".join(result["strong_signals"][:6])))
    else:
        result["why"] = "解析成功；没有强特征"
        if result["weak_signals"]:
            result["why"] += "；weak_signals=%d 个（不构成反调试/注入结论）" % len(result["weak_signals"])

    # 7) 路由
    if result.get("has_clr"):
        result["route"].append(".NET/CLR 程序 → 用 dnSpy/ILSpy 反编译看 IL；混淆用 de4dot，加密看 UNPACKING §五")
    if result["packed"]:
        result["route"].append("有壳 → 先脱壳：读 MANUAL/UNPACKING.md §一(壳速查) + §二(OEP/Dump)")
    elif result["strong_signals"]:
        result["route"].append("只有 1 个强特征（不够判壳）→ 先交叉验证，别当成没壳，也别直接脱壳")
    if result["antidebug_imports"]:
        result["route"].append("有强反调试导入 → 读 MANUAL/ANTI-DEBUG.md §二(PEB系列) + §七(两击熔断)")
    if result["injection_imports"]:
        result["route"].append("有强注入/自修改/内存篡改类导入（CreateRemoteThread/WriteProcessMemory 等）→ 重点看自修改代码与方法 Hook，按 UNPACKING §二 内存 Dump + ANTI-DEBUG §六 代理 DLL")
    if result["antivm_strings"]:
        result["route"].append("有反虚拟机特征 → 优先真机/裸金属，或按 ANTI-DEBUG §四 处理环境检测")
    if not result["packed"] and not result["strong_signals"]:
        if result["weak_signals"]:
            result["route"].append(
                "未检出壳的强特征；weak_signals=%d 个（CRT/标准运行时也常见，不构成反调试/注入结论）"
                "→ 按普通 PE 分析，先用 seep_auto_triage 交叉验证" % len(result["weak_signals"]))
        else:
            result["route"].append("未检出壳/反调试/注入的强特征 → 可 seep_r2_decompile 反编译（再用 auto_triage 交叉验证）")

    result["manual"] = ["MANUAL/UNPACKING.md", "MANUAL/ANTI-DEBUG.md"]
    result["sections"] = sections

    # ── 把"路线"变成可执行动作（散文没人照着做；命令能直接复制）──────────────
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    binp = os.path.abspath(binary_path)
    acts: List[Dict[str, Any]] = []
    nz = [x for x in sections if (x.get("raw_size") or 0) > 0]
    # 「整盘加密」判据（两条任一）：
    #  ① 标准代码/数据节（.text/.rdata/.data/.pdata）RawSize 全为 0 —— 内容被搬走
    #  ② 单个节占了文件 90% 以上且熵 > 7.5 —— 所有内容被塞进一个加密块
    _std = {".text", ".rdata", ".data", ".pdata", "_rdata", ".code", ".bss"}
    _std_secs = [x for x in sections if str(x.get("name", "")).lower() in _std]
    _zero_std = bool(_std_secs) and all((x.get("raw_size") or 0) == 0 for x in _std_secs)
    _tot = sum((x.get("raw_size") or 0) for x in sections) or 1
    _big = max(((x.get("raw_size") or 0), (x.get("entropy") or 0)) for x in sections) if sections else (0, 0)
    _one_blob = (_big[0] / _tot) > 0.90 and _big[1] > 7.5
    body_all_encrypted = _zero_std or _one_blob
    if result["packed"]:
        acts.append({"why": "判壳结论先落账本（否则后面所有结论都没有证据链）",
                     "cmd": 'python "%s/Tool/scripts/case_state.py" init --case <案例目录> --target "%s"'
                            % (root.replace("\\", "/"), binp.replace("\\", "/"))})
        acts.append({"why": "脱壳流程：壳速查 + OEP/Dump（**不要**在密文上反汇编）",
                     "read": os.path.join(root, "MANUAL", "UNPACKING.md")})
        acts.append({"why": "反调试/反VM 处置（有壳通常配套）",
                     "read": os.path.join(root, "MANUAL", "ANTI-DEBUG.md")})
        acts.append({"why": "同类壳的历史战法（知识库 412 篇）",
                     "tool": "mcp__seep__seep_kb_search", "args": {"query": "脱壳 OEP dump 壳 识别"}})
        if body_all_encrypted:
            result["warning"] = (
                "原节 RawSize 基本全为 0、主体内容集中在一个高熵畸形节里 —— 文件字节是**密文**。"
                "此时对文件做反汇编/字符串提取/熵剖面只会得到垃圾结论（实测踩过：capstone 反出 "
                "`ret 0x2d5a`、`mov esi,0xa4395bd7` 之类无意义指令）。正确顺序：动态取解密后镜像 → "
                "dump → 修 IAT → 再静态分析。"
            )
            result["forbidden_next"] = ["对文件字节做 capstone/反汇编", "对文件字节做 strings/关键字扫描",
                                        "在文件里手工找 OEP 字节"]
    elif result["strong_signals"]:
        acts.append({"why": "只有单个强特征，不够判壳：先交叉验证，别当成没壳",
                     "tool": "mcp__seep__seep_auto_triage", "args": {"target_path": binp}})
    elif result["weak_signals"]:
        acts.append({"why": "只有弱信号（CRT/运行时常见），不构成壳/反调试结论：先交叉验证",
                     "tool": "mcp__seep__seep_auto_triage", "args": {"target_path": binp}})
        acts.append({"why": "没有壳的强特征 → 可反编译（结论仍以 auto_triage 为准）",
                     "tool": "mcp__seep__seep_r2_decompile", "args": {"binary_path": binp}})
    else:
        acts.append({"why": "未检出壳的强特征 → 可反编译（再用 auto_triage 交叉验证）",
                     "tool": "mcp__seep__seep_r2_decompile", "args": {"binary_path": binp}})
    result["next_actions"] = acts

    # M2/M4：自动建案 + 需要用户提供什么（命中就问，不许自己假设"没有"）
    _case = _case_for(binary_path, "判壳 脱壳 反调试 加壳识别")
    if _case.get("case"):
        result["case"] = _case
    _needs = _detect_needs(b"", "", _case.get("case") if _case.get("created") else "")
    if _needs:
        result["need_from_user"] = _needs
        result["ask_policy"] = ("这些是**必须问用户**的输入；先问再动手。用户答『没有』才选 B（保守那一条），"
                               "并把答案记进账本（case_state.py ask/ack）。")
    return json.dumps(result, indent=2, ensure_ascii=False)


# 兼容不同 MCP/FastMCP 版本：有的版本 `@server.tool()` 返回 FunctionTool（原函数在 `.fn`），
# 有的返回裸函数。自检/评审脚本统一用 `seep_packer_detect.fn(...)` 直调，这里补稳定入口。
if not hasattr(seep_packer_detect, "fn"):
    seep_packer_detect.fn = seep_packer_detect


# ---------------------------------------------------------------------------
# 凭据脱敏基础设施（REQUIREMENTS.md 三 · PM-SPEC.md §6：凭据不落盘、不进输出、不进日志）
#
# ★ 脱敏策略（可机检，明确写死，不是"看着像就放过"）：
#   P1 键名黑名单（`_CRED_KEY_RE`，大小写不敏感正则）+ 显式元数据白名单（`_CRED_META_KEYS`）。
#      凡进入"输出/落盘"的字典，键名命中黑名单 → 其值整段替换为 `[REDACTED]`；
#      白名单只放"凭据元数据/人读说明"（如 cookies_redacted、cookie_counts、header_keys），
#      它们的值只能是布尔/计数/键名列表/固定文案，永远不含凭据值。
#   P2 值断言（`_assert_redacted`）：把本次已知的真实凭据值（cookie 值、敏感头值，
#      含 URL 编码变体）当子串扫描序列化后的载荷，以及递归校验 P1：
#      "键名命中黑名单" ⇒ "每个叶子值必须恰好是 [REDACTED]"。任一不满足 → 抛
#      `RedactionFailure`（**绝不 try/except 吞掉**，整个调用失败）。
#   P3 落盘白名单（`_http_session_snapshot`）：session_file 只接受显式字段
#      （schema/时间/方法/URL/状态码/头部"键名"/条数），入参里根本没有 header 值、cookie 值。
# 三层互为兜底：P3 让凭据进不了落盘载荷，P1 兜住新增字段，P2 兜住 P1/P3 的漏项与编码变体。
REDACTED = "[REDACTED]"

# 命中即视为凭据的键名（Cookie / Set-Cookie / Authorization / X-Api-Key / Token / 会话…）
_CRED_KEY_RE = re.compile(
    r"cookie|authorization|auth|api[-_]?key|apikey|access[-_]?key|private[-_]?key|key|token|"
    r"secret|passw|passwd|pwd|session|jwt|bearer|credential|signature|ticket|nonce|csrf|xsrf|sid",
    re.IGNORECASE)

# 白名单：凭据"元数据"与人读说明字段（不含凭据值，仍要过 P2 的值扫描）
_CRED_META_KEYS = {
    "cookies_redacted", "cookie_counts", "cookie_count", "set_cookie_names",
    "header_keys", "request_header_keys", "response_header_keys", "session",
}

_HTTP_SESSION_SCHEMA = "seep.http-session/2"   # v1 = 旧版裸 cookie 字典，已废弃（凭据不落盘）


class RedactionFailure(RuntimeError):
    """脱敏失败：宁可让调用失败，也不把凭据泄漏到输出/磁盘。"""


def _http_iso_now() -> str:
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _redact_map(mapping, secrets=()) -> dict:
    """P1：键名命中黑名单 → 值换 [REDACTED]；非敏感键保留原值，但会把已知凭据值清掉。"""
    if not isinstance(mapping, dict):
        raise RedactionFailure("期望 dict 才能脱敏，实际 %s" % type(mapping).__name__)
    out = {}
    for key, val in mapping.items():
        name = str(key)
        if _CRED_KEY_RE.search(name):
            out[name] = REDACTED
        elif isinstance(val, (str, int, float, bool)) or val is None:
            out[name] = _scrub_text(val, secrets) if isinstance(val, str) else val
        else:
            out[name] = _scrub_text(str(val), secrets)
    return out


def _redact_cookie_map(cookie_map) -> dict:
    """cookie 名→值：**值无条件**替换为 [REDACTED]。

    为什么不看键名：cookie 名可以任意命名（sid/uid/token/foo 都可能），
    按黑名单判断会漏 → 这里用"全量替换"的硬白名单（只保留键名）。
    """
    if not isinstance(cookie_map, dict):
        raise RedactionFailure("期望 dict 才能脱敏，实际 %s" % type(cookie_map).__name__)
    return {str(k): REDACTED for k in cookie_map}


def _redact_url(url: str, secrets=()) -> str:
    """URL 里的凭据也要脱：userinfo（user:pass@）与敏感 query 参数值，再清洗已知凭据值。"""
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, quote
    try:
        sp = urlsplit(str(url))
    except Exception as exc:  # 解析不了 → 无法保证脱敏 → 让调用失败（不静默放行）
        raise RedactionFailure("URL 无法解析，无法保证不泄漏: %s" % type(exc).__name__)
    netloc = sp.netloc
    if "@" in netloc:
        netloc = REDACTED + "@" + netloc.rsplit("@", 1)[1]
    pairs = []
    for k, v in parse_qsl(sp.query, keep_blank_values=True):
        if _CRED_KEY_RE.search(k):
            pairs.append(quote(str(k), safe="") + "=" + REDACTED)   # 敏感参数：值整段替换
        else:
            pairs.append(quote(str(k), safe="") + "=" + quote(_scrub_text(v, secrets), safe=""))
    return urlunsplit((sp.scheme, netloc, sp.path, "&".join(pairs), sp.fragment))


def _secret_variants(value: str) -> list:
    """真实凭据值的编码变体（原文 / URL 编码 / 反转义），用于 P2 子串扫描与正文预清洗。"""
    from urllib.parse import quote, unquote
    raw = str(value)
    out = {raw, quote(raw, safe=""), unquote(raw)}
    return [s for s in out if len(s) >= 4]


def _known_secrets(cookie_maps=(), header_maps=(), url: str = "") -> list:
    """收集本次已知的真实凭据值。

    cookie_maps：cookie 名→值（cookie 名可能不含敏感词，所以**所有值**都算凭据）；
    header_maps：头名→值（只收命中 `_CRED_KEY_RE` 的头值，如 Set-Cookie/Authorization）；
    url：URL 里的 userinfo 密码与敏感 query 参数值（?token=/&session= 也是凭据）。
    """
    found = []
    for ck_map in cookie_maps:
        if not isinstance(ck_map, dict):
            continue
        for val in ck_map.values():
            if isinstance(val, (str, int, float)):
                found.extend(_secret_variants(val) if isinstance(val, str) else [])
    for hdr_map in header_maps:
        if not isinstance(hdr_map, dict):
            continue
        for key, val in hdr_map.items():
            if not _CRED_KEY_RE.search(str(key)):
                continue
            if isinstance(val, (str, int, float)):
                found.extend(_secret_variants(val) if isinstance(val, str) else [])
    for val in _url_secrets(url):
        found.extend(_secret_variants(val))
    return sorted(set(found), key=len, reverse=True)


def _url_secrets(url: str) -> list:
    """从 URL 里取出凭据类片段（userinfo 密码 / 敏感 query 值），用于清洗与断言。"""
    from urllib.parse import urlsplit, parse_qsl
    try:
        sp = urlsplit(str(url))
    except Exception:
        return []           # 解析不了一律靠 _redact_url 报错，不在错误路径二次抛异常
    out = []
    if "@" in sp.netloc:
        userinfo = sp.netloc.rsplit("@", 1)[0]
        if ":" in userinfo:
            out.append(userinfo.split(":", 1)[1])
    for k, v in parse_qsl(sp.query, keep_blank_values=True):
        if v and _CRED_KEY_RE.search(str(k)):
            out.append(v)
    return [s for s in out if s]


def _scrub_text(text: str, secrets) -> str:
    """把已知凭据值从自由文本（如 body_preview）里替换掉。"""
    if not isinstance(text, str):
        raise RedactionFailure("期望 str 才能清洗，实际 %s" % type(text).__name__)
    for s in secrets:
        if s in text:
            text = text.replace(s, REDACTED)
    return text


def _assert_redacted(payload, secrets, where: str) -> None:
    """P2 断言：P1 递归校验 + 已知凭据值子串扫描；不通过 → RedactionFailure。"""
    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                name = str(k)
                sub = f"{path}.{name}"
                if name.lower() in _CRED_META_KEYS:
                    # 元数据（计数/键名列表/固定文案）：跳过 P1 键名检查；若被塞进嵌套 dict，仍递归查 P1。
                    # 它们的字符串叶子里的凭据值由下面的全局值扫描兜住。
                    if isinstance(v, dict):
                        walk(v, sub)
                    continue
                if _CRED_KEY_RE.search(name):
                    leaves = []
                    def collect(n):
                        if isinstance(n, dict):
                            for vv in n.values():
                                collect(vv)
                        elif isinstance(n, (list, tuple)):
                            for vv in n:
                                collect(vv)
                        else:
                            leaves.append(n)
                    collect(v)
                    if not leaves:
                        continue
                    if any(leaf != REDACTED for leaf in leaves):
                        raise RedactionFailure(f"{where}: 敏感键 {sub} 的值未脱敏")
                    continue
                walk(v, sub)
        elif isinstance(node, (list, tuple)):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    walk(payload, "$")
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    hits = [s for s in secrets if s in text]
    if hits:
        raise RedactionFailure(f"{where}: 载荷里仍出现 {len(hits)} 个已知凭据值（值本身不打印）")


def _http_session_snapshot(method, url, status, req_headers, resp_headers, set_cookie_names,
                           body_len, secrets=()) -> dict:
    """P3 落盘白名单：只产出非凭据字段；函数签名里没有 cookie 值/头值的位置。"""
    return {
        "schema": _HTTP_SESSION_SCHEMA,
        "at": _http_iso_now(),
        "cookies_redacted": True,
        "last_request": {
            "method": method,
            "url": _redact_url(url, secrets),
            "status": status,
            "header_keys": sorted(str(k) for k in (req_headers or {})),
            "body_len": body_len,
        },
        "last_response": {
            "header_keys": sorted(str(k) for k in (resp_headers or {})),
            "set_cookie_names": sorted(str(n) for n in (set_cookie_names or [])),
        },
        "note": ("本文件只存非凭据会话快照（时间/方法/URL/头名/状态码）；"
                 "Cookie、Authorization、X-Api-Key 等值一律不落盘。"
                 "会话保持请在同一次调用里传 cookies（内存），不要指望从磁盘读回凭据。"),
    }


@server.tool()
def seep_http_replay(
    url: str,
    method: str = "GET",
    headers: str = "{}",
    cookies: str = "{}",
    body: str = "",
    impersonate: str = "chrome",
    session_file: str = "",
    timeout: int = 30,
) -> str:
    """协议请求构造与重放（最强的协议层能力）：TLS 指纹伪装 + Cookie 会话管理 + 任意方法/头/体。

    为什么用它：普通 requests 的 TLS 指纹会被反爬/风控识别。本工具优先用 curl_cffi
    伪装 Chrome/Safari/Edge 的 TLS 指纹（绕过基础反爬），并支持 `session_file` 会话快照。
    ★ 凭据不落盘 / 不进输出（REQUIREMENTS.md 三 · PM-SPEC.md §6）：`session_file` 只写
      时间/方法/URL/头名/状态码这类非凭据信息；回包里的 cookie 值一律 `[REDACTED]`
      （保留键名与条数 + `cookies_redacted: true`）。会话保持靠本次调用的内存 cookie 参数。

    若本机无 curl_cffi，自动降级到 requests（仍可用，只是 TLS 指纹不伪装）。

    Args:
        url: 目标 URL
        method: GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS
        headers: JSON 字符串，如 '{"User-Agent":"...","Referer":"..."}'
        cookies: JSON 字符串，如 '{"session":"abc"}'
        body: 请求体（POST/PUT 时用；JSON 直接传字符串，或表单串）
        impersonate: TLS 指纹伪装目标 chrome/safari/edge/ff（仅 curl_cffi 生效）
        session_file: 若给出，则写入**非凭据**会话快照（时间/方法/URL/头名/状态码）；
            Cookie、Authorization 等凭据**永不落盘**（REQUIREMENTS.md 三 · PM-SPEC.md §6）。
            会话保持请在同一次调用里传 cookies（内存），不要从磁盘读回凭据。
        timeout: 超时秒数
    """
    method = method.upper()
    try:
        hdr = json.loads(headers) if headers.strip() else {}
    except Exception as exc:
        return f"[ERROR]: headers 不是合法 JSON: {exc}"
    try:
        ck = json.loads(cookies) if cookies.strip() else {}
    except Exception as exc:
        return f"[ERROR]: cookies 不是合法 JSON: {exc}"

    # 会话快照：v2 只含非凭据信息；v1（旧版裸 cookie 字典）只在内存里兼容读入，**绝不回写**
    session_read_note = ""
    if session_file and os.path.isfile(session_file):
        try:
            with open(session_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
        except (OSError, ValueError) as exc:
            saved = None
            session_read_note = f"会话快照读取失败(已忽略，不影响本次请求): {type(exc).__name__}"
        if isinstance(saved, dict) and saved.get("schema") != _HTTP_SESSION_SCHEMA:
            # 旧版文件：只在内存里用，凭据不回写（不落盘、不回显）
            legacy_ck = {str(k): v for k, v in saved.items() if isinstance(v, str)}
            if legacy_ck:
                merged = dict(legacy_ck)
                merged.update(ck)
                ck = merged
                session_read_note = (f"旧版会话文件中的 {len(legacy_ck)} 个 cookie 仅本次内存使用；"
                                     "新版快照不再落盘凭据")

    backend = ""
    resp_status = None
    resp_headers = {}
    resp_text = ""
    set_cookies = {}

    # 优先 curl_cffi（TLS 指纹伪装）
    try:
        from curl_cffi import requests as cffi_requests
        backend = f"curl_cffi(impersonate={impersonate})"
        kwargs = {"timeout": timeout, "headers": hdr, "cookies": ck}
        if impersonate and impersonate not in ("", "none"):
            kwargs["impersonate"] = impersonate
        if method in ("POST", "PUT", "PATCH") and body:
            kwargs["data"] = body
        r = cffi_requests.request(method, url, **kwargs)
        resp_status = r.status_code
        resp_headers = dict(r.headers)
        resp_text = r.text
        try:
            set_cookies = dict(r.cookies.get_dict())
        except Exception:
            set_cookies = {}
    except Exception as exc_cffi:
        # 降级 requests
        try:
            import requests as req
            backend = f"requests(降级，无TLS伪装；curl_cffi失败:{type(exc_cffi).__name__})"
            kwargs = {"timeout": timeout, "headers": hdr, "cookies": ck}
            if method in ("POST", "PUT", "PATCH") and body:
                kwargs["data"] = body
            r = req.request(method, url, **kwargs)
            resp_status = r.status_code
            resp_headers = dict(r.headers)
            resp_text = r.text
            try:
                set_cookies = r.cookies.get_dict()
            except Exception:
                set_cookies = {}
        except Exception as exc_req:
            msg = (f"[ERROR]: 请求失败。curl_cffi: {type(exc_cffi).__name__}: {exc_cffi} | "
                   f"requests: {type(exc_req).__name__}: {exc_req}")
            # 异常文案常带 URL/头值（库里会把请求信息拼进异常），同样脱敏后才回给模型
            return _scrub_text(msg, _known_secrets([ck], [hdr], url))

    # 本次已知的真实凭据值：只在内存里流转，用来「清洗 + 断言」，绝不进载荷
    secrets = _known_secrets([ck, set_cookies], [hdr, resp_headers], url)

    # 写会话快照：只写非凭据字段（P3 白名单）
    saved_note = ""
    if session_file:
        try:
            snapshot = _http_session_snapshot(method, url, resp_status, hdr, resp_headers,
                                              list(set_cookies), len(body), secrets)
            blob = json.dumps(snapshot, ensure_ascii=False, indent=2)
            # P2：先断言再落盘（顺序不能反）；不通过就抛，绝不写盘
            _assert_redacted(snapshot, secrets, "session_file")
            with open(session_file, "w", encoding="utf-8") as f:
                f.write(blob)
                f.write("\n")
            saved_note = (f"非凭据会话快照已写入 {session_file}"
                          f"（cookie {len(ck)} 个 / set-cookie 名 {len(set_cookies)} 个已脱敏，值不落盘）")
        except RedactionFailure:
            raise                      # 脱敏失败必须让调用失败（不得降级成提示）
        except OSError as exc:
            saved_note = f"会话快照写入失败(非凭据，不影响本次响应): {type(exc).__name__}: {exc}"

    # 输出：所有凭据值 → [REDACTED]（保留键名与条数，便于判断有没有登录态）
    body_preview = _scrub_text(resp_text[:2000], secrets)
    out = {
        "backend": backend,
        "request": {"method": method, "url": _redact_url(url, secrets),
                    "headers": _redact_map(hdr, secrets),
                    "cookies": _redact_cookie_map(ck),
                    "body_len": len(body)},
        "status": resp_status,
        "response_headers": _redact_map(resp_headers, secrets),
        "set_cookies": _redact_cookie_map(set_cookies),
        "cookies_redacted": True,
        "cookie_counts": {"request": len(ck), "response_set": len(set_cookies)},
        "body_preview": body_preview,
        "body_len": len(resp_text),
    }
    notes = [n for n in (session_read_note, saved_note) if n]
    if notes:
        out["session"] = "；".join(notes)
    # P2：出厂前再断言一次（这一行是“凭据不进输出”的机检闸门）
    _assert_redacted(out, secrets, "http_replay_output")
    return json.dumps(out, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# 扩展资产 第三批续（P3 渗透轻量补充，2026-10 增补）
# 纯增量：不修改任何既有工具逻辑，只在末尾追加。
#   seep_web_recon       —— Web 目标轻量侦察（指纹/头/目录/技术栈），只读不攻击
# 设计原则：渗透与逆向/协议相关的那一小部分（Web 指纹、接口发现、头分析），
#   补一个“轻量侦察”工具即可，不塞扫描器/爆破/利用框架（那会让主服务臃肿、且与逆向无关）。
#   重型渗透若需要，走独立 MCP（如 pentestMCP），不并入 seep 内核。
# ---------------------------------------------------------------------------

# 常见技术栈指纹（响应头 + 页面特征）
_WEB_FINGERPRINTS = {
    "server": ["nginx", "apache", "iis", "cloudflare", "openresty", "tomcat", "jetty", "caddy"],
    "framework": ["thinkphp", "spring", "laravel", "django", "flask", "express", "next.js", "nuxt",
                  "vue", "react", "angular", "jquery", "bootstrap"],
    "lang": ["php", "asp.net", "java", "python", "node.js", "ruby"],
    "cdn_waf": ["cloudflare", "akamai", "fastly", "aliyun", "tencent", "waf", "imperva", "sucuri"],
}
_SECURITY_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options",
                     "x-content-type-options", "referrer-policy", "permissions-policy",
                     "x-xss-protection", "access-control-allow-origin"]


# ---------------------------------------------------------------------------
# 工具自动发现 + 自动适配 MCP（轻量插件，2026-10 增补，纯增量）
# 逻辑在 Tool/mcp/tool_autodiscover.py + Tool/config/tool-capabilities.json；
# 发现状态落本机 ~/.seep/tools.local.json（gitignore，绝不入库）。
# 下面几个是薄封装：不修改任何既有工具，只在末尾追加。
# ---------------------------------------------------------------------------
def _autodiscover():
    """惰性导入自动发现插件；失败时返回 None（不拖垮整个 MCP 服务）。"""
    try:
        import tool_autodiscover as _tad  # 同目录
        return _tad
    except Exception:
        try:
            import importlib.util as _ilu
            _p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tool_autodiscover.py")
            _spec = _ilu.spec_from_file_location("tool_autodiscover", _p)
            _mod = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)
            return _mod
        except Exception:
            return None


@server.tool()
def seep_tool_discover(tool_id: str, target: str = "", record_state: bool = True) -> str:
    """六层递进发现本机某工具是否可用（环境变量/PATH/常见目录/注册表/递归扫描/别名）。

    比 seep_ensure_tool 更全：多出 Windows 注册表『已安装程序』探测 + 别名映射 + 架构匹配。
    若给了 target（PE 文件），会读 machine 字段决定 32/64 位（x32dbg/x64dbg）。
    发现结果默认记入本机 ~/.seep/tools.local.json（不进仓库）。

    Args:
        tool_id: 工具标识（支持别名，如 windbg->cdb, die->diec, radare2->r2）。
        target: 可选目标文件；PE 时用于架构匹配。
        record_state: 是否把结果写入本机状态缓存（默认 True）。
    """
    tad = _autodiscover()
    if tad is None:
        return "[ERROR]: tool_autodiscover 插件不可用（检查 Tool/mcp/tool_autodiscover.py）"
    res = tad.discover(tool_id, target=target or None)
    if record_state:
        try:
            tad.record(tool_id, res)
        except Exception:
            pass
    return json.dumps(res, indent=2, ensure_ascii=False)


def _case_lib_dir() -> str:
    """案例库根目录（仓库根/Tool/cases，不使用 SEEP_WORKSPACE 覆盖）。"""
    repo_root = os.path.dirname(os.path.dirname(BASE_DIR))  # Tool/mcp -> Tool -> 仓库根
    return os.path.join(repo_root, "Tool", "cases")


def _case_files() -> list:
    """返回 [(目录名, case.json 绝对路径)]，按目录名排序。"""
    root = _case_lib_dir()
    found = []
    if not os.path.isdir(root):
        return found
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if not os.path.isdir(path) or name.startswith(".") or name == "__pycache__":
            continue
        case_path = os.path.join(path, "case.json")
        if os.path.isfile(case_path):
            found.append((name, case_path))
    return found


def _case_normalize(raw, dirname):
    """把 case.json 归一成稳定结构；坏字段退回安全默认值。"""
    if not isinstance(raw, dict):
        raw = {}
    entry = {"dir": dirname}
    for field, default in (
        ("id", ""), ("domain", ""), ("target_type", ""),
        ("protection", []), ("authority", ""), ("goal_level", ""),
        ("outcome", ""), ("artifacts", []), ("lessons", []),
        ("tags", []), ("refs", []), ("updated", ""),
    ):
        value = raw.get(field, default)
        if isinstance(default, list):
            if not isinstance(value, list):
                value = []
            elif field == "artifacts":
                value = [x for x in value if isinstance(x, dict)]
            else:
                value = [x for x in value if isinstance(x, str)]
        elif not isinstance(value, str):
            value = ""
        entry[field] = value
    if not entry["id"]:
        entry["id"] = dirname
    return entry


def _case_load(prefer_index: bool = True):
    """载入案例：**始终实时扫描** case.json（S2 起已无索引文件可读）。

    保留 prefer_index 形参只为不改调用点签名；它不再改变行为，
    也就不存在「读过期缓存」这类失败模式。
    """
    pairs = _case_files()
    if not pairs:
        return [], "empty"
    cases = []
    for dirname, path in pairs:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                raw = json.load(fh)
        except Exception:
            raw = {}
        cases.append(_case_normalize(raw, dirname))
    return cases, "scan"


def _case_tokens(query: str) -> list:
    parts = re.split(r"[\s,;/|、，。；：!?()（）\[\]【】]+", (query or "").strip())
    return [p.lower() for p in (x.strip() for x in parts) if p][:8]


def _case_text(entry, field: str) -> str:
    value = entry.get(field, "")
    if isinstance(value, list):
        return "\n".join(str(x) for x in value)
    return str(value or "")


# === SEEP-EXT: case-lib BEGIN ===
# 案例库只读检索：Tool/cases/*/case.json（结构约定见 Tool/docs/CASE-LIB.md）；无副作用。
@server.tool()
def seep_case_read(case_id: str) -> str:
    """读取单个案例的完整上下文：case.json 全文 + facts.jsonl 前 20 行 + README 前 80 行。

    Args:
        case_id: 案例标识，可用 case.json 的 id 或目录名（如 "项目K" / "案例-6.9换肤壳"），
                  可通过 seep_case_search 获得
    """
    try:
        key = (case_id or "").strip()
        if not key:
            return "[ERROR]: case_id 不能为空"
        cases, _source = _case_load(prefer_index=False)
        target = None
        for entry in cases:
            if key == str(entry.get("id", "")) or key == str(entry.get("dir", "")):
                target = entry
                break
        if target is None:
            for entry in cases:
                if key.lower() in (str(entry.get("id", "")).lower(), str(entry.get("dir", "")).lower()):
                    target = entry
                    break
        if target is None:
            available = "、".join(str(c.get("id", c.get("dir", ""))) for c in cases[:20])
            return "[ERROR]: Case not found: %s（可用案例：%s；用 `case_state.py index` 看全量索引）" % (key, available or "无")

        case_dir = os.path.join(_case_lib_dir(), target.get("dir", ""))
        case_path = os.path.join(case_dir, "case.json")
        parts = []
        if os.path.isfile(case_path):
            with open(case_path, "r", encoding="utf-8", errors="replace") as fh:
                parts.append("[case.json]\n" + fh.read().strip())
        else:
            parts.append("[case.json]\n(缺失，以下为内存归一化结果)\n" + json.dumps(target, indent=2, ensure_ascii=False))

        facts_path = os.path.join(case_dir, "facts.jsonl")
        if os.path.isfile(facts_path):
            lines = []
            try:
                with open(facts_path, "r", encoding="utf-8", errors="replace") as fh:
                    for idx, line in enumerate(fh):
                        if idx >= 20:
                            break
                        line = line.rstrip("\r\n")
                        if line.strip():
                            lines.append(line)
            except Exception as exc:
                lines.append("(读取失败: %s)" % exc)
            parts.append("[facts.jsonl 前20行]\n" + ("\n".join(lines) if lines else "(空)"))
        else:
            parts.append("[facts.jsonl 前20行]\n(未提供 facts.jsonl)")

        readme_path = ""
        readme_label = "[README 前80行]"
        for candidate in ("README.md", "README.txt"):
            p = os.path.join(case_dir, candidate)
            if os.path.isfile(p):
                readme_path = p
                break
        if not readme_path:
            # 有些案例把总览放在 docs/ 或 v2/README.md：按 refs 顺序回退到第一篇文档
            for ref in (target.get("refs") or []):
                p = os.path.join(case_dir, str(ref).replace("/", os.sep))
                if os.path.isfile(p) and str(ref).lower().endswith((".md", ".txt")):
                    readme_path = p
                    readme_label = "%s (回退 refs: %s)" % (readme_label, ref)
                    break
        if readme_path:
            try:
                with open(readme_path, "r", encoding="utf-8", errors="replace") as fh:
                    lines = fh.read().splitlines()[:80]
                parts.append(readme_label + "\n" + "\n".join(lines))
            except Exception as exc:
                parts.append(readme_label + "\n(读取失败: %s)" % exc)
        else:
            parts.append("[README 前80行]\n(未提供 README.md / README.txt，refs 中也没有可读文档)")

        return "\n\n".join(parts)
    except Exception as exc:
        return "[ERROR]: 案例读取失败: %s: %s" % (type(exc).__name__, exc)
# === SEEP-EXT: case-lib END ===


# D1 · import 期审计（BLUEPRINT §4）：登记表必须与注册的工具集一一对应。
# 缺一条就拒绝启动 —— 宁可起不来，也不要静默多一个「没有效果标注」的能力。
try:
    EFFECT_ANNOTATIONS = _audit_tool_effects(
        [t.name for t in server._tool_manager.list_tools()],
        os.path.join(os.path.dirname(BASE_DIR), "config", "tool-effects.json"))
except Exception as _e:   # 文件缺失 / 不一致 / 字段不合规，一律拒绝启动
    raise SystemExit("[FATAL] %s: %s" % (type(_e).__name__, _e))


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------
def main():
    """MCP Server 启动入口，使用 stdio 协议与 AI Client 通信"""
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
            sys.stdin.reconfigure(encoding="utf-8")
        except Exception:
            pass

    # 父进程（dsh web / pi / codex）退出时，POSIX 下可能发 SIGTERM。
    # 转成 SystemExit 走正常收尾，避免裸抛堆栈。
    if hasattr(signal, "SIGTERM"):
        try:
            signal.signal(signal.SIGTERM, lambda *_a: sys.exit(0))
        except (ValueError, OSError, AttributeError):
            pass  # 非主线程或平台不支持时忽略

    try:
        server.run(transport="stdio")
    except KeyboardInterrupt:
        # Ctrl+C 会广播给整个控制台进程组：父进程与 MCP 子进程会同时收到。
        # 这属于正常关闭流程，静默退出即可，不要让异常沿着
        # anyio.run → asyncio.run → runpy.run_path 一路裸抛打印堆栈。
        pass
    except (BrokenPipeError, EOFError):
        # 父进程先退出导致 stdin/stdout 关闭，同样属于正常收尾
        pass


if __name__ == "__main__":
    main()
