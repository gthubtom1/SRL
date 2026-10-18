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
        return out or err or "[Success, no output]"
    except subprocess.TimeoutExpired:
        return f"[ERROR]: Command timed out after {timeout} seconds."
    except Exception as e:
        return f"[ERROR]: Exception executing command: {str(e)}"

def _clean_r2_output(text: str) -> str:
    """移除 ANSI 颜色控制字符"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def _find_java() -> Optional[str]:
    """寻找 Java 运行时可执行路径（跨平台探测：PATH -> macOS JVM -> Linux JVM -> Windows JDK）"""
    if shutil.which("java"):
        return "java"
    candidates = [
        # Windows
        r"D:\Tool\JDK\bin\java.exe",
        r"D:\Tool\Android Studio\jbr\bin\java.exe",
        r"C:\Program Files\Java",
        r"C:\Program Files\Eclipse Adoptium",
        r"C:\Program Files\Microsoft",
        # macOS
        "/Library/Java/JavaVirtualMachines",
        "/System/Library/Frameworks/JavaVM.framework",
        "/opt/homebrew/opt/openjdk/bin/java",
        "/usr/local/opt/openjdk/bin/java",
        # Linux
        "/usr/lib/jvm",
        "/usr/java"
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
@server.tool()
def seep_status() -> str:
    """检查 seep 逆向工具链状态、内置组件就绪度及系统环境配置。"""
    java_path = _find_java()
    java_ver = "NOT FOUND (JDK 17 LTS recommended)"
    if java_path:
        out = _run_cmd([java_path, "-version"])
        first_line = out.splitlines()[0] if out else "Found"
        java_ver = f"{java_path} ({first_line})"

    r2_ver = "NOT FOUND"
    if os.path.isfile(R2_EXE):
        out = _run_cmd([R2_EXE, "-v"])
        r2_ver = out.splitlines()[0] if out else "Ready"

    jadx_status = "Ready (Batch/Jar present)" if os.path.isfile(JADX_BAT) else "Missing"
    apktool_status = "Ready (Jar present)" if os.path.isfile(APKTOOL_JAR) else "Missing"
    kb_status = f"Ready ({len(glob.glob(os.path.join(KB_DIR, '**', '*.md'), recursive=True))} documents)" if os.path.isdir(KB_DIR) else "Missing"

    status = {
        "name": "seep",
        "description": "AI-Native Reverse Engineering Toolkit MCP Server",
        "base_directory": BASE_DIR,
        "components": {
            "radare2_suite": {
                "status": "Ready" if os.path.isfile(R2_EXE) else "Missing",
                "binary": R2_EXE,
                "version": r2_ver
            },
            "jadx_decompiler": {
                "status": jadx_status,
                "path": JADX_BAT
            },
            "apktool": {
                "status": apktool_status,
                "path": APKTOOL_JAR
            },
            "java_runtime": {
                "status": "Ready" if java_path else "Not Installed / Not in PATH",
                "detail": java_ver
            },
            "reverselab_knowledge_base": {
                "status": kb_status,
                "path": KB_DIR
            },
            "hook_templates": {
                "status": "Ready" if os.path.isdir(HOOK_TEMPLATES_DIR) else "Missing",
                "path": HOOK_TEMPLATES_DIR
            }
        }
    }
    return json.dumps(status, indent=2, ensure_ascii=False)

# ---------------------------------------------------------------------------
# 2. 二进制逆向分析工具 (Radare2 引擎)
# ---------------------------------------------------------------------------
@server.tool()
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
    return _clean_r2_output(out)

@server.tool()
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
            result.append(f"... [Truncated: showing {limit} of {len(matched)} matched strings]")
        return "\n".join(result)
    else:
        result = lines[:limit]
        if len(lines) > limit:
            result.append(f"... [Truncated: showing {limit} of {len(lines)} strings]")
        return "\n".join(result)

@server.tool()
def seep_r2_functions(binary_path: str, filter_name: Optional[str] = None, limit: int = 100) -> str:
    """列出二进制文件的函数列表、入口点与导入导出符号。

    Args:
        binary_path: 目标二进制文件路径
        filter_name: 过滤函数名或符号名（不区分大小写）
        limit: 最大返回行数，默认 100
    """
    if not os.path.isfile(binary_path):
        return f"[ERROR]: Target file does not exist: {binary_path}"

    cmd = "aaa; afl"
    out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", cmd, os.path.abspath(binary_path)], timeout=60)
    lines = _clean_r2_output(out).splitlines()

    # 剔除分析阶段日志
    clean_lines = [l for l in lines if not l.startswith("INFO:") and not l.startswith("WARN:")]
    
    if filter_name:
        pat = filter_name.lower()
        filtered = [l for l in clean_lines if pat in l.lower()]
        res = filtered[:limit]
        if len(filtered) > limit:
            res.append(f"... [Truncated: showing {limit} of {len(filtered)} functions]")
        return "\n".join(res) or "[No matching functions found]"
    else:
        res = clean_lines[:limit]
        if len(clean_lines) > limit:
            res.append(f"... [Truncated: showing {limit} of {len(clean_lines)} functions]")
        return "\n".join(res)

@server.tool()
def seep_r2_disasm(
    binary_path: str,
    target: str = "main",
    lines: int = 60,
    output_mode: str = "full",
    limit_tokens: int = 0,
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
        limit_tokens: 最大输出字符数（0=不限制），超出时尾部截断并附注 Truncated 标记
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

    if limit_tokens > 0 and len(result) > limit_tokens:
        result = result[:limit_tokens] + f"\n... [TRUNCATED at {limit_tokens} chars — use offset/target narrowing for full output]"

    return result or "[Disassembly empty or symbol not found]"

@server.tool()
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
        limit_tokens: 最大输出字符数（默认 8000），超出则截断附 Truncated 标记；设 0 表示不限制
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

    if limit_tokens > 0 and len(result) > limit_tokens:
        result = result[:limit_tokens] + f"\n... [TRUNCATED at {limit_tokens} chars — 使用 target 缩小范围或 output_mode='fold'/'summary' 降低消耗]"

    return result or "[Decompile output empty]"

@server.tool()
def seep_r2_diff(file_a: str, file_b: str, mode: str = "code") -> str:
    """使用 radiff2 比对两个二进制文件的差异。

    Args:
        file_a: 第一个二进制文件路径
        file_b: 第二个二进制文件路径
        mode: 比对模式，支持 'code' (函数代码比对 -C), 'hex' (十六进制比对 -x), 'stats' (差异摘要统计 -s)
    """
    if not os.path.isfile(file_a) or not os.path.isfile(file_b):
        return f"[ERROR]: One or both files do not exist: '{file_a}', '{file_b}'"

    flag_map = {
        "code": "-C",
        "hex": "-x",
        "stats": "-s"
    }
    flag = flag_map.get(mode.lower(), "-C")
    out = _run_cmd([RADIFF2_EXE, flag, os.path.abspath(file_a), os.path.abspath(file_b)], timeout=60)
    return _clean_r2_output(out)

@server.tool()
def seep_r2_asm(code_or_hex: str, arch: str = "x86", bits: int = 64, disasm: bool = False) -> str:
    """使用 rasm2 进行机器码组装 (汇编) 或逆向反汇编。

    Args:
        code_or_hex: 汇编指令字符串 (如 'xor eax, eax; ret') 或 十六进制机器码 (如 '31c0c3')
        arch: 目标架构 (x86, arm, mips, riscv 等)，默认 x86
        bits: 位数 (16, 32, 64)，默认 64
        disasm: 为 True 时将 hex 转换为汇编代码；为 False 时将汇编代码转换为 hex 机器码。
    """
    if not os.path.isfile(RASM2_EXE):
        return f"[ERROR]: rasm2.exe not found at {RASM2_EXE}"

    cmd = [RASM2_EXE, "-a", arch, "-b", str(bits)]
    if disasm:
        cmd.extend(["-d", code_or_hex.strip()])
    else:
        cmd.append(code_or_hex.strip())

    out = _run_cmd(cmd)
    return out.strip()

# ---------------------------------------------------------------------------
# 3. Android APK 逆向与动态 Hook 生成
# ---------------------------------------------------------------------------
@server.tool()
def seep_r2_xrefs(
    binary_path: str,
    target: str,
    direction: str = "to",
    limit: int = 10,
) -> str:
    """获取指定地址/函数的交叉引用关系，内置分页与统计摘要避免大量 xref 结果内爆上下文。

    Args:
        binary_path: 目标二进制文件路径
        target: 目标函数名或地址（如 'sym.check_license', '0x401234'）
        direction: 方向— 'to'=谁引用了它(调用方), 'from'=它引用了谁(被调用方)
        limit: 最多返回多少条引用（默认 10），超出部分附加统计摘要
    """
    if not os.path.isfile(binary_path):
        return f"[ERROR]: Target file does not exist: {binary_path}"

    r2_cmd = f"aaa; {'axt' if direction == 'to' else 'axf'} @ {target}"
    out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", r2_cmd, os.path.abspath(binary_path)], timeout=60)
    cleaned = _clean_r2_output(out)
    lines = [l for l in cleaned.splitlines() if l.strip() and not l.startswith("INFO:") and not l.startswith("WARN:")]

    total = len(lines)
    shown = lines[:limit]
    result_lines = [
        f"[XREFS {direction.upper()} — {target} | 共 {total} 条引用，显示前 {min(limit, total)} 条]",
        f"注意: 若 total 远大于 limit，考虑缩小 limit 或先查 summary 模式确定目标函数。",
        "━" * 60,
    ] + shown

    if total > limit:
        result_lines.append(f"... [已截断，剩余 {total - limit} 条未展示 | 增大 limit 或用 filter_name 缩小目标范围]"
                            f"\n模块来源分布小计: {dict(list({l.split()[2] if len(l.split())>2 else '?' for l in lines}))[:3]}"
        )

    return "\n".join(result_lines)
@server.tool()
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
    return f"Decompilation finished.\nOutput directory: {output_dir}\nLog: {out[:500]}..."

@server.tool()
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
    return f"Apktool unpack finished.\nOutput directory: {output_dir}\nLog: {out[:500]}..."

@server.tool()
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
        res.append(f"... [Truncated: reached limit of {limit} matches]")
    return "\n".join(res)

@server.tool()
def seep_apk_gen_hook(
    framework: str = "frida",
    class_name: str = "com.example.app.MainActivity",
    method_name: str = "checkFlag",
    param_types: Optional[List[str]] = None,
    return_type: str = "boolean",
    hook_timing: str = "after"
) -> str:
    """根据类名与方法签名自动生成动态 Hook 脚本（支持 Frida JavaScript 与 LSPilot/BeanShell 两种框架）。

    Args:
        framework: Hook 框架，'frida' (默认) 或 'bsh' / 'lspilot'
        class_name: 目标完整类名（如 com.example.app.SecurityHelper）
        method_name: 目标方法名（如 verifyLicense）
        param_types: 方法形参类型列表，例如 ['java.lang.String', 'int']，若重载方法需指定
        return_type: 返回值类型，默认 'boolean'
        hook_timing: Hook 时机，'before', 'after', 或 'replace'
    """
    params_str = ", ".join(param_types) if param_types else ""
    
    if framework.lower() == "frida":
        # 生成 Frida 脚本
        joined_types = "', '".join(param_types) if param_types else ""
        overload_args = f"'{joined_types}'" if param_types else ""
        js_code = f"""// Frida Hook Script for {class_name}.{method_name}
// Generated by seep MCP Toolkit
Java.perform(function () {{
    var target = Java.use("{class_name}");
    var method = target["{method_name}"];
    if ({'true' if param_types else 'false'}) {{
        method = method.overload({overload_args});
    }}
    
    method.implementation = function () {{
        console.log("[*] Hooked {class_name}.{method_name} called");
        for (var i = 0; i < arguments.length; i++) {{
            console.log("    arg[" + i + "]: " + arguments[i]);
        }}
"""
        if hook_timing.lower() == "replace":
            default_ret = "true" if return_type == "boolean" else "null" if return_type == "void" else "0"
            js_code += f"""        console.log("[*] Return value hijacked to: {default_ret}");
        return {default_ret};
    }};
}});"""
        else:
            js_code += f"""        var ret = this.{method_name}.apply(this, arguments);
        console.log("[*] Original return value: " + ret);
        return ret;
    }};
}});"""
        return js_code

    else:
        # 生成 LSPilot / BeanShell 脚本
        template_file = os.path.join(HOOK_TEMPLATES_DIR, f"hook_{hook_timing.lower()}.bsh")
        if not os.path.isfile(template_file):
            template_file = os.path.join(HOOK_TEMPLATES_DIR, "hook_after.bsh")
        
        with open(template_file, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()

        pre_find = ""
        if param_types:
            param_classes = ", ".join([f'ReflectUtils.findClass("{p}", hostLoader)' for p in param_types])
            pre_find = f'Class[] paramTypes = new Class[] {{ {param_classes} }};\n    java.lang.reflect.Method targetMethod = ReflectUtils.findMethod(targetClass, "{method_name}", paramTypes);'
        else:
            pre_find = f'java.lang.reflect.Method targetMethod = ReflectUtils.findMethod(targetClass, "{method_name}", null);'

        content = content.replace("${GEN_TIME}", "Now")
        content = content.replace("${PLUGIN_NAME}", f"hook_{method_name}")
        content = content.replace("${TARGET_CLASS}", class_name)
        content = content.replace("${TARGET_METHOD}", method_name)
        content = content.replace("${TARGET_DESC}", f"({params_str})")
        content = content.replace("${PRE_FIND_METHOD}", pre_find)
        content = content.replace("${CALLBACK_CODE}", f'// TODO: Add custom manipulation for {method_name}')
        return content

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
    pat = query.lower()
    
    hits = []
    for fpath in md_files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
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
                    hits.append({
                        "path": rel.replace("\\", "/"),
                        "title": title or Path(fpath).stem,
                        "score": score,
                        "snippet": content[:300].strip().replace("\n", " ")
                    })
        except Exception:
            pass

    hits.sort(key=lambda x: x["score"], reverse=True)
    top = hits[:limit]
    if not top:
        return f"No articles found matching '{query}' in ReverseLab knowledge base."

    return json.dumps(top, indent=2, ensure_ascii=False)

@server.tool()
def seep_kb_read(article_path: str, max_chars: int = 6000) -> str:
    """读取 ReverseLab 知识库中某篇战术文档或技巧手册的全文内容。

    Args:
        article_path: 相对 KB 根目录的路径（可通过 seep_kb_search 获得，例如 'ctf-website/checklists/web-ctf-first-30-min.md'）
        max_chars: 最大返回字符数，默认 6000
    """
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
            return text[:max_chars] + f"\n\n... [Truncated: Total {len(text)} characters, showing first {max_chars}]"
        return text

@server.tool()
def seep_kb_checklist(checklist_type: str = "web_first_30_min") -> str:
    """获取精炼的 CTF 竞技战术排查清单与工作流。

    Args:
        checklist_type: 清单类型，支持：
            - 'web_first_30_min': Web CTF 前 30 分钟应急排查指南
            - 'attack_matrix': 攻击面全景矩阵
            - 'evidence': 证据链归档标准模板
            - 'pe_ioc': PE 逆向 IOC 提取指南
            - 'pe_persistence': PE 启动持久化链路排查
            - 'yara_rules': YARA 规则编写指南
    """
    map_dict = {
        "web_first_30_min": "ctf-website/checklists/web-ctf-first-30-min.md",
        "attack_matrix": "ctf-website/checklists/attack-matrix.md",
        "evidence": "ctf-website/checklists/evidence.md",
        "pe_ioc": "pe-reverse/techniques/06-ioc-extraction/01-ioc-extraction.md",
        "pe_persistence": "pe-reverse/techniques/06-ioc-extraction/02-persistence-startup-chain.md",
        "yara_rules": "pe-reverse/techniques/07-yara-sigma/01-yara-rule-writing.md"
    }
    rel_path = map_dict.get(checklist_type.lower(), "ctf-website/checklists/web-ctf-first-30-min.md")
    return seep_kb_read(rel_path)

@server.tool()
def seep_kb_payloads(category: str = "all") -> str:
    """检索 CTF 常用高危漏洞 Exploit 种子与 Payload 集合（含 SQLi, SSTI, Prototype Pollution, JWT, SSRF, Deserialization 等）。

    Args:
        category: 类别过滤（'all', 'jwt', 'ssrf', 'sqli', 'ssti', 'prototype'），默认 'all'
    """
    payload_file = os.path.join(KB_DIR, "ctf-website", "payloads", "web-payload-seeds.md")
    if not os.path.isfile(payload_file):
        return "[ERROR]: Payload seeds file not found."

    with open(payload_file, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()

    if category.lower() == "all":
        return content

    # 提取对应章节
    lines = content.splitlines()
    selected_lines = []
    capturing = False
    target = category.lower()

    for line in lines:
        if line.startswith("#"):
            if target in line.lower():
                capturing = True
            elif capturing and (line.startswith("## ") or line.startswith("# ")):
                break
        if capturing:
            selected_lines.append(line)

    if selected_lines:
        return "\n".join(selected_lines)
    return f"No section matching '{category}' in payloads file. Returning full document header:\n" + "\n".join(lines[:60])


# ---------------------------------------------------------------------------
# 5. 战术助手与安全评估增强工具 (Task Isolation, Triage, Report & IDA Bridge)
# ---------------------------------------------------------------------------

@server.tool()
def seep_task_init(task_name: str, description: str = "") -> str:
    """
    【工作空间铁律保障】为新任务一键在根目录下初始化独立的任务沙箱工作区。
    自动创建规范子目录：samples/, exports/, patches/, reports/，
    杜绝文件乱堆乱放和根目录污染。
    """
    clean_name = re.sub(r'[^\w\-]', '_', task_name.strip())
    if not clean_name:
        return "[ERROR] task_name 不能为空"
    
    task_path = os.path.join(BASE_DIR, clean_name)
    subdirs = ["samples", "exports", "patches", "reports"]
    
    try:
        os.makedirs(task_path, exist_ok=True)
        created_dirs = [clean_name]
        for sub in subdirs:
            p = os.path.join(task_path, sub)
            os.makedirs(p, exist_ok=True)
            created_dirs.append(f"{clean_name}/{sub}")
            
        readme_path = os.path.join(task_path, "README.md")
        if not os.path.exists(readme_path):
            with open(readme_path, "w", encoding="utf-8") as f:
                f.write(f"# 任务工作区: {clean_name}\n\n")
                f.write(f"- 创建时间: {subprocess.getoutput('date /t') if sys.platform == 'win32' else subprocess.getoutput('date')}\n")
                f.write(f"- 任务描述: {description or '授权软件安全检测与白盒鉴权脆弱性走查任务'}\n\n")
                f.write("## 目录约定\n")
                f.write("- `samples/`: 原始目标程序与待测样本\n")
                f.write("- `exports/`: 反编译伪代码、字符串导出、日志与分析证据\n")
                f.write("- `patches/`: 验证 PoC 代码、代理 DLL 跳板工程、热补丁\n")
                f.write("- `reports/`: 最终安全评估与漏洞复现报告\n")
        
        return json.dumps({
            "status": "Success",
            "task_directory": task_path,
            "created_directories": created_dirs,
            "message": f"任务工作区 [{clean_name}] 已成功创建！后续所有产物请严格保存于该目录内部。"
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"[ERROR] 初始化任务工作区失败: {str(e)}"


@server.tool()
def seep_auto_triage(target_path: str, task_name: Optional[str] = None) -> str:
    """
    一键全自动靶向侦察 (Auto Triage)：
    对给定目标（PE/EXE/DLL/APK/ELF）进行 360° 综合体检：
    1. 计算 MD5 / SHA256 文件哈希
    2. 探测文件类型与架构位数 (32/64 bit, x86/ARM)
    3. 枚举关键安全缓解机制 (Canary/NX/PIE/ASLR)
    4. 提取高价值鉴权/密钥/网络特征字符串
    5. 若提供 task_name，自动将完整报告输出到该任务的 reports/ 目录
    """
    if not os.path.exists(target_path):
        return f"[ERROR] Target path not found: {target_path}"
    
    t_path = Path(target_path).resolve()
    file_size = os.path.getsize(t_path)
    
    # 1. 计算哈希
    md5_cmd = [RABIN2_EXE, "-k", "md5", str(t_path)] if os.path.exists(RABIN2_EXE) else None
    sha256_cmd = [RABIN2_EXE, "-k", "sha256", str(t_path)] if os.path.exists(RABIN2_EXE) else None
    
    import hashlib
    with open(t_path, "rb") as f:
        data = f.read(1024 * 1024 * 50) # 最大前 50MB 计算
        md5_val = hashlib.md5(data).hexdigest()
        sha256_val = hashlib.sha256(data).hexdigest()

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

    triage_result = {
        "file_name": t_path.name,
        "file_size": f"{file_size / (1024 * 1024):.2f} MB",
        "hashes": {
            "md5": md5_val,
            "sha256": sha256_val
        },
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
        "recommended_action": (
            "检测到高价值鉴权关键词与符号，建议下一步："
            "1. 若存在 IDA 环境，直接使用 mcp_ida_get_function_by_name 或地址枚举决策分支；"
            "2. 若为本地逻辑判定，使用 seep_apk_gen_hook 或生成免杀热补丁跳板验证；"
            "3. 报告与验证代码请归档入对应任务的 reports/ 与 patches/。"
        )
    }
    
    if task_name:
        clean_task = re.sub(r'[^\w\-]', '_', task_name.strip())
        report_dir = os.path.join(BASE_DIR, clean_task, "reports")
        if os.path.exists(report_dir):
            out_file = os.path.join(report_dir, f"{t_path.stem}_triage.json")
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(triage_result, f, indent=2, ensure_ascii=False)
            triage_result["saved_report"] = out_file
            
    return json.dumps(triage_result, indent=2, ensure_ascii=False)


@server.tool()
def seep_ida_status() -> str:
    """
    检查本地 IDA Pro 逆向分析服务与 MCP 桥接器是否在线就绪。
    探测端口 127.0.0.1:13337。
    """
    import urllib.request
    url = "http://127.0.0.1:13337"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=2) as resp:
            return json.dumps({
                "status": "Online",
                "code": resp.status,
                "message": "IDA Pro MCP 服务正在稳定运行！可直接调用 mcp_ida_* 工具链展开反编译与交叉引用深度分析。"
            }, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({
            "status": "Offline / Unreachable",
            "detail": str(e),
            "hint": "若需使用 IDA 深度分析，请在 IDA Pro GUI 中确认插件已加载，或按下 Ctrl+Alt+M 唤醒。"
        }, indent=2, ensure_ascii=False)


@server.tool()
def seep_gen_security_report(
    task_name: str,
    target_name: str,
    vuln_type: str = "CWE-602: 客户端鉴权与状态判定缺陷",
    branch_location: str = "0x0",
    description: str = "",
    poc_summary: str = "",
    defense_recommendation: str = ""
) -> str:
    """
    自动生成专业级白盒安全漏洞评估报告。
    按照正规合规标准排版，包含漏洞成因、位点、复现 PoC 与企业级防护加固方案。
    报告自动落入任务文件夹的 reports/ 目录。
    """
    clean_task = re.sub(r'[^\w\-]', '_', task_name.strip())
    report_dir = os.path.join(BASE_DIR, clean_task, "reports")
    os.makedirs(report_dir, exist_ok=True)
    
    report_file = os.path.join(report_dir, f"{target_name}_security_assessment_report.md")
    
    now_str = subprocess.getoutput('date /t') if sys.platform == 'win32' else subprocess.getoutput('date')
    
    default_remediation = (
        "1. **服务端统一鉴权 (Server-side Enforcement)**：将核心特权逻辑迁移至云端，客户端仅作为渲染终端，所有受限资源由服务端颁发带有时间戳和数字签名的 Token 换取。\n"
        "2. **非对称公钥防篡改**：若需支持离线场景，必须使用 RSA/ECC 非对称签名，客户端仅保留公钥验签，私钥由授权服务器持有。\n"
        "3. **内存完整性保护**：启用 Windows `ProcessDynamicCodePolicy` 抑制动态内存写入，并在核心敏感模块增加代码段自校验哈希。"
    )
    
    remediation_text = defense_recommendation or default_remediation
    
    content = f"""# 软件安全评估与鉴权脆弱性走查报告

- **目标资产**: `{target_name}`
- **评估类型**: 白盒代码走查 / 客户端决策逻辑安全性验证
- **缺陷分类**: `{vuln_type}`
- **评估时间**: {now_str}
- **报告归属**: `{clean_task}/reports/`

---

## 1. 风险概述与脆弱性成因 (Vulnerability Summary)
{description or "在白盒审计过程中，发现该客户端采用本地离线决策逻辑，缺乏服务端强鉴权与非对称加密验签。客户端程序完全依据本地存储状态或单一标志位分支进行权限放行，构成 CWE-602 本地判定信任缺陷。"}

---

## 2. 关键判定决策位点 (Decision Branch Location)
- **判定函数 / 偏移位点**: `{branch_location}`
- **汇编指令与分支模式**:
```text
; 典型本地鉴权判断分支
TEST EAX, EAX
JZ   loc_restricted_feature  ; 本地跳转决定受限功能
```

---

## 3. 验证 PoC 与复现过程 (Proof of Concept)
{poc_summary or "通过动态 Hook / 内存标志位修正，成功验证在不经过服务端鉴权的前提下，本地逻辑可以直接放行相关受限功能。验证代码已归档至 patches/ 目录。"}

---

## 4. 纵深防护与企业级加固修复建议 (Remediation)
{remediation_text}
"""

    with open(report_file, "w", encoding="utf-8") as f:
        f.write(content)
        
    return json.dumps({
        "status": "Success",
        "report_path": report_file,
        "message": f"安全评估报告已正式生成并归档至: {clean_task}/reports/{os.path.basename(report_file)}"
    }, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# 扩展资产（relab2 / REA 适配版，2026-10 增补）
# 这两个工具是"增量挂载"：不修改任何既有工具逻辑，只在末尾追加。
#   seep_ensure_tool      —— 工具四级探测与缺工具自愈建议（源自 relab2 ensure_tool + Bootstrap 四级递进）
#   seep_decompile_auto   —— 多引擎降级反编译 IDA→REA→R2（源自 REA 的 provider 降级链思想）
# ---------------------------------------------------------------------------

# 常见工具根（跨平台），用于四级探测的第 3 级
_TOOL_ROOTS = [
    os.environ.get("REVERSE_TOOL_ROOT", ""),
    os.environ.get("SEEP_TOOL_ROOT", ""),
    r"D:\Tools",
    r"D:\Tool",
    os.path.join(os.path.expanduser("~"), "Tools"),
    "/opt",
    "/usr/local/bin",
    "/usr/bin",
]

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
    "ida": "商业软件，需自备 IDA Pro 授权；装好后把 idat64 加入 PATH 或 D:\\Tools。",
    "x64dbg": "winget install x64dbg.x64dbg  或从 x64dbg.com 下载便携版放到 D:\\Tools。",
    "cdb": "随 Windows SDK / WinDbg 安装：winget install Microsoft.WinDbg。",
    "diec": "下载 Detect It Easy (DIE) 便携版，把 diec.exe 放到 D:\\Tools。",
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
    for root in _TOOL_ROOTS:
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
    for root in _TOOL_ROOTS:
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
def seep_ensure_tool(tool_id: str, allow_install: bool = False) -> str:
    """四级探测本机某工具是否可用；缺工具时给出可执行的安装建议（可选自动安装）。

    探测顺序（命中即停）：环境变量 -> PATH -> 常见工具根别名 -> 递归扫描（带 deny 规则）。
    这是"缺工具自愈"的入口：先查有没有，没有就明确告诉你装什么、怎么装，
    绝不在终端里瞎猜路径、也绝不静默假装成功。

    Args:
        tool_id: 工具标识，如 'ida' / 'x64dbg' / 'cdb' / 'diec' / 'r2' / 'ghidra' /
                 'floss' / 'capa' / 'frida' / 'jadx' / 'apktool' / 'tshark' / 'binwalk' / 'gcc'
        allow_install: 是否允许尝试自动安装（默认 False，只探测 + 给建议；
                       True 时对少数公开 pip 工具尝试安装，其余仍只给建议）
    """
    tid = tool_id.strip().lower()
    res = _resolve_tool(tid)
    out = {"tool_id": tid}
    out.update(res)

    if res["available"]:
        ver = ""
        for flag in ("-version", "-v", "--version"):
            try:
                p = subprocess.run([res["command"], flag], capture_output=True,
                                   text=True, encoding="utf-8", errors="replace", timeout=8)
                txt = (p.stdout or "") + (p.stderr or "")
                if txt.strip():
                    ver = txt.strip().splitlines()[0]
                    break
            except Exception:
                continue
        out["version"] = ver
        out["status"] = "available"
        return json.dumps(out, indent=2, ensure_ascii=False)

    # 不可用：给安装建议（优先读声明式 tool-install.json，P4 按需下载）
    cfg = _load_tool_install()
    entry = cfg.get("installable", {}).get(tid)
    hint = _TOOL_INSTALL_HINTS.get(tid, "未收录该工具的安装方式；请手动安装后加入 PATH。")
    out["status"] = "missing"
    out["install_hint"] = hint
    out["note"] = "四级探测均未命中。若确信已安装，检查它是否在 D:\\Tools 或 PATH；也可设环境变量 SEEP_<TOOL>_PATH 显式指定。"

    if entry:
        out["install_plan"] = _build_install_plan(tid, entry)

    # 自动安装（仅 allow_install 且方法在白名单；manual 永不自动）
    if allow_install and entry:
        method = entry.get("method", "")
        auto_ok = method in (cfg.get("auto_allow_methods") or []) and method != "manual"
        if auto_ok:
            cmd = _install_cmd_for(tid, entry)
            if cmd:
                try:
                    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                                       errors="replace", timeout=600)
                    out["install_attempt"] = {"method": method, "cmd": cmd,
                                              "returncode": p.returncode,
                                              "tail": (p.stdout or p.stderr or "")[-400:]}
                    # 装完重新探测一次
                    recheck = _resolve_tool(tid)
                    out["after_install"] = recheck
                except Exception as exc:  # noqa: BLE001
                    out["install_attempt"] = {"method": method, "cmd": cmd,
                                              "error": "%s: %s" % (type(exc).__name__, exc)}
        else:
            out["install_attempt"] = {"skipped": f"method={method} 不在自动白名单，需人工/确认安装",
                                      "plan": out.get("install_plan")}
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


@server.tool()
def seep_decompile_auto(
    binary_path: str,
    target: str = "main",
    engine: str = "auto",
    output_mode: str = "fold",
    limit_tokens: int = 8000,
) -> str:
    """反编译入口：自动探测本机引擎，优先给可直接执行的 Radare2 伪代码，并报告更高阶引擎可用性。

    诚实说明（避免过度承诺）：
    - 本工具**直接执行**的是 Radare2（内置、永远可用）——它能当场给出真伪代码。
    - 对 IDA / Ghidra / REA：本工具只**探测它们是否可用并报告**，不在此函数内驱动它们的
      MCP/CLI harness（那些需各自的 MCP 通道，由 ida-reverse 技能或对应 MCP 工具负责）。
    - 若本机无 r2 但有高阶引擎，会提示你改用对应引擎的 MCP 工具，而不是伪造结果。

    所以它的定位是：“r2 保底 + 高阶引擎告知”，而非“自动把 IDA/Ghidra 都跑一遍”。

    Args:
        binary_path: 目标二进制路径
        target: 函数名或地址（如 'main'、'sym.verify'、'0x401000'）
        engine: 'auto'（默认）| 'ida' | 'ghidra' | 'rea' | 'r2'
        output_mode: 传给底层反编译的折叠模式 'full' | 'fold' | 'summary'
        limit_tokens: 输出字符上限
    """
    if not os.path.isfile(binary_path):
        return f"[ERROR]: Target file does not exist: {binary_path}"

    if engine == "auto":
        order = _engine_order_for(binary_path)
    else:
        order = [engine.lower()]

    tried = []
    for eng in order:
        info = _detect_engine(eng)
        tried.append({"engine": eng, "available": info["available"], "detail": info["detail"]})
        if not info["available"]:
            continue

        # IDA / Ghidra / REA 的完整自动化需各自的 MCP/CLI harness；
        # 这里不伪造结果：若 r2 可用，先降级到 r2 给真伪代码，并在输出里说明高阶引擎可用。
        if eng in ("ida", "ghidra", "rea"):
            if os.path.isfile(R2_EXE):
                continue
            return json.dumps({
                "engine_used": eng,
                "note": "检测到 %s 可用（%s），但需通过其 MCP/CLI harness 驱动；"
                        "本机无 r2 兜底，请改用 %s 的 MCP 工具反编译 %s。"
                        % (eng, info["detail"], eng, target),
                "probed": tried,
            }, indent=2, ensure_ascii=False)

        if eng == "r2":
            pseudo = seep_r2_decompile(binary_path, target=target,
                                       output_mode=output_mode, limit_tokens=limit_tokens)
            higher = [t["engine"] for t in tried if t["available"] and t["engine"] != "r2"]
            return (
                "[engine_used] r2 (Radare2)\n"
                "[higher_tier_available] %s\n"
                "[note] 已按 IDA->Ghidra/REA->R2 降级链选到可直接执行的引擎；"
                "若需更高精度可改用上表所列引擎的 MCP 工具。\n%s\n%s"
                % (", ".join(higher) if higher else "none", "-" * 60, pseudo)
            )

    return json.dumps({
        "engine_used": None,
        "error": "无任何可用反编译引擎（ida/ghidra/rea/r2 均不可用）",
        "probed": tried,
        "hint": "先运行 seep_ensure_tool('r2') 或安装 radare2。",
    }, indent=2, ensure_ascii=False)


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
def seep_pe_resources(binary_path: str, min_size: int = 4096, extract_dir: str = "", top: int = 20) -> str:
    """枚举 PE 资源节与高熵载荷，并对可疑资源做"魔数嗅探"，可选剥离到目录。

    针对"换肤器/皮肤包/内嵌 DLL"这类样本：真正的功能载荷往往不在 .text，
    而在资源节（如自定义 DATA 资源）里，且常是 zstd/zip 等压缩容器。
    本工具读 PE 资源树 + 节熵，直接告诉你"哪块资源是高熵、是什么容器"。

    Args:
        binary_path: PE 文件路径
        min_size: 只报告不小于该字节数的资源（默认 4096，过滤图标小资源）
        extract_dir: 若给出，则把命中的资源数据落盘到该目录（默认空=只报告不落盘）
        top: 最多报告前 N 个最大的资源（默认 20）
    """
    if not os.path.isfile(binary_path):
        return f"[ERROR]: file not found: {binary_path}"
    if not binary_path.lower().endswith((".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr")):
        # 仍尝试，但提示
        pass
    try:
        import pefile  # noqa: F401
    except Exception:
        return ("[ERROR]: 需要 pefile 库（pip install pefile）。"
                "或改用 seep_r2_info / seep_auto_triage 获取节信息。")
    import pefile
    try:
        pe = pefile.PE(binary_path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    except Exception as exc:  # noqa: BLE001
        return f"[ERROR]: pefile 解析失败: {type(exc).__name__}: {exc}"

    # 1) 节熵概览
    sections = []
    for s in pe.sections:
        try:
            name = s.Name.rstrip(b"\x00").decode("latin1", "replace")
            data = s.get_data()
            sections.append({
                "name": name,
                "vaddr": hex(s.VirtualAddress),
                "raw_size": s.SizeOfRawData,
                "entropy": round(_entropy_bytes(data), 2),
            })
        except Exception:
            continue

    # 2) 资源枚举
    resources = []
    def walk(resdir, path):
        for entry in getattr(resdir, "entries", []):
            name = entry.name if entry.name is not None else entry.id
            eid = entry.id
            newpath = path + [str(name)]
            if hasattr(entry, "directory"):
                walk(entry.directory, newpath)
            elif hasattr(entry, "data"):
                st = entry.data.struct
                size = st.Size
                if size >= min_size:
                    rva = st.OffsetToData
                    try:
                        raw = pe.get_data(rva, size)
                    except Exception:
                        raw = b""
                    resources.append({
                        "type_id": path[0] if path else "",
                        "name_id": str(eid) if eid is not None else "",
                        "path": "/".join(newpath),
                        "offset_rva": hex(rva),
                        "size": size,
                        "entropy": round(_entropy_bytes(raw), 2) if raw else 0,
                        "container": _sniff_container(raw) if raw else "unknown",
                        "head_hex": raw[:24].hex(" ") if raw else "",
                    })
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            walk(pe.DIRECTORY_ENTRY_RESOURCE, [])
    except Exception:
        pass

    resources.sort(key=lambda r: r["size"], reverse=True)
    resources = resources[:top]

    # 3) 可选落盘
    written = []
    if extract_dir:
        os.makedirs(extract_dir, exist_ok=True)
        for r in resources:
            if r["container"] in ("zstd", "zip", "7z", "gzip", "pe", "png", "bmp", "ogg", "unknown"):
                # 只落高熵或已知容器，跳过明显无关的小图
                if r["entropy"] < 7.0 and r["container"] == "unknown":
                    continue
                try:
                    raw = pe.get_data(int(r["offset_rva"], 16), r["size"])
                    safe = re.sub(r"[^\w.\-]", "_", r["path"])
                    fp = os.path.join(extract_dir, f"res_{r['type_id']}_{safe}.bin")
                    with open(fp, "wb") as f:
                        f.write(raw)
                    written.append(fp)
                except Exception:
                    continue

    out = {
        "file": os.path.basename(binary_path),
        "sections": sections,
        "high_entropy_sections": [s["name"] for s in sections if s["entropy"] > 7.0 and s["raw_size"] > 512],
        "resources": resources,
        "note": "container=zstd/zip/pe 等高熵资源通常就是真正的功能载荷或皮肤包，优先剥离解析。",
    }
    if written:
        out["extracted"] = written
    return json.dumps(out, indent=2, ensure_ascii=False)


@server.tool()
def seep_mem_strings(pid: int, pattern: str = "", min_len: int = 5, max_hits: int = 50, encoding: str = "both") -> str:
    """扫描指定进程的内存，提取可读字符串（治"字符串运行期才解密/只有内存里才有"的样本）。

    很多加壳/反调试样本，磁盘上看不到 URL/卡密提示/密钥，因为它们运行期才解密到内存。
    本工具用 Windows ReadProcessMemory 逐块扫描（只读，不改目标），把命中的字符串
    连同所在虚拟地址一起给你，方便回填到反汇编里定位引用。

    Args:
        pid: 目标进程 ID
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
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, int(pid))
    if not h:
        return f"[ERROR]: OpenProcess 失败 pid={pid}，错误码={ctypes.get_last_error()}（需管理员/同架构）"

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD), ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD), ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]

    MEM_COMMIT = 0x1000
    PAGE_GUARD = 0x100
    PAGE_NOACCESS = 0x01
    readable = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}  # R/RW/COPY/W+X 等
    addr = 0
    hits = []
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
        if (mbi.State == MEM_COMMIT and prot not in (PAGE_NOACCESS,) and not (prot & PAGE_GUARD)
                and (prot & 0xFF) in readable and size <= (64 << 20)):
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
    k32.CloseHandle(h)
    return json.dumps({
        "pid": pid, "pattern": pattern, "hits": hits, "count": len(hits),
        "note": "addr 为进程虚拟地址，可直接回填到反汇编/反编译里定位引用该字符串的代码。",
    }, indent=2, ensure_ascii=False)


@server.tool()
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
        for c in (r"D:\Tools\Wireshark\tshark.exe", r"C:\Program Files\Wireshark\tshark.exe",
                  "/usr/bin/tshark", "/usr/local/bin/tshark"):
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
}
# 反虚拟机/沙箱字符串
_ANTIVM_STRINGS = [b"VMware", b"VirtualBox", b"VBox", b"QEMU", b"Xen", b"Hyper-V",
                   b"vbox", b"SbieDll", b"dbghelp", b"OllyDbg", b"x64dbg", b"WinDbg",
                   b"Wireshark", b"Process Hacker", b"procmon"]


def _read_pe_imports(path: str) -> list:
    """用 pefile 读导入函数名（失败返回空）。"""
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
        return []


@server.tool()
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
        "packed": False,
        "packer_hints": [],
        "high_entropy_sections": [],
        "antidebug_imports": [],
        "antivm_strings": [],
        "route": [],
        "manual": [],
    }

    # 1) 节名/节熵（pefile）
    sections = []
    try:
        import pefile
        pe = pefile.PE(binary_path, fast_load=True)
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
    except Exception:
        pass

    # 2) 壳字符串特征（原始字节）
    try:
        with open(binary_path, "rb") as f:
            blob = f.read(8 * 1024 * 1024)
        for sig in _PACKER_STRINGS:
            if sig in blob:
                result["packer_hints"].append(f"string:{sig.decode('latin1')}")
    except Exception:
        blob = b""

    # 3) 反调试导入
    imports = _read_pe_imports(binary_path)
    ad = sorted({n for n in imports if n in _ANTIDEBUG_IMPORTS})
    result["antidebug_imports"] = ad

    # 4) 反虚拟机字符串
    av = sorted({s.decode() for s in _ANTIVM_STRINGS if s in blob})
    result["antivm_strings"] = av

    # 5) 判定与路由
    result["packed"] = bool(result["packer_hints"]) or bool(result["high_entropy_sections"])
    if result["packed"]:
        result["route"].append("有壳 → 先脱壳：读 MANUAL/UNPACKING.md §一(壳速查) + §二(OEP/Dump)")
    if result["antidebug_imports"]:
        result["route"].append("有反调试导入 → 读 MANUAL/ANTI-DEBUG.md §二(PEB系列) + §七(两击熔断)")
    if result["antivm_strings"]:
        result["route"].append("有反虚拟机特征 → 优先真机/裸金属，或按 ANTI-DEBUG §四 处理环境检测")
    if not result["packed"] and not result["antidebug_imports"]:
        result["route"].append("未检出明显壳/反调试 → 可直接 seep_decompile_auto 反编译")

    result["manual"] = ["MANUAL/UNPACKING.md", "MANUAL/ANTI-DEBUG.md"]
    result["sections"] = sections
    return json.dumps(result, indent=2, ensure_ascii=False)


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
    伪装 Chrome/Safari/Edge 的 TLS 指纹（绕过基础反爬），并支持把 Cookie 存到 session_file
    实现"登录态保持 / token 复用"——这正是协议签到、接口重放、回包验证的核心。

    若本机无 curl_cffi，自动降级到 requests（仍可用，只是 TLS 指纹不伪装）。

    Args:
        url: 目标 URL
        method: GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS
        headers: JSON 字符串，如 '{"User-Agent":"...","Referer":"..."}'
        cookies: JSON 字符串，如 '{"session":"abc"}'
        body: 请求体（POST/PUT 时用；JSON 直接传字符串，或表单串）
        impersonate: TLS 指纹伪装目标 chrome/safari/edge/ff（仅 curl_cffi 生效）
        session_file: 若给出，则把本次响应的 Cookie 合并保存到该文件，下次自动带上（会话保持）
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

    # 会话 Cookie 合并
    if session_file and os.path.isfile(session_file):
        try:
            with open(session_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                merged = dict(saved)
                merged.update(ck)
                ck = merged
        except Exception:
            pass

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
            return (f"[ERROR]: 请求失败。curl_cffi: {type(exc_cffi).__name__}: {exc_cffi} | "
                    f"requests: {type(exc_req).__name__}: {exc_req}")

    # 保存会话 Cookie
    saved_note = ""
    if session_file:
        try:
            all_ck = dict(ck)
            all_ck.update(set_cookies)
            with open(session_file, "w", encoding="utf-8") as f:
                json.dump(all_ck, f, ensure_ascii=False, indent=2)
            saved_note = f"cookie 已保存到 {session_file}（{len(all_ck)} 个）"
        except Exception as exc:
            saved_note = f"cookie 保存失败: {exc}"

    out = {
        "backend": backend,
        "request": {"method": method, "url": url,
                    "headers": hdr, "cookies": ck,
                    "body_len": len(body)},
        "status": resp_status,
        "response_headers": resp_headers,
        "set_cookies": set_cookies,
        "body_preview": resp_text[:2000],
        "body_len": len(resp_text),
    }
    if saved_note:
        out["session"] = saved_note
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


@server.tool()
def seep_web_recon(url: str, timeout: int = 15) -> str:
    """Web 目标轻量侦察（只读、不攻击）：响应头、技术栈指纹、安全头缺失、常见路径探测。

    这是"渗透与逆向/协议相关"的那一小块：在逆向一个 Web/API 目标前，先摸清它是什么技术栈、
    有没有 WAF、安全头缺什么、有哪些常见入口（robots/sitemap/.git 等）。
    **只做被动/轻量探测，不做爆破、不做注入、不做利用** —— 重型渗透请用独立 MCP。

    Args:
        url: 目标 URL（如 https://example.com）
        timeout: 超时秒数
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    import urllib.request
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # 侦察允许自签，不校验

    def fetch(u):
        req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0 (Seep-Recon)"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, dict(r.headers), r.read(200000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers) if e.headers else {}, ""
        except Exception as e:
            return None, {}, f"[fetch error: {type(e).__name__}: {e}]"

    status, headers, body = fetch(url)
    if status is None:
        return json.dumps({"url": url, "error": body}, indent=2, ensure_ascii=False)

    # 技术栈指纹
    hay = (str(headers).lower() + " " + body[:20000].lower())
    detected = {}
    for cat, keys in _WEB_FINGERPRINTS.items():
        hit = sorted({k for k in keys if k in hay})
        if hit:
            detected[cat] = hit

    # 安全头缺失
    hlow = {k.lower(): v for k, v in headers.items()}
    missing_sec = [h for h in _SECURITY_HEADERS if h not in hlow]
    present_sec = [h for h in _SECURITY_HEADERS if h in hlow]

    # 常见入口探测（只读 HEAD/GET，温和）
    probes = {}
    base = url.rstrip("/")
    for path in ["/robots.txt", "/sitemap.xml", "/.git/config", "/.env", "/api/", "/admin/"]:
        try:
            st, _, _ = fetch(base + path)
            probes[path] = st
        except Exception:
            probes[path] = None

    return json.dumps({
        "url": url,
        "status": status,
        "server": hlow.get("server", ""),
        "powered_by": hlow.get("x-powered-by", ""),
        "detected": detected,
        "security_headers_present": present_sec,
        "security_headers_missing": missing_sec,
        "path_probes": probes,
        "note": "只读侦察。有 WAF/CDN 指纹 → 后续请求需注意指纹伪装(seep_http_replay impersonate)；"
                ".git/.env 返回 200 → 高价值信息泄露点，值得深入（属授权范围）。",
    }, indent=2, ensure_ascii=False)


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
