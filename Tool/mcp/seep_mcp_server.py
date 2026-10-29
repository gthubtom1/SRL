#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seep MCP：二进制与Android工具、Hook模板及可检索知识库。
能力就绪与任务成功分别由实际调用及结果验证。
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
import datetime
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Any

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    from mcp.server.fastmcp import FastMCP as MCPServer

# 基础路径与环境；资源按当前脚本位置解析。
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
KB_LOCAL_DIR = os.path.join(BASE_DIR, "kb_local")   # 本地覆盖层（不属于 vendored 上游）
LLMS_TXT = os.path.join(TOOL_DIR, "reverselab", "docs", "llms.txt")
HOOK_TEMPLATES_DIR = os.path.join(SAFE_DIR, "hook-mcp", "templates")

# 将 r2 bin 目录添加到 PATH 中，确保子进程加载依赖 dll
if os.path.isdir(R2_BIN_DIR) and R2_BIN_DIR not in os.environ.get("PATH", ""):
    os.environ["PATH"] = R2_BIN_DIR + os.pathsep + os.environ.get("PATH", "")


# 路径别名公开在schema中，运行时归一为工具的主参数。
# 别名表与包装器共同消费，避免调用者依赖隐藏参数。
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
    """暴露并归一路径别名；无条件移除空别名，兼容FastMCP默认字段dump。"""
    import functools as _ft
    import inspect as _inspect

    sig = _inspect.signature(fn)
    extras = [a for a in names if a not in sig.parameters]
    # MCP按名字传参；keyword-only允许可选主路径排在其他必填参数前。
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
    # 运行时与schema都使用这份别名契约。
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
def _run_capture(
    cmd: List[str],
    cwd: Optional[str] = None,
    timeout: int = 60,
) -> Dict[str, Any]:
    """Run a command once and retain rc/stdout/stderr separately.

    UI/callers that need text can use ``_run_cmd``; safety-sensitive tools use
    this result directly so that stderr and execution failures can never be
    mistaken for successful data.
    """
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
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "error": "",
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False, "returncode": None,
            "stdout": (exc.stdout or "") if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "") if isinstance(exc.stderr, str) else "",
            "error": "timeout after %s seconds" % timeout,
        }
    except Exception as exc:  # noqa: BLE001 - boundary must return structured failure
        return {
            "ok": False, "returncode": None, "stdout": "", "stderr": "",
            "error": "%s: %s" % (type(exc).__name__, exc),
        }


def _run_cmd(cmd: List[str], cwd: Optional[str] = None, timeout: int = 60) -> str:
    """Run an external command and render its result as legacy text."""
    result = _run_capture(cmd, cwd=cwd, timeout=timeout)
    out = result["stdout"].strip()
    err = result["stderr"].strip()
    if result["error"]:
        return f"[ERROR]: {result['error']}"
    if not result["ok"]:
        return f"[ERROR code {result['returncode']}]: {err}\n{out}".strip()
    if out and err:
        return f"{out}\n[STDERR]: {err}"
    return out or err


def _atomic_write_text(path: str, text: str) -> None:
    """Write one UTF-8 file atomically without following a final symlink."""
    target = os.path.abspath(path)
    parent = os.path.dirname(target)
    os.makedirs(parent, exist_ok=True)
    if os.path.lexists(target) and (os.path.islink(target) or not os.path.isfile(target)):
        raise OSError("目标必须是普通文件，且不能是链接")
    pending = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=parent,
            prefix=".seep-write-", delete=False,
        ) as handle:
            pending = handle.name
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(pending, target)
        pending = None
    finally:
        if pending and os.path.exists(pending):
            try:
                os.unlink(pending)
            except OSError:
                pass


def _clean_r2_output(text: str) -> str:
    """移除 ANSI 颜色控制字符"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

# ── 结果契约层（S2-3）：预算/空态/证据筛选/报告模板拆到同目录 seep_contract.py ──
# 拆的理由：主服务单文件 ≤3200 行（BASELINE-FREEZE §7）；该模块不注册工具、不 import 主服务，
# 但**有 IO 与可变缓存**（详见 seep_contract.py 顶部，不再谎称"纯函数/无 IO"）。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from seep_contract import (  # noqa: E402
    RESULT_BUDGET_CHARS, budget_gate as _budget_gate, build_report_md,
    case_evidence_dir as _case_evidence_dir, empty_output as _empty_output,
    is_err_payload as _is_err_payload, r2_focus_output as _r2_focus_output,
    missing_report_fields, page_footer as _page_footer,
    resource_constraint as _resource_constraint, strong_claim_ids as _strong_claim_ids,
    audit_tool_effects as _audit_tool_effects)
# 只读参数边界 / KB 口语检索层 / pcap 执行契约都是**校验/契约函数**，放在契约模块里；
# 契约模块不是"纯函数模块"（有 IO 与可变缓存，见其顶部）；边界判定仍在工具函数入口执行。
from seep_contract import (  # noqa: E402
    invalid_param as _invalid_param, int_in_range as _int_in_range,
    kb_rel_error, r2_target_error, kb_within as _kb_within, kb_join as _kb_join,
    R2_TARGET_FORBIDDEN, KB_ASCII_TOKEN_RE as _KB_ASCII_TOKEN_RE,
    KB_CJK_RUN_RE as _KB_CJK_RUN_RE, KB_SYN_CACHE as _KB_SYN_CACHE,
    kb_alias_expand as _kb_alias_expand, kb_cjk_bigrams as _kb_cjk_bigrams,
    kb_hit_count as _kb_hit_count, kb_load_synonyms as _kb_load_synonyms,
    kb_normalize_query as _kb_normalize_query,
    # r2 只读命令语法（seep_r2_cmd 的唯一判定来源；见 seep_contract 顶部说明）
    r2_readonly_command_check, r2_readonly_error as _r2_readonly_error,
    # pcap 执行契约（参数/执行记录/状态/分页；纯函数，argv 仍在工具函数体内）
    pcap_params as _pcap_params, pcap_execution as _pcap_execution,
    pcap_envelope as _pcap_envelope, pcap_failure as _pcap_failure, pcap_rows as _pcap_rows,
    pcap_queries as _pcap_queries, PCAP_NOTES as _PCAP_NOTES)
from seep_apk_contract import (  # noqa: E402
    inspect_apk as _inspect_apk, run_jadx as _run_jadx)
from seep_case_library import case_lib_dir as _case_lib_dir, read_case as _read_case  # noqa: E402
from seep_tool_verify import verify_tool as _verify_tool  # noqa: E402
from seep_http_security import (  # noqa: E402
    REDACTED, RedactionFailure,
    assert_redacted as _assert_redacted,
    http_session_path as _http_session_path_impl,
    http_session_snapshot as _http_session_snapshot,
    known_secrets as _known_secrets,
    _redact_cookie_map,
    _redact_map,
    _redact_url,
    _scrub_text,
    HTTP_SESSION_SCHEMA as _HTTP_SESSION_SCHEMA,
)


def _http_session_path(value: str) -> str:
    return _http_session_path_impl(value, _workspace_root())


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

def _r2_write_tokens(command: str) -> list[str]:
    """返回命令串中**被拒**的 token（已审核只读语法的反向视图）。

    历史：旧实现只按「每段首 token 是不是 w* / o+ / oo+」判，于是 `!id`（r2 起 shell）、
    `pd 20 > out.txt`（内建重定向写文件）、`aaa; C*`、`.`/`-`（跑脚本/编辑器）、
    `L <plugin>`（加载插件＝执行外部代码）全部绕过。现在真正的判定在
    `seep_contract.r2_readonly_command_check()`（白名单+硬拒字符+二次 deny 家族+显式分段），
    本函数只把它包成「命中列表」给旧调用点/回归测试用，**不再自己写第二套语法**。
    `test_runtime_registration.py` 仍钉住本函数名与 `mutates_target=true` 上界说明。
    """
    problem, tokens, _kind = r2_readonly_command_check(command)
    return [] if not problem else list(tokens or ["unknown"])


def _r2_read_only_error(problem: str = "", tokens=None, kind: str = "") -> str:
    """只读拒绝出口（委托 seep_contract.r2_readonly_error 产结构化 JSON）。"""
    return _r2_readonly_error("seep_r2_cmd", problem, list(tokens or []), kind)


@server.tool()
@_path_alias
def seep_r2_cmd(binary_path: str, command: str, analyze: bool = True) -> str:
    """在目标二进制文件上执行**已审核只读**的 radare2 命令。

    Args:
        binary_path: 目标二进制文件路径
        command: 只读 r2 命令串（例如 'afl', 'pdf @ main', 'iz', 'px 64 @ 0x1000'；
            多条用 `;` 显式分段，每段都会全校验）。写入 / `!` shell / 重定向 /
            命令链 / 插件加载 / 脚本执行一律结构化拒（read_only_violation）。
        analyze: 是否在执行命令前先执行基本代码分析 (aaa)。默认 True。
    """
    if not os.path.isfile(binary_path):
        return f"[ERROR]: Target file does not exist: {binary_path}"
    if not os.path.isfile(R2_EXE):
        return f"[ERROR]: radare2.exe not found at {R2_EXE}"

    # 校验必须在**拼接 -c 命令串之前**：被拒的命令一次 `_run_cmd` 都不会发生。
    problem, tokens, kind = r2_readonly_command_check(command)
    if problem:
        return _r2_read_only_error(problem, tokens, kind)

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
        limit: 返回最大结果行数，默认 100（1..10000）
    """
    limit, err = _int_in_range("seep_r2_strings", "limit", limit, 1, 10000)
    if err:
        return err
    if not isinstance(filter_text, (str, type(None))) or len(filter_text or "") > 400:
        return _invalid_param("seep_r2_strings", "filter_text 必须是不超过 400 字的字符串")
    if not os.path.isfile(binary_path):
        return f"[ERROR]: Target file does not exist: {binary_path}"
    if not os.path.isfile(RABIN2_EXE):
        return _empty_output(
            "seep_r2_strings",
            "rabin2 不在预期位置：%s" % RABIN2_EXE,
            diagnostics={"error": "rabin2_missing", "expected": RABIN2_EXE},
        )

    flag = "-zz" if all_sections else "-z"
    capture = _run_capture([RABIN2_EXE, flag, os.path.abspath(binary_path)])
    if not capture["ok"]:
        return _empty_output(
            "seep_r2_strings",
            "rabin2 执行失败；没有把 stderr 当作字符串数据。",
            diagnostics={
                "returncode": capture["returncode"],
                "stdout": capture["stdout"][:2000],
                "stderr": capture["stderr"][:2000],
                "error": capture["error"],
            },
        )
    out = capture["stdout"].strip()
    if not out and capture["stderr"].strip():
        return _empty_output(
            "seep_r2_strings",
            "rabin2 成功退出但没有 stdout，仅返回了 stderr；未将诊断当成字符串。",
            diagnostics={"returncode": 0, "stderr": capture["stderr"][:2000]},
        )
    if not out:
        return _empty_output("seep_r2_strings", "rabin2 成功退出但没有字符串输出。")
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
    bad = (r2_target_error(target)
           or ("" if output_mode in ("full", "branch", "summary")
               else "output_mode 只接受 full/branch/summary"))
    lines, e1 = _int_in_range("seep_r2_disasm", "lines", lines, 1, 10000)
    limit_tokens, e2 = _int_in_range("seep_r2_disasm", "limit_tokens", limit_tokens,
                                     0, 64 * 1024)
    if bad or e1 or e2:
        return _invalid_param("seep_r2_disasm", bad) if bad else (e1 or e2)
    if not os.path.isfile(binary_path):
        return f"[ERROR]: Target file does not exist: {binary_path}"
    if not os.path.isfile(R2_EXE):
        return _empty_output(
            "seep_r2_disasm", "radare2 不在预期位置：%s" % R2_EXE,
            diagnostics={"error": "radare2_missing", "expected": R2_EXE})

    if output_mode == "summary":
        # 仅抽取函数级摘要统计，不输出原始指令
        info_cmd = f"aaa; afi @ {target}"
        xref_cmd = f"axt @ {target}"
        call_cmd = f"axf @ {target}"
        info_out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", info_cmd, os.path.abspath(binary_path)], timeout=60)
        xref_out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", xref_cmd, os.path.abspath(binary_path)], timeout=60)
        call_out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", call_cmd, os.path.abspath(binary_path)], timeout=60)
        for part in (info_out, xref_out, call_out):
            err = _is_err_payload(_clean_r2_output(part))
            if err:
                return _empty_output("seep_r2_disasm", "r2 报错：" + err)
        if not any(line.strip() and not line.startswith(("INFO:", "WARN:"))
                   for line in _clean_r2_output(info_out).splitlines()):
            return _empty_output("seep_r2_disasm", "函数信息为空，先用 seep_r2_cmd(afl) 确认目标")
        summary = (
            f"[DISASM SUMMARY MODE — 上下文降噪 Token 节省模式]\n"
            f"Target: {target}\n"
            f"--- Function Info (afi) ---\n{_clean_r2_output(info_out)}\n"
            f"--- Callers (axt / xrefs-to) ---\n{_clean_r2_output(xref_out)}\n"
            f"--- Callees (axf / xrefs-from) ---\n{_clean_r2_output(call_out)}\n"
            f"提示: 使用 output_mode='branch' 或 'full' 获取指令级详情。"
        )
        return _budget_gate("seep_r2_disasm", summary, "用 target 收窄到具体函数",
                            budget_chars=limit_tokens)

    # 获取完整反汇编
    cmd = f"aaa; pdf @ {target}"
    out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", cmd, os.path.abspath(binary_path)], timeout=60)
    cleaned = _clean_r2_output(out)
    if _is_err_payload(cleaned):
        return _empty_output("seep_r2_disasm", "r2 报错：" + _is_err_payload(cleaned))
    output_lines = [l for l in cleaned.splitlines() if not l.startswith("INFO:") and not l.startswith("WARN:")]

    if not output_lines or all(not l.strip() for l in output_lines):
        cmd = f"pd {lines} @ {target}"
        out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", cmd, os.path.abspath(binary_path)], timeout=60)
        cleaned = _clean_r2_output(out)
        if _is_err_payload(cleaned):
            return _empty_output("seep_r2_disasm", "r2 报错：" + _is_err_payload(cleaned))
        output_lines = [l for l in cleaned.splitlines() if not l.startswith("INFO:") and not l.startswith("WARN:")]

    if output_mode == "branch":
        result, error = _r2_focus_output("seep_r2_disasm", target, output_lines, "branch")
        if error:
            return error
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
        "换 output_mode='branch' / 'summary'，或用 target 收窄到具体函数",
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
    bad = (r2_target_error(target)
           or ("" if output_mode in ("full", "fold", "summary")
               else "output_mode 只接受 full/fold/summary"))
    limit_tokens, e1 = _int_in_range("seep_r2_decompile", "limit_tokens", limit_tokens,
                                     0, 64 * 1024)
    if bad or e1:
        return _invalid_param("seep_r2_decompile", bad) if bad else e1
    if not os.path.isfile(binary_path):
        return f"[ERROR]: Target file does not exist: {binary_path}"
    if not os.path.isfile(R2_EXE):
        return _empty_output(
            "seep_r2_decompile", "radare2 不在预期位置：%s" % R2_EXE,
            diagnostics={"error": "radare2_missing", "expected": R2_EXE})

    if output_mode == "summary":
        # 获取函数摘要信息（不输出函数体）
        cmds = f"aaa; afi @ {target}; axf @ {target}"
        out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", cmds, os.path.abspath(binary_path)], timeout=60)
        clean = _clean_r2_output(out)
        if _is_err_payload(clean):
            return _empty_output("seep_r2_decompile", "r2 报错：" + _is_err_payload(clean))
        if not any(line.strip() and not line.startswith(("INFO:", "WARN:")) for line in clean.splitlines()):
            return _empty_output("seep_r2_decompile", "函数摘要为空，先用 seep_r2_cmd(afl) 确认目标")
        summary = (
            f"[DECOMPILE SUMMARY MODE — 最省 Token 函数摘要]\n"
            f"Target: {target}\n"
            f"{clean}\n"
            f"提示: 使用 output_mode='fold' 或 'full' 获取伪代码详情。"
        )
        return _budget_gate("seep_r2_decompile", summary, "用 target 收窄到具体函数",
                            budget_chars=limit_tokens)

    cmd = f"aaa; pdc @ {target}"
    out = _run_cmd([R2_EXE, "-q", "-e", "scr.color=0", "-c", cmd, os.path.abspath(binary_path)], timeout=60)
    cleaned = _clean_r2_output(out)
    if _is_err_payload(cleaned):
        return _empty_output("seep_r2_decompile", "r2 报错：" + _is_err_payload(cleaned))
    output_lines = [l for l in cleaned.splitlines() if not l.startswith("INFO:") and not l.startswith("WARN:")]

    if output_mode == "fold":
        result, error = _r2_focus_output("seep_r2_decompile", target, output_lines, "fold")
        if error:
            return error
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
        "用 output_mode='fold'/'summary' 降噪，或 target 换成更小的函数",
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
        return json.dumps(_inspect_apk(apk_path), indent=2, ensure_ascii=False)
    except Exception as exc:  # boundary: malformed ZIP/deflate must not crash MCP
        return json.dumps({
            "ok": False, "error": "invalid_apk", "path": apk_path,
            "detail": "%s: %s" % (type(exc).__name__, exc),
        }, ensure_ascii=False, indent=2)

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
        return json.dumps({
            "ok": False, "error": "java_missing",
            "hint": "Install JDK 17+ or set JAVA_HOME.",
        }, ensure_ascii=False, indent=2)
    jadx_entry = JADX_BAT if os.path.isfile(JADX_BAT) else shutil.which("jadx")
    if not jadx_entry:
        return json.dumps({
            "ok": False, "error": "jadx_missing", "expected": JADX_BAT,
        }, ensure_ascii=False, indent=2)

    if not output_dir:
        stem = Path(apk_path).stem
        output_dir = os.path.join(os.path.dirname(os.path.abspath(apk_path)), f"{stem}_jadx_src")

    result = _run_jadx(java_path, jadx_entry, apk_path, output_dir,
                       deobfuscate=deobfuscate, timeout=300)
    if result.get("status") in ("ok", "partial"):
        return json.dumps(result, ensure_ascii=False, indent=2)
    return _empty_output(
        "seep_apk_decompile",
        "JADX 未生成可验证的源码/资源；诊断保留 rc、stderr 与 staging 路径。",
        diagnostics=result,
    )

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
    if not os.path.isfile(APKTOOL_JAR):
        return _empty_output(
            "seep_apk_unpack",
            "Apktool JAR 不存在，不能把缺失工具当成解包完成。",
            diagnostics={"error": "apktool_jar_missing", "expected": APKTOOL_JAR},
        )

    if not output_dir:
        stem = Path(apk_path).stem
        output_dir = os.path.join(os.path.dirname(os.path.abspath(apk_path)), f"{stem}_apktool")
    output_dir = os.path.abspath(os.fspath(output_dir))
    if os.path.lexists(output_dir):
        if not os.path.isdir(output_dir) or os.path.islink(output_dir):
            return _empty_output(
                "seep_apk_unpack",
                "输出路径已存在但不是普通目录；拒绝覆盖。",
                diagnostics={"error": "output_not_directory", "output_dir": output_dir},
            )
        if os.listdir(output_dir):
            return _empty_output(
                "seep_apk_unpack",
                "输出目录非空；为保护已有文件拒绝覆盖。换一个空目录后重试。",
                diagnostics={"error": "output_not_empty", "output_dir": output_dir},
            )

    parent = os.path.dirname(output_dir)
    try:
        os.makedirs(parent, exist_ok=True)
        stage_dir = tempfile.mkdtemp(prefix=".seep-apktool-", dir=parent)
    except OSError as exc:
        return _empty_output(
            "seep_apk_unpack",
            "无法创建隔离输出目录，未启动 Apktool。",
            diagnostics={"error": "stage_create_failed", "detail": str(exc)},
        )

    cmd = [java_path, "-jar", APKTOOL_JAR, "d", "-f"]
    if no_src:
        cmd.append("-s")
    cmd.extend(["-o", stage_dir, os.path.abspath(apk_path)])

    capture = _run_capture(cmd, timeout=300)
    produced = os.path.isdir(stage_dir) and bool(os.listdir(stage_dir))
    if not capture["ok"] or not produced:
        return _empty_output(
            "seep_apk_unpack",
            "Apktool 未生成可验证产物；已有输出目录未被修改。",
            diagnostics={
                "returncode": capture["returncode"],
                "stdout": capture["stdout"][:4000],
                "stderr": capture["stderr"][:4000],
                "error": capture["error"],
                "staging": stage_dir,
                "output_published": False,
            },
        )
    try:
        if os.path.isdir(output_dir):
            os.rmdir(output_dir)  # checked empty before subprocess; race is handled below
        os.replace(stage_dir, output_dir)
    except OSError as exc:
        return _empty_output(
            "seep_apk_unpack",
            "Apktool 有产物，但发布到目标目录失败；staging 已保留。",
            diagnostics={
                "returncode": capture["returncode"],
                "stdout": capture["stdout"][:4000],
                "stderr": capture["stderr"][:4000],
                "error": "publish_failed",
                "detail": str(exc),
                "staging": stage_dir,
                "output_published": False,
            },
        )
    log = (capture["stdout"].strip() + "\n" + capture["stderr"].strip()).strip()
    return json.dumps({
        "ok": True,
        "status": "ok",
        "tool": "seep_apk_unpack",
        "output_dir": output_dir,
        "published": True,
        "log": log[:2000],
    }, ensure_ascii=False, indent=2)

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
    limit, err = _int_in_range("seep_apk_smali_search", "limit", limit, 1, 10000)
    if err:
        return err
    if not isinstance(pattern, str) or not pattern:
        return _invalid_param("seep_apk_smali_search", "pattern 必须是非空字符串")
    if len(pattern) > 4000:
        return _invalid_param("seep_apk_smali_search", "pattern 不能超过 4000 字")
    if not isinstance(case_sensitive, bool):
        return _invalid_param("seep_apk_smali_search", "case_sensitive 必须是布尔值")
    if not isinstance(directory, str) or not os.path.isdir(directory):
        return _invalid_param("seep_apk_smali_search", "directory 必须指向现有目录")

    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        regex = re.compile(pattern, flags)
    except re.error as e:
        return _invalid_param("seep_apk_smali_search", "Invalid regex pattern: %s" % e)

    matches = []
    match_total = 0
    scan_errors = []
    scanned_files = 0
    skipped_non_regular = 0

    def on_walk_error(exc):
        if len(scan_errors) < 20:
            scan_errors.append("%s: %s" % (type(exc).__name__, exc))

    for root, _, files in os.walk(directory, onerror=on_walk_error, followlinks=False):
        for f in files:
            if f.endswith((".smali", ".java", ".xml", ".json", ".txt")):
                fpath = os.path.join(root, f)
                if os.path.islink(fpath) or not os.path.isfile(fpath):
                    skipped_non_regular += 1
                    continue
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        scanned_files += 1
                        for idx, line in enumerate(fh, 1):
                            if regex.search(line):
                                match_total += 1
                                if len(matches) < limit:
                                    rel = os.path.relpath(fpath, directory)
                                    matches.append(f"{rel}:{idx}: {line.strip()[:200]}")
                except OSError as exc:
                    if len(scan_errors) < 20:
                        scan_errors.append("%s: %s" % (type(exc).__name__, exc))

    res = matches[:limit]
    if match_total > limit:
        res.append(_page_footer(len(res), match_total, "seep_apk_smali_search",
                                "调大 limit，或把 pattern / directory 收窄"))
    status = "partial" if scan_errors else ("matched" if res else "zero_results")
    return json.dumps({
        "ok": not scan_errors,
        "status": status,
        "tool": "seep_apk_smali_search",
        "directory": os.path.abspath(directory),
        "pattern": pattern,
        "scanned_files": scanned_files,
        "skipped_non_regular": skipped_non_regular,
        "error_count": len(scan_errors),
        "errors": scan_errors,
        "count": len(matches),
        "match_total": match_total,
        "matches": res,
        "note": ("扫描过程中有读取错误；零命中或部分命中都不能解释成“扫描完整且未发现”。"
                 if scan_errors else "扫描完成。"),
    }, indent=2, ensure_ascii=False)

# ---------------------------------------------------------------------------
# 4. ReverseLab 攻防战术知识库与 CTF Payload 库
# ---------------------------------------------------------------------------

@server.tool()
def seep_kb_search(query: str, category: Optional[str] = None, limit: int = 10) -> str:
    """在 ReverseLab 逆向与 Web/PE/CVE 攻防知识库中检索战术指南，术语和口语都能查。

    支持大白话（"加壳了怎么脱" → unpack/OEP/dump；"这软件要卡密怎么绕过" → license/keygen），
    每条命中回显 matched_terms / matched_bigrams（靠哪些词命中，便于判断可信度）；空结果给
    3 条最近邻文章 + 为什么接近，而不是只回一句"未命中"。

    Args:
        query: 检索词，术语或口语均可（例如 'JWT', 'SSRF', 'vmp', '加壳了怎么脱', '这软件要卡密怎么绕过'）
        category: 可选限定目录分类（例如 'ctf-website', 'pe-reverse', 'apk-reverse', 'general'）
        limit: 最大返回文章数，默认 10
    """
    if category is not None and kb_rel_error(category):
        return _invalid_param("seep_kb_search", "category " + kb_rel_error(category))
    if not isinstance(query, str) or not query.strip() or len(query) > 4000:
        return _invalid_param("seep_kb_search", "query 必须是 1..4000 字的非空字符串")
    limit, err = _int_in_range("seep_kb_search", "limit", limit, 1, 200)
    if err:
        return err
    if category:
        candidate = _kb_join(KB_DIR, category)
        # 真实边界：分类目录必须在 KB 根内，且 symlink 指到外部同样拒绝（不读根外内容）
        if not _kb_within(candidate, KB_DIR) or not os.path.isdir(candidate):
            return _invalid_param("seep_kb_search",
                                  "category 必须指向 KB 根内已存在的目录")
        search_root = candidate
    else:
        search_root = KB_DIR
    md_files = glob.glob(os.path.join(search_root, "**", "*.md"), recursive=True)
    md_files = [p for p in md_files if _kb_within(p, search_root)]
    # === SEEP-EXT: kb_local BEGIN === 本地覆盖层（Tool/mcp/kb_local/，不属于 vendored 上游）
    _KB_LOCAL = KB_LOCAL_DIR
    if os.path.isdir(_KB_LOCAL):
        md_files += [p for p in glob.glob(os.path.join(_KB_LOCAL, "**", "*.md"), recursive=True)
                     if _kb_within(p, _KB_LOCAL)]
    # === SEEP-EXT: kb_local END ===

    # ---- 权重与阈值（集中在此；调参不必动算法）----
    _KB_SINGLE_WEIGHT, _KB_TITLE_BOOST, _KB_PATH_BOOST = 0.2, 6, 4   # 单字 / 标题行 / 路径
    _KB_MAX_TOKENS, _KB_MAX_ALIAS = 8, 12            # 切词上限 / 别名术语上限
    _KB_MIN_COVERAGE = 0.6          # 原查询 2 token 要求全命中；3+ 按比例
    _KB_ALIAS_WEIGHT, _KB_GRAM_WEIGHT = 0.85, 0.45   # 别名术语 / CJK 2-gram 的权重
    _KB_GRAM_MIN_COVERAGE, _KB_GRAM_ABS_FLOOR = 0.45, 1.2   # 2-gram 覆盖率 / 最低分
    _KB_PATH_MULT, _KB_MAX_MATCHED = 1.55, 8                # 路径加权 / 回显上限

    # 1) 归一化 + 别名展开 + 2-gram 切片
    _groups, _stopwords = _kb_load_synonyms()
    pat = _kb_normalize_query(query, _stopwords)
    _alias_terms, _boost_paths, _fired = _kb_alias_expand(pat, _groups)
    _alias_terms = _alias_terms[:_KB_MAX_ALIAS]
    _bigrams = _kb_cjk_bigrams(pat)

    def _kb_split(q):   # 只切词边界；pattern 里的正则元字符不受影响
        return [x for x in (t.strip() for t in
                            re.split(r"[\s,;/|、，。；：!?()（）\[\]【】]+", q)) if x]
    _kb_query_tokens = _kb_split(pat)[:_KB_MAX_TOKENS]
    _kb_multi = len(_kb_query_tokens) > 1
    _kb_tokens = list(_kb_query_tokens)
    for _t in _alias_terms:
        if _t not in _kb_tokens:
            _kb_tokens.append(_t)

    # 2) 一次读完：小写正文 / 原文 / 标题 / 整串命中（原实现每个 token 都重算一遍 lower()）
    _kb_low, _kb_contents, _kb_title, _kb_matched, hits = {}, {}, {}, {}, []
    for fpath in md_files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
            _rel = os.path.relpath(fpath, KB_DIR).replace("\\", "/")
            # 本地覆盖层：统一成 kb_local/<相对路径>，避免同一文件被两次打分产出两条 hit
            if fpath.startswith(_KB_LOCAL + os.sep):
                _rel = "kb_local/" + os.path.relpath(fpath, _KB_LOCAL).replace(os.sep, "/")
            if _rel in _kb_low:
                continue
            _low = content.lower()
            _kb_low[_rel], _kb_contents[_rel] = _low, content
            title = ""
            for line in content.splitlines()[:5]:
                if line.startswith("# "):
                    title = line.lstrip("# ").strip()
                    break
            _kb_title[_rel] = title or Path(_rel).stem
            score, _lit = 0, []
            if pat and pat in Path(fpath).name.lower():
                score += 10
                _lit.append(pat)
            if pat and pat in _kb_title[_rel].lower():
                score += 8
                if pat not in _lit:
                    _lit.append(pat)
            if pat and _low.count(pat):
                score += _low.count(pat)
                if pat not in _lit:
                    _lit.append(pat)
            if score > 0:
                _kb_matched[_rel] = _lit
                hits.append({"path": _rel, "title": _kb_title[_rel], "score": score,
                             "snippet": content[:300].strip().replace("\n", " ")})
        except Exception:  # noqa: BLE001 —— 单篇读失败不该拖垮整次检索
            pass

    # 3) 相关性打分：原查询词（带覆盖率闸门）+ 别名术语 + CJK 2-gram 兜底
    import math as _kb_math

    _kb_n = max(len(_kb_low), 1)
    _kb_df = {}
    for _t in _kb_tokens + _bigrams:
        if _t not in _kb_df:
            _kb_df[_t] = sum(1 for _txt in _kb_low.values() if _t in _txt)

    def _kb_idf(t: str) -> float:
        return _kb_math.log((_kb_n + 1) / (_kb_df.get(t, 1) + 1)) + 1.0

    def _kb_weight(t: str) -> float:
        return 1.0 if len(t) > 1 else _KB_SINGLE_WEIGHT

    def _kb_pos_mult(rel: str, t: str) -> float:
        m = 1.0
        if t in _kb_title.get(rel, "").lower():
            m += _KB_TITLE_BOOST / 10.0
        if t in rel.lower():
            m += _KB_PATH_BOOST / 10.0
        return m

    _totals, _why = {}, {}   # rel -> score / (命中的整串+术语, 命中的 CJK 双字片段)
    for _rel, _low in _kb_low.items():
        _s, _m, _gm = 0.0, [], []
        # (a) 原查询词：保留原覆盖率闸门（2 token 必须全中，避免"命中一个就上榜"）
        _q_hits = [(_t, _kb_hit_count(_low, _t)) for _t in _kb_query_tokens]
        _q_hits = [(_t, _c) for _t, _c in _q_hits if _c]
        if _q_hits:
            _cov = len(_q_hits) / max(len(_kb_query_tokens), 1)
            if not (_kb_multi and _cov < _KB_MIN_COVERAGE):
                _s_q = sum(_kb_idf(_t) * _kb_weight(_t) * _kb_pos_mult(_rel, _t) * min(_c, 8)
                           for _t, _c in _q_hits)
                if _s_q * (_cov ** 2) > 0:
                    _s += _s_q * (_cov ** 2)
                    _m.extend(t for t, _c in _q_hits)
        # (b) 别名术语：口语→术语展开的部分不设覆盖率闸门（要的就是召回）
        _s_a = 0.0
        for _t in _alias_terms:
            _c = _kb_hit_count(_low, _t)
            if _c:
                _s_a += _kb_idf(_t) * _kb_weight(_t) * _kb_pos_mult(_rel, _t) * min(_c, 8)
                _m.append(_t)
        if _s_a > 0:
            _s += _s_a * _KB_ALIAS_WEIGHT
        # (c) CJK 2-gram 兜底：中文没空格，双字切片是最后一道召回网
        if _bigrams:
            _g_hits = [(_g, _low.count(_g)) for _g in _bigrams]
            _g_hits = [(_g, _c) for _g, _c in _g_hits if _c]
            _g_cov = len(_g_hits) / len(_bigrams)
            if _g_hits and _g_cov >= _KB_GRAM_MIN_COVERAGE:
                _s_g = sum(_kb_idf(_g) * _KB_GRAM_WEIGHT * min(_c, 4) for _g, _c in _g_hits)
                if _s_g * _g_cov >= _KB_GRAM_ABS_FLOOR:
                    _s += _s_g * _g_cov
                    _gm.extend(g for g, _c in _g_hits)
        if _s > 0:
            _totals[_rel], _why[_rel] = _s, (_m, _gm)

    # 4) boost_paths 加权 + 合并入 hits
    _kb_index = {h["path"]: h for h in hits}
    for _rel, _s in _totals.items():
        _nb = sum(1 for _p in _boost_paths if _p in _rel.lower())
        _final = _s * (_KB_PATH_MULT ** min(_nb, 2)) if _nb else _s
        if _rel in _kb_index:
            _kb_index[_rel]["score"] += _final
        else:
            hits.append({"path": _rel, "title": _kb_title.get(_rel, Path(_rel).stem),
                         "score": _final, "snippet": ""})

    # 5) matched_terms：这次是靠哪些词命中的（术语 与 CJK 双字片段分开列）——
    #    只有 matched_bigrams 没有 matched_terms = 弱召回，别当结论。
    for _h in hits:
        _terms_hit, _grams_hit = _why.get(_h["path"], ([], []))
        _mt = []
        for _t in list(_kb_matched.get(_h["path"], [])) + list(_terms_hit):
            if _t and _t not in _mt:
                _mt.append(_t)
        _h["matched_terms"] = _mt[:_KB_MAX_MATCHED]
        if _grams_hit:
            _h["matched_bigrams"] = list(dict.fromkeys(_grams_hit))[:6]
        _nb = sum(1 for _p in _boost_paths if _p in _h["path"].lower())
        if _nb:
            _h["boost"] = "boost_paths×%d" % _nb
        _h["score"] = round(_h["score"], 2)

    hits.sort(key=lambda x: x["score"], reverse=True)
    top = hits[:limit]

    # 6) snippet 改为命中位置居中（优先原查询词，其次别名术语，最后双字片段）
    for _h in top:
        _txt = _kb_contents.get(_h.get("path", ""))
        if not _txt:
            continue
        _low = _txt.lower()
        _pos = -1
        for _t in (_kb_query_tokens + _alias_terms + _bigrams + [pat]):
            _i = _low.find(_t) if _t else -1
            if _i != -1 and (_pos == -1 or _i < _pos):
                _pos = _i
        if _pos >= 0:
            _h["snippet"] = _txt[max(0, _pos - 160):_pos + 160].strip().replace("\n", " ")

    if top:
        return json.dumps(top, indent=2, ensure_ascii=False)

    # 7) 空结果绝不回"未命中"：给 3 条最近邻 + 为什么接近，让模型能顺着读下去
    _near = []
    for _rel, _low in _kb_low.items():
        _sc, _ht = 0.0, []
        for _t in _kb_tokens:
            _c = _kb_hit_count(_low, _t)
            if _c:
                _ht.append(_t)
                _sc += _kb_idf(_t) * min(_c, 8)
        _hg = [g for g in _bigrams if g in _low]
        if _hg:
            _sc += 0.35 * sum(_kb_idf(g) for g in _hg)
        if _sc > 0:
            _near.append((_sc, _rel, _ht, _hg))
    _near.sort(key=lambda x: x[0], reverse=True)
    _out = []
    for _sc, _rel, _ht, _hg in _near[:3]:
        if _ht:
            _why_text = "正文含相关术语 %s" % "、".join(_ht[:5])
        else:
            _why_text = "正文含相关双字片段 %s（词形不同但同域）" % "、".join(_hg[:5])
        _out.append({"path": _rel, "title": _kb_title.get(_rel, Path(_rel).stem),
                     "score": round(_sc, 2), "matched_terms": _ht[:_KB_MAX_MATCHED],
                     "matched_bigrams": list(dict.fromkeys(_hg))[:6], "why": _why_text,
                     "read": 'seep_kb_read("%s")' % _rel})
    if not _out:
        # 与查询零字面重合时"最近邻"不存在 —— 给库的入口/起步清单，而不是空手回"未命中"
        for _rel, _why in (
                ("general/techniques/methodology/01-reverse-checklist-first-30-min.md",
                 "库里的逆向 30 分钟起步清单：先按它把目标分类，再回到检索"),
                ("general/techniques/methodology/02-toolchain-decision-tree.md",
                 "工具链决策树：按目标类型/平台选工具，适合先定位该用哪套打法"),
                ("field_journal__index.md",
                 "现场日志索引：按真实案例找同类问题（这些案例都有可复现链路）")):
            if _rel in _kb_low:
                _out.append({"path": _rel, "title": _kb_title.get(_rel, Path(_rel).stem),
                             "score": 0.0, "matched_terms": [], "why": "与查询无字面重合，但" + _why,
                             "read": 'seep_kb_read("%s")' % _rel})
            if len(_out) >= 3:
                break
    return json.dumps({
        "ok": False, "status": "zero_match", "query": query,
        "expanded_terms": _alias_terms, "fired_groups": _fired,
        "hits": [], "near_miss": _out,
        "hint": ("没有直接命中（zero_match，不是工具崩溃）：上面 %d 篇是与本次查询重合度最高的文章"
                 "（按术语/双字片段 IDF 加权），先 seep_kb_read 读一篇再决定；若都不对，先把问题对到索引里的分组"
                 "（'INDEX-BY-QUESTION.md'：按「客户怎么问」分的入口表，seep_kb_read 可直接读），"
                 "再换成更具体的术语或英文关键词重查（本库 %d 篇）。") % (len(_out), len(_kb_low)),
    }, indent=2, ensure_ascii=False)


# 兼容早期 FastMCP 暴露的 `.fn` 调用形态：验收/脚本里 `seep_kb_search.fn(...)` 能直接跑
setattr(seep_kb_search, "fn", seep_kb_search)


def _byte_len(text: str) -> int:
    """UTF-8 字节长度（kb_read 的 max_chars 分支用；此前缺失 → 41% 的长文章会崩）。"""
    return len(str(text).encode("utf-8", "replace"))


def _kb_article_paths():
    """KB 内全部文章的相对路径（含 kb_local/<相对路径>），供 kb_read 模糊解析用。

    两个根都做 realpath 边界过滤：KB 目录里的 symlink 若指向根外（例如 work/、用户目录），
    它的文章不会进清单，模糊解析就不可能把它带出来。
    """
    out = []
    for root, prefix in ((KB_DIR, ""), (KB_LOCAL_DIR, "kb_local/")):
        if os.path.isdir(root):
            out += [prefix + os.path.relpath(p, root).replace(os.sep, "/")
                    for p in glob.glob(os.path.join(root, "**", "*.md"), recursive=True)
                    if _kb_within(p, root)]
    return out


def _kb_path_from_rel(rel: str) -> str:
    """相对路径 → 绝对路径（kb_local/ 前缀路由到本地覆盖层；只按段拼接）。"""
    rel = (rel or "").replace("\\", "/")
    if rel.startswith("kb_local/"):
        return _kb_join(KB_LOCAL_DIR, rel[len("kb_local/"):])
    return _kb_join(KB_DIR, rel)


def _kb_search_paths(query: str, n: int = 3):
    """用 seep_kb_search 的检索结果反查文章路径（口语 → 文章）。

    只认真正的命中（hits + 命中了术语/原查询词）：near_miss 和"只靠 CJK 双字片段"
    都是弱召回，替人拍板会读出一篇无关文章，比报错更糟。
    """
    try:
        fn = getattr(seep_kb_search, "fn", seep_kb_search)
        data = json.loads(fn(query, limit=n))
    except Exception:
        return []
    return [h.get("path", "") for h in (data if isinstance(data, list) else [])
            if isinstance(h, dict) and h.get("path") and h.get("matched_terms")]


@server.tool()
def seep_kb_read(article_path: str, max_chars: int = 6000) -> str:
    """读取 ReverseLab 知识库中某篇战术文档或技巧手册的全文内容。

    article_path 可以是完整相对路径、路径片段、文件名，也可以是大白话关键词
    （没精确命中时按别名表 + 双字片段自动定位，并在正文前注明实际读的是哪篇）。

    Args:
        article_path: 相对 KB 根目录的路径（可通过 seep_kb_search 获得，例如 'ctf-website/checklists/web-ctf-first-30-min.md'）
        max_chars: 最大返回字符数，默认 6000（1..200000）
    """
    rel_err = kb_rel_error(article_path)
    if rel_err:
        return _invalid_param("seep_kb_read", "article_path " + rel_err)
    max_chars, err = _int_in_range("seep_kb_read", "max_chars", max_chars, 1, 200000)
    if err:
        return err

    # 本地覆盖层：kb_local/ 前缀走 Tool/mcp/kb_local/
    _given = (article_path or "").replace("\\", "/").strip()
    target = _kb_join(KB_LOCAL_DIR, _given[len("kb_local/"):]) \
        if _given.startswith("kb_local/") else _kb_join(KB_DIR, _given)
    note = ""
    # 真实边界（含 symlink）：不在对应根内一律当“不存在”，不读、也不回显内容。
    if os.path.isfile(target) and not _kb_within(
            target, KB_LOCAL_DIR if _given.startswith("kb_local/") else KB_DIR):
        return _invalid_param("seep_kb_read", "article_path 越出 KB 根（symlink 也不允许）")
    if not os.path.isfile(target):
        # 模糊解析：① 目录/目录片段 → 列清单；② 路径片段/后缀（容忍少写目录、少写 .md）；
        # ③ 大白话 → 走检索（别名展开 + 2-gram）定位到 top1，并在正文前注明实际读的是哪篇。
        _want = _given.strip("/")
        _want_md = _want if _want.endswith(".md") else _want + ".md"
        _all = _kb_article_paths()
        if _want and not _want.lower().endswith(".md"):
            _inside = [r for r in _all if ("/" + _want + "/") in ("/" + r)]
            if _inside and not [r for r in _all
                                if Path(r).stem.lower() == Path(_want_md).stem.lower()]:
                return ("[INFO] '%s' 是目录，不是文章。目录下 %d 篇：\n%s\n"
                        "下一步：seep_kb_read(\"<上面任一路径>\")；或 seep_kb_search(\"<你的问题>\")"
                        % (_want, len(_inside), "\n".join(" - " + r for r in _inside[:20])))
        _cands = [r for r in _all if _want_md and (r.endswith(_want_md) or _want_md in r)]
        if not _cands and _want:
            _cands = [r for r in _all if Path(r).stem.lower() == Path(_want_md).stem.lower()]
        _others = []
        if not _cands:
            _guessed = _kb_search_paths(_given, 3)
            if _guessed:
                _cands, _others = _guessed[:1], _guessed[1:]
        elif len(_cands) > 1:
            # 同名多份（常见于 _archive/ 归档副本）：优先非归档里路径最短的那篇
            _cands.sort(key=lambda r: (r.startswith("_archive/"), len(r)))
            _others = _cands[1:]
            _cands = _cands[:1]
        if not _cands:
            return ("[ERROR]: Article not found: %s。KB 里既没有字面相近的文章，检索也没有足够交集——"
                    "先 seep_kb_search(\"<你的问题原话>\") 拿路径，再读。" % article_path)
        target = _kb_path_from_rel(_cands[0])
        if not _kb_within(target, KB_LOCAL_DIR if _cands[0].startswith("kb_local/")
                          else KB_DIR):
            return _invalid_param("seep_kb_read", "article_path 越出 KB 根（symlink 也不允许）")
        note = "[提示] 无精确同名文件，已按路径片段/检索自动定位到：%s\n\n" % _cands[0]
        if _others:
            note += "[其他候选] %s\n\n" % "；".join(_others[:3])
    with open(target, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
        if len(text) > max_chars:
            # 超预算仍返回结构化 JSON（note 塞进 artifact_hint，不破坏 json.loads）
            _hint = "全文长度 %d 字符（%d 字节）；本次未返回任何片段，避免把半篇当全篇" % (
                len(text), _byte_len(text))
            return _resource_constraint(
                "seep_kb_read", text, "把 max_chars 调到 ≥ %d 再读全文" % len(text),
                artifact_hint=(note.strip() + "；" + _hint) if note else _hint)
        return note + text

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
    """给自动建案判型，并保留完整主域、辅助域与歧义状态。

    第 4 轮评审 P1：以前自动建案一律 `domain=softseep` —— 等于「没判过型」冒充「判过型」，
    后面的域深度/路由门禁全部失真。现在用 `route.route.resolve()`（唯一路由入口）对
    「目标文件名 + 任务名」判一次。路由返回的全部具体域都必须保留；只留第一条会把
    跨域项目伪装成单域项目。判不出时主域为空并提示过 seep-router。
    """
    note = "未判型，先过 seep-router"
    try:
        text = "%s %s" % (os.path.basename(str(binary_path or "")), str(task_name or ""))
        _hits, domains = _route_module().resolved_domains(text)
        domains = [str(domain) for domain in domains
                   if str(domain) and str(domain) != "seep-router"]
        if not domains:
            return {"primary_domain": "", "auxiliary_domains": [],
                    "ambiguity": False, "domain_note": note}
        return {"primary_domain": domains[0],
                "auxiliary_domains": domains[1:],
                "ambiguity": len(domains) > 1,
                "domain_note": ""}
    except Exception as e:  # noqa: BLE001
        return {"primary_domain": "", "auxiliary_domains": [],
                "ambiguity": False,
                "domain_note": "%s（判型失败：%s）" % (note, str(e)[:60])}


def _store_case_routing(mod, case_dir: str, routing: Dict[str, Any]) -> Dict[str, Any]:
    """Persist routing facts without replacing an existing operator-set domain."""
    meta = mod._case_metadata(case_dir)
    routed_primary = str(routing.get("primary_domain") or "").strip()
    existing = str(meta.get("domain") or "").strip()
    effective_primary = existing or routed_primary
    if not existing and routed_primary:
        meta["domain"] = routed_primary
    candidates = []
    if routed_primary and routed_primary != effective_primary:
        candidates.append(routed_primary)
    candidates.extend(routing.get("auxiliary_domains") or [])
    auxiliary_domains = []
    for domain in candidates:
        domain = str(domain or "").strip()
        if domain and domain != effective_primary and domain not in auxiliary_domains:
            auxiliary_domains.append(domain)
    meta["auxiliary_domains"] = auxiliary_domains
    meta["ambiguity"] = bool(routing.get("ambiguity"))
    mod._atomic_write_json(os.path.join(case_dir, "case.json"), meta)
    return meta


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
        with open(p, "rb") as handle:
            h = hashlib.sha256(handle.read()[:1 << 20]).hexdigest()[:8]
        stem = os.path.splitext(os.path.basename(p))[0][:28] or "target"
        base = os.environ.get("SEEP_CASE_DIR") or os.path.join(
            os.path.expanduser("~"), ".seep", "cases", "auto")
        cdir = os.path.join(base, "%s-%s" % (stem, h))
        out["case"] = cdir.replace("\\", "/")
        # Route before the idempotence return so an old one-domain auto case is
        # upgraded with the full primary/auxiliary contract on next use.
        routing = _domain_for(p, task_name)
        domain = str(routing.get("primary_domain") or "")
        out["domain"] = domain or None
        out["auxiliary_domains"] = list(routing.get("auxiliary_domains") or [])
        out["ambiguity"] = bool(routing.get("ambiguity"))
        if routing.get("domain_note"):
            out["domain_note"] = routing["domain_note"]
        if os.path.isfile(os.path.join(cdir, "case.json")):
            mod = _case_state_module()
            persisted = _store_case_routing(mod, cdir, routing)
            out["domain"] = str(persisted.get("domain") or "") or None
            out["auxiliary_domains"] = list(persisted.get("auxiliary_domains") or [])
            out["ambiguity"] = bool(persisted.get("ambiguity"))
            out["created"] = False
            return out
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
        persisted = _store_case_routing(mod, cdir, routing)
        out["domain"] = str(persisted.get("domain") or "") or None
        out["auxiliary_domains"] = list(persisted.get("auxiliary_domains") or [])
        out["ambiguity"] = bool(persisted.get("ambiguity"))
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
    if not isinstance(target_path, str) or not target_path.strip():
        return json.dumps({
            "ok": False,
            "error": "invalid_target",
            "blocked_at": "seep_auto_triage",
            "wrote_files": 0,
        }, indent=2, ensure_ascii=False)

    try:
        t_path = Path(target_path).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        return json.dumps({
            "ok": False, "error": "target_not_found",
            "blocked_at": "seep_auto_triage", "target_path": target_path,
            "detail": "%s: %s" % (type(exc).__name__, exc),
            "wrote_files": 0,
        }, indent=2, ensure_ascii=False)
    if not t_path.is_file():
        return json.dumps({
            "ok": False, "error": "target_not_regular_file",
            "blocked_at": "seep_auto_triage",
            "detail": "目标必须是普通文件；目录、设备、FIFO 或特殊文件不会建案。",
            "wrote_files": 0,
        }, indent=2, ensure_ascii=False)
    try:
        file_size = t_path.stat().st_size
        md5_val, sha256_val = _hash_file(str(t_path))
    except OSError as exc:
        return json.dumps({
            "ok": False, "error": "target_unreadable",
            "blocked_at": "seep_auto_triage",
            "detail": "%s: %s" % (type(exc).__name__, exc),
            "wrote_files": 0,
        }, indent=2, ensure_ascii=False)

    # 1. 计算哈希（整文件流式，绝不截断）
    # 校验普通文件和完整哈希之后才允许产生案件/状态副作用。
    _attached = _attached_for(str(t_path), task_name=task_name or "")

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
    report_file = os.path.join(report_dir, "%s_security_assessment_report.md"
                               % re.sub(r'[^\w\-]', '_', target_name))
    now_str = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    content = build_report_md(clean_task, target_name, vuln_type, branch_location, description,
                              poc_summary, defense_recommendation, disasm_snippet,
                              ev_dir, strong, now_str)
    try:
        _atomic_write_text(report_file, content)
    except OSError as exc:
        try:
            if os.path.isdir(report_dir) and not os.listdir(report_dir):
                os.rmdir(report_dir)
        except OSError:
            pass
        return json.dumps({
            "ok": False, "error": "report_write_failed",
            "blocked_at": "seep_gen_security_report", "wrote_files": 0,
            "detail": "%s: %s" % (type(exc).__name__, exc),
        }, indent=2, ensure_ascii=False)
    return json.dumps({
        "ok": True, "status": "Reported", "report_path": report_file,
        "evidence_claims": strong, "confidence": "derived", "authority": "shipped-artifact",
        "limitations": ["只覆盖 evidence_claims 里的结论；其余未验证部分不进本报告",
                        "反汇编摘录为空表示本次未取，不代表不存在"],
        "message": f"报告已生成并归档至: {clean_task}/reports/{os.path.basename(report_file)}",
    }, indent=2, ensure_ascii=False)


# 选择性吸收的扩展：工具发现/安装重探与控制方式降级；不是完整 REA 运行时。
# seep_r2_decompile 仅驱动 r2。下面的私有引擎辅助函数未接入 MCP 反编译入口。

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


def _verify_discovered(tid: str, discovery: dict) -> dict:
    """Verify a discovered path without turning file existence into availability."""
    # Python libraries are verified by tool_autodiscover in a fresh interpreter.
    # Their command is the interpreter path, not a native executable, so sending
    # them through the executable identity probes would downgrade a successful
    # import to found_no_verify.
    if discovery.get("kind") == "python_lib":
        if not discovery.get("available"):
            return {"verified": False, "verdict": "missing", "tool_id": tid,
                    "kind": "python_lib", "module": discovery.get("module", ""),
                    "why": discovery.get("note") or "当前解释器无法导入该 Python 库"}
        return {
            "verified": True,
            "verdict": "ready",
            "tool_id": tid,
            "kind": "python_lib",
            "module": discovery.get("module", ""),
            "interpreter": discovery.get("interpreter", ""),
            "command": discovery.get("command", ""),
            "why": "隔离解释器导入成功",
        }
    if not discovery.get("available"):
        return {"verified": False, "verdict": "missing", "tool_id": tid,
                "why": "发现层没有找到可执行文件"}
    return _verify_tool(tid, discovery.get("command", ""), APKTOOL_JAR)


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
            verification = _verify_discovered(tid, disc)
            out["path_found"] = True
            out["verification"] = verification
            if verification.get("verified"):
                out["available"] = True
                out["status"] = "ready"
            else:
                out["available"] = False
                out["status"] = "found_no_verify"
                out["install_note"] = (
                    "路径存在但行为/身份探针未通过；先按 verification.why 核查，"
                    "不能把它当可用工具直接跑。")
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
                recheck = exec_res["recheck"]
                out.update(recheck)
                verification = _verify_discovered(tid, recheck)
                out["verification"] = verification
                out["available"] = bool(verification.get("verified"))
                out["status"] = "ready" if verification.get("verified") else "found_no_verify"
                out["after_install"] = recheck
            else:
                out["install_note"] = "自动安装已尝试但未就绪：看 install_attempt 的 stderr/命令，换一种途径重试"

        return json.dumps(out, indent=2, ensure_ascii=False)

    # 兜底回退：若插件未载入
    res = _resolve_tool(tid)
    out = {"tool_id": tid, "install_policy": policy}
    out.update(res)
    if res.get("available"):
        verification = _verify_discovered(tid, res)
        out["path_found"] = True
        out["verification"] = verification
        out["available"] = bool(verification.get("verified"))
        out["status"] = "ready" if verification.get("verified") else "found_no_verify"
    else:
        out["status"] = "missing"
    return json.dumps(out, indent=2, ensure_ascii=False)


def _load_engine_tiers() -> dict:
    """读取参考引擎顺序；当前 MCP 反编译入口不消费此表。"""
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
        rea_cli = shutil.which("rea")
        if rea_cli:
            return {"available": True, "detail": rea_cli}
        return {"available": False, "detail": "rea executable not found; npx alone does not prove installation"}
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
    if isinstance(pid, bool):
        return _invalid_param("seep_mem_strings", "pid 必须是正整数或进程别名，不能是布尔值")
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return _invalid_param("seep_mem_strings", "非法 pid=%r，必须为正整数。" % (pid,))
    if pid_int <= 0 or pid_int > 0xFFFFFFFF:
        return _invalid_param("seep_mem_strings", "pid 必须在 1..4294967295")
    min_len, err = _int_in_range("seep_mem_strings", "min_len", min_len, 1, 4096)
    if err:
        return err
    max_hits, err = _int_in_range("seep_mem_strings", "max_hits", max_hits, 1, 10000)
    if err:
        return err
    if encoding not in ("ascii", "utf16", "both"):
        return _invalid_param("seep_mem_strings", "encoding 只接受 ascii/utf16/both")
    if not isinstance(pattern, str) or len(pattern) > 4000:
        return _invalid_param("seep_mem_strings", "pattern 必须是不超过 4000 字的字符串")

    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid_int)
    if not h:
        return json.dumps({
            "ok": False, "status": "error", "error": "open_process_failed",
            "pid": pid_int, "winerror": ctypes.get_last_error(),
            "hint": "需管理员权限或目标进程架构一致。",
            "scanned": False, "hits": [], "count": 0,
        }, indent=2, ensure_ascii=False)

    hits = []
    scan_errors = []
    regions_read = 0
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
                    regions_read += 1
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
        if not res:
            error_code = ctypes.get_last_error()
            if error_code not in (0, 87):  # ERROR_INVALID_PARAMETER = normal end of address space
                scan_errors.append("VirtualQueryEx failed: winerror=%s" % error_code)
    except Exception as exc:  # noqa: BLE001 - native boundary must return structured status
        scan_errors.append("%s: %s" % (type(exc).__name__, exc))
    finally:
        # 攻击性加固：无论成功或异常退出，严密关闭目标进程句柄，防止句柄泄露锁死目标
        k32.CloseHandle(h)

    return json.dumps({
        "ok": not scan_errors,
        "status": "partial" if scan_errors else "complete",
        "pid": pid_int, "pattern": pattern, "min_len": min_len, "max_hits": max_hits,
        "encoding": encoding, "regions_read": regions_read,
        "errors": scan_errors, "hits": hits, "count": len(hits),
        "scanned": True,
        "note": "addr 为进程虚拟地址，可直接回填到反汇编/反编译里定位引用该字符串的代码。",
    }, indent=2, ensure_ascii=False)


@server.tool()
@_path_alias
def seep_pcap_extract(pcap_path: str, host_filter: str = "", mode: str = "summary",
                      port: int = 0, max_rows: int = 40) -> str:
    """从 pcap/pcapng 提取通信端点、HTTP 请求/响应、以及可选端口/主机的 TCP 载荷。

    治"卡密/授权在云端"的样本：先看它连了谁、发了什么、回了什么，往往比死磕本地校验更快。

    执行契约（完整判据见 `seep_contract.pcap_*`）：每条 tshark 调用固定
    `-n -r <绑定后的绝对路径>`（`-n` 禁名称解析 → `touches_network=false` 有 argv 证据）；
    argv 全由本函数组装，不接受调用方给 argv/shell/目标；参数先于任何文件/进程访问校验；
    rc/stdout/stderr 分开进 `executions`，stderr 不拼进数据行；rc≠0 / 缺工具 / timeout /
    部分失败 / 空数据 → status=error|unknown|zero_results|partial（**partial 不是成功**）；
    rc==0 的告警进 `warnings` 但照样给数据；`max_rows` 是显式分页，`paging` 给真口径；
    超体积预算走 resource_constraint 拒绝 + continuation，不静默截断。
    """
    # ── 1) 参数校验：先于任何文件/进程访问（MCP 直调也走同一份 contract 判定）──
    params, reason = _pcap_params(mode, port, max_rows, host_filter)
    if params is None:
        return _pcap_failure("seep_pcap_extract", "invalid", "invalid_parameters", reason,
                             hint="mode 用 summary/http/payload；port 0..65535；"
                                  "max_rows 1..10000；host_filter 只接受纯文本")
    mode, port, max_rows = params["mode"], params["port"], params["max_rows"]
    host_filter = params["host_filter"]
    if not isinstance(pcap_path, str) or not pcap_path.strip():
        return _pcap_failure("seep_pcap_extract", "invalid", "invalid_parameters", "pcap_path 必须是非空字符串")
    bound_path = os.path.abspath(pcap_path.strip())
    if not os.path.isfile(bound_path):
        return _pcap_failure("seep_pcap_extract", "error", "pcap_not_found",
                            "pcap 文件不存在或不是普通文件（路径未回显）",
                            hint="传真实存在的 pcap/pcapng 文件；不要用通配符或目录")
    # ── 2) 解析 tshark（缺工具 ≠ 成功）──
    # 只用本模块的解析结果，**不接受**调用方提供可执行路径。
    tshark = shutil.which("tshark") or ""
    if not tshark:
        bases = ([os.environ["ProgramFiles"]] if os.environ.get("ProgramFiles") else []) \
            + list(_tool_roots())
        cands = ["/usr/bin/tshark", "/usr/local/bin/tshark"] + [
            os.path.join(base, "Wireshark", name) for base in bases
            for name in ("tshark.exe", "tshark.EXE")]
        tshark = next((c for c in cands if os.path.isfile(c)), "")
    if not tshark:
        return _pcap_failure("seep_pcap_extract", "error", "tshark_missing",
                            "未找到 tshark（本机没有可执行文件）",
                            hint="安装 Wireshark 后重试，或运行 seep_ensure_tool('tshark')")

    # ── 3) 唯一执行入口：`-n -r bound_path` 固定前缀，其余参数只来自校验过的 mode/port ──
    executions = []

    def run(extra_args):
        # `-n` 必须在最前：禁用名称解析（DNS/反查），读本地文件不发起网络请求。
        # 不接受调用方给 argv/shell/目标：tshark 路径只来自本函数的解析结果。
        argv = [tshark, "-n", "-r", bound_path] + list(extra_args)
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=120)
        except subprocess.TimeoutExpired:  # 超时与 rc≠0 都不当空数据
            record = _pcap_execution(argv, timeout=True, error="TimeoutExpired")
        except Exception as exc:  # noqa: BLE001 —— 起不来进程如实记 error
            record = _pcap_execution(argv, error=type(exc).__name__)
        else:
            record = _pcap_execution(argv, rc=proc.returncode,
                                     stdout=proc.stdout or "", stderr=proc.stderr or "")
        executions.append(record)
        return record

    # ── 4) 三模式走同一入口，只换固定 "-Y/-T/-e" 参数；失败调用的 stdout 不当数据 ──
    data, totals, prefilters = {}, {}, {}
    for field, extra_args in _pcap_queries(mode, port):
        record = run(extra_args)
        data[field], totals[field], prefilters[field] = _pcap_rows(
            field, record["stdout"] if record["ok"] else "", host_filter, max_rows)

    envelope = _pcap_envelope(
        "seep_pcap_extract", os.path.basename(bound_path), mode, executions,
        data, totals, _PCAP_NOTES[mode], max_rows=max_rows,
        extra={"port": port, "host_filter": host_filter}, prefilters=prefilters)
    # 超体积预算：resource_constraint 拒绝 + continuation，绝不截断证据
    return _budget_gate(
        "seep_pcap_extract", envelope,
        "调小 max_rows 或加 host_filter / port 缩小单次返回量后重跑；"
        "已跑完的执行记录不丢：先取 paging.total 判断总量")


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
# HTTP replay redaction/session boundaries: seep_http_security.py.


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
    ★ 凭据不落盘 / 不进输出（REQUIREMENTS.md 三）：`session_file` 只写
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
        session_file: 若给出，只允许在 `SEEP_HTTP_SESSION_ROOT`（默认 `<workspace>/http-sessions`）
            下写 **.json 非凭据**会话快照（时间/方法/URL/头名/状态码）；
            Cookie、Authorization 等凭据**永不落盘**（REQUIREMENTS.md 三）。
            会话保持请在同一次调用里传 cookies（内存），不要从磁盘读回凭据。
        timeout: 超时秒数
    """
    if not isinstance(method, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}", method):
        return "[ERROR]: method 必须是有效 HTTP 方法名称"
    if not isinstance(url, str) or not isinstance(body, str):
        return "[ERROR]: url 和 body 必须是字符串"
    from urllib.parse import urlsplit
    try:
        address = urlsplit(url)
        if address.scheme not in ("http", "https") or not address.hostname:
            raise ValueError("invalid URL")
        address.port
    except ValueError:
        return "[ERROR]: url 必须是有效 HTTP(S) 地址"
    timeout, timeout_error = _int_in_range("seep_http_replay", "timeout", timeout, 1, 300)
    if timeout_error:
        return "[ERROR]: timeout 必须是 1..300 的整数"
    method = method.upper()
    try:
        hdr = json.loads(headers) if headers.strip() else {}
    except Exception as exc:
        return f"[ERROR]: headers 不是合法 JSON: {exc}"
    try:
        ck = json.loads(cookies) if cookies.strip() else {}
    except Exception as exc:
        return f"[ERROR]: cookies 不是合法 JSON: {exc}"
    if any(not isinstance(mapping, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                               for k, v in mapping.items()) for mapping in (hdr, ck)):
        return "[ERROR]: headers 和 cookies 必须是字符串键值组成的 JSON 对象"

    session_path = ""
    if session_file:
        try:
            session_path = _http_session_path(session_file)
        except ValueError as exc:
            return _invalid_param("seep_http_replay", str(exc))
        if os.path.isfile(session_path):
            try:
                with open(session_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except (OSError, ValueError) as exc:
                return _invalid_param(
                    "seep_http_replay",
                    "既有 session_file 无法安全识别，未发送请求、未覆盖：%s"
                    % type(exc).__name__)
            if not isinstance(existing, dict) or existing.get("schema") != _HTTP_SESSION_SCHEMA:
                return _invalid_param(
                    "seep_http_replay",
                    "既有 session_file 不是当前 v2 会话快照；为防止误覆盖任意文件，拒绝写入。")

    # 会话快照：v2 只含非凭据信息；v1（旧版裸 cookie 字典）只在内存里兼容读入，**绝不回写**
    session_read_note = ""
    if session_path and os.path.isfile(session_path):
        try:
            with open(session_path, "r", encoding="utf-8") as f:
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

    # Select a backend before sending. A failed request may already have been
    # processed by the peer; switching backend must never silently resend it.
    try:
        from curl_cffi import requests as http_client
        backend = f"curl_cffi(impersonate={impersonate})"
        use_impersonation = True
    except ImportError:
        try:
            import requests as http_client
        except ImportError:
            return "[ERROR]: 缺少 HTTP 后端；安装 curl_cffi 或 requests 后重试"
        backend, use_impersonation = "requests(降级，无TLS伪装；curl_cffi未安装)", False
    kwargs = {"timeout": timeout, "headers": hdr, "cookies": ck}
    if use_impersonation and impersonate and impersonate != "none":
        kwargs["impersonate"] = impersonate
    if body:
        kwargs["data"] = body
    try:
        r = http_client.request(method, url, **kwargs)
        resp_status, resp_headers, resp_text = r.status_code, dict(r.headers), r.text
        set_cookies = dict(r.cookies.get_dict())
    except Exception as exc:
        msg = (f"[ERROR]: 请求失败: {type(exc).__name__}: {exc}；"
               "未自动重发。请求可能已经送达，请先核对服务端结果再决定是否重试。")
        return _scrub_text(msg, _known_secrets([ck], [hdr], url))

    # 本次已知的真实凭据值：只在内存里流转，用来「清洗 + 断言」，绝不进载荷
    secrets = _known_secrets([ck, set_cookies], [hdr, resp_headers], url)

    # 写会话快照：只写非凭据字段（P3 白名单）
    saved_note = ""
    write_ok = True
    if session_path:
        try:
            snapshot = _http_session_snapshot(method, url, resp_status, hdr, resp_headers,
                                              list(set_cookies), len(body), secrets)
            blob = json.dumps(snapshot, ensure_ascii=False, indent=2)
            # P2：先断言再落盘（顺序不能反）；不通过就抛，绝不写盘
            _assert_redacted(snapshot, secrets, "session_file")
            _atomic_write_text(session_path, blob + "\n")
            saved_note = (f"非凭据会话快照已写入 {session_path}"
                          f"（cookie {len(ck)} 个 / set-cookie 名 {len(set_cookies)} 个已脱敏，值不落盘）")
        except RedactionFailure:
            raise                      # 脱敏失败必须让调用失败（不得降级成提示）
        except OSError as exc:
            write_ok = False
            saved_note = f"请求已完成，但会话快照写入失败: {type(exc).__name__}: {exc}"

    # 输出：所有凭据值 → [REDACTED]（保留键名与条数，便于判断有没有登录态）
    body_preview = _scrub_text(resp_text[:2000], secrets)
    out = {
        "ok": write_ok,
        "status": "complete" if write_ok else "partial",
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
    if not write_ok:
        out["error"] = "session_write_failed"
        out["network_request_completed"] = True
        out["snapshot_written"] = False
    elif session_path:
        out["snapshot_written"] = True
    notes = [n for n in (session_read_note, saved_note) if n]
    if notes:
        out["session"] = "；".join(notes)
    # P2：出厂前再断言一次（这一行是“凭据不进输出”的机检闸门）
    _assert_redacted(out, secrets, "http_replay_output")
    return json.dumps(out, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# P3 渗透轻量补充（2026-10 增补，纯增量）：seep_web_recon 只做 Web 指纹/头/目录/技术栈
# 的只读侦察；不塞扫描器/爆破/利用框架，重型渗透走独立 MCP，不并入 seep 内核。
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
    if res.get("available"):
        verification = _verify_discovered(
            tad.normalize_tool_id(tool_id), res)
        res["path_found"] = True
        res["verification"] = verification
        res["available"] = bool(verification.get("verified"))
        res["usable"] = bool(verification.get("verified"))
    if record_state:
        try:
            res['state_record'] = tad.record(tool_id, res)
        except Exception:
            res['state_record'] = {'state_saved': False, 'state_error': 'record failed'}
    return json.dumps(res, indent=2, ensure_ascii=False)


# === SEEP-EXT: case-lib BEGIN ===
# 案例库只读检索：Tool/cases/*/case.json（结构约定见 Tool/docs/CASE-LIB.md）；无副作用。
@server.tool()
def seep_case_read(case_id: str) -> str:
    """读取单个案例的完整上下文：case.json 全文 + facts.jsonl 前 20 行 + README 前 80 行。

    Args:
        case_id: 案例标识，可用 case.json 的 id 或目录名（如 "项目K" / "案例-6.9换肤壳"），
                  可通过 seep_case_search 获得
    """
    return _read_case(case_id)
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
