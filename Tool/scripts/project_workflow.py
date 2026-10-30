#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""project_workflow.py —— 唯一的「项目执行协调入口」（编排，不新增判据体系）。

它把「用户原话 → 主/辅域 → project/version/run → Manager 路线 → 执行前 check-action
→ 只读受控动作 → 原始输出/产物证据 → project_state evidence → manager attempt →
验收/收尾」串成**一次可复跑的调用**。

本入口**不自造能力**：
- 判域用 `route.load_packs()/resolve()`（Tool/skill/*/pack.json 现算，不硬编码九域）；
- 生命周期用 `project_state.py` 公开 CLI；
- 执行前检查用 `manager_state.check_action()`（与 `check-action` 子命令同一函数体）；
- 证据登记用 `project_state.py evidence`；尝试记账用 `manager_state.py attempt`；
- 受控动作只调用**当前真实存在**的 MCP 函数 / 第一方函数（见 ACTIONS 表）；
- 验收/收尾只调用 `acceptance-record` / `finish-run` 真门，本文件从不写 pass。

强制范围（逐条写进输出，不夸大）：
    enforcement_scope = workflow-entry-only
    host_wiring_required = true
    globally_enforced = false
直接调用 MCP 工具、直接跑 `tool-run.ps1 -Run`、直接起目标、或在别的会话里执行，
都**不经过**本入口，也不被它拦截。`check-action` 是锁内快照，不是租约。

本入口不做：执行用户目标、启动 GUI、`cmd /c` 任意串、网络重放/安装、r2 写命令、
修改 target、把 exit0 或方法返回当验收通过。

用法：
    python Tool/scripts/project_workflow.py classify --quote "<原话>" [--json]
    python Tool/scripts/project_workflow.py start --project <dir> --quote "<原话>" \
        [--project-id ID] [--target <目标文件>] [--version 1.0] [--route-id R1] \
        [--p 0.4 --hours 2-4h --fail "<现象即停>" --evidence-goal "<要什么证据>"]
    python Tool/scripts/project_workflow.py act --project <dir> --action <action-id> \
        [--args-json '{...}'] [--timeout 120] [--json]
    python Tool/scripts/project_workflow.py status --project <dir> [--case <旧案目录>] [--json]
    python Tool/scripts/project_workflow.py close --project <dir> --version 1.0 --run <run-id> \
        [--define id:desc]... [--accept item=pass:ev-1,ev-2]... \
        [--finish completed|failed|blocked] [--verifier X --how Y] [--json]

退出码：0 链路完整 / 2 状态或参数被拒（WAIT_USER、replan、stale、未 intake、未完成验收）/
3 能力缺口（动作不在本域 pack.tools、effects 不允许、外部解析器不可用）/
4 策略拒绝（动作不在审核映射表、参数越界）/ 5 已执行但证据未被接受（TOCTOU/记账失败）。

执行通道：子进程不由任意 CLI 子命令触发（旧 `_exec` 已移除）。父进程把
「project/refs/generation/已选路线/预期 targethash/参数载荷哈希」封成**受控信封**，
子进程在**加载 MCP 与调用工具函数之前**依次：重算哈希 → 真调 `check_action` →
**重新 `admit_action`**（取 Manager 当前主/辅域、现算 pack.tools、现读 effects）→
参数 schema 全校验 → 把目标从 version 重绑。没有项目的裸执行一律拒绝，不落盘任何凭据。

信封**不是 secret、不是凭据、也不是一次性授权**：nonce 由公开载荷哈希派生，任何人都能
重算。同一状态下的重复只读动作**允许**（每次重新 check/admit，并产生独立 capture）；
状态变 WAIT_USER / refs / route / generation 后重放必拒（因为每次都要重调）。
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import manager_state as M          # noqa: E402  (冻结：只 import，不改)
import project_state as P          # noqa: E402  (另一代理独占：只调用公开 CLI/只读函数)
import route as R                  # noqa: E402

SCHEMA = "seep-workflow/1"
CAPTURE_SCHEMA = "seep-workflow-capture/1"
EFFECTS_PATH = os.path.join(ROOT, "Tool", "config", "tool-effects.json")
MCP_SERVER = os.path.join(ROOT, "Tool", "mcp", "seep_mcp_server.py")
ENFORCEMENT_SCOPE = "workflow-entry-only"
SCOPE_NOTE = ("本入口只对**经本入口发起**的动作执行 check-action 与证据绑定；"
              "host_wiring_required=true / globally_enforced=false：直接调 MCP 工具、"
              "直接跑 tool-run.ps1 -Run、直接起目标、或在别的会话执行，都不经过它。"
              "check-action 是锁内快照，不是租约；证据只证明文件在项目内存在且哈希与声明一致，"
              "不证明功能验收。")
MAX_CAPTURE_TEXT = 256 * 1024

# ---------------------------------------------------------------------------
# 与 MCP 侧**同一份**只读参数语法（不在这里复制一份，防止语法漂移）
#
# 历史问题（独立验收 §4.3 观察项）：这里曾经把 `R2_TARGET_FORBIDDEN` / r2 正则 /
# `kb_path_error` 复制了一份，靠 `test_readonly_parameters.py` 的交叉测试钉住。
# 现在改为**直接复用** `Tool/mcp/seep_contract.py`（该模块不 import 主服务、不注册工具、
# 导入期不读盘，所以复用不会被"整份 MCP 服务准入"绑住）：
#   * `seep_contract.r2_target_error`   → r2 `@ <target>` 语法
#   * `seep_contract.kb_rel_error`      → KB 根内相对路径/分类语法
#   * `seep_contract.int_range_error`   → 整数范围（含 NaN/±Inf/OverflowError/超大整数）
#   * `seep_contract.r2_readonly_command_check` → 已审核只读 r2 命令语法
# 契约模块不可导入时**不放行**：退化为本文件的最小同语义实现（同一批正则/字符集），
# 一致性由 `test_readonly_parameters.py` 与 `test_project_workflow.py` 断言。
# ---------------------------------------------------------------------------
_CONTRACT = {"module": None, "tried": False}


def contract_module():
    """惰性导入契约模块；导入失败返回 None（调用方退化为本地同义实现，绝不跳过校验）。"""
    if _CONTRACT["module"] is not None or _CONTRACT["tried"]:
        return _CONTRACT["module"]
    _CONTRACT["tried"] = True
    try:
        mcp_dir = os.path.join(ROOT, "Tool", "mcp")
        if mcp_dir not in sys.path:
            sys.path.insert(0, mcp_dir)
        import seep_contract as _c
        _CONTRACT["module"] = _c
        return _c
    except Exception:            # noqa: BLE001
        return None


# 退化实现用的常量（与 seep_contract 同值；只在契约模块不可导入时生效）。
R2_TARGET_FORBIDDEN = (";", "\n", "\r", " ", "\t", "!", "$", "|", "&", ">", "<",
                       "`", "@", "'", '"', "\\", "/", "(", ")", "#", ",", "+",
                       "-", "*", "=", "~", "%", "{", "}", "[", "]")
_R2_SYMBOL_RE = re.compile(r"^[A-Za-z0-9_.]{1,128}$")
_R2_HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]{1,16}$")
_R2_DEC_RE = re.compile(r"^[0-9]{1,20}$")


def r2_target_error(target) -> str:
    """r2 target 语法校验："" = 合法；否则返回不含原值的原因（与 MCP 侧同口径）。"""
    contract = contract_module()
    if contract is not None:
        return contract.r2_target_error(target)
    if not isinstance(target, str):
        return "target 必须是字符串"
    if not target:
        return "target 不能为空"
    if len(target) > 128:
        return "target 过长（≤128）"
    for ch in R2_TARGET_FORBIDDEN:
        if ch in target:
            return "target 含命令/表达式分隔符（只接受符号名或地址）"
    if _R2_HEX_RE.match(target) or _R2_DEC_RE.match(target) or _R2_SYMBOL_RE.match(target):
        return ""
    return "target 语法不被接受（符号名 / 0x十六进制 / 十进制地址）"


def kb_path_error(text, allow_empty: bool = False) -> str:
    """KB 根内相对路径/分类语法校验（拒绝绝对路径/盘符/UNC/上跳/控制字符）。"""
    contract = contract_module()
    if contract is not None:
        if allow_empty and (text is None or str(text).replace("\\", "/").strip() == ""):
            return ""
        if text is None or str(text).strip() == "":
            return "不能为空"
        return contract.kb_rel_error(str(text))
    if text is None or str(text).strip() == "":
        return "" if allow_empty else "不能为空"
    body = str(text).replace("\\", "/").strip()
    if not body:
        return "" if allow_empty else "不能为空"
    if len(body) > 400:
        return "过长（≤400）"
    if any(ch in body for ch in ("\x00", "\n", "\r")):
        return "含控制字符"
    if body.startswith("//"):
        return "不接受 UNC 路径"
    if body.startswith("/"):
        return "不接受绝对路径"
    if re.match(r"^[A-Za-z]:", body):
        return "不接受 Windows 盘符路径"
    if any(part == ".." for part in body.split("/")):
        return "不接受上跳（..）"
    return ""


def int_arg_error(name: str, value, low: int, high: int) -> str:
    """整数参数的**原因串**（""=合法）。与 `seep_contract.int_range_error` 同一份。

    覆盖 bool / NaN / ±Inf / 1e999 / 10**400 / 非整数 float / 非数字串 —— 全部结构化拒，
    不抛 traceback（旧实现在 `int(float('inf'))` 上抛 OverflowError → act rc=1 + traceback）。
    """
    contract = contract_module()
    if contract is not None:
        return contract.int_range_error(name, value, low, high)
    if isinstance(value, bool):
        return "%s 不接受布尔值" % name
    if isinstance(value, float):
        if value != value:
            return "%s 必须是有限整数（不接受 NaN）" % name
        if value in (float("inf"), float("-inf")):
            return "%s 必须是有限整数（不接受 Inf）" % name
        if not value.is_integer():
            return "%s 必须是整数（不接受小数）" % name
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return "%s 必须是整数" % name
    if isinstance(value, float) and float(number) != value:
        return "%s 必须是整数" % name
    if number < low or number > high:
        return "%s 超出范围 %d..%d" % (name, low, high)
    return ""


def r2_command_error(command) -> str:
    """`r2.cmd` 类动作的命令语法：空串 = 已审核只读；否则返回原因（与 MCP 侧同一份）。"""
    contract = contract_module()
    if contract is None:
        return "契约模块不可用：无法校验 r2 命令语法（拒绝而不是放行）"
    problem, _tokens, _kind = contract.r2_readonly_command_check(command)
    return problem


class WorkflowError(Exception):
    """带退出码的结构化拒绝。message 绝不回显用户原始输入。"""

    def __init__(self, rc: int, stage: str, reason: str, **extra):
        super().__init__(reason)
        self.rc, self.stage, self.reason, self.extra = rc, stage, reason, extra


# ---------------------------------------------------------------------------
# 审核过的只读动作映射（白名单；不从用户输入派生）
#   - effects 五项来自 Tool/config/tool-effects.json，是**必要条件不是充分条件**；
#   - 只有本表登记 + effects 不允许写/网/改目标/丢数据 + 属于当前域 pack.tools 才执行；
#   - 未登记的动作 = capability_gap（不是"永久禁令"，加表即可开放）。
# ---------------------------------------------------------------------------
ACTIONS = {
    "meta.fingerprint": {
        "kind": "inproc", "params": {}, "need_pack": False,
        "review": "第一方 project_state.file_fingerprint 读版本目标（sha256/大小）；"
                  "共享前置动作，不要求任何 pack.tools 声明一个不存在的工具",
    },
    "kb.search": {
        "kind": "mcp", "tool": "seep_kb_search",
        "shared_knowledge": True,
        "params": {"query": "text", "category": "kbcat", "limit": "int:1..200"},
        "review": "seep_mcp_server.py:841 进程内 KB 文本检索（别名表 + CJK 2-gram），"
                  "只读 kb/kb_local，不启动外部进程；category 限定在 KB 根内（MCP 侧 realpath 边界）",
    },
    "kb.read": {
        "kind": "mcp", "tool": "seep_kb_read",
        "shared_knowledge": True,
        "params": {"article_path": "kbpath", "max_chars": "int:1..200000"},
        "review": "seep_mcp_server.py:1126 只读知识库文章；article_path 只接受 KB 相对路径"
                  "（MCP 侧 resolve + 根边界 + symlink 检查）",
    },
    "apk.info": {
        "kind": "mcp", "tool": "seep_apk_info", "target_param": "apk_path",
        "params": {},
        "review": "seep_mcp_server.py:585 zipfile+re 原生解析 APK 结构：不启动外部进程、不解包落盘",
    },
    "apk.smali_search": {
        "kind": "mcp", "tool": "seep_apk_smali_search",
        "params": {"directory": "projdir", "pattern": "text",
                   "case_sensitive": "bool", "limit": "int:1..10000"},
        "review": "seep_mcp_server.py:704 遍历（项目内）目录读文本；directory 必须在项目内",
    },
    "packer.detect": {
        "kind": "mcp", "tool": "seep_packer_detect", "target_param": "binary_path",
        "params": {},
        "review": "seep_mcp_server.py:2344 进程内 pefile+节熵+字节特征；pefile 不可用时返回 "
                  "status=unknown（不猜成没壳）",
    },
    "case.read": {
        "kind": "mcp", "tool": "seep_case_read", "params": {"case_id": "text"},
        "review": "seep_mcp_server.py:3105 只读案例库文本（case.json/facts/README）",
    },
    "r2.info": {
        "kind": "mcp", "tool": "seep_r2_info", "target_param": "binary_path",
        "params": {},
        "review": "seep_mcp_server.py:308 以仓库内 rabin2 -I 只读读目标；"
                  "effects 如实声明 executes_foreign_code=true（只读外部解析器）",
    },
    "r2.strings": {
        "kind": "mcp", "tool": "seep_r2_strings", "target_param": "binary_path",
        "params": {"filter_text": "text", "all_sections": "bool",
                   "limit": "int:1..10000"},
        "review": "seep_mcp_server.py:391 rabin2 -z/-zz 只读取字符串",
    },
    "r2.disasm": {
        "kind": "mcp", "tool": "seep_r2_disasm", "target_param": "binary_path",
        "params": {"target": "r2target", "lines": "int:1..10000",
                   "output_mode": "mode:full|branch|summary",
                   "limit_tokens": "int:0..65536"},
        "review": "seep_mcp_server.py:425 radare2 -q -c 'aaa;pdf' 只读反汇编（无写命令）："
                  "target 只接受符号名/0x地址/十进制地址，由 r2_target_error 在 MCP 与入口两侧同口径拒绝",
    },
    "r2.decompile": {
        "kind": "mcp", "tool": "seep_r2_decompile", "target_param": "binary_path",
        "params": {"target": "r2target", "output_mode": "mode:full|fold|summary",
                   "limit_tokens": "int:0..65536"},
        "review": "seep_mcp_server.py:509 radare2 pdc 只读反编译；target 同上只接符号/地址",
    },
    "pcap.extract": {
        "kind": "mcp", "tool": "seep_pcap_extract", "target_param": "pcap_path",
        "params": {"host_filter": "text", "mode": "mode:summary|http|payload",
                   "port": "int", "max_rows": "int:1..10000"},
        "review": "seep_mcp_server.py:2174 tshark -r 读抓包文件：不回放、不联网",
    },
}

# effects 派生拒绝的说明（不是新禁令：直接来自 Tool/config/tool-effects.json）
DERIVED_REFUSALS = {
    "seep_r2_cmd": "effects: mutates_target=true 且 command 是任意 r2 命令串",
    "seep_apk_unpack": "effects: writes_filesystem=true / executes_foreign_code=true",
    "seep_apk_decompile": "effects: writes_filesystem=true / executes_foreign_code=true",
    "seep_gen_security_report": "effects: writes_filesystem=true（生成报告文件）",
    "seep_ensure_tool": "effects: touches_network=true / may_discard_data=true（安装）",
    "seep_tool_discover": "effects: writes_filesystem=true（写工具状态）",
    "seep_http_replay": "effects: touches_network=true（网络重放）",
    "seep_auto_triage": "effects: writes_filesystem=true（task_name 会落报告）→ "
                        "capability_gap；改用 r2.info / packer.detect 拿同一只读画像",
    "seep_mem_strings": "按 pid 读活进程，越「不执行目标」边界 → capability_gap",
}


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):  # 不回显任意输入（含凭据/路径）
        raise WorkflowError(2, "args", "invalid CLI arguments (see --help)")


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def utc_slug() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def load_effects() -> dict:
    try:
        with open(EFFECTS_PATH, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
        tools = data.get("tools") if isinstance(data, dict) else None
        return tools if isinstance(tools, dict) else {}
    except (OSError, ValueError):
        return {}


def pack_tools_for(domains, skill_dir=None) -> tuple[dict, list[str]]:
    """按当前主/辅域从 pack.json 现算可用工具；域不存在则如实空表（不硬编码九域）。"""
    packs, problems = R.load_packs(skill_dir)
    by_id = {p["id"]: p for p in packs}
    out = {}
    for domain in domains:
        pack = by_id.get(str(domain or "").strip())
        tools = list((pack or {}).get("raw", {}).get("tools") or [])
        out[str(domain)] = {"known": pack is not None, "tools": tools,
                            "l1": (pack or {}).get("l1", "")}
    return out, problems


# ---------------------------------------------------------------------------
# classify —— 只判域，不建项目、不选专业路线
# ---------------------------------------------------------------------------
def classify(quote: str, skill_dir=None) -> dict:
    if not str(quote or "").strip():
        raise WorkflowError(2, "classify", "需要 --quote：先用用户原话判域")
    try:
        hits = R.resolve(quote, skill_dir, limit=None)
    except R.RouteConfigError as exc:
        raise WorkflowError(2, "classify", "领域路由配置无效，尚未建项目",
                            pack_problems=exc.problems) from exc
    concrete = [h for h in hits if not h.get("fallback")]
    packs = []
    seen = set()
    for hit in concrete:
        if hit["pack"] in seen:
            continue
        seen.add(hit["pack"])
        packs.append({"pack": hit["pack"], "label": hit["label"],
                      "priority": hit["priority"]})
    unclassified = not packs
    ambiguity = len({p["pack"] for p in packs}) > 1
    domain_info, problems = pack_tools_for([p["pack"] for p in packs], skill_dir)
    return {
        "ok": not unclassified, "schema": SCHEMA, "quote_hash": hashlib.sha256(
            str(quote).encode("utf-8")).hexdigest(),
        "primary_candidate": packs[0]["pack"] if packs else None,
        "aux_candidates": [p["pack"] for p in packs[1:]],
        "packs": packs, "ambiguity": ambiguity,
        "unclassified": unclassified,
        "requires_main_agent_decision": bool(unclassified or ambiguity),
        "decision_note": ("判域不是专业路线决定：主/辅域并列时交给主 Agent 定，"
                          "本入口不替它选域"),
        "pack_tools": domain_info, "pack_problems": problems,
        "allowed_actions": sorted(a for a, s in ACTIONS.items() if s.get("need_pack", True)),
        "shared_actions": sorted(a for a, s in ACTIONS.items() if not s.get("need_pack", True)),
        "enforcement_scope": ENFORCEMENT_SCOPE, "globally_enforced": False,
        "host_wiring_required": True, "scope_note": SCOPE_NOTE,
    }


# ---------------------------------------------------------------------------
# 动作准入（执行前，磁盘零新增）
# ---------------------------------------------------------------------------
def admit_action(action: str, domains: list[str], effects: dict, skill_dir=None) -> dict:
    spec = ACTIONS.get(action)
    if spec is None:
        raise WorkflowError(
            4, "act",
            "capability_gap：动作不在审核映射表内（不是永久禁令；复核实现并加表即可开放）",
            allowed=sorted(ACTIONS), gap_reason=gap_reason(action))
    tool = spec.get("tool", "")
    if spec.get("need_pack", True):
        info, problems = pack_tools_for(domains, skill_dir)
        owners = [d for d, meta in info.items() if tool in meta["tools"]]
        if not owners and not spec.get("shared_knowledge"):
            raise WorkflowError(
                3, "act", "capability_gap：%s 不在当前主/辅域 pack.tools 内" % tool,
                action=action, tool=tool, domains={d: m["tools"] for d, m in info.items()},
                hint="域专用动作必须由该 pack.tools 声明；也可先用 kb.search 走知识库路线")
        if not tool or tool not in effects:
            raise WorkflowError(3, "act", "capability_gap：%s 未在 tool-effects.json 登记" % tool,
                                action=action, tool=tool)
        flags = effects[tool]
        if not isinstance(flags, dict):
            raise WorkflowError(3, "act", "capability_gap：%s effects 结构无效" % tool,
                                action=action, tool=tool)
        blocking = [k for k in ("writes_filesystem", "touches_network",
                                "mutates_target", "may_discard_data") if flags.get(k)]
        if blocking:
            raise WorkflowError(
                3, "act", "capability_gap：%s effects 声明 %s=true，本入口只做只读动作"
                % (tool, ",".join(blocking)),
                action=action, tool=tool, effects=flags,
                hint="effects 五项全 false 也不是安全证明；这里是 effects 声明派生出的能力缺口")
        if not all(isinstance(flags.get(k), bool) for k in
                   ("writes_filesystem", "executes_foreign_code", "touches_network",
                    "mutates_target", "may_discard_data")):
            raise WorkflowError(3, "act", "capability_gap：%s effects 五项未完整登记" % tool,
                                action=action, tool=tool)
        return {"spec": spec, "owner_domains": owners, "effects": flags,
                "coverage": "reviewed-readonly-mapping+effects-declared",
                "executes_foreign_code": bool(flags.get("executes_foreign_code"))}
    # 共享前置动作：不要求 pack.tools 声明
    return {"spec": spec, "owner_domains": [], "effects": None,
            "coverage": "first-party-inproc", "executes_foreign_code": False}


def _proj_dir(root: Path, value: str) -> Path:
    text = str(value or "").replace("\\", "/").strip()
    if not text or text.startswith("/") or ":" in text or ".." in Path(text).parts:
        raise WorkflowError(4, "act", "参数路径必须是项目内相对路径（不接受绝对路径/上跳）")
    path = (root / text).resolve()
    if not path.is_relative_to(root.resolve()) or not path.exists():
        raise WorkflowError(4, "act", "参数路径不存在或越出项目边界")
    return path


def validate_args(root: Path, action: str, raw: dict) -> dict:
    """入口侧参数校验（与 MCP 侧**同一份**判定函数；MCP 直调也自己再检一遍）。

    任何不确定的写法一律拒绝：这里不做“尽力解析”，因为 target/category 会进入
    外部解析器的命令串或文件系统路径。整数走 `int_arg_error()`（与
    `seep_contract.int_range_error` 同一份）：bool / NaN / ±Inf / 1e999 / 10**400 /
    非整数 float / 非数字串全部结构化拒（rc=4），**不抛 traceback**。
    """
    spec = ACTIONS[action]
    if not isinstance(raw, dict):
        raise WorkflowError(4, "act", "--args-json 顶层必须是对象")
    M.reject_sensitive(raw, "workflow.args")
    out = {}
    for key, value in raw.items():
        kind = spec["params"].get(key)
        if kind is None:
            raise WorkflowError(4, "act", "未知参数（动作 %s 只接受 %s）"
                                % (action, ",".join(sorted(spec["params"])) or "无参数"))
        if kind.startswith("int"):
            bounds = kind.split(":", 1)[1] if ":" in kind else "0..1000000"
            low, _, high = bounds.partition("..")
            low_i, high_i = int(low or 0), int(high or 10 ** 6)
            reason = int_arg_error(key, value, low_i, high_i)
            if reason:
                raise WorkflowError(4, "act", "参数 %s" % reason)
            out[key] = int(value)
        elif kind == "bool":
            if not isinstance(value, bool):
                raise WorkflowError(4, "act", "参数 %s 必须是布尔值" % key)
            out[key] = value
        elif kind.startswith("mode:"):
            allowed = kind.split(":", 1)[1].split("|")
            if str(value) not in allowed:
                raise WorkflowError(4, "act", "参数 %s 只接受 %s" % (key, ",".join(allowed)))
            out[key] = str(value)
        elif kind == "projdir":
            out[key] = str(_proj_dir(root, str(value)))
        elif kind == "kbcat":
            err = kb_path_error(value, allow_empty=True)
            if err:
                raise WorkflowError(4, "act", "参数 %s %s" % (key, err))
            out[key] = str(value).replace("\\", "/").strip()
        elif kind == "kbpath":
            err = kb_path_error(value)
            if err:
                raise WorkflowError(4, "act", "参数 %s 必须是 KB 相对路径：%s" % (key, err))
            out[key] = str(value).replace("\\", "/").strip()
        elif kind == "r2target":
            err = r2_target_error(str(value))
            if err:
                raise WorkflowError(4, "act", "参数 %s 被拒绝：%s（只接受符号名 / 0x地址 / 十进制地址；"
                                    "算式要另写 parser，当前不支持）" % (key, err))
            out[key] = str(value)
        else:
            text = str(value)
            if len(text) > 4000:
                raise WorkflowError(4, "act", "参数 %s 过长" % key)
            out[key] = text
    return out


def project_target(root: Path) -> tuple[Path | None, dict, dict]:
    version, project = current_version(root)
    try:
        checked = P.target_fingerprint(root, version)
    except Exception:
        raise WorkflowError(2, "act", "版本目标哈希/typed identity 不可复核：先核对 project/version")
    target = Path(checked["path"]) if checked.get("path") is not None else None
    return target, version, project


def action_input(root: Path, version: dict, asset_id: str) -> tuple[Path, dict]:
    try:
        binding = P.asset_binding(root, version["version_id"], asset_id)
        if binding["kind"] != "file":
            raise ValueError("file parser requires a file asset")
        path = P.project_file(root, binding["local_path"])
        return path, binding
    except Exception:
        raise WorkflowError(3, "act", "输入资产必须是当前版本已登记且身份有效的文件")


# ---------------------------------------------------------------------------
# 执行（唯一执行点）：只跑映射的函数/参数，shell=False，argv 逐项不拼接
#
# `_exec` 曾经是**公开子命令**（在 parser 里、--help 可见），只校验参数**键名**，
# 不调 check_action、不绑 project/version/generation —— 那是一个"入口内绕过"。
#
# 现在（2026-10-27 主对话裁定后重写）：
#   1. 子进程不再由 CLI 子命令触达（argv 里没有可点的 _exec 分支）；
#   2. 子进程在**加载 MCP 与调用工具函数之前**依次做：
#        重算载荷哈希 → 真调 M.check_action → **重新 admit_action**
#        （取 Manager 当前 primary/aux 域、现算 pack.tools、现读 tool-effects.json）
#        → 参数 schema 全校验 → target 从 version 重绑。
#      任一不符即拒，且 `load_mcp`/`_run_cmd` 调用为 0。
#   3. **信封不是凭据、也不是一次性授权**：nonce 只是公开可重算的载荷派生值。
#      同一状态下的重复只读动作**允许**（每次重新 check + admit + 独立 capture），
#      状态变 WAIT_USER / refs / route / generation 后重放必须拒（由 check_action 每次
#      重调 + admit_action 每次重算兜住）。父侧内存表只用于**同一进程内双发检测**，
#      不作为授权；不再声称"一次性"。
#   4. 父 `act` 复用**同一个**准入函数 `admit_action`（不复制语法），避免两侧漂移。
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 结果词汇（主对话裁定 §3）：零命中/部分结果与“工具崩溃”不是一回事
#   * COMMON_OUTCOME_STATUS   = 动作跑成了但**没结果**（zero_match / zero_results /
#     unknown / empty_output / missing_result / resource_constraint / no_match）
#   * PARTIAL_OUTCOME_STATUS  = 动作跑成了但**只拿到一部分**（partial）：仍是 executed=true，
#     若真有已解析 data 则 has_result=true，但 outcome **不得** succeeded，也不算完整验收；
#     Manager attempt 状态仍写 failed（Manager 现接口），partial 的区分在
#     outcome_reason=partial / outcome_class=partial（**不**新增 Manager schema）
#   * ERROR_OUTCOME_STATUS    = 工具/执行错误（error / invalid / timeout / tshark_missing /
#     pcap_not_found）：原因原样保留，不归零命中
# Manager 只接受 succeeded/failed/blocked/partial —— 本模块不改 Manager schema，
# 仍用这 5 个词写 attempt，只把“为什么”放进 outcome_reason / outcome_class。
# ---------------------------------------------------------------------------
COMMON_OUTCOME_STATUS = ("zero_match", "zero_results", "unknown", "empty_output",
                         "missing_result", "resource_constraint", "no_match")
PARTIAL_OUTCOME_STATUS = ("partial",)
ERROR_OUTCOME_STATUS = ("error", "invalid", "tool_reported_not_ok", "tshark_missing",
                        "pcap_not_found", "no_execution")


class ContextError(Exception):
    """子进程侧上下文/参数重验失败（带退出码）。"""

    def __init__(self, rc: int, stage: str, reason: str, **extra):
        super().__init__(reason)
        self.rc, self.stage, self.reason, self.extra = rc, stage, reason, extra


def _payload_digest(context: dict, args: dict) -> str:
    body = json.dumps({"context": context, "args": args}, sort_keys=True,
                      ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _compare_digest(left: str, right: str) -> bool:
    import hmac as _hmac
    return _hmac.compare_digest(str(left), str(right))


def _envelope_digest(digest: str) -> str:
    """信封 `nonce` = 载荷哈希的派生值（**不落盘、不需要 secret、不是授权**）。

    明确措辞（主对话裁定）：这个值可被任何人用公开上下文重算，所以它
    **不是凭据、不是一次性授权**。它只让子进程确认「信封与参数/上下文是同一批」，
    并让父侧在同一进程内发现明显双发。真正授权是子进程**每次**重调的
    `check_action` + `admit_action` + target 从 version 重绑。
    """
    return hashlib.sha256(("seep-workflow-envelope:" + str(digest)).encode("utf-8")).hexdigest()[:32]


# 兼容旧名字（测试/外部只读引用）：
_envelope_nonce = _envelope_digest


def _mint_envelope(context: dict, args: dict) -> dict:
    """父侧：把受控上下文 + 参数载荷哈希封成信封（**仅内存，不是授权**）。

    明确不做“一次性”: 不在父侧维护任何已消费 nonce 表 —— 同状态的重复只读动作是
    **允许**的（主对话裁定 §2），每次都由子进程重新 check_action + admit_action +
    validate_args，并各自产生独立 capture。nonce 只用来确认“信封与参数/上下文同一批”。
    """
    digest = _payload_digest(context, args)
    envelope = {"schema": "seep-workflow-envelope/1", "nonce": _envelope_digest(digest),
                "digest": digest, "context": dict(context)}
    return envelope


def _spawn_child(envelope: dict, args: dict, timeout: int) -> dict:
    """子进程：stdin 递信封+参数，stdout 收一行 JSON；shell=False，无索引拼接。"""
    child = ("import json,sys;"
             "sys.path.insert(0, %r);"
             "import project_workflow as W;"
             "sys.exit(W.child_main(json.loads(sys.stdin.read())))" % HERE)
    body = json.dumps({"envelope": envelope, "args": args}, ensure_ascii=False)
    started = time.monotonic()
    try:
        proc = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", child],
                              input=body, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=max(1, min(int(timeout), 600)),
                              shell=False, cwd=ROOT)
        rc, out, err, timed_out = proc.returncode, proc.stdout or "", proc.stderr or "", False
    except subprocess.TimeoutExpired as exc:
        rc, timed_out = None, True
        out = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        err = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        err += "\n[workflow] timeout after %ss" % timeout
    payload = {}
    for line in reversed(out.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                payload = json.loads(line)
                break
            except ValueError:
                continue
    return {"rc": rc, "timeout": timed_out, "stdout": out, "stderr": err,
            "elapsed_s": round(time.monotonic() - started, 3), "payload": payload}


def _action_result(action: str, args: dict, proc: dict) -> dict:
    """归一子进程结果。stdout 非空**不等于**成功：跑成与"有结果"分开记。

    `tool_ok` 只来自子进程的结构化 ok；子进程被拒（rc≠0）或没吐 JSON 时一律 not ok。
    子进程 stdout 原文（`proc["stdout"]`）与 stderr 一律原样放进 capture，**不改写**，
    所以 zero_results / partial / error 的原始执行流仍可复核。
    """
    spec = ACTIONS[action]
    payload = _child_payload(proc)
    status = str(payload.get("status") or "")
    rc = proc.get("rc")
    if not payload:
        status, ok = "missing_result", False
    elif rc == 0 and payload.get("ok") is True:
        ok = True
    elif rc == 0 and payload.get("ok") is False and not status:
        status, ok = "tool_reported_not_ok", False
    else:
        ok = False
    if ok and not status:
        status = "ok"
    return {"method": ("project_state.file_fingerprint" if spec["kind"] == "inproc"
                       else "seep_mcp_server.%s" % spec.get("tool")),
            "argv": [sys.executable, "-B", "-X", "utf8", "-c",
                     "<child bootstrap: stdin envelope>", "<payload>"],
            "params": args, "rc": rc, "timeout": proc.get("timeout"),
            "elapsed_s": proc.get("elapsed_s"), "stdout": proc.get("stdout", ""),
            "stderr": proc.get("stderr", ""),
            "tool_ok": ok, "tool_payload_ok": (payload.get("ok") if payload else None),
            "tool_has_result": (payload.get("has_result") if payload else None),
            "tool_status": status or None}


def _child_payload(proc: dict) -> dict:
    """从子进程 stdout 里取那一行结构化 JSON（失败/被拒也如实返回，不猜成成功）。"""
    payload = proc.get("payload")
    if isinstance(payload, dict) and payload:
        return payload
    for line in reversed(str(proc.get("stdout") or "").splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                return parsed
    return {}


def controlled_context(root: Path, action: str, version: dict, project: dict,
                       refs: dict, generation: str, route_id: str) -> dict:
    """受控上下文：入口在执行前固化一份快照，子进程用它重验（不接受外部覆盖）。"""
    return {"schema": SCHEMA, "project": str(root), "action": str(action),
            "version_id": str(version.get("version_id")),
            "project_id": str(project.get("project_id")),
            "target_sha256": str(version.get("sha256")),
            "refs": dict(refs), "generation_id": str(generation),
            "route_id": str(route_id),
            "scope": ENFORCEMENT_SCOPE, "globally_enforced": False}


def run_action(root: Path, action: str, args: dict, timeout: int,
               context: dict | None = None) -> dict:
    """执行受控只读动作。**必须**能求出受控上下文；无项目的裸执行一律拒绝。

    上下文既可以由调用方（cmd_act）传入，也可以从项目现场重算（兼容 4 参旧调用）；
    无论哪种来源，**子进程都会独立重验**（重算哈希 → 真调 check_action →
    **重新 admit_action**（Manager 当前域 + 现算 pack.tools + 现读 effects）→
    参数 schema 全校验 → target 从 version 重绑），所以“父侧忘了传/父侧准入过宽”
    不会变成绕过。
    """
    if not isinstance(context, dict) or not context.get("project"):
        context = derive_context(root, action)
    envelope = _mint_envelope(context, args)
    return _action_result(action, args, _spawn_child(envelope, args, timeout))


def derive_context(root: Path, action: str) -> dict:
    """从项目现场重算受控上下文；无项目/无 intake/无已选路线则拒绝（不降级执行）。"""
    if not (root / "project.json").is_file():
        raise WorkflowError(4, "act",
                            "run_action 需要受控上下文（project/refs/generation/route/target_sha256）："
                            "没有项目的裸执行一律拒绝（不提供「内部入口」例外）")
    events, state = M.current_context(root)
    if state.get("status") == "uninitialized" or not state.get("generation_id"):
        raise WorkflowError(2, "act", "Manager 尚未 intake：先 start / manager init")
    if not state.get("selected_route_id"):
        raise WorkflowError(2, "act", "尚未选择路线（selected_route_id 为空）：先 plan+choose")
    version, project = current_version(root)
    return controlled_context(root, action, version, project, dict(state["references"]),
                              str(state["generation_id"]), str(state["selected_route_id"]))


def manager_domains(state: dict) -> list[str]:
    """取 Manager 当前的 primary/aux 域（共享给父 `act` 与子进程 `admit`，单一口径）。"""
    user_input = state.get("user_input") or {}
    domains = [str(user_input.get("primary_domain") or "")] + \
              list(user_input.get("auxiliary_domains") or [])
    return [d for d in domains if d]


def manager_domains_from_project(root: Path) -> list[str]:
    """从磁盘上**当前** Manager 状态取域（子进程用：不复用信封里的任何域声明）。"""
    _events, state = M.current_context(root)
    return manager_domains(state)


def admit_context(action: str, domains: list[str], effects: dict, skill_dir=None) -> dict:
    """`admit_action()` 的 `ContextError` 版（子进程用；**同一个**准入函数）。"""
    try:
        return admit_action(action, domains, effects, skill_dir)
    except WorkflowError as exc:
        raise ContextError(exc.rc, "exec", exc.reason, **{
            k: v for k, v in exc.extra.items() if k in ("action", "tool", "domains",
                                                        "effects", "hint", "gap_reason")})


def verify_action_context(payload: dict):
    """重验上下文 → 真调 check_action → **重新 admit_action** → 重验参数 → 重绑 target。

    顺序不可换，且**抛之前不 import seep_mcp_server、不调用任何工具函数**。
    返回 (action, verified_args, context, spec, admission)。

    与旧实现的差别（独立验收 §3.2 refuted）：
      旧版只做 check_action + 参数 + target 重绑，**不调用 admit_action**，
      于是一个自封信封就能让 `firmware-iot` 项目执行 `apk.info`（act 侧 rc=3 拒）。
      现在域与 effects 都在子进程里**重新算**：取 Manager 当前 primary/aux 域
      （`manager_domains_from_project`）、按 `Tool/skill/*/pack.json` 现算 pack.tools、
      现读 `Tool/config/tool-effects.json` —— 信封里的 action/args/域声明都不被信任。
    """
    if not isinstance(payload, dict):
        raise ContextError(4, "exec", "执行载荷必须是 JSON 对象")
    envelope, args = payload.get("envelope"), payload.get("args")
    if not isinstance(envelope, dict) or not isinstance(args, dict):
        raise ContextError(4, "exec", "缺少受控信封/参数：拒绝裸执行")
    context = envelope.get("context")
    if not isinstance(context, dict) or not context.get("project"):
        raise ContextError(4, "exec", "缺少受控上下文（project）：拒绝裸执行（_exec 不再可直接调用）")
    nonce = str(envelope.get("nonce") or "")
    digest = str(envelope.get("digest") or "")
    if not digest or not _compare_digest(digest, _payload_digest(context, args)):
        raise ContextError(4, "exec", "参数与受控上下文不一致（参数被替换）：拒绝执行")
    if not nonce or not _compare_digest(nonce, _envelope_digest(digest)):
        raise ContextError(4, "exec", "执行信封非本入口派生（nonce/digest 不匹配）：拒绝执行")
    action = str(context.get("action") or "")
    if action not in ACTIONS:
        raise ContextError(4, "exec", "动作不在审核映射表内：拒绝执行")
    spec = ACTIONS[action]
    target_param = spec.get("target_param")
    extra = set(args) - set(spec["params"]) - ({target_param} if target_param else set())
    if extra:
        raise ContextError(4, "exec", "参数超出该动作允许的键：拒绝执行")
    root = M.project_root(context["project"])
    if not (root / "project.json").is_file():
        raise ContextError(2, "exec", "项目不存在：先 start 登记生命周期")
    refs = context.get("refs")
    if not isinstance(refs, dict) or not refs.get("run_id"):
        raise ContextError(2, "exec", "缺少 run refs：先 intake")
    if not context.get("generation_id") or not context.get("route_id"):
        raise ContextError(2, "exec", "缺少 generation/已选路线：先 intake 并 choose")
    version, project = current_version(root)
    if str(context.get("version_id")) != str(version.get("version_id")) or \
            str(context.get("project_id")) != str(project.get("project_id")):
        raise ContextError(2, "exec", "受控上下文不是项目当前 version/project")
    if str(context.get("target_sha256")) != str(version.get("sha256")):
        raise ContextError(2, "exec", "受控上下文里的目标哈希已陈旧")
    if target_param and not context.get("input_asset") and str(version.get("kind") or "file") != "file":
        raise ContextError(3, "exec", "该 file parser 只接受 kind=file；目录/URL 在加载工具前拒绝")
    # ---- ① 真调 check_action（Manager 当前 refs/route/generation/target 快照） ----
    # 每次重新调用 = 状态变 WAIT_USER / refs / route / generation 后重放必拒。
    try:
        M.check_action(root, dict(refs), str(context["route_id"]),
                       str(version.get("sha256")), str(context["generation_id"]))
    except M.ManagerError as exc:
        raise ContextError(2, "exec", "执行前 check-action 拒绝：%s" % exc)
    # ---- ② 重新 admit_action：域/effects 从磁盘现场重算，不信信封 ----
    domains = manager_domains_from_project(root)
    if not domains:
        raise ContextError(3, "exec", "拒绝执行：Manager 当前没有登记主/辅域")
    admission = admit_context(action, domains, load_effects())
    # ---- ③ 参数 schema 全校验（与父 act 同一个 validate_args） ----
    verified = validate_args(root, action, {k: v for k, v in args.items()
                                           if k != target_param})
    # ---- ④ target 从 version 重绑（不接受外部指定） ----
    target, version2, _project = project_target(root)
    if str(version2.get("sha256")) != str(version.get("sha256")):
        raise ContextError(5, "exec", "目标在重绑期间变化")
    if context.get("input_asset") is not None:
        if not target_param or not isinstance(context["input_asset"], dict):
            raise ContextError(4, "exec", "动作不接受输入资产或绑定格式无效")
        try:
            target, binding = action_input(root, version, context["input_asset"].get("asset_id"))
        except WorkflowError:
            raise ContextError(3, "exec", "输入资产身份不可复核")
        if binding != context["input_asset"]:
            raise ContextError(5, "exec", "输入资产绑定已陈旧")
    if target_param and target is None:
        raise ContextError(3, "exec", "file parser 不接受目录或 URL target")
    if target_param:
        supplied = args.get(target_param)
        if supplied is not None and str(supplied) != str(target):
            # 目标只能来自 version；--args-json 传另一个路径做覆盖 → 拒（不是忽略）
            raise ContextError(4, "exec",
                               "拒绝外部指定目标路径：目标只能从 version 重绑")
        verified[target_param] = str(target)   # 目标从 version 重绑，不接受外部指定
    return action, verified, context, spec, admission


def classify_outcome(spec: dict, result: dict) -> tuple[str, str]:
    """把「动作是否跑成」与「是否拿到结果」分开，返回 (outcome, outcome_reason)。

    * 超时/工具报错 → failed（动作没跑成），reason 保留真实原因（timeout / error / invalid / …）
    * 跑成但 zero_results / zero_match / unknown / empty_output / resource_constraint /
      missing_result → **不是** succeeded：动作确实执行了（executed=True），但"有结果"为否，
      不能替路线背书；记 failed 并在 attempt 里写明原因（不把零命中当工具崩溃）。
    * 跑成但 partial → 记 failed + reason=partial（Manager attempt 状态仍用现接口）；
      已拿到的 data has_result 可为 true，但 outcome 不得 succeeded，也不算完整验收；
      用 `outcome_class()` 把它单独归类成 partial，不混成"零结果"或"工具崩溃"。
    * 只有 rc=0 + 工具 ok + 非上述状态才算 succeeded。

    Manager 状态词仍是它已有的 succeeded/failed/blocked/partial，不新增 schema。
    """
    status = str(result.get("tool_status") or "")
    if result.get("timeout"):
        return "failed", "timeout"
    if status in PARTIAL_OUTCOME_STATUS:
        # partial：已拿到的 data 可 has_result=true，但**绝不** succeeded、不算完整验收；
        # Manager attempt 仍用现 succeeded/failed 接口，partial 这个区分放在
        # outcome_reason/outcome_class 里（不新增 Manager schema）。
        return "failed", status
    if status in COMMON_OUTCOME_STATUS:
        # 动作跑成了，但没有可用结果——与工具崩溃区分开（rc 可能是 0 或 1）。
        return "failed", status
    if result.get("rc") != 0:
        return "failed", "tool_error:%s" % (status or "rc=%s" % result.get("rc"))
    if status.startswith("tool_error:"):
        return "failed", status
    if not result.get("tool_ok"):
        return "failed", "tool_error:%s" % (status or "not_ok")
    if result.get("tool_payload_ok") is None and spec.get("kind") != "inproc":
        return "failed", "missing_result"
    return "succeeded", "ok"


def outcome_is_no_result(reason: str) -> bool:
    """零命中/未知/空输出/超约束/缺结果：动作执行了但没结果，不能当成功。"""
    return str(reason or "") in COMMON_OUTCOME_STATUS


def outcome_is_partial(reason: str) -> bool:
    """部分结果：动作执行了、也许拿到了部分数据，但不足以当完整结果/完整验收。"""
    return str(reason or "") in PARTIAL_OUTCOME_STATUS


def outcome_class(outcome: str, reason: str) -> str:
    """把 outcome/reason 归类成 no_result / partial / error / ok（只用于报告与 rc，不改 Manager）。"""
    reason = str(reason or "")
    if outcome == "succeeded":
        return "ok"
    if outcome_is_partial(reason) or outcome == "partial":
        return "partial"
    if outcome_is_no_result(reason):
        return "no_result"
    return "error"


def action_has_result(outcome: str, reason: str, result: dict | None = None) -> bool:
    """动作是否拿到了**可用结果**（只有 succeeded 才算完整；partial 单独看真实 data）。

    * succeeded → True；
    * partial   → 工具结构化声明了 has_result（真的解析到了部分 data）才算 True，
                  但 outcome 仍不是 succeeded，也不算完整验收；
    * no_result / error → False（零结果或工具崩溃都不能替路线背书）。
    """
    if outcome == "succeeded":
        return True
    if outcome_is_partial(reason) or outcome == "partial":
        declared = (result or {}).get("tool_has_result")
        return declared is True
    return False


def current_version(root: Path) -> tuple[dict, dict]:
    """只读取项目当前 version/project（公开只读函数，不新建判据）。"""
    project = P.require_project(root)
    version_id = str(project.get("current_version_id") or "")
    P.require_id(version_id, "current_version_id")
    version = P._validate_version(root, version_id, project["project_id"])
    return version, project


def child_main(payload) -> int:
    """子进程入口（只能由 run_action 封装的受控信封驱动）。

    顺序不可换：**先** verify_action_context（重算哈希 → 真调 check_action →
    **重新 admit_action**（Manager 当前域 + 现算 pack.tools + 现读 effects）→
    参数 schema 全校验 → target 重绑），**然后**才 load_mcp / 调用工具函数。
    没有信封的裸调用返回 rc=4；被拒时 `load_mcp` 与 `_run_cmd` 调用数为 0。

    信封**不是凭据也不是一次性授权**：同一状态重复只读动作允许（每次重新 check/admit，
    每次都产生独立 capture）；状态变化后的重放由 check_action 每次重调兜住。
    """
    try:
        action, args, context, spec, admission = verify_action_context(payload)
    except ContextError as exc:
        payload_out = {"ok": False, "blocked_at": exc.stage, "reason": exc.reason,
                       "rc": exc.rc, "status": "refused"}
        payload_out.update({k: v for k, v in exc.extra.items() if k not in ("hint",)})
        print(json.dumps(payload_out, ensure_ascii=False, indent=2))
        return exc.rc
    except (M.ManagerError, WorkflowError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"ok": False, "blocked_at": "exec",
                          "reason": type(exc).__name__, "rc": 2,
                          "status": "refused"}, ensure_ascii=False))
        return 2
    if spec["kind"] == "inproc":
        target, _version, _project = project_target(M.project_root(context["project"]))
        fingerprint = P.target_fingerprint(M.project_root(context["project"]), _version)
        print(json.dumps({"ok": True, "status": "ok", "result": fingerprint,
                          "kind": fingerprint["kind"], "identity_scope": fingerprint["identity_scope"],
                          "text": json.dumps(fingerprint, ensure_ascii=False, default=str)},
                         ensure_ascii=False))
        return 0
    diagnostics_out, diagnostics_err = io.StringIO(), io.StringIO()
    failure = None
    text = ""
    try:
        # Tools may print diagnostics as well as return a value. Inspect both
        # before emitting anything to the parent capture process.
        with contextlib.redirect_stdout(diagnostics_out), contextlib.redirect_stderr(diagnostics_err):
            module = load_mcp()
            fn = getattr(module, spec["tool"])
            result = fn(**args)
            text = _result_text(result)
    except Exception as exc:  # noqa: BLE001 —— 缺依赖/解析失败如实回 unknown
        failure = (type(exc).__name__, str(exc))
    streams = (text, diagnostics_out.getvalue(), diagnostics_err.getvalue(),
               failure[1] if failure else "")
    if any(M.SENSITIVE_VALUE_RE.search(value) for value in streams):
        print(json.dumps({"ok": False, "status": "sensitive_output_blocked",
                          "has_result": False, "rc": 5}, ensure_ascii=False))
        return 5
    if diagnostics_out.getvalue():
        print(diagnostics_out.getvalue(), end="", file=sys.stderr)
    if diagnostics_err.getvalue():
        print(diagnostics_err.getvalue(), end="", file=sys.stderr)
    if failure:
        print(json.dumps({"ok": False, "status": "unknown",
                          "error": failure[0], "message": failure[1][:400]},
                         ensure_ascii=False))
        return 1
    tool_ok, status, has_result = True, "ok", None
    stripped = text.lstrip()
    if stripped.startswith("[ERROR]"):
        tool_ok, status = False, "error"
    else:
        body, parsed = _parse_tool_body(stripped)
        if isinstance(body, dict):
            status = str(body.get("status") or "")
            if body.get("ok") is False:
                # ok=false 优先：即便 body 里还写着 status=ok，也不得当成成功状态透传。
                tool_ok = False
                if status in ("", "ok", "success", "succeeded"):
                    status = "tool_reported_not_ok"
            if isinstance(body.get("has_result"), bool):
                has_result = bool(body["has_result"])
            if not status:
                if body.get("error") in COMMON_OUTCOME_STATUS:
                    status = str(body.get("error"))
                elif body.get("hits") == [] and "near_miss" in body:
                    status = "zero_match"
                elif not body.get("hits") and body.get("error"):
                    status = str(body.get("error"))
        elif isinstance(body, list) and not body:
            # 空列表命中：跑成了但没结果（ok 保持 true，status 记 zero_match）。
            tool_ok, status = True, "zero_match"
    if len(text) > 400 * 1024:
        text = text[:400 * 1024] + "\n[workflow] output truncated at 400KiB"
    # `has_result` 只在工具真的结构化声明时透传；不猜（None = 工具没说）。
    print(json.dumps({"ok": tool_ok, "status": status, "text": text,
                      "has_result": has_result}, ensure_ascii=False))
    return 0 if tool_ok else 1


def _result_text(result) -> str:
    """把工具返回值（str / dict / TextContent / tuple 内容列表）统一成文本。

    MCP 工具可以在不改变语义的前提下返回多种形状；这里**只做取文本**，
    判定仍然只发生在 `_parse_tool_body()` 之后的那一份 JSON 上，不因形状不同换判据。
    """
    if isinstance(result, str):
        return result
    if isinstance(result, (list, tuple)):
        parts = [_result_text(item) for item in result]
        return "".join(part for part in parts if part)
    text = getattr(result, "text", None)
    if isinstance(text, str):
        return text
    if hasattr(result, "model_dump"):
        try:
            dumped = result.model_dump()
            if isinstance(dumped, dict) and isinstance(dumped.get("text"), str):
                return dumped["text"]
        except Exception:  # noqa: BLE001 —— 取不到文本就走序列化兜底
            pass
    try:
        return json.dumps(result, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(result)


def _parse_tool_body(stripped: str):
    """返回 (body, parsed)：只认以 `{` / `[` 开头的 JSON（与旧口径一致）。"""
    if stripped.startswith("{"):
        try:
            return json.loads(stripped), True
        except ValueError:
            return None, False
    if stripped.startswith("["):
        try:
            return json.loads(stripped), True
        except ValueError:
            return None, False
    return None, False

def load_mcp():
    if "seep_mcp_server" in sys.modules:
        return sys.modules["seep_mcp_server"]
    spec = importlib.util.spec_from_file_location("seep_mcp_server", MCP_SERVER)
    module = importlib.util.module_from_spec(spec)
    sys.modules["seep_mcp_server"] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# act
# ---------------------------------------------------------------------------
def manager_state(root: Path) -> tuple[list, dict]:
    events, state = M.current_context(root)
    return events, state


def gap_reason(action: str) -> str:
    """未登记动作的缺口理由（取自 effects 声明，不新造禁令）。"""
    return DERIVED_REFUSALS.get(action, "未登记在 ACTIONS（capability_gap，不是永久禁令）")


def cmd_act(a) -> int:
    root = M.project_root(a.project)
    if not (root / "project.json").is_file():
        raise WorkflowError(2, "act", "项目不存在：先 start 登记生命周期")
    events, state = manager_state(root)
    if state.get("status") == "uninitialized" or not state.get("generation_id"):
        raise WorkflowError(2, "act", "Manager 尚未 intake：先 start / manager init",
                            next_actions=["登记 intake 后再执行"])
    refs = dict(state.get("references") or {})
    generation = str(state.get("generation_id") or "")
    route_id = str(state.get("selected_route_id") or "")
    # 域从**同一个** `manager_domains()` 取（子进程 `verify_action_context` 也用它），
    # 避免父/子两处语法漂移。
    domains = manager_domains(state)
    effects = load_effects()
    adm = admit_action(a.action, domains, effects)
    try:
        args = validate_args(root, a.action, json.loads(a.args_json or "{}"))
    except ValueError:
        raise WorkflowError(4, "act", "--args-json 必须合法 JSON 对象")
    target, version, project = project_target(root)
    typed_pre = P.target_fingerprint(root, version)
    spec = adm["spec"]
    target_param = spec.get("target_param")
    input_asset = None
    if getattr(a, "asset_id", ""):
        if not target_param:
            raise WorkflowError(4, "act", "该动作不接受文件输入资产")
        target, input_asset = action_input(root, version, a.asset_id)
    if target_param and input_asset is None and typed_pre["kind"] != "file":
        raise WorkflowError(3, "act", "该 file parser 只接受 kind=file；目录/URL 不会启动外部工具")
    if target_param:
        args[target_param] = str(target)
    pre = {"target_sha256": typed_pre["sha256"], "generation_id": generation,
           "references": refs, "route_id": route_id}
    # 执行前 check-action（真实函数，与 CLI 同一函数体）；不通过则磁盘零新增
    try:
        snapshot = M.check_action(root, refs, route_id, str(version.get("sha256")),
                                  generation)
    except M.ManagerError as exc:
        hints = {"waiting": state.get("waiting"), "replan_required": state.get("replan_required"),
                 "replan_reason": state.get("replan_reason"),
                 "evidence_errors": state.get("evidence_errors"),
                 "next_actions": state.get("next_actions")}
        raise WorkflowError(2, "act", "执行前 check-action 拒绝：%s" % exc,
                            hint="先 answer/replan/修证据；本次未执行、未写 capture",
                            **hints)
    if a.dry_run:
        return emit({"ok": True, "dry_run": True, "action": a.action, "admission": {
            "coverage": adm["coverage"], "owner_domains": adm["owner_domains"],
            "executes_foreign_code": adm["executes_foreign_code"]},
            "params": {k: v for k, v in args.items() if k != target_param},
            "check_action": snapshot, "enforcement_scope": ENFORCEMENT_SCOPE,
            "globally_enforced": False}, a.json,
            "[DRY] check-action 通过；未执行、未写盘（enforcement_scope=workflow-entry-only）")

    if input_asset is not None:
        context = controlled_context(root, a.action, version, project, refs, generation, route_id)
        context["input_asset"] = input_asset
        result = run_action(root, a.action, args, a.timeout, context=context)
    else:
        result = run_action(root, a.action, args, a.timeout)
    if result.get("tool_status") == "sensitive_output_blocked" or any(
            M.SENSITIVE_VALUE_RE.search(str(result.get(key) or ""))
            for key in ("stdout", "stderr")):
        return emit({"ok": False, "executed": True, "evidence_accepted": False,
                     "rc": 5, "action": a.action, "blocked_at": "output-boundary",
                     "outcome": "failed", "reason": "sensitive_output_blocked",
                     "message": "工具输出含敏感内容，已停止；未保存输出或登记证据。"},
                    a.json, "[RC5] 敏感输出已阻止，未保存或登记。", rc=5)
    try:
        post_fp = P.target_fingerprint(root, version)
        post_hash = post_fp["sha256"]
    except Exception:
        if str(version.get("kind") or "file") == "file" and version.get("local_path"):
            try:
                changed_path = (root / P.relative_ref(version["local_path"])).resolve()
                raw = P.file_fingerprint(changed_path)
                post_fp = {"kind": "file", "identity_scope": "raw-bytes", **raw}
                post_hash = raw["sha256"]
            except Exception:
                post_fp = {"kind": "file", "identity_scope": "raw-bytes", "sha256": "", "size": None}
                post_hash = ""
        else:
            post_fp = {"kind": str(version.get("kind") or "file"),
                       "identity_scope": version.get("identity_scope") or "raw-bytes",
                       "sha256": "", "size": None}
            post_hash = ""
    # TOCTOU：执行后重新核对目标哈希 + 重新取一次锁内快照
    toctou = []
    if input_asset is not None:
        try:
            if P.asset_binding(root, version["version_id"], input_asset["asset_id"]) != input_asset:
                toctou.append("输入资产身份在执行期间变化")
        except Exception:
            toctou.append("输入资产在执行后不可复核")
    if post_hash != pre["target_sha256"]:
        toctou.append("target_sha256 在执行期间变化")
    try:
        snapshot2 = M.check_action(root, refs, route_id, post_hash, generation)
    except M.ManagerError as exc:
        snapshot2 = {"ok": False, "reason": str(exc)}
        toctou.append("执行后 check-action 失败：%s" % exc)
    if snapshot2.get("ledger_head") and snapshot2["ledger_head"] != snapshot.get("ledger_head"):
        toctou.append("manager ledger_head 在执行期间推进")
    if snapshot2.get("generation_id") not in (None, generation):
        toctou.append("generation 在执行期间变化")

    run_id = str(refs.get("run_id") or "")
    version_id = str(version.get("version_id") or "")
    capture_dir = root / "versions" / version_id / "runs" / run_id / "capture"
    capture_dir.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", a.action)
    stamp = utc_slug()
    evidence_id = "ev-%s-%s-%s" % (slug, stamp, uuid.uuid4().hex[:6])
    raw_name = "raw-%s.out" % evidence_id
    raw_path = capture_dir / raw_name
    raw_text = (result["stdout"] or "") + (("\n[stderr]\n" + result["stderr"])
                                           if result["stderr"] else "")
    raw_bytes = raw_text.encode("utf-8", "replace")
    raw_path.write_bytes(raw_bytes)
    truncated = len(raw_text) > MAX_CAPTURE_TEXT
    base_outcome, outcome_reason = classify_outcome(spec, result)
    outcome = "failed" if toctou else base_outcome
    if toctou and base_outcome == "succeeded":
        outcome_reason = "toctou"
    base_has_result = action_has_result(base_outcome, outcome_reason, result)
    outcome_kind = outcome_class(base_outcome, outcome_reason)
    capture = {
        "schema": CAPTURE_SCHEMA, "action": a.action, "method": result["method"],
        "argv": result["argv"], "params": result["params"],
        "rc": result["rc"], "timeout": result["timeout"],
        "elapsed_s": result.get("elapsed_s"),
        "stdout": result["stdout"][:MAX_CAPTURE_TEXT],
        "stderr": result["stderr"][:MAX_CAPTURE_TEXT],
        "stdout_truncated": truncated,
        "raw_capture": raw_name, "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "raw_size": len(raw_bytes),
        "tool_ok": result.get("tool_ok"), "tool_status": result.get("tool_status"),
        "target_path": version.get("local_path"), "target_kind": post_fp["kind"],
        "identity_scope": post_fp["identity_scope"], "target_sha256": post_hash,
        "target_size": post_fp["size"],
        "pre_target_sha256": pre["target_sha256"],
        "generation_id": generation, "route_id": route_id, "references": refs,
        "pre_check_ledger_head": snapshot.get("ledger_head"),
        "post_check_ledger_head": snapshot2.get("ledger_head"),
        "ledger_diverged": bool(snapshot2.get("ledger_head")
                                and snapshot2["ledger_head"] != snapshot.get("ledger_head")),
        "toctou": toctou, "outcome": outcome, "outcome_reason": outcome_reason,
        "outcome_class": outcome_kind,
        "tool_has_result": result.get("tool_has_result"),
        "executed": True,
        "has_result": base_has_result,
        "admission": {"coverage": adm["coverage"], "owner_domains": adm["owner_domains"],
                      "effects": adm["effects"],
                      "executes_foreign_code": adm["executes_foreign_code"]},
        "enforcement_scope": ENFORCEMENT_SCOPE, "globally_enforced": False,
        "proof_level": "structural+recorded_witness",
        "recorded_at": now(),
    }
    if input_asset is not None:
        capture["input_asset"] = input_asset
    capture_path = capture_dir / ("%s.json" % evidence_id)
    P.atomic_json(capture_path, capture)
    rel_evidence = capture_path.relative_to(root).as_posix()
    fingerprint = P.file_fingerprint(capture_path)

    if toctou:
        return emit({
            "ok": False, "executed": True, "evidence_accepted": False, "rc": 5,
            "action": a.action, "capture": rel_evidence, "toctou": toctou,
            "outcome": outcome, "acceptance": "pending（本次未登记证据/尝试）",
            "message": "动作已执行，但执行后核对失败：证据未被接受（不伪称全局锁）",
            "enforcement_scope": ENFORCEMENT_SCOPE, "globally_enforced": False,
        }, a.json, "[RC5] 已执行但证据未被接受：%s（capture 保留：%s）"
                   % ("; ".join(toctou), rel_evidence), rc=5)

    # 真 evidence 接口（公开 CLI，另一代理独占的文件只调用）
    ev_args = [P_SCRIPT, "evidence", "--project", str(root), "--version", version_id,
                  "--run-id", run_id, "--kind", "evidence", "--evidence-id", evidence_id,
                  "--target-sha256", str(version.get("sha256")),
                  "--path", rel_evidence, "--sha256", fingerprint["sha256"],
                  "--size", str(fingerprint["size"]), "--source", rel_evidence,
                  "--raw-output", raw_path.relative_to(root).as_posix(),
                  "--how", "project_workflow.py %s (method=%s)" % (a.action, result["method"]),
                  "--recorded-by", "workflow-entry"]
    if input_asset is not None:
        ev_args += ["--input-asset", input_asset["asset_id"]]
    ev = run_cli(ev_args)
    evidence_ok = bool(ev.get("ok"))
    attempt_ok, attempt = False, {}
    if evidence_ok:
        attempt_cmd = [M_SCRIPT, "attempt", "--project", str(root), "--route-id", route_id,
                       "--status", outcome, "--result",
                       ("%s outcome=%s reason=%s rc=%s tool_ok=%s status=%s evidence=%s"
                        % (a.action, outcome, outcome_reason, result["rc"],
                           result.get("tool_ok"), result.get("tool_status"),
                           evidence_id))[:400],
                       "--evidence", rel_evidence, "--json"]
        if spec.get("tool"):
            attempt_cmd += ["--tool", spec["tool"]]
        payload = run_cli(attempt_cmd)
        attempt_ok = bool(payload.get("ok"))
        attempt = payload.get("state", {}).get("attempts", [{}])[-1] if attempt_ok else {}
    state_after = manager_state(root)[1]
    summary = {
        "ok": bool(evidence_ok and attempt_ok and base_outcome == "succeeded"),
        "action": a.action, "outcome": outcome, "outcome_reason": outcome_reason,
        "outcome_class": outcome_kind, "has_result": base_has_result, "executed": True,
        "rc": result["rc"], "timeout": result["timeout"],
        "tool_status": result.get("tool_status"),
        "capture": rel_evidence, "evidence_id": evidence_id, "evidence_registered": evidence_ok,
        "attempt_recorded": attempt_ok,
        "generation_id": generation, "route_id": route_id, "references": refs,
        "target_sha256": post_hash,
        "attempt_generation_id": attempt.get("generation_id"),
        "attempt_target_sha256": attempt.get("target_sha256"),
        "attempt_evidence_paths": [e.get("path") for e in (attempt.get("evidence") or [])],
        "acceptance": "pending（exit0/方法返回不自动 pass；验收只在 close 显式给证据）",
        "replan_required": bool(state_after.get("replan_required")),
        "next_actions": state_after.get("next_actions"),
        "enforcement_scope": ENFORCEMENT_SCOPE, "globally_enforced": False,
        "scope_note": SCOPE_NOTE,
    }
    if not (evidence_ok and attempt_ok):
        summary["rc"] = 5
        summary["message"] = "已执行但证据/尝试没记成：%s" % (
            ev.get("reason") or "manager attempt 被拒")
        return emit(summary, a.json, "[RC5] 已执行但证据未被接受：%s（capture 保留）"
                    % summary["message"], rc=5)
    if base_outcome != "succeeded":
        # 动作执行了、证据也绑定了，但**没拿到完整结果**。三种情形分开报，不混成一笔：
        #   * no_result（zero_match / zero_results / unknown / empty_output /
        #     resource_constraint / missing_result）：执行了但没结果 → rc=2
        #   * partial：执行了、有部分已解析数据（has_result 可为 true）但 outcome 不得
        #     succeeded、也不能算完整验收 → rc=2（同样不背书路线）
        #   * error/invalid/timeout/...：工具/执行真的出错 → 保留 rc=0
        #     （那是“正常的工作流步骤失败”，由 manager 的熔断/复盘机制处理）
        summary["ok"] = False
        if outcome_kind == "partial":
            summary["message"] = ("动作已执行但只拿到部分结果（outcome=partial，"
                                  "has_result=%s）：不计 route 成功，也不算完整验收；"
                                  "partial 不是工具崩溃，原始 execute 记录/capture 全保留"
                                  % base_has_result)
        elif outcome_is_no_result(outcome_reason):
            summary["message"] = ("动作已执行但未得到可用结果（outcome_reason=%s）："
                                  "不计 route 成功；capture 保留为原始请求证据" % outcome_reason)
        else:
            summary["message"] = ("动作执行失败（outcome_reason=%s）：保留真实原因，"
                                  "不当作零命中/空结果" % outcome_reason)
        rc = 2 if (outcome_kind in ("no_result", "partial")) else 0
        label = {"partial": "[PARTIAL]", "no_result": "[NO_RESULT]"}.get(outcome_kind,
                                                                       "[TOOL_ERROR]")
        return emit(summary, a.json,
                    "%s %s → %s（reason=%s, class=%s）；证据 %s 已存，但不得当作路线成功"
                    % (label, a.action, outcome, outcome_reason, outcome_kind, evidence_id),
                    rc=rc)
    return emit(summary, a.json,
                "[OK] %s → %s（rc=%s）；证据 %s；attempt 已绑定同一 run/generation；"
                "验收仍 pending" % (a.action, outcome, result["rc"], evidence_id))


P_SCRIPT = os.path.join(HERE, "project_state.py")
M_SCRIPT = os.path.join(HERE, "manager_state.py")


def run_cli(argv: list, timeout: int = 120) -> dict:
    """公开 CLI 调用（shell=False，逐项 argv）。返回解析后的 JSON（失败也不抛）。"""
    try:
        proc = subprocess.run([sys.executable, "-B", "-X", "utf8"] + [str(x) for x in argv],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, shell=False, cwd=ROOT)
    except subprocess.TimeoutExpired:
        return {"ok": False, "reason": "子进程超时（%ss）" % timeout, "rc": None}
    text = (proc.stdout or "").strip()
    payload = {}
    if text.startswith("{"):
        try:
            payload = json.loads(text)
        except ValueError:
            payload = {}
    elif text:
        payload = {"text": text[:4000]}
    payload.setdefault("rc", proc.returncode)
    if proc.returncode != 0:
        payload["ok"] = False
    if proc.returncode != 0 and "reason" not in payload:
        payload["reason"] = (text or proc.stderr or "rc=%s" % proc.returncode)[:600]
    payload.setdefault("ok", proc.returncode == 0 and payload.get("ok", False))
    return payload


# ---------------------------------------------------------------------------
# start —— 只登记生命周期，不运行目标
# ---------------------------------------------------------------------------
def sanitize_id(text: str, fallback: str = "project") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(text or "")).strip("-.")
    return cleaned[:64] or fallback


def cmd_start(a) -> int:
    root = M.project_root(a.project)
    if (root / "project.json").exists():
        raise WorkflowError(2, "start", "项目已存在；本入口不覆盖已有账号/验收/历史",
                            hint="用 status/act 继续已有项目")
    if not a.quote.strip():
        raise WorkflowError(2, "start", "用户原话不能为空；未创建项目")
    route_fields = [a.route_id, a.p is not None, a.hours, a.fail_criteria, a.evidence_goal]
    route_ok = all(route_fields)
    if any(route_fields) and not route_ok:
        raise WorkflowError(2, "start", "路线参数需同时填写 --route-id/--p/--hours/--fail/--evidence-goal；未创建项目")
    if route_ok:
        # Use the Manager's validator before the first write, so both entries
        # enforce the same route contract (including NaN and invalid IDs).
        M.route_from_args(argparse.Namespace(
            route_json="", route_id=a.route_id, success_rate=a.p,
            estimated_hours=a.hours, needs=[], fail_criteria=a.fail_criteria,
            evidence_goal=a.evidence_goal))
    cls = None
    if a.primary_domain:
        domains = [a.primary_domain] + list(a.aux_domain or [])
        pack_tools, problems = pack_tools_for(domains)
        missing = [d for d, m in pack_tools.items() if not m["known"]]
        if missing:
            raise WorkflowError(2, "start", "域不存在于 Tool/skill/*/pack.json：%s"
                                % ",".join(missing), pack_problems=problems)
        cls = {"primary_candidate": a.primary_domain,
               "aux_candidates": list(a.aux_domain or []),
               "requires_main_agent_decision": False, "packs": [],
               "pack_tools": pack_tools}
    else:
        cls = classify(a.quote, a.skill_dir)
        if cls["unclassified"]:
            raise WorkflowError(2, "start", "判不出领域（[UNCLASSIFIED]）：先问用户一句，"
                                "不建项目、不乱选域", classification=cls)
        if cls["requires_main_agent_decision"] and not a.allow_ambiguous:
            raise WorkflowError(2, "start",
                                "主/辅域并列（ambiguity）：交主 Agent 决定专业路线后再 start",
                                classification=cls,
                                hint="确认后加 --allow-ambiguous，或显式 --primary-domain/--aux-domain")
        domains = [cls["primary_candidate"]] + list(cls["aux_candidates"])
    primary = domains[0]
    project_id = sanitize_id(a.project_id or Path(root).name or "project")
    version_id = a.version
    P.require_id(project_id, "project-id")
    P.require_id(version_id, "version")
    run_id = a.run_id or ("run-" + utc_slug())
    P.require_id(run_id, "run-id")
    init_cmd = [P_SCRIPT, "init", "--project", str(root), "--project-id", project_id,
                "--title", a.title or project_id, "--domain", ",".join(d for d in domains if d),
                "--version", version_id]
    if a.target:
        target_text = str(a.target)
        if target_text.lower().startswith(("http://", "https://")):
            init_cmd += ["--target", target_text, "--asset-id", "asset-main"]
        else:
            target_path = Path(os.path.abspath(os.path.expanduser(target_text)))
            if not target_path.exists() or (not target_path.is_file() and not target_path.is_dir()):
                raise WorkflowError(2, "start", "目标不存在或类型不支持（本入口不猜路径）")
            init_cmd += ["--target", str(target_path), "--asset-id", "asset-main"]
    steps = [("project_state init", init_cmd),
             ("project_state run", [P_SCRIPT, "run", "--project", str(root), "--version", version_id,
                     "--run-id", run_id, "--executor", "workflow-entry"]),
             ("manager intake", [M_SCRIPT, "init", "--project", str(root), "--user-quote", a.quote,
                      "--primary-domain", primary,
                      "--target-version", version_id, "--project-ref", project_id,
                      "--version", version_id, "--run", run_id]
                     + sum([["--aux-domain", d] for d in domains[1:]], []) + ["--json"])]
    if route_ok:
        steps.extend([("manager plan", [M_SCRIPT, "plan", "--project", str(root), "--route-id", a.route_id,
                           "--p", str(a.p), "--hours", a.hours,
                           "--fail", a.fail_criteria, "--evidence-goal", a.evidence_goal,
                           "--json"]),
                      ("manager choose", [M_SCRIPT, "choose", "--project", str(root),
                             "--route-id", a.route_id, "--json"])])
    completed_steps = []
    for index, (stage, command) in enumerate(steps):
        result = run_cli(command)
        if not result.get("ok"):
            raise WorkflowError(2, "start", "%s 拒绝：%s" % (stage, result.get("reason")),
                                detail=result, completed_steps=list(completed_steps),
                                recovery_commands=[[sys.executable, *cmd] for _, cmd in steps[index:]],
                                hint="保留已完成阶段；按顺序执行 recovery_commands 补齐剩余阶段，再用 status 检查。不要重新 start 或删除项目。")
        completed_steps.append(stage)
    state_after = manager_state(root)[1]
    next_actions = list(state_after.get("next_actions") or [])
    if not route_ok:
        next_actions = ["登记候选路线（--p/--hours/--fail/--evidence-goal）并 choose"] + next_actions
    if not a.target:
        next_actions.append("无目标：meta.fingerprint 需先登记目标版本；kb.* 仍可走知识库路线")
    return emit({
        "ok": True, "schema": SCHEMA, "project": str(root), "project_id": project_id,
        "version": version_id, "run": run_id, "domains": domains,
        "classification": {k: cls.get(k) for k in
                           ("primary_candidate", "aux_candidates", "ambiguity",
                            "requires_main_agent_decision", "pack_tools")},
        "route_id": a.route_id if route_ok else None,
        "manager_status": state_after.get("status"),
        "next_actions": next_actions,
        "executed_target": False, "ran_any_action": False,
        "enforcement_scope": ENFORCEMENT_SCOPE, "globally_enforced": False,
        "scope_note": SCOPE_NOTE,
    }, a.json, "[OK] 生命周期已登记（未运行目标）：%s / %s / %s；下一步：%s"
               % (project_id, version_id, run_id, "; ".join(next_actions)))


# ---------------------------------------------------------------------------
# status —— 只读汇合 project + manager（任一 blocked 都不能 ok=true）
# ---------------------------------------------------------------------------
def project_summary(root: Path) -> dict:
    project = P.require_project(root)
    version_id = str(project.get("current_version_id") or "")
    out = {"ok": False, "project_id": project.get("project_id"),
           "current_version_id": version_id, "blocked": False, "reasons": []}
    try:
        version = P._validate_version(root, version_id, project["project_id"])
    except Exception as exc:
        out["reasons"].append("版本无效：%s" % exc)
        out["blocked"] = True
        return out
    out["version"] = {k: version.get(k) for k in
                       ("version_id", "kind", "sha256", "size", "local_path",
                        "identity_scope", "primary_asset_id", "auxiliary_asset_ids")}
    out["target_ok"] = False
    try:
        target = P.target_fingerprint(root, version)
        out["target"] = {k: target.get(k) for k in
                          ("kind", "sha256", "size", "identity_scope", "remote_content_verified",
                           "local_path", "snapshot_ref", "url")}
        out["target_ok"] = True
    except Exception as exc:
        out["reasons"].append("目标核验失败：%s" % type(exc).__name__)
    runs, run_errors = P._read_runs(root)
    out["active_runs"] = [r.get("run_id") for r in runs if r.get("status") == "active"]
    out["completed_runs"] = sorted(str(r.get("run_id")) for r in runs
                                   if r.get("status") == "completed")
    out["run_errors"] = run_errors
    events, fact_errors = P.read_fact_log(root)
    out["fact_errors"] = fact_errors
    acceptance = P._acceptance_state(root, version, project)
    out["acceptance"] = {k: acceptance.get(k) for k in
                         ("defined", "complete", "counts", "pending",
                          "failed_items", "stale", "required_count", "reasons",
                          "integrity_errors")}
    for key in ("run_errors", "fact_errors"):
        if out[key]:
            out["reasons"].append("%s 非空" % key)
    if acceptance.get("integrity_errors"):
        out["reasons"].append("acceptance integrity_errors 非空")
    out["blocked"] = (not out["target_ok"] or bool(out["run_errors"]) or
                       bool(out["fact_errors"]) or bool(acceptance.get("integrity_errors")))
    out["proof_level"] = "structural+recorded_witness"
    out["ok"] = not out["blocked"]
    return out


def cmd_status(a) -> int:
    root = M.project_root(a.project)
    result = {"schema": SCHEMA, "ok": False, "enforcement_scope": ENFORCEMENT_SCOPE,
              "globally_enforced": False, "host_wiring_required": True}
    project = {}
    manager = {}
    if not (root / "project.json").is_file():
        raise WorkflowError(2, "status", "项目不存在：%s" % root.name)
    try:
        project = project_summary(root)
    except Exception as exc:
        project = {"ok": False, "blocked": True,
                   "reasons": ["%s: %s" % (type(exc).__name__, exc)]}
    try:
        core = P.write_handoff(root, persist=False)
        project["core_health"] = {"state_health": core.get("state_health"),
                                  "state_errors": core.get("state_errors") or [],
                                  "report": core.get("report")}
        if core.get("state_errors"):
            project["blocked"] = True
            project["reasons"] = list(project.get("reasons") or []) + [
                "Core state_errors 非空（详见 core_health.state_errors）"]
            project["ok"] = False
    except Exception as exc:
        project.setdefault("reasons", []).append("Core health projection 失败：%s" % type(exc).__name__)
        project["blocked"] = True
        project["ok"] = False
    try:
        events, state = manager_state(root)
        manager = {
            "status": state.get("status"), "phase": state.get("phase"),
            "blocked": state.get("status") == "blocked",
            "replan_required": bool(state.get("replan_required")),
            "replan_reason": state.get("replan_reason"),
            "waiting": {"status": (state.get("waiting") or {}).get("status"),
                        "options": list(((state.get("waiting") or {}).get("options") or {}))},
            "selected_route_id": state.get("selected_route_id"),
            "generation_id": state.get("generation_id"),
            "references": state.get("references"),
            "attempts": len(state.get("attempts") or []),
            "failed_streak": _failed_streak(state),
            "evidence_errors": state.get("evidence_errors"),
            "next_actions": state.get("next_actions"),
            "event_count": len(events),
            "globally_enforced": False,
        }
        if state.get("status") == "uninitialized":
            manager["blocked"] = True
            manager["hint"] = "Manager 未 intake：先 start（或用 manager_state.py init）"
    except Exception as exc:
        manager = {"status": "error", "blocked": True,
                   "reasons": ["%s: %s" % (type(exc).__name__, exc)]}
    legacy = None
    if a.case:
        legacy = legacy_case_snapshot(a.case)
    blocked = bool(project.get("blocked")) or bool(manager.get("blocked"))
    result.update({"ok": not blocked, "blocked": blocked,
                   "project": project, "manager": manager, "legacy_case": legacy,
                   "next_actions": list(manager.get("next_actions") or [])
                   + list(project.get("reasons") and ["核对项目证据/目标"] or [])
                   + ["继续 act 或在 close 里显式给验收证据"]})
    result["scope_note"] = SCOPE_NOTE
    return emit(result, a.json, "[%s] project=%s / manager=%s"
                % ("OK" if result["ok"] else "BLOCKED",
                   "blocked" if project.get("blocked") else "ok",
                   manager.get("status")), rc=(0 if result["ok"] else 2))


def _failed_streak(state: dict) -> int:
    streak = 0
    for attempt in reversed(state.get("attempts") or []):
        if attempt.get("route_id") != state.get("selected_route_id"):
            continue
        if attempt.get("outcome") not in ("failed", "fail", "blocked"):
            break
        streak += 1
    return streak


def legacy_case_snapshot(case: str) -> dict:
    """旧 case 只读兼容：show 文本 + facts.jsonl 前后哈希（不迁移、不覆盖、不取租约）。"""
    case_dir = Path(os.path.abspath(os.path.expanduser(case)))
    facts = case_dir / "facts.jsonl"
    before = hashlib.sha256(facts.read_bytes()).hexdigest() if facts.is_file() else None
    payload = run_cli([os.path.join(HERE, "case_state.py"), "show", "--case", str(case_dir)])
    after = hashlib.sha256(facts.read_bytes()).hexdigest() if facts.is_file() else None
    return {"case": str(case_dir), "read_only": True, "migrated": False,
            "facts_sha256_before": before, "facts_sha256_after": after,
            "bytes_unchanged": before == after,
            "show_rc": payload.get("rc"),
            "summary": (payload.get("text") or "")[:1200]}


# ---------------------------------------------------------------------------
# close —— 只调用真实验收门，从不自己写 pass
# ---------------------------------------------------------------------------
def parse_define(values) -> list:
    items = []
    for raw in values or []:
        item_id, sep, desc = str(raw).partition(":")
        if not sep or not item_id.strip() or not desc.strip():
            raise WorkflowError(2, "close", "--define 格式应为 id:description")
        P.require_id(item_id.strip(), "acceptance id")
        items.append("%s:%s" % (item_id.strip(), desc.strip()))
    return items


def parse_accept(values) -> list:
    out = []
    for raw in values or []:
        text = str(raw)
        item_id, sep, rest = text.partition("=")
        if not sep:
            raise WorkflowError(2, "close", "--accept 格式应为 item=result:ev1,ev2")
        result, _, ids = rest.partition(":")
        result = result.strip()
        if result not in P.ACCEPTANCE_RESULTS:
            raise WorkflowError(2, "close", "--accept 结果只接受 %s"
                                % ",".join(P.ACCEPTANCE_RESULTS))
        evidence = [x.strip() for x in ids.split(",") if x.strip()]
        P.require_id(item_id.strip(), "acceptance id")
        for evidence_id in evidence:
            P.require_id(evidence_id, "evidence id")
        if result == "pass" and not evidence:
            raise WorkflowError(2, "close", "pass 必须给证据 id（本入口不替验收签名）")
        out.append({"item_id": item_id.strip(), "result": result, "evidence_ids": evidence})
    return out


def cmd_close(a) -> int:
    root = M.project_root(a.project)
    if not (root / "project.json").is_file():
        raise WorkflowError(2, "close", "项目不存在")
    project = P.require_project(root)
    version_id = a.version or str(project.get("current_version_id") or "")
    P.require_id(version_id, "version")
    P._validate_version(root, version_id, project["project_id"])
    if a.run:
        P.require_id(a.run, "run")
        P._run_record(root, version_id, a.run)
    if a.finish and not a.run:
        raise WorkflowError(2, "close", "--finish 必须指定 --run")
    steps = []
    defines = parse_define(a.define)
    accepts = parse_accept(a.accept)
    if accepts and (not a.verifier or not a.how):
        raise WorkflowError(2, "close", "验收必须给 --verifier 与 --how（检查来源与方式）")
    if defines:
        payload = run_cli([P_SCRIPT, "acceptance-define", "--project", str(root),
                           "--version", version_id] +
                          sum([["--item", x] for x in defines], []))
        steps.append({"step": "acceptance-define", "ok": bool(payload.get("ok")),
                      "reason": payload.get("reason")})
        if not payload.get("ok"):
            return _close_out(a, root, version_id, steps, a, refused="acceptance-define")
    for item in accepts:
        payload = run_cli([P_SCRIPT, "acceptance-record", "--project", str(root),
                           "--version", version_id, "--item-id", item["item_id"],
                           "--result", item["result"],
                           "--evidence-ids", ",".join(item["evidence_ids"]),
                           "--verifier", a.verifier, "--how", a.how,
                           "--run", a.run or ""])
        steps.append({"step": "acceptance-record:%s" % item["item_id"],
                      "ok": bool(payload.get("ok")), "reason": payload.get("reason")})
        if not payload.get("ok"):
            return _close_out(a, root, version_id, steps, a, refused="acceptance-record")
    if a.finish:
        payload = run_cli([P_SCRIPT, "finish-run", "--project", str(root),
                           "--version", version_id, "--run-id", a.run,
                           "--status", a.finish, "--note", a.note or ""])
        steps.append({"step": "finish-run:%s" % a.finish, "ok": bool(payload.get("ok")),
                      "reason": payload.get("reason")})
        if not payload.get("ok"):
            return _close_out(a, root, version_id, steps, a, refused="finish-run")
    return _close_out(a, root, version_id, steps, a, refused=None)


def _close_out(a, root, version_id, steps, args, refused) -> int:
    """汇总真门结果；从不自行写 pass/closure。"""
    project = P.require_project(root)
    version = P._validate_version(root, version_id, project["project_id"])
    acceptance = P._acceptance_state(root, version, project,
                                     require_run=(args.run if args.finish == "completed"
                                                  else ""))
    run_status = None
    if args.run:
        run_status = P._run_record(root, version_id, args.run)[0].get("status")
    try:
        health = P.write_handoff(root, persist=False)
    except Exception as exc:
        health = {"state_health": "blocked", "state_errors":
                  [{"reason": "Core health projection failed", "type": type(exc).__name__}],
                  "report": {}}
    health_errors = list(health.get("state_errors") or [])
    result = {
        "ok": refused is None and not health_errors,
        "schema": SCHEMA, "version": version_id, "run": args.run, "steps": steps,
        "refused_at": refused,
        "acceptance": {k: acceptance.get(k) for k in
                       ("defined", "complete", "counts", "pending", "failed_items",
                        "stale", "required_count", "reasons", "integrity_errors")},
        "run_status": run_status,
        "health_ok": not health_errors,
        "state_health": health.get("state_health"),
        "state_errors": health_errors,
        "report": health.get("report"),
        "wrote_pass_itself": False,
        "note": "close 只调用 acceptance-record / finish-run 真门；never 自行写 pass/closure",
        "enforcement_scope": ENFORCEMENT_SCOPE, "globally_enforced": False,
    }
    return emit(result, a.json,
                "[%s] close %s：验收=%s（required=%s）run=%s%s"
                % ("OK" if result["ok"] else "REFUSED", version_id,
                   "complete" if acceptance.get("complete") else "pending",
                   acceptance.get("required_count"), run_status,
                   "" if refused is None else "；停在 " + refused),
                rc=(0 if result["ok"] else 2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def emit(value: dict, as_json: bool, human: str = "", rc: int = 0) -> int:
    print(json.dumps(M.scrub(value), ensure_ascii=False, indent=2) if as_json
          else (human or json.dumps(M.scrub(value), ensure_ascii=False)))
    return rc


def parser() -> argparse.ArgumentParser:
    ap = SafeArgumentParser(
        description="项目执行协调入口（编排，不新增判据）：判域→生命周期→check-action→"
                    "只读动作→证据→验收。enforcement_scope=workflow-entry-only，"
                    "globally_enforced=false；不执行目标、不接受任意命令。")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("classify", help="只判域：主/辅候选 + 本域可用只读动作；不建项目")
    p.add_argument("--quote", required=True)
    p.add_argument("--skill-dir", default="")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("start", help="只登记生命周期（project/version/run/intake[/plan/choose]），不运行目标")
    p.add_argument("--project", required=True)
    p.add_argument("--quote", required=True)
    p.add_argument("--project-id", default="")
    p.add_argument("--title", default="")
    p.add_argument("--target", default="")
    p.add_argument("--version", default="1.0")
    p.add_argument("--run-id", default="")
    p.add_argument("--route-id", default="")
    p.add_argument("--p", dest="p", type=float, default=None)
    p.add_argument("--hours", default="")
    p.add_argument("--fail", dest="fail_criteria", default="")
    p.add_argument("--evidence-goal", default="")
    p.add_argument("--primary-domain", default="")
    p.add_argument("--aux-domain", action="append", default=[])
    p.add_argument("--skill-dir", default="")
    p.add_argument("--allow-ambiguous", action="store_true",
                   help="主/辅域并列时也照候选继续（默认交主 Agent 决定）")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("act", help="执行前 check-action + 只读映射动作 + 证据/尝试绑定")
    p.add_argument("--project", required=True)
    p.add_argument("--action", required=True)
    p.add_argument("--asset-id", default="", help="选择当前版本已登记的文件资产；默认主目标")
    p.add_argument("--args-json", default="{}")
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--dry-run", action="store_true", help="只做准入+check-action，不执行不写盘")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("status", help="只读汇合 project + manager 状态")
    p.add_argument("--project", required=True)
    p.add_argument("--case", default="", help="旧案目录（只读兼容，不迁移）")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("close", help="调用真实验收门（acceptance-record / finish-run）")
    p.add_argument("--project", required=True)
    p.add_argument("--version", default="")
    p.add_argument("--run", default="")
    p.add_argument("--define", action="append", default=[])
    p.add_argument("--accept", action="append", default=[])
    p.add_argument("--finish", choices=["completed", "failed", "blocked"], default="")
    p.add_argument("--verifier", default="")
    p.add_argument("--how", default="")
    p.add_argument("--note", default="")
    p.add_argument("--json", action="store_true")
    return ap


def main(argv=None) -> int:
    a = None
    try:
        raw = list(sys.argv[1:] if argv is None else argv)
        M.reject_sensitive(raw, "argv")
        a = parser().parse_args(raw)
        M.reject_sensitive(vars(a), "arguments")
        if not a.cmd:
            parser().print_help()
            return 2
        if a.cmd == "classify":
            result = classify(a.quote, a.skill_dir or None)
            if result["unclassified"]:
                result["rc"] = 2
                emit(result, a.json, "[UNCLASSIFIED] 判不出领域，请先问用户一句话（未建项目）")
                return 2
            emit(result, a.json,
                 "[OK] 主候选=%s%s；需主 Agent 决定=%s"
                 % (result["primary_candidate"],
                    ("；辅候选=" + ",".join(result["aux_candidates"]))
                    if result["aux_candidates"] else "",
                    result["requires_main_agent_decision"]))
            return 0
        if a.cmd == "start":
            return cmd_start(a)
        if a.cmd == "act":
            return cmd_act(a)
        if a.cmd == "status":
            return cmd_status(a)
        if a.cmd == "close":
            return cmd_close(a)
        raise WorkflowError(2, "args", "未知命令")
    except WorkflowError as exc:
        payload = {"ok": False, "blocked_at": exc.stage, "reason": exc.reason,
                   "rc": exc.rc, "enforcement_scope": ENFORCEMENT_SCOPE,
                   "globally_enforced": False}
        payload.update(exc.extra)
        print(json.dumps(M.scrub(payload), ensure_ascii=False, indent=2))
        return exc.rc
    except (M.ManagerError, OSError, ValueError, KeyError, TypeError) as exc:
        reason = str(exc) if isinstance(exc, M.ManagerError) else type(exc).__name__
        print(json.dumps({"ok": False, "blocked_at": getattr(a, "cmd", "args"),
                          "reason": reason, "rc": 2}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
