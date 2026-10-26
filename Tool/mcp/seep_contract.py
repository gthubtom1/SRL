#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""seep_contract.py —— 结果契约层（预算 / 空态 / 证据筛选 / 报告模板）。

从 `seep_mcp_server.py` 拆出来的**纯函数模块**：无 IO、无全局状态、不注册任何工具。
拆的理由只有一条：主服务单文件行数预算 ≤3200（`MANUAL/BASELINE-FREEZE.md` §7），
而 S2 要求「超限拒绝不截断 + 报告无证据则拒绝」，这些判据必须进代码。

三个出口（都不返回"削过的证据"）：
  * `resource_constraint`  超预算 → {ok:false,error:"resource_constraint",bytes,continuation}
  * `empty_output`         零输出 / r2 报错 → {ok:false,error:"empty_output"}
  * `page_footer`          用户显式分页 → 返回 [PAGE] 续读指针（不是静默截断）
"""
from __future__ import annotations

import json
import os
import re

RESULT_BUDGET_BYTES = 64 * 1024
RESULT_BUDGET_CHARS = 8000
REPORT_PLACEHOLDER_BRANCH = {"", "0x0", "0x00000000", "0", "none", "null",
                             "unknown", "tbd", "todo", "?", "-"}
STRONG_CONFIDENCE = ("observed", "derived")

# 报告五段（与 `Tool/scripts/case_state.py::SECTIONS` **同一份口径**）。
# 为什么写在这里：`seep_gen_security_report` 的产物必须能过
# `python Tool/scripts/case_state.py report --check --file <产物>`，
# 段名各写一套就会出现「工具出的报告自己不合格」（第 4 轮评审 P1-5）。
REPORT_SECTIONS = ("结论", "已确认", "仍未知", "下一步", "复查")
REPORT_SECTIONS_JOINED = " / ".join(REPORT_SECTIONS)


def byte_len(payload: str) -> int:
    return len((payload or "").encode("utf-8", "replace"))


def resource_constraint(tool: str, payload: str, continuation: str,
                        artifact_hint: str = "") -> str:
    """超预算的唯一出口：结构化拒绝 + 续读方式。"""
    return json.dumps({
        "ok": False, "error": "resource_constraint", "blocked_at": tool,
        "bytes": byte_len(payload), "chars": len(payload or ""),
        "budget_bytes": RESULT_BUDGET_BYTES, "budget_chars": RESULT_BUDGET_CHARS,
        "continuation": continuation,
        "artifact_hint": artifact_hint or "输出未截断：缩小 target / 换 output_mode / 用 offset 分页后重读",
    }, ensure_ascii=False, indent=2)


def budget_gate(tool: str, payload: str, continuation: str, budget_chars: int = 0) -> str:
    """在预算内原样返回；超限返回 resource_constraint（绝不截断）。"""
    if byte_len(payload) > RESULT_BUDGET_BYTES:
        return resource_constraint(tool, payload, continuation)
    if budget_chars and budget_chars > 0 and len(payload) > budget_chars:
        return resource_constraint(tool, payload, continuation)
    return payload


def empty_output(tool: str, hint: str = "") -> str:
    """空输出不是成功（旧实现回 "[Success, no output]"，等于把"没测到"签成"跑完了"）。"""
    return json.dumps({
        "ok": False, "error": "empty_output", "blocked_at": tool,
        "hint": hint or "命令跑完了但零输出：先确认 target / 命令拼写，不要当成功处理",
    }, ensure_ascii=False, indent=2)


def is_err_payload(payload: str) -> str:
    """r2 把错误打到 stdout（如 "ERROR: Invalid tmpseek address 'main'"）：当空态，别冒充结果。"""
    for line in (payload or "").splitlines():
        t = line.strip()
        if t:
            return t if t.lower().startswith(("error", "fatal", "cannot")) else ""
    return ""


def page_footer(shown: int, total: int, tool: str, howto: str) -> str:
    """分页脚注：不是"被削的证据"，是明确的续读指针。"""
    return "[PAGE] 本次返回 %d / %d 条 —— 续读方式：%s（%s）" % (shown, total, howto, tool)


def case_evidence_dir(task_name: str, case_dir: str, task_dir_fn, case_lib_dir_fn) -> str:
    """定位本案证据目录：显式 case_dir → 工作区任务目录 → Tool/cases/<task>。"""
    cands = [os.path.abspath(case_dir.strip())] if (case_dir or "").strip() else []
    for fn in (lambda: task_dir_fn(task_name),
               lambda: os.path.join(case_lib_dir_fn(),
                                    re.sub(r'[^\w\-]', '_', (task_name or "").strip()))):
        try:
            cands.append(fn())
        except Exception:
            pass
    for c in cands:
        if c and os.path.isfile(os.path.join(c, "facts.jsonl")):
            return c
    return ""


def strong_claim_ids(case_dir: str) -> list:
    """报告的**唯一**证据来源：status=proven + confidence∈{observed,derived} + 非空 evidence。"""
    out = []
    try:
        with open(os.path.join(case_dir, "facts.jsonl"), "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                if not isinstance(o, dict):
                    continue
                if str(o.get("kind") or "claim").strip().lower() not in ("", "claim"):
                    continue
                if str(o.get("status") or "").strip().lower() != "proven":
                    continue
                if str(o.get("confidence") or "").strip().lower() not in STRONG_CONFIDENCE:
                    continue
                if any(str(e).strip() for e in (o.get("evidence") or [])):
                    out.append(str(o.get("id") or "?"))
    except Exception:
        return []
    return out


def missing_report_fields(task_name: str, target_name: str, description: str,
                          poc_summary: str, branch_location: str) -> list:
    """报告必填判据：占位值不算填了。"""
    miss = [n for n, v in (("task_name", task_name), ("target_name", target_name),
                           ("description", description), ("poc_summary", poc_summary))
            if not (v or "").strip()]
    if (branch_location or "").strip().lower() in REPORT_PLACEHOLDER_BRANCH:
        miss.append("branch_location")
    return miss


def build_report_md(task_name: str, target_name: str, vuln_type: str, branch_location: str,
                    description: str, poc_summary: str, defense_recommendation: str,
                    disasm_snippet: str, evidence_dir: str, strong: list, now_str: str) -> str:
    """报告正文：**五段**（结论 / 已确认 / 仍未知 / 下一步 / 复查），没有的东西写“未提供”。

    为什么是这五段：交付物只有一种格式。本函数出的 `.md` 必须能过
    `case_state.py report --check --file <产物>`（五段齐全 + 每段 ≥2 行 + 结论 ≤3 行 +
    已确认带 E-/C-/F- ID + 无禁用措辞）；旧版是另一套 6 段技术报告，客户拿到的两份
    交付物格式对不上（第 4 轮评审 P1-5）。

    保留的限制（不许煊）：本函数是**纯函数**（不读文件）——所以“复查”段给的是
    `recheck` 现算命令，不把哈希写死；反汇编/防御建议缺了就说缺了，绝不编造指令。
    """
    evdir = (evidence_dir or "").strip() or "<案例目录>"
    evfile = os.path.join(evdir, "facts.jsonl") if evdir != "<案例目录>" else "<案例目录>/facts.jsonl"
    ids = [str(i) for i in (strong or [])]

    remediation = (defense_recommendation or "").strip()
    used_generic = not remediation
    if used_generic:
        remediation = (
            "1. **服务端统一鉴权**：核心特权逻辑上云，客户端只做渲染；受限资源由服务端签发"
            "带时间戳与签名的凭据。\n"
            "2. **非对称签名防篡改**：离线场景用 RSA/ECC，客户端只留公钥验签，私钥在授权服务器。\n"
            "3. **内存完整性保护**：启用 `ProcessDynamicCodePolicy` 抑制动态内存写入，"
            "核心模块加代码段自校验哈希。")

    dis = (disasm_snippet or "").strip()
    disasm_block = ("```text\n%s\n```" % dis) if dis else (
        "（未提供反汇编摘录：本段不编造指令。用 r2/IDA 取到真实分支后再补 `disasm_snippet`。）")
    generic_note = "" if not used_generic else (
        chr(10) + "> 注：本节为通用加固建议，**未针对本目标逐条验证**。")

    # “仍未知”的输入侧缺口（与 missing_report_fields 分开：那四个字段缺了就不该出报告；
    # 这里只列「不出报告也能交、但必须在正文里承认没取」的部分）。
    unknown_input = []
    if not dis:
        unknown_input.append("反汇编摘录 `disasm_snippet`")
    if used_generic:
        unknown_input.append("针对本目标的防御建议 `defense_recommendation`（本节退化为通用建议，"
                             "**未逐条验证**）")
    if (branch_location or "").strip().lower() in REPORT_PLACEHOLDER_BRANCH:
        unknown_input.append("判定位点 `branch_location`（占位值，未取到真实位点）")
    unknown_txt = "、".join(unknown_input) if unknown_input else "必填字段之外无缺口（边界声明仍见下两行）"

    evidence_lines = "\n".join("- `%s`（proven / observed 或 derived / 带非空 evidence）" % i
                               for i in ids) or (
        "- （无强证据：本报告不该存在——先跑 `case_state.py verify --case %s`）" % evdir)

    return f"""# 软件安全评估与鉴权脆弱性走查报告

- **目标资产**: `{target_name}`
- **评估类型**: 白盒代码走查 / 客户端决策逻辑安全性验证
- **缺陷分类**: `{vuln_type}`
- **评估时间**: {now_str}
- **报告归属**: `{task_name}/reports/`
- **证据来源**: `{evfile}`

## 1 结论

- 已确认（可交付）：{len(ids)} 条结论，全部来自 facts.jsonl 的 proven + confidence 属 observed/derived + 非空 evidence；ID 逐条列在「已确认」段。
- 未确认（不得当结论）：本报告之外的一切都**未验证**，具体缺口逐条列在「仍未知」段。

## 2 已确认

- **目标资产**: `{target_name}`（归档于 `{task_name}/reports/`）
- **缺陷分类**: `{vuln_type}`；**判定函数 / 偏移位点**: `{branch_location}`
- **成因与影响**: {description}
- **PoC 与复现过程**: {poc_summary}
- **汇编指令与分支模式**:
{disasm_block}
- **证据明细（每一行都能在 `{evfile}` 找到对应 id；找不到即为无证据陈述）**:
{evidence_lines}

## 3 仍未知

- 输入侧未取（本次未取，**不代表不存在**）：{unknown_txt}
- 账本侧未证：facts.jsonl 里 status 不等于 proven、或 confidence 为 inferred/unknown 的条目全部不算结论。
- 覆盖边界：只覆盖「已确认」段这 {len(ids)} 条 ID；其他目标、其他版本、其他平台都未验证。

## 4 下一步

- 省事（先把账本补齐）：对每条缺口用 `python Tool/scripts/case_state.py claim --case {evdir} --id <新ID> --text "<实测结论>" --status proven --evidence "<实测输出>" --confidence observed --authority shipped-artifact` 落账，再重出报告。
- 彻底（补实测）：把 `{target_name}` 的其余判定位点用 r2/IDA 逐个取到反汇编、逐个跑通 PoC，让 `verify` 从 partial 走到 pass。
- 加固（纵深防护，随报告一起交）：
{remediation}{generic_note}

## 5 怎么复查

- 五段 + ID 对账：`python Tool/scripts/case_state.py report --check --file <本报告> --case {evdir}`
- 证据链：`python Tool/scripts/case_state.py verify --case {evdir}` —— 返回 `pass` 才算证据链完整；`fail` / `unknown` 时本报告不得作为交付依据。
- 接着做：`python Tool/scripts/case_state.py resume --case {evdir}`
- 目标哈希：`python Tool/scripts/case_state.py recheck --case {evdir}` 现算（本报告不写死哈希：换了 target 就必须重算）。
"""


# ── D1 · 工具效果登记审计（缺登记 → server 起不来）────────────────────────────
class MissingEffectAudit(RuntimeError):
    """有工具没在 tool-effects.json 登记：拒绝启动，而不是静默多给一个无标注的能力。"""


EFFECT_FIELDS = ("mutates_target", "writes_filesystem", "executes_foreign_code",
                 "touches_network", "may_discard_data")


def audit_tool_effects(tool_names, config_path):
    """比对 @server.tool() 集合与登记表；不一致抛 MissingEffectAudit。

    返回 name → annotations（MCP 语义：只读/破坏性/联网），供上层按需派生。
    """
    with open(config_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    reg = doc.get("tools") or {}
    live, dead = set(tool_names), set(reg)
    missing, extra = sorted(live - dead), sorted(dead - live)
    bad_field = [n for n, e in reg.items()
                 if not isinstance(e, dict) or set(e) != set(EFFECT_FIELDS)]
    if missing or extra or bad_field:
        raise MissingEffectAudit(
            "tool-effects.json 与 @server.tool() 不一致 —— missing=%s extra=%s 字段不合规=%s"
            % (missing, extra, bad_field))
    ann = {}
    for name, e in reg.items():
        ann[name] = {
            "readOnlyHint": not (e["writes_filesystem"] or e["mutates_target"]
                                 or e["may_discard_data"]),
            "destructiveHint": bool(e["mutates_target"] or e["may_discard_data"]),
            "openWorldHint": bool(e["touches_network"]),
        }
    return ann
