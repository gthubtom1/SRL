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
    """报告正文。没有的东西写"未提供"，**绝不编造指令**。"""
    remediation = (defense_recommendation or "").strip()
    tag = "" if remediation else "\n\n> 注：本节为通用加固建议，**未针对本目标逐条验证**。\n"
    if not remediation:
        remediation = (
            "1. **服务端统一鉴权**：核心特权逻辑上云，客户端只做渲染；受限资源由服务端签发带时间戳与签名的 Token。\n"
            "2. **非对称签名防篡改**：离线场景用 RSA/ECC，客户端只留公钥验签，私钥在授权服务器。\n"
            "3. **内存完整性保护**：启用 `ProcessDynamicCodePolicy` 抑制动态内存写入，核心模块加代码段自校验哈希。")
    dis = (disasm_snippet or "").strip()
    disasm_section = ("```text\n%s\n```" % dis) if dis else \
        "（未提供反汇编摘录：本节不编造指令。用 r2/IDA 取到真实分支后再补 `disasm_snippet`。）"
    evidence_lines = "\n".join("- `%s`（proven / observed 或 derived / 带非空 evidence）" % i
                               for i in strong)
    return f"""# 软件安全评估与鉴权脆弱性走查报告

- **目标资产**: `{target_name}`
- **评估类型**: 白盒代码走查 / 客户端决策逻辑安全性验证
- **缺陷分类**: `{vuln_type}`
- **评估时间**: {now_str}
- **报告归属**: `{task_name}/reports/`
- **证据来源**: `{os.path.join(evidence_dir, "facts.jsonl")}`

## 0. 证据清单 (Evidence Ledger)

{evidence_lines}

> 报告中"已验证"的每一条结论都必须能在上面找到对应 id；找不到即为无证据陈述。

## 1. 风险概述与脆弱性成因
{description}

## 2. 关键判定决策位点
- **判定函数 / 偏移位点**: `{branch_location}`
- **汇编指令与分支模式**:
{disasm_section}

## 3. 验证 PoC 与复现过程
{poc_summary}

## 4. 纵深防护与加固建议
{remediation}{tag}

## 5. 复现指令

```bash
python Tool/scripts/case_state.py verify --case {evidence_dir or '<案例目录>'}
```

`verify` 返回 `pass` 才算本报告的证据链完整；返回 `fail` / `unknown` 时本报告不得作为交付依据。
"""
