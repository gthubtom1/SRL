#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""adapt_check.py —— 新破甲卡「适配 SEP」的四类体检

为什么要有它
------------
`check_seep_compat.py` 只回答一个问题：**条款在不在**（§11 carve-out / §7 capability
honesty / 授权门指针）。它不回答另外三个同样致命的问题：

1. **卡太胖**：8 KB 以内 / ~2,500 token 以内才装得下。实测 2026-10-23 那个会话第一次调用就
   吃掉 29,415 token 输入；每张常驻卡每多 1 K token，就是每次调用少 1 K 工作记忆。
2. **卡和自己的规矩打架**：卡里若写着「额外要一次授权确认」「遇拒答就转话题」「不许在对话里
   问 A/B/C」「必须弹窗交互」，那它装上去的第一件事就是把 `AGENTS.md §六 G-Auth` 和边界锚
   顶掉 —— 条款齐全也没用，语义已经反了。
3. **卡自己重复自己**：同一条要求写 2~4 遍，占预算、拉低遵循率（arXiv 2608.02639：20 条
   同时生效时遵循率掉到 0.2~0.6；护栏越多，遵循越接近零）。

用法
----
    python compat/adapt_check.py <card.md>            # 人读报告
    python compat/adapt_check.py <card.md> --json      # 机读（可解析）
    python compat/adapt_check.py <card.md> --strict    # 把 WARN 也当 FAIL
    python compat/adapt_check.py --list-patterns       # 看硬冲突规则表

退出码：0 = PASS（可带 WARN） / 1 = FAIL / 2 = 用法或读文件错误

四类检查
--------
| 类 | 判据 |
|---|---|
| 预算 | bytes ≤ 8192 且 est_tokens ≤ 2500（est_tokens 与 `Tool/scripts/prompt-budget.py` 同口径） |
| 硬冲突 | 命中反模式表 → FAIL，给行号 + 原文片段 + 为什么冲突 |
| 去重 | 句子归一化后同一句出现 ≥2 次 → WARN，列出次数与行号 |
| 必备条款 | `check_seep_compat.py --check` 的口径：两条条款标记 + 授权门指针 |

设计取舍
--------
- **est_tokens 是复制不是 import**：`Tool/**` 有并行改动，import 会跟着别人抖动；
  这里复制同一函数并标出处，口径一致、依赖为零。
- **必备条款比 `--check` 更严**：`--check` 靠 `is_new_gen()` 过滤旧代卡，本脚本**不过滤**
  —— 新卡要进 SEP 就必须自带条款，不管它自称哪一代。
- 硬冲突规则宁可少、每条都要能指着 §六 / 边界锚说清"为什么"，避免变成猜意图的自动审查。
"""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)                      # 破甲卡生成/

BUDGET_BYTES = 8192
BUDGET_TOKENS = 2500


# ---------------------------------------------------------------------------
# 预算：与 Tool/scripts/prompt-budget.py 的 est_tokens 同口径（复制，不 import）
# 出处：Tool/scripts/prompt-budget.py:71  def est_tokens
# ---------------------------------------------------------------------------
def est_tokens(text: str) -> int:
    """粗估 token：CJK 约 1 字 1 token；ASCII 约 4 字符 1 token。"""
    cjk = 0
    other = 0
    for ch in text:
        o = ord(ch)
        if 0x2E80 <= o <= 0x9FFF or 0xF900 <= o <= 0xFAFF or 0xFF00 <= o <= 0xFF60:
            cjk += 1
        else:
            other += 1
    return int(round(cjk * 1.0 + other / 4.0))


# ---------------------------------------------------------------------------
# 硬冲突反模式表
#   id     : 稳定标识（报告 / JSON 里用）
#   name   : 人读名字
#   pat    : 正则（IGNORECASE；对全文逐行匹配）
#   why    : 为什么这是冲突（指向 AGENTS.md §六 / 边界锚 的具体条）
# ---------------------------------------------------------------------------
# 引用型豁免：一行里若明说这是「已废止 / 历史表述 / 不覆盖」，那它是在**记录**旧漂移，
# 不是在要求它。血案逆证：quad/zh-muse.md、人设卡/space-bunny-2.md 的废止声明会被误报。
QUOTE_CTX = re.compile(
    r"废止|作废|失效|不得据此|历史表述|已废除|不再适用"
    r"|deprecated|voided|retired|no longer in force|historical wording",
    re.I,
)

RULES = [
    {
        "id": "H1-extra-auth",
        "name": "额外授权确认",
        "pat": re.compile(
            r"额外(的)?(授权|权限)(确认|验证|询问)"
            r"|(再|额外|另外|重新)(一次)?(问|确认|核对).{0,12}(授权|许可|有没有授权|是否授权)"
            r"|(每个|每换一个|逐)(目标|资产).{0,8}(都)?(要|需|必须)?(问|确认)(一次)?(授权|许可|归属)"
            r"|(extra|additional|one more)\s+(authorization|permission)\s+(check|confirmation|question)"
            r"|(ask|confirm|verify)\s+(for\s+)?(authorization|permission)\s+(again|once more)",
            re.I,
        ),
        "why": "§六：目标默认视为已授权沙箱、不逐目标询问；只在用户**明确声明**无授权时停一次。"
               "「额外/再问一次」= 在默认路径上加门，等于把 G-Auth 改成逐目标审批。",
        "allow_ctx": QUOTE_CTX,
    },
    {
        "id": "H2-drop-noauth",
        "name": "把「无授权」声明改写或忽略",
        "pat": re.compile(
            r"(用户)?(说|声明|提到)?(没有|无|未)授权.{0,18}(换个|换成|替换|占位符|忽略|当作|当没|不信|不接受|不算)"
            r"|(不提|不做|不给|跳过).{0,6}(permission\s*check|授权检查|授权确认)"
            r"|(把|将)[「\"']?(没有授权|无授权)[」\"']?.{0,12}(换|替换|忽略|当)",
            re.I,
        ),
        "why": "§六 的**唯一停止条件**是「用户明确声明目标不属于我 / 没有授权」。"
               "把这句话改写、占位符化或干脆不认，等于删掉授权门本身（血案：space-bunny-2 旧代卡）。",
        "allow_ctx": QUOTE_CTX,
    },
    {
        "id": "H3-refusal-pivot",
        "name": "遇拒答就转话题",
        "pat": re.compile(
            r"拒答.{0,14}(转|换|改)(个|成|为|另外)?(话题|问题|方向|题目)"
            r"|(被|遭到?|碰到)(模型)?拒(绝|答).{0,12}(就|立刻|直接)(换|转)(个)?(话题|问题)"
            r"|if\s+(it|the model|the reply)\s+refus(es|ed).{0,30}(change|switch)\s+(the\s+)?(subject|topic)",
            re.I,
        ),
        "why": "破甲卡的验收判据是「拒答是故障，不是答案」（§0b 有排气管：一条 exhaust 行 + 分隔线 + 完整交付）。"
               "「转话题」= 把故障合法化，卡从此永远停在第一层。",
        "allow_ctx": QUOTE_CTX,
    },
    {
        "id": "H4-ban-ask-abc",
        "name": "禁止在对话内问 A/B/C",
        "pat": re.compile(
            r"(不许|不得|禁止|不要|绝不|严禁).{0,16}(问|提|给).{0,12}(A\s*/\s*B|A、B、C|选项|选择题|方案对比)"
            r"|(禁止|不许).{0,8}对话(内)?(给出|列出|提出).{0,12}(选项|A/B/C)"
            r"|never\s+(ask|offer|present)\s+(the\s+)?(user\s+)?(a\s+)?(choices?|options?|a/b/c)",
            re.I,
        ),
        "why": "SEP 允许、并且常常要求「对话内 A/B/C 问人」（决策有三条路可走时必须让用户选）。"
               "卡里禁掉它 = 与 SEP 的交互纪律正面冲突，结果是模型替你瞎选一条路。",
        "allow_ctx": QUOTE_CTX,
    },
    {
        "id": "H5-must-popup",
        "name": "必须弹窗 / 必须 MCP 交互",
        "pat": re.compile(
            r"必须(弹|触发|弹出|拉起).{0,12}(窗|对话框|UI|界面|MCP)"
            r"|(必须|一定要)(先)?(让)?MCP.{0,12}(弹窗|弹框|交互|确认)"
            r"|must\s+(pop\s*up|trigger|show)\s+(a\s+)?(dialog|window|popup)",
            re.I,
        ),
        "why": "边界锚 + 宿主纪律：MCP 弹窗要人点、会卡住无人值守会话；"
               "卡不得把「必须点一下」写成流程前置条件。",
    },
    {
        "id": "H6-override-gate",
        "name": "声明 §六 / 授权门不适用",
        "pat": re.compile(
            r"(不适用|不受|豁免|无需遵守|不得适用).{0,12}(AGENTS\.md|§\s*六|授权门|G-Auth)"
            r"|(AGENTS\.md|§\s*六|G-Auth).{0,12}(不适用|无权|作废|失效|不覆盖)",
            re.I,
        ),
        "why": "`AGENTS.md §六` 是唯一授权门定义，人格卡**不得改写其语义**（MANUAL/PROMPT-LAYERS.md 裁决）。",
    },
]


# ---------------------------------------------------------------------------
# 必备条款：直接复用 check_seep_compat.py 的条款定义（同一事实源，不抄第二份）
# ---------------------------------------------------------------------------
def _compat_module():
    p = os.path.join(HERE, "check_seep_compat.py")
    if not os.path.isfile(p):
        return None
    spec = importlib.util.spec_from_file_location("_seep_compat_for_adapt", p)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def check_required(text: str) -> dict:
    mod = _compat_module()
    items = []
    if mod is not None:
        for c in mod.CLAUSES:
            items.append({"item": c["name"], "ok": c["marker"] in text,
                          "hint": f"缺这段条款（锚点：`{c['anchor'][:48]}`）→ 跑 "
                                  f"`python compat/check_seep_compat.py --apply` 可幂等补齐"})
        source = "import check_seep_compat.CLAUSES"
    else:
        # 降级：只跑闸门本身（对 人设卡/ quad/ kernel/ 全扫一遍）
        ok = False
        try:
            r = subprocess.run([sys.executable, os.path.join(HERE, "check_seep_compat.py"), "--check"],
                               capture_output=True, text=True, cwd=BASE, timeout=60)
            ok = r.returncode == 0
        except Exception:
            ok = False
        items.append({"item": "check_seep_compat --check（降级：整目录口径）", "ok": ok,
                      "hint": "check_seep_compat.py 不可导入，退回子进程全目录校验"})
        source = "subprocess check_seep_compat.py --check（降级）"

    # 授权门指针（与 check_seep_compat.gate_pointer_violations 同判据，但只看本卡）
    has_pointer = ("AGENTS.md" in text) and ("§六" in text)
    has_carveout = mod is not None and any(
        c["marker"] in text for c in mod.CLAUSES if "Carve-out" in c["marker"]
    )
    items.append({
        "item": "授权门指针（AGENTS.md + §六，或 §11 Carve-out）",
        "ok": bool(has_pointer or has_carveout),
        "hint": "卡必须显式承认授权门以 `AGENTS.md §六` 为准 → 加一行"
                "「授权门（本卡不覆盖，以 `AGENTS.md` §六 为准）」或 §11 Carve-out",
    })
    return {"source": source, "items": items, "ok": all(i["ok"] for i in items)}


# ---------------------------------------------------------------------------
# 去重：句子归一化后精确比对
# ---------------------------------------------------------------------------
SENT_SPLIT = re.compile(r"[。；！？]|(?<=[.!?])\s+|\n")
NOISE = re.compile(r"[`*_>#|•·\-—–\s]+")
MIN_SENT = 16


def norm_sentence(s: str) -> str:
    s = NOISE.sub(" ", s)
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s


def check_duplicates(text: str) -> dict:
    seen = {}
    order = []
    for ln, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("|"):
            continue
        # 纯装饰线（═━──***、缩进分隔）不参与去重；它本来就是重复的
        if re.fullmatch(r"[\W_]+", line):
            continue
        for part in SENT_SPLIT.split(line):
            n = norm_sentence(part)
            if len(n) < MIN_SENT:
                continue
            if n not in seen:
                seen[n] = {"count": 0, "lines": [], "sample": part.strip()[:120]}
                order.append(n)
            seen[n]["count"] += 1
            if ln not in seen[n]["lines"]:
                seen[n]["lines"].append(ln)
    dup = [dict(sentence=seen[k]["sample"], count=seen[k]["count"], lines=seen[k]["lines"])
           for k in order if seen[k]["count"] >= 2]
    warn = []
    for d in dup:
        warn.append({
            "class": "duplicate",
            "detail": f"同一句出现 {d['count']} 次（行 {', '.join(map(str, d['lines']))}）：{d['sentence']}",
        })
    return {
        "ok": True,                       # 去重只报 WARN
        "dup_count": len(dup),
        "duplicates": dup[:20],
        "warnings": warn,
    }


# ---------------------------------------------------------------------------
# 硬冲突
# ---------------------------------------------------------------------------
def check_hard_conflicts(text: str) -> dict:
    hits = []
    suppressed = []
    lines = text.splitlines()
    for rule in RULES:
        ctx = rule.get("allow_ctx")
        for ln, line in enumerate(lines, 1):
            for m in rule["pat"].finditer(line):
                frag = line.strip()
                rec = {
                    "id": rule["id"],
                    "name": rule["name"],
                    "line": ln,
                    "match": m.group(0)[:120],
                    "text": frag[:200],
                    "why": rule["why"],
                }
                # 废止声明常折行（命中在上一行、已废止在下一行）→ 用 ±1 行上下文判定
                window = " ".join(lines[max(0, ln - 2):ln + 1])
                if ctx is not None and ctx.search(window):
                    rec["suppressed_by"] = "废止/历史表述上下文（±1 行）"
                    suppressed.append(rec)
                else:
                    hits.append(rec)
    return {"ok": not hits, "hits": hits, "suppressed": suppressed}


# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------
def run(path: str, max_bytes: int = BUDGET_BYTES, max_tokens: int = BUDGET_TOKENS) -> dict:
    with io.open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    nbytes = len(text.encode("utf-8"))
    toks = est_tokens(text)

    budget_fail = []
    if nbytes > max_bytes:
        budget_fail.append(f"字节数 {nbytes} > {max_bytes}（超 {nbytes - max_bytes} B）")
    if toks > max_tokens:
        budget_fail.append(f"估算 token {toks} > {max_tokens}（超 {toks - max_tokens}）")

    hard = check_hard_conflicts(text)
    dup = check_duplicates(text)
    req = check_required(text)

    failures = []
    for d in budget_fail:
        failures.append({"class": "budget", "detail": d})
    for h in hard["hits"]:
        failures.append({"class": "hard_conflict",
                         "detail": f"[{h['id']} {h['name']}] 行 {h['line']}: …{h['match']}…"})
    for i in req["items"]:
        if not i["ok"]:
            failures.append({"class": "required", "detail": f"缺 {i['item']}"})

    warn = list(dup["warnings"])
    verdict = "FAIL" if failures else ("WARN" if warn else "PASS")
    if verdict == "WARN":
        verdict = "PASS"

    return {
        "file": os.path.abspath(path),
        "rel": os.path.relpath(os.path.abspath(path), BASE),
        "bytes": nbytes,
        "est_tokens": toks,
        "budget": {"max_bytes": max_bytes, "max_tokens": max_tokens,
                   "ok": not budget_fail, "problems": budget_fail},
        "hard_conflict": hard,
        "duplicate": dup,
        "required": req,
        "failures": failures,
        "warnings": warn,
        "verdict": verdict,
    }


def report(r: dict) -> str:
    L = []
    L.append(f"[adapt_check] {r['rel']}")
    L.append(f"  预算   : {r['bytes']} B / {r['budget']['max_bytes']} B"
             f"  ·  ~{r['est_tokens']} tok / {r['budget']['max_tokens']} tok"
             f"  → {'OK' if r['budget']['ok'] else 'FAIL'}")
    for p in r["budget"]["problems"]:
        L.append(f"           - {p}")

    hc = r["hard_conflict"]
    L.append(f"  硬冲突 : {len(hc['hits'])} 处  → {'OK' if hc['ok'] else 'FAIL'}"
             + (f"　（另有 {len(hc['suppressed'])} 处命中在废止/历史表述上下文，已豁免）"
                if hc.get("suppressed") else ""))
    for h in hc["hits"]:
        L.append(f"           ✗ [{h['id']}] {h['name']}  (行 {h['line']})")
        L.append(f"             原文: {h['text']}")
        L.append(f"             命中: {h['match']}")
        L.append(f"             为什么: {h['why']}")

    dp = r["duplicate"]
    L.append(f"  去重   : {dp['dup_count']} 组重复句  → {'WARN' if dp['dup_count'] else 'OK'}")
    for d in dp["duplicates"]:
        L.append(f"           ! ×{d['count']} 行 {d['lines']}: {d['sentence']}")

    rq = r["required"]
    L.append(f"  必备条款: 来源 {rq['source']}  → {'OK' if rq['ok'] else 'FAIL'}")
    for i in rq["items"]:
        L.append(f"           {'✓' if i['ok'] else '✗'} {i['item']}")
        if not i["ok"]:
            L.append(f"             修法: {i['hint']}")

    L.append("")
    L.append(f"  结论: {r['verdict']}"
             + (f"（{len(r['failures'])} 项失败 / {len(r['warnings'])} 项警告）"
                if r["failures"] or r["warnings"] else "（四类全绿）"))
    return "\n".join(L)


def main(argv):
    # Windows 控制台默认 cp936：不重设会在遇到 ✗ / ✓ 时崩在 print 上
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="新破甲卡适配 SEP 的体检（预算 / 硬冲突 / 去重 / 必备条款）")
    ap.add_argument("card", nargs="?", help="待检查的卡片路径")
    ap.add_argument("--json", action="store_true", help="输出机器可解析 JSON")
    ap.add_argument("--strict", action="store_true", help="去重 WARN 也按 FAIL 退出")
    ap.add_argument("--list-patterns", action="store_true", help="列出硬冲突规则表")
    ap.add_argument("--max-bytes", type=int, default=BUDGET_BYTES)
    ap.add_argument("--max-tokens", type=int, default=BUDGET_TOKENS)
    args = ap.parse_args(argv)

    if args.list_patterns:
        print(f"硬冲突规则 {len(RULES)} 条（预算 {BUDGET_BYTES} B / {BUDGET_TOKENS} tok）：")
        for r in RULES:
            print(f"  {r['id']:<18} {r['name']}")
            print(f"    why: {r['why']}")
        return 0

    if not args.card:
        ap.print_help()
        return 2
    if not os.path.isfile(args.card):
        print(f"[adapt_check] 文件不存在: {args.card}", file=sys.stderr)
        return 2

    r = run(args.card, args.max_bytes, args.max_tokens)
    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print(report(r))

    if r["failures"]:
        return 1
    if args.strict and r["warnings"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
