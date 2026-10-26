#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Seep 工作台 —— 合规规则表提取器 (extract-rules.py)

单一真值源策略：词表**唯一事实源**已搬到 `Tool/config/input-normalize.json`
（`from→to` 给中继做合规改写，`route_terms` 给路由做同义扩写）。本脚本单向提取
`from/to` 生成 sensitive-rules.json 供 compliance-relay 中继读取，**不重复维护第二份**。

回退：JSON 读不到 / 结构不对时，才解析 `security-audit-interceptor.ts` 里的
`FALLBACK_WORD_MAP` 字面量（那是扩展在 JSON 坏掉时的内嵌兜底表），并在 stderr 打 WARN——
不允许静默产出一份来路不明的规则表。

用法:
    python extract-rules.py            # 提取并写入 sensitive-rules.json
    python extract-rules.py --check    # 仅校验现有 JSON 是否与词表源一致（CI 用）
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
TS_SOURCE = os.path.join(
    REPO_ROOT, "Tool", "prompts", "extensions", "security-audit-interceptor.ts"
)
NORMALIZE_SOURCE = os.path.join(REPO_ROOT, "Tool", "config", "input-normalize.json")
NORMALIZE_SCHEMA = "seep.input-normalize/1"
OUTPUT = os.path.join(HERE, "sensitive-rules.json")

MIN_RULES = 30

# 匹配形如:  [/破解/g, "白盒鉴权脆弱性测试"],
RULE_LINE = re.compile(
    r"""\[\s*/(?P<pattern>(?:\\.|[^/\\])*)/[a-z]*\s*,\s*"(?P<replacement>(?:\\.|[^"\\])*)"\s*\]""",
    re.VERBOSE,
)

# 匹配回退表形态:  ["破解", "白盒鉴权脆弱性测试"],
FALLBACK_LINE = re.compile(
    r"""\[\s*"(?P<src>(?:\\.|[^"\\])*)"\s*,\s*"(?P<dst>(?:\\.|[^"\\])*)"\s*\]""",
    re.VERBOSE,
)
FALLBACK_NAME = "FALLBACK_WORD_MAP"

TS_STRING_ESCAPES = {
    "\\n": "\n",
    "\\t": "\t",
    "\\r": "\r",
    '\\"': '"',
    "\\'": "'",
    "\\\\": "\\",
}


def _unescape_ts_string(value: str) -> str:
    """还原 TS 字符串字面量中的转义序列。"""
    out = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            pair = value[i : i + 2]
            if pair in TS_STRING_ESCAPES:
                out.append(TS_STRING_ESCAPES[pair])
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _unescape_regex_pattern(pattern: str) -> str:
    """还原正则字面量中的转义：\\/ -> /，\\\\ -> \\，其余保持字面。"""
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            if nxt == "/":
                out.append("/")
                i += 2
                continue
            if nxt == "\\":
                out.append("\\")
                i += 2
                continue
            # 保留其他转义（虽然当前规则表未使用元字符，稳妥起见不丢信息）
            out.append(ch)
            out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def extract_rules_from_json(path: str = NORMALIZE_SOURCE) -> list[dict]:
    """从词表唯一事实源 input-normalize.json 提取 from→to。"""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"未找到词表源文件: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    schema = str(doc.get("schema") or "")
    if schema != NORMALIZE_SCHEMA:
        raise ValueError(f"词表 schema={schema!r} ≠ {NORMALIZE_SCHEMA!r}")
    raw = doc.get("pairs")
    if not isinstance(raw, list) or not raw:
        raise ValueError("词表 pairs 为空或不是数组")
    rules: list[dict] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        src = str(item.get("from") or "")
        dst = str(item.get("to") or "")
        if not src or src in seen:
            continue
        seen.add(src)
        rules.append({"from": src, "to": dst})
    return rules


def extract_rules_from_ts(ts_path: str = TS_SOURCE) -> list[dict]:
    """回退：从 TS 内嵌字面量提取（旧 SENSITIVE_WORD_MAP 或新 FALLBACK_WORD_MAP）。"""
    if not os.path.isfile(ts_path):
        raise FileNotFoundError(f"未找到 TS 规则源文件: {ts_path}")

    with open(ts_path, "r", encoding="utf-8") as fh:
        source = fh.read()

    # 1) 新形态：回退表 [[from, to], …]
    anchor = source.find(FALLBACK_NAME)
    if anchor >= 0:
        start = source.find("[", anchor)
        end = source.find("];", start) if start >= 0 else -1
        if start >= 0 and end > start:
            block = source[start:end]
            rules, seen = [], set()
            for match in FALLBACK_LINE.finditer(block):
                src = _unescape_ts_string(match.group("src"))
                dst = _unescape_ts_string(match.group("dst"))
                if not src or src in seen:
                    continue
                seen.add(src)
                rules.append({"from": src, "to": dst})
            if rules:
                return rules

    # 2) 旧形态：SENSITIVE_WORD_MAP = [[/from/g, "to"], …]
    start = source.find("SENSITIVE_WORD_MAP")
    if start == -1:
        raise ValueError("TS 源文件中既未找到 %s，也未找到 SENSITIVE_WORD_MAP" % FALLBACK_NAME)
    end = source.find("];", start)
    if end == -1:
        raise ValueError("TS 源文件中 SENSITIVE_WORD_MAP 数组未正常闭合")

    block = source[start:end]

    rules: list[dict] = []
    seen: set[str] = set()
    for match in RULE_LINE.finditer(block):
        pattern = _unescape_regex_pattern(match.group("pattern"))
        replacement = _unescape_ts_string(match.group("replacement"))
        if not pattern:
            continue
        if pattern in seen:
            continue
        seen.add(pattern)
        rules.append({"from": pattern, "to": replacement})

    return rules


def extract_rules(ts_path: str = TS_SOURCE, normalize_path: str = NORMALIZE_SOURCE) -> list[dict]:
    """优先从 JSON 词表提取；不可用时才退回 TS 内嵌表（并在 stderr 明说）。"""
    try:
        return extract_rules_from_json(normalize_path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"[WARN] 词表 JSON 不可用（{exc}），退回 TS 内嵌表", file=sys.stderr)
        return extract_rules_from_ts(ts_path)


def validate(rules: list[dict]) -> list[str]:
    """返回错误列表，空列表表示校验通过。"""
    errors: list[str] = []
    if len(rules) < MIN_RULES:
        errors.append(
            f"规则数量不足: 提取到 {len(rules)} 条，至少需要 {MIN_RULES} 条"
        )
    seen: set[str] = set()
    for idx, rule in enumerate(rules):
        src = rule.get("from", "")
        dst = rule.get("to", "")
        if not src:
            errors.append(f"第 {idx} 条规则的 from 为空")
        if not dst:
            errors.append(f"第 {idx} 条规则的 to 为空 (from={src!r})")
        if src in seen:
            errors.append(f"规则 from 重复: {src!r}")
        seen.add(src)
    return errors


def build_payload(rules: list[dict]) -> dict:
    """构造输出载荷（不含时间戳，避免无意义 diff）。"""
    rel_source = os.path.relpath(NORMALIZE_SOURCE, REPO_ROOT).replace("\\", "/")
    return {
        "schema": 1,
        "generatedFrom": rel_source,
        "_comment": "本文件由 extract-rules.py 自动生成，请勿手工编辑；请修改 Tool/config/input-normalize.json（词表唯一事实源）后重新提取。",
        "ruleCount": len(rules),
        "rules": rules,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="从 TS 扩展提取合规规则表")
    parser.add_argument(
        "--check",
        action="store_true",
        help="仅校验现有 sensitive-rules.json 是否与 TS 源一致",
    )
    args = parser.parse_args()

    try:
        rules = extract_rules()
    except (FileNotFoundError, ValueError) as exc:
        print(f"[FAIL] 规则提取失败: {exc}", file=sys.stderr)
        return 1

    errors = validate(rules)
    if errors:
        print("[FAIL] 规则校验未通过:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    payload = build_payload(rules)
    serialized = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"

    if args.check:
        if not os.path.isfile(OUTPUT):
            print(f"[FAIL] 未找到 {OUTPUT}，请先运行 extract-rules.py", file=sys.stderr)
            return 1
        with open(OUTPUT, "r", encoding="utf-8") as fh:
            current = fh.read()
        if current != serialized:
            print(
                "[FAIL] sensitive-rules.json 与 TS 源不一致，请重新运行 extract-rules.py",
                file=sys.stderr,
            )
            return 1
        print(f"[OK] 规则表已同步，共 {len(rules)} 条")
        return 0

    with open(OUTPUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(serialized)
    print(f"[OK] 已生成 {OUTPUT}")
    print(f"     规则条数: {len(rules)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
