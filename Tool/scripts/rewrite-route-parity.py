#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rewrite-route-parity.py —— 改写同域检查（R7 评审 P0-4）。

血案（审计点名未修）：
    客户的话在进模型之前会被 `Tool/prompts/extensions/security-audit-interceptor.ts`
    的 `SENSITIVE_WORD_MAP` 改写（「脱壳」→「内存转储与还原解包」、「破解」→
    「白盒鉴权脆弱性测试」…），但 39 条路由验收句（`Tool/config/skill-route-probes.json`）
    **只喂原文**给 `route.py`。于是门禁验的是"模型看到的话"，而线上模型看到的是
    "被改写后的话" —— 改写一旦把语义域带偏，就是**验收绿、线上错**。

本检查补的就是这一步：把每条验收句**先按同一张词表改写**，再跑同一个 `route.resolve()`，
断言「原文的 primary 域」与「改写后的 primary 域」完全相同。

三条不可妥协的纪律：
    1. 词表只从 .ts 现读（正则解析 `SENSITIVE_WORD_MAP`）。Python 里**不抄**一份 ——
       抄一份就是第二事实源，改 .ts 不改 Python 时会静默漂移。解析不到 → 判红并报
       "词表格式变了，本检查需同步"。
    2. 改写算法与 `buildSensitiveMatcher()` 一致：**单趟、最长优先、不回扫**
       （见 .ts 注释："替换产物不再参与匹配，杜绝 A→B、B→C 级联污染"）。
       逐条 `replace()` 会级联（「破解补丁」先撞「破解」），验的就不是线上行为了。
    3. 路由判据不许动：本脚本只调用 `route.resolve()`，不重写任何正则、不放宽任何阈值。

用法：
    python Tool/scripts/rewrite-route-parity.py            # 人读
    python Tool/scripts/rewrite-route-parity.py --json     # 机器可读（check.py 用这个）
    python Tool/scripts/rewrite-route-parity.py --verbose  # 逐条列出（含一致项）

退出码：0 = 词表解析成功 且 全部探针改写前后同域；1 = 有任一不一致 / 词表解析失败。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))            # 仓库根

INTERCEPTOR = os.path.join(ROOT, "Tool", "prompts", "extensions",
                           "security-audit-interceptor.ts")
PROBES = os.path.join(ROOT, "Tool", "config", "skill-route-probes.json")
MAP_NAME = "SENSITIVE_WORD_MAP"

# 词表两种可能写法（本文件必须能同时读）：
#   A 数组形态（当前）：[/脱壳/g, "内存转储与还原解包"],
#   B 对象字面量（若将来改成 Record）："脱壳": "内存转储与还原解包",
PAIR_ARRAY = re.compile(
    r"\[\s*/(?P<pat>(?:\\.|[^/\\])+)/(?P<flags>[a-z]*)\s*,\s*"
    r"(?:\"(?P<dq>(?:\\.|[^\"\\])*)\"|'(?P<sq>(?:\\.|[^'\\])*)')\s*\]",
    re.S)
PAIR_OBJ = re.compile(
    r"(?:\"(?P<k1>(?:\\.|[^\"\\])*)\"|'(?P<k2>(?:\\.|[^'\\])*)')\s*:\s*"
    r"(?:\"(?P<v1>(?:\\.|[^\"\\])*)\"|'(?P<v2>(?:\\.|[^'\\])*)')",
    re.S)
META_MARK = re.compile(r"\[\s*/")      # 用来数"数组里到底有多少条"，防止只解析出一半

_FMT_HINT = ("词表格式变了，本检查需同步：期望 %s 仍是"
             " `Array<[RegExp, string]>`（形如 `[/原词/g, \"改写词\"],`）"
             "或对象字面量（形如 `\"原词\": \"改写词\",`）" % MAP_NAME)


# --------------------------------------------------------------------------
# 从 .ts 里现读词表
# --------------------------------------------------------------------------
def _unescape_js_string(s):
    """只解 .ts 里会出现的转义（\\ \\" \\' \\n \\t \\uXXXX）；其余原样保留。"""
    out, i, n = [], 0, len(s)
    while i < n:
        ch = s[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = s[i + 1]
        if nxt == "n":
            out.append("\n")
        elif nxt == "t":
            out.append("\t")
        elif nxt == "r":
            out.append("\r")
        elif nxt == "u":
            try:
                out.append(chr(int(s[i + 2:i + 6], 16)))
                i += 6
                continue
            except ValueError:
                out.append("\\u")
        else:
            out.append(nxt)
        i += 2
    return "".join(out)


def _array_literal(src, name):
    """取出 `const <name> … = [ … ]` 的方括号内容（跳过字符串/正则/注释里的括号）。"""
    i = src.find(name)
    if i < 0:
        return None, "找不到 %s 定义" % name
    eq = src.find("=", i)
    if eq < 0:
        return None, "%s 后没有 `=`（定义形态变了）" % name
    # 数组形态 `= [ … ]` 与对象形态 `= { … }` 都收（只看 `=` 之后最先出现的那个括号）
    idx = [x for x in (src.find("[", eq), src.find("{", eq)) if x >= 0]
    if not idx:
        return None, "%s 后既没有数组 `[` 也没有对象 `{` 字面量" % name
    start = min(idx)
    depth, j, prev = 0, start, ""
    while j < len(src):
        ch = src[j]
        if ch in "\"'`":                                  # 字符串字面量
            q, j = ch, j + 1
            while j < len(src) and src[j] != q:
                j += 2 if src[j] == "\\" else 1
            prev = q
            j += 1
            continue
        if ch == "/" and j + 1 < len(src) and src[j + 1] in "/*":   # 注释
            if src[j + 1] == "/":
                j = src.find("\n", j)
                j = len(src) if j < 0 else j
            else:
                j = src.find("*/", j)
                j = len(src) if j < 0 else j + 2
            continue
        if ch == "/" and prev in "[,(=":                   # 正则字面量（[/脱壳/g）
            j += 1
            while j < len(src) and src[j] != "/":
                j += 2 if src[j] == "\\" else 1
            j += 1
            while j < len(src) and src[j].isalpha():       # flags
                j += 1
            prev = "/"
            continue
        if ch in "[{(":
            depth += 1
        elif ch in "]})":
            depth -= 1
            if depth == 0:
                return src[start:j + 1], ""
        if not ch.isspace():
            prev = ch
        j += 1
    return None, "%s 的数组字面量没闭合（括号不配对）" % name


def parse_word_map(ts_path):
    """返回 (pairs[(原词, 改写词)], problems[])。problems 非空 = 词表不可信。"""
    problems = []
    try:
        src = open(ts_path, encoding="utf-8", errors="replace").read()
    except OSError as e:
        return [], ["读不到 %s：%s" % (ts_path, str(e)[:60])]
    lit, err = _array_literal(src, MAP_NAME)
    if lit is None:
        return [], ["%s；%s" % (err, _FMT_HINT)]

    pairs = []
    for m in PAIR_ARRAY.finditer(lit):
        key = _unescape_js_string(m.group("pat"))
        val = _unescape_js_string(m.group("dq") if m.group("dq") is not None
                                  else m.group("sq"))
        pairs.append((key, val))
    if not pairs:                                          # 退回对象字面量形态
        for m in PAIR_OBJ.finditer(lit):
            key = _unescape_js_string(m.group("k1") if m.group("k1") is not None
                                      else m.group("k2"))
            val = _unescape_js_string(m.group("v1") if m.group("v1") is not None
                                      else m.group("v2"))
            pairs.append((key, val))

    if not pairs:
        return [], ["%s 里一条键值都没解析出来；%s" % (MAP_NAME, _FMT_HINT)]
    marked = len(META_MARK.findall(lit))
    if marked and marked != len(pairs):
        problems.append("%s 里有 %d 条、只解析出 %d 条；%s"
                        % (MAP_NAME, marked, len(pairs), _FMT_HINT))
    seen = {}
    for k, v in pairs:
        if not k:
            problems.append("%s 里有空键（格式可疑）；%s" % (MAP_NAME, _FMT_HINT))
            continue
        if k in seen and seen[k] != v:
            problems.append("%s 里键 %r 有两条不同改写词（%r / %r）"
                            % (MAP_NAME, k, seen[k], v))
        seen[k] = v
    return pairs, problems


# --------------------------------------------------------------------------
# 改写：与 buildSensitiveMatcher()/applySensitiveRewrite() 同算法
# --------------------------------------------------------------------------
def build_rewriter(pairs):
    """单趟最长优先；同键先到先得（对应 .ts 的 `if (!mapping.has(source))`）。"""
    mapping = {}
    for k, v in pairs:
        mapping.setdefault(k, v)
    keys = sorted(mapping, key=len, reverse=True)
    rx = re.compile("|".join(re.escape(k) for k in keys)) if keys else None
    return mapping, rx


def rewrite(text, mapping, rx):
    """返回 (改写后文本, [(原词, 改写词, 次数)])。

    对齐 .ts 的两个早退：以 `/` 开头的斜杠命令、空文本原样返回
    （探针里没有斜杠命令；这里仍照抄语义，免得将来加了探针后本检查变成假绿）。
    """
    text = str(text or "")
    if not text or rx is None or text.lstrip().startswith("/"):
        return text, []
    counters = {}

    def _sub(m):
        k = m.group(0)
        counters[k] = counters.get(k, 0) + 1
        return mapping[k]

    return rx.sub(_sub, text), [(k, mapping[k], c) for k, c in counters.items()]


# --------------------------------------------------------------------------
# 检查
# --------------------------------------------------------------------------
def primary_domain(route_mod, text):
    """primary = 优先级最高的**具体**域（兜底路由不算命中，与 route.py 口径一致）。"""
    hits = [h for h in route_mod.resolve(text) if not h.get("fallback")]
    return hits[0]["pack"] if hits else ""


def domain_set(route_mod, text):
    return sorted({h["pack"] for h in route_mod.resolve(text) if not h.get("fallback")})


def expected_domain(expect_skill):
    s = str(expect_skill or "").strip()
    return s.split("/")[0] if s else ""


def run(ts_path, probes_path):
    sys.path.insert(0, HERE)
    import route as route_mod                                # noqa: E402  唯一判据来源

    pairs, problems = parse_word_map(ts_path)
    mapping, rx = build_rewriter(pairs)

    try:
        doc = json.load(open(probes_path, encoding="utf-8"))
    except Exception as e:                                   # noqa: BLE001
        return {"ok": False, "problems": ["读不到探针文件 %s：%s" % (probes_path, str(e)[:60])],
                "probes": [], "inconsistencies": [], "allowed": [], "domain_set_changes": [],
                "expect_mismatch": [], "pairs": len(pairs),
                "rewrite": {"wordlist_parsed": bool(pairs), "pairs": len(pairs),
                            "keys": len(mapping)},
                "summary": {}, "interceptor": ts_path, "probes_file": probes_path}
    probes = doc.get("probes") if isinstance(doc, dict) else doc
    if not isinstance(probes, list) or not probes:
        problems.append("探针文件里没有 probes 数组（%s）" % os.path.basename(probes_path))
        probes = []

    rows, bad, allowed, set_changes, expect_bad = [], [], [], [], []
    orig_hit = same = 0
    for p in probes:
        if not isinstance(p, dict) or not str(p.get("text") or "").strip():
            problems.append("探针缺 text 字段：%r" % (p.get("id") if isinstance(p, dict) else p))
            continue
        pid = str(p.get("id") or "?")
        text = str(p["text"])
        rewritten, words = rewrite(text, mapping, rx)
        o_dom = primary_domain(route_mod, text)
        n_dom = primary_domain(route_mod, rewritten)
        exp_dom = expected_domain(p.get("expect_skill"))
        if o_dom:
            orig_hit += 1
        if o_dom == n_dom:
            same += 1
        row = {"id": pid, "text": text, "rewritten": rewritten,
               "orig_words": ["%s→%s" % (k, v) + ("×%d" % c if c > 1 else "")
                              for k, v, c in words],
               "orig_domain": o_dom, "new_domain": n_dom,
               "expect_domain": exp_dom, "expect_skill": p.get("expect_skill")}
        if exp_dom != o_dom:
            expect_bad.append({"id": pid, "expect": exp_dom, "actual": o_dom})
        if o_dom != n_dom:
            allow = bool(p.get("allow_unclassified_after_rewrite")) and n_dom == ""
            row["status"] = "ALLOWED" if allow else "FAIL"
            row["reason"] = ("改写后判不出来（探针标了 allow_unclassified_after_rewrite）"
                             if allow else
                             ("改写后判不出来" if n_dom == "" else
                              ("原文判不出来但改写后被判进 %s" % n_dom if o_dom == "" else
                               "改写把语义域带偏了：%s → %s" % (o_dom, n_dom))))
            (allowed if allow else bad).append(row)
        else:
            row["status"] = "OK"
        so, sn = domain_set(route_mod, text), domain_set(route_mod, rewritten)
        if so != sn and o_dom == n_dom:
            set_changes.append({"id": pid, "lost": sorted(set(so) - set(sn)),
                                "gained": sorted(set(sn) - set(so)),
                                "orig_domain": o_dom})
        rows.append(row)

    summary = {"probes": len(rows), "orig_classified": orig_hit,
               "same_domain": same, "inconsistent": len(bad), "allowed": len(allowed)}
    ok = not problems and not bad
    return {"ok": ok, "schema": "rewrite-route-parity/1",
            "interceptor": os.path.relpath(ts_path, ROOT).replace(os.sep, "/"),
            "probes_file": os.path.relpath(probes_path, ROOT).replace(os.sep, "/"),
            "rewrite": {"algorithm": "single-pass-longest-first（同 buildSensitiveMatcher）",
                        "wordlist_parsed": bool(pairs), "pairs": len(pairs),
                        "keys": len(mapping)},
            "summary": summary, "problems": problems,
            "inconsistencies": bad, "allowed": allowed,
            "domain_set_changes": set_changes, "expect_mismatch": expect_bad,
            "probes": rows}


def _wid(s):
    """显示宽度（CJK 算 2）—— 只用于对齐，不影响判定。"""
    return sum(2 if ord(c) > 0x2E7F else 1 for c in s)


def _pad(s, w):
    return s + " " * max(0, w - _wid(s))


def main():
    ap = argparse.ArgumentParser(
        description="改写同域检查：客户原话被安全词表改写后，路由域不许变（词表从 .ts 现读）")
    ap.add_argument("--json", action="store_true", help="机器可读（check.py 用）")
    ap.add_argument("--verbose", action="store_true", help="逐条列出所有探针（含一致项）")
    ap.add_argument("--interceptor", default=INTERCEPTOR, help="覆盖 .ts 路径（测试/破坏性验证用）")
    ap.add_argument("--probes", default=PROBES, help="覆盖探针 json 路径（测试用）")
    a = ap.parse_args()

    res = run(a.interceptor, a.probes)
    s = res["summary"] or {}
    rw = res.get("rewrite") or {"pairs": 0, "wordlist_parsed": False}

    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res["ok"] else 1

    print("[REWRITE-PARITY] 词表现读：%s → %d 条键值" % (res["interceptor"], rw["pairs"]))
    print("[REWRITE-PARITY] 改写算法：单趟最长优先（与 buildSensitiveMatcher 一致，不回扫）")
    print("[REWRITE-PARITY] 探针：%s → %d 条" % (res["probes_file"], s.get("probes", 0)))
    for p in res["problems"]:
        print("  [FAIL] " + p)
    if a.verbose:
        for r in res["probes"]:
            print("  %s %s %s→ %s %s"
                  % (_pad(r["status"], 8), _pad(r["id"], 14),
                     _pad(r["orig_domain"] or "(判不出)", 18),
                     _pad(r["new_domain"] or "(判不出)", 18),
                     " ".join(r["orig_words"]) if r["orig_words"] else "(无敏感词，未改写)"))
    for r in res["inconsistencies"]:
        print("  [FAIL] %s  %s" % (r["id"], r["reason"]))
        print("         原词    : %s" % (" ".join(r["orig_words"]) or "(无)"))
        print("         原文    : %s" % r["text"])
        print("         改写后  : %s" % r["rewritten"])
        print("         原域→新域: %s → %s" % (r["orig_domain"] or "(判不出)",
                                            r["new_domain"] or "(判不出)"))
    for r in res["allowed"]:
        print("  [INFO] %s 豁免：%s（%s → %s）" % (r["id"], r["reason"],
                                                 r["orig_domain"], r["new_domain"] or "(判不出)"))
    for c in res["domain_set_changes"]:
        print("  [INFO] %s primary 不变（%s），但命中域集合变了：lost=%s gained=%s —— 不计入失败"
              % (c["id"], c["orig_domain"], ",".join(c["lost"]) or "-",
                 ",".join(c["gained"]) or "-"))
    for e in res["expect_mismatch"]:
        print("  [INFO] %s 原文域与 expect_skill 不符（expect=%s actual=%s）——归 route-tests 管"
              % (e["id"], e["expect"] or "(空)", e["actual"] or "(判不出)"))

    if res["problems"]:
        print("  [FAIL] 词表/探针不可信：下面的同域统计不成立（rc=1），先修词表格式再谈绿")
    print("结果: 原文命中 %d 条 / 改写后仍同域 %d 条 / 不一致 %d 条%s"
          % (s.get("orig_classified", 0), s.get("same_domain", 0), s.get("inconsistent", 0),
             "" if not s.get("allowed") else "（另有 %d 条显式豁免）" % s["allowed"]))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    sys.exit(main())
