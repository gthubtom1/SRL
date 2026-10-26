#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rewrite-route-parity.py —— 三路路由同域检查（原话 / 原话+同义扩写 / 安全改写版）。

血案（审计点名未修）：
    客户的话在进模型之前会被 `Tool/prompts/extensions/security-audit-interceptor.ts`
    的词表改写（「脱壳」→「内存转储与还原解包」、「破解」→「白盒鉴权脆弱性测试」…）。
    这套 from→to 是**为降低模型拒绝率**调的，从来没为「命中路由」调过 ——
    改写后语义已经变了（脱壳 → 内存转储，会被路由带进 malware-analysis，
    而它本该落 softseep / unpack-loop）。原脚本只断言「原话 vs 改写版同域」，
    等于把「改写版就是原意」当成了前提。

现在的判据（用户口径）：
    送模型的可以用安全说法；**选域必须看「原话 + 同义扩写」，不能用改写版替代原意**。

每条探针跑三路，断言只有两条：
    A 原话                      route(原话)
    B 原话 + route_terms 扩写     route(原话 + 该原话命中的词条的 route_terms)
    C 安全改写版（from→to）        route(改写版)
    ① A 与 B **必须同域**（这才是要保的性质；不同域 → 判红，退出码 1）
    ② C **允许**不同域，但必须打印成「已知风险」清单（不判红）：改写版仍在链路上
       出现过（模型会把它写进工具参数），一旦跑偏必须看得见，不许静默。

三条不可妥协的纪律：
    1. 词表只从 `Tool/config/input-normalize.json`（唯一事实源）现读；读不到才退回
       解析 .ts 里的内嵌字面量并打 WARN。Python 里**不抄**一份 —— 抄一份就是第二
       事实源，改 JSON 不改 Python 时会静默漂移。
    2. .ts 的内嵌回退表与 JSON 的 from/to 必须逐条一致（不一致 → 判红）：
       回退表一旦漂移，「JSON 坏了」那一刻词表会静默换内容（用户明确要求不许静默失效）。
    3. 路由判据不许动：本脚本只调用 `route.resolve()`，不重写任何正则、不放宽任何阈值。

用法：
    python Tool/scripts/rewrite-route-parity.py            # 人读（三路对比 + 已知风险）
    python Tool/scripts/rewrite-route-parity.py --json     # 机器可读（check.py 用这个）
    python Tool/scripts/rewrite-route-parity.py --verbose  # 逐条列出（含 OK 项）

退出码：0 = 原话与扩写全部同域；1 = 有任一不同域 / 词表不可信 / 回退表漂移。
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
NORMALIZE = os.path.join(ROOT, "Tool", "config", "input-normalize.json")
PROBES = os.path.join(ROOT, "Tool", "config", "skill-route-probes.json")
NORMALIZE_SCHEMA = "seep.input-normalize/1"
FALLBACK_NAME = "FALLBACK_WORD_MAP"

# .ts 里两种可能的旧写法（JSON 读不到时才用）：
#   A 数组形态：[/脱壳/g, "内存转储与还原解包"],
#   B 对象字面量："脱壳": "内存转储与还原解包",
PAIR_ARRAY = re.compile(
    r"\[\s*/(?P<pat>(?:\\.|[^/\\])+)/(?P<flags>[a-z]*)\s*,\s*"
    r"(?:\"(?P<dq>(?:\\.|[^\"\\])*)\"|'(?P<sq>(?:\\.|[^'\\])*)')\s*\]",
    re.S)
PAIR_OBJ = re.compile(
    r"(?:\"(?P<k1>(?:\\.|[^\"\\])*)\"|'(?P<k2>(?:\\.|[^'\\])*)')\s*:\s*"
    r"(?:\"(?P<v1>(?:\\.|[^\"\\])*)\"|'(?P<v2>(?:\\.|[^'\\])*)')",
    re.S)
# 回退表是 [[from, to], …] 的字面量形态
FALLBACK_PAIR = re.compile(
    r"\[\s*(?:\"(?P<f1>(?:\\.|[^\"\\])*)\"|'(?P<f2>(?:\\.|[^'\\])*)')\s*,\s*"
    r"(?:\"(?P<t1>(?:\\.|[^\"\\])*)\"|'(?P<t2>(?:\\.|[^'\\])*)')\s*\]",
    re.S)


# --------------------------------------------------------------------------
# 词表：JSON 优先，.ts 内嵌回退兜底
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


def load_normalize(path=NORMALIZE):
    """返回 (pairs[{from,to,route_terms}], source, problems)。problems 非空 = 词表不可信。"""
    try:
        doc = json.load(open(path, encoding="utf-8"))
    except Exception as e:                                   # noqa: BLE001
        return [], "", ["读不到词表 %s：%s（改回 .ts 内嵌表兜底，route_terms 缺失）"
                        % (os.path.basename(path), str(e)[:80])]

    problems = []
    if not isinstance(doc, dict):
        return [], path, ["%s 顶层不是对象" % os.path.basename(path)]
    schema = str(doc.get("schema") or "")
    if schema != NORMALIZE_SCHEMA:
        problems.append("schema=%r ≠ %r" % (schema, NORMALIZE_SCHEMA))
    raw = doc.get("pairs")
    if not isinstance(raw, list) or not raw:
        return [], path, ["pairs 为空或不是数组"]

    pairs, seen = [], {}
    for i, p in enumerate(raw):
        if not isinstance(p, dict):
            problems.append("pairs[%d] 不是对象" % i)
            continue
        src, dst = str(p.get("from") or ""), str(p.get("to") or "")
        terms = p.get("route_terms")
        if not src:
            problems.append("pairs[%d] 缺 from" % i)
            continue
        if not dst:
            problems.append("%s 缺 to（改写词为空 = 条目失效）" % src)
        if not isinstance(terms, list) or not terms:
            problems.append("%s 的 route_terms 为空（路由侧拿不到同义扩写）" % src)
            terms = []
        else:
            bad = [t for t in terms if not str(t or "").strip()]
            if bad:
                problems.append("%s 的 route_terms 有空项" % src)
            terms = [str(t) for t in terms if str(t or "").strip()]
        if src in seen and seen[src] != dst:
            problems.append("from 重复且改写词不同：%r（%r / %r）" % (src, seen[src], dst))
        seen[src] = dst
        pairs.append({"from": src, "to": dst, "route_terms": terms})
    if not pairs:
        problems.append("%s 里一条完整词条都没解析出来" % os.path.basename(path))
    return pairs, path, problems


def _array_literal(src, name):
    """取出 `const <name> … = [ … ]` 的方括号内容（跳过字符串/正则/注释里的括号）。"""
    i = src.find(name)
    if i < 0:
        return None, "找不到 %s 定义" % name
    eq = src.find("=", i)
    if eq < 0:
        return None, "%s 后没有 `=`（定义形态变了）" % name
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


def read_ts(ts_path):
    try:
        return open(ts_path, encoding="utf-8", errors="replace").read(), ""
    except OSError as e:
        return "", "读不到 %s：%s" % (ts_path, str(e)[:60])


def parse_fallback_table(ts_path):
    """解析 .ts 的内嵌回退表 FALLBACK_WORD_MAP → [(from, to)]；解析不到返回 ([], 原因)。"""
    src, err = read_ts(ts_path)
    if not src:
        return [], err
    lit, why = _array_literal(src, FALLBACK_NAME + ":")
    if lit is None:
        return [], "%s 解析失败：%s" % (FALLBACK_NAME, why)
    pairs = []
    for m in FALLBACK_PAIR.finditer(lit):
        key = _unescape_js_string(m.group("f1") if m.group("f1") is not None else m.group("f2"))
        val = _unescape_js_string(m.group("t1") if m.group("t1") is not None else m.group("t2"))
        pairs.append((key, val))
    if not pairs:
        return [], "%s 里一条键值都没解析出来" % FALLBACK_NAME
    return pairs, ""


def parse_legacy_word_map(ts_path):
    """旧路径兜底：直接从 .ts 的 SENSITIVE_WORD_MAP 字面量读（无 route_terms）。"""
    src, err = read_ts(ts_path)
    if not src:
        return [], [err]
    lit, why = _array_literal(src, "SENSITIVE_WORD_MAP")
    if lit is None:
        return [], ["%s；且 %s" % (why, "%s 也没有" % FALLBACK_NAME)]
    pairs = []
    for m in PAIR_ARRAY.finditer(lit):
        key = _unescape_js_string(m.group("pat"))
        val = _unescape_js_string(m.group("dq") if m.group("dq") is not None else m.group("sq"))
        pairs.append({"from": key, "to": val, "route_terms": [key]})
    if not pairs:
        for m in PAIR_OBJ.finditer(lit):
            key = _unescape_js_string(m.group("k1") if m.group("k1") is not None else m.group("k2"))
            val = _unescape_js_string(m.group("v1") if m.group("v1") is not None else m.group("v2"))
            pairs.append({"from": key, "to": val, "route_terms": [key]})
    if not pairs:
        return [], ["SENSITIVE_WORD_MAP 里一条键值都没解析出来；词表格式变了，本检查需同步"]
    return pairs, []


def check_fallback_sync(pairs, ts_path):
    """JSON 的 from/to 与 .ts 内嵌回退表必须逐条一致（防「JSON 坏了」时静默换内容）。"""
    fb, why = parse_fallback_table(ts_path)
    if not fb:
        return [why] if why else []
    problems = []
    json_map = {p["from"]: p["to"] for p in pairs}
    fb_map = {}
    for k, v in fb:
        fb_map.setdefault(k, v)
    missing = [k for k in fb_map if k not in json_map]
    extra = [k for k in json_map if k not in fb_map]
    drift = [k for k in fb_map if k in json_map and fb_map[k] != json_map[k]]
    if missing:
        problems.append("JSON 少了 .ts 回退表里的 %d 条：%s" % (len(missing), "、".join(missing[:6])))
    if extra:
        problems.append("JSON 多了 .ts 回退表里没有的 %d 条：%s" % (len(extra), "、".join(extra[:6])))
    for k in drift:
        problems.append("词条 %r 的改写词两边不一致（JSON=%r / .ts=%r）"
                        % (k, json_map[k], fb_map[k]))
    return problems


# --------------------------------------------------------------------------
# 三路文本构造
# --------------------------------------------------------------------------
def expand_with_route_terms(text, pairs):
    """B 路：原话 + 原话命中的词条的 route_terms 扩写。

    触发只看 `from`（词表里真正会被改写的那几个词）：route_terms 是**扩写**，
    反过来拿扩写词去反查会产生假阳性（例：「有 UPX 壳」里的 `upx` 会把「脱壳」
    的同义词全加进来，反而把 softseep 拽进 malware-analysis）。
    """
    text = str(text or "")
    hits, terms = [], []
    for p in pairs:
        src = p["from"]
        if src and src in text:
            hits.append((src, list(p["route_terms"])))
            terms.extend(p["route_terms"])
    uniq = []
    for t in terms:
        if t not in uniq:
            uniq.append(t)
    if not uniq:
        return text, hits
    return text + " " + " ".join(uniq), hits


def build_rewriter(pairs):
    """C 路：单趟最长优先；同键先到先得（对应 .ts 的 `if (!mapping.has(source))`）。"""
    mapping = {}
    for p in pairs:
        if p["from"]:
            mapping.setdefault(p["from"], p["to"])
    keys = sorted(mapping, key=len, reverse=True)
    rx = re.compile("|".join(re.escape(k) for k in keys)) if keys else None
    return mapping, rx


def rewrite(text, mapping, rx):
    """返回 (改写后文本, [(原词, 改写词, 次数)])。

    对齐 .ts 的两个早退：以 `/` 开头的斜杠命令、空文本原样返回。
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


def _empty_result(problems, extra=None):
    res = {"ok": False, "schema": "rewrite-route-parity/2",
           "problems": problems, "inconsistencies": [], "known_risks": [],
           "word_rows": [], "rows": [], "probes": [],
           "rewrite": {"algorithm": "single-pass-longest-first", "wordlist_parsed": False,
                       "pairs": 0, "keys": 0, "source": ""},
           "summary": {}}
    if extra:
        res.update(extra)
    return res


def run(ts_path, probes_path, normalize_path=NORMALIZE):
    sys.path.insert(0, HERE)
    import route as route_mod                                # noqa: E402  唯一判据来源

    pairs, source, problems = load_normalize(normalize_path)
    used_fallback = False
    if not pairs:
        pairs, legacy_problems = parse_legacy_word_map(ts_path)
        problems = list(problems) + legacy_problems
        if pairs:
            used_fallback = True
            source = ts_path
            print("[REWRITE-PARITY] WARN 词表 JSON 不可用，退回收退 .ts 内嵌表（%d 条，无 route_terms）"
                  % len(pairs), file=sys.stderr)
    if pairs and not used_fallback:
        problems.extend(check_fallback_sync(pairs, ts_path))

    mapping, rx = build_rewriter(pairs)

    try:
        doc = json.load(open(probes_path, encoding="utf-8"))
    except Exception as e:                                   # noqa: BLE001
        return _empty_result(problems + ["读不到探针文件 %s：%s"
                                        % (os.path.basename(probes_path), str(e)[:60])])
    probes = doc.get("probes") if isinstance(doc, dict) else doc
    if not isinstance(probes, list) or not probes:
        problems.append("探针文件里没有 probes 数组（%s）" % os.path.basename(probes_path))
        probes = []

    rows, bad, risks, set_changes, expect_bad, word_rows = [], [], [], [], [], []
    orig_hit = same_expand = expanded = rewrite_drift = 0
    for p in probes:
        if not isinstance(p, dict) or not str(p.get("text") or "").strip():
            problems.append("探针缺 text 字段：%r" % (p.get("id") if isinstance(p, dict) else p))
            continue
        pid = str(p.get("id") or "?")
        text = str(p["text"])
        expanded_text, hits = expand_with_route_terms(text, pairs)
        rewritten, words = rewrite(text, mapping, rx)
        o_dom = primary_domain(route_mod, text)              # A 原话
        e_dom = primary_domain(route_mod, expanded_text)     # B 原话 + route_terms
        n_dom = primary_domain(route_mod, rewritten)         # C 安全改写版
        exp_dom = expected_domain(p.get("expect_skill"))
        if o_dom:
            orig_hit += 1
        if hits:
            expanded += 1
        if o_dom == e_dom:
            same_expand += 1
        if o_dom != n_dom:
            rewrite_drift += 1

        row = {"id": pid, "text": text, "expanded": expanded_text, "rewritten": rewritten,
               "route_terms_hits": ["%s→%s" % (k, "/".join(t)) for k, t in hits],
               "rewritten_words": ["%s→%s" % (k, v) + ("×%d" % c if c > 1 else "")
                                   for k, v, c in words],
               "orig_domain": o_dom, "expanded_domain": e_dom, "rewrite_domain": n_dom,
               "expect_domain": exp_dom, "expect_skill": p.get("expect_skill")}
        if exp_dom != o_dom:
            expect_bad.append({"id": pid, "expect": exp_dom, "actual": o_dom})
        if o_dom != e_dom:
            row["status"] = "FAIL"
            row["reason"] = ("扩写把语义域带偏了：%s → %s（A/B 必须同域）" % (o_dom, e_dom)
                             if o_dom else "原话判不出，扩写后判进 %s（不该发生：扩写只该补线索）" % e_dom)
            bad.append(row)
        else:
            row["status"] = "OK"
        # ② 改写版跑偏：不判红，只记账（已知风险）
        if o_dom != n_dom:
            allow = bool(p.get("allow_unclassified_after_rewrite")) and n_dom == ""
            row["rewrite_status"] = "ALLOWED" if allow else "RISK"
            risks.append({"id": pid, "orig_domain": o_dom or "(判不出)",
                          "rewrite_domain": n_dom or "(判不出)",
                          "allowed": allow,
                          "rewrite_words": row["rewritten_words"],
                          "text": text, "rewritten": rewritten})
        so, se = domain_set(route_mod, text), domain_set(route_mod, expanded_text)
        if so != se and o_dom == e_dom:
            set_changes.append({"id": pid, "lost": sorted(set(so) - set(se)),
                                "gained": sorted(set(se) - set(so)),
                                "orig_domain": o_dom})
        rows.append(row)

    # 词条级自检：拿 31 条原词本身当探针跑 A/B（词短，原话常常判不出 →
    # 判不出变判出是**预期增强**，只记 INFO；两边都判出却不同 → 判红）。
    for p in pairs:
        o = primary_domain(route_mod, p["from"])
        e = primary_domain(route_mod, p["from"] + " " + " ".join(p["route_terms"]))
        w = primary_domain(route_mod, p["to"])
        row = {"from": p["from"], "to": p["to"],
               "orig_domain": o, "expanded_domain": e, "rewrite_domain": w}
        if not o and e:
            row["status"] = "ENHANCED"
        elif not o and not e:
            row["status"] = "OK"
        elif o == e:
            row["status"] = "OK"
        else:
            row["status"] = "FAIL"
            bad.append({"id": "词条:" + p["from"],
                        "reason": "扩写把语义域带偏了：%s → %s" % (o, e),
                        "orig_domain": o, "expanded_domain": e})
        word_rows.append(row)
        # 词条级风险也进「已知风险」清单：「改写版单独当输入」时被带跑的多是单条词
        if o != w:
            risks.append({"id": "词条:" + p["from"], "kind": "word",
                          "orig_domain": o or "(判不出)",
                          "rewrite_domain": w or "(判不出)",
                          "allowed": False,
                          "rewrite_words": ["%s→%s" % (p["from"], p["to"])],
                          "text": p["from"], "rewritten": p["to"]})

    summary = {"probes": len(rows), "orig_classified": orig_hit,
               "expanded_probes": expanded, "same_domain": same_expand,
               "inconsistent": len(bad), "rewrite_drift": rewrite_drift,
               "words": len(word_rows),
               "words_enhanced": len([r for r in word_rows if r["status"] == "ENHANCED"]),
               # 词条级：单个词被改写后自己还判不判得出原域（探针句子常常被别的词兜住，
               # 所以这一项单列 —— 它是「改写版单独当输入」的风险面）
               "words_rewrite_drift": len([r for r in word_rows
                                           if r["orig_domain"] != r["rewrite_domain"]])}
    ok = not problems and not bad
    return {"ok": ok, "schema": "rewrite-route-parity/2",
            "interceptor": os.path.relpath(ts_path, ROOT).replace(os.sep, "/"),
            "wordlist": os.path.relpath(normalize_path, ROOT).replace(os.sep, "/")
                        if not used_fallback else
                        os.path.relpath(ts_path, ROOT).replace(os.sep, "/"),
            "probes_file": os.path.relpath(probes_path, ROOT).replace(os.sep, "/"),
            "rewrite": {"algorithm": "single-pass-longest-first（同 buildSensitiveMatcher）",
                        "wordlist_parsed": bool(pairs),
                        "source": "json" if not used_fallback else "ts-legacy-fallback",
                        "pairs": len(pairs), "keys": len(mapping)},
            "summary": summary, "problems": problems,
            "inconsistencies": bad, "known_risks": risks,
            "domain_set_changes": set_changes, "expect_mismatch": expect_bad,
            "word_rows": word_rows, "rows": rows, "probes": rows}


def _wid(s):
    """显示宽度（CJK 算 2）—— 只用于对齐，不影响判定。"""
    return sum(2 if ord(c) > 0x2E7F else 1 for c in s)


def _pad(s, w):
    return s + " " * max(0, w - _wid(s))


def main():
    ap = argparse.ArgumentParser(
        description="三路路由同域：原话 / 原话+route_terms 必须同域；安全改写版只记账不判红")
    ap.add_argument("--json", action="store_true", help="机器可读（check.py 用）")
    ap.add_argument("--verbose", action="store_true", help="逐条列出所有探针（含一致项）")
    ap.add_argument("--interceptor", default=INTERCEPTOR, help="覆盖 .ts 路径（测试/破坏性验证用）")
    ap.add_argument("--normalize", default=NORMALIZE, help="覆盖词表 json 路径（测试用）")
    ap.add_argument("--probes", default=PROBES, help="覆盖探针 json 路径（测试用）")
    a = ap.parse_args()

    res = run(a.interceptor, a.probes, a.normalize)
    s = res["summary"] or {}
    rw = res.get("rewrite") or {"pairs": 0, "wordlist_parsed": False, "source": "?"}

    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res["ok"] else 1

    print("[REWRITE-PARITY] 词表现在读：%s（%s）→ %d 条" % (res["wordlist"], rw["source"], rw["pairs"]))
    print("[REWRITE-PARITY] 探针：%s → %d 条；判据 = 原话 vs 原话+route_terms 必须同域" %
          (res["probes_file"], s.get("probes", 0)))
    print("[REWRITE-PARITY] 改写版（from→to）只记账：跑偏的列进「已知风险」，不判红")
    for p in res["problems"]:
        print("  [FAIL] " + p)
    if a.verbose:
        for r in res["probes"]:
            print("  %s %s A=%-18s B=%-18s C=%-18s"
                  % (_pad(r["status"], 6), _pad(r["id"], 14),
                     _pad(r["orig_domain"] or "(判不出)", 18),
                     _pad(r["expanded_domain"] or "(判不出)", 18),
                     _pad(r["rewrite_domain"] or "(判不出)", 18)))
    for r in res["inconsistencies"]:
        print("  [FAIL] %s  %s" % (r["id"], r["reason"]))
        if "text" in r:
            print("         原话    : %s" % r["text"])
            print("         扩写    : %s" % r["expanded"])
            print("         同义命中: %s" % (" ".join(r["route_terms_hits"]) or "(无)"))
    for r in res["known_risks"]:
        tag = "词条级" if r.get("kind") == "word" else "探针级"
        print("  [RISK] %s %s  改写版跑偏：%s → %s%s"
              % (tag, r["id"], r["orig_domain"], r["rewrite_domain"],
                 "（已豁免）" if r["allowed"] else ""))
        print("         改写词  : %s" % (" ".join(r["rewrite_words"]) or "(无)"))
        print("         原话    : %s" % r["text"])
        print("         改写后  : %s" % r["rewritten"])
    for c in res["domain_set_changes"]:
        print("  [INFO] %s primary 不变（%s），但命中域集合变了：lost=%s gained=%s —— 不计入失败"
              % (c["id"], c["orig_domain"], ",".join(c["lost"]) or "-",
                 ",".join(c["gained"]) or "-"))
    for e in res["expect_mismatch"]:
        print("  [INFO] %s 原话域与 expect_skill 不符（expect=%s actual=%s）——归 route-tests 管"
              % (e["id"], e["expect"] or "(空)", e["actual"] or "(判不出)"))
    if a.verbose:
        for w in res["word_rows"]:
            print("  %s 词条 %s  A=%s B=%s C=%s"
                  % (_pad(w["status"], 9), _pad(w["from"], 8),
                     w["orig_domain"] or "(判不出)", w["expanded_domain"] or "(判不出)",
                     w["rewrite_domain"] or "(判不出)"))
    elif s.get("words_rewrite_drift"):
        print("  [INFO] 词条级：%d/%d 条的改写版单独当输入时已判不出原域"
              "（探针句子被别的词兜住；这是「改写版参与路由」的真正风险面，明细 --verbose）"
              % (s["words_rewrite_drift"], s.get("words", 0)))

    if res["problems"]:
        print("  [FAIL] 词表不可信：下面的同域统计不成立（rc=1），先修词表再谈绿")
    print("结果: 原话 vs 扩写 同域 %d/%d 条（扩写生效 %d 条）/ 不一致 %d 条 / 改写版跑偏 %d 条（已知风险，不判红）"
          % (s.get("same_domain", 0), s.get("probes", 0), s.get("expanded_probes", 0),
             s.get("inconsistent", 0), s.get("rewrite_drift", 0)))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    sys.exit(main())
