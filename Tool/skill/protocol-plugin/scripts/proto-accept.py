#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""proto-accept.py -- protocol-plugin 域验收：案例判据复算 + 路由边界自检。

用途
----
1. **案例复算**：按 pack.json 的 `cases[]` 扫 protocol/plugin 案例，逐条复算本域硬判据——
   必填字段、`evidence_kind` 与 `target_type` 自洽、`artifacts[].sha256` 真实、
   `refs` 不幻影、`lessons[0]` 写清"跑的是什么/命令/rc"、`outcome != planned`。
2. **路由边界**：读 `Tool/skill/protocol-plugin/pack.json`，
   用其中的词边界规则跑 `boundary_tests`，确认不抢 web 的 spider、firmware 的 bios，
   也不会误吃无关的构建脚手架词。

用法
----
    python proto-accept.py                      # 扫全量本域案例
    python proto-accept.py --case ../cases/protocol03
    python proto-accept.py --routing-check
    python proto-accept.py --self-test
    python proto-accept.py --json

退出码：0 全部通过；2 有 FAIL 或内部错误（`{"ok": false, "blocked_at": ...}`）。

边界：只复算**本域**判据，不替代 `Tool/scripts/domain-gate.py` 的全量门禁；
哈希复算是本机读文件，不联网、不写案例目录。
"""

from __future__ import annotations

# Shared locator for both source skills and installed copies.
from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parents[2] / 'softseep' / 'scripts'))
from seep_runtime import repo_root as _seep_repo_root


import argparse
import hashlib
import json
import os
import re
import sys
import tempfile

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
ROOT = _seep_repo_root(__file__)
CASES = os.path.join(ROOT, "Tool", "cases")
# S3：路由片段目录已删，路由只活在 pack.json 的 routes 里
FRAGMENT = os.path.join(ROOT, "Tool", "skill", "protocol-plugin", "pack.json")

CASE_FIELDS = ("id", "domain", "target_type", "evidence_kind", "protection",
               "authority", "goal_level", "outcome", "artifacts", "lessons",
               "refs", "updated")
FIXTURE_WORDS = ("夹具", "教学", "fixture", "示例")
# public = 公开可分发的真实产物（教学靶场 / CTF / 公开 crackme / MIT 示例）：
# 它的 target_type **本来就该**写「公开教学靶场 XXX」。判夹具字样前先剥掉公开来源词，
# 否则真实公开样本会被逼回 fixture（另一个方向的假话）。语义见 domain_spec.EVIDENCE_KINDS。
PUBLIC_MARKERS = ("公开教学靶场", "公开", "靶场", "CTF", "crackme", "MIT", "github", "public")


def _fixture_words(target_type, kind=""):
    t = str(target_type or "")
    if str(kind or "").strip().lower() == "public":
        for w in PUBLIC_MARKERS:
            t = t.replace(w, "")
    return [w for w in FIXTURE_WORDS if w in t]
GOOD_LEVELS = ("L1", "L2", "L3", "L4")
GOOD_OUTCOMES = ("success", "partial", "blocked")


class BoundaryError(RuntimeError):
    pass

# 片段缺失时的兜底词边界规则（与 routing-fragments/protocol-plugin.json 同义）
BUILTIN_PATTERN = (
    r"(?i)(私有协议|协议逆向|协议复刻|抓包|\bpcap\b|\btshark\b|\bwireshark\b|"
    r"\bmitmproxy\b|状态机|报文|重放|\bprotobuf\b|\bflatbuffers\b|"
    r"\bwebsocket\b|\bmodbus\b|\bmqtt\b|\bhttp/2\b|\bquic\b)"
)
BUILTIN_FORBID = [r"(?i)\bspider\b", r"(?i)\bbios\b", r"(?i)\bprincipal\b",
                  r"(?i)\bzipalign\b", r"(?i)\bscaffold\b"]
BUILTIN_TESTS = [
    {"text": "抓包分析私有协议并重建分帧", "expect": "hit"},
    {"text": "用 tshark 读 pcap 里的 websocket 帧", "expect": "hit"},
    {"text": "状态机重放验证并构造新请求", "expect": "hit"},
    {"text": "protobuf 字段号与 wire type 解析", "expect": "hit"},
    {"text": "爬虫 spider 抓取目录并枚举路径", "expect": "miss"},
    {"text": "bios 固件 SPI flash dump 与 UART 接入", "expect": "miss"},
    {"text": "Kerberos principal 枚举与 SPN 发现", "expect": "miss"},
    {"text": "npm scaffold 生成项目后检查 lockfile 完整性", "expect": "miss"},
    {"text": "用 zipalign 对齐后 apksigner 重签", "expect": "miss"},
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(path):
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def repo_root(explicit=None):
    if explicit:
        root = os.path.abspath(os.path.expanduser(str(explicit)))
        if not os.path.isdir(os.path.join(root, "Tool", "cases")):
            raise ValueError("--root 不是含 Tool/cases 的仓库根: %s" % root)
        return root
    return ROOT


def _within(path, parent):
    try:
        child = os.path.realpath(path)
        base = os.path.realpath(parent)
        return os.path.commonpath((child, base)) == base
    except (OSError, ValueError):
        return False


def pack_cases(root):
    path = os.path.join(root, "Tool", "skill", "protocol-plugin", "pack.json")
    if not os.path.isfile(path):
        raise RuntimeError("缺少 domain pack: %s" % path)
    data = load(path)
    cases = data.get("cases") if isinstance(data, dict) else None
    if not isinstance(cases, list) or not cases:
        raise RuntimeError("pack.json 未声明非空 cases[]")
    out = []
    for i, name in enumerate(cases):
        if not isinstance(name, str) or not name.strip():
            raise RuntimeError("pack.json cases[%d] 不是非空字符串" % i)
        name = name.strip()
        if os.path.basename(name) != name or name in (".", ".."):
            raise RuntimeError("pack.json cases[%d] 越界或不是目录名: %r" % (i, name))
        out.append(name)
    if len(set(out)) != len(out):
        raise RuntimeError("pack.json cases[] 含重复项")
    roles = data.get("case_roles") if isinstance(data.get("case_roles"), dict) else {}
    for role in ("witness", "depth_gate"):
        values = roles.get(role, [])
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise RuntimeError("pack.json case_roles.%s 必须是字符串数组" % role)
        unknown = sorted(set(values) - set(out))
        if unknown:
            raise RuntimeError("pack.json case_roles.%s 引用未声明案例: %s"
                               % (role, ",".join(unknown)))
    return out


# ------------------------------------------------------------------ cases
def check_case(path, root):
    """返回 (problems, facts)。path 是 case 目录。"""
    problems = []
    facts = {"dir": os.path.basename(path.rstrip("/\\"))}
    cases_root = os.path.join(root, "Tool", "cases")
    if not _within(path, cases_root):
        return ["案例目录越过 Tool/cases 边界"], facts
    cf = os.path.join(path, "case.json")
    if not os.path.isfile(cf):
        return ["缺 case.json"], facts
    try:
        c = load(cf)
    except Exception as exc:  # noqa: BLE001
        return ["case.json 不是合法 JSON: %s" % str(exc)[:60]], facts

    for k in CASE_FIELDS:
        if k not in c:
            problems.append("缺字段 %s" % k)
    facts["id"] = c.get("id")
    facts["evidence_kind"] = c.get("evidence_kind")
    facts["outcome"] = c.get("outcome")
    if c.get("id") != facts["dir"]:
        problems.append("id=%r 与目录名 %r 不一致" % (c.get("id"), facts["dir"]))

    if c.get("domain") != "protocol-plugin":
        problems.append("domain=%r 不是 protocol-plugin" % c.get("domain"))
    kind = c.get("evidence_kind")
    if kind not in ("fixture", "real", "public", "self-built", "historical"):
        problems.append("evidence_kind=%r 非法" % kind)
    tt = str(c.get("target_type") or "")
    is_fix = bool(_fixture_words(tt, kind))
    if kind == "fixture" and not is_fix:
        problems.append("fixture 但 target_type 未标夹具/教学")
    if kind in ("real", "public", "self-built") and is_fix:
        problems.append("real 却把 target_type 标成夹具")
    if c.get("outcome") == "planned":
        problems.append("outcome=planned 不许入库")
    if c.get("outcome") not in GOOD_OUTCOMES:
        problems.append("outcome=%r 不在 %s" % (c.get("outcome"), GOOD_OUTCOMES))
    if c.get("goal_level") not in GOOD_LEVELS:
        problems.append("goal_level=%r 非法" % c.get("goal_level"))

    arts = c.get("artifacts") or []
    if not arts:
        problems.append("artifacts 为空")
    for art in arts:
        if not isinstance(art, dict):
            problems.append("artifacts 条目不是对象")
            continue
        ap = art.get("path") or ""
        want = (art.get("sha256") or "").lower()
        full = os.path.abspath(os.path.join(path, ap)) if ap else ""
        if not ap or os.path.isabs(ap) or not _within(full, path):
            problems.append("产物路径越出案例目录: %s" % (ap[:40] or "<空>"))
            continue
        if not os.path.isfile(full):
            problems.append("幻影产物 %s" % (ap[:40] or "<空>"))
            continue
        if len(want) != 64:
            problems.append("%s 缺 sha256" % ap[:40])
        elif sha256(full) != want:
            problems.append("%s sha256 不符（实算 %s）" % (ap[:40], sha256(full)[:12]))

    refs = c.get("refs") or []
    if not isinstance(refs, list):
        problems.append("refs 不是数组")
        refs = []
    for r in refs:
        if not isinstance(r, str) or not r.strip():
            problems.append("refs 条目不是非空相对路径")
            continue
        full = os.path.abspath(os.path.join(root, r))
        if "://" in r or os.path.isabs(r) or not _within(full, root):
            problems.append("refs 越出仓库根或不是相对路径: %s" % r[:60])
            continue
        if not os.path.isfile(full):
            problems.append("refs 幻影 %s" % r[:60])

    lessons = c.get("lessons") or []
    if not lessons:
        problems.append("lessons 为空")
    else:
        head = str(lessons[0])
        if "rc=" not in head:
            problems.append("lessons[0] 未写 rc（须写清跑的是什么/命令/rc）")
        if not re.search(r"(python|tshark|curl|\.py|\.ps1)", head):
            problems.append("lessons[0] 未写命令")

    run_json = os.path.join(path, "artifacts", "run.json")
    if os.path.isfile(run_json):
        try:
            run = load(run_json)
            runs = run.get("runs") if isinstance(run, dict) else None
            if not runs:
                problems.append("artifacts/run.json 无 runs[]")
            else:
                facts["runs"] = len(runs)
                if not any(isinstance(r, dict) and r.get("rc") == 0 for r in runs):
                    problems.append("artifacts/run.json 没有 rc=0 的运行")
        except Exception as exc:  # noqa: BLE001
            problems.append("artifacts/run.json 坏: %s" % str(exc)[:40])
    return problems, facts


def run_cases(dirs, root):
    results = []
    problems = []
    for d in dirs:
        probs, facts = check_case(d, root)
        results.append({"case": facts.get("dir"), "ok": not probs,
                        "problems": probs, "facts": facts})
        problems += ["%s: %s" % (facts.get("dir"), p) for p in probs]
    return results, problems


# ------------------------------------------------------------------ routing
def load_boundary(root=None):
    root = root or ROOT
    fragment = os.path.join(root, "Tool", "skill", "protocol-plugin", "pack.json")
    if not os.path.isfile(fragment):
        return {"source": "builtin", "status": "builtin", "merged_must": "",
                "pattern": BUILTIN_PATTERN, "forbid": BUILTIN_FORBID,
                "tests": BUILTIN_TESTS}
    try:
        frag = load(fragment)
    except Exception as exc:  # noqa: BLE001
        raise BoundaryError("pack.json 不可读或不是合法 JSON: %s" % exc) from exc
    if not isinstance(frag, dict):
        raise BoundaryError("pack.json 顶层必须是对象")
    routes = frag.get("routes")
    if not isinstance(routes, list) or not routes:
        raise BoundaryError("pack.json.routes 必须是非空数组")
    normalized = []
    for i, route in enumerate(routes):
        if not isinstance(route, dict):
            raise BoundaryError("pack.json.routes[%d] 必须是对象" % i)
        label = route.get("label")
        musts = route.get("must")
        if not isinstance(label, str) or not label.strip():
            raise BoundaryError("pack.json.routes[%d].label 必须是非空字符串" % i)
        if (not isinstance(musts, list) or not musts or
                any(not isinstance(m, str) or not m.strip() for m in musts)):
            raise BoundaryError(
                "pack.json.routes[%d].must 必须是非空字符串数组" % i)
        normalized.append(route)
    # 只取「协议」那条路由（pack 里另有「插件/Mod」路由）。
    proto = [r for r in normalized if "协议" in r["label"]]
    if not proto:
        raise BoundaryError("pack.json.routes 缺少 label 含『协议』的路由")
    musts = [m for route in proto for m in route["must"]]
    # 内联 (?i) 不能出现在表达式中间（Python 3.11+ 会报错）：统一提到最前面
    must = "(?i)" + "|".join("(?:%s)" % m.replace("(?i)", "", 1)
                             for m in musts)
    return {"source": os.path.relpath(fragment, root).replace(os.sep, "/"),
            "status": "pack", "merged_must": must, "pattern": must,
            "forbid": BUILTIN_FORBID, "tests": BUILTIN_TESTS}


def run_routing(boundary):
    pat = boundary["pattern"]
    try:
        rx = re.compile(pat)
    except re.error as exc:
        return [{"text": "<pattern>", "ok": False, "reason": "正则非法: %s" % exc}], \
               ["片段正则非法: %s" % exc]
    rows = []
    problems = []
    for t in boundary["tests"]:
        text = t.get("text") or ""
        expect = t.get("expect") or "hit"
        hit = bool(rx.search(text))
        ok = (hit and expect == "hit") or (not hit and expect == "miss")
        reasons = []
        if not ok:
            reasons.append("期望 %s，实际 %s" % (expect, "hit" if hit else "miss"))
        if hit:
            # 只有协议规则真的命中时，禁用词才有意义：命中即表示越界抢词
            for f in boundary["forbid"]:
                try:
                    if re.search(f, text):
                        ok = False
                        reasons.append("命中禁用词 %s" % f)
                except re.error:
                    reasons.append("禁用词正则非法 %s" % f)
        rows.append({"text": text, "expect": expect, "hit": hit, "ok": ok,
                     "reasons": reasons})
        if not ok:
            problems.append("路由边界『%s』: %s" % (text[:30], "；".join(reasons)))
    return rows, problems


# ------------------------------------------------------------------ self-test
def self_test():
    checks = []
    with tempfile.TemporaryDirectory(prefix="proto-accept-") as tmp:
        root = os.path.join(tmp, "repo")
        case_dir = os.path.join(root, "Tool", "cases", "protocol99")
        os.makedirs(os.path.join(case_dir, "artifacts"))
        os.makedirs(os.path.join(root, "Tool", "skill", "protocol-plugin"))
        ref_path = os.path.join(root, "Tool", "skill", "protocol-plugin", "SKILL.md")
        with open(ref_path, "w", encoding="utf-8") as fh:
            fh.write("# test\n")
        good_art = os.path.join(case_dir, "artifacts", "run.json")
        with open(good_art, "w", encoding="utf-8") as fh:
            json.dump({"case": "protocol99", "runs": [{"cmd": "python x.py", "rc": 0}]}, fh)
        good = {
            "id": "protocol99", "domain": "protocol-plugin",
            "target_type": "本地夹具二进制帧（教学样本）", "evidence_kind": "fixture",
            "protection": [], "authority": "local", "goal_level": "L3",
            "outcome": "partial",
            "artifacts": [{"path": "artifacts/run.json", "sha256": sha256(good_art)}],
            "lessons": ["跑的是 python x.py，rc=0，解析 3 帧。"],
            "refs": ["Tool/skill/protocol-plugin/SKILL.md"],
            "updated": "2026-10-21",
        }
        with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(good, fh, ensure_ascii=False)
        probs, _facts = check_case(case_dir, root)
        checks.append(("合规案例 0 problem", not probs))

        bad = json.loads(json.dumps(good))
        bad["artifacts"][0]["sha256"] = "0" * 64
        bad["evidence_kind"] = "real"
        bad["outcome"] = "planned"
        with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(bad, fh, ensure_ascii=False)
        probs_bad, _ = check_case(case_dir, root)
        joined = " | ".join(probs_bad)
        checks.append(("错哈希被发现", "sha256 不符" in joined))
        checks.append(("real 标夹具被发现", "real 却把 target_type" in joined))
        checks.append(("planned 被发现", "planned" in joined))

        outside = os.path.join(root, "outside.bin")
        with open(outside, "wb") as fh:
            fh.write(b"outside\n")
        bad = dict(good, artifacts=[{"path": "../../../outside.bin",
                                     "sha256": sha256(outside)}])
        with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(bad, fh, ensure_ascii=False)
        probs_bad, _ = check_case(case_dir, root)
        checks.append(("产物路径穿越被拒",
                       any("越出案例目录" in p for p in probs_bad)))

        bad = dict(good, refs=["https://example.test/SKILL.md"])
        with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(bad, fh, ensure_ascii=False)
        probs_bad, _ = check_case(case_dir, root)
        checks.append(("URL refs 被拒",
                       any("不是相对路径" in p for p in probs_bad)))

        bad = dict(good, refs=["../outside.txt"])
        with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(bad, fh, ensure_ascii=False)
        probs_bad, _ = check_case(case_dir, root)
        checks.append(("refs 仓库穿越被拒",
                       any("越出仓库根" in p for p in probs_bad)))

        boundary_probs, _ = check_case(root, root)
        checks.append(("案例目录边界被拒",
                       any("越过 Tool/cases" in p for p in boundary_probs)))
        malformed_pack = os.path.join(
            root, "Tool", "skill", "protocol-plugin", "pack.json")
        with open(malformed_pack, "w", encoding="utf-8") as fh:
            json.dump({"routes": "bad-string"}, fh)
        try:
            load_boundary(root)
            checks.append(("损坏 routes fail-closed", False))
        except BoundaryError as exc:
            checks.append(("损坏 routes fail-closed",
                           "routes" in str(exc)))

    rows, rproblems = run_routing(load_boundary())
    checks.append(("路由边界测试全过", not rproblems and len(rows) >= 9))
    checks.append(("不抢 spider/bios/principal",
                   all(not r["hit"] for r in rows
                       if any(w in r["text"] for w in ("spider", "bios", "principal")))))

    bad_checks = [n for n, ok in checks if not ok]
    print(json.dumps({
        "ok": not bad_checks, "self_test": True, "checks": len(checks),
        "passed": len(checks) - len(bad_checks), "failed": bad_checks,
        "routing_source": load_boundary()["source"],
    }, ensure_ascii=False))
    return 0 if not bad_checks else 1


# ------------------------------------------------------------------ main
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="protocol-plugin 域验收：案例 sha256/字段复算 + 路由词边界自检",
        epilog="退出码：0 全过；2 有 FAIL（JSON ok:false）。")
    ap.add_argument("--case", action="append", default=[],
                    help="指定案例目录（可重复）；缺省按 pack.json cases[]")
    ap.add_argument("--root", default="", help="仓库根（默认由 __file__ 推导）")
    ap.add_argument("--routing-check", action="store_true",
                    help="只跑路由片段 boundary_tests")
    ap.add_argument("--self-test", action="store_true",
                    help="离线自检：内置合规/违规案例 + 路由边界用例")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    out = {"ok": True}
    try:
        root = repo_root(args.root or None)
        declared = pack_cases(root)
        out["declared_cases"] = declared
        if args.routing_check or not args.case:
            boundary = load_boundary(root)
            rows, problems = run_routing(boundary)
            out["routing"] = {"source": boundary["source"],
                              "status": boundary.get("status"),
                              "merged_must": boundary["merged_must"],
                              "pattern": boundary["pattern"],
                              "rows": rows, "ok": not problems}
        else:
            problems = []
        if not args.routing_check:
            dirs = ([os.path.abspath(p) for p in args.case] if args.case else
                    [os.path.join(root, "Tool", "cases", name) for name in declared])
            if not dirs:
                raise RuntimeError("pack.json 没有声明任何可用案例")
            results, case_problems = run_cases(dirs, root)
            out["cases"] = results
            problems += case_problems
            out["case_count"] = len(results)
        out["problems"] = problems
        out["ok"] = not problems
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "blocked_at": "accept",
                          "reason": "%s: %s" % (type(exc).__name__, str(exc)[:160])},
                         ensure_ascii=False))
        return 2

    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        if "cases" in out:
            print("== 案例复算 ==")
            for r in out["cases"]:
                print("[%s] %-12s %s" % ("PASS" if r["ok"] else "FAIL",
                                        r["case"], "" if r["ok"] else "；".join(r["problems"])))
        if "routing" in out:
            print("== 路由边界（%s）==" % out["routing"]["source"])
            for r in out["routing"]["rows"]:
                print("[%s] %-6s %s" % ("PASS" if r["ok"] else "FAIL",
                                       r["expect"], r["text"]))
        print("\n结果: %s%s" % ("PASS" if out["ok"] else "FAIL",
                              "" if out["ok"] else "  ← " + "；".join(out["problems"][:5])))
    return 0 if out["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
