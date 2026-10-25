#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""route-playbook-parity.py —— 路由 ↔ 配方一致性门禁（D-P0-3）。

背景：同一句话必须落到同一个域。路由层（routing.json）与配方层
（Tool/playbooks/*.md 的触发词）各自演化时，会出现「路由判 A 域、配方判 B 域、
两边门禁都绿」的情况（例如 Unity IL2CPP）。

做法：
  [1] 取 domain_spec.ROUTING_TESTS 的句子（与路由串味测试同源）
  [2] 用 routing.json 复算路由结果（skill → 域目录）
  [3] 用配方触发词匹配同一句话，得到该句命中的配方
  [4] 查 Tool/config/playbook-domains.json，得到这些配方归属的域
  [5] 路由域不在「配方域 ∪ 该用例 expect_any」里 → FAIL

输出：{ok, schema, checks, bad:[{text, route, skill, playbooks, allowed}]}
退出码：0 全一致 / 1 有不一致 / 2 输入缺失。
"""
from __future__ import annotations

import argparse
import importlib.util
import io
import json
import os
import re
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

SCHEMA = "seep.route-playbook-parity/1"
HERE = os.path.dirname(os.path.abspath(__file__))
def _repo_root(start):
    """仓库根：向上找含 Tool/cases 的目录（S4 后位于 Tool/skill/<pack>/scripts/，固定层数会算错）。"""
    d = os.path.abspath(start)
    for _ in range(8):
        if os.path.isdir(os.path.join(d, "Tool", "cases")):
            return d
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return os.path.abspath(os.path.join(start, "..", "..", "..", ".."))


ROOT = _repo_root(HERE)


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def routing():
    """路由来自 pack.json（S3：routing.json 已删）。返回 (domain-gate 模块, routes, prio, fallback)。"""
    dg = _load_module(os.path.join(_repo_root(HERE), "Tool", "scripts", "domain-gate.py"), "dg_parity")
    import sys as _sys
    _sys.path.insert(0, os.path.join(_repo_root(HERE), "Tool", "scripts"))
    import route as route_mod
    res = route_mod.check()
    routes, prio = {}, []
    for i, (_p, pid, label, must) in enumerate(res.get("rows") or []):
        rid = "P%02d" % i
        routes[rid] = {"label": label, "skill": pid,
                       "keywords": [{"must": m} for m in must]}
        prio.append(rid)
    # 与执行器/门禁对齐：不再假设"未命中就落 softseep"（那是第五份域名单，
    # 也是"什么都绿"的根源）。未命中就是未命中。
    return dg, routes, prio, None


def triggers():
    """{playbook: [trigger...]}，取 `- 触发词：` 行。"""
    out = {}
    pdir = os.path.join(ROOT, "Tool", "playbooks")
    for fn in sorted(os.listdir(pdir)):
        if not fn.endswith(".md") or fn.startswith(("INDEX", "README")):
            continue
        text = io.open(os.path.join(pdir, fn), encoding="utf-8", errors="replace").read()
        m = re.search(r"(?m)^-\s*触发词[:：]\s*(.+)$", text)
        if not m:
            continue
        words = [w.strip() for w in re.split(r"[、,，;；]", m.group(1)) if w.strip()]
        out[fn[:-3]] = words
    return out


def _distinctive(words, freq, limit=2):
    keep = []
    for w in words:
        core = w.lower()
        if len(core) < 2:
            continue
        if freq.get(core, 0) > limit:
            continue
        keep.append(core)
    return keep


def _verdict(skill_dir, hit, expect_any, dom_map):
    """skill_dir 是否被配方域/期望域接受。"""
    allowed = set(expect_any or [])
    for pb in hit:
        allowed.update(dom_map.get(pb, []))
    return skill_dir in allowed, sorted(allowed)


def run(only_tests=None):
    dg, routes, prio, fallback = routing()
    books = triggers()
    dom_map = json.load(io.open(os.path.join(ROOT, "Tool", "config", "playbook-domains.json"),
                                encoding="utf-8"))["map"]
    freq = {}
    for words in books.values():
        for w in set(x.lower() for x in words):
            freq[w] = freq.get(w, 0) + 1

    tests = dg.ROUTING_TESTS
    if only_tests:
        tests = [t for t in tests if any(s in t["text"] for s in only_tests)]

    bad = []
    for t in tests:
        if not (t.get("expect_any") or []):
            # 空期望 = 这条说法本就该判不出来（内网/提权/非技术文本），
            # 配方一致性对它没有意义，跳过而不是硬判成 softseep。
            continue
        text = t["text"]
        rid, skill = dg._match_route(routes, prio, text, fallback)
        # S3：路由目标可能带归档前缀（_pending/ / safe-skills/），归一化成逻辑技能名
        _norm = (skill or "").replace("\\", "/")
        for _pre in ("_pending/safe-skills/", "_pending/"):
            if _norm.startswith(_pre):
                _norm = _norm[len(_pre):]
        skill_dir = _norm.split("/")[0]
        hit = []
        for pb, words in books.items():
            if any(w in text.lower() for w in _distinctive(words, freq)):
                hit.append(pb)
        if not hit:
            continue
        ok, allowed = _verdict(skill_dir, hit, t.get("expect_any"), dom_map)
        if not ok:
            bad.append({"text": text, "route": rid, "skill": skill_dir,
                        "playbooks": hit, "allowed": sorted(allowed)})
    return {"ok": not bad, "schema": SCHEMA, "tests": len(tests),
            "playbooks": len(books), "bad": bad}


def self_test():
    res = run()
    checks = [
        ("schema", res["schema"] == SCHEMA),
        ("tests>0", res["tests"] > 0),
        ("playbooks>=20", res["playbooks"] >= 20),
        ("report shape", isinstance(res["bad"], list)),
        ("负例：路由 forensics + 配方 apk-unpack 判不一致",
         _verdict("forensics-mobile", ["apk-unpack"], [], {"apk-unpack": ["apkseep"]})[0] is False),
        ("正例：路由 apkseep + 配方 apk-unpack 判一致",
         _verdict("apkseep", ["apk-unpack"], [], {"apk-unpack": ["apkseep"]})[0] is True),
        ("il2cpp 归 forensics-mobile", not any("il2cpp" in b["text"].lower() and
                                                b["skill"] != "forensics-mobile" for b in res["bad"])),
    ]
    failed = [n for n, ok in checks if not ok]
    print(json.dumps({"ok": not failed, "tool": "route-playbook-parity.py",
                      "checks": len(checks), "failures": failed}, ensure_ascii=False))
    return 0 if not failed else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="路由 ↔ 配方一致性门禁")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--only", nargs="*", help="只跑包含这些子串的用例")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    res = run(args.only)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print("route-playbook-parity: %s（%d 用例 / %d 配方 / 不一致 %d）"
              % ("PASS" if res["ok"] else "FAIL", res["tests"],
                 res["playbooks"], len(res["bad"])))
        for b in res["bad"]:
            print("  BAD 『%s』 route=%s skill=%s 配方=%s 允许=%s"
                  % (b["text"][:40], b["route"], b["skill"],
                     ",".join(b["playbooks"]), ",".join(b["allowed"])))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
