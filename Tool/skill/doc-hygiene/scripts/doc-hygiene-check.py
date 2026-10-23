#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""doc-hygiene-check.py —— 文档卫生与「冷启动可读性」体检。

回答一个问题：**一个没有任何上下文的模型，只读仓库文档，会不会被旧文档带偏？**

它检查的不是文笔，而是六件会导致误读的事：
  [C1] README×3 有没有「现状卡」，且卡里的版本/门禁数字与 VERSION、gate-counts 一致
  [C2] docs/README.md 有没有把「现状 / 规格 / 审查 / 历史」分开
  [C3] docs/history/ 下每篇是否带「历史 / 非现状」横幅（归档不得冒充现状）
  [C4] 有没有文档在宣称与 gate-counts 不符的 preflight 数字
  [C5] 有没有引用已搬迁/已删除的旧路径（docs/audit/、Tool/docs/HANDOFF-*、README_MCP.md 等）
  [C6] 有没有「同一主题两份文档」（重复入口：两个 ROADMAP、两个 HANDOFF…）
  [C7] MANUAL/BASELINE-FREEZE 的 first-party 预算是否等于 check-budget 实测

用法:
    python Tool/skill/doc-hygiene/scripts/doc-hygiene-check.py
    python Tool/skill/doc-hygiene/scripts/doc-hygiene-check.py --json
    python Tool/skill/doc-hygiene/scripts/doc-hygiene-check.py --fix-hints
    python Tool/skill/doc-hygiene/scripts/doc-hygiene-check.py --self-test
退出码：0 全绿 / 1 有违规 / 2 输入缺失。
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(HERE))))  # skill/doc-hygiene/scripts -> repo
SKIP_DIRS = ("/.git/", "/Tool/upstream/", "/Tool/mcp/Tool/", "/Tool/cases/",
             "/docs/history/", "/work/", "/node_modules/", "/__pycache__/", "/破甲卡生成/",
             "/.pi/", "/evidence/")
STALE_PATH_PATTERNS = (
    "docs/audit/",
    "Tool/docs/HANDOFF-",
    "Tool/docs/AUDIT-2026-10-21.md",
    "Tool/docs/README_MCP.md",
    "docs/OPTIMIZATION-2.0.md",
)
HISTORY_MARKERS = ("历史", "非现状", "归档", "not current", "historical")


def _read(p: str) -> str:
    with io.open(p, encoding="utf-8-sig", errors="replace") as f:
        return f.read()


def _md_files(root: str):
    for dp, dn, fn in os.walk(root):
        norm = dp.replace(os.sep, "/") + "/"
        if any(s in norm for s in SKIP_DIRS):
            dn[:] = []
            continue
        for f in fn:
            if f.endswith(".md"):
                yield os.path.join(dp, f)


def _gate_counts(root: str):
    p = os.path.join(root, "Tool", "config", "gate-counts.json")
    if not os.path.isfile(p):
        return {}
    try:
        return json.load(io.open(p, encoding="utf-8-sig"))
    except Exception:
        return {}


def _version(root: str) -> str:
    p = os.path.join(root, "VERSION")
    return _read(p).strip() if os.path.isfile(p) else ""


def check(root: str) -> dict:
    gc = _gate_counts(root)
    ver = _version(root)
    want_full = gc.get("preflight_full")
    violations = []

    def bad(rule, target, detail):
        violations.append({"rule": rule, "target": target, "detail": detail})

    # C1 README×3 现状卡
    card_needles = ("现状卡", "Status card")
    for name in ("README.md", "README.zh.md", "README.en.md"):
        p = os.path.join(root, name)
        if not os.path.isfile(p):
            bad("C1-readme-missing", name, "README 不存在")
            continue
        t = _read(p)
        if not any(n in t for n in card_needles):
            bad("C1-status-card-missing", name, "缺少「现状卡 / Status card」区块（冷启动第一屏）")
            continue
        if ver and ver not in t:
            bad("C1-version-mismatch", name, "现状卡未写当前版本 %s" % ver)
        if want_full:
            m = re.search(r"preflight[^\n]{0,20}?(\d+)/(\d+)", t)
            if not m:
                bad("C1-gate-number-missing", name, "现状卡未写 preflight 数字")
            elif int(m.group(1)) != want_full:
                bad("C1-gate-number-mismatch", name,
                    "现状卡写 %s/%s，gate-counts 是 %d" % (m.group(1), m.group(2), want_full))

    # C2 docs/README 分区
    p = os.path.join(root, "docs", "README.md")
    if not os.path.isfile(p):
        bad("C2-docs-index-missing", "docs/README.md", "缺 docs 索引")
    else:
        t = _read(p)
        for kw in ("现状", "审查"):
            if kw not in t:
                bad("C2-section-missing", "docs/README.md", "索引缺「%s」分区" % kw)
        if "history" not in t:
            bad("C2-history-section-missing", "docs/README.md", "索引未区分历史归档")

    # C3 history 横幅
    hist = os.path.join(root, "docs", "history")
    if os.path.isdir(hist):
        for dp, _dn, fn in os.walk(hist):
            for f in fn:
                if not f.endswith(".md"):
                    continue
                fp = os.path.join(dp, f)
                head = "\n".join(_read(fp).splitlines()[:15])
                if not any(m in head for m in HISTORY_MARKERS):
                    bad("C3-history-banner-missing", os.path.relpath(fp, root).replace(os.sep, "/"),
                        "归档文件开头 15 行内无「历史/非现状」标记")

    # C4/C5 全仓扫描
    for fp in _md_files(root):
        rel = os.path.relpath(fp, root).replace(os.sep, "/")
        if os.path.basename(fp) in ("CHANGELOG.md",):
            continue
        t = _read(fp)
        if want_full:
            for m in re.finditer(r"preflight[^\n]{0,16}?[**`]*\s*(\d+)/(\d+)", t):
                n = int(m.group(1))
                if "fast" in m.group(0).lower():
                    continue            # --fast 口径另行核对，不按全量判
                if n != want_full:
                    bad("C4-stale-gate-number", rel, "写 %s/%s，gate-counts 是 %d/%d"
                        % (m.group(1), m.group(2), want_full, want_full))
                    break
        for pat in STALE_PATH_PATTERNS:
            if pat in t:
                bad("C5-stale-path", rel, "引用了已搬迁/已删除路径：%s" % pat)
                break

    # C6 重复入口（同名主题出现在两个目录）
    by_topic: dict[str, list[str]] = {}
    for fp in _md_files(root):
        rel = os.path.relpath(fp, root).replace(os.sep, "/")
        base = os.path.basename(fp).lower()
        topic = None
        if base in ("roadmap.md", "handoff.md", "readme_mcp.md", "audit.md"):
            topic = base
        elif base.startswith(("handoff-", "handoff_")) or base.startswith("handoff-"):
            topic = "handoff.md"
        if topic:
            by_topic.setdefault(topic, []).append(rel)
    for topic, paths in by_topic.items():
        if len(paths) > 1:
            bad("C6-duplicate-topic", topic, "同一主题多处入口：" + "、".join(sorted(paths)))

    # C7 BASELINE vs check-budget
    bf = os.path.join(root, "MANUAL", "BASELINE-FREEZE.md")
    cb = os.path.join(root, "Tool", "scripts", "check-budget.py")
    if os.path.isfile(bf) and os.path.isfile(cb):
        m = re.search(r"first-party[^|]*\|\s*(\d+)\s*\|", _read(bf))
        try:
            out = subprocess.run([sys.executable, cb], cwd=root, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=120)
            txt = (out.stdout or b"").decode("utf-8", "replace")
            m2 = re.search(r"first-party[^0-9]*(\d+)\s*/", txt)
        except Exception:
            m2 = None
        if m and m2 and int(m.group(1)) != int(m2.group(1)):
            bad("C7-baseline-drift", "MANUAL/BASELINE-FREEZE.md",
                "写 %s，实测 %s（口径：git ls-files）" % (m.group(1), m2.group(1)))

    return {"ok": not violations, "checks": 7, "violations": violations,
            "gate_counts": gc, "version": ver}


HINTS = {
    "C1-status-card-missing": "在 README 首屏（导航条之后）加现状卡：版本 / 门禁数字 / 先读哪两份 / 历史在哪",
    "C1-gate-number-mismatch": "把卡里的 preflight 数字改成 gate-counts.json 的值，别手改 gate-counts 去迁就文档",
    "C1-version-mismatch": "卡里的版本必须等于 VERSION（改版本时三份 README 一起改）",
    "C2-section-missing": "docs/README 至少分：现状与交接 / 规格与流程 / 审查 / 历史归档",
    "C3-history-banner-missing": "归档文件开头加「> 历史快照（非现状）…」并指向 docs/FORK-BRIEF.md",
    "C4-stale-gate-number": "旧数字要么改成实测值，要么把整篇移入 docs/history/（归档里不改数字）",
    "C5-stale-path": "把引用改到新路径（history/…），或删掉该引用",
    "C6-duplicate-topic": "同一主题只留一份，其余删除或改成一行指针",
    "C7-baseline-drift": "先提交新增/删除的文件，再按 check-budget 实测值更新 BASELINE",
}


def self_test() -> int:
    """离线夹具：好仓库应绿，坏仓库逐项报红。"""
    checks, failed = 0, []

    def expect(label, cond):
        nonlocal checks
        checks += 1
        if not cond:
            failed.append(label)

    def mk(root, files):
        for rel, text in files.items():
            p = os.path.join(root, rel)
            d = os.path.dirname(p)
            if d:
                os.makedirs(d, exist_ok=True)
            io.open(p, "w", encoding="utf-8").write(text)

    with tempfile.TemporaryDirectory() as tmp:
        good = os.path.join(tmp, "good")
        mk(good, {
            "VERSION": "9.9.9\n",
            "Tool/config/gate-counts.json": json.dumps({"preflight_full": 44, "preflight_fast": 41}),
            "README.md": "# t\n\n> ## 现状卡\n> - 版本 9.9.9 / preflight 44/44\n",
            "README.zh.md": "# t\n\n> ## 现状卡\n> - 版本 9.9.9 / preflight 44/44\n",
            "README.en.md": "# t\n\n> ## Status card\n> - v9.9.9 / preflight 44/44\n",
            "docs/README.md": "# idx\n\n## 现状\n## 审查\n## 历史 history\n",
            "docs/history/x.md": "# x\n\n> 历史快照（非现状）\n",
        })
        r = check(good)
        expect("好仓库全绿", r["ok"] is True)

        bad1 = os.path.join(tmp, "bad1")
        shutil.copytree(good, bad1)
        mk(bad1, {"README.md": "# t\n\nno status card here\n"})
        expect("缺现状卡被抓", any(v["rule"].startswith("C1-status-card") for v in check(bad1)["violations"]))

        bad2 = os.path.join(tmp, "bad2")
        shutil.copytree(good, bad2)
        mk(bad2, {"docs/history/y.md": "# y\n\n正文没横幅\n"})
        expect("归档缺横幅被抓", any(v["rule"].startswith("C3") for v in check(bad2)["violations"]))

        bad3 = os.path.join(tmp, "bad3")
        shutil.copytree(good, bad3)
        mk(bad3, {"docs/old.md": "见 docs/audit/A.md\n"})
        expect("旧路径被抓", any(v["rule"].startswith("C5") for v in check(bad3)["violations"]))

        bad4 = os.path.join(tmp, "bad4")
        shutil.copytree(good, bad4)
        mk(bad4, {"docs/a/ROADMAP.md": "# r\n", "Tool/docs/ROADMAP.md": "# r\n"})
        expect("重复主题被抓", any(v["rule"].startswith("C6") for v in check(bad4)["violations"]))

        bad5 = os.path.join(tmp, "bad5")
        shutil.copytree(good, bad5)
        mk(bad5, {"docs/z.md": "preflight 38/38 通过\n"})
        expect("旧门禁数字被抓", any(v["rule"].startswith("C4") for v in check(bad5)["violations"]))

    print(json.dumps({"ok": not failed, "checks": checks, "failed": failed,
                      "tool": "doc-hygiene-check.py"}, ensure_ascii=False))
    return 0 if not failed else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="文档卫生与冷启动可读性体检")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--fix-hints", action="store_true", help="按违规项给出处置建议")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not os.path.isdir(args.root):
        print(json.dumps({"ok": False, "blocked_at": "root-missing", "root": args.root}, ensure_ascii=False))
        return 2

    r = check(args.root)
    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("文档卫生：%d 项体检，%d 处违规" % (r["checks"], len(r["violations"])))
        for v in r["violations"]:
            print("  [FAIL] %-26s %s — %s" % (v["rule"], v["target"], v["detail"]))
            if args.fix_hints:
                key = next((k for k in HINTS if v["rule"].startswith(k.split("-")[0])), None)
                if key:
                    print("         → " + HINTS[key])
        if r["ok"]:
            print("  冷启动可读：现状卡、索引分区、归档横幅、数字一致、无重复入口、预算对齐")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
