#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""doc-audit.py —— 通用文档治理审计（深清理 + 整理 + 遗留盘点）。

不是"删旧文件"的小工具，而是回答四个问题：
  1. 这一堆文档里，哪些是**入口**、哪些是**规格**、哪些是**历史**、哪些是**草稿**？
  2. 文档里还欠着哪些事（TODO / 待补 / 占位 / 后续）？——**遗留盘点**
  3. 哪些文档在互相打架（重复标题 / 高度重叠 / 多处入口）？
  4. 冷启动的读者能不能靠现有文档走到正确结论（死链 / 孤儿 / 索引缺失 / 版本过期）？

设计原则（为了能用在任何项目）：
  · 零依赖、零网络；不假设目录结构，一切通过 `--config` 或自动探测获得；
  · 只读：不修改、不移动、不删除任何文件；输出建议与报告，动手由人决定；
  · 每条发现都带「文件:行 + 原文片段」，可直接复核。

用法:
    python doc-audit.py --root .
    python doc-audit.py --root . --config doc-hygiene.json --report docs-audit.md
    python doc-audit.py --root . --json
    python doc-audit.py --root . --only DG07 DG02      # 只看遗留盘点与死链
    python doc-audit.py --self-test
退出码：0 无 error 级发现 / 1 有 error 级发现 / 2 输入错误。
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

DEFAULTS = {
    "entry_docs": ["README.md"],
    "index_docs": ["docs/README.md", "docs/index.md", "INDEX.md"],
    "history_dirs": ["docs/history", "history", "archive", "docs/archive"],
    "ignore": [".git", "node_modules", "vendor", "dist", "build", "__pycache__",
               ".venv", "venv", "target", ".next", "coverage"],
    "version_file": "VERSION",
    "history_markers": ["历史", "非现状", "归档", "deprecated", "historical", "not current"],
    "leftover_scope": [],          # 空=自动：根目录文件 + docs/ 下的文档
    "leftover_strong": ["TODO", "FIXME", "XXX", "HACK", "待办", "待补", "待做", "待完善",
                        "待实现", "未实现", "占位", "TBD"],
    "leftover_weak": ["后续", "下一步", "遗留", "暂不", "暂时不", "先不做", "以后再"],
    "stale_days": 365,
    "thin_doc_lines": 5,
    "dup_overlap": 0.7,
    "quiet_dirs": [],
    "dead_path_allow": [],
    "orphan_allow": [],
    "thin_doc_allow": [],
    "link_sources": [],
    "leftover_skip_files": [],
    "leftover_checkbox_files": ["ROADMAP.md", "BACKLOG.md", "TODO.md", "plan.md", "PLAN.md"],
}

TEXT_EXT = (".md", ".markdown")
DATE_RE = re.compile(r"(20\d{2})[-/年.](\d{1,2})[-/月.](\d{1,2})")
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
BACKTICK_RE = re.compile(r"`([A-Za-z0-9_\-./\u4e00-\u9fff]{3,})`")
VER_RE = re.compile(r"(?:当前版本|当前|current version|version)\D{0,8}v?(\d+\.\d+(?:\.\d+)?)", re.I)


# ----------------------------------------------------------------- 工具
def cfg_load(path):
    c = dict(DEFAULTS)
    if path and os.path.isfile(path):
        try:
            user = json.load(io.open(path, encoding="utf-8-sig"))
            if isinstance(user, dict):
                c.update({k: v for k, v in user.items() if v is not None})
        except Exception as exc:  # noqa: BLE001
            raise SystemExit("[ERROR] 配置解析失败：%s（%s）" % (path, exc))
    return c


def walk_docs(root, cfg):
    out = []
    ig = tuple("/" + x.strip("/") + "/" for x in cfg["ignore"])
    for dp, dn, fn in os.walk(root):
        norm = dp.replace(os.sep, "/") + "/"
        if any(s in norm for s in ig) or "/.git/" in norm:
            dn[:] = []
            continue
        for f in fn:
            if f.lower().endswith(TEXT_EXT):
                out.append(os.path.join(dp, f))
    return sorted(out)


def read(p):
    with io.open(p, encoding="utf-8-sig", errors="replace") as f:
        return f.read()


def rel(root, p):
    return os.path.relpath(p, root).replace(os.sep, "/")


def first_heading(text):
    for ln in text.splitlines():
        if ln.startswith("#"):
            return ln.lstrip("#").strip()
    return ""


def headings(text):
    return [ln.strip() for ln in text.splitlines() if re.match(r"^#{2,3}\s", ln)]


def inbound_index(docs, root, cfg):
    """统计每篇文档被引用次数（markdown 链接 + 反引号路径）。"""
    known = {rel(root, d): d for d in docs}
    count = {k: 0 for k in known}
    import glob as _glob
    for pat in cfg.get("link_sources", []):
        for sp in _glob.glob(os.path.join(root, pat)):
            if not os.path.isfile(sp):
                continue
            try:
                txt = read(sp)
            except Exception:
                continue
            for m in re.finditer(r"[A-Za-z0-9_\-./]+\.md", txt):
                c = m.group(0).replace(os.sep, "/").lstrip("./")
                for cand in (c, "Tool/skill/" + c, "Tool/playbooks/" + c):
                    if cand in count:
                        count[cand] += 1
                        break
    for d in docs:
        try:
            t = read(d)
        except Exception:
            continue
        src = rel(root, d)
        for m in LINK_RE.finditer(t):
            tgt = m.group(1).split("#")[0].strip()
            if tgt.lower().endswith(TEXT_EXT) or tgt.endswith("/"):
                norm = os.path.normpath(os.path.join(os.path.dirname(src), tgt)).replace(os.sep, "/")
                if norm in count and norm != src:
                    count[norm] += 1
        for m in BACKTICK_RE.finditer(t):
            tgt = m.group(1).strip().rstrip("/")
            if not tgt.endswith(TEXT_EXT):
                continue
            cands = {tgt,
                     os.path.normpath(os.path.join(os.path.dirname(src), tgt)).replace(os.sep, "/")}
            for c in cands:
                if c in count and c != src:
                    count[c] += 1
                    break
    return count


# ----------------------------------------------------------------- 检查
def audit(root, cfg):
    docs = walk_docs(root, cfg)
    if not docs:
        return {"ok": False, "findings": [{"rule": "DG00", "severity": "error",
                                           "target": root, "detail": "没有找到任何 .md 文档"}]}
    entries = {rel(root, os.path.join(root, e)) for e in cfg["entry_docs"]
               if os.path.isfile(os.path.join(root, e))}
    indexes = {rel(root, os.path.join(root, i)) for i in cfg["index_docs"]
               if os.path.isfile(os.path.join(root, i))}
    hist_dirs = tuple(h.strip("/") for h in cfg["history_dirs"])
    inb = inbound_index(docs, root, cfg)
    corpus = ""
    for _d in docs:
        try:
            corpus += read(_d)
        except Exception:
            pass
    quiet = tuple(q.strip("/") for q in cfg.get("quiet_dirs", []))
    findings = []

    def add(rule, severity, target, detail, suggestion=""):
        findings.append({"rule": rule, "severity": severity, "target": target,
                         "detail": detail, "suggestion": suggestion})

    if not entries:
        add("DG01", "error", ", ".join(cfg["entry_docs"]),
            "找不到入口文档（配置 entry_docs）", "新建一个入口文档：这是什么 / 现在什么状态 / 先读哪几篇")

    # 逐篇扫描
    leftovers = []
    for d in docs:
        r = rel(root, d)
        try:
            t = read(d)
        except Exception:
            continue
        lines = t.splitlines()
        is_quiet = any(r.startswith(q + "/") for q in quiet)
        in_hist = any(r.startswith(h + "/") for h in hist_dirs)

        # quiet 目录：只检查「归档横幅」，其余规则跳过（避免把素材库/知识库刷成噪音）
        if is_quiet and not in_hist:
            continue

        # DG02/DG03 死链与死路径
        for m in LINK_RE.finditer(t):
            tgt = m.group(1).strip()
            if tgt.startswith(("http://", "https://", "mailto:", "#", "tel:")):
                continue
            raw = tgt.split("#")[0]
            cands = {os.path.normpath(os.path.join(os.path.dirname(r), raw)).replace(os.sep, "/"),
                     os.path.normpath(raw).replace(os.sep, "/")}
            if not any(os.path.exists(os.path.join(root, c)) for c in cands):
                add("DG02", "error", r, "链接指向不存在的文件：%s" % tgt, "改到真实路径或删除该链接")
                break
        for m in BACKTICK_RE.finditer(t):
            cand = m.group(1).strip().rstrip("/")
            if not re.search(r"[./]", cand) or cand.startswith(("http", "@")):
                continue
            if any(x in cand for x in ("<", ">", "*", "$")):
                continue
            if cand.startswith(("/", "~", "..")) or "xxx" in cand.lower():
                continue          # 系统路径 / 占位
            if any(a in cand for a in cfg.get("dead_path_allow", [])):
                continue
            head_seg = cand.split("/")[0]
            if not head_seg or not os.path.isdir(os.path.join(root, head_seg)):
                continue          # 不是仓库内路径（裸文件名 / owner/repo / 系统路径）
            if " " in cand or re.search(r"[*<>$|]", cand):
                continue
            if not os.path.exists(os.path.join(root, cand)):
                add("DG03", "warn", r, "正文引用的路径不存在：%s" % cand,
                    "确认是否已搬迁；搬迁则需要更新引用")
                break

        # DG04 孤儿（无任何入链，且不是入口/索引）
        dir_referenced = (os.path.basename(r).lower() == "readme.md"
                          and os.path.dirname(r) and os.path.dirname(r) in corpus)
        if (not in_hist) and r not in entries and r not in indexes and inb.get(r, 0) == 0                 and not dir_referenced                 and not any(a in r for a in cfg.get("orphan_allow", [])):
            if not any(r.startswith(h + "/") for h in hist_dirs):
                add("DG04", "warn", r, "没有任何文档引用它（孤儿文档）",
                    "把它挂进入口/索引，或确认是废弃件后归档/删除")

        # DG07 遗留盘点：只扫「规划文档区」（默认根目录文件 + docs/），
        # 技能/知识库/插件文档里的 TODO 是技术示例或判据术语，不是项目遗留。
        scope = cfg.get("leftover_scope") or []
        if scope:
            in_scope = any(r.startswith(s) for s in scope)
        else:
            in_scope = ("/" not in r) or r.startswith("docs/")
        skip_lf = (in_hist or not in_scope
                   or any(s in r for s in cfg.get("leftover_skip_files", [])))
        if not skip_lf:
            for i, ln in enumerate(lines, 1):
                s = ln.strip()
                hit = ""
                def mentioned(word):
                    # 「TODO」「待填」这类被引号包住的词是"提到它"，不是"要做它"
                    for a, b in (("「", "」"), ("“", "”"), ('"', '"'), ("`", "`")):
                        if a + word + b in ln:
                            return True
                    return False

                for w in cfg["leftover_strong"]:
                    if w in ln and not mentioned(w):
                        hit = w
                        break
                if not hit:
                    cb_files = cfg.get("leftover_checkbox_files") or []
                    unchecked = re.match(r"^[-*]\s*\[ \]\s*(.+)$", s)
                    # 未勾选清单一律算遗留，但只在「规划/待办类文档」里算；
                    # 规格/风格/评审模板里的清单是判据，不是项目遗留。
                    if unchecked and any(f in r for f in cb_files):
                        hit = "checkbox"
                    elif not unchecked:
                        for w in cfg["leftover_weak"]:
                            if w in ln and not mentioned(w):
                                hit = w
                                break
                        # 弱词只认列表项；引用块、表格行、散文一律不算
                        if hit and not s.startswith(("-", "*")):
                            hit = ""
                if hit:
                    leftovers.append({"file": r, "line": i, "word": hit, "text": s[:180]})

        # DG08 历史目录缺横幅
        if any(r.startswith(h + "/") for h in hist_dirs):
            head = "\n".join(lines[:15])
            if not any(m in head for m in cfg["history_markers"]):
                add("DG08", "warn", r, "归档/历史文档缺「历史/非现状」横幅",
                    "在标题下一行加一行横幅，并指向当前权威文档")

        # DG09 过期（文件 mtime 超过阈值）
        age = (time.time() - os.path.getmtime(d)) / 86400
        if (not in_hist) and age > cfg["stale_days"] and r not in entries:
            add("DG09", "info", r, "%.0f 天未改动（阈值 %d）" % (age, cfg["stale_days"]),
                "确认是否仍是现状；过期则归档或更新")

        # DG12 空壳
        body = [ln for ln in lines
                if ln.strip() and not ln.strip().startswith(("#", ">", "---"))]
        if (not in_hist) and len(body) < cfg["thin_doc_lines"]                 and not any(a in r for a in cfg.get("thin_doc_allow", [])):
            add("DG12", "info", r, "内容过少（正文 %d 行）" % len(body),
                "确认是否只剩指针价值；是则合并到别处")

    # DG05 重复标题
    title_map = {}
    for d in docs:
        h = first_heading(read(d))
        if h:
            title_map.setdefault(h.strip().lower(), []).append(rel(root, d))
    for h, paths in title_map.items():
        if len(paths) > 1:
            add("DG05", "warn", "、".join(paths), "重复的一级标题：%s" % h,
                "同一主题只留一份，其余改成一行指针")

    # DG06 高度重叠（H2/H3 集合 Jaccard）
    hs = {}
    for d in docs:
        s = {x.lower() for x in headings(read(d))}
        if len(s) >= 6:
            hs[rel(root, d)] = s
    names = sorted(hs)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            inter = len(hs[a] & hs[b])
            union = len(hs[a] | hs[b]) or 1
            if inter / union >= cfg["dup_overlap"]:
                add("DG06", "warn", "%s ↔ %s" % (a, b),
                    "章节重叠 %.0f%%（疑似同一份文档的两个版本）" % (100 * inter / union),
                    "保留较新/较全的一份，另一份合并或删除")

    # DG10 索引完整性
    if indexes:
        idx = next(iter(sorted(indexes)))
        t = read(os.path.join(root, idx))
        missing = [rel(root, d) for d in docs
                   if rel(root, d) != idx and rel(root, d) not in t
                   and os.path.dirname(rel(root, d)) == os.path.dirname(idx)]
        if missing:
            add("DG10", "warn", idx, "同目录下 %d 篇文档未进索引：%s"
                % (len(missing), "、".join(missing[:5])), "把新文档挂进索引，否则冷启动找不到")

    # DG11 版本过期
    vf = os.path.join(root, cfg["version_file"])
    if os.path.isfile(vf):
        ver = read(vf).strip()
        if ver:
            for d in docs:
                r = rel(root, d)
                if any(r.startswith(h + "/") for h in hist_dirs):
                    continue
                for m in VER_RE.finditer(read(d)):
                    if m.group(1) != ver:
                        add("DG11", "warn", r, "声称当前版本 %s，VERSION 是 %s" % (m.group(1), ver),
                            "改文档或确认该处是历史叙述")

    by_rule = {}
    for f in findings:
        by_rule.setdefault(f["rule"], 0)
        by_rule[f["rule"]] += 1
    errors = [f for f in findings if f["severity"] == "error"]
    return {
        "ok": not errors,
        "root": os.path.abspath(root),
        "docs": len(docs),
        "entries": sorted(entries),
        "indexes": sorted(indexes),
        "findings": findings,
        "leftovers": leftovers,
        "summary": {"docs": len(docs), "by_rule": by_rule,
                    "errors": len(errors), "leftovers": len(leftovers)},
    }


# ----------------------------------------------------------------- 报告
def render_report(res, cfg):
    L = []
    L.append("# 文档治理审计报告\n")
    L.append("> 由 `doc-audit.py` 只读生成：未修改任何文件。\n")
    L.append("## 1. 概览\n")
    L.append("| 项 | 值 |")
    L.append("| :-- | :-- |")
    L.append("| 根目录 | `%s` |" % res.get("root", ""))
    L.append("| 文档总数 | %d |" % res.get("docs", 0))
    L.append("| 入口文档 | %s |" % ("、".join("`%s`" % e for e in res.get("entries", [])) or "（未找到）"))
    L.append("| 索引文档 | %s |" % ("、".join("`%s`" % i for i in res.get("indexes", [])) or "（无）"))
    s = res.get("summary", {})
    L.append("| error 级发现 | %d |" % s.get("errors", 0))
    L.append("| 遗留条目（TODO/待补/占位…） | %d |" % s.get("leftovers", 0))
    L.append("")
    L.append("## 2. 遗留事项台账（先处理这一节）\n")
    if not res.get("leftovers"):
        L.append("未发现 TODO/待补/占位 类表述。\n")
    else:
        L.append("| # | 文件:行 | 关键词 | 原文 | 处理建议 |")
        L.append("| --: | :-- | :-- | :-- | :-- |")
        for i, it in enumerate(res["leftovers"], 1):
            L.append("| %d | `%s:%d` | %s | %s | 仍需要→进单一 backlog；已完成→删或改为结论；已放弃→标明原因 |"
                     % (i, it["file"], it["line"], it["word"], it["text"].replace("|", "\\|")))
        L.append("")
    L.append("## 3. 发现清单\n")
    if not res.get("findings"):
        L.append("无。\n")
    else:
        L.append("| 规则 | 级别 | 目标 | 说明 | 建议 |")
        L.append("| :-- | :-- | :-- | :-- | :-- |")
        for f in res["findings"]:
            L.append("| %s | %s | %s | %s | %s |" % (f["rule"], f["severity"], f["target"],
                                                     f["detail"].replace("|", "\\|"),
                                                     f.get("suggestion", "").replace("|", "\\|")))
        L.append("")
    L.append("## 4. 冷启动五问（人工核对，填完才算收工）\n")
    L.append("1. 这个项目是什么、现在什么状态？答案在哪份文件？（%s）" % ("入口文档" if res.get("entries") else "**缺入口**"))
    L.append("2. 新人第一步该读哪三篇？")
    L.append("3. 哪些文档是历史、不能当现状？（%s）" % "、".join("`%s`" % h for h in cfg["history_dirs"]))
    L.append("4. 现在还有什么没做完？答案在遗留台账的哪几行？")
    L.append("5. 想改代码前必须守哪些约定？写在哪份文件？")
    L.append("")
    return "\n".join(L)


def self_test() -> int:
    checks, failed = 0, []

    def expect(label, cond):
        nonlocal checks
        checks += 1
        if not cond:
            failed.append(label)

    def mk(root, files):
        for relp, text in files.items():
            p = os.path.join(root, relp)
            d = os.path.dirname(p)
            if d:
                os.makedirs(d, exist_ok=True)
            io.open(p, "w", encoding="utf-8").write(text)

    with tempfile.TemporaryDirectory() as tmp:
        good = os.path.join(tmp, "good")
        mk(good, {
            "README.md": "# Proj\n\nsee [docs/spec.md](docs/spec.md)\n",
            "VERSION": "1.2.3\n",
            "docs/README.md": "# idx\n\n- [spec.md](spec.md)\n",
            "docs/spec.md": "# Spec\n\n## a\n## b\n## c\n## d\n## e\n## f\n## g\n\n当前版本 1.2.3\n",
        })
        r = audit(good, cfg_load(None))
        expect("好仓库无 error", r["ok"] is True)

        bad = os.path.join(tmp, "bad")
        mk(bad, {
            "README.md": "# P\n\n缺链接 [gone](docs/none.md)\n\nTODO: 补部署说明\n",
            "docs/orphan.md": "# Orphan\n\nFIXME 这里还没写\n",
            "docs/old.md": "# Old\n\n历史的东西\n",
        })
        rb = audit(bad, cfg_load(None))
        rules = {f["rule"] for f in rb["findings"]}
        expect("死链被抓", "DG02" in rules)
        expect("孤儿被抓", "DG04" in rules)
        expect("遗留被抓", rb["summary"]["leftovers"] >= 2)
        expect("有 error 时 ok=false", rb["ok"] is False)

        dup = os.path.join(tmp, "dup")
        mk(dup, {
            "README.md": "# P\n\n- [a](a.md)\n- [b](b.md)\n",
            "a.md": "# Same\n\n## 1\n## 2\n## 3\n## 4\n## 5\n## 6\n",
            "b.md": "# Same\n\n## 1\n## 2\n## 3\n## 4\n## 5\n## 6\n",
        })
        rd = audit(dup, cfg_load(None))
        rules = {f["rule"] for f in rd["findings"]}
        expect("重复标题被抓", "DG05" in rules)
        expect("高度重叠被抓", "DG06" in rules)

        hist = os.path.join(tmp, "hist")
        mk(hist, {
            "README.md": "# P\n\n- [h](docs/history/h.md)\n",
            "docs/history/h.md": "# H\n\n没有横幅\n",
            "VERSION": "9.9.9\n",
            "docs/live.md": "# L\n\n见 [h](history/h.md)\n\n当前版本 1.0.0\n",
        })
        rh = audit(hist, cfg_load(None))
        rules = {f["rule"] for f in rh["findings"]}
        expect("归档缺横幅被抓", "DG08" in rules)
        expect("版本过期被抓", "DG11" in rules)

        scope_case = os.path.join(tmp, "scope")
        mk(scope_case, {
            "README.md": "# P\n\n- [d](docs/d.md)\n",
            "docs/d.md": "# D\n\nTODO: 真的项目待办\n",
            "skill/x/SKILL.md": "# S\n\n示例里出现 TODO 与占位，这是技术说明\n",
            "docs/plan.md": "# Plan\n\n- [ ] 还没做的清单项\n",
        })
        rs = audit(scope_case, cfg_load(None))
        files = {x["file"] for x in rs["leftovers"]}
        expect("范围外技术文档不算遗留", "skill/x/SKILL.md" not in files)
        expect("docs 里的 TODO 算遗留", "docs/d.md" in files)
        expect("未勾选清单算遗留", any(x["word"] == "checkbox" for x in rs["leftovers"]))

        rep = render_report(rb, cfg_load(None))
        expect("报告含遗留台账", "遗留事项台账" in rep)
        expect("报告含五问", "冷启动五问" in rep)

    print(json.dumps({"ok": not failed, "checks": checks, "failed": failed,
                      "tool": "doc-audit.py"}, ensure_ascii=False))
    return 0 if not failed else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="通用文档治理审计（只读）")
    ap.add_argument("--root", default=".", help="要审计的项目根目录（默认当前目录）")
    ap.add_argument("--config", default="")
    ap.add_argument("--report", default="", help="把 Markdown 报告写到该路径")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--only", nargs="*", default=[], help="只看这些规则（如 DG07 DG02）")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not os.path.isdir(args.root):
        print(json.dumps({"ok": False, "blocked_at": "root-missing", "root": args.root}, ensure_ascii=False))
        return 2

    cfg = cfg_load(args.config)
    res = audit(args.root, cfg)
    if args.only:
        res["findings"] = [f for f in res["findings"] if f["rule"] in args.only]
        res["ok"] = not [f for f in res["findings"] if f["severity"] == "error"]

    if args.report:
        p = os.path.abspath(args.report)
        d = os.path.dirname(p)
        if d:
            os.makedirs(d, exist_ok=True)
        io.open(p, "w", encoding="utf-8", newline="\n").write(render_report(res, cfg))
        print("[OK] 报告已写入 %s" % p)

    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        s = res["summary"]
        print("文档审计：%d 篇 / error %d / warn %d / info %d / 遗留 %d 条"
              % (s["docs"], s["errors"],
                 sum(1 for f in res["findings"] if f["severity"] == "warn"),
                 sum(1 for f in res["findings"] if f["severity"] == "info"),
                 s["leftovers"]))
        for f in res["findings"]:
            print("  [%-5s] %-9s %s — %s" % (f["severity"].upper(), f["rule"], f["target"], f["detail"]))
        if res["leftovers"]:
            print("\n遗留事项（前 10 条，完整见 --report）：")
            for it in res["leftovers"][:10]:
                print("  %s:%d  %s" % (it["file"], it["line"], it["text"][:100]))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
