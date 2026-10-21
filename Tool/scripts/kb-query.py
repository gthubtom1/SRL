#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kb-query.py —— 离线检索 reverselab KB（不联网）。

用法：
    python Tool/scripts/kb-query.py --since 2026 --limit 3
    python Tool/scripts/kb-query.py --board web-pentest --since 2026 --query cache --limit 10
    python Tool/scripts/kb-query.py --self-test

输出（stdout，一行 JSON）：
    {"ok": true, "hits": [{"board","path","line","title"}], "count": N}

年份来源：文件名里的 20xx 或 frontmatter 的 date/last_updated/updated/created。
--board 过滤 KB 下的板块目录；--query 做大小写不敏感的行匹配。
退出码：0 成功（含 0 命中）/ 2 参数错误或 KB 根缺失。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
KBROOT = os.path.join(ROOT, "Tool", "mcp", "Tool", "reverselab", "kb")
TEXT_EXT = {".md", ".markdown", ".txt", ".jsonl", ".json", ".yaml", ".yml"}
YEAR_RE = re.compile(r"(?<!\d)(20\d{2})(?!\d)")
DATE_KEYS = ("date", "last_updated", "updated", "created", "year")


def _frontmatter(text):
    """返回 (meta dict, body lines)。只解析简单 key: value，不依赖 YAML。"""
    if not text.startswith("---"):
        return {}, text.splitlines()
    lines = text.splitlines()
    meta = {}
    end = None
    for i in range(1, min(len(lines), 80)):
        if lines[i].strip() in ("---", "..."):
            end = i
            break
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*?)\s*$", lines[i])
        if m:
            meta[m.group(1).lower()] = m.group(2).strip().strip('"\'')
    if end is None:
        return {}, lines
    return meta, lines[end + 1:]


def _title(meta, body, path):
    for key in ("title", "name"):
        if meta.get(key):
            return meta[key]
    for line in body:
        m = re.match(r"^\s*#\s+(.+?)\s*$", line)
        if m:
            return m.group(1).strip()
    return os.path.splitext(os.path.basename(path))[0]


def _year(meta, path):
    for key in DATE_KEYS:
        m = YEAR_RE.search(str(meta.get(key) or ""))
        if m:
            return int(m.group(1))
    m = YEAR_RE.search(os.path.basename(path))
    return int(m.group(1)) if m else None


def _board(relpath):
    return relpath.replace(os.sep, "/").split("/")[0]


def _iter_files(kbroot):
    for dp, dns, fns in os.walk(kbroot):
        dns[:] = sorted(dns)
        for fn in sorted(fns):
            p = os.path.join(dp, fn)
            if os.path.splitext(fn)[1].lower() in TEXT_EXT:
                yield p


def query(kbroot=KBROOT, board="", since=0, limit=20, term=""):
    board = (board or "").strip().strip("/")
    term_l = (term or "").strip().lower()
    hits = []
    for path in _iter_files(kbroot):
        rel = os.path.relpath(path, kbroot).replace(os.sep, "/")
        b = _board(rel)
        if board and b != board and not rel.startswith(board + "/"):
            continue
        try:
            with open(path, encoding="utf-8-sig", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        meta, body = _frontmatter(text)
        year = _year(meta, path)
        if since and (year is None or year < since):
            continue
        title = _title(meta, body, path)
        if term_l:
            for no, line in enumerate(body, 1):
                if term_l in line.lower():
                    hits.append({"board": b, "path": rel, "line": no,
                                 "title": title, "_year": year})
        else:
            hits.append({"board": b, "path": rel, "line": 1,
                         "title": title, "_year": year})
    hits.sort(key=lambda h: (h["board"] == "_archive", -(h["_year"] or 0), h["path"], h["line"]))
    if limit and limit > 0:
        hits = hits[:limit]
    for h in hits:
        h.pop("_year", None)
    return hits


def self_test():
    checks = []
    tmp = tempfile.mkdtemp(prefix="kb-query-selftest-")
    os.makedirs(os.path.join(tmp, "alpha"))
    os.makedirs(os.path.join(tmp, "beta"))
    with open(os.path.join(tmp, "alpha", "2026-a.md"), "w", encoding="utf-8") as f:
        f.write("---\ntitle: Alpha 2026\nlast_updated: 2026-01-02\n---\n# Alpha\nNEEDLE evidence\n")
    with open(os.path.join(tmp, "alpha", "2024-b.md"), "w", encoding="utf-8") as f:
        f.write("---\ntitle: Alpha old\ndate: 2024-01-01\n---\nneedle old\n")
    with open(os.path.join(tmp, "beta", "2026-c.md"), "w", encoding="utf-8") as f:
        f.write("---\ntitle: Beta 2026\nupdated: 2026-03-04\n---\nneedle beta\n")

    h1 = query(tmp, board="alpha", since=2026, limit=10, term="needle")
    checks.append(("board+since", len(h1) == 1 and h1[0]["path"] == "alpha/2026-a.md"
                   and h1[0]["board"] == "alpha" and h1[0]["line"] > 1))
    h2 = query(tmp, since=2026, limit=10, term="NEEDLE")
    checks.append(("casefold+multi", len(h2) == 2 and all("2026" in h["path"] for h in h2)))
    h3 = query(tmp, since=2026, limit=1, term="needle")
    checks.append(("limit", len(h3) == 1))
    h4 = query(tmp, since=2026, limit=10, term="")
    checks.append(("no-query-one-per-doc", len(h4) == 2 and all(h["line"] == 1 for h in h4)))
    checks.append(("schema", all(set(h) == {"board", "path", "line", "title"} for h in h1 + h2 + h3 + h4)))
    failed = [name for name, ok in checks if not ok]
    print(json.dumps({"ok": not failed, "tool": "kb-query.py", "checks": len(checks),
                      "failed": failed, "note": "temp KB fixtures; no network"},
                     ensure_ascii=False))
    return 0 if not failed else 2


def main(argv=None):
    p = argparse.ArgumentParser(description="离线检索 reverselab KB，输出 JSON")
    p.add_argument("--board", default="", help="板块目录，如 web-pentest / ad-cloud / supply-chain")
    p.add_argument("--since", type=int, default=0, help="只保留 >= 该年份的文档（如 2026）")
    p.add_argument("--limit", type=int, default=20, help="最多返回多少条命中（默认 20）")
    p.add_argument("--query", default="", help="行内关键词（大小写不敏感）")
    p.add_argument("--self-test", action="store_true", help="内置夹具自检，不联网")
    a = p.parse_args(argv)
    if a.self_test:
        return self_test()
    if a.limit < 1:
        print(json.dumps({"ok": False, "hits": [], "count": 0,
                          "error": "--limit 必须 >= 1"}, ensure_ascii=False))
        return 2
    if not os.path.isdir(KBROOT):
        print(json.dumps({"ok": False, "hits": [], "count": 0,
                          "error": "KB 根不存在: %s" % KBROOT}, ensure_ascii=False))
        return 2
    hits = query(KBROOT, a.board, a.since, a.limit, a.query)
    out = {"ok": True, "hits": hits, "count": len(hits)}
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
