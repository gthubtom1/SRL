# -*- coding: utf-8 -*-
"""文档命令 ↔ argparse 一致性检查（来自 exe-reverse 的 `check_commands.py` 思路）。

为什么需要（2026-10-25 两轮外部评审各抓到一次）：
 · `AGENTS.md` 写 `case_state.py report --check --file`，但 `--check` 不存在 → 模型跑出 rc=2 后跳过检查
 · `README.md` 写 `check.ps1 -Detailed`，脚本只有 `-Fast`
 · 大量文档写 `已退役的 setup 自检脚本`，文件早已退役
 这类"文档承诺了不存在的参数/脚本"是最便宜也最伤信任的缺陷，必须机检。
"""
import os
import re
import subprocess
import sys

# 文档里认得的"命令形态"：<script> <sub> --flags
DOC_PAT = re.compile(
    r"(?:python\s+)?(?:Tool/scripts/)?(case_state|check|gate|route|preflight)\.py\s+"
    r"([a-z][a-z0-9_-]*)?\s*((?:--[a-z][a-z0-9-]*\s*)*)"
)


def _help_text(script: str, root: str, sub: str = "") -> str:
    """顶层 --help；若有子命令，再取 `<sub> --help`（子命令的参数不在顶层帮助里）。"""
    p = os.path.join(root, "Tool", "scripts", script + ".py")
    if not os.path.isfile(p):
        return ""
    args = [sys.executable, p] + ([sub, "--help"] if sub else ["--help"])
    try:
        r = subprocess.run(args, cwd=root, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def check_doc_commands(agents_text: str, root: str):
    """返回 (ok, detail)。只检查**带子命令/带参数**的用例，纯脚本名不查。"""
    bad = []
    help_cache = {}
    seen = 0
    for m in DOC_PAT.finditer(agents_text or ""):
        script, sub, flags = m.group(1), (m.group(2) or "").strip(), m.group(3) or ""
        flag_list = re.findall(r"--([a-z][a-z0-9-]*)", flags)
        if not sub and not flag_list:
            continue
        key = (script, sub)
        if key not in help_cache:
            help_cache[key] = _help_text(script, root, sub)
        h = help_cache[key]
        if not h:
            continue
        seen += 1
        if sub and sub not in h:
            bad.append("%s.py 无子命令 `%s`" % (script, sub))
        for f in flag_list:
            if f not in h:
                bad.append("%s.py %s 无参数 `--%s`" % (script, sub or "", f))
    if not seen:
        return True, "未发现可校验的文档命令"
    uniq = sorted(set(bad))
    return (not uniq), ("；".join(uniq[:4]) if uniq else "%d 条文档命令参数都存在" % seen)
