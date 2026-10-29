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
from pathlib import Path

# 文档里认得的"命令形态"：<script> <sub> --flags
DOC_PAT = re.compile(
    r"(?:python[ \t]+)?(?:Tool/scripts/)?(case_state|check|gate|route|preflight)\.py[ \t]+"
    r"([a-z][a-z0-9_-]*)?[ \t]*((?:--[a-z][a-z0-9-]*[ \t]*)*)"
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
        seen += 1
        if not h:
            bad.append("%s.py %s 无法读取 --help" % (script, sub or ""))
            continue
        if sub and sub not in h:
            bad.append("%s.py 无子命令 `%s`" % (script, sub))
        for f in flag_list:
            if f not in h:
                bad.append("%s.py %s 无参数 `--%s`" % (script, sub or "", f))
    if not seen:
        return True, "未发现可校验的文档命令"
    uniq = sorted(set(bad))
    return (not uniq), ("；".join(uniq[:4]) if uniq else "%d 条文档命令参数都存在" % seen)


def check_install_entries(root):
    """Validate maintained guides without executing installation commands.

    Local Markdown links and concrete script paths are checked across the guide
    trees. Runnable snippets are compared with setup declarations or CLI help;
    only known read-only argparse help entry points may be started.
    """
    root = Path(root).resolve()
    files = [root / p for p in ("README.md", "README.zh.md", "README.en.md",
                                "REQUIREMENTS.md", "ROADMAP.md", "KPI.md")]
    files += [p for folder in ("docs", "MANUAL", "Tool/docs")
              for p in (root / folder).rglob("*.md")]
    files += [root / "Tool/prompts" / name for name in ("AGENTS.md", "SEEP.md")]
    files += [root / "Tool/prompts/contracts" / name
              for name in ("AGENTS.md", "CLAUDE.md", "DSH-PROFILE.md")]
    errors = []
    seen = set()
    help_cache = {}
    declarations = {}
    help_scripts = {"check", "mcp-doctor", "tool-acquire", "skill-import", "route",
                    "domain-contract-check", "domain-adapter-check", "tool-contract-check"}
    script_re = re.compile(r"(?<![\w/])((?:Tool[/\\]scripts|setup)[/\\][\w./\\-]+\.(?:py|ps1|sh))\b")
    command_re = re.compile(r"((?:Tool[/\\]scripts|setup)[/\\][\w-]+\.(py|ps1|sh))\b([^`\n;#]*)")

    def issue(path, line, message):
        errors.append({"file": path.relative_to(root).as_posix(), "line": line, "message": message})

    for path in sorted(set(files)):
        fence = False
        for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            for match in re.finditer(r"(?<!!)\[[^\]\n]+\]\(([^)\n]+)\)", line):
                target = match.group(1).strip().strip("<>").split("#", 1)[0]
                if target and not re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", target):
                    from urllib.parse import unquote
                    if not (path.parent / unquote(target)).exists():
                        issue(path, number, "missing link: " + target)
            if line.lstrip().startswith("```"):
                fence = not fence
                continue
            snippets = [line] if fence else re.findall(r"`([^`\n]+)`", line)
            for snippet in snippets:
                for match in script_re.finditer(snippet):
                    rel = match.group(1).replace("\\", "/")
                    if not (root / rel).is_file():
                        issue(path, number, "missing script: " + rel)
                for match in command_re.finditer(snippet):
                    rel, kind, tail = match.groups()
                    rel = rel.replace("\\", "/")
                    target = root / rel
                    if not target.is_file():
                        continue
                    if kind == "ps1":
                        if rel not in declarations:
                            source = target.read_text(encoding="utf-8-sig")
                            block = re.search(r"(?ims)^\s*param\s*\((.*?)^\)", source)
                            declarations[rel] = (set(re.findall(r"\$(\w+)", block.group(1).lower()))
                                                 if block else set())
                        flags = re.findall(r"(?<![\w-])-([a-zA-Z][a-zA-Z0-9]*)\b", tail)
                        allowed = declarations[rel] | {"verbose", "debug", "erroraction", "warningaction"}
                        for flag in flags:
                            if flag.lower() not in allowed:
                                issue(path, number, f"{rel} has no parameter -{flag}")
                    elif kind == "sh":
                        if rel not in declarations:
                            source = target.read_text(encoding="utf-8-sig")
                            # Options actually handled by a shell case branch.
                            declarations[rel] = set(re.findall(r"--[a-z][a-z-]*", "\n".join(
                                row.split(")", 1)[0] for row in source.splitlines()
                                if re.match(r"\s*-[-\w|]+\)", row))))
                        flags = re.findall(r"--[a-z][a-z-]*", tail)
                        for flag in flags:
                            if flag not in declarations[rel]:
                                issue(path, number, f"{rel} has no option {flag}")
                    elif target.stem in help_scripts:
                        sub = re.match(r"\s+([a-z][\w-]*)\b", tail)
                        sub = sub.group(1) if sub and target.stem == "skill-import" else ""
                        # A notation listing alternatives is not a runnable command.
                        if sub and re.match(r"\s+" + re.escape(sub) + r"[|/]", tail):
                            continue
                        key = (target.stem, sub)
                        if key not in help_cache:
                            help_cache[key] = _help_text(target.stem, str(root), sub)
                        help_text = help_cache[key]
                        if not help_text or "usage:" not in help_text.lower():
                            issue(path, number, f"help unavailable for {rel} {sub}")
                        else:
                            known = set(re.findall(r"--[a-z][a-z0-9-]*", help_text))
                            for flag in re.findall(r"--[a-z][a-z0-9-]*", tail):
                                if flag not in known:
                                    issue(path, number, f"{rel} {sub} has no option {flag}")
                    else:
                        continue
                    seen.add((rel, tail.strip()))
    return {"ok": not errors, "files": len(set(files)), "command_examples": len(seen), "errors": errors}


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Check maintained installation/document entry points")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = check_install_entries(Path(__file__).resolve().parents[3])
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else str(result))
    raise SystemExit(0 if result["ok"] else 1)
