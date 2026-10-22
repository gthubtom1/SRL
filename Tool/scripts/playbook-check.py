#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""playbook-check.py —— 配方（playbook）命令门禁。

它回答一个问题：**`Tool/playbooks/*.md` 的「步骤」里写的命令还能不能照抄就跑？**
做法：
  [1] 逐篇取「步骤」行里的反引号代码段
  [2] 只保留以 `python ` 开头的片段（其余如 powershell / 路径 / 字段名不计）
  [3] 每条命令解析出脚本路径，先校验脚本文件存在
  [4] 用 AST 读出目标脚本的 argparse 声明（`--flag` 与 `choices`），
      对**所有**命令（含占位命令）校验参数名存在、枚举值合法
  [5] 不带占位的命令再实跑 `--help`，要求 rc=0

输出：`{ok, total, bad:[{playbook,cmd,reason}]}`。
`total` 是被检查的命令条数（按配方内去重），`bad` 是脚本缺失或 `--help` 非 0 的条目。

用法：
    python Tool/scripts/playbook-check.py
    python Tool/scripts/playbook-check.py --json
    python Tool/scripts/playbook-check.py --self-test
    python Tool/scripts/playbook-check.py --root <repo> --playbooks-dir <dir>
退出码：0 全绿 / 1 有坏命令 / 2 输入缺失。
"""

from __future__ import annotations

import argparse
import ast
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
import warnings

warnings.filterwarnings("ignore", category=SyntaxWarning)

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

SCHEMA = "seep.playbook-check/1"
CODE_RE = re.compile(r"`([^`\n]+)`")
PLACEHOLDER_RE = re.compile(r"<[^<>\s]+>")
STEP_RE = re.compile(r"^\s*(?:[-*+]\s*)?(?:#{1,6}\s*)?步骤\s*[:：]")
PY_RE = re.compile(r"\bpython3?\b")
SKIP_FILES = ("INDEX.md", "README.md")
TIMEOUT = 30


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:
        return path.replace(os.sep, "/")


def step_lines(text: str) -> list[str]:
    """取「步骤」行；兼容 `- 步骤：…`、`## 步骤` 与整段以「步骤」开头。"""
    out = []
    for line in text.splitlines():
        if STEP_RE.match(line):
            out.append(line)
    return out


def extract_commands(md_text: str) -> list[str]:
    """从步骤行抽 `python ...` 片段，按出现顺序去重。"""
    seen, out = set(), []
    for line in step_lines(md_text):
        for span in CODE_RE.findall(line):
            m = PY_RE.search(span)
            if not m:
                continue
            cmd = " ".join(span[m.start():].split())
            if cmd in seen:
                continue
            seen.add(cmd)
            out.append(cmd)
    return out


def script_token(cmd: str) -> str:
    parts = cmd.split()
    return parts[1] if len(parts) > 1 else ""


def check_command(cmd: str, root: str) -> dict:
    """返回 {cmd, reason, skipped}；reason 为空表示通过。"""
    token = script_token(cmd)
    if not token:
        return {"cmd": cmd, "reason": "命令缺少脚本路径", "skipped": False}
    if token.startswith("-"):
        return {"cmd": cmd, "reason": "命令以 python 选项开头（-m/-c），无脚本文件可检", "skipped": False}
    target = token if os.path.isabs(token) else os.path.join(root, token.replace("/", os.sep))
    if not os.path.isfile(target):
        return {"cmd": cmd, "reason": "脚本不存在: " + token, "skipped": False}
    problems = flag_problems(cmd, target)
    if problems:
        return {"cmd": cmd, "reason": problems, "skipped": False}
    if PLACEHOLDER_RE.search(cmd):
        return {"cmd": cmd, "reason": "", "skipped": True}
    try:
        proc = subprocess.run([sys.executable, target, "--help"], cwd=root,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"cmd": cmd, "reason": "无法执行 --help: " + str(exc)[:80], "skipped": False}
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or b"").decode("utf-8", "replace").strip().splitlines()
        tail = ("；" + err[-1][:120]) if err else ""
        return {"cmd": cmd, "reason": "--help rc=%d%s" % (proc.returncode, tail), "skipped": False}
    return {"cmd": cmd, "reason": "", "skipped": False}


def run_check(playbooks_dir: str, root: str) -> dict:
    files = sorted(p for p in glob.glob(os.path.join(playbooks_dir, "*.md"))
                   if os.path.basename(p) not in SKIP_FILES)
    result = {
        "ok": False,
        "schema": SCHEMA,
        "playbooks_dir": rel(playbooks_dir, root),
        "playbooks": len(files),
        "total": 0,
        "skipped_placeholders": 0,
        "bad": [],
    }
    if not files:
        result["error"] = "配方目录为空或不存在: " + rel(playbooks_dir, root)
        return result
    for path in files:
        name = os.path.splitext(os.path.basename(path))[0]
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            text = fh.read()
        commands = extract_commands(text)
        for cmd in commands:
            report = check_command(cmd, root)
            result["total"] += 1
            if report["skipped"]:
                result["skipped_placeholders"] += 1
            if report["reason"]:
                result["bad"].append({"playbook": name, "cmd": cmd,
                                      "reason": report["reason"]})
    # README 索引与磁盘配方必须一致（README 是人的入口，漏行=同一说法两个答案）
    readme = os.path.join(playbooks_dir, "README.md")
    disk = {os.path.basename(p)[:-3] for p in files}
    if os.path.isfile(readme):
        txt = open(readme, encoding="utf-8", errors="replace").read()
        listed = {m.group(1) for m in re.finditer(r"\[([a-z0-9][a-z0-9-]+)\]\(([a-z0-9-]+)\.md\)", txt)
                  if m.group(1) == m.group(2)}
        missing, extra = sorted(disk - listed), sorted(listed - disk)
        m = re.search(r"## 索引（(\d+) 个）", txt)
        count_ok = bool(m) and int(m.group(1)) == len(disk)
        if missing or extra or not count_ok:
            result["bad"].append({
                "playbook": "README",
                "cmd": "Tool/playbooks/README.md",
                "reason": "索引与磁盘不一致：缺 %s；多 %s；表头计数 %s（磁盘 %d）"
                          % (missing or "-", extra or "-",
                             m.group(1) if m else "缺失", len(disk))})

    result["ok"] = not result["bad"]
    return result


def render_text(res: dict) -> str:
    lines = ["playbook-check: %s" % ("PASS" if res["ok"] else "FAIL")]
    if res.get("error"):
        lines.append("  " + res["error"])
        return "\n".join(lines)
    lines.append("配方 %d 篇 / 命令 %d 条 / 占位跳过 %d / 坏命令 %d"
                 % (res["playbooks"], res["total"],
                    res["skipped_placeholders"], len(res["bad"])))
    for item in res["bad"]:
        lines.append("  BAD [%s] %s" % (item["playbook"], item["cmd"][:120]))
        lines.append("      -> %s" % item["reason"])
    return "\n".join(lines)


def self_test() -> int:
    """临时夹具：好命令 / 缺脚本 / 占位跳过 / --help 非 0。"""
    checks, bad = 0, []

    def expect(label, cond):
        nonlocal checks
        checks += 1
        if not cond:
            bad.append(label)

    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "root")
        books = os.path.join(root, "Tool", "playbooks")
        scripts = os.path.join(root, "Tool", "scripts")
        os.makedirs(books)
        os.makedirs(scripts)

        def write(path, text):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)

        write(os.path.join(scripts, "good.py"),
              "import sys\nprint('usage: good.py')\nsys.exit(0 if '--help' in sys.argv else 3)\n")
        write(os.path.join(scripts, "broken.py"),
              "import sys\nprint('boom', file=sys.stderr)\nsys.exit(4)\n")
        write(os.path.join(scripts, "level.py"),
              "import argparse\np=argparse.ArgumentParser()\n"
              "p.add_argument('--level', choices=['M1','M2','M3','M4'])\n"
              "p.add_argument('--json', action='store_true')\nargs=p.parse_args()\n")

        write(os.path.join(books, "alpha.md"), "\n".join([
            "# alpha",
            "- 触发词：alpha、占位",
            "- 步骤：1) `python Tool/scripts/good.py --fast` → rc=0；"
            "2) `python Tool/scripts/broken.py --file <SAMPLE>` → rc=0；"
            "3) `powershell -File Tool/x.ps1` → rc=0。",
            "- 判据（可机检）：rc=0。",
        ]))
        write(os.path.join(books, "beta.md"), "\n".join([
            "# beta",
            "- 步骤：1) `python Tool/scripts/missing.py --json` → rc=1；"
            "2) `python Tool/scripts/broken.py --json` → rc=1；"
            "3) `python -c print(1)` → rc=1。",
        ]))
        write(os.path.join(scripts, "die_style.py"),
              "import argparse\np=argparse.ArgumentParser()\n"
              "p.add_argument('--level')\nargs=p.parse_args()\n"
              "if args.level not in ('M1','M2','M3','M4'):\n"
              "    print('level \u53ea\u80fd\u662f M1 / M2 / M3 / M4'); raise SystemExit(2)\n")
        write(os.path.join(books, "gamma.md"), "\n".join([
            "# gamma",
            "- 步骤：1) `python Tool/scripts/level.py --level L2 --json` → rc=0（枚举非法）；"
            "2) `python Tool/scripts/level.py --nope <SAMPLE>` → rc=0（参数不存在）；"
            "3) `python Tool/scripts/die_style.py --level L2` → rc=2（运行时枚举，无 choices=）。",
        ]))
        write(os.path.join(books, "README.md"), "- 步骤：`python Tool/scripts/missing.py`\n")

        res = run_check(books, root)
        expect("json 顶层字段齐全",
               {"ok", "total", "bad"} <= set(res))
        expect("只统计 python 片段（alpha 2 + beta 3 + gamma 3 = 8）", res["total"] == 8)
        expect("坏命令被捕获（缺脚本/--help 非 0/-c/枚举/参数/运行时枚举 = 6 + README 索引 1）",
               len(res["bad"]) == 7)
        expect("无 choices= 的运行时枚举也被拦住（die 文案）",
               any("取值非法" in b["reason"] and "die_style.py" in b["cmd"] for b in res["bad"]))
        expect("枚举值非法被捕获（--level L2）",
               any("取值非法" in b["reason"] and "gamma" == b["playbook"] for b in res["bad"]))
        expect("未知参数被捕获（占位命令也查）",
               any("未知参数" in b["reason"] for b in res["bad"]))
        reasons = {(b["playbook"], b["reason"].split(":")[0]) for b in res["bad"]}
        expect("占位命令只校验脚本存在（broken 的 --help 不实跑）",
               not any(b["playbook"] == "alpha" and "broken.py" in b["cmd"] for b in res["bad"]))
        expect("--help 非 0 被捕获",
               any(b["playbook"] == "beta" and "--help rc=4" in b["reason"] for b in res["bad"]))
        expect("缺脚本被捕获",
               any(b["playbook"] == "beta" and "脚本不存在" in b["reason"] for b in res["bad"]))
        expect("python -m/-c 被捕获",
               any(b["playbook"] == "beta" and "python 选项开头" in b["reason"] for b in res["bad"]))
        expect("README 索引与磁盘不一致被捕获",
               any(b["playbook"] == "README" and "索引与磁盘不一致" in b["reason"]
                   for b in res["bad"]))
        expect("reason 覆盖两类以上", len(reasons) >= 3)
        expect("整体 ok=false", res["ok"] is False)

        clean = os.path.join(tmp, "clean")
        write(os.path.join(clean, "solo.md"),
              "- 步骤：1) `python Tool/scripts/good.py` → rc=0。\n")
        res2 = run_check(clean, root)
        expect("全绿时 ok=true 且 bad 为空", res2["ok"] is True and res2["bad"] == [])
        expect("占位计数生效", run_check(books, root)["skipped_placeholders"] == 1)

    print(json.dumps({"ok": not bad, "checks": checks, "tool": "playbook-check.py",
                      "failures": bad}, ensure_ascii=False))
    return 0 if not bad else 1


_CLI_CACHE: dict = {}
_ENUM_CACHE: dict = {}
ENUM_MSG_RE = re.compile(
    r"(?:只能是|只能是以下之一|只接受|必须是|must be one of|one of)\s*[:：]?\s*"
    r"([A-Za-z0-9_.\-/ |,]{2,80})")


def runtime_enum(target: str, flags: dict) -> dict:
    """从脚本源码的报错文案里提取枚举（`level 只能是 M1 / M2 / M3 / M4`）。

    有些脚本不写 `add_argument(choices=...)`，只在运行时 die() 报允许值；
    只读 choices 会漏判，故补这一层。
    """
    key = (target, tuple(sorted(flags)))
    if key in _ENUM_CACHE:
        return _ENUM_CACHE[key]
    out: dict = {}
    dests = {f.lstrip("-").replace("-", "_"): f for f in flags}
    try:
        with open(target, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        _ENUM_CACHE[key] = out
        return out
    for line in lines:
        m = ENUM_MSG_RE.search(line)
        if not m:
            continue
        allowed = {t for t in re.split(r"[/|,\s]+", m.group(1).strip())
                   if 1 <= len(t) <= 24 and not t.isdigit()}
        if len(allowed) < 2:
            continue
        low = line.lower()
        for dest, flag in dests.items():
            if dest and dest in low:
                out.setdefault(flag, set()).update(allowed)
    _ENUM_CACHE[key] = out
    return out


def script_flags(target: str):
    """AST 读目标脚本的 argparse：{--flag: set(choices) 或 None}；读不到返回 None。"""
    if target in _CLI_CACHE:
        return _CLI_CACHE[target]
    try:
        with open(target, encoding="utf-8", errors="replace") as fh:
            tree = ast.parse(fh.read())
    except (OSError, SyntaxError, ValueError):
        _CLI_CACHE[target] = None
        return None
    flags: dict = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = getattr(fn, "attr", None) or getattr(fn, "id", None)
        if name != "add_argument":
            continue
        opts = [a.value for a in node.args
                if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        if not opts:
            continue
        choices = None
        for kw in node.keywords:
            if kw.arg == "choices":
                try:
                    choices = {str(v) for v in ast.literal_eval(kw.value)}
                except (ValueError, SyntaxError, TypeError):
                    choices = None
        for opt in opts:
            if opt.startswith("--"):
                flags[opt] = choices
                for extra in opts:
                    if extra.startswith("-") and not extra.startswith("--"):
                        flags.setdefault(extra, choices)
    _CLI_CACHE[target] = flags
    return flags


def flag_problems(cmd: str, target: str) -> str:
    """校验命令里的参数名与枚举值；返回空串表示通过。"""
    flags = script_flags(target)
    if not flags:
        return ""
    tokens = cmd.split()[2:]
    for i, tok in enumerate(tokens):
        if not tok.startswith("-"):
            continue
        name, _, inline = tok.partition("=")
        if name not in flags:
            return "未知参数: " + name
        choices = flags[name]
        if not choices:
            choices = runtime_enum(target, flags).get(name)
        if not choices:
            continue
        value = inline or (tokens[i + 1] if i + 1 < len(tokens) else "")
        if not value or PLACEHOLDER_RE.search(value):
            continue
        if value not in choices:
            return "参数 %s 取值非法: %s（允许 %s）" % (
                name, value, "/".join(sorted(choices)))
    return ""


def main() -> int:
    ap = argparse.ArgumentParser(
        description="配方命令门禁：校验 Tool/playbooks/*.md 步骤里的 python 命令")
    ap.add_argument("--root", default=None, help="仓库根（默认按脚本位置推断）")
    ap.add_argument("--playbooks-dir", default=None, help="配方目录（默认 <root>/Tool/playbooks）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--self-test", action="store_true", help="临时夹具自测")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    root = os.path.abspath(args.root) if args.root else repo_root()
    books = os.path.abspath(args.playbooks_dir) if args.playbooks_dir \
        else os.path.join(root, "Tool", "playbooks")
    if not os.path.isdir(books):
        msg = {"ok": False, "total": 0, "bad": [],
               "error": "配方目录不存在: " + rel(books, root)}
        print(json.dumps(msg, ensure_ascii=False) if args.json else msg["error"])
        return 2
    res = run_check(books, root)
    print(json.dumps(res, ensure_ascii=False, indent=2) if args.json else render_text(res))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
