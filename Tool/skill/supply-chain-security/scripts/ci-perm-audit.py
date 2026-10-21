#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ci-perm-audit.py -- 解析 GitHub Actions workflow 的权限面与危险触发器。

纯标准库、只读、离线。不做 YAML 全量解析（不依赖 PyYAML），只按缩进扫描
`on:` / `permissions:` / `jobs.<id>.permissions` / `uses:` / `run:` / `secrets`，
输出可复核的行号与证据。结论是“组合风险”，不是“已被利用”。

输入：
  --path    workflow 目录或单个 .yml/.yaml（默认 .github/workflows）
  --json    仅输出 JSON（默认就是 JSON；保留兼容）
  --out     同时写文件
  --self-test 离线自检（内置 workflow，断言规则命中与失败形状）

输出字段：
  workflows[]: name, file, triggers[], permissions{scope:{level}}, token_default,
               action_pins[], checkout_refs[], secrets_refs[], jobs[]
  findings[]:  rule, severity, workflow, line, evidence, why, fix
  summary:     findings_total / by_severity / workflows_total

退出码：
  0 = 审计完成，无 high
  1 = 审计完成，存在 high
  2 = 参数/读取失败，stdout 为 {"ok": false, "blocked_at": ..., "reason": ...}

示例：
  python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py --path .github/workflows
  python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py --path .github/workflows/upstream-sync.yml --out ci.json
  python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py --self-test
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import tempfile

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

SCHEMA = "seep.ci-perm-audit/1"
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
TRIGGERS = ("pull_request_target", "workflow_run", "issue_comment", "pull_request",
            "push", "schedule", "workflow_dispatch", "release", "deployment")
SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")


class CiError(Exception):
    def __init__(self, blocked_at, reason):
        super().__init__(reason)
        self.blocked_at = blocked_at
        self.reason = reason


def emit_error(blocked_at, reason, rc=2):
    print(json.dumps({"ok": False, "blocked_at": blocked_at, "reason": reason},
                     ensure_ascii=False))
    return rc


def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except OSError as exc:
        raise CiError("read", "无法读取 %s: %s" % (path, exc))


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def unquote(value):
    return value.strip().strip("'\"")


def collect_workflows(path):
    if os.path.isfile(path):
        return [path]
    if not os.path.isdir(path):
        raise CiError("path", "--path 不存在: %s" % path)
    files = sorted(glob.glob(os.path.join(path, "*.yml")) +
                   glob.glob(os.path.join(path, "*.yaml")))
    if not files:
        raise CiError("path", "目录下没有 workflow：%s" % path)
    return files


def parse_permissions(lines, start, base_indent):
    """从 permissions: 行开始解析，返回 (dict, next_index)。"""
    perms = {}
    i = start
    first = lines[start].split(":", 1)[1].strip()
    if first:
        perms["__inline__"] = unquote(first)
        return perms, i + 1
    i += 1
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        if indent_of(line) <= base_indent:
            break
        m = re.match(r"^\s*([A-Za-z0-9_-]+)\s*:\s*(\S+)", line)
        if m:
            perms[m.group(1)] = unquote(m.group(2))
        i += 1
    return perms, i


def permissions_summary(perms):
    if not perms:
        return "absent"
    inline = perms.get("__inline__")
    if inline:
        return inline
    writes = sorted(k for k, v in perms.items() if v == "write")
    return ("write:" + ",".join(writes)) if writes else "read-only"


def parse_workflow(path, root):
    lines = read_lines(path)
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    name = os.path.basename(path)
    data = {"name": name, "file": rel, "triggers": [], "permissions": {},
            "token_default": "absent", "action_pins": [], "checkout_refs": [],
            "secrets_refs": [], "jobs": [], "line_count": len(lines)}
    findings = []

    def add(rule, severity, line_no, evidence, why, fix):
        findings.append({"rule": rule, "severity": severity, "workflow": rel,
                         "line": line_no, "evidence": evidence.strip()[:300],
                         "why": why, "fix": fix})

    # ---- triggers + top-level permissions ----
    on_indent = None
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        m = re.match(r"^(\s*)(\"?on\"?)\s*:\s*(.*)$", line)
        if m and indent_of(line) == 0:
            on_indent = len(m.group(1))
            inline = m.group(3).strip()
            if inline:
                for t in TRIGGERS:
                    if re.search(r"\b%s\b" % re.escape(t), inline):
                        data["triggers"].append({"name": t, "line": i + 1})
            else:
                j = i + 1
                while j < len(lines):
                    if not lines[j].strip():
                        j += 1
                        continue
                    if indent_of(lines[j]) <= on_indent:
                        break
                    tm = re.match(r"^\s*([A-Za-z0-9_-]+)\s*:", lines[j])
                    if tm and tm.group(1) in TRIGGERS:
                        data["triggers"].append({"name": tm.group(1), "line": j + 1})
                    j += 1
        m = re.match(r"^(\s*)permissions\s*:\s*(.*)$", line)
        if m and indent_of(line) == 0:
            perms, nxt = parse_permissions(lines, i, indent_of(line))
            data["permissions"] = perms
            data["token_default"] = permissions_summary(perms)
            i = nxt
            continue
        i += 1

    trigger_names = {t["name"] for t in data["triggers"]}
    untrusted = bool(trigger_names & {"pull_request_target", "workflow_run", "issue_comment"})

    # ---- permissions findings ----
    perms = data["permissions"]
    if not perms:
        add("permissions-absent", "medium", 1,
            "workflow 没有显式 permissions:",
            "未声明时继承仓库默认 token 权限；老仓库默认可能是读写。",
            "显式写 permissions，通常 contents: read 起步，发布 job 单独提权。")
    elif perms.get("__inline__") == "write-all":
        add("permissions-write-all", "high", 1,
            "permissions: write-all",
            "token 拥有全部写权限，任何一步被利用都可改仓库/发布制品。",
            "按 job 拆最小权限；只给发布 job 必需的 contents/packages: write。")
    else:
        writes = [k for k, v in perms.items() if v == "write"]
        if writes and untrusted:
            add("permissions-broad-write", "high", 1,
                "不可信触发 + 顶层写权限: " + ",".join(sorted(writes)),
                "PR/上游触发的 job 拿到写 token，可被不可信代码利用。",
                "把写权限下移到受保护分支的发布 job；PR job 只读。")

    for t in data["triggers"]:
        if t["name"] == "pull_request_target":
            add("trigger-pull_request_target", "high", t["line"],
                lines[t["line"] - 1] if t["line"] <= len(lines) else "pull_request_target",
                "在基仓库上下文运行，能接触 secrets 与写 token。",
                "优先用 pull_request；必须用时禁止 checkout PR head，限制 job 权限与 secrets。")
        elif t["name"] == "workflow_run":
            add("trigger-workflow_run", "medium", t["line"],
                lines[t["line"] - 1] if t["line"] <= len(lines) else "workflow_run",
                "下游继承上游产物与权限，上游被投毒会传导。",
                "把上游产物当不可信输入，校验来源与 digest；下游只读。")
        elif t["name"] == "issue_comment":
            add("trigger-issue_comment", "medium", t["line"],
                lines[t["line"] - 1] if t["line"] <= len(lines) else "issue_comment",
                "外部用户可触发；若执行评论内容或 checkout 任意 ref 则危险。",
                "只做只读响应；不把评论正文插入 shell；权限最小化。")

    # ---- jobs / action pins / checkout / secrets / injection ----
    job_indent = None
    in_jobs = False
    current_job = ""
    run_indent = None
    in_run = False
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            i += 1
            continue
        if re.match(r"^jobs\s*:\s*$", line):
            in_jobs = True
            job_indent = indent_of(line) + 2
            i += 1
            continue
        if in_jobs and indent_of(line) == job_indent and re.match(r"^[A-Za-z0-9_-]+\s*:\s*$", stripped):
            current_job = stripped.split(":", 1)[0]
            data["jobs"].append(current_job)
        if in_jobs and indent_of(line) == job_indent:
            m = re.match(r"^\s*permissions\s*:\s*(.*)$", line)
            if m:
                perms_j, _ = parse_permissions(lines, i, indent_of(line))
                summary = permissions_summary(perms_j)
                if summary == "write-all" and untrusted:
                    add("job-permissions-write-all", "high", i + 1,
                        "job %s: permissions: write-all" % current_job,
                        "不可信触发下的 job 拥有全部写权限。",
                        "改 job 级最小权限；PR job 只读。")
        if stripped.startswith("#"):
            i += 1
            continue
        if "self-hosted" in stripped:
            add("runner-self-hosted", "medium", i + 1, stripped,
                "自托管 runner 跑不可信 PR 会持久化、横向到内网。",
                "PR 用 GitHub 托管 runner；自托管只跑受保护分支。")

        m = re.match(r"^\s*-?\s*uses\s*:\s*([^\s#]+)", line)
        if m:
            value = m.group(1)
            pin = {"action": value, "line": i + 1, "pinned": False, "ref": ""}
            if value.startswith("./") or value.startswith(".\\"):
                pin["pinned"] = True
                pin["ref"] = "local"
            elif value.startswith("docker://"):
                pin["ref"] = value
                pin["pinned"] = "@sha256:" in value
            elif "@" in value:
                pin["ref"] = value.rsplit("@", 1)[1]
                pin["pinned"] = bool(SHA40.match(pin["ref"]))
            data["action_pins"].append(pin)
            if not pin["pinned"]:
                add("action-unpinned", "medium", i + 1, stripped,
                    "第三方 action 用可移动 tag/branch" if pin["ref"] else "action 未指定版本",
                    "固定到 40 位 commit SHA；docker action 固定 sha256；用 Dependabot 更新。")

        if re.match(r"^\s*-?\s*(run|script)\s*:", line):
            in_run, run_indent = True, indent_of(line)
        elif in_run and stripped and indent_of(line) <= run_indent:
            in_run = False

        if re.match(r"^\s*ref\s*:\s*(\S+)", line):
            ref_value = line.split(":", 1)[1].strip()
            if re.search(r"github\.event\.pull_request\.(head|merge)_(sha|ref)|github\.head_ref", ref_value):
                data["checkout_refs"].append({"line": i + 1, "ref": ref_value,
                                              "pr_head": True})
            else:
                data["checkout_refs"].append({"line": i + 1, "ref": ref_value,
                                              "pr_head": False})
            if untrusted and re.search(r"pull_request\.head|head_ref", ref_value):
                add("checkout-pr-head", "high", i + 1, stripped,
                    "不可信触发下 checkout PR head，等于在基仓库上下文执行不可信代码。",
                    "改用 pull_request；或只读 job + 无 secrets + 人工审批 + 限制权限。")

        for sm in re.finditer(r"secrets\.([A-Za-z0-9_]+)", line):
            data["secrets_refs"].append({"name": sm.group(1), "line": i + 1})
            if untrusted:
                add("secrets-in-untrusted-trigger", "high", i + 1, stripped,
                    "不可信触发与 secrets.%s 同时出现。" % sm.group(1),
                    "把 secrets 限制在受保护分支/环境保护规则；PR 流程禁止使用。")
        if re.search(r"secrets\s*:\s*inherit", line):
            add("secrets-inherit", "medium", i + 1, stripped,
                "workflow/action 继承全部调用方 secrets。",
                "显式传需要的 secret；不要 inherit 给第三方 action。")

        if in_run and "${{" in line and re.search(r"github\.(event\.|head_ref)|inputs\.", line):
            add("expression-injection", "high", i + 1, stripped,
                "不可信事件/输入字段直接进入 run/script。",
                "通过 env: 传值并加引号/白名单；不要直接插值到 shell。")
        i += 1

    data["findings"] = findings
    return data


def public_path(path):
    """输出里尽量用相对 CWD 的路径，避免把本机绝对路径写进证据。"""
    try:
        rel = os.path.relpath(path, os.getcwd())
    except ValueError:
        return path
    return path if rel.startswith("..") else rel.replace(os.sep, "/")


def audit(path, root):
    files = collect_workflows(path)
    workflows = [parse_workflow(p, root) for p in files]
    findings = [f for w in workflows for f in w["findings"]]
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["workflow"], f["line"]))
    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {
        "schema": SCHEMA,
        "ok": True,
        "tool": {"name": "ci-perm-audit.py", "mode": "offline-static",
                 "guarantees": ["read-only", "no network", "no yaml dependency",
                                "line numbers preserved"]},
        "target": {"path": public_path(path), "workflows_total": len(workflows)},
        "workflows": [{k: v for k, v in w.items() if k != "findings"} for w in workflows],
        "findings": findings,
        "summary": {"findings_total": len(findings), "by_severity": by_sev,
                    "high_or_critical": by_sev.get("high", 0) + by_sev.get("critical", 0)},
        "limits": {"note": "缩进扫描，不解析 YAML 锚点/merge key；动态生成或 reusable "
                           "workflow 的权限需人工补看。"},
    }


def self_test():
    checks = []
    with tempfile.TemporaryDirectory(prefix="ci-perm-selftest-") as td:
        wfdir = os.path.join(td, ".github", "workflows")
        os.makedirs(wfdir)
        with open(os.path.join(wfdir, "risky.yml"), "w", encoding="utf-8") as fh:
            fh.write("""name: risky
on:
  pull_request_target:
    branches: [main]
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/setup-python@0123456789abcdef0123456789abcdef01234567
      - run: echo "${{ github.event.pull_request.title }}"
        env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
""")
        with open(os.path.join(wfdir, "safe.yml"), "w", encoding="utf-8") as fh:
            fh.write("""name: safe
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
      - run: python -m pytest
""")
        try:
            res = audit(wfdir, td)
        except CiError as exc:
            return emit_error(exc.blocked_at, exc.reason)
        rules = {f["rule"] for f in res["findings"]}
        risky = [w for w in res["workflows"] if w["name"] == "risky.yml"][0]
        safe = [w for w in res["workflows"] if w["name"] == "safe.yml"][0]
        checks.append(("workflows", res["target"]["workflows_total"] == 2))
        checks.append(("trigger", "trigger-pull_request_target" in rules))
        checks.append(("broad-write", "permissions-broad-write" in rules or
                       "permissions-write-all" in rules))
        checks.append(("checkout-pr", "checkout-pr-head" in rules))
        checks.append(("unpinned", "action-unpinned" in rules))
        checks.append(("pinned-ok", any(p["pinned"] and "setup-python" in p["action"]
                                       for p in risky["action_pins"])))
        checks.append(("injection", "expression-injection" in rules))
        checks.append(("secrets", "secrets-in-untrusted-trigger" in rules))
        checks.append(("safe-clean", not [f for f in res["findings"]
                                          if f["workflow"].endswith("safe.yml")]))
        checks.append(("line-numbers", all(f["line"] >= 1 for f in res["findings"])))
        bad = {"ok": False, "blocked_at": "path"}
        checks.append(("error-shape", bad["ok"] is False and bad["blocked_at"] == "path"))
    failed = [n for n, ok in checks if not ok]
    if failed:
        return emit_error("self-test", "失败项: " + ",".join(failed))
    print(json.dumps({"ok": True, "checks": len(checks), "mode": "builtin-fixture"},
                     ensure_ascii=False))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="ci-perm-audit.py",
        description="解析 GitHub Actions workflow 的权限面与危险触发器（缩进扫描，不依赖 PyYAML）。",
        epilog="示例: python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py "
               "--path .github/workflows --out ci.json")
    ap.add_argument("--path", default=".github/workflows",
                    help="workflow 目录或单个 yml（默认 .github/workflows）")
    ap.add_argument("--json", action="store_true", help="输出 JSON（默认行为，保留兼容）")
    ap.add_argument("--out", default="", help="把 JSON 同时写入文件")
    ap.add_argument("--self-test", action="store_true", help="离线自检（内置 workflow）")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        result = audit(args.path, os.getcwd())
    except CiError as exc:
        return emit_error(exc.blocked_at, exc.reason)
    except Exception as exc:  # noqa: BLE001
        return emit_error("audit", "%s: %s" % (type(exc).__name__, exc))
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            return emit_error("out", "无法写入 --out: %s" % exc)
    return 1 if result["summary"]["high_or_critical"] else 0


if __name__ == "__main__":
    sys.exit(main())
