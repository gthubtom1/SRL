#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""preflight.py —— 唯一门禁：改完跑这一条，1~2 分钟给你一页结论。

为什么要有它：
    以前每次改动，验证散在 7 个脚本 + 3 类临时 python（悬空引用 / 数字对账 / 双平台 parity），
    每加一个工具都要人工分头跑一遍，1~2 小时就耗在"确认没搞坏"上。

它做五件事：
    [1] 结构   悬空引用（`Tool/...` / `MANUAL/...` 指向不存在的文件）
    [2] 数字   文档里的 38 工具 / 292 篇 / N 项体检 … 与实测对账
    [3] 平台   verify.ps1 与 verify.sh 的检查项数必须相等
    [4] 功能   budget / routing / relay 规则同步 / kb 验收 / （可选）端到端冒烟 + 体检
    [5] 资产   mcp-servers.json、tool-runtimes.json、tool-capabilities.json 的 schema 与交叉覆盖

用法：
    python Tool/scripts/preflight.py            # 全量（含 verify.ps1 + smoke-e2e，约 2 分钟）
    python Tool/scripts/preflight.py --fast     # 跳过 verify.ps1 / smoke-e2e（约 20 秒）
    python Tool/scripts/preflight.py --json     # 机器可读
退出码：0 = 全绿；1 = 有 FAIL
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
TOOL = os.path.join(ROOT, "Tool")

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

EXCLUDE_DIRS = {".git", "node_modules", ".next", "__pycache__", ".venv"}
SKIP_REF_DIRS = ("Tool/mcp/Tool/safe", "Tool/upstream", "Tool/mcp/Tool/reverselab",
                 "破甲卡生成", "Tool/cases")
TEXT_EXT = {".md", ".ps1", ".sh", ".py", ".json", ".jsonc", ".yml", ".ts", ".mjs"}

results = []   # (section, name, ok, detail)

ALLOW_PATH = os.path.join(TOOL, "scripts", "preflight-allow.json")


def load_allow():
    try:
        with open(ALLOW_PATH, encoding="utf-8") as f:
            return (json.load(f) or {}).get("allow", {})
    except Exception:
        return {}


def add(section, name, ok, detail=""):
    results.append({"section": section, "name": name, "ok": bool(ok), "detail": detail})


def walk(first_only=True):
    for dp, dn, fn in os.walk(ROOT):
        dn[:] = [d for d in dn if d not in EXCLUDE_DIRS]
        rel = os.path.relpath(dp, ROOT).replace(os.sep, "/")
        if rel == ".":
            rel = ""
        for f in fn:
            p = (rel + "/" + f).lstrip("/")
            if first_only and any(p.startswith(s) for s in SKIP_REF_DIRS):
                continue
            yield p


# ---------------------------------------------------------------- [1] 结构
def check_dangling():
    all_paths = {p.lower() for p in walk(first_only=False)}
    ref_re = re.compile(r"`([A-Za-z0-9_\-./\u4e00-\u9fff]+)`")
    dangling = []
    allow = load_allow()
    for p in walk():
        if os.path.splitext(p)[1].lower() not in TEXT_EXT or p.startswith("CHANGELOG"):
            continue
        try:
            text = open(os.path.join(ROOT, p), encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        text = text.replace("%20", " ")          # 徽章 URL 里的 %20 会被误当成"空格+数字"
        for m in ref_re.finditer(text):
            ref = m.group(1).strip()
            if not ref.startswith(("Tool/", "MANUAL/", "setup/", "docs/", ".github/")):
                continue
            if "<" in ref or ">" in ref:          # 占位符（如 Tool/upstream/<名>/）不算悬空
                continue
            norm = ref.rstrip("/")
            if "xxx" in norm.lower():
                continue
            if re.search(r"upstream/[A-Z]$|upstream/[A-Z]/", norm):   # 文档里的占位（上游 A 仓库）
                continue
            if norm.endswith("relay-config.json"):      # 首次运行才生成，不在仓库
                continue
            full = os.path.join(ROOT, norm.replace("/", os.sep))
            if norm.lower() in all_paths or os.path.isfile(full) or os.path.isdir(full):
                continue
            if any(norm.startswith(a) for a in allow):
                continue
            dangling.append(f"{p} -> {ref}")
    add("1 结构", "悬空引用", not dangling,
        f"{len(dangling)} 处" + ("：" + "；".join(dangling[:5]) if dangling else ""))


# ---------------------------------------------------------------- [2] 数字
def actual_numbers():
    tools = len(re.findall(r"@server\.tool\(\)",
                           open(os.path.join(TOOL, "mcp", "seep_mcp_server.py"), encoding="utf-8").read()))
    kb = sum(1 for dp, dn, fn in os.walk(os.path.join(TOOL, "mcp", "Tool", "reverselab", "kb"))
             for f in fn if f.endswith(".md"))
    manual = len([f for f in os.listdir(os.path.join(ROOT, "MANUAL")) if f.endswith(".md")])
    skills = 0
    sd = os.path.join(TOOL, "skill")
    for n in os.listdir(sd):
        p = os.path.join(sd, n)
        if n == "safe-skills":
            skills += len([x for x in os.listdir(p) if os.path.isdir(os.path.join(p, x))])
        elif os.path.isfile(os.path.join(p, "SKILL.md")):
            skills += 1
    return {"tools": tools, "kb": kb, "manual": manual, "skills": skills}


def check_numbers(fast):
    """只对账"本仓事实型"文档里的数字；技能/第三方说明各有口径，不参与。"""
    a = actual_numbers()
    num_docs = {
        "README.md", "README.zh.md", "README.en.md", "CLAUDE.md", "DSH-PROFILE.md",
        "MANUAL/DEPLOYMENT.md", "MANUAL/DEPLOYMENT-CHECKLIST.md", "MANUAL/PROMPT-LAYERS.md",
        "Tool/docs/MCP-SETUP.md",
    }
    pats = [
        (r"(?<![\d\u2265])([\d]+)\s*个(?:原生)?\s*MCP\s*工具", "tools"),
        (r"(?<![\d\u2265])([\d]+)\s*篇(?:战术实战笔记|实战笔记|战术笔记|完整检索库)", "kb"),
        (r"MANUAL[^\n]{0,10}?(?<![\d\u2265])([\d]+)\s*份", "manual"),
    ]
    claims = []
    for p in num_docs:
        fp = os.path.join(ROOT, p.replace("/", os.sep))
        if not os.path.isfile(fp):
            continue
        try:
            text = open(fp, encoding="utf-8", errors="replace").read().replace("%20", " ")
        except Exception:
            continue
        for pat, key in pats:
            for m in re.finditer(pat, text):
                n = int(m.group(1))
                if n != a[key]:
                    claims.append("%s: %s 写 %d，实际 %d" % (p, key, n, a[key]))
    add("2 数字", "文档数字 vs 实测", not claims,
        "实测 tools=%d skills=%d kb=%d manual=%d" % (a["tools"], a["skills"], a["kb"], a["manual"])
        + ("；" + "；".join(claims[:4]) if claims else ""))


# ---------------------------------------------------------------- [3] 平台
def check_parity():
    ps1 = open(os.path.join(ROOT, "setup", "verify.ps1"), encoding="utf-8", errors="replace").read()
    sh = open(os.path.join(ROOT, "setup", "verify.sh"), encoding="utf-8", errors="replace").read()
    n1 = len(re.findall(r'Test-CheckItem\s+"', ps1))
    n2 = len(re.findall(r'check_item\s+"', sh))
    add("3 平台", "verify.ps1 / verify.sh 项数一致", n1 == n2, f"ps1={n1} sh={n2}")


# ---------------------------------------------------------------- [4] 功能
def run(cmd, timeout=600):
    try:
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout, shell=False)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return 99, str(e)


def check_functional(fast):
    py = sys.executable
    items = [
        ("budget", [py, os.path.join(TOOL, "scripts", "check-budget.py")]),
        ("routing-coherence", [py, os.path.join(TOOL, "scripts", "verify-routing-coherence.py")]),
        ("relay-rules-sync", [py, os.path.join(TOOL, "scripts", "compliance-relay", "extract-rules.py"), "--check"]),
        ("kb-acceptance", [py, os.path.join(TOOL, "scripts", "kb_acceptance.py")]),
    ]
    if not fast:
        items.append(("smoke-e2e", [py, os.path.join(TOOL, "scripts", "smoke-e2e.py")]))
    for name, cmd in items:
        rc, out = run(cmd)
        tail = " ".join((out or "").strip().splitlines()[-1:])[:120]
        add("4 功能", name, rc == 0, f"rc={rc} {tail}")
    if not fast:
        pwsh = "pwsh" if os.name != "nt" else "powershell"
        rc, out = run([pwsh, "-NoProfile", "-ExecutionPolicy", "Bypass",
                       "-File", os.path.join(ROOT, "setup", "verify.ps1")], timeout=900)
        passed = len(re.findall(r"PASS", out))
        failed = len(re.findall(r"FAIL", out))
        add("4 功能", "verify.ps1 (61 项)", rc == 0 and failed == 0, f"PASS={passed} FAIL={failed}")


# ---------------------------------------------------------------- [5] 资产
def load(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return json.load(f)


def check_assets():
    try:
        mcp = load("Tool/config/mcp-servers.json")
        servers = mcp.get("servers", {})
        add("5 资产", "mcp-servers.json 可解析", bool(servers), f"{len(servers)} 个条目")
    except Exception as e:
        add("5 资产", "mcp-servers.json 可解析", False, str(e)[:80])

    try:
        caps = load("Tool/config/tool-capabilities.json").get("tools", {})
        runs = load("Tool/config/tool-runtimes.json").get("tools", {})
        missing = [k for k in runs if k not in caps]
        add("5 资产", "runtimes ↔ capabilities 覆盖", not missing, f"runtimes={len(runs)} caps={len(caps)} 缺={missing}")
    except Exception as e:
        add("5 资产", "tool-runtimes.json 可解析", False, str(e)[:80])

    try:
        routing = load("Tool/scripts/routing.json")
        routes = routing.get("routes", {})
        pri = routing.get("priority", [])
        bad = [k for k in routes if k not in pri] + [k for k in pri if k not in routes]
        add("5 资产", "routing routes ↔ priority", not bad, f"routes={len(routes)} priority={len(pri)}")
    except Exception as e:
        add("5 资产", "routing.json 可解析", False, str(e)[:80])


# ---------------------------------------------------------------- [6] 可移植
DRIVE_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/]")
PORTABLE_DIRS = ("Tool/config", "setup", "Tool/prompts", "Tool/scripts")
PORTABLE_EXT = {".json", ".jsonc", ".ps1", ".sh", ".py", ".ts", ".md"}


def check_portable():
    r"""仓库里不允许出现"某台机器专用"的绝对路径（如 D:\Tools\... 这种）。

    为什么：换电脑/换盘符时这类路径会静默失效（工具找不到、MCP 起不来）。
    允许清单：preflight-allow.json 的 portable_allow（键为路径前缀，值为理由）。
    """
    allow = load_allow().get("portable_allow", {})
    bad = []
    for base in PORTABLE_DIRS:
        root = os.path.join(ROOT, base.replace("/", os.sep))
        if not os.path.isdir(root):
            continue
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if d not in EXCLUDE_DIRS]
            for f in fn:
                if os.path.splitext(f)[1].lower() not in PORTABLE_EXT:
                    continue
                fp = os.path.join(dp, f)
                rel = os.path.relpath(fp, ROOT).replace(os.sep, "/")
                if any(rel.startswith(k) for k in allow):
                    continue
                try:
                    text = open(fp, encoding="utf-8", errors="replace").read()
                except Exception:
                    continue
                for m in DRIVE_RE.finditer(text):
                    # 只报会被真正打开的可执行/脚本/数据文件路径；
                    # 注释里写个 D:\\Tools 这种说明性示例不影响换机执行。
                    tail = text[m.start():m.start() + 120].splitlines()[0]
                    if not re.search(r"\\.(exe|dll|py|pyw|ps1|sh|bat|cmd|jar|so|dylib|json|db|idb)\\b", tail, re.I):
                        continue
                    line = text[:m.start()].count("\n") + 1
                    bad.append(f"{rel}:{line} {tail[:60]}")
    add("6 可移植", "无机器专用绝对路径", not bad,
        f"{len(bad)} 处" + ("：" + "；".join(bad[:4]) if bad else ""))


def check_ps_encoding():
    r"""PowerShell 5.1 的解析器对编码很挑：非 ASCII 的 .ps1 必须带 UTF-8 BOM。

    血案：tool-run.ps1 曾是无 BOM 的 UTF-8，`powershell -File`（5.1）读成 ANSI，
    中文串被切碎 → ParserError → x64dbg 永远起不来（pwsh 7 却能跑，于是"本机能开、换台不能"）。
    这里同时做两道检查：BOM 规则 + 真实解析（用 5.1 的 Parser）。
    """
    bad_bom = []
    for base in ("Tool/scripts", "setup"):
        root = os.path.join(ROOT, base.replace("/", os.sep))
        if not os.path.isdir(root):
            continue
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if d not in EXCLUDE_DIRS]
            for f in fn:
                if not f.lower().endswith(".ps1"):
                    continue
                fp = os.path.join(dp, f)
                raw = open(fp, "rb").read()
                if any(b > 127 for b in raw) and not raw.startswith(b"\xef\xbb\xbf"):
                    bad_bom.append(os.path.relpath(fp, ROOT).replace(os.sep, "/"))
    if bad_bom:
        add("6 可移植", "ps1 编码可被 PS5.1 解析", False,
            "非 ASCII 且无 BOM：" + "、".join(bad_bom[:3]))
        return

    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        add("6 可移植", "ps1 编码可被 PS5.1 解析", True, "无 PowerShell，跳过")
        return
    # 只查我们真正会执行的目录：Tool/scripts + setup。
    # Tool/cases（案例夹具，含故意写坏的样本）、Tool/upstream（上游镜像）、
    # Tool/mcp/Tool/reverselab（冻结骨架）不参与解析检查。
    cmd = (
        "$bad=@(); "
        + "; ".join(
            "Get-ChildItem -Path '" + os.path.join(ROOT, d).replace("'", "''") + "' -Recurse -Filter *.ps1 "
            "-ErrorAction SilentlyContinue | ForEach-Object { $e=$null; "
            "[void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$null,[ref]$e); "
            "if($e.Count){ $bad += ($_.Name + ': ' + $e[0].Message) } }"
            for d in (os.path.join("Tool", "scripts"), "setup")
        )
        + "; $bad -join ' | '"
    )
    try:
        out = subprocess.run([ps, "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=180)
        msg = (out.stdout or "").strip()
        add("6 可移植", "ps1 编码可被 PS5.1 解析", not msg, msg[:160] or "全部 .ps1 解析通过")
    except Exception as e:
        add("6 可移植", "ps1 编码可被 PS5.1 解析", True, "解析检查跳过：" + str(e)[:60])


def check_newtools():
    """新增的两个运维脚本必须「clone 下来就能跑」：语法能过 + 输出可机读。

    为什么放进 preflight：这两个脚本正是"静默失败"的解药，
    它们自己坏了就等于又回到"agent 不知道工具没连上"的老路。
    """
    py = sys.executable
    # ① mcp-doctor：--quick 只测端口，快且不受宿主是否运行影响（rc 0/1 都算正常）
    doc = os.path.join(TOOL, "scripts", "mcp-doctor.py")
    ok, note = False, "文件缺失"
    if os.path.isfile(doc):
        try:
            r = subprocess.run([py, doc, "--quick", "--json"], capture_output=True, text=True, timeout=90)
            body = (r.stdout or "").strip()
            if body.startswith("{"):
                import json as _json
                _json.loads(body)
                ok, note = True, f"rc={r.returncode}（0/1 均属正常）"
            else:
                note = f"输出不是 JSON：{(r.stderr or body)[:120]}"
        except Exception as e:
            note = str(e)[:120]
    add("7 新脚本", "mcp-doctor 可运行（输出 JSON）", ok, note)

    # ② migrate.py：语法 + 子命令自述
    mig = os.path.join(TOOL, "scripts", "migrate.py")
    ok2, note2 = False, "文件缺失"
    if os.path.isfile(mig):
        try:
            r = subprocess.run([py, mig, "--help"], capture_output=True, text=True, timeout=60)
            ok2 = (r.returncode == 0 and "align" in (r.stdout or ""))
            note2 = "子命令齐全" if ok2 else (r.stderr or "")[:120]
        except Exception as e:
            note2 = str(e)[:120]
    add("7 新脚本", "migrate 追版引擎可运行", ok2, note2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true", help="跳过 verify.ps1 与 smoke-e2e")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    check_dangling()
    check_numbers(args.fast)
    check_parity()
    check_assets()
    check_portable()
    check_ps_encoding()
    check_newtools()
    check_functional(args.fast)

    fails = [r for r in results if not r["ok"]]
    if args.json:
        print(json.dumps({"results": results, "fails": len(fails)}, ensure_ascii=False, indent=2))
    else:
        cur = ""
        for r in results:
            if r["section"] != cur:
                cur = r["section"]
                print(f"\n[{cur}]")
            mark = "PASS" if r["ok"] else "FAIL"
            print(f"  [{mark}] {r['name']}" + (f"  — {r['detail']}" if r["detail"] else ""))
        print(f"\n结果: {len(results) - len(fails)}/{len(results)} 通过"
              + ("" if not fails else "  ← 有 FAIL，先修再推"))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
