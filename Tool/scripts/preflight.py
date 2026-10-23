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
import glob
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
SKIP_REF_DIRS = ("work", "Tool/mcp/Tool/safe", "Tool/upstream", "Tool/mcp/Tool/reverselab",
                 "破甲卡生成", "Tool/cases", "docs/audit")
TEXT_EXT = {".md", ".ps1", ".sh", ".py", ".json", ".jsonc", ".yml", ".ts", ".mjs"}

results = []   # (section, name, ok, detail)

ALLOW_PATH = os.path.join(TOOL, "scripts", "preflight-allow.json")


def load_allow():
    r"""返回白名单 JSON 全文。

    ★ 历史 bug：这里原先返回 `.get("allow", {})`，而调用方又写
      `load_allow().get("portable_allow")` —— 于是永远拿到空字典，
      加上正则写错（`\.` 多了一层反斜杠），"无机器专用绝对路径"这条检查
      等于长期失明（实测漏报「某盘 Tool 目录」与个人桌面路径）。两级都修。
    """
    try:
        with open(ALLOW_PATH, encoding="utf-8") as f:
            return json.load(f) or {}
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
    allow = (load_allow().get("allow") or {})
    for p in walk():
        # CHANGELOG 是历史记录（含已删除文件的历史路径），不参与悬空引用检查；
        # 它现在在 docs/CHANGELOG.md，所以用"路径含 CHANGELOG"而不是前缀判断。
        if os.path.splitext(p)[1].lower() not in TEXT_EXT or "CHANGELOG" in p:
            continue
        if p.replace(os.sep, "/").startswith("docs/history/"):
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
    # BASELINE-FREEZE 的 first-party 文件数必须等于 check-budget 实测（防口径漂移）
    bf = os.path.join(ROOT, "MANUAL", "BASELINE-FREEZE.md")
    cb = os.path.join(TOOL, "scripts", "check-budget.py")
    if os.path.isfile(bf) and os.path.isfile(cb):
        try:
            btxt = open(bf, encoding="utf-8", errors="replace").read()
            mb = re.search(r"first-party[^|]*\|\s*(\d+)\s*\|", btxt)
            _rc, bout = run([sys.executable, cb], timeout=120)
            mc = re.search(r"first-party[^0-9]*(\d+)\s*/", bout)
            if mb and mc and int(mb.group(1)) != int(mc.group(1)):
                claims.append("BASELINE-FREEZE: first-party 写 %s，实测 %s"
                              % (mb.group(1), mc.group(1)))
        except Exception as _exc:  # noqa: BLE001
            claims.append("BASELINE 对账失败: %s" % str(_exc)[:40])

    # 文档里的 preflight 计数必须与 Tool/config/gate-counts.json（唯一数字源）一致
    gc = os.path.join(TOOL, "config", "gate-counts.json")
    if os.path.isfile(gc):
        try:
            g = json.load(open(gc, encoding="utf-8"))
            docs = []
            for r_ in (os.path.join(ROOT, "docs"), os.path.join(ROOT, "MANUAL"),
                       os.path.join(TOOL, "skill"), os.path.join(TOOL, "docs"),
                       os.path.join(ROOT, "README.md"), os.path.join(ROOT, "README.zh.md"),
                       os.path.join(ROOT, "README.en.md")):
                if os.path.isfile(r_):
                    docs.append(r_)
                    continue
                for dp, dn, fn in os.walk(r_):
                    if "audit" in dp.replace(os.sep, "/").split("/"):
                        continue
                    docs += [os.path.join(dp, f) for f in fn if f.endswith(".md")]
            HISTORY = ("AUDIT.md", "CHANGELOG.md", "DEFERRALS.md", "CLOSURE.md")
            for fp in docs:
                if os.path.basename(fp) in HISTORY or os.path.basename(fp).startswith("AUDIT"):
                    continue
                if "/history/" in fp.replace(os.sep, "/"):
                    continue
                try:
                    t = open(fp, encoding="utf-8", errors="replace").read()
                except Exception:
                    continue
                for m in re.finditer(r"preflight[^\n]{0,14}?(?:--fast\s*)?[**`]*\s*(\d+)/(\d+)", t):
                    n, tot = int(m.group(1)), int(m.group(2))
                    want = g["preflight_fast"] if "fast" in m.group(0) else g["preflight_full"]
                    if n != want:
                        claims.append("%s: 写 %d/%d，应为 %d/%d"
                                      % (os.path.relpath(fp, ROOT).replace(os.sep, "/"),
                                         n, tot, want, want))
        except Exception as _exc:  # noqa: BLE001
            claims.append("gate-counts 对账失败: %s" % str(_exc)[:40])

    # 旧值残留机检（第一方活文档；历史 CHANGELOG/AUDIT/HANDOFF 与 audit 目录跳过）
    STALE_LITERALS = ["38 个底层分析工具", "38 工具", "38 个原生工具",
                      "292+", "v6.2.2", "v3.0.3", "Skills - 9项", "10 大逆向 Skill", "本域 7 条", "= 8/8"]
    SKIP_NAMES = ("CHANGELOG", "AUDIT", "HANDOFF", "ANALYSIS", "DEFERRALS", "OPTIMIZATION")
    for root_, _dirs, files_ in os.walk(ROOT):
        normd = root_.replace(os.sep, "/")
        if any(x in normd for x in ("/work", "/node_modules", "/__pycache__", "/upstream",
                                    "/cases", "/audit", "/mcp/Tool", "/history")):
            continue
        for f_ in files_:
            if not f_.endswith(".md"):
                continue
            if any(f_.startswith(x) for x in SKIP_NAMES):
                continue
            fp_ = os.path.join(root_, f_)
            try:
                t_ = open(fp_, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            rel_ = os.path.relpath(fp_, ROOT).replace(os.sep, "/")
            for lit in STALE_LITERALS:
                if lit in t_:
                    claims.append("%s: 残留旧值 %r" % (rel_, lit))

    # 版本身份：README×3 的 Release 徽章必须等于 VERSION
    try:
        ver_ = open(os.path.join(ROOT, "VERSION"), encoding="utf-8").read().strip()
        for rf in ("README.md", "README.zh.md", "README.en.md"):
            rp_ = os.path.join(ROOT, rf)
            if not os.path.isfile(rp_):
                continue
            rt_ = open(rp_, encoding="utf-8", errors="replace").read()
            for mm in re.finditer(r"Release-v(\d+\.\d+\.\d+)", rt_):
                if mm.group(1) != ver_:
                    claims.append("%s: Release 徽章写 v%s，VERSION 是 %s"
                                  % (rf, mm.group(1), ver_))
    except Exception as _exc:  # noqa: BLE001
        claims.append("版本一致性检查失败: %s" % str(_exc)[:40])

    add("2 数字", "文档数字 vs 实测", not claims,
        "实测 tools=%d skills=%d kb=%d manual=%d" % (a["tools"], a["skills"], a["kb"], a["manual"])
        + ("；" + "；".join(claims[:4]) if claims else ""))


# ---------------------------------------------------------------- [3] 平台
def check_parity(fast=False):
    """双平台：① 检查项数一致；② 有 bash 就**真跑** verify.sh，rc 必须 0。

    血案（R4 复审）：旧版只比项数，verify.sh 的 CLAUDE.md/DSH-PROFILE.md 路径漏改、
    实际 63/2 失败，而 preflight 仍报「项数一致」——用项数掩盖了真失败。
    """
    ps1 = open(os.path.join(ROOT, "setup", "verify.ps1"), encoding="utf-8", errors="replace").read()
    sh = open(os.path.join(ROOT, "setup", "verify.sh"), encoding="utf-8", errors="replace").read()
    n1 = len(re.findall(r'Test-CheckItem\s+"', ps1))
    n2 = len(re.findall(r'check_item\s+"', sh))
    add("3 平台", "verify.ps1 / verify.sh 项数一致", n1 == n2,
        "项数一致（%d）" % n1 if n1 == n2 else "不一致：ps1=%d sh=%d" % (n1, n2))
    if fast:
        return
    bash = shutil.which("bash")
    if not bash:
        add("3 平台", "verify.sh 实跑（bash 不可用则跳过）", True, "skipped: no bash in PATH")
        return
    rc, out = run([bash, os.path.join("setup", "verify.sh")], timeout=900)
    line = ""
    for ln in (out or "").splitlines():
        if "核心检查通过" in ln:
            line = re.sub(r"\[[0-9;]*m", "", ln).strip()
    add("3 平台", "verify.sh 实跑（rc=0）", rc == 0, line or ("rc=%d" % rc))


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
    # --out 指向不存在的父目录时必须自动创建并落盘（B-P0-3：判绿无产物）
    import tempfile
    tmp = tempfile.mkdtemp(prefix="seep-out-")
    target = os.path.join(tmp, "a", "b", "web.json")
    rc_w, _o = run([py, os.path.join(TOOL, "skill", "web-pentest", "scripts", "web-check.py"),
                    "--url", "http://127.0.0.1:9/", "--out", target], timeout=120)
    add("4 功能", "out-artifact（--out 自动建目录并落盘）",
        os.path.isfile(target) and rc_w in (0, 3),
        "rc=%d file=%s" % (rc_w, "yes" if os.path.isfile(target) else "missing"))

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
        add("4 功能", "verify.ps1（项数以体检输出为准）", rc == 0 and failed == 0, f"PASS={passed} FAIL={failed}")


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
    r"""仓库里不允许出现"某台机器专用"的绝对路径（如「某盘 Tools 目录下的绝对路径」这种）。

    为什么：换电脑/换盘符时这类路径会静默失效（工具找不到、MCP 起不来）。
    允许清单：preflight-allow.json 的 portable_allow（键为路径前缀，值为理由）。
    """
    allow = (load_allow().get("portable_allow") or {})
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
                    has_ext = re.search(
                        r"\.(exe|dll|py|pyw|ps1|sh|bat|cmd|jar|so|dylib|json|db|idb|png|jpg|jpeg|txt|log|ini)\b",
                        tail, re.I)
                    personal = re.search(r"(?i)[A-Za-z]:[\\/]{1,2}Users[\\/]", tail)
                    program = re.search(r"(?i)[A-Za-z]:[\\/]{1,2}(Program Files|Tool|Tools)[\\/]", tail)
                    if not (has_ext or personal or program):
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
        out = subprocess.run([ps, "-NoProfile", "-Command", cmd], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=180)
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
            r = subprocess.run([py, doc, "--quick", "--json"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=90)
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
            r = subprocess.run([py, mig, "--help"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=60)
            ok2 = (r.returncode == 0 and "align" in (r.stdout or ""))
            note2 = "子命令齐全" if ok2 else (r.stderr or "")[:120]
        except Exception as e:
            note2 = str(e)[:120]
    add("7 新脚本", "migrate 追版引擎可运行", ok2, note2)

    # ③ case_state.py：阶段零出口闸（空跑一次 gate，必须在缺失时返回 1 而不是崩）
    cs = os.path.join(TOOL, "scripts", "case_state.py")
    ok3, note3 = False, "文件缺失"
    if os.path.isfile(cs):
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                r1 = subprocess.run([py, cs, "init", "--case", td], capture_output=True, text=True,
                                    encoding="utf-8", errors="replace", timeout=60)
                r2 = subprocess.run([py, cs, "gate", "--case", td], capture_output=True, text=True,
                                    encoding="utf-8", errors="replace", timeout=60)
                # 负向 1：空/空格证据不许证明（血案：prove --evidence "" 曾 rc=0）
                subprocess.run([py, cs, "claim", "--case", td, "--id", "C01", "--text", "x",
                                "--status", "hypothesis"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=60)
                r3 = subprocess.run([py, cs, "prove", "--case", td, "--id", "C01", "--evidence", "   "],
                                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
                # 负向 2：claim 阶段也不许空证据
                r4 = subprocess.run([py, cs, "claim", "--case", td, "--id", "C02", "--text", "y",
                                     "--status", "proven", "--evidence", ""],
                                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
                ok3 = (r1.returncode == 0 and r2.returncode == 1 and r3.returncode == 2 and r4.returncode == 2)
                note3 = ("空案子 gate=1；空格证据 prove=2；空证据 claim=2" if ok3
                         else f"init={r1.returncode} gate={r2.returncode} prove={r3.returncode} claim={r4.returncode}")
        except Exception as e:
            note3 = str(e)[:120]
    add("7 新脚本", "case_state 出口闸可运行", ok3, note3)

    # ④ mcp-guard：上游 MCP「只增不删」可执行闸（承诺→校验）
    mg = os.path.join(TOOL, "scripts", "mcp-guard.py")
    ok4, note4 = False, "文件缺失"
    if os.path.isfile(mg):
        try:
            r = subprocess.run([py, mg, "--json"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=90)
            import json as _json
            j = _json.loads((r.stdout or "{}").strip() or "{}")
            ok4 = bool(j.get("ok"))
            info = j.get("info") or {}
            note4 = (f"工具 {info.get('tools')}（基线 {info.get('baseline')}），标记 {info.get('marks')}"
                     if ok4 else "；".join(j.get("problems") or ["未通过"]))
        except Exception as e:
            note4 = str(e)[:120]
    add("7 新脚本", "mcp-guard 只增不删闸可运行", ok4, note4)

    # ⑤ 2.0 新增能力脚本：必须"能在干净 checkout 里跑"（只查 --help / --check，不重跑重活）
    extra = [("案例索引", "gen-case-index.py", ["--check"]),
             ("探针矩阵", "probe_matrix.py", ["--help"]),
             ("脱壳流水线", "dump-restore.py", ["--help"]),
             ("环境台账", "env-ledger.py", ["--help"])]
    bad5 = []
    for label, fn, args in extra:
        fp = os.path.join(TOOL, "scripts", fn)
        if not os.path.isfile(fp):
            bad5.append(label + "(缺文件)")
            continue
        try:
            r = subprocess.run([py, fp] + args, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=90)
            if r.returncode != 0:
                bad5.append("%s(rc=%d)" % (label, r.returncode))
        except Exception as e:
            bad5.append(label + "(" + str(e)[:30] + ")")
    add("7 新脚本", "2.0 能力脚本可运行（索引/探针/脱壳/台账）", not bad5,
        "；".join(bad5) if bad5 else "4 个脚本均 rc=0")


def check_persona_gate():
    """人设卡不得改写授权门：每张卡必须带 §六 指针或 Carve-out 条款。

    血案：旧代卡 space-bunny-2.md 曾写「没有授权 / 服务器不是我的 → 不当拒绝理由、不给 permission check」，
    与 `AGENTS.md` §六 唯一停止条件正面冲突，而旧卡因为 `is_new_gen()` 过滤完全没被兼容脚本检查到。
    """
    checker = os.path.join(ROOT, "破甲卡生成", "compat", "check_seep_compat.py")
    if not os.path.isfile(checker):
        add("8 人格卡", "人设卡授权门指针", False, "缺少 破甲卡生成/compat/check_seep_compat.py（失败关闭）")
        return
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    try:
        r = subprocess.run([sys.executable, checker, "--check"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120, env=env)
        tail = (r.stdout or r.stderr or "").strip().splitlines()
        add("8 人格卡", "人设卡授权门指针（§六 或 Carve-out）", r.returncode == 0,
            (tail[-1][:120] if tail else "无输出"))
    except Exception as e:
        add("8 人格卡", "人设卡授权门指针（§六 或 Carve-out）", False, str(e)[:120])


def check_taskcards_gate():
    r"""任务卡必须带案闸命令，且与源头同源。

    血案：v1.18.5 从缺闸源重生成 analyze.md，把 P0-1 静默回退；
    且早期断言用**裸词** `gate`，被任务卡里的 `NEXT = 01-gate-bypass` 顶掉 →
    "删掉闸行仍 PASS"（审计用篡改实测证伪过）。现在一律用字面正则 `case_state\.py\s+<sub>`。
    """
    tdir = os.path.join(TOOL, "prompts", "tasks")
    subs = ["init", "claim", "prove", "depth", "instrument", "verdict", "gate"]
    need = {
        "analyze.md": [(r"case_state\.py\s+" + k + r"\b", "case_state.py " + k) for k in subs]
                      + [("必须返回 0", "必须返回 0")],
        "reverse.md": [(r"case_state\.py\s+gate\b", "case_state.py gate"),
                       (r"case_state\.py\s+deliver\b", "case_state.py deliver")],
        "reverse-deliverable.md": [(r"case_state\.py\s+gate\b", "case_state.py gate"),
                                   (r"case_state\.py\s+deliver\b", "case_state.py deliver")],
    }
    bad = []
    for f, markers in need.items():
        fp = os.path.join(tdir, f)
        if not os.path.isfile(fp):
            bad.append(f + "(缺文件)")
            continue
        t = open(fp, encoding="utf-8", errors="replace").read()
        for pat, label in markers:
            if not re.search(pat, t):
                bad.append(f + "(缺 '" + label + "')")
                break
    try:
        ver = open(os.path.join(ROOT, "VERSION"), encoding="utf-8").read().strip()
        t = open(os.path.join(tdir, "analyze.md"), encoding="utf-8", errors="replace").read()
        if "VERSION_SEEN = " + ver not in t:
            bad.append("analyze.md(VERSION_SEEN != " + ver + ")")
    except Exception as e:
        bad.append("VERSION 读取失败:" + str(e)[:40])
    gen = os.path.join(TOOL, "scripts", "gen-task-cards.py")
    if os.path.isfile(gen):
        try:
            r = subprocess.run([sys.executable, gen, "--check"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=90)
            if r.returncode != 0:
                bad.append("任务卡与源头漂移（跑 gen-task-cards.py）")
        except Exception as e:
            bad.append("gen-task-cards 失败:" + str(e)[:40])
    else:
        bad.append("缺 gen-task-cards.py")
    add("9 任务卡", "任务卡闸块在场（字面 case_state.py <sub>）+ 与源头同源", not bad,
        "；".join(bad)[:160] if bad else "三张任务卡均含字面闸命令，且与源头 sha 一致")


def check_domain_packs():
    """领域存在性（六类齐）：深度条款已全部搬到 domain-gate.py（单一实现）。

    历史：v1.20 的九件套在这里查"有没有"，v1.22 起深度断言（篇幅/必备篇/
    --self-test/案例 sha256/链接图/串味/部署）统一由 domain-gate.py 负责，
    这里只保留"目录与文件存在"，避免两份实现漂移。
    """
    packs = {
        "web-pentest": "web-pentest",
        "supply-chain-security": "supply-chain-security",
        "pwn-crypto": "pwn-crypto",
        "malware-analysis": "malware-analysis",
        "firmware-iot": "firmware-iot",
        "ad-cloud": "ad-cloud",
        "protocol-plugin": "protocol-plugin",
        "plugin-targets": "plugin-targets",
        "forensics-mobile": "forensics-mobile",
    }
    bad = []
    for dom, sk in packs.items():
        skp = os.path.join(TOOL, "skill", sk, "SKILL.md")
        if not os.path.isfile(skp):
            bad.append(dom + "(缺 SKILL)")
            continue
        if not os.path.isdir(os.path.join(TOOL, "skill", sk, "scripts")):
            bad.append(dom + "(缺 scripts/)")
        refs = os.path.join(TOOL, "skill", sk, "references")
        if not (os.path.isdir(refs) and glob.glob(os.path.join(refs, "*.md"))):
            bad.append(dom + "(缺 references/)")
        if not os.path.isfile(os.path.join(TOOL, "config", "routing-fragments", dom + ".json")):
            bad.append(dom + "(缺路由片段)")
    add("10 领域", "领域六类文件在场（深度另由 domain-gate 判）", not bad,
        "；".join(bad)[:160] if bad else "9 域 SKILL/scripts/references/路由片段齐全")


def check_domain_depth():
    """全域名深度契约（九件套 2.0）：跑 domain-gate.py，把结果压成 4 条断言。

    为什么要单列：v1.21.5 的九件套只查"有没有"，查不出"能不能打"。
    深度契约（refs 必备四篇 / 脚本 --self-test / 案例 sha256 复算 / KB 失败判据 /
    链接图无孤儿 / 路由串味 / 部署哈希）全部由 domain-gate.py 实现，这里只做汇总，
    避免 preflight 再长 300 行、也避免两份实现漂移。
    """
    gate = os.path.join(TOOL, "scripts", "domain-gate.py")
    if not os.path.isfile(gate):
        add("11 深度", "全域深度契约（domain-gate.py）", False, "缺 Tool/scripts/domain-gate.py")
        return
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    try:
        r = subprocess.run([sys.executable, gate, "--all", "--json"], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=600, env=env)
        data = json.loads(r.stdout)
    except Exception as e:  # noqa: BLE001
        add("11 深度", "全域深度契约（domain-gate.py）", False, "运行失败:" + str(e)[:80])
        return
    rows = data.get("results") or []
    buckets = {
        "全域深度（SKILL/refs/脚本/案例/KB/矩阵/任务卡）":
            [x for x in rows if x["domain"] not in ("全局",)],
        "链接图无孤儿": [x for x in rows if "链接图" in x["name"]],
        "路由串味测试集": [x for x in rows if "串味" in x["name"]],
        "仓库清理 + 部署哈希": [x for x in rows if "清理" in x["name"] or "部署" in x["name"]],
        "路由片段合入 SSOT + 案例索引同源":
            [x for x in rows if "合入 SSOT" in x["name"] or "案例索引" in x["name"]],
    }
    for label, rs in buckets.items():
        bad = [x for x in rs if not x["ok"]]
        detail = "；".join((x["domain"] + ":" + x["name"] + "(" + x["detail"][:60] + ")")
                          for x in bad[:4]) if bad else "%d 条子断言全绿" % len(rs)
        add("11 深度", label, (not bad) and bool(rs), detail)




def check_v123_deliverables():
    """v1.23 交付物：三分/串味60/时间戳/driver-triage/剧本卡/inferred白名单。"""
    sys.path.insert(0, os.path.join(TOOL, "scripts", "lib"))
    bad, kinds = [], {}
    for cf in glob.glob(os.path.join(ROOT, "Tool", "cases", "*", "case.json")):
        try:
            c = json.load(open(cf, encoding="utf-8"))
        except Exception:
            bad.append(os.path.basename(cf) + "(bad json)")
            continue
        k = c.get("evidence_kind")
        kinds[k] = kinds.get(k, 0) + 1
        if k not in ("fixture", "real", "self-built", "historical"):
            bad.append(os.path.basename(os.path.dirname(cf)) + "(kind=%r)" % k)
    add("12 v1.23", "案例真实性三分", not bad,
        "; ".join(bad[:4]) if bad else str(dict(sorted(kinds.items()))))

    try:
        from domain_spec import ROUTING_TESTS
        n = len(ROUTING_TESTS)
        add("12 v1.23", "路由串味测试 >=60 条", n >= 60, "%d 条" % n)
    except Exception as e:
        add("12 v1.23", "路由串味测试 >=60 条", False, str(e)[:60])

    hits = []
    for f in (glob.glob(os.path.join(ROOT, "Tool", "cases", "*", "artifacts", "*.json"))
          + glob.glob(os.path.join(ROOT, "Tool", "docs", "*.json"))
          + glob.glob(os.path.join(ROOT, "Tool", "config", "*.json"))):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        if isinstance(d, dict) and d.get("generated_at") and d["generated_at"] != "1970-01-01T00:00:00Z":
            hits.append(os.path.basename(f))
    add("12 v1.23", "案例产物无动态 generated_at", not hits,
        ("hits: " + ", ".join(hits[:4])) if hits else "0")

    dt = os.path.join(TOOL, "scripts", "driver-triage.py")
    if not os.path.isfile(dt):
        add("12 v1.23", "driver-triage --self-test", False, "missing driver-triage.py")
    else:
        rc, out = run([sys.executable, dt, "--self-test"], timeout=120)
        add("12 v1.23", "driver-triage --self-test", rc == 0 and '"ok"' in out, "rc=%d" % rc)

    cards = 0
    for f in glob.glob(os.path.join(TOOL, "prompts", "domains", "*.md")):
        t = open(f, encoding="utf-8", errors="replace").read()
        cards += len(re.findall("- 步骤：[^\n]*rc\s*=\s*0", t))
    add("12 v1.23", "剧本卡 >=50 张", cards >= 50, "%d" % cards)


    # 7. v1.23 新增工具：seep-start / kb-query 自检
    tools = ["seep-start.py", "kb-query.py"]
    bad7 = []
    for t in tools:
        tp = os.path.join(TOOL, "scripts", t)
        if not os.path.isfile(tp):
            bad7.append(t + "(missing)")
            continue
        rc, out = run([sys.executable, tp, "--self-test"], timeout=120)
        if rc != 0 or '"ok"' not in out:
            bad7.append("%s(rc=%d)" % (t, rc))
    add("12 v1.23", "seep-start / kb-query --self-test", not bad7,
        "; ".join(bad7) if bad7 else "2 个工具 rc=0")

    allow = glob.glob(os.path.join(TOOL, "config", "criteria-inferred", "*.json"))
    add("12 v1.23", "判据 inferred 白名单（≥10 份）", len(allow) >= 10, "%d" % len(allow))




def check_playbook_gate():
    """三层门禁：配方命令（含占位命令的参数/枚举校验）/ 能力 DAG / 意图覆盖。"""
    for label, script, extra in (
            ("配方命令门禁", "playbook-check.py", ["--json"]),
            ("能力层门禁", "capability-gate.py", ["--json"]),
            ("意图覆盖门禁", "intent-coverage.py", ["--json"]),
            ("路由↔配方一致", "route-playbook-parity.py", ["--json"])):
        sp = os.path.join(TOOL, "scripts", script)
        if not os.path.isfile(sp):
            add("13 三层", label, False, script + "(missing)")
            continue
        rc, out = run([sys.executable, sp] + extra, timeout=300)
        try:
            data = json.loads(out[out.index("{"):]) if "{" in out else {}
        except (ValueError, TypeError):
            data = {}
        ok = rc == 0 and data.get("ok") is True
        add("13 三层", label, ok,
            "rc=%d ok=%r" % (rc, data.get("ok")) if not ok else "rc=0 ok=true")


def check_mcp_contract():
    """MCP 参数契约：路径别名 / required / description / 工具数基线（2026-10-22 审计 P0）。"""
    sp = os.path.join(TOOL, "scripts", "mcp-param-contract.py")
    if not os.path.isfile(sp):
        add("14 MCP 契约", "路径参数别名 + 工具数基线", False, "mcp-param-contract.py(missing)")
        return
    rc, out = run([sys.executable, sp, "--json"], timeout=180)
    data = {}
    if "{" in (out or ""):
        try:
            data, _end = json.JSONDecoder().raw_decode((out or "")[out.index("{"):])
        except (ValueError, TypeError):
            data = {}
    if not isinstance(data, dict):
        data = {}
    ok = rc == 0 and data.get("ok") is True
    detail = "rc=%d ok=%r" % (rc, data.get("ok"))
    if not ok:
        vs = data.get("violations") or []
        detail = "%d 项违规：%s" % (len(vs), "; ".join(
            "%s/%s" % (v.get("rule"), v.get("tool")) for v in vs[:4])) if vs else detail
    else:
        detail = "%d 个工具 / %d 个吃路径，全部支持 binary_path↔target_path 别名" % (
            data.get("tool_count", 0), data.get("path_tool_count", 0))
    add("14 MCP 契约", "路径参数别名 + 工具数基线", ok, detail)


def check_skill_route():
    """技能路由探针：30 条大白话必须落到对的技能（防 \\b 与 CJK 交界类静默误路由）。"""
    sp = os.path.join(TOOL, "scripts", "skill-route-probe.py")
    if not os.path.isfile(sp):
        add("15 路由探针", "30 条大白话 → 技能命中", False, "skill-route-probe.py(missing)")
        return
    rc, out = run([sys.executable, sp, "--json"], timeout=600)
    data = {}
    if "{" in (out or ""):
        try:
            data, _end = json.JSONDecoder().raw_decode((out or "")[out.index("{"):])
        except (ValueError, TypeError):
            data = {}
    if not isinstance(data, dict):
        data = {}
    ok = rc == 0 and data.get("ok") is True
    if ok:
        detail = "%d 条探针全部命中（或本机无 PowerShell 已跳过）" % data.get("probes", 0)
    else:
        fs = data.get("fails") or []
        detail = "%d/%d 失败：%s" % (
            len(fs), data.get("probes", 0),
            "; ".join("%s→%s" % (f.get("id"), f.get("skill")) for f in fs[:3])) if fs \
            else "rc=%d ok=%r" % (rc, data.get("ok"))
    add("15 路由探针", "30 条大白话 → 技能命中", ok, detail)


def check_race_e2e():
    """HTTP/2 单包真机 e2e：racy 必须 fail、safe 必须 pass（本地回环，不联网）。"""
    sp = os.path.join(TOOL, "scripts", "h2-race-e2e.py")
    if not os.path.isfile(sp):
        add("15 路由探针", "HTTP/2 单包 e2e（racy/safe）", False, "h2-race-e2e.py(missing)")
        return
    rc, out = run([sys.executable, sp, "--json"], timeout=180)
    data = {}
    if "{" in (out or ""):
        try:
            data, _end = json.JSONDecoder().raw_decode((out or "")[out.index("{"):])
        except (ValueError, TypeError):
            data = {}
    if not isinstance(data, dict):
        data = {}
    ok = rc == 0 and data.get("ok") is True and not data.get("skipped")
    detail = ("racy=fail / safe=pass，判定与账本读回一致" if ok else
              "rc=%d ok=%r skipped=%r blocked=%r" % (rc, data.get("ok"),
                                                    data.get("skipped"), data.get("blocked_at")))
    add("15 路由探针", "HTTP/2 单包 e2e（racy/safe）", ok, detail)


def check_doc_hygiene():
    """文档治理审计：冷启动可读 + 遗留盘点（死链/孤儿/重复/版本/归档横幅/索引/遗留）。"""
    sp = os.path.join(TOOL, "skill", "doc-hygiene", "scripts", "doc-audit.py")
    cfg = os.path.join(TOOL, "config", "doc-hygiene.json")
    if not os.path.isfile(sp):
        add("16 文档", "文档治理审计（doc-audit）", False, "doc-audit.py(missing)")
        return
    cmd = [sys.executable, sp, "--root", ROOT, "--json"]
    if os.path.isfile(cfg):
        cmd += ["--config", cfg]
    rc, out = run(cmd, timeout=240)
    data = {}
    if "{" in (out or ""):
        try:
            data, _end = json.JSONDecoder().raw_decode((out or "")[out.index("{"):])
        except (ValueError, TypeError):
            data = {}
    if not isinstance(data, dict):
        data = {}
    s = data.get("summary") or {}
    ok = rc == 0 and data.get("ok") is True
    if ok:
        detail = "%d 篇 / error 0 / warn %d / 遗留 %d 条（详见 doc-audit.py --report）" % (
            s.get("docs", 0), sum(1 for x in (data.get("findings") or [])
                                  if x.get("severity") == "warn"), s.get("leftovers", 0))
    else:
        errs = [x for x in (data.get("findings") or []) if x.get("severity") == "error"]
        detail = "rc=%d / error %d：%s" % (rc, len(errs),
                                          "; ".join("%s(%s)" % (e.get("rule"), e.get("target")) for e in errs[:3]))
    add("16 文档", "文档治理审计（doc-audit）", ok, detail)


def check_language():
    """措辞 lint：任务禁令一律不留在技能/提示词/文档里（scope 由用户声明）。"""
    import re as _re
    pat = _re.compile(r"不碰|禁止用于|仅限|不得用于|不允许|不提供|不适用|超出范围|不产出|不做成品|禁止\s*(?:操作|使用|测试|访问)")
    roots = [os.path.join(TOOL, "skill"), os.path.join(TOOL, "prompts"),
             os.path.join(ROOT, "docs"), os.path.join(ROOT, "MANUAL"),
             os.path.join(TOOL, "docs"), os.path.join(TOOL, "playbooks"),
             os.path.join(TOOL, "capabilities"), os.path.join(ROOT, "Tool", "cases")]
    audit_dir = os.path.join(ROOT, "docs", "audit")
    skip = ("CHANGELOG", "AUDIT", "DEFERRALS", "STYLE.md", "/_archive/")
    hits = []
    for r in roots:
        for dp, dn, fn in os.walk(r):
            for f in fn:
                if not f.endswith(".md"):
                    continue
                fp = os.path.join(dp, f)
                rel = os.path.relpath(fp, ROOT).replace(os.sep, "/")
                if any(s in rel for s in skip) or rel.startswith("docs/audit/") or rel.startswith("docs/history/"):
                    continue
                try:
                    t = open(fp, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                n = len(pat.findall(t))
                if n:
                    hits.append("%s(%d)" % (rel, n))
    for f in glob.glob(os.path.join(ROOT, "README*.md")):
        t = open(f, encoding="utf-8", errors="replace").read()
        n = len(pat.findall(t))
        if n:
            hits.append("%s(%d)" % (os.path.basename(f), n))
    stale, badcmd = [], []
    roots_ = [os.path.join(TOOL, "prompts"), os.path.join(TOOL, "skill"),
              os.path.join(ROOT, "docs"), os.path.join(ROOT, "MANUAL"),
              os.path.join(TOOL, "docs"), os.path.join(TOOL, "playbooks"),
              os.path.join(TOOL, "cases"), os.path.join(ROOT, "README.md"),
              os.path.join(ROOT, "README.zh.md"), os.path.join(ROOT, "README.en.md")]
    files_ = []
    for r_ in roots_:
        if os.path.isfile(r_):
            files_.append(r_)
            continue
        for dp, dn, fn in os.walk(r_):
            if any(x in dp.replace(os.sep, "/") for x in ("/audit", "/_archive", "/history")):
                continue
            files_ += [os.path.join(dp, f) for f in fn if f.endswith(".md")]
    for fp in files_:
        try:
            t = open(fp, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        relp = os.path.relpath(fp, ROOT).replace(os.sep, "/")
        for pat in ("evidence/<case>", "evidence/<\u6848\u5b50\u540d>", "evidence/<C>"):
            if pat in t:
                stale.append(relp)
                break
        base = os.path.basename(fp)
        if base in ("QUICKSTART.md", "README.md", "README.zh.md", "README.en.md"):
            for m in re.finditer(r"python\s+(Tool/[A-Za-z0-9_\-./]+\.py)", t):
                if not os.path.isfile(os.path.join(ROOT, m.group(1).replace("/", os.sep))):
                    badcmd.append("%s -> %s" % (relp, m.group(1)))
    if stale:
        hits = list(hits) + ["%s(旧案目录口径)" % x for x in stale[:4]]
    if badcmd:
        hits = list(hits) + ["%s(文档命令脚本不存在)" % x for x in badcmd[:4]]

    add("13 措辞", "无任务禁令措辞（scope 由用户声明）", not hits,
        "%d 个文件：%s" % (len(hits), "；".join(hits[:6])) if hits else "0 命中")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true", help="跳过 verify.ps1 与 smoke-e2e")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    check_dangling()
    check_numbers(args.fast)
    check_parity(args.fast)
    check_assets()
    check_portable()
    check_ps_encoding()
    check_newtools()
    check_persona_gate()
    check_taskcards_gate()
    check_domain_packs()
    check_domain_depth()
    check_v123_deliverables()
    check_playbook_gate()
    check_mcp_contract()
    check_skill_route()
    check_race_e2e()
    check_doc_hygiene()
    check_language()
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
