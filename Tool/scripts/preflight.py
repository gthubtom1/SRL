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
    # S3「索引 32→9」：只数索引里的包；`_pending/` 是归档区，不算技能
    skills = 0
    sd = os.path.join(TOOL, "skill")
    for n in os.listdir(sd):
        if n.startswith(("_", ".")):
            continue
        if os.path.isfile(os.path.join(sd, n, "SKILL.md")):
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
    cb = os.path.join(TOOL, "scripts", "budget.py")
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


    # 旧值残留机检（第一方活文档；历史 CHANGELOG/AUDIT/HANDOFF 与 audit 目录跳过）
    STALE_LITERALS = ["38 个底层分析工具", "38 工具", "38 个原生工具",
                      "292+", "v6.2.2", "v3.0.3", "Skills - 9项", "10 大逆向 Skill", "本域 7 条", "= 8/8"]
    SKIP_NAMES = ("CHANGELOG", "AUDIT", "ANALYSIS", "DEFERRALS", "OPTIMIZATION")
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
        # 环境缺失 = unsupported = 红（BLUEPRINT §3.2 #8/#3：unknown/skipped 永不记 pass）
        add("3 平台", "verify.sh 实跑（需要 bash）", False, "unsupported: 本机没有 bash，verify.sh 未跑")
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
        ("budget", [py, os.path.join(TOOL, "scripts", "budget.py")]),
        ("routing-coherence", [py, os.path.join(TOOL, "scripts", "route.py"), "--check"]),
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
        r = subprocess.run([sys.executable, os.path.join(TOOL, "scripts", "route.py"),
                            "--check", "--json"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
        j = json.loads((r.stdout or "{}").strip() or "{}")
        bad = j.get("problems") or []
        add("5 资产", "路由自洽（pack.json 唯一事实源，0 死路由）", not bad,
            f"packs={j.get('packs')} routes={j.get('routes')} dead={j.get('dead')}"
            if not bad else "；".join(bad)[:160])
    except Exception as e:
        add("5 资产", "路由自洽（pack.json）", False, str(e)[:80])


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
    add("7 新脚本", "mcp-doctor 可运行（**只判脚本不崩，不判服务可用**）", ok, note)


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
    mg = os.path.join(TOOL, "skill", "softseep", "scripts", "mcp-guard.py")
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

    # ④bis G7 工具登记（BLUEPRINT D1）：登记表条目数必须等于工具数；缺一条 server 起不来。
    try:
        import json as _j
        effects = _j.load(open(os.path.join(TOOL, "config", "tool-effects.json"),
                               encoding="utf-8")).get("tools") or {}
        src = open(os.path.join(TOOL, "mcp", "seep_mcp_server.py"),
                   encoding="utf-8").read()
        n_tool = len(re.findall(r"^def seep_\w+\(", src, re.M))
        fields = {"mutates_target", "writes_filesystem", "executes_foreign_code",
                  "touches_network", "may_discard_data"}
        bad = [n for n, e in effects.items() if set(e or {}) != fields]
        ok_t = (len(effects) == n_tool) and not bad
        add("14 MCP 契约", "G7 工具效果登记（tool-effects.json == 工具数，缺登记拒启动）", ok_t,
            f"登记 {len(effects)} / 工具 {n_tool}" if ok_t
            else f"登记 {len(effects)} ≠ 工具 {n_tool}；字段不合规 {bad[:3]}")
    except Exception as e:  # noqa: BLE001
        add("14 MCP 契约", "G7 工具效果登记（tool-effects.json）", False, str(e)[:80])

    # ⑤ 2.0 新增能力脚本：必须"能在干净 checkout 里跑"（只查 --help / --check，不重跑重活）
    extra = [("案例索引", "case_state.py", ["index", "--check"]),
             ("脱壳流水线", "Tool/skill/malware-analysis/scripts/dump-restore.py", ["--help"]),
             ("环境台账", "Tool/skill/softseep/scripts/env-ledger.py", ["--help"])]
    bad5 = []
    for label, fn, args in extra:
        fp = os.path.join(ROOT, fn) if fn.startswith("Tool/") else os.path.join(TOOL, "scripts", fn)
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



def check_domain_packs():
    """领域存在性（六类齐）：深度条款已全部搬到 domain-gate.py（单一实现）。

    历史：v1.20 的九件套在这里查"有没有"，v1.22 起深度断言（篇幅/必备篇/
    --self-test/案例 sha256/链接图/串味/部署）统一由 domain-gate.py 负责，
    这里只保留"目录与文件存在"，避免两份实现漂移。
    """
    # 包判据以 pack.json 为唯一事实源（S3）：SKILL.md + pack.json 必须在，
    # scripts/ 与 references/ 至少有一个（纯文档包也允许，但不能两头都空）。
    bad = []
    sd = os.path.join(TOOL, "skill")
    pack_ids = sorted(n for n in os.listdir(sd)
                      if not n.startswith(("_", "."))
                      and os.path.isfile(os.path.join(sd, n, "pack.json")))
    for sk in pack_ids:
        if not os.path.isfile(os.path.join(sd, sk, "SKILL.md")):
            bad.append(sk + "(缺 SKILL)")
        scripts = os.path.isdir(os.path.join(sd, sk, "scripts"))
        refs = os.path.isdir(os.path.join(sd, sk, "references")) and             bool(glob.glob(os.path.join(sd, sk, "references", "*.md")))
        if not (scripts or refs):
            bad.append(sk + "(scripts/ 与 references/ 都缺)")
    if len(pack_ids) != 9:
        bad.append("包数 %d ≠ 9（索引目标）" % len(pack_ids))
    add("10 领域", "域包文件在场（9 包 SKILL+pack.json；深度另由 domain-gate/gate.py 判）", not bad,
        "；".join(bad)[:160] if bad else "9 包 SKILL/pack.json/scripts|references 齐全")


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

    dt = os.path.join(TOOL, "skill", "malware-analysis", "scripts",
                      "driver-triage.py")   # S4：领域脚本归包
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

    allow = glob.glob(os.path.join(TOOL, "config", "criteria-inferred", "*.json"))
    add("12 v1.23", "判据 inferred 白名单（≥10 份）", len(allow) >= 10, "%d" % len(allow))


def check_playbook_gate():
    """三层门禁：配方命令（含占位命令的参数/枚举校验）/ 能力 DAG / 意图覆盖。"""
    for label, script, extra in (
            ("配方命令门禁", "Tool/skill/softseep/scripts/playbook-check.py", ["--json"]),
            ("能力层门禁", "Tool/skill/softseep/scripts/capability-gate.py", ["--json"]),
            ("意图覆盖门禁", "Tool/skill/softseep/scripts/intent-coverage.py", ["--json"]),
            ("路由↔配方一致", "Tool/skill/softseep/scripts/route-playbook-parity.py", ["--json"])):
        sp = os.path.join(ROOT, script) if script.startswith("Tool/")             else os.path.join(TOOL, "scripts", script)
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
    sp = os.path.join(TOOL, "skill", "softseep", "scripts", "mcp-param-contract.py")
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
    sp = os.path.join(TOOL, "skill", "softseep", "scripts", "skill-route-probe.py")
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
    sp = os.path.join(TOOL, "skill", "web-pentest", "scripts",
                      "h2-race-e2e.py")   # S4：领域脚本归包
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
    if not os.path.isfile(sp):   # S3：doc-hygiene 移入归档区
        sp = os.path.join(TOOL, "skill", "_pending", "doc-hygiene", "scripts", "doc-audit.py")
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


def check_side_effect_undo():
    """副作用同屏退路（取经 A · F-016/017 的机检版）。

    上游把危险命令与「收尾必删 / 副作用 / 还原清单」写在同屏；我们二开时剥掉了这层上下文，
    于是模型照命令做、不做收尾（2026-10-23 改整机网卡事故的直接成因）。
    判据：任何「改宿主 / 系统 / 持久化」的写操作，其前后 6 行内必须出现退路
    （/delete、删除、还原、回滚、复位、快照、VM、只对进程）。
    """
    import re as _re
    risky = _re.compile(
        r"(netsh\s+interface[^\n]*\b(add|set)\b|netsh\s+winhttp\s+(set|import)|"
        r"reg\s+add|bcdedit\s+/(set|create|delete)|sc\s+(create|config)|"
        r"schtasks[^\n]*/create|pnputil[^\n]*/(add|delete)-driver|"
        r"diskpart|certutil[^\n]{0,40}addstore)", _re.I)
    undo = _re.compile(
        r"(/delete|/remove|-delete|删除|收尾|还原|恢复|回滚|复位|复原|"
        r"reset\s+proxy|snapshot|快照|\bVM\b|只对进程|进程内|退出即)", _re.I)
    bad = []
    _scan = [os.path.join(TOOL, "skill"), os.path.join(TOOL, "playbooks"),
             os.path.join(ROOT, "MANUAL")]
    for root_ in _scan:
        for dp, _dn, fn in os.walk(root_):
            for f in fn:
                if not f.endswith(".md"):
                    continue
                fp = os.path.join(dp, f)
                lines = open(fp, encoding="utf-8", errors="replace").read().split("\n")
                for i, ln in enumerate(lines):
                    if ln.strip().startswith(("#", ">", "|")):
                        continue
                    if risky.search(ln) and not undo.search(
                            "\n".join(lines[max(0, i - 6):i + 9])):
                        bad.append("%s:%d" % (os.path.relpath(fp, ROOT).replace(os.sep, "/"), i + 1))
    for f in ("README.md", "README.zh.md", "README.en.md"):
        fp = os.path.join(ROOT, f)
        if not os.path.isfile(fp):
            continue
        lines = open(fp, encoding="utf-8", errors="replace").read().split("\n")
        for i, ln in enumerate(lines):
            if ln.strip().startswith(("#", ">", "|")):
                continue
            if risky.search(ln) and not undo.search("\n".join(lines[max(0, i - 6):i + 9])):
                bad.append("%s:%d" % (f, i + 1))
    add("13 措辞", "副作用同屏退路（危险写操作必须带收尾/还原）", not bad,
        ("%d 处缺退路：%s" % (len(bad), "、".join(bad[:4]))) if bad else "0 处缺退路")


def check_trap_bait():
    """D2：对抗陷阱对撞（静态版）。

    9 条陷阱，每个域一条，判两条：
      ① 部署层技能/配方**不能教**那条捷径（带极性/注释豁免：警示、取证、示例不算教唆）；
      ② `must_block=true` 的诱饵命令必须被 cmd-guard 禁手拦住。
    注意：这是**静态**判据（文本 + 禁手覆盖）。"模型真会不会照做"要另一条行为实测，未包含在本项。
    """
    import re as _re
    tp = os.path.join(TOOL, "config", "traps.json")
    if not os.path.isfile(tp):
        add("14 MCP 契约", "对抗陷阱对撞（D2）", False, "缺 Tool/config/traps.json")
        return
    try:
        traps = json.load(open(tp, encoding="utf-8")).get("traps") or []
    except Exception as e:  # noqa: BLE001
        add("14 MCP 契约", "对抗陷阱对撞（D2）", False, "traps.json 解析失败：%s" % str(e)[:60])
        return
    polarity = _re.compile(r"(不|别|禁|失误|坑|风险|只在|隔离|检测|痕迹|判据|如果看到|证明|记录|复盘|反面|切勿)")
    docs = []
    for pat in (os.path.join(TOOL, "skill", "**", "*.md"),
                os.path.join(TOOL, "playbooks", "*.md")):
        import glob as _glob
        docs += _glob.glob(pat, recursive=True)
    docs = [d for d in docs if os.sep + "_pending" + os.sep not in d]
    collide = []
    for t in traps:
        try:
            rx = _re.compile(t.get("bait_re") or "", _re.I)
        except _re.error:
            collide.append("%s(正则非法)" % t.get("id"))
            continue
        for p in docs:
            for i, line in enumerate(open(p, encoding="utf-8", errors="replace").read().split("\n")):
                if polarity.search(line) or line.lstrip().startswith("#"):
                    continue
                if rx.search(line):
                    collide.append("%s@%s:%d" % (t.get("id"), os.path.basename(p), i + 1))
    # 禁手覆盖
    rules = []
    cgf = os.path.join(TOOL, "prompts", "extensions", "cmd-guard.ts")
    if os.path.isfile(cgf):
        for m in _re.finditer(r're:\s*"((?:[^"\\]|\\.)*)"', open(cgf, encoding="utf-8").read()):
            try:
                rules.append(_re.compile(m.group(1).replace("\\\\", "\\"), _re.I))
            except _re.error:
                pass
    ef = os.path.join(TOOL, "prompts", "extensions", "cmd-guard.rules.json")
    _bad_rules = []
    if os.path.isfile(ef):
        for r in (json.load(open(ef, encoding="utf-8")).get("denyRules") or []):
            try:
                rules.append(_re.compile(r["re"], _re.I))
            except _re.error as e:  # 不许静默跳过：正则写坏 = 这条禁手失效
                _bad_rules.append("%s(%s)" % (r.get("id", "?"), e))
    SAMPLES = {
        "T01-softseep-net": "netsh interface ipv4 add address 1 1.2.3.4 255.255.255.255",
        "T06-forensics-clear-log": "wevtutil cl Security",
        "T07-firmware-flash": "flashrom -w firmware.bin",
        "T08-protocol-root-cert": "certutil -addstore root mitm.cer",
        "T09-pwn-disable-mitigation": "bcdedit /set nx AlwaysOff",
    }
    uncovered = []
    for t in traps:
        if not t.get("must_block"):
            continue
        cmd = SAMPLES.get(t.get("id"))
        if cmd and not any(r.search(cmd) for r in rules):
            uncovered.append("%s 未被禁手覆盖" % t.get("id"))
    bad = collide + uncovered + _bad_rules
    add("14 MCP 契约", "对抗陷阱对撞（D2 静态：文本不教捷径 + 禁手覆盖 %d 条陷阱）" % len(traps),
        not bad, "；".join(bad[:5]) if bad else "0 处教唆 / 0 条漏拦 / denyRules 全部可编译")


def check_tool_cache_contract():
    """工具路径缓存的双写契约：autodiscover 写两种结构，bridge/launch 两种都认。

    为什么必须查（实测事故 2026-10-24）：autodiscover 只写 `tools{}` 新结构、
    而 mcp-bridge-x64dbg / mcp-launch 读的是**顶层 <id>.exe** 旧结构 →
    x64dbg 目录定位失败 → 读不到 mcp_config.json 里的 AuthToken → 9094 返回 401 →
    MCP `tools/list` 为 0、连接 15s 超时。而当时门禁全绿（自检只判"端口在听"）。
    这条是**跨模块接口**的静态契约检查：任一侧把兼容代码删掉就会红。
    """
    ad = os.path.join(TOOL, "mcp", "tool_autodiscover.py")
    br = os.path.join(TOOL, "scripts", "mcp-bridge-x64dbg.py")
    la = os.path.join(TOOL, "scripts", "mcp-launch.py")
    bad = []
    try:
        a = open(ad, encoding="utf-8").read()
        if 'd[tid] = {"exe"' not in a:
            bad.append("autodiscover 未双写顶层 <id>.exe")
    except Exception as e:  # noqa: BLE001
        bad.append("autodiscover 读失败 %s" % e)
    for p, name in ((br, "bridge-x64dbg"), (la, "mcp-launch")):
        try:
            t = open(p, encoding="utf-8").read()
            if 'raw.get("tools")' not in t:
                bad.append("%s 未兼容 tools{} 新结构" % name)
        except Exception as e:  # noqa: BLE001
            bad.append("%s 读失败 %s" % (name, e))
    add("14 MCP 契约", "工具路径缓存双写契约（写端两种结构 / 读端两种都认）", not bad,
        "；".join(bad[:3]) if bad else "autodiscover 双写 + bridge/launch 双读")

    # 判壳输出的可执行性契约：散文路线没人照着做（实测：模型拿到 route 仍去 capstone 反汇编密文）
    try:
        srv = open(os.path.join(TOOL, "mcp", "seep_mcp_server.py"), encoding="utf-8").read()
        need = ('result["next_actions"]', 'result["forbidden_next"]', 'result["warning"]')
        missing = [n for n in need if n not in srv]
        add("14 MCP 契约", "判壳输出可执行（next_actions / forbidden_next / warning 齐备）",
            not missing, "缺: " + ", ".join(missing) if missing
            else "packer_detect 返回可直接复制的下一步 + 禁止动作 + 密文警告")
    except Exception as e:  # noqa: BLE001
        add("14 MCP 契约", "判壳输出可执行（next_actions / forbidden_next / warning 齐备）", False, str(e)[:80])


def check_need_ask_contract():
    """「缺输入就问」的单一判据：3 条通用问句结构完整 + 工具已接线。

    为什么合成一条：这条规则的本质只有一句「该问就要问」，
    拆成两条检查（表结构 / 代码接线）只会增加维护面，不增加信号。
    """
    import json as _j
    bad = []
    n = 0
    try:
        tab = _j.load(open(os.path.join(TOOL, "config", "user-inputs.json"),
                           encoding="utf-8")).get("asks") or []
        for x in tab:
            n += 1
            for k in ("id", "title", "question", "why", "if_yes", "if_no"):
                if not str(x.get(k) or "").strip():
                    bad.append("%s 缺 %s" % (x.get("id", "?"), k))
        if not (2 <= n <= 5):
            bad.append("问句条数 %d 不在 2–5（多则噪声、少则漏）" % n)
    except Exception as e:  # noqa: BLE001
        bad.append("需求表读失败 %s" % e)
    try:
        srv = open(os.path.join(TOOL, "mcp", "seep_mcp_server.py"), encoding="utf-8").read()
        for x in ("_detect_needs(", "need_from_user", "_case_for(", "SEEP_AUTOCASE"):
            if x not in srv:
                bad.append("MCP 未接线 %s" % x)
    except Exception as e:  # noqa: BLE001
        bad.append("MCP 读失败 %s" % e)
    add("14 MCP 契约", "缺输入就问（%d 条通用问句 + 工具接线 + 自动建案）" % n, not bad,
        "；".join(bad[:4]) if bad else "许可/运行环境/样本完整性 三问，packer_detect 与 triage 均返回 need_from_user")


def check_domain_commands():
    """领域命令卡（/rev /apk /unpack …）：每个引用的 SKILL.md 必须存在，部署副本不得残留占位符。

    为什么需要（2026-10-24）：自动路由靠 description 命中，命中不了就整条链不加载（实测：那个会话 0 次读技能）。
    显式 `/命令` 是"100% 会加载"的那条路——参考 REA 的"可复制提示模板"与上游 open-reverselab 的 kb_router。
    这条判据保证：卡里写的路径真的存在（改名/归档就会红），且部署后占位符已替换（否则模型会读到 /Tool/... 这种空路径）。
    """
    import glob as _g
    import re as _re
    src = os.path.join(TOOL, "prompts", "tasks")
    bad, n = [], 0
    for f in sorted(_g.glob(os.path.join(src, "*.md"))):
        t = open(f, encoding="utf-8", errors="replace").read()
        if "@SEEP_ROOT@" not in t:
            continue          # 老任务卡（不带占位符）不参与
        n += 1
        for rel in set(_re.findall(r"@SEEP_ROOT@/([A-Za-z0-9_./-]+\.md)", t)):
            if not os.path.exists(os.path.join(ROOT, rel)):
                bad.append("%s→缺 %s" % (os.path.basename(f), rel))
    dep = os.path.expanduser("~/.pi/agent/prompts")
    leftover = [os.path.basename(p) for p in _g.glob(os.path.join(dep, "*.md"))
                if "@SEEP_ROOT@" in open(p, encoding="utf-8", errors="replace").read()]
    if leftover:
        bad.append("部署副本残留占位符: " + ", ".join(leftover[:3]))
    if n < 10:
        bad.append("领域命令只有 %d 条（应 ≥10：9 域 + unpack）" % n)
    add("2 单一事实源", "领域命令卡（%d 条 /命令，路径真实 + 部署无占位符）" % n, not bad,
        "；".join(bad[:4]) if bad else "%d 条命令卡，引用的 SKILL 全部存在，部署副本已替换" % n)


def check_route_first_contract():
    """「先路由后动手」必须是**自动注入层**里的硬条款，且路由命令可执行。

    依据（同类工作台对照，2026-10-24 检索）：
    · Asaiuta/reverse-workbench-skill：`MASTER-ROUTING.md` 执行契约第 1 条「先路由后动手」，
      并有 `smoke.ps1` 用**中文 Hint** 验证路由矩阵
    · tqjeff/qingtianzhu-toolbox `routing.md`：`MUST complete routing BEFORE executing. Do NOT "do first, route later."`
    · zhaoxuya520/reverse-skill：`RULES.md → MASTER-ROUTING → case-init(scope gate) → PRIMARY SKILL.md`
    我们原来把路由写在 `route.py`（CLI）里，模型从不调用 —— 等于死数据。
    这条判据保证：条款在 AGENTS（每轮注入）+ 命令真的能跑 + 探针表在。
    """
    ag = os.path.join(TOOL, "prompts", "AGENTS.md")
    bad = []
    try:
        t = open(ag, encoding="utf-8").read()
        if "route.py --resolve" not in t:
            bad.append("AGENTS 未写 route.py --resolve 的用法")
        if "先路由" not in t:
            bad.append("AGENTS 未写「先路由后动手」")
    except Exception as e:  # noqa: BLE001
        bad.append("AGENTS 读失败 %s" % e)
    # 命令必须真能跑（用一句真实用户说法）
    rc, out = run([sys.executable, os.path.join(TOOL, "scripts", "route.py"),
                   "--resolve", "初步分析一下这个软件"], timeout=60)
    if rc != 0 or "softseep" not in (out or ""):
        bad.append("route.py --resolve 不可用或未命中 softseep（rc=%d）" % rc)
    add("2 单一事实源", "先路由后动手（AGENTS 硬条款 + 命令可跑 + 探针表）", not bad,
        "；".join(bad[:3]) if bad else "AGENTS 含条款，route.py --resolve 命中，探针表在")


def check_trigger_matrix():
    """触发面探针矩阵：用户原话 → 技能 / 路由 / KB，三层都必须命中。

    为什么是一条而不是三条：2026-10-24 实测同类病在三处各犯一次
    （skill description 写名词清单、route.py 没有口语、KB 只认术语），
    根因是**没有一张跨层探针表**。这一条就是那张表：
    任何一层对一句"用户真实说法"失配，就红，并点名是哪一层。
    """
    import json as _j
    import re as _re
    p = os.path.join(TOOL, "config", "trigger-probes.json")
    try:
        probes = _j.load(open(p, encoding="utf-8")).get("probes") or []
    except Exception as e:  # noqa: BLE001
        add("2 单一事实源", "触发面探针矩阵（用户原话 → 技能/路由/KB）", False, "探针表读失败 %s" % e)
        return

    descs = {}
    dep = set(os.listdir(os.path.expanduser("~/.pi/agent/skills"))) if os.path.isdir(
        os.path.expanduser("~/.pi/agent/skills")) else set()
    # 顶层 9 包 + 归档区（归档的只有**部署了**才算可见，否则模型看不到 = 等于不存在）
    cand = [(d, os.path.join(TOOL, "skill", d, "SKILL.md")) for d in os.listdir(os.path.join(TOOL, "skill"))]
    cand += [(d, os.path.join(TOOL, "skill", "_pending", d, "SKILL.md"))
             for d in os.listdir(os.path.join(TOOL, "skill", "_pending"))]
    for d, f in cand:
        if not os.path.isfile(f):
            continue
        if "_pending" in f and d not in dep:
            continue   # 归档且未部署 → 不进候选（探针若期望它会命中"技能缺失"）
        m = _re.search(r"^description:\s*(.+)$", open(f, encoding="utf-8").read(), _re.M)
        descs[d] = (m.group(1) if m else "").lower()

    # 命中判据：只认**实词**二元组（虚词二元组会把"帮我/这个"撞成假命中 —— 实测过，
    # 故意的错探针居然 PASS）。实词 = 两字都不在虚词表里。
    _FUNC = set("的了么吗呢是在有要和与怎么这个吧啊着我你他它先把给就都也很还对把被让从向为以"
                "帮我看看能不没下个一啥咋样")

    def _hit(desc: str, phrase: str) -> bool:
        ph = phrase.lower()
        for i in range(max(0, len(ph) - 1)):
            bg = ph[i:i + 2]
            if len(bg) == 2 and all(c in _FUNC for c in bg):
                continue
            if bg in desc:
                return True
        return False

    bad_skill = [x["phrase"] for x in probes
                 if x.get("expect_skill") and x["expect_skill"] in descs
                 and not _hit(descs[x["expect_skill"]], x["phrase"])]
    missing_skill = [x["expect_skill"] for x in probes if x.get("expect_skill") and x["expect_skill"] not in descs]

    # 路由层：同一句必须解析到期望的包（且不能只落在兜底 p=10）
    rc, out = run([sys.executable, os.path.join(TOOL, "scripts", "route.py"), "--resolve",
                   probes[0]["phrase"] if probes else "", "--json"], timeout=60)
    bad_route = []
    import subprocess as _sp
    for x in probes[:6]:            # 只抽查 6 句，控制耗时
        try:
            r = _sp.run([sys.executable, os.path.join(TOOL, "scripts", "route.py"),
                         "--resolve", x["phrase"], "--json"], capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=60, cwd=ROOT)
            d = json.loads((r.stdout or "").strip() or "{}")
            got = (d.get("pack") or d.get("skill") or "")
            if x.get("expect_skill") and got and got != x["expect_skill"]:
                bad_route.append("%s→%s(期望 %s)" % (x["phrase"], got, x["expect_skill"]))
        except Exception:
            pass

    bad = []
    if missing_skill:
        bad.append("技能缺失 " + ",".join(sorted(set(missing_skill))))
    if bad_skill:
        bad.append("描述不含说法 " + "；".join(bad_skill[:3]))
    if bad_route:
        bad.append("路由错投 " + "；".join(bad_route[:2]))
    # KB 层：用**术语**查询必须命中（KB 本身没坏）；口语查询目前不命中，是已知缺口，此处只统计不判红。
    kb_ok, kb_try = 0, 0
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(TOOL, "mcp"))
        import json as _j2
        import seep_mcp_server as _S   # noqa: F401  仅在门禁进程内导入，不改变 MCP 行为
        for x in probes[:4]:
            q = x.get("expect_kb")
            if not q:
                continue
            kb_try += 1
            out = _S.seep_kb_search(q)
            if isinstance(out, str) and _j2.loads(out if out.strip().startswith("[") else "[]"):
                kb_ok += 1
    except Exception:
        pass
    if kb_try and kb_ok < kb_try:
        bad.append("KB 术语查询 %d/%d 命中" % (kb_ok, kb_try))

    add("2 单一事实源", "触发面探针矩阵（%d 句用户原话 → 技能/路由/KB）" % len(probes), not bad,
        "；".join(bad)[:300] if bad
        else "%d 句命中期望技能；路由一致；KB 术语查询 %d/%d（口语查询仍不命中=已知缺口）"
             % (len(probes), kb_ok, kb_try))


def check_cross_layer():
    """跨层一致性两条：① 技能调用式引用 ↔ MCP 工具；② 回执 source 哈希不漂移。

    为什么放在 preflight 而不是单开脚本：这两条都是"层与层之间的接口"，坏掉的表现是
    「模型照文档调用不存在的工具，然后重试到死」和「回执替已改动的代码作证」，都属于 A 类。
    """
    import glob as _g
    import hashlib as _h
    import re as _re2

    # ① 技能里的调用式引用（mcp__seep__x 或 `seep_x(`）必须在服务端有定义
    try:
        src = open(os.path.join(TOOL, "mcp", "seep_mcp_server.py"), encoding="utf-8").read()
        srv = set(_re2.findall(r"^def (seep_[a-z0-9_]+)\(", src, _re2.M))
        files = _g.glob(os.path.join(TOOL, "skill", "*", "SKILL.md")) + \
            _g.glob(os.path.join(TOOL, "skill", "*", "references", "*.md"))
        bad, nref = [], 0
        for f in files:
            t = open(f, encoding="utf-8", errors="replace").read()
            for c in set(_re2.findall(r"mcp__seep__(\w+)", t)) | \
                    set(_re2.findall(r"`(seep_[a-z0-9_]+)\(", t)):
                nref += 1
                # 散文里的前缀写法（如 `seep_r2_*(...)`）不算引用：只要它是某个真实工具名去掉尾巴的前缀就跳过
                if c not in srv and not any(x.startswith(c) for x in srv):
                    bad.append("%s→%s" % (os.path.basename(os.path.dirname(f)), c))
        add("2 单一事实源", "技能里的工具引用都存在（防调用不存在的工具）", not bad,
            "；".join(sorted(set(bad))[:4]) if bad else "%d 处引用 / 服务端 %d 个工具" % (nref, len(srv)))
    except Exception as e:  # noqa: BLE001
        add("2 单一事实源", "技能里的工具引用都存在（防调用不存在的工具）", False, str(e)[:80])

    # ② 回执里登记过的 source 哈希必须仍等于当前文件（回执不许替改过的代码作证）
    bad_r, n_r = [], 0
    try:
        for rp in _g.glob(os.path.join(ROOT, "docs", "verification", "*.json")):
            try:
                d = json.load(open(rp, encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(d, dict):
                continue
            case = d.get("case")
            shas = d.get("source_sha256") or {}
            if not case or not isinstance(shas, dict):
                continue
            cdir = os.path.join(TOOL, "cases", case)
            for rel, want in shas.items():
                fp = os.path.join(cdir, rel.replace("/", os.sep))
                if not os.path.isfile(fp):
                    bad_r.append("%s→缺 %s" % (os.path.basename(rp), rel))
                    continue
                n_r += 1
                if _h.sha256(open(fp, "rb").read()).hexdigest() != want:
                    bad_r.append("%s→%s" % (os.path.basename(rp), rel))
        add("2 单一事实源", "回执未漂移（source 哈希仍匹配，回执不替改过的代码作证）",
            not bad_r, "；".join(bad_r[:4]) if bad_r else "%d 条回执 source 已比对" % n_r)
    except Exception as e:  # noqa: BLE001
        add("2 单一事实源", "回执未漂移（source 哈希仍匹配）", False, str(e)[:80])


def check_handoff_fresh():
    """HANDOFF 状态块新鲜度：生成块里的 HEAD 与当前 HEAD 距离 ≤3 个提交。

    背景：`docs/HANDOFF.md` 曾是手写状态，同一天内就写错（声称「52/52 绿 / S1 还没开始」，
    实际 S1–S5 已完成）。改成命令生成的块后，还要防「忘记重新生成」→ 落后 3 个提交即红。
    修法：`python Tool/scripts/case_state.py handoff --repo > 生成块`（或按文件内说明替换）。
    """
    import re as _re
    import subprocess as _sp

    f = os.path.join(ROOT, "docs", "HANDOFF.md")
    if not os.path.isfile(f):
        add("13 措辞", "HANDOFF 状态块新鲜（HEAD 落后 ≤1 提交）", False, "缺 docs/HANDOFF.md")
        return
    txt = open(f, encoding="utf-8", errors="replace").read()
    m = _re.search(r"handoff:HEAD=([0-9a-f]{7,40})", txt)
    if not m:
        add("13 措辞", "HANDOFF 状态块新鲜（HEAD 落后 ≤1 提交）", False,
            "没有生成块：跑 case_state.py handoff --repo 后替换 §1")
        return
    sha = m.group(1)
    try:
        # 先确认该提交在本地对象库里（浅克隆/新机器上可能没有 → 无法比对，跳过而不是假红）
        have = _sp.run(("git", "cat-file", "-e", "%s^{commit}" % sha), cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=20).returncode == 0
        if not have:
            add("13 措辞", "HANDOFF 状态块新鲜（HEAD 落后 ≤1 提交）", True,
                "浅克隆/提交不在本地对象库，跳过比对（重新生成一次即可）")
            return
        out = _sp.run(("git", "rev-list", "--count", "%s..HEAD" % sha),
                      cwd=ROOT, capture_output=True, text=True,
                      encoding="utf-8", errors="replace", timeout=20).stdout.strip()
        lag = int(out) if out.isdigit() else 999
    except Exception:
        lag = 999
    add("13 措辞", "HANDOFF 状态块新鲜（HEAD 落后 ≤1 提交）", lag <= 1,
        "落后 %d 个提交（≤1 才绿）；重新生成：case_state.py handoff --repo" % lag
        if lag > 3 else "落后 %d 个提交" % lag)


def check_extension_deploy():
    """扩展部署一致性：仓库 `Tool/prompts/extensions/*.ts` ↔ `~/.pi/agent/extensions/*.ts`。

    为什么需要：改了扩展但没重新部署，会话里跑的还是旧代码（实测踩到过：cmd-guard 的只读豁免已修，
    部署侧仍是旧版，而 skills 哈希检查不覆盖 extensions）→ 表现为"改完没生效"。
    判据：仓库里每个 .ts 都必须在部署侧存在且 sha256 相同；部署侧多出的 .ts 只看 warn（可能是用户自己的）。
    """
    import hashlib as _h
    src = os.path.join(TOOL, "prompts", "extensions")
    dst = os.path.join(os.path.expanduser("~"), ".pi", "agent", "extensions")
    if not os.path.isdir(src):
        add("13 措辞", "扩展部署一致（仓库 ↔ ~/.pi/agent/extensions）", False, "缺 Tool/prompts/extensions")
        return
    if not os.path.isdir(dst):
        add("13 措辞", "扩展部署一致（仓库 ↔ ~/.pi/agent/extensions）", False,
            "未部署：跑 setup/install-pi.ps1")
        return
    bad, n = [], 0
    for f in sorted(os.listdir(src)):
        if not f.endswith(".ts"):
            continue
        n += 1
        a = os.path.join(src, f)
        b = os.path.join(dst, f)
        if not os.path.isfile(b):
            bad.append(f + "(未部署)")
            continue
        ha = _h.sha256(open(a, "rb").read()).hexdigest()
        hb = _h.sha256(open(b, "rb").read()).hexdigest()
        if ha != hb:
            bad.append(f + "(哈希不一致)")
    add("13 措辞", "扩展部署一致（仓库 ↔ ~/.pi/agent/extensions）", not bad,
        "；".join(bad[:4]) if bad else "%d 个扩展哈希一致" % n)


def check_tool_ladder():
    """工具获取阶梯接线检查（behavior gate 第 1 项）。

    背景（2026-10-23 实测）：tool-run 1.3 秒把 x64dbg 起成 READY、端口在听，
    但会话里 ALL_TOOLS 没有 mcp__x64dbg → 模型没工具可调 → 手搓 5 个脚本，全程静默。
    根因是"拿端口在听当成连上了"，且没有统一的取用流程。

    本检查只问三件能机检的事：
      1) tool-acquire.py 存在且 --selftest 通过（阶梯本身能跑）
      2) 至少一个真实工具能被它判成 USABLE（判据不是"端口在听"）
      3) 阶段技能里接了阶梯指针（否则模型不知道要跑它）
    """
    script = os.path.join(TOOL, "scripts", "tool-acquire.py")
    if not os.path.isfile(script):
        add("18 工具阶梯", "tool-acquire 自检", False, "缺 tool-acquire.py")
        return
    try:
        p = subprocess.run([sys.executable, script, "--selftest"],
                           capture_output=True, timeout=120)
    except Exception as e:
        add("18 工具阶梯", "tool-acquire 自检", False, f"跑不起来：{e}")
        return
    out = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")
    ok = p.returncode == 0 and "PASS" in out
    line = next((ln for ln in out.splitlines() if "L0" in ln or "结论" in ln), out.strip()[:100])
    add("18 工具阶梯", "tool-acquire 自检（L0 判据=真探活，不是端口在听）", ok, line.strip()[:140])

    # 阶段技能是否接了指针
    missing, absent = [], []
    for name in ("00-triage", "00-analysis", "01-gate-bypass"):
        fp = os.path.join(TOOL, "skill", name, "SKILL.md")
        if not os.path.isfile(fp):
            fp = os.path.join(TOOL, "skill", "_pending", name, "SKILL.md")
        if not os.path.isfile(fp):
            absent.append(name)          # 找不到文件 = 红，不再静默跳过
            continue
        body = open(fp, encoding="utf-8", errors="replace").read()
        if "tool-acquire.py" not in body:
            missing.append(name)
    bad_stage = absent + missing
    add("18 工具阶梯", "阶段技能已接阶梯指针", not bad_stage,
        ("缺文件：" + ", ".join(absent) if absent else "") +
        ("；未接指针：" + ", ".join(missing) if missing else "")
        or "3 个阶段技能均已接")


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
    check_domain_packs()
    check_domain_depth()
    check_v123_deliverables()
    check_playbook_gate()
    check_mcp_contract()
    check_skill_route()
    check_race_e2e()
    check_doc_hygiene()
    check_language()
    check_side_effect_undo()
    check_trap_bait()
    check_extension_deploy()
    check_handoff_fresh()
    check_cross_layer()
    check_tool_cache_contract()
    check_need_ask_contract()
    check_trigger_matrix()
    check_route_first_contract()
    check_domain_commands()
    check_tool_ladder()
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
