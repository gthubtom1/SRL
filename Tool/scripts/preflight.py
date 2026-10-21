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
    detail = "两平台运行时项数一致（运行时展开见 verify 输出）" if n1 == n2 else f"不一致：ps1={n1} sh={n2}"
    add("3 平台", "verify.ps1 / verify.sh 项数一致", n1 == n2, detail)


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
        "reverse.md": [(r"case_state\.py\s+gate\b", "case_state.py gate"), ("deliver", "deliver")],
        "reverse-deliverable.md": [(r"case_state\.py\s+gate\b", "case_state.py gate"), ("deliver", "deliver")],
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
    check_persona_gate()
    check_taskcards_gate()
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
