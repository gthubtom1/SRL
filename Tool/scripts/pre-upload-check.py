#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pre-upload-check.py —— 上传前体检（**只读**）：这台机器上哪些数据不能传出去。

为什么要它（2026-10-26 用户口径）：
    "凭据可以随便存在本地，只是最后要清理；上传 GitHub 之前要提醒我本机有哪些数据不能传。"
    本地随便存 ≠ 随便上传。这个脚本只回答一个问题：**现在推 GitHub / 交客户，会带出去什么**。
    它不删文件、不改 .gitignore、不碰 git 状态，只打印清单 + 退出码。

三栏（对应三种处置）：
    [1] 会进 git 的敏感文件 —— 已跟踪（`git ls-files`）且命中路径规则：**必须处理**
        （移出 git / 改用 `~/.seep/` / 脱敏）。判据 4 类：
          ① 会话凭据：`**/capture/login.json`
          ② 密钥材料：`*.pem *.key *.p12 *.pfx *.jks *.kdbx *.ppk *.keystore`
          ③ `.env` 系：`.env` / `.env.local` …（`.env.example` 等模板不算）
          ④ 凭据类文件名：文件名里有 token / password / secret / cookie / authorization
             / credential，且是数据类扩展名（.json/.yaml/.txt/.har/…）
        同时也扫「未跟踪未 ignore」与「被本仓 .gitignore 拦住但还在盘上」的：
        前者一次 `git add -A` 就会进去，后者打包整个目录时会一起出去。
    [2] 不会进 git 但本机存在 —— 在 `.gitignore` 里（或 untracked）：**本地有、别打包分发**。
        按处置面分组统计（分析工作区 work/、本机私有 ~/.seep 与 ~/.pi、第三方运行时、
        本机生成配置、运行期残留），并点名其中"凭据/密钥形态"的文件。
    [3] 内容级命中 —— 扫已跟踪文本文件里的疑似凭据（4 类）：
          ① 私钥块 `-----BEGIN … PRIVATE KEY-----`
          ② AWS Access Key 形态 `AKIA[0-9A-Z]{16}`
          ③ `Bearer <20+ 字符>`
          ④ 凭据赋值 `password|secret|token|api_key … = <16+ 高熵串>`
        **只报「文件:行 + 类型」，绝不回显凭据内容**（不打印匹配值、不打印片段、不打码片段）。

放行分两种（都不隐藏，照常在报告里点名）：
    · 结构性放行：`Tool/upstream/**`、`Tool/mcp/Tool/**` 等 vendored 第三方代码 ——
      它是上游原样代码，改不动也不该改；照样列出来供人眼确认。
    · 显式放行（下方 `ALLOW` 表）：第一方文件里**已确认是公开示例/测试语料**的命中。
      加一条 = 明确承认"这处是假值"。默认全部阻断，不给人"配一个忽略目录"的后门。

用法：
    python Tool/scripts/pre-upload-check.py            # 人读三栏报告
    python Tool/scripts/pre-upload-check.py --json     # 机器读（Agent 用）
    python Tool/scripts/pre-upload-check.py --quiet    # 只打印三栏标题行与结论

退出码：1 = [1]/[3] 有未放行项，或 Git 清单不可用导致无法判定（阻止上传）；
        0 = [1]/[3] 已完成检查且没有阻断项（仍可能有 [2] 提醒）。
"""
from __future__ import annotations

import argparse
import collections
import fnmatch
import json
import math
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _repo_root(start):
    """仓库根：向上找含 Tool/cases 的目录（换机/被 symlink 调用时也不数错层）。"""
    d = os.path.abspath(start)
    for _ in range(8):
        if os.path.isdir(os.path.join(d, "Tool", "cases")):
            return d
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return os.path.dirname(os.path.dirname(HERE))


ROOT = _repo_root(HERE)

for _s in (sys.stdout, sys.stderr):
    if sys.platform == "win32":
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 —— 流被替换/已关闭时忽略
            pass

# ---------------------------------------------------------------------------
# 显式放行表：文件 → 理由。**只收"确认是公开示例/测试语料"的第一方命中**。
# 规则：路径用 fnmatch 通配（相对仓库根、`/` 分隔）；理由必须写清"为什么不是真凭据"。
# 加条目 = 承认这处值可以公开；不加就是红 —— 宁可误红，不可漏放。
# ---------------------------------------------------------------------------
ALLOW = {
    "Tool/skill/firmware-iot/references/03-model-pitfalls.md":
        "讲「设备私钥泄露」这一坑的说明文字，含私钥头样例行文，无密钥体",
    "Tool/skill/firmware-iot/scripts/fw-repro.py":
        "复现夹具：写一个带私钥头的假文件验证检测链，密钥体是 MIIEsecret 占位",
    "Tool/skill/firmware-iot/scripts/fw-triage.py":
        "分诊自测：夹具用私钥头（RSA）+ MIIEabcdef 占位体，不是密钥",
    "Tool/skill/web-pentest/scripts/osint-secret-scan.py":
        "检测器自身的正样本（AWS 官方文档示例键 AKIA…EXAMPLE 等，字面量故意写成两级拼接，"
        "不在文件里构成完整形态），必须是假值才能证明检测会红",
    "Tool/skill/_pending/ad-cloud/scripts/ad-accept.py":
        "自测：故意在 artifact 里写一行假 token，证明「凭据红线」会红；值本身是占位 JWT",
    "Tool/capabilities/osint-secret-scan.json":
        "能力声明（文件名含 secret，内容是扫描能力描述，无凭据值）",
    "Tool/cases/ad-cloud01/input/kubeconfig.yaml":
        "教学 kubeconfig 夹具：本地 minikube 示例 JWT（iss=kubernetes.default.svc、exp=2100），非真实集群",
    "Tool/cases/ad-cloud02/input/kubeconfig.yaml":
        "教学 kubeconfig 夹具：同 ad-cloud01，示例 JWT",
    "Tool/samples/real/js-obfuscated/lamz/input.js":
        "混淆样本：ACCESS_KEY 是生成的 UUID 占位符，用于演示关键字可读性",
    "Tool/samples/real/js-obfuscated/lamz/output.js":
        "混淆样本产物：同 input.js 的 ACCESS_KEY 占位符",
    # 下面三条是 2026-10-26 首跑时人工核实过的（值本身公开/夹具，已逐个打开确认）：
    "Tool/cases/_archive/*/docs/reverse-engineering.md":
        "沙箱实验记录：token 值是显式占位 LAB-SANDBOX-AI-ACTIVATION-TOKEN.0000…，非真实凭据",
    "Tool/cases/forensics04/work/unpacked/Payload/App.app/embedded.mobileprovision":
        "110 字节夹具：内容以 'TeamIdentifier: FIXTURE1' 开头的假 provisioning 描述文件",
    "Tool/skill/_pending/safe-skills/apk-reverse/debug.keystore":
        "Android SDK 官方 debug 签名密钥（口令 android、全 SDK 通用），不是真实发布签名密钥",
    "Tool/cases/web-pentest01/input/.env":
        "漏洞演示靶场的夹具 .env：值形如 fixture-db-password-not-real（占位词自证，无真凭据）",
    "Tool/cases/web-pentest02/input/.env":
        "同 web-pentest01：夹具 .env，用于演示「/.env 可访问」这条 finding",
    "Tool/scripts/test_r10_firmware_contracts.py":
        "固件分析脱敏单测：构造测试用假 Bearer 令牌与假 AWS Key 占位值，验证脱敏逻辑。",
    "Tool/scripts/test_r10a_contracts.py":
        "竞态与复现单测：构造测试用占位 secret 字符串，验证日志脱敏与脱敏红线。",
}

# 放行理由前缀：只有这类理由可以"自动判定"（值本身就是占位词）；
# 其余理由一律要求人写在 ALLOW 表里 —— 自动判据不得替人担保"这是客户真数据"。
AUTO_REASON_PLACEHOLDER = "值自证"

# 结构性放行：vendored 第三方代码（不阻断，但照样逐条列出）
VENDOR_PREFIXES = ("Tool/upstream/", "Tool/mcp/Tool/")

# 二进制/大对象：不做内容扫描（路径规则照样生效）
BIN_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".zip", ".jar",
           ".apk", ".dex", ".exe", ".dll", ".so", ".dylib", ".bin", ".pdf", ".woff",
           ".woff2", ".ttf", ".otf", ".7z", ".gz", ".tgz", ".bz2", ".xz", ".class",
           ".db", ".sqlite", ".idb", ".i64", ".pdb", ".lib", ".a", ".o", ".obj"}
MAX_SCAN_BYTES = 1_500_000      # 超过就不扫（大文件由路径规则/体积提醒覆盖）
MAX_LINE = 4000                 # 单行过长（压缩/mermaid/生成物）不扫，避免正则回吐

# ---- 第 1 栏：路径规则 -----------------------------------------------------
CRED_DATA_EXT = {"", ".txt", ".json", ".yaml", ".yml", ".har", ".ini", ".cfg", ".conf",
                 ".xml", ".csv", ".log", ".cookie", ".cookies", ".dat", ".tsv", ".sql"}
PATH_RULES = (
    ("会话凭据文件",
     re.compile(r"(^|/)capture/login\.json$", re.I)),
    ("密钥/凭据库文件",
     re.compile(r"\.(pem|key|p12|pfx|jks|kdbx|ppk|keystore|ovpn|mobileprovision)$", re.I)),
    (".env 文件",
     re.compile(r"(^|/)\.env(\.(?!(example|sample|template|dist)$)[\w.~-]+)?$", re.I)),
    ("凭据类文件名",
     re.compile(r"(?i)(^|[._-])(tokens?|passwords?|passwd|pwd|secrets?|cookies?|creds?|"
                r"credentials?|apikeys?|api[_-]?keys?|authorization|bearer)([._-]|$)")),
)

# ---- 第 3 栏：内容规则 -----------------------------------------------------
CONTENT_RULES = (
    ("私钥块", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("AWS Access Key", re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")),
    ("Bearer 令牌", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._\-]{20,})")),
    ("凭据赋值", re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|"
                          r"access[_-]?key|client[_-]?secret)\b\s*[=:]\s*([\"']?)"
                          r"([A-Za-z0-9+/_.\-]{16,})\2")),
)
# 占位值前缀：这些明显不是真凭据，不报（报只会训练人忽略告警）
PLACEHOLDER = re.compile(r"(?i)^(your|xxx+|a{6,}|b{6,}|c{6,}|e{6,}|changeme|placeholder|"
                         r"redacted|dummy|fake|example|sample|test|todo|none|null|"
                         r"0x[0-9a-f]+|\.\.\.|\$\{|\{\{|%s|\*+)")
# 占位词（整词匹配，**区分大小写**）：值里出现 fixture / notreal 这类小写占位词 → 自证的假值。
# 为什么要这一条：教学靶场的 .env 常写成 fixture-db-password-not-real，
# 前缀规则（fixture.）匹不到但熵值够高。没有它就只剩两种选择：误红整排靶场，
# 或给 `**/input/.env` 开目录级后门 —— 后者会把真凭据一起放过，所以宁可要这条。
# 为什么**不**加 (?i)（試过，错）：大小写不敏感时 `…NN7EXAMPLE` 这类占位键也会被当成
# “自证假值”而放行 —— 那是把"检测器自己的正样本"误当成安全，反向训练人忽略告警。
PLACEHOLDER_WORD = re.compile(
    r"(?:^|[^a-z])(fixture|notreal|not-real|not_real|dummy|fake|example|sample|"
    r"placeholder|redacted|changeme|yourapi|yourtoken|yourkey|testonly)(?:[^a-z]|$)")

# ---- 第 2 栏：本机私有资产分组（按处置面，不按目录）------------------------
# (标签, 前缀列表, 说明) —— 顺序即优先级，先命中先算
LOCAL_GROUPS = (
    ("分析工作区", ("work/",),
     "seep_task_init / 安全报告默认落点：目标样本、抓包、分析稿（用户数据，勿分发）"),
    ("本机私人目录", ("~/.seep/", "~/.pi/"),
     "会话状态与 Agent 凭据（auth.json / mcp-auth.json / tools.local.json），只在本人机器上"),
    ("第三方运行时", ("Tool/mcp/Tool/safe/", "Tool/upstream/"),
     "下游/上游自带的 venv、node_modules、大二进制（体积大且与机器绑定）"),
    ("本机生成配置", ("opencode.jsonc", "setup/cordis.generated.yml", "mcp.json",
                 "Tool/scripts/compliance-relay/relay-config.json", "tools.local.json",
                 "capture/login.json"),
     "由本机安装脚本生成、含本机绝对路径或访问 token"),
    ("运行期残留", (".pi/", ".playwright-mcp/", ".pytest_cache/", "evidence/", "Hook.log",
               "IDAHook.log"),
     "浏览器自动化截图/快照、审计调试残留"),
)
LOCAL_SENSITIVE_NAME = re.compile(
    r"(?i)((^|/)\.env($|\.(?!example|sample|template|dist))|"
    r"(^|/)capture/login\.json$|\.(pem|key|p12|pfx|jks|kdbx|ppk)$|"
    r"(token|password|passwd|secret|cookie|cred|apikey)[\w.-]*\."
    r"(json|txt|ya?ml|ini|conf|har|cookies?)$)")
LOCAL_PRUNE = {"node_modules", ".venv", "venv", "__pycache__", ".git", ".mypy_cache",
               ".pytest_cache", "site-packages", ".next"}

# 以下前缀里的 ignored 文件**不**逐条进第 1/3 栏（量太大：28k 个 venv/site-packages 文件）。
# 保守边界：.gitignore 里能出现在**这两个前缀内部**的规则只有 node_modules/、__pycache__/、
# **/capture/login.json（已单独覆盖），所以不会漏真正的本仓文件。
# 反过来的风险（宁红不绿）：若以后在 .gitignore 里给 Tool/upstream 或 Tool/mcp/Tool 内的
# 真实数据文件加忽略规则，那个文件会只出现在第 2 栏、不进第 1 栏 —— 见到这种情况请改这里。
BULK_IGNORED = ("work/", ".pi/", ".playwright-mcp/", ".pytest_cache/", "evidence/",
                "Tool/mcp/Tool/safe/", "Tool/upstream/")

# 上传体积提醒（GitHub 单文件 100MB 硬限、50MB 警告）
BIG_FILE_WARN = 50 * 1000 * 1000


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------
def _git(*args, timeout=120):
    """跑 git（只读命令）。没装 git / 不在工作树 → None（调用方降级，不假装成功）。"""
    try:
        p = subprocess.run(["git", "-C", ROOT] + list(args),
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=timeout)
    except Exception:  # noqa: BLE001 —— FileNotFoundError / 超时 / 权限
        return None
    if p.returncode != 0:
        return None
    return [x for x in p.stdout.decode("utf-8", "replace").split("\0") if x]


def _entropy(s):
    if not s:
        return 0.0
    c = collections.Counter(s)
    n = float(len(s))
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _norm(rel):
    """统一成 `/` 分隔、无前导 `./` 的相对路径。

    注意不能写 `lstrip("./")`：那是字符集剥离，会把 `.env` 削成 `env`（曾经就把
    `.env` / `.gitignore` 这类点开头文件全漏掉）。只剥整段 `./` 前缀。
    """
    p = str(rel or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _state_tag(item):
    """命中项的状态标签（已跟踪 / 未跟踪 / 已ignore）—— 不打印任何内容片段。"""
    st = item.get("state")
    if st == "untracked":
        return "未跟踪"
    if st == "ignored":
        return "已ignore"
    return "已跟踪"


def _value_is_placeholder(val):
    """值本身自证是假值？（占位前缀 或 含 fixture/not-real 之类整词）

    只用于**内容级**判定；路径级规则从不因内容而放行（漏一个真文件代价太高）。
    """
    return bool(PLACEHOLDER.match(val) or PLACEHOLDER_WORD.search(val))


def _allowed(rel):
    """显式放行表命中？返回理由或 None。"""
    rel = _norm(rel)
    for pat, why in ALLOW.items():
        if rel == pat or fnmatch.fnmatch(rel, pat):
            return why
    return None


def _vendored(rel):
    rel = _norm(rel)
    return any(rel.startswith(p) for p in VENDOR_PREFIXES)


def _size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d%s" % (n, unit)) if unit == "B" else ("%.1f%s" % (n, unit))
        n /= 1024.0
    return "%.1fGB" % n


# ---------------------------------------------------------------------------
# 第 1 栏：会进 git 的敏感文件
# ---------------------------------------------------------------------------
def check_tracked(tracked, loose=(), ignored_set=()):
    """已跟踪 + 路径规则。返回 (阻断项, 放行项)；每项 = dict(path, rule, allow, vendored)。

    loose：未进 git 但扫得到的文件（未跟踪未 ignore + 被本仓 .gitignore 拦住的）。
    它们现在还不进 git，但 `git add`（或打包整个目录）就会出去，
    所以按"会进 git"算（否则脚本会在最危险的那一刻给人绿灯）。
    """
    blocked, waived = [], []
    loose = set(_norm(x) for x in loose)
    ignored_set = set(_norm(x) for x in ignored_set)
    for rel in tracked:
        p = _norm(rel)
        base = p.rsplit("/", 1)[-1]
        ext = os.path.splitext(base)[1].lower()
        for rule, pat in PATH_RULES:
            if rule == "凭据类文件名":
                if ext not in CRED_DATA_EXT and ext != "":
                    continue          # .py/.md/.ts 里的 "token" 是代码不是数据
                if not pat.search(base):
                    continue
                # nmap 的 passwords.lst / creds.lua 这类字典文件是通用数据，不算凭据
                if re.search(r"(?i)(passwords?|creds?|secrets?)\.(lst|txt|dic|lua)$", base):
                    continue
            elif not pat.search(p):
                continue
            item = {"path": p, "rule": rule}
            if p in loose:
                if p in ignored_set:
                    item["state"] = "ignored"        # 本仓 .gitignore 拦住，但文件还在盘上
                else:
                    item["state"] = "untracked"      # `git add -A` 会直接把它带进去
            why = _allowed(p)
            if why:
                item["allow"] = why
                waived.append(item)
            elif _vendored(p):
                item["vendored"] = True
                waived.append(item)
            else:
                blocked.append(item)
            break
    return blocked, waived


# ---------------------------------------------------------------------------
# 第 3 栏：内容级命中（只报 文件:行 + 类型）
# ---------------------------------------------------------------------------
def check_content(tracked, loose=(), ignored_set=()):
    """扫已跟踪文本文件（+ 未进 git 但扫得到的，见 check_tracked 的说明）。

    返回 (阻断项, 放行项)；每项 = dict(path, line, rule, allow)。
    """
    blocked, waived = [], []
    loose = set(_norm(x) for x in loose)
    ignored_set = set(_norm(x) for x in ignored_set)
    for rel in tracked:
        p = _norm(rel)
        if os.path.splitext(p)[1].lower() in BIN_EXT:
            continue
        fp = os.path.join(ROOT, p.replace("/", os.sep))
        if not os.path.isfile(fp) or _size(fp) > MAX_SCAN_BYTES:
            continue                      # 已跟踪但本地没有（浅克隆/稀疏检出）→ 跳过
        try:
            with open(fp, "rb") as f:
                raw = f.read()
        except OSError:
            continue
        if b"\x00" in raw[:8192]:          # 二进制伪装成文本
            continue
        for line_no, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
            if len(line) > MAX_LINE:
                continue
            for rule, pat in CONTENT_RULES:
                hit = False
                auto = False
                for m in pat.finditer(line):
                    if rule in ("Bearer 令牌", "凭据赋值"):
                        val = m.group(1) if rule == "Bearer 令牌" else m.group(3)
                        if PLACEHOLDER.match(val):
                            continue
                        if rule == "凭据赋值":
                            if not (any(ch.isdigit() for ch in val)
                                    and any(ch.isalpha() for ch in val)):
                                continue          # 纯标识符/纯数字（如 secret=0x140003000）
                            if _entropy(val) < 3.3:
                                continue          # 低熵 = 变量名/路径/重复字符，不是凭据
                        if _value_is_placeholder(val):
                            auto = True               # 值自证是占位值 → 记为自动放行
                            continue
                    hit = True
                    break
                if auto and not hit:
                    waived.append({"path": p, "line": line_no, "rule": rule,
                                   "allow": AUTO_REASON_PLACEHOLDER})
                    break
                if not hit:
                    continue
                item = {"path": p, "line": line_no, "rule": rule}
                if p in loose:
                    item["state"] = "ignored" if p in ignored_set else "untracked"
                why = _allowed(p)
                if why:
                    item["allow"] = why
                    waived.append(item)
                elif _vendored(p):
                    item["vendored"] = True
                    waived.append(item)
                else:
                    blocked.append(item)
                break                     # 一行只报一个类型（避免同一行刷屏）
    return blocked, waived


# ---------------------------------------------------------------------------
# 第 2 栏：不会进 git 但本机存在
# ---------------------------------------------------------------------------
def _walk(prefixes_abs, prune=LOCAL_PRUNE, base=None):
    """按前缀目录遍历（剪掉 node_modules/.venv 等）。返回 [(相对路径, 字节)]。

    base：相对路径的基准（默认仓库根）。~/.pi 在另一个盘符时不能用仓库根算 relpath。
    """
    base = base or ROOT
    out = []
    for absdir in prefixes_abs:
        if not os.path.isdir(absdir):
            continue
        for dp, dirs, files in os.walk(absdir):
            dirs[:] = [d for d in dirs if d not in prune]
            for f in files:
                fp = os.path.join(dp, f)
                try:
                    rel = os.path.relpath(fp, base).replace(os.sep, "/")
                except ValueError:      # Windows：跨盘符 relpath 会抛，退回绝对路径
                    rel = fp.replace(os.sep, "/")
                out.append((rel, _size(fp)))
    return out


def _repo_internal_ignored():
    """`.gitignore` 命中的**本仓文件**（排掉 BULK_IGNORED 那些一大片的第三方/工作区）。

    为什么要把它们算进第 1/3 栏：刚加进 .gitignore 的 `*.pem` 不会把盘上的 `x.pem` 变没，
    它只是拦住下次 `git add`。对“上传”这个动作而言，被本仓规则拦住 = “现在不会传”，
    但文件还在，而且本仓内部**没有任何 ignore 规则**会把 Tool/skill/**、Tool/cases/** 里的
    第一方文件排除（查过：只有 node_modules/、__pycache__/、/work/、**/capture/login.json），
    所以这里多扫的代价接近 0，而漏扫代价是“以为安全就传了出去”。
    """
    ign = _git("ls-files", "-o", "-i", "--exclude-standard", "-z")
    if ign is None:
        return None
    out = []
    for rel in ign:
        p = _norm(rel)
        if any(p.startswith(b) for b in BULK_IGNORED):
            continue
        out.append(p)
    return out


def check_local(tracked_set, untracked):
    """本机存在但不会进 git 的东西：被 ignore 的（`git ls-files -o -i`）+ untracked。

    为什么要传 untracked 进来：未跟踪且未被 ignore 的文件能同时落进
    `planning`（会进 git）与 `ignored`（本机存在，但文件的确在盘上）两个集合；
    两边各自统计，不重不漏。
    """
    ignored = _git("ls-files", "-o", "-i", "--exclude-standard", "-z")
    if ignored is None:
        ignored = list(untracked or [])
        git_ok = False
    else:
        git_ok = True
    ignored = [_norm(x) for x in ignored]
    for x in untracked:                      # 本机确实存在，只是下一步才会被 add
        if _norm(x) not in ignored:
            ignored.append(_norm(x))
    # 每组：直接数 ignore 清单（快、与 git 口径一致）；体积按目录实测
    groups = collections.OrderedDict()
    for label, prefixes, hint in LOCAL_GROUPS:
        groups[label] = {"label": label, "hint": hint, "count": 0, "bytes": 0,
                         "sensitive": [], "prefixes": prefixes}

    def group_of(rel):
        for label, prefixes, _hint in LOCAL_GROUPS:
            for pre in prefixes:
                if pre.startswith("~/"):
                    continue              # home 目录不在这张清单里
                if rel == pre.rstrip("/") or rel.startswith(pre):
                    return label
        if rel.startswith("Tool/mcp/Tool/safe/"):
            return "第三方运行时"
        return "其它本机残留"

    other = {"label": "其它本机残留", "hint": "零散 untracked / ignore 命中",
             "count": 0, "bytes": 0, "sensitive": [], "prefixes": []}
    for rel in ignored:
        g = group_of(rel)
        bucket = other if g == "其它本机残留" else groups[g]
        bucket["count"] += 1
        if LOCAL_SENSITIVE_NAME.search(rel) and len(bucket["sensitive"]) < 12:
            bucket["sensitive"].append(rel)
    rows = [v for v in list(groups.values()) + [other] if v["count"]]

    # 体积：只对存在的目录前缀实测（避免 2.9 万个文件逐个 stat）
    for row in rows:
        prefixes = [p for p in row["prefixes"] if not p.startswith("~/")]
        paths = []
        for pre in prefixes:
            ap = os.path.join(ROOT, pre.replace("/", os.sep).rstrip(os.sep))
            if os.path.isdir(ap):
                paths.append(ap)
            elif os.path.isfile(ap):
                row["bytes"] += _size(ap)
        if paths:
            for _rel, sz in _walk(paths):
                row["bytes"] += sz
    # 体积实测后，把它换算成"文件数也对得上"的直觉值；没有可测前缀（零散残留）就标 —
    for row in rows:
        row["size"] = _human(row["bytes"]) if row["bytes"] else "—"

    # 本机 home 下的私有目录（不进仓库，但换机/打包交付时最容易被一起带走）
    home = os.path.expanduser("~")
    home_rows = []
    for name in (".seep", ".pi"):
        d = os.path.join(home, name)
        if not os.path.isdir(d):
            continue
        files = _walk([d], base=home)
        tracked_home = [r for r, _s in files if r in tracked_set]
        sens = [r for r, _s in files if LOCAL_SENSITIVE_NAME.search(r)][:8]
        home_rows.append({"label": "~/%s" % name, "count": len(files),
                          "size": _human(sum(s for _r, s in files)),
                          "sensitive": sens, "tracked": tracked_home,
                          "hint": "本机私有（Agent 凭据/会话状态），绝不打包分发"})
    return rows, home_rows, git_ok


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="上传前体检（只读）：会进 git 的敏感文件 / 本机不该外带的目录 / 内容级凭据命中",
        epilog="退出码：1 = 会进 git 的敏感文件或内容级命中（阻止上传）；0 = 干净（第 2 栏仍可能提醒）。")
    ap.add_argument("--json", action="store_true", help="输出 JSON（Agent 读）")
    ap.add_argument("--quiet", action="store_true", help="只打印栏目标题行与结论")
    a = ap.parse_args(argv)

    tracked = _git("ls-files", "-z")
    untracked = _git("ls-files", "-o", "--exclude-standard", "-z")
    git_ok = tracked is not None
    tracked = tracked or []
    untracked = untracked or []
    tracked_set = {_norm(x) for x in tracked}

    if git_ok:
        # 扫描面 = 已跟踪 + 未跟踪未 ignore + 已被本仓 .gitignore 拦住的（见 _repo_internal_ignored）
        extra = _repo_internal_ignored() or []
        seen = set(tracked_set)
        loose = set()
        for x in list(untracked) + list(extra):
            nx = _norm(x)
            if nx in seen:
                continue
            loose.add(nx)
        scan = tracked + sorted(loose)
        t_block, t_waive = check_tracked(scan, loose, extra)
        c_block, c_waive = check_content(scan, loose, extra)
    else:
        t_block, t_waive, c_block, c_waive = [], [], [], []
    local_rows, home_rows, ignored_ok = check_local(tracked_set, untracked)

    big = sorted(((_size(os.path.join(ROOT, p.replace("/", os.sep))), p) for p in tracked),
                 reverse=True)
    big = [(s, p) for s, p in big if s >= BIG_FILE_WARN][:5]

    # Git 清单不可用时第 1/3 栏根本没有被检查。上传安全门必须 fail closed：
    # 不能把“无法判定”输出成 ok=true / rc=0，让聚合门禁误以为敏感文件与内容扫描已通过。
    rc = 1 if (not git_ok or t_block or c_block) else 0

    if a.json:
        print(json.dumps({
            "ok": rc == 0, "rc": rc, "git": git_ok,
            "tracked_sensitive": t_block, "tracked_sensitive_waived": t_waive,
            "content_hits": c_block, "content_hits_waived": c_waive,
            "local_only": local_rows, "home_private": home_rows,
            "big_tracked": [{"path": p, "size": s} for s, p in big],
        }, indent=2, ensure_ascii=False))
        return rc

    print("上传前体检（只读，不改文件/不改 git）：%s" % ROOT)
    if not git_ok:
        print("[WARN] 没装 git 或不在工作树：第 1/3 栏无法判定（只做第 2 栏），"
              "换机自检请在有 git 的机器上跑")

    # ---------------- [1]
    print()
    print("[1] 会进 git 的敏感文件（已跟踪 + 未跟踪未 ignore 且命中路径规则 → 必须处理）")
    if not git_ok:
        print("    跳过（没有 git 清单）")
    elif not t_block:
        print("    0 条（无 —— 没有已跟踪/未跟踪的凭据、密钥文件）")
    else:
        for it in t_block:
            print("    ✗ [%s] %-48s  %s" % (_state_tag(it), it["path"], it["rule"]))
        print("    → 处置：移出 git（git rm --cached）+ 加进 .gitignore；或改存到 ~/.seep/")
        if any(it.get("state") == "untracked" for it in t_block):
            print("    → 标「未跟踪」的还没进 git，但 `git add -A` 会带进去：先删或先加 .gitignore")
        if any(it.get("state") == "ignored" for it in t_block):
            print("    → 标「已ignore」的已被本仓 .gitignore 拦住（git 不会传），但文件还在盘上："
                  "打包整个目录时会一起出去，删掉或挪进 ~/.seep/ 才算完")
    if t_waive:
        print("  已放行 %d 条（工具链/第三方/显式登记，仍列给你确认）：" % len(t_waive))
        for it in t_waive[:12]:
            tag = "第三方" if it.get("vendored") else "已登记"
            print("    · [%s] %-52s %s" % (tag, it["path"], it["rule"]))
        if len(t_waive) > 12:
            print("    · …另有 %d 条（--json 看全量）" % (len(t_waive) - 12))

    # ---------------- [3]（放在第 2 栏之前：它才是阻断项）
    print()
    print("[3] 内容级命中（已跟踪文本文件里的疑似凭据；只报 文件:行 + 类型，不回显内容）")
    if not git_ok:
        print("    跳过（没有 git 清单）")
    elif not c_block:
        print("    0 条（无 —— 没有命中私钥块/AKIA/Bearer/凭据赋值）")
    else:
        for it in c_block:
            print("    ✗ [%s] %-44s:%-5d  %s"
                  % (_state_tag(it), it["path"], it["line"], it["rule"]))
        print("    → 处置：改成占位值（<TOKEN>）或删掉；确属公开示例就在脚本 ALLOW 表登记理由")
    if c_waive:
        perfile = collections.Counter((it["path"], it["rule"]) for it in c_waive)
        auto_n = sum(1 for it in c_waive if it.get("allow") == AUTO_REASON_PLACEHOLDER)
        print("  已放行 %d 处命中（%d 个文件；第三方 vendored / ALLOW 登记 / 值自证占位 %d 处）："
              % (len(c_waive), len(perfile), auto_n))
        for (p, rule), n in list(perfile.items())[:10]:
            tag = "第三方" if _vendored(p) else (
                "值自证" if _allowed(p) == AUTO_REASON_PLACEHOLDER else "已登记")
            if not _vendored(p) and tag != "值自证":
                tag = "已登记"
            print("    · [%s] %-52s %-12s ×%d" % (tag, p, rule, n))
        if len(perfile) > 10:
            print("    · …另有 %d 个文件（--json 看全量）" % (len(perfile) - 10))

    # ---------------- [2]
    print()
    print("[2] 不会进 git 但本机存在（在 .gitignore 里 / untracked → 本地有、别打包分发）")
    if not local_rows:
        print("    0 组（没有本机残留）")
    for row in local_rows:
        print("    · %-12s %5d 个文件 %8s  %s"
              % (row["label"], row["count"], row["size"], row["hint"]))
        for s in row["sensitive"][:5]:
            print("        ‼ 凭据形态：%s（别打包/别贴公网）" % s)
        if len(row["sensitive"]) > 5:
            print("        ‼ …另有 %d 个凭据形态文件" % (len(row["sensitive"]) - 5))
    for row in home_rows:
        flag = ""
        if row["tracked"]:
            flag = "  ✗ 其中 %d 个竟已被 git 跟踪！" % len(row["tracked"])
        print("    · %-12s %5d 个文件 %8s  %s%s"
              % (row["label"], row["count"], row["size"], row["hint"], flag))
        for s in row["sensitive"][:4]:
            print("        ‼ 凭据形态：%s" % s)
    if not ignored_ok:
        print("    [WARN] 拿不到 `git ls-files -o -i`：只列了 untracked")

    # ---------------- 体积提醒
    if big:
        print()
        print("[附] 已入库的大文件（GitHub 单文件 >50MB 警告 / >100MB 拒收）")
        for s, p in big:
            print("    · %8s  %s" % (_human(s), p))

    print()
    if not git_ok:
        print("结果: 无法判定，阻止上传 —— Git 清单不可用，敏感文件与内容级凭据均未检查")
        print("修完后复跑：python Tool/scripts/pre-upload-check.py")
    elif rc:
        print("结果: 阻止上传 —— 会进 git 的敏感文件 %d 条 / 内容级命中 %d 条（本机仅提醒 %d 组）"
              % (len(t_block), len(c_block), len(local_rows)))
        print("修完复跑：python Tool/scripts/pre-upload-check.py")
    else:
        print("结果: 可以上传 —— 会进 git 的敏感文件 0 条 / 内容级命中 0 条"
              "（本机仅提醒 %d 组，打包交付前仍要排除）" % len(local_rows))
    return rc


if __name__ == "__main__":
    sys.exit(main())
