#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""变异测试（植入失败）—— **隔离版**：只在临时 fixture 里弄坏，真实仓库零写入。

为什么改（2026-10 审计）：旧版为了证明"判据真的会红"，**直接改真实仓库的 5 个受保护文件**
（案例 MANIFEST / 两个 SKILL.md / pack.json / README.md），**并往仓库外** `~/.pi/agent/prompts/`
落一张假提示词。它在 `finally` 里按字节还原，但进程被强杀/断电/KeyboardInterrupt 落在
`finally` 之前，受保护文件就留在被篡改状态；`~/.pi` 的残留文件连 `git checkout` 都兜不住。
于是"证明判据会红"的手段本身成了最危险的一步；变异测试与验收完整性记录另存为测试证据。

现在怎么做（判据一点没放宽）：
  1. 夹具 = **当前工作树的真实字节**：`git ls-files` + `git status -uall` 的 `??`，
     所以"当前未提交代码"也进夹具，不用 mock 补丁顶替判据。
  2. 每个植入一个**独立** `TemporaryDirectory` 仓库副本 + 独立 agent-root（fixture home）。
  3. 用户目录**不改 HOME/USERPROFILE/CODEX_HOME**：给子进程注入 `PYTHONPATH=<hook>`，
     hook 是 `sitecustomize.py`，只把 `os.path.expanduser("~…")` 映射到 `SEEP_ISO_HOME`。
     所有写盘路径都过 `Fixture.path()` / `home_path()` 的包含性校验，越界即抛 `IsolationError`。
  4. checker 一律**真跑**（`gate.py --all` / `preflight.py --fast`），不 mock 判据。
  5. 断言用**基线 delta**：先在纯净 fixture 上跑一次记 FAIL 行基线，植入后只认**新增** FAIL
     行且必须含该植入的 `expect` 子串（基线已含 → `unverified`）。
  6. 跑不起来 / 基线已红 / 植入未生效 → `unverified`，**不计 pass**，退出码非 0。

用法：
    python Tool/scripts/mutation.py                 # 全部植入（默认并行 3）
    python Tool/scripts/mutation.py --fast          # 只跑快子集
    python Tool/scripts/mutation.py --only m1,m5    # 只跑指定植入
    python Tool/scripts/mutation.py --jobs 4        # 并行度（上限 1..4）
    python Tool/scripts/mutation.py --keep          # 保留 fixture（诊断用，需自己删）
    python Tool/scripts/mutation.py --json
退出码：0 = 全部被抓（每项都有新增 FAIL 且命中目标判据）
        1 = 有漏网 / 判据跑不起来 / 基线已红（unverified 也是 1，不当 pass）
        2 = 用法错误

隔离边界（如实声明，别读成"什么都没改"）：
  * 真实仓库：只读（`git ls-files` / `git status` 只读子命令 + 读文件字节）。
  * 真实用户目录：只读一次清单 + 起止哈希（隔离防护校验用），**不读凭据**、不复制无关目录。
  * 唯一写盘：`TemporaryDirectory` 内的 repo 副本与 fixture home，进程退出即删。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PY = sys.executable
DEFAULT_JOBS = 3
MAX_JOBS = 4

# 子进程只允许出现这几个 task-specific 变量（其它一律从当前 env 里继承，但 HOME 类不碰）
ISO_ENV_KEYS = ("SEEP_ISO_HOME", "PYTHONPATH", "PYTHONIOENCODING", "PYTHONDONTWRITEBYTECODE")

# 夹具默认**不跳任何目录**：跳目录会让 checker 在纯净夹具上就红（实测：跳过案例大目录
# 会把「事实漂移」的案例数算错、跳过 Tool/upstream 会让「悬空引用」多 71 处），
# 于是对应植入变成"基线已红 → 不可判定"。宁可多拷 390MB，也不要让判据失真。
# 这里只保留三类防御性排除：git 元数据、字节码缓存、虚拟环境（都不该进判据输入）。
SKIP_NAMES = ("__pycache__", ".git", ".venv")
SKIP_DIRS = ()

# 夹具并发上限需要的磁盘余量倍数（每个在跑的植入一份完整副本 + 1 份基线副本）
DISK_COPIES = MAX_JOBS + 1


class IsolationError(RuntimeError):
    """植入函数试图写到 fixture 之外 —— 直接失败，不请求放行。"""


# ─────────────────────────────── 夹具 ────────────────────────────────
def _sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def repo_manifest(src=ROOT):
    """当前工作树 == 该进夹具的文件：git 跟踪 + `??` 未跟踪（**不含**忽略区）。

    只读：`git ls-files -z` / `git status --porcelain -uall -z`。
    """
    tracked = subprocess.run(["git", "ls-files", "-z"], cwd=src, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=120).stdout
    untracked = subprocess.run(["git", "status", "--porcelain", "-uall", "-z"], cwd=src,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=120).stdout
    files = [f.decode("utf-8", "replace") for f in tracked.split(b"\0") if f]
    for rec in untracked.split(b"\0"):
        if rec.startswith(b"?? "):
            files.append(rec[3:].decode("utf-8", "replace"))
    seen, out = set(), []
    for rel in files:
        rel = rel.replace("\\", "/")
        if rel and rel not in seen:
            seen.add(rel)
            out.append(rel)
    return sorted(out)


def _skipped(rel):
    if any(rel == d or rel.startswith(d + "/") for d in SKIP_DIRS):
        return True
    return any(part in SKIP_NAMES for part in rel.split("/"))


def manifest_bytes(files):
    """夹具大概占多少字节（只 stat，不读内容）。"""
    total = 0
    for rel in files:
        if _skipped(rel):
            continue
        try:
            total += os.path.getsize(os.path.join(ROOT, rel))
        except OSError:
            pass
    return total


class Fixture:
    """临时仓库副本 + 独立 agent-root。所有写入必须落在 self.root 或 self.home 内。"""

    def __init__(self, files, tag="", keep=False):
        self.keep = keep
        self.tmp = tempfile.mkdtemp(prefix="seep-mut-%s-" % (tag or "x"))
        self.root = os.path.join(self.tmp, "repo")
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.root, exist_ok=True)
        os.makedirs(self.home, exist_ok=True)
        self.files = files
        self._copied = 0
        for rel in files:
            if _skipped(rel):
                continue
            src = os.path.join(ROOT, rel)
            if not os.path.isfile(src):
                continue
            dst = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)
            self._copied += 1

    # —— 包含性校验：越界即抛，绝不"先原地改再恢复" ——
    def _inside(self, base, p):
        rb, rp = os.path.realpath(base), os.path.realpath(p)
        if rb != rp and not rp.startswith(rb + os.sep):
            raise IsolationError("写盘越界（fixture 之外）：%s 不在 %s 内" % (rp, rb))
        return rp

    def path(self, rel):
        return self._inside(self.root, os.path.join(self.root, rel))

    def home_path(self, *parts):
        return self._inside(self.home, os.path.join(self.home, *parts))

    def clean(self):
        if getattr(self, "keep", False):
            print("[keep] fixture 保留：%s" % self.tmp)
            return
        shutil.rmtree(self.tmp, ignore_errors=True)


# ─────────────────────── 子进程：独立 agent-root ──────────────────────
_SITECUSTOMIZE = '''\
# 由 Tool/scripts/mutation.py 生成的隔离 hook（只在 fixture 子进程里生效）。
# 唯一作用：把 os.path.expanduser("~...") 指到 SEEP_ISO_HOME。
# 刻意**不改** HOME/USERPROFILE/CODEX_HOME —— 不改用户全局 env。
import os

_iso_home = os.environ.get("SEEP_ISO_HOME")
if _iso_home:
    _real_expanduser = os.path.expanduser

    def _expanduser(path):
        if isinstance(path, str):
            if path == "~":
                return _iso_home
            if path.startswith("~/") or path.startswith("~\\\\"):
                return os.path.join(_iso_home, path[2:])
        return _real_expanduser(path)

    os.path.expanduser = _expanduser
'''


def write_hook(hookdir):
    os.makedirs(hookdir, exist_ok=True)
    fp = os.path.join(hookdir, "sitecustomize.py")
    with open(fp, "w", encoding="utf-8", newline="\n") as f:
        f.write(_SITECUSTOMIZE)
    return hookdir


def child_env(fx, hookdir):
    """Keep HOME unchanged; bind application roots to this test fixture."""
    env = dict(os.environ)
    env["SEEP_ISO_HOME"] = fx.home
    env["PI_CODING_AGENT_DIR"] = fx.home_path(".pi", "agent")
    env["PI_AGENT_DIR"] = fx.home_path(".pi", "agent")
    env["SEEP_RUNTIME_ROOT"] = fx.root
    old = env.get("PYTHONPATH") or ""
    env["PYTHONPATH"] = hookdir + ((os.pathsep + old) if old else "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run_in(fx, hookdir, argv, timeout=1200):
    """在 fixture 仓库里真跑一个 checker。返回 (rc, 合并输出)。"""
    try:
        p = subprocess.run([PY, "-B", "-X", "utf8"] + argv, cwd=fx.root,
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", env=child_env(fx, hookdir), timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, "[mutation] checker 超时（>%ds）：%s" % (timeout, " ".join(argv))
    except Exception as e:  # noqa: BLE001
        return -2, "[mutation] checker 无法执行：%s: %s" % (type(e).__name__, e)


# checker "真的跑起来了"的最低证据：至少产出一条判据行。
# 为什么需要：`python Tool/scripts/does-not-exist.py` 也是 rc=2、零 [FAIL]，
# 只看"零新增 FAIL"会把它误判成"植入没被抓到 = 判据是装饰品"，方向正好反了。
JUDGE_MARKERS = ("[FAIL", "[PASS", "[GATE]", "[WARN", "[INFO", "结果:", "[VERIFY")


def looks_runnable(out):
    return any(m in (out or "") for m in JUDGE_MARKERS)


CHR_BS = chr(92)


def normalize_paths(text):
    """把"每个 fixture 都不同的临时路径"抹成占位符，再比对 FAIL 行。

    为什么必须做：基线跑在 base fixture、植入跑在 m? fixture，两者临时根不同；
    「找不到 <tmp>/seep-mut-m3-xxxx/home/.pi/agent/mcp.json」这类行会因为路径不同
    而"看起来是新增 FAIL" —— 那是噪声，不是证据，会把 delta 判据变成摆设。

    实现上先统一成正斜杠再按路径段替换，不用正则 —— 避免转义歧义。
    """
    if not text:
        return text
    tdir = tempfile.gettempdir().replace(CHR_BS, "/")
    out = text.replace(CHR_BS, "/").replace(tdir, "<tmp>")
    # 盘符写法不同（D:/tmp 与 /tmp）：只抹"临时根最后一个路径段 + /seep-mut-"，不误伤其它路径
    base = tdir.rsplit("/", 1)[-1]
    if base:
        out = out.replace("/" + base + "/seep-mut-", "/<tmp>/seep-mut-")
    parts = out.split("/")
    for i, part in enumerate(parts):
        if part.startswith("seep-mut-"):
            parts[i] = "<fixture>"
    # 同一临时根的两种写法（`D:/tmp/...` 与 `/tmp/...`）归一，避免"路径前缀不同"造成假新增
    return "/".join(parts).replace("/<tmp>/", "<tmp>/")


def fail_lines(out):
    """把 checker 输出里的**判据失败**行拍平，便于 delta 比对。

    两种输出结构都要接住：
      * preflight.py：单行 `[FAIL] 名称 — 详情`
      * gate.py：`[FAIL] <pack>` 之后跟缩进的 `- <原因>`（原因行本身不带 [FAIL]）
    gate 的"原因行"必须收进来，否则 `[FAIL] pwn-crypto` 这种粒度过粗——
    只证"这个包红了"，不证"是 G2 抓的"。原因行统一加 `[原因] <pack>/` 前缀，
    这样 m1 可以要求命中"哈希不符"、m5 可以要求命中"未声明字段"。
    只取失败口径；`[WARN]/[INFO]` 与 `G4 skipped` 两边都不算证据。
    """
    rows, cur = [], ""
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("[FAIL"):
            cur = s[len("[FAIL]"):].strip(" []") if "]" in s else ""
            rows.append(normalize_paths(s))
            continue
        # gate 的原因行：缩进 + 以 "- " 开头
        if line[:1].isspace() and s.startswith("- ") and cur:
            rows.append(normalize_paths("[原因] %s/%s" % (cur, s[2:])))
    return rows


# ─────────────────────────────── 植入 ────────────────────────────────
IMPLANTS = []


def implant(name, checker, expect, fast=True, baseline_note=""):
    def deco(fn):
        IMPLANTS.append({"id": name, "checker": checker, "expect": expect,
                         "fast": fast, "fn": fn, "baseline_note": baseline_note})
        return fn
    return deco


# 1. 改一条案例 MANIFEST 哈希 → 该包必须红（G4/G6 会点名哈希不符）
@implant("m1", ["Tool/scripts/gate.py", "--all"], ["softseep", "哈希不符"])
def m1(fx):
    rel = "Tool/cases/golden-crackme/artifacts/MANIFEST.sha256"
    p = fx.path(rel)
    with open(p, encoding="utf-8") as f:
        lines = f.read().splitlines()
    hit = False
    for i, line in enumerate(lines):
        if line.strip() and not line.startswith("#"):
            h, rest = line.split(None, 1)
            lines[i] = ("0" * 64 if h[0] != "0" else "1" * 64) + " " + rest
            hit = True
            break
    if not hit:
        raise IsolationError("夹具里 MANIFEST 没有可篡改的行：%s" % rel)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


# 2. 把技能描述换成中性描述 → 触发面探针必须红
@implant("m2", ["Tool/scripts/preflight.py", "--fast"], ["触发面探针矩阵", "描述不含说法"])
def m2(fx):
    p = fx.path("Tool/skill/softseep/SKILL.md")
    with open(p, encoding="utf-8") as f:
        src = f.read()
    out = re.sub(r"^description:.*$", 'description: "通用二进制分析工具"', src,
                 count=1, flags=re.M)
    if out == src:
        raise IsolationError("夹具里 softseep/SKILL.md 没有 description 行可改")
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(out)


# 3. 给普通域技能加"总控"字样 → 总控唯一判据必须红
@implant("m3", ["Tool/scripts/preflight.py", "--fast"], ["总控唯一", "含「总控」"])
def m3(fx):
    p = fx.path("Tool/skill/apkseep/SKILL.md")
    with open(p, encoding="utf-8") as f:
        s = f.read()
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write("<!-- 本文件是总控 Orchestrator -->\n" + s)


# 4. 往 fixture agent-root 放本项目受管的退役提示词 → 提示词残留必须红
#    ★ manifest 绑定 fixture 源根与当前内容哈希；无受管身份的用户卡应保留，不算残留。
@implant("m4", ["Tool/scripts/preflight.py", "--fast"], ["提示词残留", "zz-mutation"])
def m4(fx):
    d = fx.home_path(".pi", "agent", "prompts")
    os.makedirs(d, exist_ok=True)
    fp = fx.home_path(".pi", "agent", "prompts", "zz-mutation.md")
    if os.path.exists(fx.path("Tool/prompts/tasks/zz-mutation.md")):
        raise IsolationError("m4 退役卡仍在 fixture 源 tasks 中，不能验证残留")
    with open(fp, "w", encoding="utf-8", newline="\n") as f:
        f.write("---\ndescription: x\n---\n")
    manifest = {
        "schema": "seep-agent-install/1",
        "runtime_id": "seep-reverse-lab/softseep",
        "source_root": os.path.realpath(fx.root),
        "status": "complete",
        "managed_files": {"prompts/zz-mutation.md": _sha256_file(fp)},
    }
    with open(fx.home_path(".pi", "agent", "seep-install-manifest.json"),
              "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")


# 5. 给 pack.json 加未知字段 → G2 必须红
@implant("m5", ["Tool/scripts/gate.py", "--all"], ["pwn-crypto", "多出未声明字段"])
def m5(fx):
    p = fx.path("Tool/skill/pwn-crypto/pack.json")
    with open(p, encoding="utf-8") as f:
        d = json.load(f)
    d["zz_unknown_field"] = True
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(d, ensure_ascii=False, indent=2) + "\n")


# 6. 在活跃文档新增错误工具数 → 事实漂移必须红
@implant("m6", ["Tool/scripts/preflight.py", "--fast"], ["事实漂移", "工具=99"])
def m6(fx):
    p = fx.path("README.md")
    with open(p, encoding="utf-8") as f:
        s = f.read()
    # 产品 README 已移除容易漂移的静态工具数，不能再用旧字面量作为植入前置。
    # 只在 fixture 中追加一条明确错误事实，让既有 preflight 判据直接检查它。
    out = s + ("" if s.endswith("\n") else "\n") + "事实漂移探针：99 个工具\n"
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(out)


# ──────────────────────── 基线 / 单项执行 ────────────────────────────
_baseline_lock = threading.Lock()
_baselines = {}


def baseline_for(checker, files):
    """在**纯净** fixture 上跑一次 checker，记 FAIL 行基线（每个 checker 一次，缓存）。

    为什么必须有（不是"因为夹具不全"这么窄）：`preflight.py --fast` 在**当前工作树**上
    不植入就有 11 条 FAIL（部署面未装、doc-audit、别名基线…）。旧版判据是"输出里出现
    `[FAIL]` 且含 expect 子串"，在这种仓库上 100% 假绿。所以判据改成：
    **只认植入后新增的 FAIL 行**，且每个 expect 都要被某条新增行覆盖。
    基线里已经含 expect 的项，直接判 unverified（不可判定），不当 pass。
    """
    key = tuple(checker)
    with _baseline_lock:
        if key in _baselines:
            return _baselines[key]
    fx = Fixture(files, "base")
    try:
        hookdir = write_hook(os.path.join(fx.tmp, "hook"))
        rc, out = run_in(fx, hookdir, checker)
        rec = {"rc": rc, "fails": fail_lines(out), "raw": out,
               "tail": out.strip().splitlines()[-6:]}
    finally:
        fx.clean()
    with _baseline_lock:
        _baselines[key] = rec
    return rec


def run_one(imp, files, keep=False):
    """跑一个植入：新 fixture → 植入 → 真跑 checker → 基线 delta 判定。"""
    name, checker, expect = imp["id"], imp["checker"], imp["expect"]
    fx = Fixture(files, name, keep=keep)
    rec = {"id": name, "expect": expect, "checker": " ".join(checker),
           "status": "unverified", "caught": False, "hits": [], "notes": []}
    try:
        hookdir = write_hook(os.path.join(fx.tmp, "hook"))
        base = baseline_for(checker, files)
        rec["baseline_rc"] = base["rc"]
        rec["baseline_fails"] = len(base["fails"])
        if base["rc"] in (-1, -2):
            rec["notes"].append("基线 checker 跑不起来：%s" % (base["tail"] or [""])[-1])
            return rec
        if not looks_runnable(base.get("raw", "")):
            rec["notes"].append("基线 checker 没产出任何判据行（疑似脚本不存在/崩溃）→ 不可判定")
            rec["baseline_tail"] = (base.get("tail") or [""])[-1][:160]
            return rec
        base_set = set(base["fails"])
        wants0 = [expect] if isinstance(expect, str) else list(expect)
        # 基线里已经红了的判据不能当证据：否则会把"夹具本来就红"读成"植入被抓"
        expect_in_base = [x for x in base["fails"] if any(w in x for w in wants0)]
        if expect_in_base:
            rec["notes"].append("基线已含「%s」判据红（夹具不全，判据早就红）→ 该植入不可判定"
                                % " / ".join(wants0))
            rec["baseline_hit"] = expect_in_base[0][:160]
            return rec
        try:
            imp["fn"](fx)
        except IsolationError as e:
            rec["notes"].append("隔离越界：%s" % e)
            return rec
        rc, out = run_in(fx, hookdir, checker)
        rec["rc"] = rc
        if rc in (-1, -2):
            rec["notes"].append("植入后 checker 跑不起来（不当 pass）：%s"
                                % (out.strip().splitlines()[-1] if out.strip() else ""))
            return rec
        if not looks_runnable(out):
            rec["notes"].append("植入后 checker 没产出任何判据行（疑似崩溃）→ 不可判定，不计 pass")
            rec["tail"] = out.strip().splitlines()[-2:]
            return rec
        new = [x for x in fail_lines(out) if x not in base_set]
        wants = [expect] if isinstance(expect, str) else list(expect)
        # 每个 want 都必须被**某条新增 FAIL** 覆盖到（"全部命中"才算抓到）：
        # 只要求"任一词出现"会太松 —— 夹具里别的红可能顺带含同一个词。
        hit, missing = [], []
        for w in wants:
            got = [x for x in new if w in x]
            if got:
                hit.append(got[0])
            else:
                missing.append(w)
        noise = [x for x in new if not any(w in x for w in wants)]
        rec["new_fails"] = len(new)
        rec["hits"] = hit[:4]
        rec["noise_fails"] = len(noise)
        rec["noise_samples"] = [x[:160] for x in noise[:3]]
        if noise:
            rec["notes"].append("另有 %d 条新增 FAIL 与本植入无关（checker 有不确定性项 / 夹具临"
                                "时路径差异），只登记不采信" % len(noise))
        if hit and not missing:
            rec["caught"] = True
            rec["status"] = "caught"
            rec["notes"].append("植入后新增 %d 条 FAIL，判据逐项命中「%s」"
                                % (len(new), " / ".join(wants)))
        elif new:
            rec["status"] = "unverified"
            rec["notes"].append("植入后确有新增 FAIL（%d 条），但判据没被完整覆盖（缺「%s」）"
                                "→ 不是该判据抓的，不计 pass"
                                % (len(new), " / ".join(missing or wants)))
            rec["notes"].append("最像的一条：%s" % new[0][:160])
        else:
            rec["status"] = "missed"
            rec["notes"].append("植入后零新增 FAIL → 该判据是装饰品（真漏网）")
        return rec
    except Exception:  # noqa: BLE001
        rec["status"] = "unverified"
        rec["notes"].append("执行异常（不当 pass）：%s" % traceback.format_exc(limit=3).strip()[-400:])
        return rec
    finally:
        fx.clean()


# ───────────────────── 隔离防护：真实仓库/用户目录起止一致 ────────────────────
PROTECTED_FILES = (
    "Tool/cases/golden-crackme/artifacts/MANIFEST.sha256",
    "Tool/skill/softseep/SKILL.md",
    "Tool/skill/apkseep/SKILL.md",
    "Tool/skill/pwn-crypto/pack.json",
    "README.md",
    "Tool/scripts/preflight.py",
    "Tool/scripts/gate.py",
    "Tool/scripts/check.py",
    "Tool/prompts/AGENTS.md",
    "Tool/prompts/SEEP.md",
    "AGENTS.md",
)

# 只登记清单 + 哈希，**不读内容入内存以外的地方**、不复制、不涉及凭据文件。
USER_WATCH = (
    (os.path.join(".pi", "agent", "prompts"), True),
    (os.path.join(".pi", "agent", "skills"), False),
)


def repo_snapshot(paths=PROTECTED_FILES, extra_dirs=("Tool/scripts", "Tool/skill", "Tool/prompts")):
    """真实仓库只读快照：受保护文件哈希 + 关键目录清单。"""
    snap = {"files": {}, "dirs": {}}
    for rel in paths:
        fp = os.path.join(ROOT, rel)
        snap["files"][rel] = _sha256_file(fp) if os.path.isfile(fp) else None
    for rel in extra_dirs:
        d = os.path.join(ROOT, rel)
        if os.path.isdir(d):
            snap["dirs"][rel] = sorted(os.listdir(d))
    snap["git"] = subprocess.run(["git", "status", "--porcelain", "-uall"], cwd=ROOT,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 timeout=120).stdout.decode("utf-8", "replace")
    return snap


def user_snapshot():
    """真实用户目录：**只登记清单 + 明文文件哈希**，不跟随符号链接、不读凭据类文件。"""
    snap = {}
    home = os.path.expanduser("~")
    for rel, hash_names in USER_WATCH:
        d = os.path.join(home, rel)
        if not os.path.isdir(d):
            snap[rel] = None
            continue
        names = sorted(os.listdir(d))
        entry = {"names": names, "hash": {}}
        if hash_names:
            for n in names:
                fp = os.path.join(d, n)
                if os.path.isfile(fp) and not os.path.islink(fp) and \
                        _looks_like_prompt_card(n):
                    try:
                        entry["hash"][n] = _sha256_file(fp)
                    except OSError:
                        entry["hash"][n] = "unreadable"
        snap[rel] = entry
    return snap


def _looks_like_prompt_card(name):
    """只看 .md 卡片（真提示词目录里就是这类）；其它一律不哈希、不读。"""
    return name.lower().endswith(".md") and "cred" not in name.lower() \
        and "secret" not in name.lower() and "token" not in name.lower()


def diff_snapshots(before, after, label):
    probs = []
    for rel in before["files"]:
        if before["files"][rel] != after["files"].get(rel):
            probs.append("%s: %s 变了（起=%s 止=%s）" % (
                label, rel, (before["files"][rel] or "-")[:12], (after["files"].get(rel) or "-")[:12]))
    for rel in before["dirs"]:
        if before["dirs"][rel] != after["dirs"].get(rel):
            probs.append("%s: 目录清单变了 %s" % (label, rel))
    if before.get("git") != after.get("git"):
        probs.append("%s: git status 起止不一致（真实仓库被写过）" % label)
    return probs


def diff_user(before, after):
    probs = []
    for rel, b in before.items():
        a = after.get(rel, "MISSING")
        if a is None and b is None:
            continue
        if b is None or a is None or b == "MISSING":
            if b != a:
                probs.append("用户目录 %s 存在性变了" % rel)
            continue
        if b["names"] != a["names"]:
            probs.append("用户目录 %s 清单变了：%d → %d 项" % (rel, len(b["names"]), len(a["names"])))
        for n, h in b["hash"].items():
            if a["hash"].get(n) != h:
                probs.append("用户提示词 %s/%s 哈希变了" % (rel.replace(os.sep, "/"), n))
    return probs


# ─────────────────────────────── 主流程 ────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="变异测试（隔离版）：只在临时 fixture 里植入失败")
    ap.add_argument("--fast", action="store_true", help="只跑快的子集")
    ap.add_argument("--only", default="", help="只跑这些植入 id（逗号分隔，如 m1,m5）")
    ap.add_argument("--jobs", type=int, default=DEFAULT_JOBS,
                    help="并行度（%d..%d，默认 %d；>%d 会被夹到 %d）"
                         % (1, MAX_JOBS, DEFAULT_JOBS, MAX_JOBS, MAX_JOBS))
    ap.add_argument("--keep", action="store_true", help="保留 fixture 目录（诊断用；自己删）")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    jobs = max(1, min(int(a.jobs or DEFAULT_JOBS), MAX_JOBS))
    picked = [x for x in IMPLANTS if (not a.fast) or x["fast"]]
    if a.only:
        want = {s.strip() for s in a.only.split(",") if s.strip()}
        unknown = want - {x["id"] for x in IMPLANTS}
        if unknown:
            print("[ERR] 没有这些植入：%s（可选：%s）"
                  % (",".join(sorted(unknown)), ",".join(x["id"] for x in IMPLANTS)))
            return 2
        picked = [x for x in picked if x["id"] in want]

    files = repo_manifest()
    if not files:
        print("[ERR] 拿不到工作树清单（git 不可用？）—— 没有夹具就不跑，绝不动真实文件")
        return 2

    need = manifest_bytes(files) * DISK_COPIES
    free = shutil.disk_usage(tempfile.gettempdir()).free
    if free < need:
        print("[ERR] 临时目录余量不够：需要约 %.0f MB（%d 份副本），可用 %.0f MB。"
              % (need / 1e6, DISK_COPIES, free / 1e6))
        print("      降并行（--jobs 1）或清理临时目录后重跑；不降级成「少拷文件」——"
              "少拷会让判据基线失真，那种绿没有意义。")
        return 2

    if not a.json:
        print("变异测试（隔离版）：%d 个植入 / 并行 %d / 夹具 = 工作树真实字节（%d 个文件，约 %.0f MB/份）"
              % (len(picked), jobs, len(files), manifest_bytes(files) / 1e6))
        print("  真实仓库与真实 ~/.pi 全程只读；植入只落在 TemporaryDirectory 的 repo 副本里。\n")

    before_repo = repo_snapshot()
    before_user = user_snapshot()

    results = []
    if jobs == 1:
        for imp in picked:
            results.append(run_one(imp, files, keep=a.keep))
    else:
        queue = list(picked)
        queue_lock = threading.Lock()

        def worker():
            while True:
                with queue_lock:
                    if not queue:
                        return
                    imp = queue.pop(0)
                rec = run_one(imp, files, keep=a.keep)
                with queue_lock:
                    results.append(rec)

        threads = [threading.Thread(target=worker) for _ in range(min(jobs, len(picked)))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    after_repo = repo_snapshot()
    after_user = user_snapshot()
    iso_problems = diff_snapshots(before_repo, after_repo, "真实仓库") + diff_user(before_user, after_user)

    order = {x["id"]: i for i, x in enumerate(IMPLANTS)}
    results.sort(key=lambda r: order.get(r["id"], 99))

    if a.json:
        print(json.dumps({"isolated": not iso_problems, "isolation_problems": iso_problems,
                          "fixture_files": len(files), "jobs": jobs, "results": results},
                         ensure_ascii=False, indent=2))
    else:
        print("%-5s %-16s %-9s %-7s %s" % ("植入", "判定", "新增FAIL", "噪声", "命中的检查"))
        print("-" * 108)
        label = {"caught": "抓到", "missed": "**漏网**", "unverified": "未验证"}
        for r in results:
            print("%-5s %-16s %-9s %-7s %s" % (
                r["id"], label.get(r["status"], r["status"]),
                str(r.get("new_fails", "-")), str(r.get("noise_fails", "-")),
                (r["hits"][0] if r["hits"] else (r["notes"][-1] if r["notes"] else ""))[:70]))
        print("-" * 108)
        for r in results:
            for n in r["notes"]:
                print("  [%s] %s" % (r["id"], n[:200]))
        caught = sum(1 for r in results if r["status"] == "caught")
        missed = [r["id"] for r in results if r["status"] == "missed"]
        unver = [r["id"] for r in results if r["status"] == "unverified"]
        print("结果: %d/%d 变异被抓" % (caught, len(results)))
        if missed:
            print("  漏网：%s  ← 该判据是装饰品" % ", ".join(missed))
        if unver:
            print("  未验证（不计 pass）：%s" % ", ".join(unver))
        print("隔离防护：%s" % ("真实仓库与用户 prompts 起止哈希/清单一致（零越界写盘）"
                          if not iso_problems else "**越界**："))
        for p in iso_problems:
            print("  - " + p)

    ok = (not iso_problems) and results and all(r["status"] == "caught" for r in results)
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
