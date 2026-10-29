#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""导入外部技能/扩展：唯一入口（判型建议 + 事务式 stage/backup/validate/deploy/verify/回执）。

为什么（2026-10-24 用户提的最后一环；导入事务设计记录）：
    用户从网上找到一个 skill，不会知道我们的架构（域 vs 横切 vs 子技能）、格式（frontmatter 要求）、
    放哪儿、要不要部署。**不该让用户手改**——他只要说"加这个"，剩下是 Agent 的事。

本脚本只做机械的、可判定可回滚的事：
    ① 校验 frontmatter（name / description）
    ② 判型**只给建议**（A/B/C 三选二）；正式身份不靠关键词：
       - 正式域 = `pack.json` 的 `id` == 目录名，且过真实 `gate.g2_schema` / 路由契约校验；
       - 横切技能 = 显式 `--kind crosscutting`（或已在 domain-aliases.json#cross_cutting）；
       - 子技能 = 显式 `--parent <真实域名>`，落 `_pending/`，**自动**在父 SKILL.md 插入幂等的一行引用；
       - 工具 = 只声明不安装（validate manifest），不写本轮不拥有的 tool catalogs。
    ③ 事务落位：plan → 多资源锁 → journal(intent) → stage(同卷) → validate → commit(备份+改名)
       → 父引用 → deploy(逐 root 同卷备份+改名) → verify(hash/manifest/路由/父入口) → 回执；
       任一步失败按**事实**逆序回滚，备份保留可复查，回滚不完整就如实报 partial。
    ④ 回执分开报：files_imported / deployed / available_next_session / formal_domain_active，
       不把"复制成功"说成"能选/有能力"；也不把"父域按需可达"说成"全局自动选中"。

IMPORT-02 修的四条硬边界（导入事务修复记录）：
    · **改名失败即放弃**：`_move` 只做同卷 os.replace/os.rename，失败直接 Refuse(5)，
      绝不再退回 `shutil.move`（COPY+DEL 会把旧目录拆成两半）。staging/backup 一律与被改目标同卷：
      仓库侧在 `<skill_dir>/.import-{staging,backup}`，每个部署根在自己的 `<root>/.import-{staging,backup}`。
    · **journal 先 intent 后 done**：回滚按磁盘事实检查，报 `rolled_back` / `rollback_partial` + 可复查位置。
    · **多资源锁**：按规范化目标路径全局排序，同时持有 skill 锁 / 父目录锁 / 父文件锁 / dest 锁；
      跨进程 O_CREAT|O_EXCL（不是进程内 thread 锁），有界等待，绝不自动删疑似活锁。
    · **父引用必须真可达**：仓库父 SKILL.md 写 `../_pending/<child>/SKILL.md`（相对**父技能目录**解析，
      不依赖 repo cwd）；部署侧把子技能复制到 `<root>/<parent>/references/imported-subskills/<child>/`，
      入口 SKILL.md 映射为 GUIDE.md（不会被当成新的全局技能），父部署 SKILL.md 指向该真实相对文档。
    · **唯一 roots 解析/边界**：plan/import/deploy/verify/status 共用 `_resolve_deploy_roots`；
      自定义 --skill-dir 且无显式 --deploy-root 时不读写真实用户根；根与 source/skill-dir/repo
      重叠、互为祖先、是 symlink/junction 一律先拒，拒之前零写。
    · **status 只读**：`status`/`recovery-report` 报残留锁/staging/备份/journal 与动作阶段，
      不删任何东西；缺自动恢复能力时明确 `pending_manual=true`。

用法（旧入口仍可用，语义已收紧为"建议 + needs_classification"，不会擅自部署）：
    python Tool/scripts/skill-import.py --from <目录或 SKILL.md 路径> [--name N] [--dry-run]
    python Tool/scripts/skill-import.py --selftest
    python Tool/scripts/skill-import.py import --kind auto|domain|crosscutting|subskill|tool \
        --from <路径> [--name N] [--parent <真实域名>] [--pack <pack.json>] [--tool-id T] \
        [--skill-dir <Tool/skill 根>] [--deploy-root <root> ...] [--no-deploy] [--replace] [--json]
    python Tool/scripts/skill-import.py plan|stage|validate|deploy|verify|status ...

退出码：0 成功 / 2 判型未定（needs_classification）或用法错误 / 3 能力缺口（tool 模式只声明）
        / 4 策略拒绝（非正式域无 pack、父域不存在、路径逃逸、根不合法、并发锁、目标已存在）
        / 5 已写盘但 verify 失败（已回滚或如实报 partial）
"""
import argparse
import hashlib
import io
import json
import os
import random
import re
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOOL = os.path.join(ROOT, "Tool")
SKILL_DIR = os.path.join(TOOL, "skill")
PENDING = os.path.join(SKILL_DIR, "_pending")
SCRIPTS = os.path.join(TOOL, "scripts")
ALIASES = os.path.join(TOOL, "config", "domain-aliases.json")

STAGING_NAME = ".import-staging"
BACKUP_NAME = ".import-backup"
JOURNAL_DIR = "journals"
MANIFEST_NAME = "import-manifest.json"
MANIFEST_SCHEMA = "seep.skill-import.manifest/1"
IMPORT_MAP_NAME = "import-map.json"
SCHEMA = "seep.skill-import.receipt/1"
RECOVERY_SCHEMA = "seep.skill-import.recovery/1"
SUBSCHEMA_MAP = "seep.skill-import.subskill-map/1"

# 锁等待（秒）：并发事务排队而不是立刻失败；进程内无锁、全靠 O_CREAT|O_EXCL（跨进程）
LOCK_WAIT_S = float(os.environ.get("SEEP_IMPORT_LOCK_WAIT", "20"))
LOCK_POLL_S = 0.03

# 域技能的"广度"判据（第 2 轮评审：老的「120 行 + 加权分数 ≥4」不可解释也不可复核）
DOMAIN_MIN_EXTS = 3        # 覆盖面：正文里出现的文件后缀**种类**
DOMAIN_MIN_TECHS = 4       # 技法面：正文里命中的技法类别
DOMAIN_MIN_TRIGGERS = 2    # 显式声明：description 里"用户会说的触发词"个数
DOMAIN_MIN_LINES = 120     # 仅供参考，不再参与判定（行数多 ≠ 域技能）
FILE_EXT_RE = re.compile(r"\.(exe|dll|sys|so|dylib|apk|aab|dex|bin|img|trx|squashfs|ubi|pcap|jar|ipa|"
                         r"elf|macho|js|php|py|zip|7z|ova|qcow2)\b", re.I)
TECH_HINTS = ("脱壳", "反调试", "抓包", "加密", "混淆", "反编译", "溢出", "注入", "取证", "报文", "固件",
              "解包", "重打包", "hook", "unpack", "decompile", "exploit", "fuzz", "kernel", "driver")

# "用户会说的触发词"：模型选技能只看 description，里面没有用户原话就选不中。
# 命中 ≥2 个 = 这份描述能承接真实对话，才配当常驻入口（域技能）。
TRIGGER_HINTS = ("怎么", "如何", "为什么", "帮我", "能不能", "这是什么", "怎么办", "什么工具",
                 "脱壳", "加壳", "加固", "反调试", "抓包", "解包", "重打包", "反编译", "破解",
                 "解密", "加密", "混淆", "取证", "溢出", "注入", "固件", "协议", "证书", "内存",
                 "hook", "dump", "unpack", "decompile", "patch", "crack", "fuzz", "trace")

# 一看就知道"这是整个下载的项目"的标志（2026-10-26 第 2 轮评审：copytree 会把整仓搬进技能目录）
PROJECT_MARKERS = (".git", ".gitmodules", ".github", "node_modules", "package.json",
                   "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.toml", "go.mod",
                   "pom.xml", ".vscode", "docker-compose.yml", "vite.config.ts", "webpack.config.js")
COPY_IGNORE = shutil.ignore_patterns(".git", ".github", "node_modules", "__pycache__", ".venv",
                                     ".pytest_cache", "*.pyc", STAGING_NAME, BACKUP_NAME)

NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{1,40}")
RESERVED_NAMES = {"_pending", STAGING_NAME, BACKUP_NAME, "."}
# 父 SKILL.md 里**唯一**允许被插入子技能行的锚点（9 个域都有这一行）
PARENT_ANCHOR = "本域相关子技能放在"
# 兼容口径：`_pending/<child>/SKILL.md` 是 `../_pending/<child>/SKILL.md` 的子串
PENDING_LINK_RE = re.compile(r"_pending/([A-Za-z0-9_.-]+)/SKILL\.md")
# 部署侧引用（父部署 SKILL.md → 复制进来的子技能入口文档）
DEPLOY_REF_RE = re.compile(r"references/imported-subskills/([A-Za-z0-9_.-]+)/GUIDE\.md")
REPO_REF_TMPL = "../_pending/%s/SKILL.md"
DEPLOY_REF_TMPL = "references/imported-subskills/%s/GUIDE.md"
REF_BULLET_RE = re.compile(r"^\s*-\s+`[^`]*(?:_pending|imported-subskills)/[^`]+`")

# 部署侧 import-map.json 的**权威**字段（IMPORT-03 / R-NEW-1）：
# 这些都是身份/入口/映射声明，必须参与核验，不能只抄进回执。
SUB_MAP_FIELDS = ("schema", "child", "parent", "entry", "mapping", "files")
SUB_MAP_ENTRY_SRC = "SKILL.md"      # 仓库侧子技能入口
SUB_MAP_ENTRY_DST = "GUIDE.md"      # 部署侧入口（改名，避免被当成新全局技能）

KINDS = ("auto", "domain", "crosscutting", "subskill", "tool")


# ============================================================ 旧实现保留区
def read_skill(path):
    if os.path.isdir(path):
        p = os.path.join(path, "SKILL.md")
    else:
        p = path
    if not os.path.isfile(p):
        raise SystemExit("[拒] 找不到 SKILL.md：%s" % p)
    with io.open(p, encoding="utf-8", errors="replace") as stream:
        return p, stream.read()


def parse(text):
    m = re.search(r"^---\s*$(.*?)^---\s*$", text, re.M | re.S)
    fm = m.group(1) if m else ""
    name = re.search(r"^name:\s*(.+)$", fm, re.M)
    desc = re.search(r"^description:\s*(.+)$", fm, re.M)
    return {
        "name": (name.group(1).strip().strip('"\'') if name else ""),
        "description": (" ".join(desc.group(1).strip().strip('"\'').split()) if desc else ""),
        "has_frontmatter": bool(m),
    }


def _criterion_declared(meta):
    """判据 A 显式声明：frontmatter 有 name + description，且描述里 ≥2 个用户会说的触发词。"""
    name, desc = (meta.get("name") or ""), (meta.get("description") or "")
    if not name or not desc:
        return False, "frontmatter 缺 name 或 description（name=%r）" % name
    low = desc.lower()
    hits = [t for t in TRIGGER_HINTS if t.lower() in low]
    if len(hits) < DOMAIN_MIN_TRIGGERS:
        return False, ("description 只命中 %d 个用户触发词（门槛 %d）：%s"
                       % (len(hits), DOMAIN_MIN_TRIGGERS, "、".join(hits) or "无"))
    return True, ("name=%s / description 命中 %d 个用户触发词：%s"
                  % (name, len(hits), "、".join(hits)))


def classify(text, meta=None):
    """域 vs 子技能：三条**可单独解释**的判据，命中任意两条 = 域技能。

    ★ 2026-10-26：本函数只产出**判型建议**（`kind_suggestion`），不再是身份裁定。
      正式域身份只认 pack.json 的 id + 真实 g2/路由/evidence 校验，见 `_decide_kind()`。

    为什么换掉旧实现（第 2 轮评审）：「120 行 + 分数 ≥4」只能回答"分够了"，
    而用户问的是"凭什么是域技能"。现在的三条都可以指着正文/描述核对：
      A 显式声明：frontmatter 有 name + description，且描述含 ≥2 个用户会说的触发词；
      B 覆盖面：正文覆盖的**文件后缀种类** ≥ 3；
      C 技法面：正文命中的**技法类别** ≥ 4。
    A 管"模型能不能选得中它"，B/C 管"它是不是一份能接住多种输入的入口文档"。
    """
    meta = meta if meta else parse(text)
    lines = len(text.splitlines())
    exts = sorted({e.lower() for e in FILE_EXT_RE.findall(text)})
    techs = sorted({t for t in TECH_HINTS if t.lower() in text.lower()})
    a_ok, a_why = _criterion_declared(meta)
    b_ok = len(exts) >= DOMAIN_MIN_EXTS
    b_why = "覆盖后缀 %d 种（门槛 %d）：%s" % (len(exts), DOMAIN_MIN_EXTS, " ".join(exts[:10]) or "无")
    c_ok = len(techs) >= DOMAIN_MIN_TECHS
    c_why = "命中技法 %d 类（门槛 %d）：%s" % (len(techs), DOMAIN_MIN_TECHS, "、".join(techs[:10]) or "无")
    hits = sum(1 for ok in (a_ok, b_ok, c_ok) if ok)
    kind = "domain" if hits >= 2 else "subskill"
    return kind, {
        "lines": lines, "exts": exts, "techs": techs, "hits": hits,
        "criteria": [("A 显式声明", a_ok, a_why),
                     ("B 覆盖面", b_ok, b_why),
                     ("C 技法面", c_ok, c_why)],
    }


def _download_markers(d):
    """目录里出现这些 = 用户给的是「整个下载的项目」，而不是技能目录。"""
    return [x for x in PROJECT_MARKERS if os.path.exists(os.path.join(d, x))]


def _copy_plan(src_dir):
    """复制范围 = SKILL.md 的**父目录本身**（不往上一层爬，也不整仓搬）。返回文件数。"""
    n = 0
    for _r, ds, fs in os.walk(src_dir):
        ds[:] = [x for x in ds if x not in (".git", ".github", "node_modules", "__pycache__", ".venv")]
        n += len(fs)
    return n


def _effect_status(kind, name, dest, dry, deploy=True):
    """R6 P1-7：判成子技能 / 只落 `_pending/` / dry-run 时，“不生效”必须说出来。

    返回 (effective, why, 3 条要生效的具体动作)。新事务路径改用 `_receipt_status()`，
    本函数保留给旧调用方与 `--selftest`（语义不变：不生效就得说出来）。
    """
    if kind == "subskill":
        why = ("判为子技能（不常驻）：它只在 %s/，不会部署到 ~/.pi/agent/skills/，"
               "模型按需读、不会自动选中它" % ("Tool/skill/_pending/" + name))
        acts = [
            "把它改写成域技能（frontmatter 的 description 写用户会说的原话 + 文件后缀，正文补齐覆盖面/技法面），"
            "再重跑本脚本落到 Tool/skill/%s/" % name,
            "或者把它并进所属域的 SKILL.md：在那些域里加一行「需要时读 _pending/%s/SKILL.md」" % name,
            "改完跑 python Tool/scripts/check.py --fast 验证（确认它真的进了加载名单）",
        ]
        return False, why, acts
    if dry:
        why = "dry-run：什么都没写盘，%s/ 与 ~/.pi/agent/skills/%s/ 都不存在，模型选不中它" % (name, name)
        acts = [
            "去掉 --dry-run 重跑同一条命令（真正落到 Tool/skill/%s/）" % name,
            "确认 description 里含用户会说的原话 + 文件后缀（模型只看这一句）",
            "跑 python Tool/scripts/check.py --fast 验证（部署目录与仓库一致）",
        ]
        return False, why, acts
    if not deploy:
        why = "本次传了 deploy=False：只落在仓库 Tool/skill/%s/，没同步到 ~/.pi/agent/skills/" % name
        acts = [
            "用默认参数（不带 deploy=False）重跑本脚本",
            "或者手动拷 Tool/skill/%s/ 到 ~/.pi/agent/skills/%s/" % (name, name),
            "跑 python Tool/scripts/check.py --fast 验证",
        ]
        return False, why, acts
    return True, "已部署到 ~/.pi/agent/skills/%s/（域技能，下次会话自动加载）" % name, []


# ============================================================ 复用真实检查器
_MODCACHE = {}


def _module(rel_path, alias):
    """按文件路径加载仓库里**真实**的检查器模块（不复制 schema，不 shell 出去）。"""
    if alias in _MODCACHE:
        return _MODCACHE[alias]
    path = rel_path if os.path.isabs(rel_path) else os.path.join(ROOT, rel_path.replace("/", os.sep))
    import importlib.util
    spec = importlib.util.spec_from_file_location(alias, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _MODCACHE[alias] = mod
    return mod


def _route():
    return _module(os.path.join(SCRIPTS, "route.py"), "seep_route_for_import")


def _gate():
    return _module(os.path.join(SCRIPTS, "gate.py"), "seep_gate_for_import")


def _domain_gate():
    return _module(os.path.join(SCRIPTS, "domain-gate.py"), "seep_domain_gate_for_import")


def _runtime_root_module():
    return _module(os.path.join(SCRIPTS, "lib", "runtime_root.py"),
                   "seep_runtime_root_for_import")


def _default_deploy_root():
    """Resolve the default AgentRoot at call time, never from a module-load snapshot."""
    try:
        # HOME is the final public locator.  Pass it explicitly so Windows does not
        # silently prefer USERPROFILE when a portable HOME was injected by setup/tests.
        home = os.environ.get("HOME") or None
        agent_root = _runtime_root_module().resolve_agent_root(home=home)
    except Exception as exc:  # noqa: BLE001
        raise Refuse(4, "agent_root_invalid",
                     "无法解析默认 AgentRoot：%s" % str(exc)[:160])
    return os.path.join(os.fspath(agent_root), "skills")


def _norm_sha(p):
    """部署/仓库哈希口径 = domain-gate.py:98 `_norm_sha`（文本按 LF 归一）。

    直接调用真实实现；加载失败（如模块依赖缺失）才退回**同口径**本地实现，
    并在回执里记 `sha_source`，不假装用的是门禁口径。
    """
    try:
        return _domain_gate()._norm_sha(p)
    except Exception:  # noqa: BLE001
        if os.path.splitext(p)[1].lower() in (".md", ".py", ".json", ".txt", ".yml", ".yaml"):
            with open(p, "rb") as fh:
                raw = fh.read().replace(bytes([13, 10]), bytes([10]))
            return hashlib.sha256(raw).hexdigest()
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()


def tree_diff(want, got):
    """两份 hash_tree 的差异：缺文件/多文件/同名不同 hash（漂移不能只看集合差）。"""
    out = []
    for rel in sorted(set(want) | set(got)):
        if rel not in got:
            out.append("缺 " + rel)
        elif rel not in want:
            out.append("多 " + rel)
        elif want[rel] != got[rel]:
            out.append("漂移 " + rel)
    return out


def hash_tree(d):
    """{相对路径: norm_sha}：部署等价判据（同名同 hash，逐文件）。"""
    out = {}
    if not os.path.isdir(d):
        return out
    for dp, dn, fn in os.walk(d):
        dn[:] = sorted(x for x in dn if x not in ("__pycache__",))
        for f in sorted(fn):
            p = os.path.join(dp, f)
            out[os.path.relpath(p, d).replace(os.sep, "/")] = _norm_sha(p)
    return out


def hash_tree_dir_file(p):
    try:
        return _norm_sha(p)
    except Exception:  # noqa: BLE001
        return ""


# ============================================================ 拒绝与工具函数
class Refuse(Exception):
    """策略拒绝/校验失败：带退出码与机读码，交给回执而不是抛栈。"""

    def __init__(self, rc, code, message, **extra):
        Exception.__init__(self, message)
        self.rc = int(rc)
        self.code = code
        self.message = message
        self.extra = extra

    def as_dict(self):
        d = {"rc": self.rc, "code": self.code, "message": self.message}
        d.update(self.extra)
        return d


def _ts():
    # Same-process transactions can start within one second; time_ns prevents journal,
    # staging and intentionally-kept backup directories from colliding across retries.
    return (time.strftime("%Y%m%d-%H%M%S") +
            "-%d-%d" % (os.getpid(), time.time_ns()))


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _sha1(s):
    return hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()


def _bytes_sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _bytes_sha_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read_text(p):
    with io.open(p, encoding="utf-8", newline="") as f:
        return f.read()


def _norm(p):
    """规范化：绝对路径 + realpath（解 symlink/junction）+ normcase。"""
    return os.path.normcase(os.path.realpath(os.path.abspath(p)))


def _within(child, parent):
    c, p = _norm(child), _norm(parent)
    if c == p:
        return True
    return c.startswith(p.rstrip(os.sep) + os.sep)


def _is_link(p):
    try:
        if os.path.islink(p):
            return True
        isj = getattr(os.path, "isjunction", None)
        if isj is not None and isj(p):
            return True
    except OSError:
        pass
    return False


def _rel_overlap_reason(root, other, label):
    """root 与 other 是否重叠/互为祖先；返回原因字符串或 ""（不拼绝对路径原值）。"""
    r = _redact_path(root)
    o = _redact_path(other)
    if _within(root, other):
        return "部署根在 %s 里：%s ⊂ %s" % (label, r, o)
    if _within(other, root):
        return "部署根是 %s 的祖先：%s ⊃ %s" % (label, r, o)
    return ""


def _move(src, dst, journal=None, role="", faults=None):
    """同卷**改名**（原子）：os.replace/os.rename。失败即放弃——绝不 copytree/copy+删源。

    为什么（IMPORT-02 R1）：旧实现失败后退回 `shutil.move`，目录是"逐文件复制 → 删源"，
    中途遇到被占用文件就留下"备份里一半、源里一半"的旧技能，而 journal 还没登记 moved。
    现在只有两种结果：整体换名成功，或整体失败（旧内容原地不动）。
    """
    try:
        os.replace(src, dst)
        return "replace"
    except OSError as e1:
        try:
            os.rename(src, dst)
            return "rename"
        except OSError as e2:
            raise Refuse(5, "move_failed",
                         "同卷改名失败，已放弃（不复制、不删源）：%s → %s（%s）"
                         % (src, dst, str(e2 or e1)[:160]),
                         src=src, dst=dst, role=role)


def _fault(faults, point):
    """测试注入点：faults 里出现该名字 = 在该阶段抛异常（模拟 copy/rename/verify 中断）。"""
    # 真实强退回归必须绕过解释器清理；该环境变量由测试显式设置，生产路径默认不读取。
    if os.environ.get("SEEP_IMPORT_CRASH_POINT") == point:
        os._exit(87)
    if not faults:
        return
    if point in faults:
        raise RuntimeError("注入故障：%s" % point)


def _load_json(p):
    with io.open(p, encoding="utf-8-sig") as f:
        return json.load(f)


def aliases():
    try:
        return _load_json(ALIASES)
    except Exception:  # noqa: BLE001
        return {}


def cross_cutting_names():
    return {str(x.get("name")) for x in (aliases().get("cross_cutting") or [])
            if isinstance(x, dict) and x.get("name")}


def scan_packs(skill_dir=None):
    """(packs, problems)：复用 route.load_packs（现算，不读第二份索引）。"""
    return _route().load_packs(skill_dir or SKILL_DIR)


def _valid_name(name):
    if not name or not NAME_RE.fullmatch(name or ""):
        return False, "名字不合法：%r（要英文/数字/._-，2–41 字，不能以 . 开头）" % name
    if name in RESERVED_NAMES or name.startswith("."):
        return False, "名字是保留名：%r" % name
    return True, ""


def _check_source_tree(src_dir):
    """源目录安全检查：项目根、符号链接逃逸、自包含复制。

    为什么（2026-10-26 复审）：copytree 默认跟随符号链接，一个 `logs -> C:\\` 就能把
    整个盘搬进技能目录；而父目录是下载的项目根时会把 .git/node_modules 一起搬。
    """
    markers = _download_markers(src_dir)
    if markers:
        raise Refuse(4, "project_root",
                     "这是整个下载的项目，不是技能目录：%s 里有 %s（复制范围只允许 SKILL.md 的父目录）"
                     % (src_dir, "、".join(markers)))
    real_root = os.path.realpath(src_dir)
    links = []
    for dp, dn, fn in os.walk(src_dir, followlinks=False):
        for name in list(dn) + list(fn):
            p = os.path.join(dp, name)
            if not _is_link(p):
                continue
            real = os.path.realpath(p)
            inside = real == real_root or real.startswith(real_root + os.sep)
            links.append({"path": os.path.relpath(p, src_dir), "target": real, "inside": inside})
            dn[:] = [x for x in dn if x != name]
    escapes = [l for l in links if not l["inside"]]
    if escapes:
        raise Refuse(4, "symlink_escape",
                     "源目录里有指向目录外的符号链接：%s（拒绝把外部内容复制进技能目录）"
                     % "、".join("%s -> %s" % (l["path"], l["target"]) for l in escapes[:3]))
    if links:
        raise Refuse(4, "symlink_present",
                     "源目录里有符号链接：%s（导入只接受真实文件，避免复制重复/循环）"
                     % "、".join(l["path"] for l in links[:3]))
    return True


def _check_self_copy(src_dir, target):
    rs = os.path.realpath(src_dir)
    rt = os.path.realpath(target)
    if rs == rt or rt.startswith(rs + os.sep):
        raise Refuse(4, "self_copy", "源目录与目标目录重叠（递归自我复制）：%s → %s" % (rs, rt))
    if rs.startswith(rt + os.sep):
        raise Refuse(4, "self_copy", "源目录在目标目录里面（递归自我复制）：%s ⊂ %s" % (rs, rt))


# ============================================================ 唯一 roots 解析（plan/import/deploy/verify/status）
def _repo_root_for(skill_dir):
    """<repo>/Tool/skill → <repo>；识别不出就返回 None（测试/多仓临时根，只做局部判定）。"""
    d = os.path.abspath(skill_dir or "")
    if os.path.basename(d) == "skill" and os.path.basename(os.path.dirname(d)) == "Tool":
        return os.path.dirname(os.path.dirname(d))
    return None


def _redact_path(raw):
    """拒绝信息里的路径不进原值：只留末级名字 + 长度（不回显绝对路径/用户名/盘符）。"""
    if not raw:
        return "?"
    name = os.path.basename(os.path.normpath(str(raw)))
    return "<path:%s,len=%d>" % (name if name and name not in (".", "..", os.sep) else "?",
                                  len(str(raw)))


def _validate_deploy_root(root, skill_dir, repo=None, src_dir=None):
    """单个部署根的边界校验（只读；任何写入之前）。消息不回显敏感原值。"""
    rp = os.path.abspath(root)
    if not rp or rp == os.sep or os.path.dirname(rp) == rp:
        raise Refuse(4, "deploy_root_not_dir", "部署根不能是文件系统根：%s" % _redact_path(root))
    if _is_link(rp):
        raise Refuse(4, "deploy_root_symlink",
                     "部署根是符号链接/junction（拒绝写穿到别处）：%s（目标 %s）"
                     % (_redact_path(rp), _redact_path(os.path.realpath(rp))))
    # 注："根已存在但不是目录"不在这里拒：它不是路径逃逸，而是在申请锁目录时立刻失败的
    # I/O 不可能（rc=5 且仓库/部署面零部分写）。这里只做**写盘前**的边界拒绝。
    checks = [("skill-dir", skill_dir),
              ("repo", repo or _repo_root_for(skill_dir)),
              ("源目录", src_dir)]
    for label, other in checks:
        if not other:
            continue
        why = _rel_overlap_reason(rp, other, label)
        if why:
            raise Refuse(4, "deploy_root_overlap",
                         "%s（拒在写盘前：仓库/源目录与部署根不得重叠或互为祖先）" % why,
                         root=_redact_path(rp), other=_redact_path(os.path.abspath(other)),
                         label=label)
    return rp


def _resolve_deploy_roots(opts, kind, src_dir=None, allow_empty=False):
    """**唯一** roots 解析：返回 (roots, warnings)。不写盘。

    allow_empty=True（verify/status/subskill）时"没给根"是合法的，返回 []，**绝不**兜底到
    真实用户根也不读它。allow_empty=False（domain/crosscutting 的 import/plan/deploy）时：
      · 给了根 → 逐个过边界校验；
      · 没给根 + 自定义 --skill-dir → 拒 deploy_root_required，不悄悄写真实 ~/.pi；
      · 没给根 + 默认 skill-dir → 当前 AgentRoot 下的 skills（每次调用重新解析环境）。
    """
    skill_dir = os.path.abspath(opts.get("skill_dir") or SKILL_DIR)
    given = [os.path.abspath(r) for r in (opts.get("deploy_roots") or []) if r]
    custom = _norm(skill_dir) != _norm(SKILL_DIR)
    warnings = []
    if not opts.get("deploy", True) and kind not in ("verify", "status"):
        if given:
            warnings.append("给了 --deploy-root 但同时 --no-deploy：本次不写部署面")
        return [], warnings
    if not given:
        if allow_empty:
            return [], warnings
        if custom:
            raise Refuse(4, "deploy_root_required",
                         "自定义 --skill-dir 时必须显式 --deploy-root（否则只写仓库：加 --no-deploy）",
                         hint="--no-deploy 或 --deploy-root <skills 根>")
        default_root = _default_deploy_root()
        return [default_root], [
            "未给 --deploy-root：按当前 AgentRoot 写默认根 %s（自定义 skill-dir 时不再这样兜底）"
            % default_root
        ]
    repo = _repo_root_for(skill_dir)
    out, seen = [], set()
    for r in given:
        rp = _validate_deploy_root(r, skill_dir, repo=repo, src_dir=src_dir)
        k = _norm(rp)
        if k in seen:
            continue
        seen.add(k)
        out.append(rp)
    return out, warnings


# ============================================================ 并发锁（多资源、跨进程、全局有序）
def _lock_dir(root):
    return os.path.join(root, STAGING_NAME)


def _lock_path(skill_dir, name):
    """同名事务锁（旧文件名保留，外部脚本/探针按此路径检查）。"""
    return os.path.join(_lock_dir(skill_dir), "%s.lock" % name)


def _res_lock_path(root, key):
    return os.path.join(_lock_dir(root), "res-%s.lock" % _sha1(key)[:16])


def _lock_payload(role, path):
    return {"role": role, "protected": path, "pid": os.getpid(), "ts": _now(),
            "host": os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "",
            "proc_start": _process_start_token(os.getpid()),
            "argv0": os.path.basename(sys.argv[0] or "")}


def _lock_guard_path(path):
    """OS-owned short mutex for create/inspect/takeover/remove of one root's lock files.

    The transaction lock files contain a PID, but a file's mere existence cannot make
    "read stale metadata, then replace/unlink" atomic.  An advisory OS lock gives us
    that boundary and is released automatically if its owner exits.
    """
    lock_parent = os.path.dirname(os.path.abspath(path))
    root = (os.path.dirname(lock_parent)
            if os.path.basename(lock_parent) == STAGING_NAME else lock_parent)
    name = "seep-import-lock-guard-%s" % _sha1(_norm(root))
    return os.path.join(tempfile.gettempdir(), name)


def _try_os_guard(fd):
    """Try to take a one-byte exclusive advisory lock without blocking."""
    if os.name == "nt":
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_os_guard(fd):
    if os.name == "nt":
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)


def _acquire_lock_guard(path):
    """Acquire the short OS-owned critical section for a root's lock namespace."""
    guard = _lock_guard_path(path)
    try:
        os.makedirs(os.path.dirname(guard), exist_ok=True)
        fd = os.open(guard, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as exc:
        raise Refuse(5, "lock_guard_unwritable",
                     "无法建立锁接管临界区：%s（%s）" % (guard, str(exc)[:120]))
    try:
        # msvcrt can only lock bytes that exist.
        if os.fstat(fd).st_size == 0:
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, b"\0")
        deadline = time.time() + LOCK_WAIT_S
        while True:
            try:
                _try_os_guard(fd)
                return fd
            except OSError:
                if time.time() >= deadline:
                    raise Refuse(4, "lock_guard_busy",
                                 "锁接管临界区在等待 %.1fs 后仍被占用" % LOCK_WAIT_S)
                time.sleep(LOCK_POLL_S + random.random() * LOCK_POLL_S)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _close_lock_guard(fd):
    """Release the short guard and surface a failed close instead of hiding it."""
    failure = None
    try:
        _unlock_os_guard(fd)
    except OSError as exc:
        failure = exc
    try:
        os.close(fd)
    except OSError as exc:
        if failure is None:
            failure = exc
    if failure is not None:
        raise Refuse(5, "lock_guard_close_failed",
                     "锁接管临界区释放失败：%s" % str(failure)[:120])


def _lock_or_takeover_inside_guard(path, payload):
    """Create or replace one dead lock while holding the OS-owned guard."""
    got = _write_lock(path, payload)
    takeover = None
    if got is not None:
        return got, takeover
    meta = _read_lock(path)
    if meta.get("alive") is not False:
        return None, meta
    try:
        os.remove(path)
    except FileNotFoundError:
        # A holder released between metadata inspection and removal; retry creation.
        pass
    except OSError as exc:
        raise Refuse(5, "stale_lock_remove_failed",
                     "已确认属主退出的锁无法安全接管：%s（%s）"
                     % (path, str(exc)[:120]))
    got = _write_lock(path, payload)
    return got, meta


def _lock_or_takeover(path, payload):
    """Serialize all lock mutations for one root, then create/take over one resource."""
    fd = _acquire_lock_guard(path)
    primary = None
    result = None
    try:
        result = _lock_or_takeover_inside_guard(path, payload)
        return result
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            _close_lock_guard(fd)
        except BaseException as close_exc:
            if primary is None:
                if (isinstance(close_exc, Refuse) and result
                        and result[0]):
                    close_exc.extra["acquired_lock"] = result[0]
                raise


def _write_lock(path, payload):
    """原子占锁：O_CREAT|O_EXCL（跨进程有效，不依赖 Windows 文件锁语义）。"""
    d = os.path.dirname(path)
    try:
        os.makedirs(d, exist_ok=True)
    except OSError as e:
        raise Refuse(5, "lock_dir_unwritable",
                     "无法建立锁目录（部署根不是可用目录？）：%s（%s）" % (d, str(e)[:120]))
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return None
    except OSError as e:
        raise Refuse(5, "lock_unwritable", "无法创建锁文件：%s（%s）" % (path, str(e)[:120]))
    failure = None
    try:
        body = ("pid=%d ts=%s\n%s\n"
                % (payload.get("pid", os.getpid()), payload.get("ts", _now()),
                   json.dumps(payload, ensure_ascii=False, sort_keys=True)))
        view = memoryview(body.encode("utf-8"))
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("lock metadata short write")
            view = view[written:]
        os.fsync(fd)
    except BaseException as exc:  # cleanup must not mask the persistence failure
        failure = exc
    if fd is not None:
        try:
            os.close(fd)
        except OSError as exc:
            if failure is None:
                failure = exc
            elif isinstance(failure, OSError):
                failure = OSError("%s；close: %s" % (str(failure)[:100], str(exc)[:100]))
        fd = None
    if failure is not None:
        cleanup = ""
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            cleanup = "；清理失败：%s" % str(exc)[:120]
        if isinstance(failure, OSError):
            raise Refuse(
                5, "lock_persist_failed",
                "锁元数据未持久化，已拒绝继续：%s（%s%s）"
                % (path, str(failure)[:120], cleanup))
        raise failure
    return path


def _process_start_token(pid):
    """Stable process-start token, used to reject PID reuse when the OS exposes it."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None
    try:
        with io.open("/proc/%d/stat" % pid, encoding="utf-8", errors="replace") as stream:
            suffix = stream.read().rsplit(")", 1)[1].strip().split()
        return "proc-start:%s" % suffix[19]
    except (OSError, IndexError):
        pass
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [
            wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x00101000, False, pid)
        if not handle:
            return None
        try:
            created = wintypes.FILETIME()
            exited = wintypes.FILETIME()
            kernel = wintypes.FILETIME()
            user = wintypes.FILETIME()
            if not kernel32.GetProcessTimes(
                    handle, ctypes.byref(created), ctypes.byref(exited),
                    ctypes.byref(kernel), ctypes.byref(user)):
                return None
            value = (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)
            return "win-start:%d" % value
        finally:
            kernel32.CloseHandle(handle)
    except Exception:  # noqa: BLE001
        return None


def _pid_alive(pid, expected_start=None):
    """Return True/False only when liveness is knowable; None means permission/host unknown."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None
    if pid <= 0:
        return False
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            actual = _process_start_token(pid)
            if expected_start and actual and actual != expected_start:
                return False
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return None
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        query_limited = 0x1000
        synchronize = 0x00100000
        kernel32.OpenProcess.argtypes = [
            wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(query_limited | synchronize, False, pid)
        if not handle:
            # Access denied means the process exists; invalid parameter means it exited.
            if ctypes.get_last_error() != 5:
                return False
            actual = _process_start_token(pid)
            return False if expected_start and actual and actual != expected_start else True
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return None
            if code.value != 259:  # STILL_ACTIVE
                return False
            actual = _process_start_token(pid)
            if expected_start and actual and actual != expected_start:
                return False
            return True
        finally:
            kernel32.CloseHandle(handle)
    except Exception:  # noqa: BLE001
        return None


def _read_lock(path):
    """锁属主元数据（公开信息：pid/ts/角色/保护路径），只读，不删。"""
    meta = {"path": path}
    try:
        with io.open(path, encoding="utf-8", errors="replace") as stream:
            t = stream.read()
    except OSError:
        return meta
    m = re.search(r"pid=(\d+)", t)
    if m:
        meta["pid"] = int(m.group(1))
    for line in t.splitlines():
        if line.lstrip().startswith("{"):
            try:
                meta.update(json.loads(line))
            except ValueError:
                pass
    current_host = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or ""
    lock_host = str(meta.get("host") or "")
    meta["alive"] = (_pid_alive(meta.get("pid"), meta.get("proc_start"))
                     if not lock_host or lock_host == current_host else None)
    meta["note"] = ("属主进程已退出，可由下一次导入原子接管并恢复"
                    if meta["alive"] is False else
                    "属主仍在运行或无法确认；本事务继续等待/拒绝，不删除活锁")
    return meta


def _acquire_lock(skill_dir, name):
    """单个同名锁的**非阻塞**尝试（旧接口，测试/探针直接用）。返回锁路径或 None。"""
    got, _takeover = _lock_or_takeover(
        _lock_path(skill_dir, name), _lock_payload("skill", name))
    return got


def _release_lock(path):
    """Remove one owned lock. Return an error string instead of hiding cleanup failure."""
    if not path:
        return ""
    fd = None
    failure = ""
    try:
        fd = _acquire_lock_guard(path)
        os.remove(path)
    except FileNotFoundError:
        pass
    except Refuse as e:
        failure = "%s: %s" % (path, e.message)
    except OSError as e:
        failure = "%s: %s" % (path, str(e)[:120])
    finally:
        if fd is not None:
            try:
                _close_lock_guard(fd)
            except Refuse as e:
                close_failure = "%s: %s" % (path, e.message)
                failure = close_failure if not failure else failure + "；" + close_failure
    return failure


def _release_stale_lock(path):
    """Remove a legacy stale lock only while holding the same OS guard as takeover."""
    fd = None
    try:
        fd = _acquire_lock_guard(path)
        if _read_lock(path).get("alive") is not False:
            return ""
        os.remove(path)
        return ""
    except FileNotFoundError:
        return ""
    except Refuse as exc:
        return "%s: %s" % (path, exc.message)
    except OSError as exc:
        return "%s: %s" % (path, str(exc)[:120])
    finally:
        if fd is not None:
            try:
                _close_lock_guard(fd)
            except Refuse as exc:
                return "%s: %s" % (path, exc.message)


def _release_locks(paths):
    errors = []
    dirs = {os.path.dirname(p) for p in (paths or []) if p}
    for p in reversed(list(paths or [])):
        why = _release_lock(p)
        if why:
            errors.append(why)
    for d in sorted(dirs):
        try:
            if os.path.isdir(d):
                for name in os.listdir(d):
                    if not (name.startswith("stale-") and name.endswith(".lock")):
                        continue
                    p = os.path.join(d, name)
                    why = _release_stale_lock(p)
                    if why:
                        errors.append(why)
            if os.path.isdir(d) and not os.listdir(d):
                os.rmdir(d)
        except OSError as exc:
            errors.append("%s: %s" % (d, str(exc)[:120]))
    return errors


def _takeover_stale_lock(path, payload):
    """Take over a provably dead lock through the root's OS-owned mutation guard."""
    return _lock_or_takeover(path, payload)


def _lock_specs(plan):
    """列出本事务要同时持有的全部锁；sort 键 = 规范化被保护路径（全局一致顺序，避免死锁）。"""
    skill_dir = plan["skill_dir"]
    name = plan["name"]
    target = plan.get("target")
    info = plan.get("parent") or {}
    specs = []

    def add(root, key, role, path, lock_path=None):
        specs.append({"root": root, "role": role, "key": key, "path": path,
                      "lock_path": lock_path or _res_lock_path(root, key),
                      "sort": (_norm(path), role)})

    add(skill_dir, "skill:%s" % name, "skill", target or os.path.join(skill_dir, name),
        lock_path=_lock_path(skill_dir, name))
    if target:
        add(skill_dir, "parentdir:%s" % _norm(os.path.dirname(target)),
            "repo-parent-dir", os.path.dirname(target))
        add(skill_dir, "dest:%s" % _norm(target), "repo-dest", target)
    if info.get("skill_md"):
        add(skill_dir, "file:%s" % _norm(info["skill_md"]), "repo-parent-file", info["skill_md"])
    for i, root in enumerate(plan.get("deploy_roots") or []):
        if plan.get("kind") == "subskill" and info.get("domain"):
            proot = os.path.join(root, info["domain"])
            add(root, "parentdir:%s" % _norm(proot), "deploy-parent-dir:%d" % i, proot)
            add(root, "file:%s" % _norm(os.path.join(proot, "SKILL.md")),
                "deploy-parent-file:%d" % i, os.path.join(proot, "SKILL.md"))
            add(root, "dest:%s" % _norm(os.path.join(proot, "references", "imported-subskills", name)),
                "deploy-subskill-dest:%d" % i,
                os.path.join(proot, "references", "imported-subskills", name))
        else:
            add(root, "parentdir:%s" % _norm(root), "deploy-parent-dir:%d" % i, root)
            add(root, "dest:%s" % _norm(os.path.join(root, name)), "deploy-dest:%d" % i,
                os.path.join(root, name))
    return specs


def _recovery_lock_specs(skill_dir, base_specs, name, prefixes):
    """Add lock coverage for resources named by durable journals from earlier roots."""
    jdir = os.path.join(_lock_dir(skill_dir), JOURNAL_DIR)
    if not os.path.isdir(jdir):
        return list(base_specs)
    stamp_re = re.compile(r"^\d{8}-\d{6}-\d+(?:-\d+)?\.jsonl$")
    paths = []
    for filename in sorted(os.listdir(jdir)):
        remainder = next(
            (filename[len(prefix):] for prefix in prefixes if filename.startswith(prefix)),
            None)
        if remainder is not None and stamp_re.fullmatch(remainder):
            paths.append(os.path.join(jdir, filename))
    out = list(base_specs)
    seen = {_norm(spec["lock_path"]) for spec in out}

    def add(root, protected, role, key_kind):
        key = "%s:%s" % (key_kind, _norm(protected))
        lock_path = _res_lock_path(root, key)
        if _norm(lock_path) in seen:
            return
        seen.add(_norm(lock_path))
        out.append({
            "root": root,
            "role": role,
            "key": key,
            "path": protected,
            "lock_path": lock_path,
            "sort": (_norm(protected), role),
        })

    for path in paths:
        entries, _malformed = _read_journal_entries(path)
        if str(entries[0].get("name") or "") != name:
            raise Refuse(5, "journal_identity_mismatch",
                         "journal 文件名与事务声明的技能名不一致，拒绝预占错误资源锁：%s"
                         % path, journal=path)
        base = entries[0]
        journal_roots = [
            str(root) for root in (base.get("deploy_roots") or [])
            if root and not _within(str(root), skill_dir)
        ]
        roots = [skill_dir] + [os.path.abspath(root) for root in journal_roots]

        def owner_root(protected):
            if not protected:
                return None
            matches = [root for root in roots if _within(protected, root)]
            return max(matches, key=len) if matches else None

        for root in roots:
            add(root, os.path.abspath(root),
                "recovery-root:%s" % os.path.basename(os.path.abspath(root)),
                "parentdir")
        for entry in entries:
            if entry.get("op") != "intent":
                continue
            protected = []
            if entry.get("action") == "move":
                protected.extend([entry.get("src"), entry.get("dst")])
            elif entry.get("action") == "patch":
                protected.append(entry.get("file"))
            elif entry.get("action") == "mkdir":
                protected.append(entry.get("dst"))
            for item in protected:
                if not item:
                    continue
                root = owner_root(item)
                if root is None:
                    continue
                parent = os.path.dirname(os.path.abspath(item))
                add(root, parent,
                    "recovery-parent:%s" % os.path.basename(path), "parentdir")
                add(root, os.path.abspath(item),
                    "recovery-intent-dest:%s" % os.path.basename(path), "dest")
                add(root, os.path.abspath(item),
                    "recovery-intent-file:%s" % os.path.basename(path), "file")
    return out


def _acquire_locks(specs, wait=None):
    """按规范化路径**全局有序**依次占锁（有界等待）；原子接管已退出属主的锁。"""
    if not specs:
        return []
    budget = LOCK_WAIT_S if wait is None else float(wait)
    deadline = time.time() + budget
    ordered = sorted(specs, key=lambda s: (s["sort"][0], s["sort"][1], s["lock_path"]))
    held = []
    try:
        for s in ordered:
            payload = _lock_payload(s["role"], s.get("path") or s["lock_path"])
            got, takeover = _lock_or_takeover(s["lock_path"], payload)
            if got is None:
                holder_now = takeover or _read_lock(s["lock_path"])
                if (holder_now.get("alive") is True
                        and holder_now.get("pid") == os.getpid()):
                    raise Refuse(
                        4, "locked",
                        "同一进程内重复占用非重入事务锁：%s（角色 %s）"
                        % (s["lock_path"], s["role"]),
                        lock=s["lock_path"], role=s["role"], holder=holder_now,
                        next_actions=["外层事务结束并释放锁后再重试；不要在同一事务内递归导入"],
                    )
            while got is None and time.time() < deadline:
                time.sleep(LOCK_POLL_S + random.random() * LOCK_POLL_S)
                got, takeover = _lock_or_takeover(s["lock_path"], payload)
            if got is None:
                holder = _read_lock(s["lock_path"])
                raise Refuse(4, "locked",
                             "资源被另一个导入事务占用：%s（角色 %s）" % (s["lock_path"], s["role"]),
                             lock=s["lock_path"], role=s["role"], holder=holder,
                             waited_s=round(budget, 1),
                             next_actions=[
                                 "等它结束后重跑（锁是跨进程的，不会自动过期）",
                                 "用 `python Tool/scripts/skill-import.py status` 看属主 pid/ts、"
                                 "进程存活状态与动作阶段",
                                 "已退出属主的锁会在下一次导入时原子接管；活锁仍会阻止写入",
                             ])
            held.append(got)
        return held
    except BaseException as exc:
        cleanup_paths = list(held)
        if isinstance(exc, Refuse) and exc.extra.get("acquired_lock"):
            cleanup_paths.append(exc.extra.pop("acquired_lock"))
        cleanup_errors = _release_locks(cleanup_paths)
        if cleanup_errors and isinstance(exc, Refuse):
            exc.extra["cleanup_errors"] = cleanup_errors
            exc.message += "；锁清理也失败：%s" % "；".join(cleanup_errors[:3])
            exc.args = (exc.message,)
        raise


# ============================================================ 事务 journal（先 intent，后 done）
class Journal(list):
    """事务日志：每次登记都落盘+fsync；`rollback` 依据它 + 磁盘事实判定。

    条目形状：
      {"op":"phase","phase":"stage|validate|commit|parent|deploy|verify"}
      {"op":"staging","dir":<本事务 staging 目录>}
      {"op":"intent","id":X,"action":"move|mkdir|patch", ...}   ← 操作**前**
      {"op":"done","id":X}                                     ← 操作**完成后**
    为什么先 intent：旧实现在 `_move` 之后才登记；rename 中途失败时 journal 里没有该项，
    回滚把"被搬走一半的旧目录"当成功，回执却写 `rolled_back=true`（独立验收 R1/B9/B11）。
    """

    def __init__(self, path=None, base=None):
        list.__init__(self)
        self.path = path
        self.base = dict(base or {})
        self._fh = None
        self._seq = 0
        self._failed = None
        if path:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                self._fh = io.open(path, "a", encoding="utf-8", newline="\n")  # noqa: SIM115
            except Exception as exc:  # noqa: BLE001
                raise Refuse(5, "journal_open_failed",
                             "事务 journal 无法创建，已拒绝任何破坏性写入（%s）"
                             % type(exc).__name__)

    def next_id(self):
        self._seq += 1
        return "op%d" % self._seq

    def record(self, op, **kw):
        e = {"op": op, "pid": os.getpid(), "ts": _now()}
        e.update(self.base)
        e.update(kw)
        self._flush(e)
        # Keep memory equal to durable evidence: a line that was not fsynced cannot be
        # used by the current process to perform the operation it describes.
        self.append(e)
        return e

    def _flush(self, e):
        if self._failed:
            raise Refuse(5, "journal_persist_failed",
                         "事务 journal 已发生持久化失败，拒绝继续任何写操作")
        if not self._fh:
            raise Refuse(5, "journal_closed",
                         "事务 journal 已关闭，不能在持久性不明时继续破坏性操作")
        try:
            line = json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n"
            written = self._fh.write(line)
            if written != len(line):
                raise OSError("journal short write: %r != %r" % (written, len(line)))
            self._fh.flush()
            os.fsync(self._fh.fileno())
        except Exception as exc:  # noqa: BLE001
            self._failed = exc
            raise Refuse(5, "journal_persist_failed",
                         "事务 journal 写入/flush/fsync 失败，已停止：%s"
                         % str(exc)[:160])

    def close(self, remove=False):
        errors = []
        if self._fh:
            try:
                self._fh.close()
            except Exception as exc:  # noqa: BLE001
                errors.append("close:%s" % str(exc)[:120])
            self._fh = None
        if remove and self.path:
            try:
                os.remove(self.path)
            except FileNotFoundError:
                pass
            except OSError as exc:
                errors.append("remove:%s" % str(exc)[:120])
            try:
                d = os.path.dirname(self.path)
                if os.path.isdir(d) and not os.listdir(d):
                    os.rmdir(d)
            except OSError as exc:
                if os.path.isdir(d) and not os.listdir(d):
                    errors.append("rmdir:%s" % str(exc)[:120])
        if errors:
            raise Refuse(5, "journal_cleanup_failed",
                         "事务 journal 关闭/清理失败，结果不得当作已收尾：%s"
                         % "；".join(errors))


def _jrec(journal, op, **kw):
    """兼容普通 list（旧测试/探针传 `[]`）与 Journal。"""
    if journal is None:
        return kw
    if hasattr(journal, "record"):
        return journal.record(op, **kw)
    kw["op"] = op
    journal.append(kw)
    return kw


def _jid(journal):
    if hasattr(journal, "next_id"):
        return journal.next_id()
    return "op%d" % (len(journal or []) + 1)


def _cleanup_staging(rec, journal=None, roots=None):
    """Delete only this transaction's staging/empty backup dirs; return real failures."""
    dirs = [e.get("dir") for e in (journal or []) if e.get("op") == "staging"]
    dirs += list((rec or {}).pop("_staging_dirs", []) or [])
    errors = []
    for d in sorted(set(dirs)):
        if d and os.path.isdir(d):
            try:
                shutil.rmtree(d)
            except OSError as exc:
                errors.append("%s: %s" % (d, str(exc)[:120]))
    if not (rec or {}).get("rollback_partial"):
        backup_dirs = [
            e.get("dst") for e in (journal or [])
            if e.get("op") == "intent" and e.get("action") == "mkdir"
            and "backup-dir" in str(e.get("role") or "")
        ]
        for d in sorted(set(backup_dirs)):
            if d and os.path.isdir(d):
                try:
                    if not os.listdir(d):
                        os.rmdir(d)
                except OSError as exc:
                    errors.append("%s: %s" % (d, str(exc)[:120]))
    for root in (roots or []):
        st = _lock_dir(root)
        try:
            if os.path.isdir(st) and not os.listdir(st):
                os.rmdir(st)
        except OSError as exc:
            errors.append("%s: %s" % (st, str(exc)[:120]))
    return errors


# ============================================================ 判型（建议 → 身份）
def suggest_kind(text, meta):
    kind, detail = classify(text, meta)
    return {"kind_suggestion": kind, "detail": detail,
            "note": "关键词/后缀/技法只是判型建议，不是正式域身份；正式域必须有 pack.json"}


def _pack_from(src_dir, explicit):
    """返回 (pack_path, pack_obj) 或 (None, None)。显式 --pack 优先，其次 <src>/pack.json。"""
    cands = []
    if explicit:
        if not os.path.isfile(explicit):
            raise Refuse(4, "pack_missing", "--pack 指向的 pack.json 不存在：%s" % explicit)
        cands.append(explicit)
    cands.append(os.path.join(src_dir, "pack.json"))
    for p in cands:
        if p and os.path.isfile(p):
            try:
                return p, _load_json(p)
            except Exception as e:  # noqa: BLE001
                raise Refuse(4, "pack_unreadable", "pack.json 读不了：%s（%s）" % (p, str(e)[:120]))
    return None, None


def _decide_kind(opts, ctx):
    """返回 (kind, why)。auto 只在**有真实 pack** 或**已在横切表**时才给出可执行身份。"""
    explicit = opts.get("kind") or "auto"
    if explicit not in KINDS:
        raise Refuse(2, "bad_kind", "未知 --kind：%r（可选 %s）" % (explicit, "/".join(KINDS)))
    pack = ctx["pack"]
    if explicit == "tool":
        return "tool", "显式 --kind tool（只声明，不安装）"
    if explicit in ("domain", "crosscutting", "subskill"):
        return explicit, "显式 --kind %s" % explicit
    # ---- auto：只给建议，不擅称 ----
    if pack is not None:
        pid = str((pack or {}).get("id") or "")
        if pid and pid == ctx["name"]:
            return "domain", ("附带 pack.json 的 id=%s 与目录名一致（真实 pack 才算域，关键词不算）" % pid)
        raise Refuse(2, "needs_classification",
                     "附带 pack.json 的 id=%r 与名字 %r 不一致：先由 Agent 确认哪个是正式域 id"
                     % (pid, ctx["name"]), suggestion=ctx["suggestion"])
    if ctx["name"] in cross_cutting_names():
        return "crosscutting", "名字已在 domain-aliases.json#cross_cutting（横切技能，不是正式域）"
    raise Refuse(2, "needs_classification",
                 "判型未定：没有 pack.json、也不在横切表（关键词命中只是建议，不能自封正式域）",
                 suggestion=ctx["suggestion"],
                 next_actions=[
                     "正式域：补齐真实 pack.json（id==目录名、routes/witness/evidence_contract 真实）"
                     "后用 --kind domain --pack <pack.json> 显式选择；缺 witness/案例就如实报缺口，不许伪造",
                     "横切技能：--kind crosscutting（可被多域复用，不是客户可见正式域）",
                     "子技能：--kind subskill --parent <真实域名>（落 _pending/ 并自动补父域引用）",
                     "工具：--kind tool --from <manifest.json>（只声明，不安装、不宣称可用）",
                 ])


def _global_domain_contracts(name, skill_dir=None):
    """Report only registrations that still consume a stale, non-pack domain set."""
    pending = []
    skill_dir = os.path.abspath(skill_dir or SKILL_DIR)
    ds = None
    try:
        ds = _module(os.path.join(SCRIPTS, "lib", "domain_spec.py"), "seep_domain_spec_for_import")
        if name not in list(getattr(ds, "DOMAINS", {}) or {}):
            pending.append("lib/domain_spec.py DOMAINS 缺 %s（深度门禁/案例矩阵/KB 数/ROUTING_TESTS 固定集）"
                           % name)
    except Exception as e:  # noqa: BLE001
        pending.append("读不到 lib/domain_spec.py（%s）" % str(e)[:60])
    tpl = os.path.join(TOOL, "cases", "_templates", "%s.json" % name)
    if not os.path.isfile(tpl):
        pending.append("domain-gate.py 要求 Tool/cases/_templates/%s.json，且模板份数 == len(DOMAINS)" % name)
    try:
        dac = _module(os.path.join(SCRIPTS, "domain-adapter-check.py"), "seep_domain_adapter_for_import")
        repo = _repo_root_for(skill_dir)
        current = set(dac.formal_domains(repo)) if repo and hasattr(dac, "formal_domains") else set()
        if repo and current and name not in current:
            pending.append("domain-adapter-check.py 动态 formal_domains() 未发现 %s" % name)
    except Exception as e:  # noqa: BLE001
        pending.append("domain-adapter-check.py 动态领域扫描失败（%s）" % str(e)[:60])
    try:
        inv = _module(os.path.join(SCRIPTS, "invariants.py"), "seep_invariants_for_import")
        count = getattr(inv, "DOMAIN_COUNT", None)
        n_domains = len(getattr(ds, "DOMAINS", {}) or {}) if ds is not None else None
        if n_domains is None or name not in list(getattr(ds, "DOMAINS", {}) or {}):
            pending.append(
                "invariants.py DOMAIN_COUNT=%s 仍依赖固定领域表；新域 %s 尚未进入动态 pack 集合的对账"
                % (count, name))
    except Exception as e:  # noqa: BLE001
        pending.append("读不到 invariants.py（%s）" % str(e)[:60])
    formal = list((aliases().get("formal_domains") or []))
    if name not in formal:
        pending.append("Tool/config/domain-aliases.json formal_domains 缺 %s（唯一分类表，导入器不自动写）" % name)
    return pending


# ============================================================ plan
def _opts(src="", name=None, kind="auto", parent="", pack="", entry="", skill_dir=None,
          deploy_roots=None, deploy=True, dry=False, replace=False, tool_id="",
          tool_manifest=""):
    return {
        "src": src or "", "name": name or "", "kind": kind or "auto", "parent": parent or "",
        "pack": pack or "", "entry": entry or "",
        "skill_dir": os.path.abspath(skill_dir) if skill_dir else SKILL_DIR,
        "deploy_roots": [os.path.abspath(r) for r in (deploy_roots or []) if r],
        "deploy": bool(deploy), "dry": bool(dry), "replace": bool(replace),
        "tool_id": tool_id or "", "tool_manifest": tool_manifest or src,
    }


def plan_import(opts):
    """只读阶段：解析 meta、判型、查 pack/父域存在性、**校验 roots 边界**、算落点。不写盘。"""
    if not opts["src"]:
        raise Refuse(2, "missing_from", "缺 --from（外部技能目录 / SKILL.md / tool manifest）")
    kind_hint = opts["kind"]
    if kind_hint == "tool" or (kind_hint == "auto" and str(opts["src"]).lower().endswith(".json")
                               and not os.path.isdir(opts["src"])):
        return _plan_tool(opts)

    try:
        p, text = read_skill(opts["src"])
    except SystemExit:
        raise Refuse(4, "skill_md_missing",
                     "找不到 SKILL.md：%s（源必须是技能目录或 SKILL.md 本身）" % opts["src"])
    meta = parse(text)
    if not meta["description"]:
        raise Refuse(4, "no_description", "缺 description —— 它是模型选择该技能的唯一依据，必须先写")
    name = (opts["name"] or meta["name"] or os.path.basename(os.path.dirname(p)) or "").strip()
    ok, why = _valid_name(name)
    if not ok:
        raise Refuse(4, "bad_name", why)
    src_dir = os.path.dirname(os.path.abspath(p))
    _check_source_tree(src_dir)

    pack_path, pack = _pack_from(src_dir, opts["pack"])
    ctx = {"src": opts["src"], "skill_md": p, "text": text, "meta": meta, "name": name,
           "src_dir": src_dir, "pack_path": pack_path, "pack": pack,
           "suggestion": suggest_kind(text, meta), "kind": None, "why": ""}
    kind, why = _decide_kind(opts, ctx)
    ctx["kind"], ctx["why"] = kind, why
    skill_dir = opts["skill_dir"]

    plan = {
        "schema": "seep.skill-import.plan/1",
        "kind": kind, "name": name,
        "kind_why": why,
        "kind_suggestion": ctx["suggestion"]["kind_suggestion"],
        "criteria": ["%s %s：%s" % ("✅" if o else "❌", n, w)
                     for n, o, w in ctx["suggestion"]["detail"]["criteria"]],
        "src": src_dir, "skill_md": p,
        "meta": meta,
        "suggestion_detail": ctx["suggestion"]["detail"],
        "entry": opts.get("entry") or "",
        "src_files": _copy_plan(src_dir),
        "skill_dir": skill_dir,
        "pack": pack_path,
        "parent": None,
        "target": None,
        "deploy_roots": [],
        "warnings": [],
    }
    if kind == "crosscutting":
        plan["target"] = os.path.join(skill_dir, name)
        if name not in cross_cutting_names():
            plan["warnings"].append("名字不在 domain-aliases.json#cross_cutting：本次是显式声明，"
                                    "分类表仍由人工/单独变更登记")
    elif kind == "subskill":
        if not opts["parent"]:
            raise Refuse(2, "needs_parent", "子技能必须 --parent <真实域名>（否则无法补父域引用，等于写了没人读）")
        packs, problems = scan_packs(skill_dir)
        ids = {x["id"] for x in packs}
        parent = opts["parent"]
        if parent not in ids:
            raise Refuse(4, "parent_missing",
                         "父域 %r 不是真实 pack 域（%s 里只有 %s）" % (parent, skill_dir, "、".join(sorted(ids))))
        pp = os.path.join(skill_dir, parent, "SKILL.md")
        if not os.path.isfile(pp):
            raise Refuse(4, "parent_skill_missing", "父域缺 SKILL.md：%s" % pp)
        with io.open(pp, encoding="utf-8", errors="replace") as f:
            anchor_count = sum(1 for ln in f if PARENT_ANCHOR in ln)
        if anchor_count != 1:
            raise Refuse(4, "parent_anchor",
                         "父 SKILL.md 的锚点「%s」出现 %d 次（必须恰好 1 次，否则不知道插哪）"
                         % (PARENT_ANCHOR, anchor_count))
        plan["parent"] = {"domain": parent, "skill_md": pp, "anchor": PARENT_ANCHOR,
                          "repo_ref": REPO_REF_TMPL % name,
                          "deploy_ref": DEPLOY_REF_TMPL % name}
        plan["target"] = os.path.join(skill_dir, "_pending", name)
    else:  # domain
        if pack is None:
            raise Refuse(4, "why_not_domain",
                         "正式域必须有 pack.json：没有 pack 就不能路由、不能被 gate 判、不算域；"
                         "缺 witness/案例/evidence_contract 就如实报缺口，不许伪造")
        plan["target"] = os.path.join(skill_dir, name)
    _check_self_copy(src_dir, plan["target"])
    if kind == "subskill":
        # 子技能可选部署（复制到父域 references/imported-subskills/）；没给根就是 repo-only，不兜底
        roots, warns = _resolve_deploy_roots(opts, kind, src_dir=src_dir, allow_empty=True)
        plan["deploy_roots"] = roots
        plan["warnings"].extend(warns)
    else:
        roots, warns = _resolve_deploy_roots(opts, kind, src_dir=src_dir)
        plan["deploy_roots"] = roots
        plan["warnings"].extend(warns)
    # lexists also catches a dangling symlink/junction occupying the target name.
    plan["replace_needed"] = os.path.lexists(plan["target"])
    plan["replace"] = bool(opts.get("replace"))
    return plan


def _plan_tool(opts):
    """tool 模式：只校验 manifest，**不写任何 tool catalog**（本轮不拥有那些文件）。"""
    path = opts["tool_manifest"] or opts["src"]
    if not os.path.isfile(path):
        raise Refuse(4, "tool_manifest_missing", "tool manifest 不存在：%s" % path)
    try:
        raw = _load_json(path)
    except Exception as e:  # noqa: BLE001
        raise Refuse(4, "tool_manifest_bad", "tool manifest 不是合法 JSON：%s" % str(e)[:120])
    if not isinstance(raw, dict):
        raise Refuse(4, "tool_manifest_bad", "tool manifest 顶层必须是对象")
    tool_id = str(opts["tool_id"] or raw.get("id") or raw.get("tool") or "").strip()
    ok, why = _valid_name(tool_id)
    if not ok:
        raise Refuse(4, "bad_name", "工具 id " + why)
    return {
        "schema": "seep.skill-import.plan/1", "kind": "tool", "name": tool_id,
        "meta": {"name": tool_id, "description": str(raw.get("why") or "")[:200]},
        "suggestion_detail": {}, "entry": "",
        "kind_why": "显式 --kind tool：只声明，不安装、不写 catalogs",
        "kind_suggestion": "tool", "criteria": [],
        "src": path, "skill_md": "", "src_files": 1, "skill_dir": opts["skill_dir"],
        "pack": None, "parent": None, "target": None, "deploy_roots": [],
        "manifest": raw, "manifest_path": path, "warnings": [],
        "replace_needed": False, "replace": False,
    }


# ============================================================ 校验
def validate_pack(plan, staged_dir, skill_dir):
    """用**真实** gate.g2_schema + route 契约校验 pack（不复制 schema、不跑整套门禁）。

    g2 覆盖：schema/字段集合/l1/limits/cases 存在/case_roles/tools 在 MCP 清单/witness/
    evidence_contract。routes 再由 route.py 的真实现（正则/优先级/SKILL.md 在场）判。
    """
    pack = plan.get("pack_obj")
    name = plan["name"]
    if not isinstance(pack, dict):
        raise Refuse(4, "pack_bad", "pack 顶层不是对象")
    if str(pack.get("id") or "") != name:
        raise Refuse(4, "pack_id_mismatch",
                     "pack.id=%r 与目录名/--name=%r 不一致（正式域身份 = id == 目录名）"
                     % (pack.get("id"), name))
    # g2 still validates the canonical pack-facing path, but hashes the actual
    # staged skill directory before the transaction commits it into Tool/skill.
    bad = _gate().g2_schema(pack, witness_root=staged_dir)
    if bad:
        raise Refuse(4, "pack_schema", "pack 不符合真实 g2_schema：%s" % "；".join(bad[:6]),
                     g2=bad)
    route_mod = _route()
    # 孤立目录复算：只用这一个 pack 跑真实 route.check（死路由/坏正则/重复优先级/SKILL.md）
    tmp = tempfile.mkdtemp(prefix="seep-import-route-")
    try:
        d = os.path.join(tmp, name)
        os.makedirs(d)
        shutil.copy2(os.path.join(staged_dir, "SKILL.md"), os.path.join(d, "SKILL.md"))
        shutil.copy2(os.path.join(staged_dir, "pack.json"), os.path.join(d, "pack.json"))
        res = route_mod.check(tmp)
        if res["problems"]:
            raise Refuse(4, "pack_routes", "路由契约不过：%s" % "；".join(res["problems"][:6]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # 与已存在域的路由空间冲突（优先级重复会让路由顺序不确定）
    packs, problems = route_mod.load_packs(skill_dir)
    other_prios = {}
    for p in packs:
        if p["id"] == name:
            continue
        for r in p["routes"]:
            if isinstance(r, dict):
                other_prios.setdefault(int(r.get("priority") or 0), []).append(p["id"])
    clash = []
    for r in pack.get("routes") or []:
        pr = int((r or {}).get("priority") or 0)
        if pr in other_prios:
            clash.append("%d 已被 %s 使用" % (pr, ",".join(other_prios[pr])))
    if clash:
        raise Refuse(4, "priority_clash", "新域路由 priority 与现有域冲突：%s" % "；".join(clash[:5]))
    return {"g2_ok": True, "routes": len(pack.get("routes") or []),
            "evidence_contract_ok": isinstance(pack.get("evidence_contract"), dict),
            "witness_declared": bool(pack.get("witness")),
            "witness_tool_declared": bool(pack.get("witness_tool")),
            # 声明 ≠ 实跑：本批不执行任何 witness/技能代码，所以这里恒 false
            "witness_ran": False,
            "case_roles_from_import": False,
            "note": "只做结构/路由契约校验；witness 未实跑（witness_ran=false），"
                    "案例矩阵/深度门禁另属'第 10 域'变更"}


def _is_ref_bullet(line):
    return bool(REF_BULLET_RE.match(line))


def _ref_name_of(line):
    m = PENDING_LINK_RE.search(line)
    if m:
        return m.group(1)
    m = DEPLOY_REF_RE.search(line)
    if m:
        return m.group(1)
    return ""


def _insert_parent_line(text, name, line_text, anchor):
    """在父 SKILL.md 的**唯一锚点**后的子技能列表里插入/排序一行（其余字符不动）。

    返回 (new_text, line_no, mode, inserted_with_newline)。
    """
    lines = text.splitlines(True)
    idx = [i for i, ln in enumerate(lines) if anchor in ln]
    if len(idx) != 1:
        raise Refuse(4, "parent_anchor", "锚点出现 %d 次：%s" % (len(idx), anchor))
    i = idx[0]
    nl = "\r\n" if "\r\n" in text else "\n"
    new_line = line_text.replace("\r\n", "\n").replace("\n", nl).rstrip("\r\n") + nl
    j = i + 1
    while j < len(lines) and not lines[j].strip():
        j += 1
    if j < len(lines) and _is_ref_bullet(lines[j]):
        start = j
        k = j
        while k < len(lines) and _is_ref_bullet(lines[k]):
            k += 1
        block = lines[start:k]
        pos = len(block)
        for n, b in enumerate(block):
            child = _ref_name_of(b)
            if child and child > name:
                pos = n
                break
        lines.insert(start + pos, new_line)
        return "".join(lines), start + pos + 1, "sorted-insert", new_line
    lines.insert(i + 1, new_line)
    return "".join(lines), i + 2, "append-after-anchor", new_line


def _write_text_durable(path, text):
    """Write text and prove both content and descriptor close completed."""
    stream = None
    failure = None
    try:
        stream = io.open(path, "w", encoding="utf-8", newline="")  # noqa: SIM115
        written = stream.write(text)
        if written != len(text):
            raise OSError("atomic write short write: %r != %r" % (written, len(text)))
        stream.flush()
        os.fsync(stream.fileno())
    except BaseException as exc:  # cleanup must not hide the first failure
        failure = exc
    if stream is not None:
        try:
            stream.close()
        except OSError as exc:
            if failure is None:
                failure = exc
    if failure is not None:
        raise failure


def _fsync_path(path):
    """fsync a copied file and report close failures separately."""
    fd = None
    failure = None
    try:
        fd = os.open(path, os.O_RDWR)
        os.fsync(fd)
    except BaseException as exc:
        failure = exc
    if fd is not None:
        try:
            os.close(fd)
        except OSError as exc:
            if failure is None:
                failure = exc
    if failure is not None:
        raise failure


def _atomic_write_text(path, text):
    """同目录临时文件 + os.replace：父 SKILL.md 不做截断式重写（并发读到半写的窗口）。"""
    d = os.path.dirname(os.path.abspath(path))
    tmp = os.path.join(d, ".%s.seep-tmp-%d-%d"
                       % (os.path.basename(path), os.getpid(), time.time_ns()))
    try:
        _write_text_durable(tmp, text)
        os.replace(tmp, path)
    except BaseException as exc:
        cleanup = ""
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        except OSError as cleanup_exc:
            cleanup = "；临时文件清理失败：%s" % str(cleanup_exc)[:120]
        if isinstance(exc, OSError):
            raise Refuse(5, "atomic_write_failed",
                         "原子写无法保证持久落盘：%s（%s%s）"
                         % (path, str(exc)[:160], cleanup))
        raise
    return path


def _atomic_copy(src, dst):
    d = os.path.dirname(os.path.abspath(dst))
    tmp = os.path.join(d, ".%s.seep-tmp-%d-%d"
                       % (os.path.basename(dst), os.getpid(), time.time_ns()))
    try:
        shutil.copy2(src, tmp)
        _fsync_path(tmp)
        os.replace(tmp, dst)
    except BaseException as exc:
        cleanup = ""
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        except OSError as cleanup_exc:
            cleanup = "；临时文件清理失败：%s" % str(cleanup_exc)[:120]
        if isinstance(exc, OSError):
            raise Refuse(5, "atomic_copy_failed",
                         "原子复制无法保证持久落盘：%s（%s%s）"
                         % (dst, str(exc)[:160], cleanup))
        raise
    return dst


# ============================================================ 事务：stage / commit / parent / deploy
def _stage(plan, journal, faults):
    name, skill_dir = plan["name"], plan["skill_dir"]
    staging = os.path.join(_lock_dir(skill_dir), "%s-%s" % (name, _ts()))
    os.makedirs(os.path.dirname(staging), exist_ok=True)
    # Persist cleanup ownership before file creation.  A process death *during* the
    # copy then leaves enough durable evidence for the next transaction to remove it.
    _jrec(journal, "staging", dir=staging)
    _fault(faults, "stage.copy")
    try:
        shutil.copytree(plan["src"], staging, ignore=COPY_IGNORE)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    _fault(faults, "stage.copy.after")
    # 附带 pack 在源目录外 → 合法地写进 stage（这是身份声明，不是伪造内容）
    pack_injected = False
    if plan["kind"] == "domain":
        dst_pack = os.path.join(staging, "pack.json")
        src_pack = plan.get("pack")
        if not os.path.isfile(dst_pack):
            shutil.copy2(src_pack, dst_pack)
            pack_injected = True
        elif os.path.realpath(src_pack) != os.path.realpath(dst_pack):
            shutil.copy2(src_pack, dst_pack)
            pack_injected = True
        plan["pack_obj"] = _load_json(dst_pack)
    _fault(faults, "stage.manifest")
    manifest = {"schema": MANIFEST_SCHEMA, "name": name, "kind": plan["kind"],
                "files": hash_tree(staging)}
    with io.open(os.path.join(staging, MANIFEST_NAME), "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    plan["_staging"] = staging
    return {"staging": staging, "pack_injected": pack_injected,
            "staged_files": len(manifest["files"]), "manifest": manifest}


def _move_tracked(journal, src, dst, role, faults=None, fault_point=None):
    """登记 intent → 改名 → 登记 done（回滚只按事实判定）。"""
    jid = _jid(journal)
    _jrec(journal, "intent", id=jid, action="move", role=role, src=src, dst=dst)
    if fault_point:
        _fault(faults, fault_point)
    how = _move(src, dst, journal=journal, role=role, faults=faults)
    _jrec(journal, "done", id=jid, result=how)
    return how


def _mkdir_tracked(journal, path, role):
    if os.path.isdir(path):
        return False
    jid = _jid(journal)
    _jrec(journal, "intent", id=jid, action="mkdir", role=role, dst=path)
    os.makedirs(path, exist_ok=True)
    _jrec(journal, "done", id=jid)
    return True


def _commit(plan, staging, skill_dir, journal, faults):
    """仓库侧：旧目录整体改名进 backup → staging 改名进 target。任何一步失败都不半搬。"""
    name = plan["name"]
    target = plan["target"]
    backup_dir = os.path.join(skill_dir, BACKUP_NAME, "%s-%s" % (name, _ts()))
    backup_path = None
    if os.path.lexists(target):
        if not plan.get("replace"):
            raise Refuse(4, "target_exists",
                         "目标已存在：%s（要覆盖必须显式 --replace；不会 rmtree 旧目录再 copy）" % target)
        _fault(faults, "commit.backup")
        _mkdir_tracked(journal, backup_dir, "repo-backup-dir")
        backup_path = os.path.join(backup_dir, name)
        _fault(faults, "commit.backup.rename.before")
        _move_tracked(journal, target, backup_path, "repo-old", faults)
        _fault(faults, "commit.backup.rename.after")
    _mkdir_tracked(journal, os.path.dirname(target), "repo-parent-dir")
    _fault(faults, "commit.swap")
    _move_tracked(journal, staging, target, "repo-new", faults, fault_point="commit.swap.move")
    _fault(faults, "commit.swap.after")
    return {"target": target, "backup": backup_dir if backup_path else None,
            "backup_path": backup_path, "replaced": bool(backup_path)}


def _patch_file(journal, file, name, line_text, anchor, faults, fault_point, backup_path,
                role, ref_resolver):
    """父 SKILL.md 的幂等插入：备份 → (原子) 写 → 读回复核；journal 先 intent 后 done。"""
    text = _read_text(file)
    if ref_resolver(text):
        return {"file": file, "changed": False, "idempotent": True,
                "note": "父 SKILL.md 已引用该子技能，本次不改（幂等）"}
    new_text, line_no, mode, inserted = _insert_parent_line(text, name, line_text, anchor)
    if new_text == text:
        return {"file": file, "changed": False, "idempotent": True, "mode": mode}
    before_sha = _bytes_sha(file)
    jid = _jid(journal)
    _jrec(journal, "intent", id=jid, action="patch", role=role, file=file, backup=backup_path,
          before_sha=before_sha, after_sha=_bytes_sha_text(new_text), inserted=inserted)
    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    _atomic_copy(file, backup_path)
    _fault(faults, fault_point)
    _atomic_write_text(file, new_text)
    _fault(faults, fault_point + ".write.after")
    written = _read_text(file)
    if written != new_text:
        raise Refuse(5, "parent_write", "父 SKILL.md 写入后内容不一致：%s" % file)
    _jrec(journal, "done", id=jid)
    _fault(faults, fault_point + ".after")
    return {"file": file, "changed": True, "idempotent": False, "line": line_no,
            "anchor": anchor, "inserted": inserted.rstrip("\r\n"), "backup": backup_path,
            "mode": mode, "ref": line_text}


def _patch_parent(plan, journal, faults, backup_dir):
    """仓库父 SKILL.md：写 `../_pending/<child>/SKILL.md`（相对**父技能目录**解析）。"""
    info = plan.get("parent")
    if not info:
        return None
    name = plan["name"]
    desc = plan.get("entry") or (plan["meta"]["description"] or "按需读的子技能")[:60]
    line_text = "- `%s` —— %s" % (REPO_REF_TMPL % name, desc)
    pbackup = os.path.join(backup_dir, "_parent", info["domain"], "SKILL.md")
    return _patch_file(journal, info["skill_md"], name, line_text, info["anchor"],
                       faults, "parent.patch", pbackup, "repo-parent",
                       lambda t: name in PENDING_LINK_RE.findall(t))


def _patch_deployed_parent(plan, journal, faults, root, idx, backup_dir):
    """部署父 SKILL.md：写 `references/imported-subskills/<child>/GUIDE.md`（真实相对文档）。"""
    info = plan.get("parent")
    if not info:
        return None
    name = plan["name"]
    dparent = os.path.join(root, info["domain"], "SKILL.md")
    if not os.path.isfile(dparent):
        return {"file": dparent, "changed": False, "pending": True,
                "note": "父域未部署到该 root：部署侧入口未建立（pending，不宣称可达）"}
    desc = plan.get("entry") or (plan["meta"]["description"] or "按需读的子技能")[:60]
    line_text = "- `%s` —— %s" % (DEPLOY_REF_TMPL % name, desc)
    pbackup = os.path.join(backup_dir, "_parent", "deploy-%d" % idx, "SKILL.md")
    return _patch_file(journal, dparent, name, line_text, info["anchor"],
                       faults, "deploy.parent.patch.%d" % idx, pbackup, "deploy-parent:%d" % idx,
                       lambda t: name in DEPLOY_REF_RE.findall(t))


def _deploy_one(plan, root, idx, repo_target, backup_dir, journal, faults):
    """把一个已落仓库的技能部署到 root：staging 与 backup 都在**该 root 本地同卷**。"""
    name = plan["name"]
    staging = os.path.join(_lock_dir(root), "%s-%s" % (name, _ts()))
    os.makedirs(os.path.dirname(staging), exist_ok=True)
    _jrec(journal, "staging", dir=staging)
    _fault(faults, "deploy.copy.%d" % idx)
    try:
        shutil.copytree(repo_target, staging, ignore=COPY_IGNORE)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    _fault(faults, "deploy.copy.after.%d" % idx)
    target = os.path.join(root, name)
    backup_path = None
    if os.path.lexists(target):
        bdir = os.path.join(root, BACKUP_NAME, "%s-%s" % (name, _ts()))
        _fault(faults, "deploy.backup.%d" % idx)
        _mkdir_tracked(journal, bdir, "deploy-backup-dir:%d" % idx)
        backup_path = os.path.join(bdir, name)
        _move_tracked(journal, target, backup_path, "deploy-old:%d" % idx, faults)
    _fault(faults, "deploy.swap.%d" % idx)
    _move_tracked(journal, staging, target, "deploy-new:%d" % idx, faults)
    _fault(faults, "deploy.after.%d" % idx)
    return {"root": root, "path": target, "backup": backup_path,
            "files": len(hash_tree(target))}


def _deploy_subskill(plan, root, idx, repo_child, journal, faults):
    """子技能部署：<root>/<parent>/references/imported-subskills/<child>/（入口 SKILL.md → GUIDE.md）。

    为什么这么放（IMPORT-02 R3/裁定 3）：
      · 模型只读部署根，仓库里那行它读不到 → 必须把子技能本体复制到部署面；
      · 不能被当成"新的全局技能" → 不放 <root>/<child>，入口文档改名 GUIDE.md；
      · 父部署 SKILL.md 指向 `references/imported-subskills/<child>/GUIDE.md`，按**父技能目录**可解析；
      · 父域没部署到该 root 时如实报 pending（不自动把父域搬过去）。
    """
    info = plan.get("parent") or {}
    name = plan["name"]
    parent = info.get("domain")
    proot = os.path.join(root, parent) if parent else None
    base = {"root": root, "role": "subskill", "parent": parent}
    if not parent or not os.path.isdir(proot) or not os.path.isfile(os.path.join(proot, "SKILL.md")):
        return dict(base, deployed=False, pending=True, path=None,
                    why="父域未部署到该 root（不自动部署父域）：部署侧入口 pending，不宣称可达")
    refs_parent = os.path.join(proot, "references", "imported-subskills")
    target = os.path.join(refs_parent, name)
    _mkdir_tracked(journal, refs_parent, "deploy-parent-refs-dir:%d" % idx)
    staging = os.path.join(_lock_dir(root), "%s-%s" % (name, _ts()))
    os.makedirs(os.path.dirname(staging), exist_ok=True)
    _jrec(journal, "staging", dir=staging)
    _fault(faults, "deploy.copy.%d" % idx)
    try:
        shutil.copytree(repo_child, staging, ignore=COPY_IGNORE)
        entry_src = os.path.join(staging, "SKILL.md")
        if os.path.isfile(entry_src):
            os.replace(entry_src, os.path.join(staging, "GUIDE.md"))
        files = hash_tree(staging)
        sub_manifest = {"schema": SUBSCHEMA_MAP, "child": name, "parent": parent,
                        "mapping": {SUB_MAP_ENTRY_SRC: SUB_MAP_ENTRY_DST}, "files": files,
                        "entry": DEPLOY_REF_TMPL % name,
                        "note": "部署侧副本：入口改名 GUIDE.md，避免被当成新的全局技能被自动选中"}
        with io.open(os.path.join(staging, IMPORT_MAP_NAME), "w", encoding="utf-8",
                     newline="\n") as f:
            json.dump(sub_manifest, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")
        # 生产与 verify 共用**同一份** map schema/语义校验：写下去的 map 必须自己能过
        with io.open(os.path.join(staging, IMPORT_MAP_NAME), encoding="utf-8") as stream:
            probs = _validate_sub_map(
                json.load(stream), name, parent, repo_child, staging)[0]
        if probs:
            raise Refuse(5, "map_contract", "部署侧 map 自检不过：%s" % "；".join(probs[:4]))
        _fault(faults, "deploy.copy.after.%d" % idx)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    backup_path = None
    if os.path.lexists(target):
        bdir = os.path.join(root, BACKUP_NAME, "%s-%s" % (name, _ts()))
        _mkdir_tracked(journal, bdir, "deploy-backup-dir:%d" % idx)
        backup_path = os.path.join(bdir, name)
        _move_tracked(journal, target, backup_path, "deploy-old:%d" % idx, faults)
    _move_tracked(journal, staging, target, "deploy-new:%d" % idx, faults)
    patch = _patch_deployed_parent(plan, journal, faults, root, idx,
                                   os.path.join(root, BACKUP_NAME, "%s-%s" % (name, _ts())))
    return dict(base, deployed=True, pending=False, path=target, files=len(files),
                mapping={SUB_MAP_ENTRY_SRC: SUB_MAP_ENTRY_DST}, entry=DEPLOY_REF_TMPL % name,
                hashes=files, backup=backup_path, parent_patch=patch)


# ============================================================ 入口可达性（真实解析，不是字符串 contains）
def _resolve_refs(text, base_file, name, regex):
    """把 base_file 所在**技能目录**当基准解析行内相对路径；返回真实存在的文档列表。"""
    base = os.path.dirname(os.path.abspath(base_file))
    out = []
    for line in text.splitlines():
        if not regex.search(line):
            continue
        for ref in re.findall(r"`([^`]+)`", line):
            if not regex.search(ref):
                continue
            if name and not regex.search(ref).group(1) == name:
                continue
            p = os.path.normpath(os.path.join(base, ref.replace("/", os.sep).replace("\\", os.sep)))
            if os.path.isfile(p):
                out.append(p)
    return out


def _entry_reachable(plan):
    """仓库父引用核验：那一行必须能按**父技能目录**解析到真实文件。"""
    info = plan.get("parent")
    if not info:
        return None
    try:
        t = _read_text(info["skill_md"])
    except Exception:  # noqa: BLE001
        return False
    if plan["name"] not in PENDING_LINK_RE.findall(t):
        return False
    return bool(_resolve_refs(t, info["skill_md"], plan["name"], PENDING_LINK_RE))


def _repo_parent_entries(skill_dir, name):
    """扫所有域 SKILL.md，找出真正能按技能目录解析到 `_pending/<name>/SKILL.md` 的域。"""
    linked, dangling = [], []
    child = os.path.join(skill_dir, "_pending", name, "SKILL.md")
    for d in sorted(os.listdir(skill_dir)) if os.path.isdir(skill_dir) else []:
        if d.startswith(".") or d == "_pending":
            continue
        pp = os.path.join(skill_dir, d, "SKILL.md")
        if not os.path.isfile(pp):
            continue
        try:
            t = _read_text(pp)
        except OSError:
            continue
        if name not in PENDING_LINK_RE.findall(t):
            continue
        resolved = _resolve_refs(t, pp, name, PENDING_LINK_RE)
        if any(os.path.normcase(p) == os.path.normcase(child) for p in resolved):
            linked.append(d)
        else:
            dangling.append({"domain": d, "resolved": resolved})
    return linked, dangling


def _map_rel_problem(rel, forbid):
    """相对路径规范化：拒绝绝对路径/盘符/穿越/空段/重复（返回原因或 ""）。"""
    if not isinstance(rel, str) or not rel.strip():
        return "路径为空"
    if rel != rel.strip() or "\x00" in rel:
        return "路径含空白/控制符"
    norm_slashes = rel.replace("\\", "/")
    if norm_slashes.startswith("/") or re.match(r"^[A-Za-z]:", norm_slashes):
        return "绝对路径"
    parts = norm_slashes.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return "含空段/./..（穿越或重复分隔）"
    if re.search(r"[<>:\"|?*]", norm_slashes):
        return "含非法字符"
    if norm_slashes in forbid:
        return "落到了禁止的映射目标：%s" % norm_slashes
    return ""


def _validate_sub_map(sub, name, parent, repo_child, deploy_dir):
    """**权威** map 契约校验（IMPORT-03 / R-NEW-1）：生产与 verify 共用这一份。

    为什么不只是抄进回执：`schema/child/parent/entry/mapping/files` 是身份与入口声明。
    若它们不参与判定，把 mapping 改成 OTHER.md 之后 verify 仍绿 = 可达性证明是假的。
    返回 (problems, resolved_entry, mapping) —— 收集全部问题而不是第一条就返回，便于回执。
    """
    problems = []
    if not isinstance(sub, dict):
        return (["map 顶层不是对象"], None, {})
    missing = [f for f in SUB_MAP_FIELDS if f not in sub]
    if missing:
        problems.append("map 缺权威字段：%s" % ",".join(missing))
    if sub.get("schema") != SUBSCHEMA_MAP:
        problems.append("schema 不是 %s" % SUBSCHEMA_MAP)
    if sub.get("child") != name:
        problems.append("child 声明与目录名不一致")
    if sub.get("parent") != parent:
        problems.append("parent 声明与部署父域不一致")
    if sub.get("entry") != DEPLOY_REF_TMPL % name:
        problems.append("entry 声明不是 %s" % (DEPLOY_REF_TMPL % name))

    mapping = sub.get("mapping")
    if not isinstance(mapping, dict) or not mapping:
        problems.append("mapping 不是非空对象")
        mapping = {}
    else:
        if len(mapping) != 1:
            problems.append("mapping 声明了 %d 条（入口只能一对一）" % len(mapping))
        srcs = [SUB_MAP_ENTRY_SRC]
        if sorted(mapping) != sorted(srcs):
            problems.append("mapping 源侧必须是 %s（不能多对一/映射到别的源）"
                            % SUB_MAP_ENTRY_SRC)
        dst = mapping.get(SUB_MAP_ENTRY_SRC)
        if dst != SUB_MAP_ENTRY_DST:
            problems.append("mapping 目标不是 %s（入口改名契约）" % SUB_MAP_ENTRY_DST)
    # 映射里的**每条**路径都要规范化：不得绝对/穿越/重复/落到别的源文件
    all_dsts = {}
    for src_rel, dst_rel in sorted(mapping.items()):
        why = _map_rel_problem(src_rel, {IMPORT_MAP_NAME})
        if why:
            problems.append("映射源 %r：%s" % (src_rel, why))
        why = _map_rel_problem(dst_rel, {SUB_MAP_ENTRY_SRC, IMPORT_MAP_NAME})
        if why:
            problems.append("映射目标 %r：%s" % (dst_rel, why))
        if isinstance(dst_rel, str):
            key = dst_rel.replace("\\", "/")
            if key in all_dsts and all_dsts[key] != src_rel:
                problems.append("多对一：%r 与 %r 映射到同一目标 %r"
                                % (all_dsts[key], src_rel, key))
            all_dsts[key] = src_rel

    files = sub.get("files")
    if not isinstance(files, dict) or not files:
        problems.append("files 不是非空对象")
        files = {}
    else:
        for rel in sorted(files):
            why = _map_rel_problem(rel, {IMPORT_MAP_NAME})
            if why:
                problems.append("files 里的 %r：%s" % (rel, why))
        if SUB_MAP_ENTRY_DST not in files:
            problems.append("files 没有登记入口 %s" % SUB_MAP_ENTRY_DST)

    # 映射后的文件必须**真的存在**，且 path 映射后 size/hash 与声明一致（不是"GUIDE 在就算"）
    for src_rel, dst_rel in sorted(mapping.items()):
        if not isinstance(dst_rel, str):
            continue
        target = os.path.join(deploy_dir, dst_rel.replace("/", os.sep))
        if not os.path.isfile(target):
            problems.append("映射目标 %r 在部署副本里不存在" % dst_rel)
            continue
        declared = files.get(dst_rel)
        if not declared:
            problems.append("映射目标 %r 未登记到 files（不可核）" % dst_rel)
            continue
        real = _norm_sha(target)
        if real != declared:
            problems.append("映射目标 %r 的 hash 与 map 声明不一致" % dst_rel)
        src_file = os.path.join(repo_child, src_rel.replace("/", os.sep))
        if not os.path.isfile(src_file):
            problems.append("仓库侧源 %r 不存在" % src_rel)
        elif real != _norm_sha(src_file):
            problems.append("映射目标 %r 与仓库侧 %r 不同源（内容/hash 不一致）"
                            % (dst_rel, src_rel))
        elif os.path.getsize(target) != os.path.getsize(src_file):
            # hash 口径按 LF 归一，故另比原始字节数：CRLF/截断冒充不得逃过
            problems.append("映射目标 %r 的字节数与仓库侧 %r 不一致" % (dst_rel, src_rel))

    mapped = mapping.get(SUB_MAP_ENTRY_SRC)
    entry_file = (os.path.join(deploy_dir, mapped.replace("/", os.sep))
                  if isinstance(mapped, str) and mapped else None)
    if entry_file and not os.path.isfile(entry_file):
        entry_file = None
    return (problems, entry_file, mapping)


def _verify_subskill_deploy(plan_or_name, skill_dir, root, idx, parent=None):
    """部署侧核验：父部署 SKILL.md 的引用行 + 复制进来的文档/映射 hash。只读。"""
    name = plan_or_name["name"] if isinstance(plan_or_name, dict) else plan_or_name
    parent = parent or ((plan_or_name.get("parent") or {}).get("domain")
                        if isinstance(plan_or_name, dict) else None)
    rep = {"root": root, "role": "subskill", "parent": parent,
           "path": os.path.join(root, parent, "references", "imported-subskills", name)
           if parent else None}
    dparent = os.path.join(root, parent, "SKILL.md") if parent else None
    if not dparent or not os.path.isfile(dparent):
        rep.update(status="parent_not_deployed", pending=True, hashes_equal=None,
                   entry_reachable=False,
                   why="父域未部署到该 root：按需可达尚未建立（pending，不是失败）")
        return rep
    text = _read_text(dparent)
    if name not in DEPLOY_REF_RE.findall(text):
        rep.update(status="parent_ref_missing", pending=False, hashes_equal=False,
                   entry_reachable=False,
                   why="部署父 SKILL.md 没有指向 references/imported-subskills/%s/GUIDE.md 的行" % name)
        return rep
    resolved = _resolve_refs(text, dparent, name, DEPLOY_REF_RE)
    rep["entry_reachable"] = bool(resolved)
    rep["entry_file"] = resolved[0] if resolved else None
    mp = os.path.join(rep["path"], IMPORT_MAP_NAME)
    if not os.path.isfile(mp):
        rep.update(status="map_missing", pending=False, hashes_equal=False,
                   why="缺部署侧映射清单 %s" % IMPORT_MAP_NAME)
        return rep
    sub = None
    try:
        sub = _load_json(mp)
    except Exception:  # noqa: BLE001
        # 不回显原始 JSON 片段（可能带路径/凭据形状内容），只报"读不了"
        rep.update(status="map_unreadable", pending=False, hashes_equal=False,
                   why="部署侧映射清单不是合法 JSON")
        return rep
    now = hash_tree(rep["path"])
    now.pop(IMPORT_MAP_NAME, None)
    declared_files = sub.get("files") if isinstance(sub, dict) else None
    want = dict(declared_files) if isinstance(declared_files, dict) else {}
    diff = tree_diff(want, now)
    rep["mapping"] = (sub.get("mapping") if isinstance(sub, dict) else {}) or {}
    rep["files"] = len(now)
    rep["diff"] = diff[:6]
    # 入口文档必须与仓库子技能 SKILL.md 同 hash（且按 map 的 mapping 解析，不硬编码 GUIDE）
    repo_child = os.path.join(skill_dir, "_pending", name)
    repo_skill = os.path.join(repo_child, SUB_MAP_ENTRY_SRC)
    problems, entry_file, _mapping = _validate_sub_map(sub, name, parent, repo_child, rep["path"])
    rep["map_problems"] = problems[:8]
    mapped_target = entry_file
    entry_equal = None
    if mapped_target and os.path.isfile(repo_skill):
        # 只有映射解析出的文件**就是**父引用那个文件时，入口 hash 才有意义
        same_file = bool(resolved) and os.path.normcase(os.path.abspath(mapped_target)) in \
            {os.path.normcase(os.path.abspath(p)) for p in resolved}
        entry_equal = (_norm_sha(repo_skill) == _norm_sha(mapped_target)) and same_file
        if resolved and not same_file:
            problems.append("map 映射的目标不是父 SKILL.md 引用的那个文件")
            rep["map_problems"] = problems[:8]
    rep["entry_hash_equal"] = entry_equal
    ok = bool(resolved) and not diff and entry_equal is not False and not problems
    rep["hashes_equal"] = ok
    rep["status"] = "ok" if ok else "drift"
    rep["why"] = ("部署父 SKILL.md 的相对引用可解析、map 身份/入口/映射与 hash 一致" if ok else
                  "部署侧不一致：%s" % ("；".join((diff + problems)[:4])
                                        or "引用不可解析/入口 hash 不同"))
    return rep


def _validate_repo_manifest(manifest, name, kind):
    """仓库侧 import-manifest.json 的身份字段也是**契约**：schema/name/kind 被改不得仍绿。

    与 `_validate_sub_map` 同一口径：生产写的值就是这里要求的值；_verify 与 cmd_verify 共用。
    """
    problems = []
    if not isinstance(manifest, dict):
        return ["manifest 顶层不是对象"]
    if manifest.get("schema") != MANIFEST_SCHEMA:
        problems.append("schema 不是 %s" % MANIFEST_SCHEMA)
    if manifest.get("name") != name:
        problems.append("name 声明与技能名不一致")
    if manifest.get("kind") != kind:
        problems.append("kind 声明与实际类型 %s 不一致" % kind)
    if not isinstance(manifest.get("files"), dict) or not manifest.get("files"):
        problems.append("files 不是非空对象")
    return problems


# ============================================================ verify
def _verify(plan, receipt, skill_dir, faults):
    """真实核验：manifest(hash) + 路由 + 父入口 + 部署等价（按 kind 分开判）。失败 = rc5。"""
    name, kind = plan["name"], plan["kind"]
    target = plan["target"]
    _fault(faults, "verify.before")
    mf_path = os.path.join(target, MANIFEST_NAME)
    if not os.path.isfile(mf_path):
        raise Refuse(5, "manifest_missing", "commit 后缺 %s（回执不可核）" % MANIFEST_NAME)
    manifest = _load_json(mf_path)
    mproblems = _validate_repo_manifest(manifest, name, kind)
    if mproblems:
        raise Refuse(5, "manifest_contract",
                     "%s 身份/字段与契约不符：%s" % (MANIFEST_NAME, "；".join(mproblems[:4])))
    now = hash_tree(target)
    drift = []
    for rel, sha in sorted((manifest.get("files") or {}).items()):
        if rel == MANIFEST_NAME:
            continue
        if rel not in now:
            drift.append("缺 %s" % rel)
        elif now[rel] != sha:
            drift.append("漂移 %s" % rel)
    extra = sorted(set(now) - set(manifest.get("files") or {}) - {MANIFEST_NAME})
    if drift or extra:
        raise Refuse(5, "manifest_drift",
                     "stage 清单与落盘不一致：%s" % "；".join((drift + ["多 " + x for x in extra])[:6]))
    res = {"manifest_files": len(manifest.get("files") or {}), "drift": drift,
           "extra": extra, "repo_hashes": len(now)}

    route_mod = _route()
    rcheck = route_mod.check(skill_dir)
    ours = [p for p in (rcheck.get("problems") or []) if name in p]
    res["route_check"] = {"packs": rcheck["packs"], "routes": rcheck["routes"],
                          "dead": rcheck["dead"], "problems": len(rcheck.get("problems") or []),
                          "problems_about_this_pack": ours}
    if ours or (kind == "domain" and rcheck.get("problems")):
        raise Refuse(5, "route_check", "route.py --check 不通过：%s"
                     % "；".join((rcheck.get("problems") or [])[:4]))
    ids = {row[1] for row in (rcheck.get("rows") or [])}
    res["route_visible"] = name in ids if kind == "domain" else None
    if kind == "domain":
        if not res["route_visible"]:
            raise Refuse(5, "route_invisible", "新域没有出现在路由索引里（路由不可发现）")
        l1 = str((plan.get("pack_obj") or {}).get("l1") or "")
        hits = route_mod.resolve(l1, skill_dir) if l1 else []
        res["route_resolve"] = [{"pack": h["pack"], "label": h["label"]} for h in hits[:3]]
        res["route_hit_self"] = any(h["pack"] == name for h in hits)
        if not res["route_hit_self"]:
            raise Refuse(
                5,
                "route_self_miss",
                "domain pack.l1 没有命中该域自己的路由：路由索引可见不等于可路由，"
                "拒绝把新域标记为生效",
                l1=l1,
                resolved=[h.get("pack") for h in hits[:8]],
            )

    if kind == "subskill":
        # 子技能**不**做顶层部署等价比较（它永不部署成 <root>/<name>）
        reach = _entry_reachable(plan)
        res["entry_reachable"] = reach
        if not reach:
            raise Refuse(5, "entry_missing",
                         "父 SKILL.md 里没有可解析到 %s 的引用（模型读不到内容）" % plan.get("parent", {}).get("repo_ref", ""))
        dep = []
        for i, root in enumerate(plan.get("deploy_roots") or []):
            d = _verify_subskill_deploy(plan, skill_dir, root, i)
            dep.append(d)
            if d.get("status") == "drift":
                raise Refuse(5, "subskill_deploy_drift",
                             "部署侧子技能不一致：root[%d] %s（%s）"
                             % (i, d.get("path"), d.get("why")))
        res["deploy"] = dep
        return res

    # 部署等价（逐 root 逐文件 hash，与 domain-gate._norm_sha 同口径）
    dep = []
    repo_hashes = hash_tree(target)
    for i, root in enumerate(plan.get("deploy_roots") or []):
        path = os.path.join(root, name)
        other = hash_tree(path)
        same = other == repo_hashes
        dep.append({"root": root, "path": path, "files": len(other), "hashes_equal": same,
                    "diff": tree_diff(repo_hashes, other)[:5]})
        if not same:
            raise Refuse(5, "verify_hash_drift",
                         "root[%d] %s 与仓库不一致：%s" % (i, path, dep[-1]["diff"]))
    res["deploy"] = dep
    res["entry_reachable"] = None
    return res


# ============================================================ 回滚（按事实）
def _restore_patched(it):
    """父文件回滚：能整体还原就整体还原；被别人改过就只撤自己那一行（不覆盖别人的提交）。"""
    f, backup = it.get("file"), it.get("backup")
    before_sha, after_sha = it.get("before_sha"), it.get("after_sha")
    if not f or not os.path.isfile(f):
        return False, "父文件不存在，无法回滚（备份：%s）" % backup, True
    cur = _bytes_sha(f)
    if before_sha and cur == before_sha:
        return True, "父文件已是原状", False
    if backup and os.path.isfile(backup) and (not after_sha or cur == after_sha):
        _atomic_copy(backup, f)
        ok = (not before_sha) or _bytes_sha(f) == before_sha
        return ok, ("用备份原子还原" if ok else "还原后 hash 与导入前不一致（备份：%s）" % backup), not ok
    inserted = it.get("inserted") or ""
    text = _read_text(f)
    if inserted and text.count(inserted) == 1:
        _atomic_write_text(f, text.replace(inserted, "", 1))
        return True, "父文件被外部改动过：仅撤掉本事务插入的那一行（保留他人改动）", True
    return False, "父文件已被外部改写且无法安全撤行（备份：%s）" % backup, True


def _rollback(journal, receipt):
    """逆序回滚；**每条都按磁盘事实判定**，判不了就如实 partial，不谎报 rolled_back。

    顺序：删除新建 → 备份改名回来 → 父 SKILL.md 还原 → 清理本事务新建的空目录。
    """
    entries = [e for e in (journal or []) if e.get("op") in ("intent", "done")]
    done = {e.get("id") for e in entries if e.get("op") == "done"}
    reports = []
    failed = False
    partial = False
    for e in reversed(entries):
        if e.get("op") != "intent":
            continue
        action = e.get("action")
        rep = {"op": action, "role": e.get("role"),
               "path": e.get("dst") or e.get("file") or e.get("src"),
               "src": e.get("src"), "dst": e.get("dst"), "file": e.get("file"),
               "applied": e.get("id") in done}
        ok, why = True, ""
        try:
            if action == "move":
                src, dst = e.get("src"), e.get("dst")
                hs, hd = os.path.exists(src), os.path.exists(dst)
                if not rep["applied"]:
                    if hs and not hd:
                        why = "intent 未生效（源未动、目标未生成）"
                    elif hd and not hs:
                        _move(dst, src, role=e.get("role"))
                        ok = os.path.exists(src) and not os.path.exists(dst)
                        why = ("按事实搬回：" + ("成功" if ok else "失败")) + "（位置：" + str(dst) + "）"
                    else:
                        ok, partial = False, True
                        why = "源与目标状态不可判定（疑似部分迁移）：src=%s dst=%s" % (src, dst)
                else:
                    if hd and not hs:
                        _move(dst, src, role=e.get("role"))
                        ok = os.path.exists(src) and not os.path.exists(dst)
                        why = "已搬回原位" if ok else "搬回失败（旧内容仍在 %s，可复查）" % dst
                    elif hs and not hd:
                        why = "已是原始状态"
                    elif hs and hd:
                        ok, partial = False, True
                        why = "源与目标同时存在（疑似部分迁移）：%s / %s" % (src, dst)
                    else:
                        ok, partial = False, True
                        why = "源与目标都不存在（旧内容位置未知，备份目录可查）"
            elif action == "mkdir":
                d = e.get("dst")
                backup_dir = "backup-dir" in str(e.get("role") or "")
                if backup_dir and (partial or failed):
                    why = "回滚不完整：保留本事务备份目录作为可复查位置"
                elif os.path.isdir(d) and not os.listdir(d):
                    os.rmdir(d)
                    why = "删除本事务新建的空目录"
                elif os.path.isdir(d):
                    why = "目录非空（可能已存旧内容），保留"
                else:
                    why = "目录不存在"
            elif action == "patch":
                ok, why, p2 = _restore_patched(e)
                partial = partial or p2
            else:
                ok, why = False, "未知回滚项"
        except Exception as ex:  # noqa: BLE001
            ok, why = False, str(ex)[:200]
        rep.update(ok=bool(ok), why=why)
        if not ok:
            failed = True
        reports.append(rep)
    receipt["rollback"] = reports
    receipt["rolled_back"] = bool(reports) and not failed
    receipt["rollback_partial"] = bool(partial or failed)
    actual_backups = [
        e.get("dst") for e in (journal or [])
        if e.get("op") == "intent" and e.get("action") == "mkdir"
        and "backup-dir" in str(e.get("role") or "")
        and e.get("dst") and os.path.isdir(e.get("dst"))
    ]
    existing = {}
    for item in receipt.get("backups") or {}:
        value = receipt["backups"].get(item)
        if isinstance(value, list):
            kept = [p for p in value if p and os.path.exists(p)]
            if kept:
                existing[item] = kept
        elif value and os.path.exists(value):
            existing[item] = value
    if actual_backups:
        existing.setdefault("directories", sorted(set(actual_backups)))
    patch_backups = [
        e.get("backup") for e in (journal or [])
        if e.get("op") == "intent" and e.get("action") == "patch"
        and e.get("backup") and os.path.isfile(e.get("backup"))
    ]
    if patch_backups:
        parent_existing = existing.get("parent")
        if not parent_existing:
            parent_existing = []
        elif isinstance(parent_existing, str):
            parent_existing = [parent_existing]
        else:
            parent_existing = list(parent_existing)
        parent_existing.extend(p for p in patch_backups if p not in parent_existing)
        existing["parent"] = parent_existing
    receipt["backups"] = existing
    receipt["backup_kept"] = bool(existing)
    receipt["rollback_note"] = (
        "按磁盘事实逆序回滚；`applied=false` 的项是操作前登记的 intent（未生效）"
        if reports else "本事务没有需要回滚的动作（失败发生在任何写操作之前）")
    return reports


# ============================================================ 只读恢复报告 / status
def _read_journal_entries(path):
    """Parse durable journal lines. Only an incomplete final write may be ignored."""
    try:
        with io.open(path, encoding="utf-8", errors="replace") as stream:
            raw = stream.read()
    except OSError as exc:
        raise Refuse(5, "journal_unreadable",
                     "事务 journal 无法读取：%s（%s）" % (path, str(exc)[:120]))
    lines = raw.splitlines()
    final_newline = raw.endswith("\n")
    entries, malformed = [], []
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        if index == len(lines) - 1 and not final_newline:
            # The newline is the durable record boundary.  A syntactically complete
            # suffix without it may still be an un-fsynced torn write, so recovery must
            # never promote it into evidence.
            malformed.append(index + 1)
            continue
        try:
            value = json.loads(line)
        except ValueError:
            raise Refuse(5, "journal_corrupt",
                         "事务 journal 中间存在损坏记录，不能安全自动恢复：%s" % path)
        if not isinstance(value, dict):
            raise Refuse(5, "journal_corrupt",
                         "事务 journal 记录不是对象，不能安全自动恢复：%s" % path)
        entries.append(value)
    if not entries:
        raise Refuse(5, "journal_empty",
                     "事务 journal 没有可用记录，不能安全自动恢复：%s" % path)
    return entries, malformed


def _journal_phase(entries):
    phase = None
    for entry in entries:
        if entry.get("op") == "phase" and entry.get("phase"):
            phase = entry["phase"]
    return phase


def _effective_journal_stage(entries, phase):
    """A commit rename window must never be described as validation/staging."""
    facts = _journal_disk_facts(entries)
    moved_on_disk = any(
        fact["dst_exists"] and not fact["src_exists"] for fact in facts)
    if phase == "commit_started":
        return "commit_in_progress"
    if phase in (None, "", "stage", "validate", "prepare") and moved_on_disk:
        return "commit_in_progress"
    return phase


def _journal_disk_facts(entries):
    facts = []
    for entry in entries:
        if entry.get("op") != "intent" or entry.get("action") != "move":
            continue
        src, dst = entry.get("src"), entry.get("dst")
        facts.append({
            "role": entry.get("role"),
            "src": src,
            "dst": dst,
            "src_exists": bool(src and os.path.exists(src)),
            "dst_exists": bool(dst and os.path.exists(dst)),
            "recorded_done": any(
                done.get("op") == "done" and done.get("id") == entry.get("id")
                for done in entries
            ),
        })
    return facts


def _verified_disk_problems(entries):
    """Prove that the verified journal still describes the current disk state."""
    done = {e.get("id") for e in entries if e.get("op") == "done"}
    problems = []
    for entry in entries:
        if entry.get("op") != "intent" or entry.get("action") != "move":
            continue
        jid, dst, role = entry.get("id"), entry.get("dst"), entry.get("role")
        if jid not in done:
            problems.append("move done 记录缺失：%s" % role)
        elif not dst or not os.path.exists(dst):
            problems.append("已完成移动的目标不存在：%s → %s" % (role, dst))
    for entry in entries:
        if entry.get("op") != "intent" or entry.get("action") != "patch":
            continue
        jid, file, role = entry.get("id"), entry.get("file"), entry.get("role")
        if jid not in done:
            problems.append("patch done 记录缺失：%s" % role)
            continue
        if not file or not os.path.isfile(file):
            problems.append("已完成的父文件写入目标不存在：%s" % role)
            continue
        expected = entry.get("after_sha")
        if expected:
            try:
                if _bytes_sha(file) != expected:
                    problems.append("已完成的父文件写入内容已漂移：%s" % role)
            except OSError as exc:
                problems.append("已完成的父文件无法读取：%s（%s）"
                                % (role, str(exc)[:80]))

    snapshots = [e for e in entries if e.get("op") == "verified_snapshot"]
    if not snapshots:
        problems.append("verified_snapshot 缺失，无法证明当前内容和验证时一致")
        return problems
    snapshot = snapshots[-1]
    target = snapshot.get("target")
    expected_target = snapshot.get("target_hashes")
    if not target or not isinstance(expected_target, dict):
        problems.append("verified_snapshot 的仓库目标/哈希声明损坏")
    else:
        diff = tree_diff(expected_target, hash_tree(target))
        if diff:
            problems.append("仓库 verified 快照漂移：%s" % "；".join(diff[:4]))

    deployments = snapshot.get("deploy")
    if not isinstance(deployments, list):
        problems.append("verified_snapshot 的部署声明损坏")
        return problems
    for index, item in enumerate(deployments):
        if not isinstance(item, dict):
            problems.append("verified_snapshot 的部署项损坏：root[%d]" % index)
            continue
        path, pending = item.get("path"), bool(item.get("pending"))
        expected = item.get("hashes")
        if pending:
            continue
        if not path or not isinstance(expected, dict):
            problems.append("verified_snapshot 的部署路径/哈希缺失：root[%d]" % index)
            continue
        diff = tree_diff(expected, hash_tree(path))
        if diff:
            problems.append("部署 verified 快照漂移：root[%d] %s"
                            % (index, "；".join(diff[:4])))
    return problems


def _verified_snapshot_payload(plan, receipt):
    """Content snapshot persisted immediately before the durable verified marker."""
    deployments = []
    for item in receipt.get("deployed") or []:
        path = item.get("path")
        pending = bool(item.get("pending"))
        exists = bool(path and os.path.isdir(path))
        deployments.append({
            "path": path,
            "pending": pending,
            "exists": exists,
            "hashes": hash_tree(path) if exists else {},
        })
    target = plan.get("target")
    return {
        "target": target,
        "target_hashes": hash_tree(target),
        "deploy": deployments,
    }


def _rollback_disk_problems(entries):
    """Read-only prediction of rollback states that cannot safely be automated."""
    problems = []
    move_entries = [
        e for e in entries if e.get("op") == "intent" and e.get("action") == "move"]
    state = {}
    for entry in move_entries:
        for path in (entry.get("src"), entry.get("dst")):
            if path:
                state[_norm(path)] = os.path.exists(path)

    def exists(path):
        return bool(path and state.get(_norm(path), False))

    def set_exists(path, value):
        if path:
            state[_norm(path)] = bool(value)

    # Follow the same reverse order as _rollback, updating a virtual filesystem after
    # each move.  A replace sequence legitimately has target+backup+staging on disk at
    # the same time; judging each intent independently would call that healthy window
    # unrecoverable even though the reverse moves restore it deterministically.
    for entry in reversed(entries):
        if entry.get("op") != "intent":
            continue
        action = entry.get("action")
        if action == "move":
            src, dst, role = entry.get("src"), entry.get("dst"), entry.get("role")
            src_exists = exists(src)
            dst_exists = exists(dst)
            if src_exists == dst_exists:
                problems.append(
                    "move 状态不可判定：%s（src_exists=%s, dst_exists=%s）"
                    % (role, src_exists, dst_exists))
            elif dst_exists and not src_exists:
                set_exists(dst, False)
                set_exists(src, True)
        elif action == "patch":
            file = entry.get("file")
            if not file or not os.path.isfile(file):
                problems.append("待回滚父文件不存在：%s" % (entry.get("role") or "patch"))
                continue
            try:
                current = _bytes_sha(file)
            except OSError as exc:
                problems.append("待回滚父文件无法读取：%s（%s）"
                                % (entry.get("role") or "patch", str(exc)[:80]))
                continue
            before = entry.get("before_sha")
            after = entry.get("after_sha")
            backup = entry.get("backup")
            inserted = entry.get("inserted") or ""
            can_restore_from_backup = (
                backup and os.path.isfile(backup) and (not after or current == after))
            can_remove_single_line = False
            if inserted:
                try:
                    can_remove_single_line = _read_text(file).count(inserted) == 1
                except OSError:
                    pass
            if not ((before and current == before)
                    or can_restore_from_backup or can_remove_single_line):
                problems.append("父文件已被外部改写且无法安全撤行：%s"
                                % (entry.get("role") or "patch"))
    return problems


def _journal_tail(path, n=12):
    try:
        entries, malformed = _read_journal_entries(path)
    except Refuse as exc:
        return {"path": path, "entries": 0, "tail": [], "phase": None,
                "problem": exc.code, "message": exc.message}
    phase = _journal_phase(entries)
    facts = _journal_disk_facts(entries)
    disk_problems = (
        _verified_disk_problems(entries)
        if phase == "verified" else _rollback_disk_problems(entries))
    recovery_action = (
        "roll_forward" if phase == "verified" and not disk_problems
        else "rollback" if phase != "verified" and not disk_problems
        else "manual")
    return {
        "path": path,
        "entries": len(entries),
        "tail": entries[-n:],
        "staging_dirs": sorted({
            e.get("dir") for e in entries if e.get("op") == "staging" and e.get("dir")
        }),
        "phase": phase,
        "effective_stage": _effective_journal_stage(entries, phase),
        "commit_started": any(
            e.get("op") == "phase" and e.get("phase") == "commit_started" for e in entries),
        "disk_facts": facts,
        "disk_problems": disk_problems[:12],
        "recovery_action": recovery_action,
        "auto_recoverable": not disk_problems,
        "ignored_incomplete_tail_lines": malformed,
    }


def _remove_journal_file(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise Refuse(5, "journal_remove_failed",
                     "自动恢复已完成，但无法清理 journal：%s（%s）"
                     % (path, str(exc)[:120]))


def _recover_one_transaction(path, skill_dir, roots, expected_name=None):
    entries, malformed = _read_journal_entries(path)
    if expected_name and str(entries[0].get("name") or "") != expected_name:
        raise Refuse(5, "journal_identity_mismatch",
                     "journal 文件名与该事务声明的技能名不一致，拒绝误恢复：%s" % path,
                     journal=path)
    phase = _journal_phase(entries)
    base = dict(entries[0])
    journal_roots = [
        str(r) for r in (base.get("deploy_roots") or [])
        if r and not _within(str(r), skill_dir)
    ]
    all_roots = []
    seen = {_norm(skill_dir)}
    for root in list(roots or []) + journal_roots:
        if root and _norm(root) not in seen:
            seen.add(_norm(root))
            all_roots.append(os.path.abspath(root))

    if phase == "verified":
        disk_problems = _verified_disk_problems(entries)
        if disk_problems:
            raise Refuse(
                5, "automatic_recovery_disk_mismatch",
                "上次 journal 已到 verified，但当前磁盘不满足 roll-forward 证据：%s"
                % "；".join(disk_problems[:4]),
                journal=path, disk_problems=disk_problems[:12],
                disk_facts=_journal_disk_facts(entries))
        # Verify and its phase record were durably completed, and completed move
        # destinations still exist. Roll forward now only removes bookkeeping.
        rec = {}
        action = "roll_forward"
        rollback = []
    else:
        rec = {}
        _rollback(entries, rec)
        if rec.get("rollback_partial"):
            raise Refuse(5, "automatic_recovery_partial",
                         "上次事务可识别，但自动回滚不能证明完整：%s" % path,
                         journal=path, rollback=rec.get("rollback") or [])
        action = "rollback"
        rollback = rec.get("rollback") or []
    cleanup_errors = _cleanup_staging(rec, entries, all_roots)
    if cleanup_errors:
        raise Refuse(5, "automatic_recovery_cleanup_failed",
                     "上次事务已恢复，但 staging/空备份目录清理失败：%s"
                     % "；".join(cleanup_errors[:4]),
                     journal=path)
    _remove_journal_file(path)
    return {
        "journal": path,
        "action": action,
        "phase": phase,
        "effective_stage": _effective_journal_stage(entries, phase),
        "rollback": rollback,
        "ignored_incomplete_tail_lines": malformed,
        "cleaned": True,
    }


def _recover_pending_transactions(skill_dir, roots, name, held_locks, prefixes=None):
    """Recover stale transactions while the caller holds this name's complete lock set."""
    if not held_locks:
        raise Refuse(5, "recovery_without_locks",
                     "拒绝在未持锁时自动恢复事务")
    jdir = os.path.join(_lock_dir(skill_dir), JOURNAL_DIR)
    if not os.path.isdir(jdir):
        return []
    prefixes = tuple(prefixes or ("%s-" % name,))
    stamp_re = re.compile(r"^\d{8}-\d{6}-\d+(?:-\d+)?\.jsonl$")
    recovered = []
    for filename in sorted(os.listdir(jdir)):
        remainder = next(
            (filename[len(prefix):] for prefix in prefixes if filename.startswith(prefix)),
            None)
        if remainder is None or not stamp_re.fullmatch(remainder):
            continue
        recovered.append(_recover_one_transaction(
            os.path.join(jdir, filename), skill_dir, roots, expected_name=name))
    return recovered


def _recovery_report(skill_dir, roots, name=""):
    """**只读**：报告可自动恢复的残留和必须人工/活锁等待的真实状态。"""
    rep = {"schema": RECOVERY_SCHEMA, "read_only": True, "auto_recover": True,
           "pending_manual": False, "name_filter": name or "",
           "scanned_roots": [], "locks": [], "staging": [], "journals": [], "backups": [],
           "notes": [
               "本报告只读；下一次带同名完整锁集的 import 会自动回滚未验证事务或完成已验证事务",
               "活锁或无法证明已退出的属主继续阻止写入；staging/journal 由持锁恢复流程清理",
               "备份（.import-backup）刻意保留供复查，不算残留故障",
           ]}
    if not skill_dir:
        return rep

    def scan(root, label):
        item = {"root": os.path.abspath(root), "label": label, "exists": os.path.isdir(root),
                "locks": [], "staging": [], "journals": [], "backups": []}
        st = _lock_dir(os.path.abspath(root))
        if os.path.isdir(st):
            for x in sorted(os.listdir(st)):
                p = os.path.join(st, x)
                if x.endswith(".lock"):
                    meta = _read_lock(p)
                    if name and name not in x and name not in str(meta.get("protected", "")):
                        continue
                    rec = {
                        "path": p,
                        "owner": label,
                        "meta": meta,
                        "auto_recoverable": meta.get("alive") is False,
                    }
                    item["locks"].append(rec)
                    rep["locks"].append(rec)
                elif x == JOURNAL_DIR and os.path.isdir(p):
                    for y in sorted(os.listdir(p)):
                        jp = os.path.join(p, y)
                        if name and name not in y:
                            continue
                        report = _journal_tail(jp)
                        rec = {
                            "path": jp,
                            "owner": label,
                            "report": report,
                            "auto_recoverable": (
                                not bool(report.get("problem"))
                                and bool(report.get("auto_recoverable"))),
                        }
                        item["journals"].append(rec)
                        rep["journals"].append(rec)
                elif os.path.isdir(p):
                    if name and name not in x:
                        continue
                    item["staging"].append(p)
                    rep["staging"].append({"path": p, "owner": label})
        bk = os.path.join(os.path.abspath(root), BACKUP_NAME)
        if os.path.isdir(bk):
            for x in sorted(os.listdir(bk)):
                if name and name not in x:
                    continue
                item["backups"].append(os.path.join(bk, x))
                rep["backups"].append({"path": os.path.join(bk, x), "owner": label,
                                       "kept_by_design": True})
        rep["scanned_roots"].append(item)

    scan(skill_dir, "skill-dir")
    seen = {_norm(skill_dir)}
    for r in roots or []:
        if _norm(r) in seen:
            continue
        seen.add(_norm(r))
        scan(r, "deploy-root")
    live_or_unknown = [
        lock for lock in rep["locks"]
        if lock.get("meta", {}).get("alive") is not False
    ]
    bad_journals = [j for j in rep["journals"] if not j.get("auto_recoverable")]
    orphan_staging = [
        s for s in rep["staging"]
        if not any(
            _norm(s.get("path") or "") in {
                _norm(x) for x in (j.get("report", {}).get("staging_dirs") or [])
            }
            for j in rep["journals"]
        )
    ]
    rep["auto_recoverable"] = bool(
        [x for x in rep["locks"] if x.get("auto_recoverable")]
        or [x for x in rep["journals"] if x.get("auto_recoverable")])
    rep["pending_manual"] = bool(live_or_unknown or bad_journals or orphan_staging)
    rep["actions"] = [
        "已退出属主的锁和对应 journal 会在下一次同名 import 中原子接管并自动恢复",
        "若 locks[].meta.alive 为 true/null，先等待活进程或人工核实，恢复流程不会删除活锁",
        "看 journals[].report.effective_stage/disk_facts 可核对提交窗口的真实磁盘状态",
        "备份在 backups[]（.import-backup/…），保留供复查，不自动清",
    ] if rep["pending_manual"] else ["无残留锁/staging/journal（备份若存在属刻意保留）"]
    return rep


def cmd_status(opts):
    """只读入口：报告残留锁/staging/备份/journal 与动作阶段。不写盘、不删东西。"""
    name = opts.get("name") or ""
    skill_dir = os.path.abspath(opts.get("skill_dir") or SKILL_DIR)
    roots, warnings = _resolve_deploy_roots(_merge(opts, deploy=True), "status", allow_empty=True)
    rep = _recovery_report(skill_dir, roots, name=name)
    rec = {"schema": SCHEMA, "rc": 0, "stage": "status", "kind": "status", "name": name,
           "written": False, "effective": False, "available_next_session": False,
           "formal_domain_active": False, "deployed": [], "files_imported": 0,
           "warnings": warnings, "recovery": rep,
           "why": ("存在活锁、损坏 journal 或孤立 staging → 需要等待/人工处理"
                   if rep["pending_manual"] else
                   ("可自动恢复残留：下一次同名 import 会在持锁后处理"
                    if rep["auto_recoverable"] else "无残留锁/staging/journal")),
           "to_take_effect": rep["actions"]}
    rec["effective_status"] = ("recovery_pending_manual" if rep["pending_manual"] else
                               ("recovery_auto_pending" if rep["auto_recoverable"] else "clean"))
    _emit(rec, opts)
    return 0


# ============================================================ 回执
def _receipt_status(plan, receipt):
    kind = plan["kind"]
    deployed = [d for d in receipt.get("deployed") or [] if d.get("hashes_equal")]
    if kind == "tool":
        return "declared_not_available", False, [
            "capability_gap：tool catalogs（tool-capabilities/tool-runtimes/tool-effects）本轮不写",
            "adapter/安装/探活属另一批授权面；本次不宣称工具可用",
        ]
    if kind == "subskill":
        # 语义声明：子技能落 _pending/（不部署成顶层技能、不进路由）；父 SKILL.md 已受控引用。
        # ★ 「通过 parent 按需可达」≠「全局 auto 选中」：available_next_session 恒 false。
        sideways = [d for d in (receipt.get("deployed") or [])
                    if d.get("role") == "subskill" and d.get("hashes_equal")]
        acts = [
            "要让模型自动选中：改写成正式域（需要真实 pack + witness）或并入父域正文",
            "跑 python Tool/scripts/check.py --fast 复核子技能衔接",
        ]
        if sideways:
            acts.insert(0, "部署侧已按需可达：<root>/<parent>/references/imported-subskills/<child>/"
                           "（入口文档 GUIDE.md），父部署 SKILL.md 写相对引用；这仍不是全局自动选中")
        elif receipt.get("deploy_pending"):
            acts.insert(0, "部署侧还没建立（父域未部署到该 root）：pending，不宣称模型可读")
        else:
            acts.insert(0, "本次没给 --deploy-root：只有仓库侧可达，部署面 pending")
        return "pending_subskill", False, acts
    if kind == "crosscutting":
        if deployed:
            return "crosscutting_deployed", True, [
                "横切技能已部署且 hash 一致；它不是客户可见正式域，不计入域数量",
                "分类表 domain-aliases.json#cross_cutting 由人工/单独变更登记（导入器不自动写）",
            ]
        return "crosscutting_staged", False, [
            "已落仓库未部署：加 --deploy-root <skills 根> 或去掉 --no-deploy",
        ]
    # domain
    if receipt.get("formal_domain_active"):
        return "domain_active", True, ["跑 python Tool/scripts/check.py 做全量门禁"]
    acts = ["新域已在仓库且路由可发现，但全局硬编码契约未登记 → formal_domain_active=false"]
    acts += ["待单独一批处理：" + x for x in (receipt.get("registered_pending_contracts") or [])[:5]]
    if not deployed:
        acts.append("deployed 为空：本次没写任何部署根，模型下次会话选不中它")
    return "domain_registered_pending_contracts", False, acts


def _receipt_base(plan):
    return {
        "schema": SCHEMA,
        "kind": plan["kind"],
        "name": plan["name"],
        "dest": plan.get("target") or "",
        "src": plan.get("src") or "",
        "kind_why": plan.get("kind_why") or "",
        "kind_suggestion": plan.get("kind_suggestion"),
        "dry_run": False,
        "want_replace": bool(plan.get("replace")),
        "hits": (plan.get("suggestion_detail") or {}).get("hits"),
        "warnings": list(plan.get("warnings") or []),
        "stage": "plan",
        "files_imported": 0,
        "deployed": [],
        "available_next_session": False,
        "formal_domain_active": False,
        "registered_pending_contracts": [],
        "capability_gap": False,
        "route_visible": None,
        "rollback": [],
        "rolled_back": False,
        "rollback_partial": False,
        "backups": {},
        "backup_kept": False,
        "effective": False,
    }


def _refusal_receipt(opts, r, stage="plan"):
    skill_dir = os.path.abspath(opts.get("skill_dir") or SKILL_DIR)
    rec = {"schema": SCHEMA, "kind": opts.get("kind"), "name": opts.get("name") or "",
           "rc": r.rc, "dry_run": bool(opts.get("dry")), "written": False,
           "effective": False, "stage": stage, "files_imported": 0, "deployed": [],
           "available_next_session": False, "formal_domain_active": False,
           "registered_pending_contracts": [], "capability_gap": False,
           "kind_suggestion": (r.extra.get("suggestion") or {}).get("kind_suggestion"),
           "refusal": r.as_dict(),
           "why": r.message, "to_take_effect": (r.extra.get("next_actions") or []),
           "rollback": [], "rolled_back": False, "rollback_partial": False,
           "backups": {}, "backup_kept": False}
    rec["effective_status"] = (
        "needs_classification" if r.code == "needs_classification"
        else "capability_gap" if r.rc == 3
        else "failed")
    if not rec["to_take_effect"]:
        rec["to_take_effect"] = [
            "按 refusal.code 修正后重跑；本次未产生可宣称的 deployed/effective 结果"]
    roots = list(opts.get("deploy_roots") or [])
    rec["recovery"] = _recovery_report(skill_dir, roots, name=opts.get("name") or "")
    return rec


def _apply_cleanup_failure(rec, failures, message):
    """Preserve the primary failure while attaching cleanup failures as secondary facts."""
    cleanup = {
        "rc": 5,
        "code": "transaction_cleanup_failed",
        "message": message,
        "details": list(failures)[:6],
        "next_actions": [
            "先运行 status 核对 journal、staging 和锁的属主/阶段",
            "等失败属主退出后重跑同一事务，由持锁恢复流程清理或完成回滚",
        ],
    }
    primary = rec.get("refusal")
    if primary:
        primary.setdefault("secondary_failures", []).append(cleanup)
        primary["message"] += "；另有清理失败：" + message
        rec["why"] = primary["message"]
    else:
        rec["refusal"] = cleanup
        rec["why"] = message
    rec["rc"] = 5
    rec["effective"] = False
    rec["available_next_session"] = False


def run_import(opts, faults=None):
    """完整事务：plan → 多资源锁 → journal → stage → validate → commit/父引用 → deploy → verify。"""
    faults = faults or {}
    try:
        plan = plan_import(opts)
    except Refuse as r:
        return _refusal_receipt(opts, r)
    rec = _receipt_base(plan)
    rec["rc"] = 0
    rec["written"] = False
    if plan["kind"] == "tool":
        return _run_tool(plan, rec, dry=opts.get("dry"))

    if opts["dry"]:
        rec.update({"dry_run": True, "stage": "plan",
                    "why": "dry-run：什么都没写盘（不建 staging、不备份、不部署）",
                    "effective_status": "dry_run",
                    "to_take_effect": ["去掉 --dry-run 重跑同一条命令"]})
        rec["plan"] = {k: plan[k] for k in ("kind", "name", "target", "src_files",
                                            "deploy_roots", "pack", "parent", "replace_needed")}
        rec["recovery"] = _recovery_report(plan["skill_dir"], plan.get("deploy_roots") or [],
                                           name=plan["name"])
        return rec

    skill_dir = plan["skill_dir"]
    roots = [skill_dir] + list(plan.get("deploy_roots") or [])
    journal = None
    locks = []
    keep_journal = False
    defer_cleanup = False
    cleanup_failures = []
    try:
        recovery_prefixes = ("%s-" % plan["name"], "deploy-%s-" % plan["name"])
        lock_specs = _recovery_lock_specs(
            skill_dir, _lock_specs(plan), plan["name"], recovery_prefixes)
        locks = _acquire_locks(lock_specs)
        recovered = _recover_pending_transactions(
            skill_dir, plan.get("deploy_roots") or [], plan["name"], locks,
            prefixes=recovery_prefixes)
        if recovered:
            rec["auto_recovered"] = recovered
        if not plan.get("replace"):
            # Preflight every destination after stale recovery, before creating a
            # journal or staging tree.  The repository target and deployment roots
            # can exist independently; checking only the repository would overwrite
            # a same-named user skill already installed in an agent root.
            targets = [plan["target"]]
            for root in plan.get("deploy_roots") or []:
                if plan["kind"] == "subskill":
                    parent = (plan.get("parent") or {}).get("domain")
                    if parent:
                        targets.append(os.path.join(
                            root, parent, "references", "imported-subskills", plan["name"]))
                else:
                    targets.append(os.path.join(root, plan["name"]))
            occupied = [path for path in targets if os.path.lexists(path)]
            if occupied:
                raise Refuse(
                    4, "target_exists",
                    "导入目标已存在；要覆盖必须显式 --replace（不会直接替换用户现有技能）",
                    targets=[_redact_path(path) for path in occupied],
                    hint="核对现有目标内容后，再决定是否传 --replace 保留备份并替换",
                )
        journal = Journal(os.path.join(_lock_dir(skill_dir), JOURNAL_DIR,
                                      "%s-%s.jsonl" % (plan["name"], _ts())),
                          base={"name": plan["name"], "kind": plan["kind"],
                                "skill_dir": skill_dir,
                                "deploy_roots": list(plan.get("deploy_roots") or [])})
        rec["journal"] = journal.path
        rec["locks_held"] = list(locks)
        # ---- stage ----
        _jrec(journal, "phase", phase="stage")
        st = _stage(plan, journal, faults)
        rec["stage"] = "stage"
        rec["staging_dirs"] = [st["staging"]]
        rec["pack_injected"] = st["pack_injected"]
        # ---- validate ----
        if plan["kind"] == "domain":
            rec["validation"] = validate_pack(plan, st["staging"], skill_dir)
        elif plan["kind"] == "subskill":
            rec["validation"] = {"parent": plan["parent"]["domain"],
                                 "anchored": True, "note": "父域真实存在 + 锚点唯一",
                                 "repo_ref": plan["parent"]["repo_ref"]}
        else:
            rec["validation"] = {"crosscutting": plan["name"] in cross_cutting_names(),
                                 "note": "横切技能不需要 pack"}
        _fault(faults, "validate")
        _jrec(journal, "phase", phase="validate")
        rec["stage"] = "validate"
        # ---- commit ----
        _jrec(journal, "phase", phase="prepare")
        _jrec(journal, "phase", phase="commit_started")
        rec["commit_started"] = True
        cm = _commit(plan, st["staging"], skill_dir, journal, faults)
        _jrec(journal, "phase", phase="commit")
        rec["stage"] = "commit"
        rec["committed"] = True
        rec["backups"]["repo"] = cm["backup"]
        rec["files_imported"] = len(hash_tree(plan["target"]))
        # ---- 父引用（子技能，仓库侧）----
        if plan["kind"] == "subskill":
            backup_dir = cm["backup"] or os.path.join(
                skill_dir, BACKUP_NAME, "%s-%s" % (plan["name"], _ts()))
            _jrec(journal, "phase", phase="parent")
            rec["parent_patch"] = _patch_parent(plan, journal, faults, backup_dir) or {}
            if rec["parent_patch"].get("changed"):
                rec["backups"]["parent"] = rec["parent_patch"].get("backup")
        # ---- deploy（逐 root；每个 root 本地同卷备份）----
        _jrec(journal, "phase", phase="deploy")
        for i, root in enumerate(plan.get("deploy_roots") or []):
            if plan["kind"] == "subskill":
                d = _deploy_subskill(plan, root, i, plan["target"], journal, faults)
                entry = {"root": d["root"], "path": d.get("path"), "role": "subskill",
                         "parent": d.get("parent"), "files": d.get("files", 0),
                         "hashes_equal": None, "pending": bool(d.get("pending")),
                         "backup": d.get("backup"), "entry": d.get("entry"),
                         "why": d.get("why") or ""}
                if d.get("deployed"):
                    entry["hashes_equal"] = True
                    rec["backups"].setdefault("deploy", []).append(d.get("backup"))
                elif d.get("pending"):
                    rec["deploy_pending"] = True
                rec["deployed"].append(entry)
            else:
                d = _deploy_one(plan, root, i, plan["target"], cm["backup"], journal, faults)
                rec["deployed"].append({"root": d["root"], "path": d["path"], "files": d["files"],
                                        "hashes_equal": False, "backup": d["backup"]})
                rec["backups"].setdefault("deploy", []).append(d["backup"])
            rec["stage"] = "deploy"
            _fault(faults, "deploy.between.%d" % i)
        # ---- verify ----
        _jrec(journal, "phase", phase="verify")
        rec["stage"] = "verify"
        v = _verify(plan, rec, skill_dir, faults)
        rec["verify"] = v
        rec["route_visible"] = v.get("route_visible")
        rec["witness_ran"] = False
        rec["deployed"] = v["deploy"]
        rec["entry_reachable"] = v.get("entry_reachable")
        if plan["kind"] == "domain":
            rec["registered_pending_contracts"] = _global_domain_contracts(
                plan["name"], skill_dir)
            rec["capability_gap"] = bool(rec["registered_pending_contracts"])
            rec["formal_domain_active"] = bool(
                v.get("route_visible") and rec["deployed"]
                and all(d["hashes_equal"] for d in rec["deployed"])
                and not rec["registered_pending_contracts"])
        _jrec(journal, "verified_snapshot", **_verified_snapshot_payload(plan, rec))
        _jrec(journal, "phase", phase="verified")
        _fault(faults, "verify.after")
        rec["written"] = True
        rec["stage"] = "receipt"
    except Refuse as r:
        rec["rc"] = r.rc
        rec["refusal"] = r.as_dict()
        rec["stage"] = r.extra.get("stage") or rec.get("stage") or "plan"
        rec["why"] = r.message
        if (r.code == "journal_persist_failed" and rec.get("commit_started")):
            # Once commit has started, a journal failure leaves durability unknown.
            # Do not launch further destructive renames.  Preserve the durable prefix
            # for the next lock-holding retry to restore or roll forward from disk facts.
            defer_cleanup = True
            keep_journal = True
            rec["recovery_required"] = True
            rec["journal_kept"] = journal.path if journal else ""
            rec["refusal"]["next_actions"] = [
                "等当前进程退出后重跑同一导入；下一次持锁会先按 journal/磁盘事实回滚或拒绝不确定状态",
                "先跑 status 核对 effective_stage、disk_facts 与 pending_manual",
            ]
        else:
            _rollback(journal, rec)
            if rec.get("rollback_partial"):
                keep_journal = True
                rec["journal_kept"] = (journal.path if journal else "")
        rec["_staging_roots"] = roots
    except Exception as e:  # noqa: BLE001
        rec["rc"] = 5
        rec["stage"] = rec.get("stage") or "plan"
        rec["why"] = "导入中断：%s" % str(e)[:200]
        rec["refusal"] = {"rc": 5, "code": "interrupted", "message": str(e)[:200]}
        _rollback(journal, rec)
        if rec.get("rollback_partial"):
            keep_journal = True
            rec["journal_kept"] = (journal.path if journal else "")
    finally:
        if not defer_cleanup:
            cleanup_failures.extend(_cleanup_staging(rec, journal, roots))
        if journal is not None:
            try:
                journal.close(remove=not keep_journal and not cleanup_failures)
            except Refuse as exc:
                cleanup_failures.append(exc.message)
                keep_journal = True
        release_failures = _release_locks(locks)
        cleanup_failures.extend(release_failures)
        rec.pop("committed", None)
        rec.pop("commit_started", None)
        rec.pop("staging_dirs", None)
    if cleanup_failures:
        _apply_cleanup_failure(
            rec, cleanup_failures,
            "事务主体已结束，但锁/journal/staging 清理失败；不得当作已收尾")
    rec["recovery"] = _recovery_report(skill_dir, plan.get("deploy_roots") or [],
                                       name=plan["name"])
    rec.pop("journal", None)
    _finish(rec, plan)
    return rec


def _run_tool(plan, rec, dry=False):
    """tool 模式：只 validate manifest，报 staged/not_available，不动 catalogs。"""
    raw = plan["manifest"]
    missing = [k for k in ("id",) if not str(raw.get(k) or plan["name"]).strip()]
    declared = sorted(raw)
    try:
        tc = _module(os.path.join(SCRIPTS, "tool-contract-check.py"), "seep_tool_contract_for_import")
        cat = tc.Catalogs(ROOT)
        registered = cat.tool_registered(plan["name"])
        catalogs_readable = True
    except Exception:  # noqa: BLE001
        registered, catalogs_readable = [], False
    rec.update({
        "rc": 3 if not missing else 4,
        "stage": "validate",
        "tool_id": plan["name"],
        "manifest_path": plan["manifest_path"],
        "manifest_fields": declared,
        "declared": True,
        "registered_in_catalogs": registered,
        "catalogs_readable": catalogs_readable,
        "catalogs_written": False,
        "staged": False,
        "not_available": True,
        "capability_gap": True,
        "formal_domain_active": False,
        "available_next_session": False,
        "effective": False,
        "why": ("tool 模式只声明：manifest 结构可读，但工具注册表/适配器/安装不在本次事务授权内；"
                "declared ≠ available"),
        "to_take_effect": [
            "capability_gap 待 adapter：tool-capabilities.json / tool-runtimes.json / tool-effects.json 登记属另一批",
            "安装/探活/上线需独立授权（tool-acquire.py / setup 面），本脚本不下载不执行",
            "补齐登记后跑 python Tool/scripts/tool-contract-check.py --json 复核",
        ],
    })
    if missing:
        rec["refusal"] = {"rc": 4, "code": "tool_manifest_incomplete",
                          "message": "manifest 缺字段：%s" % ",".join(missing)}
    rec["dry_run"] = bool(dry)
    rec["effective_status"] = "declared_not_available"
    rec.setdefault("available_next_session_note",
                   "工具未登记/未安装：下次会话不会有它（declared ≠ available）")
    rec["deployed"] = rec.get("deployed") or []
    rec["files_imported"] = 0
    rec["recovery"] = _recovery_report(plan["skill_dir"], [], name=plan["name"])
    return rec


def _sync_backup_receipt(rec):
    # backup_kept is a disk fact even on success.  A successful replace must report
    # its retained backup, while paths that were rolled back or already vanished do not.
    existing = {}
    for label, value in (rec.get("backups") or {}).items():
        if isinstance(value, list):
            kept = [p for p in value if p and os.path.exists(p)]
            if kept:
                existing[label] = kept
        elif value and os.path.exists(value):
            existing[label] = value
    rec["backups"] = existing
    rec["backup_kept"] = bool(existing)


def _finish(rec, plan):
    _sync_backup_receipt(rec)
    if int(rec.get("rc") or 0) != 0:
        refusal = rec.get("refusal") or {}
        status = (
            "rollback_partial" if rec.get("rollback_partial")
            else "verified_cleanup_pending"
            if rec.get("verify") and refusal.get("code") == "transaction_cleanup_failed"
            else "failed")
        rec["effective_status"] = status
        rec["effective"] = False
        rec["available_next_session"] = False
        rec["formal_domain_active"] = False
        wrote_on_disk = bool(
            rec.get("written") or rec.get("recovery_required")
            or rec.get("rollback_partial"))
        rec["written"] = wrote_on_disk
        if not wrote_on_disk:
            rec["files_imported"] = 0
            rec["deployed"] = []
        elif os.path.isdir(plan.get("target") or ""):
            rec["files_imported"] = len(hash_tree(plan["target"]))
        elif not rec.get("verify"):
            # A partially committed transaction is described through recovery/rollback;
            # only a completed in-memory verify may retain verified deployment entries.
            rec["deployed"] = []
        actions = list(refusal.get("next_actions") or [])
        if not actions:
            actions = ["按 refusal.code 修正后重跑；本次没有可宣称的 staged/deployed 结果"]
        rec["to_take_effect"] = actions
        rec.setdefault("backups", {})
        # Never let a failed target_exists or rollback inherit a success-stage label.
        return
    status, effective, acts = _receipt_status(plan, rec)
    rec["effective_status"] = status
    rec["effective"] = effective
    rec.setdefault("to_take_effect", acts)
    # ★ 两个字段必须分开报（不把「复制成功」说成「能选」）：
    #   available_next_session = 文件真的在部署根、逐文件 hash 与仓库一致（pi 下次会话会加载它）
    #   formal_domain_active    = 还要求路由可发现 + 全局硬编码契约已登记（= 客户可见正式域）
    deployed_ok = bool(rec.get("deployed")) and all(
        d.get("hashes_equal") for d in rec["deployed"] if not d.get("pending"))
    rec["available_next_session"] = bool(deployed_ok and plan["kind"] in ("domain", "crosscutting"))
    rec["available_next_session_note"] = (
        "已部署且 hash 一致：下次会话会被加载（子技能不部署成顶层技能，故恒 false）"
        if rec["available_next_session"] else
        "未部署/未通过 hash 核验：下次会话选不中它")
    rec.setdefault("why", {
        "domain_active": "已部署且 hash 一致、路由可发现、全局契约已登记",
        "domain_registered_pending_contracts": "新域已落位并路由可发现，但全局硬编码契约未登记 → 不算生效",
        "crosscutting_deployed": "横切技能已部署且 hash 一致（不是正式域）",
        "crosscutting_staged": "横切技能只在仓库，未部署",
        "pending_subskill": "子技能在 _pending/，父 SKILL.md 已按技能目录相对路径引用；不部署成顶层技能、不自动选中",
        "declared_not_available": "工具只声明，未登记未安装",
        "dry_run": "dry-run，零写盘",
    }.get(status, ""))
    rec.setdefault("files_imported", 0)
    rec.setdefault("deployed", [])


# ============================================================ 子命令
def cmd_plan(opts):
    rec = run_import(_merge(opts, dry=True))
    _emit(rec, opts)
    return rec["rc"]


def cmd_stage(opts):
    """只 stage/validate：不部署，所以强制 deploy=False（避免无谓的部署根要求）。"""
    opts = _merge(opts, deploy=False)
    try:
        plan = plan_import(opts)
    except Refuse as r:
        rec = _refusal_receipt(opts, r)
        _emit(rec, opts)
        return rec["rc"]
    if plan["kind"] == "tool":
        return cmd_import(opts)
    locks = []
    journal = None
    st = None
    close_failures = []
    rec = {"schema": SCHEMA, "rc": 5, "stage": "plan", "kind": plan["kind"],
           "name": plan["name"], "written": False, "effective": False,
           "files_imported": 0, "why": "stage 未完成", "to_take_effect": []}
    try:
        recovery_prefixes = ("%s-" % plan["name"], "deploy-%s-" % plan["name"])
        lock_specs = _recovery_lock_specs(
            plan["skill_dir"], _lock_specs(plan), plan["name"], recovery_prefixes)
        locks = _acquire_locks(lock_specs)
        recovered = _recover_pending_transactions(
            plan["skill_dir"], [], plan["name"], locks,
            prefixes=recovery_prefixes)
        if recovered:
            rec["auto_recovered"] = recovered
        journal = Journal(os.path.join(_lock_dir(plan["skill_dir"]), JOURNAL_DIR,
                                      "%s-%s.jsonl" % (plan["name"], _ts())),
                          base={"name": plan["name"], "kind": plan["kind"],
                                "skill_dir": plan["skill_dir"]})
        _jrec(journal, "phase", phase="stage")
        st = _stage(plan, journal, {})
        rec = {"schema": SCHEMA, "rc": 0, "stage": "stage", "kind": plan["kind"],
               "name": plan["name"], "staging": st["staging"], "written": True,
               "effective": False, "files_imported": st["staged_files"],
               "why": "只 stage，未 commit/deploy（诊断用；完整事务用 import）",
               "to_take_effect": ["commit 属 import 子命令"]}
        if plan["kind"] == "domain":
            rec["validation"] = validate_pack(plan, st["staging"], plan["skill_dir"])
    except Refuse as r:
        failed_stage = "validate" if st is not None else "stage"
        rec = _refusal_receipt(opts, r, stage=failed_stage)
        if st is not None and os.path.isdir(st["staging"]):
            # Stage diagnostics are deliberately retained on validation failure so the
            # next import can inspect/recover them.  The receipt must report that disk
            # fact instead of claiming the command wrote nothing.
            rec["written"] = True
            rec["staging"] = st["staging"]
            rec["staged_files"] = st["staged_files"]
            rec["files_imported"] = st["staged_files"]
        else:
            rec["written"] = False
    finally:
        if journal is not None:
            try:
                # Stage is deliberately diagnostic: its durable journal/staging evidence
                # remains visible after success and can be recovered by the next import.
                journal.close(remove=False)
            except Refuse as exc:
                close_failures.append(exc.message)
        release_failures = _release_locks(locks)
        close_failures.extend(release_failures)
    if close_failures:
        _apply_cleanup_failure(
            rec, close_failures, "stage 已结束，但 journal 关闭或锁清理失败")
    rec["recovery"] = _recovery_report(plan["skill_dir"], [], name=plan["name"])
    if rec["rc"] == 0:
        rec["effective_status"] = "staged_diagnostic"
    _emit(rec, opts)
    return rec["rc"]


def cmd_deploy(opts):
    """只把**已存在的仓库技能**部署到显式 roots（不碰仓库；失败按事实回滚 roots）。"""
    name = opts["name"]
    ok, why = _valid_name(name)
    if not ok:
        rec = {"schema": SCHEMA, "rc": 4, "stage": "plan", "written": False,
               "effective": False, "why": why}
        _emit(rec, opts)
        return 4
    src = os.path.join(opts["skill_dir"], name)
    if not os.path.isdir(src):
        rec = {"schema": SCHEMA, "rc": 4, "stage": "plan", "written": False,
               "effective": False, "why": "仓库里没有该技能：%s" % src}
        _emit(rec, opts)
        return 4
    try:
        roots, warnings = _resolve_deploy_roots(_merge(opts, deploy=True), "deploy", src_dir=src,
                                               allow_empty=False)
    except Refuse as r:
        rec = _refusal_receipt(opts, r)
        _emit(rec, opts)
        return rec["rc"]
    plan = {"kind": "crosscutting", "name": name, "target": src, "skill_dir": opts["skill_dir"],
            "deploy_roots": roots, "parent": None, "warnings": list(warnings)}
    journal = None
    locks = []
    rec = {"schema": SCHEMA, "rc": 0, "kind": "deploy", "name": name, "stage": "deploy",
           "written": False, "effective": False, "deployed": [], "files_imported": 0,
           "formal_domain_active": False, "registered_pending_contracts": [],
           "capability_gap": False, "available_next_session": False, "rollback": [],
           "rolled_back": False, "rollback_partial": False, "backups": {},
           "backup_kept": False, "warnings": warnings}
    keep_journal = False
    defer_cleanup = False
    cleanup_failures = []
    try:
        recovery_prefixes = ("%s-" % name, "deploy-%s-" % name)
        lock_specs = _recovery_lock_specs(
            opts["skill_dir"], _lock_specs(plan), name, recovery_prefixes)
        locks = _acquire_locks(lock_specs)
        recovered = _recover_pending_transactions(
            opts["skill_dir"], roots, name, locks, prefixes=recovery_prefixes)
        if recovered:
            rec["auto_recovered"] = recovered
        if not opts.get("replace"):
            occupied = [os.path.join(root, name) for root in roots
                        if os.path.lexists(os.path.join(root, name))]
            if occupied:
                raise Refuse(
                    4, "target_exists",
                    "部署目标已存在；要覆盖必须显式 --replace（不会直接替换用户现有技能）",
                    targets=[_redact_path(path) for path in occupied],
                    hint="核对现有部署内容后，再决定是否传 --replace 保留备份并替换",
                )
        journal = Journal(os.path.join(_lock_dir(opts["skill_dir"]), JOURNAL_DIR,
                                      "deploy-%s-%s.jsonl" % (name, _ts())),
                          base={"name": name, "kind": "deploy",
                                "skill_dir": opts["skill_dir"],
                                "deploy_roots": list(roots)})
        rec["journal"] = journal.path
        repo_hashes = hash_tree(src)
        _jrec(journal, "phase", phase="deploy_started")
        _jrec(journal, "phase", phase="prepare")
        for i, root in enumerate(roots):
            _jrec(journal, "phase", phase="commit_started", root=root)
            rec["commit_started"] = True
            d = _deploy_one(plan, root, i, src, None, journal, {})
            same = hash_tree(d["path"]) == repo_hashes
            rec["deployed"].append({"root": d["root"], "path": d["path"], "files": d["files"],
                                    "hashes_equal": same, "backup": d["backup"]})
            rec["backups"].setdefault("deploy", []).append(d["backup"])
            _fault({}, "deploy.between.%d" % i)
        _jrec(journal, "phase", phase="deploy_done")
        rec["stage"] = "verify"
        _jrec(journal, "phase", phase="verify")
        if not all(d["hashes_equal"] for d in rec["deployed"]):
            raise Refuse(5, "verify_hash_drift", "部署与仓库 hash 不一致")
        _jrec(journal, "verified_snapshot", **_verified_snapshot_payload(plan, rec))
        _jrec(journal, "phase", phase="verified")
        rec.update({"written": True, "effective": True, "effective_status": "deployed",
                    "available_next_session": True,
                    "backup_kept": bool(
                        any(p and os.path.exists(p)
                            for p in (rec.get("backups") or {}).get("deploy", []))),
                    "why": "按显式 deploy-root 部署，逐文件 hash 与仓库一致（每个 root 本地同卷备份）",
                    "to_take_effect": ["下次会话验证是否出现在技能列表"]})
    except Refuse as r:
        rec["rc"] = r.rc
        rec["refusal"] = r.as_dict()
        rec["stage"] = rec.get("stage") or "deploy"
        rec["why"] = r.message
        rec["effective_status"] = "failed"
        rec["deployed"] = []
        rec["files_imported"] = 0
        rec["available_next_session"] = False
        if r.code == "journal_persist_failed" and rec.get("commit_started"):
            defer_cleanup = True
            keep_journal = True
            rec["recovery_required"] = True
            rec["journal_kept"] = journal.path if journal else ""
            # The durable prefix proves that a destructive deploy window may already
            # have opened.  "Unknown" is safer than claiming the disk was untouched.
            rec["written"] = True
            rec["to_take_effect"] = [
                "等当前进程退出后重跑同一 deploy；下一次持锁会先按 journal/磁盘事实恢复",
                "先跑 status 核对 effective_stage、disk_facts 与 pending_manual",
            ]
        else:
            _rollback(journal, rec)
            rec["written"] = bool(rec.get("rollback_partial"))
            keep_journal = bool(rec.get("rollback_partial"))
            rec["to_take_effect"] = [
                "按 refusal.code 修正后重跑；失败目标不得计为已部署"]
    except Exception as e:  # noqa: BLE001
        rec["rc"] = 5
        rec["why"] = "部署中断：%s" % str(e)[:200]
        rec["effective_status"] = "failed"
        rec["deployed"] = []
        rec["files_imported"] = 0
        rec["available_next_session"] = False
        _rollback(journal, rec)
        rec["written"] = bool(rec.get("rollback_partial"))
        keep_journal = bool(rec.get("rollback_partial"))
    finally:
        if not defer_cleanup:
            cleanup_failures.extend(
                _cleanup_staging(rec, journal, [opts["skill_dir"]] + list(roots)))
        if journal is not None:
            try:
                journal.close(remove=not keep_journal and not cleanup_failures)
            except Refuse as exc:
                cleanup_failures.append(exc.message)
                keep_journal = True
        cleanup_failures.extend(_release_locks(locks))
        rec.pop("journal", None)
        rec.pop("commit_started", None)
    if cleanup_failures:
        _apply_cleanup_failure(
            rec, cleanup_failures, "部署主体已结束，但锁/journal/staging 清理失败")
        rec["effective_status"] = "failed"
    _sync_backup_receipt(rec)
    rec["recovery"] = _recovery_report(opts["skill_dir"], roots, name=name)
    _emit(rec, opts)
    return rec["rc"]


def cmd_verify(opts):
    """只读核验一个已落位技能：按 kind 分别判（subskill 不按顶层部署比较）。不写盘。"""
    name = opts["name"]
    skill_dir = os.path.abspath(opts.get("skill_dir") or SKILL_DIR)
    packs, _ = scan_packs(skill_dir)
    kind = "domain" if any(p["id"] == name for p in packs) else ""
    target = os.path.join(skill_dir, name)
    parent = None
    if kind == "domain" and not os.path.isdir(target):
        kind = ""
    if not kind:
        child = os.path.join(skill_dir, "_pending", name)
        if os.path.isdir(child):
            kind, target = "subskill", child
            linked, _dangling = _repo_parent_entries(skill_dir, name)
            parent = linked[0] if linked else None
        elif os.path.isdir(target):
            kind = "crosscutting"
    if not kind:
        rec = {"schema": SCHEMA, "rc": 4, "stage": "verify", "name": name,
               "why": "找不到该技能：%s/%s 或 _pending/%s" % (skill_dir, name, name),
               "effective": False, "written": False}
        _emit(rec, opts)
        return 4
    try:
        roots, warnings = _resolve_deploy_roots(_merge(opts, deploy=True), "verify",
                                               allow_empty=True)
    except Refuse as r:
        rec = _refusal_receipt(opts, r, stage="verify")
        _emit(rec, opts)
        return rec["rc"]
    rec = {"schema": SCHEMA, "rc": 0, "stage": "verify", "kind": kind, "name": name,
           "dest": target, "written": False, "effective": False, "deployed": [],
           "files_imported": len(hash_tree(target)),
           "formal_domain_active": False, "registered_pending_contracts": [],
           "capability_gap": False, "available_next_session": False, "rollback": [],
           "warnings": list(warnings), "verify_scope": "repo+deploy" if roots else "repo_only",
           "why": "", "to_take_effect": []}
    if not roots and kind != "subskill":
        rec.update({"rc": 4, "effective_status": "verify_failed",
                    "refusal": {"rc": 4, "code": "deploy_root_required",
                                "message": "自定义 --skill-dir 且未给 --deploy-root："
                                           "不兜底真实用户根，也不假装核过部署面"},
                    "why": "未给 --deploy-root：只核了仓库侧（scope=repo_only），部署面未核验",
                    "to_take_effect": ["显式给 --deploy-root <skills 根> 后重跑 verify"]})
        rec["recovery"] = _recovery_report(skill_dir, [], name=name)
        _emit(rec, opts)
        return rec["rc"]
    route_mod = _route()
    rcheck = route_mod.check(skill_dir)
    ours = [p for p in (rcheck.get("problems") or []) if name in p]
    rec["route_visible"] = name in {row[1] for row in (rcheck.get("rows") or [])}
    rec["route_check"] = {"problems": len(rcheck.get("problems") or []), "about_this": ours}
    route_self_miss = False
    if kind == "domain":
        try:
            pack_obj = _load_json(os.path.join(target, "pack.json"))
        except Exception:  # noqa: BLE001
            pack_obj = {}
        l1 = str(pack_obj.get("l1") or "")
        hits = route_mod.resolve(l1, skill_dir) if l1 else []
        rec["route_resolve"] = [{"pack": h["pack"], "label": h["label"]} for h in hits[:3]]
        rec["route_hit_self"] = any(h["pack"] == name for h in hits)
        route_self_miss = not rec["route_hit_self"]

    # ---- manifest 漂移（含"多出来的文件"，不只缺/改）----
    mf_path = os.path.join(target, MANIFEST_NAME)
    drift_all = []
    if os.path.isfile(mf_path):
        try:
            manifest = _load_json(mf_path)
        except Exception:  # noqa: BLE001
            manifest = {}
            drift_all.append("manifest 读不了（不是合法 JSON）")
        drift_all.extend(_validate_repo_manifest(manifest, name, kind))
        now = hash_tree(target)
        want = dict(manifest.get("files") or {})
        for rel in sorted(want):
            if rel == MANIFEST_NAME:
                continue
            if rel not in now:
                drift_all.append("缺 %s" % rel)
            elif now[rel] != want[rel]:
                drift_all.append("漂移 %s" % rel)
        for rel in sorted(set(now) - set(want) - {MANIFEST_NAME}):
            drift_all.append("多 %s（不在 manifest）" % rel)

    if kind == "subskill":
        linked, dangling = _repo_parent_entries(skill_dir, name)
        ok_domains = [d for d in linked if not any(x["domain"] == d for x in dangling)]
        rec["repo_parent_entries"] = {"linked": ok_domains, "dangling": dangling,
                                      "all_linked": linked}
        rec["parent"] = parent
        rec["entry_reachable"] = bool(ok_domains)
        dep = []
        for i, root in enumerate(roots):
            for dom in (ok_domains or [None]):
                d = _verify_subskill_deploy(name, skill_dir, root, i, parent=dom)
                d["domain"] = dom
                dep.append(d)
        rec["deployed"] = dep
        drift_sub = [d for d in dep if d.get("status") == "drift"]
        wired = [d for d in dep if d.get("status") == "ok"]
        rec["deploy_reachable"] = bool(wired)
        if not ok_domains:
            rec.update({"rc": 5, "effective_status": "verify_failed",
                        "why": "子技能在 _pending/ 但没有任何域 SKILL.md 用可解析的相对路径引用它"
                               "（模型读不到内容）",
                        "to_take_effect": ["用 import --kind subskill --parent <域> 重跑，或手工补 "
                                          "`../_pending/%s/SKILL.md` 一行" % name]})
        elif drift_sub or drift_all:
            rec.update({"rc": 5, "effective_status": "verify_failed",
                        "why": "核验不通过：%s" % "；".join(
                            drift_all[:4] + [d.get("why", "") for d in drift_sub][:3])})
        else:
            rec["effective_status"] = "pending_subskill"
            rec["why"] = ("子技能在 _pending/，父 SKILL.md（%s）引用可按技能目录解析；"
                          "部署侧%s——仍不会被全局自动选中"
                          % (", ".join(ok_domains) or "-",
                             "按需可达（%d 个 root）" % len(wired) if wired
                             else "尚未建立（pending）"))
            rec["to_take_effect"] = [
                "子技能不部署成顶层技能：不走自动选中",
                "要给模型自动选中：改写成正式域或并入父域正文",
            ]
        rec["effective"] = False
        rec["available_next_session"] = False
        rec["recovery"] = _recovery_report(skill_dir, roots, name=name)
        _emit(rec, opts)
        return rec["rc"]

    # ---- domain / crosscutting ----
    repo_hashes = hash_tree(target)
    drift_deploy = []
    for root in roots:
        path = os.path.join(root, name)
        other = hash_tree(path)
        same = other == repo_hashes
        rec["deployed"].append({"root": root, "path": path, "files": len(other),
                                "hashes_equal": same,
                                "diff": tree_diff(repo_hashes, other)[:5]})
        if not same:
            drift_deploy.append(path)
    if kind == "domain":
        rec["registered_pending_contracts"] = _global_domain_contracts(name, skill_dir)
        rec["formal_domain_active"] = bool(
            rec["route_visible"] and rec["deployed"]
            and all(d["hashes_equal"] for d in rec["deployed"])
            and not rec["registered_pending_contracts"])
        rec["capability_gap"] = bool(rec["registered_pending_contracts"])
    deployed_ok = bool(rec["deployed"]) and all(d["hashes_equal"] for d in rec["deployed"])
    if ours or drift_deploy or drift_all or route_self_miss:
        rec["rc"] = 5
        bad_root = next((d for d in rec["deployed"] if not d["hashes_equal"]), None)
        rec["why"] = "核验不通过：%s" % (
            ("pack.l1 未命中自身路由"
             if route_self_miss and not (ours or drift_deploy or drift_all)
             else "；".join(ours[:3] + drift_all[:3])) or
            "部署 hash 漂移（%s：%s）" % (bad_root["path"] if bad_root else "?",
                                       "；".join((bad_root or {}).get("diff") or []) or "?"))
        rec["effective_status"] = "verify_failed"
        if route_self_miss:
            rec["refusal"] = {
                "rc": 5,
                "code": "route_self_miss",
                "message": "domain pack.l1 没有命中该域自己的路由",
            }
            rec["to_take_effect"] = ["修正 pack.l1 或 routes[].must，再重跑 verify"]
        else:
            rec["to_take_effect"] = [
                "修好漂移后重跑 verify；部署面请用 import --replace 重建"
            ]
        rec["recovery"] = _recovery_report(skill_dir, roots, name=name)
        _emit(rec, opts)
        return rec["rc"]
    if kind == "domain":
        status = "domain_active" if rec["formal_domain_active"] else \
            "domain_registered_pending_contracts"
    elif deployed_ok:
        status = "crosscutting_deployed"
    else:
        status = "crosscutting_staged"
    rec["effective_status"] = status
    # 「别把复制成功说成能选」：effective 只表达**这个入口现在可用**，
    # 正式域还额外要求 formal_domain_active（全局契约已登记），两者分开报。
    rec["effective"] = bool(status in ("domain_active", "crosscutting_deployed"))
    rec["capability_gap"] = bool(rec["registered_pending_contracts"])
    rec["available_next_session"] = bool(deployed_ok and kind != "subskill")
    if status == "domain_active":
        rec["why"] = "manifest/hash/路由/部署逐项核验通过，且全局契约已登记"
    elif status == "domain_registered_pending_contracts":
        rec["why"] = "manifest/hash/路由/部署逐项核验通过；全局硬编码契约未登记 → 不算正式域生效"
    elif status == "crosscutting_deployed":
        rec["why"] = "横切技能：部署 hash 一致（不是客户可见正式域）"
    else:
        rec["why"] = "仓库里在，但没有部署到任何显式 deploy-root"
    rec["to_take_effect"] = ["待单独一批：" + x for x in rec["registered_pending_contracts"][:5]]
    rec["recovery"] = _recovery_report(skill_dir, roots, name=name)
    _emit(rec, opts)
    return rec["rc"]


def _merge(opts, **kw):
    out = dict(opts)
    out.update(kw)
    return out


def cmd_import(opts):
    rec = run_import(opts)
    _emit(rec, opts)
    return rec["rc"]


def _emit(rec, opts):
    if opts.get("json"):
        print(json.dumps(rec, ensure_ascii=False, indent=2))
        return
    print("来源：%s" % (rec.get("src") or rec.get("manifest_path") or "-"))
    print("名字：%s" % rec.get("name"))
    print("类型：%s（%s）" % (rec.get("kind"), rec.get("kind_why") or rec.get("why") or ""))
    print("阶段：%s  rc=%s" % (rec.get("stage"), rec.get("rc")))
    if rec.get("dry_run"):
        print("[dry-run] 未写入。")
    if rec.get("rolled_back"):
        print("[已回滚] %s（备份保留：%s）" % (rec.get("why"), rec.get("backups")))
    elif rec.get("rollback_partial"):
        print("[回滚不完整] %s（见 rollback/backups，需人工复查）" % rec.get("why"))
    elif rec.get("refusal"):
        print("[拒] %s" % rec.get("refusal", {}).get("message"))
    else:
        print("落位：%s  文件：%s" % (rec.get("dest"), rec.get("files_imported")))
        for d in rec.get("deployed") or []:
            print("部署：%s（hash 一致=%s%s）" % (d.get("path"), d.get("hashes_equal"),
                                            "，pending" if d.get("pending") else ""))
    if rec.get("effective"):
        print("[已生效] %s" % rec.get("why"))
    else:
        print("[未生效] %s" % rec.get("why"))
        for a in (rec.get("to_take_effect") or [])[:6]:
            print("  · %s" % a)
    rp = rec.get("recovery") or {}
    if rp.get("pending_manual"):
        print("[恢复] 存在活锁、损坏 journal 或孤立 staging：pending_manual；"
              "跑 status 看属主与阶段")
    elif rp.get("auto_recoverable"):
        print("[恢复] 检测到可恢复残留；下一次同名事务会持锁自动恢复")
    print("[报告] " + json.dumps(rec, ensure_ascii=False))


# ============================================================ 旧入口
def import_skill(src, name=None, dry=False, deploy=True, skill_dir=None, deploy_roots=None,
                 kind="auto", parent="", pack="", entry="", replace=False, faults=None):
    """旧签名保留（`--from/--dry-run` 路径）。语义已收紧：判型不确定 → needs_classification。

    为什么改：旧实现对"关键词三选二"直接落 `Tool/skill/<x>/` 并部署，等于用描述用词
    自封正式域。现在只有**带真实 pack** 或**显式 --kind** 才会落盘；否则如实报
    `needs_classification` 给 Agent（用户不用填技术表）。
    """
    opts = _opts(src=src, name=name, kind=kind, parent=parent, pack=pack, entry=entry,
                 skill_dir=skill_dir, deploy_roots=deploy_roots, deploy=deploy, dry=dry,
                 replace=replace)
    rec = run_import(opts, faults=faults)
    if rec.get("refusal") and rec["rc"] in (2, 4) and not rec.get("rolled_back"):
        print("[报告] " + json.dumps(rec, ensure_ascii=False))
        return rec
    _emit(rec, {"json": False})
    return rec


# ============================================================ 自测（旧口径保留）
def selftest():
    """自测：域/子技能判定（三选二）+ 复制范围锁定 + 下载项目拒绝 + 未生效提示。"""
    ok, total = 0, 6
    tmp = tempfile.mkdtemp(prefix="seep-skill-")

    def _mk(d, body):
        os.makedirs(d, exist_ok=True)
        with io.open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8") as stream:
            stream.write(body)
        return d

    try:
        # ① 域技能：声明（A）+ 多后缀（B）+ 多技法（C）→ 3/3
        d1 = _mk(os.path.join(tmp, "big"),
                 "---\nname: zz-big\ndescription: \"这个 exe 加壳了怎么脱壳/反调试/抓包 (.exe/.apk/.bin)\"\n---\n"
                 + "\n".join(["## 段 %d 脱壳 反调试 取证 抓包 .exe .apk .bin" % i for i in range(140)]))
        with io.open(os.path.join(d1, "SKILL.md"), encoding="utf-8") as stream:
            t1 = stream.read()
        k1, m1 = classify(t1, parse(t1))
        assert k1 == "domain" and m1["hits"] >= 2, (k1, m1)
        ok += 1
        # ② 子技能：短正文 + 单一技法 + 描述无触发词 → 0/3
        d2 = _mk(os.path.join(tmp, "small"),
                 "---\nname: zz-small\ndescription: \"读 yara 规则 (.yar)\"\n---\n## 1\n小技巧\n")
        with io.open(os.path.join(d2, "SKILL.md"), encoding="utf-8") as stream:
            t2 = stream.read()
        k2, m2 = classify(t2, parse(t2))
        assert k2 == "subskill", (k2, m2)
        ok += 1
        # ③ 判据 A 单独可解释（不靠行数：短正文 + 好描述 = A 命中）
        d3 = _mk(os.path.join(tmp, "short-good"),
                 "---\nname: zz-short\ndescription: \"这个 apk 怎么脱壳 / 抓包 / 解包\"\n---\n短\n")
        with io.open(os.path.join(d3, "SKILL.md"), encoding="utf-8") as stream:
            t3 = stream.read()
        a_ok, a_why = _criterion_declared(parse(t3))
        assert a_ok, a_why
        ok += 1
        # ④ 只给 SKILL.md 时复制范围 = 父目录（不往上爬）
        assert _copy_plan(d1) >= 1
        assert os.path.dirname(os.path.abspath(os.path.join(d1, "SKILL.md"))) == d1
        ok += 1
        # ⑤ 父目录像"整个下载的项目"→ 拒绝（有 .git/node_modules）
        repo = os.path.join(tmp, "downloaded-repo")
        os.makedirs(os.path.join(repo, ".git"), exist_ok=True)
        os.makedirs(os.path.join(repo, "node_modules"), exist_ok=True)
        _mk(os.path.join(repo, "skill"), "---\nname: zz-x\ndescription: \"x\"\n---\n")
        assert ".git" in _download_markers(repo), _download_markers(repo)
        assert not _download_markers(os.path.join(repo, "skill"))
        ok += 1
        # ⑥ 判为子技能 / dry-run 时，“未生效”必须能说出来（R6 P1-7）
        eff, eff_why, eff_acts = _effect_status("subskill", "zz-small", "Tool/skill/_pending/zz-small", False)
        assert eff is False and "不会" in eff_why and len(eff_acts) == 3, (eff, eff_why, eff_acts)
        eff2, _, acts2 = _effect_status("domain", "zz-big", "Tool/skill/zz-big", True)
        assert eff2 is False and len(acts2) == 3, (eff2, acts2)
        eff3, _, _ = _effect_status("domain", "zz-big", "Tool/skill/zz-big", False, True)
        assert eff3 is True
        ok += 1
        print("自测通过：判定/复制范围/项目拒绝/未生效提示（%d/%d）—— A/B/C 三选二，行数不参与；"
              "关键词只给建议，正式域只认 pack" % (ok, total))
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================ CLI
COMMANDS = ("import", "plan", "stage", "validate", "deploy", "verify", "status", "recovery-report")


def _parser(cmd):
    ap = argparse.ArgumentParser(description="导入外部技能/扩展（判型建议 + 事务落位 + 部署 + 回执）")
    ap.add_argument("--from", dest="src", default="", help="外部技能目录 / SKILL.md / tool manifest")
    ap.add_argument("--name", default="", help="覆盖名字（默认 frontmatter name / 目录名）")
    ap.add_argument("--kind", default="auto", choices=list(KINDS),
                    help="auto=只建议；domain/crosscutting/subskill/tool=显式声明")
    ap.add_argument("--parent", default="", help="子技能的父域 id（必须是真实 pack 域）")
    ap.add_argument("--pack", default="", help="正式域的 pack.json（源目录内没有时用它）")
    ap.add_argument("--entry", default="", help="父 SKILL.md 里那一行的『何时读』一句话")
    ap.add_argument("--tool-id", default="", help="tool 模式的工具 id（默认取 manifest.id）")
    ap.add_argument("--tool-manifest", default="", help="tool 模式的 manifest 路径")
    ap.add_argument("--skill-dir", default="", help="Tool/skill 根的显式注入（测试/多仓）")
    ap.add_argument("--deploy-root", action="append", default=[],
                    help="部署根（可多次；不传则用 ~/.pi/agent/skills，自定义 skill-dir 时必填）")
    ap.add_argument("--no-deploy", action="store_true", help="只写仓库，不部署")
    ap.add_argument("--replace", action="store_true",
                    help="目标已存在时显式替换：备份→rename，绝不 rmtree 旧再 copy")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    return ap


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = None
    if argv and not argv[0].startswith("-") and argv[0] in COMMANDS:
        cmd = argv.pop(0)
    ap = _parser(cmd)
    if cmd:
        ap.add_argument("cmd", nargs="?", default=cmd)
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    roots = list(a.deploy_root or [])
    opts = _opts(src=a.src if hasattr(a, "src") else "", name=a.name, kind=a.kind,
                 parent=a.parent, pack=a.pack, entry=a.entry,
                 skill_dir=a.skill_dir or None, deploy_roots=roots,
                 deploy=not a.no_deploy, dry=a.dry_run, replace=a.replace,
                 tool_id=a.tool_id, tool_manifest=a.tool_manifest)
    opts["json"] = a.json
    try:
        return _dispatch(cmd, opts, ap)
    except Refuse as r:
        # 顶层统一 Refuse 处理：**所有** subcommand 同一条规则（含 status/recovery-report
        # 的 root 解析）。以前只有部分子命令内部 try，status 裸抛 traceback（R-NEW-2）。
        return _refuse_out(opts, r, cmd or "import")
    except Exception as e:  # noqa: BLE001
        # 未预期异常：**如实报 unknown**（rc=5、written=false、refusal.code=unknown_error），
        # 不 traceback、不回显原值，但绝不 return 0——不用 catch-all 把它掩盖成"通过"。
        return _refuse_out(opts, Refuse(
            5, "unknown_error",
            "未预期异常（%s）：本次结果未知，不得当作通过；零写保证仍由外层路径约束"
            % type(e).__name__), cmd or "import")


def _refuse_out(opts, r, stage):
    """结构化拒执：机读 refusal + rc，不 traceback、不回显敏感原值、零写。"""
    o = dict(opts)
    if stage in ("status", "recovery-report"):
        # 根不合法时不得再去扫那个根（即使是只读）：回执只报拒因。
        o["deploy_roots"] = []
    try:
        rec = _refusal_receipt(o, r, stage=stage)
    except Exception:  # noqa: BLE001
        # 拒执路径自己出错也不能变成 traceback/rc=1：退到最小机读回执
        rec = {"schema": SCHEMA, "kind": opts.get("kind"), "name": opts.get("name") or "",
               "rc": r.rc, "stage": stage, "written": False, "effective": False,
               "deployed": [], "files_imported": 0, "recovery": None,
               "refusal": r.as_dict(), "why": r.message, "to_take_effect": []}
    _emit(rec, opts)
    return rec["rc"]


def _dispatch(cmd, opts, ap):
    if cmd is None:
        # 旧入口：没有 --from 就打印帮助（rc=4，与旧行为一致）
        if not opts["src"]:
            ap.print_help()
            return 4
        return cmd_import(opts)
    if cmd == "import":
        return cmd_import(opts)
    if cmd == "plan":
        return cmd_plan(opts)
    if cmd in ("stage", "validate"):
        # validate = stage + 真实 pack 校验（cmd_stage 内部已跑 validate_pack）；保留别名供诊断
        return cmd_stage(opts)
    if cmd == "deploy":
        return cmd_deploy(opts)
    if cmd == "verify":
        return cmd_verify(opts)
    if cmd in ("status", "recovery-report"):
        return cmd_status(opts)
    ap.print_help()
    return 2


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
