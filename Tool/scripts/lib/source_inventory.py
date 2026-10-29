#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""source_inventory.py —— 仓库源清单（**唯一**计数真相源；#43 审计的窄修复）。

为什么要有它
    `budget.py::first_party_files()` 原来自己算一遍（12 条 **子串** skip + `os.walk` 回退）：
      · 子串 `"/work"` 误排 `.github/workflows/*.yml`，`"/audit"` 误排 `docs/audits/*`、
        `"/upstream"` 误排 `setup/upstream-rules.json`、`"/evidence/"` 误排 `Tool/skill/*/evidence/*`（实测 13 条）；
      · 回退走 `os.walk` 时把**绝对路径**丢进同一条子串判定 —— 仓库只要装在含
        `work`/`cases`/`audit`/`evidence` 的路径下，`Tool/` 会被整体剪掉，退化成 ~40 条静默绿；
      · 只管 tracked，同一份代码在导出包 / 换机上口径不一致。
    `mutation.py` / `pre-upload-check.py` 又各自实现了 tracked+untracked 一遍。三份口径 = 三个真相源。

本模块的口径（`POLICY`，与 MANUAL/BASELINE-FREEZE.md §7 同步）
    inventory = git 已跟踪 + 未被 .gitignore 忽略的未跟踪；raw `files` 保留全量；
    只有 `Tool/config/thirdparty-fixtures.json` 中逐项通过来源、路径、size、sha256
    校验的现有 `Tool/samples/real/` 输入才标为 `thirdparty_input`，其余（包括
    样本 README/LICENSE/生成脚本和未知新文件）一律标为 `first_party`；
    只用准确 segment 判定排除，不做任何子串匹配；排除项都带原因字符串，落在
    `excluded[]` 里可审计，不是静默丢弃；角色计数不减少 raw inventory 闭包。
    `.github/`、`.gitignore`、`.gitattributes`、`.mcp.json`、`Tool/mcp/.baseline/tools.json`
    这类真实源/状态文件保留；只有运行时点目录才整体排除。

两条硬约束
    1. `root` 必须是 git 顶层（父 repo 里跑 = 直接用别人的清单，必须拒）。
    2. git 不可用 / 不是本 repo 时，**只**接受可验证的导出 manifest；
       manifest 缺失或验不过 → `mode="unverified"`，**不返回 walk 出来的小数字、也不返回成功**。

只读边界：只读本 project 内的文件元数据 + 字节（`sha256` 用）；不读 HOME/用户配置/凭据，
不改索引、不 git add/commit、不联网、不执行目标。

用法
    python Tool/scripts/lib/source_inventory.py                    # 打印当前计数
    python Tool/scripts/lib/source_inventory.py --json
    python Tool/scripts/lib/source_inventory.py --generate-manifest [--out PATH]
    python Tool/scripts/lib/source_inventory.py --verify-manifest PATH

退出码：0 = 计数可用（**不代表**在预算内）；2 = 信息不全/未验证；1 = 清单不可用（拒）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time

POLICY = "seep.source_inventory/2"
MANIFEST_SCHEMA = "seep.source-inventory.manifest/2"
FIXTURE_SCHEMA = "seep.thirdparty-fixtures/1"
FIXTURE_CONFIG = os.path.join("Tool", "config", "thirdparty-fixtures.json")
FIXTURE_ROOT = "Tool/samples/real"
MANIFEST_NAME = "source-inventory.manifest.json"

# 角色由显式 thirdparty fixture ledger 计算；预算消费者只读 first_party。
ROLE_FIRST = "first_party"
ROLE_THIRD = "thirdparty_input"

# ── 明确排除：vendor 树 + 各自独立记账的目录（不是"不重要"，是"不记在引擎账上"）
EXCLUDE_ROOTS = (
    ("Tool/upstream", "vendor: 上游仓库整树（F6 上游隔离边界）"),
    ("Tool/mcp/Tool", "vendor: 随包第三方工具树（F1 冻结骨架）"),
    ("Tool/cases", "data: 案例库，独立预算 1500"),
    ("Tool/work", "runtime: 工作区产物"),
    ("Tool/audit", "runtime: 审计产物"),
    ("tmp", "runtime: 仓库根临时产物（不计入引擎预算）"),
    ("破甲卡生成", "data: 外部卡生成输入，非引擎源"),
)

# ── 任意目录层命中即排除
EXCLUDE_SEGMENTS = {
    "node_modules": "vendor: 依赖树",
    "__pycache__": "runtime: 字节码缓存",
    ".git": "runtime: 版本库内部",
    ".pi": "runtime: 宿主元数据（非项目源）",
    ".pytest_cache": "runtime: 测试缓存",
    ".mypy_cache": "runtime: 静态检查缓存",
    ".ruff_cache": "runtime: 静态检查缓存",
    ".venv": "runtime: 虚拟环境",
    "venv": "runtime: 虚拟环境",
    ".next": "runtime: 构建缓存",
    # .gitignore:136 已忽略；仓内零读取方；pre-upload-check.py 自列为「运行期残留」
    ".playwright-mcp": "runtime: 浏览器自动化残留",
    ".r12-validation": "runtime: R12 隔离验收运行目录",
    ".seep": "runtime: 本机工作台状态目录",
}

# classify 的 data/doc 仍保留为路径分类辅助；预算角色由显式 fixture 清单计算。
ROLE_RULES = (
    (("Tool/samples/",), "data"),
    (("Tool/mcp/.baseline/",), "state"),
    (("docs/", "MANUAL/", "Tool/docs/"), "doc"),
)

_GIT = ("git", "-c", "core.fsmonitor=false", "-c", "core.quotepath=false")


class SourceInventoryError(Exception):
    """清单不可用（拒绝）。不是"未验证"——是明确判错。"""


# ───────────────────────────── 基础 ─────────────────────────────
def _git(root, *args, timeout=120):
    """只读 git 调用。进程级 -c 关 fsmonitor + 不读用户全局 excludes（可复现 + 不碰用户配置）。"""
    cmd = list(_GIT) + ["-c", "core.excludesFile=" + os.devnull, "-C", root] + list(args)
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)
    if p.returncode != 0:
        return None, (p.stderr or b"").decode("utf-8", "replace").strip()[:200]
    return p.stdout, ""


def _zsplit(raw):
    if not raw:
        return []
    # Git emits raw filesystem bytes with core.quotepath=false.  On POSIX a valid
    # repository can contain names that are not UTF-8; replacement decoding would
    # collapse distinct paths and make the inventory incomplete-but-green.
    return [x.decode(sys.getfilesystemencoding(), "surrogateescape")
            for x in raw.split(b"\0") if x]


def git_toplevel(root):
    """realpath 形式的 git 顶层；不可用返回 None。"""
    out, _err = _git(root, "rev-parse", "--show-toplevel")
    if not out:
        return None
    line = out.decode(sys.getfilesystemencoding(), "surrogateescape").strip()
    return os.path.realpath(line) if line else None


def _sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _rooted_file(root, rel, position):
    """Return a file/directory path whose lexical and resolved paths stay inside root."""
    normalized = normalize_rel(rel)
    root_real = os.path.realpath(root)
    lexical = os.path.abspath(os.path.join(root_real, normalized.replace("/", os.sep)))
    try:
        lexical_inside = os.path.commonpath((root_real, lexical)) == root_real
    except ValueError:
        lexical_inside = False
    resolved = os.path.realpath(lexical)
    try:
        resolved_inside = os.path.commonpath((root_real, resolved)) == root_real
    except ValueError:
        resolved_inside = False
    if not lexical_inside or not resolved_inside:
        raise SourceInventoryError("源路径越界：%s" % position)
    return resolved


def _fixture_config_path(root):
    return _rooted_file(root, FIXTURE_CONFIG, "fixture config")


def _fixture_roles(root):
    """Load and verify the explicit third-party input ledger.

    Missing config is harmless for synthetic repositories without samples/real;
    a real samples tree without the ledger is incomplete.  No glob or path-prefix
    exemption is accepted: every role is established by one file record and its
    current bytes.
    """
    path = _fixture_config_path(root)
    sample_root = _rooted_file(root, FIXTURE_ROOT, "fixture root")
    if not os.path.isfile(path):
        if os.path.isdir(sample_root):
            raise SourceInventoryError("第三方 fixture 清单缺失：%s" % FIXTURE_CONFIG)
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as exc:
        raise SourceInventoryError("第三方 fixture 清单损坏：%s" % str(exc)[:160])
    if not isinstance(doc, dict) or doc.get("schema") != FIXTURE_SCHEMA:
        raise SourceInventoryError("第三方 fixture schema 不匹配")
    if doc.get("root") != FIXTURE_ROOT:
        raise SourceInventoryError("第三方 fixture root 必须为 %s" % FIXTURE_ROOT)
    sources = doc.get("sources")
    entries = doc.get("files")
    if not isinstance(sources, dict) or not isinstance(entries, list) or not entries:
        raise SourceInventoryError("第三方 fixture 缺 sources/files 闭包")
    for key, source in sources.items():
        if not isinstance(key, str) or not isinstance(source, dict):
            raise SourceInventoryError("第三方来源记录非法：sources[%r]" % key)
        url = source.get("url")
        if not isinstance(url, str) or not url.strip():
            raise SourceInventoryError("第三方来源缺引用：source=%r position=sources[%r].url" % (key, key))
        evidence = normalize_rel(source.get("evidence"))
        if not evidence.startswith(FIXTURE_ROOT + "/") and evidence != FIXTURE_ROOT:
            raise SourceInventoryError("第三方来源证据越界：source=%r position=sources[%r].evidence" % (key, key))
        evidence_path = _rooted_file(root, evidence, "sources[%s].evidence" % key)
        if not os.path.isfile(evidence_path):
            raise SourceInventoryError("第三方来源证据缺失：source=%r position=sources[%r].evidence" % (key, key))
        try:
            with open(evidence_path, encoding="utf-8", errors="replace") as f:
                evidence_text = f.read()
        except OSError:
            raise SourceInventoryError("第三方来源证据不可读：source=%r position=sources[%r].evidence" % (key, key))
        if url not in evidence_text:
            raise SourceInventoryError("第三方来源锚点不匹配：source=%r position=sources[%r].url" % (key, key))
    roles = {}
    for item in entries:
        if not isinstance(item, dict):
            raise SourceInventoryError("第三方 fixture 条目非法")
        rel = normalize_rel(item.get("path"))
        if rel in roles:
            raise SourceInventoryError("第三方 fixture 路径重复：%s" % rel)
        if not rel.startswith(FIXTURE_ROOT + "/"):
            raise SourceInventoryError("第三方 fixture 路径越界：%s" % rel)
        keep, reason, _old_role = classify(rel)
        if not keep:
            raise SourceInventoryError("第三方 fixture 路径不在 inventory：%s (%s)" % (rel, reason))
        source = item.get("source")
        if not isinstance(source, str) or source not in sources:
            raise SourceInventoryError("第三方 fixture 来源未定义：%s" % rel)
        full = _rooted_file(root, rel, "files[%s].path" % rel)
        if not os.path.isfile(full):
            raise SourceInventoryError("第三方 fixture 文件缺失：%s" % rel)
        size = item.get("size")
        digest = item.get("sha256")
        if (type(size) is not int or size < 0 or not isinstance(digest, str)
                or len(digest) != 64 or digest.lower() != digest
                or any(c not in "0123456789abcdef" for c in digest)):
            raise SourceInventoryError("第三方 fixture 缺少有效 size/sha256：%s" % rel)
        actual_size = os.path.getsize(full)
        actual_hash = _sha256(full)
        if actual_size != size:
            raise SourceInventoryError("第三方 fixture size 漂移：%s" % rel)
        if actual_hash != digest:
            raise SourceInventoryError("第三方 fixture sha256 漂移：%s" % rel)
        roles[rel] = ROLE_THIRD
    return roles


def _apply_roles(root, files):
    """Recompute roles from the validated ledger; never trust an entry role."""
    roles = _fixture_roles(root)
    counts = {ROLE_FIRST: 0, ROLE_THIRD: 0}
    for entry in files:
        role = ROLE_THIRD if entry["path"] in roles else ROLE_FIRST
        entry["role"] = role
        counts[role] += 1
    return counts
def normalize_rel(rel):
    """规范化仓库相对路径；拒绝越界、绝对路径、NUL 和 Windows 数据流。"""
    if not isinstance(rel, str):
        raise SourceInventoryError("清单路径必须是字符串")
    text = rel.replace("\\", "/")
    if not text or text.startswith("/") or ":" in text or "\x00" in text:
        raise SourceInventoryError("清单路径非法（绝对路径/空路径）：%r" % rel)
    parts = [x for x in text.split("/") if x not in ("", ".")]
    if not parts or any(x == ".." for x in parts):
        raise SourceInventoryError("清单路径越界（escape）：%r" % rel)
    return "/".join(parts)


def classify(rel):
    """(included, reason, role)。纯 segment 判定 —— 不看子串、不看 root 绝对路径。"""
    p = normalize_rel(rel)
    if p == MANIFEST_NAME:
        return False, "meta: 清单自身不进清单（防自指循环）", "meta"
    for rootdir, reason in EXCLUDE_ROOTS:
        if p == rootdir or p.startswith(rootdir + "/"):
            return False, reason, "excluded"
    dirs = p.split("/")[:-1]
    for seg in dirs:
        reason = EXCLUDE_SEGMENTS.get(seg)
        if reason:
            return False, reason, "excluded"
    role = "source"
    for prefixes, name in ROLE_RULES:
        if any(p.startswith(x) for x in prefixes):
            role = name
            break
    return True, "", role


def _sort_key(rel):
    return rel.encode("utf-8", "surrogateescape")


def _gitlink_paths(root):
    """已索引的 gitlink / submodule（mode 160000）。只读 `ls-files -s`，**不递归、不拉取**。"""
    out, _err = _git(root, "ls-files", "-s", "-z")
    if out is None:
        raise SourceInventoryError("git ls-files -s 失败，无法核对 gitlink：" + _err)
    if not out:
        return set()
    links = set()
    for rec in _zsplit(out):
        if not rec or "\t" not in rec:
            continue
        meta, path = rec.split("\t", 1)
        if meta.split(" ", 1)[0] == "160000":
            links.add(path.strip("/"))
    return links


# ───────────────────────────── 采集 ─────────────────────────────
def _result(mode, root, top, reason="", **extra):
    out = {"policy": POLICY, "mode": mode, "ok": mode != "unverified", "root": root,
           "git_toplevel": top, "mode_reason": reason, "stable": None, "head": None,
           "files": [], "excluded": [], "errors": [],
           # F1/F2：**完整性**与「数字」分开报。complete=False ⇒ 消费者不得判绿。
           "source_complete": mode != "unverified", "missing_tracked": [], "unsupported": [],
           "deleted_staged": [],
           "counts": {"included": 0, "tracked": 0, "untracked": 0, "excluded": 0,
                      "missing": 0, "unsupported": 0, "first_party": 0,
                      "thirdparty_input": 0, "deleted_staged": 0, "by_role": {}}}
    out.update(extra)
    return out


def collect(root, hashes=False, include_untracked=True):
    """按 POLICY 采集。root 必须是 git 顶层，否则 **拒**（不猜父 repo）。

    ``source_complete`` describes the **current index/worktree source set**:
    staged deletions are an intentional change to that set and are reported in
    ``deleted_staged``; an indexed file missing from the worktree remains a real
    ``missing_tracked`` gap.  HEAD itself is not the source set.
    """
    root = os.path.realpath(root)
    top = git_toplevel(root)
    if top is None:
        return _result("unverified", root, None, "git 不可用或不是 git 仓库 → 需可验证导出 manifest")
    if top != root:
        raise SourceInventoryError(
            "root 不是 git 顶层（疑似父 repo 误用）：root=%s toplevel=%s" % (root, top))

    cached, err = _git(root, "ls-files", "-z", "--cached")
    if cached is None:
        return _result("unverified", root, top, "git ls-files 失败：" + err)
    tracked_all = sorted(_zsplit(cached), key=_sort_key)
    untracked_all = []
    if include_untracked:
        other, err = _git(root, "ls-files", "-z", "--others", "--exclude-standard")
        if other is None:
            return _result("unverified", root, top, "git ls-files --others 失败：" + err)
        seen = set(tracked_all)
        untracked_all = sorted([x for x in _zsplit(other) if x not in seen], key=_sort_key)
    links = _gitlink_paths(root)

    head_out, _e = _git(root, "rev-parse", "HEAD")
    head = head_out.decode("utf-8", "replace").strip() if head_out else ""
    deleted_staged = []
    if head:
        diff_out, diff_err = _git(
            root, "diff", "--cached", "--name-only", "--diff-filter=D", "-z", "--")
        if diff_out is None:
            return _result("unverified", root, top,
                           "git diff --cached 失败：" + diff_err)
        deleted_staged = [
            {"path": rel, "tracked": True,
             "reason": "staged deletion: 已从索引移除，不是工作树缺失"}
            for rel in sorted(_zsplit(diff_out), key=_sort_key)
        ]

    files, excluded, missing, unsupported = [], [], [], []
    n_tracked = n_untracked = 0
    by_role = {}
    for rel, is_tracked in ([(r, True) for r in tracked_all] +
                            [(r, False) for r in untracked_all]):
        # F2：gitlink / 嵌套 .git 目录 —— 不记录 size=0 的假 source，不递归子仓库。
        _bare = rel.rstrip("/")
        if _bare in links or rel.endswith("/"):
            keep, reason, _role = classify(_bare)
            if not keep:                       # 已在明确 vendor/runtime 根下 → 保持 excluded
                excluded.append({"path": _bare, "reason": reason, "tracked": is_tracked})
            else:
                unsupported.append({
                    "path": _bare, "tracked": is_tracked,
                    "reason": ("gitlink: submodule 未物化（不递归、不拉取）" if _bare in links
                               else "nested-repo: 目录内含 .git，未物化（不递归、不拉取）")})
            continue
        keep, reason, role = classify(rel)
        if not keep:
            excluded.append({"path": rel, "reason": reason, "tracked": is_tracked})
            continue
        try:
            full = _rooted_file(root, rel, rel)
        except SourceInventoryError as exc:
            unsupported.append({"path": rel, "tracked": is_tracked, "reason": str(exc)})
            continue
        try:
            before = os.stat(full)
        except OSError:
            # F1：已跟踪但工作树不存在 —— 不当“没东西可数”，单独记名并让完整性变 incomplete。
            if is_tracked:
                missing.append({"path": rel, "tracked": True,
                                "reason": "missing: 已跟踪但工作树不存在（未判为删除批准）"})
            excluded.append({"path": rel, "reason": "missing: 列在 git 里但磁盘上没有",
                             "tracked": is_tracked})
            if not is_tracked:
                unsupported.append({"path": rel, "tracked": False,
                                    "reason": "枚举后的未跟踪文件已不可读"})
            continue
        if not stat.S_ISREG(before.st_mode):
            unsupported.append({"path": rel, "tracked": is_tracked, "reason": "非普通文件，不能作为源文件读取"})
            continue
        size = before.st_size
        entry = {"path": rel, "size": size, "role": role, "tracked": is_tracked}
        if hashes:
            entry["sha256"] = _sha256(full)
            try:
                after = os.stat(full)
            except OSError:
                after = None
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
            if (entry["sha256"] is None or after is None
                    or any(getattr(before, k) != getattr(after, k) for k in fields)):
                unsupported.append({"path": rel, "tracked": is_tracked,
                                    "reason": "读取失败或计算摘要期间文件发生变化"})
                continue
        files.append(entry)
        n_tracked += 1 if is_tracked else 0
        n_untracked += 0 if is_tracked else 1
        by_role[role] = by_role.get(role, 0) + 1

    # 稳定性：**用与枚举相同的策略**比第二次（F4：trackedOnly 不能与 all 比成伪不稳）
    probe = (["ls-files", "-z", "--cached", "--others", "--exclude-standard"]
             if include_untracked else ["ls-files", "-z", "--cached"])
    union_out, _e2 = _git(root, *probe)
    head_out2, _e3 = _git(root, "rev-parse", "HEAD")
    head2 = head_out2.decode("utf-8", "replace").strip() if head_out2 else ""
    deleted_staged2 = []
    if head:
        diff_out2, _diff_err2 = _git(
            root, "diff", "--cached", "--name-only", "--diff-filter=D", "-z", "--")
        if diff_out2 is not None:
            deleted_staged2 = sorted(_zsplit(diff_out2), key=_sort_key)
    stable = None
    if union_out is not None:
        want = (set(tracked_all) | set(untracked_all)) if include_untracked else set(tracked_all)
        stable = (
            set(_zsplit(union_out)) == want
            and head == head2
            and deleted_staged2 == [entry["path"] for entry in deleted_staged]
        )

    inv = _result("git", root, top, "", files=files, excluded=excluded,
                  stable=bool(stable), head=head)
    inv["missing_tracked"] = missing
    inv["unsupported"] = unsupported
    inv["deleted_staged"] = deleted_staged
    inv["source_complete"] = bool(stable) and not missing and not unsupported
    if not stable:
        inv["errors"].append("采集期间 Git 清单变化或稳定性复核失败")
    inv["counts"] = {"included": len(files), "tracked": n_tracked, "untracked": n_untracked,
                     "excluded": len(excluded), "missing": len(missing),
                     "unsupported": len(unsupported), "first_party": 0,
                     "thirdparty_input": 0, "deleted_staged": len(deleted_staged),
                     "by_role": {}}
    try:
        role_counts = _apply_roles(root, inv["files"])
        inv["counts"]["first_party"] = role_counts[ROLE_FIRST]
        inv["counts"]["thirdparty_input"] = role_counts[ROLE_THIRD]
        inv["counts"]["by_role"] = dict(role_counts)
    except SourceInventoryError as exc:
        # Raw enumeration remains visible, but an invalid ledger is not complete.
        for entry in inv["files"]:
            entry["role"] = ROLE_FIRST
        inv["counts"]["first_party"] = len(inv["files"])
        inv["counts"]["by_role"] = {ROLE_FIRST: len(inv["files"]), ROLE_THIRD: 0}
        inv["errors"].append(str(exc))
        inv["source_complete"] = False
    inv["include"] = {"untracked": bool(include_untracked), "hashes": bool(hashes)}
    inv["ok"] = inv["source_complete"]
    return inv


# ─────────────────────── manifest 生成 / 校验 ───────────────────────
def build_manifest(root, include_untracked=True):
    inv = collect(root, hashes=True, include_untracked=include_untracked)
    if inv["mode"] != "git":
        raise SourceInventoryError("无法生成 manifest：" + (inv.get("mode_reason") or inv["mode"]))
    return {
        "schema": MANIFEST_SCHEMA,
        "policy": POLICY,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "git_commit": inv["head"],
        "stable": inv["stable"],
        "include": {"untracked": bool(include_untracked),
                    "exclude_roots": [r for r, _ in EXCLUDE_ROOTS],
                    "exclude_segments": sorted(EXCLUDE_SEGMENTS)},
        "counts": inv["counts"],
        "files": [{"path": f["path"], "size": f["size"], "sha256": f["sha256"], "role": f["role"]}
                  for f in inv["files"]],
        "excluded": inv["excluded"],
        "missing_tracked": inv["missing_tracked"],
        "unsupported": inv["unsupported"],
        "deleted_staged": inv["deleted_staged"],
        "source_complete": inv["source_complete"],
        "meta_policy": "清单自身（%s）不进清单；meta 不参与计数" % MANIFEST_NAME,
    }


def write_manifest(root, out_path=None, include_untracked=True):
    doc = build_manifest(root, include_untracked=include_untracked)
    out_path = out_path or _rooted_file(root, MANIFEST_NAME, "default manifest")
    staged = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=os.path.dirname(os.path.abspath(out_path)),
                                         prefix=".source-inventory-", suffix=".tmp", delete=False) as f:
            staged = f.name
            json.dump(doc, f, ensure_ascii=False, indent=1, sort_keys=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(staged, out_path)
    except (OSError, ValueError, TypeError) as exc:
        raise SourceInventoryError("manifest 写入失败：%s" % exc) from exc
    finally:
        if staged is not None and os.path.exists(staged):
            os.unlink(staged)
    return out_path, doc


def _enumerate_present(root):
    """root 里"按策略应被包含"的文件集合 —— 只用于检 extraSource。

    git 可用 → 用 git（准确的 ignore 语义）；不可用 → segment 过滤的 walk。
    注意：这里的枚举**永远不产生计数**，计数只来自已验过的 manifest。
    """
    cached, err = _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    if cached is not None:
        return set(_zsplit(cached)), "git"
    present = set()

    def walk_error(exc):
        raise SourceInventoryError("无法完整枚举导出源树：%s" % exc) from exc

    for dirpath, dirs, names in os.walk(root, onerror=walk_error):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        included_dirs = []
        for d in sorted(dirs):
            rel = (rel_dir + "/" + d).lstrip("/")
            # classify expects a file path; include the directory itself in its segments.
            if not classify(rel + "/_inventory_probe_")[0]:
                continue
            resolved = _rooted_file(root, rel, rel)
            lexical = os.path.join(root, rel.replace("/", os.sep))
            if os.path.normcase(resolved) != os.path.normcase(os.path.abspath(lexical)):
                raise SourceInventoryError("源目录链接无法完整枚举：%s" % rel)
            included_dirs.append(d)
        dirs[:] = included_dirs
        for name in names:
            rel = (rel_dir + "/" + name).lstrip("/")
            if classify(rel)[0]:
                present.add(rel)
    return present, "walk"


def verify_manifest(manifest, root, hashes=True):
    """校验导出 manifest。始终核对字节摘要；hashes 参数仅为兼容旧调用保留。"""
    root = os.path.realpath(root)
    if isinstance(manifest, (str, os.PathLike)):
        try:
            with open(os.fspath(manifest), encoding="utf-8") as f:
                manifest = json.load(f)
        except (OSError, ValueError) as exc:
            raise SourceInventoryError("manifest 读不出/不是 JSON：%s" % str(exc)[:120])
    if not isinstance(manifest, dict):
        raise SourceInventoryError("manifest 结构非法（不是对象）")
    if manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("policy") != POLICY:
        raise SourceInventoryError("manifest schema/policy 不匹配（schema=%r policy=%r）"
                                  % (manifest.get("schema"), manifest.get("policy")))
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list):
        raise SourceInventoryError("manifest 缺 files[]（闭包不完整）")
    counts = manifest.get("counts")
    if not isinstance(counts, dict):
        raise SourceInventoryError("manifest counts 必须是对象")
    for key in ("included", ROLE_FIRST, ROLE_THIRD):
        if type(counts.get(key)) is not int or counts[key] < 0:
            raise SourceInventoryError("manifest 缺少有效计数：%s" % key)
    for key in ("missing_tracked", "unsupported", "excluded"):
        entries = manifest.get(key)
        if not isinstance(entries, list) or any(not isinstance(e, dict) for e in entries):
            raise SourceInventoryError("manifest %s 必须是对象列表" % key)
    deleted_staged = manifest.get("deleted_staged", [])
    if not isinstance(deleted_staged, list) or any(not isinstance(e, dict) for e in deleted_staged):
        raise SourceInventoryError("manifest deleted_staged 必须是对象列表")
    if type(manifest.get("stable")) is not bool or type(manifest.get("source_complete")) is not bool:
        raise SourceInventoryError("manifest stable/source_complete 必须是布尔值")
    if counts.get("included") != len(raw_files):
        raise SourceInventoryError("manifest 自身不一致：counts.included=%r 而 files=%d"
                                   % (counts.get("included"), len(raw_files)))
    roles = _fixture_roles(root)
    files, seen = [], set()
    for entry in raw_files:
        if not isinstance(entry, dict):
            raise SourceInventoryError("manifest files[] 元素非法")
        rel = normalize_rel(entry.get("path"))          # → escape/绝对路径在这里拒
        if rel in seen:
            raise SourceInventoryError("manifest 路径重复：%s" % rel)
        seen.add(rel)
        keep, reason, _old_role = classify(rel)
        if not keep:
            raise SourceInventoryError("manifest 含策略外路径（%s）：%s" % (reason, rel))
        expected_role = ROLE_THIRD if rel in roles else ROLE_FIRST
        if "role" in entry and entry.get("role") != expected_role:
            raise SourceInventoryError("manifest role map 不匹配：%s 应为 %s" % (rel, expected_role))
        full = _rooted_file(root, rel, rel)
        if not os.path.isfile(full):
            raise SourceInventoryError("manifest 路径缺失或非普通文件（stale）：%s" % rel)
        try:
            size = os.path.getsize(full)
        except OSError:
            raise SourceInventoryError("manifest 路径在源树缺失（stale）：%s" % rel)
        if type(entry.get("size")) is not int or size != entry.get("size"):
            raise SourceInventoryError(
                "stale：%s 大小 %d ≠ 清单 %r" % (rel, size, entry.get("size")))
        want = entry.get("sha256")
        if (not isinstance(want, str) or len(want) != 64
                or any(c not in "0123456789abcdef" for c in want)):
            raise SourceInventoryError("manifest 缺有效 sha256：%s" % rel)
        got = _sha256(full)
        if got != want:
            raise SourceInventoryError("source 字节不一致：%s（%s ≠ %s）" % (rel, got, want))
        files.append({"path": rel, "size": size, "sha256": entry.get("sha256"),
                      "role": expected_role, "tracked": None})

    role_counts = _by_role(files)
    if (counts.get(ROLE_FIRST) != role_counts.get(ROLE_FIRST, 0)
            or counts.get(ROLE_THIRD) != role_counts.get(ROLE_THIRD, 0)):
        raise SourceInventoryError("manifest role 计数不一致")

    # F1：清单里的 missing / unsupported 是**声明过的已存在缺口**，不被当成“已完成”。
    man_missing = manifest["missing_tracked"]
    man_unsup = manifest["unsupported"]

    # extraSource：源树里按策略应被包含、但 manifest 没列的文件
    present, how = _enumerate_present(root)
    extra = sorted(set(p for p in present if classify(p)[0]) - seen, key=_sort_key)
    if extra:
        detail = "；".join(extra[:5]) + ("…" if len(extra) > 5 else "")
        msg = "manifest 未覆盖源树新增文件（extraSource，枚举方式=%s）：%d 条 — %s" % (
            how, len(extra), detail)
        if how == "git":
            raise SourceInventoryError(msg)     # 能准确枚举 → 硬拒
        inv = _result("unverified", root, git_toplevel(root), msg + "（git 不可用，无法判 ignore 语义）")
        inv["errors"] = [msg]
        inv["files"] = files
        inv["missing_tracked"] = man_missing
        inv["unsupported"] = man_unsup
        inv["deleted_staged"] = deleted_staged
        inv["source_complete"] = False
        inv["counts"] = {"included": len(files), "tracked": None, "untracked": None,
                         "excluded": len(manifest.get("excluded") or []),
                         "missing": len(man_missing), "unsupported": len(man_unsup),
                         "first_party": role_counts.get(ROLE_FIRST, 0),
                         "thirdparty_input": role_counts.get(ROLE_THIRD, 0),
                         "deleted_staged": len(deleted_staged),
                         "by_role": role_counts}
        inv["manifest"] = {"schema": MANIFEST_SCHEMA, "generated_at": manifest.get("generated_at"),
                           "git_commit": manifest.get("git_commit"), "extra": extra}
        return inv

    by_role = _by_role(files)
    inv = _result("manifest", root, git_toplevel(root), "",
                  files=files, excluded=list(manifest.get("excluded") or []),
                  stable=manifest.get("stable"), head=manifest.get("git_commit") or "")
    inv["missing_tracked"] = man_missing
    inv["unsupported"] = man_unsup
    inv["deleted_staged"] = deleted_staged
    inv["source_complete"] = (manifest["source_complete"] and manifest["stable"]
                              and not man_missing and not man_unsup)
    inv["ok"] = inv["source_complete"]
    inv["counts"] = {"included": len(files), "tracked": None, "untracked": None,
                     "excluded": len(inv["excluded"]), "missing": len(man_missing),
                     "unsupported": len(man_unsup), "first_party": role_counts.get(ROLE_FIRST, 0),
                     "thirdparty_input": role_counts.get(ROLE_THIRD, 0),
                     "deleted_staged": len(deleted_staged), "by_role": role_counts}
    inv["manifest"] = {"schema": MANIFEST_SCHEMA, "generated_at": manifest.get("generated_at"),
                       "git_commit": manifest.get("git_commit"), "enumerated_by": how}
    return inv


def _by_role(files):
    out = {}
    for f in files:
        out[f["role"]] = out.get(f["role"], 0) + 1
    return out


def default_manifest_path(root):
    """导出包自带清单的**唯一**预期位置：`<root>/source-inventory.manifest.json`。

    F3：不搜父目录、不搜个人目录、不搜其它版本号 —— 只认根内这一个确切文件名。
    """
    return _rooted_file(root, MANIFEST_NAME, "default manifest")


def inventory(root, manifest=None, hashes=False, autodiscover=None):
    """统一入口：git 优先；git 不可用时用显式 manifest / 根内默认 manifest；都没有 → unverified。

    优先级（要紧，防“过期 manifest 覆盖真实 git 源”）：
      1. `collect()` 成功（真 git 且 root 是顶层）→ **永远不用 manifest**（除非显式 `manifest=`）；
      2. 真 git 但显式 `manifest=` → 仍验 manifest（调用方明确要求的那份）；
      3. 非 git（导出包）→ 显式 `manifest=` → 根内 `<root>/source-inventory.manifest.json`；
      4. 都没有 → unverified（不 walk 冒充）。
    `autodiscover=False` 关掉第 3 步的默认文件名查找（导出系统可显式控）。
    """
    root = os.path.realpath(root)
    inv = collect(root, hashes=hashes)
    if inv["mode"] == "git" and manifest is None:
        return inv
    if manifest is None and autodiscover is not False and inv["mode"] != "git":
        cand = default_manifest_path(root)
        if os.path.isfile(cand):
            out = verify_manifest(cand, root, hashes=hashes)
            out["manifest_source"] = "auto:<root>/%s" % MANIFEST_NAME
            return out
    if manifest:
        out = verify_manifest(manifest, root, hashes=hashes)
        out["manifest_source"] = "explicit"
        return out
    return inv


def count(root, manifest=None, autodiscover=None):
    """(first_party_count|None, inv)。None = 未验证 / 不完整。"""
    inv = inventory(root, manifest=manifest, autodiscover=autodiscover)
    if inv["mode"] == "unverified" or not inv.get("source_complete", False):
        return None, inv
    return inv["counts"]["first_party"], inv


# ───────────────────────────── CLI ─────────────────────────────
def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    ap = argparse.ArgumentParser(description="仓库源清单（唯一计数真相源）")
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
        help="仓库根（默认按本文件位置推断）")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--hashes", action="store_true", help="计算 sha256（慢，manifest 用）")
    ap.add_argument("--generate-manifest", nargs="?", const="", default=None, metavar="PATH")
    ap.add_argument("--verify-manifest", default=None, metavar="PATH")
    a = ap.parse_args(argv)

    try:
        if a.generate_manifest is not None:
            path, doc = write_manifest(a.root, a.generate_manifest or None)
            print("[inventory] 已写 manifest：%s（%d 条，含 sha256）"
                  % (path, doc["counts"]["included"]))
            return 0 if doc["source_complete"] else 2
        inv = (verify_manifest(a.verify_manifest, a.root, hashes=True)
               if a.verify_manifest else inventory(a.root, hashes=a.hashes))
    except SourceInventoryError as exc:
        print("[inventory] 拒：%s" % exc, file=sys.stderr)
        return 1

    if a.json:
        print(json.dumps(inv, ensure_ascii=False, indent=1))
    else:
        c = inv["counts"]
        print("[inventory] mode=%s ok=%s stable=%s" % (inv["mode"], inv["ok"], inv["stable"]))
        print("  raw_included=%s first_party=%s thirdparty_input=%s tracked=%s untracked=%s excluded=%s"
              % (c["included"], c.get("first_party"), c.get("thirdparty_input"),
                 c["tracked"], c["untracked"], c["excluded"]))
        print("  by_role=%s" % json.dumps(c["by_role"], ensure_ascii=False, sort_keys=True))
        if inv["mode_reason"]:
            print("  reason=%s" % inv["mode_reason"])
    return 0 if inv["mode"] != "unverified" and inv["source_complete"] else 2


if __name__ == "__main__":
    sys.exit(main())
