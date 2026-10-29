#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_source_inventory.py —— `Tool/scripts/lib/source_inventory.py` 的行为测试。

为什么要有（#43 审计结论）：
    旧 `budget.py::first_party_files()` 有三条实测缺陷，每一条都能把预算报成假绿：
      1. 12 条 **子串** skip → `.github/workflows/*.yml` 撞 `/work`、`docs/audits/*` 撞 `/audit`、
         `setup/upstream-rules.json` 撞 `/upstream`、`Tool/skill/*/evidence/*` 撞 `/evidence/`；
      2. 回退走 `os.walk` 时把**绝对路径**丢进同一判定 → 仓库装在含 `work`/`cases`/`audit`/`evidence`
         的目录下，`Tool/` 被整体剪掉，退化成 ~40 条静默绿；
      3. 父 repo 里跑 = 用别人的清单；无 git 时"随便 walk 一个数"冒充同口径。
    本文件把这些行为**逐条钉住**：每条用例驱动真实的 `source_inventory`，不在测试里复制判定逻辑。

不做什么：不在真实仓库上写 git（fixture 用 `git init`/无 commit，跑完即删）、
不复制真实 6919 文件 / 390MB、不联网、不执行样本、不读 HOME/用户配置。

用法：
    python Tool/scripts/test_source_inventory.py            # 全部
    python Tool/scripts/test_source_inventory.py -v
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "lib", "source_inventory.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("seep_source_inventory_test", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


si = _load_module()

GIT = shutil.which("git")


def _git(root, *args):
    p = subprocess.run([GIT, "-c", "core.fsmonitor=false", "-C", root] + list(args),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if p.returncode != 0:
        raise AssertionError("git %s 失败：%s" % (" ".join(args),
                                                (p.stderr or b"").decode("utf-8", "replace")[:200]))
    return p.stdout


SEED_TRACKED = [
    "Tool/scripts/engine.py",
    "Tool/config/tool.json",
    ".github/workflows/gates.yml",          # dot 源 + 路径含 "workflows"
    ".github/workflows/upstream-sync.yml",
    "setup/upstream-rules.json",            # 路径含 "upstream" 但不是 vendor 树
    "docs/audits/2026-10-25-deep-audit.md",  # 路径含 "audit"
    "Tool/skill/apkseep/evidence/capability-matrix.json",  # 路径含 "evidence"
    ".gitignore",
    ".gitattributes",
    "Tool/mcp/.baseline/tools.json",        # 状态文件，mcp-guard.py 实际读取 → 保留
    "Tool/skill/_pending/中文 目录/带 空格 的源.md",       # Unicode + 空格
    "MANUAL/BASELINE-FREEZE.md",
]
SEED_EXCLUDED = [
    "Tool/upstream/vendor.py",              # vendor 树
    "Tool/mcp/Tool/safe/x.js",              # 随包第三方树
    "Tool/cases/case01/case.json",          # 案例库（独立账）
    "Tool/work/scratch.md",                 # 工作区
    "破甲卡生成/card.md",                    # 外部输入
    "Tool/scripts/__pycache__/x.pyc",       # runtime segment
    ".pi/goals/active.md",                  # runtime 点目录
    ".playwright-mcp/page-1.yml",           # runtime 点目录
]
GITIGNORE = "\n".join([
    "__pycache__/", "*.pyc", ".pi/", ".playwright-mcp/", "/work/", "*.log", "",
])


class Fixture:
    """临时 git 仓库：`git init` + 一次 add（**不 commit**），用完删除。"""

    def __init__(self, dirname="repo"):
        self.tmp = tempfile.mkdtemp(prefix="seep-inv-")
        self._old_git_ceiling = os.environ.get("GIT_CEILING_DIRECTORIES")
        # Keep synthetic gitless exports below a process-level ceiling so git
        # cannot discover the user's enclosing repository. HOME/USERPROFILE stay untouched.
        os.environ["GIT_CEILING_DIRECTORIES"] = self.tmp
        self.root = os.path.join(self.tmp, dirname)

    def write(self, rel, data="x", tracked=True):
        path = os.path.join(self.root, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(path) or self.root, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(data)
        return path

    def init(self, tracked=(), untracked=(), excluded=(), build=True):
        os.makedirs(self.root, exist_ok=True)
        if build:
            self.write(".gitignore", GITIGNORE, tracked=True)
            for rel in tracked:
                if rel == ".gitignore":
                    continue
                self.write(rel, "tracked:" + rel)
            for rel in excluded:      # 磁盘上真实存在，但属于 vendor/runtime（不入 git）
                self.write(rel, "excluded:" + rel)
            _git(self.root, "init", "-q")
            _git(self.root, "add", ".gitignore")
            for rel in tracked:
                if rel != ".gitignore":
                    _git(self.root, "add", "--", rel)
            for rel in untracked:
                self.write(rel, "untracked:" + rel)
        else:
            os.makedirs(self.root, exist_ok=True)
        return self.root

    def plain_copy(self, name="plain"):
        """无 `.git` 的导出树副本（gitless 分支用）。嵌套 `.git` 一并剔除。"""
        dst = os.path.join(self.tmp, name)
        shutil.copytree(self.root, dst, ignore=shutil.ignore_patterns(".git"))
        return dst

    def add_nested_repo(self, rel, files=("x.py",), link=False):
        """在 root 里造一个**嵌套独立 git repo**（未注册 submodule）。

        `link=True` 时另把它 `git add` 成 gitlink（mode 160000）—— 用来验证 F2。
        不递归、不拉取、不联网。
        """
        nested = os.path.join(self.root, rel.replace("/", os.sep))
        os.makedirs(nested, exist_ok=True)
        for name in files:
            with open(os.path.join(nested, name), "w", encoding="utf-8") as f:
                f.write("nested:" + name)
        _git(nested, "init", "-q")
        _git(nested, "add", ".")
        if link:
            _git(self.root, "add", "--", rel)
        return nested

    def commit(self, root=None, message="fixture baseline"):
        """提交临时夹具；身份只写在命令级，不读取或修改用户 Git 配置。"""
        target = root or self.root
        _git(target, "-c", "user.name=Seep Fixture",
             "-c", "user.email=seep-fixture@example.invalid",
             "commit", "-q", "-m", message)

    def clean(self):
        """删除 fixture。

        ★ Windows 下 `.git/objects/*` 是**只读**属性，`shutil.rmtree(..., ignore_errors=True)`
          会失败且不报 —— 实测漏了 368 个 `seep-inv-*` 临时目录在 `D:/tmp`。
          所以先递归清只读位再真删，删不掉就报错（不静默积垃圾），也不用已弃用的 `onerror`。
        """
        if not os.path.isdir(self.tmp):
            return
        for root, dirs, names in os.walk(self.tmp):
            for name in dirs + names:
                path = os.path.join(root, name)
                try:
                    os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
                except OSError:
                    pass
        try:
            os.chmod(self.tmp, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
        except OSError:
            pass
        shutil.rmtree(self.tmp)
        if self._old_git_ceiling is None:
            os.environ.pop("GIT_CEILING_DIRECTORIES", None)
        else:
            os.environ["GIT_CEILING_DIRECTORIES"] = self._old_git_ceiling
        if os.path.exists(self.tmp):
            raise AssertionError("fixture 清理后仍存在：%s" % self.tmp)


def paths(inv):
    return sorted(f["path"] for f in inv["files"])


@unittest.skipUnless(GIT, "缺 git：inventory 的核心语义无法验证（不是 skip 掉的通过）")
class GitInventoryTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()
        self.root = self.fx.init(tracked=SEED_TRACKED, excluded=SEED_EXCLUDED,
                                 untracked=["Tool/scripts/new_module.py", "docs/新 目录/未跟踪.md"])

    def tearDown(self):
        self.fx.clean()

    # ── 1. 口径：只排准确 segment，不排子串 ──────────────────────────
    def test_scope_includes_real_sources_and_excludes_vendor_runtime(self):
        inv = si.collect(self.root)
        self.assertEqual(inv["mode"], "git")
        got = set(paths(inv))
        for rel in SEED_TRACKED:
            self.assertIn(rel, got, "真实源被误排：%s" % rel)
        for rel in SEED_EXCLUDED:
            self.assertNotIn(rel, got, "vendor/runtime 被误计入：%s" % rel)
        # 未跟踪未忽略的两个也必须在（含空格 + Unicode + 新 module）
        self.assertIn("Tool/scripts/new_module.py", got)
        self.assertIn("docs/新 目录/未跟踪.md", got)
        # 排除项必须带原因（不是静默丢弃）。.gitignore 拦掉的 runtime 路径本来就不在
        # git 枚举里，所以只对「磁盘上有、且未被 ignore」的 vendor/runtime 路径要求理由。
        reasons = {e["path"]: e["reason"] for e in inv["excluded"]}
        for rel in ("Tool/upstream/vendor.py", "Tool/mcp/Tool/safe/x.js",
                    "Tool/cases/case01/case.json", "Tool/work/scratch.md",
                    "破甲卡生成/card.md"):
            self.assertIn(rel, reasons, "排除项没留原因：%s" % rel)
            self.assertTrue(reasons[rel].strip())

    def test_counts_split_tracked_and_untracked(self):
        inv = si.collect(self.root)
        c = inv["counts"]
        self.assertEqual(c["tracked"] + c["untracked"], c["included"])
        self.assertEqual(c["tracked"], len(SEED_TRACKED))
        self.assertEqual(c["untracked"], 2)

    def test_staged_deletion_is_audited_but_not_a_worktree_missing_file(self):
        fx = Fixture("staged-deletion")
        try:
            root = fx.init(tracked=["Tool/src/keep.py", "Tool/src/gone.py"])
            fx.commit(root)
            _git(root, "rm", "-q", "--", "Tool/src/gone.py")

            inv = si.collect(root)
            self.assertTrue(inv["source_complete"])
            self.assertEqual(inv["missing_tracked"], [])
            self.assertEqual([e["path"] for e in inv["deleted_staged"]],
                             ["Tool/src/gone.py"])
            self.assertEqual(inv["counts"]["deleted_staged"], 1)
            self.assertEqual(paths(inv), [".gitignore", "Tool/src/keep.py"])

            manifest = si.build_manifest(root)
            self.assertEqual([e["path"] for e in manifest["deleted_staged"]],
                             ["Tool/src/gone.py"])
            self.assertTrue(manifest["source_complete"])
        finally:
            fx.clean()

    def test_unstaged_deletion_remains_a_real_missing_source(self):
        fx = Fixture("unstaged-deletion")
        try:
            root = fx.init(tracked=["Tool/src/keep.py", "Tool/src/gone.py"])
            fx.commit(root)
            os.remove(os.path.join(root, "Tool", "src", "gone.py"))

            inv = si.collect(root)
            self.assertFalse(inv["source_complete"])
            self.assertEqual([e["path"] for e in inv["missing_tracked"]],
                             ["Tool/src/gone.py"])
            self.assertEqual(inv["deleted_staged"], [])
            self.assertEqual(inv["counts"]["deleted_staged"], 0)
        finally:
            fx.clean()

    def test_mixed_staged_and_unstaged_deletions_keep_both_states_visible(self):
        fx = Fixture("mixed-deletion")
        try:
            root = fx.init(tracked=[
                "Tool/src/keep.py", "Tool/src/staged.py", "Tool/src/unstaged.py",
            ])
            fx.commit(root)
            _git(root, "rm", "-q", "--", "Tool/src/staged.py")
            os.remove(os.path.join(root, "Tool", "src", "unstaged.py"))

            inv = si.collect(root)
            self.assertFalse(inv["source_complete"])
            self.assertEqual([e["path"] for e in inv["deleted_staged"]],
                             ["Tool/src/staged.py"])
            self.assertEqual([e["path"] for e in inv["missing_tracked"]],
                             ["Tool/src/unstaged.py"])
            self.assertEqual(inv["counts"]["deleted_staged"], 1)
            self.assertEqual(inv["counts"]["missing"], 1)
        finally:
            fx.clean()

    def test_staged_deletion_change_during_collection_is_unstable(self):
        fx = Fixture("staged-change")
        try:
            root = fx.init(tracked=["Tool/src/keep.py", "Tool/src/gone.py"])
            fx.commit(root)
            _git(root, "rm", "-q", "--", "Tool/src/gone.py")
            original_git = si._git
            diff_calls = 0

            def changing_git(git_root, *args, **kwargs):
                nonlocal diff_calls
                out = original_git(git_root, *args, **kwargs)
                if args == (
                    "diff", "--cached", "--name-only", "--diff-filter=D", "-z", "--"
                ):
                    diff_calls += 1
                    if diff_calls == 1:
                        _git(root, "restore", "--staged", "--", "Tool/src/gone.py")
                return out

            with mock.patch.object(si, "_git", side_effect=changing_git):
                inv = si.collect(root)
            self.assertFalse(inv["stable"])
            self.assertFalse(inv["source_complete"])
        finally:
            fx.clean()

    def test_relative_posix_paths_and_stable_order(self):
        inv = si.collect(self.root)
        got = paths(inv)
        self.assertEqual(got, sorted(got, key=lambda s: s.encode("utf-8", "surrogateescape")))
        for f in inv["files"]:
            self.assertNotIn("\\", f["path"])
            self.assertFalse(f["path"].startswith("/"))
            self.assertGreaterEqual(f["size"], 0)
        # 两次采集必须一致（稳定排序，不受文件系统顺序影响）
        self.assertEqual(got, paths(si.collect(self.root)))

    # ── 2. root 名字里带 work/cases/audit/evidence 不影响结果 ─────────
    def test_root_name_with_work_cases_audit_evidence_is_irrelevant(self):
        baseline = si.collect(self.root)["counts"]["included"]
        for name in ("repo-work", os.path.join("cases", "repo"),
                     os.path.join("audit", "repo"), "repo-evidence"):
            fx = Fixture(dirname=name)
            try:
                fx.init(tracked=SEED_TRACKED, untracked=["Tool/scripts/new_module.py"])
                n = si.collect(fx.root)["counts"]["included"]
                self.assertEqual(n, len(SEED_TRACKED) + 1,
                                 "root 名字含敏感词改变了计数：%s → %s（基线 %s）" % (name, n, baseline))
            finally:
                fx.clean()

    # ── 3. 父 repo 误用必须拒 ────────────────────────────────────────
    def test_parent_repo_misuse_is_rejected(self):
        nested = os.path.join(self.root, "Tool", "scripts")   # 在 repo 内部的普通子目录
        with self.assertRaises(si.SourceInventoryError) as ctx:
            si.collect(nested)
        self.assertIn("顶层", str(ctx.exception))

    def test_git_toplevel_matches_root(self):
        self.assertEqual(si.git_toplevel(self.root), os.path.realpath(self.root))

    # ── 4. manifest：生成 / 同口径 / 逐 byte 一致 ──────────────────────
    def test_gitless_manifest_reproduces_scope_and_bytes(self):
        inv_git = si.collect(self.root)
        manifest = si.build_manifest(self.root)
        self.assertEqual(manifest["counts"]["included"], inv_git["counts"]["included"])

        # 复制到**没有 .git** 的目录：走 gitless 分支
        plain = os.path.join(self.fx.tmp, "plain")
        shutil.copytree(self.root, plain, ignore=shutil.ignore_patterns(".git"))
        self.assertIsNone(si.git_toplevel(plain), "夹具复制后仍被认成 git 仓库")

        got = si.verify_manifest(manifest, plain, hashes=True)
        self.assertEqual(got["mode"], "manifest")
        self.assertEqual(got["counts"]["included"], inv_git["counts"]["included"])
        self.assertEqual(paths(got), paths(inv_git))
        by_path = {f["path"]: f for f in inv_git["files"]}
        for f in got["files"]:
            self.assertEqual(f["sha256"], si._sha256(os.path.join(plain, f["path"].replace("/", os.sep))))
            self.assertEqual(f["size"], by_path[f["path"]]["size"])

        # 无 git 且无 manifest → 未验证，**不返回 walk 出来的小数字**
        loose = si.inventory(plain)
        self.assertEqual(loose["mode"], "unverified")
        self.assertFalse(loose["ok"])
        self.assertEqual(loose["counts"]["included"], 0)
        n, inv = si.count(plain)
        self.assertIsNone(n, "gitless 无 manifest 不得返回计数")
        self.assertEqual(inv["mode"], "unverified")

    def test_manifest_rejects_stale_missing_escape_and_extra(self):
        manifest = si.build_manifest(self.root)
        plain = os.path.join(self.fx.tmp, "plain2")
        shutil.copytree(self.root, plain, ignore=shutil.ignore_patterns(".git"))
        n_before = manifest["counts"]["included"]

        # stale：改一个字节
        target = os.path.join(plain, "Tool", "scripts", "engine.py")
        with open(target, "rb") as f:
            original = f.read()
        with open(target, "wb") as f:
            f.write(original + b"tamper")
        with self.assertRaises(si.SourceInventoryError) as ctx:
            si.verify_manifest(manifest, plain)
        self.assertIn("stale", str(ctx.exception))
        # 恢复原字节 → 回正
        with open(target, "wb") as f:
            f.write(original)
        self.assertEqual(si.verify_manifest(manifest, plain)["counts"]["included"], n_before)

        # missing：删一个文件
        gone = os.path.join(plain, ".github", "workflows", "gates.yml")
        with open(gone, "rb") as f:
            keep = f.read()
        os.remove(gone)
        with self.assertRaises(si.SourceInventoryError) as ctx:
            si.verify_manifest(manifest, plain)
        self.assertIn("stale", str(ctx.exception))
        with open(gone, "wb") as f:
            f.write(keep)
        self.assertEqual(si.verify_manifest(manifest, plain)["counts"]["included"], n_before)

        # escape / absolute
        # A generated, deliberately invalid Windows reference; never a local locator.
        windows_absolute = "/".join(("Z:", "x.py"))
        for bad in ("../outside.py", "/abs/path.py", windows_absolute):
            broken = json.loads(json.dumps(manifest))
            broken["files"][0]["path"] = bad
            with self.assertRaises(si.SourceInventoryError):
                si.verify_manifest(broken, plain)

        # extraSource（在**能准确枚举 ignore 语义**的 git 根上验 → 硬拒）
        extra_rel = "Tool/scripts/added_after_export.py"
        self.fx.write(extra_rel, tracked=False)
        try:
            with self.assertRaises(si.SourceInventoryError) as ctx:
                si.verify_manifest(manifest, self.root)
            self.assertIn("extraSource", str(ctx.exception))
        finally:
            os.remove(os.path.join(self.root, extra_rel))
        # 无 git 的导出树无法判 ignore 语义 → extraSource 只能给 unverified，不可冒充通过
        self.fx.write(extra_rel, tracked=False)
        try:
            n2 = manifest["counts"]["included"]
            inv = si.verify_manifest(manifest, plain)
            self.assertEqual(inv["counts"]["included"], n2)  # plain 未改，仍可验
            self.fx.write(os.path.join(plain, extra_rel), tracked=False)
            inv2 = si.verify_manifest(manifest, plain)
            self.assertEqual(inv2["mode"], "unverified")
            self.assertFalse(inv2["ok"])
            os.remove(os.path.join(plain, extra_rel))
        finally:
            os.remove(os.path.join(self.root, extra_rel))

    def test_manifest_schema_and_self_consistency_rejected(self):
        manifest = si.build_manifest(self.root)
        for mutate, needle in (
            (lambda d: d.update(schema="other/1"), "schema"),
            (lambda d: d.update(policy="other"), "schema"),
            (lambda d: d["counts"].update(included=d["counts"]["included"] + 1), "不一致"),
            (lambda d: d.pop("files"), "闭包"),
        ):
            broken = json.loads(json.dumps(manifest))
            mutate(broken)
            with self.assertRaises(si.SourceInventoryError) as ctx:
                si.verify_manifest(broken, self.root)
            self.assertIn(needle, str(ctx.exception))

    def test_manifest_excludes_itself_to_avoid_self_reference(self):
        manifest = si.build_manifest(self.root)
        self.assertNotIn(si.MANIFEST_NAME, [f["path"] for f in manifest["files"]])
        # 真实写出后，re-collect 也不会把 manifest 自身算进计数
        path, doc = si.write_manifest(self.root)
        try:
            self.assertTrue(os.path.isfile(path))
            after = si.collect(self.root)
            self.assertNotIn(si.MANIFEST_NAME, paths(after))
            self.assertEqual(after["counts"]["included"], doc["counts"]["included"])
        finally:
            os.remove(path)

    # ── 5. 加/删文件 → 计数跟着动（不是恒绿常量）──────────────────────
    def test_count_tracks_tree_changes(self):
        base = si.collect(self.root)["counts"]["included"]
        self.fx.write("Tool/scripts/extra_one.py", tracked=False)
        self.assertEqual(si.collect(self.root)["counts"]["included"], base + 1)
        os.remove(os.path.join(self.root, "Tool", "scripts", "extra_one.py"))
        self.assertEqual(si.collect(self.root)["counts"]["included"], base)


class CompletenessTests(unittest.TestCase):
    """F1：已跟踪但工作树被删 —— 不得把 OVER 洗成 OK。

    主裁定（F1 必修）：区分「实际存在 count」与 `missing_tracked` / `source_complete`；
    有未解决缺失时消费者必须不完整（rc2/UNKN），而不是拿小数字判绿。
    不猜“缺失 = 用户批准删除”（本批不造 tombstone/审批系统，不改 Git 索引）。
    """

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "seep_budget_c1", os.path.join(HERE, "budget.py"))
        cls.budget = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.budget)

    def _budget_json(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self.budget.main(["--json"])
        return rc, json.loads(buf.getvalue())

    @unittest.skipUnless(GIT, "缺 git")
    def test_missing_tracked_makes_incomplete_and_blockers_green(self):
        fx = Fixture("missing")
        try:
            names = ["Tool/m%d.py" % i for i in range(1, 7)]
            root = fx.init(tracked=names + [".gitignore"])
            full = si.collect(root)
            self.assertTrue(full["source_complete"])
            self.assertEqual(full["counts"]["included"], len(names) + 1)
            self.assertEqual(full["counts"]["missing"], 0)

            # 删掉 2 个**已跟踪**文件（不 stage、不改索引）→ raw 数字下降，但完整性必须变红
            for rel in names[:2]:
                os.remove(os.path.join(root, rel.replace("/", os.sep)))
            gap = si.collect(root)
            self.assertEqual(gap["counts"]["included"], len(names) - 1)   # 4 + .gitignore
            self.assertEqual(gap["counts"]["missing"], 2)
            self.assertFalse(gap["source_complete"], "缺失必须让完整性变红")
            self.assertEqual([e["path"] for e in gap["missing_tracked"]], names[:2])
            # 数字与完整性分开报：count() 不得给出可判绿的数字
            n, inv = si.count(root)
            self.assertIsNone(n, "缺失未解决时 count() 不得返回数字")
            self.assertFalse(inv["source_complete"])

            # restore → 回正（raw 与完整性一起回来）
            for rel in names[:2]:
                fx.write(rel, "tracked:" + rel)
            back = si.collect(root)
            self.assertTrue(back["source_complete"])
            self.assertEqual(back["counts"]["included"], len(names) + 1)
            self.assertEqual(back["counts"]["missing"], 0)
            n2, _i = si.count(root)
            self.assertEqual(n2, len(names) + 1)
        finally:
            fx.clean()

    @unittest.skipUnless(GIT, "缺 git")
    def test_missing_does_not_flip_limit_to_green_in_budget(self):
        """用真实 budget.main() 验：raw 从 951 降到 949（跨门槛），状态不得从 OVER 变 OK。"""
        fx = Fixture("limit")
        try:
            # 951 个场景太重：直接合成一个 limit=6 的等价断言（同一代码路径，不复制判定）
            names = ["Tool/m%d.py" % i for i in range(6)] + [".gitignore"]   # 7
            root = fx.init(tracked=names)
            for rel in names[1:3]:      # 删 2 → 5
                os.remove(os.path.join(root, rel.replace("/", os.sep)))
            inv = si.collect(root)
            self.assertEqual(inv["counts"]["included"], 5)      # 跨过 limit=6
            self.assertFalse(inv["source_complete"])
            self.assertEqual(si.count(root)[0], None)
            # 同一条代码路径在 budget 里的表现：value=None → UNKN，不可能是 OK
            original = self.budget.first_party_inventory
            self.budget.first_party_inventory = lambda: (None, inv)
            try:
                rc, doc = self._budget_json()
            finally:
                self.budget.first_party_inventory = original
            row = [r for r in doc["budget"] if r["item"] == "first-party 引擎文件"][0]
            self.assertIsNone(row["value"])
            self.assertFalse(row["ok"])
            self.assertTrue(row.get("unverified"))
            self.assertEqual(rc, 2, "缺失/incomplete 必须是 rc=2，不得 0 绿也不得 1 OVER")
            self.assertFalse(doc["source_inventory"]["source_complete"])
            self.assertEqual(doc["source_inventory"]["missing_tracked"], ["Tool/m1.py", "Tool/m2.py"])
        finally:
            fx.clean()

    @unittest.skipUnless(GIT, "缺 git")
    def test_budget_human_output_names_missing(self):
        fx = Fixture("missing-human")
        try:
            root = fx.init(tracked=["Tool/a.py", "Tool/b.py", ".gitignore"])
            os.remove(os.path.join(root, "Tool", "b.py"))
            original = self.budget.first_party_inventory
            # 换成真实 collect：验证 first_party_inventory 本身会折成 None
            self.budget.first_party_inventory = lambda: (
                (lambda inv: (None if not inv["source_complete"] else inv["counts"]["included"], inv))(
                    si.collect(root)))
            import contextlib
            import io
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    rc = self.budget.main([])
            finally:
                self.budget.first_party_inventory = original
            human = buf.getvalue()
            self.assertIn("INCOMPLETE", human)
            self.assertIn("missingTracked=1", human)
            self.assertIn("Tool/b.py", human)
            self.assertEqual(rc, 2)
        finally:
            fx.clean()

    @unittest.skipUnless(GIT, "缺 git")
    def test_missing_is_recorded_in_manifest_and_kept_incomplete(self):
        """manifest 必须把 missing 声明下去，**不能**变成“已批准删除”。"""
        fx = Fixture("missing-man")
        try:
            root = fx.init(tracked=["Tool/a.py", "Tool/b.py", ".gitignore"])
            os.remove(os.path.join(root, "Tool", "b.py"))
            doc = si.build_manifest(root)
            self.assertFalse(doc["source_complete"])
            self.assertEqual([e["path"] for e in doc["missing_tracked"]], ["Tool/b.py"])
            self.assertNotIn("Tool/b.py", [f["path"] for f in doc["files"]],
                             "缺失文件不得当成 size=0 的 source 条目")
            plain = fx.plain_copy("plain")
            mpath = os.path.join(plain, si.MANIFEST_NAME)
            with open(mpath, "w", encoding="utf-8") as f:
                json.dump(doc, f, ensure_ascii=False)
            inv = si.inventory(plain)          # 自动发现
            self.assertEqual(inv["mode"], "manifest")
            self.assertFalse(inv["source_complete"], "导出的清单自己也承认不完整")
            self.assertIsNone(si.count(plain)[0])
        finally:
            fx.clean()


class GitlinkTests(unittest.TestCase):
    """F2：gitlink / 嵌套 .git 不得记 size=0 假 source；不递归、不拉取。"""

    @unittest.skipUnless(GIT, "缺 git")
    def test_nested_repo_is_unsupported_not_a_source_entry(self):
        fx = Fixture("nested")
        try:
            root = fx.init(tracked=["Tool/a.py", ".gitignore"])
            fx.add_nested_repo("vendorish/dep")     # 未注册 submodule，git 只报 "vendorish/dep/"
            inv = si.collect(root)
            got = paths(inv)
            self.assertNotIn("vendorish/dep", got)
            self.assertNotIn("vendorish/dep/", got)
            self.assertFalse(any(p.endswith("/") for p in got), "不得留 trailing-slash 假条目")
            self.assertEqual([e["path"] for e in inv["unsupported"]], ["vendorish/dep"])
            self.assertIn("nested-repo", inv["unsupported"][0]["reason"])
            self.assertFalse(inv["source_complete"])
            self.assertEqual(inv["counts"]["unsupported"], 1)
            self.assertIsNone(si.count(root)[0], "未知/未物化依赖不得当可判绿")
            # 不得递归进去把内层文件当 source
            self.assertNotIn("vendorish/dep/x.py", got)
        finally:
            fx.clean()

    @unittest.skipUnless(GIT, "缺 git")
    def test_gitlink_under_vendor_root_stays_excluded(self):
        fx = Fixture("gitlink-vendor")
        try:
            root = fx.init(tracked=["Tool/a.py", ".gitignore"])
            fx.add_nested_repo("Tool/upstream/dep", link=False)
            inv = si.collect(root)
            self.assertNotIn("Tool/upstream/dep", paths(inv))
            self.assertEqual(inv["unsupported"], [],
                             "已在明确 vendor 根下的未物化依赖保持 excluded，不进 unsupported")
            reasons = {e["path"]: e["reason"] for e in inv["excluded"]}
            self.assertIn("Tool/upstream/dep", reasons)
            self.assertTrue(reasons["Tool/upstream/dep"].startswith("vendor:"))
            self.assertTrue(inv["source_complete"], "vendor 下的未知依赖不污染引擎完整性")
        finally:
            fx.clean()


class DefaultManifestTests(unittest.TestCase):
    """F3：导出包自带默认清单必须能被 inventory/budget/preflight 入口消费。"""

    @unittest.skipUnless(GIT, "缺 git")
    def test_export_autodiscovery_same_count(self):
        fx = Fixture("export")
        try:
            root = fx.init(tracked=["Tool/scripts/a.py", "Tool/config/c.json", ".gitignore"],
                           untracked=["Tool/scripts/new.py"])
            doc = si.build_manifest(root)
            plain = fx.plain_copy("plain")
            mpath = os.path.join(plain, si.MANIFEST_NAME)
            with open(mpath, "w", encoding="utf-8") as f:
                json.dump(doc, f, ensure_ascii=False)
            inv = si.inventory(plain)                       # 不显式传 manifest
            self.assertEqual(inv["mode"], "manifest")
            self.assertTrue(inv["manifest_source"].startswith("auto:"))
            self.assertEqual(inv["counts"]["included"], doc["counts"]["included"])
            self.assertTrue(inv["source_complete"])
            self.assertEqual(si.count(plain)[0], doc["counts"]["included"])
            # autodiscover=False → 回到未验证（不许静默搜别处）
            self.assertEqual(si.inventory(plain, autodiscover=False)["mode"], "unverified")
            # 显式 manifest 优先于默认/优先于 git（同一 validator，不另立规则）
            other = si.build_manifest(root)
            inv2 = si.inventory(plain, manifest=other)
            self.assertEqual(inv2["manifest_source"], "explicit")
            self.assertEqual(inv2["counts"]["included"], other["counts"]["included"])
            inv3 = si.inventory(root, manifest=other)      # 真 git 根 + 显式清单 → 仍按清单
            self.assertEqual(inv3["mode"], "manifest")
            self.assertEqual(inv3["manifest_source"], "explicit")
        finally:
            fx.clean()

    @unittest.skipUnless(GIT, "缺 git")
    def test_repo_git_source_wins_over_stale_manifest_in_root(self):
        """真 git 源**永不**被根内过期 manifest 覆盖（防“过期清单冒充源”）。"""
        fx = Fixture("stale-man")
        try:
            root = fx.init(tracked=["Tool/a.py", "Tool/b.py", ".gitignore"])
            stale = si.build_manifest(root)
            stale["counts"]["included"] = 999      # 故意过期
            stale["files"] = stale["files"][:1]
            stale["counts"]["included"] = len(stale["files"])
            with open(os.path.join(root, si.MANIFEST_NAME), "w", encoding="utf-8") as f:
                json.dump(stale, f, ensure_ascii=False)
            inv = si.inventory(root)                # git 可用 → 忽略 manifest
            self.assertEqual(inv["mode"], "git")
            self.assertEqual(inv["counts"]["included"], 3)
            self.assertNotIn("manifest_source", inv or {})
        finally:
            fx.clean()

    def test_default_manifest_path_is_exact_name_only(self):
        root = os.path.join(tempfile.gettempdir(), "seep-inv-namecheck")
        self.assertEqual(si.default_manifest_path(root),
                         os.path.join(os.path.realpath(root), "source-inventory.manifest.json"))
        # 不搜父目录/版本号：路径只由 root 决定
        self.assertEqual(os.path.dirname(si.default_manifest_path(root)), os.path.realpath(root))

    @unittest.skipUnless(GIT, "缺 git")
    def test_bad_or_missing_manifest_still_unverified(self):
        fx = Fixture("badman")
        try:
            root = fx.init(tracked=["Tool/a.py", ".gitignore"])
            plain = fx.plain_copy("plain")
            with open(os.path.join(plain, si.MANIFEST_NAME), "w", encoding="utf-8") as f:
                f.write("{ not json")
            with self.assertRaises(si.SourceInventoryError):
                si.inventory(plain)                  # 坏清单：拒，不许 walk 兜底
            os.remove(os.path.join(plain, si.MANIFEST_NAME))
            inv = si.inventory(plain)
            self.assertEqual(inv["mode"], "unverified")
            self.assertIsNone(si.count(plain)[0])
        finally:
            fx.clean()


class StabilityModeTests(unittest.TestCase):
    """F4：include_untracked=False 必须用**同一策略**比两次，不能与 all 模式比成伪不稳。"""

    @unittest.skipUnless(GIT, "缺 git")
    def test_tracked_only_stability_is_not_false_negative(self):
        fx = Fixture("stable4")
        try:
            root = fx.init(tracked=["Tool/a.py", "Tool/b.py", ".gitignore"],
                           untracked=["Tool/c.py"])
            all_mode = si.collect(root, include_untracked=True)
            tr_mode = si.collect(root, include_untracked=False)
            self.assertTrue(all_mode["stable"], "默认模式必须稳")
            self.assertTrue(tr_mode["stable"], "trackedOnly 不得与 all 模式比成伪不稳")
            self.assertEqual(all_mode["counts"]["included"] - tr_mode["counts"]["included"], 1)

            # tracked 稳定：untracked 的合法变化不影响 trackedOnly 的 stable
            fx.write("Tool/d.py", "untracked:d")
            fx.write("Tool/e.py", "untracked:e")
            tr2 = si.collect(root, include_untracked=False)
            self.assertTrue(tr2["stable"], "untracked 变化不应让 trackedOnly 不稳")
            self.assertEqual(tr2["counts"]["included"], tr_mode["counts"]["included"])
            all2 = si.collect(root, include_untracked=True)
            self.assertTrue(all2["stable"], "all 模式在同一快照里也应稳")
            self.assertEqual(all2["counts"]["included"], all_mode["counts"]["included"] + 2)
        finally:
            fx.clean()


class ClassifyUnitTests(unittest.TestCase):
    """纯函数级：不需要 git。"""

    def test_segment_not_substring(self):
        for rel in (".github/workflows/gates.yml", "setup/upstream-rules.json",
                    "docs/audits/x.md", "Tool/skill/apkseep/evidence/m.json",
                    "Tool/mcp/.baseline/tools.json", ".mcp.json", ".gitignore"):
            self.assertTrue(si.classify(rel)[0], "被误排：%s" % rel)
        for rel in ("Tool/upstream/a/b.py", "Tool/mcp/Tool/safe/x.js", "Tool/cases/c/case.json",
                    "Tool/work/x.md", "a/node_modules/b.js", "a/__pycache__/c.pyc",
                    ".pi/goals/x.md", "docs/.pytest_cache/x"):
            self.assertFalse(si.classify(rel)[0], "被误计入：%s" % rel)

    def test_manifest_name_excluded(self):
        self.assertFalse(si.classify(si.MANIFEST_NAME)[0])
        self.assertEqual(si.classify(si.MANIFEST_NAME)[2], "meta")

    def test_normalize_rel_rejects_escapes(self):
        for bad in ("", "/x", "../x", "a/../../b", "C:/x"):
            with self.assertRaises(si.SourceInventoryError):
                si.normalize_rel(bad)
        self.assertEqual(si.normalize_rel("./a//b/"), "a/b")

    def test_role_is_annotation_only(self):
        # Tool/samples 初始标 data，但**仍然计入**（本批不靠重分类减数）
        keep, _reason, role = si.classify("Tool/samples/real/a.apk")
        self.assertTrue(keep)
        self.assertEqual(role, "data")

    def test_git_byte_paths_do_not_collapse_on_invalid_utf8(self):
        decoded = si._zsplit(b"ok.py\0bad-\xff.py\0bad-\xfe.py\0")
        self.assertEqual(len(decoded), 3)
        self.assertEqual(len(set(decoded)), 3)
        self.assertFalse(any("\ufffd" in name for name in decoded))

    def test_gitless_walk_permission_error_is_not_silently_skipped(self):
        def blocked_walk(_root, onerror=None):
            onerror(PermissionError("denied"))
            return iter(())

        with mock.patch.object(si, "_git", return_value=(None, "not a repo")), \
                mock.patch.object(si.os, "walk", side_effect=blocked_walk):
            with self.assertRaises(si.SourceInventoryError):
                si._enumerate_present("/tmp/not-used")


def make_role_fixture():
    fx = Fixture("roles")
    root = fx.init(tracked=["Tool/samples/real/README.md"])
    source_url = "https://example.invalid/vendor"
    fx.write("Tool/samples/real/README.md", source_url + "\n")
    listed = "Tool/samples/real/vendor/input.bin"
    unlisted = "Tool/samples/real/vendor/generator.py"
    fx.write(listed, "external-bytes")
    fx.write(unlisted, "generated-here")
    full = os.path.join(root, listed.replace("/", os.sep))
    doc = {
        "schema": si.FIXTURE_SCHEMA,
        "root": si.FIXTURE_ROOT,
        "sources": {"vendor": {"url": source_url,
                                "evidence": "Tool/samples/real/README.md"}},
        "files": [{"path": listed, "source": "vendor",
                   "size": os.path.getsize(full), "sha256": si._sha256(full)}],
    }
    fx.write("Tool/config/thirdparty-fixtures.json", json.dumps(doc, ensure_ascii=False))
    return fx, root, listed, unlisted


class ThirdPartyRoleTests(unittest.TestCase):
    """显式来源/字节证据才可移出 first-party；伪 role 不能洗白。"""

    def test_unlisted_sample_stays_first_party(self):
        fx, root, listed, unlisted = make_role_fixture()
        try:
            inv = si.collect(root)
            self.assertTrue(inv["source_complete"])
            self.assertEqual(inv["counts"]["thirdparty_input"], 1)
            self.assertEqual(inv["counts"]["first_party"] + inv["counts"]["thirdparty_input"],
                             inv["counts"]["included"])
            roles = {f["path"]: f["role"] for f in inv["files"]}
            self.assertEqual(roles[listed], "thirdparty_input")
            self.assertEqual(roles[unlisted], "first_party")
        finally:
            fx.clean()

    def test_source_url_and_document_anchor_are_bound(self):
        fx, root, _listed, _unlisted = make_role_fixture()
        try:
            cfg = os.path.join(root, "Tool", "config", "thirdparty-fixtures.json")
            evidence = os.path.join(root, "Tool", "samples", "real", "README.md")
            with open(cfg, encoding="utf-8") as f:
                doc = json.load(f)
            original_url = doc["sources"]["vendor"]["url"]
            with open(evidence, encoding="utf-8") as f:
                original_text = f.read()

            doc["sources"]["vendor"]["url"] = "https://example.invalid/changed"
            with open(cfg, "w", encoding="utf-8") as f:
                json.dump(doc, f)
            rejected = si.collect(root)
            self.assertFalse(rejected["source_complete"])
            self.assertTrue(any("source='vendor'" in e and "sources['vendor'].url" in e
                                for e in rejected["errors"]))
            self.assertFalse(any("changed" in e for e in rejected["errors"]))

            doc["sources"]["vendor"]["url"] = original_url
            with open(cfg, "w", encoding="utf-8") as f:
                json.dump(doc, f)
            self.assertTrue(si.collect(root)["source_complete"])

            with open(evidence, "w", encoding="utf-8") as f:
                f.write("source documentation without the anchor\n")
            rejected_doc = si.collect(root)
            self.assertFalse(rejected_doc["source_complete"])
            self.assertTrue(any("source='vendor'" in e and "sources['vendor'].url" in e
                                for e in rejected_doc["errors"]))
            with open(evidence, "w", encoding="utf-8") as f:
                f.write(original_text)
            self.assertTrue(si.collect(root)["source_complete"])
        finally:
            fx.clean()

    def test_resolved_fixture_paths_cannot_escape_root(self):
        fx, root, _listed, _unlisted = make_role_fixture()
        try:
            with self.assertRaises(si.SourceInventoryError):
                si._rooted_file(root, "../outside.txt", "test.path")
        finally:
            fx.clean()

    def test_fixture_hash_missing_and_pseudo_vendor_are_incomplete(self):
        fx, root, listed, _unlisted = make_role_fixture()
        try:
            cfg = os.path.join(root, "Tool", "config", "thirdparty-fixtures.json")
            with open(cfg, encoding="utf-8") as f:
                doc = json.load(f)
            doc["files"][0]["sha256"] = "0" * 64
            with open(cfg, "w", encoding="utf-8") as f:
                json.dump(doc, f)
            inv = si.collect(root)
            self.assertFalse(inv["source_complete"])
            self.assertIsNone(si.count(root)[0])
        finally:
            fx.clean()

        fx, root, listed, _unlisted = make_role_fixture()
        try:
            os.remove(os.path.join(root, listed.replace("/", os.sep)))
            inv = si.collect(root)
            self.assertFalse(inv["source_complete"])
            self.assertIsNone(si.count(root)[0])
        finally:
            fx.clean()

        fx, root, listed, _unlisted = make_role_fixture()
        try:
            cfg = os.path.join(root, "Tool", "config", "thirdparty-fixtures.json")
            with open(cfg, encoding="utf-8") as f:
                doc = json.load(f)
            doc["files"][0]["path"] = "Tool/scripts/fake-vendor.bin"
            with open(cfg, "w", encoding="utf-8") as f:
                json.dump(doc, f)
            inv = si.collect(root)
            self.assertFalse(inv["source_complete"])
            self.assertTrue(any("越界" in e for e in inv["errors"]))
        finally:
            fx.clean()

    def test_manifest_recomputes_role_and_gitless_restore_control(self):
        fx, root, listed, _unlisted = make_role_fixture()
        try:
            manifest = si.build_manifest(root)
            first = next(f for f in manifest["files"] if f["role"] == "first_party")
            forged = json.loads(json.dumps(manifest))
            forged_first = next(f for f in forged["files"] if f["path"] == first["path"])
            forged_first["role"] = "thirdparty_input"
            with self.assertRaises(si.SourceInventoryError):
                si.verify_manifest(forged, root)

            plain = fx.plain_copy("isolated-export")
            with open(os.path.join(plain, si.MANIFEST_NAME), "w", encoding="utf-8") as f:
                json.dump(manifest, f)
            good = si.inventory(plain)
            self.assertEqual(good["mode"], "manifest")
            extra = os.path.join(plain, "Tool", "samples", "real", "vendor", "extra.js")
            with open(extra, "w", encoding="utf-8") as f:
                f.write("new")
            bad = si.inventory(plain)
            self.assertEqual(bad["mode"], "unverified")
            os.remove(extra)
            restored = si.inventory(plain)
            self.assertEqual(restored["mode"], "manifest")
        finally:
            fx.clean()

@unittest.skipUnless(GIT, "缺 git")
class InventoryBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture("boundaries")
        self.root = self.fx.init(tracked=["Tool/src/engine.py"])
        self.addCleanup(self.fx.clean)

    def _link_outside_source(self):
        source_dir = os.path.join(self.root, "Tool", "src")
        outside = os.path.join(self.fx.tmp, "outside")
        shutil.copytree(source_dir, outside)
        shutil.rmtree(source_dir)
        if os.name == "nt":
            p = subprocess.run(["cmd", "/c", "mklink", "/J", source_dir, outside],
                               capture_output=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stderr)
        else:
            os.symlink(outside, source_dir, target_is_directory=True)
        return outside

    def test_runtime_tmp_is_excluded_without_hiding_source_names(self):
        self.fx.write("tmp/review/output.json", "runtime")
        self.fx.write("Tool/scripts/tmp/helper.py", "source")
        self.fx.write("tmp-helper.py", "source")
        inv = si.collect(self.root)
        self.assertNotIn("tmp/review/output.json", paths(inv))
        self.assertIn("Tool/scripts/tmp/helper.py", paths(inv))
        self.assertIn("tmp-helper.py", paths(inv))
        self.assertTrue(any(e["path"] == "tmp/review/output.json" for e in inv["excluded"]))

    def test_audit_runtime_directories_are_excluded_by_path_segment(self):
        audit_paths = [
            ".r12-validation/agent/fake.py",
            ".seep/state/cache.py",
            "Tool/.r12-validation/agent/nested.py",
            "Tool/.seep/state/nested.py",
        ]
        for rel in audit_paths:
            self.fx.write(rel, "runtime")

        inv = si.collect(self.root)
        included = set(paths(inv))
        excluded = {e["path"]: e["reason"] for e in inv["excluded"]}
        for rel in audit_paths:
            self.assertNotIn(rel, included)
            self.assertIn(rel, excluded)
            self.assertIn("runtime:", excluded[rel])
        self.assertEqual(inv["counts"]["included"],
                         len([f for f in inv["files"] if f["path"].startswith("Tool/src/")])
                         + 1)  # .gitignore

    def test_default_manifest_rejects_same_size_content_change(self):
        manifest = si.build_manifest(self.root)
        plain = self.fx.plain_copy()
        with open(os.path.join(plain, si.MANIFEST_NAME), "w", encoding="utf-8") as f:
            json.dump(manifest, f)
        target = os.path.join(plain, "Tool", "src", "engine.py")
        with open(target, "rb") as f:
            original = f.read()
        with open(target, "wb") as f:
            f.write(b"!" * len(original))
        with self.assertRaises(si.SourceInventoryError):
            si.inventory(plain)
        with self.assertRaises(si.SourceInventoryError):
            si.verify_manifest(manifest, plain, hashes=False)

    def test_manifest_pathlike_is_accepted(self):
        manifest = si.build_manifest(self.root)
        plain = self.fx.plain_copy()
        manifest_path = Path(plain) / si.MANIFEST_NAME
        with manifest_path.open("w", encoding="utf-8") as f:
            json.dump(manifest, f)
        inv = si.verify_manifest(manifest_path, plain)
        self.assertEqual(inv["mode"], "manifest")
        self.assertTrue(inv["source_complete"])

    def test_collection_does_not_hash_a_source_link_outside_root(self):
        outside = self._link_outside_source()
        original_hash = si._sha256

        def bounded_hash(path):
            self.assertFalse(os.path.realpath(path).startswith(outside + os.sep))
            return original_hash(path)

        with mock.patch.object(si, "_sha256", side_effect=bounded_hash):
            inv = si.collect(self.root, hashes=True)
        self.assertFalse(inv["source_complete"])
        self.assertFalse(inv["ok"])
        self.assertIn("Tool/src/engine.py", [e["path"] for e in inv["unsupported"]])

    def test_manifest_rejects_source_link_outside_root(self):
        manifest = si.build_manifest(self.root)
        self._link_outside_source()
        with self.assertRaises(si.SourceInventoryError):
            si.verify_manifest(manifest, self.root)

    def test_nonregular_tracked_source_is_not_counted(self):
        source = os.path.join(self.root, "Tool", "src", "engine.py")
        os.remove(source)
        os.mkdir(source)
        inv = si.collect(self.root)
        self.assertFalse(inv["source_complete"])
        self.assertNotIn("Tool/src/engine.py", paths(inv))

    def test_changed_enumeration_is_incomplete_and_cli_returns_two(self):
        original_git = si._git

        def changing_git(root, *args, **kwargs):
            if args == ("ls-files", "-z", "--cached", "--others", "--exclude-standard"):
                self.fx.write("Tool/src/late.py", "late")
            return original_git(root, *args, **kwargs)

        with mock.patch.object(si, "_git", side_effect=changing_git):
            inv = si.collect(self.root)
        self.assertFalse(inv["stable"])
        self.assertFalse(inv["source_complete"])
        self.assertFalse(inv["ok"])
        import contextlib
        import io
        with mock.patch.object(si, "inventory", return_value=inv), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(si.main(["--root", self.root, "--json"]), 2)

    def test_bad_manifest_metadata_is_rejected_as_inventory_error(self):
        manifest = si.build_manifest(self.root)
        for key, value in (("counts", [1]), ("missing_tracked", [None]),
                           ("unsupported", "bad"), ("excluded", {}), ("stable", "yes"),
                           ("source_complete", "yes")):
            with self.subTest(key=key):
                broken = json.loads(json.dumps(manifest))
                broken[key] = value
                with self.assertRaises(si.SourceInventoryError):
                    si.verify_manifest(broken, self.root)

    def test_incomplete_manifest_and_failed_write_preserve_truth(self):
        source = os.path.join(self.root, "Tool", "src", "engine.py")
        os.remove(source)
        path, doc = si.write_manifest(self.root)
        self.assertFalse(doc["source_complete"])
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(si.main(["--root", self.root, "--generate-manifest"]), 2)
        with open(path, "rb") as f:
            original = f.read()
        with mock.patch.object(si.json, "dump", side_effect=OSError("fixture write failure")):
            with self.assertRaises(si.SourceInventoryError):
                si.write_manifest(self.root)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), original)

    def test_gitless_runtime_directory_is_pruned_before_following_links(self):
        manifest = si.build_manifest(self.root)
        plain = self.fx.plain_copy()
        runtime = os.path.join(plain, "node_modules")
        os.mkdir(runtime)
        with open(os.path.join(runtime, "root.js"), "w", encoding="utf-8") as f:
            f.write("vendor")
        with open(os.path.join(plain, si.MANIFEST_NAME), "w", encoding="utf-8") as f:
            json.dump(manifest, f)
        self.assertTrue(si.inventory(plain)["source_complete"])
        os.remove(os.path.join(runtime, "root.js"))
        # A source directory link is an unresolved gap, even when unlisted.
        outside = os.path.join(self.fx.tmp, "extra-outside")
        os.mkdir(outside)
        link = os.path.join(plain, "linked-source")
        if os.name == "nt":
            p = subprocess.run(["cmd", "/c", "mklink", "/J", link, outside],
                               capture_output=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stderr)
        else:
            os.symlink(outside, link, target_is_directory=True)
        with self.assertRaises(si.SourceInventoryError):
            si.inventory(plain)


class InventoryPathTests(unittest.TestCase):
    def test_path_values_cannot_address_streams_or_coerce_nontext(self):
        for path in (None, 1, ["file.py"], "Tool/file.py:stream", "Tool/dir:stream/file.py", "a\x00b"):
            with self.subTest(path=path), self.assertRaises(si.SourceInventoryError):
                si.normalize_rel(path)


class BudgetConsumerTests(unittest.TestCase):
    """budget.py 必须**消费**共享清单，并把“未验证”单列成一个不绿的状态。

    这里只 monkeypatch `first_party_inventory` 的返回值，不改任何判定逻辑：
    要证明的行为是「拿不到数字时 rc=2 + value=null + ok=false」，而不是「大致能跑」。
    """

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "seep_budget_test", os.path.join(HERE, "budget.py"))
        cls.budget = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.budget)

    def _run(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self.budget.main(["--json"])
        return rc, json.loads(buf.getvalue())

    def test_unverified_inventory_is_rc2_not_green_and_not_over(self):
        original = self.budget.first_party_inventory
        self.budget.first_party_inventory = lambda: (None, {
            "mode": "unverified", "mode_reason": "git 不可用且无 manifest",
            "policy": "seep.source_inventory/1", "counts": {}, "stable": None})
        try:
            rc, doc = self._run()
        finally:
            self.budget.first_party_inventory = original
        row = [r for r in doc["budget"] if r["item"] == "first-party 引擎文件"][0]
        self.assertIsNone(row["value"])
        self.assertFalse(row["ok"])
        self.assertTrue(row.get("unverified"))
        self.assertFalse(doc["ok"])
        self.assertEqual(rc, 2, "未验证必须是 rc=2（不得当 0 绿，也不得冒称 1 超限）")

    def test_real_count_is_live_and_reported(self):
        rc, doc = self._run()
        row = [r for r in doc["budget"] if r["item"] == "first-party 引擎文件"][0]
        self.assertEqual(row["limit"], 950, "阈值本批不得改")
        self.assertEqual(doc["source_inventory"]["mode"], "git")
        self.assertIn("policy", doc["source_inventory"])
        # F1/F2 新增字段必须存在（三态可区分）
        self.assertIn("source_complete", doc["source_inventory"])
        # 这是对“当前工作树”的集成测试，工作树可能正保留待归档删除。
        # 完整时必须有数字；不完整时必须明确 UNKN/rc=2，不能为了测试把
        # incomplete 当成完整，也不能要求测试反过来修改用户的 Git 索引。
        if doc["source_inventory"]["source_complete"]:
            self.assertIsInstance(row["value"], int)
            expected = (0 if all(r.get("ok") and not r.get("unverified")
                                  for r in doc["budget"]) else 1)
            self.assertEqual(rc, expected)
        else:
            self.assertIsNone(row["value"])
            self.assertTrue(row.get("unverified"))
            self.assertEqual(rc, 2)

    def test_no_git_with_valid_manifest_is_a_real_positive(self):
        """F3：真 gitless 导出包 + 合法默认 manifest → budget 必须能给出数字（不是一律 rc2）。"""
        if not GIT:
            self.skipTest("缺 git")
        fx = Fixture("budget-gitless")
        try:
            root = fx.init(tracked=["Tool/scripts/a.py", "Tool/config/c.json", ".gitignore"])
            doc = si.build_manifest(root)
            plain = fx.plain_copy("plain")
            with open(os.path.join(plain, si.MANIFEST_NAME), "w", encoding="utf-8") as f:
                json.dump(doc, f, ensure_ascii=False)
            # 不碰真仓库：直接把 first_party_inventory 指向这个导出根（同一个 inventory 函数）
            original = self.budget.first_party_inventory

            def _from_plain():
                inv = si.inventory(plain)
                if inv.get("mode") == "unverified" or not inv.get("source_complete", True):
                    return None, inv
                return inv["counts"]["included"], inv

            self.budget.first_party_inventory = _from_plain
            try:
                rc, out = self._run()
            finally:
                self.budget.first_party_inventory = original
            row = [r for r in out["budget"] if r["item"] == "first-party 引擎文件"][0]
            self.assertEqual(row["value"], doc["counts"]["included"])
            self.assertEqual(out["source_inventory"]["mode"], "manifest")
            self.assertTrue(out["source_inventory"]["manifest_source"].startswith("auto:"))
            self.assertIn(rc, (0, 1), "有合法清单 + 完整 → 必须能给出真实判定（0/1），不得一律 2")
        finally:
            fx.clean()


class CliTests(unittest.TestCase):
    """CLI 契约：rc=0 可用 / rc=1 拒 / rc=2 未验证。"""

    @unittest.skipUnless(GIT, "缺 git")
    def test_cli_rc_matrix(self):
        fx = Fixture()
        try:
            root = fx.init(tracked=SEED_TRACKED)
            p = subprocess.run([sys.executable, MODULE_PATH, "--root", root, "--json"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            self.assertEqual(p.returncode, 0, p.stderr.decode("utf-8", "replace")[:300])
            doc = json.loads(p.stdout.decode("utf-8", "replace"))
            self.assertEqual(doc["counts"]["included"], len(SEED_TRACKED))

            # 未验证（复制到无 .git 目录，且不给 manifest）
            plain = os.path.join(fx.tmp, "plain")
            shutil.copytree(root, plain, ignore=shutil.ignore_patterns(".git"))
            p2 = subprocess.run([sys.executable, MODULE_PATH, "--root", plain, "--json"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            self.assertEqual(p2.returncode, 2, "gitless 无 manifest 必须是 rc=2")
            doc2 = json.loads(p2.stdout.decode("utf-8", "replace"))
            self.assertEqual(doc2["mode"], "unverified")

            # 拒：父 repo 误用（root 指向子目录）
            p3 = subprocess.run([sys.executable, MODULE_PATH, "--root",
                                 os.path.join(root, "Tool"), "--json"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            self.assertEqual(p3.returncode, 1, "父 repo 误用必须 rc=1")
        finally:
            fx.clean()


def _run_suite():
    """跑全部用例并**显式报出 skip 数**。

    为什么不用裸 `unittest.main()`：`wasSuccessful()` 在「有 skip」时也是 True，
    于是“缺 git / 缺环境”会被渲染成“全过”。本项目已经踩过一次这种假绿
    （mutation.py 的 baseline 注释就是这个坑）。所以这里把三种情况分开：
      rc=0 全部真跑且过（skipped=0）；rc=1 有 failure/error；rc=2 有 skip（**不是通过**）。
    """
    import io
    import types
    # 模块名可能与 `__name__` 不一致（被 importlib 以别名加载时）：用本帧 globals 做 shim。
    module = types.SimpleNamespace(**globals())
    args = [a for a in sys.argv[1:] if a not in ("-v", "--verbose")]
    verbose = any(a in ("-v", "--verbose") for a in sys.argv[1:])
    selectors = [a for a in args if not a.startswith("-")]
    # Accept normal unittest selectors (Class, Class.test_method, module.Class...).
    if selectors:
        suite = unittest.defaultTestLoader.loadTestsFromNames(selectors, module)
    else:
        suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    stream = io.StringIO() if not verbose else sys.stderr
    result = unittest.TextTestRunner(stream=stream, verbosity=2 if verbose else 1).run(suite)
    if not verbose:
        sys.stderr.write(stream.getvalue())
    ran, fail, err, skip = (result.testsRun, len(result.failures),
                            len(result.errors), len(result.skipped))
    print("[test_source_inventory] ran=%d failures=%d errors=%d skipped=%d" % (ran, fail, err, skip))
    for case, why in result.skipped:
        print("  [SKIP] %s — %s" % (case.id().rsplit(".", 1)[-1], why))
    if fail or err:
        print("  结论: FAIL（有 %d failure / %d error）" % (fail, err))
        return 1
    if skip:
        print("  结论: INCOMPLETE — %d 条被跳过，**不得当成全部能力已验证**" % skip)
        print("         （git 用例需要真 git 才能验；缺 git 时只能验 classify/normalize 纯函数）")
        return 2
    print("  结论: PASS（%d/%d 真跑，无 skip）" % (ran, ran))
    return 0


if __name__ == "__main__":
    sys.exit(_run_suite())
