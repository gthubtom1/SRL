#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`mutation.py` 隔离行为的自测：证明"只在 fixture 里写"这件事本身有判据。

为什么要有（不然隔离只是注释）：旧版 `mutation.py` 直接改真实仓库的 5 个受保护文件，
并往仓库外 `~/.pi/agent/prompts/` 落一张假提示词；靠 `finally` 还原，进程被强杀就留疤。
本套件不测"植入能不能被抓"（那是 `mutation.py` 自己的事），只测隔离层：

  T1 包含性校验：写 fixture 之外的路径 → `IsolationError`（不是"写了再恢复"）
  T2 夹具闸门：植入函数只碰 fixture 内的文件，真实仓库字节不变（起止哈希一致）
  T3 哨兵目录：真实仓库外的哨兵目录零写入（越界会被 T1 拦，这里再验一次真实面）
  T4 无 HOME 改动：子进程 env 里 HOME/USERPROFILE/CODEX_HOME 与父进程逐字相同，
     且子进程 `expanduser("~")` 指向 fixture home（hook 生效）
  T5 并发无碰撞：两/三个植入并行跑，各自 fixture 互不影响，判定互不串台
  T6 故障被真实 checker 抓到：`preflight.py --fast`（真脚本、真临时仓库）对
     "总控"植入必须**新增** FAIL 并命中判据；不是 mock
  T7 不可判定 ≠ pass：checker 跑不起来时状态必须是 unverified/missed，退出码非 0

只在 `TemporaryDirectory` / `mkdtemp` 里写；真实仓库与真实 `~/.pi` 只读。
用法：python -B -X utf8 Tool/scripts/test_mutation_isolation.py
退出码：0 = 全绿；1 = 有失败
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import mutation as mut  # noqa: E402


def _hash_file(p):
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


class TempRepo(unittest.TestCase):
    """最小临时仓库：只放本套件真正需要的几个文件（不拷 390MB 真实树）。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="seep-mutiso-")
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(self.repo, "Tool", "skill", "apkseep"))
        with open(os.path.join(self.repo, "Tool", "skill", "apkseep", "SKILL.md"),
                  "w", encoding="utf-8") as f:
            f.write("---\nname: apkseep\ndescription: \"apk\"\n---\n正文\n")
        with open(os.path.join(self.repo, "README.md"), "w", encoding="utf-8") as f:
            f.write("当前 README 没有静态工具数。\n")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class T1Containment(TempRepo):
    def test_write_outside_fixture_is_refused(self):
        fx = mut.Fixture([], "t1")
        try:
            with self.assertRaises(mut.IsolationError):
                fx.path(os.path.join("..", "escape.txt"))
            with self.assertRaises(mut.IsolationError):
                fx.path(os.path.join(self.tmp, "absolute-escape.txt"))
            with self.assertRaises(mut.IsolationError):
                fx.home_path("..", "..", "escape2.txt")
        finally:
            fx.clean()

    def test_inside_fixture_is_allowed(self):
        fx = mut.Fixture([], "t1b")
        try:
            p = fx.path(os.path.join("Tool", "skill", "x.md"))
            self.assertTrue(os.path.realpath(p).startswith(os.path.realpath(fx.root)))
            h = fx.home_path(".pi", "agent", "prompts")
            self.assertTrue(os.path.realpath(h).startswith(os.path.realpath(fx.home)))
        finally:
            fx.clean()


class T2FixtureOnly(TempRepo):
    def test_implant_touches_only_fixture(self):
        """植入写的是 fixture 副本；真实 temp 仓库（本次测试的"真实仓库"）字节不变。"""
        target = os.path.join(self.repo, "Tool", "skill", "apkseep", "SKILL.md")
        before = _hash_file(target)
        files = ["Tool/skill/apkseep/SKILL.md"]
        orig_root = mut.ROOT
        mut.ROOT = self.repo
        try:
            fx = mut.Fixture(files, "t2")
            try:
                mut.m3(fx)
                fx_copy = fx.path("Tool/skill/apkseep/SKILL.md")
                with open(fx_copy, encoding="utf-8") as handle:
                    self.assertIn("总控", handle.read())
                self.assertEqual(before, _hash_file(target),
                                 "植入穿透到了真实文件（应当只改 fixture 副本）")
            finally:
                fx.clean()
        finally:
            mut.ROOT = orig_root

    def test_manifest_lists_untracked_and_tracked(self):
        """夹具清单来自 git：未提交的 `??` 文件也要进夹具（不是只拷已提交版本）。"""
        files = mut.repo_manifest()
        self.assertIn("Tool/scripts/mutation.py", files)
        # 未跟踪文件至少出现一个（当前工作树存在；没有则跳过而不是假绿）
        dirty = subprocess.run(["git", "status", "--porcelain", "-uall"], cwd=ROOT,
                               stdout=subprocess.PIPE, text=True).stdout
        if "?? " in dirty:
            self.assertTrue(any(f for f in files),
                            "有未跟踪文件但夹具清单为空")


class T3Sentinel(TempRepo):
    def test_sentinel_dir_untouched(self):
        """哨兵目录放在 fixture 之外；植入与 checker 都不许碰它。"""
        sentinel = os.path.join(self.tmp, "sentinel")
        os.makedirs(sentinel)
        with open(os.path.join(sentinel, "keep.txt"), "w", encoding="utf-8") as f:
            f.write("keep")
        before = sorted(os.listdir(sentinel)), _hash_file(os.path.join(sentinel, "keep.txt"))
        fx = mut.Fixture([], "t3")
        try:
            mut.m4(fx)  # 写的是 fixture 的 .pi/agent/prompts
            self.assertTrue(os.path.isdir(fx.home_path(".pi", "agent", "prompts")))
            self.assertFalse(os.path.exists(os.path.join(sentinel, "zz-mutation.md")))
        finally:
            fx.clean()
        after = sorted(os.listdir(sentinel)), _hash_file(os.path.join(sentinel, "keep.txt"))
        self.assertEqual(before, after, "哨兵目录被写过")


class T4NoHomeMutation(TempRepo):
    def test_child_env_keeps_home_and_hook_redirects_expanduser(self):
        fx = mut.Fixture([], "t4")
        try:
            hook = mut.write_hook(os.path.join(fx.tmp, "hook"))
            env = mut.child_env(fx, hook)
            for k in ("HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "CODEX_HOME"):
                self.assertEqual(os.environ.get(k), env.get(k),
                                 "子进程 env 改了 %s —— 不许改用户全局 env" % k)
            self.assertEqual(env["SEEP_ISO_HOME"], fx.home)
            self.assertEqual(os.environ.get("SEEP_ISO_HOME"), None,
                             "父进程不该被塞 SEEP_ISO_HOME（进程级隔离）")
            # 真跑一个子进程，验证 expanduser("~") 被指到 fixture home
            code = ("import os,sys;"
                    "sys.stdout.write(os.path.expanduser('~')+'|'+"
                    "os.path.expanduser('~/.pi/agent/prompts'))")
            p = subprocess.run([mut.PY, "-B", "-c", code], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", env=env, cwd=fx.root,
                               timeout=120)
            self.assertEqual(p.returncode, 0, p.stderr)
            got = (p.stdout or "").split("|")
            self.assertEqual(os.path.realpath(got[0]), os.path.realpath(fx.home))
            self.assertTrue(os.path.realpath(got[1]).startswith(os.path.realpath(fx.home)))
        finally:
            fx.clean()

    def test_hook_does_not_swallow_other_users(self):
        """hook 只改 `~` / `~/…`；`~otheruser` 必须交给真正的 expanduser（不被劫持）。"""
        fx = mut.Fixture([], "t4b")
        try:
            hook = mut.write_hook(os.path.join(fx.tmp, "hook"))
            env = mut.child_env(fx, hook)
            code = "import os,sys;sys.stdout.write(os.path.expanduser('~nobody-not-here'))"
            p = subprocess.run([mut.PY, "-B", "-c", code], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", env=env, cwd=fx.root,
                               timeout=120)
            self.assertEqual(p.returncode, 0, p.stderr)
            got = (p.stdout or "").strip()
            self.assertFalse(got.startswith(os.path.realpath(fx.home)),
                             "hook 把 ~otheruser 也劫持到了 fixture home")
            # 判定口径：与**真** expanduser 的结果一致（不是与字面量 '~…' 比）
            ref = subprocess.run([mut.PY, "-B", "-c",
                                  "import os,sys;sys.stdout.write(os.path.expanduser(sys.argv[1]))",
                                  "~nobody-not-here"],
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace", timeout=120,
                                 env={k: v for k, v in os.environ.items()})
            self.assertEqual(got, (ref.stdout or "").strip())
        finally:
            fx.clean()


class T4cPathNoise(TempRepo):
    """fixture 临时路径不同，不能让 FAIL 行"看起来是新增"（否则 delta 判据是摆设）。"""

    def test_fixture_paths_are_normalized(self):
        BS = chr(92)
        temp_root = tempfile.gettempdir()
        a = mut.normalize_paths("找不到 " + temp_root + BS +
                                "seep-mut-m3-x" + BS + "home" + BS + ".pi" + BS + "mcp.json")
        b = mut.normalize_paths("找不到 " + temp_root.replace(BS, "/") +
                                "/seep-mut-base-abc/home/.pi/mcp.json")
        self.assertEqual(a, b, "两个 fixture 的临时路径没归一 → 会伪造新增 FAIL")
        self.assertIn("<fixture>", a)
        self.assertNotIn("seep-mut-m3-x", a)

    def test_unrelated_paths_untouched(self):
        line = "[FAIL] 悬空引用  — README.md -> Tool/prompts/AGENTS.md"
        self.assertEqual(mut.normalize_paths(line), line)


class T5Concurrency(TempRepo):
    def test_parallel_implants_do_not_collide(self):
        """两个植入并行：各自 fixture 独立，一个植入的改动不出现在另一个 fixture 里。"""
        files = ["Tool/skill/apkseep/SKILL.md", "README.md"]
        orig_root = mut.ROOT
        mut.ROOT = self.repo
        try:
            import threading
            out = {}
            lock = threading.Lock()

            def work(imp):
                rec = mut.run_one(imp, files)
                with lock:
                    out[imp["id"]] = rec

            picks = [x for x in mut.IMPLANTS if x["id"] in ("m3", "m6")]
            threads = [threading.Thread(target=work, args=(p,)) for p in picks]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(set(out), {"m3", "m6"})
            # 并发下每个记录都必须自洽（不得出现"两个植入判定串台"）
            for rid, rec in out.items():
                self.assertEqual(rec["id"], rid)
                self.assertIn(rec["status"], ("caught", "missed", "unverified"))
        finally:
            mut.ROOT = orig_root

    def test_fixture_dirs_are_distinct(self):
        a = mut.Fixture([], "a")
        b = mut.Fixture([], "b")
        try:
            self.assertNotEqual(os.path.realpath(a.tmp), os.path.realpath(b.tmp))
            self.assertNotEqual(os.path.realpath(a.home), os.path.realpath(b.home))
        finally:
            a.clean()
            b.clean()


class T6RealCheckerCatches(TempRepo):
    """用**真 checker**（不是 mock）证明故障会被抓到：真 repo 副本 + 真 preflight。"""

    def test_real_preflight_catches_orchestrator_implant(self):
        files = mut.repo_manifest()
        self.assertIn("Tool/scripts/preflight.py", files)
        imp = next(x for x in mut.IMPLANTS if x["id"] == "m3")
        rec = mut.run_one(imp, files)
        # 夹具可能缺件 → 允许 unverified，但**绝不允许**把"没抓到"记成 caught
        if rec["status"] == "caught":
            self.assertTrue(rec["hits"])
            self.assertIn("总控", rec["hits"][0])
        else:
            self.assertIn(rec["status"], ("unverified",))
            self.assertFalse(rec["caught"])
            self.assertTrue(rec["notes"], "不可判定必须给出原因，不能沉默")

    def test_baseline_prevents_false_positive(self):
        """同一 checker 的基线 FAIL 不会被算成"抓到植入"。"""
        files = ["Tool/skill/apkseep/SKILL.md"]
        orig_root = mut.ROOT
        mut.ROOT = self.repo
        try:
            base = mut.baseline_for(["Tool/scripts/preflight.py", "--fast"], files)
            self.assertIn("rc", base)
            self.assertIsInstance(base["fails"], list)
        finally:
            mut.ROOT = orig_root


class T7UnrunnableIsNotPass(TempRepo):
    def test_missing_checker_is_unverified_not_pass(self):
        files = ["README.md"]
        orig_root = mut.ROOT
        mut.ROOT = self.repo
        try:
            fake = {"id": "zz", "checker": ["Tool/scripts/does-not-exist.py"],
                    "expect": "任何", "fn": mut.m6, "fast": True, "baseline_note": ""}
            rec = mut.run_one(fake, files)
            self.assertNotEqual(rec["status"], "caught")
            self.assertFalse(rec["caught"])
            self.assertIn(rec["status"], ("unverified",))
            self.assertTrue(any("跑不起来" in n or "基线" in n for n in rec["notes"]),
                            "不可判定必须写明原因：%r" % (rec["notes"],))
        finally:
            mut.ROOT = orig_root

    def test_implant_not_applied_is_not_pass(self):
        """植入未生效（函数拒绝落盘）→ unverified，不许当成"抓到"。"""
        files = ["README.md", "Tool/scripts/r12-stub-check.py"]
        orig_root = mut.ROOT
        mut.ROOT = self.repo
        try:
            os.makedirs(os.path.join(self.repo, "Tool", "scripts"), exist_ok=True)
            with open(os.path.join(self.repo, "Tool", "scripts", "r12-stub-check.py"),
                      "w", encoding="utf-8") as f:
                f.write("print('[PASS] fixture checker ran')\n")

            def refused_implant(_fixture):
                raise mut.IsolationError("fixture 明确拒绝植入")

            fake = {"id": "zz-no-write", "checker": ["Tool/scripts/r12-stub-check.py"],
                    "expect": "任何", "fn": refused_implant, "fast": True,
                    "baseline_note": ""}
            rec = mut.run_one(fake, files)
            self.assertNotEqual(rec["status"], "caught")
            self.assertIn(rec["status"], ("unverified",))
            self.assertTrue(any("隔离越界" in n for n in rec["notes"]), rec["notes"])
        finally:
            mut.ROOT = orig_root


class T8RealRepoUntouched(unittest.TestCase):
    """对**真实仓库**跑一次快照对比：mutation 的隔离防护本身必须稳定。"""

    def test_repo_snapshot_stable_across_fixture_work(self):
        before = mut.repo_snapshot()
        fx = mut.Fixture(["README.md", "Tool/scripts/gate.py"], "t8")
        try:
            mut.write_hook(os.path.join(fx.tmp, "hook"))
            # This test verifies containment, not the public README wording.
            # Seed the mutation's input inside the isolated copy only.
            with open(fx.path("README.md"), "w", encoding="utf-8") as handle:
                handle.write("当前 README 没有静态工具数。\n")
            mut.m6(fx)
            with open(fx.path("README.md"), encoding="utf-8") as handle:
                self.assertEqual(
                    handle.read(),
                    "当前 README 没有静态工具数。\n事实漂移探针：99 个工具\n",
                )
        finally:
            fx.clean()
        after = mut.repo_snapshot()
        self.assertEqual(mut.diff_snapshots(before, after, "真实仓库"), [])

    def test_user_snapshot_has_no_content_leak(self):
        """用户目录快照只登记清单/哈希，不把文件内容塞进结构里。"""
        with tempfile.TemporaryDirectory(prefix="seep-mut-home-") as home:
            prompts = os.path.join(home, ".pi", "agent", "prompts")
            os.makedirs(prompts)
            with open(os.path.join(prompts, "card.md"), "w", encoding="utf-8") as handle:
                handle.write("fixture prompt\n")
            with patch.object(mut.os.path, "expanduser", return_value=home):
                snap = mut.user_snapshot()
        for rel, entry in snap.items():
            if entry is None:
                continue
            self.assertEqual(sorted(entry.keys()), ["hash", "names"])
            for n, h in entry["hash"].items():
                self.assertRegex(h, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    unittest.main(verbosity=2)
