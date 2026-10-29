#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_import_transactions.py —— IMPORT-02 专项回归（事务/回滚/并发/roots 边界/只读恢复报告）。

为什么单独一个文件（与 test_skill_import.py 的 34 条并列而不是替换它）：
    R1–R9 的反例都是**真实 I/O 故障**与**跨进程竞态**，靠"注入操作前抛异常"测不出来。
    本文件把每条反例钉成可回归断言，且判据一律看**磁盘末态**（旧目录逐字节 hash、
    部署根 hash、父文件行数/内容），不看函数返回值。

硬边界（与 IMPORTER 的授权面一致）：
  · 所有写入都在 `tempfile.mkdtemp()` 的临时 repo + 临时 agent roots；
    `--skill-dir`/`--deploy-root` 显式注入，绝不碰真实 `Tool/skill`、`~/.pi`、HOME。
  · 不执行被导入技能代码、不联网、不安装、不跑目标、不改 git。
  · 唯一**不是**"空想"的 I/O 故障：在临时根里创建**同名文件占位**/打开文件句柄，
    让真实 `os.replace` 失败（Windows WinError 32/17/183），不用 monkeypatch 伪造返回值。

跑法：
    python -B -X utf8 Tool/scripts/test_import_transactions.py
退出码 0 = 全部通过。
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
ROOT = os.path.dirname(TOOL)
SCRIPT = os.path.join(HERE, "skill-import.py")
MANIFEST = "import-manifest.json"

PACK_TMPL = {
    "schema": "seep.pack/1",
    "id": "",
    "l1": "",
    "routes": [{"label": "lab route", "must": [], "priority": 0}],
    "stages": ["0-analysis"],
    "tools": ["seep_apk_info"],
    "cases": ["leaf-apk"],
    "case_roles": {"witness": ["leaf-apk"], "depth_gate": ["leaf-apk"]},
    "witness": {
        "cmd": "python Tool/scripts/case_state.py verify --case Tool/cases/leaf-apk",
        "expect": "exit0",
        "budget_s": 30,
    },
    "witness_tool": {"cmd": "echo witness-tool", "why": "测试用见证工具声明"},
    "evidence_contract": {
        "required_fields": ["claim", "confidence", "authority", "evidence"],
        "authority_allow": ["shipped-artifact", "controlled-replay", "external-service"],
        "pass_forbids_confidence": ["inferred", "unknown"],
    },
    "limitations": ["测试用 pack，不是真实域"],
    "invalidation": ["测试结束即失效"],
}


def _load_impl():
    spec = importlib.util.spec_from_file_location("seep_skill_import_txn_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def snapshot(path):
    import hashlib
    out = {}
    if not os.path.isdir(path):
        return out
    for dp, dn, fn in os.walk(path):
        dn[:] = sorted(dn)
        for f in sorted(fn):
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, path).replace(os.sep, "/")
            try:
                with open(p, "rb") as fh:
                    out[rel] = hashlib.sha256(fh.read()).hexdigest()
            except OSError:
                out[rel] = "<unreadable>"
    return out


class TxnCase(unittest.TestCase):
    """临时 repo（Tool/skill）+ 两个临时 agent root；真实目录前后做哨兵比对。"""

    @classmethod
    def setUpClass(cls):
        cls.impl = _load_impl()

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="seep-import-txn-")
        self.fake_home = os.path.join(self.tmp, "home")
        os.makedirs(self.fake_home)
        self.env_guard = mock.patch.dict(os.environ, {
            "HOME": self.fake_home, "USERPROFILE": self.fake_home,
            "PI_CODING_AGENT_DIR": "", "PI_AGENT_DIR": "",
        }, clear=False)
        self.env_guard.start()
        self.repo = os.path.join(self.tmp, "repo")
        self.skill_dir = os.path.join(self.repo, "Tool", "skill")
        os.makedirs(self.skill_dir)
        self.roots = [os.path.join(self.tmp, "agent-a", "skills"),
                      os.path.join(self.tmp, "agent-b", "skills")]
        for r in self.roots:
            os.makedirs(r)
        self.parent = "zz-parent"
        self._make_domain(self.parent, "parent 域", 9050)

    def tearDown(self):
        self.env_guard.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------ 造数据
    def _make_domain(self, name, l1, priority, anchor_children=(), body="", root=None):
        d = os.path.join(root or self.skill_dir, name)
        os.makedirs(d, exist_ok=True)
        children = "".join("- `_pending/%s/SKILL.md` —— 已有子技能\n" % c for c in anchor_children)
        text = ("---\nname: %s\ndescription: \"%s：怎么用/帮我看看\"\n---\n\n%s\n\n"
                "## 子技能（按需读，不常驻）\n\n"
                "本域相关子技能放在 `Tool/skill/_pending/`（不占常驻上下文，需要时再读）：\n\n"
                "%s" % (name, l1, body, children))
        with io.open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        pack = json.loads(json.dumps(PACK_TMPL))
        pack["id"] = name
        pack["l1"] = ("%s 这个问题怎么处理" % l1)[:120]
        pack["routes"][0]["must"] = ["(?i)%s" % l1]
        pack["routes"][0]["priority"] = priority
        scripts = os.path.join(d, "scripts")
        os.makedirs(scripts, exist_ok=True)
        with io.open(
            os.path.join(scripts, "witness.py"),
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(
                "#!/usr/bin/env python3\n"
                "import json\n"
                "print(json.dumps({'domain': %r, 'status': 'fixture-only'}))\n" % name
            )
        pack["witness_tool"]["cmd"] = "Tool/skill/%s/scripts/witness.py" % name
        with io.open(os.path.join(d, "pack.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(pack, f, ensure_ascii=False, indent=2)
            f.write("\n")
        return d

    def _make_skill(self, name, desc="怎么做的说明 (.exe)", body=None, extra=None):
        d = os.path.join(self.tmp, "src", name)
        os.makedirs(d, exist_ok=True)
        text = ("---\nname: %s\ndescription: \"%s\"\n---\n\n%s\n"
                % (name, desc, body if body is not None else "## 1\n小技巧\n"))
        with io.open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        for rel, content in (extra or {}).items():
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with io.open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write(content)
        return d

    def _seed_skill(self, name, desc="旧版本 (.exe)", body=None):
        d = os.path.join(self.skill_dir, name)
        os.makedirs(d, exist_ok=True)
        with io.open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8", newline="\n") as f:
            f.write("---\nname: %s\ndescription: \"%s\"\n---\n\nOLD\n" % (name, desc))
        with io.open(os.path.join(d, "old-only.txt"), "w", encoding="utf-8") as f:
            f.write("keep me\n")
        return d

    def opts(self, **kw):
        base = dict(skill_dir=self.skill_dir, deploy_roots=list(self.roots))
        base.update(kw)
        return self.impl._opts(**base)

    def run_import(self, faults=None, **kw):
        return self.impl.run_import(self.opts(**kw), faults=faults or {})

    def cli(self, *args, env_extra=None):
        cmd = [sys.executable, "-B", "-X", "utf8", SCRIPT] + list(args)
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        env.update(env_extra or {})
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", cwd=ROOT, env=env, timeout=300)
        return r.returncode, (r.stdout or "") + (r.stderr or "")

    def quiet(self, fn, *a, **kw):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = fn(*a, **kw)
        return rc, buf.getvalue()

    def quiet_json(self, fn, **opts):
        """跑子命令并解析回执（cmd_* 走 `[报告] ` 行；--json 走纯 JSON）。"""
        o = dict(opts)
        o["json"] = True
        rc, out = self.quiet(fn, o)
        return rc, json.loads(out)

    def _deploy_parent_into(self, root):
        """把父域整体复制到部署根（模拟"父域本来就已部署"，不通过导入器）。"""
        dst = os.path.join(root, self.parent)
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        shutil.copytree(os.path.join(self.skill_dir, self.parent), dst)
        return dst


# ================================================================ 1. 改名失败即放弃（R1）
class TestNoCopyDeleteFallback(TxnCase):
    def test_move_never_falls_back_to_copy(self):
        """`_move` 只有 os.replace/os.rename 两条路；代码里不得出现 COPY+DEL 退路。"""
        with io.open(SCRIPT, encoding="utf-8") as f:
            src = f.read()
        offenders = []
        for ln in src.splitlines():
            s = ln.strip()
            if "shutil.move" not in s or s.startswith("#"):
                continue
            if s.startswith('"') or s.startswith("'") or s.startswith("- "):
                continue
            if "不再退回" in s or "旧实现失败后退回" in s:
                continue
            offenders.append(s)
        self.assertEqual(offenders, [], "IMPORT-02 禁止 COPY+DEL 退路（会把旧目录拆成两半）")
        # 同卷改名失败 → Refuse(5) 且源原样在场（绝不 copy+删源）
        a = os.path.join(self.tmp, "mv-a")
        os.makedirs(os.path.join(a, "sub"))
        with io.open(os.path.join(a, "sub", "f.txt"), "w", encoding="utf-8") as f:
            f.write("x\n")
        before = snapshot(a)
        victim = os.path.join(self.tmp, "mv-b")
        os.makedirs(os.path.join(victim, "already"))
        with io.open(os.path.join(victim, "already", "g.txt"), "w", encoding="utf-8") as f:
            f.write("y\n")
        with self.assertRaises(self.impl.Refuse) as ctx:
            self.impl._move(a, victim)
        self.assertEqual(ctx.exception.code, "move_failed")
        self.assertEqual(ctx.exception.rc, 5)
        self.assertEqual(snapshot(a), before, "改名失败后源目录必须逐字节原样保留")

    def test_deploy_command_requires_replace_before_touching_any_root(self):
        """deploy must not replace an existing user skill unless --replace is explicit."""
        name = "zz-deploy-existing"
        repo = self._seed_skill(name)
        occupied = os.path.join(self.roots[1], name)
        os.makedirs(occupied)
        with io.open(os.path.join(occupied, "SKILL.md"), "w", encoding="utf-8") as stream:
            stream.write("USER EXISTING CONTENT\n")
        before = snapshot(occupied)

        opts = self.opts(name=name, deploy_roots=list(self.roots), replace=False)
        rc, rec = self.quiet_json(self.impl.cmd_deploy, **opts)
        self.assertEqual(rc, 4, rec)
        self.assertEqual(rec["refusal"]["code"], "target_exists", rec)
        self.assertFalse(rec["written"], rec)
        self.assertFalse(os.path.exists(os.path.join(self.roots[0], name)), rec)
        self.assertEqual(snapshot(occupied), before)
        self.assertFalse(os.path.exists(os.path.join(self.roots[1], self.impl.BACKUP_NAME)))

        opts["replace"] = True
        rc2, rec2 = self.quiet_json(self.impl.cmd_deploy, **opts)
        self.assertEqual(rc2, 0, rec2)
        for root in self.roots:
            self.assertEqual(self.impl.hash_tree(os.path.join(root, name)),
                             self.impl.hash_tree(repo))
        kept = [path for path in rec2.get("backups", {}).get("deploy", []) if path]
        self.assertTrue(kept, rec2.get("backups"))
        restored = os.path.join(kept[0], "SKILL.md")
        with io.open(restored, encoding="utf-8") as stream:
            self.assertIn("USER EXISTING CONTENT", stream.read())

    def test_import_requires_replace_before_overwriting_deployed_user_skill(self):
        """A normal import must preflight every deploy root before writing any target."""
        name = "zz-import-existing"
        src = self._make_skill(name, desc="new repository version (.exe)")
        occupied = os.path.join(self.roots[1], name)
        os.makedirs(occupied)
        with io.open(os.path.join(occupied, "SKILL.md"), "w", encoding="utf-8") as stream:
            stream.write("USER EXISTING CONTENT\n")
        before = snapshot(occupied)

        rec = self.run_import(src=src, kind="crosscutting", replace=False)
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "target_exists", rec)
        self.assertFalse(rec["written"], rec)
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, name)), rec)
        self.assertFalse(os.path.exists(os.path.join(self.roots[0], name)), rec)
        self.assertEqual(snapshot(occupied), before)
        self.assertFalse(os.path.exists(os.path.join(self.roots[1], self.impl.BACKUP_NAME)))

        rec2 = self.run_import(src=src, kind="crosscutting", replace=True)
        self.assertEqual(rec2["rc"], 0, rec2)
        for root in self.roots:
            self.assertEqual(self.impl.hash_tree(os.path.join(root, name)),
                             self.impl.hash_tree(os.path.join(self.skill_dir, name)))
        kept = [path for path in rec2.get("backups", {}).get("deploy", []) if path]
        self.assertTrue(kept, rec2.get("backups"))
        with io.open(os.path.join(kept[0], "SKILL.md"), encoding="utf-8") as stream:
            self.assertIn("USER EXISTING CONTENT", stream.read())

    @contextlib.contextmanager
    def _frozen_clock(self, stamp):
        """冻结 `_ts()`，以便在**真实**目标路径上预先放障碍物（不用 monkeypatch 伪造返回值）。"""
        orig = self.impl._ts
        self.impl._ts = lambda: stamp
        try:
            yield stamp
        finally:
            self.impl._ts = orig

    def _occupy(self, base, name, stamp):
        """在 `_ts()` 生成的路径上预先建一个**非空目录**，让真实 os.replace 目录改名失败。

        为什么不用“同名文件”：Windows 上 os.replace(目录 → 文件) 是**允许**的（会覆盖文件），
        只有目录 → **非空目录** 才真失败（WinError 5/17/183）。这才是要演的真实故障。
        """
        d = os.path.join(base, "%s-%s" % (name, stamp))
        occ = os.path.join(d, name)
        os.makedirs(occ, exist_ok=True)
        with io.open(os.path.join(occ, "occupier.txt"), "w", encoding="utf-8") as f:
            f.write("occupier\n")
        return d

    def test_real_rename_failure_keeps_old_repo_dir_intact(self):
        """**自然** rename 失败：备份目标位被非空目录占住 → 旧技能目录完整、无部分复制。"""
        name = "zz-nat1"
        dest = self._seed_skill(name)
        before = snapshot(dest)
        stamp = "frozen-nat1"
        with self._frozen_clock(stamp):
            self._occupy(os.path.join(self.skill_dir, self.impl.BACKUP_NAME), name, stamp)
            src = self._make_skill(name, desc="新版本 (.exe)")
            rec = self.run_import(src=src, kind="crosscutting", replace=True)
        self.assertEqual(rec["rc"], 5, rec.get("why"))
        self.assertEqual(rec["refusal"]["code"], "move_failed", rec.get("why"))
        self.assertEqual(snapshot(dest), before, "旧技能目录被部分搬走了：%s" % rec.get("why"))
        self.assertTrue(os.path.isfile(os.path.join(dest, "old-only.txt")))
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, name, MANIFEST)))

    def test_real_rename_failure_keeps_deploy_dir_intact(self):
        """部署根侧同样：rename 失败 → 旧部署逐字节完整（不回退 copy+del）。"""
        name = "zz-nat2"
        src = self._make_skill(name, desc="v1 (.exe)")
        rec = self.run_import(src=src, kind="crosscutting")
        self.assertEqual(rec["rc"], 0, rec)
        dep0 = snapshot(os.path.join(self.roots[0], name))
        dep1 = snapshot(os.path.join(self.roots[1], name))
        stamp = "frozen-nat2"
        with self._frozen_clock(stamp):
            self._occupy(os.path.join(self.roots[1], self.impl.BACKUP_NAME), name, stamp)
            src2 = self._make_skill(name, desc="v2 (.exe)", body="## 2\nv2 body\n")
            rec2 = self.run_import(src=src2, kind="crosscutting", replace=True)
        self.assertEqual(rec2["rc"], 5, rec2.get("why"))
        self.assertEqual(snapshot(os.path.join(self.roots[1], name)), dep1,
                         "旧部署被部分搬走")
        # 本事务不得留下半提交：第 1 个 root 必须回到 v1，仓库也不得有 v2
        self.assertEqual(snapshot(os.path.join(self.roots[0], name)), dep0)
        with io.open(os.path.join(self.skill_dir, name, "SKILL.md"),
                     encoding="utf-8") as f:
            repo_text = f.read()
        self.assertNotIn("v2 body", repo_text)

    def test_rollback_is_honest_on_fully_recoverable_path(self):
        """可完整回滚的失败必须如实 rolled_back=true，并逐项给出磁盘事实。"""
        name = "zz-honest"
        self._seed_skill(name)
        src = self._make_skill(name, desc="新版本 (.exe)")
        rec = self.run_import(src=src, kind="crosscutting", replace=True,
                              faults={"deploy.swap.0": True})
        self.assertEqual(rec["rc"], 5, rec)
        self.assertTrue(rec["rolled_back"], rec.get("rollback"))
        self.assertFalse(rec["rollback_partial"], rec.get("rollback"))
        for item in rec["rollback"]:
            self.assertIn("ok", item)
            self.assertIn("applied", item)   # intent 是否真的执行过（不猜）
        self.assertFalse(rec.get("backup_kept"))

    def test_rollback_partial_when_old_content_vanishes(self):
        """旧内容被外部弄丢时不得谎报 rolled_back=true：必须 partial + 指向可复查位置。"""
        name = "zz-partial"
        self._seed_skill(name)
        src = self._make_skill(name, desc="新版本 (.exe)", body="## 2\nv2\n")
        orig = self.impl._deploy_one

        def saboteur(plan, root, idx, repo_target, backup_dir, journal, faults):
            # 让仓库备份里的旧内容“消失”，模拟回滚无法复原的事实
            for e in list(journal):
                if e.get("op") == "intent" and e.get("role") == "repo-old" and e.get("dst"):
                    if os.path.isdir(e["dst"]):
                        shutil.rmtree(e["dst"], ignore_errors=True)
            return orig(plan, root, idx, repo_target, backup_dir, journal, faults)

        self.impl._deploy_one = saboteur
        try:
            rec = self.run_import(src=src, kind="crosscutting", replace=True,
                                  faults={"deploy.swap.1": True})
        finally:
            self.impl._deploy_one = orig
        self.assertEqual(rec["rc"], 5, rec.get("why"))
        self.assertFalse(rec["rolled_back"], rec.get("rollback"))
        self.assertTrue(rec["rollback_partial"], rec.get("rollback"))
        self.assertTrue(rec.get("backup_kept"))
        self.assertTrue(any((not r.get("ok")) or ("备份" in (r.get("why") or ""))
                            for r in rec["rollback"]), rec["rollback"])
        # 可复查位置必须在回执里（旧内容已丢时位置可能已被清空，但路径/事实要说清）
        self.assertTrue(rec["backups"].get("repo"))
        bad = [r for r in rec["rollback"] if not r.get("ok")]
        self.assertTrue(bad, rec["rollback"])
        self.assertTrue(any((r.get("dst") or r.get("path") or "") != "" for r in bad), bad)
        self.assertIn("rollback_note", rec)

    def test_parent_patch_failure_receipt_points_to_real_kept_backup(self):
        name = "zz-parent-fail-receipt"
        src = self._make_skill(name, desc="父写失败 (.yar)")
        rec = self.run_import(
            src=src, kind="subskill", parent=self.parent, deploy_roots=[],
            faults={"parent.patch": True})
        self.assertEqual(rec["rc"], 5, rec.get("why"))
        self.assertFalse(rec["deployed"])
        self.assertTrue(rec["backup_kept"], rec.get("backups"))
        kept = rec["backups"].get("parent") or []
        if isinstance(kept, str):
            kept = [kept]
        self.assertTrue(kept, rec.get("backups"))
        self.assertTrue(all(os.path.isfile(path) for path in kept), kept)
        self.assertEqual(rec["effective_status"], "failed")

    def test_journal_registers_intent_before_operation(self):
        """journal 必须“先 intent、后 done”：改名中途失败时能看到未生效的 intent。"""
        name = "zz-jr"
        self._seed_skill(name)
        src = self._make_skill(name, desc="新版本 (.exe)", body="## 2\nv2\n")
        rec = self.run_import(src=src, kind="crosscutting", replace=True,
                              faults={"commit.swap.move": True})
        self.assertEqual(rec["rc"], 5, rec)
        pending = [r for r in rec["rollback"] if not r["applied"]]
        self.assertTrue(pending, rec["rollback"])
        self.assertTrue(any(r["op"] == "move" and r["role"] == "repo-new" for r in pending),
                        rec["rollback"])
        self.assertIn("old-only.txt", snapshot(os.path.join(self.skill_dir, name)))
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, name, MANIFEST)))


# ================================================================ 2. 多资源锁 / 并发（R2）
class TestMultiResourceLocking(TxnCase):
    def test_legacy_stale_cleanup_rechecks_liveness_under_os_guard(self):
        alive = os.path.join(self.tmp, "stale-alive.lock")
        self.impl._write_lock(alive, self.impl._lock_payload("test", "alive"))
        with mock.patch.object(
                self.impl, "_acquire_lock_guard",
                wraps=self.impl._acquire_lock_guard) as guard:
            self.assertEqual(self.impl._release_stale_lock(alive), "")
        guard.assert_called_once_with(alive)
        self.assertTrue(os.path.exists(alive), "属主仍存活时不得删除 stale-* 锁")
        os.remove(alive)

        dead = os.path.join(self.tmp, "stale-dead.lock")
        payload = self.impl._lock_payload("test", "dead")
        payload["pid"] = 99999999
        self.impl._write_lock(dead, payload)
        self.assertEqual(self.impl._release_stale_lock(dead), "")
        self.assertFalse(os.path.exists(dead))

    def test_liveness_uses_process_start_token_to_reject_pid_reuse(self):
        payload = self.impl._lock_payload("test", "fixture")
        token = payload.get("proc_start")
        if token:
            self.assertIs(self.impl._pid_alive(payload["pid"], token), True)
            self.assertIs(self.impl._pid_alive(payload["pid"], token + "-reused"), False)
        path = os.path.join(self.tmp, "pid-reuse.lock")
        payload["proc_start"] = "definitely-old-process"
        self.impl._write_lock(path, payload)
        meta = self.impl._read_lock(path)
        if meta.get("proc_start") and self.impl._process_start_token(payload["pid"]):
            self.assertIs(meta["alive"], False)

    def test_stale_lock_takeover_allows_only_one_concurrent_winner(self):
        path = os.path.join(self.tmp, "race.lock")
        stale = {
            "role": "stale",
            "protected": "fixture",
            "pid": 99999999,
            "ts": "2000-01-01T00:00:00",
            "host": os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "",
            "proc_start": None,
            "argv0": "stale-test",
        }
        with io.open(path, "w", encoding="utf-8", newline="\n") as stream:
            stream.write("pid=%d ts=%s\n%s\n"
                         % (stale["pid"], stale["ts"],
                            json.dumps(stale, ensure_ascii=False, sort_keys=True)))
        code = (
            "import importlib.util,json,time;"
            "s=importlib.util.spec_from_file_location('race_import',%r);"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            "got,_=m._takeover_stale_lock(%r,m._lock_payload('race','fixture'));"
            "print('GOT' if got else 'NONE',flush=True);"
            "time.sleep(3.0)"
        ) % (SCRIPT, path)
        procs = [
            subprocess.Popen(
                [sys.executable, "-B", "-X", "utf8", "-c", code],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace",
                cwd=ROOT, env=dict(os.environ))
            for _ in range(2)
        ]
        results = []
        for proc in procs:
            out, err = proc.communicate(timeout=10)
            results.append((proc.returncode, out.strip(), err))
        self.assertEqual([item[0] for item in results], [0, 0], results)
        self.assertEqual(sorted(item[1] for item in results), ["GOT", "NONE"], results)
        os.remove(path)

    def test_lock_specs_sorted_by_normalized_path(self):
        """锁必须覆盖 skill / 父目录 / 父文件 / 每个 dest，并按规范化路径全局排序。"""
        src = self._make_skill("zz-lk", desc="锁 (.yar)")
        plan = self.impl.plan_import(self.opts(src=src, kind="subskill", parent=self.parent))
        specs = self.impl._lock_specs(plan)
        roles = {s["role"] for s in specs}
        self.assertIn("skill", roles)
        self.assertIn("repo-parent-dir", roles)
        self.assertIn("repo-dest", roles)
        self.assertIn("repo-parent-file", roles)
        self.assertIn("deploy-parent-file:0", roles)
        self.assertIn("deploy-parent-file:1", roles)
        keys = [s["sort"] for s in specs]
        self.assertEqual(len(keys), len(set(keys)), "锁键重复（自锁死）")
        # 两个 plan 的排序结果必须一致（跨进程不会"你等我、我等你"）
        plan2 = self.impl.plan_import(self.opts(src=src, kind="subskill", parent=self.parent))
        self.assertEqual(keys, [s["sort"] for s in self.impl._lock_specs(plan2)])

    def test_two_processes_same_parent_keep_both_refs(self):
        """2–4 个进程导入不同子技能到同一父域：引用一条不丢，仓库+部署都可达。"""
        self._deploy_parent_into(self.roots[0])
        kids = ["zz-m0", "zz-m1", "zz-m2", "zz-m3"]
        paths = [self._make_skill(k, desc="子 %s (.yar)" % k) for k in kids]
        procs = []
        for p in paths:
            procs.append(subprocess.Popen(
                [sys.executable, "-B", "-X", "utf8", SCRIPT, "import", "--kind", "subskill",
                 "--parent", self.parent, "--from", p, "--skill-dir", self.skill_dir,
                 "--deploy-root", self.roots[0], "--json"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                errors="replace", cwd=ROOT))
        outs = []
        for pr in procs:
            o, _ = pr.communicate(timeout=300)
            outs.append((pr.returncode, o))
        rcs = [r[0] for r in outs]
        self.assertEqual(rcs, [0, 0, 0, 0], [o[1][-400:] for o in outs if o[0] != 0])
        # 仓库侧：4 条引用都在，且都能按**父技能目录**解析
        pp = os.path.join(self.skill_dir, self.parent, "SKILL.md")
        with io.open(pp, encoding="utf-8", newline="") as f:
            text = f.read()
        for k in kids:
            self.assertEqual(text.count("../_pending/%s/SKILL.md" % k), 1, (k, text[-800:]))
            target = os.path.normpath(os.path.join(os.path.dirname(pp), "..", "_pending", k,
                                                   "SKILL.md"))
            self.assertTrue(os.path.isfile(target), target)
        # 部署侧：4 条引用都在，且指向真实 GUIDE.md（不给 deployment 丢引用）
        dp = os.path.join(self.roots[0], self.parent, "SKILL.md")
        with io.open(dp, encoding="utf-8", newline="") as f:
            dtext = f.read()
        for k in kids:
            rel = "references/imported-subskills/%s/GUIDE.md" % k
            self.assertEqual(dtext.count(rel), 1, (k, dtext[-800:]))
            self.assertTrue(os.path.isfile(os.path.join(os.path.dirname(dp),
                                                        rel.replace("/", os.sep))))
        # 每个子技能只多 1 行（无重复块/无错位）
        self.assertEqual(len(text.splitlines()) - len(dtext.splitlines()), 0)

    def test_lock_contention_still_blocks_other_transaction(self):
        """事务持锁期间，另一事务改同一父文件必须真的被挡住（跨进程互斥，不是线程锁）。"""
        a = self._make_skill("zz-keep-a", desc="已提交 A (.yar)")
        b = self._make_skill("zz-keep-b", desc="将失败 B (.yar)")
        self.assertEqual(self.run_import(src=a, kind="subskill", parent=self.parent,
                                         deploy_roots=[], deploy=False)["rc"], 0)
        orig = self.impl._deploy_subskill
        state = {}

        def saboteur(plan, root, idx, repo_child, journal, faults):
            if "blocked" not in state:
                c_src = self._make_skill("zz-keep-c", desc="并发 C (.yar)")
                state["blocked"] = self.run_import(src=c_src, kind="subskill",
                                                   parent=self.parent, deploy_roots=[],
                                                   deploy=False)
            raise self.impl.Refuse(5, "injected_after_parent",
                                   "模拟部署阶段失败（此时另一事务被锁挡住）")
            return None

        self.impl._deploy_subskill = saboteur
        try:
            rec_b = self.run_import(src=b, kind="subskill", parent=self.parent,
                                    deploy_roots=[self.roots[0]])
        finally:
            self.impl._deploy_subskill = orig
        blocked = state.get("blocked") or {}
        self.assertEqual(blocked.get("rc"), 4, blocked.get("why"))
        self.assertEqual((blocked.get("refusal") or {}).get("code"), "locked")
        self.assertEqual(rec_b["rc"], 5, rec_b.get("why"))
        with io.open(os.path.join(self.skill_dir, self.parent, "SKILL.md"),
                     encoding="utf-8", newline="") as f:
            text = f.read()
        self.assertEqual(text.count("../_pending/zz-keep-a/SKILL.md"), 1, text[-600:])
        # C 被锁挡在写盘之前：它不该有任何引用（也没有半写）
        self.assertEqual(text.count("../_pending/zz-keep-c/SKILL.md"), 0, text[-600:])
        self.assertEqual(text.count("../_pending/zz-keep-b/SKILL.md"), 0, text[-600:])
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, "_pending", "zz-keep-c")))
        self.assertTrue(rec_b["rolled_back"], rec_b.get("rollback"))

    def test_rollback_does_not_clobber_another_committed_transaction(self):
        """回滚只撤自己那一行：**另一事务**在本事务写完后提交的引用必须原样留着。

        构造：先有已提交的 A；本事务 B 写完仓库父引用/部署副本后，另一事务 C 在自己的锁窗口
        内把 C 的 `_pending/` 与父引用写下并提交；然后 B 在部署侧失败回滚。
        要求：A、C 的引用都在，B 的引用被撤掉；回滚如实报 partial（父文件被别人改过，
        不能谎报"整份还原"）。
        """
        a = self._make_skill("zz-keep-a", desc="已提交 A (.yar)")
        b = self._make_skill("zz-keep-b", desc="将失败 B (.yar)")
        self.assertEqual(self.run_import(src=a, kind="subskill", parent=self.parent,
                                         deploy_roots=[], deploy=False)["rc"], 0)
        # 部署侧父域先就位，让本事务会走"部署侧可读"分支
        self._deploy_parent_into(self.roots[0])
        pp = os.path.join(self.skill_dir, self.parent, "SKILL.md")
        c_line = "- `../_pending/zz-keep-c/SKILL.md` —— 另一事务已提交" + chr(10)
        orig = self.impl._deploy_subskill
        state = {}

        def saboteur(plan, root, idx, repo_child, journal, faults):
            out = orig(plan, root, idx, repo_child, journal, faults)
            if "patched" not in state:
                # 模拟另一事务（在它自己的锁窗口内）真的提交：落 _pending + 写父引用
                cdir = os.path.join(self.skill_dir, "_pending", "zz-keep-c")
                os.makedirs(cdir, exist_ok=True)
                with io.open(os.path.join(cdir, "SKILL.md"), "w", encoding="utf-8",
                             newline="\n") as f:
                    f.write(chr(10).join([
                        "---", "name: zz-keep-c", 'description: "C"', "---", "C", ""]))
                with io.open(pp, encoding="utf-8", newline="") as f:
                    text = f.read()
                with io.open(pp, "w", encoding="utf-8", newline="") as f:
                    f.write(text + c_line)
                state["patched"] = True
            raise self.impl.Refuse(5, "injected_after_parent", "模拟部署阶段失败")
            return out

        self.impl._deploy_subskill = saboteur
        try:
            rec_b = self.run_import(src=b, kind="subskill", parent=self.parent,
                                    deploy_roots=[self.roots[0]])
        finally:
            self.impl._deploy_subskill = orig
        self.assertEqual(rec_b["rc"], 5, rec_b.get("why"))
        with io.open(pp, encoding="utf-8", newline="") as f:
            text = f.read()
        # 已提交的 A 与 C 的引用必须都在；失败事务 B 的引用必须被撤掉
        self.assertEqual(text.count("../_pending/zz-keep-a/SKILL.md"), 1, text[-600:])
        self.assertEqual(text.count("../_pending/zz-keep-c/SKILL.md"), 1, text[-600:])
        self.assertEqual(text.count("../_pending/zz-keep-b/SKILL.md"), 0, text[-600:])
        # B 的子技能目录/部署副本不应残留
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, "_pending", "zz-keep-b")))
        self.assertFalse(os.path.exists(os.path.join(
            self.roots[0], self.parent, "references", "imported-subskills", "zz-keep-b")))
        # 这条回滚必然是部分回滚（父文件已被别人改过），必须如实报，不能谎报整份还原
        self.assertTrue(rec_b["rollback_partial"], rec_b.get("rollback"))
        patch = [r for r in rec_b["rollback"] if r["op"] == "patch"
                 and r["role"] == "repo-parent"]
        self.assertTrue(patch and any("仅撤掉本事务" in (r.get("why") or "") for r in patch),
                        rec_b.get("rollback"))

    def test_lock_contention_is_reported_with_owner_metadata(self):
        """被占用时报 locked + 属主公开元数据（pid/ts/role），不静默、不硬闯。"""
        src = self._make_skill("zz-lk2", desc="锁2 (.exe)")
        held = self.impl._acquire_lock(self.skill_dir, "zz-lk2")
        self.assertIsNotNone(held)
        try:
            rec = self.run_import(src=src, kind="crosscutting")
        finally:
            self.impl._release_lock(held)
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "locked")
        holder = rec["refusal"].get("holder") or {}
        self.assertTrue(holder.get("pid"))
        self.assertTrue(holder.get("ts"))
        self.assertTrue(holder.get("path"))
        # 被拒事务零落盘，且别人的活锁还在（拒绝路径不删他人锁）
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, "zz-lk2")))


# ================================================================ 3. 父引用真实可达（R3/R7b）
class TestParentReachability(TxnCase):
    def test_repo_ref_is_relative_to_skill_dir_not_repo_cwd(self):
        """仓库父引用必须是 `../_pending/<child>/SKILL.md`，按**父技能目录**可解析。"""
        src = self._make_skill("zz-rr", desc="可达 (.yar)")
        rec = self.run_import(src=src, kind="subskill", parent=self.parent, deploy_roots=[],
                              deploy=False)
        self.assertEqual(rec["rc"], 0, rec)
        pp = os.path.join(self.skill_dir, self.parent, "SKILL.md")
        with io.open(pp, encoding="utf-8", newline="") as f:
            text = f.read()
        self.assertIn("`../_pending/zz-rr/SKILL.md`", text)
        resolved = os.path.normpath(os.path.join(self.skill_dir, self.parent, "..", "_pending",
                                                "zz-rr", "SKILL.md"))
        self.assertTrue(os.path.isfile(resolved), resolved)
        self.assertTrue(rec["entry_reachable"])

    def test_deployed_parent_points_at_real_document(self):
        """部署侧：子技能复制到 references/imported-subskills/<child>/，入口改名 GUIDE.md。"""
        self._deploy_parent_into(self.roots[0])
        src = self._make_skill("zz-dp", desc="部署可达 (.yar)", extra={"references/a.md": "A\n"})
        rec = self.run_import(src=src, kind="subskill", parent=self.parent,
                              deploy_roots=[self.roots[0]])
        self.assertEqual(rec["rc"], 0, rec)
        base = os.path.join(self.roots[0], self.parent, "references", "imported-subskills", "zz-dp")
        self.assertTrue(os.path.isfile(os.path.join(base, "GUIDE.md")))
        self.assertFalse(os.path.exists(os.path.join(base, "SKILL.md")),
                         "入口文档不能叫 SKILL.md（否则会被当成新的全局技能）")
        self.assertTrue(os.path.isfile(os.path.join(base, "references", "a.md")),
                        "相对资产必须一起复制")
        # 不能被当成顶层技能被自动选中
        self.assertFalse(os.path.exists(os.path.join(self.roots[0], "zz-dp")))
        dp = os.path.join(self.roots[0], self.parent, "SKILL.md")
        with io.open(dp, encoding="utf-8") as f:
            deployed_parent = f.read()
        self.assertIn("references/imported-subskills/zz-dp/GUIDE.md", deployed_parent)
        # manifest 记录路径映射与 hash
        with io.open(os.path.join(base, self.impl.IMPORT_MAP_NAME), encoding="utf-8") as f:
            mp = json.load(f)
        self.assertEqual(mp["mapping"], {"SKILL.md": "GUIDE.md"})
        self.assertIn("GUIDE.md", mp["files"])
        self.assertTrue(mp["files"]["GUIDE.md"])

    def test_parent_not_deployed_reports_pending_not_reachable(self):
        """父域没部署到该 root → 如实报 pending，不宣称可达、也不自动搬父域。"""
        src = self._make_skill("zz-pend", desc="pending (.yar)")
        rec = self.run_import(src=src, kind="subskill", parent=self.parent,
                              deploy_roots=[self.roots[0]])
        self.assertEqual(rec["rc"], 0, rec)
        self.assertTrue(rec.get("deploy_pending"), rec.get("deployed"))
        self.assertFalse(os.path.exists(os.path.join(self.roots[0], self.parent)),
                         "不得擅自把父域整体部署过去")
        self.assertFalse(rec["available_next_session"])
        self.assertEqual(rec["effective_status"], "pending_subskill")
        self.assertIn("pending", "；".join(rec["to_take_effect"]))

    def test_verify_catches_lost_parent_ref(self):
        """父引用被外部撤回 → verify 必须 rc=5（不能给绿）。"""
        src = self._make_skill("zz-vr", desc="verify 引用 (.yar)")
        rec = self.run_import(src=src, kind="subskill", parent=self.parent, deploy_roots=[],
                              deploy=False)
        self.assertEqual(rec["rc"], 0, rec)
        pp = os.path.join(self.skill_dir, self.parent, "SKILL.md")
        self._make_domain(self.parent, "parent 域", 9050)      # 逐字节还原父文件
        rc, v = self.quiet_json(self.impl.cmd_verify,
                                **self.opts(name="zz-vr", deploy_roots=[], deploy=True))
        self.assertEqual(rc, 5, v)
        self.assertEqual(v["effective_status"], "verify_failed")
        self.assertFalse(v["entry_reachable"])

    def test_verify_catches_deployed_subskill_drift(self):
        """部署侧副本被改 → verify 必须报漂移（映射 hash / 入口 hash）。"""
        self._deploy_parent_into(self.roots[0])
        src = self._make_skill("zz-vd", desc="verify 部署 (.yar)")
        rec = self.run_import(src=src, kind="subskill", parent=self.parent,
                              deploy_roots=[self.roots[0]])
        self.assertEqual(rec["rc"], 0, rec)
        guide = os.path.join(self.roots[0], self.parent, "references", "imported-subskills",
                             "zz-vd", "GUIDE.md")
        with io.open(guide, "a", encoding="utf-8") as f:
            f.write("\nTAMPERED\n")
        rc, v = self.quiet_json(self.impl.cmd_verify,
                                **self.opts(name="zz-vd", deploy_roots=[self.roots[0]]))
        self.assertEqual(rc, 5, v)
        self.assertEqual(v["effective_status"], "verify_failed")


# ================================================================ 4. roots 唯一解析 / 边界（R4/R9）
class TestRootsBoundary(TxnCase):
    def _sentinel(self):
        return snapshot(self.tmp)

    def test_custom_skill_dir_without_deploy_root_refused(self):
        src = self._make_skill("zz-r1", desc="无根 (.exe)")
        before = self._sentinel()
        rec = self.impl.run_import(self.impl._opts(src=src, kind="crosscutting",
                                                   skill_dir=self.skill_dir))
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "deploy_root_required")
        self.assertEqual(self._sentinel(), before, "被拒之前不许写任何一个字节")

    def test_deploy_cmd_without_root_refuses_for_custom_skill_dir(self):
        """`deploy` 子命令必须走同一道门（旧实现会兜底到真实 ~/.pi）。"""
        name = "zz-r2"
        self.run_import(src=self._make_skill(name, desc="部署 (.exe)"), kind="crosscutting",
                        deploy=False, deploy_roots=[])
        before = snapshot(self.fake_home)
        rc, out = self.cli("deploy", "--name", name, "--skill-dir", self.skill_dir, "--json")
        self.assertEqual(rc, 4, out[-600:])
        self.assertIn("deploy_root_required", out)
        self.assertEqual(snapshot(self.fake_home), before)

    def test_root_overlap_and_symlink_refused_before_write(self):
        src = self._make_skill("zz-r3", desc="逃逸 (.exe)")
        cases = {
            "root==skill_dir": self.skill_dir,
            "root inside repo": self.repo,
            "root==Tool": os.path.join(self.repo, "Tool"),
            "root==src parent": os.path.dirname(src),
        }
        for label, root in cases.items():
            before = self._sentinel()
            rec = self.impl.run_import(self.opts(src=src, kind="crosscutting",
                                                 deploy_roots=[root]))
            self.assertEqual(rec["rc"], 4, (label, rec.get("why")))
            self.assertEqual(rec["refusal"]["code"], "deploy_root_overlap", label)
            self.assertEqual(self._sentinel(), before, "%s：拒绝前写了盘" % label)
        # symlink 部署根
        link_target = os.path.join(self.tmp, "SENTINEL-target")
        os.makedirs(link_target, exist_ok=True)
        link = os.path.join(self.tmp, "SENTINEL-link")
        try:
            os.symlink(link_target, link, target_is_directory=True)
        except (OSError, NotImplementedError) as e:
            self.skipTest("本机不能创建符号链接：%s" % e)
        before = self._sentinel()
        rec = self.impl.run_import(self.opts(src=src, kind="crosscutting",
                                             deploy_roots=[link]))
        self.assertEqual(rec["rc"], 4, rec.get("why"))
        self.assertEqual(rec["refusal"]["code"], "deploy_root_symlink")
        self.assertEqual(self._sentinel(), before)

    def test_verify_never_falls_back_to_real_user_root(self):
        """verify 不给根：subskill 走"不部署"分支；domain/crosscutting 明确拒，不读真实根。"""
        name = "zz-r4"
        self.run_import(src=self._make_skill(name, desc="verify 根 (.exe)"), kind="crosscutting",
                        deploy=False, deploy_roots=[])
        before = snapshot(self.fake_home)
        rc, out = self.cli("verify", "--name", name, "--skill-dir", self.skill_dir, "--json")
        v = json.loads(out)
        self.assertEqual(rc, 4, out[-600:])
        self.assertEqual(v["refusal"]["code"], "deploy_root_required")
        self.assertEqual(v["verify_scope"], "repo_only")
        self.assertEqual(snapshot(self.fake_home), before)

    def test_default_deploy_root_reads_current_agent_root_environment_each_call(self):
        """模块加载后再注入环境也必须生效；PI_CODING_AGENT_DIR 优先于 PI_AGENT_DIR。"""
        first = os.path.join(self.tmp, "agent-current-a")
        second = os.path.join(self.tmp, "agent-current-b")
        fallback = os.path.join(self.tmp, "agent-current-c")
        with mock.patch.object(self.impl, "SKILL_DIR", self.skill_dir):
            with mock.patch.dict(os.environ, {
                    "PI_CODING_AGENT_DIR": first,
                    "PI_AGENT_DIR": fallback,
            }, clear=False):
                resolved = self.impl._resolve_deploy_roots(
                    self.impl._opts(skill_dir=self.skill_dir), "crosscutting")
            self.assertEqual(resolved[0], [os.path.join(first, "skills")])

            env = mock.patch.dict(os.environ, {
                    "PI_CODING_AGENT_DIR": second,
                    "PI_AGENT_DIR": first,
            }, clear=False)
            env.start()
            try:
                resolved2 = self.impl._resolve_deploy_roots(
                    self.impl._opts(skill_dir=self.skill_dir), "crosscutting")
            finally:
                env.stop()
            self.assertEqual(resolved2[0], [os.path.join(second, "skills")])

            with mock.patch.dict(os.environ, {
                    "PI_CODING_AGENT_DIR": "", "PI_AGENT_DIR": "",
                    "HOME": self.fake_home, "USERPROFILE": self.fake_home,
            }, clear=False):
                resolved3 = self.impl._resolve_deploy_roots(
                    self.impl._opts(skill_dir=self.skill_dir), "crosscutting")
            self.assertEqual(resolved3[0], [os.path.join(self.fake_home, ".pi", "agent", "skills")])

    def test_agent_root_environment_is_honored_before_fresh_module_load(self):
        code = (
            "import importlib.util, json;"
            "p=json.loads(%r);"
            "s=importlib.util.spec_from_file_location('fresh_import', %r);"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            "print(m._default_deploy_root())"
        ) % (json.dumps({
            "HOME": self.fake_home,
            "USERPROFILE": self.fake_home,
            "PI_CODING_AGENT_DIR": os.path.join(self.tmp, "fresh-agent"),
            "PI_AGENT_DIR": os.path.join(self.tmp, "ignored-agent"),
        }), SCRIPT)
        env = dict(os.environ)
        env.update({
            "HOME": self.fake_home,
            "USERPROFILE": self.fake_home,
            "PI_CODING_AGENT_DIR": os.path.join(self.tmp, "fresh-agent"),
            "PI_AGENT_DIR": os.path.join(self.tmp, "ignored-agent"),
            "PYTHONIOENCODING": "utf-8",
        })
        r = subprocess.run(
            [sys.executable, "-B", "-X", "utf8", "-c", code],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            cwd=ROOT, env=env, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), os.path.join(self.tmp, "fresh-agent", "skills"))

        with mock.patch.object(self.impl, "SKILL_DIR", self.skill_dir):
            with mock.patch.dict(os.environ, {
                    "PI_CODING_AGENT_DIR": os.path.abspath(os.sep),
                    "PI_AGENT_DIR": os.path.join(self.tmp, "must-not-fallback"),
            }, clear=False):
                with self.assertRaises(self.impl.Refuse) as caught:
                    self.impl._resolve_deploy_roots(
                        self.impl._opts(skill_dir=self.skill_dir), "crosscutting")
        self.assertEqual(caught.exception.code, "agent_root_invalid")


# ================================================================ 4b. journal durability
class TestJournalDurability(TxnCase):
    def test_write_flush_and_fsync_failures_are_never_swallowed(self):
        journal_path = os.path.join(self.tmp, "journal.jsonl")

        failing_write = mock.Mock()
        failing_write.write.side_effect = OSError("write failed")
        journal = self.impl.Journal(journal_path)
        real_handle = journal._fh
        journal._fh = failing_write
        try:
            with self.assertRaises(self.impl.Refuse) as caught:
                journal.record("phase", phase="stage")
        finally:
            journal._fh = real_handle
            journal.close()
        self.assertEqual(caught.exception.code, "journal_persist_failed")
        self.assertEqual(list(journal), [], "未持久化的记录不得进入内存事实")

        failing_flush = mock.Mock()
        failing_flush.flush.side_effect = OSError("flush failed")
        journal = self.impl.Journal(journal_path)
        real_handle = journal._fh
        journal._fh = failing_flush
        try:
            with self.assertRaises(self.impl.Refuse) as caught:
                journal.record("phase", phase="stage")
        finally:
            journal._fh = real_handle
            journal.close()
        self.assertEqual(caught.exception.code, "journal_persist_failed")
        self.assertEqual(list(journal), [])

        journal = self.impl.Journal(journal_path)
        try:
            with mock.patch.object(self.impl.os, "fsync", side_effect=OSError("fsync failed")):
                with self.assertRaises(self.impl.Refuse) as caught:
                    journal.record("phase", phase="stage")
        finally:
            journal.close()
        self.assertEqual(caught.exception.code, "journal_persist_failed")
        self.assertEqual(list(journal), [])

    def test_journal_record_failure_stops_before_stage_and_destructive_rename(self):
        name = "zz-journal-fail"
        src = self._make_skill(name, desc="journal 失败 (.exe)")
        with mock.patch.object(
                self.impl.Journal,
                "_flush",
                side_effect=self.impl.Refuse(
                    5, "journal_persist_failed", "注入 journal 持久化失败")):
            rec = self.run_import(src=src, kind="crosscutting")
        self.assertEqual(rec["rc"], 5, rec)
        self.assertEqual(rec["refusal"]["code"], "journal_persist_failed")
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, name)))
        self.assertFalse(any(os.path.exists(os.path.join(r, name)) for r in self.roots))
        self.assertFalse(rec["recovery"]["pending_manual"], rec["recovery"])
        self.assertFalse(rec["recovery"]["auto_recoverable"], rec["recovery"])

    def test_journal_failure_after_commit_does_not_launch_rollback_renames(self):
        name = "zz-journal-after-commit"
        old = self._seed_skill(name)
        src = self._make_skill(name, desc="新版本 (.exe)", body="## 2\nNEW COMMIT\n")
        original = self.impl.Journal.record

        def fail_after_commit(journal, op, **kw):
            if op == "phase" and kw.get("phase") == "commit":
                raise self.impl.Refuse(
                    5, "journal_persist_failed", "注入提交后的 journal 持久化失败")
            return original(journal, op, **kw)

        with mock.patch.object(self.impl.Journal, "record", new=fail_after_commit):
            rec = self.run_import(
                src=src, kind="crosscutting", replace=True, deploy_roots=[], deploy=False)
        self.assertEqual(rec["rc"], 5, rec.get("why"))
        self.assertTrue(rec.get("recovery_required"), rec)
        self.assertTrue(rec.get("journal_kept"), rec)
        self.assertEqual(rec["effective_status"], "failed")
        self.assertTrue(rec["written"], rec)
        self.assertEqual(rec["deployed"], [])
        self.assertGreater(rec["files_imported"], 0, rec)
        self.assertTrue(rec["recovery"]["auto_recoverable"], rec["recovery"])
        # No rollback rename was launched after the durability failure: the new
        # repository entry is still on disk, and its durable journal can undo it later.
        with io.open(os.path.join(old, "SKILL.md"), encoding="utf-8") as stream:
            self.assertIn("NEW COMMIT", stream.read())
        rec2 = self.run_import(
            src=src, kind="crosscutting", replace=True, deploy_roots=[], deploy=False)
        self.assertEqual(rec2["rc"], 0, rec2.get("why"))
        recovered = rec2.get("auto_recovered") or []
        self.assertEqual([item["action"] for item in recovered], ["rollback"], recovered)

    def test_deploy_journal_failure_after_first_root_reports_real_write_state(self):
        name = "zz-deploy-journal-after-root"
        self._seed_skill(name)
        original = self.impl.Journal.record

        def fail_at_second_root(journal, op, **kw):
            if (op == "phase" and kw.get("phase") == "commit_started"
                    and self.impl._norm(kw.get("root") or "") == self.impl._norm(self.roots[1])):
                raise self.impl.Refuse(
                    5, "journal_persist_failed", "注入第二个部署根的 journal 持久化失败")
            return original(journal, op, **kw)

        opts = self.opts(name=name)
        opts["json"] = True
        with mock.patch.object(self.impl.Journal, "record", new=fail_at_second_root):
            rc, rec = self.quiet_json(self.impl.cmd_deploy, **opts)
        self.assertEqual(rc, 5, rec)
        self.assertEqual(rec["refusal"]["code"], "journal_persist_failed", rec)
        self.assertTrue(rec["written"], rec)
        self.assertTrue(rec["recovery_required"], rec)
        self.assertEqual(rec["deployed"], [], rec)
        self.assertTrue(os.path.isdir(os.path.join(self.roots[0], name)), rec)
        self.assertFalse(os.path.exists(os.path.join(self.roots[1], name)), rec)
        self.assertTrue(rec["recovery"]["auto_recoverable"], rec["recovery"])
        self.assertEqual(
            rec["recovery"]["journals"][0]["report"]["effective_stage"],
            "commit_in_progress", rec["recovery"])

    def test_cleanup_failure_is_secondary_to_the_primary_journal_failure(self):
        name = "zz-journal-double-fault"
        self._seed_skill(name)
        src = self._make_skill(name, desc="双重故障 (.exe)", body="## new\n")
        original = self.impl.Journal.record

        def fail_after_commit(journal, op, **kw):
            if op == "phase" and kw.get("phase") == "commit":
                raise self.impl.Refuse(
                    5, "journal_persist_failed", "主故障：journal 持久化失败")
            return original(journal, op, **kw)

        def fail_close(journal, remove=False):
            if journal._fh:
                journal._fh.close()
                journal._fh = None
            raise self.impl.Refuse(
                5, "journal_cleanup_failed", "次故障：journal 关闭失败")

        with mock.patch.object(self.impl.Journal, "record", new=fail_after_commit):
            with mock.patch.object(
                    self.impl.Journal, "close", new=fail_close):
                rec = self.run_import(
                    src=src, kind="crosscutting", replace=True,
                    deploy_roots=[], deploy=False)
        self.assertEqual(rec["rc"], 5)
        self.assertEqual(rec["refusal"]["code"], "journal_persist_failed", rec)
        secondary = rec["refusal"].get("secondary_failures") or []
        self.assertEqual(secondary[0]["code"], "transaction_cleanup_failed", secondary)

    def test_cleanup_failure_after_verified_keeps_disk_facts_but_not_effective(self):
        name = "zz-cleanup-after-verify"
        src = self._make_skill(name, desc="清理失败 (.exe)")
        original = self.impl._release_locks

        def release_then_report(paths):
            errors = original(paths)
            return errors + ["injected release failure"]

        with mock.patch.object(self.impl, "_release_locks", side_effect=release_then_report):
            rec = self.run_import(src=src, kind="crosscutting")
        self.assertEqual(rec["rc"], 5, rec.get("why"))
        self.assertEqual(rec["effective_status"], "verified_cleanup_pending")
        self.assertTrue(rec["written"], rec)
        self.assertGreater(rec["files_imported"], 0, rec)
        self.assertTrue(rec["deployed"], rec)
        self.assertFalse(rec["effective"], rec)
        self.assertFalse(rec["available_next_session"], rec)
        self.assertEqual(rec["refusal"]["code"], "transaction_cleanup_failed")
        self.assertTrue(rec["to_take_effect"], rec)

    def test_journal_cleanup_failure_is_reported_not_masked(self):
        path = os.path.join(self.tmp, "cleanup.jsonl")
        journal = self.impl.Journal(path)
        journal.record("phase", phase="stage")
        with mock.patch.object(self.impl.os, "remove", side_effect=OSError("remove failed")):
            with self.assertRaises(self.impl.Refuse) as caught:
                journal.close(remove=True)
        self.assertEqual(caught.exception.code, "journal_cleanup_failed")
        self.assertTrue(os.path.isfile(path))

    def test_journal_close_failure_is_reported(self):
        path = os.path.join(self.tmp, "close.jsonl")
        journal = self.impl.Journal(path)
        real_handle = journal._fh
        failing = mock.Mock(wraps=real_handle)
        failing.close.side_effect = [OSError("close failed"), None]
        journal._fh = failing
        try:
            with self.assertRaises(self.impl.Refuse) as caught:
                journal.close()
        finally:
            real_handle.close()
        self.assertEqual(caught.exception.code, "journal_cleanup_failed")

    def test_journal_short_write_is_a_persistence_failure(self):
        path = os.path.join(self.tmp, "short.jsonl")
        journal = self.impl.Journal(path)
        real_handle = journal._fh
        failing = mock.Mock(wraps=real_handle)
        failing.write.return_value = 0
        journal._fh = failing
        try:
            with self.assertRaises(self.impl.Refuse) as caught:
                journal.record("phase", phase="stage")
        finally:
            journal._fh = real_handle
            journal.close()
        self.assertEqual(caught.exception.code, "journal_persist_failed")
        self.assertEqual(list(journal), [])

    def test_journal_corruption_with_final_newline_is_not_ignored(self):
        path = os.path.join(self.tmp, "corrupt.jsonl")
        valid = json.dumps({"op": "phase", "phase": "validate"})
        with io.open(path, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(valid + "\n{broken")
        entries, malformed = self.impl._read_journal_entries(path)
        self.assertEqual([e["phase"] for e in entries], ["validate"])
        self.assertEqual(malformed, [2])
        with io.open(path, "a", encoding="utf-8", newline="\n") as stream:
            stream.write("\n")
        with self.assertRaises(self.impl.Refuse) as caught:
            self.impl._read_journal_entries(path)
        self.assertEqual(caught.exception.code, "journal_corrupt")

    def test_complete_json_without_record_boundary_is_not_durable_evidence(self):
        path = os.path.join(self.tmp, "unterminated.jsonl")
        first = json.dumps({"op": "phase", "phase": "validate"})
        second = json.dumps({"op": "phase", "phase": "commit_started"})
        with io.open(path, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(first + "\n" + second)
        entries, malformed = self.impl._read_journal_entries(path)
        self.assertEqual([e["phase"] for e in entries], ["validate"])
        self.assertEqual(malformed, [2])

    def test_atomic_write_fsync_failure_keeps_target_and_cleans_tmp(self):
        path = os.path.join(self.tmp, "parent.md")
        with io.open(path, "w", encoding="utf-8", newline="") as stream:
            stream.write("before\n")
        with mock.patch.object(
                self.impl.os, "fsync", side_effect=OSError("atomic fsync failed")):
            with self.assertRaises(self.impl.Refuse) as caught:
                self.impl._atomic_write_text(path, "after\n")
        self.assertEqual(caught.exception.code, "atomic_write_failed")
        with io.open(path, encoding="utf-8", newline="") as stream:
            self.assertEqual(stream.read(), "before\n")
        self.assertEqual(
            [x for x in os.listdir(self.tmp) if ".seep-tmp-" in x], [])

    def test_lock_metadata_handles_short_write_and_fsync_failure(self):
        path = os.path.join(self.tmp, "short-write.lock")
        real_write = self.impl.os.write

        def short_write(fd, data):
            return real_write(fd, bytes(data[:5]))

        with mock.patch.object(self.impl.os, "write", side_effect=short_write):
            got = self.impl._write_lock(
                path, self.impl._lock_payload("test", "fixture"))
        self.assertEqual(got, path)
        meta = self.impl._read_lock(path)
        self.assertEqual(meta.get("pid"), os.getpid())
        os.remove(path)

        with mock.patch.object(
                self.impl.os, "fsync", side_effect=OSError("lock fsync failed")):
            with self.assertRaises(self.impl.Refuse) as caught:
                self.impl._write_lock(
                    path, self.impl._lock_payload("test", "fixture"))
        self.assertEqual(caught.exception.code, "lock_persist_failed")
        self.assertFalse(os.path.exists(path))


# ================================================================ 4c. route self-hit
class TestDomainOwnRoute(TxnCase):
    def test_import_rejects_pack_whose_l1_does_not_hit_its_own_route(self):
        name = "zz-self-route"
        src = self._make_domain(name, "actual-trigger", 9310,
                                root=os.path.join(self.tmp, "scratch"))
        pack_path = os.path.join(src, "pack.json")
        with io.open(pack_path, encoding="utf-8") as stream:
            pack = json.load(stream)
        pack["l1"] = "completely unrelated index text"
        with io.open(pack_path, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(pack, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        before = snapshot(self.skill_dir)
        rec = self.run_import(src=src, name=name, kind="domain")
        self.assertEqual(rec["rc"], 5, rec)
        self.assertEqual(rec["refusal"]["code"], "route_self_miss")
        self.assertTrue(rec["rolled_back"], rec.get("rollback"))
        self.assertEqual(snapshot(self.skill_dir), before)
        self.assertFalse(any(os.path.exists(os.path.join(r, name)) for r in self.roots))

    def test_verify_rejects_forged_manifest_after_l1_no_longer_hits_self(self):
        name = "zz-self-route-v"
        src = self._make_domain(name, "verify-trigger", 9311,
                                root=os.path.join(self.tmp, "scratch-v"))
        rec = self.run_import(src=src, name=name, kind="domain")
        self.assertEqual(rec["rc"], 0, rec)
        target = os.path.join(self.skill_dir, name)
        pack_path = os.path.join(target, "pack.json")
        with io.open(pack_path, encoding="utf-8") as stream:
            pack = json.load(stream)
        pack["l1"] = "no route owns this sentence"
        with io.open(pack_path, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(pack, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        manifest_path = os.path.join(target, "import-manifest.json")
        with io.open(manifest_path, encoding="utf-8") as stream:
            manifest = json.load(stream)
        manifest["files"] = self.impl.hash_tree(target)
        manifest["files"].pop("import-manifest.json", None)
        with io.open(manifest_path, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(manifest, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        rc, out = self.cli("verify", "--name", name, "--skill-dir", self.skill_dir,
                           "--deploy-root", self.roots[0], "--deploy-root", self.roots[1],
                           "--json")
        payload = json.loads(out)
        self.assertEqual(rc, 5, out[-1000:])
        self.assertFalse(payload["route_hit_self"])
        self.assertEqual(payload["effective_status"], "verify_failed")


# ================================================================ 4d. real process death
class TestProcessCrashRecovery(TxnCase):
    def _run_cli_import(self, src, name, kind="crosscutting", replace=False,
                        crash_point="", parent=""):
        args = ["import", "--from", src, "--name", name, "--kind", kind,
                "--skill-dir", self.skill_dir,
                "--deploy-root", self.roots[0], "--deploy-root", self.roots[1], "--json"]
        if replace:
            args.append("--replace")
        if parent:
            args.extend(["--parent", parent])
        return self.cli(*args, env_extra={"SEEP_IMPORT_CRASH_POINT": crash_point})

    def _assert_auto_retry_green(self, src, name, kind, replace, parent=""):
        rc, out = self._run_cli_import(
            src, name, kind=kind, replace=replace, parent=parent)
        payload = json.loads(out)
        self.assertEqual(rc, 0, out[-1800:])
        self.assertTrue(payload.get("auto_recovered"), payload)
        self.assertFalse(payload["recovery"]["pending_manual"], payload["recovery"])
        self.assertFalse(payload["recovery"]["auto_recoverable"], payload["recovery"])
        self.assertFalse(os.path.isfile(self.impl._lock_path(self.skill_dir, name)))
        return payload

    def test_real_os_exit_commit_window_matrix_recovers_then_retries(self):
        for point in (
                "commit.backup.rename.before",
                "commit.backup.rename.after",
                "commit.swap.move",
                "commit.swap.after",
        ):
            with self.subTest(point=point):
                name = "zz-crash-" + point.rsplit(".", 1)[-1]
                self._seed_skill(name)
                src = self._make_skill(name, desc="强退矩阵 (.exe)", body="## 2\nnew\n")
                rc, out = self._run_cli_import(
                    src, name, replace=True, crash_point=point)
                self.assertEqual(rc, 87, out[-1000:])
                self.assertTrue(os.path.isfile(self.impl._lock_path(self.skill_dir, name)))
                status_rc, status_out = self.cli(
                    "status", "--name", name, "--skill-dir", self.skill_dir,
                    "--deploy-root", self.roots[0], "--deploy-root", self.roots[1],
                    "--json", env_extra={"SEEP_IMPORT_CRASH_POINT": ""})
                status_payload = json.loads(status_out)
                self.assertEqual(status_rc, 0, status_out[-1000:])
                self.assertEqual(
                    status_payload["recovery"]["journals"][0]["report"]["effective_stage"],
                    "commit_in_progress", status_payload["recovery"]["journals"])
                payload = self._assert_auto_retry_green(
                    src, name, kind="crosscutting", replace=True)
                self.assertEqual(payload["effective_status"], "crosscutting_deployed")

    def test_real_os_exit_during_stage_cleanup_has_durable_owner(self):
        name = "zz-crash-stage-copy"
        src = self._make_skill(name, desc="stage 强退 (.exe)")
        rc, out = self._run_cli_import(
            src, name, crash_point="stage.copy.after")
        self.assertEqual(rc, 87, out[-1000:])
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, name)))
        pending = self.impl._recovery_report(
            self.skill_dir, self.roots, name)["staging"]
        self.assertTrue(any(os.path.isdir(item["path"]) for item in pending), pending)
        payload = self._assert_auto_retry_green(
            src, name, kind="crosscutting", replace=False)
        self.assertEqual(payload["effective_status"], "crosscutting_deployed")

    def test_real_os_exit_parent_patch_before_and_after_recovers(self):
        for point in ("parent.patch", "parent.patch.after"):
            with self.subTest(point=point):
                name = "zz-crash-parent-" + point.rsplit(".", 1)[-1]
                src = self._make_skill(name, desc="父文件强退 (.yar)")
                parent_path = os.path.join(self.skill_dir, self.parent, "SKILL.md")
                with io.open(parent_path, encoding="utf-8") as stream:
                    before_parent = stream.read()
                rc, out = self._run_cli_import(
                    src, name, kind="subskill", crash_point=point, parent=self.parent)
                self.assertEqual(rc, 87, out[-1000:])
                self.assertTrue(os.path.isfile(self.impl._lock_path(self.skill_dir, name)))
                payload = self._assert_auto_retry_green(
                    src, name, kind="subskill", replace=False, parent=self.parent)
                self.assertEqual(payload["effective_status"], "pending_subskill")
                self.assertTrue(payload["entry_reachable"])
                with io.open(parent_path, encoding="utf-8") as stream:
                    self.assertNotEqual(stream.read(), before_parent)

    def test_real_os_exit_between_two_deploy_roots_recovers(self):
        name = "zz-crash-between-roots"
        src = self._make_skill(name, desc="双根强退 (.exe)")
        rc, out = self._run_cli_import(
            src, name, crash_point="deploy.between.0")
        self.assertEqual(rc, 87, out[-1000:])
        self.assertTrue(os.path.exists(os.path.join(self.roots[0], name)))
        self.assertFalse(os.path.exists(os.path.join(self.roots[1], name)))
        payload = self._assert_auto_retry_green(
            src, name, kind="crosscutting", replace=False)
        self.assertEqual([d["hashes_equal"] for d in payload["deployed"]], [True, True])

    def test_recovery_locks_cover_roots_from_the_old_journal(self):
        name = "zz-crash-recovery-locks"
        src = self._make_skill(name, desc="恢复锁根 (.exe)")
        rc, out = self._run_cli_import(
            src, name, crash_point="deploy.between.0")
        self.assertEqual(rc, 87, out[-1000:])
        plan = self.impl.plan_import(self.opts(
            src=src, name=name, kind="crosscutting",
            deploy_roots=[self.roots[0]], replace=False))
        prefixes = ("%s-" % name, "deploy-%s-" % name)
        specs = self.impl._recovery_lock_specs(
            self.skill_dir, self.impl._lock_specs(plan), name, prefixes)
        protected = {self.impl._norm(item["path"]) for item in specs}
        self.assertIn(self.impl._norm(self.roots[0]), protected)
        self.assertIn(self.impl._norm(self.roots[1]), protected)
        self._assert_auto_retry_green(
            src, name, kind="crosscutting", replace=False)

    def test_real_os_exit_after_verified_phase_rolls_forward_and_cleans(self):
        name = "zz-crash-verified"
        src = self._make_skill(name, desc="verified 强退 (.exe)")
        rc, out = self._run_cli_import(
            src, name, crash_point="verify.after")
        self.assertEqual(rc, 87, out[-1000:])
        self.assertTrue(os.path.isdir(os.path.join(self.skill_dir, name)))
        payload = self._assert_auto_retry_green(
            src, name, kind="crosscutting", replace=True)
        self.assertEqual(payload["auto_recovered"][0]["action"], "roll_forward")

    def test_verified_recovery_refuses_roll_forward_when_disk_evidence_is_gone(self):
        name = "zz-crash-verified-missing"
        src = self._make_skill(name, desc="verified 磁盘丢失 (.exe)")
        rc, out = self._run_cli_import(
            src, name, crash_point="verify.after")
        self.assertEqual(rc, 87, out[-1000:])
        shutil.rmtree(os.path.join(self.skill_dir, name))
        status_rc, status_out = self.cli(
            "status", "--name", name, "--skill-dir", self.skill_dir,
            "--deploy-root", self.roots[0], "--deploy-root", self.roots[1],
            "--json", env_extra={"SEEP_IMPORT_CRASH_POINT": ""})
        status_payload = json.loads(status_out)
        self.assertEqual(status_rc, 0, status_out[-1000:])
        report = status_payload["recovery"]["journals"][0]["report"]
        self.assertFalse(report["auto_recoverable"], report)
        self.assertEqual(report["recovery_action"], "manual", report)
        self.assertTrue(report["disk_problems"], report)
        self.assertTrue(status_payload["recovery"]["pending_manual"], status_payload["recovery"])
        rc2, out2 = self._run_cli_import(
            src, name, kind="crosscutting", replace=False)
        payload = json.loads(out2)
        self.assertEqual(rc2, 5, out2[-1800:])
        self.assertEqual(payload["refusal"]["code"], "automatic_recovery_disk_mismatch")
        self.assertFalse(payload["recovery"]["auto_recoverable"], payload["recovery"])
        self.assertTrue(payload["recovery"]["pending_manual"], payload["recovery"])

    def test_verified_recovery_refuses_roll_forward_after_content_drift(self):
        name = "zz-crash-verified-drift"
        src = self._make_skill(name, desc="verified 内容漂移 (.exe)")
        rc, out = self._run_cli_import(
            src, name, crash_point="verify.after")
        self.assertEqual(rc, 87, out[-1000:])
        skill_file = os.path.join(self.skill_dir, name, "SKILL.md")
        with io.open(skill_file, "a", encoding="utf-8", newline="\n") as stream:
            stream.write("\nEXTERNAL DRIFT\n")
        status_rc, status_out = self.cli(
            "status", "--name", name, "--skill-dir", self.skill_dir,
            "--deploy-root", self.roots[0], "--deploy-root", self.roots[1],
            "--json", env_extra={"SEEP_IMPORT_CRASH_POINT": ""})
        status_payload = json.loads(status_out)
        self.assertEqual(status_rc, 0, status_out[-1000:])
        report = status_payload["recovery"]["journals"][0]["report"]
        self.assertEqual(report["recovery_action"], "manual", report)
        self.assertTrue(any("快照漂移" in item for item in report["disk_problems"]), report)
        rc2, out2 = self._run_cli_import(
            src, name, kind="crosscutting", replace=True)
        payload = json.loads(out2)
        self.assertEqual(rc2, 5, out2[-1800:])
        self.assertEqual(payload["refusal"]["code"], "automatic_recovery_disk_mismatch")
        self.assertTrue(payload["recovery"]["pending_manual"], payload["recovery"])

    def test_deploy_subcommand_process_death_recovers_before_retry(self):
        name = "zz-crash-deploy-cmd"
        src = self._seed_skill(name)
        args = ["deploy", "--name", name, "--skill-dir", self.skill_dir,
                "--deploy-root", self.roots[0], "--deploy-root", self.roots[1], "--json"]
        rc, out = self.cli(*args, env_extra={"SEEP_IMPORT_CRASH_POINT": "deploy.between.0"})
        self.assertEqual(rc, 87, out[-1000:])
        self.assertTrue(os.path.exists(os.path.join(self.roots[0], name)))
        self.assertFalse(os.path.exists(os.path.join(self.roots[1], name)))
        rc2, out2 = self.cli(*args, env_extra={"SEEP_IMPORT_CRASH_POINT": ""})
        payload = json.loads(out2)
        self.assertEqual(rc2, 0, out2[-1800:])
        self.assertTrue(payload.get("auto_recovered"), payload)
        for root in self.roots:
            self.assertEqual(self.impl.hash_tree(os.path.join(root, name)),
                             self.impl.hash_tree(src))
        self.assertFalse(payload["recovery"]["pending_manual"], payload["recovery"])


# ================================================================ 5. 只读恢复报告（R5/裁定 6）
class TestRecoveryReport(TxnCase):
    def test_failed_validate_receipt_reports_preserved_staging(self):
        name = "zz-stage-invalid-pack"
        src = self._make_skill(name, desc="structurally invalid pack (.exe)")
        with io.open(os.path.join(src, "pack.json"), "w", encoding="utf-8", newline="\n") as stream:
            json.dump({"id": name}, stream)
            stream.write("\n")

        rc, out = self.cli(
            "stage", "--from", src, "--name", name, "--kind", "domain",
            "--skill-dir", self.skill_dir, "--json")
        rec = json.loads(out)
        self.assertEqual(rc, 4, rec)
        self.assertEqual(rec["refusal"]["code"], "pack_schema", rec)
        self.assertEqual(rec["stage"], "validate", rec)
        self.assertTrue(rec["written"], rec)
        self.assertGreater(rec["files_imported"], 0, rec)
        self.assertTrue(os.path.isdir(rec["staging"]), rec)
        self.assertTrue(rec["recovery"]["auto_recoverable"], rec["recovery"])
        self.assertFalse(rec["recovery"]["pending_manual"], rec["recovery"])

    def test_stage_diagnostic_is_recovered_by_next_import(self):
        name = "zz-stage-retry"
        src = self._make_skill(name, desc="stage 重试 (.exe)")
        rc, out = self.cli("stage", "--from", src, "--name", name, "--kind", "crosscutting",
                           "--skill-dir", self.skill_dir, "--json")
        staged = json.loads(out)
        self.assertEqual(rc, 0, out[-1000:])
        self.assertEqual(staged["effective_status"], "staged_diagnostic")
        self.assertTrue(staged["recovery"]["auto_recoverable"], staged["recovery"])
        self.assertFalse(staged["recovery"]["pending_manual"], staged["recovery"])
        rec = self.run_import(src=src, name=name, kind="crosscutting")
        self.assertEqual(rec["rc"], 0, rec)
        self.assertEqual(rec["auto_recovered"][0]["action"], "rollback")
        self.assertFalse(rec["recovery"]["auto_recoverable"], rec["recovery"])

    def test_status_is_read_only_and_reports_leftovers(self):
        """中断残留（staging + 锁 + journal）→ status 如实报，且一个字节都不动。"""
        name = "zz-st"
        src = self._make_skill(name, desc="status (.exe)")
        plan = self.impl.plan_import(self.opts(src=src, kind="crosscutting"))
        st = self.impl._stage(plan, [], {})
        staging = st["staging"]
        held = self.impl._acquire_lock(self.skill_dir, name)
        jdir = os.path.join(self.skill_dir, self.impl.STAGING_NAME, self.impl.JOURNAL_DIR)
        os.makedirs(jdir, exist_ok=True)
        jp = os.path.join(jdir, "%s-dead.jsonl" % name)
        with io.open(jp, "w", encoding="utf-8") as f:
            f.write(json.dumps({"op": "phase", "phase": "deploy", "pid": 424242}) + "\n")
        before = snapshot(self.skill_dir)
        try:
            rc, rep = self.quiet_json(self.impl.cmd_status,
                                      **self.opts(name=name, deploy_roots=[self.roots[0]],
                                                  deploy=True))
            after = snapshot(self.skill_dir)
        finally:
            self.impl._release_lock(held)
        self.assertEqual(rc, 0, rep)
        self.assertTrue(rep["recovery"]["read_only"])
        self.assertTrue(rep["recovery"]["auto_recover"])
        self.assertTrue(rep["recovery"]["pending_manual"])
        self.assertTrue(rep["recovery"]["auto_recoverable"])
        self.assertTrue(any(l["path"] == held for l in rep["recovery"]["locks"]))
        self.assertTrue(any(s["path"] == staging for s in rep["recovery"]["staging"]))
        self.assertTrue(any(j["path"] == jp for j in rep["recovery"]["journals"]))
        self.assertEqual(rep["recovery"]["journals"][0]["report"]["phase"], "deploy")
        self.assertEqual(after, before, "status 是只读入口：不得删锁/staging/journal")

    def test_receipt_reports_pending_manual_after_kill_like_leftover(self):
        """回执里也必须带 recovery 段（残留存在时 pending_manual=true）。"""
        name = "zz-st2"
        src = self._make_skill(name, desc="回执恢复 (.exe)")
        plan = self.impl.plan_import(self.opts(src=src, kind="crosscutting"))
        st = self.impl._stage(plan, [], {})
        held = self.impl._acquire_lock(self.skill_dir, name)
        try:
            rc, rep = self.quiet_json(self.impl.cmd_import,
                                      **self.opts(src=src, kind="crosscutting", name=name))
        finally:
            self.impl._release_lock(held)
        self.assertEqual(rc, rep["rc"])
        self.assertEqual(rep["rc"], 4, rep.get("why"))
        self.assertTrue(rep["recovery"]["pending_manual"])
        self.assertTrue(os.path.isdir(st["staging"]), "拒绝路径不得删他人的 staging")

    def test_status_clean_after_success(self):
        """正常成功后不应有残留锁/journal（staging 目录清干净）。"""
        name = "zz-st3"
        rec = self.run_import(src=self._make_skill(name, desc="clean (.exe)"),
                              kind="crosscutting")
        self.assertEqual(rec["rc"], 0, rec)
        self.assertFalse(rec["recovery"]["pending_manual"], rec["recovery"])
        self.assertFalse(os.path.isfile(self.impl._lock_path(self.skill_dir, name)))


# ================================================================ 6. 缺口如实声明（裁定 7）
class TestGapDeclaration(TxnCase):
    def test_all_five_hardcoded_contracts_pointed_out(self):
        """固定表契约仍如实列出；动态 pack 面不得再依赖 FORMAL_DOMAINS。"""
        d = os.path.join(self.tmp, "scratch")
        os.makedirs(d, exist_ok=True)
        src = self._make_domain("zz-gap", "gap 域", 9300, root=d)
        rec = self.run_import(src=src, name="zz-gap", kind="domain")
        self.assertEqual(rec["rc"], 0, rec)
        pending = "；".join(rec["registered_pending_contracts"])
        for key in ("domain_spec", "_templates/zz-gap.json", "DOMAIN_COUNT",
                    "formal_domains"):
            self.assertIn(key, pending, key)
        self.assertNotIn("FORMAL_DOMAINS", pending)
        self.assertTrue(rec["capability_gap"])
        self.assertFalse(rec["formal_domain_active"])
        self.assertFalse(rec["effective"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
