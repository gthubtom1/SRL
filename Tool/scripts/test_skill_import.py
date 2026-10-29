#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_skill_import.py —— 单入口扩展导入（skill-import.py）的真实文件事务回归测试。

本文件只做一件事：把「导入要么完整成功、要么原样回滚」钉成可回归的断言。
被测代码是 `Tool/scripts/skill-import.py` 的**真实函数与真实 CLI**，判据用的是仓库里
**真实检查器**（`route.py` 的 load_packs/check/resolve、`gate.py` 的 g2_schema、
`domain-gate.py` 的 _norm_sha、`tool-contract-check.py` 的 Catalogs），不复制 schema、
不 mock 文件内容、不 shell 出去跑全仓门禁。

硬边界（与设计稿 work/goal-recovery/extension-import-plan.md §7 一致）：
  · 所有写入都发生在 `tempfile.mkdtemp()` 造的临时 repo + 临时 agent root；
    `--skill-dir` / `--deploy-root` 显式注入，**绝不**碰真实 `Tool/skill`、`~/.pi`、
    HOME/CODEX_HOME 或用户目录（G0 哨兵每条用例都查）。
  · 不执行被导入的技能代码、不联网、不安装、不跑目标、不改 git。

跑法：
    python -B -X utf8 Tool/scripts/test_skill_import.py
退出码 0 = 全部通过。
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
ROOT = os.path.dirname(TOOL)
SCRIPT = os.path.join(HERE, "skill-import.py")

PACK_TMPL = {
    "schema": "seep.pack/1",
    "id": "",
    "l1": "",
    "routes": [{"label": "lab route", "must": [], "priority": 0}],
    "stages": ["0-analysis"],
    "tools": ["seep_apk_info"],
    "cases": ["leaf-apk"],
    "case_roles": {"witness": ["leaf-apk"], "depth_gate": ["leaf-apk"]},
    "witness": {"cmd": "python Tool/scripts/case_state.py verify --case Tool/cases/leaf-apk",
                "expect": "exit0", "budget_s": 30},
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
    spec = importlib.util.spec_from_file_location("seep_skill_import_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def snapshot(path):
    """目录快照（相对路径 → 字节哈希）：用于「真实目录没被动过」的哨兵断言。"""
    import hashlib
    out = {}
    if not os.path.isdir(path):
        return out
    for dp, dn, fn in os.walk(path):
        dn[:] = sorted(dn)
        for f in sorted(fn):
            p = os.path.join(dp, f)
            try:
                with open(p, "rb") as fh:
                    data = fh.read()
                out[os.path.relpath(p, path).replace(os.sep, "/")] = hashlib.sha256(data).hexdigest()
            except OSError:
                out[os.path.relpath(p, path).replace(os.sep, "/")] = "<unreadable>"
    return out


def write_text(path, text, **kwargs):
    with io.open(path, "w", encoding="utf-8", **kwargs) as stream:
        stream.write(text)


def read_text(path, **kwargs):
    with io.open(path, encoding="utf-8", **kwargs) as stream:
        return stream.read()


def softseep_navigation_fixture():
    """Copy the current product's four-column index, omitting unrelated prose."""
    text = read_text(os.path.join(TOOL, "skill", "softseep", "SKILL.md"))
    start = text.index("## 🧭 本领域专业子技能导航")
    end = text.index("\n## 调度总流程", start)
    return text[start:end] + "\n\n## 调度总流程\n\n隔离夹具正文。\n"


class ImportCase(unittest.TestCase):
    """公共装置：临时 repo（Tool/skill + Tool/cases/_templates）+ 临时 agent roots。"""

    @classmethod
    def setUpClass(cls):
        cls.impl = _load_impl()

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="seep-import-test-")
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
        # 一个真实的父域（pack.id == 目录名，锚点唯一）
        self.parent = "zz-parent"
        self._make_domain(self.parent, "parent 域", 9050,
                          anchor_children=["zzz-alpha"], body="父域正文\n")

    def tearDown(self):
        self.env_guard.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------ 造数据
    def _make_domain(self, name, l1, priority, anchor_children=(), body="", pack_extra=None,
                     root=None):
        d = os.path.join(root or self.skill_dir, name)
        os.makedirs(d, exist_ok=True)
        children = "".join("- `subskills/%s/SKILL.md` —— 已有子技能\n" % c for c in anchor_children)
        text = ("---\nname: %s\ndescription: \"%s：怎么用/帮我看看\"\n---\n\n%s\n\n"
                "## 子技能（按需读，不常驻）\n\n"
                "本域相关子技能放在 `subskills/`（不占常驻上下文，需要时再读）：\n\n"
                "%s" % (name, l1, body, children))
        write_text(os.path.join(d, "SKILL.md"), text, newline="\n")
        pack = json.loads(json.dumps(PACK_TMPL))
        pack["id"] = name
        pack["l1"] = ("%s 这个问题怎么处理" % l1)[:120]
        pack["routes"][0]["must"] = ["(?i)%s" % l1]
        pack["routes"][0]["priority"] = priority
        scripts = os.path.join(d, "scripts")
        os.makedirs(scripts, exist_ok=True)
        write_text(
            os.path.join(scripts, "witness.py"),
            "#!/usr/bin/env python3\n"
            "import json\n"
            "print(json.dumps({'domain': %r, 'status': 'fixture-only'}))\n" % name,
            newline="\n",
        )
        pack["witness_tool"]["cmd"] = "Tool/skill/%s/scripts/witness.py" % name
        if pack_extra:
            pack.update(pack_extra)
        with io.open(os.path.join(d, "pack.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(pack, f, ensure_ascii=False, indent=2)
            f.write("\n")
        return d, pack

    def _make_skill(self, name, desc="怎么做的说明 (.exe)", extra_json=None, body=None):
        d = os.path.join(self.tmp, "src", name)
        os.makedirs(d, exist_ok=True)
        text = ("---\nname: %s\ndescription: \"%s\"\n---\n\n%s\n"
                % (name, desc, body if body is not None else "## 1\n小技巧\n"))
        write_text(os.path.join(d, "SKILL.md"), text, newline="\n")
        if extra_json:
            with io.open(os.path.join(d, extra_json[0]), "w", encoding="utf-8", newline="\n") as f:
                json.dump(extra_json[1], f, ensure_ascii=False, indent=2)
        return d

    def scratch_pack(self, name, l1, priority, **kw):
        """在临时 scratch 目录里造一个**源**域（不落 skill_dir，避免自我复制/目标已存在）。"""
        root = os.path.join(self.tmp, "scratch")
        os.makedirs(root, exist_ok=True)
        d, pack = self._make_domain(name, l1, priority, root=root, **kw)
        return d, pack

    def opts(self, **kw):
        base = dict(skill_dir=self.skill_dir, deploy_roots=list(self.roots))
        base.update(kw)
        return self.impl._opts(**base)

    def run_import_with(self, faults=None, **kw):
        return self.impl.run_import(self.opts(**kw), faults=faults or {})

    def cli(self, *args):
        cmd = [sys.executable, "-B", "-X", "utf8", SCRIPT] + list(args)
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", cwd=ROOT, env=env, timeout=300)
        return r.returncode, (r.stdout or "") + (r.stderr or "")


# ================================================================ 1. 旧入口
class TestLegacyEntry(ImportCase):
    def test_selftest_cli_still_green(self):
        rc, out = self.cli("--selftest")
        self.assertEqual(rc, 0, out)
        self.assertIn("自测通过", out)

    def test_legacy_from_without_pack_reports_needs_classification(self):
        """旧 `--from` 不再用关键词自封正式域：如实报 needs_classification + rc=2。"""
        src = self._make_skill("zz-legacy", desc="这个 exe 加壳了怎么脱壳/反调试/抓包 (.exe/.apk/.bin)",
                              body="\n".join("脱壳 反调试 取证 抓包 .exe .apk .bin" for _ in range(140)) + "\n")
        before = snapshot(self.skill_dir)
        rc, out = self.cli("--from", src, "--skill-dir", self.skill_dir,
                           "--deploy-root", self.roots[0])
        self.assertEqual(rc, 2, out)
        self.assertIn("needs_classification", out)
        payload = json.loads(out.rsplit("[报告] ", 1)[1].splitlines()[0])
        self.assertEqual(payload["kind"], "auto")
        self.assertFalse(payload["effective"])
        self.assertFalse(payload["written"])
        self.assertEqual(payload["kind_suggestion"], "domain")   # 建议仍是 domain，只是不自封
        self.assertEqual(snapshot(self.skill_dir), before)
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, "zz-legacy")))

    def test_legacy_from_with_real_pack_is_accepted_as_domain(self):
        """旧接口附带合法 pack.json（id == 目录名）→ 合法按域处理（不再要求用户填技术表）。"""
        src, _pack = self.scratch_pack("zz-legacy-dom", "legacy 域", 9060)
        rec = self.impl.run_import(self.opts(src=src, name="zz-legacy-dom"))
        self.assertEqual(rec["rc"], 0, rec)
        self.assertEqual(rec["kind"], "domain")
        self.assertTrue(rec["validation"]["g2_ok"])
        # 声明 ≠ 实跑：本批不执行任何 witness 代码
        self.assertTrue(rec["validation"]["witness_declared"])
        self.assertFalse(rec["validation"]["witness_ran"])
        self.assertFalse(rec["validation"]["case_roles_from_import"])
        self.assertEqual(rec["route_visible"], True)


# ================================================================ 2. 判型
class TestClassification(ImportCase):
    def test_auto_suggestion_but_no_write(self):
        src = self._make_skill("zz-auto", desc="帮我脱壳/抓包/反编译 (.exe/.apk/.dll)",
                               body="\n".join("脱壳 反调试 取证 抓包 .exe .apk .dll" for _ in range(140)))
        before = snapshot(self.skill_dir)
        rec = self.impl.run_import(self.opts(src=src, dry=True))
        self.assertEqual(rec["rc"], 2, rec)
        self.assertEqual(rec["refusal"]["code"], "needs_classification")
        self.assertEqual(rec["refusal"]["suggestion"]["kind_suggestion"], "domain")
        self.assertFalse(rec["written"])
        self.assertEqual(rec["files_imported"], 0)
        # 关键词命中 3/3 也不许自称正式域
        self.assertIn("不是正式域身份", rec["refusal"]["suggestion"]["note"])
        self.assertEqual(snapshot(self.skill_dir), before)

    def test_auto_with_pack_id_mismatch_asks_agent(self):
        """附带 pack 但 id != 目录名 → 不由关键词自封，报 needs_classification 给 Agent 确认。"""
        src = self._make_skill("zz-mismatch", desc="脱壳/抓包/反调试 (.exe/.apk/.dll)",
                               body="\n".join("脱壳 反调试 取证 抓包 .exe .apk .dll" for _ in range(140)))
        pack = json.loads(json.dumps(PACK_TMPL))
        pack["id"] = "some-other-id"
        pack["l1"] = "别的域"
        pack["routes"][0]["must"] = ["other"]
        pack["routes"][0]["priority"] = 9090
        with io.open(os.path.join(src, "pack.json"), "w", encoding="utf-8") as f:
            json.dump(pack, f, ensure_ascii=False)
        before = snapshot(self.skill_dir)
        rec = self.impl.run_import(self.opts(src=src, name="zz-mismatch"))
        self.assertEqual(rec["rc"], 2, rec)
        self.assertEqual(rec["refusal"]["code"], "needs_classification")
        self.assertIn("some-other-id", rec["refusal"]["message"])
        self.assertEqual(snapshot(self.skill_dir), before)

    def test_external_pack_injected_for_domain(self):
        """源目录没有 pack.json，但给了 --pack（id == --name）→ 合法按域导入，pack 落进 stage。"""
        src = self._make_skill("zz-extpack", desc="外部 pack (.exe)")
        scripts = os.path.join(src, "scripts")
        os.makedirs(scripts)
        write_text(
            os.path.join(scripts, "witness.py"),
            "#!/usr/bin/env python3\n"
            "import json\n"
            "print(json.dumps({'ok': True, 'domain': 'zz-extpack', 'witness': 'fixture'}))\n",
            newline="\n",
        )
        pack_dir, _pack = self.scratch_pack("zz-extpack", "extpack 域", 9095)
        rec = self.impl.run_import(self.opts(src=src, name="zz-extpack", kind="domain",
                                             pack=os.path.join(pack_dir, "pack.json")))
        self.assertEqual(rec["rc"], 0, rec)
        self.assertTrue(rec["pack_injected"])
        self.assertTrue(os.path.isfile(os.path.join(self.skill_dir, "zz-extpack", "pack.json")))
        self.assertTrue(rec["route_visible"])
        self.assertFalse(rec["formal_domain_active"])

    def test_explicit_domain_without_pack_refused(self):
        src = self._make_skill("zz-nopack")
        before = snapshot(self.skill_dir)
        rec = self.impl.run_import(self.opts(src=src, kind="domain"))
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "why_not_domain")
        self.assertIn("pack", rec["refusal"]["message"])
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, "zz-nopack")))
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, ".import-staging")))
        self.assertEqual(snapshot(self.skill_dir), before)


# ================================================================ 3. 正式域
class TestDomainImport(ImportCase):
    def test_domain_with_valid_pack_routes_but_not_globally_active(self):
        """带真实 pack 的新域：路由可发现，但全局契约未登记 → formal_domain_active=false。"""
        src, _pack = self.scratch_pack("zz-newdom", "newdom 云盘取证", 9070)
        rec = self.impl.run_import(self.opts(src=src, name="zz-newdom"))

        self.assertEqual(rec["rc"], 0, rec)
        self.assertEqual(rec["effective_status"], "domain_registered_pending_contracts")
        self.assertFalse(rec["formal_domain_active"])
        self.assertTrue(rec["capability_gap"])
        self.assertTrue(rec["route_visible"])
        self.assertTrue(rec["validation"]["g2_ok"])
        self.assertEqual(rec["files_imported"], 4)   # SKILL.md + pack.json + witness.py + manifest
        # 落位与部署都是真的，且 hash 一致
        self.assertTrue(os.path.isdir(os.path.join(self.skill_dir, "zz-newdom")))
        self.assertEqual(len(rec["deployed"]), 2)
        for d in rec["deployed"]:
            self.assertTrue(d["hashes_equal"], d)
        # 未登记项必须点名（不是假装 effective）
        pending = "；".join(rec["registered_pending_contracts"])
        self.assertIn("domain_spec", pending)
        self.assertIn("domain-aliases.json", pending)
        self.assertNotIn("FORMAL_DOMAINS", pending)
        self.assertFalse(rec["effective"])

        # 用**真实** route.py 复算：pack 数 +1、新路由可解析命中
        route_mod = self.impl._route()
        packs, problems = route_mod.load_packs(self.skill_dir)
        ids = {p["id"] for p in packs}
        self.assertIn("zz-newdom", ids)
        self.assertEqual(problems, [])
        hits = route_mod.resolve("newdom 云盘取证", self.skill_dir)
        self.assertIn("zz-newdom", {h["pack"] for h in hits})

    def test_domain_with_invalid_pack_rejected_by_real_g2(self):
        """pack 缺字段/案例不存在 → 被真实 gate.g2_schema 拒（不复制 schema 自证）。"""
        d = os.path.join(self.tmp, "src", "zz-badpack")
        os.makedirs(d, exist_ok=True)
        write_text(os.path.join(d, "SKILL.md"),
                   "---\nname: zz-badpack\ndescription: \"坏 pack\"\n---\n正文\n")
        bad = json.loads(json.dumps(PACK_TMPL))
        bad["id"] = "zz-badpack"
        bad["l1"] = "bad"
        bad["cases"] = ["does-not-exist-case"]
        bad["routes"][0]["must"] = ["bad"]
        bad["routes"][0]["priority"] = 9075
        with io.open(os.path.join(d, "pack.json"), "w", encoding="utf-8") as f:
            json.dump(bad, f, ensure_ascii=False)
        before = snapshot(self.skill_dir)
        rec = self.impl.run_import(self.opts(src=d, name="zz-badpack", kind="domain"))
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "pack_schema")
        self.assertIn("案例目录不存在", "；".join(rec["refusal"]["g2"]))
        self.assertEqual(snapshot(self.skill_dir), before)   # staging 也清干净了

    def test_domain_priority_clash_with_existing_domain(self):
        src, _pack = self.scratch_pack("zz-clash", "clash 域", 9050)   # 与父域同优先级
        rec = self.impl.run_import(self.opts(src=src, name="zz-clash"))
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "priority_clash")


# ================================================================ 4. 横切 / 子技能
class TestCrosscuttingAndSubskill(ImportCase):
    def test_crosscutting_lands_and_deploys(self):
        src = self._make_skill("zz-cross", desc="横切：抓包脚本怎么用 (.pcap)")
        rec = self.impl.run_import(self.opts(src=src, kind="crosscutting"))
        self.assertEqual(rec["rc"], 0, rec)
        self.assertEqual(rec["effective_status"], "crosscutting_deployed")
        self.assertTrue(os.path.isfile(os.path.join(self.skill_dir, "zz-cross", "SKILL.md")))
        self.assertEqual(len(rec["deployed"]), 2)
        self.assertFalse(rec["formal_domain_active"])
        self.assertTrue(any("cross_cutting" in w for w in rec["warnings"]))

    def test_subskill_parent_patch_and_idempotent(self):
        src = self._make_skill("zz-child", desc="读 yara 规则 (.yar)")
        pp = os.path.join(self.skill_dir, self.parent, "SKILL.md")
        before = read_text(pp)
        rec = self.impl.run_import(self.opts(src=src, kind="subskill", parent=self.parent))
        self.assertEqual(rec["rc"], 0, rec)
        self.assertEqual(rec["dest"], os.path.join(self.skill_dir, self.parent, "subskills", "zz-child"))
        self.assertTrue(rec["entry_reachable"])
        patch = rec["parent_patch"]
        self.assertTrue(patch["changed"])
        self.assertTrue(os.path.isfile(patch["backup"]))
        after = read_text(pp)
        self.assertEqual(len(after.splitlines()), len(before.splitlines()) + 1)
        self.assertEqual(after.count("subskills/zz-child/SKILL.md"), 1)
        # 只多一行，别的字符不动
        self.assertEqual(after.replace(patch["inserted"] + "\n", "").rstrip("\n"),
                         before.rstrip("\n"))
        # 幂等：替换重跑不再插第二行
        rec2 = self.impl.run_import(self.opts(src=src, kind="subskill", parent=self.parent,
                                             replace=True))
        self.assertEqual(rec2["rc"], 0, rec2)
        self.assertTrue(rec2["parent_patch"].get("idempotent"))
        self.assertEqual(read_text(pp).count("subskills/zz-child/SKILL.md"), 1)

    def test_subskill_missing_parent_refused_untouched(self):
        src = self._make_skill("zz-orphan")
        pp = os.path.join(self.skill_dir, self.parent, "SKILL.md")
        before = snapshot(os.path.join(self.skill_dir, self.parent))
        rec = self.impl.run_import(self.opts(src=src, kind="subskill", parent="no-such-domain"))
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "parent_missing")
        self.assertEqual(snapshot(os.path.join(self.skill_dir, self.parent)), before)
        self.assertEqual(read_text(pp).count("_pending/zz-orphan"), 0)
        # 缺 --parent 也不能默默落 _pending
        rec2 = self.impl.run_import(self.opts(src=src, kind="subskill"))
        self.assertEqual(rec2["rc"], 2, rec2)
        self.assertEqual(rec2["refusal"]["code"], "needs_parent")


# ================================================================ 5. 替换与回滚
class TestReplaceAndRollback(ImportCase):
    def _seed_existing(self, name="zz-rep"):
        dest = os.path.join(self.skill_dir, name)
        os.makedirs(dest)
        write_text(os.path.join(dest, "SKILL.md"),
                   "---\nname: %s\ndescription: \"旧版本\"\n---\nOLD\n" % name,
                   newline="\n")
        write_text(os.path.join(dest, "old-only.txt"), "keep me\n")
        return dest

    def test_replace_requires_flag_then_keeps_backup(self):
        dest = self._seed_existing()
        src = self._make_skill("zz-rep", desc="新版本 (.exe)")
        before_hash = self.impl.hash_tree(dest)
        rec = self.impl.run_import(self.opts(src=src, kind="crosscutting"))
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "target_exists")
        self.assertEqual(rec["effective_status"], "failed")
        self.assertEqual(rec["files_imported"], 0)
        self.assertEqual(rec["deployed"], [])
        self.assertEqual(rec["backups"], {})
        self.assertFalse(rec.get("backup_kept", False))
        self.assertEqual(self.impl.hash_tree(dest), before_hash)

        rec2 = self.impl.run_import(self.opts(src=src, kind="crosscutting", replace=True))
        self.assertEqual(rec2["rc"], 0, rec2)
        backup = rec2["backups"]["repo"]
        self.assertTrue(backup and os.path.isdir(backup), rec2["backups"])
        self.assertTrue(rec2["backup_kept"], rec2["backups"])
        # 备份是**旧目录整体搬迁**（不是 rmtree）：内容逐文件还在
        self.assertEqual(self.impl.hash_tree(os.path.join(backup, "zz-rep")), before_hash)
        self.assertFalse(os.path.exists(os.path.join(dest, "old-only.txt")))
        self.assertIn("新版本", read_text(os.path.join(dest, "SKILL.md")))

    def test_rapid_replacements_keep_distinct_backup_directories(self):
        name = "zz-rapid-replace"
        self._seed_existing(name)
        backups = []
        for version in ("v1", "v2"):
            src = self._make_skill(
                name, desc="%s (.exe)" % version, body="## %s\n%s\n" % (version, version))
            rec = self.impl.run_import(
                self.opts(src=src, kind="crosscutting", replace=True))
            self.assertEqual(rec["rc"], 0, rec)
            backups.append(rec["backups"]["repo"])
        self.assertNotEqual(backups[0], backups[1])
        self.assertTrue(all(os.path.isdir(path) for path in backups), backups)

    def test_fault_during_commit_swap_restores_old_dir(self):
        dest = self._seed_existing("zz-f1")
        src = self._make_skill("zz-f1", desc="新版本 (.exe)")
        before_hash = self.impl.hash_tree(dest)
        rec = self.impl.run_import(self.opts(src=src, kind="crosscutting", replace=True),
                                  faults={"commit.swap": True})
        self.assertEqual(rec["rc"], 5, rec)
        self.assertIn("注入故障", rec["why"])
        self.assertTrue(rec["rolled_back"], rec["rollback"])
        self.assertEqual(self.impl.hash_tree(dest), before_hash)
        self.assertIn("old-only.txt", self.impl.hash_tree(dest))

    def test_fault_during_deploy_second_root_restores_both(self):
        src = self._make_skill("zz-f2", desc="部署两处 (.exe)")
        # 先真实导入一次，制造「已部署的旧版本」
        r0 = self.impl.run_import(self.opts(src=src, kind="crosscutting"))
        self.assertEqual(r0["rc"], 0, r0)
        root1 = os.path.join(self.roots[0], "zz-f2")
        root2 = os.path.join(self.roots[1], "zz-f2")
        r1_before, r2_before = snapshot(root1), snapshot(root2)
        repo_before = snapshot(os.path.join(self.skill_dir, "zz-f2"))
        new_src = self._make_skill("zz-f2", desc="部署两处 v2 (.exe)", body="## 2\n新内容\n")
        rec = self.impl.run_import(self.opts(src=new_src, kind="crosscutting", replace=True),
                                  faults={"deploy.swap.1": True})
        self.assertEqual(rec["rc"], 5, rec)
        self.assertTrue(rec["rolled_back"], rec["rollback"])
        self.assertEqual(rec["effective_status"], "failed")
        self.assertFalse(rec["effective"])
        self.assertFalse(rec["available_next_session"])
        self.assertEqual(rec["deployed"], [])
        self.assertEqual(rec["files_imported"], 0)
        self.assertEqual(snapshot(root1), r1_before)
        self.assertEqual(snapshot(root2), r2_before)
        self.assertEqual(snapshot(os.path.join(self.skill_dir, "zz-f2")), repo_before)
        self.assertTrue(rec["backup_kept"], rec.get("backups"))
        self.assertEqual(set(rec["backups"]), {"retained_staging"})
        backups = rec["backups"]["retained_staging"]
        self.assertEqual(len(backups), 3, rec)
        self.assertEqual(set(backups), {item["backup"] for item in rec["retained_staging"]})
        manifest_hashes = set()
        for backup in backups:
            copied = snapshot(backup)
            manifest_hashes.add(copied.pop(self.impl.MANIFEST_NAME))
            self.assertEqual(copied, snapshot(new_src))
            manifest = json.loads(read_text(os.path.join(backup, self.impl.MANIFEST_NAME)))
            self.assertEqual(manifest["schema"], self.impl.MANIFEST_SCHEMA)
            self.assertEqual(manifest["name"], "zz-f2")
            self.assertEqual(manifest["kind"], "crosscutting")
            self.assertEqual(manifest["files"], self.impl.hash_tree(new_src))
        self.assertEqual(len(manifest_hashes), 1, "三份保留副本必须属于同一次 v2 导入")
        for root in [self.skill_dir] + self.roots:
            self.assertEqual(sum(self.impl._within(backup, os.path.join(root, self.impl.BACKUP_NAME))
                                 for backup in backups), 1)

    def test_verify_hash_drift_preserves_post_publish_edits_and_rejects_completion(self):
        src = self._make_skill("zz-f3", desc="verify 漂移 (.exe)")
        dest = os.path.join(self.skill_dir, "zz-f3")
        # Published content changed outside the transaction: verify must fail and
        # the stronger C7 contract forbids deleting that write during undo.
        published = {}
        orig = self.impl._verify

        def tampered(plan, receipt, skill_dir, faults):
            published["deploy"] = [snapshot(os.path.join(root, "zz-f3")) for root in self.roots]
            p = os.path.join(plan["target"], "SKILL.md")
            with open(p, "rb") as stream:
                data = stream.read()
            with open(p, "wb") as stream:
                stream.write(data + b"\nTAMPERED\n")
            return orig(plan, receipt, skill_dir, faults)

        import contextlib
        buf = io.StringIO()
        self.impl._verify = tampered
        try:
            with contextlib.redirect_stdout(buf):
                rec = self.impl.run_import(self.opts(src=src, kind="crosscutting"))
        finally:
            self.impl._verify = orig
        self.assertEqual(rec["rc"], 5, rec)
        self.assertEqual(rec["refusal"]["code"], "manifest_drift")
        self.assertFalse(rec["rolled_back"], rec["rollback"])
        self.assertTrue(rec["rollback_partial"], rec["rollback"])
        self.assertFalse(rec["effective"])
        self.assertTrue(rec["recovery"]["pending_manual"])
        self.assertIn("TAMPERED", read_text(os.path.join(dest, "SKILL.md")))
        self.assertEqual([snapshot(os.path.join(root, "zz-f3")) for root in self.roots], published["deploy"])

    def test_fault_during_repo_copy_leaves_nothing(self):
        src = self._make_skill("zz-f4", desc="copy 中断 (.exe)")
        before = snapshot(self.skill_dir)
        rec = self.impl.run_import(self.opts(src=src, kind="crosscutting"),
                                   faults={"stage.copy": True})
        self.assertEqual(rec["rc"], 5, rec)
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, "zz-f4")))
        self.assertEqual(snapshot(self.skill_dir), before)

    def test_fault_during_parent_patch_restores_parent(self):
        src = self._make_skill("zz-f5", desc="父引用中断 (.yar)")
        pp = os.path.join(self.skill_dir, self.parent, "SKILL.md")
        before_text = read_text(pp, newline="")
        rec = self.impl.run_import(self.opts(src=src, kind="subskill", parent=self.parent),
                                   faults={"parent.patch": True})
        self.assertEqual(rec["rc"], 5, rec)
        self.assertEqual(read_text(pp, newline=""), before_text)
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, self.parent, "subskills", "zz-f5")))


# ================================================================ 6. 拒绝面
class TestRefusals(ImportCase):
    def test_symlink_escape_refused(self):
        src = self._make_skill("zz-link")
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        write_text(os.path.join(outside, "secret.txt"), "secret\n")
        link = os.path.join(src, "leak")
        try:
            os.symlink(outside, link, target_is_directory=True)
        except (OSError, NotImplementedError) as e:      # Windows 无权限创建链接
            self.skipTest("本机不允许创建符号链接：%s" % e)
        rec = self.impl.run_import(self.opts(src=src, kind="crosscutting"))
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "symlink_escape")
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, "zz-link")))

    def test_self_copy_refused(self):
        """源目录 = 目标目录（递归自我复制）→ 拒。"""
        dest = os.path.join(self.skill_dir, "zz-self")
        os.makedirs(dest)
        write_text(os.path.join(dest, "SKILL.md"),
                   "---\nname: zz-self\ndescription: \"自我复制\"\n---\n")
        before = snapshot(self.skill_dir)
        rec = self.impl.run_import(self.opts(src=dest, name="zz-self", kind="crosscutting",
                                             replace=True))
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "self_copy")
        self.assertEqual(snapshot(self.skill_dir), before)

    def test_project_root_refused(self):
        proj = os.path.join(self.tmp, "proj")
        os.makedirs(os.path.join(proj, ".git"))
        os.makedirs(os.path.join(proj, "node_modules"))
        write_text(os.path.join(proj, "package.json"), "{}\n")
        write_text(os.path.join(proj, "SKILL.md"),
                   "---\nname: zz-proj\ndescription: \"项目根\"\n---\n")
        rec = self.impl.run_import(self.opts(src=proj, kind="crosscutting"))
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "project_root")

    def test_missing_skill_md_and_missing_pack_refused(self):
        """源里没有 SKILL.md / --pack 指向不存在的文件 → 结构化拒绝（不抛栈）。"""
        empty = os.path.join(self.tmp, "src", "zz-empty")
        os.makedirs(empty)
        rec = self.impl.run_import(self.opts(src=empty, kind="crosscutting"))
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "skill_md_missing")

        src = self._make_skill("zz-nopackfile")
        rec2 = self.impl.run_import(self.opts(src=src, kind="domain",
                                             pack=os.path.join(self.tmp, "nope.json")))
        self.assertEqual(rec2["rc"], 4, rec2)
        self.assertEqual(rec2["refusal"]["code"], "pack_missing")
        self.assertFalse(os.path.exists(os.path.join(self.skill_dir, "zz-nopackfile")))

    def test_bad_name_refused(self):
        src = self._make_skill("zz-name")
        for bad in ("..", "a", "_pending", ".hidden", "名字"):
            rec = self.impl.run_import(self.opts(src=src, name=bad, kind="crosscutting"))
            self.assertEqual(rec["rc"], 4, (bad, rec))
            self.assertEqual(rec["refusal"]["code"], "bad_name", bad)


# ================================================================ 7. dry-run / 并发 / 部署注入
class TestDryRunAndConcurrency(ImportCase):
    def test_dry_run_writes_nothing(self):
        src = self._make_skill("zz-dry", desc="dry (.exe)")
        before_repo = snapshot(self.skill_dir)
        before_roots = [snapshot(r) for r in self.roots]
        rec = self.impl.run_import(self.opts(src=src, kind="crosscutting", dry=True))
        self.assertEqual(rec["rc"], 0, rec)
        self.assertTrue(rec["dry_run"])
        self.assertFalse(rec["written"])
        self.assertEqual(rec["files_imported"], 0)
        self.assertEqual(rec["deployed"], [])
        self.assertEqual(snapshot(self.skill_dir), before_repo)
        self.assertEqual([snapshot(r) for r in self.roots], before_roots)

    def test_dry_run_cli_writes_nothing(self):
        src = self._make_skill("zz-dry2", desc="dry cli (.exe)")
        before = snapshot(self.skill_dir)
        rc, out = self.cli("import", "--kind", "crosscutting", "--from", src, "--dry-run",
                           "--json", "--skill-dir", self.skill_dir,
                           "--deploy-root", self.roots[0])
        self.assertEqual(rc, 0, out)
        rec = json.loads(out)
        self.assertTrue(rec["dry_run"])
        self.assertEqual(snapshot(self.skill_dir), before)

    def test_concurrent_same_name_does_not_mix(self):
        src_a = self._make_skill("zz-race", desc="A 版本 (.exe)", body="## A\n内容 A\n")
        src_b = self._make_skill("zz-race-b", desc="B 版本 (.exe)", body="## B\n内容 B\n")
        before = snapshot(self.skill_dir)
        lock = self.impl._acquire_lock(self.skill_dir, "zz-race")
        self.assertIsNotNone(lock)
        try:
            rec = self.impl.run_import(self.opts(src=src_b, name="zz-race", kind="crosscutting"))
            self.assertEqual(rec["rc"], 4, rec)
            self.assertEqual(rec["refusal"]["code"], "locked")
            # IMPORT-02：别人的**活锁**不许被本次拒绝路径删掉（旧实现会连同 .import-staging 一起 rmtree），
            # 所以要排除他人的锁再比“无半写状态”。
            after = {k: v for k, v in snapshot(self.skill_dir).items()
                     if not (k.startswith(self.impl.STAGING_NAME + "/") and k.endswith(".lock"))}
            self.assertEqual(after, before)
            self.assertTrue(os.path.isfile(lock), "别人的活锁被删了（会破坏并发互斥）")
        finally:
            self.impl._release_lock(lock)
        # 锁释放后可以正常导入，且内容只来自 A
        rec2 = self.impl.run_import(self.opts(src=src_a, name="zz-race", kind="crosscutting"))
        self.assertEqual(rec2["rc"], 0, rec2)
        body = read_text(os.path.join(self.skill_dir, "zz-race", "SKILL.md"))
        self.assertIn("内容 A", body)
        self.assertNotIn("内容 B", body)
        # 正常收尾后不该残留本事务的锁
        self.assertFalse(os.path.isfile(self.impl._lock_path(self.skill_dir, "zz-race")))

    def test_deploy_root_is_injected_not_home(self):
        """部署只写显式 --deploy-root：绝不碰 ~/.pi（本机真实用户根）。"""
        src = self._make_skill("zz-inj", desc="注入 (.exe)")
        rec = self.impl.run_import(self.opts(src=src, kind="crosscutting"))
        self.assertEqual(rec["rc"], 0, rec)
        self.assertEqual([d["path"] for d in rec["deployed"]],
                         [os.path.join(r, "zz-inj") for r in self.roots])
        self.assertEqual(snapshot(self.fake_home), {})  # fake HOME 一个字节都没写

    def test_custom_skill_dir_without_deploy_root_refuses_to_touch_home(self):
        """自定义 --skill-dir 且没给 --deploy-root → 拒（rc=4），绝不悄悄写真实 ~/.pi。"""
        src = self._make_skill("zz-noroot", desc="没给部署根 (.exe)")
        before = snapshot(self.skill_dir)
        rec = self.impl.run_import(self.impl._opts(src=src, kind="crosscutting",
                                                   skill_dir=self.skill_dir))
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "deploy_root_required")
        self.assertEqual(snapshot(self.skill_dir), before)
        self.assertEqual(snapshot(self.fake_home), {})

    def test_no_deploy_keeps_repo_only(self):
        src = self._make_skill("zz-nodeploy", desc="只落仓库 (.exe)")
        before_roots = [snapshot(r) for r in self.roots]
        rec = self.impl.run_import(self.opts(src=src, kind="crosscutting", deploy=False,
                                             deploy_roots=[]))
        self.assertEqual(rec["rc"], 0, rec)
        self.assertTrue(os.path.isdir(os.path.join(self.skill_dir, "zz-nodeploy")))
        self.assertEqual(rec["deployed"], [])
        self.assertFalse(rec["available_next_session"])
        self.assertEqual([snapshot(r) for r in self.roots], before_roots)


# ================================================================ 8. tool 模式
class TestToolMode(ImportCase):
    def _manifest(self, tool_id="zz-mcp-tool"):
        p = os.path.join(self.tmp, "tool-manifest.json")
        with io.open(p, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"id": tool_id, "why": "测试用工具声明",
                       "probe": {"exe_candidates": ["zz.exe"]}}, f, ensure_ascii=False, indent=2)
        return p

    def test_tool_mode_declares_without_writing_catalogs(self):
        man = self._manifest()
        catalogs = [os.path.join(TOOL, "config", n) for n in
                    ("tool-capabilities.json", "tool-runtimes.json", "tool-effects.json")]
        before = [snapshot(os.path.dirname(p)) for p in catalogs]
        rec = self.impl.run_import(self.opts(src=man, kind="tool", tool_id="zz-mcp-tool"))
        self.assertEqual(rec["rc"], 3, rec)                 # 能力缺口 = rc 3，不是成功
        self.assertTrue(rec["capability_gap"])
        self.assertTrue(rec["declared"])
        self.assertTrue(rec["not_available"])
        self.assertFalse(rec["catalogs_written"])
        self.assertFalse(rec["effective"])
        self.assertFalse(rec["formal_domain_active"])
        self.assertFalse(rec["available_next_session"])
        self.assertIn("capability_gap", "；".join(rec["to_take_effect"]))
        self.assertEqual([snapshot(os.path.dirname(p)) for p in catalogs], before)

    def test_tool_mode_bad_manifest_refused(self):
        p = os.path.join(self.tmp, "bad.json")
        write_text(p, "{not json")
        rec = self.impl.run_import(self.opts(src=p, kind="tool"))
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "tool_manifest_bad")


# ================================================================ 9. verify 子命令
class TestVerifyCommand(ImportCase):
    def test_verify_reports_manifest_and_routes_readonly(self):
        src, _pack = self.scratch_pack("zz-verify", "verifydom 域", 9080)
        rec = self.impl.run_import(self.opts(src=src, name="zz-verify"))
        self.assertEqual(rec["rc"], 0, rec)
        before = snapshot(self.skill_dir)
        buf = io.StringIO()
        import contextlib
        with contextlib.redirect_stdout(buf):
            out = self.impl.cmd_verify(self.opts(name="zz-verify"))
        self.assertEqual(out, 0, buf.getvalue())
        self.assertIn("全局硬编码契约未登记", buf.getvalue())
        self.assertIn("[未生效]", buf.getvalue())
        self.assertEqual(snapshot(self.skill_dir), before)   # verify 只读

    def test_verify_catches_deploy_drift(self):
        src, _pack = self.scratch_pack("zz-drift", "driftdom 域", 9085)
        rec = self.impl.run_import(self.opts(src=src, name="zz-drift"))
        self.assertEqual(rec["rc"], 0, rec)
        victim = os.path.join(self.roots[1], "zz-drift", "SKILL.md")
        with open(victim, "ab") as f:
            f.write(b"\nextra\n")
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self.impl.cmd_verify(self.opts(name="zz-drift"))
        self.assertEqual(rc, 5, buf.getvalue())
        self.assertIn("部署 hash 漂移", buf.getvalue())
        self.assertIn("漂移 SKILL.md", buf.getvalue())


class TestCanonicalLifecycle(ImportCase):
    """Actual CLI coverage of canonical identity, reinstall and negative paths."""

    def invoke(self, command, name, parent="", *extra):
        args = [command, "--name", name, "--skill-dir", self.skill_dir,
                "--deploy-root", self.roots[0], "--json"]
        if parent:
            args.extend(["--parent", parent])
        rc, out = self.cli(*(args + list(extra)))
        self.assertNotIn("Traceback", out)
        return rc, json.loads(out)

    def seed_child(self, name="zz-life", parent=None):
        parent = parent or self.parent
        if not os.path.exists(os.path.join(self.roots[0], parent)):
            shutil.copytree(os.path.join(self.skill_dir, parent), os.path.join(self.roots[0], parent))
        src = self._make_skill(name)
        rc, out = self.cli("import", "--kind", "subskill", "--parent", parent,
                           "--from", src, "--skill-dir", self.skill_dir,
                           "--deploy-root", self.roots[0], "--json")
        self.assertEqual(rc, 0, out)
        return src, os.path.join(self.skill_dir, parent, "subskills", name)

    def test_import_replace_verify_and_recursive_reinstall_are_equivalent(self):
        src, child = self.seed_child()
        for suffix in ("v1", "v2"):
            write_text(os.path.join(src, "SKILL.md"),
                       "---\nname: zz-life\ndescription: fixture\n---\n" + suffix + "\n")
            rc, out = self.cli("import", "--kind", "subskill", "--parent", self.parent,
                               "--from", src, "--skill-dir", self.skill_dir,
                               "--deploy-root", self.roots[0], "--replace", "--json")
            self.assertEqual(rc, 0, out)
            self.assertEqual(self.invoke("verify", "zz-life")[0], 0)
        deployed = os.path.join(self.roots[0], self.parent)
        self.assertEqual(snapshot(deployed), snapshot(os.path.join(self.skill_dir, self.parent)))
        shutil.rmtree(deployed)
        shutil.copytree(os.path.join(self.skill_dir, self.parent), deployed)
        self.assertEqual(self.invoke("verify", "zz-life")[0], 0)
        fresh = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c",
                                "from pathlib import Path; print(Path(__import__('sys').argv[1]).read_text(encoding='utf-8'))",
                                os.path.join(deployed, "subskills", "zz-life", "SKILL.md")],
                               capture_output=True, text=True, encoding="utf-8", timeout=20)
        self.assertEqual(fresh.returncode, 0, fresh.stderr)
        self.assertIn("v2", fresh.stdout)
        self.assertTrue(os.path.isfile(os.path.join(child, "SKILL.md")))

    def test_deploy_subcommand_uses_parent_scope_and_requires_replace(self):
        _, child = self.seed_child()
        target = os.path.join(self.roots[0], self.parent, "subskills", "zz-life")
        before = snapshot(target)
        rc, rec = self.invoke("deploy", "zz-life", self.parent)
        self.assertEqual(rc, 4, rec)
        self.assertEqual(rec["refusal"]["code"], "target_exists")
        self.assertEqual(snapshot(target), before)
        shutil.rmtree(target)
        rc, rec = self.invoke("deploy", "zz-life", self.parent)
        self.assertEqual(rc, 0, rec)
        self.assertFalse(rec["available_next_session"])
        self.assertEqual(snapshot(child), snapshot(target))
        self.assertEqual(self.invoke("verify", "zz-life", self.parent)[0], 0)

    def test_same_name_in_two_parents_requires_explicit_identity(self):
        self.seed_child()
        other = "zz-other"
        self._make_domain(other, "other domain", 9061)
        self.seed_child(parent=other)
        before = snapshot(self.tmp)
        for command in ("verify", "deploy", "status"):
            rc, rec = self.invoke(command, "zz-life")
            self.assertEqual(rc, 4, rec)
            self.assertEqual(rec["refusal"]["code"], "skill_ambiguous")
        self.assertEqual(snapshot(self.tmp), before)
        for parent in (self.parent, other):
            self.assertEqual(self.invoke("verify", "zz-life", parent)[0], 0)
            rc, rec = self.invoke("status", "zz-life", parent)
            self.assertEqual(rc, 0, rec)
            self.assertEqual(rec["dest"], os.path.join(self.skill_dir, parent, "subskills", "zz-life"))

    def test_wrong_parent_and_missing_source_are_rejected(self):
        _, child = self.seed_child()
        other = "zz-other"
        self._make_domain(other, "other domain", 9061)
        for command in ("verify", "deploy", "status"):
            rc, rec = self.invoke(command, "zz-life", other)
            self.assertEqual(rc, 4, rec)
            self.assertEqual(rec["refusal"]["code"], "skill_missing")
        shutil.rmtree(child)
        rc, rec = self.invoke("verify", "zz-life", self.parent)
        self.assertEqual(rc, 4, rec)
        self.assertFalse(rec["effective"])

    def test_pending_copy_and_stale_navigation_never_override_canonical_child(self):
        src, child = self.seed_child()
        old = os.path.join(self.skill_dir, "_pending", "zz-life")
        os.makedirs(old)
        write_text(os.path.join(old, "SKILL.md"), "OLD PENDING\n")
        pp = os.path.join(self.skill_dir, self.parent, "SKILL.md")
        write_text(pp, read_text(pp).replace("subskills/zz-life/SKILL.md", "../_pending/zz-life/SKILL.md"))
        rc, rec = self.invoke("verify", "zz-life")
        self.assertEqual(rc, 5, rec)
        self.assertEqual(rec["dest"], child)
        rc, out = self.cli("import", "--kind", "subskill", "--parent", self.parent,
                           "--from", src, "--skill-dir", self.skill_dir,
                           "--deploy-root", self.roots[0], "--replace", "--json")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("../_pending/zz-life", read_text(pp))
        self.assertEqual(read_text(os.path.join(old, "SKILL.md")), "OLD PENDING\n")
        self.assertEqual(self.invoke("verify", "zz-life")[0], 0)

    def test_manifest_parent_tamper_and_missing_deployed_parent_ref_fail(self):
        _, child = self.seed_child()
        manifest = os.path.join(child, "import-manifest.json")
        original = read_text(manifest, newline="")
        obj = json.loads(original)
        obj["parent"] = "zz-forged"
        write_text(manifest, json.dumps(obj), newline="")
        for command in ("verify", "deploy"):
            rc, rec = self.invoke(command, "zz-life", self.parent, "--replace")
            self.assertEqual(rc, 5, rec)
        write_text(manifest, original, newline="")
        parent_file = os.path.join(self.roots[0], self.parent, "SKILL.md")
        original = read_text(parent_file, newline="")
        write_text(parent_file, original.replace("subskills/zz-life/SKILL.md", "subskills/missing/SKILL.md"), newline="")
        rc, rec = self.invoke("verify", "zz-life")
        self.assertEqual(rc, 5, rec)
        write_text(parent_file, original, newline="")
        self.assertEqual(self.invoke("verify", "zz-life")[0], 0)

    def test_missing_deployed_parent_stays_pending_in_deploy_and_verify(self):
        self.seed_child()
        shutil.rmtree(os.path.join(self.roots[0], self.parent))
        before = snapshot(self.roots[0])
        for command in ("deploy", "verify"):
            rc, rec = self.invoke(command, "zz-life", self.parent)
            self.assertEqual(rc, 0, rec)
            self.assertTrue(rec["deployed"][0]["pending"])
            self.assertFalse(rec["available_next_session"])
            self.assertFalse(rec["effective"])
        self.assertEqual(snapshot(self.roots[0]), before)


class TestTableNavigation(ImportCase):
    def setUp(self):
        super().setUp()
        parent_file = os.path.join(self.skill_dir, self.parent, "SKILL.md")
        prefix = read_text(parent_file).split("## 子技能", 1)[0]
        self.original = prefix + softseep_navigation_fixture()
        write_text(parent_file, self.original, newline="")
        # Existing paths are inert fixture files, never copied customer material.
        for child in set(re.findall(r"subskills/([\w.-]+)/SKILL\.md", self.original)):
            directory = os.path.join(self.skill_dir, self.parent, "subskills", child)
            os.makedirs(directory, exist_ok=True)
            write_text(os.path.join(directory, "SKILL.md"),
                       "---\nname: %s\ndescription: fixture\n---\nINERT\n" % child, newline="")
        for root in self.roots:
            shutil.copytree(os.path.join(self.skill_dir, self.parent), os.path.join(root, self.parent))

    def import_table_child(self, name, desc, entry, replace=False, display=None):
        source = self._make_skill(name, desc=desc)
        if display:
            path = os.path.join(source, "SKILL.md")
            write_text(path, read_text(path).replace("name: " + name, "name: " + display), newline="")
        args = ["import", "--from", source, "--name", name, "--kind", "subskill",
                "--parent", self.parent, "--entry", entry, "--skill-dir", self.skill_dir,
                "--deploy-root", self.roots[0], "--deploy-root", self.roots[1], "--json"]
        if replace:
            args.append("--replace")
        rc, out = self.cli(*args)
        return rc, json.loads(out)

    def test_real_softseep_table_adds_and_updates_one_escaped_row(self):
        name = "zz-table-child"
        for replace, description in ((False, "功能 | `代码`"), (True, "更新 | 功能")):
            rc, rec = self.import_table_child(name, description, "遇到 A | B\r\n下一行", replace,
                                               display="名称 | 显示")
            self.assertEqual(rc, 0, rec)
            parent_file = os.path.join(self.skill_dir, self.parent, "SKILL.md")
            text = read_text(parent_file, newline="")
            rows = [line for line in text.splitlines() if "subskills/%s/SKILL.md" % name in line]
            self.assertEqual(len(rows), 1, text)
            self.assertTrue(rows[0].startswith("| "), rows)
            self.assertEqual(rows[0].count("|"), 5, rows)
            self.assertIn("名称 &#124; 显示", rows[0])
            self.assertIn("遇到 A &#124; B 下一行", rows[0])
            self.assertNotIn("\r", rows[0])
            self.assertEqual(text.replace(rows[0] + "\n", ""), self.original)
            for root in self.roots:
                self.assertEqual(snapshot(os.path.join(self.skill_dir, self.parent)),
                                 snapshot(os.path.join(root, self.parent)))
            rc, rec = self.import_table_child(name, description, "遇到 A | B\r\n下一行", True,
                                               display="名称 | 显示")
            self.assertEqual(rc, 0, rec)
            self.assertTrue(rec["parent_patch"]["idempotent"])
            self.assertEqual(read_text(parent_file, newline=""), text)

    def test_existing_raw_path_row_is_updated_in_place(self):
        name = "unpack-pe"  # Current softseep's row intentionally has no backticks.
        rc, out = self.cli("verify", "--name", name, "--parent", self.parent,
                           "--skill-dir", self.skill_dir, "--deploy-root", self.roots[0], "--json")
        self.assertEqual(rc, 0, out)
        original_row = next(line for line in self.original.splitlines() if "subskills/unpack-pe/SKILL.md" in line)
        rc, rec = self.import_table_child(name, "新功能 | 说明", "触发\n多行", True)
        self.assertEqual(rc, 0, rec)
        result = read_text(os.path.join(self.skill_dir, self.parent, "SKILL.md"), newline="")
        row = next(line for line in result.splitlines() if "subskills/unpack-pe/SKILL.md" in line)
        self.assertIn("新功能 &#124; 说明", row)
        self.assertIn("触发 多行", row)
        self.assertEqual(result, self.original.replace(original_row, row))
        for root in self.roots:
            self.assertEqual(snapshot(os.path.join(self.skill_dir, self.parent)), snapshot(os.path.join(root, self.parent)))

    def test_old_misplaced_bullet_moves_into_the_existing_table(self):
        name = "zz-misplaced"
        broken = self.original.replace("\n\n| 技能名称", "\n- `subskills/%s/SKILL.md` —— old\n\n| 技能名称" % name, 1)
        for directory in [self.skill_dir] + self.roots:
            write_text(os.path.join(directory, self.parent, "SKILL.md"), broken, newline="")
        rc, rec = self.import_table_child(name, "功能", "触发")
        self.assertEqual(rc, 0, rec)
        text = read_text(os.path.join(self.skill_dir, self.parent, "SKILL.md"), newline="")
        rows = [line for line in text.splitlines() if "subskills/%s/SKILL.md" % name in line]
        self.assertEqual(len(rows), 1, text)
        self.assertTrue(rows[0].startswith("| "))
        self.assertEqual(text.replace(rows[0] + "\n", ""), self.original)

    def test_table_preserves_crlf_and_damaged_table_is_not_bypassed(self):
        for directory in [self.skill_dir] + self.roots:
            write_text(os.path.join(directory, self.parent, "SKILL.md"),
                       self.original.replace("\n", "\r\n"), newline="")
        rc, rec = self.import_table_child("zz-crlf-table", "功能", "触发")
        self.assertEqual(rc, 0, rec)
        for directory in [self.skill_dir] + self.roots:
            with open(os.path.join(directory, self.parent, "SKILL.md"), "rb") as stream:
                raw = stream.read()
            self.assertNotIn(b"\n", raw.replace(b"\r\n", b""))
        parent_file = os.path.join(self.skill_dir, self.parent, "SKILL.md")
        text = read_text(parent_file, newline="").replace("| :--- | :--- | :--- | :--- |", "| --- | --- |")
        write_text(parent_file, text, newline="")
        before = snapshot(os.path.join(self.skill_dir, self.parent))
        rc, rec = self.import_table_child("zz-bad-table", "功能", "触发")
        self.assertEqual(rc, 4, rec)
        self.assertEqual(rec["refusal"]["code"], "parent_navigation_table")
        self.assertEqual(snapshot(os.path.join(self.skill_dir, self.parent)), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
