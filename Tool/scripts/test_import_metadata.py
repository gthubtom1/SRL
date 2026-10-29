#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_import_metadata.py —— 子技能清单、旧映射迁移与只读拒执回归。

新导入与完整安装同形：父域 subskills/<child>/SKILL.md，不产生 import-map.json。
旧映射夹具只用于验证身份核验和迁移：schema/child/parent/entry/mapping/files、
路径逃逸、多对一、缺件、内容/hash/字节数、未知用户文件的负例全部保留。
有身份的旧副本经同卷备份后退出活跃目录；坏映射拒绝并保留原件。
每个篡改负例均还原原字节，再验证迁移和 canonical verify 成功，防止恒红。
所有写入仅限临时 repo/部署根；不联网、不执行技能代码、不部署真实 AgentRoot。

跑法：python -B -X utf8 Tool/scripts/test_import_metadata.py
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
ROOT = os.path.dirname(TOOL)
SCRIPT = os.path.join(HERE, "skill-import.py")
MAP = "import-map.json"
GUIDE_REF = "references/imported-subskills/%s/GUIDE.md"

PACK = {
    "schema": "seep.pack/1", "id": "", "l1": "",
    "routes": [{"label": "lab", "must": [], "priority": 0}],
    "stages": ["0-analysis"], "tools": ["seep_apk_info"], "cases": ["leaf-apk"],
    "case_roles": {"witness": ["leaf-apk"], "depth_gate": ["leaf-apk"]},
    "witness": {"cmd": "echo witness", "expect": "exit0", "budget_s": 30},
    "witness_tool": {"cmd": "echo witness-tool", "why": "元数据回归用"},
    "evidence_contract": {"required_fields": ["claim", "confidence", "authority", "evidence"],
                          "authority_allow": ["shipped-artifact", "controlled-replay",
                                              "external-service"],
                          "pass_forbids_confidence": ["inferred", "unknown"]},
    "limitations": ["测试用 pack"], "invalidation": ["测试结束即失效"],
}


def snapshot(path):
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


def cli(*args, timeout=300):
    cmd = [sys.executable, "-B", "-X", "utf8", SCRIPT] + [str(a) for a in args]
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", cwd=ROOT, env=env, timeout=timeout)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def receipt(out):
    s = out.find("{")
    if s >= 0:
        try:
            return json.loads(out[s:])
        except ValueError:
            pass
    if "[报告] " in out:
        try:
            return json.loads(out.rsplit("[报告] ", 1)[1].splitlines()[0])
        except ValueError:
            return None
    return None


class _Lab(unittest.TestCase):
    """夹具基类：**不含 test_**，避免被继承后重复跑一遍。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="seep-import-meta-")
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
        self.root = os.path.join(self.tmp, "agent-a", "skills")
        os.makedirs(self.root)
        self.parent = "zz-mp"
        self.child = "zz-mpc"
        self._domain(self.parent, "元数据父域", 9010)
        shutil.copytree(os.path.join(self.skill_dir, self.parent),
                        os.path.join(self.root, self.parent))
        self.src = self._skill(self.child)
        rc, out = cli("import", "--kind", "subskill", "--parent", self.parent,
                      "--from", self.src, "--skill-dir", self.skill_dir,
                      "--deploy-root", self.root, "--json")
        self.assertEqual(rc, 0, out[-800:])
        self.base = os.path.join(self.root, self.parent, "subskills", self.child)
        self.legacy = os.path.join(self.root, self.parent, "references", "imported-subskills",
                                   self.child)
        self.mp = os.path.join(self.legacy, MAP)
        self._make_legacy()
        with open(self.mp, "rb") as fh:
            self.map_raw = fh.read()
        self.map_obj = json.loads(self.map_raw.decode("utf-8"))
        shutil.rmtree(self.legacy)

    def tearDown(self):
        self.env_guard.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------ 夹具
    def _domain(self, name, l1, priority):
        d = os.path.join(self.skill_dir, name)
        os.makedirs(d, exist_ok=True)
        text = ("---\nname: %s\ndescription: \"%s：怎么用/帮我看看\"\n---\n\n父域正文\n\n"
                "## 子技能（按需读，不常驻）\n\n"
                "本域相关子技能放在 `Tool/skill/_pending/`（不占常驻上下文，需要时再读）：\n\n"
                % (name, l1))
        with io.open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        pack = json.loads(json.dumps(PACK))
        pack["id"] = name
        pack["l1"] = ("%s 这个问题怎么处理" % l1)[:120]
        pack["routes"][0]["must"] = ["(?i)%s" % l1]
        pack["routes"][0]["priority"] = priority
        with io.open(os.path.join(d, "pack.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(pack, f, ensure_ascii=False, indent=2)
            f.write("\n")
        return d

    def _skill(self, name):
        d = os.path.join(self.tmp, "ext-src", name)
        os.makedirs(d, exist_ok=True)
        with io.open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8", newline="\n") as f:
            f.write("---\nname: %s\ndescription: \"元数据子技能 (.yar)\"\n---\n\n## 1\n小技巧\n" % name)
        os.makedirs(os.path.join(d, "references"), exist_ok=True)
        with io.open(os.path.join(d, "references", "a.md"), "w", encoding="utf-8",
                     newline="\n") as f:
            f.write("A\n")
        return d

    def _make_legacy(self):
        """Construct historical data only: production no longer writes a map."""
        if os.path.exists(self.legacy):
            shutil.rmtree(self.legacy)
        shutil.copytree(self.base, self.legacy)
        os.replace(os.path.join(self.legacy, "SKILL.md"), os.path.join(self.legacy, "GUIDE.md"))
        hashes = snapshot(self.legacy)
        obj = {"schema": "seep.skill-import.subskill-map/1", "child": self.child,
               "parent": self.parent, "entry": GUIDE_REF % self.child,
               "mapping": {"SKILL.md": "GUIDE.md"}, "files": hashes}
        with io.open(self.mp, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(obj, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")

    def verify(self):
        # Map negatives now exercise identity-checked legacy migration through the
        # real CLI. Canonical verify itself stays read-only and never trusts a map.
        if os.path.exists(self.legacy):
            rc, out = cli("deploy", "--name", self.child, "--parent", self.parent,
                          "--skill-dir", self.skill_dir, "--deploy-root", self.root,
                          "--replace", "--json")
            if rc:
                return rc, receipt(out) or {}, out
        rc, out = cli("verify", "--name", self.child, "--skill-dir", self.skill_dir,
                      "--deploy-root", self.root, "--json")
        return rc, (receipt(out) or {}), out

    def write_map(self, obj):
        if not os.path.isdir(self.legacy):
            self._make_legacy()
        with io.open(self.mp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")

    def restore_map(self):
        self._make_legacy()
        with open(self.mp, "wb") as f:
            f.write(self.map_raw)

    def _mutate_and_verify(self, label, mutate):
        """篡改 → verify 必须 rc=5 且报 map 契约问题；还原后同一 fixture verify 回 0。"""
        obj = json.loads(json.dumps(self.map_obj))
        mutate(obj)
        self.write_map(obj)
        rc, rec, out = self.verify()
        self.assertEqual(rc, 5, "%s：篡改后 verify 仍 rc=%s（%s）" % (label, rc, rec.get("why")))
        self.assertEqual(rec.get("effective_status"), "failed", label)
        self.assertNotIn("Traceback", out, label)
        problems = (rec.get("refusal") or {}).get("problems") or []
        self.assertTrue(problems, "%s：必须给出旧映射身份/清单冲突：%s" % (label, rec))
        self.restore_map()
        rc2, rec2, _ = self.verify()
        self.assertEqual(rc2, 0, "%s：还原后仍 rc=%s（恒红）：%s" % (label, rc2, rec2.get("why")))
        self.assertEqual(rec2.get("effective_status"), "pending_subskill", label)


class MetaCase(_Lab):
    """R-NEW-1：部署侧 import-map.json 身份/入口/映射声明是权威契约。"""

    # ============================================================ R-NEW-1 写死/漂移
    def test_baseline_verify_is_green_and_read_only(self):
        """正对照：未篡改 → rc=0；verify 是只读入口（临时树逐字节不变）。"""
        before = snapshot(self.tmp)
        rc, rec, _ = self.verify()
        self.assertEqual(rc, 0, rec.get("why"))
        self.assertEqual(rec.get("effective_status"), "pending_subskill")
        self.assertFalse(rec.get("written"))
        self.assertEqual(snapshot(self.tmp), before, "verify 不得写盘")

    def test_mapping_points_to_other_document(self):
        """R-NEW-1 原始反例：mapping 换 OTHER.md（files/内容都不动）→ 必须 rc=5。"""
        self._mutate_and_verify("mapping→OTHER.md",
                                lambda o: o.__setitem__("mapping", {"SKILL.md": "OTHER.md"}))

    def test_mapping_target_exists_but_is_not_contract_entry(self):
        """更强的形状：把 OTHER.md **真的造出来**并登记 hash，仍不得算可达。"""
        other = os.path.join(self.base, "OTHER.md")
        with io.open(other, "w", encoding="utf-8", newline="\n") as f:
            f.write("OTHER\n")
        try:
            obj = json.loads(json.dumps(self.map_obj))
            obj["mapping"] = {"SKILL.md": "OTHER.md"}
            obj["files"]["OTHER.md"] = hashlib.sha256(b"OTHER\n").hexdigest()
            self.write_map(obj)
            rc, rec, out = self.verify()
            self.assertEqual(rc, 5, "OTHER.md 真实存在仍不得当成入口：%s" % rec.get("why"))
            self.assertNotIn("Traceback", out)
            problems = (rec.get("refusal") or {}).get("problems") or []
            self.assertTrue(any("mapping" in p or "映射" in p or "entry" in p
                                for p in problems), problems)
        finally:
            os.remove(other)
        self.restore_map()
        rc2, rec2, _ = self.verify()
        self.assertEqual(rc2, 0, "还原后仍 rc=%s：%s" % (rc2, rec2.get("why")))

    def test_mapping_traversal_and_many_to_one(self):
        """路径规范化：`../` 穿越、绝对路径、多对一 全部拒。"""
        self._mutate_and_verify("mapping 穿越 ../evil.md",
                                lambda o: o.__setitem__("mapping", {"SKILL.md": "../evil.md"}))
        self._mutate_and_verify("mapping 绝对路径",
                                lambda o: o.__setitem__("mapping",
                                                        {"SKILL.md": "/tmp/evil.md"}))
        self._mutate_and_verify(
            "mapping 多对一",
            lambda o: o.__setitem__("mapping",
                                    {"SKILL.md": "GUIDE.md", "X.md": "GUIDE.md"}))
        self._mutate_and_verify("mapping 三对一",
                                lambda o: o.__setitem__("mapping",
                                                        {"SKILL.md": "GUIDE.md",
                                                         "A.md": "GUIDE.md",
                                                         "B.md": "GUIDE.md"}))
        self._mutate_and_verify("files 里登记穿越路径",
                                lambda o: o["files"].__setitem__("../../evil.txt", "0" * 64))

    def test_mapping_entry_missing_or_empty(self):
        """缺映射条目 / 空映射 都不得当成"GUIDE 在就行"。"""
        self._mutate_and_verify("mapping 缺 SKILL.md 条目",
                                lambda o: o.__setitem__("mapping", {}))
        self._mutate_and_verify("mapping 键写成别的源",
                                lambda o: o.__setitem__("mapping", {"README.md": "GUIDE.md"}))
        self._mutate_and_verify("mapping 整段删除", lambda o: o.pop("mapping"))
        self._mutate_and_verify("mapping 不是对象（列表）",
                                lambda o: o.__setitem__("mapping", ["SKILL.md", "GUIDE.md"]))
        self._mutate_and_verify("files 不是对象（字符串）",
                                lambda o: o.__setitem__("files", "GUIDE.md"))

    def test_entry_child_parent_schema_forged(self):
        """header 字段（entry/child/parent/schema）被改后不得仍 rc=0。"""
        self._mutate_and_verify(
            "entry 换掉",
            lambda o: o.__setitem__("entry", GUIDE_REF % "zz-other"))
        self._mutate_and_verify("child 伪造",
                                lambda o: o.__setitem__("child", "zz-other"))
        self._mutate_and_verify("parent 伪造",
                                lambda o: o.__setitem__("parent", "zz-other-domain"))
        self._mutate_and_verify("schema 伪造",
                                lambda o: o.__setitem__("schema", "seep.whatever/0"))
        self._mutate_and_verify("schema 删除", lambda o: o.pop("schema"))
        self._mutate_and_verify("entry 删除", lambda o: o.pop("entry"))
        self._mutate_and_verify("entry 穿越路径",
                                lambda o: o.__setitem__(
                                    "entry", "references/imported-subskills/../%s/GUIDE.md"
                                    % self.child))

    def test_files_hash_real_drift_and_missing_entry(self):
        """`files` 声明漂移（真实内容没变、只有声明被改）必须 rc=5；入口未登记也拒。"""
        def flip_hash(o):
            o["files"]["GUIDE.md"] = "0" * 64
        self._mutate_and_verify("files.GUIDE.md hash 被改", flip_hash)
        self._mutate_and_verify("files 删掉入口登记", lambda o: o["files"].pop("GUIDE.md"))
        self._mutate_and_verify("files 整段删除", lambda o: o.pop("files"))

    def test_repo_manifest_identity_fields_are_contract(self):
        """仓库侧 import-manifest.json 的 schema/name/kind 也是契约：篡改不得 rc=0。"""
        mf = os.path.join(self.skill_dir, self.parent, "subskills", self.child, "import-manifest.json")
        with open(mf, "rb") as fh:
            raw = fh.read()
        obj = json.loads(raw.decode("utf-8"))
        for label, mutate in (
                ("schema 伪造", lambda o: o.__setitem__("schema", "seep.x/0")),
                ("name 伪造", lambda o: o.__setitem__("name", "zz-other")),
                ("kind 伪造", lambda o: o.__setitem__("kind", "domain")),
                ("files 整段删除", lambda o: o.pop("files"))):
            o = json.loads(json.dumps(obj))
            mutate(o)
            with io.open(mf, "w", encoding="utf-8", newline="\n") as f:
                json.dump(o, f, ensure_ascii=False, indent=2, sort_keys=True)
                f.write("\n")
            rc, rec, out = self.verify()
            self.assertEqual(rc, 5, "%s：rc=%s（%s）" % (label, rc, rec.get("why")))
            self.assertNotIn("Traceback", out)
            with open(mf, "wb") as f:
                f.write(raw)
            rc2, rec2, _ = self.verify()
            self.assertEqual(rc2, 0, "%s：还原后仍 rc=%s（%s）" % (label, rc2, rec2.get("why")))

    def test_deployed_entry_content_drift_still_caught(self):
        """内容漂移仍在判：改部署 SKILL.md 一个字节 → rc=5，还原 → 0。"""
        guide = os.path.join(self.base, "SKILL.md")
        with open(guide, "rb") as fh:
            raw = fh.read()
        try:
            with open(guide, "ab") as fh:
                fh.write(b"\nTAMPER\n")
            rc, rec, out = self.verify()
            self.assertEqual(rc, 5, rec.get("why"))
            self.assertNotIn("Traceback", out)
        finally:
            with open(guide, "wb") as fh:
                fh.write(raw)
        rc2, rec2, _ = self.verify()
        self.assertEqual(rc2, 0, rec2.get("why"))

    def test_deployed_entry_size_drift_with_same_norm_hash(self):
        """hash 口径按 LF 归一：CRLF 冒充会让 size 变而 hash 不变 → 必须靠 size 抓住。"""
        guide = os.path.join(self.base, "SKILL.md")
        with open(guide, "rb") as fh:
            raw = fh.read()
        try:
            with open(guide, "wb") as fh:
                fh.write(raw.replace(b"\n", b"\r\n"))
            rc, rec, out = self.verify()
            self.assertEqual(rc, 5, "CRLF 冒充（norm hash 相同、size 不同）应当 rc=5：%s"
                             % rec.get("why"))
            self.assertNotIn("Traceback", out)
            dep = (rec.get("deployed") or [{}])[0]
            self.assertTrue(any("字节数" in p for p in (dep.get("map_problems") or [])),
                            dep.get("map_problems"))
        finally:
            with open(guide, "wb") as fh:
                fh.write(raw)
        rc2, rec2, _ = self.verify()
        self.assertEqual(rc2, 0, rec2.get("why"))

    def test_production_and_verify_share_one_map_validator(self):
        """旧映射仅由迁移读取；新生产路径不再写第二份入口。"""
        with io.open(SCRIPT, encoding="utf-8") as f:
            src = f.read()
        self.assertEqual(src.count("def _validate_sub_map("), 1,
                         "map 契约校验必须只有一份实现（生产/verify 共用）")
        calls = [ln for ln in src.splitlines()
                 if "_validate_sub_map(" in ln and "def " not in ln]
        self.assertEqual(len(calls), 1,
                         "旧映射只允许在受管副本迁移时读取，不在新部署中产生")
        self._make_legacy()
        # 导入成功后，磁盘上的 map 自己也要能过这一份校验（自洽，不是两套口径）
        sys.path.insert(0, HERE)
        import importlib.util
        spec = importlib.util.spec_from_file_location("seep_import_meta_under_test", SCRIPT)
        impl = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(impl)
        self.assertEqual(
            impl._validate_sub_map(self.map_obj, self.child, self.parent,
                                   os.path.join(self.skill_dir, self.parent, "subskills", self.child),
                                   self.legacy)[0], [])
        # schema/字段常量就是契约本身（不是随手字符串）
        self.assertEqual(sorted(impl.SUB_MAP_FIELDS),
                         sorted(["schema", "child", "parent", "entry", "mapping", "files"]))
        self.assertEqual(impl.SUBSCHEMA_MAP, "seep.skill-import.subskill-map/1")


# ================================================================ R-NEW-2 统一拒执
class RefusalCase(_Lab):
    """status / recovery-report 收到非法根：与 import/plan/deploy/verify 同一规则。"""

    def _assert_refusal(self, cmd, root, want_code, note):
        before_tmp, before_spy = snapshot(self.tmp), snapshot(self.root)
        rc, out = cli(cmd, "--skill-dir", self.skill_dir, "--deploy-root", root, "--json")
        rec = receipt(out) or {}
        code = (rec.get("refusal") or {}).get("code") or ""
        self.assertNotIn("Traceback", out, "%s/%s 不得 traceback：%s" % (cmd, note, out[-300:]))
        self.assertEqual(rc, 4, "%s/%s：rc=%s（%s）" % (cmd, note, rc, rec.get("why")))
        self.assertEqual(code, want_code, "%s/%s：code=%r" % (cmd, note, code))
        self.assertEqual(rec.get("rc"), 4)
        self.assertFalse(rec.get("written"), "%s/%s 拒绝时 written 必须 false" % (cmd, note))
        self.assertEqual(snapshot(self.tmp), before_tmp, "%s/%s 拒绝时不得写盘" % (cmd, note))
        self.assertEqual(snapshot(self.root), before_spy, "%s/%s 拒绝时不得写部署根" % (cmd, note))

    def test_status_and_recovery_report_refuse_invalid_roots(self):
        for cmd in ("status", "recovery-report"):
            self._assert_refusal(cmd, self.skill_dir, "deploy_root_overlap", "root==skill-dir")
            self._assert_refusal(cmd, self.repo, "deploy_root_overlap", "root⊂repo")
            self._assert_refusal(cmd, os.path.abspath(os.sep), "deploy_root_not_dir",
                                 "root=文件系统根")

    def test_status_and_recovery_report_refuse_symlink_root(self):
        link = os.path.join(self.tmp, "link-to-root")
        made = None
        try:
            os.symlink(self.root, link, target_is_directory=True)
            made = "symlink"
        except OSError:
            r = subprocess.run(["cmd", "/c", "mklink", "/J", link, self.root],
                               capture_output=True, text=True)
            made = "junction" if os.path.isdir(link) else None
        self.assertTrue(made, "本机建不出 symlink/junction，无法验证该反例")
        target_before = snapshot(self.root)
        for cmd in ("status", "recovery-report"):
            self._assert_refusal(cmd, link, "deploy_root_symlink", made)
        self.assertEqual(snapshot(self.root), target_before, "拒绝时链接目标不得被写")

    def test_refusal_never_echoes_raw_path(self):
        """拒执消息不回显敏感/绝对原值：只有末级名字与长度标记。"""
        root = os.path.join(self.skill_dir, "sentinel-secret-dir")
        os.makedirs(root, exist_ok=True)
        rc, out = cli("status", "--skill-dir", self.skill_dir, "--deploy-root", root, "--json")
        rec = receipt(out) or {}
        msg = json.dumps(rec.get("refusal") or {}, ensure_ascii=False)
        self.assertEqual(rc, 4, msg)
        self.assertNotIn(self.tmp.replace("\\", "\\\\"), msg, "拒执不得回显绝对路径原值")
        self.assertIn("<path:", msg, "拒执应给出脱敏后的路径标记")
        self.assertIn("sentinel-secret-dir", msg, "末级名字保留（可用于定位）")

    def test_missing_deploy_root_is_documented_not_silent(self):
        """status 缺显式根：按设计 rc=0 且只扫 skill-dir（不兜底真实用户根、也不写盘）。

        与 import/plan 的 `deploy_root_required` rc=4 对照，说明"缺根"对 status 不是非法根，
        但它也**绝不能**悄悄把真实 ~/.pi 当默认根扫。
        """
        before = snapshot(self.tmp)
        rc, out = cli("status", "--skill-dir", self.skill_dir, "--json")
        rec = receipt(out) or {}
        self.assertEqual(rc, 0, out[-500:])
        roots = [x.get("root") for x in (rec.get("recovery") or {}).get("scanned_roots") or []]
        self.assertEqual([os.path.normcase(x) for x in roots],
                         [os.path.normcase(self.skill_dir)])
        self.assertTrue(all(".pi" not in x for x in roots), roots)
        self.assertEqual(snapshot(self.tmp), before)
        # 同一 fixture 里 import/plan 仍然拒（不是把所有缺根都放行）
        rc2, out2 = cli("plan", "--from", self.src, "--kind", "crosscutting",
                        "--skill-dir", self.skill_dir, "--json")
        self.assertEqual(rc2, 4, out2[-400:])
        self.assertEqual((receipt(out2) or {}).get("refusal", {}).get("code"),
                         "deploy_root_required")

    def test_normal_status_is_read_only_and_rc0(self):
        """正常 status（合法根）仍 rc=0，且前后逐字节不变（只读入口不退化）。"""
        before = snapshot(self.tmp)
        rc, out = cli("status", "--skill-dir", self.skill_dir, "--deploy-root", self.root,
                      "--json")
        rec = receipt(out) or {}
        self.assertEqual(rc, 0, out[-500:])
        self.assertTrue(rec["recovery"]["read_only"])
        self.assertTrue(rec["recovery"]["auto_recover"])
        self.assertFalse(rec["recovery"]["auto_recoverable"])
        self.assertEqual(snapshot(self.tmp), before, "status 是只读入口")

    def test_unexpected_error_is_reported_unknown_not_ok(self):
        """未预期异常：rc=5 + refusal.code=unknown_error（不 traceback、不 return 0）。"""
        sys.path.insert(0, HERE)
        import importlib.util
        spec = importlib.util.spec_from_file_location("seep_import_meta_u", SCRIPT)
        impl = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(impl)

        def boom(opts):
            raise RuntimeError("boom")

        orig = impl.cmd_status
        impl.cmd_status = boom
        buf = io.StringIO()
        try:
            with unittest.mock.patch("sys.stdout", buf):
                rc = impl.main(["status", "--skill-dir", self.skill_dir,
                                "--deploy-root", self.root, "--json"])
        finally:
            impl.cmd_status = orig
        out = buf.getvalue()
        self.assertEqual(rc, 5, out[-400:])
        self.assertNotIn("Traceback", out)
        rec = json.loads(out)
        self.assertEqual((rec.get("refusal") or {}).get("code"), "unknown_error")
        self.assertFalse(rec.get("written"))
        self.assertFalse(rec.get("effective"))
        self.assertNotIn("boom", json.dumps(rec, ensure_ascii=False),
                         "unknown 回执不回显异常原文")


class LegacyMigrationCase(_Lab):
    def test_owned_legacy_copy_is_retired_and_navigation_is_canonical(self):
        self._make_legacy()
        parent_file = os.path.join(self.root, self.parent, "SKILL.md")
        with io.open(parent_file, encoding="utf-8") as stream:
            text = stream.read()
        with io.open(parent_file, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text.replace("subskills/%s/SKILL.md" % self.child, GUIDE_REF % self.child))
        rc, out = cli("deploy", "--name", self.child, "--parent", self.parent,
                      "--skill-dir", self.skill_dir, "--deploy-root", self.root, "--replace", "--json")
        rec = receipt(out) or {}
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(self.legacy))
        kept = rec["backups"]["legacy"]
        self.assertTrue(all(os.path.isfile(os.path.join(p, MAP)) for p in kept))
        with io.open(parent_file, encoding="utf-8") as stream:
            result = stream.read()
        self.assertNotIn(GUIDE_REF % self.child, result)
        self.assertIn("subskills/%s/SKILL.md" % self.child, result)
        self.assertEqual(snapshot(self.base), snapshot(os.path.join(
            self.skill_dir, self.parent, "subskills", self.child)))
        self.assertEqual(self.verify()[0], 0)

    def test_unknown_legacy_user_files_are_preserved_and_block_deploy(self):
        self._make_legacy()
        with io.open(os.path.join(self.legacy, "user-note.txt"), "w", encoding="utf-8") as stream:
            stream.write("USER CONTENT\n")
        before = snapshot(os.path.join(self.root, self.parent))
        rc, out = cli("deploy", "--name", self.child, "--parent", self.parent,
                      "--skill-dir", self.skill_dir, "--deploy-root", self.root, "--replace", "--json")
        self.assertEqual(rc, 5, out)
        self.assertEqual((receipt(out) or {})["refusal"]["code"], "legacy_deploy_conflict")
        self.assertEqual(snapshot(os.path.join(self.root, self.parent)), before)

    def test_process_death_after_legacy_move_recovers_before_retry(self):
        self._make_legacy()
        args = ["deploy", "--name", self.child, "--parent", self.parent,
                "--skill-dir", self.skill_dir, "--deploy-root", self.root, "--replace", "--json"]
        with mock.patch.dict(os.environ, {"SEEP_IMPORT_CRASH_POINT": "deploy.legacy.after.0"}):
            rc, out = cli(*args)
        self.assertEqual(rc, 87, out)
        rc, out = cli(*args)
        rec = receipt(out) or {}
        self.assertEqual(rc, 0, out)
        self.assertEqual(rec["auto_recovered"][0]["action"], "rollback")
        self.assertFalse(os.path.exists(self.legacy))
        self.assertFalse(rec["recovery"]["pending_manual"])
        self.assertEqual(self.verify()[0], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
