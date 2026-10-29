#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_domain_registry.py —— 正式域注册表（pack.json#id 为唯一身份）的必要回归。

钉住五件事（都只看**真实**实现，不复制 schema、不 mock）：
  1. 旧九域逐值无退：metadata（skill/board/matrix/case_globs/ext_scripts/kb_line_max/
     archive_*）、公共 LIMITS、REQUIRED_REFS、ROUTING_TESTS 与迁移前**逐项相等**。
  2. 单向依赖：lib/domain_registry.py 不 import route；正式全集不来自
     domain-aliases.json#formal_domains（删掉它，全集不变）。
  3. 深度契约严格：缺 depth / 未声明字段（cases_min 等）/ kb_line_max 越界 → 显式失败；
     400 的 softseep/apkseep 特例精确保留。
  4. 横切/别名/_pending 命名空间不得变成正式域。
  5. 临时第 10 域走**真实** skill-import 事务（显式 temp skill-dir + temp deploy root，
     无真实部署）：导入后 registry/route/adapter 都看得见它，但缺 depth_contract →
     显式 incomplete（不绿）；卸载/回滚后回到原集合。

硬边界：写入只发生在 tempfile 目录；真实 Tool/skill 前后 sha256 比对，部署根也使用
每个测试自己的临时目录。测试不读取或快照真实用户 AgentRoot。
不联网、不安装、不跑目标、不 commit。

跑法：python -B -X utf8 Tool/scripts/test_domain_registry.py
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
ROOT = os.path.dirname(TOOL)
LIB = os.path.join(HERE, "lib")
REAL_SKILL_DIR = os.path.join(TOOL, "skill")

sys.path.insert(0, LIB)
sys.path.insert(0, HERE)
import domain_registry as registry_mod  # noqa: E402
import domain_spec as spec_mod          # noqa: E402

REGISTRY_SRC = os.path.join(LIB, "domain_registry.py")


def _load(path, alias):
    spec = importlib.util.spec_from_file_location(alias, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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
                with open(p, "rb") as handle:
                    out[rel] = hashlib.sha256(handle.read()).hexdigest()
            except OSError:
                out[rel] = "<unreadable>"
    return out


def write_text(path, text):
    with io.open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def write_json(path, value):
    with io.open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


# ---------------------------------------------------------------------------
# 冻结基线：迁移**前** lib/domain_spec.py 的九域表 / LIMITS / REQUIRED_REFS / 路由回归集。
# 只做“逐值无退”的对照，不参与任何判据生成。
# ---------------------------------------------------------------------------
FROZEN_DOMAINS = {
    'apkseep': {
        'skill': 'apkseep',
        'board': 'apk-reverse',
        'matrix': 'apkseep-matrix.json',
        'case_globs': ['apkseep*'],
        'ext_scripts': [],
        'kb_line_max': 400,
    },
    'firmware-iot': {
        'skill': 'firmware-iot',
        'board': 'firmware-iot',
        'matrix': 'firmware-iot-matrix.json',
        'case_globs': ['firmware-iot*'],
        'ext_scripts': ['`fw-triage`（S4 已删：壳，真身在 firmware-iot/scripts/）'],
    },
    'web-pentest': {
        'skill': 'web-pentest',
        'board': 'web-pentest',
        'matrix': 'web-pentest-matrix.json',
        'case_globs': ['web-pentest*'],
        'ext_scripts': [],
    },
    'pwn-crypto': {
        'skill': 'pwn-crypto',
        'board': 'pwn-crypto',
        'matrix': 'pwn-crypto-matrix.json',
        'case_globs': ['pwn-crypto*'],
        'ext_scripts': ['Tool/skill/pwn-crypto/scripts/pwn-check.py'],
    },
    'protocol-plugin': {
        'skill': 'protocol-plugin',
        'board': 'protocol',
        'matrix': 'protocol-plugin-matrix.json',
        'case_globs': ['protocol*'],
        'ext_scripts': [],
    },
    'forensics-mobile': {
        'skill': 'forensics-mobile',
        'board': 'forensics',
        'matrix': 'forensics-mobile-matrix.json',
        'case_globs': ['forensics*'],
        'ext_scripts': ['`forensics-check`（S4 已删：壳，真身在 forensics-mobile/scripts/）'],
    },
    'malware-analysis': {
        'skill': 'malware-analysis',
        'board': 'malware-analysis',
        'matrix': 'malware-analysis-matrix.json',
        'case_globs': ['malware-analysis*'],
        'ext_scripts': ['Tool/skill/malware-analysis/scripts/mal-triage.py'],
    },
    'supply-chain-security': {
        'skill': 'supply-chain-security',
        'board': 'supply-chain',
        'matrix': 'supply-chain-security-matrix.json',
        'case_globs': ['supply-chain*'],
        'ext_scripts': ['Tool/skill/supply-chain-security/scripts/sc-check.py'],
    },
    'softseep': {
        'skill': 'softseep',
        'board': 'pe-reverse',
        'matrix': 'reverse-matrix.json',
        'case_globs': ['项目*', '案例*'],
        'ext_scripts': ['Tool/skill/malware-analysis/scripts/driver-triage.py'],
        'kb_line_max': 400,
        'archive_cases': 'Tool/cases/_archive',
        'archive_kb': 'Tool/mcp/Tool/reverselab/kb/_archive/pe-reverse',
    },
}

FROZEN_LIMITS = {
    'skill_max': 600,
    'skill_min': 120,
    'ref_max': 400,
    'ref_min': 60,
    'kb_max': 200,
    'kb_min': 50,
    'refs_min': 6,
    'refs_max': 10,
    'scripts_min': 2,
    'scripts_max': 16,
    'cases_min': 3,
    'cases_max': 7,
    'kb_min_count': 6,
    'kb_max_count': 10,
    'matrix_min': 12,
    'cards_min': 20,
    'cards_max': 30,
    'roadmap_max': 80,
}

FROZEN_REQUIRED_REFS = [('criteria', '01-criteria.md'), ('failure', '02-failure-criteria.md'), ('pitfalls', '03-model-pitfalls.md'), ('walkthrough', '04-walkthrough-*.md')]

FROZEN_ROUTING_TESTS_COUNT = 60
FROZEN_ROUTING_TESTS_SHA256 = "0446c8f69453d518a015803b10bd1c6c3506e8031c5e916f1d81261c61f5e194"

META_KEYS = ("_pack", "_incomplete")


def _compat(depth):
    """去掉兼容视图的元字段，只留深度契约字段（与冻结表同形）。"""
    return {k: v for k, v in depth.items() if k not in META_KEYS}


def routing_sha(tests):
    return hashlib.sha256(json.dumps(tests, ensure_ascii=False, sort_keys=True)
                          .encode("utf-8")).hexdigest()


class FrozenNineTest(unittest.TestCase):
    """1. 旧九域逐值无退（值来自 pack#depth_contract 的兼容视图，不是第二份表）。"""

    def test_domain_set_is_still_the_nine(self):
        self.assertEqual(sorted(spec_mod.DOMAINS), sorted(FROZEN_DOMAINS))
        self.assertEqual(sorted(registry_mod.load_registry(ROOT).ids()), sorted(FROZEN_DOMAINS))

    def test_per_domain_metadata_unchanged(self):
        for domain, expected in FROZEN_DOMAINS.items():
            with self.subTest(domain=domain):
                self.assertEqual(_compat(spec_mod.DOMAINS[domain]), expected,
                                 "域 %s 的深度元数据回退/漂移" % domain)

    def test_public_limits_and_required_refs_unchanged(self):
        self.assertEqual(dict(spec_mod.LIMITS), FROZEN_LIMITS)
        self.assertEqual(spec_mod.REQUIRED_REFS, FROZEN_REQUIRED_REFS)

    def test_original_routing_assertions_preserved_with_additive_cases(self):
        # Keep the exact original contract; new task boundaries append cases
        # instead of turning the old inventory size into a coverage ceiling.
        self.assertGreaterEqual(len(spec_mod.ROUTING_TESTS), FROZEN_ROUTING_TESTS_COUNT)
        original = spec_mod.ROUTING_TESTS[:FROZEN_ROUTING_TESTS_COUNT]
        self.assertEqual(routing_sha(original), FROZEN_ROUTING_TESTS_SHA256)
        self.assertEqual(len({r["text"] for r in spec_mod.ROUTING_TESTS}),
                         len(spec_mod.ROUTING_TESTS))

    def test_depth_limit_bounds_stay_tied_to_public_limits(self):
        self.assertEqual(spec_mod.DEPTH_LIMIT_DRIFT, [])
        for key, (low_key, high_key) in registry_mod.DEPTH_LIMIT_SOURCE.items():
            self.assertEqual(registry_mod.DEPTH_LIMITS[key],
                             (spec_mod.LIMITS[low_key], spec_mod.LIMITS[high_key]))

    def test_legacy_400_line_exception_preserved_exactly(self):
        for domain in ("softseep", "apkseep"):
            self.assertEqual(spec_mod.DOMAINS[domain].get("kb_line_max"), 400)
        others = {d: v.get("kb_line_max") for d, v in spec_mod.DOMAINS.items()
                  if d not in ("softseep", "apkseep")}
        self.assertTrue(all(v is None for v in others.values()), others)


class LoaderIsolationTest(unittest.TestCase):
    """2. 单向依赖；正式全集来自 pack，不来自别名配置。"""

    def test_registry_does_not_import_route(self):
        """单向依赖：registry 只读 pack，不 import route（也不 import domain_spec / gate）。"""
        import ast

        with io.open(REGISTRY_SRC, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertNotIn("route", imported)
        self.assertNotIn("domain_spec", imported)
        self.assertNotIn("gate", imported)

    def test_ids_come_from_packs_not_alias_config(self):
        with tempfile.TemporaryDirectory(prefix="seep-registry-ids-") as tmp:
            repo = os.path.join(tmp, "repo")
            cfg = os.path.join(repo, "Tool", "config")
            os.makedirs(cfg)
            for name in ("aa-one", "bb-two"):
                d = os.path.join(repo, "Tool", "skill", name)
                os.makedirs(d)
                write_text(os.path.join(d, "SKILL.md"), "x\n")
                write_json(os.path.join(d, "pack.json"),
                           {"schema": "seep.pack/1", "id": name,
                            "depth_contract": {"skill": name, "board": name,
                                               "matrix": name + "-matrix.json",
                                               "case_globs": [name + "*"]}})
            write_json(os.path.join(cfg, "domain-aliases.json"),
                       {"schema": "seep.domain-aliases/1",
                        "formal_domains": ["aa-one", "bb-two", "ghost-domain"],
                        "aliases": {"reverse": {"alias_to": "softseep", "status": "legacy"}},
                        "cross_cutting": ["seep-router", "unpack-loop"],
                        "pending_patterns": ["_pending/**/*"]})
            self.assertEqual(registry_mod.load_registry(repo).ids(), ["aa-one", "bb-two"])
            os.remove(os.path.join(cfg, "domain-aliases.json"))
            reg = registry_mod.load_registry(repo)
            self.assertEqual(reg.ids(), ["aa-one", "bb-two"])
            self.assertTrue(reg.warnings)
class DepthContractTest(unittest.TestCase):
    """3. 深度契约严格：不许用 metadata 改小下限 / 随意抬上限。"""

    def _pack(self):
        with io.open(os.path.join(REAL_SKILL_DIR, "apkseep", "pack.json"),
                     encoding="utf-8-sig") as handle:
            return json.load(handle)

    def _errors(self, pack):
        return registry_mod.validate_depth_contract(pack, ROOT)[1]

    def test_real_packs_are_all_valid(self):
        reg = registry_mod.load_registry(ROOT)
        self.assertEqual(reg.errors, [])
        self.assertEqual(reg.incomplete(), {})
        for domain in reg.ids():
            self.assertIsNotNone(reg.depth(domain), domain)

    def test_missing_depth_is_explicit_not_filtered(self):
        pack = self._pack()
        pack.pop("depth_contract")
        errs = self._errors(pack)
        self.assertTrue(any("depth_contract" in e for e in errs), errs)

    def test_loosening_fields_are_rejected(self):
        for key, value in (("cases_min", 1), ("refs_min", 1), ("scripts_min", 0)):
            pack = self._pack()
            pack["depth_contract"][key] = value
            with self.subTest(field=key):
                self.assertTrue(self._errors(pack), "未声明的放宽字段必须报错")

    def test_limits_cannot_be_raised_or_lowered(self):
        for value, ok in ((199, False), (200, True), (400, True), (401, False)):
            pack = self._pack()
            pack["depth_contract"]["kb_line_max"] = value
            with self.subTest(kb_line_max=value):
                self.assertEqual(not self._errors(pack), ok)
        for value, ok in ((2, False), (3, True), (7, True), (8, False), (99, False)):
            pack = self._pack()
            pack["depth_contract"]["cases_max"] = value
            with self.subTest(cases_max=value):
                self.assertEqual(not self._errors(pack), ok)

    def test_wrong_types_are_rejected(self):
        pack = self._pack()
        pack["depth_contract"]["case_globs"] = "apkseep*"
        self.assertTrue(self._errors(pack))
        pack = self._pack()
        pack["depth_contract"]["matrix"] = ""
        self.assertTrue(self._errors(pack))

    def test_contract_paths_cannot_escape_their_roots(self):
        cases = (
            ("skill", "../outside", "skill"),
            ("matrix", "../../outside-matrix.json", "matrix"),
            ("board", "/absolute-board", "board"),
            ("case_globs", ["../outside/*"], "case_globs"),
            ("case_globs", ["safe/*", "../../outside/*"], "case_globs"),
        )
        for field, value, expected in cases:
            with self.subTest(field=field, value=value):
                pack = self._pack()
                pack["depth_contract"][field] = value
                errors = self._errors(pack)
                self.assertTrue(any(expected in error for error in errors), errors)

    def test_gate_g2_uses_the_same_validation(self):
        gate = _load(os.path.join(HERE, "gate.py"), "seep_gate_for_registry_test")
        self.assertEqual(gate.g2_schema(self._pack()), [])
        bad = self._pack()
        bad["depth_contract"]["cases_max"] = 99
        self.assertTrue(any("cases_max" in e for e in gate.g2_schema(bad)))

    def test_case_dirs_reject_links_outside_cases_root(self):
        with tempfile.TemporaryDirectory(prefix="seep-case-link-") as tmp:
            repo = os.path.join(tmp, "repo")
            skill = os.path.join(repo, "Tool", "skill", "fixture-domain")
            cases = os.path.join(repo, "Tool", "cases")
            outside = os.path.join(tmp, "outside-case")
            os.makedirs(skill)
            os.makedirs(cases)
            os.makedirs(outside)
            write_text(os.path.join(skill, "SKILL.md"), "fixture\n")
            write_json(os.path.join(skill, "pack.json"), {
                "schema": "seep.pack/1",
                "id": "fixture-domain",
                "depth_contract": {
                    "skill": "fixture-domain",
                    "board": "fixture-domain",
                    "matrix": "fixture-domain-matrix.json",
                    "case_globs": ["linked-*"],
                },
            })
            os.symlink(outside, os.path.join(cases, "linked-outside"),
                       target_is_directory=True)
            self.assertEqual(
                registry_mod.case_dirs(repo, "fixture-domain"), [])


class RoutingConfigurationTest(unittest.TestCase):
    def test_osint_recipe_keeps_primary_and_replay_domains(self):
        path = os.path.join(ROOT, "Tool", "config", "playbook-domains.json")
        with io.open(path, encoding="utf-8") as handle:
            domains = json.load(handle)["map"]["osint-recon"]
        self.assertEqual(set(domains), {"softseep", "web-pentest"})


class DomainContractConsumerTest(unittest.TestCase):
    """domain-gate --spec 只消费当前契约，旧 SPEC/缺件/错域/篡改数字都必须失败。"""

    @staticmethod
    def _repo(tmp, contract=None, old_contract=None):
        repo = tempfile.mkdtemp(prefix="repo-", dir=tmp)
        skill = os.path.join(repo, "Tool", "skill", "fixture-domain")
        os.makedirs(skill)
        write_text(os.path.join(skill, "SKILL.md"), "fixture\n")
        write_json(os.path.join(skill, "pack.json"), {
            "schema": "seep.pack/1",
            "id": "fixture-domain",
            "depth_contract": {
                "skill": "fixture-domain",
                "board": "fixture-domain",
                "matrix": "fixture-domain-matrix.json",
                "case_globs": ["fixture-domain*"],
            },
        })
        os.makedirs(os.path.join(repo, "docs"))
        if contract is not None:
            write_text(os.path.join(repo, "docs", "DOMAIN-CONTRACT.md"), contract)
        if old_contract is not None:
            os.makedirs(os.path.join(repo, "docs", "history"))
            write_text(os.path.join(repo, "docs", "history", "X-DOMAIN-SPEC-v2.md"), old_contract)
        return repo

    @staticmethod
    def _check(repo):
        gate = _load(os.path.join(HERE, "domain-gate.py"),
                     "seep_domain_gate_contract_fixture")
        gate._use_root(repo)
        gate.DOMAIN_LOAD_ERRORS = []
        gate.results = []
        gate.check_spec()
        return gate.results[-1]

    def test_current_contract_passes_and_old_or_mutated_inputs_fail(self):
        valid = "skill 600; ref 400; refs 6–10; cards 20–30; fixture-domain\n"
        with tempfile.TemporaryDirectory(prefix="seep-domain-contract-") as tmp:
            with self.subTest(case="valid"):
                result = self._check(self._repo(tmp, contract=valid))
                self.assertTrue(result["ok"], result)
            with self.subTest(case="old-path-only"):
                result = self._check(self._repo(tmp, old_contract=valid))
                self.assertFalse(result["ok"], result)
            for label, text in (
                ("missing-domain", valid.replace("fixture-domain", "other-domain")),
                ("numeric-tamper", valid.replace("600", "599")),
            ):
                with self.subTest(case=label):
                    result = self._check(self._repo(tmp, contract=text))
                    self.assertFalse(result["ok"], result)




class NamespaceSeparationTest(unittest.TestCase):
    """4. 横切/别名/待迁移命名空间不能变成正式域。"""

    def _repo(self, tmp, name, aliases=None):
        repo = os.path.join(tmp, "repo")
        d = os.path.join(repo, "Tool", "skill", name)
        os.makedirs(d)
        write_text(os.path.join(d, "SKILL.md"), "x\n")
        write_json(os.path.join(d, "pack.json"),
                   {"schema": "seep.pack/1", "id": name,
                    "depth_contract": {"skill": name, "board": name,
                                       "matrix": name + "-matrix.json",
                                       "case_globs": [name + "*"]}})
        cfg = os.path.join(repo, "Tool", "config")
        os.makedirs(cfg)
        write_json(os.path.join(cfg, "domain-aliases.json"),
                   {"schema": "seep.domain-aliases/1", "aliases": aliases or {},
                    "cross_cutting": ["seep-router"],
                    "pending_patterns": ["_pending/**/*"]})
        return repo

    def test_cross_cutting_pack_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="seep-ns-cross-") as tmp:
            reg = registry_mod.load_registry(self._repo(tmp, "seep-router"))
            self.assertEqual(reg.ids(), [])
            self.assertTrue(any("cross_cutting" in e for e in reg.errors), reg.errors)

    def test_alias_name_cannot_be_a_formal_domain(self):
        with tempfile.TemporaryDirectory(prefix="seep-ns-alias-") as tmp:
            repo = self._repo(tmp, "reverse",
                              {"reverse": {"alias_to": "softseep", "status": "legacy"}})
            reg = registry_mod.load_registry(repo)
            self.assertEqual(reg.ids(), [])
            self.assertTrue(any("别名" in e for e in reg.errors), reg.errors)

    def test_underscore_namespaces_are_skipped(self):
        with tempfile.TemporaryDirectory(prefix="seep-ns-pending-") as tmp:
            repo = self._repo(tmp, "real-domain")
            pend = os.path.join(repo, "Tool", "skill", "_pending", "sub")
            os.makedirs(pend)
            write_text(os.path.join(pend, "SKILL.md"), "x\n")
            write_json(os.path.join(pend, "pack.json"),
                       {"schema": "seep.pack/1", "id": "sub"})
            self.assertEqual(registry_mod.load_registry(repo).ids(), ["real-domain"])

    def test_explicit_pending_skill_is_not_a_formal_domain(self):
        with tempfile.TemporaryDirectory(prefix="seep-ns-pending-name-") as tmp:
            repo = self._repo(tmp, "pending-skill")
            config = os.path.join(repo, "Tool/config/domain-aliases.json")
            write_json(config, {"pending_skills": ["pending-skill"]})
            reg = registry_mod.load_registry(repo)
            self.assertEqual(reg.ids(), [])
            self.assertTrue(reg.errors)

    def test_bad_alias_target_is_reported_without_crashing_loader(self):
        for target in (["missing"], {"unexpected": "missing"}):
            with self.subTest(target=target), tempfile.TemporaryDirectory(prefix="seep-ns-bad-alias-") as tmp:
                repo = self._repo(tmp, "real-domain", {
                    "old": {"alias_to": target, "status": "legacy"}})
                reg = registry_mod.load_registry(repo)
                self.assertEqual(reg.ids(), ["real-domain"])
                self.assertTrue(any('alias_to' in error for error in reg.errors))


class TenthDomainTransactionTest(unittest.TestCase):
    """5. 真实导入事务（temp roots）→ 注册/路由/adapter 可见；缺 depth 不绿；卸载回原集合。"""

    NAME = "zz-tenth"
    PACK = {
        "schema": "seep.pack/1", "id": "", "l1": "zz 临时域怎么处理",
        "routes": [{"label": "zz tenth", "must": ["(?i)zz-tenth"], "priority": 9099}],
        "stages": ["0-analysis"], "tools": ["seep_apk_info"], "cases": ["leaf-apk"],
        "case_roles": {"witness": ["leaf-apk"], "depth_gate": ["leaf-apk"]},
        "witness": {"cmd": "python Tool/scripts/case_state.py verify "
                           "--case Tool/cases/leaf-apk",
                    "expect": "exit0", "budget_s": 30},
        "witness_tool": {"cmd": "Tool/skill/zz-tenth/scripts/witness.py",
                         "why": "临时第 10 域回归"},
        "evidence_contract": {"required_fields": ["claim", "confidence", "authority", "evidence"],
                              "authority_allow": ["shipped-artifact", "controlled-replay",
                                                  "external-service"],
                              "pass_forbids_confidence": ["inferred", "unknown"]},
        "limitations": ["临时域，只证明扩展机制"], "invalidation": ["测试结束即失效"],
    }

    @classmethod
    def setUpClass(cls):
        cls.real_skill_before = snapshot(REAL_SKILL_DIR)
        cls.impl = _load(os.path.join(HERE, "skill-import.py"),
                         "seep_skill_import_for_registry_test")

    @classmethod
    def tearDownClass(cls):
        assert snapshot(REAL_SKILL_DIR) == cls.real_skill_before, "真实 Tool/skill 被测试改动"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="seep-registry-10th-")
        self.repo = os.path.join(self.tmp, "repo")
        self.skill_dir = os.path.join(self.repo, "Tool", "skill")
        os.makedirs(self.skill_dir)
        cfg = os.path.join(self.repo, "Tool", "config")
        os.makedirs(cfg)
        write_json(os.path.join(cfg, "domain-aliases.json"),
                   {"schema": "seep.domain-aliases/1", "aliases": {},
                    "cross_cutting": ["seep-router", "unpack-loop"],
                    "pending_patterns": ["_pending/**/*"]})
        self._seed_domain("zz-base", 9098)
        self.roots = [os.path.join(self.tmp, "agent-a", "skills")]
        for root in self.roots:
            os.makedirs(root)

    def tearDown(self):
        self.assertEqual(snapshot(REAL_SKILL_DIR), self.real_skill_before)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed_domain(self, name, priority):
        """已闭合的对照域：带合法 depth_contract（第 10 域缺它才是对照）。"""
        d = os.path.join(self.skill_dir, name)
        os.makedirs(d, exist_ok=True)
        write_text(os.path.join(d, "SKILL.md"), "seed\n")
        pack = json.loads(json.dumps(self.PACK))
        pack["id"] = name
        pack["l1"] = "%s 怎么处理" % name
        pack["routes"][0]["must"] = ["(?i)%s" % name]
        pack["routes"][0]["priority"] = priority
        pack["depth_contract"] = {"skill": name, "board": name,
                                  "matrix": name + "-matrix.json",
                                  "case_globs": [name + "*"], "ext_scripts": []}
        write_json(os.path.join(d, "pack.json"), pack)

    def _src(self):
        d = os.path.join(self.tmp, "src", self.NAME)
        os.makedirs(d, exist_ok=True)
        os.makedirs(os.path.join(d, "scripts"), exist_ok=True)
        write_text(os.path.join(d, "SKILL.md"),
                   '---\nname: %s\ndescription: "zz 临时域"\n---\n\n正文\n' % self.NAME)
        write_text(os.path.join(d, "scripts", "witness.py"),
                   "import json\nprint(json.dumps({'ok': True, 'domain': 'zz-tenth', "
                   "'witness': 'fixture'}))\n")
        pack = json.loads(json.dumps(self.PACK))
        pack["id"] = self.NAME
        pack["l1"] = "zz-tenth 临时域怎么处理"
        write_json(os.path.join(d, "pack.json"), pack)
        return d

    def _opts(self, src):
        return self.impl._opts(src=src, name=self.NAME, kind="domain",
                               skill_dir=self.skill_dir, deploy_roots=list(self.roots))

    def _import(self):
        return self.impl.run_import(self._opts(self._src()), faults={})

    def test_import_registers_route_and_adapter_see_it(self):
        self.assertEqual(registry_mod.load_registry(self.repo).ids(), ["zz-base"])
        rec = self._import()
        self.assertEqual(rec["rc"], 0, rec.get("why"))
        self.assertTrue(rec["route_visible"])
        for deployed in rec["deployed"]:
            self.assertTrue(deployed["path"].startswith(self.tmp), deployed)
        reg = registry_mod.load_registry(self.repo)
        self.assertIn(self.NAME, reg.ids())

        import route as route_mod
        packs, problems = route_mod.load_packs(self.skill_dir)
        self.assertEqual(problems, [])
        self.assertIn(self.NAME, {p["id"] for p in packs})
        self.assertIn(self.NAME, {h["pack"] for h in
                                  route_mod.resolve("zz-tenth 怎么处理", self.skill_dir)})

        dac = _load(os.path.join(HERE, "domain-adapter-check.py"),
                    "seep_dac_for_registry_test")
        self.assertIn(self.NAME, dac.formal_domains(self.repo))
        report = dac.build_report(self.repo)
        row = next(r for r in report["domains"] if r["domain"] == self.NAME)
        self.assertEqual(row["contracts"]["depth_contract"]["status"], "FAIL")
        self.assertIn("depth_contract", " ".join(row["contracts"]["depth_contract"]["missing"]))

    def test_missing_depth_stays_incomplete_and_never_green(self):
        self.assertEqual(self._import()["rc"], 0)
        reg = registry_mod.load_registry(self.repo)
        status = reg.status(self.NAME)
        self.assertTrue(status["registered"])
        self.assertTrue(status["route_declared"])
        self.assertFalse(status["depth_declared"])
        self.assertFalse(status["depth_contract_valid"])
        self.assertFalse(status["materials"]["case_template"])
        self.assertTrue(status["incomplete"])
        self.assertEqual(sorted(reg.incomplete()), [self.NAME])

    def test_uninstall_restores_previous_set(self):
        self.assertEqual(self._import()["rc"], 0)
        self.assertIn(self.NAME, registry_mod.load_registry(self.repo).ids())
        shutil.rmtree(os.path.join(self.skill_dir, self.NAME))
        after = registry_mod.load_registry(self.repo)
        self.assertEqual(after.ids(), ["zz-base"])
        self.assertEqual(after.incomplete(), {})

    def test_aborted_transaction_leaves_nothing(self):
        """stage 阶段真实 I/O 中断 → 仓库侧零残留，注册表仍是原集合。"""
        before = snapshot(self.skill_dir)
        rec = self.impl.run_import(self._opts(self._src()), faults={"stage.copy": True})
        self.assertNotEqual(rec["rc"], 0, rec)
        self.assertEqual(snapshot(self.skill_dir), before)
        self.assertEqual(registry_mod.load_registry(self.repo).ids(), ["zz-base"])

    def test_fake_witness_pack_is_rejected_by_real_g2(self):
        src = self._src()
        with io.open(os.path.join(src, "pack.json"), encoding="utf-8") as handle:
            pack = json.load(handle)
        pack["cases"] = ["does-not-exist-case"]
        pack["case_roles"] = {"witness": ["does-not-exist-case"],
                              "depth_gate": ["does-not-exist-case"]}
        write_json(os.path.join(src, "pack.json"), pack)
        before = snapshot(self.skill_dir)
        rec = self.impl.run_import(self._opts(src), faults={})
        self.assertEqual(rec["rc"], 4, rec)
        self.assertEqual(rec["refusal"]["code"], "pack_schema")
        self.assertEqual(snapshot(self.skill_dir), before)
        self.assertEqual(registry_mod.load_registry(self.repo).ids(), ["zz-base"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
