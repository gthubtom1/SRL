"""Real host-neutral discovery, CLI/MCP parity and negative resource fixtures."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lib.capability_discovery import discover, _Catalog, _description, _score, _terms

ROOT = Path(__file__).resolve().parents[2]
KB_FIXTURE = "Tool/mcp/Tool/reverselab/kb/" + "oauth.md"
CONFIG_FIXTURE = "Tool/config/" + "oauth.json"


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="seep-discovery-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write("Tool/config/domain-aliases.json", {"cross_cutting": [], "aliases": {}})
        for name in ("web-pentest", "protocol-plugin"):
            self.write("Tool/skill/" + name + "/pack.json",
                       {"schema": "seep.pack/1", "id": name, "tools": ["seep_example"]})
            self.write("Tool/skill/" + name + "/SKILL.md", "# General domain\n")
        self.write("Tool/config/tool-capabilities.json", {"tools": {"ida": {}}})
        self.write("Tool/config/mcp-servers.json", {"servers": {"playwright": {}}})
        self.write("Tool/mcp/seep_mcp_server.py", "@server.tool()\ndef seep_example():\n    return ''\n")
        self.oauth = "Tool/skill/web-pentest/subskills/oauth-oidc/SKILL.md"
        self.write(self.oauth, '---\nname: oauth-oidc\ndescription: >-\n  OAuth PKCE callback testing\n---\n'
                   '# OAuth callback\n[Input](references/input.md)\n'
                   '`' + KB_FIXTURE + '`\n`seep_example`\n')
        self.write("Tool/skill/web-pentest/subskills/oauth-oidc/references/input.md", "# Input\n")
        self.write(KB_FIXTURE, "# OAuth reference\n")
        self.write("Tool/scripts/validate.py", "raise AssertionError('must not execute')\n")
        self.cap = {"id": "callback", "title": "OAuth callback", "domain": "web-pentest",
                    "inputs": ["config"], "outputs": ["tests"], "scripts": ["Tool/scripts/validate.py"],
                    "refs": [self.oauth], "maturity": "usable", "compose": []}
        self.write("Tool/capabilities/callback.json", self.cap)

    def write(self, path, value):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(value, ensure_ascii=False) if isinstance(value, dict) else value,
                     encoding="utf-8")
        return p

    def query(self, query="OAuth PKCE callback", limit=20):
        return discover(self.root, query, limit)

    def capability(self, result):
        return next(r for r in result["resources"] if r["kind"] == "capability")

    def test_development_borrows_subskill_without_case_or_task_domain(self):
        result = self.query()
        self.assertEqual(result["status"], "matches")
        sub = next(r for r in result["resources"] if r["kind"] == "subskill")
        self.assertEqual(sub["path"], self.oauth)
        self.assertTrue(any(l["kind"] == "kb_article" and l["present"] for l in sub["links"]))
        self.assertEqual(sub["tools"][0]["runtime_status"], "not_checked")
        self.assertFalse((self.root / "work").exists())

    def test_multiline_frontmatter(self):
        self.assertEqual(_description('---\ndescription: >-\n  OAuth flow\n  PKCE\n---\n'), "OAuth flow PKCE")

    def test_ascii_boundaries_do_not_match_eac_in_react(self):
        self.assertEqual(_score("EAC anti-cheat", _terms("React page white screen"))[0], 0)

    def test_ordinary_tests_have_normal_empty_result(self):
        result = self.query("给这个 Python 函数补单元测试")
        self.assertEqual(result["status"], "no_matches")
        self.assertTrue(result["ok"])

    def test_query_not_echoed_and_never_executes(self):
        with patch("subprocess.run", side_effect=AssertionError("execution forbidden")):
            result = self.query("OAuth PRIVATE-SECRET-123")
        self.assertNotIn("PRIVATE-SECRET-123", json.dumps(result))
        self.assertFalse(result["execution_performed"])

    def test_reserved_and_probe_do_not_promote(self):
        for fields in ({"reserved": True}, {"maturity": "probe", "note": "offline only"}):
            self.write("Tool/capabilities/callback.json", {**self.cap, **fields})
            item = self.capability(self.query())
            self.assertFalse(item["declared_auto_composable"])
            self.assertEqual(item["applicability"], "reference_only_not_automatic_execution")

    def test_missing_script_keeps_method_but_not_composable(self):
        (self.root / "Tool/scripts/validate.py").unlink()
        self.assertFalse(self.capability(self.query())["declared_auto_composable"])

    def test_compose_missing_or_cyclic_is_reported(self):
        for child in (None, {**self.cap, "id": "child", "compose": ["callback"]}):
            with self.subTest(child=child):
                self.write("Tool/capabilities/callback.json", {**self.cap, "compose": ["child"]})
                if child:
                    self.write("Tool/capabilities/child.json", child)
                result = self.query()
                item = next(r for r in result["resources"] if r["id"] == "capability:callback")
                self.assertFalse(item["declared_auto_composable"])

    def test_compose_is_not_a_mandatory_task_chain(self):
        self.write("Tool/capabilities/callback.json", {**self.cap, "compose": ["child"]})
        self.write("Tool/capabilities/child.json", {**self.cap, "id": "child", "reserved": True})
        resources = {r["id"]: r for r in self.query()["resources"]}
        self.assertTrue(resources["capability:callback"]["declared_auto_composable"])
        self.assertFalse(resources["capability:child"]["declared_auto_composable"])

    def test_owner_does_not_force_script_directory(self):
        self.assertTrue(self.capability(self.query())["declared_auto_composable"])

    def test_broken_json_is_partial_not_no_match(self):
        self.write("Tool/capabilities/bad.json", "{broken")
        result = self.query("unrelatedxyz")
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["warnings"])

    def test_invalid_domain_id_not_silently_accepted(self):
        self.write("Tool/skill/web-pentest/pack.json", {"id": "elsewhere", "schema": "seep.pack/1"})
        self.assertEqual(self.query()["status"], "partial")

    def test_invalid_capability_array_is_reported(self):
        self.write("Tool/capabilities/callback.json", {**self.cap, "scripts": 7})
        self.assertEqual(self.query()["status"], "partial")

    def test_invalid_tool_catalog_shape_is_partial(self):
        self.write("Tool/config/tool-capabilities.json", {"tools": []})
        self.assertEqual(self.query()["status"], "partial")

    def test_missing_method_reference_is_explicit(self):
        self.write(self.oauth, "# OAuth PKCE\n[Missing](references/missing.md)\n")
        result = self.query()
        self.assertEqual(result["status"], "partial")
        self.assertTrue(any(w["code"] == "unresolved_reference" for w in result["warnings"]))

    def test_json_reference_is_not_misread_as_javascript(self):
        self.write(CONFIG_FIXTURE, {})
        self.write(self.oauth, "# OAuth PKCE\n`" + CONFIG_FIXTURE + "`\n")
        result = self.query()
        self.assertEqual(result["status"], "matches")
        links = next(r for r in result["resources"] if r["kind"] == "subskill")["links"]
        self.assertTrue(any(l.get("path") == CONFIG_FIXTURE and l["present"]
                            and l["kind"] == "configuration" for l in links))

    def test_software_registry_is_not_a_method(self):
        self.write(self.oauth, "# OAuth PKCE\n`tool:ida`\n")
        sub = next(r for r in self.query()["resources"] if r["kind"] == "subskill")
        link = next(l for l in sub["links"] if l.get("kind") == "tool_software")
        self.assertTrue(link["declared"])
        self.assertFalse(link["invocable_method"])

    def test_result_budget_exposes_omitted_resources(self):
        with patch("lib.capability_discovery.MAX_OUTPUT_BYTES", 2400):
            result = self.query()
        self.assertLessEqual(len(json.dumps(result, ensure_ascii=False).encode("utf-8")), 2400)
        self.assertEqual(result["total_matches"], len(result["resources"]) + result["omitted_count"])

    def test_pending_not_discovered(self):
        self.write("Tool/skill/_pending/old/SKILL.md", "# OAuth PKCE\n")
        self.assertFalse(any("_pending" in r["path"] for r in self.query()["resources"]))

    def test_duplicate_child_names_keep_parent_identity(self):
        self.write("Tool/skill/protocol-plugin/subskills/oauth-oidc/SKILL.md", "# OAuth PKCE\n")
        sub = [r for r in self.query()["resources"] if r["kind"] == "subskill"]
        self.assertEqual(len(sub), 2)
        self.assertEqual(len({r["id"] for r in sub}), 2)

    def test_links_do_not_read_outside_source_root(self):
        self.write(self.oauth, "# OAuth PKCE\n[secret](../../../../../../outside.md)\n")
        result = self.query()
        for resource in result["resources"]:
            self.assertFalse(any("outside.md" in str(l) for l in resource["links"]))

    def test_linked_source_escape_is_rejected_before_registry(self):
        outside = Path(self.temp.name).parent / (self.root.name + "-outside")
        try:
            (self.root / "Tool/skill/linked").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("host does not permit directory symlinks")
        with patch("lib.capability_discovery.domain_registry.load_registry",
                   side_effect=AssertionError("must not open untrusted registry")):
            self.assertEqual(self.query()["status"], "partial")

    def test_budget_refuses_oversized_declarations_before_registry_load(self):
        with patch("lib.capability_discovery.MAX_FILE_BYTES", 5):
            result = self.query()
        self.assertEqual(result["status"], "partial")
        self.assertTrue(any(w["code"] == "resource_constraint" for w in result["warnings"]))

    def test_typed_service_software_and_script_references(self):
        self.write("Tool/playbooks/oauth.md", '# OAuth PKCE\n- 触发：OAuth\n'
                   '`tool:ida` `mcp:playwright` `repo:validate`\n')
        book = next(r for r in self.query()["resources"] if r["kind"] == "playbook")
        links = {l["kind"]: l for l in book["links"]}
        self.assertFalse(links["tool_software"]["invocable_method"])
        self.assertFalse(links["mcp_server"]["invocable_method"])
        self.assertEqual(links["script_reference"]["status"], "unique")

    def test_script_ambiguity_not_arbitrarily_resolved(self):
        self.write("Tool/skill/protocol-plugin/scripts/validate.py", "# second script\n")
        catalog = _Catalog(self.root)
        reference = catalog.reference({"kind": "typed_reference", "namespace": "repo", "name": "validate"})
        self.assertEqual(reference["status"], "ambiguous")
        self.assertEqual(reference["candidate_count"], 2)

    def test_limit_exposes_omission_and_source_change_invalidates_revision(self):
        first = self.query(limit=1)
        self.assertGreater(first["omitted_count"], 0)
        self.write(self.oauth, "# OAuth PKCE updated\n")
        self.assertNotEqual(first["source_revision"], self.query(limit=1)["source_revision"])

    def test_invalid_parameters_and_root(self):
        for query, limit in (("", 5), (None, 5), ("a" * 2001, 5), ("OAuth", True), ("OAuth", 21)):
            self.assertEqual(discover(self.root, query, limit)["status"], "invalid_parameter")
        self.assertEqual(discover(self.root / "absent", "OAuth")["status"], "invalid_source")

    def test_cli_matches_core_and_unmatched_is_exit_zero(self):
        for question in ("OAuth PKCE callback", "unrelatedxyz"):
            proc = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "Tool/scripts/route.py"),
                                   "--skill-dir", str(self.root / "Tool/skill"),
                                   "--discover", question, "--limit", "20", "--json"],
                                  capture_output=True, text=True, encoding="utf-8", timeout=15)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout), self.query(question))


class ShippedDiscoveryTests(unittest.TestCase):
    def test_shipped_domain_crosstalk_matrix_keeps_primary_and_auxiliary_domains(self):
        path = ROOT / "Tool/scripts/domain-gate.py"
        spec = importlib.util.spec_from_file_location("discovery_domain_gate", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        import route
        for case in module.ROUTING_TESTS:
            with self.subTest(text=case["text"]):
                _hits, domains = route.resolved_domains(case["text"])
                self.assertEqual(module.routing_failures(case, domains), [])

    def test_discovered_oauth_method_has_a_working_offline_validation_path(self):
        result = discover(ROOT, "OAuth PKCE 回调 身份绑定", 5)
        method = next(r for r in result["resources"] if r["path"].endswith("oauth-oidc/SKILL.md"))
        script = next(l["path"] for l in method["links"] if l["kind"] == "script")
        self.assertTrue(script.endswith("oauth-oidc/scripts/oauth-review.py"))
        self.assertIn("PKCE", (ROOT / method["path"]).read_text(encoding="utf-8"))
        proc = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / script), "--self-test"],
                              cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("pass", proc.stdout.lower())

    def test_source_surface_baseline_is_separate_from_observed_handshake(self):
        modules = []
        for path in (ROOT / "Tool/scripts/preflight.py",
                     ROOT / "Tool/skill/softseep/scripts/mcp-param-contract.py"):
            spec = importlib.util.spec_from_file_location("discovery_baseline_" + str(len(modules)), path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            modules.append(module)
        with tempfile.TemporaryDirectory(prefix="seep-source-baseline-") as home:
            tool = Path(home) / "Tool"
            path = tool / "mcp/.baseline/tools.json"
            path.parent.mkdir(parents=True)
            snapshot = tool / "config/packs.baseline.json"
            snapshot.parent.mkdir(parents=True)
            snapshot.write_text('{"mcp_handshake":{"servers":{"seep":{"toolsCount":20}}}}')
            before = snapshot.read_bytes()
            for data, expected in (({"count": 1, "tools": ["seep_new"]}, 1),
                                   ({"count": 2, "tools": ["seep_new"]}, None),
                                   ({"count": 2, "tools": ["seep_new", "seep_new"]}, None),
                                   ({"count": True, "tools": ["seep_new"]}, None)):
                path.write_text(json.dumps(data), encoding="utf-8")
                for module in modules:
                    with patch.object(module, "TOOL", str(tool)):
                        fn = getattr(module, "_tool_count_baseline", None) or module._resolve_baseline
                        self.assertEqual(fn(), expected)
            path.unlink()
            for module in modules:
                with patch.object(module, "TOOL", str(tool)):
                    fn = getattr(module, "_tool_count_baseline", None) or module._resolve_baseline
                    self.assertIsNone(fn())
            self.assertEqual(snapshot.read_bytes(), before)

    def test_nine_domains_and_development_topic_are_reachable(self):
        cases = {"web-pentest": "OAuth PKCE", "protocol-plugin": "私有协议 构包 分帧",
                 "softseep": "IDA 反编译", "apkseep": "Android APK 加固",
                 "firmware-iot": "固件 squashfs", "pwn-crypto": "RSA ROP",
                 "forensics-mobile": "取证 时间线", "malware-analysis": "YARA IOC 恶意样本",
                 "supply-chain-security": "SBOM 供应链"}
        for domain, query in cases.items():
            with self.subTest(domain=domain):
                result = discover(ROOT, query, 20)
                self.assertTrue(any(r["domain"] == domain for r in result["resources"]), result)
                self.assertFalse(result["execution_performed"])

    def test_unknown_research_and_no_progress_reach_existing_investigation_recipe(self):
        for query in ("技术未知 版本差异 查资料", "网上资料 反复空转 没有新证据", "换会话忘记警告 环境风险"):
            with self.subTest(query=query):
                result = discover(ROOT, query, 10)
                self.assertTrue(any(r["path"] == "Tool/playbooks/evidence-led-investigation.md"
                                    for r in result["resources"]), result)
                self.assertFalse(result["execution_performed"])

    def test_mcp_and_cli_share_core_without_pi(self):
        # Import under an isolated home; never load a Pi extension or real user state.
        with tempfile.TemporaryDirectory(prefix="seep-discovery-home-") as home:
            source = (ROOT / "Tool/mcp/seep_mcp_server.py").as_posix()
            code = ("import importlib.util,json; s=importlib.util.spec_from_file_location('s',"
                    + repr(source) + "); m=importlib.util.module_from_spec(s); s.loader.exec_module(m);"
                    "print(json.dumps(m.seep_capability_discover('OAuth PKCE',2)))")
            env = dict(os.environ, HOME=home, USERPROFILE=home, SEEP_STATE_DIR=home,
                       SEEP_AUTOCASE="0", PYTHONIOENCODING="utf-8")
            proc = subprocess.run([sys.executable, "-c", code], cwd=ROOT / "Tool/mcp", env=env,
                                  capture_output=True, text=True, encoding="utf-8", timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout), discover(ROOT, "OAuth PKCE", 2))

    def test_registered_stdio_mcp_schema_result_and_error(self):
        with tempfile.TemporaryDirectory(prefix="seep-discovery-stdio-") as home:
            code = '''
import asyncio,json,os,sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
async def run():
    params=StdioServerParameters(command=sys.executable,args=[sys.argv[1]],env=dict(os.environ))
    async with stdio_client(params) as (read,write):
        async with ClientSession(read,write) as client:
            await client.initialize()
            inventory=await client.list_tools()
            tool=next(t for t in inventory.tools if t.name=='seep_capability_discover')
            assert 'query' in tool.inputSchema.get('required',[])
            good=await client.call_tool(tool.name,{'query':'OAuth PKCE','limit':2})
            assert not good.isError
            result=json.loads(next(c.text for c in good.content if c.type=='text'))
            bad=await client.call_tool(tool.name,{'query':'OAuth','limit':0})
            assert bad.isError
            print(json.dumps(result))
asyncio.run(run())
'''
            env = dict(os.environ, HOME=home, USERPROFILE=home, SEEP_STATE_DIR=home,
                       SEEP_AUTOCASE="0", PYTHONIOENCODING="utf-8",
                       APPDATA=home, LOCALAPPDATA=home, XDG_CONFIG_HOME=home,
                       SEEP_AGENT_MCP=str(Path(home) / "mcp.json"), SEEP_WORKSPACE=home)
            proc = subprocess.run([sys.executable, "-c", code, str(ROOT / "Tool/mcp/seep_mcp_server.py")],
                                  cwd=home, env=env, capture_output=True, text=True,
                                  encoding="utf-8", timeout=45)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout), discover(ROOT, "OAuth PKCE", 2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
