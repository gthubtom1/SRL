"""Synthetic resource mutation, real CLI/MCP reads and bounded authoring tests."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lib import resource_maintenance as M
from lib.capability_discovery import discover
from lib.resource_sources import Sources, SourceError, DEFAULTS, knowledge_entries, knowledge_path

ROOT = Path(__file__).resolve().parents[2]


class Evolution(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="seep-evolution-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.backups = self.base / "backups"
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"SEEP_RESOURCE_CONFIG": "", "PYTHONDONTWRITEBYTECODE": "1"}).start()
        self.write("Tool/config/resource-sources.json", {"schema": "seep.resource-sources/1",
                                                       "sources": DEFAULTS, "disabled_resources": []})
        self.write("Tool/config/domain-aliases.json", {"cross_cutting": [], "aliases": {}})
        self.write("Tool/skill/web-pentest/pack.json", {"schema": "seep.pack/1", "id": "web-pentest", "tools": []})
        self.write("Tool/skill/web-pentest/SKILL.md", "# Web methods\n")
        self.write("Tool/config/tool-capabilities.json", {"tools": {}})
        self.write("Tool/config/mcp-servers.json", {"servers": {}})
        self.write(".gitignore", "/Tool/mcp/kb_local/**/.project.lock\n/Tool/mcp/kb_local/**/.project-transaction.json\n")
        for name in ("Tool/mcp/kb_local", "Tool/mcp/Tool/reverselab/kb"):
            (self.repo / name).mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True, capture_output=True)

    def write(self, relative, value):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) if isinstance(value, (dict, list)) else value, encoding="utf-8")
        return path

    def local(self, sources=(), disabled=()):
        path = self.base / "sources.json"
        path.write_text(json.dumps({"schema": "seep.resource-sources/1", "sources": list(sources),
                                   "disabled_resources": list(disabled)}), encoding="utf-8")
        os.environ["SEEP_RESOURCE_CONFIG"] = str(path)
        return path

    def request(self, **changes):
        req = {"source_id": "local-kb", "path": "softseep/unpacking/vmp.md",
               "body": "# VMP investigation\nCompare the exact version before choosing a method.\n",
               "metadata": {"id": "vmp-investigation", "title": "VMP investigation", "summary": "Version-specific VMP observations",
                            "tags": ["VMP", "unpacking"], "applies_to": "Synthetic Windows fixture only",
                            "maturity": "reference", "sources": ["https://example.invalid/method"], "counterexamples": ""},
               "reason": "Retain a sourced method without claiming target success", "expected_sha256": "absent",
               "reviewed": [], "project": None, "evidence": [], "queries": ["VMP investigation"]}
        req.update(changes)
        return req

    def plan(self, request):
        plan = M.prepare(self.repo, request)
        if plan["action"] == "review_required":
            request = copy.deepcopy(request)
            request["reviewed"] = [{"resource_id": r["resource_id"], "sha256": M.read_resource(self.repo, r["resource_id"])["sha256"],
                                    "decision": "Read and compare the source scope; this is a deliberate update or separate condition"}
                                   for r in plan["comparison"]["candidates"]]
            plan = M.prepare(self.repo, request)
        return plan

    def create(self, request=None):
        return M.apply(self.repo, self.plan(request or self.request()), backups=self.backups)

    def target(self):
        return self.repo / "Tool/mcp/kb_local/softseep/unpacking/vmp.md"

    def test_standalone_tool_and_mcp_declarations_are_discoverable(self):
        self.write("Tool/config/tool-capabilities.json", {"tools": {"sentinel": {"display": "ZephyrSentinel"}}})
        self.write("Tool/config/mcp-servers.json", {"servers": {"zephyr": {"description": "ZephyrSentinel", "env": {"PRIVATE": "DO_NOT_RETURN"}}}})
        result = discover(self.repo, "ZephyrSentinel", 20)
        self.assertEqual({r["kind"] for r in result["resources"]}, {"tool_software", "mcp_server"})
        self.assertTrue(all(r["runtime_status"] == "not_checked" for r in result["resources"]))
        self.assertNotIn("DO_NOT_RETURN", json.dumps(result))

    def test_skill_add_remove_and_disable_without_restart(self):
        name = "Tool/skill/web-pentest/subskills/sentinel/SKILL.md"
        self.assertFalse(discover(self.repo, "ZephyrSentinel")["resources"])
        path = self.write(name, "# ZephyrSentinel\n")
        result = discover(self.repo, "ZephyrSentinel")
        self.assertTrue(result["resources"])
        self.local(disabled=["subskill:" + name])
        self.assertFalse(discover(self.repo, "ZephyrSentinel")["resources"])
        os.environ["SEEP_RESOURCE_CONFIG"] = ""
        path.unlink()
        self.assertFalse(discover(self.repo, "ZephyrSentinel")["resources"])

    def test_private_sources_explicit_and_logically_referenced(self):
        folder = self.base / "private-knowledge"
        folder.mkdir(); (folder / "method.md").write_text("# ZephyrSentinel private method\n", encoding="utf-8")
        self.local([{"id": "personal", "kind": "knowledge", "path": str(folder), "enabled": True,
                     "writable": False, "visibility": "private"}])
        result = discover(self.repo, "ZephyrSentinel")
        item = result["resources"][0]
        self.assertEqual(item["resource_source"]["visibility"], "private")
        self.assertNotIn(str(folder), json.dumps(result))
        self.assertIn("ZephyrSentinel", M.read_resource(self.repo, item["read_reference"])["text"])
        self.assertEqual(knowledge_path(self.repo, item["path"]), str(folder / "method.md"))

    def test_external_skill_is_readable_not_installed_or_executed(self):
        folder = self.base / "personal-skills";folder.mkdir()
        (folder / "SKILL.md").write_text("# ZephyrSentinel skill\n", encoding="utf-8")
        self.local([{"id": "personal", "kind": "skill", "path": str(folder), "enabled": True,
                     "writable": False, "visibility": "private"}])
        result = discover(self.repo, "ZephyrSentinel")
        self.assertEqual(result["resources"][0]["kind"], "external_skill")
        self.assertFalse(result["execution_performed"])
        self.assertIn("ZephyrSentinel", M.read_resource(self.repo, result["resources"][0]["read_reference"])["text"])

    def test_bad_explicit_config_is_not_silently_accepted(self):
        os.environ["SEEP_RESOURCE_CONFIG"] = str(self.base / "missing.json")
        self.assertEqual(discover(self.repo, "anything")["status"], "partial")
        with self.assertRaises(SourceError): Sources(self.repo)

    def test_source_disable_and_private_root_move(self):
        folder = self.base / "first";folder.mkdir()
        (folder / "x.md").write_text("# ZephyrSentinel\n", encoding="utf-8")
        row = {"id": "personal", "kind": "knowledge", "path": str(folder), "enabled": True,
               "writable": False, "visibility": "private"}
        self.local([row]); before = Sources(self.repo).revision
        moved = self.base / "second";folder.rename(moved);row["path"] = str(moved)
        self.local([row]);self.assertNotEqual(before, Sources(self.repo).revision)
        self.assertTrue(discover(self.repo, "ZephyrSentinel")["resources"])
        row["enabled"] = False;self.local([row])
        self.assertFalse(discover(self.repo, "ZephyrSentinel")["resources"])
        with self.assertRaises(SourceError): M.read_resource(self.repo, "knowledge:personal/x.md")

    def test_link_escape_and_readonly_write_are_rejected(self):
        request = self.request(source_id="builtin-kb")
        with self.assertRaises(SourceError): M.prepare(self.repo, request)
        outside = self.base / "outside.md";outside.write_text("# ZephyrSentinel\n", encoding="utf-8")
        try: (self.repo / "Tool/mcp/kb_local/link.md").symlink_to(outside)
        except OSError: self.skipTest("symlinks unavailable")
        with self.assertRaises(SourceError): M.read_resource(self.repo, "knowledge:local-kb/link.md")
        self.assertFalse(discover(self.repo, "ZephyrSentinel")["resources"])

    def test_create_is_discoverable_and_readback_matches(self):
        result = self.create()
        self.assertTrue(result["readback_verified"] and result["query_verified"])
        self.assertFalse(result["automatic_publication"])
        item = next(r for r in discover(self.repo, "VMP investigation")["resources"] if r["kind"] == "kb_article")
        self.assertEqual(item["read_reference"], result["resource_id"])
        self.assertEqual(M.read_resource(self.repo, result["resource_id"])["sha256"], result["sha256"])

    def test_same_body_and_scope_noop_without_new_file(self):
        self.create();request = self.request(path="other.md")
        request["metadata"]["id"] = "another-id"
        plan = self.plan(request)
        self.assertEqual(plan["action"], "noop")
        self.assertFalse(M.apply(self.repo, plan)["changed"])
        self.assertFalse((self.repo / "Tool/mcp/kb_local/other.md").exists())

    def test_unchanged_update_is_noop(self):
        self.create();request = self.request(expected_sha256=M.digest(self.target().read_bytes()))
        self.assertEqual(M.prepare(self.repo, request)["action"], "noop")

    def test_related_content_requires_read_and_compare(self):
        self.create();request = self.request(path="new-version.md")
        request["metadata"]["id"] = "new-version";request["metadata"]["applies_to"] = "A different version"
        request["body"] += "A version-specific counterexample.\n"
        self.assertEqual(M.prepare(self.repo, request)["action"], "review_required")
        self.assertEqual(self.plan(request)["action"], "create")

    def test_update_preserves_stable_id_and_can_restore(self):
        self.create();before = self.target().read_bytes()
        request = self.request(expected_sha256=M.digest(before));request["body"] += "Known unsupported version.\n"
        result = self.create(request)
        self.assertNotEqual(before, self.target().read_bytes())
        self.assertTrue(M.restore(self.repo, result["backup_receipt"], backups=self.backups)["restored"])
        self.assertEqual(before, self.target().read_bytes())

    def test_restore_wont_overwrite_later_edit(self):
        result = self.create();self.target().write_text("Later user's edit\n", encoding="utf-8")
        with self.assertRaisesRegex(SourceError, "later_change"):
            M.restore(self.repo, result["backup_receipt"], backups=self.backups)
        self.assertEqual(self.target().read_text(encoding="utf-8"), "Later user's edit\n")

    def test_stale_target_plan_and_corpus_are_rejected(self):
        first = self.plan(self.request());second = copy.deepcopy(first)
        M.apply(self.repo, first, backups=self.backups)
        with self.assertRaises(SourceError): M.apply(self.repo, second, backups=self.backups)
        request = self.request(path="other.md");request["metadata"]["id"] = "other"
        request["body"] += "Alternative.\n"
        planned = self.plan(request)
        self.write("Tool/mcp/kb_local/new.md", "# Unrelated later material\n")
        with self.assertRaises(SourceError): M.apply(self.repo, planned, backups=self.backups)
        self.assertFalse((self.repo / "Tool/mcp/kb_local/other.md").exists())

    def test_stale_source_configuration_is_rejected(self):
        planned = self.plan(self.request());self.local(disabled=["tool_software:unused"])
        with self.assertRaises(SourceError): M.apply(self.repo, planned, backups=self.backups)

    def test_bad_query_rolls_back_and_keeps_backup(self):
        planned = self.plan(self.request(queries=["ImpossibleSentinelUnmatched"]))
        with self.assertRaisesRegex(SourceError, "query_verification"):
            M.apply(self.repo, planned, backups=self.backups)
        self.assertFalse(self.target().exists())
        self.assertFalse((self.repo / "Tool/mcp/kb_local/.project-transaction.json").exists())
        self.assertTrue(list(self.backups.glob("*.json")))

    def test_pattern_detected_secrets_rejected_in_body_metadata_and_reason(self):
        secret = "Bearer " + "Q7vN2kP9rT4xC8mA6dF3hJ5sL0wZ1bY2"
        for field in ("body", "reason", "summary"):
            request = self.request()
            if field == "summary": request["metadata"][field] = secret
            else: request[field] = secret
            with self.subTest(field=field), self.assertRaises(SourceError): M.prepare(self.repo, request)
        self.assertFalse(self.target().exists())

    def test_project_evidence_required_and_bound(self):
        request = self.request();request["metadata"]["maturity"] = "case"
        with self.assertRaises(SourceError): M.prepare(self.repo, request)
        project = self.base / "project";project.mkdir();evidence = project / "result.txt"
        evidence.write_text("Synthetic verified output\n", encoding="utf-8")
        request["project"] = str(project)
        request["evidence"] = [{"id": "evidence-one", "path": "result.txt", "sha256": M.digest(evidence.read_bytes())}]
        planned = self.plan(request);evidence.write_text("Changed\n", encoding="utf-8")
        with self.assertRaises(SourceError): M.apply(self.repo, planned, backups=self.backups)

    def test_method_requires_counterexample_not_only_tool_success(self):
        request = self.request();request["metadata"]["maturity"] = "method"
        project = self.base / "project";project.mkdir();p = project / "output.txt";p.write_text("test output\n")
        request.update(project=str(project), evidence=[{"id": "test", "path": "output.txt", "sha256": M.digest(p.read_bytes())}])
        with self.assertRaises(SourceError): M.prepare(self.repo, request)
        request["metadata"]["counterexamples"] = "Other platforms are not verified"
        plan = self.plan(request)
        self.assertFalse(plan["semantic_equivalence_verified"])
        self.assertNotIn(str(project), json.dumps(M.metadata(plan["content"])))

    def test_retired_not_default_discovery_but_explicit_read_survives(self):
        self.create();request = self.request(expected_sha256=M.digest(self.target().read_bytes()))
        request["metadata"]["maturity"] = "retired"
        self.create(request)
        self.assertFalse(discover(self.repo, "VMP investigation")["resources"])
        self.assertEqual(knowledge_entries(self.repo), [])
        self.assertIn('"retired"', M.read_resource(self.repo, "knowledge:local-kb/softseep/unpacking/vmp.md")["text"])

    def test_budget_boundary_is_checked_without_changing_policy(self):
        planned = self.plan(self.request())
        with patch.object(M, "_budget", return_value=(1180, 1180)):
            with self.assertRaisesRegex(SourceError, "budget_exceeded"):
                M.apply(self.repo, planned, backups=self.backups)
        self.assertFalse(self.target().exists())

    def test_backup_cannot_be_created_in_repository(self):
        with self.assertRaises(SourceError):
            M.apply(self.repo, self.plan(self.request()), backups=self.repo / "private-backups")
        self.assertFalse((self.repo / "private-backups").exists())

    def test_traversal_and_hidden_write_rejected(self):
        for path in ("../escape.md", "/absolute.md", "x\\escape.md", ".hidden.md", "x.py", "AGENTS.md", "sub/SKILL.md"):
            with self.subTest(path=path), self.assertRaises(SourceError): M.prepare(self.repo, self.request(path=path))

    def test_existing_stable_id_cannot_be_silently_changed(self):
        self.create();request = self.request(expected_sha256=M.digest(self.target().read_bytes()))
        request["metadata"]["id"] = "different-id"
        with self.assertRaises(SourceError): M.prepare(self.repo, request)

    def test_real_cli_prepares_applies_and_reads(self):
        request = self.base / "request.json";request.write_text(json.dumps(self.request()), encoding="utf-8")
        args = [sys.executable, "-B", str(ROOT / "Tool/scripts/resource-maintain.py"), "--root", str(self.repo)]
        planned = subprocess.run(args + ["plan", "--request", str(request)], capture_output=True, text=True, encoding="utf-8", timeout=20)
        self.assertEqual(planned.returncode, 0, planned.stdout + planned.stderr)
        plan = self.base / "plan.json";plan.write_text(planned.stdout, encoding="utf-8")
        applied = subprocess.run(args + ["apply", "--plan", str(plan), "--backups", str(self.backups)], capture_output=True, text=True, encoding="utf-8", timeout=20)
        self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        result = json.loads(applied.stdout)
        read = subprocess.run(args + ["read", "--resource", result["resource_id"]], capture_output=True, text=True, encoding="utf-8", timeout=20)
        self.assertEqual(json.loads(read.stdout)["sha256"], result["sha256"])

    def test_existing_mcp_search_and_read_use_new_knowledge(self):
        self.create()
        spec = importlib.util.spec_from_file_location("evolution_mcp", ROOT / "Tool/mcp/seep_mcp_server.py")
        server = importlib.util.module_from_spec(spec);spec.loader.exec_module(server)
        with patch.object(server, "KB_DIR", str(self.repo / "Tool/mcp/Tool/reverselab/kb")), \
             patch.object(server, "KB_LOCAL_DIR", str(self.repo / "Tool/mcp/kb_local")):
            search = json.loads(server.seep_kb_search("VMP investigation"))
            self.assertTrue(any(row["path"] == "kb_local/softseep/unpacking/vmp.md" for row in search), search)
            read = server.seep_kb_read("kb_local/softseep/unpacking/vmp.md", max_chars=12000)
            self.assertEqual(read, self.target().read_text(encoding="utf-8"))

    def test_two_cli_writers_do_not_overwrite_each_other(self):
        plan = self.base / "plan.json";plan.write_text(json.dumps(self.plan(self.request())), encoding="utf-8")
        args = [sys.executable, "-B", str(ROOT / "Tool/scripts/resource-maintain.py"), "--root", str(self.repo),
                "apply", "--plan", str(plan), "--backups", str(self.backups)]
        processes = [subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        results = [p.communicate(timeout=30) for p in processes]
        self.assertEqual(sorted(p.returncode for p in processes), [0, 2], results)
        self.assertEqual(len(list(self.backups.glob("*.json"))), 1)
        self.assertIn("VMP investigation", self.target().read_text(encoding="utf-8"))

    def test_shared_source_cannot_relabel_itself_private_to_avoid_budget(self):
        rows = copy.deepcopy(DEFAULTS);rows[-1]["visibility"] = "private"
        self.write("Tool/config/resource-sources.json", {"schema": "seep.resource-sources/1", "sources": rows})
        with self.assertRaises(SourceError): Sources(self.repo)

    def test_private_writable_source_stays_private(self):
        folder = self.base / "private-kb"
        self.local([{"id": "personal", "kind": "knowledge", "path": str(folder), "enabled": True,
                     "writable": True, "visibility": "private"}])
        result = self.create(self.request(source_id="personal"))
        self.assertEqual(result["visibility"], "private")
        self.assertFalse(self.target().exists())
        self.assertTrue((folder / "softseep/unpacking/vmp.md").exists())

    def test_huge_source_is_partial_not_empty_success(self):
        self.write("Tool/mcp/kb_local/large.md", "A" * (256 * 1024 + 1))
        self.assertEqual(discover(self.repo, "unmatched")["status"], "partial")

    def test_duplicate_json_keys_and_invalid_shapes_rejected(self):
        path = self.local()
        path.write_text('{"schema":"seep.resource-sources/1","sources":[],"sources":[]}', encoding="utf-8")
        with self.assertRaises(SourceError): Sources(self.repo)
        for field, value in (("kind", []), ("id", []), ("visibility", {})):
            row = {"id": "personal", "kind": "knowledge", "path": str(self.base / "notes"),
                   "enabled": True, "writable": False, "visibility": "private"}
            row[field] = value;self.local([row])
            with self.subTest(field=field), self.assertRaises(SourceError): Sources(self.repo)

    def test_noop_needs_no_extra_agent_confirmation(self):
        result = self.create()
        original = self.target().read_bytes()
        request = self.request(expected_sha256=result["sha256"])
        plan = M.prepare(self.repo, request)
        self.assertEqual(M.apply(self.repo, plan), {"ok": True, "changed": False, "action": "noop"})
        self.assertEqual(original, self.target().read_bytes())

    def test_true_stdio_mcp_discovery_search_and_read_after_authoring(self):
        self.create()
        path = self.local([{"id": "builtin-kb", "enabled": False}, {"id": "local-kb", "enabled": False},
                           {"id": "learned", "kind": "knowledge", "path": str(self.repo / "Tool/mcp/kb_local"),
                            "enabled": True, "writable": False, "visibility": "private"}])
        code = r'''
import asyncio,json,os,sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
async def run():
    params=StdioServerParameters(command=sys.executable,args=[sys.argv[1]],env=dict(os.environ))
    async with stdio_client(params) as (read,write):
        async with ClientSession(read,write) as client:
            await client.initialize()
            async def call(name,args):
                result=await client.call_tool(name,args)
                assert not result.isError,result
                return next(v.text for v in result.content if v.type=='text')
            found=json.loads(await call('seep_capability_discover',{'query':'VMP investigation','limit':20}))
            item=next(v for v in found['resources'] if v.get('resource_source',{}).get('id')=='learned')
            hits=json.loads(await call('seep_kb_search',{'query':'VMP investigation'}))
            assert any(v['path']==item['path'] for v in hits),hits
            text=await call('seep_kb_read',{'article_path':item['path'],'max_chars':12000})
            assert 'Compare the exact version' in text,text
            print(json.dumps({'tools':len((await client.list_tools()).tools),'read':True,'reference':item['path']}))
asyncio.run(run())
'''
        home = self.base / "home";home.mkdir()
        env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), APPDATA=str(home), LOCALAPPDATA=str(home),
                   XDG_CONFIG_HOME=str(home), PYTHONIOENCODING="utf-8", SEEP_RESOURCE_CONFIG=str(path),
                   SEEP_WORKSPACE=str(home), SEEP_AUTOCASE="0", SEEP_AGENT_MCP=str(home / "mcp.json"))
        result = subprocess.run([sys.executable, "-B", "-c", code, str(ROOT / "Tool/mcp/seep_mcp_server.py")],
                                env=env, cwd=home, capture_output=True, text=True, encoding="utf-8", timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["tools"], 23)

    def interrupted_apply(self):
        plan = self.base / "crash-plan.json";plan.write_text(json.dumps(self.plan(self.request())), encoding="utf-8")
        code = r'''
import json,os,pathlib,sys
sys.path.insert(0,sys.argv[1]);from lib import resource_maintenance as M
old=M._replace
def crash(path,data):
    old(path,data)
    if pathlib.Path(path).name=='vmp.md':os._exit(71)
M._replace=crash
M.apply(pathlib.Path(sys.argv[2]),json.loads(pathlib.Path(sys.argv[3]).read_text(encoding='utf-8')),backups=sys.argv[4])
'''
        result = subprocess.run([sys.executable, "-B", "-c", code, str(ROOT / "Tool/scripts"), str(self.repo),
                                 str(plan), str(self.backups)], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 71, result.stdout + result.stderr)
        self.assertTrue((self.repo / "Tool/mcp/kb_local/.project-transaction.json").exists())
        return M.backups_view(self.repo, backups=self.backups)["backups"][-1]["receipt"]

    def test_real_process_interruption_recovers_only_owned_write(self):
        receipt = self.interrupted_apply()
        self.assertTrue(self.target().exists())
        self.assertTrue(M.recover(self.repo, receipt, backups=self.backups)["recovered"])
        self.assertFalse(self.target().exists())
        self.assertFalse((self.repo / "Tool/mcp/kb_local/.project-transaction.json").exists())
        self.assertTrue(self.create()["ok"])

    def test_interrupted_recovery_refuses_later_user_change(self):
        receipt = self.interrupted_apply()
        self.target().write_text("A later user edit must survive\n", encoding="utf-8")
        with self.assertRaisesRegex(SourceError, "later_change"):
            M.recover(self.repo, receipt, backups=self.backups)
        self.assertEqual(self.target().read_text(encoding="utf-8"), "A later user edit must survive\n")

    def test_short_chinese_topic_retrieval_is_not_silently_lost(self):
        request = self.request(queries=["脱壳"])
        request["metadata"].update(title="Windows脱壳记录", tags=["脱壳"])
        self.assertTrue(self.create(request)["query_verified"])
        self.assertTrue(discover(self.repo, "脱壳")["resources"])

    def server(self):
        spec = importlib.util.spec_from_file_location("resource_review_mcp", ROOT / "Tool/mcp/seep_mcp_server.py")
        module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_mcp_cannot_read_hidden_nonmarkdown_or_oversized_side_files(self):
        folder = self.base / "private-notes";folder.mkdir()
        for name in (".env", "auth.json", ".hidden.md"):
            (folder / name).write_text("SYNTHETIC_PRIVATE_SENTINEL", encoding="utf-8")
        (folder / "huge.md").write_text("OVERSIZE_SENTINEL" + "汉" * 100000, encoding="utf-8")
        self.local([{"id": "personal", "kind": "knowledge", "path": str(folder), "enabled": True,
                     "writable": False, "visibility": "private"}])
        server = self.server()
        for name in (".env", "auth.json", ".hidden.md", "huge.md"):
            with self.subTest(name=name):
                result = server.seep_kb_read("sources/personal/" + name, max_chars=200000)
                self.assertNotIn("SYNTHETIC_PRIVATE_SENTINEL", result)
                self.assertNotIn("OVERSIZE_SENTINEL", result)
                with self.assertRaises(SourceError): M.read_resource(self.repo, "knowledge:personal/" + name)

    @unittest.skipUnless(os.name == "nt", "Windows path identity")
    def test_disabled_file_case_alias_rejected_by_cli_mcp_and_write_plan(self):
        folder = self.base / "private-notes";folder.mkdir()
        path = folder / "note.md";path.write_text("# Private note\nSYNTHETIC_DISABLED_SENTINEL\n", encoding="utf-8")
        self.local([{"id": "personal", "kind": "knowledge", "path": str(folder), "enabled": True,
                     "writable": True, "visibility": "private"}], disabled=["knowledge:personal/note.md"])
        with self.assertRaises(SourceError): M.read_resource(self.repo, "knowledge:personal/NOTE.md")
        self.assertNotIn("SYNTHETIC_DISABLED_SENTINEL", self.server().seep_kb_read("sources/personal/NOTE.md"))
        with self.assertRaises(SourceError):
            M.prepare(self.repo, self.request(source_id="personal", path="NOTE.md", expected_sha256=M.digest(path.read_bytes())))

    def test_disabled_tool_blocks_default_ensure_before_installer_dispatch(self):
        import types
        self.local(disabled=["tool_software:sentinel"])
        calls = []
        stub = types.SimpleNamespace(discover=lambda *a, **k: {"available": False},
                                     install_plan=lambda *a, **k: {"has_plan": True, "auto_allowed": True},
                                     propose_install=lambda *a, **k: calls.append((a, k)) or {"executed": False})
        server = self.server()
        with patch.object(server, "_autodiscover", return_value=stub):
            result = json.loads(server.seep_ensure_tool("sentinel"))
        self.assertEqual(calls, [], result)
        self.assertFalse(result.get("available"))
        self.assertIn("disabled", result.get("status", ""))

    def test_disabled_tool_blocks_install_plan_execute_register_and_acquire(self):
        self.local(disabled=["tool_software:sentinel"])
        spec = importlib.util.spec_from_file_location("resource_review_discoverer", ROOT / "Tool/mcp/tool_autodiscover.py")
        module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with patch.object(module, "_install_table", side_effect=AssertionError("disabled tool reached install catalog")), \
             patch.object(module, "_mcp_entry_for", side_effect=AssertionError("disabled tool reached MCP registration")):
            self.assertEqual(module.install_plan("sentinel")["status"], "disabled")
            self.assertEqual(module.propose_install("sentinel", execute=True)["status"], "disabled")
            self.assertEqual(module.register_mcp("sentinel", apply=True)["status"], "disabled")
        spec = importlib.util.spec_from_file_location("resource_review_acquire", ROOT / "Tool/scripts/tool-acquire.py")
        acquire = importlib.util.module_from_spec(spec);spec.loader.exec_module(acquire)
        with patch.object(acquire, "l0", side_effect=AssertionError("disabled tool reached probe/start")):
            self.assertEqual(acquire.acquire("sentinel", True, True)["verdict"], "DISABLED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
