"""Ownership-aware preflight tests for installer-preserved user assets."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("preflight_ownership_under_test", HERE / "preflight.py")
assert SPEC and SPEC.loader
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def agent_text(body: str) -> str:
    return (
        "---\n"
        f"name: {body}\n"
        f"description: {body} fixture\n"
        "tools: read\n"
        f'systemPrompt: "{body} system prompt"\n'
        "---\n"
        f"{body}\n"
    )


class PreflightOwnershipTests(unittest.TestCase):
    def _paths(self, td: str):
        base = Path(td)
        source = base / "source"
        tool = source / "Tool"
        agent = base / "agent"
        for path in (
            tool / "prompts/tasks",
            tool / "prompts/agents",
            tool / "prompts/extensions",
            tool / "skill",
            agent / "prompts",
            agent / "agents",
            agent / "extensions",
            agent / "skills",
        ):
            path.mkdir(parents=True, exist_ok=True)
        return source, tool, agent

    def _manifest(self, source: Path, agent: Path, managed: dict[str, str] | None = None):
        payload = {
            "schema": "seep-agent-install/1",
            "runtime_id": "seep-reverse-lab/softseep",
            "source_root": str(source.resolve()),
            "status": "complete",
            "managed_files": managed or {},
        }
        write(agent / "seep-install-manifest.json", json.dumps(payload, indent=2) + "\n")

    def _patch(self, source: Path, tool: Path, agent: Path):
        return (
            patch.object(preflight, "ROOT", str(source)),
            patch.object(preflight, "TOOL", str(tool)),
            patch.object(preflight, "agent_root_path", return_value=agent),
        )

    def _canonical(self, source: Path, agent: Path):
        assets = {
            "Tool/prompts/AGENTS.md": "# AGENTS\n\nSource prompt\n",
            "Tool/prompts/SEEP.md": "# SEEP\n\nSource layers\n",
            "Tool/prompts/tasks/managed.md": "# Managed task\n\nSource task\n",
            "Tool/prompts/agents/managed.md": agent_text("managed-agent"),
            "Tool/prompts/extensions/guard.ts": "export const guard = true;\n",
            "Tool/skill/managed/SKILL.md": (
                "---\nname: managed\ndescription: Managed source skill fixture for ownership testing.\n---\n"
            ),
            "Tool/skill/managed/scripts/run.py": "print('managed')\n",
        }
        deployed = {
            "prompts/managed.md": "prompts/tasks/managed.md",
            "agents/managed.md": "prompts/agents/managed.md",
            "extensions/guard.ts": "prompts/extensions/guard.ts",
            "skills/managed/SKILL.md": "skill/managed/SKILL.md",
            "skills/managed/scripts/run.py": "skill/managed/scripts/run.py",
        }
        for rel, text in assets.items():
            write(source / rel, text)
        write(agent / "AGENTS.md", assets["Tool/prompts/AGENTS.md"])
        write(agent / "SEEP.md", assets["Tool/prompts/SEEP.md"])
        managed = {}
        for rel, source_rel in deployed.items():
            dest = write(agent / rel, assets["Tool/" + source_rel])
            managed[rel] = sha(dest)
        self._manifest(source, agent, managed)
        return managed

    def _package(self, source, agent, managed):
        """Copy the frozen producer and real package into this source fixture."""
        repository = HERE.parents[1]
        setup = source / 'setup'
        setup.mkdir(exist_ok=True)
        for name in ('merge_agent_config.py', 'pi-persona-rewind.package.json'):
            shutil.copy2(repository / 'setup' / name, setup / name)
        package = source / 'Tool/prompts/packages/pi-seep-ext'
        shutil.copytree(repository / 'Tool/prompts/packages/pi-seep-ext', package,
                        ignore=shutil.ignore_patterns('__pycache__'))
        deployed = agent / 'packages/pi-seep-ext'
        shutil.copytree(package, deployed)
        managed = dict(managed)
        for path in deployed.rglob('*'):
            if path.is_file():
                managed[path.relative_to(agent).as_posix()] = sha(path)
        self._manifest(source, agent, managed)
        return managed

    def _ownership_results(self, source, tool, agent):
        p1, p2, p3 = self._patch(source, tool, agent)
        results = []
        with p1, p2, p3:
            for checker in (preflight.check_deploy_bidirectional,
                            preflight.check_prompt_residue, preflight.check_agents_deploy):
                preflight.results.clear()
                checker()
                results.extend(preflight.results)
        return results

    def test_package_records_pass_all_three_ownership_consumers(self):
        with tempfile.TemporaryDirectory(prefix='seep-preflight-package-') as td:
            source, tool, agent = self._paths(td)
            managed = self._package(source, agent, self._canonical(source, agent))
            self.assertIn('packages/pi-seep-ext/LICENSE', managed)
            results = self._ownership_results(source, tool, agent)
            self.assertEqual(len(results), 3)
            self.assertTrue(all(row['ok'] and row.get('level') != 'WARN' for row in results), results)

    def test_package_bytes_and_source_must_both_match_recorded_hash(self):
        with tempfile.TemporaryDirectory(prefix='seep-preflight-package-hash-') as td:
            source, tool, agent = self._paths(td)
            managed = self._package(source, agent, self._canonical(source, agent))
            rel = 'packages/pi-seep-ext/LICENSE'
            deployed = agent / rel
            original = deployed.read_bytes()
            src = source / 'Tool/prompts/packages/pi-seep-ext/LICENSE'
            for kind in ('deployed-edit', 'forged-record', 'source-drift', 'missing-deployed'):
                with self.subTest(kind=kind):
                    entries = dict(managed)
                    deployed.write_bytes(original)
                    src.write_bytes(original)
                    if kind == 'source-drift':
                        src.write_bytes(original + b'\nnew source')
                    elif kind == 'missing-deployed':
                        deployed.unlink()
                    else:
                        deployed.write_bytes(original + b'\nuser edit')
                        if kind == 'forged-record':
                            entries[rel] = sha(deployed)
                    self._manifest(source, agent, entries)
                    before = {p.relative_to(agent).as_posix(): sha(p)
                              for p in agent.rglob('*') if p.is_file()}
                    results = self._ownership_results(source, tool, agent)
                    self.assertEqual(len(results), 3)
                    self.assertTrue(all(not row['ok'] and 'package ownership' in row['detail']
                                        for row in results), results)
                    if kind in ('forged-record', 'source-drift'):
                        self.assertTrue(all('source hash mismatch' in row['detail'] for row in results), results)
                    self.assertEqual(before, {p.relative_to(agent).as_posix(): sha(p)
                                              for p in agent.rglob('*') if p.is_file()})

    def test_package_escapes_other_packages_and_unmanaged_files_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix='seep-preflight-package-path-') as td:
            source, tool, agent = self._paths(td)
            managed = self._package(source, agent, self._canonical(source, agent))
            for rel in ('packages/other/LICENSE', 'packages/pi-seep-ext-other/LICENSE',
                        'packages/pi-seep-ext/../../outside.ts',
                        'packages/pi-seep-ext//LICENSE', 'packages/pi-seep-ext/./LICENSE',
                        'packages/pi-seep-ext/LICENSE:stream',
                        'packages/pi-seep-ext/USER-NOTES.md',
                        'packages/pi-seep-ext/extensions/remote.ts'):
                with self.subTest(path=rel):
                    self._manifest(source, agent, dict(managed, **{rel: '0' * 64}))
                    results = self._ownership_results(source, tool, agent)
                    self.assertEqual(len(results), 3)
                    self.assertTrue(all(not row['ok'] for row in results), results)

    def test_package_target_junction_does_not_borrow_outside_bytes(self):
        if os.name != 'nt':
            self.skipTest('Windows junction check')
        with tempfile.TemporaryDirectory(prefix='seep-preflight-package-link-') as td:
            source, tool, agent = self._paths(td)
            self._package(source, agent, self._canonical(source, agent))
            directory = agent / 'packages/pi-seep-ext/lib'
            outside = Path(td) / 'outside'
            shutil.move(str(directory), str(outside))
            linked = subprocess.run(['cmd', '/d', '/c', 'mklink', '/J', str(directory), str(outside)],
                                    capture_output=True, timeout=10)
            self.assertEqual(linked.returncode, 0, linked.stdout + linked.stderr)
            before = {p.name: sha(p) for p in outside.iterdir() if p.is_file()}
            try:
                results = self._ownership_results(source, tool, agent)
                self.assertTrue(all(not row['ok'] and 'linked deployment path' in row['detail']
                                    for row in results), results)
                self.assertEqual(before, {p.name: sha(p) for p in outside.iterdir() if p.is_file()})
            finally:
                directory.rmdir()

    def test_valid_package_does_not_claim_same_name_user_agent(self):
        with tempfile.TemporaryDirectory(prefix='seep-preflight-package-user-') as td:
            source, tool, agent = self._paths(td)
            managed = self._package(source, agent, self._canonical(source, agent))
            managed.pop('agents/managed.md')
            custom = write(agent / 'agents/managed.md', agent_text('user override'))
            self._manifest(source, agent, managed)
            before = sha(custom)
            results = self._ownership_results(source, tool, agent)
            self.assertTrue(all(row['ok'] for row in results), results)
            agents = results[-1]
            self.assertEqual(agents.get('level'), 'WARN', agents)
            self.assertIn('同名覆盖未验证', agents['detail'])
            self.assertEqual(sha(custom), before)

    def test_unknown_user_assets_are_preserved_and_reported_not_failed(self):
        with tempfile.TemporaryDirectory(prefix="seep-preflight-own-user-") as td:
            source, tool, agent = self._paths(td)
            self._canonical(source, agent)
            custom = {
                agent / "prompts/user-task.md": "# User task\n\nKEEP_TASK\n",
                agent / "agents/user-agent.md": agent_text("user-agent") + "KEEP_AGENT\n",
                agent / "skills/user-skill/SKILL.md": (
                    "---\nname: user-skill\ndescription: User-owned preserved skill fixture.\n---\nKEEP_SKILL\n"
                ),
            }
            for path, text in custom.items():
                write(path, text)
            p1, p2, p3 = self._patch(source, tool, agent)
            with p1, p2, p3:
                preflight.results.clear()
                preflight.check_prompt_residue()
                prompt = preflight.results[-1]
                preflight.results.clear()
                preflight.check_deploy_bidirectional()
                deploy = preflight.results[-1]
                preflight.results.clear()
                preflight.check_agents_deploy()
                agents = preflight.results[-1]
                preflight.results.clear()
                preflight.check_dropin_skills()
                dropin = preflight.results[-1]

            self.assertTrue(prompt["ok"], prompt)
            self.assertEqual(prompt.get("level"), "WARN", prompt)
            self.assertIn("用户自有", prompt["detail"])
            self.assertTrue(deploy["ok"], deploy)
            self.assertEqual(deploy.get("level"), "WARN", deploy)
            self.assertIn("用户自有", deploy["detail"])
            self.assertTrue(agents["ok"], agents)
            self.assertEqual(agents.get("level"), "WARN", agents)
            self.assertIn("用户自有", agents["detail"])
            self.assertTrue(dropin["ok"], dropin)
            for path in custom:
                self.assertTrue(path.is_file(), path)

    def test_managed_leftovers_still_fail(self):
        with tempfile.TemporaryDirectory(prefix="seep-preflight-own-stale-") as td:
            source, tool, agent = self._paths(td)
            managed = self._canonical(source, agent)
            stale = {
                "prompts/stale.md": agent / "prompts/stale.md",
                "agents/stale.md": agent / "agents/stale.md",
                "extensions/stale.ts": agent / "extensions/stale.ts",
                "skills/stale/SKILL.md": agent / "skills/stale/SKILL.md",
            }
            for rel, path in stale.items():
                write(path, "stale managed asset\n")
                managed[rel] = sha(path)
            self._manifest(source, agent, managed)
            p1, p2, p3 = self._patch(source, tool, agent)
            with p1, p2, p3:
                preflight.results.clear()
                preflight.check_prompt_residue()
                prompt = preflight.results[-1]
                preflight.results.clear()
                preflight.check_deploy_bidirectional()
                deploy = preflight.results[-1]
                preflight.results.clear()
                preflight.check_agents_deploy()
                agents = preflight.results[-1]

            self.assertFalse(prompt["ok"], prompt)
            self.assertIn("受管残留", prompt["detail"])
            self.assertFalse(deploy["ok"], deploy)
            self.assertIn("受管残留", deploy["detail"])
            self.assertFalse(agents["ok"], agents)
            self.assertIn("受管遗留", agents["detail"])

    def test_prompt_residue_requires_current_owned_bytes(self):
        """同一退役卡只在本项目 manifest 登记且哈希仍匹配时 FAIL。"""
        with tempfile.TemporaryDirectory(prefix="seep-preflight-own-prompt-") as td:
            source, tool, agent = self._paths(td)
            managed = self._canonical(source, agent)
            rel = "prompts/zz-mutation.md"
            card = write(agent / rel, "---\ndescription: x\n---\n")
            installed_hash = sha(card)
            self.assertFalse((tool / "prompts/tasks/zz-mutation.md").exists())
            p1, p2, p3 = self._patch(source, tool, agent)
            with p1, p2, p3:
                for label in ("managed", "unmanaged", "user-edited"):
                    with self.subTest(label=label):
                        entries = dict(managed)
                        if label != "unmanaged":
                            entries[rel] = installed_hash
                        if label == "user-edited":
                            write(card, "User edited prompt: preserve these bytes.\n")
                        self._manifest(source, agent, entries)
                        manifest_path = agent / "seep-install-manifest.json"
                        before = {path: sha(path) for path in (card, manifest_path)}
                        loaded = preflight._load_install_ownership(str(agent))
                        self.assertEqual(
                            preflight._managed_file_current(str(agent), loaded, rel),
                            label == "managed",
                        )
                        for checker in (preflight.check_prompt_residue,
                                        preflight.check_deploy_bidirectional):
                            preflight.results.clear()
                            checker()
                            result = preflight.results[-1]
                            self.assertEqual(result["ok"], label != "managed", result)
                            self.assertIn("zz-mutation", result["detail"])
                            if label == "managed":
                                self.assertIn("受管残留", result["detail"])
                                self.assertIsNone(result.get("level"), result)
                            else:
                                self.assertEqual(result.get("level"), "WARN", result)
                                self.assertIn("用户自有", result["detail"])
                            self.assertEqual(before, {path: sha(path) for path in before},
                                             "核验不应删除或改写提示词及所有权记录")

    def test_managed_drift_and_missing_source_assets_fail(self):
        with tempfile.TemporaryDirectory(prefix="seep-preflight-own-drift-") as td:
            source, tool, agent = self._paths(td)
            write(source / "Tool/prompts/tasks/managed.md", "new task\n")
            write(source / "Tool/prompts/tasks/missing.md", "missing task\n")
            write(source / "Tool/prompts/agents/managed.md", agent_text("managed-new"))
            write(source / "Tool/prompts/agents/missing.md", agent_text("missing-agent"))
            write(
                source / "Tool/skill/managed/SKILL.md",
                "---\nname: managed\ndescription: Managed skill new source content.\n---\n",
            )
            dest_task = write(agent / "prompts/managed.md", "old task\n")
            dest_agent = write(agent / "agents/managed.md", agent_text("managed-old"))
            dest_skill = write(
                agent / "skills/managed/SKILL.md",
                "---\nname: managed\ndescription: Managed skill old deployment content.\n---\n",
            )
            managed = {
                "prompts/managed.md": sha(dest_task),
                "agents/managed.md": sha(dest_agent),
                "skills/managed/SKILL.md": sha(dest_skill),
            }
            self._manifest(source, agent, managed)
            p1, p2, p3 = self._patch(source, tool, agent)
            with p1, p2, p3:
                preflight.results.clear()
                preflight.check_deploy_bidirectional()
                deploy = preflight.results[-1]
                preflight.results.clear()
                preflight.check_agents_deploy()
                agents = preflight.results[-1]

            self.assertFalse(deploy["ok"], deploy)
            self.assertIn("未部署", deploy["detail"])
            self.assertIn("不一致", deploy["detail"])
            self.assertFalse(agents["ok"], agents)
            self.assertIn("未部署", agents["detail"])
            self.assertIn("哈希不一致", agents["detail"])

    def test_same_name_user_override_is_explicitly_unverified(self):
        with tempfile.TemporaryDirectory(prefix="seep-preflight-own-override-") as td:
            source, tool, agent = self._paths(td)
            write(source / "Tool/prompts/tasks/managed.md", "source task\n")
            write(source / "Tool/prompts/agents/managed.md", agent_text("managed"))
            write(agent / "prompts/managed.md", "user task override\n")
            write(agent / "agents/managed.md", agent_text("user-override"))
            self._manifest(source, agent, {})
            p1, p2, p3 = self._patch(source, tool, agent)
            with p1, p2, p3:
                preflight.results.clear()
                preflight.check_prompt_residue()
                residue = preflight.results[-1]
                preflight.results.clear()
                preflight.check_deploy_bidirectional()
                deploy = preflight.results[-1]
                preflight.results.clear()
                preflight.check_agents_deploy()
                agents = preflight.results[-1]

            self.assertTrue(residue["ok"], residue)
            self.assertTrue(deploy["ok"], deploy)
            self.assertEqual(deploy.get("level"), "WARN", deploy)
            self.assertIn("同名覆盖未验证", deploy["detail"])
            self.assertNotIn("哈希一致", deploy["detail"])
            self.assertTrue(agents["ok"], agents)
            self.assertEqual(agents.get("level"), "WARN", agents)
            self.assertIn("同名覆盖未验证", agents["detail"])

    def test_missing_or_invalid_manifest_fails_ownership_checks(self):
        with tempfile.TemporaryDirectory(prefix="seep-preflight-own-manifest-") as td:
            source, tool, agent = self._paths(td)
            write(source / "Tool/prompts/agents/managed.md", agent_text("managed"))
            write(agent / "agents/managed.md", agent_text("managed"))
            manifest = agent / "seep-install-manifest.json"
            cases = [
                ("missing", None),
                ("malformed", "{not-json"),
                ("schema", {"schema": "wrong", "runtime_id": "seep-reverse-lab/softseep",
                            "status": "complete", "source_root": str(source.resolve()),
                            "managed_files": {}}),
                ("source_root", {"schema": "seep-agent-install/1",
                                 "runtime_id": "seep-reverse-lab/softseep",
                                 "status": "complete", "source_root": str(agent),
                                 "managed_files": {}}),
                ("managed_files", {"schema": "seep-agent-install/1",
                                   "runtime_id": "seep-reverse-lab/softseep",
                                   "status": "complete", "source_root": str(source.resolve()),
                                   "managed_files": []}),
            ]
            p1, p2, p3 = self._patch(source, tool, agent)
            with p1, p2, p3:
                for label, value in cases:
                    with self.subTest(label=label):
                        if manifest.exists():
                            manifest.unlink()
                        if value is not None:
                            write(manifest, value if isinstance(value, str)
                                  else json.dumps(value) + "\n")
                        for checker in (preflight.check_prompt_residue,
                                        preflight.check_deploy_bidirectional,
                                        preflight.check_agents_deploy):
                            preflight.results.clear()
                            checker()
                            self.assertFalse(preflight.results[-1]["ok"], preflight.results[-1])
                            self.assertIn("seep-install-manifest.json",
                                          preflight.results[-1]["detail"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
