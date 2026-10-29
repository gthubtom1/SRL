"""Ownership-aware preflight tests for installer-preserved user assets."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
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
