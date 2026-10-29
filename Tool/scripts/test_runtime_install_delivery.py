#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Task-local delivery checks for setup runtime registration wiring."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1].parent
POWERSHELL = shutil.which("powershell") or "powershell"
REAL_SETUP = ROOT / "setup"
REAL_RUNTIME = ROOT / "Tool" / "scripts" / "lib" / "runtime_root.py"
REAL_LOCK = ROOT / "Tool" / "scripts" / "lib" / "project_lock.py"
REAL_TRANSACTION = ROOT / "Tool" / "scripts" / "lib" / "project_transaction.py"
REAL_BRIDGE = ROOT / "Tool" / "scripts" / "runtime-root.py"
REAL_MIGRATE = ROOT / "Tool" / "skill" / "softseep" / "scripts" / "version-migrate.py"
REAL_PACK = ROOT / "Tool" / "skill" / "softseep" / "pack.json"
TMP_ROOT = ROOT / "work" / "final-delivery" / "tmp"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_ps(script: Path, *args: str, env=None):
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), *args],
        cwd=str(script.parents[1]),
        env=env if env is not None else os.environ.copy(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=55,
    )


def run_ps_bytes(script: Path, *args: str, env=None):
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), *args],
        cwd=str(script.parents[1]),
        env=env if env is not None else os.environ.copy(),
        capture_output=True,
        timeout=55,
    )


def run_py(*args: str):
    return subprocess.run(
        ["python", "-B", str(REAL_BRIDGE), *args],
        cwd=str(ROOT),
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=55,
    )


def copy_file(source: Path, destination: Path):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def isolated_environment(base: Path) -> dict[str, str]:
    """Return a host-isolated environment rooted under the test workspace."""
    home = base / "host-home"
    temp = base / "host-temp"
    appdata = home / "AppData"
    localappdata = appdata / "Local"
    xdg_config = home / ".config"
    for path in (home, temp, appdata, localappdata, xdg_config):
        path.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update({
        "HOME": str(home),
        "USERPROFILE": str(home),
        "HOMEDRIVE": home.drive,
        "HOMEPATH": str(home)[len(home.drive):],
        "TEMP": str(temp),
        "TMP": str(temp),
        "TMPDIR": str(temp),
        "APPDATA": str(appdata),
        "LOCALAPPDATA": str(localappdata),
        "XDG_CONFIG_HOME": str(xdg_config),
        "PI_CODING_AGENT_DIR": str(base / "ambient-agent"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(home / ".gitconfig"),
    })
    for name in ("PI_AGENT_DIR", "SEEP_REPO_URL", "SEEP_RUNTIME_ROOT"):
        env.pop(name, None)
    return env


def build_workbench(base: Path) -> Path:
    """Make a minimal source runtime with real helper/lock/pack/migrate files."""
    wb = base / "workbench"
    for rel in ("Tool/cases", "Tool/scripts/lib", "Tool/skill/softseep/scripts",
                "Tool/prompts/tasks", "Tool/prompts/agents", "Tool/config"):
        (wb / rel).mkdir(parents=True, exist_ok=True)
    copy_file(REAL_RUNTIME, wb / "Tool/scripts/lib/runtime_root.py")
    copy_file(REAL_LOCK, wb / "Tool/scripts/lib/project_lock.py")
    copy_file(REAL_TRANSACTION, wb / "Tool/scripts/lib/project_transaction.py")
    copy_file(REAL_BRIDGE, wb / "Tool/scripts/runtime-root.py")
    copy_file(REAL_MIGRATE, wb / "Tool/skill/softseep/scripts/version-migrate.py")
    copy_file(REAL_PACK, wb / "Tool/skill/softseep/pack.json")
    (wb / "Tool/skill/softseep/SKILL.md").write_text("# SoftSeep fixture\n", encoding="utf-8")
    copy_file(ROOT / "VERSION", wb / "VERSION")
    for name in ("install-pi.ps1", "install.ps1", "update.ps1", "uninstall.ps1", "merge_agent_config.py"):
        copy_file(REAL_SETUP / name, wb / "setup" / name)
    # Inert fixture-only setup children: no packages, network, or external tools.
    (wb / "setup/generate-configs.ps1").write_text("exit 0\n", encoding="utf-8")
    (wb / "Tool/scripts/check.py").write_text("print('fixture check ok')\n", encoding="utf-8")
    (wb / "Tool/prompts/SEEP.md").write_text("Seep Reverse Lab fixture prompt\n", encoding="utf-8")
    (wb / "Tool/prompts/AGENTS.md").write_text("Seep Reverse Lab fixture agents\n", encoding="utf-8")
    (wb / "Tool/prompts/tasks/fixture.md").write_text("fixture @SEEP_ROOT@\n", encoding="utf-8")
    (wb / "Tool/prompts/agents/fixture-agent.md").write_text("Seep Reverse Lab fixture agent\n", encoding="utf-8")
    (wb / "Tool/config/mcp-servers.json").write_text('{"servers":{}}\n', encoding="utf-8")
    return wb


class RuntimeInstallDeliveryTests(unittest.TestCase):
    def setUp(self):
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="runtime-install-delivery-", dir=TMP_ROOT)
        self.base = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.environment = patch.dict(os.environ, isolated_environment(self.base), clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def install(self, wb: Path, agent: Path):
        return run_ps(wb / "setup/install-pi.ps1", "-AgentRoot", str(agent), "-SkipPackages")

    def test_repeat_install_updates_owned_tasks_and_agents(self):
        wb = build_workbench(self.base)
        agent = self.base / "agent"
        first = self.install(wb, agent)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        task = wb / "Tool/prompts/tasks/fixture.md"
        role = wb / "Tool/prompts/agents/fixture-agent.md"
        task.write_text("UPDATED task @SEEP_ROOT@\n", encoding="utf-8")
        role.write_text("UPDATED role\n", encoding="utf-8")
        second = self.install(wb, agent)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual((agent / "prompts/fixture.md").read_text(encoding="utf-8"),
                         "UPDATED task " + wb.as_posix() + "\n")
        self.assertEqual((agent / "agents/fixture-agent.md").read_text(encoding="utf-8"),
                         "UPDATED role\n")
        manifest = json.loads((agent / "seep-install-manifest.json").read_text(encoding="utf-8"))
        for relative in ("prompts/fixture.md", "agents/fixture-agent.md"):
            self.assertEqual(manifest["managed_files"][relative], digest(agent / relative))

    def test_repeat_install_preserves_user_edits_to_owned_tasks_and_agents(self):
        wb = build_workbench(self.base)
        agent = self.base / "agent"
        first = self.install(wb, agent)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        for relative in ("prompts/fixture.md", "agents/fixture-agent.md"):
            (agent / relative).write_text("USER EDIT keep\n", encoding="utf-8")
        (wb / "Tool/prompts/tasks/fixture.md").write_text("UPDATED task\n", encoding="utf-8")
        (wb / "Tool/prompts/agents/fixture-agent.md").write_text("UPDATED role\n", encoding="utf-8")
        second = self.install(wb, agent)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        manifest = json.loads((agent / "seep-install-manifest.json").read_text(encoding="utf-8"))
        for relative in ("prompts/fixture.md", "agents/fixture-agent.md"):
            self.assertEqual((agent / relative).read_text(encoding="utf-8"), "USER EDIT keep\n")
            self.assertNotIn(relative, manifest["managed_files"])

    def test_installer_preserves_deep_user_config_and_repairs_agent_settings_bom(self):
        wb = build_workbench(self.base)
        agent = self.base / "agent"
        (agent / "agents").mkdir(parents=True)
        nested = "leaf value"
        for _ in range(16):
            nested = {"nested": nested}
        (agent / "settings.json").write_text(json.dumps({"custom": nested}), encoding="utf-8")
        (agent / "mcp.json").write_text(json.dumps({"custom": nested, "mcpServers": {}}), encoding="utf-8")
        role_settings = agent / "agents/settings.json"
        role_settings.write_text('{"builtInEnabled":false,"maxConcurrent":2,"custom":"keep"}', encoding="utf-8-sig")
        result = self.install(wb, agent)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for name in ("settings.json", "mcp.json"):
            self.assertEqual(json.loads((agent / name).read_text(encoding="utf-8"))["custom"], nested)
        self.assertFalse(role_settings.read_bytes().startswith(b"\xef\xbb\xbf"))
        self.assertEqual(json.loads(role_settings.read_text()), {"builtInEnabled": False, "maxConcurrent": 2, "custom": "keep"})

    def test_installer_rejects_invalid_nested_config_before_asset_changes(self):
        wb = build_workbench(self.base)
        agent = self.base / "agent"
        agent.mkdir()
        original = b'{"mcpServers": ["keep malformed original"]}'
        (agent / "mcp.json").write_bytes(original)
        result = self.install(wb, agent)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((agent / "mcp.json").read_bytes(), original)
        self.assertFalse((agent / "skills").exists())

    def test_installer_extracts_missing_ida_bundle_when_node_bundles_exist(self):
        wb = build_workbench(self.base)
        for name in ("js-reverse-mcp", "playwright-mcp"):
            (wb / "Tool/mcp/Tool/safe" / name / "node_modules").mkdir(parents=True)
        (wb / "setup/extract-deps.ps1").write_text(
            "Set-Content -LiteralPath (Join-Path $PSScriptRoot 'extracted.marker') -Value 'ran'\nexit 0\n", encoding="utf-8")
        result = run_ps(wb / "setup/install.ps1", "-AgentRoot", str(self.base / "agent"),
                        "-SkipPi", "-SkipTools", "-SkipPython", "-NonInteractive")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((wb / "setup/extracted.marker").is_file())

    def test_skip_packages_does_not_require_node_or_pi(self):
        wb = build_workbench(self.base)
        bins = self.base / "python-only"
        bins.mkdir()
        (bins / "python.cmd").write_text(
            f'@echo off\r\n"{Path(sys.executable)}" %*\r\n',
            encoding="ascii",
            newline="",
        )
        env = dict(os.environ, PATH=str(bins))
        proc = run_ps(
            wb / "setup/install-pi.ps1", "-AgentRoot", str(self.base / "agent"),
            "-SkipPackages",
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(
            json.loads((self.base / "agent/seep-install-manifest.json").read_text(encoding="utf-8"))["status"],
            "complete",
        )

    def test_rule_update_and_uninstall_preserve_user_blocks(self):
        wb = build_workbench(self.base)
        agent = self.base / "agent"
        self.assertEqual(self.install(wb, agent).returncode, 0)
        for name in ("AGENTS.md", "SEEP.md"):
            path = agent / name
            path.write_text(path.read_text(encoding="utf-8") + "\nUSER BLOCK KEEP\n", encoding="utf-8")
            (wb / "Tool/prompts" / name).write_text("Seep Reverse Lab NEW source\n", encoding="utf-8")
        updated = self.install(wb, agent)
        self.assertEqual(updated.returncode, 0, updated.stdout + updated.stderr)
        for name in ("AGENTS.md", "SEEP.md"):
            text = (agent / name).read_text(encoding="utf-8")
            self.assertIn("NEW source", text)
            self.assertIn("USER BLOCK KEEP", text)
            self.assertNotIn("fixture prompt", text)
        removed = run_ps(wb / "setup/uninstall.ps1", "-AgentRoot", str(agent), "-Yes")
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        for name in ("AGENTS.md", "SEEP.md"):
            self.assertIn("USER BLOCK KEEP", (agent / name).read_text(encoding="utf-8"))
            self.assertNotIn("NEW source", (agent / name).read_text(encoding="utf-8"))

    def test_uninstall_preserves_deep_custom_config_and_rejects_broken_json(self):
        wb = build_workbench(self.base)
        agent = self.base / 'agent'
        installed = self.install(wb, agent)
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        settings = agent / 'settings.json'
        original = settings.read_bytes()
        settings.write_bytes(b'{broken')
        before = {str(p.relative_to(agent)): p.read_bytes() for p in agent.rglob('*') if p.is_file()}
        proc = run_ps(wb / 'setup/uninstall.ps1', '-AgentRoot', str(agent), '-Yes')
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(before, {str(p.relative_to(agent)): p.read_bytes() for p in agent.rglob('*') if p.is_file()})
        settings.write_bytes(original)
        nested = 'leaf'
        for _ in range(28):
            nested = {'nested': nested}
        custom_package = {'source': 'npm:custom', 'settings': nested}
        cfg = json.loads(settings.read_text(encoding='utf-8'))
        cfg.update(custom=nested, packages=cfg['packages'] + [custom_package])
        settings.write_text(json.dumps(cfg), encoding='utf-8')
        proc = run_ps(wb / 'setup/uninstall.ps1', '-AgentRoot', str(agent), '-Yes')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        actual = json.loads(settings.read_text(encoding='utf-8'))
        self.assertEqual(actual['custom'], nested)
        self.assertEqual(actual['packages'], [custom_package])

    def test_real_config_generator_merges_jsonc_and_preserves_malformed(self):
        wb = build_workbench(self.base)
        copy_file(REAL_SETUP / "generate-configs.ps1", wb / "setup/generate-configs.ps1")
        (wb / ".mcp.json").write_text(json.dumps({"userSetting": 42, "mcpServers": {
            "custom": {"command": "keep"}, "seep": {"customField": "retain"}}}), encoding="utf-8")
        (wb / "opencode.jsonc").write_text('{// user comment\n"model":"keep-model","mcp":{"custom":{"type":"remote","url":"https://example.invalid/a,//b"},},}', encoding="utf-8")
        proc = run_ps(wb / "setup/generate-configs.ps1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        cfg = json.loads((wb / ".mcp.json").read_text(encoding="utf-8-sig"))
        self.assertEqual(cfg["userSetting"], 42)
        self.assertEqual(cfg["mcpServers"]["custom"]["command"], "keep")
        self.assertEqual(cfg["mcpServers"]["seep"]["customField"], "retain")
        cfg = json.loads((wb / "opencode.jsonc").read_text(encoding="utf-8-sig"))
        self.assertEqual(cfg["model"], "keep-model")
        self.assertEqual(cfg["mcp"]["custom"]["url"], "https://example.invalid/a,//b")
        self.assertTrue(list(wb.glob("opencode.jsonc.bak-*")))
        bad = b'{broken user config'
        (wb / ".mcp.json").write_bytes(bad)
        proc = run_ps(wb / "setup/generate-configs.ps1")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual((wb / ".mcp.json").read_bytes(), bad)

    def test_real_extractor_uses_archive_root_and_missing_archive_fails(self):
        import zipfile
        wb = build_workbench(self.base)
        copy_file(REAL_SETUP / "extract-deps.ps1", wb / "setup/extract-deps.ps1")
        for component, archive, root in (("js-reverse-mcp", "node_modules.zip", "node_modules"),
                                          ("playwright-mcp", "node_modules.zip", "node_modules"),
                                          ("ida-pro-mcp", "venv.zip", ".venv")):
            folder = wb / "Tool/mcp/Tool/safe" / component
            folder.mkdir(parents=True)
            with zipfile.ZipFile(folder / archive, "w") as z:
                z.writestr(root + "/fixture/entry.txt", "synthetic dependency")
        proc = run_ps(wb / "setup/extract-deps.ps1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue((wb / "Tool/mcp/Tool/safe/js-reverse-mcp/node_modules/fixture/entry.txt").is_file())
        self.assertFalse((wb / "Tool/mcp/Tool/safe/js-reverse-mcp/node_modules/node_modules").exists())
        missing_base = self.base / "missing-package"
        copy_file(REAL_SETUP / "extract-deps.ps1", missing_base / "setup/extract-deps.ps1")
        self.assertNotEqual(run_ps(missing_base / "setup/extract-deps.ps1").returncode, 0)

    def test_real_config_generator_clears_prior_child_failure(self):
        wb = build_workbench(self.base)
        script = wb / "setup/generate-configs.ps1"
        copy_file(REAL_SETUP / "generate-configs.ps1", script)
        command = ("& python -c 'raise SystemExit(7)'; & '" +
                   str(script).replace("'", "''") + "'; exit $LASTEXITCODE")
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                              cwd=wb, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=55)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue((wb / ".mcp.json").is_file())
        self.assertTrue((wb / "opencode.jsonc").is_file())

    def test_restore_conflict_and_update_check_failure_are_nonzero(self):
        wb = build_workbench(self.base)
        agent = self.base / "agent"
        self.assertEqual(self.install(wb, agent).returncode, 0)
        backup = self.base / "restore-conflict"
        (backup / "blocked").mkdir(parents=True)
        (backup / "blocked/child.txt").write_text("restore me", encoding="utf-8")
        (agent / "blocked").write_text("preserve conflict", encoding="utf-8")
        restored = run_ps(wb / "setup/uninstall.ps1", "-AgentRoot", str(agent), "-Restore", str(backup))
        self.assertNotEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        self.assertEqual((agent / "blocked").read_text(encoding="utf-8"), "preserve conflict")
        (wb / "Tool/scripts/check.py").write_text("print('fixture failing environment check')\nraise SystemExit(7)\n", encoding="utf-8")
        proc = run_ps(wb / "setup/update.ps1", "-AgentRoot", str(agent), "-NoPull", "-SkipPackages", "-SkipPython")
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("Seep 工作台更新完成:", proc.stdout)
        self.assertIn("fixture failing environment check", proc.stdout)

    def test_archive_update_does_not_claim_git_reset_updated_files(self):
        from unittest.mock import patch
        wb = build_workbench(self.base)
        agent = self.base / "agent"
        original = (wb / "VERSION").read_bytes()
        (wb / "setup/install.ps1").write_text("exit 0\n", encoding="utf-8")
        with patch.dict(os.environ, {"SEEP_REPO_URL": str(self.base / "missing-remote")}):
            proc = run_ps(wb / "setup/update.ps1", "-AgentRoot", str(agent),
                          "-SkipPackages", "-SkipPython", "-SkipVerify")
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("Seep 工作台更新完成:", proc.stdout)
        self.assertEqual((wb / "VERSION").read_bytes(), original)
        self.assertFalse((wb / ".git").exists())

    def test_extension_copy_failure_preserves_old_file_and_returns_failure(self):
        import ctypes
        wb = build_workbench(self.base)
        src = wb / "Tool/prompts/extensions/fixture.ts"
        src.parent.mkdir(parents=True)
        src.write_text("// Seep Reverse Lab new extension\n", encoding="utf-8")
        agent = self.base / "agent"
        self.assertEqual(self.install(wb, agent).returncode, 0)
        deployed = agent / "extensions/fixture.ts"
        old = deployed.read_bytes()
        src.write_text("// Seep Reverse Lab replacement\n", encoding="utf-8")
        create = ctypes.windll.kernel32.CreateFileW
        create.restype = ctypes.c_void_p
        create.argtypes = (ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                           ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p)
        # Allow the installer to read and back up the old asset, but deny
        # replacement while this handle is open. This injects a failure after
        # the backup has been created instead of preventing backup entirely.
        handle = create(str(deployed), 0x80000000, 0x1, None, 3, 0, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        try:
            proc = self.install(wb, agent)
        finally:
            ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(handle))
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(deployed.read_bytes(), old)
        self.assertFalse(list((agent / "extensions").glob(".seep-extension-*.tmp")))
        backups = list(agent.glob("backup-install-extensions-*/fixture.ts"))
        self.assertTrue(any(path.read_bytes() == old for path in backups))

    def test_extension_backup_failure_never_replaces_destination(self):
        import ctypes
        wb = build_workbench(self.base)
        src = wb / "Tool/prompts/extensions/fixture.ts"
        src.parent.mkdir(parents=True)
        src.write_text("// Seep Reverse Lab first extension\n", encoding="utf-8")
        agent = self.base / "agent"
        self.assertEqual(self.install(wb, agent).returncode, 0)
        deployed = agent / "extensions/fixture.ts"
        old = deployed.read_bytes()
        src.write_text("// Seep Reverse Lab replacement must not land\n", encoding="utf-8")
        create = ctypes.windll.kernel32.CreateFileW
        create.restype = ctypes.c_void_p
        create.argtypes = (ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                           ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p)
        handle = create(str(deployed), 0x80000000, 0, None, 3, 0, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        try:
            proc = self.install(wb, agent)
        finally:
            ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(handle))
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(deployed.read_bytes(), old)
        self.assertFalse(list((agent / "extensions").glob(".seep-extension-*.tmp")))
        self.assertFalse(list(agent.glob("backup-install-extensions-*")))

    def test_skill_copy_failure_restores_backup_and_returns_failure(self):
        from unittest.mock import patch
        wb = build_workbench(self.base)
        agent = self.base / "agent"
        self.assertEqual(self.install(wb, agent).returncode, 0)
        deployed = agent / "skills/softseep"
        old_skill = (deployed / "SKILL.md").read_bytes()
        marker = deployed / "user-marker.txt"
        marker.write_text("preserve in backup\n", encoding="utf-8")
        (wb / "Tool/skill/softseep/SKILL.md").write_text(
            "# SoftSeep replacement must not land\n", encoding="utf-8")
        with patch.dict(os.environ, {"SEEP_INTERNAL_TEST_FAIL_SKILL_COPY": "softseep"}):
            proc = self.install(wb, agent)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((deployed / "SKILL.md").read_bytes(), old_skill)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve in backup\n")
        backups = sorted(agent.glob("backup-install-skills-*/softseep"))
        self.assertTrue(any((path / "user-marker.txt").is_file() for path in backups))

    def test_update_detects_lost_mcp_entry_and_changed_user_data(self):
        wb = build_workbench(self.base)
        agent = self.base / "agent"
        agent.mkdir()
        (agent / "mcp.json").write_text('{"mcpServers":{"user-custom":{"command":"keep"}}}', encoding="utf-8")
        (agent / "lab-mode.flag").write_text("original", encoding="utf-8")
        # Simulate an installer regression; the updater's independent integrity
        # check must fail even when both child scripts return success.
        (wb / "setup/install.ps1").write_text(
            "param([switch]$NonInteractive,[string]$AgentRoot,[switch]$SkipPackages,[switch]$SkipPython,[switch]$SkipTools)\n"
            "[IO.File]::WriteAllText((Join-Path $AgentRoot 'mcp.json'), '{\"mcpServers\":{}}')\n"
            "[IO.File]::WriteAllText((Join-Path $AgentRoot 'lab-mode.flag'), 'changed')\nexit 0\n", encoding="utf-8")
        proc = run_ps(wb / "setup/update.ps1", "-AgentRoot", str(agent), "-NoPull",
                      "-SkipPackages", "-SkipPython", "-SkipVerify")
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("Seep 工作台更新完成:", proc.stdout)

    def test_update_rejects_bad_mcp_and_detects_new_protected_file(self):
        wb = build_workbench(self.base)
        agent = self.base / 'agent'
        agent.mkdir()
        cfg = agent / 'mcp.json'
        cfg.write_bytes(b'{broken')
        (wb / 'setup/install.ps1').write_text(
            "param([switch]$NonInteractive,[string]$AgentRoot,[switch]$SkipTools)\n"
            "[IO.File]::WriteAllText((Join-Path $AgentRoot 'models.json'), '{}')\nexit 0\n", encoding='utf-8')
        result = run_ps(wb / 'setup/update.ps1', '-AgentRoot', str(agent), '-NoPull', '-SkipVerify')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((agent / 'models.json').exists())
        cfg.write_text('{"mcpServers":{}}', encoding='utf-8')
        result = run_ps(wb / 'setup/update.ps1', '-AgentRoot', str(agent), '-NoPull', '-SkipVerify')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('Seep 工作台更新完成:', result.stdout)

    def test_uninstall_preserves_undeployed_pending_skill(self):
        wb = build_workbench(self.base)
        (wb / "Tool/skill/_pending").mkdir()
        agent = self.base / "agent"
        self.assertEqual(self.install(wb, agent).returncode, 0)
        custom = agent / "skills/_pending/user.txt"
        custom.parent.mkdir()
        custom.write_text("user-owned", encoding="utf-8")
        proc = run_ps(wb / "setup/uninstall.ps1", "-AgentRoot", str(agent), "-Yes")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(custom.is_file())

    def test_ida_binding_uses_selected_agent_and_preserves_malformed_config(self):
        from unittest.mock import patch
        wb = build_workbench(self.base)
        copy_file(REAL_SETUP / "install-ida.ps1", wb / "setup/install-ida.ps1")
        ida = self.base / "fixture IDA"
        (ida / "plugins/ida_pro_mcp").mkdir(parents=True)
        (ida / "ida.exe").write_bytes(b"fixture marker; never executed")
        (ida / "plugins/ida_pro_mcp/server.py").write_text("# fixture server; never executed\n", encoding="utf-8")
        agent = self.base / "selected-agent"
        profile = self.base / "isolated-profile"
        default_config = profile / ".pi/agent/mcp.json"
        default_config.parent.mkdir(parents=True)
        default_config.write_bytes(b'{"mcpServers":{"default-user":{"command":"keep"}}}')
        before_default = default_config.read_bytes()
        agent.mkdir()
        selected = agent / "mcp.json"
        selected.write_text('{"mcpServers":{"custom":{"command":"keep"}}}', encoding="utf-8")
        with patch.dict(os.environ, {"PI_CODING_AGENT_DIR":str(agent), "USERPROFILE":str(profile)}):
            proc = run_ps(wb / "setup/install-ida.ps1", "-IdaRoot", str(ida), "-SkipPip")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            cfg = json.loads(selected.read_text(encoding="utf-8-sig"))["mcpServers"]
            self.assertIn("ida", cfg)
            self.assertEqual(cfg["custom"], {"command":"keep"})
            self.assertEqual(default_config.read_bytes(), before_default)
            bad = b'{broken user config'
            selected.write_bytes(bad)
            proc = run_ps(wb / "setup/install-ida.ps1", "-IdaRoot", str(ida), "-SkipPip")
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(selected.read_bytes(), bad)
            self.assertEqual(default_config.read_bytes(), before_default)

    def test_pi_web_launcher_starts_host_and_preserves_child_status(self):
        wb = build_workbench(self.base)
        copy_file(REAL_SETUP / "pi-web-lan.cmd", wb / "setup/pi-web-lan.cmd")
        bins = self.base / "bin"
        bins.mkdir()
        marker = self.base / "host-started.txt"
        (bins / "pi-web.cmd").write_text('@echo off\n>"%SEEP_TEST_MARKER%" echo %*\nexit /b 7\n', encoding="ascii")
        env = dict(os.environ, PATH=str(bins) + os.pathsep + os.environ.get("PATH", ""),
                   SEEP_TEST_MARKER=str(marker), PI_WEB_HOSTNAME="127.0.0.1", PI_WEB_PORT="32123")
        proc = subprocess.run([os.environ["COMSPEC"], "/d", "/c", str(wb / "setup/pi-web-lan.cmd")],
                              cwd=wb, env=env, input=b"\n\n", capture_output=True, timeout=20)
        self.assertEqual(proc.returncode, 7, proc.stdout.decode("utf-8", errors="replace"))
        self.assertTrue(marker.is_file())
        self.assertIn("32123", marker.read_text(encoding="ascii"))
    def test_explicit_root_is_propagated_to_installer_environment_check(self):
        wb = build_workbench(self.base)
        agent = self.base / "selected-agent"
        (wb / "Tool/scripts/check.py").write_text(
            "import os\nfrom pathlib import Path\nassert Path(os.environ['PI_CODING_AGENT_DIR']).resolve() == Path(" + repr(str(agent)) + ").resolve()\n",
            encoding="utf-8")
        proc = run_ps(wb / "setup/install.ps1", "-AgentRoot", str(agent), "-SkipPackages",
                      "-SkipPython", "-SkipTools", "-NonInteractive")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("CommandNotFoundException", proc.stdout + proc.stderr)

    def test_total_installer_skip_packages_does_not_require_node(self):
        wb = build_workbench(self.base)
        bins = self.base / "python-only"
        bins.mkdir()
        (bins / "python.cmd").write_text(
            f'@echo off\r\n"{Path(sys.executable)}" %*\r\n',
            encoding="ascii",
            newline="",
        )
        env = isolated_environment(self.base)
        env["PATH"] = str(bins)
        proc = run_ps(
            wb / "setup/install.ps1",
            "-AgentRoot", str(self.base / "agent"),
            "-SkipPackages", "-SkipPython", "-SkipTools", "-NonInteractive",
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("[FAIL] Pi 需要 Node.js", proc.stdout + proc.stderr)
        self.assertTrue((self.base / "agent/seep-install-manifest.json").is_file())

    def test_preflight_compares_full_owned_prompt_and_rejects_tamper(self):
        from unittest.mock import patch
        import sys
        sys.path.insert(0, str(ROOT / "Tool/scripts"))
        import preflight as pf
        wb = build_workbench(self.base)
        (wb / "Tool/prompts/tasks/fixture.md").unlink()
        (wb / "Tool/skill/softseep/SKILL.md").write_text("# fixture\n", encoding="utf-8")
        agent = self.base / "selected-agent"
        self.assertEqual(self.install(wb, agent).returncode, 0)
        path = agent / "AGENTS.md"
        good = "USER PREFIX\n" + path.read_text(encoding="utf-8") + "\nUSER SUFFIX\n"
        def check(text):
            path.write_text(text, encoding="utf-8")
            with patch.object(pf, "TOOL", str(wb / "Tool")), patch.object(pf, "results", []), \
                 patch.dict(os.environ, {"PI_CODING_AGENT_DIR": str(agent)}):
                pf.check_deploy_bidirectional()
                return list(pf.results)
        self.assertTrue(all(x["ok"] for x in check(good)))
        stale = good.replace("Seep Reverse Lab fixture agents", "stale source")
        self.assertTrue(any(not x["ok"] and "AGENTS.md" in x["detail"] for x in check(stale)))
        broken = good + "<!-- seep:managed:begin -->"
        self.assertTrue(any(not x["ok"] for x in check(broken)))
        legacy = (wb / "Tool/prompts/AGENTS.md").read_text(encoding="utf-8") + "\n<!-- magpie:begin -->\nhost text\n<!-- magpie:end -->\n"
        self.assertTrue(all(x["ok"] for x in check(legacy)))

    def test_start_uses_custom_root_and_never_creates_default_agent(self):
        wb = build_workbench(self.base)
        copy_file(ROOT / "start.bat", wb / "start.bat")
        agent, profile, bins = self.base / "custom agent", self.base / "empty-profile", self.base / "bin"
        agent.mkdir(); profile.mkdir(); bins.mkdir()
        installed = self.install(wb, agent)
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        (bins / "pi.cmd").write_text('@echo off\n>"%PI_CODING_AGENT_DIR%\\opened.txt" echo opened\nexit /b 0\n', encoding="ascii")
        env = dict(os.environ, PI_CODING_AGENT_DIR=str(agent), USERPROFILE=str(profile),
                   PATH=str(bins) + os.pathsep + os.environ.get("PATH", ""))
        proc = subprocess.run([os.environ["COMSPEC"], "/d", "/c", str(wb / "start.bat")],
                              cwd=wb, env=env, input=b"\n", capture_output=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stdout.decode("utf-8", errors="replace"))
        self.assertTrue((agent / "opened.txt").is_file())
        self.assertTrue((agent / "lab-mode.flag").is_file())
        self.assertFalse((profile / ".pi").exists())

        # The runtime resolver also supports this legacy environment alias.
        (agent / "opened.txt").unlink()
        env.pop("PI_CODING_AGENT_DIR")
        env["PI_AGENT_DIR"] = str(agent)
        proc = subprocess.run([os.environ["COMSPEC"], "/d", "/c", str(wb / "start.bat")],
                              cwd=wb, env=env, input=b"\n", capture_output=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stdout.decode("utf-8", errors="replace"))
        self.assertTrue((agent / "opened.txt").is_file())
        self.assertFalse((profile / ".pi").exists())

    def test_start_rejects_retained_prompt_without_runtime_registration(self):
        wb = build_workbench(self.base)
        copy_file(ROOT / "start.bat", wb / "start.bat")
        agent, bins = self.base / "partial agent", self.base / "bin"
        agent.mkdir(); bins.mkdir()
        (agent / "SEEP.md").write_text("user text retained after uninstall\n", encoding="utf-8")
        (bins / "pi.cmd").write_text("@echo off\r\nexit /b 0\r\n", encoding="ascii")
        env = dict(os.environ, PI_CODING_AGENT_DIR=str(agent),
                   PATH=str(bins) + os.pathsep + os.environ.get("PATH", ""))
        proc = subprocess.run([os.environ["COMSPEC"], "/d", "/c", str(wb / "start.bat")],
                              cwd=wb, env=env, input=b"\n", capture_output=True, timeout=20)
        self.assertNotEqual(proc.returncode, 0,
                            proc.stdout.decode("utf-8", errors="replace"))
        self.assertIn("仅保留 SEEP.md 不算已安装",
                      proc.stdout.decode("utf-8", errors="replace"))

    def test_uninstall_backup_failure_preserves_components_and_registration(self):
        import ctypes
        wb = build_workbench(self.base)
        extension = wb / "Tool/prompts/extensions/fixture.ts"
        extension.parent.mkdir(parents=True)
        extension.write_text("// Seep Reverse Lab fixture\n", encoding="utf-8")
        agent = self.base / "agent"
        self.assertEqual(self.install(wb, agent).returncode, 0)
        deployed = agent / "extensions/fixture.ts"
        registration = (agent / "seep-runtime.json").read_bytes()
        create = ctypes.windll.kernel32.CreateFileW
        create.restype = ctypes.c_void_p
        create.argtypes = (ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                           ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p)
        handle = create(str(deployed), 0x80000000, 0, None, 3, 0, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        try:
            proc = run_ps(wb / "setup/uninstall.ps1", "-AgentRoot", str(agent), "-Yes")
        finally:
            ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(handle))
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((agent / "seep-runtime.json").read_bytes(), registration)
        self.assertTrue((agent / "skills/softseep/pack.json").is_file())
        self.assertEqual(deployed.read_bytes(), extension.read_bytes())

    def test_missing_host_is_not_ready_and_auth_check_does_not_open_stores(self):
        import importlib.util
        from unittest.mock import patch
        from types import SimpleNamespace
        spec = importlib.util.spec_from_file_location("delivery_env_check", ROOT / "Tool/scripts/env-check.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        agent = self.base / "public-agent"
        agent.mkdir()
        for name in ("SEEP.md", "AGENTS.md"):
            (agent / name).write_text("public fixture", encoding="utf-8")
        (agent / "mcp.json").write_text('{"mcpServers":{"fixture":{"command":"fixture"}}}', encoding="utf-8")
        (agent / "settings.json").write_text('{"defaultProvider":"fixture","defaultModel":"fixture-model"}', encoding="utf-8")
        with patch.object(module, "agent_dir", return_value=str(agent)), \
             patch.object(module, "expected_extensions", return_value=[]), \
             patch.object(module, "expected_skills", return_value=[]), \
             patch.object(module, "_mcp_service_probe", return_value={"available":True}), \
             patch.object(module, "_model_credential_probe", return_value={"configured":True}), \
             patch("shutil.which", return_value=None):
            result = module.check()
        self.assertFalse(result["installed"])
        self.assertFalse(result["checks"]["pi"])
        self.assertFalse(result["checks"]["node"])
        actual_open = open
        def public_only(path, *args, **kwargs):
            self.assertNotIn(Path(path).name, ("auth.json", "models.json"))
            return actual_open(path, *args, **kwargs)
        with patch("builtins.open", side_effect=public_only), \
             patch("shutil.which", return_value="fixture-pi"), \
             patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout='{"status":"ready"}')) as run:
            result = module._model_credential_probe(str(agent))
        self.assertTrue(result["configured"])
        args = run.call_args.args[0]
        self.assertIn("--no-refresh", args)
        self.assertNotIn("--credentials", args)

    def test_install_registers_real_copy_and_preserves_user_data(self):
        wb = build_workbench(self.base)
        agent = self.base / "用户 agent root/space"
        (agent / "prompts").mkdir(parents=True)
        (agent / "agents").mkdir(parents=True)
        (agent / "prompts/user-custom.md").write_text("user prompt keep\n", encoding="utf-8")
        (agent / "agents/user-custom.md").write_text("user agent keep\n", encoding="utf-8")
        (agent / "mcp.json").write_text(
            json.dumps({"mcpServers": {"user-custom": {"command": "user-tool"}}}), encoding="utf-8"
        )
        (agent / "settings.json").write_text(
            json.dumps({"customSetting": "keep", "packages": ["npm:user-custom"]}), encoding="utf-8"
        )
        (agent / "lab-mode.flag").write_text("fixture\n", encoding="utf-8")

        installed = self.install(wb, agent)
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        origin = agent / "seep-runtime.json"
        deployed = agent / "skills/softseep/scripts/version-migrate.py"
        source = wb / "Tool/skill/softseep/scripts/version-migrate.py"
        self.assertTrue(origin.is_file())
        self.assertTrue(deployed.is_file())
        self.assertEqual(digest(source), digest(deployed))
        self.assertNotEqual(origin.read_bytes()[:3], b"\xef\xbb\xbf")
        registration = json.loads(origin.read_text(encoding="utf-8"))
        self.assertEqual(Path(registration["source_root"]).resolve(), wb.resolve())
        self.assertEqual(registration["ownership"]["config_only"], True)

        # Deployed migration finds the registration with no SEEP_RUNTIME_ROOT.
        env = os.environ.copy()
        env.pop("SEEP_RUNTIME_ROOT", None)
        env["PI_CODING_AGENT_DIR"] = str(agent)
        fresh = subprocess.run(
            ["python", "-B", str(deployed), "--self-test"], cwd=str(wb), env=env,
            capture_output=True, encoding="utf-8", errors="replace", text=True, timeout=55,
        )
        self.assertEqual(fresh.returncode, 0, fresh.stdout + fresh.stderr)

        deployed_tree = agent / "skills/softseep"
        legacy_marker = deployed_tree / "legacy-marker.txt"
        legacy_guide = deployed_tree / "GUIDE.md"
        legacy_marker.write_bytes(b"legacy-marker-v1")
        legacy_guide.write_bytes(b"user modified guide v1\x00\xff")
        repeated = self.install(wb, agent)
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        skill_backups = sorted(agent.glob("backup-install-skills-*/softseep"))
        self.assertGreaterEqual(len(skill_backups), 1)
        self.assertEqual((skill_backups[-1] / "legacy-marker.txt").read_bytes(), b"legacy-marker-v1")
        self.assertEqual((skill_backups[-1] / "GUIDE.md").read_bytes(), b"user modified guide v1\x00\xff")
        legacy_marker = deployed_tree / "legacy-marker.txt"
        legacy_guide = deployed_tree / "GUIDE.md"
        legacy_marker.write_bytes(b"legacy-marker-v2")
        legacy_guide.write_bytes(b"user modified guide v2\x01")
        repeated_again = self.install(wb, agent)
        self.assertEqual(repeated_again.returncode, 0, repeated_again.stdout + repeated_again.stderr)
        skill_backups_again = sorted(agent.glob("backup-install-skills-*/softseep"))
        self.assertGreater(len(skill_backups_again), len(skill_backups))
        self.assertTrue(any((p / "GUIDE.md").read_bytes() == b"user modified guide v2\x01" for p in skill_backups_again))
        self.assertEqual(digest(source), digest(deployed))
        self.assertEqual((agent / "agents/user-custom.md").read_text(encoding="utf-8"), "user agent keep\n")
        mcp = json.loads((agent / "mcp.json").read_text(encoding="utf-8"))
        self.assertIn("user-custom", mcp["mcpServers"])
        settings = json.loads((agent / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual(settings["customSetting"], "keep")
        self.assertIn("npm:user-custom", settings["packages"])

        repeated = self.install(wb, agent)
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertTrue(any(agent.glob("seep-runtime.json.backup-*")))

        # Tampered registration is rejected by the real deployed migration.
        tampered = json.loads(origin.read_text(encoding="utf-8"))
        tampered["entry_sha256"]["Tool/skill/softseep/pack.json"] = "0" * 64
        origin.write_text(json.dumps(tampered), encoding="utf-8")
        rejected = subprocess.run(
            ["python", "-B", str(deployed), "--self-test"], cwd=str(wb), env=env,
            capture_output=True, encoding="utf-8", errors="replace", text=True, timeout=55,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertNotIn("Traceback", rejected.stdout + rejected.stderr)
        self.assertIn("runtime_mismatch", rejected.stdout)

        # A drive root is rejected before any agent-root write.
        before = sorted(str(p.relative_to(self.base)) for p in agent.rglob("*"))
        invalid = run_ps(wb / "setup/install-pi.ps1", "-AgentRoot", "C:\\", "-SkipPackages")
        self.assertNotEqual(invalid.returncode, 0)
        after = sorted(str(p.relative_to(self.base)) for p in agent.rglob("*"))
        self.assertEqual(before, after)

    def test_install_uses_utf8_pipes_and_excludes_runtime_caches(self):
        wb = build_workbench(self.base)
        cache = wb / "Tool/skill/softseep/scripts/__pycache__/fixture.cpython-312.pyc"
        cache.parent.mkdir(parents=True)
        cache.write_bytes(b"host-specific bytecode")
        agent = self.base / "agent with spaces"
        env = isolated_environment(self.base)
        installed = run_ps_bytes(
            wb / "setup/install-pi.ps1", "-AgentRoot", str(agent), "-SkipPackages", env=env
        )
        self.assertEqual(installed.returncode, 0, installed.stderr.decode("utf-8", "replace"))
        # Windows PowerShell 5.1 inherits the console code page for Write-Host and
        # Python independently. Both producers must emit one valid UTF-8 stream.
        installed.stdout.decode("utf-8", "strict")
        installed.stderr.decode("utf-8", "strict")
        self.assertIn("Pi Agent", installed.stdout.decode("utf-8"))

        self.assertFalse((agent / "skills/softseep/scripts/__pycache__").exists())
        manifest = json.loads((agent / "seep-install-manifest.json").read_text(encoding="utf-8"))
        self.assertFalse(any("__pycache__" in rel or rel.endswith(".pyc")
                             for rel in manifest["managed_files"]))

    def test_failed_skill_update_does_not_claim_unpublished_source_files(self):
        wb = build_workbench(self.base)
        agent = self.base / "failed update agent"
        self.assertEqual(self.install(wb, agent).returncode, 0)
        deployed = agent / "skills/softseep/SKILL.md"
        old_digest = digest(deployed)
        marker = agent / "skills/softseep/user-marker.txt"
        marker.write_text("keep after rollback\n", encoding="utf-8")
        source = wb / "Tool/skill/softseep/SKILL.md"
        source.write_text("# SoftSeep unpublished replacement\n", encoding="utf-8")
        env = isolated_environment(self.base)
        env["SEEP_INTERNAL_TEST_FAIL_SKILL_COPY"] = "softseep"
        failed = run_ps_bytes(
            wb / "setup/install-pi.ps1", "-AgentRoot", str(agent), "-SkipPackages", env=env
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(digest(deployed), old_digest)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep after rollback\n")
        manifest = json.loads((agent / "seep-install-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "incomplete")
        self.assertEqual(manifest["managed_files"].get("skills/softseep/SKILL.md"), old_digest)
        self.assertNotEqual(manifest["managed_files"].get("skills/softseep/SKILL.md"), digest(source))

        recovered = self.install(wb, agent)
        self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
        self.assertEqual(digest(deployed), digest(source))
        self.assertFalse(marker.exists())
        self.assertTrue(any(agent.glob("backup-install-skills-*/softseep/user-marker.txt")))

    def test_install_copy_and_child_failures_are_nonzero(self):
        invalid_source = build_workbench(self.base / "invalid-source")
        (invalid_source / "Tool/skill/softseep/pack.json").unlink()
        invalid_agent = self.base / "invalid-source-agent"
        invalid_install = self.install(invalid_source, invalid_agent)
        self.assertNotEqual(invalid_install.returncode, 0)
        self.assertFalse((invalid_agent / "seep-runtime.json").exists())

        wb = build_workbench(self.base)
        blocked = self.base / "blocked agent"
        blocked.mkdir(parents=True)
        (blocked / "skills").write_text("not-a-directory", encoding="utf-8")
        failed_copy = self.install(wb, blocked)
        self.assertNotEqual(failed_copy.returncode, 0)
        self.assertFalse((blocked / "seep-runtime.json").exists())

        child_fail = self.base / "child-fail agent"
        first = self.install(wb, child_fail)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        (wb / "Tool/config/mcp-servers.json").unlink()
        update = run_ps(
            wb / "setup/update.ps1", "-AgentRoot", str(child_fail), "-NoPull",
            "-SkipPackages", "-SkipPython", "-SkipVerify",
        )
        self.assertNotEqual(update.returncode, 0)

    def test_update_and_uninstall_are_offline_scoped_and_safe(self):
        wb = build_workbench(self.base)
        agent = self.base / "update agent"
        agent.mkdir(parents=True)
        (agent / "prompts/user-custom.md").parent.mkdir(parents=True, exist_ok=True)
        (agent / "prompts/user-custom.md").write_text("user prompt keep\n", encoding="utf-8")
        (agent / "agents").mkdir(parents=True, exist_ok=True)
        (agent / "agents/user-custom.md").write_text("user agent keep\n", encoding="utf-8")
        (agent / "mcp.json").write_text(
            json.dumps({"mcpServers": {"user-custom": {"command": "user-tool"}}}), encoding="utf-8"
        )
        installed = self.install(wb, agent)
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        update = run_ps(
            wb / "setup/update.ps1", "-AgentRoot", str(agent), "-NoPull",
            "-SkipPackages", "-SkipPython", "-SkipVerify",
        )
        self.assertEqual(update.returncode, 0, update.stdout + update.stderr)

        # A tampered registration is not trusted; the independent install
        # manifest remains the bounded cleanup authority.
        origin = agent / "seep-runtime.json"
        tampered = json.loads(origin.read_text(encoding="utf-8"))
        tampered["source_root"] = str(self.base / "other-source")
        origin.write_text(json.dumps(tampered), encoding="utf-8")
        refused = run_ps(wb / "setup/uninstall.ps1", "-AgentRoot", str(agent), "-DryRun")
        self.assertEqual(refused.returncode, 0, refused.stdout + refused.stderr)
        self.assertIn("依据安装所有权清单", refused.stdout)
        self.assertTrue(origin.exists())
        restored = self.install(wb, agent)
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)

        # Dry-run must not create a backup or mutate any user/runtime file.
        before = {str(p.relative_to(agent)): digest(p) for p in agent.rglob("*") if p.is_file()}
        dry = run_ps(wb / "setup/uninstall.ps1", "-AgentRoot", str(agent), "-DryRun")
        self.assertEqual(dry.returncode, 0, dry.stdout + dry.stderr)
        after = {str(p.relative_to(agent)): digest(p) for p in agent.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

        removed = run_ps(wb / "setup/uninstall.ps1", "-AgentRoot", str(agent), "-Yes")
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assertFalse((agent / "seep-runtime.json").exists())
        self.assertTrue(wb.exists())
        self.assertTrue((wb / "Tool/scripts/lib/project_lock.py").exists())
        self.assertTrue((agent / "mcp.json").exists())
        self.assertIn("user-custom", json.loads((agent / "mcp.json").read_text(encoding="utf-8"))["mcpServers"])
        self.assertTrue((agent / "prompts/user-custom.md").exists())
        self.assertTrue((agent / "agents/user-custom.md").exists())
        self.assertTrue(any(agent.glob("backup-uninstall-*/seep-runtime.json")))

    def test_update_restores_stash_and_conflict_preserves_it(self):
        wb = build_workbench(self.base)
        remote = self.base / "remote.git"
        subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
        (wb / "Tool/cases/.keep").write_text("fixture\n", encoding="utf-8")
        (wb / "conflict.txt").write_text("base\n", encoding="utf-8")
        for args in (("init", "-b", "main"), ("add", "."),
                     ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                      "commit", "-m", "base"),
                     ("remote", "add", "origin", str(remote)),
                     ("push", "-u", "origin", "main")):
            subprocess.run(["git", "-C", str(wb), *args], check=True, capture_output=True)

        agent = self.base / "agent-success"
        local = wb / "user-change.txt"
        local.write_text("local work\n", encoding="utf-8")
        update = run_ps(wb / "setup/update.ps1", "-AgentRoot", str(agent), "-SkipPackages",
                        "-SkipPython", "-SkipVerify")
        self.assertEqual(update.returncode, 0, update.stdout + update.stderr)
        self.assertEqual(local.read_text(encoding="utf-8"), "local work\n")
        stash = subprocess.run(["git", "-C", str(wb), "stash", "list"],
                               capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(stash.stdout.strip(), "")

        (wb / "conflict.txt").write_text("remote\n", encoding="utf-8")
        for args in (("add", "conflict.txt"),
                     ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                      "commit", "-m", "remote"),
                     ("push", "origin", "main"),
                     ("reset", "--hard", "HEAD^")):
            subprocess.run(["git", "-C", str(wb), *args], check=True, capture_output=True)
        (wb / "conflict.txt").write_text("local\n", encoding="utf-8")
        conflicted = run_ps(wb / "setup/update.ps1", "-AgentRoot", str(self.base / "agent-conflict"),
                            "-SkipPackages", "-SkipPython", "-SkipVerify")
        self.assertNotEqual(conflicted.returncode, 0, conflicted.stdout + conflicted.stderr)
        self.assertIn("已明确保留", conflicted.stdout + conflicted.stderr)
        self.assertIn("stash apply", conflicted.stdout + conflicted.stderr)
        self.assertNotIn("Seep 工作台更新完成:", conflicted.stdout)
        stash = subprocess.run(["git", "-C", str(wb), "stash", "list"],
                               capture_output=True, text=True, encoding="utf-8")
        self.assertNotEqual(stash.stdout.strip(), "")

    def test_partial_uninstall_without_runtime_preserves_same_name_user_assets(self):
        wb = build_workbench(self.base)
        agent = self.base / "agent"
        user_task = agent / "prompts/fixture.md"
        user_agent = agent / "agents/fixture-agent.md"
        user_settings = agent / "agents/settings.json"
        user_task_text = f"fixture {wb.resolve().as_posix()}\n"
        for path, text in (
            (user_task, user_task_text),
            (user_agent, "USER AGENT\n"),
            (user_settings, '{"builtInEnabled":false,"custom":"keep"}\n'),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        installed = self.install(wb, agent)
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        user_skill_file = agent / "skills/softseep/user-owned.txt"
        user_skill_file.write_text("user-owned\n", encoding="utf-8")
        (agent / "seep-runtime.json").write_text("{broken", encoding="utf-8")

        removed = run_ps(wb / "setup/uninstall.ps1", "-AgentRoot", str(agent), "-Yes")
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assertIn("依据安装所有权清单", removed.stdout)
        self.assertEqual(user_task.read_text(encoding="utf-8"), user_task_text)
        self.assertEqual(user_agent.read_text(encoding="utf-8"), "USER AGENT\n")
        self.assertEqual(user_settings.read_text(encoding="utf-8"),
                         '{"builtInEnabled":false,"custom":"keep"}\n')
        self.assertEqual(user_skill_file.read_text(encoding="utf-8"), "user-owned\n")
        self.assertFalse((agent / "skills/softseep/pack.json").exists(), removed.stdout)
        self.assertFalse((agent / "seep-runtime.json").exists())
        self.assertFalse((agent / "seep-install-manifest.json").exists())

        missing_agent = self.base / "agent-missing-runtime"
        second_install = self.install(wb, missing_agent)
        self.assertEqual(second_install.returncode, 0,
                         second_install.stdout + second_install.stderr)
        missing_user_file = missing_agent / "skills/softseep/user-missing-runtime.txt"
        missing_user_file.write_text("user-owned\n", encoding="utf-8")
        (missing_agent / "seep-runtime.json").unlink()
        missing_removed = run_ps(wb / "setup/uninstall.ps1",
                                 "-AgentRoot", str(missing_agent), "-Yes")
        self.assertEqual(missing_removed.returncode, 0,
                         missing_removed.stdout + missing_removed.stderr)
        self.assertIn("依据安装所有权清单", missing_removed.stdout)
        self.assertFalse((missing_agent / "skills/softseep/pack.json").exists())
        self.assertEqual(missing_user_file.read_text(encoding="utf-8"), "user-owned\n")

    def test_uninstall_cleans_owned_tasks_agents_and_default_agent_settings(self):
        wb = build_workbench(self.base)
        agent = self.base / "agent"
        installed = self.install(wb, agent)
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        manifest = json.loads((agent / "seep-install-manifest.json").read_text(encoding="utf-8"))
        owned = [
            agent / "prompts/fixture.md",
            agent / "agents/fixture-agent.md",
            agent / "agents/settings.json",
        ]
        self.assertTrue(all(path.is_file() for path in owned))
        self.assertEqual(owned[0].read_text(encoding="utf-8"),
                         f"fixture {wb.resolve().as_posix()}\n")
        self.assertEqual(manifest["managed_files"]["prompts/fixture.md"], digest(owned[0]))
        user_task = agent / "prompts/user-task.md"
        user_agent = agent / "agents/user-agent.md"
        user_empty_skill = agent / "skills/user-empty-skill"
        user_task.write_text("user task\n", encoding="utf-8")
        user_agent.write_text("user agent\n", encoding="utf-8")
        user_empty_skill.mkdir()

        removed = run_ps(wb / "setup/uninstall.ps1", "-AgentRoot", str(agent), "-Yes")
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assertTrue(all(not path.exists() for path in owned),
                        {str(path): path.exists() for path in owned})
        self.assertEqual(user_task.read_text(encoding="utf-8"), "user task\n")
        self.assertEqual(user_agent.read_text(encoding="utf-8"), "user agent\n")
        self.assertTrue(user_empty_skill.is_dir(), removed.stdout + removed.stderr)

    def test_uninstall_without_runtime_or_manifest_preserves_same_content_user_assets(self):
        wb = build_workbench(self.base)
        agent = self.base / "agent"
        fixture_task = f"fixture {wb.resolve().as_posix()}\n"
        assets = {
            agent / "prompts/fixture.md": fixture_task,
            agent / "agents/fixture-agent.md": "Seep Reverse Lab fixture agent\n",
            agent / "skills/softseep/pack.json": (wb / "Tool/skill/softseep/pack.json").read_text(encoding="utf-8"),
            agent / "extensions/fixture.ts": "// Seep Reverse Lab user extension\n",
        }
        for path, text in assets.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        source_extension = wb / "Tool/prompts/extensions/fixture.ts"
        source_extension.parent.mkdir(parents=True)
        source_extension.write_text("// Seep Reverse Lab user extension\n", encoding="utf-8")

        proc = run_ps(wb / "setup/uninstall.ps1", "-AgentRoot", str(agent), "-Yes")

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for path in assets:
            self.assertTrue(path.is_file(), f"unproven user asset was removed: {path}\n{proc.stdout}{proc.stderr}")

    def test_uninstall_preserves_preexisting_lab_flag_without_ownership_proof(self):
        wb = build_workbench(self.base)
        agent = self.base / "agent with user lab flag"
        agent.mkdir()
        flag = agent / "lab-mode.flag"
        original = b"created by the user before installation\n"
        flag.write_bytes(original)
        installed = self.install(wb, agent)
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)

        removed = run_ps(wb / "setup/uninstall.ps1", "-AgentRoot", str(agent), "-Yes")
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assertEqual(flag.read_bytes(), original)
        self.assertIn("安装清单不能证明", removed.stdout)

    def test_restore_relative_backup_path_keeps_original_layout(self):
        wb = build_workbench(self.base)
        agent = self.base / "restore agent"
        backup = wb / "backup fixture"
        nested = backup / "skills/softseep/custom.txt"
        nested.parent.mkdir(parents=True)
        nested.write_bytes(b"original user content\n")
        restored = run_ps(wb / "setup/uninstall.ps1", "-AgentRoot", str(agent),
                          "-Restore", "backup fixture")
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        self.assertEqual(sorted(str(p.relative_to(agent)).replace('\\', '/')
                                for p in agent.rglob('*') if p.is_file()),
                         ['skills/softseep/custom.txt'])
        self.assertEqual((agent / "skills/softseep/custom.txt").read_bytes(),
                         nested.read_bytes())

    def test_cli_root_priority_and_registration_guards(self):
        explicit = self.base / "explicit agent 空格"
        result = run_py("resolve", "--agent-root", str(explicit))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(str(explicit.resolve()), json.loads(result.stdout)["agent_root"])
        bad = run_py("resolve", "--agent-root", "C:\\")
        self.assertNotEqual(bad.returncode, 0)
        self.assertFalse(explicit.exists())


if __name__ == "__main__":
    unittest.main()
