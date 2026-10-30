#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Task-local parity checks for the three Unix shell entrypoints.

These checks execute through Windows Git Bash but cover the Bash installer,
updater, and uninstaller.  Every subprocess uses an isolated in-repository
HOME/USERPROFILE/TEMP/AgentRoot; no package, network, or customer target is
executed.
"""
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
TMP_ROOT = ROOT / "work" / "final-delivery" / "tmp"
REAL_SETUP = ROOT / "setup"
REAL_RUNTIME = ROOT / "Tool/scripts/lib/runtime_root.py"
REAL_LOCK = ROOT / "Tool/scripts/lib/project_lock.py"
REAL_TRANSACTION = ROOT / "Tool/scripts/lib/project_transaction.py"
REAL_BRIDGE = ROOT / "Tool/scripts/runtime-root.py"
REAL_MIGRATE = ROOT / "Tool/skill/softseep/scripts/version-migrate.py"
REAL_PACK = ROOT / "Tool/skill/softseep/pack.json"
REAL_MERGE = ROOT / "setup/merge_agent_config.py"
REAL_PERSONA_PKG = ROOT / "Tool/prompts/packages/pi-seep-ext"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy_file(src: Path, dst: Path):
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


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


def run_bash(script: Path, *args: str, env=None):
    bash = shutil.which("bash")
    if not bash and os.name == "nt":
        # Git for Windows normally adds cmd/git.exe to PATH, not bin/bash.exe.
        # Resolve its shipped sibling without changing the user's PATH.
        git = shutil.which("git")
        if git:
            git_dir = Path(git).resolve().parent
            for candidate in (git_dir.parent / "bin/bash.exe", git_dir / "bash.exe"):
                if candidate.is_file():
                    bash = str(candidate)
                    break
    if not bash:
        raise RuntimeError("Bash is required for shell delivery checks; install Git Bash or expose bash on PATH")
    return subprocess.run(
        [bash, str(script), *args], cwd=str(script.parents[1]),
        env=env if env is not None else os.environ.copy(), capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=55,
    )


def build_fixture(base: Path) -> Path:
    wb = base / "fixture workbench"
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
    copy_file(REAL_MERGE, wb / "setup/merge_agent_config.py")
    copy_file(REAL_SETUP / "pi-persona-rewind.package.json", wb / "setup/pi-persona-rewind.package.json")
    # 安装器会把这个目录同步进 AgentRoot/packages；夹具必须带上，否则合并阶段会正确拒绝。
    shutil.copytree(REAL_PERSONA_PKG, wb / "Tool/prompts/packages/pi-seep-ext",
                    ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("install.sh", "update.sh", "uninstall.sh"):
        copy_file(REAL_SETUP / name, wb / "setup" / name)
    (wb / "Tool/scripts/check.py").write_text("print('task-local check ok')\n", encoding="utf-8")
    (wb / "Tool/prompts/SEEP.md").write_text("Seep Reverse Lab fixture\n", encoding="utf-8")
    (wb / "Tool/prompts/AGENTS.md").write_text("Seep Reverse Lab fixture\n", encoding="utf-8")
    (wb / "Tool/prompts/tasks/fixture.md").write_text("fixture @SEEP_ROOT@\n", encoding="utf-8")
    (wb / "Tool/prompts/agents/fixture.md").write_text("fixture\n", encoding="utf-8")
    (wb / "Tool/config/mcp-servers.json").write_text('{"servers":{}}\n', encoding="utf-8")
    return wb


class ShellRuntimeDeliveryTests(unittest.TestCase):
    def setUp(self):
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="runtime-shell-delivery-", dir=TMP_ROOT)
        self.base = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.environment = patch.dict(os.environ, isolated_environment(self.base), clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def shim_env(self, name, body):
        shim = self.base / 'shim-bin' / name
        shim.parent.mkdir(exist_ok=True)
        shim.write_text('#!/usr/bin/env bash\n' + body, encoding='utf-8', newline='\n')
        shim.chmod(0o755)
        return {**os.environ, 'PATH': str(shim.parent) + os.pathsep + os.environ['PATH']}

    def _assert_real_prompt_uninstall(self, *, keep_packages):
        wb = build_fixture(self.base)
        for name in ('AGENTS.md', 'SEEP.md'):
            copy_file(ROOT / 'Tool/prompts' / name, wb / 'Tool/prompts' / name)
        agent = self.base / 'real prompt agent'
        installed = run_bash(wb / 'setup/install.sh', '--agent-root', str(agent),
                             '--skip-packages', '--skip-python')
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        prefix, tail = 'USER PREFIX 中文\n', '\nUSER TAIL 中文\n'
        for name in ('AGENTS.md', 'SEEP.md'):
            path = agent / name
            block = path.read_text(encoding='utf-8').rstrip('\n')
            self.assertIn((wb / 'Tool/prompts' / name).read_text(encoding='utf-8').rstrip(), block)
            path.write_text(prefix + block + tail, encoding='utf-8')
        protected = {p.relative_to(agent).as_posix(): p.read_bytes() for p in agent.rglob('*')
                     if p.is_file() and (p.is_relative_to(agent / 'packages/pi-seep-ext')
                                        or p.name in ('settings.json', 'seep-install-manifest.json')
                                        and p.parent == agent)}
        flags = ('--keep-packages',) if keep_packages else ()
        removed = run_bash(wb / 'setup/uninstall.sh', '--agent-root', str(agent), '--yes', *flags)
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        for name in ('AGENTS.md', 'SEEP.md'):
            self.assertEqual((agent / name).read_text(encoding='utf-8'), prefix + tail)
        if keep_packages:
            for rel, data in protected.items():
                self.assertEqual((agent / rel).read_bytes(), data, rel)
        else:
            self.assertFalse((agent / 'packages/pi-seep-ext').exists())

    def test_uninstall_real_prompt_sources_removes_only_managed_blocks(self):
        self._assert_real_prompt_uninstall(keep_packages=False)

    def test_uninstall_real_prompt_sources_with_keep_packages(self):
        self._assert_real_prompt_uninstall(keep_packages=True)

    def test_uninstall_bad_real_prompt_boundaries_rejects_before_any_changes(self):
        wb = build_fixture(self.base)
        for name in ('AGENTS.md', 'SEEP.md'):
            copy_file(ROOT / 'Tool/prompts' / name, wb / 'Tool/prompts' / name)
        agent = self.base / 'bad real prompt agent'
        installed = run_bash(wb / 'setup/install.sh', '--agent-root', str(agent),
                             '--skip-packages', '--skip-python')
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        begin, end = '<!-- seep:managed:begin -->', '<!-- seep:managed:end -->'
        source = (wb / 'Tool/prompts/SEEP.md').read_text(encoding='utf-8')
        block = begin + '\n' + source + '\n' + end
        bad_blocks = (block + block, begin + source, source + end,
                      end + source + begin, '<!-- seep:managed:broken -->' + source + end,
                      block + '<!-- seep:managed:broken -->')
        for path in (agent / 'AGENTS.md', agent / 'SEEP.md'):
            path.write_text(path.read_text(encoding='utf-8') + '\nUSER TAIL 中文\n', encoding='utf-8')
        def snapshot():
            return {p.relative_to(agent).as_posix(): p.read_bytes() if p.is_file() else None
                    for p in agent.rglob('*')}
        for index, bad in enumerate(bad_blocks):
            for keep in (False, True):
                with self.subTest(boundary=index, keep_packages=keep):
                    (agent / 'SEEP.md').write_text(bad + '\nUSER TAIL 中文\n', encoding='utf-8')
                    before = snapshot()
                    flags = ('--keep-packages',) if keep else ()
                    removed = run_bash(wb / 'setup/uninstall.sh', '--agent-root', str(agent), '--yes', *flags)
                    self.assertNotEqual(removed.returncode, 0, removed.stdout + removed.stderr)
                    self.assertIn('invalid managed prompt boundary: SEEP.md', removed.stdout + removed.stderr)
                    self.assertNotIn('卸载完成', removed.stdout)
                    self.assertNotIn('系统已是干净状态', removed.stdout)
                    self.assertEqual(snapshot(), before)

    def test_plugin_recovery_and_owned_uninstall(self):
        import ctypes
        wb = build_fixture(self.base)
        agent = self.base / 'plugin agent'
        source = wb / 'Tool/prompts/packages/pi-seep-ext'
        def install():
            return run_bash(wb / 'setup/install.sh', '--agent-root', str(agent),
                            '--skip-packages', '--skip-python')
        dependency = source / 'lib/agent-dir.ts'
        saved = dependency.read_bytes()
        dependency.unlink()
        failed = install()
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        self.assertFalse(agent.exists())
        dependency.write_bytes(saved)
        first = install()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        target = agent / 'packages/pi-seep-ext'
        before = {p.relative_to(target).as_posix(): p.read_bytes() for p in target.rglob('*') if p.is_file()}
        manifest = json.loads((agent / 'seep-install-manifest.json').read_text())
        for rel, data in before.items():
            self.assertEqual(manifest['managed_files']['packages/pi-seep-ext/' + rel],
                             hashlib.sha256(data).hexdigest())
        notes = target / 'USER-NOTES.md'
        notes.write_bytes(b'USER DATA')
        originals = {name: (source / name).read_bytes() for name in ('LICENSE', 'UPSTREAM.json')}
        for name, data in originals.items():
            (source / name).write_bytes(data + b'\n')
        create = ctypes.windll.kernel32.CreateFileW
        create.restype = ctypes.c_void_p
        create.argtypes = (ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                           ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p)
        handle = create(str(target / 'UPSTREAM.json'), 0x80000000, 0x1, None, 3, 0, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        try:
            failed = install()
        finally:
            ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(handle))
            for name, data in originals.items():
                (source / name).write_bytes(data)
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        self.assertIn('originals restored and verified', failed.stdout)
        for rel, data in before.items():
            self.assertEqual((target / rel).read_bytes(), data)
        self.assertTrue(list(target.parent.glob('pi-seep-ext.bak-*')))
        repeated = install()
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        kept = run_bash(wb / 'setup/uninstall.sh', '--agent-root', str(agent), '--yes', '--keep-packages')
        self.assertEqual(kept.returncode, 0, kept.stdout + kept.stderr)
        self.assertTrue((target / 'extensions/persona.ts').is_file())
        retained = json.loads((agent / 'seep-install-manifest.json').read_text())
        for rel in before:
            key = 'packages/pi-seep-ext/' + rel
            self.assertEqual(retained['managed_files'][key], manifest['managed_files'][key])
        settings = agent / 'settings.json'
        local = {'source': './packages/pi-seep-ext', 'extensions': [], 'autoload': False}
        custom = {'source': 'npm:custom', 'extensions': []}
        settings.write_text(json.dumps({'packages': [local, custom]}), encoding='utf-8')
        handle = create(str(target / 'UPSTREAM.json'), 0x80000000, 0x1, None, 3, 0, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        try:
            failed = run_bash(wb / 'setup/uninstall.sh', '--agent-root', str(agent), '--yes',
                              '--keep-prompts', '--keep-skills', '--keep-mcp')
        finally:
            ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(handle))
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        self.assertEqual(json.loads(settings.read_text())['packages'], [local, custom])
        for rel, data in before.items():
            self.assertEqual((target / rel).read_bytes(), data)
        edited = target / 'extensions/persona.ts'
        edited.write_bytes(b'USER EDIT')
        removed = run_bash(wb / 'setup/uninstall.sh', '--agent-root', str(agent), '--yes',
                           '--keep-prompts', '--keep-skills', '--keep-mcp')
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assertEqual(json.loads(settings.read_text())['packages'], [custom])
        self.assertEqual(notes.read_bytes(), b'USER DATA')
        self.assertEqual(edited.read_bytes(), b'USER EDIT')
        self.assertFalse((target / 'extensions/rewind.ts').exists())

    def test_uninstall_preserves_preexisting_lab_flag_without_ownership_proof(self):
        wb = build_fixture(self.base)
        agent = self.base / 'agent with user lab flag'
        agent.mkdir()
        flag = agent / 'lab-mode.flag'
        original = b'created by the user before installation\n'
        flag.write_bytes(original)
        installed = run_bash(wb / 'setup/install.sh', '--agent-root', str(agent),
                             '--skip-packages', '--skip-python')
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        removed = run_bash(wb / 'setup/uninstall.sh', '--agent-root', str(agent), '--yes')
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assertTrue(flag.is_file(), 'uninstall deleted the user lab flag')
        self.assertEqual(flag.read_bytes(), original)
        self.assertIn('安装清单不能证明', removed.stdout)

    def test_bad_config_stops_before_replacing_assets(self):
        wb = build_fixture(self.base)
        agent = self.base / 'agent'
        for rel, bad in (('settings.json', '{"packages":{}}'),
                         ('agents/settings.json', '[]'),
                         ('mcp.json', '{"mcpServers":[]}')):
            with self.subTest(rel=rel):
                if agent.exists():
                    shutil.rmtree(agent)
                old_skill = agent / 'skills/softseep/custom.txt'
                old_skill.parent.mkdir(parents=True)
                old_skill.write_bytes(b'preserve existing tree')
                cfg = agent / rel
                cfg.parent.mkdir(parents=True, exist_ok=True)
                cfg.write_text(bad, encoding='utf-8')
                before = {str(p.relative_to(agent)): p.read_bytes() for p in agent.rglob('*') if p.is_file()}
                proc = run_bash(wb / 'setup/install.sh', '--agent-root', str(agent), '--skip-packages', '--skip-python')
                self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertEqual(before, {str(p.relative_to(agent)): p.read_bytes() for p in agent.rglob('*') if p.is_file()})

    def test_missing_dependency_archives_and_partial_unzip_fail(self):
        wb = build_fixture(self.base)
        agent = self.base / 'agent'
        proc = run_bash(wb / 'setup/install.sh', '--agent-root', str(agent), '--skip-python')
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for mod in ('js-reverse-mcp', 'playwright-mcp'):
            archive = wb / 'Tool/mcp/Tool/safe' / mod / 'node_modules.zip'
            archive.parent.mkdir(parents=True)
            archive.write_bytes(b'fixture archive; shim handles extraction')
        env = self.shim_env('unzip', 'while [ $# -gt 0 ]; do\n  if [ "$1" = -d ]; then shift; mkdir -p "$1/node_modules"; fi\n  shift\ndone\nexit 2\n')
        proc = run_bash(wb / 'setup/install.sh', '--agent-root', str(agent), '--skip-python', env=env)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse((wb / 'Tool/mcp/Tool/safe/js-reverse-mcp/node_modules').exists())
        import zipfile
        for mod in ('js-reverse-mcp', 'playwright-mcp'):
            archive = wb / 'Tool/mcp/Tool/safe' / mod / 'node_modules.zip'
            with zipfile.ZipFile(archive, 'w') as bundle:
                bundle.writestr('node_modules/fixture/index.js', '// synthetic dependency\n')
        proc = run_bash(wb / 'setup/install.sh', '--agent-root', str(agent), '--skip-python')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue((wb / 'Tool/mcp/Tool/safe/js-reverse-mcp/node_modules/fixture/index.js').is_file())
        self.assertFalse((wb / 'Tool/mcp/Tool/safe/js-reverse-mcp/node_modules/node_modules').exists())

    def test_older_python3_falls_back_to_usable_python_and_missing_root_arg_fails(self):
        wb = build_fixture(self.base)
        agent = self.base / 'agent'
        env = self.shim_env('python3', 'case "$*" in\n  *version_info*) echo 3.10; exit 1 ;;\nesac\necho 1\n')
        proc = run_bash(wb / 'setup/install.sh', '--agent-root', str(agent), '--skip-packages', '--skip-python', env=env)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        env['PI_CODING_AGENT_DIR'] = str(agent)
        for entry in ('install.sh', 'update.sh', 'uninstall.sh'):
            for args in (('--agent-root',), ('--agent-root', '--skip-packages', '--skip-python')):
                proc = run_bash(wb / 'setup' / entry, *args, env=env)
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        for entry in ('update.sh', 'uninstall.sh'):
            proc = run_bash(wb / 'setup' / entry, '--agent-root', str(agent), '--dry-run', env=env)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        proc = run_bash(wb / 'setup/uninstall.sh', '--restore', env=env)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)

    def test_skip_packages_does_not_require_pi_or_node(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        shim = self.base / "python-only"
        shim.mkdir()
        python = shim / "python"
        python.write_text(
            f'#!/usr/bin/env bash\nexec "{Path(sys.executable).as_posix()}" "$@"\n',
            encoding="utf-8", newline="\n",
        )
        python.chmod(0o755)
        env = {**os.environ, "PATH": str(shim) + ":/usr/bin:/bin"}
        installed = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                             "--skip-packages", "--skip-python", env=env)
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        self.assertIn("已跳过宿主/包检查", installed.stdout)

        blocked = run_bash(wb / "setup/install.sh", "--agent-root",
                           str(self.base / "second-agent"), env=env)
        self.assertNotEqual(blocked.returncode, 0, blocked.stdout + blocked.stderr)
        self.assertIn("Pi/Node 宿主不可用", blocked.stdout)

    def test_agents_bom_normalization_keeps_backup(self):
        wb = build_fixture(self.base)
        agent = self.base / 'agent'
        settings = agent / 'agents/settings.json'
        settings.parent.mkdir(parents=True)
        original = b'\xef\xbb\xbf{"builtInEnabled":false,"custom":{"nested":[1,2]}}'
        settings.write_bytes(original)
        proc = run_bash(wb / 'setup/install.sh', '--agent-root', str(agent), '--skip-packages', '--skip-python')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse(settings.read_bytes().startswith(b'\xef\xbb\xbf'))
        self.assertEqual(json.loads(settings.read_text(encoding='utf-8')), json.loads(original.decode('utf-8-sig')))
        backups = list(settings.parent.glob('settings.json.bak-*'))
        self.assertTrue(any(p.read_bytes() == original for p in backups))

    def test_uninstall_rejects_broken_config_and_preserves_object_packages(self):
        wb = build_fixture(self.base)
        agent = self.base / 'agent'
        installed = run_bash(wb / 'setup/install.sh', '--agent-root', str(agent), '--skip-packages', '--skip-python')
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        cfg = agent / 'settings.json'
        original = cfg.read_bytes()
        cfg.write_bytes(b'{broken')
        before = {str(p.relative_to(agent)): p.read_bytes() for p in agent.rglob('*') if p.is_file()}
        proc = run_bash(wb / 'setup/uninstall.sh', '--agent-root', str(agent), '--yes')
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(before, {str(p.relative_to(agent)): p.read_bytes() for p in agent.rglob('*') if p.is_file()})
        data = json.loads(original)
        custom = {'source': 'npm:custom-package', 'extensions': []}
        data['packages'].append(custom)
        cfg.write_text(json.dumps(data), encoding='utf-8')
        proc = run_bash(wb / 'setup/uninstall.sh', '--agent-root', str(agent), '--yes')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(json.loads(cfg.read_text(encoding='utf-8'))['packages'], [custom])

    def test_install_update_deployed_help_invalid_root_and_uninstall_dry_run(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent root with spaces"
        (agent / "mcp.json").parent.mkdir(parents=True, exist_ok=True)
        (agent / "mcp.json").write_text(
            json.dumps({"mcpServers": {"user-custom": {"command": "keep"}}}), encoding="utf-8"
        )
        (agent / "prompts").mkdir(parents=True, exist_ok=True)
        (agent / "prompts/user.md").write_text("user prompt\n", encoding="utf-8")

        installed = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                             "--skip-packages", "--skip-python")
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        origin = agent / "seep-runtime.json"
        deployed = agent / "skills/softseep/scripts/version-migrate.py"
        self.assertTrue(origin.is_file())
        self.assertEqual(sha(wb / "Tool/skill/softseep/scripts/version-migrate.py"), sha(deployed))
        self.assertEqual(json.loads(origin.read_text(encoding="utf-8"))["source_root"], str(wb.resolve()))
        self.assertTrue((agent / "agents/fixture.md").is_file())
        self.assertNotIn("@SEEP_ROOT@", (agent / "prompts/fixture.md").read_text(encoding="utf-8-sig"))

        # No ambient runtime env: deployed migration resolves the registration.
        env = os.environ.copy()
        env.pop("SEEP_RUNTIME_ROOT", None)
        env["PI_CODING_AGENT_DIR"] = str(agent)
        help_run = subprocess.run(
            ["python", "-B", str(deployed), "--help"], cwd=str(wb), env=env,
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=55,
        )
        self.assertEqual(help_run.returncode, 0, help_run.stdout + help_run.stderr)
        self.assertIn("usage:", help_run.stdout.lower())

        deployed_tree = agent / "skills/softseep"
        (deployed_tree / "legacy-marker.txt").write_bytes(b"legacy-marker-v1")
        (deployed_tree / "GUIDE.md").write_bytes(b"user modified guide v1\x00\xff")
        repeated = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                            "--skip-packages", "--skip-python")
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        backups = sorted(agent.glob("backup-install-skills-*/softseep"))
        self.assertGreaterEqual(len(backups), 1)
        self.assertEqual((backups[-1] / "legacy-marker.txt").read_bytes(), b"legacy-marker-v1")
        self.assertEqual((backups[-1] / "GUIDE.md").read_bytes(), b"user modified guide v1\x00\xff")
        (deployed_tree / "legacy-marker.txt").write_bytes(b"legacy-marker-v2")
        (deployed_tree / "GUIDE.md").write_bytes(b"user modified guide v2\x01")
        repeated_again = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                                  "--skip-packages", "--skip-python")
        self.assertEqual(repeated_again.returncode, 0, repeated_again.stdout + repeated_again.stderr)
        backups_again = sorted(agent.glob("backup-install-skills-*/softseep"))
        self.assertGreater(len(backups_again), len(backups))
        self.assertTrue(any((p / "GUIDE.md").read_bytes() == b"user modified guide v2\x01" for p in backups_again))
        self.assertEqual(sha(wb / "Tool/skill/softseep/scripts/version-migrate.py"), sha(deployed))

        updated = run_bash(wb / "setup/update.sh", "--agent-root", str(agent), "--no-pull",
                           "--skip-packages", "--skip-python", "--skip-verify")
        self.assertEqual(updated.returncode, 0, updated.stdout + updated.stderr)
        self.assertIn("user-custom", json.loads((agent / "mcp.json").read_text(encoding="utf-8"))["mcpServers"])

        before = {str(p.relative_to(agent)): sha(p) for p in agent.rglob("*") if p.is_file()}
        dry = run_bash(wb / "setup/uninstall.sh", "--agent-root", str(agent), "--dry-run")
        self.assertEqual(dry.returncode, 0, dry.stdout + dry.stderr)
        after = {str(p.relative_to(agent)): sha(p) for p in agent.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

        invalid = run_bash(wb / "setup/install.sh", "--agent-root", "C:\\",
                           "--skip-packages", "--skip-python")
        self.assertNotEqual(invalid.returncode, 0)
        self.assertEqual(before, {str(p.relative_to(agent)): sha(p) for p in agent.rglob("*") if p.is_file()})

    def test_repeat_install_updates_owned_tasks_and_agents(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        agent.mkdir()
        custom_package = {"source": "npm:synthetic-user", "extensions": []}
        (agent / "settings.json").write_text(json.dumps({"packages": [custom_package]}), encoding="utf-8")
        installed = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                             "--skip-packages", "--skip-python")
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)

        task = wb / "Tool/prompts/tasks/fixture.md"
        role = wb / "Tool/prompts/agents/fixture.md"
        task.write_text("UPDATED task @SEEP_ROOT@\n", encoding="utf-8")
        role.write_text("UPDATED role\n", encoding="utf-8")
        repeated = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                            "--skip-packages", "--skip-python")
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        packages = json.loads((agent / "settings.json").read_text(encoding="utf-8"))["packages"]
        pair = json.loads((wb / "setup/pi-persona-rewind.package.json").read_text(encoding="utf-8"))
        self.assertEqual(packages.count(pair["source"]), 1)
        self.assertIn(custom_package, packages)
        deployed = agent / "packages/pi-seep-ext"
        self.assertTrue((deployed / "extensions/persona.ts").is_file())
        self.assertTrue((deployed / "extensions/rewind.ts").is_file())
        self.assertFalse((deployed / "extensions/remote.ts").exists())

        self.assertEqual((agent / "prompts/fixture.md").read_text(encoding="utf-8"),
                         "UPDATED task " + wb.resolve().as_posix() + "\n")
        self.assertEqual((agent / "agents/fixture.md").read_text(encoding="utf-8"),
                         "UPDATED role\n")
        self.assertTrue(any(agent.glob("backup-install-tasks-*/fixture.md")))
        self.assertTrue(any(agent.glob("backup-install-extensions-*/fixture.md")))
        manifest = json.loads((agent / "seep-install-manifest.json").read_text(encoding="utf-8"))
        for relative in ("prompts/fixture.md", "agents/fixture.md"):
            self.assertEqual(manifest["managed_files"][relative], sha(agent / relative))
            self.assertNotIn(relative, manifest["preexisting_files"])

    def test_repeat_install_preserves_user_edited_or_preexisting_tasks_and_agents(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        preexisting = {
            agent / "prompts/fixture.md": "PREEXISTING task keep\n",
            agent / "agents/fixture.md": "PREEXISTING role keep\n",
        }
        for path, text in preexisting.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

        installed = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                             "--skip-packages", "--skip-python")
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        manifest = json.loads((agent / "seep-install-manifest.json").read_text(encoding="utf-8"))
        for path, text in preexisting.items():
            relative = path.relative_to(agent).as_posix()
            self.assertEqual(path.read_text(encoding="utf-8"), text)
            self.assertIn(relative, manifest["preexisting_files"])
            self.assertNotIn(relative, manifest["managed_files"])

        (wb / "Tool/prompts/tasks/fixture.md").write_text("UPDATED source task\n", encoding="utf-8")
        (wb / "Tool/prompts/agents/fixture.md").write_text("UPDATED source role\n", encoding="utf-8")
        repeated = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                            "--skip-packages", "--skip-python")
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        for path, text in preexisting.items():
            self.assertEqual(path.read_text(encoding="utf-8"), text)

    def test_failed_skill_update_does_not_claim_unpublished_source_files(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        installed = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                             "--skip-packages", "--skip-python")
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        deployed = agent / "skills/softseep/SKILL.md"
        old_digest = sha(deployed)
        source = wb / "Tool/skill/softseep/SKILL.md"
        source.write_text("# unpublished replacement\n", encoding="utf-8")
        unpublished = wb / "Tool/skill/softseep/UNPUBLISHED.txt"
        unpublished.write_text("must not be claimed after rollback\n", encoding="utf-8")

        env = {**os.environ, "SEEP_INTERNAL_TEST_FAIL_SKILL_COPY": "softseep"}
        failed = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                          "--skip-packages", "--skip-python", env=env)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(sha(deployed), old_digest)
        self.assertFalse((agent / "skills/softseep/UNPUBLISHED.txt").exists())
        manifest = json.loads((agent / "seep-install-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "incomplete")
        self.assertEqual(manifest["managed_files"].get("skills/softseep/SKILL.md"), old_digest)
        self.assertNotIn("skills/softseep/UNPUBLISHED.txt", manifest["managed_files"])

        recovered = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                             "--skip-packages", "--skip-python")
        self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
        self.assertEqual(sha(deployed), sha(source))
        manifest = json.loads((agent / "seep-install-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["managed_files"]["skills/softseep/UNPUBLISHED.txt"],
                         sha(unpublished))

    def test_install_excludes_runtime_caches_from_copy_and_manifest(self):
        wb = build_fixture(self.base)
        cache = wb / "Tool/skill/softseep/scripts/__pycache__/fixture.cpython-312.pyc"
        cache.parent.mkdir(parents=True)
        cache.write_bytes(b"host-specific bytecode")
        agent = self.base / "agent with spaces"

        installed = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                             "--skip-packages", "--skip-python")
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        self.assertFalse((agent / "skills/softseep/scripts/__pycache__").exists())
        manifest = json.loads((agent / "seep-install-manifest.json").read_text(encoding="utf-8"))
        self.assertFalse(any("__pycache__" in rel or rel.endswith((".pyc", ".pyo"))
                             for rel in manifest["managed_files"]))

    def test_registration_tamper_uses_install_manifest_without_trusting_runtime(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        installed = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                             "--skip-packages", "--skip-python")
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        origin = agent / "seep-runtime.json"
        before_origin = origin.read_bytes()
        unrelated = self.base / "unrelated-entry.py"
        shutil.copy2(wb / "Tool/skill/softseep/scripts/version-migrate.py", unrelated)
        negative = subprocess.run(
            ["python", "-B", str(wb / "Tool/scripts/runtime-root.py"), "register",
             "--agent-root", str(agent), "--runtime-root", str(wb),
             "--entry-source", str(unrelated),
             "--entry-dest", str(agent / "skills/softseep/scripts/version-migrate.py")],
            cwd=str(wb), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=55,
        )
        self.assertNotEqual(negative.returncode, 0)
        self.assertEqual(origin.read_bytes(), before_origin)
        data = json.loads(origin.read_text(encoding="utf-8"))
        data["source_root"] = str(self.base / "wrong-source")
        origin.write_text(json.dumps(data), encoding="utf-8")
        refused = run_bash(wb / "setup/uninstall.sh", "--agent-root", str(agent), "--dry-run")
        self.assertEqual(refused.returncode, 0, refused.stdout + refused.stderr)
        self.assertIn("依据安装所有权清单", refused.stdout)
        self.assertTrue(origin.exists())

    def test_update_default_verify_runs_from_root_and_failures_propagate(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        check = wb / "Tool/scripts/check.py"
        check.write_text("import os\nfrom pathlib import Path\nassert Path.cwd() == Path(__file__).resolve().parents[2]\nassert Path(os.environ['PI_CODING_AGENT_DIR']).resolve() == Path(" + repr(str(agent)) + ").resolve()\nPath('verify-root.txt').write_text('verified')\n", encoding="utf-8")
        installed = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                             "--skip-packages", "--skip-python")
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        (wb / "verify-root.txt").unlink()
        updated = run_bash(wb / "setup/update.sh", "--agent-root", str(agent),
                           "--no-pull", "--skip-packages", "--skip-python")
        self.assertEqual(updated.returncode, 0, updated.stdout + updated.stderr)
        self.assertTrue((wb / "verify-root.txt").is_file())
        check.write_text("raise SystemExit(9)\n", encoding="utf-8")
        failed = run_bash(wb / "setup/update.sh", "--agent-root", str(agent),
                          "--no-pull", "--skip-packages", "--skip-python")
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        self.assertNotIn("Seep 工作台更新完成:", failed.stdout)

    def _init_update_repo(self, wb: Path):
        remote = self.base / ("remote-" + wb.name + ".git")
        subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
        (wb / "Tool/cases/.keep").write_text("fixture\n", encoding="utf-8")
        (wb / "conflict.txt").write_text("base\n", encoding="utf-8")
        for args in (("init", "-b", "main"), ("add", ".")):
            subprocess.run(["git", "-C", str(wb), *args], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(wb), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid",
                        "commit", "-m", "fixture"], check=True, capture_output=True)
        for args in (("remote", "add", "origin", str(remote)), ("push", "-u", "origin", "main")):
            subprocess.run(["git", "-C", str(wb), *args], check=True, capture_output=True)
        return remote

    def test_update_restores_automatic_stash_after_success(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        self._init_update_repo(wb)
        changed = wb / "user-change.txt"
        changed.write_text("local work\n", encoding="utf-8")
        proc = run_bash(wb / "setup/update.sh", "--agent-root", str(agent),
                        "--skip-packages", "--skip-python", "--skip-verify")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(changed.read_text(encoding="utf-8"), "local work\n")
        stash = subprocess.run(["git", "-C", str(wb), "stash", "list"],
                               capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(stash.stdout.strip(), "")

    def test_update_stash_conflict_is_nonzero_and_preserves_stash(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        self._init_update_repo(wb)
        (wb / "conflict.txt").write_text("remote\n", encoding="utf-8")
        for args in (("add", "conflict.txt"),
                     ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                      "commit", "-m", "remote"),
                     ("push", "origin", "main"),
                     ("reset", "--hard", "HEAD^")):
            subprocess.run(["git", "-C", str(wb), *args], check=True, capture_output=True)
        (wb / "conflict.txt").write_text("local\n", encoding="utf-8")
        proc = run_bash(wb / "setup/update.sh", "--agent-root", str(agent),
                        "--skip-packages", "--skip-python", "--skip-verify")
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("已明确保留", proc.stdout + proc.stderr)
        self.assertIn("stash apply", proc.stdout + proc.stderr)
        self.assertNotIn("Seep 工作台更新完成:", proc.stdout)
        stash = subprocess.run(["git", "-C", str(wb), "stash", "list"],
                               capture_output=True, text=True, encoding="utf-8")
        self.assertNotEqual(stash.stdout.strip(), "")

    def test_failed_git_pull_stops_before_install(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        for args in (("init", "-b", "main"), ("add", "."),
                     ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture"),
                     ("remote", "add", "origin", str(self.base / "missing-remote"))):
            subprocess.run(["git", "-C", str(wb), *args], check=True, capture_output=True)
        (wb / "setup/install.sh").write_text("#!/usr/bin/env bash\ntouch \"$(dirname \"$0\")/should-not-install\"\nexit 0\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(wb), "add", "."], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(wb), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-m", "fixture installer"], check=True, capture_output=True)
        proc = run_bash(wb / "setup/update.sh", "--agent-root", str(agent), "--skip-verify")
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse((wb / "setup/should-not-install").exists())

    def test_update_detects_protected_content_change_and_unreadable_mcp(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        agent.mkdir()
        protected = agent / "lab-mode.flag"
        protected.write_text("enabled", encoding="utf-8")
        cfg = agent / "mcp.json"
        cfg.write_text('{"mcpServers":{"user":{"command":"keep"}}}', encoding="utf-8")
        (wb / "setup/install.sh").write_text(
            '#!/usr/bin/env bash\nprintf changed > "$PI_CODING_AGENT_DIR/lab-mode.flag"\nexit 0\n', encoding="utf-8")
        result = run_bash(wb / "setup/update.sh", "--agent-root", str(agent), "--no-pull", "--skip-verify")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Seep 工作台更新完成:", result.stdout)
        cfg.write_text('{"mcpServers":["invalid"]}', encoding="utf-8")
        (wb / "setup/install.sh").write_text(
            '#!/usr/bin/env bash\ntouch "$(dirname "$0")/should-not-install"\nexit 0\n', encoding="utf-8")
        result = run_bash(wb / "setup/update.sh", "--agent-root", str(agent), "--no-pull", "--skip-verify")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((wb / "setup/should-not-install").exists())

    def test_archive_update_does_not_initialize_git_or_report_success(self):
        from unittest.mock import patch
        wb = build_fixture(self.base)
        (wb / "setup/install.sh").write_text("exit 0\n", encoding="utf-8")
        with patch.dict(os.environ, {"SEEP_REPO_URL": str(self.base / "missing-remote")}):
            proc = run_bash(wb / "setup/update.sh", "--agent-root", str(self.base / "agent"), "--skip-verify")
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("Seep 工作台更新完成:", proc.stdout)
        self.assertFalse((wb / ".git").exists())

    def test_uninstall_cleans_dynamic_mcp_list_and_preserves_pending(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        (wb / "Tool/skill/_pending").mkdir()
        entries = {"seep": {"command": "python", "args": ["{ROOT_POSIX}/Tool/mcp/seep_mcp_server.py"]},
                   "ida": {"command": "python", "args": ["{ROOT_POSIX}/Tool/scripts/mcp-launch.py", "--server", "ida"]},
                   "x64dbg": {"command": "python", "args": ["{ROOT_POSIX}/Tool/scripts/mcp-launch.py", "--server", "x64dbg"]}}
        (wb / "Tool/config/mcp-servers.json").write_text(json.dumps({"servers":entries}), encoding="utf-8")
        installed = run_bash(wb / "setup/install.sh", "--agent-root", str(agent), "--skip-packages", "--skip-python")
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        cfg = agent / "mcp.json"
        data = json.loads(cfg.read_text(encoding="utf-8"))
        data["mcpServers"]["user-custom"] = {"command":"keep"}
        cfg.write_text(json.dumps(data), encoding="utf-8")
        custom = agent / "skills/_pending/user.txt"
        custom.parent.mkdir()
        custom.write_text("user-owned", encoding="utf-8")
        removed = run_bash(wb / "setup/uninstall.sh", "--agent-root", str(agent), "--yes")
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assertEqual(json.loads(cfg.read_text(encoding="utf-8"))["mcpServers"], {"user-custom":{"command":"keep"}})
        self.assertTrue(custom.is_file())

    def test_partial_uninstall_without_runtime_preserves_same_name_user_assets(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        user_task = agent / "prompts/fixture.md"
        user_agent = agent / "agents/fixture.md"
        user_settings = agent / "agents/settings.json"
        user_task_text = f"fixture {wb.resolve().as_posix()}\n"
        for path, text in (
            (user_task, user_task_text),
            (user_agent, "USER AGENT\n"),
            (user_settings, '{"builtInEnabled":false,"custom":"keep"}\n'),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        installed = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                             "--skip-packages", "--skip-python")
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        user_skill_file = agent / "skills/softseep/user-owned.txt"
        user_skill_file.write_text("user-owned\n", encoding="utf-8")
        (agent / "seep-runtime.json").write_text("{broken", encoding="utf-8")

        removed = run_bash(wb / "setup/uninstall.sh", "--agent-root", str(agent), "--yes")
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
        second_install = run_bash(wb / "setup/install.sh", "--agent-root", str(missing_agent),
                                  "--skip-packages", "--skip-python")
        self.assertEqual(second_install.returncode, 0,
                         second_install.stdout + second_install.stderr)
        missing_user_file = missing_agent / "skills/softseep/user-missing-runtime.txt"
        missing_user_file.write_text("user-owned\n", encoding="utf-8")
        (missing_agent / "seep-runtime.json").unlink()
        missing_removed = run_bash(wb / "setup/uninstall.sh",
                                   "--agent-root", str(missing_agent), "--yes")
        self.assertEqual(missing_removed.returncode, 0,
                         missing_removed.stdout + missing_removed.stderr)
        self.assertIn("依据安装所有权清单", missing_removed.stdout)
        self.assertFalse((missing_agent / "skills/softseep/pack.json").exists())
        self.assertEqual(missing_user_file.read_text(encoding="utf-8"), "user-owned\n")

    def test_uninstall_cleans_owned_tasks_agents_and_default_agent_settings(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        installed = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                             "--skip-packages", "--skip-python")
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        manifest = json.loads((agent / "seep-install-manifest.json").read_text(encoding="utf-8"))
        owned = [
            agent / "prompts/fixture.md",
            agent / "agents/fixture.md",
            agent / "agents/settings.json",
        ]
        self.assertTrue(all(path.is_file() for path in owned))
        self.assertEqual(manifest["managed_files"]["prompts/fixture.md"], sha(owned[0]))
        user_task = agent / "prompts/user-task.md"
        user_agent = agent / "agents/user-agent.md"
        user_empty_skill = agent / "skills/user-empty-skill"
        user_task.write_text("user task\n", encoding="utf-8")
        user_agent.write_text("user agent\n", encoding="utf-8")
        user_empty_skill.mkdir()

        removed = run_bash(wb / "setup/uninstall.sh", "--agent-root", str(agent), "--yes")
        self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
        self.assertTrue(all(not path.exists() for path in owned),
                        {str(path): path.exists() for path in owned})
        self.assertEqual(user_task.read_text(encoding="utf-8"), "user task\n")
        self.assertEqual(user_agent.read_text(encoding="utf-8"), "user agent\n")
        self.assertTrue(user_empty_skill.is_dir(), removed.stdout + removed.stderr)

    def test_uninstall_without_runtime_or_manifest_preserves_same_content_user_assets(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        fixture_task = f"fixture {wb.resolve().as_posix()}\n"
        assets = {
            agent / "prompts/fixture.md": fixture_task,
            agent / "agents/fixture.md": "fixture\n",
            agent / "skills/softseep/pack.json": (wb / "Tool/skill/softseep/pack.json").read_text(encoding="utf-8"),
            agent / "extensions/fixture.ts": "// Seep Reverse Lab user extension\n",
        }
        for path, text in assets.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        source_extension = wb / "Tool/prompts/extensions/fixture.ts"
        source_extension.parent.mkdir(parents=True)
        source_extension.write_text("// Seep Reverse Lab user extension\n", encoding="utf-8")

        proc = run_bash(wb / "setup/uninstall.sh", "--agent-root", str(agent), "--yes")

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for path in assets:
            self.assertTrue(path.is_file(), f"unproven user asset was removed: {path}\n{proc.stdout}{proc.stderr}")

    def test_extension_copy_failure_is_not_reported_as_install_success(self):
        import ctypes
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        source = wb / "Tool/prompts/extensions/fixture.ts"
        source.parent.mkdir(parents=True)
        source.write_text("// Seep Reverse Lab fixture\n", encoding="utf-8")
        proc = run_bash(wb / "setup/install.sh", "--agent-root", str(agent), "--skip-packages", "--skip-python")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        deployed = agent / "extensions/fixture.ts"
        old = deployed.read_bytes()
        source.write_text("// Seep Reverse Lab new fixture\n", encoding="utf-8")
        create = ctypes.windll.kernel32.CreateFileW
        create.restype = ctypes.c_void_p
        create.argtypes = (ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                           ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p)
        # FILE_SHARE_READ lets the installer create its backup. Withholding
        # write/delete sharing then makes the atomic replacement fail, which
        # exercises rollback instead of failing before the backup is captured.
        handle = create(str(deployed), 0x80000000, 0x1, None, 3, 0, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        try:
            proc = run_bash(wb / "setup/install.sh", "--agent-root", str(agent), "--skip-packages", "--skip-python")
        finally:
            ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(handle))
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(deployed.read_bytes(), old)
        self.assertFalse(list((agent / "extensions").glob(".seep-extension-*")))
        backups = list(agent.glob("backup-install-extensions-*/fixture.ts"))
        self.assertTrue(any(path.read_bytes() == old for path in backups))

    def test_skill_copy_failure_restores_backup_and_returns_failure(self):
        wb = build_fixture(self.base)
        agent = self.base / "agent"
        installed = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                             "--skip-packages", "--skip-python")
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        deployed = agent / "skills/softseep"
        old_skill = (deployed / "SKILL.md").read_bytes()
        marker = deployed / "user-marker.txt"
        marker.write_text("preserve in backup\n", encoding="utf-8")
        (wb / "Tool/skill/softseep/SKILL.md").write_text(
            "# SoftSeep replacement must not land\n", encoding="utf-8")
        env = {**os.environ, "SEEP_INTERNAL_TEST_FAIL_SKILL_COPY": "softseep"}
        proc = run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                        "--skip-packages", "--skip-python", env=env)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((deployed / "SKILL.md").read_bytes(), old_skill)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve in backup\n")
        backups = sorted(agent.glob("backup-install-skills-*/softseep"))
        self.assertTrue(any((path / "user-marker.txt").is_file() for path in backups))


if __name__ == "__main__":
    unittest.main()
