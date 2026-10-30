#!/usr/bin/env python3
"""Retry command regressions using Node's native TypeScript stripping (no Pi SDK).

Run: python Tool/scripts/test_retry_levels.py
Missing Node or unsupported type stripping fails visibly instead of skipping.
The real registered handler writes only synthetic settings. The reload callback
reloads those settings into a test host; real SDK reload acceptance is separate.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
EXTENSION = ROOT / "Tool/prompts/extensions/retry-level.ts"

HARNESS = r'''
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {syncBuiltinESMExports} from "node:module";
import {pathToFileURL} from "node:url";

const [extension, scenario] = process.argv.slice(2);
const fixtureAgent = process.env.PI_CODING_AGENT_DIR;
const settingsPath = path.join(fixtureAgent, "settings.json");
if (scenario === "tilde-root") {
  // Keep both the configured root and the homedir fallback inside this fixture.
  os.homedir = () => path.dirname(fixtureAgent);
  process.env.PI_CODING_AGENT_DIR = "~/" + path.basename(fixtureAgent);
}
const initial = {
  theme: "preserve", custom: {nested: ["keep", 42]},
  retry: {enabled: false, maxRetries: 3, custom: "keep-retry",
    provider: {timeoutMs: 12345, custom: "keep-provider"}},
};
fs.writeFileSync(settingsPath, JSON.stringify(initial, null, 2));
const read = () => JSON.parse(fs.readFileSync(settingsPath, "utf8"));
let live = read(), reloads = 0, mutations = 0, selections = 0;
// Count mutation attempts as well as checking bytes: an invalid command must
// not rewrite identical settings or create temporary candidates.
for (const name of ["openSync", "writeFileSync", "renameSync", "unlinkSync"]) {
  const original = fs[name];
  fs[name] = (...args) => {
    if (String(args[0]).startsWith(settingsPath) &&
        (name !== "openSync" || /[wa+]/.test(String(args[1])))) mutations++;
    return original(...args);
  };
}
syncBuiltinESMExports();
const commands = new Map(), statuses = [], notices = [];
const {default: extensionFactory} = await import(pathToFileURL(extension).href);
extensionFactory({registerCommand: (name, command) => commands.set(name, command), on() {}});
const command = commands.get("retry");
assert.equal(typeof command?.handler, "function", "real /retry handler must register");
const ctx = {
  hasUI: true,
  ui: {
    setStatus: (...args) => statuses.push(args),
    notify: (message, level) => notices.push({message, level}),
    select: async () => { selections++; return undefined; },
  },
  reload: async () => { reloads++; live = read(); },
};
function preserved(saved) {
  assert.deepEqual(saved.custom, initial.custom);
  assert.equal(saved.theme, initial.theme);
  assert.equal(saved.retry.custom, initial.retry.custom);
  assert.equal(saved.retry.provider.custom, initial.retry.provider.custom);
  assert.equal(saved.retry.provider.timeoutMs, initial.retry.provider.timeoutMs);
}
async function changed(arg, enabled) {
  const previousReloads = reloads;
  await command.handler(arg, ctx);
  const saved = read();
  assert.equal(saved.retry.enabled, enabled, `/retry ${arg}: saved enabled`);
  assert.equal(saved.retry.maxRetries, 3, `/retry ${arg}: saved maxRetries`);
  assert.equal(reloads, previousReloads + 1, "successful change must await reload");
  assert.deepEqual(live, saved, "test host must see saved settings after reload");
  assert.equal(notices.at(-1)?.level, "info");
  assert.equal(statuses.at(-1)?.[0], "command:/retry");
  preserved(saved);
}
async function unchanged(arg, expectNotice) {
  const bytes = fs.readFileSync(settingsPath), previousLive = structuredClone(live);
  const previousReloads = reloads, previousMutations = mutations;
  const previousStatuses = statuses.length, previousNotices = notices.length;
  await command.handler(arg, ctx);
  assert.ok(fs.readFileSync(settingsPath).equals(bytes), "original settings bytes must survive");
  assert.equal(mutations, previousMutations, "no settings write attempts");
  assert.equal(reloads, previousReloads, "no reload for cancelled/invalid input");
  assert.deepEqual(live, previousLive);
  assert.equal(statuses.length, previousStatuses);
  assert.equal(notices.length, previousNotices + (expectNotice ? 1 : 0));
  if (expectNotice) assert.equal(notices.at(-1).level, "warning");
}
if (scenario === "direct3-off" || scenario === "tilde-root") {
  await changed("3", true);
  await changed("off", false);
  await changed("3", true);
  assert.equal(selections, 0, "direct arguments must not open the menu");
} else if (scenario === "menu-cancel") {
  await unchanged("", false);
  assert.equal(selections, 1, "no arguments must open the menu");
} else if (scenario === "invalid") {
  await unchanged("4", true);
  await unchanged("invalid", true);
  assert.equal(selections, 0);
} else {
  assert.fail(`unknown scenario: ${scenario}`);
}
console.log(`PASS ${scenario}`);
'''


class RetryLevels(unittest.TestCase):
    def run_scenario(self, scenario, *, standalone=False):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node with --experimental-strip-types is required")
        with tempfile.TemporaryDirectory(prefix="seep-retry-levels-") as folder:
            fixture = Path(folder)
            agent_dir = fixture / "agent"
            agent_dir.mkdir()
            script = fixture / "retry-levels.mjs"
            script.write_text(HARNESS, encoding="utf-8")
            extension = EXTENSION
            if standalone:
                extension = agent_dir / "extensions/retry-level.ts"
                extension.parent.mkdir()
                shutil.copy2(EXTENSION, extension)
            env = dict(os.environ, PI_CODING_AGENT_DIR=str(agent_dir), NODE_NO_WARNINGS="1")
            # Do not inherit host preload hooks into this isolated Node process.
            env.pop("NODE_OPTIONS", None)
            result = subprocess.run(
                [node, "--experimental-strip-types", str(script), str(extension), scenario],
                cwd=fixture, env=env, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(f"PASS {scenario}", result.stdout)

    def test_direct_three_enables_retry_and_off_disables_it(self):
        self.run_scenario("direct3-off")

    def test_menu_cancellation_preserves_settings_without_reload(self):
        self.run_scenario("menu-cancel")

    def test_invalid_arguments_preserve_settings_without_reload(self):
        self.run_scenario("invalid")

    def test_tilde_agent_root_updates_the_selected_settings(self):
        self.run_scenario("tilde-root")

    def test_standalone_delivery_needs_no_companion_package(self):
        self.run_scenario("tilde-root", standalone=True)

    def assert_retry_retained_after_package_uninstall(self, platform):
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from Tool.scripts import test_runtime_install_delivery as ps
        from Tool.scripts import test_runtime_shell_delivery as sh
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node with --experimental-strip-types is required")
        with tempfile.TemporaryDirectory(prefix="seep-retained-retry-") as folder:
            base = Path(folder)
            agent = base / "agent"
            env = ps.isolated_environment(base)
            env.update(PI_CODING_AGENT_DIR=str(agent), NODE_NO_WARNINGS="1")
            env.pop("NODE_OPTIONS", None)
            wb = (ps.build_workbench if platform == "powershell" else sh.build_fixture)(base)
            source = wb / "Tool/prompts/extensions/retry-level.ts"
            source.parent.mkdir()
            shutil.copy2(EXTENSION, source)
            if platform == "powershell":
                installed = ps.run_ps(wb / "setup/install-pi.ps1", "-AgentRoot", str(agent),
                                      "-SkipPackages", env=env)
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                removed = ps.run_ps(wb / "setup/uninstall.ps1", "-AgentRoot", str(agent),
                                    "-Yes", "-KeepPrompts", env=env)
            else:
                installed = sh.run_bash(wb / "setup/install.sh", "--agent-root", str(agent),
                                        "--skip-packages", "--skip-python", env=env)
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                removed = sh.run_bash(wb / "setup/uninstall.sh", "--agent-root", str(agent),
                                      "--yes", "--keep-prompts", env=env)
            self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
            delivered = agent / "extensions/retry-level.ts"
            self.assertTrue(delivered.is_file())
            self.assertFalse((agent / "packages/pi-seep-ext").exists())
            script = base / "retained-retry.mjs"
            script.write_text(r'''
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {pathToFileURL} from "node:url";
const {default: factory} = await import(pathToFileURL(process.argv[2]));
let retry, reloads=0;
factory({on(){},registerCommand(name, command){if(name==="retry")retry=command;}});
await retry.handler("3",{hasUI:true,ui:{notify(){},setStatus(){}},reload:async()=>{reloads++;}});
const settings=JSON.parse(fs.readFileSync(path.join(process.env.PI_CODING_AGENT_DIR,"settings.json"),"utf8"));
assert.equal(settings.retry.enabled,true);
assert.equal(settings.retry.maxRetries,3);
assert.equal(reloads,1);
''', encoding="utf-8")
            result = subprocess.run([node, "--experimental-strip-types",
                                     str(script), str(delivered)], cwd=base, env=env,
                                    capture_output=True, text=True, encoding="utf-8", timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_powershell_package_uninstall_keeps_independent_retry_working(self):
        self.assert_retry_retained_after_package_uninstall("powershell")

    def test_bash_package_uninstall_keeps_independent_retry_working(self):
        self.assert_retry_retained_after_package_uninstall("bash")


if __name__ == "__main__":
    unittest.main()
