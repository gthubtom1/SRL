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
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
EXTENSION = ROOT / "Tool/prompts/extensions/retry-level.ts"

HARNESS = r'''
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {syncBuiltinESMExports} from "node:module";
import {pathToFileURL} from "node:url";

const [extension, scenario] = process.argv.slice(2);
const settingsPath = path.join(process.env.PI_CODING_AGENT_DIR, "settings.json");
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
if (scenario === "direct3-off") {
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
    def run_scenario(self, scenario):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node with --experimental-strip-types is required")
        with tempfile.TemporaryDirectory(prefix="seep-retry-levels-") as folder:
            fixture = Path(folder)
            agent_dir = fixture / "agent"
            agent_dir.mkdir()
            script = fixture / "retry-levels.mjs"
            script.write_text(HARNESS, encoding="utf-8")
            env = dict(os.environ, PI_CODING_AGENT_DIR=str(agent_dir), NODE_NO_WARNINGS="1")
            # Do not inherit host preload hooks into this isolated Node process.
            env.pop("NODE_OPTIONS", None)
            result = subprocess.run(
                [node, "--experimental-strip-types", str(script), str(EXTENSION), scenario],
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


if __name__ == "__main__":
    unittest.main()
