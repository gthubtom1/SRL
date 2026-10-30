// Isolated real-SDK acceptance. No credentials, remote extension, or model API.
// node setup/test_persona_rewind_sdk.mjs <sdk-package-dir> [--extensions-only]
// Optional PERSONA_AUDIT_DIR retains synthetic evidence; scratch is always removed.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import { syncBuiltinESMExports } from "node:module";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const sdkRoot = resolve(process.argv[2] || "missing-sdk-directory");
const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const vendored = join(repoRoot, "Tool/prompts/packages/pi-seep-ext");
const declaration = JSON.parse(fs.readFileSync(join(repoRoot, "setup/pi-persona-rewind.package.json"), "utf8"));
const scratch = fs.mkdtempSync(join(os.tmpdir(), "seep-persona-rewind-"));
const agentDir = join(scratch, "agent");
const project = join(scratch, "project");
const auditDir = process.env.PERSONA_AUDIT_DIR && resolve(process.env.PERSONA_AUDIT_DIR);
fs.mkdirSync(join(agentDir, "personas"), { recursive: true });
fs.mkdirSync(project, { recursive: true });
fs.mkdirSync(join(scratch, "home"), { recursive: true });
process.env.PI_CODING_AGENT_DIR = agentDir;
process.env.PI_OFFLINE = "1";
os.homedir = () => join(scratch, "home");
const nativeRead = fs.readFileSync;
const forbiddenReads = [];
fs.readFileSync = (file, ...args) => {
  const path = String(file).replaceAll("\\", "/");
  if (!path.startsWith(scratch.replaceAll("\\", "/")) &&
      /\/personas\/|\/(?:auth|models)\.json$|\/(?:PERSONALITY|RULES|SEEP)\.md$/i.test(path)) {
    forbiddenReads.push(path);
    throw new Error("Non-fixture private file read denied");
  }
  return nativeRead(file, ...args);
};
syncBuiltinESMExports();
let networkCalls = 0;
globalThis.fetch = async () => { networkCalls++; throw new Error("Network forbidden in persona acceptance"); };
const deadline = setTimeout(() => { console.error("FAIL: persona acceptance exceeded 180s"); process.exit(1); }, 180000);
const results = [], captures = [], sessions = new Set();
const record = (name, data = {}) => { results.push({ name, ...data }); console.log(`  ok  ${name}`); };
let sdkVersion;
try {
  sdkVersion = JSON.parse(fs.readFileSync(join(sdkRoot, "package.json"), "utf8")).version;
  assert.match(sdkVersion, /^1\.(2|4)\./);
  const sdk = await import(pathToFileURL(join(sdkRoot, "dist/index.js")));
  const { loadExtensions } = await import(pathToFileURL(join(sdkRoot, "dist/core/extensions/loader.js")));
  const { buildSystemPrompt, buildSystemPromptState } = await import(pathToFileURL(join(sdkRoot, "dist/core/system-prompt.js")));
  const ai = await import(pathToFileURL(join(dirname(sdkRoot), "pi-ai/dist/index.js")));
  assert.equal(declaration.source, "./packages/pi-seep-ext");
  assert.deepEqual(declaration.commands, ["persona", "rewind", "undo-reply"]);
  assert.deepEqual(declaration.extensions, ["extensions/persona.ts", "extensions/rewind.ts"]);
  const deployed = join(agentDir, "packages/pi-seep-ext");
  if (process.argv.includes("--extensions-only")) {
    fs.cpSync(vendored, deployed, { recursive: true });
    fs.writeFileSync(join(agentDir, "settings.json"), JSON.stringify({ packages: [declaration.source] }));
    record("fixture-copy-without-installer", { installerTested: false });
  } else {
    const custom = { source: join(scratch, "user-package"), extensions: [], skills: [] };
    fs.mkdirSync(custom.source);
    fs.writeFileSync(join(custom.source, "package.json"), JSON.stringify({ name: "synthetic-user", pi: {} }));
    fs.writeFileSync(join(agentDir, "settings.json"), JSON.stringify({ packages: [custom], userValue: "keep" }));
    for (let i = 0; i < 2; i++) {
      execFileSync(process.env.PYTHON || "python", [join(repoRoot, "setup/merge_agent_config.py"),
        "--root", repoRoot, "--agent-dir", agentDir, "--persona-rewind-only"],
      { encoding: "utf8", timeout: 30000, env: { ...process.env, PYTHONIOENCODING: "utf-8" } });
      const saved = JSON.parse(fs.readFileSync(join(agentDir, "settings.json"), "utf8"));
      assert.deepEqual(saved.packages, [custom, declaration.source]);
      assert.equal(saved.userValue, "keep");
    }
    record("installer-deploy-idempotent", { installerTested: true });
  }
  assert.deepEqual(fs.readdirSync(join(deployed, "extensions")).sort(), ["persona.ts", "rewind.ts"]);
  const settingsManager = sdk.SettingsManager.create(project, agentDir);
  const loader = new sdk.DefaultResourceLoader({ cwd: project, agentDir, settingsManager,
    noContextFiles: true, noSkills: true, noPromptTemplates: true, noThemes: true });
  await loader.reload();
  const loaded = loader.getExtensions();
  assert.deepEqual(loaded.errors, []);
  assert.deepEqual(loaded.warnings || [], []);
  assert.deepEqual(loaded.extensions.map((e) => e.resolvedPath.replaceAll("\\", "/")).sort(),
    declaration.extensions.map((rel) => join(deployed, rel).replaceAll("\\", "/")).sort());
  assert.deepEqual(loaded.extensions.flatMap((e) => [...e.commands.keys()]).sort(), ["persona", "rewind", "undo-reply"]);
  record("real-package-loader-two-extensions");

  const model = { id: "synthetic", name: "synthetic", provider: "synthetic", api: "openai-completions",
    reasoning: false, input: ["text", "image"], baseUrl: "http://invalid.invalid",
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 100000, maxTokens: 100 };
  const literal = "A<personality>literal</personality>  B\r\nC";
  const image = { type: "image", mimeType: "image/png", data: "c3ludGhldGljLWltYWdl" };
  const reply = (content = [{ type: "text", text: literal }]) => ({ role: "assistant", content,
    api: model.api, provider: model.provider, model: model.id, stopReason: "stop", timestamp: 4,
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } } });
  let pendingTool = false;
  const runtime = new Proxy({ getModel: () => model, getPhysicalModel: () => model,
    getAvailableSnapshot: () => [model], hasConfiguredAuth: () => true,
    streamSimple: (_model, context) => {
      captures.push(structuredClone(context));
      const message = reply();
      if (pendingTool) {
        pendingTool = false;
        message.content = [{ type: "toolCall", id: "synthetic-call", name: "synthetic_probe", arguments: {} }];
        message.stopReason = "toolUse";
      }
      return { async *[Symbol.asyncIterator]() { yield { type: "done", reason: message.stopReason, message }; },
        result: async () => message };
    },
  }, { get: (object, key) => key in object ? object[key] : (() => undefined) });
  const paths = { persona: join(deployed, "extensions/persona.ts"), rewind: join(deployed, "extensions/rewind.ts"),
    load: join(repoRoot, "Tool/prompts/extensions/load-system-prompt.ts") };
  const settingsFile = join(agentDir, "personas.json");
  const settings = (mode = "cached", defaultId = null) => fs.writeFileSync(settingsFile, JSON.stringify({ mode, defaultId, unknownKey: "keep" }));
  for (const [name, text] of Object.entries({ "alpha.md": "SYNTH_ALPHA_CARD", "beta.md": "SYNTH_BETA_CARD" })) {
    fs.writeFileSync(join(agentDir, "personas", name), text + "\r\n");
  }
  fs.writeFileSync(join(agentDir, "RULES.md"), "SYNTH_GLOBAL_RULES");
  fs.writeFileSync(join(project, "RULES.md"), "SYNTH_PROJECT_RULES");
  fs.writeFileSync(join(project, "SEEP.md"), "SYNTH_SEEP_RULES");
  fs.writeFileSync(join(project, "PERSONALITY.md"), "SYNTH_LEGACY_PERSONALITY");
  const contextFiles = [{ path: join(project, "SYNTH_CONTEXT.md"), content: "SYNTH_PROJECT_CONTEXT\n<personality>project literal</personality>" }];
  async function harness(order, persistent = false, reopen) {
    const extensions = await loadExtensions(order.map((name) => paths[name]), project);
    assert.deepEqual(extensions.errors, []);
    const resourceLoader = { getExtensions: () => extensions, getSkills: () => ({ skills: [], diagnostics: [] }),
      getPrompts: () => ({ prompts: [], diagnostics: [] }), getThemes: () => ({ themes: [], diagnostics: [] }),
      getAgentsFiles: () => ({ agentsFiles: contextFiles }), getSystemPrompt: () => "SYNTH_BASE",
      getSystemPromptSource: () => undefined, getAppendSystemPrompt: () => [], getAppendSystemPromptSources: () => [],
      extendResources() {}, reload: async () => {} };
    const sm = reopen ? sdk.SessionManager.open(reopen) : persistent
      ? sdk.SessionManager.create(project, join(scratch, "sessions")) : sdk.SessionManager.inMemory(project);
    const { session } = await sdk.createAgentSession({ cwd: project, agentDir, model, modelRuntime: runtime,
      resourceLoader, tools: ["synthetic_probe"], sessionManager: sm, thinkingLevel: "off",
      customTools: [{ name: "synthetic_probe", label: "synthetic", description: "Synthetic local test tool",
        parameters: { type: "object", properties: {} },
        execute: async () => ({ content: [{ type: "text", text: literal }, image], details: {} }) }],
      settingsManager: sdk.SettingsManager.inMemory({ compaction: { enabled: false }, retry: { enabled: false }, cacheWarming: "off" }) });
    sessions.add(session);
    const notices = [], statuses = new Map(), errors = [];
    let choose = () => undefined, confirmation = false, draft;
    const ui = { notify: (text, level) => notices.push({ text: String(text), level }),
      setEditorText: (text) => { draft = text; }, setStatus: (key, value) => statuses.set(key, value), setWidget() {},
      select: async (title, options) => choose(title, options), confirm: async () => confirmation };
    await session.bindExtensions({ mode: "rpc", uiContext: ui,
      commandContextActions: { navigateTree: (id, options) => session.navigateTree(id, options) } });
    const runner = session.extensionRunner;
    runner.onError((e) => errors.push(e));
    assert.deepEqual(runner.getCommandDiagnostics(), []);
    return { session, sm, runner, notices, statuses, errors, draft: () => draft,
      choose: (fn) => { choose = fn; }, confirm: (yes) => { confirmation = yes; },
      dispose: () => { session.dispose(); sessions.delete(session); } };
  }
  const promptReferences = new Map();
  let defaultPromptReference;
  const count = (text, token) => text.split(token).length - 1;
  function checkPrompt(text, choice, legacy = "SYNTH_LEGACY_PERSONALITY") {
    for (const token of ["SYNTH_SEEP_RULES", "边界锚", "SYNTH_PROJECT_CONTEXT", "SYNTH_PROJECT_RULES", "SYNTH_BASE"]) {
      assert.equal(count(text, token), 1, `${token}: prompt must contain exactly one copy`);
    }
    assert.ok(text.includes("<personality>project literal</personality>"), "project instructions are source material too");
    assert.ok(!text.includes("SYNTH_GLOBAL_RULES"), "project RULES must win");
    for (const [id, token] of [["alpha", "SYNTH_ALPHA_CARD"], ["beta", "SYNTH_BETA_CARD"], ["legacy", legacy]]) {
      assert.equal(count(text, token), choice === id ? 1 : 0, `${choice}: ${token}`);
    }
  }
  async function request(x, choice, label, tool = false) {
    const start = captures.length;
    pendingTool = tool;
    await x.session.prompt(literal);
    const fresh = captures.slice(start);
    assert.equal(fresh.length, tool ? 2 : 1, "fake transport must really execute");
    for (const context of fresh) {
      const effectivePrompt = ai.getCurrentSystemPrompt(context.messages);
      checkPrompt(effectivePrompt, choice);
      const referenceKey = label.slice(label.indexOf("/") + 1);
      if (promptReferences.has(referenceKey)) assert.equal(effectivePrompt, promptReferences.get(referenceKey),
        `${referenceKey}: both load orders must produce identical effective prompt text`);
      else promptReferences.set(referenceKey, effectivePrompt);
      const user = context.messages.filter((m) => m.role === "user").at(-1);
      assert.deepEqual(user.content, [{ type: "text", text: literal }]);
      for (const message of context.messages.filter((m) => m.role === "assistant")) {
        for (const block of message.content.filter((b) => b.type === "text")) assert.equal(block.text, literal);
      }
      for (const message of context.messages.filter((m) => m.role === "toolResult")) {
        assert.deepEqual(message.content, [{ type: "text", text: literal }, image]);
      }
      assert.deepEqual(ai.getCurrentTools(context.messages).map((t) => t.name), ["synthetic_probe"]);
    }
    assert.deepEqual(x.errors, []);
    record(label, { requests: fresh.length, systemMessages: fresh.map((c) => c.messages.filter((m) => m.role === "system").length),
      effectivePrompt: ai.getCurrentSystemPrompt(fresh.at(-1).messages) });
    return fresh;
  }

  for (const order of [["load", "persona", "rewind"], ["persona", "rewind", "load"]]) {
    const label = order.join(">");
    for (const mode of ["cached", "every-turn"]) {
      settings(mode, "alpha");
      const x = await harness(order, true);
      assert.equal(x.sm.getEntries().filter((e) => e.type === "custom").length, 0, "default must not append a choice");
      const before = await x.runner.emitBeforeAgentStart({ messageType: "user", prompt: literal },
        { cwd: project, customPrompt: "SYNTH_BASE", contextFiles, sections: {} });
      assert.equal(before.systemPromptOptions.forceSystemPrompt, undefined);
      const beforePrompt = buildSystemPrompt(before.systemPromptOptions);
      checkPrompt(beforePrompt, "alpha");
      if (defaultPromptReference) assert.equal(beforePrompt, defaultPromptReference, "default prompt must be identical across mode and load order");
      else defaultPromptReference = beforePrompt;
      const transformed = await x.runner.emitContext([
        { role: "system", ...buildSystemPromptState(before.systemPromptOptions), timestamp: 1 },
        { role: "user", content: [{ type: "text", text: literal }, image], timestamp: 2 },
        reply(), { role: "toolResult", toolCallId: "old", toolName: "synthetic_probe", content: [{ type: "text", text: literal }, image], timestamp: 3 },
        { role: "system", content: "", sections: { personality: "<personality>STALE_SYNTH_CARD</personality>" }, timestamp: 4 },
      ]);
      checkPrompt(ai.getCurrentSystemPrompt(transformed), "alpha");
      assert.ok(!ai.getCurrentSystemPrompt(transformed).includes("STALE_SYNTH_CARD"));
      assert.deepEqual(transformed.filter((m) => m.role !== "system"), [
        { role: "user", content: [{ type: "text", text: literal }, image], timestamp: 2 }, reply(),
        { role: "toolResult", toolCallId: "old", toolName: "synthetic_probe", content: [{ type: "text", text: literal }, image], timestamp: 3 }]);
      record(`${label}/${mode}/before-and-context-effective-default`);
      await request(x, "alpha", `${label}/${mode}/default`, true);
      for (const choice of ["alpha", "beta", "off"]) {
        await x.session.prompt(`/persona ${choice}`);
        const fresh = await request(x, choice, `${label}/${mode}/${choice}`, choice === "beta");
        if (mode === "every-turn") assert.ok(fresh.every((c) => c.messages.filter((m) => m.role === "system").length === 1));
        if (mode === "cached" && choice === "beta") assert.ok(fresh[0].messages.filter((m) => m.role === "system").length > 1,
          "cached preserves SDK transcript deltas; every-turn must have different request behavior");
      }
      // UI cancellation and mode switching must leave bytes and session choices alone.
      const oldSettings = fs.readFileSync(settingsFile);
      const entryCount = x.sm.getEntries().length;
      x.choose(() => undefined);
      await x.session.prompt("/persona");
      await x.session.prompt("/persona mode");
      assert.ok(fs.readFileSync(settingsFile).equals(oldSettings));
      assert.equal(x.sm.getEntries().length, entryCount);
      for (const target of [mode === "cached" ? "every-turn" : "cached", mode]) {
        x.choose((_title, options) => options.find((v) => v.replace(/^● /, "").startsWith(target + "（")));
        await x.session.prompt("/persona mode");
        assert.equal(JSON.parse(fs.readFileSync(settingsFile, "utf8")).mode, target);
        assert.equal(JSON.parse(fs.readFileSync(settingsFile, "utf8")).unknownKey, "keep");
        await x.session.prompt("/persona alpha");
        const seen = await request(x, "alpha", `${label}/${mode}/switch-${target}`);
        if (target === "every-turn") assert.equal(seen[0].messages.filter((m) => m.role === "system").length, 1);
        await x.session.prompt("/persona list");
        assert.ok(x.notices.at(-1).text.includes(`模式：${target}`));
      }
      // Navigate across the off entry. All entries remain append-only, off stays off.
      const anchor = x.sm.getLeafId();
      const question = x.sm.appendMessage({ role: "user", content: literal, timestamp: 10 });
      x.sm.appendMessage(reply());
      await x.session.prompt("/persona off");
      const history = fs.readFileSync(x.sm.getSessionFile());
      await x.session.prompt("/undo-reply");
      assert.equal(x.sm.getLeafId(), anchor);
      assert.equal(x.draft(), literal);
      assert.ok(x.sm.getEntry(question));
      assert.ok(fs.readFileSync(x.sm.getSessionFile()).subarray(0, history.length).equals(history));
      await request(x, "off", `${label}/${mode}/off-after-rewind`);
      x.sm.appendCompaction(literal, null, 1000);
      await request(x, "off", `${label}/${mode}/off-after-compaction`);
      const y = await harness(order);
      await y.session.prompt("/persona beta");
      await request(y, "beta", `${label}/${mode}/second-session`);
      await request(x, "off", `${label}/${mode}/first-session-still-off`);
      const sessionFile = x.sm.getSessionFile();
      y.dispose(); x.dispose();
      const resumed = await harness(order, false, sessionFile);
      await request(resumed, "off", `${label}/${mode}/off-after-reopen`);
      resumed.dispose();
    }
    settings("cached", "missing-default");
    fs.writeFileSync(join(project, "PERSONALITY.md"), "SYNTH_LEGACY_PERSONALITY");
    const legacy = await harness(order);
    await request(legacy, "legacy", `${label}/missing-default-falls-back-to-legacy`);
    fs.writeFileSync(join(project, "PERSONALITY.md"), "SYNTH_LEGACY_REFRESHED");
    await legacy.session.prompt(literal);
    let effective = ai.getCurrentSystemPrompt(captures.at(-1).messages);
    checkPrompt(effective, "legacy", "SYNTH_LEGACY_REFRESHED");
    assert.ok(!effective.includes("SYNTH_LEGACY_PERSONALITY"));
    // Also repair an already rendered, stale section during the same run.
    fs.writeFileSync(join(project, "PERSONALITY.md"), "SYNTH_LEGACY_LATEST");
    const refreshed = await legacy.runner.emitContext(captures.at(-1).messages);
    effective = ai.getCurrentSystemPrompt(refreshed);
    checkPrompt(effective, "legacy", "SYNTH_LEGACY_LATEST");
    assert.ok(!effective.includes("SYNTH_LEGACY_REFRESHED"));
    fs.unlinkSync(join(project, "PERSONALITY.md"));
    const removed = await legacy.runner.emitContext(refreshed);
    checkPrompt(ai.getCurrentSystemPrompt(removed), "off");
    await request(legacy, "off", `${label}/no-default-no-legacy`);
    // Rules use project .pi > project > global, including refresh/removal.
    fs.mkdirSync(join(project, ".pi"), { recursive: true });
    fs.writeFileSync(join(project, ".pi/RULES.md"), "SYNTH_DOT_PI_RULES");
    let rulesContext = await legacy.runner.emitContext(captures.at(-1).messages);
    let rulesPrompt = ai.getCurrentSystemPrompt(rulesContext);
    assert.equal(count(rulesPrompt, "SYNTH_DOT_PI_RULES"), 1);
    assert.ok(!rulesPrompt.includes("SYNTH_PROJECT_RULES") && !rulesPrompt.includes("SYNTH_GLOBAL_RULES"));
    fs.unlinkSync(join(project, ".pi/RULES.md"));
    fs.unlinkSync(join(project, "RULES.md"));
    rulesContext = await legacy.runner.emitContext(rulesContext);
    rulesPrompt = ai.getCurrentSystemPrompt(rulesContext);
    assert.equal(count(rulesPrompt, "SYNTH_GLOBAL_RULES"), 1);
    assert.ok(!rulesPrompt.includes("SYNTH_DOT_PI_RULES") && !rulesPrompt.includes("SYNTH_PROJECT_RULES"));
    fs.writeFileSync(join(project, "RULES.md"), "SYNTH_PROJECT_RULES");
    record(`${label}/legacy-refresh-removal-and-rules-priority`);
    legacy.dispose();
    fs.writeFileSync(join(project, "PERSONALITY.md"), "SYNTH_LEGACY_PERSONALITY");
  }

  // Command errors must be visible and must preserve old settings.
  settings();
  const failure = await harness(["persona", "rewind", "load"]);
  failure.choose((_title, options) => options.find((value) => value.startsWith("every-turn")));
  const realRename = fs.renameSync;
  fs.renameSync = (from, to) => {
    if (resolve(String(to)) === settingsFile) throw Object.assign(new Error("injected EACCES"), { code: "EACCES" });
    return realRename(from, to);
  };
  syncBuiltinESMExports();
  const original = fs.readFileSync(settingsFile);
  try {
    for (const command of ["/persona mode", "/persona badge"]) {
      await failure.session.prompt(command);
      assert.equal(failure.notices.at(-1).level, "error");
      assert.match(failure.notices.at(-1).text, /未能保存/);
      assert.ok(fs.readFileSync(settingsFile).equals(original));
    }
  } finally { fs.renameSync = realRename; syncBuiltinESMExports(); }
  assert.deepEqual(fs.readdirSync(agentDir).filter((name) => name.endsWith(".tmp")), []);
  fs.writeFileSync(settingsFile, "{broken");
  await failure.session.prompt("/persona badge");
  assert.equal(failure.notices.at(-1).level, "error");
  assert.equal(fs.readFileSync(settingsFile, "utf8"), "{broken");
  settings();
  const append = failure.sm.appendCustomEntry.bind(failure.sm);
  failure.sm.appendCustomEntry = () => { throw new Error("injected session append failure"); };
  await failure.session.prompt("/persona alpha");
  assert.equal(failure.notices.at(-1).level, "error");
  assert.equal(failure.sm.getEntries().filter((e) => e.type === "custom").length, 0);
  failure.sm.appendCustomEntry = append;
  // Tool work: cancel picker, refuse confirmation, then accept real navigateTree.
  const userId = failure.sm.appendMessage({ role: "user", content: literal, timestamp: 11 });
  failure.sm.appendMessage(reply([{ type: "toolCall", id: "probe", name: "synthetic_probe", arguments: {} }]));
  const leaf = failure.sm.getLeafId();
  failure.choose(() => undefined);
  await failure.session.prompt("/rewind");
  assert.equal(failure.sm.getLeafId(), leaf);
  failure.choose((_title, options) => options[0]); failure.confirm(false);
  await failure.session.prompt("/undo-reply");
  assert.equal(failure.sm.getLeafId(), leaf);
  failure.confirm(true);
  await failure.session.prompt("/rewind");
  assert.ok(!failure.sm.getBranch().some((e) => e.id === userId));
  assert.ok(failure.sm.getEntry(userId));
  assert.equal(failure.draft(), literal);
  assert.deepEqual(failure.errors, []);
  failure.dispose();
  record("settings-and-session-write-failures-visible; rewind-cancel-confirm");
  for (const [name, text] of [["alpha.md", "SYNTH_ALPHA_CARD"], ["beta.md", "SYNTH_BETA_CARD"]]) {
    assert.equal(fs.readFileSync(join(agentDir, "personas", name), "utf8"), text + "\r\n", "persona card bytes must remain unchanged");
  }
  assert.deepEqual(forbiddenReads, []);
  assert.equal(networkCalls, 0);
  const hashes = Object.fromEntries(["package.json", ...declaration.extensions,
    ...fs.readdirSync(join(deployed, "lib")).map((name) => `lib/${name}`)].map((rel) =>
    [rel, createHash("sha256").update(fs.readFileSync(join(deployed, rel))).digest("hex")]));
  const report = { result: "PASS", sdkVersion, nodeVersion: process.version, upstreamCommit: declaration.upstream.commit,
    installerTested: !process.argv.includes("--extensions-only"), networkCalls, forbiddenReads, hashes, results };
  if (auditDir) {
    fs.mkdirSync(auditDir, { recursive: true });
    fs.writeFileSync(join(auditDir, `sdk-${sdkVersion}-results.json`), JSON.stringify(report, null, 2));
    fs.writeFileSync(join(auditDir, `sdk-${sdkVersion}-contexts.json`), JSON.stringify(captures, null, 2));
  }
  console.log(JSON.stringify({ result: report.result, sdkVersion, checks: results.length, networkCalls, forbiddenReads }, null, 2));
} finally {
  clearTimeout(deadline);
  for (const session of sessions) session.dispose();
  fs.rmSync(scratch, { recursive: true, force: true });
}
