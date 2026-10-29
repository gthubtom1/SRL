// Executes the installed source hook, without loading a user AgentRoot, model,
// credentials, client samples or other extensions. Each call receives Pi's input
// event contract. The Python suite sends the resulting material through HTTP.
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const operations = JSON.parse(fs.readFileSync(0, "utf8"));
let mod;
let handlers;
let events;
let notices;
async function load() {
  mod = await import(pathToFileURL(process.argv[2]).href + `?reload=${Math.random()}`);
  handlers = {};
  events = [];
  notices = [];
  mod.default({
    on(name, handler) { handlers[name] = handler; },
    events: { emit(name, data) { events.push({ name, data }); } },
  });
}
await load();
const rows = [];
for (const op of operations) {
  if (op.lab !== undefined) {
    const flag = path.join(process.env.PI_CODING_AGENT_DIR, "lab-mode.flag");
    if (op.lab) fs.writeFileSync(flag, "fixture");
    else fs.rmSync(flag, { force: true });
  }
  if (op.safe !== undefined) {
    const flag = path.join(process.env.PI_CODING_AGENT_DIR, "gemini-safe.flag");
    if (op.safe) fs.writeFileSync(flag, "fixture");
    else fs.rmSync(flag, { force: true });
  }
  if (op.reload) await load();
  events.length = 0;
  notices.length = 0;
  const event = structuredClone(op.event ?? { source: "interactive", text: op.text ?? "" });
  const before = structuredClone(event);
  const result = await handlers.input(event, { ui: { notify(s) { notices.push(s); } } });
  const text = result?.action === "transform" ? result.text : event.text;
  const images = result?.action === "transform" && result.images !== undefined ? result.images : event.images;
  const payload = structuredClone(op.payload ?? { contents: [{ parts: [{ text }] }], config: { systemInstruction: "original" } });
  const request = handlers.before_provider_request({ payload }, { model: op.model }) ?? payload;
  const context = structuredClone(op.context ?? [{ role: "user", content: text }]);
  const finalContext = handlers.context ? (await handlers.context({ messages: context }, {}))?.messages ?? context : context;
  rows.push({ result, text, images, event, before, request, context: finalContext,
    terms: mod.deriveRouteTerms(text), events: structuredClone(events), notices: [...notices],
    lab: fs.existsSync(path.join(process.env.PI_CODING_AGENT_DIR, "lab-mode.flag")) });
}
process.stdout.write(JSON.stringify(rows));
