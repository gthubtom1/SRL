import { getCurrentSystemMessage } from "@earendil-works/pi-ai";
import { resolveAgentDir } from "../lib/agent-dir.ts";
import { PERSONALITY_SECTION, patchSystemSections, renderSection } from "../lib/inject.ts";
import type {
  BeforeAgentStartEvent,
  CommandContext,
  ContextWithSystemEvent,
  ExtensionApi,
  SessionEntryLike,
} from "../lib/pi-api.ts";
import {
  PERSONAS_DIR_NAME,
  listPersonas,
  personasDir,
  readPersonaText,
  readSettings,
  writeSettings,
  type PersonaInjectMode,
  type PersonaSettings,
} from "../lib/personas.ts";
import { PERSONA_STATE_TYPE, resolvePersonaSelection } from "../lib/session-state.ts";

/**
 * Per-conversation personas, as a pi extension.
 *
 * The persona set is a directory (`<agentDir>/personas/*.md`); the file name is
 * the persona's name, so adding, renaming and retiring personas is done in a
 * file manager. Which persona a conversation uses is stored *in that
 * conversation* (an append-only session entry), which is what makes the choice
 * per-conversation. Rewinding turns leaves the latest conversation choice in
 * force, including an explicit choice of no persona.
 *
 * Entry points, in the order a person meets them:
 *
 * - the status line shows the current persona as a button (`人设 · 破甲v2`),
 *   because a slash command alone leaves you guessing which persona is active;
 * - clicking it, or typing `/persona`, opens a picker with a `无人设` row and a
 *   row that switches the injection mode;
 * - `/persona <name>` and `/persona off` skip the picker.
 */
export default function personaExtension(pi: ExtensionApi): void {
  const agentDir = resolveAgentDir();
  const STATUS_KEY = "command:/persona";
  const WIDGET_KEY = "persona";

  /**
   * Every entry the session has ever appended, in append order — *not* the
   * current branch.
   *
   * The persona is a setting of the conversation, so the last choice must win.
   * Reading only the branch made an undo resurrect a persona the user had just
   * switched off: rewinding to a message sent before the switch also rewound the
   * switch itself, and the old identity came back on the next turn. Entries stay
   * append-only and branch-shaped for everything else; this is the one place
   * that deliberately ignores the branch.
   */
  const sessionEntriesOf = (ctx: { sessionManager: { getEntries?(): SessionEntryLike[]; getBranch(): SessionEntryLike[] } }): SessionEntryLike[] => {
    try {
      const { sessionManager } = ctx;
      if (typeof sessionManager.getEntries === "function") return sessionManager.getEntries();
      return sessionManager.getBranch();
    } catch {
      return [];
    }
  };

  /**
   * The persona a branch is using: an explicit session entry wins (including an
   * explicit "none"), otherwise the configured default, and a default whose file
   * has since been deleted counts as none.
   */
  function currentPersona(entries: readonly SessionEntryLike[], settings: PersonaSettings): string | null {
    return resolvePersonaSelection(agentDir, entries, settings) ?? null;
  }

  // generic-rules belongs to load-system-prompt (project rules take priority).
  // This extension owns only the named personality section, never message text.

  /**
   * Where the current persona shows up, using only what an extension may paint:
   *
   * - a status cell under the composer. pi-web renders a `command:` key as a
   *   button that sends that slash command, so the label doubles as the entry
   *   point (`人设：色情破甲` → click → picker), on upstream pi-web as well;
   * - optionally a widget line in the same shelf, for people who want it bigger
   *   (`/persona badge on`). Widgets are display-only, so the status cell stays
   *   the clickable one.
   *
   * Nothing here needs a pi-web change: both are plain `ctx.ui` calls, and the
   * TUI shows the same status text.
   */
  function updateIndicators(
    ctx: { ui: { setStatus(key: string, text?: string): void; setWidget?(key: string, content?: string[]): void }; sessionManager: { getEntries?(): SessionEntryLike[]; getBranch(): SessionEntryLike[] } },
    settings: PersonaSettings = readSettings(agentDir),
  ): void {
    const personaId = currentPersona(sessionEntriesOf(ctx), settings);
    ctx.ui.setStatus(STATUS_KEY, personaId ? `🧑‍🎤 人设：${personaId}` : "🧑‍🎤 人设：无");
    if (typeof ctx.ui.setWidget === "function") {
      ctx.ui.setWidget(
        WIDGET_KEY,
        settings.showBadge && personaId ? [`🧑‍🎤 当前人设：${personaId}　·　输入 /persona 切换`] : undefined,
      );
    }
  }

  function recordPersona(ctx: CommandContext, personaId: string | null): void {
    try {
      pi.appendEntry(PERSONA_STATE_TYPE, { personaId });
    } catch (error) {
      ctx.ui.notify(`未能保存人设选择：${String(error)}`, "error");
      return;
    }
    updateIndicators(ctx);
    ctx.ui.notify(personaId ? `人设：${personaId}（本对话）` : "人设：无（本对话）", "info");
  }

  function saveSettings(ctx: CommandContext, patch: Record<string, unknown>): PersonaSettings | null {
    try {
      return writeSettings(patch, agentDir);
    } catch (error) {
      ctx.ui.notify(`未能保存人设设置：${String(error)}`, "error");
      return null;
    }
  }

  async function pickMode(ctx: CommandContext, settings: PersonaSettings): Promise<void> {
    const labels: Record<PersonaInjectMode, string> = {
      cached: "cached（结构化增量，保留提示词缓存）",
      "every-turn": "every-turn（每次模型请求重放完整系统提示词与当前人设）",
    };
    const modes = Object.keys(labels) as PersonaInjectMode[];
    const options = modes.map((mode) => `${settings.mode === mode ? "● " : ""}${labels[mode]}`);
    const choice = await ctx.ui.select("注入模式（全局，影响所有人设）", options);
    if (choice === undefined) return;
    const mode = modes[options.indexOf(choice)];
    if (!mode || !saveSettings(ctx, { mode })) return;
    ctx.ui.notify(`注入模式：${mode}`, "info");
  }

  async function pickPersona(ctx: CommandContext): Promise<void> {
    const settings = readSettings(agentDir);
    const current = currentPersona(sessionEntriesOf(ctx), settings);
    const personas = listPersonas(agentDir);
    const modeLabel = `⚙ 注入模式（当前 ${settings.mode}）`;
    const options = [
      current ? "无人设" : "● 无人设",
      ...personas.map((persona) => (persona.id === current ? `● ${persona.name}` : persona.name)),
      modeLabel,
    ];
    if (personas.length === 0) {
      ctx.ui.notify(`还没放人设文件：把 <名字>.md 放进 ${personasDir(agentDir)} 就会出现`, "info");
    }
    const choice = await ctx.ui.select("选择人设（本对话）", options);
    if (choice === undefined) return; // Esc: change nothing, rather than silently clearing.
    if (choice === modeLabel) return pickMode(ctx, settings);
    const name = choice.replace(/^● /, "");
    if (name === "无人设") return recordPersona(ctx, null);
    const found = personas.find((persona) => persona.name === name || persona.id === name);
    if (!found) {
      ctx.ui.notify(`没有「${name}」这个人设文件了`, "warning");
      return;
    }
    recordPersona(ctx, found.id);
  }

  pi.on("session_start", (_event, ctx) => {
    updateIndicators(ctx as unknown as CommandContext);
  });

  pi.registerCommand("persona", {
    description: "选择本对话的人设（无人设 / 各 personas 文件）、切换注入模式",
    handler: async (args, ctx) => {
      const arg = args.trim();
      if (arg === "" || arg === "pick") return pickPersona(ctx);

      const settings = readSettings(agentDir);
      if (arg === "off" || arg === "none" || arg === "无" || arg === "无人设") return recordPersona(ctx, null);
      if (arg === "mode") return pickMode(ctx, settings);
      if (arg === "badge") {
        const showBadge = !settings.showBadge;
        if (!saveSettings(ctx, { showBadge })) return;
        updateIndicators(ctx);
        ctx.ui.notify(showBadge ? "已显示人设徽标（输入框上方一行）" : "已隐藏人设徽标", "info");
        return;
      }
      if (arg === "list") {
        const personas = listPersonas(agentDir);
        const current = currentPersona(sessionEntriesOf(ctx), settings);
        ctx.ui.notify(
          personas.length === 0
            ? `personas 目录为空：${agentDir}/personas`
            : `人设：${personas.map((persona) => (persona.id === current ? `●${persona.name}` : persona.name)).join("、")}（当前：${current ?? "无"}，模式：${settings.mode}）`,
          "info",
        );
        return;
      }

      const found = listPersonas(agentDir).find((persona) => persona.id === arg || persona.name === arg);
      if (!found) {
        const names = listPersonas(agentDir).map((persona) => persona.name);
        ctx.ui.notify(
          `没有「${arg}」这个人设。${names.length ? `可用：${names.join("、")}` : `请先在 ${agentDir}/${PERSONAS_DIR_NAME}/ 放一个 <名字>.md`}`,
          "warning",
        );
        return;
      }
      return recordPersona(ctx, found.id);
    },
  });

  pi.on("before_agent_start", (event: BeforeAgentStartEvent, ctx) => {
    const selection = resolvePersonaSelection(agentDir, sessionEntriesOf(ctx));
    if (selection === undefined) return; // Legacy PERSONALITY.md owns this slot.
    const options = event.systemPromptOptions ?? (event.systemPromptOptions = {});
    options.sections ??= {};
    const text = readPersonaText(agentDir, selection);
    // Keep personality before workbench rules/boundaries in either load order.
    const otherSections = { ...options.sections };
    delete otherSections[PERSONALITY_SECTION];
    options.sections = text ? { [PERSONALITY_SECTION]: text, ...otherSections } : otherSections;
  });

  pi.on("context_with_system", (event: ContextWithSystemEvent, ctx) => {
    if (event.messages[0]?.role !== "system") return;
    const settings = readSettings(agentDir);
    const selection = resolvePersonaSelection(agentDir, sessionEntriesOf(ctx), settings);
    if (selection !== undefined) {
      const text = readPersonaText(agentDir, selection);
      patchSystemSections(event.messages, {
        [PERSONALITY_SECTION]: text ? renderSection(PERSONALITY_SECTION, text) : null,
      });
    }
    if (settings.mode !== "every-turn") return;

    // Every provider call (including tool continuations) gets a fresh, complete
    // checkpoint. Pi replays sections AND tool declarations itself. Delaying
    // this until context time includes every before_agent_start handler, in
    // either load order. Cached mode keeps Pi's original transcript deltas.
    // Nothing here inspects or edits conversation text, images, or attachments.
    const head = getCurrentSystemMessage(event.messages as Parameters<typeof getCurrentSystemMessage>[0]);
    if (head) return { messages: [head, ...event.messages.filter((message) => message.role !== "system")] };
  });
}
