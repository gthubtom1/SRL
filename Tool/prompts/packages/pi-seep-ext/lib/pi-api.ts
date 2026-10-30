/**
 * Minimal structural types for the pi extension API this package uses.
 *
 * They are declared here instead of imported from
 * `@earendil-works/pi-coding-agent` so the package has no build step and no
 * dependency: pi loads the TypeScript directly, and the shapes below are the
 * documented contract (docs/extensions.md, docs/rpc-extension-ui.md). Anything
 * this package does not call is deliberately absent.
 */

export interface UiDialogOptions {
  timeout?: number;
}

export interface UiContext {
  select(title: string, options: string[], opts?: UiDialogOptions): Promise<string | undefined>;
  confirm(title: string, message: string, opts?: UiDialogOptions): Promise<boolean>;
  input(title: string, placeholder?: string, opts?: UiDialogOptions): Promise<string | undefined>;
  notify(message: string, type?: "info" | "warning" | "error"): void;
  /**
   * Status line text. A key beginning with `command:` is rendered as a button
   * that sends that slash command, which is how pi-web turns a status into a
   * one-click entry point without extending the protocol.
   */
  setStatus(key: string, text: string | undefined): void;
  setWidget(key: string, content: string[] | undefined, options?: { placement?: "aboveEditor" | "belowEditor" }): void;
  setEditorText(text: string): void;
  getEditorText(): string;
}

export interface SessionEntryLike {
  type?: string;
  id?: string;
  parentId?: string | null;
  customType?: string;
  data?: unknown;
  message?: { role?: string; content?: unknown };
}

export interface SessionManagerLike {
  getBranch(fromId?: string): SessionEntryLike[];
  getEntries(): SessionEntryLike[];
  getLeafId(): string | null;
  getCwd?: () => string;
}

export interface PromptOptionsLike {
  sections?: Record<string, string | null>;
  forceSystemPrompt?: string;
}

export interface BeforeAgentStartEvent {
  systemPrompt: string;
  systemPromptOptions?: PromptOptionsLike;
  messageType?: string;
}

export interface BeforeAgentStartResult {
  systemPrompt?: string;
}

export interface ContextMessage {
  role?: string;
  content?: unknown;
  sections?: Record<string, string | null>;
}

/**
 * Before each provider call, *without* the prompt and tool system messages:
 * pi restores its own state afterwards, so only conversation messages are ours.
 */
export interface ContextEvent {
  messages: ContextMessage[];
}

export interface ContextWithSystemEvent {
  messages: ContextMessage[];
}

export interface BaseContext {
  ui: UiContext;
  mode: string;
  hasUI: boolean;
  cwd: string;
  sessionManager: SessionManagerLike;
}

export interface CommandContext extends BaseContext {
  waitForIdle(): Promise<void>;
  /** Move the branch's leaf back to an earlier entry; the old branch stays in the file. */
  navigateTree(targetId: string, options?: { summarize?: boolean; customInstructions?: string; label?: string }): Promise<{ cancelled: boolean }>;
  reload(): Promise<void>;
}

export interface ExecResultLike {
  stdout: string;
  stderr: string;
  code: number;
  killed: boolean;
}

export interface CustomMessageInput {
  customType: string;
  content: string;
  display?: boolean;
  details?: unknown;
}

export interface ExtensionApi {
  on(event: "session_start", handler: (event: unknown, ctx: BaseContext) => void | Promise<void>): void;
  on(event: "before_agent_start", handler: (event: BeforeAgentStartEvent, ctx: BaseContext) => BeforeAgentStartResult | undefined | void): void;
  on(event: "context_with_system", handler: (event: ContextWithSystemEvent, ctx: BaseContext) => { messages: ContextMessage[] } | void | undefined): void;
  on(event: "context", handler: (event: ContextEvent, ctx: BaseContext) => { messages: ContextMessage[] } | undefined | void): void;
  registerCommand(name: string, options: {
    description?: string;
    handler: (args: string, ctx: CommandContext) => Promise<void>;
  }): void;
  /** Append a session entry that follows the branch but never reaches the model. */
  appendEntry<T = unknown>(customType: string, data?: T): void;
  /** Run a program without a shell. Rejects when the program cannot be spawned. */
  exec(command: string, args: string[], options?: { timeout?: number; cwd?: string }): Promise<ExecResultLike>;
  /** Post a message into the transcript. `display: true` makes it visible. */
  sendMessage(message: CustomMessageInput, options?: { triggerTurn?: boolean }): void | Promise<void>;
  setSessionName(name: string): void;
}
