/**
 * What a rewind can target.
 *
 * Pi's sessions are a tree: every entry has an id and a parent, and the branch
 * in force is the path from the root to the current leaf. Moving the leaf back
 * (`navigateTree`) is the supported way to "undo a turn" — the old branch stays
 * in the file, so nothing is destroyed and the user can come back to it.
 *
 * Two shapes are worth offering:
 *
 * - every user message is a place to rewind to (the generic `/rewind`),
 * - the final turn is worth a one-command undo, but *only* while it has no tool
 *   work: re-running a turn that wrote files or ran commands is not an undo, it
 *   is a decision that needs an explicit confirmation.
 */

interface ContentBlockLike {
  type?: string;
  text?: string;
}

interface MessageLike {
  role?: string;
  content?: unknown;
}

export interface EntryLike {
  type?: string;
  id?: string;
  customType?: string;
  message?: MessageLike;
}

export interface RewindCandidate {
  entryId: string;
  /** Position among the user messages, 1-based, for a numbered picker. */
  turn: number;
  /** Full message text, put back in the composer as a draft. */
  text: string;
  /** First line of the message, shortened for a dialog row. */
  preview: string;
  /** The turn did tool work after it: rewinding drops that too, so confirm first. */
  hasToolWork: boolean;
}

const PREVIEW_LENGTH = 72;

function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  const parts: string[] = [];
  for (const block of content as ContentBlockLike[]) {
    if (block?.type === "text" && typeof block.text === "string") parts.push(block.text);
  }
  return parts.join("\n");
}

function previewOf(text: string): string {
  const line = text.replace(/\s+/g, " ").trim();
  return line.length > PREVIEW_LENGTH ? `${line.slice(0, PREVIEW_LENGTH - 1)}…` : line;
}

function roleOf(entry: EntryLike): string | undefined {
  return entry.type === "message" ? entry.message?.role : undefined;
}

/** Whether an entry is work a rewind would throw away (a tool call or its result). */
function isToolWork(entry: EntryLike): boolean {
  if (entry.type !== "message") return false;
  const role = entry.message?.role;
  if (role === "toolResult" || role === "tool") return true;
  if (role !== "assistant" || !Array.isArray(entry.message?.content)) return false;
  return (entry.message.content as ContentBlockLike[]).some(
    (block) => block?.type === "toolCall" || block?.type === "toolCallResult",
  );
}

function candidateOf(entry: EntryLike, turn: number): RewindCandidate | null {
  if (!entry.id) return null;
  const text = textOf(entry.message?.content);
  return { entryId: entry.id, turn, text, preview: previewOf(text), hasToolWork: false };
}

/** Every user message on this branch, oldest first. */
export function listRewindCandidates(entries: readonly EntryLike[]): RewindCandidate[] {
  const candidates: RewindCandidate[] = [];
  let current: RewindCandidate | null = null;
  let turn = 0;

  for (const entry of entries) {
    const role = roleOf(entry);
    if (role === "user") {
      turn += 1;
      current = candidateOf(entry, turn);
      if (current) candidates.push(current);
      continue;
    }
    if (current && isToolWork(entry)) current.hasToolWork = true;
  }

  return candidates;
}

export interface ReplyUndo extends RewindCandidate {
  /** The assistant entry the rewind also drops; kept for reporting. */
  replyId: string | null;
}

/**
 * The newest turn, when dropping just its reply is unambiguous: the reply is the
 * last thing on the branch and the turn did no tool work. `null` otherwise —
 * a turn with tools needs `/rewind` and its confirmation.
 */
export function lastReplyOnlyTurn(entries: readonly EntryLike[]): ReplyUndo | null {
  let lastUser: RewindCandidate | null = null;
  let turn = 0;
  let sawToolWork = false;
  let lastRole: string | undefined;
  let lastAssistantId: string | null = null;

  for (const entry of entries) {
    const role = roleOf(entry);
    if (role === "user") {
      turn += 1;
      lastUser = candidateOf(entry, turn);
      sawToolWork = false;
      lastAssistantId = null;
      lastRole = role;
      continue;
    }
    if (isToolWork(entry)) sawToolWork = true;
    if (role === "assistant" && entry.id) lastAssistantId = entry.id;
    if (role) lastRole = role;
  }

  if (!lastUser || sawToolWork || lastRole !== "assistant") return null;
  return { ...lastUser, hasToolWork: false, replyId: lastAssistantId };
}

/** Number a candidate the way the picker shows it: `3. 先看下这个报错` */
export function formatCandidate(candidate: RewindCandidate): string {
  const text = candidate.preview || "(empty message)";
  return candidate.hasToolWork ? `${candidate.turn}. ${text}  [tools]` : `${candidate.turn}. ${text}`;
}

/**
 * Newest first, which is what a person reaching for "undo" expects, while the
 * numbering stays in conversation order.
 */
export function pickerOptions(candidates: readonly RewindCandidate[]): { labels: string[]; ordered: RewindCandidate[] } {
  const ordered = [...candidates].reverse();
  return { labels: ordered.map(formatCandidate), ordered };
}
