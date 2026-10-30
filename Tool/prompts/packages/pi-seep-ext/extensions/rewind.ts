import {
  formatCandidate,
  lastReplyOnlyTurn,
  listRewindCandidates,
  pickerOptions,
  type RewindCandidate,
} from "../lib/rewind-targets.ts";
import type { BaseContext, CommandContext, ExtensionApi } from "../lib/pi-api.ts";

/** A `command:` status key is painted as a button that sends that slash command. */
const STATUS_KEY = "command:/undo-reply";
const STATUS_LABEL = "⟲ 回退";

/**
 * Undoing a turn, as a pi extension.
 *
 * Nothing here edits a session file. Pi stores a session as a tree and the
 * branch in force is the path from the root to the current leaf, so "rewind"
 * is moving the leaf back (`navigateTree`): the turn leaves the context, the
 * entries stay in the file, and going forward again is possible. That is the
 * supported API, and it cannot corrupt a session the way truncating JSONL can.
 *
 * Two commands, because the two intents differ:
 *
 * - `/rewind` — pick any earlier user message, confirm when the turn did tool
 *   work, then put that message back in the composer as a draft.
 * - `/undo-reply` — the one-command case: drop the last reply when it is the end
 *   of the branch and did no tool work, which is how a refused turn is re-asked.
 *   When the turn did tool work it hands over to the picker instead of failing,
 *   because that is what the person reaching for "undo" wanted anyway — it just
 *   needs the explicit confirmation.
 *
 * Both are also what the status-bar「⟲ 回退」cell sends, so the cell stays a
 * dumb sender and every safety rule lives here.
 */
export default function rewindExtension(pi: ExtensionApi): void {
  /**
   * Put the entry point under the composer. pi-web renders a `command:` status
   * key as a button that sends that slash command (same trick as `/persona`),
   * so one click undoes the last reply — no pi-web patch, no extra API. The TUI
   * shows the same text as a plain status cell.
   */
  const paintStatus = (ctx: BaseContext): void => {
    if (ctx.mode === "json" || ctx.mode === "print") return;
    ctx.ui.setStatus(STATUS_KEY, STATUS_LABEL);
  };

  pi.on("session_start", (_event, ctx) => {
    paintStatus(ctx);
  });

  /** Move the leaf back to `picked` and restore its text as a draft. */
  const rewindTo = async (ctx: CommandContext, picked: RewindCandidate, confirmToolWork: boolean): Promise<boolean> => {
    if (confirmToolWork && picked.hasToolWork) {
      const ok = await ctx.ui.confirm(
        `第 ${picked.turn} 条消息之后有工具调用`,
        "回退会把这些工具调用和结果一起移出上下文（文件、命令产生的效果不会被撤销）。继续？",
      );
      if (!ok) return false;
    }

    try {
      const result = await ctx.navigateTree(picked.entryId, { summarize: false });
      if (result?.cancelled) return false;
    } catch (error) {
      // pi refuses navigation while a run or a compaction is in flight.
      ctx.ui.notify(
        `现在不能回退：${error instanceof Error ? error.message : String(error)}\n等这一轮结束再试。`,
        "warning",
      );
      return false;
    }

    ctx.ui.setEditorText(picked.text);
    return true;
  };

  /** Shared picker. Returns true when a rewind actually happened. */
  const pickAndRewind = async (ctx: CommandContext): Promise<boolean> => {
    const candidates = listRewindCandidates(ctx.sessionManager.getBranch());
    if (candidates.length === 0) {
      ctx.ui.notify("本对话还没有可以回退的用户消息", "info");
      return false;
    }

    const { labels, ordered } = pickerOptions(candidates);
    const choice = await ctx.ui.select("回退到哪条消息之前（该消息及之后的内容移出上下文，原文放回输入框）", labels);
    if (choice === undefined) return false;

    const picked = ordered[labels.indexOf(choice)];
    if (!picked) return false;

    const done = await rewindTo(ctx, picked, true);
    if (done) ctx.ui.notify(`已回退到第 ${picked.turn} 条消息之前，原文已放回输入框`, "info");
    return done;
  };

  pi.registerCommand("rewind", {
    description: "回退到某条用户消息之前（原文放回输入框）",
    handler: async (args, ctx: CommandContext) => {
      paintStatus(ctx);
      if (args.trim() === "list") {
        const candidates = listRewindCandidates(ctx.sessionManager.getBranch());
        if (candidates.length === 0) {
          ctx.ui.notify("本对话还没有可以回退的用户消息", "info");
          return;
        }
        // A long conversation would otherwise dump every turn into one notice.
        const shown = candidates.slice(-15);
        const hidden = candidates.length - shown.length;
        ctx.ui.notify(
          [...(hidden > 0 ? [`…更早的 ${hidden} 条未显示`] : []), ...shown.map(formatCandidate)].join("\n"),
          "info",
        );
        return;
      }

      await pickAndRewind(ctx);
    },
  });

  pi.registerCommand("undo-reply", {
    description: "只删掉最后一条回复（无工具调用时），把问题放回输入框重问",
    handler: async (_args, ctx: CommandContext) => {
      paintStatus(ctx);
      const target = lastReplyOnlyTurn(ctx.sessionManager.getBranch());
      if (!target) {
        // Not a one-click undo: the last turn did tool work, or something came
        // after the reply. Rather than dead-end, open the picker that can do it
        // with the confirmation it needs.
        const candidates = listRewindCandidates(ctx.sessionManager.getBranch());
        if (candidates.length > 0) {
          ctx.ui.notify("最后一条回复带着工具调用或后面还有内容，改从列表里选（会先确认）", "info");
        }
        await pickAndRewind(ctx);
        return;
      }

      const done = await rewindTo(ctx, target, false);
      if (done) ctx.ui.notify(`已删除最后一条回复，第 ${target.turn} 条问题已放回输入框`, "info");
    },
  });
}
