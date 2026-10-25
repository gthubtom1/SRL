/**
 * seep-memory —— 案子记忆层（插件自动记录 + 触发式读取）
 *
 * 设计来源：6.8 会话最后 40 分钟。用户明确要求两件事：
 *   1. 记忆由插件**自动记录**，不要塞进提示词；
 *   2. 只在需要时**触发式读取**（启动只给一张地图，不是把整本流水账灌进上下文）。
 *
 * 目录布局（S2 起状态副本已收口）：
 *   <case>/facts.jsonl      唯一账本：claim（case_state.py 写）/ kind:"event"（本插件写）
 *                           **不再有 memory/facts.jsonl 第二份副本**
 *   <case>/memory/map.md    当前地图（agent 每 20 分钟维护；启动时注入，硬上限 1.5KB）
 *   <case>/memory/traps.md  踩过的坑（@@TRAP）
 *   <case>/memory/gates.md  门禁结论（@@GATE）
 *   <case>/memory/dead.md   死路（@@DEAD）
 *
 * 为什么改：@@FACT 以前写 <case>/memory/facts.jsonl，而 case_state.py 读 <case>/facts.jsonl ——
 * 同一语义两份账，扩展写的那份 gate 根本不看。现在只写一份账本（append-only）。
 * 标记写入的事件行带 confidence:"unknown" / authority:"none"：**永不计 pass**（S2-4）。
 *
 * case 目录：
 *   process.env.SEEP_CASE_DIR，缺省 ./.seep-case
 *   **目录不存在就静默跳过**（没开案子的普通会话不该被这个扩展打扰）。
 *
 * 隐私红线（硬约束，不是建议）：
 *   · 不写文件内容：read/grep 只记路径，write/edit 只记字符数；
 *   · 不写凭据：命中 Authorization/token/password/secret 等词，整条摘要丢弃，
 *     只落一条 {"summary":"redacted","redacted":true}；
 *   · 所有 IO 都包 try/catch，扩展异常不允许影响会话。
 *
 * 命令：
 *   /map             打印 memory/map.md（≤40 行）
 *   /facts           打印 <case>/facts.jsonl 最近 20 条（claim / state / event 混存）
 *   /traps           打印 memory/traps.md
 *   /memory-note X   追加一条 note 事件（进 facts.jsonl，kind:"event"）
 *
 * 关闭：不设 SEEP_CASE_DIR 且当前目录没有 .seep-case 时，本扩展等同空转。
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type {
	ExtensionAPI,
	ExtensionCommandContext,
} from "@earendil-works/pi-coding-agent";

/* ────────────────────────────── 常量 ────────────────────────────── */

const MAX_SUMMARY = 200;
const MAP_MAX_LINES = 40;
const MAP_INJECT_BYTES = 1536; // 1.5KB
const TRAPS_MAX_LINES = 60;
const FACTS_LAST_N = 20;
const SECTION_KEY = "seep-memory-map";

/**
 * 凭据词表。命中即整条丢弃 —— 宁可少记一条，也不让 token 落盘。
 * 注意：只用于判断「这条摘要能不能写」，不用于改写内容。
 */
const SECRET_RE =
	/(authorization|bearer\s|api[_-]?key|access[_-]?token|refresh[_-]?token|\btoken\b|password|passwd|pwd\s*[:=]|secret|private[_-]?key|client[_-]?secret|凭据|密码|密钥|口令)/i;

/** 标记通道：模型在输出里写 @@FACT / @@TRAP / @@GATE / @@DEAD 开头的行。 */
const MARKERS: { prefix: string; file: string; kind: string }[] = [
	{ prefix: "@@FACT", file: "facts.jsonl", kind: "fact" },
	{ prefix: "@@TRAP", file: "traps.md", kind: "trap" },
	{ prefix: "@@GATE", file: "gates.md", kind: "gate" },
	{ prefix: "@@DEAD", file: "dead.md", kind: "dead" },
];

/** tool_call 里允许摘录的字段：路径 / 命令 / 查询词，都不含文件正文。 */
const SAFE_INPUT_KEYS = [
	"command",
	"file_path",
	"filePath",
	"path",
	"target",
	"pattern",
	"query",
	"url",
	"glob",
	"description",
	"action",
	"name",
	"host",
	"port",
];

/** 只记长度、绝不记正文的字段。 */
const CONTENT_INPUT_KEYS = [
	"content",
	"text",
	"oldText",
	"newText",
	"old_string",
	"new_string",
	"old_str",
	"new_str",
	"patch",
	"diff",
];

/* ────────────────────────────── 路径 ────────────────────────────── */

function caseDir(): string {
	// 解析顺序（外部评审 A7：只认 ./.seep-case 与开工流程不一致，记忆会静默丢失）：
	//   ① SEEP_CASE_DIR（显式）
	//   ② ~/.seep/current-case 指针（`case_state.py init` 会写，跨目录会话也能找到）
	//   ③ ./.seep-case（旧默认）
	if (process.env.SEEP_CASE_DIR) {
		try {
			return path.resolve(process.env.SEEP_CASE_DIR);
		} catch {
			/* fallthrough */
		}
	}
	try {
		const home = process.env.USERPROFILE || process.env.HOME || "";
		const ptr = path.join(home, ".seep", "current-case");
		if (home && fs.existsSync(ptr)) {
			const t = fs.readFileSync(ptr, "utf-8").trim();
			if (t) return path.resolve(t);
		}
	} catch {
		/* fallthrough */
	}
	return path.resolve(".seep-case");
}

function memoryDir(): string {
	return path.join(caseDir(), "memory");
}

function memFile(name: string): string {
	return path.join(memoryDir(), name);
}

/** 唯一账本：<case>/facts.jsonl（与 case_state.py 同一份，不再有 memory/ 副本）。 */
function ledgerFile(): string {
	return path.join(caseDir(), "facts.jsonl");
}

/* ────────────────────────────── 小工具 ────────────────────────────── */

function nowISO(): string {
	return new Date().toISOString();
}

function clip(s: string, n: number = MAX_SUMMARY): string {
	const one = String(s ?? "").replace(/\s+/g, " ").trim();
	if (one.length <= n) return one;
	return one.slice(0, n) + "…";
}

function looksSecret(s: string): boolean {
	return SECRET_RE.test(s);
}

/** 脱敏判定：命中凭据词就返回 redacted 摘要，否则返回原文。 */
function scrub(s: string): { text: string; redacted: boolean } {
	const text = clip(s);
	if (looksSecret(text)) return { text: "redacted", redacted: true };
	return { text, redacted: false };
}

function cwdOf(ctx: any): string {
	try {
		const c = ctx?.cwd;
		if (typeof c === "string" && c) return c;
	} catch {}
	return process.cwd();
}

/** 案例目录不存在 → 整个扩展空转（不创建、不报错）。 */
function caseExists(): boolean {
	try {
		return fs.existsSync(caseDir()) && fs.statSync(caseDir()).isDirectory();
	} catch {
		return false;
	}
}

async function readText(file: string): Promise<string> {
	try {
		return await fs.promises.readFile(file, "utf-8");
	} catch {
		return "";
	}
}

/* ───────────────────── 串行写队列（appendFile） ───────────────────── */

let writeChain: Promise<void> = Promise.resolve();

/**
 * 同一个进程里的事件写盘必须排队：tool_call 可能并行触发，
 * 并发 appendFile 虽不会丢数据，但行序会乱，时间线就不可信了。
 */
function enqueue(task: () => Promise<void>): void {
	writeChain = writeChain.then(task, task).catch(() => {
		/* 任何写盘异常都在这里吞掉：扩展不能成为会话的故障源 */
	});
}

async function ensureMemoryDir(): Promise<boolean> {
	if (!caseExists()) return false;
	try {
		await fs.promises.mkdir(memoryDir(), { recursive: true });
		return true;
	} catch {
		return false;
	}
}

async function appendLine(file: string, line: string): Promise<void> {
	if (!(await ensureMemoryDir())) return;
	try {
		await fs.promises.appendFile(file, line.endsWith("\n") ? line : line + "\n", "utf-8");
	} catch {
		/* 静默：写不进去不影响会话 */
	}
}

/** 追加一行到唯一账本（append-only；任何异常静默，扩展不能阻塞会话）。 */
async function appendLedger(obj: Record<string, unknown>): Promise<void> {
	if (!caseExists()) return;
	try {
		await fs.promises.appendFile(ledgerFile(), JSON.stringify(obj) + "\n", "utf-8");
	} catch {
		/* 静默 */
	}
}

interface EventEntry {
	ts: string;
	kind: "user" | "tool" | "turn" | "note";
	tool?: string;
	summary: string;
	cwd: string;
	redacted?: boolean;
}

function recordEvent(entry: Omit<EventEntry, "ts">): void {
	enqueue(async () => {
		try {
			// 事件行走同一个账本（kind:"event"）：S2 前写在 memory/events.jsonl，gate 读不到
			await appendLedger({ ts: nowISO(), ...entry, kind: "event", event: entry.kind });
		} catch {}
	});
}

/* ────────────────────── 从消息 / 工具输入取摘要 ────────────────────── */

function extractText(message: any): string {
	try {
		if (!message) return "";
		const c = message?.content;
		if (typeof c === "string") return c;
		if (Array.isArray(c)) {
			return c
				.map((b: any) => (b && b.type === "text" && typeof b.text === "string" ? b.text : ""))
				.filter(Boolean)
				.join("\n");
		}
	} catch {}
	return "";
}

function summarizeToolInput(name: string, input: any): { text: string; redacted: boolean } {
	const parts: string[] = [];
	try {
		if (input && typeof input === "object") {
			for (const k of SAFE_INPUT_KEYS) {
				const v = (input as Record<string, unknown>)[k];
				if (typeof v === "string" && v.trim()) parts.push(`${k}=${clip(v, 120)}`);
			}
			for (const k of CONTENT_INPUT_KEYS) {
				const v = (input as Record<string, unknown>)[k];
				if (typeof v === "string") parts.push(`${k}:${v.length}c(未记录正文)`);
			}
		}
	} catch {}
	if (!parts.length) parts.push(`(${name} 调用，无可摘要字段)`);
	return scrub(parts.join(" "));
}

/* ─────────────────────────── 标记通道 ─────────────────────────── */

function stripMarkerPrefix(line: string, prefix: string): string {
	let s = line.trim();
	// 允许行首是列表符号：`- @@FACT ...` / `* @@TRAP ...`
	s = s.replace(/^[-*+]\s+/, "");
	if (!s.startsWith(prefix)) return "";
	s = s.slice(prefix.length);
	s = s.replace(/^\s*[:：\-—]\s*/, "").trim();
	return s;
}

/** 解析一条 assistant 消息里的标记；返回 [目标文件, 去前缀后的文本]。 */
function parseMarkers(text: string): { file: string; kind: string; body: string }[] {
	const out: { file: string; kind: string; body: string }[] = [];
	const seen = new Set<string>();
	try {
		for (const rawLine of text.split(/\r?\n/)) {
			for (const m of MARKERS) {
				const body = stripMarkerPrefix(rawLine, m.prefix);
				if (!body) continue;
				const key = `${m.file}\u0000${body}`;
				if (seen.has(key)) continue;
				seen.add(key);
				out.push({ file: m.file, kind: m.kind, body });
			}
		}
	} catch {}
	return out;
}

function persistMarkers(items: { file: string; kind: string; body: string }[], cwd: string): void {
	if (!items.length) return;
	enqueue(async () => {
		try {
			for (const it of items) {
				const { text, redacted } = scrub(it.body);
				if (redacted) {
					// 标记里带凭据：不写目标文件，只在事件流里留一条 redacted
					await appendLedger({
						ts: nowISO(), kind: "event", event: "note",
						summary: "redacted", redacted: true, cwd,
					});
					continue;
				}
				if (it.kind === "fact") {
					// 结论速记 → 唯一账本。confidence 默认为 unknown：没标 observed/derived 就不计 pass。
					await appendLedger({
						ts: nowISO(), kind: "fact", claim: text,
						confidence: "unknown", authority: "none",
						source: "marker", cwd,
					});
				} else {
					if (!(await ensureMemoryDir())) continue;
					await appendLine(memFile(it.file), `- [${nowISO()}] ${text}`);
				}
			}
		} catch {}
	});
}

/* ─────────────────────────── 输出辅助 ─────────────────────────── */

function emit(ctx: any, msg: string, level: "info" | "warning" = "info"): void {
	let shown = false;
	try {
		const ui = (ctx as ExtensionCommandContext | undefined)?.ui;
		if (ui && typeof ui.notify === "function") {
			ui.notify(msg, level);
			shown = true;
		}
	} catch {}
	if (!shown) {
		try {
			console.log(msg);
		} catch {}
	}
}

function missingCaseMessage(): string {
	return (
		`未找到案例目录：${caseDir()}\n` +
		`把 SEEP_CASE_DIR 指向 <case>（例如 $env:SEEP_CASE_DIR="D:/work/项目J"），` +
		`或在当前目录建 .seep-case/。没有案例目录时本插件不记录任何东西。`
	);
}

/** 按字节裁切（不切碎 UTF-8 字符）。 */
function cutToBytes(s: string, maxBytes: number): string {
	let out = s;
	while (out && Buffer.byteLength(out, "utf8") > maxBytes) out = out.slice(0, -1);
	return out;
}

/** 按行数与字节数双重截断，避免把超长地图塞进提示词。 */
function capForPrompt(text: string, maxBytes: number, maxLines: number): string {
	if (maxBytes <= 0) return "";
	const lines = text.replace(/\r\n/g, "\n").split("\n").slice(0, maxLines);
	const SUFFIX = "\n…（截断）";
	let out = "";
	for (const line of lines) {
		const candidate = out ? `${out}\n${line}` : line;
		if (Buffer.byteLength(candidate, "utf8") <= maxBytes) {
			out = candidate;
			continue;
		}
		// 这一行放不下：保留已积累的内容，并确保加上省略标记后仍不超限。
		const suffixBytes = Buffer.byteLength(SUFFIX, "utf8");
		const room = Math.max(0, maxBytes - suffixBytes);
		if (!out) {
			// 第一行就超长：从行首裁到预算内，而不是整段丢掉。
			out = cutToBytes(line, room);
		} else if (Buffer.byteLength(out, "utf8") > room) {
			out = cutToBytes(out, room);
		}
		out += SUFFIX;
		break;
	}
	return out;
}

/* ─────────────────────────── 扩展入口 ─────────────────────────── */

export default function seepMemory(pi: ExtensionAPI) {
	/* 1. 会话开始：记一条 note，并把 case 目录状态告诉用户（只提示一次，不吵） */
	pi.on("session_start", async (_event: any, ctx: any) => {
		try {
			if (!caseExists()) return;
			recordEvent({ kind: "note", summary: "session_start", cwd: cwdOf(ctx) });
		} catch {}
	});

	/* 2. 用户输入：kind=user（凭据命中即 redacted） */
	pi.on("input", async (event: any, ctx: any) => {
		try {
			if (!caseExists()) return;
			const raw = typeof event?.text === "string" ? event.text : "";
			if (!raw.trim()) return;
			const { text, redacted } = scrub(raw);
			recordEvent({ kind: "user", summary: text, cwd: cwdOf(ctx), redacted });
		} catch {}
	});

	/* 3. 工具调用：kind=tool。不记结果、不记文件正文。 */
	pi.on("tool_call", async (event: any, ctx: any) => {
		try {
			if (!caseExists()) return;
			const name = String(event?.toolName ?? "unknown");
			const { text, redacted } = summarizeToolInput(name, event?.input);
			recordEvent({ kind: "tool", tool: name, summary: text, cwd: cwdOf(ctx), redacted });
		} catch {}
	});

	/* 4. 每轮结束：kind=turn + 解析 @@ 标记 */
	pi.on("turn_end", async (event: any, ctx: any) => {
		try {
			if (!caseExists()) return;
			const cwd = cwdOf(ctx);
			const message = event?.message;
			const body = extractText(message);
			const idx = typeof event?.turnIndex === "number" ? event.turnIndex : "?";
			const firstLine = body.split(/\r?\n/).find((l) => l.trim()) || "(本轮无文本)";
			const { text, redacted } = scrub(`turn #${idx}: ${firstLine}`);
			recordEvent({ kind: "turn", summary: text, cwd, redacted });

			// 标记只加权，不是唯一通道：没写标记也不会丢事件流。
			// 标记单独脱敏（persistMarkers 内做），不能被 turn 摘要的命中连坐。
			if (!message?.role || message.role === "assistant") {
				persistMarkers(parseMarkers(body), cwd);
			}
		} catch {}
	});

	/**
	 * 5. 触发式注入：每次 run 开始只挂 map.md，不挂 events / facts / traps。
	 *    - 硬上限 1.5KB + 40 行；
	 *    - map.md 不存在/为空 → 不注入，连 section 都不建；
	 *    - 任何异常都吞掉，绝不阻断 run。
	 */
	pi.on("before_agent_start", async (event: any, _ctx: any) => {
		try {
			if (!caseExists()) return {};
			const raw = await readText(memFile("map.md"));
			if (!raw.trim()) return {};
			// 硬上限 1.5KB：header + body + footer 全部算在内。
			const header = `[Seep 记忆地图 · 插件自动注入 · 只读]\n`;
			const footer =
				`\n[来源 <case>/memory/map.md。需要细节时用 /map /facts /traps；` +
				`不要假设这里没写的结论已经验证过。]`;
			const budget =
				MAP_INJECT_BYTES -
				Buffer.byteLength(header, "utf8") -
				Buffer.byteLength(footer, "utf8") -
				2; // 两个换行
			const body = capForPrompt(raw, budget, MAP_MAX_LINES);
			if (!body.trim()) return {};
			const opts = event?.systemPromptOptions;
			if (!opts) return {};
			opts.sections = opts.sections ?? {};
			opts.sections[SECTION_KEY] = `${header}${body}${footer}`;
		} catch {}
		return {};
	});

	/* ────────────────────────── 命令 ────────────────────────── */

	pi.registerCommand("map", {
		description: "打印案子记忆地图 memory/map.md（最多 40 行）",
		handler: async (_args: string, ctx: ExtensionCommandContext) => {
			try {
				if (!caseExists()) {
					emit(ctx, missingCaseMessage(), "warning");
					return;
				}
				const raw = await readText(memFile("map.md"));
				if (!raw.trim()) {
					emit(ctx, `map.md 为空或不存在：${memFile("map.md")}`, "warning");
					return;
				}
				const lines = raw.replace(/\r\n/g, "\n").split("\n").slice(0, MAP_MAX_LINES);
				const more = raw.split("\n").length > MAP_MAX_LINES ? "\n…（已截断到 40 行）" : "";
				emit(ctx, `=== memory/map.md ===\n${lines.join("\n")}${more}`);
			} catch (e) {
				emit(ctx, `/map 读取失败（已忽略）：${(e as Error)?.message ?? e}`, "warning");
			}
		},
	});

	pi.registerCommand("facts", {
		description: `打印 <case>/facts.jsonl 最近 ${FACTS_LAST_N} 条（claim / state / event）`,
		handler: async (_args: string, ctx: ExtensionCommandContext) => {
			try {
				if (!caseExists()) {
					emit(ctx, missingCaseMessage(), "warning");
					return;
				}
				const raw = await readText(ledgerFile());
				const lines = raw
					.replace(/\r\n/g, "\n")
					.split("\n")
					.map((l) => l.trim())
					.filter(Boolean);
				if (!lines.length) {
					emit(ctx, `facts.jsonl 为空或不存在：${ledgerFile()}`, "warning");
					return;
				}
				const tail = lines.slice(-FACTS_LAST_N);
				const out: string[] = [`=== facts.jsonl（最近 ${tail.length} 条 / 共 ${lines.length}）===`];
				tail.forEach((line, i) => {
					try {
						const o = JSON.parse(line);
						const ts = String(o.ts ?? o.created ?? "").replace("T", " ").slice(0, 19);
						const tag = o.kind || o.status || "claim";
						const text = clip(String(o.claim ?? o.text ?? o.summary ?? line), 180);
						const conf = o.confidence ? `/${o.confidence}` : "";
						out.push(`${String(i + 1).padStart(2)}. [${ts}] (${tag}${conf}) ${text}`);
					} catch {
						out.push(`${String(i + 1).padStart(2)}. ${clip(line, 180)}`);
					}
				});
				emit(ctx, out.join("\n"));
			} catch (e) {
				emit(ctx, `/facts 读取失败（已忽略）：${(e as Error)?.message ?? e}`, "warning");
			}
		},
	});

	pi.registerCommand("traps", {
		description: "打印案子踩坑清单 memory/traps.md",
		handler: async (_args: string, ctx: ExtensionCommandContext) => {
			try {
				if (!caseExists()) {
					emit(ctx, missingCaseMessage(), "warning");
					return;
				}
				const raw = await readText(memFile("traps.md"));
				if (!raw.trim()) {
					emit(ctx, `traps.md 为空或不存在：${memFile("traps.md")}`, "warning");
					return;
				}
				const all = raw.replace(/\r\n/g, "\n").split("\n");
				const lines = all.slice(0, TRAPS_MAX_LINES);
				const more = all.length > TRAPS_MAX_LINES ? `\n…（已截断到 ${TRAPS_MAX_LINES} 行）` : "";
				emit(ctx, `=== memory/traps.md ===\n${lines.join("\n")}${more}`);
			} catch (e) {
				emit(ctx, `/traps 读取失败（已忽略）：${(e as Error)?.message ?? e}`, "warning");
			}
		},
	});

	pi.registerCommand("memory-note", {
		description: "追加一条 note 事件到 facts.jsonl（kind:event）：/memory-note <文本>",
		handler: async (args: string, ctx: ExtensionCommandContext) => {
			try {
				if (!caseExists()) {
					emit(ctx, missingCaseMessage(), "warning");
					return;
				}
				const raw = String(args ?? "").trim();
				if (!raw) {
					emit(ctx, "用法：/memory-note <要记的一句话>", "warning");
					return;
				}
				const { text, redacted } = scrub(raw);
				recordEvent({ kind: "note", summary: text, cwd: cwdOf(ctx), redacted });
				emit(
					ctx,
					redacted
						? "已记录 note（内容命中凭据词，已按隐私红线脱敏为 redacted）。"
						: "已记录 note 到 facts.jsonl（kind:event）。",
				);
			} catch (e) {
				emit(ctx, `/memory-note 写入失败（已忽略）：${(e as Error)?.message ?? e}`, "warning");
			}
		},
	});
}
