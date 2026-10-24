/**
 * seep-events —— 工具事件账（每个工具动作自动落盘，不依赖模型自觉）
 *
 * 存在的原因（血案）：
 *   "facts 一直是 0"。规矩写在提示词里，模型忙起来就忘了记账；
 *   一次会话几十个工具动作之后，问「你到底跑过什么」只能靠翻上下文猜。
 *   事实账（case_state.py）是**结论**账，必须由模型主动写；
 *   事件账是**动作**账，必须由插件自动写 —— 两者不能混。
 *
 * 落盘位置（硬约定，与 case_state.py events 子命令对齐）：
 *   <case>/events.jsonl      每行一个 JSON：
 *     ts      ISO 时间戳（结账时刻）
 *     eid     单调递增的事件号（<毫秒>-<序号>，字符串排序即时间序）
 *     tool    工具名（bash / read / edit / mcp__xxx …）
 *     ok      该次调用是否成功（!isError）
 *     durMs   工具真实执行耗时（tool_call 到 tool_result 的墙钟差值）
 *     risk    "block" / "warn" / null —— **规则等级**，见下
 *     summary ≤200 字输入摘要（已脱敏；不写文件正文）
 *
 * case 目录解析顺序：
 *   1. 环境变量 SEEP_CASE_DIR
 *   2. <cwd>/.seep-case
 *   目录不存在 → **静默跳过**：不创建目录、不报错、不打扰（没开案子的普通会话不该被记账）。
 *
 * ── risk 的语义（重要，别读错）────────────────────────────────
 *   risk 是「这条动作按本地规则表的等级」，**不等于它真的被拦了**。
 *   被别的扩展（如 cmd-guard）拦下的调用不会产生 tool_result，
 *   因此这类调用以 ok=false 落账 —— ok 才是「有没有跑完」的事实。
 *   规则表是 cmd-guard 禁手表的子集，抄在这里而不是读文件：
 *   记账层不允许有「规则文件读不到 → 整个扩展静默失效」这种失败模式。
 *   risk = null 表示没有任何规则命中（绝大多数读类动作）。
 *
 * ── 脱敏（硬约束）──────────────────────────────────────────────
 *   summary 里出现 token|secret|key|password|card_code|cookie|authorization 时，
 *   把**其后的值**替换成 ***（保留键名，便于事后知道"这步需要凭据"）。
 *   与 seep-memory 的「整条丢弃」不同：这里是动作账，丢了就断线；
 *   凭据本体仍然一个字节都不落盘。
 *
 * ── 容错（硬约束）──────────────────────────────────────────────
 *   所有 handler 整体 try/catch，任何异常吞掉；写盘串行排队。
 *   记账层永远不许成为会话的故障源 —— 它坏了顶多没有事件账，
 *   绝不会让工具调用失败或被阻断。
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

/* ────────────────────────────── 常量 ────────────────────────────── */

/** 摘要硬上限（字符数） */
const MAX_SUMMARY = 200;
/** 未结账的 pending 上限：超过就丢最老的，绝不无限涨内存 */
const PENDING_MAX = 256;
/**
 * 等 tool_result 的最长时间。超时说明这次调用没有结果（被别的扩展拦下 / 进程被杀），
 * 按 ok=false 补账 —— 宁可晚记，也不要让「被拦下的动作」在账上消失。
 * 取 5 分钟：远大于普通命令，又远小于重编译/长任务，误判概率低。
 */
const FLUSH_MS = 5 * 60 * 1000;

/** tool_call 里允许摘录的字段：路径 / 命令 / 查询词，都不含文件正文。 */
const SAFE_INPUT_KEYS = [
	"command",
	"script",
	"code",
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
	"case",
	"args",
	"id",
	"level",
	"status",
];

/** 只记长度、绝不记正文的字段（写文件 / 打补丁类工具的正文）。 */
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
	"bytes",
	"payload",
];

type Risk = "block" | "warn" | null;

/**
 * 风险规则表（cmd-guard 禁手表的记账子集）。
 * 顺序有意义：先匹配到的等级胜出，所以 block 类必须排在 warn 类之前。
 * 不读 cmd-guard.rules.json —— 记账层不许有「规则文件读不到就静默失效」的失败模式。
 */
const RISK_RULES: { re: RegExp; level: Exclude<Risk, null> }[] = [
	// ── block：改本机全局网络 / 不可逆破坏 ──
	{ re: /\b(new|remove|set)-netipaddress\b/i, level: "block" },
	{ re: /\b(set|enable|disable|restart)-net(adapter|ipinterface|tcpsetting)\b/i, level: "block" },
	{ re: /netsh\s+winhttp\s+set\b/i, level: "block" },
	{ re: /netsh\s+(interface|winsock)\s+(set|reset|add)\b/i, level: "block" },
	{ re: /\b(route|netsh\s+route)\s+(add|delete)\b/i, level: "block" },
	{ re: /\bset-netroute\b/i, level: "block" },
	{ re: /\brm\s+-[a-z]*[rf][a-z]*\b/i, level: "block" },
	{ re: /\b(rd|rmdir)\s+\/s\b/i, level: "block" },
	{ re: /\bformat\s+[a-z]:/i, level: "block" },
	{ re: /\b(mkfs|diskpart|fdisk)\b/i, level: "block" },
	{ re: /\bgit\s+reset\s+--hard\b/i, level: "block" },
	{ re: /\bgit\s+clean\s+-[a-z]*f/i, level: "block" },
	{ re: /\bgit\s+push\b[^\n]*--force\b/i, level: "block" },
	{ re: /\b(reg\s+delete|bcdedit|cipher\s+\/w)\b/i, level: "block" },
	{ re: /\b(shutdown|reboot|Restart-Computer|Stop-Computer)\b/i, level: "block" },
	{ re: /\bdrop\s+(table|database)\b|\btruncate\s+table\b/i, level: "block" },
	{ re: />\s*\/dev\/(sd|nvme|hd)/i, level: "block" },
	// ── warn：会把结果带进来 / 有外部副作用 / 用 shell 拉起 GUI ──
	{ re: /\b(curl|wget)\b[^|\n]*\|\s*(ba|z|k)?sh\b/i, level: "warn" },
	{ re: /\b(invoke-webrequest|iwr|curl)\b[^\n]*\|\s*(iex|invoke-expression)\b/i, level: "warn" },
	{ re: /powershell(\.exe)?\s+-(enc|encodedcommand|e)\b/i, level: "warn" },
	{ re: /\bcertutil\b[^\n]*-urlcache\b/i, level: "warn" },
	{ re: /\bchmod\s+[0-7]*7[0-7]*7\b/i, level: "warn" },
	{ re: /\btaskkill\b[^\n]*\/f\b/i, level: "warn" },
	{ re: /\bnet\s+user\b[^\n]*\/add\b/i, level: "warn" },
	{ re: /\bschtasks\b[^\n]*\/create\b/i, level: "warn" },
	{ re: /\bstart\b[^\n]*\.exe\b/i, level: "warn" },
	{ re: /\b(del|erase|rm)\s+[^\n|&;]+/i, level: "warn" },
];

/** 脱敏关键词（保留键名，值换成 ***）。 */
const SECRET_WORD = "token|secret|key|password|card_code|cookie|authorization";
/**
 * 认证方案前缀：`Authorization: Bearer sk-xxx` 里的真值是方案名**后面**那一段。
 * 必须先于 KV 规则跑，否则只把 Bearer 打成 ***、sk-xxx 会原样漏出去（已实测到这个漏洞）。
 */
const RE_SECRET_SCHEME = /\b(bearer|basic|digest|negotiate|token)\s+([^\s,;&|"')\]}]+)/gi;
/** key=value / "key": "value" */
const RE_SECRET_KV = new RegExp(
	`(${SECRET_WORD})([A-Za-z0-9_-]*)(\\s*["']?\\s*[:=]\\s*)("[^"]*"|'[^']*'|[^\\s,;&|"')\\]}]+)`,
	"gi",
);
/** key value（空格分隔，值至少 3 字符） */
const RE_SECRET_BARE = new RegExp(
	`\\b(${SECRET_WORD})([A-Za-z0-9_-]*)(\\s+)("[^"]*"|'[^']*'|[^\\s,;&|"')\\]}]{3,})`,
	"gi",
);

/* ────────────────────────────── 小工具 ────────────────────────────── */

function clip(s: string, n: number = MAX_SUMMARY): string {
	const one = String(s ?? "")
		.replace(/\s+/g, " ")
		.trim();
	if (one.length <= n) return one;
	return one.slice(0, n) + "…";
}

/** 关键词后的值换成 ***：保留键名，便于事后知道「这步要凭据」，但凭据本体不落盘。 */
function redact(s: string): string {
	let out = String(s ?? "");
	try {
		// 顺序不可换：先吃方案名后的真值，再吃 key=value
		out = out.replace(RE_SECRET_SCHEME, (_m, scheme) => `${scheme} ***`);
		out = out.replace(RE_SECRET_KV, (_m, k, rest, sep) => `${k}${rest}${sep}***`);
		out = out.replace(RE_SECRET_BARE, (_m, k, rest, sep) => `${k}${rest}${sep}***`);
	} catch {
		// 正则不该抛；万一抛了，宁可整条打码也不把原文写出去
		return "redacted";
	}
	return out;
}

/** case 目录：SEEP_CASE_DIR → <cwd>/.seep-case。 */
function caseDirOf(cwd: string): string {
	try {
		const raw = process.env.SEEP_CASE_DIR;
		if (raw && raw.trim()) return path.resolve(raw.trim());
		return path.resolve(cwd || process.cwd(), ".seep-case");
	} catch {
		return path.resolve(".seep-case");
	}
}

function cwdOf(ctx: any, fallback: string): string {
	try {
		const c = ctx?.cwd;
		if (typeof c === "string" && c) return c;
	} catch {}
	return fallback;
}

/** 案例目录不存在 → 整个扩展空转（不创建、不报错）。 */
function caseExists(cwd: string): boolean {
	try {
		const d = caseDirOf(cwd);
		return fs.existsSync(d) && fs.statSync(d).isDirectory();
	} catch {
		return false;
	}
}

/* ───────────────────── 串行写盘 + 事件号 ───────────────────── */

let writeChain: Promise<void> = Promise.resolve();
let seq = 0;

function nextEid(): string {
	seq += 1;
	return `${Date.now()}-${String(seq).padStart(4, "0")}`;
}

function enqueue(task: () => Promise<void>): void {
	writeChain = writeChain.then(task, task).catch(() => {
		/* 写盘异常一律吞掉：记账层不是会话的故障源 */
	});
}

interface EventRow {
	tool: string;
	ok: boolean;
	durMs: number;
	risk: Risk;
	summary: string;
}

function record(cwd: string, row: EventRow): void {
	enqueue(async () => {
		try {
			if (!caseExists(cwd)) return;
			const line = JSON.stringify({
				ts: new Date().toISOString(),
				eid: nextEid(),
				tool: row.tool,
				ok: row.ok,
				durMs: row.durMs,
				risk: row.risk,
				summary: clip(row.summary, MAX_SUMMARY),
			});
			await fs.promises.appendFile(path.join(caseDirOf(cwd), "events.jsonl"), line + "\n", "utf-8");
		} catch {
			/* 静默 */
		}
	});
}

/* ────────────────────── 摘要 / 风险 ────────────────────── */

function summarizeToolInput(name: string, input: any): string {
	const parts: string[] = [];
	try {
		if (input && typeof input === "object") {
			for (const k of SAFE_INPUT_KEYS) {
				const v = (input as Record<string, unknown>)[k];
				if (typeof v === "string" && v.trim()) parts.push(`${k}=${clip(v, 120)}`);
				else if (typeof v === "number" || typeof v === "boolean") parts.push(`${k}=${v}`);
			}
			for (const k of CONTENT_INPUT_KEYS) {
				const v = (input as Record<string, unknown>)[k];
				if (typeof v === "string") parts.push(`${k}:${v.length}c(正文不入账)`);
			}
		}
	} catch {}
	if (!parts.length) parts.push(`(${name} 调用，无可摘要字段)`);
	// 先拼再脱敏：键名与值分开处理会漏掉「值在别的字段里」的情况
	return redact(clip(parts.join(" "), MAX_SUMMARY * 2));
}

function assessRisk(name: string, input: any): Risk {
	try {
		let hay = "";
		try {
			hay = typeof input === "string" ? input : JSON.stringify(input ?? {});
		} catch {
			hay = "";
		}
		hay = `${name} ${hay}`;
		for (const rule of RISK_RULES) {
			if (rule.re.test(hay)) return rule.level;
		}
	} catch {}
	return null;
}

/* ────────────────────── 未结账补账 ────────────────────── */

interface Pending {
	start: number;
	risk: Risk;
	summary: string;
	tool: string;
}

/** toolCallId → 已开始但还没拿到结果的调用 */
const pending = new Map<string, Pending>();

function keepPendingBounded(): void {
	try {
		while (pending.size > PENDING_MAX) {
			const first = pending.keys().next();
			if (first.done) break;
			pending.delete(first.value);
		}
	} catch {}
}

/**
 * 把「开了但没等到结果」的调用按 ok=false 结账。
 * @param all true = 会话已结束（agent_end / shutdown），全部结账；false = 只结超过 FLUSH_MS 的
 */
function flushPending(cwd: string, all: boolean): void {
	try {
		const now = Date.now();
		for (const [id, p] of Array.from(pending.entries())) {
			if (!all && now - p.start < FLUSH_MS) continue;
			pending.delete(id);
			record(cwd, {
				tool: p.tool,
				ok: false,
				durMs: Math.max(1, now - p.start),
				risk: p.risk,
				summary: p.summary,
			});
		}
	} catch {}
}

/* ─────────────────────────── 扩展入口 ─────────────────────────── */

export default function seepEvents(pi: ExtensionAPI) {
	/** 最近一次看到的 cwd：给 turn_end / agent_end 这类不带 cwd 的钩子兜底 */
	let lastCwd = "";

	/* 1. 工具开始：只登记 pending，不落盘（此时还不知道 ok / 耗时） */
	pi.on("tool_call", async (event: any, ctx: any) => {
		try {
			const cwd = cwdOf(ctx, lastCwd || process.cwd());
			lastCwd = cwd;
			if (!caseExists(cwd)) return;
			flushPending(cwd, false);
			const id = String(event?.toolCallId ?? "") || `no-id-${nextEid()}`;
			const tool = String(event?.toolName ?? "unknown");
			pending.set(id, {
				start: Date.now(),
				risk: assessRisk(tool, event?.input),
				summary: summarizeToolInput(tool, event?.input),
				tool,
			});
			keepPendingBounded();
		} catch {}
	});

	/* 2. 工具结束：结账一行（ok / durMs / risk / summary 都齐了） */
	pi.on("tool_result", async (event: any, ctx: any) => {
		try {
			const cwd = cwdOf(ctx, lastCwd || process.cwd());
			lastCwd = cwd;
			if (!caseExists(cwd)) return;
			flushPending(cwd, false);
			const id = String(event?.toolCallId ?? "");
			const p = id ? pending.get(id) : undefined;
			if (id && p) pending.delete(id);
			const tool = String(event?.toolName ?? p?.tool ?? "unknown");
			record(cwd, {
				tool,
				ok: !event?.isError,
				durMs: p ? Math.max(1, Date.now() - p.start) : 0,
				risk: p ? p.risk : assessRisk(tool, event?.input),
				summary: p ? p.summary : summarizeToolInput(tool, event?.input),
			});
		} catch {}
	});

	/* 3. 每轮结束：顺手补掉超时未结账的调用（不主动写别的） */
	pi.on("turn_end", async (_event: any, ctx: any) => {
		try {
			const cwd = cwdOf(ctx, lastCwd || process.cwd());
			lastCwd = cwd;
			if (!caseExists(cwd)) return;
			flushPending(cwd, false);
		} catch {}
	});

	/* 4. 会话结束：所有没等到结果的调用按 ok=false 结账（不会有结果了） */
	pi.on("agent_end", async (_event: any, ctx: any) => {
		try {
			const cwd = cwdOf(ctx, lastCwd || process.cwd());
			lastCwd = cwd;
			if (!caseExists(cwd)) return;
			flushPending(cwd, true);
		} catch {}
	});

	pi.on("session_shutdown", async (_event: any, ctx: any) => {
		try {
			const cwd = cwdOf(ctx, lastCwd || process.cwd());
			if (!caseExists(cwd)) return;
			flushPending(cwd, true);
		} catch {}
	});
}
