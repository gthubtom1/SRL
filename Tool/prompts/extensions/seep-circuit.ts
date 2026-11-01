/**
 * Pause identical failed inputs, leaving changed calls and other sessions usable.
 * Successful edits/writes invalidate prior streaks so build/test repair can proceed.
 * This is retry guidance, not authorization or a task-wide stopping condition.
 */

import { createHash } from "node:crypto";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

/* ────────────────────────────── 常量 ────────────────────────────── */

/** 默认阈值：连撞 2 次，第 3 次拦。 */
const DEFAULT_N = 2;
/** signature 上限（字符数）。够认出形状，又不至于把整行日志当 key。 */
const SIG_MAX = 80;
/** 记住的 tool 数上限：防 MCP 工具爆炸式命名把内存拖死。 */
const TOOL_MAX = 128;
/** 每个 tool 记住的 signature 数上限：只留最近的几条。 */
const SIG_PER_TOOL_MAX = 8;
/** 等待 tool_result 的调用上限；tool_result 不一定回传 input，必须保留发起时的形状。 */
const ACTIVE_CALL_MAX = 256;
/** 本插件自己发出去的拦截文案标记：这类结果不能回头算作「又失败一次」。 */
const OWN_MARK = "[seep-circuit] TOOL_BLOCKED";

/**
 * 白名单：照 reason 办的那几条命令必须永远能跑。
 * 否则 bash 一熔断，模型连查表命令都发不出去 = 死锁（比不拦更糟）。
 */
const SANCTIONED = new Set(["tool-acquire.py", "case_state.py", "preflight.py"]);

/**
 * 永不熔断的「迭代型」工具：命中即放行、且**不计数**。
 *
 * 判据：这个工具的正常用法里，「上一次调用报错、下一次改参数再来」是主路径。
 *   · edit   —— oldText 不匹配 → 重读文件、改 oldText 再试（这是正确姿势，不是撞墙）
 *   · write  —— 路径/权限/编码问题常靠换路径或建目录解决
 *   · read   —— 读一个不存在的文件是侦察步骤，不是能力缺陷
 *   · grep/find/ls —— 「没找到」既是一次探索结果，也可能是一种成功
 *   · todo   —— 记账工具，报错说明参数写错，改一下就行
 * 熔断它们只会让任务卡死（连「修」的手段都被拦掉），收益为零。
 */
const NEVER_BREAK = new Set(["edit", "write", "read", "grep", "find", "ls", "todo"]);

/** 该工具是否属于「永不熔断」的一类（工具名大小写不敏感）。 */
function isNeverBreak(tool: string): boolean {
	try {
		return NEVER_BREAK.has(String(tool ?? "").trim().toLowerCase());
	} catch {
		return false;
	}
}

/* ────────────────────────────── 状态 ────────────────────────────── */
/*
 * 全部在内存：sessionId → (tool → (调用签名 → { 连撞次数, 最近一次错误形状 }))。
 * key 用**调用签名**（这次调用长什么形状），而不是整个工具名 ——
 * 这样「某个签名撞满」只会拦住同一类调用，其它 bash 命令不受牵连。
 * 错误摘要仅用于状态诊断；调用标识对完整输入求哈希，不输出原始参数。
 * 不做持久化是刻意的 —— 跨会话保留会把「新会话第一次调用」也算成第三次。
 * 插入顺序即最近使用顺序，超上限时丢最老的 tool。
 */
type StreakEntry = { count: number; errSig: string };
type ActiveCall = { tool: string; callSig: string; at: number; revision: number };
type SessionState = {
	streaks: Map<string, Map<string, StreakEntry>>;
	calls: Map<string, ActiveCall>;
	tripped: number;
	revision: number;
};
const sessionStates = new Map<string, SessionState>();

function sessionIdOf(ctx: any): string {
	// 真实 session id 是完整会话的身份，不能让工具执行期间的 cwd 变化把同一个
	// 会话拆成两份状态；否则 tool_call 记在旧 cwd、tool_result 落在新 cwd，失败
	// 形状永远结不上账。旧宿主没有 session id 时才退回 cwd 分区。
	try {
		const sid = ctx?.sessionManager?.getSessionId?.();
		if (typeof sid === "string" && sid.trim()) return `id:${sid.trim()}`;
	} catch {}
	for (const value of [ctx?.sessionId, ctx?.session_id, ctx?.sessionID]) {
		if (typeof value === "string" && value.trim()) return `id:${value.trim()}`;
	}
	let cwd = "";
	try {
		cwd = typeof ctx?.cwd === "string" && ctx.cwd ? pathResolve(ctx.cwd) : pathResolve(process.cwd());
	} catch {
		cwd = "unknown";
	}
	return `cwd:${cwd}`;
}

export function sessionPathKeyForTest(
	value: string,
	platform: NodeJS.Platform = process.platform,
): string {
	const normalized = String(value).replace(/\\/g, "/").replace(/\/+$/, "");
	// Windows 路径大小写不敏感；POSIX 区分大小写，不能把 /tmp/A 与 /tmp/a 合并。
	return platform === "win32" ? normalized.toLowerCase() : normalized;
}

function pathResolve(value: string): string {
	return sessionPathKeyForTest(value);
}

function emptySessionState(): SessionState {
	return {
		streaks: new Map<string, Map<string, StreakEntry>>(),
		calls: new Map<string, ActiveCall>(),
		tripped: 0,
	revision: 0,
	};
}

function stateFor(ctx: any): SessionState {
	const id = sessionIdOf(ctx);
	let state = sessionStates.get(id);
	if (!state) {
		state = emptySessionState();
		sessionStates.set(id, state);
	}
	return state;
}

function rememberActiveCall(state: SessionState, id: string, tool: string, callSig: string): void {
	if (!id) return;
	// 删除再重插，使 Map 顺序保持 LRU；异常宿主重复使用 id 时也覆盖旧值。
	state.calls.delete(id);
	state.calls.set(id, { tool, callSig, at: Date.now(), revision: state.revision });
	while (state.calls.size > ACTIVE_CALL_MAX) {
		const first = state.calls.keys().next();
		if (first.done) break;
		state.calls.delete(first.value);
	}
}

/** 阈值：环境变量可变，非法值退回默认（每次读，便于测试与临时放宽）。 */
function threshold(): number {
	try {
		const raw = process.env.SEEP_CIRCUIT_N;
		if (raw === undefined || raw === null || String(raw).trim() === "") return DEFAULT_N;
		const n = Number.parseInt(String(raw).trim(), 10);
		if (!Number.isFinite(n) || n < 0) return DEFAULT_N;
		return n; // 0 = 只计数不拦
	} catch {
		return DEFAULT_N;
	}
}

function toolBucket(state: SessionState, tool: string): Map<string, StreakEntry> {
	let b = state.streaks.get(tool);
	if (!b) {
		b = new Map<string, StreakEntry>();
		state.streaks.set(tool, b);
	}
	// 超上限：Map 的迭代顺序即插入顺序，删最老的 key 即可
	while (state.streaks.size > TOOL_MAX) {
		const first = state.streaks.keys().next();
		if (first.done || first.value === tool) break;
		state.streaks.delete(first.value);
	}
	return b;
}

function bumpStreak(state: SessionState, tool: string, callSig: string, errSig: string): number {
	const b = toolBucket(state, tool);
	const prev = b.get(callSig);
	const next = (prev?.count ?? 0) + 1;
	b.delete(callSig);
	// 重插到尾部 = 标记为最近；错误形状只留最近一次（给 reason 用）
	b.set(callSig, { count: next, errSig: errSig || prev?.errSig || "(no message)" });
	while (b.size > SIG_PER_TOOL_MAX) {
		const first = b.keys().next();
		if (first.done || first.value === callSig) break;
		b.delete(first.value);
	}
	return next;
}

/** 该 tool 下**这一种调用形状**的连撞记录（没有 → null）。 */
function entryFor(state: SessionState, tool: string, callSig: string): StreakEntry | null {
	const b = state.streaks.get(tool);
	if (!b) return null;
	return b.get(callSig) ?? null;
}

function clearTool(state: SessionState, tool: string): void {
	state.streaks.delete(tool);
}

/* ────────────────────── 错误形状归一化 ────────────────────── */

/** 把 tool_result 的 content 摊平成纯文本（图片块直接跳过）。 */
function textOf(event: any): string {
	try {
		const parts: string[] = [];
		const content = event?.content;
		if (Array.isArray(content)) {
			for (const item of content) {
				if (typeof item === "string") parts.push(item);
				else if (item && typeof item === "object" && typeof (item as any).text === "string") {
					parts.push((item as any).text);
				}
			}
		} else if (typeof content === "string") {
			parts.push(content);
		}
		return parts.join("\n");
	} catch {
		return "";
	}
}

/**
 * signature 归一化：同一形状、不同参数 → 同一个 key。
 *   1. 取首个非空行（错误首行信息量最大；堆栈/调用链只会带来噪声）
 *   2. 去掉引号/反引号包着的内容（往往是路径、标识符、参数值）
 *   3. 路径 → <path>
 *   4. 数字 → <n>
 *   5. 折叠空白 + 小写 + 截 80 字
 */
export function signatureOf(text: string): string {
	let s = "";
	try {
		const raw = String(text ?? "");
		// 1. 首个非空行
		for (const line of raw.split(/\r?\n/)) {
			const t = line.trim();
			if (t) {
				s = t;
				break;
			}
		}
		if (!s) return "(no message)";
		// 2. 引号内容（含未闭合的）
		s = s.replace(/"[^"]*"/g, " ").replace(/'[^']*'/g, " ").replace(/`[^`]*`/g, " ");
		// 3. 路径：盘符 / 反斜杠 / 正斜杠的连续非空白串（先于数字，否则 C:\a\1 会被拆碎）
		s = s.replace(/(?:[A-Za-z]:)?[\\/][^\s,;:"')}\]]*/g, " <path> ");
		// 3b. 裸文件名（含扩展名）也是「同一形状不同参数」的主要变量源
		s = s.replace(/\b[\w.-]+\.(?:py|js|mjs|ts|exe|dll|so|apk|json|jsonl|md|txt|log|bin|zip|pyc)\b/gi, " <file> ");
		// 4. 数字（含 0x.. / 1.2 / 1e9）
		s = s.replace(/\b0x[0-9a-f]+\b/gi, " <n> ").replace(/\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b/gi, " <n> ");
		// 5. 折叠空白 + 小写 + 截断
		s = s.replace(/\s+/g, " ").trim().toLowerCase();
		if (!s) return "(no message)";
		if (s.length > SIG_MAX) s = s.slice(0, SIG_MAX);
		return s;
	} catch {
		return "(unparsed)";
	}
}

/** 这条结果是不是本插件自己拦出来的（拦截不能自我加码，否则一发不可收拾）。 */
function isOwnBlock(text: string): boolean {
	try {
		return String(text ?? "").includes(OWN_MARK);
	} catch {
		return false;
	}
}

/* ───────────────── 合法业务出口（不计数）───────────────── */

/**
 * 合法业务出口的标记：这些不是「工具坏了」，是工具**正确地告诉模型一个结果**。
 *   [UNCLASSIFIED] —— route.py --resolve --strict 判不出领域（rc=2，设计如此）
 *   [NONE]         —— 侦察类脚本「什么也没找到」（路由/检索的合法空结果）
 *   [FALLBACK]     —— 路由只命中兜底条目（合法降级，不等于失败）
 */
const LEGIT_MARKS = ["[UNCLASSIFIED]", "[NONE]", "[FALLBACK]"];

/**
 * 这次调用的退出码（拿不到就是 null）。
 * bash 工具把真退出码放在 structuredContent.exit_code，失败时还会在文本尾部
 * 追加一行 `Command exited with code N` —— 两条路都认，拿不到才认 null。
 */
export function exitCodeOf(event: any): number | null {
	try {
		const sc = event?.structuredContent;
		const cands = [
			sc?.exit_code,
			sc?.exitCode,
			event?.details?.exitCode,
			event?.details?.exit_code,
			event?.exitCode,
		];
		for (const c of cands) {
			if (typeof c === "number" && Number.isFinite(c)) return c;
			if (typeof c === "string" && /^-?\d+$/.test(c.trim())) return Number.parseInt(c.trim(), 10);
		}
		// 文本尾巴：`Command exited with code 2` / `Command exited with code 1`
		const tail = textOf(event);
		const m = tail.match(/Command exited with code (-?\d+)/);
		if (m) return Number.parseInt(m[1], 10);
		return null;
	} catch {
		return null;
	}
}

/** 输出首行的去空白文本（没有非空行 → 空串）。 */
function firstLine(output: string): string {
	try {
		for (const line of String(output ?? "").split(/\r?\n/)) {
			const t = line.trim();
			if (t) return t;
		}
		return "";
	} catch {
		return "";
	}
}

/**
 * 这是不是一次**合法的业务出口**（不应当算作工具失败）？
 *
 * 判据（全部满足才算）：
 *   1. rc 是 0 或 2 —— route.py 的契约：0 通过 / 1 坏声明 / 2 判型未定（UNCLASSIFIED）。
 *      rc=1 永远不算合法出口（那是真的坏声明）；
 *   2. 输出首行（去空白）以 [UNCLASSIFIED] / [NONE] / [FALLBACK] 开头。
 *
 * 故意写成纯函数：test_gates.py 直接调它断言，不在 Python 里拄一份逻辑。
 */
export function isLegitBusinessExit(rc: number | null, output: string): boolean {
	try {
		if (rc === null || rc === undefined) return false;
		if (rc !== 0 && rc !== 2) return false;
		const head = firstLine(output);
		if (!head) return false;
		return LEGIT_MARKS.some((m) => head.startsWith(m));
	} catch {
		return false;
	}
}

function commandSegments(command: string): string[] {
	const out: string[] = [];
	let current = "";
	let quote = "";
	let escaped = false;
	for (const ch of String(command ?? "")) {
		if (escaped) {
			current += ch;
			escaped = false;
			continue;
		}
		if (ch === "\\" && quote !== "'") {
			current += ch;
			escaped = true;
			continue;
		}
		if (quote) {
			current += ch;
			if (ch === quote) quote = "";
			continue;
		}
		if (ch === "'" || ch === '"') {
			quote = ch;
			current += ch;
			continue;
		}
		if (ch === ";" || ch === "&" || ch === "|" || ch === "\n" || ch === "\r") {
			if (current.trim()) out.push(current.trim());
			current = "";
			continue;
		}
		current += ch;
	}
	if (current.trim()) out.push(current.trim());
	return out;
}

function commandTokens(segment: string): string[] {
	const out: string[] = [];
	let current = "";
	let quote = "";
	let escaped = false;
	for (const ch of String(segment ?? "")) {
		if (escaped) {
			current += ch;
			escaped = false;
			continue;
		}
		if (ch === "\\" && quote !== "'") {
			// Windows 路径里的反斜杠属于值本身；只有反斜杠后紧跟引号时才当转义。
			current += ch;
			escaped = true;
			continue;
		}
		if (quote) {
			if (ch === quote) quote = "";
			else current += ch;
			continue;
		}
		if (ch === "'" || ch === '"') {
			quote = ch;
			continue;
		}
		if (/\s/.test(ch)) {
			if (current) {
				out.push(current);
				current = "";
			}
			continue;
		}
		current += ch;
	}
	if (current) out.push(current);
	return out;
}

function basenameLower(value: string): string {
	return String(value ?? "").replace(/^.*[\\/]/, "").replace(/\.exe$/i, "").toLowerCase();
}

function sanctionedScriptInSegment(segment: string): boolean {
	const tokens = commandTokens(segment);
	if (!tokens.length) return false;
	let index = 0;
	while (index < tokens.length && (/^[A-Za-z_][A-Za-z0-9_]*=.*/.test(tokens[index]) ||
		["env", "command", "exec"].includes(basenameLower(tokens[index])))) index += 1;
	if (index >= tokens.length) return false;

	const head = basenameLower(tokens[index]);
	const direct = tokens[index].replace(/^.*[\\/]/, "");
	if (SANCTIONED.has(direct.toLowerCase())) return true;

	if (["python", "python3", "py"].includes(head)) {
		index += 1;
		while (index < tokens.length) {
			const token = tokens[index];
			const low = token.toLowerCase();
			if (low === "-c" || low === "-m") return false; // 内联/模块启动没有可验证脚本身份
			if (low === "-w" || low === "-x") {
				index += 2;
				continue;
			}
			if (token.startsWith("-")) {
				index += 1;
				continue;
			}
			const script = token.replace(/^.*[\\/]/, "").toLowerCase();
			return SANCTIONED.has(script);
		}
		return false;
	}

	if (["powershell", "pwsh"].includes(head)) {
		const fileFlag = tokens.findIndex((value, i) => i > index &&
			["-file", "/file"].includes(value.toLowerCase()));
		if (fileFlag >= 0 && fileFlag + 1 < tokens.length) {
			const script = tokens[fileFlag + 1].replace(/^.*[\\/]/, "").toLowerCase();
			return SANCTIONED.has(script);
		}
		return false;
	}

	if (["bash", "sh"].includes(head)) {
		const script = tokens[index + 1];
		return !!script && SANCTIONED.has(script.replace(/^.*[\\/]/, "").toLowerCase());
	}
	return false;
}

/**
 * 只从命令的真实可执行文件/脚本位置判断白名单。
 * notes/URL/参数值里出现文件名，或 `python -c` / `-m` 间接引用，都不算出口。
 */
function isSanctioned(input: any): boolean {
	try {
		const command =
			typeof input === "string"
				? input
				: typeof input?.command === "string"
					? input.command
					: typeof input?.cmd === "string"
						? input.cmd
						: "";
		if (!command.trim()) return false;
		const segments = commandSegments(command);
		return segments.length > 0 && segments.every(sanctionedScriptInSegment);
	} catch {
		return false;
	}
}

export function isSanctionedForTest(input: any): boolean {
	return isSanctioned(input);
}

/* ─────────────────── 调用形状签名（熔断作用面）─────────────────── */

/** Preserve all input values without placing commands or secrets in diagnostics. */
export function callSignature(tool: string, input: any): string {
	try {
		const canonical = (value: any): any => {
			if (Array.isArray(value)) return value.map(canonical);
			if (value && typeof value === "object") {
				return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
			}
			return value;
		};
		const payload = JSON.stringify(canonical(input));
		if (payload === undefined) return "";
		return `${String(tool).toLowerCase()}:${createHash("sha256").update(payload).digest("hex").slice(0, 24)}`;
	} catch {
		return "";
	}
}

/* ─────────────────────── 拦截文案 ─────────────────────── */

function buildReason(tool: string, callSig: string, count: number): string {
	return [
		`${OWN_MARK}：${tool} 的同一输入已连续失败 ${count} 次；本次重复调用暂停。`,
		`调用标识：${callSig}。这不代表整个任务停止，也不需要用户代执行。`,
		"先检查实际错误、工具 schema、当前状态和相关源码，修正后继续；参数不同的调用仍可执行。",
		"成功修改代码后允许重新测试；修复后的旧异步结果不会恢复过期计数。",
		"同一命令若可能已经产生副作用，先观察状态，不因超时直接重放。",
		"只有确实缺少用户独有输入、扩大范围或遇到不可替代操作时才询问。",
	].join("\n");
}

/* ─────────────────────────── 扩展入口 ─────────────────────────── */

export default function seepCircuit(pi: ExtensionAPI) {
	/* 1. Pause only repeated inputs; diagnosis and changed calls remain available. */
	pi.on("tool_call", async (event: any, ctx: any) => {
		try {
			const state = stateFor(ctx);
			const tool = String(event?.toolName ?? "unknown");
			// 迭代型工具（edit/write/read/grep/find/ls/todo）永不熔断：试错是它们的主路径
			if (isNeverBreak(tool)) return;
			// 白名单命令始终放行：熔断的出路必须可达，否则死锁
			if (isSanctioned(event?.input)) return;
			const callSig = callSignature(tool, event?.input);
			const callId = String(event?.toolCallId ?? "").trim();
			rememberActiveCall(state, callId, tool, callSig);
			const n = threshold();
			if (n <= 0) return; // 关闭熔断（只计数）
			// ★ 只看**本次调用的形状**：一个签名撞满不该把整个 bash 禁掉
			if (callSig) {
				const e = entryFor(state, tool, callSig);
				if (!e || e.count < n) return; // 这个形状还没到阈值 → 其它命令照常可用
				state.tripped += 1;
				return {
					block: true,
					reason: buildReason(tool, callSig, e.count),
				};
			}
			// Unknown input cannot identify a repeated call; do not block unrelated work.
			return;
		} catch {
			// 熔断层自身出错 → 放行（绝不因为记账问题误拦正常调用）
			return;
		}
	});

	/* 2. 结果后：更新计数（成功清零 / 失败按形状累加 / 自己的拦截不计） */
	pi.on("tool_result", async (event: any, ctx: any) => {
		try {
			const state = stateFor(ctx);
			const callId = String(event?.toolCallId ?? "").trim();
			const tracked = callId ? state.calls.get(callId) : undefined;
			const tool = String(event?.toolName || tracked?.tool || "unknown");
			if (callId) state.calls.delete(callId);
			const rc = exitCodeOf(event);
			const failed = Boolean(event?.isError) || (rc !== null && rc !== 0);
			if (isNeverBreak(tool)) {
				if (!failed && ["edit", "write"].includes(tool.toLowerCase())) {
					state.streaks.clear();
					state.revision += 1;
				}
				return;
			}
			if (tracked && tracked.revision !== state.revision) return;
			const text = textOf(event);
			if (!failed) {
				// 工具本身没坏 → 该工具名下所有形状的计数清零
				// 白名单命令成功尤其要清零：照 reason 办完就该恢复可用，不能「修好了还被拦」
				clearTool(state, tool);
				return;
			}
			if (isOwnBlock(text)) return; // 自己拦出来的不算「又失败一次」
			// ★ 合法业务出口不算失败：route.py --resolve 判不出领域就是 rc=2 + 首行 [UNCLASSIFIED]，
			//   这是设计好的结果；[NONE] / [FALLBACK] 同理。既不加计数，也不清零（它不是成功也不是失败）。
			if (isLegitBusinessExit(exitCodeOf(event), text)) return;
			// Without an input identity, a result must not poison unrelated calls.
			const callSig = tracked?.callSig || callSignature(tool, event?.input);
			if (!callSig) return;
			bumpStreak(state, tool, callSig, signatureOf(text));
		} catch {
			/* 计数出错一律吞掉：不干预 */
		}
	});

	/* 3. 会话开：清空计数（同一进程内换会话不继承上回的撞车记录） */
	pi.on("session_start", async (_event: any, ctx: any) => {
		try {
			sessionStates.set(sessionIdOf(ctx), emptySessionState());
		} catch {}
	});

	pi.on("session_shutdown", async (_event: any, ctx: any) => {
		try {
			sessionStates.delete(sessionIdOf(ctx));
		} catch {}
	});

	/* 4. `/circuit` —— 看状态 / reset。人不该被自己装的熔断关在门外。 */
	try {
		pi.registerCommand?.("circuit", {
			description: "熔断状态：/circuit 查看，/circuit reset 清零（默认阈值见 SEEP_CIRCUIT_N）",
			handler: async (args: string, ctx: any) => {
				try {
					const state = stateFor(ctx);
					const n = threshold();
					const lines: string[] = [
						`[seep-circuit] 阈值 SEEP_CIRCUIT_N=${n}${n > 0 ? "" : "（关闭：只计数不拦）"} · 已拦 ${state.tripped} 次`,
					];
					if (!state.streaks.size) lines.push("当前会话无失败记录。");
					for (const [tool, b] of state.streaks) {
						// 熔断作用面是**调用形状**，不是一个工具：单独标出哪些形状已到阈值
						const detail = Array.from(b.entries())
							.map(([sig, e]) =>
								`${n > 0 && e.count >= n ? "★" : ""}${e.count}×「${sig}」（错：${e.errSig}）`,
							)
							.join(" · ");
						const hot = Array.from(b.values()).filter((e) => n > 0 && e.count >= n).length;
						lines.push(`${tool}  ${hot ? `★已熔断 ${hot} 种形状` : "计数中"}  ${detail}`);
					}
					const say = (ctx as any)?.ui?.notify ?? (ctx as any)?.ui?.showMessage;
					if (typeof say === "function") say.call((ctx as any).ui, lines.join("\n"));
					else console.log(lines.join("\n"));
					if (String(args ?? "").trim().toLowerCase() === "reset") {
						sessionStates.set(sessionIdOf(ctx), emptySessionState());
						const say2 = (ctx as any)?.ui?.notify ?? (ctx as any)?.ui?.showMessage;
						if (typeof say2 === "function") say2.call((ctx as any).ui, "[seep-circuit] 计数已清零。");
					}
				} catch {
					/* 命令面板出错不打扰会话 */
				}
			},
		});
	} catch {
		/* 老版本 pi 没有 registerCommand → 只是少一个命令，事件层照常工作 */
	}
}
