/**
 * seep-circuit —— 同类工具错误熔断（pi 扩展）
 *
 * 存在的原因（血案）：
 *   模型参数错一次（少个 `--json`、路径多一层反斜杠、少个 `--start`），
 *   **不回头查工具能力表**，而是当场手搓一个等价脚本把活绕过去。
 *   结果是：能力表永远不更新，一次性替代件越攒越多，下一次换机/换目标又重来一遍；
 *   而「这批活到底是谁干的」在账上变成一堆无名 python 临时文件。
 *
 *   提示词里写「先查能力表」管不住这一层 —— 手搓脚本的快感只需要 1 秒，
 *   而查表要 3 步。真正能管住的是**物理拦截**：
 *   同一工具在同一「错误形状」上连撞两次，第三次连发都发不出去。
 *
 * ── 它做什么 ────────────────────────────────────────────────
 *   1. 归一化错误形状    tool_result.isError → (tool, signature)
 *      signature = 错误首行（去掉引号内容 / 路径 / 数字 / 折叠空白 / 小写）前 80 字
 *      「unexpected keyword argument」「file does not exist」「connection refused」
 *      这类**同一形状不同参数**的错误因此会被并成一类，而不是每次算新的。
 *   2. 连续计数          同一 (tool, 调用签名) 连撞 N 次（默认 2，见 SEEP_CIRCUIT_N）
 *      中间任何一次同工具成功 → 该工具名下计数**全部清零**（工具本身没坏就别拦）。
 *   3. 熔断              达阈值后，第 N+1 次**同签名**的调用直接 block，
 *      reason 里给四条纪律：查能力表 → 禁止临场手搓 → 发 A/B/C 卡 → decisions.md 记账。
 *
 * ── 两条硬约束（用户口径：限制只挡真坑，挡不住就是摩擦）────────────────
 *   A. 合法业务出口不计数（isLegitBusinessExit）：
 *      `python Tool/scripts/route.py --resolve "…"` 判不出领域时是 **rc=2 +
 *      首行 `[UNCLASSIFIED]`** —— 这是设计好的合法结果，不是工具坏了。
 *      `[NONE]`（没命中）/ `[FALLBACK]`（走兜底）同理。这类结果**既不计数也不拦**，
 *      否则连撞两次就封掉整个 bash（实测连 `python -c "print(1)"` 都被拦）。
 *   B. 熔断只拦**同一调用形状**：拦的是 `(tool, 本次调用的签名)`，不是整个工具。
 *      一个签名撞满之后，其它形状的 bash 命令照常可用（reason 里会写明这一点）。
 *      签名算不出来时才退回整工具判定，并在 reason 里说明是退回。
 *
 * ── 它不做什么 ───────────────────────────────────────────────
 *   · 不判「谁的错」：工具错、参数错、环境错一视同仁 —— 反正都该先查表。
 *   · 不熔断「迭代型」工具（见 NEVER_BREAK：edit / write / read / grep / find / ls / todo）。
 *     这些工具的参数就是用来**试错**的：edit 的 oldText 不匹配、grep 没匹配到，
 *     都是正常的一次迭代，不是「工具坏了」。把它们算成失败会直接制造死锁
 *     —— P4-1 实测：11 个 SKILL.md 连续改不动，只能靠人 reset。
 *     熔断要盯的是**会真正失败的外部/命令类工具**（bash / MCP / Agent 等）。
 *   · 不持久化：状态只在内存里，**每次会话重置**（另挂一个 session_start 清空，
 *     因为同一个 pi 进程里换会话不该继承上一次的撞车记录）。跨会话保留会把新会话的合法第一步也拦掉。
 *   · 不拦「照 reason 办」的那几条命令（见 SANCTIONED）：否则 bash 被熔断后，
 *     模型连 `tool-acquire.py` 都跑不了 —— 熔断会变成死锁。这是本文件最关键的一处设计。
 *
 * ── 逃生口（重要）─────────────────────────────────────────────
 *   1. 白名单命令：只有真实执行 tool-acquire.py / case_state.py / preflight.py 的
 *      命令行才放行；notes / URL / 参数值里出现同名文本不算，`python -c` 间接引用也不算。
 *      熔断的**唯一正确出路**必须始终可达，同时不能变成任意子串旁路。
 *   2. `/circuit`       看当前各 tool 的撞车次数与已熔断项
 *      `/circuit reset` 清空全部计数（人判断「这次是环境问题，不是能力问题」时用）
 *   3. SEEP_CIRCUIT_N=0 关闭熔断（只计数不拦），N=3 放宽到连撞 3 次。
 *
 * ── 容错（硬约束）──────────────────────────────────────────────
 *   所有 handler 整体 try/catch，异常一律吞掉、返回 undefined（= 不干预）。
 *   熔断层坏掉的后果只能是「没拦住」，绝不允许变成「正常调用被误拦」。
 */

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
/** 调用签名上限（字符数）。比错误签名宽一点：命令串要能认出来。 */
const CALL_SIG_MAX = 120;

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
 * 错误形状只用于给 reason 说清「撞的是什么错」，不参与判定。
 * 不做持久化是刻意的 —— 跨会话保留会把「新会话第一次调用」也算成第三次。
 * 插入顺序即最近使用顺序，超上限时丢最老的 tool。
 */
type StreakEntry = { count: number; errSig: string };
type ActiveCall = { tool: string; callSig: string; at: number };
type SessionState = {
	streaks: Map<string, Map<string, StreakEntry>>;
	calls: Map<string, ActiveCall>;
	tripped: number;
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
	state.calls.set(id, { tool, callSig, at: Date.now() });
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

/** 该工具名下最高的连续失败（同分取最近的）。只给 /circuit 展示与「签名算不出来」时用。 */
function worstStreak(state: SessionState, tool: string): { sig: string; count: number; errSig: string } | null {
	const b = state.streaks.get(tool);
	if (!b) return null;
	let best: { sig: string; count: number; errSig: string } | null = null;
	for (const [sig, e] of b) {
		if (!best || e.count >= best.count) best = { sig, count: e.count, errSig: e.errSig };
	}
	return best;
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

/**
 * 归一化「这次调用长什么形状」。
 *
 * 为什么需要它：旧实现把失败记在**整个工具名**上 —— 一个签名撞满就把 bash 整个禁掉，
 * 然后 `cd /tmp; python -c "print(1)"` 这种无关命令也被拦（实测需要 tool-acquire 才能解毒）。
 * 那是典型的摩擦：限制的作用面（整个 bash）远大于真坑（一种调用形状）。
 *
 * 形状的取法（尽量粗、但不能粗到两种不同活儿共用一个 key）：
 *   · bash/powershell：命令串的第一个「词」+ 是否带 --resolve 这类子命令外形
 *     如 `python Tool/scripts/route.py --resolve "…"` → `python route.py --resolve`
 *     这样同一个脚本的**同一子命令**连撞才会熔断，换脚本/换子命令立刻放行。
 *   · 其它工具：取 input 的顶层 key 排序（参数形状）+ 首个字符串值的前一段。
 *   · 算不出来 → 返回 ""（调用方退回旧行为：整个工具判定，并在 reason 里说明）。
 */
export function callSignature(tool: string, input: any): string {
	try {
		const t = String(tool ?? "").trim().toLowerCase();
		const obj = input && typeof input === "object" ? (input as any) : null;

		// 命令类工具：看命令本身
		const cmdRaw =
			typeof input === "string"
				? input
				: typeof obj?.command === "string"
					? obj.command
					: typeof obj?.cmd === "string"
						? obj.cmd
						: typeof obj?.script === "string"
							? obj.script
							: "";
		if (cmdRaw) {
			// ① 取第一段（按 ; && || | 换行切），只看命令主体
			const seg = String(cmdRaw).split(/[;&|\n\r]+/).map((s) => s.trim()).find((s) => s && !/^cd\s/.test(s)) ?? "";
			const words = seg.split(/\s+/).filter(Boolean);
			if (!words.length) return "";
			// ② 解释器壳（python/node/pwsh/bash …）剥掉一层：真正被跑的是它后面那个脚本
			const SHELLS = new Set(["python", "python3", "py", "node", "pwsh", "powershell", "bash", "sh", "cmd", "deno", "tsx"]);
			let base = words[0].replace(/^.*[\\/]/, "").toLowerCase();
			let rest = words.slice(1);
			while (SHELLS.has(base) && rest.length) {
				const next = rest[0];
				if (next.startsWith("-")) break; // python -c / node -e：内联串，别再剥
				base = String(next).replace(/^.*[\\/]/, "").toLowerCase();
				rest = rest.slice(1);
			}
			// ③ 子命令形参（--resolve / --check / --fast …）只留**第一个**，参数值一律丢掉
			const flag = rest.find((w) => /^--?[A-Za-z]/.test(w));
			// ④ 内联串（python -c …）：只留前 40 字，避免把每次不同的小脚本当成同一形状
			const inline = rest.find((w) => w === "-c" || w === "-e");
			let sig = inline
				? `${base} ${inline} ${(rest[rest.indexOf(inline) + 1] ?? "").slice(0, 40)}`
				: `${base}${flag ? " " + flag : ""}`;
			sig = sig.replace(/\s+/g, " ").trim().toLowerCase();
			return sig.length > CALL_SIG_MAX ? sig.slice(0, CALL_SIG_MAX) : sig;
		}

		// 非命令类：用参数形状（top-level key 排序）+ 首个字符串值的前一段
		if (obj) {
			const keys = Object.keys(obj).sort().slice(0, 6).join(",");
			let first = "";
			for (const k of Object.keys(obj)) {
				const v = obj[k];
				if (typeof v === "string" && v.trim()) {
					first = v.trim().split(/[\r\n]/)[0].slice(0, 40);
					break;
				}
			}
			const sig = `${keys}${first ? " | " + first : ""}`.replace(/\s+/g, " ").trim().toLowerCase();
			if (!sig) return "";
			return `${t}:${sig.length > CALL_SIG_MAX ? sig.slice(0, CALL_SIG_MAX) : sig}`;
		}
		return "";
	} catch {
		return "";
	}
}

/* ─────────────────────── 拦截文案 ─────────────────────── */

/** 当前案子名（给 reason 里的命令填上真参数；没有案子就留 <case>）。 */
function caseArgOf(ctx: any): string {
	try {
		const d = ctx?.cwd;
		const base = typeof d === "string" && d ? String(d).replace(/[\\/]+$/, "").split(/[\\/]/).pop() : "";
		return base || "<case>";
	} catch {
		return "<case>";
	}
}

function buildReason(
	tool: string,
	callSig: string,
	errSig: string,
	count: number,
	nth: number,
	caseArg: string,
	wholeTool: boolean,
): string {
	const n = threshold();
	const scope = wholeTool
		? `  作用面：本次调用形状算不出来 → 退回整工具判定（${tool} 名下所有形状合计已到阈值）。`
		: [
			`  作用面：**本次只拦这一种调用形状（${callSig}），其它 ${tool} 命令照常可用**。`,
			`  换形状 = 换命令/换脚本/换子命令 → 不拦；同一个形状再发 → 继续拦。`,
		].join("\n");
	return [
		`${OWN_MARK}：${tool} 在调用形状「${callSig || "(未识别)"}」上已连续失败 ${count} 次（阈值 ${n}），第 ${nth} 次调用被直接拦下。`,
		`  触发它的错误形状：「${errSig}」`,
		`  这不是「再试一次就好了」的问题 —— 同一形状连撞两次，说明你对该工具的口径是错的，换参数重试只会撞第三次。`,
		scope,
		``,
		`1) 先查能力表（工具四阶梯，别再靠猜参数）：`,
		`   python Tool/scripts/tool-acquire.py --tool ${tool} --start`,
		``,
		`2) 禁止临场手写等价替代工具。`,
		`   不许为了绕开这次失败现搓脚本 / 临时 DLL / 一次性 python 去干同一件事 ——`,
		`   这类替代件不会被记账，下次换机换目标又得重来，且它跑出来的结论没有出处。`,
		``,
		`3) 确需替代 → 停下发对话内 A/B/C 卡，把选择权交回人（唯一允许的问人方式）：`,
		`   python Tool/scripts/case_state.py ask --case ${caseArg} \\`,
		`     --stuck "${tool} 在「${callSig || "(未识别)"}」上连撞 ${count} 次，能力表里没有可用档位" \\`,
		`     --option "A 按能力表装/修这个工具，继续用它" \\`,
		`     --option "B 换成能力表里的另一档工具做同一件事" \\`,
		`     --option "C 由你手工提供可用替代件"`,
		``,
		`4) 这是记录在案的决策：在 case/decisions.md 写一段「为什么换路」——`,
		`   撞了什么形状、试过哪几档、为什么判定这条路不通、新路凭什么可行。`,
		`   没有这段，换路等于没发生（下一轮又会走回老路）。`,
		``,
		`解除熔断：跑完上面第 1) 条且成功 → 计数自动清零；或人执行 /circuit reset。`,
		`注意：其它形状的 ${tool} 调用 / 普通的 cd、python -c 这类无关命令现在就能正常跑（不在本次拦截范围内）。`,
	].join("\n");
}

/* ─────────────────────────── 扩展入口 ─────────────────────────── */

export default function seepCircuit(pi: ExtensionAPI) {
	/* 1. 调用前：达阈值直接拦（返回 undefined = 不干预） */
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
					reason: buildReason(tool, callSig, e.errSig, e.count, e.count + 1, caseArgOf(ctx), false),
				};
			}
			// 签名算不出来 → 退回旧行为（整工具判定），但 reason 里说明这是退回
			const worst = worstStreak(state, tool);
			if (!worst || worst.count < n) return;
			state.tripped += 1;
			return {
				block: true,
				reason: buildReason(tool, "(未识别)", worst.errSig, worst.count, worst.count + 1, caseArgOf(ctx), true),
			};
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
			// 迭代型工具不参与计数：既不累加，也不清零（它们的「成功」不代表外部工具修好了）
			if (isNeverBreak(tool)) return;
			const text = textOf(event);
			if (!event?.isError) {
				// 工具本身没坏 → 该工具名下所有形状的计数清零
				// 白名单命令成功尤其要清零：照 reason 办完就该恢复可用，不能「修好了还被拦」
				clearTool(state, tool);
				return;
			}
			if (isOwnBlock(text)) return; // 自己拦出来的不算「又失败一次」
			// ★ 合法业务出口不算失败：route.py --resolve 判不出领域就是 rc=2 + 首行 [UNCLASSIFIED]，
			//   这是设计好的结果；[NONE] / [FALLBACK] 同理。既不加计数，也不清零（它不是成功也不是失败）。
			if (isLegitBusinessExit(exitCodeOf(event), text)) return;
			// 计数记在**本次调用的形状**上（算不出来才退回一个固定 key，同时让 tool_call 走整工具判定）
			const callSig = tracked?.callSig || callSignature(tool, event?.input) || "(未识别)";
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
