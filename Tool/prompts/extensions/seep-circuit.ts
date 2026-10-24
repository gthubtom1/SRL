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
 *   2. 连续计数          同一 (tool, signature) 连撞 N 次（默认 2，见 SEEP_CIRCUIT_N）
 *      中间任何一次同工具成功 → 该工具名下计数**全部清零**（工具本身没坏就别拦）。
 *   3. 熔断              达阈值后，第 N+1 次对该 tool 的调用直接 block，
 *      reason 里给四条纪律：查能力表 → 禁止临场手搓 → 发 A/B/C 卡 → decisions.md 记账。
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
 *   1. 白名单命令：input 里出现 tool-acquire.py / case_state.py / preflight.py 的一律放行
 *      —— 熔断的**唯一正确出路**必须始终可达。
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
/** 本插件自己发出去的拦截文案标记：这类结果不能回头算作「又失败一次」。 */
const OWN_MARK = "[seep-circuit] TOOL_BLOCKED";

/**
 * 白名单：照 reason 办的那几条命令必须永远能跑。
 * 否则 bash 一熔断，模型连查表命令都发不出去 = 死锁（比不拦更糟）。
 */
const SANCTIONED = ["tool-acquire.py", "case_state.py", "preflight.py"];

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
 * 全部在内存：tool → (signature → 连续失败次数)。
 * 不做持久化是刻意的 —— 跨会话保留会把「新会话第一次调用」也算成第三次。
 * 插入顺序即最近使用顺序，超上限时丢最老的 tool。
 */
const streaks = new Map<string, Map<string, number>>();
/** 已熔断的次数（只给 /circuit 展示用，不参与判定）。 */
let tripped = 0;

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

function toolBucket(tool: string): Map<string, number> {
	let b = streaks.get(tool);
	if (!b) {
		b = new Map<string, number>();
		streaks.set(tool, b);
	}
	// 超上限：Map 的迭代顺序即插入顺序，删最老的 key 即可
	while (streaks.size > TOOL_MAX) {
		const first = streaks.keys().next();
		if (first.done || first.value === tool) break;
		streaks.delete(first.value);
	}
	return b;
}

function bumpStreak(tool: string, sig: string): number {
	const b = toolBucket(tool);
	const next = (b.get(sig) ?? 0) + 1;
	b.delete(sig);
	b.set(sig, next); // 重插到尾部 = 标记为最近
	while (b.size > SIG_PER_TOOL_MAX) {
		const first = b.keys().next();
		if (first.done || first.value === sig) break;
		b.delete(first.value);
	}
	return next;
}

/** 该工具名下最高的连续失败（同分取最近的）。 */
function worstStreak(tool: string): { sig: string; count: number } | null {
	const b = streaks.get(tool);
	if (!b) return null;
	let best: { sig: string; count: number } | null = null;
	for (const [sig, count] of b) {
		if (!best || count >= best.count) best = { sig, count };
	}
	return best;
}

function clearTool(tool: string): void {
	streaks.delete(tool);
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

/** input 里是否出现「照 reason 办」的白名单命令。 */
function isSanctioned(input: any): boolean {
	try {
		let hay = "";
		if (typeof input === "string") hay = input;
		else {
			try {
				hay = JSON.stringify(input ?? {});
			} catch {
				hay = "";
			}
		}
		if (!hay) return false;
		const low = hay.toLowerCase();
		return SANCTIONED.some((k) => low.includes(k.toLowerCase()));
	} catch {
		return false;
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

function buildReason(tool: string, sig: string, count: number, nth: number, caseArg: string): string {
	const n = threshold();
	return [
		`${OWN_MARK}：${tool} 在「${sig}」上已连续失败 ${count} 次（阈值 ${n}），第 ${nth} 次调用被直接拦下。`,
		`  这不是「再试一次就好了」的问题 —— 同一形状连撞两次，说明你对该工具的口径是错的，换参数重试只会撞第三次。`,
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
		`     --stuck "${tool} 在「${sig}」上连撞 ${count} 次，能力表里没有可用档位" \\`,
		`     --option "A 按能力表装/修这个工具，继续用它" \\`,
		`     --option "B 换成能力表里的另一档工具做同一件事" \\`,
		`     --option "C 由你手工提供可用替代件"`,
		``,
		`4) 这是记录在案的决策：在 case/decisions.md 写一段「为什么换路」——`,
		`   撞了什么形状、试过哪几档、为什么判定这条路不通、新路凭什么可行。`,
		`   没有这段，换路等于没发生（下一轮又会走回老路）。`,
		``,
		`解除熔断：跑完上面第 1) 条且成功 → 该工具计数自动清零；或人执行 /circuit reset。`,
		`如需人工解除：新开一个会话（熔断计数只在会话内有效）。`,
	].join("\n");
}

/* ─────────────────────────── 扩展入口 ─────────────────────────── */

export default function seepCircuit(pi: ExtensionAPI) {
	/* 1. 调用前：达阈值直接拦（返回 undefined = 不干预） */
	pi.on("tool_call", async (event: any, ctx: any) => {
		try {
			const tool = String(event?.toolName ?? "unknown");
			// 迭代型工具（edit/write/read/grep/find/ls/todo）永不熔断：试错是它们的主路径
			if (isNeverBreak(tool)) return;
			// 白名单命令始终放行：熔断的出路必须可达，否则死锁
			if (isSanctioned(event?.input)) return;
			const n = threshold();
			if (n <= 0) return; // 关闭熔断（只计数）
			const worst = worstStreak(tool);
			if (!worst || worst.count < n) return;
			tripped += 1;
			const nth = worst.count + 1;
			return { block: true, reason: buildReason(tool, worst.sig, worst.count, nth, caseArgOf(ctx)) };
		} catch {
			// 熔断层自身出错 → 放行（绝不因为记账问题误拦正常调用）
			return;
		}
	});

	/* 2. 结果后：更新计数（成功清零 / 失败按形状累加 / 自己的拦截不计） */
	pi.on("tool_result", async (event: any) => {
		try {
			const tool = String(event?.toolName ?? "unknown");
			// 迭代型工具不参与计数：既不累加，也不清零（它们的「成功」不代表外部工具修好了）
			if (isNeverBreak(tool)) return;
			const text = textOf(event);
			if (!event?.isError) {
				// 工具本身没坏 → 该工具名下所有形状的计数清零
				// 白名单命令成功尤其要清零：照 reason 办完就该恢复可用，不能「修好了还被拦」
				clearTool(tool);
				return;
			}
			if (isOwnBlock(text)) return; // 自己拦出来的不算「又失败一次」
			bumpStreak(tool, signatureOf(text));
		} catch {
			/* 计数出错一律吞掉：不干预 */
		}
	});

	/* 3. 会话开：清空计数（同一进程内换会话不继承上回的撞车记录） */
	pi.on("session_start", async () => {
		try {
			streaks.clear();
			tripped = 0;
		} catch {}
	});

	/* 4. `/circuit` —— 看状态 / reset。人不该被自己装的熔断关在门外。 */
	try {
		pi.registerCommand?.("circuit", {
			description: "熔断状态：/circuit 查看，/circuit reset 清零（默认阈值见 SEEP_CIRCUIT_N）",
			handler: async (args: string, ctx: any) => {
				try {
					const n = threshold();
					const lines: string[] = [
						`[seep-circuit] 阈值 SEEP_CIRCUIT_N=${n}${n > 0 ? "" : "（关闭：只计数不拦）"} · 已拦 ${tripped} 次`,
					];
					if (!streaks.size) lines.push("当前无失败记录。");
					for (const [tool, b] of streaks) {
						const top = worstStreak(tool);
						const detail = Array.from(b.entries())
							.map(([sig, c]) => `${c}×「${sig}」`)
							.join(" · ");
						lines.push(`${tool}  ${top && n > 0 && top.count >= n ? "★已熔断" : "计数中"}  ${detail}`);
					}
					const say = (ctx as any)?.ui?.notify ?? (ctx as any)?.ui?.showMessage;
					if (typeof say === "function") say.call((ctx as any).ui, lines.join("\n"));
					else console.log(lines.join("\n"));
					if (String(args ?? "").trim().toLowerCase() === "reset") {
						streaks.clear();
						tripped = 0;
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
