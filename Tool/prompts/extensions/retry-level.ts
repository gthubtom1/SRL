/**
 * Pi Retry Level Extension
 *
 * /retry                 打开菜单选择重试档位（关闭 / 3 / 5 / 10 / 15 / 30 / 无限）
 * /retry cycle           无菜单循环切档（按一次切一档）
 * /retry <档位>          直接切档：off | 3 | 5 | 10 | 15 | 30 | infinite
 * /retry status          查看当前档位
 *
 * 底部状态栏始终显示当前档位，不会再出现"设了 10 次却什么都不显示"。
 * 无限档是 9999 次 + 指数避让，**随时可按 Esc 中断**（pi 自带重试取消键）。
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import * as fs from "node:fs";
import * as path from "node:path";

type Level = { key: string; label: string; enabled: boolean; maxRetries: number };

const INFINITE = 9999;

const LEVELS: Level[] = [
	{ key: "off", label: "关闭（网络一断就报错）", enabled: false, maxRetries: 3 },
	{ key: "3", label: "3 次（pi 默认）", enabled: true, maxRetries: 3 },
	{ key: "5", label: "5 次", enabled: true, maxRetries: 5 },
	{ key: "10", label: "10 次", enabled: true, maxRetries: 10 },
	{ key: "15", label: "15 次", enabled: true, maxRetries: 15 },
	{ key: "30", label: "30 次", enabled: true, maxRetries: 30 },
	{ key: "infinite", label: "无限次（Esc 可随时中断）", enabled: true, maxRetries: INFINITE },
];

/**
 * 「等下去也不会好」的错误：命中就把无限档降回 3 次，免得白等几小时。
 * 判据分两类：
 *  1) 配额/账单类且明确说了很久以后才恢复（配额错误重试无意义，不在 pi 的黑名单措辞里）
 *  2) 认证/授权/参数类，本身就是永久性错误
 * 网络抖动、5xx、overloaded、rate limit 不在其中 —— 那些该重试。
 */
const HOPELESS_PATTERNS: RegExp[] = [
	/(quota|usage limit|balance|credits?|quota exceeded|insufficient).{0,80}(resets?|retry after|try again).{0,40}(\d+\s*(h|hour|hours|小时)|\d{4,})/i,
	/(individual quota reached|out of budget|insufficient_quota|billing|monthly usage limit|free usage limit)/i,
	/(401|unauthorized|invalid[ _-]?api[ _-]?key|authentication[ _-]?(failed|error)|invalid[ _-]?token)/i,
	/(403|forbidden|permission[ _-]?denied|model[ _-]?not[ _-]?found|unsupported[ _-]?model)/i,
];

export default function retryLevelExtension(pi: ExtensionAPI) {
	const homeDir = process.env.USERPROFILE || process.env.HOME || "";
	const settingsPath = path.join(homeDir, ".pi", "agent", "settings.json");

	function readSettings(): Record<string, any> {
		try {
			if (fs.existsSync(settingsPath)) {
				return JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
			}
		} catch {}
		return {};
	}

	function writeSettings(settings: Record<string, any>): boolean {
		try {
			const dir = path.dirname(settingsPath);
			if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
			fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), "utf-8");
			return true;
		} catch {
			return false;
		}
	}

	function currentLevel(settings: Record<string, any>): Level {
		const enabled = settings.retry?.enabled !== false;
		const max = settings.retry?.maxRetries ?? 3;
		if (!enabled) return LEVELS[0];
		if (max >= 100) return LEVELS[LEVELS.length - 1];
		return LEVELS.find((l) => l.enabled && l.maxRetries === max) ?? LEVELS[1];
	}

	function statusText(level: Level): string {
		if (!level.enabled) return "重试: 关";
		return level.maxRetries >= 100 ? "重试: 无限" : `重试: ${level.maxRetries} 次`;
	}

	function apply(level: Level): { ok: boolean; message: string } {
		const settings = readSettings();
		settings.retry = settings.retry || {};
		settings.retry.enabled = level.enabled;
		settings.retry.maxRetries = level.maxRetries;
		settings.retry.baseDelayMs = 2000;
		settings.retry.maxAgentDelayMs = 60000;
		// provider 级重试保持 0：按 pi 官方建议，provider 级重试会拖慢 pi 自己处理配额/用量错误
		settings.retry.provider = settings.retry.provider || {};
		settings.retry.provider.maxRetries = 0;
		settings.retry.provider.maxRetryDelayMs = 30000;

		const ok = writeSettings(settings);
		return {
			ok,
			message: ok ? `已切换到：${statusText(level)}` : `写入失败，settings.json 没改成（路径：${settingsPath}）`,
		};
	}

	function nextLevel(level: Level): Level {
		const idx = LEVELS.indexOf(level);
		return LEVELS[(idx + 1) % LEVELS.length];
	}

	function parseLevel(arg: string): Level | undefined {
		const a = arg.trim().toLowerCase();
		if (a === "off" || a === "0" || a === "no" || a === "false") return LEVELS[0];
		if (a === "on" || a === "infinite" || a === "max" || a === "inf") return LEVELS[LEVELS.length - 1];
		if (/^\d+$/.test(a)) return LEVELS.find((l) => l.maxRetries === parseInt(a, 10));
		return undefined;
	}

	pi.registerCommand("retry", {
		description:
			"重试档位菜单：关闭 / 3 / 5 / 10 / 15 / 30 / 无限（/retry cycle 循环，/retry status 查看）",
		getArgumentCompletions: (prefix) => {
			const options = ["cycle", "status", "off", "3", "5", "10", "15", "30", "infinite"];
			const filtered = options.filter((o) => o.startsWith(prefix));
			return filtered.length > 0 ? filtered.map((o) => ({ value: o, label: o })) : null;
		},
		handler: async (args, ctx) => {
			const arg = args.trim();
			const lower = arg.toLowerCase();
			const settings = readSettings();
			const current = currentLevel(settings);

			let target: Level | undefined;

			if (lower === "status" || lower === "info") {
				ctx.ui.notify(`当前档位：${statusText(current)}`, "info");
				ctx.ui.setStatus("retry", statusText(current));
				return;
			}

			if (lower === "cycle" || lower === "next") {
				target = nextLevel(current);
			} else if (arg) {
				target = parseLevel(arg);
				if (!target) {
					const valid = LEVELS.map((l) => l.key).join(" / ");
					ctx.ui.notify(`看不懂的档位「${arg}」。可选：${valid}，或直接 /retry 打开菜单。`, "warning");
					return;
				}
			} else if (ctx.hasUI) {
				// 无参数 = 打开菜单；当前档位打勾
				const labels = LEVELS.map((l) => (l.key === current.key ? `● ${l.label}` : `  ${l.label}`));
				const picked = await ctx.ui.select("网络重试档位（选完立刻生效，Esc 取消）", labels);
				if (!picked) return;
				const idx = labels.indexOf(picked);
				if (idx < 0) return;
				target = LEVELS[idx];
			} else {
				target = nextLevel(current);
			}

			const { ok, message } = apply(target);
			ctx.ui.setStatus("retry", statusText(target));
			ctx.ui.notify(message, ok ? "info" : "error");
			await ctx.reload();
		},
	});

	// pi 自己会重试它判定为"可重试"的错误，但它的判据是关键词白名单，
	// 认不出"配额要等 3 小时才恢复"这类等下去也没用的错。这里兜底。
	pi.on("agent_end", async (event, ctx) => {
		const last = event.messages[event.messages.length - 1] as any;
		if (!last || last.stopReason !== "error" || !last.errorMessage) return;
		const text = String(last.errorMessage);
		if (!HOPELESS_PATTERNS.some((re) => re.test(text))) return;

		const current = currentLevel(readSettings());
		if (current.maxRetries < 100) return; // 只在"无限"档时插手，普通档位不管

		const { ok, message } = apply(LEVELS[1]);
		ctx.ui.setStatus("retry", statusText(LEVELS[1]));
		ctx.ui.notify(
			`${ok ? "这类错误重试没意义" : "检测到无望的错误，但没能写入设置"}：重试已降回 3 次。${message}\n详情：${text.slice(0, 160)}`,
			"warning",
		);
		await ctx.reload();
	});

	pi.on("session_start", async (_event, ctx) => {
		const level = currentLevel(readSettings());
		ctx.ui.setStatus("retry", statusText(level));
	});
}