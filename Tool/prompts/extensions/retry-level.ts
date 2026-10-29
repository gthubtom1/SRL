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
import { homedir } from "node:os";
import * as path from "node:path";
import { randomBytes } from "node:crypto";

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
	const configuredAgentDir = process.env.PI_CODING_AGENT_DIR?.trim();
	let homeDir = "";
	try {
		homeDir = homedir();
	} catch {}
	homeDir ||= process.env.USERPROFILE?.trim() || process.env.HOME?.trim() || "";
	const agentDir = configuredAgentDir
		? path.resolve(configuredAgentDir)
		: homeDir
			? path.join(homeDir, ".pi", "agent")
			: path.resolve(".pi", "agent");
	const settingsPath = path.join(agentDir, "settings.json");

	function readSettings(): Record<string, any> | null {
		try {
			const settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
			const object = (value: any) => value !== null && typeof value === "object" && !Array.isArray(value);
			if (!object(settings) || (settings.retry !== undefined && !object(settings.retry)) ||
				(settings.retry?.provider !== undefined && !object(settings.retry.provider))) return null;
			return settings;
		} catch (err: any) {
			return err?.code === "ENOENT" ? {} : null;
		}
	}

	function writeSettings(settings: Record<string, any>): boolean {
		const dir = path.dirname(settingsPath);
		const suffix = `${process.pid}.${randomBytes(8).toString("hex")}`;
		const tempPath = `${settingsPath}.${suffix}.tmp`;
		const backupPath = `${settingsPath}.${suffix}.bak`;
		const displacedPath = `${settingsPath}.${suffix}.old`;
		let fd: number | undefined;
		let backupMade = false;
		let originalDisplaced = false;
		let candidatePublished = false;
		try {
			if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
			const payload = JSON.stringify(settings, null, 2);

			// 候选文件先写同目录临时文件并 fsync，不能直接截断正式 settings.json。
			fd = fs.openSync(tempPath, "wx");
			fs.writeFileSync(fd, payload, { encoding: "utf-8" });
			fs.fsyncSync(fd);
			fs.closeSync(fd);
			fd = undefined;
			JSON.parse(fs.readFileSync(tempPath, "utf-8"));

			// 保留一份已 fsync 的原文件，若替换后的回读校验失败可原子恢复。
			if (fs.existsSync(settingsPath)) {
				const original = fs.readFileSync(settingsPath, "utf-8");
				fd = fs.openSync(backupPath, "wx");
				fs.writeFileSync(fd, original, { encoding: "utf-8" });
				fs.fsyncSync(fd);
				fs.closeSync(fd);
				fd = undefined;
				backupMade = true;
			}

			try {
				// POSIX 通常可一次 replace；Windows 对已存在目标可能返回 EEXIST/EPERM。
				fs.renameSync(tempPath, settingsPath);
				candidatePublished = true;
			} catch {
				if (!fs.existsSync(settingsPath)) throw new Error("settings destination disappeared");
				fs.renameSync(settingsPath, displacedPath);
				originalDisplaced = true;
				fs.renameSync(tempPath, settingsPath);
				candidatePublished = true;
			}
			const readBack = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
			if (JSON.stringify(readBack) !== JSON.stringify(settings)) {
				throw new Error("settings read-back mismatch");
			}
			if (backupMade) {
				try { fs.unlinkSync(backupPath); } catch {}
			}
			if (originalDisplaced) {
				try { fs.unlinkSync(displacedPath); } catch {}
			}
			return true;
		} catch (error) {
			if (process.env.SEEP_DEBUG_RETRY) {
				console.error("[retry-level] settings atomic update failed:", error);
			}
			if (fd !== undefined) {
				try { fs.closeSync(fd); } catch {}
			}

			// 回读失败时 settingsPath 仍可能是刚发布的坏候选；Windows 不允许 rename
			// 覆盖它。先移走坏候选，再把 fsync 过的旧文件放回原位。
			const recoveryPath = originalDisplaced && fs.existsSync(displacedPath)
				? displacedPath
				: backupMade && fs.existsSync(backupPath)
					? backupPath
					: undefined;
			let recovered = true;
			if (originalDisplaced || candidatePublished) {
				try {
					if (candidatePublished && fs.existsSync(settingsPath)) fs.unlinkSync(settingsPath);
					if (recoveryPath) fs.renameSync(recoveryPath, settingsPath);
				} catch {
					recovered = false;
				}
			}
			try { fs.unlinkSync(tempPath); } catch {}
			// 恢复未完成时保留任一份旧文件，供用户手工恢复；绝不能在失败路径丢旧数据。
			if (recovered) {
				try { fs.unlinkSync(backupPath); } catch {}
				try { fs.unlinkSync(displacedPath); } catch {}
			}
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
		if (!settings) return { ok: false, message: `读取 settings.json 失败或格式无效，未写入（路径：${settingsPath}）` };
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
			if (!settings) {
				ctx.ui.notify(`读取 settings.json 失败或格式无效，未修改（路径：${settingsPath}）`, "error");
				return;
			}
			const current = currentLevel(settings);

			let target: Level | undefined;

			if (lower === "status" || lower === "info") {
				ctx.ui.notify(`当前档位：${statusText(current)}`, "info");
				ctx.ui.setStatus("command:/retry", statusText(current));
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
			if (ok) ctx.ui.setStatus("command:/retry", statusText(target));
			ctx.ui.notify(message, ok ? "info" : "error");
			if (ok) await ctx.reload();
		},
	});

	// pi 自己会重试它判定为"可重试"的错误，但它的判据是关键词白名单，
	// 认不出"配额要等 3 小时才恢复"这类等下去也没用的错。这里兜底。
	pi.on("agent_end", async (event, ctx) => {
		const messages = Array.isArray(event?.messages) ? event.messages : [];
		const last = [...messages].reverse().find((message: any) =>
			message && typeof message === "object" && message.role === "assistant"
		) as any;
		if (!last || last.stopReason !== "error" || !last.errorMessage) return;
		const text = String(last.errorMessage);
		if (!HOPELESS_PATTERNS.some((re) => re.test(text))) return;

		const settings = readSettings();
		if (!settings) {
			ctx.ui.notify(`检测到无法自动恢复的错误，但无法读取重试设置（路径：${settingsPath}）。`, "warning");
			return;
		}
		const current = currentLevel(settings);
		if (current.maxRetries < 100) return; // 只在"无限"档时插手，普通档位不管

		// agent_end 使用 ExtensionContext，不提供 command-only 的 reload()。
		// 先中止当前运行，避免宿主继续安排重试；设置留给下次重载生效。
		ctx.abort();
		const { ok, message } = apply(LEVELS[1]);
		if (ok) ctx.ui.setStatus("command:/retry", statusText(LEVELS[1]));
		ctx.ui.notify(
			`${ok ? "检测到无法自动恢复的错误，已请求停止当前重试；3 次设置将在重载后生效。" : "检测到无法自动恢复的错误，已请求停止当前重试，但未能保存设置。"}${message}\n详情：${text.slice(0, 160)}`,
			"warning",
		);
	});

	pi.on("session_start", async (_event, ctx) => {
		const settings = readSettings();
		ctx.ui.setStatus("command:/retry", settings ? statusText(currentLevel(settings)) : "重试: 未知（设置不可读）");
	});
}
