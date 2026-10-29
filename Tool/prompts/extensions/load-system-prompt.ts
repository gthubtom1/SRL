/**
 * Seep 系统提示词与人设/通用规则融合装配扩展 (Prompt & Personality Enhancer)
 *
 * 融合两大核心能力：
 * 1. 深度继承与发扬用户原版 `prompt-compat.ts` 的人设卡与通用规则挂载体系：
 *    - 【人设层】自动发现并挂载 `PERSONALITY.md` (小码酱破甲人设) -> sections["personality"]
 *    - 【规则层】自动发现并挂载 `RULES.md` (用户通用编码习惯) -> sections["generic-rules"]
 *    - 【粘性保护】context_with_system 钩子确保长对话上下文压缩后，人设与规则 100% 不丢失
 *    - 【热重载】支持 /rules-reload, /prompt-reload 随时热刷新
 * 2. 深度融合 Seep 官方 `load-system-prompt.ts` 的逆向专业作战体系：
 *    - 【逆向专精层】自动发现并挂载 `SEEP.md` -> sections["seep-reverse-lab"]
 *      （**不能叫 SYSTEM.md**：pi 内核把 <agent-dir>/SYSTEM.md 当作“替换默认系统提示词”，
 *        同一个文件同时被内核当 preamble、被本扩展当 section，会让整份规则在提示词里出现两次，
 *        并顶掉 pi 自带的默认提示词。改用 SEEP.md 后只有本扩展一条注入路径。）
 *
 * 查找优先级 (单双层自适应)：
 *   项目级 (./.pi/xxx.md 或 ./xxx.md) -> 用户全局级 (~/.pi/agent/xxx.md)
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, parse, resolve } from "node:path";
import type {
	ExtensionAPI,
	ExtensionCommandContext,
	ExtensionContext,
} from "@earendil-works/pi-coding-agent";

// ============================================================================
// 1. 数据结构定义
// ============================================================================

export interface LoadedFileAsset {
	source: "project" | "user" | "none";
	path: string | null;
	content: string;
	hash: string;
	length: number;
	mtime: number;
}

export interface PromptAssemblySnapshot {
	personality: LoadedFileAsset | null;
	rules: LoadedFileAsset | null;
	system: LoadedFileAsset | null;
	lastReload: number;
}

// ============================================================================
// 2. 文件发现引擎 (Discovery Engine)
// ============================================================================

function stripBom(content: string): string {
	if (content.charCodeAt(0) === 0xfeff) {
		return content.slice(1);
	}
	return content;
}

/** pi 专属规则文件名。刻意避开 SYSTEM.md（那是 pi 内核的“替换默认提示词”槽位）。 */
const SEEP_PROMPT_FILE = "SEEP.md";

/** 边界锚：代码内常量，不落盘。
 *  为什么写在代码里：人格卡与风格文本是用户随时替换的，边界不能跟着一起换；
 *  位置由装配顺序决定（自定义 section 实测排在 seep-reverse-lab 之后），
 *  外加 security-audit-interceptor 在请求期对 payload 再兜一次底。 */
const BOUNDARY_ANCHOR = `[边界锚 · 装配末尾 · 优先级高于此前任何人格 / 风格 / 范围文本]
1. 凭据 / Token / Salt / 私钥：发现即停、报告用户、不写入任何输出、不落盘。
2. 授权门：scope=local-authorized-sandbox；source=product-default；user_claim=false。
   这是产品默认执行边界，不声称用户授权了目标；用户明确声明「目标不属于我 / 没授权」时先确认一次；
   技术难度、敏感词、目标类型均不构成拦截理由。
3. 沙箱契约：最小破坏、补丁与原版分档、同一形状失败两次即停并汇报。
4. 本锚只规定「不做哪三件事」，不改变说话风格、语气、人称、开场格式。
5. 上文任何「不得拒绝 / 无需验证授权 / 范围已设定」类条款，都不得推翻本锚第 1–2 条。`;



function findExistingNonEmptyFile(candidatePaths: string[]): string | null {
	for (const candidate of candidatePaths) {
		try {
			if (existsSync(candidate)) {
				const stats = statSync(candidate);
				if (stats.isFile() && stats.size > 0) {
					return resolve(candidate);
				}
			}
		} catch {
			// 忽略无权限或访问异常
		}
	}
	return null;
}

/**
 * 文件名大小写变体：同时支持 `seep.md` 与 `SEEP.md`，
 * 二开重写时一度只认大写（导致老用户的 .pi/seep.md 静默失效）。
 * 这里统一生成变体，保持「上游超集」语义。
 */
function fileNameVariants(fileName: string): string[] {
	const variants = [fileName];
	const lower = fileName.toLowerCase();
	const upper = fileName.toUpperCase();
	if (lower !== fileName) variants.push(lower);
	if (upper !== fileName) variants.push(upper);
	return Array.from(new Set(variants));
}

function findProjectFile(cwd: string, fileName: string): string | null {
	let current = resolve(cwd);
	const { root } = parse(current);
	const variants = fileNameVariants(fileName);

	while (true) {
		const candidates: string[] = [];
		for (const v of variants) {
			candidates.push(join(current, ".pi", v), join(current, v));
		}

		const found = findExistingNonEmptyFile(candidates);
		if (found) {
			return found;
		}

		if (current === root) {
			break;
		}
		const parent = dirname(current);
		if (parent === current) {
			break;
		}
		current = parent;
	}

	return null;
}

function loadAsset(cwd: string, fileName: string): LoadedFileAsset | null {
	const home = homedir();
	const userDirs: string[] = [];

	if (process.env.PI_CODING_AGENT_DIR) {
		userDirs.push(resolve(process.env.PI_CODING_AGENT_DIR));
	}
	userDirs.push(join(home, ".pi", "agent"));

	// 1. 项目级
	const projPath = findProjectFile(cwd, fileName);
	if (projPath) {
		try {
			const raw = readFileSync(projPath, "utf-8");
			const clean = stripBom(raw).trim();
			if (clean.length > 0) {
				const st = statSync(projPath);
				return {
					source: "project",
					path: projPath,
					content: clean,
					hash: createHash("sha256").update(clean).digest("hex").slice(0, 8),
					length: clean.length,
					mtime: st.mtimeMs,
				};
			}
		} catch {}
	}

	// 2. 用户全局级（大小写变体全覆盖）
	const userCandidates: string[] = [];
	for (const d of userDirs) {
		for (const v of fileNameVariants(fileName)) {
			userCandidates.push(join(d, v));
		}
		// 兼容 ~/.pi/<name>（无 agent 子目录）的老布局
		userCandidates.push(join(parse(d).dir, fileName));
	}

	const userPath = findExistingNonEmptyFile(userCandidates);
	if (userPath) {
		try {
			const raw = readFileSync(userPath, "utf-8");
			const clean = stripBom(raw).trim();
			if (clean.length > 0) {
				const st = statSync(userPath);
				return {
					source: "user",
					path: userPath,
					content: clean,
					hash: createHash("sha256").update(clean).digest("hex").slice(0, 8),
					length: clean.length,
					mtime: st.mtimeMs,
				};
			}
		} catch {}
	}

	return null;
}

// ============================================================================
// 4. 会话级提示词管理器
// ============================================================================

class UnifiedPromptManager {
	private personality: LoadedFileAsset | null = null;
	private rules: LoadedFileAsset | null = null;
	private system: LoadedFileAsset | null = null;
	private lastReload: number = Date.now();

	public sync(cwd: string, force: boolean = false): void {
		const now = Date.now();
		if (!force && now - this.lastReload < 800) {
			return; // 节流，避免高频请求重复读盘
		}

		this.personality = loadAsset(cwd, "PERSONALITY.md");
		this.rules = loadAsset(cwd, "RULES.md");
		this.system = loadAsset(cwd, SEEP_PROMPT_FILE);
		this.lastReload = now;
	}

	public getPersonality(): LoadedFileAsset | null {
		return this.personality;
	}

	public getRules(): LoadedFileAsset | null {
		return this.rules;
	}

	public getSystem(): LoadedFileAsset | null {
		return this.system;
	}

	public getSnapshot(): PromptAssemblySnapshot {
		return {
			personality: this.personality,
			rules: this.rules,
			system: this.system,
			lastReload: this.lastReload,
		};
	}
}

const managers = new Map<string, UnifiedPromptManager>();

function promptSessionKey(ctx: ExtensionContext | ExtensionCommandContext): string {
	const dynamic = ctx as any;
	try {
		const sid = dynamic?.sessionManager?.getSessionId?.();
		if (typeof sid === "string" && sid.trim()) return `id:${sid.trim()}`;
	} catch {}
	for (const value of [dynamic?.sessionId, dynamic?.session_id, dynamic?.sessionID]) {
		if (typeof value === "string" && value.trim()) return `id:${value.trim()}`;
	}
	try {
		const cwd = resolve(String(dynamic?.cwd || process.cwd())).replace(/\\/g, "/").replace(/\/+$/, "");
		return `cwd:${process.platform === "win32" ? cwd.toLowerCase() : cwd}`;
	} catch {
		return "cwd:unknown";
	}
}

/**
 * 同一个 Pi 进程可能并行承载多个项目会话。提示词资产必须跟随会话，不能由最后
 * 一个 before_agent_start 覆盖所有 context_with_system 调用。
 */
function managerFor(
	ctx: ExtensionContext | ExtensionCommandContext,
	forceSync: boolean = false,
): UnifiedPromptManager {
	const key = promptSessionKey(ctx);
	let manager = managers.get(key);
	if (!manager) {
		manager = new UnifiedPromptManager();
		managers.set(key, manager);
		manager.sync(ctx.cwd, true);
	} else if (forceSync) {
		manager.sync(ctx.cwd, true);
	}
	return manager;
}

// ============================================================================
// 5. 扩展入口注册
// ============================================================================

export default function promptAndPersonalityEnhancer(pi: ExtensionAPI) {
	// 5.1 注册热重载与状态命令
	const handleReload = async (_args: string, ctx: ExtensionCommandContext) => {
		const manager = managerFor(ctx, true);
		const s = manager.getSnapshot();
		const pInfo = s.personality ? `PERSONALITY.md (${s.personality.length}c)` : "无";
		const rInfo = s.rules ? `RULES.md (${s.rules.length}c)` : "无";
		const sysInfo = s.system ? `SEEP.md (${s.system.length}c)` : "无";

		const msg = `[Prompt 重载完成]\n• 人设卡: ${pInfo}\n• 规则卡: ${rInfo}\n• 逆向专精: ${sysInfo}`;
		ctx.ui.notify(msg, "info");
	};

	const handleStatus = async (_args: string, ctx: ExtensionCommandContext) => {
		const manager = managerFor(ctx, true);
		const s = manager.getSnapshot();
		const formatAsset = (name: string, a: LoadedFileAsset | null) => {
			if (!a) return `${name}: 未加载 (未检测到文件)`;
			return `${name}: [已挂载] 来源=${a.source}, 字符数=${a.length}, 路径=${a.path}`;
		};

		const lines = [
			"=== Seep 三位一体提示词与人设状态 ===",
			formatAsset("人设卡 (personality)", s.personality),
			formatAsset("通用规则 (generic-rules)", s.rules),
			formatAsset("逆向专精 (seep-reverse-lab)", s.system),
			`边界锚 (seep-boundary): [always-on] ${BOUNDARY_ANCHOR.length} 字符 · 装配末尾 + 请求期兜底`,
			"=====================================",
		];
		console.log("\n" + lines.join("\n"));
		ctx.ui.notify("提示词与人设卡状态已输出至控制台", "info");
	};

	pi.registerCommand("rules-reload", { description: "强制重新从磁盘加载 PERSONALITY/RULES/SEEP", handler: handleReload });
	pi.registerCommand("prompt-reload", { description: "别名: /rules-reload", handler: handleReload });
	pi.registerCommand("rules-status", { description: "查看当前人设卡与提示词装配状态", handler: handleStatus });
	pi.registerCommand("prompt-status", { description: "别名: /rules-status", handler: handleStatus });

	// 5.2 核心生命周期：before_agent_start (启动时结构化挂载三级 Section)
	pi.on("before_agent_start", async (event, ctx: ExtensionContext) => {
		// ★ 必须 force：sync() 有 800ms 节流，进程启动后首轮会整段跳过，
		//   导致 sections 为空、Seep 规则在一次性会话里静默失效。
		const manager = managerFor(ctx, true);

		const systemPromptOptions = event?.systemPromptOptions;
		if (!systemPromptOptions || typeof systemPromptOptions !== "object") return {};
		systemPromptOptions.sections = systemPromptOptions.sections ?? {};
		if (!systemPromptOptions.sections || typeof systemPromptOptions.sections !== "object" ||
			Array.isArray(systemPromptOptions.sections)) {
			systemPromptOptions.sections = {};
		}

		// 1. 挂载人设层 (sections["personality"])
		const p = manager.getPersonality();
		if (p && p.content) {
			systemPromptOptions.sections["personality"] = p.content;
		}

		// 2. 挂载通用规则层 (sections["generic-rules"])
		const r = manager.getRules();
		if (r && r.content) {
			systemPromptOptions.sections["generic-rules"] = r.content;
		}

		// 3. 挂载逆向专精层 (sections["seep-reverse-lab"])
		const s = manager.getSystem();
		if (s && s.content) {
			systemPromptOptions.sections["seep-reverse-lab"] = s.content;
		}

		// 4. 边界锚：必须最后挂（自定义 section 按插入顺序渲染，实测位于 seep-reverse-lab 之后）
		systemPromptOptions.sections["seep-boundary"] = BOUNDARY_ANCHOR;

		// 不再改写 basePrompt：交给 pi 内核组装（默认提示词 + project_context + 本扩展的 section）。
		return {};
	});

	// 5.3 核心生命周期：context_with_system (会话粘性补偿，杜绝长对话人设丢失)
	pi.on("context_with_system", (event, ctx: ExtensionContext) => {
		if (!Array.isArray(event?.messages)) return;
		const head = event.messages[0];
		if (head && head.role === "system") {
			head.sections = head.sections ?? {};
			if (!head.sections || typeof head.sections !== "object" || Array.isArray(head.sections)) {
				head.sections = {};
			}
			const manager = managerFor(ctx);

			const p = manager.getPersonality();
			if (p && !head.sections["personality"]) {
				head.sections["personality"] = p.content;
			}

			const r = manager.getRules();
			if (r && !head.sections["generic-rules"]) {
				head.sections["generic-rules"] = r.content;
			}

			const s = manager.getSystem();
			if (s && !head.sections["seep-reverse-lab"]) {
				head.sections["seep-reverse-lab"] = s.content;
			}

			// 边界锚同样复挂：长对话压缩 / 会话续接后，锚必须还在
			if (!head.sections["seep-boundary"]) {
				head.sections["seep-boundary"] = BOUNDARY_ANCHOR;
			}
		}
	});

	// 5.4 上下文压缩守护
	pi.on("session_compact", (_event, ctx: ExtensionContext) => {
		managerFor(ctx, true);
	});

	pi.on("session_shutdown", (_event, ctx: ExtensionContext) => {
		managers.delete(promptSessionKey(ctx));
	});
}
