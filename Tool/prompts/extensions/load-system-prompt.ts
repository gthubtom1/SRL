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
 *    - 【逆向专精层】自动发现并挂载 `SYSTEM.md` -> sections["seep-reverse-lab"]
 *    - 【Windows 平台自愈】自动恢复被 Windows 原生 Pi loader 偶发剥离的 basePrompt 核心工具说明
 *
 * 查找优先级 (单双层自适应)：
 *   项目级 (./.pi/xxx.md 或 ./xxx.md) -> 用户全局级 (~/.pi/agent/xxx.md)
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, parse, resolve } from "node:path";
import type {
	BuildSystemPromptOptions,
	ExtensionAPI,
	ExtensionCommandContext,
	ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { getDocsPath, getExamplesPath, getReadmePath } from "@earendil-works/pi-coding-agent";

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
 * 文件名大小写变体：原版扩展同时支持 `system.md` 与 `SYSTEM.md`，
 * 二开重写时一度只认大写（导致老用户的 .pi/system.md 静默失效）。
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
// 3. 兜底恢复 Windows Pi 原生 loader 丢失的基础系统 Prompt
// ============================================================================

function buildDefaultPrompt(options: BuildSystemPromptOptions): string {
	const readmePath = getReadmePath();
	const docsPath = getDocsPath();
	const examplesPath = getExamplesPath();
	const tools = options.selectedTools || ["read", "bash", "edit", "write"];

	const visibleTools = tools.filter((name) => !!options.toolSnippets?.[name]);
	const toolsList =
		visibleTools.length > 0
			? visibleTools.map((name) => `- ${name}: ${options.toolSnippets![name]}`).join("\n")
			: "(none)";

	const guidelinesList: string[] = [];
	const guidelinesSet = new Set<string>();
	const addGuideline = (guideline: string) => {
		if (!guidelinesSet.has(guideline)) {
			guidelinesSet.add(guideline);
			guidelinesList.push(guideline);
		}
	};

	for (const guideline of options.promptGuidelines ?? []) {
		const normalized = guideline.trim();
		if (normalized.length > 0) {
			addGuideline(normalized);
		}
	}

	addGuideline("Be concise in your responses");
	addGuideline("Show file paths clearly when working with files");

	const guidelines = guidelinesList.map((g) => `- ${g}`).join("\n");

	return `You are an expert coding assistant operating inside pi, a coding agent harness. You help users by reading files, executing commands, editing code, and writing new files.

Available tools:
${toolsList}

In addition to the tools above, you may have access to other custom tools depending on the project.

Guidelines:
${guidelines}

Pi documentation (read only when the user asks about pi itself, its SDK, extensions, themes, skills, or TUI):
- Main documentation: ${readmePath}
- Additional docs: ${docsPath}
- Examples: ${examplesPath} (extensions, custom tools, SDK)
- When reading pi docs or examples, resolve docs/... under Additional docs and examples/... under Examples, not the current working directory
- When asked about: extensions (docs/extensions.md, examples/extensions/), themes (docs/themes.md), skills (docs/skills.md), prompt templates (docs/prompt-templates.md), TUI components (docs/tui.md), keybindings (docs/keybindings.md), SDK integrations (docs/sdk.md), custom providers (docs/custom-provider.md), adding models (docs/models.md), pi packages (docs/packages.md), environment variables (docs/environment-variables.md)
- When working on pi topics, read the docs and examples, and follow .md cross-references before implementing
- Always read pi .md files completely and follow links to related docs (e.g., tui.md for TUI API details)`;
}

// ============================================================================
// 4. 全局单例管理器
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
		this.system = loadAsset(cwd, "SYSTEM.md");
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

const manager = new UnifiedPromptManager();

// ============================================================================
// 5. 扩展入口注册
// ============================================================================

export default function promptAndPersonalityEnhancer(pi: ExtensionAPI) {
	// 5.1 注册热重载与状态命令
	const handleReload = async (_args: string, ctx: ExtensionCommandContext) => {
		manager.sync(ctx.cwd, true);
		const s = manager.getSnapshot();
		const pInfo = s.personality ? `PERSONALITY.md (${s.personality.length}c)` : "无";
		const rInfo = s.rules ? `RULES.md (${s.rules.length}c)` : "无";
		const sysInfo = s.system ? `SYSTEM.md (${s.system.length}c)` : "无";

		const msg = `[Prompt 重载完成]\n• 人设卡: ${pInfo}\n• 规则卡: ${rInfo}\n• 逆向专精: ${sysInfo}`;
		ctx.ui.notify(msg, "info");
	};

	const handleStatus = async (_args: string, ctx: ExtensionCommandContext) => {
		manager.sync(ctx.cwd);
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
			"=====================================",
		];
		console.log("\n" + lines.join("\n"));
		ctx.ui.notify("提示词与人设卡状态已输出至控制台", "info");
	};

	pi.registerCommand("rules-reload", { description: "强制重新从磁盘加载 PERSONALITY/RULES/SYSTEM", handler: handleReload });
	pi.registerCommand("prompt-reload", { description: "别名: /rules-reload", handler: handleReload });
	pi.registerCommand("omp-reload", { description: "别名: /rules-reload", handler: handleReload });
	pi.registerCommand("rules-status", { description: "查看当前人设卡与提示词装配状态", handler: handleStatus });
	pi.registerCommand("prompt-status", { description: "别名: /rules-status", handler: handleStatus });

	// 5.2 核心生命周期：before_agent_start (启动时结构化挂载三级 Section)
	pi.on("before_agent_start", async (event, ctx: ExtensionContext) => {
		manager.sync(ctx.cwd);

		const { systemPrompt, systemPromptOptions } = event;
		systemPromptOptions.sections = systemPromptOptions.sections ?? {};

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

		// 4. Windows 原生 Pi loader 基础 prompt 自愈
		let basePrompt = systemPrompt;
		if (systemPromptOptions.customPrompt) {
			const reconstructedDefault = buildDefaultPrompt(systemPromptOptions);
			basePrompt = systemPrompt.replace(systemPromptOptions.customPrompt, reconstructedDefault);
		}

		return {
			systemPrompt: basePrompt,
		};
	});

	// 5.3 核心生命周期：context_with_system (会话粘性补偿，杜绝长对话人设丢失)
	pi.on("context_with_system", (event, ctx: ExtensionContext) => {
		const head = event.messages[0];
		if (head && head.role === "system") {
			head.sections = head.sections ?? {};

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
		}
	});

	// 5.4 上下文压缩守护
	pi.on("session_compact", (_event, ctx: ExtensionContext) => {
		manager.sync(ctx.cwd, true);
	});
}
