/**
 * cmd-guard —— 命令执行物理兜底（pi 扩展）
 *
 * 它解决的是「提示词管不住」的那部分：
 *   · 模型可能忘了传 timeout（pi 的 bash/powershell 工具里 timeout 是可选的，不传 = 无限等）
 *   · 模型可能直接拉起 GUI 程序
 *
 * 这两件事模型自己是察觉不到的 —— 命令阻塞期间模型不在运行，没有任何代码在跑。
 * 「终端计时器在涨 + token 计数静止」= 卡在命令，不是卡在推理。这类卡死不会自愈。
 * 所以必须有一层**物理拦截**，不能只靠文档说「不许这么干」。
 *
 * ── 它做什么 ────────────────────────────────────────────────
 *   1. 补 timeout      没带 timeout 的调用按命令类型自动补（探查 / 分析 / 构建三档）
 *   2. 拦 GUI 二进制   弹窗等输入、零 stdout、进程永不退 —— 同步等它 = 整轮卡死
 *   3. 有界化易挂命令   ssh/scp 补 ConnectTimeout；超大递归扫描抬 timeout
 *   4. 把坑回灌给模型   长链命令、`start` 不带 /b、vmrun 快照锁等，在结果里回一句
 *   5. 卡死可见         底栏实时状态（已跑多久 / 静默多久）+ `/stall` 报告
 *
 * ── 它不做什么 ───────────────────────────────────────────────
 *   · 不解决「上游把 tool_use 结构化块当纯文本返回」那类 API 格式问题。
 *   · 不是路由、不是技能、不是工具清单 —— 它只是一层兜底。
 *     工具在哪、怎么装、怎么登记，全在技能包的 TOOL-CHAIN.md 里。
 *
 * ── ★ GUI 清单从哪来（这是本文件最关键的设计）─────────────────
 *   优先级：rules.json 手工项 > TOOL-CHAIN.md 派生 > 内置兜底表
 *
 *   TOOL-CHAIN.md 是唯一事实源。它写成什么，这里就拦什么 ——
 *   你在文档里加一行 `` `foo.exe`→`foo-cli` ``，本插件下次调用就认得，不用改代码。
 *   反过来：文档里删了，拦截自动消失。
 *
 *   ⚠️ 绝不依赖任何 `tool-index.md` 之类的生成物：那些是旧框架的产物，
 *      路径在换机后根本不存在，读不到会导致 GUI 拦截**整个静默失效**（最坏情况）。
 *      找不到文档时只退到内置兜底表，并在启动横幅里明说「★未找到 TOOL-CHAIN.md」。
 *
 * ── 关闭 ────────────────────────────────────────────────────
 *   设环境变量 CMD_GUARD=0 后重启 pi
 *   或 `/guard off`（本次会话内关），`/guard on` 开回来
 */

import * as fs from "node:fs";
import * as path from "node:path";

/* ────────────────────────────── 配置 ────────────────────────────── */

interface GuardConfig {
	/** 模型自带 timeout 时的默认值（普通命令档） */
	defaultTimeout: number;
	/** 探查类（只读快命令） */
	probeTimeout: number;
	/** 分析类（默认档，缺省等于 defaultTimeout） */
	analysisTimeout: number;
	/** 构建类 / 解释器 */
	heavyTimeout: number;
	/** 递归大目录扫描的最低 timeout */
	scanTimeout: number;
	/** 超过它算「疑似卡死」，底栏变红 */
	stallSeconds: number;
	/** 超过它没有新输出，底栏变黄（还在跑，可能只是慢） */
	noOutputStallSeconds: number;
	/** false = 只记账不阻断（出问题时先观察，不打断） */
	enforce: boolean;
	/** false = 不拦 GUI，只注入 timeout 兜底。客户机 / VM 上 GUI 是正当手段，用这个 */
	blockGui: boolean;
	/** true = 物理拦下「盘根递归扫描」（find / · dir /s C:\）。这类命令几乎必然超时且无产出 */
	blockRootScan: boolean;
	/** 给 ssh/scp 补 ConnectTimeout */
	hardenSsh: boolean;
	/** 手写 GUI 名单（覆盖同名派生项）。值可以是提示语，null / "" 表示「明确不拦」 */
	guiBinaries: Record<string, string | null>;
	/** 命令里含其中任一子串则整条跳过守卫（救急用，慎用） */
	allow: string[];
	/** ★ 硬性禁手：正则命中即拦（或按 severity 只提示）。内置表见 BUILTIN_DENY，这里只管追加 */
	denyRules: DenyRule[];
	/** 按 id 关掉某条内置禁手（例如本机就是专用靶机，允许改网卡） */
	disableDeny: string[];
	/** 额外的 GUI 名单来源文档（Markdown）。文档里 `` `a.exe`→`b` `` 会被派生 */
	toolChainPaths: string[];
	/** ★ 技能包根（含 TOOL-CHAIN.md 的那一层）。留空 = 自动探测 */
	skillRoot: string | null;
}

const HERE = __dirname;

interface DenyRule {
	/** 稳定标识，用于统计与 /guard 展示 */
	id: string;
	/** 正则源码（不区分大小写） */
	re: string;
	/** 给人看的一句话标签 */
	label: string;
	/** block = 直接拦；warn = 只提示不改行为 */
	severity: "block" | "warn";
	/** 为什么禁 + 该改用哪条路（会原样回给模型） */
	hint: string;
}

/**
 * ★ 内置禁手表（2026-10-23 血案后加）
 *
 * 事件：为了「接管授权服务端」，Agent 给正在上网的 DHCP 网卡挂了 /32 别名 IP，
 * 又 `netsh winhttp set proxy` 指向本地假服务器 —— 假服务器一杀，整机断网。
 * 分析机通常就是用户的日常机：改本机全局网络 = 把用户和 Agent 一起搞离线。
 *
 * 判定原则：
 *   1. **改本机网络状态**的写操作 → block。分析永远不需要它；需要观察就用抓包（进程内 hook / 回环代理）。
 *   2. **用 shell 拉起 GUI 目标** → warn。父进程链本身就是反自动化检测面（真实双击父进程 = explorer.exe）。
 *   3. 只读查询（netsh winhttp show / Get-NetIPAddress / ipconfig /all）一律不拦。
 */
/**
 * ★ 只读查看器判定（2026-10-24 误伤修正）
 *
 * 事故：`sed -n '61,62p' <一份含 flashrom 字样的文档>` 被判"刷固件"拦下 —— 读文档被自己的护栏挡住。
 * 原则：**只要那一段命令的程序是文本查看器，它就不可能执行 payload**，与 heredoc 同性质。
 */
const READONLY_PROGRAMS = new Set([
	"grep", "egrep", "fgrep", "rg", "ag", "ack", "findstr", "select-string", "get-content",
	"cat", "gc", "head", "tail", "less", "more", "type", "sed", "awk", "cut", "sort", "uniq",
	"wc", "diff", "comm", "xxd", "od", "hexdump", "strings", "file", "stat", "ls", "dir",
]);

function isReadOnlySegment(cmd: string, at: number): boolean {
	const before = cmd.slice(0, at);
	// 找到命中位置所在那一段的起点（最近的分隔符）
	const seps = [before.lastIndexOf("|"), before.lastIndexOf(";"), before.lastIndexOf("&&"),
		before.lastIndexOf("||"), before.lastIndexOf("\n")];
	const start = Math.max(0, ...seps) + 1;
	let seg = cmd.slice(start, at).trim();
	// 去掉引号/括号/前缀命令（sudo、env、xargs 等不影响"是否是查看器"的判断：
	// 只要段内出现了引号包裹，说明命中串是**参数**而不是程序名）
	if (/^["'`]/.test(seg)) return true;
	// 取段内**首个非选项 token** 作为程序名（旧实现取 pop() 最后一个，
	// 于是 `grep -n flashrom x.md` 被解析成程序名 "flashrom" → 读文档被当成刷固件拦下）
	const toks = seg.split(/\s+/).filter(Boolean).map((t) => t.toLowerCase().replace(/^[("']+/, ""));
	const prog = (toks.find((t) => !t.startsWith("-") && !t.includes("=")) || toks[0] || "");
	if (READONLY_PROGRAMS.has(prog)) return true;
	// git 的只读子命令
	if (/\bgit\s+(show|log|diff|grep)\b/i.test(cmd.slice(start, at + 1))) return true;
	// 命中串本身被引号包住 → 它是参数/字面量，不是被执行的程序
	const hitText = cmd.slice(at, at + 40);
	if (/^["'`]/.test(hitText)) return true;
	return false;
}

const BUILTIN_DENY: DenyRule[] = [
	// ── 网络写操作（block，最高优先）──
	{
		id: "net-ip-alias",
		re: "\\b(New|Remove|Set)-NetIPAddress\\b",
		label: "改网卡 IP（挂/删别名）",
		severity: "block",
		hint:
			"在用户正在上网的网卡上加/删 IP 会打乱源地址选择，直接导致整机断网（已发生过）。\n" +
			"要观察客户端连了哪个服务端：走抓包，不改网络 —— \n" +
			"  ① 进程内 hook（Frida hook WinHttpSendRequest/WinHttpReceiveResponse，最隐蔽，不装驱动）\n" +
			"  ② 回环代理 + 只对该进程生效的重定向（mitmproxy 监听 127.0.0.1 + 目标进程内改 URL/代理参数）\n" +
			"  ③ 只读查现状：`Get-NetIPAddress` / `netsh winhttp show proxy` / `net-rollback.py verify`\n" +
			"确实要改：先 `python Tool/scripts/net-rollback.py snapshot`，再在命令里加 cmd-guard-skip 显式放行。",
	},
	{
		id: "net-iface-write",
		re: "\\b(Set|Enable|Disable|Restart)-Net(Adapter|IPInterface|TCPSetting)\\b|\\bDisable-NetAdapter\\b",
		label: "改网卡/接口状态",
		severity: "block",
		hint: "禁用或重启网卡 = 用户立刻断网。要复现网络条件请在 VM / 容器里做，不要动宿主网卡。",
	},
	{
		id: "net-winhttp-write",
		re: "\\bnetsh\\s+winhttp\\s+(set|import|add)\\b",
		label: "改 WinHTTP 代理",
		severity: "block",
		hint:
			"`netsh winhttp set proxy` 是**整机生效**：假代理一死，所有走 WinHTTP 的程序（含浏览器/更新/客户端）全部失联。\n" +
			"要抓该进程的报文就把代理收敛到进程内：Frida hook `WinHttpGetIEProxyConfigForCurrentUser` / `WinHttpOpen` 的代理参数，\n" +
			"或 mitmproxy + 目标进程内改 URL。只读查询用 `netsh winhttp show proxy`（不拦）。\n" +
			"还原：`netsh winhttp reset proxy` 或 `python Tool/scripts/net-rollback.py restore`。",
	},
	{
		id: "net-dns-write",
		re: "\\bnetsh\\s+(int|interface)\\s+(ip|ipv4)\\s+(set|add)\\s+(dns|address)\\b|\\bSet-DnsClientServerAddress\\b",
		label: "改 DNS / 接口地址",
		severity: "block",
		hint: "改 DNS 会污染整机解析。要重定向某个域名：用抓包工具自己的 map 功能，或进程内 hook（GetAddrInfoW）。",
	},
	{
		id: "net-route-write",
		re: "\\broute\\s+(add|delete|change)\\b|\\b(New|Remove|Set)-NetRoute\\b",
		label: "改路由表",
		severity: "block",
		hint: "改默认路由是断网的标准姿势，且往往残留。要观察流量去向用抓包；要隔离目标请在 VM 里改。",
	},
	{
		id: "net-winsock-reset",
		re: "\\bnetsh\\s+winsock\\s+reset\\b|\\bnetsh\\s+advfirewall\\s+set\\b",
		label: "重置 winsock / 关防火墙",
		severity: "block",
		hint: "重置 winsock 需要重启且会打断用户所有网络会话；关防火墙会把用户暴露掉。两边都别做。",
	},
	// ── 启动纪律（warn：父进程链是反自动化检测面）──
	{
		id: "launch-start-process",
		re: "\\bStart-Process\\b[^|;]*\\.exe",
		label: "用 Start-Process 拉起 exe",
		severity: "warn",
		hint:
			"父进程会是 powershell.exe —— 目标读一次父进程名就知道是被程序拉起（真实双击的父进程是 explorer.exe）。\n" +
			"改用：`powershell -File Tool/scripts/launch-gui.ps1 -Target <exe> -Mode user`（推荐，让用户自己双击）\n" +
			"或 `-Mode shell`（走 explorer.exe 拉起，父进程 = explorer.exe）。",
	},
	{
		id: "launch-cmd-start",
		re: "\\bcmd(\\.exe)?\\s+/c\\s+start\\b|\\bstart\\s+(\"\"\\s+)?[A-Za-z]:\\\\",
		label: "用 cmd start 拉起 exe",
		severity: "warn",
		hint: "父进程会是 cmd.exe，且带独立窗口/不等退出。改用 launch-gui.ps1。",
	},
	{
		id: "launch-subprocess",
		re: "subprocess\\.(Popen|run)\\([^)]*\\.exe",
		label: "用 python subprocess 拉起 exe",
		severity: "warn",
		hint:
			"父进程会是 python.exe；若再带 DETACHED_PROCESS / CREATE_SUSPENDED / DEBUG_PROCESS 标志，\n" +
			"就是反自动化检测的教科书特征。改用 launch-gui.ps1 -Mode shell（explorer 父进程、零参数、无标志）。",
	},
];

const DEFAULTS: GuardConfig = {
	defaultTimeout: 120,
	probeTimeout: 30,
	analysisTimeout: 120,
	heavyTimeout: 600,
	scanTimeout: 180,
	stallSeconds: 240,
	noOutputStallSeconds: 90,
	enforce: true,
	blockGui: true,
	blockRootScan: true,
	hardenSsh: true,
	guiBinaries: {},
	allow: ["cmd-guard-skip"],
	denyRules: [],
	disableDeny: [],
	toolChainPaths: [],
	skillRoot: null,
};

/**
 * 内置兜底表：TOOL-CHAIN.md 读不到时，至少拦住这些「会弹窗 / 会等人」的二进制。
 * **这是下限不是上限** —— 文档里有的都会额外加进来。
 * 值 = 给模型的替代提示；null = 明确不拦（本身就是 headless）。
 */
const BUILTIN_GUI: Record<string, string | null> = {
	"die.exe": "改用 CLI 版 diec（先 --version 确认参数）",
	"wireshark.exe": "改用 tshark",
	"x64dbg.exe": "改用控制台 headless 版（stdin 喂命令、输出可读）",
	"x32dbg.exe": "改用控制台 headless 版",
	"ida.exe": "改用 idat（headless）或 Ghidra analyzeHeadless",
	"ida64.exe": "改用 idat（headless）或 Ghidra analyzeHeadless",
	"windbg.exe": "改用 cdb.exe（支持 crash dump 分析）",
	"dnspy.exe": "改用 dnSpy.Console",
	"ollydbg.exe": "改用控制台版调试器",
	"immunitydebugger.exe": "改用控制台版调试器",
	"cheatengine.exe": "内存扫描走脚本，不要同步等 GUI",
	"cheatengine-x86_64.exe": "内存扫描走脚本，不要同步等 GUI",
	"ilspy.exe": "改用 ilspycmd",
	"procmon.exe": "改用 procmon64.exe /B 批处理模式，或 Sysmon CLI",
	"binaryninja.exe": "改用 Binary Ninja 的 Python API / headless",
	"jeb.exe": "改用 jeb-cli / headless 模式",
	// 这两个本身就是 headless —— 明确标「不拦」
	"idat.exe": null,
	"idat64.exe": null,
	"analyzeheadless.bat": null,
};

/** 解释器 / 包管理器：跑的是任意脚本，不能用分类 timeout 硬套 */
const INTERPRETERS = new Set([
	"python", "python3", "py", "pip", "pip3", "uv", "pipx",
	"node", "npm", "npx", "pnpm", "yarn", "bun",
	"bash", "sh", "pwsh", "powershell", "cmd", "wsl",
	"java", "javac", "dotnet", "go", "cargo", "rustc",
	"make", "cmake", "msbuild", "gradle", "mvn",
	"r2", "radare2", "ghidra", "analyzeheadless",
]);

/* ──────────────────── 技能包根定位（换机零配置）──────────────────── */

function fileExists(p: string): boolean {
	try {
		return fs.existsSync(p);
	} catch {
		return false;
	}
}

/**
 * TOOL-CHAIN.md 在包内的位置。
 * 现行布局：skillpack/TOOL-CHAIN.md（必须随 skillpack/ 一起分发，否则按 AI-INSTALL.md
 * 只装 skillpack/ 的机器上，TOOLS.md 里的链接就是死的，verify-doc-links.py 也会报断链）。
 * 早期布局：<根>/TOOL-CHAIN.md。两种都认，换布局不用改代码。
 */
function chainPath(root: string): string | null {
	for (const rel of [path.join("skillpack", "TOOL-CHAIN.md"), "TOOL-CHAIN.md"]) {
		const p = path.join(root, rel);
		if (fileExists(p)) return p;
	}
	return null;
}

function looksLikeRoot(dir: string): boolean {
	return chainPath(dir) !== null;
}

/**
 * 按顺序找含 TOOL-CHAIN.md 的目录。第一个命中即返回。
 * 顺序刻意设计成「越确定越靠前」，这样在任何机器上都不需要先设环境变量。
 */
function findSkillRoot(configured: string | null): string | null {
	const candidates: string[] = [];
	if (configured) candidates.push(configured);

	// 1) 显式环境变量
	for (const k of ["RELAB_SKILL_ROOT", "REVERSE_SKILL_ROOT", "CMD_GUARD_SKILL_ROOT"]) {
		const v = process.env[k];
		if (v) candidates.push(v);
	}

	// 2) 本文件就躺在技能包里 → 从 __dirname 往上数（kernel/extensions/pi/ → 根）
	//    这是最可靠的一条：只要整包 clone 下来就成立，不依赖任何环境变量。
	let dir = HERE;
	for (let i = 0; i < 5; i++) {
		candidates.push(dir);
		const up = path.dirname(dir);
		if (up === dir) break;
		dir = up;
	}

	// 3) 习惯位置（换盘用环境变量覆盖即可）
	candidates.push("C:/relab2", "C:/relab", "D:/relab2");
	// 3) 习惯位置。换盘 / 换机器用环境变量覆盖即可，不要往这里堆历史路径 ——
	//    那是「不许猜路径」纪律要治的病：探一个谁也说不清在哪的目录，
	//    探到了说不清是哪台机器的，探不到又看不出原因。
	//    确实装在别处 → 设 RELAB_SKILL_ROOT，或在 rules.json 写 skillRoot / toolChainPaths。
	candidates.push("C:/relab2", "C:/relab", "D:/relab2");
	const seen = new Set<string>();
	for (const c of candidates) {
		const abs = path.resolve(c);
		const key = abs.toLowerCase();
		if (seen.has(key)) continue;
		seen.add(key);
		if (looksLikeRoot(abs)) return abs;
	}
	return null;
}

/** 技能包根 + 文档清单。root 为 null 表示一处都没找到 —— 启动时会明说。 */
function docSources(config: GuardConfig, root: string | null): string[] {
	const out: string[] = [];
	if (root) {
		const main = chainPath(root);
		if (main) out.push(main);
		// 技能包里其它也会写 GUI 替代方案的地方，一并认（存在才认）
		for (const rel of ["skillpack/skills/TOOLS.md", "skillpack/skills/SKILL.md"]) {
			const p = path.join(root, rel);
			if (fileExists(p)) out.push(p);
		}
	}
	for (const p of config.toolChainPaths) {
		const abs = path.resolve(p);
		if (fileExists(abs)) out.push(abs);
	}
	return out;
}

/* ──────────────────── 从文档派生 GUI 名单 ──────────────────── */

/**
 * 认两种写法，都是文档里自然会出现的人话：
 *   行内：  `die.exe`→`diec`   `Wireshark.exe`→`tshark`   `ida.exe` 改用 idat
 *   表格：  | `foo.exe` | **`foo-cli`** `-x <file>` |
 *
 * 不做精确解析 —— 宁可多拦几个（模型看到提示会自己判断），不可漏拦。
 */
const ARROW_RE = /`?([\w.\-]+\.(?:exe|bat|cmd))`?\s*(?:→|->|=>|改用|换成)\s*`?([\w.\-]+(?:\.exe|\.bat|\.cmd)?)`?/gi;
const TABLE_RE = /^\s*\|\s*`?([\w.\-]+\.(?:exe|bat|cmd))`?\s*\|[^|]*?`([\w.\-]+(?:\.exe|\.bat|\.cmd)?)`/gim;

function parseGuiFromDoc(text: string, source: string): Map<string, string> {
	const out = new Map<string, string>();

	ARROW_RE.lastIndex = 0;
	let m: RegExpExecArray | null;
	while ((m = ARROW_RE.exec(text)) !== null) {
		const gui = m[1].toLowerCase();
		const cli = m[2].toLowerCase();
		if (gui === cli) continue; // 自己指向自己 = 本身就是 CLI
		out.set(gui, `改用 ${cli}（来源 ${source}）`);
	}

	TABLE_RE.lastIndex = 0;
	while ((m = TABLE_RE.exec(text)) !== null) {
		const gui = m[1].toLowerCase();
		const cli = m[2].toLowerCase();
		if (gui === cli) continue;
		if (!out.has(gui)) out.set(gui, `改用 ${cli}（来源 ${source}）`);
	}

	return out;
}

/* ──────────────────────── 规则加载（含热重载）──────────────────── */

let config: GuardConfig = { ...DEFAULTS };
/** exe 名（小写）→ 替代提示；值 null = 明确不拦 */
let guiTable = new Map<string, string | null>();
let rulesSource = "内置兜底表";
let loadedAt = 0;
let loadedStamp = "";

function rulesPath(): string {
	return path.join(HERE, "cmd-guard.rules.json");
}

function mtimeOf(p: string): string {
	try {
		return String(fs.statSync(p).mtimeMs);
	} catch {
		return "0";
	}
}

function loadConfig(force = false): void {
	const now = Date.now();
	const rp = rulesPath();
	const stamp = `${mtimeOf(rp)}:${process.env.RELAB_SKILL_ROOT || ""}`;
	// 30 秒节流：文件没变就别反复读盘；但 /guard reload 走 force
	if (!force && stamp === loadedStamp && now - loadedAt < 30_000) return;
	loadedStamp = stamp;
	loadedAt = now;

	config = { ...DEFAULTS, guiBinaries: {}, allow: [...DEFAULTS.allow], toolChainPaths: [] };
	let parseError = "";
	try {
		if (fileExists(rp)) {
			const raw = JSON.parse(fs.readFileSync(rp, "utf-8")) as Record<string, unknown>;
			for (const k of Object.keys(DEFAULTS) as (keyof GuardConfig)[]) {
				if (raw[k] !== undefined) (config as Record<string, unknown>)[k] = raw[k];
			}
			// 兼容老 rules.json：indexPaths 也当成文档来源
			const legacy = raw.indexPaths;
			if (Array.isArray(legacy)) {
				config.toolChainPaths = [...config.toolChainPaths, ...(legacy as string[])];
			}
		}
	} catch (e) {
		// 规则坏了要用默认值，但不能因此让守卫变成故障源 —— 也不能静默
		parseError = (e as Error).message;
		console.error(`[cmd-guard] rules.json 解析失败，改用默认配置：${parseError}`);
	}
	if (!Array.isArray(config.allow)) config.allow = [];
	if (!Array.isArray(config.toolChainPaths)) config.toolChainPaths = [];
	// denyRules：rules.json 里给了就「在内置表基础上追加」，而不是整体替换 ——
	// 否则用户写一条自己的规则就把网络禁手全关了。（DEFAULTS.denyRules 必须是空数组，
	// 否则这里会把内置表当「追加项」再拼一遍。）
	{
		const disabled = new Set((Array.isArray(config.disableDeny) ? config.disableDeny : []).map((x) => String(x)));
		const extra = Array.isArray(config.denyRules) ? config.denyRules : [];
		const clean: DenyRule[] = [];
		for (const r of extra as unknown as DenyRule[]) {
			if (!r || typeof r !== "object") continue;
			const re = String((r as DenyRule).re || "");
			if (!re) continue;
			try {
				new RegExp(re, "i");
			} catch {
				console.error(`[cmd-guard] denyRules 正则写错，已忽略：${re}`);
				continue;
			}
			clean.push({
				id: String((r as DenyRule).id || `custom-${clean.length}`),
				re,
				label: String((r as DenyRule).label || re),
				severity: (r as DenyRule).severity === "warn" ? "warn" : "block",
				hint: String((r as DenyRule).hint || ""),
			});
		}
		config.denyRules = [...BUILTIN_DENY.filter((r) => !disabled.has(r.id)), ...clean];
	}
	// 手工项必须是「exe 名 → 提示语/null」的对象。旧版这里收的是数组，两种形状都见过，
	// 先按形状判断：写错时退成空表并在 stderr 说明，而不是让 Object.entries 拿数组当表用。
	if (!config.guiBinaries || typeof config.guiBinaries !== "object" || Array.isArray(config.guiBinaries)) {
		if (config.guiBinaries !== undefined && config.guiBinaries !== null) {
			console.error("[cmd-guard] guiBinaries 形状不对（要 \"exe名\": \"提示语\" 对象），本项已忽略");
		}
		config.guiBinaries = {};
	}

	const root = findSkillRoot(config.skillRoot);
	const docs = docSources(config, root);

	// 优先级（后者覆盖前者）：内置基线 → 文档派生 → rules.json 手工项
	guiTable = new Map(Object.entries(BUILTIN_GUI));
	rulesSource = docs.length ? `文档派生（${docs.length} 份）` : "内置兜底表";
	if (!docs.length) rulesSource += " ★未找到 TOOL-CHAIN.md";
	if (parseError) rulesSource += " ★rules.json 有错";

	for (const d of docs) {
		try {
			for (const [k, v] of parseGuiFromDoc(fs.readFileSync(d, "utf-8"), path.basename(d))) {
				guiTable.set(k, v);
			}
		} catch (e) {
			console.error(`[cmd-guard] 读文档失败 ${d}：${(e as Error).message}`);
		}
	}

	for (const [k, v] of Object.entries(config.guiBinaries || {})) {
		guiTable.set(k.toLowerCase(), v === null || v === "" ? null : String(v));
	}
}

/* ─────────────────────── 命令识别与分类 ─────────────────────── */

const SEG_SPLIT = /&&|\|\||[;\n|]/;

/**
 * 抽出命令里**真正被调用**的可执行文件名。
 * 只看「命令位置」—— 字符串开头，或分段（`&&` `||` `;` `|` 换行）之后的第一个词元。
 * 这样 `Test-Path D:\Tools\die\die.exe` 这种「探测文件在不在」不会被误拦。
 */
function invokedNames(cmd: string): string[] {
	const out: string[] = [];
	for (const rawSeg of cmd.split(SEG_SPLIT)) {
		let seg = rawSeg.replace(/^\s*[({\[]+/, "");
		// 剥掉前置包装，最多剥 5 层（env A=1 nohup sudo start /b X ...）
		for (let i = 0; i < 5; i++) {
			const before = seg;
			seg = seg.replace(
				/^\s*(?:&\s*|call\s+|nohup\s+|sudo\s+|doas\s+|time\s+|start(?:\s+\/[bB])?\s+|Start-Process\s+(?:-FilePath\s+)?|Invoke-Item\s+|ii\s+)/i,
				"",
			);
			seg = seg.replace(/^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)+/, "");
			if (seg === before) break;
		}
		seg = seg.trim();
		if (!seg) continue;
		const m = seg.match(/^["']?([^"'&\s|;]+)["']?/);
		if (!m) continue;
		const base = (m[1].split(/[\\/]/).pop() || "").toLowerCase();
		if (base) out.push(base);
	}
	return out;
}

/** 词元在 GUI 表里命中吗？返回 [表内键, 提示] 或 null（提示为 null 表示明确不拦） */
function guiHit(token: string): [string, string | null] | null {
	const keys = token.includes(".") ? [token] : [token, `${token}.exe`, `${token}.bat`, `${token}.cmd`];
	for (const k of keys) {
		if (guiTable.has(k)) return [k, guiTable.get(k) ?? null];
	}
	return null;
}

function findGui(cmd: string): [string, string] | null {
	for (const name of invokedNames(cmd)) {
		const hit = guiHit(name);
		if (!hit) continue;
		if (hit[1] === null) continue; // 明确标记为 headless，不拦
		return [hit[0], hit[1]];
	}
	return null;
}

const HEAVY = [
	/\bvmrun\b/i,
	/\bvboxmanage\b/i,
	/\bnpm\s+(i|install|ci)\b/i,
	/\bnpx\b/i,
	/\bpip\s+install\b/i,
	/\bgit\s+clone\b/i,
	/\b(msbuild|dotnet\s+build|gradle|maven|mvn|cmake|ninja|cargo\s+build|turbo\s+build)\b/i,
	/\banalyzeHeadless\b/i,
	/\bdir\s+\/[sS]\b/,
	/\bmake\b/i,
];
const PROBE = [
	/^\s*(ls|dir|Get-ChildItem|gci)\b/i,
	/^\s*(cat|type|head|tail|less|more)\b/i,
	/^\s*(which|where|Get-Command|Test-Path|Resolve-Path|Get-Item|Get-Content)\b/i,
	/^\s*(echo|cd|pwd|whoami|date|ver|uname)\b/i,
	/^\s*(git\s+(status|log|diff|show|branch|rev-parse))\b/i,
];
const RECURSIVE_SCAN =
	/\b(find|rg|grep|Get-ChildItem|gci)\b[^\n]*(\s-r\b|-Recurse|[A-Za-z]:[\\/](HACKER|Project|Users|Windows|node_modules|EXE|Tools|\.git)\b|\/(usr|var|opt|home)\b)/i;
/**
 * POSIX 根扫描：`find /` · `grep -r /` · `du -sh /`。
 * ★ v2.1.0 新增：`find /` 不带盘符，旧的两条正则都漏判 ——
 *   实测事故：agent 发出 `find / -maxdepth 8 -type d -name x`，未命中任何规则，
 *   只拿到默认 120s，仍在盘根扫了几分钟。
 */
const POSIX_ROOT_SCAN = /\b(find|du|tree)\b[^\n]*?\s\/((\s)|$)|\b(grep|rg)\b[^\n]*?\s-[a-zA-Z]*r[a-zA-Z]*\s[^\n]*?\s\/((\s)|$)/i;
/** 命中盘根递归扫描则返回该命令片段，否则 null。 */
function detectRootScan(cmd: string): string | null {
	if (POSIX_ROOT_SCAN.test(cmd)) return cmd.trim();
	if (DRIVE_ROOT_SCAN.test(cmd)) return cmd.trim();
	return null;
}

const DRIVE_ROOT_SCAN =
	// 只认「命令词 + 路径正好停在盘符根」。旧版两处写法都有问题：
	//   顶层 `|` 让第二个分支脱离命令词 → 任何带 C:\ 的命令都被当成全盘扫描；
	//   负向前瞻只查「后面还有没有反斜杠」→ `C:\relab2` 没有反斜杠，也被误判成全盘扫描。
	// 现在两条分支都要求路径 token 到此为止。
	/\b(find|rg|grep|dir|Get-ChildItem|gci)\b[^\n]*?(?:"[A-Za-z]:[\\/]"|[A-Za-z]:[\\/](?=[\s"']*$))/i;

function classify(cmd: string): "probe" | "heavy" | "normal" {
	if (HEAVY.some((r) => r.test(cmd))) return "heavy";
	if (PROBE.some((r) => r.test(cmd))) return "probe";
	return "normal";
}

function pickTimeout(cmd: string): { secs: number; why: string } {
	// 解释器 / 包管理器跑的是任意脚本，给最宽的
	const head = invokedNames(cmd)[0] ?? "";
	if (head && INTERPRETERS.has(head.replace(/\.(exe|bat|cmd)$/i, ""))) {
		return { secs: config.heavyTimeout, why: "解释器/包管理器" };
	}
	const kind = classify(cmd);
	if (kind === "probe") return { secs: config.probeTimeout, why: "探查" };
	if (kind === "heavy") return { secs: config.heavyTimeout, why: "构建" };
	return { secs: config.analysisTimeout || config.defaultTimeout, why: "分析" };
}

function countSegments(cmd: string): number {
	return cmd.split(SEG_SPLIT).map((s) => s.trim()).filter(Boolean).length;
}

function head(cmd: string, n = 72): string {
	const one = cmd.replace(/\s+/g, " ").trim();
	return one.length > n ? one.slice(0, n) + "…" : one;
}

/** 给 ssh/scp 补连接超时 + 心跳，bash 侧再断掉交互提示。 */
function hardenSsh(cmd: string, shell: "bash" | "powershell"): { cmd: string; injected: string[] } {
	const injected: string[] = [];
	// 只在「真命令位置」注入，否则 echo "ssh is old" 会被改写（这个坑踩过）
	const SEG = /(^|[\n;|&(]\s*)((?:[\w.]+=\S+\s+)*)((?:ssh|scp|sftp|rsync))\b/gi;
	const already = /ConnectTimeout/i.test(cmd);
	let touched = false;

	let out = cmd.replace(SEG, (m, lead: string, envPrefix: string, word: string) => {
		touched = true;
		if (already) return m;
		return lead + envPrefix + word + " -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=3";
	});
	if (touched && !already) injected.push("ssh/scp: ConnectTimeout=15 + ServerAlive 心跳");

	const hasRealSsh = /(^|[\n;|&(]\s*)((?:[\w.]+=\S+\s+)*)(?:ssh)\b/i.test(cmd);
	if (shell === "bash" && hasRealSsh && !/<\s*\//.test(out)) {
		out = out + " < /dev/null";
		injected.push("ssh: </dev/null 断交互");
	}
	return { cmd: out, injected };
}

/* ─────────────────────────── 记账 ─────────────────────────── */

interface CallRecord {
	command: string;
	shell: "bash" | "powershell";
	startedAt: number;
	lastOutputAt: number;
	injected: string[];
	notes: string[];
	ownTimeout: number | null;
}

interface HistoryEntry {
	at: string;
	toolName: string;
	head: string;
	seconds: number;
	verdict: string;
}

type TextContent = { type: "text"; text: string };

const running = new Map<string, CallRecord>();
const history: HistoryEntry[] = [];
const blocked: { at: string; cmd: string; reason: string }[] = [];
let stats = { guarded: 0, injected: 0, blocked: 0 };
let ticker: ReturnType<typeof setInterval> | null = null;
let enabled = true;

/** 最近一次事件回调带来的 ctx —— 用来访问 ui（ExtensionAPI 本身没有 ui） */
let hostCtx: any = null;

function fmtSec(ms: number): string {
	const s = Math.floor(ms / 1000);
	return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m${String(s % 60).padStart(2, "0")}s`;
}

function stopTicker(): void {
	if (ticker) {
		clearInterval(ticker);
		ticker = null;
	}
}

function renderStatus(): void {
	const ui = hostCtx?.ui;
	if (!ui?.setStatus) return;
	if (!running.size) {
		ui.setStatus("cmd-guard", stats.guarded || stats.blocked ? `⛨ guard · 守卫${stats.guarded} · 拦${stats.blocked}` : undefined);
		return;
	}
	const parts: string[] = [];
	for (const r of running.values()) {
		const total = Date.now() - r.startedAt;
		const silent = Date.now() - r.lastOutputAt;
		const mark = total >= config.stallSeconds ? "✖" : silent >= config.noOutputStallSeconds ? "◐" : "●";
		parts.push(`${mark} ${r.shell} ${fmtSec(total)} · 静默 ${fmtSec(silent)} · ${head(r.command, 40)}`);
	}
	ui.setStatus("cmd-guard", "⛨ " + parts.join("  |  "));
}

function ensureTicker(): void {
	if (ticker) return;
	ticker = setInterval(() => {
		if (!running.size) {
			stopTicker();
			renderStatus();
			return;
		}
		renderStatus();
	}, 1000);
	if (typeof ticker.unref === "function") ticker.unref();
}

/* ───────────────────────── 扩展主体 ───────────────────────── */

export default function cmdGuard(pi: any): void {
	if (process.env.CMD_GUARD === "0") {
		enabled = false;
		return;
	}

	loadConfig(true);

	// 启动横幅：规则来源必须看得见。静默降级是这个插件最坏的失败模式。
	const active = [...guiTable.entries()].filter(([, v]) => v !== null).length;
	console.error(
		`[cmd-guard] 已加载 · timeout ${config.probeTimeout}/${config.analysisTimeout || config.defaultTimeout}/${config.heavyTimeout}s` +
			` · GUI 拦截 ${active} 条 · 规则来源 ${rulesSource}` +
			` · 卡死阈值 ${config.stallSeconds}s · 静默阈值 ${config.noOutputStallSeconds}s` +
			`${config.enforce ? "" : " · ★enforce=false，只记账不阻断"}` +
			`${config.blockGui ? "" : " · ★blockGui=false，不拦 GUI"}` +
			`${config.blockRootScan ? " · 盘根扫描=拦截" : " · ★blockRootScan=false，盘根扫描只抬 timeout"}`,
	);

	// ── 上下文捕获：ExtensionAPI 没有 ui，ui 在 handler 的第二个参数上 ──
	const remember = (ctx: any): void => {
		if (ctx) hostCtx = ctx;
	};

	pi.on("session_start", (_e: unknown, ctx: any) => {
		remember(ctx);
		if (!guiTable.size || rulesSource.includes("★")) {
			ctx?.ui?.notify?.(
				`cmd-guard 降级中：${rulesSource}\n` +
					`GUI 拦截只剩内置兜底表。设 RELAB_SKILL_ROOT 指向技能包根，或在 cmd-guard.rules.json 写 toolChainPaths。`,
				"warning",
			);
		}
	});

	pi.on("tool_call", (event: any, ctx: any) => {
		remember(ctx);
		if (!enabled) return;
		const name = event.toolName;
		// ★ 弹窗式问人一律拦下（2026-10-23 用户明确要求，已强调多次）。
		//   理由：① 选项只能 2–4 个、每项 ≤60 字，四要素长卡塞不进去；
		//         ② 它把「等人」变成一次工具往返，给上下文塞结构化噪声；
		//         ③ 用户要的是“对话框里列 A/B/C/D，我回一个字母”。
		if (name === "ask_user_question") {
			const reason =
				`[cmd-guard] 已拦下：弹窗式问人（ask_user_question）不用于本项目。\n` +
				`改用对话内 A/B/C：先把卡落盘并列出选项，然后把下面这段**原样贴进对话**：\n\n` +
				`  【需要你选】<一句话：卡在哪>\n` +
				`    A  …\n` +
				`    B  …\n` +
				`    C  …\n` +
				`  直接回 A / B / C\n\n` +
				`落盘与回执：\n` +
				`  python Tool/scripts/case_state.py ask --case <case> --stuck "..." --option "A ..." --option "B ..." --option "C ..."\n` +
				`  python Tool/scripts/case_state.py ack --case <case> --ack A\n\n` +
				`（ask 会打印可直接粘贴的卡片；等待态写在 state.awaiting_human）`;
			return { block: true, reason };
		}
		if (name !== "bash" && name !== "powershell") return;
		const shell: "bash" | "powershell" = name === "bash" ? "bash" : "powershell";
		let cmd = String(event.input?.command ?? "");
		if (!cmd.trim()) return;

		loadConfig();
		if (config.allow.some((a) => a && cmd.toLowerCase().includes(a.toLowerCase()))) return;

		const injected: string[] = [];
		const notes: string[] = [];

		/* 0.5 禁手表 —— 网络写操作（block）/ 启动纪律（warn）。
		   比 GUI 拦截更优先：它造成的是「用户整机受影响」，比挂死严重。 */
		if (Array.isArray(config.denyRules) && config.denyRules.length) {
			for (const rule of config.denyRules) {
				let re: RegExp;
				try {
					re = new RegExp(rule.re, "i");
				} catch {
					continue;
				}
				const hit = cmd.match(re);
				if (!hit) continue;
				// ★ 误伤修正（2026-10-23）：heredoc 体里写的命令是"数据"，不是被执行的东西。
				//   实例：用 `python - <<'PY'` 往 markdown 里写一段"禁手清单"，
				//   因为正文里出现了 `New-NetIPAddress` 就被整条拦下 —— 写文档被自己的护栏挡住。
				//   判据：命中位置在第一个 heredoc 标记之后 → 只记笔记，不阻断。
				const heredocAt = cmd.search(/<<-?\s*['"]?[A-Za-z_][A-Za-z0-9_]*['"]?/);
				if (heredocAt >= 0 && typeof hit.index === "number" && hit.index > heredocAt) {
					notes.push(`（heredoc 数据区里出现了「${rule.label}」字样，按文本处理，未阻断）`);
					continue;
				}
				// ★ 只读查看器例外（2026-10-24）：grep/sed/cat/Get-Content 看文档时命中禁手词，属于"读到"不是"要做"。
				if (typeof hit.index === "number" && isReadOnlySegment(cmd, hit.index)) {
					notes.push(`（只读查看：出现「${rule.label}」字样，按文本处理，未阻断）`);
					continue;
				}
				const body =
					`[cmd-guard] ${rule.severity === "block" ? "已拦下" : "注意"}：${rule.label}\n` +
					`命中：\`${head(hit[0], 80)}\`\n` +
					rule.hint;
				if (rule.severity === "block") {
					if (config.enforce) {
						blocked.push({ at: new Date().toISOString().slice(11, 19), cmd: head(cmd, 100), reason: head(`${rule.label}：${rule.id}`, 100) });
						stats.blocked++;
						ctx?.ui?.notify?.(`cmd-guard 拦下：${rule.label}`, "warning");
						return { block: true, reason: body };
					}
					notes.push(`【禁手但 enforce=false】${rule.label}`);
				} else {
					notes.push(body);
				}
			}
		}

		/* 1. GUI / 交互式二进制 —— 物理拦下，这是 die.exe 那次挂死的根因 */
		if (config.blockGui) {
			const hit = findGui(cmd);
			if (hit) {
				const reason =
					`[cmd-guard] 已拦下：\`${hit[0]}\` 是 GUI/交互式程序。\n` +
					`它会弹窗等输入、零 stdout、进程永不退出；命令阻塞期间模型不在运行，物理上无法自愈。\n` +
					`改用：${hit[1]}\n` +
					`工具真实路径怎么查：先跑 \`(Get-Command <工具id> -ErrorAction SilentlyContinue).Source\`，` +
					`无值再按 TOOL-CHAIN.md 的四级递进（env → PATH → _map.json 别名 → 递归兜底）。\n` +
					`确实只能用 GUI 时：宿主有界面控制能力（computer-use 等）就开界面会话，别在 bash 里同步等；` +
					`否则加 \`cmd-guard-skip\` 到命令里临时放行并立刻中断。`;
				blocked.push({ at: new Date().toISOString().slice(11, 19), cmd: head(cmd, 100), reason: head(reason, 100) });
				stats.blocked++;
				if (config.enforce) {
					ctx?.ui?.notify?.(`cmd-guard 拦下 ${hit[0]}：改用 ${hit[1].slice(0, 60)}`, "warning");
					return { block: true, reason };
				}
				notes.push(`\`${hit[0]}\` 在 GUI 名单里但 enforce=false，本次未拦。`);
			}
		}

		/* 1.5 盘根递归扫描 —— 拦下而不是只抬 timeout：抬到 180s 仍是 3 分钟空转 */
		if (config.blockRootScan) {
			const rootHit = detectRootScan(cmd);
			if (rootHit) {
				const reason =
					`[cmd-guard] 已拦下盘根递归扫描：\`${head(rootHit, 80)}\`。\n` +
					`这类命令会扫满整盘、几十秒到几分钟不返回；命令阻塞期间模型不在运行，物理上无法自愈。\n` +
					`改用：已知路径常量（项目内 TOOL_DIR / 配置里的绝对路径）→ \`where.exe <id>\` / \`Get-Command <id>\` → 工具发现器。\n` +
					`确实要扫：把范围缩到具体目录（\`find <dir> -maxdepth N\`），或加 \`cmd-guard-skip\` 临时放行并显式传 timeout。`;
				blocked.push({ at: new Date().toISOString().slice(11, 19), cmd: head(cmd, 100), reason: head(reason, 100) });
				stats.blocked++;
				if (config.enforce) {
					ctx?.ui?.notify?.("cmd-guard 拦下盘根递归扫描：改用具体目录或工具发现器", "warning");
					return { block: true, reason };
				}
				notes.push("盘根递归扫描：blockRootScan=true 但 enforce=false，本次未拦。");
			}
		}

		/* 2. timeout —— 不传就是无限等，这里替模型补上 */
		const cur = typeof event.input.timeout === "number" && event.input.timeout > 0 ? event.input.timeout : 0;
		if (RECURSIVE_SCAN.test(cmd) || DRIVE_ROOT_SCAN.test(cmd)) {
			const want = Math.max(config.scanTimeout, cur);
			if (want !== cur) {
				event.input.timeout = want;
				injected.push(`timeout=${want}（递归大目录扫描）`);
			} else {
				injected.push(`timeout=${cur}（模型自带，递归扫描）`);
			}
		} else if (!cur) {
			const t = pickTimeout(cmd);
			event.input.timeout = t.secs;
			injected.push(`timeout=${t.secs}（${t.why}）`);
		} else {
			injected.push(`timeout=${cur}（模型自带）`);
		}

		/* 3. ssh / scp 有界化 */
		if (config.hardenSsh && /\b(ssh|scp|sftp|rsync)\b/i.test(cmd)) {
			const hardened = hardenSsh(cmd, shell);
			if (hardened.cmd !== cmd) {
				cmd = hardened.cmd;
				event.input.command = cmd;
				injected.push(...hardened.injected);
			}
		}

		/* 4. 链长等坑 —— 只提示不拦，避免误伤正当的多步操作 */
		const segs = countSegments(cmd);
		if (segs > 8) {
			notes.push(
				`单条命令串了 ${segs} 段（>8）。任一段等交互或打错路径，整条就死，且出错时前面产物落在哪说不清。拆成多条单独调用。`,
			);
		}
		if (/\/(tmp|var\/tmp)\b|\bC:\\tmp\b/i.test(cmd) && /\b(ssh|scp)\b/i.test(cmd)) {
			notes.push(
				"同一条命令里混用了 POSIX 路径（Git-Bash 下 `/tmp` 实为 `C:\\tmp`）与 Windows 路径，远程端路径几乎必错。两端路径分两次调用，别混写。",
			);
		}
		if (/\bstart\s+(?!\/[bB])/i.test(cmd) && shell === "powershell") {
			notes.push("`start` 不带 /b 会新开一个独立窗口并立刻返回，后台进程不受管。改用 `start /b ... > log 2>&1` + 轮询产物。");
		}
		if (/\bvmrun\b.*\b(snapshot|suspend)\b/i.test(cmd)) {
			notes.push(
				"`vmrun snapshot/suspend` 是 VIX 同步调用，VM 运行中 / 实时扫描 / 快照锁争用时可无限期挂起。改成后台执行 + 轮询 `*.vmsn` 是否落地。",
			);
		}

		stats.guarded++;
		stats.injected += injected.length;

		running.set(event.toolCallId, {
			command: cmd,
			shell,
			startedAt: Date.now(),
			lastOutputAt: Date.now(),
			injected,
			notes,
			ownTimeout: typeof event.input.timeout === "number" ? event.input.timeout : null,
		});
		ensureTicker();
		renderStatus();
		return;
	});

	/* 有输出就刷新静默计时 */
	pi.on("tool_execution_update", (event: any, ctx: any) => {
		remember(ctx);
		const r = running.get(event.toolCallId);
		if (r) r.lastOutputAt = Date.now();
	});

	/* 结束：记账 + 把提示回灌给模型，让它自己改 */
	pi.on("tool_result", (event: any, ctx: any) => {
		remember(ctx);
		const r = running.get(event.toolCallId);
		if (!r) return;
		running.delete(event.toolCallId);
		if (!running.size) stopTicker();
		renderStatus();

		const secs = Math.round((Date.now() - r.startedAt) / 1000);
		const verdict = event.isError ? "失败" : "完成";
		// 工具在问用户（need_from_user）→ 必须转达，不许自己往下做。
		// 为什么放这里：提示词里的规则模型会忽略，工具结果里追加的文字每次都会进上下文。
		// 实测（2026-10-24 会话 01a16e82）：seep_packer_detect 已返回 3 条问句，模型没转达就继续分析。
		let askNote: TextContent | null = null;
		try {
			const dump = JSON.stringify({ c: event.content, s: event.structuredContent, d: event.details });
			if (dump.includes("need_from_user")) {
				const NL = String.fromCharCode(10);
				const qs = [...dump.matchAll(/"question"\s*:\s*"([^"]{8,160})"/g)].map((m) => m[1]);
				const parts = [
					"[必须转达 · 不是建议]",
					"这个工具正在向你索要只有用户才能提供的东西。在做任何下一步分析之前，",
					"必须先调用 ask_user_question 把它们原样问给用户，并把回答（有/没有）记进账本。",
					...(qs.length ? qs.map((q: string, i: number) => `${i + 1}. ${q}`) : ["（问句见上面的 need_from_user）"]),
					"用户答「没有」才走 if_no 路线；不许假设「没有」继续往下做。",
				];
				askNote = { type: "text", text: NL + parts.join(NL) };
			}
		} catch {
			askNote = null;
		}

		history.unshift({
			at: new Date().toISOString().slice(11, 19),
			toolName: r.shell,
			head: head(r.command, 60),
			seconds: secs,
			verdict,
		});
		if (history.length > 20) history.length = 20;

		if (secs >= config.stallSeconds) {
			history[0].verdict += "（已过卡死阈值）";
		}

		if (r.notes.length) {
			// 返回 content 才是官方改法；顺带把 structuredContent 带回去，否则会被丢
			const line: TextContent = {
				type: "text",
				text:
					`\n[cmd-guard 提示 · ${secs}s · ${verdict}]\n` +
					r.notes.map((n) => `- ${n}`).join("\n") +
					(r.injected.length ? `\n（已自动注入：${r.injected.join("；")}）` : ""),
			};
			if (Array.isArray(event.content)) {
				return {
					content: askNote ? [...event.content, line, askNote] : [...event.content, line],
					details: event.details,
					structuredContent: event.structuredContent,
				};
			}
		}
		if (askNote && Array.isArray(event.content)) {
			return {
				content: [...event.content, askNote],
				details: event.details,
				structuredContent: event.structuredContent,
			};
		}
		return;
	});

	pi.on("agent_end", (_e: unknown, ctx: any) => {
		remember(ctx);
		running.clear();
		stopTicker();
		renderStatus();
	});

	pi.on("session_shutdown", () => {
		stopTicker();
	});

	/* ── /stall ── */
	pi.registerCommand("stall", {
		description: "命令执行健康报告：当前在跑什么、卡多久、注入了什么、被拦过什么",
		handler: async (_arg: string, ctx: any) => {
			remember(ctx);
			loadConfig(true);
			const L: string[] = [];
			L.push("⛨ cmd-guard 状态");
			L.push(running.size ? "── 正在执行 ──" : "── 当前无命令在执行 ──");
			for (const r of running.values()) {
				const total = Date.now() - r.startedAt;
				const silent = Date.now() - r.lastOutputAt;
				L.push(
					`  ${r.shell}  已 ${fmtSec(total)}  静默 ${fmtSec(silent)}  timeout=${r.ownTimeout ?? "无"}` +
						`${total >= config.stallSeconds ? "  ✖ 已过卡死阈值" : silent >= config.noOutputStallSeconds ? "  ◐ 长时间无输出" : ""}`,
				);
				L.push(`    ${head(r.command, 90)}`);
				if (r.injected.length) L.push(`    已注入：${r.injected.join("；")}`);
			}
			L.push(
				`── 本会话 ──  守卫 ${stats.guarded} 次，注入 ${stats.injected} 条，拦下 ${stats.blocked} 次`,
			);
			L.push(
				`  卡死阈值 ${config.stallSeconds}s / 静默阈值 ${config.noOutputStallSeconds}s / 默认 timeout ${config.defaultTimeout}s`,
			);
			L.push(`  GUI 规则 ${[...guiTable.values()].filter((v) => v !== null).length} 条，规则源=${rulesSource}`);
			if (blocked.length) {
				L.push("── 被拦下 ──");
				for (const b of blocked.slice(0, 5)) L.push(`  ${b.at}  ${b.cmd}\n    ${b.reason}`);
			}
			if (history.length) {
				L.push("── 最近执行 ──");
				for (const h of history.slice(0, 8)) L.push(`  ${h.at}  ${String(h.seconds).padStart(5)}s  ${h.verdict}  ${h.toolName}  ${h.head}`);
			}
			L.push("── 处置处方 ──");
			L.push("  卡在 ssh/scp   → 对方是否在等输入？IP 是否写错？先 `ssh -n -o ConnectTimeout=5 <ip> echo ok` 单验连通。");
			L.push("  卡在 vmrun     → 快照写盘慢或锁争用。改后台 `start /b vmrun ... >log 2>&1` 后轮询 `*.vmsn`。");
			L.push("  卡在 GUI 二进制 → 已物理拦下，按拦截理由里的 CLI 替代走。");
			L.push("  卡在 find/grep  → 递归范围太大，收窄到子目录或加 `-maxdepth`。");
			L.push("  卡在 npx/npm    → 首次拉包或版本解析，加 timeout 并看包管理器缓存锁。");
			L.push("  计时器在涨 + token 不动 = 卡在命令（不在推理）→ 中断换路线，发「继续」；这种中断不会自愈。");
			ctx?.ui?.notify?.(L.join("\n"), running.size ? "warning" : "info");
		},
	});

	/* ── /guard on|off|reload|rules ── */
	pi.registerCommand("guard", {
		description: "命令守卫开关：/guard off 关掉注入与拦截，/guard on 恢复，/guard reload 重读文档，/guard rules 看派生出的 GUI 名单",
		handler: async (arg: string, ctx: any) => {
			remember(ctx);
			const a = (arg || "").trim().toLowerCase();
			if (a === "off") enabled = false;
			else if (a === "on") enabled = true;
			else if (a === "reload") {
				loadConfig(true);
				loadedStamp = "0";
			} else if (a === "rules") {
				const rows = [...guiTable.entries()].sort();
				const L = rows.map(([k, v]) => (v === null ? `  ${k}  —— 明确不拦` : `  ${k}  →  ${v}`));
				L.unshift(`GUI 名单 ${rows.length} 条（${rulesSource}）`);
				ctx?.ui?.notify?.(L.join("\n"), "info");
				return;
			}
			const msg =
				`cmd-guard ${enabled ? "启用" : "停用"}｜GUI 规则 ${[...guiTable.values()].filter((v) => v !== null).length} 条` +
				`（规则源=${rulesSource}）｜timeout ${config.probeTimeout}/${config.analysisTimeout || config.defaultTimeout}/${config.heavyTimeout}s` +
				`｜卡死阈值 ${config.stallSeconds}s｜enforce=${config.enforce} blockGui=${config.blockGui} blockRootScan=${config.blockRootScan}` +
				`｜规则文件 ${fileExists(rulesPath()) ? rulesPath() : "（未建，用内置默认）"}`;
			ctx?.ui?.notify?.(msg, enabled ? "info" : "warning");
		},
	});
}
