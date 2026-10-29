/** 当前案目标身份与数据边界诊断。授权由会话和宿主处理；历史首答和回执不构成全局授权。 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/* ────────────────────────────── 常量 ────────────────────────────── */

/** 历史不可覆盖禁写名单已退役；隐私读取保护另行保留。 */
export const NEVER_WRITABLE: string[] = [];

/** 兼容旧配置形状；回执配置不裁决当前动作。 */
export const RUN_ACK_TTL_MINUTES = 60;

/** 运行目标闸的配置（`gate.run_ack`）。 */
export type RunAckConfig = {
	/** 回执有效期（分钟）。 */
	ttlMinutes: number;
	/** 回执带 case 时，是否要求本次命令里的目标路径落在该案 case.json 的目标下。 */
	requireCaseTarget: boolean;
};

/** 闸的配置形状（answer-contract.json 的 `gate` 块是唯一来源）。 */
export type GateConfig = {
	/** 历史配置，保留结构兼容。 */
	ttlMinutes: number;
	/** 永远放行的只读分诊工具（小写、不带 `mcp__seep__` 前缀）。 */
	whitelist: string[];
	/** 历史目标绑定配置，诊断不依赖此开关。 */
	bindTarget: boolean;
	/** 运行目标闸（P0-4）。 */
	runAck: RunAckConfig;
	/** 旧工具分类配置，仅作兼容。 */
	execTools: string[];
	/** 旧禁写配置不再实施。 */
	neverWritable: string[];
};

/** 读不到 / 读坏 `gate` 块时的兜底（与 answer-contract.json 保持同值，改一处要改两处）。 */
export const DEFAULT_GATE: GateConfig = {
	ttlMinutes: 60,
	// 历史分类配置保留兼容，不裁决用户授权。
	whitelist: ["seep_kb_search", "seep_kb_read", "seep_case_read", "seep_tool_discover", "seep_r2_info"],
	bindTarget: true,
	runAck: { ttlMinutes: RUN_ACK_TTL_MINUTES, requireCaseTarget: true },
	execTools: ["seep_r2_cmd"],
	neverWritable: NEVER_WRITABLE.slice(),
};

/** 只读工具集合也用于保留个人隐私读取保护。 */
const READONLY_TOOLS = new Set([
	"read",
	"grep",
	"find",
	"ls",
	"todo",
	"web_search",
	"web_fetch",
	"glob",
	"view",
]);

/** 只读程序：命中分析类关键词但程序本身是「看」的，按读取处理（防误伤文档检索）。
 *  注意：`file` / `strings` **不在**这里 —— 它们直接对着目标二进制取值，属于分析类（第 2 轮补洞）。 */
const READONLY_PROGS = new Set([
	"grep",
	"egrep",
	"fgrep",
	"rg",
	"ag",
	"find",
	"findstr",
	"select-string",
	"get-content",
	"get-childitem",
	"get-item",
	"get-filehash",
	"test-path",
	"resolve-path",
	"ls",
	"dir",
	"cat",
	"type",
	"head",
	"tail",
	"less",
	"more",
	"wc",
	"sed",
	"awk",
	"sort",
	"uniq",
	"cut",
	"tr",
	"echo",
	"printf",
	"diff",
	"cmp",
	"stat",
	"which",
	"where",
	"pwd",
	"git",
	// 只改「当前目录 / 建个空目录」，自己动不了任何分析：`cd Tool/skill/ && cat SKILL.md` 读技能不能被拦
	"cd",
	"pushd",
	"popd",
	"set-location",
	"sl",
	"mkdir",
]);

/** 命令级放行（闸的出路必须随时可达；写宽了会假绿，所以只认这几条确切的子命令）。 */
const CMD_ALLOW: RegExp[] = [
	/case_state\.py\s+answer\b/i,
	// `init` 只建案件目录 / 写 pointer，不读目标内容、不跑任何分析工具 → 必须放行，
	// 否则「先 init 建案 → 再 answer --check」这条官方顺序在第一步就被自己的闸拦住（R6 P1-1）。
	// `claim|prove|repro|deliver` 仍在下面的 CMD_ANALYSIS 里，不许跟着放行。
	/case_state\.py\s+init\b/i,
	/case_state\.py\s+--help\b/i,
	/case_state\.py\s+-h\b/i,
	/Tool\/scripts\/(preflight|check|gate|route)\.py\b/i,
	// 技能脚本的**自检**：`python Tool/skill/<skill>/scripts/<x>.py --self-test` 是体检不是分析
	/python[0-9.]*\s+["']?[^\s"']*Tool\/skill\/[^\s"']*\/scripts\/[^\s"']+\.py["']?\s+[^\n]*?(--self-test|--help|-h)\b/i,
];

/** 已改写成 Windows 反斜杠或带盘符的写法也要认，所以比较前先归一化分隔符。 */
function normalizeCmd(raw: string): string {
	return raw.replace(/\\/g, "/");
}

/** 分析类关键词（只在 shell 命令里找；命中即说明这一句在动工具，不是在说话）。 */
type CmdPattern = { re: RegExp; why: string };

const CMD_ANALYSIS: CmdPattern[] = [
	// ★★★ DO-NOT-RE-ADD 锁：这里只留"改动案子账本"这一类（那会写入结论）。
	//     所有工具调用（x64dbg/IDA/Ghidra/r2/rabin2/jadx/apktool/frida/tshark/objdump/readelf/
	//     strings/binwalk/7z/unzip/upx/xxd/nmap/file/curl/wget/nc、tool-run.ps1、launch-gui.ps1、
	//     mcp-launch.py、技能脚本、全部 MCP 工具）都不算分析动作，不需要首答。
	{ re: /case_state[.]py\s+(?:claim|prove|repro|deliver)(?![A-Za-z0-9_-])/i, why: "案子写账（会写入账本）" },
];

/** 解释器内联执行：`python -c` / `python - <<'PY'` / `powershell -c` / `node -e` … */
const INLINE_EXEC =
	/(^|[^A-Za-z0-9_.-])(python[0-9.]*|py|pwsh|powershell|node|perl|ruby|php)(?=$|[^A-Za-z0-9_.-])[^\n;&|]*?\s(?:-c\b|-e\b|--command\b|-\s*<<)/i;

/** 内联体里出现这些 → 才算「在动分析工具 / 在联网」，否则 `python -c "print(1)"` 不拦。
 *  R7 P0-4：把新加的分析工具也纳进来（只加严）：`python -c "import binwalk"` 同样是分析动作。 */
const INLINE_SUSPECT =
	/(^|[^A-Za-z0-9_.-])(rabin2|objdump|readelf|strings|binwalk|7z|7za|unzip|upx|tshark|xxd|nmap|file|curl|wget|ncat|nc|socket|requests|urllib|httpx?)(?=$|[^A-Za-z0-9_.-])/i;

/* ─────────────────── 运行目标闸的判据（第 3 轮 P0-4）─────────────────── */

/** 启动器程序：这些程序后面跟的 `.exe` 是**被执行**的目标，不是文档里的字。 */
const LAUNCHER_PROGS = new Set([
	"start-process",
	"saps",
	"start",
	"call",
	"explorer",
	"invoke-item",
	"ii",
	"cmd",
	"rundll32",
	"shelexecute",
	"wine",
	"wine64",
]);

/** 运行目标的直接特征：「这句命令要把客户的东西拉起来」。 */
const RUN_TRIGGERS: CmdPattern[] = [
	// ★★★ DO-NOT-RE-ADD：这里不再列 launch-gui.ps1 / Start-Process / wine / & "D:/..." 等
	//     "用工具"的动作 —— 启动我们自己的工具一律静默。
	//     分类只用于描述动作，不裁决授权。
];

/** `.exe` 作为 token 出现（前后是空白/引号/`-`/括号/`;|&` 这类边界）。 */
const EXE_TOKEN = /(^|[\s"'`(\[=&;|])[^\s"'`|&;]*\.exe(?=$|[\s"'`)\]),;|&])/i;

/* ───────────────────────────── 纯函数层 ───────────────────────────── */

/** 把未知宿主对象窄化成可索引的记录（不用 any 糊过去）。 */
function asRecord(v: unknown): Record<string, unknown> {
	return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
}

function asText(v: unknown): string {
	return typeof v === "string" ? v : "";
}

/** 从契约对象里读 `gate` 块（唯一来源）；缺字段就逐项回落到 DEFAULT_GATE。 */
export function parseGate(raw: unknown): GateConfig {
	const g = asRecord(asRecord(raw).gate);
	const ttl = Number(g.ttl_minutes);
	const wl = Array.isArray(g.whitelist)
		? g.whitelist.filter((x): x is string => typeof x === "string").map((s) => s.trim().toLowerCase()).filter(Boolean)
		: [];
	const ra = asRecord(g.run_ack);
	const raTtl = Number(ra.ttl_minutes);
	const execTools = Array.isArray(g.exec_tools)
		? g.exec_tools.filter((x): x is string => typeof x === "string").map((s) => s.trim().toLowerCase()).filter(Boolean)
		: [];
	return {
		ttlMinutes: Number.isFinite(ttl) && ttl > 0 ? ttl : DEFAULT_GATE.ttlMinutes,
		whitelist: wl.length > 0 ? wl : DEFAULT_GATE.whitelist.slice(),
		bindTarget: typeof g.bind_target === "boolean" ? g.bind_target : DEFAULT_GATE.bindTarget,
		runAck: {
			ttlMinutes: Number.isFinite(raTtl) && raTtl > 0 ? raTtl : DEFAULT_GATE.runAck.ttlMinutes,
			requireCaseTarget:
				typeof ra.require_case_target === "boolean" ? ra.require_case_target : DEFAULT_GATE.runAck.requireCaseTarget,
		},
		execTools: execTools.length > 0 ? execTools : DEFAULT_GATE.execTools.slice(),
		// 不执行历史不可覆盖禁写名单。
		neverWritable: [],
	};
}

/**
 * 属于「分析类」的工具名（第 4 轮 P0-3）：`seep_*` 或**任意** `mcp__<server>__*`。
 * 只认 `seep_*` 时，`mcp__x64dbg__load_binary` / `mcp__ida__decompile` 可以绕开首答直接开工。
 */
function isAnalysisToolName(name: string): boolean {
	// ★★★ DO-NOT-RE-ADD 锁（用户 2026-10-26 裁定）：所有 MCP 工具都是"我们自己的工具"，
	//     用它们不需要首答 / 回执 / A-B-C。永远返回 false。
	//     要改成"算分析动作"，必须先让用户改文件头那条锁。
	void name;
	return false;
}

/** `mcp__seep__seep_auto_triage` → `seep_auto_triage`（白名单按裸名比对）。 */
function bareToolName(name: string): string {
	const n = name.toLowerCase();
	return n.startsWith("mcp__seep__") ? n.slice("mcp__seep__".length) : n;
}

/**
 * 白名单比对（第 4 轮 P0-4）：契约里写裸名（`seep_kb_search`）或全名
 * （`mcp__seep__seep_kb_search`）都认；其它服务（`mcp__x64dbg__*`）永远不是白名单。
 */
export function isWhitelistedTool(name: string, gate: GateConfig = DEFAULT_GATE): boolean {
	const n = name.trim().toLowerCase();
	if (!n) return false;
	const bare = bareToolName(n);
	return gate.whitelist.includes(n) || gate.whitelist.includes(bare) || gate.whitelist.includes("mcp__seep__" + bare);
}

/** 取一段命令里的「第一个 token」（跳过 `VAR=value` 前缀、去掉引号）；用于判「这一句到底在跑什么」。 */
function firstToken(segment: string): string {
	let s = segment.trim().replace(/^[("'`]+/, "");
	for (let i = 0; i < 3; i++) {
		const m = s.match(/^[A-Za-z_][A-Za-z0-9_]*=[^\s]*\s+/);
		if (!m) break;
		s = s.slice(m[0].length);
	}
	return (s.split(/\s+/)[0] || "").replace(/^["'`]+|["'`]+$/g, "");
}

/** 取一段命令里的「程序名」：取 basename 并去掉 .exe 后缀（小写）。 */
function programOf(segment: string): string {
	const first = firstToken(segment);
	const base = first.split(/[\\/]/).pop() || first;
	return base.replace(/\.(exe|cmd|bat)$/i, "").toLowerCase();
}

/**
 * 按 `&& || ; | 换行` 切段：一段只放行自己，别让 `preflight && frida ...` 沾光。
 *
 * 引号内的分隔符不是分隔符（`grep -rn "nmap|7z|xxd" Tool/` 是在搜这几个词，不是在跑 7z）。
 * 这个切分只可能把片段**变长**（合并），不可能变短 —— 所以不会因为这条路放过任何真命令：
 * 真正的管子（`grep x | nmap`）依旧切得开，`bash -c "nmap x"` 仍整段带着 nmap 字面量。
 */
function splitSegments(cmd: string): string[] {
	const out: string[] = [];
	let cur = "";
	let quote: string | null = null;
	for (let i = 0; i < cmd.length; i++) {
		const ch = cmd[i];
		if (quote) {
			cur += ch;
			if (ch === quote) quote = null;
			continue;
		}
		if (ch === '"' || ch === "'" || ch === "`") {
			quote = ch;
			cur += ch;
			continue;
		}
		const two = ch + (cmd[i + 1] ?? "");
		if (two === "&&" || two === "||") {
			out.push(cur);
			cur = "";
			i++;
			continue;
		}
		if (ch === "&" || ch === "|" || ch === ";" || ch === "\n") {
			out.push(cur);
			cur = "";
			continue;
		}
		cur += ch;
	}
	out.push(cur);
	return out.map((s) => s.trim()).filter((s) => s.length > 0);
}

/**
 * heredoc 数据区按文本算，不按命令算（与 cmd-guard 的既有判据一致）。
 * 实例：用 `cat > notes.md <<'EOF'` 往文档里写一段带 `frida -U` 的 SOP，
 * 那是**写文档**，不是要启动 frida；不豁免就会变成「写文档被自己的门禁挡住」。
 * 只豁免「带 > / >> 重定向到文件」的 heredoc：`python - <<'PY'` 里的正文是真代码，不剥。
 */
function stripQuotedHeredoc(cmd: string): string {
	const keep: string[] = [];
	let stop: string | null = null;
	for (const ln of cmd.split("\n")) {
		if (stop) {
			if (ln.trim() === stop) stop = null;
			continue; // 数据区整行跳过
		}
		keep.push(ln);
		const m = ln.match(/<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?/);
		if (m && />>?\s*\S+/.test(ln)) stop = m[1];
	}
	return keep.join("\n");
}

/** 解释器内联执行判定（在「已剥掉写文件 heredoc」的文本上跑，避免误伤写文档）。 */
export function classifyInlineExecution(text: string): { analysis: boolean; why: string } {
	const m = text.match(INLINE_EXEC);
	if (!m) return { analysis: false, why: "" };
	const hit = text.match(INLINE_SUSPECT);
	if (!hit) return { analysis: false, why: "" };
	return {
		analysis: true,
		why: "解释器内联执行（" + m[2].toLowerCase() + " …）：命令体里出现「" + hit[0].trim() + "」",
	};
}

/** 单段命令 → 是否分析类 + 命中的是什么（用于 block 文案里说清"我在拦哪一句"）。 */
export function classifySegment(segment: string): { analysis: boolean; why: string } {
	const seg = normalizeCmd(segment);
	// 1) 放行命令（answer / --help / preflight|check|gate|route / 技能脚本 --self-test）：这一段整体不看
	if (CMD_ALLOW.some((re) => re.test(seg))) return { analysis: false, why: "" };
	// 2) 只要是不是「看」的程序（grep/cat/Get-Content…），命中关键词也当读取
	if (READONLY_PROGS.has(programOf(segment))) return { analysis: false, why: "" };
	// 3) `xxx --help` 是在问用法，不是在跑分析
	if (/(^|\s)(--help|-h|\/\?)\s*$/.test(seg)) return { analysis: false, why: "" };
	for (const p of CMD_ANALYSIS) {
		const m = seg.match(p.re);
		if (m) return { analysis: true, why: p.why + "（命中「" + m[0].trim() + "」）" };
	}
	return { analysis: false, why: "" };
}

/** 判定一次工具调用是否属于「分析类」（不看标记，只看这次要干什么）。 */
export function classifyTool(
	toolName: string,
	args: unknown,
	gate: GateConfig = DEFAULT_GATE,
): { analysis: boolean; why: string } {
	const name = toolName.trim();
	if (!name) return { analysis: false, why: "" };
	const lname = name.toLowerCase();
	// 读类工具优先放行：拦它们等于把工作台锁死（评审明确警告过这一条）
	if (READONLY_TOOLS.has(lname)) return { analysis: false, why: "" };
	if (isAnalysisToolName(lname)) {
		// 第 2 轮批评①：只读分诊是首答的取证手段，永远放行（名单见 gate.whitelist）
		if (isWhitelistedTool(lname, gate)) return { analysis: false, why: "" };
		// 兼容旧分类字段；此分类不裁决授权。
		if (gate.execTools.includes(bareToolName(lname))) {
			return { analysis: true, why: "可执行分析工具 " + name + "（工具动作）" };
		}
		return { analysis: true, why: "MCP 分析工具 " + name };
	}
	if (lname !== "bash" && lname !== "powershell") return { analysis: false, why: "" };
	const a = asRecord(args);
	const cmd = asText(a.command ?? a.cmd ?? "");
	if (!cmd.trim()) return { analysis: false, why: "" };
	const visible = stripQuotedHeredoc(normalizeCmd(cmd));
	for (const seg of splitSegments(visible)) {
		const v = classifySegment(seg);
		if (v.analysis) return { analysis: true, why: v.why };
	}
	// 第 2 轮批评②：`python -c ...` / `python - <<'PY' ...` / `powershell -c ...`
	const inline = classifyInlineExecution(visible);
	if (inline.analysis) return inline;
	return { analysis: false, why: "" };
}

/** 某案登记过的目标（`case.json` 的 `target_files[].path` 与 `target`/`target_path`/`target_type`）。 */
export type CaseTargets = {
	dir: string;
	paths: string[];
	targetSha256: string;
	files?: { path: string; sha256: string }[];
};

const PATHLIKE_EXT =
	/\.(exe|dll|sys|apk|dex|so|elf|bin|img|iso|zip|7z|rar|tar|gz|xz|py|js|ts|json|md|txt|log|pcap|dmp|dat|jar|aar|crx|xpi|vhd|vmdk)$/i;

function cleanToken(tok: string): string {
	return tok.replace(/^["'`(\[]+/, "").replace(/["'`)\],;:]+$/, "");
}

function looksLikePath(tok: string): boolean {
	const t = cleanToken(tok);
	if (!t || t.length < 2) return false;
	if (/^https?:\/\//i.test(t)) return false; // URL 不当目标文件路径处理（避免 curl 一律误判换目标）
	// 带 shell 元字符的碎片（`subprocess.run(['a.exe` 这种）不是路径：
	// 否则 `python -c "import subprocess;subprocess.run(['a.exe'])"` 会被当成「换了个目标」误拦
	if (/[;'"`$<>|{}]/.test(t)) return false;
	if (/^[A-Za-z]:[\\/]/.test(t)) return true;
	if (t.indexOf("/") >= 0 || t.indexOf("\\") >= 0) return true;
	return PATHLIKE_EXT.test(t);
}

/** 从一次工具调用里抠出「可能是目标文件」的路径（纯字符串处理，不碰磁盘）。 */
export function extractPaths(toolName: string, args: unknown): string[] {
	const lname = toolName.trim().toLowerCase();
	const a = asRecord(args);
	const out: string[] = [];
	if (lname === "bash" || lname === "powershell") {
		const cmd = stripQuotedHeredoc(normalizeCmd(asText(a.command ?? a.cmd ?? "")));
		const tokens = cmd.match(/"[^"\n]*"|'[^'\n]*'|[^\s]+/g) || [];
		for (const token of tokens) {
			const inner = cleanToken(token);
			// `--cmd "python helper.py --input ..."` 是嵌套命令，不是一个含空格的路径。
			const parts = /^["']/.test(token) && /^(?:python(?:\d+(?:\.\d+)?)?|py|node)(?:\.exe)?\s/i.test(inner)
				? (inner.match(/"[^"\n]*"|'[^'\n]*'|[^\s]+/g) || []) : [token];
			for (const tok of parts) {
				for (const part of tok.split("=")) {
					if (part && looksLikePath(part)) out.push(cleanToken(part));
				}
			}
		}
	} else {
		const keys = [
			"path",
			"file_path",
			"filePath",
			"file",
			"binary_path",
			"target",
			"target_path",
			"cwd",
			"dir",
			"input",
			"src",
			"source",
			"sample",
		];
		for (const k of keys) {
			const v = asText(a[k]).trim();
			if (v && looksLikePath(v)) out.push(cleanToken(v));
		}
		if (out.length === 0) {
			for (const v of Object.keys(a).map((k) => a[k])) {
				const s = asText(v).trim();
				if (s && looksLikePath(s) && !/\s/.test(s)) out.push(cleanToken(s));
			}
		}
	}
	const seen = new Set<string>();
	const uniq: string[] = [];
	for (const p of out) {
		const k = cmpKey(p);
		if (!k || seen.has(k)) continue;
		seen.add(k);
		uniq.push(p);
	}
	return uniq;
}

function normPath(p: string): string {
	let s = p.trim().replace(/\\/g, "/").replace(/\/{2,}/g, "/").replace(/\/+$/, "");
	if (/^[A-Za-z]:/.test(s)) s = s.charAt(0).toLowerCase() + s.slice(1);
	return s;
}

/** 比较键：Windows 盘符路径整串小写（NTFS 不区分大小写），其余按原样。 */
function cmpKey(p: string): string {
	const n = normPath(p);
	return /^[a-z]:\//.test(n) ? n.toLowerCase() : n;
}

function under(child: string, parent: string): boolean {
	const c = cmpKey(child);
	const p = cmpKey(parent);
	if (!c || !p) return false;
	return c === p || c.indexOf(p + "/") === 0;
}

/** 当前案登记目标的内容哈希缓存。 */
const _shaCache = new Map<string, { key: string; sha: string }>();

/** 目标文件的内容哈希；读不了返回空串。 */
export function fileSha256(p: string): string {
	try {
		const st = fs.statSync(p);
		if (!st.isFile()) return "";
		// 缓存键必须含 inode 与 ctime：只看 size+mtime 时，"同长度替换内容 + 保留 mtime"
		// 会命中旧缓存，于是换目标检查被绕过（测试 A8 的第一版 fixture 就是这么绕过去的）。
		const key = [String(st.size), String(st.mtimeMs), String(st.ctimeMs), String(st.ino ?? 0)].join(":");
		const hit = _shaCache.get(p);
		if (hit && hit.key === key) return hit.sha;
		const sha = createHash("sha256").update(fs.readFileSync(p)).digest("hex");
		_shaCache.set(p, { key, sha });
		return sha;
	} catch {
		return "";
	}
}

export function targetMismatch(
	toolName: string,
	args: unknown,
	marker: unknown,
	caseTargets: CaseTargets | null,
): string {
	if (!caseTargets) return "";
	const dir = path.resolve(caseTargets.dir);
	const targets = caseTargets.paths.map((p) => path.resolve(dir, p));
	// 核对登记目标本身，不能拿命令中的工具脚本/输出哈希冒充目标哈希。
	// 即使目标只由 --case 间接引用，也可诊断内容是否与当前案登记一致。
	const mt = (caseTargets.targetSha256 || caseTargets.files?.[0]?.sha256 || "").trim().toLowerCase();
	const matches = (a: string, b: string) => {
		const n = Math.min(a.length, b.length);
		return n >= 12 && a.slice(0, n) === b.slice(0, n);
	};
	const files = caseTargets.files?.length
		? caseTargets.files
		: targets.slice(0, 1).map((p) => ({ path: p, sha256: caseTargets.targetSha256 || mt }));
	if (mt.length >= 12 && files.length > 0) {
		if (!matches(files[0].sha256.toLowerCase(), mt)) return "目标内容已变或登记已变，请核对当前案登记";
		for (const file of files) {
			const actual = fileSha256(path.resolve(dir, file.path));
			if (!actual) return "登记目标不可读：请核对原件位置";
			if (!matches(actual, file.sha256.toLowerCase())) {
				return "目标内容已变（与当前案登记的哈希不同），请核对原件";
			}
		}
	}
	const explicit = asRecord(args);
	for (const key of ["target", "target_path", "binary_path", "sample"]) {
		const value = asText(explicit[key]).trim();
		if (!value || !looksLikePath(value)) continue;
		const abs = path.resolve(value);
		if (!under(abs, dir) && !targets.some((target) => under(abs, target))) {
			return "指定目标路径（" + value + "）不在当前案登记中，请核对目标身份";
		}
	}
	const paths = extractPaths(toolName, args);
	// 解释器后的脚本是执行工具；--out/--output 是产物位置。它们不能作为目标哈希候选。
	// 逐个检查剩余输入，不能因同时带有一个正确目标就放过另一个未登记目标。
	const support = new Set<string>();
	const command = asText(asRecord(args).command ?? asRecord(args).cmd ?? "");
	const token = '("[^"\\n]+"|\'[^\'\\n]+\'|[^\\s"\']+)';
	const script = new RegExp('(?:^|[\\s"\';|&])(?:python(?:3(?:\\.\\d+)?)?|py|node)(?:\\.exe)?\\s+(?:(?:-B|-u|-X\\s+utf8)\\s+)*' + token, 'gi');
	const output = new RegExp('(?:^|\\s)--(?:out|output)\\s+' + token, 'g');
	for (const re of [script, output]) {
		for (const match of command.matchAll(re)) {
			const p = cleanToken(match[1]);
			if (looksLikePath(p)) support.add(cmpKey(path.resolve(p)));
		}
	}
	const foreign = paths.filter((p) => {
		const abs = path.resolve(p);
		return !under(abs, dir) && !targets.some((t) => under(abs, t) || cmpKey(abs) === cmpKey(path.dirname(t)))
			&& !support.has(cmpKey(abs));
	});
	return foreign.length === 0 ? "" : "本次参数里的路径（" + foreign.slice(0, 2).join(" / ") + "）不在该案 case.json 的 target_files/target 下";
}

/** 个人隐私区：读类工具（read/grep/find/ls）只在这些路径上直接拦下。
 *  ★ 为什么需要（R8 P1-5）："别乱翻我东西"原来只有提示词，读类工具不限目录。
 *  用"窄黑名单"而不是白名单：白名单会误伤客户放在任意目录的目标文件。
 */
const SENSITIVE_PATH_RE =
	/(^|[\\/])(\.ssh|\.aws|\.gnupg|\.netrc|\.git-credentials|\.config[\\/]gh|Cookies|Login Data|keychain|credentials|passwords?|id_rsa|id_ed25519|Web Data|Local State)([\\/.]|$)/i;

function _allStrings(v: unknown, out: string[] = [], depth = 0): string[] {
	if (depth > 6 || out.length > 400) return out;
	if (typeof v === "string") {
		out.push(v);
		return out;
	}
	if (Array.isArray(v)) {
		for (const x of v) _allStrings(x, out, depth + 1);
		return out;
	}
	if (v && typeof v === "object") {
		for (const k of Object.keys(v as Record<string, unknown>)) {
			_allStrings((v as Record<string, unknown>)[k], out, depth + 1);
		}
	}
	return out;
}

export function sensitivePathHit(args: unknown): string {
	for (const s of _allStrings(args)) {
		if (SENSITIVE_PATH_RE.test(s)) return s.length > 120 ? s.slice(0, 120) + "..." : s;
	}
	return "";
}

/** 兼容原调用签名；目标诊断取调用方明确提供的当前案，不用旧首答。 */
export function shouldBlock(
 toolName: string, args: unknown, _marker: unknown, _contractHash: string, _now: number,
 gate: GateConfig = DEFAULT_GATE, caseTargets: CaseTargets | null = null,
): { block: boolean; reason: string; analysis: boolean } {
 const cls = classifyTool(toolName, args, gate);
 const reason = caseTargets ? targetMismatch(toolName, args, null, caseTargets) : "";
 return { block: false, reason, analysis: cls.analysis };
}

/* ─────────────────── 运行目标闸（纯函数层，第 3 轮 P0-4）─────────────────── */

/**
 * 单段命令 → 是不是「要把目标拉起来跑」。
 * 关键区分：**看文件**（ls *.exe / find -name *.exe / grep .exe README）不拦，
 *           **执行文件**（./a.exe / Start-Process a.exe / cmd /c a.exe / wine a.exe）分类为运行。
 */
export function classifyRunSegment(segment: string): { run: boolean; why: string } {
	const seg = normalizeCmd(segment);
	if (!seg.trim()) return { run: false, why: "" };
	// 工作台自检命令（answer / preflight / check / gate / route / 技能脚本自检）不执行目标
	if (CMD_ALLOW.some((re) => re.test(seg))) return { run: false, why: "" };
	const prog = programOf(segment);
	// 只读程序（ls / find / grep / cat / Get-Content…）：列个 *.exe 不算运行，不拦（禁止项）
	if (READONLY_PROGS.has(prog)) return { run: false, why: "" };
	for (const p of RUN_TRIGGERS) {
		const m = seg.match(p.re);
		if (m) return { run: true, why: p.why + "（命中「" + m[0].trim() + "」）" };
	}
	// 启动器程序（cmd /c、start、explorer、invoke-item…）+ 命令里任意 `.exe` token：
	// 先于「程序位」判：`explorer.exe a.exe` 要报「启动器 explorer 拉起 .exe」，不是「执行 explorer.exe」
	if (LAUNCHER_PROGS.has(prog) && EXE_TOKEN.test(seg)) {
		return { run: true, why: "启动器 " + prog + " 拉起 .exe" };
	}
	// `.exe` 在程序位（第一个 token）：`./a.exe` / `"<盘>:/tools/a.exe" -k` / `a.exe`
	const head = firstToken(segment);
	if (/\.exe$/i.test(head)) return { run: true, why: "直接把 .exe 当程序执行（" + head + "）" };
	// 内联执行里再拉进程：`python -c "subprocess.run(['a.exe'])"`、`powershell -c "& .\\a.exe"`
	const inline = seg.match(INLINE_EXEC);
	if (inline && /\.exe(?=$|[\s"'`)\]])|subprocess|popen|os\.system|startfile|child_process|spawn/i.test(seg)) {
		return { run: true, why: "解释器内联执行里拉起进程（" + inline[2].toLowerCase() + " …）" };
	}
	// `bash -c "./a.exe"` / `sh -c 'a.exe -k'`：把 -c 后面那段当子命令再判一次
	const sub = segment.match(/(^|[\s;&|])(?:ba|z|da)?sh\s+-c\s+["']?(.+?)["']?\s*$/i);
	if (sub && sub[2]) {
		const inner = classifyRunSegment(sub[2]);
		if (inner.run) return { run: true, why: "shell -c 子命令 → " + inner.why };
	}
	return { run: false, why: "" };
}

/** 判定一次工具调用是不是「要运行目标程序」（不看回执，只看工具名/命令文本）。 */
export function classifyRunTarget(toolName: string, args: unknown, gate: GateConfig = DEFAULT_GATE): { run: boolean; why: string } {
	const name = toolName.trim();
	const lname = name.toLowerCase();
	if (lname !== "bash" && lname !== "powershell") return { run: false, why: "" };
	const a = asRecord(args);
	const cmd = asText(a.command ?? a.cmd ?? "");
	if (!cmd.trim()) return { run: false, why: "" };
	const visible = stripQuotedHeredoc(normalizeCmd(cmd));
	for (const seg of splitSegments(visible)) {
		const v = classifyRunSegment(seg);
		if (v.run) return v;
	}
	return { run: false, why: "" };
}

/** 参数匹配登记目标，包括案外登记的绝对路径；不是执行动作判断。 */
export function touchesCaseTarget(args: unknown, caseTargets: CaseTargets | null): boolean {
 if (!caseTargets) return false;
 const dir = path.resolve(caseTargets.dir);
 const targets = caseTargets.paths.map(p => path.resolve(dir, p));
 const paths = [...extractPaths("bash", args), ...extractPaths("input", args)];
 return paths.some(p => {
  const abs = path.resolve(p);
  return under(abs, path.resolve(dir, "target")) || targets.some(t => under(abs, t));
 });
}

/** 兼容调用签名：旧回执不会决定当前动作。 */
export function shouldBlockRun(
 toolName: string, args: unknown, _runAck: unknown, _now: number,
 gate: GateConfig = DEFAULT_GATE, caseTargets: CaseTargets | null = null, _caseHint = "",
): { block: boolean; reason: string; run: boolean } {
 const run = classifyRunTarget(toolName, args, gate).run;
 const reason = caseTargets ? targetMismatch(toolName, args, null, caseTargets) : "";
 return { block: false, reason, run };
}

/* ─────────────────────────── 写入守卫（纯函数层） ─────────────────────────── */

/**
 * 写类工具名。读类工具一律不在这里 —— 守卫只管「往哪写」。
 */
const WRITE_TOOLS = new Set([
	"write",
	"edit",
	"apply_patch",
	"patch",
	"multiedit",
	"create_file",
	"str_replace_editor",
]);

/** write/edit 的路径参数名（宿主实现不一致，逐个认）。 */
export function writeTargetPath(args: unknown): string {
	const a = asRecord(args);
	for (const k of ["path", "file_path", "filePath", "file", "target_file", "target"]) {
		const v = asText(a[k]).trim();
		if (v) return v;
	}
	return "";
}

function tempRoots(): string[] {
	const roots = [os.tmpdir(), "/tmp", "/var/tmp", "/dev/shm"];
	for (const k of ["TEMP", "TMP", "TMPDIR"]) {
		const v = (process.env[k] ?? "").trim();
		if (v) roots.push(v);
	}
	return roots.filter((r) => r.length > 0);
}

/** `~` / `~/x` → 绝对路径（禁写名单里全是 `~` 写法）。 */
export function expandHome(p: string): string {
	const s = p.trim();
	if (s === "~") return os.homedir();
	if (s.startsWith("~/") || s.startsWith("~\\")) return path.join(os.homedir(), s.slice(2));
	return s;
}

/** 异常 → 一行可读文本（拿不到就写一句占位，绝不因为 err 本身再抛）。 */
export function errText(err: unknown): string {
	if (err instanceof Error) return (err.name || "Error") + ": " + (err.message || "");
		try {
		const s = String(err);
		return s || "（空异常）";
	} catch {
		return "（无法转成文本的异常）";
	}
}

/** 系统临时目录（含任何路径里的 /tmp/ 或 /temp/ 段：任意盘符下的 tmp 目录也算临时区）。 */
export function isTempPath(p: string): boolean {
	const n = cmpKey(p);
	if (tempRoots().some((r) => under(p, r))) return true;
	return /(^|\/)(tmp|temp)(\/|$)/i.test(n);
}

/** `~/.seep/current-case` 里记的当前案目录（case_state.py init 写的机器级指针）。 */
function currentCaseDirs(): string[] {
	const out: string[] = [];
	try {
		const p = path.join(os.homedir(), ".seep", "current-case");
		const txt = fs.readFileSync(p, "utf-8").trim();
		if (txt) out.push(txt);
	} catch {
		/* 没有就算了 */
	}
	return out;
}

/** 已知项目、案件及临时目录，用于写入范围提示。 */
export function writeAllowRoots(cwd: string = process.cwd()): string[] {
	const roots: string[] = tempRoots();
	const repo = findRepoRoot(cwd);
	const base = repo || path.resolve(cwd);
	roots.push(base, path.join(base, "Tool"), path.join(base, "work"));
	const home = os.homedir();
	roots.push(path.join(home, ".seep"), path.join(home, ".pi", "agent"));
	for (const c of currentCaseDirs()) roots.push(c);
	return roots;
}

/** 写入范围仅作为提示；用户授权的维护不因历史名单被阻止。 */
export function writeDecision(
 toolName: string, args: unknown, roots: string[],
 temp: (p: string) => boolean = isTempPath, _never: string[] = NEVER_WRITABLE,
): { block: boolean; reason: string; code: string } {
 const lname = toolName.trim().toLowerCase();
 if (!WRITE_TOOLS.has(lname)) return { block: false, reason: "", code: "not-write" };
 const raw = writeTargetPath(args);
 if (!raw) return { block: false, reason: "", code: "no-path" };
 const abs = path.resolve(expandHome(raw));
 if (temp(abs) || roots.some(r => under(abs, r))) return { block: false, reason: "", code: "allowed" };
 return { block: false, reason: "写入路径不在已知项目/案件范围：" + raw + "；请核对当前任务的数据边界。", code: "outside-roots" };
}

/* ───────────────────────────── 磁盘层 ───────────────────────────── */

function existingDirectory(value: string): string {
	try {
		const resolved = path.resolve(value);
		return fs.statSync(resolved).isDirectory() ? resolved : "";
	} catch {
		return "";
	}
}

/**
 * 当前案件目录：显式环境变量 → 本会话 cwd 下的 .seep-case → 机器级指针。
 * 与 seep-events / seep-memory 使用同一优先级，避免同一进程并行跑两个项目时，
 * 后启动的全局指针把另一个会话的目标诊断串过来。
 */
export function currentCaseHint(cwd: string = ""): string {
	const candidates: string[] = [];
	const explicit = (process.env.SEEP_CASE_DIR ?? "").trim();
	if (explicit) candidates.push(explicit);
	try {
		candidates.push(path.resolve(cwd || process.cwd(), ".seep-case"));
	} catch {}
	try {
		const pointer = fs.readFileSync(path.join(os.homedir(), ".seep", "current-case"), "utf-8")
			.split(/\r?\n/)
			.map((line) => line.trim())
			.find(Boolean);
		if (pointer && path.isAbsolute(pointer)) candidates.push(pointer);
	} catch {}
	for (const candidate of candidates) {
		const dir = existingDirectory(candidate);
		if (dir) return dir;
	}
	return "";
}

/** 找仓库根的 Tool/config/answer-contract.json：环境变量 → cwd 逐级上溯 → 常见相对位置。 */
export function findContract(): string {
	const rel = path.join("Tool", "config", "answer-contract.json");
	const cands: string[] = [];
	const env = (process.env.SEEP_TOOL_ROOT ?? "").trim();
	if (env) {
		cands.push(path.join(env, "Tool", "config", "answer-contract.json"), path.join(env, "config", "answer-contract.json"));
	}
	let dir = process.cwd();
	for (let i = 0; i < 8; i++) {
		cands.push(path.join(dir, rel), path.join(dir, "config", "answer-contract.json"));
		const up = path.dirname(dir);
		if (up === dir) break;
		dir = up;
	}
	for (const c of cands) {
		try {
			if (fs.statSync(c).isFile()) return c;
		} catch {
			/* 下一个候选 */
		}
	}
	return "";
}

/** 仓库根：优先由 answer-contract.json 的位置反推，其次逐级上溯找 `Tool/` 目录。 */
export function findRepoRoot(cwd: string = process.cwd()): string {
	const c = findContract();
	if (c) {
		let dir = path.dirname(c); // …/Tool/config 或 …/config
		if (path.basename(dir).toLowerCase() === "config") dir = path.dirname(dir);
		if (path.basename(dir).toLowerCase() === "tool") dir = path.dirname(dir);
		return dir;
	}
	let dir = path.resolve(cwd);
	for (let i = 0; i < 8; i++) {
		try {
			if (fs.statSync(path.join(dir, "Tool")).isDirectory()) return dir;
		} catch {
			/* 继续上溯 */
		}
		const up = path.dirname(dir);
		if (up === dir) break;
		dir = up;
	}
	return "";
}

/** 读契约哈希 + gate 块：读不到返回 {hash:"", gate:DEFAULT_GATE}。按 mtime 缓存，避免每次工具调用都读盘。 */
let contractCache: { file: string; mtimeMs: number; hash: string; gate: GateConfig } = {
	file: "",
	mtimeMs: -1,
	hash: "",
	gate: DEFAULT_GATE,
};

function loadContract(): { hash: string; gate: GateConfig } {
	const file = findContract();
	if (!file) return { hash: "", gate: DEFAULT_GATE };
	try {
		const st = fs.statSync(file);
		if (contractCache.file === file && contractCache.mtimeMs === st.mtimeMs) {
			return { hash: contractCache.hash, gate: contractCache.gate };
		}
		const buf = fs.readFileSync(file);
		// 用 node:crypto 而不是引第三方库：零新依赖
		const h = String(createHash("sha256").update(buf).digest("hex"));
		let raw: unknown = null;
		try {
			raw = JSON.parse(buf.toString("utf-8"));
		} catch {
			raw = null;
		}
		contractCache = { file, mtimeMs: st.mtimeMs, hash: h, gate: parseGate(raw) };
		return { hash: h, gate: contractCache.gate };
	} catch {
		return { hash: "", gate: DEFAULT_GATE };
	}
}

export function contractHash(): string {
	return loadContract().hash;
}

/** 契约里的 `gate` 块（阈值唯一来源）。 */
export function gateConfig(): GateConfig {
	return loadContract().gate;
}

/** 读某案 case.json 里登记的目标（`target_files[].path` / `target` / `target_path` / `target_type`）。失败返回 null。 */
let caseCache: { file: string; mtimeMs: number; data: CaseTargets | null } = { file: "", mtimeMs: -1, data: null };

export function readCaseTargets(caseDir: string): CaseTargets | null {
	const dir = path.resolve(caseDir);
	const file = path.join(dir, "case.json");
	try {
		const st = fs.statSync(file);
		if (caseCache.file === file && caseCache.mtimeMs === st.mtimeMs) return caseCache.data;
		const raw: unknown = JSON.parse(fs.readFileSync(file, "utf-8"));
		const cj = asRecord(raw);
		const paths: string[] = [];
		const shas: string[] = [];
		const files: { path: string; sha256: string }[] = [];
		const tfiles = cj.target_files;
		if (Array.isArray(tfiles)) {
			for (const it of tfiles) {
				const r = asRecord(it);
				const p = asText(r.path).trim();
				if (p) paths.push(p);
				const s = asText(r.sha256).trim();
				if (s) shas.push(s);
				if (p && s) files.push({ path: p, sha256: s });
			}
		}
		for (const k of ["target", "target_path", "target_type"]) {
			// 注：case_state.py 的 case.json 骨架把目标路径写在 `target_type` 里（历史字段名），也得认
			const value = cj[k];
			const v = asText(typeof value === "object" && value ? asRecord(value).path : value).trim();
			if (v && !/^https?:\/\//i.test(v)) paths.push(v);
			const sha = asText(asRecord(value).sha256).trim();
			if (v && sha && files.length === 0) files.push({ path: v, sha256: sha });
		}
		const data: CaseTargets = { dir, paths, files, targetSha256: shas[0] || files[0]?.sha256 || "" };
		caseCache = { file, mtimeMs: st.mtimeMs, data };
		return data;
	} catch {
		return null;
	}
}

/* ─────────────────────────── 扩展入口 ─────────────────────────── */

export default function answerGate(pi: ExtensionAPI) {
 // 同一当前案事实用于所有调用的非阻断诊断，不读取历史首答/运行回执。
 pi.on("tool_call", (event: unknown, ctx: unknown) => {
  try {
   const e = asRecord(event), tool = asText(e.toolName ?? e.name), args = e.input ?? e.args;
   const caseDir = currentCaseHint(asText(asRecord(ctx).cwd));
   const targets = caseDir ? readCaseTargets(caseDir) : null;
   const diagnostics: string[] = [];
   if (caseDir && !targets) diagnostics.push("无法读取当前案登记：" + caseDir);
   const v = shouldBlock(tool, args, null, "", Date.now(), gateConfig(), targets);
   if (v.reason) diagnostics.push(v.reason);
   const w = writeDecision(tool, args, writeAllowRoots());
   if (w.reason) diagnostics.push(w.reason);
   if (diagnostics.length) {
    const message = "[case-context] " + diagnostics.join("；");
    console.warn(message);
    const ui = asRecord(asRecord(ctx).ui);
    if (typeof ui.notify === "function") (ui.notify as (s: string) => void).call(ui, message);
   }
  } catch (err) { console.warn("[case-context] 诊断失败：" + errText(err)); }
  return undefined;
 });
	pi.on("tool_call", (event: unknown) => {
		try {
			const e = asRecord(event);
			const tool = asText(e.toolName ?? e.name);
			const base = tool.replace(/^mcp__[^_]+__/, "");
			if (!READONLY_TOOLS.has(base) && !READONLY_TOOLS.has(tool)) return undefined;
			const hit = sensitivePathHit(e.input ?? e.args);
			if (!hit) return undefined;
			console.warn("[read-guard] 已拦下个人隐私区路径：" + hit);
			return {
				block: true,
				reason:
					"[read-guard] 已拦下：这条路径属于个人隐私区（" + hit + "）。\n" +
					"分析只需要三类路径：目标文件、案件目录（work/ 或 Tool/cases/<案>/）、工具安装目录。\n" +
					"如果确实需要看它，请让用户把文件复制到案件目录后再继续。",
			};
		} catch {
			return undefined;
		}
	});
 try {
  pi.registerCommand?.("answer-gate", {
   description: "查看当前案上下文诊断状态",
   handler: async (_args: string, ctx: unknown) => {
    const dir = currentCaseHint(asText(asRecord(ctx).cwd));
    const targets = dir ? readCaseTargets(dir) : null;
    const message = "[case-context] 当前案=" + (dir || "未设置") +
     (dir ? (targets ? "；登记目标=" + (targets.paths.join(" / ") || "无") : "；无法读取 case.json") : "") +
     "；历史首答和运行回执不决定工具调用";
    const ui = asRecord(asRecord(ctx).ui), notify = ui.notify ?? ui.showMessage;
    if (typeof notify === "function") (notify as (s: string) => void).call(ui, message);
    else console.log(message);
   },
  });
 } catch (err) { console.warn("[case-context] 状态命令注册失败：" + errText(err)); }
}
