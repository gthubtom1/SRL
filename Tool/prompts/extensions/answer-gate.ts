/**
 * answer-gate —— 首答闸（pi 扩展）
 *
 * ── 为什么需要这道闸（独立评审第 1 轮 P1-5 原话）──────────────────
 *   「首答四要素（判断 / 到哪一步 / 缺什么 / 大约多少功夫）只有 `case_state.py answer --check`
 *    这个自检命令，没有任何运行时保障；扩展里也没有任何东西在回复前校验它。」
 *
 *   这句话是准的：`answer --check` 只能校验「它被调用时传进去的那份 JSON」，
 *   它管不住「根本没被调用」。提示词里写一百遍「必须先给四要素」，
 *   模型只要直接调第一个分析工具，首答就被跳过了 —— 而首答被跳过，
 *   用户拿到的第一段话就是「我在跑 triage」，不是「这是什么、能做到哪、缺什么、要多久」。
 *   `case_state.py` 文件头的血案（第 20 秒报结论、3.5 小时后发现方向全错）就是这条链的下游。
 *
 *   所以这道闸把「自觉」换成「执行层」：
 *     **首答记录落地之前，分析类工具连发都发不出去。**
 *   反过来也必须成立，否则这道闸会变成新的缺陷：
 *     **读类工具（read/grep/find/ls/todo）与自检命令（answer / --help / preflight / check / gate / route）
 *      永远放行** —— 闸的出路必须始终可达，不能把人关在自己装的闸外面。
 *
 * ── 它认什么凭证 ──────────────────────────────────────────────
 *   `~/.seep/answer-pass.json`（由 `case_state.py answer --check` **通过时**写入，失败不写）：
 *     {"schema":"seep.answer-pass/1","case":"<abs 或 ''>","at":"<ISO8601>",
 *      "contract_sha256":"<Tool/config/answer-contract.json 的 sha256>"}
 *   有效 = 文件存在 + schema 对 + contract_sha256 与**当前**契约一致 + at 在 4 小时内。
 *   契约改了（四要素多一项 / ceiling 四句改了）→ 旧标记自动作废，必须重新过一遍首答。
 *
 * ── 只拦「分析类」，不拦别的 ───────────────────────────────────
 *   拦：① 工具名以 `seep_` 开头（MCP；codemode 下是 `mcp__seep__seep_*`，同样拦）
 *       ② bash/powershell 命令里出现：`Tool/skill/`、`case_state.py (init|claim|prove|repro|deliver)`、
 *          `tool-run.ps1`、`radare2|r2 |jadx|apktool|frida|x64dbg|ghidra`
 *   不拦：read / grep / find / ls / todo；`case_state.py answer`、`case_state.py --help`、
 *         `Tool/scripts/{preflight,check,gate,route}.py`；以及命中处所在的**只读程序段**
 *         （`grep -rn "frida" docs/` 是在读文档，不是在跑工具）。
 *
 * ── 容错（硬约束）──────────────────────────────────────────────
 *   · 读不到标记文件 / 标记坏了 → **按缺失处理（block）**：fail-closed，不能靠删文件绕过闸。
 *   · 读不到 `Tool/config/answer-contract.json` → **只告警不 block**：
 *     一次工作台搬迁/半截落盘不该把整个会话锁死（闸降级成提示）。
 *   · 本文件自身抛异常 → 放行（绝不因为闸的 bug 误拦正常调用）。
 *   · 人工逃生：`/answer-gate` 看状态；`SEEP_ANSWER_GATE=0` 关闭（默认开，见文件尾说明）。
 *
 * 中文注释、零新依赖、纯函数 `shouldBlock(...)` 可单测（不碰磁盘）。
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/* ────────────────────────────── 常量 ────────────────────────────── */

/** 标记 schema：格式一变，旧标记一律当无效（宁可重做一次首答，也不认半截数据）。 */
export const MARKER_SCHEMA = "seep.answer-pass/1";

/** 有效期 4 小时：够覆盖一次完整首答 + 头一轮分析，又不至于让上周的标记一直放行。 */
export const TTL_MS = 4 * 60 * 60 * 1000;

/** 标记文件位置（`~/.seep/answer-pass.json`，与 case_state.py 的写入侧一致）。 */
export function markerPath(): string {
	return path.join(os.homedir(), ".seep", "answer-pass.json");
}

/** 读类工具名（自带只读语义）：永不拦。`todo` 也在这里 —— 建清单是首答之前的正当动作。 */
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

/** 只读程序：命中分析类关键词但程序本身是「看」的，按读取处理（防误伤文档检索）。 */
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
	"file",
	"strings",
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
	/case_state\.py\s+--help\b/i,
	/case_state\.py\s+-h\b/i,
	/Tool\/scripts\/(preflight|check|gate|route)\.py\b/i,
];

/** 已改写成 Windows 反斜杠或带盘符的写法也要认，所以比较前先归一化分隔符。 */
function normalizeCmd(raw: string): string {
	return raw.replace(/\\/g, "/");
}

/** 分析类关键词（只在 shell 命令里找；命中即说明这一句在动工具，不是在说话）。 */
type CmdPattern = { re: RegExp; why: string };

const CMD_ANALYSIS: CmdPattern[] = [
	{ re: /Tool\/skill\//i, why: "读技能包目录（Tool\/skill\/）" },
	{ re: /case_state\.py\s+(init|claim|prove|repro|deliver)\b/i, why: "案子写账（case_state.py 子命令）" },
	{ re: /tool-run\.ps1/i, why: "工具链入口 tool-run.ps1" },
	{
		// 前后都要求「不是字母数字」的边界：`r2` 不能命中 `armv7r2x`，`ghidra` 不能命中 `ghidra_notes.md` 之外的词。
		re: /(^|[^A-Za-z0-9_.-])(radare2|r2|jadx|apktool|frida|x64dbg|ghidra)(?=$|[^A-Za-z0-9_.-])/i,
		why: "逆向工具链（radare2 / r2 / jadx / apktool / frida / x64dbg / ghidra）",
	},
];

/* ───────────────────────────── 纯函数层 ───────────────────────────── */

/** 把未知宿主对象窄化成可索引的记录（不用 any 糊过去）。 */
function asRecord(v: unknown): Record<string, unknown> {
	return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
}

function asText(v: unknown): string {
	return typeof v === "string" ? v : "";
}

/** 命中的工具名是否属于「分析类」MCP 工具。codemode 下 seep 工具叫 `mcp__seep__seep_*`。 */
function isAnalysisToolName(name: string): boolean {
	const n = name.toLowerCase();
	return n.startsWith("seep_") || n.startsWith("mcp__seep__seep_");
}

/** 取一段命令里的「程序名」：跳过 `VAR=value` 前缀与引号，取 basename 并去掉 .exe 后缀。 */
function programOf(segment: string): string {
	let s = segment.trim().replace(/^[("'`]+/, "");
	for (let i = 0; i < 3; i++) {
		const m = s.match(/^[A-Za-z_][A-Za-z0-9_]*=[^\s]*\s+/);
		if (!m) break;
		s = s.slice(m[0].length);
	}
	const first = (s.split(/\s+/)[0] || "").replace(/^["'`]+|["'`]+$/g, "");
	const base = first.split(/[\\/]/).pop() || first;
	return base.replace(/\.(exe|cmd|bat)$/i, "").toLowerCase();
}

/** 按 `&& || ; | 换行` 切段：一段只放行自己，别让 `preflight && frida ...` 沾光。 */
function splitSegments(cmd: string): string[] {
	return cmd
		.split(/&&|\|\||[;\n|]/)
		.map((s) => s.trim())
		.filter((s) => s.length > 0);
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

/** 单段命令 → 是否分析类 + 命中的是什么（用于 block 文案里说清"我在拦哪一句"）。 */
export function classifySegment(segment: string): { analysis: boolean; why: string } {
	const seg = normalizeCmd(segment);
	// 1) 放行命令（answer / --help / preflight|check|gate|route）：这一段整体不看
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
export function classifyTool(toolName: string, args: unknown): { analysis: boolean; why: string } {
	const name = toolName.trim();
	if (!name) return { analysis: false, why: "" };
	const lname = name.toLowerCase();
	// 读类工具优先放行：拦它们等于把工作台锁死（评审明确警告过这一条）
	if (READONLY_TOOLS.has(lname)) return { analysis: false, why: "" };
	if (isAnalysisToolName(lname)) return { analysis: true, why: "MCP 分析工具 " + name };
	if (lname !== "bash" && lname !== "powershell") return { analysis: false, why: "" };
	const a = asRecord(args);
	const cmd = asText(a.command ?? a.cmd ?? "");
	if (!cmd.trim()) return { analysis: false, why: "" };
	for (const seg of splitSegments(stripQuotedHeredoc(cmd))) {
		const v = classifySegment(seg);
		if (v.analysis) return { analysis: true, why: v.why };
	}
	return { analysis: false, why: "" };
}

/**
 * 标记有效性：文件存在 + schema 对 + contract_sha256 与当前契约一致 + at 在 4 小时内。
 * 契约哈希拿不到（空串）时由 shouldBlock 决定「只告警」——这里只报「无法判定」。
 */
export function markerState(marker: unknown, contractHash: string, now: number): { ok: boolean; why: string } {
	const m = asRecord(marker);
	if (marker === null || marker === undefined || Object.keys(m).length === 0) {
		return { ok: false, why: "没有首答记录（" + markerPath() + " 不存在或读不出）" };
	}
	if (asText(m.schema) !== MARKER_SCHEMA) {
		return { ok: false, why: "标记格式不是 " + MARKER_SCHEMA + "（可能被手改坏了）" };
	}
	const got = asText(m.contract_sha256).trim().toLowerCase();
	if (!got) return { ok: false, why: "标记里没有 contract_sha256" };
	if (!contractHash) return { ok: false, why: "拿不到当前 answer-contract.json 的哈希，无法比对" };
	if (got !== contractHash.trim().toLowerCase()) {
		return { ok: false, why: "首答契约已变（answer-contract.json 的 sha256 与标记不一致），上一份首答不再算数" };
	}
	const atRaw = asText(m.at).trim();
	const at = Date.parse(atRaw);
	if (!Number.isFinite(at)) return { ok: false, why: "标记里的 at 不是合法时间（" + (atRaw || "空") + "）" };
	const age = now - at;
	if (age > TTL_MS) {
		const hours = (age / 3600000).toFixed(1);
		return { ok: false, why: "首答记录已过期（" + hours + " 小时前写的，闸只认 4 小时内）" };
	}
	return { ok: true, why: "" };
}

/** block 文案：必须是「照着抄就能过」的三步，并且说清这是闸不是报错。 */
export function buildBlockReason(toolName: string, why: string, markerWhy: string): string {
	return [
		"[answer-gate] 已拦下：" + toolName + "（" + why + "）",
		"",
		"**这是一道闸，不是报错。** 它只要求一件事：在动分析工具之前，先把首答四要素说出来。",
		"拦下原因：" + markerWhy,
		"",
		"照着抄三步（第 1 步只是打印骨架，可以直接复制）：",
		"",
		"  1) python Tool/scripts/case_state.py answer --template",
		"",
		"  2) 按骨架填成一份 JSON（四要素：judgment 判断 / ceiling 到哪一步 / missing 缺什么 / effort 大约多少功夫），",
		"     存成 a.json，例如：",
		'        {"judgment":"PE32+，未见壳，关键在校验函数","ceiling":"只能看懂结构",',
		'         "missing":["有没有卡密"],"effort":"1-2 小时；依据：未见壳、纯本地判定，读一遍导入表即可定性"}',
		"",
		"  3) python Tool/scripts/case_state.py answer --check --file a.json",
		"",
		"  看到 [PASS] → 会自动写 " + markerPath() + "（4 小时内有效），把刚才那条命令原样重发即可。",
		"  看到 [缺] … → 按提示补，补完再跑第 3 步；不合格不会写标记。",
		"",
		"（ceiling 只认四句之一：只能看懂结构 / 能改到能用 / 能完全自己接管 / 现在做不了 —— 取自 answer-contract.json）",
	].join("\n");
}

/**
 * 纯函数闸门（可单测，不碰磁盘）：
 *   toolName     工具名（`seep_auto_triage` / `bash` / `read` …）
 *   args         工具入参（只用 `.command`/`.cmd`）
 *   marker       已读出的标记对象（读不到传 null）
 *   contractHash 当前 answer-contract.json 的 sha256（读不到传 ""）
 *   now          epoch ms
 * 返回 block=true 时 reason 即给模型看的完整文案。
 */
export function shouldBlock(
	toolName: string,
	args: unknown,
	marker: unknown,
	contractHash: string,
	now: number,
): { block: boolean; reason: string; analysis: boolean } {
	const cls = classifyTool(toolName, args);
	if (!cls.analysis) return { block: false, reason: "", analysis: false };
	// 读不到契约 → 只告警不拦：一次半截落盘不该把整个工作台锁死
	if (!contractHash) {
		return {
			block: false,
			reason: "[answer-gate][WARN] 读不到 Tool/config/answer-contract.json，本次放行（闸降级为提示）",
			analysis: true,
		};
	}
	const st = markerState(marker, contractHash, now);
	if (st.ok) return { block: false, reason: "", analysis: true };
	return { block: true, reason: buildBlockReason(toolName, cls.why, st.why), analysis: true };
}

/* ───────────────────────────── 磁盘层 ───────────────────────────── */

/** 读标记：任何异常（不存在 / 半截 JSON / 权限）都当「没有」→ 由调用方 block。 */
export function readMarker(p = markerPath()): unknown {
	try {
		if (!fs.existsSync(p)) return null;
		const txt = fs.readFileSync(p, "utf-8");
		const obj: unknown = JSON.parse(txt);
		return typeof obj === "object" && obj !== null ? obj : null;
	} catch {
		return null;
	}
}

/** 找仓库根的 Tool/config/answer-contract.json：环境变量 → cwd 逐级上溯 → 常见相对位置。 */
export function findContract(): string {
	const rel = path.join("Tool", "config", "answer-contract.json");
	const cands: string[] = [];
	const env = (process.env.SEEP_TOOL_ROOT ?? "").trim();
	if (env) cands.push(path.join(env, "Tool", "config", "answer-contract.json"), path.join(env, "config", "answer-contract.json"));
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

/** 读契约哈希：读不到返回 ""（→ 只告警不拦）。按 mtime 缓存，避免每次工具调用都读盘。 */
let contractCache: { file: string; mtimeMs: number; hash: string } = { file: "", mtimeMs: -1, hash: "" };

export function contractHash(): string {
	const file = findContract();
	if (!file) return "";
	try {
		const st = fs.statSync(file);
		if (contractCache.file === file && contractCache.mtimeMs === st.mtimeMs) return contractCache.hash;
		// 用 node:crypto 而不是引第三方库：零新依赖
		const h = createHash("sha256").update(fs.readFileSync(file)).digest("hex");
		contractCache = { file, mtimeMs: st.mtimeMs, hash: String(h) };
		return contractCache.hash;
	} catch {
		return "";
	}
}

/** 闸是否被人工关掉（默认开）。关掉只为「闸自己的 bug 把工作台锁死」这一种情形。 */
function disabledByEnv(): boolean {
	return (process.env.SEEP_ANSWER_GATE ?? "").trim() === "0";
}

/* ─────────────────────────── 扩展入口 ─────────────────────────── */

export default function answerGate(pi: ExtensionAPI) {
	/**
	 * tool_call 是第一道也是唯一一道校验点：拦在「发出去之前」，
	 * 而不是拦在「结果回来之后」（那时工具已经动过目标了，闸就没意义了）。
	 */
	pi.on("tool_call", (event: unknown) => {
		try {
			const e = asRecord(event);
			const tool = asText(e.toolName ?? e.name);
			const args = e.input ?? e.args;
			// 先分类：读类工具连标记文件都不读（不去碰磁盘，就不可能误伤它）
			if (!classifyTool(tool, args).analysis) return undefined;
			const v = shouldBlock(tool, args, readMarker(), contractHash(), Date.now());
			if (!v.block) {
				if (v.reason) console.warn(v.reason);
				return undefined;
			}
			if (disabledByEnv()) {
				console.warn("[answer-gate] SEEP_ANSWER_GATE=0 → 闸被人工关闭，本次放行：" + tool);
				return undefined;
			}
			return { block: true, reason: v.reason };
		} catch {
			// 闸自己出错 → 放行（绝不因为闸的 bug 误拦正常调用）
			return undefined;
		}
	});

	/** `/answer-gate`：让人能看见闸的状态，而不是凭猜。 */
	try {
		pi.registerCommand?.("answer-gate", {
			description: "看首答闸状态：/answer-gate（有效 / 过期 / 契约变了 / 没有记录）",
			handler: async (_args: string, ctx: unknown) => {
				const lines: string[] = ["[answer-gate] 标记=" + markerPath()];
				try {
					const hash = contractHash();
					const file = findContract();
					lines.push("  契约=" + (file || "（找不到，闸降级为提示）") + (hash ? " sha256=" + hash.slice(0, 12) + "…" : ""));
					const marker = readMarker();
					const st = markerState(marker, hash, Date.now());
					lines.push("  状态=" + (st.ok ? "有效（分析类工具放行）" : "无效 → 分析类工具会被拦：" + st.why));
					const m = asRecord(marker);
					if (st.ok) lines.push("  写入时间=" + asText(m.at) + " · case=" + (asText(m.case) || "（未指定）"));
					if (disabledByEnv()) lines.push("  ★ SEEP_ANSWER_GATE=0：闸已被人工关闭（默认开）");
					lines.push("  过闸：python Tool/scripts/case_state.py answer --template → 填四要素 → answer --check --file a.json");
				} catch {
					lines.push("  状态=读取出错（不影响会话）");
				}
				const text = lines.join("\n");
				try {
					// 宿主 UI 形状未知：逐层窄化，拿不到就打印，不抛
					const ui = asRecord(asRecord(ctx).ui);
					const notify = ui.notify ?? ui.showMessage;
					if (typeof notify === "function") {
						(notify as (s: string) => void).call(ui, text);
						return;
					}
				} catch {
					/* 落到 console */
				}
				console.log(text);
			},
		});
	} catch {
		/* 老版本 pi 没有 registerCommand → 只是少一个查看命令，闸照常工作 */
	}
}
