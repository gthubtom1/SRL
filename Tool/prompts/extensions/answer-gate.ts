/**
 * answer-gate —— 首答闸 + 写入守卫（pi 扩展）
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
 * ── 第 2 轮评审的三条批评（都已修）─────────────────────────────
 *   ① 「把只读分诊也拦了 → 首答反而只能靠猜」：**纯读取**的五个体检工具
 *      `seep_kb_search` / `seep_kb_read` / `seep_case_read` / `seep_tool_discover` / `seep_r2_info`
 *      **永远放行**（首答要靠它们取证）。名单写在 answer-contract.json 的 `gate.whitelist`（唯一来源）。
 *   ② 「不拦 rabin2 / python -c / curl → 闸有洞」：新增 `rabin2|objdump|readelf|strings|file`
 *      与 `curl|wget|ncat|nc`，以及解释器内联执行（`python -c` / `python - <<` / `powershell -c`，
 *      命令体里出现上述工具名或 socket/requests/http 才算）。`python Tool/scripts/*.py`、
 *      `python Tool/skill/*\/scripts/*.py --self-test`、`cat > x <<EOF` 写文件仍放行。
 *   ③ 「一份标记 4 小时对所有目标生效」：标记加 `case` + `target_sha256`，有效期收到
 *      `gate.ttl_minutes`（默认 60 分钟）；标记带 `case` 时，本次参数里的路径必须落在该案
 *      `case.json` 的 `target_files`/`target` 下，否则 block（「换了目标要重新给首答」）。
 *
 * ── 第 3 轮评审的两条（P0-4 / P0-3 部分，都已修）───────────────────
 *   ④ **P0-4「运行客户的目标程序」原来一个门都没有**：`answer-gate` 里没有 `launch-gui`，
 *      `cmd-guard.ts` 对 `Start-Process *.exe` 只是 warn，ack 也只在 `gate --stage` 时被检查。
 *      → 本轮加**第三道 handler「运行目标闸」**（见下面 `classifyRunTarget` / `shouldBlockRun`）：
 *        bash/powershell 命令里出现 `launch-gui.ps1` / `Start-Process` / 把 `.exe` 当程序执行 /
 *        `wine ` / `& "<盘符>…"` → 必须持有 `~/.seep/run-ack.json`（由 `case_state.py ack` 原子写，
 *        60 分钟内有效、绑本案目标），否则 block。拦在**命令文本层**：`launch-gui.ps1` 内部
 *        再拉子进程不用再拦一次。
 *   ⑤ **P0-3 部分「首答白名单 8 个永远放行 = 先分析再补首答」**：`seep_auto_triage` /
 *      `seep_packer_detect` / `seep_apk_info` 会**读目标里的内容**，属于「分析」→ 移出白名单；
 *      只留 5 个纯读取（`seep_r2_info` 只看架构/位数）。为了不让「首答只能靠猜」复活，
 *      block 文案里明写两条合法出路：先写首答再用 triage / 直接问用户要判断。
 *
 * ── 第 4 轮评审的四个 P0（都已修）───────────────────────────────
 *   ⑥ **首答通行证原来能由被约束方自己写**：写守卫把 `~/.seep/` 与 `~/.pi/agent/` 整体放行，
 *      模型可以自己写 `answer-pass.json` / `run-ack.json` / `current-case`，甚至改
 *      `cmd-guard.rules.json`（30 秒热加载）/ `answer-contract.json` / `AGENTS.md`。
 *      → 写守卫加**永久禁写名单**（`gate.never_writable` + 硬编码兜底 `NEVER_WRITABLE`），
 *        优先级高于任何允许根：`Tool/` 仍可写（框架要能改代码），但这八类凭证/规则/契约/提示词永久禁写。
 *   ⑦ **`--adhoc` 临时首答被当成通行证**：标记里的 `"adhoc": true` 现在直接判无效
 *      （`markerState` → `valid:false / reason:"adhoc-not-a-pass"`），必须绑案子重跑 `answer --check --case`。
 *   ⑧ **运行闸不看字母**：`ack --choice B`（「先别运行」）也会开闸。`runAckState` 只认 letter ∈ {A, C}，
 *      B 与其它字母一律 block。
 *   ⑩ **首答标记不看目标内容哈希**（第 5 轮评审 P1，审计点名）：`target_sha256` 原来只写不比较，
 *      同路径换文件仍算同一目标。现在 `targetMismatch` 会算当前文件哈希并与标记比对，
 *      不同即 block（"换了目标要重新给首答"）。
 *   ⑨ **只认 `seep_*`**：`mcp__x64dbg__*` / `mcp__ida__*` 等其它 MCP 工具可无首答直接开工。
 *      → 工具名以 `mcp__` 开头（任意服务）都算分析动作，**只有** `gate.whitelist` 里的 5 个
 *        （裸名或 `mcp__seep__seep_kb_search` 这种全名都认）放行；`gate.exec_tools`
 *        （当前 `seep_r2_cmd`）除首答外还要运行回执。
 *
 * ── 它认什么凭证 ──────────────────────────────────────────────
 *   `~/.seep/answer-pass.json`（由 `case_state.py answer --check` **通过时**写入，失败不写）：
 *     {"schema":"seep.answer-pass/1","case":"<abs 或 ''>","target_sha256":"<登记的目标哈希或 ''>",
 *      "at":"<ISO8601>","contract_sha256":"<Tool/config/answer-contract.json 的 sha256>"}
 *   有效 = 文件存在 + schema 对 + **没有 `adhoc:true`** + contract_sha256 与**当前**契约一致
 *          + at 在 ttl_minutes 内。
 *   契约改了（四要素多一项 / ceiling 四句改了 / gate 块改了）→ 旧标记自动作废，必须重新过一遍首答。
 *   这些凭证（`answer-pass.json` / `run-ack.json` / `current-case`）**只许 `case_state.py` 写**：
 *   写守卫对它们永久禁写（见 `NEVER_WRITABLE`）。
 *
 * ── 只拦「分析类」，不拦别的 ───────────────────────────────────
 *   运行目标闸（第三道 handler，独立于首答闸）——
 *   拦：`launch-gui.ps1`、`Start-Process`、`wine `、`& "<盘>:/…"`、把 `.exe` 当程序跑；
 *   放行：`ls *.exe` / `find -name *.exe` / `grep \.exe README` 这类**只看文件名**的只读命令，
 *         以及 `case_state.py`/`preflight`/`check`/`gate`/`route` 这些不执行目标的工作台命令。
 *
 *   首答闸 ——
 *   拦：① 非白名单的 `seep_*` / **任意** `mcp__<server>__*`（codemode 下 seep 工具是 `mcp__seep__seep_*`；
 *          `mcp__x64dbg__*` / `mcp__ida__*` 等其它 MCP 服务同样算分析动作，第 4 轮 P0-3）
 *       ② bash/powershell 命令里出现：`Tool/skill/`（跑技能脚本；`--self-test` 除外）、
 *          `case_state.py (claim|prove|repro|deliver)`、`tool-run.ps1`、
 *          `radare2|r2|jadx|apktool|frida|x64dbg|ghidra`、`rabin2|objdump|readelf|strings|file`、
 *          `curl|wget|ncat|nc`、解释器内联执行（python -c / python - << / powershell -c …）
 *   不拦：read / grep / find / ls / todo；`case_state.py answer|init|--help`（init 只建案不分析，
 *         冷启动顺序必须能走通：`init`（不拦）→ `answer --check --case` → 再分析）、
 *         `Tool/scripts/{preflight,check,gate,route}.py`、白名单 seep_* 分诊；
 *         以及命中处所在的**只读程序段**（`grep -rn "frida" docs/` 是在读文档，不是在跑工具）。
 *
 * ── 写入守卫（第 2 轮评审新增要求）──────────────────────────────
 *   写类工具（write/edit/apply_patch…）只许写到：案件目录（`~/.seep/current-case`
 *   或标记里的 case）、仓库存放区 `work/` 与 `Tool/`、`~/.seep/`、`~/.pi/agent/`、系统临时目录；
 *   其余（桌面 / 系统目录 / 仓库根的自造文件）一律 block，文案给「要改仓库请明确说明」。
 *   **但凭证、闸规则、契约、提示词不受允许根保护**：`NEVER_WRITABLE`（`gate.never_writable`）
 *   里的路径永久禁写，优先级高于上面所有允许根（第 4 轮 P0-1/P0-5）。
 *   读类工具完全不受影响。
 *
 * ── 容错（硬约束）──────────────────────────────────────────────
 *   · 读不到标记文件 / 标记坏了 → **按缺失处理（block）**：fail-closed，不能靠删文件绕过闸。
 *   · 读不到 `Tool/config/answer-contract.json` → **只告警不 block**：
 *     一次工作台搬迁/半截落盘不该把整个会话锁死（闸降级成提示）。
 *   · 标记带 case 但读不到该案 case.json → **只告警不 block**（目标绑定降级为提示）。
 *   · 本文件自身抛异常 → 放行（绝不因为闸的 bug 误拦正常调用）。
 *   · 人工逃生：`/answer-gate` 看状态；`SEEP_ANSWER_GATE=0` 关闭（默认开，见文件尾说明）。
 *
 * 中文注释、零新依赖、纯函数 `shouldBlock(...)` / `writeDecision(...)` 可单测（不碰磁盘）。
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/* ────────────────────────────── 常量 ────────────────────────────── */

/** 标记 schema：格式一变，旧标记一律当无效（宁可重做一次首答，也不认半截数据）。 */
export const MARKER_SCHEMA = "seep.answer-pass/1";

/** 运行回执 schema（`case_state.py ack` 成功时写 `~/.seep/run-ack.json`，P0-4）。 */
export const RUN_ACK_SCHEMA = "seep.run-ack/1";

/** 默认有效期 60 分钟（真正生效的值取自 answer-contract.json 的 `gate.ttl_minutes`）。 */
export const TTL_MS = 60 * 60 * 1000;

/**
 * 运行闸只认的两个字母：A=允许在本机运行，C=用户自己双击、你只观察。
 * B（先别运行）与任何其它字母一律不放行 —— 第 4 轮 P0：`ack --choice B` 原来也能开闸。
 */
export const RUN_OK_LETTERS = new Set(["A", "C"]);

/**
 * 永久禁写（第 4 轮 P0-1/P0-4）：闸的凭证、闸的规则、契约、提示词。
 * 优先级**高于**任何允许根（`Tool/`、`~/.seep/`、`~/.pi/agent/` 整体放行也压不住它）。
 * `gate.never_writable` 只能往里加，减不掉这里的硬编码兜底 —— 否则改一行配置就能把闸拆了。
 */
export const NEVER_WRITABLE: string[] = [
	"~/.seep/answer-pass.json",
	"~/.seep/run-ack.json",
	"~/.seep/current-case",
	"~/.pi/agent",
	"**/cmd-guard.rules.json",
	"**/answer-contract.json",
	"**/AGENTS.md",
	"**/SEEP.md",
];

/** 运行回执的默认有效期 60 分钟（真正生效的值取自 `gate.run_ack.ttl_minutes`）。 */
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
	/** 标记有效期（分钟）。 */
	ttlMinutes: number;
	/** 永远放行的只读分诊工具（小写、不带 `mcp__seep__` 前缀）。 */
	whitelist: string[];
	/** 标记带 case 时是否绑定目标（参数里的路径必须落在该案登记的 target_files/target 下）。 */
	bindTarget: boolean;
	/** 运行目标闸（P0-4）。 */
	runAck: RunAckConfig;
	/** 「可执行目标」工具（第 4 轮 P0-4）：除首答外还要运行回执（当前 `seep_r2_cmd`）。 */
	execTools: string[];
	/** 永久禁写的凭证/规则/契约/提示词（`never_writable`；只能加不能减，见 NEVER_WRITABLE）。 */
	neverWritable: string[];
};

/** 读不到 / 读坏 `gate` 块时的兜底（与 answer-contract.json 保持同值，改一处要改两处）。 */
export const DEFAULT_GATE: GateConfig = {
	ttlMinutes: 60,
	// 只留**纯读取**语义：跑分诊会用目标里的内容做判断，那已经是「分析」，要先给首答（第 3 轮 P0-3）
	whitelist: ["seep_kb_search", "seep_kb_read", "seep_case_read", "seep_tool_discover", "seep_r2_info"],
	bindTarget: true,
	runAck: { ttlMinutes: RUN_ACK_TTL_MINUTES, requireCaseTarget: true },
	execTools: ["seep_r2_cmd"],
	neverWritable: NEVER_WRITABLE.slice(),
};

/** 标记文件位置（`~/.seep/answer-pass.json`，与 case_state.py 的写入侧一致）。 */
export function markerPath(): string {
	return path.join(os.homedir(), ".seep", "answer-pass.json");
}

/** 运行回执位置（`~/.seep/run-ack.json`，由 `case_state.py ack` 原子写）。 */
export function runAckPath(): string {
	return path.join(os.homedir(), ".seep", "run-ack.json");
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
	{ re: /Tool\/skill\//i, why: "跑技能包目录（Tool\/skill\/）里的脚本" },
	// 注意：`init` 不在这里（它在 CMD_ALLOW）。只建案不做分析，冷启动第一步必须能过。
	{ re: /case_state\.py\s+(claim|prove|repro|deliver)\b/i, why: "案子写账（case_state.py 子命令）" },
	{ re: /tool-run\.ps1/i, why: "工具链入口 tool-run.ps1" },
	{
		// 前后都要求「不是字母数字」的边界：`r2` 不能命中 `armv7r2x`，`ghidra` 不能命中 `ghidra_notes.md` 之外的词。
		re: /(^|[^A-Za-z0-9_.-])(radare2|r2|jadx|apktool|frida|x64dbg|ghidra)(?=$|[^A-Za-z0-9_.-])/i,
		why: "逆向工具链（radare2 / r2 / jadx / apktool / frida / x64dbg / ghidra）",
	},
	{
		// 第 2 轮补洞：这些直接读/取目标的结构或把目标跑起来，同样属于「动分析工具」。
		re: /(^|[^A-Za-z0-9_.-])(rabin2|objdump|readelf|strings)(?=$|[^A-Za-z0-9_.-])/i,
		why: "二进制结构工具（rabin2 / objdump / readelf / strings）",
	},
	{
		// `file x.exe` 命中；`--file a.json` 因为前面是 `-` 不算（边界排除了 `-`）
		re: /(^|[^A-Za-z0-9_.-])file\s+[^\s-]/i,
		why: "文件类型识别 file（对着目标取值）",
	},
	{
		re: /(^|[^A-Za-z0-9_.-])(curl|wget|ncat)(?=$|[^A-Za-z0-9_.-])/i,
		why: "联网取物（curl / wget / ncat）",
	},
	{
		re: /(^|[^A-Za-z0-9_.-])nc\s+/i,
		why: "netcat 连接（nc）",
	},
];

/** 解释器内联执行：`python -c` / `python - <<'PY'` / `powershell -c` / `node -e` … */
const INLINE_EXEC =
	/(^|[^A-Za-z0-9_.-])(python[0-9.]*|py|pwsh|powershell|node|perl|ruby|php)(?=$|[^A-Za-z0-9_.-])[^\n;&|]*?\s(?:-c\b|-e\b|--command\b|-\s*<<)/i;

/** 内联体里出现这些 → 才算「在动分析工具 / 在联网」，否则 `python -c "print(1)"` 不拦。 */
const INLINE_SUSPECT =
	/(^|[^A-Za-z0-9_.-])(rabin2|objdump|readelf|strings|file|curl|wget|ncat|nc|socket|requests|urllib|httpx?)(?=$|[^A-Za-z0-9_.-])/i;

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
	{ re: /launch-gui\.ps1/i, why: "调用 launch-gui.ps1（它内部会拉起目标进程）" },
	{
		re: /(^|[^A-Za-z0-9_.-])start-process(?=$|[^A-Za-z0-9_-])/i,
		why: "Start-Process 拉起进程",
	},
	{ re: /(^|[^A-Za-z0-9_.-])wine(64)?\s+/i, why: "用 wine 跑 Windows 程序" },
	{
		// PowerShell 调用运算符：`& "<盘>:/tools/a.exe"`
		re: /&\s*["']?[A-Za-z]:[\\/]/,
		why: "PowerShell 调用运算符 & 直接执行盘符路径",
	},
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
	const never = Array.isArray(g.never_writable)
		? g.never_writable.filter((x): x is string => typeof x === "string").map((s) => s.trim()).filter(Boolean)
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
		// 契约里的 never_writable 只能**加**：硬编码的凭证/规则永远在名单里
		neverWritable: mergeNeverWritable(never),
	};
}

/** 合并禁写名单：硬编码兜底 + 契约追加（去重、保序）。 */
export function mergeNeverWritable(extra: string[]): string[] {
	const out: string[] = [];
	const seen = new Set<string>();
	for (const p of [...NEVER_WRITABLE, ...extra]) {
		// 归一化：结尾的 `/**` 与不带星号是同一棵树（`~/.pi/agent` vs `~/.pi/agent/**`）
		const k = p.trim().replace(/\/\*\*$/, "").toLowerCase();
		if (!k || seen.has(k)) continue;
		seen.add(k);
		out.push(p.trim());
	}
	return out;
}

/** 当前生效的永久禁写名单（契约只能加、不能减）。 */
export function neverWritableList(gate: GateConfig = DEFAULT_GATE): string[] {
	return mergeNeverWritable(Array.isArray(gate.neverWritable) ? gate.neverWritable : []);
}

/**
 * 属于「分析类」的工具名（第 4 轮 P0-3）：`seep_*` 或**任意** `mcp__<server>__*`。
 * 只认 `seep_*` 时，`mcp__x64dbg__load_binary` / `mcp__ida__decompile` 可以绕开首答直接开工。
 */
function isAnalysisToolName(name: string): boolean {
	const n = name.toLowerCase();
	return n.startsWith("seep_") || n.startsWith("mcp__");
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
		// 第 4 轮 P0-4：exec_tools 会**在本机跑**分析命令，首答之外还要运行回执（见 classifyRunTarget）
		if (gate.execTools.includes(bareToolName(lname))) {
			return { analysis: true, why: "可执行分析工具 " + name + "（首答 + 运行回执都要求）" };
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

/**
 * 标记有效性：文件存在 + schema 对 + **不是 adhoc** + contract_sha256 与当前契约一致 + at 在 ttl 内。
 * 契约哈希拿不到（空串）时由 shouldBlock 决定「只告警」——这里只报「无法判定」。
 *
 * 第 4 轮 P0-2：`--adhoc` 写的临时首答（标记里 `"adhoc": true`）**不得当通行证**：
 * 它没绑案子、没绑目标，拿它开工等于把「临时问一句」变成「跳过首答」。
 * 返回里同时给 `valid`（布尔）和 `reason`（机器可读码），`why` 是给人看的一句话。
 */
export type MarkerState = { ok: boolean; valid: boolean; reason: string; why: string };

export function markerState(
	marker: unknown,
	contractHash: string,
	now: number,
	ttlMs: number = TTL_MS,
): MarkerState {
	const m = asRecord(marker);
	if (marker === null || marker === undefined || Object.keys(m).length === 0) {
		return {
			ok: false,
			valid: false,
			reason: "no-marker",
			why: "没有首答记录（" + markerPath() + " 不存在或读不出）",
		};
	}
	if (asText(m.schema) !== MARKER_SCHEMA) {
		return {
			ok: false,
			valid: false,
			reason: "bad-schema",
			why: "标记格式不是 " + MARKER_SCHEMA + "（可能被手改坏了）",
		};
	}
	// 第 4 轮 P0-2：adhoc 临时首答 = 无效凭证（字段在就判，不看值真假：`"adhoc":"x"` 也不认）
	if (m.adhoc === true || m.adhoc === "true" || (typeof m.adhoc === "string" && m.adhoc.trim() !== "")) {
		return {
			ok: false,
			valid: false,
			reason: "adhoc-not-a-pass",
			why: "临时首答不能当通行证，请绑案子重跑 `answer --check --case`（标记里写着 adhoc=true）",
		};
	}
	const got = asText(m.contract_sha256).trim().toLowerCase();
	if (!got) {
		return { ok: false, valid: false, reason: "no-contract-sha", why: "标记里没有 contract_sha256" };
	}
	if (!contractHash) {
		return {
			ok: false,
			valid: false,
			reason: "no-contract-hash",
			why: "拿不到当前 answer-contract.json 的哈希，无法比对",
		};
	}
	if (got !== contractHash.trim().toLowerCase()) {
		return {
			ok: false,
			valid: false,
			reason: "contract-changed",
			why: "首答契约已变（answer-contract.json 的 sha256 与标记不一致），上一份首答不再算数",
		};
	}
	const atRaw = asText(m.at).trim();
	const at = Date.parse(atRaw);
	if (!Number.isFinite(at)) {
		return {
			ok: false,
			valid: false,
			reason: "bad-time",
			why: "标记里的 at 不是合法时间（" + (atRaw || "空") + "）",
		};
	}
	const age = now - at;
	const ttl = Number.isFinite(ttlMs) && ttlMs > 0 ? ttlMs : TTL_MS;
	if (age > ttl) {
		const mins = Math.round(age / 60000);
		return {
			ok: false,
			valid: false,
			reason: "expired",
			why: "首答记录已过期（" + mins + " 分钟前写的，闸只认 " + Math.round(ttl / 60000) + " 分钟内）",
		};
	}
	return { ok: true, valid: true, reason: "ok", why: "" };
}

/** 某案登记过的目标（`case.json` 的 `target_files[].path` 与 `target`/`target_path`/`target_type`）。 */
export type CaseTargets = { dir: string; paths: string[]; targetSha256: string };

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
		for (const tok of cmd.split(/\s+/)) {
			for (const part of tok.split("=")) {
				if (part && looksLikePath(part)) out.push(cleanToken(part));
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

/**
 * 第 2 轮批评③：标记带 case 时，本次参数里的路径必须落在该案登记的
 * `target_files`/`target` 下（或就在案件目录里），否则视为「换了目标」。
 * 返回 "" 表示不冲突（或无从判定：没有路径 / 没有 case / 没有 case.json）。
 */
const _shaCache = new Map<string, { key: string; sha: string }>();

/** 目标文件的内容哈希（带 size+mtime 缓存；读不了返回空串）。
 *  ★ 为什么需要它：第 4 轮评审 P1——标记里的 `target_sha256` 只被写、从不比较，
 *    于是"同一路径换掉文件内容"仍算同一个目标，旧首答继续有效。
 */
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
	const caseDir = asText(asRecord(marker).case).trim();
	if (!caseDir) return "";
	const paths = extractPaths(toolName, args);
	if (paths.length === 0) return "";
	const dir = path.resolve(caseDir);
	const targets = caseTargets.paths.map((p) => path.resolve(dir, p));
	const baseNames = new Set<string>();
	for (const t of targets) {
		const b = path.basename(cmpKey(t));
		if (b) baseNames.add(b);
	}
	const hit = paths.some((p) => {
		const abs = path.resolve(p);
		if (under(abs, dir)) return true;
		if (targets.some((t) => under(abs, t))) return true;
		const b = path.basename(cmpKey(abs));
		return b.length > 0 && baseNames.has(b);
	});
	// 内容哈希比对：路径对得上不等于"还是那个文件"。
	const mt = asText(asRecord(marker).target_sha256).trim().toLowerCase();
	if (mt.length >= 12) {
		const files = paths.filter((p) => {
			try {
				return fs.statSync(p).isFile();
			} catch {
				return false;
			}
		});
		if (files.length > 0) {
			const anyMatch = files.some((p) => {
				const h = fileSha256(p);
				if (!h) return false;
				if (h === mt) return true;
				const n = Math.min(mt.length, h.length);
				return mt.slice(0, n) === h.slice(0, n) && n >= 12;
			});
			if (!anyMatch) {
				return (
					"目标内容已变（与首答时登记的哈希不同：标记 " +
					mt.slice(0, 12) +
					"…）：同一个路径换了文件也要重新给首答"
				);
			}
		}
	}
	if (hit) return "";
	return "本次参数里的路径（" + paths.slice(0, 2).join(" / ") + "）不在该案 case.json 的 target_files/target 下";
}

/** block 文案：必须是「照着抄就能过」的三步，并且说清这是闸不是报错。 */
export function buildBlockReason(
	toolName: string,
	why: string,
	markerWhy: string,
	gate: GateConfig = DEFAULT_GATE,
): string {
	const mins = Math.round(gate.ttlMinutes);
	return [
		"[answer-gate] 已拦下：" + toolName + "（" + why + "）",
		"",
		"**这是一道闸，不是报错。** 它只要求一件事：在动分析工具之前，先把首答四要素说出来。",
		"拦下原因：" + markerWhy,
		"",
		"冷启动顺序（三步走，第一步不会被拦）：`init`（不拦）→ `answer --check --case` → 再分析。",
		"  还没有案件目录：python Tool/scripts/case_state.py init --case <案件目录> --target <目标文件>（不拦，随便跑）",
		"",
		"照着抄三步（第 1 步只是打印骨架，可以直接复制）：",
		"",
		"  1) python Tool/scripts/case_state.py answer --template",
		"",
		"  2) 按骨架填成一份 JSON（四要素：judgment 判断 / ceiling 到哪一步 / missing 缺什么 / effort 大约多少功夫；missing 里必须含「授权来源：本人自有|书面授权|公开靶场|开源」之一），",
		"     存成 a.json，例如：",
		'        {"judgment":"PE32+，未见壳，关键在校验函数","ceiling":"只能看懂结构",',
		'         "missing":["授权来源：本人自有","有没有卡密"],',
		'         "effort":"1-2 小时；依据：未见壳、纯本地判定，读一遍导入表即可定性"}',
		"",
		"  3) python Tool/scripts/case_state.py answer --check --file a.json --case <本案目录>",
		"",
		"看到 [PASS] → 会自动写 " + markerPath() + "（" + mins + " 分钟内有效），把刚才那条命令原样重发即可。",
		"看到 [缺] … → 按提示补，补完再跑第 3 步；不合格不会写标记。",
		"",
		"（ceiling 只认四句之一：只能看懂结构 / 能改到能用 / 能完全自己接管 / 现在做不了 —— 取自 answer-contract.json）",
		"",
		"**怕「首答只能靠猜」？两条路都合法（第 3 轮 P0-3）：**",
		"",
		"  · 要提前看结构，先跑 case_state.py answer --template 写首答，再用 triage：",
		"    首答里的「判断」允许是一句带保留的话（例如「PE32+，看起来未加壳，关键在校验函数；待 triage 确认」），",
		"    只要四要素齐、effort 带区间和依据。过了闸就能直接调 seep_auto_triage / seep_packer_detect / seep_apk_info。",
		"  · 或者让用户直接给你判断：「这文件你从哪拿的？有卡密吗？双击过吗？报什么错？」",
		"    把他说的话写进 judgment / missing，同样能过闸。",
		"",
		"永远放行的只有**纯读取**五个：" + gate.whitelist.join(" / ") + "（seep_r2_info 只看架构/位数）。",
		"seep_auto_triage / seep_packer_detect / seep_apk_info 会读目标里的内容 —— 那是「分析」，请先给首答。",
	].join("\n");
}

/** 「换了目标」的专用文案：不复用三步，而是明说要重新给首答。 */
export function buildTargetBlockReason(toolName: string, why: string, mismatch: string, marker: unknown): string {
	const m = asRecord(marker);
	const mt = asText(m.target_sha256).trim();
	return [
		"[answer-gate] 已拦下：" + toolName + "（" + why + "）",
		"",
		"拦下原因：" + mismatch + "。",
		"上一份首答绑的是另一个目标：case=" + (asText(m.case) || "（未指定）") +
			(mt ? " · target_sha256=" + mt.slice(0, 12) + "…" : ""),
		"",
		"**换了目标要重新给首答。** 首答里的「判断 / 缺什么 / 多少功夫」是针对某个目标的，",
		"换一个目标（另一份 exe/apk/固件）时那些结论不再成立，闸不让你拿旧首答去套新目标。",
		"",
		"照做（两步）：",
		"  1) python Tool/scripts/case_state.py answer --template   （按新目标重写四要素，存成 a.json）",
		"  2) python Tool/scripts/case_state.py answer --check --file a.json --case <新目标所在的案件目录>",
		"",
		"看到 [PASS] 后把刚才那条命令原样重发。",
		"（如果只是想读旧目标的资料：seep_kb_search / seep_kb_read / seep_case_read / seep_tool_discover / seep_r2_info 永远放行；",
		" seep_auto_triage / seep_packer_detect 会读目标内容，必须先给首答）",
	].join("\n");
}

/**
 * 纯函数闸门（可单测，不碰磁盘）：
 *   toolName     工具名（`seep_auto_triage` / `bash` / `read` …）
 *   marker       已读出的标记对象（读不到传 null）
 *   contractHash 当前 answer-contract.json 的 sha256（读不到传 ""）
 *   now          epoch ms
 *   gate         answer-contract.json 的 `gate` 块（默认 DEFAULT_GATE）
 *   caseTargets  标记 case 的登记目标（bindTarget 打开时由调用方读盘传入，纯函数只做比较）
 * 返回 block=true 时 reason 即给模型看的完整文案。
 */
export function shouldBlock(
	toolName: string,
	args: unknown,
	marker: unknown,
	contractHash: string,
	now: number,
	gate: GateConfig = DEFAULT_GATE,
	caseTargets: CaseTargets | null = null,
): { block: boolean; reason: string; analysis: boolean } {
	const cls = classifyTool(toolName, args, gate);
	if (!cls.analysis) return { block: false, reason: "", analysis: false };
	// 读不到契约 → 只告警不拦：一次半截落盘不该把整个工作台锁死
	if (!contractHash) {
		return {
			block: false,
			reason: "[answer-gate][WARN] 读不到 Tool/config/answer-contract.json，本次放行（闸降级为提示）",
			analysis: true,
		};
	}
	const ttlMs = Math.round(gate.ttlMinutes * 60000);
	const st = markerState(marker, contractHash, now, ttlMs);
	if (!st.ok) return { block: true, reason: buildBlockReason(toolName, cls.why, st.why, gate), analysis: true };
	if (gate.bindTarget) {
		const mismatch = targetMismatch(toolName, args, marker, caseTargets);
		if (mismatch) {
			return { block: true, reason: buildTargetBlockReason(toolName, cls.why, mismatch, marker), analysis: true };
		}
	}
	return { block: false, reason: "", analysis: true };
}

/* ─────────────────── 运行目标闸（纯函数层，第 3 轮 P0-4）─────────────────── */

/**
 * 单段命令 → 是不是「要把目标拉起来跑」。
 * 关键区分：**看文件**（ls *.exe / find -name *.exe / grep .exe README）不拦，
 *           **执行文件**（./a.exe / Start-Process a.exe / cmd /c a.exe / wine a.exe）拦。
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
	// 第 4 轮 P0-4：`gate.exec_tools`（当前 seep_r2_cmd）名字本身就是「在本机跑分析命令」→
	// 除首答外还要运行回执；它不依赖命令文本，所以放在 bash 判定之前。
	const bare = bareToolName(lname);
	if (gate.execTools.includes(bare) || gate.execTools.includes(lname)) {
		return { run: true, why: "可执行分析工具 " + name + "（会在本机对目标跑命令）" };
	}
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

/**
 * 回执带 case 时，本次命令里的目标路径必须落在该案 case.json 的 `target_files`/`target` 下
 * （basename 匹配允许「cwd 下的相对路径」对上「案件目录里的登记路径」）。
 * 返回 "" = 不冲突。
 */
export function runTargetMismatch(
	toolName: string,
	args: unknown,
	caseDir: string,
	caseTargets: CaseTargets | null,
): string {
	if (!caseDir) return "";
	const paths = extractPaths(toolName, args);
	if (paths.length === 0) return "";
	const dir = path.resolve(caseDir);
	const targets = (caseTargets?.paths ?? []).map((p) => path.resolve(dir, p));
	const baseNames = new Set<string>();
	for (const t of targets) {
		const b = path.basename(cmpKey(t));
		if (b) baseNames.add(b);
	}
	const hit = paths.some((p) => {
		const abs = path.resolve(p);
		if (under(abs, dir)) return true;
		if (targets.some((t) => under(abs, t))) return true;
		const b = path.basename(cmpKey(abs));
		return b.length > 0 && baseNames.has(b);
	});
	if (hit) return "";
	const tail =
		targets.length === 0
			? "（该案 case.json 没登记 target_files/target，闸只能按「路径在案件目录内」判定）"
			: "";
	return (
		"本次命令里的目标（" + paths.slice(0, 2).join(" / ") + "）不在该案 case.json 登记的目标下" + tail
	);
}

/**
 * 运行回执有效性：文件存在 + schema 对 + **letter ∈ {A, C}** + at 在 `gate.run_ack.ttl_minutes` 内
 * （+ `require_case_target` 打开且回执带 case 时，目标要落在该案 case.json 下）。
 *
 * 第 4 轮 P0-3：原来只看「有没有字母」—— `ack --choice B`（先别运行）也会开闸。
 * 现在 B 与任何其它字母一律 block；`reason` 给出机器可读码（`letter-b` / `letter-not-allowed`）。
 */
export type RunAckState = { ok: boolean; why: string; mismatch: boolean; reason: string };

export function runAckState(
	runAck: unknown,
	now: number,
	cfg: RunAckConfig = DEFAULT_GATE.runAck,
	toolName = "",
	args: unknown = {},
	caseTargets: CaseTargets | null = null,
): RunAckState {
	const a = asRecord(runAck);
	if (runAck === null || runAck === undefined || Object.keys(a).length === 0) {
		return {
			ok: false,
			why: "没有运行回执（" + runAckPath() + " 不存在或读不出）",
			mismatch: false,
			reason: "no-ack",
		};
	}
	if (asText(a.schema) !== RUN_ACK_SCHEMA) {
		return {
			ok: false,
			why: "回执格式不是 " + RUN_ACK_SCHEMA + "（可能被手改坏了）",
			mismatch: false,
			reason: "bad-schema",
		};
	}
	const letter = asText(a.letter).trim().toUpperCase();
	if (!letter) {
		return {
			ok: false,
			why: "回执里没有 letter（用户选了哪个字母）",
			mismatch: false,
			reason: "no-letter",
		};
	}
	if (!RUN_OK_LETTERS.has(letter)) {
		if (letter === "B") {
			return {
				ok: false,
				why: "用户在卡上选了 B（先别运行）：请改用静态分析或重新征求同意",
				mismatch: false,
				reason: "letter-b",
			};
		}
		return {
			ok: false,
			why: "回执里 letter=" + letter + " 不在闸允许的 {A, C} 内（A 允许本机运行 / C 用户自己运行你观察）：视为未同意",
			mismatch: false,
			reason: "letter-not-allowed",
		};
	}
	const atRaw = asText(a.at).trim();
	const at = Date.parse(atRaw);
	if (!Number.isFinite(at)) {
		return {
			ok: false,
			why: "回执里的 at 不是合法时间（" + (atRaw || "空") + "）",
			mismatch: false,
			reason: "bad-time",
		};
	}
	const mins = Number.isFinite(cfg.ttlMinutes) && cfg.ttlMinutes > 0 ? cfg.ttlMinutes : RUN_ACK_TTL_MINUTES;
	const age = now - at;
	if (age > mins * 60000) {
		return {
			ok: false,
			why: "运行回执已过期（" + Math.round(age / 60000) + " 分钟前记的，闸只认 " + Math.round(mins) + " 分钟内）",
			mismatch: false,
			reason: "expired",
		};
	}
	if (age < -5 * 60000) {
		return { ok: false, why: "回执时间在过去之后（时钟不对，或文件被改），不认", mismatch: false, reason: "future" };
	}
	const caseDir = asText(a.case).trim();
	if (!cfg.requireCaseTarget || !caseDir) return { ok: true, why: "", mismatch: false, reason: "ok" };
	const bad = runTargetMismatch(toolName, args, caseDir, caseTargets);
	if (bad) return { ok: false, why: bad, mismatch: true, reason: "target-mismatch" };
	return { ok: true, why: "", mismatch: false, reason: "ok" };
}

/** 运行目标闸的 block 文案：三步必须能照抄（发卡 → ack → 重发）。 */
export function buildRunBlockReason(
	toolName: string,
	why: string,
	stateWhy: string,
	cfg: RunAckConfig = DEFAULT_GATE.runAck,
	caseHint = "",
	runAck: unknown = null,
): string {
	const C = caseHint || "<C>";
	const a = asRecord(runAck);
	const mins = Math.round(Number.isFinite(cfg.ttlMinutes) && cfg.ttlMinutes > 0 ? cfg.ttlMinutes : RUN_ACK_TTL_MINUTES);
	const prevCase = asText(a.case).trim();
	return [
		"[run-gate] 已拦下：" + toolName + "（这条命令会在本机把目标程序拉起来）",
		"",
		"拦下原因：" + why,
		"回执状态：" + stateWhy,
		...(prevCase ? ["上一张回执绑的是：case=" + prevCase] : []),
		"",
		"**这是一道闸，不是报错。** 在这台机器上运行客户的目标程序，必须先拿到用户明确的一句“可以”。",
		"闸只认 " + runAckPath() + "（由 case_state.py ack 写入，" + mins + " 分钟内有效、且绑本案目标）。",
		"字母只认 A（允许在本机运行）与 C（用户自己运行、你只观察）；B（先别运行）与其它字母一律不开闸。",
		"",
		"照着抄三步（" + C + " = 本案目录）：",
		"",
		"  1) 发一张卡问用户「允许在本机运行它吗」：",
		"     python Tool/scripts/case_state.py ask --case " + C + " \\",
		'       --stuck "允许我在本机运行目标程序吗（要拉起它）" \\',
		'       --option "A 允许在本机运行（只跑目标，不改系统设置、不联网）" \\',
		'       --option "B 先别运行，只做静态分析" \\',
		'       --option "C 我自己双击运行，你只观察"',
		"     把输出里那段【需要你选】**原样贴进对话**，然后停下等字母。",
		"",
		"  2) 用户回了字母之后，记录回执（成功会原子写 " + runAckPath() + "）：",
		"     python Tool/scripts/case_state.py ack --case " + C + " --id <卡id> --choice <字母>",
		"     （当前 CLI 的等价写法：python Tool/scripts/case_state.py ack --case " + C + " --ack <字母>）",
		"",
		"  3) 看到 [ACK] … 之后，把刚才那条命令**原样重新发一遍** —— 闸会自动放行。",
		"",
		"不想走这条路时的合法做法：",
		"  · 只看文件清单/结构：ls / dir / find / grep（不执行）永远放行；",
		"  · 让用户自己双击运行，你只拿他说看到什么（把结论写进首答的 missing / 下一步）。",
	].join("\n");
}

/** 运行目标闸的纯函数判定（不碰磁盘；回执与 caseTargets 由调用方读）。 */
export function shouldBlockRun(
	toolName: string,
	args: unknown,
	runAck: unknown,
	now: number,
	gate: GateConfig = DEFAULT_GATE,
	caseTargets: CaseTargets | null = null,
	caseHint = "",
): { block: boolean; reason: string; run: boolean } {
	const cls = classifyRunTarget(toolName, args, gate);
	if (!cls.run) return { block: false, reason: "", run: false };
	const st = runAckState(runAck, now, gate.runAck, toolName, args, caseTargets);
	if (st.ok) return { block: false, reason: "", run: true };
	return { block: true, reason: buildRunBlockReason(toolName, cls.why, st.why, gate.runAck, caseHint, runAck), run: true };
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

/**
 * 永久禁写判定（第 4 轮 P0-1/P0-4）：凭证 / 闸规则 / 契约 / 提示词。
 * 两种写法：
 *   · 双星斜杠前缀（两个星号 + 斜杠 + 文件名）→ 任意目录下的同名文件（AGENTS.md、cmd-guard.rules.json…）
 *   · 具体路径（可带 `~`，可选结尾 `/**`）→ 该路径本身及其子树。
 * 大小写不敏感（Windows 不区分；这几个名字也不会因大小写误伤别的文件）。
 */
export function isNeverWritable(
	rawPath: string,
	patterns: string[] = NEVER_WRITABLE,
): { hit: boolean; pattern: string } {
	const abs = cmpKey(path.resolve(expandHome(rawPath))).toLowerCase();
	if (!abs) return { hit: false, pattern: "" };
	for (const raw of patterns) {
		const p = (raw || "").trim();
		if (!p) continue;
		if (/^\*\*\//.test(p)) {
			const suffix = p.slice(3).replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
			if (!suffix) continue;
			if (abs === suffix || abs.endsWith("/" + suffix)) return { hit: true, pattern: p };
			continue;
		}
		const s = p.endsWith("/**") ? p.slice(0, -3) : p;
		const pat = cmpKey(path.resolve(expandHome(s))).toLowerCase();
		if (!pat) continue;
		if (abs === pat || abs.startsWith(pat + "/")) return { hit: true, pattern: p };
	}
	return { hit: false, pattern: "" };
}

/** 禁写的专用文案：说清楚「为什么」、「谁才能写」、「怎么让用户确认」。 */
export function buildNeverWriteReason(raw: string, pattern: string): string {
	return [
		"[write-guard] 已拦下：写 " + raw + "（命中永久禁写规则 " + pattern + "）",
		"",
		"**闸的凭证与规则不允许由 Agent 写；要让用户确认，请出 A/B/C 卡。**",
		"",
		"永久禁写：" + NEVER_WRITABLE.join(" / ") + "。",
		"这条优先级高于所有允许根（`Tool/` 可写也压不住它）：凭证只能由 `case_state.py answer/ack` 写，",
		"契约/闸规则/提示词只能由用户在会话里明确确认后由人改。",
		"",
		"要让用户确认，请发一张 A/B/C 卡（不要在文件夹里“自己批准自己”）：",
		"  python Tool/scripts/case_state.py ask --case <本案目录> \\",
		'    --stuck "<你要用户确认什么>" \\',
		'    --option "A <选了会怎样>" --option "B <选了会怎样>" --option "C <选了会怎样>"',
	].join("\n");
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
	try {
		const c = asText(asRecord(readMarker()).case).trim();
		if (c) out.push(c);
	} catch {
		/* 没有就算了 */
	}
	return out;
}

/**
 * 允许写的位置：案件目录、`work/`、`Tool/`、`~/.seep/`、`~/.pi/agent/`、系统临时目录。
 * 注意（第 4 轮 P0-1）：「允许写 `~/.seep/` / `~/.pi/agent/`」里的凭证与规则类文件
 * 被 NEVER_WRITABLE 压住 —— 允许根只管目录，禁写名单优先级更高。
 * 读类工具不经过这里。
 */
export function writeAllowRoots(cwd: string = process.cwd()): string[] {
	const roots: string[] = tempRoots();
	const repo = findRepoRoot(cwd);
	const base = repo || path.resolve(cwd);
	roots.push(path.join(base, "Tool"), path.join(base, "work"));
	const home = os.homedir();
	roots.push(path.join(home, ".seep"), path.join(home, ".pi", "agent"));
	for (const c of currentCaseDirs()) roots.push(c);
	return roots;
}

export function buildWriteBlockReason(raw: string): string {
	return [
		"[write-guard] 已拦下：写 " + raw,
		"",
		"**只许写案件目录或 work/；要改仓库请明确说明。**",
		"放行的位置：案件目录（Tool/cases/<case>/ 或 ~/.seep/current-case 指的目录）、work/、Tool/、",
		"           ~/.seep/、~/.pi/agent/、系统临时目录。",
		"（凭证（answer-pass.json / run-ack.json / current-case）、cmd-guard.rules.json、answer-contract.json、",
		" AGENTS.md、SEEP.md 在这些目录里也**永久禁写** —— 它们不是代码，是闸本身。）",
		"",
		"要改仓库本体（Tool/ 之外的文件）：先跟用户说清「改哪个文件、为什么改、影响什么」，得到确认再动。",
		"读类工具（read/grep/find/ls）不受这条限制。",
	].join("\n");
}

/**
 * 纯函数写入判定（三道判定，优先级从高到低）：
 *   1) 命中 NEVER_WRITABLE（凭证 / 闸规则 / 契约 / 提示词）→ block（不受允许根影响）
 *   2) 在临时目录或允许根下 → 放行
 *   3) 其余 → block（文案：要改仓库请明确说明）
 *   toolName 工具名（write/edit/apply_patch …）
 *   args     工具入参（取 path/file_path/…）
 *   roots    允许写的根（由 writeAllowRoots() 现算）
 *   temp     临时目录判定（可注入，便于单测）
 *   never    永久禁写名单（默认硬编码兜底 + 契约追加，可注入）
 */
export function writeDecision(
	toolName: string,
	args: unknown,
	roots: string[],
	temp: (p: string) => boolean = isTempPath,
	never: string[] = NEVER_WRITABLE,
): { block: boolean; reason: string; code: string } {
	const lname = toolName.trim().toLowerCase();
	if (!WRITE_TOOLS.has(lname)) return { block: false, reason: "", code: "not-write" };
	const raw = writeTargetPath(args);
	if (!raw) return { block: false, reason: "", code: "no-path" };
	// 1) 永久禁写优先于一切允许根（这是第 4 轮 P0-1 的核心）
	const nv = isNeverWritable(raw, never);
	if (nv.hit) return { block: true, reason: buildNeverWriteReason(raw, nv.pattern), code: "never-writable" };
	// 2) 允许根 / 临时区
	const abs = path.resolve(expandHome(raw));
	if (temp(abs) || roots.some((r) => under(abs, r))) return { block: false, reason: "", code: "allowed" };
	// 3) 其余一律拦
	return { block: true, reason: buildWriteBlockReason(raw), code: "outside-roots" };
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

/** 读运行回执（`~/.seep/run-ack.json`）：与 readMarker 同一套容错（读不到 = null → block）。 */
export function readRunAck(p = runAckPath()): unknown {
	return readMarker(p);
}

/** 当前案件目录提示（`~/.seep/current-case`）：只用于把 block 文案里的 `<C>` 填成真实路径。 */
export function currentCaseHint(): string {
	try {
		return fs.readFileSync(path.join(os.homedir(), ".seep", "current-case"), "utf-8").trim();
	} catch {
		return "";
	}
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
		const tfiles = cj.target_files;
		if (Array.isArray(tfiles)) {
			for (const it of tfiles) {
				const r = asRecord(it);
				const p = asText(r.path).trim();
				if (p) paths.push(p);
				const s = asText(r.sha256).trim();
				if (s) shas.push(s);
			}
		}
		for (const k of ["target", "target_path", "target_type"]) {
			// 注：case_state.py 的 case.json 骨架把目标路径写在 `target_type` 里（历史字段名），也得认
			const v = asText(cj[k]).trim();
			if (v && !/^https?:\/\//i.test(v)) paths.push(v);
		}
		const data: CaseTargets = { dir, paths, targetSha256: shas.length > 0 ? shas[0] : "" };
		caseCache = { file, mtimeMs: st.mtimeMs, data };
		return data;
	} catch {
		return null;
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
			const gate = gateConfig();
			// 先分类：读类工具连标记文件都不读（不去碰磁盘，就不可能误伤它）
			if (!classifyTool(tool, args, gate).analysis) return undefined;
			const marker = readMarker();
			const caseDir = asText(asRecord(marker).case).trim();
			// 目标绑定要读该案 case.json：读不到只告警（降级为提示），不锁死人
			const caseTargets = gate.bindTarget && caseDir ? readCaseTargets(caseDir) : null;
			const v = shouldBlock(tool, args, marker, contractHash(), Date.now(), gate, caseTargets);
			if (!v.block) {
				if (v.reason) console.warn(v.reason);
				if (gate.bindTarget && caseDir && !caseTargets) {
					console.warn("[answer-gate][WARN] 读不到 " + caseDir + "/case.json → 本次不做目标绑定检查");
				}
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

	/**
	 * 写入守卫（第 2 轮评审第 4 条）：第二个 tool_call handler。
	 * 只对 write/edit 这类写工具生效 —— 读类工具完全不经过判定。
	 */
	pi.on("tool_call", (event: unknown) => {
		try {
			const e = asRecord(event);
			const tool = asText(e.toolName ?? e.name);
			const args = e.input ?? e.args;
			const gate = gateConfig();
			const v = writeDecision(tool, args, writeAllowRoots(), isTempPath, neverWritableList(gate));
			if (!v.block) return undefined;
			if (disabledByEnv()) {
				console.warn("[write-guard] SEEP_ANSWER_GATE=0 → 写入守卫被人工关闭，本次放行：" + tool);
				return undefined;
			}
			return { block: true, reason: v.reason };
		} catch {
			// 守卫自己出错 → 放行（不能因为守卫的 bug 把写盘全锁死）
			return undefined;
		}
	});

	/**
	 * 运行目标闸（第 3 轮评审 P0-4）：第三个 tool_call handler。
	 *
	 * 为什么单开一道：首答闸管的是「先说话再分析」，这道管的是「用户允许了才在本机运行」。
	 * 两件事没有包含关系 —— 首答写得再全，也不等于用户同意在这台机器上双击客户的东西。
	 *
	 * 拦点选在**命令文本层**：`launch-gui.ps1` 自己内部会再拉子进程，所以不必去拦子进程。
	 */
	pi.on("tool_call", (event: unknown) => {
		try {
			const e = asRecord(event);
			const tool = asText(e.toolName ?? e.name);
			const args = e.input ?? e.args;
			const gate = gateConfig();
			// 先分类：不是「要运行目标」的命令，连回执文件都不读
			// （exec_tools 如 seep_r2_cmd 也算「要运行」→ 必须在这里用同一份 gate 分类）
			if (!classifyRunTarget(tool, args, gate).run) return undefined;
			const ack = readRunAck();
			const ackCase = asText(asRecord(ack).case).trim();
			const caseTargets = ackCase ? readCaseTargets(ackCase) : null;
			const hint = currentCaseHint() || ackCase;
			const v = shouldBlockRun(tool, args, ack, Date.now(), gate, caseTargets, hint);
			if (!v.block) {
				if (gate.runAck.requireCaseTarget && ackCase && !caseTargets) {
					console.warn("[run-gate][WARN] 读不到 " + ackCase + "/case.json → 本次不做目标绑定检查");
				}
				return undefined;
			}
			if (disabledByEnv()) {
				console.warn("[run-gate] SEEP_ANSWER_GATE=0 → 闸被人工关闭，本次放行：" + tool);
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
			description: "看三道闸的状态：/answer-gate（首答标记 / 运行回执 / 写入白名单）",
			handler: async (_args: string, ctx: unknown) => {
				const lines: string[] = ["[answer-gate] 首答标记=" + markerPath()];
				try {
					const cfg = loadContract();
					const file = findContract();
					lines.push(
						"  契约=" + (file || "（找不到，闸降级为提示）") + (cfg.hash ? " sha256=" + cfg.hash.slice(0, 12) + "…" : ""),
					);
					lines.push(
						"  策略=TTL " + cfg.gate.ttlMinutes + " 分钟 · 白名单 " + cfg.gate.whitelist.length + " 个 · 目标绑定=" +
							(cfg.gate.bindTarget ? "开" : "关") + " · adhoc=" + "一律无效",
					);
					lines.push(
						"  永久禁写=" + neverWritableList(cfg.gate).join(" / "),
					);
					const marker = readMarker();
					const st = markerState(marker, cfg.hash, Date.now(), Math.round(cfg.gate.ttlMinutes * 60000));
					lines.push("  状态=" + (st.ok ? "有效（非白名单分析类工具放行）" : "无效 → 分析类工具会被拦：" + st.why));
					const m = asRecord(marker);
					if (st.ok) {
						const caseDir = asText(m.case).trim();
						const ct = caseDir ? readCaseTargets(caseDir) : null;
						lines.push(
							"  写入时间=" + asText(m.at) + " · case=" + (caseDir || "（未指定）") + " · target_sha256=" +
								(asText(m.target_sha256) || "（未写入）"),
						);
						if (cfg.gate.bindTarget && caseDir) {
							lines.push(
								"  目标绑定=" +
									(ct
										? ct.paths.length > 0
											? ct.paths.slice(0, 3).join(" / ")
											: "（该案 case.json 没登记目标 → 不检查）"
										: "（读不到 case.json → 本次不检查）"),
							);
						}
					}
					if (disabledByEnv()) lines.push("  ★ SEEP_ANSWER_GATE=0：闸已被人工关闭（默认开）");
					lines.push(
						"  过首答闸：python Tool/scripts/case_state.py answer --template → 填四要素 → answer --check --file a.json --case <本案目录>",
					);
					// ── 运行目标闸（P0-4）的状态 ──
					lines.push("[run-gate] 运行回执=" + runAckPath());
					const ack = readRunAck();
					const ra = asRecord(ack);
					const ackCase = asText(ra.case).trim();
					const raSt = runAckState(
						ack,
						Date.now(),
						cfg.gate.runAck,
						"",
						{},
						ackCase ? readCaseTargets(ackCase) : null,
					);
					lines.push(
						"  策略=TTL " + cfg.gate.runAck.ttlMinutes + " 分钟 · 绑目标=" +
							(cfg.gate.runAck.requireCaseTarget ? "开" : "关") + " · 只认字母=" + Array.from(RUN_OK_LETTERS).join("/"),
					);
					lines.push(
						"  可执行工具（首答+回执）=" + (cfg.gate.execTools.length > 0 ? cfg.gate.execTools.join(" / ") : "（无）"),
					);
					lines.push(
						"  状态=" + (raSt.ok ? "有效（带本案目标的命令可以运行）" : "无效 → 运行目标的命令会被拦：" + raSt.why),
					);
					if (Object.keys(ra).length > 0) {
						lines.push(
							"  回执=" + asText(ra.letter) + " · at=" + asText(ra.at) + " · case=" + (ackCase || "（未指定）") +
								" · target_sha256=" + (asText(ra.target_sha256).slice(0, 12) || "（未写入）"),
						);
					}
					lines.push(
						"  过运行闸：case_state.py ask --case <C>（问「允许在本机运行它吗」）→ 用户回字母 → case_state.py ack --case <C> --ack <字母>",
					);
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
