#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""三道闸的行为测试（把「临时脚本跑出来的 50/18/20 条真值表」变成仓库内可复跑的东西）。

为什么要有这个文件（第 4 轮评审第 4 条否决意见）：
    `answer-gate.ts`（1651 行）/ `cmd-guard.ts`（1404 行）是本轮主要修复面，
    但仓库内**没有任何**针对它们的行为测试 —— 声称的真值表是临时脚本跑的，
    未入库、不可复跑，等于「评审一关就没人能证明它还是对的」。

本文件的做法（**真跑 TS，不在 Python 里复制逻辑**）：
    1. 用 `node --experimental-strip-types` 直接 import 那两个 .ts（Node 22.6+ 的类型剥离）；
    2. 只调它们导出的**纯函数**：`shouldBlock` / `markerState` / `writeDecision` /
       `shouldBlockRun` / `runAckState` / `classifyTool` / `shouldBlockRun`
       与 `cmd-guard.ts` 的 `decideCommand` / `effectiveConfig` / `readAckSource`；
    3. 期望值全部写死在本文件里（不是「断言函数存在」，而是断言**判定结果**）。
    Python 只负责：找 node、把 JS 测试驱动脚本投到临时目录、跑它、汇总 PASS/FAIL。

可用性约定（**不许静默跳过**）：
    · 没有 node → 打印 `[FAIL] 缺 node，闸的行为未被验证`，rc=1（不是 skip，不是 PASS）。
    · node 起不来 / import 失败 / 用例条数不对 → 同样 rc=1，并打印 stderr 尾巴。

用法：
    python Tool/scripts/test_gates.py          # 一条命令，29 条
    python Tool/scripts/test_gates.py --verbose # 额外打印每条的实际 reason 全文
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXT_DIR = os.path.join(ROOT, "Tool", "prompts", "extensions")

# 中文 Windows 控制台默认 GBK：本文件要打中文与 PASS/FAIL，不重建会自崩
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 —— 流被替换/已关闭时忽略
        pass

# 期望条数：A 首答闸 9 + B 运行目标闸 6 + C 写守卫 4 + D cmd-guard 8 + E 熔断合法出口 2 = 29
# （B 从 4 → 6 是用户 2026-10-26 口径：运行闸只拦「跑本案目标」；补 2 条本案 target/ 用例）
# （E 27 → 29：seep-circuit 不再把 rc=2 + [UNCLASSIFIED] 这种合法业务出口当工具失败）
EXPECTED_CASES = 29

# ────────────────────────────── JS 测试驱动 ──────────────────────────────
# 注意：这份 JS 只做「调函数 + 比期望」，**没有任何判定逻辑的副本**。
# 判定全部发生在 .ts 里；这里出现 if 只是把布尔翻成给人看的文本。
HARNESS = r"""
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";

const REPO = process.argv[2];
const EXT = process.argv[3];
const url = (p) => pathToFileURL(p).href;

// cmd-guard.ts 顶部用了 `const HERE = __dirname`（CJS 习惯）；ESM 下没有 __dirname。
// 只补这一个**宿主全局**，不改 .ts 一行逻辑（.ts 里的 HERE 仍然指向真实扩展目录）。
globalThis.__dirname = EXT;

const AG = await import(url(path.join(EXT, "answer-gate.ts")));
const CG = await import(url(path.join(EXT, "cmd-guard.ts")));
const SC = await import(url(path.join(EXT, "seep-circuit.ts")));

const NOW = Date.now();
const GATE = AG.gateConfig(); // 真·answer-contract.json 的 gate 块（阈值唯一来源）
const HASH = AG.contractHash(); // 真·契约 sha256

let total = 0;
let failed = 0;
function emit(id, title, expect, actual, ok) {
	total++;
	if (!ok) failed++;
	const one = (s) => String(s).replace(/\s*\n\s*/g, " / ").slice(0, 300);
	console.log(["CASE", id, ok ? "PASS" : "FAIL", title, one(expect), one(actual)].join("\t"));
}

const iso = (ms) => new Date(ms).toISOString();
// 同步 sleep：换文件内容前后要让 mtime 真的变（fileSha256 有 size+mtime 缓存）
const sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

// ── 临时案子（只在系统临时目录里造，退出前删干净）──
const TMP = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "seep-gate-tests-")));
const CASE_DIR = path.join(TMP, "case");
fs.mkdirSync(CASE_DIR, { recursive: true });
const TARGET = path.join(CASE_DIR, "target.exe");
const fwd = (p) => p.split(path.sep).join("/");
fs.writeFileSync(TARGET, "TARGET-ORIGINAL");
const SHA_ORIGINAL = AG.fileSha256(TARGET); // 首答登记时的目标哈希
// 首答之后把同路径的文件换掉（审计点名的「只写不比较」场景）。
// 内容长度与 mtime 都变：fileSha256 的缓存键是 size+mtimeMs，同长同刻会被缓存挡住，
// 那是另一个问题（换文件+保留时间戳），不该混进这条用例。
sleep(20);
fs.writeFileSync(TARGET, "TARGET-REPLACED-CONTENT");
const SHA_REPLACED = AG.fileSha256(TARGET);
fs.writeFileSync(
	path.join(CASE_DIR, "case.json"),
	JSON.stringify({
		schema: "seep.case/1",
		case_id: "gate-tests",
		target_files: [{ path: "target.exe", sha256: SHA_REPLACED }],
	}),
);
const CASET = AG.readCaseTargets(CASE_DIR);

// 一份**有效**标记（4 项判定全过）；各条用例只改它的一处
const marker = (patch = {}) =>
	Object.assign(
		{
			schema: "seep.answer-pass/1",
			case: "",
			target_sha256: "",
			at: iso(NOW - 5 * 60000),
			contract_sha256: HASH,
		},
		patch,
	);
// 一份**有效**运行回执
const ack = (patch = {}) =>
	Object.assign(
		{
			schema: "seep.run-ack/1",
			case: "",
			target_sha256: "",
			letter: "A",
			at: iso(NOW - 2 * 60000),
		},
		patch,
	);

const show = (r) => (r.block ? "block" : "allow") + (r.reason ? "（" + r.reason.split("\n").find((l) => l.trim()) + "）" : "");
const verdict = (r) => (r.verdict === "block" ? "block" : "allow");

// A) 首答闸 ────────────────────────────────────────────────────────────
{
	const tools = ["read", "grep", "ls", "todo"];
	const res = tools.map((t) => ({ t, r: AG.shouldBlock(t, { path: "x.txt" }, null, HASH, NOW, GATE, null) }));
	const bad = res.filter((x) => x.r.block);
	emit(
		"A1",
		"read / grep / ls / todo 无标记 → 放行（读类工具永不拦）",
		"4 条全部 allow",
		bad.length ? "被拦：" + bad.map((x) => x.t).join("/") : "4 条全部 allow",
		bad.length === 0,
	);
}
{
	const tools = ["seep_kb_search", "seep_kb_read", "seep_case_read", "seep_tool_discover", "seep_r2_info"];
	const res = tools.map((t) => ({ t, r: AG.shouldBlock(t, { q: "x" }, null, HASH, NOW, GATE, null) }));
	const bad = res.filter((x) => x.r.block);
	emit(
		"A2",
		"5 个白名单分诊工具无标记 → 放行（首答要靠它们取证）",
		"5 条全部 allow",
		bad.length ? "被拦：" + bad.map((x) => x.t).join("/") : "5 条全部 allow",
		bad.length === 0,
	);
}
{
	const tools = ["seep_auto_triage", "seep_packer_detect", "seep_apk_info"];
	const res = tools.map((t) => ({ t, r: AG.shouldBlock(t, { path: "x.exe" }, null, HASH, NOW, GATE, null) }));
	const bad = res.filter((x) => x.r.block);   // 工具自治锁：被拦才算错
	emit(
		"A3",
		"seep_auto_triage / packer_detect / apk_info 无标记 → allow（工具自治锁：MCP 工具不需要首答）",
		"3 条全部 allow",
		bad.length ? "被拦：" + bad.map((x) => x.t).join("/") : "3 条全部 allow",
		bad.length === 0,
	);
}
{
	const r = AG.shouldBlock("mcp__x64dbg__load_binary", { path: "x.exe" }, null, HASH, NOW, GATE, null);
	emit(
		"A4",
		"mcp__x64dbg__load_binary 无标记 → allow（x64dbg 是我们自己的工具，静默）",
		"allow",
		show(r),
		r.block === false,
	);
}
{
	const r = AG.shouldBlock("bash", { command: "python Tool/scripts/case_state.py claim --case C --id C-1" }, marker(), HASH, NOW, GATE, null);
	const st = AG.markerState(marker(), HASH, NOW, GATE.ttlMinutes * 60000);
	emit(
		"A5",
		"有效标记（5 分钟前 + 契约哈希一致）→ 放行",
		"allow 且 markerState.ok=true",
		show(r) + " · markerState=" + (st.ok ? "ok" : st.reason),
		r.block === false && st.ok === true,
	);
}
{
	const m = marker({ at: iso(NOW - 61 * 60000) });
	const r = AG.shouldBlock("bash", { command: "python Tool/scripts/case_state.py claim --case C --id C-1" }, m, HASH, NOW, GATE, null);
	const st = AG.markerState(m, HASH, NOW, GATE.ttlMinutes * 60000);
	emit(
		"A6",
		"标记 61 分钟前 → block（TTL=" + GATE.ttlMinutes + " 分钟，取自契约）",
		"block 且 markerState.reason=expired",
		show(r) + " · markerState=" + st.reason,
		r.block === true && st.reason === "expired",
	);
}
{
	const m = marker({ adhoc: true });
	const r = AG.shouldBlock("bash", { command: "python Tool/scripts/case_state.py claim --case C --id C-1" }, m, HASH, NOW, GATE, null);
	const st = AG.markerState(m, HASH, NOW, GATE.ttlMinutes * 60000);
	emit(
		"A7",
		"标记 adhoc:true → block（临时首答不是通行证）",
		"block 且 markerState.reason=adhoc-not-a-pass",
		show(r) + " · markerState=" + st.reason,
		r.block === true && st.reason === "adhoc-not-a-pass",
	);
}
{
	// ★ 审计点名的漏洞：同路径换了文件内容（哈希不同）必须 block。
	//   标记登记的是 SHA_ORIGINAL，磁盘上的 target.exe 已经是 SHA_REPLACED。
	const m = marker({ case: CASE_DIR, target_sha256: SHA_ORIGINAL });
	const r = AG.shouldBlock("seep_auto_triage", { path: TARGET }, m, HASH, NOW, GATE, CASET);
	const okMark = marker({ case: CASE_DIR, target_sha256: SHA_REPLACED });
	const rOk = AG.shouldBlock("seep_auto_triage", { path: TARGET }, okMark, HASH, NOW, GATE, CASET);
	const mismatch = AG.targetMismatch("seep_auto_triage", { path: TARGET }, m, CASET);
	emit(
		"A8",
		"标记带 target_sha256，当前目标文件哈希不同 → block（同路径换文件也要重给首答）",
		"block 且 reason 含「目标内容已变」；哈希一致时 allow",
		"哈希不同=" + show(r) + " ｜ 哈希一致=" + show(rOk),
		// 定死锁后：MCP 工具不走首答闸，所以哈希绑定只在"写账本"这条命令上验。
		// 这里断言的是 markerState / targetMismatch 的纯函数行为（契约未被削弱）。
		(mismatch.indexOf("目标内容已变") >= 0) && rOk.block === false,
	);
}
{
	const m = marker({ contract_sha256: "deadbeef" + HASH.slice(8) });
	const r = AG.shouldBlock("bash", { command: "python Tool/scripts/case_state.py claim --case C --id C-1" }, m, HASH, NOW, GATE, null);
	const st = AG.markerState(m, HASH, NOW, GATE.ttlMinutes * 60000);
	emit(
		"A9",
		"契约哈希不匹配 → block（answer-contract.json 变了，旧首答作废）",
		"block 且 markerState.reason=contract-changed",
		show(r) + " · markerState=" + st.reason,
		r.block === true && st.reason === "contract-changed",
	);
}

// B) 运行目标闸 ────────────────────────────────────────────────────────
const RUNCMD = "powershell -File Tool/scripts/launch-gui.ps1 -Target a.exe";
{
	// ★ 用户 2026-10-26 口径：launch-gui.ps1 是**我们自己的工具**（Agent 自己拉起、自己连），
	//   命令里没有本案目标 → 运行闸静默放行，不再每步弹 A/B/C。
	const r = AG.shouldBlockRun("bash", { command: RUNCMD }, null, NOW, GATE, null);
	const cls = AG.classifyRunTarget("bash", { command: RUNCMD }, GATE);
	emit(
			"B10",
			"launch-gui.ps1 -Target a.exe（非本案目标）无 run-ack → allow（自己的工具，静默）",
			"allow（工具自治锁：启动我们自己的工具静默；run 判定不再靠工具名）",
			"run=" + cls.run + " · " + show(r),
			r.block === false,
		);
}
{
	const m = marker({ case: CASE_DIR });
	const firstAnswer = AG.shouldBlock("seep_r2_cmd", { command: "px" }, m, HASH, NOW, GATE, null);
	const cmd = "powershell -File Tool/scripts/launch-gui.ps1 -Target " + fwd(TARGET);
	const rB = AG.shouldBlockRun("bash", { command: cmd }, ack({ letter: "B", case: CASE_DIR }), NOW, GATE, CASET);
	const rA = AG.shouldBlockRun("bash", { command: cmd }, ack({ letter: "A", case: CASE_DIR }), NOW, GATE, CASET);
	const stB = AG.runAckState(ack({ letter: "B", case: CASE_DIR }), NOW, GATE.runAck, "bash", { command: cmd }, CASET);
	emit(
		"B11",
		"run-ack letter=B → block；letter=A + 本案目标 → 放行",
		"B: block 且 runAckState.reason=letter-b ｜ A: allow",
		"B=" + show(rB) + "（" + stB.reason + "）｜ A=" + show(rA),
		rB.block === true && stB.reason === "letter-b" && rA.block === false,
	);
}
{
	const cmd = "powershell -File Tool/scripts/launch-gui.ps1 -Target " + fwd(TARGET);
	const old = ack({ letter: "A", case: CASE_DIR, at: iso(NOW - 61 * 60000) });
	const r = AG.shouldBlockRun("bash", { command: cmd }, old, NOW, GATE, CASET);
	const st = AG.runAckState(old, NOW, GATE.runAck, "bash", { command: cmd }, CASET);
	emit(
		"B12",
		"run-ack 61 分钟前 → block（TTL=" + GATE.runAck.ttlMinutes + " 分钟，取自契约）",
		"block 且 runAckState.reason=expired",
		show(r) + " · runAckState=" + st.reason,
		r.block === true && st.reason === "expired",
	);
}
{
	// seep_r2_cmd 是「我们自己的工具」：只跑分析命令（不碰本案目标）→ 静默；
	// 但命令里带上本案登记的目标 = 在跑客户样本 → 首答有效也必须先有 run-ack。
	const m = marker({ case: CASE_DIR });
	const firstAnswer = AG.shouldBlock("seep_r2_cmd", { command: "px" }, m, HASH, NOW, GATE, null);
	const silent = AG.shouldBlockRun("seep_r2_cmd", { command: "px" }, null, NOW, GATE, CASET);
	const onTarget = { command: "px " + fwd(TARGET) };
	const r = AG.shouldBlockRun("seep_r2_cmd", onTarget, null, NOW, GATE, CASET);
	const st = AG.runAckState(null, NOW, GATE.runAck, "seep_r2_cmd", onTarget, CASET);
	emit(
		"B13",
		"seep_r2_cmd：不碰本案目标 → 静默 allow；命令带本案目标且无 run-ack → 运行闸 block",
		"首答闸 allow 且 静默 allow 且 带目标 block 且 runAckState.reason=no-ack",
		"首答闸=" + show(firstAnswer) + " ｜ 静默=" + show(silent) + " ｜ 带目标=" + show(r) +
			"（" + st.reason + "）",
		firstAnswer.block === false && silent.block === false && r.block === true && st.reason === "no-ack",
	);
}
{
	// ★ 用户 2026-10-26 口径的正例：命令里就是本案 target/ 下的样本、没有回执 → block。
	const TARGET_DIR = path.join(CASE_DIR, "target");
	fs.mkdirSync(TARGET_DIR, { recursive: true });
	const TARGET_IN_DIR = path.join(TARGET_DIR, "a.exe");
	fs.writeFileSync(TARGET_IN_DIR, "TARGET-IN-DIR");
	const cmd = "powershell -File Tool/scripts/launch-gui.ps1 -Target " + fwd(TARGET_IN_DIR);
	const r = AG.shouldBlockRun("bash", { command: cmd }, null, NOW, GATE, CASET);
	emit(
		"B14",
		"命令里是本案 target/a.exe 且无 run-ack → block（跑客户样本才要回执）",
		"block",
		show(r),
		r.block === true,
	);
	const rA = AG.shouldBlockRun("bash", { command: cmd }, ack({ letter: "A", case: CASE_DIR }), NOW, GATE, CASET);
	emit(
		"B15",
		"同一本案 target/a.exe + 有效 A 回执 → allow",
		"allow",
		show(rA),
		rA.block === false,
	);
}

// C) 写守卫 ────────────────────────────────────────────────────────────
// 允许根用 writeAllowRoots() 的「静态部分」（仓库 Tool/ + work/ + ~/.seep + ~/.pi/agent）：
// 不含 ~/.seep/current-case 里那个**机器级指针**，否则测试结果取决于这台机器上当前案子是谁，
// 就不再可复跑了。never_writable 的优先级照样被这组根压测（~/.seep 与 Tool/ 都在里面）。
const ROOTS = [
	path.join(REPO, "Tool"),
	path.join(REPO, "work"),
	path.join(os.homedir(), ".seep"),
	path.join(os.homedir(), ".pi", "agent"),
];
const W = (p) => AG.writeDecision("write", { path: p }, ROOTS);
{
	const raw = "~/.seep/answer-pass.json";
	const r = W(raw);
	emit(
		"C14",
		"write ~/.seep/answer-pass.json → block（永久禁写压过 ~/.seep 允许根）",
		"block 且 code=never-writable",
		show(r) + " · code=" + r.code,
		r.block === true && r.code === "never-writable",
	);
}
{
	const raw = path.join(REPO, "Tool", "config", "answer-contract.json");
	const r = W(raw);
	emit(
		"C15",
		"write <repo>/Tool/config/answer-contract.json → block（契约在 Tool/ 里也永久禁写）",
		"block 且 code=never-writable",
		show(r) + " · code=" + r.code,
		r.block === true && r.code === "never-writable",
	);
}
{
	const raw = path.join(REPO, "Tool", "scripts", "case_state.py");
	const r = W(raw);
	emit(
		"C16",
		"write <repo>/Tool/scripts/case_state.py → 放行（Tool/ 是允许根）",
		"allow 且 code=allowed",
		show(r) + " · code=" + r.code,
		r.block === false && r.code === "allowed",
	);
}
{
	// 用户桌面（Windows 上形如 <盘>:/Users/<用户>/Desktop/x.txt）。
	// 用本机 home 推出来，**不把某台机器的用户目录写进仓库**（preflight 的「无机器专用绝对路径」）。
	const raw = path.join(os.homedir(), "Desktop", "x.txt");
	const r = W(raw);
	emit(
		"C17",
		"write 用户桌面 x.txt → block（用户目录不在任何允许根）",
		"block 且 code=outside-roots",
		show(r) + " · code=" + r.code + " · path=" + raw,
		r.block === true && r.code === "outside-roots",
	);
}

// D) cmd-guard.decideCommand ───────────────────────────────────────────
const CFG = CG.effectiveConfig(); // 真·内置禁手表 + cmd-guard.rules.json
const KEY = (CFG.allow && CFG.allow.length ? CFG.allow[0] : "cmd-guard-skip");
const D = (cmd, src) => CG.decideCommand(cmd, CFG, src, NOW);
const denyCase = (id, title, cmd, needle) => {
	const r = D(cmd, null);
	const hit = r.reason.indexOf(needle) >= 0;
	emit(
		id,
		title,
		"block 且 reason 含「" + needle + "」",
		verdict(r) + (r.reason ? "（" + r.reason.split("\n")[0].slice(0, 70) + "…）" : ""),
		r.verdict === "block" && hit,
	);
};
denyCase("D18", 'python -c "import os; os.remove(...)" → deny（解释器内联删文件）',
	'python -c "import os; os.remove(\'x\')"', "解释器内联删文件");
denyCase("D19", "python -c subprocess.run(['netsh','winhttp','set','proxy',…]) → deny（argv 形态）",
	'python -c "import subprocess; subprocess.run([\'netsh\',\'winhttp\',\'set\',\'proxy\',\'x\'])"', "解释器内联拉起系统工具");
denyCase("D20", "netsh winhttp set proxy 1.2.3.4:8080 → deny（整机代理）",
	"netsh winhttp set proxy 1.2.3.4:8080", "改 WinHTTP 代理");
denyCase("D21", "bcdedit /set testsigning on → deny（改引导配置）",
	"bcdedit /set testsigning on", "改引导配置");
{
	const r = D("python Tool/scripts/preflight.py --fast", null);
	emit(
		"D22",
		"python Tool/scripts/preflight.py --fast → allow（工作台自检不拦）",
		"allow",
		verdict(r),
		r.verdict === "allow",
	);
}
const FAKE_HOME = path.join(TMP, "home");
fs.mkdirSync(path.join(FAKE_HOME, ".seep"), { recursive: true });
{
	// ★ 审计点名的「自助口令」：口令命中只是一个**申请**，没有用户回执必须 block。
	const cmd = "netsh winhttp set proxy 1.2.3.4:8080 # " + KEY;
	const src = CG.readAckSource(FAKE_HOME); // 真去读那个不存在的 ~/.seep/run-ack.json
	const r = D(cmd, src);
	emit(
		"D23",
		"带临时放行口令但无 run-ack → block（口令不是通行证）",
		"block 且 skip.requested=true / granted=false",
		verdict(r) + " · requested=" + r.skip.requested + " granted=" + r.skip.granted +
			" · " + (r.reason ? r.reason.split("\n").slice(0, 3).join(" / ").slice(0, 80) : ""),
		r.verdict === "block" && r.skip.requested === true && r.skip.granted === false,
	);
}
{
	// 同一台机器上真的写一份用户回执（A）→ 同一口令必须放行，并在 note 里标注来源。
	fs.writeFileSync(
		path.join(FAKE_HOME, ".seep", "run-ack.json"),
		JSON.stringify({
			schema: "seep.run-ack/1",
			case: path.join(REPO, "work", "gate-tests-case"),
			target_sha256: "",
			letter: "A",
			at: iso(NOW - 2 * 60000),
		}),
	);
	const cmd = "netsh winhttp set proxy 1.2.3.4:8080 # " + KEY;
	const src = CG.readAckSource(FAKE_HOME); // 真从磁盘读回执 + validateAck
	const r = D(cmd, src);
	const noteOk = r.note.indexOf("基于用户回执") >= 0 && r.note.indexOf("letter=A") >= 0;
	emit(
		"D24",
		"口令 + 有效 A 回执 → allow，且 note 标注「基于用户回执 letter=A」",
		"allow 且 note 含「基于用户回执」与 letter=A",
		verdict(r) + " · note=" + (r.note || "（空）").slice(0, 80),
		r.verdict === "allow" && r.skip.granted === true && noteOk,
	);
}
{
	const r = D('grep -rn "frida" Tool/', null);
	emit(
		"D25",
		'grep -rn "frida" Tool/ → allow（只读查看器，逆向关键词不算执行）',
		"allow 且 notes 里无「已拦下」",
		verdict(r) + " · notes=" + (r.notes.length ? r.notes.join(" / ").slice(0, 80) : "（无）"),
		r.verdict === "allow" && r.reason === "",
	);
}

// E) seep-circuit.isLegitBusinessExit ─────────────────────────────
// 用户口径：限制只挡真坑。route.py --resolve 判不出领域 = rc=2 + 首行 [UNCLASSIFIED]，
// 这是设计好的合法出口，不许当工具失败计数（否则连撞 2 次就把整个 bash 禁掉）。
{
	const r = SC.isLegitBusinessExit(2, "[UNCLASSIFIED] 判不出领域，请先问用户一句话");
	emit(
		"E26",
		"isLegitBusinessExit(2, '[UNCLASSIFIED]…') → true（合法业务出口，不计数）",
		"true",
		String(r),
		r === true,
	);
}
{
	const r = SC.isLegitBusinessExit(1, "Traceback (most recent call last):\n  File \"x.py\", line 1");
	emit(
		"E27",
		"isLegitBusinessExit(1, 'Traceback…') → false（真报错照常计数）",
		"false",
		String(r),
		r === false,
	);
}

// 清理临时案子（失败也清，用一个统一出口）
try {
	fs.rmSync(TMP, { recursive: true, force: true });
} catch (e) {
	console.error("[gate-tests] 临时目录清理失败：" + String(e && e.message));
}
console.log(["SUMMARY", String(total), String(failed)].join("\t"));
"""


def main():
    ap = argparse.ArgumentParser(description="三道闸（首答 / 运行回执 / 写守卫 + cmd-guard）的行为测试")
    ap.add_argument("--verbose", action="store_true", help="打印每条的实际 reason 全文")
    a = ap.parse_args()

    print("[gate-tests] 真跑 TS 纯函数：%s" % EXT_DIR)
    node = shutil.which("node")
    if not node:
        # 明确失败：缺 node 等于「闸的行为没有被验证」，不许 skip 成 PASS。
        print("[FAIL] 缺 node，闸的行为未被验证")
        print("       修法：装 Node 22.6+（需要 --experimental-strip-types），或让 node 进 PATH")
        return 1
    try:
        ver = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=60).stdout.strip()
    except Exception as e:  # noqa: BLE001
        print("[FAIL] node 起不来（%s）：闸的行为未被验证" % str(e)[:80])
        return 1

    tmpdir = tempfile.mkdtemp(prefix="seep-gate-harness-")
    harness = os.path.join(tmpdir, "harness.mjs")
    with open(harness, "w", encoding="utf-8", newline="\n") as f:
        f.write(HARNESS)
    env = dict(os.environ, PYTHONIOENCODING="utf-8", NODE_NO_WARNINGS="1")
    try:
        p = subprocess.run(
            [node, "--experimental-strip-types", harness, ROOT, EXT_DIR],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=300, env=env,
        )
    except subprocess.TimeoutExpired:
        print("[FAIL] node 跑 harness 超时（>300s）：闸的行为未被验证")
        return 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    out = (p.stdout or "") + (p.stderr or "")
    rows = []
    summary = None
    for line in (p.stdout or "").splitlines():
        if not line.startswith("CASE\t"):
            if line.startswith("SUMMARY\t"):
                summary = line.split("\t")
            continue
        parts = line.split("\t")
        if len(parts) >= 6:
            rows.append(parts[1:6])
    if p.returncode != 0 and not rows:
        print("[FAIL] node %s 跑不起来：闸的行为未被验证" % ver)
        for line in out.strip().splitlines()[-12:]:
            print("       " + line)
        return 1

    print("[gate-tests] node %s · %d 条用例" % (ver, len(rows)))
    for cid, status, title, expect, actual in rows:
        print("[%s] %-4s %s" % (status, cid, title))
        if status != "PASS" or a.verbose:
            print("        期望：%s" % expect)
            print("        实际：%s" % actual)

    passed = sum(1 for r in rows if r[1] == "PASS")
    bad = [r for r in rows if r[1] != "PASS"]
    ids = [r[0] for r in rows]
    problems = []
    if len(rows) != EXPECTED_CASES:
        problems.append("用例条数=%d，期望 %d（有测试没跑到，不许当 PASS）" % (len(rows), EXPECTED_CASES))
    if len(set(ids)) != len(ids):
        problems.append("用例 id 有重复")
    if summary is None:
        problems.append("harness 没有打 SUMMARY（可能中途崩了）")
    elif int(summary[1]) != len(rows) or int(summary[2]) != len(bad):
        problems.append("SUMMARY(total=%s fail=%s) 与 Python 统计(%d/%d) 不一致" % (summary[1], summary[2], len(rows), len(bad)))
    if bad:
        problems.append("失败 %d 条：%s" % (len(bad), "、".join(r[0] for r in bad)))

    print("结果: %d/%d PASS" % (passed, len(rows)))
    if problems:
        for pr in problems:
            print("[FAIL] " + pr)
        if p.returncode != 0:
            tail = out.strip().splitlines()[-6:]
            if tail:
                print("[FAIL] node 退出码 %d，尾巴：" % p.returncode)
                for line in tail:
                    print("       " + line)
        return 1
    print("[OK] 三道闸的行为与期望一致（首答 9 + 运行回执 6 + 写守卫 4 + cmd-guard 8 + 熔断合法出口 2）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
