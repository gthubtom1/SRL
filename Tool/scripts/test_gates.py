#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""三道闸的行为测试（把「临时脚本跑出来的 50/18/20 条真值表」变成仓库内可复跑的东西）。

为什么要有这个文件（第 4 轮评审第 4 条否决意见）：
    `answer-gate.ts`（1651 行）/ `cmd-guard.ts`（1404 行）是本轮主要修复面，
    但仓库内**没有任何**针对它们的行为测试 —— 声称的真值表是临时脚本跑的，
    未入库、不可复跑，等于「评审一关就没人能证明它还是对的」。

本文件的做法（**真跑 TS，不在 Python 里复制逻辑**）：
    1. 用 `node --experimental-strip-types` 直接 import 那两个 .ts（Node 22.6+ 的类型剥离）；
    2. 只调它们导出的**纯函数**：`shouldBlock` / `writeDecision` /
       `shouldBlockRun` / `classifyTool` / `targetMismatch`
       与 `cmd-guard.ts` 的 `decideCommand` / `effectiveConfig` / `readAckSource`；
    3. 期望值全部写死在本文件里（不是「断言函数存在」，而是断言**判定结果**）。
    Python 只负责：找 node、把 JS 测试驱动脚本投到临时目录、跑它、汇总 PASS/FAIL。

可用性约定（**不许静默跳过**）：
    · 没有 node → 打印 `[FAIL] 缺 node，闸的行为未被验证`，rc=1（不是 skip，不是 PASS）。
    · node 起不来 / import 失败 / 用例条数不对 → 同样 rc=1，并打印 stderr 尾巴。

用法：
    python Tool/scripts/test_gates.py          # 一条命令，39 条
    python Tool/scripts/test_gates.py --verbose # 额外打印每条的实际 reason 全文
"""
import argparse
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXT_DIR = os.path.join(ROOT, "Tool", "prompts", "extensions")

# 中文 Windows 控制台默认 GBK：本文件要打中文与 PASS/FAIL，不重建会自崩
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 —— 流被替换/已关闭时忽略
        pass

# 期望条数：A 上下文 16 + B 运行上下文 6 + C 写入范围 4 + D cmd-guard 9
# + E 熔断出口 2 + F 熔断逃生口解析 5 = 42
EXPECTED_CASES = 42

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
const TMP = fs.mkdtempSync(path.join(process.argv[4] || os.tmpdir(), "seep-gate-tests-"));
try {
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

// A) 当前案上下文诊断 ──────────────────────────────────────────────────
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

	emit(
		"A5",
		"有效标记（5 分钟前 + 契约哈希一致）→ 放行",
		"allow",
		show(r),
		r.block === false,
	);
}
{
	const m = marker({ at: iso(NOW - 61 * 60000) });
	const r = AG.shouldBlock("bash", { command: "python Tool/scripts/case_state.py claim --case C --id C-1" }, m, HASH, NOW, GATE, null);

	emit(
		"A6",
		"标记 61 分钟前 → allow（TTL=" + GATE.ttlMinutes + " 分钟，取自契约）",
		"allow",
		show(r),
		r.block === false,
	);
}
{
	const m = marker({ adhoc: true });
	const r = AG.shouldBlock("bash", { command: "python Tool/scripts/case_state.py claim --case C --id C-1" }, m, HASH, NOW, GATE, null);

	emit(
		"A7",
		"标记 adhoc:true 不影响已授权操作",
		"allow",
		show(r),
		r.block === false,
	);
}
{
	// 登记的原始哈希与磁盘内容不同，应诊断而不阻断。
	const m = marker({ case: CASE_DIR, target_sha256: SHA_ORIGINAL });
	const r = AG.shouldBlock("seep_auto_triage", { path: TARGET }, m, HASH, NOW, GATE, CASET);
	const okMark = marker({ case: CASE_DIR, target_sha256: SHA_REPLACED });
	const rOk = AG.shouldBlock("seep_auto_triage", { path: TARGET }, okMark, HASH, NOW, GATE, CASET);
	const oldTargets = { ...CASET, targetSha256: SHA_ORIGINAL, files: [{ path: TARGET, sha256: SHA_ORIGINAL }] };
	const mismatch = AG.targetMismatch("seep_auto_triage", { path: TARGET }, m, oldTargets);
	emit(
		"A8",
		"MCP 工具自主放行；targetMismatch 仍识别同路径换文件",
		"MCP 两次均 allow；targetMismatch 含「目标内容已变」",
		"哈希不同=" + show(r) + " ｜ 哈希一致=" + show(rOk),
		// 核对当前案登记哈希变化的诊断。
		(mismatch.indexOf("目标内容已变") >= 0) && r.block === false && rOk.block === false,
	);
}
{
	const m = marker({ contract_sha256: "deadbeef" + HASH.slice(8) });
	const r = AG.shouldBlock("bash", { command: "python Tool/scripts/case_state.py claim --case C --id C-1" }, m, HASH, NOW, GATE, null);

	emit(
		"A9",
		"契约变化不阻止已授权操作",
		"allow",
		show(r),
		r.block === false,
	);
}

// 真实 repro 误拦及目标身份反例：工具脚本/产物不参与目标哈希比较。
{
	const PROJECT = path.join(TMP, "project");
	const CD = path.join(PROJECT, "case");
	const INPUT = path.join(TMP, "inputs");
	fs.mkdirSync(CD, { recursive: true });
	fs.mkdirSync(INPUT, { recursive: true });
	fs.mkdirSync(path.join(PROJECT, "analysis"), { recursive: true });
	const target = path.join(INPUT, "backup.tar");
	const helper = path.join(PROJECT, "analysis", "review_static.py");
	fs.writeFileSync(target, "ORIGINAL");
	fs.writeFileSync(helper, "print('ok')");
	const sha = AG.fileSha256(target);
	fs.writeFileSync(path.join(CD, "case.json"), JSON.stringify({ target: { path: target, sha256: sha }, target_files: [{ path: target, sha256: sha }] }));
	const ct = AG.readCaseTargets(CD);
	const m = marker({ case: CD, target_sha256: sha });
	const command = 'python Tool/scripts/case_state.py repro --case ' + fwd(CD) +
		' --id static-recompute --cmd "python ' + fwd(helper) + ' --original-dir ' + fwd(INPUT) +
		'" --expect ok --runs 1 --timeout 30 --out ' + fwd(path.join(CD, 'recompute'));
	const check = (cmd) => AG.shouldBlock("bash", { command: cmd }, m, HASH, NOW, GATE, ct);
	const good = check(command);
	emit("A10", "原件未变，repro 含工具脚本/分析脚本/输出目录 → allow", "allow 且无诊断", show(good), !good.block && !good.reason);
	const extra = path.join(TMP, "other.bin");
	fs.writeFileSync(extra, "FOREIGN");
	const mixed = check(command + ' --input ' + fwd(target) + ' --other ' + fwd(extra));
	emit("A11", "正确原件不能掩盖同时引用未登记目标", "allow + 诊断额外路径", show(mixed), !mixed.block && mixed.reason.includes(fwd(extra)));
	const other = path.join(TMP, "other");
	fs.mkdirSync(other);
	const sameName = path.join(other, "backup.tar");
	fs.writeFileSync(sameName, "ORIGINAL");
	const alias = check(command + ' --input ' + fwd(sameName));
	emit("A12", "同名同内容的另一未登记路径仍是另一目标", "allow + 诊断另一条路径", show(alias), !alias.block && alias.reason.includes(fwd(sameName)));
	const st = fs.statSync(target);
	sleep(30);
	fs.writeFileSync(target, "REPLACED"); // 同长度，并恢复 mtime，不能命中旧哈希缓存。
	fs.utimesSync(target, st.atime, st.mtime);
	const changed = check(command);
	emit("A13", "只间接引用 --case，目标同长替换并保留 mtime", "allow + 目标内容已变诊断", show(changed), !changed.block && changed.reason.includes("目标内容已变"));
	fs.writeFileSync(target, "ORIGINAL");
	fs.unlinkSync(target);
	const missing = check(command);
	emit("A14", "登记原件缺失，脚本存在也不能代替原件", "allow + 目标不可读诊断", show(missing), !missing.block && missing.reason.includes("目标不可读"));
	fs.writeFileSync(target, "ORIGINAL");
	const secondary = path.join(INPUT, "frames.json");
	fs.writeFileSync(secondary, "[1]");
	const multi = { ...ct, files: [...ct.files, { path: secondary, sha256: AG.fileSha256(secondary) }] };
	sleep(20);
	fs.writeFileSync(secondary, "[2]");
	const secondaryBad = AG.shouldBlock("bash", { command }, m, HASH, NOW, GATE, multi);
	emit("A15", "登记辅材料被替换，主材料正确也须诊断", "allow + 目标内容已变", show(secondaryBad), !secondaryBad.block && secondaryBad.reason.includes("目标内容已变"));
	const refreshed = check(command);
	emit("A16", "恢复原件后原 repro 可继续", "allow 且无诊断", show(refreshed), !refreshed.block && !refreshed.reason);
}

// B) 运行与目标上下文：历史回执不决定本次调用。
const RUNCMD = "powershell -File Tool/scripts/launch-gui.ps1 -Target a.exe";
{
 const r = AG.shouldBlockRun("bash", {command:RUNCMD}, null, NOW, GATE, null);
 emit("B10", "无当前案或回执，工具调用不被旧闸阻止", "allow", show(r), !r.block);
}
{
 const cmd = {command:'"' + fwd(TARGET) + '"'};
 const b = AG.shouldBlockRun("bash",cmd,ack({letter:"B",case:CASE_DIR}),NOW,GATE,CASET);
 const a = AG.shouldBlockRun("bash",cmd,ack({letter:"A",case:CASE_DIR}),NOW,GATE,CASET);
 emit("B11", "旧 B/A 均不裁决本次调用", "两者 allow", show(b) + " / " + show(a), !b.block && !a.block);
}
{
 const r = AG.shouldBlockRun("bash",{command:'"'+fwd(TARGET)+'"'},ack({letter:"A",at:iso(NOW-61*60000)}),NOW,GATE,CASET);
 emit("B12", "旧回执过期不阻止", "allow", show(r), !r.block);
}
{
 const r = AG.shouldBlockRun("seep_r2_cmd",{command:"px "+fwd(TARGET)},null,NOW,GATE,CASET);
 emit("B13", "分析工具无 ACK 不阻止", "allow", show(r), !r.block);
}
{
 const cmd={command:'"'+fwd(TARGET)+'"'};
 const r=AG.shouldBlockRun("bash",cmd,null,NOW,GATE,CASET);
 emit("B14", "已登记目标无 ACK 不阻止", "allow + 识别目标", show(r), !r.block && AG.touchesCaseTarget(cmd,CASET));
 const other=ack({letter:"B",case:path.join(TMP,"other-case")});
 const stale=AG.shouldBlockRun("bash",cmd,other,NOW,GATE,CASET);
 emit("B15", "跨案旧 B 不裁决当前目标", "allow", show(stale), !stale.block);
}

// C) 写守卫 ────────────────────────────────────────────────────────────
// 允许根用 writeAllowRoots() 的「静态部分」（仓库 Tool/ + work/ + ~/.seep + ~/.pi/agent）：
// 不含 ~/.seep/current-case 里那个**机器级指针**，否则测试结果取决于这台机器上当前案子是谁，
// 就不再可复跑了。历史禁写配置不作为阻断依据。
const ROOTS = [
	path.join(REPO, "Tool"),
	path.join(REPO, "work"),
	path.join(os.homedir(), ".seep"),
	path.join(os.homedir(), ".pi", "agent"),
];
const W = (p, temp) => AG.writeDecision("write", { path: p }, ROOTS, temp);
{
	const raw = "~/.seep/answer-pass.json";
	const r = W(raw);
	emit(
		"C14",
		"授权维护历史状态文件不因旧名单被拦",
		"allow 且 code=allowed",
		show(r) + " · code=" + r.code,
		r.block === false && r.code === "allowed",
	);
}
{
	const raw = path.join(REPO, "Tool", "config", "answer-contract.json");
	const r = W(raw);
	emit(
		"C15",
		"授权维护契约不因旧名单被拦",
		"allow 且 code=allowed",
		show(r) + " · code=" + r.code,
		r.block === false && r.code === "allowed",
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
	// Isolation harnesses intentionally put HOME under TEMP. This case tests the
	// roots diagnostic, so disable the temp shortcut until it is exercised by its
	// own cases; otherwise the runner's environment decides whether this passes.
	const r = W(raw, () => false);
	emit(
		"C17",
		"已授权案外写入给范围诊断，不凭旧根阻止",
		"allow 且 code=outside-roots",
		show(r) + " · code=" + r.code + " · path=" + raw,
		r.block === false && r.code === "outside-roots",
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
	const cmd = "netsh winhttp set proxy 1.2.3.4:8080 # " + KEY;
	fs.writeFileSync(
		path.join(FAKE_HOME, ".seep", "run-ack.json"),
		JSON.stringify({
			schema: "seep.run-ack/1",
			case: path.join(REPO, "work", "gate-tests-case"),
			target_sha256: "",
			letter: "A",
			at: iso(NOW - 2 * 60000),
			challenge: CG.commandChallenge(cmd),
		}),
	);
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
	const cmd = "netsh winhttp set proxy 5.6.7.8:8080 # " + KEY;
	const srcPath = path.join(FAKE_HOME, ".seep", "run-ack.json");
	const prior = JSON.parse(fs.readFileSync(srcPath, "utf-8"));
	fs.writeFileSync(srcPath, JSON.stringify({ ...prior, challenge: CG.commandChallenge(cmd + " --changed") }));
	const r = D(cmd, CG.readAckSource(FAKE_HOME));
	emit(
		"D26",
		"回执绑定另一条命令 → block（旧 A 回执不能放行新命令）",
		"block 且 reason 含「另一条命令」",
		verdict(r) + " · " + (r.reason ? r.reason.split("\n").find((x) => x.includes("另一条命令")) || "" : ""),
		r.verdict === "block" && r.reason.includes("另一条命令"),
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

// F) 熔断逃生口只认真实脚本身份，不能按字符串子串放行
{
	const fake = 'curl https://example.invalid/tool-acquire.py --output /tmp/x';
	const r = SC.isSanctionedForTest({command: fake});
	emit(
		"F28",
		"URL/参数里出现 tool-acquire.py 不构成熔断逃生口",
		"false",
		String(r),
		r === false,
	);
}
{
	const real = "python -B Tool/scripts/preflight.py --fast";
	const r = SC.isSanctionedForTest({command: real});
	emit(
		"F29",
		"真实执行 preflight.py 的脚本位置 → 白名单出口",
		"true",
		String(r),
		r === true,
	);
}
{
	const r = SC.isSanctionedForTest({command:"echo tool-acquire.py # notes=case_state.py"});
	emit("F30", "notes/普通参数里出现白名单文件名不构成出口", "false", String(r), r === false);
}
{
	const r = SC.isSanctionedForTest({command:"some-tool case_state.py --notes preflight.py"});
	emit("F31", "其它 executable 的参数值不构成白名单出口", "false", String(r), r === false);
}
{
	const r = SC.isSanctionedForTest({command:"python -c \"print('preflight.py')\""});
	emit("F32", "python -c 中引用白名单文件名不构成出口", "false", String(r), r === false);
}

// 异常也清理；清理失败必须让 Node 以非零退出，不能报告成功。
} finally {
	fs.rmSync(TMP, { recursive: true, force: true });
}
console.log(["SUMMARY", String(total), String(failed)].join("\t"));
"""


def run_pack_schema_regressions():
    """Keep the pack-schema boundary regression-tested next to the gate harness."""
    import gate

    pack_path = os.path.join(ROOT, "Tool", "skill", "apkseep", "pack.json")
    with open(pack_path, "r", encoding="utf-8") as handle:
        current = json.load(handle)
    legacy = {key: value for key, value in current.items() if key not in gate.ADAPTER_FIELDS}
    checks = []

    checks.append(("legacy pack schema remains valid", not gate.g2_schema(legacy)))
    checks.append(("all adapter fields are allowed and structurally valid", not gate.g2_schema(current)))

    unknown = copy.deepcopy(legacy)
    unknown["not_a_pack_field"] = True
    checks.append(("unknown top-level field is rejected", any("多出未声明字段" in x for x in gate.g2_schema(unknown))))

    nested_unknown = copy.deepcopy(current)
    nested_unknown["case_roles"]["unexpected"] = []
    checks.append(("unknown case role is rejected", any("未知角色" in x for x in gate.g2_schema(nested_unknown))))

    witness_mismatch = copy.deepcopy(current)
    witness_mismatch["case_roles"]["witness"] = list(witness_mismatch["cases"][:-1])
    checks.append(("case_roles witness mismatch is rejected",
                   any("case_roles.witness" in x for x in gate.g2_schema(witness_mismatch))))

    unknown_witness_field = copy.deepcopy(current)
    unknown_witness_field["witness_tool"]["unexpected"] = True
    checks.append(("unknown witness_tool field is rejected",
                   any("witness_tool" in x and "未知字段" in x
                       for x in gate.g2_schema(unknown_witness_field))))

    blank_witness_reason = copy.deepcopy(current)
    blank_witness_reason["witness_tool"]["why"] = " "
    checks.append(("blank witness_tool.why is rejected",
                   any("witness_tool.why" in x for x in gate.g2_schema(blank_witness_reason))))

    for field in gate.ADAPTER_FIELDS:
        for malformed_value, label in ((None, "null"), ("not-an-object", "non-object")):
            malformed = copy.deepcopy(current)
            malformed[field] = malformed_value
            checks.append(("%s %s is rejected" % (field, label),
                           any((field in reason and "对象" in reason)
                               for reason in gate.g2_schema(malformed))))

    failed = [name for name, ok in checks if not ok]
    print("[pack-schema-tests] %d checks: %d PASS" % (len(checks), len(checks) - len(failed)))
    for name, ok in checks:
        print("[%s] %s" % ("PASS" if ok else "FAIL", name))
    return not failed


def run_gate_failclosed_regressions():
    """Tool inventory I/O failure must fail the pack schema gate closed."""
    import gate

    pack_path = os.path.join(ROOT, "Tool", "skill", "apkseep", "pack.json")
    with open(pack_path, "r", encoding="utf-8") as handle:
        pack = json.load(handle)
    legacy = {key: value for key, value in pack.items() if key not in gate.ADAPTER_FIELDS}
    checks = []
    with mock.patch.object(gate, "_tool_names", side_effect=OSError("injected unreadable server")):
        reasons = gate.g2_schema(legacy)
    checks.append(("unreadable MCP inventory is an error",
                   any("无法读取 MCP 工具清单" in reason for reason in reasons)))

    with mock.patch.object(gate, "_tool_names", return_value=set()):
        reasons = gate.g2_schema(legacy)
    checks.append(("declared tool cannot pass against an empty inventory",
                   any("工具不存在" in reason for reason in reasons)))

    failed = [name for name, ok in checks if not ok]
    print("[gate-failclosed-tests] %d checks: %d PASS" % (len(checks), len(checks) - len(failed)))
    for name, ok in checks:
        print("[%s] %s" % ("PASS" if ok else "FAIL", name))
    return not failed


def main():
    ap = argparse.ArgumentParser(description="当前案上下文与 cmd-guard 行为测试")
    ap.add_argument("--verbose", action="store_true", help="打印每条的实际 reason 全文")
    a = ap.parse_args()

    print("[gate-tests] pack schema regression")
    if not run_pack_schema_regressions():
        print("[FAIL] pack schema regression")
        return 1
    print("[gate-tests] fail-closed regression")
    if not run_gate_failclosed_regressions():
        print("[FAIL] gate fail-closed regression")
        return 1

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
    env = dict(os.environ, PYTHONIOENCODING="utf-8", NODE_NO_WARNINGS="1")
    try:
        with open(harness, "w", encoding="utf-8", newline="\n") as f:
            f.write(HARNESS)
        p = subprocess.run(
            [node, "--experimental-strip-types", harness, ROOT, EXT_DIR, tmpdir],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=300, env=env,
        )
    except subprocess.TimeoutExpired:
        print("[FAIL] node 跑 harness 超时（>300s）：闸的行为未被验证")
        return 1
    except OSError as e:
        print("[FAIL] harness 无法启动或写入（%s）：闸的行为未被验证" % str(e)[:160])
        return 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    out = (p.stdout or "") + (p.stderr or "")
    rows = []
    summaries = []
    malformed_rows = []
    for line in (p.stdout or "").splitlines():
        if not (line == "CASE" or line.startswith("CASE\t")):
            if line == "SUMMARY" or line.startswith("SUMMARY\t"):
                summaries.append(line.split("\t"))
            continue
        parts = line.split("\t")
        if len(parts) == 6 and parts[1] and parts[2] in ("PASS", "FAIL"):
            rows.append(parts[1:6])
        else:
            malformed_rows.append(line)
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
    if p.returncode != 0:
        problems.append("node 退出码 %d（即使用例全部 PASS 也不能成功）" % p.returncode)
    if malformed_rows:
        problems.append("CASE 格式无效：%d 条" % len(malformed_rows))
    if len(rows) != EXPECTED_CASES:
        problems.append("用例条数=%d，期望 %d（有测试没跑到，不许当 PASS）" % (len(rows), EXPECTED_CASES))
    if len(set(ids)) != len(ids):
        problems.append("用例 id 有重复")
    if len(summaries) != 1:
        problems.append("harness 必须恰好输出一条 SUMMARY，实际 %d 条" % len(summaries))
    elif len(summaries[0]) != 3 or not all(x.isascii() and x.isdecimal() and len(x) <= 9 for x in summaries[0][1:]):
        problems.append("SUMMARY 格式无效：必须为 SUMMARY、非负整数 total 和 fail")
    else:
        total, failures = map(int, summaries[0][1:])
        if total != len(rows) or failures != len(bad):
            problems.append("SUMMARY(total=%d fail=%d) 与 Python 统计(%d/%d) 不一致" % (total, failures, len(rows), len(bad)))
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
    print("[OK] 行为与期望一致（上下文 16 + 运行上下文 6 + 写入范围 4 + cmd-guard 9 + 熔断出口 7）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
