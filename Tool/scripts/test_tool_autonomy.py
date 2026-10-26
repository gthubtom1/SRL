#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""工具自治行为测试（DO-NOT-RE-ADD 锁）。用工具静默；只有跑本案目标才要回执。"""
import json, os, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TS = os.path.join(ROOT, "Tool", "prompts", "extensions", "answer-gate.ts")
CASES = [
 ("x64dbg MCP", "mcp__x64dbg__load_binary", {"path": "a.exe"}, False),
 ("IDA MCP", "mcp__ida__decompile", {"addr": "0x1000"}, False),
 ("seep_r2_cmd", "seep_r2_cmd", {"binary_path": "a.exe", "command": "aaa"}, False),
 ("seep_auto_triage", "seep_auto_triage", {"binary_path": "a.exe"}, False),
 ("技能脚本", "bash", {"command": "python Tool/skill/apkseep/scripts/doctor.py --json"}, False),
 ("tool-run.ps1", "bash", {"command": "powershell -File Tool/scripts/tool-run.ps1 -Tool x64dbg"}, False),
 ("launch-gui.ps1", "bash", {"command": "powershell -File Tool/scripts/launch-gui.ps1 -Target a.exe"}, False),
 ("mcp-launch.py", "bash", {"command": "python Tool/scripts/mcp-launch.py --server ida"}, False),
 ("r2", "bash", {"command": "r2 -A a.exe"}, False),
 ("jadx", "bash", {"command": "jadx -d out a.apk"}, False),
 ("frida", "bash", {"command": "frida -U -f com.x"}, False),
 ("tshark", "bash", {"command": "tshark -r a.pcap"}, False),
 ("binwalk", "bash", {"command": "binwalk fw.bin"}, False),
 ("nmap", "bash", {"command": "nmap -sT 10.0.0.1"}, False),
 ("装工具", "bash", {"command": "pip install frida-tools"}, False),
 ("写账本 claim", "bash", {"command": "python Tool/scripts/case_state.py claim --case C --id C-1"}, True),
]

GATE = {"whitelist": ["seep_kb_search"], "execTools": [], "bindTarget": False,
        "ttlMinutes": 60, "runAck": {"ttlMinutes": 60, "requireCaseTarget": True}}

TPL = """import { classifyTool, shouldBlockRun } from @JS@;
const cases = @CASES@;
const gate = @GATE@;
const caseT = { dir: @DIR@, paths: [@TGT@], targetSha256: "" };
const out = [];
for (const [d, t, a, w] of cases) out.push(["classify", d, w, classifyTool(t, a, gate).analysis]);
const r1 = shouldBlockRun("bash", { command: caseT.paths[0] }, null, Date.now(), gate, caseT, caseT.dir);
out.push(["runtarget", "无回执跑本案目标 → 必须拦", true, r1.block]);
const r2 = shouldBlockRun("bash", { command: "powershell -File Tool/scripts/tool-run.ps1 -Tool x64dbg" }, null, Date.now(), gate, caseT, caseT.dir);
out.push(["runtarget", "启动我们自己的工具 → 必须放行", false, r2.block]);
console.log(JSON.stringify(out));
"""


def main():
    npx = shutil.which("npx") or shutil.which("npx.cmd")
    if not npx:
        print("[FAIL] 缺 npx，工具自治未被验证（跳过不等于通过）")
        return 1
    tmp = tempfile.mkdtemp(prefix="toolauto-")
    try:
        cmd = '"%s" tsc "%s" --outDir "%s" --target es2022 --module es2022 --moduleResolution node --skipLibCheck' % (npx, TS, tmp)
        cp = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
        bad = [ln for ln in (cp.stdout or "").splitlines() if "error TS1" in ln]
        if bad:
            print("[FAIL] answer-gate.ts 编译不过：")
            for ln in bad[:5]:
                print("   " + ln.strip())
            return 1
        js = os.path.join(tmp, "answer-gate.js")
        if not os.path.isfile(js):
            print("[FAIL] 没产出 answer-gate.js")
            return 1
        js_url = "file:///" + js.replace("\\", "/").replace(" ", "%20")
        case_dir = os.path.join(ROOT, "Tool", "cases", "_lock_probe").replace("\\", "/")
        target = os.path.join(ROOT, "Tool", "cases", "_lock_probe", "target", "a.exe").replace("\\", "/")
        tpl = TPL.replace("@JS@", json.dumps(js_url))
        tpl = tpl.replace("@CASES@", json.dumps(CASES, ensure_ascii=False))
        tpl = tpl.replace("@GATE@", json.dumps(GATE, ensure_ascii=False))
        tpl = tpl.replace("@DIR@", json.dumps(case_dir))
        tpl = tpl.replace("@TGT@", json.dumps(target))
        probe = os.path.join(tmp, "probe.mjs")
        with open(probe, "w", encoding="utf-8") as f:
            f.write(tpl)
        rp = subprocess.run(["node", probe], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        if rp.returncode != 0:
            print("[FAIL] node 跑不动探针：" + (rp.stderr or "")[:300])
            return 1
        rows = json.loads((rp.stdout or "[]").strip() or "[]")
        fails = []
        for _k, desc, want, got in rows:
            ok = bool(want) == bool(got)
            print("  [%s] %-38s 期望=%s 实际=%s" % ("PASS" if ok else "FAIL", desc, want, got))
            if not ok:
                fails.append(desc)
        if fails or len(rows) != len(CASES) + 2:
            print("[FAIL] 工具自治：%d 条不符（%s）" % (len(fails), "；".join(fails[:6])))
            return 1
        print("[OK] 工具自治：%d 条全过 —— 用工具静默、只有跑本案目标才要回执" % len(rows))
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
