#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""读守卫的行为测试（R8 P1-5 的可复跑证据）。

为什么单独一个文件：`test_gates.py` 的用例表是固定条数（EXPECTED_CASES），
塞新用例要改计数常量、容易掩盖"有测试没跑到"。这里独立成一个套件，
只验证一件事：读类工具在"个人隐私区"路径上会被拦、在正常路径上不会被拦。

判据来源：REQUIREMENTS.md 三（"别乱翻我东西"）。
做法：用 `npx tsc` 把 `answer-gate.ts` 编译到临时目录，再用 node 调 `sensitivePathHit`。
缺 node / 编译失败 → rc=1（**不许 skip 成 PASS**）。
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TS = os.path.join(ROOT, "Tool", "prompts", "extensions", "answer-gate.ts")

CASES = [
    ("~/.ssh/id_rsa", True),
    ("C:" + "/Users/me/AppData/Local/Google/Chrome/User Data/Default/Login Data", True),
    ("C:" + "/Users/me/Documents/passwords.txt", True),
    ("~/.aws/credentials", True),
    ("D:" + "/work/case/artifacts/run.log", False),
    ("Tool/cases/golden-crackme/target/a.exe", False),
    ("grep -rn frida Tool/", False),
]


def main() -> int:
    npx = shutil.which("npx") or shutil.which("npx.cmd")
    if not npx:
        print("[FAIL] 缺 npx，读守卫的行为未被验证（跳过不等于通过）")
        return 1
    tmp = tempfile.mkdtemp(prefix="readguard-")
    try:
        # Windows 上 npx 是 .cmd，必须经 shell 才能起（否则 CreateProcess 直接 FileNotFound）
        cmd = '"%s" tsc "%s" --outDir "%s" --target es2022 --module es2022 --moduleResolution node --skipLibCheck' % (npx, TS, tmp)
        cp = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=300)
        bad = [ln for ln in (cp.stdout or "").splitlines() if "error TS1" in ln]
        if bad:
            print("[FAIL] answer-gate.ts 编译不过（语法错误）：")
            for ln in bad[:5]:
                print("   " + ln.strip())
            return 1
        js = os.path.join(tmp, "answer-gate.js")
        if not os.path.isfile(js):
            print("[FAIL] 没产出 answer-gate.js（编译目标异常）")
            return 1
        probe = os.path.join(tmp, "probe.mjs")
        with open(probe, "w", encoding="utf-8") as f:
            f.write(
                "import { sensitivePathHit } from %s;\n"
                "const cases = %s;\n"
                "let out = [];\n"
                "for (const [p, want] of cases) { const hit = sensitivePathHit({ path: p }); out.push([p, want, !!hit]); }\n"
                "console.log(JSON.stringify(out));\n"
                % (json.dumps("file:///" + js.replace("\\", "/").replace(" ", "%20")), json.dumps(CASES, ensure_ascii=False))
            )
        rp = subprocess.run(["node", probe], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=120)
        if rp.returncode != 0:
            print("[FAIL] node 跑不动探针：" + (rp.stderr or "")[:200])
            return 1
        rows = json.loads((rp.stdout or "[]").strip() or "[]")
        fails = [(p, want) for p, want, got in rows if want != got]
        for p, want, got in rows:
            print("  [%s] %-62s 期望=%s 实际=%s"
                  % ("PASS" if want == got else "FAIL", p[:62], want, got))
        if fails or len(rows) != len(CASES):
            print("[FAIL] 读守卫：%d/%d 通过（期望 %d 条）" % (len(rows) - len(fails), len(rows), len(CASES)))
            return 1
        print("[OK] 读守卫：%d/%d 通过（隐私区拦、正常路径放行）" % (len(rows), len(CASES)))
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
