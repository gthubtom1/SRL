#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""seep-start.py —— 建案子、落 scope、打印该域下一步三条真实命令。

用法：
    python Tool/scripts/seep-start.py --domain web-pentest --case 站点A
    python Tool/scripts/seep-start.py --domain reverse --case 项目A --target Tool/samples/real/crackerjack/a.exe
    python Tool/scripts/seep-start.py --self-test

做的事：
    1) 调 Tool/scripts/case_state.py init --case evidence/<case> --target <target>
       （失败打印结构化 JSON 错误，rc=2）；
    2) 建 evidence/<case>/artifacts/ 与 scope.md；
    3) 从本文件内置小表打印该域下一步 3 条命令（全部是仓库内真实脚本与参数）。

退出码：0 成功 / 2 参数或 case_state.init 失败。
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CASE_STATE = os.path.join(HERE, "case_state.py")

DOMAINS = (
    "web-pentest", "pwn-crypto", "firmware-iot", "ad-cloud", "protocol-plugin",
    "plugin-targets", "forensics-mobile", "malware-analysis",
    "supply-chain-security", "reverse", "site-clone",
)

# 每域 3 条下一步命令。{case_dir}=evidence/<case>，{target}=--target 或域默认样本。
COMMANDS = {
    "site-clone": [
        "python Tool/skill/site-clone/scripts/site-accept.py --case Tool/cases/site-clone01 --json",
        "python Tool/skill/site-clone/scripts/site-diff.py --crawl Tool/cases/site-clone01/artifacts/crawl --rebuild Tool/cases/site-clone01/artifacts/rebuild --out {case_dir}/artifacts/diff.json",
        "python Tool/skill/site-clone/scripts/site-crawl.py --self-test",
    ],
    "web-pentest": [
        "python Tool/skill/web-pentest/scripts/web-accept.py --root .",
        "python Tool/skill/web-pentest/scripts/web-repro.py --probe Tool/cases/web-pentest05/artifacts/probe.json --out {case_dir}/artifacts/web-verdict.json",
        "python Tool/skill/web-pentest/scripts/web-check.py --self-test",
    ],
    "pwn-crypto": [
        "python Tool/scripts/pwn-check.py --file Tool/cases/pwn-crypto03/artifacts/stack_overflow.exe --json",
        "python Tool/skill/pwn-crypto/scripts/pwn-repro.py --objdump Tool/cases/pwn-crypto03/artifacts/stack_overflow.dis --func vuln --probe-log Tool/cases/pwn-crypto03/artifacts/probe.txt",
        "python Tool/skill/pwn-crypto/scripts/crypto-verify.py --self-test",
    ],
    "firmware-iot": [
        "python Tool/scripts/fw-triage.py --file Tool/cases/firmware-iot03/input/43341b0rtecdc.bin --json",
        "python Tool/skill/firmware-iot/scripts/fw-repro.py --file Tool/cases/firmware-iot05/input/ota-fixture.zip --out-dir {case_dir}/artifacts/fw --json",
        "python Tool/skill/firmware-iot/scripts/fw-accept.py --root . --json",
    ],
    "ad-cloud": [
        "python Tool/skill/ad-cloud/scripts/ad-repro.py --kind adcs-esc --input Tool/cases/ad-cloud01/input/adcs-find.json",
        "python Tool/skill/ad-cloud/scripts/cloud-iam-eval.py --input Tool/cases/ad-cloud05/input/policy.json --action iam:CreatePolicyVersion --resource '*'",
        "python Tool/scripts/adcloud-check.py --kubeconfig Tool/cases/ad-cloud01/input/kubeconfig.yaml --json",
    ],
    "protocol-plugin": [
        "python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file Tool/cases/protocol03/input/websocket.pcapng --json --extract {case_dir}/artifacts/streams",
        "python Tool/skill/protocol-plugin/scripts/proto-repro.py --input Tool/cases/protocol02/input/sample.bin --json",
        "python Tool/skill/protocol-plugin/scripts/proto-accept.py --json",
    ],
    "plugin-targets": [
        "python Tool/skill/plugin-targets/scripts/plugin-triage.py --path Tool/cases/plugin04/input/app.asar --json",
        "python Tool/skill/plugin-targets/scripts/plugin-repro.py --path Tool/cases/_archive/plugin01/input/ext.zip --out {case_dir}/artifacts/repro --json",
        "python Tool/skill/plugin-targets/scripts/plugin-accept.py --root . --json",
    ],
    "forensics-mobile": [
        "python Tool/skill/forensics-mobile/scripts/forensics-check.py --file Tool/cases/forensics03/input/AppReadiness.evtx --json",
        "python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input Tool/cases/forensics03/input/History.sqlite --out {case_dir}/artifacts/timeline.json --json",
        "python Tool/skill/forensics-mobile/scripts/evidence-accept.py --case Tool/cases/forensics03 --json",
    ],
    "malware-analysis": [
        "python Tool/scripts/mal-triage.py --file Tool/cases/malware-analysis03/input/packed-upx.exe --json",
        "python Tool/skill/malware-analysis/scripts/mal-unpack.py --file Tool/cases/malware-analysis03/input/packed-upx.exe --out-dir {case_dir}/artifacts/unpack --json",
        "python Tool/skill/malware-analysis/scripts/ioc-extract.py --file Tool/cases/malware-analysis04/input/macro-loader.docm --json-out {case_dir}/artifacts/iocs.json",
    ],
    "supply-chain-security": [
        "python Tool/scripts/sc-check.py --path Tool/ --max-files 1000 --out {case_dir}/artifacts/sc.json",
        "python Tool/skill/supply-chain-security/scripts/sbom-reach.py --sbom Tool/cases/supply-chain04/input/bom.json --source Tool/cases/supply-chain04/input/src --out {case_dir}/artifacts/reach.json",
        "python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py --path .github/workflows --out {case_dir}/artifacts/ci.json",
    ],
    "reverse": [
        "python Tool/skill/softseep/scripts/preflight-classify.py {target}",
        "python Tool/scripts/mal-triage.py --file {target} --json",
        "python Tool/scripts/case_state.py show --case {case_dir}",
    ],
}

DEFAULT_TARGET = {
    "reverse": "Tool/samples/real/crackerjack/a.exe",
}


def _err(step, case, cmd, rc, stdout="", stderr=""):
    return {
        "ok": False,
        "step": step,
        "case": case,
        "cmd": cmd,
        "rc": rc,
        "stdout": (stdout or "").strip()[-800:],
        "stderr": (stderr or "").strip()[-800:],
    }


def _safe_case(case):
    c = (case or "").strip()
    if not c or c in (".", "..") or os.path.isabs(c) or any(x in c for x in ("/", "\\")):
        return None
    return c


def _quote(p):
    return '"%s"' % p if any(ch.isspace() for ch in p) else p


def _scope(case, domain, target, case_dir):
    return "\n".join([
        "# %s — scope" % case,
        "",
        "- domain: `%s`" % domain,
        "- case: `%s`" % case,
        "- target: `%s`" % (target or "<target>"),
        "- created_utc: `%s`" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "- authorization: <授权编号 / 范围 / 时间窗 / 速率上限>",
        "- boundary: 只读优先；越界、写操作、持久化必须单独授权并留回滚记录。",
        "- evidence_dir: `%s`" % os.path.relpath(case_dir, ROOT).replace(os.sep, "/"),
        "- artifacts: `%s/artifacts/`" % os.path.relpath(case_dir, ROOT).replace(os.sep, "/"),
        "",
        "> 把原始输出放进 artifacts/，命令与 rc 写进 report.md；凭据/token/私钥只留指纹。",
        "",
    ])


def _next_commands(domain, case_dir, target):
    rel = os.path.relpath(case_dir, ROOT).replace(os.sep, "/")
    tgt = target or DEFAULT_TARGET.get(domain, "<target>")
    return [c.format(case_dir=rel, target=_quote(tgt)) for c in COMMANDS[domain]]


def start(domain, case, target, root=ROOT):
    case_dir = os.path.join(root, "evidence", case)
    cmd = [sys.executable, CASE_STATE, "init", "--case", case_dir]
    if target:
        cmd += ["--target", target]
    r = subprocess.run(cmd, cwd=root, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        return 2, _err("case_state.init", case, cmd, r.returncode, r.stdout, r.stderr)
    art = os.path.join(case_dir, "artifacts")
    os.makedirs(art, exist_ok=True)
    scope = os.path.join(case_dir, "scope.md")
    if not os.path.isfile(scope):
        with open(scope, "w", encoding="utf-8", newline="\n") as f:
            f.write(_scope(case, domain, target, case_dir))
    return 0, {
        "ok": True,
        "domain": domain,
        "case": case,
        "case_dir": case_dir,
        "artifacts": art,
        "scope": scope,
        "next": _next_commands(domain, case_dir, target),
    }


def self_test():
    checks = []
    checks.append(("domains", len(COMMANDS) == len(DOMAINS) and all(d in COMMANDS for d in DOMAINS)
                   and all(len(COMMANDS[d]) == 3 for d in DOMAINS)))
    tmp = tempfile.mkdtemp(prefix="seep-start-selftest-")
    case = "selftest"
    case_dir = os.path.join(tmp, "evidence", case)
    # 用真实 case_state.py 在临时目录建案，不污染仓库 evidence/。
    cmd = [sys.executable, CASE_STATE, "init", "--case", case_dir]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    checks.append(("case_state_init", r.returncode == 0))
    os.makedirs(os.path.join(case_dir, "artifacts"), exist_ok=True)
    scope = os.path.join(case_dir, "scope.md")
    with open(scope, "w", encoding="utf-8", newline="\n") as f:
        f.write(_scope(case, "web-pentest", "", case_dir))
    checks.append(("evidence_layout",
                   os.path.isdir(os.path.join(case_dir, "artifacts"))
                   and os.path.isfile(scope)
                   and os.path.isfile(os.path.join(case_dir, "facts.jsonl"))))
    cmds = _next_commands("web-pentest", case_dir, "")
    checks.append(("three_commands", len(cmds) == 3
                   and all(c.startswith("python Tool/") for c in cmds)))
    failed = [name for name, ok in checks if not ok]
    print(json.dumps({"ok": not failed, "tool": "seep-start.py",
                      "checks": len(checks), "failed": failed,
                      "note": "temp case_state init + evidence layout + command table"},
                     ensure_ascii=False))
    return 0 if not failed else 2


def main(argv=None):
    p = argparse.ArgumentParser(
        description="建案子 + evidence scope + 打印该域下一步 3 条命令")
    p.add_argument("--domain", choices=DOMAINS, help="十一域之一")
    p.add_argument("--case", help="案子名（只允许字母/数字/中文/-/_；落到 evidence/<case>）")
    p.add_argument("--target", default="", help="目标路径/URL/样本（可选）")
    p.add_argument("--self-test", action="store_true", help="离线自检，rc=0")
    a = p.parse_args(argv)

    if a.self_test:
        return self_test()

    if not a.domain or not a.case:
        p.error("--domain 与 --case 必填（或使用 --self-test）")
    case = _safe_case(a.case)
    if not case:
        print(json.dumps(_err("args", a.case, [], 2,
                              stderr="--case 只能是单段名称，不能含 / \\ .. 或绝对路径"),
                         ensure_ascii=False), file=sys.stderr)
        return 2

    rc, data = start(a.domain, case, a.target)
    if rc != 0:
        print(json.dumps(data, ensure_ascii=False), file=sys.stderr)
        return rc
    print("[OK] case: %s" % data["case_dir"])
    print("[OK] artifacts: %s" % data["artifacts"])
    print("[OK] scope: %s" % data["scope"])
    print("下一步 3 条命令（从仓库根执行）：")
    for i, c in enumerate(data["next"], 1):
        print("  %d) %s" % (i, c))
    return 0


if __name__ == "__main__":
    sys.exit(main())
