#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prove the case-bound witness rejects a swapped/hash-mismatched target.

The witness is the one place where "did we analyse *that* published artifact" can be
checked mechanically: it compares the sha256 reported by pwn-check against the
sha256 registered in this case's own `case.json` `target_files[]`.

This tool runs the real `Tool/skill/pwn-crypto/scripts/witness.py` against a set of
inputs and records the exit codes, so the case carries its own negative evidence
instead of pointing at a staging log:

  P1  default target                       -> rc 0, artifact_kind from case.json
  N1  another real case's binary (dvcp)    -> rc 1 (hash mismatch)
  N2  one byte of the real artifact flipped-> rc 1 (hash mismatch)
  N3  0-byte file                          -> rc 1 (structured parse reject from pwn-check)
  N4  case.json manifest sha zeros         -> rc 1 (manifest tampered)

Every input is copied into a temporary directory; the real target bytes are hashed
before and after and never modified. No target is started.

Usage:
    python Tool/cases/pwn-crypto07/tools/witness-negative-check.py [--json]
Exit: 0 when every expectation holds, 1 otherwise.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CASE = os.path.dirname(HERE)


def find_repo(start):
    """向上找真正的仓库根（含 Tool/scripts/gate.py），而不是从案例层数硬推。

    暂存期案例树在 work/.../filetree/Tool/cases/ 下，层数推断会指向 filetree；
    合并后两者一致。找不到就返回从 start 向上三层（保持旧行为，不静默指错）。
    """
    d = os.path.abspath(start)
    for _ in range(10):
        if os.path.isfile(os.path.join(d, "Tool", "scripts", "gate.py")):
            return d
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(start))))


REPO = find_repo(CASE)
# 合并后默认就是仓库里的 witness.py。暂存期可用 WITNESS_PATH 指向尚未合并的副本
# （本批就是靠它把「新 witness 会拒换包」变成可复跑的证据）。
WITNESS = os.environ.get("WITNESS_PATH") or os.path.join(
    REPO, "Tool", "skill", "pwn-crypto", "scripts", "witness.py")
TARGET = os.path.join(CASE, "target", "dostackbufferoverflowgood.exe")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(runtime_root, *args):
    script = os.path.join(runtime_root, "Tool", "skill", "pwn-crypto", "scripts",
                          "witness.py")
    env = dict(
        os.environ,
        PYTHONIOENCODING="utf-8",
        SEEP_RUNTIME_ROOT=runtime_root,
        HOME=os.path.join(runtime_root, ".isolated-home"),
        USERPROFILE=os.path.join(runtime_root, ".isolated-home"),
        APPDATA=os.path.join(runtime_root, ".isolated-home", "AppData", "Roaming"),
        LOCALAPPDATA=os.path.join(runtime_root, ".isolated-home", "AppData", "Local"),
        PI_CODING_AGENT_DIR=os.path.join(runtime_root, ".isolated-agent"),
    )
    p = subprocess.run([sys.executable, "-B", script] + list(args),
                       cwd=runtime_root, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=300, env=env)
    return p.returncode, (p.stdout or ""), (p.stderr or "")


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    if "--help" in args or "-h" in args:
        print(__doc__)
        return 0
    if not os.path.isfile(WITNESS):
        print(json.dumps({"ok": False, "blocked_at": "witness",
                          "reason": "witness.py 不存在：%s" % WITNESS}, ensure_ascii=False))
        return 2
    if not os.path.isfile(TARGET):
        print(json.dumps({"ok": False, "blocked_at": "target",
                          "reason": "目标不存在：%s" % TARGET}, ensure_ascii=False))
        return 2
    tgt_before = sha256_file(TARGET)

    tmp = tempfile.mkdtemp(prefix="pwn07-witness-neg-")
    rows = []
    try:
        # Mirror the real source layout and copy every runtime marker/import the
        # witness and pwn-check resolve.  The old fixture copied only two .py
        # files, so seep_runtime was absent and every valid positive control
        # died with ModuleNotFoundError before exercising the real witness.
        runtime = os.path.join(tmp, "runtime")
        pwn_scripts = os.path.join(runtime, "Tool", "skill", "pwn-crypto", "scripts")
        soft_scripts = os.path.join(runtime, "Tool", "skill", "softseep", "scripts")
        lib_dir = os.path.join(runtime, "Tool", "scripts", "lib")
        os.makedirs(pwn_scripts)
        os.makedirs(soft_scripts)
        shutil.copy2(WITNESS, os.path.join(pwn_scripts, "witness.py"))
        pwn_check = os.environ.get("PWN_CHECK_PATH") or os.path.join(
            REPO, "Tool", "skill", "pwn-crypto", "scripts", "pwn-check.py")
        shutil.copy2(pwn_check, os.path.join(pwn_scripts, "pwn-check.py"))
        shutil.copy2(
            os.path.join(REPO, "Tool", "skill", "softseep", "scripts", "seep_runtime.py"),
            os.path.join(soft_scripts, "seep_runtime.py"))
        shutil.copytree(os.path.join(REPO, "Tool", "scripts", "lib"), lib_dir)
        shutil.copy2(os.path.join(REPO, "VERSION"), os.path.join(runtime, "VERSION"))
        shutil.copy2(
            os.path.join(REPO, "Tool", "skill", "softseep", "pack.json"),
            os.path.join(runtime, "Tool", "skill", "softseep", "pack.json"))
        shutil.copy2(
            os.path.join(REPO, "Tool", "skill", "softseep", "scripts",
                         "version-migrate.py"),
            os.path.join(soft_scripts, "version-migrate.py"))
        os.makedirs(os.path.join(runtime, "Tool", "cases"))

        case_dst = os.path.join(tmp, "case")
        shutil.copytree(CASE, case_dst, ignore=shutil.ignore_patterns("__pycache__"))

        def case_with(**meta_patch):
            d = os.path.join(tmp, "case-" + str(len(rows)))
            shutil.copytree(case_dst, d, ignore=shutil.ignore_patterns("__pycache__"))
            cj = os.path.join(d, "case.json")
            with open(cj, encoding="utf-8") as stream:
                meta = json.load(stream)
            meta_patch_fn = meta_patch.get("fn")
            if meta_patch_fn:
                meta_patch_fn(meta)
            with open(cj, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(meta, stream, ensure_ascii=False, indent=1)
            return d

        # P1: default target, real manifest
        rc, out, err = run(runtime, "--case-dir", case_dst, "--self-test")
        kind = "public"
        rows.append({"name": "P1 default target (manifest hash matches)", "expect_rc": 0,
                     "rc": rc, "ok": rc == 0 and ('"artifact_kind": "%s"' % kind) in out,
                     "artifact_kind": kind, "stdout": out, "stderr": err})

        # N1: another real case's binary
        dvcp = os.path.join(REPO, "Tool", "cases", "pwn-crypto06", "target", "dvcp.exe")
        if os.path.isfile(dvcp):
            dvcp_copy = os.path.join(tmp, "dvcp.exe")
            shutil.copy2(dvcp, dvcp_copy)
            rc, out, err = run(runtime, "--case-dir", case_dst, "--target", dvcp_copy)
            rows.append({"name": "N1 swapped target (other real case binary)", "expect_rc": 1,
                         "rc": rc, "ok": rc != 0,
                         "stdout": out, "stderr": err})
        else:
            rows.append({"name": "N1 swapped target (other real case binary)",
                         "expect_rc": 1, "rc": None, "ok": False,
                         "stdout": "",
                         "stderr": "找不到 pwn-crypto06/target/dvcp.exe：换包负例未执行"})

        # N2: one byte flipped
        drift = os.path.join(tmp, "drift.bin")
        with open(TARGET, "rb") as stream:
            data = bytearray(stream.read())
        data[-1] ^= 0xFF
        with open(drift, "wb") as stream:
            stream.write(bytes(data))
        rc, out, err = run(runtime, "--case-dir", case_dst, "--target", drift)
        rows.append({"name": "N2 target byte drift (hash mismatch)", "expect_rc": 1,
                     "rc": rc, "ok": rc != 0,
                     "stdout": out, "stderr": err})

        # N3: empty file
        empty = os.path.join(tmp, "empty.bin")
        with open(empty, "wb"):
            pass
        rc, out, err = run(runtime, "--case-dir", case_dst, "--target", empty)
        rows.append({"name": "N3 empty file (structured parse reject)", "expect_rc": 1,
                     "rc": rc, "ok": rc != 0 and "rc=2" in (out + err),
                     "stdout": out, "stderr": err})

        # N4: manifest hash tampered
        def zero_hash(meta):
            meta["target_files"][0]["sha256"] = "0" * 64
        tam = case_with(fn=zero_hash)
        rc, out, err = run(runtime, "--case-dir", tam, "--self-test")
        # --self-test 把失败归一成 rc=2（并输出 {"ok":false,...}）：只要求"非 0 且明确失败"
        rows.append({"name": "N4 case.json manifest sha256 tampered", "expect_rc": "non-zero",
                     "rc": rc, "ok": rc != 0 and '"ok": false' in out,
                     "stdout": out, "stderr": err})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    tgt_after = sha256_file(TARGET)
    passed = sum(1 for r in rows if r["ok"])
    report = {
        "schema": "seep.pwn-witness-negative-controls/1",
        "case": "pwn-crypto07",
        "witness": "sandbox:Tool/skill/pwn-crypto/scripts/witness.py",
        "witness_sha256": sha256_file(WITNESS),
        "pwn_check_used": "sandbox:Tool/skill/pwn-crypto/scripts/pwn-check.py",
        "pwn_check_sha256": sha256_file(os.environ.get("PWN_CHECK_PATH") or os.path.join(
            REPO, "Tool", "skill", "pwn-crypto", "scripts", "pwn-check.py")),
        "runtime_fixture": "copied Tool/scripts/lib + softseep runtime markers",
        "host_isolation": {
            "HOME": "<sandbox>/runtime/.isolated-home",
            "APPDATA": "<sandbox>/runtime/.isolated-home/AppData/Roaming",
            "LOCALAPPDATA": "<sandbox>/runtime/.isolated-home/AppData/Local",
            "PI_CODING_AGENT_DIR": "<sandbox>/runtime/.isolated-agent",
        },
        "target_sha256_before": tgt_before,
        "target_sha256_after": tgt_after,
        "target_unmodified": tgt_before == tgt_after,
        "criterion": "witness exits 0 only when pwn-check's reported sha256 equals the "
                     "sha256 registered in the case's own case.json target_files[]",
        "summary": {"total": len(rows), "passed": passed,
                    "failed": [r["name"] for r in rows if not r["ok"]]},
        "controls": rows,
        "note": "负例在临时目录里复制输入构造；目标原字节未改，也从未被执行。",
    }
    if "--json" in args:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("[witness-neg] witness=%s sha256=%s" % (os.path.basename(WITNESS),
                                                      report["witness_sha256"][:16]))
        for r in rows:
            print("  %-4s %-52s rc=%s (expect %s)"
                  % ("PASS" if r["ok"] else "FAIL", r["name"],
                     r["rc"], r["expect_rc"]))
        print("[witness-neg] %d/%d PASS" % (passed, len(rows)))
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
