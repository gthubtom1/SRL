# -*- coding: utf-8 -*-
"""采集三件产物（压缩件 / 脱壳件 / 补丁件）的真实 stdout，落 capture/run.json + run2.json。"""
import subprocess, json, os, hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKED = os.path.join(ROOT, "target", "a_upx.exe")
UNPACKED = os.path.join(ROOT, "unpacked", "a_unpacked.exe")
PATCHED = os.path.join(ROOT, "artifacts", "a_upx.patched.exe")


def run(exe, inp):
    p = subprocess.run([exe], input=inp.encode(), capture_output=True, timeout=20)
    return {
        "input": inp,
        "argv": [exe],
        "exit": p.returncode,
        "stdout_raw": p.stdout.decode("utf-8", "replace"),
        "stdout_hex": p.stdout.hex(),
        "stderr_raw": p.stderr.decode("utf-8", "replace"),
    }


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


inputs = ["trance", "wrong", "x", "tranceXYZ", "TRANCE"]
matrix = {}
for name, exe in (("packed", PACKED), ("unpacked", UNPACKED), ("patched", PATCHED)):
    matrix[name] = {i: run(exe, i) for i in inputs}

run1 = {
    "cmd": "python subprocess Popen(stdin=PIPE) 直喂; 等价 shell: printf 'wrong' | Tool/cases/leaf-pe-packed/target/a_upx.exe",
    "exit": matrix["packed"]["wrong"]["exit"],
    "stdout_head": matrix["packed"]["wrong"]["stdout_raw"].strip(),
    "expect": "压缩件能否直接运行（壳自解压）：stdout 出 FAIL 说明壳解压后业务代码已接管；退出码恒 0 不能作判据",
    "target": "Tool/cases/leaf-pe-packed/target/a_upx.exe",
    "captured_at": "2026-10-24",
    "tool": "python 3 subprocess (shell=False, stdin 直喂, capture_output)",
    "runs": [matrix["packed"][i] for i in inputs],
    "negative_control": {
        "cmd": "printf 'trance' | Tool/cases/leaf-pe-packed/target/a_upx.exe",
        "exit": matrix["packed"]["trance"]["exit"],
        "stdout_head": matrix["packed"]["trance"]["stdout_raw"].strip(),
        "expect": "stdout 出现 PASS 即证明压缩件解压后功能完好（对照组）",
    },
    "verdict_of_runs": {
        "packed_trance": matrix["packed"]["trance"]["stdout_raw"].strip(),
        "packed_wrong": matrix["packed"]["wrong"]["stdout_raw"].strip(),
    },
    "shell_self_extract": {
        "question": "压缩件能否直接运行（壳是否自解压）",
        "answer": "能",
        "evidence": "packed+trance -> %s / packed+wrong -> %s"
        % (matrix["packed"]["trance"]["stdout_raw"].strip(), matrix["packed"]["wrong"]["stdout_raw"].strip()),
    },
}

run2 = {
    "cmd": "printf 'wrong' | Tool/cases/leaf-pe-packed/artifacts/a_upx.patched.exe",
    "exit": matrix["patched"]["wrong"]["exit"],
    "stdout_head": matrix["patched"]["wrong"]["stdout_raw"].strip(),
    "expect": "补丁件 + 错误输入 wrong 必须 PASS（证明判定已旁路）；对照组 unpacked + wrong 必须 FAIL",
    "target": "Tool/cases/leaf-pe-packed/artifacts/a_upx.patched.exe",
    "captured_at": "2026-10-24",
    "tool": "python 3 subprocess (shell=False, stdin 直喂, capture_output)",
    "patch": {
        "base": "Tool/cases/leaf-pe-packed/unpacked/a_unpacked.exe",
        "file_offset": "0x1e82",
        "rva": "0x2882",
        "va": "0x140002882",
        "before": "74 13 (je 0x140002897)",
        "after": "eb 1d (jmp 0x1400028a1 = lea rcx, str.PASS)",
        "bytes_changed": 2,
        "size_before": os.path.getsize(UNPACKED),
        "size_after": os.path.getsize(PATCHED),
        "sha256_before": sha(UNPACKED),
        "sha256_after": sha(PATCHED),
    },
    "runs": [matrix["patched"][i] for i in inputs],
    "negative_control": {
        "cmd": "printf 'wrong' | Tool/cases/leaf-pe-packed/unpacked/a_unpacked.exe",
        "exit": matrix["unpacked"]["wrong"]["exit"],
        "stdout_head": matrix["unpacked"]["wrong"]["stdout_raw"].strip(),
        "expect": "stdout 出现 FAIL 即证明未打补丁的脱壳件确实做了校验（负例，防止「本来就通过」）",
        "verified": matrix["unpacked"]["wrong"]["stdout_raw"].strip() == "FAIL",
    },
    "verdict_of_runs": {
        "unpacked_trance": matrix["unpacked"]["trance"]["stdout_raw"].strip(),
        "unpacked_wrong": matrix["unpacked"]["wrong"]["stdout_raw"].strip(),
        "patched_trance": matrix["patched"]["trance"]["stdout_raw"].strip(),
        "patched_wrong": matrix["patched"]["wrong"]["stdout_raw"].strip(),
    },
    "all_runs_matrix": {k: {i: v["stdout_raw"].strip() for i, v in d.items()} for k, d in matrix.items()},
}

json.dump(run1, open(os.path.join(ROOT, "capture", "run.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
json.dump(run2, open(os.path.join(ROOT, "capture", "run2.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)

for k, d in matrix.items():
    print(k, {i: v["stdout_raw"].strip() for i, v in d.items()})
