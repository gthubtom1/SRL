#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pwn-repro.py — 栈帧/崩溃偏移复算与一致性验收（纯标准库，只读）。

它把三种“真实证据”换算成同一把尺子：
    1. objdump -d 里 `lea -0xNN(%rbp)` 的缓冲区位移 → 覆盖到 saved RIP 的偏移；
    2. 程序运行时打印的 `buf=0x.. frame=0x..` → 偏移 = frame - buf + 8；
    3. 崩溃日志里的 `rip=0x...` + cyclic 模式 → cyclic 偏移。
两种来源都给出时必须一致，否则判为“偏移不可信”。

用法：
    python Tool/skill/pwn-crypto/scripts/pwn-repro.py --objdump disasm.txt --func vuln
    python Tool/skill/pwn-crypto/scripts/pwn-repro.py --probe-log probe.txt
    python Tool/skill/pwn-crypto/scripts/pwn-repro.py --crash-log crash.txt --pattern-length 300
    python Tool/skill/pwn-crypto/scripts/pwn-repro.py --objdump d.txt --func vuln --probe-log p.txt
    python Tool/skill/pwn-crypto/scripts/pwn-repro.py --cyclic 64
    python Tool/skill/pwn-crypto/scripts/pwn-repro.py --cyclic 300 --find 0x6161616c
    python Tool/skill/pwn-crypto/scripts/pwn-repro.py --self-test
输出：JSON（--json 可省略，默认就是 JSON）。
退出码：0 成功且一致；1 可解析但多来源不一致；2 结构化失败（blocked_at/reason）。
"""
from __future__ import annotations

import argparse
import json
import re
import sys

if sys.platform == "win32":
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass

# pwntools `cyclic` 同款字母表；保持可互相复算
ALPHABET = "abcdefghijklmnopqrstuvwxyz"


def error_payload(blocked_at, reason):
    return {"ok": False, "blocked_at": blocked_at, "reason": reason}


def de_bruijn(k, n):
    """返回 de Bruijn 序列（B(k, n)），与 pwntools cyclic 的生成方式一致。"""
    a = [0] * (k * n)
    sequence = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return sequence


CYCLIC_N = 4  # 与 pwntools context.cyclic_size 默认值一致，保证 `pwn cyclic` 可互相复算


def cyclic(length):
    if length <= 0:
        return b""
    seq = de_bruijn(len(ALPHABET), CYCLIC_N)
    if length > len(seq):
        raise RuntimeError("cyclic: 长度超限（26^4=456976）")
    return "".join(ALPHABET[i] for i in seq[:length]).encode()


def cyclic_find(needle, pattern=None):
    """在 cyclic 模式中定位 needle；支持 4/8 字节小端（崩溃寄存器常见形态）。"""
    if pattern is None:
        pattern = cyclic(0x10000)
    if isinstance(needle, int):
        width = 8 if needle > 0xffffffff else 4
        raw = needle.to_bytes(width, "little")
    else:
        raw = needle
    return pattern.find(raw)


def read_text(path, blocked_at):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        raise RuntimeError("%s: %s" % (blocked_at, exc))


RBP_LEA = re.compile(r"lea\s+(-?0x[0-9a-fA-F]+)\(%rbp\)")
RSP_SUB = re.compile(r"sub\s+\$0x([0-9a-fA-F]+),%rsp")
FUNC_HEAD = re.compile(r"^[0-9a-fA-F]+ <([^>]+)>:\s*$", re.M)


def offset_from_objdump(text, func=None):
    """从 GNU objdump -d 文本提取 buffer→saved RIP 偏移（x86_64 rbp 帧）。"""
    if func:
        m = re.search(r"^[0-9a-fA-F]+ <" + re.escape(func) + r">:\s*$", text, re.M)
        if not m:
            raise RuntimeError("objdump: 未找到函数 <%s>" % func)
        start = m.start()
        nxt = FUNC_HEAD.search(text, m.end())
        block = text[start:nxt.start() if nxt else len(text)]
    else:
        block = text
    disps = [int(x, 16) for x in RBP_LEA.findall(block)]
    # 只保留朝向栈顶（负位移）的缓冲区引用
    disps = [-d for d in disps if d < 0]
    sub = RSP_SUB.search(block)
    frame = int(sub.group(1), 16) if sub else None
    if not disps:
        raise RuntimeError("objdump: 未找到 lea -0x..(%rbp) 缓冲区引用；"
                           "确认用 -O0 编译并带帧指针")
    buf_disp = max(disps)          # 最深引用通常是 buf[0]
    return {"method": "objdump-rbp", "buffer_disp": buf_disp,
            "rsp_sub": frame, "offset": buf_disp + 8,
            "func": func or "(whole-file)"}


PROBE = re.compile(r"buf=(?:0x)?([0-9a-fA-F]+)\s+frame=(?:0x)?([0-9a-fA-F]+)", re.I)


def offset_from_probe(text):
    m = PROBE.search(text)
    if not m:
        raise RuntimeError("probe: 需要一行 `buf=0x.. frame=0x..`（运行时打印）")
    buf, frame = int(m.group(1), 16), int(m.group(2), 16)
    if frame <= buf:
        raise RuntimeError("probe: frame=0x%x <= buf=0x%x，不是 rbp 帧布局" % (frame, buf))
    delta = frame - buf
    if delta > 0x10000:
        raise RuntimeError("probe: frame-buf=0x%x 过大，疑似取错变量" % delta)
    return {"method": "runtime-probe", "buf": "0x%x" % buf, "frame": "0x%x" % frame,
            "buffer_disp": delta, "offset": delta + 8}


CRASH_RIP = re.compile(r"(?:rip|RIP|eip|EIP)\s*[=:]\s*(?:0x)?([0-9a-fA-F]+)")
CRASH_RSP = re.compile(r"(?:rsp|RSP|esp|ESP)\s*[=:]\s*(?:0x)?([0-9a-fA-F]+)")


def offset_from_crash(text, pattern_length=4096):
    m = CRASH_RIP.search(text)
    if not m:
        raise RuntimeError("crash: 未找到 rip=0x... 行；需要调试器/异常处理输出")
    rip = int(m.group(1), 16)
    pattern = cyclic(max(pattern_length, 64))
    off = cyclic_find(rip, pattern)
    if off < 0 and rip > 0xffffffff:
        # 有些日志把寄存器写成 0x0000000061616261（高位补零）
        off = cyclic_find(rip & 0xffffffff, pattern)
    if off < 0:
        raise RuntimeError("crash: rip=0x%x 不在 cyclic 模式中，无法反推偏移" % rip)
    out = {"method": "crash-cyclic", "rip": "0x%x" % rip, "offset": off}
    mrsp = CRASH_RSP.search(text)
    if mrsp:
        out["rsp"] = "0x%x" % int(mrsp.group(1), 16)
    return out


def run(args):
    result = {"ok": True, "evidence": []}
    if args.cyclic is not None:
        pat = cyclic(args.cyclic)
        result["cyclic"] = {"length": len(pat), "prefix": pat[:32].decode("latin-1")}
        if args.find is not None:
            off = cyclic_find(args.find, cyclic(max(args.cyclic, 0x10000)))
            result["cyclic"]["find"] = {"value": "0x%x" % args.find, "offset": off}
            if off < 0:
                result["ok"] = False
                result.update(error_payload("cyclic-find", "值不在模式中"))
                return result, 1
        if not any([args.objdump, args.probe_log, args.crash_log]):
            return result, 0
    if args.objdump:
        text = read_text(args.objdump, "objdump")
        e = offset_from_objdump(text, args.func)
        result["evidence"].append(e)
    if args.probe_log:
        text = read_text(args.probe_log, "probe")
        e = offset_from_probe(text)
        result["evidence"].append(e)
    if args.crash_log:
        text = read_text(args.crash_log, "crash")
        e = offset_from_crash(text, args.pattern_length)
        result["evidence"].append(e)
    if not result["evidence"]:
        raise RuntimeError("没有输入：给 --objdump / --probe-log / --crash-log / --cyclic")
    offsets = sorted({e["offset"] for e in result["evidence"]})
    result["offsets"] = offsets
    result["consistent"] = len(offsets) == 1
    if not result["consistent"]:
        result["ok"] = False
        result["blocked_at"] = "offset-mismatch"
        result["reason"] = "多来源偏移不一致: %s" % offsets
        return result, 1
    result["offset"] = offsets[0]
    return result, 0


SELFTEST_ASM = """\
0000000140001474 <vuln>:
   140001474:\t55                   \tpush   %rbp
   140001475:\t48 89 e5             \tmov    %rsp,%rbp
   140001478:\t48 83 ec 70          \tsub    $0x70,%rsp
   140001499:\t48 8d 55 b0          \tlea    -0x50(%rbp),%rdx
   1400014d4:\te8 ef 12 00 00       \tcall   1400027c8 <gets>
   1400014d9:\t48 8d 45 b0          \tlea    -0x50(%rbp),%rax
0000000140001500 <main>:
   140001500:\t55                   \tpush   %rbp
"""


def self_test():
    checks = []
    checks.append(("objdump-offset", offset_from_objdump(SELFTEST_ASM, "vuln")["offset"] == 88))
    probe = "buf=00000000005FFDD0 frame=00000000005FFE20 ret=0000000140001500\n"
    checks.append(("probe-offset", offset_from_probe(probe)["offset"] == 88))
    pat = cyclic(300)
    value = int.from_bytes(pat[40:44], "little")
    crash = "RIP: 0x%x\nRSP: 0x%x\n" % (value, 0x5ffe00)
    checks.append(("crash-cyclic", offset_from_crash(crash, 300)["offset"] == 40))
    checks.append(("cyclic-known", cyclic(8) == b"aaaabaaa"))
    checks.append(("find-known", cyclic_find(int.from_bytes(cyclic(8)[3:7], "little"),
                                             cyclic(256)) == 3))
    try:
        offset_from_probe("no address here")
        checks.append(("failure-shape", False))
    except RuntimeError as exc:
        checks.append(("failure-guard", "buf=" in str(exc)))
    failed = [n for n, ok in checks if not ok]
    if failed:
        return error_payload("self-test", "失败项: " + ",".join(failed)), 2
    return {"ok": True, "checks": len(checks)}, 0


def main():
    ap = argparse.ArgumentParser(
        description="栈帧/崩溃偏移复算：objdump 位移、运行时 probe、cyclic 崩溃日志三源对齐",
        epilog="退出码：0 一致；1 不一致；2 结构化失败。")
    ap.add_argument("--objdump", help="objdump -d 的文本输出（文件路径）")
    ap.add_argument("--func", help="只分析该函数（objdump 符号名）")
    ap.add_argument("--probe-log", help="含 `buf=0x.. frame=0x..` 的运行时日志")
    ap.add_argument("--crash-log", help="含 `rip=0x..` 的崩溃日志")
    ap.add_argument("--pattern-length", type=int, default=4096, help="cyclic 模式长度")
    ap.add_argument("--cyclic", type=int, help="生成指定长度的 cyclic 模式")
    ap.add_argument("--find", type=lambda s: int(s, 0), help="在 cyclic 模式中定位该值")
    ap.add_argument("--self-test", action="store_true", help="内置样本自检（离线）")
    args = ap.parse_args()
    if args.self_test:
        try:
            payload, rc = self_test()
        except Exception as exc:  # noqa: BLE001
            payload, rc = error_payload("self-test", str(exc)[:200]), 2
        print(json.dumps(payload, ensure_ascii=False))
        return rc
    try:
        payload, rc = run(args)
    except RuntimeError as exc:
        blocked, _, reason = str(exc).partition(": ")
        print(json.dumps(error_payload(blocked or "input", reason or str(exc)),
                         ensure_ascii=False))
        return 2
    except Exception as exc:  # noqa: BLE001 —— 兜底也不许抛裸栈
        print(json.dumps(error_payload("internal", str(exc)[:200]), ensure_ascii=False))
        return 2
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
