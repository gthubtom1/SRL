#!/usr/bin/env python3
"""Extract native crash blocks from a log or tombstone and locate the fault.

Native deaths are the expensive kind: no Java stack, often no obvious cause, and
the interesting question ("which library, which offset, is this a real fault or
an arranged one?") is buried in a debug dump that is tedious to read by hand.

This reads a saved `logcat` capture or a tombstone file and reports, per crash:

  * the signal, fault address, and cause
  * the register state that matters (the faulting pointer)
  * the backtrace, split into your own libraries vs system libraries
  * a verdict hint when the fault address looks *arranged* rather than accidental

With `--lib NAME=PATH` it also resolves a frame to a local copy of the library
and prints the bytes at that offset, plus a disassembly window when a decoder is
available.

Why the verdict hint matters: a hardening layer that decides the environment is
hostile rarely calls `kill`. It more often arranges a fault -- load a small
constant, use it as a pointer -- so the death looks like an ordinary bug. The
tell is a fault address that is a small integer combined with a register holding
that same integer. This script flags that shape so you look at the right place
instead of hunting a bug that is not there.

Usage
-----
  python native_crash.py capture.txt
  python native_crash.py tombstone_07
  python native_crash.py capture.txt --lib libfoo.so=/path/to/local/libfoo.so
  python native_crash.py capture.txt --lib libfoo.so=./libfoo.so --disasm 16
"""

import argparse
import json
import os
import re
import struct
import sys

SIGNAL_RE = re.compile(
    r"signal\s+(\d+)\s+\((\w+)\)\s*,?\s*code\s+(\d+)\s*\(([^)]+)\)\s*,?\s*fault addr\s+(0x[0-9a-fA-F]+)")
PID_RE = re.compile(r"pid:\s*(\d+),\s*tid:\s*(\d+),\s*name:\s*(\S+)\s*>>>\s*(\S+)")
PROC_RE = re.compile(r"Cmdline:\s*(\S+)")
UPTIME_RE = re.compile(r"Process uptime:\s*(\d+)")
FRAME_RE = re.compile(r"#(\d+)\s+pc\s+([0-9a-fA-F]+)\s+(\S+)")
REG_RE = re.compile(r"^\s*([xX]\d{1,2}|sp|lr|pc|pst)\s+([0-9a-fA-F]{8,16})")
SYSTEM_LIB_RE = re.compile(r"^/(apex|system|vendor|data/dalvik-cache|memfd)")


def is_system_lib(path):
    if not path.startswith("/"):
        return True
    return bool(SYSTEM_LIB_RE.match(path))


def parse(text):
    """Yield crash dicts."""
    lines = text.splitlines()
    crashes = []
    i = 0
    while i < len(lines):
        m = SIGNAL_RE.search(lines[i])
        # some ROMs print the signal line without "F DEBUG"; accept both
        if not m:
            i += 1
            continue
        block = {"signal": int(m.group(1)), "signame": m.group(2),
                 "si_code": m.group(4), "fault": m.group(5),
                 "frames": [], "regs": {}, "raw": []}
        # walk up a little to pick up pid/cmdline/uptime printed just before
        for j in range(max(0, i - 25), i):
            l = lines[j]
            mm = PID_RE.search(l)
            if mm and "pid" not in block:
                block["pid"], block["tid"], block["tname"], block["proc"] = mm.groups()
            mm = PROC_RE.search(l)
            if mm and "proc" not in block:
                block["proc"] = mm.group(1)
            mm = UPTIME_RE.search(l)
            if mm:
                block["uptime"] = mm.group(1)
            if "Cause:" in l and "cause" not in block:
                block["cause"] = l.split("Cause:", 1)[1].strip()
        # walk down through the dump
        j = i
        while j < len(lines) and j < i + 120:
            l = lines[j]
            if j > i + 3 and SIGNAL_RE.search(l) and j > i + 3:
                break
            block["raw"].append(l.strip())
            mm = PID_RE.search(l)
            if mm and "pid" not in block:
                block["pid"], block["tid"], block["tname"], block["proc"] = mm.groups()
            mm = PROC_RE.search(l)
            if mm and "proc" not in block:
                block["proc"] = mm.group(1)
            mm = UPTIME_RE.search(l)
            if mm:
                block["uptime"] = mm.group(1)
            if "Cause:" in l and "cause" not in block:
                block["cause"] = l.split("Cause:", 1)[1].strip()
            mm = FRAME_RE.search(l)
            if mm:
                # Backtrace lines look like either of:
                #   #00 pc 00000000000128cc  /data/app/.../lib/arm64/libfoo.so
                #   #02 pc 00000000000cccd0  /apex/.../libc.so (__pthread_start+256)
                # The path is group(3); anything after it is a symbol in parens.
                path = mm.group(3)
                rest = l.split(path, 1)[1].strip() if path in l else ""
                sym = ""
                m2 = re.search(r"\(([^)]+)\)", rest)
                if m2:
                    sym = m2.group(1)
                block["frames"].append({
                    "n": mm.group(1), "pc": int(mm.group(2), 16),
                    "path": path, "symbol": sym,
                })
            # Register dumps put several registers on one line, so collect all of
            # them rather than only the leading one.
            for k, v in re.findall(r"\b([xX]\d{1,2}|sp|lr|pc|pst)\s+([0-9a-fA-F]{8,16})\b",
                                   l.replace("F DEBUG   :", " ")):
                block["regs"][k] = int(v, 16)
            if "backtrace:" in l:
                pass
            j += 1
        i = j if j > i else i + 1
        crashes.append(block)
    return crashes


def verdict_hint(crash):
    hints = []
    fault = int(crash["fault"], 16)
    regs = crash["regs"]
    if fault <= 0x100:
        holder = [k for k, v in regs.items() if v == fault]
        hints.append("fault address is a small integer (%s)." % crash["fault"])
        if holder:
            hints.append("register(s) %s hold exactly that value -- this is the shape of an "
                         "ARRANGED fault, not an accident." % ", ".join(sorted(holder)))
        hints.append("check whether the instruction at the faulting pc loaded that constant "
                     "a few instructions earlier and used it as a pointer.")
    if crash["signame"] == "SIGKILL":
        hints.append("SIGKILL with no tombstone: this is a deliberate termination, not a bug. "
                     "No crash dump exists because nothing faulted.")
    if crash.get("cause") and "null pointer" in crash["cause"] and fault > 0x100:
        hints.append("a genuine null-ish dereference; treat as an ordinary bug unless a small "
                     "constant is involved.")
    return hints


def load_libs(specs):
    out = {}
    for s in specs or []:
        if "=" not in s:
            sys.exit("--lib expects NAME=PATH, got %r" % s)
        name, path = s.split("=", 1)
        with open(path, "rb") as fh:
            out[name] = fh.read()
    return out


def maybe_disasm(data, offset, count):
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_ARCH_X86, CS_MODE_64
    except Exception:
        return None
    # guess arch from ELF e_machine
    if data[:4] != b"\x7fELF":
        return None
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine == 183:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        start = offset & ~3
    elif machine == 62:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        start = max(0, offset - 16)
    else:
        return None
    out = []
    for ins in md.disasm(data[start:start + count * 8], start):
        mark = " <<<" if ins.address <= offset < ins.address + ins.size else ""
        out.append("      0x%06x  %-10s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
        if len(out) >= count:
            break
    if not out:
        # capstone stopped immediately -- say so rather than implying emptiness
        return ["      (decoder produced nothing from this offset; a silent stop is not "
                "evidence there is no code here)"]
    return out


TOMBSTONE = """*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'test/fixture/fixture:13/TQ1A/1:user/release-keys'
pid: 1234, tid: 1240, name: RenderThread  >>> com.example.app <<<
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x10
Cause: null pointer dereference
    x0  0000000000000000  x1  0000000000000010  x2  0000000000000000
    x8  0000000000000010  sp  00000000ffffff00  lr  0000000000000001
backtrace:
      #00 pc 00000000000128cc  /data/app/com.example-1/lib/arm64/libfoo.so (Java_a_b+40)
      #01 pc 00000000000cccd0  /apex/com.android.runtime/lib64/bionic/libc.so (__pthread_start+256)
"""

KILLED = """pid: 55, tid: 55, name: main  >>> com.example.app <<<
signal 9 (SIGKILL), code 0 (SI_USER), fault addr 0x0
"""


def self_test():
    """Offline self-test: built-in tombstone text only, no device, no decoder.

    The parse is pinned field by field (signal, fault address, pid/cmdline, frames,
    registers) and the verdict hint is asserted on the arranged-fault shape this
    script exists to flag.
    """
    import contextlib
    import io
    import shutil
    import tempfile

    checks = 0
    tmp = tempfile.mkdtemp(prefix='native_crash-selftest-')
    try:
        # 1) parse: every field the report prints
        crashes = parse(TOMBSTONE)
        assert len(crashes) == 1, len(crashes)
        c = crashes[0]
        assert (c['signal'], c['signame'], c['si_code']) == (11, 'SIGSEGV', 'SEGV_MAPERR'), c
        assert c['fault'] == '0x10', c['fault']
        assert (c['pid'], c['tid']) == ('1234', '1240'), (c['pid'], c['tid'])
        assert c['proc'] == 'com.example.app', c['proc']
        assert c['cause'] == 'null pointer dereference', c.get('cause')
        checks += 1

        # 2) register block: x1/x8 hold the fault address, sp is read too
        assert c['regs']['x8'] == 0x10 and c['regs']['x1'] == 0x10, c['regs']
        assert c['regs']['sp'] == 0xffffff00, c['regs']
        checks += 1

        # 3) frames: path, symbol, and the app/system split
        assert len(c['frames']) == 2, c['frames']
        assert c['frames'][0]['path'].endswith('libfoo.so'), c['frames'][0]
        assert c['frames'][0]['symbol'] == 'Java_a_b+40', c['frames'][0]
        assert c['frames'][0]['pc'] == 0x128cc, c['frames'][0]
        assert is_system_lib(c['frames'][1]['path']) is True
        assert is_system_lib(c['frames'][0]['path']) is False
        assert is_system_lib('libc.so') is True           # no path = not ours
        checks += 1

        # 4) the arranged-fault hint: small fault address held in a register
        hints = verdict_hint(c)
        assert any('small integer' in h for h in hints), hints
        assert any('ARRANGED fault' in h and 'x8' in h for h in hints), hints
        checks += 1

        # 5) SIGKILL is named as a deliberate termination, not a bug
        killed = parse(KILLED)[0]
        assert killed['signame'] == 'SIGKILL' and killed['fault'] == '0x0'
        hints = verdict_hint(killed)
        assert any('deliberate termination' in h for h in hints), hints
        checks += 1

        # 6) --lib resolves frames against a local copy; a bad spec is refused
        lib = os.path.join(tmp, 'libfoo.so')
        with open(lib, 'wb') as fh:
            fh.write(b'\x7fELF' + b'\x00' * 8 + bytes(range(32)))
        libs = load_libs(['libfoo.so=%s' % lib])
        assert list(libs) == ['libfoo.so'] and libs['libfoo.so'][:4] == b'\x7fELF'
        try:
            load_libs(['no-equals-sign'])
            raise AssertionError('load_libs accepted a NAME=PATH spec without "="')
        except SystemExit:
            pass
        checks += 1

        # 7) CLI: the report names the crash, splits the backtrace, keeps the footer
        log = os.path.join(tmp, 'capture.txt')
        with open(log, 'w', encoding='utf-8') as fh:
            fh.write(TOMBSTONE)
        out = io.StringIO()
        old_argv = sys.argv
        sys.argv = ['native_crash.py', log, '--lib', 'libfoo.so=%s' % lib]
        try:
            with contextlib.redirect_stdout(out):
                rc = main()
        finally:
            sys.argv = old_argv
        text = out.getvalue()
        assert rc is None, rc
        assert 'CRASH 1' in text and 'signal    : SIGSEGV (11)' in text, text[:300]
        assert 'fault addr: 0x10' in text, text[:300]
        assert '#00 [APP]' in text and '#01 [system]' in text, text
        assert 'local libfoo.so @ 0x%x' % 0x128cc in text, text
        assert 'RECORD THIS' in text, text[-200:]
        checks += 1

        # 8) a capture with no crash block says so instead of printing nothing
        empty = os.path.join(tmp, 'empty.txt')
        with open(empty, 'w', encoding='utf-8') as fh:
            fh.write('I/ActivityManager: nothing crashed here\n')
        sys.argv = ['native_crash.py', empty]
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                main()
        finally:
            sys.argv = old_argv
        assert 'no native crash block found' in out.getvalue(), out.getvalue()
        checks += 1

        print(json.dumps({'ok': True, 'checks': checks, 'tool': 'native_crash.py'}))
        return 0
    except Exception as exc:
        print(json.dumps({'ok': False, 'checks': checks, 'tool': 'native_crash.py',
                          'reason': '%s: %s' % (type(exc).__name__, exc)}))
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    if '--self-test' in sys.argv[1:]:
        return self_test()
    ap = argparse.ArgumentParser(description="Locate native crashes from a log or tombstone.")
    ap.add_argument("logfile", help="logcat capture or tombstone file")
    ap.add_argument("--lib", action="append", metavar="NAME=PATH",
                    help="resolve frames for this library name to a local file")
    ap.add_argument("--disasm", type=int, default=0, metavar="N",
                    help="disassemble N instructions around the faulting pc")
    ap.add_argument("--frames", type=int, default=12, help="how many frames to print")
    args = ap.parse_args()

    if not os.path.exists(args.logfile):
        sys.exit("no such file: %s" % args.logfile)
    with open(args.logfile, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    crashes = parse(text)
    if not crashes:
        print("no native crash block found in %s" % args.logfile)
        print("")
        print("This is a real negative only if the capture covers the death. Check:")
        print("  - was the crash buffer cleared *after* the build under test was installed?")
        print("  - does the capture include the tombstone? (a SIGKILL leaves none)")
        print("  - did the process die at all, or did it merely restart?")
        return

    libs = load_libs(args.lib)

    for idx, c in enumerate(crashes, 1):
        print("=" * 72)
        print("CRASH %d" % idx)
        print("  process   : %s" % c.get("proc", "?"))
        print("  pid/tid   : %s / %s" % (c.get("pid", "?"), c.get("tid", "?")))
        if c.get("uptime"):
            print("  uptime    : %ss  <-- time from launch to death; your test window must "
                  "exceed this" % c["uptime"])
        print("  signal    : %s (%d), si_code=%s" % (c["signame"], c["signal"], c["si_code"]))
        print("  fault addr: %s" % c["fault"])
        if c.get("cause"):
            print("  cause     : %s" % c["cause"])

        hints = verdict_hint(c)
        if hints:
            print("  HINTS")
            for h in hints:
                print("    - %s" % h)

        app_frames = [f for f in c["frames"] if not is_system_lib(f["path"])]
        if app_frames:
            print("  backtrace (your libraries):")
            for f in app_frames[:args.frames]:
                print("    #%s pc 0x%x  %s%s"
                      % (f["n"], f["pc"], os.path.basename(f["path"]),
                         ("  (%s)" % f["symbol"]) if f["symbol"] else ""))
        else:
            print("  backtrace: no frame inside an app library")
            print("    -> the fault is in the runtime or a system library; an app-side")
            print("       patch is unlikely to be the cause. Look at what called in.")

        if c["frames"]:
            print("  full backtrace:")
            for f in c["frames"][:args.frames]:
                tag = "system" if is_system_lib(f["path"]) else "APP"
                print("    #%s [%s] pc 0x%x  %s%s"
                      % (f["n"], tag, f["pc"], (f["path"] or "?"),
                         ("  (%s)" % f["symbol"]) if f["symbol"] else ""))

        # resolve against local libraries
        for f in c["frames"]:
            base = os.path.basename(f["path"])
            for name, data in libs.items():
                if name in base or base in name:
                    print("  local %s @ 0x%x:" % (name, f["pc"]))
                    if args.disasm and f is c["frames"][0]:
                        for line in maybe_disasm(data, f["pc"], args.disasm) or []:
                            print(line)
                    else:
                        print("      raw: %s" % data[f["pc"]:f["pc"] + 16].hex(" "))
        print("")

    print("=" * 72)
    print("RECORD THIS: signal, fault addr, and the time-to-death above. They are the")
    print("baseline an attempted fix must be measured against -- without them a later")
    print("run cannot distinguish 'fixed' from 'the timing changed'.")


if __name__ == "__main__":
    sys.exit(main())
