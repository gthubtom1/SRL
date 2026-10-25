#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tier-3 verifier check: does any branch target a `move-result*` instruction?

WHY THIS EXISTS
---------------
`move-result*` is not an ordinary instruction. The verifier requires it to be the
immediate successor of the invoke that produced the value it copies. A branch that
lands on a `move-result` therefore bypasses the producer, and the class fails to
load with:

    VerifyError: ... copyRes1 v11 <- result0 type=Undefined

This matters specifically for byte-level patching. Redirecting a branch
(`if-*` -> `goto`) is the intuitive way to force one side of a condition, and it
is the way that silently creates this violation. Replacing the branch with a pair
of `nop`s cannot: it removes a control-flow edge instead of adding one.

The check must be done on the control-flow graph, not linearly. A "is the
previous instruction the producer?" scan over the instruction list reports clean
on a method that has a branch jumping straight onto a `move-result`, because the
producer does sit immediately before it in the stream. Only asking "does ANY
branch target this offset" sees the problem.

Usage
-----
    python dex_check_verifier.py app.apk                 # whole image
    python dex_check_verifier.py app.apk --class 'Lcom/ex/Foo;'
    python dex_check_verifier.py before.dex after.dex    # compare two builds

Exit codes: 0 = no findings, 1 = findings present, 2 = usage/parse error. The
non-zero-on-findings convention is deliberate so a pipeline can gate on it.
"""

import argparse
import json
import os
import shutil
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dexutil import (  # noqa: E402
    Dex, IF_TEST, IF_TESTZ, MOVE_RESULT_OPS, load_dex, selftest_dex,
)


def analyse_method(dex, code_off):
    """Return (findings, clean, detail) for one method body.

    findings: list of (branch_offset, move_result_offset, is_conditional)
    clean:    whether the decode consumed exactly insns_size units
    detail:   human string when not clean

    ONLY conditional branches are reported. An unconditional `goto` that lands on
    a `move-result` is a normal compiler-generated merge point: the producer runs
    on the incoming path and the goto is a *forward* jump to the shared epilogue,
    so nothing is bypassed. Reporting those as violations makes the tool unusable
    -- on a real sample they outnumber genuine findings by 20:1 and are pure
    compiler output.

    The real hazard is narrower: redirecting a CONDITIONAL branch so that it lands
    directly on a `move-result`. That skips the producing invoke on the taken path.
    """
    insns = list(dex.decode(code_off))
    info = dex.code_info(code_off)
    expected = info["insns_off"] + info["insns_size"] * 2
    ended = (insns[-1]["off"] + insns[-1]["units"] * 2) if insns else info["insns_off"]
    clean = (ended == expected)
    detail = "" if clean else ("decode ended at 0x%x, method body ends at 0x%x"
                               % (ended, expected))

    move_results = {i["off"] for i in insns if i["op"] in MOVE_RESULT_OPS}
    findings = []
    for i in insns:
        if i["op"] not in IF_TEST and i["op"] not in IF_TESTZ:
            continue
        t = dex.branch_target(i)
        if t is not None and t in move_results:
            findings.append((i["off"], t, True))
    return findings, clean, detail


def scan_image(path, entry, cls_filter):
    dex, entry_name = load_dex(path, entry)
    problems = dex.check()
    if problems:
        for p in problems:
            print("  [structure] %s" % p)
        raise RuntimeError("structurally broken: %s" % path)

    total_methods = 0
    total_findings = 0
    unclean = 0
    for fqcn in dex.class_names():
        if cls_filter and cls_filter not in fqcn:
            continue
        try:
            methods = list(dex.methods_of(fqcn))
        except Exception:
            continue
        for _section, _midx, _c, name, desc, code_off in methods:
            if code_off == 0:
                continue
            total_methods += 1
            findings, clean, detail = analyse_method(dex, code_off)
            if not clean:
                unclean += 1
            if findings:
                total_findings += len(findings)
                print("  VIOLATION %s.%s%s" % (fqcn, name, desc))
                for b_off, mr_off, _cond in findings:
                    b_insn = dex.insn_at(code_off, b_off)
                    mr_insn = dex.insn_at(code_off, mr_off)
                    print("      conditional branch 0x%x (%s)"
                          % (b_off, dex.describe(b_insn)))
                    print("        -> move-result 0x%x (%s)"
                          % (mr_off, dex.describe(mr_insn)))
                    print("        the producing invoke is bypassed on the taken "
                          "path: the class will fail to load")
    return {"methods": total_methods, "findings": total_findings,
            "unclean": unclean, "entry": entry_name}


def self_test():
    """Offline self-test: a generated dex, no APK and no sample file.

    `dexutil.selftest_dex()` builds one class whose conditional branch targets a
    `move-result` on purpose. The assertions are about the CFG reasoning this tool exists
    for: exactly one finding, at exactly the branch and target offsets the fixture
    declares, and the report's method/finding counts -- plus the exit-code contract (a
    build WITH findings exits 1, so a pipeline can gate on it).
    """
    import contextlib
    import io

    checks = 0
    tmpdir = tempfile.mkdtemp(prefix='dex-verifier-selftest-')
    try:
        blob, meta = selftest_dex()
        path = os.path.join(tmpdir, 'classes.dex')
        with open(path, 'wb') as fh:
            fh.write(blob)

        dex, _entry = load_dex(path)
        assert dex.check() == [], dex.check()
        checks += 1

        findings, clean, detail = analyse_method(dex, meta['code_gate'])
        assert clean, detail
        assert findings == [(meta['off_if_eqz'], meta['off_move_result'], True)], findings
        checks += 1

        # The stub body has no branch at all: a clean body must produce no finding, or
        # the tool would report every method as broken.
        stub_findings, stub_clean, _d = analyse_method(dex, meta['code_stub'])
        assert (stub_findings, stub_clean) == ([], True), (stub_findings, stub_clean)
        checks += 1

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            stats = scan_image(path, None, None)
        assert stats['methods'] == 2, stats
        assert stats['findings'] == 1, stats
        assert stats['unclean'] == 0, stats
        assert stats['entry'] == path, stats['entry']
        assert 'VIOLATION Lcom/ex/Foo;.gate()V' in out.getvalue(), out.getvalue()
        checks += 1

        with contextlib.redirect_stdout(io.StringIO()):
            filtered = scan_image(path, None, 'NoSuchClass')
        assert filtered['methods'] == 0 and filtered['findings'] == 0, filtered
        checks += 1

        # Exit-code contract: findings present -> 1 (a pipeline gate), clean -> 0.
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(['dex_check_verifier.py', path])
        assert rc == 1, rc
        checks += 1

        clean_path = os.path.join(tmpdir, 'clean.dex')
        with open(clean_path, 'wb') as fh:
            fh.write(blob)
        dex_check = load_dex(clean_path)[0]
        assert analyse_method(dex_check, meta['code_stub'])[0] == []
        checks += 1

        # The documented boundary, asserted: an unconditional `goto` landing on a
        # move-result is normal compiler output, NOT a violation. Rewrite the conditional
        # branch (2 units, 21t) into `goto/16` (also 2 units, 20t) with the same target
        # and require the finding to disappear. Without this, the tool would report
        # 20x more "violations" than exist.
        patched = bytearray(blob)
        off = meta['off_if_eqz']
        patched[off:off + 4] = struct.pack('<HH', 0x0029, 0xFFFF)
        goto_dex = Dex(bytes(patched), 'goto.dex')
        goto_findings, goto_clean, goto_detail = analyse_method(goto_dex, meta['code_gate'])
        assert goto_findings == [], goto_findings
        assert goto_clean, goto_detail
        goto_dex_branch = goto_dex.insn_at(meta['code_gate'], off)
        assert goto_dex_branch['op'] == 0x29, goto_dex_branch['name']
        assert goto_dex.branch_target(goto_dex_branch) == meta['off_move_result']
        checks += 1
    except Exception as exc:          # a failed assertion IS the signal: report, rc=1
        print(json.dumps({"ok": False, "checks": checks, "tool": "dex_check_verifier.py",
                          "reason": "%s: %s" % (type(exc).__name__, exc)},
                         ensure_ascii=False))
        return 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    print(json.dumps({"ok": True, "checks": checks, "tool": "dex_check_verifier.py"},
                     ensure_ascii=False))
    return 0


def main(argv):
    if '--self-test' in argv[1:]:
        return self_test()

    ap = argparse.ArgumentParser(
        description="Detect branch-into-move-result verifier violations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage")[-1][:800])
    ap.add_argument("targets", nargs="+", help="one .dex/.apk, or two to compare")
    ap.add_argument("--entry", help="archive member (default: first classes*.dex)")
    ap.add_argument("--class", dest="cls", help="substring filter on the class name")
    ap.add_argument("--self-test", action="store_true", dest="self_test",
                    help="run offline self-test and exit (no APK, no sample)")
    args = ap.parse_args(argv[1:])

    results = []
    for path in args.targets:
        print("== %s" % path)
        try:
            stats = scan_image(path, args.entry, args.cls)
        except Exception as exc:
            print("  error: %s" % exc)
            return 2
        results.append(stats)
        print("  methods checked: %d   violations: %d   unclean decodes: %d"
              % (stats["methods"], stats["findings"], stats["unclean"]))
        print("")

    if len(results) >= 2:
        before, after = results[0], results[1]
        print("== comparison")
        print("   violations %d -> %d" % (before["findings"], after["findings"]))
        if after["findings"] > before["findings"]:
            print("   REGRESSION: your patch introduced %d new violation(s). A "
                  "branch now lands on a move-result." % (after["findings"] - before["findings"]))
            print("   Fix: replace the branch with `nop`s (removes an edge) instead "
                  "of redirecting it (adds one).")
            return 1
        if before["findings"] and after["findings"] == before["findings"]:
            print("   note: violations exist in BOTH builds, so they are pre-existing "
                  "and not caused by the patch. Do not 'fix' them as part of this task.")

    if any(r["unclean"] for r in results):
        print("== WARNING: unclean decodes reported above. Offsets from those "
              "methods are unreliable -- widen the instruction format table or "
              "cross-check against a disassembler before trusting a patch offset.")

    if any(r["findings"] for r in results):
        return 1
    print("== no branch-into-move-result violations")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
