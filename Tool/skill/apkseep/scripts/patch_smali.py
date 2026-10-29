#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Method-level smali patcher.

Design notes (each one earned the hard way):
- Only the instruction body is replaced. The `.method` / `.end method` lines and method or
  parameter annotation blocks are preserved; debug/local entries attached to the old body
  are intentionally discarded with that body.
- The patch manifest must state a self-consistent `.registers` value: the assembler rejects
  out-of-range registers, so `registers` must be >= the number of parameter registers and
  >= the highest register index used by any instruction + 1. Parameter registers:
  static method = number of parameters; instance method = number of parameters + 1 (this).
- The manifest is a JSON list; each entry:
  {
    "file":   "com/example/Helper.smali",              # path relative to the smali tree root
    "method": ".method public final show(Landroid/app/Activity;)V",  # exact .method line
    "registers": 3,
    "body": ["invoke-interface {p3}, ...;", "return-void"],
    "note": "why this patch exists"                     # optional, report only
  }

A literal-match tool: whitespace, operand punctuation and instruction names must match the
source exactly, and the anchor must be unique. See references/patch-audit.md section 3.

Usage:
  python patch_smali.py <smali_tree> <patch.json> [--dry-run]
"""
import json
import os
import re
import sys


def split_methods(text):
    """Split smali text into [(method_decl, start_idx, end_idx)] using line indices."""
    lines = text.split('\n')
    out = []
    start = None
    decl = None
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith('.method ') and start is None:
            start, decl = i, s
        elif s == '.end method' and start is not None:
            out.append((decl, start, i))
            start, decl = None, None
    return lines, out


def _resolve_patch_file(tree, relpath):
    """Resolve a manifest path while refusing absolute and escaping paths."""
    if not isinstance(relpath, str) or not relpath.strip():
        raise ValueError('manifest file must be a non-empty relative path')
    root = os.path.realpath(os.path.abspath(tree))
    candidate = os.path.realpath(os.path.abspath(os.path.join(
        root, relpath.replace('/', os.sep))))
    try:
        inside = os.path.commonpath((root, candidate)) == root
    except ValueError:                         # different Windows drives
        inside = False
    if not inside:
        raise ValueError('path escapes the smali tree: %s' % relpath)
    return candidate


def _find_one(path, decl_wanted):
    """Return (unique_match_or_none, error_message_or_none)."""
    with open(path, 'r', encoding='utf-8') as f:
        lines, methods = split_methods(f.read())
    hits = [m for m in methods if m[0] == decl_wanted.strip()]
    if not hits:
        return None, 'method not found: %s' % decl_wanted
    if len(hits) > 1:
        return None, 'ambiguous (%d matches): %s' % (len(hits), decl_wanted)
    return (lines, hits[0]), None


def _preserved_metadata(lines, start, end):
    """Return annotation and parameter blocks found inside one method."""
    preserved = []
    i = start + 1
    while i < end:
        stripped = lines[i].strip()
        if stripped == '.annotation' or stripped.startswith('.annotation '):
            closing = '.end annotation'
        elif stripped == '.param' or stripped.startswith('.param '):
            closing = '.end param'
        else:
            i += 1
            continue
        j = i + 1
        while j < end and lines[j].strip() != closing:
            j += 1
        if j < end:
            preserved.extend(lines[i:j + 1])
            i = j + 1
        else:
            preserved.append(lines[i])
            i += 1
    return preserved


def patch_one(path, decl_wanted, registers, body):
    found, error = _find_one(path, decl_wanted)
    if error:
        return False, error
    lines, (_, start, end) = found
    # Keep the .method line; rewrite the interior: .registers + body
    new_inner = ['    .registers %d' % registers, '']
    metadata = _preserved_metadata(lines, start, end)
    if metadata:
        new_inner.extend(metadata)
        if new_inner[-1].strip():
            new_inner.append('')
    for b in body:
        new_inner.append('    ' + b)
    new_lines = lines[:start + 1] + new_inner + [''] + lines[end:]
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(new_lines))
    return True, 'ok'


SMALI_FIXTURE = """.class public Lcom/example/Helper;
.super Ljava/lang/Object;

.method public final show(Landroid/app/Activity;)V
    .registers 1
    return-void
.end method

.method public final hide()V
    .registers 1
    return-void
.end method
"""


def self_test():
    """Offline self-test: a built-in smali file and manifest, written to a temp dir.

    The patcher's whole promise is that only the instruction body of the named
    method changes, so that is what is asserted -- plus the two refusals (missing
    method, ambiguous anchor) that stop a patch from landing somewhere unintended.
    """
    import contextlib
    import io
    import json
    import shutil
    import tempfile

    checks = 0
    tmp = tempfile.mkdtemp(prefix='patch_smali-selftest-')
    tree = os.path.join(tmp, 'smali')
    src = os.path.join(tree, 'com', 'example', 'Helper.smali')
    decl = '.method public final show(Landroid/app/Activity;)V'

    def run(argv):
        out = io.StringIO()
        old = sys.argv
        sys.argv = argv
        try:
            with contextlib.redirect_stdout(out):
                rc = main()
        finally:
            sys.argv = old
        return rc, out.getvalue()

    def write(path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(text)

    try:
        write(src, SMALI_FIXTURE)

        # 1) method splitting finds both methods with their exact declarations
        lines, methods = split_methods(SMALI_FIXTURE)
        assert len(methods) == 2, methods
        assert methods[0][0] == decl, methods[0][0]
        assert lines[methods[0][1]] == decl and lines[methods[0][2]] == '.end method'
        assert methods[1][0] == '.method public final hide()V'
        checks += 1

        # 2) patch_one rewrites only the target body, leaving the other method alone
        ok, msg = patch_one(src, decl, 3,
                            ['invoke-static {}, Lcom/example/Probe;->x()V',
                             'return-void'])
        assert ok is True, msg
        text = open(src, encoding='utf-8').read()
        start = text.index(decl)
        block = text[start:text.index('.end method', start)]
        assert '    .registers 3' in block, block
        assert '    invoke-static {}, Lcom/example/Probe;->x()V' in block, block
        assert '.registers 1' not in block, block
        assert text.count('.registers 1') == 1, 'the other method was rewritten'
        assert text.count('.end method') == 2 and text.count('.method ') == 2, text
        assert text.startswith('.class public Lcom/example/Helper;')
        assert '.method public final hide()V' in text
        checks += 1

        # 3) a missing method and an ambiguous anchor are both refused
        ok, msg = patch_one(src, '.method public final nope()V', 1, ['return-void'])
        assert ok is False and msg == 'method not found: .method public final nope()V', msg
        dup = os.path.join(tree, 'com', 'example', 'Dup.smali')
        write(dup, SMALI_FIXTURE.replace('public final hide()V',
                                         'public final show(Landroid/app/Activity;)V'))
        ok, msg = patch_one(dup, decl, 1, ['return-void'])
        assert ok is False and 'ambiguous (2 matches)' in msg, msg
        checks += 1

        # 4) dry-run reports without writing; a missing anchor is a failure
        manifest = os.path.join(tmp, 'patch.json')
        with open(manifest, 'w', encoding='utf-8') as fh:
            json.dump([{'file': 'com/example/Helper.smali', 'method': decl,
                        'registers': 5,
                        'body': ['invoke-static {}, Lcom/example/Probe;->y()V',
                                 'return-void']}], fh)
        before = open(src, encoding='utf-8').read()
        rc, out = run(['patch_smali.py', tree, manifest, '--dry-run'])
        assert rc == 0, rc
        assert '[DRY-OK]' in out, out
        assert open(src, encoding='utf-8').read() == before, '--dry-run wrote to disk'
        checks += 1

        # 5) the real patch applies, and a manifest that misses is rc 1
        rc, out = run(['patch_smali.py', tree, manifest])
        assert rc == 0, rc
        assert 'patched=1 failed=0' in out, out
        assert '.registers 5' in open(src, encoding='utf-8').read()
        with open(manifest, 'w', encoding='utf-8') as fh:
            json.dump([{'file': 'com/example/Helper.smali',
                        'method': '.method public final gone()V',
                        'registers': 1, 'body': ['return-void']},
                       {'file': 'com/example/Absent.smali', 'method': decl,
                        'registers': 1, 'body': ['return-void']}], fh)
        rc, out = run(['patch_smali.py', tree, manifest, '--dry-run'])
        assert rc == 1, rc
        assert '[DRY-FAIL]' in out and '[MISS-FILE]' in out, out
        assert 'failed=2' in out, out
        checks += 1

        # 6) usage contract: too few arguments is rc 2, not a traceback
        rc, out = run(['patch_smali.py'])
        assert rc == 2, rc
        assert 'patch_smali.py' in out
        checks += 1

        print(json.dumps({'ok': True, 'checks': checks, 'tool': 'patch_smali.py'}))
        return 0
    except Exception as exc:
        print(json.dumps({'ok': False, 'checks': checks, 'tool': 'patch_smali.py',
                          'reason': '%s: %s' % (type(exc).__name__, exc)}))
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    if '--self-test' in sys.argv[1:]:
        return self_test()
    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        print((__doc__ or "").strip() or "usage: patch_smali.py ...")
        return 0
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    tree = sys.argv[1]
    spec = sys.argv[2]
    dry = '--dry-run' in sys.argv
    with open(spec, 'r', encoding='utf-8') as f:
        patches = json.load(f)
    ok = fail = 0
    for p in patches:
        try:
            full = _resolve_patch_file(tree, p.get('file'))
        except ValueError as exc:
            print('[UNSAFE-FILE] %s' % exc)
            fail += 1
            continue
        if not os.path.isfile(full):
            print('[MISS-FILE] %s' % p['file'])
            fail += 1
            continue
        if dry:
            found, error = _find_one(full, p['method'])
            detail = 'ready' if found else error
            print('[%s] %s :: %s  (%s)'
                  % ('DRY-OK' if found else 'DRY-FAIL', p['file'], p['method'], detail))
            ok += 1 if found else 0
            fail += 0 if found else 1
            continue
        okk, msg = patch_one(full, p['method'], p['registers'], p['body'])
        print('[%s] %s :: %s  (%s)' % ('OK' if okk else 'FAIL', p['file'], p['method'].split('(')[0].replace('.method ', ''), msg))
        ok += 1 if okk else 0
        fail += 0 if okk else 1
    print('\npatched=%d failed=%d%s' % (ok, fail, ' [dry-run]' if dry else ''))
    return 0 if fail == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
