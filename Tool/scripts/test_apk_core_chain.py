#!/usr/bin/env python3
"""Offline regressions for the bounded apkseep core chain."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "Tool" / "skill" / "apkseep" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import dex_patch_bytes as dexpatch  # noqa: E402
import patch_smali  # noqa: E402
import preflight  # noqa: E402
import repack  # noqa: E402


def run_script(script, *args, path_dir=None, timeout=20):
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    if path_dir is not None:
        env["PATH"] = str(path_dir)
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), *map(str, args)],
        cwd=REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=env,
    )


def write_minimal_apk(path, *, compressed_arsc=False, signature=False):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"manifest",
                    compress_type=zipfile.ZIP_STORED)
        zf.writestr("resources.arsc", b"arsc" + b"\0" * 40,
                    compress_type=zipfile.ZIP_DEFLATED if compressed_arsc
                    else zipfile.ZIP_STORED)
        zf.writestr("classes.dex", b"dex\n035\0payload")
        if signature:
            zf.writestr("META-INF/CERT.RSA", b"signature")


class NonSeekableWriter:
    def __init__(self, handle):
        self.handle = handle

    def write(self, data):
        return self.handle.write(data)

    def flush(self):
        return self.handle.flush()

    def tell(self):
        return self.handle.tell()

    def seekable(self):
        return False


class ApkCoreChainTests(unittest.TestCase):
    def test_patch_smali_dry_run_matches_real_unique_requirement(self):
        decl = ".method public static f()V"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            smali = root / "tree" / "A.smali"
            smali.parent.mkdir()
            smali.write_text(
                "%s\n    .registers 1\n    return-void\n.end method\n\n"
                "%s\n    .registers 1\n    return-void\n.end method\n"
                % (decl, decl),
                encoding="utf-8",
            )
            manifest = root / "patch.json"
            manifest.write_text(json.dumps([{
                "file": "A.smali", "method": decl, "registers": 1,
                "body": ["return-void"],
            }]), encoding="utf-8")
            dry = run_script("patch_smali.py", root / "tree", manifest, "--dry-run")
            real = run_script("patch_smali.py", root / "tree", manifest)

        self.assertEqual(dry.returncode, 1, dry.stdout + dry.stderr)
        self.assertIn("DRY-FAIL", dry.stdout)
        self.assertIn("ambiguous (2 matches)", dry.stdout)
        self.assertEqual(real.returncode, 1, real.stdout + real.stderr)
        self.assertIn("ambiguous (2 matches)", real.stdout)

    def test_patch_smali_refuses_tree_escape(self):
        decl = ".method public static f()V"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree = root / "tree"
            tree.mkdir()
            outside = root / "outside.smali"
            outside.write_text(
                "%s\n    .registers 1\n    return-void\n.end method\n" % decl,
                encoding="utf-8",
            )
            before = outside.read_bytes()
            manifest = root / "patch.json"
            manifest.write_text(json.dumps([{
                "file": "../outside.smali", "method": decl, "registers": 2,
                "body": ["return-void"],
            }]), encoding="utf-8")
            got = run_script("patch_smali.py", tree, manifest)
            after = outside.read_bytes()

        self.assertEqual(got.returncode, 1, got.stdout + got.stderr)
        self.assertIn("[UNSAFE-FILE]", got.stdout)
        self.assertIn("escapes the smali tree", got.stdout)
        self.assertEqual(before, after)

    def test_patch_smali_preserves_annotations_and_params(self):
        decl = ".method public static f()V"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "A.smali"
            src.write_text(
                "%s\n"
                "    .registers 1\n"
                "    .annotation runtime Lcom/example/Keep;\n"
                "    .end annotation\n"
                "    .param p0, \"value\"\n"
                "        .annotation runtime Lcom/example/ParamKeep;\n"
                "        .end annotation\n"
                "    .end param\n"
                "    return-void\n"
                ".end method\n" % decl,
                encoding="utf-8",
            )
            manifest = root / "patch.json"
            manifest.write_text(json.dumps([{
                "file": "A.smali", "method": decl, "registers": 2,
                "body": ["invoke-static {}, Lcom/example/Probe;->x()V",
                         "return-void"],
            }]), encoding="utf-8")
            got = run_script("patch_smali.py", root, manifest)
            text = src.read_text(encoding="utf-8")

        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(text.count(".annotation runtime"), 2, text)
        self.assertEqual(text.count(".end annotation"), 2, text)
        self.assertIn('.param p0, "value"', text)
        self.assertIn(".registers 2", text)
        self.assertIn("Lcom/example/Probe;->x()V", text)

    def test_dex_patch_rejects_two_specs_that_collide_at_one_site(self):
        blob, _meta = dexpatch.selftest_dex()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dex_path = root / "classes.dex"
            dex_path.write_bytes(blob)
            spec_path = root / "spec.json"
            common = {
                "class": "Lcom/ex/Foo;", "method": "gate",
                "match": {"kind": "if-testz"},
            }
            spec_path.write_text(json.dumps({"patches": [
                dict(common, name="first", replace={"kind": "nops"}),
                dict(common, name="second", replace={"kind": "bytes",
                                                     "bytes": "0e000000"}),
            ]}), encoding="utf-8")

            for dry_flag in ((), ("--dry-run",)):
                out = root / ("dry.dex" if dry_flag else "out.dex")
                argv = ["dex_patch_bytes.py", str(dex_path), "--spec",
                        str(spec_path), "-o", str(out), *dry_flag]
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = dexpatch.main(argv)
                self.assertEqual(rc, 1, buf.getvalue())
                self.assertIn("FATAL [1]", buf.getvalue())
                self.assertNotIn("Traceback", buf.getvalue())
                self.assertFalse(out.exists(), "a failed multi-patch run wrote output")

    def test_repack_clears_streaming_data_descriptor_flag(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "stream.apk"
            out = root / "out.apk"
            with open(src, "wb") as raw:
                with zipfile.ZipFile(NonSeekableWriter(raw), "w",
                                     zipfile.ZIP_DEFLATED) as zf:
                    with zf.open("classes.dex", "w") as member:
                        member.write(b"dex\n035\0streamed-payload")
            with zipfile.ZipFile(src) as zf:
                self.assertTrue(zf.getinfo("classes.dex").flag_bits & 0x08)

            with contextlib.redirect_stdout(io.StringIO()):
                repack.build_unsigned(str(src), {}, str(out))

            blob = out.read_bytes()
            with zipfile.ZipFile(out) as zf:
                info = zf.getinfo("classes.dex")
                local_flags = struct.unpack_from("<H", blob, info.header_offset + 6)[0]
                next_sig = blob[info.header_offset + 30 + len(info.filename.encode("utf-8"))
                                + info.compress_size:][:4]
                self.assertIsNone(zf.testzip())
            self.assertFalse(local_flags & 0x08)
            self.assertIn(next_sig, (b"PK\x03\x04", b"PK\x01\x02"), next_sig)

    def test_repack_treats_failed_jarsigner_as_failure(self):
        with tempfile.TemporaryDirectory() as td:
            apk = Path(td) / "probe.apk"
            write_minimal_apk(apk)
            env = mock.patch.dict(os.environ, {"PYTHONIOENCODING": "utf-8"})
            buf = io.StringIO()
            with env, contextlib.redirect_stdout(buf):
                ok = repack.verify_apk(
                    str(apk), {"jarsigner": sys.executable}, expect_signed=True)
        self.assertFalse(ok, buf.getvalue())
        self.assertIn("jarsigner] FAILED", buf.getvalue())

    def test_repack_preserves_source_named_like_old_output_scratch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, output = root / "out.apk.tmp", root / "out.apk"
            write_minimal_apk(source)
            before = source.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()):
                repack.build_unsigned(str(source), {}, str(output))
            self.assertEqual(source.read_bytes(), before)
            with zipfile.ZipFile(output) as zf:
                self.assertIsNone(zf.testzip())
                self.assertEqual(zf.read("classes.dex"), b"dex\n035\0payload")

    def test_repack_preserves_unrelated_old_scratch_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, output = root / "source.apk", root / "out.apk"
            marker = root / "out.apk.tmp"
            marker.write_bytes(b"caller-owned data")
            write_minimal_apk(source)
            with contextlib.redirect_stdout(io.StringIO()):
                repack.build_unsigned(str(source), {}, str(output))
            self.assertEqual(marker.read_bytes(), b"caller-owned data")
            self.assertFalse(list(root.glob(".repack-*.tmp")))

    def test_repack_failure_preserves_output_and_removes_owned_scratch(self):
        for stage in ("compression", "publication"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                source, output = root / "source.apk", root / "out.apk"
                write_minimal_apk(source)
                before = source.read_bytes()
                output.write_bytes(b"previous output")
                target = repack if stage == "compression" else repack.os
                name = "_deflate_raw" if stage == "compression" else "replace"
                with mock.patch.object(target, name, side_effect=OSError(stage)):
                    with self.assertRaisesRegex(OSError, stage):
                        with contextlib.redirect_stdout(io.StringIO()):
                            repack.build_unsigned(str(source), {}, str(output))
                self.assertEqual(source.read_bytes(), before)
                self.assertEqual(output.read_bytes(), b"previous output")
                self.assertFalse(list(root.glob(".repack-*.tmp")))

    def test_repack_no_sign_checks_layout_without_signature_tools(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            good = root / "good.apk"
            bad = root / "bad.apk"
            good_src = root / "good-src.apk"
            write_minimal_apk(good_src)
            with contextlib.redirect_stdout(io.StringIO()):
                repack.build_unsigned(str(good_src), {}, str(good))
            write_minimal_apk(bad, compressed_arsc=True)
            with mock.patch.object(repack, "run") as run_mock:
                with contextlib.redirect_stdout(io.StringIO()):
                    good_ok = repack.verify_apk(
                        str(good), {"jarsigner": sys.executable}, expect_signed=False)
                    bad_ok = repack.verify_apk(
                        str(bad), {"jarsigner": sys.executable}, expect_signed=False)
            run_mock.assert_not_called()
        self.assertTrue(good_ok)
        self.assertFalse(bad_ok)

    def test_repack_refuses_same_input_and_output_before_writing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            apk = root / "same.apk"
            write_minimal_apk(apk, signature=True)
            before = apk.read_bytes()
            got = run_script("repack.py", "--apk", apk, "--out", apk,
                             "--no-sign", path_dir=root)
            after = apk.read_bytes()
        self.assertEqual(got.returncode, 1, got.stdout + got.stderr)
        self.assertIn("output would overwrite source APK", got.stdout + got.stderr)
        self.assertEqual(before, after)

    def test_repack_scratch_name_cannot_delete_a_source_named_unsigned(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            apk = root / "unsigned.apk"
            out = root / "out.apk"
            write_minimal_apk(apk, signature=True)
            before = apk.read_bytes()
            got = run_script("repack.py", "--apk", apk, "--out", out,
                             "--workdir", root, "--no-sign", path_dir=root)
            after = apk.read_bytes()
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
            self.assertEqual(before, after)
            self.assertTrue(out.exists())

    def test_repack_rejects_split_output_collisions(self):
        source = os.path.abspath("base.apk")
        with self.assertRaises(SystemExit):
            repack.reject_output_collisions([source], [source])
        with self.assertRaises(SystemExit):
            repack.reject_output_collisions([], ["out/base.apk", "out/base.apk"])

    def test_repack_split_merge_does_not_delete_input_with_temporary_name(self):
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "base.apk"
            special = root / "merged.apk.unsigned"
            write_minimal_apk(base)
            write_minimal_apk(special)
            before = special.read_bytes()
            args = SimpleNamespace(out=str(root / "merged.apk"),
                                   drop_split_resources=False, abi=None,
                                   no_sign=True)
            info = {"path": str(special), "name": special.name,
                    "abis": [], "res": 0, "arsc": 0}
            with contextlib.redirect_stdout(io.StringIO()):
                rc = repack._split_merge(
                    args, {}, {"path": str(base), "name": base.name}, [info])
            self.assertEqual(rc, 0)
            self.assertEqual(special.read_bytes(), before)
            self.assertTrue((root / "merged.apk").exists())

    def test_repack_resign_scratch_does_not_remove_caller_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "base.apk"
            write_minimal_apk(source)
            caller_dir = root / ".unsigned"
            caller_dir.mkdir()
            marker = caller_dir / "keep.txt"
            marker.write_text("caller data", encoding="utf-8")

            def copy_one(unsigned, out_path):
                shutil.copy2(unsigned, out_path)
                return out_path

            with contextlib.redirect_stdout(io.StringIO()):
                repack.resign_split_set(
                    [{"path": str(source), "name": source.name}], str(root), copy_one)
            self.assertEqual(marker.read_text(encoding="utf-8"), "caller data")

    def test_preflight_stops_after_ambiguous_device_selection(self):
        calls = []

        def fake_run(cmd, timeout=60):
            calls.append(cmd)
            if cmd[-2:] == ["devices", "-l"]:
                return 0, "List of devices attached\nA\tdevice\nB\tdevice\n"
            return 0, ""

        old_argv = sys.argv
        try:
            sys.argv = ["preflight.py", "--cleanup", "--json"]
            with mock.patch.object(preflight, "run", side_effect=fake_run), \
                    contextlib.redirect_stdout(io.StringIO()) as buf:
                rc = preflight.main()
        finally:
            sys.argv = old_argv

        self.assertEqual(rc, 1, buf.getvalue())
        self.assertEqual(calls, [["adb", "devices", "-l"]], calls)
        self.assertIn("no --serial", buf.getvalue())

    def test_preflight_rejects_requested_serial_that_is_not_online(self):
        calls = []

        def fake_run(cmd, timeout=60):
            calls.append(cmd)
            return 0, "List of devices attached\nA\tdevice\nB\tunauthorized\n"

        old_argv = sys.argv
        try:
            sys.argv = ["preflight.py", "--serial", "B", "--cleanup", "--json"]
            with mock.patch.object(preflight, "run", side_effect=fake_run), \
                    contextlib.redirect_stdout(io.StringIO()) as buf:
                rc = preflight.main()
        finally:
            sys.argv = old_argv

        self.assertEqual(rc, 1, buf.getvalue())
        self.assertEqual(calls, [["adb", "devices", "-l"]], calls)
        self.assertIn("requested serial is not online", buf.getvalue())

    def test_preflight_cleanup_failures_are_reported_as_failures(self):
        def fake_run(cmd, timeout=60):
            tail = " ".join(cmd)
            if cmd[-2:] == ["devices", "-l"]:
                return 0, "List of devices attached\nA\tdevice\n"
            if tail.endswith("shell settings get global http_proxy"):
                return 0, "127.0.0.1:8080\n"
            if tail.endswith("shell settings put global http_proxy :0"):
                return 7, "denied proxy cleanup\n"
            if tail.endswith("forward --list"):
                return 0, "A tcp:1 tcp:2\n"
            if tail.endswith("forward --remove-all"):
                return 8, "denied forward cleanup\n"
            return 0, ""

        old_argv = sys.argv
        try:
            sys.argv = ["preflight.py", "--serial", "A", "--cleanup", "--json"]
            with mock.patch.object(preflight.shutil, "which", return_value="found"), \
                    mock.patch.object(preflight, "run", side_effect=fake_run), \
                    contextlib.redirect_stdout(io.StringIO()) as buf:
                rc = preflight.main()
        finally:
            sys.argv = old_argv

        payload = json.loads(buf.getvalue())
        rows = [r for r in payload["rows"]
                if r["area"] in ("state:proxy", "state:forwards")]
        details = " | ".join(r["detail"] for r in rows)
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertEqual(sum(r["level"] == "WARN" for r in rows), 3, rows)
        self.assertIn("proxy cleanup FAILED (rc=7)", details)
        self.assertIn("forward cleanup FAILED (rc=8)", details)
        self.assertNotIn("cleared", details)
        self.assertNotIn("removed (--cleanup)", details)

    def test_shipped_offline_self_tests_remain_green(self):
        with tempfile.TemporaryDirectory() as td:
            empty_path = Path(td)
            for script in ("patch_smali.py", "dex_patch_bytes.py", "repack.py",
                           "preflight.py", "doctor.py"):
                got = run_script(script, "--self-test", path_dir=empty_path, timeout=30)
                self.assertEqual(got.returncode, 0,
                                 "%s failed:\n%s\n%s"
                                 % (script, got.stdout, got.stderr))

    def test_witness_help_entry_resolves_without_a_device(self):
        with tempfile.TemporaryDirectory() as td:
            got = run_script("witness.py", "--help", path_dir=Path(td))
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn("apkseep witness", got.stdout)


if __name__ == "__main__":
    unittest.main()
