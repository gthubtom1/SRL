#!/usr/bin/env python3
"""Bounded nine-domain task delivery, real offline tools + existing project CLIs.

Run: python -B -X utf8 Tool/scripts/test_domain_task_delivery.py
Artifacts: tmp/final-closure-20261030/domain-delivery/run-*/
No sample is executed. Loopback HTTP serves only our synthetic extracted files.
Missing tools are explicit unittest skips (BLOCKED), never substitute outputs.
Core validates evidence identity, not the truth of arbitrary analyst prose; all
professional assertions below run before any acceptance pass is recorded.
"""
from __future__ import annotations

import functools
import hashlib
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "Tool/scripts"
SKILLS = ROOT / "Tool/skill"
OUT = ROOT / "tmp/final-closure-20261030/domain-delivery"
SESSION = None
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8", PYTHONUTF8="1")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def pcap_records(path):
    """Independent classic PCAP record reader; never decode auth attributes."""
    data = Path(path).read_bytes()
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}[data[:4]]
    assert struct.unpack_from(endian + "I", data, 20)[0] == 1, "Ethernet required"
    records, pos = [], 24
    while pos < len(data):
        sec, usec, cap, wire = struct.unpack_from(endian + "IIII", data, pos)
        pos += 16
        assert pos + cap <= len(data), "truncated packet"
        records.append((sec + usec / 1e6, data[pos:pos + cap], wire))
        pos += cap
    return records


class DomainDelivery(unittest.TestCase):
    def setUp(self):
        global SESSION
        if SESSION is None:
            OUT.mkdir(parents=True, exist_ok=True)
            SESSION = Path(tempfile.mkdtemp(prefix="run-", dir=OUT))
        # Leave room for Windows archive staging and revision SHA filenames.
        self.base = SESSION / ("t" + self._testMethodName.split("_")[1])
        self.base.mkdir()
        self.project = self.base / "project"
        self.counter = 0
        self.sources = {}
        self.evidence = []
        self.run_id = "delivery"
        self.domains = []
        self.bounds = []
        self.addCleanup(self.check_sources)

    def check_sources(self):
        for path, fingerprint in self.sources.items():
            self.assertEqual(sha(path), fingerprint, "source changed: " + str(path))

    def public(self, case, filename):
        directory = ROOT / "Tool/cases" / case
        path = directory / "target" / filename
        meta = load(directory / "case.json")
        records = [r for r in meta["target_files"] if r["path"] == "target/" + filename]
        self.assertEqual(len(records), 1)
        self.assertEqual(sha(path), records[0]["sha256"], "public sample identity drift")
        self.sources[path] = sha(path)
        save(self.base / (case + "-sample.json"), {
            "case": case, "kind": meta.get("evidence_kind"), **records[0]})
        return path

    def invoke(self, argv, expect=0, capture=None, timeout=55):
        self.counter += 1
        destination = capture or self.base / "commands" / ("%03d" % self.counter)
        destination.parent.mkdir(parents=True, exist_ok=True)
        args = list(map(str, argv))
        started = time.monotonic()
        proc = subprocess.run(args, cwd=ROOT, env=ENV, capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=timeout, shell=False)
        stdout = destination.with_suffix(".stdout.txt")
        stderr = destination.with_suffix(".stderr.txt")
        stdout.write_text(proc.stdout, encoding="utf-8")
        stderr.write_text(proc.stderr, encoding="utf-8")
        save(destination.with_suffix(".command.json"), {
            "argv": args, "cwd": str(ROOT), "rc": proc.returncode,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "python_script_sha256": sha(args[4]) if len(args) > 4 and args[4].endswith(".py") and Path(args[4]).is_file() else None,
            "stdout": {"path": str(stdout), "sha256": sha(stdout)},
            "stderr": {"path": str(stderr), "sha256": sha(stderr)},
            "sample_executed": False})
        if expect is not None:
            self.assertIn(proc.returncode, expect if isinstance(expect, tuple) else (expect,),
                          str(args) + "\n" + proc.stdout[-3000:] + proc.stderr[-1000:])
        return proc, stdout

    def cli(self, script, *args, expect=0):
        proc, _ = self.invoke([sys.executable, "-B", "-X", "utf8", SCRIPTS / script, *args], expect)
        try:
            value = json.loads(proc.stdout)
        except ValueError:
            self.fail("CLI did not return JSON: " + proc.stdout[-2000:])
        if expect == 0:
            self.assertTrue(value.get("ok"), value)
        elif expect is not None:
            self.assertFalse(value.get("ok"), value)
        return value

    def start(self, target, primary, auxiliary=(), quote="只读核实有限静态目标，记录证据"):
        self.domains = [primary, *auxiliary]
        args = []
        for domain in auxiliary:
            args += ["--aux-domain", domain]
        result = self.cli("project_workflow.py", "start", "--project", self.project,
                          "--target", target, "--primary-domain", primary,
                          "--quote", quote, "--allow-ambiguous", "--run-id", self.run_id,
                          "--route-id", "static", "--p", "0.5", "--hours", "1h",
                          "--fail", "identity drift or unsupported semantic claim",
                          "--evidence-goal", "bounded observed task with negative controls",
                          *args, "--json")
        self.assertFalse(result["executed_target"])
        self.assertEqual(result["run"], self.run_id)
        self.version = load(self.project / "versions/1.0/version.json")
        self.target = self.project / self.version["local_path"]
        # A second process must recover exactly this project/version/run.
        self.cli("project_state.py", "resume", "--project", self.project)
        return self.target

    def asset(self, source, ident):
        result = self.cli("project_state.py", "asset", "--project", self.project,
                          "--version", "1.0", "--asset-id", ident,
                          "--role", "auxiliary", "--target", source)
        # Use the authoritative API for both file and directory snapshot bindings.
        if str(SCRIPTS) not in sys.path:
            sys.path.insert(0, str(SCRIPTS))
        import project_state
        binding = project_state.asset_binding(self.project, "1.0", ident)
        self.assertEqual(binding["asset_id"], ident, result)
        return self.project / binding["local_path"]

    def register(self, path, ident, asset=""):
        rel = path.relative_to(self.project).as_posix()
        extra = ["--input-asset", asset] if asset else []
        result = self.cli("project_state.py", "evidence", "--project", self.project,
                          "--version", "1.0", "--run-id", self.run_id,
                          "--evidence-id", ident, "--kind", "evidence",
                          "--target-sha256", self.version["sha256"],
                          "--path", rel, "--source", rel, "--sha256", sha(path),
                          "--size", path.stat().st_size, "--how", "real read-only CLI output",
                          *extra)
        if asset:
            self.assertEqual(result["evidence"]["input_asset"]["asset_id"], asset)
        self.evidence.append(ident)
        return ident

    def tool(self, domain, script, *args, ident, asset="", expect=0, as_json=True):
        capture = self.project / "versions/1.0/runs" / self.run_id / "capture" / ident
        proc, stdout = self.invoke([sys.executable, "-B", "-X", "utf8",
                                   SKILLS / domain / "scripts" / script, *args],
                                  expect, capture)
        self.register(stdout, ident, asset)
        self.register(capture.with_suffix(".command.json"), ident + "-command", asset)
        return json.loads(proc.stdout) if as_json else proc.stdout

    def external(self, argv, ident, asset="", as_json=False):
        capture = self.project / "versions/1.0/runs" / self.run_id / "capture" / ident
        proc, stdout = self.invoke(argv, capture=capture)
        self.register(stdout, ident, asset)
        self.register(capture.with_suffix(".command.json"), ident + "-command", asset)
        return json.loads(proc.stdout) if as_json else proc.stdout

    def finish(self, observed, boundary):
        # This method is called ONLY after professional assertions and controls.
        self.bounds.append(boundary)
        path = self.project / "versions/1.0/artifacts/claims.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        records = [
            {"id": "bounded-observation", "kind": "claim", "claim": observed,
             "status": "proven", "confidence": "observed", "authority": "offline-verifier",
             "evidence": list(self.evidence)},
            {"id": "unsupported-strong-conclusion", "kind": "claim", "claim": boundary,
             "status": "proven", "confidence": "observed", "authority": "offline-verifier",
             "evidence": []}]
        path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records), encoding="utf-8")
        self.register(path, "claims")
        self.cli("project_state.py", "acceptance-define", "--project", self.project,
                 "--version", "1.0", "--item", "bounded:" + observed)
        self.cli("project_state.py", "acceptance-record", "--project", self.project,
                 "--version", "1.0", "--item-id", "bounded", "--result", "pass",
                 "--verifier", "negative-control", "--how", "no supporting evidence",
                 "--run", self.run_id, expect=2)
        self.cli("project_state.py", "finish-run", "--project", self.project,
                 "--version", "1.0", "--run-id", self.run_id, "--status", "completed", expect=2)
        self.assertEqual(load(self.project / "versions/1.0/runs/delivery/run.json")["status"], "active")
        closed = self.cli("project_workflow.py", "close", "--project", self.project,
                          "--version", "1.0", "--run", self.run_id,
                          "--define", "bounded:" + observed,
                          "--accept", "bounded=pass:" + ",".join(self.evidence),
                          "--verifier", "test_domain_task_delivery",
                          "--how", "professional assertions and negative controls in dedicated test",
                          "--finish", "completed", "--json")
        self.assertTrue(closed["acceptance"]["complete"])
        self.assertEqual(closed["run_status"], "completed")
        self.cli("project_report.py", "generate", "--project", self.project,
                 "--version", "1.0", "--run-id", self.run_id, "--report-id", "delivery",
                 "--kind", "final", "--claim-evidence-id", "claims")
        manifest = load(self.project / "reports/delivery/manifest.json")
        self.assertEqual(manifest["claims"]["confirmed_ids"], ["bounded-observation"])
        self.assertEqual(manifest["claims"]["unknown_ids"], ["unsupported-strong-conclusion"])
        self.cli("project_report.py", "show", "--project", self.project, "--final")
        resume = self.cli("project_state.py", "resume", "--project", self.project)
        self.assertEqual(resume["handoff"]["closure_errors"], [])
        save(self.base / "task-result.json", {"status": "PASS-bounded-task", "test": self._testMethodName,
             "domains": self.domains,
             "observed": observed, "unsupported": boundary,
             "professional_checks": "assertions completed before acceptance", "project": str(self.project)})

    def need(self, executable):
        binary = shutil.which(executable)
        if not binary:
            self.skipTest("BLOCKED: " + executable + " required for independent semantic verification")
        return binary

    def r2(self):
        binary = ROOT / "Tool/mcp/Tool/safe/radare2/bin" / ("radare2.exe" if os.name == "nt" else "radare2")
        return str(binary) if binary.is_file() else self.need("radare2")

    def assert_rejects(self, checker, wrong):
        with self.assertRaises(AssertionError):
            checker(wrong)

    def test_01_software_branch_task(self):
        binary = self.r2()
        target = self.start(self.public("golden-crackme", "a.exe"), "softseep")
        data = self.external([binary, "-2", "-q", "-c", "aaa;pdfj @ sym.main", target],
                             ident="main-disassembly", as_json=True)

        def validate(value):
            ops = {o["offset"]: o for o in value["ops"]}
            self.assertEqual(value["addr"], 0x140002860)
            for address, literal in ((0x14000287a, 0x6e617274), (0x140002897, 0x65636e)):
                self.assertEqual(ops[address]["type"], "cmp")
                self.assertEqual(ops[address]["val"], literal)
            self.assertEqual(ops[0x140002882]["jump"], 0x140002897)
            self.assertEqual(ops[0x14000289f]["jump"], 0x140002884)
            self.assertIn("str.FAIL", ops[0x140002884]["disasm"])
            self.assertIn("str.PASS", ops[0x1400028a1]["disasm"])
            return ops

        ops = validate(data)
        # Map observed virtual instructions back to raw file, independently of r2.
        pe = target.read_bytes()
        off = struct.unpack_from("<I", pe, 0x3c)[0]
        optsize = struct.unpack_from("<H", pe, off + 20)[0]
        sections = off + 24 + optsize
        text_va, text_size, text_raw = None, None, None
        for n in range(struct.unpack_from("<H", pe, off + 6)[0]):
            section = sections + 40 * n
            if pe[section:section + 8].rstrip(b"\0") == b".text":
                text_va = struct.unpack_from("<I", pe, section + 12)[0]
                text_size, text_raw = struct.unpack_from("<II", pe, section + 16)
        self.assertIsNotNone(text_raw)
        for address in (0x14000287a, 0x140002882, 0x140002897, 0x14000289f):
            instruction = bytes.fromhex(ops[address]["bytes"])
            file_offset = address - 0x140000000 - text_va + text_raw
            self.assertEqual(pe[file_offset:file_offset + len(instruction)], instruction)
        wrong = json.loads(json.dumps(data))
        next(o for o in wrong["ops"] if o["offset"] == 0x14000287a)["val"] ^= 1
        self.assert_rejects(validate, wrong)
        self.finish("PE main at 0x140002860 compares overlapping tran and nce-NUL words and branches to FAIL/PASS",
                    "A patched binary runs correctly and preserves all original behavior")

    def test_02_apk_so_delivery_and_archive(self):
        self.r2()  # This task requires the actual softseep auxiliary parser.
        apk = self.public("apkseep07", "UnCrackable-Level2.apk")
        target = self.start(apk, "apkseep", ["softseep"], "核实 APK JNI 边界并复查 SO 导入")
        act = self.cli("project_workflow.py", "act", "--project", self.project,
                       "--action", "apk.info", "--json")
        self.assertEqual(act["outcome"], "succeeded")
        self.evidence.append(act["evidence_id"])
        probe = self.tool("apkseep", "java2c_probe.py", "--apk", target, "--json", ident="jni-boundary")
        expected = {"Java_sg_vantagepoint_uncrackable2_CodeCheck_bar",
                    "Java_sg_vantagepoint_uncrackable2_MainActivity_init"}
        def check_jni_materials(value):
            self.assertEqual(value["dex"][0]["native_methods"], 2)
            self.assertEqual(len(value["native"]), 4)
            self.assertEqual({x["arch"] for x in value["native"]}, {"arm", "aarch64", "x86", "x86_64"})
            for library in value["native"]:
                self.assertEqual(set(library["java_symbol_sample"]), expected)
        check_jni_materials(probe)
        with zipfile.ZipFile(target) as zf:
            dex = module("delivery_java2c", SKILLS / "apkseep/scripts/java2c_probe.py").Dex(zf.read("classes.dex"), "classes.dex")
            methods = [m for m in dex.methods if m["flags"] & 0x100]
            self.assertEqual({(m["class"], m["name"]) for m in methods}, {
                ("Lsg/vantagepoint/uncrackable2/CodeCheck;", "bar"),
                ("Lsg/vantagepoint/uncrackable2/MainActivity;", "init")})
            self.assertTrue(all(m["code_off"] == 0 for m in methods))
            source_so = self.base / "libfoo.so"
            source_so.write_bytes(zf.read("lib/arm64-v8a/libfoo.so"))
            stripped = self.base / "without-native.apk"
            with zipfile.ZipFile(stripped, "w") as out:
                for name in zf.namelist():
                    if not name.startswith("lib/"):
                        out.writestr(name, zf.read(name))
        so = self.asset(source_so, "arm64-so")
        capture_dir = self.project / "versions/1.0/runs/delivery/capture"
        before_refusal = {p.name: sha(p) for p in capture_dir.iterdir() if p.is_file()}
        refused = self.cli("project_workflow.py", "act", "--project", self.project,
                           "--action", "pcap.extract", "--json", expect=3)
        self.assertIn("pack.tools", refused["reason"])
        self.assertEqual(before_refusal, {p.name: sha(p) for p in capture_dir.iterdir() if p.is_file()})
        native_action = self.cli("project_workflow.py", "act", "--project", self.project,
                                "--action", "r2.disasm", "--asset-id", "arm64-so",
                                "--args-json", json.dumps({"target": "sym.Java_sg_vantagepoint_uncrackable2_CodeCheck_bar",
                                                           "lines": 100, "output_mode": "full"}), "--json")
        self.assertEqual(native_action["outcome"], "succeeded")
        native_capture = load(self.project / native_action["capture"])
        self.assertEqual(native_capture["admission"]["owner_domains"], ["softseep"])
        self.assertEqual(native_capture["input_asset"]["asset_id"], "arm64-so")
        self.assertIn("strncmp", native_capture["stdout"])
        self.assertIn("0x00000e48", native_capture["stdout"])
        self.evidence.append(native_action["evidence_id"])
        plt = self.tool("apkseep", "elf_plt.py", so, ident="native-plt", asset="arm64-so", as_json=False)
        self.assertRegex(plt, r"0x0*810\s+-> strncmp\s+\(GOT 0x12fb8\)")
        self.assertRegex(plt, r"0x0*800\s+-> ptrace\s+\(GOT 0x12fb0\)")
        stripped_input = self.asset(stripped, "without-so")
        negative = self.tool("apkseep", "java2c_probe.py", "--apk", stripped_input, "--json",
                             ident="without-so-control", asset="without-so")
        self.assertEqual(negative["native"], [])
        self.assertEqual(negative["dex"][0]["native_methods"], 2)
        # jni-sinking also describes declarations without their libraries. That
        # route label cannot certify delivery; the same material predicate must
        # reject the stripped APK even when its label is unchanged.
        self.assert_rejects(check_jni_materials, negative)
        self.finish("Two DEX native declarations match exports in four ABI libraries; softseep disassembly observes CodeCheck_bar call at 0xe48 and arm64 PLT 0x810 resolving strncmp, 0x800 ptrace",
                    "The APK has been bypassed and runs correctly on an Android device")
        self.archive_and_faults()

    def archive_and_faults(self):
        archive = self.base / "delivery.zip"
        self.cli("project_archive.py", "export", "--project", self.project, "--out", archive)
        self.cli("project_archive.py", "verify", "--archive", archive)
        with zipfile.ZipFile(archive) as zf:
            manifest = json.loads(zf.read("archive.json"))
            names = {x["path"] for x in manifest["files"]}
            self.assertIn("reports/delivery/report.md", names)
            self.assertIn("versions/1.0/runs/delivery/capture/native-plt.stdout.txt", names)
            self.assertTrue(any(p.startswith("assets/arm64-so/") for p in names))
        original = self.project
        original.rename(self.base / "original-project-moved")
        relocated = self.base / "relocated" / "restored"
        relocated.parent.mkdir()
        self.cli("project_archive.py", "import", "--archive", archive, "--project", relocated)
        self.project = relocated
        result = self.cli("project_state.py", "resume", "--project", relocated)
        self.assertTrue(result["handoff"]["acceptance_complete"])
        self.assertEqual(result["handoff"]["completed_runs"], [self.run_id])
        self.cli("project_report.py", "show", "--project", relocated, "--final")
        # Replay uses only the imported project's input asset, after old root moved.
        import project_state
        binding = project_state.asset_binding(relocated, "1.0", "arm64-so")
        proc, _ = self.invoke([sys.executable, "-B", "-X", "utf8", SKILLS / "apkseep/scripts/elf_plt.py",
                               relocated / binding["local_path"], "--symbol", "strncmp"])
        self.assertRegex(proc.stdout, r"0x0*810.*strncmp")
        faults = {}
        for label, victim in (("evidence-tamper", relocated / "versions/1.0/runs/delivery/capture/native-plt.stdout.txt"),
                              ("missing-asset", relocated / binding["local_path"]),
                              ("report-tamper", relocated / "reports/delivery/report.md")):
            original_bytes = victim.read_bytes()
            try:
                if label == "missing-asset":
                    victim.unlink()
                else:
                    victim.write_bytes(original_bytes + b"\nmodified\n")
                rejected = self.cli("project_state.py", "resume", "--project", relocated, expect=2)
                self.assertTrue(rejected["handoff"]["closure_errors"] or rejected["handoff"].get("report"), rejected)
                self.cli("project_report.py", "show", "--project", relocated, "--final", expect=2)
                faults[label] = "rejected by resumed closure and report"
            finally:
                victim.write_bytes(original_bytes)
            self.cli("project_state.py", "resume", "--project", relocated)
        # Cross-run / cross-version controls use copies; delivery archive stays healthy.
        for mode in ("cross-run", "wrong-version"):
            clone = self.base / mode
            shutil.copytree(relocated, clone)
            version = "1.0"
            if mode == "wrong-version":
                changed = self.base / "new-version.apk"
                with zipfile.ZipFile(changed, "w") as zf:
                    zf.writestr("AndroidManifest.xml", b"synthetic version control")
                version = "2.0"
                self.cli("project_state.py", "version", "--project", clone, "--version", version,
                         "--parent", "1.0", "--target", changed)
                self.cli("project_state.py", "acceptance-define", "--project", clone,
                         "--version", version, "--item", "bounded:version isolation")
            self.cli("project_state.py", "run", "--project", clone, "--version", version, "--run-id", "next-run")
            self.cli("project_state.py", "acceptance-record", "--project", clone,
                     "--version", version, "--item-id", "bounded", "--result", "pass",
                     "--evidence-ids", "native-plt", "--verifier", "negative-control",
                     "--how", "must refuse stale evidence", "--run", "next-run", expect=2)
            self.cli("project_state.py", "finish-run", "--project", clone, "--version", version,
                     "--run-id", "next-run", "--status", "completed", expect=2)
            self.assertEqual(load(clone / ("versions/" + version + "/runs/next-run/run.json"))["status"], "active")
            faults[mode] = "pass and completed refused; run remains active"
        # Missing/corrupt ZIP member must fail actual archive validation.
        for mode in ("missing", "tampered"):
            broken = self.base / (mode + ".zip")
            with zipfile.ZipFile(archive) as src, zipfile.ZipFile(broken, "w", zipfile.ZIP_DEFLATED) as dst:
                for item in src.infolist():
                    data = src.read(item)
                    if item.filename.endswith("capture/native-plt.stdout.txt"):
                        if mode == "missing":
                            continue
                        data += b"changed"
                    dst.writestr(item, data)
            self.cli("project_archive.py", "verify", "--archive", broken, expect=2)
            faults["archive-" + mode] = "rejected"
        save(self.base / "archive-fault-results.json", faults)

    def test_03_protocol_radius_task(self):
        tshark = self.need("tshark")
        target = self.start(self.public("protocol05", "RADIUS.pcap"), "protocol-plugin", ["forensics-mobile"])
        summary = self.tool("protocol-plugin", "pcap-summary.py", "--file", target, "--json", ident="radius-summary")
        self.assertEqual(summary["packet_count"], 4)
        self.assertEqual(summary["session_count"], 2)
        raw = pcap_records(target)
        expected = [(1, 1, 5, 139), (2, 11, 5, 109), (3, 1, 6, 174), (4, 2, 6, 97)]
        manual = []
        for frame, (_, packet, _) in enumerate(raw, 1):
            ihl = (packet[14] & 15) * 4
            self.assertEqual(packet[23], 17)
            udp = 14 + ihl
            sport, dport, length = struct.unpack_from("!HHH", packet, udp)
            self.assertIn(1812, (sport, dport))
            code, ident, size = struct.unpack_from("!BBH", packet, udp + 8)
            self.assertEqual(size, length - 8)
            manual.append((frame, code, ident, size))
        self.assertEqual(manual, expected)
        text = self.external([tshark, "-n", "-r", target, "-T", "fields", "-e", "frame.number",
                              "-e", "radius.code", "-e", "radius.id", "-e", "radius.length"], ident="radius-fields")
        decoded = [tuple(map(int, line.split("\t"))) for line in text.splitlines()]
        self.assertEqual(decoded, expected)
        self.assertEqual(decoded[0][2], decoded[1][2])
        self.assertEqual(decoded[2][2], decoded[3][2])
        self.assertNotEqual(decoded[0][2], decoded[3][2])  # wrong response pairing
        forensic = self.tool("forensics-mobile", "forensics-check.py", "--file", target, "--json", ident="radius-forensic")
        self.assertEqual(forensic["meta"]["packet_count"], 4)
        self.assertEqual(forensic["integrity"]["sha256"], sha(target))
        truncated = self.base / "truncated.pcap"
        truncated.write_bytes(target.read_bytes()[:30])
        proc, _ = self.invoke([sys.executable, "-B", SKILLS / "protocol-plugin/scripts/pcap-summary.py",
                               "--file", truncated, "--json"], expect=2)
        self.assertFalse(json.loads(proc.stdout)["ok"])
        self.finish("Four RADIUS packets form id=5 Access-Request/Challenge and id=6 Access-Request/Accept pairs; lengths agree with UDP and tshark",
                    "RADIUS authentication authenticators are cryptographically verified")

    def test_04_forensic_timeline_task(self):
        tshark = self.need("tshark")
        target = self.start(self.public("forensics07", "bgp-4byte-asn.pcap"), "forensics-mobile", ["protocol-plugin"])
        forensic = self.tool("forensics-mobile", "forensics-check.py", "--file", target, "--json", ident="timeline")
        records = pcap_records(target)
        self.assertEqual(len(records), 91)
        self.assertEqual(forensic["meta"]["packet_count"], 91)
        times = [record[0] for record in records]
        self.assertAlmostEqual(min(times), 1555002999.743518, places=5)
        self.assertAlmostEqual(max(times), 1555003020.444552, places=5)
        self.assertTrue(forensic["timeline"]["start_utc"].startswith("2019-04-11T17:16:39"))
        self.assertTrue(forensic["timeline"]["end_utc"].startswith("2019-04-11T17:17:00"))
        self.assertEqual(forensic["integrity"]["sha256"], sha(target))
        text = self.external([tshark, "-n", "-r", target, "-Y", "bgp", "-T", "fields",
                              "-e", "frame.number", "-e", "frame.time_epoch", "-e", "ip.src",
                              "-e", "ip.dst", "-e", "bgp.type"], ident="bgp-events")
        rows = {int(line.split("\t")[0]): line.split("\t") for line in text.splitlines()}
        expected = {6: ("1.0.2.2", "1.0.2.1", "1"), 48: ("1.0.4.2", "1.0.4.1", "4"),
                    85: ("1.0.0.2", "1.0.0.1", "3")}
        for frame, event in expected.items():
            self.assertEqual(tuple(rows[frame][2:]), event)
            self.assertAlmostEqual(float(rows[frame][1]), records[frame - 1][0], places=5)
        self.assertNotEqual(rows[85][-1], "4")
        self.assertNotIn("2014", forensic["timeline"]["start_utc"])
        self.finish("BGP capture has 91 frames in 2019-04-11 17:16:39.743518..17:17:00.444552 UTC; frames 6/48/85 decode OPEN/KEEPALIVE/NOTIFICATION at recorded endpoints",
                    "Capture timestamps prove wall clock accuracy and a complete established BGP state machine")

    def test_05_pwn_protections_task(self):
        target = self.start(self.public("pwn-crypto07", "dostackbufferoverflowgood.exe"), "pwn-crypto", ["softseep"])
        result = self.tool("pwn-crypto", "pwn-check.py", "--file", target, "--json", ident="protection-surface")
        data = target.read_bytes()
        pe = struct.unpack_from("<I", data, 0x3c)[0]
        machine = struct.unpack_from("<H", data, pe + 4)[0]
        flags_offset = pe + 24 + 70
        flags = struct.unpack_from("<H", data, flags_offset)[0]
        self.assertEqual(machine, 0x14c)
        self.assertFalse(flags & 0x140)
        self.assertEqual(result["protections"]["NX"], "Disabled")
        self.assertEqual(result["protections"]["PIE"], "Disabled")
        cookie = result["load_config"]
        self.assertEqual(cookie["rva"], "0x31e0")
        self.assertEqual(sha(target), self.version["sha256"])
        self.assertEqual(cookie["security_cookie"], "0x8044018")
        self.assertEqual(struct.unpack_from("<I", data, 0x1fe0 + 0x3c)[0], 0x8044018)
        self.assertIn("SecurityCookie", result["protections"]["Canary"])
        self.assertTrue(any(x["symbol"] == "memmove" for x in result["dangerous_imports"]))
        # Controlled header variation, still never executed; true positive off->on.
        variant = self.base / "nx-aslr-control.exe"
        changed = bytearray(data)
        struct.pack_into("<H", changed, flags_offset, flags | 0x140)
        variant.write_bytes(changed)
        variant_input = self.asset(variant, "protection-control")
        control = self.tool("pwn-crypto", "pwn-check.py", "--file", variant_input, "--json",
                            ident="protections-on-control", asset="protection-control")
        self.assertEqual(control["protections"]["NX"], "Enabled")
        self.assertEqual(control["protections"]["PIE"], "Enabled (DYNAMIC_BASE/ASLR)")
        self.assertNotEqual(control["sha256"], result["sha256"])
        self.finish("Published PE32 lacks NX_COMPAT/DYNAMIC_BASE and declares a SecurityCookie; memmove import observed; controlled flag changes produce Enabled",
                    "A working exploit or per-function GS protection has been demonstrated")

    def test_06_malware_packed_vs_clean_task(self):
        target = self.start(self.public("leaf-pe-packed", "a_upx.exe"), "malware-analysis", ["softseep"])
        clean = self.asset(self.public("golden-crackme", "a.exe"), "clean-original")
        packed = self.tool("malware-analysis", "mal-triage.py", "--file", target, "--json", ident="packed-static")
        plain = self.tool("malware-analysis", "mal-triage.py", "--file", clean, "--json", ident="clean-static", asset="clean-original")
        by_name = {s["name"]: s for s in packed["sections"]}
        self.assertEqual(set(by_name), {"UPX0", "UPX1", "UPX2"})
        self.assertEqual(by_name["UPX0"]["rawsize"], 0)
        self.assertGreater(by_name["UPX0"]["vsize"], 0)
        self.assertTrue(by_name["UPX1"]["entry"])
        self.assertGreater(by_name["UPX1"]["entropy"], 7.2)
        self.assertTrue(any("GetProcAddress" == hit["symbol"] for group in packed["suspicious_imports"] for hit in group["hits"]))
        self.assertFalse(any(s["name"].startswith("UPX") for s in plain["sections"]))
        self.assertFalse(any("UPX" in a for a in plain["section_anomalies"]))
        self.assertEqual(packed["iocs"]["urls"], [])
        self.assertEqual(packed["iocs"]["domains"], [])
        self.assertIn("无唯一字符串", packed["yara"]["text"])
        save(self.base / "behavior-chain.json", {"status": "BLOCKED", "reason": "No same-sample traffic or memory capture in retained materials; packed sample is a public benign crackme", "needed": ["authorized same-sample traffic/memory", "isolated execution environment for dynamic behavior if required"]})
        self.finish("Packed public crackme has UPX0 zero disk size, high entropy UPX1 entry and dynamic-resolution import; clean original has no UPX sections",
                    "The sample is malicious, its candidate YARA rule is specific, or C2 behavior is established")

    def test_07_firmware_web_material_handoff(self):
        target = self.start(self.public("firmware-iot06", "cramfs.bin"), "firmware-iot", ["web-pentest"])
        real_out = self.project / "versions/1.0/artifacts/real-rootfs"
        result = self.tool("firmware-iot", "fw-repro.py", "--file", target,
                           "--out-dir", real_out, "--json", ident="public-cramfs", expect=(0, 1, 2))
        if result.get("blocked_at") == "tool-missing":
            self.skipTest("BLOCKED: real CramFS extractor missing; no extraction success claimed")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["extraction"]["status"], "extracted")
        files = list((real_out / "extracted-cramfs").rglob("*"))
        files = [p for p in files if p.is_file()]
        self.assertEqual([p.name for p in files], ["lsb-release"])
        self.assertEqual(files[0].read_text(encoding="utf-8"),
                         'DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\nDISTRIB_CODENAME=jammy\nDISTRIB_DESCRIPTION="Ubuntu 22.04.5 LTS"\n')
        self.register(files[0], "release-info")
        fixture = self.base / "synthetic-web-rootfs.tar"
        members = {"www/index.html": b"<html><title>synthetic firmware UI</title>static only</html>",
                   "www/robots.txt": b"User-agent: *\nDisallow: /admin/\n",
                   "www/.git/HEAD": b"ref: refs/heads/main\n"}
        with tarfile.open(fixture, "w", format=tarfile.USTAR_FORMAT) as tf:
            for name, content in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                tf.addfile(info, io.BytesIO(content))
        registered = self.asset(fixture, "synthetic-firmware")
        extracted = self.project / "versions/1.0/artifacts/synthetic-rootfs"
        synthetic = self.tool("firmware-iot", "fw-repro.py", "--file", registered,
                              "--out-dir", extracted, "--json", ident="synthetic-extract", asset="synthetic-firmware")
        self.assertEqual(synthetic["extraction"]["status"], "extracted")
        webroot = extracted / "extracted-tar/www"
        for name, content in members.items():
            self.assertEqual((webroot / name.removeprefix("www/")).read_bytes(), content)
        # Preserve extracted bytes as a registered snapshot; serve that snapshot.
        served = self.asset(webroot, "extracted-web")
        server = None
        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass
        handler = functools.partial(QuietHandler, directory=str(served))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        url = "http://127.0.0.1:%d/" % server.server_port
        try:
            scan = self.tool("web-pentest", "web-check.py", "--url", url, "--rate", "0",
                             "--max-paths", "6", "--timeout", "3", ident="extracted-web-scan", asset="extracted-web")
            hits = scan["checks"]["sensitive_paths"]["hits"]
            self.assertTrue(any(h["path"] == "/.git/HEAD" and h["verdict"] == "hit" for h in hits))
            self.assertIn("/admin/", scan["checks"]["robots"]["interesting"])
            # Counterexample uses another served directory, never mutates registered asset.
            safe = self.base / "safe-web"
            safe.mkdir()
            (safe / "index.html").write_bytes(members["www/index.html"])
            safe_input = self.asset(safe, "web-without-git")
            class FallbackHandler(QuietHandler):
                def do_GET(self):
                    self.path = "/index.html"
                    super().do_GET()
            safe_handler = functools.partial(FallbackHandler, directory=str(safe_input))
            safe_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), safe_handler)
            safe_worker = threading.Thread(target=safe_server.serve_forever, daemon=True)
            safe_worker.start()
            try:
                safe_url = "http://127.0.0.1:%d/" % safe_server.server_port
                control = self.tool("web-pentest", "web-check.py", "--url", safe_url, "--rate", "0",
                                    "--max-paths", "6", "--timeout", "3", ident="web-without-git-control",
                                    asset="web-without-git")
                control_rows = control["checks"]["sensitive_paths"]["hits"]
                self.assertFalse(any(h["verdict"] == "hit" for h in control_rows))
                git_row = next(h for h in control_rows if h["path"] == "/.git/HEAD")
                self.assertEqual(git_row["status"], 200)
                self.assertEqual(git_row["verdict"], "soft-404/spa-fallback")
            finally:
                safe_server.shutdown()
                safe_server.server_close()
                safe_worker.join(timeout=2)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)
        save(self.base / "real-device-web.json", {"status": "BLOCKED", "reason": "Public cramfs contains only lsb-release; no www/service/device. Firmware->Web task uses explicitly synthetic rootfs and loopback HTTP."})
        self.finish("Real CramFS yields exact Ubuntu 22.04.5 lsb-release; synthetic www bytes survive extraction and asset snapshot; loopback scan distinguishes exposed git HEAD from HTTP 200 soft-404 fallback",
                    "The real firmware device boots and its Web service is exploitable")

    def test_08_supply_chain_artifact_task(self):
        manifest = self.public("supply-chain05", "package.json")
        target = self.start(manifest, "supply-chain-security", ["forensics-mobile"])
        # Scan isolated registered material, no ancestor lockfile contamination.
        scanroot = self.project / "versions/1.0/artifacts/manifest-snapshot"
        scanroot.mkdir(parents=True)
        shutil.copyfile(target, scanroot / "package.json")
        result = self.tool("supply-chain-security", "sc-check.py", "--path", scanroot,
                           ident="public-manifest-risks", expect=1)
        self.assertEqual(result["inventory"]["locks"], [])
        self.assertTrue(any(r["category"] == "lockfile" and r["level"] == "high" for r in result["risks"]))
        declaration = load(target)
        total = len(declaration.get("dependencies", {})) + len(declaration.get("devDependencies", {}))
        self.assertEqual(total, 114)
        fixture_root = ROOT / "Tool/cases/supply-chain04/input"
        # Copy only explicitly named non-executable source fixtures; do not copy pycache.
        fixture = self.base / "reach-fixture"
        (fixture / "src").mkdir(parents=True)
        for name in ("package-lock.json", "bom.json", "freeze.txt", "src/app.py", "src/index.js", "src/util.py"):
            source = fixture_root / name
            self.sources[source] = sha(source)
            shutil.copyfile(source, fixture / name)
        registered = self.asset(fixture, "reach-fixture")
        args = ["--lock", registered / "package-lock.json", "--sbom", registered / "bom.json",
                "--freeze", registered / "freeze.txt", "--source", registered / "src"]
        reach = self.tool("supply-chain-security", "sbom-reach.py", *args, ident="fixture-import-reach", asset="reach-fixture")
        self.assertEqual({r["name"] for r in reach["reachable"]}, {"left-pad", "PyYAML"})
        self.assertEqual({r["name"] for r in reach["unreachable"]}, {"requests", "@corp/auth"})
        for component in reach["reachable"]:
            self.assertTrue(component["entry_hit"])
            for hit in component["hits"]:
                line = (registered / "src" / hit["file"]).read_text(encoding="utf-8").splitlines()[hit["line"] - 1]
                self.assertEqual(line.strip()[:160], hit["snippet"])
        self.assertEqual(reach["missing_from_sbom"], [])
        changed = self.base / "without-imports"
        changed.mkdir()
        (changed / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        (changed / "app.py").write_text("value = 1\n", encoding="utf-8")
        changed_input = self.asset(changed, "without-imports")
        negative = self.tool("supply-chain-security", "sbom-reach.py", *args[:-2], "--source", changed_input,
                             ident="without-imports-control", asset="without-imports")
        self.assertEqual(negative["reachable"], [])
        bad = self.base / "broken-lock.json"
        bad.write_text("{invalid", encoding="utf-8")
        proc, _ = self.invoke([sys.executable, "-B", SKILLS / "supply-chain-security/scripts/sbom-reach.py",
                               "--lock", bad, "--source", changed], expect=2)
        self.assertFalse(json.loads(proc.stdout)["ok"])
        # Existing forensic tool inventories the actual deliverable ZIP, no install/build.
        release = self.base / "synthetic-review-bundle.zip"
        with zipfile.ZipFile(release, "w") as zf:
            zf.write(target, "public/package.json")
            for file in sorted(registered.rglob("*")):
                if file.is_file():
                    zf.write(file, "fixture/" + file.relative_to(registered).as_posix())
        artifact = self.asset(release, "review-artifact")
        inventory = self.tool("forensics-mobile", "forensics-check.py", "--file", artifact, "--json",
                              ident="artifact-inventory", asset="review-artifact")
        self.assertEqual(inventory["integrity"]["sha256"], sha(release))
        self.assertIn(inventory["type"], ("archive", "zip"))
        with zipfile.ZipFile(artifact) as zf:
            self.assertEqual(hashlib.sha256(zf.read("public/package.json")).hexdigest(), sha(target))
            self.assertEqual(zf.read("fixture/package-lock.json"), (registered / "package-lock.json").read_bytes())
        self.finish("Public manifest declares 114 dependencies without lock; explicit fixture import hits are left-pad/PyYAML only; review ZIP binds exact manifest and fixture bytes",
                    "A real release signature, complete SBOM, CVE exploitability or upstream build provenance is verified")
        bundle = self.base / "supply-review-project.zip"
        self.cli("project_archive.py", "export", "--project", self.project, "--out", bundle)
        self.cli("project_archive.py", "verify", "--archive", bundle)


class ArtifactResult(unittest.TextTestResult):
    def startTest(self, test):
        print("TASK " + test.id(), flush=True)
        super().startTest(test)


def main():
    global SESSION
    OUT.mkdir(parents=True, exist_ok=True)
    SESSION = Path(tempfile.mkdtemp(prefix="run-", dir=OUT))
    shutil.copyfile(__file__, SESSION / "test-source.py")
    execution_code_sha256 = sha(SESSION / "test-source.py")
    ENV.update(TEMP=str(SESSION), TMP=str(SESSION), TMPDIR=str(SESSION))
    log = io.StringIO()
    runner = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=ArtifactResult)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DomainDelivery)
    test_names = [test._testMethodName for test in suite]
    started = time.monotonic()
    result = runner.run(suite)
    text = log.getvalue()
    (SESSION / "unittest.log").write_text(text, encoding="utf-8")
    print(text)
    failed_names = {t._testMethodName for t, _ in result.failures + result.errors}
    skipped_names = {t._testMethodName for t, _ in result.skipped}
    outcomes = {name: ("FAIL" if name in failed_names else "BLOCKED" if name in skipped_names else "PASS")
                for name in test_names}
    summary = {"schema": "domain-task-delivery/1", "artifacts": str(SESSION),
               "execution_code_sha256": execution_code_sha256,
               "test_outcomes": outcomes,
               "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
               "skips": [{"test": str(t), "reason": reason} for t, reason in result.skipped],
               "passed_tests": result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
               "all_bounded_tasks_verified": result.wasSuccessful() and not result.skipped,
               "elapsed_seconds": round(time.monotonic() - started, 3),
               "scope": "Nine bounded domains across eight tasks; synthetic chains explicitly identified; no target execution",
               "blocked_chains": ["same-sample malware traffic/memory behavior", "real firmware device Web service",
                                  "Android runtime/bypass", "real release signature/CVE/build provenance"],
               "task_results": [{**load(p), "full_test_status": outcomes[load(p)["test"]]}
                                for p in sorted(SESSION.glob("*/task-result.json"))],
               "failure_details": [{"test": str(t), "traceback": tb} for t, tb in result.failures + result.errors]}
    save(SESSION / "results.json", summary)
    save(OUT / "latest-results.json", summary)
    print(json.dumps({k: v for k, v in summary.items() if k not in ("task_results", "failure_details")}, ensure_ascii=False, indent=2))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
