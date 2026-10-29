#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synthetic CLI regression for D08 project archive export/import.

No customer samples, target execution, network, package installation, or source
module edits are involved.  Every subprocess is bounded to 45 seconds.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path, PureWindowsPath

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = ROOT / "Tool/scripts/project_archive.py"
STATE = ROOT / "Tool/scripts/project_state.py"
REPORT = ROOT / "Tool/scripts/project_report.py"
TMP_ROOT = ROOT / "work/final-delivery/tmp"
TMP_ROOT.mkdir(parents=True, exist_ok=True)
ENV = dict(os.environ, TEMP=str(TMP_ROOT), TMP=str(TMP_ROOT), TMPDIR=str(TMP_ROOT),
           PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")


def invoke(script: Path, *args, timeout: int = 45) -> tuple[int, dict, str]:
    result = subprocess.run([sys.executable, "-B", str(script), *map(str, args)],
                            cwd=str(ROOT), env=ENV, capture_output=True, text=True,
                            encoding="utf-8", timeout=timeout)
    try:
        payload = json.loads(result.stdout)
    except ValueError as exc:
        raise AssertionError((result.returncode, result.stdout[-2000:],
                              result.stderr[-2000:])) from exc
    if result.stderr:
        raise AssertionError(result.stderr[-2000:])
    return result.returncode, payload, result.stdout


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class ArchiveFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="d08-archive-", dir=str(TMP_ROOT))
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def state(self, project: Path, command: str, *args) -> dict:
        code, payload, _ = invoke(STATE, command, "--project", project, *args)
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload.get("ok"), payload)
        return payload

    def report(self, project: Path, command: str, *args) -> dict:
        code, payload, _ = invoke(REPORT, command, "--project", project, *args)
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload.get("ok"), payload)
        return payload

    def make_project(self, mode: str = "completed") -> Path:
        project = self.base / ("project-" + mode)
        target = self.base / ("target-" + mode + ".bin")
        target.write_bytes(b"synthetic-target-D08-" + mode.encode("ascii") * 8)
        self.state(project, "init", "--project-id", "synthetic-%s" % mode,
                   "--target", target)
        self.state(project, "version", "--version", "1.1", "--parent", "1.0",
                   "--target", target)
        capture = project / "versions/1.1/capture/probe.log"
        source = project / "versions/1.1/capture/source.txt"
        capture.parent.mkdir(parents=True, exist_ok=True)
        (project / "versions/1.1/artifacts/empty-tree/child").mkdir(parents=True, exist_ok=True)
        capture.write_bytes(b"synthetic probe evidence; no semantic claim\n")
        source.write_bytes(b"synthetic verifier source\n")
        run_id = "run-%s" % mode
        self.state(project, "run", "--version", "1.1", "--run-id", run_id)
        version = read_json(project / "versions/1.1/version.json")
        self.state(project, "evidence", "--version", "1.1", "--run-id", run_id,
                   "--evidence-id", "ev-1", "--target-sha256", version["sha256"],
                   "--path", "versions/1.1/capture/probe.log", "--sha256", sha(capture),
                   "--size", capture.stat().st_size,
                   "--source", "versions/1.1/capture/source.txt", "--how", "synthetic CLI probe")
        self.state(project, "acceptance-define", "--version", "1.1",
                   "--item", "probe:synthetic evidence is structurally bound")
        result = "unknown" if mode == "pending" else "pass"
        self.state(project, "acceptance-record", "--version", "1.1", "--item-id", "probe",
                   "--result", result, "--evidence-ids", "ev-1",
                   "--verifier", "synthetic-verifier", "--how", "read-only synthetic probe",
                   "--run", run_id)
        if mode != "pending":
            self.state(project, "finish-run", "--version", "1.1", "--run-id", run_id,
                       "--status", "failed" if mode == "failed" else "completed",
                       "--note", "synthetic fixture")
            self.report(project, "generate", "--report-id", "final-%s" % mode,
                        "--version", "1.1", "--run-id", run_id, "--kind", "final")
        else:
            self.report(project, "generate", "--report-id", "interim-pending",
                        "--version", "1.1", "--run-id", run_id, "--kind", "interim")
        return project

    def export(self, project: Path, name: str = "bundle.zip") -> Path:
        bundle = self.base / name
        code, payload, _ = invoke(ARCHIVE, "export", "--project", project, "--out", bundle)
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["ok"], payload)
        self.assertTrue(bundle.is_file())
        return bundle

    def import_bundle(self, bundle: Path, destination: Path, *extra) -> tuple[int, dict, str]:
        return invoke(ARCHIVE, "import", "--archive", bundle, "--project", destination, *extra)

    @unittest.skipUnless(os.name == "nt", "real Windows ordinary-path import regression")
    def test_windows_deep_import_refuses_before_writes_and_same_archive_recovers(self):
        import project_archive as A
        project = self.make_project("path-budget")
        relative = "notes/" + "a" * 35 + "/" + "b" * 35 + "/probe.bin"
        note = project / relative
        note.parent.mkdir(parents=True)
        note.write_bytes(b"same archive, same member bytes\n")
        bundle = self.export(project)
        archive_before = bundle.read_bytes()
        for label, parent_length, expected_role in (("final", 175, "destination"),
                                                     ("temporary", 140, "staging")):
            with self.subTest(label=label):
                parent = self.base / label
                parent.mkdir()
                while len(str(parent)) < parent_length:
                    parent /= "d" * max(1, min(32, parent_length - len(str(parent)) - 1))
                    parent.mkdir()
                destination = parent / "r"
                if label == "temporary":
                    # Final file AND its deepest directory fit. Only the random
                    # sibling staging name pushes this exact archive over budget.
                    with zipfile.ZipFile(bundle) as archive:
                        manifest = json.loads(archive.read("archive.json"))
                    for row in manifest["files"]:
                        self.assertLessEqual(len(str(destination / row["path"])), 259)
                        self.assertLessEqual(len(str((destination / row["path"]).parent)), 247)
                    for directory in manifest["directories"]:
                        self.assertLessEqual(len(str(destination / directory)), 247)
                before = list(parent.iterdir())
                code, payload, _ = self.import_bundle(bundle, destination)
                self.assert_refused(code, payload, destination)
                self.assertEqual(payload["blocked_at"], "archive_path_preflight")
                self.assertEqual(payload["error_code"], "path_limit")
                details = payload["path_limit"]
                self.assertEqual(details["role"], expected_role, payload)
                self.assertGreater(details["actual"], details["maximum"])
                self.assertEqual(details["unit"], "UTF-16 code units excluding NUL")
                self.assertFalse(details["native_long_path_support"])
                self.assertIn("更短", payload["reason"])
                self.assertEqual(payload["recovery"]["action"],
                                 "retry_same_archive_in_shorter_directory")
                # Includes the parent lock: refusal occurs before any write.
                self.assertEqual(list(parent.iterdir()), before)
        destination = self.base / "short"
        code, payload, _ = self.import_bundle(bundle, destination)
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["ok"])
        self.assertEqual((destination / relative).read_bytes(), note.read_bytes())
        self.assertEqual(bundle.read_bytes(), archive_before)
        self.state(destination, "resume")
        self.report(destination, "status")
        # An unusably long root is rejected even if its parent cannot be stat'ed.
        impossible = self.base / ("x" * 220) / "restored"
        code, payload, _ = self.import_bundle(bundle, impossible)
        self.assert_refused(code, payload, impossible)
        self.assertEqual(payload["error_code"], "path_limit")
        self.assertFalse(list(self.base.glob(A.STAGING_PREFIX + "*")))

    def test_windows_budget_boundaries_unicode_and_implicit_parents(self):
        import project_archive as A
        from unittest.mock import patch
        # Pure paths exercise the Windows policy on every host without asking
        # another platform's filesystem to emulate Windows.
        with patch.object(A, "WINDOWS_PATH_POLICY", True):
            root = PureWindowsPath("C:/")
            file_at_limit = root / ("a" * 128) / ("b" * 127)
            self.assertEqual(len(str(file_at_limit)), 259)
            A._check_import_path(file_at_limit, "destination")
            with self.assertRaises(A.ArchivePathError) as caught:
                A._check_import_path(PureWindowsPath(str(file_at_limit) + "x"), "destination")
            self.assertEqual(caught.exception.details["maximum"], 259)
            directory_at_limit = root / ("a" * 244)
            A._check_import_path(directory_at_limit, "destination", directory=True)
            with self.assertRaises(A.ArchivePathError):
                A._check_import_path(PureWindowsPath(str(directory_at_limit) + "x"),
                                     "destination", directory=True)
            # Non-BMP characters count as two UTF-16 code units.
            unicode_file = root / ("a" * 128) / ("\U0001f9ea" * 64)
            self.assertLess(len(str(unicode_file)), 259)
            with self.assertRaises(A.ArchivePathError) as caught:
                A._check_import_path(unicode_file, "destination")
            self.assertEqual(caught.exception.details["actual"], 260)
            with self.assertRaises(A.ArchivePathError) as caught:
                A._check_import_path(root / ("x" * 256), "destination")
            self.assertEqual(caught.exception.details["metric"], "component")
            # The file fits but its implicit directory exceeds CreateDirectory's
            # legacy budget, even without a directories entry in the manifest.
            relative = "a" * 243 + "/f"
            manifest = {"directories": [], "files": [{"path": relative}]}
            with self.assertRaises(A.ArchivePathError) as caught:
                A._check_import_layout(PureWindowsPath("C:/r"), "staging", manifest)
            self.assertEqual(caught.exception.details["metric"], "directory_path")
            self.assertEqual(caught.exception.details["member"], relative)
            manifest = {"directories": ["a" * 243], "files": []}
            with self.assertRaises(A.ArchivePathError):
                A._check_import_layout(PureWindowsPath("C:/r"), "staging", manifest)
        with patch.object(A, "WINDOWS_PATH_POLICY", False):
            A._check_import_layout(PureWindowsPath("C:/r"), "destination", manifest)

    def test_directory_snapshot_members_survive_relocation(self):
        source = self.base / "input-tree"
        (source / "__pycache__" / "empty").mkdir(parents=True)
        (source / "module.pyc").write_bytes(b"user-supplied bytecode")
        (source / ".seep-project-legitimate").write_bytes(b"user-supplied name")
        project = self.base / "tree-project"
        self.state(project, "init", "--project-id", "tree", "--target", source)
        bundle = self.export(project)
        source.rename(self.base / "source-removed")
        project.rename(self.base / "project-removed")
        imported = self.base / "new-location"
        rc, out, text = invoke(ARCHIVE, "import", "--archive", bundle, "--project", imported)
        self.assertEqual(rc, 0, text)
        self.state(imported, "resume")
        tree = imported / "assets/asset-main/snapshot/tree"
        self.assertEqual((tree / "module.pyc").read_bytes(), b"user-supplied bytecode")
        self.assertTrue((tree / "__pycache__/empty").is_dir())
        self.assertEqual((tree / ".seep-project-legitimate").read_bytes(), b"user-supplied name")

    def bundle_entries(self, bundle: Path) -> dict[str, bytes]:
        with zipfile.ZipFile(bundle) as archive:
            return {info.filename: archive.read(info) for info in archive.infolist()}

    def rewrite(self, source: Path, name: str, change) -> Path:
        destination = self.base / name
        entries = self.bundle_entries(source)
        manifest = json.loads(entries["archive.json"].decode("utf-8"))
        special = change(manifest, entries)
        entries["archive.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path, data in entries.items():
                if path == special:
                    info = zipfile.ZipInfo(path)
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    archive.writestr(info, data)
                else:
                    archive.writestr(path, data)
        return destination

    def assert_refused(self, code: int, payload: dict, output_or_destination=None,
                       destination: Path | None = None) -> None:
        self.assertEqual(code, 2, payload)
        self.assertFalse(payload.get("ok"), payload)
        if destination is None and isinstance(output_or_destination, Path):
            destination = output_or_destination
        if destination is not None:
            self.assertFalse(destination.exists(), destination)

    def test_round_trip_moves_source_and_replays_core(self) -> None:
        project = self.make_project("completed")
        bundle = self.export(project)
        with zipfile.ZipFile(bundle) as archive:
            manifest = json.loads(archive.read("archive.json"))
        self.assertEqual(manifest["schema"], "seep-project-archive/1")
        self.assertIn("versions/1.1/capture/probe.log", [x["path"] for x in manifest["files"]])
        self.assertIn("versions/1.1/runs/run-completed/run.json", [x["path"] for x in manifest["files"]])
        self.assertIn("versions/1.1/artifacts/empty-tree/child", manifest["directories"])
        moved = self.base / "source-moved-away"
        shutil.move(str(project), str(moved))
        destination = self.base / "restored"
        code, payload, _ = self.import_bundle(bundle, destination)
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["ok"])
        self.assertFalse(project.exists())
        resume = invoke(STATE, "resume", "--project", destination)
        self.assertEqual(resume[0], 0, resume[1])
        status = invoke(REPORT, "status", "--project", destination)
        self.assertEqual(status[0], 0, status[1])
        self.assertTrue(status[1]["ok"], status[1])
        self.assertTrue(status[1]["final_pointer"]["valid"])
        self.assertTrue((destination / "reports/final-completed/report.md").is_file())
        self.assertTrue((destination / "versions/1.1/artifacts/empty-tree/child").is_dir())

    def test_verify_rechecks_member_bytes_and_size(self) -> None:
        project = self.make_project("completed")
        bundle = self.export(project)
        code, payload, _ = invoke(ARCHIVE, "verify", "--archive", bundle)
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["ok"], payload)
        member = "project.json"
        original = self.bundle_entries(bundle)[member]
        with self.subTest("same_size_changed_bytes"):
            def changed_bytes(manifest, entries):
                entries[member] = bytes([original[0] ^ 1]) + original[1:]
                return None
            bad = self.rewrite(bundle, "verify-byte-tamper.zip", changed_bytes)
            verify = invoke(ARCHIVE, "verify", "--archive", bad)
            self.assert_refused(*verify)
            imported = self.import_bundle(bad, self.base / "verify-byte-tamper-dest")
            self.assert_refused(*imported, self.base / "verify-byte-tamper-dest")
        with self.subTest("changed_size_same_original_hash"):
            def changed_size(manifest, entries):
                entries[member] = original + b"x"
                return None
            bad = self.rewrite(bundle, "verify-size-tamper.zip", changed_size)
            verify = invoke(ARCHIVE, "verify", "--archive", bad)
            self.assert_refused(*verify)
            imported = self.import_bundle(bad, self.base / "verify-size-tamper-dest")
            self.assert_refused(*imported, self.base / "verify-size-tamper-dest")

    def test_default_export_accepts_highly_compressible_member(self) -> None:
        project = self.make_project("compressible")
        (project / "manager.log").write_bytes(b"A" * (64 * 1024))
        bundle = self.export(project, "compressible.zip")
        verify = invoke(ARCHIVE, "verify", "--archive", bundle)
        self.assertEqual(verify[0], 0, verify[1])
        destination = self.base / "compressible-restored"
        imported = self.import_bundle(bundle, destination)
        self.assertEqual(imported[0], 0, imported[1])
        self.assertEqual((destination / "manager.log").read_bytes(), b"A" * (64 * 1024))

    def test_import_applies_safe_path_and_sensitive_location_rules(self) -> None:
        project = self.make_project("path-rules")
        bundle = self.export(project, "path-rules.zip")
        with self.subTest("colon"):
            def colon(manifest, entries):
                old = manifest["files"][0]["path"]
                manifest["files"][0]["path"] = "assets/x:data"
                entries["assets/x:data"] = entries.pop(old)
                return None
            bad = self.rewrite(bundle, "colon.zip", colon)
            self.assert_refused(*invoke(ARCHIVE, "verify", "--archive", bad))
            self.assert_refused(*self.import_bundle(bad, self.base / "colon-dest"),
                                self.base / "colon-dest")
        with self.subTest("sensitive_filename"):
            def sensitive(manifest, entries):
                old = manifest["files"][0]["path"]
                manifest["files"][0]["path"] = "private.key"
                entries["private.key"] = entries.pop(old)
                return None
            bad = self.rewrite(bundle, "sensitive-name.zip", sensitive)
            self.assert_refused(*invoke(ARCHIVE, "verify", "--archive", bad))
            self.assert_refused(*self.import_bundle(bad, self.base / "sensitive-dest"),
                                self.base / "sensitive-dest")

    def test_pending_and_failed_projects_are_transportable(self) -> None:
        for mode in ("pending", "failed"):
            with self.subTest(mode=mode):
                project = self.make_project(mode)
                bundle = self.export(project, mode + ".zip")
                destination = self.base / ("restored-" + mode)
                code, payload, _ = self.import_bundle(bundle, destination)
                self.assertEqual(code, 0, payload)
                self.assertTrue(payload["ok"], payload)
                self.assertEqual(invoke(STATE, "resume", "--project", destination)[0], 0)
                self.assertEqual(invoke(REPORT, "status", "--project", destination)[0], 0)

    def test_directory_manifest_conflicts_and_traversal_are_rejected(self) -> None:
        project = self.make_project("directory-rules")
        bundle = self.export(project, "directory-rules.zip")
        for label, directory in (("same", "project.json"),
                                 ("file-prefix", "project.json/child"),
                                 ("traversal", "../empty")):
            with self.subTest(label=label):
                def add_directory(manifest, entries, directory=directory):
                    manifest.setdefault("directories", []).append(directory)
                    return None
                bad = self.rewrite(bundle, label + "-directory.zip", add_directory)
                self.assert_refused(*invoke(ARCHIVE, "verify", "--archive", bad))
                destination = self.base / (label + "-directory-dest")
                self.assert_refused(*self.import_bundle(bad, destination), destination)

        project = self.make_project("completed")
        bundle = self.export(project)
        with self.subTest("missing"):
            def missing(manifest, entries):
                entries.pop(manifest["files"][-1]["path"])
                return None
            bad = self.rewrite(bundle, "missing.zip", missing)
            self.assert_refused(*self.import_bundle(bad, self.base / "missing-dest"),
                                self.base / "missing-dest")
        with self.subTest("extra"):
            def extra(manifest, entries):
                entries["extra.txt"] = b"extra"
                return None
            bad = self.rewrite(bundle, "extra.zip", extra)
            self.assert_refused(*self.import_bundle(bad, self.base / "extra-dest"),
                                self.base / "extra-dest")
        with self.subTest("hash"):
            def bad_hash(manifest, entries):
                manifest["files"][0]["sha256"] = "0" * 64
                return None
            bad = self.rewrite(bundle, "hash.zip", bad_hash)
            self.assert_refused(*self.import_bundle(bad, self.base / "hash-dest"),
                                self.base / "hash-dest")
        with self.subTest("traversal"):
            def traversal(manifest, entries):
                old = manifest["files"][0]["path"]
                row = manifest["files"][0]
                row["path"] = "../escape"
                entries["../escape"] = entries.pop(old)
                return None
            bad = self.rewrite(bundle, "traversal.zip", traversal)
            self.assert_refused(*self.import_bundle(bad, self.base / "traversal-dest"),
                                self.base / "traversal-dest")
        with self.subTest("case"):
            def case_collision(manifest, entries):
                original = manifest["files"][0]
                row = dict(original)
                row["path"] = original["path"].swapcase()
                manifest["files"].append(row)
                manifest["file_count"] += 1
                manifest["total_size"] += row["size"]
                entries[row["path"]] = entries[original["path"]]
                return None
            bad = self.rewrite(bundle, "case.zip", case_collision)
            self.assert_refused(*self.import_bundle(bad, self.base / "case-dest"),
                                self.base / "case-dest")
        with self.subTest("link"):
            def link(manifest, entries):
                data = b"link-target-not-followed"
                row = {"path": "link", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                manifest["files"].append(row)
                manifest["file_count"] += 1
                manifest["total_size"] += row["size"]
                entries["link"] = data
                return "link"
            bad = self.rewrite(bundle, "link.zip", link)
            self.assert_refused(*self.import_bundle(bad, self.base / "link-dest"),
                                self.base / "link-dest")

    def test_resource_limit_corrupt_source_existing_target_and_no_publish(self) -> None:
        project = self.make_project("completed")
        bundle = self.export(project)
        limited = self.base / "limited-dest"
        code, payload, _ = self.import_bundle(bundle, limited, "--max-total-bytes", "1")
        self.assert_refused(code, payload, limited)
        self.assertFalse(any(p.name.startswith(".seep-archive-staging-")
                             for p in self.base.iterdir()))
        target = self.base / "existing-dest"
        target.mkdir()
        sentinel = target / "keep.bin"
        sentinel.write_bytes(b"must remain byte-for-byte")
        before = sentinel.read_bytes()
        code, payload, _ = self.import_bundle(bundle, target)
        self.assert_refused(code, payload)
        self.assertEqual(before, sentinel.read_bytes())
        corrupted = project / "versions/1.1/capture/probe.log"
        corrupted.write_bytes(b"tampered evidence")
        failed_bundle = self.base / "corrupt-source.zip"
        code, payload, _ = invoke(ARCHIVE, "export", "--project", project, "--out", failed_bundle)
        self.assert_refused(code, payload)
        self.assertFalse(failed_bundle.exists())

    def test_verify_rejects_case_collisions_across_files_and_directories(self):
        project = self.make_project("case-topology")
        bundle = self.export(project)
        for label, directories, additions in (
                ("file-dir-case", ["PROJECT.JSON"], {}),
                ("file-prefix-case", ["PROJECT.JSON/child"], {}),
                ("implicit-dir-case", [], {"Notes/a.txt": b"a", "notes/b.txt": b"b"}),
                ("file-prefix-file-case", [], {"Node": b"a", "node/child": b"b"})):
            with self.subTest(label=label):
                def change(manifest, entries):
                    manifest["directories"].extend(directories)
                    for path, data in additions.items():
                        entries[path] = data
                        manifest["files"].append({"path": path, "size": len(data),
                                                  "sha256": hashlib.sha256(data).hexdigest()})
                        manifest["file_count"] += 1
                        manifest["total_size"] += len(data)
                bad = self.rewrite(bundle, label + ".zip", change)
                self.assert_refused(*invoke(ARCHIVE, "verify", "--archive", bad))
                destination = self.base / (label + "-destination")
                self.assert_refused(*self.import_bundle(bad, destination), destination)

    def test_export_rechecks_archived_bytes_before_publication(self):
        import project_archive as A
        from unittest.mock import patch
        project = self.make_project("pack-race")
        note = project / "notes.bin"
        original = b"stable note"
        note.write_bytes(original)
        out = self.base / "must-not-publish.zip"
        real_write = zipfile.ZipFile.write
        touched = []
        def changed_write(bundle, filename, *args, **kwargs):
            if Path(filename) == note:
                touched.append(True)
                note.write_bytes(b"mutant note")
                try:
                    return real_write(bundle, filename, *args, **kwargs)
                finally:
                    note.write_bytes(original)
            return real_write(bundle, filename, *args, **kwargs)
        with patch.object(zipfile.ZipFile, "write", new=changed_write):
            with self.assertRaises(A.ArchiveError):
                A.export_archive(str(project), str(out), A.argparse.Namespace())
        self.assertEqual(touched, [True])
        self.assertEqual(note.read_bytes(), original)
        self.assertFalse(out.exists())
        self.assertFalse(list(self.base.glob(".seep-archive-*.tmp")))

    def test_export_detects_source_tree_changes_during_pack(self):
        import project_archive as A
        from unittest.mock import patch
        project = self.make_project("tree-race")
        out = self.base / "changed-tree.zip"
        new_path = project / "created-during-pack.txt"
        real_write = zipfile.ZipFile.write
        def changed_write(bundle, filename, *args, **kwargs):
            result = real_write(bundle, filename, *args, **kwargs)
            new_path.write_bytes(b"new user data")
            return result
        with patch.object(zipfile.ZipFile, "write", new=changed_write):
            with self.assertRaises(A.ArchiveError):
                A.export_archive(str(project), str(out), A.argparse.Namespace())
        self.assertEqual(new_path.read_bytes(), b"new user data")
        self.assertFalse(out.exists())
        self.assertFalse(list(self.base.glob(".seep-archive-*.tmp")))

    def test_verify_rejects_reserved_manifest_as_implicit_parent_or_case_alias(self):
        project = self.make_project("reserved-root")
        bundle = self.export(project)
        for label, directories, additions in (
                ("manifest-parent", [], {"archive.json/child": b"x"}),
                ("manifest-case", [], {"ARCHIVE.JSON": b"x"}),
                ("manifest-dir-case", ["ARCHIVE.JSON"], {}),
                ("manifest-dir-parent", ["archive.json/child"], {})):
            with self.subTest(label=label):
                def change(manifest, entries):
                    manifest["directories"].extend(directories)
                    for path, data in additions.items():
                        entries[path] = data
                        manifest["files"].append({"path": path, "size": len(data),
                                                  "sha256": hashlib.sha256(data).hexdigest()})
                        manifest["file_count"] += 1
                        manifest["total_size"] += len(data)
                bad = self.rewrite(bundle, label + ".zip", change)
                self.assert_refused(*invoke(ARCHIVE, "verify", "--archive", bad))
                destination = self.base / (label + "-destination")
                self.assert_refused(*self.import_bundle(bad, destination), destination)

    def test_implicit_directories_count_toward_archive_resource_limit(self):
        import project_archive as A
        data = b"x"
        manifest = {"schema": A.ARCHIVE_SCHEMA,
                    "project": {"schema": A.P.PROJECT_SCHEMA, "project_id": "bounded"},
                    "files": [{"path": "a/b/c/d/leaf", "size": 1,
                               "sha256": hashlib.sha256(data).hexdigest()}],
                    "directories": [], "file_count": 1, "total_size": 1}
        limits = A._limits(A.argparse.Namespace(max_files=3))
        with self.assertRaises(A.ArchiveError):
            A._validate_manifest(manifest, limits)

    def test_export_stops_enumeration_when_entry_limit_is_exceeded(self):
        import project_archive as A
        from unittest.mock import patch
        project = self.base / "bounded-enumeration"
        project.mkdir()
        for index in range(10):
            (project / ("note-%d" % index)).write_bytes(b"x")
        out = self.base / "bounded.zip"
        real_scandir = os.scandir
        visited = []
        class LimitedScandir:
            def __init__(self, path):
                self.iterator = real_scandir(path)
            def __enter__(self):
                return self
            def __exit__(self, *unused):
                self.iterator.close()
            def __iter__(self):
                return self
            def __next__(self):
                entry = next(self.iterator)
                if entry.name != ".project.lock":
                    visited.append(entry.name)
                if len(visited) > 3:
                    raise AssertionError("enumeration continued beyond max_files + 1")
                return entry
        with patch.object(A, "_validate_source", return_value={"project": {}}), \
                patch.object(A.os, "scandir", side_effect=LimitedScandir):
            with self.assertRaises(A.ArchiveError):
                A.export_archive(str(project), str(out), A.argparse.Namespace(max_files=2))
        self.assertEqual(len(visited), 3)
        self.assertFalse(out.exists())
        self.assertFalse(list(self.base.glob(".seep-archive-*.tmp")))

    def test_archive_paths_refuse_linked_ancestors(self):
        project = self.make_project("ancestor-link")
        bundle = self.export(project)
        alias = self.base / "alias"
        try:
            alias.symlink_to(self.base, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("host cannot create symlinks; ancestor boundary unverified")
        try:
            source_alias = alias / project.name
            out = self.base / "source-alias.zip"
            self.assert_refused(*invoke(ARCHIVE, "export", "--project", source_alias, "--out", out))
            self.assertFalse(out.exists())
            target_parent = self.base / "output-parent"
            target_parent.mkdir()
            self.assert_refused(*invoke(ARCHIVE, "export", "--project", project,
                                       "--out", alias / target_parent.name / "output.zip"))
            self.assertFalse((target_parent / "output.zip").exists())
            self.assert_refused(*invoke(ARCHIVE, "verify", "--archive", alias / bundle.name))
            destination = target_parent / "imported"
            self.assert_refused(*self.import_bundle(bundle, alias / target_parent.name / "imported"))
            self.assertFalse(destination.exists())
        finally:
            alias.unlink()

    def test_concurrent_import_has_one_non_overwriting_winner(self) -> None:
        project = self.make_project("completed")
        bundle = self.export(project)
        destination = self.base / "concurrent-dest"
        command = [sys.executable, "-B", str(ARCHIVE), "import", "--archive", str(bundle),
                   "--project", str(destination)]
        processes = [subprocess.Popen(command, cwd=str(ROOT), env=ENV,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, encoding="utf-8") for _ in range(2)]
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=45)
            self.assertFalse(stderr, stderr)
            results.append((process.returncode, json.loads(stdout)))
        self.assertEqual(sorted(code for code, _payload in results), [0, 2], results)
        self.assertTrue(destination.is_dir())
        self.assertTrue((destination / "project.json").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
