#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bounded CLI integration for D02 typed file/directory/URL targets.

Synthetic fixtures only; no network, installer, browser, customer sample, or external
parser is used.  Run with PYTHONDONTWRITEBYTECODE=1.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "Tool/scripts/project_state.py"
WORKFLOW = ROOT / "Tool/scripts/project_workflow.py"
REPORT = ROOT / "Tool/scripts/project_report.py"
ARCHIVE = ROOT / "Tool/scripts/project_archive.py"
TMP = ROOT / "work/final-delivery/tmp"
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")


def cli(script: Path, *args):
    proc = subprocess.run([sys.executable, "-B", "-X", "utf8", str(script),
                           *map(str, args)], cwd=str(ROOT), env=ENV,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=50)
    try:
        payload = json.loads(proc.stdout)
    except ValueError:
        raise AssertionError((proc.returncode, proc.stdout[-2000:], proc.stderr[-1000:]))
    return proc.returncode, payload, proc.stdout


class TypedInputCLI(unittest.TestCase):
    def setUp(self):
        TMP.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="typed-cli-", dir=str(TMP))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def state(self, project: Path, *args):
        return cli(STATE, *args, "--project", project)

    def test_refused_replacements_preserve_registered_materials(self):
        for kind in ("file", "directory"):
            with self.subTest(kind=kind):
                source = self.base / kind / "sample"
                source.parent.mkdir()
                if kind == "file":
                    source.write_bytes(b"original")
                else:
                    source.mkdir()
                    (source / "part").write_bytes(b"original")
                project = self.base / ("immutable-" + kind)
                self.assertEqual(self.state(project, "init", "--project-id", kind,
                                            "--target", source)[0], 0)
                def snapshot():
                    return {p.relative_to(project).as_posix(): p.read_bytes()
                            for p in project.rglob("*") if p.is_file() and p.name != ".project.lock"}
                before = snapshot()
                (source if kind == "file" else source / "part").write_bytes(b"replacement")
                for command in (("asset", "--asset-id", "asset-main", "--version", "1.0"),
                                ("version", "--version", "1.0")):
                    rc, _, text = self.state(project, *command, "--target", source)
                    self.assertEqual(rc, 2, text)
                    self.assertEqual(snapshot(), before)
                self.assertEqual(self.state(project, "resume")[0], 0)

    def test_metadata_basename_and_ipv6_are_ordinary_inputs(self):
        source = self.base / "asset.json"
        source.write_bytes(b'{"user": "material"}')
        for index, target in enumerate((source, "http://[::1]/a", "http://[::1]:8080/a")):
            project = self.base / ("names-" + str(index))
            rc, _, text = self.state(project, "init", "--project-id", "names" + str(index),
                                     "--target", target)
            self.assertEqual(rc, 0, text)
            self.assertEqual(self.state(project, "resume")[0], 0)
            if index == 0:
                version = json.loads((project / "versions/1.0/version.json").read_text(encoding="utf-8"))
                self.assertEqual((project / version["local_path"]).read_bytes(), source.read_bytes())

    def test_three_inputs_resume_and_report_with_explicit_kind(self):
        file_source = self.base / "sample.bin"
        file_source.write_bytes(b"synthetic-file-target\n")
        directory_source = self.base / "目录"
        (directory_source / "空目录").mkdir(parents=True)
        (directory_source / "中文.txt").write_text("合成目录\n", encoding="utf-8")
        cases = (("file", file_source, "file"),
                 ("directory", directory_source, "directory"),
                 ("url_descriptor", "https://example.invalid/a?q=synthetic#f", "url_descriptor"))
        for name, source, expected in cases:
            with self.subTest(kind=name):
                project = self.base / ("p-" + name)
                rc, out, text = self.state(project, "init", "--project-id", "typed-" + name,
                                           "--target", source)
                self.assertEqual(rc, 0, text)
                version = json.loads((project / "versions/1.0/version.json").read_text(encoding="utf-8"))
                self.assertEqual(version["kind"], expected)
                self.assertEqual(version["identity_scope"],
                                 "raw-bytes" if expected == "file" else
                                 "tree-content" if expected == "directory" else "descriptor-only")
                if expected == "url_descriptor":
                    self.assertFalse(version["remote_content_verified"])
                    self.assertNotIn("content_sha256", version)
                    self.assertIsNone(version.get("local_path"))
                if expected == "directory":
                    self.assertEqual(version["identity"]["entry_count"], 2)
                    directory_source.rename(self.base / ("moved-" + name))
                rc, resumed, text = self.state(project, "resume")
                self.assertEqual(rc, 0, text)
                self.assertFalse(resumed["handoff"].get("state_errors"), resumed)
                self.assertEqual(resumed["handoff"]["current_version"]["kind"], expected)
                self.state(project, "run", "--version", "1.0", "--run-id", "r1")
                rc, report, text = cli(REPORT, "generate", "--project", project,
                                        "--report-id", "typed-report", "--version", "1.0",
                                        "--run-id", "r1", "--kind", "interim")
                self.assertEqual(rc, 0, text)
                manifest = json.loads((project / "reports/typed-report/manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(manifest["target"]["kind"], expected)
                self.assertEqual(manifest["target"]["identity_scope"], version["identity_scope"])
                if expected == "file":
                    archive = self.base / "typed-project.zip"
                    imported = self.base / "typed-imported"
                    rc, _, text = cli(ARCHIVE, "export", "--project", project, "--out", archive)
                    self.assertEqual(rc, 0, text)
                    rc, _, text = cli(ARCHIVE, "import", "--archive", archive, "--project", imported)
                    self.assertEqual(rc, 0, text)
                    rc, resumed_import, text = self.state(imported, "resume")
                    self.assertEqual(rc, 0, text)
                    self.assertEqual(resumed_import["handoff"]["current_version"]["kind"], expected)
                    rc, _, text = cli(REPORT, "generate", "--project", imported,
                                      "--report-id", "typed-imported-report", "--version", "1.0",
                                      "--run-id", "r1", "--kind", "interim")
                    self.assertEqual(rc, 0, text)
                    imported_manifest = json.loads((imported / "reports/typed-imported-report/manifest.json").read_text(encoding="utf-8"))
                    self.assertEqual(imported_manifest["target"]["kind"], expected)
                    rc, shown, text = cli(REPORT, "show", "--project", imported,
                                          "--report-id", "typed-imported-report")
                    self.assertEqual(rc, 0, text)

    def test_directory_tamper_unknown_kind_and_sensitive_url_fail_closed(self):
        source = self.base / "tree"
        (source / "empty").mkdir(parents=True)
        project = self.base / "tamper"
        rc, _, text = self.state(project, "init", "--project-id", "tamper", "--target", source)
        self.assertEqual(rc, 0, text)
        (project / "assets/asset-main/snapshot/tree/extra.txt").write_text("tamper", encoding="utf-8")
        rc, out, text = self.state(project, "resume")
        self.assertEqual(rc, 2, text)
        self.assertTrue(out["handoff"]["state_errors"])
        version_path = project / "versions/1.0/version.json"
        version = json.loads(version_path.read_text(encoding="utf-8"))
        version["kind"] = "made_up_kind"
        version_path.write_text(json.dumps(version, ensure_ascii=False) + "\n", encoding="utf-8")
        rc, out, text = self.state(project, "resume")
        self.assertEqual(rc, 2, text)
        self.assertTrue(any(any(term in json.dumps(error, ensure_ascii=False)
                                for term in ("unknown", "未知"))
                           for error in out["handoff"]["state_errors"]), out["handoff"]["state_errors"])
        secret = "synthetic-secret-marker"
        bad = "https://example.invalid/a?access_token=" + secret
        sensitive_project = self.base / "sensitive"
        rc, out, text = self.state(sensitive_project, "init", "--project-id", "sensitive",
                                   "--target", bad)
        self.assertEqual(rc, 2)
        self.assertNotIn(secret, text)
        self.assertFalse(any(secret in p.read_text(encoding="utf-8", errors="ignore")
                              for p in sensitive_project.rglob("*") if p.is_file()))

    def test_asset_roles_are_explicit_and_file_parser_refuses_typed_nonfile(self):
        primary = self.base / "primary.bin"
        auxiliary = self.base / "secondary.bin"
        auxiliary = self.base / "secondary.bin"
        self.base.mkdir(parents=True, exist_ok=True)
        primary.write_bytes(b"primary")
        auxiliary.parent.mkdir(parents=True, exist_ok=True)
        auxiliary.write_bytes(b"auxiliary")
        project = self.base / "roles"
        self.assertEqual(self.state(project, "init", "--project-id", "roles",
                                     "--target", primary)[0], 0)
        rc, out, text = self.state(project, "asset", "--asset-id", "aux-1",
                                   "--target", auxiliary, "--version", "1.0",
                                   "--role", "auxiliary")
        self.assertEqual(rc, 0, text)
        version = json.loads((project / "versions/1.0/version.json").read_text(encoding="utf-8"))
        self.assertEqual(version["primary_asset_id"], "asset-main")
        self.assertEqual(version["auxiliary_asset_ids"], ["aux-1"])
        rc, _, text = self.state(project, "version", "--version", "1.0",
                                 "--asset", "aux-1", "--primary-asset", "aux-1")
        self.assertEqual(rc, 2, text)

        # Workflow starts a real lifecycle, then rejects the file parser before
        # loading/spawning a tool when the declared target is a directory/URL.
        directory = self.base / "workflow-dir"
        (directory / "empty").mkdir(parents=True)
        wf_project = self.base / "wf"
        rc, started, text = cli(WORKFLOW, "start", "--json", "--project", wf_project,
                                 "--quote", "这个安卓 APK 有没有加固", "--allow-ambiguous",
                                 "--target", directory, "--route-id", "R1", "--p", "0.4",
                                 "--hours", "1h", "--fail", "合成失败", "--evidence-goal", "画像")
        self.assertEqual(rc, 0, text)
        rc, refused, text = cli(WORKFLOW, "act", "--json", "--project", wf_project,
                                 "--action", "apk.info")
        self.assertEqual(rc, 3, text)
        self.assertIn("kind=file", refused.get("reason", ""))


    def test_inconsistent_target_identities_refuse_resume_without_rewriting_record(self):
        source = self.base / "identity.bin"
        source.write_bytes(b"original")
        for index, (key, value) in enumerate((("sha256", "0" * 64), ("size", 999),
                                             ("algorithm", "wrong-algorithm"))):
            with self.subTest(key=key):
                project = self.base / ("inconsistent-" + str(index))
                rc, _, text = self.state(project, "init", "--project-id", "identity",
                                         "--target", source)
                self.assertEqual(rc, 0, text)
                path = project / "versions/1.0/version.json"
                version = json.loads(path.read_text(encoding="utf-8"))
                version["identity"][key] = value
                path.write_text(json.dumps(version), encoding="utf-8")
                before = path.read_bytes()
                rc, payload, text = self.state(project, "resume")
                self.assertEqual(rc, 2, text)
                self.assertTrue(payload["handoff"]["state_errors"])
                self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
