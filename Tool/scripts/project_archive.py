#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Portable, integrity-checked project archive export/import.

The archive is deliberately a transport format, not a second project ledger:
project_state remains the authority for project, evidence, acceptance, closure,
and resume health.  This module only inventories project-relative files and
replays the existing Core validation in a fresh Python process before publish.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from pathlib import Path, PurePosixPath

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import project_state as P  # noqa: E402
from lib.project_lock import project_lock  # noqa: E402

ARCHIVE_SCHEMA = "seep-project-archive/1"
ARCHIVE_MANIFEST = "archive.json"
DEFAULT_LIMITS = {
    "max_archive_bytes": 512 * 1024 * 1024,
    "max_member_bytes": 128 * 1024 * 1024,
    "max_total_bytes": 512 * 1024 * 1024,
    "max_files": 10000,
    "max_compression_ratio": 200,
}
TEMP_PREFIXES = (".seep-archive-", ".seep-project-", ".seep-copy-")
STAGING_PREFIX = ".seep-archive-staging-"
# This importer and its Core subprocesses use ordinary Win32 paths.  Keep a
# conservative policy even on hosts with long paths enabled; this is not a
# claim of native/extended-path support. Limits exclude the terminating NUL.
WINDOWS_PATH_POLICY = os.name == "nt"
WINDOWS_FILE_UNITS = 259
WINDOWS_DIRECTORY_UNITS = 247  # legacy CreateDirectory: MAX_PATH - 12, minus NUL
WINDOWS_COMPONENT_UNITS = 255
SENSITIVE_EXTENSIONS = {".pem", ".key", ".p12", ".pfx", ".jks", ".kdb"}
SENSITIVE_NAMES = {
    ".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials",
    "credential", "credentials.json", "secrets", "secret", "passwords",
    "password", "tokens", "token", "private-key", "private_key", "private",
}


class ArchiveError(Exception):
    """Expected, structured refusal; the message never contains file contents."""


class ArchivePathError(ArchiveError):
    """A destination cannot fit the importer's ordinary Windows path budget."""

    def __init__(self, role: str, metric: str, actual: int, maximum: int,
                 member: str | None = None):
        super().__init__(
            "Windows 普通路径限制：%s 的 %s 为 %d，当前导入器上限为 %d；"
            "请在更短的已有普通父目录（如 C:\\s）下，用同一归档导入到不存在的目标。"
            "此限制不代表完整原生长路径支持。" % (role, metric, actual, maximum))
        self.details = {"platform": "win32", "policy": "conservative_legacy_win32",
                        "native_long_path_support": False, "role": role,
                        "metric": metric, "actual": actual, "maximum": maximum,
                        "unit": "UTF-16 code units excluding NUL"}
        if member is not None:
            self.details["member"] = member


def _windows_units(value: str) -> int:
    return len(value.encode("utf-16-le", errors="surrogatepass")) // 2


def _check_import_path(path: Path, role: str, *, directory: bool = False,
                       member: str | None = None) -> None:
    if not WINDOWS_PATH_POLICY:
        return
    maximum = WINDOWS_DIRECTORY_UNITS if directory else WINDOWS_FILE_UNITS
    units = _windows_units(str(path))
    if units > maximum:
        raise ArchivePathError(role, "directory_path" if directory else "file_path",
                               units, maximum, member)
    for component in path.parts[1:]:  # the drive/UNC anchor is not a component
        units = _windows_units(component)
        if units > WINDOWS_COMPONENT_UNITS:
            raise ArchivePathError(role, "component", units, WINDOWS_COMPONENT_UNITS, member)


def _check_import_layout(root: Path, role: str, manifest: dict | None = None) -> None:
    """Check both the published tree and staging, including implicit parents.

    Core resume writes handoff.json through a .seep-project- temporary (the
    supported CPython runtime uses eight random suffix characters) and takes a
    root lock. These writes must fit before a staging directory is created.
    """
    if not WINDOWS_PATH_POLICY:
        return
    _check_import_path(root, role, directory=True)
    for name in (".project.lock", "handoff.json", ".seep-project-" + "x" * 8):
        _check_import_path(root / name, role + "_core")
    if manifest is None:
        return
    for relative in manifest.get("directories", []):
        _check_import_path(root / PurePosixPath(relative), role, directory=True, member=relative)
    for row in manifest["files"]:
        path = root / PurePosixPath(row["path"])
        _check_import_path(path, role, member=row["path"])
        _check_import_path(path.parent, role, directory=True, member=row["path"])


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def _emit(value: dict, code: int = 0) -> int:
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return code


def _refuse(stage: str, reason: str, **extra: object) -> int:
    payload = {"ok": False, "blocked_at": stage, "reason": reason}
    payload.update(extra)
    return _emit(payload, 2)


def _safe_rel(value: str, label: str = "path") -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ArchiveError("%s 非法" % label)
    if "\\" in value:
        raise ArchiveError("%s 必须使用项目内 POSIX 相对路径" % label)
    if value.startswith("/") or value.startswith("//"):
        raise ArchiveError("%s 不能是绝对路径或 UNC 路径" % label)
    drive, _tail = os.path.splitdrive(value)
    if drive or (len(value) >= 2 and value[1] == ":"):
        raise ArchiveError("%s 不能包含盘符" % label)
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ArchiveError("%s 含路径越界或不规范片段" % label)
    windows_devices = {"CON", "PRN", "AUX", "NUL"} \
        | {"COM%d" % index for index in range(1, 10)} \
        | {"LPT%d" % index for index in range(1, 10)}
    for part in path.parts:
        if ":" in part or part.endswith((".", " ")):
            raise ArchiveError("%s 含 Windows 保留/ADS 路径段" % label)
        device = part.rstrip(" .").split(".", 1)[0].upper()
        if device in windows_devices:
            raise ArchiveError("%s 含 Windows 设备名路径段" % label)
    normalized = path.as_posix()
    if normalized != value or normalized in ("", "."):
        raise ArchiveError("%s 不是规范相对路径" % label)
    return normalized


def _sensitive_location(relative: str) -> bool:
    """Reject credential-like material by type/location without opening it."""
    path = PurePosixPath(relative)
    for part in path.parts:
        lower = part.casefold()
        stem = Path(lower).stem
        if lower in SENSITIVE_NAMES or stem in SENSITIVE_NAMES:
            return True
        if Path(lower).suffix in SENSITIVE_EXTENSIONS:
            return True
        if any(word in lower for word in ("private-key", "private_key", "credential", "password")):
            return True
    return False


def _is_reparse(path: Path, info: os.stat_result | None = None) -> bool:
    try:
        value = info or path.lstat()
    except OSError as exc:
        raise ArchiveError("无法读取项目项类型：%s" % path.name) from exc
    # FILE_ATTRIBUTE_REPARSE_POINT on Windows.  lstat catches ordinary links.
    return bool(getattr(value, "st_file_attributes", 0) & 0x400)


def _fingerprint(path: Path, max_bytes: int | None = None) -> dict:
    try:
        before = path.stat()
        if max_bytes is not None and before.st_size > max_bytes:
            raise ArchiveError("项目文件超过大小资源上限（仅位置）：%s" % path.name)
        if not stat.S_ISREG(before.st_mode) or _is_reparse(path, before):
            raise ArchiveError("项目项不是普通文件：%s" % path.name)
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1 << 20), b""):
                size += len(block)
                if max_bytes is not None and size > max_bytes:
                    raise ArchiveError("项目文件读取超过大小资源上限（仅位置）：%s" % path.name)
                digest.update(block)
        after = path.stat()
    except ArchiveError:
        raise
    except OSError as exc:
        raise ArchiveError("项目文件不可读（仅位置）：%s" % path.name) from exc
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise ArchiveError("项目文件在读取期间发生变化（仅位置）：%s" % path.name)
    if size != after.st_size:
        raise ArchiveError("项目文件大小不稳定（仅位置）：%s" % path.name)
    return {"sha256": digest.hexdigest(), "size": size}


def _limits(args: argparse.Namespace) -> dict:
    values = {}
    for name, default in DEFAULT_LIMITS.items():
        value = getattr(args, name, default)
        if type(value) is not int or value <= 0:
            raise ArchiveError("资源限制必须是正整数：%s" % name)
        values[name] = value
    return values


def _reject_linked_path(path: Path) -> None:
    # Check the lexical path before resolve() erases linked ancestors.
    for candidate in (path, *path.parents):
        if candidate.is_symlink() or (candidate.exists() and _is_reparse(candidate)):
            raise ArchiveError("归档路径经过链接或 reparse 项（仅位置）：%s" % candidate.name)


def _check_source_root(root: Path) -> Path:
    root = Path(os.path.abspath(str(root)))
    _reject_linked_path(root)
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise ArchiveError("项目根目录不存在或不是普通目录")
    if _is_reparse(root):
        raise ArchiveError("项目根目录是 reparse 项")
    return root.resolve()


def _check_output_path(root: Path, out: Path) -> Path:
    out = Path(os.path.abspath(str(out)))
    _reject_linked_path(out)
    if out.exists():
        raise ArchiveError("导出目标已存在")
    try:
        out.resolve().relative_to(root.resolve())
    except ValueError:
        pass
    else:
        raise ArchiveError("导出目标不能位于源工程内部")
    if not out.parent.exists() or not out.parent.is_dir():
        raise ArchiveError("导出目标父目录不存在")
    if out.parent.is_symlink() or _is_reparse(out.parent):
        raise ArchiveError("导出目标父目录不是普通目录")
    return out


def _iter_project_tree(root: Path, max_files: int) -> tuple[list[tuple[str, Path]], list[str]]:
    files: list[tuple[str, Path]] = []
    directories: list[str] = []
    pending = [root]
    count = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or _is_reparse(path, info):
                    raise ArchiveError("项目包含链接或 reparse 项（仅位置）：%s" % relative)
                is_directory = stat.S_ISDIR(info.st_mode)
                if not is_directory and not stat.S_ISREG(info.st_mode):
                    raise ArchiveError("项目包含特殊文件（仅位置）：%s" % relative)
                if relative == ".project.lock" and not is_directory:
                    continue
                count += 1
                if count > max_files:
                    raise ArchiveError("文件和目录数量超过资源上限")
                normalized = _safe_rel(relative, "项目路径")
                if _sensitive_location(normalized):
                    raise ArchiveError("检测到不归档的敏感材料（仅位置）：%s" % normalized)
                if is_directory:
                    directories.append(normalized)
                    pending.append(path)
                else:
                    files.append((normalized, path))
    _check_path_topology([relative for relative, _path in files], directories, max_files)
    return sorted(files), sorted(directories)


def _validate_source(root: Path) -> dict:
    """Run the existing Core closure and report validators under the project lock."""
    try:
        project = P.require_project(root)
        handoff = P.write_handoff(root, persist=False)
    except Exception as exc:
        raise ArchiveError("Core 工程/账本审计拒绝导出（%s）" % type(exc).__name__) from exc
    if handoff.get("state_errors"):
        raise ArchiveError("Core 工程存在结构、证据、验收或收尾完整性错误")
    # project_report.status is itself locked.  The export already owns that same
    # project lock, so use its read-only status primitives rather than spawning a
    # nested CLI that would deadlock.  The report module remains the authority for
    # report verification; this code only composes its public status shape.
    try:
        import project_report as R
        entries, problems = R._read_index(root)
        registered = [entry for entry in entries if entry.get("kind") == "registered"]
        reports = [R._verify(root, project, entry) for entry in registered]
        final = R._final_view(root, project)
    except Exception as exc:
        raise ArchiveError("报告 status 无法完成只读验证（%s）" % type(exc).__name__) from exc
    if problems or any(report.get("stale") for report in reports) or not final.get("integrity_ok"):
        raise ArchiveError("报告/引用链不完整或已 stale，拒绝导出")
    report = {"ok": True, "reports": reports,
              "final_pointer": {key: final.get(key) for key in final if key != "report"}}
    return {"project": project, "handoff": handoff, "report": report}


def _archive_manifest(project: dict, records: list[dict], total: int,
                      directories: list[str]) -> dict:
    return {
        "schema": ARCHIVE_SCHEMA,
        "project": {"schema": project.get("schema"), "project_id": project.get("project_id")},
        "files": records,
        "directories": directories,
        "file_count": len(records),
        "total_size": total,
        "created_at": _now(),
    }


def _publish_new_file(temporary: Path, destination: Path) -> None:
    """Publish without replacing a concurrently-created existing destination."""
    if destination.exists():
        raise ArchiveError("导出目标在发布前已存在")
    try:
        os.link(str(temporary), str(destination))
    except OSError as exc:
        raise ArchiveError("无法以不覆盖方式发布归档") from exc
    finally:
        if temporary.exists():
            temporary.unlink()


def export_archive(project_arg: str, out_arg: str, args: argparse.Namespace) -> dict:
    root = _check_source_root(Path(project_arg))
    out = _check_output_path(root, Path(out_arg))
    limits = _limits(args)
    with project_lock(root):
        files, directories = _iter_project_tree(root, limits["max_files"])
        records: list[dict] = []
        total = 0
        for relative, path in files:
            fingerprint = _fingerprint(path, min(limits["max_member_bytes"], limits["max_total_bytes"] - total))
            total += fingerprint["size"]
            if fingerprint["size"] > limits["max_member_bytes"]:
                raise ArchiveError("单文件超过资源上限（仅位置）：%s" % relative)
            if total > limits["max_total_bytes"]:
                raise ArchiveError("工程总大小超过资源上限")
            records.append({"path": relative, **fingerprint})
        checked = _validate_source(root)
        manifest = _archive_manifest(checked["project"], records, total, directories)
        _validate_manifest(manifest, limits)
        fd, temporary_name = tempfile.mkstemp(prefix=".seep-archive-", suffix=".tmp",
                                               dir=str(out.parent))
        os.close(fd)
        temporary = Path(temporary_name)
        try:
            with zipfile.ZipFile(str(temporary), "w", compression=zipfile.ZIP_STORED,
                                 allowZip64=True) as bundle:
                for record, (_relative, path) in zip(records, files):
                    before = _fingerprint(path, record["size"])
                    if before != {"sha256": record["sha256"], "size": record["size"]}:
                        raise ArchiveError("项目文件在打包前发生变化（仅位置）：%s" % record["path"])
                    bundle.write(str(path), arcname=record["path"])
                    after = _fingerprint(path, record["size"])
                    if after != before:
                        raise ArchiveError("项目文件在打包期间发生变化（仅位置）：%s" % record["path"])
                bundle.writestr(ARCHIVE_MANIFEST, _json(manifest).encode("utf-8"))
            if temporary.stat().st_size > limits["max_archive_bytes"]:
                raise ArchiveError("归档文件超过资源上限")
            # Verify what was actually packed, including content that changed only
            # during ZipFile.write and was restored before the source recheck.
            _read_and_validate_zip(temporary, limits)
            _validate_source(root)
            current_files, current_directories = _iter_project_tree(root, limits["max_files"])
            if ([relative for relative, _path in current_files]
                    != [relative for relative, _path in files]
                    or current_directories != directories):
                raise ArchiveError("项目文件或目录集合在打包期间发生变化")
            for record, (_relative, path) in zip(records, current_files):
                if _fingerprint(path, record["size"]) != {"sha256": record["sha256"], "size": record["size"]}:
                    raise ArchiveError("项目文件在打包期间发生变化（仅位置）：%s" % record["path"])
            _publish_new_file(temporary, out)
        finally:
            if temporary.exists():
                temporary.unlink()
    return {"ok": True, "operation": "export", "archive": str(out),
            "schema": ARCHIVE_SCHEMA, "project": manifest["project"],
            "file_count": manifest["file_count"], "total_size": manifest["total_size"],
            "archive_size": out.stat().st_size, "limits": limits}


def _zip_member_name(name: str) -> str:
    return _safe_rel(name, "ZIP 成员路径")


def _zip_is_regular(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(mode)
    if mode and file_type not in (0, stat.S_IFREG):
        return False
    # DOS reparse bit and encrypted members are not accepted as ordinary files.
    if info.external_attr & 0x400 or info.flag_bits & 0x1:
        return False
    return True


def _check_path_topology(files: list[str], directories: list[str], max_files: int) -> None:
    """Check portable names and count implicit parents, excluding the manifest."""
    nodes: dict[str, tuple[str, str]] = {ARCHIVE_MANIFEST: (ARCHIVE_MANIFEST, "file")}
    for relative, leaf_kind in ([(value, "directory") for value in directories]
                                + [(value, "file") for value in files]):
        parts = PurePosixPath(relative).parts
        for index in range(1, len(parts) + 1):
            path = "/".join(parts[:index])
            kind = leaf_kind if index == len(parts) else "directory"
            previous = nodes.get(path.casefold())
            if previous is not None:
                if previous[0] != path:
                    raise ArchiveError("归档清单存在跨文件/目录的大小写冲突")
                if previous[1] != kind:
                    raise ArchiveError("归档清单存在文件/目录前缀冲突")
            nodes[path.casefold()] = (path, kind)
            if len(nodes) - 1 > max_files:
                raise ArchiveError("归档隐式/显式文件和目录数量超过资源上限")


def _validate_manifest(manifest: object, limits: dict) -> tuple[dict, dict[str, dict]]:
    if not isinstance(manifest, dict) or manifest.get("schema") != ARCHIVE_SCHEMA:
        raise ArchiveError("归档清单 schema 无效")
    project = manifest.get("project")
    if not isinstance(project, dict) or project.get("schema") != P.PROJECT_SCHEMA:
        raise ArchiveError("归档清单中的 project schema 无效")
    try:
        project_id = P.require_id(str(project.get("project_id", "")), "project_id")
    except Exception as exc:
        raise ArchiveError("归档清单 project_id 无效") from exc
    if project_id != project.get("project_id"):
        raise ArchiveError("归档清单 project_id 类型无效")
    rows = manifest.get("files")
    raw_directories = manifest.get("directories", [])
    directories = [] if raw_directories is None else raw_directories
    file_count = manifest.get("file_count")
    declared_total = manifest.get("total_size")
    if type(file_count) is not int or file_count < 0 \
            or not isinstance(rows, list) or len(rows) != file_count:
        raise ArchiveError("归档清单文件计数无效")
    if not isinstance(directories, list):
        raise ArchiveError("归档清单 directories 必须是列表")
    if type(declared_total) is not int or declared_total < 0:
        raise ArchiveError("归档清单总大小无效")
    if len(rows) + len(directories) > limits["max_files"]:
        raise ArchiveError("归档文件和目录数量超过资源上限")
    by_path: dict[str, dict] = {}
    folded: dict[str, str] = {}
    total = 0
    for row in rows:
        if not isinstance(row, dict):
            raise ArchiveError("归档清单文件项无效")
        path = _safe_rel(row.get("path"), "清单路径")
        if path == ARCHIVE_MANIFEST:
            raise ArchiveError("归档清单不能登记 archive.json 自身")
        if path.casefold() in folded:
            raise ArchiveError("归档清单存在重复或大小写冲突路径")
        if _sensitive_location(path):
            raise ArchiveError("归档清单包含不归档的敏感材料（仅位置）")
        folded[path.casefold()] = path
        size = row.get("size")
        digest = row.get("sha256")
        if type(size) is not int or size < 0 or size > limits["max_member_bytes"]:
            raise ArchiveError("归档清单文件大小超过或不符合资源限制")
        if not isinstance(digest, str) or len(digest) != 64 \
                or digest != digest.lower() or any(c not in "0123456789abcdef" for c in digest):
            raise ArchiveError("归档清单存在非法 SHA256")
        total += size
        if total > limits["max_total_bytes"]:
            raise ArchiveError("归档清单总大小超过资源上限")
        by_path[path] = {"path": path, "size": size, "sha256": digest}
    if total != declared_total:
        raise ArchiveError("归档清单总大小不可复算")
    directory_paths: list[str] = []
    directory_folded: dict[str, str] = {}
    for value in directories:
        directory = _safe_rel(value, "清单目录路径")
        if directory == ARCHIVE_MANIFEST or _sensitive_location(directory):
            raise ArchiveError("归档清单目录路径保留或敏感（仅位置）")
        folded = directory.casefold()
        if folded in directory_folded:
            raise ArchiveError("归档清单 directories 存在重复或大小写冲突")
        directory_folded[folded] = directory
        directory_paths.append(directory)
    _check_path_topology(list(by_path), directory_paths, limits["max_files"])
    return {"schema": manifest["schema"], "project": {"schema": project["schema"],
            "project_id": project_id}, "files": list(by_path.values()),
            "directories": sorted(directory_paths), "file_count": len(by_path),
            "total_size": total}, by_path


def _stream_member(bundle: zipfile.ZipFile, info: zipfile.ZipInfo,
                   expected: dict | None, limits: dict, label: str) -> int:
    """Read one member fully so zipfile checks CRC and we recheck actual bytes."""
    digest = hashlib.sha256()
    size = 0
    maximum = 2 * 1024 * 1024 if label == ARCHIVE_MANIFEST else limits["max_member_bytes"]
    try:
        with bundle.open(info, "r") as source:
            for block in iter(lambda: source.read(1 << 20), b""):
                size += len(block)
                if size > maximum:
                    raise ArchiveError("ZIP 成员实际展开超过资源上限")
                digest.update(block)
    except ArchiveError:
        raise
    except (OSError, RuntimeError, EOFError, zipfile.BadZipFile, zlib.error) as exc:
        raise ArchiveError("ZIP 成员 CRC/内容校验失败（仅位置）：%s" % label) from exc
    if info.compress_size and size / info.compress_size > limits["max_compression_ratio"]:
        raise ArchiveError("ZIP 成员实际压缩比超过资源上限")
    if expected is not None and (size != expected["size"] or digest.hexdigest() != expected["sha256"]):
        raise ArchiveError("ZIP 成员大小或 SHA256 不符（仅位置）：%s" % label)
    return size


def _stream_validate_members(bundle: zipfile.ZipFile, infos: list[zipfile.ZipInfo],
                             by_path: dict[str, dict], limits: dict) -> None:
    actual_total = 0
    for info in infos:
        name = _zip_member_name(info.filename)
        expected = by_path.get(name)
        size = _stream_member(bundle, info, expected, limits, name)
        if name != ARCHIVE_MANIFEST:
            actual_total += size
            if actual_total > limits["max_total_bytes"]:
                raise ArchiveError("ZIP 成员实际总大小超过资源上限")
    if actual_total != sum(row["size"] for row in by_path.values()):
        raise ArchiveError("ZIP 成员实际总大小与清单不符")


def _read_and_validate_zip(archive: Path, limits: dict) -> tuple[dict, list[zipfile.ZipInfo]]:
    _reject_linked_path(archive)
    if not archive.is_file() or archive.is_symlink() or _is_reparse(archive):
        raise ArchiveError("归档文件不存在或不是普通文件")
    if archive.stat().st_size > limits["max_archive_bytes"]:
        raise ArchiveError("归档文件超过资源上限")
    try:
        bundle = zipfile.ZipFile(str(archive), "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise ArchiveError("ZIP 容器不可读") from exc
    try:
        infos = bundle.infolist()
        if len(infos) > limits["max_files"] + 1:
            raise ArchiveError("ZIP 成员数量超过资源上限")
        names: dict[str, str] = {}
        for info in infos:
            name = _zip_member_name(info.filename)
            if name.casefold() in names:
                raise ArchiveError("ZIP 存在重复或大小写冲突成员")
            names[name.casefold()] = name
            if not _zip_is_regular(info) or info.is_dir():
                raise ArchiveError("ZIP 包含目录、链接、reparse 或特殊成员（仅位置）")
            if info.file_size > limits["max_member_bytes"]:
                raise ArchiveError("ZIP 成员超过资源上限")
            if info.file_size and info.compress_size == 0:
                raise ArchiveError("ZIP 成员压缩尺寸异常")
            if info.compress_size and info.file_size / info.compress_size > limits["max_compression_ratio"]:
                raise ArchiveError("ZIP 成员压缩比超过资源上限")
        if names.get(ARCHIVE_MANIFEST) != ARCHIVE_MANIFEST:
            raise ArchiveError("ZIP 缺少唯一 archive.json 清单")
        manifest_info = next(info for info in infos if info.filename == ARCHIVE_MANIFEST)
        if manifest_info.file_size > 2 * 1024 * 1024:
            raise ArchiveError("归档清单超过资源上限")
        try:
            manifest = json.loads(bundle.read(manifest_info).decode("utf-8"))
        except Exception as exc:
            raise ArchiveError("归档清单不可解析") from exc
        normalized, by_path = _validate_manifest(manifest, limits)
        expected = {ARCHIVE_MANIFEST} | set(by_path)
        actual = set(names.values())
        if actual != expected:
            raise ArchiveError("ZIP 成员与清单不一致（存在缺件或 extra）")
        _stream_validate_members(bundle, infos, by_path, limits)
        return normalized, infos
    except ArchiveError:
        raise
    finally:
        bundle.close()


def _extract_to_staging(archive: Path, staging: Path, manifest: dict,
                        limits: dict) -> None:
    wanted = {row["path"]: row for row in manifest["files"]}
    for relative in manifest.get("directories", []):
        directory = staging.joinpath(*PurePosixPath(relative).parts)
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ArchiveError("声明目录创建失败（仅位置）：%s" % relative) from exc
        if directory.is_symlink() or _is_reparse(directory) or not directory.is_dir():
            raise ArchiveError("声明目录不是普通目录（仅位置）：%s" % relative)
    with zipfile.ZipFile(str(archive), "r") as bundle:
        for row in manifest["files"]:
            info = bundle.getinfo(row["path"])
            destination = staging.joinpath(*PurePosixPath(row["path"]).parts)
            digest = hashlib.sha256()
            size = 0
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(info, "r") as source, destination.open("xb") as target:
                    for block in iter(lambda: source.read(1 << 20), b""):
                        size += len(block)
                        if size > limits["max_member_bytes"] or size > row["size"]:
                            raise ArchiveError("ZIP 成员实际展开超过清单/资源限制")
                        digest.update(block)
                        target.write(block)
            except ArchiveError:
                raise
            except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
                raise ArchiveError("ZIP 成员展开失败（仅位置）：%s" % row["path"]) from exc
            if size != row["size"] or digest.hexdigest() != row["sha256"]:
                raise ArchiveError("ZIP 成员大小或 SHA256 不符（仅位置）：%s" % row["path"])
    if set(wanted) != {row["path"] for row in manifest["files"]}:
        raise ArchiveError("归档展开集合不可复核")
    for relative in manifest.get("directories", []):
        directory = staging.joinpath(*PurePosixPath(relative).parts)
        if directory.is_symlink() or _is_reparse(directory) or not directory.is_dir():
            raise ArchiveError("声明目录导入后不可复核（仅位置）：%s" % relative)


def _run_core_cli(script: Path, command: str, root: Path) -> dict:
    result = subprocess.run(
        [sys.executable, "-B", str(script), command, "--project", str(root)],
        cwd=str(SCRIPT_DIR.parent.parent), capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=45,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8"),
    )
    try:
        payload = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise ArchiveError("Core %s 未返回可解析 JSON" % command) from exc
    if result.returncode != 0 or not payload.get("ok"):
        raise ArchiveError("Core %s 验证拒绝导入" % command)
    return payload


def _validate_staging(staging: Path, manifest: dict) -> dict:
    try:
        project = P.require_project(staging)
    except Exception as exc:
        raise ArchiveError("staging project.json 无效") from exc
    expected_project = manifest["project"]
    if project.get("schema") != expected_project["schema"] \
            or project.get("project_id") != expected_project["project_id"]:
        raise ArchiveError("staging 工程身份与归档清单不一致")
    for relative in manifest.get("directories", []):
        path = staging / PurePosixPath(relative)
        if not path.is_dir() or path.is_symlink() or _is_reparse(path):
            raise ArchiveError("staging 缺少声明目录（仅位置）：%s" % relative)
    for row in manifest["files"]:
        path = staging / PurePosixPath(row["path"])
        if not path.is_file() or path.is_symlink() or _is_reparse(path):
            raise ArchiveError("staging 缺少普通文件（仅位置）：%s" % row["path"])
        actual = _fingerprint(path)
        if actual != {"sha256": row["sha256"], "size": row["size"]}:
            raise ArchiveError("staging 文件指纹不符（仅位置）：%s" % row["path"])
    _run_core_cli(SCRIPT_DIR / "project_state.py", "resume", staging)
    report = _run_core_cli(SCRIPT_DIR / "project_report.py", "status", staging)
    return {"project": {"schema": project.get("schema"), "project_id": project.get("project_id")},
            "report": {"ok": bool(report.get("ok"))}}


def import_archive(archive_arg: str, project_arg: str, args: argparse.Namespace) -> dict:
    archive = Path(os.path.abspath(str(archive_arg)))
    destination = Path(os.path.abspath(str(project_arg)))
    _check_import_layout(destination, "destination")
    _check_import_path(destination.parent / ".project.lock", "parent_lock")
    _reject_linked_path(destination)
    limits = _limits(args)
    if not destination.parent.exists() or not destination.parent.is_dir():
        raise ArchiveError("导入目标父目录不存在")
    if destination.parent.is_symlink() or _is_reparse(destination.parent):
        raise ArchiveError("导入目标父目录不是普通目录")
    manifest, _infos = _read_and_validate_zip(archive, limits)
    # Plan an exact, random sibling name before any lock/staging write. mkdir
    # below claims it exclusively; a collision is a refusal, never a reuse.
    staging = destination.parent / (STAGING_PREFIX + secrets.token_hex(4))
    _check_import_layout(destination, "destination", manifest)
    _check_import_layout(staging, "staging", manifest)
    validation = None
    published = False
    # The existing project lock is used on the destination parent so cooperating
    # imports of the same destination serialize their existence check and publish.
    # An unrelated external writer is outside this lock's guarantee.
    with project_lock(destination.parent):
        if destination.exists():
            raise ArchiveError("导入目标已存在，拒绝覆盖")
        staging.mkdir(mode=0o700)  # exclusive, with mkdtemp's private permissions
        try:
            _extract_to_staging(archive, staging, manifest, limits)
            validation = _validate_staging(staging, manifest)
            if destination.exists():
                raise ArchiveError("导入目标在验证期间已存在，拒绝覆盖")
            try:
                os.rename(str(staging), str(destination))
            except FileExistsError as exc:
                raise ArchiveError("并发导入竞争失败：目标已由另一导入发布") from exc
            except OSError as exc:
                raise ArchiveError("无法原子发布导入目标") from exc
            published = True
        finally:
            if not published and staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
    return {"ok": True, "operation": "import", "archive": str(archive),
            "project": manifest["project"], "destination": str(destination),
            "file_count": manifest["file_count"], "total_size": manifest["total_size"],
            "validation": validation, "limits": limits}


def verify_archive(archive_arg: str, args: argparse.Namespace) -> dict:
    archive = Path(os.path.abspath(str(archive_arg)))
    limits = _limits(args)
    manifest, infos = _read_and_validate_zip(archive, limits)
    return {"ok": True, "operation": "verify", "archive": str(archive),
            "schema": manifest["schema"], "project": manifest["project"],
            "file_count": manifest["file_count"], "total_size": manifest["total_size"],
            "member_count": len(infos), "limits": limits}


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="工程闭包归档导出/重导入（JSON stdout，失败 rc=2）")
    sub = ap.add_subparsers(dest="command", required=True)
    def limits(p: argparse.ArgumentParser) -> None:
        p.add_argument("--max-archive-bytes", type=int, default=DEFAULT_LIMITS["max_archive_bytes"])
        p.add_argument("--max-member-bytes", type=int, default=DEFAULT_LIMITS["max_member_bytes"])
        p.add_argument("--max-total-bytes", type=int, default=DEFAULT_LIMITS["max_total_bytes"])
        p.add_argument("--max-files", type=int, default=DEFAULT_LIMITS["max_files"])
        p.add_argument("--max-compression-ratio", type=int,
                       default=DEFAULT_LIMITS["max_compression_ratio"])
    p = sub.add_parser("export", help="锁定并导出健康工程闭包")
    p.add_argument("--project", required=True)
    p.add_argument("--out", required=True)
    limits(p)
    p = sub.add_parser("import", help="完整验证后发布到不存在的目标目录")
    p.add_argument("--archive", required=True)
    p.add_argument("--project", required=True)
    limits(p)
    p = sub.add_parser("verify", help="只验证 ZIP 与独立清单，不创建项目")
    p.add_argument("--archive", required=True)
    limits(p)
    return ap


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(sys.argv[1:] if argv is None else argv)
        if args.command == "export":
            return _emit(export_archive(args.project, args.out, args))
        if args.command == "import":
            return _emit(import_archive(args.archive, args.project, args))
        return _emit(verify_archive(args.archive, args))
    except ArchivePathError as exc:
        return _refuse("archive_path_preflight", str(exc), error_code="path_limit",
                       path_limit=exc.details,
                       recovery={"action": "retry_same_archive_in_shorter_directory",
                                 "example_destination": "C:\\s\\restored",
                                 "requires_existing_plain_parent": True,
                                 "requires_absent_destination": True})
    except ArchiveError as exc:
        return _refuse("archive", str(exc))
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return _refuse("archive", "操作被拒绝（%s）" % type(exc).__name__)
    except Exception as exc:  # structured refusal; do not expose values or paths
        return _refuse("archive", "内部校验失败（%s）" % type(exc).__name__)


if __name__ == "__main__":
    raise SystemExit(main())
