"""Recoverable rollback for bounded project file transactions.

Callers hold the shared project lock. A durable before-image journal is published
before any managed file changes; unlinking it is the commit point. A later writer
may restore an interrupted operation. Readers refuse pending transactions.
This is a local crash-recovery mechanism, not a concurrent external-edit protocol.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

from .project_lock import project_file

JOURNAL = ".project-transaction.json"
SCHEMA = "seep-project-transaction/1"
MAX_BYTES = 64 << 20
MAX_JOURNAL_BYTES = 90 << 20
# One bounded directory snapshot (20,000 entries) plus Core metadata.
MAX_FILES = 20032
MAX_DIRECTORIES = 20064


def _path(root: Path, ref: str) -> Path:
    if not isinstance(ref, str) or "\x00" in ref:
        raise ValueError("invalid transaction path")
    path = project_file(root, ref)
    if ref != path.relative_to(root).as_posix() or ref.casefold() in (".", ".project.lock"):
        raise ValueError("noncanonical transaction path")
    for part in (path, *path.parents):
        if part.is_symlink() or (part.exists() and getattr(part.lstat(), "st_file_attributes", 0)
                                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024)):
            raise ValueError("linked transaction path")
        if part == root:
            break
    return path


def pending(root: Path) -> bool:
    path = root / JOURNAL
    return path.exists() or path.is_symlink()


def _sync_directory(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass  # Directory fsync is not supported on every platform.


def _replace(path: Path, payload: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".seep-transaction-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _snapshot(root: Path, refs: list[str], directories: list[str] | None = None) -> dict:
    if not refs or len(refs) > MAX_FILES or any(not isinstance(ref, str) for ref in refs):
        raise ValueError("invalid transaction write set")
    names = {ref.casefold() for ref in refs}
    if len(names) != len(refs) or JOURNAL.casefold() in names:
        raise ValueError("duplicate/reserved transaction destination")
    if directories is not None and not isinstance(directories, list):
        raise ValueError("invalid transaction directory write set")
    declared = list(directories or [])
    if len(declared) > MAX_DIRECTORIES or any(not isinstance(ref, str) for ref in declared):
        raise ValueError("invalid transaction directory write set")
    if len({ref.casefold() for ref in declared}) != len(declared):
        raise ValueError("duplicate transaction directory")
    rows, created, total = [], set(), 0
    for ref in declared:
        directory = _path(root, ref)
        parts = ref.casefold().split("/")
        ancestors = {"/".join(parts[:index]) for index in range(1, len(parts) + 1)}
        if JOURNAL.casefold() in ancestors or not ancestors.isdisjoint(names):
            raise ValueError("transaction directory conflicts with file destination")
        for parent in (directory, *directory.parents):
            if parent == root:
                break
            if not parent.exists():
                created.add(parent.relative_to(root).as_posix())
            elif not parent.is_dir():
                raise ValueError("transaction directory is not a directory")
    for ref in refs:
        path = _path(root, ref)
        for parent in path.parents:
            if parent == root:
                break
            if not parent.exists():
                created.add(parent.relative_to(root).as_posix())
            elif not parent.is_dir():
                raise ValueError("transaction parent is not a directory")
        payload = None
        if path.exists():
            if not path.is_file():
                raise ValueError("transaction destination is not a file")
            if path.stat().st_size > MAX_BYTES - total:
                raise ValueError("transaction before-images exceed 64 MiB")
            with path.open("rb") as stream:
                payload = stream.read(MAX_BYTES - total + 1)
            total += len(payload)
            if total > MAX_BYTES:
                raise ValueError("transaction before-images exceed 64 MiB")
        rows.append({"path": ref,
                     "before": base64.b64encode(payload).decode("ascii") if payload is not None else None,
                     "sha256": hashlib.sha256(payload).hexdigest() if payload is not None else None})
    if len(created) > MAX_DIRECTORIES:
        raise ValueError("transaction created directory count exceeds limit")
    return {"schema": SCHEMA, "files": rows, "directory_paths": declared,
            "created_directories": sorted(created)}


def _load(root: Path) -> tuple[list, list]:
    path = _path(root, JOURNAL)
    if not path.is_file() or path.stat().st_size > MAX_JOURNAL_BYTES:
        raise ValueError("invalid transaction journal")
    with path.open("rb") as stream:
        payload = stream.read(MAX_JOURNAL_BYTES + 1)
    if len(payload) > MAX_JOURNAL_BYTES:
        raise ValueError("transaction journal exceeds limit")
    data = json.loads(payload)
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValueError("invalid transaction journal schema")
    rows, directories = data.get("files"), data.get("created_directories")
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_FILES or not isinstance(directories, list):
        raise ValueError("invalid transaction journal write set")
    files, seen, total = [], set(), 0
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid transaction journal row")
        ref = row.get("path")
        target = _path(root, ref)
        if ref.casefold() == JOURNAL.casefold() or ref.casefold() in seen:
            raise ValueError("duplicate/reserved transaction destination")
        seen.add(ref.casefold())
        payload = row.get("before")
        if payload is not None:
            if not isinstance(payload, str):
                raise ValueError("invalid transaction before-image")
            payload = base64.b64decode(payload, validate=True)
            total += len(payload)
            if total > MAX_BYTES or hashlib.sha256(payload).hexdigest() != row.get("sha256"):
                raise ValueError("invalid transaction before-image fingerprint")
        elif row.get("sha256") is not None:
            raise ValueError("invalid absent transaction before-image")
        if target.exists() and not target.is_file():
            raise ValueError("transaction restore destination is not a file")
        files.append((target, payload))
    if len(directories) > MAX_DIRECTORIES:
        raise ValueError("invalid transaction directory count")
    declared = data.get("directory_paths", [])
    if not isinstance(declared, list) or len(declared) > MAX_DIRECTORIES:
        raise ValueError("invalid transaction directory write set")
    declared_paths, declared_names = [], set()
    for ref in declared:
        directory = _path(root, ref)
        name = ref.casefold()
        parts = name.split("/")
        ancestors = {"/".join(parts[:index]) for index in range(1, len(parts) + 1)}
        if name in declared_names or JOURNAL.casefold() in ancestors or not ancestors.isdisjoint(seen):
            raise ValueError("invalid transaction directory destination")
        if directory.exists() and not directory.is_dir():
            raise ValueError("transaction directory is not a directory")
        declared_paths.append(directory)
        declared_names.add(name)
    parents = {p.relative_to(root).as_posix() for target, _ in files for p in target.parents
               if p != root and p.is_relative_to(root)}
    parents.update(p.relative_to(root).as_posix() for directory in declared_paths
                   for p in (directory, *directory.parents) if p != root and p.is_relative_to(root))
    checked, checked_names = [], set()
    for ref in directories:
        directory = _path(root, ref)
        if ref not in parents or ref.casefold() in checked_names or directory.exists() and not directory.is_dir():
            raise ValueError("invalid transaction created directory")
        checked.append(directory)
        checked_names.add(ref.casefold())
    return files, sorted(checked, key=lambda p: len(p.parts), reverse=True)


def recover(root: Path) -> bool:
    """Restore all before-images; validate the entire journal before changing files."""
    if not pending(root):
        return False
    files, directories = _load(root)
    for path, payload in reversed(files):
        if payload is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            _replace(path, payload)
    for directory in directories:
        try:
            directory.rmdir()  # Never recursively remove unexpected contents.
        except FileNotFoundError:
            pass
    (root / JOURNAL).unlink()
    _sync_directory(root)
    return True


@contextlib.contextmanager
def file_transaction(root: Path, refs: list[str], *, directories: list[str] | None = None):
    """Commit only when the caller returns normally; retain journal if rollback fails."""
    root = Path(os.path.abspath(root))
    if pending(root):
        raise ValueError("pending project transaction requires recovery")
    snapshot = _snapshot(root, refs, directories)
    journal = _path(root, JOURNAL)
    payload = (json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    if len(payload) > MAX_JOURNAL_BYTES:
        raise ValueError("transaction journal exceeds limit")
    _replace(journal, payload)
    try:
        yield
        journal.unlink()
        _sync_directory(root)
    except BaseException:
        recover(root)
        raise
