"""Recursive deployment asset inventory shared by source and runtime gates.

The checks compare every deployable file in a skill tree. Cache, temporary and
sensitive files are deliberately omitted, while links and unreadable files are
treated as errors so a gate cannot silently inspect only a convenient subset.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat


SKIP_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".venv",
    "__pycache__",
    "node_modules",
    "temp",
    "tmp",
    "venv",
}
SKIP_SUFFIXES = {
    ".bak",
    ".old",
    ".pyc",
    ".pyo",
    ".swo",
    ".swp",
    ".temp",
    ".tmp",
}
SENSITIVE_NAMES = {
    ".env",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
}
SENSITIVE_SUFFIXES = {
    ".jks",
    ".kdbx",
    ".key",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
}
TEXT_SUFFIXES = {
    ".c",
    ".cmd",
    ".cpp",
    ".cs",
    ".css",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".java",
    ".js",
    ".json",
    ".jsonc",
    ".jsx",
    ".kt",
    ".md",
    ".mjs",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


class DeployAssetError(RuntimeError):
    """A deployment tree could not be inventoried safely."""


_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _is_link(path: Path) -> bool:
    info = os.lstat(path)
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE
    )


def _excluded_file(path: Path) -> bool:
    name = path.name.lower()
    suffix = path.suffix.lower()
    return (
        name in SENSITIVE_NAMES
        or name.startswith((".env.", ".seep-tmp-", ".tmp-"))
        or name.endswith("~")
        or suffix in SKIP_SUFFIXES
        or suffix in SENSITIVE_SUFFIXES
    )


def _digest(path: Path) -> str:
    suffix = path.suffix.lower()
    raw = path.read_bytes()
    if suffix in TEXT_SUFFIXES:
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            raw = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(raw).hexdigest()


def inventory_tree(root: str | os.PathLike[str]) -> dict[str, dict[str, int | str]]:
    """Return ``relative path -> identity`` for a deployable tree."""
    raw_root = Path(root)
    if _is_link(raw_root):
        raise DeployAssetError("deployment root is a symlink/reparse point: %s" % raw_root)
    base = raw_root.resolve(strict=True)
    if not base.is_dir():
        raise DeployAssetError("not a directory: %s" % base)
    inventory: dict[str, dict[str, int | str]] = {}
    for current, dirs, files in os.walk(base, followlinks=False, onerror=lambda exc: (_ for _ in ()).throw(exc)):
        folder = Path(current)
        kept_dirs = []
        for name in sorted(dirs):
            path = folder / name
            if name.lower() in SKIP_DIRS:
                continue
            if _is_link(path):
                raise DeployAssetError("deployment tree contains symlink directory: %s" % path)
            kept_dirs.append(name)
        dirs[:] = kept_dirs
        for name in sorted(files):
            path = folder / name
            if _is_link(path):
                raise DeployAssetError("deployment tree contains symlink file: %s" % path)
            if _excluded_file(path):
                continue
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(base)
            except (OSError, ValueError) as exc:
                raise DeployAssetError("asset escapes deployment root: %s" % path) from exc
            if not resolved.is_file():
                raise DeployAssetError("deployment asset is not a regular file: %s" % path)
            relative = resolved.relative_to(base).as_posix()
            inventory[relative] = {
                "sha256": _digest(resolved),
                "size": resolved.stat().st_size,
            }
    return inventory


def compare_trees(source: str | os.PathLike[str],
                  deployed: str | os.PathLike[str]) -> dict[str, list[str]]:
    """Compare complete deployable inventories, without hiding either side."""
    try:
        src = inventory_tree(source)
    except (OSError, DeployAssetError) as exc:
        return {"missing": [], "extra": [], "drift": [], "errors": ["source: %s" % exc]}
    try:
        dst = inventory_tree(deployed)
    except FileNotFoundError:
        dst = {}
    except (OSError, DeployAssetError) as exc:
        return {"missing": [], "extra": [], "drift": [], "errors": ["deployment: %s" % exc]}

    missing = sorted(set(src) - set(dst))
    extra = sorted(set(dst) - set(src))
    drift = sorted(
        path for path in set(src) & set(dst)
        if src[path]["sha256"] != dst[path]["sha256"] or src[path]["size"] != dst[path]["size"]
    )
    return {"missing": missing, "extra": extra, "drift": drift, "errors": []}
