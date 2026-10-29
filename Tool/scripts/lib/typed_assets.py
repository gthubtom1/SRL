#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Typed asset identity primitives: ``file`` / ``directory`` / ``url_descriptor``.

Batch #42-1.  This module is the single place where directory-tree and URL-descriptor
identity rules live; project_state now consumes its explicit verifier and Manager /
Workflow / Report reuse that Core entry point.  Archive export/import and the
professional claim ledger remain outside this module.

Facts this module never claims:
* a copy-only snapshot is not an atomic filesystem snapshot, and it does not
  defeat every ABA on the source tree (it re-verifies the source before/after);
* a directory tree hash covers relative POSIX path / type / sha256 / size only,
  not permissions, mtime or xattr;
* a URL descriptor hash is a hash of the *description text*, never of remote
  content, response headers, status or a point-in-time state.  No connection,
  request, download or browser is ever made here.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

try:
    from lib.project_lock import atomic_copy, digest
    from pathlib import PurePosixPath
except ImportError:  # pragma: no cover - imported as Tool.scripts.lib.*
    from Tool.scripts.lib.project_lock import atomic_copy, digest
    from pathlib import PurePosixPath

ASSET_SCHEMA = "seep-typed-asset/1"
SNAPSHOT_SCHEMA = "seep-typed-snapshot/1"
MANIFEST_SCHEMA = "seep-typed-snapshot-manifest/1"
TREE_SCHEMA = "seep-typed-tree/1"
URL_SCHEMA = "seep-typed-url-descriptor/1"

DIR_ALGO = "sha256-canonical-json-tree/1"
FILE_ALGO = "sha256-raw-bytes/1"
URL_ALGO = "sha256-canonical-json-descriptor/1"

KINDS = ("file", "directory", "url_descriptor")
ROLES = ("primary", "auxiliary", "action_target")
ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

DIRECTORY_LIMITS = (
    "内容身份只覆盖相对 POSIX 路径/type/sha256/size；权限、mtime、xattr 不纳入 content identity",
    "复制式快照（copy-only），不是原子文件系统快照；来源在复制前后各验一次，不承诺对抗全部 ABA",
    "混合用途目录只是载体：不据此推断域，也不自动选择 primary/auxiliary 角色",
    "只拒绝 symlink/reparse/pipe/device 与越界相对路径；不读取用户其它目录",
)
URL_LIMITS = (
    "descriptor sha256 只证明这份描述文本，不是远端内容 hash、不是响应/状态/时间戳快照",
    "本模块不建立任何连接、不请求、不下载、不启动浏览器、不执行远端内容",
)


class TypedAssetError(ValueError):
    """Identity/schema violation. Messages never echo secret values or abs paths."""


class LimitExceeded(TypedAssetError):
    """A declared resource bound was hit; the result is never a usable snapshot."""


class ConcurrentChange(TypedAssetError):
    """The source changed while it was being measured or copied."""


class RootPathError(TypedAssetError):
    """A filesystem/drive/UNC anchor was offered as a scannable directory."""


class SnapshotBoundaryError(TypedAssetError):
    """snapshot source and the final destination slot overlap or are equal."""

@dataclass(frozen=True)
class DirectoryLimits:
    max_entries: int = 20000
    max_bytes: int = 512 * 1024 * 1024
    max_file_bytes: int = 256 * 1024 * 1024
    max_depth: int = 32
    max_path_chars: int = 1024


# --------------------------------------------------------------------------- #
# path resolution: lexical project-relative check, no symlink-following resolve
# --------------------------------------------------------------------------- #
def _project_path(root: Path, relative: str, label: str = "local_path") -> Path:
    """Resolve a project-relative ref **without** resolving symlinks.

    ``lib.project_lock.project_file`` also validates through ``Path.resolve()``,
    which follows links (an in-project dangling link reads as an escape) and on
    some Pythons raises on a dangling outer path.  We keep the same lexical
    rules and add a per-component link/reparse refusal, so the failure is an
    explicit error and the link is never followed.
    """
    text = str(relative if relative is not None else "").replace("\\", "/")
    ref = PurePosixPath(text)
    if not text or ref.is_absolute() or ".." in ref.parts or ":" in text:
        raise TypedAssetError("%s must be a project-relative path "
                              "(no absolute/drive/'..'): %r" % (label, text[:64]))
    current = Path(root)
    for part in ref.parts:
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            continue          # not created yet: later components cannot exist either
        except OSError as exc:  # pragma: no cover - exotic filesystem
            raise TypedAssetError("%s is unreadable (%s)" % (label, type(exc).__name__))
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _REPARSE:
            raise TypedAssetError("%s must not traverse a symlink/reparse point: %r"
                                  % (label, text[:64]))
    return current


# --------------------------------------------------------------------------- #
# small local durable write (a copy helper, not a new project-state store)
# --------------------------------------------------------------------------- #
def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".typed-asset-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _tree_sha(entries: list) -> str:
    return hashlib.sha256(_canonical({"schema": TREE_SCHEMA, "entries": entries})).hexdigest()


def _lexical(path: Path) -> Path:
    """Absolute + normalised, **without** resolving links (identity for comparison)."""
    return Path(os.path.abspath(str(path)))


def _refuse_anchor(path: Path, label: str = "source root") -> None:
    """Refuse filesystem/drive/UNC roots by metadata only, before any listing.

    ``Path.anchor``/``parent == self`` is pure string arithmetic: no ``stat``, no
    ``scandir``, so an anchor is rejected without touching the filesystem.  This
    is a separate boundary from resource limits: a root is not "too big".
    """
    candidate = Path(os.path.abspath(str(path)))
    if candidate.anchor and (candidate == Path(candidate.anchor)
                             or candidate.parent == candidate):
        raise RootPathError("%s must not be a filesystem/drive/UNC anchor" % label)


def _plain_dir(path: Path, label: str) -> None:
    _refuse_anchor(path, label)
    st = os.lstat(path)
    attrs = getattr(st, "st_file_attributes", 0)
    if stat.S_ISLNK(st.st_mode) or attrs & _REPARSE:
        raise TypedAssetError("%s must not be a symlink/reparse point" % label)
    if not stat.S_ISDIR(st.st_mode):
        raise TypedAssetError("%s must be a directory" % label)


def _hash_regular(path: Path, rel: str, limits: DirectoryLimits) -> tuple[str, int]:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _REPARSE:
        raise TypedAssetError("symlink/reparse not allowed in tree: %s" % rel)
    if not stat.S_ISREG(st.st_mode):
        raise TypedAssetError("non-regular file not allowed (pipe/device/socket): %s" % rel)
    hasher = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
            raise ConcurrentChange("file replaced while opening: %s" % rel)
        for block in iter(lambda: stream.read(1 << 20), b""):
            total += len(block)
            if total > limits.max_file_bytes:
                raise LimitExceeded("max_file_bytes exceeded: %s" % rel)
            hasher.update(block)
        closing = os.fstat(stream.fileno())
    after = os.lstat(path)
    if (closing.st_size, after.st_size) != (total, total) \
            or closing.st_mtime_ns != st.st_mtime_ns or after.st_mtime_ns != st.st_mtime_ns \
            or (after.st_dev, after.st_ino) != (st.st_dev, st.st_ino):
        raise ConcurrentChange("file changed while hashing: %s" % rel)
    return hasher.hexdigest(), total


def _walk(root: Path, limits: DirectoryLimits) -> list:
    entries: list[dict] = []
    seen_bytes = [0]

    def bump() -> None:
        if len(entries) > limits.max_entries:
            raise LimitExceeded("max_entries exceeded (%d)" % limits.max_entries)

    def visit(directory: Path, prefix: str, depth: int) -> None:
        if depth > limits.max_depth:
            raise LimitExceeded("max_depth exceeded at %r" % (prefix or "."))
        with os.scandir(directory) as scan:
            items = sorted(scan, key=lambda item: item.name)
        for item in items:
            name = item.name
            if name in (".", "..") or any(ch in name for ch in (":", "\\", "\x00")):
                raise TypedAssetError("unsafe path name in tree at %r" % (prefix + name))
            rel = prefix + name
            if len(rel) > limits.max_path_chars:
                raise LimitExceeded("max_path_chars exceeded at %r" % rel[:64])
            st = item.stat(follow_symlinks=False)
            attrs = getattr(st, "st_file_attributes", 0)
            if stat.S_ISLNK(st.st_mode) or attrs & _REPARSE:
                raise TypedAssetError("symlink/reparse escape not allowed: %s" % rel)
            if stat.S_ISDIR(st.st_mode):
                entries.append({"path": rel, "type": "directory"})
                bump()
                visit(Path(item.path), rel + "/", depth + 1)
            elif stat.S_ISREG(st.st_mode):
                sha, size = _hash_regular(Path(item.path), rel, limits)
                seen_bytes[0] += size
                if seen_bytes[0] > limits.max_bytes:
                    raise LimitExceeded("max_bytes exceeded (%d)" % limits.max_bytes)
                entries.append({"path": rel, "type": "file", "sha256": sha, "size": size})
                bump()
            else:
                raise TypedAssetError(
                    "non-regular file not allowed (pipe/device/socket): %s" % rel)

    visit(root, "", 0)
    entries.sort(key=lambda entry: entry["path"])
    return entries


# --------------------------------------------------------------------------- #
# kind=file  (keeps the existing raw sha256/size semantics, no new truth source)
# --------------------------------------------------------------------------- #
def declared_identity(record: dict) -> dict:
    """Validate every supplied representation before any caller binds its identity.

    Legacy file records may omit the nested identity. When both forms exist they
    describe one identity, so neither may silently override the other.
    """
    if not isinstance(record, dict):
        raise TypedAssetError("asset record must be an object")
    kind = record.get("kind")
    algorithms = {"file": FILE_ALGO, "directory": DIR_ALGO, "url_descriptor": URL_ALGO}
    if not isinstance(kind, str) or kind not in algorithms:
        raise TypedAssetError("unknown asset kind; refusing file fallback")
    if "identity" in record and not isinstance(record["identity"], dict):
        raise TypedAssetError("asset identity must be an object")
    identity = record.get("identity", {})
    if not identity and kind == "file":
        identity = {"algorithm": FILE_ALGO, "sha256": record.get("sha256"),
                    "size": record.get("size")}
    if identity.get("algorithm") != algorithms[kind]:
        raise TypedAssetError("unknown %s identity algorithm" % kind)
    sha, size = identity.get("sha256"), identity.get("size")
    if sha is None:
        raise TypedAssetError("asset identity missing sha256")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise TypedAssetError("asset identity sha256 invalid")
    if type(size) is not int or size < 0:
        raise TypedAssetError("asset identity size invalid")
    result = {"algorithm": algorithms[kind], "sha256": sha, "size": size}
    if kind == "directory":
        for key in ("entry_count", "file_count"):
            if type(identity.get(key)) is not int or identity[key] < 0:
                raise TypedAssetError("directory identity %s invalid" % key)
            result[key] = identity[key]
        if result["file_count"] > result["entry_count"]:
            raise TypedAssetError("directory file_count exceeds entry_count")
    for key in ("sha256", "target_sha256"):
        if key in record and record[key] != sha:
            raise TypedAssetError("asset identity disagrees with %s" % key)
    for key in ("size", "target_size"):
        if key in record and (type(record[key]) is not int or record[key] != size):
            raise TypedAssetError("asset identity disagrees with %s" % key)
    if "algorithm" in record and record["algorithm"] != algorithms[kind]:
        raise TypedAssetError("asset identity disagrees with algorithm")
    scopes = {"file": "raw-bytes", "directory": "tree-content",
              "url_descriptor": "descriptor-only"}
    if "identity_scope" in record and record["identity_scope"] != scopes[kind]:
        raise TypedAssetError("asset identity_scope does not match kind")
    if "remote_content_verified" in record and record["remote_content_verified"] is not False:
        raise TypedAssetError("asset identity cannot claim verified remote content")
    return result


def file_identity(project_root: Path, local_path: str) -> dict:
    """Fingerprint a project-relative regular file; reuses lib.project_lock.digest."""
    root = Path(project_root)
    path = _project_path(root, local_path)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _REPARSE:
        raise TypedAssetError("file asset must not be a symlink/reparse point")
    if not stat.S_ISREG(st.st_mode):
        raise FileNotFoundError("missing local file: %s" % local_path)
    sha = digest(path)
    # Size/mtime can stay equal for a same-length rewrite (including Windows
    # timestamp publication delays). Re-read the bytes before accepting the
    # measured identity; metadata alone must not certify the earlier digest.
    confirmed_sha = digest(path)
    after = os.lstat(path)
    if confirmed_sha != sha or after.st_size != st.st_size or after.st_mtime_ns != st.st_mtime_ns \
            or (after.st_dev, after.st_ino) != (st.st_dev, st.st_ino):
        raise ConcurrentChange("file changed while hashing: %s" % local_path)
    return {"schema": ASSET_SCHEMA, "kind": "file", "algorithm": FILE_ALGO,
            "sha256": sha, "size": st.st_size,
            "local_path": str(local_path).replace("\\", "/"),
            # the same numbers under the shared typed-identity shape: derived from
            # sha256/size above, not a second truth source.
            "identity": {"algorithm": FILE_ALGO, "sha256": sha, "size": st.st_size}}


# --------------------------------------------------------------------------- #
# kind=directory  (deterministic tree manifest + copy-only snapshot)
# --------------------------------------------------------------------------- #
def directory_identity(source_root: Path, limits: DirectoryLimits | None = None) -> dict:
    """Pure, read-only tree identity. No copy, no domain inference."""
    limits = limits or DirectoryLimits()
    root = Path(source_root)
    _plain_dir(root, "source root")
    entries = _walk(root, limits)
    files = [entry for entry in entries if entry["type"] == "file"]
    return {"algorithm": DIR_ALGO, "sha256": _tree_sha(entries),
            "size": sum(entry["size"] for entry in files),
            "entry_count": len(entries), "file_count": len(files),
            "entries": entries, "content_identity_limits": list(DIRECTORY_LIMITS)}


def prepare_snapshot(source_root: Path, project_root: Path, snapshot_ref: str,
                     limits: DirectoryLimits | None = None) -> dict:
    """Copy-only snapshot into an explicit project-relative slot; never overwrites."""
    limits = limits or DirectoryLimits()
    root = Path(project_root)
    destination = _project_path(root, snapshot_ref, "snapshot_ref")
    source = Path(source_root)
    # Containment must be decided on the *final* slot, before any mkdir/staging/copy:
    # writing inside the source (or over its ancestor) would mutate the very tree we
    # are about to claim a stable identity for.  A sibling slot stays legal even when
    # the source itself lives inside the project.  Raising here (not later) is what
    # keeps this a boundary error instead of a self-inflicted ConcurrentChange.
    source_abs, destination_abs = _lexical(source), _lexical(destination)
    _plain_dir(source_abs, "source root")
    if source_abs == destination_abs:
        raise SnapshotBoundaryError(
            "snapshot slot is the source root itself; refusing to snapshot a tree "
            "into itself")
    if destination_abs.is_relative_to(source_abs):
        raise SnapshotBoundaryError(
            "snapshot slot lies inside the source tree; the copy would change the "
            "identity being measured (choose a slot outside the source)")
    if source_abs.is_relative_to(destination_abs):
        raise SnapshotBoundaryError(
            "snapshot slot is an ancestor of the source root; the copy would "
            "overwrite its own input (choose a slot outside the source)")
    if destination.exists() or destination.is_symlink():
        raise TypedAssetError("snapshot slot already exists; refusing to overwrite: %s"
                             % snapshot_ref)
    measured = directory_identity(source_abs, limits)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = destination.parent / (".typed-staging-" + uuid.uuid4().hex)
    try:
        tree = staging / "tree"
        tree.mkdir(parents=True)
        for entry in measured["entries"]:
            target = tree / entry["path"]
            if entry["type"] == "directory":
                target.mkdir(parents=True, exist_ok=True)
            else:
                try:
                    atomic_copy(source / entry["path"], target,
                                entry["sha256"], entry["size"])
                except ValueError:
                    # lib.project_lock raises ValueError when the staged copy does not
                    # match the fingerprint measured a moment ago.
                    raise ConcurrentChange("source changed during snapshot copy: %r"
                                           % entry["path"]) from None
        copied = directory_identity(tree, limits)
        if copied["sha256"] != measured["sha256"]:
            raise ConcurrentChange("source changed during snapshot copy (staged tree differs)")
        again = directory_identity(source, limits)
        if again["sha256"] != measured["sha256"]:
            raise ConcurrentChange("source changed during snapshot copy")
        record = {
            "schema": ASSET_SCHEMA, "kind": "directory",
            "identity": {key: measured[key] for key in
                         ("algorithm", "sha256", "size", "entry_count", "file_count")},
            "snapshot_ref": snapshot_ref,
            "snapshot_tree_ref": snapshot_ref + "/tree",
            "manifest_ref": snapshot_ref + "/manifest.json",
            "domain_scope": "undeclared",
            "content_identity_limits": list(DIRECTORY_LIMITS),
        }
        _atomic_json(staging / "manifest.json",
                     {"schema": MANIFEST_SCHEMA, "identity": record["identity"],
                      "entries": measured["entries"],
                      "content_identity_limits": list(DIRECTORY_LIMITS)})
        _fsync_dir(tree)
        os.replace(staging, destination)
        _fsync_dir(destination.parent)
        return record
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


ENTRY_KEYS = {"file": {"path", "type", "sha256", "size"}, "directory": {"path", "type"}}


def _check_entries(entries, project_root: Path, tree_ref: str) -> list:
    root = Path(project_root)
    if not isinstance(entries, list):
        raise TypedAssetError("tree manifest entries must be a list")
    paths = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("type") not in ENTRY_KEYS:
            raise TypedAssetError("invalid manifest entry type")
        if set(entry) != ENTRY_KEYS[entry["type"]]:
            raise TypedAssetError("manifest entry has unexpected/missing fields")
        rel = entry["path"]
        if not isinstance(rel, str):
            raise TypedAssetError("manifest entry path must be a string")
        _project_path(root, tree_ref + "/" + rel, "manifest entry path")
        if entry["type"] == "file":
            if type(entry.get("size")) is not int or entry["size"] < 0 \
                    or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256"))):
                raise TypedAssetError("manifest entry has invalid sha256/size")
        paths.append(rel)
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        raise TypedAssetError("manifest entries must be unique and sorted")
    return entries


MAX_MANIFEST_BYTES = 64 * 1024 * 1024


def _load_manifest(path: Path) -> dict:
    """Parse only our own manifest schema, with a byte bound (no unbounded read)."""
    size = path.stat().st_size
    if size > MAX_MANIFEST_BYTES:
        raise TypedAssetError("snapshot manifest too large (%d bytes)" % size)
    try:
        value = json.loads(path.read_bytes().decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise TypedAssetError("snapshot manifest is not valid UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise TypedAssetError("snapshot manifest must be a JSON object")
    return value


def verify_snapshot(project_root: Path, record: dict,
                    limits: DirectoryLimits | None = None) -> Path:
    """Re-derive the materialized tree and reject漏项/extra/伪sha/escape."""
    limits = limits or DirectoryLimits()
    root = Path(project_root)
    identity = declared_identity(record)
    if record.get("kind") != "directory":
        raise TypedAssetError("not a directory record")
    declared_sha = identity["sha256"]
    tree_ref = str(record.get("snapshot_tree_ref") or "")
    tree = _project_path(root, tree_ref, "snapshot_tree_ref")
    manifest_path = _project_path(root, str(record.get("manifest_ref") or ""),
                                  "manifest_ref")
    if not manifest_path.is_file():
        raise FileNotFoundError("missing snapshot manifest")
    manifest = _load_manifest(manifest_path)
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise TypedAssetError("snapshot manifest schema invalid")
    manifest_identity = declared_identity({"kind": "directory",
                                           "identity": manifest.get("identity")})
    if manifest_identity != identity:
        raise TypedAssetError("snapshot manifest identity does not match the asset record")
    entries = _check_entries(manifest.get("entries"), root, tree_ref)
    if _tree_sha(entries) != declared_sha:
        raise TypedAssetError("snapshot manifest sha is not the sha of its own entries")
    if not tree.is_dir():
        raise FileNotFoundError("missing snapshot tree")
    actual = directory_identity(tree, limits)
    if actual["sha256"] != declared_sha:
        recorded = {entry["path"] for entry in entries}
        present = {entry["path"] for entry in actual["entries"]}
        missing = sorted(recorded - present)
        extra = sorted(present - recorded)
        if missing:
            raise TypedAssetError("snapshot tree missing entries: %s" % ", ".join(missing[:5]))
        if extra:
            raise TypedAssetError("snapshot tree has extra files: %s" % ", ".join(extra[:5]))
        raise TypedAssetError("snapshot tree content sha mismatch (tampered bytes)")
    if any(actual[key] != identity[key] for key in identity):
        raise TypedAssetError("snapshot tree shape differs from the recorded identity")
    return tree


# --------------------------------------------------------------------------- #
# kind=url_descriptor  (static description only; zero network)
# --------------------------------------------------------------------------- #
def _manager_sensitive_check(payload: dict) -> None:
    """Reuse Manager's single detector; never echo the matched value/key."""
    try:
        import manager_state as manager
    except ImportError:  # pragma: no cover
        from Tool.scripts import manager_state as manager
    try:
        manager.reject_sensitive(payload)
    except Exception as exc:
        if type(exc).__name__ == "ManagerError":
            raise TypedAssetError(
                "URL descriptor rejected by the manager sensitive-input check "
                "(value withheld)") from None
        raise


def _reject_sensitive_descriptor(normalized: str, query: str) -> None:
    _manager_sensitive_check({"url": normalized})
    try:
        import manager_state as manager
    except ImportError:  # pragma: no cover
        from Tool.scripts import manager_state as manager
    for index, pair in enumerate([item for item in query.split("&") if item]):
        raw_key, _, raw_value = pair.partition("=")
        decoded = [raw_key, raw_value]
        try:
            decoded = [unquote(raw_key), unquote(raw_value)]
        except Exception:  # pragma: no cover - malformed percent escapes
            pass
        for candidate in {raw_key, decoded[0]}:
            # Manager's exact public numeric keys (limit_tokens/...) are not credentials
            # when the value is a valid non-negative integer; reuse its predicate.
            public_numeric = (candidate in manager.PUBLIC_NUMERIC_TOKEN_KEYS
                              and manager.public_numeric_value(decoded[1]))
            if candidate and not public_numeric \
                    and manager.SENSITIVE_KEY_RE.search(candidate):
                raise TypedAssetError("URL descriptor has a credential-style query key "
                                      "at query[%d] (key withheld)" % index)
        # the *value* is scanned by Manager's own value detector (e.g. ``Bearer …``)
        for candidate in {raw_value, decoded[1]}:
            if candidate:
                _manager_sensitive_check({"value": candidate})


def _normalized_host(host: str) -> str:
    try:
        host.encode("ascii")
        return host.lower()
    except UnicodeEncodeError:
        try:
            return host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise TypedAssetError("URL host is not a valid IDNA name") from None


def url_descriptor(value: str) -> dict:
    """Describe an http/https URL; static identity only. Makes no request."""
    text = str(value or "").strip()
    if not text:
        raise TypedAssetError("empty URL descriptor")
    if any(ch.isspace() for ch in text):
        raise TypedAssetError("URL descriptor must not contain whitespace")
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise TypedAssetError("only http/https URLs can be described (scheme=%r)" % scheme)
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise TypedAssetError("URL userinfo/credentials are not allowed in a descriptor")
    host = parts.hostname or ""
    if not host:
        raise TypedAssetError("URL descriptor needs a host")
    try:
        port = parts.port
    except ValueError:
        raise TypedAssetError("URL descriptor has an invalid port") from None
    default_port = 443 if scheme == "https" else 80
    netloc = _normalized_host(host)
    if ":" in netloc:
        netloc = "[%s]" % netloc
    if port is not None and port != default_port:
        netloc = "%s:%d" % (netloc, port)
    normalized = urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))
    _reject_sensitive_descriptor(normalized, parts.query)
    payload = {"schema": URL_SCHEMA, "url": normalized, "scheme": scheme,
               "host": netloc, "port": port if port is not None else default_port,
               "path": parts.path, "query": parts.query, "fragment": parts.fragment}
    return {"schema": ASSET_SCHEMA, "kind": "url_descriptor", "url": normalized,
            "descriptor": payload,
            "identity": {"algorithm": URL_ALGO,
                         "sha256": hashlib.sha256(_canonical(payload)).hexdigest(),
                         "size": len(normalized.encode("utf-8"))},
            "identity_scope": "descriptor-only",
            "remote_content_verified": False,
            "content_identity_limits": list(URL_LIMITS)}


REMOTE_CLAIM_FIELDS = ("response_sha256", "remote_content_sha256", "content_sha256",
                       "etag", "last_modified", "status_code", "response_headers")


def verify_url_descriptor(record: dict) -> dict:
    """Prove the record only describes text; a remote-content hash is a hard error."""
    identity = declared_identity(record)
    if record.get("kind") != "url_descriptor":
        raise TypedAssetError("not a url_descriptor record")
    for field in REMOTE_CLAIM_FIELDS:
        if field in record:
            raise TypedAssetError(
                "url_descriptor must not carry remote observation field %r "
                "(that belongs to a separate observation record)" % field)
    if record.get("remote_content_verified"):
        raise TypedAssetError("url_descriptor cannot claim verified remote content")
    recomputed = url_descriptor(record.get("url", ""))
    if recomputed["url"] != record.get("url"):
        raise TypedAssetError("URL descriptor is not in normalized form")
    if recomputed["identity"]["sha256"] != identity["sha256"]:
        raise TypedAssetError("URL descriptor sha mismatch (identity does not match text)")
    if recomputed["identity"] != identity:
        raise TypedAssetError("URL descriptor size mismatch (identity does not match text)")
    if not isinstance(record.get("descriptor"), dict) \
            or _canonical(record["descriptor"]) != _canonical(recomputed["descriptor"]):
        raise TypedAssetError("URL descriptor payload does not match verified text")
    return {"ok": True, "kind": "url_descriptor",
            "identity_sha256": recomputed["identity"]["sha256"],
            "remote_content_verified": False}


# --------------------------------------------------------------------------- #
# selection / dispatch interfaces (no guessing, no auto-first-file)
# --------------------------------------------------------------------------- #
def build_snapshot(assets: list, primary_asset_id: str | None = None,
                   auxiliary_asset_ids=(), action_target_asset_id: str | None = None) -> dict:
    """Declare which asset plays which role. Never infers a primary."""
    if not isinstance(assets, list):
        raise TypedAssetError("snapshot assets must be a list")
    if not isinstance(auxiliary_asset_ids, (list, tuple)):
        raise TypedAssetError("auxiliary_asset_ids must be a list or tuple")
    cleaned = []
    seen = set()
    for asset in assets:
        if not isinstance(asset, dict):
            raise TypedAssetError("snapshot asset must be an object")
        asset_id = asset.get("asset_id")
        if not isinstance(asset_id, str) or not ID_RE.fullmatch(asset_id):
            raise TypedAssetError("invalid asset_id: %r" % asset_id)
        if asset_id in seen:
            raise TypedAssetError("duplicate asset_id: %s" % asset_id)
        seen.add(asset_id)
        identity = declared_identity(asset)
        cleaned.append(dict(asset, identity=identity))
    if any(not isinstance(item, str) or not ID_RE.fullmatch(item)
           for item in auxiliary_asset_ids):
        raise TypedAssetError("auxiliary asset_id invalid")
    auxiliary = sorted(set(auxiliary_asset_ids))
    for item in auxiliary:
        if item not in seen:
            raise TypedAssetError("auxiliary asset_id not in snapshot: %s" % item)
    if primary_asset_id is not None and (not isinstance(primary_asset_id, str)
                                         or primary_asset_id not in seen):
        raise TypedAssetError("primary asset_id not in snapshot")
    if action_target_asset_id is not None and (not isinstance(action_target_asset_id, str)
                                               or action_target_asset_id not in seen):
        raise TypedAssetError("action_target asset_id not in snapshot")
    if primary_asset_id and primary_asset_id in auxiliary:
        raise TypedAssetError("an asset cannot be both primary and auxiliary")
    return {"schema": SNAPSHOT_SCHEMA, "assets": sorted(cleaned, key=lambda a: a["asset_id"]),
            "primary_asset_id": primary_asset_id,
            "auxiliary_asset_ids": auxiliary,
            "action_target_asset_id": action_target_asset_id,
            "domain_scope": "undeclared"}


def validate_selection(snapshot: dict, requested_asset_id: str, role: str,
                       allowed_kinds=None) -> dict:
    """Bind one asset to one role by exact id; auxiliary sha never stands in for primary."""
    if not isinstance(snapshot, dict) or snapshot.get("schema") != SNAPSHOT_SCHEMA:
        raise TypedAssetError("not a typed snapshot")
    snapshot = build_snapshot(snapshot.get("assets"), snapshot.get("primary_asset_id"),
                              snapshot.get("auxiliary_asset_ids", []),
                              snapshot.get("action_target_asset_id"))
    if role not in ROLES:
        raise TypedAssetError("unknown role %r (expected one of %s)"
                              % (role, ", ".join(ROLES)))
    assets = {asset.get("asset_id"): asset for asset in snapshot.get("assets") or []}
    asset = assets.get(str(requested_asset_id))
    if asset is None:
        raise TypedAssetError("asset_id %r is not declared in the snapshot; "
                              "refusing to fall back to another asset"
                              % (requested_asset_id,))
    declared = {"primary": snapshot.get("primary_asset_id"),
                "auxiliary": list(snapshot.get("auxiliary_asset_ids") or []),
                "action_target": snapshot.get("action_target_asset_id")}
    if role == "auxiliary":
        if asset["asset_id"] not in declared["auxiliary"]:
            raise TypedAssetError("asset %s is not declared as auxiliary" % asset["asset_id"])
    elif not declared[role]:
        raise TypedAssetError("snapshot declares no %s asset; refusing to guess "
                              "(the first asset is never used implicitly)" % role)
    elif declared[role] != asset["asset_id"]:
        raise TypedAssetError("asset %s is not the declared %s asset"
                              % (asset["asset_id"], role))
    if allowed_kinds is not None:
        allowed = tuple(allowed_kinds)
        if asset["kind"] not in allowed:
            raise TypedAssetError("action for role %s does not accept kind %r "
                                  "(allowed: %s); a file parser must refuse "
                                  "directory/URL descriptors"
                                  % (role, asset["kind"], ", ".join(allowed)))
    return {"ok": True, "asset_id": asset["asset_id"], "kind": asset["kind"],
            "role": role, "identity_sha256": asset["identity"]["sha256"],
            "identity_size": asset["identity"]["size"],
            "snapshot_ref": asset.get("snapshot_ref")}


def verify_target(project_root: Path, record: dict) -> dict:
    """Dispatch verification by explicit kind; unknown kinds are rejected, not file-ified."""
    identity = declared_identity(record)
    kind = record["kind"]
    if kind == "file":
        measured = file_identity(Path(project_root), record.get("local_path"))
        if measured["identity"] != identity:
            raise TypedAssetError("local file fingerprint mismatch")
        path = _project_path(Path(project_root), record.get("local_path"))
        return {"ok": True, "kind": "file", "identity_sha256": identity["sha256"], "path": path}
    if kind == "directory":
        tree = verify_snapshot(Path(project_root), record)
        return {"ok": True, "kind": "directory",
                "identity_sha256": record["identity"]["sha256"], "path": tree}
    if kind == "url_descriptor":
        value = verify_url_descriptor(record)
        return {"ok": True, "kind": "url_descriptor",
                "identity_sha256": value["identity_sha256"], "path": None}
    raise TypedAssetError("unknown asset kind %r; refusing to treat it as a file" % (kind,))
