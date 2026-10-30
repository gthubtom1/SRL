#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Long-lived project state for Seep-Reverse-Lab.

The project ledger is portable metadata.  Target identity is represented by
hash, size, and a project-relative local_path.  source_path and source_host
are local execution metadata only and are never used as target identity.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import socket
import stat
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath

from lib.project_lock import atomic_copy, project_file, project_lock, project_locked, verify_file
from lib import typed_assets as T

PROJECT_SCHEMA = "seep-project/1"
ASSET_SCHEMA = "seep-asset/1"
VERSION_SCHEMA = "seep-version/1"
RUN_SCHEMA = "seep-run/1"
MIGRATION_SCHEMA = "seep-migration/1"
HANDOFF_SCHEMA = "seep-handoff/1"
FACTS_SCHEMA = "seep-project-facts/1"
EVIDENCE_SCHEMA = "seep-evidence/1"
ACCEPTANCE_SCHEMA = "seep-acceptance/1"
ACCEPTANCE_SNAPSHOT_SCHEMA = "seep-acceptance-snapshot/1"
CLOSURE_SEAL_SCHEMA = "seep-closure-seal/1"

RUN_END_STATUSES = ("completed", "failed", "blocked", "cancelled")
MIGRATION_STATUSES = ("planned", "partial", "completed", "blocked")
EVIDENCE_KINDS = ("artifact", "evidence")
ACCEPTANCE_RESULTS = ("pass", "fail", "unknown", "skipped")
ACCEPTANCE_STATUSES = ("pending", "pass", "fail", "unknown", "skipped")
PROOF_LEVEL = "structural+recorded_witness"
PROOF_LIMITS = (
    "登记只证明文件在项目内存在，且 sha256/大小与声明一致（structural）",
    "pass 只记录外部已执行检查的有来源见证（recorded_witness），不证明日志语义或功能真实成功",
    "CLI 不执行目标、不解析日志语义，不把 exit0 或非空文件当作功能成功",
    "本地完整性/一致性防错：不含私钥签名，不承诺抵御有意的一致多文件重写",
)
METADATA_NAMES = frozenset(("project.json", "facts.jsonl", "handoff.json", "version.json",
                            "manifest.json", "acceptance.json", "run.json", "migration.json",
                            "reverse-baseline.json", "asset.json"))
UNRESOLVED_ALIGN_KEYS = ("missing", "multi", "manual", "needs_manual")
ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fail(stage: str, reason: str) -> int:
    print(json.dumps({"ok": False, "blocked_at": stage, "reason": reason}, ensure_ascii=False))
    return 2


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def file_fingerprint(path: Path) -> dict:
    return {"sha256": sha256_file(str(path)), "size": path.stat().st_size}


def target_identity_fields(record: dict) -> dict:
    """Return the compatibility fingerprint plus the explicit typed identity."""
    if not isinstance(record, dict):
        raise ValueError("target record must be an object")
    value = dict(record)
    value.setdefault("kind", "file")
    identity = T.declared_identity(value)
    kind = value["kind"]
    return {"kind": kind, "sha256": identity["sha256"], "size": identity["size"],
            "identity_scope": {"file": "raw-bytes", "directory": "tree-content",
                               "url_descriptor": "descriptor-only"}[kind],
            "remote_content_verified": False}


def verify_target(root: Path, record: dict) -> dict:
    """The shared target verifier: explicit kind dispatch, never implicit file fallback."""
    if not isinstance(record, dict):
        raise ValueError("target record must be an object")
    value = dict(record)
    kind = value.get("kind", "file")
    value["kind"] = kind
    if kind not in T.KINDS:
        raise ValueError("unknown target kind %r; refusing to treat it as a file" % kind)
    identity = value.get("identity") if isinstance(value.get("identity"), dict) else {}
    if kind == "file":
        value.setdefault("sha256", identity.get("sha256"))
        value.setdefault("size", identity.get("size"))
        value.setdefault("local_path", record.get("local_path"))
        checked = T.verify_target(Path(root), value)
        path = checked.get("path")
    else:
        checked = T.verify_target(Path(root), value)
        path = checked.get("path")
    fields = target_identity_fields(value)
    return {"ok": True, **fields, "path": (str(path) if path is not None else None),
            "local_path": value.get("local_path"),
            "snapshot_ref": value.get("snapshot_ref"),
            "snapshot_tree_ref": value.get("snapshot_tree_ref"),
            "manifest_ref": value.get("manifest_ref"),
            "url": value.get("url")}


def target_fingerprint(root: Path, record: dict) -> dict:
    """Verify and expose a target fingerprint without changing legacy sha/size callers."""
    return verify_target(root, record)


def _typed_record_fields(record: dict, source_path: str | None = None) -> dict:
    fields = target_identity_fields(record)
    kind = fields["kind"]
    identity = dict(record.get("identity") or {})
    result = {"kind": kind, "identity": identity,
              "identity_scope": fields["identity_scope"],
              "remote_content_verified": fields["remote_content_verified"],
              "sha256": fields["sha256"], "size": fields["size"],
              "target_sha256": fields["sha256"], "target_size": fields["size"],
              "local_path": record.get("local_path"),
              "source_path": source_path, "source_host": None}
    for key in ("url", "descriptor", "snapshot_ref", "snapshot_tree_ref", "manifest_ref",
                "content_identity_limits", "domain_scope"):
        if key in record:
            result[key] = record[key]
    return result


def _directory_input(source: Path, root: Path, snapshot_ref: str,
                     materialize: bool = True) -> dict:
    if materialize:
        return T.prepare_snapshot(source, root, snapshot_ref)
    destination = project_file(root, snapshot_ref)
    source_path = source.absolute()
    if destination == source_path or destination.is_relative_to(source_path) \
            or source_path.is_relative_to(destination):
        raise T.SnapshotBoundaryError("snapshot slot overlaps the source tree")
    measured = T.directory_identity(source)
    return {"kind": "directory",
            "identity": {k: measured[k] for k in
                         ("algorithm", "sha256", "size", "entry_count", "file_count")},
            "snapshot_ref": snapshot_ref, "snapshot_tree_ref": snapshot_ref + "/tree",
            "manifest_ref": snapshot_ref + "/manifest.json", "domain_scope": "undeclared",
            "content_identity_limits": list(T.DIRECTORY_LIMITS)}


def _target_from_input(root: Path, version: str, target: str,
                       materialize: bool = True) -> dict:
    text = str(target or "")
    if text.lower().startswith(("http://", "https://")):
        descriptor = T.url_descriptor(text)
        return _typed_record_fields(descriptor)
    source = Path(os.path.abspath(os.path.expanduser(text)))
    if source.is_dir():
        record = _directory_input(source, root, "versions/%s/target" % version, materialize)
        record["local_path"] = record["snapshot_tree_ref"]
        return _typed_record_fields(record, str(source))
    if not source.is_file():
        raise FileNotFoundError("目标不存在")
    st = os.lstat(source)
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise ValueError("file target must be a regular non-link file")
    sha = sha256_file(str(source))
    record = {"kind": "file", "sha256": sha, "size": st.st_size,
              "identity": {"algorithm": T.FILE_ALGO, "sha256": sha, "size": st.st_size},
              "local_path": "versions/%s/target/%s" % (version, source.name)}
    if materialize:
        atomic_copy(source, project_file(root, record["local_path"]), sha, st.st_size)
    return _typed_record_fields(record, str(source))



def _fsync_dir(path: Path) -> None:
    # Directory fsync is not available on every supported platform.
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".seep-project-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def atomic_bytes(path: Path, data: bytes) -> None:
    """Durably replace a file with exact bytes (immutable revision archives)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".seep-project-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def atomic_json(path: Path, value: dict) -> None:
    atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def metadata_transaction(root: Path, paths: list[Path], *, directories=()):
    """Group known destinations and empty directories while holding project_lock."""
    from lib.project_transaction import file_transaction
    return file_transaction(root, [p.relative_to(root).as_posix() for p in paths],
                            directories=[p.relative_to(root).as_posix() for p in directories])


def append_jsonl(path: Path, value: dict) -> None:
    """Append one fsynced record; an interrupted write is later reported."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(str(path), os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o644)
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(fd, payload[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)


def project_root(value: str) -> Path:
    return Path(os.path.abspath(value))


def require_id(value: str, label: str) -> str:
    if not value or value in (".", "..") or any(c not in ID_CHARS for c in value):
        raise ValueError("%s 只能包含字母、数字、点、连字符和下划线：%s" % (label, value))
    return value


def relative_ref(value: str, label: str = "local_path") -> str:
    text = str(value).replace("\\", "/")
    path = PurePosixPath(text)
    if not text or path.is_absolute() or ".." in path.parts:
        raise ValueError("%s 必须是项目内相对路径：%s" % (label, value))
    return path.as_posix()


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON 对象无效：%s" % path)
    return value


def require_project(root: Path) -> dict:
    p = project_file(root, "project.json")
    if not p.is_file():
        raise FileNotFoundError("缺少 project.json：%s" % p)
    data = load_json(p)
    if data.get("schema") != PROJECT_SCHEMA:
        raise ValueError("project.json schema 不是 %s" % PROJECT_SCHEMA)
    require_id(str(data.get("project_id", "")), "project_id")
    return data


def write_event(root: Path, event_type: str, message: str, version: str = "", run: str = "",
                extra: dict | None = None) -> dict:
    """Append one fact event; ``extra`` adds bindings (e.g. closure_sha256).

    Reserved identity keys can never be overwritten through ``extra``: the
    append-only ledger stays the independent witness for the closure seal.
    """
    project = require_project(root)
    event = {"schema": FACTS_SCHEMA, "id": "E-" + uuid.uuid4().hex[:12],
             "kind": "event", "type": event_type, "message": message,
             "project_id": project["project_id"],
             "version_id": version or None, "run_id": run or None,
             "created_at": now()}
    for key, value in (extra or {}).items():
        if key not in event:
            event[key] = value
    _validate_fact(event, project["project_id"])
    append_jsonl(project_file(root, "facts.jsonl"), event)
    return event


def _local_metadata(source_path: str) -> dict:
    return {"source_path": source_path, "source_host": socket.gethostname()}


def _asset_record(root: Path, asset_id: str) -> dict:
    require_id(asset_id, "asset_id")
    path = project_file(root, "assets/%s/asset.json" % asset_id)
    if not path.is_file():
        raise FileNotFoundError("asset 不存在：%s" % asset_id)
    data = load_json(path)
    if data.get("schema") != ASSET_SCHEMA or data.get("asset_id") != asset_id:
        raise ValueError("asset.json 身份无效：%s" % path)
    return data


def _select_assets(root: Path, asset_ids: list[str], primary_asset_id: str = "",
                   auxiliary_asset_ids=()) -> dict:
    """Resolve roles explicitly; the first asset is never a hidden primary."""
    ids = []
    for value in asset_ids or []:
        value = require_id(value, "asset_id")
        if value not in ids:
            ids.append(value)
    records = {asset_id: _asset_record(root, asset_id) for asset_id in ids}
    for asset_id, record in records.items():
        verify_target(root, record)
    if primary_asset_id:
        primary_asset_id = require_id(primary_asset_id, "primary_asset_id")
        if primary_asset_id not in records:
            raise ValueError("primary_asset_id 不在当前版本资产中")
    candidates = [asset_id for asset_id in ids if records[asset_id].get("role") == "primary"]
    if primary_asset_id and candidates and candidates != [primary_asset_id]:
        raise ValueError("primary asset role conflicts with explicit primary_asset_id")
    if not primary_asset_id:
        if len(candidates) == 1:
            primary_asset_id = candidates[0]
        elif len(ids) == 1 and records[ids[0]].get("role") != "auxiliary":
            primary_asset_id = ids[0]
        elif len(ids) > 1 and any(records[value].get("role") != "auxiliary" for value in ids):
            raise ValueError("多资产必须显式指定唯一 primary_asset_id；拒绝按排序取首项")
    if len(candidates) > 1 and candidates != [primary_asset_id]:
        raise ValueError("多资产声明了多个 primary")
    auxiliary = [require_id(x, "auxiliary_asset_id") for x in (auxiliary_asset_ids or []) if x]
    if any(x not in records for x in auxiliary):
        raise ValueError("auxiliary_asset_id 不在当前版本资产中")
    if primary_asset_id and primary_asset_id in auxiliary:
        raise ValueError("primary 不能同时是 auxiliary")
    if not auxiliary:
        auxiliary = [x for x in ids if x != primary_asset_id]
    return {"primary": records.get(primary_asset_id), "primary_asset_id": primary_asset_id,
            "auxiliary_asset_ids": auxiliary, "records": records}
def _target_fields(root: Path, asset_ids: list[str], version: str,
                   target_path: str = "", target_fingerprint: dict | None = None,
                   primary_asset_id: str = "", auxiliary_asset_ids=()) -> dict:
    if target_path:
        return _target_from_input(root, version, target_path)
    if target_fingerprint:
        return _typed_record_fields(target_fingerprint,
                                    target_fingerprint.get("source_path"))
    selected = _select_assets(root, asset_ids, primary_asset_id, auxiliary_asset_ids)
    if selected["primary"]:
        return _typed_record_fields(selected["primary"])
    # A version without a supplied target still has a stable relative file slot.
    local_path = relative_ref("versions/%s/target" % version)
    return {"kind": "file", "identity": {}, "identity_scope": "raw-bytes",
            "remote_content_verified": False, "sha256": None, "size": None,
            "target_sha256": None, "target_size": None, "local_path": local_path,
            "source_path": None, "source_host": None}


def _check_reverse_identity(root: Path, version: str, fingerprint: dict, parent: str = "") -> str:
    path = root / "versions" / version / "reverse-baseline.json"
    if not path.exists():
        return parent
    baseline = load_json(path)
    if baseline.get("schema") not in ("seep-reverse-baseline/1", "seep-migration/1") or baseline.get("version") != version:
        raise ValueError("reverse baseline 身份无效")
    if any(baseline.get("binary", {}).get(k) != fingerprint.get(k) for k in ("sha256", "size")):
        raise ValueError("reverse baseline 与版本目标不匹配")
    if parent and baseline.get("parent_version") != parent:
        raise ValueError("reverse baseline parent 不匹配")
    registered_parent = baseline.get("parent_version") or ""
    if registered_parent:
        require_id(registered_parent, "parent")
    return parent or registered_parent


def _initialize_staged(root: Path, a, project: dict, ts: str) -> None:
    """Stage beside the project, then journal every published file and directory.

    Existing inputs (including a reverse baseline) are never replaced. Unknown
    staging remnants after process exit remain outside the project and untouched.
    """
    with tempfile.TemporaryDirectory(prefix=".seep-init-", dir=root.parent) as temporary:
        staged = Path(temporary)
        baseline_ref = "versions/%s/reverse-baseline.json" % a.version
        baseline = project_file(root, baseline_ref)
        if baseline.exists():
            atomic_bytes(staged / baseline_ref, baseline.read_bytes())
        atomic_json(staged / "project.json", project)
        atomic_text(staged / "scope.md", "# 项目边界\n\n- 项目：%s\n- 创建时间：%s\n\n## 客户原话\n\n" % (project["title"], ts))
        append_jsonl(staged / "facts.jsonl", {"schema": FACTS_SCHEMA, "kind": "state",
                                             "project_id": a.project_id, "status": "active",
                                             "created_at": ts})
        for name in ("assets", "versions", "reports"):
            (staged / name).mkdir(exist_ok=True)
        if a.target:
            add_asset(staged, a.asset_id, a.target, a.version, a.force, parent=a.parent)
        else:
            ensure_version(staged, a.version, a.parent, [], a.force)
        write_handoff(staged)
        files = [p for p in staged.rglob("*") if p.is_file()
                 and p.relative_to(staged).as_posix() != baseline_ref]
        # Publish the project marker last; never overwrite unowned metadata.
        files.sort(key=lambda p: (p.name == "project.json", p.relative_to(staged).as_posix()))
        for source in files:
            destination = project_file(root, source.relative_to(staged).as_posix())
            if destination.exists() or destination.is_symlink():
                raise ValueError("init refuses existing output: %s" % destination.relative_to(root))
        directories = [project_file(root, p.relative_to(staged).as_posix())
                       for p in sorted((p for p in staged.rglob("*") if p.is_dir()),
                                       key=lambda p: len(p.parts))]
        destinations = [project_file(root, p.relative_to(staged).as_posix()) for p in files]
        with metadata_transaction(root, destinations, directories=directories):
            for destination in directories:
                destination.mkdir(exist_ok=True)
            for source, destination in zip(files, destinations):
                os.replace(source, destination)
                _fsync_dir(destination.parent)
            # Include any pre-existing report/baseline context in the projection.
            write_handoff(root)


@project_locked("project", recover=True)
def cmd_init(a) -> int:
    root = project_root(a.project)
    if (root / "project.json").exists():
        return fail("init", "项目已存在；--force 也不能重置 scope、验收或历史")
    try:
        require_id(a.project_id, "project-id")
        require_id(a.version, "version")
        if a.target:
            require_id(a.asset_id, "asset-id")
        if a.parent:
            require_id(a.parent, "parent")
        if a.target:
            if str(a.target).lower().startswith(("http://", "https://")):
                T.url_descriptor(a.target)
            else:
                target = Path(os.path.abspath(os.path.expanduser(a.target)))
                if not target.exists() or (not target.is_file() and not target.is_dir()):
                    return fail("init", "目标不存在或类型不支持")
                if target.is_file():
                    st = os.lstat(target)
                    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                        return fail("init", "file target must be a regular non-link file")
                    a.parent = _check_reverse_identity(root, a.version,
                                                       file_fingerprint(target), a.parent)
                else:
                    _directory_input(target, root, "assets/%s/snapshot" % a.asset_id, False)
        if (root / "scope.md").exists() or (root / "facts.jsonl").exists():
            return fail("init", "已有 scope/facts，拒绝覆盖；请先恢复已有项目")
        manifest_path = root / "versions" / a.version / "manifest.json"
        if manifest_path.exists():
            return fail("init", "已有 manifest，拒绝覆盖；请先恢复已有版本")
        ts = now()
        project = {"schema": PROJECT_SCHEMA, "project_id": a.project_id,
                   "title": a.title or a.project_id,
                   "domains": [x for x in a.domain.split(",") if x],
                   "status": "active", "created_at": ts, "updated_at": ts,
                   "current_version_id": a.version}
        root.mkdir(parents=True, exist_ok=True)
        _initialize_staged(root, a, project, ts)
        print(json.dumps({"ok": True, "project": str(root), "project_id": a.project_id,
                          "version": a.version, "handoff": "handoff.json"}, ensure_ascii=False))
        return 0
    except Exception as exc:
        return fail("init", "%s: %s" % (type(exc).__name__, exc))


def add_asset(root: Path, asset_id: str, target: str, version: str, force: bool,
              parent: str = "", role: str = "primary", *, materialize=None) -> dict:
    """Write inside the caller's registration transaction or unpublished init stage."""
    require_id(asset_id, "asset_id")
    require_id(version, "version")
    if role not in ("primary", "auxiliary"):
        raise ValueError("asset role must be primary or auxiliary")
    text = str(target or "")
    path = project_file(root, "assets/%s/asset.json" % asset_id)
    if text.lower().startswith(("http://", "https://")):
        typed = T.url_descriptor(text)
        data = {"schema": ASSET_SCHEMA, "asset_id": asset_id, "kind": "url_descriptor",
                "logical_name": typed["url"], "role": role, **typed,
                "created_at": now()}
        data["schema"] = ASSET_SCHEMA
    else:
        source = Path(os.path.abspath(os.path.expanduser(text)))
        if source.is_dir():
            typed = _directory_input(source, root, "assets/%s/snapshot" % asset_id, False)
            typed["local_path"] = typed["snapshot_tree_ref"]
            data = {"schema": ASSET_SCHEMA, "asset_id": asset_id,
                    "logical_name": source.name, "role": role,
                    **_typed_record_fields(typed, str(source)), "created_at": now()}
        elif source.is_file():
            st = os.lstat(source)
            if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                raise ValueError("file asset must be a regular non-link file")
            sha = sha256_file(str(source))
            data = {"schema": ASSET_SCHEMA, "asset_id": asset_id, "kind": "file",
                    "logical_name": source.name, "role": role,
                    "sha256": sha, "size": st.st_size,
                    "identity": {"algorithm": T.FILE_ALGO, "sha256": sha, "size": st.st_size},
                    "identity_scope": "raw-bytes", "remote_content_verified": False,
                    "local_path": relative_ref("assets/%s/content/%s" % (asset_id, source.name)),
                    **_local_metadata(str(source)), "created_at": now()}
        else:
            raise FileNotFoundError("目标不存在")
    if path.exists():
        old = load_json(path)
        if force or target_identity_fields(old).get("sha256") != target_identity_fields(data).get("sha256") \
                or old.get("kind") != data.get("kind"):
            raise ValueError("asset_id 已存在；拒绝替换或 force 重置")
        verify_target(root, old)
        data = old
    vpath = project_file(root, "versions/%s/version.json" % version)
    existing = _validate_version(root, version, require_project(root)["project_id"]) if vpath.exists() else None
    if parent:
        require_id(parent, "parent")
    if existing:
        if existing.get("schema") != VERSION_SCHEMA or existing.get("version_id") != version:
            raise ValueError("version.json 身份无效")
        if force:
            raise ValueError("已有版本拒绝 --force；保留 manifest、验收和历史")
        if parent and parent != existing.get("parent_version_id"):
            raise ValueError("已有版本 parent 不可更换")
        if existing.get("sha256"):
            verify_target(root, existing)
        registered = _select_assets(root, existing.get("asset_ids") or [],
                                    existing.get("primary_asset_id") or "",
                                    existing.get("auxiliary_asset_ids") or [])
        if role == "primary" and registered["primary_asset_id"] and registered["primary_asset_id"] != asset_id:
            raise ValueError("已有版本 primary 身份不可替换；请登记为 auxiliary")
        _validate_manifest(root, version, existing["project_id"])
    elif any((root / "versions" / version / name).exists()
             for name in ("manifest.json", "acceptance.json")):
        raise ValueError("已有 manifest/acceptance，拒绝覆盖孤立版本元数据")
    if role == "primary" and (not existing or not existing.get("primary_asset_id")
                              or existing.get("primary_asset_id") == asset_id):
        parent = _check_reverse_identity(root, version, target_identity_fields(data), parent)
    if existing and existing.get("sha256") and asset_id not in (existing.get("asset_ids") or []) \
            and role == "primary":
        if existing.get("kind", "file") != data.get("kind") or existing.get("sha256") != data.get("sha256"):
            raise ValueError("已有版本 primary 目标不可替换；请把新材料登记为 auxiliary")
    if existing and not existing.get("sha256") and role == "primary":
        _unbound_acceptance(root, version, existing["project_id"])
    if not path.exists():
        if materialize is not None:
            materialize(data)
        elif data["kind"] == "directory":
            copied = _directory_input(source, root, "assets/%s/snapshot" % asset_id)
            if copied["identity"] != data["identity"]:
                raise T.ConcurrentChange("source changed before asset registration")
        elif data["kind"] == "file":
            atomic_copy(source, project_file(root, data["local_path"]),
                        data["sha256"], data["size"])
    verify_target(root, data)
    atomic_json(path, data)
    primary = (existing or {}).get("primary_asset_id") or (asset_id if role == "primary" and not existing else "")
    if existing and not (existing.get("asset_ids") or []) and role == "primary":
        primary = asset_id
    auxiliary = list((existing or {}).get("auxiliary_asset_ids") or [])
    if existing and asset_id not in (existing.get("asset_ids") or []) and asset_id != primary:
        auxiliary.append(asset_id)
    ensure_version(root, version, parent, list((existing or {}).get("asset_ids") or []) + [asset_id],
                   force, primary_asset_id=primary, auxiliary_asset_ids=auxiliary)
    return data



def _unbound_acceptance(root: Path, version: str, project_id: str) -> dict:
    data = load_acceptance(root, version, project_id)
    if (data.get("target_sha256") is not None or data.get("items") != []
            or _acceptance_defined_data(data) or _acceptance_presence_markers(root, version)
            or _chain_log_path(root, version).exists()):
        raise ValueError("首次绑定目标只允许未定义的空验收占位；已有验收请创建新版本")
    return data


def ensure_version(root: Path, version: str, parent: str, asset_ids: list[str], force: bool,
                   target_path: str = "", primary_asset_id: str = "",
                   auxiliary_asset_ids=(), *, materialize=None) -> dict:
    """Write inside the caller's registration transaction or unpublished init stage."""
    require_id(version, "version")
    if parent:
        require_id(parent, "parent")
    asset_ids = list(dict.fromkeys(require_id(x, "asset_id") for x in (asset_ids or []) if x))
    selected = _select_assets(root, asset_ids, primary_asset_id, auxiliary_asset_ids)
    candidate = _target_from_input(root, version, target_path, False) if target_path else selected.get("primary")
    if candidate:
        parent = _check_reverse_identity(root, version,
                                         {"sha256": target_identity_fields(candidate)["sha256"],
                                          "size": target_identity_fields(candidate)["size"]}, parent)
    path = project_file(root, "versions/%s/version.json" % version)
    vroot = path.parent
    if path.exists():
        data = _validate_version(root, version, require_project(root)["project_id"])
        if data.get("schema") != VERSION_SCHEMA or data.get("version_id") != version:
            raise ValueError("version.json 身份无效：%s" % path)
        if force:
            raise ValueError("已有版本拒绝 --force；保留 manifest、验收和历史")
        if parent and parent != data.get("parent_version_id"):
            raise ValueError("已有版本 parent 不可更换")
        if data.get("sha256"):
            verify_target(root, data)
        merged_assets = list(dict.fromkeys(list(data.get("asset_ids") or []) + asset_ids))
        old_primary = _select_assets(root, data.get("asset_ids") or [],
                                     data.get("primary_asset_id") or "",
                                     data.get("auxiliary_asset_ids") or [])["primary_asset_id"]
        requested_primary = primary_asset_id or old_primary
        if old_primary and requested_primary and old_primary != requested_primary:
            raise ValueError("已有版本 primary 身份不可替换")
        selected = _select_assets(root, merged_assets, requested_primary, auxiliary_asset_ids)
        if candidate and data.get("sha256"):
            new_fields = target_identity_fields(candidate)
            old_fields = target_identity_fields(data)
            if new_fields["kind"] != old_fields["kind"] or new_fields["sha256"] != old_fields["sha256"]:
                raise ValueError("已有版本目标不可更换；请创建新版本")
        target = {}
        placeholder = None
        if candidate and not data.get("sha256"):
            placeholder = _unbound_acceptance(root, version, data["project_id"])
            target = ((materialize(candidate) if materialize is not None
                       else _target_from_input(root, version, target_path)) if target_path
                      else _typed_record_fields(candidate))
        changed = (data.get("asset_ids") != merged_assets or
                   data.get("primary_asset_id") != selected["primary_asset_id"] or
                   data.get("auxiliary_asset_ids") != selected["auxiliary_asset_ids"])
        data["asset_ids"] = merged_assets
        data["primary_asset_id"] = selected["primary_asset_id"]
        data["auxiliary_asset_ids"] = selected["auxiliary_asset_ids"]
        for key, value in target.items():
            if data.get(key) != value:
                data[key] = value
                changed = True
        if changed:
            manifest = _validate_manifest(root, version, data["project_id"])
            manifest["assets"] = merged_assets
            updates = [(path, data), (vroot / "manifest.json", manifest)]
            if placeholder is not None:
                placeholder["target_sha256"] = data["sha256"]
                updates.append((_acceptance_path(root, version), placeholder))
            for p, value in updates:
                atomic_json(p, value)
        return data
    if (vroot / "manifest.json").exists() or (vroot / "acceptance.json").exists():
        raise ValueError("已有 manifest/acceptance，拒绝覆盖孤立版本元数据")
    project = require_project(root)
    target = ((materialize(candidate) if materialize is not None
               else _target_from_input(root, version, target_path)) if target_path
              else _typed_record_fields(selected["primary"]) if selected["primary"]
              else _target_fields(root, [], version))
    for d in ("runs", "reports", "artifacts", "target"):
        (vroot / d).mkdir(parents=True, exist_ok=True)
    data = {"schema": VERSION_SCHEMA, "project_id": project["project_id"],
            "version_id": version, "label": version, "parent_version_id": parent or None,
            "asset_ids": asset_ids, "primary_asset_id": selected["primary_asset_id"],
            "auxiliary_asset_ids": selected["auxiliary_asset_ids"], "status": "active",
            "created_at": now(), "updated_at": now(), **target}
    atomic_json(path, data)
    atomic_json(vroot / "acceptance.json", {"schema": "seep-acceptance/1",
                                             "project_id": data["project_id"],
                                             "version_id": version,
                                             "target_sha256": target.get("sha256"),
                                             "items": []})
    atomic_json(vroot / "manifest.json", {"schema": "seep-version-manifest/1",
                                           "project_id": project["project_id"],
                                           "version_id": version, "assets": asset_ids,
                                           "artifacts": []})
    return data


@contextlib.contextmanager
def _registration_transaction(root: Path, version: str, target: str = "", asset_id: str = ""):
    """Freeze new material beside the project before declaring the full write set.

    Only the prepared, enumerated files are published under the durable journal.
    A source change cannot add unjournaled files during the project mutation.
    """
    require_id(version, "version")
    if asset_id:
        require_id(asset_id, "asset_id")
    vroot = project_file(root, "versions/%s" % version)
    project = require_project(root)
    existing = (_validate_version(root, version, project["project_id"])
                if (vroot / "version.json").exists() else None)
    asset_path = project_file(root, "assets/%s/asset.json" % asset_id) if asset_id else None
    needs_material = bool(target) and (not asset_path.exists() if asset_path is not None
                                      else not existing or not existing.get("sha256"))
    paths = [root / name for name in ("project.json", "facts.jsonl", "handoff.json")]
    paths.extend(vroot / name for name in ("version.json", "manifest.json", "acceptance.json"))
    if asset_path is not None:
        paths.append(asset_path)
    directories = {vroot / name for name in ("runs", "reports", "artifacts", "target")} if not existing else set()
    with tempfile.TemporaryDirectory(prefix=".seep-registration-", dir=root.parent) as temporary:
        staged = Path(temporary)
        record, files = None, []
        if needs_material:
            source = Path(os.path.abspath(os.path.expanduser(target)))
            if asset_id and not target.lower().startswith(("http://", "https://")) and source.is_dir():
                record = _directory_input(source, root, "assets/%s/snapshot" % asset_id, False)
                record["local_path"] = record["snapshot_tree_ref"]
                record = _typed_record_fields(record, str(source))
            else:
                record = _target_from_input(root, version, target, False)
                source = Path(record["source_path"]) if record.get("source_path") else None
                if asset_id and record["kind"] == "file":
                    record["local_path"] = "assets/%s/content/%s" % (asset_id, source.name)
            if record["kind"] == "directory":
                copied = _directory_input(source, staged, record["snapshot_ref"])
                if copied["identity"] != record["identity"]:
                    raise T.ConcurrentChange("source changed before registration")
            elif record["kind"] == "file":
                atomic_copy(source, project_file(staged, record["local_path"]),
                            record["sha256"], record["size"])
            verify_target(staged, record)
            files = sorted((p for p in staged.rglob("*") if p.is_file()),
                           key=lambda p: p.relative_to(staged).as_posix())
            for source_file in files:
                destination = project_file(root, source_file.relative_to(staged).as_posix())
                if destination.exists() or destination.is_symlink():
                    raise ValueError("registration refuses existing target material")
                paths.append(destination)
            directories.update(project_file(root, p.relative_to(staged).as_posix())
                               for p in staged.rglob("*") if p.is_dir())

        def publish(expected):
            if record is None or target_identity_fields(expected) != target_identity_fields(record):
                raise T.ConcurrentChange("target changed after registration preparation")
            for name in ("local_path", "snapshot_ref", "snapshot_tree_ref", "manifest_ref"):
                if expected.get(name) != record.get(name):
                    raise ValueError("prepared target destination mismatch")
            for directory in sorted(directories, key=lambda p: len(p.parts)):
                directory.mkdir(parents=True, exist_ok=True)
            for source_file in files:
                destination = project_file(root, source_file.relative_to(staged).as_posix())
                os.replace(source_file, destination)
                _fsync_dir(destination.parent)
            return dict(record)

        with metadata_transaction(root, paths, directories=sorted(directories)):
            yield publish if needs_material else None


@project_locked("project", recover=True)
def cmd_asset(a) -> int:
    root = project_root(a.project)
    try:
        require_project(root)
        with _registration_transaction(root, a.version, a.target, a.asset_id) as materialize:
            data = add_asset(root, a.asset_id, a.target, a.version, False,
                             role=a.role, materialize=materialize)
            event = write_event(root, "asset_registered", "登记资产 %s（%s）" % (a.asset_id, a.role),
                                a.version)
            write_handoff(root)
        print(json.dumps({"ok": True, "asset": data, "event": event["id"]}, ensure_ascii=False))
        return 0
    except Exception as exc:
        return fail("asset", "%s: %s" % (type(exc).__name__, exc))


@project_locked("project", recover=True)
def cmd_version(a) -> int:
    root = project_root(a.project)
    try:
        project = require_project(root)
        require_id(a.version, "version")
        if a.parent:
            _validate_version(root, a.parent, project["project_id"])
        target = getattr(a, "target", "")
        with _registration_transaction(root, a.version, target) as materialize:
            data = ensure_version(root, a.version, a.parent,
                                  [x for x in a.asset.split(",") if x], a.force,
                                  target_path=target,
                                  primary_asset_id=getattr(a, "primary_asset", ""),
                                  auxiliary_asset_ids=[x for x in getattr(a, "aux_asset", "").split(",") if x],
                                  materialize=materialize)
            project["current_version_id"] = a.version
            project["updated_at"] = now()
            atomic_json(root / "project.json", project)
            event = write_event(root, "version_created", "创建版本 %s" % a.version, a.version)
            write_handoff(root)
        print(json.dumps({"ok": True, "version": data, "event": event["id"]}, ensure_ascii=False))
        return 0
    except Exception as exc:
        return fail("version", "%s: %s" % (type(exc).__name__, exc))


def _find_run(root: Path, run_id: str) -> Path | None:
    for path in sorted((root / "versions").glob("*/runs/*/run.json")):
        if path.parent.name == run_id:
            return path
    return None


@project_locked("project", recover=True)
def cmd_run(a) -> int:
    root = project_root(a.project)
    try:
        project = require_project(root)
        require_id(a.version, "version")
        _validate_version(root, a.version, project["project_id"])
        rid = a.run_id or ("run-" + time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6])
        require_id(rid, "run_id")
        if _find_run(root, rid) is not None or (root / "versions" / a.version / "runs" / rid).exists():
            return fail("run", "run_id 已存在，必须使用新的 run_id：%s" % rid)
        run = {"schema": RUN_SCHEMA, "run_id": rid, "project_id": project["project_id"],
               "version_id": a.version, "started_at": now(), "finished_at": None,
               "executor": a.executor, "executor_host": socket.gethostname(),
               "status": "active", "scope_sha256": None,
               "artifact_manifest": relative_ref("runs/%s/MANIFEST.sha256" % rid)}
        rroot = project_file(root, "versions/%s/runs/%s" % (a.version, rid))
        directories = [rroot / name for name in ("capture", "artifacts")]
        with metadata_transaction(root, [rroot / "run.json", root / "facts.jsonl", root / "handoff.json"],
                                  directories=directories):
            rroot.mkdir(parents=True, exist_ok=False)
            for directory in directories:
                directory.mkdir()
            atomic_json(rroot / "run.json", run)
            write_event(root, "run_started", "开始运行批次 %s" % rid, a.version, rid)
            write_handoff(root)
        print(json.dumps({"ok": True, "run": run, "path": relative_ref(str(rroot.relative_to(root)))}, ensure_ascii=False))
        return 0
    except Exception as exc:
        return fail("run", "%s: %s" % (type(exc).__name__, exc))


@project_locked("project", recover=True)
def cmd_event(a) -> int:
    root = project_root(a.project)
    try:
        require_project(root)
        with metadata_transaction(root, [root / "facts.jsonl", root / "handoff.json"]):
            event = write_event(root, a.type, a.message, a.version, a.run)
            write_handoff(root)
        print(json.dumps({"ok": True, "event": event}, ensure_ascii=False))
        return 0
    except Exception as exc:
        return fail("event", "%s: %s" % (type(exc).__name__, exc))


def _require_inside(root: Path, path: Path, label: str) -> Path:
    """Reject external paths and symlink escapes; return the resolved path."""
    resolved = path.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("%s 必须是项目内路径，禁止外部或逃逸路径：%s" % (label, path))
    return resolved


def _evidence_path(root: Path, record: dict) -> Path:
    binding = record.get("input_asset")
    if binding is not None:
        current = asset_binding(root, record.get("version_id"), binding.get("asset_id"))
        if current != binding:
            raise ValueError("evidence input asset identity changed")
    path = _evidence_origin_path(root, record.get("local_path", ""), record.get("version_id"),
                                 record.get("run_id"), "evidence")
    verify_file(root, record)
    # source is provenance (the origin may move after a local copy). A raw
    # output explicitly bound by the producer is part of the durable evidence.
    raw = record.get("raw_output")
    if record.get("recorded_by") == "workflow-entry":
        # Existing captures already declare these bytes. Recheck them too when
        # reading a project created before raw_output became an indexed field.
        with path.open("rb") as stream:
            payload = stream.read((4 << 20) + 1)
        if len(payload) > 4 << 20:
            raise ValueError("workflow capture exceeds resource limit")
        capture = json.loads(payload)
        if not isinstance(capture, dict) or capture.get("schema") != "seep-workflow-capture/1":
            raise ValueError("workflow capture schema invalid")
        name = capture.get("raw_capture")
        if not isinstance(name, str) or name in ("", ".", "..") \
                or any(ch in name for ch in ("/", "\\", ":")):
            raise ValueError("workflow raw capture must be a sibling filename")
        declared = {"local_path": (path.parent / name).relative_to(root).as_posix(),
                    "sha256": capture.get("raw_sha256"), "size": capture.get("raw_size")}
        if raw is not None and raw != declared:
            raise ValueError("workflow raw capture disagrees with evidence binding")
        raw = declared
    if raw is not None or "raw_output" in record:
        if not isinstance(raw, dict) or set(raw) != {"local_path", "sha256", "size"}:
            raise ValueError("evidence raw_output binding invalid")
        raw_path = _evidence_origin_path(root, raw["local_path"], record.get("version_id"),
                                         record.get("run_id"), "raw output")
        checked = T.file_identity(root, raw_path.relative_to(root).as_posix())
        if checked["sha256"] != raw["sha256"] or type(raw["size"]) is not int \
                or checked["size"] != raw["size"]:
            raise ValueError("evidence raw output fingerprint mismatch")
    return path


def asset_binding(root: Path, version_id: str, asset_id: str) -> dict:
    """Bind a tool input to an already registered member of this version."""
    project = require_project(root)
    version = _validate_version(root, version_id, project["project_id"])
    require_id(asset_id, "asset_id")
    if asset_id not in (version.get("asset_ids") or []):
        raise ValueError("input asset is not registered in this version")
    record = _asset_record(root, asset_id)
    checked = verify_target(root, record)
    return {"asset_id": asset_id, "kind": checked["kind"],
            "sha256": checked["sha256"], "size": checked["size"],
            "local_path": record.get("local_path"),
            "identity_scope": checked["identity_scope"]}


def _require_relative_source(root: Path, value: str, label: str) -> Path:
    """Registration input must be a project-relative path, read only."""
    if not value:
        raise ValueError("%s 必须提供项目内相对路径" % label)
    ref = relative_ref(value, label)
    path = project_file(root, ref)
    _require_inside(root, path, label)
    if path.is_symlink():
        raise ValueError("%s 不允许 symlink：%s" % (label, ref))
    if not path.is_file():
        raise FileNotFoundError("%s 文件不存在（只读已有文件）：%s" % (label, ref))
    return path


def _evidence_origin_path(root: Path, value: str, version_id: str, run_id: str,
                          label: str) -> Path:
    """A shared output is legal; an explicit foreign version/run is not."""
    path = _require_relative_source(root, value, label)
    parts = path.relative_to(root).parts
    if len(parts) >= 2 and parts[0].casefold() == "versions":
        if os.path.normcase(parts[1]) != os.path.normcase(str(version_id)):
            raise ValueError("evidence/source belongs to another version")
        if len(parts) >= 4 and parts[2].casefold() == "runs" \
                and os.path.normcase(parts[3]) != os.path.normcase(str(run_id)):
            raise ValueError("evidence/source belongs to another run")
    return path


def _declared(value: str, label: str, pattern_len: int) -> str:
    text = (value or "").strip().lower()
    if len(text) != pattern_len or any(c not in "0123456789abcdef" for c in text):
        raise ValueError("%s 必须是 %d 位十六进制：%r" % (label, pattern_len, value))
    return text


def _run_record(root: Path, version: str, run_id: str) -> tuple[dict, Path]:
    require_id(version, "version")
    require_id(run_id, "run_id")
    path = project_file(root, "versions/%s/runs/%s/run.json" % (version, run_id))
    if not path.is_file():
        raise FileNotFoundError("run 不存在：%s/%s" % (version, run_id))
    run = load_json(path)
    project = require_project(root)
    if run.get("schema") != RUN_SCHEMA or run.get("run_id") != run_id:
        raise ValueError("run.json 身份无效：%s" % path)
    if run.get("version_id") != version or run.get("project_id") != project["project_id"]:
        raise ValueError("run 与 project/version 身份不匹配：%s" % run_id)
    return run, path


@project_locked("project", recover=True)
def cmd_evidence(a) -> int:
    root = project_root(a.project)
    try:
        project = require_project(root)
        if a.kind not in EVIDENCE_KINDS:
            return fail("evidence", "非法 kind：%s；允许值：%s" % (a.kind, ",".join(EVIDENCE_KINDS)))
        version = _validate_version(root, a.version, project["project_id"])
        run, _ = _run_record(root, a.version, a.run_id)
        if run.get("status") != "active":
            return fail("evidence", "只能为 active run 登记证据；已收尾 run 的证据集不可再追加：%s" % a.run_id)
        evidence_id = require_id(a.evidence_id, "evidence_id")
        target_sha = _declared(a.target_sha256, "target_sha256", 64)
        if target_sha != (version.get("sha256") or ""):
            return fail("evidence", "target_sha256 与当前版本目标不符，拒绝跨版本/伪造指纹登记")
        verify_target(root, version)
        input_asset = (asset_binding(root, a.version, a.input_asset)
                       if getattr(a, "input_asset", "") else None)
        source = _evidence_origin_path(root, a.path, a.version, a.run_id, "evidence path")
        _evidence_origin_path(root, a.source, a.version, a.run_id, "source")
        raw_output = None
        if getattr(a, "raw_output", ""):
            raw_path = _evidence_origin_path(root, a.raw_output, a.version, a.run_id, "raw output")
            measured = T.file_identity(root, raw_path.relative_to(root).as_posix())
            raw_output = {"local_path": measured["local_path"],
                          "sha256": measured["sha256"], "size": measured["size"]}
        # Domain tools commonly call raw command captures run.json. Only the
        # root/reserved lifecycle locations make that name project bookkeeping.
        parts = source.relative_to(root).parts
        lifecycle_run = (len(parts) == 5 and parts[0] == "versions" and parts[2] == "runs")
        tool_run_output = source.name == "run.json" and len(parts) > 1 and not lifecycle_run
        if (source.name in METADATA_NAMES and not tool_run_output) or source.name == ".project.lock":
            return fail("evidence", "项目自身元数据/账本不能充当证据（自证无效）：%s" % a.path)
        if source.is_relative_to(root / "versions" / a.version / "evidence"):
            return fail("evidence", "证据登记记录自身不能充当证据：%s" % a.path)
        if source.is_relative_to(root / "versions" / a.version / "target"):
            return fail("evidence", "版本目标二进制本身不能作为证据：%s" % a.path)
        for other in (root / "versions").iterdir():
            if other.name != a.version and source.is_relative_to(other):
                return fail("evidence", "证据不得取自其他版本目录（%s）：%s" % (other.name, a.path))
        sha = _declared(a.sha256, "sha256", 64)
        size = int(a.size)
        actual = file_fingerprint(source)
        if actual["sha256"] != sha or actual["size"] != size:
            return fail("evidence", "声明的 sha256/size 与实际文件不符：%s" % a.path)
        if actual["size"] <= 0:
            return fail("evidence", "空文件不能作为证据：%s" % a.path)
        directory = root / "versions" / a.version / "evidence"
        record_path = directory / (evidence_id + ".json")
        stored = relative_ref(str(source.relative_to(root)))
        # Validate the destination index before writing any evidence record.
        manifest_path = project_file(root, "versions/%s/manifest.json" % a.version)
        manifest = _validate_manifest(root, a.version, project["project_id"])
        ledger = manifest.get("evidence", [])
        if not isinstance(ledger, list) or any(not isinstance(e, dict) for e in ledger):
            raise ValueError("manifest evidence 索引无效：%s" % a.version)
        indexed = [e for e in ledger if e.get("evidence_id") == evidence_id]
        if len(indexed) > 1:
            raise ValueError("manifest evidence_id 重复：%s" % evidence_id)
        if record_path.exists():
            old = load_json(record_path)
            if old.get("sha256") != sha or old.get("target_sha256") != target_sha:
                return fail("evidence", "evidence_id 已登记且指纹不同；旧记录不可覆盖：%s" % evidence_id)
            if old.get("run_id") != a.run_id or old.get("version_id") != a.version:
                return fail("evidence", "evidence_id 已绑定其他 run/version；不可覆盖：%s" % evidence_id)
            if old.get("input_asset") != input_asset:
                return fail("evidence", "evidence_id 已绑定不同输入资产")
            if old.get("raw_output") != raw_output:
                return fail("evidence", "evidence_id 已绑定不同原始输出")
            _evidence_path(root, old)
            if not indexed or any(indexed[0].get(k) != old.get(k) for k in
                                  ("sha256", "size", "target_sha256", "run_id", "local_path", "kind", "raw_output")):
                raise ValueError("已有 evidence 登记与 manifest 索引不一致")
            print(json.dumps({"ok": True, "idempotent": True, "evidence": old,
                              "proof_level": PROOF_LEVEL}, ensure_ascii=False))
            return 0
        if indexed:
            raise ValueError("manifest 已登记 evidence_id 但记录缺失；拒绝覆盖历史：%s" % evidence_id)
        record = {"schema": EVIDENCE_SCHEMA, "evidence_id": evidence_id, "kind": a.kind,
                  "project_id": project["project_id"], "version_id": a.version,
                  "run_id": a.run_id, "target_sha256": target_sha,
                  "local_path": stored, "sha256": sha, "size": size,
                  "source": relative_ref(a.source, "source"),
                  "how": a.how or "", "created_at": now(), "recorded_by": a.recorded_by or "agent"}
        if record["how"].strip().lower() in ("", "none") and not a.how:
            record["how"] = "unspecified"
        if input_asset is not None:
            record["input_asset"] = input_asset
        if raw_output is not None:
            record["raw_output"] = raw_output
        ledger.append({"evidence_id": evidence_id, "kind": record["kind"],
                       "run_id": a.run_id, "sha256": sha, "size": size,
                       "local_path": stored, "target_sha256": target_sha,
                       "created_at": record["created_at"]})
        if raw_output is not None:
            ledger[-1]["raw_output"] = raw_output
        manifest["evidence"] = ledger
        with metadata_transaction(root, [record_path, manifest_path, root / "facts.jsonl", root / "handoff.json"]):
            atomic_json(record_path, record)
            _evidence_path(root, record)
            atomic_json(manifest_path, manifest)
            write_event(root, "evidence_registered", "登记证据 %s（%s）" % (evidence_id, record["kind"]),
                        a.version, a.run_id)
            write_handoff(root)
        print(json.dumps({"ok": True, "evidence": record, "proof_level": PROOF_LEVEL,
                          "proof_limits": list(PROOF_LIMITS)}, ensure_ascii=False))
        return 0
    except Exception as exc:
        return fail("evidence", "%s: %s" % (type(exc).__name__, exc))


def _acceptance_path(root: Path, version: str) -> Path:
    return root / "versions" / version / "acceptance.json"


def load_acceptance(root: Path, version: str, project_id: str) -> dict:
    path = _acceptance_path(root, version)
    if not path.is_file():
        raise FileNotFoundError("acceptance 不存在：%s" % version)
    data = load_json(path)
    if data.get("schema") != ACCEPTANCE_SCHEMA or data.get("version_id") != version:
        raise ValueError("acceptance 身份无效：%s" % version)
    if data.get("project_id") != project_id:
        raise ValueError("acceptance project_id 不匹配：%s" % version)
    if "target_sha256" not in data:
        raise ValueError("acceptance 未绑定 target_sha256：%s" % version)
    bound = data.get("target_sha256")
    if bound is not None and (not isinstance(bound, str) or len(bound) != 64
                              or any(c not in "0123456789abcdef" for c in bound)):
        raise ValueError("acceptance target_sha256 非法：%s" % version)
    items = data.get("items")
    if not isinstance(items, list):
        raise ValueError("acceptance items 无效：%s" % version)
    return data


def acceptance_items(data: dict) -> list[dict]:
    return [x for x in data.get("items") or [] if isinstance(x, dict)]


def required_items(data: dict) -> list[dict]:
    return [x for x in acceptance_items(data) if x.get("required")]


def _origin_of(item: dict) -> dict:
    origin = item.get("origin")
    return origin if isinstance(origin, dict) else {}


def _is_sha256(value) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _canonical_json(value) -> bytes:
    """Canonical bytes for sealing a whole object (no field whitelist)."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def closure_seal(record: dict) -> str:
    """Seal the *entire* closure + snapshot object into one local hash.

    The seal covers every field (including display-only ones such as
    ``target_size``/``proof_level``/``proof_limits``/``captured_at``), so it is
    not a hand-maintained whitelist.  It is a local consistency record, not a
    cryptographic signature: a self-consistent rewrite of the whole directory
    is explicitly outside the proof ceiling.
    """
    closure = record.get("closure")
    sealed = ({key: value for key, value in closure.items() if key != "seal_sha256"}
              if isinstance(closure, dict) else closure)
    return hashlib.sha256(_canonical_json(
        {"schema": CLOSURE_SEAL_SCHEMA,
         "closure": sealed,
         "acceptance_snapshot": record.get("acceptance_snapshot")})).hexdigest()


def _event_status(event: dict) -> str:
    """Ending status of a recorded event; legacy events only carry a message."""
    if "status" in event:
        return str(event.get("status") or "")
    message = str(event.get("message") or "")
    return message.rsplit("：", 1)[-1].strip() if "：" in message else ""


def _acceptance_revision_dir(root: Path, version_id: str) -> Path:
    return root / "versions" / version_id / "acceptance-revisions"


def _acceptance_revision_path(root: Path, version_id: str, value: str) -> Path:
    return _acceptance_revision_dir(root, version_id) / ("rev-" + value + ".json")


def _archive_acceptance(root: Path, version_id: str, payload: bytes) -> str:
    """Store exact bytes under their own sha256; never overwrite different bytes."""
    value = hashlib.sha256(payload).hexdigest()
    path = _acceptance_revision_path(root, version_id, value)
    if path.exists():
        if sha256_file(str(path)) != value:
            raise ValueError("不可覆盖修订内容与文件名不符：%s" % value)
        return value
    atomic_bytes(path, payload)
    if sha256_file(str(path)) != value:
        raise ValueError("不可覆盖修订写入后校验失败：%s" % value)
    return value


ACCEPTANCE_CHAIN_SCHEMA = "seep-acceptance-chain/1"


def _serialize(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _chain_log_path(root: Path, version_id: str) -> Path:
    return _acceptance_revision_dir(root, version_id) / "chain.jsonl"


def _read_chain_log(root: Path, version_id: str) -> tuple[list[str], list[str]]:
    """Read the append-only write log: every state this CLI ever wrote, in order."""
    path = _chain_log_path(root, version_id)
    if not path.is_file():
        return [], ["缺少验收写链日志（acceptance-revisions/chain.jsonl）"]
    values: list[str] = []
    problems: list[str] = []
    for number, raw in enumerate(path.read_bytes().splitlines()):
        if not raw.strip():
            problems.append("验收写链日志存在空行：第 %d 行" % (number + 1))
            continue
        try:
            record = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            problems.append("验收写链日志不可解析：第 %d 行（%s）" % (number + 1, exc))
            continue
        if not isinstance(record, dict) or record.get("schema") != ACCEPTANCE_CHAIN_SCHEMA:
            problems.append("验收写链日志 schema 无效：第 %d 行" % (number + 1))
            continue
        if record.get("version_id") != version_id:
            problems.append("验收写链日志版本不符：第 %d 行" % (number + 1))
            continue
        if record.get("seq") != number:
            problems.append("验收写链日志序号不连续：第 %d 行" % (number + 1))
            continue
        value = record.get("sha256")
        if not _is_sha256(value):
            problems.append("验收写链日志哈希非法：第 %d 行" % (number + 1))
            continue
        values.append(value)
    return values, problems


def _append_chain_log(root: Path, version_id: str, value: str, seq: int) -> None:
    append_jsonl(_chain_log_path(root, version_id),
                 {"schema": ACCEPTANCE_CHAIN_SCHEMA, "version_id": version_id,
                  "seq": seq, "sha256": value, "recorded_at": now()})


def write_acceptance(root: Path, version_id: str, data: dict, log_seq: int | None = None) -> str:
    """Write the live checklist verbatim, then append it to the write log.

    The log records every state this CLI produced, in order, so the live bytes
    are pinned between writes: a hand-edited checklist no longer matches the log
    head and cannot be laundered into the revision archive.
    """
    payload = _serialize(data)
    atomic_bytes(_acceptance_path(root, version_id), payload)
    value = hashlib.sha256(payload).hexdigest()
    if sha256_file(str(_acceptance_path(root, version_id))) != value:
        raise ValueError("验收清单写入后哈希校验失败：%s" % value)
    if log_seq is not None:
        _append_chain_log(root, version_id, value, log_seq)
    return value


def _acceptance_chain(root: Path, version_id: str, data: dict,
                      current_sha: str | None = None) -> tuple[list[str], list[str]]:
    """Recompute the append-only acceptance revision chain from immutable files.

    Three independent records must agree:

    * ``acceptance-revisions/chain.jsonl`` - append-only log of every state this
      CLI wrote, in order (seq 0..n-1); its head must be the live checklist.
    * ``acceptance-revisions/rev-<sha256>.json`` - verbatim predecessors; the
      file name is the sha256 of the stored bytes, so archived content cannot be
      rewritten in place.
    * the live ``acceptance.json`` fields ``archive_index`` (ordered
      predecessors, genesis first), ``revision_history`` (sorted, genesis
      excluded) and ``revisions`` (their count).

    Returned chain = ``archive_index + [sha256(live acceptance.json)]``, i.e.
    genesis first and the live state last.  Disagreements are reported; the
    caller decides whether they block work or only the completion gate.
    """
    problems: list[str] = []
    if current_sha is None:
        current_sha = sha256_file(str(_acceptance_path(root, version_id)))
    history = data.get("revision_history")
    if history is None:
        history = []
    if not isinstance(history, list):
        return [], ["revision_history 必须是列表"]
    if any(not _is_sha256(x) for x in history):
        problems.append("revision_history 含非法哈希")
    revisions = data.get("revisions")
    if revisions is None:
        revisions = 0
    if type(revisions) is not int or revisions < 0:
        problems.append("revisions 字段非法：%r" % (revisions,))
        revisions = 0
    present: dict[str, Path] = {}
    directory = _acceptance_revision_dir(root, version_id)
    if directory.is_dir():
        for path in sorted(directory.glob("*.json")):
            stem = path.stem
            if not stem.startswith("rev-") or not _is_sha256(stem[4:]):
                problems.append("修订归档文件名无效：%s" % path.name)
                continue
            value = stem[4:]
            if value in present:
                problems.append("修订归档文件名重复：%s" % path.name)
            present[value] = path
    for value, path in present.items():
        if sha256_file(str(path)) != value:
            problems.append("修订归档内容与文件名哈希不符：%s" % path.name)
    logged, log_problems = _read_chain_log(root, version_id)
    # A checklist that the chain never started on (``acceptance-define`` never
    # ran: no log, no archive index, no revision, nothing recorded) is unborn,
    # not damaged.  Its absence must not be projected as an integrity error.
    # Any log archive/record present makes a missing log a real defect again.
    unborn = (not logged and data.get("archive_index") is None
              and not present and not (data.get("revision_history") or [])
              and not [x for x in acceptance_items(data)
                       if x.get("status") not in (None, "pending")])
    if not unborn:
        problems.extend(log_problems)
    index = data.get("archive_index")
    recorded = [x for x in acceptance_items(data) if x.get("status") not in (None, "pending")]
    if index is None:
        if recorded:
            problems.append("验收清单缺少不可覆盖修订索引（历史被剥离或早于修订链）")
        for value in history:
            if _is_sha256(value) and value not in present:
                problems.append("缺少不可覆盖修订文件：%s" % value)
        if revisions != len(history):
            problems.append("revisions=%d 与 revision_history 数量 %d 不符"
                            % (revisions, len(history)))
        # The write log is an independent witness: a checklist whose index was
        # stripped still cannot claim to be the state this CLI last wrote.  This
        # is the same head check the indexed path performs, applied to the
        # index-less shape so real stripping is not silently reported as "no
        # chain problems" with nothing recorded yet (LIFECYCLE-05 A2).
        if logged and current_sha != logged[-1]:
            problems.append("当前验收清单不是写链日志的最新状态（被手改或剥离历史）")
        return list(history) + [current_sha], problems
    if not isinstance(index, list) or any(not _is_sha256(x) for x in index):
        return list(history) + [current_sha], problems + ["archive_index 必须是哈希列表"]
    if not index:
        problems.append("archive_index 缺少 genesis 修订（定义状态未归档）")
    if len(set(index)) != len(index):
        problems.append("archive_index 存在重复哈希")
    if current_sha in index:
        problems.append("archive_index 把当前修订当作历史修订（不可复算）")
    chain = list(index) + [current_sha]
    if set(present) != set(index):
        missing = sorted(set(index) - set(present))
        extra = sorted(set(present) - set(index))
        if missing:
            problems.append("缺少不可覆盖修订文件：%s" % ",".join(missing))
        if extra:
            problems.append("acceptance-revisions 存在未登记修订：%s" % ",".join(extra))
    if revisions != max(len(index) - 1, 0):
        problems.append("revisions=%d 与修订链长度 %d 不符" % (revisions, max(len(index) - 1, 0)))
    if list(history) != sorted(index[1:]):
        problems.append("revision_history 与不可覆盖修订链不一致")
    if logged:
        if list(index) != logged[:len(index)]:
            problems.append("不可覆盖修订链与写链日志前缀不一致")
        if current_sha != logged[-1]:
            problems.append("当前验收清单不是写链日志的最新状态（被手改或剥离历史）")
        if len(set(logged)) != len(logged):
            problems.append("写链日志存在重复状态")
    for position, value_hash in enumerate(index):
        path = present.get(value_hash)
        if path is None:
            continue
        try:
            value = load_json(path)
        except Exception as exc:
            problems.append("修订归档不可读（%s）：%s" % (value_hash, exc))
            continue
        prior = value.get("archive_index")
        if prior is None:
            prior = []
        if not isinstance(prior, list) or prior != index[:position]:
            problems.append("修订链在位置 %d 不可复算：%s" % (position, value_hash))
        prior_history = value.get("revision_history")
        if prior_history is None:
            prior_history = []
        if not isinstance(prior_history, list) or prior_history != sorted(index[1:position]):
            problems.append("修订链历史在位置 %d 不可复算：%s" % (position, value_hash))
        prior_revisions = value.get("revisions")
        if prior_revisions is None:
            prior_revisions = 0
        if prior_revisions != max(position - 1, 0):
            problems.append("修订链 revisions 在位置 %d 不一致：%s" % (position, value_hash))
    return chain, problems


def _revision_document(root: Path, version_id: str, value: str) -> dict:
    """Locate one *immutable* acceptance revision by the hash that consumed it.

    A completed run/migration records ``closure.acceptance_sha256``.  That exact
    revision is either archived as ``acceptance-revisions/rev-<sha256>.json`` or,
    when nothing was appended afterwards, still the live ``acceptance.json``.
    Later legal revisions never invalidate it, so a multi-run history is not
    re-interpreted through the *current* checklist head.
    """
    if not _is_sha256(value):
        raise ValueError("修订哈希非法：%r" % (value,))
    path = _acceptance_revision_path(root, version_id, value)
    if path.is_file():
        if sha256_file(str(path)) != value:
            raise ValueError("修订归档内容与文件名哈希不符：%s" % path.name)
        return load_json(path)
    live = _acceptance_path(root, version_id)
    if live.is_file() and sha256_file(str(live)) == value:
        return load_json(live)
    raise FileNotFoundError("不可覆盖修订不存在：%s" % value)


def _revision_lineage(root: Path, version_id: str, data: dict,
                      self_sha: str) -> tuple[list[str], list[str]]:
    """Recompute one fixed revision's own chain: ``archive_index + [itself]``.

    Unlike :func:`_acceptance_chain` this never compares against the live write
    log or the set of files currently on disk, so it stays valid after later
    runs append further revisions.  Every predecessor's own ``archive_index`` /
    ``revision_history`` / ``revisions`` must reproduce the chain position.
    """
    problems: list[str] = []
    history = data.get("revision_history")
    history = [] if history is None else history
    revisions = data.get("revisions")
    revisions = 0 if revisions is None else revisions
    index = data.get("archive_index")
    if index is None:
        index = []
        problems.append("修订缺少不可覆盖修订索引（历史被剥离或早于修订链）")
    if not isinstance(index, list) or any(not _is_sha256(x) for x in index):
        return [], problems + ["archive_index 必须是哈希列表"]
    if not isinstance(history, list) or any(not _is_sha256(x) for x in history):
        problems.append("revision_history 必须是哈希列表")
        history = [x for x in history if _is_sha256(x)] if isinstance(history, list) else []
    if type(revisions) is not int or revisions < 0:
        problems.append("revisions 字段非法：%r" % (revisions,))
        revisions = 0
    if not index:
        problems.append("archive_index 缺少 genesis 修订（定义状态未归档）")
    if len(set(index)) != len(index):
        problems.append("archive_index 存在重复哈希")
    if self_sha in index:
        problems.append("archive_index 把当前修订当作历史修订（不可复算）")
    if revisions != max(len(index) - 1, 0):
        problems.append("revisions=%d 与修订链长度 %d 不符"
                        % (revisions, max(len(index) - 1, 0)))
    if list(history) != sorted(index[1:]):
        problems.append("revision_history 与不可覆盖修订链不一致")
    for position, value_hash in enumerate(index):
        path = _acceptance_revision_path(root, version_id, value_hash)
        if not path.is_file():
            problems.append("缺少不可覆盖修订文件：%s" % value_hash)
            continue
        if sha256_file(str(path)) != value_hash:
            problems.append("修订归档内容与文件名哈希不符：%s" % path.name)
            continue
        try:
            value = load_json(path)
        except Exception as exc:
            problems.append("修订归档不可读（%s）：%s" % (value_hash, exc))
            continue
        prior = value.get("archive_index")
        prior = [] if prior is None else prior
        if not isinstance(prior, list) or prior != index[:position]:
            problems.append("修订链在位置 %d 不可复算：%s" % (position, value_hash))
        prior_history = value.get("revision_history")
        prior_history = [] if prior_history is None else prior_history
        if not isinstance(prior_history, list) or prior_history != sorted(index[1:position]):
            problems.append("修订链历史在位置 %d 不可复算：%s" % (position, value_hash))
        prior_revisions = value.get("revisions")
        prior_revisions = 0 if prior_revisions is None else prior_revisions
        if prior_revisions != max(position - 1, 0):
            problems.append("修订链 revisions 在位置 %d 不一致：%s" % (position, value_hash))
    return list(index) + [self_sha], problems


def _pass_provenance(root: Path, version: dict, item: dict,
                    require_run: str = "") -> tuple[list[str], list[str]]:
    """A pass is only valid when produced by a recorded, run-bound, revisioned witness.

    Two very different kinds of failure are kept apart here (main-agent ruling 1):

    ``problems``     the witness itself is broken or was hand-edited (missing
                     verifier/how/revision, foreign version/target, unknown
                     run record).  That is *evidence integrity* and always
                     blocks.
    ``ineligible``   the witness is intact but its origin run reached a
                     non-completing terminal state (failed/cancelled/blocked) or
                     the pass belongs to another run.  Nothing was tampered
                     with; the draft simply is not usable to complete anything.
                     Reported as unfinished/ineligible, never as corruption.
    """
    problems: list[str] = []
    ineligible: list[str] = []
    verifier = item.get("verifier")
    how = item.get("how")
    if not isinstance(verifier, str) or not verifier.strip():
        problems.append("pass 缺少非空 verifier")
    if not isinstance(how, str) or not how.strip():
        problems.append("pass 缺少非空 how")
    revision = item.get("revision")
    if type(revision) is not int or revision < 1:
        problems.append("pass 缺少有效 revision（必须 >=1 且来自真实修订）")
    origin = _origin_of(item)
    if origin.get("version_id") != version.get("version_id"):
        problems.append("pass origin.version_id 与当前版本不符")
    if origin.get("target_sha256") != (version.get("sha256") or None):
        problems.append("pass origin.target_sha256 与版本目标不符")
    run_id = origin.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        problems.append("pass 缺少 origin.run_id（必须以具体 run 登记）")
    else:
        if require_run and run_id != require_run:
            ineligible.append("pass origin.run_id 与当前 run 不符：%s != %s" % (run_id, require_run))
        try:
            run, _ = _run_record(root, str(version.get("version_id")), run_id)
            if run.get("status") not in ("active", "completed"):
                ineligible.append("pass origin.run %s 已 %s：记录完整但该 pass 不具备完成资格"
                                  % (run_id, run.get("status")))
        except Exception as exc:
            problems.append("pass origin.run 无效：%s" % exc)
    return problems, ineligible


_ITEM_CHAIN_FIELDS = ("id", "status", "result", "evidence_ids", "verifier", "how", "revision")


def _acceptance_record_mismatch(root: Path, version: dict, data: dict,
                                chain: list[str]) -> list[str]:
    """The live checklist must be exactly the predecessor revision + one record."""
    problems: list[str] = []
    after = acceptance_items(data)
    # Any non-pending state must have been produced by an acceptance-record.
    recorded = [x for x in after if x.get("status") not in (None, "pending")]
    if not recorded:
        return problems
    if len(chain) < 2:
        problems.append("存在已记录验收项却无可复算的不可覆盖修订（绕过 acceptance-record）")
        return problems
    path = _acceptance_revision_path(root, version["version_id"], chain[-2])
    try:
        previous = load_json(path)
    except Exception as exc:
        problems.append("无法读取上一版不可覆盖修订：%s" % exc)
        return problems
    before = acceptance_items(previous)
    if len(before) != len(after) or not after:
        problems.append("当前验收清单与不可覆盖修订的项数不一致")
        return problems

    def row(value: dict) -> tuple:
        return tuple(json.dumps(value.get(k), ensure_ascii=False, sort_keys=True)
                     for k in _ITEM_CHAIN_FIELDS)

    # Only a row that carries a recorded status can be the ``acceptance-record`` edit.
    changed = [i for i in range(len(after))
               if row(before[i]) != row(after[i])
               and after[i].get("status") not in (None, "pending")]
    if len(changed) != 1:
        problems.append("当前验收清单不是一次可复算的 acceptance-record 修订（记录差异项=%d）" % len(changed))
        return problems
    index = changed[0]
    old_revision = before[index].get("revision")
    old_revision = old_revision if type(old_revision) is int else 0
    new_revision = after[index].get("revision")
    if type(new_revision) is not int or new_revision != old_revision + 1:
        problems.append("验收项 %s 的 revision 未按记录链递增" % after[index].get("id"))
    if not after[index].get("recorded_at"):
        problems.append("验收项 %s 缺少 recorded_at" % after[index].get("id"))
    origin = _origin_of(after[index])
    for key in ("version_id", "run_id", "target_sha256"):
        if key not in origin:
            problems.append("验收项 %s 的 origin 缺少 %s" % (after[index].get("id"), key))
    return problems


def _evidence_verdict(root: Path, item: dict, version: dict, project_id: str,
                      require_run: str = "") -> tuple[bool, list[str], list[dict], list[str]]:
    """Check a recorded pass witness; never infers semantics from content.

    Returns ``(ok, problems, valid, ineligible)``.  ``problems`` are real
    integrity failures (missing/mismatched files, foreign version, unknown run);
    ``ineligible`` only means the (intact) witness belongs to a run that did not
    complete, so the draft cannot be used to complete anything.  A caller that
    accepts a *new* pass refuses both; a read-only projection reports
    ``ineligible`` as unfinished instead of corruption.
    """
    problems = []
    ineligible: list[str] = []
    valid = []
    ids = item.get("evidence_ids")
    if not isinstance(ids, list) or not ids:
        return False, ["pass 未登记 evidence_ids"], valid, ineligible
    for evidence_id in ids:
        if not isinstance(evidence_id, str) or not evidence_id:
            problems.append("evidence id 非法")
            continue
        path = root / "versions" / version["version_id"] / "evidence" / (evidence_id + ".json")
        try:
            if not path.is_file():
                raise FileNotFoundError("证据不存在：%s" % evidence_id)
            record = load_json(path)
            if record.get("schema") != EVIDENCE_SCHEMA or record.get("evidence_id") != evidence_id:
                raise ValueError("证据身份无效：%s" % evidence_id)
            if record.get("project_id") != project_id:
                raise ValueError("证据 project_id 不匹配：%s" % evidence_id)
            if record.get("version_id") != version["version_id"]:
                raise ValueError("证据不属于本版本：%s" % evidence_id)
            if require_run and record.get("run_id") != require_run:
                ineligible.append("证据不属于当前 run（%s != %s）：%s"
                                  % (record.get("run_id"), require_run, evidence_id))
            run, _ = _run_record(root, version["version_id"], str(record.get("run_id")))
            if run.get("status") not in ("active", "completed"):
                ineligible.append("证据 %s 所属 run %s 已 %s：证据文件完整，但该 pass 不具备完成资格"
                                  % (evidence_id, record.get("run_id"), run.get("status")))
            # Ruling 2: ineligibility never short-circuits the integrity checks.
            # A tampered/missing raw file must still be reported as corruption
            # even when its origin run did not complete.
            if record.get("target_sha256") != (version.get("sha256") or ""):
                raise ValueError("证据 target_sha256 与当前版本目标不符：%s" % evidence_id)
            local = _evidence_path(root, record)
            if local.stat().st_size <= 0 or not record.get("size"):
                raise ValueError("证据文件为空：%s" % evidence_id)
            origin = _origin_of(item)
            if origin.get("version_id") not in (None, version["version_id"]):
                raise ValueError("验收项来源版本与当前版本不符：%s" % evidence_id)
            if origin.get("run_id") not in (None, record.get("run_id")):
                raise ValueError("验收项来源 run 与证据不符：%s" % evidence_id)
            # run_sha256 is deliberately not recorded: run.json changes when the
            # run is finished, so it is not reproducible at resume time and would
            # turn a whole-object comparison into a hand-maintained whitelist.
            valid.append({"evidence_id": evidence_id, "sha256": record.get("sha256"),
                          "size": record.get("size"), "run_id": record.get("run_id"),
                          "local_path": record.get("local_path"),
                          "target_sha256": record.get("target_sha256")})
        except Exception as exc:
            problems.append("%s: %s" % (evidence_id, exc))
    return (not problems and not ineligible and bool(valid)), problems, valid, ineligible
def _evidence_index_problems(root: Path, version_id: str) -> list[str]:
    """Cross-check every registered evidence record against the manifest index.

    The completion gate and ``resume`` share this exact core (rule A): each raw
    evidence file's hash/size, its independent registration record, the
    ``manifest.evidence`` index and (via the acceptance state) the consumed
    revision references must agree.  A self-consistent edit of a file *and* its
    own record must therefore be caught before ``completed`` is ever written.
    """
    problems: list[str] = []
    directory = root / "versions" / version_id / "evidence"
    records: dict[str, dict] = {}
    if directory.is_dir():
        for path in sorted(directory.glob("*.json")):
            try:
                record = load_json(path)
            except Exception as exc:
                problems.append("证据登记记录不可读：%s（%s）" % (path.name, exc))
                continue
            if record.get("schema") != EVIDENCE_SCHEMA or record.get("evidence_id") != path.stem:
                problems.append("证据登记记录身份无效：%s" % path.name)
                continue
            records[path.stem] = record
            try:
                local = _evidence_path(root, record)
            except Exception as exc:
                problems.append("证据原始文件不可复核：%s（%s）" % (path.stem, exc))
                continue
            actual = file_fingerprint(local)
            if actual["sha256"] != record.get("sha256") or actual["size"] != record.get("size"):
                problems.append("证据原始文件与登记记录不一致：%s" % path.stem)
    manifest_path = root / "versions" / version_id / "manifest.json"
    manifest = None
    if not manifest_path.is_file():
        problems.append("缺少版本 manifest，无法核验证据索引：%s" % version_id)
    else:
        try:
            manifest = load_json(manifest_path)
        except Exception as exc:
            problems.append("版本 manifest 不可读：%s（%s）" % (version_id, exc))
    if manifest is not None:
        ledger = manifest.get("evidence")
        if ledger is None:
            ledger = []
        if not isinstance(ledger, list):
            problems.append("manifest evidence 索引不是列表：%s" % version_id)
            ledger = []
        indexed: dict[str, dict] = {}
        for entry in ledger:
            if not isinstance(entry, dict):
                problems.append("manifest evidence 索引项无效：%s" % version_id)
                continue
            evidence_id = entry.get("evidence_id")
            if not isinstance(evidence_id, str) or not evidence_id:
                problems.append("manifest evidence 索引存在空 evidence_id：%s" % version_id)
                continue
            if evidence_id in indexed:
                problems.append("manifest evidence 索引重复：%s" % evidence_id)
            indexed[evidence_id] = entry
            record = records.get(evidence_id)
            if record is None:
                problems.append("manifest 证据索引缺少登记记录：%s" % evidence_id)
                continue
            if any(record.get(k) != entry.get(k) for k in ("sha256", "size", "local_path",
                                                          "target_sha256", "run_id")):
                problems.append("manifest 证据索引与登记记录不一致：%s" % evidence_id)
            if record.get("raw_output") != entry.get("raw_output"):
                problems.append("manifest 原始输出索引与登记记录不一致：%s" % evidence_id)
        for evidence_id in sorted(set(records) - set(indexed)):
            problems.append("证据已登记但未进入 manifest 索引：%s" % evidence_id)
    return problems


def _evidence_integrity(root: Path, version: dict, project_id: str) -> list[str]:
    """One evidence-consistency rule set shared by completion and resume."""
    version_id = str(version.get("version_id") or "")
    problems = _evidence_index_problems(root, version_id)
    try:
        data = load_acceptance(root, version_id, project_id)
    except Exception as exc:
        # Rule C parity: the live chain state (``_acceptance_state``) already
        # reports an unreadable checklist (and its consequences) on its own; the
        # raw index/file cross-check above is still returned unchanged, so a
        # completion gate keeps refusing.  What is *not* added here is a second,
        # duplicate "unreadable checklist" error that would gate legal
        # in-progress work (e.g. a hand edit on an active draft, which the
        # ``chain_problems``/``integrity_errors`` path already reports).
        return problems
    for item in required_items(data):
        for evidence_id in item.get("evidence_ids") or []:
            record_path = (root / "versions" / version_id / "evidence"
                           / (str(evidence_id) + ".json"))
            if not record_path.is_file():
                problems.append("验收项 %s 引用的证据缺少登记记录：%s"
                                % (item.get("id"), evidence_id))
    return problems


def _acceptance_items_state(root: Path, version: dict, project: dict, data: dict,
                            require_run: str = "") -> dict:
    """Evaluate the *contents* of one checklist document (no chain checks).

    Shared by the live evaluation (:func:`_acceptance_state`) and by fixed
    revision replay (:func:`_revision_state`), so an old completion is checked
    with exactly the same item/evidence rules as a current one.
    """
    state = {"required_count": 0,
             "counts": {k: 0 for k in ACCEPTANCE_STATUSES}, "pending": [],
             "failed_items": [], "stale": [], "unsettled": [], "passed": [],
             "reasons": [], "duplicate": False}
    items = required_items(data)
    state["required_count"] = len(items)
    if not items:
        state["reasons"].append("验收清单为空：无 required 验收项")
        return state
    seen = set()
    duplicate = False
    for item in items:
        item_id = str(item.get("id") or "")
        try:
            require_id(item_id, "acceptance id")
        except ValueError as exc:
            state["reasons"].append(str(exc))
            duplicate = True
            continue
        if item_id in seen:
            state["reasons"].append("验收清单重复 id：%s" % item_id)
            duplicate = True
        seen.add(item_id)
        status = item.get("status") if item.get("status") in ACCEPTANCE_STATUSES else "unknown"
        state["counts"][status] = state["counts"].get(status, 0) + 1
        row = {"id": item_id, "description": item.get("description"), "status": status}
        if status == "pass":
            problems, ineligible = _pass_provenance(root, version, item,
                                                    require_run=require_run)
            ok, evidence_problems, valid, evidence_ineligible = _evidence_verdict(
                root, item, version, project["project_id"], require_run=require_run)
            # Integrity problems (tampered/missing files, hand-edited rows) always
            # block.  Ineligible witnesses (origin run failed/cancelled/blocked,
            # or the pass belongs to another run) only mean the draft is not
            # usable for completion: reported as unfinished, never as corruption.
            problems.extend(evidence_problems)
            ineligible.extend(evidence_ineligible)
            if ok and not problems:
                row["evidence"] = valid
                state["passed"].append(row)
            elif problems:
                row["problems"] = problems
                state["stale"].append(row)
                state["reasons"].append("验收证据/记录链失效：%s" % item_id)
            else:
                row["problems"] = list(ineligible)
                row["ineligible"] = True
                state["unsettled"].append(row)
                state["reasons"].append("验收项未完成（pass 不具备完成资格）：%s" % item_id)
        elif status == "pending":
            state["pending"].append(row)
        else:
            state["failed_items"].append(row)
    state["duplicate"] = duplicate
    return state


def _merge_items_state(state: dict, items_state: dict, chain_problems: list[str]) -> dict:
    """Combine item evaluation with chain integrity into the full state object."""
    for key in ("required_count", "pending", "failed_items", "stale", "unsettled",
                "passed", "reasons", "duplicate"):
        value = items_state[key]
        if key == "required_count":
            state[key] = value
        elif key == "reasons":
            state[key].extend(value)
        else:
            state[key] = value
    state["counts"] = dict(items_state["counts"])
    core_complete = (bool(state["required_count"]) and not state["pending"]
                     and not state["failed_items"] and not state["stale"]
                     and not state["unsettled"] and not state["duplicate"])
    state["complete"] = core_complete and not chain_problems
    # LIFECYCLE-05 A2 (REVIEW-04 §2-3): incomplete completion *eligibility*
    # (pending / failed / cancelled / blocked / unsettled) is not corruption, but
    # a checklist chain that cannot be recomputed (revision hash, chain head,
    # archive/log relation, target binding) is corruption at **every** stage,
    # including a purely pending draft.  Rule C only ever meant "an in-progress
    # draft must not block *work*"; it never meant "report a broken chain as ok".
    # Escalating it here makes the projection agree with the three write entries
    # (acceptance-record / finish-run / migration), which already refuse.
    state["integrity_errors"] = list(chain_problems)
    return state


def _acceptance_defined_data(data: dict) -> bool:
    """Whether the live object is more than init's empty placeholder."""
    return bool(acceptance_items(data) or data.get("defined_at")
                or data.get("archive_index") is not None
                or data.get("revision_history") or data.get("revisions"))


def _acceptance_presence_markers(root: Path, version_id: str) -> list[str]:
    """Find independent witnesses that acceptance was formally born.

    This read-only probe is intentionally small: append-only facts, the revision
    slot, and an existing completed closure are already part of the project
    ledger.  It lets a missing live/history pair remain distinguishable from an
    init-created empty placeholder without inventing another schema.
    """
    markers: list[str] = []
    for event_type in ("acceptance_defined", "acceptance_recorded"):
        if _events_of(root, event_type, version_id):
            markers.append(event_type)
    revision_dir = _acceptance_revision_dir(root, version_id)
    if revision_dir.exists():
        markers.append("acceptance-revisions")
    for path in sorted((root / "versions" / version_id / "runs").glob("*/run.json")):
        try:
            run = load_json(path)
        except Exception:
            continue
        if run.get("status") == "completed" and (
                isinstance(run.get("closure"), dict)
                or isinstance(run.get("acceptance_snapshot"), dict)):
            markers.append("completed acceptance closure")
            break
    return markers


def _acceptance_presence_failure(version_id: str, reason: str,
                                 markers: list[str]) -> str:
    suffix = "；正式存在见证：%s" % ",".join(markers) if markers else ""
    return "验收清单/历史存在性损坏（版本 %s）：%s%s" % (version_id, reason, suffix)


def _acceptance_state(root: Path, version: dict, project: dict, require_run: str = "") -> dict:
    """Non-raising evaluation of the *live* (active draft) checklist."""
    version_id = version.get("version_id")
    state = {"defined": False, "version_id": version_id, "required_count": 0,
             "counts": {k: 0 for k in ACCEPTANCE_STATUSES}, "pending": [],
             "failed_items": [], "stale": [], "unsettled": [], "passed": [],
             "complete": False,
             "acceptance_sha256": None, "target_sha256": version.get("sha256"),
             "chain": [], "chain_problems": [], "integrity_errors": [],
             "reasons": [], "proof_level": PROOF_LEVEL,
             "proof_limits": list(PROOF_LIMITS)}
    path = _acceptance_path(root, version_id)
    try:
        data = load_acceptance(root, version_id, project["project_id"])
    except Exception as exc:
        markers = _acceptance_presence_markers(root, version_id)
        # A valid init-created empty placeholder is the only unborn state.  Once
        # a formal witness exists, a missing/corrupt live file is integrity loss,
        # never a fresh pending checklist.
        if path.exists() or markers:
            detail = _acceptance_presence_failure(version_id, "%s: %s" %
                                                  (type(exc).__name__, exc), markers)
            state["defined"] = True
            state["reasons"].append(detail)
            state["chain_problems"].append(detail)
            state["integrity_errors"] = [detail]
        else:
            state["reasons"].append("未定义验收清单：当前版本仍处于合法 pending")
        return state
    state["defined"] = _acceptance_defined_data(data)
    state["acceptance_sha256"] = sha256_file(str(path))
    # The checklist must stay bound to the current version target.
    bound_problems: list[str] = []
    if data.get("target_sha256") != (version.get("sha256") or None):
        bound_problems.append("acceptance.target_sha256 与当前版本目标不符")
    chain, chain_problems = _acceptance_chain(root, version_id, data)
    state["chain"] = chain
    chain_problems = bound_problems + chain_problems
    chain_problems += _acceptance_record_mismatch(root, version, data, chain)
    state["chain_problems"] = list(chain_problems)
    return _merge_items_state(state, _acceptance_items_state(root, version, project, data,
                                                             require_run=require_run),
                              chain_problems)


def _revision_state(root: Path, version: dict, project: dict, data: dict,
                    self_sha: str, require_run: str = "") -> dict:
    """Evaluate one *fixed* revision: its own chain, items and evidence replay.

    This is what a completed run/migration is re-verified against, so later
    legal revisions of the same version can never make an old completion stale,
    while a hand-edited live head still fails chain validation elsewhere.
    """
    state = {"defined": True, "version_id": version.get("version_id"),
             "required_count": 0,
             "counts": {k: 0 for k in ACCEPTANCE_STATUSES}, "pending": [],
             "failed_items": [], "stale": [], "unsettled": [], "passed": [],
             "complete": False,
             "acceptance_sha256": self_sha, "target_sha256": version.get("sha256"),
             "chain": [], "chain_problems": [], "integrity_errors": [],
             "reasons": [], "proof_level": PROOF_LEVEL,
             "proof_limits": list(PROOF_LIMITS)}
    bound_problems: list[str] = []
    if data.get("target_sha256") != (version.get("sha256") or None):
        bound_problems.append("acceptance.target_sha256 与当前版本目标不符")
    if data.get("schema") != ACCEPTANCE_SCHEMA or data.get("version_id") != state["version_id"]:
        bound_problems.append("不可覆盖修订身份无效")
    if data.get("project_id") != project["project_id"]:
        bound_problems.append("不可覆盖修订 project_id 不匹配")
    chain, chain_problems = _revision_lineage(root, state["version_id"], data, self_sha)
    state["chain"] = chain
    chain_problems = bound_problems + chain_problems
    chain_problems += _acceptance_record_mismatch(root, version, data, chain)
    state["chain_problems"] = list(chain_problems)
    return _merge_items_state(state, _acceptance_items_state(root, version, project, data,
                                                             require_run=require_run),
                              chain_problems)


def _acceptance_snapshot(root: Path, version: dict, project: dict, require_run: str = "",
                         captured_at: str = "") -> dict:
    """Consume the acceptance snapshot; execution requires a full pass.

    require_run binds every pass witness to one run (run completion); an empty
    value accepts any completed/active run of the same version (migration).

    The completion gate and ``resume`` share the same evidence consistency core
    (:func:`_evidence_integrity`), so a completion can never be written while
    the evidence it consumes is already inconsistent.  A violated precondition
    raises *before* any ``run_finished`` event or completed migration exists.
    """
    verify_target(root, version)
    state = _acceptance_state(root, version, project, require_run=require_run)
    if not state["complete"]:
        detail = "; ".join(list(state["reasons"]) + list(state["chain_problems"]))
        raise ValueError("验收未完成：%s" % (detail or
                                            "pending=%d failed=%d stale=%d" % (len(state["pending"]),
                                                                                 len(state["failed_items"]),
                                                                                 len(state["stale"]))))
    integrity = _evidence_integrity(root, version, project["project_id"])
    if integrity:
        raise ValueError("证据一致性核验失败：%s" % "; ".join(integrity))
    snapshot = {"schema": ACCEPTANCE_SNAPSHOT_SCHEMA, "version_id": version["version_id"],
                "target_sha256": version.get("sha256"), "target_size": version.get("size"),
                "acceptance_sha256": state["acceptance_sha256"],
                "acceptance_chain": list(state["chain"]),
                "evidence_sha256": {e["evidence_id"]: e["sha256"]
                                    for r in state["passed"] for e in r["evidence"]},
                "evidence_local_path": {e["evidence_id"]: e["local_path"]
                                        for r in state["passed"] for e in r["evidence"]},
                "required": state["passed"], "required_count": state["required_count"],
                "run_id": require_run or None,
                "counts": state["counts"], "captured_at": captured_at or now(),
                "proof_level": PROOF_LEVEL, "proof_limits": list(PROOF_LIMITS)}
    return snapshot


def _expected_snapshot(record: dict, owner: dict, state: dict, require_run: str,
                       actual_acceptance: str | None) -> dict:
    """Rebuild the *whole* snapshot object from live state for comparison.

    Nothing is whitelisted: every field the producer writes is reproduced, so
    display-only fields (``target_size``/``proof_level``/``proof_limits``) are
    checked exactly like hash fields.  ``captured_at`` is taken from
    ``closure.recorded_at``, which is itself covered by the sealed object and
    pinned to the append-only completion event.
    """
    closure = record.get("closure") or {}
    return {"schema": ACCEPTANCE_SNAPSHOT_SCHEMA,
            "version_id": owner["version_id"],
            "target_sha256": owner.get("sha256"),
            "target_size": owner.get("size"),
            "acceptance_sha256": actual_acceptance,
            "acceptance_chain": list(state["chain"]),
            "evidence_sha256": {e["evidence_id"]: e["sha256"]
                                for r in state["passed"] for e in r["evidence"]},
            "evidence_local_path": {e["evidence_id"]: e["local_path"]
                                    for r in state["passed"] for e in r["evidence"]},
            "required": [dict(row) for row in state["passed"]],
            "required_count": state["required_count"],
            "run_id": require_run or None,
            "counts": state["counts"],
            "captured_at": closure.get("recorded_at"),
            "proof_level": PROOF_LEVEL,
            "proof_limits": list(PROOF_LIMITS)}


def _snapshot_differences(recorded, expected) -> list[str]:
    """Name the snapshot fields that disagree (no silent whole-object verdict)."""
    if not isinstance(recorded, dict):
        return ["<snapshot not an object>"]
    keys = sorted(set(recorded) | set(expected))
    return [key for key in keys if recorded.get(key) != expected.get(key)]


@project_locked("project", recover=True)
def cmd_acceptance_define(a) -> int:
    root = project_root(a.project)
    try:
        project = require_project(root)
        version = _validate_version(root, a.version, project["project_id"])
        items = []
        seen = set()
        for raw in a.item or []:
            item_id, sep, description = raw.partition(":")
            if not sep:
                return fail("acceptance", "--item 格式应为 id:description：%s" % raw)
            item_id = require_id(item_id.strip(), "acceptance id")
            description = description.strip()
            if not description:
                return fail("acceptance", "验收项 description 不得为空：%s" % item_id)
            if item_id in seen:
                return fail("acceptance", "验收清单重复 id：%s" % item_id)
            seen.add(item_id)
            items.append({"id": item_id, "description": description, "required": True,
                          "status": "pending", "evidence_ids": [], "result": None})
        if not items:
            return fail("acceptance", "验收清单不得为空：至少需要一个 required 项")
        data = {"schema": ACCEPTANCE_SCHEMA, "project_id": project["project_id"],
                "version_id": a.version, "target_sha256": version.get("sha256"),
                "items": items, "defined_at": now(), "note": a.note or "",
                "revisions": 0, "revision_history": [], "archive_index": [],
                "proof_level": PROOF_LEVEL, "proof_limits": list(PROOF_LIMITS)}
        path = _acceptance_path(root, a.version)
        log_path = _chain_log_path(root, a.version)
        if not path.exists():
            markers = _acceptance_presence_markers(root, a.version)
            return fail("acceptance", _acceptance_presence_failure(
                a.version, "缺少 acceptance.json，拒绝重新定义/重建", markers))
        if log_path.exists():
            logged, log_problems = _read_chain_log(root, a.version)
            if log_problems:
                return fail("acceptance", "验收写链日志已损坏，拒绝重新定义：%s" %
                            "; ".join(log_problems))
        else:
            logged = []
        existing = load_acceptance(root, a.version, project["project_id"])
        if _acceptance_defined_data(existing):
            _, existing_problems = _acceptance_chain(root, a.version, existing)
            if existing_problems:
                return fail("acceptance", "验收正式历史不可复核，拒绝重新定义：%s" %
                            "; ".join(existing_problems))
        if path.exists():
            current_items = [{k: x.get(k) for k in ("id", "description", "required")}
                             for x in acceptance_items(existing)]
            requested = [{k: x.get(k) for k in ("id", "description", "required")} for x in items]
            untouched = all(x.get("status") == "pending" and not x.get("evidence_ids")
                            for x in acceptance_items(existing))
            if untouched and current_items == requested:
                print(json.dumps({"ok": True, "idempotent": True, "acceptance": existing}, ensure_ascii=False))
                return 0
            # Only the untouched placeholder (empty item list) may be filled in.
            if acceptance_items(existing) or existing.get("revisions"):
                return fail("acceptance", "验收清单已定义且已开始记录结果；不可覆盖（历史修订需保留）")
            previous_bytes = path.read_bytes()
            genesis = hashlib.sha256(previous_bytes).hexdigest()
            data["archive_index"] = [genesis]
            data["revision_history"] = []
            data["revisions"] = 0
            if logged and logged != [genesis]:
                return fail("acceptance", "验收写链日志与定义状态不一致，拒绝覆盖：%s" % a.version)
        archive_path = _acceptance_revision_path(root, a.version, genesis)
        with metadata_transaction(root, [path, archive_path, log_path, root / "facts.jsonl", root / "handoff.json"]):
            _archive_acceptance(root, a.version, previous_bytes)
            if not logged:
                _append_chain_log(root, a.version, genesis, 0)
                logged = [genesis]
            write_acceptance(root, a.version, data, log_seq=len(logged))
            write_event(root, "acceptance_defined", "定义验收清单 %s（%d 项）" % (a.version, len(items)), a.version, "")
            write_handoff(root)
        print(json.dumps({"ok": True, "acceptance": data, "proof_level": PROOF_LEVEL}, ensure_ascii=False))
        return 0
    except Exception as exc:
        return fail("acceptance", "%s: %s" % (type(exc).__name__, exc))


@project_locked("project", recover=True)
def cmd_acceptance_record(a) -> int:
    root = project_root(a.project)
    try:
        project = require_project(root)
        version = _validate_version(root, a.version, project["project_id"])
        if a.result not in ACCEPTANCE_RESULTS:
            return fail("acceptance", "非法结果：%s；允许值：%s" % (a.result, ",".join(ACCEPTANCE_RESULTS)))
        data = load_acceptance(root, a.version, project["project_id"])
        items = acceptance_items(data)
        target = next((x for x in items if x.get("id") == a.item_id), None)
        if target is None:
            return fail("acceptance", "验收项不存在：%s" % a.item_id)
        if data.get("target_sha256") != (version.get("sha256") or ""):
            return fail("acceptance", "验收清单绑定的目标哈希与当前版本不符")
        evidence_ids = [x for x in (a.evidence_ids or "").split(",") if x]
        for evidence_id in evidence_ids:
            require_id(evidence_id, "evidence id")
        verifier = (a.verifier or "").strip()
        how = (a.how or "").strip()
        if not verifier or not how:
            return fail("acceptance", "必须提供 verifier 与 how（检查来源与方式）")
        if a.result == "pass":
            verify_target(root, version)
            if not evidence_ids:
                return fail("acceptance", "pass 必须至少登记一条证据")
            probe = {"evidence_ids": evidence_ids,
                     "origin": {"version_id": a.version, "run_id": a.run or None}}
            ok, problems, valid, ineligible = _evidence_verdict(root, probe, version,
                                                               project["project_id"])
            if not ok:
                # A new pass never accepts a witness from a non-completing run:
                # the refusal stays, but it is worded as ineligibility (not as
                # a damaged file).
                detail = "; ".join(problems + ineligible)
                if ineligible and not problems:
                    return fail("acceptance", "pass 证据不具备完成资格：%s" % detail)
                return fail("acceptance", "pass 证据无效：%s" % detail)
        # Main-agent ruling 1: an acceptance result belongs to one real *active*
        # run.  Once a run is completed/failed/blocked/cancelled its acceptance is
        # frozen — the command is refused and nothing (checklist, revision chain,
        # events) is written.  New project facts need a new run.
        if not a.run:
            return fail("acceptance", "必须用 --run 绑定真实 run：验收结果不得脱离运行批次登记")
        try:
            bound_run, _ = _run_record(root, a.version, a.run)
        except Exception as exc:
            return fail("acceptance", "绑定的 run 不可用：%s: %s" % (type(exc).__name__, exc))
        if bound_run.get("status") != "active":
            return fail("acceptance", "run %s 当前状态是 %s：已收尾 run 的验收不可再修改"
                        "（完成/失败/取消后验收冻结，新事实请开新 run）"
                        % (a.run, bound_run.get("status")))
        # Append-only revision: validate the existing immutable chain first (a
        # damaged or stripped chain must fail closed, never be repaired in
        # place), then archive the live bytes so they become a predecessor of
        # the state about to be written.
        previous_path = _acceptance_path(root, a.version)
        previous_bytes = previous_path.read_bytes()
        previous_sha = sha256_file(str(previous_path))
        current_chain, chain_problems = _acceptance_chain(root, a.version, data,
                                                         current_sha=previous_sha)
        if chain_problems:
            return fail("acceptance", "验收修订链已损坏，拒绝在损坏链上继续记录：%s" %
                        "; ".join(chain_problems))
        # Validate the independent append-only log before any archive/write.
        logged, log_problems = _read_chain_log(root, a.version)
        if log_problems or not logged:
            return fail("acceptance", "验收写链日志不可用，拒绝记录：%s" %
                        "; ".join(log_problems or ["日志为空"]))
        # Ruling 5: the write entries and resume share one audit over the whole
        # existing formal ledger.  If another completed record is already broken,
        # this write is refused instead of producing a "write ok / resume red".
        conflicts = _write_gate_conflicts(root, version_id=a.version, run_id=a.run or "")
        if conflicts:
            return _write_gate_failure("acceptance", conflicts)
        # Idempotence avoids writes, never integrity checks: identical arguments
        # cannot make a damaged live head/history acceptable.
        origin = target.get("origin") if isinstance(target.get("origin"), dict) else {}
        if (target.get("status") == a.result and target.get("evidence_ids") == evidence_ids
                and target.get("verifier") == verifier and target.get("how") == how
                and (origin.get("run_id") or "") == (a.run or "")):
            print(json.dumps({"ok": True, "idempotent": True, "acceptance": data,
                              "proof_level": PROOF_LEVEL}, ensure_ascii=False))
            return 0
        predecessors = list(current_chain)
        target.update({"status": a.result, "result": a.result, "evidence_ids": evidence_ids,
                       "verifier": verifier, "how": how, "recorded_at": now(),
                       "origin": {"version_id": a.version, "run_id": a.run or None,
                                  "target_sha256": data.get("target_sha256")},
                       "revision": int(target.get("revision") or 0) + 1})
        data["updated_at"] = now()
        data["revisions"] = len(predecessors) - 1
        data["revision_history"] = sorted(predecessors[1:])
        data["archive_index"] = predecessors
        archive_path = _acceptance_revision_path(root, a.version, previous_sha)
        with metadata_transaction(root, [previous_path, archive_path, _chain_log_path(root, a.version),
                                         root / "facts.jsonl", root / "handoff.json"]):
            _archive_acceptance(root, a.version, previous_bytes)
            new_sha = write_acceptance(root, a.version, data, log_seq=len(logged))
            if new_sha != sha256_file(str(previous_path)):
                raise ValueError("验收修订写入后校验失败：%s" % new_sha)
            write_event(root, "acceptance_recorded", "验收项 %s：%s" % (a.item_id, a.result), a.version, a.run or "")
            write_handoff(root)
        print(json.dumps({"ok": True, "acceptance": data,
                          "proof_level": PROOF_LEVEL,
                          "proof_limits": list(PROOF_LIMITS),
                          "previous_sha256": previous_sha}, ensure_ascii=False))
        return 0
    except Exception as exc:
        return fail("acceptance", "%s: %s" % (type(exc).__name__, exc))


@project_locked("project", recover=True)
def cmd_finish_run(a) -> int:
    root = project_root(a.project)
    try:
        project = require_project(root)
        require_id(a.version, "version")
        require_id(a.run_id, "run_id")
        path = root / "versions" / a.version / "runs" / a.run_id / "run.json"
        if not path.is_file():
            return fail("run", "运行批次不存在：%s" % path)
        run = load_json(path)
        if run.get("schema") != RUN_SCHEMA or run.get("run_id") != a.run_id or run.get("version_id") != a.version:
            return fail("run", "run.json 身份无效：%s" % path)
        if run.get("status") != "active":
            # Backward-compatible failure semantics; repeated completion is rejected.
            return fail("run", "只能结束 active run，当前状态是：%s（重复完成也拒绝，历史快照不可覆盖）" % run.get("status"))
        # A completion may be recorded at most once per run, whatever the current
        # status projection claims: an already-completed run must not gain a
        # second closure event (and a hand-rolled status edit must not either).
        previous_events = _run_finished_events(root, a.version, a.run_id)
        if any(_event_status(event) == "completed" for event in previous_events):
            return fail("run", "该 run 已有 completed 完成事件，拒绝重复写入完成快照：%s" % a.run_id)
        if a.status not in RUN_END_STATUSES:
            return fail("run", "非法结束状态：%s；允许值：%s" % (a.status, ",".join(RUN_END_STATUSES)))
        # Rule A': the shared write gate refuses any terminal transition that a
        # residual formal witness (closure/snapshot of this run, or a completion
        # event the projection denies) already contradicts.  A failure may not
        # be "explained away" as failed/blocked/cancelled either: the conflict is
        # reported and nothing is written.
        conflicts = _write_gate_conflicts(root, run_id=a.run_id)
        if conflicts:
            return _write_gate_failure("run", conflicts)
        snapshot = None
        stamp = now()
        if a.status == "completed":
            version = _validate_version(root, a.version, project["project_id"])
            if not version.get("sha256"):
                return fail("run", "当前版本无目标哈希，无法核验验收证据")
            try:
                snapshot = _acceptance_snapshot(root, version, project, require_run=a.run_id,
                                                captured_at=stamp)
            except Exception as exc:
                return fail("run", "completed 被拒绝：%s: %s" % (type(exc).__name__, exc))
        run["status"] = a.status
        run["finished_at"] = stamp
        run["finish_note"] = a.note
        run.pop("closure", None)
        run.pop("acceptance_snapshot", None)
        if snapshot is not None:
            run["closure"] = {"kind": "run-completed", "recorded_at": run["finished_at"],
                              "seal_sha256": None,
                              "target_sha256": snapshot["target_sha256"],
                              "acceptance_sha256": snapshot["acceptance_sha256"],
                              "acceptance_chain": snapshot["acceptance_chain"],
                              "evidence_sha256": snapshot["evidence_sha256"],
                              "required_count": snapshot["required_count"],
                              "proof_level": PROOF_LEVEL}
            run["acceptance_snapshot"] = snapshot
        seal = None
        if snapshot is not None:
            seal = closure_seal(run)
            run["closure"]["seal_sha256"] = seal
        with metadata_transaction(root, [path, root / "facts.jsonl", root / "handoff.json"]):
            atomic_json(path, run)
            event = write_event(root, "run_finished", "运行批次 %s：%s" % (a.run_id, a.status),
                                a.version, a.run_id,
                                extra={"status": a.status, "closure_sha256": seal,
                                       "closure_kind": run["closure"]["kind"] if seal else None})
            write_handoff(root)
        print(json.dumps({"ok": True, "run": run, "event": event["id"],
                          "closure_sha256": seal,
                          "proof_level": PROOF_LEVEL if snapshot else None}, ensure_ascii=False))
        return 0
    except Exception as exc:
        return fail("run", "%s: %s" % (type(exc).__name__, exc))


def _has_unresolved(value) -> bool:
    if value is None or value is False or value == 0 or value == "":
        return False
    if isinstance(value, str) and value.strip().lower() in ("0", "false", "none", "null", "no"):
        return False
    return bool(value)


def _validate_version(root: Path, version_id: str, project_id: str) -> dict:
    require_id(version_id, "version")
    path = project_file(root, "versions/%s/version.json" % version_id)
    if not path.is_file():
        raise FileNotFoundError("版本不存在：%s" % version_id)
    data = load_json(path)
    if data.get("schema") != VERSION_SCHEMA or data.get("version_id") != version_id:
        raise ValueError("版本身份校验失败：%s" % version_id)
    if data.get("project_id") != project_id:
        raise ValueError("版本 project_id 不匹配：%s" % version_id)
    kind = str(data.get("kind") or "file")
    if kind not in T.KINDS:
        raise ValueError("版本 target kind 未知，拒绝 file fallback")
    if "identity" in data and not isinstance(data["identity"], dict):
        raise ValueError("版本 target identity 必须是对象")
    if kind != "file" or data.get("identity") or any(data.get(key) is not None
            for key in ("sha256", "size", "target_sha256", "target_size")):
        target_identity_fields(data)
    if kind == "url_descriptor":
        T.verify_url_descriptor(data)
    elif kind == "directory" and (not data.get("snapshot_tree_ref") or not data.get("manifest_ref")):
        raise ValueError("目录版本缺少 snapshot 引用")
    if "local_path" in data and data.get("local_path") is not None \
            and data.get("local_path") != relative_ref(data["local_path"]):
        raise ValueError("版本 local_path 必须是相对路径：%s" % version_id)
    asset_ids = data.get("asset_ids", [])
    auxiliary = data.get("auxiliary_asset_ids", [])
    for label, values in (("asset_ids", asset_ids), ("auxiliary_asset_ids", auxiliary)):
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise ValueError("版本 %s 必须是资产 ID 列表" % label)
        if len(set(values)) != len(values):
            raise ValueError("版本 %s 包含重复资产 ID" % label)
        for value in values:
            require_id(value, label)
    primary = data.get("primary_asset_id")
    if primary and (not isinstance(primary, str) or primary not in asset_ids):
        raise ValueError("版本 primary_asset_id 不在资产列表中")
    if any(value not in asset_ids or value == primary for value in auxiliary):
        raise ValueError("版本 auxiliary_asset_ids 与资产列表/主资产不一致")
    # Enumerating existing asset.json files cannot detect a deleted descriptor.
    # Follow the version's declared references as well, without reading origins.
    for asset_id in asset_ids:
        target_identity_fields(_asset_record(root, asset_id))
    return data


def _validate_manifest(root: Path, version_id: str, project_id: str) -> dict:
    require_id(version_id, "version")
    path = project_file(root, "versions/%s/manifest.json" % version_id)
    if not path.is_file():
        raise FileNotFoundError("版本 manifest 不存在：%s" % version_id)
    data = load_json(path)
    if data.get("schema") != "seep-version-manifest/1" or data.get("version_id") != version_id:
        raise ValueError("manifest 身份校验失败：%s" % version_id)
    if data.get("project_id") != project_id:
        raise ValueError("manifest project_id 不匹配：%s" % version_id)
    return data


def _aob_hits(data: bytes, text: str) -> list[int]:
    tokens = text.replace(",", " ").split()
    if not tokens:
        raise ValueError("AOB 为空")
    pattern = []
    for token in tokens:
        if token in ("?", "??"):
            pattern.append(None)
        elif len(token) == 2 and all(c in "0123456789abcdefABCDEF" for c in token):
            pattern.append(int(token, 16))
        else:
            raise ValueError("AOB 非法")
    if all(x is None for x in pattern):
        raise ValueError("AOB 不能全通配")
    hits = []
    for i in range(len(data) - len(pattern) + 1):
        if all(v is None or data[i + j] == v for j, v in enumerate(pattern)):
            hits.append(i)
            if len(hits) == 2:
                break
    return hits


def validate_alignment(root: Path, align: dict, source: dict, target: dict) -> None:
    """Recheck positioning evidence, never treat a unique AOB as acceptance."""
    if any(_has_unresolved(align.get(key)) for key in UNRESOLVED_ALIGN_KEYS):
        raise ValueError("align 带未解决的顶层标记")
    if align.get("schema") != "seep-migration-align/1":
        raise ValueError("align schema 无效")
    if align.get("old_version") != source["version_id"] or align.get("new_version") != target["version_id"]:
        raise ValueError("align old/new 版本不匹配")
    old_data = verify_file(root, source).read_bytes()
    new_data = verify_file(root, target).read_bytes()
    for key, version in (("old_binary", source), ("new_binary", target)):
        binary = align.get(key)
        if not isinstance(binary, dict) or any(binary.get(k) != version.get(k) for k in ("sha256", "size")):
            raise ValueError("align 双方哈希/大小不匹配：%s" % key)
    baseline_path = root / "versions" / source["version_id"] / "reverse-baseline.json"
    if not baseline_path.exists():
        baseline_path = baseline_path.with_name("manifest.json")
    baseline = load_json(baseline_path)
    if baseline.get("schema") not in ("seep-reverse-baseline/1", "seep-migration/1"):
        raise ValueError("缺少 reverse baseline")
    if (baseline.get("version") != source["version_id"] or
            any(baseline.get("binary", {}).get(k) != source.get(k) for k in ("sha256", "size"))):
        raise ValueError("reverse baseline 版本/哈希不匹配")
    if baseline.get("binary", {}).get("local_path"):
        verify_file(root, baseline["binary"])
    sites = baseline.get("sites")
    rows = align.get("sites")
    if not isinstance(sites, list) or not sites or not isinstance(rows, list) or not rows:
        raise ValueError("align sites 不得为空")
    ids = [s.get("id") for s in sites]
    row_ids = [r.get("id") for r in rows]
    if not all(isinstance(i, str) and i for i in ids) or len(set(ids)) != len(ids) or set(row_ids) != set(ids) or len(row_ids) != len(ids):
        raise ValueError("align 位点集合不匹配")
    expected = {s: sum(r.get("status") == s for r in rows)
                for s in ("unique", "missing", "multi", "needs_manual")}
    summary = align.get("summary")
    if not isinstance(summary, dict) or set(summary) != set(expected):
        raise ValueError("align summary 字段无效")
    if any(type(summary[k]) is not int or summary[k] != v for k, v in expected.items()):
        raise ValueError("align summary 与 sites 不一致")
    if expected["unique"] != len(rows):
        raise ValueError("align 有 missing/multi/manual 或未知状态")
    by_id = {r["id"]: r for r in rows}
    for site in sites:
        pattern = str(site.get("aob") or "")
        old_hits = _aob_hits(old_data, pattern)
        old_offset = int(str(site.get("offset")), 0)
        if old_hits != [old_offset]:
            raise ValueError("基线 AOB 唯一性/offset 校验失败")
        hits = _aob_hits(new_data, pattern)
        row = by_id[site["id"]]
        if len(hits) != 1 or type(row.get("matches")) is not int or row["matches"] != 1:
            raise ValueError("unique 不是可复核的定位候选")
        reported = row.get("hits")
        if not isinstance(reported, list) or len(reported) != 1 or int(str(reported[0].get("offset")), 0) != hits[0]:
            raise ValueError("align offset 与实际命中不一致")


@project_locked("project", recover=True)
def cmd_migration(a) -> int:
    root = project_root(a.project)
    try:
        project = require_project(root)
        if a.source == a.target:
            return fail("migration", "source 和 target 不能相同")
        source = _validate_version(root, a.source, project["project_id"])
        target = _validate_version(root, a.target, project["project_id"])
        _validate_manifest(root, a.source, project["project_id"])
        _validate_manifest(root, a.target, project["project_id"])
        if source.get("version_id") == target.get("version_id"):
            return fail("migration", "source/target 版本校验失败：版本号相同")
        align = {}
        if a.align:
            align = load_json(Path(a.align))
        if a.status not in MIGRATION_STATUSES:
            return fail("migration", "非法迁移状态：%s；允许值：%s" % (a.status, ",".join(MIGRATION_STATUSES)))
        snapshot = None
        stamp = now()
        if a.status == "completed":
            if not a.align:
                return fail("migration", "completed 必须提供合法 align")
            if not target.get("sha256"):
                return fail("migration", "当前目标无哈希，无法核验验收证据")
            try:
                validate_alignment(root, align, source, target)
                snapshot = _acceptance_snapshot(root, target, project, captured_at=stamp)
            except Exception as exc:
                return fail("migration", "completed 被拒绝：%s: %s" % (type(exc).__name__, exc))
        elif a.align:
            validate_alignment(root, align, source, target)
        migration_id = a.migration_id or ("mig-%s-to-%s-%s" % (a.source, a.target, uuid.uuid4().hex[:6]))
        require_id(migration_id, "migration_id")
        # Rule A'/D: same shared gate as finish-run.  The target version's own
        # ledger must not already contradict a completion (e.g. an archived
        # completed revision, or a residual closure whose event was deleted), and
        # a new revision may not be registered to launder such a conflict.
        conflicts = _write_gate_conflicts(root, version_id=a.target)
        if conflicts:
            return _write_gate_failure("migration", conflicts)
        data = {"schema": MIGRATION_SCHEMA, "migration_id": migration_id,
                "project_id": project["project_id"], "from_version": a.source,
                "to_version": a.target,
                "source_manifest": relative_ref("versions/%s/manifest.json" % a.source),
                "target_manifest": relative_ref("versions/%s/manifest.json" % a.target),
                "source_sha256": source.get("sha256"), "target_sha256": target.get("sha256"),
                "align": align, "status": a.status, "created_at": stamp, "note": a.note,
                "revision_id": "rev-" + uuid.uuid4().hex}
        if snapshot is not None:
            data["closure"] = {"kind": "migration-completed", "recorded_at": data["created_at"],
                               "seal_sha256": None,
                               "target_sha256": snapshot["target_sha256"],
                               "acceptance_sha256": snapshot["acceptance_sha256"],
                               "acceptance_chain": snapshot["acceptance_chain"],
                               "evidence_sha256": snapshot["evidence_sha256"],
                               "required_count": snapshot["required_count"],
                               "align_sha256": hashlib.sha256(
                                   json.dumps(align, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest(),
                               "proof_level": PROOF_LEVEL}
            data["acceptance_snapshot"] = snapshot
        # Each completed revision is sealed once.  A repeated write of the same
        # revision_id (only possible through a hand edit) is rejected, and a
        # legacy immutable revision archive is never overwritten.
        previous_events = _migration_events(root, data["revision_id"])
        if any(_event_status(event) == "completed" for event in previous_events):
            return fail("migration", "该迁移修订已有 completed 完成事件，拒绝重复写入完成快照：%s"
                        % data["revision_id"])
        seal = None
        if snapshot is not None:
            seal = closure_seal(data)
            data["closure"]["seal_sha256"] = seal
        # Retain every revision and publish its projection/event/handoff together.
        from lib.project_transaction import file_transaction
        revisions = project_file(root, "versions/%s/migrations" % a.target)
        previous_path = project_file(root, "versions/%s/migration.json" % a.target)
        previous_archive = None
        if previous_path.exists():
            previous = load_json(previous_path)
            previous_revision = previous.get("revision_id")
            if not previous_revision:
                previous_revision = "legacy-" + sha256_file(str(previous_path))
            require_id(previous_revision, "revision_id")
            archive = project_file(root, "versions/%s/migrations/%s.json" % (a.target, previous_revision))
            if not archive.exists():
                previous_archive = (archive, previous_path.read_bytes())
        revision_path = revisions / (data["revision_id"] + ".json")
        if revision_path.exists():
            raise ValueError("迁移修订路径已存在，拒绝覆盖历史")
        write_set = [relative_ref(str(revision_path.relative_to(root))),
                     relative_ref(str(previous_path.relative_to(root))), "facts.jsonl", "handoff.json"]
        if previous_archive:
            write_set.append(relative_ref(str(previous_archive[0].relative_to(root))))
        with file_transaction(root, write_set):
            if previous_archive:
                atomic_bytes(*previous_archive)
            atomic_json(revision_path, data)
            atomic_json(previous_path, data)
            event = write_event(root, "migration_recorded", "%s -> %s：%s" % (a.source, a.target, a.status),
                                a.target, "",
                                extra={"status": a.status, "migration_id": migration_id,
                                       "revision_id": data["revision_id"],
                                       "closure_sha256": seal,
                                       "closure_kind": data["closure"]["kind"] if seal else None})
            write_handoff(root)
        print(json.dumps({"ok": True, "migration": data, "event": event["id"],
                          "closure_sha256": seal}, ensure_ascii=False))
        return 0
    except Exception as exc:
        return fail("migration", "%s: %s" % (type(exc).__name__, exc))


def _validate_fact(value: dict, project_id: str) -> None:
    """Validate shared fact fields without closing the vocabulary of custom events."""
    if value.get("schema") != FACTS_SCHEMA:
        raise ValueError("unexpected schema")
    if value.get("project_id") != project_id:
        raise ValueError("fact project identity mismatch")
    if not isinstance(value.get("created_at"), str) or not value["created_at"].strip():
        raise ValueError("fact created_at must be a nonempty string")
    kind = value.get("kind")
    if kind == "state":
        if not isinstance(value.get("status"), str) or not value["status"].strip():
            raise ValueError("state status must be a nonempty string")
        return
    if kind != "event":
        raise ValueError("unknown fact kind")
    if not isinstance(value.get("id"), str):
        raise ValueError("event id must be a string")
    require_id(value["id"], "event id")
    if not isinstance(value.get("type"), str) or not value["type"].strip():
        raise ValueError("event type must be a nonempty string")
    if not isinstance(value.get("message"), str):
        raise ValueError("event message must be a string")
    for key in ("version_id", "run_id", "migration_id", "revision_id"):
        if value.get(key) is not None:
            if not isinstance(value[key], str):
                raise ValueError("event %s must be a string or null" % key)
            require_id(value[key], key)
    if value["type"] in ("run_started", "run_finished"):
        if not value.get("version_id") or not value.get("run_id"):
            raise ValueError("run event requires version_id and run_id")
    if value["type"] in ("run_finished", "migration_recorded"):
        statuses = RUN_END_STATUSES if value["type"] == "run_finished" else MIGRATION_STATUSES
        if ("status" in value and not isinstance(value["status"], str)
                or _event_status(value) not in statuses):
            raise ValueError("invalid terminal event status")
        if value["type"] == "migration_recorded" and not value.get("version_id"):
            raise ValueError("migration event requires version_id")
    for key in ("closure_sha256",):
        if value.get(key) is not None and not _is_sha256(value[key]):
            raise ValueError("invalid %s" % key)


def read_fact_log(root: Path) -> tuple[list[dict], list[dict]]:
    project = require_project(root)
    try:
        path = project_file(root, "facts.jsonl")
        payload = path.read_bytes()
    except (OSError, ValueError) as exc:
        return [], [{"line": 0, "reason": "facts.jsonl unreadable: %s" % exc}]
    events = []
    errors = []
    seen = set()
    for no, raw in enumerate(payload.splitlines(), 1):
        if not raw.strip():
            errors.append({"line": no, "reason": "blank line"})
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            errors.append({"line": no, "reason": "invalid utf-8: %s" % exc})
            continue
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            errors.append({"line": no, "reason": "invalid json: %s" % exc.msg})
            continue
        if not isinstance(value, dict):
            errors.append({"line": no, "reason": "record is not a JSON object"})
            continue
        try:
            _validate_fact(value, project["project_id"])
            if value.get("kind") == "event":
                if value["id"] in seen:
                    raise ValueError("duplicate event id: %s" % value["id"])
                seen.add(value["id"])
        except ValueError as exc:
            errors.append({"line": no, "reason": str(exc)})
            continue
        events.append(value)
    return events, errors


def read_events(root: Path) -> list[dict]:
    return read_fact_log(root)[0]


def _events_of(root: Path, event_type: str, version_id: str = "", key: str = "",
               value: str = "") -> list[dict]:
    """Select append-only events by type/version and one identity field."""
    selected = []
    for event in read_events(root):
        if event.get("type") != event_type:
            continue
        if version_id and event.get("version_id") != version_id:
            continue
        if key and event.get(key) != value:
            continue
        selected.append(event)
    return selected


def _run_finished_events(root: Path, version_id: str, run_id: str) -> list[dict]:
    return _events_of(root, "run_finished", version_id, "run_id", run_id)


def _migration_events(root: Path, revision_id: str) -> list[dict]:
    """Events of one migration *revision* (a migration_id may be revised)."""
    return _events_of(root, "migration_recorded", "", "revision_id", revision_id)


def _read_runs(root: Path) -> tuple[list[dict], list[dict]]:
    runs = []
    errors = []
    for path in sorted((root / "versions").glob("*/runs/*/run.json")):
        try:
            value, _ = _run_record(root, path.parent.parent.parent.name, path.parent.name)
            runs.append(value)
        except Exception as exc:
            errors.append({"path": relative_ref(str(path.relative_to(root))), "reason": str(exc)})
    runs.sort(key=lambda x: (x.get("started_at", ""), x.get("run_id", "")))
    return runs, errors


def _read_migrations(root: Path) -> tuple[list[dict], list[dict], dict]:
    """Read every on-disk migration record, keeping *all* copies per revision.

    ``migrations`` is the de-duplicated report list (first copy of a revision
    wins, exactly as before); ``copies`` maps one revision id to every file that
    carries it (the mutable ``migration.json`` projection *and* the immutable
    ``migrations/<revision>.json`` archive).  The audit needs the copies: a
    projection edit must not be able to hide a completed archive copy.
    """
    migrations = []
    errors = []
    copies: dict[str, list[dict]] = {}
    project_id = require_project(root)["project_id"]
    paths = list((root / "versions").glob("*/migrations/*.json"))
    paths += list((root / "versions").glob("*/migration.json"))
    for path in sorted(paths):
        try:
            path = project_file(root, path.relative_to(root).as_posix())
            value = load_json(path)
            version = path.parent.parent.name if path.parent.name == "migrations" else path.parent.name
            if value.get("schema") != MIGRATION_SCHEMA or value.get("to_version") != version:
                raise ValueError("migration target identity mismatch")
            if value.get("project_id") != project_id:
                raise ValueError("migration project identity mismatch")
            for key in ("migration_id", "from_version", "to_version"):
                if not isinstance(value.get(key), str):
                    raise ValueError("migration %s must be a string" % key)
                require_id(value[key], key)
            if value["from_version"] == version:
                raise ValueError("migration source and target must differ")
            if not isinstance(value.get("status"), str) or value["status"] not in MIGRATION_STATUSES:
                raise ValueError("invalid migration status")
            if not isinstance(value.get("created_at"), str) or not value["created_at"].strip():
                raise ValueError("migration created_at must be a nonempty string")
            if "align" in value and not isinstance(value["align"], dict):
                raise ValueError("migration align must be an object")
            for prefix, owner in (("source", value["from_version"]), ("target", version)):
                canonical = _validate_version(root, owner, project_id)
                manifest_key = prefix + "_manifest"
                expected = "versions/%s/manifest.json" % owner
                if manifest_key in value:
                    if value[manifest_key] != expected:
                        raise ValueError("migration %s identity mismatch" % manifest_key)
                    project_file(root, expected)
                hash_key = prefix + "_sha256"
                if hash_key in value and value[hash_key] != canonical.get("sha256"):
                    raise ValueError("migration %s identity mismatch" % hash_key)
            revision = value.get("revision_id")
            if "revision_id" in value:
                if not isinstance(revision, str):
                    raise ValueError("migration revision_id must be a string")
                require_id(revision, "revision_id")
            if path.parent.name == "migrations":
                if revision and path.stem != revision:
                    raise ValueError("migration revision/archive filename mismatch")
                # Old archives were sometimes reserialized; their name's digest
                # cannot establish byte integrity. Keep them readable as legacy.
                if not revision and not (path.stem.startswith("legacy-") and _is_sha256(path.stem[7:])):
                    raise ValueError("invalid legacy migration archive filename")
            identity = (str(revision) if revision
                        else "anon:" + relative_ref(str(path.relative_to(root))))
            group = copies.setdefault(identity, [])
            if group and any(value.get(key) != group[0].get(key) for key in
                             ("project_id", "migration_id", "from_version", "to_version",
                              "source_manifest", "target_manifest", "source_sha256", "target_sha256")):
                errors.append({"path": path.relative_to(root).as_posix(),
                               "reason": "migration revision copies have conflicting identity"})
            group.append(value)
            if len(group) == 1:
                migrations.append(value)
        except Exception as exc:
            errors.append({"path": relative_ref(str(path.relative_to(root))), "reason": str(exc)})
    migrations.sort(key=lambda x: x.get("created_at", ""))
    return migrations, errors, copies


def _residual_closure(record: dict) -> bool:
    """A stored closure/snapshot is itself a formal (residual) completion witness.

    Deleting the append-only event does not turn a recorded completion back into
    "never completed": the sealed closure object survives in ``run.json`` /
    ``migration.json`` and is a residual witness the projection may not deny.
    """
    return (isinstance(record.get("closure"), dict)
            or isinstance(record.get("acceptance_snapshot"), dict))


def _missing_witness(record: dict, label: str, ident: str, events: list[dict],
                     has_pass: bool, errors: list[dict], legacy: list[dict],
                     forced: bool = False, why: str = "") -> None:
    """Rule C/D: a completed claim without a verifiable witness is never ok.

    It stays legacy/unverified (readable, blocked, rc=2) when the ledger proves
    it was a pre-closure historical record; when *any* formal witness exists (an
    event carrying a seal, a pass checklist, several events, a residual
    closure/snapshot object, or ``forced`` for a caller-known witness such as an
    immutable completed revision copy) the missing or damaged closure is reported
    as an error instead of being laundered back into "legacy".
    """
    completed_events = [event for event in events if _event_status(event) == "completed"]
    witnessed = [event for event in completed_events if event.get("closure_sha256")]
    residual = _residual_closure(record)
    multi = len(completed_events) > 1
    if witnessed or has_pass or multi or residual or forced:
        detail = ("完成事件存在但收尾快照缺失/损坏" if witnessed or multi
                  else "目标版本存在 pass 验收记录")
        if residual and not (witnessed or multi):
            detail = "存在残留收尾记录（closure/acceptance_snapshot）"
        if forced and not (witnessed or multi or residual):
            detail = why or "存在其他不可覆盖的完成见证"
        if has_pass and witnessed:
            detail += "，且当前存在 pass 验收记录"
        errors.append({"reason": "%s 缺少可复核收尾见证（%s）：%s"
                                 % (label, detail, ident),
                       "witnessed": bool(witnessed), "events": len(completed_events),
                       "residual": residual})
    else:
        # Rule C: historical compatibility means *readable*, never auto-verified.
        reason = "历史 completed 无验收收尾记录，不作为已验收"
        legacy.append({"kind": label, "id": ident, "verified": False, "reason": reason})
        errors.append({"reason": "%s 为未验证的历史完成记录（%s）：%s" % (label, reason, ident),
                       "legacy": True})


def _verify_snapshot(root: Path, project: dict, record: dict, owner: dict, label: str,
                     ident: str, errors: list[dict]) -> dict:
    """Re-verify a completion against the *fixed* revision it consumed.

    A completed run/migration is bound to ``closure.acceptance_sha256``.  That
    revision (archived ``acceptance-revisions/rev-<sha>.json``, or the live file
    when nothing was appended afterwards) is replayed together with the original
    evidence files, so a later *legal* revision of the same version neither
    rewrites nor invalidates the earlier completion.  The live head is still
    audited separately: a hand-edited checklist (no legal appended revision)
    leaves the project blocked.
    """
    closure = record.get("closure")
    snapshot = record.get("acceptance_snapshot")
    require_run = ident if label == "completed run" else ""
    version_id = owner["version_id"]
    if owner.get("sha256") != closure.get("target_sha256"):
        errors.append({"reason": "%s 的目标哈希已变：%s" % (label, ident)})
    if not isinstance(snapshot, dict):
        errors.append({"reason": "%s 的验收收尾快照缺失/无效：%s" % (label, ident)})
    consumed_sha = closure.get("acceptance_sha256")
    if not _is_sha256(consumed_sha):
        errors.append({"reason": "%s 的 closure.acceptance_sha256 无效：%s" % (label, ident)})
        return {}
    # 1. The consumed revision must still exist and be re-checkable.
    try:
        fixed = _revision_document(root, version_id, consumed_sha)
    except Exception as exc:
        live_path = _acceptance_path(root, version_id)
        live_sha = sha256_file(str(live_path)) if live_path.is_file() else None
        if live_sha is not None and live_sha != consumed_sha:
            errors.append({"reason": "%s 完成后当前清单已变（stale）：消费的不可覆盖修订"
                                     "已不可复核：%s（%s）" % (label, ident, exc),
                           "recorded": consumed_sha, "current": live_sha})
        else:
            errors.append({"reason": "%s 消费的不可覆盖验收修订不存在或不可复核：%s（%s）"
                                     % (label, ident, exc),
                           "revision": consumed_sha})
        return {}
    state = _revision_state(root, owner, project, fixed, consumed_sha,
                            require_run=require_run)
    # 2. The consumed chain must be exactly the chain that revision recomputes.
    derived_chain = list(state["chain"])
    consumed = closure.get("acceptance_chain")
    if consumed is not None:
        if not isinstance(consumed, list) or not consumed:
            errors.append({"reason": "%s 消费的历史修订记录无效：%s" % (label, ident)})
        else:
            if len(consumed) != len(set(consumed)):
                errors.append({"reason": "%s 消费修订出现重复：%s" % (label, ident)})
            if derived_chain and list(consumed) != derived_chain:
                errors.append({"reason": "%s 消费了非不可覆盖链上的修订（与修订自身链不一致）：%s"
                                         % (label, ident),
                               "recorded": list(consumed), "derived": derived_chain})
    if isinstance(snapshot, dict):
        snapshot_chain = snapshot.get("acceptance_chain")
        if snapshot_chain is not None and (not derived_chain
                                           or snapshot_chain != derived_chain):
            errors.append({"reason": "%s 的验收快照修订链不可复算：%s" % (label, ident)})
    # 3. Evidence hashes and witness rows are re-derived from the real files.
    expected_evidence = {e["evidence_id"]: e["sha256"]
                         for r in state["passed"] for e in r["evidence"]}
    if closure.get("evidence_sha256") != expected_evidence:
        errors.append({"reason": "%s 的证据哈希与真实证据索引不符：%s" % (label, ident),
                       "recorded": closure.get("evidence_sha256"),
                       "expected": expected_evidence})
    if closure.get("required_count") != state["required_count"]:
        errors.append({"reason": "%s 的 required_count 与消费修订不符：%s" % (label, ident)})
    if isinstance(snapshot, dict):
        expected_snapshot = _expected_snapshot(record, owner, state, require_run, consumed_sha)
        if snapshot != expected_snapshot:
            errors.append({"reason": "%s 的验收快照与当前验收/证据不符：%s" % (label, ident),
                           "fields": _snapshot_differences(snapshot, expected_snapshot)})
    # 4. The consumed revision itself must still be a complete, intact pass.
    if state["stale"]:
        errors.append({"reason": "%s 的验收证据已失效：%s" % (label, ident),
                       "stale": [x["id"] for x in state["stale"]]})
    if state["integrity_errors"]:
        errors.append({"reason": "%s 的验收记录链不可复算：%s" % (label, ident),
                       "integrity": list(state["integrity_errors"])})
    if not state["complete"]:
        errors.append({"reason": "%s 消费的验收修订未处于完整 pass 状态：%s" % (label, ident),
                       "reasons": list(state["reasons"])})
    # 5. The live checklist head is the *draft* for new runs: it may legally move
    # past this revision, but it must still be a reproducible chain state.  A
    # hand edit (no appended revision) blocks instead of re-interpreting history.
    path = _acceptance_path(root, version_id)
    if path.is_file():
        live_sha = sha256_file(str(path))
        try:
            live = load_acceptance(root, version_id, project["project_id"])
            _, live_problems = _acceptance_chain(root, version_id, live,
                                                 current_sha=live_sha)
        except Exception as exc:
            live_problems = ["当前验收清单不可读：%s: %s" % (type(exc).__name__, exc)]
        if live_problems:
            reason = "%s 所在版本的当前验收清单头不可复核（手改或剥离历史）" % label
            if live_sha != consumed_sha:
                reason = "%s 完成后当前清单已变（stale）且不可复核" % label
            errors.append({"reason": "%s：%s" % (reason, ident),
                           "problem": list(live_problems)})
    # 6. Evidence consistency: the *same* core the completion gate uses, so a
    # record accepted at completion time can never disagree at resume time.
    for problem in _evidence_integrity(root, owner, project["project_id"]):
        errors.append({"reason": "%s 的%s：%s" % (label, problem, ident)})
    return state


def _audit_closure(root: Path, project: dict, record: dict, owner: dict | None, label: str,
                   ident: str, expected_events: list[dict], errors: list[dict],
                   legacy: list[dict]) -> None:
    """Audit one *current-completed* record against the ledger and real files."""
    closure = record.get("closure")
    closure_events = [event for event in expected_events
                      if _event_status(event) == "completed"]
    owner_state = (_acceptance_state(root, owner, project,
                                     require_run=ident if label == "completed run" else "")
                   if owner is not None else None)
    has_pass = bool(owner_state and owner_state["counts"].get("pass"))
    multi = len(closure_events) > 1
    if not isinstance(closure, dict) or not isinstance(record.get("acceptance_snapshot"), dict):
        _missing_witness(record, label, ident, expected_events, has_pass, errors, legacy)
        return
    if owner is None:
        errors.append({"reason": "%s 的版本不存在：%s" % (label, ident)})
        return
    try:
        verify_target(root, owner)
    except Exception as exc:
        errors.append({"reason": "%s 的目标不可复核：%s（%s）" % (label, ident, exc)})
    if multi:
        errors.append({"reason": "%s 存在多条 completed 完成事件，收尾不可复核：%s"
                                 % (label, ident), "events": len(closure_events)})
    # Rule B: the whole closure object is sealed; the independent witness is the
    # append-only ledger, so a sealed record cannot vouch for itself.
    recorded_seal = closure.get("seal_sha256")
    if not _is_sha256(recorded_seal):
        errors.append({"reason": "%s 的收尾未绑定完整性封条：%s" % (label, ident)})
    else:
        recomputed = closure_seal(record)
        if recomputed != recorded_seal:
            errors.append({"reason": "%s 的整对象封条不可复算（closure/snapshot 被改）：%s"
                                     % (label, ident),
                           "recorded": recorded_seal, "recomputed": recomputed})
        event_seals = [event.get("closure_sha256") for event in closure_events
                       if event.get("closure_sha256")]
        if not event_seals:
            errors.append({"reason": "%s 的完成事件未绑定收尾封条（无可复核见证）：%s"
                                     % (label, ident)})
        elif recorded_seal not in event_seals:
            errors.append({"reason": "%s 的收尾封条与完成事件不一致：%s" % (label, ident),
                           "recorded": recorded_seal, "events": event_seals})
    _verify_snapshot(root, project, record, owner, label, ident, errors)


def _audit_run(root: Path, project: dict, versions: list[dict], run: dict,
               errors: list[dict], legacy: list[dict]) -> None:
    """Runs: the terminal state must match every residual formal witness."""
    ident = str(run.get("run_id"))
    version_id = str(run.get("version_id"))
    status = run.get("status")
    events = _run_finished_events(root, version_id, ident)
    completed = [event for event in events if _event_status(event) == "completed"]
    owner = next((v for v in versions if v.get("version_id") == version_id), None)
    if status == "completed":
        _audit_closure(root, project, run, owner, "completed run", ident, events, errors, legacy)
        return
    if completed:
        # Rule D: a completion event the run projection denies.  The current
        # status alone is never the authority.
        errors.append({"reason": "run %s 的完成事件与当前状态矛盾（当前 %s）：账本记录过 completed"
                                 % (ident, status)})
        return
    if _residual_closure(run):
        # Rule A': residual closure/snapshot is a formal witness on its own.  The
        # projection may not be rewritten to active/failed/blocked/cancelled and
        # then re-opened as "never completed" (that is the laundering gap).
        owner_state = _acceptance_state(root, owner, project,
                                        require_run=ident) if owner is not None else None
        has_pass = bool(owner_state and owner_state["counts"].get("pass"))
        errors.append({"reason": "run %s 存在残留收尾记录（closure/acceptance_snapshot）但状态为 %s、"
                                 "且无对应完成事件：完成不可否认，不可按未完成继续写入/验收"
                                 % (ident, status), "residual": True})
        _missing_witness(run, "completed run", ident, events, has_pass, errors, legacy)


def _migration_copy_problems(group: list[dict], record: dict, events: list[dict]) -> list[str]:
    """Every on-disk copy of one revision must agree about having completed."""
    problems = []
    completed_events = [event for event in events if _event_status(event) == "completed"]
    for copy in group:
        if copy is record:
            continue
        if copy.get("status") == "completed" and record.get("status") != "completed":
            problems.append("不可覆盖修订副本仍记录 completed，但当前投影为 %s"
                            % record.get("status"))
            continue
        if copy.get("status") == "completed" and copy.get("closure") != record.get("closure"):
            problems.append("不可覆盖修订副本的收尾与当前投影不一致")
            continue
        if _residual_closure(copy) and not _residual_closure(record):
            problems.append("不可覆盖修订副本仍保留收尾记录（closure/acceptance_snapshot）")
            continue
        if _residual_closure(copy) and not completed_events:
            problems.append("不可覆盖修订副本保留收尾记录但无对应完成事件")
    return problems


def _audit_migration(root: Path, project: dict, versions: list[dict], migration: dict,
                     group: list[dict], errors: list[dict], legacy: list[dict]) -> None:
    """Migrations: same rules as runs, plus the immutable revision copies."""
    revision_id = migration.get("revision_id")
    ident = str(migration.get("migration_id") or revision_id)
    status = migration.get("status")
    events = _migration_events(root, str(revision_id)) if revision_id else []
    completed = [event for event in events if _event_status(event) == "completed"]
    owner = next((v for v in versions if v.get("version_id") == migration.get("to_version")),
                 None)
    if status == "completed":
        _audit_closure(root, project, migration, owner, "completed migration", ident,
                       events, errors, legacy)
        for problem in _migration_copy_problems(group, migration, events):
            errors.append({"reason": "migration %s 的%s：不可覆盖历史不得被投影掩盖"
                                     % (ident, problem), "residual": True})
        return
    if completed:
        errors.append({"reason": "migration %s 的完成事件与当前状态矛盾（当前 %s）：账本记录过 completed"
                                 % (ident, status)})
        return
    problems = _migration_copy_problems(group, migration, events)
    if problems or _residual_closure(migration):
        owner_state = _acceptance_state(root, owner, project) if owner is not None else None
        has_pass = bool(owner_state and owner_state["counts"].get("pass"))
        if _residual_closure(migration):
            errors.append({"reason": "migration %s 存在残留收尾记录（closure/acceptance_snapshot）"
                                     "但状态为 %s、且无对应完成事件：完成不可否认，不可按未完成继续写入"
                                     % (ident, status), "residual": True})
        for problem in problems:
            errors.append({"reason": "migration %s 的%s：不可覆盖历史不得被投影掩盖"
                                     % (ident, problem), "residual": True})
        _missing_witness(migration, "completed migration", ident, events, has_pass,
                         errors, legacy, forced=bool(problems),
                         why="不可覆盖修订副本仍为完成见证")


def _audit_ledger(root: Path, project: dict, versions: list[dict], runs: list[dict],
                  migrations: list[dict], copies: dict[str, list[dict]],
                  run_ids: set[str] | None = None,
                  migration_targets: set[str] | None = None) -> tuple[list[dict], list[dict]]:
    """The single closure-audit used by ``resume`` *and* both write gates.

    Sharing one implementation is the point: a completion the gate accepts must
    never be something ``resume`` then calls inconsistent (and vice versa).
    """
    errors: list[dict] = []
    legacy: list[dict] = []
    on_disk_runs = {(str(run.get("version_id")), str(run.get("run_id"))) for run in runs}
    for run in runs:
        if run_ids is not None and str(run.get("run_id")) not in run_ids:
            continue
        _audit_run(root, project, versions, run, errors, legacy)
    for event in _events_of(root, "run_finished"):
        if _event_status(event) != "completed":
            continue
        identity = (str(event.get("version_id")), str(event.get("run_id")))
        if identity in on_disk_runs or run_ids is not None and identity[1] not in run_ids:
            continue
        errors.append({"reason": "run 完成事件对应的运行记录缺失：%s/%s" % identity})
    on_disk_revisions = set()
    for migration in migrations:
        revision_id = str(migration.get("revision_id"))
        on_disk_revisions.add(revision_id)
        if (migration_targets is not None
                and str(migration.get("to_version")) not in migration_targets):
            continue
        _audit_migration(root, project, versions, migration,
                         copies.get(revision_id, [migration]), errors, legacy)
    for event in _events_of(root, "migration_recorded"):
        revision_id = event.get("revision_id")
        if not revision_id or _event_status(event) != "completed":
            continue
        if str(revision_id) in on_disk_revisions:
            continue
        if (migration_targets is not None
                and str(event.get("version_id")) not in migration_targets):
            continue
        # Rule D: the ledger proves a completion whose revision record is gone.
        errors.append({"reason": "migration 完成事件对应的不可覆盖修订记录缺失：%s" % revision_id})
    return errors, legacy


def _load_ledger(root: Path) -> dict:
    """Read the ledger once for the shared audit (versions/runs/migrations/copies)."""
    project = require_project(root)
    versions = []
    errors = []
    for p in sorted((root / "versions").glob("*/version.json")):
        try:
            value = _validate_version(root, p.parent.name, project["project_id"])
            versions.append(value)
        except Exception as exc:
            errors.append({"reason": "version 元数据不可复核：%s（%s）" % (p.parent.name, exc)})
    runs, run_errors = _read_runs(root)
    migrations, migration_errors, copies = _read_migrations(root)
    _, fact_errors = read_fact_log(root)
    errors.extend(run_errors + migration_errors + fact_errors)
    return {"project": project, "versions": versions, "runs": runs,
            "migrations": migrations, "copies": copies, "errors": errors}


def _write_gate_conflicts(root: Path, version_id: str = "", run_id: str = "") -> list[str]:
    """Shared pre-write validation for ``finish-run``, ``migration`` and ``acceptance-record``.

    The write entries and ``resume`` run the *same* audit over the **whole**
    formal ledger (every run and every migration revision), not just the record
    being written: accepting a write that leaves another completed record stale
    would produce a "write ok / resume red" split.  ``version_id``/``run_id`` are
    kept for call-site readability only and never narrow the audit.

    Nothing is repaired or back-filled: the write is simply refused.  A record
    with *no* formal witness at all (pre-closure history) keeps the project
    blocked at resume time (rule C) but is not itself a contradiction, which is
    the documented historical-compatibility behaviour.  Only conflicts with a
    real witness (residual closure/snapshot, sealed event, immutable completed
    copy, stale completion) refuse the write.
    """
    del version_id, run_id  # scope is the whole ledger on purpose
    ledger = _load_ledger(root)
    errors, _ = _audit_ledger(root, ledger["project"], ledger["versions"], ledger["runs"],
                              ledger["migrations"], ledger["copies"])
    return [str(item.get("reason")) for item in ledger["errors"] + errors if not item.get("legacy")]


def _write_gate_failure(stage: str, conflicts: list[str]) -> int:
    return fail(stage, "写入口与 resume 共用校验拒绝本次写入（不得通过新事件/新修订/非完成状态洗白）：%s"
                % "; ".join(conflicts))


def write_handoff(root: Path, *, persist: bool = True) -> dict:
    project = require_project(root)
    versions = []
    version_errors = []
    for p in sorted((root / "versions").glob("*/version.json")):
        try:
            value = _validate_version(root, p.parent.name, project["project_id"])
            versions.append(value)
        except Exception as exc:
            version_errors.append({"path": relative_ref(str(p.relative_to(root))), "reason": str(exc)})
    current_id = project.get("current_version_id")
    current = next((x for x in versions if x.get("version_id") == current_id), None)
    runs, run_errors = _read_runs(root)
    migrations, migration_errors, migration_copies = _read_migrations(root)
    events, fact_errors = read_fact_log(root)
    facts_path = root / "facts.jsonl"
    facts_hash = hashlib.sha256(facts_path.read_bytes()).hexdigest() if facts_path.exists() else None
    recent_run = runs[-1] if runs else None
    current_migration_path = root / "versions" / str(current_id) / "migration.json"
    current_migration = None
    if current_migration_path.is_file():
        try:
            current_migration = load_json(current_migration_path)
        except (ValueError, OSError):
            pass  # _read_migrations has already recorded the error.
    asset_errors = []
    for p in sorted((root / "assets").glob("*/asset.json")):
        try:
            value = _asset_record(root, p.parent.name)
            verify_target(root, value)
        except Exception as exc:
            asset_errors.append({"path": relative_ref(str(p.relative_to(root))), "reason": str(exc)})
    for version in versions:
        try:
            if version.get("sha256") or version.get("size") is not None:
                verify_target(root, version)
        except Exception as exc:
            asset_errors.append({"path": version.get("local_path"), "reason": str(exc)})
    for p in sorted((root / "versions").glob("*/reverse-baseline.json")):
        try:
            baseline = load_json(p)
            if baseline.get("schema") not in ("seep-reverse-baseline/1", "seep-migration/1") or baseline.get("version") != p.parent.name:
                raise ValueError("reverse baseline identity mismatch")
            verify_file(root, baseline.get("binary") or {})
            canonical = next((v for v in versions if v.get("version_id") == p.parent.name), None)
            if canonical and canonical.get("sha256"):
                _check_reverse_identity(root, p.parent.name, canonical, canonical.get("parent_version_id") or "")
                if (baseline.get("parent_version") or None) != canonical.get("parent_version_id"):
                    raise ValueError("reverse baseline parent mismatch")
        except Exception as exc:
            asset_errors.append({"path": relative_ref(str(p.relative_to(root))), "reason": str(exc)})
    errors = fact_errors + version_errors + run_errors + migration_errors + asset_errors
    if current is None:
        errors.append({"reason": "current version missing"})
    # Evidence / acceptance audit: structural only, never semantic success.
    # The manifest-index vs record vs raw-file cross-check is the *same* core the
    # completion gate uses (rule A); it is not re-implemented here.
    evidence_errors = []
    for manifest_path in sorted((root / "versions").glob("*/manifest.json")):
        version_id = manifest_path.parent.name
        problems = _evidence_index_problems(root, version_id)
        if problems:
            evidence_errors.append({"path": relative_ref(str(manifest_path.relative_to(root))),
                                    "reason": "; ".join(problems)})
    for p in sorted((root / "versions").glob("*/evidence/*.json")):
        try:
            record = load_json(p)
            version_id = p.parent.parent.name
            if record.get("schema") != EVIDENCE_SCHEMA or record.get("evidence_id") != p.stem:
                raise ValueError("evidence identity mismatch")
            if record.get("version_id") != version_id or record.get("project_id") != project["project_id"]:
                raise ValueError("evidence version/project mismatch")
            _evidence_path(root, record)
        except Exception as exc:
            evidence_errors.append({"path": relative_ref(str(p.relative_to(root))), "reason": str(exc)})
    acceptance = None
    acceptance_errors = []
    if current is not None:
        acceptance = _acceptance_state(root, current, project)
        # Ruling 1: raw-evidence integrity and completion eligibility are two
        # different things.  Only a witness that is broken/hand-edited/chained
        # inconsistently is an *integrity* error; a pass whose origin run simply
        # did not complete (failed/cancelled/blocked) is an unfinished, ineligible
        # draft and is reported as such instead of "evidence already invalid".
        if acceptance["stale"]:
            acceptance_errors.append({"reason": "当前版本验收证据完整性受损（原始证据被修改/缺失或记录链不可复算）：%s" %
                                                ",".join(x["id"] for x in acceptance["stale"]),
                                     "stale": [x["id"] for x in acceptance["stale"]],
                                     "kind": "integrity"})
        if acceptance["integrity_errors"]:
            acceptance_errors.append({"reason": "当前版本验收记录链不完整/不一致：%s" %
                                                "; ".join(acceptance["integrity_errors"]),
                                     "integrity": list(acceptance["integrity_errors"]),
                                     "kind": "integrity"})
    unsettled = list((acceptance or {}).get("unsettled") or [])
    unfinished_ids = sorted({x["id"] for x in (acceptance or {}).get("pending", [])
                             + (acceptance or {}).get("failed_items", []) + unsettled})
    closed_runs = [x for x in runs if x.get("status") == "completed"]
    closed_migrations = [x for x in migrations if x.get("status") == "completed"]
    closure_errors, closure_legacy = _audit_ledger(root, project, versions, runs,
                                                   migrations, migration_copies)
    errors = errors + evidence_errors + acceptance_errors + closure_errors
    next_actions = []
    if asset_errors or evidence_errors:
        next_actions.append("恢复本地资产、目标及证据文件，并核验 SHA256 后重新 resume")
    if acceptance_errors:
        next_actions.append("恢复被篡改或丢失的验收证据，并重新执行检查")
    if acceptance and not acceptance["complete"]:
        blocked_ids = unfinished_ids or [x["id"] for x in acceptance["stale"]]
        if blocked_ids:
            next_actions.append("继续处理未完成验收项：%s" % ",".join(blocked_ids))
    if unsettled:
        next_actions.append("验收项 %s 的记录完整但 origin run 已收尾为非完成状态："
                            "需新建 run 重新登记证据与验收（新 run 不继承旧 pass）"
                            % ",".join(sorted(x["id"] for x in unsettled)))
    if not (acceptance or {}).get("defined"):
        next_actions.append("定义当前版本非空 required 验收清单（acceptance define）")
    if closure_legacy:
        next_actions.append("历史 completed 无验收收尾记录：需重新验收后才能引用为已验收")
    if closure_errors:
        next_actions.append("恢复历史收尾所需验收证据，或重新执行相应检查后再完成")
    if fact_errors:
        next_actions.append("修复 facts.jsonl 损坏行后重新运行 handoff/resume")
    if current is None:
        next_actions.append("确认 project.current_version_id 对应的 version.json")
    if current_migration and current_migration.get("status") != "completed":
        next_actions.append("继续处理当前版本迁移对齐项：%s" % current_migration.get("status"))
    if recent_run and recent_run.get("status") == "active":
        next_actions.append("继续或结束最近 active run：%s" % recent_run.get("run_id"))
    elif recent_run and recent_run.get("status") in ("failed", "cancelled", "blocked"):
        # A normal non-completing ending is not corruption: explain it and point
        # at the recoverable path (a new run), never at "restore evidence".
        next_actions.append("最近 run %s 已合法收尾为 %s（非完成结果，不是数据完整性错误）："
                            "如需完成请新建 run 重新登记证据与验收（新 run 不继承旧 pass）"
                            % (recent_run.get("run_id"), recent_run.get("status")))
    if not next_actions:
        next_actions.append("从当前版本和最近 run 继续下一步工作")
    handoff = {
        "schema": HANDOFF_SCHEMA, "project_id": project["project_id"],
        "current_version_id": current_id,
        "current_version": ({"version_id": current.get("version_id"),
                              "parent_version_id": current.get("parent_version_id"),
                              "status": current.get("status"),
                              "kind": current.get("kind", "file"),
                              "identity": current.get("identity"),
                              "identity_scope": current.get("identity_scope"),
                              "remote_content_verified": current.get("remote_content_verified", False),
                              "sha256": current.get("sha256"),
                              "size": current.get("size"),
                              "local_path": current.get("local_path")} if current else None),

        "current_run_id": recent_run.get("run_id") if recent_run else None,
        "recent_run": recent_run,
        "active_runs": [x.get("run_id") for x in runs if x.get("status") == "active"],
        "migration_status": current_migration.get("status") if current_migration else "none",
        "migration": current_migration,
        "migrations": [{"migration_id": x.get("migration_id"),
                        "from_version": x.get("from_version"),
                        "to_version": x.get("to_version"),
                        "status": x.get("status")} for x in migrations],
        "status": "blocked" if errors else project.get("status", "active"),
        # Ruling 1: ``ok``/``active`` only ever means "the state is readable and
        # internally consistent", never "the target feature passed".  Business
        # completion is expressed by acceptance_complete/last_run_status.
        "state_health": "blocked" if errors else "ok",
        "integrity_errors": list(acceptance_errors) + list(closure_errors),
        "last_run_status": recent_run.get("status") if recent_run else None,
        "last_run_id": recent_run.get("run_id") if recent_run else None,
        "versions": [{"version_id": x.get("version_id"),
                       "parent_version_id": x.get("parent_version_id"),
                       "status": x.get("status"),
                       "kind": x.get("kind", "file"),
                       "identity_scope": x.get("identity_scope"),
                       "sha256": x.get("sha256"),
                       "size": x.get("size"), "local_path": x.get("local_path")} for x in versions],

        "facts_status": "corrupt" if fact_errors else "valid",
        "corrupt_fact_lines": [x.get("line") for x in fact_errors],
        "fact_errors": fact_errors,
        "facts_sha256": facts_hash,
        "source_facts_sha256": facts_hash,
        "state_errors": errors,
        "evidence_errors": evidence_errors,
        "acceptance": acceptance,
        "acceptance_errors": acceptance_errors,
        "acceptance_pending": [x["id"] for x in (acceptance or {}).get("pending", [])],
        "acceptance_failed": [x["id"] for x in (acceptance or {}).get("failed_items", [])],
        "acceptance_stale": [x["id"] for x in (acceptance or {}).get("stale", [])],
        # ``unsettled``: witness intact, origin run not completed.  The live draft
        # is unfinished/ineligible, *not* corrupt: no integrity error is raised.
        "acceptance_unsettled": [x["id"] for x in (acceptance or {}).get("unsettled", [])],
        "acceptance_unfinished": unfinished_ids,
        "acceptance_eligible": bool((acceptance or {}).get("complete")) and not errors,
        "acceptance_counts": (acceptance or {}).get("counts"),
        # Rule C: a completion claim is only ever "complete" when its closure is
        # itself re-checkable.  Any closure_errors (including legacy/unverified
        # historical records) keeps this false even if the checklist looks green.
        "acceptance_complete": bool((acceptance or {}).get("complete")) and not errors,
        "closure_errors": closure_errors,
        "closure_legacy": closure_legacy,
        "completed_runs": sorted({str(x.get("run_id")) for x in closed_runs}),
        "completed_migrations": sorted({str(x.get("migration_id")) for x in closed_migrations}),
        "proof_level": PROOF_LEVEL,
        "proof_limits": list(PROOF_LIMITS),
        "next_actions": next_actions,
        "event_count": len(events),
        "updated_at": now()
    }
    # --- staged report hook (integration_pending until the main agent merges) ---
    # The report ledger is *additive*: it can only make the handoff stricter.
    # Report presence never turns state_health/ok into true, and an existing
    # blocked/acceptance error is never displaced: the report's own errors are
    # always kept under handoff["report"]["errors"] and are merged into (never
    # substituted for) the existing state_errors list.
    report = _report_handoff_view(root)
    handoff["report"] = report
    report_errors = report.get("errors") or []
    if report_errors:
        handoff["state_errors"] = list(handoff["state_errors"]) + [
            item for item in report_errors if item not in handoff["state_errors"]]
        handoff["state_health"] = "blocked"
        handoff["status"] = "blocked"
        handoff["acceptance_eligible"] = False
        handoff["acceptance_complete"] = False
        handoff["next_actions"] = (list(handoff["next_actions"])
                                   + list(report.get("next_actions") or []))
    if persist:
        atomic_json(root / "handoff.json", handoff)
    return handoff


def _report_handoff_view(root: Path) -> dict:
    """Read-only report index / final-pointer projection (staged, not applied).

    Contract for the merged version:
      * must **not** take ``project_lock`` again (``write_handoff``'s callers
        already hold it, ``project_lock`` is not re-entrant across processes);
      * must **never** raise and must never echo an exception message (a message
        can carry a path or a value): only a fixed reason plus the exception
        *type* is reported, and a broken index is an explicit error, never
        "fresh";
      * report presence alone never makes the project ok.
    """
    try:
        from project_report import handoff_view
        return handoff_view(root)
    except Exception as exc:  # noqa: BLE001 - the hook may not break resume
        return {"schema": "seep-report-handoff/1", "wired": False,
                "integration_pending": False, "present": False,
                "registered": [], "current_final": None, "stale": [],
                "errors": [{"reason": "报告索引读取不可用（project_report.handoff_view 调用失败）",
                            "kind": "report_index",
                            "exception_type": type(exc).__name__}],
                "next_actions": ["检查 reports/index.jsonl 与 project_report.py 是否可用"]}


@project_locked("project")
def cmd_handoff(a) -> int:
    try:
        data = write_handoff(project_root(a.project))
        ok = not data.get("state_errors")
        print(json.dumps({"ok": ok, "handoff": data}, ensure_ascii=False, indent=2))
        return 0 if ok else 2
    except Exception as exc:
        return fail("handoff", "%s: %s" % (type(exc).__name__, exc))


@project_locked("project")
def cmd_resume(a) -> int:
    root = project_root(a.project)
    try:
        data = write_handoff(root)
        ok = not data.get("state_errors")
        print(json.dumps({"ok": ok, "project": require_project(root), "handoff": data}, ensure_ascii=False, indent=2))
        return 0 if ok else 2
    except Exception as exc:
        return fail("resume", "%s: %s" % (type(exc).__name__, exc))


def self_test() -> int:
    checks = []

    def record(name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError(name)
        checks.append(name)

    def quiet(callable_, *args):
        with contextlib.redirect_stdout(io.StringIO()):
            return callable_(*args)

    try:
        with tempfile.TemporaryDirectory(prefix="seep-project-") as td:
            base = Path(td)
            target1 = base / "target-1.bin"
            target2 = base / "target-2.bin"
            target1.write_bytes(b"sample-v1")
            target2.write_bytes(b"sample-v2")
            root = base / "project"
            init_args = argparse.Namespace(project=str(root), project_id="demo", title="Demo",
                                            domain="softseep,web-pentest", version="1.0", parent="",
                                            target=str(target1), asset_id="asset-main", force=False)
            record("init", quiet(cmd_init, init_args) == 0)
            asset = load_json(root / "assets/asset-main/asset.json")
            record("asset fingerprint", asset["sha256"] == sha256_file(str(target1)) and asset["size"] == target1.stat().st_size)
            record("asset relative local_path", not PurePosixPath(asset["local_path"]).is_absolute())
            version10 = load_json(root / "versions/1.0/version.json")
            record("version fingerprint", version10["target_sha256"] == asset["sha256"] and version10["size"] == asset["size"])
            record("version relative local_path", not PurePosixPath(version10["local_path"]).is_absolute())

            version_args = argparse.Namespace(project=str(root), version="1.1", parent="1.0",
                                               asset="", target="", force=False)
            record("version 1.0 to 1.1", quiet(cmd_version, version_args) == 0)
            asset_v11 = add_asset(root, "asset-v11", str(target2), "1.1", False)
            version11 = load_json(root / "versions/1.1/version.json")
            record("version 1.1 target", version11["target_sha256"] == asset_v11["sha256"])

            run_args = argparse.Namespace(project=str(root), version="1.1", run_id="run-test", executor="self-test")
            record("run start", quiet(cmd_run, run_args) == 0)
            record("duplicate run", quiet(cmd_run, run_args) == 2)
            finish_args = argparse.Namespace(project=str(root), version="1.1", run_id="run-test",
                                              status="completed", note="ok", force=False)
            record("reject unverified completed run", quiet(cmd_finish_run, finish_args) == 2)
            finish_args.status = "blocked"
            record("finish active run", quiet(cmd_finish_run, finish_args) == 0)
            record("finish non-active run", quiet(cmd_finish_run, finish_args) == 2)

            align_path = base / "align.json"
            atomic_json(align_path, {"missing": 1})
            bad_migration = argparse.Namespace(project=str(root), source="1.0", target="1.1",
                                                migration_id="mig-bad", align=str(align_path),
                                                status="completed", note="")
            record("reject illegal completed migration", quiet(cmd_migration, bad_migration) == 2)
            record("migration not created on rejection", not (root / "versions/1.1/migration.json").exists())
            good_migration = argparse.Namespace(project=str(root), source="1.0", target="1.1",
                                                migration_id="mig-test", align="", status="partial",
                                                note="one manual item")
            record("migration 1.0 to 1.1", quiet(cmd_migration, good_migration) == 0)
            record("target-owned migration", load_json(root / "versions/1.1/migration.json")["to_version"] == "1.1")

            # Evidence -> acceptance -> completion chain (structural only).
            run2 = argparse.Namespace(project=str(root), version="1.1", run_id="run-accept", executor="self-test")
            record("acceptance run start", quiet(cmd_run, run2) == 0)
            define = argparse.Namespace(project=str(root), version="1.1",
                                        item=["probe: synthetic probe recorded"], note="self-test")
            record("define acceptance", quiet(cmd_acceptance_define, define) == 0)
            record("identical redefinition is idempotent", quiet(cmd_acceptance_define, define) == 0)
            accept = argparse.Namespace(project=str(root), version="1.1", item_id="probe", result="pass",
                                        evidence_ids="", verifier="self-test", how="synthetic", run="run-accept")
            record("pass without evidence rejected", quiet(cmd_acceptance_record, accept) == 2)
            accept.result = "unknown"
            record("unknown recorded but not completion", quiet(cmd_acceptance_record, accept) == 0)
            finish2 = argparse.Namespace(project=str(root), version="1.1", run_id="run-accept",
                                         status="completed", note="", force=False)
            record("unknown acceptance blocks completion", quiet(cmd_finish_run, finish2) == 2)
            probe = root / "versions/1.1/artifacts/probe.log"
            probe.parent.mkdir(parents=True, exist_ok=True)
            probe.write_bytes(b"synthetic witness\n")
            digest = hashlib.sha256(probe.read_bytes()).hexdigest()
            target_sha = version11["target_sha256"]
            evidence = argparse.Namespace(project=str(root), version="1.1", run_id="run-accept",
                                          kind="evidence", evidence_id="ev-probe",
                                          target_sha256=target_sha, path="versions/1.1/artifacts/probe.log",
                                          sha256=digest, size=probe.stat().st_size,
                                          source="versions/1.1/artifacts/probe.log", how="synthetic",
                                          recorded_by="self-test")
            record("register evidence", quiet(cmd_evidence, evidence) == 0)
            record("duplicate evidence id idempotent", quiet(cmd_evidence, evidence) == 0)
            forged = argparse.Namespace(**{**vars(evidence), "evidence_id": "ev-forged", "target_sha256": "0" * 64})
            record("cross-target evidence rejected", quiet(cmd_evidence, forged) == 2)
            escaped = argparse.Namespace(**{**vars(evidence), "evidence_id": "ev-escape", "path": "../outside.log"})
            record("escaping evidence path rejected", quiet(cmd_evidence, escaped) == 2)
            accept.evidence_ids = "ev-probe"
            accept.result = "pass"
            record("pass with verified evidence", quiet(cmd_acceptance_record, accept) == 0)
            record("acceptance revision history kept",
                   len(load_json(root / "versions/1.1/acceptance.json")["revision_history"]) == 2 and
                   len(list((root / "versions/1.1/acceptance-revisions").glob("*.json"))) == 3)
            record("completed run allowed", quiet(cmd_finish_run, finish2) == 0)
            completed = load_json(root / "versions/1.1/runs/run-accept/run.json")
            record("closure snapshot recorded",
                   completed["closure"]["target_sha256"] == target_sha and
                   completed["closure"]["evidence_sha256"] == {"ev-probe": digest})
            record("repeat completion rejected", quiet(cmd_finish_run, finish2) == 2)
            record("repeat completion preserves bytes",
                   load_json(root / "versions/1.1/runs/run-accept/run.json") == completed)
            original = probe.read_bytes()
            probe.write_bytes(b"tampered witness\n")
            record("tampered evidence blocks resume", quiet(cmd_resume, argparse.Namespace(project=str(root))) == 2)
            tampered = load_json(root / "handoff.json")
            record("tampered evidence stale", tampered["status"] == "blocked" and
                   tampered["acceptance_stale"] == ["probe"] and not tampered.get("acceptance_complete"))
            record("tampered evidence blocks recompletion", quiet(cmd_finish_run, finish2) == 2)
            probe.write_bytes(original)
            record("restored evidence resumes", quiet(cmd_resume, argparse.Namespace(project=str(root))) == 0)

            handoff = load_json(root / "handoff.json")
            record("handoff current version", handoff["current_version_id"] == "1.1")
            record("handoff recent run", handoff["recent_run"]["run_id"] in ("run-test", "run-accept"))
            record("handoff completed runs", handoff["completed_runs"] == ["run-accept"])
            record("handoff no closure errors", handoff["closure_errors"] == [] and
                   handoff["acceptance_stale"] == [] and handoff["acceptance_complete"])
            record("handoff migration status", handoff["migration_status"] == "partial")
            record("handoff facts hash", handoff["facts_sha256"] == hashlib.sha256((root / "facts.jsonl").read_bytes()).hexdigest())
            record("handoff proof level recorded", handoff["proof_level"] == PROOF_LEVEL)
            corrupt_line = len((root / "facts.jsonl").read_bytes().splitlines()) + 1
            with open(root / "facts.jsonl", "ab") as f:
                f.write(b"{corrupt facts line\n")
            record("corrupt facts handoff", quiet(cmd_handoff, argparse.Namespace(project=str(root))) == 2)
            corrupt_handoff = load_json(root / "handoff.json")
            record("corrupt facts explicit", corrupt_handoff["facts_status"] == "corrupt" and corrupt_line in corrupt_handoff["corrupt_fact_lines"])
            record("corrupt facts resume", quiet(cmd_resume, argparse.Namespace(project=str(root))) == 2)
        print(json.dumps({"ok": True, "checks": len(checks), "conclusion": "project state self-test passed"}, ensure_ascii=True))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "checks": len(checks), "failed_check": str(exc)}, ensure_ascii=True))
        return 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Seep 长期项目/版本/运行批次状态层")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("init"); p.add_argument("--project", required=True); p.add_argument("--project-id", required=True)
    p.add_argument("--title", default=""); p.add_argument("--domain", default=""); p.add_argument("--version", default="1.0")
    p.add_argument("--parent", default=""); p.add_argument("--target", default=""); p.add_argument("--asset-id", default="asset-main"); p.add_argument("--force", action="store_true")
    p = sub.add_parser("asset"); p.add_argument("--project", required=True); p.add_argument("--asset-id", required=True); p.add_argument("--target", required=True); p.add_argument("--version", required=True); p.add_argument("--role", choices=["primary", "auxiliary"], default="auxiliary")
    p = sub.add_parser("version"); p.add_argument("--project", required=True); p.add_argument("--version", required=True); p.add_argument("--parent", default=""); p.add_argument("--asset", default=""); p.add_argument("--target", default=""); p.add_argument("--primary-asset", dest="primary_asset", default=""); p.add_argument("--aux-asset", dest="aux_asset", default=""); p.add_argument("--force", action="store_true")
    p = sub.add_parser("run"); p.add_argument("--project", required=True); p.add_argument("--version", required=True); p.add_argument("--run-id", default=""); p.add_argument("--executor", default="agent")
    p = sub.add_parser("finish-run"); p.add_argument("--project", required=True); p.add_argument("--version", required=True); p.add_argument("--run-id", required=True); p.add_argument("--status", required=True); p.add_argument("--note", default=""); p.add_argument("--force", action="store_true")
    p = sub.add_parser("event"); p.add_argument("--project", required=True); p.add_argument("--type", required=True); p.add_argument("--message", required=True); p.add_argument("--version", default=""); p.add_argument("--run", default="")
    p = sub.add_parser("evidence"); p.add_argument("--project", required=True); p.add_argument("--version", required=True); p.add_argument("--run-id", required=True); p.add_argument("--kind", default="evidence"); p.add_argument("--evidence-id", required=True); p.add_argument("--target-sha256", required=True); p.add_argument("--path", required=True); p.add_argument("--sha256", required=True); p.add_argument("--size", required=True); p.add_argument("--source", default=""); p.add_argument("--how", default=""); p.add_argument("--recorded-by", default="agent")
    p.add_argument("--input-asset", default="", help="已登记的本版本工具输入资产 ID")
    p.add_argument("--raw-output", default="", help="必须随证据保留的项目内原始输出文件")
    p = sub.add_parser("acceptance-define"); p.add_argument("--project", required=True); p.add_argument("--version", required=True); p.add_argument("--item", action="append", default=[]); p.add_argument("--note", default="")
    p = sub.add_parser("acceptance-record"); p.add_argument("--project", required=True); p.add_argument("--version", required=True); p.add_argument("--item-id", required=True); p.add_argument("--result", required=True); p.add_argument("--evidence-ids", default=""); p.add_argument("--verifier", default=""); p.add_argument("--how", default=""); p.add_argument("--run", default="")
    p = sub.add_parser("migration"); p.add_argument("--project", required=True); p.add_argument("--source", required=True); p.add_argument("--target", required=True); p.add_argument("--migration-id", default=""); p.add_argument("--align", default=""); p.add_argument("--status", default="partial", choices=list(MIGRATION_STATUSES)); p.add_argument("--note", default="")
    p = sub.add_parser("handoff"); p.add_argument("--project", required=True)
    p = sub.add_parser("resume"); p.add_argument("--project", required=True)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    try:
        if a.cmd == "init": return cmd_init(a)
        if a.cmd == "asset": return cmd_asset(a)
        if a.cmd == "version": return cmd_version(a)
        if a.cmd == "run": return cmd_run(a)
        if a.cmd == "finish-run": return cmd_finish_run(a)
        if a.cmd == "event": return cmd_event(a)
        if a.cmd == "evidence": return cmd_evidence(a)
        if a.cmd == "acceptance-define": return cmd_acceptance_define(a)
        if a.cmd == "acceptance-record": return cmd_acceptance_record(a)
        if a.cmd == "migration": return cmd_migration(a)
        if a.cmd == "handoff": return cmd_handoff(a)
        if a.cmd == "resume": return cmd_resume(a)
        ap.print_help(); return 4
    except Exception as exc:
        return fail(a.cmd or "args", "%s: %s" % (type(exc).__name__, exc))


if __name__ == "__main__":
    raise SystemExit(main())
