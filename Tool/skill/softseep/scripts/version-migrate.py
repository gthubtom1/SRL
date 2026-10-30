#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross-version reverse-engineering ledger and AOB alignment.

This is an incremental migration helper, not a claim that a new version is
already understood. It fingerprints each version, records semantic sites and
patch bytes, aligns wildcard AOBs in a new binary, and emits a report that
separates unique matches from misses and ambiguous matches.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import os
import re
import stat
import struct
import sys
import uuid
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


class _BootstrapError(Exception):
    def __init__(self, code: str, detail: str):
        self.code = code
        self.detail = detail
        super().__init__(detail)


def _path_value(value) -> Path:
    text = str(value or "").strip()
    if not text or "\x00" in text:
        raise _BootstrapError("runtime_missing", "runtime locator is empty or unusable")
    try:
        return Path(os.path.abspath(os.path.expanduser(text)))
    except (OSError, ValueError):
        raise _BootstrapError("runtime_missing", "runtime locator is unusable")


def _agent_root_value() -> Path:
    for key in ("PI_CODING_AGENT_DIR", "PI_AGENT_DIR"):
        value = str(os.environ.get(key) or "").strip()
        if value:
            return _path_value(value)
    return _path_value(Path.home() / ".pi" / "agent")


def _registered_runtime_root() -> Path:
    agent = _agent_root_value()
    origin = agent / "seep-runtime.json"
    if not origin.is_file():
        raise _BootstrapError("runtime_missing", "no runtime-origin registration")
    try:
        data = json.loads(origin.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise _BootstrapError("runtime_mismatch", "runtime-origin is not valid JSON")
    if not isinstance(data, dict):
        raise _BootstrapError("runtime_mismatch", "runtime-origin is not an object")
    source = data.get("source_root")
    if isinstance(source, str) and source.strip():
        return _path_value(source)
    relative = data.get("relative_root")
    if isinstance(relative, str) and relative.strip():
        rel = Path(relative.strip().replace("\\", "/"))
        if rel.is_absolute() or ".." in rel.parts:
            raise _BootstrapError("runtime_mismatch", "runtime-origin relative root escapes agent")
        return agent / rel
    raise _BootstrapError("runtime_missing", "runtime-origin has no runtime root")


def _runtime_helper_path():
    explicit = str(os.environ.get("SEEP_RUNTIME_ROOT") or "").strip()
    if explicit:
        # An explicit root is hard: even a missing helper must not fall through.
        return (_path_value(explicit) / "Tool" / "scripts" / "lib" / "runtime_root.py", False)

    script = Path(__file__).resolve()
    for parent in (script.parent, *script.parents):
        helper = parent / "Tool" / "scripts" / "lib" / "runtime_root.py"
        entry = parent / "Tool" / "skill" / "softseep" / "scripts" / "version-migrate.py"
        if helper.is_file() and entry.resolve() == script:
            return (helper, True)

    return (_registered_runtime_root() / "Tool" / "scripts" / "lib" / "runtime_root.py", False)


def _load_runtime_root():
    helper, is_source_entry = _runtime_helper_path()
    if not helper.is_file():
        raise _BootstrapError("runtime_missing", "runtime helper is not present")
    spec = importlib.util.spec_from_file_location("_seep_public_runtime_root", helper)
    if spec is None or spec.loader is None:
        raise _BootstrapError("runtime_missing", "runtime helper cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, is_source_entry


def _bootstrap_runtime():
    runtime_root, is_source_entry = _load_runtime_root()
    try:
        resolved = runtime_root.resolve_cli_runtime(
            script_path=__file__ if is_source_entry else None, env=os.environ
        )
    except Exception as exc:
        code = getattr(exc, "code", "runtime_missing")
        detail = getattr(exc, "detail", "runtime verification failed")
        raise _BootstrapError(code, detail)
    root = Path(resolved["runtime_root"]).resolve()
    scripts = root / "Tool" / "scripts"
    if any(not (scripts / "lib" / name).is_file()
           for name in ("project_lock.py", "project_transaction.py")):
        raise _BootstrapError("runtime_missing", "verified runtime has no shared lock/transaction")
    sys.path.insert(0, str(scripts))
    try:
        lock = importlib.import_module("lib.project_lock")
        transaction = importlib.import_module("lib.project_transaction")
    except Exception:
        raise _BootstrapError("runtime_missing", "shared lock/transaction module cannot be imported")
    required = ("atomic_copy", "project_file", "project_locked", "verify_file")
    if (any(not hasattr(lock, name) for name in required)
            or not callable(getattr(transaction, "file_transaction", None))):
        raise _BootstrapError("runtime_mismatch", "shared lock/transaction API is incomplete")
    return resolved, tuple(getattr(lock, name) for name in required), transaction.file_transaction


_BOOTSTRAP_ERROR = None
try:
    _RUNTIME, (_atomic_copy, _project_file, _project_locked, _verify_file), file_transaction = _bootstrap_runtime()
    atomic_copy = _atomic_copy
    project_file = _project_file
    project_locked = _project_locked
    verify_file = _verify_file
except Exception as exc:
    _BOOTSTRAP_ERROR = (getattr(exc, "code", "runtime_missing"),
                        getattr(exc, "detail", "runtime bootstrap failed"))

if _BOOTSTRAP_ERROR:
    # Keep module loading safe enough for argparse to emit structured failure;
    # command handlers are never reached while the public runtime is absent.
    def project_locked(_argument, *, recover=False):
        def decorate(function):
            return function
        return decorate


SCHEMA = "seep-reverse-baseline/1"
LEGACY_SCHEMA = "seep-migration/1"
HEX = re.compile(r"^[0-9a-fA-F]{2}$")
UI_APPLY_METHODS = ("overlay", "resource_replace", "code_patch", "server_content")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def pe_info(data: bytes) -> dict:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"format": "unknown"}
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            return {"format": "MZ"}
        machine, nsec, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, pe + 4)
        opt = pe + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic not in (0x10B, 0x20B):
            return {"format": "PE", "parse_error": True}
        image_base = struct.unpack_from("<Q" if magic == 0x20B else "<I", data,
                                        opt + (24 if magic == 0x20B else 28))[0]
        entry = struct.unpack_from("<I", data, opt + 16)[0]
        section_start = opt + opt_size
        sections = []
        for i in range(nsec):
            off = section_start + i * 40
            if off + 40 > len(data):
                break
            name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
            virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
            sections.append({"name": name, "virtual_size": virtual_size,
                             "virtual_address": virtual_addr, "raw_size": raw_size,
                             "raw_pointer": raw_ptr})
        return {"format": "PE32+" if magic == 0x20B else "PE32",
                "machine": {0x8664: "x64", 0x14C: "x86", 0xAA64: "arm64"}.get(machine, hex(machine)),
                "entry_rva": hex(entry), "image_base": hex(image_base), "sections": sections}
    except (IndexError, struct.error, ValueError):
        return {"format": "PE", "parse_error": True}


def fingerprint(path: str) -> dict:
    p = os.path.abspath(path)
    if not os.path.isfile(p):
        raise FileNotFoundError(p)
    data = Path(p).read_bytes()
    info = pe_info(data)
    return {"path": p, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), **info}


def require_id(value: str) -> str:
    if not isinstance(value, str) or not value or value in (".", "..") or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for c in value):
        raise ValueError("非法版本/site ID：%s" % value)
    return value


def version_file(case: str, version: str, name: str) -> Path:
    return project_file(Path(case).resolve(), "versions/%s/%s" % (require_id(version), name))


def load_manifest(case: str, version: str) -> tuple[str, dict]:
    path = version_file(case, version, "reverse-baseline.json")
    if not path.exists():
        path = version_file(case, version, "manifest.json")  # Legacy read only.
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") not in (SCHEMA, LEGACY_SCHEMA) or data.get("version") != version:
        raise ValueError("reverse baseline schema/version 无效")
    require_fingerprint(data.get("binary"))
    sites = data.get("sites")
    if not isinstance(sites, list) or any(not isinstance(site, dict) for site in sites):
        raise ValueError("reverse baseline sites 无效")
    ids = [require_id(site.get("id")) for site in sites]
    if len(set(ids)) != len(ids):
        raise ValueError("reverse baseline site id 重复")
    return str(path), data


def require_fingerprint(record) -> None:
    if (not isinstance(record, dict) or type(record.get("size")) is not int or record["size"] < 0
            or not isinstance(record.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])):
        raise ValueError("binary fingerprint 无效")


def read_bound_binary(path: Path, record: dict) -> bytes:
    require_fingerprint(record)
    data = path.read_bytes()
    if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
        raise ValueError("binary fingerprint mismatch: %s" % path)
    return data


def project_regular_file(root: Path, value: str, label: str) -> dict:
    """Describe one ordinary file without admitting absolute/linked paths."""
    text = str(value or "").strip()
    if not text or "\x00" in text:
        raise ValueError("%s 路径为空或无效" % label)
    reference = text.replace("\\", "/")
    relative = PurePosixPath(reference)
    if relative.is_absolute() or ".." in relative.parts or ":" in reference:
        raise ValueError("%s 必须使用项目内相对路径" % label)
    path = root.joinpath(*relative.parts)
    current = path
    while True:
        if current.is_symlink() or (
            current.exists()
            and getattr(current.lstat(), "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024)
        ):
            raise ValueError("%s 不能引用符号链接或重解析点" % label)
        if current == root or current.parent == current:
            break
        current = current.parent
    path = project_file(root, reference)
    if not path.is_file():
        raise FileNotFoundError("%s 文件不存在：%s" % (label, relative.as_posix()))
    size = path.stat().st_size
    digest = sha256_file(str(path))
    if path.stat().st_size != size:
        raise ValueError("%s 文件在登记时发生变化" % label)
    return {"path": relative.as_posix(), "sha256": digest, "size": size}


def baseline_file(case: str, manifest: dict) -> Path:
    binary = manifest.get("binary") or {}
    root = Path(case).resolve()
    local = binary.get("local_path")
    if local:
        return verify_file(root, binary)
    if manifest.get("schema") != LEGACY_SCHEMA:
        raise ValueError("reverse baseline 缺少项目内文件引用")
    # Older seep-migration/1 baselines can reference their original external file.
    candidate = Path(binary.get("path") or root / manifest.get("source_exe", ""))
    fp = fingerprint(str(candidate))
    if any(fp.get(k) != binary.get(k) for k in ("sha256", "size")):
        raise ValueError("旧基线文件哈希/大小不匹配")
    return candidate


def validate_project_binary(case: str, version: str, fp: dict, parent: str = "") -> dict | None:
    require_fingerprint(fp)
    path = version_file(case, version, "version.json")
    if path.exists():
        record = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(record, dict) or record.get("schema") != "seep-version/1" or record.get("version_id") != version:
            raise ValueError("project version 身份无效")
        require_fingerprint(record)
        if any(record.get(k) != fp.get(k) for k in ("sha256", "size")):
            raise ValueError("project version 与 reverse binary 不匹配")
        verify_file(Path(case).resolve(), record)
        if parent and parent != record.get("parent_version_id"):
            raise ValueError("project version parent 不匹配")
        return record
    return None


def save_json(path: str, data: dict) -> None:
    save_text(Path(path), json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def save_text(destination: Path, text: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".seep-reverse-", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def parse_aob(pattern: str) -> list[int | None]:
    tokens = str(pattern or "").replace(",", " ").split()
    if not tokens:
        raise ValueError("AOB 为空")
    out: list[int | None] = []
    for token in tokens:
        if token in ("?", "??"):
            out.append(None)
        elif HEX.fullmatch(token):
            out.append(int(token, 16))
        else:
            raise ValueError("AOB token 非法：%s" % token)
    if all(value is None for value in out):
        raise ValueError("AOB 不能全通配")
    return out


def find_aob(data: bytes, pattern: list[int | None], limit: int = 200) -> list[int]:
    n = len(pattern)
    if n == 0 or n > len(data):
        return []
    hits = []
    for i in range(len(data) - n + 1):
        if all(v is None or data[i + j] == v for j, v in enumerate(pattern)):
            hits.append(i)
            if len(hits) >= limit:
                break
    return hits


def rva_for_offset(info: dict, offset: int) -> str | None:
    for sec in info.get("sections") or []:
        start = sec.get("raw_pointer", 0)
        end = start + sec.get("raw_size", 0)
        if start <= offset < end:
            return hex(sec.get("virtual_address", 0) + offset - start)
    return None


@project_locked("case", recover=True)
def cmd_init(args) -> int:
    require_id(args.version)
    if args.parent:
        require_id(args.parent)
    fp = fingerprint(args.file)
    canonical = validate_project_binary(args.case, args.version, fp, args.parent)
    parent = args.parent or (canonical.get("parent_version_id") if canonical else None)
    path = version_file(args.case, args.version, "reverse-baseline.json")
    legacy = version_file(args.case, args.version, "manifest.json")
    if path.exists() or (legacy.is_file() and json.loads(legacy.read_text(encoding="utf-8")).get("schema") == LEGACY_SCHEMA):
        return fail("baseline-exists", "已有反向基线；--force 也不得清除位点/历史")
    local = "versions/%s/reverse-target/%s" % (args.version, Path(args.file).name)
    root = Path(args.case).resolve()
    fp["local_path"] = local
    manifest = {"schema": SCHEMA, "version": args.version,
                "source_exe": local,
                "binary": fp, "parent_version": parent or None,
                "sites": [], "ui": [], "license": [], "acceptance": [],
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    with file_transaction(root, [local, path.relative_to(root).as_posix()]):
        atomic_copy(Path(args.file), project_file(root, local), fp["sha256"], fp["size"])
        save_json(str(path), manifest)
    print(json.dumps({"ok": True, "version": args.version, "manifest": str(path),
                      "sha256": fp["sha256"], "format": fp.get("format")}, ensure_ascii=False))
    return 0


@project_locked("case", recover=True)
def cmd_add_site(args) -> int:
    path, manifest = load_manifest(args.case, args.version)
    require_id(args.id)
    baseline = baseline_file(args.case, manifest)
    fp = fingerprint(args.file)
    if any(fp.get(k) != manifest.get("binary", {}).get(k) for k in ("sha256", "size")):
        return fail("site-file", "登记文件不属于该基线（哈希/大小不匹配）")
    validate_project_binary(args.case, args.version, fp, manifest.get("parent_version") or "")
    if any(str(x.get("id")) == args.id for x in manifest.get("sites") or []):
        return fail("site-exists", "site id 已存在：%s" % args.id)
    old = bytes.fromhex(args.original.replace(" ", "")) if args.original else b""
    new = bytes.fromhex(args.new.replace(" ", "")) if args.new else b""
    if old and new and old == new:
        return fail("site", "original/new 不能相同")
    if old and new and len(old) != len(new):
        return fail("site", "original/new 必须等长")
    data = read_bound_binary(baseline, manifest["binary"])
    off = int(args.offset, 0) if args.offset else None
    hits = find_aob(data, parse_aob(args.aob), limit=2) if args.aob else []
    if args.aob:
        if len(hits) != 1:
            return fail("site-unique", "旧版本 AOB 命中 %d 处，不能登记为唯一位点" % len(hits))
        if off is not None and off != hits[0]:
            return fail("site-offset", "offset 与实际 AOB 命中不一致")
        off = hits[0]
    if off is None:
        return fail("site", "需要 --offset 或能在 --file 中唯一命中的 --aob")
    width = max(len(old), len(new), len(parse_aob(args.aob)) if args.aob else 1)
    if off < 0 or off + width > len(data):
        return fail("site-offset", "位点越界")
    if old and data[off:off + len(old)] != old:
        return fail("site-bytes", "offset 处原始字节与 --original 不符")
    info = manifest.get("binary") or fingerprint(args.file)
    site = {"id": args.id, "sem": args.sem, "kind": args.kind,
            "aob": args.aob or "", "offset": hex(off),
            "rva": rva_for_offset(info, off), "window": args.window,
            "patch": {"orig": args.original or "", "new": args.new or ""},
            "self_check": {"hits_in_own_binary": len(hits) if args.aob else None,
                           "unique": bool(args.aob and len(hits) == 1),
                           "meaning": "positioning_candidate_only"}}
    manifest.setdefault("sites", []).append(site)
    # Upgrade legacy state to a new file, preserving manifest.json byte for byte.
    destination = version_file(args.case, args.version, "reverse-baseline.json")
    root = Path(args.case).resolve()
    upgrading = manifest.get("schema") == LEGACY_SCHEMA
    refs = [destination.relative_to(root).as_posix()]
    if upgrading:
        local = "versions/%s/reverse-target/%s" % (args.version, baseline.name)
        refs.insert(0, local)
        manifest["schema"] = SCHEMA
        manifest["binary"]["local_path"] = local
        manifest["source_exe"] = local
    with file_transaction(root, refs):
        if upgrading:
            atomic_copy(baseline, project_file(root, local), fp["sha256"], fp["size"])
        save_json(str(destination), manifest)
    print(json.dumps({"ok": True, "manifest": str(destination), "site": site}, ensure_ascii=False))
    return 0


@project_locked("case", recover=True)
def cmd_add_ui(args) -> int:
    """Record a custom UI delivery without applying or modifying it."""
    path, manifest = load_manifest(args.case, args.version)
    root = Path(args.case).resolve()
    ui_id = require_id(args.id)
    if args.apply_method not in UI_APPLY_METHODS:
        return fail("ui-apply-method", "apply_method 必须是：%s" %
                    "|".join(UI_APPLY_METHODS))
    stack = str(args.stack or "").strip()
    if not stack or "\x00" in stack:
        return fail("ui", "stack 不能为空")
    anchor_type = str(args.anchor_type or "").strip()
    anchor = str(args.anchor or "").strip()
    if bool(anchor_type) != bool(anchor):
        return fail("ui-anchor", "anchor-type 与 anchor 必须同时提供或同时留空")
    if "\x00" in anchor_type or "\x00" in anchor:
        return fail("ui-anchor", "anchor 不能包含空字符")

    records = manifest.get("ui")
    if records is None:
        records = manifest["ui"] = []
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        return fail("ui-schema", "reverse baseline ui 必须是对象数组")
    existing_ids = [require_id(item.get("id")) for item in records]
    if len(set(existing_ids)) != len(existing_ids):
        return fail("ui-schema", "reverse baseline ui id 已损坏或重复")
    if ui_id in existing_ids:
        return fail("ui-exists", "UI id 已存在：%s" % ui_id)

    acceptance = []
    for value in args.acceptance or []:
        item = require_id(str(value or "").strip())
        if item not in acceptance:
            acceptance.append(item)
    try:
        inventory = project_regular_file(root, args.inventory, "inventory")
        assets = [project_regular_file(root, value, "asset") for value in args.asset or []]
        screenshots_upstream = [
            project_regular_file(root, value, "upstream screenshot")
            for value in args.screenshot_upstream or []
        ]
        screenshots_custom = [
            project_regular_file(root, value, "custom screenshot")
            for value in args.screenshot_custom or []
        ]
    except (OSError, ValueError) as exc:
        return fail("ui-file", str(exc))

    record = {
        "id": ui_id,
        "stack": stack,
        "apply_method": args.apply_method,
        "anchor_type": anchor_type,
        "anchor": anchor,
        "inventory": inventory,
        "assets": assets,
        "screenshots": {
            "upstream": screenshots_upstream,
            "custom": screenshots_custom,
        },
        "acceptance": acceptance,
        "meaning": "recorded_custom_ui_only_not_applied",
    }
    records.append(record)
    destination = version_file(args.case, args.version, "reverse-baseline.json")
    if manifest.get("schema") != SCHEMA:
        return fail("ui-schema", "add-ui 仅写入 seep-reverse-baseline/1；请先升级旧基线")
    try:
        with file_transaction(
            root, [destination.relative_to(root).as_posix()]
        ):
            save_json(str(destination), manifest)
    except Exception:
        records.pop()
        raise
    print(json.dumps({"ok": True, "manifest": str(destination), "ui": record},
                     ensure_ascii=False))
    return 0


def cmd_fingerprint(args) -> int:
    try:
        print(json.dumps({"ok": True, **fingerprint(args.file)}, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        return fail("fingerprint", "%s: %s" % (type(exc).__name__, exc))


def alignment_sites(old: dict, old_data: bytes, data: bytes, new_fp: dict) -> list[dict]:
    results = []
    for site in old["sites"]:
        aob = str(site.get("aob") or "").strip()
        if not aob:
            results.append({"id": site["id"], "status": "needs_manual", "reason": "旧位点没有 AOB"})
            continue
        own_hits = find_aob(old_data, parse_aob(aob), limit=2)
        if own_hits != [int(str(site.get("offset")), 0)]:
            raise ValueError("旧基线 AOB/offset 不可复核")
        hits = find_aob(data, parse_aob(aob), limit=20)
        row = {"id": site["id"], "sem": site.get("sem"), "old_rva": site.get("rva"),
               "matches": len(hits), "hits": [{"offset": hex(x), "rva": rva_for_offset(new_fp, x)} for x in hits]}
        row["status"] = "unique" if len(hits) == 1 else ("missing" if not hits else "multi")
        results.append(row)
    return results


def alignment_summary(results: list[dict]) -> dict:
    return {s: sum(1 for row in results if row["status"] == s)
            for s in ("unique", "missing", "multi", "needs_manual")}


@project_locked("case", recover=True)
def cmd_align(args) -> int:
    require_id(args.new_version)
    if args.old == args.new_version:
        return fail("align", "old/new 不能相同")
    # Validate both destinations before writing either one.
    out_path = version_file(args.case, args.new_version, "align.json")
    revision = version_file(args.case, args.new_version, "align-revisions/%s.json" % uuid.uuid4().hex)
    old_path, old = load_manifest(args.case, args.old)
    old_file = baseline_file(args.case, old)
    old_data = read_bound_binary(old_file, old["binary"])
    old_fp = fingerprint(str(old_file))
    if any(old_fp[k] != old["binary"][k] for k in ("sha256", "size")):
        return fail("align-baseline", "旧基线文件在读取时改变")
    validate_project_binary(args.case, args.old, old_fp, old.get("parent_version") or "")
    new_fp = fingerprint(args.new)
    canonical = validate_project_binary(args.case, args.new_version, new_fp)
    new_file = verify_file(Path(args.case).resolve(), canonical) if canonical else Path(args.new)
    data = read_bound_binary(new_file, new_fp)
    if canonical:
        new_fp["local_path"] = canonical["local_path"]
    results = alignment_sites(old, old_data, data, pe_info(data))
    out = {"schema": "seep-migration-align/1", "old_version": args.old,
           "new_version": args.new_version, "old_manifest": old_path,
           "old_manifest_sha256": sha256_file(old_path),
           "old_binary": old_fp, "new_binary": new_fp, "sites": results,
           "meaning": "unique is a positioning candidate, not acceptance",
           "summary": alignment_summary(results)}
    root = Path(args.case).resolve()
    if revision.exists():
        raise ValueError("align revision already exists")
    with file_transaction(root, [p.relative_to(root).as_posix() for p in (revision, out_path)]):
        save_json(str(revision), out)
        save_json(str(out_path), out)
    valid = bool(results) and all(row["status"] == "unique" for row in results)
    print(json.dumps({"ok": valid, "align": str(out_path), "summary": out["summary"]}, ensure_ascii=False, indent=2))
    return 0 if valid else 2


@project_locked("case")
def cmd_report(args) -> int:
    require_id(args.new_version)
    old_path, old = load_manifest(args.case, args.old)
    path = version_file(args.case, args.new_version, "align.json")
    out_path = version_file(args.case, args.new_version, "migrate-report.md")
    if not path.is_file():
        return fail("report", "先运行 align 生成 %s" % path)
    align = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(align, dict) or align.get("schema") != "seep-migration-align/1"
            or align.get("old_version") != args.old or align.get("new_version") != args.new_version):
        return fail("report-source", "align 来源版本/schema 与报告参数不一致")
    if "old_manifest_sha256" in align and align["old_manifest_sha256"] != sha256_file(old_path):
        return fail("report-source", "旧基线在 align 后改变，请重新对齐")
    old_fp, new_fp = align.get("old_binary"), align.get("new_binary")
    require_fingerprint(old_fp)
    require_fingerprint(new_fp)
    if any(old_fp[k] != old["binary"][k] for k in ("sha256", "size")):
        return fail("report-source", "align 旧文件与基线不一致")
    old_data = read_bound_binary(baseline_file(args.case, old), old_fp)
    validate_project_binary(args.case, args.old, old_fp, old.get("parent_version") or "")
    canonical = validate_project_binary(args.case, args.new_version, new_fp)
    if canonical:
        new_file = verify_file(Path(args.case).resolve(), canonical)
    else:
        if new_fp.get("local_path"):
            return fail("report-source", "align 对应的 Core 版本记录缺失")
        # Standalone alignment has no Core copy: recheck its explicitly supplied input.
        if not isinstance(new_fp.get("path"), str) or not Path(new_fp["path"]).is_absolute():
            return fail("report-source", "align 新文件路径无效")
        new_file = Path(new_fp["path"])
    data = read_bound_binary(new_file, new_fp)
    results = alignment_sites(old, old_data, data, pe_info(data))
    if align.get("sites") != results or align.get("summary") != alignment_summary(results):
        return fail("report-source", "align 位点/汇总不可复核，请重新对齐")
    lines = ["# 跨版本迁移报告", "", f"- 旧版本：`{args.old}`", f"- 新版本：`{args.new_version}`",
             f"- 新文件：`{new_fp['sha256']}`", "", "## 位点结果", ""]
    for row in results:
        lines.append("- `%s`：%s；旧 RVA=%s；命中=%s；新位置=%s" %
                     (row.get("id"), row["status"], row.get("old_rva"), row.get("matches"),
                      ", ".join(str(x.get("rva") or x.get("offset")) for x in row.get("hits") or []) or "-") )
    lines += ["", "## 边界", "", "unique 仅表示字节定位候选，不证明语义、功能或验收完成；missing/multi/needs_manual 必须重新定位。"]
    save_text(out_path, "\n".join(lines) + "\n")
    print(json.dumps({"ok": True, "report": str(out_path)}, ensure_ascii=False))
    return 0


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="seep-version-") as td:
        old = os.path.join(td, "old.bin")
        new = os.path.join(td, "new.bin")
        Path(old).write_bytes(b"AAAA\x85\xc0\x74\x12BBBB")
        Path(new).write_bytes(b"ZZZZ\x85\xc0\x75\x12BBBB")
        case = os.path.join(td, "case")
        os.makedirs(case)
        init_args = argparse.Namespace(case=case, version="1.0", file=old, parent="", force=False)
        if cmd_init(init_args) != 0:
            return 1
        add_args = argparse.Namespace(case=case, version="1.0", file=old, id="gate-01", sem="branch",
                                      kind="code", aob="85 C0 74 ??", offset="0x4", original="85 C0 74 12",
                                      new="85 C0 EB 12", window=24)
        if cmd_add_site(add_args) != 0:
            return 1
        align_args = argparse.Namespace(case=case, old="1.0", new=new, new_version="1.1")
        rc = cmd_align(align_args)
        if rc != 2:
            return 1
        print(json.dumps({"ok": True, "checks": 3}, ensure_ascii=True))
        return 0


def fail(stage: str, reason: str) -> int:
    print(json.dumps({"ok": False, "blocked_at": stage, "reason": reason}, ensure_ascii=False))
    return 2


def main() -> int:
    ap = argparse.ArgumentParser(description="版本账与跨版本 AOB 对齐工具")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("fingerprint"); p.add_argument("--file", required=True)
    p = sub.add_parser("init"); p.add_argument("--case", required=True); p.add_argument("--version", required=True); p.add_argument("--file", required=True); p.add_argument("--parent", default=""); p.add_argument("--force", action="store_true")
    p = sub.add_parser("add-site"); p.add_argument("--case", required=True); p.add_argument("--version", required=True); p.add_argument("--file", required=True); p.add_argument("--id", required=True); p.add_argument("--sem", required=True); p.add_argument("--kind", default="code"); p.add_argument("--aob", default=""); p.add_argument("--offset", default=""); p.add_argument("--original", default=""); p.add_argument("--new", default=""); p.add_argument("--window", type=int, default=24)
    p = sub.add_parser("add-ui"); p.add_argument("--case", required=True); p.add_argument("--version", required=True); p.add_argument("--id", required=True); p.add_argument("--stack", required=True); p.add_argument("--apply-method", required=True); p.add_argument("--inventory", required=True); p.add_argument("--anchor-type", default=""); p.add_argument("--anchor", default=""); p.add_argument("--asset", action="append", default=[]); p.add_argument("--screenshot-upstream", action="append", default=[]); p.add_argument("--screenshot-custom", action="append", default=[]); p.add_argument("--acceptance", action="append", default=[])
    p = sub.add_parser("align"); p.add_argument("--case", required=True); p.add_argument("--old", required=True); p.add_argument("--new", required=True); p.add_argument("--new-version", required=True)
    p = sub.add_parser("report"); p.add_argument("--case", required=True); p.add_argument("--old", required=True); p.add_argument("--new-version", required=True)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if _BOOTSTRAP_ERROR:
        return fail("runtime", "%s: %s" % _BOOTSTRAP_ERROR)
    try:
        if args.self_test: return self_test()
        if args.cmd == "fingerprint": return cmd_fingerprint(args)
        if args.cmd == "init": return cmd_init(args)
        if args.cmd == "add-site": return cmd_add_site(args)
        if args.cmd == "add-ui": return cmd_add_ui(args)
        if args.cmd == "align": return cmd_align(args)
        if args.cmd == "report": return cmd_report(args)
        ap.print_help(); return 4
    except Exception as exc:
        return fail(args.cmd or "args", "%s: %s" % (type(exc).__name__, exc))


if __name__ == "__main__":
    raise SystemExit(main())
