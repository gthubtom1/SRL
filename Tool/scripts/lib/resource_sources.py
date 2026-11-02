"""Explicit, bounded resource roots shared by discovery, KB and maintenance.

No host credential/configuration crawling, installation or target execution.
The optional local configuration is authoritative and read afresh per call.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = "seep.resource-sources/1"
META_SCHEMA = "seep.knowledge/1"
META_PREFIX = "<!-- seep-resource: "
MAX_FILE = 256 * 1024
MAX_FILES = 1200
MAX_BYTES = 16 * 1024 * 1024
_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_SKIP = {"_pending", "_archive", "_archived", "node_modules", "__pycache__"}
DEFAULTS = [
    {"id": "core-skills", "kind": "skill", "path": "Tool/skill", "enabled": True,
     "writable": False, "visibility": "shared"},
    {"id": "builtin-kb", "kind": "knowledge", "path": "Tool/mcp/Tool/reverselab/kb", "enabled": True,
     "writable": False, "visibility": "shared"},
    {"id": "local-kb", "kind": "knowledge", "path": "Tool/mcp/kb_local", "enabled": True,
     "writable": True, "visibility": "shared"},
]


class SourceError(ValueError):
    pass


def resource_key(value):
    return os.path.normcase(value)


def linked(path: Path) -> bool:
    try:
        info = path.lstat()
        return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 1024)
    except FileNotFoundError:
        return False


def relative(value: str) -> str:
    if (not isinstance(value, str) or not value or "\\" in value or ":" in value
            or value.startswith("/") or any(p in {"", ".", ".."} for p in value.split("/"))
            or any(ord(c) < 32 for c in value)):
        raise SourceError("resource_relative_path_invalid")
    return value


def contained(root: Path, value: str) -> Path:
    relative(value)
    path = root / value
    if not path.resolve().is_relative_to(root.resolve()):
        raise SourceError("resource_path_escape")
    for part in (path, *path.parents):
        if linked(part):
            raise SourceError("resource_path_link")
        if part == root:
            break
    return path


def _json(raw: str):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SourceError("resource_duplicate_json_key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, RecursionError):
        raise SourceError("resource_json_invalid") from None


def _config(path: Path):
    if linked(path) or not path.is_file() or path.stat().st_size > 65536:
        raise SourceError("resource_configuration_invalid")
    obj = _json(path.read_text(encoding="utf-8-sig"))
    if (not isinstance(obj, dict) or obj.get("schema") != SCHEMA
            or set(obj) - {"schema", "sources", "disabled_resources"}
            or not isinstance(obj.get("sources"), list) or len(obj["sources"]) > 32
            or not isinstance(obj.get("disabled_resources", []), list)
            or len(obj.get("disabled_resources", [])) > 1000
            or any(not isinstance(v, str) or not 1 <= len(v) <= 400
                   for v in obj.get("disabled_resources", []))):
        raise SourceError("resource_configuration_invalid")
    return obj


class Sources:
    def __init__(self, repo, *, local_config=None, kb_roots=None):
        self.repo = Path(repo).resolve()
        config = self.repo / "Tool/config/resource-sources.json"
        shared = _config(config) if config.exists() or config.is_symlink() else {"sources": DEFAULTS}
        self.disabled = set(shared.get("disabled_resources", []))
        rows, names = [], set()
        for entry in shared["sources"]:
            rows.append(self._entry(entry, private=False))
            if rows[-1]["id"] in names:
                raise SourceError("resource_source_id_duplicate")
            names.add(rows[-1]["id"])
        selected = local_config if local_config is not None else os.environ.get("SEEP_RESOURCE_CONFIG")
        self.config_hashes = [hashlib.sha256(json.dumps(shared, sort_keys=True).encode()).hexdigest()]
        if selected:
            path = Path(selected).expanduser()
            if not path.is_absolute() or not path.is_file():
                raise SourceError("explicit_resource_configuration_unavailable")
            extra = _config(path)
            self.config_hashes.append(hashlib.sha256(path.read_bytes()).hexdigest())
            self.disabled.update(extra.get("disabled_resources", []))
            seen = set()
            for item in extra["sources"]:
                if not isinstance(item, dict) or not isinstance(item.get("id"), str) or item["id"] in seen:
                    raise SourceError("resource_local_source_invalid")
                ident = item.get("id")
                seen.add(ident)
                if ident in names:
                    if set(item) != {"id", "enabled"} or type(item["enabled"]) is not bool:
                        raise SourceError("resource_builtin_override_only_enabled")
                    next(r for r in rows if r["id"] == ident)["enabled"] = item["enabled"]
                else:
                    rows.append(self._entry(item, private=True))
                    names.add(rows[-1]["id"])
        if kb_roots:
            # Preserve explicit fixture/embedding roots used by the existing KB API.
            for row in rows:
                original = next((d for d in DEFAULTS if d["id"] == row["id"]), None)
                if (row["id"] in kb_roots and original and
                        Path(kb_roots[row["id"]]).resolve() != (self.repo / original["path"]).resolve()):
                    row["root"] = Path(kb_roots[row["id"]]).resolve()
        roots = [r["root"] for r in rows]
        if len(set(roots)) != len(roots):
            raise SourceError("resource_duplicate_root")
        self.rows = rows
        self.disabled = {self.canonical_id(value) for value in self.disabled}
        self.revision = hashlib.sha256(json.dumps([self.config_hashes, sorted(self.disabled),
            [(r["id"], str(r["root"]), r["enabled"]) for r in rows]], sort_keys=True).encode()).hexdigest()

    def canonical_id(self, ident):
        kind, _, tail = ident.partition(":")
        if kind in {"knowledge", "skill"} and "/" in tail:
            source_id, rel = tail.split("/", 1)
            row = next((r for r in self.rows if r["id"] == source_id), None)
            if row:
                try:
                    path = contained(row["root"], rel).resolve()
                    rel = path.relative_to(row["root"].resolve()).as_posix()
                    return resource_key(kind + ":" + source_id + "/" + rel)
                except (SourceError, OSError, ValueError):
                    pass
        return resource_key(ident)

    def is_disabled(self, ident):
        return bool(self.disabled) and self.canonical_id(ident) in self.disabled

    def _entry(self, obj, private):
        fields = {"id", "kind", "path", "enabled", "writable", "visibility"}
        if (not isinstance(obj, dict) or set(obj) != fields or not isinstance(obj["id"], str)
                or not _ID.fullmatch(obj["id"]) or not isinstance(obj["kind"], str) or obj["kind"] not in {"skill", "knowledge"}
                or type(obj["enabled"]) is not bool or type(obj["writable"]) is not bool
                or not isinstance(obj["visibility"], str) or obj["visibility"] not in {"shared", "private"} or not isinstance(obj["path"], str)):
            raise SourceError("resource_source_shape_invalid")
        if obj["kind"] == "skill" and obj["writable"]:
            raise SourceError("skills_must_use_existing_importer")
        if private:
            raw = Path(obj["path"]).expanduser()
            if not raw.is_absolute() or obj["visibility"] != "private":
                raise SourceError("local_resource_requires_absolute_private_root")
            root = raw.resolve()
            if (root == root.parent or root == Path.home().resolve() or root.is_relative_to(self.repo)
                    or self.repo.is_relative_to(root) or linked(raw)):
                raise SourceError("local_resource_root_invalid")
        else:
            if obj["visibility"] != "shared":
                raise SourceError("repository_resources_are_shared_and_budgeted")
            root = contained(self.repo, obj["path"])
            if obj["id"] == "core-skills" and (obj["kind"] != "skill" or obj["path"] != "Tool/skill"):
                raise SourceError("formal_skill_root_is_owned_by_pack_registry")
            if obj["writable"] and (obj["kind"] != "knowledge" or
                    not root.is_relative_to(self.repo / "Tool/mcp/kb_local")):
                raise SourceError("shared_resource_write_root_invalid")
        return {**obj, "root": root}

    def get(self, ident, *, writable=False):
        row = next((r for r in self.rows if r["id"] == ident), None)
        if not row or not row["enabled"] or writable and not row["writable"]:
            raise SourceError("resource_source_unavailable_or_readonly")
        if linked(row["root"]):
            raise SourceError("resource_root_link")
        return row

    def view(self):
        return [{k: r[k] for k in ("id", "kind", "enabled", "writable", "visibility")}
                | {"present": r["root"].is_dir()} for r in self.rows]

    def documents(self, kind):
        count, size, directories = 0, 0, 0
        for row in self.rows:
            if row["kind"] != kind or not row["enabled"]:
                continue
            folder = row["root"]
            if linked(folder):
                raise SourceError("resource_root_link")
            if not folder.is_dir():
                continue
            for parent, dirs, files in os.walk(folder, followlinks=False):
                directories += 1
                if directories > 4096:
                    raise SourceError("resource_directory_budget_exceeded")
                dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in _SKIP
                                 and not linked(Path(parent) / d))
                for name in sorted(files):
                    if name.startswith(".") or not name.lower().endswith(".md") or kind == "skill" and name != "SKILL.md":
                        continue
                    path = Path(parent) / name
                    if linked(path):
                        continue
                    rel = path.relative_to(folder).as_posix()
                    path = contained(folder, rel)
                    ident = kind + ":" + row["id"] + "/" + rel
                    if self.is_disabled(ident):
                        continue
                    current = path.stat().st_size
                    count += 1
                    size += current
                    if current > MAX_FILE or count > MAX_FILES or size > MAX_BYTES:
                        raise SourceError("resource_read_budget_exceeded")
                    yield row, rel, path, ident


def metadata(text):
    if not text.startswith(META_PREFIX):
        return None
    line = text.split("\n", 1)[0]
    if len(line) > 16384 or not line.endswith(" -->"):
        raise SourceError("knowledge_metadata_invalid")
    obj = _json(line[len(META_PREFIX):-4])
    if not isinstance(obj, dict) or obj.get("schema") != META_SCHEMA:
        raise SourceError("knowledge_metadata_invalid")
    return obj


def read_document(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise SourceError("resource_file_budget_exceeded")
    return raw


def document_path(source, rel, *, allow_directory=False):
    relative(rel)
    if any(part.startswith(".") or part in _SKIP for part in rel.split("/")):
        raise SourceError("resource_not_an_eligible_document")
    path = contained(source["root"], rel)
    if path.is_file():
        if path.suffix.lower() != ".md" or path.stat().st_size > MAX_FILE:
            raise SourceError("resource_not_an_eligible_document")
    elif not allow_directory or path.exists() and not path.is_dir():
        raise SourceError("resource_document_unavailable")
    return path


def require_enabled(repo, kind, name):
    if kind not in {"tool_software", "mcp_server"} or not isinstance(name, str) or not 1 <= len(name) <= 160:
        raise SourceError("resource_policy_identifier_invalid")
    if Sources(repo).is_disabled(kind + ":" + name):
        raise SourceError("resource_disabled")


def article_reference(source_id, rel):
    if source_id == "builtin-kb":
        return rel
    return ("kb_local/" if source_id == "local-kb" else "sources/" + source_id + "/") + rel


def knowledge_entries(repo, builtin=None, local=None, category=None):
    overrides = {k: v for k, v in (("builtin-kb", builtin), ("local-kb", local)) if v is not None}
    sources = Sources(repo, kb_roots=overrides)
    if category:
        relative(category)
        valid = False
        for source in sources.rows:
            if source["kind"] != "knowledge" or not source["enabled"]:
                continue
            prefix = article_reference(source["id"], "")
            if prefix and category == prefix.rstrip("/"):
                valid = source["root"].is_dir() or valid
                continue
            rel = category[len(prefix):] if prefix and category.startswith(prefix) else category if not category.startswith(("sources/", "kb_local/")) else ""
            if rel and contained(source["root"], rel).is_dir():
                valid = True
        if not valid:
            raise SourceError("knowledge_category_unavailable")
    rows = []
    for source, rel, path, ident in sources.documents("knowledge"):
        reference = article_reference(source["id"], rel)
        if category:
            relative(category)
            if not (reference == category or reference.startswith(category.rstrip("/") + "/")):
                # Legacy categories also include local additions in that category.
                if source["id"] != "local-kb" or not rel.startswith(category.rstrip("/") + "/"):
                    continue
        text = read_document(path).decode("utf-8-sig")
        meta = metadata(text)
        if meta and meta.get("maturity") == "retired":
            continue
        rows.append((reference, str(path), source["id"], ident))
    return rows


def knowledge_path(repo, reference, builtin=None, local=None):
    relative(reference)
    overrides = {k: v for k, v in (("builtin-kb", builtin), ("local-kb", local)) if v is not None}
    sources = Sources(repo, kb_roots=overrides)
    if reference.startswith("kb_local/"):
        ident, rel = "local-kb", reference[len("kb_local/"):]
    elif reference.startswith("sources/"):
        parts = reference.split("/", 2)
        if len(parts) != 3:
            raise SourceError("knowledge_reference_invalid")
        _, ident, rel = parts
    else:
        ident, rel = "builtin-kb", reference
    row = sources.get(ident)
    if row["kind"] != "knowledge" or sources.is_disabled("knowledge:" + ident + "/" + rel):
        raise SourceError("knowledge_reference_disabled")
    return str(document_path(row, rel, allow_directory=True))
