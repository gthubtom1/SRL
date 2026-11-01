"""Read-only, host-neutral discovery of existing Seep methods and typed links.

No tools, scripts, targets, providers or model calls are executed. Discovery
eligibility is not action admission, runtime readiness, or task acceptance.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import unquote

from . import domain_registry

SCHEMA = "seep.capability-discovery/1"
MAX_FILE_BYTES = 256 * 1024
MAX_FILES = 1200
MAX_READ_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 48 * 1024
_SKIP = {"_pending", "_archive", "_archived", "node_modules", "__pycache__"}
_GENERIC = {"python", "javascript", "typescript", "react", "test", "tests",
            "function", "code", "project", "help", "please", "seep"}
_STOP = {"帮我", "一下", "这个", "我们", "项目", "功能", "开发", "实现", "测试",
         "怎么", "如何", "需要", "一个", "进行", "分析", "问题", "检查", "当前",
         "程序", "软件", "文件", "相关", "使用", "方法", "代码", "可以", "是否"}
_PATH = re.compile(r"Tool/[A-Za-z0-9_./\-\u3400-\u9fff]+\.(?:md|py|ps1|js|ts|sh|json)")
_LINK = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)\)")


def _description(text):
    """Read the small frontmatter subset used by skills, without executing YAML."""
    if not text.startswith("---"):
        return ""
    front = text.split("---", 2)
    if len(front) < 3:
        return ""
    match = re.search(r"^description:\s*(.*)((?:\n[ \t]+[^\n]*)*)", front[1], re.M)
    if not match:
        return ""
    value = match.group(1).strip()
    if value in ("|", ">", "|-", ">-"):
        value = match.group(2)
    return " ".join(value.strip().strip("\"'").split())[:1200]


def _title(text, fallback):
    match = re.search(r"^#\s+(.+)$", text, re.M)
    return (match.group(1).strip() if match else fallback)[:160]


def _terms(query):
    latin = {v.lower() for v in re.findall(r"[A-Za-z][A-Za-z0-9_.+-]{1,63}", query)}
    latin -= _GENERIC
    chinese = set()
    for block in re.findall(r"[\u3400-\u9fff]+", query):
        for word in sorted(_STOP, key=len, reverse=True):
            block = block.replace(word, " ")
        for part in block.split():
            chinese.update(part[i:i + 2] for i in range(len(part) - 1))
    return latin, chinese


def _score(text, terms):
    latin, chinese = terms
    words = set(re.findall(r"[a-z][a-z0-9_.+-]*", text.lower()))
    matches = sorted(latin & words)
    zh = sorted(t for t in chinese if t in text)
    # One generic CJK fragment cannot turn an unrelated task into a specialty.
    score = len(matches) * 12 + (len(zh) * 2 if len(zh) >= 2 else 0)
    return score, (matches + zh)[:8]


class _Catalog:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.warnings = []
        self.fingerprints = []
        self.files = 0
        self.bytes = 0
        self.records = []
        self.methods = set()
        self.tools = {}
        self.servers = {}
        self.packs = {}
        self.repo_aliases = {}

    def warn(self, code, path):
        item = {"code": code, "source": str(path)[:240]}
        if item not in self.warnings and len(self.warnings) < 40:
            self.warnings.append(item)

    def path(self, value):
        value = str(value).replace("\\", "/")
        if not value or ":" in value or value.startswith("/"):
            return None
        try:
            target = (self.root / value).resolve()
            target.relative_to(self.root)
        except (ValueError, OSError, RuntimeError):
            return None
        return target

    def exists(self, value):
        target = self.path(value)
        return target is not None and target.is_file()

    def read(self, relative, optional=False):
        target = self.path(relative)
        if target is None:
            self.warn("outside_source_root", relative)
            return None
        try:
            size = target.stat().st_size
            if self.files >= MAX_FILES or size > MAX_FILE_BYTES or self.bytes + size > MAX_READ_BYTES:
                self.warn("resource_constraint", relative)
                return None
            with target.open("rb") as handle:
                data = handle.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES:
                self.warn("resource_constraint", relative)
                return None
            self.files += 1
            self.bytes += len(data)
            self.fingerprints.append((relative, hashlib.sha256(data).hexdigest()))
            return data.decode("utf-8-sig")
        except (OSError, UnicodeError):
            if not optional:
                self.warn("unreadable_source", relative)
            return None

    def load_json(self, relative, optional=False):
        text = self.read(relative, optional)
        if text is None:
            return {}
        try:
            obj = json.loads(text)
            if not isinstance(obj, dict):
                raise ValueError("object required")
            return obj
        except (ValueError, TypeError):
            self.warn("invalid_json_source", relative)
            return {}

    def children(self, relative):
        folder = self.path(relative)
        if folder is None or not folder.is_dir():
            return []
        result = []
        try:
            for p in folder.iterdir():
                if len(result) >= MAX_FILES:
                    self.warn("resource_constraint", relative)
                    break
                if p.name.startswith(".") or p.name in _SKIP:
                    continue
                if p.is_symlink():
                    self.warn("untrusted_source_link", relative + "/" + p.name)
                    continue
                try:
                    p.resolve().relative_to(self.root)
                except (ValueError, OSError, RuntimeError):
                    self.warn("outside_source_root", relative + "/" + p.name)
                    continue
                result.append(p)
        except OSError:
            self.warn("unreadable_source", relative)
        return sorted(result, key=lambda p: p.name)

    def link(self, kind, relative, **extra):
        return {"kind": kind, "path": relative, "present": self.exists(relative), **extra}

    def links(self, text, relative):
        paths = set(_PATH.findall(text))
        for raw in _LINK.findall(text):
            raw = unquote(raw.split("#", 1)[0])
            if not raw or ":" in raw or raw.startswith("/"):
                continue
            candidate = self.path((Path(relative).parent / raw).as_posix())
            if candidate is not None:
                paths.add(candidate.relative_to(self.root).as_posix())
        out = []
        for path in sorted(paths):
            if any(p in _SKIP for p in Path(path).parts):
                continue
            kind = ("kb_article" if "/reverselab/kb/" in path else
                    "skill" if path.endswith("SKILL.md") else
                    "reference" if path.endswith(".md") else "script")
            out.append(self.link(kind, path))
        for namespace, name in sorted(set(re.findall(
                r"`(tool|mcp|repo|probe|reserved|apk):([A-Za-z0-9_.-]+)`", text))):
            out.append({"kind": "typed_reference", "namespace": namespace, "name": name})
        return out

    def add_markdown(self, relative, kind, domain=None):
        text = self.read(relative)
        if text is None:
            return
        description = _description(text)
        title = _title(text, Path(relative).stem)
        # Playbooks use short trigger/intent lines rather than skill frontmatter.
        if kind == "playbook":
            description = " ".join(l[:700] for l in text.splitlines()[:10]
                                   if re.search(r"触发|意图|trigger|intent", l, re.I))[:1200]
        self.records.append({"id": kind + ":" + relative, "kind": kind, "path": relative,
                             "domain": domain, "title": title, "description": description,
                             "search": title + " " + description, "links": self.links(text, relative),
                             "method_tools": sorted(set(re.findall(r"\bseep_[a-z0-9_]+\b", text)))})

    def load(self):
        # Validate bounded paths before the canonical loader opens declarations.
        safe = True
        for folder in self.children("Tool/skill"):
            if folder.is_dir() and (folder / "pack.json").exists():
                relative = "Tool/skill/" + folder.name + "/pack.json"
                if self.read(relative) is None:
                    safe = False
        aliases = "Tool/config/domain-aliases.json"
        if (self.root / aliases).exists() and self.read(aliases) is None:
            safe = False
        if not safe or self.warnings:
            return
        # Domain identities come from the existing registry, not a second list.
        registry = domain_registry.load_registry(str(self.root))
        for error in registry.errors:
            self.warn("domain_registry", error)
        for domain in registry.ids():
            pack = registry.get(domain)
            if pack.dir != domain or pack.raw.get("schema") != "seep.pack/1":
                self.warn("invalid_domain_source", "Tool/skill/" + pack.dir + "/pack.json")
                continue
            if pack.raw.get("id") == domain:
                self.packs[domain] = pack.raw
                if not isinstance(pack.raw.get("tools", []), list):
                    self.warn("invalid_domain_tools", "Tool/skill/" + domain + "/pack.json")
                    self.packs[domain] = {**pack.raw, "tools": []}
                relative = "Tool/skill/" + domain
                # Include the declaration in the source revision.
                self.add_markdown(relative + "/SKILL.md", "skill", domain)
                for child in self.children(relative + "/subskills"):
                    if child.is_dir() and (child / "SKILL.md").is_file():
                        self.add_markdown(relative + "/subskills/" + child.name + "/SKILL.md",
                                          "subskill", domain)
        for entry in registry.namespace.get("cross_cutting", []):
            name = entry.get("name") if isinstance(entry, dict) else entry
            if isinstance(name, str) and re.fullmatch(r"[a-z0-9-]+", name):
                if self.exists("Tool/skill/" + name + "/SKILL.md"):
                    self.add_markdown("Tool/skill/" + name + "/SKILL.md", "crosscutting")
        for path in self.children("Tool/playbooks"):
            if path.suffix == ".md" and path.stem.lower() not in ("readme", "index"):
                self.add_markdown(path.relative_to(self.root).as_posix(), "playbook")
        for path in self.children("Tool/capabilities"):
            if path.suffix != ".json":
                continue
            relative = path.relative_to(self.root).as_posix()
            obj = self.load_json(relative)
            arrays = ("inputs", "outputs", "scripts", "refs", "compose")
            if (obj.get("id") != path.stem or obj.get("domain") not in self.packs
                    or obj.get("maturity") not in ("probe", "usable", "battle-tested")
                    or any(not isinstance(obj.get(k), list) or
                           any(not isinstance(v, str) or not v for v in obj[k]) for k in arrays)
                    or not isinstance(obj.get("reserved", False), bool) or obj.get("archived")
                    or not isinstance(obj.get("title"), str)
                    or any(k in obj and (not isinstance(obj[k], list) or
                           any(not isinstance(v, str) for v in obj[k])) for k in ("triggers", "aliases"))):
                self.warn("invalid_capability_source", relative)
                continue
            links = [self.link("script", s) for s in obj["scripts"]]
            links += [self.link("reference", s) for s in obj["refs"]]
            eligible = (obj.get("reserved") is not True and
                        obj["maturity"] in ("usable", "battle-tested") and
                        bool(obj["scripts"]) and bool(obj["refs"]) and
                        all(l["present"] for l in links))
            self.records.append({"id": "capability:" + obj["id"], "kind": "capability",
                                 "domain": obj["domain"], "path": relative,
                                 "title": str(obj.get("title", obj["id"]))[:160],
                                 "description": str(obj.get("note", ""))[:700],
                                 "search": " ".join(str(obj.get(k, "")) for k in
                                                     ("title", "triggers", "aliases", "inputs", "outputs")),
                                 "links": links, "maturity": obj["maturity"],
                                 "reserved": obj.get("reserved", False),
                                 "declared_auto_composable": eligible,
                                 "compose": obj["compose"]})
        self.qualify_compositions()
        self.tools = self.load_json("Tool/config/tool-capabilities.json", optional=True).get("tools", {})
        self.servers = self.load_json("Tool/config/mcp-servers.json", optional=True).get("servers", {})
        self.repo_aliases = self.load_json("Tool/config/playbook-capability-aliases.json", optional=True).get("repo", {})
        for name in ("tools", "servers", "repo_aliases"):
            if not isinstance(getattr(self, name), dict):
                self.warn("invalid_catalog_shape", name)
                setattr(self, name, {})
        source = self.read("Tool/mcp/seep_mcp_server.py", optional=True)
        if source:
            try:
                tree = ast.parse(source)
                self.methods = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                                and any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                                        and isinstance(d.func.value, ast.Name) and d.func.value.id == "server"
                                        and d.func.attr == "tool" for d in n.decorator_list)}
            except SyntaxError:
                self.warn("invalid_tool_source", "Tool/mcp/seep_mcp_server.py")

    def qualify_compositions(self):
        records = {r["id"].split(":", 1)[1]: r for r in self.records if r["kind"] == "capability"}
        memo = {}

        def eligible(name, trail):
            if name in memo:
                return memo[name]
            if name not in records or name in trail or len(trail) >= 64:
                self.warn("invalid_compose", "capability:" + name)
                return False
            record = records[name]
            children = [eligible(child, trail + (name,)) for child in record["compose"]]
            memo[name] = record["declared_auto_composable"] and all(children)
            return memo[name]

        for name, record in records.items():
            record["declared_auto_composable"] = eligible(name, ())

    def reference(self, item):
        if item["kind"] != "typed_reference":
            return item
        namespace, name = item["namespace"], item["name"]
        if namespace == "tool":
            return {**item, "kind": "tool_software", "declared": name in self.tools,
                    "source": "Tool/config/tool-capabilities.json#tools." + name,
                    "runtime_status": "not_checked", "invocable_method": False}
        if namespace == "mcp":
            return {**item, "kind": "mcp_server", "declared": name in self.servers,
                    "source": "Tool/config/mcp-servers.json#servers." + name,
                    "runtime_status": "not_checked", "invocable_method": False}
        if namespace in ("probe", "reserved"):
            return {**item, **self.link("capability_reference", "Tool/capabilities/" + name + ".json"),
                    "qualification_required": True}
        if namespace == "repo":
            if name in self.repo_aliases:
                paths = [self.repo_aliases[name]] if isinstance(self.repo_aliases[name], str) else []
            else:
                paths = []
                patterns = ("Tool/scripts/*", "Tool/skill/*/scripts/*", "Tool/skill/*/subskills/*/scripts/*")
                for pattern in patterns:
                    for p in self.root.glob(pattern):
                        relative = p.relative_to(self.root).as_posix()
                        if p.stem.replace("_", "-").lower() == name.replace("_", "-").lower() and p.suffix in (".py", ".ps1", ".sh", ".js", ".ts") and not any(
                                part in _SKIP for part in p.parts) and self.exists(relative):
                            paths.append(relative)
            paths = sorted(set(p for p in paths if self.exists(p)))
            return {**item, "kind": "script_reference", "paths": paths[:8],
                    "status": "unique" if len(paths) == 1 else "ambiguous" if paths else "missing",
                    "candidate_count": len(paths), "execution_performed": False}
        if namespace == "apk":
            return {**item, **self.link("apk_capability", "Tool/skill/apkseep/scripts/capabilities.py"),
                    "entry": "CAPABILITIES." + name, "qualification_required": True}
        return {**item, "qualification_required": True, "runtime_status": "not_checked"}

    def present(self, record, score, matched):
        for link in record["links"]:
            if "present" in link and not link["present"]:
                self.warn("unresolved_reference", link["path"])
        out = {k: record[k] for k in ("id", "kind", "domain", "path", "title", "description")}
        out.update({"score": score, "matched_terms": matched,
                    "applicability": "candidate_requires_method_review",
                    "links": [self.reference(l) for l in record["links"][:8]],
                    "omitted_links": max(0, len(record["links"]) - 8)})
        if record["kind"] == "capability":
            out.update({k: record[k] for k in ("maturity", "reserved", "declared_auto_composable", "compose")})
            out["limitations"] = ["Declaration only; action admission, tool readiness and target evidence remain separate."]
            if record["reserved"] or record["maturity"] == "probe":
                out["applicability"] = "reference_only_not_automatic_execution"
        pack = self.packs.get(record["domain"], {})
        names = record.get("method_tools", [])
        if record["kind"] == "skill":
            names = sorted(set(names + [n for n in pack.get("tools", []) if isinstance(n, str)]))
        out["tools"] = [{"kind": "mcp_tool", "server": "seep", "name": name,
                          "registered_in_source": name in self.methods,
                          "runtime_status": "not_checked", "schema_required": True}
                         for name in names[:8]]
        roles = pack.get("case_roles", {})
        cases = roles.get("witness", []) if isinstance(roles, dict) else []
        if not isinstance(cases, list):
            cases = []
        out["case_references"] = [self.link("case_metadata", "Tool/cases/" + name + "/case.json",
                                           role="declared_witness_not_current_evidence")
                                  for name in cases[:2] if isinstance(name, str)]
        return out


def discover(root, query, limit=5):
    """Return a bounded discovery view; never execute resources or echo a query."""
    base = {"schema": SCHEMA, "ok": False, "resources": [], "warnings": [],
            "execution_performed": False, "runtime_verified": False}
    if (not isinstance(query, str) or not query.strip() or len(query) > 2000
            or isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20):
        return {**base, "status": "invalid_parameter",
                "error": "query must be nonempty (<=2000 characters); limit must be 1..20"}
    catalog = _Catalog(root)
    if not catalog.path("Tool/skill") or not (catalog.root / "Tool/skill").is_dir():
        return {**base, "status": "invalid_source", "error": "Seep source root has no Tool/skill directory"}
    catalog.load()
    scored = []
    terms = _terms(query)
    for record in catalog.records:
        score, matched = _score(record["search"], terms)
        if score:
            scored.append((score, record, matched))
    scored.sort(key=lambda item: (-item[0], item[1]["id"]))
    selected = []
    for score, record, matched in scored[:limit]:
        candidate = catalog.present(record, score, matched)
        if len(json.dumps(selected + [candidate], ensure_ascii=False).encode("utf-8")) > MAX_OUTPUT_BYTES - 8000:
            break
        selected.append(candidate)
    revision = hashlib.sha256(json.dumps(sorted(catalog.fingerprints)).encode()).hexdigest()
    result = {**base, "ok": True,
            "status": "partial" if catalog.warnings else "matches" if scored else "no_matches",
            "resources": selected, "warnings": catalog.warnings, "source_revision": revision,
            "total_matches": len(scored), "omitted_count": len(scored) - len(selected),
            "read_stats": {"files": catalog.files, "bytes": catalog.bytes},
            "next": ["Read the selected method and its prerequisites before choosing an operation.",
                     "For a professional unknown, use seep_kb_search(query=...) then seep_kb_read(article_path=...).",
                     "Inspect the host's actual tool schema; source registration is not runtime readiness.",
                     "Use existing tools or CLI on the current task; retain output and verify the specific result."],
            "continuation": "Narrow the current question or increase limit (max 20); follow exact resource links.",
            "limitations": ["Ownership does not restrict cross-domain use or turn development into an audit.",
                            "Candidates, declared witnesses and tool references do not prove task success.",
                            "No target code, scripts, case payloads or sample binaries were executed or read."],
            "validation_resources": [catalog.link("sample_catalog", "Tool/samples/README.md",
                                                  role="only_for_toolchain_or_method_validation_not_target_evidence")] if selected else []}
    result["omitted_warning_count"] = 0
    while len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > MAX_OUTPUT_BYTES:
        if result["resources"]:
            result["resources"].pop()
            result["omitted_count"] += 1
        elif result["warnings"]:
            result["warnings"].pop()
            result["omitted_warning_count"] += 1
        else:
            break
    return result
