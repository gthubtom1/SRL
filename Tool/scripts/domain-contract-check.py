#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static contract drift report for the nine first-party domain packs.

The pack ids are the only formal-domain authority used by this report.  This
script is deliberately read-only in normal operation: it does not migrate
cases, rewrite configuration, or change domain-gate's case source.
"""
from __future__ import annotations

import argparse
import glob
import json
import ntpath
import os
import sys
import tempfile
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(HERE, "lib"))
import domain_registry as registry_mod  # noqa: E402  单向：registry 不 import 本脚本
from runtime_root import resolve_agent_root  # noqa: E402
SKILL_ROOT = os.path.join(ROOT, "Tool", "skill")
CONFIG_ROOT = os.path.join(ROOT, "Tool", "config")
CASES_ROOT = os.path.join(ROOT, "Tool", "cases")
DEPLOY_ROOT = str(resolve_agent_root() / "skills")
NAMESPACE_CONFIG = os.path.join(CONFIG_ROOT, "domain-aliases.json")
SCHEMA = "seep.domain-contract-check/1"
SOURCE_FILES = {
    "capability-matrix": os.path.join(CONFIG_ROOT, "capability-matrix.json"),
    "playbook-domains": os.path.join(CONFIG_ROOT, "playbook-domains.json"),
    "taskcard-sources": os.path.join(CONFIG_ROOT, "taskcard-sources.json"),
}


def safe_relative_pattern(value: str) -> bool:
    """A pack/config-owned glob that cannot leave its declared base directory."""
    if not isinstance(value, str):
        return False
    text = value.replace("\\", "/").strip()
    if not text or "\x00" in text or any(ch in text for ch in ("\n", "\r")):
        return False
    drive, _tail = ntpath.splitdrive(text)
    if drive or text.startswith("/") or text.startswith("../"):
        return False
    return all(part not in ("", ".", "..") for part in text.split("/"))


def path_within(root: str, path: str) -> bool:
    """Compare real paths so an in-root symlink cannot escape its namespace."""
    try:
        root_real = os.path.realpath(root)
        path_real = os.path.realpath(path)
        return os.path.commonpath((root_real, path_real)) == root_real
    except (OSError, ValueError):
        return False


def load_json(path: str) -> tuple[Any, str | None]:
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            return json.load(fh), None
    except Exception as exc:  # noqa: BLE001 - report must survive bad input
        return None, "%s: %s" % (os.path.basename(path), str(exc)[:160])


def write_json(path: str, value: Any) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(value, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def load_packs(skill_root: str) -> tuple[list[dict[str, Any]], list[str]]:
    packs: list[dict[str, Any]] = []
    errors: list[str] = []
    if not os.path.isdir(skill_root):
        return packs, ["缺技能根目录: %s" % skill_root]
    for dirname in sorted(os.listdir(skill_root)):
        pack_path = os.path.join(skill_root, dirname, "pack.json")
        if not os.path.isfile(pack_path):
            continue
        if dirname.startswith(("_", ".")):
            errors.append("%s：归档/待迁移命名空间（_ 开头）不得带 pack.json 冒充正式域" % dirname)
            continue
        raw, error = load_json(pack_path)
        if error:
            errors.append("%s/%s" % (dirname, error))
            continue
        if not isinstance(raw, dict):
            errors.append("%s/pack.json 顶层不是对象" % dirname)
            continue
        pack_id = raw.get("id")
        if not isinstance(pack_id, str) or not pack_id.strip():
            errors.append("%s/pack.json 缺少非空 id" % dirname)
            continue
        pack_id = pack_id.strip()
        if pack_id != dirname:
            errors.append("%s/pack.json id=%r 与目录名不一致" % (dirname, pack_id))
        if any(p["id"] == pack_id for p in packs):
            errors.append("pack id 重复: %s" % pack_id)
        packs.append({
            "id": pack_id,
            "dir": dirname,
            "path": pack_path,
            "raw": raw,
        })
    return packs, errors


def source_mentions(name: str, data: Any) -> set[str]:
    """Extract domain-valued fields, including explicit formal declarations."""
    if not isinstance(data, dict):
        return set()
    values = set(x for x in data.get("formal_domains", []) if isinstance(x, str))
    if name == "capability-matrix":
        values.update(x for x in data.get("families", []) if isinstance(x, str))
        capabilities = data.get("capabilities")
        if isinstance(capabilities, dict):
            for row in capabilities.values():
                if isinstance(row, dict):
                    values.update(x for x in row if isinstance(x, str))
        return values
    if name == "playbook-domains":
        mapping = data.get("map")
        if isinstance(mapping, dict):
            for domains in mapping.values():
                if isinstance(domains, list):
                    values.update(x for x in domains if isinstance(x, str))
        return values
    if name == "taskcard-sources":
        domains = data.get("domains")
        if isinstance(domains, dict):
            values.update(domains)
        return values
    if name == "domain_spec":
        return set(data)
    return values


def load_namespace_config(path: str = NAMESPACE_CONFIG) -> tuple[dict[str, Any], str | None]:
    data, error = load_json(path)
    if error:
        return {}, error
    if not isinstance(data, dict):
        return {}, "domain-aliases.json 顶层不是对象"
    return data, validate_namespace_config(data)


def validate_namespace_config(data: dict[str, Any]) -> str | None:
    """Validate explicit/in-file namespace data with the same rules."""
    if not isinstance(data, dict):
        return "domain-aliases.json 顶层不是对象"
    errors: list[str] = []
    formal = data.get("formal_domains")
    if not isinstance(formal, list) or any(not isinstance(x, str) or not x.strip() for x in formal):
        errors.append("formal_domains 必须是非空字符串数组")
    aliases = data.get("aliases")
    if not isinstance(aliases, dict) or any(
            not isinstance(name, str) or not isinstance(value, dict)
            or not isinstance(value.get("status"), str)
            or (value.get("alias_to") is not None and not isinstance(value.get("alias_to"), str))
            for name, value in (aliases.items() if isinstance(aliases, dict) else [])):
        errors.append("aliases 必须是 {name: {alias_to, status}} 对象")
    cross = data.get("cross_cutting")
    if not isinstance(cross, list) or any(
            not isinstance(x, str) and not (isinstance(x, dict) and isinstance(x.get("name"), str))
            for x in (cross if isinstance(cross, list) else [])):
        errors.append("cross_cutting 必须是名称数组或对象数组")
    patterns = data.get("pending_patterns")
    pending_skills_config = data.get("pending_skills")
    if patterns is not None and (not isinstance(patterns, list)
                                 or any(not isinstance(x, str) or not x for x in patterns)):
        errors.append("pending_patterns 必须是字符串数组")
    elif isinstance(patterns, list) and any(not safe_relative_pattern(x) for x in patterns):
        errors.append("pending_patterns 只能是 Tool/skill 根内相对模式")
    if pending_skills_config is not None and (not isinstance(pending_skills_config, list)
                                               or any(not isinstance(x, str) or not x for x in pending_skills_config)):
        errors.append("pending_skills 必须是字符串数组")
    elif isinstance(pending_skills_config, list) and any(
            not safe_relative_pattern(x) for x in pending_skills_config):
        errors.append("pending_skills 只能是 Tool/skill 根内相对路径")
    if patterns is None and pending_skills_config is None:
        errors.append("必须提供 pending_patterns 或 pending_skills")
    return "; ".join(errors) if errors else None


def namespace_names(config: dict[str, Any]) -> dict[str, Any]:
    aliases = config.get("aliases") if isinstance(config.get("aliases"), dict) else {}
    cross_raw = config.get("cross_cutting") if isinstance(config.get("cross_cutting"), list) else []
    cross = {x if isinstance(x, str) else x.get("name") for x in cross_raw}
    cross.discard(None)
    return {
        "formal_domains": {x for x in config.get("formal_domains", []) if isinstance(x, str)},
        "aliases": aliases,
        "pending_aliases": {
            name for name, value in aliases.items()
            if isinstance(value, dict) and value.get("status") in {"pending-alias", "pending-subskill"}
        },
        "cross_cutting": {x for x in cross if isinstance(x, str)},
        "pending_patterns": [x for x in config.get("pending_patterns", []) if isinstance(x, str)],
        "pending_skills": {x for x in config.get("pending_skills", []) if isinstance(x, str)},
    }


def pending_skills(skill_root: str, config: dict[str, Any]) -> tuple[list[dict[str, str]], list[str]]:
    names = namespace_names(config)
    candidates: set[str] = set()
    errors: list[str] = []
    for pattern in names["pending_patterns"]:
        if not safe_relative_pattern(pattern):
            continue
        for path in glob.glob(os.path.join(skill_root, pattern), recursive=True):
            if os.path.isdir(path) and path_within(skill_root, path):
                candidates.add(os.path.normpath(path))
            elif os.path.isdir(path):
                errors.append("pending_patterns 命中越出 Tool/skill 的路径：%s"
                              % os.path.relpath(path, skill_root).replace(os.sep, "/"))
    for name in names["pending_skills"]:
        if not safe_relative_pattern(name):
            continue
        path = os.path.join(skill_root, name)
        if path_within(skill_root, path):
            candidates.add(path)
        else:
            errors.append("pending_skills 路径越出 Tool/skill：%s" % name)
    found: list[dict[str, str]] = []
    for current in sorted(candidates):
        if not path_within(skill_root, current):
            errors.append("pending skill 通过链接越出 Tool/skill：%s"
                          % os.path.relpath(current, skill_root).replace(os.sep, "/"))
            continue
        if not os.path.isfile(os.path.join(current, "SKILL.md")):
            continue
        rel = os.path.relpath(current, skill_root).replace(os.sep, "/")
        found.append({"name": os.path.basename(current), "path": rel})
    return sorted(found, key=lambda x: x["path"]), errors


def classify_mentions(mentions: set[str], formal: set[str], namespace: dict[str, Any],
                      pending: list[dict[str, str]]) -> dict[str, list[str]]:
    aliases = sorted(mentions & set(namespace["aliases"]))
    pending_aliases = sorted(mentions & namespace["pending_aliases"])
    cross = sorted(mentions & namespace["cross_cutting"])
    pending_names = {x["name"] for x in pending} | namespace["pending_skills"]
    pending_hits = sorted(mentions & pending_names)
    unknown = sorted(mentions - formal - set(namespace["aliases"])
                     - namespace["cross_cutting"] - pending_names)
    return {
        "formal": sorted(mentions & formal),
        "aliases": aliases,
        "pending_aliases": pending_aliases,
        "cross_cutting": cross,
        "pending": pending_hits,
        "unknown": unknown,
    }


def read_domain_spec(path: str | None = None) -> tuple[dict[str, Any], str | None]:
    if path:
        data, error = load_json(path)
        return (data if isinstance(data, dict) else {}), error
    try:
        sys.path.insert(0, os.path.join(HERE, "lib"))
        from domain_spec import DOMAINS  # type: ignore
        return dict(DOMAINS), None
    except Exception as exc:  # noqa: BLE001
        return {}, "domain_spec import failed: %s" % str(exc)[:160]


def source_report(
    formal: set[str],
    domain_spec: dict[str, Any],
    source_paths: dict[str, str],
    namespace: dict[str, Any],
    pending: list[dict[str, str]],
) -> tuple[dict[str, Any], list[str]]:
    records: dict[str, Any] = {}
    errors: list[str] = []
    all_sources = dict(source_paths)
    all_sources["domain_spec"] = "Tool/scripts/lib/domain_spec.py"
    for name, path in all_sources.items():
        if name == "domain_spec":
            mentions = set(domain_spec)
            error = None
        else:
            data, error = load_json(path)
            mentions = source_mentions(name, data)
        if error:
            errors.append(error)
        classified = classify_mentions(mentions, formal, namespace, pending)
        records[name] = {
            "path": path,
            "mentions": sorted(mentions),
            "formal": classified["formal"],
            "missing_formal": sorted(formal - mentions),
            "aliases": classified["aliases"],
            "pending_aliases": classified["pending_aliases"],
            "cross_cutting": classified["cross_cutting"],
            "pending": classified["pending"],
            "unknown": classified["unknown"],
            "load_error": error,
        }
    return records, errors


def actual_case_dirs(cases_root: str, globs: list[str]) -> tuple[set[str], list[str]]:
    found: set[str] = set()
    errors: list[str] = []
    for pattern in globs:
        if not safe_relative_pattern(pattern):
            continue
        for path in glob.glob(os.path.join(cases_root, pattern)):
            if os.path.isdir(path) and path_within(cases_root, path):
                found.add(os.path.basename(os.path.normpath(path)))
            elif os.path.isdir(path):
                errors.append("case_globs 命中越出 Tool/cases 的路径：%s"
                              % os.path.relpath(path, cases_root).replace(os.sep, "/"))
    return found, errors


def case_reports(
    packs_by_id: dict[str, dict[str, Any]],
    domain_spec: dict[str, Any],
    cases_root: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for domain in sorted(packs_by_id):
        pack = packs_by_id[domain]
        raw_cases = pack["raw"].get("cases", [])
        declared = {x for x in raw_cases if isinstance(x, str)} if isinstance(raw_cases, list) else set()
        invalid: list[str] = []
        if not isinstance(raw_cases, list):
            invalid.append("pack.json cases 不是数组")
        elif any(not isinstance(x, str) for x in raw_cases):
            invalid.append("pack.json cases 含非字符串")
        spec = domain_spec.get(domain)
        if not isinstance(spec, dict):
            invalid.append("domain_spec 缺少正式域")
            spec = {}
        globs = spec.get("case_globs", [])
        if not isinstance(globs, list):
            globs = []
            invalid.append("domain_spec.case_globs 不是数组")
        raw_globs = [x for x in globs if isinstance(x, str)]
        unsafe_globs = [x for x in raw_globs if not safe_relative_pattern(x)]
        if unsafe_globs:
            invalid.append("domain_spec.case_globs 越出 cases 根：%s" %
                           ",".join(unsafe_globs))
        globs = [x for x in raw_globs if safe_relative_pattern(x)]
        actual, boundary_errors = actual_case_dirs(cases_root, globs)
        invalid.extend(boundary_errors)
        unsafe_declared = {x for x in declared if not safe_relative_pattern(x)}
        if unsafe_declared:
            invalid.append("pack.json cases 越出 cases 根：%s"
                           % ",".join(sorted(unsafe_declared)))
        declared_safe = declared - unsafe_declared

        raw_roles = pack["raw"].get("case_roles")
        witness_role: set[str] = set()
        depth_role: set[str] = set()
        if not isinstance(raw_roles, dict):
            invalid.append("pack.json case_roles 不是对象")
        else:
            extra_roles = set(raw_roles) - {"witness", "depth_gate"}
            if extra_roles:
                invalid.append("case_roles 含未知角色：%s" % ",".join(sorted(extra_roles)))
            for role in ("witness", "depth_gate"):
                value = raw_roles.get(role)
                if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
                    invalid.append("case_roles.%s 不是字符串数组" % role)
                    continue
                if role == "witness":
                    witness_role = set(value)
                else:
                    depth_role = set(value)
            if isinstance(raw_roles.get("witness"), list) and witness_role != declared:
                invalid.append("case_roles.witness 与 pack.json cases 不一致")
            if isinstance(raw_roles.get("depth_gate"), list) and depth_role != actual:
                invalid.append("case_roles.depth_gate 与 domain_spec.case_globs 实际命中不一致")

        declared_only = declared - actual
        glob_only = actual - declared
        role_split_explained = sorted(
            (declared_only & witness_role) | (glob_only & depth_role))
        role_split_unexplained = sorted(
            (declared_only - witness_role) | (glob_only - depth_role))
        rows.append({
            "domain": domain,
            "case_globs": globs,
            "declared": sorted(declared),
            "actual": sorted(actual),
            "witness_cases": sorted(declared),
            "depth_gate_cases": sorted(actual),
            "declared_only": sorted(declared_only),
            "glob_only": sorted(glob_only),
            "role_split_explained": role_split_explained,
            "role_split_unexplained": role_split_unexplained,
            "missing_on_disk": sorted(
                x for x in declared_safe
                if (not path_within(cases_root, os.path.join(cases_root, x))
                    or not os.path.isdir(os.path.join(cases_root, x)))),
            "overlap": sorted(declared_safe & actual),
            "invalid": invalid,
        })
    return rows


def presence_reports(
    packs_by_id: dict[str, dict[str, Any]],
    domain_spec: dict[str, Any],
    deploy_root: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for domain in sorted(packs_by_id):
        pack = packs_by_id[domain]
        pack_dir = os.path.dirname(pack["path"])
        spec = domain_spec.get(domain)
        spec_present = isinstance(spec, dict)
        skill_name = str(spec.get("skill") or domain) if spec_present else domain
        safe_skill = safe_relative_pattern(skill_name) and "/" not in skill_name.replace("\\", "/")
        deploy_dir = os.path.join(deploy_root, skill_name) if safe_skill else ""
        rows.append({
            "domain": domain,
            "pack_json": {"path": pack["path"], "present": os.path.isfile(pack["path"])},
            "skill_md": {"path": os.path.join(pack_dir, "SKILL.md"),
                         "present": os.path.isfile(os.path.join(pack_dir, "SKILL.md"))},
            "domain_spec": {"present": spec_present, "skill": skill_name},
            "deployment_skill_dir": {"path": deploy_dir, "present":
                                     bool(safe_skill and os.path.isdir(deploy_dir)),
                                     "invalid": not safe_skill},
        })
    return rows


def has_contract_drift(report: dict[str, Any]) -> bool:
    if report["errors"]:
        return True
    if report["pack_errors"]:
        return True
    if report["formal_domain_spec_only"]:
        return True
    for source in report["sources"].values():
        if source["load_error"] or source["missing_formal"] or source["unknown"]:
            return True
    for row in report["cases"]:
        if row["role_split_unexplained"] or row["missing_on_disk"] or row["invalid"]:
            return True
    for row in report["presence"]:
        if not all((row["pack_json"]["present"], row["skill_md"]["present"],
                    row["domain_spec"]["present"], row["deployment_skill_dir"]["present"])):
            return True
    return False


def build_report(
    root: str = ROOT,
    deploy_root: str = DEPLOY_ROOT,
    domain_spec_override: dict[str, Any] | None = None,
    source_paths_override: dict[str, str] | None = None,
    namespace_config_override: dict[str, Any] | None = None,
    namespace_path_override: str | None = None,
) -> dict[str, Any]:
    skill_root = os.path.join(root, "Tool", "skill")
    config_root = os.path.join(root, "Tool", "config")
    cases_root = os.path.join(root, "Tool", "cases")
    packs, pack_errors = load_packs(skill_root)
    formal = {p["id"] for p in packs}
    domain_spec, spec_error = (domain_spec_override, None) if domain_spec_override is not None \
        else read_domain_spec()
    domain_spec = domain_spec or {}
    namespace_path = namespace_path_override or os.path.join(config_root, "domain-aliases.json")
    if namespace_config_override is not None:
        namespace_config = namespace_config_override
        namespace_error = validate_namespace_config(namespace_config)
    else:
        namespace_config, namespace_error = load_namespace_config(namespace_path)
    namespace_config = namespace_config or {}
    namespace = namespace_names(namespace_config)
    namespace_formal = namespace["formal_domains"]
    namespace_errors = [namespace_error] if namespace_error else []
    namespace_errors.extend("formal_domains 缺少 pack id: %s" % x
                            for x in sorted(formal - namespace_formal))
    namespace_errors.extend("formal_domains 含非 pack id: %s" % x
                            for x in sorted(namespace_formal - formal))
    source_paths = source_paths_override or {
        "capability-matrix": os.path.join(config_root, "capability-matrix.json"),
        "playbook-domains": os.path.join(config_root, "playbook-domains.json"),
        "taskcard-sources": os.path.join(config_root, "taskcard-sources.json"),
    }
    pending, pending_errors = pending_skills(skill_root, namespace_config)
    sources, source_errors = source_report(formal, domain_spec, source_paths, namespace, pending)
    packs_by_id = {p["id"]: p for p in packs}
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "evidence_level": "structural/static",
        "root": root,
        "formal_domains": sorted(formal),
        "pack_count": len(formal),
        "pack_errors": pack_errors,
        "domain_spec_domains": sorted(domain_spec),
        "formal_domain_spec_only": sorted(set(domain_spec) - formal),
        "namespace": {
            "path": namespace_path,
            "formal_domains": sorted(namespace_formal),
            "aliases": namespace_config.get("aliases", {}),
            "pending_aliases": sorted(namespace["pending_aliases"]),
            "cross_cutting": sorted(namespace["cross_cutting"]),
            "pending_patterns": namespace["pending_patterns"],
            "errors": namespace_errors,
        },
        "known_aliases": namespace_config.get("aliases", {}),
        "cross_cutting_skills": [
            {"name": name, "present": os.path.isdir(os.path.join(skill_root, name))}
            for name in sorted(namespace["cross_cutting"])
        ],
        "sources": sources,
        "pending_skills": pending,
        "cases": case_reports(packs_by_id, domain_spec, cases_root),
        "presence": presence_reports(packs_by_id, domain_spec, deploy_root),
        "errors": (namespace_errors + pack_errors + pending_errors
                   + ([spec_error] if spec_error else []) + source_errors),
    }
    report["drift"] = has_contract_drift(report)
    report["ok"] = not report["drift"]
    report["summary"] = {
        "formal_domains": len(formal),
        "source_count": len(sources),
        "alias_hits": sorted({x for s in sources.values() for x in s["aliases"]}),
        "pending_alias_hits": sorted({x for s in sources.values() for x in s["pending_aliases"]}),
        "unknown_hits": sorted({x for s in sources.values() for x in s["unknown"]}),
        "cross_cutting_hits": sorted({x for s in sources.values() for x in s["cross_cutting"]}),
        "pending_skill_count": len(pending),
        "case_drift_domains": sorted(row["domain"] for row in report["cases"]
                                      if row["role_split_unexplained"]
                                      or row["missing_on_disk"] or row["invalid"]),
        "role_split_domains": sorted(row["domain"] for row in report["cases"]
                                     if row["role_split_explained"]),
        "presence_gaps": sorted(row["domain"] for row in report["presence"]
                                 if not all((row["pack_json"]["present"], row["skill_md"]["present"],
                                             row["domain_spec"]["present"],
                                             row["deployment_skill_dir"]["present"]))),
        "verdict": "DRIFT" if report["drift"] else "CLEAN",
    }
    return report


def print_human(report: dict[str, Any]) -> None:
    print("schema: %s" % report["schema"])
    print("evidence_level: %s" % report["evidence_level"])
    print("formal domains (%d): %s" % (report["pack_count"], ", ".join(report["formal_domains"])))
    for name, source in report["sources"].items():
        bits = []
        for key, label in (("missing_formal", "missing"), ("aliases", "aliases"),
                           ("pending_aliases", "pending-aliases"), ("unknown", "unknown"),
                           ("cross_cutting", "cross"),
                           ("pending", "pending")):
            if source[key]:
                bits.append("%s=%s" % (label, ",".join(source[key])))
        print("source %-20s %s" % (name + ":", "; ".join(bits) if bits else "formal names aligned"))
    print("pending skills (%d): %s" % (
        len(report["pending_skills"]),
        ", ".join(x["path"] for x in report["pending_skills"]) or "none"))
    print("cross-cutting skills: %s" % ", ".join(
        x["name"] for x in report["cross_cutting_skills"] if x["present"]) or "none")
    print("case contract:")
    for row in report["cases"]:
        drift = []
        for key in ("role_split_unexplained", "missing_on_disk", "invalid"):
            if row[key]:
                drift.append("%s=%s" % (key, ",".join(row[key])))
        if row["role_split_explained"]:
            drift.insert(0, "role_split_explained=%s" % ",".join(row["role_split_explained"]))
        print("  %-24s %s" % (row["domain"], "; ".join(drift) if drift else "clean"))
    print("presence:")
    for row in report["presence"]:
        missing = []
        for key, label in (("pack_json", "pack.json"), ("skill_md", "SKILL.md"),
                           ("domain_spec", "domain_spec"),
                           ("deployment_skill_dir", "deployment")):
            if not row[key]["present"]:
                missing.append(label)
        print("  %-24s %s" % (row["domain"], "missing=" + ",".join(missing) if missing else "present"))
    if report["formal_domain_spec_only"]:
        print("domain_spec-only: %s" % ", ".join(report["formal_domain_spec_only"]))
    if report["errors"]:
        print("errors: %s" % "; ".join(report["errors"]))
    print("verdict: %s (default mode is report-only; --strict returns 2)" % report["summary"]["verdict"])


def make_selftest_fixture(root: str, deploy_root: str, domain_spec: dict[str, Any]) -> dict[str, str]:
    os.makedirs(os.path.join(root, "Tool", "skill"), exist_ok=True)
    os.makedirs(os.path.join(root, "Tool", "config"), exist_ok=True)
    os.makedirs(os.path.join(root, "Tool", "cases"), exist_ok=True)
    for domain, spec in domain_spec.items():
        skill_dir = os.path.join(root, "Tool", "skill", domain)
        os.makedirs(skill_dir, exist_ok=True)
        case_glob = (spec.get("case_globs") or [domain + "*"])[0]
        case_name = str(case_glob).split("*", 1)[0] + "case"
        write_json(os.path.join(skill_dir, "pack.json"), {
            "schema": "seep.pack/1", "id": domain, "cases": [case_name],
            "case_roles": {"witness": [case_name], "depth_gate": [case_name]},
        })
        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as fh:
            fh.write("fixture\n")
        os.makedirs(os.path.join(root, "Tool", "cases", case_name), exist_ok=True)
        os.makedirs(os.path.join(deploy_root, str(spec.get("skill") or domain)), exist_ok=True)
    os.makedirs(os.path.join(root, "Tool", "skill", "_pending", "fixture-pending"), exist_ok=True)
    with open(os.path.join(root, "Tool", "skill", "_pending", "fixture-pending", "SKILL.md"),
              "w", encoding="utf-8") as fh:
        fh.write("fixture pending\n")
    namespace = {
        "schema": "seep.domain-aliases/1",
        "formal_domains": sorted(domain_spec),
        "aliases": {
            "reverse": {"alias_to": "softseep", "status": "legacy"},
            "client-license-validation-bypass": {"alias_to": None, "status": "pending-alias"},
        },
        "cross_cutting": ["seep-router", "unpack-loop"],
        "pending_patterns": ["_pending/**/*"],
    }
    namespace_path = os.path.join(root, "Tool", "config", "domain-aliases.json")
    write_json(namespace_path, namespace)
    cap = {"formal_domains": sorted(domain_spec), "families": sorted(domain_spec),
           "capabilities": {"fixture": {d: "full" for d in domain_spec}}}
    play = {"map": {"fixture": sorted(domain_spec)}}
    task = {"formal_domains": sorted(domain_spec),
            "domains": {d: ["fixture"] for d in domain_spec}}
    paths = {
        "domain-aliases": namespace_path,
        "capability-matrix": os.path.join(root, "Tool", "config", "capability-matrix.json"),
        "playbook-domains": os.path.join(root, "Tool", "config", "playbook-domains.json"),
        "taskcard-sources": os.path.join(root, "Tool", "config", "taskcard-sources.json"),
    }
    write_json(paths["capability-matrix"], cap)
    write_json(paths["playbook-domains"], play)
    write_json(paths["taskcard-sources"], task)
    return paths


def run_self_test() -> dict[str, Any]:
    domains = {
        "apkseep": {"skill": "apkseep", "case_globs": ["apkseep*"]},
        "firmware-iot": {"skill": "firmware-iot", "case_globs": ["firmware-iot*"]},
        "web-pentest": {"skill": "web-pentest", "case_globs": ["web-pentest*"]},
        "pwn-crypto": {"skill": "pwn-crypto", "case_globs": ["pwn-crypto*"]},
        "protocol-plugin": {"skill": "protocol-plugin", "case_globs": ["protocol*"]},
        "forensics-mobile": {"skill": "forensics-mobile", "case_globs": ["forensics*"]},
        "malware-analysis": {"skill": "malware-analysis", "case_globs": ["malware-analysis*"]},
        "supply-chain-security": {"skill": "supply-chain-security", "case_globs": ["supply-chain*"]},
        "softseep": {"skill": "softseep", "case_globs": ["项目*"]},
    }
    checks: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="seep-domain-contract-") as tmp:
        fixture = os.path.join(tmp, "repo")
        deploy = os.path.join(tmp, "deploy")
        paths = make_selftest_fixture(fixture, deploy, domains)
        clean = build_report(fixture, deploy, domains, paths,
                              namespace_path_override=paths["domain-aliases"])
        checks.append({"name": "clean_pass", "ok": not clean["drift"]})
        checks.append({"name": "namespace_config_read", "ok": (
            clean["namespace"]["aliases"]["reverse"]["alias_to"] == "softseep"
            and "seep-router" in clean["namespace"]["cross_cutting"]
            and clean["namespace"]["pending_aliases"] == ["client-license-validation-bypass"]
            and clean["namespace"]["pending_patterns"] == ["_pending/**/*"]
        )})
        unsafe_namespace = json.loads(json.dumps(
            load_json(paths["domain-aliases"])[0]))
        unsafe_namespace["pending_patterns"] = ["../outside/**/*"]
        unsafe = build_report(
            fixture, deploy, domains, paths,
            namespace_config_override=unsafe_namespace,
            namespace_path_override=paths["domain-aliases"],
        )
        checks.append({"name": "pending_pattern_cannot_escape", "ok": (
            unsafe["drift"]
            and any("pending_patterns" in error for error in unsafe["namespace"]["errors"])
        )})

        # A syntactically relative glob can still resolve outside through a
        # directory link. Both pending skill discovery and case discovery must
        # report that escape and omit the external entry.
        outside_pending = os.path.join(tmp, "outside-pending")
        os.makedirs(outside_pending)
        with open(os.path.join(outside_pending, "SKILL.md"), "w", encoding="utf-8") as fh:
            fh.write("outside\n")
        pending_link = os.path.join(fixture, "Tool", "skill", "_pending", "escaped")
        os.makedirs(os.path.dirname(pending_link), exist_ok=True)
        os.symlink(outside_pending, pending_link, target_is_directory=True)
        linked_pending = pending_skills(
            os.path.join(fixture, "Tool", "skill"),
            load_json(paths["domain-aliases"])[0],
        )
        checks.append({"name": "pending_glob_link_cannot_escape", "ok": (
            not any(item["path"].endswith("/escaped") for item in linked_pending[0])
            and any("越出" in error for error in linked_pending[1])
        )})
        os.unlink(pending_link)

        outside_case = os.path.join(tmp, "outside-case")
        os.makedirs(outside_case)
        case_link = os.path.join(fixture, "Tool", "cases", "apkseep-outside")
        os.symlink(outside_case, case_link, target_is_directory=True)
        linked_case_report = build_report(
            fixture, deploy, domains, paths,
            namespace_path_override=paths["domain-aliases"],
        )
        linked_apk_case = next(x for x in linked_case_report["cases"]
                               if x["domain"] == "apkseep")
        checks.append({"name": "case_glob_link_cannot_escape", "ok": (
            "apkseep-outside" not in linked_apk_case["actual"]
            and any("越出" in error for error in linked_apk_case["invalid"])
            and linked_case_report["drift"]
        )})
        os.unlink(case_link)

        # A witness-only case and a depth-only case are both valid when their
        # roles are explicit.  The glob still defines depth_gate membership.
        apk_pack = os.path.join(fixture, "Tool", "skill", "apkseep", "pack.json")
        role_pack, _ = load_json(apk_pack)
        role_pack["cases"].append("witness-only")
        role_pack["case_roles"]["witness"].append("witness-only")
        write_json(apk_pack, role_pack)
        os.makedirs(os.path.join(fixture, "Tool", "cases", "witness-only"), exist_ok=True)
        os.makedirs(os.path.join(fixture, "Tool", "cases", "apkseep-extra"), exist_ok=True)
        role_pack["case_roles"]["depth_gate"].append("apkseep-extra")
        write_json(apk_pack, role_pack)
        role_split = build_report(fixture, deploy, domains, paths,
                                  namespace_path_override=paths["domain-aliases"])
        role_case = next(x for x in role_split["cases"] if x["domain"] == "apkseep")
        checks.extend([
            {"name": "role_split_explained", "ok": (
                "witness-only" in role_case["role_split_explained"]
                and "apkseep-extra" in role_case["role_split_explained"]
                and not role_split["drift"]
            )},
            {"name": "classified_aliases_do_not_drift", "ok": not role_split["drift"]},
        ])

        task_data, _ = load_json(paths["taskcard-sources"])
        task_data["formal_domains"].remove("apkseep")
        task_data["domains"].pop("apkseep")
        task_data["domains"]["mystery-domain"] = ["fixture"]
        task_data["domains"]["mystery-alias"] = ["fixture"]
        play_data, _ = load_json(paths["playbook-domains"])
        play_data["map"]["fixture"].append("reverse")
        play_data["map"]["fixture"].append("seep-router")
        play_data["map"]["fixture"].append("fixture-pending")
        play_data["map"]["fixture"].append("client-license-validation-bypass")
        write_json(paths["taskcard-sources"], task_data)
        write_json(paths["playbook-domains"], play_data)
        apk_pack = os.path.join(fixture, "Tool", "skill", "apkseep", "pack.json")
        pack_data, _ = load_json(apk_pack)
        pack_data["cases"].append("apkseep-missing")
        write_json(apk_pack, pack_data)
        os.makedirs(os.path.join(fixture, "Tool", "cases", "apkseep-extra"), exist_ok=True)
        dirty = build_report(fixture, deploy, domains, paths,
                              namespace_path_override=paths["domain-aliases"])
        apk_source = dirty["sources"]["taskcard-sources"]
        apk_case = next(x for x in dirty["cases"] if x["domain"] == "apkseep")
        checks.extend([
            {"name": "formal_domain_missing", "ok": "apkseep" in apk_source["missing_formal"]},
            {"name": "old_alias", "ok": "reverse" in dirty["sources"]["playbook-domains"]["aliases"]},
            {"name": "pending_alias", "ok": (
                "client-license-validation-bypass" in dirty["sources"]["playbook-domains"]["pending_aliases"]
                and "client-license-validation-bypass" not in dirty["sources"]["playbook-domains"]["unknown"]
            )},
            {"name": "cross_cutting", "ok": "seep-router" in dirty["sources"]["playbook-domains"]["cross_cutting"]},
            {"name": "pending_skill", "ok": "fixture-pending" in dirty["sources"]["playbook-domains"]["pending"]},
            {"name": "unknown_domain", "ok": "mystery-domain" in apk_source["unknown"]},
            {"name": "unknown_alias", "ok": "mystery-alias" in apk_source["unknown"]},
            {"name": "case_declared_only", "ok": "apkseep-missing" in apk_case["declared_only"]},
            {"name": "case_glob_only", "ok": "apkseep-extra" in apk_case["glob_only"]},
            {"name": "case_missing_on_disk", "ok": "apkseep-missing" in apk_case["missing_on_disk"]},
            {"name": "case_unexplained", "ok": "apkseep-missing" in apk_case["role_split_unexplained"]},
            {"name": "dirty_detected", "ok": dirty["drift"]},
        ])

        # A malformed extra domain pack must make the structural report drift,
        # even when every otherwise-valid pack and source still aligns.
        bad_pack_dir = os.path.join(fixture, "Tool", "skill", "broken-domain")
        os.makedirs(bad_pack_dir, exist_ok=True)
        with open(os.path.join(bad_pack_dir, "pack.json"), "w", encoding="utf-8") as fh:
            fh.write("{not json\n")
        broken = build_report(fixture, deploy, domains, paths,
                              namespace_path_override=paths["domain-aliases"])
        checks.extend([
            {"name": "broken_pack_reported", "ok": any(
                "broken-domain/pack.json" in error for error in broken["pack_errors"])},
            {"name": "broken_pack_drifts", "ok": broken["drift"] and not broken["ok"]},
            {"name": "broken_pack_in_errors", "ok": any(
                "broken-domain/pack.json" in error for error in broken["errors"])},
        ])
    return {
        "schema": "seep.domain-contract-check-self-test/1",
        "ok": all(x["ok"] for x in checks),
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report static drift between nine pack domains and legacy/cross-cutting sources.")
    parser.add_argument("--json", action="store_true", help="emit the structured report")
    parser.add_argument("--strict", action="store_true", help="return 2 when drift or gaps are found")
    parser.add_argument("--self-test", action="store_true", help="run isolated clean and drift regression checks")
    args = parser.parse_args(argv)
    if args.self_test:
        result = run_self_test()
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print("self-test: %s" % ("PASS" if result["ok"] else "FAIL"))
            for check in result["checks"]:
                print("  [%s] %s" % ("PASS" if check["ok"] else "FAIL", check["name"]))
        return 0 if result["ok"] else 1
    report = build_report()
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=False))
    else:
        print_human(report)
    return 2 if args.strict and report["drift"] else 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
