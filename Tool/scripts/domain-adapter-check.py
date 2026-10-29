#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check the long-lived adapter contract of the formal domain packs.

Formal-domain identity comes **only** from `Tool/skill/<dir>/pack.json` where
`id == dir`; the set is dynamic (nine today, but not defined as "exactly nine").
Cross-cutting skills, legacy aliases and `_pending/**` subskills are *not* formal
domains and are excluded by `lib/domain_registry.py`.

This is a structural/static check.  It reads pack.json as the domain entry
point, verifies declared fields (including the per-domain `depth_contract`), and
resolves filesystem pointers without running witness commands, target files,
installers, or network operations.  Default mode is report-only; --strict
returns 2 when any contract is WARN or FAIL.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SKILL_ROOT_REL = "Tool/skill"
SCHEMA = "seep.domain-adapter-check/1"
EVIDENCE_LEVEL = "structural/static"

sys.path.insert(0, os.path.join(HERE, "lib"))
import domain_registry as registry_mod  # noqa: E402  单向：registry 不 import 本脚本


def formal_domains(root=None, skill_root=None):
    """正式域全集（**动态**：pack.json#id == 目录名；不按“恰 9 个”定义）。

    历史：这里是硬编码的 9 元组，多一个 pack 就报 unexpected。现在加域不需要改本文件；
    命名空间分离（横切/别名/待迁移）由 domain_registry 负责，本脚本只消费它的结果。
    """
    return registry_mod.load_registry(root or ROOT, skill_root).ids()


# 兼容旧消费者（skill-import.py 用 getattr(dac, "FORMAL_DOMAINS") 报缺口）：
# 这只是“当前仓库正式域”的派生快照，不是阈值/期望集。
FORMAL_DOMAINS = tuple(formal_domains(ROOT))
CONTRACT_NAMES = (
    "depth_contract",
    "project_lifecycle",
    "input_contract",
    "route_contract",
    "evidence_contract",
    "acceptance_contract",
    "failure_contract",
    "version_contract",
    "extension_contract",
)
REQUIRED_EVIDENCE_FIELDS = ("claim", "confidence", "authority", "evidence")
ALLOWED_AUTHORITIES = {"shipped-artifact", "controlled-replay", "external-service"}
FORBIDDEN_CONFIDENCE = {"inferred", "unknown"}
PATH_KEY_HINTS = (
    "path", "entry", "script", "file", "cmd", "command", "pointer",
    "project", "manager", "version", "run", "migration", "handoff", "resume",
    "criteria",
    "block", "reroute", "route", "variant", "incremental", "extension",
    "parent_skill",
)
PATH_RE = re.compile(r"(?:^|[\\/])(?:Tool|docs|setup|scripts|references|cases)[\\/]|\.py$|\.md$|\.json$")


def is_nonempty(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return value is not None


def load_json(path: str) -> tuple[Any, str | None]:
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            return json.load(handle), None
    except Exception as exc:  # report all malformed packs instead of crashing
        return None, "%s: %s" % (os.path.basename(path), str(exc)[:160])


def rel(root: str, path: str) -> str:
    try:
        return os.path.relpath(path, root).replace(os.sep, "/")
    except Exception:
        return str(path).replace(os.sep, "/")


def resolve_ref(root: str, value: str) -> str | None:
    """Resolve a repository-relative pointer; never accepts a network URI."""
    text = str(value).strip().strip("'\"").replace("\\", "/")
    if not text or "://" in text or text.startswith("~") or os.path.isabs(text):
        return None
    text = text.split("#", 1)[0].split("?", 1)[0].strip()
    if not text:
        return None
    candidate = os.path.normpath(os.path.join(root, text))
    root_real = os.path.realpath(root)
    candidate_real = os.path.realpath(candidate)
    try:
        within = os.path.commonpath((root_real, candidate_real)) == root_real
    except ValueError:
        return None
    if not within:
        return None
    return candidate_real


def path_like(value: Any) -> bool:
    return isinstance(value, str) and bool(PATH_RE.search(value.replace("\\", "/")))


def command_paths(command: Any) -> list[str]:
    if not isinstance(command, str) or not command.strip():
        return []
    try:
        tokens = shlex.split(command, posix=False)
    except ValueError:
        tokens = command.split()
    paths = []
    for token in tokens:
        token = token.strip("'\"").rstrip(",;)")
        normalized = token.replace("\\", "/")
        if ("/" in normalized or "\\" in token) and not normalized.startswith(("http:", "https:")):
            paths.append(token)
        elif normalized.endswith((".py", ".json", ".md", ".ps1", ".sh")):
            paths.append(token)
    return paths


def reachable_paths(root: str, values: list[Any]) -> tuple[list[str], list[str]]:
    found, missing = [], []
    seen = set()
    for value in values:
        if not isinstance(value, str):
            continue
        ref = value.strip()
        if not ref or ref in seen:
            continue
        seen.add(ref)
        path = resolve_ref(root, ref)
        if path and os.path.exists(path):
            found.append(ref)
        else:
            missing.append(ref)
    return found, missing


def command_reachability(root: str, command: Any) -> dict[str, Any]:
    refs = command_paths(command)
    found, missing = reachable_paths(root, refs)
    return {"command": command if isinstance(command, str) else None,
            "references": refs, "reachable": found, "missing": missing,
            "ok": bool(refs) and not missing}


def nested_pointer_values(value: Any, key: str = "") -> list[str]:
    """Collect declared path-like pointers, not arbitrary prose or keywords."""
    values: list[str] = []
    if isinstance(value, dict):
        for name, child in value.items():
            values.extend(nested_pointer_values(child, str(name).lower()))
    elif isinstance(value, list):
        for child in value:
            values.extend(nested_pointer_values(child, key))
    elif isinstance(value, str) and (key in PATH_KEY_HINTS or path_like(value)):
        values.append(value)
    return values


def status(ok: bool, warning: bool = False) -> str:
    if ok:
        return "PASS"
    return "WARN" if warning else "FAIL"


def result(name: str, state: str, evidence: list[str], missing: list[str] | None = None,
           paths: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"status": state, "ok": state == "PASS", "evidence": evidence,
            "missing": missing or [], "paths": paths or [],
            "evidence_level": EVIDENCE_LEVEL}


def make_row(domain: str, pack: dict[str, Any] | None, root: str,
             skill_root: str | None = None,
             load_error: str | None = None) -> dict[str, Any]:
    skill_root = os.path.abspath(skill_root or os.path.join(root, SKILL_ROOT_REL))
    skill_dir = os.path.join(skill_root, domain)
    skill_path = os.path.join(skill_dir, "SKILL.md")
    refs_dir = os.path.join(skill_dir, "references")
    # depth_contract 放在最前：缺它 = 该域的静态深度要求没有登记，
    # 不能因为 8 项适配器契约齐了就当作“域闭合”。
    row: dict[str, Any] = {"domain": domain, "pack": None, "contracts": {},
                           "evidence_level": EVIDENCE_LEVEL}
    depth, depth_errors = (registry_mod.validate_depth_contract(pack["raw"], root,
                                                                skill_root)
                           if pack is not None else (None, [load_error or "pack.json missing"]))
    row["contracts"]["depth_contract"] = result(
        "depth_contract", "PASS" if depth is not None else "FAIL",
        ["pack.depth_contract 合法：%s" % ", ".join(sorted(depth))] if depth else [],
        [] if depth is not None else list(depth_errors))
    if pack is None:
        reason = load_error or "pack.json missing"
        for name in CONTRACT_NAMES:
            row["contracts"][name] = result(name, "FAIL", [], [reason])
        return row

    raw = pack["raw"]
    row["pack"] = {"path": rel(root, pack["path"]), "id": raw.get("id"),
                    "schema": raw.get("schema")}
    skill_exists = os.path.isfile(skill_path)
    refs_failure = os.path.isfile(os.path.join(refs_dir, "02-failure-criteria.md"))

    # project_lifecycle: shared state code is useful evidence, but does not
    # become a per-domain adapter until the pack declares reachable pointers.
    lifecycle = raw.get("project_lifecycle")
    lifecycle_values = nested_pointer_values(lifecycle)
    lifecycle_found, lifecycle_missing = reachable_paths(root, lifecycle_values)
    shared = []
    for relpath in ("Tool/scripts/project_state.py", "Tool/scripts/manager_state.py"):
        if os.path.isfile(os.path.join(root, relpath)):
            shared.append(relpath)
    lifecycle_keys = {str(k) for k in lifecycle} if isinstance(lifecycle, dict) else set()
    lifecycle_required = {"entry", "manager", "handoff", "resume", "version", "run", "migration"}
    lifecycle_nonempty = (isinstance(lifecycle, dict)
                          and all(is_nonempty(lifecycle.get(key)) for key in lifecycle_required))
    lifecycle_ok = (lifecycle_required <= lifecycle_keys and lifecycle_nonempty
                    and bool(lifecycle_values) and not lifecycle_missing)
    lifecycle_state = ("PASS" if lifecycle_ok else
                       ("FAIL" if lifecycle_missing else status(False, warning=bool(shared))))
    lifecycle_gaps = list(lifecycle_missing)
    if not (lifecycle_required <= lifecycle_keys and lifecycle_nonempty and lifecycle_values):
        lifecycle_gaps.append(
            "pack.project_lifecycle must declare non-empty entry/manager/handoff/resume/version/run/migration pointers")
    row["contracts"]["project_lifecycle"] = result(
        "project_lifecycle", lifecycle_state,
        (["declared reachable lifecycle pointers: %s" % ", ".join(lifecycle_found)]
         if lifecycle_ok else ["shared lifecycle entries present: %s" % ", ".join(shared)]),
        lifecycle_gaps,
        [{"ref": x, "reachable": x in lifecycle_found} for x in lifecycle_values])

    # input_contract: l1/cases are real structural fallback evidence, but an
    # explicit type/sample/environment declaration is required for full PASS.
    inputs = raw.get("input_contract")
    input_keys = set(inputs) if isinstance(inputs, dict) else set()
    declared_cases = raw.get("cases")
    case_missing = []
    if isinstance(declared_cases, list):
        for case in declared_cases:
            if isinstance(case, str):
                ref = "Tool/cases/%s" % case
                resolved = resolve_ref(root, ref)
                if resolved is None or not os.path.isdir(resolved):
                    case_missing.append(ref)
    input_structural = (is_nonempty(raw.get("l1")) and isinstance(declared_cases, list)
                        and bool(declared_cases) and skill_exists and not case_missing)
    input_explicit = (isinstance(inputs, dict)
                      and all(is_nonempty(inputs.get(key))
                              for key in ("types", "sample_completeness", "environment")))
    input_state = "PASS" if input_structural and input_explicit else ("WARN" if input_structural else "FAIL")
    row["contracts"]["input_contract"] = result(
        "input_contract", input_state,
        ["pack.l1 non-empty", "declared case directories reachable"] if input_structural else [],
        ([] if input_explicit else ["explicit input_contract.types/sample_completeness/environment"])
        + case_missing,
    )

    # route_contract is intentionally tied to the actual skill directory and
    # reference tree, not just to route/stage words in pack.json.
    routes = raw.get("routes")
    route_ok = (isinstance(routes, list) and bool(routes)
                and all(isinstance(x, dict) and is_nonempty(x.get("label"))
                        and isinstance(x.get("must"), list) and bool(x.get("must")) for x in routes)
                and isinstance(raw.get("stages"), list) and bool(raw.get("stages"))
                and isinstance(raw.get("limitations"), list) and bool(raw.get("limitations"))
                and isinstance(raw.get("invalidation"), list) and bool(raw.get("invalidation"))
                and skill_exists and os.path.isdir(refs_dir))
    row["contracts"]["route_contract"] = result(
        "route_contract", "PASS" if route_ok else "FAIL",
        ["routes/stages/limitations/invalidation non-empty", rel(root, skill_path), rel(root, refs_dir)]
        if route_ok else [],
        [] if route_ok else ["non-empty routes/stages/limitations/invalidation and reachable SKILL.md/references"],
    )

    # Evidence is the one contract already expressed as a complete structured
    # object in every current pack; validate exact values instead of keywords.
    evidence = raw.get("evidence_contract")
    evidence_ok = (isinstance(evidence, dict)
                   and isinstance(evidence.get("required_fields"), list)
                   and set(evidence.get("required_fields")) >= set(REQUIRED_EVIDENCE_FIELDS)
                   and isinstance(evidence.get("authority_allow"), list)
                   and bool(set(evidence.get("authority_allow")) & ALLOWED_AUTHORITIES)
                   and isinstance(evidence.get("pass_forbids_confidence"), list)
                   and bool(set(evidence.get("pass_forbids_confidence")) & FORBIDDEN_CONFIDENCE))
    row["contracts"]["evidence_contract"] = result(
        "evidence_contract", "PASS" if evidence_ok else "FAIL",
        ["required_fields/authority_allow/pass_forbids_confidence validated as arrays"],
        [] if evidence_ok else ["complete evidence_contract arrays and allowed values"],
    )

    # Acceptance is proven only by reachable command/file references.  Commands
    # are parsed but never executed.
    witness = raw.get("witness") if isinstance(raw.get("witness"), dict) else {}
    witness_tool = raw.get("witness_tool") if isinstance(raw.get("witness_tool"), dict) else {}
    witness_report = command_reachability(root, witness.get("cmd"))
    tool_report = command_reachability(root, witness_tool.get("cmd"))
    verification_dir = os.path.isdir(os.path.join(root, "docs", "verification"))
    acceptance_ok = witness_report["ok"] and tool_report["ok"] and verification_dir
    row["contracts"]["acceptance_contract"] = result(
        "acceptance_contract", "PASS" if acceptance_ok else "FAIL",
        ["witness command reachable", "witness_tool entry reachable", "docs/verification reachable"]
        if acceptance_ok else [],
        [] if acceptance_ok else ["reachable witness/witness_tool references and docs/verification"],
        [witness_report, tool_report])

    failure = raw.get("failure_contract")
    failure_values = nested_pointer_values(failure)
    failure_found, failure_missing = reachable_paths(root, failure_values)
    invalidation = raw.get("invalidation")
    failure_structural = (isinstance(raw.get("limitations"), list) and bool(raw.get("limitations"))
                          and isinstance(invalidation, list) and bool(invalidation)
                          and refs_failure)
    failure_block = failure.get("block") if isinstance(failure, dict) else None
    failure_block_ok = (isinstance(failure_block, str) and is_nonempty(failure_block)
                        and (failure_block.replace("\\", "/").endswith("Tool/config/blockers.json")
                             or failure_block.replace("\\", "/").endswith("Tool/scripts/manager_state.py")))
    failure_explicit = (isinstance(failure, dict)
                        and all(is_nonempty(failure.get(key)) for key in ("criteria", "block", "reroute"))
                        and failure_block_ok and bool(failure_values) and not failure_missing)
    failure_state = "PASS" if failure_structural and failure_explicit else ("WARN" if failure_structural else "FAIL")
    row["contracts"]["failure_contract"] = result(
        "failure_contract", failure_state,
        ["limitations/invalidation non-empty", rel(root, os.path.join(refs_dir, "02-failure-criteria.md"))]
        + (["declared failure pointers reachable: %s" % ", ".join(failure_found)] if failure_explicit else []),
        ([] if failure_explicit else ["explicit reachable failure_contract criteria/block/reroute pointers"])
        + ([] if failure_structural else ["limitations, invalidation, and references/02-failure-criteria.md"]),
        [{"ref": x, "reachable": x in failure_found} for x in failure_values])

    version = raw.get("version_contract")
    version_values = nested_pointer_values(version)
    version_found, version_missing = reachable_paths(root, version_values)
    version_keys = set(version) if isinstance(version, dict) else set()
    version_required = {"version", "run", "migration", "variant", "incremental"}
    version_nonempty = (isinstance(version, dict)
                        and all(is_nonempty(version.get(key)) for key in version_required))
    version_ok = (version_required <= version_keys and version_nonempty and bool(version_values)
                  and not version_missing)
    row["contracts"]["version_contract"] = result(
        "version_contract", "PASS" if version_ok else "FAIL",
        ["version/run/migration/variant/incremental pointers reachable: %s" % ", ".join(version_found)] if version_ok else [],
        [] if version_ok else ["pack.version_contract with reachable version/run/migration/variant/incremental pointers"],
        [{"ref": x, "reachable": x in version_found} for x in version_values])

    extension = raw.get("extension_contract")
    extension_values = nested_pointer_values(extension)
    extension_found, extension_missing = reachable_paths(root, extension_values)
    extension_keys = set(extension) if isinstance(extension, dict) else set()
    extension_required = {"entry", "docs", "pack", "parent_skill"}
    extension_nonempty = (isinstance(extension, dict)
                          and all(is_nonempty(extension.get(key)) for key in extension_required))
    extension_ok = (extension_required <= extension_keys and extension_nonempty and bool(extension_values)
                    and not extension_missing and any("skill-import" in x or "pack.json" in x
                                                      for x in extension_found))
    row["contracts"]["extension_contract"] = result(
        "extension_contract", "PASS" if extension_ok else "FAIL",
        ["extension entry and pack/skill import path reachable: %s" % ", ".join(extension_found)]
        if extension_ok else [],
        ([] if extension_ok else list(extension_missing)
         + ["explicit reachable skill/tool/domain extension entry (skill-import.py or pack.json)"]),
        [{"ref": x, "reachable": x in extension_found} for x in extension_values])
    return row


def load_packs(root: str, skill_root: str | None = None) -> tuple[dict[str, dict[str, Any]], list[str]]:
    packs: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    skill_root = os.path.abspath(skill_root or os.path.join(root, SKILL_ROOT_REL))
    if not os.path.isdir(skill_root):
        return packs, ["missing Tool/skill"]
    for dirname in sorted(os.listdir(skill_root)):
        path = os.path.join(skill_root, dirname, "pack.json")
        if not os.path.isfile(path):
            continue
        raw, error = load_json(path)
        if error:
            errors.append("%s/pack.json: %s" % (dirname, error))
            continue
        if dirname.startswith(("_", ".")):
            errors.append("%s：归档/待迁移命名空间（_ 开头）不得带 pack.json 冒充正式域" % dirname)
            continue
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not raw.get("id", "").strip():
            errors.append("%s/pack.json missing non-empty id" % dirname)
            continue
        domain = raw["id"].strip()
        if domain != dirname:
            errors.append("%s/pack.json id=%s does not match directory" % (dirname, domain))
        if domain in packs:
            errors.append("duplicate pack id: %s" % domain)
        packs[domain] = {"path": path, "raw": raw}
    return packs, errors


def build_report(root: str = ROOT, skill_root: str | None = None) -> dict[str, Any]:
    """根可显式注入（测试用）；默认本仓库结构，不依赖任何全局 Root 真相源。"""
    root = os.path.abspath(root)
    skill_root = os.path.abspath(skill_root or os.path.join(root, SKILL_ROOT_REL))
    packs, errors = load_packs(root, skill_root)
    formal = formal_domains(root, skill_root)
    registry = registry_mod.load_registry(root, skill_root)
    errors.extend(registry.errors)
    rows = []
    for domain in formal:
        pack = packs.get(domain)
        rows.append(make_row(domain, pack, root, skill_root,
                             None if pack else "formal pack missing"))
    unexpected = sorted(set(packs) - set(formal))
    if unexpected:
        # 多出来的 pack 不再“报 unexpected 就完事”：它们的 id 落在正式集合之外
        # （横切/别名/待迁移命名空间，或 id 与目录不一致），必须显式说明原因。
        errors.append("pack id 不在正式域集合（命名空间冲突或身份不一致）：%s"
                      % ", ".join(unexpected))
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0}
    for row in rows:
        for contract in row["contracts"].values():
            counts[contract["status"]] += 1
    gap_domains = sorted(row["domain"] for row in rows
                         if any(c["status"] != "PASS" for c in row["contracts"].values()))
    contract_gaps = sorted({name for row in rows for name, c in row["contracts"].items()
                            if c["status"] != "PASS"})
    report = {
        "schema": SCHEMA,
        "evidence_level": EVIDENCE_LEVEL,
        "root": root,
        "formal_domains": list(formal),
        "pack_domains": sorted(packs),
        "incomplete": registry.incomplete(),
        "errors": errors,
        "domains": rows,
        "summary": {"domain_count": len(rows), "contract_count": len(rows) * len(CONTRACT_NAMES),
                    "pass": counts["PASS"], "warn": counts["WARN"], "fail": counts["FAIL"],
                    "gap_domains": gap_domains, "gap_contracts": contract_gaps},
    }
    report["contract_ok"] = not errors and not gap_domains
    report["execution_ok"] = None
    report["execution_evaluated"] = False
    report["ok"] = report["contract_ok"]
    report["verdict"] = ("PASS" if report["contract_ok"]
                         else ("FAIL" if errors or counts["FAIL"] else "WARN"))
    return report


def print_human(report: dict[str, Any]) -> None:
    print("schema: %s" % report["schema"])
    print("evidence_level: %s" % report["evidence_level"])
    print("formal domains (%d): %s" % (len(report["formal_domains"]), ", ".join(report["formal_domains"])))
    for row in report["domains"]:
        print("[%s] %s" % ("PASS" if all(c["status"] == "PASS" for c in row["contracts"].values()) else "GAP",
                             row["domain"]))
        for name in CONTRACT_NAMES:
            contract = row["contracts"][name]
            detail = "; ".join(contract["missing"] or contract["evidence"] or ["no structural evidence"])
            print("  %-22s %-4s %s" % (name, contract["status"], detail))
    summary = report["summary"]
    print("summary: PASS=%d WARN=%d FAIL=%d domains_with_gaps=%d" %
          (summary["pass"], summary["warn"], summary["fail"], len(summary["gap_domains"])))
    if report["errors"]:
        print("errors: %s" % "; ".join(report["errors"]))
    print("verdict: %s (default report-only; --strict returns 2 for gaps)" % report["verdict"])


def write_fixture(path: str, domain: str) -> None:  # noqa: D401 - fixture builder
    skill = os.path.join(path, "Tool", "skill", domain)
    os.makedirs(os.path.join(skill, "references"), exist_ok=True)
    os.makedirs(os.path.join(path, "Tool", "cases", domain + "01"), exist_ok=True)
    os.makedirs(os.path.join(path, "docs", "verification"), exist_ok=True)
    for relpath in ("Tool/scripts/project_state.py", "Tool/scripts/manager_state.py",
                     "Tool/scripts/case_state.py", "Tool/scripts/skill-import.py",
                     "Tool/docs/EXTEND.md",
                     "Tool/skill/%s/scripts/witness.py" % domain):
        full = os.path.join(path, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as handle:
            handle.write("fixture\n")
    with open(os.path.join(skill, "SKILL.md"), "w", encoding="utf-8") as handle:
        handle.write("fixture skill\n")
    with open(os.path.join(skill, "references", "02-failure-criteria.md"), "w", encoding="utf-8") as handle:
        handle.write("fixture failure criteria\n")
    pack = {
        "schema": "seep.pack/1", "id": domain, "l1": "file sample and isolated environment",
        "depth_contract": {"skill": domain, "board": domain, "matrix": "%s-matrix.json" % domain,
                           "case_globs": [domain + "*"], "ext_scripts": []},
        "routes": [{"label": "fixture", "must": ["fixture"]}],
        "stages": ["intake", "verify"], "limitations": ["fixture limit"],
        "invalidation": ["fixture -> alternate route"], "cases": [domain + "01"],
        "witness": {"cmd": "python Tool/scripts/case_state.py --case Tool/cases/%s01" % domain},
        "witness_tool": {"cmd": "Tool/skill/%s/scripts/witness.py" % domain},
        "evidence_contract": {"required_fields": list(REQUIRED_EVIDENCE_FIELDS),
                              "authority_allow": sorted(ALLOWED_AUTHORITIES),
                              "pass_forbids_confidence": sorted(FORBIDDEN_CONFIDENCE)},
        "project_lifecycle": {key: "Tool/scripts/%s.py" % ("manager_state" if key in {"manager", "handoff", "resume", "run"} else "project_state")
                              for key in ("entry", "manager", "handoff", "resume", "version", "run", "migration")},
        "input_contract": {"types": ["file"], "sample_completeness": "case target present",
                           "environment": "isolated fixture"},
        "failure_contract": {"criteria": "Tool/skill/%s/references/02-failure-criteria.md" % domain,
                              "block": "Tool/scripts/manager_state.py", "reroute": "Tool/scripts/project_state.py"},
        "version_contract": {"version": "Tool/scripts/project_state.py", "run": "Tool/scripts/project_state.py",
                             "migration": "Tool/scripts/project_state.py", "variant": "Tool/scripts/manager_state.py",
                             "incremental": "Tool/scripts/project_state.py"},
        "extension_contract": {"entry": "Tool/scripts/skill-import.py", "docs": "Tool/docs/EXTEND.md",
                               "pack": "Tool/skill/%s/pack.json" % domain,
                               "parent_skill": "Tool/skill/softseep/SKILL.md"},
    }
    with open(os.path.join(skill, "pack.json"), "w", encoding="utf-8") as handle:
        json.dump(pack, handle, ensure_ascii=False, indent=2)


def run_self_test() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="seep-domain-adapter-") as tmp:
        seed = formal_domains(ROOT) or ["fixture-domain"]
        for domain in seed:
            write_fixture(tmp, domain)
        clean = build_report(tmp)
        checks.append({"name": "clean", "ok": clean["contract_ok"]})
        checks.append({"name": "execution_is_not_claimed", "ok": (
            clean["execution_evaluated"] is False
            and clean["execution_ok"] is None
        )})

        # build_report's injected skill root must also be the root used to
        # validate each pack's depth_contract.  A repository-relative config
        # can otherwise make a valid external skill tree look missing.
        alternate_skill_root = os.path.join(tmp, "alternate-skills")
        os.makedirs(alternate_skill_root)
        for domain in seed:
            source_dir = os.path.join(tmp, SKILL_ROOT_REL, domain)
            shutil.copytree(source_dir, os.path.join(alternate_skill_root, domain))
        alternate = build_report(tmp, alternate_skill_root)
        checks.append({"name": "injected_skill_root_used_for_depth", "ok": (
            alternate["formal_domains"]
            and all(row["contracts"]["depth_contract"]["status"] == "PASS"
                    for row in alternate["domains"])
        )})

        pack_path = os.path.join(tmp, "Tool", "skill", "apkseep", "pack.json")
        pack, _ = load_json(pack_path)
        pack.pop("input_contract", None)
        with open(pack_path, "w", encoding="utf-8") as handle:
            json.dump(pack, handle)
        missing_field = build_report(tmp)
        checks.append({"name": "missing_field_warn", "ok": next(r for r in missing_field["domains"] if r["domain"] == "apkseep")["contracts"]["input_contract"]["status"] == "WARN"})

        pack["witness_tool"]["cmd"] = "Tool/skill/apkseep/scripts/missing-witness.py"
        with open(pack_path, "w", encoding="utf-8") as handle:
            json.dump(pack, handle)
        missing_entry = build_report(tmp)
        checks.append({"name": "missing_entry_fail", "ok": next(r for r in missing_entry["domains"] if r["domain"] == "apkseep")["contracts"]["acceptance_contract"]["status"] == "FAIL"})

        pack["witness_tool"]["cmd"] = "Tool/skill/apkseep/scripts/witness.py"
        pack.pop("version_contract", None)
        with open(pack_path, "w", encoding="utf-8") as handle:
            json.dump(pack, handle)
        missing_version = build_report(tmp)
        checks.append({"name": "missing_version_pointer_fail", "ok": next(r for r in missing_version["domains"] if r["domain"] == "apkseep")["contracts"]["version_contract"]["status"] == "FAIL"})

        broken_dir = os.path.join(tmp, "Tool", "skill", "broken-domain")
        os.makedirs(broken_dir, exist_ok=True)
        with open(os.path.join(broken_dir, "pack.json"), "w", encoding="utf-8") as handle:
            handle.write("{broken")
        broken = build_report(tmp)
        checks.append({"name": "load_error_is_fail_not_warn", "ok": (
            broken["verdict"] == "FAIL"
            and any("broken-domain/pack.json" in error for error in broken["errors"])
        )})
    return {"schema": "seep.domain-adapter-check-self-test/1", "ok": all(x["ok"] for x in checks), "checks": checks}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check structural/static long-lived adapter contracts for the formal domain packs "
                    "(ids are read from pack.json; the count is dynamic, not fixed at nine).")
    parser.add_argument("--json", action="store_true", help="emit a structured report")
    parser.add_argument("--strict", action="store_true", help="return 2 when any domain contract has a gap")
    parser.add_argument("--self-test", action="store_true", help="run isolated clean, missing-field, missing-entry, and version-pointer tests")
    args = parser.parse_args(argv)
    if args.self_test:
        report = run_self_test()
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print("self-test: %s" % ("PASS" if report["ok"] else "FAIL"))
            for check in report["checks"]:
                print("  [%s] %s" % ("PASS" if check["ok"] else "FAIL", check["name"]))
        return 0 if report["ok"] else 1
    report = build_report()
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_human(report)
    return 2 if args.strict and not report["contract_ok"] else 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
