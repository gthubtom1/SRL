#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Read-only case-library access used by the MCP server.

Keeping this logic outside the tool registry keeps the server entrypoint below
its source-line budget. Case files are scanned live; no generated index or
cached copy can become stale.
"""
from __future__ import annotations

import json
import os


def case_lib_dir() -> str:
    """Return ``<repo>/Tool/cases`` without consulting user state."""
    repo_root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    return os.path.join(repo_root, "Tool", "cases")


def case_files() -> list[tuple[str, str]]:
    """Return ``[(directory_name, case_json_path)]`` in stable order."""
    root = case_lib_dir()
    found: list[tuple[str, str]] = []
    if not os.path.isdir(root):
        return found
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if (not os.path.isdir(path) or os.path.islink(path)
                or name.startswith(".") or name == "__pycache__"):
            continue
        case_path = os.path.join(path, "case.json")
        safe_case_path = _case_path(root, path, "case.json")
        if safe_case_path and not os.path.islink(case_path) and os.path.isfile(safe_case_path):
            found.append((name, safe_case_path))
    return found


def normalize_case(raw, dirname: str) -> dict:
    """Normalize one case file while keeping malformed optional fields harmless."""
    if not isinstance(raw, dict):
        raw = {}
    entry = {"dir": dirname}
    for field, default in (
        ("id", ""),
        ("domain", ""),
        ("target_type", ""),
        ("protection", []),
        ("authority", ""),
        ("goal_level", ""),
        ("outcome", ""),
        ("artifacts", []),
        ("lessons", []),
        ("tags", []),
        ("refs", []),
        ("updated", ""),
    ):
        value = raw.get(field, default)
        if isinstance(default, list):
            if not isinstance(value, list):
                value = []
            elif field == "artifacts":
                value = [item for item in value if isinstance(item, dict)]
            else:
                value = [item for item in value if isinstance(item, str)]
        elif not isinstance(value, str):
            value = ""
        entry[field] = value
    if not entry["id"]:
        entry["id"] = dirname
    return entry


def load_cases(prefer_index: bool = True) -> tuple[list[dict], str]:
    """Load all case files live.

    ``prefer_index`` is retained for the existing call signature; there is no
    index file to prefer, which removes stale-cache behavior entirely.
    """
    del prefer_index
    pairs = case_files()
    if not pairs:
        return [], "empty"
    cases = []
    for dirname, path in pairs:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                raw = json.load(handle)
        except Exception:
            raw = {}
        cases.append(normalize_case(raw, dirname))
    return cases, "scan"


def _case_path(root: str, case_dir: str, rel: str) -> str | None:
    """Resolve a case-relative file without allowing root escape or links."""
    if not isinstance(rel, str) or not rel.strip():
        return None
    ref = rel.strip().replace("\\", os.sep).replace("/", os.sep)
    if (os.path.isabs(ref) or os.path.splitdrive(ref)[0]
            or ref.startswith(("\\", "//")) or "\x00" in ref):
        return None
    root_real = os.path.realpath(root)
    case_real = os.path.realpath(case_dir)
    if os.path.commonpath((root_real, case_real)) != root_real:
        return None
    candidate = os.path.realpath(os.path.join(case_real, ref))
    if os.path.commonpath((case_real, candidate)) != case_real:
        return None
    return candidate


def read_case(case_id: str) -> str:
    """Render one case's JSON, fact prefix, and README/reference prefix."""
    try:
        key = (case_id or "").strip()
        if not key:
            return "[ERROR]: case_id 不能为空"
        cases, _source = load_cases(prefer_index=False)
        target = None
        for entry in cases:
            if key == str(entry.get("id", "")) or key == str(entry.get("dir", "")):
                target = entry
                break
        if target is None:
            for entry in cases:
                if key.lower() in (
                    str(entry.get("id", "")).lower(),
                    str(entry.get("dir", "")).lower(),
                ):
                    target = entry
                    break
        if target is None:
            available = "、".join(
                str(case.get("id", case.get("dir", ""))) for case in cases[:20]
            )
            return (
                "[ERROR]: Case not found: %s（可用案例：%s；用 `case_state.py index` "
                "看全量索引）" % (key, available or "无")
            )

        root = case_lib_dir()
        case_dir = os.path.join(root, target.get("dir", ""))
        case_dir_real = os.path.realpath(case_dir)
        if os.path.commonpath((os.path.realpath(root), case_dir_real)) != os.path.realpath(root):
            return "[ERROR]: 案例目录越出案例库根目录，拒绝读取"
        case_path = _case_path(root, case_dir, "case.json")
        parts = []
        if case_path and os.path.isfile(case_path):
            with open(case_path, "r", encoding="utf-8", errors="replace") as handle:
                parts.append("[case.json]\n" + handle.read().strip())
        else:
            parts.append(
                "[case.json]\n(缺失，以下为内存归一化结果)\n"
                + json.dumps(target, indent=2, ensure_ascii=False)
            )

        facts_path = _case_path(root, case_dir, "facts.jsonl")
        if facts_path and os.path.isfile(facts_path):
            lines = []
            try:
                with open(
                    facts_path, "r", encoding="utf-8", errors="replace"
                ) as handle:
                    for index, line in enumerate(handle):
                        if index >= 20:
                            break
                        line = line.rstrip("\r\n")
                        if line.strip():
                            lines.append(line)
            except Exception as exc:
                lines.append("(读取失败: %s)" % exc)
            parts.append(
                "[facts.jsonl 前20行]\n" + ("\n".join(lines) if lines else "(空)")
            )
        else:
            parts.append("[facts.jsonl 前20行]\n(未提供 facts.jsonl)")

        readme_path = ""
        readme_label = "[README 前80行]"
        for candidate in ("README.md", "README.txt"):
            path = _case_path(root, case_dir, candidate)
            if not path:
                continue
            if os.path.isfile(path):
                readme_path = path
                break
        if not readme_path:
            for ref in target.get("refs") or []:
                path = _case_path(root, case_dir, str(ref))
                if not path:
                    continue
                if os.path.isfile(path) and str(ref).lower().endswith((".md", ".txt")):
                    readme_path = path
                    readme_label = "%s (回退 refs: %s)" % (readme_label, ref)
                    break
        if readme_path:
            try:
                with open(
                    readme_path, "r", encoding="utf-8", errors="replace"
                ) as handle:
                    lines = handle.read().splitlines()[:80]
                parts.append(readme_label + "\n" + "\n".join(lines))
            except Exception as exc:
                parts.append(readme_label + "\n(读取失败: %s)" % exc)
        else:
            parts.append(
                "[README 前80行]\n"
                "(未提供 README.md / README.txt，refs 中也没有可读文档)"
            )

        return "\n\n".join(parts)
    except Exception as exc:
        return "[ERROR]: 案例读取失败: %s: %s" % (type(exc).__name__, exc)
