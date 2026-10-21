#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen-case-index.py — 扫描 Tool/cases/*/case.json 生成/校验案例索引。

设计目标：
  * 纯标准库，路径由 __file__ 推导，不写死任何本机绝对路径；
  * `case.json` 是唯一事实来源，`index.json` 只是可重建的派生缓存；
  * `--check` 可直接接门禁：磁盘与索引不一致即 rc=1；
  * `source_hash` 覆盖全部 case.json 的路径与字节，供 MCP / 文档判断新鲜度。

用法：
    python Tool/scripts/gen-case-index.py                # 生成 Tool/cases/index.json
    python Tool/scripts/gen-case-index.py --stats        # 生成并打印领域/等级/结论分布
    python Tool/scripts/gen-case-index.py --check        # 校验索引是否与磁盘一致（rc=1 表示过期）
    python Tool/scripts/gen-case-index.py --check --stats
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

SCHEMA = 1
HERE = os.path.dirname(os.path.abspath(__file__))          # Tool/scripts
ROOT = os.path.dirname(os.path.dirname(HERE))              # 仓库根
CASES_DIR = os.path.join(ROOT, "Tool", "cases")
INDEX_PATH = os.path.join(CASES_DIR, "index.json")

# case.json 的规范字段；缺失时补默认值，保证索引结构稳定。
CASE_FIELDS = {
    "id": "",
    "domain": "",
    "target_type": "",
    "evidence_kind": "",
    "protection": [],
    "authority": "",
    "goal_level": "",
    "outcome": "",
    "artifacts": [],
    "repro": {},
    "lessons": [],
    "tags": [],
    "refs": [],
    "updated": "",
}
LIST_FIELDS = ("protection", "lessons", "tags", "refs")
SKIP_DIRS = {"__pycache__", ".git", ".svn"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _case_files():
    """返回 [(目录名, case.json 绝对路径)]，按目录名排序。"""
    found = []
    if not os.path.isdir(CASES_DIR):
        return found
    for name in sorted(os.listdir(CASES_DIR)):
        if name.startswith("_"):   # _templates / _unpack 等非案例目录
            continue
        path = os.path.join(CASES_DIR, name)
        if not os.path.isdir(path) or name in SKIP_DIRS or name.startswith("."):
            continue
        case_path = os.path.join(path, "case.json")
        if os.path.isfile(case_path):
            found.append((name, case_path))
    return found


def _missing_case_dirs():
    """有案例目录但缺 case.json 的目录名（防止新增案例忘记写元数据）。"""
    missing = []
    if not os.path.isdir(CASES_DIR):
        return missing
    for name in sorted(os.listdir(CASES_DIR)):
        if name.startswith("_"):   # _templates / _unpack 等非案例目录
            continue
        path = os.path.join(CASES_DIR, name)
        if not os.path.isdir(path) or name in SKIP_DIRS or name.startswith("."):
            continue
        if not os.path.isfile(os.path.join(path, "case.json")):
            missing.append(name)
    return missing


def _normalize(data, dirname):
    """把任意 case.json 归一成索引条目；类型不符时退回安全默认值。"""
    if not isinstance(data, dict):
        data = {}
    entry = {"dir": dirname}
    for field, default in CASE_FIELDS.items():
        value = data.get(field, default)
        if field in LIST_FIELDS:
            if not isinstance(value, list):
                value = []
            else:
                value = [x for x in value if isinstance(x, str)]
        elif field == "artifacts":
            if not isinstance(value, list):
                value = []
            else:
                cleaned = []
                for item in value:
                    if isinstance(item, dict):
                        cleaned.append({
                            "path": item.get("path", "") if isinstance(item.get("path", ""), str) else "",
                            "sha256": item.get("sha256", "") if isinstance(item.get("sha256", ""), str) else "",
                        })
                value = cleaned
        elif not isinstance(value, str):
            value = ""
        entry[field] = value
    if not entry["id"]:
        entry["id"] = dirname
    return entry


def _source_hash(pairs):
    """对排序后的 (相对路径, 字节) 做 sha256；路径用 / 分隔，跨平台稳定。"""
    digest = hashlib.sha256()
    for dirname, path in pairs:
        rel = "Tool/cases/%s/case.json" % dirname
        with open(path, "rb") as fh:
            raw = fh.read()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(raw)
        digest.update(b"\x00")
    return digest.hexdigest()


def build_index(generated_at=None):
    pairs = _case_files()
    entries = []
    for dirname, path in pairs:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            try:
                data = json.load(fh)
            except Exception as exc:
                raise ValueError("无法解析 %s: %s" % (os.path.join(dirname, "case.json"), exc))
        entries.append(_normalize(data, dirname))

    seen = {}
    for entry in entries:
        seen.setdefault(entry["id"], []).append(entry["dir"])
    dup = {k: v for k, v in seen.items() if len(v) > 1}
    if dup:
        raise ValueError("case id 重复: " + json.dumps(dup, ensure_ascii=False))

    return {
        "schema": SCHEMA,
        "generated_at": generated_at or _now_iso(),
        "source_hash": _source_hash(pairs),
        "case_count": len(entries),
        "cases": entries,
    }


def write_index(index):
    with open(INDEX_PATH, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(index, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def check_index(stats=False):
    problems = []
    if not os.path.isfile(INDEX_PATH):
        problems.append("索引不存在：%s（先运行一次 gen-case-index.py）" % INDEX_PATH)
    missing = _missing_case_dirs()
    if missing:
        problems.append("以下案例目录缺少 case.json：" + "、".join(missing))

    try:
        disk = build_index()
    except Exception as exc:
        print("[FAIL] 无法扫描案例目录：%s" % exc)
        return 1

    existing = None
    if os.path.isfile(INDEX_PATH):
        try:
            with open(INDEX_PATH, "r", encoding="utf-8", errors="replace") as fh:
                existing = json.load(fh)
        except Exception as exc:
            problems.append("索引无法解析：%s" % exc)

    if isinstance(existing, dict):
        if existing.get("schema") != SCHEMA:
            problems.append("schema 不一致：磁盘 %r / 期望 %r" % (existing.get("schema"), SCHEMA))
        if existing.get("source_hash") != disk["source_hash"]:
            problems.append("source_hash 过期：case.json 已变化，请重新生成索引")
        if existing.get("case_count") != disk["case_count"]:
            problems.append("case_count 不一致：磁盘 %r / 实际 %r" % (existing.get("case_count"), disk["case_count"]))
        if _canonical(existing.get("cases")) != _canonical(disk["cases"]):
            old_ids = {c.get("id") for c in existing.get("cases", []) if isinstance(c, dict)}
            new_ids = {c.get("id") for c in disk["cases"]}
            detail = []
            if old_ids - new_ids:
                detail.append("索引多出: " + "、".join(sorted(str(x) for x in old_ids - new_ids)))
            if new_ids - old_ids:
                detail.append("索引缺少: " + "、".join(sorted(str(x) for x in new_ids - old_ids)))
            problems.append("cases 内容不一致" + ("（" + "；".join(detail) + "）" if detail else ""))

    if problems:
        print("[FAIL] 案例索引与磁盘不一致：")
        for item in problems:
            print("   - " + item)
        return 1

    print("[OK] 案例索引已是最新：%d 个案例，source_hash=%s"
          % (disk["case_count"], disk["source_hash"][:12]))
    if stats:
        print_stats(disk)
    return 0


def _dist(cases, field):
    counts = {}
    for entry in cases:
        key = entry.get(field) or "(未填)"
        counts[key] = counts.get(key, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def print_stats(index=None):
    index = index or build_index()
    cases = index["cases"]
    print("案例总数: %d" % index["case_count"])
    print("source_hash: %s" % index["source_hash"])
    for title, field in (("领域分布", "domain"), ("目标等级分布", "goal_level"), ("结论分布", "outcome")):
        print("%s:" % title)
        for key, count in _dist(cases, field):
            print("  %-18s %d" % (key, count))


def main(argv=None):
    ap = argparse.ArgumentParser(description="生成 / 校验 Tool/cases/index.json")
    ap.add_argument("--check", action="store_true", help="只校验索引是否与磁盘一致；不一致 rc=1")
    ap.add_argument("--stats", action="store_true", help="打印领域 / 等级 / 结论分布")
    args = ap.parse_args(argv)

    if args.check:
        return check_index(stats=args.stats)

    try:
        index = build_index()
    except Exception as exc:
        print("[FAIL] 生成索引失败：%s" % exc)
        return 1
    write_index(index)
    print("[OK] 已写入 %s：%d 个案例，source_hash=%s"
          % (INDEX_PATH, index["case_count"], index["source_hash"][:12]))
    missing = _missing_case_dirs()
    if missing:
        print("[WARN] 以下案例目录缺少 case.json：" + "、".join(missing))
    if args.stats:
        print_stats(index)
    return 0


if __name__ == "__main__":
    sys.exit(main())
