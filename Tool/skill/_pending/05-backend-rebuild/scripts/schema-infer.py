#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""schema-infer.py -- 从响应样本聚类字段、推断主键/枚举/时间格式，产出 schema.json + DDL。

输入：JSON 响应样本（文件或目录，可多个）。样本来源应该是**录制**的响应体
（api-surface.py 的 samples/ 目录就是），不要拿手写假数据冒充。

推断规则（全部可复算，不猜业务语义）：
  * 字段集合：所有样本的键并集，保留首次出现顺序；空值单独统计 null_rate。
  * 类型：integer / real / bool / text / json；混合降级为 TEXT 并在 warnings 记一条。
  * 主键：id → <表>_id → pk/uuid/guid/key/code → 任意唯一非空 *_id →
          最多 3 列的唯一组合；都不满足则 primary_key=null（DDL 不加主键，notes 说明）。
  * 枚举：text 且 2 ≤ distinct ≤ --max-enum、distinct/rows ≤ 0.34、值长度 ≤ 64。
  * 时间：ISO8601 / date；整数按字段名 + 量级判 epoch_s / epoch_ms。
  * 子表：数组里的对象 → <父表>_<字段> 表，父表有单列主键时补 <父>_id 外键列。

输出：
  <out>   schema.json（tables/fields/ddl/notes/warnings）
  <ddl>   CREATE TABLE 草案（--ddl 指定；默认与 out 同目录 schema.sql）

用法：
  python Tool/skill/_pending/05-backend-rebuild/scripts/schema-infer.py \
      --samples work/api/samples --out work/api/schema.json --ddl work/api/schema.sql
  python Tool/skill/_pending/05-backend-rebuild/scripts/schema-infer.py --self-test
  python Tool/skill/_pending/05-backend-rebuild/scripts/schema-infer.py --help

退出码：0 = ok；2 = blocked（{ok:false,blocked_at,reason}）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

SCHEMA = "seep.schema-infer/1"
ISO_RX = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$")
DATE_RX = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TIME_NAME_RX = re.compile(r"(?i)(_at$|_time$|time$|date$|_ts$|timestamp|expires|created|updated|deleted)")
IDENT_RX = re.compile(r"[^A-Za-z0-9_]+")
STOP_TABLE = {"pageprops", "__n_ssg", "__n_ssp", "props", "data", "result", "response"}


def emit(obj, code=0):
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    return code


def blocked(at, reason):
    return emit({"ok": False, "blocked_at": at, "reason": str(reason)[:600]}, 2)

class JsonArgParser(argparse.ArgumentParser):
    """参数错误也走统一失败形状：{ok:false,blocked_at,reason} + rc=2。"""

    def error(self, message):
        blocked("args", message)
        raise SystemExit(2)



def ident(s):
    s = IDENT_RX.sub("_", str(s or "")).strip("_")
    if not s:
        s = "col"
    if s[0].isdigit():
        s = "f_" + s
    return s.lower()


def table_name(s, default="records"):
    n = ident(s) or default
    return n


def jtype(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "real"
    if isinstance(v, str):
        return "text"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return "unknown"


def sql_type(types):
    types = {t for t in types if t != "null"}
    if not types:
        return "TEXT"
    if types <= {"integer"}:
        return "INTEGER"
    if types <= {"integer", "real"}:
        return "REAL"
    if types <= {"bool"}:
        return "INTEGER"          # SQLite 没有 bool；0/1 存
    return "TEXT"                 # text / json / 混合


def load_samples(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for dp, _dn, fn in os.walk(p):
                for f in sorted(fn):
                    if f.lower().endswith(".json"):
                        files.append(os.path.join(dp, f))
        elif os.path.isfile(p):
            files.append(p)
        else:
            raise FileNotFoundError(f"样本路径不存在：{p}")
    docs = []
    for p in sorted(set(files)):
        try:
            with open(p, encoding="utf-8-sig") as f:
                docs.append((p, json.load(f)))
        except Exception as e:  # noqa: BLE001
            raise ValueError(f"样本不是合法 JSON：{p} ({e})")
    if not docs:
        raise ValueError("没有找到 .json 样本")
    return docs


def collect(docs, root_name):
    """返回 {table: [row,...]}；对象里的数组按 <key> 拆子表，其余标量归父表。"""
    tables = {}
    notes = []
    for path, doc in docs:
        base = root_name or os.path.splitext(os.path.basename(path))[0]

        def feed(name, value, origin):
            name = table_name(name, base)
            if isinstance(value, list):
                rows = [r for r in value if isinstance(r, dict)]
                if rows:
                    tables.setdefault(name, []).extend(rows)
                elif value:
                    notes.append(f"{origin}: 列表 `{name}` 内不是对象，忽略（{len(value)} 项）")
                return
            if isinstance(value, dict):
                arrays = {k: v for k, v in value.items() if isinstance(v, list) and v and all(isinstance(x, dict) for x in v)}
                scalars = {k: v for k, v in value.items() if k not in arrays}
                if arrays:
                    if any(not isinstance(v, (dict, list)) for v in scalars.values()) or scalars:
                        tables.setdefault(name, []).append(scalars)
                    for k, v in arrays.items():
                        feed(f"{name}_{k}" if name else k, v, origin)
                    return
                tables.setdefault(name, []).append(value)
                return
            notes.append(f"{origin}: 顶层不是对象/对象列表，跳过（{type(value).__name__}）")

        if isinstance(doc, list):
            feed(base, doc, path)
        elif isinstance(doc, dict):
            lists = {k: v for k, v in doc.items() if isinstance(v, list) and v and all(isinstance(x, dict) for x in v)}
            if lists:
                # 一层包装（如 {"data":[...]}）不额外造父表
                only_wrapper = len(lists) == 1 and len(doc) <= 2 and all(not isinstance(v, (dict, list)) for k, v in doc.items() if k not in lists)
                if only_wrapper:
                    k, v = next(iter(lists.items()))
                    feed(table_name(k, base), v, path)
                else:
                    feed(base, doc, path)
            else:
                feed(base, doc, path)
        else:
            notes.append(f"{path}: 顶层是标量，跳过")
    return tables, notes


def field_stats(rows):
    order, stats = [], {}
    for row in rows:
        for k, v in row.items():
            if k not in stats:
                order.append(k)
                stats[k] = {"types": [], "values": [], "nulls": 0, "total": 0, "seen": set()}
            st = stats[k]
            st["total"] += 1
            if v is None:
                st["nulls"] += 1
                continue
            t = jtype(v)
            if t not in st["types"]:
                st["types"].append(t)
            key = json.dumps(v, ensure_ascii=False, sort_keys=True) if isinstance(v, (dict, list)) else repr(v)
            if key not in st["seen"]:
                st["seen"].add(key)
                if len(st["values"]) < 5 and not isinstance(v, (dict, list)):
                    st["values"].append(v)
    return order, stats


def time_format(values, types, name):
    strings = [v for v in values if isinstance(v, str)]
    ints = [v for v in values if isinstance(v, int) and not isinstance(v, bool)]
    if strings and len(strings) == len(values):
        if all(ISO_RX.match(s) for s in strings):
            return "iso8601"
        if all(DATE_RX.match(s) for s in strings):
            return "date"
    if ints and len(ints) == len(values) and TIME_NAME_RX.search(name):
        if all(1_000_000_000 <= v <= 4_000_000_000 for v in ints):
            return "epoch_s"
        if all(1_000_000_000_000 <= v <= 4_000_000_000_000 for v in ints):
            return "epoch_ms"
    return None


def enum_values(values, rows, max_enum):
    if not values or any(not isinstance(v, str) for v in values):
        return None
    distinct = sorted(set(values))
    if len(distinct) < 2:
        return None
    cap = max(2, min(max_enum, int(rows * 0.34)))   # 小样本放宽到 2，避免把二元状态漏掉
    if len(distinct) > cap:
        return None
    if any(len(v) > 64 for v in distinct):
        return None
    return distinct


def pick_pk(table, order, stats, rows):
    if len(rows) < 2:
        return [], "insufficient-rows"          # 单行样本无法验证唯一性，不许拿 JSON blob 当主键

    def scalar(f):
        return bool(stats[f]["types"]) and set(stats[f]["types"]) <= {"integer", "real", "bool", "text"}

    unique = lambda f: (scalar(f) and stats[f]["nulls"] == 0  # noqa: E731
                        and len(stats[f]["seen"]) == len(rows))
    prefs = ["id", f"{table}_id", "pk", "uuid", "guid", "key", "code"]
    for cand in prefs:
        if cand in stats and unique(cand):
            return [cand], "name-preference"
    for f in order:
        if f.endswith("_id") and unique(f):
            return [f], "unique-*_id"
    for f in order:
        if unique(f):
            return [f], "unique-field"
    # 组合键：按字段顺序枚举 2/3 列（只接受标量列）
    cand = [f for f in order if stats[f]["nulls"] == 0 and scalar(f)]
    for size in (2, 3):
        for i in range(len(cand)):
            for j in range(i + 1, len(cand)):
                combo = [cand[i], cand[j]]
                if size == 3:
                    for k in range(j + 1, len(cand)):
                        triple = combo + [cand[k]]
                        keys = {tuple(json.dumps(r.get(f), sort_keys=True) for f in triple) for r in rows}
                        if len(keys) == len(rows):
                            return triple, "unique-composite"
                    continue
                keys = {tuple(json.dumps(r.get(f), sort_keys=True) for f in combo) for r in rows}
                if len(keys) == len(rows):
                    return combo, "unique-composite"
    return [], "none"


def infer(tables, max_enum=12, fk_links=None):
    out, warnings, notes = [], [], []
    fk_links = fk_links or {}
    for name in sorted(tables):
        rows = [r for r in tables[name] if isinstance(r, dict)]
        if not rows:
            continue
        order, stats = field_stats(rows)
        pk, pk_reason = pick_pk(name, order, stats, rows)
        fields = []
        for f in order:
            st = stats[f]
            types = st["types"]
            values = st["values"]
            nullable = st["nulls"] > 0
            tf = time_format(values, types, f)
            en = enum_values(values, len(rows), max_enum)
            field = {
                "name": f,
                "sql_type": sql_type(types),
                "json_types": sorted(types),
                "nullable": nullable,
                "null_rate": round(st["nulls"] / st["total"], 4) if st["total"] else 0.0,
                "distinct": len(st["seen"]),
                "examples": values[:3],
                "primary_key": f in pk,
            }
            if en:
                field["enum"] = en
            if tf:
                field["time_format"] = tf
            if "object" in types or "array" in types:
                field["stored_as"] = "json-text"
            if len(types) > 1:
                warnings.append(f"{name}.{f}: 混合类型 {sorted(types)} → 降级 {field['sql_type']}")
            fields.append(field)
        pos = {f: i for i, f in enumerate(order)}
        fields.sort(key=lambda x: (not x["primary_key"], pos.get(x["name"], 999)))
        fks = []
        if name in fk_links:
            parent, parent_pk = fk_links[name]
            fk = {"field": f"{parent}_id", "references": f"{parent}({parent_pk})", "derived": True}
            if not any(f["name"] == fk["field"] for f in fields):
                fields.append({"name": f"{parent}_id", "sql_type": "TEXT", "json_types": [],
                               "nullable": False, "null_rate": 0.0, "distinct": len(rows),
                               "examples": [], "primary_key": False})
                fks.append(fk)
                pos = {f: i for i, f in enumerate(order)}
        fields.sort(key=lambda x: (not x["primary_key"], pos.get(x["name"], 999)))
        if pk:
            notes.append(f"{name}: 主键 {pk}（{pk_reason}）")
        elif pk_reason == "insufficient-rows":
            notes.append(f"{name}: 只有 {len(rows)} 行样本，主键不可判；DDL 不加主键，补业务样本后重跑")
        else:
            notes.append(f"{name}: 无自然主键（样本不足或不唯一）；DDL 不加主键，落库时补代理键")
        out.append({"name": name, "rows": len(rows), "primary_key": pk,
                    "primary_key_reason": pk_reason, "fields": fields,
                    "foreign_keys": fks})
    return out, notes, warnings


DDL_TYPES = {"INTEGER": "INTEGER", "REAL": "REAL", "TEXT": "TEXT"}


def ddl_for(tables):
    lines = ["-- schema-infer.py 草案（SQLite 方言；改方言时只改类型映射，不要改列名）",
             "-- 约定：枚举存 TEXT，时间存 TEXT(ISO8601) 或 INTEGER(epoch)，JSON 存 TEXT。", ""]
    for t in tables:
        cols = []
        pk = t["primary_key"]
        for f in t["fields"]:
            c = f'  "{f["name"]}" {DDL_TYPES.get(f["sql_type"], "TEXT")}'
            if not f["nullable"] and f["name"] not in pk:
                c += " NOT NULL"
            cols.append(c)
        if len(pk) == 1:
            for i, c in enumerate(cols):
                if f'"{pk[0]}"' in c:
                    cols[i] = c + " PRIMARY KEY"
        if len(pk) > 1:
            cols.append("  PRIMARY KEY (" + ", ".join(f'"{c}"' for c in pk) + ")")
        lines.append(f'CREATE TABLE IF NOT EXISTS "{t["name"]}" (')
        lines.append(",\n".join(cols))
        lines.append(");")
        for f in t["fields"]:
            if f.get("enum"):
                vals = ", ".join(f"'{v}'" for v in f["enum"])
                lines.append(f"-- {t['name']}.{f['name']} 枚举：{vals}")
        for fk in t.get("foreign_keys") or []:
            lines.append(f"-- {t['name']}.{fk['field']} -> {fk['references']}（推断外键，加索引）")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def merge_fk(tables, inferred):
    links = {}
    names = {t["name"]: t for t in inferred}
    for t in inferred:
        for f in t["fields"]:
            child = f"{t['name']}_{f['name']}"
            if child in tables and t["primary_key"] and len(t["primary_key"]) == 1:
                links[child] = (t["name"], t["primary_key"][0])
    return links


def build(paths, root_name=None, max_enum=12):
    docs = load_samples(paths)
    tables, cnotes = collect(docs, root_name)
    if not tables:
        raise ValueError("样本里没有可聚类对象（需要 JSON 对象或对象列表）")
    first, notes, warnings = infer(tables, max_enum)
    links = merge_fk(tables, first)
    if links:
        tables2, notes2, warnings2 = infer(tables, max_enum, fk_links=links)
        first, notes, warnings = tables2, notes + notes2, warnings + warnings2
    ddl = ddl_for(first)
    return {
        "schema": SCHEMA,
        "inputs": sorted({os.path.basename(p) for p, _ in docs}),
        "tables": first,
        "ddl": ddl,
        "notes": sorted(notes + cnotes),
        "warnings": sorted(set(warnings)),
        "rules": [
            "主键只在样本唯一且非空时成立；样本 < 2 行不给主键。",
            "枚举是样本内观测值，不代表业务全集；上线前用真实数据复核。",
            "时间格式按值判定，字段名只用于区分秒/毫秒。",
            "DDL 是草案：不加索引、不加触发器，部署前按查询补。",
        ],
    }


# ------------------------------------------------------------------ self-test
S1 = [
    {"id": "u1", "name": "alice", "status": "active", "score": 10,
     "created_at": "2026-01-02T03:04:05Z", "tags": ["a", "b"]},
    {"id": "u2", "name": "bob", "status": "disabled", "score": 7,
     "created_at": "2026-01-03T04:05:06Z", "tags": []},
    {"id": "u3", "name": "carol", "status": "active", "score": 0,
     "created_at": "2026-01-04T05:06:07Z", "tags": ["c"]},
]
S2 = {"quiz": {"id": "q1", "title": "t", "created_at": "2026-02-01T00:00:00Z"},
      "answers": [
          {"id": "a1", "question_id": "q1", "correct": True, "elapsed_ms": 1200},
          {"id": "a2", "question_id": "q1", "correct": False, "elapsed_ms": 900},
      ]}


def self_test():
    with tempfile.TemporaryDirectory() as td:
        d1 = os.path.join(td, "samples")
        os.makedirs(d1)
        with open(os.path.join(d1, "users.json"), "w", encoding="utf-8") as f:
            json.dump(S1, f)
        with open(os.path.join(d1, "quiz.json"), "w", encoding="utf-8") as f:
            json.dump(S2, f)
        out = os.path.join(td, "schema.json")
        ddlp = os.path.join(td, "schema.sql")
        doc = build([d1], max_enum=12)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        with open(ddlp, "w", encoding="utf-8") as f:
            f.write(doc["ddl"])
        tabs = {t["name"]: t for t in doc["tables"]}
        assert doc["schema"] == SCHEMA
        assert "users" in tabs, list(tabs)
        users = tabs["users"]
        assert users["primary_key"] == ["id"], users["primary_key"]
        fmap = {f["name"]: f for f in users["fields"]}
        assert fmap["status"].get("enum") == ["active", "disabled"], fmap["status"]
        assert fmap["created_at"].get("time_format") == "iso8601", fmap["created_at"]
        assert fmap["score"]["sql_type"] == "INTEGER", fmap["score"]
        child = [n for n in tabs if n.endswith("_answers")]
        assert child, list(tabs)
        assert tabs[child[0]]["primary_key"] == ["id"], tabs[child[0]]
        assert "CREATE TABLE IF NOT EXISTS \"users\"" in doc["ddl"], doc["ddl"][:200]
        assert "PRIMARY KEY" in doc["ddl"]
        assert "status" in doc["ddl"] and "枚举" in doc["ddl"]
        # 确定性：同输入两次输出一致
        assert json.dumps(doc, sort_keys=True) == json.dumps(build([d1], max_enum=12), sort_keys=True)
        # 空/坏输入必须抛错（CLI 会转 rc=2）
        bad = os.path.join(td, "bad.json")
        open(bad, "w", encoding="utf-8").write("{not json")
        for probe in ([os.path.join(td, "nope")], [bad]):
            try:
                build(probe)
            except Exception:  # noqa: BLE001
                pass
            else:
                raise AssertionError(f"坏输入应抛错：{probe}")
        return emit({"ok": True, "self_test": True, "tables": sorted(tabs),
                     "ddl_lines": len(doc["ddl"].splitlines())}, 0)


def main(argv=None):
    ap = JsonArgParser(
        description="响应样本 → schema.json + CREATE TABLE 草案（字段/主键/枚举/时间）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="退出码：0 ok / 2 blocked")
    ap.add_argument("--samples", nargs="+", default=[], help="JSON 样本文件或目录（可多个）")
    ap.add_argument("--out", default="schema.json")
    ap.add_argument("--ddl", default=None, help="DDL 落盘路径，默认 <out 目录>/schema.sql")
    ap.add_argument("--name", default=None, help="顶层表名（默认取目录/文件名）")
    ap.add_argument("--max-enum", type=int, default=12)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        try:
            return self_test()
        except Exception as e:  # noqa: BLE001
            return blocked("self-test", e)
    if not args.samples:
        return blocked("input", "至少给一个 --samples（文件或目录）")
    try:
        doc = build(args.samples, root_name=args.name, max_enum=args.max_enum)
    except FileNotFoundError as e:
        return blocked("samples", e)
    except Exception as e:  # noqa: BLE001
        return blocked("infer", e)

    outdir = os.path.dirname(os.path.abspath(args.out)) or "."
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    ddlp = args.ddl or os.path.join(outdir, "schema.sql")
    with open(ddlp, "w", encoding="utf-8") as f:
        f.write(doc["ddl"])
    return emit({"ok": True, "out": args.out, "ddl": ddlp,
                 "tables": [{"name": t["name"], "rows": t["rows"],
                             "primary_key": t["primary_key"]} for t in doc["tables"]],
                 "warnings": len(doc["warnings"])}, 0)


if __name__ == "__main__":
    sys.exit(main())
