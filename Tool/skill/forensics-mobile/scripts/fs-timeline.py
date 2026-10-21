#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fs-timeline.py -- 把 evtx / 注册表 hive / 文件系统 / 浏览器 History 归一化成 UTC 时间线 JSON。

用法:
    python fs-timeline.py --input evidence/AppReadiness.evtx --json
    python fs-timeline.py --input evidence/Explorer.hiv --input evidence/ -o timeline.json
    python fs-timeline.py --input evidence/History.sqlite --kind sqlite --json
    python fs-timeline.py --self-test

输入:
    --input   可重复；文件或目录。自动识别 ElfFile(evtx) / regf(hive) /
              SQLite(仅 urls+visits 或 moz_places+moz_historyvisits) / 其它按文件系统。
    --kind    auto|evtx|registry|sqlite|filesystem，默认 auto。
    --out     写出 timeline.json（目录或文件名均可）。
    --max-events  默认 20000，超出截断并在 warnings 标注。
    --all-times   文件系统同时输出 mtime/atime/ctime 三类事件（默认仅 mtime）。

输出:
    {"ok": true, "events": [...], "summary": {...}, "inputs": [...], "warnings": [...]}
    每个事件含 time_utc / source / kind / actor / object / detail / confidence。

退出码:
    0 成功；2 失败（输出 {"ok": false, "blocked_at": "...", "reason": "..."}）。
只读：不挂载、不执行、不写回证据；SQLite 以 mode=ro&immutable=1 打开。
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import sqlite3
import struct
import sys
import tempfile

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

FILETIME_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
UNIX_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules"}
MAX_INPUT_BYTES = 512 * 1024 * 1024


class TimelineError(Exception):
    def __init__(self, blocked_at, reason):
        super().__init__(reason)
        self.blocked_at = blocked_at
        self.reason = reason


def sha256_file(path, limit=None):
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            total += len(chunk)
            if limit and total >= limit:
                break
    return h.hexdigest()


def dt_iso(dt):
    if dt is None:
        return None
    return dt.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def filetime_dt(value):
    if not value:
        return None
    try:
        return FILETIME_EPOCH + _dt.timedelta(microseconds=int(value) // 10)
    except (OverflowError, ValueError):
        return None


def chrome_dt(value):
    # Chromium/Edge: microseconds since 1601-01-01 UTC (not 100ns FILETIME).
    if not value:
        return None
    try:
        return FILETIME_EPOCH + _dt.timedelta(microseconds=int(value))
    except (OverflowError, ValueError):
        return None


def firefox_dt(value):
    if not value:
        return None
    try:
        return UNIX_EPOCH + _dt.timedelta(microseconds=int(value))
    except (OverflowError, ValueError):
        return None


def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def i32(data, off):
    return struct.unpack_from("<i", data, off)[0]


def u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def align8(n):
    return (n + 7) & ~7


ACTION_BY_KIND = (
    ("evtx", "event-logged"),
    ("registry", "key-written"),
    ("browser", "url-visited"),
    ("filesystem", "file-modified"),
    ("plist", "plist-read"),
    ("sqlite", "db-row-read"),
)


def derive_action(kind, detail=None):
    """四要素里的「动作」：必须显式给出，不能留给读者从 kind 猜。"""
    for prefix, act in ACTION_BY_KIND:
        if kind.startswith(prefix):
            return act
    return "observed:" + kind


def event(ts, source, kind, actor, obj, detail=None, confidence="observed", action=None):
    return {
        "time_utc": dt_iso(ts),
        "source": source,
        "kind": kind,
        "action": action or derive_action(kind, detail),
        "actor": actor,
        "object": obj,
        "detail": detail or {},
        "confidence": confidence,
    }


# ---------------------------------------------------------------- EVTX
def parse_evtx(path, max_events, warnings):
    with open(path, "rb") as fh:
        data = fh.read(MAX_INPUT_BYTES + 1)
    if len(data) < 4096 or data[:8] != b"ElfFile\x00":
        raise TimelineError("type", "不是 EVTX（缺少 ElfFile 头）")
    chunk_count = u16(data, 0x2A)
    events = []
    for idx in range(min(chunk_count, 4096)):
        base = 4096 + idx * 0x10000
        if base + 0x200 > len(data):
            warnings.append("evtx: chunk %d 超出文件尾部，停止" % idx)
            break
        if data[base:base + 8] != b"ElfChnk\x00":
            warnings.append("evtx: chunk %d 头无效，跳过" % idx)
            continue
        free = u32(data, base + 0x30)
        if not (0x200 <= free <= 0x10000):
            warnings.append("evtx: chunk %d free-space=%#x 异常，跳过" % (idx, free))
            continue
        p = base + 0x200
        end = base + free
        while p + 28 <= end and data[p:p + 4] == b"**\x00\x00":
            size = u32(data, p + 4)
            if size < 28 or p + size > end:
                warnings.append("evtx: chunk %d record@%#x size=%d 越界，停止" % (idx, p - base, size))
                break
            rid = u64(data, p + 8)
            ts = filetime_dt(u64(data, p + 0x10))
            if ts:
                events.append(event(
                    ts, os.path.basename(path), "evtx-record", "event-record",
                    "%s#chunk=%d/record=%d" % (os.path.basename(path), idx, rid),
                    {"chunk": idx, "record_id": rid, "record_offset": p - base,
                     "record_size": size},
                ))
            p += align8(size)
            if len(events) >= max_events:
                warnings.append("evtx: 达到 --max-events=%d，截断" % max_events)
                return events
    return events


# ---------------------------------------------------------------- REGF
def _reg_name(data, cell, flags, nlen):
    raw = data[cell + 0x50:cell + 0x50 + nlen]
    if flags & 0x20:
        return raw.decode("latin-1", "replace")
    return raw.decode("utf-16le", "replace")


def parse_regf(path, max_events, warnings, label=None):
    with open(path, "rb") as fh:
        data = fh.read(MAX_INPUT_BYTES + 1)
    if len(data) < 4096 or data[:4] != b"regf":
        raise TimelineError("type", "不是注册表 hive（缺少 regf 头）")
    hive_size = u32(data, 0x28)
    end = min(len(data), 4096 + hive_size)
    label = label or os.path.splitext(os.path.basename(path))[0]
    keys = {}
    pos = 4096
    hbins = 0
    while pos + 0x20 <= end:
        if data[pos:pos + 4] != b"hbin":
            warnings.append("registry: hbin 头缺失 @%#x，停止" % pos)
            break
        hbin_size = u32(data, pos + 8)
        if hbin_size < 0x20 or pos + hbin_size > end:
            warnings.append("registry: hbin 大小异常 @%#x size=%#x，停止" % (pos, hbin_size))
            break
        hbins += 1
        hbin_end = pos + hbin_size
        p = pos + 0x20
        while p + 4 <= hbin_end:
            size = i32(data, p)
            if size == 0:
                break
            cell_size = abs(size)
            if cell_size < 8 or p + cell_size > hbin_end:
                warnings.append("registry: cell 越界 @%#x size=%d，停止本 hbin" % (p, size))
                break
            if data[p + 4:p + 6] == b"nk":
                flags = u16(data, p + 6)
                last_write = u64(data, p + 8)
                parent = u32(data, p + 0x14)
                nlen = u16(data, p + 0x4C)
                if nlen <= 255:
                    keys[p - 4096] = {
                        "name": _reg_name(data, p, flags, nlen),
                        "last_write": last_write,
                        "parent": parent,
                    }
            p += align8(cell_size)
        pos = hbin_end
    if not keys:
        raise TimelineError("parse", "hive 中未找到任何 nk 键（可能加密/截断/格式不符）")

    path_cache = {}

    def key_path(off, depth=0, seen=None):
        if off in path_cache:
            return path_cache[off]
        seen = seen or set()
        node = keys.get(off)
        if not node or depth > 64 or off in seen:
            return ""
        seen.add(off)
        parent = node["parent"]
        prefix = ""
        if parent in keys and parent != off:
            prefix = key_path(parent, depth + 1, seen)
        full = (prefix + "\\" if prefix else "") + node["name"]
        full = full[:512]
        path_cache[off] = full
        return full

    events = []
    header_ts = filetime_dt(u64(data, 0x0C))
    if header_ts:
        events.append(event(
            header_ts, os.path.basename(path), "registry-header", "hive-header",
            label, {"hive_bins": hbins, "hive_size": hive_size},
        ))
    for off, node in keys.items():
        ts = filetime_dt(node["last_write"])
        if not ts:
            continue
        events.append(event(
            ts, os.path.basename(path), "registry-key", "registry-key",
            label + "\\" + key_path(off),
            {"cell_offset": off, "raw_last_write": node["last_write"]},
        ))
        if len(events) >= max_events:
            warnings.append("registry: 达到 --max-events=%d，截断" % max_events)
            break
    events.sort(key=lambda x: x["time_utc"] or "")
    return events


# ---------------------------------------------------------------- SQLite History
def parse_sqlite_history(path, max_events, warnings):
    uri = "file:%s?mode=ro&immutable=1" % path.replace("\\", "/")
    try:
        con = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise TimelineError("permission", "SQLite 只读打开失败：%s" % exc)
    events = []
    try:
        tables = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if {"urls", "visits"} <= tables:
            rows = con.execute(
                "SELECT u.url, v.visit_time, u.title FROM visits v "
                "JOIN urls u ON u.id = v.url ORDER BY v.visit_time").fetchall()
            for url, visit_time, title in rows:
                ts = chrome_dt(visit_time)
                if not ts:
                    continue
                events.append(event(
                    ts, os.path.basename(path), "browser-history", "browser-visit",
                    url, {"title": (title or "")[:160], "timestamp_basis": "chromium 1601-epoch us"},
                    "observed",
                ))
                if len(events) >= max_events:
                    warnings.append("sqlite: 达到 --max-events=%d，截断" % max_events)
                    break
        elif {"moz_places", "moz_historyvisits"} <= tables:
            rows = con.execute(
                "SELECT p.url, h.visit_date, p.title FROM moz_historyvisits h "
                "JOIN moz_places p ON p.id = h.place_id ORDER BY h.visit_date").fetchall()
            for url, visit_date, title in rows:
                ts = firefox_dt(visit_date)
                if not ts:
                    continue
                events.append(event(
                    ts, os.path.basename(path), "browser-history", "browser-visit",
                    url, {"title": (title or "")[:160], "timestamp_basis": "firefox unix-epoch us"},
                    "observed",
                ))
                if len(events) >= max_events:
                    warnings.append("sqlite: 达到 --max-events=%d，截断" % max_events)
                    break
        else:
            warnings.append("sqlite: 未发现 urls+visits / moz_places+moz_historyvisits，按非 History 库跳过")
    finally:
        con.close()
    return events


# ---------------------------------------------------------------- filesystem
def stat_event(path, display, st, use_all_times):
    common = {
        "path": display,
        "size": st.st_size,
        "mode": oct(st.st_mode & 0o777),
        "mtime_utc": dt_iso(_dt.datetime.fromtimestamp(st.st_mtime, _dt.timezone.utc)),
        "atime_utc": dt_iso(_dt.datetime.fromtimestamp(st.st_atime, _dt.timezone.utc)),
        "ctime_utc": dt_iso(_dt.datetime.fromtimestamp(st.st_ctime, _dt.timezone.utc)),
    }
    birth = getattr(st, "st_birthtime", None)
    if birth:
        common["birthtime_utc"] = dt_iso(_dt.datetime.fromtimestamp(birth, _dt.timezone.utc))
    out = [event(_dt.datetime.fromtimestamp(st.st_mtime, _dt.timezone.utc),
                 os.path.basename(display), "filesystem-mtime", "file", display, common)]
    if use_all_times:
        out.append(event(_dt.datetime.fromtimestamp(st.st_atime, _dt.timezone.utc),
                         os.path.basename(display), "filesystem-atime", "file", display, common))
        out.append(event(_dt.datetime.fromtimestamp(st.st_ctime, _dt.timezone.utc),
                         os.path.basename(display), "filesystem-ctime", "file", display, common))
    return out


def parse_filesystem(path, max_events, warnings, use_all_times):
    events = []
    if os.path.isfile(path):
        st = os.stat(path)
        return stat_event(path, os.path.basename(path), st, use_all_times)
    if not os.path.isdir(path):
        raise TimelineError("input", "路径不存在或不是常规文件/目录")
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            full = os.path.join(root, name)
            display = os.path.relpath(full, path).replace("\\", "/")
            try:
                st = os.stat(full)
            except OSError as exc:
                warnings.append("filesystem: 无法 stat %s：%s" % (display, exc))
                continue
            events.extend(stat_event(full, display, st, use_all_times))
            if len(events) >= max_events:
                warnings.append("filesystem: 达到 --max-events=%d，截断" % max_events)
                return events
    return events


# ---------------------------------------------------------------- dispatch
def detect_kind(path):
    if os.path.isdir(path):
        return "filesystem"
    with open(path, "rb") as fh:
        head = fh.read(16)
    if head[:8] == b"ElfFile\x00":
        return "evtx"
    if head[:4] == b"regf":
        return "registry"
    if head[:16] == b"SQLite format 3\x00":
        return "sqlite"
    return "filesystem"


def collect(inputs, kind, max_events, warnings, use_all_times):
    events, infos = [], []
    for path in inputs:
        if not os.path.exists(path):
            raise TimelineError("input", "输入不存在：%s" % path)
        actual = kind if kind != "auto" else detect_kind(path)
        info = {"path": path, "kind": actual, "sha256": None, "size": None, "events": 0}
        try:
            if os.path.isfile(path):
                info["sha256"] = sha256_file(path)
                info["size"] = os.path.getsize(path)
            else:
                info["size"] = 0
            if actual == "evtx":
                got = parse_evtx(path, max_events, warnings)
            elif actual == "registry":
                got = parse_regf(path, max_events, warnings)
            elif actual == "sqlite":
                got = parse_sqlite_history(path, max_events, warnings)
            elif actual == "filesystem":
                got = parse_filesystem(path, max_events, warnings, use_all_times)
            else:
                raise TimelineError("type", "不支持的 kind=%s" % actual)
        except TimelineError as exc:
            info["error"] = {"blocked_at": exc.blocked_at, "reason": exc.reason}
            warnings.append("%s: %s" % (path, exc.reason))
            events.append(None)
            infos.append(info)
            continue
        except (OSError, sqlite3.Error, struct.error) as exc:
            info["error"] = {"blocked_at": "parse", "reason": str(exc)}
            warnings.append("%s: %s" % (path, exc))
            infos.append(info)
            events.append(None)
            continue
        info["events"] = len(got)
        infos.append(info)
        events.extend(got)
    events = [x for x in events if x]
    events.sort(key=lambda x: (x["time_utc"] or "", x["source"], x["object"]))
    return events, infos


def summarize(events):
    times = [e["time_utc"] for e in events if e.get("time_utc")]
    by_kind = {}
    for e in events:
        by_kind[e["kind"]] = by_kind.get(e["kind"], 0) + 1
    return {
        "events": len(events),
        "start_utc": min(times) if times else None,
        "end_utc": max(times) if times else None,
        "by_kind": by_kind,
        "timezone": "UTC",
        "clock_skew": "unknown; cross-check acquisition record and NTP",
        "ordering": "time_utc ascending, source/object tie-break",
    }


def write_json(path, payload):
    target = path
    if os.path.isdir(path) or not os.path.splitext(path)[1]:
        os.makedirs(path, exist_ok=True)
        target = os.path.join(path, "timeline.json")
    else:
        os.makedirs(os.path.dirname(os.path.abspath(target)) or ".", exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return target


# ---------------------------------------------------------------- self-test
def _build_evtx(ts):
    rec = bytearray(64)
    struct.pack_into("<4sIQQ", rec, 0, b"**\x00\x00", len(rec), 89, int(ts.timestamp() * 10_000_000) + 116444736000000000)
    data = bytearray(4096 + 0x10000)
    data[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQ", data, 0x08, 0, 0)
    struct.pack_into("<H", data, 0x2A, 1)
    base = 4096
    data[base:base + 8] = b"ElfChnk\x00"
    struct.pack_into("<I", data, base + 0x28, 0x200)
    struct.pack_into("<I", data, base + 0x2C, 0x200 + len(rec))
    struct.pack_into("<I", data, base + 0x30, 0x200 + len(rec))
    data[base + 0x200:base + 0x200 + len(rec)] = rec
    return bytes(data)


def _build_regf(ts):
    data = bytearray(4096 + 0x1000)
    data[0:4] = b"regf"
    struct.pack_into("<Q", data, 0x0C, 134000000000000000)
    struct.pack_into("<I", data, 0x24, 0x20)
    struct.pack_into("<I", data, 0x28, 0x1000)
    base = 4096
    data[base:base + 4] = b"hbin"
    struct.pack_into("<I", data, base + 8, 0x1000)
    cell = base + 0x20
    name = b"SelfTest"
    nk_len = 0x4C + len(name)
    total = align8(4 + nk_len)
    struct.pack_into("<i", data, cell, -total)
    off = cell + 4
    data[off:off + 2] = b"nk"
    struct.pack_into("<H", data, off + 2, 0x20)
    struct.pack_into("<Q", data, off + 4, int(ts.timestamp() * 10_000_000) + 116444736000000000)
    struct.pack_into("<I", data, off + 0x10, 0xFFFFFFFF)
    struct.pack_into("<H", data, off + 0x48, len(name))
    data[off + 0x4C:off + 0x4C + len(name)] = name
    return bytes(data)


def _build_history(ts):
    return int((ts - FILETIME_EPOCH).total_seconds() * 1_000_000)


def self_test():
    checks = 0
    warnings = []
    tmp = tempfile.mkdtemp(prefix="fs-timeline-selftest-")
    try:
        ts = _dt.datetime(2026, 10, 20, 3, 14, 5, 123456, tzinfo=_dt.timezone.utc)
        evtx = os.path.join(tmp, "selftest.evtx")
        with open(evtx, "wb") as fh:
            fh.write(_build_evtx(ts))
        ev = parse_evtx(evtx, 100, warnings)
        assert ev and ev[0]["time_utc"].startswith("2026-10-20T03:14:05")
        checks += 1

        hive = os.path.join(tmp, "selftest.hiv")
        with open(hive, "wb") as fh:
            fh.write(_build_regf(ts))
        reg = parse_regf(hive, 100, warnings)
        assert any(x["kind"] == "registry-key" and "SelfTest" in x["object"] for x in reg)
        assert any(x["time_utc"].startswith("2026-10-20T03:14:05") for x in reg)
        checks += 1

        hist = os.path.join(tmp, "History.sqlite")
        con = sqlite3.connect(hist)
        con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_time INTEGER)")
        con.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
        chrome_ts = _build_history(ts)
        con.execute("INSERT INTO urls VALUES (1,'https://example.invalid/a','self-test',?)", (chrome_ts,))
        con.execute("INSERT INTO visits VALUES (1,1,?)", (chrome_ts,))
        con.commit()
        con.close()
        sql = parse_sqlite_history(hist, 100, warnings)
        assert len(sql) == 1 and sql[0]["object"] == "https://example.invalid/a"
        checks += 1

        fsdir = os.path.join(tmp, "fs")
        os.makedirs(fsdir)
        sample = os.path.join(fsdir, "note.txt")
        with open(sample, "w", encoding="utf-8") as fh:
            fh.write("self-test\n")
        os.utime(sample, (ts.timestamp(), ts.timestamp()))
        fsev = parse_filesystem(fsdir, 100, warnings, False)
        assert fsev and fsev[0]["kind"] == "filesystem-mtime"
        checks += 1

        all_events, infos = collect([evtx, hive, hist, fsdir], "auto", 100, [], False)
        summary = summarize(all_events)
        assert summary["events"] >= 4 and summary["start_utc"] <= summary["end_utc"]
        assert all(i["sha256"] for i in infos if i["kind"] != "filesystem")
        checks += 1

        # 失败路径必须是结构化 rc=2，而不是裸栈
        missing = os.path.join(tmp, "nope.evtx")
        try:
            collect([missing], "auto", 10, [], False)
        except TimelineError as exc:
            assert exc.blocked_at == "input"
            checks += 1
        print(json.dumps({"ok": True, "checks": checks,
                          "sample_events": summary["events"],
                          "note": "offline self-test: evtx/regf/sqlite/fs/failure-path"},
                         ensure_ascii=False))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "blocked_at": "self-test", "reason": str(exc)},
                         ensure_ascii=False))
        return 2
    finally:
        for root, dirs, files in os.walk(tmp, topdown=False):
            for name in files:
                try:
                    os.chmod(os.path.join(root, name), 0o600)
                except OSError:
                    pass
        try:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:  # noqa: BLE001
            pass


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="把 evtx / 注册表 hive / 文件系统 / 浏览器 History 归一化为 UTC 时间线 JSON")
    ap.add_argument("--input", "-i", action="append", default=[], help="输入文件或目录，可重复")
    ap.add_argument("--kind", choices=["auto", "evtx", "registry", "sqlite", "filesystem"],
                    default="auto", help="强制解析器（默认 auto）")
    ap.add_argument("--out", "-o", help="输出 timeline.json（目录或文件名）")
    ap.add_argument("--json", action="store_true", help="把完整时间线打印到 stdout")
    ap.add_argument("--max-events", type=int, default=20000, help="最大事件数（默认 20000）")
    ap.add_argument("--all-times", action="store_true",
                    help="文件系统同时输出 atime/ctime（默认仅 mtime）")
    ap.add_argument("--label", help="覆盖注册表 hive 的根标签（默认文件名）")
    ap.add_argument("--self-test", action="store_true", help="离线自检并打印 JSON 结论")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.input:
        print(json.dumps({"ok": False, "blocked_at": "usage",
                          "reason": "至少一个 --input；或用 --self-test"}, ensure_ascii=False))
        return 2
    warnings = []
    try:
        # --label 仅对单 hive 生效
        if args.label and len(args.input) == 1:
            kind = args.kind if args.kind != "auto" else detect_kind(args.input[0])
            if kind == "registry":
                events = parse_regf(args.input[0], args.max_events, warnings, label=args.label)
                infos = [{"path": args.input[0], "kind": "registry",
                          "sha256": sha256_file(args.input[0]),
                          "size": os.path.getsize(args.input[0]), "events": len(events)}]
            else:
                events, infos = collect(args.input, args.kind, args.max_events, warnings, args.all_times)
        else:
            events, infos = collect(args.input, args.kind, args.max_events, warnings, args.all_times)
    except TimelineError as exc:
        print(json.dumps({"ok": False, "blocked_at": exc.blocked_at, "reason": exc.reason},
                         ensure_ascii=False))
        return 2
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "blocked_at": "unexpected", "reason": str(exc)},
                         ensure_ascii=False))
        return 2

    payload = {
        "ok": bool(events),
        "tool": "fs-timeline.py",
        "generated_at": (os.environ.get("SEEP_TIMESTAMP") or None),
        "timezone": "UTC",
        "events": events,
        "summary": summarize(events),
        "inputs": infos,
        "warnings": warnings,
    }
    if not events:
        payload["blocked_at"] = "no-events"
        payload["reason"] = "所有输入均未产生事件；检查类型/权限/过滤条件"
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(json.dumps({"ok": False, "blocked_at": "no-events",
                              "reason": payload["reason"]}, ensure_ascii=False))
        return 2
    if args.out:
        try:
            target = write_json(args.out, payload)
        except OSError as exc:
            # 血案（R3 审计）：输出目录不可创建时旧版裸栈 rc=1，自动化无法判断卡点。
            print(json.dumps({"ok": False, "blocked_at": "out",
                              "reason": "%s: %s" % (type(exc).__name__, exc)},
                             ensure_ascii=False))
            return 2
        print("wrote: %s" % target)
    if args.json or not args.out:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
