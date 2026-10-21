#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evidence-accept.py -- 取证案例目录的证据链四要素机检（只读、离线）。

用法:
    python evidence-accept.py --case Tool/cases/forensics03
    python evidence-accept.py --case Tool/cases/forensics03 --json
    python evidence-accept.py --self-test

检查:
    1. case.json 必填字段、domain、outcome、evidence_kind/target_type 自洽；
    2. artifacts[] 路径存在且 sha256 复算一致（禁止 ../ 逃逸）；
    3. acquisition 采集方法/工具/时间/时区/时钟偏差；
    4. timeframe 起止可解析且顺序正确；
    5. findings[] 四要素（时间/主体/动作/对象）+ confidence 枚举；
    6. lessons[0] 写明跑什么、命令、rc；
    7. refs 指向仓库内真实文件；input/ 存在；
    8. 若 artifacts 含 timeline.json，则检查 ok/events 非空。

退出码:
    0 全部通过；2 有失败或输入错误（输出 {"ok": false, "blocked_at": ..., "reason": ...}）。
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys
import tempfile

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(HERE))))
CASE_FIELDS = ("id", "domain", "target_type", "evidence_kind", "protection",
               "authority", "goal_level", "outcome", "artifacts", "lessons",
               "refs", "updated")
FIXTURE_WORDS = ("夹具", "教学", "fixture", "示例")
CONFIDENCE = {"observed", "inferred", "unverified", "observed-log"}


class AcceptError(Exception):
    def __init__(self, blocked_at, reason):
        super().__init__(reason)
        self.blocked_at = blocked_at
        self.reason = reason


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_iso(value):
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        return _dt.datetime.fromisoformat(text)
    except ValueError:
        return None


def inside(base, target):
    try:
        return os.path.commonpath([os.path.abspath(base), os.path.abspath(target)]) == os.path.abspath(base)
    except ValueError:
        return False


def check_case(case_dir, domain="forensics-mobile"):
    failures, warnings = [], []
    checks = 0

    def ok(cond, message):
        nonlocal checks
        checks += 1
        if not cond:
            failures.append(message)
        return bool(cond)

    case_dir = os.path.abspath(case_dir)
    case_json = os.path.join(case_dir, "case.json")
    if not os.path.isfile(case_json):
        raise AcceptError("input", "缺少 case.json：%s" % case_json)
    try:
        with open(case_json, encoding="utf-8-sig") as fh:
            case = json.load(fh)
    except (OSError, ValueError) as exc:
        raise AcceptError("parse", "case.json 读取失败：%s" % exc)

    missing = [k for k in CASE_FIELDS if k not in case]
    ok(not missing, "case.json 缺字段：%s" % ",".join(missing))
    ok(case.get("domain") == domain, "domain=%r，期望 %r" % (case.get("domain"), domain))
    ok(case.get("outcome") != "planned", "outcome=planned 不许入库")

    kind = case.get("evidence_kind")
    ok(kind in ("fixture", "real", "self-built", "historical"), "evidence_kind=%r 非 fixture/real" % kind)
    target = str(case.get("target_type") or "")
    is_fixture_word = any(w in target for w in FIXTURE_WORDS)
    if kind == "fixture":
        ok(is_fixture_word, "fixture 的 target_type 必须含 夹具/教学/fixture/示例")
    elif kind in ("real", "self-built"):
        ok(not is_fixture_word, "real 的 target_type 不得含夹具/教学字样")

    acquisition = case.get("acquisition") or {}
    for key in ("method", "tool", "collected_at", "timezone", "clock_skew"):
        ok(bool(acquisition.get(key)), "acquisition 缺 %s" % key)

    timeframe = case.get("timeframe") or {}
    start = parse_iso(timeframe.get("start"))
    end = parse_iso(timeframe.get("end"))
    ok(start is not None, "timeframe.start 不是 ISO 时间")
    ok(end is not None, "timeframe.end 不是 ISO 时间")
    if start and end:
        ok(start <= end, "timeframe.start > end")
    ok(bool(timeframe.get("clock_skew")), "timeframe 缺 clock_skew")

    artifacts = case.get("artifacts") or []
    ok(bool(artifacts), "artifacts 为空")
    for art in artifacts:
        rel = art.get("path") if isinstance(art, dict) else None
        want = (art.get("sha256") if isinstance(art, dict) else "") or ""
        ok(bool(rel), "artifact 缺 path")
        if not rel:
            continue
        full = os.path.join(case_dir, rel)
        if not inside(case_dir, full):
            ok(False, "artifact 路径逃逸案例目录：%s" % rel)
            continue
        if not ok(os.path.isfile(full), "artifact 不存在：%s" % rel):
            continue
        if not ok(len(want) == 64, "artifact 缺 sha256：%s" % rel):
            continue
        actual = sha256_file(full)
        ok(actual == want.lower(), "artifact sha256 不符：%s（实际 %s）" % (rel, actual[:16]))
        if os.path.basename(rel) == "timeline.json":
            try:
                with open(full, encoding="utf-8") as fh:
                    tl = json.load(fh)
                ok(bool(tl.get("ok")) and bool(tl.get("events")), "timeline.json 无事件或 ok!=true")
                # 四要素必须在**事件级**成立：时间/主体/动作/对象。
                # 血案（R2 审计）：旧版只查 findings，timeline 1040 条事件 action 全空也能过。
                evs = tl.get("events") or []
                miss_action = [e for e in evs if not str(e.get("action") or "").strip()]
                bad_actor = [e for e in evs
                             if ("/" in str(e.get("actor") or "") or "\\" in str(e.get("actor") or ""))]
                ok(not miss_action, "timeline 有 %d/%d 条事件缺 action（例：%s）"
                   % (len(miss_action), len(evs), str(miss_action[0].get("kind") if miss_action else "")))
                ok(len(bad_actor) <= max(1, len(evs) // 20),
                   "timeline 有 %d/%d 条事件 actor 像路径（主体必须是账号/进程/PID）"
                   % (len(bad_actor), len(evs)))
            except (OSError, ValueError) as exc:
                ok(False, "timeline.json 不可读：%s" % exc)

    findings = case.get("findings") or []
    ok(bool(findings), "findings 为空（没有四要素结论）")
    for i, f in enumerate(findings, 1):
        ok(parse_iso(f.get("time_utc")) is not None, "finding#%d time_utc 非法" % i)
        for key in ("actor", "action", "object"):
            ok(bool(str(f.get(key) or "").strip()), "finding#%d 缺 %s" % (i, key))
        ok(f.get("confidence") in CONFIDENCE,
           "finding#%d confidence=%r 非 observed/inferred/unverified" % (i, f.get("confidence")))
        for ref in f.get("evidence_refs") or []:
            if not isinstance(ref, str) or "://" in ref:
                continue
            candidates = [os.path.join(case_dir, ref), os.path.join(ROOT, ref)]
            ok(any(os.path.isfile(c) for c in candidates), "finding#%d evidence_ref 幻影：%s" % (i, ref))

    lessons = case.get("lessons") or []
    ok(bool(lessons), "lessons 为空")
    if lessons:
        first = str(lessons[0])
        ok(bool(re.search(r"rc\s*=\s*\d+", first)), "lessons[0] 未写 rc=数字")
        ok(bool(re.search(r"(python|tshark|wevtutil|reg\s+save|sqlite3|grep|fs-timeline|forensics-check)",
                          first, re.I)), "lessons[0] 未写实际命令/工具")
        ok("input/" in first or "--file" in first or "--input" in first or "--case" in first,
           "lessons[0] 未写输入对象")

    refs = case.get("refs") or []
    ok(bool(refs), "refs 为空")
    for ref in refs:
        if not isinstance(ref, str) or "://" in ref:
            continue
        ok(os.path.isfile(os.path.join(ROOT, ref)), "refs 幻影：%s" % ref)

    ok(os.path.isdir(os.path.join(case_dir, "input")), "缺 input/ 目录")

    # 交叉一致性（复审 P0）：案例自述与实际磁盘必须对得上，否则 accept 会假绿。
    blob = json.dumps(case, ensure_ascii=False)
    for m in re.finditer(r"input/[A-Za-z0-9_.\-]+", blob):
        ip = m.group(0)
        ok(os.path.isfile(os.path.join(case_dir, ip)), "案例提到 %s 但文件不存在" % ip)
    kind_map = {"hive": (".hiv",), "evtx": (".evtx",), "pcap": (".pcap", ".pcapng"),
                "ipa": (".ipa",), "apk": (".apk",), "asar": (".asar",), "vsix": (".vsix",)}
    all_names = []
    for dp, dn, fn in os.walk(case_dir):
        all_names += [f.lower() for f in fn]
    tt = str(case.get("target_type") or "").lower()
    for word, exts in kind_map.items():
        if word in tt and not any(n.endswith(exts) for n in all_names):
            ok(False, "target_type 称 %s，但案例内无 %s 文件" % (word, "/".join(exts)))

    def _events(path):
        try:
            d = json.load(open(path, encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(d, dict):
            return None
        if "timeline_summary" in d:
            return (d.get("timeline_summary") or {}).get("events")
        if "events" in d:
            return len(d.get("events") or [])
        return None

    rp = os.path.join(case_dir, "artifacts", "run.json")
    tp = os.path.join(case_dir, "artifacts", "timeline.json")
    if os.path.isfile(rp) and os.path.isfile(tp):
        a, b = _events(rp), _events(tp)
        if a is not None and b is not None:
            ok(int(a) == int(b), "run.json 事件数 %s != timeline.json %s" % (a, b))

    # 与门禁同源的三条硬断言（单跑 accept 也不能假绿）：
    #   ① timeframe.end 必须等于 timeline 最后事件；
    #   ② observed 结论的 time_utc 必须出现在 timeline 事件里；
    #   ③ 声称「均只读」时输入不得可写。
    tlf = os.path.join(case_dir, "artifacts", "timeline.json")
    if os.path.isfile(tlf):
        try:
            tl2 = json.load(open(tlf, encoding="utf-8"))
            evs2 = tl2.get("events") or []
            times2 = {str(e.get("time_utc")) for e in evs2}
            if evs2:
                latest = max(str(e.get("time_utc")) for e in evs2)
                tf_end = str(timeframe.get("end") or "")
                ok(bool(tf_end) and latest.startswith(tf_end[:19]),
                   "timeframe.end=%s 与时间线最后事件 %s 不一致" % (tf_end, latest))
                for i, f in enumerate(findings, 1):
                    if str(f.get("confidence")) == "observed":
                        ft = str(f.get("time_utc") or "")
                        ok((not ft) or (ft in times2),
                           "finding#%d observed 的 time_utc=%s 不在时间线" % (i, ft))
        except Exception:  # noqa: BLE001
            ok(False, "timeline.json 解析失败")
    if re.search(r"均只读|all read-only", blob):
        for dp, dn, fn in os.walk(os.path.join(case_dir, "input")):
            for f in fn:
                ok(not os.access(os.path.join(dp, f), os.W_OK),
                   "声称均只读，但 %s 可写" % f)


    # 只读检查：证据文件不应可写（Windows 上 chmod a-w 可能仍显示可写，故只告警）
    for art in artifacts:
        rel = art.get("path") if isinstance(art, dict) else None
        if rel and os.path.isfile(os.path.join(case_dir, rel)):
            if os.access(os.path.join(case_dir, rel), os.W_OK):
                warnings.append("artifact 可写：%s（应只读封存）" % rel)

    return {"ok": not failures, "case": case.get("id") or os.path.basename(case_dir),
            "domain": domain, "checks": checks, "failures": failures,
            "warnings": warnings, "artifacts": len(artifacts), "findings": len(findings)}


def self_test():
    checks = 0
    try:
        with tempfile.TemporaryDirectory(prefix="evidence-accept-selftest-") as tmp:
            case_dir = os.path.join(tmp, "forensics99")
            os.makedirs(os.path.join(case_dir, "input"))
            os.makedirs(os.path.join(case_dir, "artifacts"))
            evidence = os.path.join(case_dir, "input", "sample.bin")
            with open(evidence, "wb") as fh:
                fh.write(b"evidence-self-test\n")
            run = os.path.join(case_dir, "artifacts", "run.json")
            with open(run, "w", encoding="utf-8") as fh:
                json.dump({"ok": True, "checks": 1}, fh)
            timeline = os.path.join(case_dir, "artifacts", "timeline.json")
            with open(timeline, "w", encoding="utf-8") as fh:
                json.dump({"ok": True, "events": [{"time_utc": "2026-10-20T00:00:00Z",
                                                 "source": "selftest.evtx", "kind": "evtx-record",
                                                 "action": "event-logged", "actor": "alice",
                                                 "object": "4624", "detail": {}, "confidence": "observed"}]}, fh)
            case = {
                "id": "forensics99", "domain": "forensics-mobile",
                "target_type": "离线自检夹具", "evidence_kind": "fixture",
                "protection": [], "authority": "local", "goal_level": "L1",
                "outcome": "partial",
                "acquisition": {"method": "self-test", "tool": "evidence-accept.py",
                                "collected_at": "2026-10-20T00:00:00Z", "timezone": "UTC",
                                "clock_skew": "0"},
                "timeframe": {"start": "2026-10-20T00:00:00Z", "end": "2026-10-20T00:00:00Z",
                              "clock_skew": "0"},
                "artifacts": [
                    {"path": "input/sample.bin", "sha256": sha256_file(evidence)},
                    {"path": "artifacts/run.json", "sha256": sha256_file(run)},
                    {"path": "artifacts/timeline.json", "sha256": sha256_file(timeline)},
                ],
                "findings": [{"time_utc": "2026-10-20T00:00:00Z", "actor": "selftest",
                              "action": "stat", "object": "input/sample.bin",
                              "confidence": "observed",
                              "evidence_refs": ["input/sample.bin"]}],
                "lessons": ["跑的是 self-test，命令 python evidence-accept.py --case forensics99，rc=0；夹具通过。"],
                "refs": ["Tool/skill/forensics-mobile/SKILL.md"],
                "updated": "2026-10-20",
            }
            with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
                json.dump(case, fh, ensure_ascii=False)
            result = check_case(case_dir)
            assert result["ok"] is True, result
            checks += 1

            # 篡改哈希必须被抓到
            case["artifacts"][0]["sha256"] = "0" * 64
            with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
                json.dump(case, fh, ensure_ascii=False)
            bad = check_case(case_dir)
            assert bad["ok"] is False and any("sha256" in x for x in bad["failures"]), bad
            checks += 1

            # 缺四要素/越界路径必须被抓到
            case["artifacts"][0]["sha256"] = sha256_file(evidence)
            case["findings"] = [{"time_utc": "bad", "actor": "", "action": "",
                                 "object": "", "confidence": "certain"}]
            case["artifacts"].append({"path": "../escape.bin", "sha256": "0" * 64})
            with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
                json.dump(case, fh, ensure_ascii=False)
            bad2 = check_case(case_dir)
            assert bad2["ok"] is False and len(bad2["failures"]) >= 4, bad2
            checks += 1

            # 非 case 目录必须结构化失败
            try:
                check_case(os.path.join(tmp, "missing"))
                raise AssertionError("missing case dir must raise AcceptError")
            except AcceptError as exc:
                assert exc.blocked_at == "input"
                checks += 1

        print(json.dumps({"ok": True, "checks": checks,
                          "note": "offline self-test: four-elements/hash/tamper/escape/failure-path"},
                         ensure_ascii=False))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "blocked_at": "self-test", "reason": str(exc)},
                         ensure_ascii=False))
        return 2


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="取证案例证据链四要素机检：字段/哈希/采集记录/时间线/findings/refs")
    ap.add_argument("--case", "-c", help="案例目录（含 case.json）")
    ap.add_argument("--domain", default="forensics-mobile", help="期望 domain（默认 forensics-mobile）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--self-test", action="store_true", help="离线自检并打印 JSON 结论")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.case:
        print(json.dumps({"ok": False, "blocked_at": "usage",
                          "reason": "需要 --case；或用 --self-test"}, ensure_ascii=False))
        return 2
    try:
        result = check_case(args.case, args.domain)
    except AcceptError as exc:
        print(json.dumps({"ok": False, "blocked_at": exc.blocked_at, "reason": exc.reason},
                         ensure_ascii=False))
        return 2
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "blocked_at": "unexpected", "reason": str(exc)},
                         ensure_ascii=False))
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("case    : %s" % result["case"])
        print("checks  : %d" % result["checks"])
        print("result  : %s" % ("PASS" if result["ok"] else "FAIL"))
        for x in result["failures"]:
            print("  - FAIL %s" % x)
        for x in result["warnings"]:
            print("  - WARN %s" % x)
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
