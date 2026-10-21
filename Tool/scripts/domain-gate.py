#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""domain-gate.py —— 领域深度门禁（九件套 2.0 的可执行版）。

它回答一个问题：**这个域现在能不能独立打一场？**
判据全部来自 `docs/DOMAIN-SPEC-v2.md` + `Tool/scripts/lib/domain_spec.py`：

    [1] 篇幅   SKILL ≤600 / ref 60–400 / KB 50–200
    [2] 必备篇 01-criteria / 02-failure-criteria / 03-model-pitfalls / 04-walkthrough-*
    [3] 脚本   2–4 个，`--help` 与 `--self-test` 都必须 rc=0
    [4] 案例   3–5 个，≥1 个 evidence_kind=real，sha256 复算，refs 不幻影
    [5] KB     6–10 篇，含 *failure-criteria*，README 链接到每一篇
    [6] 矩阵   rows/families ≥12
    [7] 任务卡 20–30 张，六段齐全，reference 存在
    [8] 链接图 每个 ref / KB 文件至少被别处引用一次
    [9] 路由   跨域串味测试集（zipalign/spider/principal/bios/scaffold/src-xxx.dll）
    [10] 清理  根目录无 优化方案*.md；ROADMAP ≤80 行；docs/AUDIT.md 存在
    [11] 部署  ~/.pi/agent/skills 与仓库逐域哈希一致

用法：
    python Tool/scripts/domain-gate.py --all
    python Tool/scripts/domain-gate.py --domain web-pentest --json
    python Tool/scripts/domain-gate.py --links --routing
退出码：0 全绿 / 1 有 FAIL / 2 契约漂移
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import subprocess
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
TOOL = os.path.join(ROOT, "Tool")
KBROOT = os.path.join(TOOL, "mcp", "Tool", "reverselab", "kb")
sys.path.insert(0, os.path.join(HERE, "lib"))

from domain_spec import (  # noqa: E402
    CASE_FIELDS, DOMAINS, FIXTURE_WORDS, LIMITS, REQUIRED_REFS, ROUTING_TESTS,
)

TEXT_EXT = {".md", ".py", ".ps1", ".sh", ".json", ".yml", ".yaml", ".txt"}
SKIP_TEXT = ("CHANGELOG", "Tool/upstream/", "Tool/mcp/Tool/safe/",
             "Tool/mcp/Tool/reverselab/kb/AI-USAGE.md")
results = []


def add(section, name, ok, detail=""):
    results.append({"domain": section, "name": name, "ok": bool(ok), "detail": detail})


def rj(p):
    with open(p, encoding="utf-8-sig") as f:
        return json.load(f)


def lines(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(p):
    return os.path.relpath(p, ROOT).replace(os.sep, "/")


# ---------------------------------------------------------------- [1][2] refs
def check_refs(dom, spec):
    d = os.path.join(TOOL, "skill", spec["skill"], "references")
    if not os.path.isdir(d):
        add(dom, "references 目录", False, "缺失 " + rel(d))
        return []
    refs = sorted(glob.glob(os.path.join(d, "*.md")))
    bad = []
    if not (LIMITS["refs_min"] <= len(refs) <= LIMITS["refs_max"]):
        bad.append("篇数 %d（要求 %d–%d）" % (len(refs), LIMITS["refs_min"], LIMITS["refs_max"]))
    for p in refs:
        n = len(lines(p))
        if n > LIMITS["ref_max"] or n < LIMITS["ref_min"]:
            bad.append("%s %d 行（要求 %d–%d）" % (os.path.basename(p), n,
                                                LIMITS["ref_min"], LIMITS["ref_max"]))
    names = [os.path.basename(p) for p in refs]
    for key, pat in REQUIRED_REFS:
        if any(ch in pat for ch in "*?["):
            if not any(fnmatch(n, pat) for n in names):
                bad.append("缺必备篇 " + pat)
        elif pat not in names:
            bad.append("缺必备篇 " + pat)
    # 必备篇内容机检
    crit = os.path.join(d, "01-criteria.md")
    if os.path.isfile(crit):
        t = "\n".join(lines(crit))
        if "误报" not in t or "证据" not in t:
            bad.append("01-criteria.md 缺『证据形态/误报风险』列")
        if t.count("\n|") < 8:
            bad.append("01-criteria.md 判据表行数 <8")
    fail = os.path.join(d, "02-failure-criteria.md")
    if os.path.isfile(fail):
        t = "\n".join(lines(fail))
        if t.count("\n|") < 9:
            bad.append("02-failure-criteria.md 失败判据表 <8 行")
        if "改走" not in t and "降级" not in t and "转" not in t:
            bad.append("02-failure-criteria.md 缺『改走哪条』")
    pit = os.path.join(d, "03-model-pitfalls.md")
    if os.path.isfile(pit):
        t = "\n".join(lines(pit))
        if len(re.findall(r"^#{2,4}\s|\n\d+\.\s", t, re.M)) < 10:
            bad.append("03-model-pitfalls.md 条目 <10")
    walk = glob.glob(os.path.join(d, "04-walkthrough-*.md"))
    if walk and "\n".join(lines(walk[0])).count("```") < 4:
        bad.append("04-walkthrough 代码块 <2")
    add(dom, "references 篇数/篇幅/必备篇", not bad,
        "；".join(bad) if bad else "%d 篇，必备四篇齐全，篇幅合规" % len(refs))
    return refs


def fnmatch(name, pat):
    import fnmatch as _f
    return _f.fnmatch(name, pat)


# ---------------------------------------------------------------- [0] SKILL
def check_skill(dom, spec):
    p = os.path.join(TOOL, "skill", spec["skill"], "SKILL.md")
    if not os.path.isfile(p):
        add(dom, "SKILL.md", False, "缺失")
        return
    t = "\n".join(lines(p))
    n = len(lines(p))
    bad = []
    if n > LIMITS["skill_max"]:
        bad.append("%d 行 > %d" % (n, LIMITS["skill_max"]))
    if n < LIMITS["skill_min"]:
        bad.append("%d 行 < %d（深度不足）" % (n, LIMITS["skill_min"]))
    for marker in ("判据", "失败判据", "模型常见失误", "边界"):
        if marker not in t:
            bad.append("缺『%s』节" % marker)
    if "references/" not in t:
        bad.append("SKILL 未索引任何 reference")
    add(dom, "SKILL.md 篇幅与四节", not bad, "；".join(bad) if bad else "%d 行" % n)


# ---------------------------------------------------------------- [3] scripts
def check_scripts(dom, spec):
    d = os.path.join(TOOL, "skill", spec["skill"], "scripts")
    found = sorted(glob.glob(os.path.join(d, "*.py"))) if os.path.isdir(d) else []
    for e in spec.get("ext_scripts") or []:
        p = os.path.join(ROOT, e)
        if os.path.isfile(p):
            found.append(p)
    if not (LIMITS["scripts_min"] <= len(found) <= LIMITS["scripts_max"]):
        add(dom, "脚本数量", False, "%d 个（要求 %d–%d）：%s" % (
            len(found), LIMITS["scripts_min"], LIMITS["scripts_max"],
            ",".join(os.path.basename(x) for x in found)))
        return
    bad = []
    for p in found:
        for flag, need_ok in (("--help", True), ("--self-test", True)):
            try:
                r = subprocess.run([sys.executable, p, flag], capture_output=True,
                                   text=True, encoding="utf-8", errors="replace",
                                   timeout=120, cwd=ROOT)
            except Exception as e:  # noqa: BLE001
                bad.append("%s %s 异常:%s" % (os.path.basename(p), flag, str(e)[:30]))
                continue
            if r.returncode != 0:
                bad.append("%s %s rc=%d" % (os.path.basename(p), flag, r.returncode))
            elif flag == "--self-test" and '"ok"' not in (r.stdout or ""):
                bad.append("%s --self-test 无 JSON 结论" % os.path.basename(p))
    add(dom, "脚本 --help / --self-test", not bad,
        "；".join(bad) if bad else "%d 个脚本全部 rc=0" % len(found))


# ---------------------------------------------------------------- [4] cases
def check_cases(dom, spec):
    cdir = os.path.join(ROOT, "Tool", "cases")
    dirs = []
    for g in spec["case_globs"]:
        dirs += [x for x in glob.glob(os.path.join(cdir, g)) if os.path.isdir(x)]
    dirs = sorted(set(dirs))
    cmax = spec.get("cases_max", LIMITS["cases_max"])
    bad = []
    if not (LIMITS["cases_min"] <= len(dirs) <= cmax):
        bad.append("案例 %d 个（要求 %d–%d）" % (len(dirs), LIMITS["cases_min"], cmax))
    real = 0
    recorded_real = 0
    for cd in dirs:
        cf = os.path.join(cd, "case.json")
        if not os.path.isfile(cf):
            bad.append(os.path.basename(cd) + "(缺 case.json)")
            continue
        try:
            c = rj(cf)
        except Exception as e:  # noqa: BLE001
            bad.append("%s(case.json 坏:%s)" % (os.path.basename(cd), str(e)[:30]))
            continue
        miss = [k for k in CASE_FIELDS if k not in c]
        if miss:
            bad.append("%s(缺 %s)" % (os.path.basename(cd), ",".join(miss)))
        kind = c.get("evidence_kind")
        if kind not in ("fixture", "real"):
            bad.append("%s(evidence_kind=%r)" % (os.path.basename(cd), kind))
            kind = None
        tt = str(c.get("target_type") or "")
        is_fix = any(w in tt for w in FIXTURE_WORDS)
        if kind == "fixture" and not is_fix:
            bad.append("%s(fixture 但 target_type 未标夹具)" % os.path.basename(cd))
        if kind == "real" and is_fix:
            bad.append("%s(real 却标成夹具)" % os.path.basename(cd))
        if kind == "real":
            real += 1
            rp = c.get("repro") or {}
            if rp.get("status") == "recorded" or ("rc=" in "\n".join(c.get("lessons") or [])):
                recorded_real += 1
        # 单域模式也要能抓到「伪 real」：real 但既没有命令/rc、也没标 not-recorded。
        if c.get("evidence_kind") == "real":
            _txt = "\n".join(c.get("lessons") or [])
            _rp = c.get("repro") or {}
            if ("rc=" not in _txt) and ("python " not in _txt) and ("命令" not in _txt) \
                    and _rp.get("status") != "not-recorded":
                bad.append(os.path.basename(cd) + "(real 但无命令/rc 且未标 not-recorded)")
        # 交叉一致性（审计 P0）：case.json 里写到的 input 必须存在；
        # target_type 声称的样本类型必须有对应扩展名；run.json 与 timeline.json 的事件数必须一致。
        blob = json.dumps(c, ensure_ascii=False)
        for m in __import__("re").finditer(r"input/[A-Za-z0-9_.\-]+", blob):
            ip = m.group(0)
            if not os.path.isfile(os.path.join(cd, ip)):
                bad.append("%s(提到 %s 但文件不存在)" % (os.path.basename(cd), ip))
                break
        kind_map = {"hive": (".hiv",), "evtx": (".evtx",), "pcap": (".pcap", ".pcapng"),
                    "ipa": (".ipa",), "apk": (".apk",), "docm": (".docm",),
                    "asar": (".asar",), "vsix": (".vsix",), "crx": (".crx",)}
        all_files = []
        for dp, dn, fn in os.walk(cd):
            all_files += [f.lower() for f in fn]
        for word, exts in kind_map.items():
            if word in tt.lower() and not any(f.endswith(exts) for f in all_files):
                bad.append("%s(target_type 称 %s，但案例内无 %s 文件)"
                           % (os.path.basename(cd), word, "/".join(exts)))
        def _events(path):
            try:
                d = rj(path)
            except Exception:  # noqa: BLE001
                return None
            if not isinstance(d, dict):
                return None
            if "timeline_summary" in d:
                return (d.get("timeline_summary") or {}).get("events")
            if "events" in d:
                return len(d.get("events") or [])
            return None
        rp = os.path.join(cd, "artifacts", "run.json")
        tp = os.path.join(cd, "artifacts", "timeline.json")
        if os.path.isfile(rp) and os.path.isfile(tp):
            a, b = _events(rp), _events(tp)
            if a is not None and b is not None and int(a) != int(b):
                bad.append("%s(run.json 事件数 %s != timeline.json %s)" % (os.path.basename(cd), a, b))
        # 更深一层的自述-磁盘一致性（R4 三审）：
        #   a) 声称 reg save / last-write 却没有 .hiv 输入 → FAIL；
        #   b) 有 timeline.json 时，observed 结论的 time_utc 必须出现在时间线事件里；
        #   c) timeframe.end 必须等于时间线最后一个事件的时间。
        if re.search(r"reg\s+save|last[-_ ]write", blob, re.I) and not any(
                f.endswith(".hiv") for f in all_files):
            bad.append("%s(声称 reg save/last-write 但无 .hiv 输入)" % os.path.basename(cd))
        # 只读声明与 mtime 区间声明也必须与磁盘/时间线一致（R4 三审的同类问题）。
        if re.search(r"均只读|all read-only", blob):
            for dp, dn, fn in os.walk(os.path.join(cd, "input")):
                for f in fn:
                    if os.access(os.path.join(dp, f), os.W_OK):
                        bad.append("%s(声称均只读，但 %s 可写)" % (os.path.basename(cd), f))
                        break
                else:
                    continue
                break
        tlf = os.path.join(cd, "artifacts", "timeline.json")
        if os.path.isfile(tlf):
            try:
                tl = rj(tlf)
                evs = tl.get("events") or []
                times = {str(e.get("time_utc")) for e in evs}
                if evs:
                    latest = max(str(e.get("time_utc")) for e in evs)
                    tf_end = str((c.get("timeframe") or {}).get("end") or "")
                    if tf_end and not latest.startswith(tf_end[:19]):
                        bad.append("%s(timeframe.end=%s 与时间线最后事件 %s 不一致)"
                                   % (os.path.basename(cd), tf_end, latest))
                    # mtime 区间声明 vs 时间线的 filesystem-mtime 事件
                    fs_times = [str(e.get("time_utc")) for e in evs
                                if str(e.get("kind") or "").startswith("filesystem")]
                    # 只对「mtime 语境」的区间做校验（浏览器访问时间区间不适用于 fs 事件）
                    for m in re.finditer(
                            r"mtime[^\n]{0,80}?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z?\s*[–-]\s*(\d{2}:\d{2}:\d{2})Z",
                            blob, re.I):
                        start, end_t = m.group(1), m.group(2)
                        lo, hi = start + "Z", start[:11] + end_t + "Z"
                        outside = [x for x in fs_times if not (lo <= x <= hi)]
                        if outside:
                            bad.append("%s(mtime 区间声明 %s…%s 与时间线 %s 矛盾)"
                                       % (os.path.basename(cd), start, end_t, outside[0]))
                            break
                    for f in c.get("findings") or []:
                        if str(f.get("confidence")) == "observed":
                            ft = str(f.get("time_utc") or "")
                            if ft and ft not in times:
                                bad.append("%s(observed 结论 time_utc=%s 不在时间线里)"
                                           % (os.path.basename(cd), ft))
                                break
            except Exception:  # noqa: BLE001
                bad.append(os.path.basename(cd) + "(timeline.json 解析失败)")
        if c.get("outcome") == "planned":
            bad.append(os.path.basename(cd) + "(outcome=planned 不许入库)")
        if not (c.get("lessons") or []):
            bad.append(os.path.basename(cd) + "(lessons 为空)")
        for art in c.get("artifacts") or []:
            ap = art.get("path") or ""
            want = (art.get("sha256") or "").lower()
            full = os.path.join(cd, ap)
            if not ap or not os.path.isfile(full):
                bad.append("%s(幻影产物 %s)" % (os.path.basename(cd), ap[:40]))
                continue
            if len(want) != 64:
                bad.append("%s(%s 缺 sha256)" % (os.path.basename(cd), ap[:30]))
            elif sha256(full) != want:
                bad.append("%s(%s sha256 不符，重算=%s)" % (
                    os.path.basename(cd), ap[:30], sha256(full)[:12]))
        for r in c.get("refs") or []:
            if isinstance(r, str) and "://" not in r:
                if not os.path.isfile(os.path.join(ROOT, r)):
                    bad.append("%s(refs 幻影 %s)" % (os.path.basename(cd), r[:40]))
    if real < 1:
        bad.append("没有任何 evidence_kind=real 的案例（每域至少 1 个真跑）")
    # 验收脚本接入（域级一次跑完，不做逐案例调用）：
    # 各域 accept 的接口不统一（有的 --case 收目录名、有的收路径，且内部还有
    # 「本域至少 3-5 个案例」的聚合断言），逐案例调用会把接口差异误报成验收失败。
    # 血案（R3 审计 P0-2）：forensics 的 evidence-accept 已红两例，门禁却仍 8/8。
    acc = sorted(glob.glob(os.path.join(TOOL, "skill", spec["skill"], "scripts", "*accept*.py")))
    if acc:
        try:
            hp = subprocess.run([sys.executable, acc[0], "--help"], capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=60)
            htxt = (hp.stdout or "") + (hp.stderr or "")
            cargs = [sys.executable, acc[0]]
            if "--root" in htxt:
                cargs += ["--root", ROOT]
            if "--json" in htxt:
                cargs += ["--json"]
            r = subprocess.run(cargs, capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=300, cwd=ROOT)
            # 有的 accept 只支持单案例（--case 必填）。域级跑出 rc=2 且提示 --case 时，
            # 退化为逐案例调用；这是接口差异，不是验收失败。
            if r.returncode == 2 and "--case" in ((r.stderr or "") + (r.stdout or "")):
                r = None
                for cd in dirs:
                    if not os.path.isfile(os.path.join(cd, "case.json")):
                        continue
                    rr = subprocess.run([sys.executable, acc[0], "--case", cd],
                                        capture_output=True, text=True, encoding="utf-8",
                                        errors="replace", timeout=300, cwd=ROOT)
                    if rr.returncode != 0:
                        tail = [x for x in ((rr.stdout or "") + (rr.stderr or "")).splitlines()
                                if "FAIL" in x or "failures" in x][:2]
                        bad.append("%s(%s rc=%d%s)" % (os.path.basename(cd),
                                                       os.path.basename(acc[0]), rr.returncode,
                                                       "：" + "；".join(tail) if tail else ""))
                r = None
            if r is not None and r.returncode != 0:
                tail = [x for x in ((r.stdout or "") + (r.stderr or "")).splitlines()
                        if "FAIL" in x or "failures" in x][:3]
                bad.append("%s(域级验收 rc=%d%s)" % (os.path.basename(acc[0]), r.returncode,
                                                   "：" + "；".join(tail) if tail else ""))
        except Exception as e:  # noqa: BLE001
            bad.append("accept 异常:%s" % str(e)[:50])
    if real >= 1 and recorded_real < 1:
        bad.append("没有『有命令+rc』的 real 案例（real 不许全部是 not-recorded 历史归档）")
    add(dom, "案例字段/真跑/sha256 复算", not bad,
        "；".join(bad[:6]) + ("…" if len(bad) > 6 else "") if bad
        else "%d 个案例（real %d），hash 复算一致" % (len(dirs), real))


# ---------------------------------------------------------------- [5] KB
def check_kb(dom, spec):
    d = os.path.join(KBROOT, spec["board"])
    if not os.path.isdir(d):
        add(dom, "KB board", False, "缺失 " + rel(d))
        return
    mds = [p for p in glob.glob(os.path.join(d, "**", "*.md"), recursive=True)]
    tech = [p for p in mds if os.path.basename(p) != "README.md"]
    total = len(mds)
    kmax = spec.get("kb_max_count", LIMITS["kb_max_count"])
    lmax = spec.get("kb_line_max", LIMITS["kb_max"])
    bad = []
    if not (LIMITS["kb_min_count"] <= total <= kmax):
        bad.append("KB %d 篇（要求 %d–%d）" % (total, LIMITS["kb_min_count"], kmax))
    for p in tech:
        n = len(lines(p))
        if n > lmax or n < LIMITS["kb_min"]:
            bad.append("%s %d 行（要求 %d–%d）" % (os.path.basename(p), n,
                                                LIMITS["kb_min"], lmax))
    if not any("failure-criteria" in os.path.basename(p) for p in tech):
        bad.append("缺 *failure-criteria* 失败判据篇")
    rd = os.path.join(d, "README.md")
    if os.path.isfile(rd):
        # board README + techniques/README.md 构成一条索引链：任一处链接即算入链。
        # 大 board（如 pe-reverse 40+ 篇）用分目录 README 分层索引是正常做法，
        # 强行要求 board README 直链每一篇会逼出 200 行流水账。
        t = "\n".join(lines(rd))
        trd = os.path.join(d, "techniques", "README.md")
        if os.path.isfile(trd):
            t += "\n" + "\n".join(lines(trd))
        missing = [os.path.basename(p) for p in tech
                   if os.path.basename(p) not in t and rel(p) not in t]
        if missing:
            bad.append("README 未链接：" + ",".join(missing[:4]))
    else:
        bad.append("缺 README.md")
    add(dom, "KB 篇数/篇幅/失败判据/README 索引", not bad,
        "；".join(bad) if bad else "%d 篇（含失败判据），README 全索引" % total)


# ---------------------------------------------------------------- [6] matrix
def check_matrix(dom, spec):
    p = os.path.join(TOOL, "config", spec["matrix"])
    if not os.path.isfile(p):
        add(dom, "矩阵", False, "缺 " + spec["matrix"])
        return
    try:
        d = rj(p)
    except Exception as e:  # noqa: BLE001
        add(dom, "矩阵", False, "坏 JSON:" + str(e)[:50])
        return
    rows = d.get("rows") or d.get("families") or []
    bad = []
    if len(rows) < LIMITS["matrix_min"]:
        bad.append("条目 %d < %d" % (len(rows), LIMITS["matrix_min"]))
    for r in rows:
        if not isinstance(r, dict):
            bad.append("非对象条目")
            break
        if not (r.get("criteria") and r.get("fail") and (r.get("match") or r.get("family"))):
            bad.append("条目缺 match/criteria/fail：%s" % (r.get("id") or r.get("category")))
            break
    add(dom, "矩阵 ≥12 条 + 判据/失败判据", not bad,
        "；".join(bad) if bad else "%d 条" % len(rows))


# ---------------------------------------------------------------- [7] cards
def check_cards(dom, spec=None):
    p = os.path.join(TOOL, "prompts", "domains", dom + ".md")
    if not os.path.isfile(p):
        add(dom, "任务卡", False, "缺 Tool/prompts/domains/%s.md" % dom)
        return
    t = "\n".join(lines(p))
    # 卡片：### 开头，六段用 - 触发词：/- 前置：/- 步骤：/- 判据：/- 失败判据：/- reference：
    blocks = re.split(r"^### ", t, flags=re.M)[1:]
    bad = []
    if not (LIMITS["cards_min"] <= len(blocks) <= LIMITS["cards_max"]):
        bad.append("卡片 %d 张（要求 %d–%d）" % (len(blocks), LIMITS["cards_min"], LIMITS["cards_max"]))
    keys = ("触发词", "前置", "步骤", "判据", "失败判据", "reference")
    # 对题性（弱机检）：卡标题里的 ASCII 技术词，必须在该域 references 的**某处**出现过。
    # 否则就是「卡写着 hayabusa / kube-bench，文档里查无此物」——审计 P1-4 的原形。
    corpus = ""
    if spec:
        rdir = os.path.join(TOOL, "skill", spec["skill"], "references")
        if os.path.isdir(rdir):
            corpus = "\n".join(open(x, encoding="utf-8", errors="replace").read()
                                for x in sorted(glob.glob(os.path.join(rdir, "*.md")))).lower()
    seen = set()
    for b in blocks:
        head = b.splitlines()[0].strip()
        seen.add(head)
        miss = [k for k in keys if ("- " + k + "：") not in b]
        if miss:
            bad.append("%s(缺 %s)" % (head[:24], ",".join(miss)))
            continue
        m = re.search(r"- reference：\s*`?([A-Za-z0-9_\-./]+)`?", b)
        if not m or not os.path.isfile(os.path.join(ROOT, m.group(1))):
            bad.append("%s(reference 幻影)" % head[:24])
        elif corpus:
            toks = [t.lower() for t in re.findall(r"[A-Za-z][A-Za-z0-9_\-]{3,}", head)]
            if toks and not any(t in corpus for t in toks):
                bad.append("%s(标题技术词在 references 查无)" % head[:20])
    if len(seen) != len(blocks):
        bad.append("卡片标题重复")
    add(dom, "任务卡 20–30 张 + 六段 + reference", not bad,
        "；".join(bad[:5]) if bad else "%d 张，六段齐全" % len(blocks))


# ---------------------------------------------------------------- [8] links
def _area(path):
    """引用归属域：skill/<name> 或 kb/<board>，用于「同名文件只在同域内算命中」。"""
    parts = path.replace(os.sep, "/").split("/")
    if len(parts) > 2 and parts[0] == "Tool" and parts[1] == "skill":
        return "skill:" + parts[2]
    if "reverselab/kb/" in path:
        i = path.replace(os.sep, "/").index("reverselab/kb/")
        rest = path.replace(os.sep, "/")[i + len("reverselab/kb/"):]
        # 根目录散篇（field_journal_* / re_pattern_* / edr_bypass_SKILL.md）同属一个"根区"，
        # 否则它们只能靠根 README 的路径级引用入链，而根 README 用的是文件名。
        return "kb:" + (rest.split("/")[0] if "/" in rest else "_root")
    return "other:" + (parts[0] if parts else "")


DERIVED = ("cases/index.json", "kb-index.json", "capability-matrix.json",
           "tool-index.json", "case-index.json")


def check_links():
    """每个 ref/KB 必须有真人可读的入链。

    2026-10-21 审计 P1：旧版 `r in txt or base in txt` 让 basename 跨域互相顶替——
    10 个域都有 `01-criteria.md`，任一处写 `references/01-criteria.md` 就等于给
    10 个文件同时记了一票（76% 的文件其实没有路径级引用）。现在：
      * 路径级命中（完整相对路径）永远算；
      * basename 命中只在**同一域**（同 skill / 同 board）内算；
      * 派生缓存（index.json / kb-index.json 等）不计票——机器索引不等于人能找到。
    """
    cand = []
    for d in glob.glob(os.path.join(TOOL, "skill", "*", "references")):
        cand += glob.glob(os.path.join(d, "*.md"))
    cand += glob.glob(os.path.join(KBROOT, "**", "*.md"), recursive=True)
    cand = [p for p in cand if os.path.isfile(p)]
    corpus = {}
    for dp, dn, fn in os.walk(ROOT):
        dn[:] = [x for x in dn if x not in (".git", "node_modules", "__pycache__", ".pytest_cache")]
        for f in fn:
            p = os.path.join(dp, f)
            r = rel(p)
            if os.path.splitext(f)[1].lower() not in TEXT_EXT:
                continue
            if any(s in r for s in SKIP_TEXT) or any(r.endswith(x) for x in DERIVED):
                continue
            try:
                corpus[r] = open(p, encoding="utf-8", errors="replace").read()
            except Exception:  # noqa: BLE001
                continue
    # 相对 Markdown 链接（`[...](sub/x.md)`）解析成仓库相对路径，等价于路径级引用：
    # 否则 kb/README.md 里 `[APK](apk-reverse/README.md)` 这种正确写法会被判成孤儿。
    linked = set()
    for other, txt in corpus.items():
        base_dir = os.path.dirname(other)
        for m in __import__("re").finditer(r"\]\(([^)\s#]+)", txt):
            t = m.group(1)
            if t.startswith(("http://", "https://", "mailto:", "/")):
                continue
            linked.add(os.path.normpath(os.path.join(base_dir, t)).replace(os.sep, "/"))
    orphans, weak = [], []
    for p in cand:
        r = rel(p)
        base = os.path.basename(p)
        area = _area(r)
        strong = weak_hit = False
        if r in linked:
            strong = True
        for other, txt in corpus.items():
            if other == r or strong:
                continue
            if r in txt:
                strong = True
                break
            # README.md 这种通用名不给 basename 学分：必须有路径级或解析后的相对链接，
            # 否则「10 个 README 互相提名」就等于人人有入链（R4 复审实测 7 个 board README 假绿）。
            if base in txt and _area(other) == area and base.lower() != "readme.md":
                weak_hit = True
        if not (strong or weak_hit):
            orphans.append(r)
        elif not strong:
            weak.append(r)
    detail = "%d 个文件均有路径级或同域入链" % len(cand)
    if weak:
        detail += "；%d 个仅同域 basename 入链" % len(weak)
    add("全局", "链接图无孤儿（路径级或同域 basename 入链）", not orphans,
        ("%d 个孤儿：%s；" % (len(orphans), "；".join(orphans[:6])) if orphans else "") + detail)


LINK_RE = __import__("re").compile(r"\[([^\]]{1,200})\]\(([^)\s]+)\)")
MD_SKIP = ("http://", "https://", "mailto:", "#", "/")


def check_md_links():
    """Markdown 相对链接必须点得开（索引写了但点不开，比没索引更误导）。"""
    roots = [os.path.join(TOOL, "skill"), KBROOT]
    bad = []
    total = 0
    for root in roots:
        for dp, dn, fn in os.walk(root):
            rp = dp.replace(os.sep, "/")
            if "/upstream" in rp or "/safe/" in rp or "__pycache__" in rp:
                dn[:] = []
                continue
            for f in fn:
                if not f.endswith(".md"):
                    continue
                p = os.path.join(dp, f)
                try:
                    txt = open(p, encoding="utf-8", errors="replace").read()
                except Exception:  # noqa: BLE001
                    continue
                for m in LINK_RE.finditer(txt):
                    t = m.group(2)
                    if t.startswith(MD_SKIP):
                        continue
                    path = t.split("#", 1)[0]
                    if not path:
                        continue
                    total += 1
                    if not os.path.isfile(os.path.join(dp, path)):
                        bad.append("%s -> %s" % (rel(p), t))
    add("全局", "Markdown 相对链接可解析（%d 条）" % total, not bad,
        "%d 条死链：%s" % (len(bad), "；".join(bad[:5])) if bad else "全部指向真实文件")


def check_repro_and_templates():
    """真实案例必须有可追溯证据链；模板必须与 CASE_FIELDS 同源。"""
    bad = []
    for cf in sorted(glob.glob(os.path.join(ROOT, "Tool", "cases", "*", "case.json"))):
        c = rj(cf)
        kind = c.get("evidence_kind")
        txt = "\n".join(c.get("lessons") or [])
        repro = c.get("repro") or {}
        if kind == "real":
            recorded = ("rc=" in txt) or ("python " in txt) or ("命令" in txt)
            if not recorded and repro.get("status") != "not-recorded":
                bad.append("%s(real 但无命令/rc 且未标 not-recorded)" % os.path.basename(os.path.dirname(cf)))
            if repro.get("status") == "not-recorded" and not repro.get("reason"):
                bad.append("%s(not-recorded 缺 reason)" % os.path.basename(os.path.dirname(cf)))
    tdir = os.path.join(ROOT, "Tool", "cases", "_templates")
    tpls = sorted(glob.glob(os.path.join(tdir, "*.json")))
    if len(tpls) != len(DOMAINS):
        bad.append("模板 %d 份（要求 %d）" % (len(tpls), len(DOMAINS)))
    for t in tpls:
        try:
            d = rj(t)
        except Exception as e:  # noqa: BLE001
            bad.append(os.path.basename(t) + "(坏:" + str(e)[:20] + ")")
            continue
        miss = [k for k in CASE_FIELDS if k not in d]
        if miss:
            bad.append("%s(缺 %s)" % (os.path.basename(t), ",".join(miss)))
        if d.get("outcome") not in ("partial", "success", "confirmed", "failed"):
            bad.append("%s(outcome=%r)" % (os.path.basename(t), d.get("outcome")))
        for r in d.get("refs") or []:
            if isinstance(r, str) and "://" not in r and not r.startswith("<"):
                if not os.path.isfile(os.path.join(ROOT, r)):
                    bad.append("%s(refs 幻影 %s)" % (os.path.basename(t), r[:40]))
    add("全局", "真实案例证据链 + 十份模板同源", not bad,
        "；".join(bad[:5]) if bad else "real 案例证据链可追溯，10 份模板与 CASE_FIELDS 同源")




def check_global_reference_limits():
    """全仓单篇 reference ≤400 行（不只十域）——审计 P1 的要求。"""
    bad = []
    files = glob.glob(os.path.join(TOOL, "skill", "**", "references", "*.md"), recursive=True)
    files = [f for f in files if os.path.isfile(f)]
    for f in sorted(files):
        n = len(lines(f))
        if n > LIMITS["ref_max"]:
            bad.append("%s %d 行 > %d" % (rel(f), n, LIMITS["ref_max"]))
    add("全局", "全仓单篇 reference ≤400 行（%d 篇）" % len(files), not bad,
        "；".join(bad[:6]) if bad else "全部合规（最大 %d 行）" % max(
            [len(lines(f)) for f in files] or [0]))



def check_criteria_backing(dom, spec):
    """判据字段必须至少有一个能被脚本真实输出（不是全都靠人填）。"""
    ref = os.path.join(TOOL, "skill", spec["skill"], "references", "01-criteria.md")
    if not os.path.isfile(ref):
        add(dom, "判据字段脚本背书（≥1）", False, "缺 01-criteria.md")
        return
    txt = open(ref, encoding="utf-8", errors="replace").read()
    fields = set(re.findall(r"`([a-z][a-z0-9_]{2,}(?:\.[a-z0-9_]+)*)`", txt))
    src = ""
    sd = os.path.join(TOOL, "skill", spec["skill"], "scripts")
    for f in sorted(glob.glob(os.path.join(sd, "*.py"))):
        src += open(f, encoding="utf-8", errors="replace").read()
    backed = [f for f in fields if f.split(".")[-1] in src]
    add(dom, "判据字段脚本背书（≥1）", bool(backed),
        "%d/%d 字段被脚本输出（例：%s）" % (len(backed), len(fields), ", ".join(sorted(backed)[:3]) or "-"))


def check_2026_presence(dom, spec):
    """2026 基线：该域 reference 或 KB 板至少要有一处 2026 内容（防止知识库整体过期）。"""
    hits = []
    for f in glob.glob(os.path.join(TOOL, "skill", spec["skill"], "references", "*.md")):
        if "2026" in open(f, encoding="utf-8", errors="replace").read():
            hits.append(os.path.basename(f))
    board = os.path.join(KBROOT, spec["board"])
    for f in glob.glob(os.path.join(board, "**", "*.md"), recursive=True):
        if "2026" in open(f, encoding="utf-8", errors="replace").read():
            hits.append("kb:" + os.path.basename(f))
    add(dom, "2026 基线内容在场", bool(hits), "命中 %d 处（例：%s）" % (len(hits), ", ".join(hits[:2]) or "-"))


def check_mutation_test():
    """反例回归：在临时副本上改 sha256 / timeframe / 只读声明，门禁必须变红。"""
    import shutil
    import tempfile
    tmp = tempfile.mkdtemp(prefix="seep-mut-")
    try:
        dst = os.path.join(tmp, "Tool", "cases", "web-pentest99")
        os.makedirs(os.path.join(dst, "artifacts"), exist_ok=True)
        art = os.path.join(dst, "artifacts", "run.json")
        open(art, "w", encoding="utf-8", newline="\n").write('{"ok": true}\n')
        h = hashlib.sha256(open(art, "rb").read()).hexdigest()
        case = {
            "id": "web-pentest99", "domain": "web-pentest", "target_type": "本地夹具（教学）",
            "evidence_kind": "fixture", "protection": [], "authority": "local",
            "goal_level": "L1", "outcome": "partial",
            "artifacts": [{"path": "artifacts/run.json", "sha256": h}],
            "lessons": ["夹具；命令：python x.py；rc=0"], "refs": [],
            "updated": "2026-10-22",
        }
        cf = os.path.join(dst, "case.json")
        json.dump(case, open(cf, "w", encoding="utf-8"))
        ok_clean = _case_errors(dst) == []
        bad = dict(case)
        bad["artifacts"] = [{"path": "artifacts/run.json", "sha256": "0" * 64}]
        json.dump(bad, open(cf, "w", encoding="utf-8"))
        ok_sha = _case_errors(dst) != []
        case2 = dict(case, timeframe={"start": "2026-10-21T00:00:00Z", "end": "2026-10-21T00:01:00Z"})
        case2["artifacts"] = case["artifacts"]
        json.dump(case2, open(cf, "w", encoding="utf-8"))
        tl = os.path.join(dst, "artifacts", "timeline.json")
        json.dump({"ok": True, "events": [{"time_utc": "2026-10-21T00:05:00Z", "kind": "evtx-record",
                                           "action": "x", "actor": "a", "object": "o"}]},
                  open(tl, "w", encoding="utf-8"))
        ok_tf = any("timeframe" in e for e in _case_errors(dst))
        add("全局", "变更反例回归（sha256/timeframe 必须红）", ok_clean and ok_sha and ok_tf,
            "clean=%s sha_red=%s tf_red=%s" % (ok_clean, ok_sha, ok_tf))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _case_errors(cd):
    """在临时副本上复用 check_cases 的核心字段/哈希/时间线断言（不写 results）。"""
    errs = []
    c = rj(os.path.join(cd, "case.json"))
    for art in c.get("artifacts") or []:
        p = os.path.join(cd, art.get("path", ""))
        if not os.path.isfile(p):
            errs.append("phantom")
        elif sha256(p) != str(art.get("sha256")).lower():
            errs.append("sha256")
    tlf = os.path.join(cd, "artifacts", "timeline.json")
    if os.path.isfile(tlf):
        tl = rj(tlf)
        evs = tl.get("events") or []
        if evs:
            latest = max(str(e.get("time_utc")) for e in evs)
            end = str((c.get("timeframe") or {}).get("end") or "")
            if end and not latest.startswith(end[:19]):
                errs.append("timeframe")
    return errs


# ---------------------------------------------------------------- [9] routing
def _match_route(routes, priority, text, fallback=None):
    """与 master-route.ps1 完全同语义：priority 顺序取第一个命中的域。

    三条语义必须与执行器一致（2026-10-21 审计 P0 的教训：门禁和执行器各一套语义 =
    门禁绿、运行时红）：
      1. 只有 mustAll、没有 must 的规则**有效**（从真起判）；
      2. exclude 命中即本条规则失效；
      3. fallback（R0）不参与竞争，只有全不命中时才用它。
    """
    for rid in priority:
        if fallback and rid == fallback:
            continue
        r = routes.get(rid) or {}
        for kw in r.get("keywords") or []:
            must = kw.get("must")
            alls = kw.get("mustAll") or []
            if not must and not alls:
                continue
            ok = bool(re.search(must, text)) if must else True
            if ok and alls:
                ok = all(re.search(a, text) for a in alls)
            if ok and kw.get("exclude") and re.search(kw["exclude"], text):
                ok = False
            if ok:
                return rid, (r.get("skill") or "")
    if fallback:
        return fallback, ((routes.get(fallback) or {}).get("skill") or "")
    return None, ""


def check_routing():
    rp = os.path.join(TOOL, "scripts", "routing.json")
    try:
        d = rj(rp)
    except Exception as e:  # noqa: BLE001
        add("全局", "路由串味测试集", False, "routing.json 坏:" + str(e)[:40])
        return
    routes, prio = d.get("routes") or {}, d.get("priority") or []
    fallback = (d.get("meta") or {}).get("fallbackId")
    bad = []
    for t in ROUTING_TESTS:
        rid, skill = _match_route(routes, prio, t["text"], fallback)
        got = (skill.split("/")[0] if skill else (rid or "None"))
        if got not in (t.get("expect_any") or []):
            bad.append("『%s』→ %s（期望 %s）" % (t["text"][:24], got,
                                             "/".join(t.get("expect_any") or [])))
        if got in (t.get("forbid") or []):
            bad.append("『%s』误命中 %s" % (t["text"][:20], got))
    add("全局", "路由串味测试集（%d 条）" % len(ROUTING_TESTS), not bad,
        "；".join(bad) if bad else "全部命中期望域，无跨域误命中")


# ---------------------------------------------------------------- [10] 清理
def check_cleanup():
    bad = []
    # 根目录 md allowlist（DOMAIN-SPEC §11）：人读入口 + 宿主直接读取的 agent 契约。
    # 契约（DOMAIN-SPEC §11）：根目录只允许 README*/ROADMAP。
    # 过程文档→work/plans，提示词→Tool/prompts/sources，agent 契约→Tool/prompts/contracts。
    allow_root = {"README.md", "README.zh.md", "README.en.md", "ROADMAP.md"}
    for f in sorted(glob.glob(os.path.join(ROOT, "*.md"))):
        b = os.path.basename(f)
        if b.startswith("优化方案"):
            bad.append("根目录残留过程文档 " + b)
        elif b not in allow_root:
            bad.append("根目录出现未登记的 md：%s（过程文档→work/plans，提示词→Tool/prompts/sources）" % b)
    rm = os.path.join(ROOT, "ROADMAP.md")
    if not os.path.isfile(rm):
        bad.append("缺 ROADMAP.md")
    elif len(lines(rm)) > LIMITS["roadmap_max"]:
        bad.append("ROADMAP.md %d 行 > %d" % (len(lines(rm)), LIMITS["roadmap_max"]))
    ap = os.path.join(ROOT, "docs", "AUDIT.md")
    if not os.path.isfile(ap):
        bad.append("缺 docs/AUDIT.md")
    else:
        t = "\n".join(lines(ap))
        # 只把「整行就是待填」当空台账；审计正文里引用这个词（说明历史缺陷）不算。
        if any(ln.strip().startswith("待填") for ln in t.splitlines()):
            bad.append("docs/AUDIT.md 仍有『待填』占位行——空台账不算审计")
        for k in ("R1", "R2", "R3", "R4"):
            if "## " + k not in t:
                bad.append("docs/AUDIT.md 缺 %s 结论" % k)
                continue
            seg = t.split("## " + k, 1)[1][:4000]
            if not any(x in seg for x in ("证据", "处置", "判定")):
                bad.append("docs/AUDIT.md 的 %s 无证据/判定/处置行" % k)
    add("全局", "仓库清理（无过程文档 / ROADMAP / AUDIT）", not bad,
        "；".join(bad) if bad else "根目录干净，ROADMAP/AUDIT 就位")


# ---------------------------------------------------------------- [11] 部署
def check_deploy(only=None):
    agent = os.path.join(os.path.expanduser("~"), ".pi", "agent", "skills")
    if not os.path.isdir(agent):
        add("全局", "部署哈希一致", False, "未找到 ~/.pi/agent/skills（先跑 setup/install-pi.ps1）")
        return
    bad = []
    for dom, spec in DOMAINS.items():
        if only and dom != only:
            continue
        src = os.path.join(TOOL, "skill", spec["skill"])
        dst = os.path.join(agent, spec["skill"])
        if not os.path.isdir(dst):
            bad.append("%s(未部署)" % spec["skill"])
            continue
        for dp, dn, fn in os.walk(src):
            dn[:] = [x for x in dn if x not in ("__pycache__",)]
            for f in fn:
                if os.path.splitext(f)[1].lower() not in (".md", ".py", ".json"):
                    continue
                s = os.path.join(dp, f)
                t = os.path.join(dst, os.path.relpath(s, src))
                if not os.path.isfile(t):
                    bad.append("%s(缺 %s)" % (spec["skill"], os.path.relpath(s, src)))
                elif sha256(s) != sha256(t):
                    bad.append("%s(%s 哈希不一致)" % (spec["skill"], os.path.relpath(s, src)))
    add("全局", "部署哈希一致（仓库 ↔ ~/.pi/agent/skills）", not bad,
        "；".join(bad[:6]) + ("…" if len(bad) > 6 else "") if bad
        else "十域 SKILL/references/scripts 哈希一致")



# ---------------------------------------------------------------- [12] 片段合入
def check_fragments():
    """路由片段必须已合入 SSOT（routing.json）——判定交给 merge-routing-fragment.py。

    单一实现：片段↔SSOT 的比较（含 mustAll/note）只在合并器里写一次，
    门禁只调用它，避免"门禁只看 must、看不到 mustAll"这类盲区。
    """
    mg = os.path.join(TOOL, "scripts", "merge-routing-fragment.py")
    if not os.path.isfile(mg):
        add("全局", "路由片段已合入 SSOT（routing.json）", False, "缺 merge-routing-fragment.py")
        return
    try:
        r = subprocess.run([sys.executable, mg, "--check"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120, cwd=ROOT)
    except Exception as e:  # noqa: BLE001
        add("全局", "路由片段已合入 SSOT（routing.json）", False, str(e)[:80])
        return
    out = (r.stdout or "").strip().splitlines()
    bad = [x.replace("[FAIL] ", "") for x in out if x.startswith("[FAIL]")]
    add("全局", "路由片段已合入 SSOT（routing.json）", r.returncode == 0,
        "；".join(bad[:5]) if bad else "%d 份片段与 SSOT 一致" % len([x for x in out if x.startswith("[OK]")]))


# ---------------------------------------------------------------- [13] 案例索引
def check_case_index():
    p = os.path.join(TOOL, "scripts", "gen-case-index.py")
    if not os.path.isfile(p):
        add("全局", "案例索引与磁盘一致", False, "缺 gen-case-index.py")
        return
    try:
        r = subprocess.run([sys.executable, p, "--check"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120, cwd=ROOT)
        ok = r.returncode == 0
        tail = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
        add("全局", "案例索引与磁盘一致（index.json）", ok, tail[-1][:100] if tail else "")
    except Exception as e:  # noqa: BLE001
        add("全局", "案例索引与磁盘一致（index.json）", False, str(e)[:80])


# ---------------------------------------------------------------- main
def check_spec():
    """契约漂移：SPEC 文档行数/条数与 domain_spec.py 是否明显不一致。"""
    p = os.path.join(ROOT, "docs", "DOMAIN-SPEC-v2.md")
    bad = []
    if not os.path.isfile(p):
        bad.append("缺 docs/DOMAIN-SPEC-v2.md")
    else:
        t = "\n".join(lines(p))
        for k in ("600", "400", "6–10", "20–30"):
            if k not in t:
                bad.append("SPEC 缺关键数字 " + k)
    for dom in DOMAINS:
        if dom not in (open(p, encoding="utf-8", errors="replace").read() if os.path.isfile(p) else ""):
            bad.append("SPEC 未提及域 " + dom)
    add("全局", "契约未漂移（SPEC ↔ domain_spec.py）", not bad, "；".join(bad) if bad else "10 域覆盖")


def main():
    ap = argparse.ArgumentParser(description="领域深度门禁（九件套 2.0）")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--domain", action="append", default=[])
    ap.add_argument("--links", action="store_true")
    ap.add_argument("--routing", action="store_true")
    ap.add_argument("--cleanup", action="store_true")
    ap.add_argument("--deploy", action="store_true")
    ap.add_argument("--spec", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    only = a.domain[0] if a.domain else None
    if not any([a.all, a.domain, a.links, a.routing, a.cleanup, a.deploy, a.spec]):
        a.all = True
    if a.domain:
        unknown = [d for d in a.domain if d not in DOMAINS]
        if unknown:
            print("[FAIL] 未知域：%s（可用：%s）" % (",".join(unknown), ",".join(DOMAINS)))
            return 2
    if a.all or a.domain:
        check_spec()
        for dom, spec in DOMAINS.items():
            if a.domain and dom not in a.domain:
                continue
            if not spec.get("skill") or not os.path.isdir(os.path.join(TOOL, "skill", spec["skill"])):
                add(dom, "技能目录", False, "缺失 Tool/skill/" + str(spec.get("skill")))
                continue
            check_skill(dom, spec)
            check_refs(dom, spec)
            check_scripts(dom, spec)
            check_cases(dom, spec)
            check_kb(dom, spec)
            check_matrix(dom, spec)
            check_cards(dom, spec)
            check_criteria_backing(dom, spec)
            check_2026_presence(dom, spec)
    if a.all or a.links:
        check_links()
        check_md_links()
        check_repro_and_templates()
        check_global_reference_limits()
        check_mutation_test()
        check_fragments()
        check_case_index()
    if a.all or a.routing:
        check_routing()
    if a.all or a.cleanup:
        check_cleanup()
    if a.all or a.deploy:
        check_deploy(only)
    fails = [r for r in results if not r["ok"]]
    if a.json:
        print(json.dumps({"results": results, "fails": len(fails)}, ensure_ascii=False, indent=2))
    else:
        cur = ""
        for r in results:
            if r["domain"] != cur:
                cur = r["domain"]
                print("\n[%s]" % cur)
            print("  [%s] %s%s" % ("PASS" if r["ok"] else "FAIL", r["name"],
                                   ("  — " + r["detail"]) if r["detail"] else ""))
        print("\n结果: %d/%d 通过%s" % (len(results) - len(fails), len(results),
                                       "" if not fails else "  ← 有 FAIL"))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
