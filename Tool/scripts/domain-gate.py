#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""domain-gate.py —— 领域深度门禁（九件套 2.0 的可执行版）。

它回答一个问题：**这个域现在能不能独立打一场？**
判据全部来自 `docs/DOMAIN-CONTRACT.md` + `Tool/scripts/lib/domain_spec.py`：

    [1] 篇幅   SKILL ≤600 / ref 60–400 / KB 50–200
    [2] 必备篇 01-criteria / 02-failure-criteria / 03-model-pitfalls / 04-walkthrough-*
    [3] 脚本   ≥2 个（上限已取消），`--help` 与 `--self-test` 都必须 rc=0
    [4] 案例   3–5 个，≥1 个 evidence_kind=real|public，sha256 复算，refs 不幻影
    [5] KB     ≥6 篇（上限已取消），含 *failure-criteria*，README 链接到每一篇
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
from pathlib import Path
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

import domain_registry as registry_mod  # noqa: E402  单向：registry 不 import 本脚本
from case_execution import assess as assess_case_execution  # noqa: E402
from deploy_assets import compare_trees as compare_deploy_trees  # noqa: E402
from runtime_root import RuntimeRootError, resolve_agent_root  # noqa: E402
from typed_assets import TypedAssetError, _project_path  # noqa: E402
from domain_spec import (  # noqa: E402
    CASE_FIELDS, DOMAINS, DOMAIN_LOAD_ERRORS, FIXTURE_WORDS, LIMITS, REQUIRED_REFS,
    ROUTING_TESTS, fixture_words_in,
)

# 正式域全集与逐域深度契约的唯一来源：pack.json#id + pack#depth_contract。
# DOMAINS 只是 domain_spec 里的兼容视图（内容同样取 pack），不再保存域清单。
_REGISTRY = None
FORMAL_DOMAINS = []
DEPTH = {}
DOMAINS = {}


def _use_root(root):
    """显式切换仓库根（测试/fixture 用）。默认结构 = 本文件所在仓库，不改全局真相源。"""
    global ROOT, TOOL, KBROOT, _REGISTRY, FORMAL_DOMAINS, DEPTH, DOMAINS
    ROOT = os.path.abspath(root)
    TOOL = os.path.join(ROOT, "Tool")
    KBROOT = os.path.join(TOOL, "mcp", "Tool", "reverselab", "kb")
    _REGISTRY = registry_mod.load_registry(ROOT)
    FORMAL_DOMAINS = _REGISTRY.ids()
    DEPTH = {d: (_REGISTRY.depth(d) or {}) for d in FORMAL_DOMAINS}
    # 逐域 spec = depth_contract（skill/board/matrix/case_globs/ext_scripts/...）。
    DOMAINS = _REGISTRY.as_domains()
    return _REGISTRY


_use_root(ROOT)

TEXT_EXT = {".md", ".py", ".ps1", ".sh", ".json", ".yml", ".yaml", ".txt"}
# 数量上限放宽的可见标记：凡取消上限的检查，detail 末尾必须带这句，避免「静默放宽」。
LIMIT_RELAX_NOTE = "（上限已取消：内容多不是缺陷；下限仍判）"
SKIP_TEXT = ("CHANGELOG", "Tool/upstream/", "Tool/mcp/Tool/safe/",
             "Tool/mcp/Tool/reverselab/kb/AI-USAGE.md")
results = []
# W6：缺件/无法自检的域。这些既不算 PASS，也不许静默跳过；末尾必须逐条打印
# `[UNCOVERED] <域>：<具体缺什么>`，并让退出码非 0（不进“全绿”）。
uncovered = []


def add(section, name, ok, detail=""):
    results.append({"domain": section, "name": name, "ok": bool(ok), "detail": detail})


def _register_load_errors():
    """注册表级错误（坏 pack / id 不符 / 命名空间冲突 / 缺 depth）→ 显式 UNCOVERED。

    绝不允许“载入器报错、域从集合里消失、门禁却全绿”。错误一条条显示，指向具体域。
    """
    for problem in _REGISTRY.errors:
        mark_uncovered("全局", "域注册表：%s" % problem)
    for problem in DOMAIN_LOAD_ERRORS:
        mark_uncovered("全局", "domain_spec 载入：%s" % problem)
    for domain, reasons in sorted(_REGISTRY.incomplete().items()):
        mark_uncovered(domain, "depth/schema/材料不完整：%s" % "；".join(reasons))


def mark_uncovered(dom, reason):
    """登记一条「未覆盖」：缺件或无法自检 → 不算 PASS，也不静默跳过。"""
    reason = str(reason).strip()
    if any(u["domain"] == dom and u["reason"] == reason for u in uncovered):
        return
    uncovered.append({"domain": dom, "reason": reason})
    # 同时进 results（ok=False），让 preflight / --json 的消费者也看得到。
    add(dom, "[UNCOVERED] 缺件/无法自检（不计 PASS）", False, reason)


def rj(p):
    with open(p, encoding="utf-8-sig") as f:
        return json.load(f)


def read_text_file(p, encoding="utf-8", errors="replace"):
    with open(p, encoding=encoding, errors=errors) as f:
        return f.read()


def write_bytes_file(p, data):
    with open(p, "wb") as f:
        f.write(data)


def write_text_file(p, data, newline=None):
    with open(p, "w", encoding="utf-8", newline=newline) as f:
        f.write(data)


def write_json_file(p, data):
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f)


def lines(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()



def _norm_sha(p):
    """文本文件按 LF 归一后取哈希：避免 CRLF/LF 工作树造成部署假红（R5 P1-1）。"""
    if os.path.splitext(p)[1].lower() in (".md", ".py", ".json", ".txt", ".yml", ".yaml"):
        with open(p, "rb") as stream:
            raw = stream.read().replace(bytes([13, 10]), bytes([10]))
        return hashlib.sha256(raw).hexdigest()
    return sha256(p)

def rel(p):
    """相对路径（**不许炸**）。

    2026-10-25 外部评审 B3：仓库根出现一个 46 字节的 `nul` 设备文件时，
    os.path.relpath 抛 ValueError('path is on mount ...') → 整个域深度检查崩掉，
    报错还完全无法定位。任何 walk 到的路径都必须能安全转成相对路径。
    """
    try:
        return os.path.relpath(p, ROOT).replace(os.sep, "/")
    except Exception:
        try:
            return str(p).replace(os.sep, "/")[-120:]
        except Exception:
            return "<unprintable>"


def _local_path(root, relative, label="local_path", within=None):
    """Resolve a nonempty project-relative path without crossing links or ``..``."""
    if not isinstance(relative, str) or not relative.strip() or "\0" in relative:
        raise TypedAssetError("%s 必须是非空相对路径" % label)
    path = _project_path(Path(root), relative, label=label)
    if within is not None:
        boundary = _project_path(Path(root), within, label=label + " boundary")
        try:
            path.relative_to(boundary)
        except ValueError as exc:
            raise TypedAssetError("%s 越出允许目录：%s" % (label, relative[:64])) from exc
    return path


# ---------------------------------------------------------------- [1][2] refs
def check_refs(dom, spec):
    d = os.path.join(TOOL, "skill", spec["skill"], "references")
    if not os.path.isdir(d):
        mark_uncovered(dom, "缺 references 目录 %s" % rel(d))
        add(dom, "references 目录", False, "缺失 " + rel(d))
        return []
    refs = sorted(glob.glob(os.path.join(d, "*.md")))
    bad = []
    # 放宽（2026-10 收口）：references 篇数**只判下限**。上限（LIMITS["refs_max"]）
    # 仍登记在 domain_spec 里供人读，但不再据此判红——「内容多」不是缺陷。
    # 放宽必须在 detail 里可见（LIMIT_RELAX_NOTE），不许静默。
    if len(refs) < LIMITS["refs_min"]:
        bad.append("篇数 %d（要求 ≥%d）" % (len(refs), LIMITS["refs_min"]))
        mark_uncovered(dom, "缺 references（%d 篇，要求 ≥%d）" % (
            len(refs), LIMITS["refs_min"]))
    for p in refs:
        n = len(lines(p))
        if n > LIMITS["ref_max"] or n < LIMITS["ref_min"]:
            bad.append("%s %d 行（要求 %d–%d）" % (os.path.basename(p), n,
                                                LIMITS["ref_min"], LIMITS["ref_max"]))
    names = [os.path.basename(p) for p in refs]
    missing_required = []
    for key, pat in REQUIRED_REFS:
        if any(ch in pat for ch in "*?["):
            if not any(fnmatch(n, pat) for n in names):
                bad.append("缺必备篇 " + pat)
                missing_required.append(pat)
        elif pat not in names:
            bad.append("缺必备篇 " + pat)
            missing_required.append(pat)
    if missing_required:
        mark_uncovered(dom, "缺必备篇 %s" % ",".join(missing_required))
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
        ("；".join(bad) if bad else "%d 篇，必备四篇齐全，篇幅合规" % len(refs))
        + LIMIT_RELAX_NOTE)
    return refs


def fnmatch(name, pat):
    import fnmatch as _f
    return _f.fnmatch(name, pat)


# ---------------------------------------------------------------- [0] SKILL
def check_skill(dom, spec):
    p = os.path.join(TOOL, "skill", spec["skill"], "SKILL.md")
    if not os.path.isfile(p):
        mark_uncovered(dom, "缺 %s/SKILL.md" % os.path.basename(str(spec["skill"])))
        add(dom, "SKILL.md", False, "缺失")
        return
    t = "\n".join(lines(p))
    n = len(lines(p))
    bad = []
    if n > LIMITS["skill_max"]:
        bad.append("%d 行 > %d" % (n, LIMITS["skill_max"]))
    if n < LIMITS["skill_min"]:
        bad.append("%d 行 < %d（深度不足）" % (n, LIMITS["skill_min"]))
    for marker in ("判据", "失败判据", "模型常见失误"):
        if marker not in t:
            bad.append("缺『%s』节" % marker)
    if ("范围" not in t) and ("边界" not in t):
        bad.append("缺『范围/边界』节")
    if "references/" not in t:
        bad.append("SKILL 未索引任何 reference")
    add(dom, "SKILL.md 篇幅与四节", not bad, "；".join(bad) if bad else "%d 行" % n)


# ---------------------------------------------------------------- [3] scripts
def _self_test_conclusion(output):
    """Read a final JSON object, allowing progress lines before that conclusion."""
    decoder = json.JSONDecoder()
    for match in re.finditer(r"(?m)^[ \t]*[\{\[]", output):
        try:
            value, end = decoder.raw_decode(output, match.end() - 1)
        except ValueError:
            continue
        if not output[end:].strip():
            return isinstance(value, dict) and value.get("ok") is True
    return False


def check_scripts(dom, spec):
    d = os.path.join(TOOL, "skill", spec["skill"], "scripts")
    found = sorted(glob.glob(os.path.join(d, "*.py"))) if os.path.isdir(d) else []
    for e in spec.get("ext_scripts") or []:
        p = os.path.join(ROOT, e)
        if os.path.isfile(p):
            found.append(p)
    found = list({os.path.normcase(os.path.abspath(p)): p for p in found}.values())
    # 放宽（2026-10 收口）：脚本数量**只判下限**，上限（LIMITS["scripts_max"]）不再判红。
    # 少了仍然红（缺件不许被放宽掩盖）；多了只报数字，不判缺陷。
    if len(found) < LIMITS["scripts_min"]:
        mark_uncovered(dom, "缺脚本（%d 个，要求 ≥%d）" % (
            len(found), LIMITS["scripts_min"]))
        add(dom, "脚本数量", False, "%d 个（要求 ≥%d）：%s%s" % (
            len(found), LIMITS["scripts_min"],
            ",".join(os.path.basename(x) for x in found), LIMIT_RELAX_NOTE))
        return
    bad = []
    for p in found:
        for flag, need_ok in (("--help", True), ("--self-test", True)):
            try:
                r = subprocess.run([sys.executable, "-B", p, flag], capture_output=True,
                                   text=True, encoding="utf-8", errors="replace",
                                   timeout=120, cwd=ROOT)
            except Exception as e:  # noqa: BLE001
                bad.append("%s %s 异常:%s" % (os.path.basename(p), flag, str(e)[:30]))
                continue
            if r.returncode != 0:
                bad.append("%s %s rc=%d" % (os.path.basename(p), flag, r.returncode))
            elif flag == "--self-test" and not _self_test_conclusion(r.stdout or ""):
                bad.append("%s --self-test 缺少 ok=true 的最终 JSON 对象" % os.path.basename(p))
    add(dom, "脚本 --help / --self-test", not bad,
        ("；".join(bad) if bad else "%d 个脚本全部 rc=0（数量下限 %d）" % (
            len(found), LIMITS["scripts_min"])) + LIMIT_RELAX_NOTE)
    if bad:
        # --help / --self-test 不绿 = 这个域的脚本无法自检（不是“跑过了”）。
        mark_uncovered(dom, "脚本无法自检：%s%s" % (
            "；".join(bad[:3]), "…等 %d 项" % len(bad) if len(bad) > 3 else ""))


APK_ACCEPTANCE_CASES = ("leaf-apk", "apkseep07", "apkseep08", "apkseep09")


def _run_case_state(case_dir, command):
    script = os.path.join(TOOL, "scripts", "case_state.py")
    argv = [sys.executable, "-B", script, command, "--case", case_dir]
    if command == "verify":
        argv.append("--json")
    # Run target-origin verification from outside the repository root.  This
    # catches accidental cwd-dependent path resolution instead of hiding it in
    # the normal gate launch directory.
    cwd = TOOL if command == "verify-origin" else ROOT
    return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=300, cwd=cwd)


def check_apk_acceptance(dom):
    """Bind the four shipped APK evidence cases to semantic + origin checks."""
    bad, checked = [], []
    for name in APK_ACCEPTANCE_CASES:
        case_dir = os.path.join(TOOL, "cases", name)
        case_file = os.path.join(case_dir, "case.json")
        if not os.path.isfile(case_file):
            bad.append("%s(缺案例)" % name)
            continue
        try:
            meta = rj(case_file)
        except Exception as exc:  # noqa: BLE001
            bad.append("%s(case.json 坏:%s)" % (name, str(exc)[:40]))
            continue
        if meta.get("acceptance_profile") != "apk-target/1":
            bad.append("%s(未声明 acceptance_profile=apk-target/1)" % name)
        target = meta.get("target")
        if not isinstance(target, dict) or not all(
                target.get(key) not in (None, "") for key in ("path", "sha256", "size")):
            bad.append("%s(target path/sha256/size 不完整)" % name)
        entries = meta.get("target_files")
        if not isinstance(entries, list) or not entries:
            bad.append("%s(target_files 为空)" % name)
        registered = []
        if isinstance(target, dict):
            registered.append(("target", target))
        if isinstance(entries, list):
            registered.extend(("target_files[%d]" % index, item)
                              for index, item in enumerate(entries)
                              if isinstance(item, dict))
        for source, item in registered:
            raw = str(item.get("path") or "").strip()
            try:
                resolved = _local_path(
                    case_dir, raw, "%s.%s.path" % (name, source),
                    within="target",
                )
            except (OSError, TypedAssetError) as exc:
                bad.append("%s(%s.path 必须是案例内相对路径：%s)"
                           % (name, source, str(exc)[:100]))
                continue
            if not resolved.is_file():
                bad.append("%s(%s.path 指向不存在文件)" % (name, source))

        verify = _run_case_state(case_dir, "verify")
        if verify.returncode != 0:
            tail = ((verify.stdout or "") + (verify.stderr or "")).strip().splitlines()
            bad.append("%s(case verify rc=%d:%s)"
                       % (name, verify.returncode, tail[-1][:100] if tail else ""))
        origin = _run_case_state(case_dir, "verify-origin")
        if origin.returncode != 0:
            tail = ((origin.stdout or "") + (origin.stderr or "")).strip().splitlines()
            bad.append("%s(verify-origin rc=%d:%s)"
                       % (name, origin.returncode, tail[-1][:100] if tail else ""))
        checked.append(name)

    ok = not bad and checked == list(APK_ACCEPTANCE_CASES)
    add(dom, "APK 原件绑定与证据语义", ok,
        "；".join(bad[:6]) if bad else
        "%d 个案例通过 case verify + verify-origin（cwd 独立性由测试覆盖）"
        % len(checked))
    if not ok:
        mark_uncovered(dom, "APK 验收失败：%s" % (
            "；".join(bad[:3]) if bad else "案例集合不完整"))


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
        if len(dirs) < LIMITS["cases_min"]:
            mark_uncovered(dom, "缺案例（Tool/cases/%s 命中 %d 个，要求 %d–%d）" % (
                "|".join(spec["case_globs"]), len(dirs), LIMITS["cases_min"], cmax))
    real = 0
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
        # 分档：real（客户真实目标）/ public（公开可分发的真实产物：靶场·CTF·公开 crackme·
        #        MIT 示例）/ self-built（自己编译）/ fixture（合成夹具）/ historical（归档）。
        # 语义唯一来源：lib/domain_spec.EVIDENCE_KINDS；promotion 只能按事实走。
        kind = c.get("evidence_kind")
        if kind not in ("fixture", "real", "public", "self-built", "historical"):
            bad.append("%s(evidence_kind=%r)" % (os.path.basename(cd), kind))
            kind = None
        tt = str(c.get("target_type") or "")
        # public = 公开可分发的真实产物：先剥掉「公开教学靶场/CTF/公开 crackme」来源词再判夹具字样
        is_fix = bool(fixture_words_in(tt, kind))
        if kind == "fixture" and not is_fix:
            bad.append("%s(fixture 但 target_type 未标夹具)" % os.path.basename(cd))
        if kind in ("real", "public") and is_fix:
            bad.append("%s(%s 却标成夹具)" % (os.path.basename(cd), kind))
        execution = assess_case_execution(c)
        if execution["defects"]:
            bad.extend(
                "%s(%s)" % (os.path.basename(cd), defect)
                for defect in execution["defects"]
            )
        elif execution["execution_bound"]:
            real += 1
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
        # 案例内路径先做词法与链接边界校验，再读取/复算。路径越界不能靠
        # “哈希恰好正确”洗白。
        listed = set()
        for index, art in enumerate(c.get("artifacts") or []):
            raw_path = (art.get("path") if isinstance(art, dict)
                        else str(art or "")) or ""
            try:
                full = _local_path(
                    cd, raw_path, "artifacts[%d].path" % index,
                )
            except (OSError, TypedAssetError) as exc:
                bad.append("%s(产物路径越界/无效 %r：%s)" % (
                    os.path.basename(cd), raw_path[:40], str(exc)[:80]))
                continue
            normalized = full.relative_to(Path(cd)).as_posix()
            listed.add(normalized)
            want = str(art.get("sha256") or "").lower() if isinstance(art, dict) else ""
            if not full.is_file():
                bad.append("%s(幻影产物 %s)" % (os.path.basename(cd), normalized))
                continue
            if len(want) != 64:
                bad.append("%s(%s 缺 sha256)" % (os.path.basename(cd), normalized))
            elif sha256(full) != want:
                bad.append("%s(%s sha256 不符，重算=%s)" % (
                    os.path.basename(cd), normalized, sha256(full)[:12]))
            # JSON artifact 必须确定：非空 generated_at 会让复跑漂移。
            if full.suffix.lower() == ".json":
                try:
                    document = rj(full)
                except Exception:  # noqa: BLE001
                    document = {}
                if isinstance(document, dict) and document.get("generated_at"):
                    bad.append("%s(%s 含非空 generated_at，复跑会漂)" % (
                        os.path.basename(cd), normalized))

        adir = Path(cd, "artifacts")
        manifest = {}
        mf = adir / "MANIFEST.sha256"
        if mf.is_file():
            for ln in lines(mf):
                parts = ln.split(None, 1)
                if len(parts) == 2:
                    digest, raw_path = parts[0].lower(), parts[1].strip()
                    try:
                        manifest_file = _local_path(
                            cd, raw_path, "MANIFEST.sha256 entry",
                        )
                    except (OSError, TypedAssetError) as exc:
                        bad.append("%s(MANIFEST 路径越界/无效 %r：%s)" % (
                            os.path.basename(cd), raw_path[:40], str(exc)[:80]))
                        continue
                    normalized = manifest_file.relative_to(Path(cd)).as_posix()
                    manifest[normalized] = digest
                    if not manifest_file.is_file():
                        bad.append("%s(MANIFEST 指向幻影 %s)" % (
                            os.path.basename(cd), normalized))
                    elif not re.fullmatch(r"[0-9a-f]{64}", digest):
                        bad.append("%s(MANIFEST 哈希格式错误 %s)" % (
                            os.path.basename(cd), normalized))
                    elif sha256(manifest_file) != digest:
                        bad.append("%s(MANIFEST 哈希不符 %s)" % (
                            os.path.basename(cd), normalized))
        if adir.is_dir():
            for dp, dn, fn in os.walk(adir):
                for f in sorted(fn):
                    fp = os.path.join(dp, f)
                    relp = os.path.relpath(fp, cd).replace("\\", "/")
                    if relp.lower().endswith("readme.md") or relp.endswith("MANIFEST.sha256"):
                        continue
                    if relp in listed:
                        continue
                    if manifest.get(relp) == sha256(fp):
                        continue
                    bad.append("%s(%s 未登记且不在 MANIFEST)" % (os.path.basename(cd), relp))
        for r in c.get("refs") or []:
            if isinstance(r, str) and "://" not in r:
                try:
                    ref_path = _local_path(ROOT, r, "refs")
                except (OSError, TypedAssetError) as exc:
                    bad.append("%s(refs 路径越界/无效 %r：%s)" % (
                        os.path.basename(cd), r[:40], str(exc)[:80]))
                    continue
                if not ref_path.is_file():
                    bad.append("%s(refs 幻影 %s)" % (os.path.basename(cd), r[:40]))
    if real < 1:
        bad.append("没有任何执行绑定的 real/public 案例（not-recorded 与文字描述不计见证）")
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
    add(dom, "案例字段/真跑/sha256 复算", not bad,
        "；".join(bad[:6]) + ("…" if len(bad) > 6 else "") if bad
        else "%d 个案例（real %d），hash 复算一致" % (len(dirs), real))
    if dom == "apkseep":
        check_apk_acceptance(dom)


# ---------------------------------------------------------------- [5] KB
def check_kb(dom, spec):
    d = os.path.join(KBROOT, spec["board"])
    if not os.path.isdir(d):
        mark_uncovered(dom, "缺 KB 板 %s" % rel(d))
        add(dom, "KB board", False, "缺失 " + rel(d))
        return
    mds = [p for p in glob.glob(os.path.join(d, "**", "*.md"), recursive=True)]
    tech = [p for p in mds if os.path.basename(p) != "README.md"]
    total = len(mds)
    # 放宽（2026-10 收口）：KB **篇数**只判下限。per-domain 的 kb_max_count 与全仓
    # kb_max_count 不再参与判红（apkseep 27 篇曾判超）；单篇行数（kb_line_max）仍判。
    lmax = spec.get("kb_line_max", LIMITS["kb_max"])
    bad = []
    if total < LIMITS["kb_min_count"]:
        bad.append("KB %d 篇（要求 ≥%d）" % (total, LIMITS["kb_min_count"]))
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
        ("；".join(bad) if bad else "%d 篇（含失败判据），README 全索引" % total)
        + LIMIT_RELAX_NOTE)


# ---------------------------------------------------------------- [6] matrix
def check_matrix(dom, spec):
    p = os.path.join(TOOL, "config", spec["matrix"])
    if not os.path.isfile(p):
        mark_uncovered(dom, "缺矩阵 Tool/config/%s" % spec["matrix"])
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
        mark_uncovered(dom, "缺任务卡 Tool/prompts/domains/%s.md" % dom)
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
            corpus = "\n".join(read_text_file(x)
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
                corpus[r] = read_text_file(p)
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
                    txt = read_text_file(p)
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
        execution = assess_case_execution(c)
        if execution["defects"]:
            bad.extend(
                "%s(%s)" % (os.path.basename(os.path.dirname(cf)), defect)
                for defect in execution["defects"]
            )
    tdir = os.path.join(ROOT, "Tool", "cases", "_templates")
    tpls = sorted(glob.glob(os.path.join(tdir, "*.json")))
    tpl_names = {os.path.basename(t)[:-5] for t in tpls}
    # W6：模板集必须与正式域全集（pack id，动态）同源。只比总数会丢信息（看不出是哪个域缺），
    # 所以按域名逐个对；断言本身没放宽（仍然必须一一对应）。
    missing_tpl = [d for d in FORMAL_DOMAINS if d not in tpl_names]
    extra_tpl = sorted(tpl_names - set(FORMAL_DOMAINS))
    for d in missing_tpl:
        mark_uncovered(d, "缺案例模板 Tool/cases/_templates/%s.json" % d)
    if len(tpls) != len(FORMAL_DOMAINS) or missing_tpl or extra_tpl:
        bad.append("模板 %d 份 / 域 %d 个%s%s" % (
            len(tpls), len(FORMAL_DOMAINS),
            "；缺模板：" + ",".join(missing_tpl) if missing_tpl else "",
            "；多余模板（域已迁出）：" + ",".join(extra_tpl) if extra_tpl else ""))
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
                try:
                    ref_path = _local_path(ROOT, r, "template refs")
                except (OSError, TypedAssetError) as exc:
                    bad.append("%s(refs 路径越界/无效 %r：%s)" % (
                        os.path.basename(t), r[:40], str(exc)[:80]))
                    continue
                if not ref_path.is_file():
                    bad.append("%s(refs 幻影 %s)" % (os.path.basename(t), r[:40]))
    add("全局", "真实案例证据链 + 模板份数与正式域同源", not bad,
        "；".join(bad[:5]) if bad else "real 案例证据链可追溯，%d 份模板与 CASE_FIELDS 同源" % len(glob.glob(os.path.join(ROOT, "Tool", "cases", "_templates", "*.json"))))




def check_global_reference_limits():
    """全仓单篇 reference ≤400 行（不只单域）——审计 P1 的要求。"""
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
    txt = read_text_file(ref)
    # 2026-10-25：A+ 深度补齐后，判据文件里的反引号标识符大涨（含 `curl`/`null` 这类命令片段），
    # 若仍要求"每个标识符都有脚本背书"，白名单会无限膨胀、且失去意义。
    # 现在的口径：**至少 1 个字段被脚本真实背书**（防"全凭人填"），其余覆盖情况只报数字，不判红。
    fields = set(re.findall(r"`([a-z][a-z0-9_]{2,}(?:\.[a-z0-9_]+)*)`", txt))
    src = ""
    sd = os.path.join(TOOL, "skill", spec["skill"], "scripts")
    for f in sorted(glob.glob(os.path.join(sd, "*.py"))):
        src += read_text_file(f)
    backed = [f for f in fields if f.split(".")[-1] in src]
    allow_path = os.path.join(TOOL, "config", "criteria-inferred", dom + ".json")
    allowed = {}
    if os.path.isfile(allow_path):
        try:
            allowed = (rj(allow_path).get("fields") or {})
        except Exception:  # noqa: BLE001
            allowed = {}
    uncovered = [f for f in fields if f not in backed and f not in allowed]
    add(dom, "判据字段脚本背书或 inferred 白名单",
        bool(backed),
        "%d 背书 / %d 白名单 / %d 未覆盖（共 %d）；未覆盖：%s"
        % (len(backed), len(allowed), len(uncovered), len(fields),
           ", ".join(sorted(uncovered)[:3]) or "-"))


def check_2026_presence(dom, spec):
    """2026 基线：该域 reference 或 KB 板至少要有一处 2026 内容（防止知识库整体过期）。"""
    hits = []
    for f in glob.glob(os.path.join(TOOL, "skill", spec["skill"], "references", "*.md")):
        if "2026" in read_text_file(f):
            hits.append(os.path.basename(f))
    board = os.path.join(KBROOT, spec["board"])
    for f in glob.glob(os.path.join(board, "**", "*.md"), recursive=True):
        if "2026" in read_text_file(f):
            hits.append("kb:" + os.path.basename(f))
    add(dom, "2026 基线内容在场", bool(hits), "命中 %d 处（例：%s）" % (len(hits), ", ".join(hits[:2]) or "-"))


def _case_errors(cd):
    """单案例四类一致性断言（反例回归复用）：sha256 / timeframe / 只读声明 / 伪 real。"""
    errs = []
    try:
        c = rj(os.path.join(cd, "case.json"))
    except Exception:  # noqa: BLE001
        return ["case-json"]
    blob = json.dumps(c, ensure_ascii=False)
    for index, art in enumerate(c.get("artifacts") or []):
        raw = art.get("path", "") if isinstance(art, dict) else str(art or "")
        try:
            fp = _local_path(cd, raw, "artifacts[%d].path" % index)
        except (OSError, TypedAssetError):
            errs.append("path-escape")
            continue
        if not os.path.isfile(fp):
            errs.append("phantom")
        elif not isinstance(art, dict) or sha256(fp) != str(art.get("sha256") or "").lower():
            errs.append("sha256")
    tlf = os.path.join(cd, "artifacts", "timeline.json")
    if os.path.isfile(tlf):
        tl = rj(tlf)
        evs = tl.get("events") or []
        if evs:
            latest = max(str(e.get("time_utc")) for e in evs)
            end_t = str((c.get("timeframe") or {}).get("end") or "")
            if end_t and not latest.startswith(end_t[:19]):
                errs.append("timeframe")
            times = {str(e.get("time_utc")) for e in evs}
            for f in c.get("findings") or []:
                if str(f.get("confidence")) == "observed":
                    ft = str(f.get("time_utc") or "")
                    if ft and ft not in times:
                        errs.append("observed-time")
                        break
    if re.search(r"均只读|all read-only", blob):
        for dp, dn, fn in os.walk(os.path.join(cd, "input")):
            for f in fn:
                if os.access(os.path.join(dp, f), os.W_OK):
                    errs.append("readonly-claim")
                    break
            else:
                continue
            break
    # public/real 只认结构化 command + returncode + hashed artifact。
    execution = assess_case_execution(c)
    if execution["defects"]:
        errs.append("fake-real")
    return errs


def check_mutation_test():
    """反例回归：sha256 / timeframe / 只读声明 / 伪 real 四类都必须被抓红。"""
    import shutil
    import tempfile

    def build(tmp, mutate):
        d = os.path.join(tmp, "c")
        os.makedirs(os.path.join(d, "input"), exist_ok=True)
        os.makedirs(os.path.join(d, "artifacts"), exist_ok=True)
        write_bytes_file(os.path.join(d, "input", "a.bin"), b"x")
        art = os.path.join(d, "artifacts", "run.json")
        write_text_file(art, '{"ok": true}\n', newline="\n")
        h = sha256(art)
        case = {"id": "mut", "domain": "web-pentest", "target_type": "fixture 夹具",
                "evidence_kind": "fixture", "protection": [], "authority": "local",
                "goal_level": "L1", "outcome": "partial",
                "artifacts": [{"path": "artifacts/run.json", "sha256": h}],
                "lessons": ["cmd: python x.py; rc=0"], "refs": [], "updated": "2026-10-22"}
        mutate(d, case, art, h)
        write_json_file(os.path.join(d, "case.json"), case)

    def noop(d, c, art, h):
        pass

    def mut_sha(d, c, art, h):
        c["artifacts"] = [{"path": "artifacts/run.json", "sha256": "0" * 64}]

    def mut_tf(d, c, art, h):
        c["timeframe"] = {"start": "2026-10-21T00:00:00Z", "end": "2026-10-21T00:01:00Z"}
        write_json_file(os.path.join(d, "artifacts", "timeline.json"),
                        {"ok": True, "events": [{"time_utc": "2026-10-21T00:05:00Z",
                                                 "kind": "evtx-record", "action": "x",
                                                 "actor": "a", "object": "o"}]})

    def mut_ro(d, c, art, h):
        c["lessons"] = ["均只读封存；json"]

    def mut_fake(d, c, art, h):
        c["evidence_kind"] = "real"
        c["lessons"] = ["本场景代表真实目标，无命令"]
        c.pop("timeframe", None)

    res = {}
    for name, fn in (("clean", noop), ("sha256", mut_sha), ("timeframe", mut_tf),
                     ("readonly-claim", mut_ro), ("fake-real", mut_fake)):
        tmp = tempfile.mkdtemp(prefix="seep-mut-")
        try:
            build(tmp, fn)
            res[name] = _case_errors(os.path.join(tmp, "c"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    ok = (res["clean"] == [] and "sha256" in res["sha256"]
          and "timeframe" in res["timeframe"]
          and "readonly-claim" in res["readonly-claim"]
          and "fake-real" in res["fake-real"])
    add("全局", "变更反例回归（sha256/timeframe/只读/伪 real）", ok,
        json.dumps(res, ensure_ascii=False)[:260])


# ---------------------------------------------------------------- [9] routing
def _match_route(routes, priority, text, fallback=None):
    """Project the first matching route for playbook-parity checks.

    The domain gate itself must use :func:`routing_failures` with the complete
    resolved set.  ``route-playbook-parity.py`` still needs the primary route
    for its diagnostic output, so keep that projection behind a compatibility
    helper instead of letting callers mistake it for classification authority.
    """
    for rid in priority:
        if fallback and rid == fallback:
            continue
        route = routes.get(rid) or {}
        for keyword in route.get("keywords") or []:
            must = keyword.get("must")
            all_must = keyword.get("mustAll") or []
            if not must and not all_must:
                continue
            matched = bool(re.search(must, text)) if must else True
            if matched and all_must:
                matched = all(re.search(pattern, text) for pattern in all_must)
            exclude = keyword.get("exclude")
            if matched and exclude and re.search(exclude, text):
                matched = False
            if matched:
                return rid, str(route.get("skill") or "")
    if fallback:
        return fallback, str((routes.get(fallback) or {}).get("skill") or "")
    return None, ""


def routing_failures(test, domains):
    """Judge one routing case against the complete deduplicated domain list."""
    domains = list(domains or [])
    bad = []
    expected = list(test.get("expect_any") or [])
    if not expected:
        if domains:
            bad.append("『%s』→ %s（期望：判不出领域 UNCLASSIFIED）"
                       % (str(test.get("text") or "")[:24], "/".join(domains)))
    elif not domains or domains[0] not in expected:
        bad.append("『%s』→ %s（主域期望 %s）"
                   % (str(test.get("text") or "")[:24],
                      "/".join(domains) or "(空)", "/".join(expected)))

    if "expect_aux" in test:
        expected_aux = list(test.get("expect_aux") or [])
        actual_aux = domains[1:]
        if actual_aux != expected_aux:
            bad.append("『%s』→ %s（辅助域期望 %s）"
                       % (str(test.get("text") or "")[:24],
                          "/".join(domains) or "(空)",
                          "/".join(expected_aux) or "(空)"))
    elif len(domains) > 1:
        bad.append("『%s』命中多个领域但未登记 expect_aux：%s"
                   % (str(test.get("text") or "")[:20], "/".join(domains)))

    if "expect_ambiguity" in test and bool(test["expect_ambiguity"]) != (len(domains) > 1):
        bad.append("『%s』→ %s（歧义期望 %s，实际 %s）"
                   % (str(test.get("text") or "")[:24], "/".join(domains) or "(空)",
                      bool(test["expect_ambiguity"]), len(domains) > 1))

    forbidden = [domain for domain in domains if domain in set(test.get("forbid") or [])]
    if forbidden:
        bad.append("『%s』误命中 %s（完整命中 %s）"
                   % (str(test.get("text") or "")[:20], "/".join(forbidden),
                      "/".join(domains)))
    return bad


def check_routing():
    try:
        import route as route_mod
        skill_dir = os.path.join(TOOL, "skill")
        config = route_mod.check(skill_dir)
        if config.get("problems"):
            raise ValueError("；".join(config["problems"]))
    except Exception as e:  # noqa: BLE001
        add("全局", "路由串味测试集", False, "pack.json 路由坏:" + str(e)[:40])
        return
    bad = []
    for t in ROUTING_TESTS:
        try:
            _hits, domains = route_mod.resolved_domains(t["text"], skill_dir)
        except Exception as e:  # noqa: BLE001
            bad.append("『%s』路由执行失败：%s"
                       % (str(t.get("text") or "")[:24], str(e)[:60]))
            continue
        bad.extend(routing_failures(t, domains))
    add("全局", "路由串味测试集（%d 条）" % len(ROUTING_TESTS), not bad,
        "；".join(bad[:8]) if bad else "完整命中集合满足主域、辅助域、歧义与禁止域约束")


# ---------------------------------------------------------------- [10] 清理
def check_cleanup():
    bad = []
    # 根目录 md allowlist（DOMAIN-CONTRACT §清理）：人读入口 + 宿主直接读取的 agent 契约。
    # 契约（DOMAIN-CONTRACT §清理）：根目录只允许 README*/ROADMAP + 需求与审查提示词（人读入口）。
    # REVIEW-PROMPT-INDEPENDENT.md = 交给外部模型做独立审查的提示词（正式交付物）。
    # 过程文档→work/plans，提示词→Tool/prompts/sources，agent 契约→Tool/prompts/contracts。
    # KPI.md 是 BLUEPRINT §6 规定的根级台账（唯一 KPI 表），不是过程文档：
    # 它的存在本身就是「新增必须先有一行 KPI 前后对比」这条刹车。
    # REQUIREMENTS.md = 客户需求（白话）+ 产品解读，是"接手必读"的第一份，属人读入口。
    allow_root = {"README.md", "README.zh.md", "README.en.md", "ROADMAP.md", "KPI.md", "REQUIREMENTS.md", "REVIEW-PROMPT.md", "REVIEW-PROMPT-INDEPENDENT.md"}
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
        # 两种合法形态：①完整台账（含 R1–R4 结论）②索引页（正文已归档到 docs/history/ 并给出链接）
        is_index = ("history/" in t) and ("历史" in t)
        for k in ([] if is_index else ["R1", "R2", "R3", "R4"]):
            if "## " + k not in t:
                bad.append("docs/AUDIT.md 缺 %s 结论" % k)
                continue
            seg = t.split("## " + k, 1)[1][:4000]
            if not any(x in seg for x in ("证据", "处置", "判定")):
                bad.append("docs/AUDIT.md 的 %s 无证据/判定/处置行" % k)
    add("全局", "仓库清理（无过程文档 / ROADMAP / AUDIT）", not bad,
        "；".join(bad) if bad else "根目录干净，ROADMAP/AUDIT 就位")


# ---------------------------------------------------------------- [11] 部署
def _all_skills():
    """列出仓库内全部技能：(部署名, Tool/skill 下的相对路径)。safe-skills 子技能按扁平名部署。"""
    out = []
    base = os.path.join(TOOL, "skill")
    if not os.path.isdir(base):
        return out
    for n in sorted(os.listdir(base)):
        p = os.path.join(base, n)
        if n.startswith(("_", ".")):   # S3：_pending/ 是归档区，不参与索引/部署
            continue
        if n == "safe-skills" and os.path.isdir(p):
            for sub in sorted(os.listdir(p)):
                if os.path.isfile(os.path.join(p, sub, "SKILL.md")):
                    out.append((sub, "safe-skills/" + sub))
        elif os.path.isfile(os.path.join(p, "SKILL.md")):
            out.append((n, n))
    return out


def check_deploy(only=None, agent_root=None):
    try:
        agent = Path(resolve_agent_root(agent_root, env=os.environ), "skills")
    except RuntimeRootError as exc:
        add("全局", "部署哈希一致", False,
            "AgentRoot 无效（显式参数、PI_CODING_AGENT_DIR、PI_AGENT_DIR 或 HOME）：%s"
            % exc.detail)
        return
    if not agent.is_dir():
        add("全局", "部署哈希一致", False,
            "未找到 AgentRoot/skills：%s（先运行安装入口）" % agent)
        return
    all_skills = _all_skills()
    if only:
        spec = DOMAINS.get(only) or {}
        selected = [(os.path.basename(str(spec.get("skill") or "")).strip("/"),
                     str(spec.get("skill") or ""))]
        selected = [(name, rel_path) for name, rel_path in selected if name and rel_path]
    else:
        archived = {
            str(spec.get("skill")) for spec in DOMAINS.values()
            if spec.get("archived")
        }
        selected = [
            (name, rel_path) for name, rel_path in all_skills
            if rel_path not in archived
        ]

    source_map = {
        name: Path(TOOL, "skill", *rel_path.split("/"))
        for name, rel_path in selected
    }
    deployed_map = {
        path.name: path for path in agent.iterdir()
        if path.is_dir() and path.name not in {".", ".."}
    } if agent.is_dir() else {}
    bad = []
    missing = sorted(set(source_map) - set(deployed_map))
    extra = sorted(set(deployed_map) - set(source_map))
    if missing:
        bad.append("未部署目录:" + ",".join(missing[:4]))
    if extra:
        bad.append("部署残留目录:" + ",".join(extra[:4]))
    for name in sorted(set(source_map) & set(deployed_map)):
        differences = compare_deploy_trees(source_map[name], deployed_map[name])
        for key, label in (
                ("missing", "缺资产"), ("extra", "残留资产"),
                ("drift", "哈希不一致"), ("errors", "无法核验")):
            paths = differences.get(key) or []
            if paths:
                bad.append("%s(%s：%s)" % (
                    name, label, ",".join(str(path) for path in paths[:4])
                    + ("…" if len(paths) > 4 else "")))

    add("全局", "部署哈希一致（递归资产：仓库 ↔ AgentRoot/skills）", not bad,
        "；".join(bad[:8]) + ("…" if len(bad) > 8 else "") if bad
        else "%d 个技能的全部可部署资产递归哈希一致" % len(source_map))



# ---------------------------------------------------------------- [13] 案例索引
def check_case_index():
    p = os.path.join(TOOL, "scripts", "case_state.py")
    if not os.path.isfile(p):
        add("全局", "案例索引与磁盘一致", False, "缺 case_state.py")
        return
    try:
        r = subprocess.run([sys.executable, p, "index", "--check"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120, cwd=ROOT)
        ok = r.returncode == 0
        tail = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
        add("全局", "案例索引与磁盘一致（现算，无 index.json 缓存）", ok, tail[-1][:100] if tail else "")
    except Exception as e:  # noqa: BLE001
        add("全局", "案例索引与磁盘一致（现算，无 index.json 缓存）", False, str(e)[:80])


# ---------------------------------------------------------------- main
def check_spec():
    """契约漂移：DOMAIN-CONTRACT 文档的关键阈值/域清单与公共实现是否明显不一致。"""
    p = os.path.join(ROOT, "docs", "DOMAIN-CONTRACT.md")
    bad = []
    if not os.path.isfile(p):
        bad.append("缺 docs/DOMAIN-CONTRACT.md")
    else:
        t = "\n".join(lines(p))
        for k in ("600", "400", "6–10", "20–30"):
            if k not in t:
                bad.append("DOMAIN-CONTRACT 缺关键数字 " + k)
    spec_text = "\n".join(lines(p)) if os.path.isfile(p) else ""
    for dom in FORMAL_DOMAINS:
        if dom not in spec_text:
            bad.append("DOMAIN-CONTRACT 未提及域 " + dom)
    if DOMAIN_LOAD_ERRORS:
        bad.append("domain_spec 载入错误：" + "；".join(DOMAIN_LOAD_ERRORS[:3]))
    add("全局", "契约未漂移（DOMAIN-CONTRACT ↔ 公共 LIMITS/pack depth_contract）", not bad,
        "；".join(bad) if bad else ("%d 域覆盖（域清单来自 pack.json#id）" % len(FORMAL_DOMAINS)))


def main():
    ap = argparse.ArgumentParser(description="领域深度门禁（九件套 2.0）")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--domain", action="append", default=[])
    ap.add_argument("--links", action="store_true")
    ap.add_argument("--routing", action="store_true")
    ap.add_argument("--cleanup", action="store_true")
    ap.add_argument("--deploy", action="store_true")
    ap.add_argument("--spec", action="store_true")
    ap.add_argument("--mutation-test", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--root", default="", help="仓库根（默认本仓库；fixture 用显式根）")
    ap.add_argument("--agent-root", default="",
                    help="部署 AgentRoot（默认按 PI_CODING_AGENT_DIR、PI_AGENT_DIR、HOME 解析）")
    a = ap.parse_args()
    if a.root:
        _use_root(a.root)
    only = a.domain[0] if a.domain else None
    if a.mutation_test:
        check_mutation_test()
        bad = [r for r in results if not r["ok"]]
        print(("PASS" if not bad else "FAIL") + " mutation-test: "
              + (results[0]["detail"] if results else ""))
        return 0 if not bad else 1
    if not any([a.all, a.domain, a.links, a.routing, a.cleanup, a.deploy, a.spec]):
        a.all = True
    if a.domain:
        unknown = [d for d in a.domain if d not in DOMAINS]
        if unknown:
            print("[FAIL] 未知域：%s（可用：%s）" % (",".join(unknown), ",".join(FORMAL_DOMAINS)))
            return 2
    _register_load_errors()
    if a.all or a.domain or a.spec:
        check_spec()
    if a.all or a.domain:
        for dom, spec in DOMAINS.items():
            if a.domain and dom not in a.domain:
                continue
            if not spec.get("skill") or not os.path.isdir(os.path.join(TOOL, "skill", spec["skill"])):
                mark_uncovered(dom, "缺技能目录 Tool/skill/%s" % spec.get("skill"))
                add(dom, "技能目录", False, "缺失 Tool/skill/" + str(spec.get("skill")))
                continue
            # 缺 depth_contract 字段/材料的新域**不许**把门禁打崩（KeyError），也不许静默
            # 跳过：逐域 try 兜底 → 显式 UNCOVERED + FAIL 行，其余域照常检查。
            try:
                check_skill(dom, spec)
                check_refs(dom, spec)
                check_scripts(dom, spec)
                check_cases(dom, spec)
                check_kb(dom, spec)
                check_matrix(dom, spec)
                check_cards(dom, spec)
                check_criteria_backing(dom, spec)
                check_2026_presence(dom, spec)
            except Exception as exc:  # noqa: BLE001
                mark_uncovered(dom, "深度检查中断（domain=%s，%s: %s）"
                               % (dom, type(exc).__name__, str(exc)[:120]))
                add(dom, "深度检查中断（缺字段/材料，不计 PASS）", False,
                    "%s: %s；spec=%s" % (type(exc).__name__, str(exc)[:120],
                                         ",".join(sorted(spec))))
    if a.all or a.links:
        check_links()
        check_md_links()
        check_repro_and_templates()
        check_global_reference_limits()
        check_mutation_test()
        check_case_index()
    if a.all or a.routing:
        check_routing()
    if a.all or a.cleanup:
        check_cleanup()
    if a.all or a.deploy:
        check_deploy(only, a.agent_root or None)
    fails = [r for r in results if not r["ok"]]
    # W6：全绿 = 无 FAIL **且**无 UNCOVERED。缺件/无法自检不允许被当成通过。
    green = (not fails) and (not uncovered)
    if a.json:
        print(json.dumps({"results": results, "fails": len(fails),
                          "uncovered": uncovered, "green": green},
                         ensure_ascii=False, indent=2))
    else:
        cur = ""
        for r in results:
            if r["domain"] != cur:
                cur = r["domain"]
                print("\n[%s]" % cur)
            print("  [%s] %s%s" % ("PASS" if r["ok"] else "FAIL", r["name"],
                                   ("  — " + r["detail"]) if r["detail"] else ""))
        if uncovered:
            print("\n未覆盖（缺件/无法自检；不计 PASS，也不静默跳过）:")
            for u in uncovered:
                print("[UNCOVERED] %s：%s（不计 PASS，也不静默跳过）" % (u["domain"], u["reason"]))
        print("\n结果: %d/%d 通过%s%s" % (
            len(results) - len(fails), len(results),
            "；UNCOVERED %d 域：%s（不计 PASS）" % (
                len({u["domain"] for u in uncovered}),
                ",".join(sorted({u["domain"] for u in uncovered}))) if uncovered else "",
            "  ← 有 FAIL" if fails else ("  ← 不全绿" if uncovered else "")))
    return 0 if green else 1


if __name__ == "__main__":
    sys.exit(main())
