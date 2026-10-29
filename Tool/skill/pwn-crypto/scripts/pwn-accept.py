#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pwn-accept.py -- pwn-crypto 域验收（离线、只读，不执行目标）。

复算六类硬判据：
  1. 字段      CASE_FIELDS 齐全；domain/evidence_kind/outcome/goal_level 合法
  2. 真跑      evidence_kind=real 必须有命令 + rc（或 repro.status=recorded、
               not-recorded 时必须有 reason）
  3. 哈希      artifacts[].sha256 逐字节复算；旧记录若是在 CRLF 工作区算的，
               按换行归一化接受并给 warning（工作区已由 .gitattributes 归一为 LF）
  4. refs      refs[] 必须是仓库内真实文件，不许幻影
  5. 保护位    case 声称的 NX/PIE 必须与 pwn-check/run.json 的 protections 一致；
               无脚本产物时用 lessons/commands.txt 里的编译开关复核（-no-pie /
               -fno-stack-protector / -z execstack）
  6. FSOP 字段 出现 io_file_vtable / exit_funcs_target / tls_dtor_hit / fsop_works
               时取值必须自洽：fsop_works=true 且给了 io_file_vtable 时，vtable 必须
               是 _IO_wfile_jumps / _IO_str_jumps 之一（见 heap-and-sandbox.md §6）

用法：
  python Tool/skill/pwn-crypto/scripts/pwn-accept.py                # 扫全量本域案例
  python Tool/skill/pwn-crypto/scripts/pwn-accept.py --case pwn-crypto03
  python Tool/skill/pwn-crypto/scripts/pwn-accept.py --root . --json
  python Tool/skill/pwn-crypto/scripts/pwn-accept.py --self-test    # 离线自检

退出码：0 全部通过（或 self-test 通过）；2 有 FAIL / 坏输入。
边界：只复算本域判据，不替代 Tool/scripts/domain-gate.py；不联网、不写案例目录。
"""

from __future__ import annotations

# Shared locator for both source skills and installed copies.
from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parents[2] / 'softseep' / 'scripts'))
from seep_runtime import repo_root as _seep_repo_root


import argparse
import glob
import hashlib
import json
import os
import re
import sys
import tempfile

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

SCHEMA = "seep.pwn-accept/1"
VERSION = "1.0.0"
CASE_FIELDS = ("id", "domain", "target_type", "evidence_kind", "protection",
               "authority", "goal_level", "outcome", "artifacts", "lessons",
               "refs", "updated")
FIXTURE_WORDS = ("夹具", "教学", "fixture", "示例")
# public = 公开可分发的真实产物（教学靶场 / CTF / 公开 crackme / MIT 示例）：
# 它的 target_type **本来就该**写「公开教学靶场 XXX」。判夹具字样前先剥掉公开来源词，
# 否则真实公开样本会被逼回 fixture（另一个方向的假话）。语义见 domain_spec.EVIDENCE_KINDS。
PUBLIC_MARKERS = ("公开教学靶场", "公开", "靶场", "CTF", "crackme", "MIT", "github", "public")


def _fixture_words(target_type, kind=""):
    t = str(target_type or "")
    if str(kind or "").strip().lower() == "public":
        for w in PUBLIC_MARKERS:
            t = t.replace(w, "")
    return [w for w in FIXTURE_WORDS if w in t]
EV_KINDS = ("fixture", "real", "public", "self-built", "historical")
GOOD_OUTCOMES = ("success", "partial", "blocked", "confirmed")
GOOD_LEVELS = ("L1", "L2", "L3", "L4")
FSOP_KEYS = ("io_file_vtable", "exit_funcs_target", "tls_dtor_hit", "fsop_works")
FSOP_VTABLES = ("_IO_wfile_jumps", "_IO_str_jumps")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
CMD_RE = re.compile(r"(python|gcc|gdb|objdump|nm |curl|hashcat|readelf|\.py|\.ps1|\.exe|\.sh)")
PIE_NO = re.compile(r"\bno[\s_-]*pie|pie\s*(?:off|disabled|n/?a)")
NX_NO = re.compile(r"\bno[\s_-]*nx|nx\s*(?:off|disabled)")
CANARY_NO = re.compile(r"\bno[\s_-]*canary|canary\s*(?:absent|off|not[\s-]*found|disabled)")


# ------------------------------------------------------------------ helpers
def repo_root(explicit=None):
    if explicit is not None:
        return os.path.realpath(os.path.abspath(os.path.expanduser(explicit)))
    return os.path.realpath(os.path.abspath(_seep_repo_root(__file__)))


def inside(base, target):
    """Contain a resolved path, including symlink and junction targets."""
    base = os.path.realpath(os.path.abspath(base))
    target = os.path.realpath(os.path.abspath(target))
    try:
        return os.path.commonpath([base, target]) == base
    except ValueError:
        return False


def read_json(path):
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_crlf(path):
    """同一内容按 CRLF 换行归档时的哈希（老记录来自 Windows 工作区）。"""
    with open(path, "rb") as fh:
        data = fh.read()
    if b"\r\n" in data:
        return hashlib.sha256(data).hexdigest()
    return hashlib.sha256(data.replace(b"\n", b"\r\n")).hexdigest()


def claim_state(claims):
    """把 case.protection 的自然语言条目折成 {nx/pie/canary: bool|None}。"""
    st = {"nx": None, "pie": None, "canary": None}
    for raw in claims or []:
        s = str(raw).strip().lower()
        if not s:
            continue
        if "nx" in s:
            st["nx"] = not bool(NX_NO.search(s))
        if "pie" in s:
            st["pie"] = not bool(PIE_NO.search(s))
        if "canary" in s:
            st["canary"] = not bool(CANARY_NO.search(s))
    return st


def out_state(value):
    """pwn-check 的字符串值 -> bool；N/A / 未知 -> None（不参与比对）。"""
    if value is None:
        return None
    s = str(value).strip().lower()
    if not s or s.startswith("n/a") or s in ("unknown", "none", "-"):
        return None
    if s.startswith(("enabled", "true", "yes", "on", "present", "found")):
        return True
    if s.startswith(("disabled", "false", "no", "off", "absent", "not found")):
        return False
    if "enabled" in s:
        return True
    if "disabled" in s:
        return False
    if "not found" in s:
        return False
    return None


def find_protections(case_dir):
    """在 artifacts/*.json 里找第一份 pwn-check 风格 protections 字典。"""
    arts = os.path.join(case_dir, "artifacts")
    if not os.path.isdir(arts):
        return {}
    for p in sorted(glob.glob(os.path.join(arts, "*.json"))):
        try:
            d = read_json(p)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(d, dict) and isinstance(d.get("protections"), dict) and d["protections"]:
            return {"protections": d["protections"], "source": "artifacts/" + os.path.basename(p)}
    return {}


def compile_evidence(case_dir, case):
    text = "\n".join(str(x) for x in (case.get("lessons") or []))
    cp = os.path.join(case_dir, "artifacts", "commands.txt")
    if os.path.isfile(cp):
        with open(cp, encoding="utf-8", errors="replace") as fh:
            text += "\n" + fh.read()
    return text.lower()


def collect_fsop(case_dir):
    """收集 artifacts/*.json 里出现的 FSOP/退出链字段（递归，取第一次出现）。"""
    found = {}
    arts = os.path.join(case_dir, "artifacts")
    if not os.path.isdir(arts):
        return found

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in FSOP_KEYS and k not in found:
                    found[k] = v
                else:
                    walk(v)
        elif isinstance(obj, list):
            for x in obj:
                walk(x)

    for p in sorted(glob.glob(os.path.join(arts, "*.json"))):
        try:
            walk(read_json(p))
        except Exception:  # noqa: BLE001
            continue
    return found


def iter_cases(root, pattern=r"^pwn-crypto"):
    base = os.path.join(root, "Tool", "cases")
    if not os.path.isdir(base):
        return []
    out = []
    for name in sorted(os.listdir(base)):
        p = os.path.join(base, name)
        if os.path.isdir(p) and re.match(pattern, name):
            out.append(p)
    return out


# ------------------------------------------------------------------ checks
def check_protection(case_dir, case, issues, warnings, facts):
    """保护位声称 vs 脚本输出（或编译开关）。返回 (ok, source)。"""
    claims = claim_state(case.get("protection") or [])
    facts["claimed"] = claims
    if all(v is None for v in claims.values()):
        facts["protection_source"] = "declared-none"
        return True, "declared-none"
    prot = find_protections(case_dir)
    ok = True
    if prot:
        out = prot["protections"]
        facts["script_protections"] = out
        for key, sym in (("nx", "NX"), ("pie", "PIE")):
            if claims[key] is None:
                continue
            got = out_state(out.get(sym))
            if got is None:
                warnings.append("case 声称 %s=%s，%s 的 %s=%r 无法判定" %
                                (sym, claims[key], prot["source"], sym, out.get(sym)))
            elif got != claims[key]:
                issues.append("保护位不一致：case 声称 %s=%s，%s 输出 %r" %
                              (sym, claims[key], prot["source"], out.get(sym)))
                ok = False
        if claims["canary"] is not None:
            got = out_state(out.get("Canary"))
            if got is not None and got != claims["canary"]:
                warnings.append("Canary 声称 %s 与 %r 不一致（非致命，只记录）" %
                                (claims["canary"], out.get("Canary")))
        return ok, prot["source"]

    # 无 pwn-check 产物：用编译开关复核（PE 现场编译案例的常见形态）
    ev = compile_evidence(case_dir, case)
    if claims["pie"] is not None:
        no_pie = "-no-pie" in ev or "-no_pie" in ev
        if claims["pie"] and no_pie:
            issues.append("保护位不一致：case 声称 PIE，但编译命令含 -no-pie")
            ok = False
        elif not claims["pie"] and not no_pie:
            issues.append("保护位不一致：case 声称 No PIE，但编译命令未出现 -no-pie")
            ok = False
    if claims["canary"] is not None:
        no_canary = "-fno-stack-protector" in ev
        if claims["canary"] and no_canary:
            issues.append("保护位不一致：case 声称 Canary，但编译命令含 -fno-stack-protector")
            ok = False
        elif not claims["canary"] and not no_canary:
            issues.append("保护位不一致：case 声称 No Canary，但编译命令未出现 -fno-stack-protector")
            ok = False
    if claims["nx"]:
        if "-z execstack" in ev:
            issues.append("保护位不一致：case 声称 NX，但编译命令含 -z execstack")
            ok = False
        else:
            warnings.append("NX 声称无 pwn-check 产物，按默认 NX 接受（无 -z execstack）")
    return ok, "compile-flags"


def check_fsop(case_dir, issues, facts):
    fsop = collect_fsop(case_dir)
    if not fsop:
        facts["fsop_ok"] = None
        return True
    facts["fsop"] = fsop
    ok = True
    for key in ("tls_dtor_hit", "fsop_works"):
        if key in fsop and not isinstance(fsop[key], bool):
            issues.append("%s 必须是 bool（实际 %r）" % (key, fsop[key]))
            ok = False
    if fsop.get("fsop_works") is True and "io_file_vtable" in fsop:
        vtable = str(fsop.get("io_file_vtable") or "")
        if not any(name in vtable for name in FSOP_VTABLES):
            issues.append("fsop_works=true 但 io_file_vtable=%r 不是 %s" %
                          (vtable, "/".join(FSOP_VTABLES)))
            ok = False
    if fsop.get("tls_dtor_hit") is True and not fsop.get("exit_funcs_target"):
        # 退出链两种触发互斥：TLS 命中时允许没有 exit_funcs_target，但要有 marker 说明
        facts.setdefault("notes", []).append("tls_dtor_hit=true 且未记 exit_funcs_target（允许，需 marker）")
    if "exit_funcs_target" in fsop and fsop["exit_funcs_target"]:
        if not re.search(r"0x[0-9a-fA-F]{4,}", str(fsop["exit_funcs_target"])):
            issues.append("exit_funcs_target=%r 不是地址" % (fsop["exit_funcs_target"],))
            ok = False
    facts["fsop_ok"] = ok
    return ok


def check_case(case_dir, root):
    case_dir = os.path.realpath(os.path.abspath(case_dir))
    root = os.path.realpath(os.path.abspath(root))
    result = {"case": os.path.basename(case_dir), "ok": False,
              "issues": [], "warnings": [], "facts": {}}
    issues, warnings, facts = result["issues"], result["warnings"], result["facts"]
    cf = os.path.join(case_dir, "case.json")
    if not os.path.isfile(cf):
        issues.append("缺 case.json")
        return result
    try:
        case = read_json(cf)
    except Exception as exc:  # noqa: BLE001
        issues.append("case.json 解析失败: %s" % str(exc)[:60])
        return result
    if not isinstance(case, dict):
        issues.append("case.json 顶层必须是 JSON object")
        return result

    miss = [k for k in CASE_FIELDS if k not in case]
    if miss:
        issues.append("缺字段: " + ",".join(miss))
    facts.update(id=case.get("id"), evidence_kind=case.get("evidence_kind"),
                 outcome=case.get("outcome"), goal_level=case.get("goal_level"))
    if case.get("domain") != "pwn-crypto":
        issues.append("domain=%r 不是 pwn-crypto" % (case.get("domain"),))
    kind = case.get("evidence_kind")
    if kind not in EV_KINDS:
        issues.append("evidence_kind=%r 非法" % (kind,))
    target_type = str(case.get("target_type") or "")
    is_fix = bool(_fixture_words(target_type, kind))
    if kind == "fixture" and not is_fix:
        issues.append("fixture 但 target_type 未标夹具/教学")
    if kind in ("real", "self-built") and is_fix:
        issues.append("real 却把 target_type 标成夹具")
    if case.get("outcome") == "planned":
        issues.append("outcome=planned 不许入库")
    elif case.get("outcome") not in GOOD_OUTCOMES:
        issues.append("outcome=%r 不在 %s" % (case.get("outcome"), GOOD_OUTCOMES))
    if case.get("goal_level") not in GOOD_LEVELS:
        issues.append("goal_level=%r 非法" % (case.get("goal_level"),))

    # --- 2. 真跑 / recorded
    lessons = [str(x) for x in (case.get("lessons") or [])]
    if not lessons or not lessons[0].strip():
        issues.append("lessons 为空")
    else:
        head = lessons[0]
        if "rc=" not in head:
            issues.append("lessons[0] 未写 rc（须写清跑的是什么/命令/rc）")
        if not CMD_RE.search(head):
            issues.append("lessons[0] 未写可复跑命令")
    recorded = any("rc=" in x for x in lessons)
    repro = case.get("repro") or {}
    facts["recorded"] = recorded
    facts["repro_status"] = repro.get("status")
    if kind in ("real", "self-built"):
        if repro.get("status") == "not-recorded":
            if not repro.get("reason"):
                issues.append("repro.status=not-recorded 缺 reason")
        elif not recorded:
            issues.append("real 案例无命令+rc（repro.status=%r）" % (repro.get("status"),))

    # --- 3. 哈希
    arts = case.get("artifacts") or []
    if not arts:
        issues.append("artifacts 为空")
    hash_bad = crlf = 0
    for art in arts:
        if not isinstance(art, dict):
            issues.append("artifacts 条目不是对象")
            continue
        ap = str(art.get("path") or "")
        want = str(art.get("sha256") or "").lower()
        full = os.path.realpath(os.path.join(case_dir, ap))
        if not ap or not inside(case_dir, full):
            issues.append("产物路径逃逸案例目录 %s" % (ap[:48] or "<空>"))
            hash_bad += 1
            continue
        if not os.path.isfile(full):
            issues.append("幻影产物 %s" % (ap[:48] or "<空>"))
            hash_bad += 1
            continue
        if not HEX64.match(want):
            issues.append("%s 缺 sha256 / 不是 64 位 hex" % ap[:48])
            hash_bad += 1
            continue
        got = sha256_file(full)
        if got != want:
            if sha256_crlf(full) == want:
                crlf += 1
                warnings.append("%s 记录的是 CRLF 归档哈希，工作区为 LF，已按换行归一化接受" % ap[:48])
            else:
                issues.append("%s sha256 不符（实算 %s）" % (ap[:48], got[:12]))
                hash_bad += 1
    facts["hashes_ok"] = hash_bad == 0
    facts["crlf_normalized"] = crlf

    # --- 4. refs
    refs = case.get("refs") or []
    if not refs:
        issues.append("refs 为空")
    ref_bad = 0 if refs else 1
    for ref in refs:
        rs = str(ref or "").strip()
        if not rs:
            issues.append("refs 有空值")
            ref_bad += 1
        full = os.path.realpath(os.path.join(root, rs))
        if "://" in rs or rs.startswith("<") or not inside(root, full):
            issues.append("refs 逃逸仓库或不是本地文件 %s" % rs[:60])
            ref_bad += 1
        elif not os.path.isfile(full):
            issues.append("refs 幻影 %s" % rs[:60])
            ref_bad += 1
    facts["refs_ok"] = ref_bad == 0

    # --- 5. 保护位一致性
    ok, source = check_protection(case_dir, case, issues, warnings, facts)
    facts["protection_ok"] = ok
    facts["protection_source"] = source

    # --- 6. FSOP / 退出链字段自洽
    check_fsop(case_dir, issues, facts)

    result["ok"] = not issues
    return result


# ------------------------------------------------------------------ self-test
def _write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)


def _mk_case(root, name, *, protection, prot_out, tamper_hash=False,
             crlf_record=False, fsop=None):
    d = os.path.join(root, "Tool", "cases", name)
    rp = os.path.join(d, "artifacts", "run.json")
    _write(rp, {"protections": prot_out} if prot_out else {"title": "self-test"})
    if fsop:
        _write(os.path.join(d, "artifacts", "fsop.json"), {"fsop": fsop})
    digest = sha256_crlf(rp) if crlf_record else sha256_file(rp)
    if tamper_hash:
        digest = "0" * 64
    _write(os.path.join(d, "case.json"), {
        "id": name, "domain": "pwn-crypto", "target_type": "本地自建 ELF（self-test）",
        "evidence_kind": "real", "protection": protection, "authority": "授权自检",
        "goal_level": "L3", "outcome": "confirmed",
        "artifacts": [{"path": "artifacts/run.json", "sha256": digest}],
        "lessons": ["python Tool/skill/pwn-crypto/scripts/pwn-accept.py --case %s，rc=0" % name],
        "refs": ["Tool/skill/pwn-crypto/references/01-criteria.md"],
        "updated": "2026-10-22", "repro": {"status": "recorded", "evidence": "self-test"},
    })
    return d


def self_test():
    checks = []
    try:
        # 单元：声称/输出折值
        assert claim_state(["NX", "PIE/ASLR"]) == {"nx": True, "pie": True, "canary": None}
        assert claim_state(["No PIE (-no-pie)"])["pie"] is False
        assert claim_state(["Canary absent", "No Canary (-fno-stack-protector)"])["canary"] is False
        assert out_state("Enabled (DYNAMIC_BASE/ASLR)") is True
        assert out_state("Disabled") is False
        assert out_state("Not found") is False
        assert out_state("N/A (PE 无 ELF RELRO)") is None
        checks.append("claim/out folding")

        with tempfile.TemporaryDirectory() as tmp:
            assert repo_root(tmp) == os.path.realpath(tmp)
            checks.append("--root explicit path")
            os.makedirs(os.path.join(tmp, "Tool", "skill", "pwn-crypto", "references"))
            with open(os.path.join(tmp, "Tool", "skill", "pwn-crypto", "references",
                                   "01-criteria.md"), "w", encoding="utf-8") as fh:
                fh.write("# stub\n")
            good = _mk_case(tmp, "pwn-crypto90", protection=["NX", "PIE/ASLR"],
                            prot_out={"NX": "Enabled", "PIE": "Enabled (DYNAMIC_BASE/ASLR)"})
            r = check_case(good, tmp)
            assert r["ok"], r["issues"]
            assert r["facts"]["protection_ok"] is True
            checks.append("good case passes")

            escape = _mk_case(tmp, "pwn-crypto96", protection=[], prot_out=None)
            outside = os.path.join(tmp, "outside-artifact.json")
            _write(outside, {"title": "outside"})
            case_path = os.path.join(escape, "case.json")
            with open(case_path, encoding="utf-8") as fh:
                escape_case = json.load(fh)
            escape_case["artifacts"] = [
                {"path": "../../../../outside-artifact.json", "sha256": sha256_file(outside)}]
            _write(case_path, escape_case)
            r = check_case(escape, tmp)
            assert not r["ok"] and any("产物路径逃逸" in x for x in r["issues"]), r
            checks.append("artifact containment")

            import pathlib
            with tempfile.NamedTemporaryFile(prefix="pwn-accept-ref-", suffix=".md",
                                             dir=os.path.dirname(tmp), delete=False) as fh:
                fh.write(b"outside\n")
                outside_ref = fh.name
            try:
                escape_case["artifacts"] = [{
                    "path": "artifacts/run.json",
                    "sha256": sha256_file(os.path.join(escape, "artifacts", "run.json")),
                }]
                escape_case["refs"] = ["../" + pathlib.Path(outside_ref).name]
                _write(case_path, escape_case)
                r = check_case(escape, tmp)
                assert not r["ok"] and any("refs 逃逸仓库" in x for x in r["issues"]), r
                checks.append("ref containment")
            finally:
                try:
                    os.unlink(outside_ref)
                except OSError:
                    pass

            _write(case_path, [])
            r = check_case(escape, tmp)
            assert not r["ok"] and any("JSON object" in x for x in r["issues"]), r
            checks.append("non-object JSON fail-closed")

            crlf = _mk_case(tmp, "pwn-crypto91", protection=["NX"],
                            prot_out={"NX": "Enabled"}, crlf_record=True)
            r = check_case(crlf, tmp)
            assert r["ok"], r["issues"]
            assert r["facts"]["crlf_normalized"] == 1
            checks.append("CRLF-recorded hash accepted with warning")

            tampered = _mk_case(tmp, "pwn-crypto92", protection=["NX"],
                                prot_out={"NX": "Enabled"}, tamper_hash=True)
            r = check_case(tampered, tmp)
            assert not r["ok"] and r["facts"]["hashes_ok"] is False
            checks.append("bad hash rejected")

            mismatch = _mk_case(tmp, "pwn-crypto93", protection=["NX", "PIE/ASLR"],
                                prot_out={"NX": "Enabled", "PIE": "Disabled"})
            r = check_case(mismatch, tmp)
            assert not r["ok"] and r["facts"]["protection_ok"] is False
            checks.append("PX->non-PIE claim mismatch rejected")

            bad_fsop = _mk_case(tmp, "pwn-crypto94", protection=[], prot_out=None,
                                fsop={"fsop_works": True, "io_file_vtable": "_IO_2_1_stderr_"})
            r = check_case(bad_fsop, tmp)
            assert not r["ok"] and r["facts"]["fsop_ok"] is False
            checks.append("illegal fsop vtable rejected")

            good_fsop = _mk_case(tmp, "pwn-crypto95", protection=[], prot_out=None,
                                 fsop={"io_file_vtable": "_IO_wfile_jumps",
                                       "fsop_works": True,
                                       "exit_funcs_target": "0x7ffff7fb2000",
                                       "tls_dtor_hit": False})
            r = check_case(good_fsop, tmp)
            assert r["ok"], r["issues"]
            assert r["facts"]["fsop_ok"] is True
            checks.append("legal fsop fields accepted")
    except AssertionError as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "blocked_at": "self-test",
                          "reason": "断言失败: %s" % (str(exc)[:120] or "assertion"),
                          "checks_done": len(checks)}, ensure_ascii=False))
        return 2
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "blocked_at": "self-test",
                          "reason": "%s: %s" % (type(exc).__name__, str(exc)[:120])},
                         ensure_ascii=False))
        return 2
    print(json.dumps({"ok": True, "schema": SCHEMA, "version": VERSION,
                      "self_test": "pwn-accept", "checks": len(checks),
                      "passed": checks}, ensure_ascii=False))
    return 0


# ------------------------------------------------------------------ main
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="pwn-crypto 域验收：字段/哈希/真跑/refs/保护位一致性/FSOP 字段")
    ap.add_argument("--root", default=None, help="仓库根（默认由脚本位置推导）")
    ap.add_argument("--case", action="append", default=[],
                    help="只验指定案例（目录路径或 Tool/cases 下的目录名，可重复）")
    ap.add_argument("--json", action="store_true", help="机器可读 JSON 输出")
    ap.add_argument("--self-test", action="store_true", help="离线自检（临时目录），rc=0")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    root = repo_root(args.root)
    if args.case:
        dirs = []
        for name in args.case:
            p = name if os.path.isdir(name) else os.path.join(root, "Tool", "cases", name)
            if not os.path.isdir(p):
                print(json.dumps({"ok": False, "blocked_at": "case",
                                  "reason": "找不到案例目录 %s" % name},
                                 ensure_ascii=False))
                return 2
            dirs.append(p)
    else:
        dirs = iter_cases(root)
        if not dirs:
            print(json.dumps({"ok": False, "blocked_at": "cases",
                              "reason": "Tool/cases 下没有 pwn-crypto* 案例"},
                             ensure_ascii=False))
            return 2

    results = [check_case(d, root) for d in dirs]
    fails = [r for r in results if not r["ok"]]
    report = {"schema": SCHEMA, "version": VERSION, "root": root,
              "ok": not fails, "passed": len(results) - len(fails),
              "total": len(results),
              "failures": sum(len(r["issues"]) for r in results),
              "cases": results}
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for r in results:
            print("[%s] %s%s" % ("PASS" if r["ok"] else "FAIL", r["case"],
                                 "" if r["ok"] else "  — " + "；".join(r["issues"][:3])))
            for w in r["warnings"]:
                print("        warn: " + w)
        print("结果: %d/%d 通过，%d 条问题" %
              (report["passed"], report["total"], report["failures"]))
    return 0 if not fails else 2


if __name__ == "__main__":
    sys.exit(main())
