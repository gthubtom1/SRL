#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""reverse-accept.py — 逆向域案例验收器（只读 + 复算）。

验收内容：
  1) 每个 case.json 的必填字段齐全；
  2) artifacts[].path 存在，artifacts[].sha256 真实复算一致；
  3) refs[] 指向仓库内真实文件（相对仓库根）；
  4) 若案例目录有 patch_manifest.json（或 --manifest 指定），检查补丁清单完整性：
     target_sha256 / patches[].offset/original/new/等长 / result_sha256。

用法：
  python Tool/skill/softseep/scripts/reverse-accept.py
  python Tool/skill/softseep/scripts/reverse-accept.py --root . --case Tool/cases/项目A
  python Tool/skill/softseep/scripts/reverse-accept.py --manifest Tool/cases/项目A/patch_manifest.json
  python Tool/skill/softseep/scripts/reverse-accept.py --self-test

退出码：0 全部通过；2 失败（输出 {"ok": false, "blocked_at": ..., "reason": ...}）。
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
CASE_FIELDS = ("id", "domain", "target_type", "evidence_kind", "protection",
               "authority", "goal_level", "outcome", "artifacts", "lessons",
               "refs", "updated")


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def emit_fail(blocked_at: str, reason: str) -> int:
    print(json.dumps({"ok": False, "blocked_at": blocked_at, "reason": reason},
                     ensure_ascii=True))
    return 2


def check_manifest(path: str) -> list[str]:
    bad: list[str] = []
    try:
        with open(path, encoding="utf-8") as f:
            m = json.load(f)
    except Exception as exc:  # noqa: BLE001
        return ["manifest 坏 JSON: %s" % exc]
    if not m.get("target_sha256") or len(str(m["target_sha256"])) != 64:
        bad.append("manifest 缺 target_sha256 或长度不是 64")
    patches = m.get("patches")
    if not isinstance(patches, list) or not patches:
        bad.append("manifest 缺 patches[] 或为空")
        return bad
    for i, p in enumerate(patches):
        tag = "patches[%d]" % i
        if not isinstance(p, dict):
            bad.append(tag + " 不是对象")
            continue
        try:
            off = int(p.get("offset"))
        except (TypeError, ValueError):
            bad.append(tag + " 缺整数 offset")
            continue
        if off < 0:
            bad.append(tag + " offset 为负")
        old = str(p.get("original") or "")
        new = str(p.get("new") or "")
        if not old or not new:
            bad.append(tag + " 缺 original/new")
            continue
        try:
            ob = bytes.fromhex(old)
            nb = bytes.fromhex(new)
        except ValueError:
            bad.append(tag + " original/new 不是 hex")
            continue
        if len(ob) != len(nb):
            bad.append(tag + " original/new 不等长（%d vs %d）" % (len(ob), len(nb)))
    if not m.get("result_sha256"):
        bad.append("manifest 缺 result_sha256")
    elif len(str(m["result_sha256"])) != 64:
        bad.append("manifest result_sha256 长度不是 64")
    return bad


def accept_case(case_dir: str, manifest: str | None = None) -> list[str]:
    bad: list[str] = []
    cf = os.path.join(case_dir, "case.json")
    if not os.path.isfile(cf):
        return ["缺 case.json"]
    try:
        with open(cf, encoding="utf-8-sig") as f:
            c = json.load(f)
    except Exception as exc:  # noqa: BLE001
        return ["case.json 坏 JSON: %s" % exc]
    miss = [k for k in CASE_FIELDS if k not in c]
    if miss:
        bad.append("缺字段: " + ",".join(miss))
    if c.get("evidence_kind") not in ("fixture", "real", "self-built", "historical"):
        bad.append("evidence_kind 不是 fixture/real")
    for a in c.get("artifacts") or []:
        ap = a.get("path") or ""
        full = os.path.join(case_dir, ap)
        if not ap or not os.path.isfile(full):
            bad.append("幻影产物: %s" % (ap or "<空>"))
            continue
        want = str(a.get("sha256") or "").lower()
        got = sha256(full)
        if len(want) != 64:
            bad.append("%s 缺 sha256" % ap)
        elif got != want:
            bad.append("%s sha256 不符（实际 %s）" % (ap, got[:12]))
    for r in c.get("refs") or []:
        if not isinstance(r, str) or "://" in r:
            continue
        if not os.path.isfile(os.path.join(ROOT, r)):
            bad.append("幻影 ref: %s" % r)
    mf = manifest or os.path.join(case_dir, "patch_manifest.json")
    if manifest or os.path.isfile(mf):
        if not os.path.isfile(mf):
            bad.append("指定的 manifest 不存在: %s" % mf)
        else:
            bad.extend(check_manifest(mf))
    return bad


def discover(root: str) -> list[str]:
    out: list[str] = []
    for pat in ("项目*", "案例*"):
        out.extend(sorted(glob.glob(os.path.join(root, "Tool", "cases", pat))))
    return [p for p in out if os.path.isdir(p)]


def self_test() -> int:
    checks = 0
    tmp = tempfile.mkdtemp(prefix="reverse-accept-")
    try:
        case = os.path.join(tmp, "case")
        os.makedirs(case, exist_ok=True)
        art = os.path.join(case, "artifact.bin")
        with open(art, "wb") as f:
            f.write(b"SEEP-ACCEPT\n")
        ref = os.path.join(case, "ref.md")
        with open(ref, "w", encoding="utf-8") as f:
            f.write("# ref\n")
        c = {
            "id": "selftest", "domain": "reverse", "target_type": "本地夹具",
            "evidence_kind": "fixture", "protection": [], "authority": "local",
            "goal_level": "L1", "outcome": "success",
            "artifacts": [{"path": "artifact.bin", "sha256": sha256(art)}],
            "lessons": ["self-test"], "refs": ["Tool/skill/softseep/SKILL.md"],
            "updated": "2026-10-21",
        }
        with open(os.path.join(case, "case.json"), "w", encoding="utf-8") as f:
            json.dump(c, f, ensure_ascii=False)
        bad = accept_case(case)
        assert not bad, bad
        checks += 1
        m = {
            "target_sha256": "0" * 64,
            "patches": [{"offset": 0, "original": "4142", "new": "4344"}],
            "result_sha256": "1" * 64,
        }
        with open(os.path.join(case, "patch_manifest.json"), "w", encoding="utf-8") as f:
            json.dump(m, f)
        bad = accept_case(case)
        assert not bad, bad
        checks += 1
        m["patches"][0]["new"] = "434445"
        with open(os.path.join(case, "patch_manifest.json"), "w", encoding="utf-8") as f:
            json.dump(m, f)
        bad = accept_case(case)
        assert bad and any("不等长" in x for x in bad), bad
        checks += 1
        c["artifacts"][0]["sha256"] = "f" * 64
        with open(os.path.join(case, "case.json"), "w", encoding="utf-8") as f:
            json.dump(c, f)
        bad = accept_case(case)
        assert any("sha256 不符" in x for x in bad), bad
        checks += 1
        print(json.dumps({"ok": True, "checks": checks}, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return emit_fail("self-test", "%s: %s" % (type(exc).__name__, exc))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="逆向域案例验收：复算 artifacts sha256、检查 refs 存在、检查补丁清单完整性",
        epilog="退出码：0 通过；2 失败（输出 ok=false 的 JSON）")
    ap.add_argument("--root", default=ROOT, help="仓库根（默认由 __file__ 推导）")
    ap.add_argument("--case", action="append", default=[], help="只验收指定案例目录（可多次）")
    ap.add_argument("--manifest", default=None, help="额外检查指定 patch manifest")
    ap.add_argument("--self-test", action="store_true", help="离线自测，rc=0")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    root = os.path.abspath(a.root)
    cases = [os.path.abspath(x) for x in a.case] if a.case else discover(root)
    if not cases:
        return emit_fail("discover", "未找到案例目录（Tool/cases/项目* 或 案例*）")
    all_bad: list[str] = []
    for cd in cases:
        try:
            bad = accept_case(cd, a.manifest)
        except Exception as exc:  # noqa: BLE001
            
            bad = ["%s: %s" % (type(exc).__name__, exc)]
        for x in bad:
            all_bad.append("%s：%s" % (os.path.basename(cd), x))
    if all_bad:
        return emit_fail("case-accept", "；".join(all_bad[:12]))
    print(json.dumps({"ok": True, "cases": len(cases)}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
