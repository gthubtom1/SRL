#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""forge.py —— 三合一骨架生成器（配方 / 能力 / 域）。

一条命令生成骨架，并且在**落盘之前**先过对应门禁：

    python Tool/scripts/forge.py playbook   <name>   # -> Tool/playbooks/<name>.md
    python Tool/scripts/forge.py capability <name>   # -> capability JSON + ref 卡 + 脚本（含 --self-test）
    python Tool/scripts/forge.py domain     <name>   # -> SKILL + references/（6 篇）+ scripts/（2 个）

生成流程（先临时目录，绿了再 move）：

    1. 按 `Tool/scripts/forge-templates/` 渲染到临时目录
    2. 跑门禁：playbook → `playbook-check.py`；capability → `capability-gate.py`
       + 脚本 `--self-test`；domain → 结构等价比对（篇幅/必备篇/脚本自检），
       已注册域随后补跑 `domain-gate.py --domain <name>`
    3. 门禁红 → 不落盘，输出结构化错误 rc=2；绿 → move 到仓库并回报路径

用法：
    python Tool/scripts/forge.py <playbook|capability|domain> <name>
    python Tool/scripts/forge.py <kind> <name> --dry-run
    python Tool/scripts/forge.py <kind> <name> --json
    python Tool/scripts/forge.py --self-test
退出码：0 生成/演练成功 / 2 输入缺失、命名非法、门禁红或目标已存在。
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
TEMPLATES = os.path.join(HERE, "forge-templates")
KINDS = ("playbook", "capability", "domain")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SKIP_FILES = ("INDEX.md", "README.md")
TIMEOUT = 120

# 与 capability-gate.py 的 DEFAULT_FAMILIES 保持一致（仅用于临时矩阵夹具）
DEFAULT_FAMILIES = ["account-automation", "site-rebuild", "client-license",
                    "reverse-mapping", "firmware", "forensics", "protocol",
                    "supply-chain", "plugin", "malware"]

DOMAIN_REFS = [
    ("01", "criteria", "判据表",
     "每条判据的机检字段、取值范围与阈值",
     "判据与证据的对应关系",
     "阈值冲突时的唯一裁决处"),
    ("02", "failure-criteria", "失败判据与换路",
     "每一步的失败形态与 `blocked_at` 取值",
     "换路顺序与二次尝试边界",
     "失败证据如何留痕"),
    ("03", "model-pitfalls", "模型常见失误",
     "把相似当一致的典型误判",
     "只跑主路径、忽略失败路径",
     "路径与阈值写死后不可复算"),
    ("04", "walkthrough", "真实走查",
     "一次完整输入的逐步执行",
     "每步 rc、关键字段与证据路径",
     "从哪里开始换路、为什么"),
    ("05", "inputs-and-scope", "输入面与范围",
     "必填输入与可选输入的边界",
     "scope 与授权的最小声明",
     "越界动作的停手点"),
    ("06", "evidence-and-handoff", "证据与交接",
     "证据形态、命名与 sha256 清单",
     "报告五段结构与引用方式",
     "跨域转交时的最小信息集"),
]

DOMAIN_SCRIPT_ROLES = {
    "check": "输入面判定与结构化结果",
    "accept": "判据汇总与验收结论",
}


class ForgeError(Exception):
    def __init__(self, stage: str, reason: str, bad=None):
        super().__init__(reason)
        self.stage = stage
        self.reason = reason
        self.bad = bad or []


def title_of(name: str) -> str:
    words = [w for w in re.split(r"[-_.]+", name) if w]
    return " ".join(w[:1].upper() + w[1:] for w in words) or name


def read_template(templates: str, filename: str) -> str:
    path = os.path.join(templates, filename)
    if not os.path.isfile(path):
        raise ForgeError("template", "模板缺失: " + filename)
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def render(templates: str, filename: str, variables: dict) -> str:
    text = read_template(templates, filename)
    for key, value in variables.items():
        text = text.replace("{{" + key + "}}", str(value))
    return text


def build_plan(kind: str, name: str, templates: str) -> dict:
    title = title_of(name)
    trigger_words = "、".join([w for w in re.split(r"[-_.]+", name) if w])
    plan: dict[str, str] = {}
    if kind == "playbook":
        plan["Tool/playbooks/%s.md" % name] = render(templates, "playbook.md.tmpl", {
            "name": name,
            "title": title,
            "trigger_words": trigger_words,
            "capabilities": "`repo:preflight` `repo:case_state` `repo:kb-query`",
            "main_script": "Tool/scripts/preflight.py",
        })
    elif kind == "capability":
        plan["Tool/capabilities/%s.json" % name] = render(
            templates, "capability.json.tmpl",
            {"name": name, "title": title, "trigger_words": trigger_words})
        plan["Tool/capabilities/%s.md" % name] = render(
            templates, "capability-ref.md.tmpl",
            {"name": name, "title": title, "trigger_words": trigger_words})
        plan["Tool/scripts/%s.py" % name] = render(
            templates, "capability-script.py.tmpl", {"name": name, "title": title})
    elif kind == "domain":
        skill_vars = {
            "name": name,
            "title": title,
            "trigger_words": trigger_words or name,
            "capabilities": ("`repo:case_state` `repo:preflight` "
                             "`repo:%s-check` `repo:%s-accept`" % (name, name)),
        }
        plan["Tool/skill/%s/SKILL.md" % name] = render(
            templates, "domain-SKILL.md.tmpl", skill_vars)
        for num, slug, ref_title, p1, p2, p3 in DOMAIN_REFS:
            file_slug = slug if slug != "walkthrough" else "walkthrough-" + name
            plan["Tool/skill/%s/references/%s-%s.md" % (name, num, file_slug)] = render(
                templates, "domain-ref.md.tmpl", {
                    "name": name, "title": title, "num": num, "slug": file_slug,
                    "ref_title": ref_title, "purpose_1": p1, "purpose_2": p2,
                    "purpose_3": p3,
                })
        for role in DOMAIN_SCRIPT_ROLES:
            plan["Tool/skill/%s/scripts/%s-%s.py" % (name, name, role)] = render(
                templates, "domain-script.py.tmpl",
                {"name": name, "title": title, "role": role})
    else:
        raise ForgeError("input", "未知类型: " + kind)
    return plan


def run_cmd(args, cwd: str) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)[:200]
    out = (proc.stdout or b"").decode("utf-8", "replace")
    err = (proc.stderr or b"").decode("utf-8", "replace")
    return proc.returncode, out, err


def gate_json(script: str, args: list[str], cwd: str) -> tuple[int, dict | None, str]:
    rc, out, err = run_cmd([sys.executable, script] + args, cwd)
    data = None
    if out.strip():
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            start, end = out.find("{"), out.rfind("}")
            if start >= 0 and end > start:
                try:
                    data = json.loads(out[start:end + 1])
                except json.JSONDecodeError:
                    data = None
    return rc, data, (err or out).strip()


def write_plan(stage: str, plan: dict) -> None:
    for relpath, content in plan.items():
        target = os.path.join(stage, relpath.replace("/", os.sep))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)


def matrix_families(root: str) -> list[str]:
    path = os.path.join(root, "Tool", "config", "capability-matrix.json")
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8-sig") as fh:
                data = json.load(fh)
            families = data.get("families")
            if isinstance(families, list) and families:
                return families
        except (OSError, json.JSONDecodeError):
            pass
    return list(DEFAULT_FAMILIES)


def write_stage_matrix(stage: str, root: str, name: str) -> None:
    families = matrix_families(root)
    data = {"families": families,
            "capabilities": {name: {family: "partial" for family in families}}}
    target = os.path.join(stage, "Tool", "config", "capability-matrix.json")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


def lint_domain(stage: str, name: str) -> list[str]:
    """结构等价比对：篇幅 / 必备篇 / 脚本 --help 与 --self-test。"""
    bad = []
    skill = os.path.join(stage, "Tool", "skill", name, "SKILL.md")
    refs_dir = os.path.join(stage, "Tool", "skill", name, "references")
    scripts_dir = os.path.join(stage, "Tool", "skill", name, "scripts")
    skill_text = ""
    if not os.path.isfile(skill):
        bad.append("SKILL.md 缺失")
    else:
        with open(skill, encoding="utf-8") as fh:
            skill_text = fh.read()
        n = len(skill_text.splitlines())
        if not 120 <= n <= 600:
            bad.append("SKILL.md 篇幅 %d 行（要求 120–600）" % n)
        for marker in ("判据", "失败判据", "模型常见失误"):
            if marker not in skill_text:
                bad.append("SKILL.md 缺『%s』节" % marker)
        if "范围" not in skill_text and "边界" not in skill_text:
            bad.append("SKILL.md 缺『范围/边界』节")
        if "references/" not in skill_text:
            bad.append("SKILL.md 未索引 reference")
    refs = sorted(glob.glob(os.path.join(refs_dir, "*.md"))) if os.path.isdir(refs_dir) else []
    if not 6 <= len(refs) <= 10:
        bad.append("references 篇数 %d（要求 6–10）" % len(refs))
    required = ["01-criteria.md", "02-failure-criteria.md", "03-model-pitfalls.md"]
    names = [os.path.basename(p) for p in refs]
    for required_name in required:
        if required_name not in names:
            bad.append("references 缺必备篇 " + required_name)
    if not any(n.startswith("04-walkthrough") for n in names):
        bad.append("references 缺 04-walkthrough-*.md")
    for path in refs:
        with open(path, encoding="utf-8") as fh:
            n = len(fh.read().splitlines())
        if not 60 <= n <= 400:
            bad.append("%s 篇幅 %d 行（要求 60–400）" % (os.path.basename(path), n))
        if "references/" not in (skill_text or ""):
            continue
        if os.path.basename(path) not in (skill_text or ""):
            bad.append("SKILL.md 未引用 " + os.path.basename(path))
    scripts = sorted(glob.glob(os.path.join(scripts_dir, "*.py"))) if os.path.isdir(scripts_dir) else []
    if not 2 <= len(scripts) <= 4:
        bad.append("scripts 数量 %d（要求 2–4）" % len(scripts))
    for path in scripts:
        for flag in ("--help", "--self-test"):
            rc, out, err = run_cmd([sys.executable, path, flag], stage)
            if rc != 0:
                bad.append("%s %s rc=%d" % (os.path.basename(path), flag, rc))
    return bad


def domain_registered(name: str) -> bool:
    lib = os.path.join(HERE, "lib")
    if lib not in sys.path:
        sys.path.insert(0, lib)
    try:
        from domain_spec import DOMAINS  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return False
    return name in DOMAINS


def validate(kind: str, name: str, stage: str, root: str) -> list[dict]:
    gates: list[dict] = []
    if kind == "playbook":
        rc, data, detail = gate_json(
            os.path.join(HERE, "playbook-check.py"),
            ["--root", root, "--playbooks-dir", os.path.join(stage, "Tool", "playbooks"),
             "--json"], stage)
        ok = rc == 0 and bool(data and data.get("ok"))
        gates.append({"gate": "playbook-check", "ok": ok,
                      "detail": "bad=%d total=%s" % (
                          len((data or {}).get("bad") or []),
                          (data or {}).get("total", "?")) if data else detail[:200],
                      "bad": (data or {}).get("bad") or []})
    elif kind == "capability":
        write_stage_matrix(stage, root, name)
        rc, data, detail = gate_json(os.path.join(HERE, "capability-gate.py"),
                                     ["--root", stage, "--json"], stage)
        ok = rc == 0 and bool(data and data.get("ok"))
        gates.append({"gate": "capability-gate", "ok": ok,
                      "detail": "dangling=%s" % (
                          (data or {}).get("counts", {}).get("dangling", "?")
                          if data else detail[:200])})
        script = os.path.join(stage, "Tool", "scripts", name + ".py")
        rc, out, err = run_cmd([sys.executable, script, "--self-test"], stage)
        gates.append({"gate": name + ".py --self-test", "ok": rc == 0,
                      "detail": (out or err).strip()[:200]})
    else:
        bad = lint_domain(stage, name)
        gates.append({"gate": "domain-structure", "ok": not bad,
                      "detail": "；".join(bad) if bad else "SKILL/refs/scripts 结构合规",
                      "bad": bad})
        if domain_registered(name):
            gates.append({"gate": "domain-gate --domain", "ok": None, "skipped": True,
                          "detail": "已注册域：落盘后补跑 domain-gate --domain " + name})
        else:
            gates.append({"gate": "domain-gate --domain", "ok": None, "skipped": True,
                          "detail": "域未注册（domain_spec/DOMAIN-SPEC 未收录），先补注册再跑门禁"})
    return gates


def conflicts(plan: dict, root: str, force: bool) -> list[str]:
    found = []
    for relpath in plan:
        target = os.path.join(root, relpath.replace("/", os.sep))
        if os.path.exists(target):
            found.append(relpath + ("（已存在）" if not force else "（--force 覆盖）"))
    return found


def persist(stage: str, plan: dict, root: str) -> list[str]:
    written = []
    for relpath in plan:
        src = os.path.join(stage, relpath.replace("/", os.sep))
        dst = os.path.join(root, relpath.replace("/", os.sep))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)
        written.append(relpath)
    return written


def undo(written: list[str], root: str) -> None:
    for relpath in written:
        path = os.path.join(root, relpath.replace("/", os.sep))
        try:
            if os.path.isfile(path):
                os.remove(path)
            parent = os.path.dirname(path)
            while parent.startswith(root) and parent != root and not os.listdir(parent):
                os.rmdir(parent)
                parent = os.path.dirname(parent)
        except OSError:
            pass


def forge(kind: str, name: str, root: str = ROOT, templates: str = TEMPLATES,
          dry_run: bool = False, force: bool = False) -> dict:
    payload: dict = {"ok": False, "kind": kind, "name": name,
                     "schema": "seep.forge/1", "gates": [], "written": []}
    if kind not in KINDS:
        payload.update(stage="input", reason="类型必须是 " + "/".join(KINDS))
        return payload
    if not NAME_RE.match(name or ""):
        payload.update(stage="input",
                       reason="名字需匹配 [a-z0-9][a-z0-9._-]{0,63}，实际 %r" % name)
        return payload
    try:
        plan = build_plan(kind, name, templates)
    except ForgeError as exc:
        payload.update(stage=exc.stage, reason=exc.reason, bad=exc.bad)
        return payload
    payload["would_write"] = sorted(plan)
    clashes = conflicts(plan, root, force)
    if clashes and not force:
        payload.update(stage="conflict", reason="目标已存在（--force 才覆盖）", bad=clashes)
        return payload
    stage = tempfile.mkdtemp(prefix="forge-")
    try:
        write_plan(stage, plan)
        gates = validate(kind, name, stage, root)
        payload["gates"] = gates
        red = [g for g in gates if g.get("ok") is False]
        if red:
            payload.update(stage="validate", reason="门禁未通过，未落盘", bad=red)
            return payload
        if dry_run:
            payload.update(ok=True, stage="dry-run", reason="门禁全绿（演练，未落盘）")
            return payload
        written = persist(stage, plan, root)
        payload["written"] = written
        payload["ok"] = True
        payload["stage"] = "done"
        payload["reason"] = "已生成 %d 个文件" % len(written)
        if kind == "domain" and domain_registered(name):
            rc, data, detail = gate_json(os.path.join(HERE, "domain-gate.py"),
                                         ["--domain", name, "--json"], root)
            payload["gates"].append({"gate": "domain-gate --domain", "ok": rc == 0,
                                     "detail": "fails=%s" % (
                                         (data or {}).get("fails", "?") if data else detail[:200])})
            if rc != 0:
                undo(written, root)
                payload.update(ok=False, stage="validate", written=[],
                               reason="domain-gate --domain 红，已回滚落盘")
        return payload
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def emit(payload: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    head = "forge: %s %s" % (payload.get("kind", "?"), payload.get("name", "?"))
    print(head + " -> " + ("PASS" if payload.get("ok") else "FAIL"))
    if payload.get("reason"):
        print("  " + payload["reason"])
    for gate in payload.get("gates") or []:
        state = "SKIP" if gate.get("skipped") else ("PASS" if gate.get("ok") else "FAIL")
        print("  [%s] %s — %s" % (state, gate.get("gate"), str(gate.get("detail", ""))[:160]))
    if payload.get("would_write"):
        print("  计划写入: " + ", ".join(payload["would_write"]))
    if payload.get("written"):
        print("  已写入: " + ", ".join(payload["written"]))
    for item in payload.get("bad") or []:
        if isinstance(item, dict):
            print("  BAD " + json.dumps(item, ensure_ascii=False)[:300])
        else:
            print("  BAD " + str(item))


def self_test() -> int:
    checks, failures = 0, []

    def expect(label, cond):
        nonlocal checks
        checks += 1
        if not cond:
            failures.append(label)

    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "root")
        scripts = os.path.join(root, "Tool", "scripts")
        os.makedirs(scripts)
        for stem in ("preflight", "case_state", "kb-query"):
            with open(os.path.join(scripts, stem + ".py"), "w", encoding="utf-8") as fh:
                fh.write("import sys\nprint('usage')\n"
                         "sys.exit(0 if '--help' in sys.argv else 0)\n")

        res = forge("playbook", "demo-flow", root=root)
        expect("playbook 生成 rc/ok", res["ok"] is True and res["stage"] == "done")
        target = os.path.join(root, "Tool", "playbooks", "demo-flow.md")
        expect("playbook 落盘", os.path.isfile(target))
        text = open(target, encoding="utf-8").read() if os.path.isfile(target) else ""
        for marker in ("触发词", "步骤", "判据", "失败判据", "能力"):
            expect("playbook 含 " + marker, marker in text)
        expect("playbook 跑了 playbook-check",
               any(g["gate"] == "playbook-check" and g["ok"] for g in res["gates"]))

        res_cap = forge("capability", "demo-cap", root=root)
        expect("capability 生成 rc/ok", res_cap["ok"] is True)
        cap_json = os.path.join(root, "Tool", "capabilities", "demo-cap.json")
        cap_script = os.path.join(root, "Tool", "scripts", "demo-cap.py")
        expect("capability JSON + 脚本落盘",
               os.path.isfile(cap_json) and os.path.isfile(cap_script))
        data = json.load(open(cap_json, encoding="utf-8")) if os.path.isfile(cap_json) else {}
        for key in ("id", "title", "inputs", "outputs", "scripts", "refs",
                    "maturity", "compose"):
            expect("capability JSON 含 " + key, key in data)
        expect("capability maturity=probe", data.get("maturity") == "probe")
        expect("capability 脚本 --self-test rc=0",
               run_cmd([sys.executable, cap_script, "--self-test"], root)[0] == 0)
        expect("capability 跑了 capability-gate",
               any(g["gate"] == "capability-gate" and g["ok"] for g in res_cap["gates"]))

        res_dom = forge("domain", "demo-dom", root=root)
        expect("domain 生成 rc/ok", res_dom["ok"] is True)
        skill = os.path.join(root, "Tool", "skill", "demo-dom", "SKILL.md")
        refs = glob.glob(os.path.join(root, "Tool", "skill", "demo-dom", "references", "*.md"))
        dom_scripts = glob.glob(os.path.join(root, "Tool", "skill", "demo-dom", "scripts", "*.py"))
        expect("domain SKILL 落盘", os.path.isfile(skill))
        expect("domain refs 6 篇", len(refs) == 6)
        expect("domain scripts 2 个", len(dom_scripts) == 2)
        if os.path.isfile(skill):
            n = len(open(skill, encoding="utf-8").read().splitlines())
            expect("domain SKILL 篇幅 120–600", 120 <= n <= 600)
        expect("domain 结构门禁绿",
               any(g["gate"] == "domain-structure" and g["ok"] for g in res_dom["gates"]))
        expect("domain-gate 未注册时跳过",
               any(g["gate"] == "domain-gate --domain" and g.get("skipped")
                   for g in res_dom["gates"]))
        for path in dom_scripts:
            expect("domain 脚本 %s --self-test" % os.path.basename(path),
                   run_cmd([sys.executable, path, "--self-test"], root)[0] == 0)

        res_dry = forge("playbook", "dry-flow", root=root, dry_run=True)
        expect("dry-run rc/ok", res_dry["ok"] is True and res_dry["stage"] == "dry-run")
        expect("dry-run 不落盘",
               not os.path.exists(os.path.join(root, "Tool", "playbooks", "dry-flow.md")))

        res_dup = forge("playbook", "demo-flow", root=root)
        expect("重复目标 rc=2 结构化",
               res_dup["ok"] is False and res_dup["stage"] == "conflict")
        expect("--force 覆盖成功",
               forge("playbook", "demo-flow", root=root, force=True)["ok"] is True)

        bad_templates = os.path.join(tmp, "bad-templates")
        shutil.copytree(TEMPLATES, bad_templates)
        with open(os.path.join(bad_templates, "playbook.md.tmpl"), "w", encoding="utf-8") as fh:
            fh.write("# {{title}}\n- 触发词：{{name}}\n- 步骤：1) "
                     "`python Tool/scripts/nope.py --fast` → rc=0。\n")
        res_red = forge("playbook", "red-flow", root=root, templates=bad_templates)
        expect("门禁红 rc=2", res_red["ok"] is False and res_red["stage"] == "validate")
        expect("门禁红不落盘",
               not os.path.exists(os.path.join(root, "Tool", "playbooks", "red-flow.md")))

        res_name = forge("playbook", "Bad Name", root=root)
        expect("非法命名 rc=2 结构化",
               res_name["ok"] is False and res_name["stage"] == "input")
        res_kind = forge("unknown", "x", root=root)
        expect("未知类型 rc=2 结构化", res_kind["ok"] is False and res_kind["stage"] == "input")

    print(json.dumps({"ok": not failures, "checks": checks, "tool": "forge.py",
                      "failures": failures}, ensure_ascii=False))
    return 0 if not failures else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="三合一骨架生成器：配方 / 能力 / 域（先临时目录过门禁，绿了再落盘）")
    ap.add_argument("kind", nargs="?", choices=KINDS, help="playbook | capability | domain")
    ap.add_argument("name", nargs="?", help="骨架名（小写、数字、-_.）")
    ap.add_argument("--root", default=None, help="仓库根（默认按脚本位置推断）")
    ap.add_argument("--templates", default=None, help="模板目录（默认 Tool/scripts/forge-templates）")
    ap.add_argument("--dry-run", action="store_true", help="只生成到临时目录并过门禁，不落盘")
    ap.add_argument("--force", action="store_true", help="覆盖已存在的目标文件")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--self-test", action="store_true", help="临时夹具自测")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not args.kind or not args.name:
        payload = {"ok": False, "stage": "input",
                   "reason": "用法: forge.py <playbook|capability|domain> <name>"}
        emit(payload, args.json)
        return 2
    root = os.path.abspath(args.root) if args.root else ROOT
    templates = os.path.abspath(args.templates) if args.templates else TEMPLATES
    payload = forge(args.kind, args.name, root=root, templates=templates,
                    dry_run=args.dry_run, force=args.force)
    emit(payload, args.json)
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    sys.exit(main())
