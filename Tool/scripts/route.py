#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""route.py —— 路由唯一入口（S3）：从 `Tool/skill/*/pack.json` 现算，不再有 routing.json 副本。

为什么重写：旧 `routing.json` 是可以和实现漂移的第二份表（上游 45 条路由目标全不存在就是
这个形态）。现在路由声明在包里，`route.py --check` 保证**0 条死路由**。

用法：
    python Tool/scripts/route.py --index            # 每行一条路由：priority<TAB>pack<TAB>label
    python Tool/scripts/route.py --index --json     # 机器可读
    python Tool/scripts/route.py --resolve "安卓 APK 去广告"
    python Tool/scripts/route.py --resolve "安卓 APK 去广告" --limit 3  # 自选预览上限
    python Tool/scripts/route.py --resolve "区块链智能合约有没有漏洞" --strict   # 判不出 → rc=2
    python Tool/scripts/route.py --check            # 死路由/坏正则/坏优先级 → rc=1

兜底路由（`"fallback": true`）仍然存在（保住 softseep 的兜底条目），但**不再静默**：
`--resolve` 命中它会打 `[FALLBACK]` 标记；`--strict` 下若**唯一命中是兜底**，
输出 `[UNCLASSIFIED]` 且 rc=2 —— “我判不出来”是合法且可观测的出口（PLAN-OPTIMIZATION W5）。

退出码：0 通过 / 1 有死路由或坏声明 / 2 参数错误或 --strict 判型未定（UNCLASSIFIED）
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))          # 仓库根
SKILL_DIR = os.path.join(ROOT, "Tool", "skill")

sys.path.insert(0, os.path.join(HERE, "lib"))
import domain_registry as registry_mod  # noqa: E402  单向：registry 不 import route

# 必备字段（legacy seep.pack/1 形状，**不**含后面新增的契约扩展）。
PACK_KEYS = {"schema", "id", "l1", "routes", "stages", "tools", "cases", "witness",
             "witness_tool",   # 真跑该域自己的脚本（外部评审 C1：witness 只查账本 = 假绿）
             "evidence_contract", "limitations", "invalidation"}
# 允许出现、但不是“必备”的扩展字段：逐域静态深度要求
# （skill/board/matrix/case_globs/ext_scripts/kb_line_max/archive_*）。
# 缺失由 lib/domain_registry + domain-adapter-check + invariants 显式报“不完整”，
# 而不是让 g2 在 legacy pack 上直接红（也会挡住“先把域导进来再补契约”的正常流程）。
OPTIONAL_KEYS = {"depth_contract"}
ROUTE_KEYS = {"label", "must", "priority",
              "fallback"}       # 兜底路由显式标记（W5）：命中它≠判型成功
ROUTE_REQUIRED = {"label", "must", "priority"}   # fallback 可选：只有兜底那条要写

UNCLASSIFIED = "[UNCLASSIFIED] 判不出领域，请先问用户一句话"


class RouteConfigError(ValueError):
    def __init__(self, problems):
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


def _repo_of(skill_dir):
    """Tool/skill → 仓库根；测试的临时 skill 根同样成立（<repo>/Tool/skill）。"""
    return os.path.dirname(os.path.dirname(os.path.abspath(skill_dir or SKILL_DIR)))


def namespace_of(skill_dir=None):
    """命名空间分类（横切/别名/待迁移）。缺 domain-aliases.json 时返回空分类，不报错。

    正式域**全集**不从这里来（唯一来源是 pack.json#id）；这里只回答“哪些名字不是域”。
    """
    root = _repo_of(skill_dir)
    path = os.path.join(root, registry_mod.ALIAS_REL)
    if not os.path.isfile(path):
        empty = {"aliases": {}, "cross_cutting": set(), "pending_skills": set(),
                 "pending_patterns": ["_pending/**/*"], "errors": []}
        return empty
    ns = registry_mod.load_namespace(root)
    ns.pop("formal_domains_declared", None)
    ns.pop("path", None)
    ns.pop("load_error", None)
    return ns


def formal_domain_ids(skill_dir=None):
    """正式域 id 全集（动态，不硬编码 9/10）。"""
    return registry_mod.load_registry(_repo_of(skill_dir), skill_dir).ids()


def pack_files(skill_dir=None):
    d = skill_dir or SKILL_DIR
    if not os.path.isdir(d):
        return []
    out = []
    for name in sorted(os.listdir(d)):
        p = os.path.join(d, name, "pack.json")
        if os.path.isfile(p):
            out.append((name, p))
    return out


def load_packs(skill_dir=None):
    """返回 (packs, problems)。packs 里每项带 dir/id/l1/routes，problems 非空即不可信。

    命名空间分离（2026-10-27 裁定）：横切技能（seep-router/unpack-loop）、历史别名、
    `_pending/` 待迁移子技能**不是**正式域。没有 pack 的横切技能自然被跳过；
    一旦它们长了 pack，这里显式报“命名空间冲突”，不再默默变成客户可见域。
    """
    packs, problems = [], []
    seen = {}
    namespace = namespace_of(skill_dir)
    problems.extend(namespace.get("errors") or [])
    cross = set(namespace.get("cross_cutting") or ())
    alias_names = set(namespace.get("aliases") or {})
    pending_names = set(namespace.get("pending_skills") or ())
    if not os.path.isdir(skill_dir or SKILL_DIR):
        problems.append("缺技能根目录")
    try:
        files = pack_files(skill_dir)
    except OSError as exc:
        problems.append("无法列出技能目录：" + str(exc))
        files = []
    for dirname, path in files:
        if dirname.startswith(("_", ".")):
            problems.append("%s：归档/待迁移命名空间（_ 开头）不得带 pack.json 冒充正式域" % dirname)
            continue
        if dirname in cross:
            problems.append("%s：横切技能（domain-aliases.json#cross_cutting）不是正式域" % dirname)
            continue
        if dirname in alias_names:
            problems.append("%s：历史别名（domain-aliases.json#aliases）不能定义正式域" % dirname)
            continue
        if dirname in pending_names:
            problems.append("%s：待迁移子技能（pending_skills）不是正式域" % dirname)
            continue
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                raw = json.load(f)
        except Exception as e:
            problems.append("%s/pack.json 解析失败：%s" % (dirname, str(e)[:60]))
            continue
        if not isinstance(raw, dict):
            problems.append("%s/pack.json 顶层不是对象" % dirname)
            continue
        pid = str(raw.get("id") or "")
        if raw.get("schema") != registry_mod.PACK_SCHEMA:
            problems.append("%s：pack.schema 无效" % dirname)
        if not isinstance(raw.get("id"), str) or not pid.strip():
            problems.append("%s：id 必须是非空字符串" % dirname)
        if pid != dirname:
            problems.append("%s：id=%r 与目录名不一致" % (dirname, pid))
        if pid in seen:
            problems.append("pack id 重复：%s（%s 与 %s）" % (pid, seen[pid], dirname))
        seen[pid] = dirname
        if pid in cross or pid in alias_names or pid in pending_names:
            problems.append("%s：pack id 落在非正式命名空间（横切/别名/待迁移）" % pid)
        routes = raw.get("routes")
        if not isinstance(routes, list) or not routes:
            problems.append("%s：routes 为空或非数组" % dirname)
            routes = []
        valid_routes = []
        for i, r in enumerate(routes):
            before = len(problems)
            if not isinstance(r, dict):
                problems.append("%s routes[%d]：不是对象" % (dirname, i))
                continue
            extra = set(r) - ROUTE_KEYS
            miss = ROUTE_REQUIRED - set(r)
            if extra:
                problems.append("%s routes[%d]：多出未声明字段 %s（.strict 语义）"
                                % (dirname, i, ",".join(sorted(extra))))
            if miss:
                problems.append("%s routes[%d]：缺字段 %s" % (dirname, i, ",".join(sorted(miss))))
            must = r.get("must")
            if not isinstance(must, list) or not must:
                problems.append("%s routes[%d]：must 必须是非空数组" % (dirname, i))
            else:
                for j, pat in enumerate(must):
                    if not isinstance(pat, str) or not pat.strip():
                        problems.append("%s routes[%d].must[%d] 必须是非空正则字符串" % (dirname, i, j))
                        continue
                    try:
                        re.compile(pat)
                    except re.error as e:
                        problems.append("%s routes[%d].must[%d] 正则非法：%s"
                                        % (dirname, i, j, str(e)[:40]))
            if isinstance(r.get("priority"), bool) or not isinstance(r.get("priority"), int):
                problems.append("%s routes[%d]：priority 必须是整数" % (dirname, i))
            if "fallback" in r and not isinstance(r.get("fallback"), bool):
                problems.append("%s routes[%d]：fallback 必须是 true/false" % (dirname, i))
            if not isinstance(r.get("label"), str) or not r["label"].strip():
                problems.append("%s routes[%d]：label 不能为空" % (dirname, i))
            if len(problems) == before:
                valid_routes.append(r)
        if not os.path.isfile(os.path.join(os.path.dirname(path), "SKILL.md")):
            problems.append("%s：缺 SKILL.md（路由指向一个不存在的能力）" % dirname)
        packs.append({"dir": dirname, "path": path, "id": pid or dirname,
                      "l1": str(raw.get("l1") or ""), "routes": valid_routes, "raw": raw})
    return packs, problems


def flat_routes(packs):
    """扁平化：[(priority, pack_id, label, [must...])]，按优先级从高到低。"""
    out = []
    for p in packs:
        for r in p["routes"]:
            if isinstance(r, dict):
                out.append((int(r.get("priority") or 0), p["id"],
                            str(r.get("label") or ""), list(r.get("must") or [])))
    out.sort(key=lambda x: (-x[0], x[1], x[2]))
    return out


def check(skill_dir=None):
    packs, problems = load_packs(skill_dir)
    rows = flat_routes(packs)
    # 死路由判据：包目录必须存在、必须有 SKILL.md、每条路由必须能解析到 pack id
    ids = {p["id"] for p in packs}
    dead = [r for r in rows if r[1] not in ids]
    if dead:
        problems.append("死路由 %d 条：%s" % (len(dead), "、".join("%s/%s" % (d[1], d[2]) for d in dead)))
    prios = [r[0] for r in rows]
    dup = {x for x in prios if prios.count(x) > 1}
    if dup:
        problems.append("priority 重复 %d 个：%s（路由顺序不确定）"
                        % (len(dup), "、".join(str(x) for x in sorted(dup)[:8])))
    # 静态深度契约缺失 → 路由可达 ≠ 域闭合，显式报（不静默把“能路由”当成“可用”）。
    registry = registry_mod.load_registry(_repo_of(skill_dir), skill_dir)
    for problem in registry.errors:
        if problem not in problems:
            problems.append("registry: " + problem)
    return {"packs": len(packs), "routes": len(rows), "dead": len(dead),
            "formal_domains": registry.ids(), "incomplete": registry.incomplete(),
            "problems": problems, "rows": rows}


def fallback_keys(packs):
    """{(pack_id, label)}：被显式标记为兜底的路由（`"fallback": true`）。"""
    out = set()
    for p in packs:
        for r in p["routes"]:
            if isinstance(r, dict) and r.get("fallback") is True:
                out.add((p["id"], str(r.get("label") or "")))
    return out


def trusted_packs(skill_dir=None):
    packs, problems = load_packs(skill_dir)
    if problems:
        raise RouteConfigError(problems)
    return packs


def resolve(text, skill_dir=None, limit=None):
    """Return matching route rows in priority order.

    A project may legitimately need every matching route: a primary domain plus
    auxiliary domains and more than one route within the same domain.  Truncating
    by default silently hid part of that contract.  Callers that want a bounded
    preview must pass ``limit`` explicitly.
    """
    packs = trusted_packs(skill_dir)
    fb = fallback_keys(packs)
    text = str(text or "")
    hits = []
    for prio, pid, label, must in flat_routes(packs):
        for pat in must:
            try:
                if re.search(pat, text):
                    hits.append({"pack": pid, "label": label, "priority": prio,
                                 "must": pat, "fallback": (pid, label) in fb})
                    break
            except re.error:
                continue
    hits.sort(key=lambda x: -x["priority"])
    return hits if limit is None else hits[:limit]


def resolved_domains(text, skill_dir=None):
    """Return ``(hits, domains)`` with all hits and stable deduplicated domains."""
    hits = resolve(text, skill_dir, limit=None)
    domains = []
    seen = set()
    for hit in hits:
        if hit.get("fallback"):
            continue
        domain = str(hit.get("pack") or "")
        if domain and domain != "seep-router" and domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return hits, domains


def _positive_limit(value):
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("limit must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("limit must be a positive integer")
    return parsed


def main():
    ap = argparse.ArgumentParser(description="路由唯一入口：从 pack.json 现算（无 routing.json 副本）")
    ap.add_argument("--index", action="store_true", help="列出全部路由（priority<TAB>pack<TAB>label）")
    ap.add_argument("--check", action="store_true", help="死路由 / 坏正则 / 坏优先级 → rc=1")
    ap.add_argument("--resolve", default="", help="按一段自然语言匹配路由")
    ap.add_argument("--limit", type=_positive_limit, default=None,
                    help="只显示前 N 条命中（默认显示全部）")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="兼容旧参数：未识别默认就是 [UNCLASSIFIED] + rc=2，此开关已无副作用")
    ap.add_argument("--skill-dir", default="", help="覆盖 Tool/skill 根（测试用）")
    a = ap.parse_args()
    sd = a.skill_dir or None

    try:
        hits = resolve(a.resolve, sd, limit=a.limit) if a.resolve else []
        indexed_packs = trusted_packs(sd) if a.index else []
    except RouteConfigError as exc:
        if a.json:
            print(json.dumps({"ok": False, "error": "route_config", "problems": exc.problems,
                              "hits": []}, ensure_ascii=False, indent=2))
        else:
            for problem in exc.problems:
                print("[FAIL] " + problem)
        return 1

    if a.resolve:
        concrete = [h for h in hits if not h.get("fallback")]
        # ★ 未识别是**默认结果**，不再藏在 --strict 后面：
        #   兜底路由已从 pack.json 删除，所以"只有兜底命中"等价于"没有具体域命中"。
        fell_back = bool(hits) and not concrete
        unclassified = not concrete                  # 无具体域 → 判不出来
        if a.json:
            print(json.dumps({"query": a.resolve, "hits": hits,
                              "fallback": fell_back, "unclassified": unclassified,
                              "message": UNCLASSIFIED if unclassified else ""},
                             ensure_ascii=False, indent=2))
        elif not hits:
            print(UNCLASSIFIED)
        else:
            for h in hits:
                print("%-24s p=%-4d %s%s" % (h["pack"], h["priority"], h["label"],
                                             "  [FALLBACK]" if h.get("fallback") else ""))
            if unclassified:
                print(UNCLASSIFIED)
        return 2 if unclassified else 0

    if a.check:
        res = check(sd)
        if a.json:
            out = {k: v for k, v in res.items() if k != "rows"}
            out["fallbacks"] = len(fallback_keys(load_packs(sd)[0]))
            print(json.dumps(out, ensure_ascii=False, indent=2))
        else:
            print("[ROUTE] %d 个 pack / %d 条路由 / 死路由 %d" % (res["packs"], res["routes"], res["dead"]))
            print("[ROUTE] 正式域（动态，来自 pack.json#id）：%s" % ", ".join(res["formal_domains"]))
            for domain, reasons in sorted(res["incomplete"].items()):
                print("  [INCOMPLETE] %s：%s" % (domain, "；".join(reasons)))
            for p in res["problems"]:
                print("  [FAIL] " + p)
            if not res["problems"]:
                print("[PASS] 路由自洽：0 条死路由")
        return 1 if res["problems"] else 0

    if a.index:
        rows = flat_routes(indexed_packs)
        if a.json:
            fb = fallback_keys(indexed_packs)
            print(json.dumps([{"priority": p, "pack": pid, "label": lb, "must": m,
                               "fallback": (pid, lb) in fb}
                              for p, pid, lb, m in rows], ensure_ascii=False, indent=2))
        else:
            for p, pid, lb, _m in rows:
                print("%d\t%s\t%s" % (p, pid, lb))
        return 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
