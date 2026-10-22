#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run-drill.py -- 阶段五真实演练：site-clone-drill01 的 backend_required 9 条 → mock → 切换回归。

输入（只读，不改案例仓库）：
  Tool/cases/site-clone-drill01/artifacts/diff.json
      data_boundary 里 boundary=backend-required 的 7 条路由
      backend_required_features / network 里点名的 2 个跨域 API（/info/country、POST api.youtest.me）
      → 共 9 条 backend_required 清单
  artifacts/crawl/data/_next/data/<build>/<route>.json  录制页面数据体（真实样本）

流水线（每个阶段都落盘，失败时 rc=2 且指出卡在哪一步）：
  1. 生成 work/<drill>/har.backend-required.json（9 条能力端点 + 录制数据端点）
  2. api-surface.py        → api/api-surface.json（+ api-js.json 静态交叉验证）
  3. schema-infer.py       → api/schema.json + api/schema.sql（真实录制体）
  4. backend-scaffold.py   → backend/（录制快照回放 + 缺的给 stub）
  5. switch-verify.py      → api/switched.json（四类 × 正常/超时/错误码）
  6. report.json / REPORT.md

产物全部写 <repo>/work/（gitignore），不写仓库、不写系统 hosts。

用法：
  python Tool/skill/05-backend-rebuild/evals/run-drill.py
  python Tool/skill/05-backend-rebuild/evals/run-drill.py --case Tool/cases/site-clone-drill01 --work work/backend-rebuild-drill01
  python Tool/skill/05-backend-rebuild/evals/run-drill.py --help

退出码：0 = 全流程通过；2 = blocked（{ok:false,blocked_at,reason}）。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
# repo/Tool/skill/05-backend-rebuild/evals -> repo
REPO = os.path.dirname(os.path.dirname(os.path.dirname(SKILL)))
SCRIPTS = os.path.join(SKILL, "scripts")
BUILD_HINT = "MF0PX5Om9anXYG9uRYEC-"

# /find 等 7 条 backend-required 路由 → 客户端真正需要的能力端点。
# 方法/角色来自页面用途（README §3 的能力清单），路径是复刻实现形态；
# 抓包里没有这些能力的响应体 → mock 只能给 stub，不许伪造。
CAPS = {
    "/find": ("GET", "block", "/api/quiz/lookup", "list",
              "code", "玩家凭 code 找测验"),
    "/player/name": ("POST", "block", "/api/player", "login",
                     None, "玩家加入（会话建立）"),
    "/player/playing": ("GET", "block", "/api/player/quiz", "list",
                        "quiz_id", "玩家答题页拉题目"),
    "/player/completed": ("POST", "block", "/api/player/answer", "submit",
                          None, "逐题作答提交"),
    "/user/creating": ("POST", "block", "/api/quiz", "submit",
                       None, "创建测验（客户端同源形态）"),
    "/user/scoreboard": ("GET", "block", "/api/scoreboard", "list",
                         "quiz_id", "成绩榜"),
    "/user/share": ("GET", "block", "/api/share", "list",
                    "code", "分享落地页"),
}
EXTRA_APIS = [
    ("GET", "api", "/info/country", "heartbeat", "host",
     "feature: 国家/旗帜查询（跨域，抓取阶段被策略拦截）"),
    ("POST", "api", "/api/quiz", "submit", None,
     "feature: 创建测验写入（客户端跨域形态，与 #5 同路径不同 host）"),
]
HOSTS = {"block": "block.youtest.me", "api": "api.youtest.me"}
SKIP_JS = ("node_modules",)


def emit(obj, code=0):
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    return code


def blocked(at, reason, **extra):
    obj = {"ok": False, "blocked_at": at, "reason": str(reason)[:800]}
    obj.update(extra)
    return emit(obj, 2)


def load_json(p):
    with open(p, encoding="utf-8-sig") as f:
        return json.load(f)


def run(name, argv, cwd=None):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable] + argv, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=cwd, env=env, timeout=300)
    tail = (r.stdout or "")[-1200:] + (("\n[stderr] " + (r.stderr or "")[-600:]) if r.stderr else "")
    try:
        doc = json.loads(r.stdout)
    except Exception:  # noqa: BLE001
        doc = None
    return {"name": name, "rc": r.returncode, "out": doc, "tail": tail}


def build_har(case, work):
    diff = load_json(os.path.join(case, "artifacts", "diff.json"))
    build_id = ((diff.get("crawl") or {}).get("build_id") or BUILD_HINT)
    routes = [d["route"] for d in diff.get("data_boundary") or []
              if d.get("boundary") == "backend-required"]
    routes = sorted(set(routes))
    if len(routes) != 7:
        raise ValueError(f"案例 backend-required 路由应为 7 条，实际 {len(routes)}：{routes}")

    entries, items = [], []
    # 1) 9 条能力端点（方法/路径是复刻实现形态，证据列在 evidence 里）
    for i, route in enumerate(routes, 1):
        method, hostk, path, role, qkey, why = CAPS[route]
        item = {"n": i, "kind": "capability", "route": route, "method": method,
                "host": HOSTS[hostk], "path": path, "role": role,
                "evidence": f"data_boundary[{route}]=backend-required", "why": why}
        if qkey:
            item["query"] = {qkey: f"DR{i:02d}"}
        items.append(item)
    for j, (method, hostk, path, role, qkey, why) in enumerate(EXTRA_APIS, 8):
        item = {"n": j, "kind": "api", "route": None, "method": method,
                "host": HOSTS[hostk], "path": path, "role": role,
                "evidence": "backend_required_features / network.blocked_hosts", "why": why}
        if qkey:
            item["query"] = {qkey: "127.0.0.1"}
        items.append(item)
    if len(items) != 9:
        raise ValueError(f"backend_required 清单应为 9 条，实际 {len(items)}")

    for it in items:
        qs = "&".join(f"{k}={v}" for k, v in (it.get("query") or {}).items())
        url = f"https://{it['host']}{it['path']}" + (f"?{qs}" if qs else "")
        entries.append({
            "request": {"method": it["method"], "url": url,
                        "queryString": [{"name": k, "value": str(v)}
                                        for k, v in (it.get("query") or {}).items()],
                        "postData": ({"text": json.dumps({"name": "drill-player",
                                                          "code": "DR1"}, ensure_ascii=False)}
                                     if it["method"] == "POST" else None)},
            "response": {"status": 200,
                         "content": {"mimeType": "application/json", "text": ""}},
            "_seep": {"kind": it["kind"], "role": it["role"], "n": it["n"],
                      "why": it["why"], "evidence": it["evidence"]},
        })

    # 2) 录制数据端点：页面实际拉的 _next/data/<build>/<route>.json（真实体）
    recorded = []
    data_root = os.path.join(case, "artifacts", "crawl", "data", "_next", "data", build_id)
    for route in routes:
        fp = os.path.join(data_root, *[s for s in route.split("/") if s]) + ".json"
        if not os.path.isfile(fp):
            continue
        text = open(fp, encoding="utf-8-sig").read()
        url = f"https://{HOSTS['block']}/_next/data/{build_id}{route}.json"
        entries.append({
            "request": {"method": "GET", "url": url, "queryString": []},
            "response": {"status": 200,
                         "content": {"mimeType": "application/json", "text": text}},
            "_seep": {"kind": "recorded-data", "role": "list", "route": route,
                      "why": "抓包阶段实际拉取的页面数据 URL（录制体）",
                      "evidence": f"artifacts/crawl/data/_next/data/{build_id}{route}.json"},
        })
        recorded.append({"route": route, "file": os.path.relpath(fp, case).replace(os.sep, "/"),
                         "bytes": len(text.encode("utf-8"))})

    har = {"log": {"version": "1.2", "creator": {"name": "seep-05-drill"},
                   "entries": entries}}
    os.makedirs(work, exist_ok=True)
    harp = os.path.join(work, "har.backend-required.json")
    with open(harp, "w", encoding="utf-8") as f:
        json.dump(har, f, ensure_ascii=False, indent=1)
    with open(os.path.join(work, "items.json"), "w", encoding="utf-8") as f:
        json.dump({"schema": "seep.drill-items/1", "case": os.path.basename(case),
                   "count": len(items), "items": items, "recorded_data": recorded},
                  f, ensure_ascii=False, indent=2)
    return harp, items, recorded, build_id


def find_js_with(case, needle, limit=400):
    root = os.path.join(case, "artifacts", "crawl", "assets")
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_JS]
        for f in sorted(fn):
            if not f.endswith((".js", ".mjs")):
                continue
            p = os.path.join(dp, f)
            try:
                if needle in open(p, encoding="utf-8", errors="ignore").read():
                    return p
            except Exception:  # noqa: BLE001
                continue
            limit -= 1
            if limit <= 0:
                return None
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="site-clone-drill01 backend_required 9 条 → mock → switch-verify 真实演练",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="退出码：0 全流程通过 / 2 blocked")
    ap.add_argument("--case", default=os.path.join(REPO, "Tool", "cases", "site-clone-drill01"))
    ap.add_argument("--work", default=os.path.join(REPO, "work", "backend-rebuild-drill01"))
    ap.add_argument("--keep", action="store_true", help="保留已有 work 目录（默认清空重建）")
    args = ap.parse_args(argv)

    case = os.path.abspath(args.case)
    work = os.path.abspath(args.work)
    if not os.path.isfile(os.path.join(case, "artifacts", "diff.json")):
        return blocked("case", f"案例产物缺失：{case}")
    try:
        work_root = os.path.abspath(os.path.join(REPO, "work"))
        if os.path.commonpath([work, work_root]) != work_root:
            return blocked("work", "产物目录必须在仓库根 work/ 下（不写仓库）")
    except ValueError:
        return blocked("work", "产物目录与仓库不在同一盘符")
    if not args.keep and os.path.isdir(work):
        shutil.rmtree(work)
    os.makedirs(work, exist_ok=True)

    stages = []
    try:
        har, items, recorded, build_id = build_har(case, work)
    except Exception as e:  # noqa: BLE001
        return blocked("har", e)

    api_out = os.path.join(work, "api", "api-surface.json")
    st = run("api-surface", [os.path.join(SCRIPTS, "api-surface.py"),
                             "--har", har, "--out", api_out])
    stages.append(st)
    if st["rc"] != 0:
        return blocked("api-surface", st["tail"])
    surface = load_json(api_out)
    eps = surface["endpoints"]
    if len({e["id"] for e in eps}) < 9:
        return blocked("api-surface", f"端点少于 9：{len(eps)}")

    # 静态交叉验证（JS 里同一路径常量必须能被找到，证明抓包不是孤证）
    js = find_js_with(case, "info/country")
    js_stage = {"name": "api-surface-js", "rc": 0, "skipped": js is None}
    if js:
        js_out = os.path.join(work, "api", "api-surface-js.json")
        r = run("api-surface-js", [os.path.join(SCRIPTS, "api-surface.py"), "--js", js,
                                   "--js-path-prefixes", "/info,/api,/v1",
                                   "--out", js_out])
        js_stage = {"name": "api-surface-js", "rc": r["rc"], "file": js_out,
                    "matched": bool(r["out"] and r["out"].get("ok")),
                    "stats": (r["out"] or {}).get("stats")}
        if r["rc"] != 0:
            return blocked("api-surface-js", r["tail"])
    stages.append(js_stage)

    # schema-infer 只吃真实录制体（页面数据），不造业务数据
    rec_dir = os.path.join(work, "recorded")
    os.makedirs(rec_dir, exist_ok=True)
    for rec in recorded:
        src = os.path.join(case, rec["file"])
        dst = os.path.join(rec_dir, rec["route"].strip("/").replace("/", "_") + ".json")
        shutil.copyfile(src, dst)
    schema_out = os.path.join(work, "api", "schema.json")
    ddl_out = os.path.join(work, "api", "schema.sql")
    st = run("schema-infer", [os.path.join(SCRIPTS, "schema-infer.py"),
                              "--samples", rec_dir, "--out", schema_out, "--ddl", ddl_out])
    stages.append(st)
    if st["rc"] != 0:
        return blocked("schema-infer", st["tail"])
    schema_doc = load_json(schema_out)
    if "CREATE TABLE" not in schema_doc.get("ddl", ""):
        return blocked("schema-infer", "DDL 为空")

    backend = os.path.join(work, "backend")
    st = run("backend-scaffold", [os.path.join(SCRIPTS, "backend-scaffold.py"),
                                  "--api", api_out, "--schema", schema_out, "--out", backend])
    stages.append(st)
    if st["rc"] != 0:
        return blocked("backend-scaffold", st["tail"])
    bstats = (st["out"] or {}).get("stats") or {}
    if bstats.get("routes", 0) < 9:
        return blocked("backend-scaffold", f"路由不足 9：{bstats}")

    switched = os.path.join(work, "api", "switched.json")
    st = run("switch-verify", [os.path.join(SCRIPTS, "switch-verify.py"),
                               "--api", api_out, "--server", os.path.join(backend, "server.py"),
                               "--port", "0", "--timeout", "1.2",
                               "--mode", "proxy", "--out", switched])
    stages.append(st)
    if st["rc"] != 0:
        return blocked("switch-verify", st["tail"])
    sw = load_json(switched)
    if sw.get("verdict") != "pass":
        return blocked("switch-verify", f"verdict={sw.get('verdict')}")

    report = {
        "schema": "seep.backend-rebuild-drill/1",
        "case": os.path.basename(case),
        "case_sha_scope": ["artifacts/diff.json", "artifacts/crawl/data/_next/data"],
        "work": os.path.relpath(work, REPO).replace(os.sep, "/"),
        "build_id": build_id,
        "items": {"count": len(items),
                  "by_kind": {k: sum(1 for i in items if i["kind"] == k) for k in ("capability", "api")},
                  "by_role": {r: sum(1 for i in items if i["role"] == r)
                              for r in sorted({i["role"] for i in items})}},
        "recorded_data": recorded,
        "stages": stages,
        "surface": {"endpoints": len(eps), "roles": surface.get("roles"),
                    "by_method": surface["stats"]["by_method"],
                    "with_samples": surface["stats"]["with_samples"]},
        "schema": {"tables": [{"name": t["name"], "rows": t["rows"],
                               "primary_key": t["primary_key"]} for t in schema_doc["tables"]],
                   "warnings": schema_doc.get("warnings")},
        "mock": bstats,
        "switch": {"verdict": sw.get("verdict"), "counts": sw.get("counts"),
                   "base": sw.get("switch", {}).get("base"),
                   "mode": sw.get("switch", {}).get("mode")},
        "observations": [
            f"9 条 backend_required 清单（7 能力 + 2 跨域 API）→ {len(eps)} 个端点；录制数据端点单列，供回放取真实体。",
            f"mock 路由 {bstats.get('routes')} 条：录制回放 {bstats.get('recorded')} 条、派生骨架 {bstats.get('stub')} 条；骨架明确标 source=scaffold-stub。",
            "页面数据体只有 pageProps/title 一类 shell 字段、无 id/枚举/时间值 → 主键不可判，schema 草案需补真实业务响应样本后重跑。",
            "切换只产出 hosts.fragment/proxy.pac 与 switched.json，未写系统 hosts（applied=false）。",
        ],
        "verdict": "L3-可跑：9/9 覆盖 + 四类×三路回归全绿",
    }
    with open(os.path.join(work, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    lines = [
        f"# 阶段五演练：{report['case']}（backend_required {len(items)} 条）", "",
        f"- 产物目录：`{report['work']}`（work/，不入库）",
        f"- API 面：{report['surface']['endpoints']} 个端点，角色计数 {report['items']['by_role']}",
        f"- 录制数据端点：{len(recorded)} 条（{build_id}）",
        f"- schema 表：{', '.join(t['name'] for t in report['schema']['tables'])}",
        f"- mock：路由 {bstats.get('routes')} / 录制 {bstats.get('recorded')} / 骨架 {bstats.get('stub')}",
        f"- switch-verify：{report['switch']['verdict']}，{report['switch']['counts']}",
        "", "## 阶段 rc", "",
    ]
    for s in stages:
        lines.append(f"- {s['name']}: rc={s['rc']}" + (f" stats={s.get('stats')}" if s.get("stats") else ""))
    lines += ["", "## 结论", "", report["verdict"], ""]
    with open(os.path.join(work, "REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return emit({"ok": True, "work": report["work"], "items": report["items"],
                 "surface": report["surface"], "mock": bstats,
                 "switch": report["switch"], "report": os.path.join(report["work"], "report.json")}, 0)


if __name__ == "__main__":
    sys.exit(main())
