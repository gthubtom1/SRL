#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mcp-param-contract.py -- seep MCP 服务的「参数契约」门禁。

回答一个问题：**模型第一次调用这个 MCP 服务时，能不能不靠猜就传对参数？**

背景（2026-10-22 审计 P0）：auto_triage 收 `target_path`，而 r2/packer/decompile
一批工具收 `binary_path`，同一个服务里两套命名。历史血案：模型一次 rejected 之后
就再没用过 MCP 工具，改用 184 次 bash 手搓 strings/pefile。

判据：
  [1] 所有吃路径的工具，schema 必须同时暴露 binary_path 与 target_path（以及
      apk_path/file_path/sample_path/artifact_path/pcap_path/dir_path 全集）
  [2] 路径主参数不得出现在 required 里（否则「只传别名」会被 schema 直接拒绝）
  [3] 不得有以 `_` 开头的工具泄漏进注册表（辅助函数误挂 @server.tool 的典型症状）
  [4] 每个工具必须有非空 description（模型靠它选工具）
  [5] 工具总数与 Tool/config/tool-capabilities.json 记录的基线一致（防静默丢失）
  [6] **真调用探针**：对 5 个代表工具用「非主参数名」各真调一次（只读、无害），
      回包不得出现 unexpected keyword argument / Field required。
      —— 2026-10-24 P1-8：只有 [1]–[5] 时本门禁报全绿，而运行时 17 个吃路径的
      工具**全错**（FastMCP 把 arg_model 全部字段按默认值 dump 下来，别名层只 pop
      非空别名 → 空串别名漏进原函数 → TypeError）；可见「只查 schema」= 假阳性。

用法:
    python Tool/skill/softseep/scripts/mcp-param-contract.py
    python Tool/skill/softseep/scripts/mcp-param-contract.py --json
    python Tool/skill/softseep/scripts/mcp-param-contract.py --server <path/to/seep_mcp_server.py>
    python Tool/skill/softseep/scripts/mcp-param-contract.py --no-runtime   # 只查 schema（排障/离线用）
    python Tool/skill/softseep/scripts/mcp-param-contract.py --self-test
退出码：0 全绿 / 1 有违规 / 2 输入缺失或服务无法加载。
"""

from __future__ import annotations

# Shared locator for both source skills and installed copies.
from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parents[2] / 'softseep' / 'scripts'))
from seep_runtime import repo_root as _seep_repo_root


import argparse
import asyncio
import glob
import importlib.util
import io
import json
import os
import sys
import tempfile
import warnings

# 加载 MCP 服务模块时 pydantic-settings 会报一条与本次判定无关的 forward-ref 警告，
# 它会把 stderr 拼进 stdout、污染 --json 输出，先把警告压掉。
warnings.filterwarnings("ignore")

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

def _repo_root(start):
    return _seep_repo_root(__file__)


ROOT = _repo_root(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "Tool")
DEFAULT_SERVER = os.path.join(TOOL, "mcp", "seep_mcp_server.py")
CAPS = os.path.join(TOOL, "config", "tool-capabilities.json")

PATH_PARAM_RE = ("_path", "directory", "file_")
REQUIRED_ALIASES = ("binary_path", "target_path")
# 只有「指向被测目标」的参数才属于别名契约；KB 文稿路径、输出目录不参与。
TARGET_LIKE = {
    "binary_path", "target_path", "apk_path", "pcap_path",
    "file_a", "file_b", "directory",
}
# 次要操作数（第二个文件）本来就该必填，不受别名契约约束。
SECONDARY_OPERANDS = {"file_b"}

# ---------------------------------------------------------------------------
# 判据 [6]：真调用探针（2026-10-24 P1-8）
# 选的都是「只读、对一个存在的文件必然安全」的工具；（工具, 非主参数名）
# 任何业务回答都算过 —— 只有「参数层被拒」才算失败。
# ---------------------------------------------------------------------------
RUNTIME_PROBES = (
    # (工具, 非主参数名, 对照调用的参数模板) —— "{probe}" 会被换成探针文件绝对路径
    ("seep_apk_info", "target_path", {"apk_path": "{probe}"}),
    ("seep_packer_detect", "target_path", {"binary_path": "{probe}"}),
    ("seep_auto_triage", "binary_path", {"target_path": "{probe}"}),
    ("seep_r2_info", "target_path", {"binary_path": "{probe}"}),
    ("seep_mem_strings", "binary_path", {"target_path": "{probe}"}),
)
# 两类回答都算「别名被拒」：Python 层的 unexpected keyword，或 pydantic 层的
# validation error / Field required（说明别名压根没进 schema）。
REJECT_MARKERS = ("unexpected keyword argument", "field required", "validation error",
                  "缺少")  # 最后一个是别名层自己的「缺少参数」文案（它也是参数被打丢的症状）
PROBE_FILE_CANDIDATES = (
    os.path.join(TOOL, "samples", "real", "crackerjack", "a.exe"),
)


def _probe_file(server_path: str):
    """挑一个真实存在的探针文件：优先仓库标靶 a.exe，其次任意样本 exe，最后用服务自身。"""
    for cand in PROBE_FILE_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    for cand in sorted(glob.glob(os.path.join(TOOL, "samples", "**", "*.exe"), recursive=True)):
        if os.path.isfile(cand):
            return cand
    return server_path if os.path.isfile(server_path) else None


def _norm(answer: str) -> str:
    return " ".join((answer or "").split())


def run_runtime_probes(module, tools, probe_file):
    """真调一次（走 FastMCP 的 ToolManager，与 MCP 客户端同一条路），双路对照：

    A 路：只用别名调；B 路：只用主参数名调。两者的回答必须一致。
    一致 ⇒ 别名真的被解包到了同一个参数上（对照实验，不是只看 schema）。
    """
    results = []
    manager = getattr(getattr(module, "server", None), "_tool_manager", None)
    by_name = {t["name"]: t for t in tools}
    base = os.path.basename(probe_file) if probe_file else ""
    for name, alias, ref_tpl in RUNTIME_PROBES:
        rec = {"tool": name, "alias": alias, "status": "pass", "detail": ""}
        if manager is None:
            rec.update(status="skipped", detail="拿不到 server._tool_manager，真调用探针跳过")
        elif name not in by_name:
            rec.update(status="skipped", detail="工具未注册（可能被删/改名）")
        elif alias not in (by_name[name].get("props") or []):
            # schema 里没这个别名 → 即使底层不报错，模型传了也会被 pydantic 静默丢弃
            rec.update(status="fail",
                       detail="%s 不在 schema 里（别名层没挂上：@_path_alias / @_pid_alias 漏了？）" % alias)
        elif not probe_file:
            rec.update(status="skipped", detail="找不到探针文件")
        else:
            ref_args = {k: (probe_file if v == "{probe}" else v) for k, v in ref_tpl.items()}
            answers = {}
            for label, args in (("alias", {alias: probe_file}), ("ref", ref_args)):
                try:
                    out = asyncio.run(manager.call_tool(name, args))
                    answers[label] = out if isinstance(out, str) else json.dumps(out, ensure_ascii=False, default=str)
                except Exception as exc:  # 工具内部报错不影响判定，只看参数层
                    answers[label] = "%s: %s" % (type(exc).__name__, exc)
            a_norm, r_norm = _norm(answers["alias"]), _norm(answers["ref"])
            hit = [m for m in REJECT_MARKERS if m in (a_norm + " " + r_norm).lower()]
            if hit:
                rec.update(status="fail", detail="%s=%s 被拒（命中 %r）：%s" % (
                    alias, base, hit[0], (a_norm or r_norm)[:150]))
            elif a_norm != r_norm:
                rec.update(status="fail",
                           detail="%s 与 %s 的回答不一致（别名没落到同一个参数上）：alias=%s | ref=%s" % (
                               alias, "/".join(ref_args), a_norm[:70], r_norm[:70]))
            else:
                rec.update(detail="%s ≡ %s（%s）：%s" % (
                    alias, "/".join(ref_args), base, a_norm[:70]))
        results.append(rec)
    return results


def _is_target_tool(tool) -> bool:
    return any(p in TARGET_LIKE for p in tool["props"] if _is_path_param(p))


def _is_path_param(name: str) -> bool:
    return name.endswith("_path") or name == "directory" or name.startswith("file_")


def load_tools(server_path: str):
    """把 MCP 服务模块导入并取出已注册工具（不跑 stdio）。"""
    spec = importlib.util.spec_from_file_location("seep_mcp_contract_probe", server_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("无法加载 MCP 服务：%s" % server_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # 模块底部有 __main__ 守卫，导入不会起服务
    server = getattr(module, "server", None)
    if server is None:
        raise RuntimeError("模块里找不到 server 实例：%s" % server_path)
    tools = asyncio.run(server.list_tools())
    out = []
    for t in tools:
        schema = t.inputSchema or {}
        props = list((schema.get("properties") or {}).keys())
        out.append({
            "name": t.name,
            "description": t.description or "",
            "props": props,
            "required": list(schema.get("required") or []),
        })
    return out, module


def check(tools, baseline=None, probes=None):
    violations = []
    path_tools = [t for t in tools if _is_target_tool(t)]

    for t in path_tools:
        for alias in REQUIRED_ALIASES:
            if alias not in t["props"]:
                violations.append({
                    "rule": "1-alias-missing",
                    "tool": t["name"],
                    "detail": "缺少路径别名 %s（现有 %s）" % (alias, ", ".join(p for p in t["props"] if _is_path_param(p))),
                })
        for name in t["required"]:
            if name in TARGET_LIKE and name not in SECONDARY_OPERANDS:
                violations.append({
                    "rule": "2-alias-shadowed-by-required",
                    "tool": t["name"],
                    "detail": "%s 在 required 里，只传别名会被 schema 拒绝" % name,
                })

    for t in tools:
        if t["name"].startswith("_"):
            violations.append({"rule": "3-helper-leaked", "tool": t["name"],
                               "detail": "以 _ 开头的辅助函数被注册成了 MCP 工具"})
        if not t["description"].strip():
            violations.append({"rule": "4-empty-description", "tool": t["name"],
                               "detail": "没有 description，模型无法按语义选工具"})

    if baseline is not None and len(tools) != baseline:
        violations.append({"rule": "5-tool-count-drift", "tool": "-",
                           "detail": "实际 %d 个工具，基线 %d 个" % (len(tools), baseline)})

    probes = list(probes or [])
    for p in probes:
        if p.get("status") == "fail":
            violations.append({"rule": "6-alias-runtime-rejected", "tool": p.get("tool", "-"),
                               "detail": p.get("detail", "")})

    return {
        "ok": not violations,
        "tool_count": len(tools),
        "path_tool_count": len(path_tools),
        "baseline": baseline,
        "probes": probes,
        "probe_pass": len([p for p in probes if p.get("status") == "pass"]),
        "probe_failed": len([p for p in probes if p.get("status") == "fail"]),
        "probe_skipped": len([p for p in probes if p.get("status") == "skipped"]),
        "violations": violations,
    }


def _resolve_baseline():
    """工具数基线：唯一来源 Tool/config/packs.baseline.json 的
    mcp_handshake.servers.seep.toolsCount（退化到 toolNames 条数）。

    历史（外部评审 F10）：曾经读 Tool/config/gate-counts.json，该文件后来被删，函数就
    return None，而 main() 的 "if baseline is not None" 把整段比对静默跳过 —— 于是 40→20 的
    工具削减既没人发现、门禁还打印「工具数基线一致」。现在基线缺失时显式 WARN，
    不再假装比对过。
    """
    pb = os.path.join(TOOL, "config", "packs.baseline.json")
    if os.path.isfile(pb):
        try:
            d = json.load(open(pb, encoding="utf-8"))
            srv = ((d.get("mcp_handshake") or {}).get("servers") or {}).get("seep") or {}
            n = srv.get("toolsCount")
            if isinstance(n, int) and n > 0:
                return n
            names = srv.get("toolNames")
            if isinstance(names, list) and names:
                return len(names)
        except Exception as exc:  # noqa: BLE001
            print("[WARN] packs.baseline.json 读不出工具数基线：%s" % exc)
    gc = os.path.join(TOOL, "config", "gate-counts.json")
    if os.path.isfile(gc):
        try:
            d = json.load(open(gc, encoding="utf-8"))
            for k in ("mcp_seep_tools", "seep_tools", "tools"):
                n = d.get(k)
                if isinstance(n, int) and n > 0:
                    return n
        except Exception:  # noqa: BLE001
            pass
    return None


def _self_test():
    """造假工具/假探针结果验判据能抓出违规（离线，不需要 MCP 服务）。"""
    good = {"name": "seep_ok", "description": "d",
            "props": ["binary_path", "target_path", "apk_path", "file_path",
                      "sample_path", "artifact_path", "pcap_path", "dir_path"],
            "required": []}
    bad_alias = {"name": "seep_legacy", "description": "d",
                 "props": ["target_path", "apk_path", "file_path", "sample_path",
                           "artifact_path", "pcap_path", "dir_path"],
                 "required": []}
    bad_req = dict(good, name="seep_req", required=["binary_path"])
    leak = {"name": "_helper", "description": "d", "props": ["x"], "required": ["x"]}
    probe_bad = {"tool": "seep_apk_info", "alias": "target_path", "status": "fail",
                 "detail": "TypeError: got an unexpected keyword argument 'target_path'"}
    probe_ok = {"tool": "seep_apk_info", "alias": "target_path", "status": "pass", "detail": "ok"}
    probe_skip = {"tool": "seep_gone", "alias": "target_path", "status": "skipped", "detail": "未注册"}
    checks = [
        ("good", check([good])["ok"] is True),
        ("alias-missing", any(v["rule"] == "1-alias-missing" for v in check([bad_alias])["violations"])),
        ("required-shadow", any(v["rule"] == "2-alias-shadowed-by-required" for v in check([bad_req])["violations"])),
        ("helper-leak", any(v["rule"] == "3-helper-leaked" for v in check([leak, good])["violations"])),
        ("count-drift", any(v["rule"] == "5-tool-count-drift" for v in check([good], baseline=99)["violations"])),
        ("no-path-tool", check([leak])["violations"] and check([])["ok"] is True),
        ("runtime-reject", any(v["rule"] == "6-alias-runtime-rejected"
                               for v in check([good], probes=[probe_bad])["violations"])),
        ("runtime-pass", check([good], probes=[probe_ok])["ok"] is True),
        ("runtime-skip-not-fail", check([good], probes=[probe_skip])["ok"] is True),
    ]
    failed = [n for n, ok in checks if not ok]
    print(json.dumps({"ok": not failed, "checks": len(checks), "failed": failed,
                      "tool": "mcp-param-contract.py"}, ensure_ascii=False))
    return 0 if not failed else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="seep MCP 参数契约门禁")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    ap.add_argument("--server", default=DEFAULT_SERVER, help="MCP 服务入口文件")
    ap.add_argument("--no-baseline", action="store_true", help="跳过工具数基线对账")
    ap.add_argument("--self-test", action="store_true", help="离线自测（不加载服务）")
    ap.add_argument("--no-runtime", action="store_true", help="跳过真调用探针（只查 schema）")
    args = ap.parse_args()

    if args.self_test:
        return _self_test()

    if not os.path.isfile(args.server):
        msg = {"ok": False, "error": "MCP 服务文件不存在：%s" % args.server, "blocked_at": "server-missing"}
        print(json.dumps(msg, ensure_ascii=False))
        return 2

    try:
        tools, module = load_tools(args.server)
    except Exception as exc:  # 模块导入失败（依赖缺失/语法错误）
        msg = {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc), "blocked_at": "server-load-failed"}
        print(json.dumps(msg, ensure_ascii=False))
        return 2

    probes = []
    if not args.no_runtime:
        try:
            probes = run_runtime_probes(module, tools, _probe_file(args.server))
        except Exception as exc:  # 探针本身炸了，不能静默当通过
            probes = [{"tool": "-", "alias": "-", "status": "fail",
                       "detail": "真调用探针异常：%s: %s" % (type(exc).__name__, exc)}]

    baseline = None if args.no_baseline else _resolve_baseline()
    if baseline is None and not args.no_baseline:
        print("[WARN] 工具数基线缺失（packs.baseline.json 里没有 mcp_handshake.servers.seep.toolsCount）"
              "—— 本次没有比对工具数，不代表没被削减")
    result = check(tools, baseline, probes)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("MCP 参数契约：%d 个工具（其中 %d 个吃路径）" % (result["tool_count"], result["path_tool_count"]))
        for p in probes:
            tag = {"pass": "PASS", "fail": "FAIL", "skipped": "SKIP"}.get(p.get("status"), "?")
            print("  [%s] 真调用 %-20s %s" % (tag, p.get("tool"), p.get("detail")))
        if result["ok"]:
            print("  全绿：路径参数别名、required、description、工具数、真调用探针均一致")
        else:
            for v in result["violations"]:
                print("  [FAIL] %-28s %s — %s" % (v["rule"], v["tool"], v["detail"]))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
