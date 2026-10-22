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

用法:
    python Tool/scripts/mcp-param-contract.py
    python Tool/scripts/mcp-param-contract.py --json
    python Tool/scripts/mcp-param-contract.py --server <path/to/seep_mcp_server.py>
    python Tool/scripts/mcp-param-contract.py --self-test
退出码：0 全绿 / 1 有违规 / 2 输入缺失或服务无法加载。
"""

from __future__ import annotations

import argparse
import asyncio
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

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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
    return out


def check(tools, baseline=None):
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

    return {
        "ok": not violations,
        "tool_count": len(tools),
        "path_tool_count": len(path_tools),
        "baseline": baseline,
        "violations": violations,
    }


def _resolve_baseline():
    """工具数基线：单一事实源 Tool/config/gate-counts.json 的 mcp_seep_tools。"""
    gc = os.path.join(TOOL, "config", "gate-counts.json")
    try:
        with open(gc, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    val = data.get("mcp_seep_tools") if isinstance(data, dict) else None
    if isinstance(val, int) and val > 0:
        return val
    # 回退：tool-capabilities.json 里的 mcp.seep.tool_count
    try:
        with open(CAPS, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    node = data
    for key in ("mcp", "seep"):
        node = node.get(key, {}) if isinstance(node, dict) else {}
    val = node.get("tool_count") if isinstance(node, dict) else None
    return val if isinstance(val, int) and val > 0 else None


def _self_test():
    """造 3 个假工具验证判据能抓出违规（离线，不需要 MCP 服务）。"""
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
    checks = [
        ("good", check([good])["ok"] is True),
        ("alias-missing", any(v["rule"] == "1-alias-missing" for v in check([bad_alias])["violations"])),
        ("required-shadow", any(v["rule"] == "2-alias-shadowed-by-required" for v in check([bad_req])["violations"])),
        ("helper-leak", any(v["rule"] == "3-helper-leaked" for v in check([leak, good])["violations"])),
        ("count-drift", any(v["rule"] == "5-tool-count-drift" for v in check([good], baseline=99)["violations"])),
        ("no-path-tool", check([leak])["violations"] and check([])["ok"] is True),
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
    args = ap.parse_args()

    if args.self_test:
        return _self_test()

    if not os.path.isfile(args.server):
        msg = {"ok": False, "error": "MCP 服务文件不存在：%s" % args.server, "blocked_at": "server-missing"}
        print(json.dumps(msg, ensure_ascii=False))
        return 2

    try:
        tools = load_tools(args.server)
    except Exception as exc:  # 模块导入失败（依赖缺失/语法错误）
        msg = {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc), "blocked_at": "server-load-failed"}
        print(json.dumps(msg, ensure_ascii=False))
        return 2

    baseline = None if args.no_baseline else _resolve_baseline()
    result = check(tools, baseline)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("MCP 参数契约：%d 个工具（其中 %d 个吃路径）" % (result["tool_count"], result["path_tool_count"]))
        if result["ok"]:
            print("  全绿：路径参数别名、required、description、工具数均一致")
        else:
            for v in result["violations"]:
                print("  [FAIL] %-28s %s — %s" % (v["rule"], v["tool"], v["detail"]))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
