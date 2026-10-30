#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Behavioral verification for tools discovered by the MCP server.

Discovery answers "a matching file exists"; this module answers "that file
behaved like the requested tool in an isolated read-only probe".
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
from lib import process_tree


def _tool_identity_module():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = os.path.join(root, "Tool", "scripts", "lib", "tool_identity.py")
    spec = importlib.util.spec_from_file_location("seep_tool_identity", path)
    if spec is None or spec.loader is None:
        raise ImportError("tool_identity loader unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_tool(tool_id: str, command: str, apktool_jar: str = "") -> dict:
    """Probe the discovered command itself; a bundled JAR cannot vouch for it.

    apktool_jar remains accepted for caller compatibility. Launcher identity is
    always checked by executing command, never an unrelated java/JAR pair.
    """
    tid = str(tool_id or "").strip().lower()
    exe = os.path.abspath(command) if command and os.path.isfile(command) else ""
    if not exe:
        return {
            "verified": False,
            "verdict": "missing",
            "tool_id": tid,
            "command": command or "",
            "why": "未找到可执行文件",
        }

    if tid == "r2":
        argv = [
            exe, "-q", "-e", "scr.color=0", "-c", "iIj", sys.executable,
        ]
        try:
            proc = process_tree.run(
                argv, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=30, stdin=subprocess.DEVNULL,
            )
            try:
                info = json.loads(proc.stdout or "")
            except (TypeError, ValueError):
                info = None
            verified = (proc.returncode == 0 and isinstance(info, dict)
                        and isinstance(info.get("arch"), str) and bool(info["arch"].strip()))
            return {
                "verified": verified,
                "verdict": "ready" if verified else "found_no_verify",
                "tool_id": tid, "command": exe, "probe_command": argv,
                "returncode": proc.returncode,
                "why": ("radare2 实际分析探针通过" if verified
                        else "radare2 实际分析探针未通过（输出不回显）"),
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "verified": False, "verdict": "found_no_verify",
                "tool_id": tid, "command": exe,
                "why": "radare2 实际分析探针失败：%s" % type(exc).__name__,
            }

    try:
        identity = _tool_identity_module()
        probe_name = {"r2": "radare2"}.get(tid, tid)
        if probe_name not in identity.PROBES:
            return {
                "verified": False,
                "verdict": "found_no_verify",
                "tool_id": tid,
                "command": exe,
                "why": "没有该工具的行为探针；路径存在不能证明身份或功能可用",
            }
        result = identity.probe(probe_name, exe)
        verified = result.get("ok") is True and result.get("verified") is True
        return {
            "verified": verified,
            "verdict": "ready" if verified else "found_no_verify",
            "tool_id": tid,
            "command": exe,
            "returncode": result.get("returncode"),
            "why": result.get("why") or "",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "verified": False,
            "verdict": "found_no_verify",
            "tool_id": tid,
            "command": exe,
            "why": "行为探针不可用：%s" % type(exc).__name__,
        }


if __name__ == "__main__":
    import json

    tool = sys.argv[1] if len(sys.argv) > 1 else ""
    path = sys.argv[2] if len(sys.argv) > 2 else ""
    jar = sys.argv[3] if len(sys.argv) > 3 else ""
    print(json.dumps(verify_tool(tool, path, jar), ensure_ascii=False, indent=2))
