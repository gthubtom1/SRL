#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Current Seep MCP smoke tests.

This file tests the current server surface. Missing real fixtures are reported as
UNVERIFIED (rc=2), never as an unconditional pass. Temporary APK inputs are
created locally so the basic parser test does not depend on a case directory.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import zipfile
from unittest.mock import patch
from types import SimpleNamespace

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import seep_mcp_server as S


def check(name: str, condition: bool, detail: str = "") -> None:
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {name}" + (f" — {detail}" if detail else ""))
    if not condition:
        raise AssertionError(f"{name}: {detail}")


def main() -> int:
    try:
        print("=== Seep MCP current-surface smoke test ===")
        check("server imports", callable(S.seep_r2_info))
        check("r2 write commands are classified", "wx" in S._r2_write_tokens("aaa; wx 90"))
        check("r2 shell/redirect/plugin commands are refused",
              all(S._r2_write_tokens(c) for c in
                  ("!id", "!!id", "pd 20 > out.txt", "aaa; C*", "L /tmp/x.so",
                   "-i s.r2", "w hello", "r 100", "unknowncmd")))
        check("r2 reviewed read-only commands stay allowed",
              all(not S._r2_write_tokens(c) for c in
                  ("afl", "iz", "iR", "pdf @ main", "pd 20 @ main", "axt @ main",
                   "iS.", "afl~sym")))
        check("KB search returns structured text", "jwt" in S.seep_kb_search("JWT", limit=3).lower())
        check("tool discovery returns JSON", "status" in json.loads(S.seep_ensure_tool("r2")))
        with patch.object(S.shutil, "which", side_effect=lambda name: "npx.cmd" if name == "npx" else None):
            check("npx alone does not make REA available", not S._detect_engine("rea")["available"])
        with patch.object(S.shutil, "which", return_value="rea.cmd"):
            check("REA executable discovery reports its path", S._detect_engine("rea")["detail"] == "rea.cmd")
        discovered = {"available": True, "command": "new-tool.exe", "via": "install-recheck"}
        fake = SimpleNamespace(
            discover=lambda _: {"available": False, "command": "", "via": "none"},
            install_plan=lambda _: {"has_plan": True, "auto_allowed": True},
            propose_install=lambda *_a, **_kw: {"executed": True, "recheck": discovered})
        verified = {"verified": True, "verdict": "ready", "tool_id": "fixture",
                    "command": "new-tool.exe", "why": "fixture probe"}
        with patch.object(S, "_autodiscover", return_value=fake), \
                patch.object(S, "_verify_tool", return_value=verified):
            installed = json.loads(S.seep_ensure_tool("fixture"))
            check("successful install returns consistent top-level discovery",
                  installed["status"] == "ready" and installed["available"] is True
                  and installed["command"] == "new-tool.exe" and installed["via"] == "install-recheck")
            probe_only = json.loads(S.seep_ensure_tool("fixture", allow_install=False))
            check("probe-only keeps missing state", probe_only["status"] == "missing"
                  and probe_only["available"] is False and "install_attempt" not in probe_only)

        with tempfile.TemporaryDirectory(prefix="seep-mcp-smoke-") as td:
            apk = os.path.join(td, "sample.apk")
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
                zf.writestr("AndroidManifest.xml", b"android package activity")
            apk_info = json.loads(S.seep_apk_info(apk))
            check("APK info parses temporary APK", apk_info.get("dex_count") == 1)

            missing = S.seep_r2_info(os.path.join(td, "missing.exe"))
            check("missing binary is an error", "ERROR" in missing)

            # ── pcap：真实 MCP 入口（FastMCP call_tool）→ subprocess spy，零 spawn ──
            check("pcap entry pins -n -r through the real MCP call path",
                  _pcap_mcp_path(td))

        print("ALL CURRENT MCP SMOKE TESTS PASSED")
        return 0
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"UNVERIFIED: MCP smoke test could not complete: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


def _pcap_mcp_path(td: str) -> bool:
    """走真 MCP 入口（server.call_tool）验证 pcap 契约；subprocess.run 被 spy 替换。"""
    import asyncio
    import struct
    import subprocess

    class _Proc:
        def __init__(self, rc=0, out="", err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    pcap = os.path.join(td, "smoke-empty.pcap")
    with open(pcap, "wb") as fh:
        fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    calls = []
    real_run = subprocess.run
    subprocess.run = lambda argv, **kw: (
        calls.append(list(argv)),
        _Proc(0, "10.0.0.1:1 <-> 10.0.0.2:80 5 3 1200 800 1.5\n", "warn\n"))[1]
    try:
        async def go():
            content, _meta = await S.server.call_tool(
                "seep_pcap_extract", {"pcap_path": pcap, "mode": "summary"})
            good = json.loads(content[0].text)
            calls.clear()
            content2, _meta2 = await S.server.call_tool(
                "seep_pcap_extract", {"pcap_path": pcap, "mode": "summary; id"})
            bad_text = content2[0].text
            return good, json.loads(bad_text), bad_text, list(calls)
        good, bad, bad_text, inject_calls = asyncio.run(go())
    finally:
        subprocess.run = real_run
    check("pcap status is ok with pinned argv",
          good.get("status") == "ok" and good.get("no_network") is True, str(good)[:120])
    check("pcap data rows exclude stderr warnings",
          "warn" not in json.dumps(good.get("tcp_conversations")),
          str(good.get("tcp_conversations"))[:120])
    check("pcap injections are refused at the MCP entry without spawning",
          bad.get("error") == "invalid_parameters" and not inject_calls
          and "summary; id" not in bad_text, bad_text[:160])
    return True


if __name__ == "__main__":
    sys.exit(main())
