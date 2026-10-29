# -*- coding: utf-8 -*-
"""工具"身份自检"：文件存在 ≠ 这个工具可用。

为什么（2026-10-25 真样本验收实测）：
    某机器上的 `rabin2.exe` 实际是 **radare2.exe 改名**
    （`rabin2 -h` 打出的 `-I` 说明是 r2 的 "run script file before the file is opened"，
      strings 里是 `r_main_radare2`）。于是 `rabin2 -I <pe>` 被当成"加载脚本"，
      r2 随后进交互模式等 stdin —— 实测把一条 bash 命令卡死 900 秒。
    而 `tool-acquire` 判它 "USABLE（停在 L0）"、`tool-index.md` 写 16/16 就位。

修法：每个工具配一条"行为探针"（真实 argv + 期望输出正则 + 超时 + 关 stdin）。
    探针不过 → BROKEN（不是 usable），并在输出里说明"存在但不是那个工具"。
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys

# 探针：工具 id → (额外参数, 期望正则, 超时秒)
# 夹具一律用"本机必然存在的文件"，避免依赖被分析样本。
PROBES = {
    "rabin2": (["-I", "{self_py}"], r"(?i)\barch\b|\bclass\b", 20),
    "radare2": (["-v"], r"(?i)radare2\s+\d", 20),
    "jadx": (["--version"], r"^\d+\.\d+", 60),
    "apktool": (["--version"], r"^\d+\.\d+", 60),
    "upx": (["--version"], r"(?i)upx", 30),
    "frida": (["--version"], r"^\d+\.\d+", 30),
    "python": (["--version"], r"(?i)python\s*3", 20),
    "httpx": (["-version", "-no-color"], r"(?is)projectdiscovery\.io.*Current Version:\s*v?\d+\.\d+", 20),
}


def _run(argv, timeout):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                           timeout=timeout, stdin=subprocess.DEVNULL)
        return (p.stdout or "") + (p.stderr or ""), p.returncode
    except subprocess.TimeoutExpired:
        return "<TIMEOUT 等输入或卡死>", -9
    except FileNotFoundError:
        return "<NOT FOUND>", -2
    except Exception as e:  # noqa: BLE001
        return "<ERR %s>" % e, -3


def probe(tool_id, exe_path=None):
    """返回 {ok, tool, exe, why}。exe_path 为空时从 PATH/发现层找。"""
    spec = PROBES.get({'r2': 'radare2'}.get(tool_id, tool_id))
    if not spec:
        return {"ok": None, "verified": False, "tool": tool_id, "exe": exe_path or "",
                "why": "未配探针（不做身份断言，只报存在）"}
    args, pat, tmo = spec
    exe = exe_path or shutil.which(tool_id) or ""
    if not exe or not os.path.isfile(exe):
        return {"ok": False, "tool": tool_id, "exe": exe, "why": "找不到可执行文件"}
    argv = [exe] + [a.format(self_py=sys.executable) for a in args]
    if os.name == "nt" and not exe.lower().endswith((".exe", ".bat", ".cmd")):
        argv = ["bash", exe] + argv[1:]
    out, rc = _run(argv, tmo)
    hit = re.search(pat, out or "", re.M)
    if hit and rc == 0:
        return {"ok": True, "verified": True, "returncode": rc, "tool": tool_id, "exe": exe,
                "why": "探针命中：%s" % hit.group(0)[:60]}
    why = "探针未命中（输出=%r）" % (out or "")[:160]
    if rc != 0:
        why = "探针退出码 %s；%s" % (rc, why)
    if tool_id == "rabin2" and "run script file before the file is opened" in (out or ""):
        why += " —— 这个 rabin2.exe 是 radare2.exe 改名（-I 被当成加载脚本）"
    if "<TIMEOUT" in (out or ""):
        why += " —— 进程不退出（多半进了交互模式，调用方会被卡死）"
    return {"ok": False, "verified": False, "returncode": rc, "tool": tool_id, "exe": exe, "why": why}


def probe_all(limit=None):
    out = []
    for tid in PROBES:
        if limit and tid not in limit:
            continue
        out.append(probe(tid))
    return out


if __name__ == "__main__":
    res = probe_all()
    if "--json" in sys.argv:
        print(json.dumps(res, ensure_ascii=False, indent=1))
    else:
        for r in res:
            print("%-8s %-8s %-50s %s" % (r["tool"], "OK" if r["ok"] else "BROKEN",
                                          r["exe"][:50], r["why"][:90]))
    sys.exit(0 if all(r["ok"] for r in res) else 1)
