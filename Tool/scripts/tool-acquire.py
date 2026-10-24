#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tool-acquire.py —— 工具获取阶梯（L0 探活 → L1 启动 → L2 连上 → L3 装 → L4 求助）

## 为什么有这个脚本（2026-10-23 实测）

`tool-run.ps1` 1.3 秒把 x64dbg 起成 READY、9094 在听，但会话里 ALL_TOOLS **没有 mcp__x64dbg**
→ 模型没有工具可调 → 手搓了 5 个一次性调试器脚本，全程静默。

根因不是"工具没装"，是**没有统一的"取用"流程**：
  · 拿"端口在听"当成了"连上了"（L0 冒充 L2）
  · 连不上就当作"工具不存在"，直接绕过，不求助

本脚本把四阶梯变成**可执行、可留痕**的判定，输出结构化结论给模型消费。

## 判据（关键：L2 只认"工具在 ALL_TOOLS 里"，不认"端口在听"）

  L0 alive   : MCP 型 → 端口在听 且 tools/list ≥1；CLI 型 → where 命中且能跑无害命令
  L1 started : tool-run.ps1 返回 status=READY
  L2 linked  : 用 `pi` 的能力面无法从外部查 → 改为"本进程直连 tools/list 成功"，
               并要求模型在会话内自证（见 --emit-session-probe）
  L3 install : 缺工具 → 给安装计划（不自动装，等用户确认）
  L4 ask     : 全不通 → 输出 ASK 卡

## 用法

    python Tool/scripts/tool-acquire.py --tool x64dbg
    python Tool/scripts/tool-acquire.py --tool ghidra --json
    python Tool/scripts/tool-acquire.py --tool x64dbg --start        # 允许 L1 自动启动
    python Tool/scripts/tool-acquire.py --list                       # 列出已知工具与能力
    python Tool/scripts/tool-acquire.py --selftest

退出码：0 可用（L0 或 L2 通过） / 1 需启动 / 2 需安装 / 3 需求助 / 4 输入错误
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
REPO = os.path.dirname(TOOL)
TOOL_RUN = os.path.join(HERE, "tool-run.ps1")
RUNTIMES = os.path.join(TOOL, "config", "tool-runtimes.json")
CAPS = os.path.join(TOOL, "config", "tool-capabilities.json")
PATHS_CACHE = os.path.join(os.path.expanduser("~"), ".seep", "tool-paths.json")


def load_json(p: str) -> dict:
    try:
        with open(p, encoding="utf-8-sig") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def cached_exe(tool_id: str) -> str:
    entry = (load_json(PATHS_CACHE) or {}).get(tool_id)
    exe = entry.get("exe") if isinstance(entry, dict) else entry
    return exe if isinstance(exe, str) and os.path.isfile(exe) else ""


def where(exe_name: str) -> str:
    try:
        out = subprocess.run(["where", exe_name], capture_output=True, timeout=8)
        lines = (out.stdout or b"").decode("utf-8", "replace").splitlines()
        for ln in lines:
            if os.path.isfile(ln.strip()):
                return ln.strip()
    except Exception:
        pass
    return ""


# ───────────────────────── L0 探活 ─────────────────────────

def mcp_probe(url: str, auth_header: str = "", auth_token: str = "") -> dict:
    """直连上游 tools/list；返回 {ok, tools, detail}。"""
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Accept": "application/json, text/event-stream"})
    if auth_header and auth_token:
        req.add_header(auth_header, f"Bearer {auth_token}")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            raw = r.read()
            ctype = r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        return {"ok": False, "tools": 0, "detail": f"HTTP {e.code}（端口在听但拒绝/未初始化）"}
    except Exception as e:
        return {"ok": False, "tools": 0, "detail": f"连不上：{type(e).__name__}"}

    data = None
    if "text/event-stream" in (ctype or ""):
        for line in raw.decode("utf-8", "replace").splitlines():
            if line.startswith("data:"):
                frag = line[5:].strip()
                if frag:
                    try:
                        data = json.loads(frag)
                    except Exception:
                        pass
    else:
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            data = None
    tools = ((data or {}).get("result") or {}).get("tools") or []
    if tools:
        return {"ok": True, "tools": len(tools), "detail": f"{len(tools)} 个工具"}
    return {"ok": False, "tools": 0, "detail": "tools/list 返回 0 个工具或需先 initialize"}


MCP_DIR = os.path.join(TOOL, "mcp")


def autodiscover(tool_id: str) -> str:
    """复用 tool_autodiscover 的八层发现（env / PATH / 常见目录 / 注册表 / 开始菜单 / Everything / 扫描 / 别名）。

    2026-10-23 教训：upx / dnspy / de4dot / pe-sieve 全在 D:\Tools 下，
    但旧版只查 PATH → 假阴性 → 模型会去"装一个已经有的工具"。
    这个八层发现本来就在仓库里（tool-run.ps1 用的就是它），不要另造一套。
    """
    if not os.path.isdir(MCP_DIR):
        return ""
    code = (
        "import sys,json;"
        f"sys.path.insert(0,r'{MCP_DIR}');"
        "import tool_autodiscover as A;"
        f"r=A.discover(r'{tool_id}', use_registry=True);"
        "print(r.get('command') or '')"
    )
    try:
        p = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=90)
        cmd = (p.stdout or b"").decode("utf-8", "replace").strip().splitlines()
        for ln in reversed(cmd):
            ln = ln.strip()
            if ln and os.path.isfile(ln):
                return ln
    except Exception:
        pass
    return ""


def local_candidates(tool_id: str, cap: dict) -> list[str]:
    """CLI 型工具的真实可能位置（**不止 PATH**）。

    2026-10-23 教训：jadx / apktool 都在仓库里（`Tool/mcp/Tool/safe/<id>/...`，
    形式是 .bat / .jar），但旧版只查 `where` → 报了假的"不可用"。
    这种假阴性会直接把模型推向"去装一个已经有的工具"—— 与需求完全相反。
    """
    out: list[str] = []
    exe = cached_exe(tool_id)
    if exe:
        out.append(exe)
    ctrl = (cap.get("control") or {})
    for key in ("headless_cmd", "gui_cmd", "mcp_register"):
        v = ctrl.get(key)
        if isinstance(v, str) and v:
            first = v.split()[0].strip('"')
            if os.path.isabs(first) and os.path.isfile(first):
                out.append(first)
    # 仓库自带的 safe 目录（jadx/apktool/r2/frida …）
    safe = os.path.join(TOOL, "mcp", "Tool", "safe")
    if os.path.isdir(safe):
        for pat in (f"{tool_id}/bin/{tool_id}.bat", f"{tool_id}/bin/{tool_id}.cmd",
                    f"{tool_id}/bin/{tool_id}.exe", f"{tool_id}/{tool_id}.jar",
                    f"{tool_id}/bin/{tool_id}"):
            p = os.path.join(safe, pat.replace("/", os.sep))
            if os.path.isfile(p):
                out.append(p)
        # 名字不完全一致的（r2/radare2、ida/idat…）交给 exe_candidates 扫
        base = os.path.join(safe, tool_id)
        if os.path.isdir(base):
            for dp, _dn, fn in os.walk(base):
                for f in fn:
                    if os.path.splitext(f)[1].lower() in (".exe", ".bat", ".cmd", ".jar") \
                            and tool_id.split("2")[0].lower()[:4] in f.lower():
                        out.append(os.path.join(dp, f))
                    if len(out) > 6:
                        break
    return out


def l0(tool_id: str, rt: dict, cap: dict) -> dict:
    modes = rt.get("modes") or []
    mcp_mode = next((m for m in modes if m.get("kind") in ("mcp-http", "mcp-stdio")), None)
    if mcp_mode:
        ep = mcp_mode.get("endpoint") or {}
        url = ep.get("url") or ""
        auth = (mcp_mode.get("auth") or {})
        token = ""
        if auth.get("authJson"):
            aj = auth["authJson"].replace("{exeDir}", os.path.dirname(cached_exe(tool_id) or "") or ".")
            token = str(load_json(aj).get("AuthToken") or "") if os.path.isfile(aj) else ""
        r = mcp_probe(url, auth.get("header", ""), token) if url else {"ok": False, "tools": 0, "detail": "无 endpoint"}
        return {"level": "L0", "kind": "mcp", "url": url, **r}

    # CLI / GUI 型：八层发现（与 tool-run 同一实现）→ 缓存 → 能力表 → PATH
    ad = autodiscover(tool_id)
    if ad:
        return {"level": "L0", "kind": "cli", "exe": ad, "ok": True,
                "tools": 0, "detail": ad + "  [autodiscover]"}
    hits = local_candidates(tool_id, cap)
    if hits:
        return {"level": "L0", "kind": "cli", "exe": hits[0],
                "ok": True, "tools": 0, "detail": hits[0]}
    exe = ""
    cands = (cap.get("exe_candidates") or []) + [tool_id]
    for c in cands:
        exe = where(c) or where(c + ".exe")
        if exe:
            break
    return {"level": "L0", "kind": "cli", "exe": exe,
            "ok": bool(exe), "tools": 0,
            "detail": exe if exe else "八层发现均未找到（可能在非标位置；用 --use <路径> 手工指定，不要直接判定为'没装'）"}


# ───────────────────────── L1 启动 ─────────────────────────

def l1_start(tool_id: str) -> dict:
    if not os.path.isfile(TOOL_RUN):
        return {"level": "L1", "ok": False, "detail": f"缺 {TOOL_RUN}"}
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                            "-File", TOOL_RUN, "-Tool", tool_id],
                           capture_output=True, timeout=180)
        out = (p.stdout or b"").decode("utf-8", "replace")
    except Exception as e:
        return {"level": "L1", "ok": False, "detail": f"启动异常：{type(e).__name__}"}

    # tool-run.ps1 最后一行是结构化 JSON；优先从里面取 status / error，不要整段糊给模型
    status, err = "", ""
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        status = str(d.get("status") or "")
        err = str(d.get("error") or d.get("note") or "")
    ready = status.upper() == "READY"
    if ready:
        detail = f"READY（{err or 'ok'}）"
    elif status:
        detail = f"status={status} {err}".strip()
    else:
        detail = (out.strip().splitlines()[-1][:160] if out.strip() else "无输出")
    return {"level": "L1", "ok": ready, "detail": detail, "status": status}


# ───────────────────────── L3 安装计划 ─────────────────────────

def l3_install(tool_id: str, cap: dict) -> dict:
    hint = (cap.get("install_hint") or "").strip()
    how = hint or "未知：请查官方文档 / GitHub README"
    return {"level": "L3", "ok": False, "auto": False,
            "plan": {"tool": tool_id, "what": cap.get("display") or tool_id,
                     "how": how, "needs_user": True},
            "detail": f"安装计划：{how[:90]}"}


# ───────────────────────── L4 求助 ─────────────────────────

def l4_ask(tool_id: str, stuck: str, why: str) -> dict:
    return {
        "level": "L4", "ok": False,
        "ask": {
            "title": f"我想用 {tool_id} 做这件事，但卡在 {stuck}",
            "detail": why,
            "options": {
                "A": f"我帮你把 {tool_id} 弄起来（我给你命令/我装）",
                "B": "换替代工具或替代路线",
                "C": "你继续用脚本兜底（我接受风险）",
            },
            "prompt": "直接回 A / B / C",
        },
        "detail": "需要用户决定",
    }


# ───────────────────────── 主流程 ─────────────────────────

def acquire(tool_id: str, allow_start: bool) -> dict:
    runtimes = (load_json(RUNTIMES).get("tools") or {})
    caps = (load_json(CAPS).get("tools") or {})
    rt = runtimes.get(tool_id) or {}
    cap = caps.get(tool_id) or {}
    steps = []

    s0 = l0(tool_id, rt, cap)
    steps.append(s0)
    if s0["ok"]:
        return {"tool": tool_id, "verdict": "USABLE", "at": "L0", "steps": steps,
                "note": "已可用，直接用；不需要启动"}

    if not allow_start:
        return {"tool": tool_id, "verdict": "NEED_START", "at": "L0", "steps": steps,
                "next": f"python Tool/scripts/tool-acquire.py --tool {tool_id} --start"}

    s1 = l1_start(tool_id)
    steps.append(s1)
    if s1["ok"]:
        s0b = l0(tool_id, rt, cap)
        steps.append(s0b)
        if s0b["ok"]:
            return {"tool": tool_id, "verdict": "USABLE", "at": "L1", "steps": steps,
                    "note": "启动后已可用。⚠️ 若它是 MCP 型：必须确认本会话 ALL_TOOLS 里有该命名空间，"
                            "否则要重启宿主（工具只在会话启动时注册）"}
        return {"tool": tool_id, "verdict": "STARTED_BUT_NOT_LINKED", "at": "L1", "steps": steps,
                "next": "MCP 型工具启动后需重启宿主才会注册；或改用 stdio 桥"}

    s3 = l3_install(tool_id, cap)
    steps.append(s3)
    s4 = l4_ask(tool_id, "L1 启动失败", s1["detail"])
    steps.append(s4)
    return {"tool": tool_id, "verdict": "NEED_USER", "at": "L4", "steps": steps,
            "note": "⚠️ 到此必须发 ASK 卡，不许静默改用手搓脚本"}


def list_tools() -> int:
    runtimes = (load_json(RUNTIMES).get("tools") or {})
    caps = (load_json(CAPS).get("tools") or {})
    print(f"{'tool':12s} {'kind':10s} {'mcp':4s} {'headless':9s} {'display'}")
    for tid in sorted(set(runtimes) | set(caps)):
        rt = runtimes.get(tid) or {}
        cap = caps.get(tid) or {}
        kinds = ",".join(sorted({m.get("kind", "?") for m in (rt.get("modes") or [])})) or "-"
        c = cap.get("capabilities") or {}
        print(f"{tid:12s} {kinds:10s} {str(c.get('mcp', '?')):4s} {str(c.get('headless', '?')):9s} "
              f"{cap.get('display', '')}")
    return 0


def selftest() -> int:
    print("== tool-acquire 自检 ==")
    r = acquire("x64dbg", allow_start=False)
    d0 = r["steps"][0].get("detail", "") if r.get("steps") else ""
    print(f"x64dbg L0: {r['verdict']}  {d0}")
    # 判据演进（两次踩坑记录）：
    #   v1 只判 "steps 非空" → acquire() 总会先 append s0 ⇒ **永远 PASS**（FINAL-2 A2）
    #   v2 判 verdict == USABLE → 等于要求「GUI 此刻正在运行」，新机器/没开调试器时**必红**，
    #      门禁从此依赖活体状态（实测踩到：x64dbg 端口在听但 401 ⇒ 48/48 掉到 47/48）
    #   v3（现行）判**鉴别力**：① 一定要真探过（有 detail）；② 端口在听但拒绝(401/403)时
    #      **绝不许**判 USABLE（这才是那个 fail-open 的实质）；③ verdict 必须是诚实取值之一。
    honest = {"USABLE", "NEED_START", "STARTED_BUT_NOT_LINKED", "NEED_USER"}
    fail_open = (r["verdict"] == "USABLE") and ("401" in d0 or "403" in d0 or "refus" in d0.lower())
    probed = bool(d0.strip())
    _ok = (not fail_open) and probed and (r["verdict"] in honest)
    print("PASS" if _ok else "FAIL",
          "（反 fail-open：端口在听但拒绝时不许判 USABLE；不要求 GUI 正在运行）")
    return 0 if _ok else 1


def sweep() -> int:
    """本机工具体检：能力表里每个 tool_id 探一次（缓存优先），输出可用/缺失。"""
    import os as _os
    import sys as _sys
    sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "mcp"))
    import tool_autodiscover as _T

    caps = _T._capabilities_table().get("tools", {})
    rows, miss = [], []
    for tid in sorted(caps):
        try:
            r = _T.discover(tid)
        except Exception as e:  # noqa: BLE001
            rows.append((tid, False, "EXC " + str(e)[:40], "-"))
            miss.append(tid)
            continue
        ok = bool(r.get("available"))
        rows.append((tid, ok, str(r.get("command") or "")[:52], str(r.get("via") or "-")))
        if not ok:
            miss.append(tid)
    print("本机工具体检（能力表 %d 项；缓存优先，缺失项见 `--tool <id>` 拿安装建议）" % len(caps))
    print("%-16s %-5s %-10s %s" % ("tool_id", "可用", "via", "路径"))
    print("-" * 92)
    for tid, ok, cmd, via in rows:
        print("%-16s %-5s %-10s %s" % (tid, "是" if ok else "否", via, cmd))
    print("-" * 92)
    print("可用 %d / 缺失 %d" % (len(rows) - len(miss), len(miss)))
    if miss:
        print("缺失：" + "、".join(miss))
        print("→ 装好后用 `tool-acquire.py --add <tool_id> --exe <真实exe路径>` 登记（只写本机，不进仓库）")
    return 0


def add_tool(tool_id: str, exe: str) -> int:
    """把本机某个工具的**真实路径**登记进机器级缓存（不进仓库）。"""
    import os as _os
    import sys as _sys
    sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "mcp"))
    import tool_autodiscover as _T

    if not tool_id:
        print("用法：--add <tool_id> --exe <exe 路径>")
        return 4
    p = _os.path.expanduser(exe or "")
    if not p or not _os.path.isfile(p):
        print("[拒] 路径不存在：%r\n  不猜名字 —— 请给真实 exe 路径（可用 --sweep 看缺哪些，"
              "或 --tool <id> 让发现链自己找）" % exe)
        return 4
    _T._cache_put(_T.normalize_tool_id(tool_id), p, "manual")
    print("[OK] 已登记 %s → %s（只写 %s，不进仓库）"
          % (tool_id, p, _T._PATH_CACHE_FILE))
    print("\n如需让**所有机器**都知道这个工具（而不是只本机），把下面条目补进 "
          "Tool/config/tool-capabilities.json 的 tools：")
    print('  "%s": {"display": "%s", "exe_candidates": ["%s"], '
          '"capabilities": {"cli": true, "gui": false, "headless": null, "mcp": false}, '
          '"install_hint": "%s"}'
          % (tool_id, tool_id, _os.path.basename(p), "按官方安装方式；本机路径由 --add 记住"))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="工具获取阶梯：探活→启动→连上→装→求助")
    ap.add_argument("--tool", default="")
    ap.add_argument("--start", action="store_true", help="允许 L1 自动启动")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--sweep", action="store_true", help="本机工具体检（能力表逐项探活）")
    ap.add_argument("--add", default="", help="登记本机新工具：--add <id> --exe <路径>")
    ap.add_argument("--exe", default="", help="配合 --add 的真实可执行文件路径")
    a = ap.parse_args()

    if a.list:
        return list_tools()
    if a.sweep:
        return sweep()
    if a.add:
        return add_tool(a.add, a.exe)
    if a.selftest:
        return selftest()
    if not a.tool:
        ap.print_help()
        return 4

    r = acquire(a.tool, a.start)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=1))
    else:
        print(f"[{r['tool']}] 结论：{r['verdict']}（停在 {r['at']}）")
        for s in r["steps"]:
            flag = "OK  " if s.get("ok") else "FAIL"
            print(f"  {flag} {s['level']:3s} {s.get('detail', '')}")
        for k in ("next", "note"):
            if r.get(k):
                print(f"  → {r[k]}")
        if r["verdict"] == "NEED_USER":
            plan = (r["steps"][-2].get("plan") or {}) if len(r["steps"]) >= 2 else {}
            if plan:
                print(f"\n  安装/修复计划：{plan.get('how', '')}")
            ask = r["steps"][-1].get("ask") or {}
            print("\n【需要你选】" + str(ask.get("title", "")))
            for k, v in (ask.get("options") or {}).items():
                print(f"  {k} {v}")
            print(ask.get("prompt", ""))

    return {"USABLE": 0, "NEED_START": 1, "NEED_USER": 3,
            "STARTED_BUT_NOT_LINKED": 3}.get(r["verdict"], 2)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
