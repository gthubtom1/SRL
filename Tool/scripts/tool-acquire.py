#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""工具获取：发现、验证、按需启动和白名单安装。

仅探测：--tool <id> --json；允许启动时加 --start；已有安装授权时加 --install。
CLI 必须通过已声明的身份探针才报 USABLE；未知工具路径报 FOUND_NO_VERIFY。
MCP 必须完成独立协议握手，session_verified=false 提醒宿主另查本会话工具表。
启动、安装或协议失败时返回实际原因和下一步，供模型继续修复或选择替代能力。

退出码：0=已验证身份或独立连接，1=需启动，2=仍需处理/未验证，4=输入或身份错误。
"""

from __future__ import annotations

import argparse
import json
import os
from lib import mcp_http
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
REPO = os.path.dirname(TOOL)
TOOL_RUN = os.path.join(HERE, "tool-run.ps1")
RUNTIMES = os.path.join(TOOL, "config", "tool-runtimes.json")
CAPS = os.path.join(TOOL, "config", "tool-capabilities.json")


def load_json(p: str, strict: bool = False) -> dict:
    try:
        with open(p, encoding="utf-8-sig") as f:
            result = json.load(f)
        if not isinstance(result, dict):
            raise ValueError('JSON 顶层必须是对象')
        return result
    except Exception:
        if strict:
            raise
        return {}


# ───────────────────────── L0 探活 ─────────────────────────

def mcp_probe(url: str, auth_header: str = "", auth_token: str = "", transport: str = "http") -> dict:
    """Perform an independent handshake; host-session registration remains unverified."""
    headers = {auth_header: f"Bearer {auth_token}"} if auth_header and auth_token else {}

    result = mcp_http.probe_endpoint({'url': url, 'transport': transport, 'headers': headers})
    count = result.get('tools', 0)
    return {**result, 'ok': result['ok'] and count > 0, 'tools': count,
            'detail': (f'独立握手发现 {count} 个工具；当前宿主工具表仍需核验' if result['ok'] else
                       'MCP 握手失败: ' + result.get('error', 'unknown'))}


MCP_DIR = os.path.join(TOOL, "mcp")


def _discovery_module():
    if MCP_DIR not in sys.path:
        sys.path.insert(0, MCP_DIR)
    import tool_autodiscover
    return tool_autodiscover


def autodiscover(tool_id: str) -> dict:
    """Preserve executable versus Python-library discovery and verification data."""
    if not os.path.isdir(MCP_DIR):
        return {}
    code = ("import sys,json; sys.path.insert(0,sys.argv[1]); import tool_autodiscover as A; "
            "print(json.dumps(A.discover(sys.argv[2],use_registry=True)))")
    try:
        p = subprocess.run([sys.executable, "-c", code, MCP_DIR, tool_id], capture_output=True, timeout=90)
        if p.returncode != 0:
            return {}
        cmd = (p.stdout or b"").decode("utf-8", "replace").strip().splitlines()
        for ln in reversed(cmd):
            ln = ln.strip()
            try:
                result = json.loads(ln)
            except ValueError:
                continue
            if isinstance(result, dict):
                return result
    except Exception:
        pass
    return {}




def l0(tool_id: str, rt: dict, cap: dict) -> dict:
    modes = rt.get("modes") or []
    failed_mcp = None
    discovery = None
    for mcp_mode in (m for m in modes if (m.get('endpoint') or {}).get('url')):
        ep = mcp_mode.get("endpoint") or {}
        url = ep.get("url") or ""
        auth = (mcp_mode.get("auth") or {})
        token = ""
        if auth.get("authJson"):
            if discovery is None:
                discovery = autodiscover(tool_id)
            aj = auth["authJson"].replace("{exeDir}", os.path.dirname(discovery.get('command') or '') or '.')
            token = str(load_json(aj).get("AuthToken") or "") if os.path.isfile(aj) else ""
        r = mcp_probe(url, auth.get("header", ""), token, ep.get('transport', 'http'))
        failed_mcp = {"level": "L0", "kind": "mcp", "url": url, **r}
        if r['ok']:
            return failed_mcp
    declared = cap.get('capabilities') or {}
    if failed_mcp and not (declared.get('cli') or declared.get('headless')):
        return failed_mcp

    # Reuse the common discoverer without discarding its result kind.
    ad = discovery if discovery is not None else autodiscover(tool_id)
    if ad.get('available'):
        if ad.get('kind') == 'python_lib':
            return {'level': 'L0', 'kind': 'python_lib', 'ok': True, 'tools': 0,
                    'module': ad['module'], 'interpreter': ad['interpreter'],
                    'detail': '已在指定解释器中成功导入 ' + ad['module']}
        exe = ad.get('command') or ''
        if os.path.isfile(exe):
            return {"level": "L0", "kind": "cli", "exe": exe, "ok": True,
                    "tools": 0, "detail": exe + "  [autodiscover]"}
    # Do not bypass the shared discoverer's identity/path filters with a second
    # cache or PATH implementation.
    return {"level": "L0", "kind": "cli", "exe": '', 'ok': False, 'tools': 0,
            'detail': '统一发现器未找到匹配工具；可用 --add <id> --exe <路径> 登记现有安装后复探'}


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
    ready = p.returncode == 0 and status.upper() in ("READY", "ALREADY_READY", "CLI_READY")
    if ready:
        detail = f"READY（{err or 'ok'}）"
    elif status:
        detail = f"status={status} {err}".strip()
    else:
        detail = (out.strip().splitlines()[-1][:160] if out.strip() else "无输出")
    return {"level": "L1", "ok": ready, "detail": detail, "status": status, "returncode": p.returncode}


# ───────────────────────── L3 安装计划 ─────────────────────────

def l3_install(tool_id: str, cap: dict) -> dict:
    hint = (cap.get("install_hint") or "").strip()
    how = hint or "未知：请查官方文档 / GitHub README"
    try:
        plan = _discovery_module().install_plan(tool_id)
    except Exception as exc:
        return {'level': 'L3', 'ok': False, 'auto': False, 'plan': {},
                'detail': '安装计划无法读取: ' + type(exc).__name__}
    plan['how'] = how
    return {"level": "L3", "ok": False, "auto": bool(plan.get('has_plan') and plan.get('auto_allowed')),
            "plan": plan,
            "detail": f"安装计划：{how[:90]}"}





# ───────────────────────── 主流程 ─────────────────────────

def _assess_available(tool_id, steps, at):
    result = {'tool': tool_id, 'verdict': 'USABLE', 'at': at, 'steps': steps,
              'session_verified': False, 'runtime_verified': False}
    latest = steps[-1]
    if latest.get('kind') == 'python_lib':
        result.update(import_verified=True, module=latest['module'], interpreter=latest['interpreter'],
                      note='解释器导入成功；任务所需 API 和产物另行验证')
        return result
    if latest.get('kind') == 'mcp':
        result['connection_verified'] = True
        result['note'] = '独立 MCP 握手成功；当前宿主仍需核对本会话工具表'
        return result
    from lib import tool_identity
    try:
        identity = tool_identity.probe(tool_id, latest.get('exe'))
    except Exception as exc:
        identity = {'ok': None, 'verified': False, 'why': type(exc).__name__}
    result['identity'] = identity
    if identity.get('ok') is False:
        result['verdict'] = 'USABLE_BUT_BROKEN'
        result['next'] = '检查工具身份和依赖，修复后重新探测'
    elif identity.get('ok') is not True:
        result['verdict'] = 'FOUND_NO_VERIFY'
        result['next'] = '路径已找到；按官方接口完成任务所需的能力验证后再使用'
    return result


def acquire(tool_id: str, allow_start: bool, allow_install: bool = False) -> dict:
    try:
        runtimes = load_json(RUNTIMES, strict=True).get('tools')
        caps = load_json(CAPS, strict=True).get('tools')
        if not isinstance(runtimes, dict) or not isinstance(caps, dict):
            raise ValueError('tools 必须是对象')
        rt, cap = runtimes.get(tool_id, {}), caps.get(tool_id, {})
        if not isinstance(rt, dict) or not isinstance(cap, dict):
            raise ValueError('工具声明必须是对象')
        modes = rt.get('modes', [])
        if not isinstance(modes, list) or any(not isinstance(m, dict) for m in modes):
            raise ValueError('modes 必须是对象数组')
        if not isinstance(cap.get('capabilities', {}), dict) or any(
                not isinstance(m.get(field, {}), dict) for m in modes for field in ('endpoint', 'auth')):
            raise ValueError('capabilities/endpoint/auth 必须是对象')
        for mode in modes:
            for field, keys in (('endpoint', ('url', 'transport')), ('auth', ('header', 'authJson'))):
                if any(not isinstance(mode.get(field, {}).get(key, ''), str) for key in keys):
                    raise ValueError('endpoint/auth 字段必须是字符串')
        if not isinstance(cap.get('install_hint', ''), str):
            raise ValueError('install_hint 必须是字符串')
    except Exception as exc:
        return {'tool': tool_id, 'verdict': 'CONFIG_ERROR', 'at': 'config', 'steps': [],
                'reason': str(exc), 'session_verified': False, 'runtime_verified': False}
    steps = []

    s0 = l0(tool_id, rt, cap)
    steps.append(s0)
    if s0["ok"]:
        return _assess_available(tool_id, steps, 'L0')

    if not allow_start and not allow_install:
        return {"tool": tool_id, "verdict": "NEED_START", "at": "L0", "steps": steps,
                "next": f"python Tool/scripts/tool-acquire.py --tool {tool_id} --start"}

    s1 = l1_start(tool_id) if allow_start else {'level': 'L1', 'ok': False, 'detail': '本次未请求启动'}
    if allow_start:
        steps.append(s1)
    if s1['ok']:
        s0b = l0(tool_id, rt, cap)
        steps.append(s0b)
        if s0b["ok"]:
            return _assess_available(tool_id, steps, 'L1')
        return {"tool": tool_id, "verdict": "STARTED_BUT_NOT_LINKED", "at": "L1", "steps": steps,
                "next": "检查独立握手失败原因，并由宿主重新加载配置、核对本会话工具表"}

    s3 = l3_install(tool_id, cap)
    steps.append(s3)
    install_plan_error = (s3.get("plan") or {}).get("config_error")
    if install_plan_error:
        return {
            "tool": tool_id, "verdict": "CONFIG_ERROR", "at": "L3",
            "steps": steps, "config_error": install_plan_error,
            "reason": install_plan_error, "session_verified": False,
            "runtime_verified": False,
            "next": "修复 Tool/config/tool-install.json 后重新发现，禁止按坏清单执行安装",
        }
    if allow_install and s3.get('auto'):
        installed = _discovery_module().propose_install(tool_id, execute=True)
        steps.append({'level': 'L3', 'ok': bool(installed.get('success')), 'install_attempt': installed,
                      'detail': '已尝试白名单安装并复探'})
        if installed.get('success'):
            after = l0(tool_id, rt, cap)
            if not after['ok'] and allow_start:
                steps.append(l1_start(tool_id))
                after = l0(tool_id, rt, cap)
            steps.append(after)
            if after['ok']:
                return _assess_available(tool_id, steps, 'L3')
    return {'tool': tool_id, 'verdict': 'NEED_ACTION', 'at': 'L3', 'steps': steps,
            'session_verified': False, 'runtime_verified': False,
            'next': '结合失败原因继续安装、修复或选择替代工具；已有授权范围内由智能体继续处理，缺少必要凭据或人工步骤时再询问用户'}


def tool_catalog() -> dict:
    """Return the machine-readable catalog, failing closed on malformed config."""
    runtimes_doc = load_json(RUNTIMES, strict=True)
    caps_doc = load_json(CAPS, strict=True)
    runtimes = runtimes_doc.get("tools")
    caps = caps_doc.get("tools")
    if not isinstance(runtimes, dict):
        raise ValueError("tool-runtimes.json#tools 必须是对象")
    if not isinstance(caps, dict):
        raise ValueError("tool-capabilities.json#tools 必须是对象")
    rows = []
    for tid in sorted(set(runtimes) | set(caps)):
        rt = runtimes.get(tid) or {}
        cap = caps.get(tid) or {}
        if not isinstance(rt, dict) or not isinstance(cap, dict):
            raise ValueError("工具条目必须是对象: %s" % tid)
        modes = rt.get("modes") or []
        if not isinstance(modes, list) or any(not isinstance(mode, dict) for mode in modes):
            raise ValueError("工具 modes 必须是对象数组: %s" % tid)
        capabilities = cap.get("capabilities") or {}
        if not isinstance(capabilities, dict):
            raise ValueError("工具 capabilities 必须是对象: %s" % tid)
        rows.append({
            "tool": tid,
            "display": cap.get("display", ""),
            "kinds": sorted({str(mode.get("kind", "?")) for mode in modes}),
            "capabilities": {
                "mcp": capabilities.get("mcp"),
                "headless": capabilities.get("headless"),
                "cli": capabilities.get("cli"),
                "gui": capabilities.get("gui"),
            },
        })
    return {"ok": True, "schema": "seep.tool-catalog/1",
            "tool_count": len(rows), "tools": rows}


def list_tools(json_output: bool = False) -> int:
    try:
        catalog = tool_catalog()
    except Exception as exc:
        if json_output:
            print(json.dumps({"ok": False, "schema": "seep.tool-catalog/1",
                              "error": str(exc), "tool_count": 0, "tools": []},
                             ensure_ascii=False, indent=1))
        print("[tool-acquire] 工具目录读取失败: %s" % exc, file=sys.stderr)
        return 2
    if json_output:
        print(json.dumps(catalog, ensure_ascii=False, indent=1))
        return 0
    print(f"{'tool':12s} {'kind':10s} {'mcp':4s} {'headless':9s} {'display'}")
    for row in catalog["tools"]:
        kinds = ",".join(row["kinds"]) or "-"
        capabilities = row["capabilities"]
        print(f"{row['tool']:12s} {kinds:10s} {str(capabilities.get('mcp', '?')):4s} "
              f"{str(capabilities.get('headless', '?')):9s} {row['display']}")
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
    honest = {"USABLE", "NEED_START", "STARTED_BUT_NOT_LINKED", "NEED_ACTION", "FOUND_NO_VERIFY", "USABLE_BUT_BROKEN"}
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
    print("%-16s %-5s %-10s %s" % ("tool_id", "发现", "via", "路径"))
    print("-" * 92)
    for tid, ok, cmd, via in rows:
        print("%-16s %-5s %-10s %s" % (tid, "是" if ok else "否", via, cmd))
    print("-" * 92)
    print("已发现 %d / 未发现 %d；路径发现不等于任务运行验证" % (len(rows) - len(miss), len(miss)))
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
    if not _T._cache_put(_T.normalize_tool_id(tool_id), p, "manual"):
        print("[FAIL] 路径缓存写入失败，未完成登记")
        return 1
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
    ap.add_argument('--install', action='store_true', help='按已有授权尝试白名单安装并复探')
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--sweep", action="store_true", help="本机工具体检（能力表逐项探活）")
    ap.add_argument("--add", default="", help="登记本机新工具：--add <id> --exe <路径>")
    ap.add_argument("--exe", default="", help="配合 --add 的真实可执行文件路径")
    a = ap.parse_args()

    if a.list:
        return list_tools(json_output=a.json)
    if a.sweep:
        return sweep()
    if a.add:
        return add_tool(a.add, a.exe)
    if a.selftest:
        return selftest()
    if not a.tool:
        ap.print_help()
        return 4

    r = acquire(a.tool, a.start, a.install)

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

    return {"USABLE": 0, "NEED_START": 1, "NEED_ACTION": 2, "FOUND_NO_VERIFY": 2, 'CONFIG_ERROR': 4, "USABLE_BUT_BROKEN": 4,
            "STARTED_BUT_NOT_LINKED": 3}.get(r["verdict"], 2)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
