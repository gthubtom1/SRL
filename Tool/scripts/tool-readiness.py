#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tool-readiness.py —— 六个"真有通路"的工具：探测 → 安装计划 → 自检 → 一张就绪表。

为什么要有这个文件（用户口径：让它更能干）：
    工具账本声明了一堆工具，但用户真正用得上的只有 6 条通路：r2/rabin2、jadx、apktool、
    tshark、ida、x64dbg。过去缺工具时 Agent 拿到的是一句报错或"去装吧"，
    于是它就停下来等人 —— 这就是能力浪费。正确的链路是：
        **能探测到 → 缺了给可执行安装计划（默认自动装）→ 装完自检 → 一句话调用**
    本脚本负责这条链路的前三段，并把结果压成一张 6 行表；第四段在 tool-runtimes.json 的 modes。

判据（铁律，别改回去）：
    · **文件存在 ≠ READY**。必须真跑一次自检（rabin2 -v / jadx --version / apktool --version /
      tshark -v）并拿到**匹配期望正则**的输出；GUI-only 的 ida/x64dbg 没有 --version，
      PE 头只能核验格式/架构，状态仍为 FOUND_NO_VERIFY，启动与 MCP 连接需另验。
      历史教训：`Tool/scripts/lib/tool_identity.py` 记着"rabin2.exe 其实是 radare2.exe 改名"
      把一条命令卡死 900 秒 —— 所以 r2 的 expect 必须打出 'rabin2 <版本>'。
    · 探测来源按 tool-runtimes.json 的 `probe` 字段：环境变量 → PATH → 仓库内置副本
      （Tool/mcp/Tool/safe/**）→ 常见安装目录通配（{drive}/*/Wireshark 之类）。
    · 安装**只生成、不执行**：命令写在 tool-runtimes.json 的 `install` 字段（供 seep_ensure_tool
      使用），本脚本只打印 + 标注"需管理员/需联网/需替换路径"。
    · 本脚本**不联网、不装东西、不改 PATH**。

用法：
    python Tool/scripts/tool-readiness.py                 # 人读：6 行表 + MISSING 的安装计划
    python Tool/scripts/tool-readiness.py --json          # 机读（Agent 读这个）
    python Tool/scripts/tool-readiness.py --no-verify     # 只探测不跑自检（快，用于排障）
    python Tool/scripts/tool-readiness.py --budget 15     # 放宽单个工具的目录搜索预算（秒）

退出码（这就是 check.py 的 `tool-readiness` 套件判据）：
    0 = **探测机制本身可用**：6 行齐全 / 每行状态合法 / 每个 MISSING 都带安装命令
        （★ 不要求本机 6 个都 READY —— 那会让换机器必红）
    1 = 机制坏了：行数不对 / 状态非法 / MISSING 无安装命令 / 6 个全 MISSING 且无任何计划

探测结果取决于"这台机器"，机制是否可用取决于"这份代码"。别把两者混成一个判据。
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
import time
import unicodedata

from lib import process_tree

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)                          # Tool/
ROOT = os.path.dirname(TOOL)                          # 仓库根
RUNTIMES = os.path.join(TOOL, "config", "tool-runtimes.json")
LIB = os.path.join(HERE, "lib")

# 这 6 个是"真有通路"的工具（能力账本里声明了、且我们自己接过命令）。
# 顺序即展示顺序：先原生逆向（r2/ida/x64dbg），再安卓（jadx/apktool），最后协议（tshark）。
TOOLS = ("r2", "jadx", "apktool", "tshark", "ida", "x64dbg")
STATUSES = ("READY", "FOUND_NO_VERIFY", "MISSING")
DISPLAY = {"r2": "r2/rabin2", "jadx": "jadx", "apktool": "apktool",
           "tshark": "tshark", "ida": "ida", "x64dbg": "x64dbg"}

# 中文 Windows 控制台默认 cp936：本脚本自己打中文与表格线，不重建 stdout 就会自崩。
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 —— 流被替换/已关闭时忽略
        pass

# 子进程统一 env：不设 PYTHONIOENCODING 时，子工具打一个非 GBK 字符就会炸成 Traceback，
# 看起来像"工具坏了"，其实是编码问题。
CHILD_ENV = dict(os.environ, PYTHONIOENCODING="utf-8")

MACHINES = {0x014C: "I386", 0x8664: "AMD64", 0xAA64: "ARM64", 0x01C4: "ARMNT"}


# ---------------------------------------------------------------- 小工具
def _width(s):
    """显示宽度：中文/全角算 2 格，否则 1（表格对齐必须按显示宽度，不能按 len）。"""
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in s)


def _clip(s, n):
    s = s or ""
    if _width(s) <= n:
        return s
    out = ""
    for ch in s:
        if _width(out + ch) > n - 3:
            break
        out += ch
    return out + "..."


def _pad(s, n):
    return s + " " * max(0, n - _width(s))


def _clip_mid(s, n, tail=22):
    """中间省略：路径列必须保留**文件名**（尾部），只砍中间的目录层。

    为什么不能像其它列那样直接砍尾：`仓库内置: Tool\\mcp\\...\\rabin2.exe`
    砍掉尾巴剩下一串目录，等于没告诉用户“哪个可执行文件”。
    """
    s = s or ""
    if _width(s) <= n or n <= tail + 6:
        return _clip(s, n)
    head_w = n - tail - 3
    head, hw = "", 0
    for ch in s:
        w = _width(ch)
        if hw + w > head_w:
            break
        head += ch
        hw += w
    t, tw = "", 0
    for ch in reversed(s):
        w = _width(ch)
        if tw + w > tail:
            break
        t = ch + t
        tw += w
    return head + "..." + t


def _drives():
    """本机存在的盘符根（C:/ D:/ …）—— 让通配能扫到"装在哪都可能"的工具，又不写死盘符。"""
    out = []
    if os.name != "nt":
        return out
    for ch in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        p = ch + ":/"
        try:
            if os.path.exists(p):
                out.append(p)
        except OSError:
            continue
    return out


def _placeholders():
    home = os.path.expanduser("~")
    return {
        "home": home,
        "repo": ROOT,
        "localappdata": os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local"),
        "appdata": os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming"),
        "programfiles": os.environ.get("ProgramFiles") or os.environ.get("ProgramW6432") or "",
        "programfilesx86": os.environ.get("ProgramFiles(x86)") or "",
    }


def _expand(pattern):
    """把 probe.globs 里的 {home}/{programfiles}/…/{drive} 展开成具体模式（缺的占位符整条跳过）。"""
    ph = _placeholders()
    pats = [pattern]
    if "{drive}" in pattern:
        pats = [pattern.replace("{drive}", d) for d in _drives()]
    out = []
    for p in pats:
        bad = False
        for k, v in ph.items():
            if "{%s}" % k in p:
                if not v:
                    bad = True
                    break
                p = p.replace("{%s}" % k, v)
        if not bad:
            out.append(p.replace("\\", "/"))
    return out


def _rel(path):
    """仓库内路径显示成相对路径（表格里短一截、也不泄露用户名）。"""
    try:
        rel = os.path.relpath(path, ROOT)
    except ValueError:
        return path
    return rel if not rel.startswith("..") else path


# ---------------------------------------------------------------- 探测
def probe(spec, budget=8.0):
    """按 probe 字段找可执行文件。返回 (hits, truncated)。

    hits: [{"path","via","viaDetail"}]，via ∈ env / PATH / repo / dir
    层次顺序是"越可信越靠前"：显式环境变量 > PATH（系统装）> 仓库内置副本 > 磁盘通配。
    注意：仓库内置副本排在 PATH 之后 —— 用户装了新版就以系统版为准。
    """
    seen, hits = set(), []
    truncated = False
    deadline = time.time() + max(1.0, float(budget))

    def add(p, via, detail=""):
        ap = os.path.abspath(p)
        key = os.path.normcase(ap)
        if key in seen:
            return
        seen.add(key)
        hits.append({"path": ap, "via": via, "viaDetail": detail})

    for var in spec.get("envVars") or []:
        v = (os.environ.get(var) or "").strip().strip('"')
        if v and os.path.isfile(v):
            add(v, "env", "%s 环境变量" % var)

    for name in spec.get("names") or []:
        w = shutil.which(name)
        if w:
            add(w, "PATH", "PATH 上的 %s" % name)

    for rel in spec.get("repoPaths") or []:
        p = os.path.join(ROOT, rel.replace("/", os.sep))
        if os.path.isfile(p):
            add(p, "repo", "仓库内置副本")

    for pat in spec.get("globs") or []:
        for one in _expand(pat):
            if time.time() > deadline:
                truncated = True
                break
            try:
                # ** 才允许递归；盘符通配一律非递归（扫全盘会把检查拖成几分钟）
                for f in glob.iglob(one, recursive="**" in one):
                    if os.path.isfile(f):
                        add(f, "dir", one)
                    if time.time() > deadline:
                        truncated = True
                        break
            except OSError:
                continue
            if truncated:
                break
        if truncated:
            break
    return hits, truncated


# ---------------------------------------------------------------- 自检
def _pe_info(path):
    """PE 头自检：MZ → e_lfanew → 'PE\\0\\0' → machine。给没有 --version 的 GUI 工具用。"""
    try:
        with open(path, "rb") as f:
            head = f.read(0x40)
            size = os.fstat(f.fileno()).st_size
            lfanew = int.from_bytes(head[0x3C:0x40], 'little')
            if len(head) < 0x40 or lfanew < 0x40 or lfanew + 6 > size:
                return {'ok': False, 'why': 'e_lfanew 越界（疑似截断/伪造）'}
            f.seek(lfanew)
            pe = f.read(6)
    except OSError as e:
        return {"ok": False, "why": "读不到文件：%s" % e}
    if head[:2] != b"MZ":
        return {"ok": False, "why": "不是 PE（无 MZ 头）"}
    if pe[:4] != b"PE\0\0":
        return {"ok": False, "why": "不是 PE（无 PE\\0\\0 签名）"}
    machine = int.from_bytes(pe[4:6], "little")
    return {"ok": True, "machine": MACHINES.get(machine, "0x%04X" % machine), "size": size}


def verify(spec, exe, timeout_override=None):
    """跑最小自检。kind=exec 跑真实 argv 并要求输出匹配 expect；kind=pe 解析 PE 头。"""
    kind = (spec.get("kind") or "exec").lower()
    tmo = float(timeout_override or spec.get("timeoutSec") or 20)

    if kind == "pe":
        info = _pe_info(exe)
        if not info.get("ok"):
            return {"ok": False, "line": "PE 自检失败：%s" % info.get("why"), "exe": exe,
                    "why": info.get("why") or "PE 自检失败"}
        want = [str(x).upper() for x in (spec.get("expectMachine") or [])]
        if want and info["machine"].upper() not in want:
            return {"ok": False, "exe": exe,
                    "line": "PE machine=%s（期望 %s）" % (info["machine"], "/".join(want)),
                    "why": "架构不符（32/64 位拿错了）"}
        sib = [n for n in (spec.get("informSiblings") or [])
               if os.path.isfile(os.path.join(os.path.dirname(exe), n))]
        inform = spec.get("informSiblings") or []
        mb = info["size"] / 1048576.0
        size_txt = ("%.1f MB" % mb) if mb >= 1 else ("%.0f KB" % (info["size"] / 1024.0))
        line = "PE %s · %s · %s" % (info["machine"], size_txt, os.path.basename(exe))
        if inform:
            line += "（依赖 %d/%d）" % (len(sib), len(inform))
        return {"ok": True, "runtime_verified": False, "line": line, "exe": exe,
                "why": "PE 格式和架构通过；尚未验证工具启动、授权、依赖和 MCP 连接"}

    args = [str(a) for a in (spec.get("args") or [])]
    # Probe each discovered candidate itself. Substituting another executable
    # would attribute that program's result and provenance to this candidate.
    target = exe
    argv = [target] + args
    # .bat/.cmd 必须走 cmd /c：CreateProcess 直接跑批处理会静默失败（实测 rc=1、输出空）
    if os.name == "nt" and target.lower().endswith((".bat", ".cmd")):
        argv = ["cmd", "/c", target] + args

    t0 = time.time()
    try:
        p = process_tree.run(argv, cwd=os.path.dirname(target) or None,
                             capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=tmo, stdin=subprocess.DEVNULL,
                             env=CHILD_ENV)
        out = (p.stdout or "") + ("\n" if (p.stdout and p.stderr) else "") + (p.stderr or "")
        rc = p.returncode
    except subprocess.TimeoutExpired:
        return {"ok": False, "exe": target, "rc": None, "secs": time.time() - t0,
                "line": "自检超时 >%gs（stdin 已关仍不退出）" % tmo,
                "why": "超时（多半进了交互模式）"}
    except OSError as e:
        return {"ok": False, "exe": target, "rc": None, "secs": time.time() - t0,
                "line": "无法执行：%s" % e, "why": "无法执行：%s" % e}

    secs = time.time() - t0
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    first = lines[0] if lines else ""
    expect = spec.get("expect")
    allow = spec.get("allowRc")
    allow = [0] if allow is None else allow
    hit = None
    if expect:
        m = re.search(expect, out, re.M)
        hit = m.group(0).strip() if m else None

    if not first:
        return {"ok": False, "exe": target, "rc": rc, "secs": secs,
                "line": "(无输出，rc=%s)" % rc, "why": "自检没有任何输出"}
    if expect and not hit:
        return {"ok": False, "exe": target, "rc": rc, "secs": secs,
                "line": first,
                "why": "输出不匹配期望 /%s/（可能是别的程序改名冒充）" % expect}
    if rc not in allow:
        return {"ok": False, "exe": target, "rc": rc, "secs": secs, "line": first,
                "why": "退出码 %s 不在允许值 %s" % (rc, allow)}
    line = first if (not hit or hit in first) else "%s → %s" % (first, hit)
    return {"ok": True, "exe": target, "rc": rc, "secs": secs, "line": line,
            "why": "自检输出命中"}


def identity(tid, spec, exe):
    """行为身份探针（可选）：复用 Tool/scripts/lib/tool_identity.py 的 PROBES。

    为什么还要这一层：`--version` 能过，但二进制可能是被改名/被换过的副本。
    tool_identity 的探针是"真跑一次功能"（如 rabin2 -I），能抓出这种情况。
    """
    want = spec.get("identityProbe")
    if not want:
        return None
    try:
        if LIB not in sys.path:
            sys.path.insert(0, LIB)
        import tool_identity  # noqa: PLC0415 —— 可选依赖，缺了不影响主判据
        r = tool_identity.probe(want, os.path.abspath(exe))
        return {"ok": r.get("ok"), "why": (r.get("why") or "").strip()[:90]}
    except Exception as e:  # noqa: BLE001
        return {"ok": None, "why": "行为探针不可用：%s" % str(e)[:60]}


# ---------------------------------------------------------------- 安装计划
def install_plan(spec, tid=None):
    """Use the executable allowlist; keep manual prerequisites explicit."""
    ins = spec.get("install") or {}
    primary = ins.get("primary") or {}
    cmd = (primary.get("cmd") or "").strip()
    if not cmd:
        for alt in ins.get("alternatives") or []:
            c = (alt.get("cmd") or "").strip()
            if c:
                primary, cmd = alt, c
                break
    tags = []
    if ins.get("requiresNetwork"):
        tags.append("需联网")
    if ins.get("requiresAdmin"):
        tags.append("需管理员")
    if ins.get("requiresInput"):
        tags.append("需替换路径")
    for r in ins.get("requires") or []:
        tags.append("需 %s" % r)
    if ins.get("license"):
        tags.append("需商业授权")
    if tid:
        sys.path.insert(0, os.path.join(TOOL, 'mcp'))
        import tool_autodiscover
        config_error = ''
        try:
            # The shared reader falls back to an empty catalog on JSON errors.
            # Read strictly here so a manual hint cannot conceal a broken catalog.
            with open(tool_autodiscover._INSTALL_FILE, encoding='utf-8-sig') as handle:
                catalog = json.load(handle)
            tool_autodiscover._install_methods(catalog, tool_autodiscover.normalize_tool_id(tid))
        except (OSError, ValueError, TypeError) as exc:
            config_error = '安装配置无效: ' + str(exc)
        if config_error:
            return {'cmd': '', 'via': 'manual', 'note': primary.get('note') or '',
                    'tags': tags, 'pathHint': ins.get('pathHint', ''), 'alternatives': [],
                    'auto_allowed': False, 'config_error': config_error}
        shared = tool_autodiscover.install_plan(tid)
        if shared.get('has_plan') and shared.get('auto_allowed'):
            return {'cmd': f'python Tool/scripts/tool-acquire.py --tool {tid} --install --json',
                    'via': shared.get('method', ''), 'note': shared.get('note', ''),
                    'tags': tags, 'pathHint': ins.get('pathHint', ''), 'alternatives': [],
                    'auto_allowed': shared.get('auto_allowed', False)}
        return {'cmd': '', 'via': 'manual', 'note': shared.get('note') or primary.get('note') or shared.get('reason', ''),
                'tags': tags, 'pathHint': ins.get('pathHint', ''), 'alternatives': [],
                'auto_allowed': False}
    return {
        "cmd": cmd,
        "via": primary.get("via") or "",
        "note": (primary.get("note") or "").strip(),
        "tags": tags,
        "pathHint": (ins.get("pathHint") or "").strip(),
        "alternatives": [{"via": a.get("via") or "", "cmd": (a.get("cmd") or "").strip(),
                          "note": (a.get("note") or "").strip()}
                         for a in (ins.get("alternatives") or [])],
    }


# ---------------------------------------------------------------- 主判定
def inspect(tid, spec, do_verify=True, budget=8.0, verify_timeout=None):
    """返回一行结果：工具 / 状态 / 在哪 / 自检首行 / 安装计划。"""
    row = {"id": tid, "display": DISPLAY.get(tid, tid), "status": "MISSING",
           "path": "", "via": "", "viaDetail": "", "selftest": "", "why": "",
           "install": install_plan(spec, tid), "candidates": 0, "problems": []}
    pexec, vexec = spec.get("probe") or {}, spec.get("verify") or {}
    if not pexec:
        row["problems"].append("%s: tool-runtimes.json 缺 probe 字段" % tid)
    if not vexec:
        row["problems"].append("%s: tool-runtimes.json 缺 verify 字段" % tid)
    if row['install'].get('config_error'):
        row['problems'].append('%s: %s' % (tid, row['install']['config_error']))
    if not row["install"]["cmd"] and not row['install']['note']:
        row["problems"].append("%s: 缺 install 获取方法或人工安装说明" % tid)

    hits, truncated = probe(pexec, budget=budget)
    row["candidates"] = len(hits)
    if truncated:
        row["why"] = "目录搜索超预算（%gs）提前收手，结果可能不完整" % budget
    if not hits:
        row["status"] = "MISSING"
        row["selftest"] = row["why"] or "未探测到（PATH/仓库副本/常见目录都没有）"
        return row

    if not do_verify:
        row.update(status="FOUND_NO_VERIFY", path=hits[0]["path"], via=hits[0]["via"],
                   viaDetail=hits[0]["viaDetail"],
                   selftest="(跳过自检：--no-verify)", why="未跑自检，不能判 READY")
        return row

    fails = []
    # Probe every candidate in discovery order.  A valid install can follow
    # several same-named or stale copies; silently stopping after three made a
    # usable fourth candidate look unverified.
    for h in hits:
        v = verify(vexec, h["path"], timeout_override=verify_timeout)
        if not v.get("ok"):
            fails.append({"path": h["path"], "why": v.get("why"), "line": v.get("line")})
            continue
        idr = identity(tid, vexec, v.get("exe") or h["path"])
        if idr and idr.get("ok") is not True:
            fails.append({"path": h["path"], "line": v.get("line"),
                          "why": "版本对但行为探针不过：%s" % idr.get("why")})
            continue
        row.update(status="FOUND_NO_VERIFY" if v.get('runtime_verified') is False else "READY",
                   path=v.get('exe') or h["path"], via=h["via"], viaDetail=h["viaDetail"],
                   selftest=v.get("line") or "", why=v.get("why") or "")
        if idr and idr.get("ok"):
            row["selftest"] = "%s（行为✔）" % row["selftest"]
        return row

    first = fails[0] if fails else {"path": hits[0]["path"], "why": "自检未通过", "line": ""}
    row.update(status="FOUND_NO_VERIFY", path=first["path"], via=hits[0]["via"],
               viaDetail=hits[0]["viaDetail"],
               selftest=first.get("line") or "(自检无输出)",
               why="找到但自检失败：%s" % (first.get("why") or ""))
    return row


def print_table(rows):
    head = ["工具", "状态", "在哪", "版本/自检输出首行", "缺的话怎么办"]
    via_label = {"env": "环境变量", "PATH": "PATH", "repo": "仓库内置", "dir": "磁盘扫描"}
    cells = []
    for r in rows:
        where = "—"
        if r["path"]:
            where = "%s: %s" % (via_label.get(r["via"], r["via"] or "?"), _rel(r["path"]))
        if r["status"] == "MISSING":
            hint = ("[%s] %s" % ("/".join(r["install"]["tags"]), r["install"]["cmd"])
                    if r["install"]["cmd"] else r['install']['note'])
        elif r["status"] == "READY":
            hint = "—（已就绪，可直接调）"
        else:
            hint = "已找到，运行能力待核验 → 见下方说明"
        cells.append([r["display"], r["status"], where, r["selftest"], hint])

    widths = [max([_width(h)] + [_width(c[i]) for c in cells]) for i, h in enumerate(head)]
    caps = [10, 16, 48, 42, 46]
    widths = [min(w, cap) for w, cap in zip(widths, caps)]
    lines = []
    for r_idx, r in enumerate([head] + cells):
        out = []
        for i, c in enumerate(r):
            if r_idx == 0:
                out.append(_pad(c, widths[i]))
            elif i == 2:
                out.append(_pad(_clip_mid(c, widths[i]), widths[i]))
            else:
                out.append(_pad(_clip(c, widths[i]), widths[i]))
        lines.append("| " + " | ".join(out) + " |")
    print("\n".join(lines))
    print("状态说明：READY=探测到且自检通过（真跑过一次，拿到期望输出）；"
          "FOUND_NO_VERIFY=找到了但运行能力未通过验证；MISSING=PATH/仓库副本/常见目录都没探测到")


def print_plans(rows):
    miss = [r for r in rows if r["status"] == "MISSING"]
    bad = [r for r in rows if r["status"] == "FOUND_NO_VERIFY"]
    if bad:
        print("\n找到但运行能力未验证（FOUND_NO_VERIFY）：")
        for r in bad:
            print("  · %-9s %s" % (r["display"], _rel(r["path"])))
            print("    %s" % (r["why"] or ""))
            print("    按上述原因复验启动、依赖或连接；确认安装损坏后再修复。")
    if not miss:
        return
    print("\n安装计划（只生成、不执行；复制到 PowerShell 即可，本轮不联网不装任何东西）：")
    for r in miss:
        ins = r["install"]
        print("  · %s%s" % (r["display"], ("  [%s]" % "/".join(ins["tags"])) if ins["tags"] else ""))
        if ins["cmd"]:
            print("    命令：%s" % ins["cmd"])
        else:
            print("    自动安装：无当前平台的白名单方法，按下面的来源和说明处理")
        if ins["note"]:
            print("    说明：%s" % ins["note"])
        if ins["pathHint"]:
            print("    路径：%s" % ins["pathHint"])
        for a in ins["alternatives"]:
            print("    备选(%s)：%s" % (a["via"] or "?", a["cmd"] or "-"))
        print("    装完重探：python Tool/scripts/tool-readiness.py")


def main():
    ap = argparse.ArgumentParser(
        description="六个真通路的工具：探测 + 安装计划 + 自检 + 就绪表（不联网、不安装）",
        epilog="退出码 0 = 探测机制可用（6 行齐全/状态合法/MISSING 都有安装命令）；"
               "1 = 机制坏了。本机缺几个工具不算机制坏。")
    ap.add_argument("--json", action="store_true", help="机读输出（Agent 用）")
    ap.add_argument("--no-verify", action="store_true", help="只探测不跑自检（快；结果不会是 READY）")
    ap.add_argument("--budget", type=float, default=8.0, help="单个工具的目录搜索预算秒（默认 8）")
    ap.add_argument("--verify-timeout", type=float, default=None,
                    help="自检超时秒（默认取配置 timeoutSec，缺省 20）")
    a = ap.parse_args()

    problems = []
    missing_install_cfg = set()   # 配置里就缺 install 的，下面不再重复报一遍
    try:
        with open(RUNTIMES, encoding="utf-8") as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict) or not isinstance(cfg.get('tools'), dict):
            raise ValueError('配置及 tools 必须是对象')
        tools_cfg = cfg['tools']
    except Exception as e:  # noqa: BLE001
        reason = "读不到 %s：%s" % (RUNTIMES, e)
        print(json.dumps({'ok': False, 'problems': [reason], 'tools': []}, ensure_ascii=False)
              if a.json else reason)
        return 1

    rows = []
    for tid in TOOLS:
        spec = tools_cfg.get(tid)
        if not isinstance(spec, dict):
            problems.append("%s: tool-runtimes.json 里没有这个工具" % tid)
            spec = {}
        row = inspect(tid, spec, do_verify=not a.no_verify, budget=a.budget,
                      verify_timeout=a.verify_timeout)
        for _p in row.pop("problems"):
            problems.append(_p)
            if "缺 install" in _p:
                missing_install_cfg.add(tid)
        rows.append(row)

    # ↓↓ 判据：机制可用性（不是"本机装没装"）
    if len(rows) != len(TOOLS):
        problems.append("行数 %d ≠ %d（应为 6 个工具各一行）" % (len(rows), len(TOOLS)))
    for r in rows:
        if r["status"] not in STATUSES:
            problems.append("%s: 状态 %r 非法（只允许 %s）" % (r["id"], r["status"],
                                                          "/".join(STATUSES)))
        if (r["status"] == "MISSING" and not (r["install"]["cmd"] or r['install']['note'])
                and r["id"] not in missing_install_cfg):
            problems.append("%s: MISSING 但没有安装命令（不能只说『去装吧』）" % r["id"])
    miss = [r for r in rows if r["status"] == "MISSING"]
    if miss and len(miss) == len(rows) and not any(r["install"]["cmd"] or r['install']['note'] for r in miss):
        problems.append("6 个全 MISSING 且没有任何安装计划 —— 探测器等于摆设")

    counts = {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES}
    ok = not problems

    if a.json:
        print(json.dumps({
            "ok": ok,
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "repo": ROOT,
            "criteria": "6 行齐全 / 状态合法 / MISSING 都带安装命令（不要求本机全 READY）",
            "counts": counts,
            "problems": problems,
            "tools": [{"id": r["id"], "status": r["status"], "path": r["path"],
                       "via": r["via"],
                       "selftest": r["selftest"], "why": r["why"],
                       "install_cmd": r["install"]["cmd"],
                        "install_note": r['install']['note'],
                       "install_tags": r["install"]["tags"]} for r in rows],
        }, ensure_ascii=False, indent=2))
        return 0 if ok else 1

    print("工具就绪表（探测 + 自检；判据：READY 必须真跑过自检并拿到期望输出）")
    print("读取：Tool/config/tool-runtimes.json 的 probe / verify / install 字段")
    print()
    print_table(rows)
    print_plans(rows)
    print()
    if problems:
        print("探测机制：✗ 有 %d 个问题（这些是真 bug，跟本机装没装无关）" % len(problems))
        for p in problems:
            print("  · %s" % p)
    print("结果: %d/%d 行 | READY %d / FOUND_NO_VERIFY %d / MISSING %d | 探测机制 %s"
          % (len(rows), len(TOOLS), counts["READY"], counts["FOUND_NO_VERIFY"],
             counts["MISSING"], "OK" if ok else "✗"))
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:      # `--json | head -40` 会提前关管道，不该算失败
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:  # noqa: BLE001
            pass
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
