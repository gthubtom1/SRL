#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""env-check.py —— 给 Agent 用的"这台机器装没装好"自检（一条命令出结论）。

为什么需要：
    换电脑时用户不该知道要跑 install.ps1。Agent 应该自己判断"这台机器还没配好"，
    然后自己装、自己校验、把结果汇报给人。

用法：
    python Tool/scripts/env-check.py            # JSON（Agent 读这个）
    python Tool/scripts/env-check.py --text     # 人读的一页报告

退出码：0 = 已就绪；1 = 需要安装/修复（看 next_actions）
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
def _repo_root(start):
    """仓库根：向上找含 Tool/cases 的目录（S4 后位于 Tool/skill/<pack>/scripts/，固定层数会算错）。"""
    d = os.path.abspath(start)
    for _ in range(8):
        if os.path.isdir(os.path.join(d, "Tool", "cases")):
            return d
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return os.path.abspath(os.path.join(start, "..", "..", "..", ".."))


ROOT = _repo_root(HERE)
TOOL = os.path.join(ROOT, "Tool")

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def agent_dir() -> str:
    env = os.environ.get("PI_CODING_AGENT_DIR", "").strip()
    if env:
        return os.path.abspath(os.path.expanduser(env))
    return os.path.join(os.path.expanduser("~"), ".pi", "agent")


def expected_extensions():
    d = os.path.join(TOOL, "prompts", "extensions")
    if not os.path.isdir(d):
        return []
    return sorted(f for f in os.listdir(d)
                  if os.path.splitext(f)[1].lower() in (".ts", ".json", ".md"))


def expected_skills():
    d = os.path.join(TOOL, "skill")
    out = []
    if not os.path.isdir(d):
        return out
    for n in os.listdir(d):
        p = os.path.join(d, n)
        if n == "safe-skills":
            out += [x for x in os.listdir(p) if os.path.isdir(os.path.join(p, x))]
        elif os.path.isfile(os.path.join(p, "SKILL.md")):
            out.append(n)
    return sorted(out)


def looks_like_path(s: str) -> bool:
    """只把"真的会被当成文件打开"的参数当路径。

    注意：npm 包名（@playwright/mcp@latest）也带斜杠，但它是包标识，不是路径。
    """
    if not s or s.startswith(("@", "-", "!", "{")):
        return False
    if s.startswith(("http://", "https://")):
        return False
    if len(s) >= 2 and s[1] == ":":          # Windows 盘符
        return True
    if s.startswith(("/", "~", "./", "../")):
        return True
    return s.lower().endswith((".py", ".exe", ".js", ".mjs", ".ts"))


def check():
    ad = agent_dir()
    repo_ver = ""
    try:
        repo_ver = open(os.path.join(ROOT, "VERSION"), encoding="utf-8").read().strip()
    except Exception:
        pass

    res = {
        "repo_root": ROOT,
        "repo_version": repo_ver,
        "agent_dir": ad,
        "checks": {},
        "missing": [],
        "next_actions": [],
        "installed": False,
    }

    # 1) agent 目录与两份提示词
    res["checks"]["agent_dir_exists"] = os.path.isdir(ad)
    for f in ("SEEP.md", "AGENTS.md"):
        ok = os.path.isfile(os.path.join(ad, f))
        res["checks"][f] = ok
        if not ok:
            res["missing"].append(f"~/.pi/agent/{f}")

    # 2) 扩展（.ts / .json / .md 三类都要在）
    exp_ext = expected_extensions()
    have_ext = []
    ext_dir = os.path.join(ad, "extensions")
    if os.path.isdir(ext_dir):
        have_ext = os.listdir(ext_dir)
    miss_ext = [f for f in exp_ext if f not in have_ext]
    res["checks"]["extensions"] = {"expected": len(exp_ext), "missing": miss_ext}
    if miss_ext:
        res["missing"] += [f"~/.pi/agent/extensions/{f}" for f in miss_ext]

    # 3) 技能
    exp_sk = expected_skills()
    sk_dir = os.path.join(ad, "skills")
    have_sk = os.listdir(sk_dir) if os.path.isdir(sk_dir) else []
    miss_sk = [s for s in exp_sk if s not in have_sk]
    res["checks"]["skills"] = {"expected": len(exp_sk), "missing": miss_sk}
    if miss_sk:
        res["missing"] += [f"~/.pi/agent/skills/{s}" for s in miss_sk]

    # 4) MCP 配置：条目存在 + 可执行文件路径存在
    mcp_path = os.path.join(ad, "mcp.json")
    servers, broken = [], []
    if os.path.isfile(mcp_path):
        try:
            cfg = json.load(open(mcp_path, encoding="utf-8"))
            for name, e in (cfg.get("mcpServers") or {}).items():
                servers.append(name)
                args = e.get("args") or []
                for a in args:
                    if isinstance(a, str) and looks_like_path(a) and not a.startswith(("{", "!", "-")):
                        p = a.replace("{ROOT_POSIX}", ROOT.replace(os.sep, "/"))
                        if not os.path.exists(p.replace("/", os.sep)):
                            broken.append(f"{name}: {a}")
        except Exception as exc:
            broken.append(f"mcp.json 解析失败: {exc}")
    else:
        broken.append("~/.pi/agent/mcp.json 不存在")
    res["checks"]["mcp"] = {"servers": servers, "broken": broken}
    if broken:
        res["missing"] += broken

    # 5) settings.json：packages 与 retry 档位
    st_path = os.path.join(ad, "settings.json")
    pk, retry = 0, None
    if os.path.isfile(st_path):
        try:
            st = json.load(open(st_path, encoding="utf-8"))
            pk = len(st.get("packages") or [])
            retry = (st.get("retry") or {}).get("maxRetries")
        except Exception:
            pass
    res["checks"]["settings"] = {"packages": pk, "retry_max": retry}

    # 结论与下一步
    if not res["missing"]:
        res["installed"] = True
    else:
        res["next_actions"] = [
            "powershell -ExecutionPolicy Bypass -File setup\\install.ps1",
            "powershell -ExecutionPolicy Bypass -File setup\\verify.ps1 -Detailed",
            "python Tool/scripts/preflight.py --fast",
        ]
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--text", action="store_true")
    args = ap.parse_args()
    r = check()

    if args.text:
        print(f"仓库: {r['repo_root']}  v{r['repo_version']}")
        print(f"Agent 目录: {r['agent_dir']}")
        c = r["checks"]
        print(f"  提示词: SEEP.md={c.get('SEEP.md')} AGENTS.md={c.get('AGENTS.md')}")
        print(f"  扩展: 期望 {c['extensions']['expected']}，缺 {len(c['extensions']['missing'])}")
        print(f"  技能: 期望 {c['skills']['expected']}，缺 {len(c['skills']['missing'])}")
        print(f"  MCP: {', '.join(c['mcp']['servers']) or '无'}；异常 {len(c['mcp']['broken'])}")
        print(f"  settings: packages={c['settings']['packages']} retry.maxRetries={c['settings']['retry_max']}")
        print("结论:", "已就绪" if r["installed"] else f"需要安装/修复（缺 {len(r['missing'])} 项）")
        for m in r["missing"][:10]:
            print("  -", m)
        if r["next_actions"]:
            print("下一步由 Agent 执行:")
            for a in r["next_actions"]:
                print("  $", a)
    else:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0 if r["installed"] else 1


if __name__ == "__main__":
    sys.exit(main())
