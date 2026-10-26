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
import re
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


MCP_SERVER = os.path.join(TOOL, "mcp", "seep_mcp_server.py")
MCP_MIN_TOOLS = 15     # 工具数下限（不是基线值：基线对账在 preflight 里）


def _mcp_service_probe(path=None, timeout=120):
    """MCP「服务可用」实测：能解析 + 工具没被削减 + 真能握手。

    为什么（2026-10-26 第 2 轮评审 P0）：原来只查 mcp.json 里 mcpServers 有没有条目、
    args 里的路径存不存在 —— 服务 import 崩了 / 缺依赖 / `@server.tool` 一个没注册，
    也报"就绪"。用户拿到的结果是假绿，等真调 `mcp__seep__*` 才发现根本没有工具。

    三层，全过才算「服务可用」：
      ① `ast.parse`：文件能被解释器读成 Python（语法/编码没坏）；
      ② `@server.tool` 装饰器数量 ≥ MCP_MIN_TOOLS：工具没被削减；
      ③ stdio 握手 initialize + tools/list：真能起进程、真返回工具表。
    """
    path = path or MCP_SERVER
    out = {"file": path, "parses": False, "tool_count": 0, "handshake_ok": False,
           "handshake_tools": 0, "stage": "未测", "detail": "", "available": False}
    if not os.path.isfile(path):
        out["stage"] = "missing"
        out["detail"] = "文件不存在：%s（MCP 服务体不在仓库里）" % path
        return out
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
        import ast
        ast.parse(text, filename=path)
        out["parses"] = True
    except SyntaxError as e:
        out["stage"] = "ast"
        out["detail"] = "ast 解析失败：第 %s 行：%s" % (getattr(e, "lineno", "?"), e.msg)
        return out
    except Exception as e:  # noqa: BLE001
        out["stage"] = "ast"
        out["detail"] = "ast 解析失败：%s" % str(e)[:160]
        return out
    out["tool_count"] = len(re.findall(r"^\s*@server\.tool\b", text, re.M))
    if out["tool_count"] < MCP_MIN_TOOLS:
        out["stage"] = "tool_count"
        out["detail"] = ("@server.tool 只有 %d 个（门槛 %d）：工具被削减或注册失效"
                         % (out["tool_count"], MCP_MIN_TOOLS))
        return out
    try:
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        # 复用 preflight 里同一份握手实现，避免两处逻辑漂移（只导入纯函数，无副作用）
        from preflight import _mcp_stdio_handshake
    except Exception as e:  # noqa: BLE001
        out["stage"] = "handshake-import"
        out["detail"] = "拿不到握手实现（preflight 导入失败）：%s" % str(e)[:120]
        return out
    ok, n, stage, detail = _mcp_stdio_handshake(path, timeout=timeout)
    out["handshake_ok"] = bool(ok)
    out["handshake_tools"] = n
    out["stage"] = stage
    out["detail"] = detail
    out["available"] = bool(ok and out["tool_count"] >= MCP_MIN_TOOLS)
    return out


# 模型凭据交给用户/Agent 去补的动作（可直接复制，不需要联网）。
MODEL_CRED_ACTION = (
    "补模型凭据：开一个 Agent 会话执行 /login 选 provider 登录（或把 provider 的 apiKey 写进 "
    "~/.pi/agent/models.json 的 providers 里），然后重跑 python Tool/scripts/env-check.py --text")


def _mask_path(p: str) -> str:
    """展示用脱敏：把家目录换成 ~（绝不用来展示任何 key 内容）。"""
    home = os.path.expanduser("~")
    if home and home in p:
        p = p.replace(home, "~")
    return p


def _cred_usable(v) -> bool:
    """凭据条目是否"看起来有东西"——只看有没有，不校验内容、不联网、不打印。"""
    if isinstance(v, str):
        return bool(v.strip())
    if isinstance(v, dict):
        for k in ("key", "apiKey", "access", "refresh", "accessToken", "token", "env", "api_key"):
            val = v.get(k)
            if isinstance(val, str) and val.strip():
                return True
            if isinstance(val, dict) and val:
                return True
    return False


def _model_credential_probe(ad=None):
    """模型/凭据体检：只判「有没有配」，不联网验证 key 是否有效。

    为什么（第 3 轮评审 P0-5）：MCP 侧修好了，但模型层没凭据时整台机器依然开不了
    会话——以前这里完全不看 auth.json / models.json，装完就报 installed: true。

    判定顺序（与 Pi 的凭据解析顺序大体一致，越靠前越可信）：
      ① <agent-dir>/auth.json 里有非空条目（/login 存下来的 key 或 OAuth 令牌）；
      ② models.json 的 providers 里至少一个带非空 apiKey（自定义 provider）；
      ③ 都没有 → 未配置。
    输出只含 provider 名或脱敏后的文件路径，不含任何 key/token 内容。
    """
    ad = ad or agent_dir()
    auth_p = os.path.join(ad, "auth.json")
    models_p = os.path.join(ad, "models.json")
    out = {"configured": False, "source": "", "providers": [], "stage": "未测",
           "files": [_mask_path(auth_p), _mask_path(models_p)], "detail": ""}
    notes = []

    # ① auth.json
    if not os.path.isfile(auth_p):
        notes.append("auth.json 不存在")
    else:
        try:
            raw = open(auth_p, encoding="utf-8", errors="replace").read()
            data = json.loads(raw) if raw.strip() else {}
            names = sorted(k for k, v in (data.items() if isinstance(data, dict) else [])
                           if _cred_usable(v))
            if names:
                shown = ", ".join(names[:3]) + (" 等" if len(names) > 3 else "")
                out.update(configured=True, stage="auth.json", providers=names,
                           source="auth.json: " + shown,
                           detail="auth.json 有 %d 个可用凭据条目" % len(names))
                return out
            notes.append("auth.json 存在但没有可用条目（空文件或空对象）")
        except Exception as exc:  # noqa: BLE001
            notes.append("auth.json 解析失败：%s" % str(exc)[:80])

    # ② models.json（自定义 provider 的 apiKey 写在文件里）
    if not os.path.isfile(models_p):
        notes.append("models.json 不存在")
    else:
        try:
            cfg = json.load(open(models_p, encoding="utf-8"))
            provs = cfg.get("providers") or {}
            names = sorted(str(k) for k, v in (provs.items() if isinstance(provs, dict) else [])
                           if isinstance(v, dict) and _cred_usable(v))
            if names:
                shown = ", ".join(names[:3]) + (" 等" if len(names) > 3 else "")
                out.update(configured=True, stage="models.json", providers=names,
                           source="models.json: " + shown,
                           detail="models.json 有 %d 个带 apiKey 的 provider" % len(names))
                return out
            notes.append("models.json 存在但没有带 apiKey 的 provider")
        except Exception as exc:  # noqa: BLE001
            notes.append("models.json 解析失败：%s" % str(exc)[:80])

    out["detail"] = "；".join(notes) or "没有找到任何凭据来源"
    return out


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
    res["checks"]["mcp"] = {"servers": servers, "broken": broken, "config_ready": bool(servers) and not broken}
    if broken:
        res["missing"] += broken

    # 4b) MCP 服务可用（第 2 轮评审 P0）：配置就绪 ≠ 服务可用。
    #     以前这里只判「mcpServers 有条目 + 文件路径在」→ 服务起不来也报"就绪"。
    svc = _mcp_service_probe()
    res["checks"]["mcp"]["service"] = svc
    if not svc["available"]:
        res["missing"].append(
            "MCP 服务不可用（seep 握手失败阶段 %s）：%s" % (svc["stage"], svc["detail"] or "无详情"))

    # 4c) 模型/凭据（第 3 轮评审 P0-5）：没有可用 provider 就开不了会话，
    #     以前这一项完全没查 → 装完报 installed: true，用户一开口就报鉴权错。
    cred = _model_credential_probe(ad)
    res["checks"]["model_credential"] = cred
    if not cred["configured"]:
        res["missing"].append(
            "模型凭据未配置（auth.json / models.json 都没有可用 provider）：%s" % (cred["detail"] or ""))

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
        if not svc["available"]:
            # 服务连不上不是"没安装"，install.ps1 修不了 —— 先指向自愈器
            res["next_actions"].insert(0, "python Tool/scripts/mcp-doctor.py --fix")
        if not cred["configured"]:
            res["next_actions"].append(MODEL_CRED_ACTION)
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
        print(f"  MCP 配置就绪: {', '.join(c['mcp']['servers']) or '无'}；异常 {len(c['mcp']['broken'])}（仅代表 mcp.json 条目 + 路径存在）")
        sv = (c.get("mcp") or {}).get("service") or {}
        print("  MCP 服务可用: %s（ast 解析=%s / @server.tool=%s ≥ %d / 握手=%s）"
              % ("可用" if sv.get("available") else "不可用@%s" % sv.get("stage"),
                 "OK" if sv.get("parses") else "失败", sv.get("tool_count"), MCP_MIN_TOOLS,
                 ("OK %d 工具" % sv.get("handshake_tools")) if sv.get("handshake_ok") else "失败"))
        cr = c.get("model_credential") or {}
        if cr.get("configured"):
            print("模型凭据：已配置（%s）" % (cr.get("source") or cr.get("stage")))
        else:
            print("模型凭据：未配置（需要登录/API key）")
            print("  查过: %s（%s）" % ("、".join(cr.get("files") or []), cr.get("detail") or "无详情"))
        print(f"  settings: packages={c['settings']['packages']} retry.maxRetries={c['settings']['retry_max']}")
        print("结论:", ("已就绪（配置就绪且服务可用）" if r["installed"]
                        else f"需要安装/修复（缺 {len(r['missing'])} 项；配置就绪≠服务可用，看上面两行）"))
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
