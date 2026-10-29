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
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from lib.runtime_root import RuntimeRootError, resolve_agent_root

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
    return str(resolve_agent_root())


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
        if n.startswith("_"):
            continue
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


def _mcp_service_probe(path=None, timeout=120, config=None):
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
           "probe_target": "configured" if config is not None else "source",
           "handshake_tools": 0, "stage": "未测", "detail": "", "available": False}
    if not os.path.isfile(path):
        out["stage"] = "missing"
        out["detail"] = "文件不存在：%s（MCP 服务体不在仓库里）" % path
        return out
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        import ast
        tree = ast.parse(text, filename=path)
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
    expected_tools = [node.name for node in ast.walk(tree)
                      if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                      and any(isinstance(d, ast.Call) and ast.unparse(d.func) == "server.tool"
                              for d in node.decorator_list)]
    if config is None:
        ok, n, stage, detail = _mcp_stdio_handshake(
            path, timeout=timeout, required_tools=expected_tools)
    else:
        problems = _mcp_config_problems(config)
        if isinstance(config, dict) and (not config.get("command")
                                        or config.get("transport", "stdio") != "stdio"):
            problems.append("Seep 检测需要 stdio 启动配置")
        if problems:
            out.update(stage="config", detail="; ".join(problems))
            return out
        ok, n, stage, detail = _mcp_stdio_handshake(
            timeout=timeout, command=config["command"], args=config.get("args", []),
            env=config.get("env"), cwd=config.get("cwd"), required_tools=expected_tools)
    out["handshake_ok"] = bool(ok)
    out["handshake_tools"] = n
    out["stage"] = stage
    out["detail"] = detail
    out["available"] = bool(ok and out["tool_count"] >= MCP_MIN_TOOLS)
    return out


def _mcp_config_problems(entry):
    """Validate final launch settings without starting optional GUI/remote servers."""
    import shutil
    if not isinstance(entry, dict):
        return ["服务配置必须是对象"]
    # Remote optional servers are owned and connected by the host.
    if entry.get("url") and not entry.get("command"):
        return []
    command, args, env = entry.get("command"), entry.get("args", []), entry.get("env", {})
    if not isinstance(command, str) or not command.strip():
        return ["command 缺失"]
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return ["args 必须是字符串数组"]
    if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str)
                                          for k, v in env.items()):
        return ["env 必须是字符串映射"]
    cwd = entry.get("cwd")
    if cwd is not None and (not isinstance(cwd, str) or not os.path.isdir(cwd)):
        return ["cwd 不存在或不是目录"]
    child_env = dict(os.environ, **env)
    binary = command
    if not os.path.isabs(binary) and ("/" in binary or "\\" in binary):
        binary = os.path.join(cwd or os.getcwd(), binary)
    problems = []
    if not shutil.which(binary, path=child_env.get("PATH")):
        problems.append("command 不可执行：" + command)
    for arg in args:
        if looks_like_path(arg):
            target = os.path.expanduser(arg)
            if not os.path.isabs(target):
                target = os.path.join(cwd or os.getcwd(), target)
            if not os.path.exists(target):
                problems.append("参数路径不存在：" + arg)
    return problems


def _deployment_differences(source, destination):
    """Compare managed payloads, so an empty/stale directory cannot prove readiness."""
    source, destination = Path(source), Path(destination)
    problems = []
    for original in sorted(source.rglob("*")):
        if not original.is_file() or "__pycache__" in original.parts or original.suffix == ".pyc":
            continue
        relative = original.relative_to(source)
        deployed = destination / relative
        try:
            if hashlib.sha256(original.read_bytes()).digest() == hashlib.sha256(deployed.read_bytes()).digest():
                continue
            problems.append(str(relative) + "（内容不同）")
        except OSError:
            problems.append(str(relative) + "（缺失或不可读）")
    return problems


def _prompt_matches(source, destination):
    """Compare the managed source block while retaining host and user additions."""
    def owned(text):
        begin, end = "<!-- seep:managed:begin -->", "<!-- seep:managed:end -->"
        if begin in text or end in text:
            if text.count(begin) != 1 or text.count(end) != 1 or text.index(begin) > text.index(end):
                raise ValueError("invalid managed prompt boundary")
            text = text[text.index(begin) + len(begin):text.index(end)]
        lines, skip = [], False
        for line in text.splitlines():
            if "magpie:begin" in line:
                skip = True
            elif "magpie:end" in line:
                skip = False
            elif not skip:
                lines.append(line)
        return "\n".join(lines).strip()
    try:
        expected = owned(Path(source).read_text(encoding="utf-8-sig"))
        actual = owned(Path(destination).read_text(encoding="utf-8-sig"))
        return bool(expected) and expected == actual
    except (OSError, ValueError):
        return False


# 模型凭据交给用户/Agent 去补的动作（可直接复制，不需要联网）。
MODEL_CRED_ACTION = (
    "在 Pi 会话中选择模型并通过 /login 登录；凭据由用户在宿主操作，然后重跑环境检查")


def _mask_path(p: str) -> str:
    """展示用脱敏：把家目录换成 ~（绝不用来展示任何 key 内容）。"""
    home = os.path.expanduser("~")
    if home and home in p:
        p = p.replace(home, "~")
    return p


def _model_credential_probe(ad=None):
    """Ask the host for readiness metadata; never open credential stores."""
    import shutil
    import subprocess
    out = {"configured": False, "stage": "host-auth-check", "providers": [],
           "source": "pi auth check (no credentials, no refresh)", "detail": ""}
    try:
        settings_path = os.path.join(ad or agent_dir(), "settings.json")
        with open(settings_path, encoding="utf-8-sig") as handle:
            settings = json.load(handle)
        if not isinstance(settings, dict):
            raise ValueError("settings must be an object")
        provider, model = settings.get("defaultProvider"), settings.get("defaultModel")
        if not all(isinstance(x, str) and re.fullmatch(r"[\w./:+@-]+", x)
                   for x in (provider, model)):
            out["detail"] = "请先在宿主中选择模型并登录；未读取凭据文件"
            return out
        command = shutil.which("pi.cmd") if os.name == "nt" else shutil.which("pi")
        if not command:
            out["detail"] = "Pi 命令不可用"
            return out
        env = dict(os.environ, PI_CODING_AGENT_DIR=ad or agent_dir())
        proc = subprocess.run([command, "auth", "check", "--provider", provider,
                               "--model", model, "--json", "--no-refresh"],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=20, env=env)
        # Deliberately retain only documented metadata, never raw host output.
        result = json.loads(proc.stdout)
        if not isinstance(result, dict):
            raise ValueError("host auth result must be an object")
        out["configured"] = proc.returncode == 0 and result.get("status") == "ready"
        out["providers"] = [provider] if out["configured"] else []
        out["detail"] = "宿主认证就绪；未发送模型请求" if out["configured"] else "宿主认证未就绪，请在宿主登录"
    except (OSError, ValueError, subprocess.SubprocessError):
        out["detail"] = "宿主认证检查未完成，请在宿主确认登录和所选模型"
    return out


def check():
    ad = agent_dir()
    repo_ver = ""
    try:
        with open(os.path.join(ROOT, "VERSION"), encoding="utf-8") as handle:
            repo_ver = handle.read().strip()
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

    # Configuration files alone do not provide an executable conversation host.
    import shutil
    import subprocess
    for command in ("pi", "node"):
        binary = shutil.which("pi.cmd") if command == "pi" and os.name == "nt" else shutil.which(command)
        available = False
        if binary:
            try:
                probe = subprocess.run([binary, "--version"], capture_output=True,
                                       text=True, encoding="utf-8", errors="replace", timeout=15)
                available = probe.returncode == 0
                if command == "node":
                    version = re.search(r"v?(\d+)\.(\d+)\.(\d+)", probe.stdout)
                    available = available and bool(version) and tuple(map(int, version.groups())) >= (22, 19, 0)
            except (OSError, subprocess.SubprocessError):
                pass
        res["checks"][command] = available
        if not available:
            res["missing"].append("宿主命令不可用或版本过旧：" + command)

    # 1) agent 目录与两份提示词
    res["checks"]["agent_dir_exists"] = os.path.isdir(ad)
    for f in ("SEEP.md", "AGENTS.md"):
        ok = _prompt_matches(Path(TOOL, "prompts", f), Path(ad, f))
        res["checks"][f] = ok
        if not ok:
            res["missing"].append(str(Path(ad, f)) + "（缺失、内容过期或托管边界无效）")

    # 2) 扩展（.ts / .json / .md 三类都要在）
    exp_ext = expected_extensions()
    ext_dir = os.path.join(ad, "extensions")
    miss_ext = []
    for f in exp_ext:
        try:
            source = Path(TOOL, "prompts", "extensions", f).read_bytes()
            if source != Path(ext_dir, f).read_bytes():
                miss_ext.append(f)
        except OSError:
            miss_ext.append(f)
    res["checks"]["extensions"] = {"expected": len(exp_ext), "missing": miss_ext}
    if miss_ext:
        res["missing"] += [f"~/.pi/agent/extensions/{f}" for f in miss_ext]

    # 3) 技能
    exp_sk = expected_skills()
    sk_dir = os.path.join(ad, "skills")
    invalid_sk = {}
    for s in exp_sk:
        source = Path(TOOL, "skill", s)
        if not source.is_dir():
            source = Path(TOOL, "skill", "safe-skills", s)
        differences = _deployment_differences(source, Path(sk_dir, s))
        if differences:
            invalid_sk[s] = differences
    miss_sk = sorted(invalid_sk)
    res["checks"]["skills"] = {"expected": len(exp_sk), "missing": miss_sk,
                               "invalid_files": invalid_sk}
    if miss_sk:
        res["missing"] += [f"~/.pi/agent/skills/{s}" for s in miss_sk]

    # 4) MCP 配置：条目存在 + 可执行文件路径存在
    mcp_path = os.path.join(ad, "mcp.json")
    servers, broken, entries = [], [], {}
    if os.path.isfile(mcp_path):
        try:
            with open(mcp_path, encoding="utf-8-sig") as handle:
                cfg = json.load(handle)
            entries = cfg.get("mcpServers") or {}
            for name, e in entries.items():
                servers.append(name)
                broken.extend(f"{name}: {p}" for p in _mcp_config_problems(e))
        except Exception as exc:
            broken.append(f"mcp.json 解析失败: {exc}")
            entries = {}
    else:
        broken.append("~/.pi/agent/mcp.json 不存在")
    if "seep" not in entries:
        broken.append("缺少 seep MCP 配置")
    res["checks"]["mcp"] = {"servers": servers, "broken": broken, "config_ready": bool(servers) and not broken}
    if broken:
        res["missing"] += broken

    # 4b) MCP 服务可用（第 2 轮评审 P0）：配置就绪 ≠ 服务可用。
    #     以前这里只判「mcpServers 有条目 + 文件路径在」→ 服务起不来也报"就绪"。
    svc = _mcp_service_probe(config=entries.get("seep", {}))
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
            "宿主认证未就绪：%s" % (cred["detail"] or ""))

    # 5) settings.json：packages 与 retry 档位
    st_path = os.path.join(ad, "settings.json")
    pk, retry = 0, None
    if os.path.isfile(st_path):
        try:
            with open(st_path, encoding="utf-8") as handle:
                st = json.load(handle)
            pk = len(st.get("packages") or [])
            retry = (st.get("retry") or {}).get("maxRetries")
        except Exception:
            pass
    res["checks"]["settings"] = {"packages": pk, "retry_max": retry}

    # 结论与下一步
    if not res["missing"]:
        res["installed"] = True
    else:
        # Keep recovery on the same AgentRoot; authentication cannot be repaired
        # by reinstalling already verified files or starting unrelated services.
        if os.name == "nt":
            quote = lambda value: "'" + value.replace("'", "''") + "'"
            context = "$env:PI_CODING_AGENT_DIR = " + quote(ad)
            install = ("powershell -NoProfile -ExecutionPolicy Bypass -File setup/install.ps1 "
                       "-NonInteractive -AgentRoot " + quote(ad))
        else:
            import shlex
            quote = shlex.quote
            context = "export PI_CODING_AGENT_DIR=" + quote(ad)
            install = "bash setup/install.sh --agent-root " + quote(ad)
        auth_only = not cred["configured"] and len(res["missing"]) == 1
        res["next_actions"] = [context]
        if not auth_only:
            if not svc["available"]:
                res["next_actions"].append(
                    "python Tool/scripts/mcp-doctor.py --file " + quote(mcp_path) + " --fix")
            res["next_actions"].append(install)
        if not cred["configured"]:
            res["next_actions"].append(MODEL_CRED_ACTION)
        res["next_actions"].append("python Tool/scripts/env-check.py")
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--text", action="store_true")
    args = ap.parse_args()
    try:
        r = check()
    except RuntimeRootError as exc:
        print(str(exc) if args.text else json.dumps(exc.as_dict(), ensure_ascii=False))
        return 1

    if args.text:
        print(f"仓库: {r['repo_root']}  v{r['repo_version']}")
        print(f"Agent 目录: {r['agent_dir']}")
        c = r["checks"]
        print(f"  提示词: SEEP.md={c.get('SEEP.md')} AGENTS.md={c.get('AGENTS.md')}")
        print(f"  扩展: 期望 {c['extensions']['expected']}，缺 {len(c['extensions']['missing'])}")
        print(f"  技能: 期望 {c['skills']['expected']}，缺 {len(c['skills']['missing'])}")
        print(f"  MCP 配置就绪: {', '.join(c['mcp']['servers']) or '无'}；异常 {len(c['mcp']['broken'])}（已检查启动命令与参数路径）")
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
