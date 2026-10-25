# -*- coding: utf-8 -*-
"""入口契约检查（从 preflight 抽出来，避免在 shell heredoc 里写正则被转义破坏）。

为什么单独成文件（2026-10-25，外部评审 A4）：
    preflight 里这条判据原本靠 `"/rev" in AGENTS.md` 通过，而那个 `/rev` 其实来自
    知识库路径 `Tool/mcp/Tool/reverselab/kb` —— 判据靠字符串碰巧命中。
    重写时又踩了一个坑：把正则写在 shell heredoc 里，`\\w` 被转义吃掉 → 正则恒不命中
    → **判据看起来在跑，实际永远绿**。所以抽成独立模块，用文件写入，正则不再经过 shell。
"""
import os
import re

# 命令写法：`/name`，且前面不是字母数字/下划线/斜杠，后面不是字母数字/斜杠/连字符/下划线

# pi 宿主自带命令（不在我们的 extensions 里注册，但确实存在）
BUILTIN = {"mcp", "reload", "model", "login", "logout", "compact", "new", "quit", "help",
           "skills", "memory", "goal", "status", "resume", "theme", "packages", "agents"}

_CMD = re.compile(r"/([a-z][a-z0-9_-]{1,20})")
_REG = re.compile(r"register[A-Za-z]*\s*\(\s*[\"']([a-z][a-z0-9_-]{1,20})[\"']")
_BEFORE_OK = set(" \t\n\r(（[【,，:：、|")


def find_commands(text: str) -> set:
    """找出文本里"像命令"的 /name（排除路径片段 /mcp/ /setup/）。"""
    out = set()
    for m in _CMD.finditer(text or ""):
        pre = text[m.start() - 1] if m.start() else " "
        post = text[m.end():m.end() + 1]
        if pre.isalnum() or pre in "/_-":
            continue
        if post and (post.isalnum() or post in "/_-"):
            continue
        out.add(m.group(1))
    return out


def registered_commands(ext_dir: str) -> set:
    """扩展里真正 register* 过的命令名。"""
    out = set()
    if not os.path.isdir(ext_dir):
        return out
    for f in sorted(os.listdir(ext_dir)):
        if not f.endswith((".ts", ".js", ".mjs")):
            continue
        try:
            with open(os.path.join(ext_dir, f), encoding="utf-8", errors="replace") as fh:
                out |= set(_REG.findall(fh.read()))
        except Exception:
            pass
    return out


def check(agents_text: str, ext_dir: str):
    """返回 (是否通过, 说明)。

    判据：
      ① AGENTS 必须有「选域」说明（说话即入口）
      ② AGENTS 里出现的每个 `/cmd` 都必须真的注册过（禁止教用户打不存在的命令）
    """
    bad = []
    if "选域" not in (agents_text or ""):
        bad.append("AGENTS 未写「选域」入口")
    cmds = find_commands(agents_text)
    reg = registered_commands(ext_dir)
    ghost = sorted(c for c in cmds if c not in reg and c not in BUILTIN)
    if ghost:
        bad.append("承诺了未注册的命令：" + ", ".join("/" + g for g in ghost[:5]))
    return (not bad), ("；".join(bad) if bad else "无未注册命令；入口=说话")
