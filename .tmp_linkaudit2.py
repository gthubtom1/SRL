"""断链审计 v2：按「技能目录 → references → scripts → 仓库根 → Tool/scripts」多基址解析。"""

import io
import os
import re

ROOT = os.path.abspath(".")
SKILL_ROOT = os.path.join(ROOT, "Tool", "skill")
SKIP = ("Tool/upstream", "Tool/mcp/Tool", ".git", "node_modules", "__pycache__")

issues = []
checked = 0


def rel(p):
    return os.path.relpath(p, ROOT).replace(os.sep, "/")


def find_any_basename(name):
    """在整个 Tool/ 下按 basename 找一次（用于 *.exe / 工具二进制引用）。"""
    for d, dirs, files in os.walk(os.path.join(ROOT, "Tool")):
        if any(s.replace("/", os.sep) in d for s in ("upstream", "node_modules", "__pycache__")):
            dirs[:] = []
            continue
        if name.lower() in (f.lower() for f in files):
            return os.path.join(d, name)
    return None


link_re = re.compile(r"`([A-Za-z0-9_\-./\\]+\.(?:md|py|ps1|sh|json|bsh|js|jar|exe))`")

for skill in sorted(os.listdir(SKILL_ROOT)):
    sdir = os.path.join(SKILL_ROOT, skill)
    if not os.path.isdir(sdir):
        continue
    subs = ([os.path.join(sdir, d) for d in os.listdir(sdir)
             if os.path.isdir(os.path.join(sdir, d))] if skill == "safe-skills" else [sdir])
    for tdir in subs:
        md = os.path.join(tdir, "SKILL.md")
        if not os.path.isfile(md):
            continue
        text = io.open(md, encoding="utf-8", errors="ignore").read()
        for m in link_re.finditer(text):
            p = m.group(1)
            if p.startswith(("http", "~", "/", "D:", "C:")) or "://" in p:
                continue
            checked += 1
            bases = [
                tdir,
                os.path.join(tdir, "references"),
                os.path.join(tdir, "scripts"),
                ROOT,
                os.path.join(ROOT, "Tool", "scripts"),
                os.path.join(ROOT, "Tool", "scripts", "apk"),
            ]
            if any(os.path.exists(os.path.join(b, p.replace("\\", "/"))) for b in bases):
                continue
            if p.lower().endswith(".exe") and find_any_basename(p):
                continue          # 工具二进制引用（radare2.exe 等）
            issues.append((rel(md), p))

print("检查引用总数:", checked)
print("真实断链:", len(issues))
for f, p in issues:
    print(f"  {f}  ->  {p}")

# 反向：references 里是否有「从未被 SKILL.md 提及」的孤儿文件
print()
print("=== 孤儿参考文件（存在但 SKILL.md 未提及）===")
orphans = 0
for skill in sorted(os.listdir(SKILL_ROOT)):
    sdir = os.path.join(SKILL_ROOT, skill)
    if not os.path.isdir(sdir):
        continue
    subs = ([os.path.join(sdir, d) for d in os.listdir(sdir)
             if os.path.isdir(os.path.join(sdir, d))] if skill == "safe-skills" else [sdir])
    for tdir in subs:
        md = os.path.join(tdir, "SKILL.md")
        refd = os.path.join(tdir, "references")
        if not (os.path.isfile(md) and os.path.isdir(refd)):
            continue
        text = io.open(md, encoding="utf-8", errors="ignore").read()
        for f in sorted(os.listdir(refd)):
            if not f.endswith(".md"):
                continue
            if f not in text:
                orphans += 1
print("孤儿文件数:", orphans)
