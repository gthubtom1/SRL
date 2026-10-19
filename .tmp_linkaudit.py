"""全链路断链审计：技能引用 / 工具名一致性 / KB 映射 / frontmatter / 文档脚本引用。"""

import io
import json
import os
import re

ROOT = os.path.abspath(".")
SKILL_ROOT = os.path.join(ROOT, "Tool", "skill")
SKIP = ("Tool/upstream", "Tool/mcp/Tool", ".git", "node_modules", "__pycache__")

issues = []


def rel(p):
    return os.path.relpath(p, ROOT).replace(os.sep, "/")


# ---------------------------------------------------------------- A. SKILL.md 内部引用
print("=== A. SKILL.md 内部路径引用是否存在 ===")
link_re = re.compile(r"`([A-Za-z0-9_\-./\\]+\.(?:md|py|ps1|sh|json|bsh|js|jar|exe))`")
for skill in sorted(os.listdir(SKILL_ROOT)):
    sdir = os.path.join(SKILL_ROOT, skill)
    if not os.path.isdir(sdir):
        continue
    targets = []
    if skill == "safe-skills":
        targets = [os.path.join(sdir, d) for d in os.listdir(sdir) if os.path.isdir(os.path.join(sdir, d))]
    else:
        targets = [sdir]
    for tdir in targets:
        md = os.path.join(tdir, "SKILL.md")
        if not os.path.isfile(md):
            issues.append(("A", rel(tdir), "缺 SKILL.md"))
            continue
        text = io.open(md, encoding="utf-8", errors="ignore").read()
        for m in link_re.finditer(text):
            p = m.group(1)
            if p.startswith(("http", "~", "/", "D:", "C:")) or "://" in p:
                continue
            cand = os.path.join(tdir, p.replace("\\", "/"))
            if not os.path.exists(cand):
                issues.append(("A", rel(md), "引用不存在: " + p))

# ---------------------------------------------------------------- B. 工具名一致性
print("=== B. 工具名一致性（文档 ↔ 代码）===")
src = io.open("Tool/mcp/seep_mcp_server.py", encoding="utf-8").read()
real_tools = set(re.findall(r"^def (seep_[a-z0-9_]+)\(", src, re.M))
print("  代码中真实工具数:", len(real_tools))

doc_files = []
for d, dirs, files in os.walk(ROOT):
    n = d.replace(os.sep, "/")
    if any(s in n for s in SKIP):
        dirs[:] = []
        continue
    for f in files:
        if f.endswith(".md"):
            doc_files.append(os.path.join(d, f))

mentioned = {}
for f in doc_files:
    t = io.open(f, encoding="utf-8", errors="ignore").read()
    for name in set(re.findall(r"\b(seep_[a-z0-9_]+)\b", t)):
        mentioned.setdefault(name, []).append(rel(f))

ghost = sorted(n for n in mentioned if n not in real_tools)
print("  文档里提到但代码不存在的工具名:", ghost or "无")
for g in ghost:
    issues.append(("B", mentioned[g][0], "幽灵工具名: " + g))

undocumented = sorted(real_tools - set(mentioned))
print("  代码里有但文档从未提到的工具:", undocumented or "无")

# ---------------------------------------------------------------- C. KB checklist 映射
print("=== C. seep_kb_checklist 映射文件 ===")
kb = "Tool/mcp/Tool/reverselab/kb"
for m in re.finditer(r'"([a-z_0-9]+)":\s*"([^"]+)"', src):
    key, path = m.group(1), m.group(2)
    if path.endswith(".md") and "/" in path and not path.startswith("http"):
        full = os.path.join(kb, path)
        ok = os.path.isfile(full)
        if not ok:
            issues.append(("C", "seep_kb_checklist", f"{key} -> {path} 不存在"))
        print(f"  {key:22s} {'OK ' if ok else 'MISS'} {path}")

# ---------------------------------------------------------------- D. frontmatter
print("=== D. 技能 frontmatter（name 与目录名一致 / description 非空）===")
for skill in sorted(os.listdir(SKILL_ROOT)):
    sdir = os.path.join(SKILL_ROOT, skill)
    if not os.path.isdir(sdir):
        continue
    subs = [os.path.join(sdir, d) for d in os.listdir(sdir) if os.path.isdir(os.path.join(sdir, d))] if skill == "safe-skills" else [sdir]
    for tdir in subs:
        md = os.path.join(tdir, "SKILL.md")
        if not os.path.isfile(md):
            continue
        raw = io.open(md, encoding="utf-8", errors="ignore").read()
        if raw.startswith("\ufeff"):
            issues.append(("D", rel(md), "带 BOM（Agent 会静默跳过）"))
        m = re.match(r"^---\s*\n(.*?)\n---", raw, re.S)
        if not m:
            issues.append(("D", rel(md), "frontmatter 缺失"))
            continue
        fm = m.group(1)
        nm = re.search(r"^name:\s*(.+)$", fm, re.M)
        ds = re.search(r"^description:\s*(.+)$", fm, re.M | re.S)
        dirname = os.path.basename(tdir)
        if not nm:
            issues.append(("D", rel(md), "frontmatter 缺 name"))
        elif nm.group(1).strip().strip('"\'') != dirname:
            issues.append(("D", rel(md), f"name({nm.group(1).strip()}) != 目录名({dirname})"))
        if not ds or not ds.group(1).strip():
            issues.append(("D", rel(md), "description 为空"))

# ---------------------------------------------------------------- E. 文档引用的脚本
print("=== E. 文档中引用的 setup/Tool 脚本是否存在 ===")
script_re = re.compile(r"`((?:setup|Tool|MANUAL)/[A-Za-z0-9_\-./]+\.(?:ps1|sh|py|md|json))`")
checked = set()
for f in doc_files:
    if rel(f).startswith(("Tool/skill", "Tool/docs")):
        continue
    t = io.open(f, encoding="utf-8", errors="ignore").read()
    for m in script_re.finditer(t):
        p = m.group(1)
        if p in checked:
            continue
        checked.add(p)
        if not os.path.exists(os.path.join(ROOT, p)):
            issues.append(("E", rel(f), "引用不存在: " + p))

print()
print("=" * 60)
print("问题总数:", len(issues))
for kind, where, detail in issues:
    print(f"  [{kind}] {where} :: {detail}")
