#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""导入外部技能：用户只说一句"我要加这个技能"，剩下的判定/改造/安装/验证由这里完成。

为什么（2026-10-24 用户提的最后一环）：
    用户从网上找到一个 skill，不会知道我们的架构（域 vs 子技能）、格式（frontmatter 要求）、
    放哪儿、要不要部署。**不该让用户手改**——他只要说"加这个"，剩下是 Agent 的事。

本脚本负责**机械部分**（可判定、可校验）：
    ① 校验 frontmatter（name / description 是否齐全、是否合法）
    ② **判定它是「域技能」还是「子技能」**（依据：覆盖面 + 正文规模 + 覆盖的文件类型数）
    ③ 放到正确位置（域 → Tool/skill/<名>/ ；子 → Tool/skill/_pending/<名>/）
    ④ 域技能顺带部署到 ~/.pi/agent/skills/（下次会话自动加载）
    ⑤ 打印**给 Agent 的收尾清单**：描述要不要改写成"用户原话+后缀"、若为子技能要在父域 SKILL.md
       加一行"何时读它"、最后跑 check

用法：
    python Tool/scripts/skill-import.py --from <目录或 SKILL.md 路径> [--name 名字] [--dry-run]
    python Tool/scripts/skill-import.py --selftest
"""
import argparse
import io
import os
import re
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SKILL_DIR = os.path.join(ROOT, "Tool", "skill")
PENDING = os.path.join(SKILL_DIR, "_pending")
DEPLOY = os.path.expanduser(os.path.join("~", ".pi", "agent", "skills"))

# 域技能的"广度"判据：正文规模 + 覆盖的文件类型/技法类别数量
DOMAIN_MIN_LINES = 120
FILE_EXT_RE = re.compile(r"\.(exe|dll|sys|so|dylib|apk|aab|dex|bin|img|trx|squashfs|ubi|pcap|jar|ipa|"
                         r"elf|macho|js|php|py|zip|7z|ova|qcow2)\b", re.I)
TECH_HINTS = ("脱壳", "反调试", "抓包", "加密", "混淆", "反编译", "溢出", "注入", "取证", "报文", "固件",
              "解包", "重打包", "hook", "unpack", "decompile", "exploit", "fuzz", "kernel", "driver")


def read_skill(path):
    if os.path.isdir(path):
        p = os.path.join(path, "SKILL.md")
    else:
        p = path
    if not os.path.isfile(p):
        raise SystemExit("[拒] 找不到 SKILL.md：%s" % p)
    return p, io.open(p, encoding="utf-8", errors="replace").read()


def parse(text):
    m = re.search(r"^---\s*$(.*?)^---\s*$", text, re.M | re.S)
    fm = m.group(1) if m else ""
    name = re.search(r"^name:\s*(.+)$", fm, re.M)
    desc = re.search(r"^description:\s*(.+)$", fm, re.M)
    return {
        "name": (name.group(1).strip().strip('"\'') if name else ""),
        "description": (" ".join(desc.group(1).strip().strip('"\'').split()) if desc else ""),
        "has_frontmatter": bool(m),
    }


def classify(text, meta):
    """域 vs 子技能：只看可量化的广度指标（不做语义猜测）。"""
    lines = len(text.splitlines())
    exts = {e.lower() for e in FILE_EXT_RE.findall(text)}
    techs = {t for t in TECH_HINTS if t.lower() in text.lower()}
    score = 0
    if lines >= DOMAIN_MIN_LINES:
        score += 2
    elif lines >= 60:
        score += 1
    if len(exts) >= 3:
        score += 2
    elif len(exts) >= 1:
        score += 1
    if len(techs) >= 4:
        score += 2
    elif len(techs) >= 2:
        score += 1
    kind = "domain" if score >= 4 else "subskill"
    return kind, {"lines": lines, "exts": sorted(exts), "techs": sorted(techs), "score": score}


def import_skill(src, name=None, dry=False, deploy=True):
    p, text = read_skill(src)
    meta = parse(text)
    name = (name or meta["name"] or os.path.basename(os.path.dirname(p)) or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,40}", name or ""):
        raise SystemExit("[拒] 技能名不合法：%r（要英文/数字/._-，2–41 字）" % name)
    if not meta["description"]:
        raise SystemExit("[拒] 缺 description —— 它是模型选择该技能的唯一依据，必须先写")
    kind, m = classify(text, meta)
    dest = os.path.join(SKILL_DIR if kind == "domain" else PENDING, name)

    print("来源：%s" % p)
    print("名字：%s" % name)
    print("判定：**%s**（正文 %d 行 / 文件类型 %d 种 / 技法 %d 类 / 分 %d）"
          % ("域技能（常驻，自动被选中）" if kind == "domain" else "子技能（不常驻，按需读）",
             m["lines"], len(m["exts"]), len(m["techs"]), m["score"]))
    print("去向：%s" % dest)
    if m["exts"]:
        print("      覆盖后缀：%s" % " ".join(m["exts"][:8]))

    if dry:
        print("\n[dry-run] 未写入。")
    else:
        if os.path.exists(dest):
            raise SystemExit("[拒] 目标已存在：%s（先改名或删除旧的）" % dest)
        os.makedirs(PENDING if kind == "subskill" else SKILL_DIR, exist_ok=True)
        shutil.copytree(os.path.dirname(p), dest) if os.path.isdir(os.path.dirname(p)) else None
        if not os.path.isdir(dest):
            os.makedirs(dest, exist_ok=True)
            shutil.copy2(p, os.path.join(dest, "SKILL.md"))
        # 域技能：同步部署（下次会话即可用）
        if kind == "domain" and deploy:
            tgt = os.path.join(DEPLOY, name)
            shutil.rmtree(tgt, ignore_errors=True)
            shutil.copytree(dest, tgt)
            print("已部署：%s（下次会话自动加载）" % tgt)

    print("\n== 给 Agent 的收尾清单（用户不用管这些） ==")
    if len(meta["description"]) < 40 or not re.search(r"[\u4e00-\u9fff]", meta["description"]):
        print("1. **改写 description**：必须写用户会说的原话 + 文件后缀（例：'这个 exe 加壳了怎么脱/"
              "脱壳/dump 内存 (.exe/.dll)'）。现在的描述模型很可能选不中。")
    else:
        print("1. description 看起来够用（含中文、长度 %d）" % len(meta["description"]))
    if kind == "subskill":
        print("2. 在所属**域**的 SKILL.md 里加一行：'需要时读 `_pending/%s/SKILL.md`'" % name)
    else:
        print("2. 若想让它进 gate 的 6 道判据（当见证域），再补 `pack.json`；不补也能用")
    print("3. 跑 `python Tool/scripts/check.py --fast` 验证")
    return kind, dest


def selftest():
    """自测：造一个假的域技能 + 一个假的子技能，验证判定与落位正确。"""
    ok = 0
    tmp = tempfile.mkdtemp(prefix="seep-skill-")
    try:
        # 域技能：长正文 + 多后缀 + 多技法
        d1 = os.path.join(tmp, "big")
        os.makedirs(d1)
        io.open(os.path.join(d1, "SKILL.md"), "w", encoding="utf-8").write(
            "---\nname: zz-big\ndescription: \"测试：分析各种目标，脱壳/反调试/抓包/取证 (.exe/.apk/.bin)\"\n---\n"
            + "\n".join(["## 段 %d 脱壳 反调试 取证 抓包 .exe .apk .bin" % i for i in range(140)]))
        k1, _ = classify(io.open(os.path.join(d1, "SKILL.md"), encoding="utf-8").read(), {})
        assert k1 == "domain", k1
        ok += 1
        # 子技能：短正文 + 单一技法
        d2 = os.path.join(tmp, "small")
        os.makedirs(d2)
        io.open(os.path.join(d2, "SKILL.md"), "w", encoding="utf-8").write(
            "---\nname: zz-small\ndescription: \"只做一件事：读 yara 规则 (.yar)\"\n---\n## 1\n小技巧\n")
        k2, _ = classify(io.open(os.path.join(d2, "SKILL.md"), encoding="utf-8").read(), {})
        assert k2 == "subskill", k2
        ok += 1
        print("自测通过：域/子技能判定正确（%d/2）" % ok)
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="导入外部技能（判定域/子技能 + 落位 + 部署）")
    ap.add_argument("--from", dest="src", default="", help="外部技能的目录或 SKILL.md 路径")
    ap.add_argument("--name", default="", help="覆盖技能名（默认取 frontmatter 的 name）")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.src:
        ap.print_help()
        return 4
    import_skill(a.src, a.name or None, dry=a.dry_run)
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
