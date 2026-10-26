#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""导入外部技能：用户只说一句"我要加这个技能"，剩下的判定/改造/安装/验证由这里完成。

为什么（2026-10-24 用户提的最后一环）：
    用户从网上找到一个 skill，不会知道我们的架构（域 vs 子技能）、格式（frontmatter 要求）、
    放哪儿、要不要部署。**不该让用户手改**——他只要说"加这个"，剩下是 Agent 的事。

本脚本负责**机械部分**（可判定、可校验）：
    ① 校验 frontmatter（name / description 是否齐全、是否合法）
    ② **判定它是「域技能」还是「子技能」**（依据：显式声明 / 覆盖面 / 技法面，三选二，见 classify）
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
import json
import os
import re
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SKILL_DIR = os.path.join(ROOT, "Tool", "skill")
PENDING = os.path.join(SKILL_DIR, "_pending")
DEPLOY = os.path.expanduser(os.path.join("~", ".pi", "agent", "skills"))

# 域技能的"广度"判据（第 2 轮评审：老的「120 行 + 加权分数 ≥4」不可解释也不可复核）
DOMAIN_MIN_EXTS = 3        # 覆盖面：正文里出现的文件后缀**种类**
DOMAIN_MIN_TECHS = 4       # 技法面：正文里命中的技法类别
DOMAIN_MIN_TRIGGERS = 2    # 显式声明：description 里"用户会说的触发词"个数
DOMAIN_MIN_LINES = 120     # 仅供参考，不再参与判定（行数多 ≠ 域技能）
FILE_EXT_RE = re.compile(r"\.(exe|dll|sys|so|dylib|apk|aab|dex|bin|img|trx|squashfs|ubi|pcap|jar|ipa|"
                         r"elf|macho|js|php|py|zip|7z|ova|qcow2)\b", re.I)
TECH_HINTS = ("脱壳", "反调试", "抓包", "加密", "混淆", "反编译", "溢出", "注入", "取证", "报文", "固件",
              "解包", "重打包", "hook", "unpack", "decompile", "exploit", "fuzz", "kernel", "driver")

# "用户会说的触发词"：模型选技能只看 description，里面没有用户原话就选不中。
# 命中 ≥2 个 = 这份描述能承接真实对话，才配当常驻入口（域技能）。
TRIGGER_HINTS = ("怎么", "如何", "为什么", "帮我", "能不能", "这是什么", "怎么办", "什么工具",
                 "脱壳", "加壳", "加固", "反调试", "抓包", "解包", "重打包", "反编译", "破解",
                 "解密", "加密", "混淆", "取证", "溢出", "注入", "固件", "协议", "证书", "内存",
                 "hook", "dump", "unpack", "decompile", "patch", "crack", "fuzz", "trace")

# 一看就知道"这是整个下载的项目"的标志（2026-10-26 第 2 轮评审：copytree 会把整仓搬进技能目录）
PROJECT_MARKERS = (".git", ".gitmodules", ".github", "node_modules", "package.json",
                   "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.toml", "go.mod",
                   "pom.xml", ".vscode", "docker-compose.yml", "vite.config.ts", "webpack.config.js")
COPY_IGNORE = shutil.ignore_patterns(".git", ".github", "node_modules", "__pycache__", ".venv",
                                     ".pytest_cache", "*.pyc")


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


def _criterion_declared(meta):
    """判据 A 显式声明：frontmatter 有 name + description，且描述里 ≥2 个用户会说的触发词。"""
    name, desc = (meta.get("name") or ""), (meta.get("description") or "")
    if not name or not desc:
        return False, "frontmatter 缺 name 或 description（name=%r）" % name
    low = desc.lower()
    hits = [t for t in TRIGGER_HINTS if t.lower() in low]
    if len(hits) < DOMAIN_MIN_TRIGGERS:
        return False, ("description 只命中 %d 个用户触发词（门槛 %d）：%s"
                       % (len(hits), DOMAIN_MIN_TRIGGERS, "、".join(hits) or "无"))
    return True, ("name=%s / description 命中 %d 个用户触发词：%s"
                  % (name, len(hits), "、".join(hits)))


def classify(text, meta=None):
    """域 vs 子技能：三条**可单独解释**的判据，命中任意两条 = 域技能。

    为什么换掉旧实现（第 2 轮评审）：「120 行 + 分数 ≥4」只能回答"分够了"，
    而用户问的是"凭什么是域技能"。现在的三条都可以指着正文/描述核对：
      A 显式声明：frontmatter 有 name + description，且描述含 ≥2 个用户会说的触发词；
      B 覆盖面：正文覆盖的**文件后缀种类** ≥ 3；
      C 技法面：正文命中的**技法类别** ≥ 4。
    A 管"模型能不能选得中它"，B/C 管"它是不是一份能接住多种输入的入口文档"。
    """
    meta = meta if meta else parse(text)
    lines = len(text.splitlines())
    exts = sorted({e.lower() for e in FILE_EXT_RE.findall(text)})
    techs = sorted({t for t in TECH_HINTS if t.lower() in text.lower()})
    a_ok, a_why = _criterion_declared(meta)
    b_ok = len(exts) >= DOMAIN_MIN_EXTS
    b_why = "覆盖后缀 %d 种（门槛 %d）：%s" % (len(exts), DOMAIN_MIN_EXTS, " ".join(exts[:10]) or "无")
    c_ok = len(techs) >= DOMAIN_MIN_TECHS
    c_why = "命中技法 %d 类（门槛 %d）：%s" % (len(techs), DOMAIN_MIN_TECHS, "、".join(techs[:10]) or "无")
    hits = sum(1 for ok in (a_ok, b_ok, c_ok) if ok)
    kind = "domain" if hits >= 2 else "subskill"
    return kind, {
        "lines": lines, "exts": exts, "techs": techs, "hits": hits,
        "criteria": [("A 显式声明", a_ok, a_why),
                     ("B 覆盖面", b_ok, b_why),
                     ("C 技法面", c_ok, c_why)],
    }


def _download_markers(d):
    """目录里出现这些 = 用户给的是「整个下载的项目」，而不是技能目录。"""
    return [x for x in PROJECT_MARKERS if os.path.exists(os.path.join(d, x))]


def _copy_plan(src_dir):
    """复制范围 = SKILL.md 的**父目录本身**（不往上一层爬，也不整仓搬）。返回文件数。"""
    n = 0
    for _r, ds, fs in os.walk(src_dir):
        ds[:] = [x for x in ds if x not in (".git", ".github", "node_modules", "__pycache__", ".venv")]
        n += len(fs)
    return n


def _effect_status(kind, name, dest, dry, deploy=True):
    """R6 P1-7：判成子技能 / 只落 `_pending/` / dry-run 时，“不生效”必须说出来。

    血案（`Tool/scripts/skill-import.py` 原实现）：判为 subskill 时只打印一份收尾清单，
    用户（和 Agent）以为“已导入”，实际它没进 `~/.pi/agent/skills/`，模型永远选不中它。
    返回 (effective, why, 3 条要生效的具体动作)。
    """
    if kind == "subskill":
        why = ("判为子技能（不常驻）：它只在 %s/，不会部署到 ~/.pi/agent/skills/，"
               "模型按需读、不会自动选中它" % ("Tool/skill/_pending/" + name))
        acts = [
            "把它改写成域技能（frontmatter 的 description 写用户会说的原话 + 文件后缀，正文补齐覆盖面/技法面），"
            "再重跑本脚本落到 Tool/skill/%s/" % name,
            "或者把它并进所属域的 SKILL.md：在那些域里加一行「需要时读 _pending/%s/SKILL.md」" % name,
            "改完跑 python Tool/scripts/check.py --fast 验证（确认它真的进了加载名单）",
        ]
        return False, why, acts
    if dry:
        why = "dry-run：什么都没写盘，%s/ 与 ~/.pi/agent/skills/%s/ 都不存在，模型选不中它" % (name, name)
        acts = [
            "去掉 --dry-run 重跑同一条命令（真正落到 Tool/skill/%s/）" % name,
            "确认 description 里含用户会说的原话 + 文件后缀（模型只看这一句）",
            "跑 python Tool/scripts/check.py --fast 验证（部署目录与仓库一致）",
        ]
        return False, why, acts
    if not deploy:
        why = "本次传了 deploy=False：只落在仓库 Tool/skill/%s/，没同步到 ~/.pi/agent/skills/" % name
        acts = [
            "用默认参数（不带 deploy=False）重跑本脚本",
            "或者手动拷 Tool/skill/%s/ 到 ~/.pi/agent/skills/%s/" % (name, name),
            "跑 python Tool/scripts/check.py --fast 验证",
        ]
        return False, why, acts
    return True, "已部署到 ~/.pi/agent/skills/%s/（域技能，下次会话自动加载）" % name, []


def import_skill(src, name=None, dry=False, deploy=True):
    p, text = read_skill(src)
    meta = parse(text)
    name = (name or meta["name"] or os.path.basename(os.path.dirname(p)) or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,40}", name or ""):
        raise SystemExit("[拒] 技能名不合法：%r（要英文/数字/._-，2–41 字）" % name)
    if not meta["description"]:
        raise SystemExit("[拒] 缺 description —— 它是模型选择该技能的唯一依据，必须先写")

    # ★ 复制范围严格锁定在「SKILL.md 的父目录」（第 2 轮评审：旧版 copytree(dirname)
    #   会把整个下载目录——含 .git/node_modules——搬进技能目录）。
    src_dir = os.path.dirname(os.path.abspath(p))
    markers = _download_markers(src_dir)
    if markers:
        raise SystemExit(
            "[拒] 这是**整个下载的项目**，不是技能目录：%s 里有 %s\n"
            "     请只给技能目录（含 SKILL.md 的那个目录），例如 %s\n"
          "     为什么：复制范围 = SKILL.md 的父目录；父目录是项目根时，整个仓（含 .git、\n"
            "     node_modules）会被一起搬进技能目录，技能包体就烂了。"
            % (src_dir, "、".join(markers), os.path.join(src_dir, "<技能名>", "SKILL.md")))

    kind, m = classify(text, meta)
    dest = os.path.join(SKILL_DIR if kind == "domain" else PENDING, name)

    print("来源：%s" % p)
    print("名字：%s" % name)
    print("判定：**%s**（三选二，命中 %d/3）"
          % ("域技能（常驻，自动被选中）" if kind == "domain" else "子技能（不常驻，按需读）", m["hits"]))
    for ck, c_ok, c_why in m["criteria"]:
        print("  判据 %s %s：%s" % ("✅" if c_ok else "❌", ck, c_why))
    print("     （参考：正文 %d 行 —— 行数不再参与判定）" % m["lines"])
    print("去向：%s" % dest)
    print("复制范围：%s（仅此目录，%d 个文件；不含 .git/node_modules）"
          % (src_dir, _copy_plan(src_dir)))

    if dry:
        print("\n[dry-run] 未写入。")
    else:
        if os.path.exists(dest):
            raise SystemExit("[拒] 目标已存在：%s（先改名或删除旧的）" % dest)
        os.makedirs(PENDING if kind == "subskill" else SKILL_DIR, exist_ok=True)
        shutil.copytree(src_dir, dest, ignore=COPY_IGNORE)
        print("已复制：%s → %s（只取技能目录本身）" % (src_dir, dest))
        # 域技能：同步部署（下次会话即可用）
        if kind == "domain" and deploy:
            tgt = os.path.join(DEPLOY, name)
            shutil.rmtree(tgt, ignore_errors=True)
            shutil.copytree(dest, tgt, ignore=COPY_IGNORE)
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

    # R6 P1-7：“不生效”必须说出来（不是只报一句判定就完事）：
    # 用户在导入技能时问的就是“加好了吗”；子技能落在 _pending/ 却没被选中，不说就是骗人。
    effective, eff_why, eff_acts = _effect_status(kind, name, dest, dry, deploy)
    if effective:
        print("\n[已生效] 模型能自动选中它：%s" % eff_why)
    else:
        print("\n[未生效] 该技能不会被自动选中：%s；要生效请 ①%s ②%s ③%s"
              % (eff_why, eff_acts[0], eff_acts[1], eff_acts[2]))
    report = {
        "kind": kind,
        "name": name,
        "dest": dest,
        "effective": effective,
        "why": eff_why,
        "to_take_effect": eff_acts,
        "dry_run": bool(dry),
        "hits": m["hits"],
    }
    print("[报告] " + json.dumps(report, ensure_ascii=False))
    return report


def selftest():
    """自测：域/子技能判定（三选二）+ 复制范围锁定 + 下载项目拒绝。"""
    ok, total = 0, 6
    tmp = tempfile.mkdtemp(prefix="seep-skill-")

    def _mk(d, body):
        os.makedirs(d, exist_ok=True)
        io.open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8").write(body)
        return d

    try:
        # ① 域技能：声明（A）+ 多后缀（B）+ 多技法（C）→ 3/3
        d1 = _mk(os.path.join(tmp, "big"),
                 "---\nname: zz-big\ndescription: \"这个 exe 加壳了怎么脱壳/反调试/抓包 (.exe/.apk/.bin)\"\n---\n"
                 + "\n".join(["## 段 %d 脱壳 反调试 取证 抓包 .exe .apk .bin" % i for i in range(140)]))
        t1 = io.open(os.path.join(d1, "SKILL.md"), encoding="utf-8").read()
        k1, m1 = classify(t1, parse(t1))
        assert k1 == "domain" and m1["hits"] >= 2, (k1, m1)
        ok += 1
        # ② 子技能：短正文 + 单一技法 + 描述无触发词 → 0/3
        d2 = _mk(os.path.join(tmp, "small"),
                 "---\nname: zz-small\ndescription: \"读 yara 规则 (.yar)\"\n---\n## 1\n小技巧\n")
        t2 = io.open(os.path.join(d2, "SKILL.md"), encoding="utf-8").read()
        k2, m2 = classify(t2, parse(t2))
        assert k2 == "subskill", (k2, m2)
        ok += 1
        # ③ 判据 A 单独可解释（不靠行数：短正文 + 好描述 = A 命中）
        d3 = _mk(os.path.join(tmp, "short-good"),
                 "---\nname: zz-short\ndescription: \"这个 apk 怎么脱壳 / 抓包 / 解包\"\n---\n短\n")
        t3 = io.open(os.path.join(d3, "SKILL.md"), encoding="utf-8").read()
        a_ok, a_why = _criterion_declared(parse(t3))
        assert a_ok, a_why
        ok += 1
        # ④ 只给 SKILL.md 时复制范围 = 父目录（不往上爬）
        assert _copy_plan(d1) >= 1
        assert os.path.dirname(os.path.abspath(os.path.join(d1, "SKILL.md"))) == d1
        ok += 1
        # ⑤ 父目录像"整个下载的项目"→ 拒绝（有 .git/node_modules）
        repo = os.path.join(tmp, "downloaded-repo")
        os.makedirs(os.path.join(repo, ".git"), exist_ok=True)
        os.makedirs(os.path.join(repo, "node_modules"), exist_ok=True)
        _mk(os.path.join(repo, "skill"), "---\nname: zz-x\ndescription: \"x\"\n---\n")
        assert ".git" in _download_markers(repo), _download_markers(repo)
        assert not _download_markers(os.path.join(repo, "skill"))
        ok += 1
        # ⑥ 判为子技能 / dry-run 时，“未生效”必须能说出来（R6 P1-7）
        eff, eff_why, eff_acts = _effect_status("subskill", "zz-small", "Tool/skill/_pending/zz-small", False)
        assert eff is False and "不会" in eff_why and len(eff_acts) == 3, (eff, eff_why, eff_acts)
        eff2, _, acts2 = _effect_status("domain", "zz-big", "Tool/skill/zz-big", True)
        assert eff2 is False and len(acts2) == 3, (eff2, acts2)
        eff3, _, _ = _effect_status("domain", "zz-big", "Tool/skill/zz-big", False, True)
        assert eff3 is True
        ok += 1
        print("自测通过：判定/复制范围/项目拒绝/未生效提示（%d/%d）—— A/B/C 三选二，行数不参与" % (ok, total))
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
