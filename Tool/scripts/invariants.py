# -*- coding: utf-8 -*-
"""架构不变量（Architecture Invariants）—— 一张矩阵覆盖**全部正式域**（数量动态）。

为什么要有这个（2026-10-25 用户决定）：
    "真跑每个域"不可行，也不是成熟项目的做法。真正要保证的是**逻辑闭环**。

**口径修正（2026-10-27）**：不变量只证明「结构闭环」，**不能**证明「该域在真实任务里
能接上」。可用性另有独立证据面（gate.py 的 real/public 见证、domain-gate 的脚本自检、
部署哈希、领域行为验收）；任何一条不变量通过都不许被读成“域可用”。

用法：
    python Tool/scripts/invariants.py            # 人读矩阵
    python Tool/scripts/invariants.py --json     # 机读
    python Tool/scripts/invariants.py --check    # 有不变量不成立 → 退出码 1
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys

# 中文 Windows 控制台默认 cp936/GBK，矩阵里的 ✓/✗ 会直接抛 UnicodeEncodeError，
# 导致 --check 与 --json 两种模式都“从未真正求值”。这里无条件改成 UTF-8（管道/重定向亦生效），
# errors="replace" 保证再怎么奇怪的字符也只是显示成 ?，不会让检查本身崩掉。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 —— 极老旧解释器/已被替换的流（如 None）时忽略
        pass

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SKILL = os.path.join(ROOT, "Tool", "skill")
CFG = os.path.join(ROOT, "Tool", "config")

# 域清单**唯一来源**：lib/domain_registry（pack.json#id，动态；不按“恰 9 目录”定义）。
# 以前这里按磁盘扫 `Tool/skill/*/SKILL.md`，扫出 11 个——把判型层 seep-router 与
# 横切层 unpack-loop 也算成“域”。现在它们由 domain-aliases.json#cross_cutting 排除，
# 即使将来出现 pack 也不会进正式域全集（route/registry 会显式报命名空间冲突）。
sys.path.insert(0, os.path.join(ROOT, "Tool", "scripts", "lib"))
import domain_registry as registry_mod  # noqa: E402
from domain_spec import DOMAINS  # noqa: E402
from runtime_root import RuntimeRootError, resolve_agent_root  # noqa: E402

_REGISTRY = registry_mod.load_registry(ROOT)
# 兼容旧消费者（skill-import.py 用 getattr(inv, "DOMAIN_COUNT") 报缺口）：
# **不是**阈值/期望值，只是“当前正式域个数”的派生视图（随 pack 变化，会一起变）。
DOMAIN_COUNT = len(_REGISTRY.ids())

INVARIANTS = {
    "I1": "入口唯一：判型只在一处（seep-router），域不自称总控",
    "I2": "能力可达：pack.tools 里每个工具都有落点（脚本/能力表/内置命令）",
    "I3": "交接闭包：SKILL 里指向别处的路径都存在，且不指向自己",
    "I4": "证据同构：所有域的证据契约（require / 禁止的置信度）完全一致",
    "I5": "等级唯一：M1–M4 只在 seep-router 定义，其它域只引用",
    "I6": "失败可表达：每个域都有 invalidation（什么情况判废、回哪一层）",
    "I7": "见证可跑：每个域的 witness_tool 脚本文件真实存在",
    "I8": "部署等价：仓库技能 ↔ 已部署技能 哈希一致",
    "I9": "能力有路线：声明脱壳/加壳/加固的域必须指向 unpack-loop（否则遇加固样本会直接改产物）",
}


def _domains():
    """正式域全集（唯一来源 lib/domain_registry，动态——不按“恰 9 个”定义）。

    seep-router（判型层）与 unpack-loop（横切层）不是客户可见域，不进矩阵；
    它们与各域的约束关系在 I1 / I9 里以“被引用”的方式检查。
    缺 SKILL.md / 缺 depth_contract 的域**不剔除**，由 check() 直接判红（不允许静默消失）。
    """
    return _REGISTRY.ids()


def _pack(name):
    p = os.path.join(SKILL, name, "pack.json")
    if not os.path.isfile(p):
        return None
    try:
        with open(p, encoding="utf-8") as stream:
            return json.load(stream)
    except Exception:  # noqa: BLE001
        return None


def _skill_text(name):
    p = os.path.join(SKILL, name, "SKILL.md")
    try:
        with open(p, encoding="utf-8", errors="replace") as stream:
            return stream.read()
    except Exception:  # noqa: BLE001
        return ""


def check(name):
    """对单个域返回 {invariant_id: (ok, note)}。"""
    res = {}
    # 结构注册（pack.json）与深度契约（depth_contract）是两件事：缺一个就明确报哪一个，
    # 不把“没 pack”静默当成“横切层可接受”。横切/判型层不走 check()（见 _domains()）。
    if _pack(name) is None:
        return {i: (False, "缺 Tool/skill/%s/pack.json（pack.id 是正式域唯一身份）" % name)
                for i in INVARIANTS}
    if name not in _REGISTRY.packs:
        return {i: (False, "pack 存在但未被载入器接受：%s" % "；".join(_REGISTRY.errors[:2]))
                for i in INVARIANTS}
    if _REGISTRY.depth(name) is None:
        reasons = "；".join(_REGISTRY.packs[name].depth_errors[:2]) or "depth_contract 不合法"
        return {i: (False, "缺/坏 depth_contract：%s" % reasons) for i in INVARIANTS}
    if not os.path.isfile(os.path.join(SKILL, name, "SKILL.md")):
        # 域在注册表里但磁盘上没技能：全部判红，不静默跳过。
        return {i: (False, "缺 Tool/skill/%s/SKILL.md" % name) for i in INVARIANTS}
    txt = _skill_text(name)
    pk = _pack(name)
    is_router = name == "seep-router"
    is_crosscut = name == "unpack-loop"

    # I1 入口唯一
    if is_router:
        res["I1"] = (pk is None, "判型层无 pack（不参与路由）" if pk is None else "判型层竟然有 pack")
    elif "总控" in txt.split("##")[0]:
        res["I1"] = (False, "域在自己的头部自称总控")
    else:
        res["I1"] = (True, "不自称总控")

    # I2 能力可达
    if pk is None:
        res["I2"] = (True, "无 pack（横切/判型层）")
    else:
        caps = {}
        try:
            with open(os.path.join(CFG, "tool-capabilities.json"), encoding="utf-8") as stream:
                caps = json.load(stream)
        except Exception:  # noqa: BLE001
            pass
        cap_ids = set((caps.get("tools") or {}).keys()) if isinstance(caps, dict) else set()
        if isinstance(caps, dict) and not cap_ids:
            cap_ids = {t.get("id") for t in (caps.get("capabilities") or []) if isinstance(t, dict)}
        # MCP 工具（seep_*）在服务端注册，不在能力表里 —— 从服务端源码与副作用表里取名字
        for src in (os.path.join(ROOT, "Tool", "mcp", "seep_mcp_server.py"),
                    os.path.join(CFG, "tool-effects.json")):
            try:
                with open(src, encoding="utf-8", errors="replace") as stream:
                    raw = stream.read()
            except Exception:  # noqa: BLE001
                continue
            cap_ids |= set(re.findall(r'name="(seep_[a-z0-9_]+)"', raw))
            cap_ids |= set(re.findall(r'"(seep_[a-z0-9_]+)"\s*:', raw))
        missing = []
        for t in pk.get("tools") or []:
            base = os.path.basename(str(t))
            local = os.path.join(SKILL, name, "scripts", base)
            in_caps = base in cap_ids or base.rstrip(".py") in cap_ids
            has_local = os.path.isfile(local)
            has_scripts = bool(glob.glob(os.path.join(ROOT, "Tool", "scripts", base))) or \
                bool(glob.glob(os.path.join(ROOT, "Tool", "scripts", "**", base), recursive=True))
            if not (in_caps or has_local or has_scripts):
                missing.append(base)
        res["I2"] = (not missing, "缺落点：%s" % "、".join(missing) if missing else "全部有落点")

    # I3 交接闭包
    refs = re.findall(r"Tool/skill/([A-Za-z0-9_.-]+)/SKILL\.md", txt)
    bad = []
    for r in set(refs):
        tgt = os.path.join(SKILL, r, "SKILL.md")
        if not os.path.isfile(tgt):
            bad.append("指向不存在的域 %s" % r)
        if r == name and not is_crosscut:
            bad.append("指向自己（%s）" % name)
    res["I3"] = (not bad, "；".join(bad) if bad else "引用 %d 个域，全部存在" % len(set(refs)))

    # I4 证据同构
    baseline = {"required_fields": ["claim", "confidence", "authority", "evidence"],
                "authority_allow": ["shipped-artifact", "controlled-replay", "external-service"],
                "pass_forbids_confidence": ["inferred", "unknown"]}
    if pk is None:
        res["I4"] = (True, "无 pack")
    else:
        ec = pk.get("evidence_contract") or {}
        same = all(sorted(ec.get(k) or []) == sorted(v) for k, v in baseline.items())
        res["I4"] = (same, "契约一致" if same else "契约与基线不同：%s" % json.dumps(ec, ensure_ascii=False)[:80])

    # I5 等级唯一
    if is_router:
        ok = all(m in txt for m in ("M1", "M2", "M3", "M4"))
        res["I5"] = (ok, "M1–M4 在此定义" if ok else "router 未定义全四级")
    else:
        mentions = re.findall(r"\bM[1-4]\b", txt)
        if not mentions:
            res["I5"] = (True, "未自造等级（不涉及）")
        else:
            points = "seep-router" in txt
            res["I5"] = (points, "引用 router 的等级" if points else "用了 M 级但没引用 seep-router")

    # I6 失败可表达
    if pk is None:
        ok = "## 什么时候停" in txt or "判废" in txt or "不适用" in txt
        res["I6"] = (ok, "有停止条件" if ok else "缺停止/判废条件")
    else:
        inv = pk.get("invalidation") or []
        res["I6"] = (bool(inv), "invalidation %d 条" % len(inv) if inv else "缺 invalidation")

    # I7 见证可跑
    wt = (pk or {}).get("witness_tool") or {}
    cmd = str(wt.get("cmd") or "")
    if not cmd:
        res["I7"] = (is_crosscut or is_router, "无 witness_tool（判型/横切层可接受）")
    else:
        base = os.path.basename(cmd.split()[0] if cmd.split() else "")
        p1 = os.path.join(SKILL, name, "scripts", base)
        p2 = os.path.join(ROOT, "Tool", "scripts", base)
        res["I7"] = (os.path.isfile(p1) or os.path.isfile(p2), base if (os.path.isfile(p1) or os.path.isfile(p2)) else "脚本不存在：%s" % base)

    # I8 部署等价
    try:
        agent_root = resolve_agent_root()
    except RuntimeRootError as exc:
        res["I8"] = (False, "AgentRoot 无效：%s" % exc.code)
    else:
        dep = os.path.join(str(agent_root), "skills", name)
        if not os.path.isdir(dep):
            res["I8"] = (False, "未部署（AgentRoot=%s）" % agent_root)
        else:
            import hashlib

            def h(p):
                with open(p, "rb") as stream:
                    b = stream.read()
                if b"\x00" not in b[:4096]:
                    b = b.replace(b"\r\n", b"\n")
                return hashlib.sha256(b).hexdigest()

            diffs = []
            for rel in ("SKILL.md", "pack.json"):
                src = os.path.join(SKILL, name, rel)
                dst = os.path.join(dep, rel)
                if os.path.isfile(src) and (not os.path.isfile(dst) or h(src) != h(dst)):
                    diffs.append(rel)
            res["I8"] = (not diffs, "一致" if not diffs else "不一致：%s" % "、".join(diffs))
    # I9 能力有路线
    if is_crosscut or is_router:
        res["I9"] = (True, "判型/横切层不适用")
    elif re.search(r"脱壳|加壳|加固", txt):
        res["I9"] = ("unpack-loop" in txt, "有指针" if "unpack-loop" in txt else "声明了脱壳能力但没有路线指针")
    else:
        res["I9"] = (True, "未声明脱壳能力")

    return res


def main():
    doms = _domains()
    rows = {d: check(d) for d in doms}
    json_out = "--json" in sys.argv
    fails = []
    for d, r in rows.items():
        for iid, (ok, note) in r.items():
            if not ok:
                fails.append((d, iid, note))
    if json_out:
        print(json.dumps({"domains": doms, "invariants": INVARIANTS,
                          "matrix": {d: {k: {"ok": v[0], "note": v[1]} for k, v in r.items()}
                                     for d, r in rows.items()},
                          "fails": [{"domain": d, "invariant": i, "note": n} for d, i, n in fails]},
                         ensure_ascii=False, indent=1))
    else:
        ids = list(INVARIANTS)
        print("架构不变量矩阵（%d 域 × %d 条）\n" % (len(doms), len(ids)))
        print("域".ljust(22) + " ".join(ids))
        for d in doms:
            line = d.ljust(20)
            for i in ids:
                ok = rows[d][i][0]
                line += " %s " % ("✓" if ok else "✗")
            print(line)
        print()
        for i in ids:
            print("%s %s" % (i, INVARIANTS[i]))
            bad = [(d, rows[d][i][1]) for d in doms if not rows[d][i][0]]
            for d, note in bad:
                print("     ✗ %-20s %s" % (d, note))
        print()
        print("结论：%s" % ("全部不变量成立（%d 域一次覆盖）" % len(doms) if not fails
                          else "%d 处违反" % len(fails)))
    if "--check" in sys.argv:
        return 1 if fails else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
