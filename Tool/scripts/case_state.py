#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""case_state.py —— 案子的事实账 / 深度门 / 可行性裁定 / 出口闸。

存在的原因（血案）：
    一次会话在第 20 秒就报出"权威在客户端"的结论（照抄上一轮报告），3 分 46 秒开始造交付物，
    3.5 小时后发现方向从一开始就错，中途改判 4 次且全部静默。
    问题不是"分析太少"，而是**结论没有证据、也没有任何东西拦住它往下走**。

    光在技能里写规则没用 —— 这次就把规则变成可执行的闸：
      1. 结论必须落成 claim（带 status / evidence / how / ttl）；
      2. 深度 D0–D5 必须逐级登记（做到 / 做不到 + 原因）；
      3. 可行性裁定必须显式写（可赢 / 部分可赢 / 不可赢 + 交付上限）；
      4. `gate` 子命令把上面三条合成一个退出码 —— 过了才允许进下一阶段。

用法：
    python Tool/scripts/case_state.py init    --case <目录> --target <样本>
    python Tool/scripts/case_state.py claim   --case <目录> --id C01 --text "权威在服务端" \\
                                              --status hypothesis --how "triage" 
    python Tool/scripts/case_state.py prove   --case <目录> --id C01 \
                                              --evidence "capture/run.json"   # 路径/命令+产物/哈希/账本编号，纯文本一律拒
    python Tool/scripts/case_state.py verify-origin --case <目录>            # 重算原件 sha256，变了/移了 rc=2
    python Tool/scripts/case_state.py refute  --case <目录> --id C01 --by "C05"
    python Tool/scripts/case_state.py depth   --case <目录> --level D2 --result pass --note "LoadLibrary 命中 winhttp"
    python Tool/scripts/case_state.py stale   --case <目录> --reason "换 exe:sha256 变了"
    python Tool/scripts/case_state.py gaps    --case <目录> --add --id G1 --missing "有效卡密" \
                                              --impact "拿不到合法响应" --repairable no \
                                              --delta -0.45 --alt "买真卡|旧版存档"
    python Tool/scripts/case_state.py gaps    --case <目录> --list
    python Tool/scripts/case_state.py plan    --case <目录> --level L2 --route "字节补丁" \
                                              --p 0.85 --hours "1-2" --needs "" --fail "打完仍无界面"
    python Tool/scripts/case_state.py plan    --case <目录> --list
    python Tool/scripts/case_state.py choose  --case <目录> --level L2 --route "字节补丁"
    python Tool/scripts/case_state.py advise  --case <目录> --form pe-shelled
    python Tool/scripts/case_state.py verdict --case <目录> --value 部分可赢 --tier M2 \
                                              --note "缺有效卡密(G1)，钥匙在服务端"
    python Tool/scripts/case_state.py gate    --case <目录>
    python Tool/scripts/case_state.py gate    --case <目录> --stage 0a   # 阶段产物闸（按内容判）
    python Tool/scripts/case_state.py stage   --case <目录> --set 0b      # 进阶前先过 [当前阶段) 的产物闸
    python Tool/scripts/case_state.py stage   --case <目录> --set 2 --force --reason "历史产物已不在盘上"
    python Tool/scripts/case_state.py stage   --case <目录> --show
    python Tool/scripts/case_state.py show    --case <目录>
    python Tool/scripts/case_state.py resume  --case <目录>

租约锁（P1-2：治「双会话同写静默丢条」+ 半截写盘）：
    python Tool/scripts/case_state.py lock   --case <目录> [--ttl 3600] [--force]
    python Tool/scripts/case_state.py unlock --case <目录> [--force]
    python Tool/scripts/case_state.py who    --case <目录>
    写盘命令（claim/prove/refute/stale/depth/verdict/instrument/choose/
    deliver/ask/ack/gaps/plan）都会先查租约：无锁只警告 [WARN] NO_LEASE 仍执行，
    别人持锁则 rc=2 拒绝写；只读命令（gate/show/resume/events/advise）不查。

阶段零出口物（B 批新增；S2 起 state 不再单独落盘）：
    facts.jsonl（唯一账本：claim / kind:"state" 重放行 / kind:"event"）+ gaps.json + plan.json。
    state = 账本里最后一条 state 行重放（`replay` 查看 / --migrate 迁移 / --compact 瘦身）。
    gate 除原有断言外，还要求：stale 全部复验、plan ≥2 条候选、verdict 后必须 choose、
    不可补缺件要写进 verdict note 且菜单里不得有依赖它的路线。

状态副本收口（S2-1）：
    `replay`  状态重放（state 不存快照）      `index`  案例索引现算（不落 index.json）
    `verify`  证据强度聚合（unknown 永不计 pass）

阶段机 + 产物闸（P2-1）：
    state.stage ∈ intake|0a|0b|1|2|3|4|done，每次变更追进 stage_history。
    gate --stage <s> 只认磁盘产物的**内容**，不认自述：
      0a report/triage.md    ≥300B + 六字段名（载体/保护/授权权威/改动面/检测器/交付壁垒）
      0b report/static.md    ≥600B + `## ` 小节 ≥3 + 含 facts 或 证据
      1  capture/login.json（凭据类）  能 json.load + 非空 device_id
         capture/run.json（运行类）   能 json.load + 非空 cmd/stdout_head/expect + 整数 exit
         两者二选一即可；都在时用凭据类，并在输出里注明 run.json 已忽略
      2  report/dynamic.md   ≥600B + RVA / VA / 基址 三个词（地址台账三列）
      3  artifacts/MANIFEST.sha256  每条 `sha256  path` 文件存在且哈希一致
      4  report/final.md     ≥300B + 含 验收/功能 + state.verdict 非空
    另：stage 不一致、awaiting_human 未 ack 都直接红。不带 --stage 时 gate 行为不变。

进阶闸（P2-4 缝1：`stage --set` 以前不校验产物 → 可静默跳阶）：
    从 S 前进到 T 之前，[S, T) 每个阶段的产物闸（与 `gate --stage` 同一套判据）都要先过；
    不过 → rc=2 + 打印缺什么 + 给 --force 提示。三条豁免（都写理由，不许变成新的缝）：
      ① intake → 0a：还没产物可查；
      ② 回退（T 不晚于 S）：回退不是进阶，不产生新的「未挣到的阶段」；
      ③ 复位/复核（T 在 stage_history 里到达过）：当时已过闸，重走只算复核。
    另（P0-3b）：进阶段 1 及以后必须先有 scope.md 且「授权来源」命中本人自有 / 书面授权 /
    公开靶场 / 开源 之一；该条**不受**豁免③影响（复位也不能绕过授权事实的机检）。
    --force 允许跳过，但必须配 --reason "..."（缺 reason → rc=2）；
    state.stage_history 里记 forced:true + reason + skipped（跳掉的阶段）。

两套词表（P2-4 缝2：`--tier` 以前只收 T1/T2/T3，但阶段用的是 M1–M4）：
    T 词表 = 后端档位 T1–T4（05-backend-rebuild 三问定档）；M 词表 = 交付上限 M1–M4。
    `verdict --tier` 两套都收，**哪个词表就原样存哪个槽位**（T→state.tier，M→state.max_level），
    绝不改写用户输入；换算只用于展示：M1↔T1 / M2↔T2 / M3|M4↔T3（`show` 里同时打印两栏）。

退出码：gate 0=通过 / 1=未通过；其它命令 0=成功 / 2=参数或状态错误
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

LEVELS = ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7"]
CORE_LEVELS = ["D0", "D1", "D2", "D3", "D4", "D5"]
# 旧案扩展级：缺失只告警、不阻断；但裁定=可赢时必须至少 na + 原因（见 gate）
OPTIONAL_LEVELS = ["D6", "D7"]
LEVEL_NAME = {
    "D0": "结构（节表/资源/导入/字符串/熵）",
    "D1": "存活（能否到第一个窗口；双击与程序拉起分开测）",
    "D2": "动态依赖（运行时实际加载的网络/加密库）",
    "D3": "出站行为（DNS/TCP/明文或TLS/时间点）",
    "D4": "对照实验（断网/换目录/改时间）",
    "D5": "钥匙归属（文件/内存/授权后产生）",
    "D6": "kill-switch 层数（几层独立闸门、是否逐层验证）",
    "D7": "静默失败面（进程活着但不干活：网络/文件/窗口/API 序列四路）",
}
PLAN_LEVELS = ["L0", "L1", "L2", "L3", "L4"]
GAP_REPAIRABLE = ["yes", "no", "partial"]
# 缺件规则：repairable=no 且 delta <= 此值 → 阻断（note 必须提、菜单不得依赖）
GAP_DELTA_BLOCK = -0.3
CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")
VERDICTS = ["可赢", "部分可赢", "不可赢"]
INSTRUMENTS = ["baseline", "x64dbg", "frida-spawn", "frida-attach", "external", "network"]
INSTRUMENT_NAME = {
    "baseline": "裸启动（双击 / explorer，不挂任何仪器）",
    "x64dbg": "调试器 attach（最容易被反调试干掉）",
    "frida-spawn": "Frida spawn（-f，启动即挂）",
    "frida-attach": "Frida attach（进程起来后挂）",
    "external": "外部观测（Procmon / ETW / 文件与注册表快照 diff）",
    "network": "网络层（代理 / 抓包 / 冒充服务器）",
}
ISTATUS = ["ok", "partial", "blocked", "killed"]
MAX_LEVEL_BY_VERDICT = {"可赢": "M3", "部分可赢": "M2", "不可赢": "M1"}
# 后端档位（05-backend-rebuild 三问定档）：不可赢恒 M1；否则 T1→基准、T2→M3、T3/T4→M4
# 缝2（P2-4）：这里原本只认 T1/T2/T3，和阶段/交付用的 M1–M4 是两套词表，用户传 M2 会被挡。
# 现在两套都收，各存各的槽位（T→tier，M→max_level），换算只用于展示：
#   M1↔T1 / M2↔T2 / M3|M4↔T3（T4 在 M 词表里没有更上级，展示成「无对应」）。
TIERS_T = ["T1", "T2", "T3", "T4"]   # 后端档位词表
TIERS_M = ["M1", "M2", "M3", "M4"]   # 交付上限词表（deliver 封顶用）
TIERS = TIERS_T + TIERS_M
M_TO_T = {"M1": "T1", "M2": "T2", "M3": "T3", "M4": "T3"}
T_TO_M = {"T1": "M1", "T2": "M2", "T3": "M3|M4", "T4": "（无对应）"}
# T 档位 → 交付上限（既有规则不变：T1 走裁定基准，T2→M3，T3/T4→M4）
TIER_LEVEL = {"T1": None, "T2": "M3", "T3": "M4", "T4": "M4"}
STATUSES = ["hypothesis", "proven", "refuted"]

# ---------------------------------------------------------------- 阶段机（P2-1）
# 血案：产物闸以前只认「文件存不存在」→ 空文件 / 400 字节垃圾都能过关，
# 「2 分钟造假过关」是真实发生过的通关路径。现在每一阶段都按**文件内容**判。
STAGES = ["intake", "0a", "0b", "1", "2", "3", "4", "done"]
STAGE_NEXT = {"intake": "0a", "0a": "0b", "0b": "1", "1": "2",
              "2": "3", "3": "4", "4": "done", "done": "done"}
STAGE_NAME = {
    "intake": "建案（init）",
    "0a": "快筛画像卡（00-triage）",
    "0b": "静态分析（00-analysis）",
    "1": "登录/鉴权抓取",
    "2": "动态分析 + 地址台账",
    "3": "产物清单与哈希（MANIFEST）",
    "4": "最终报告与验收",
    "done": "结案",
}
# 这些阶段是「已经动手」的阶段：先要用户的回执，不许替人做主往下走
STAGE_ACK_REQUIRED = {"1", "2", "3", "4"}
TRIAGE_FIELDS = ["载体", "保护", "授权权威", "改动面", "检测器", "交付壁垒"]
FINAL_WORDS = ["验收", "功能"]
DYNAMIC_WORDS = ["RVA", "VA", "基址"]


def paths(case):
    d = os.path.abspath(case)
    return d, os.path.join(d, "facts.jsonl")


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


# ---------------------------------------------------------------- 原子写
# 血案：整文件 json.dump 直写 + 跨会话无锁 = 写入被打断就留半截 JSON，整份账本从此读不出来。
# 现在统一走 tempfile(同目录) → flush+fsync → os.replace，失败清理 tmp。

def _tmp_sibling(path):
    """在目标同目录开临时文件：只有同目录 rename 才是原子的（跨盘 os.replace 不是）。"""
    d = os.path.dirname(os.path.abspath(path)) or "."
    if not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    return tempfile.mkstemp(dir=d, prefix=".tmp-" + os.path.basename(path) + "-", suffix=".part")


def _drop_tmp(tmp):
    if tmp and os.path.exists(tmp):
        try:
            os.remove(tmp)
        except OSError:
            pass


def _atomic_write_text(path, text):
    """原子写文本：tempfile → write → flush+fsync → os.replace。失败清理 tmp。"""
    fd, tmp = _tmp_sibling(path)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(text.encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None
    finally:
        _drop_tmp(tmp)


def _atomic_write_json(path, obj):
    _atomic_write_text(path, json.dumps(obj, ensure_ascii=False, indent=2))


def _atomic_append_line(path, line):
    """原子追加一行：先把旧内容抄进 tmp，再追加新行 → fsync → os.replace。

    为什么不用 open("a")：追加写到一半断电/被杀就是半行 JSON，load_facts 从此必报错。
    """
    fd, tmp = _tmp_sibling(path)
    try:
        with os.fdopen(fd, "wb") as out:
            if os.path.isfile(path):
                with open(path, "rb") as src:
                    shutil.copyfileobj(src, out, 1 << 20)
            out.write((line if line.endswith("\n") else line + "\n").encode("utf-8"))
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        tmp = None
    finally:
        _drop_tmp(tmp)


# ---------------------------------------------------------------- 租约锁（P1-2）
# 为什么需要：两个会话同时开同一个 case 时，旧实现是「各自 load → 各自整文件覆盖」，
# 后写的直接把先写的条目吃掉，且两边都不报错（静默丢条）。租约把「写权」显式化。

LEASE_NAME = ".lease.json"
LEASE_TTL_DEFAULT = 3600
_LEASE_NOTED = False    # 同一进程里 [WARN] NO_LEASE 只打一行


def _lease_path(case):
    return os.path.join(os.path.abspath(case), LEASE_NAME)


def _session_id():
    """会话标识：SEEP_SESSION_ID 优先（跨进程可重入的判据），缺省用当前 pid。"""
    s = (os.environ.get("SEEP_SESSION_ID") or "").strip()
    return s or str(os.getpid())


def _href():
    try:
        host = socket.gethostname()
    except Exception:
        host = "?"
    return "%s:%s" % (host, os.getcwd())


def _ts_epoch(v):
    """lease 时间字段 → epoch 秒。支持 epoch 数字 / ISO / "YYYY-mm-dd HH:MM:SS"。"""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v or "").strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        pass
    try:
        return datetime.datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s).timestamp()
    except Exception:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            return time.mktime(time.strptime(s, fmt))
        except Exception:
            continue
    return None


def _read_lease(case):
    """读租约。文件不存在/坏 JSON 一律当无锁（宁可放行 + 警告，也不要卡死老案子）。"""
    p = _lease_path(case)
    if not os.path.isfile(p):
        return None
    try:
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        return None
    return d if isinstance(d, dict) else None


def _write_lease(case, lease):
    _atomic_write_json(_lease_path(case), lease)


def _lease_status(lease):
    """→ (expired, age_sec, ttl_sec)。过期判据：now - heartbeat_at > ttl_sec。

    heartbeat_at 解析不出来时按「已过期」处理：锁坏了不该把案子的写权永久锁死。
    """
    try:
        ttl = float(lease.get("ttl_sec"))
    except (TypeError, ValueError):
        ttl = float(LEASE_TTL_DEFAULT)
    hb = _ts_epoch(lease.get("heartbeat_at"))
    if hb is None:
        return True, None, ttl
    age = time.time() - hb
    return (age > ttl), age, ttl


def _lease_expired(lease):
    return _lease_status(lease)[0]


def _print_holder(lease, tag="当前持有者"):
    expired, age, ttl = _lease_status(lease)
    print("[LEASE] %s：session=%s  pid=%s  ttl=%ds" % (
        tag, lease.get("session") or "?", lease.get("pid") or "?", int(ttl)))
    print("        acquired_at=%s  heartbeat_at=%s  age=%s" % (
        lease.get("acquired_at") or "-", lease.get("heartbeat_at") or "-",
        "?" if age is None else "%ds" % int(age)))
    if lease.get("href"):
        print("        href=%s" % lease["href"])
    if expired:
        print("        状态：已过期（now - heartbeat_at > ttl_sec）—— 任何会话都可接管")


def lease_guard(case, readonly=False):
    """写盘前的租约闸。

    - 无锁 / 已过期：打一行 [WARN] NO_LEASE，**仍然执行**（向后兼容既有用法）；
    - 别的会话持有效锁：rc=2 拒绝写，并给出 --force / 换 case / 只读 三条建议；
    - 自己持锁：静默放行。
    """
    global _LEASE_NOTED
    if readonly:
        return
    lease = _read_lease(case)
    me = _session_id()
    if lease is None or _lease_expired(lease):
        if not _LEASE_NOTED:
            _LEASE_NOTED = True
            print("[WARN] NO_LEASE —— %s 没有有效租约；本次写入继续（建议先 lock 再去掉这行警告）"
                  % os.path.abspath(case))
        return
    if str(lease.get("session") or "") == me:
        return
    print("[ERR] 写被拒绝：该 case 已被另一个会话锁定（双会话同写会静默丢条）")
    _print_holder(lease)
    print("[ERR] 建议：python Tool/scripts/case_state.py lock --case %s --force   # 接管写权"
          % case)
    print("      或换一个 --case；只想看内容用 show / resume / gate / who（只读，不写盘）")
    sys.exit(2)


URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def store_target(target):
    """--target 归一化：URL（http:// 或 https://）原样保存，本地路径才转绝对路径。

    血案：--target https://example.com 曾存成 D:\\...\\https:\\example.com（假本地路径），
    show 后与输入不一致。
    """
    t = (target or "").strip()
    if not t:
        return ""
    if URL_RE.match(t):
        return t
    return os.path.abspath(t)


LEDGER_STATE_KIND = "state"
LEDGER_EVENT_KIND = "event"
LEDGER_GAPS_KIND = "gaps"
LEDGER_PLAN_KIND = "plan"

def _state_default():
    return {"schema": "seep-case/1", "target": "", "depth": {}, "verdict": None,
            "max_level": None, "stage": "intake", "stage_history": [],
            "next_action": "", "updated": now()}

def load_ledger(case):
    """唯一账本 facts.jsonl 的全部行（claim / kind:"state" / kind:"event" 混存，append-only）。

    S2 起不再有第二份状态文件：state 由 state 行重放，事件账（工具流水）以 event 行
    追加进同一账本。S2 之前的两类历史副本已迁完，`replay --drop-legacy` 只负责清残留。
    """
    _, fp = paths(case)
    if not os.path.isfile(fp):
        return []
    out = []
    with open(fp, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                die("facts.jsonl 第 %d 行不是合法 JSON：%s（先修或备份后重写）" % (len(out) + 1, e))
    return out

def _entry_kind(entry):
    if not isinstance(entry, dict):
        return ""
    return str(entry.get("kind") or "").strip().lower()

def _is_claim(entry):
    """claim 行判据：有 id + status，且 kind 缺省或 claim。state/event 行不算 claim。"""
    if not isinstance(entry, dict):
        return False
    if not str(entry.get("id") or "").strip() or not str(entry.get("status") or "").strip():
        return False
    return _entry_kind(entry) in ("", "claim")

def load_facts(case):
    """只返回 claim 行（gate / verify 的判据面），state / event 行不外泄给旧消费者。"""
    return [e for e in load_ledger(case) if _is_claim(e)]

def _legacy_files(case):
    """S2 之前的两类历史副本（迁移已全部完成）。这里只报残留，供 `replay --drop-legacy` 清理。"""
    d, _ = paths(case)
    return [p for p in (os.path.join(d, "state.json"),
                        os.path.join(d, "ai_manifest.json")) if os.path.isfile(p)]

def load_state(case):
    """案子状态 = facts.jsonl 里最后一条 kind:"state" 行重放（不存快照）。"""
    d, _ = paths(case)
    if not os.path.isdir(d):
        die("case 目录不存在：%s\n先跑：case_state.py init --case %s --target <样本>" % (d, case))
    last = None
    for e in load_ledger(case):
        if _entry_kind(e) == LEDGER_STATE_KIND and isinstance(e.get("state"), dict):
            last = e["state"]
    st = _state_default()
    if isinstance(last, dict):
        st.update(last)
    return st


def save_state(case, st):
    """写回 = 往账本追加一条 state 行（append-only，最后一条生效）。

    为什么重放而不是覆盖快照：两个会话同时写同一份快照会静默丢条；
    append-only 最坏情况是"多一行"，不是"少一条"。
    """
    d, fp = paths(case)
    if not os.path.isdir(d):
        die("case 目录不存在：%s" % d)
    st = dict(st)
    st["updated"] = now()
    _atomic_append_line(fp, json.dumps({"kind": LEDGER_STATE_KIND, "ts": st["updated"],
                                        "state": st}, ensure_ascii=False))
    return "facts.jsonl#state"

def append_fact(case, fact):
    d, fp = paths(case)
    if not os.path.isdir(d):
        die_json("case-not-found",
                 "案例目录不存在：%s（先跑 case_state.py init --case <目录>）" % d)
    _atomic_append_line(fp, json.dumps(fact, ensure_ascii=False))


def die(msg, code=2):
    print(f"[ERR] {msg}")
    sys.exit(code)


def die_json(blocked_at, reason, code=2):
    """结构化失败：{ok:false, blocked_at, reason} + rc=2（供门禁与配方判据机检）。"""
    print(json.dumps({"ok": False, "blocked_at": blocked_at, "reason": reason},
                     ensure_ascii=False))
    sys.exit(code)


EVIDENCE_PATH_RE = re.compile(
    r"[\\/]|\.(?:json|jsonl|txt|log|md|bin|dmp|png|jpe?g|csv|xml|html|pcapng?|so|apk|exe|dll|zip|tar|gz)$",
    re.I)


# 证据必须是「别人能重放的材料」（外部评审第 2 轮：纯文本证据 = 没法核对）：
#   ① 路径且文件真实存在；② 命令 + 可核对产物（.json/.log/.md/sha256/rc=/exit=）；
#   ③ 哈希（32–64 位 hex 或 sha256:<hex>）；④ E-/F-/C- 编号且该编号在本案账本里存在。
# 反例「看过了」「已确认」「分析完成」一律拒绝。
EVIDENCE_CMD_PREFIXES = ("python ", "python3 ", "pwsh ", "powershell ", "bash ", "cmd ")
EVIDENCE_CMD_PRODUCT_RE = re.compile(r"\.json|\.log|\.md|sha256|rc=|exit=", re.I)
EVIDENCE_SHA_RE = re.compile(r"^(?:sha256:)?[0-9a-f]{32,64}$", re.I)
EVIDENCE_ID_RE = re.compile(r"\b([ECF])-(\d{2,})\b")
EVIDENCE_REPLAY_HINT = (
    "证据必须能被别人重放：给路径 / 命令+产物 / 哈希 / 账本编号其一\n"
    "     反例（一律拒绝）：「看过了」「已确认」「分析完成」——纯文本没法复现\n"
    "     正例：capture/run.json ｜ python Tool/scripts/preflight.py --fast -> x.json rc=0 ｜ "
    "<sha256> ｜ C-001（账本里已有的编号）")


def _evidence_is_command(ev):
    """命令形：以已知解释器开头或带 ` --` 参数，且同一串里带可核对的产出描述。"""
    low = ev.lower()
    if not (low.startswith(EVIDENCE_CMD_PREFIXES) or " --" in ev):
        return False
    return bool(EVIDENCE_CMD_PRODUCT_RE.search(ev))


def require_evidence(value, case=None):
    """证据必须可重放：路径存在 / 命令+产物 / 哈希 / 账本编号；纯文本一律拒绝。"""
    ev = (value or "").strip()
    if not ev:
        return ev
    # ① 命令 + 产物（先判：命令串里常含 `/`，会被 EVIDENCE_PATH_RE 误当路径）
    if _evidence_is_command(ev):
        return ev
    # ② 哈希
    if EVIDENCE_SHA_RE.match(ev):
        return ev
    # ③ 路径：形似路径就必须真实存在（原行为保留）
    #   先判路径存在：文件名里带 E-001 这类号时，存在文件优先于「账本编号」分支。
    path_like = bool(EVIDENCE_PATH_RE.search(ev))
    path_ok = False
    if path_like:
        cands = [ev]
        if case:
            cands.append(os.path.join(os.path.abspath(case), ev))
        path_ok = any(os.path.exists(c) for c in cands)
        if path_ok:
            return ev
    # ④ 账本编号：E-/F-/C- 且该编号在本案账本里存在（case 为空时不猜，走下面拒绝）
    ids = ["%s-%s" % (a_, b_) for a_, b_ in EVIDENCE_ID_RE.findall(ev)]
    if ids:
        have = set()
        if case:
            try:
                have = _ledger_ids(os.path.abspath(case))
            except Exception:  # noqa: BLE001 —— init 早期账本还没写，别在这里崩
                have = set()
        if any(i.upper() in have for i in ids):
            return ev
        if not path_like:
            die_json("evidence-unknown-id",
                     "证据编号不在本账本里：%s（先 claim/prove 出这条 ID，或换成路径 / 命令+产物 / 哈希）\n     %s"
                     % ("、".join(ids), EVIDENCE_REPLAY_HINT))
    if path_like:
        die_json("evidence-missing",
                 '证据路径不存在：%s（不要写不存在的文件路径；日志/截图请落到磁盘再引用）\n     %s'
                 % (ev, EVIDENCE_REPLAY_HINT))
    # ⑤ 剩下的都是纯文本
    die_json("evidence-not-replayable",
             "证据不是可重放材料：%s\n     %s" % (ev[:80], EVIDENCE_REPLAY_HINT))


def _json_path(case, name):
    return os.path.join(os.path.abspath(case), name)


def _load_list(case, name):
    p = _json_path(case, name)
    if not os.path.isfile(p):
        return []
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        die("%s 不是合法 JSON：%s（先修或备份后重写）" % (name, e))
    if not isinstance(data, list):
        die("%s 顶层必须是数组" % name)
    return data


def _save_list(case, name, data):
    _atomic_write_json(_json_path(case, name), data)


def _load_ledger_list(case, kind):
    """账本里的列表型状态（gaps / plan）：最后一条 kind 行整体生效。

    S4：gaps.json / plan.json 不再是独立文件 —— 状态文件只剩 4 类
    （case.json / facts.jsonl / artifacts/MANIFEST.sha256 / packs.baseline.json）。
    """
    out = []
    for e in load_ledger(case):
        if _entry_kind(e) == kind and isinstance(e.get("items"), list):
            out = e["items"]
    return out


def _append_ledger_list(case, kind, items):
    d, fp = paths(case)
    if not os.path.isdir(d):
        die("case 目录不存在：%s" % d)
    _atomic_append_line(fp, json.dumps({"kind": kind, "ts": now(), "items": items},
                                       ensure_ascii=False))


def load_gaps(case):
    return _load_ledger_list(case, LEDGER_GAPS_KIND)


def save_gaps(case, gaps):
    _append_ledger_list(case, LEDGER_GAPS_KIND, gaps)


def load_plan(case):
    return _load_ledger_list(case, LEDGER_PLAN_KIND)


def save_plan(case, plan):
    _append_ledger_list(case, LEDGER_PLAN_KIND, plan)


def _blocking_gaps(gaps):
    """不可补且概率折损够大的缺件：会关掉整条路线。"""
    out = []
    for g in gaps:
        if str(g.get("repairable") or "").lower() != "no":
            continue
        try:
            d = float(g.get("delta") or 0)
        except (TypeError, ValueError):
            d = 0.0
        if d <= GAP_DELTA_BLOCK:
            out.append(g)
    return out


def _depends(route_item, gap):
    """路线是否显式依赖该缺件：看 needs 里有没有缺件 id 或缺少物名称。"""
    needs = str((route_item or {}).get("needs") or "").strip().lower()
    if not needs:
        return False
    gid = str(gap.get("id") or "").strip().lower()
    miss = str(gap.get("missing") or "").strip().lower()
    return bool((gid and gid in needs) or (miss and miss in needs))


def _mentions(text, gap):
    t = str(text or "").strip().lower()
    if not t:
        return False
    gid = str(gap.get("id") or "").strip().lower()
    miss = str(gap.get("missing") or "").strip().lower()
    return bool((gid and gid in t) or (miss and miss in t))


def _cfg(name):
    p = os.path.join(CONFIG_DIR, name)
    if not os.path.isfile(p):
        die("缺配置文件：%s（应随仓库分发在 Tool/config/）" % p)
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        die("配置文件 %s 不是合法 JSON：%s" % (name, e))


def _score(hay, keys):
    h = str(hay or "").lower()
    return sum(1 for k in (keys or []) if str(k).strip() and str(k).strip().lower() in h)


def print_plan(plan, title="路线菜单"):
    if not plan:
        print("  （空：还没有路线菜单）")
        return
    print("  %s（%d 条）：" % (title, len(plan)))
    print("    级   成功率  工时      选中  路线 / 失败判据")
    for x in plan:
        print("    %-4s %5.2f   %-8s  %-4s  %s" % (
            x.get("level", ""), float(x.get("p") or 0), str(x.get("hours") or "")[:8],
            "✓" if x.get("chosen") else "", x.get("route", "")))
        if (x.get("fail_criteria") or "").strip():
            print("          失败判据：%s" % x["fail_criteria"])
        if (x.get("needs") or "").strip():
            print("          依赖/缺件：%s" % x["needs"])


def print_gaps(gaps, title="缺件台账"):
    if not gaps:
        print("  （空：还没有登记缺件）")
        return
    print("  %s（%d 条）：" % (title, len(gaps)))
    for g in gaps:
        tag = "阻断" if g in _blocking_gaps(gaps) else ""
        print("    %-4s %-18s 可补性=%-7s Δ%-6s %s" % (
            g.get("id", ""), str(g.get("missing") or "")[:18],
            g.get("repairable", ""), g.get("delta", ""), tag))
        if (g.get("impact") or "").strip():
            print("          影响：%s" % g["impact"])
        if g.get("alt"):
            print("          替代：%s" % "、".join(g["alt"]))


# ---------------------------------------------------------------- commands
def _fingerprint_target(target):
    """建案时给目标原件拍指纹（外部评审第 2 轮：只存路径 → 原件被改坏后无法验证）。

    - 目标在盘上：写 path + sha256 + size + at；
    - 目标未就位（不存在/URL/读不了）：不报错，但 sha256=None + note 说明。
    """
    t = (target or "").strip()
    at = now()
    if not t:
        return {"path": "", "sha256": None, "size": None, "at": at,
                "note": "目标未就位（建案时不存在）"}
    p = store_target(t)
    missing = {"path": p, "sha256": None, "size": None, "at": at,
               "note": "目标未就位（建案时不存在）"}
    if URL_RE.match(p) or not os.path.isfile(p):
        return missing
    try:
        return {"path": p, "sha256": _sha256_file(p),
                "size": os.path.getsize(p), "at": at}
    except OSError:
        return missing


def cmd_init(a):
    d, fp = paths(a.case)
    os.makedirs(d, exist_ok=True)
    left = _legacy_files(a.case)
    if left and not a.force:
        die("发现历史状态副本 %s：先 `replay --drop-legacy` 清理，或加 --force 重建"
            % ", ".join(os.path.basename(x) for x in left))
    has_state_row = any(_entry_kind(e) == LEDGER_STATE_KIND for e in load_ledger(a.case))
    if has_state_row and not a.force:
        die("facts.jsonl 里已有 state 重放行；要重建加 --force（当前不会覆盖）")
    st = {"schema": "seep-case/1", "target": store_target(a.target),
          "depth": {}, "verdict": None, "max_level": None,
          "stage": "intake", "stage_history": [],
          "next_action": "跑 D0 结构 + D1 存活", "updated": now()}
    target_fp = _fingerprint_target(a.target)
    backend = save_state(a.case, st)
    open(fp, "a", encoding="utf-8").close()
    # ★ 案例索引同源：preflight / domain-gate 跑 `case_state.py index --check`。
    #   init 必须同时写 case.json 骨架，否则「新建一个 case」会让索引检查变红
    #   （2026-10-23 实测：aimbot 目录缺 case.json → 「案例索引与磁盘一致」失败）。
    wrote_meta = _ensure_case_meta(d, st, getattr(a, "evidence_kind", "real"), target_fp)
    # 记一个机器级指针，供扩展（seep-memory/seep-events）在任意 cwd 下找到当前案（外部评审 A7）
    try:
        pdir = os.path.join(os.path.expanduser("~"), ".seep")
        os.makedirs(pdir, exist_ok=True)
        with open(os.path.join(pdir, "current-case"), "w", encoding="utf-8") as _pf:
            _pf.write(d)
    except Exception:
        pass
    # scope.md = 授权与边界契约（学 reverse-workbench-skill 的 case-guard）：
    # 开工前先写"做什么 / 不做什么 / 环境"；scope 未就绪不许 ACT。
    try:
        scope_p = os.path.join(d, "scope.md")
        if not os.path.isfile(scope_p):
            tgt = (a.target or "").strip() or "（未指定）"
            L = [
                "# 范围契约（scope）", "",
                "> 开工前填完这三节。没填完不许对目标动手（学 case-guard：scope 未就绪不 ACT）。", "",
                "## 1. 目标与授权", "",
                "- 目标：%s" % tgt,
                "- 授权来源：本人自有 / 书面授权 / 公开靶场 / 开源（选一，写清楚）",
                "- 客户原话：<粘贴客户关于授权的那句话>", "",
                "## 2. 边界（不做的事）", "",
                "- 不改系统级配置（网卡/路由/DNS/驱动/服务/系统 hosts）",
                "- 不动与目标无关的进程与文件",
                "- 不碰凭据：卡密/账号/密钥由用户自己输入，不写入任何输出", "",
                "## 3. 环境与交付预期", "",
                "- 隔离方式：实体机 / 虚拟机 / 容器（写清楚；有快照更好）",
                "- 网络：可断网 / 仅目标可达 / 其他",
                "- 期望层级：M1 结构 / M2 功能面通 / M3 能跑+授权自家 / M4 全栈自洽（判型后确认）",
            ]
            with open(scope_p, "w", encoding="utf-8", newline=chr(10)) as _sf:
                _sf.write(chr(10).join(L) + chr(10))
            print("[OK] scope.md 已生成（开工前先填授权与边界）：%s" % scope_p)
    except Exception as _e:  # noqa: BLE001
        print("[WARN] scope.md 生成失败：%s" % _e)

    print("[OK] case.json 骨架已写：evidence_kind=%s goal_level/domain/lessons 请按实际补"
              % getattr(a, "evidence_kind", "real"))
    if target_fp.get("sha256"):
        print("[OK] 原件指纹已登记：sha256=%s size=%s at=%s"
              % (target_fp["sha256"], target_fp.get("size"), target_fp.get("at")))
    else:
        print("[WARN] 目标未就位（建案时不存在）：%s —— 原件就位后重跑 init --force 登记指纹"
              % (target_fp.get("path") or a.target or "（未指定）"))


def _ensure_case_meta(d, st, evidence_kind="real", target_fp=None):
    """写 case.json 骨架（已存在就不动）。字段由 `case_state.py index` 现算时归一。"""
    cj = os.path.join(d, "case.json")
    if os.path.isfile(cj):
        return False
    kind = evidence_kind if evidence_kind in ("fixture", "real", "self-built", "historical") else "real"
    meta = {
        "id": os.path.basename(d.rstrip("/\\")),
        # 新案例默认域：`softseep`（旧名 `reverse` 已不是合法域，见 domain_spec.DOMAINS）
        "domain": "softseep",
        "target_type": st.get("target") or "",
        # ★ 原件指纹块（第 2 轮评审）：建案时就能重放比对「原件动没动」。
        #   只新增字段，不动原有 target_type 等语义；`index` 不读此块，故不影响索引。
        "target": target_fp or {},
        "evidence_kind": kind,
        "protection": [],
        "authority": "",
        "goal_level": "",
        "outcome": "partial",
        "artifacts": [],
        "repro": {"status": "in-progress", "evidence": "facts.jsonl 尚空"},
        "evidence_dir": ".",
        "lessons": [],
        "tags": [],
        "refs": [],
        "updated": now()[:10],
    }
    try:
        with open(cj, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=1)
    except OSError:
        return False
    return True



def cmd_verify_origin(a):
    """重算目标原件哈希，与建案时登记的指纹对账（第 2 轮评审：「原件不动」必须可验证）。

    rc=0 且打印指纹 = 原件与建案时一致；rc=2 = 原件已变/已被移动/无法比对。
    """
    d = os.path.abspath(a.case)
    cj = os.path.join(d, "case.json")
    if not os.path.isfile(cj):
        die_json("case-not-found",
                 "case.json 不存在：%s（先跑 init --case <目录> --target <原件>）" % d)
    try:
        with open(cj, encoding="utf-8") as f:
            meta = json.load(f)
    except (OSError, ValueError) as e:
        die_json("case-json-unreadable", "case.json 读不出来：%s: %s" % (type(e).__name__, e))
    tgt = meta.get("target") if isinstance(meta, dict) else None
    tgt = tgt if isinstance(tgt, dict) else {}
    path = str(tgt.get("path") or "").strip()
    want = str(tgt.get("sha256") or "").strip().lower()
    want_size = tgt.get("size")
    if not path:
        print("[ERR] 本案件没登记原件路径（case.json 的 target.path 为空）：无法验证原件未变")
        print("     修法：python Tool/scripts/case_state.py init --case %s --target <原件> --force" % d)
        return 2
    print("[INFO] 登记指纹：path=%s sha256=%s size=%s at=%s"
          % (path, want or "(未登记)",
             want_size if want_size is not None else "(未登记)", tgt.get("at") or "(未登记)"))
    if URL_RE.match(path):
        print("[ERR] 原件已变/已被移动：目标登记为 URL（%s），本地无原件可重算哈希" % path)
        return 2
    if not os.path.isfile(path):
        print("[ERR] 原件已变/已被移动：%s 当前不存在（被删 / 改名 / 移走）" % path)
        if tgt.get("note"):
            print("     登记备注：%s" % tgt["note"])
        return 2
    try:
        got, got_size = _sha256_file(path), os.path.getsize(path)
    except OSError as e:
        print("[ERR] 原件已变/已被移动：%s 读不出来：%s" % (path, e))
        return 2
    if not want:
        print("[ERR] 原件已变/已被移动：建案时目标未就位（sha256 未登记），现在才出现"
              "（sha256=%s size=%s）" % (got, got_size))
        print("     修法：python Tool/scripts/case_state.py init --case %s --target %s --force" % (d, path))
        return 2
    if got != want or (want_size is not None and got_size != want_size):
        print("[ERR] 原件已变/已被移动：%s" % path)
        print("     登记：sha256=%s size=%s" % (want, want_size))
        print("     现在：sha256=%s size=%s" % (got, got_size))
        print("     注意：原件变了，以前的证据不再自动成立（stale 后再 prove）")
        return 2
    print("[OK] 原件未变：path=%s sha256=%s size=%s 建案时间=%s"
          % (path, got, got_size, tgt.get("at") or "(未登记)"))
    return 0


def cmd_lock(a):
    """拿写权租约。同一会话重复 lock = 续约；别人的锁未过期就拒绝（rc=1）。"""
    d, _ = paths(a.case)
    if not os.path.isdir(d):
        die("case 目录不存在：%s\n先跑：case_state.py init --case %s --target <样本>" % (d, a.case))
    me = _session_id()
    ttl = a.ttl if (a.ttl and a.ttl > 0) else LEASE_TTL_DEFAULT
    ts = now()
    old = _read_lease(a.case)
    expired, age, old_ttl = _lease_status(old) if old else (True, None, float(ttl))
    same = bool(old) and str(old.get("session") or "") == me

    if old is not None and expired:
        action = "TAKEOVER"      # 过期锁视为无锁，任何人都能接管
    elif old is None:
        action = "ACQUIRED"
    elif same:
        action = "RENEWED"       # 可重入：自己的锁重复 lock = 续约
    elif a.force:
        action = "TAKEOVER"
    else:
        action = None

    if action is None:
        # 别人的有效锁 + 无 --force → 拒绝，rc=1（不是 2：2 留给「写盘被挡」）
        print("[LOCK] 拒绝：该 case 已被另一个会话锁定（rc=1）")
        _print_holder(old)
        print("[LOCK] 三条出路：")
        print("       1) 接管写权：python Tool/scripts/case_state.py lock --case %s --force" % a.case)
        print("       2) 换 case ：另开一个目录/会话，别和一个目录抢着写")
        print("       3) 只读查看：python Tool/scripts/case_state.py who|show|resume|gate --case %s" % a.case)
        return 1

    lease = {"pid": os.getpid(), "session": me, "href": _href(),
             "acquired_at": (old.get("acquired_at") if (same and not expired and old) else ts) or ts,
             "heartbeat_at": ts, "ttl_sec": int(ttl)}
    _write_lease(a.case, lease)
    detail = {"ACQUIRED": "新锁", "RENEWED": "同一会话续约",
              "TAKEOVER": ("过期%.0fs > ttl%d" % (age or 0, int(old_ttl or ttl)) if (old and expired)
                           else "--force 强制接管")}[action]
    print("%s  session=%s  case=%s  ttl=%ds（%s）" % (action, me, d, int(ttl), detail))
    if action == "TAKEOVER" and old:
        _print_holder(old, "被接管的前持有者")
    return 0


def cmd_unlock(a):
    """释放租约。不是自己持有且无 --force 就拒绕（rc=1）。"""
    d, _ = paths(a.case)
    if not os.path.isdir(d):
        die("case 目录不存在：%s" % d)
    me = _session_id()
    old = _read_lease(a.case)
    if old is None:
        print("NO_LEASE —— %s 本来就没有锁（无需释放）" % d)
        return 0
    expired = _lease_expired(old)
    same = str(old.get("session") or "") == me
    if not same and not expired and not a.force:
        print("[UNLOCK] 拒绝：锁不是本会话持有的（rc=1）")
        _print_holder(old)
        print("[UNLOCK] 建议：python Tool/scripts/case_state.py unlock --case %s --force" % a.case)
        return 1
    try:
        os.remove(_lease_path(a.case))
    except OSError as e:
        die("删不掉 %s：%s" % (_lease_path(a.case), e))
    note = "（过期锁强制清理）" if (expired and not same) else ""
    print("RELEASED  session=%s  case=%s%s" % (old.get("session") or "?", d, note))
    return 0


def cmd_who(a):
    """打印当前持锁者。无锁/过期一律 NO_LEASE 且 rc=0（方便脚本判）。"""
    d, _ = paths(a.case)
    if not os.path.isdir(d):
        die("case 目录不存在：%s" % d)
    lease = _read_lease(a.case)
    if lease is None:
        print("NO_LEASE")
        print("  说明：%s 没有租约文件（%s 不存在或不是合法 JSON）" % (d, LEASE_NAME))
        return 0
    expired, age, ttl = _lease_status(lease)
    if expired:
        print("NO_LEASE")
        print("  说明：存在过期 lease -> session=%s  heartbeat_at=%s  age=%s > ttl=%ds（可被任意会话接管）"
              % (lease.get("session") or "?", lease.get("heartbeat_at") or "-",
                 "?" if age is None else "%ds" % int(age), int(ttl)))
        return 0
    me = _session_id()
    print("LEASE  session=%s  pid=%s  ttl=%ds" % (
        lease.get("session") or "?", lease.get("pid") or "?", int(ttl)))
    if lease.get("href"):
        print("  href=%s" % lease["href"])
    print("  acquired_at=%s  heartbeat_at=%s  age=%s  剩余=%ds" % (
        lease.get("acquired_at") or "-", lease.get("heartbeat_at") or "-",
        "?" if age is None else "%ds" % int(age), int(ttl - (age or 0))))
    print("  当前会话=%s（%s）" % (me, "就是持有者" if str(lease.get("session") or "") == me
                                 else "不是持有者：写盘会被拒 rc=2"))
    return 0


CONFIDENCE_STATES = ("observed", "derived", "inferred", "unknown")
AUTHORITY_STATES = ("shipped-artifact", "controlled-replay", "external-service",
                    "reported", "none")


def _norm_confidence(v, default="unknown"):
    """证据强度四态（S2-4）：observed > derived > inferred > unknown。

    unknown 永不计 pass：没有明确声明的 claim 一律落 unknown，不会被聚合器当成已证。
    """
    s = str(v or "").strip().lower()
    return s if s in CONFIDENCE_STATES else default


def cmd_claim(a):
    lease_guard(a.case)
    facts = load_facts(a.case)
    if any(f["id"] == a.id for f in facts):
        die(f"claim {a.id} 已存在（要改用它自己的 prove/refute 子命令）")
    if a.status not in STATUSES:
        die(f"status 只能是 {STATUSES}")
    if not (a.text or "").strip():
        die("claim 的 --text 不能为空（一句话语义是证据索引）")
    by = (getattr(a, "by", "") or "").strip()
    if a.status == "refuted" and not by:
        die("refuted 必须带非空 --by（指向推翻它的证据/claim id），否则历史不可追溯")
    ev = require_evidence(a.evidence, a.case)
    if a.status == "proven" and not ev:
        die("proven 必须带非空 --evidence（空串/空格不算证据；没有证据只能写 hypothesis）")
    fact = {"id": a.id, "claim": a.text, "status": a.status,
            "evidence": [ev] if ev else [],
            "how": a.how or "", "ttl": (a.ttl or "").strip(), "created": now(),
            "confidence": _norm_confidence(getattr(a, "confidence", "")),
            "authority": (str(getattr(a, "authority", "") or "").strip().lower() or "none"),
            "refuted_by": (by or None)}
    append_fact(a.case, fact)
    print(f"[OK] {a.id} = {a.status}  {a.text}")


def _rewrite_claims(case, facts):
    """只改 claim 行：按 id 替换账本里的对应行，其余行（state/event/repro/gaps/plan/downgrade）
    **原样保留且相对顺序不变**（append-only 账本的前提）。

    血案（F3）：旧 `_rewrite_facts` 拿 `load_facts()`（只剩 claim 行）整文件重写，于是按文档顺序
    init → claim → prove 的第一次 prove 就把 state 行（target/stage/verdict）、plan、repro 全删掉。
    现在先把全量 `load_ledger()` 读回来，逐行判断：是 claim 且 id 命中 → 换成新对象，否则原样抄回。
    调用方新增的 claim（账本里还没有）追加到末尾，仍不丢任何旧行。
    """
    _, fp = paths(case)
    new_by_id = {}
    for f in facts:
        if isinstance(f, dict) and str(f.get("id") or "").strip():
            new_by_id[str(f.get("id"))] = f
    out, seen = [], set()
    for e in load_ledger(case):
        fid = str(e.get("id") or "").strip() if isinstance(e, dict) else ""
        if fid and fid in new_by_id and _is_claim(e):
            out.append(new_by_id[fid])
            seen.add(fid)
        else:
            out.append(e)
    for fid, f in new_by_id.items():
        if fid not in seen:
            out.append(f)
    _atomic_write_text(fp, "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in out))


def _rewrite_facts(case, facts):
    """兼容旧名：语义已改成“只改 claim 行”，与 `_rewrite_claims` 完全等价（不再整文件丢行）。"""
    _rewrite_claims(case, facts)


def cmd_prove(a):
    lease_guard(a.case)
    ev = require_evidence(a.evidence, a.case)
    if not ev:
        die("prove 必须带非空 --evidence（空串/空格不算证据）")
    facts = load_facts(a.case)
    hit = next((f for f in facts if f["id"] == a.id), None)
    if not hit:
        die(f"没有 claim {a.id}")
    # S2-4：置信度/权威必须显式声明；不声明就维持 unknown（unknown 永不计 pass）
    if getattr(a, "confidence", ""):
        hit["confidence"] = _norm_confidence(a.confidence)
    else:
        hit.setdefault("confidence", "unknown")
    if getattr(a, "authority", ""):
        hit["authority"] = str(a.authority).strip().lower()
    else:
        hit.setdefault("authority", "none")
    was_stale = hit.get("status") == "stale"
    if was_stale:
        # 复验复活：保留失效原因做审计，但状态回 proven、证据追加
        hit.setdefault("stale_history", []).append(
            {"reason": hit.get("stale_reason") or "", "at": hit.get("staled_at") or ""})
        hit.pop("stale_reason", None)
        hit.pop("staled_at", None)
        hit["revalidated_at"] = now()
    hit["status"] = "proven"
    hit["evidence"] = (hit.get("evidence") or []) + [ev]
    hit["updated"] = now()
    _rewrite_claims(a.case, facts)
    tail = "（原 stale 已复验复活）" if was_stale else ""
    hint = ""
    if hit.get("confidence") in ("unknown", "inferred") or hit.get("authority") in ("", "none"):
        hint = ("\n[WARN] 本条 confidence=%s authority=%s → 聚合时不算 pass；"
                "实测证据请显式声明 --confidence observed --authority shipped-artifact"
                % (hit.get("confidence"), hit.get("authority")))
    print(f"[OK] {a.id} 已证实{tail}（证据 {len(hit['evidence'])} 条）{hint}")


def cmd_refute(a):
    lease_guard(a.case)
    by = (a.by or "").strip()
    if not by:
        die("refute 必须带非空 --by（指向推翻它的证据/claim id）")
    facts = load_facts(a.case)
    hit = next((f for f in facts if f["id"] == a.id), None)
    if not hit:
        die(f"没有 claim {a.id}")
    hit["status"] = "refuted"
    hit["refuted_by"] = by
    hit["updated"] = now()
    _rewrite_claims(a.case, facts)
    print(f"[OK] {a.id} 已标记被推翻，依据 = {a.by}（历史保留，不删）")


def cmd_stale(a):
    """TTL 失效：把当前所有 proven 降为 stale（保留证据，只改状态 + 失效原因）。

    典型触发：换了 exe（hash 变了）、目标更新、服务器换域名 —— 旧结论不再自动成立。
    复活方式：prove --id <id> --evidence "复验：..."（status 回 proven）。
    """
    reason = (a.reason or "").strip()
    lease_guard(a.case)
    facts = load_facts(a.case)
    proven = [f for f in facts if f.get("status") == "proven"]
    if not proven:
        die("没有 proven 的结论可作废（stale 只作用于已证事实）")
    ts = now()
    for f in proven:
        f["status"] = "stale"
        f["stale_reason"] = reason or "（未写原因）"
        f["staled_at"] = ts
        f["updated"] = ts
    _rewrite_claims(a.case, facts)
    print("[OK] %d 条 proven 已标为 stale，原因：%s" % (len(proven), reason or "（未写原因）"))
    print("     证据保留；复验用 prove --id <id> --evidence ...，否则 gate 拒绝")


def cmd_gaps(a):
    if not os.path.isdir(os.path.abspath(a.case)):
        die("case 目录不存在：%s" % os.path.abspath(a.case))
    gaps = load_gaps(a.case)
    if a.list_mode:
        print_gaps(gaps)
        return
    if not a.add:
        die("gaps 需要 --add（登记缺件）或 --list（查看）")
    lease_guard(a.case)   # 只有 --add 会写盘，--list 不查锁
    gid = (a.id or "").strip()
    missing = (a.missing or "").strip()
    if not gid or not missing:
        die("缺件必须有 --id 与 --missing（缺什么）")
    if any(g.get("id") == gid for g in gaps):
        die(f"缺件 {gid} 已存在（要改请先手工编辑 gaps.json）")
    rep = (a.repairable or "").strip().lower()
    if rep not in GAP_REPAIRABLE:
        die(f"--repairable 只能是 {GAP_REPAIRABLE}")
    try:
        delta = float(a.delta)
    except (TypeError, ValueError):
        die("--delta 必须是数字（概率折损，如 -0.45）")
    if not (-1.0 <= delta <= 1.0):
        die("--delta 应在 -1.0 ~ 1.0 之间")
    alt = [x.strip() for x in (a.alt or "").split("|") if x.strip()]
    gap = {"id": gid, "missing": missing, "impact": (a.impact or "").strip(),
           "repairable": rep, "delta": delta, "alt": alt, "created": now()}
    gaps.append(gap)
    save_gaps(a.case, gaps)
    tag = "（阻断级：不可补且 Δ≤%.1f）" % GAP_DELTA_BLOCK if gap in _blocking_gaps([gap]) else ""
    print("[OK] 缺件 %s 已登记：%s  可补性=%s Δ%s %s" % (gid, missing, rep, delta, tag))


def cmd_plan(a):
    if not os.path.isdir(os.path.abspath(a.case)):
        die("case 目录不存在：%s" % os.path.abspath(a.case))
    if a.from_advise:
        return _plan_from_advise(a)
    plan = load_plan(a.case)
    if a.list_mode:
        print_plan(plan)
        return
    lease_guard(a.case)   # 走到这里就是写盘（--list / --from-advise 已在上面分流）
    level = (a.level or "").strip().upper()
    route = (a.route or "").strip()
    if not level and route:
        # 宽容写法：`--add "L2 patch"` 直接从路线名里推等级；推不出就让用户显式给
        m = re.search(r"L([0-4])", route, re.I)
        if m:
            level = "L" + m.group(1)
    if not level or not route:
        die("plan 需要 --route（别名 --add）+ 成功率先验 --p（别名 --prob）；"\
            "等级可写在路线名里（如 --add \"L2 patch\"），也可 --level L2；或用 --list / --from-advise")
    if level not in PLAN_LEVELS:
        die(f"level 只能是 {PLAN_LEVELS}")
    if a.p is None:
        die("plan 必须给 --p（别名 --prob；成功率先验 0~1，不是拍脑袋，要写清乘出来的因子）")
    if not (0.0 <= float(a.p) <= 1.0):
        die("--p 必须在 0~1 之间")
    if any(x.get("level") == level and x.get("route") == route for x in plan):
        die(f"路线已存在：{level} {route}")
    item = {"level": level, "route": route, "p": float(a.p),
            "hours": (a.hours or "").strip(), "needs": (a.needs or "").strip(),
            "fail_criteria": (a.fail_criteria or "").strip(),
            "chosen": False, "created": now()}
    plan.append(item)
    save_plan(a.case, plan)
    print("[OK] 已登记路线 %s %s（p=%.2f，工时 %s）" % (level, route, item["p"], item["hours"] or "?"))
    print("     菜单共 %d 条；选定用 choose --level %s --route \"%s\"" % (len(plan), level, route))


def cmd_choose(a):
    lease_guard(a.case)
    level = (a.level or "").strip().upper()
    route = (a.route or "").strip()
    if level not in PLAN_LEVELS:
        die(f"level 只能是 {PLAN_LEVELS}")
    plan = load_plan(a.case)
    if not plan:
        die("还没有路线菜单（plan.json）：先 plan --add / plan --from-advise")
    hit = next((x for x in plan if x.get("level") == level and x.get("route") == route), None)
    if not hit:
        die("菜单里没有这条路线：%s %s（先 plan --list 看现有候选）" % (level, route))
    for x in plan:
        x["chosen"] = (x is hit)
    hit["chosen_at"] = now()
    save_plan(a.case, plan)
    st = load_state(a.case)
    st["goal_level"] = level
    st["goal_route"] = route
    st["next_action"] = "按 %s（%s）进 01-gate-bypass" % (level, route)
    save_state(a.case, st)
    print("[OK] 已选定 %s %s（p=%.2f，工时 %s）；state.goal_level = %s"
          % (level, route, float(hit.get("p") or 0), hit.get("hours") or "?", level))


def _pick_form(strat, form_arg, hay):
    forms = strat.get("forms") or []
    if not forms:
        die("strategy.json 里没有 forms")
    fa = (form_arg or "").strip()
    if fa:
        hit = next((f for f in forms if str(f.get("id", "")).lower() == fa.lower()), None)
        if hit:
            return hit, "explicit"
        best = max(forms, key=lambda f: _score(fa, f.get("match")))
        if _score(fa, best.get("match")) > 0:
            return best, "form-arg-match"
        die("strategy.json 没有形态 %s；可选：%s" % (fa, "、".join(str(f.get("id")) for f in forms)))
    best = max(forms, key=lambda f: _score(hay, f.get("match")))
    if _score(hay, best.get("match")) > 0:
        return best, "auto-match"
    gen = next((f for f in forms if f.get("id") == "generic"), forms[0])
    return gen, "fallback"


def _pick_family(matrix, hay):
    fams = matrix.get("families") or []
    if not fams:
        return None
    best = max(fams, key=lambda f: _score(hay, f.get("match")))
    return best if _score(hay, best.get("match")) > 0 else None


def _advise(a):
    """读 instrument-matrix + strategy，按 gaps/instruments 过滤，返回建议（不写盘）。"""
    st = load_state(a.case)
    facts = load_facts(a.case)
    gaps = load_gaps(a.case)
    inst = st.get("instruments") or {}
    matrix = _cfg("instrument-matrix.json")
    strat = _cfg("strategy.json")
    hay = " ".join([a.case, str(st.get("target") or "")]
                   + [str(f.get("claim") or "") for f in facts]
                   + [str(f.get("how") or "") for f in facts]
                   + list(inst.keys()))
    form, how = _pick_form(strat, getattr(a, "form", ""), hay)
    fam = _pick_family(matrix, hay + " " + str(form.get("id", "")) + " "
                       + " ".join(str(x) for x in (form.get("match") or [])))
    blocking = _blocking_gaps(gaps)
    banned = set(str(x) for x in ((fam or {}).get("banned") or []))
    dead = {k for k, v in inst.items() if str(v.get("status")) in ("blocked", "killed")}
    ok_routes, blocked_routes = [], []
    for r in form.get("routes") or []:
        reasons = []
        for g in blocking:
            if _depends({"needs": r.get("needs", "")}, g):
                reasons.append("依赖不可补缺件 %s（%s，Δ%s）" % (g.get("id"), g.get("missing"), g.get("delta")))
        for i in r.get("instruments") or []:
            if i in banned:
                reasons.append("仪器 %s 被壳族 %s 禁用" % (i, (fam or {}).get("id")))
            elif i in dead:
                reasons.append("仪器 %s 实测不可用（%s）" % (i, inst[i].get("status")))
        item = dict(r)
        item["reasons"] = reasons
        (blocked_routes if reasons else ok_routes).append(item)
    return {"form": form, "how": how, "family": fam, "blocking": blocking,
            "ok": ok_routes, "blocked": blocked_routes}


def _print_advise(res):
    form = res["form"]
    fam = res["family"]
    print("[建议] 形态 = %s（%s；匹配方式 %s）"
          % (form.get("id"), form.get("name") or "", res["how"]))
    if fam:
        print("  仪器族 = %s（%s）" % (fam.get("id"), fam.get("name") or ""))
        print("    可用仪器：%s" % ("、".join(fam.get("allowed") or []) or "-"))
        print("    禁用仪器：%s" % ("、".join(fam.get("banned") or []) or "-"))
        for p in (fam.get("pitfalls") or [])[:5]:
            print("    陷阱：%s" % p)
    if res["blocking"]:
        print("  阻断缺件（不可补且 Δ≤%.1f）：" % GAP_DELTA_BLOCK)
        for g in res["blocking"]:
            print("    %s %s  Δ%s  替代：%s"
                  % (g.get("id"), g.get("missing"), g.get("delta"),
                     "、".join(g.get("alt") or []) or "无"))
    print("  可选路线（%d）：" % len(res["ok"]))
    for r in res["ok"]:
        print("    %-3s %-24s p=%.2f  %-7s 失败判据：%s"
              % (r.get("level"), r.get("route"), float(r.get("p") or 0),
                 r.get("hours") or "?", r.get("fail") or ""))
    if res["blocked"]:
        print("  已剔除（%d）：" % len(res["blocked"]))
        for r in res["blocked"]:
            print("    %-3s %-24s — %s"
                  % (r.get("level"), r.get("route"), "；".join(r["reasons"])))
    print("  说明：advise 只输出建议、不写盘；确认后 plan --from-advise [--form <id>] 一次性导入")


def cmd_advise(a):
    res = _advise(a)
    _print_advise(res)
    if not res["ok"]:
        print("[WARN] 没有可行路线：缺件或仪器把菜单全关了 —— 先补缺件/换形态，别硬上")


def _plan_from_advise(a):
    res = _advise(a)
    if not res["ok"]:
        _print_advise(res)
        die("advise 没有给出可行路线，不能导入；先补缺件或换 --form")
    lease_guard(a.case)
    plan = load_plan(a.case)
    # ★ 从 advise 导入 = 以 advise 为准**重建**菜单（默认清空旧条目）。
    #   血案：只追加会让"已被缺件剔除的 L4"留在菜单里 → gate 永远因该条被拒。
    keep = bool(getattr(a, "keep", False))
    if not keep:
        plan = []
    added = 0
    for r in res["ok"]:
        if any(x.get("level") == r.get("level") and x.get("route") == r.get("route") for x in plan):
            continue
        plan.append({"level": r.get("level"), "route": r.get("route"),
                     "p": float(r.get("p") or 0), "hours": r.get("hours") or "",
                     "needs": r.get("needs") or "", "fail_criteria": r.get("fail") or "",
                     "chosen": False, "source": "advise:%s" % res["form"].get("id"),
                     "created": now()})
        added += 1
    save_plan(a.case, plan)
    print("[OK] 从 advise 导入 %d 条路线（形态 %s）；菜单共 %d 条"
          % (added, res["form"].get("id"), len(plan)))
    print_plan(plan)


def cmd_depth(a):
    lease_guard(a.case)
    if a.level not in LEVELS:
        die(f"level 只能是 {LEVELS}")
    if not a.result:
        # --prove "说明" 的简写：视为 pass；无说明又无 result 就是没登记，直接退
        if (a.note or "").strip():
            a.result = "pass"
        else:
            die("result 必填（pass / fail / na）；想简写用 --prove \"说明\" 表示 pass")
    if a.result not in ("pass", "fail", "na"):
        die("result 只能是 pass / fail / na")
    st = load_state(a.case)
    st["depth"][a.level] = {"result": a.result, "note": a.note or "", "ts": now()}
    save_state(a.case, st)
    print(f"[OK] {a.level} = {a.result}  {a.note or ''}")


def cmd_verdict(a):
    lease_guard(a.case)
    if a.value not in VERDICTS:
        die(f"verdict 只能是 {VERDICTS}")
    base = MAX_LEVEL_BY_VERDICT[a.value]
    # 缝2（P2-4）：--tier 同时收 T 词表（后端档位 T1–T4）与 M 词表（交付上限 M1–M4）。
    # 哪个词表就原样存哪个槽：T → state.tier，M → state.max_level，不改写用户输入。
    word = (getattr(a, "tier", "") or "").strip().upper()
    if word and word not in TIERS:
        die("--tier 只收 T1/T2/T3/T4 或 M1/M2/M3/M4（T=后端档位，M=交付上限；"
            "换算 M1↔T1 / M2↔T2 / M3|M4↔T3，仅用于展示）")
    manual = (getattr(a, "max_level", "") or "").strip().upper()
    if manual and manual not in TIERS_M:
        die("--max-level 只收 M1/M2/M3/M4（T 词表用 --tier）")
    # 档位规则（写明，避免"部分可赢+T2 直接跳 M4"的未定义行为）：
    #   不可赢 → 恒 M1；否则 T1 → 裁定基准（可赢 M3 / 部分可赢 M2）；T2 → M3；T3/T4 → M4
    #   若用户直接给 M 词表，那就是交付上限本身（不抬高、不换算）。
    tier_slot, level = None, base
    if word.startswith("T"):
        tier_slot = word
        level = TIER_LEVEL[word] or base
    elif word:
        level = word
    if a.value == "不可赢":
        if word and level != "M1":
            die(f"不可赢 = 恒 M1（不能自己往上抬到 {level}）：--tier M1 或 T1")
        level = "M1"
    if manual and manual != level:
        die(f"{a.value}" + (f" + {word}" if word else "")
            + f" 对应的交付上限必须是 {level}（不能自己往上抬）")
    st = load_state(a.case)
    st["verdict"] = a.value
    st["tier"] = tier_slot           # T 词表原样（没给 T 词就是 None）
    st["tier_input"] = word or None  # 用户原始输入：show 里回显，不被换算覆盖
    st["max_level"] = level          # M 词表原样
    st["verdict_note"] = a.note or ""
    st["next_action"] = "进 01-gate-bypass" if a.value != "不可赢" else "只交 M1 + 天花板声明，不许承诺成品"
    save_state(a.case, st)
    print(f"[OK] 裁定 = {a.value}，交付上限 = {level}"
          + (f"（--tier {word} 原样存；换算 {tier_view(word)}）" if word else ""))


def cmd_instrument(a):
    lease_guard(a.case)
    if a.name not in INSTRUMENTS:
        die(f"instrument 只能是 {INSTRUMENTS}")
    if a.status not in ISTATUS:
        die(f"status 只能是 {ISTATUS}")
    st = load_state(a.case)
    st.setdefault("instruments", {})[a.name] = {
        "status": a.status, "launch": a.launch or "", "note": a.note or "", "ts": now()}
    save_state(a.case, st)
    print(f"[OK] 仪器 {a.name} = {a.status}  {a.note or ''}")


def _events_path(case):
    """事件账文件：<case>/events.jsonl（由 pi 扩展 seep-events 自动写）。"""
    return os.path.join(os.path.abspath(case), "events.jsonl")


def _ledger_events(case):
    """事件行：S2 起事件账也进 facts.jsonl（kind:"event"），不再单开 events.jsonl。"""
    rows = []
    for e in load_ledger(case):
        if _entry_kind(e) == LEDGER_EVENT_KIND:
            rows.append(e)
    return rows


def _events_nonempty(case):
    """事件账是否存在且非空（账本 event 行或历史 events.jsonl 任一都算）。"""
    if _ledger_events(case):
        return True
    try:
        p = _events_path(case)
        return os.path.isfile(p) and os.path.getsize(p) > 0
    except Exception:
        return False


def cmd_events(a):
    """事件账：动作级流水（谁跑了什么工具、成没成、多久）。只读，不改任何状态。

    与 claim 行的分工：claim 是**结论**账（模型主动写，必须带证据），
    event 行是**动作**账（扩展自动写，不依赖模型自觉）。
    两者同一个账本 facts.jsonl（S2 合并），所以不可能出现「两份互相不知道」。
    缺事件行不是错误 —— 只说明这个 case 还没跑过带扩展的会话，所以恒 rc=0。
    """
    rows = _ledger_events(a.case)
    p = os.path.join(os.path.abspath(a.case), "facts.jsonl")
    if not rows:
        p = _events_path(a.case)
        if not _events_nonempty(a.case):
            print("没有事件账（本 case 尚未跑过带扩展的会话）")
            print("  期望位置：%s（kind:\"event\" 行）" % os.path.join(os.path.abspath(a.case), "facts.jsonl"))
            print("  事件账由 pi 扩展 seep-memory / seep-events 自动写；结论仍以 claim 行 / gate 为准。")
            return 0
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    rows.append(obj)

    n = a.tail if isinstance(a.tail, int) and a.tail > 0 else 10
    print("[EVENTS] %s" % p)
    print("总条数：%d" % len(rows))
    if not rows:
        print("0 条有效事件（文件存在但为空）—— 本 case 尚未跑过带扩展的会话")
        return 0

    tail = rows[-n:]
    print("最近 %d 条（ts | tool | ok | risk | summary）：" % len(tail))
    for o in tail:
        ts = str(o.get("ts") or "")[:19].replace("T", " ")
        tool = str(o.get("tool") or o.get("event") or o.get("kind") or "?")
        ok = "ok" if o.get("ok", True) else "FAIL"
        risk = o.get("risk") or "-"
        summ = str(o.get("summary") or o.get("text") or "")
        if len(summ) > 120:
            summ = summ[:120] + "…"
        print("  %s | %-14s | %-4s | %-5s | %s" % (ts, tool, ok, risk, summ))

    if getattr(a, "json", False):
        print(json.dumps({"file": p, "total": len(rows), "tail": tail},
                         ensure_ascii=False, indent=2))
    return 0


# ---------------------------------------------------------------- 阶段机（P2-1）
def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_artifact(p):
    """→ (ok, text, size)。读不到就不算存在（目录/权限错都当不过）。"""
    if not os.path.isfile(p):
        return False, "", 0
    try:
        with open(p, "rb") as f:
            raw = f.read()
    except OSError:
        return False, "", 0
    return True, raw.decode("utf-8", "replace"), len(raw)


def _word_in(text, word):
    """按“两边不是字母”判词，避开 RVA 里包含 VA 这类假命中。"""
    return re.search(r"(?<![A-Za-z])" + re.escape(word) + r"(?![A-Za-z])", text) is not None


def _chk_triage(case, p, st=None):
    ok, text, size = _read_artifact(p)
    if not ok:
        return ["文件不存在"]
    probs = []
    if size < 300:
        probs.append("只有 %d 字节（要 ≥300）" % size)
    lack = [f for f in TRIAGE_FIELDS if f not in text]
    if lack:
        probs.append("缺字段名：" + "、".join(lack))
    return probs


def _chk_static(case, p, st=None):
    ok, text, size = _read_artifact(p)
    if not ok:
        return ["文件不存在"]
    probs = []
    if size < 600:
        probs.append("只有 %d 字节（要 ≥600）" % size)
    heads = sum(1 for ln in text.splitlines() if ln.strip().startswith("## "))
    if heads < 3:
        probs.append("只有 %d 个 `## ` 小节（要 ≥3）" % heads)
    if ("facts" not in text) and ("证据" not in text):
        probs.append("必须出现 `facts` 或 `证据`（结论要挂到事实账）")
    return probs


def _chk_login(case, p, st=None):
    if not os.path.isfile(p):
        return ["文件不存在"]
    try:
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
    except Exception as e:  # noqa: BLE001
        return ["不是合法 JSON：%s: %s" % (type(e).__name__, e)]
    if not isinstance(d, dict):
        return ["顶层必须是 JSON 对象"]
    v = d.get("device_id")
    if v is None:
        # 宽容一层：嵌套对象里的 device_id 也算（登录响应常套 data）
        def _dig(o, depth=0):
            if depth > 4 or not isinstance(o, dict):
                return None
            if "device_id" in o:
                return o["device_id"]
            for x in o.values():
                r = _dig(x, depth + 1)
                if r is not None:
                    return r
            return None
        v = _dig(d)
    if v is None or (isinstance(v, str) and not v.strip()):
        return ["缺非空键 device_id"]
    return []


def _chk_run(case, p, st=None):
    """运行类动态确认产物：无登录目标（crackme/CLI）的「真跑一遍」记录。

    四个键缺一不可，且必须是**真实运行**才可能填出来的东西：
      cmd          跑了什么命令（非空字符串）
      exit         进程退出码（int；bool 是 int 的子类，这里明确排除）
      stdout_head  截一段真实输出（非空字符串）
      expect       说明「这段输出代表通过」（非空字符串）
    """
    if not os.path.isfile(p):
        return ["文件不存在"]
    try:
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
    except Exception as e:  # noqa: BLE001
        return ["不是合法 JSON：%s: %s" % (type(e).__name__, e)]
    if not isinstance(d, dict):
        return ["顶层必须是 JSON 对象"]
    probs = []
    if not isinstance(d.get("cmd"), str) or not d.get("cmd").strip():
        probs.append("缺非空字符串 cmd（跑的是什么命令）")
    ex = d.get("exit")
    if isinstance(ex, bool) or not isinstance(ex, int):
        probs.append("缺整数 exit（进程退出码；bool / 字符串 / 缺失都不算）")
    for k, why in (("stdout_head", "非空字符串 stdout_head（截一段真实输出）"),
                   ("expect", "非空字符串 expect（说明「这段输出代表通过」）")):
        v = d.get(k)
        if not isinstance(v, str) or not v.strip():
            probs.append("缺" + why)
    return probs


def _chk_dynamic(case, p, st=None):
    ok, text, size = _read_artifact(p)
    if not ok:
        return ["文件不存在"]
    probs = []
    if size < 600:
        probs.append("只有 %d 字节（要 ≥600）" % size)
    lack = [w for w in DYNAMIC_WORDS if not _word_in(text, w)]
    if lack:
        probs.append("缺地址台账列：" + "、".join(lack))
    return probs


def _manifest_candidates(case, manifest_path, rel):
    """path 的解析顺序：原样 → 相对 case 根 → 相对 manifest 所在目录。"""
    if os.path.isabs(rel):
        cands = [rel]
    else:
        cands = [rel,
                 os.path.join(os.path.abspath(case), rel),
                 os.path.join(os.path.dirname(os.path.abspath(manifest_path)), rel)]
    return [c for c in cands if os.path.isfile(c)]


def _chk_manifest(case, p, st=None):
    ok, text, size = _read_artifact(p)
    if not ok:
        return ["文件不存在"]
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return ["文件是空的（至少 1 行 `sha256  path`）"]
    probs, good, badfmt = [], 0, 0
    for ln in lines:
        if ln.startswith("#"):
            continue
        parts = ln.split(None, 1)
        if len(parts) != 2 or not re.match(r"^[0-9a-fA-F]{64}$", parts[0]):
            badfmt += 1
            if len(probs) < 3:
                probs.append("行格式不对（要 `sha256  path`）：%s" % ln[:60])
            continue
        dig, rel = parts[0].lower(), parts[1].strip()
        cands = _manifest_candidates(case, p, rel)
        if not cands:
            probs.append("清单里的文件不存在：%s" % rel)
            continue
        try:
            got = _sha256_file(cands[0])
        except OSError as e:
            probs.append("读不了 %s：%s" % (rel, e))
            continue
        if got != dig:
            probs.append("哈希不一致：%s（记录 %s…，实际 %s…）" % (rel, dig[:12], got[:12]))
            continue
        good += 1
    if badfmt and good == 0:
        probs.insert(0, "没有 1 行合法 `sha256  path`")
    elif good < 1:
        probs.insert(0, "没有 1 行通过校验（要求至少 1 行合法、文件存在且哈希一致）")
    return probs


def _chk_final(case, p, st=None):
    ok, text, size = _read_artifact(p)
    if not ok:
        return ["文件不存在"]
    probs = []
    if size < 300:
        probs.append("只有 %d 字节（要 ≥300）" % size)
    lack = [w for w in FINAL_WORDS if w not in text]
    if lack:
        probs.append("缺词：" + "、".join("`%s`" % w for w in lack))
    if not str(((st or {}).get("verdict")) or "").strip():
        probs.append("state.verdict 为空（先 verdict --value ...）")
    return probs


# stage → [(相对路径, 内容校验函数, 人读判据)]。顺序即打印顺序。
STAGE_ARTIFACTS = {
    "intake": [],
    "0a": [("report/triage.md", _chk_triage,
            "≥300 字节；同时出现六个字段名：载体 保护 授权权威 改动面 检测器 交付壁垒")],
    "0b": [("report/static.md", _chk_static,
            "≥600 字节；`## ` 小节 ≥3 个；出现 `facts` 或 `证据`")],
    # 阶段 1 二选一（见 STAGE_ANY_OF）：凭据类 login.json 在前 = 优先级高
    "1": [("capture/login.json", _chk_login, "能 json.load；含非空键 device_id"),
          ("capture/run.json", _chk_run,
           "能 json.load；含非空 cmd / stdout_head / expect + 整数 exit")],
    "2": [("report/dynamic.md", _chk_dynamic, "≥600 字节；出现 RVA / VA / 基址")],
    "3": [("artifacts/MANIFEST.sha256", _chk_manifest,
            "至少 1 行 `sha256  path`；每行文件真实存在且哈希一致")],
    "4": [("report/final.md", _chk_final,
            "≥300 字节；含 `验收` 与 `功能`；state.verdict 非空")],
    "done": [],
}


# 阶段 1 二选一（P2-5）：无登录目标（crackme / CLI）没有 login.json 可交，它的
# 「动态确认」产物应是一条真实运行记录。两文件任一过关即过，书写顺序即优先级
# （凭据类在前 → 两者都在时走凭据类，并注明 run.json 已忽略）。
STAGE_ANY_OF = {"1"}

ANY_OF_LABEL = {"capture/login.json": "凭据类", "capture/run.json": "运行类"}

ANY_OF_FIX = {
    "capture/login.json": "写 capture/login.json（登录/授权响应，含非空 device_id）",
    "capture/run.json": ('写 capture/run.json（真跑一遍的记录，四个键齐全）：'
                         '{"cmd":"...","exit":0,"stdout_head":"...",'
                         '"expect":"这段输出代表通过"}'),
}


def _any_of_stage(case, stage, st=None):
    """二选一产物评估 → (命中模式名|None, 命中路径|None, 附注[list], 未过项[list])。

    过 = 其中一个产物的内容判据全过；`notes` 里带上「另一个也存在但已忽略」的说明。
    全不过时 `probs` 里逐条列出每种模式缺什么，并同时给出两种补齐方式。
    """
    results = []
    for rel, chk, hint in STAGE_ARTIFACTS.get(stage, []):
        full = os.path.join(os.path.abspath(case), rel)
        try:
            subs = chk(case, full, st) or []
        except Exception as e:  # noqa: BLE001 —— 产物坏了不许把闸崩掉
            subs = ["校验时异常：%s: %s" % (type(e).__name__, e)]
        results.append((rel, full, hint, subs))

    names = " / ".join(ANY_OF_LABEL.get(r, r) for r, _c, _h in STAGE_ARTIFACTS.get(stage, []))
    for rel, full, hint, subs in results:
        if subs:
            continue
        notes = []
        for orel, ofull, _oh, _os in results:
            if orel != rel and os.path.isfile(ofull):
                notes.append("（同时存在 %s，已忽略）" % orel)
        return ANY_OF_LABEL.get(rel, rel), rel, notes, []

    probs = ["产物未过：阶段 %s 的 %s 二选一都没满足" % (stage, names)]
    for rel, full, hint, subs in results:
        probs.append("· %s 未过 —— %s\n       判据：%s\n       路径：%s"
                     % (rel, "；".join(subs), hint, full))
    probs.append("补齐方式（二选一，不必两个都写）：")
    for rel in [r for r, _c, _h in STAGE_ARTIFACTS.get(stage, [])]:
        probs.append("  - " + ANY_OF_FIX.get(rel, "写 " + rel))
    return None, None, [], probs


def _cs_cmd(case, sub, extra=""):
    """可直接复制执行的下一条命令（提示行专用）。"""
    tail = (" " + extra) if extra else ""
    return "python Tool/scripts/case_state.py %s --case %s%s" % (sub, case, tail)


def _stage_problems(case, stage, st):
    """返回该阶段的全部未过项（字符串，已带下一步命令）。空列表=过关。"""
    if not STAGE_ARTIFACTS.get(stage):
        return []
    if stage in STAGE_ANY_OF:
        return list(_any_of_stage(case, stage, st)[3])
    probs = []
    for rel, chk, hint in STAGE_ARTIFACTS.get(stage, []):
        full = os.path.join(os.path.abspath(case), rel)
        try:
            subs = chk(case, full, st) or []
        except Exception as e:  # noqa: BLE001 —— 产物坏了不许把闸崩掉
            subs = ["校验时异常：%s: %s" % (type(e).__name__, e)]
        if subs:
            probs.append("产物未过：%s —— %s\n     判据：%s\n     路径：%s"
                         % (rel, "；".join(subs), hint, full))
    return probs


SCOPE_AUTH_VALUES = ("本人自有", "书面授权", "公开靶场", "开源")


def _scope_problems(case):
    """scope.md 的「授权来源」必须被**记录**成四选一（P0-3b）。

    第 2 轮评审：「四选一」可由模型代填 —— 客户可能从没说过授权。
    所以再加一道：「客户原话」行必须非空、不是模板占位、长度 ≥ 6。
    这条只机检「授权事实有没有落纸」，不裁决授权本身。返回 [] = 已记录；
    否则返回一条带可复制修法的未过项。
    """
    d = os.path.abspath(case)
    p = os.path.join(d, "scope.md")
    fix = ("先填 scope.md 的授权来源（四个之一：本人自有 / 书面授权 / 公开靶场 / 开源）"
           " + 目标：%s" % p)
    fix_q = ("在 %s 第 1 节加一行（把尖括号换成客户关于授权的那句原话，至少 6 字）：\n"
             "       客户原话：<粘贴客户关于授权的那句话>\n"
             "     （客户没说过授权就不要开工，不许模型代填）" % p)
    if not os.path.isfile(p):
        return ["范围契约 scope.md 不存在（进阶段 1 及以后前必须先写）\n     " + fix]
    try:
        raw = open(p, encoding="utf-8", errors="replace").read()
    except OSError as e:
        return ["scope.md 读不出来：%s\n     %s" % (e, fix)]
    line = ""
    for ln in raw.splitlines():
        if "授权来源" in ln:
            line = ln.strip()
            break
    if not line:
        return ["scope.md 里找不到「授权来源」一行\n     " + fix]
    m = re.search(r"授权来源\s*[:：]\s*(.*)$", line)
    val = m.group(1).strip() if m else ""
    if not val:
        return ["scope.md 的「授权来源」为空（模板没填）\n     " + fix]
    hits = [v for v in SCOPE_AUTH_VALUES if v in val]
    if "选一" in val or len(hits) > 1:
        return ["scope.md 的「授权来源」还是模板原样（%s），没改成四选一之一\n     %s"
                % (val[:60], fix)]
    if len(hits) != 1:
        return ["scope.md 的「授权来源」=「%s」不在四个之一"
                "（本人自有 / 书面授权 / 公开靶场 / 开源）\n     %s" % (val[:60], fix)]
    # ★ 第 2 轮评审：授权来源必须是客户说过的，不是模型替客户选的。
    qline = ""
    for ln in raw.splitlines():
        if "客户原话" in ln:
            qline = ln.strip()
            break
    if not qline:
        return ["scope.md 缺「客户原话」一行（授权来源无法证明是客户说的）\n     " + fix_q]
    mq = re.search(r"客户原话\s*[:：]\s*(.*)$", qline)
    qval = mq.group(1).strip() if mq else ""
    bare = qval.strip(" \t\"'“”‘’「」")
    if (not bare or "粘贴客户" in bare or bare.startswith("<") or bare.endswith(">")
            or len(bare) < 6):
        return ["scope.md 的「客户原话」还是空/模板占位/太短（%r）：写客户关于授权的原话，至少 6 字\n"
                "     %s" % (qval[:60], fix_q)]
    return []


# ---------------------------------------------------------------- 进阶闸（P2-4 缝1）
# 血案：p2-replay 自己照实写过「唯一的缝」—— `stage --set` 不校验产物，
# 直接 `stage --set 4` 就能在磁盘上留下一个没有任何产物支撑的假阶段号，
# 拦住跳阶的只有「set 之后记得 gate」这条口头纪律。现在把纪律变成闸。
STAGE_EXEMPT = {("intake", "0a")}   # 豁免①：建案后还没产物可查，直接进快筛


def _stage_index(stage):
    try:
        return STAGES.index(str(stage))
    except ValueError:
        return -1


def _max_stage_reached(st):
    """历史上到达过的最高阶段（state.stage + 全部 stage_history[].stage）。"""
    idx = _stage_index((st or {}).get("stage") or "intake")
    if idx < 0:
        idx = 0
    for h in (st or {}).get("stage_history") or []:
        if not isinstance(h, dict):
            continue
        i = _stage_index(h.get("stage") or "")
        if i > idx:
            idx = i
    return idx


def _advance_problems(case, cur, target, st):
    """进阶闸：[cur, target) 每个阶段的产物闸都要先过。返回 [(阶段, [未过项...])]。

    空列表 = 可以进阶。三条豁免（每条都写明理由，不许变成新的静默跳阶缝）：
      ① intake → 0a：还没产物可查（建案后第一跳）；
      ② 回退（target 不晚于 cur）：回退不是进阶，不产生新的「未挣到的阶段」；
      ③ 复位/复核（target 在 stage_history 里到达过）：当时已过闸，重走只算复核
         —— p2-replay 负例后的 `--set 4` 复位就走这条。
    除豁免外，判据与 `gate --stage` 完全同一套（_stage_problems），不另开一套宽松口径。

    ★ P0-3b：scope.md 的授权来源是进入阶段 1 及以后的**前置条件**，不受豁免③影响 ——
    豁免只免「产物闸重查」，不免「授权事实有没有被记录」；否则复位就成了绕过 scope 的缝。
    """
    ci, ti = _stage_index(cur), _stage_index(target)
    if ci < 0 or ti < 0 or ti <= ci:
        return []
    if (cur, target) in STAGE_EXEMPT:
        return []
    out = []
    if ti >= _stage_index("1"):
        scope = _scope_problems(case)
        if scope:
            out.append(("1", scope))
    if ti > _max_stage_reached(st):
        for stage in STAGES[ci:ti]:
            probs = _stage_problems(case, stage, st)
            if probs:
                out.append((stage, probs))
    return out


def _force_check(forced, reason):
    """--force 必须带 --reason：返回错误文案，None 表示合法。"""
    if forced and not str(reason or "").strip():
        return ('--force 必须同时给 --reason "..."：跳过产物闸要留下为什么跳过（会写进 state.stage_history）')
    return None


def tier_view(word):
    """展示用换算（不改用户输入值）：T 词表 → M 词表，M 词表 → T 词表。"""
    w = str(word or "").strip().upper()
    if w in M_TO_T:
        return "≈ %s" % M_TO_T[w]
    if w in T_TO_M:
        return "≈ %s" % T_TO_M[w]
    return ""


def cmd_stage(a):
    """阶段机：--set 写阶段（先过进阶产物闸）+ 记 history；--show 看当前/下一阶段/还缺什么。"""
    d = os.path.abspath(a.case)
    if not os.path.isdir(d):
        die("case 目录不存在：%s\n先跑：case_state.py init --case %s --target <样本>" % (d, a.case))
    st = load_state(a.case)
    cur = str(st.get("stage") or "intake")
    if cur not in STAGES:
        cur = "intake"
    want = (getattr(a, "set", "") or "").strip()
    do_show = bool(getattr(a, "show", False))
    if not want and not do_show:
        die("stage 需要 --set <阶段>（写）或 --show（看）")
    if want:
        if want not in STAGES:
            die("阶段只能是：%s" % " / ".join(STAGES))
        # 缝1：--force 必须配 --reason（否则“跳过闸”本身又成了一条静默路）
        forced = bool(getattr(a, "force", False))
        reason = (getattr(a, "reason", "") or "").strip()
        bad = _force_check(forced, reason)
        if bad:
            die(bad)
        blocked = _advance_problems(a.case, cur, want, st) if want != cur else []
        if blocked and not forced:
            print("[FAIL] 进阶被拦：%s → %s（stage --set 不再允许静默跳阶）" % (cur, want))
            for stage_label, probs in blocked:
                print("  阶段 %s（%s）—— %d 项未过："
                      % (stage_label, STAGE_NAME.get(stage_label, "?"), len(probs)))
                for it in probs:
                    for i, ln in enumerate(str(it).splitlines()):
                        print("    " + ("- " if i == 0 else "  ") + ln)
            print("\n[FAIL] 共 %d 个阶段的产物闸未过（rc=2）：%s"
                  % (len(blocked), "、".join(s for s, _ in blocked)))
            print("       补齐后先跑闸：%s" % _cs_cmd(a.case, "gate", "--stage " + cur))
            print("       确知要跳过（历史产物已不在盘上等）：%s"
                  % _cs_cmd(a.case, "stage", '--set %s --force --reason "<为什么跳过>"' % want))
            sys.exit(2)
        lease_guard(a.case)
        st["stage"] = want
        hist = st.setdefault("stage_history", [])
        if not isinstance(hist, list):
            hist = st["stage_history"] = []
        entry = {"stage": want, "at": now(), "from": cur}
        if forced:
            entry["forced"] = True
            entry["reason"] = reason
            if blocked:
                entry["skipped"] = [s for s, _ in blocked]
        else:
            # 走到这里 blocked 必为空（否则上方已 exit 2）：记一笔「这次进阶过了哪几个阶段的闸」
            gated = STAGES[_stage_index(cur):_stage_index(want)]
            if gated:
                entry["gated"] = gated
        hist.append(entry)
        save_state(a.case, st)
        if forced and blocked:
            print("[WARN] FORCED 跳过 %d 个阶段的产物闸：%s（原因：%s）"
                  % (len(blocked), "、".join(s for s, _ in blocked), reason))
        print("[OK] 阶段 %s → %s（%s）%s"
              % (cur, want, STAGE_NAME.get(want, ""), "  forced" if forced else ""))
        cur = want

    nxt = STAGE_NEXT.get(cur, "done")
    print("[STAGE] case=%s" % d)
    print("  当前：%s（%s）" % (cur, STAGE_NAME.get(cur, "?")))
    print("  下一：%s（%s）" % (nxt, STAGE_NAME.get(nxt, "?")))
    hist = st.get("stage_history") or []
    if hist:
        tail = hist[-3:]
        print("  最近变更：" + "；".join(
            "%s@%s" % (h.get("stage"), str(h.get("at"))[5:19]) for h in tail if isinstance(h, dict)))
    aw = st.get("awaiting_human") or {}
    if aw and not str(aw.get("ack") or "").strip():
        print("  [WAIT] 有未回执的卡：%s" % (aw.get("card") or "?"))
        print("         回执后：%s" % _cs_cmd(a.case, "ack", "--ack <字母>"))

    # 下一阶段还缺什么（只列仍未过的；过关就提示可以直接 stage --set）
    if nxt != cur:
        probs = _stage_problems(a.case, nxt, st)
        if probs:
            print("  进入 %s 还缺 %d 项：" % (nxt, len(probs)))
            for it in probs:
                for i, ln in enumerate(str(it).splitlines()):
                    print("    " + ("- " if i == 0 else "  ") + ln)
            print("  补齐后：%s" % _cs_cmd(a.case, "stage", "--set " + nxt))
        else:
            print("  进入 %s 的产物已齐 → %s" % (nxt, _cs_cmd(a.case, "stage", "--set " + nxt)))
    else:
        print("  已在终点阶段（%s）" % cur)


def _stage_gate(a):
    """gate --stage <s>：只认磁盘产物内容的阶段闸。不过就 rc=1 并给可复制命令。"""
    stage = str(a.stage).strip()
    if stage not in STAGES:
        die("--stage 只能是：%s" % " / ".join(STAGES))
    st = load_state(a.case)
    cur = str(st.get("stage") or "intake")
    if cur not in STAGES:
        cur = "intake"
    probs = []

    # ① 授权范围契约（P0-3b）：进阶段 1 及以后，scope.md 必须记了授权来源（四选一）
    if _stage_index(stage) >= _stage_index("1"):
        probs.extend(_scope_problems(a.case))

    # ② 阶段不一致：不许跳阶（跳阶=没登记就往下走）
    if cur != stage:
        probs.append("阶段不一致：state.stage=%s ≠ --stage %s\n"
                     "     先登记：%s" % (cur, stage, _cs_cmd(a.case, "stage", "--set " + stage)))

    # ③ 等人回执未 ack：动手阶段（1–4）一律红
    aw = st.get("awaiting_human") or {}
    if aw and not str(aw.get("ack") or "").strip() and stage in STAGE_ACK_REQUIRED:
        opts = list((aw.get("options") or {}).keys())
        probs.append("还在等用户回执（ask 卡 %s）\n"
                     "     必须先 ack（%s）"
                     % (aw.get("card") or "?",
                        _cs_cmd(a.case, "ack", "--ack " + (opts[0] if opts else "<字母>"))))

    # ④ 产物内容判据（阶段 1 是二选一：凭据类 login.json / 运行类 run.json）
    arts = STAGE_ARTIFACTS.get(stage, [])
    mode = mode_rel = None
    mode_notes = []
    if stage in STAGE_ANY_OF:
        mode, mode_rel, mode_notes, subs = _any_of_stage(a.case, stage, st)
        if subs:
            probs.append("\n     ".join(subs))
    else:
        for rel, chk, hint in arts:
            full = os.path.join(os.path.abspath(a.case), rel)
            try:
                subs = chk(a.case, full, st) or []
            except Exception as e:  # noqa: BLE001
                subs = ["校验时异常：%s: %s" % (type(e).__name__, e)]
            if subs:
                probs.append("产物未过：%s —— %s\n     判据：%s\n     路径：%s"
                             % (rel, "；".join(subs), hint, full))

    if probs:
        print("[FAIL] 阶段产物闸未通过：--stage %s（state.stage=%s）" % (stage, cur))
        for i, p in enumerate(probs, 1):
            print("   %d) %s" % (i, p))
        nxt = STAGE_NEXT.get(stage, "done")
        print("\n[FAIL] 共 %d 项未过；按上面的命令补齐后重跑：%s"
              % (len(probs), _cs_cmd(a.case, "gate", "--stage " + stage)))
        if nxt != stage:
            print("       过关后：%s" % _cs_cmd(a.case, "stage", "--set " + nxt))
        sys.exit(1)

    if mode:
        names = " / ".join(ANY_OF_LABEL.get(rel, rel) for rel, _c, _h in arts)
        print("[PASS] 阶段 %s 产物闸通过（%s 二选一，走的是%s：%s）%s"
              % (stage, names, mode, mode_rel, STAGE_NAME.get(stage, "")))
        for n in mode_notes:
            print("       " + n)
    else:
        print("[PASS] 阶段 %s 产物闸通过（%d 个产物按内容校验：%s）"
              % (stage, len(arts), STAGE_NAME.get(stage, "")))
    nxt = STAGE_NEXT.get(stage, "done")
    if nxt != stage:
        print("       下一阶段：%s（%s）→ %s"
              % (nxt, STAGE_NAME.get(nxt, "?"), _cs_cmd(a.case, "stage", "--set " + nxt)))
    sys.exit(0)


def cmd_gate(a):
    if getattr(a, "stage", ""):
        return _stage_gate(a)   # P2-1：带 --stage 走阶段产物闸（按内容判）
    st = load_state(a.case)
    facts = load_facts(a.case)
    plan = load_plan(a.case)
    gaps = load_gaps(a.case)
    depth = st.get("depth", {})
    bad = []
    warn = []

    # ---- 深度门：D0–D5 必填；D6/D7 只告警（旧案不因扩展级全红）
    missing = [lv for lv in CORE_LEVELS if lv not in depth]
    failed = [lv for lv in CORE_LEVELS if lv in depth and depth[lv].get("result") == "fail"]
    failed_opt = [lv for lv in OPTIONAL_LEVELS if depth.get(lv, {}).get("result") == "fail"]
    if missing:
        bad.append("深度未登记：" + "、".join(f"{lv}({LEVEL_NAME[lv]})" for lv in missing))
    if failed:
        bad.append("深度未通过：" + "、".join(failed))
    for lv in OPTIONAL_LEVELS:
        if lv not in depth:
            warn.append(f"{lv} 未登记（{LEVEL_NAME[lv]}）—— 老案子不阻断，但建议补；裁定=可赢时必填")
    for lv in failed_opt:
        warn.append(f"{lv} = fail（{LEVEL_NAME[lv]}）：该轴有未过的闸门，不能据此报「可赢」")

    # na 不能当洗白：D0–D5 必须写原因，且不许全 na（血案：全 na + 可赢 也能过闸）
    bare_na = [lv for lv, v in depth.items()
               if lv in CORE_LEVELS and v.get("result") == "na" and not (v.get("note") or "").strip()]
    if bare_na:
        bad.append("na 必须写原因：" + "、".join(bare_na))
    for lv in OPTIONAL_LEVELS:
        if lv in depth and depth[lv].get("result") == "na" and not (depth[lv].get("note") or "").strip():
            warn.append(f"{lv} 记了 na 但没写原因（可选级不阻断，但建议补；裁定=可赢时必填）")
    core_vals = [depth[lv] for lv in CORE_LEVELS if lv in depth]
    if core_vals and all(v.get("result") == "na" for v in core_vals):
        bad.append("D0–D5 全 na：等于什么都没做，不许出闸")
    passed = {lv for lv, v in depth.items() if v.get("result") == "pass"}
    need_by_verdict = {"可赢": {"D0", "D1", "D2", "D3", "D4"},
                       "部分可赢": {"D0", "D1", "D2", "D3"},
                       "不可赢": {"D0", "D1", "D2"}}

    proven = [f for f in facts if f["status"] == "proven"]
    if not proven:
        bad.append("没有任何已证事实（proven）：阶段零至少要有一条带证据的结论")

    naked = [f["id"] for f in facts
             if f["status"] == "proven"
             and not any(str(e).strip() for e in (f.get("evidence") or []))]
    if naked:
        bad.append("无证据的 proven：" + "、".join(naked))

    nohow = [f["id"] for f in facts
             if f["status"] == "proven" and not str(f.get("how") or "").strip()]
    if nohow:
        bad.append("proven 缺 how（怎么测的）：" + "、".join(nohow))

    # ---- S2-4：置信度 / 权威（unknown 永不计 pass；gate 先告警，--strict 时阻断）
    weak_conf = [f["id"] for f in facts
                 if f["status"] == "proven"
                 and _norm_confidence(f.get("confidence")) in WEAK_CONFIDENCE]
    no_auth = [f["id"] for f in facts
               if f["status"] == "proven"
               and str(f.get("authority") or "none").strip().lower() in ("", "none")]
    msg_conf = ("proven 但置信度不足（unknown/inferred）：" + "、".join(weak_conf)
                + " —— verify 会整案判 unknown（不计 pass）；补 --confidence observed")
    msg_auth = ("proven 但 authority 未声明：" + "、".join(no_auth)
                + " —— 补 --authority shipped-artifact|controlled-replay|external-service")
    if weak_conf or no_auth:
        if a.strict:
            for m in (msg_conf if weak_conf else "", msg_auth if no_auth else ""):
                if m:
                    bad.append(m)
        else:
            for m in (msg_conf if weak_conf else "", msg_auth if no_auth else ""):
                if m:
                    warn.append(m)

    # ---- TTL：stale 未复验 → 拒绝（证明可复活）
    stale = [f for f in facts if f.get("status") == "stale"]
    if stale:
        bad.append("有 %d 条结论已 stale 且未复验（%s）：先复验或说明为何仍成立 —— "
                   "prove --id <id> --evidence \"复验：...\""
                   % (len(stale), "、".join(f["id"] for f in stale)))

    if not st.get("verdict"):
        bad.append("未给可行性裁定（verdict）")
    else:
        need = need_by_verdict.get(st["verdict"], set())
        lack = sorted(need - passed)
        if lack:
            bad.append(f"裁定「{st['verdict']}」要求 {'/'.join(sorted(need))} 全部 pass，缺：" + "、".join(lack))

    # ---- 缺件经济学：不可补且 Δ≤-0.3 的缺件会关掉路线
    blocking = _blocking_gaps(gaps)
    if st.get("verdict"):
        note = st.get("verdict_note") or ""
        for g in blocking:
            if not _mentions(note, g):
                bad.append("裁定 note 必须提到不可补缺件 %s（%s，Δ%s）：它决定了哪级路线被关掉"
                           % (g.get("id"), g.get("missing"), g.get("delta")))
    for g in blocking:
        dep = [p for p in plan if _depends(p, g)]
        if dep:
            bad.append("菜单含依赖不可补缺件 %s（%s）的路线：%s —— 必须剔除"
                       % (g.get("id"), g.get("missing"),
                          "、".join("%s %s" % (p.get("level"), p.get("route")) for p in dep)))

    # ---- 路线菜单：至少 2 条候选；裁定后必须 choose
    if len(plan) < 2:
        bad.append("路线菜单（plan）不足 2 条候选（当前 %d）：先 advise 看建议，再 plan --add / plan --from-advise"
                   % len(plan))
    chosen = [p for p in plan if p.get("chosen")]
    if len(chosen) > 1:
        bad.append("菜单出现 %d 条 chosen：只能选定一条" % len(chosen))
    if st.get("verdict") and not chosen:
        bad.append("已给裁定但未 choose 路线：阶段一必须按选定等级执行（choose --level Lx --route ...）")
    if chosen and st.get("goal_level") and chosen[0].get("level") != st["goal_level"]:
        bad.append("chosen 与 state.goal_level 不一致（%s vs %s）：重跑 choose"
                   % (chosen[0].get("level"), st["goal_level"]))

    # ---- 可赢时 D6/D7 必须至少 na + 原因（防止拿「可赢」但没查 kill-switch / 静默失败）
    if st.get("verdict") == "可赢":
        lack_opt = [lv for lv in OPTIONAL_LEVELS
                    if lv not in depth or not (depth[lv].get("note") or "").strip()]
        if lack_opt:
            bad.append("裁定=可赢要求 D6/D7 至少 na 并写原因，缺：" + "、".join(lack_opt))
        if failed_opt:
            bad.append("裁定=可赢但 " + "、".join(failed_opt)
                       + " = fail（kill-switch / 静默失败面未过）")

    # I0：仪器可行性。血案——2 小时后才发现调试器一挂就自毁、Frida 早期挂载会被静默掐网络
    inst = st.get("instruments") or {}
    alive = [k for k, v in inst.items()
             if v.get("status") in ("ok", "partial") and k != "baseline"]
    if len(inst) < 2:
        bad.append("未登记仪器可行性（I0）：至少 2 种（如 frida-attach + external）")
    elif not alive:
        bad.append("所有仪器都被阻断：至少要有一种可观测手段（外部观测/网络层也算）")

    pend = [f["id"] for f in facts if f["status"] == "hypothesis"]
    if a.strict and pend:
        bad.append("仍有 hypothesis 未处理：" + "、".join(pend))

    # ★ P0-3b：范围契约不是「生成完就算」。阶段 1 及以后必须已记录授权来源；
    #   阶段 0/0a 只提示（否则建案就红），但把「进阶段 1 前必填」摆在输出里。
    cur_stage = str(st.get("stage") or "intake")
    if _stage_index(cur_stage) >= _stage_index("1"):
        bad.extend(_scope_problems(a.case))
    else:
        _sp = _scope_problems(a.case)
        if _sp:
            warn.append("scope.md 授权来源未就绪（阶段 0 不阻断，进阶段 1 前必须填）："
                        + _sp[0].splitlines()[0])

    if warn:
        print("[WARN] 不阻断的提醒：")
        for w in warn:
            print("   - " + w)

    # ---- 事件账体检（P1-1）：只打一行提示，**不改退出码** ——
    # 老案子没有 events.jsonl 是正常状态，不能因此变红。
    if not _events_nonempty(a.case):
        print("[WARN] NO_EVENTS —— 本 case 没有事件账（%s 缺失或为空）："
              "只说明还没跑过带 seep-events 扩展的会话，不影响本闸结论" % _events_path(a.case))

    if bad:
        print("[FAIL] 阶段零出口闸未通过：")
        for b in bad:
            print("   - " + b)
        print(f"\n事实：proven {sum(1 for f in facts if f['status']=='proven')} / "
              f"stale {len(stale)} / hypothesis {len(pend)} / "
              f"refuted {sum(1 for f in facts if f['status']=='refuted')}")
        print(f"菜单：{len(plan)} 条，chosen {len(chosen)}；缺件：{len(gaps)} 条（阻断 {len(blocking)}）")
        sys.exit(1)

    print(f"[PASS] 阶段零出口闸通过 —— 裁定 {st['verdict']}，交付上限 {st['max_level']}，"
          f"深度 {len(depth)}/{len(LEVELS)}，事实 {len(facts)} 条")
    if chosen:
        c = chosen[0]
        print(f"       选定路线：{c.get('level')} {c.get('route')}（p={float(c.get('p') or 0):.2f}，"
              f"工时 {c.get('hours') or '?'}，失败判据：{c.get('fail_criteria') or '未写'}）")
    print(f"       下一步：{st.get('next_action') or '进 01-gate-bypass'}")
    sys.exit(0)


RANK = {"M1": 1, "M2": 2, "M3": 3, "M4": 4}
# 客户语言：对外只说这三句（PM-SPEC §7），内部 M/L/T 代号只在账本/调试输出里出现。
LEVEL_CUSTOMER = {
    "M1": "只能看懂结构", "M2": "能改到能用",
    "M3": "能完全自己接管", "M4": "能完全自己接管",
    # 历史词表（旧案账本里可能残留）也只是查表展示，不把代号写给客户
    "L1": "只能看懂结构", "L2": "能改到能用", "L3": "能完全自己接管",
    "T1": "只能看懂结构", "T2": "能改到能用",
    "T3": "能完全自己接管", "T4": "能完全自己接管",
}


def _repro_records(case):
    """账本里的 repro 记录（宽松读：坏行/非 repro 行直接跳过，不让交付闸变成解析器）。"""
    out = []
    fjs = os.path.join(os.path.abspath(case), "facts.jsonl")
    if not os.path.isfile(fjs):
        return out
    with open(fjs, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and _entry_kind(rec) == "repro":
                out.append(rec)
    return out


def _is_complete_e3(rec):
    """交叉验证证据的**结构**判据（只认结构化记录，不认任何地方手写的 "grade": "E3" 字样）。

    kind=repro 且 grade=E3、cmd 非空、runs>=2、digests 条数 == runs（真跑了几次就有几个指纹）、
    expect 非空（有可机检的期望片段）、also_cmd 非空且 != cmd（两路真独立）。
    """
    if not isinstance(rec, dict) or _entry_kind(rec) != "repro":
        return False
    if str(rec.get("grade") or "").strip().upper() != "E3":
        return False
    cmd = str(rec.get("cmd") or "").strip()
    also = str(rec.get("also_cmd") or "").strip()
    expect = str(rec.get("expect") or "").strip()
    try:
        runs = int(rec.get("runs") or 0)
    except (TypeError, ValueError):
        return False
    digests = rec.get("digests")
    return bool(cmd) and bool(expect) and bool(also) and also != cmd \
        and runs >= 2 and isinstance(digests, list) and len(digests) == runs


def _is_complete_repro(rec):
    """「能改到能用」（M2）的结构判据（P0-4b）：至少一条真跑过两次且一致的复现记录。

    只认结构化账本行，不认报告/对话里的自述：kind=repro、cmd 非空、expect 非空、
    runs>=2、digests 条数 == runs、consistent==true。
    """
    if not isinstance(rec, dict) or _entry_kind(rec) != "repro":
        return False
    cmd = str(rec.get("cmd") or "").strip()
    expect = str(rec.get("expect") or "").strip()
    try:
        runs = int(rec.get("runs") or 0)
    except (TypeError, ValueError):
        return False
    digests = rec.get("digests")
    return bool(cmd) and bool(expect) and runs >= 2 \
        and isinstance(digests, list) and len(digests) == runs \
        and rec.get("consistent") is True


def cmd_deliver(a):
    """交付分级闸：产物等级不许超过阶段零裁定的上限（血案：文件生成了就宣布可用）。"""
    lease_guard(a.case)
    st = load_state(a.case)
    if not st.get("verdict"):
        die("还没给可行性裁定（verdict），不许交付")
    cap = st.get("max_level") or "M1"
    if a.level not in RANK:
        die("level 只能是 M1 / M2 / M3 / M4")
    if RANK[a.level] > RANK.get(cap, 1):
        die(f"越级交付：裁定 {st['verdict']} 的上限是 {cap}，不接受 {a.level}")
    # 外部评审 A5：最高两级（M3/M4）必须有**交叉验证/端到端**证据，不能只靠自述
    if a.level in ("M3", "M4"):
        recs = _repro_records(a.case)
        strong = [r for r in recs if _is_complete_e3(r)]
        if not strong:
            die("交付 %s 需要至少一条**结构完整**的 E3 交叉验证记录"
                "（kind=repro / grade=E3 / cmd 非空 / expect 非空 / runs>=2 / digests 条数==runs / "
                "also_cmd 非空且 != cmd）。账本里现有 repro 记录 %d 条，其中 0 条达标"
                "（只写 "
                "\"grade\": \"E3\" 字样不算数）。\n"
                "修法：python Tool/scripts/case_state.py repro --case %s --id E-001 "
                "--cmd \"<第一路命令>\" --expect \"<必须出现的片段>\" "
                "--also-cmd \"<另一条**真不同**的命令>\" --runs 2"
                "（必须带 --case 与 --id 才会落账本；两路命令相同会被拒升 E3），"
                "之后用 show 确认账本里出现 grade=E3 的 repro 行；"
                "撑不到 E3 就交付 M2 并写明天花板" % (a.level, len(recs), os.path.abspath(a.case)))
    # P0-4b：「能改到能用」（M2）不是「文件改动了」就算 —— 至少一条结构化 repro（真跑两次且一致）
    if a.level == "M2":
        recs = _repro_records(a.case)
        good = [r for r in recs if _is_complete_repro(r)]
        if not good:
            cdir = os.path.abspath(a.case)
            die("交付 M2（客户话：能改到能用）必须至少有 1 条**结构完整**的复现记录；"
                "账本里现有 repro 记录 %d 条，其中 0 条达标。\n"
                "判据（缺一不可）：kind=repro / cmd 非空 / expect 非空 / runs>=2 / "
                "digests 条数==runs / consistent==true（报告或对话里写「跑过了」不算）。\n"
                "出路①（补证据，推荐）：\n"
                "  python Tool/scripts/case_state.py repro --case %s --id E-001 "
                "--cmd \"<能复现的命令>\" --expect \"<必须出现的片段>\" --runs 2\n"
                "  输出里应出现「一致=True」且写入账本；然后重跑本命令。\n"
                "出路②（不补证据就降档，只交结构理解）：\n"
                "  python Tool/scripts/case_state.py deliver --case %s --level M1 "
                "--evidence \"<截图/日志>\"（客户话：只能看懂结构）"
                % (len(recs), cdir, cdir))
    ev = require_evidence(a.evidence, a.case)
    if not ev:
        die("交付必须有可核对的证明（--evidence：证据文件路径 / 命令+产物 / 哈希 / 账本编号；纯文本不算）")
    st.setdefault("deliveries", []).append(
        {"level": a.level, "evidence": a.evidence, "note": a.note or "", "ts": now()})
    st["next_action"] = {"M1": "补功能面，冲 M2", "M2": "冲 M3（UI/授权）",
                         "M3": "追版与维护", "M4": "维护"}.get(a.level, "")
    save_state(a.case, st)
    print(f"[OK] 已登记交付 {a.level}（上限 {cap}）：{a.evidence}")


def cmd_show(a):
    st = load_state(a.case)
    facts = load_facts(a.case)
    gaps = load_gaps(a.case)
    plan = load_plan(a.case)
    print(f"案子：{a.case}")
    print(f"  目标：{st.get('target') or '-'}")
    # 缝2（P2-4）：T 词表与 M 词表各存各的，这里两栅都打（并附展示用换算）
    tier_v, lvl_v = st.get("tier"), st.get("max_level")
    print(f"  裁定：{st.get('verdict') or '（未给）'}"
          + (f"（原始 --tier 输入 {st['tier_input']}）" if st.get("tier_input") else ""))
    print(f"  后端档位（T 词表）：{tier_v or '（未给）'}"
          + (("  " + tier_view(tier_v)) if tier_v else ""))
    print(f"  交付上限（M 词表）：{lvl_v or '-'}"
          + (("  " + tier_view(lvl_v)) if lvl_v else "")
          + (f"   选定等级：{st['goal_level']}"
             + (f"（{st['goal_route']}）" if st.get("goal_route") else "")
             if st.get("goal_level") else ""))
    if st.get("verdict_note"):
        print(f"  裁定理由：{st['verdict_note']}")
    inst = st.get("instruments") or {}
    if inst:
        print("  仪器（I0）：")
        for k, v in inst.items():
            print(f"    {k:<14} {v['status']:<8} {v.get('note','')}")
    print("  深度：")
    for lv in LEVELS:
        v = st.get("depth", {}).get(lv)
        optional = "（可选）" if lv in OPTIONAL_LEVELS else ""
        mark = v["result"] if v else "未登记"
        print(f"    {lv} {mark:<4} {LEVEL_NAME[lv]}{optional}"
              + (f"  — {v['note']}" if v and v.get("note") else ""))
    print_gaps(gaps)
    print_plan(plan)
    print(f"  事实（{len(facts)} 条）：")
    for f in facts:
        tag = {"proven": "已证", "hypothesis": "待验", "refuted": "已推翻",
               "stale": "失效"}.get(f["status"], f["status"])
        extra = f"  被 {f['refuted_by']} 推翻" if f.get("refuted_by") else ""
        if f.get("stale_reason"):
            extra += f"  stale: {f['stale_reason']}"
        print(f"    [{tag}] {f['id']:<6} {f['claim'][:52]}{extra}")


def cmd_resume(a):
    st = load_state(a.case)
    facts = load_facts(a.case)
    plan = load_plan(a.case)
    gaps = load_gaps(a.case)
    proven = [f for f in facts if f["status"] == "proven"]
    pend = [f for f in facts if f["status"] == "hypothesis"]
    stale = [f for f in facts if f["status"] == "stale"]
    print(f"[接续] {a.case}  裁定={st.get('verdict') or '未给'}  上限={st.get('max_level') or '-'}"
          + (f"  选定等级={st['goal_level']}"
             + (f"（{st['goal_route']}）" if st.get("goal_route") else "")
             if st.get("goal_level") else ""))
    print(f"  已证 {len(proven)} / 待验 {len(pend)} / "
          f"已推翻 {sum(1 for f in facts if f['status']=='refuted')} / stale {len(stale)}")
    if pend:
        print("  待验清单：" + "、".join(f["id"] for f in pend))
    if stale:
        print("  stale 待复验：" + "、".join(f["id"] for f in stale))
    print_gaps(gaps)
    print_plan(plan)
    dl = st.get("deliveries") or []
    if dl:
        print("  已登记交付：" + "、".join(f"{d['level']}({d['ts'][:16]})" for d in dl))
    print(f"  下一步：{st.get('next_action') or '（未写）'}")


def cmd_handoff(a):
    """案例级续接快照：≤40 行，全部由账本现算（不读任何手写文档）。

    四问（PowerContext RFC 0048）：目标 / 当前状态 / 能否继续 / 下一步。
    设计红线：**不写任何需要人维护的数字**，所以它不可能过期。
    """
    st = load_state(a.case)
    facts = load_facts(a.case)
    plan = load_plan(a.case)
    gaps = load_gaps(a.case)
    proven = [f for f in facts if f["status"] == "proven"]
    pend = [f for f in facts if f["status"] == "hypothesis"]
    stale = [f for f in facts if f["status"] == "stale"]
    refuted = [f for f in facts if f["status"] == "refuted"]

    def _cut(x, n=96):
        x = " ".join(str(x).split())
        return x if len(x) <= n else x[:n] + "…"

    out = []
    out.append("=" * 68)
    out.append("接续快照 · %s" % a.case)
    out.append("=" * 68)
    # ① 目标
    out.append("【目标】裁定=%s  上限=%s%s"
               % (st.get("verdict") or "未给", st.get("max_level") or "-",
                  ("  选定=%s" % st["goal_level"]) if st.get("goal_level") else ""))
    if st.get("stage"):
        out.append("        阶段=%s  深度=%s  仪器=%s"
                   % (st.get("stage"), st.get("depth") or "-", st.get("instrument") or "-"))
    # ② 当前状态
    out.append("【状态】已证 %d / 待验 %d / 已推翻 %d / stale %d"
               % (len(proven), len(pend), len(refuted), len(stale)))
    for f in proven[:6]:
        out.append("  ✓ %s %s" % (f["id"], _cut(f.get("claim"))))
    if len(proven) > 6:
        out.append("  … 另 %d 条已证（case_state.py verify --case）" % (len(proven) - 6))
    for f in pend[:4]:
        out.append("  ? %s %s" % (f["id"], _cut(f.get("claim"))))
    for f in stale[:3]:
        out.append("  ! %s 已过期待复验：%s" % (f["id"], _cut(f.get("claim"))))
    if gaps:
        out.append("【缺件】" + "；".join(
            "%s(%s)" % (g["id"], _cut(g.get("missing"), 40)) for g in gaps[:4]))
    if plan:
        out.append("【路线】" + "；".join(
            "%s:%s" % (p.get("id"), _cut(p.get("desc") or p.get("route"), 40)) for p in plan[:4]))
    dl = st.get("deliveries") or []
    if dl:
        out.append("【已交付】" + "、".join("%s(%s)" % (d["level"], d["ts"][:16]) for d in dl[-3:]))
    # ③ 能否继续
    asks = [e for e in (st.get("asks") or []) if not e.get("acked")]
    if asks:
        out.append("【卡住·等用户】" + "；".join(_cut(x.get("q") or x.get("text"), 60) for x in asks[:3]))
    else:
        out.append("【可继续】无未决 ASK")
    # ④ 下一步
    out.append("【下一步】%s" % (st.get("next_action") or "（未写：先定下一步并落账）"))
    out.append("【红线】上面没列出的结论都**没验证过**，不许当已知条件用；"
               "新结论必须先 claim 再 prove（证据落 artifacts/ + MANIFEST）")
    out.append("=" * 68)
    print("\n".join(out[:40]))


def _git(*args):
    try:
        return subprocess.run(("git",) + args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20).stdout.strip()
    except Exception:
        return ""


def cmd_repo_handoff(a):
    """仓库级续接快照（生成块）。只放**可现算**的东西：HEAD、未提交、最近提交、判据命令。"""
    head = _git("rev-parse", "--short", "HEAD") or "unknown"
    branch = _git("rev-parse", "--abbrev-ref", "HEAD") or "-"
    dirty = len([l for l in _git("status", "--porcelain").splitlines() if l.strip()])
    log = [l for l in _git("log", "--oneline", "-6").splitlines() if l.strip()]
    tags = [t for t in _git("tag", "--sort=-creatordate").splitlines() if t.strip()][:5]
    out = [
        "<!-- handoff:generated by `python Tool/scripts/case_state.py handoff --repo`"
        " —— 本节整块重写，勿手改 -->",
        "<!-- handoff:HEAD=%s -->" % head,
        "",
        "| 项 | 值（现算，不手写） |",
        "| :-- | :-- |",
        "| 分支 / HEAD | `%s` / `%s` |" % (branch, head),
        "| 未提交改动 | %d 个文件 |" % dirty,
        "| 最近 tag（版本定位） | %s |" % ("、".join("`%s`" % t for t in tags) if tags else "（暂无）"),
        "",
        "**最近提交**",
        "",
    ]
    out += ["- `%s`" % l for l in log]
    out += [
        "",
        "**判据（数字只看命令输出，本文不写死）**",
        "",
        "```bash",
        "python Tool/scripts/preflight.py --fast    # 门禁",
        "python Tool/scripts/gate.py --all          # 按包判定（证据强度）",
        "python Tool/scripts/route.py --check       # 路由死链",
        "python Tool/scripts/case_state.py verify --all   # 证据聚合",
        "```",
        "",
        "<!-- /handoff:generated -->",
    ]
    print("\n".join(out))


# ───────────────────── 5 件事（2026-10-25）：首答/降级/重放/BLK/复查 ─────────────────────
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_TOOL = os.path.join(_ROOT, "Tool")


def _stdin_utf8():
    """读 stdin 时强制 UTF-8：Windows 下 sys.stdin 默认按 locale(cp936) 解码，
    管道进来的中文 JSON 会变成乱码，导致 ceiling/missing 比对凭空失败（实测）。"""
    buf = getattr(sys.stdin, "buffer", None)
    if buf is not None:
        return buf.read().decode("utf-8", "replace")
    return sys.stdin.read()


def _jd(rel):
    with open(os.path.join(_TOOL, "config", rel), encoding="utf-8") as f:
        return json.load(f)


def _write_answer_pass(case=""):
    """首答过的凭证：写 ~/.seep/answer-pass.json（扩展 answer-gate.ts 认这一个文件）。

    为什么要有这个文件：提示词里写「必须先给四要素」管不住模型 —— 它只要直接调第一个
    分析工具，首答就被跳过了；而 `answer --check` 只能校验「被调用时传进来的那份 JSON」，
    管不住「根本没被调用」。所以把「通过」变成一个磁盘事实，让扩展在 tool_call 里查它：
    没有这个标记，分析类工具连发都发不出去。

    只在**通过时**调用（失败不写）；写盘失败也不改判定结果（rc 仍是 0），只是闸继续拦。
    契约哈希写进去是为了「契约改了 → 旧标记自动作废」：四要素一改，上一份首答不算数。
    第 2 轮评审：标记还要**绑目标** —— `case` 记案件目录，`target_sha256` 记该案
    case.json 里登记的目标哈希（target_files[].sha256 优先；没登记就按 target 路径现算），
    有效期由 answer-contract.json 的 gate.ttl_minutes 决定（当前 60 分钟）。
    """
    import datetime
    import hashlib
    try:
        with open(os.path.join(_TOOL, "config", "answer-contract.json"), "rb") as f:
            ch = hashlib.sha256(f.read()).hexdigest()
        case_abs = os.path.abspath(os.path.expanduser(case)) if case else ""
        # 目标哈希：只从该案 case.json 的登记里取（没给 case / 没登记 / 文件不在 → 空串）
        target_sha = ""
        try:
            cj = {}
            cjp = os.path.join(case_abs, "case.json") if case_abs else ""
            if cjp and os.path.isfile(cjp):
                with open(cjp, encoding="utf-8") as f:
                    cj = json.load(f)
            for it in (cj.get("target_files") or []):
                sh = str((it or {}).get("sha256") or "").strip().lower()
                if sh:
                    target_sha = sh
                    break
            if not target_sha:
                for k in ("target", "target_path", "target_type"):
                    v = cj.get(k)
                    if isinstance(v, dict):
                        # 新 case.json 的 target 是原件指纹块：直接用它登记的 sha256（别 str(dict) 当路径）
                        sh = str(v.get("sha256") or "").strip().lower()
                        if sh:
                            target_sha = sh
                            break
                        v = v.get("path") or ""
                    v = str(v or "").strip()
                    if not v:
                        continue
                    ap = v if os.path.isabs(v) else os.path.join(case_abs, v)
                    if os.path.isfile(ap):
                        hh = hashlib.sha256()
                        with open(ap, "rb") as f:
                            for chunk in iter(lambda: f.read(1 << 20), b""):
                                hh.update(chunk)
                        target_sha = hh.hexdigest()
                        break
        except Exception:  # noqa: BLE001
            target_sha = ""
        payload = {
            "schema": "seep.answer-pass/1",
            "case": case_abs,
            # 目标身份：换目标必须重新给首答（扩展按 case.json 的 target_files/target 比对路径）
            "target_sha256": target_sha,
            # ISO8601 带 UTC 偏移：扩展侧 Date.parse 直接认，不做本地时区猜测
            "at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "contract_sha256": ch,
        }
        p = os.path.join(os.path.expanduser("~"), ".seep", "answer-pass.json")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
        os.replace(tmp, p)  # 原子落盘：扩展永远读不到半截 JSON
    except Exception:  # noqa: BLE001
        pass


def _check_answer(obj, c):
    bad = []
    for f in c["required"]:
        v = obj.get(f["key"])
        if not v or (isinstance(v, (list, dict)) and not v):
            bad.append("缺 %s（%s）" % (f["label"], f["hint"]))
    ceil_v = str(obj.get("ceiling") or "")
    if ceil_v and ceil_v not in c["ceiling_sentences"]:
        bad.append("「到哪一步」只能用这四句之一：" + " / ".join(c["ceiling_sentences"]))
    r = c["ask_rules"]
    for q in obj.get("asks") or []:
        opts = q.get("options") or []
        if not (r["min_options"] <= len(opts) <= r["max_options"] + 1):
            bad.append("%s 选项数 %d 不在 %d–%d" % (q.get("id"), len(opts),
                                                   r["min_options"], r["max_options"]))
        for o in opts:
            if r["require_consequence"] and not str(o.get("consequence") or "").strip():
                bad.append("%s/%s 没写「选了会怎样」" % (q.get("id"), o.get("key")))
    text = json.dumps(obj, ensure_ascii=False)
    for p in c["forbidden_phrases"]:
        if p in text:
            bad.append("出现禁用措辞「%s」（无证据的肯定）" % p)
    return bad


def cmd_answer(a):
    """首答三要素：缺一即不合格；选项必须写「选了会怎样」。"""
    c = _jd("answer-contract.json")
    if a.template:
        print("【判断】这是什么 / 有没有保护 / 关键在哪：…")
        print("【到哪一步】" + " | ".join(c["ceiling_sentences"]))
        print("【缺什么】① … ② …")
        print("【大约多少功夫】X 小时 – Y 天（依据：为什么是这个量级）")
        print("【已有证据】E-001 …（或：暂无，只有文件哈希）")
        print("【请你选】Q1｜…  A …→选了会怎样  B …→…  C 我不确定→…")
        print("【你要做的】回一个字母")
        return 0
    if a.selftest:
        good = {"judgment": "PE32+，未见壳", "ceiling": "只能看懂结构",
                "missing": ["有没有卡密"],
                "effort": "半小时 – 2 小时；依据：未见壳、纯本地判定，读一遍导入表即可定性",
                "asks": [{"id": "Q1", "options": [
                    {"key": "A", "consequence": "走在线对比"},
                    {"key": "B", "consequence": "走离线判定"},
                    {"key": "C", "consequence": "先找校验痕迹"}]}]}
        bad = {"judgment": "x", "missing": [],
               "asks": [{"id": "Q1", "options": [{"key": "A"}]}]}
        ok = (1 if not _check_answer(good, c) else 0) + (1 if _check_answer(bad, c) else 0)
        print("[answer --selftest] %d/2 通过" % ok)
        return 0 if ok == 2 else 1
    src = a.file or ""
    try:
        obj = json.load(open(src, encoding="utf-8")) if src else json.loads(_stdin_utf8())
    except Exception as e:  # noqa: BLE001
        print("[ERR] 读不到 JSON：%s" % e)
        return 2
    bad = _check_answer(obj, c)
    for b in bad:
        print("[缺] " + b)
    print("[PASS] 首答合格" if not bad else "[FAIL] 首答不合格（%d 项）" % len(bad))
    if not bad:
        # 通过才写标记（就是 --check 的放行凭证）；失败不写，扩展 answer-gate.ts 继续拦
        _write_answer_pass(getattr(a, "case", "") or "")
        _cp = str(getattr(a, "case", "") or "").strip()
        print("[标记] 已写 ~/.seep/answer-pass.json（TTL 取自 gate.ttl_minutes；case=%s）"
              % (_cp or "（未指定，不绑目标）"))
    return 0 if not bad else 1


def cmd_block(a):
    """按 BLK 码渲染失败五段（卡层/现象/为什么/已拿到/两条出路）。"""
    c = _jd("blockers.json")
    if a.list or not a.code:
        for x in c["codes"]:
            print("%-7s %-14s %s" % (x["code"], x["name"], x["customer"]))
        return 0 if a.list else 2
    hit = [x for x in c["codes"] if x["code"].lower() == a.code.lower()]
    if not hit:
        print("[ERR] 未知 BLK 码：%s（用 block --list 看全部）" % a.code)
        return 2
    x = hit[0]
    # P0-4：五段是**给客户看的正文**，不带内部代号；码写 stderr + 账本（st.blocker）。
    try:
        sys.stderr.write("[block] 内部码 %s（只记账，不进客户正文）\n" % x["code"])
    except Exception:  # noqa: BLE001
        pass
    print("【卡在哪一层】%s（%s）" % (x["name"], x["customer"]))
    print("【我看到什么】%s" % (a.detail or "（填现象，带证据 ID）"))
    print("【为什么】%s" % (a.why or "（一句白话原因）"))
    print("【已经拿到什么】%s" % (a.got or "（当前到哪一级 + 哪几条结论成立）"))
    print("【两条出路】")
    for i, e in enumerate(x["exits"], 1):
        print("  %d. %s" % (i, e))
    if a.case:
        try:
            st = load_state(a.case)
            # next_action 会被 resume/handoff 原样展示给客户，所以只放客户话；码进 blocker 字段。
            st["next_action"] = "%s：%s" % (x["customer"], x["name"])
            st["blocker"] = x["code"]
            save_state(a.case, st)
        except Exception:  # noqa: BLE001
            pass
    return 0


def cmd_repro(a):
    """证据结构化重放：跑 N 次比对输出指纹；一致 + 期望命中才给 E2。"""
    import hashlib
    import subprocess as _sp
    if not a.cmd:
        print("[ERR] 需要 --cmd")
        return 2
    runs = max(1, int(a.runs or 2))
    digests, outs = [], []
    for i in range(runs):
        try:
            p = _sp.run(a.cmd, shell=True, capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=int(a.timeout or 300))
        except Exception as e:  # noqa: BLE001
            print("[ERR] 第 %d 次执行失败：%s" % (i + 1, e))
            return 2
        blob = (p.stdout or "") + (p.stderr or "")
        outs.append(blob)
        digests.append(hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()[:16])
        if a.expect and a.expect not in blob:
            print("[WARN] 第 %d 次输出里没找到期望片段：%r" % (i + 1, a.expect))
    same = len(set(digests)) == 1
    expect_ok = bool(a.expect) and all(a.expect in o for o in outs)
    grade = "E2" if (same and expect_ok) else "E1"
    # E3 = 两条**独立**命令各自一致且都命中期望（外部评审 A5：最高等级上限必须有可机检依据）
    # 独立性是硬要求：--also-cmd 就是 --cmd 本身（去空白后相等）不能算交叉验证，一分不给。
    alt = (getattr(a, "also_cmd", "") or "").strip()
    first_cmd = (a.cmd or "").strip()
    alt_is_same = bool(alt) and " ".join(alt.split()) == " ".join(first_cmd.split())
    if alt_is_same and grade == "E2":
        print("[repro] 第二路与第一路是同一条命令，不算交叉验证 → 拒绝升级 E3，保持 %s" % grade)
    if grade == "E2" and alt and not alt_is_same:
        alt_d, alt_ok_all, alt_hit = [], True, True
        for _i in range(runs):
            import subprocess as _sp2
            try:
                p2 = _sp2.run(alt, shell=True, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=int(a.timeout or 300))
            except Exception as e:  # noqa: BLE001
                print("[repro] 第二路执行失败：%s" % e)
                alt_ok_all = False
                break
            blob2 = (p2.stdout or "") + (p2.stderr or "")
            alt_d.append(hashlib.sha256(blob2.encode("utf-8", "replace")).hexdigest()[:16])
            if a.expect and a.expect not in blob2:
                alt_hit = False
        if alt_ok_all and len(set(alt_d)) == 1 and alt_hit:
            grade = "E3"
            print("[repro] 第二路一致（%s）→ 交叉验证成立，证据等级升到 E3" % ",".join(alt_d))
        else:
            print("[repro] 第二路不一致/未命中 → 保持 E2（不许自称交叉验证）")
    print("[repro] 运行 %d 次；指纹 %s；一致=%s；期望命中=%s"
          % (runs, ",".join(digests), same, expect_ok))
    print("[repro] 该证据最高等级 = %s（E2 需：输出一致 + 期望命中；E3 另需第二路命令真的不同且一致）" % grade)
    if a.case and a.id:
        try:
            rec = {"kind": "repro", "id": a.id, "cmd": a.cmd, "also_cmd": alt, "expect": a.expect,
                   "runs": runs, "digests": digests, "consistent": same,
                   "grade": grade, "ts": now()}
            with open(os.path.join(os.path.abspath(a.case), "facts.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            print("[repro] 已写入账本")
        except Exception as e:  # noqa: BLE001
            print("[WARN] 写账本失败：%s" % e)
    # 退出码语义：E2/E3（可当证据）返回 0；E1（不可重复或达不到期望）返回 1。
    return 0 if grade in ("E2", "E3") else 1


def _downgrade_notice(old, new, reason):
    """降级通知的**客户语言**：不出现 M1/M2 之类内部代号（P0-4），代号只进账本。"""
    old_w = LEVEL_CUSTOMER.get(str(old or "").strip().upper())
    new_w = LEVEL_CUSTOMER.get(str(new or "").strip().upper())
    if old_w and new_w:
        return "【降级通知】原来判断能到「%s」，现在只能到「%s」。原因：%s" % (
            old_w, new_w, reason)
    if new_w:
        return "【降级通知】交付上限被下调：现在只能到「%s」。原因：%s" % (new_w, reason)
    return "【降级通知】交付上限被下调（具体档位见账本）。原因：%s" % reason


def cmd_downgrade(a):
    """上限降级必须留通知：承诺过 M2 就不能静默降到 M1。"""
    st = load_state(a.case)
    old = st.get("max_level") or "-"
    new = a.to
    if not new:
        print("[ERR] 需要 --to（如 M1）")
        return 2
    if old == new:
        print("[SKIP] 上限没变（%s）" % old)
        return 0
    if a.reason is None:
        print("[ERR] 降级必须写 --reason（为什么降）")
        return 2
    notif = _downgrade_notice(old, new, a.reason)
    # 账本里同时留代号（可审计）+ 客户话（可直接展示）
    ledger_notice = "【降级通知】%s → %s。原因：%s" % (old, new, a.reason)
    st["max_level"] = new
    st["next_action"] = notif
    save_state(a.case, st)
    with open(os.path.join(os.path.abspath(a.case), "facts.jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps({"kind": "downgrade", "from": old, "to": new,
                            "reason": a.reason, "notice": notif,
                            "notice_internal": ledger_notice, "ts": now()},
                           ensure_ascii=False) + "\n")
    print(notif)
    print("[OK] 已记入账本（kind=downgrade）")
    return 0


def cmd_recheck(a):
    """复查单：两周后照着能复现（目标哈希/环境/证据/重放命令/期望）。"""
    d = os.path.abspath(a.case)
    cj = json.load(open(os.path.join(d, "case.json"), encoding="utf-8"))
    files = cj.get("target_files") or []
    repro = []
    fj = os.path.join(d, "facts.jsonl")
    if os.path.isfile(fj):
        for line in open(fj, encoding="utf-8"):
            if line.strip() and '"kind": "repro"' in line:
                repro.append(json.loads(line))
    L = ["# 复查单（%s）" % os.path.basename(d), "", "## 目标身份", ""]
    for f in files:
        L.append("- `%s` sha256=%s" % (f.get("path"), f.get("sha256")))
    if not files:
        L.append("- （未登记 target_files：请在 case.json 补哈希）")
    L += ["", "## 环境", "",
          "- 生成时间：%s" % now(),
          "- 工具版本：见各证据 `tool_version`",
          "- 已知会变：在线服务、证书、IP（复现失败先查这些）", "",
          "## 证据与重放", ""]
    if repro:
        for r in repro:
            L.append("- `%s` → `%s`（期望包含 `%s`；跑过 %d 次，指纹 %s）"
                     % (r.get("id"), r.get("cmd"), r.get("expect"), r.get("runs"),
                        ",".join(r.get("digests") or [])))
    else:
        L.append("- （暂无结构化重放：跑 `case_state.py repro --case %s --id E-001 "
                 "--cmd \"<命令>\" --expect \"<片段>\"`）" % d)
    L += ["", "## 复现失败怎么判", "",
          "- 先查「已知会变」；仍不一致 → 该结论降为 `未验证`，不要否定整份报告", ""]
    out = os.path.join(d, "recheck.md")
    open(out, "w", encoding="utf-8", newline="\n").write("\n".join(L) + "\n")
    print("[OK] 复查单已生成：%s（%d 条重放记录）" % (out, len(repro)))
    return 0


SECTIONS = ["结论", "已确认", "仍未知", "下一步", "复查"]

# PM-SPEC §11：交付物不得落明文凭据。四条规则的边界都以「两份真实报告 + 全部模板」不误报为准：
#   - 私钥块头 / AWS AK 是强特征，不误报；
#   - 关键字赋值必须紧跟 : 或 = 且值 >=6 个非空字符，所以“secrets 使用 OIDC”“SA token 短时化”不命中（无 : / =）；
#   - Bearer 令牌要求 20+ 连续非空字符，“Bearer 认证”之类白描不会命中。
CRED_RULES = (
    ("PRIVATE KEY 私钥块", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("明文口令/密钥赋值",
     re.compile(r"(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S{6,}", re.I)),
    ("Bearer 令牌", re.compile(r"Bearer\s+\S{20,}", re.I)),
)


# ---------------------------------------------------------------- 报告 ID 对账（P0-4a）
# 血案：`report --check` 以前只认 "E-/C-/F- 的形状"，写 `E-999` 也算“有证据 ID”。
# 现在：**案件报告**（在 Tool/cases/<case>/ 下，或显式给了 --case）必须把每个 ID 对到该案
# facts.jsonl；模板/孤立报告（不是案件报告）只查格式，绝不误伤 Tool/prompts/reports/* 与 templates/*。
REPORT_ID_RE = re.compile(r"\b([ECF])-(\d{2,})\b")


def _cases_root():
    return os.path.join(_TOOL, "cases")


def _case_for_report(path, case_arg=""):
    """报告 → 案件目录。返回 (case_dir|None, note)。

    None = 模板/孤立报告：不做 ID 对账（只查五段格式）。
    """
    if case_arg:
        d = os.path.abspath(case_arg)
        return (d, "explicit") if os.path.isdir(d) else (None, "missing")
    if not path:
        return None, ""
    root = os.path.abspath(_cases_root())
    try:
        rel = os.path.relpath(os.path.abspath(path), root)
    except ValueError:          # 跨盘符（Windows）→ 不可能是案件目录
        return None, ""
    parts = rel.replace("\\", "/").split("/")
    if len(parts) < 2 or parts[0] in ("", ".", "..") or parts[0].startswith("_"):
        return None, ""
    d = os.path.join(root, parts[0])
    return (d, "path") if os.path.isdir(d) else (None, "")


def _ledger_ids(case_dir):
    """该案 facts.jsonl 里出现过的全部 ID（claim / repro / 其它带 id 的行）。"""
    ids = set()
    fp = os.path.join(case_dir, "facts.jsonl")
    if not os.path.isfile(fp):
        return ids
    with open(fp, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and str(rec.get("id") or "").strip():
                ids.add(str(rec["id"]).strip().upper())
    return ids


def _report_id_refs(text):
    """报告里出现过的 E-/C-/F- ID（去重、按出现顺序）。"""
    out, seen = [], set()
    for m in REPORT_ID_RE.finditer(text):
        ident = "%s-%s" % (m.group(1), m.group(2))
        if ident not in seen:
            seen.add(ident)
            out.append(ident)
    return out


def _reconcile_report_ids(text, case_dir):
    refs = _report_id_refs(text)
    ids = _ledger_ids(case_dir)
    return refs, [r for r in refs if r.upper() not in ids]


def _recheck_section_problem(body_lines, case_dir):
    """case.json 有 target_files 时，复查段必须提到目标哈希前缀或 resume 命令。"""
    cj = os.path.join(case_dir, "case.json")
    tfiles = []
    if os.path.isfile(cj):
        try:
            with open(cj, encoding="utf-8") as f:
                tfiles = json.load(f).get("target_files") or []
        except (OSError, ValueError):
            tfiles = []
    hashes = [str(x.get("sha256") or "").strip().lower()
              for x in tfiles if isinstance(x, dict)]
    hashes = [h for h in hashes if len(h) >= 8]
    if not hashes:
        return None
    body = "\n".join(body_lines).lower()
    if "resume" in body:
        return None
    if any(h in body or h[:8] in body or h[:12] in body for h in hashes):
        return None
    return ("复查段既没写目标哈希前缀，也没写 resume 命令（case.json 登记了 target_files）\n"
            "     修法：在复查段加一行 `python Tool/scripts/case_state.py resume --case %s`，"
            "或写进目标哈希前缀 `%s…`（完整哈希：`recheck --case %s` 现算）"
            % (os.path.abspath(case_dir), hashes[0][:12], os.path.abspath(case_dir)))


def cmd_report(a):
    """报告五段校验：缺段不算交付（对应 PM-SPEC §3.3/§7）；案件报告额外做 ID 对账。"""
    if a.selftest:
        N = chr(10)
        good = (
            "# r" + N + "## 1 结论" + N + "能到「只能看懂结构」" + N + "卡在壳上" + N            + "## 2 已确认" + N + "- x（E-001）" + N + "- y（C-002）" + N            + "## 3 仍未知" + N + "- z 缺实测" + N + "- w 需硬件" + N            + "## 4 下一步" + N + "- 省事：A" + N + "- 彻底：B" + N            + "## 5 怎么复查" + N + "- recheck.md" + N + "- 重放 E-001" + N)
        bad = "# r\n## 1 结论\nx\n"
        ok = (1 if not _check_report(good) else 0) + (1 if _check_report(bad) else 0)
        print("[report --selftest] %d/2 通过" % ok)

        def _mk(ids, tail):
            return N.join([
                "# r", "## 1 结论", "能到「只能看懂结构」", "卡在壳上",
                "## 2 已确认", "- x（%s）" % ids, "- y（F-001）",
                "## 3 仍未知", "- z 缺实测", "- w 需硬件",
                "## 4 下一步", "- 省事：A", "- 彻底：B",
                "## 5 怎么复查", "- recheck.md", "- %s" % tail, ""])

        ok2 = 0
        tmp = tempfile.mkdtemp(prefix="cs-report-")
        try:
            with open(os.path.join(tmp, "facts.jsonl"), "w", encoding="utf-8") as f:
                f.write(json.dumps({"id": "F-001", "claim": "x", "status": "proven",
                                    "evidence": ["a.log"], "how": "h"},
                                   ensure_ascii=False) + N)
            with open(os.path.join(tmp, "case.json"), "w", encoding="utf-8") as f:
                json.dump({"id": "t", "target_files": [
                    {"path": "target/a.exe", "sha256": "a" * 64}]}, f)
            # ① 真实 ID + resume 命令 → 过
            ok2 += 1 if not _check_report(_mk("F-001", "resume --case " + tmp),
                                          case_dir=tmp) else 0
            # ② 假 ID → 必红且点名
            miss = _check_report(_mk("E-999", "resume --case " + tmp), case_dir=tmp)
            ok2 += 1 if miss and "E-999" in N.join(miss) else 0
            # ③ 有 target_files 但复查段既无哈希前缀又无 resume → 必红
            nohash = _check_report(_mk("F-001", "recheck.md"), case_dir=tmp)
            ok2 += 1 if nohash and "复查段" in N.join(nohash) else 0
            # ④ 模板/孤立报告（不传 case_dir）不做 ID 对账 → 假 ID 也能过格式
            ok2 += 1 if not _check_report(_mk("E-999", "重放 E-999")) else 0
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        print("[report --selftest] 新增语义 %d/4 通过"
              "（ID 对账 / 假 ID 必红 / 复查段哈希 / 模板不误伤）" % ok2)
        return 0 if (ok == 2 and ok2 == 4) else 1
    src = a.file or ""
    if not src or not os.path.isfile(src):
        print("[ERR] 需要 --file <报告.md>")
        return 2
    case_arg = getattr(a, "case", "") or ""
    case_dir, cnote = _case_for_report(src, case_arg)
    if case_arg and cnote == "missing":
        print("[ERR] case 目录不存在：%s" % os.path.abspath(case_arg))
        return 2
    text = open(src, encoding="utf-8", errors="replace").read()
    bad = _check_report(text, case_dir=case_dir)
    for b in bad:
        print("[缺] " + b)
    if case_dir:
        refs, missing = _reconcile_report_ids(text, case_dir)
        if missing:
            print("[FAIL] ID 对账：%d 个引用里有 %d 个在 %s/facts.jsonl 找不到：%s"
                  % (len(refs), len(missing), case_dir, "、".join(missing)))
        else:
            print("[report] ID 对账通过：%d 个 E-/C-/F- ID 全部存在于 %s/facts.jsonl"
                  % (len(refs), case_dir))
    else:
        print("[report] 未做 ID 对账（不是案件报告）：%s 不在 Tool/cases/<case>/ 下，"
              "且未给 --case；本次只做五段格式检查" % src)
    print("[PASS] 报告五段齐全" if not bad else "[FAIL] 报告不合格（%d 项）" % len(bad))
    return 0 if not bad else 1


def _check_report(text, case_dir=None):
    """报告校验（2026-10-25 外部评审 3.3：原来只查标题存在，"空内容"能绕过）。

    现在要求：
      ① 五段标题都在；
      ② 每段标题下至少 2 行非空内容；
      ③ 结论段 ≤3 行；
      ④ "已确认"段至少出现 1 个证据/结论 ID（E-/C-/F-）；
      ⑤ 出现禁用措辞（应该可以/大概能/通常没问题）即不合格；
      ⑥ 凭据扫描（PM-SPEC §11）：命中私钥块 / AK / 明文口令赋值 / Bearer 令牌即不合格。
    ⑦ P0-4a：给了案件目录（case_dir）时，每个 E-/C-/F- ID 必须存在于该案 facts.jsonl；
       有 target_files 时，复查段还要提到目标哈希前缀或 resume 命令。
    不传 case_dir（模板/孤立报告）= 只做 ①–⑥，不做 ⑦（不误伤模板）。
    """
    import re as _re
    bad = []
    lines = text.splitlines()
    # ⑥ 先扫凭据（写进报告就等于泄露，优先级高于分段格式）；不回显命中内容，避免二次泄露。
    for _n, _l in enumerate(lines, 1):
        for _rule, _rx in CRED_RULES:
            if _rx.search(_l):
                bad.append("第 %d 行命中凭据扫描「%s」：报告里不许出现明文凭据，"
                           "改成 [REDACTED]（最多留前 6 位 + 指纹/哈希 前 8 位）" % (_n, _rule))
                break
    idx = {}
    for i, l in enumerate(lines):
        for sec in SECTIONS:
            if l.strip().startswith("#") and sec in l and sec not in idx:
                idx[sec] = i
    for sec in SECTIONS:
        if sec not in idx:
            bad.append("缺段：" + sec)
    # ⑦ ID 对账：只有案件报告才做（模板/孤立报告不误伤）
    if case_dir:
        refs, missing = _reconcile_report_ids(text, case_dir)
        if missing:
            bad.append("ID 对账失败：报告引用了 facts.jsonl 里不存在的 ID：%s（已核对 %d 个）—— "
                       "要么在账本里补这条结论，要么把报告改成真实存在的 ID"
                       % ("、".join(missing), len(refs)))
    if bad:
        return bad
    order = sorted(idx.items(), key=lambda kv: kv[1])
    for n, (sec, i) in enumerate(order):
        end_i = order[n + 1][1] if n + 1 < len(order) else len(lines)
        body = [x for x in lines[i + 1:end_i] if x.strip() and not x.strip().startswith("#")]
        if len(body) < 2:
            bad.append(sec + " 段内容过少（" + str(len(body)) + " 行，至少 2 行）")
        if sec == "结论" and len(body) > 3:
            bad.append("结论段 " + str(len(body)) + " 行（要求 <=3 行）")
        if sec == "已确认" and not _re.search(r"[ECF]-2[0-9]{3,}|[ECF]-[0-9]{2,}", chr(10).join(body)):
            bad.append("已确认段没有证据/结论 ID（E-xx / C-xx / F-xx）")
        if sec == "复查" and case_dir:
            prob = _recheck_section_problem(body, case_dir)
            if prob:
                bad.append(prob)
    for w in ("应该可以", "大概能", "通常没问题"):
        if w in text:
            bad.append("出现禁用措辞「" + w + "」")
    return bad

def _self_test():
    checks = 0
    try:
        g = {"id": "G1", "missing": "有效卡密", "repairable": "no", "delta": -0.45}
        assert _blocking_gaps([g]) == [g]; checks += 1
        assert _depends({"needs": "G1"}, g); checks += 1
        assert _mentions("缺 G1 导致不可赢", g); checks += 1
        assert len(now()) >= 19; checks += 1
        # --target 归一化：URL 原样，本地路径绝对化
        assert store_target("https://example.com/a?b=1") == "https://example.com/a?b=1"; checks += 1
        assert store_target("HTTP://Example.com") == "HTTP://Example.com"; checks += 1
        assert store_target("") == ""; checks += 1
        assert store_target("rel/x.bin") == os.path.abspath("rel/x.bin"); checks += 1
        # 租约（P1-2）：过期判据 = now - heartbeat_at > ttl_sec
        fresh = {"ttl_sec": 3600, "heartbeat_at": now()}
        assert _lease_status(fresh)[0] is False; checks += 1
        old_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - 7200))
        assert _lease_status({"ttl_sec": 3600, "heartbeat_at": old_iso})[0] is True; checks += 1
        assert _lease_status({"ttl_sec": 3600, "heartbeat_at": "not-a-time"})[0] is True; checks += 1
        assert _ts_epoch("2026-01-01T00:00:00") is not None; checks += 1
        assert _session_id().strip() != ""; checks += 1
        # 阶段产物闸（P2-1）：判据看**内容**不看存在（治「2 分钟造假过关」）
        assert STAGES[0] == "intake" and STAGE_NEXT["0a"] == "0b"; checks += 1
        assert STAGE_ARTIFACTS["0a"][0][0] == "report/triage.md"; checks += 1
        assert [r for r, _c, _h in STAGE_ARTIFACTS["1"]] == \
            ["capture/login.json", "capture/run.json"]; checks += 1
        tmp = tempfile.mkdtemp(prefix="cs-selftest-")
        try:
            # 0a：400 字节垃圾（无六字段名）必须不过；补全字段名才过
            p = os.path.join(tmp, "triage.md")
            with open(p, "w", encoding="utf-8") as f:
                f.write("x" * 400)
            assert _chk_triage(tmp, p); checks += 1
            with open(p, "w", encoding="utf-8") as f:
                f.write("x" * 400 + "\n" + " ".join(TRIAGE_FIELDS) + "\n")
            assert _chk_triage(tmp, p) == []; checks += 1
            # 0b：≥600B + `## ` ≥3 + facts/证据
            p2 = os.path.join(tmp, "static.md")
            with open(p2, "w", encoding="utf-8") as f:
                f.write("y" * 700 + "\n## a\n## b\n## c\n证据\n")
            assert _chk_static(tmp, p2) == []; checks += 1
            with open(p2, "w", encoding="utf-8") as f:
                f.write("y" * 700)
            assert _chk_static(tmp, p2); checks += 1
            # 1：device_id 空串不算
            p3 = os.path.join(tmp, "login.json")
            with open(p3, "w", encoding="utf-8") as f:
                json.dump({"device_id": ""}, f)
            assert _chk_login(tmp, p3); checks += 1
            with open(p3, "w", encoding="utf-8") as f:
                json.dump({"device_id": "abc-123"}, f)
            assert _chk_login(tmp, p3) == []; checks += 1
            # 1（P2-5 新增分支）：无登录目标的「运行类」产物 capture/run.json
            case1 = os.path.join(tmp, "case1")
            os.makedirs(os.path.join(case1, "capture"), exist_ok=True)
            run_json = os.path.join(case1, "capture", "run.json")
            login_json = os.path.join(case1, "capture", "login.json")
            # 正例：四个键齐 → 通过
            with open(run_json, "w", encoding="utf-8") as f:
                json.dump({"cmd": "./crackme --serial 1234", "exit": 0,
                           "stdout_head": "PASS serial ok",
                           "expect": "出现 PASS 即通过"}, f)
            assert _chk_run(case1, run_json) == []; checks += 1
            # 只在 run.json 时：阶段 1 二选一必须走「运行类」
            assert _any_of_stage(case1, "1", {})[0] == "运行类"; checks += 1
            # 反例：缺 expect → 必红且点名 expect
            with open(run_json, "w", encoding="utf-8") as f:
                json.dump({"cmd": "x", "exit": 0, "stdout_head": "ok"}, f)
            lack = _chk_run(case1, run_json)
            assert lack and any("expect" in x for x in lack); checks += 1
            assert _any_of_stage(case1, "1", {})[0] is None; checks += 1
            # 反例：两个文件都不在 → 红，且同时列出两种补齐方式
            os.remove(run_json)
            assert set(os.listdir(os.path.join(case1, "capture"))) == set(); checks += 1
            fixes = "\n".join(_any_of_stage(case1, "1", {})[3])
            assert "capture/login.json" in fixes and "capture/run.json" in fixes; checks += 1
            # 两个都在 → 凭据类优先，并注明 run.json 已忽略
            with open(run_json, "w", encoding="utf-8") as f:
                json.dump({"cmd": "a", "exit": 0, "stdout_head": "b", "expect": "c"}, f)
            with open(login_json, "w", encoding="utf-8") as f:
                json.dump({"device_id": "dev-1"}, f)
            both = _any_of_stage(case1, "1", {})
            assert both[0] == "凭据类" and both[1] == "capture/login.json"; checks += 1
            assert any("run.json" in n and "已忽略" in n for n in both[2]); checks += 1
            os.remove(login_json)
            # 运行类只认 int exit：字符串 / bool 都不算
            with open(run_json, "w", encoding="utf-8") as f:
                json.dump({"cmd": "a", "exit": "0", "stdout_head": "b", "expect": "c"}, f)
            assert _chk_run(case1, run_json); checks += 1
            # 2：只有 RVA 不算有 VA（子串假命中）
            p4 = os.path.join(tmp, "dynamic.md")
            with open(p4, "w", encoding="utf-8") as f:
                f.write("z" * 700 + "\nRVA 基址\n")
            assert _chk_dynamic(tmp, p4); checks += 1
            with open(p4, "w", encoding="utf-8") as f:
                f.write("z" * 700 + "\nRVA VA 基址\n")
            assert _chk_dynamic(tmp, p4) == []; checks += 1
            # 3：MANIFEST 哈希必须对得上真实文件
            art = os.path.join(tmp, "artifacts")
            os.makedirs(art, exist_ok=True)
            blob = os.path.join(tmp, "a.bin")
            with open(blob, "wb") as f:
                f.write(b"hello")
            p5 = os.path.join(art, "MANIFEST.sha256")
            with open(p5, "w", encoding="utf-8") as f:
                f.write("0" * 64 + "  a.bin\n")
            assert _chk_manifest(tmp, p5); checks += 1
            with open(p5, "w", encoding="utf-8") as f:
                f.write(_sha256_file(blob) + "  a.bin\n")
            assert _chk_manifest(tmp, p5) == []; checks += 1
            # 4：final 还得 state.verdict 非空
            p6 = os.path.join(tmp, "final.md")
            with open(p6, "w", encoding="utf-8") as f:
                f.write("验收 功能 " + "w" * 300)
            assert _chk_final(tmp, p6, {"verdict": "部分可赢"}) == []; checks += 1
            assert _chk_final(tmp, p6, {"verdict": ""}); checks += 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        # 第 2 轮评审：证据必须可重放（纯文本一律拒）
        import io as _io
        import contextlib as _ctx

        def _rej(fn):
            """断言 fn() 以 rc=2 + evidence-* 结构拒绝（真写 SystemExit）。"""
            buf = _io.StringIO()
            try:
                with _ctx.redirect_stdout(buf):
                    fn()
            except SystemExit as e:
                return e.code == 2 and "evidence-" in buf.getvalue()
            return False

        tmp3 = tempfile.mkdtemp(prefix="cs-ev-")
        try:
            with open(os.path.join(tmp3, "facts.jsonl"), "w", encoding="utf-8") as f:
                f.write(json.dumps({"id": "C-001", "claim": "x", "status": "hypothesis"},
                                   ensure_ascii=False) + "\n")
            # 纯文本 → 拒
            assert _rej(lambda: require_evidence("看过了", tmp3)); checks += 1
            assert _rej(lambda: require_evidence("已确认", tmp3)); checks += 1
            assert _rej(lambda: require_evidence("分析完成", tmp3)); checks += 1
            # 命令 + 产物 → 收；命令但没产物描述 → 拒
            cmd = "python Tool/scripts/preflight.py --fast -> x.json rc=0"
            assert require_evidence(cmd, tmp3) == cmd; checks += 1
            assert _rej(lambda: require_evidence("bash run.sh", tmp3)); checks += 1
            # 哈希（64 hex / sha256:<hex>）→ 收
            assert require_evidence("a" * 64, tmp3); checks += 1
            assert require_evidence("sha256:" + "b" * 64, tmp3); checks += 1
            # 账本编号：存在收 / 不存在拒（要读账本，不能崩）
            assert require_evidence("见 C-001 的实测", tmp3); checks += 1
            assert _rej(lambda: require_evidence("见 C-999", tmp3)); checks += 1
            # 路径：存在收 / 不存在拒（原行为保留）
            with open(os.path.join(tmp3, "run.log"), "w", encoding="utf-8") as f:
                f.write("x")
            assert require_evidence("run.log", tmp3); checks += 1
            assert _rej(lambda: require_evidence("ghost.json", tmp3)); checks += 1
            # 文件名里带 ID 但文件真实存在 → 按路径收（存在优先于「账本编号」分支）
            os.makedirs(os.path.join(tmp3, "artifacts"), exist_ok=True)
            with open(os.path.join(tmp3, "artifacts", "E-999-notes.md"), "w", encoding="utf-8") as f:
                f.write("x")
            assert require_evidence(os.path.join(tmp3, "artifacts", "E-999-notes.md"), tmp3); checks += 1
            # 建案指纹：存在 → sha256+size；未就位 → sha256=None + note（不报错）
            fp = _fingerprint_target(os.path.join(tmp3, "run.log"))
            assert len(fp.get("sha256") or "") == 64 and fp.get("size") == 1; checks += 1
            fp2 = _fingerprint_target(os.path.join(tmp3, "nope.bin"))
            assert fp2.get("sha256") is None and "目标未就位" in (fp2.get("note") or ""); checks += 1
        finally:
            shutil.rmtree(tmp3, ignore_errors=True)
        # 进阶闸（P2-4 缝1）：`stage --set` 不许静默跳阶
        tmp2 = tempfile.mkdtemp(prefix="cs-adv-")
        try:
            # ① intake → 0a 豁免（还没产物可查）
            assert _advance_problems(tmp2, "intake", "0a", {"stage": "intake"}) == []; checks += 1
            # ② 回退不查（回退不是进阶）
            assert _advance_problems(tmp2, "4", "0a", {"stage": "4"}) == []; checks += 1
            # ③ 新阶段 + 空盘：必须拦，且点名 0a / 0b
            probs = _advance_problems(tmp2, "intake", "2", {"stage": "intake"})
            assert probs and {s for s, _ in probs} >= {"0a", "0b"}; checks += 1
            # ★ P0-3b：进阶段 1 及以后必须有 scope.md 且授权来源已记录（四选一）
            assert _scope_problems(tmp2); checks += 1
            with open(os.path.join(tmp2, "scope.md"), "w", encoding="utf-8") as f:
                f.write("- 目标：x\n- 授权来源：本人自有 / 书面授权 / 公开靶场 / 开源（选一，写清楚）\n")
            assert _scope_problems(tmp2); checks += 1          # 模板未改 → 红
            with open(os.path.join(tmp2, "scope.md"), "w", encoding="utf-8") as f:
                f.write("- 目标：x\n- 授权来源：公开靶场（HTB 自有账号）\n")
            # 第 2 轮评审：光四选一不够 —— 必须有客户原话
            assert _scope_problems(tmp2); checks += 1          # 缺「客户原话」→ 红
            with open(os.path.join(tmp2, "scope.md"), "w", encoding="utf-8") as f:
                f.write("- 目标：x\n- 授权来源：公开靶场（HTB 自有账号）\n"
                        "- 客户原话：<粘贴客户关于授权的那句话>\n")
            assert _scope_problems(tmp2); checks += 1          # 模板占位 → 红
            with open(os.path.join(tmp2, "scope.md"), "w", encoding="utf-8") as f:
                f.write("- 目标：x\n- 授权来源：公开靶场（HTB 自有账号）\n"
                        "- 客户原话：同意\n")
            assert _scope_problems(tmp2); checks += 1          # 太短（<6）→ 红
            with open(os.path.join(tmp2, "scope.md"), "w", encoding="utf-8") as f:
                f.write("- 目标：x\n- 授权来源：公开靶场（HTB 自有账号）\n"
                        "- 客户原话：这个靶场是我自己的账号，随便打。\n")
            assert _scope_problems(tmp2) == []; checks += 1    # 四选一 + 客户原话 → 绿
            # ④ 补齐 triage.md（按 report/ 布局）后：0a → 0b 放行
            os.makedirs(os.path.join(tmp2, "report"), exist_ok=True)
            tp = os.path.join(tmp2, "report", "triage.md")
            with open(tp, "w", encoding="utf-8") as f:
                f.write("x" * 400 + "\n" + " ".join(TRIAGE_FIELDS) + "\n")
            assert _advance_problems(tmp2, "0a", "0b", {"stage": "0a"}) == []; checks += 1
            # ⑤ 复位/复核：target 在 stage_history 里到达过 → 产物闸不重查（重放负例复位走这条）
            #   但 scope 不受豁免（P0-3b）：刚才已写合法 scope，这里才放行。
            st_hist = {"stage": "0a", "stage_history": [{"stage": "4", "from": "3"}]}
            assert _advance_problems(tmp2, "0a", "4", st_hist) == []; checks += 1
            assert _max_stage_reached(st_hist) == _stage_index("4"); checks += 1
            # 复位也绕不过 scope：移除 scope.md 后同样的复位必须被拦住（P0-3b）
            os.remove(os.path.join(tmp2, "scope.md"))
            assert _advance_problems(tmp2, "0a", "4", st_hist); checks += 1
        finally:
            shutil.rmtree(tmp2, ignore_errors=True)
        # --force 必须带 --reason
        assert _force_check(True, ""); checks += 1
        assert _force_check(True, "回放测试") is None; checks += 1
        assert _force_check(False, "") is None; checks += 1
        # 缝2：两套词表都收；换算只用于展示
        assert "T4" in TIERS and "M4" in TIERS and "X9" not in TIERS; checks += 1
        assert M_TO_T["M4"] == "T3" and T_TO_M["T2"] == "M2"; checks += 1
        assert tier_view("M2") == "≈ T2" and tier_view("T3") == "≈ M3|M4"; checks += 1
        assert tier_view("X9") == ""; checks += 1
        assert TIER_LEVEL["T2"] == "M3" and TIER_LEVEL["T1"] is None; checks += 1
        # P0-4b：M2 的 repro 结构判据（任一项不满足都必须拒）
        base = {"kind": "repro", "cmd": "echo hi", "expect": "hi", "runs": 2,
                "digests": ["a", "a"], "consistent": True}
        assert _is_complete_repro(base); checks += 1
        for k, v in (("cmd", ""), ("expect", ""), ("runs", 1),
                     ("digests", ["a"]), ("consistent", False), ("kind", "claim")):
            r = dict(base); r[k] = v
            assert not _is_complete_repro(r); checks += 1
        # P0-4：降级通知是客户话，不出现 M-/L- 内部代号
        _dn = _downgrade_notice("M2", "M1", "缺关键证据")
        assert "能改到能用" in _dn and "只能看懂结构" in _dn and "M2" not in _dn; checks += 1
        print(json.dumps({"ok": True, "checks": checks}, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "blocked_at": "self-test",
                          "reason": "%s: %s" % (type(exc).__name__, exc)}, ensure_ascii=True))
        return 2



# ─────────────────── 对话内 A/B/C 问人（唯一允许的问人方式） ───────────────────
#
# 为什么不弹窗：弹窗（ask_user_question 那类）有三个问题 ——
#   ① 选项只能 2–4 个、每项 ≤60 字，四要素长卡塞不进去；
#   ② 它是一等工具调用，会把「等人」变成「一次工具往返」，上下文里留一堆结构化噪声；
#   ③ 用户明确要求：就用对话框里列 A/B/C，他回一个字母。
# 所以：卡写文件（给人复核）+ 正文里列 A/B/C（给人在对话里回）+ state 落 awaiting_human。

def _ask_dir(case):
    d, _ = paths(case)
    p = os.path.join(d, "ask")
    os.makedirs(p, exist_ok=True)
    return p


def cmd_ask(a):
    """发一张对话内 A/B/C 卡，并把案子置为 awaiting_human。"""
    d, _ = paths(a.case)
    if not os.path.isdir(d):
        die("case 目录不存在：%s" % d)
    opts = [x for x in (a.option or []) if x.strip()]
    if len(opts) < 2:
        die("至少要两个选项：--option \"A 你自己双击启动\" --option \"B 我用 explorer 拉起\"")
    lease_guard(a.case)   # 写卡片文件 + state.awaiting_human

    # 选项解析：首字母作 key
    parsed = []
    for o in opts:
        m = re.match(r"^\s*([A-Za-z])[\.、:：)]?\s*(.+)$", o)
        if m:
            parsed.append((m.group(1).upper(), m.group(2).strip()))
        else:
            parsed.append((chr(65 + len(parsed)), o.strip()))

    ts = now().replace(":", "").replace("-", "")[:15]
    lines = ["# 需要你选（对话内回一个字母即可）", "",
             f"- 时间：{now()}",
             f"- 案子：{os.path.basename(d)}",
             f"- 卡在哪：{a.stuck}", "",
             "## 选项", ""]
    for k, v in parsed:
        lines.append(f"- **{k}** {v}")
    if a.monitor:
        lines += ["", "## 我这边正在做什么", "", a.monitor]
    if a.guarantee:
        lines += ["", "## 你操作期间我保证", "", a.guarantee]
    if a.expect:
        lines += ["", "## 我拿到什么", "", a.expect]
    lines += ["", "---", "", f"直接回 `{parsed[0][0]}` / `{parsed[1][0]}` …… 即可。"]

    fp = os.path.join(_ask_dir(a.case), f"{ts}.md")
    with open(fp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    st = load_state(a.case)
    st["awaiting_human"] = {"since": now(), "card": fp, "stuck": a.stuck,
                            "options": {k: v for k, v in parsed}, "ack": None}
    save_state(a.case, st)

    # 给模型的下一个动作：把这段原样贴进对话（不要调弹窗工具）
    print("[ASK] 已生成卡片：%s" % fp)
    print("[ASK] 下面这段**原样贴进对话**（本项目只用对话内选项，不用弹窗工具）：\n")
    print(f"【需要你选】{a.stuck}")
    for k, v in parsed:
        print(f"  {k}  {v}")
    print(f"直接回 {' / '.join(k for k, _ in parsed)}")
    if a.monitor:
        print(f"\n我在做什么：{a.monitor}")
    if a.guarantee:
        print(f"你操作期间我保证：{a.guarantee}")
    if a.expect:
        print(f"我拿到什么：{a.expect}")
    print("\n（回执后执行：python Tool/scripts/case_state.py ack --case %s --ack <字母>）" % a.case)


def cmd_ack(a):
    """记录用户回执，解除 awaiting_human。"""
    lease_guard(a.case)
    st = load_state(a.case)
    aw = st.get("awaiting_human")
    if not aw:
        die("当前没有等待中的卡（awaiting_human 为空）。先 ask。")
    letter = a.ack.strip().upper()[:1]
    opts = aw.get("options") or {}
    if opts and letter not in opts:
        die("回执 %r 不在选项里：%s" % (letter, " / ".join(opts.keys())))
    aw["ack"] = letter
    aw["acked_at"] = now()
    st["awaiting_human"] = aw
    st["next_action"] = "用户选了 %s：%s" % (letter, (opts.get(letter) or "")[:80])
    backend = save_state(a.case, st)
    print("[ACK] 已记录：%s -> %s（%s）" % (letter, opts.get(letter, ""), backend))
    print("[ACK] 现在可以从断点继续，不需要重头再来。")


# ---------------------------------------------------------------- 状态重放（S2-1）
def cmd_replay(a):
    """状态重放 / 迁移 / 压缩：state 不存快照，只由账本 state 行重放。

    --migrate      兼容旧调用（迁移已全部完成，现在只报告残留数量）
    --drop-legacy  删除历史副本（state.json / ai_manifest.json，存在才删）
    --compact      只保留最后一条 state 行（账本瘦身，claim/event 不动）

    为什么：快照与账本行是同一状态的两份副本，两端各自开局就会分叉；
    append-only 账本只多行、不少条，重放结果唯一。
    """
    d, fp = paths(a.case)
    if not os.path.isdir(d):
        die("case 目录不存在：%s" % d)
    if a.migrate or a.drop_legacy or a.compact:
        lease_guard(a.case)
    if a.migrate:
        left = _legacy_files(a.case)
        print("[SKIP] 无需迁移：状态已全在账本里（残留副本 %d 个，用 --drop-legacy 清理）" % len(left))
    if a.drop_legacy:
        left = _legacy_files(a.case)
        for p in left:
            os.remove(p)
            print("[OK] 已删除历史副本：%s" % p)
        if not left:
            print("[SKIP] 没有历史副本可删")
    if a.compact:
        ledger = load_ledger(a.case)
        idxs = [i for i, e in enumerate(ledger) if _entry_kind(e) == LEDGER_STATE_KIND]
        if len(idxs) <= 1:
            print("[SKIP] state 行 %d 条，无需压缩" % len(idxs))
        else:
            keep = idxs[-1]
            out = [e for i, e in enumerate(ledger) if i not in set(idxs) or i == keep]
            _atomic_write_text(fp, "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in out))
            print("[OK] 账本压缩：state 行 %d → 1，总行 %d → %d" % (len(idxs), len(ledger), len(out)))

    ledger = load_ledger(a.case)
    st = load_state(a.case)
    claims = [e for e in ledger if _is_claim(e)]
    states = [e for e in ledger if _entry_kind(e) == LEDGER_STATE_KIND]
    events = [e for e in ledger if _entry_kind(e) == LEDGER_EVENT_KIND]
    other = len(ledger) - len(claims) - len(states) - len(events)
    print("[REPLAY] %s" % fp)
    print("  账本行：%d（claim %d / state %d / event %d / gaps+plan %d）"
          % (len(ledger), len(claims), len(states), len(events), other))
    print("  重放状态：verdict=%s max_level=%s stage=%s depth=%d next=%s"
          % (st.get("verdict"), st.get("max_level"), st.get("stage"),
             len(st.get("depth") or {}), (st.get("next_action") or "")[:40]))
    left = _legacy_files(a.case)
    if left:
        print("  [WARN] 残留历史副本 %d 个：跑 --drop-legacy 收口（%s）"
              % (len(left), ", ".join(os.path.basename(x) for x in left)))
    if getattr(a, "json", False):
        print(json.dumps({"state": st, "ledger": {"total": len(ledger), "claims": len(claims),
                                                    "states": len(states), "events": len(events)}},
                         ensure_ascii=False, indent=2))
    return 0


# ---------------------------------------------------------------- 索引现算（S2-1）
# 血案：Tool/cases/index.json 是第三份副本，gen-case-index.py 还会硬编码 "repro": {}，
# 于是 case.json 50/56 有 repro、index.json 55/55 全空 —— 派生缓存一旦落盘就会分叉。
# 现在索引只在调用时现算：磁盘上不存在可漂移的副本。
CASE_FIELDS = ("id", "domain", "target_type", "evidence_kind", "protection", "authority",
               "goal_level", "outcome", "artifacts", "repro", "lessons", "tags", "refs",
               "updated")
CASE_LIST_FIELDS = ("protection", "lessons", "tags", "refs")
EVIDENCE_KIND_OK = ("fixture", "real", "self-built", "historical")
OUTCOME_OK = ("success", "partial", "blocked", "confirmed")  # confirmed = 历史同义词（success）


def cases_root():
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cases")


def _norm_case(raw, dirname):
    entry = {}
    for k in CASE_FIELDS:
        v = raw.get(k)
        if k in CASE_LIST_FIELDS:
            entry[k] = [x for x in v if isinstance(x, str)] if isinstance(v, list) else []
        elif k == "artifacts":
            entry[k] = [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []
        elif k == "repro":
            entry[k] = v if isinstance(v, dict) else {}
        else:
            entry[k] = v if isinstance(v, str) else ""
    if not entry["id"]:
        entry["id"] = dirname
    entry["dir"] = dirname
    return entry


def scan_cases(root=None):
    """现算案例索引。返回 (entries, problems)；problems 非空 = 索引本身不可信。"""
    root = root or cases_root()
    entries, problems = [], []
    if not os.path.isdir(root):
        return entries, ["案例目录不存在：%s" % root]
    seen = {}
    for name in sorted(os.listdir(root)):
        d = os.path.join(root, name)
        if not os.path.isdir(d) or name.startswith("."):
            continue
        cj = os.path.join(d, "case.json")
        if not os.path.isfile(cj):
            # `_archive` / `_templates` 这类容器目录不算案例；其他目录缺 case.json 就是漏登记
            if not name.startswith("_"):
                problems.append("%s：缺 case.json" % name)
            continue
        try:
            with open(cj, encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as e:
            problems.append("%s：case.json 解析失败（%s）" % (name, str(e)[:60]))
            continue
        if not isinstance(raw, dict):
            problems.append("%s：case.json 顶层不是对象" % name)
            continue
        entry = _norm_case(raw, name)
        if entry["id"] != name:
            problems.append("%s：case.json 的 id=%r 与目录名不一致" % (name, entry["id"]))
        if entry["evidence_kind"] and entry["evidence_kind"] not in EVIDENCE_KIND_OK:
            problems.append("%s：evidence_kind=%r 不在 %s"
                            % (name, entry["evidence_kind"], "|".join(EVIDENCE_KIND_OK)))
        if entry["outcome"] and entry["outcome"] not in OUTCOME_OK:
            problems.append("%s：outcome=%r 不在 %s"
                            % (name, entry["outcome"], "|".join(OUTCOME_OK)))
        if entry["id"] in seen:
            problems.append("id 重复：%s（%s 与 %s）" % (entry["id"], seen[entry["id"]], name))
        seen[entry["id"]] = name
        entries.append(entry)
    return entries, problems


def cmd_index(a):
    """案例索引：现算（Tool/cases/*/case.json 是唯一事实来源，磁盘上不再存 index.json）。"""
    root = getattr(a, "root", "") or cases_root()
    entries, problems = scan_cases(root)
    as_json = getattr(a, "json", False)
    if as_json:
        # JSON 模式只输出一个对象（把 problems 放进对象里，不在后面再追加人读行）
        print(json.dumps({"schema": 1, "root": root, "case_count": len(entries),
                          "problems": problems, "cases": entries},
                         ensure_ascii=False, indent=2))
        return 1 if problems else 0
    print("[INDEX] %s  案例 %d 个（现算，无缓存副本）" % (root, len(entries)))
    if getattr(a, "stats", False):
        def _tally(field):
            m = {}
            for e in entries:
                m[e.get(field) or "(空)"] = m.get(e.get(field) or "(空)", 0) + 1
            return "，".join("%s=%d" % (k, v) for k, v in sorted(m.items()))
        for f in ("domain", "evidence_kind", "outcome", "goal_level"):
            print("  %-14s %s" % (f, _tally(f)))
    if not getattr(a, "check", False) and not getattr(a, "stats", False):
        for e in entries:
            print("  %-22s %-16s %-10s %-5s %s" % (
                e["id"], e["domain"][:16], e["evidence_kind"], e["goal_level"],
                e["outcome"]))
    if problems:
        print("[FAIL] 索引不一致 %d 处：" % len(problems))
        for p in problems:
            print("   - " + p)
        return 1
    if getattr(a, "check", False):
        print("[PASS] 案例索引与磁盘一致（%d 个 case.json）" % len(entries))
    return 0


# ---------------------------------------------------------------- 证据强度聚合（S2-4）
# 血案：旧聚合把「没写 confidence」的 claim 当已证，于是一个空 case 也能签成 recorded。
# 现在判据写死在这里，不接受任何包/脚本自行放宽。
BAD_STATUSES = ("fail", "unknown", "unsupported", "truncated", "skipped")
WEAK_CONFIDENCE = ("inferred", "unknown")
STRONG_CONFIDENCE = ("observed", "derived")


def verify_case(case):
    """单案聚合：返回 {verdict: pass|fail|unknown, reasons, counts}。"""
    facts = load_facts(case)
    st = load_state(case)
    counts = {k: 0 for k in CONFIDENCE_STATES}
    bad, stale, weak, noauth = {}, [], [], []
    for f in facts:
        conf = _norm_confidence(f.get("confidence"))
        counts[conf] = counts.get(conf, 0) + 1
        status = str(f.get("status") or "").strip().lower()
        if status in BAD_STATUSES:
            bad[status] = bad.get(status, 0) + 1
        if status == "stale":
            stale.append(str(f.get("id")))
        if status == "proven":
            if conf in WEAK_CONFIDENCE:
                weak.append("%s(%s)" % (f.get("id"), conf))
            if str(f.get("authority") or "none").strip().lower() in ("", "none"):
                noauth.append(str(f.get("id")))
    proven = sum(1 for f in facts if str(f.get("status") or "").lower() == "proven")
    strong = sum(1 for f in facts
                 if str(f.get("status") or "").lower() == "proven"
                 and _norm_confidence(f.get("confidence")) in STRONG_CONFIDENCE
                 and str(f.get("authority") or "none").strip().lower() not in ("", "none"))
    fail_reasons, unknown_reasons = [], []
    for k in sorted(bad):
        fail_reasons.append("%s=%d（任一非零即不得 pass）" % (k, bad[k]))
    if stale:
        fail_reasons.append("stale 未复验：" + "、".join(stale))
    if not facts:
        unknown_reasons.append("账本无 claim（facts 为空）→ unknown，不得计 pass")
    elif not proven:
        unknown_reasons.append("没有 proven claim")
    # 弱证据不算 pass 证据，但**不把整案拖成 unknown**：它们被"排除在证据集外"并明示出来。
    # 判据（与 pack.json 的 evidence_contract.pass_forbids_confidence 一致）：
    #   pass = 无 fail 类状态 + ≥1 条 observed/derived 背书；inferred/unknown 的 proven 只进 excluded。
    excluded = weak + noauth
    if not facts:
        unknown_reasons.append("账本无 claim（facts 为空）→ unknown，不得计 pass")
    elif strong == 0:
        unknown_reasons.append("没有 observed/derived 背书（%d 条 claim 全是 inferred/unknown）" % len(facts))
    verdict = "fail" if fail_reasons else ("unknown" if unknown_reasons else "pass")
    return {"case": os.path.basename(os.path.abspath(case)), "verdict": verdict,
            "claims": len(facts), "proven": proven, "strong": strong,
            "confidence": counts, "bad": bad, "stale": stale, "excluded": excluded,
            "reasons": fail_reasons + unknown_reasons,
            "state_verdict": st.get("verdict"), "stage": st.get("stage")}


def cmd_verify(a):
    """证据强度聚合：unknown 永不计 pass。

    判据（写死，不许各包自行放宽）：
      * fail / unknown / unsupported / truncated / skipped 任一非零 → 整案 fail
      * 有 stale 未复验 → fail
      * 无 claim / 无 proven / proven 的 confidence ∈ {inferred,unknown} 或 authority=none → unknown
      * 全部 proven 且 confidence ∈ {observed,derived} 且 authority 非 none → pass
    """
    if getattr(a, "all", False):
        root = cases_root()
        targets = []
        if os.path.isdir(root):
            for name in sorted(os.listdir(root)):
                d = os.path.join(root, name)
                if not os.path.isdir(d) or name.startswith("."):
                    continue
                if not os.path.isfile(os.path.join(d, "case.json")):
                    continue
                targets.append(d)
    else:
        if not (getattr(a, "case", "") or "").strip():
            die("verify 需要 --case <目录> 或 --all")
        targets = [a.case]
    results = [verify_case(t) for t in targets]
    if getattr(a, "json", False):
        print(json.dumps({"schema": "seep.verify/1", "results": results},
                         ensure_ascii=False, indent=2))
    else:
        for r in results:
            mark = {"pass": "PASS", "fail": "FAIL", "unknown": "UNKNOWN"}[r["verdict"]]
            print("[%s] %-22s claim %d（proven %d / 背书 %d）conf=%s state=%s stage=%s" % (
                mark, r["case"], r["claims"], r["proven"], r.get("strong", 0),
                "/".join("%s:%d" % (k, v) for k, v in r["confidence"].items() if v),
                r["state_verdict"], r["stage"]))
            for why in r["reasons"]:
                print("   - " + why)
            if r.get("excluded"):
                print("   - 排除在证据集外（不计 pass）：" + "、".join(r["excluded"][:8])
                      + ("…" if len(r["excluded"]) > 8 else ""))
        n_pass = sum(1 for r in results if r["verdict"] == "pass")
        n_fail = sum(1 for r in results if r["verdict"] == "fail")
        n_unk = sum(1 for r in results if r["verdict"] == "unknown")
        print("[VERIFY] %d 个案子：pass %d / fail %d / unknown %d（unknown 永不计 pass）"
              % (len(results), n_pass, n_fail, n_unk))
    return 0 if all(r["verdict"] == "pass" for r in results) else 1


def main():
    if "--self-test" in sys.argv[1:]:
        sys.exit(_self_test())
    ap = argparse.ArgumentParser(description="案子事实账 / 深度门 / 可行性裁定 / 出口闸")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init"); p.add_argument("--case", required=True)
    p.add_argument("--target", default=""); p.add_argument("--force", action="store_true")
    p.add_argument("--evidence-kind", dest="evidence_kind", default="real",
                   choices=["fixture", "real", "self-built", "historical"],
                   help="案例真实性（写进 case.json，preflight 按此分档）")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("lock", help="拿写权租约（同一会话重复 lock = 续约）")
    p.add_argument("--case", required=True)
    p.add_argument("--ttl", type=int, default=LEASE_TTL_DEFAULT,
                   help="租约时长秒（默认 %d）：now - heartbeat_at > ttl 即视为过期" % LEASE_TTL_DEFAULT)
    p.add_argument("--force", action="store_true", help="别人持有效锁时强制接管（打印 TAKEOVER）")
    p.set_defaults(func=cmd_lock)

    p = sub.add_parser("unlock", help="释放租约（不是自己持有且无 --force 则拒绝）")
    p.add_argument("--case", required=True)
    p.add_argument("--force", action="store_true", help="强行释放别人的锁（或过期锁）")
    p.set_defaults(func=cmd_unlock)

    p = sub.add_parser("who", help="打印当前持锁者；无锁打印 NO_LEASE（rc=0）")
    p.add_argument("--case", required=True)
    p.set_defaults(func=cmd_who)

    p = sub.add_parser("claim"); p.add_argument("--case", required=True)
    p.add_argument("--id", required=True); p.add_argument("--text", required=True)
    p.add_argument("--status", default="hypothesis"); p.add_argument("--evidence", default="")
    p.add_argument("--by", default="", help="status=refuted 时必填：谁推翻了它")
    p.add_argument("--how", default=""); p.add_argument("--ttl", default="")
    p.add_argument("--confidence", default="", choices=[""] + list(CONFIDENCE_STATES),
                   help="证据强度（S2-4）：observed/derived/inferred/unknown；缺省=unknown，永不计 pass")
    p.add_argument("--authority", default="", choices=[""] + list(AUTHORITY_STATES),
                   help="证据权威：shipped-artifact/controlled-replay/external-service/reported/none")
    p.set_defaults(func=cmd_claim)

    p = sub.add_parser("prove"); p.add_argument("--case", required=True)
    p.add_argument("--id", required=True); p.add_argument("--evidence", required=True)
    p.add_argument("--confidence", default="", choices=[""] + list(CONFIDENCE_STATES),
                   help="必须显式声明才算数（observed/derived）")
    p.add_argument("--authority", default="", choices=[""] + list(AUTHORITY_STATES),
                   help="证据权威（不接受 none 当已证）")
    p.set_defaults(func=cmd_prove)

    p = sub.add_parser("refute"); p.add_argument("--case", required=True)
    p.add_argument("--id", required=True); p.add_argument("--by", required=True)
    p.set_defaults(func=cmd_refute)

    p = sub.add_parser("stale", help="TTL 失效：把所有 proven 降为 stale（保留证据）")
    p.add_argument("--case", required=True)
    p.add_argument("--reason", default="", help="为何失效，如『换 exe:sha256 变了』")
    p.set_defaults(func=cmd_stale)

    p = sub.add_parser("gaps", help="缺件经济学：登记不可补/可补缺件与概率折损")
    p.add_argument("--case", required=True)
    p.add_argument("--add", action="store_true", help="登记一条缺件")
    p.add_argument("--list", dest="list_mode", action="store_true", help="列出缺件台账")
    p.add_argument("--id", default=""); p.add_argument("--missing", default="")
    p.add_argument("--impact", default="")
    p.add_argument("--repairable", default="", help="yes / no / partial")
    p.add_argument("--delta", default="0", help="概率折损（负数），如 -0.45")
    p.add_argument("--alt", default="", help="替代方案，用 | 分隔")
    p.set_defaults(func=cmd_gaps)

    p = sub.add_parser("plan", help="路线菜单（L0–L4 + 成功率 + 工时 + 失败判据）")
    p.add_argument("--case", required=True)
    p.add_argument("--level", default="", help="L0–L4")
    p.add_argument("--route", "--add", dest="route", default="", help="路线名（--add 亦可）")
    p.add_argument("--p", "--prob", "--success", dest="p", type=float, default=None, help="成功率先验 0~1（--prob 亦可）")
    p.add_argument("--hours", "--eta", dest="hours", default=""); p.add_argument("--needs", default="")
    p.add_argument("--fail", dest="fail_criteria", default="", help="失败判据（什么现象就停手）")
    p.add_argument("--from-advise", action="store_true", help="把 advise 的可行路线一次性导入")
    p.add_argument("--form", default="", help="配合 --from-advise：指定形态 id")
    p.add_argument("--list", dest="list_mode", action="store_true")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("choose", help="从菜单选定一条路线，写 state.goal_level")
    p.add_argument("--case", required=True)
    p.add_argument("--level", required=True); p.add_argument("--route", required=True)
    p.set_defaults(func=cmd_choose)

    p = sub.add_parser("advise", help="按仪器/策略矩阵 + gaps 给建议菜单（不写盘）")
    p.add_argument("--case", required=True)
    p.add_argument("--form", default="", help="strategy.json 里的形态 id（如 pe-shelled）")
    p.set_defaults(func=cmd_advise)

    p = sub.add_parser("depth"); p.add_argument("--case", required=True)
    p.add_argument("--level", "--set", dest="level", required=True, help="D0–D7（--set 亦可）")
    p.add_argument("--result", default="", help="pass / fail / na；配 --prove 时可省，默认 pass")
    p.add_argument("--note", "--prove", dest="note", default="", help="备注/证据说明（--prove 亦可，表示这条已 pass）")
    p.set_defaults(func=cmd_depth)

    p = sub.add_parser("instrument"); p.add_argument("--case", required=True)
    p.add_argument("--name", required=True); p.add_argument("--status", required=True)
    p.add_argument("--launch", default=""); p.add_argument("--note", default="")
    p.set_defaults(func=cmd_instrument)

    p = sub.add_parser("verdict"); p.add_argument("--case", required=True)
    p.add_argument("--value", required=True)
    p.add_argument("--tier", default="",
                   help="后端档位 / 交付上限（两套词表都收，原样存）："
                        "T1|T2|T3|T4（后端档位，05-backend-rebuild）或 M1|M2|M3|M4（交付上限）。"
                        "档位规则：不可赢恒 M1；T1→裁定基准（可赢 M3/部分可赢 M2）；T2→M3；T3/T4→M4。"
                        "展示用换算（不改输入值）：M1↔T1 / M2↔T2 / M3|M4↔T3")
    p.add_argument("--max-level", default="")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_verdict)

    p = sub.add_parser("events", help="事件账：工具动作流水（seep-events 扩展自动写；缺失不算错误，rc=0）")
    p.add_argument("--case", required=True)
    p.add_argument("--tail", type=int, default=10, help="只显示最近 N 条（默认 10）")
    p.add_argument("--json", action="store_true", help="额外输出 JSON（机器可读）")
    p.set_defaults(func=cmd_events)

    p = sub.add_parser("gate"); p.add_argument("--case", required=True)
    p.add_argument("--strict", action="store_true", help="连 hypothesis 也不许留")
    p.add_argument("--stage", default="",
                   help="阶段产物闸：intake|0a|0b|1|2|3|4|done（按文件内容判，不带则行为不变）")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("stage", help="阶段机：--set <阶段>（先过进阶产物闸）+ --reason 记 forced；--show 看当前/下一阶段/缺什么")
    p.add_argument("--case", required=True)
    p.add_argument("--set", dest="set", default="", help="/".join(STAGES))
    p.add_argument("--show", action="store_true", help="打印当前阶段 + 下一阶段 + 还缺什么")
    p.add_argument("--force", action="store_true",
                   help="跳过进阶产物闸（必须配 --reason；会在 state.stage_history 记 forced:true + reason + skipped）")
    p.add_argument("--reason", default="", help="配合 --force：为什么跳过产物闸")
    p.set_defaults(func=cmd_stage)

    p = sub.add_parser("answer")
    p.add_argument("--template", action="store_true"); p.add_argument("--check", action="store_true")
    p.add_argument("--file", default=""); p.add_argument("--selftest", action="store_true")
    # --case 只影响标记（~/.seep/answer-pass.json）：给了就把首答绑到该案登记的目标
    p.add_argument("--case", default="",
                   help="把首答标记绑到这个案件目录（写入其 case.json 登记的目标哈希）")
    p.set_defaults(func=cmd_answer)
    p = sub.add_parser("block")
    p.add_argument("--code", default=""); p.add_argument("--case", default="")
    p.add_argument("--detail", default=""); p.add_argument("--why", default=""); p.add_argument("--got", default="")
    p.add_argument("--list", action="store_true"); p.set_defaults(func=cmd_block)
    p = sub.add_parser("repro")
    p.add_argument("--case", default=""); p.add_argument("--id", default="")
    p.add_argument("--cmd", default=""); p.add_argument("--expect", default="")
    p.add_argument("--runs", type=int, default=2); p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--also-cmd", dest="also_cmd", default="", help="第二路独立命令（一致则 E3 交叉验证）")
    p.set_defaults(func=cmd_repro)
    p = sub.add_parser("downgrade")
    p.add_argument("--case", required=True); p.add_argument("--to", required=True)
    p.add_argument("--reason", default=None); p.set_defaults(func=cmd_downgrade)
    p = sub.add_parser("report")
    p.add_argument("--file", default=""); p.add_argument("--selftest", action="store_true")
    p.add_argument("--check", action="store_true", help="同默认行为（兼容文档写法）")
    p.add_argument("--case", default="",
                   help="显式指定案件目录：把报告里的 E-/C-/F- ID 对到该案 facts.jsonl"
                        "（不传则按路径是否在 Tool/cases/<case>/ 下自动判定）")
    p.set_defaults(func=cmd_report)
    p = sub.add_parser("recheck")
    p.add_argument("--case", required=True); p.set_defaults(func=cmd_recheck)
    p = sub.add_parser("deliver"); p.add_argument("--case", required=True)
    p.add_argument("--level", required=True); p.add_argument("--evidence", "--ev", dest="evidence", required=True)
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_deliver)

    p = sub.add_parser("ask", help="发一张对话内 A/B/C 卡（唯一允许的问人方式，不用弹窗）")
    p.add_argument("--case", required=True)
    p.add_argument("--stuck", required=True, help="一句话：卡在哪")
    p.add_argument("--option", action="append", help='形如 "A 你自己双击启动目标"；至少两个')
    p.add_argument("--monitor", default="", help="我这边正在监控什么")
    p.add_argument("--guarantee", default="不动鼠标键盘、不改系统设置、不主动联网")
    p.add_argument("--expect", default="", help="我拿到什么")
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("ack", help="记录用户回执（回一个字母），解除 awaiting_human")
    p.add_argument("--case", required=True)
    p.add_argument("--ack", required=True)
    p.set_defaults(func=cmd_ack)

    p = sub.add_parser("replay", help="状态重放：state 不存快照，由账本 state 行重放（--migrate/--drop-legacy/--compact）")
    p.add_argument("--case", required=True)
    p.add_argument("--migrate", action="store_true", help="兼容旧调用：迁移已完成，只报残留数量")
    p.add_argument("--drop-legacy", dest="drop_legacy", action="store_true", help="删除历史副本（state.json / ai_manifest.json）")
    p.add_argument("--compact", action="store_true", help="只保留最后一条 state 行（claim/event 不动）")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("index", help="案例索引：现算（不落 index.json 缓存）")
    p.add_argument("--check", action="store_true", help="索引与磁盘不一致则 rc=1")
    p.add_argument("--stats", action="store_true", help="额外打印领域 / 真实性 / 结论分布")
    p.add_argument("--json", action="store_true")
    p.add_argument("--root", default="", help="案例根目录（缺省 Tool/cases）")
    p.set_defaults(func=cmd_index)

    p = sub.add_parser("verify", help="证据强度聚合：unknown 永不计 pass（fail/unknown/... 任一非零即不得 pass）")
    p.add_argument("--case", default="", help="单案路径（与 --all 二选一）")
    p.add_argument("--all", action="store_true", help="对 Tool/cases/* 全量跑")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("verify-origin",
                       help="重算目标原件 sha256 并与建案时登记的指纹对账（变了/移了就 rc=2）")
    p.add_argument("--case", required=True)
    p.set_defaults(func=cmd_verify_origin)

    p = sub.add_parser("show"); p.add_argument("--case", required=True); p.set_defaults(func=cmd_show)
    p = sub.add_parser("resume"); p.add_argument("--case", required=True); p.set_defaults(func=cmd_resume)
    p = sub.add_parser("handoff")
    p.add_argument("--case"); p.add_argument("--repo", action="store_true")
    p.set_defaults(func=lambda a: cmd_repo_handoff(a) if a.repo else cmd_handoff(a))

    a = ap.parse_args()
    sys.exit(a.func(a) or 0)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
