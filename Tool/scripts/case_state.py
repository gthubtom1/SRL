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
    另（P0-3b 改口径）：进阶段 1 及以后必须先有 scope.md（**边界 / 环境记录**）；
    用户 2026-10-26 口径：**不再要求任何授权字段**（授权来源四选一 / 客户原话一律删掉），
    也不许因为没填授权而拦阶段。该条**不受**豁免③影响（复位也不能绕过边界记录的机检）。
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
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from lib.case_repro import case_locked
from lib import case_ledger as _case_ledger
from lib.case_lifecycle import recovering as case_recovering


def _case_api():
    # gate loads this file through importlib without adding it to sys.modules.
    return SimpleNamespace(**globals())

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
# Repository root is anchored to this source file, never to process cwd.  Several
# case records use repository-relative paths such as
# ``Tool/cases/<case>/target/<file>``; resolving those with ``Path.is_file()``
# directly made verification succeed only when the caller happened to run from
# the repository root.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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

# ── 等级唯一权威：`Tool/config/levels.json`（用户 2026-10-26 决定）──
# 对外只说四句话（只能看懂结构 / 能改到能用 / 能完全自己接管 / 现在做不了）；
# 内部代号（M1–M4 / L1–L3 / T1–T4 / J1–J3）只进账本、stderr 与 facts.jsonl。
# 为什么在运行时读文件、不在代码里再抄一份：四句话有三个读者（deliver/show 的客户话、
# report --check 的禁代号扫描、preflight 的一致性判据），抄三份就会漂三份。
LEVELS_JSON = os.path.join(CONFIG_DIR, "levels.json")
_LEVELS_FALLBACK = {
    "customer": ["只能看懂结构", "能改到能用", "能完全自己接管", "现在做不了"],
    "internal": [("M1", "只能看懂结构", "E1"), ("M2", "能改到能用", "E2"),
                 ("M3", "能完全自己接管", "E3"), ("M4", "能完全自己接管", "E4"),
                 ("L1", "只能看懂结构", "E1"), ("L2", "能改到能用", "E2"),
                 ("L3", "能完全自己接管", "E3"),
                 ("T1", "只能看懂结构", "E1"), ("T2", "能改到能用", "E2"),
                 ("T3", "能完全自己接管", "E3"), ("T4", "能完全自己接管", "E4"),
                 ("J1", "只能看懂结构", "E1"), ("J2", "能改到能用", "E2"),
                 ("J3", "能完全自己接管", "E3")],
}


def load_level_authority():
    """→ (四句 list, [(代号, 客户话, 证据门槛)], {代号: 客户话}, {M 代号: 门槛}, 来源)。

    来源 = "levels.json"（读得到）或 "builtin"（回退内置副本）。回退不会让闸失明，
    但 preflight 的「等级唯一权威」会把 builtin 判红 —— 权威只在那个 JSON 里。
    """
    cust, internal, src = [], [], "builtin"
    try:
        with open(LEVELS_JSON, encoding="utf-8") as f:
            d = json.load(f) or {}
        cust = [str(x.get("sentence") or "") for x in (d.get("customer") or [])
                if str(x.get("sentence") or "")]
        internal = [(str(x.get("code") or "").upper(), str(x.get("customer") or ""),
                     str(x.get("evidence_min") or "").upper())
                    for x in (d.get("internal") or []) if str(x.get("code") or "")]
        if cust and internal:
            src = "levels.json"
        else:
            cust, internal = [], []
    except Exception:  # noqa: BLE001 —— 配置坏了不能连累闸；preflight 会点名
        cust, internal, src = [], [], "builtin"
    if src != "levels.json":
        cust = list(_LEVELS_FALLBACK["customer"])
        internal = list(_LEVELS_FALLBACK["internal"])
    cust_map = {code: sentence for code, sentence, _ev in internal}
    bar = {code: ev for code, _s, ev in internal if code.startswith("M")}
    return cust, internal, cust_map, bar, src


LEVEL_SENTENCES, LEVEL_INTERNAL, _LEVEL_CUSTOMER, _LEVEL_BAR, LEVEL_SOURCE = load_level_authority()
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


def _replace_retry(tmp, path, tries=4):
    """os.replace 在 Windows 上会被瞬间的占用（AV/索引/另一个读句柄）打成 WinError 5。

    重试只是一层耐噪（不是放宽判据）：重试完仍失败就抛出，调用方负责把它变成 rc≠0。
    """
    last = None
    for i in range(tries):
        try:
            os.replace(tmp, path)
            return
        except PermissionError as e:  # noqa: PERF203
            last = e
            time.sleep(0.05 * (i + 1))
    raise last  # type: ignore[misc]


def _atomic_write_text(path, text):
    """原子写文本：tempfile → write → flush+fsync → os.replace。失败清理 tmp。"""
    fd, tmp = _tmp_sibling(path)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(text.encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        _replace_retry(tmp, path)
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
                    if src.tell():
                        src.seek(-1, os.SEEK_END)
                        if src.read(1) != b"\n":
                            out.write(b"\n")
            out.write((line if line.endswith("\n") else line + "\n").encode("utf-8"))
            out.flush()
            os.fsync(out.fileno())
        _replace_retry(tmp, path)
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

def load_ledger(case, *, lock=True):
    """唯一账本 facts.jsonl 的全部行（claim / kind:"state" / kind:"event" 混存，append-only）。

    state 由 state 行重放，事件账（工具流水）以 event 行追加进同一账本。
    旧 state.json / ai_manifest.json 由 replay 保全原字节并登记后再按需移除。
    """
    try:
        return _case_ledger.read(case, lock=lock)
    except (OSError, ValueError, TypeError, TimeoutError) as exc:
        die("case ledger refused: %s" % exc)

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

def load_facts(case, *, lock=True):
    """只返回 claim 行（gate / verify 的判据面），state / event 行不外泄给旧消费者。"""
    return [e for e in load_ledger(case, lock=lock) if _is_claim(e)]

def _legacy_files(case):
    """发现待保全的历史副本；replay --drop-legacy 先归档核对再移除。"""
    d, _ = paths(case)
    return [p for p in (os.path.join(d, "state.json"),
                        os.path.join(d, "ai_manifest.json")) if os.path.isfile(p)]

def load_state(case, *, lock=True):
    """案子状态 = facts.jsonl 里最后一条 kind:"state" 行重放（不存快照）。"""
    d, _ = paths(case)
    if not os.path.isdir(d):
        die("case 目录不存在：%s\n先跑：case_state.py init --case %s --target <样本>" % (d, case))
    last = None
    for e in load_ledger(case, lock=lock):
        if _entry_kind(e) == LEDGER_STATE_KIND and isinstance(e.get("state"), dict):
            last = e["state"]
    st = _state_default()
    if isinstance(last, dict):
        st.update(last)
    return st


@_case_ledger.locked
def save_state(case, st):
    """写回 = 往账本追加一条 state 行（append-only，最后一条生效）。

    整个读改写必须持共享 OS 锁；仅使用 append-only 并不能避免并发丢失。
    """
    d, fp = paths(case)
    if not os.path.isdir(d):
        die("case 目录不存在：%s" % d)
    _case_ledger.validate_state(st)
    st = dict(st)
    st["updated"] = now()
    append_fact(case, {"kind": LEDGER_STATE_KIND, "ts": st["updated"], "state": st})
    return "facts.jsonl#state"

@_case_ledger.locked
def append_fact(case, fact):
    d, fp = paths(case)
    if not os.path.isdir(d):
        die_json("case-not-found",
                 "案例目录不存在：%s（先跑 case_state.py init --case <目录>）" % d)
    _case_ledger.validate_rows(load_ledger(case) + [fact])
    _atomic_append_line(fp, json.dumps(fact, ensure_ascii=False, allow_nan=False))


@_case_ledger.locked
def _append_group(case, rows):
    """Publish related ledger rows with one atomic replacement, preserving old bytes."""
    _case_ledger.validate_rows(load_ledger(case) + rows)
    _, fp = paths(case)
    _atomic_append_line(fp, "\n".join(json.dumps(row, ensure_ascii=False, allow_nan=False) for row in rows))


def _state_row(state):
    state = dict(state, updated=now())
    return {"kind": LEDGER_STATE_KIND, "ts": state["updated"], "state": state}


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


# 可核对的材料：非空普通文件、命令引用的本地产物、当前文件的完整 SHA256，
# 或最终落到这些材料的账本引用；文本里的哈希、循环编号不能自证。
# 命令字符串不证明执行，执行记录使用 lib.case_repro 的捕获协议。
EVIDENCE_CMD_PREFIXES = ("python ", "python3 ", "pwsh ", "powershell ", "bash ", "cmd ")
EVIDENCE_CMD_PRODUCT_RE = re.compile(r"\.json|\.log|\.md|sha256|rc=|exit=", re.I)
EVIDENCE_ID_RE = re.compile(r"\b([ECF])-(\d{2,})\b")
# 命令串里“像产物”的 token：扩展名必须是落盘产物（脚本 .py/.sh 不算，避免拿输入脚本充产物）
EVIDENCE_ARTIFACT_RE = re.compile(
    r"[^\s\"'<>|;)(=]+\.(?:json|jsonl|log|md|txt|csv|xml|html?|png|jpe?g|gif|dmp|pcapng?|"
    r"zip|tar|gz|exe|dll|bin|so|apk)(?![A-Za-z0-9])", re.I)
def _evidence_is_command(ev):
    """命令形：以已知解释器开头或带 ` --` 参数，且同一串里带可核对的产出描述。"""
    low = ev.lower()
    if not (low.startswith(EVIDENCE_CMD_PREFIXES) or " --" in ev):
        return False
    return bool(EVIDENCE_CMD_PRODUCT_RE.search(ev))


def _clean_ev_token(tok):
    """命令串 token → 裸路径：去掉引号/首尾标点/重定向箭头（保留 Windows 盘符冒号）。"""
    t = (tok or "").strip().strip("'\"`")
    t = t.rstrip(".,;:)]}>")
    for p in ("->", "=>", ">>", ">"):
        if t.startswith(p):
            t = t[len(p):]
    t = t.lstrip("<>= ").strip("'\"`")
    return t


def _cmd_artifact_tokens(ev):
    """从命令串解析出“像产物”的路径/文件名（保持出现顺序、去重）。"""
    out = []
    for m in EVIDENCE_ARTIFACT_RE.finditer(ev or ""):
        t = _clean_ev_token(m.group(0))
        if t and t not in out:
            out.append(t)
    return out


def _norm_path(p):
    try:
        return os.path.normcase(os.path.realpath(os.path.abspath(str(p))))
    except Exception:  # noqa: BLE001 —— 路径怪串不该让证据闸崩
        return os.path.normcase(os.path.abspath(str(p)))


def _resolve_registered_path(case_root, registered):
    """Resolve a case target independently of the process working directory.

    Supported forms are:

    * absolute paths (for genuinely external, user-owned targets);
    * paths relative to the case directory;
    * repository-relative paths such as ``Tool/cases/<case>/target/x.apk``.

    Case-relative interpretation wins when a relative path exists there.  If
    both case-relative and repository-relative interpretations exist and point
    to different files, the record is ambiguous and is rejected instead of
    guessing.  Relative paths may not escape either allowed root.
    """
    from pathlib import Path

    raw = str(registered or "").strip()
    if not raw or URL_RE.match(raw):
        raise ValueError("target path is empty or is a URL")
    candidate = Path(os.path.expanduser(raw))
    if candidate.is_absolute():
        resolved = candidate.resolve(strict=False)
        return str(resolved), "absolute"

    case_dir = Path(case_root).resolve()
    repo_dir = Path(REPO_ROOT).resolve()
    roots = [("case", case_dir), ("repository", repo_dir)]
    candidates = []
    for label, root in roots:
        resolved = (root / candidate).resolve(strict=False)
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        if resolved.is_file():
            candidates.append((label, resolved))

    unique = {}
    for label, resolved in candidates:
        unique.setdefault(_norm_path(resolved), (label, resolved))
    if not unique:
        tried = [str((root / candidate).resolve(strict=False)) for _label, root in roots]
        raise ValueError("target path does not resolve from case or repository root: %s"
                         % " ; ".join(tried))
    if len(unique) > 1:
        raise ValueError("target path is ambiguous between case and repository roots: %s"
                         % " ; ".join(str(item[1]) for item in unique.values()))
    label, resolved = next(iter(unique.values()))
    return str(resolved), label


def _paths_overlap(path, root):
    """path 是否落在 root 下（用 realpath/normcase，Windows 大小写与软链都不误判）。"""
    if not path or not root:
        return False
    p, r = _norm_path(path), _norm_path(root)
    try:
        return os.path.commonpath([p, r]) == r
    except ValueError:      # 跨盘符
        return False


def _case_target_paths(case):
    """本案登记的目标文件（target / target_files）→ 归一化路径集合。"""
    out = set()
    if not case:
        return out
    cj = os.path.join(os.path.abspath(case), "case.json")
    try:
        with open(cj, encoding="utf-8") as f:
            meta = json.load(f)
    except (OSError, ValueError):
        return out
    if not isinstance(meta, dict):
        return out
    t = meta.get("target")
    if isinstance(t, dict) and str(t.get("path") or "").strip():
        out.add(_norm_path(t["path"]))
    for it in meta.get("target_files") or []:
        if isinstance(it, dict) and str(it.get("path") or "").strip():
            out.add(_norm_path(it["path"]))
    return out


def require_evidence(value, case=None):
    """Resolve current local material; command text alone is not execution proof."""
    if not isinstance(value, str):
        die_json("evidence-invalid", "evidence must be a string")
    ev = value.strip()
    if not ev:
        return ev
    from lib.case_evidence import resolve
    try:
        from lib.project_lock import project_lock
        with project_lock(_case_ledger.root_path(case)):
            resolve(_case_api(), case, ev)
    except (OSError, ValueError, TypeError, KeyError, TimeoutError) as exc:
        die_json("evidence-not-replayable", str(exc))
    return ev


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


def _load_ledger_list(case, kind, *, lock=True):
    """账本里的列表型状态（gaps / plan）：最后一条 kind 行整体生效。

    S4：gaps.json / plan.json 不再是独立文件 —— 状态文件只剩 4 类
    （case.json / facts.jsonl / artifacts/MANIFEST.sha256 / packs.baseline.json）。
    """
    out = []
    for e in load_ledger(case, lock=lock):
        if _entry_kind(e) == kind and isinstance(e.get("items"), list):
            out = e["items"]
    return out


def _append_ledger_list(case, kind, items):
    d, fp = paths(case)
    if not os.path.isdir(d):
        die("case 目录不存在：%s" % d)
    append_fact(case, {"kind": kind, "ts": now(), "items": items})


def load_gaps(case, *, lock=True):
    return _load_ledger_list(case, LEDGER_GAPS_KIND, lock=lock)


def save_gaps(case, gaps):
    _append_ledger_list(case, LEDGER_GAPS_KIND, gaps)


def load_plan(case, *, lock=True):
    return _load_ledger_list(case, LEDGER_PLAN_KIND, lock=lock)


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


def _refresh_target_fp(case):
    """原件晚于 init 就位时补登指纹（只补空值，绝不改已登记的哈希）。

    为什么需要：`init --target X` 时 X 还不存在 → case.json 的 target.sha256 为 None，
    之后拿目标哈希做证据就会得到字面量 "None"。写命令发现“登记过路径、哈希还空、
    现在文件已就位”时补算一次（与 init 本来会写的值相同），哈希证据才核对得起来。
    """
    if not case:
        return False
    from pathlib import Path
    from lib.case_repro import _local, _plain
    from lib.project_lock import project_lock

    root = _plain(Path(os.path.abspath(case)))
    cj = _local(root, "case.json")
    if not cj.is_file():
        return False
    with project_lock(root):
        with cj.open(encoding="utf-8") as f:
            meta = json.load(f, object_pairs_hook=_case_ledger._unique)
        if not isinstance(meta, dict):
            raise ValueError("case.json must be an object")
        target = meta.get("target")
        if not isinstance(target, dict):
            raise ValueError("case.json target must be an object")
        raw_path = target.get("path")
        if raw_path is None:
            raw_path = ""
        if not isinstance(raw_path, str):
            raise ValueError("case.json target.path must be a string")
        path = raw_path.strip()
        registered_sha = target.get("sha256")
        if registered_sha not in (None, ""):
            if not isinstance(registered_sha, str) or not re.fullmatch(
                    r"[0-9a-fA-F]{64}", registered_sha.strip()):
                raise ValueError("case.json target.sha256 is invalid")
            return False
        state_target = str(load_state(str(root)).get("target") or "").strip()

        def target_key(value):
            value = str(value or "").strip()
            if not value or URL_RE.match(value):
                return value
            candidate = Path(value)
            if not candidate.is_absolute():
                candidate = root / candidate
            return os.path.normcase(os.path.abspath(candidate))

        if state_target and path and target_key(state_target) != target_key(path):
            raise ValueError("case metadata target disagrees with recorded state target")
        if not path or URL_RE.match(path) or not os.path.isfile(
                path if os.path.isabs(path) else str(root / path)):
            return False
        source = _plain(Path(path if os.path.isabs(path) else str(root / path)))
        before = os.lstat(source)
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise ValueError("case target must be a regular non-link file")
        sha = _sha256_file(str(source))
        after = os.lstat(source)
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            raise ValueError("case target changed while binding")
        size = after.st_size

        entries = meta.get("target_files")
        if entries is None:
            entries = []
        if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
            raise ValueError("case.json target_files must be an array of objects")
        if entries:
            # A pre-existing item without a digest is a placeholder.  It must
            # point to the same target; never repurpose it for another file.
            for item in entries:
                item_path = item.get("path")
                if item_path not in (None, "") and target_key(item_path) != target_key(path):
                    raise ValueError("case.json target_files points to another target")
        target["sha256"], target["size"] = sha, size
        target.pop("note", None)
        meta["target"] = target
        meta["target_files"] = [{"path": path, "sha256": sha, "size": size}]
        _atomic_write_json(str(cj), meta)
    return True


def cmd_init(a):
    from lib.case_lifecycle import initialize
    try:
        return initialize(a, _case_api())
    except (OSError, ValueError, TypeError, TimeoutError) as exc:
        die_json("case-init", str(exc))


DOMAIN_UNCLASSIFIED_NOTE = "未判型，先过 seep-router"


def _case_metadata(case, *, missing_ok=False):
    """Read case.json through the case root with duplicate-key/link checks."""
    from pathlib import Path
    from lib.case_repro import _local, _plain
    root = _plain(Path(os.path.abspath(case)))
    path = _local(root, "case.json")
    if not path.is_file():
        if missing_ok:
            return None
        raise ValueError("case.json is missing")
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream, object_pairs_hook=_case_ledger._unique)
    if not isinstance(value, dict):
        raise ValueError("case.json must be an object")
    return value


def _case_domain(case):
    """读 case.json 里的 `domain`（判型结果）。读不到/没写就返回空串。

    R7 P1-4：`init --domain <域>` 现在真的会落进 case.json，`show` 必须能看见它 ——
    否则客户无从判断「这个案子到底按哪个域在做」。`show` 是客户可见输出，缺文件不报错。
    """
    try:
        meta = _case_metadata(case, missing_ok=True)
    except (OSError, ValueError):
        return ""
    if meta is None:
        return ""
    return str(meta.get("domain") or "").strip()


def _target_files_entry(target_fp):
    """把 `_fingerprint_target` 的指纹块转成 `case.json.target_files[]` 元素。

    第 5 轮评审 P1：新建案只写了 `target`（指纹块），`recheck` 却只读 `target_files`，
    于是新案的复查单永远显示「未登记 target_files」。这里只收**有哈希的真文件**：
    目标未就位（URL/不存在/读不了）时不写空壳条目，保持「没登记 = 没资产」可机检。
    """
    if not isinstance(target_fp, dict):
        return []
    path = str(target_fp.get("path") or "").strip()
    sha = str(target_fp.get("sha256") or "").strip().lower()
    if not path or not sha:
        return []
    return [{"path": path, "sha256": sha, "size": target_fp.get("size")}]


def _ensure_case_meta(d, st, evidence_kind="unknown", target_fp=None, domain=""):
    """写 case.json 骨架（已存在就不动）。字段由 `case_state.py index` 现算时归一。

    第 4 轮评审 P1：`domain` **不再一律写 softseep**。判不出就不写（留空）+ 提示走 seep-router —
    一律写 softseep 等于把「没判过型」伪装成「判过型」，后面的域深度/路由门禁全部失真。
    判型入口：`python Tool/scripts/route.py --resolve "<目标名 + 任务名>"`（判不出会打
    `[UNCLASSIFIED]`）。
    """
    from pathlib import Path
    from lib.case_repro import _local
    cj = _local(Path(d), "case.json")
    if cj.is_file():
        # 第 5 轮评审 P1：老案（case.json 早于 target_files）在重跑 init / init --force 时补登记。
        # 只在「现有 target_files 没有任何 sha256」时补，绝不覆盖人工登记过的相对路径。
        if target_fp is not None or str(domain or "").strip():
            meta = _case_metadata(d)
            fresh = _target_files_entry(target_fp) if target_fp is not None else []
            cur = meta.get("target_files", [])
            if not isinstance(cur, list) or any(not isinstance(item, dict) for item in cur):
                raise ValueError("target_files must be an array of objects")
            if fresh and not any(str(item.get("sha256") or "").strip() for item in cur):
                meta["target_files"] = fresh
            if target_fp is not None:
                meta["target"] = target_fp
                meta["target_type"] = st.get("target") or ""
            if str(domain or "").strip() and not str(meta.get("domain") or "").strip():
                meta["domain"] = str(domain).strip()
            _atomic_write_json(cj, meta)
        return False
    kind = evidence_kind if evidence_kind in ("fixture", "real", "public",
                                             "self-built", "historical") else "unknown"
    dom = str(domain or "").strip()
    meta = {
        "id": os.path.basename(d.rstrip("/\\")),
        # 域留空 = 未判型（不是「默认 softseep」）：先 route.py --resolve，判出再补
        "domain": dom,
        "target_type": st.get("target") or "",
        # ★ 原件指纹块（第 2 轮评审）：建案时就能重放比对「原件动没动」。
        #   只新增字段，不动原有 target_type 等语义；`index` 不读此块，故不影响索引。
        "target": target_fp or {},
        # ★ 目标资产清单（第 5 轮评审 P1）：`recheck` / report 的复查段只认 target_files，
        #   老 init 只写 target 指纹块 → 新案复查单永远「未登记」。这里同时写，target 保持不动（兼容）。
        "target_files": _target_files_entry(target_fp),
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
    _atomic_write_json(str(cj), meta)
    if not dom:
        print("[WARN] %s：case.json 的 domain 留空 —— %s，判出域后再补"
              "（python Tool/scripts/route.py --resolve \"<目标名 + 任务名>\"）"
              % (os.path.basename(cj), DOMAIN_UNCLASSIFIED_NOTE))
    return True



@case_locked
def cmd_verify_origin(a):
    """重算目标原件哈希，与建案时登记的指纹对账（第 2 轮评审：「原件不动」必须可验证）。

    rc=0 且打印指纹 = 原件与建案时一致；rc=2 = 原件已变/已被移动/无法比对。
    """
    d = os.path.abspath(a.case)
    try:
        meta = _case_metadata(d)
    except (OSError, ValueError) as e:
        die_json("case-json-unreadable", "case.json 读不出来：%s: %s" % (type(e).__name__, e))
    tgt = meta.get("target") if isinstance(meta, dict) else None
    tgt = tgt if isinstance(tgt, dict) else {}
    records = {}

    def add_record(raw, *, source, at=""):
        if not isinstance(raw, dict):
            raise ValueError("%s must be an object" % source)
        path = str(raw.get("path") or "").strip()
        sha = str(raw.get("sha256") or "").strip().lower()
        size = raw.get("size")
        if not path and not sha and size is None:
            return
        if not path:
            raise ValueError("%s.path is empty" % source)
        resolved, resolution = _resolve_registered_path(d, path)
        key = _norm_path(resolved)
        record = records.setdefault(key, {
            "registered": path, "resolved": resolved, "resolution": resolution,
            "sha256": "", "size": None, "sources": [], "at": at,
        })
        record["sources"].append(source)
        if sha:
            if not re.fullmatch(r"[0-9a-f]{64}", sha):
                raise ValueError("%s.sha256 is malformed" % source)
            if record["sha256"] and record["sha256"] != sha:
                raise ValueError("%s conflicts with another target fingerprint" % source)
            record["sha256"] = sha
        if size is not None:
            if isinstance(size, bool):
                raise ValueError("%s.size must be an integer" % source)
            try:
                size = int(size)
            except (TypeError, ValueError):
                raise ValueError("%s.size must be an integer" % source)
            if size < 0:
                raise ValueError("%s.size must be non-negative" % source)
            if record["size"] is not None and record["size"] != size:
                raise ValueError("%s conflicts with another target size" % source)
            record["size"] = size

    try:
        add_record(tgt, source="target", at=str(tgt.get("at") or ""))
        entries = meta.get("target_files") or []
        if not isinstance(entries, list):
            raise ValueError("target_files must be an array")
        for index, entry in enumerate(entries):
            add_record(entry, source="target_files[%d]" % index)
    except (OSError, ValueError) as exc:
        print("[ERR] 原件无法确定性解析：%s" % exc)
        return 2
    if not records:
        print("[ERR] 本案件没登记原件路径（case.json 的 target.path 为空）：无法验证原件未变")
        print("     修法：python Tool/scripts/case_state.py init --case %s --target <原件> --force" % d)
        return 2
    failed = False
    for record in sorted(records.values(), key=lambda item: item["resolved"].lower()):
        path = record["resolved"]
        want = record["sha256"]
        want_size = record["size"]
        print("[INFO] 登记指纹：registered=%s resolved=%s via=%s sha256=%s size=%s at=%s"
              % (record["registered"], path, record["resolution"], want or "(未登记)",
                 want_size if want_size is not None else "(未登记)",
                 record["at"] or "(未登记)"))
        if not os.path.isfile(path):
            print("[ERR] 原件已变/已被移动：%s 当前不存在（被删 / 改名 / 移走）" % path)
            failed = True
            continue
        try:
            got, got_size = _sha256_file(path), os.path.getsize(path)
        except OSError as e:
            print("[ERR] 原件已变/已被移动：%s 读不出来：%s" % (path, e))
            failed = True
            continue
        if not want:
            print("[ERR] 原件已变/已被移动：%s 的 sha256 未登记（现在=%s size=%s）"
                  % (path, got, got_size))
            print("     修法：python Tool/scripts/case_state.py init --case %s --target %s --force"
                  % (d, record["registered"]))
            failed = True
            continue
        if got != want or (want_size is not None and got_size != want_size):
            print("[ERR] 原件已变/已被移动：%s" % path)
            print("     登记：sha256=%s size=%s" % (want, want_size))
            print("     现在：sha256=%s size=%s" % (got, got_size))
            print("     注意：原件变了，以前的证据不再自动成立（stale 后再 prove）")
            failed = True
            continue
        print("[OK] 原件未变：resolved=%s sha256=%s size=%s"
              % (path, got, got_size))
    if failed:
        return 2
    return 0


@case_locked
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


@case_locked
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


@case_locked
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


@case_locked
def cmd_claim(a):
    lease_guard(a.case)
    _refresh_target_fp(a.case)
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
    if ev:
        from lib.case_evidence import bind
        bind(_case_api(), a.case, fact, ev)
    try:
        append_fact(a.case, fact)
    except Exception as e:  # noqa: BLE001 —— R6 P1-4：账本写不进去就不许 rc=0
        print("[ERR] 写账本失败（%s 没落账）：%s" % (a.id, e))
        return 2
    print(f"[OK] {a.id} = {a.status}  {a.text}")

@_case_ledger.locked
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
        _case_ledger.validate_row(f)
        if not _is_claim(f) or f["id"] in new_by_id:
            raise ValueError("claim rewrite requires unique claim objects")
        new_by_id[f["id"]] = f
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
    _case_ledger.validate_rows(out)
    _atomic_write_text(fp, "".join(json.dumps(x, ensure_ascii=False, allow_nan=False) + "\n" for x in out))


def _rewrite_facts(case, facts):
    """兼容旧名：语义已改成“只改 claim 行”，与 `_rewrite_claims` 完全等价（不再整文件丢行）。"""
    _rewrite_claims(case, facts)


@case_locked
def cmd_prove(a):
    lease_guard(a.case)
    _refresh_target_fp(a.case)
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
    from lib.case_evidence import bind
    bind(_case_api(), a.case, hit, ev)
    hit["updated"] = now()
    try:
        _rewrite_claims(a.case, facts)
    except Exception as e:  # noqa: BLE001 —— R6 P1-4：写账本失败必须非零（否则等于“已证实”没落账）
        print("[ERR] 写账本失败（%s 没落账）：%s" % (a.id, e))
        return 2
    tail = "（原 stale 已复验复活）" if was_stale else ""
    hint = ""
    if hit.get("confidence") in ("unknown", "inferred") or hit.get("authority") in ("", "none"):
        hint = ("\n[WARN] 本条 confidence=%s authority=%s → 聚合时不算 pass；"
                "实测证据请显式声明 --confidence observed --authority shipped-artifact"
                % (hit.get("confidence"), hit.get("authority")))
    print(f"[OK] {a.id} 已证实{tail}（证据 {len(hit['evidence'])} 条）{hint}")


@case_locked
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
    try:
        _rewrite_claims(a.case, facts)
    except Exception as e:  # noqa: BLE001 —— R6 P1-4：账本写不进去就不许 rc=0
        print("[ERR] 写账本失败（%s 没落账）：%s" % (a.id, e))
        return 2
    print(f"[OK] {a.id} 已标记被推翻，依据 = {a.by}（历史保留，不删）")


@case_locked
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
    try:
        _rewrite_claims(a.case, facts)
    except Exception as e:  # noqa: BLE001 —— R6 P1-4：账本写不进去就不许 rc=0
        print("[ERR] 写账本失败（stale 没落账）：%s" % e)
        return 2
    print("[OK] %d 条 proven 已标为 stale，原因：%s" % (len(proven), reason or "（未写原因）"))
    print("     证据保留；复验用 prove --id <id> --evidence ...，否则 gate 拒绝")


@case_locked
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


@case_locked
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


@case_locked
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
    st = load_state(a.case)
    st["goal_level"] = level
    st["goal_route"] = route
    st["next_action"] = "按 %s（%s）进 01-gate-bypass" % (level, route)
    _append_group(a.case, [{"kind": LEDGER_PLAN_KIND, "ts": now(), "items": plan}, _state_row(st)])
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


@case_locked
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


@case_locked
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


@case_locked
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
    print(f"[OK] 裁定 = {a.value}，能做到哪一步 = {_customer_level(level)}（内部档位见账本）")


@case_locked
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


@case_locked
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
    """Resolve manifest paths only inside the case tree.

    Keep both layouts used by existing cases (relative to the case root or to
    the manifest directory), but never let a correct hash turn a path outside
    the case into valid stage evidence.  Reuse the typed-asset path contract so
    absolute/drive/``..`` references and symlink/reparse traversal fail closed.
    """
    from pathlib import Path
    from lib.typed_assets import TypedAssetError, _project_path

    case_root = Path(os.path.abspath(case))
    refs = [str(rel)]
    try:
        manifest_dir = Path(os.path.abspath(manifest_path)).parent
        manifest_rel = manifest_dir.relative_to(case_root).as_posix()
    except (OSError, ValueError):
        pass
    else:
        refs.append(manifest_rel.rstrip("/") + "/" + str(rel))

    found = []
    seen = set()
    for ref in refs:
        try:
            path = _project_path(case_root, ref)
        except (OSError, ValueError, TypedAssetError):
            continue
        key = os.path.normcase(os.path.abspath(path))
        if key not in seen and path.is_file():
            seen.add(key)
            found.append(str(path))
    return found


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


AUTH_DECL_VALUES = ("本人自有", "书面授权", "公开靶场", "开源")


def _scope_problems(case):
    """scope.md 是「边界 / 环境」记录（目标 / 隔离方式 / 边界 / 期望档位）。

    用户 2026-10-26 口径：**不再要求任何授权字段** —— 「授权来源」四选一、客户原话
    一律不再机检，也不许因为没填它们而拦阶段（不许拿评审意见压用户口径）。
    这里只机检一条事实：这份边界记录在不在、读不读得出。
    返回 [] = 已记录；否则返回一条带可复制修法的未过项。
    """
    d = os.path.abspath(case)
    p = os.path.join(d, "scope.md")
    fix = "先写一份范围契约（目标 / 隔离方式 / 边界 / 期望档位）：%s" % p
    if not os.path.isfile(p):
        return ["范围契约 scope.md 不存在（进阶段 1 及以后前必须先写）\n     " + fix]
    try:
        raw = open(p, encoding="utf-8", errors="replace").read()
    except OSError as e:
        return ["scope.md 读不出来：%s\n     %s" % (e, fix)]
    if not raw.strip():
        return ["scope.md 是空的（边界 / 环境没记录）\n     " + fix]
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

    ★ P0-3b（用户 2026-10-26 改口径）：scope.md 是「边界 / 环境」记录，进阶段 1 及以后必须有；
    不再要求任何授权字段，该条不受豁免③影响 —— 豁免只免「产物闸重查」，不免「边界记录有没有落纸」。
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


@case_locked
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

    # ① 范围契约（边界 / 环境记录）：进阶段 1 及以后必须有 scope.md（不再要求任何授权字段）
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


@case_locked
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
    for identifier, reason in _claim_evidence_problems(a.case, facts).items():
        bad.append("%s evidence: %s" % (identifier, reason))

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
               and str(f.get("authority") or "none").strip().lower() in ("", "none", "reported")]
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

    # ★ P0-3b（用户 2026-10-26 改口径）：范围契约不是「生成完就算」——阶段 1 及以后必须有
    #   scope.md（边界 / 环境记录）；**不要求授权字段**，也不因其缺失拦截。
    cur_stage = str(st.get("stage") or "intake")
    if _stage_index(cur_stage) >= _stage_index("1"):
        bad.extend(_scope_problems(a.case))
    else:
        _sp = _scope_problems(a.case)
        if _sp:
            warn.append("scope.md 未就绪（阶段 0 不阻断，进阶段 1 前必须写）："
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
# 客户语言：对外只说四句（用户 2026-10-26 决定，以最终效果为准）。
# 唯一权威是 `Tool/config/levels.json`；这两张表只是它在进程内的视图（同一份过滤结果），
# preflight 的「等级唯一权威」逐代号比对 JSON 与本模块，漂一个字符就红。
LEVEL_CUSTOMER = _LEVEL_CUSTOMER
# R6 P1：M3/M4 客户话相同（都是「能完全自己接管」），区别**靠证据门槛**：M4 必须是端到端 E4。
# 证据门槛同样来自 levels.json 的 internal[].evidence_min（M 四档 → LEVEL_BAR）。
LEVEL_BAR = _LEVEL_BAR


def _customer_level(word):
    """内部档位 → 客户话；不认识的返回空串（调用方自己决定怎么说）。"""
    return LEVEL_CUSTOMER.get(str(word or "").strip().upper(), "")


def _code_hint(tag, msg):
    """R6 P0-4：内部代号只走 stderr（客户可见的 stdout 不出现 M1..M4 / L1..L3 / J1..J3）。"""
    try:
        sys.stderr.write("[%s] %s\n" % (tag, msg))
    except Exception:  # noqa: BLE001
        pass


def die_split(customer_msg, internal_msg, code=2):
    """客户话走 stdout，带代号的诊断/修法命令走 stderr，rc=code。"""
    _code_hint("internal", internal_msg)
    print("[ERR] " + customer_msg)
    sys.exit(code)


def _repro_records(case):
    """读取复现历史；坏账本和重复记录不能被交付闸静默忽略。"""
    from pathlib import Path
    from lib.case_repro import _local
    from lib.project_transaction import pending
    try:
        root = Path(os.path.abspath(case))
        _local(root, "facts.jsonl")
        if pending(root):
            die("有中断事务，先重试原写入命令恢复，不能用未提交记录验收")
    except ValueError as exc:
        die(str(exc))
    out, identifiers = [], set()
    for rec in load_ledger(case):
        if not isinstance(rec, dict) or "kind" in rec and not isinstance(rec["kind"], str):
            die("facts.jsonl 包含非法记录结构")
        if _entry_kind(rec) == "repro":
            identifier = rec.get("id")
            if not isinstance(identifier, str) or not identifier.strip() or identifier in identifiers:
                die("facts.jsonl 包含缺失或重复的 repro id")
            identifiers.add(identifier)
            out.append(rec)
    return out


def _case_target_info(case):
    """复验当前目标；URL 仅绑定地址文本，不声称已认证远端内容。"""
    from lib.case_repro import target_identity
    try:
        return target_identity(case, load_state(case).get("target", ""))
    except (OSError, ValueError, TypeError) as exc:
        die("目标身份复验失败：%s" % exc)


# 反例程序（第 4 轮评审 P0-1）：这些只回显参数 / 列目录，永远打不开目标文件。
# 血案：`echo mytarget.exe` 里出现了目标 basename，旧判据直接放行 —— 但它没读过目标。
_NEVER_TOUCH_PROGS = {"echo", "printf", "true", "false", "dir", "ls"}
# 解释器：程序之后的**命令体**里必须再出现目标路径/哈希（`python -c "print(1)"` 不算）。
_INTERP_PROGS = {"python", "python2", "python3", "py", "node", "nodejs",
                 "powershell", "pwsh"}
# shell 包装：`cmd /c echo x` / `bash -c "cat x"` 要先剥壳再看真程序（防借壳洗白）。
_SHELL_PROGS = {"cmd", "bash", "sh", "zsh", "wsl", "busybox"}
_TOKEN_RE = re.compile(r'"([^"]*)"|\'([^\']*)\'|(\S+)')


def _target_strong_tokens(info):
    """**能唯一定位这份原件**的字面量：完整路径（两种分隔符）/ `sha256:<前12位>`。

    只出现 basename 不算（第 4 轮评审 P0-1）：`echo mytarget.exe` 恰好就会打印这个名字。
    """
    info = info if isinstance(info, dict) else {}
    out, seen = [], set()
    path = str(info.get("path") or "").strip()
    for p in (path, path.replace("\\", "/"), path.replace("/", "\\")):
        key = p.replace("\\", "/").lower()
        if p and key not in seen:
            seen.add(key)
            out.append(p)
    sha = str(info.get("sha256") or "").strip().lower()
    if len(sha) >= 12:
        out.append("sha256:" + sha[:12])
    return out


def _prog_base(tok):
    """命令首个 token → 程序 basename（去引号/目录/常见后缀，小写）。"""
    s = str(tok or "").strip().strip('"\'')
    s = s.replace("\\", "/").rsplit("/", 1)[-1]
    for suf in (".exe", ".cmd", ".bat", ".ps1", ".com"):
        if s.lower().endswith(suf):
            s = s[:-len(suf)]
    return s.lower()


def _cmd_head(text):
    """(首个程序 basename, 该程序之后的命令体)。剥掉 cmd/bash 这类 shell 包装。"""
    s = str(text or "")
    toks = [(next((g for g in m.groups() if g is not None), ""), m.start(), m.end())
            for m in _TOKEN_RE.finditer(s)]
    if not toks:
        return "", ""
    i = 0
    for _ in range(5):
        name = _prog_base(toks[i][0].split()[0]) if toks[i][0].split() else ""
        if name not in _SHELL_PROGS:
            tail = s[toks[i][2]:]
            if " " in toks[i][0]:       # 引号内整段命令：内容也算命令体
                tail = toks[i][0] + tail
            return name, tail
        j = i + 1
        while j < len(toks) and toks[j][0].startswith(("/", "-")) \
                and len(toks[j][0]) <= 4:
            j += 1                      # 跳过 /c、-c 这类开关
        if j >= len(toks):
            return name, ""
        i = j
    return _prog_base(toks[i][0].split()[0]), ""


def _cmd_evidence_problem(text, info):
    """命令是否含明确目标引用（仅启发式，不能认证进程读取行为）。返回 '' = 通过，否则一句话拒绝理由（带反例）。

    第 4 轮评审 P0-1 判据（三条缺一不可）：
      ① 命令里必须出现目标的**完整路径**或 `sha256:` + 哈希前 12 位（只写 basename 不够）；
      ② 排除显然只回显或列目录的命令头；cat/type/tee 可以读取输入，不作此断言；
      ③ 解释器（python/node/powershell）的**命令体**里必须再出现目标路径/哈希。
    """
    info = info if isinstance(info, dict) else {}
    s = str(text or "").strip()
    if not s:
        return "命令为空"
    path = str(info.get("path") or "").strip()
    name = str(info.get("name") or "").strip() \
        or os.path.basename(path.replace("\\", "/")) or "<目标>"
    strong = _target_strong_tokens(info)
    if not strong:
        return ("本案没登记可用目标（完整路径 / sha256）：先"
                "`init --case <目录> --target <原件>`")
    low = s.replace("\\", "/").lower()
    hit = [t for t in strong if t.replace("\\", "/").lower() in low]
    if not hit:
        return ("命令里没有出现目标的**完整路径**或 `sha256:<前12位>`：只写 basename（%s）不算。\n"
                "      反例：`echo %s` 不算 —— 它只是把参数原样打印，没读过目标。\n"
                "      应写成：`python -c \"print(open(r'%s','rb').read(16))\"`"
                % (name, name, path or "<目标完整路径>"))
    prog, body = _cmd_head(s)
    if prog in _NEVER_TOUCH_PROGS:
        return ("首个程序是 `%s`：仅此命令头不足以说明对目标的观测。\n"
                "      反例：`echo %s` / `ls %s` 不证明目标行为。\n"
                "      改用真读目标的命令：`python -c \"print(open(r'%s','rb').read(16))\"`"
                % (prog, name, name, path or "<目标完整路径>"))
    if prog in _INTERP_PROGS:
        blow = body.replace("\\", "/").lower()
        if not any(t.replace("\\", "/").lower() in blow for t in hit):
            return ("解释器（%s）的命令体里没有目标路径/哈希：`%s -c \"print(1)\"` 类的命令没碰目标。\n"
                    "      把目标写进它执行的代码：`python -c \"print(open(r'%s','rb').read(16))\"`"
                    % (prog, prog, path or "<目标完整路径>"))
    return ""


def _cmd_binds_target(text, info):
    """命令文本是否通过目标引用启发式检查；不认证真实读取。"""
    return _cmd_evidence_problem(text, info) == ""


def _rec_binds_target(rec, target=None):
    """记录命令的目标引用检查：E2 看 --cmd，E3 两路命令都要绑定。

    target 为 None 时退回记录自带 target 块（账本可手写，所以结构判据里两条都要对得上）。
    """
    if not isinstance(rec, dict):
        return False
    info = target
    if not (isinstance(info, dict) and (info.get("path") or info.get("name")
                                        or info.get("sha256"))):
        info = rec.get("target")
    if not isinstance(info, dict) or not (info.get("path") or info.get("name")
                                          or info.get("sha256")):
        return False
    if not _cmd_binds_target(rec.get("cmd"), info):
        return False
    if str(rec.get("grade") or "").strip().upper() == "E3" \
            and not _cmd_binds_target(rec.get("also_cmd"), info):
        return False
    return True


def _is_complete_e3(rec, target=None, case=None):
    """两路成功、一致且命中预期；交付还须复验目标与两路日志。"""
    from lib.case_repro import complete_record
    return complete_record(rec, binder=_cmd_binds_target, target=target, case=case, cross=True)


def _is_complete_repro(rec, target=None, case=None):
    """至少两次成功且一致；传 case 时还核对磁盘捕获及当前目标。"""
    from lib.case_repro import complete_record
    return complete_record(rec, binder=_cmd_binds_target, target=target, case=case)


def _project_acceptance_binding(project, version_id, case_target):
    """Bind M4 to the project state's existing, re-checkable E4 chain.

    The project CLI remains the only producer of E4.  This helper reads that
    chain under the project's OS lock, forces a fresh handoff computation, and
    requires the named project version to describe the same case target.  It
    writes no project evidence and cannot upgrade an incomplete acceptance.
    """
    from pathlib import Path
    from lib.project_lock import project_lock
    from lib import typed_assets
    import project_state

    text = str(project or "").strip()
    version_id = str(version_id or "").strip()
    if not text:
        raise ValueError("M4 必须提供已验证项目目录（--acceptance-project）")
    root = Path(os.path.abspath(os.path.expanduser(text)))
    if not root.is_dir():
        raise ValueError("验收项目目录不存在：%s" % root)
    project_state.require_id(version_id, "acceptance-version")
    if not isinstance(case_target, dict) or not case_target.get("sha256"):
        raise ValueError("当前案例目标身份不完整")
    with project_lock(root, recover=True):
        handoff = project_state.write_handoff(root, persist=True)
        if handoff.get("current_version_id") != version_id:
            raise ValueError("验收项目当前版本是 %r，不是请求的 %r"
                             % (handoff.get("current_version_id"), version_id))
        errors = []
        for key in ("state_errors", "acceptance_errors", "evidence_errors", "closure_errors"):
            value = handoff.get(key)
            if value:
                errors.extend(value if isinstance(value, list) else [value])
        if errors:
            raise ValueError("验收项目完整性未通过：%s" % json.dumps(errors, ensure_ascii=False))
        if handoff.get("state_health") != "ok" or handoff.get("status") != "active":
            raise ValueError("验收项目状态不是健康的 active")
        if not handoff.get("acceptance_complete") or not handoff.get("acceptance_eligible"):
            raise ValueError("验收项目尚未形成完整、可复核的端到端验收")
        run_id = handoff.get("last_run_id")
        if handoff.get("last_run_status") != "completed" or not run_id \
                or run_id not in (handoff.get("completed_runs") or []):
            raise ValueError("验收项目最近 run 尚未 completed，不能作为 M4 的端到端见证")
        current = handoff.get("current_version") or {}
        version_path = project_state.project_file(
            root, "versions/%s/version.json" % version_id)
        version_record = project_state.load_json(version_path)
        kind = version_record.get("kind", "file")
        if case_target.get("identity_scope") == "file-bytes":
            if kind != "file":
                raise ValueError("案例目标是文件字节，但验收项目版本是 %s" % kind)
            if (version_record.get("sha256") != case_target.get("sha256")
                    or version_record.get("size") != case_target.get("size")):
                raise ValueError("验收项目版本与案例目标 SHA256/大小不一致")
            verified = project_state.verify_target(root, version_record)
            identity_match = "file-sha256+size"
        elif case_target.get("identity_scope") == "url-reference-only":
            if kind != "url_descriptor":
                raise ValueError("案例目标是 URL 描述，但验收项目版本是 %s" % kind)
            verified = project_state.verify_target(root, version_record)
            normalized_case = typed_assets.url_descriptor(case_target.get("path", ""))
            if normalized_case.get("url") != version_record.get("url"):
                raise ValueError("验收项目 URL 描述与案例目标不一致")
            identity_match = "normalized-url-descriptor"
        else:
            raise ValueError("M4 不支持当前案例目标身份类型：%s"
                             % case_target.get("identity_scope"))
        handoff_path = root / "handoff.json"
        facts_path = root / "facts.jsonl"
        handoff_sha = hashlib.sha256(handoff_path.read_bytes()).hexdigest()
        facts_sha = hashlib.sha256(facts_path.read_bytes()).hexdigest()
        return {
            "schema": "seep-case-e4-project/1",
            "project": str(root),
            "project_id": handoff.get("project_id"),
            "version_id": version_id,
            "target_kind": kind,
            "target_sha256": verified.get("sha256"),
            "target_size": verified.get("size"),
            "target_identity_scope": verified.get("identity_scope"),
            "case_target_sha256": case_target.get("sha256"),
            "case_target_size": case_target.get("size"),
            "case_target_identity_scope": case_target.get("identity_scope"),
            "identity_match": identity_match,
            "last_run_id": run_id,
            "last_run_status": handoff.get("last_run_status"),
            "completed_runs": list(handoff.get("completed_runs") or []),
            "acceptance_complete": True,
            "acceptance_counts": handoff.get("acceptance_counts"),
            "handoff_sha256": handoff_sha,
            "facts_sha256": facts_sha,
            "proof_level": handoff.get("proof_level"),
            "proof_limits": list(handoff.get("proof_limits") or []),
        }


@case_locked
def cmd_deliver(a):
    """交付分级闸：产物等级不许超过阶段零裁定的上限（血案：文件生成了就宣布可用）。

    R6 P0-4：本命令的 stdout 是**客户正文**，不出现 M1..M4 / L1..L3 / J1..J3；
    代号只走 stderr（`_code_hint` / `die_split`）与账本字段。
    """
    lease_guard(a.case)
    st = load_state(a.case)
    if not st.get("verdict"):
        die("还没给可行性裁定（verdict），不许交付")
    cap = st.get("max_level") or "M1"
    if a.level not in RANK:
        die_split("交付等级只能用四档之一：只能看懂结构 / 能改到能用 / 能完全自己接管"
                  "（内部代号见 stderr 与账本）",
                  "level=%r 不在 M1..M4" % (a.level,))
    if RANK[a.level] > RANK.get(cap, 1):
        die_split("越级交付：裁定「%s」只支持到「%s」，不接受「%s」的交付（内部档位见账本）"
                  % (st["verdict"], _customer_level(cap) or "见账本",
                     _customer_level(a.level) or "见账本"),
                  "越级交付：裁定 %s 的上限是 %s，不接受 %s" % (st["verdict"], cap, a.level))
    # 外部评审 A5：最高两级（M3/M4）必须有**交叉验证/端到端**证据，不能只靠自述
    acceptance_project = str(getattr(a, "acceptance_project", "") or "").strip()
    acceptance_version = str(getattr(a, "acceptance_version", "") or "").strip()
    if a.level != "M4" and (acceptance_project or acceptance_version):
        die("--acceptance-project/--acceptance-version 只用于端到端交付等级")
    tinfo = _case_target_info(a.case) if a.level in ("M2", "M3", "M4") else {}
    if a.level in ("M3", "M4"):
        recs = _repro_records(a.case)
        strong = [r for r in recs if _is_complete_e3(r, tinfo, a.case)]
        if not strong:
            die_split(
                "交付「能完全自己接管」需要至少一条结构完整的交叉验证记录"
                "（两路命令都真跑过本案目标、跑两次结果一致）。账本里现有 repro 记录 %d 条，"
                "0 条达标（只写等级字样不算数）。补证据的命令与内部档位见 stderr。" % len(recs),
                "交付 %s 需要至少一条**结构完整**的 E3 交叉验证记录"
                "（kind=repro / grade=E3 / cmd 非空 / expect 非空 / runs>=2 / digests 条数==runs / "
                "also_cmd 非空且 != cmd；两路命令还必须都真碰过本案目标）。"
                "账本里现有 repro 记录 %d 条，其中 0 条达标"
                "（只写 \"grade\": \"E3\" 字样不算数）。\n"
                "修法：python Tool/scripts/case_state.py repro --case %s --id E-001 "
                "--cmd \"<第一路命令，必须含目标完整路径 %s 或 sha256:<前12位>>\" "
                "--expect \"<必须出现的片段>\" "
                "--also-cmd \"<另一条**真不同**且也真跑目标的命令>\" --runs 2"
                "（必须带 --case 与 --id 才会落账本；两路命令相同会被拒升 E3），"
                "之后用 show 确认账本里出现 grade=E3 的 repro 行；"
                "撑不到 E3 就交付 M2 并写明天花板"
                % (a.level, len(recs), os.path.abspath(a.case),
                   tinfo.get("name") or "<目标名>"))
    # P0-4b：「能改到能用」（M2）不是「文件改动了」就算 —— 至少一条结构化 repro（真跑两次且一致）
    if a.level == "M2":
        recs = _repro_records(a.case)
        good = [r for r in recs if _is_complete_repro(r, tinfo, a.case)]
        if not good:
            cdir = os.path.abspath(a.case)
            die_split(
                "交付「能改到能用」必须至少有 1 条结构完整、真跑过本案目标且两次一致的复现记录；"
                "账本里现有 repro 记录 %d 条，0 条达标（报告或对话里写「跑过了」不算）。"
                "两条出路（补证据 / 降档只交结构理解）的命令与代号见 stderr。" % len(recs),
                "交付 M2（客户话：能改到能用）必须至少有 1 条**结构完整**的复现记录；"
                "账本里现有 repro 记录 %d 条，其中 0 条达标。\n"
                "判据（缺一不可）：kind=repro / cmd 非空且**含目标完整路径或 sha256:前12位**"
                "（只写 basename 或 echo 回显不算）/ expect 非空 / "
                "runs>=2 / digests 条数==runs / consistent==true（报告或对话里写「跑过了」不算）。\n"
                "出路①（补证据，推荐）：\n"
                "  python Tool/scripts/case_state.py repro --case %s --id E-001 "
                "--cmd \"<能复现的命令：里面要写 %s 的完整路径>\" "
                "--expect \"<必须出现的片段>\" --runs 2\n"
                "  输出里应出现「一致=True」且写入账本；然后重跑本命令。\n"
                "出路②（不补证据就降档，只交结构理解）：\n"
                "  python Tool/scripts/case_state.py deliver --case %s --level M1 "
                "--evidence \"<截图/日志>\"（客户话：只能看懂结构）"
                % (len(recs), cdir, tinfo.get("name") or "<目标名>", cdir))
    ev = require_evidence(a.evidence, a.case)
    if not ev:
        die("交付必须有可核对的证明（--evidence：证据文件路径 / 命令+产物 / 哈希 / 账本编号；纯文本不算）")
    delivery = {"level": a.level, "evidence": a.evidence,
                "note": a.note or "", "ts": now()}
    if a.level == "M4":
        if not acceptance_project or not acceptance_version:
            die_split(
                "端到端交付还必须绑定一个已完成验收的真实项目版本。",
                "M4 requires --acceptance-project <目录> --acceptance-version <版本>; "
                "E3 repro alone is not E4.")
        try:
            delivery["end_to_end_acceptance"] = _project_acceptance_binding(
                acceptance_project, acceptance_version, tinfo)
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            die_split("端到端验收复核未通过，交付未登记。",
                      "M4 project acceptance binding rejected: %s" % exc)
    st.setdefault("deliveries", []).append(delivery)
    # next_action 会被 show/resume 原样展示给客户 → 只能写客户话，不带代号
    st["next_action"] = {"M1": "补功能面，冲「能改到能用」",
                         "M2": "冲「能完全自己接管」（UI / 授权）",
                         "M3": "追版与维护", "M4": "维护"}.get(a.level, "")
    try:
        save_state(a.case, st)
    except Exception as e:  # noqa: BLE001 —— 账本写不进去就不许报成功（R6 P1-4）
        print("[ERR] 写账本失败（交付没落账）：%s" % e)
        return 2
    _code_hint("deliver", "交付等级 %s（上限 %s，依据门槛 %s）已落账"
               % (a.level, cap, LEVEL_BAR.get(a.level, "?")))
    print("[OK] 已登记交付：%s（上限：%s；内部档位见账本）：%s"
          % (_customer_level(a.level) or "见账本", _customer_level(cap) or "见账本",
             a.evidence))


def cmd_show(a):
    # show is a read-only compatibility view.  Taking project_lock here creates
    # ``.project.lock`` inside legacy case directories, violating the promise
    # that inspecting an old case leaves every byte and entry untouched.
    root = _case_ledger.root_path(a.case)
    from lib.project_transaction import pending
    if pending(root):
        die("pending case transaction requires retry/recovery before reading", 2)
    st = load_state(a.case, lock=False)
    facts = load_facts(a.case, lock=False)
    gaps = load_gaps(a.case, lock=False)
    plan = load_plan(a.case, lock=False)
    print(f"案子：{a.case}")
    print(f"  目标：{st.get('target') or '-'}")
    _dom = _case_domain(a.case)
    print(f"  域：{_dom or '（未判型；判型见 python Tool/scripts/route.py --resolve）'}")
    # 缝2（P2-4）：T 词表与 M 词表各存各的 —— 但 show 是客户可见输出（R6 P0-4），
    # 只见客户话，代号一律「内部档位见账本」（代号本身走 stderr）。
    tier_v, lvl_v = st.get("tier"), st.get("max_level")
    if tier_v or lvl_v or st.get("tier_input"):
        _code_hint("show", "内部档位 tier=%s max_level=%s tier_input=%s"
                   % (tier_v or "-", lvl_v or "-", st.get("tier_input") or "-"))
    print(f"  裁定：{st.get('verdict') or '（未给）'}")
    if tier_v:
        print(f"  后端档位：{_customer_level(tier_v) or '（未给）'}（内部档位见账本）")
    print(f"  上限：{_customer_level(lvl_v) or '（未给）'}（内部档位见账本）"
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


@case_locked
def cmd_resume(a):
    st = load_state(a.case)
    facts = load_facts(a.case)
    plan = load_plan(a.case)
    gaps = load_gaps(a.case)
    proven = [f for f in facts if f["status"] == "proven"]
    pend = [f for f in facts if f["status"] == "hypothesis"]
    stale = [f for f in facts if f["status"] == "stale"]
    print(f"[接续] {a.case}  裁定={st.get('verdict') or '未给'}  "
          f"上限={_customer_level(st.get('max_level')) or '-'}"
          + (f"  选定等级={st['goal_level']}"
             + (f"（{st['goal_route']}）" if st.get("goal_route") else "")
             if st.get("goal_level") else ""))
    if st.get("max_level"):
        _code_hint("resume", "内部档位 max_level=%s" % st.get("max_level"))
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
        print("  已登记交付：" + "、".join("%s(%s)" % (_customer_level(d["level"]) or "见账本",
                                                  d["ts"][:16]) for d in dl))
        _code_hint("resume", "已登记交付 %s" % "、".join(str(d["level"]) for d in dl))
    print(f"  下一步：{st.get('next_action') or '（未写）'}")


@case_locked
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
    awaiting = st.get("awaiting_human") or {}
    if awaiting and not awaiting.get("ack"):
        asks.append({"text": awaiting.get("stuck") or awaiting.get("card") or "待用户回答"})
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


def _write_answer_pass(case="", adhoc=False):
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
    with open(os.path.join(_TOOL, "config", "answer-contract.json"), "rb") as f:
        ch = hashlib.sha256(f.read()).hexdigest()
    case_abs = os.path.abspath(os.path.expanduser(case)) if case else ""
    target_sha = ""
    if case_abs:
        cj = _case_metadata(case_abs)
        files = cj.get("target_files") or []
        if not isinstance(files, list) or any(not isinstance(item, dict) for item in files):
            raise ValueError("case.json target_files must be an array of objects")
        for item in files:
            sh = str(item.get("sha256") or "").strip().lower()
            if sh:
                if re.fullmatch(r"[0-9a-f]{64}", sh) is None:
                    raise ValueError("case.json target_files sha256 is malformed")
                target_sha = sh
                break
        if not target_sha:
            target = cj.get("target")
            if isinstance(target, dict):
                target_sha = str(target.get("sha256") or "").strip().lower()
                if target_sha and re.fullmatch(r"[0-9a-f]{64}", target_sha) is None:
                    raise ValueError("case.json target sha256 is malformed")
                target = target.get("path") or ""
            target = str(target or "").strip()
            if not target_sha and target and not URL_RE.match(target):
                from pathlib import Path
                from lib.case_repro import _plain
                candidate = Path(target)
                if not candidate.is_absolute():
                    candidate = Path(case_abs) / candidate
                candidate = _plain(candidate)
                if candidate.is_file():
                    target_sha = _sha256_file(str(candidate))
    payload = {
        "schema": "seep.answer-pass/1",
        "case": case_abs,
        # 目标身份：换目标必须重新给首答（扩展按 case.json 的 target_files/target 比对路径）
        "target_sha256": target_sha,
        # ISO8601 带 UTC 偏移：扩展侧 Date.parse 直接认，不做本地时区猜测
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "contract_sha256": ch,
    }
    if adhoc:
        # P0-4 机检（第 3 轮评审）：没绑案的标记必须显式标 adhoc，扩展不得当交付凭证
        payload["adhoc"] = True
    p = os.path.join(os.path.expanduser("~"), ".seep", "answer-pass.json")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    _atomic_write_json(p, payload)
    return p


# 内部话术（第 4 轮评审 P0-2）：选项是给客户看的，不能出现 if_yes/if_no/按…走 这类词。
_ANSWER_JARGON = re.compile(r"if[_-]?(?:yes|no)(?:[^a-z]|$)|if\s+(?:yes|no)(?:[^a-z]|$)|"
                            r"按\s*[^\s，,。；;]{0,8}\s*走", re.I)
# 「缺什么」里的占位写法（写这些等于没写）
_MISSING_PLACEHOLDERS = {"无", "none", "-", "—", "n/a", "na", "null", "没有",
                         "暂无", "0", "…", "..."}
# R8 P0-5：「无 / 不需要」是**合法答案**（真的一件不缺时不许被逼着写「现在做不了」）。
# 代价：必须同时给出「到哪一步」（四句之一）与「大约多少功夫」的依据（下面另行机检）。
_MISSING_NONE = {"无", "没有", "不缺", "无缺", "一样不缺", "什么都不缺", "没什么缺的",
                 "不需要", "无需", "none", "nothing", "n/a", "na", "null", "0"}
# 「授权来源：…」只是一条**声明**，用户 2026-10-26 口径下**不再要求它出现**；
# 这里保留识别只为一件事：真写了它时，别把它算成「还缺什么」的缺口（否则会逼着为它出 A/B/C）。
_MISSING_DECL_MARK = "授权来源"

# ── R6 P0-2：首答「最小内容判据」──
# 血案（`Tool/scripts/case_state.py:2976-3043` 实测）：
#   {"judgment":"一个程序文件","ceiling":"能改到能用","missing":["证据齐不齐"],
#    "effort":"2 小时；依据：这类文件一般这样"}  → 只验形状，返回 []（合格）。
# 现在：判断必须落在**可核对的技术事实**上（或明说未检测 + 点名下一步动作），
# 功夫必须给**区间**（或明说无法估 + 下一步/代价），且两句都不许是空话。
# R8 P0-5：词表原来只认二进制（PE/ELF/壳/x86…），于是**正确的网站/固件首答被判不合格**
# （实测「接口没鉴权，可能越权」FAIL、「squashfs 固件」FAIL）。
# 现在按域扩展：二进制 / Web 接口 / 固件 / 流量 / 供应链 / 保护与反调试都算「可核对的技术事实」。
# 拉丁词一律加 \b（旧的裸 PE|ELF 会命中 self/rapid 这类无关字符串，等于放宽），中文词照旧子串。
_ANSWER_TECH_RE = re.compile(
    # 二进制 / 包格式 / 运行栈
    r"\b(?:PE(?:32|64)?\+?|ELF|Mach-O|APK|DEX|ZIP|Java|Native|IL2CPP|Dart|Hermes)\b"
    r"|\b(?:x86|x64|ARM|AArch64)\b"
    # 保护面：壳 / 加固 / 混淆 / 签名 / 反调试 / 虚拟机 / 符号
    r"|壳|加壳|无壳|加固|脱壳|混淆|明文|加密|签名|反调试|虚拟机|\bdump\b|\bsection\b|符号"
    # Web / 接口
    r"|\b(?:HTTP|HTTPS|API|XSS|SSRF|IDOR|JWT|Cookie)s?\b"
    r"|接口|越权|未授权|注入|报文|握手|\bnonce\b"
    # 固件 / IoT
    r"|\b(?:squashfs|cramfs|UBIFS|JFFS2|rootfs|UART|JTAG)\b"
    r"|固件|串口"
    # 流量 / 供应链
    r"|\bpcap(?:ng)?\b|\bSBOM\b|锁文件|依赖|许可证",
    re.I)
# R8 P0-5：禁用词「已完成」只禁「声称全部做完」的语境（无证据的肯定），
# 单纯陈述某一步做完（「squashfs 解包已完成」）不算 —— 旧口径把正确首答直接打红。
_DONE_WORD = "已完成"
_DONE_CLAIM_RE = re.compile(
    r"(?:全部|所有|一切|整体|任务|工作|这单|本单)\s*(?:都|也)?\s*(?:已经|已)\s*完成"
    r"|(?:已经|已)\s*(?:全部|所有|一切|整体|任务|工作)\s*完成"
    r"|完成\s*(?:了)?\s*(?:全部|所有|一切|整体|任务|工作)")
_ANSWER_UNDET_RE = re.compile(r"未检测|未判定")
_ANSWER_ACT_RE = re.compile(r"hash|哈希|跑|读|看|triage|r2|rabin2", re.I)
_ANSWER_EMPTY_TALK = re.compile(r"一般这样|看情况|通常|大概|应该")
_ANSWER_SPAN_RE = re.compile(r"\d+\s*[-–~到]\s*\d+")          # 2-4 / 30~60
_ANSWER_UNIT_RE = re.compile(r"分钟|小时|天|min|hours?|hrs?|\bh\b|\bd\b", re.I)
_ANSWER_NEXT_RE = re.compile(r"下一步|接下来|然后|先|再|跑|读|看|triage|r2|rabin2|hash|哈希", re.I)
_ANSWER_COST_RE = re.compile(r"代价|成本|工时|功夫|分钟|小时|天|min|hour|hr|元", re.I)
_ANSWER_AUTH_LINE_RE = re.compile(r"授权来源\s*[:：]\s*([^\n；;，,]*)")


def _answer_strings(obj):
    """首答里所有字符串叶子（含 missing 各条 / asks / next），用于找「授权来源」。"""
    out = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_answer_strings(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(_answer_strings(v))
    elif isinstance(obj, str):
        out.append(obj)
    return out


def _answer_auth_source(obj):
    """首答里是否写了「授权来源：<四选一>」。命中返回该值，没有返回 ""。

    用户 2026-10-26 口径：**不再要求**这张声明（不写也合格、不拦阶段）。
    保留识别只为一件事：写了它时，「缺什么」里就只有声明、没有真缺口，
    也按「真一件不缺」看待（否则写声明反而被判「缺什么不能空着」）。
    """
    for s in _answer_strings(obj):
        for m in _ANSWER_AUTH_LINE_RE.finditer(s):
            val = m.group(1).strip()
            hits = [v for v in AUTH_DECL_VALUES if v in val]
            if len(hits) == 1 and "选一" not in val:
                return hits[0]
    return ""


def _missing_items(obj):
    """(原始条目, 真条目)：占位（无/none/-）与 1 字垃圾不算真条目（第 4 轮评审 P0-2）。

    R8 P0-5：`授权来源：…` **不再是必须项**（用户 2026-10-26 口径：不逼客户/模型填授权）。
    但若真的写了它，它是一条**声明**而不是「还缺什么」的缺口 —— 所以不进真条目
    （否则每个首答都被迫为它单出一道 A/B/C）。
    """
    raw = obj.get("missing") if isinstance(obj, dict) else None
    if isinstance(raw, str):
        items = re.split("[；;、,，" + chr(10) + "]", raw)
    elif isinstance(raw, list):
        items = raw
    else:
        items = []
    shown = [str(x).strip() for x in items if str(x).strip()]
    real = [x for x in shown
            if x.lower() not in _MISSING_PLACEHOLDERS and len(x) >= 2
            and _MISSING_DECL_MARK not in x]
    return shown, real


def _check_answer(obj, c):
    bad = []
    ceil_v = str(obj.get("ceiling") or "").strip()
    for f in c["required"]:
        v = obj.get(f["key"])
        if isinstance(v, str):
            v = v.strip()          # 空白串不算“已填”（P0-4 机检：空格 `judgment` 不能过）
        # 第 4 轮评审 P0-2：只有「到哪一步 = 现在做不了」时才允许「缺什么」为空
        allow_empty = f["key"] == "missing" and ceil_v == "现在做不了"
        if f["key"] not in obj:
            bad.append("缺 %s（%s）" % (f["label"], f["hint"]))
        elif not allow_empty and (not v or (isinstance(v, (list, dict)) and not v)):
            bad.append("缺 %s（%s）" % (f["label"], f["hint"]))
    if ceil_v and ceil_v not in c["ceiling_sentences"]:
        bad.append("「到哪一步」只能用这四句之一：" + " / ".join(c["ceiling_sentences"]))
    # P0-4 机检（第 3 轮评审）：首答字段不能拿空格/占位符凑
    judge = str(obj.get("judgment") or "").strip()
    if judge and (len(judge) < 4 or judge.lower() in ("x", "-", "无", "n/a", "na")):
        bad.append("「判断」太短或是占位符（x / - / 无）：至少 4 个字，写清是什么、有没有保护")
    effort = str(obj.get("effort") or "").strip()
    if effort:
        has_num = re.search(r"\d", effort) is not None
        has_why = re.search(r"依据|因为|based on", effort, re.I) is not None
        # 「无法估」是本轮允许的第二种形态（不许瞎编数字）—— 但依据仍必须写，且下文另查「下一步+代价」
        if not (has_why and (has_num or "无法估" in effort)):
            bad.append("「大约多少功夫」必须同时含**数字**（或明写「无法估」）与**依据关键词**"
                       "（依据 / 因为 / based on）：形如「2–4 小时；依据：判定点已定位」")
    # ── 第 4 轮评审 P0-2：内容闸（原来只验字段，"不知道是什么 + 无 + 感觉"也能合格）──
    miss_txt, real_missing = _missing_items(obj)
    miss_all = " ".join(miss_txt)
    has_decl = bool(_answer_auth_source(obj))
    says_none = any(x.strip().lower() in _MISSING_NONE for x in miss_txt)
    # 「除了授权声明之外没有别的缺口」：真一件不缺是合法答案（R8 P0-5）
    no_gap = (not real_missing) and (says_none or has_decl)
    # ── R6 P0-2：**最小内容判据**（原来「一个程序文件」+「这类文件一般这样」也能过）──
    if judge:
        if _ANSWER_EMPTY_TALK.search(judge):
            bad.append("「判断」里出现空话（一般这样 / 看情况 / 通常 / 大概 / 应该）："
                       "换成可核对的事实，例如「PE32+ x86-64，未见壳（区段熵 6.1），本地常量比较」")
        elif not (_ANSWER_TECH_RE.search(judge)
                  or (_ANSWER_UNDET_RE.search(judge) and _ANSWER_ACT_RE.search(miss_all))):
            bad.append("「判断」没有技术事实：至少含一个**可核对的技术词**，按域任选一个——"
                       "二进制：PE / PE32+ / ELF / Mach-O / APK / DEX / ZIP / 壳 / 加壳 / 无壳 / 加固 / "
                       "脱壳 / x86 / x64 / ARM / AArch64 / Java / Native / IL2CPP / 签名 / 混淆 / 反调试 / "
                       "虚拟机 / dump / section / 符号；网站接口：HTTP / 接口 / API / 越权 / 未授权 / 注入 / "
                       "XSS / SSRF / IDOR / JWT / Cookie / 报文 / 握手 / nonce；固件：固件 / squashfs / cramfs / "
                       "UBIFS / JFFS2 / rootfs / 串口 / UART / JTAG；流量与供应链：pcap / SBOM / 锁文件 / 依赖 / "
                       "许可证。或者写「未检测 / 未判定」并在「缺什么」里点名下一步动作"
                       "（hash / 哈希 / 跑 / 读 / 看 / triage / r2 / rabin2）。"
                       "反例：「一个程序文件」—— 没说是什么、有没有保护")
    if effort:
        if _ANSWER_EMPTY_TALK.search(effort):
            bad.append("「大约多少功夫」里出现空话（一般这样 / 看情况 / 通常 / 大概 / 应该）："
                       "换成「2-4 小时；依据：判定点已定位，只剩回归与重打包」这种带依据的区间。"
                       "反例：「2 小时；依据：这类文件一般这样」")
        elif ("无法估" not in effort
              and not (_ANSWER_SPAN_RE.search(effort) and _ANSWER_UNIT_RE.search(effort))):
            bad.append("「大约多少功夫」必须给**区间**（形如 2-4 小时 / 30 分钟~2 小时 / 1-3 天；"
                       "单个数字不合格），确实估不出就写「无法估」并在「缺什么」里给出「下一步 + 代价」。"
                       "反例：「2 小时；依据：这类文件一般这样」")
        elif "无法估" in effort:
            nxt = " ".join([miss_all, effort, str(obj.get("next") or ""),
                            str(obj.get("plan") or "")])
            if not (_ANSWER_NEXT_RE.search(nxt) and _ANSWER_COST_RE.search(nxt)):
                bad.append("写了「无法估」就必须同时给「下一步 + 代价」"
                           "（例如「缺什么」里写「下一步：先跑 triage 读导入表（代价约 2 小时）」）")
    # 用户 2026-10-26 口径：**不再要求「授权来源」**（这行原先是硬要求，已删）。
    # 「授权这件事」以用户自己的要求为准，不许再逼客户/模型填来源、也不许因它拦首答。

    if ceil_v != "现在做不了":                     # 真做不了才允许「什么都不缺」
        if not (real_missing or no_gap):
            bad.append("「缺什么」不能空着或写占位（%s）：逐条写清还缺哪几样"
                       "（例如「卡密有没有」「要不要复现证据」）；确实一样不缺，"
                       "就直接写「无」或「不需要」，但必须同时给出「到哪一步」与"
                       "「大约多少功夫」的**依据**（形如「2-4 小时；依据：判定点已定位」）"
                       % (" / ".join(miss_txt) or "空"))
    # R8 P0-5：写「无 / 不需要」不是冤路 —— 但得配上「到哪一步」与功夫依据（不许拿它当偷懒开关）
    if says_none or no_gap:
        has_why = re.search(r"依据|因为|based on", effort, re.I) is not None
        has_span = _ANSWER_SPAN_RE.search(effort) or "无法估" in effort
        if not (ceil_v in c["ceiling_sentences"] and has_why and has_span):
            bad.append("写「缺什么 = 无 / 不需要」时，必须同时给「到哪一步」（四句之一）与"
                       "「大约多少功夫」的区间加依据（形如「2-4 小时；依据：判定点已定位」）——"
                       "「无」是一个结论，不是省掉判断的理由")
    asks = [q for q in (obj.get("asks") or []) if isinstance(q, dict)]
    if real_missing and not asks:
        bad.append("「缺什么」列了 %d 项，却没有一条「请你选」（asks）："
                   "缺的每一项都要用一道 2–4 选项的题问出来（每项写「选了会怎样」）"
                   % len(real_missing))
    if ceil_v in ("能改到能用", "能完全自己接管") and real_missing:
        blob = " ".join(real_missing) or " ".join(miss_txt)
        if not re.search(r"证据|复现|验收", blob):
            bad.append("承诺「%s」却没说清证据从哪来：承诺「缺什么」里必须至少提到"
                       "「证据 / 复现 / 验收」之一（否则是空口承诺）" % ceil_v)
    r = c["ask_rules"]
    for q in asks:
        opts = q.get("options") or []
        if not (r["min_options"] <= len(opts) <= r["max_options"] + 1):
            bad.append("%s 选项数 %d 不在 %d–%d" % (q.get("id"), len(opts),
                                                   r["min_options"], r["max_options"]))
        for o in opts:
            if not isinstance(o, dict):
                bad.append("%s 里有非对象选项" % q.get("id"))
                continue
            if r["require_consequence"] and not str(o.get("consequence") or "").strip():
                bad.append("%s/%s 没写「选了会怎样」" % (q.get("id"), o.get("key")))
            otext = " ".join(str(o.get(k) or "") for k in
                             ("key", "text", "label", "consequence"))
            if _ANSWER_JARGON.search(otext):
                bad.append("%s/%s 的选项里出现内部话术（if_yes / if_no / 按…走）："
                           "客户看不懂，改成「选了会怎样」的白话"
                           % (q.get("id"), o.get("key")))
    text = json.dumps(obj, ensure_ascii=False)
    for p in c["forbidden_phrases"]:
        if p not in text:
            continue
        # R8 P0-5：只有「声称全部做完了」才算无证据的肯定；
        # 「解包已完成」只是在说某一步的现状，不判红（否则正确的固件首答被打掉）。
        if p == _DONE_WORD and not _DONE_CLAIM_RE.search(text):
            continue
        bad.append("出现禁用措辞「%s」（无证据的肯定）" % p)
    return bad


def cmd_answer(a):
    """首答三要素：缺一即不合格；选项必须写「选了会怎样」。"""
    c = _jd("answer-contract.json")
    if a.template:
        print("【判断】这是什么 / 有没有保护 / 关键在哪：…")
        print("【到哪一步】" + " | ".join(c["ceiling_sentences"]))
        print("【缺什么】① … / ② …（还缺哪几样：卡密 / 账号 / 样本完整性 / 复现证据）")
        print("【大约多少功夫】X 小时 – Y 天（依据：为什么是这个量级）")
        print("【已有证据】E-001 …（或：暂无，只有文件哈希）")
        print("【请你选】Q1｜…  A …→选了会怎样  B …→…  C 我不确定→…")
        print("【你要做的】回一个字母")
        return 0
    if a.selftest:
        good = {"judgment": "PE32+，未见壳", "ceiling": "只能看懂结构",
                "missing": ["有没有卡密", "授权来源：本人自有"],
                "effort": "1–2 小时；依据：未见壳、纯本地判定，读一遍导入表即可定性",
                "asks": [{"id": "Q1", "options": [
                    {"key": "A", "consequence": "走在线对比"},
                    {"key": "B", "consequence": "走离线判定"},
                    {"key": "C", "consequence": "先找校验痕迹"}]}]}
        bad = {"judgment": "x", "missing": [],
               "asks": [{"id": "Q1", "options": [{"key": "A"}]}]}
        # P0-4 机检（第 3 轮评审）：空格 judgment / 无数字 effort 必须红
        blank = {"judgment": " ", "ceiling": "只能看懂结构", "missing": ["a"],
                 "effort": "2-4 小时；依据：已定位"}
        noeff = {"judgment": "PE32+ 无壳", "ceiling": "只能看懂结构", "missing": ["a"],
                 "effort": "看情况"}
        base_ok = ((1 if not _check_answer(good, c) else 0)
                   + (1 if _check_answer(bad, c) else 0))
        extra_ok = ((1 if _check_answer(blank, c) else 0)
                    + (1 if _check_answer(noeff, c) else 0))
        # 第 4 轮评审 P0-2 **内容闸**：只凑字段（说不清 + missing=无 + 不问）必须红；
        # 内容讲清楚（判定/缺项/依据/选项后果）必须过。旧断言只验字段，正是被打穿的形态。
        fake = {"judgment": "不知道是什么", "ceiling": "能改到能用",
                "missing": ["无"], "effort": "1天；依据：感觉", "asks": []}
        promise = {"judgment": "PE32+，无壳，本地常量比较", "ceiling": "能改到能用",
                   "missing": ["卡密有没有", "要不要复现证据", "授权来源：本人自有"],
                   "effort": "2-4 小时；依据：判定点已定位",
                   "asks": [{"id": "Q1", "options": [
                       {"key": "A", "consequence": "走在线对比，能到更高一档"},
                       {"key": "B", "consequence": "只离线判定，最多只能看懂结构"}]}]}
        noask = dict(promise, asks=[])          # 缺两项却一条不问 → 红
        jargon = dict(promise, asks=[{"id": "Q1", "options": [
            {"key": "A", "consequence": "按 if_yes 走"},
            {"key": "B", "consequence": "按 if_no 走"}]}])
        content_ok = ((1 if _check_answer(fake, c) else 0)
                      + (1 if not _check_answer(promise, c) else 0)
                      + (1 if _check_answer(noask, c) else 0)
                      + (1 if _check_answer(jargon, c) else 0))
        # ── R6 P0-2 / P0-3：**最小内容判据**（只验形状的旧口径被实测打穿）──
        # ① 评审原始 payload（"一个程序文件" + "这类文件一般这样"）必须红；
        # ② 用户 2026-10-26 口径：**不再要求「授权来源」** —— 不写 / 写空都不得因此打红
        #    （这两条原先是「拒无授权 / 拒空授权」，现按新口径反过来验：不填授权也能过）；
        # ③ 工时：单点估计 → 红；「无法估」不给下一步+代价 → 红；给了 → 绿；
        # ④ 「未检测」+ missing 里点名动作 → 绿（给真没看过的首答留出路，不许拿它当豁免）。
        hollow = {"judgment": "一个程序文件", "ceiling": "能改到能用",
                  "missing": ["证据齐不齐", "授权来源：本人自有"],
                  "effort": "2 小时；依据：这类文件一般这样",
                  "asks": [{"id": "Q1", "options": [
                      {"key": "A", "consequence": "继续"},
                      {"key": "B", "consequence": "停止"}]}]}
        noauth = dict(promise, missing=["卡密有没有", "要不要复现证据"])
        blankauth = dict(promise, missing=["授权来源：", "卡密有没有", "要不要复现证据"])
        pointest = dict(promise, effort="2 小时；依据：判定点已定位")
        unknow_bad = dict(promise, effort="无法估；依据：壳还没看清",
                          missing=["授权来源：本人自有", "卡密有没有", "要不要复现证据"])
        unknow_ok = dict(promise, effort="无法估；依据：壳还没看清",
                         missing=["授权来源：本人自有",
                                  "下一步：先跑 triage 读导入表（代价约 2 小时）",
                                  "要不要复现证据"])
        undet = dict(promise, judgment="未检测，还没看保护",
                     missing=["授权来源：本人自有",
                              "下一步：跑一遍 triage 看壳（代价约 1 小时）",
                              "要不要复现证据"])
        r6_ok = ((1 if _check_answer(hollow, c) else 0)
                 + (1 if not _check_answer(noauth, c) else 0)      # 不写授权来源 → 合格
                 + (1 if not _check_answer(blankauth, c) else 0)   # 写了但空 → 同样合格
                 + (1 if _check_answer(pointest, c) else 0)
                 + (1 if _check_answer(unknow_bad, c) else 0)
                 + (1 if not _check_answer(unknow_ok, c) else 0)
                 + (1 if not _check_answer(undet, c) else 0))
        print("[answer --selftest] %d/2 通过" % base_ok)      # 兼容旧断言（preflight 认 2/2）
        # ── R8 P0-5：域词表（网站/固件首答不许再被二进制词表打红）/「缺什么 = 无」合法 /
        #    「已完成」按语境判（声称全做完才红，描述某一步做完不红）──
        web = {"judgment": "接口没有鉴权，可能越权访问", "ceiling": "只能看懂结构",
               "missing": ["授权来源：本人自有"], "effort": "1-2 小时；依据：只看接口"}
        fw = {"judgment": "squashfs 固件，解包已完成，启动脚本里有硬编码口令",
              "ceiling": "只能看懂结构", "missing": ["授权来源：本人自有"],
              "effort": "1-2 小时；依据：文件系统已解开"}
        none = dict(web, judgment="PE32+ x86-64，未见壳", ceiling="能改到能用",
                    missing=["无", "授权来源：本人自有"], effort="2-4 小时；依据：判定点已定位")
        none_lazy = dict(none, effort="2 小时；依据：感觉")   # 「无」+ 没依据/单点工时 → 必红
        claimed = dict(web, judgment="已完成全部功能，接口没鉴权")  # 声称全做完 → 必红
        r8_ok = ((1 if not _check_answer(web, c) else 0)
                 + (1 if not _check_answer(fw, c) else 0)
                 + (1 if not _check_answer(none, c) else 0)
                 + (1 if _check_answer(none_lazy, c) else 0)
                 + (1 if _check_answer(claimed, c) else 0))
        print("[answer --selftest] R8 域词表 / 缺什么=无 / 已完成语境 %d/5 通过" % r8_ok)
        print("[answer --selftest] 新增语义 %d/4 通过（拒凑字段 / 过内容 / 缺项必问 / 拒内部话术）"
              % content_ok)
        print("[answer --selftest] R6 最小内容 %d/7 通过（拒空洞首答 / 不写授权也过 / 授权写空也过 / "
              "拒单点工时 / 无法估无代价 / 无法估带代价 / 未检测带动作）" % r6_ok)
        print("[answer --selftest] 合计 %d/20"
              % (base_ok + extra_ok + content_ok + r6_ok + r8_ok))
        return 0 if (base_ok == 2 and extra_ok == 2 and content_ok == 4
                     and r6_ok == 7 and r8_ok == 5) else 1
    src = a.file or ""
    try:
        obj = json.load(open(src, encoding="utf-8")) if src else json.loads(_stdin_utf8())
    except Exception as e:  # noqa: BLE001
        print("[ERR] 读不到 JSON：%s" % e)
        return 2
    # P0-4 机检（第 3 轮评审）：首答标记必须绑目标 —— 没 --case 就得给 --adhoc（≥6 字）。
    case_arg = str(getattr(a, "case", "") or "").strip()
    adhoc = str(getattr(a, "adhoc", "") or "").strip()
    if case_arg:
        if not os.path.isdir(os.path.abspath(os.path.expanduser(case_arg))):
            print("[ERR] --case 不是案件目录：%s（先 init；确实只临时问一句用 --adhoc <原因>）"
                  % case_arg)
            return 2
    elif len(adhoc) < 6:
        print("[ERR] 首答必须绑案：给 --case <案件目录>；确实只临时问一句时给 --adhoc <原因>"
              "（≥6 字，如 \"临时问一句不建案\"）")
        return 2
    if not case_arg:
        print("[ADHOC] 未绑目标，不得用于交付（原因：%s）" % adhoc)
    bad = _check_answer(obj, c)
    for b in bad:
        print("[缺] " + b)
    print("[PASS] 首答合格" if not bad else "[FAIL] 首答不合格（%d 项）" % len(bad))
    if not bad:
        # 通过才写标记（就是 --check 的放行凭证）；失败不写，扩展 answer-gate.ts 继续拦
        try:
            marker = _write_answer_pass(case_arg, adhoc=(not case_arg))
        except (OSError, ValueError, TypeError) as exc:
            print("[ERR] 首答内容合格，但放行标记没有写成：%s" % exc)
            return 2
        print("[标记] 已写 %s（TTL 取自 gate.ttl_minutes；case=%s；adhoc=%s）"
              % (marker, case_arg or "（未指定，不绑目标）", "true" if not case_arg else "false"))
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
        @case_locked
        def record_block(args):
            lease_guard(args.case)
            st = load_state(args.case)
            # next_action 会被 resume/handoff 原样展示给客户，所以只放客户话；码进 blocker 字段。
            st["next_action"] = "%s：%s" % (x["customer"], x["name"])
            st["blocker"] = x["code"]
            save_state(args.case, st)
            return 0
        return record_block(a)
    return 0


def _safe_token(s):
    """文件名安全片段（证据 id）：只留字母数字与 -_，其余转 _。"""
    out = "".join(ch if (ch.isalnum() or ch in "-_") else "_" for ch in str(s or ""))
    return out.strip("_") or "noid"


def cmd_repro(a):
    """执行并捕获重放；命令引用检查只是启发式，不认证语义正确或仪器独立。"""
    from lib.case_repro import run_repro
    return run_repro(a, _case_api())


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


@case_locked
def cmd_downgrade(a):
    """上限降级必须留通知：承诺过「能改到能用」就不能静默降到「只能看懂结构」。

    R6 P0-4：stdout 只给客户话（不出现 M/L/J 代号）；代号只进 stderr / 账本 `*_internal`。
    R6 P1-4：写账本失败 → rc=2（降级不落账等于静默降级）。
    """
    lease_guard(a.case)
    st = load_state(a.case)
    old = st.get("max_level") or "-"
    new = a.to
    if new not in RANK or old not in RANK or RANK[new] > RANK[old]:
        print("[ERR] 降级只能从已登记的交付上限调低；提高上限应重新裁定。")
        return 2
    if old == new:
        print("[SKIP] 上限没变（%s；内部档位见账本）" % (_customer_level(old) or "见账本"))
        return 0
    if not str(a.reason or "").strip():
        print("[ERR] 降级必须写 --reason（为什么降）")
        return 2
    notif = _downgrade_notice(old, new, a.reason)
    # 账本里同时留代号（可审计）+ 客户话（可直接展示）：代号只在 *_internal 字段里
    ledger_notice = "【降级通知】%s → %s。原因：%s" % (old, new, a.reason)
    st["max_level"] = new
    st["next_action"] = notif
    try:
        _append_group(a.case, [_state_row(st),
                              {"kind": "downgrade", "from": old, "to": new,
                               "reason": a.reason, "notice": notif,
                               "notice_internal": ledger_notice, "ts": now()}])
    except Exception as e:  # noqa: BLE001 —— R6 P1-4：降级不落账 = 静默降级，不许 rc=0
        print("[ERR] 写账本失败（降级没有落账）：%s" % e)
        return 2
    _code_hint("downgrade", "上限 %s → %s" % (old, new))
    print(notif)
    print("[OK] 已记入账本（内部档位与原因已留档）")
    return 0


@case_locked
def cmd_recheck(a):
    """复查单：两周后照着能复现（目标哈希/环境/证据/重放命令/期望）。"""
    d = os.path.abspath(a.case)
    from pathlib import Path
    from lib.case_repro import _local
    lease_guard(a.case)
    with _local(Path(d), "case.json").open(encoding="utf-8") as stream:
        cj = json.load(stream, object_pairs_hook=_case_ledger._unique)
    if not isinstance(cj, dict):
        die("case.json must be an object")
    files = cj.get("target_files", [])
    if not isinstance(files, list) or any(not isinstance(item, dict) for item in files):
        die("target_files must be an array of objects")
    repro = _repro_records(a.case)
    L = ["# 复查单（%s）" % os.path.basename(d), "", "## 目标身份", ""]
    for f in files:
        L.append("- `%s` sha256=%s" % (f.get("path"), f.get("sha256")))
    if not files:
        L.append("- （未登记 target_files：请在 case.json 补哈希）")
    L += ["", "## 环境", "",
          "- 生成时间：%s" % now(),
          "- 环境：见各证据的 `env` 字段（python / os / cwd），产物哈希见 `artifacts` 字段",
          "- 已知会变：在线服务、证书、IP（复现失败先查这些）", "",
          "## 证据与重放", ""]
    if repro:
        for r in repro:
            valid = _is_complete_repro(r, case=a.case)
            check = "当前捕获复验通过（不认证结论语义）" if valid else "未通过当前捕获复验；仅保留历史声明"
            digests = r.get("digests")
            digests = digests if isinstance(digests, list) and all(isinstance(x, str) for x in digests) else []
            L.append("- `%s` → `%s`（期望包含 `%s`；登记次数 %s，指纹 %s；%s）"
                     % (r.get("id"), r.get("cmd"), r.get("expect"), r.get("runs"),
                         ",".join(digests), check))
    else:
        L.append("- （暂无结构化重放：跑 `case_state.py repro --case %s --id E-001 "
                 "--cmd \"<命令>\" --expect \"<片段>\"`）" % d)
    L += ["", "## 复现失败怎么判", "",
          "- 先查「已知会变」；仍不一致 → 该结论降为 `未验证`，不要否定整份报告", ""]
    out = str(_local(Path(d), "recheck.md"))
    _atomic_write_text(out, "\n".join(L) + "\n")
    # 先把「目标身份」回显到 stdout：复查时第一眼要能看到目标哈希，
    # 不用再去翻文件（机检：`recheck | grep sha256` 能拿到）。
    for f in files:
        print("[INFO] 登记目标身份：%s sha256=%s" % (f.get("path"), f.get("sha256")))
    if not files:
        print("[WARN] case.json 未登记 target_files（复查单没有目标哈希）")
    print("[OK] 复查单已生成：%s（%d 条重放记录）" % (out, len(repro)))
    return 0


SECTIONS = ["结论", "已确认", "仍未知", "下一步", "复查"]

# REQUIREMENTS.md 的凭据规则：交付物不得落明文凭据。四条规则的边界都以「两份真实报告 + 全部模板」不误报为准：
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
# facts.jsonl；**找不到账本时报告里不许出现 E-/C-/F- 编号**（第 4 轮评审 P0-3：
# `E-999` 在白纸报告里白写也能过）。要给编号就得 `--case <案件目录>` 或把报告放进
# `Tool/cases/<case>/`；模板里的占位编号同理（带 --case 才验得了）。
REPORT_ID_RE = re.compile(r"\b([ECF])-(\d{2,})\b")


def _cases_root():
    return os.path.join(_TOOL, "cases")


def _case_for_report(path, case_arg=""):
    """报告 → 案件目录。返回 (case_dir|None, note)。

    None = 找不到账本：**不许出现 E-/C-/F- 编号**（第 4 轮评审 P0-3），格式照查。
    P1（第 3 轮评审）：报告模板让交付物写 `work/<case>/report.md`，以前这种路径一律当
    "模板" → 假 ID 也能过。现在 `work/<name>/...` 会去 `Tool/cases/<name>/facts.jsonl` 对账；
    找不到再退回 `work/<name>/facts.jsonl`；两边都没有才打 `work-noledger:<name>`。
    也认手写路径 `work/<name>.md`（把文件名当案名）。
    """
    if case_arg:
        d = os.path.abspath(case_arg)
        return (d, "explicit") if os.path.isdir(d) else (None, "missing")
    if not path:
        return None, ""
    ap = os.path.abspath(path)
    root = os.path.abspath(_cases_root())
    try:
        rel = os.path.relpath(ap, root)
    except ValueError:          # 跨盘符（Windows）→ 不可能是案件目录
        rel = ""
    if rel and not (rel == ".." or rel.startswith(".." + os.sep)):
        parts = rel.replace("\\", "/").split("/")
        if len(parts) >= 2 and parts[0] not in ("", ".") and not parts[0].startswith("_"):
            d = os.path.join(root, parts[0])
            if os.path.isdir(d):
                return d, "path"
    # work/<name>/... → 相应案件账本
    wparts = ap.replace("\\", "/").split("/")
    for i in range(len(wparts) - 2, -1, -1):
        if wparts[i].lower() != "work":
            continue
        if i + 1 >= len(wparts):
            return None, ""
        name = wparts[i + 1]
        if i + 2 >= len(wparts):
            # work/<name>.md（手写路径）→ 把文件名当案名
            if not name.lower().endswith(".md"):
                return None, ""
            name = name[:-3]
        if not name or name in (".", "..", "cases"):
            return None, ""
        cand = os.path.join(root, name)
        if os.path.isfile(os.path.join(cand, "facts.jsonl")):
            return cand, "work:" + name
        local = os.path.join(os.sep.join(wparts[:i + 1]), name, "facts.jsonl")
        if os.path.isfile(local):
            return os.path.dirname(local), "work-local:" + name
        return None, "work-noledger:" + name
    return None, ""
    return None, ""


def _ledger_ids(case_dir):
    """Validated claim/replay identifiers, shared with evidence resolution."""
    return set(_ledger_records_by_id(case_dir))


def _report_id_refs(text):
    """报告里出现过的 E-/C-/F- ID（去重、按出现顺序）。"""
    out, seen = [], set()
    for m in REPORT_ID_RE.finditer(text):
        ident = "%s-%s" % (m.group(1), m.group(2))
        if ident not in seen:
            seen.add(ident)
            out.append(ident)
    return out


def _ledger_records_by_id(case_dir):
    """id → 已校验的 claim/repro 行；重复编号或坏账本直接拒绝。

    为什么不用 `load_facts`：报告 ID 对账需要看 **status/confidence/authority**，
    而这三样只在账本原文里，聚合层（facts）拿不到 repro / 非 claim 行。
    """
    return {rec["id"].strip().upper(): rec for rec in load_ledger(case_dir)
            if _is_claim(rec) or _entry_kind(rec) == "repro"}


# 「已确认」段只许放已证结论：status=proven + confidence∈{observed,derived} + authority 非空/none
CONFIRMED_CONFIDENCE = ("observed", "derived")


def _confirmed_section_weak(case_dir, body_lines):
    """「已确认」段里的未证结论 → ["C-001（status=hypothesis，confidence=unknown，authority=none）"]。

    血案（审计 P0）：旧闸只查 ID 在 facts.jsonl 里**存在**，于是 `claim --status hypothesis`
    写进「已确认」也能 PASS。现在逐个 ID 查 status / confidence / authority：
    没证过的结论不许进「已确认」，只能进「仍未知」。
    """
    refs = _report_id_refs("\n".join(body_lines))
    if not refs:
        return []
    recs = _ledger_records_by_id(case_dir)
    weak = []
    for rid in refs:
        rec = recs.get(rid.upper())
        if rec is None:
            continue        # 不存在的 ID 由 ID 对账（P0-4a）负责报红
        st = str(rec.get("status") or "").strip().lower()
        conf = _norm_confidence(rec.get("confidence"), default="")
        auth = str(rec.get("authority") or "").strip().lower()
        why = []
        if st != "proven":
            why.append("status=%s" % (st or "(无：不是结论行)"))
        if conf not in CONFIRMED_CONFIDENCE:
            why.append("confidence=%s" % (conf or "unknown"))
        if auth not in ("shipped-artifact", "controlled-replay", "external-service"):
            why.append("authority=%s" % (auth or "(空)"))
        if not why:
            from lib.case_evidence import claim_files
            try:
                claim_files(_case_api(), case_dir, rec, rows=load_ledger(case_dir))
            except (OSError, ValueError, TypeError, KeyError) as exc:
                why.append("evidence=%s" % exc)
        if why:
            weak.append("%s（%s）" % (rid, "，".join(why)))
    return weak


def _reconcile_report_ids(text, case_dir):
    refs = _report_id_refs(text)
    ids = _ledger_ids(case_dir)
    return refs, [r for r in refs if r.upper() not in ids]


def _recheck_section_problem(body_lines, case_dir):
    """case.json 有 target_files 时，复查段必须提到目标哈希前缀或 resume 命令。"""
    from pathlib import Path
    from lib.case_repro import _local, _plain
    from lib.project_lock import project_lock

    try:
        root = _plain(Path(case_dir))
        cj = _local(root, "case.json")
        if not cj.exists():
            return None
        with project_lock(root):
            with cj.open(encoding="utf-8") as f:
                metadata = json.load(f, object_pairs_hook=_case_ledger._unique)
        if not isinstance(metadata, dict):
            raise ValueError("top level must be an object")
        tfiles = metadata.get("target_files")
        if tfiles is None:
            tfiles = []
        if not isinstance(tfiles, list):
            raise ValueError("target_files must be a list")
        hashes = []
        for item in tfiles:
            if not isinstance(item, dict):
                raise ValueError("target_files entries must be objects")
            value = item.get("sha256")
            if value in (None, ""):
                continue
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
                raise ValueError("target_files sha256 must be a complete hex digest")
            hashes.append(value.lower())
    except (OSError, ValueError, TypeError) as exc:
        return "复查段未核验：case.json 不可安全读取（%s）" % str(exc)[:160]
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
    """报告五段校验：缺段不算交付（对应 REQUIREMENTS.md 的交付规则）；案件报告额外做 ID 对账。"""
    if a.selftest:
        N = chr(10)
        good = (
            "# r" + N + "## 1 结论" + N + "能到「只能看懂结构」" + N + "卡在壳上" + N            + "## 2 已确认" + N + "- x（E-001）" + N + "- y（C-002）" + N            + "## 3 仍未知" + N + "- z 缺实测" + N + "- w 需硬件" + N            + "## 4 下一步" + N + "- 省事：A" + N + "- 彻底：B" + N            + "## 5 怎么复查" + N + "- recheck.md" + N + "- resume --case <案件目录>；重放 E-001" + N)
        bad = "# r\n## 1 结论\nx\n"
        ok = 0          # 格式判据在下面建好临时账本后再算（good 带编号，必须有账本才合法）


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
            with open(os.path.join(tmp, "a.log"), "w", encoding="utf-8") as f:
                f.write("report self-test fixture evidence\n")
            with open(os.path.join(tmp, "facts.jsonl"), "w", encoding="utf-8") as f:
                # 默认全部是“可进已确认”的强结论（proven + observed + shipped-artifact）；
                # 下面 C-003/C-004/C-005 是本轮新增语义的反例。
                for _fid, _extra in (("F-001", {}), ("E-001", {}), ("C-002", {}),
                                     ("C-003", {"status": "hypothesis"}),
                                     ("C-004", {"confidence": "inferred"}),
                                     ("C-005", {"authority": "none"})):
                    _rec = {"id": _fid, "claim": "x", "status": "proven",
                            "evidence": ["a.log"], "how": "h",
                            "confidence": "observed", "authority": "shipped-artifact"}
                    _rec.update(_extra)
                    f.write(json.dumps(_rec, ensure_ascii=False) + N)
            with open(os.path.join(tmp, "case.json"), "w", encoding="utf-8") as f:
                json.dump({"id": "t", "target_files": [
                    {"path": "target/a.exe", "sha256": "a" * 64}]}, f)
            # 格式 2/2：good（有账本、编号真实）过；bad（缺段）必红
            ok = ((1 if not _check_report(good, case_dir=tmp) else 0)
                  + (1 if _check_report(bad) else 0))
            # ① 真实 ID + resume 命令 → 过
            ok2 += 1 if not _check_report(_mk("F-001", "resume --case " + tmp),
                                          case_dir=tmp) else 0
            # ② 假 ID → 必红且点名
            miss = _check_report(_mk("E-999", "resume --case " + tmp), case_dir=tmp)
            ok2 += 1 if miss and "E-999" in N.join(miss) else 0
            # ②b 审计 P0：「已确认」段只许放已证结论（hypothesis / inferred / authority=none 必红）
            hyp = _check_report(_mk("C-003", "resume --case " + tmp), case_dir=tmp)
            ok2 += 1 if hyp and "未证结论" in N.join(hyp) and "仍未知" in N.join(hyp) else 0
            inf = _check_report(_mk("C-004", "resume --case " + tmp), case_dir=tmp)
            ok2 += 1 if inf and "C-004" in N.join(inf) and "confidence=inferred" in N.join(inf) else 0
            noauth = _check_report(_mk("C-005", "resume --case " + tmp), case_dir=tmp)
            ok2 += 1 if noauth and "C-005" in N.join(noauth) and "authority=none" in N.join(noauth) else 0
            # ③ 有 target_files 但复查段既无哈希前缀又无 resume → 必红
            nohash = _check_report(_mk("F-001", "recheck.md"), case_dir=tmp)
            ok2 += 1 if nohash and "复查段" in N.join(nohash) else 0
            # ④ 第 4 轮 P0-3（旧断言是「不传 case_dir 时假 ID 也能过」，正是被打穿的口子）：
            #    找不到账本 + 报告里有编号 → 必红，并提示 --case / 放进 Tool/cases/<case>/
            noled = _check_report(_mk("E-999", "重放 E-999"))
            ok2 += 1 if noled and "找不到账本" in N.join(noled) else 0
            # ⑨ case 目录存在但**没有账本**（facts.jsonl 缺失）+ 报告有编号 → 同样必红
            empty = os.path.join(tmp, "emptydir")
            os.makedirs(empty, exist_ok=True)
            lock = _check_report(_mk("F-001", "resume --case " + empty), case_dir=empty)
            ok2 += 1 if lock and "找不到账本" in N.join(lock) else 0
            # ⑤ P1（第 3 轮评审）：work/<name>/report.md 必须对到 Tool/cases/<name> 的账本
            wroot = os.path.join(tmp, "Tool", "cases")
            os.makedirs(os.path.join(wroot, "wcase"), exist_ok=True)
            shutil.copyfile(os.path.join(tmp, "facts.jsonl"),
                            os.path.join(wroot, "wcase", "facts.jsonl"))
            shutil.copyfile(os.path.join(tmp, "case.json"),
                            os.path.join(wroot, "wcase", "case.json"))
            wrep = os.path.join(tmp, "work", "wcase", "report.md")
            os.makedirs(os.path.dirname(wrep), exist_ok=True)
            _root0 = _cases_root
            globals()["_cases_root"] = lambda: wroot
            try:
                _cd, _note = _case_for_report(wrep)
                ok2 += 1 if _cd and _note == "work:wcase" else 0
                miss2 = _check_report(_mk("E-999", "resume --case " + (_cd or "")),
                                      case_dir=_cd)
                ok2 += 1 if miss2 and "E-999" in N.join(miss2) else 0
                _cd2, _note2 = _case_for_report(os.path.join(tmp, "work", "noledger", "report.md"))
                ok2 += 1 if not _cd2 and _note2.startswith("work-noledger:") else 0
                _cd3, _note3 = _case_for_report(os.path.join(tmp, "work", "wcase.md"))
                ok2 += 1 if _cd3 and _note3 == "work:wcase" else 0
            finally:
                globals()["_cases_root"] = _root0
            # ⑩ R8 P1-2：内部代号（M/L/J / max_level / facts.jsonl）出现在客户可见报告里 → 必红
            _cn = _check_report(
                _mk("F-001", "resume --case " + tmp).replace(
                    "卡在壳上", "卡在壳上（上限 L1，见 facts.jsonl 的 max_level）"),
                case_dir=tmp)
            ok2 += 1 if _cn and "内部代号" in N.join(_cn) else 0
            # ⑪ 同一段文字在 `Tool/prompts/**` 模板里是占位符 → 不算代号问题
            _tpl = _check_report(
                _mk("F-001", "resume --case " + tmp).replace("卡在壳上", "卡在壳上（上限 M2）"),
                case_dir=tmp, is_template=True)
            ok2 += 1 if _tpl == [] else 0
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        print("[report --selftest] %d/2 通过" % ok)
        print("[report --selftest] 新增语义 %d/14 通过"
              "（ID 对账 / 假 ID 必红 / 已确认只许已证结论(hypothesis/inferred/无authority) / "
              "复查段哈希 / 无账本禁编号 / work 路径对账 / 禁内部代号 / 模板除外）" % ok2)
        return 0 if (ok == 2 and ok2 == 14) else 1
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
    bad = _check_report(text, case_dir=case_dir, is_template=_is_template_path(src))
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
        if _is_template_path(src):
            print("[report] 模板文件：未做 ID 对账（模板里的 E-001 是占位符，不是交付物）"
                  " —— 交付物请放进 Tool/cases/<case>/ 或给 --case")
            if not bad:
                print("[PASS] 报告五段齐全")
            return 0 if not bad else 1
        if cnote.startswith("work-noledger:"):
            _wn = cnote.split(":", 1)[1]
            print("[report] 找不到账本（work/%s 无对应账本）：既没有 Tool/cases/%s/facts.jsonl，"
                  "也没有 work/%s/facts.jsonl —— 报告里若出现 E-/C-/F- 编号即 FAIL（没法核对）"
                  % (_wn, _wn, _wn))
        else:
            print("[report] 找不到账本（不是案件报告）：%s 不在 Tool/cases/<case>/ 下，"
                  "也不在 work/<case>/ 下，且未给 --case —— 报告里若出现 E-/C-/F- 编号即 FAIL；"
                  "给它 --case <案件目录>，或把报告放进 Tool/cases/<case>/" % src)
    print("[PASS] 报告五段齐全" if not bad else "[FAIL] 报告不合格（%d 项）" % len(bad))
    return 0 if not bad else 1


def _is_template_path(path):
    """模板文件判定：Tool/prompts/ 下的是模板（E-001 是占位符），不是可交付报告。

    为什么需要：第 4 轮评审要求"无账本 + 报告里有证据编号 → 必红"，
    但模板天然没有账本。若不给模板开后门，10 份模板会全部被判红——
    那不是诚实，是把"模板"和"交付物"混为一谈。
    """
    try:
        root = os.path.normcase(os.path.realpath(os.path.join(_TOOL, "prompts")))
        candidate = os.path.normcase(os.path.realpath(os.path.abspath(os.fspath(path))))
        return os.path.commonpath((root, candidate)) == root
    except (OSError, TypeError, ValueError):
        return False


# ── R8 P1-2：客户可见文本禁代号 ──
# 血案：两份真实报告（golden-crackme / leaf-pe-packed 的 report/final.md）里带着
# `facts.jsonl` / `max_level` / `L1` 仍被判 PASS —— 客户拿到报告看不懂那些内部词。
# 规则：内部代号/内部字段名只许出现在 `Tool/prompts/**` 模板（模板要用占位符）；
# **案件报告一律禁**，命中即 FAIL 并给替换建议。
# 代号词表同样取自 levels.json（internal[].code）—— 新刻度只改那个文件，扫描自动跟上；
# 配置读不到时退回内置副本（见 load_level_authority），免得禁代号扫描静默失明。
_REPORT_CODE_ALT = "|".join(sorted((re.escape(c) for c in _LEVEL_CUSTOMER), key=len, reverse=True))
_REPORT_CODE_RE = re.compile(r"(?<![A-Za-z0-9_])((?:%s)|BLK-\d+)(?![0-9])" % _REPORT_CODE_ALT)
# 反误伤：硬件/缓存里的同名串（Apple M1 芯片、L1 缓存）不是内部档位代号。
# 只排除这两种明确形态；其余一律当代号（宁可报出来改措辞，也不放过真泄露）。
_REPORT_CODE_EXEMPT_RE = re.compile(r"^(?:M[1-4]\s*(?:芯片|SoC|Max|Pro|Ultra)|L[1-3]\s*(?:缓存|cache))",
                                   re.I)
_REPORT_INTERNAL_WORDS = (("max_level", "内部字段，改用“见账本”"),
                          ("facts.jsonl", "内部字段，改用“见账本”"))
_REPORT_CODE_HINT = dict(_LEVEL_CUSTOMER)
_REPORT_CODE_ADVICE = (
    "内部档位代号 → 四句客户话之一（%s；逐档映射见 levels.json 的 internal[]）；"
    "max_level / facts.jsonl→内部字段，改用“见账本”；BLK-n→「卡在哪 + 两条出路」"
    % " / ".join(LEVEL_SENTENCES))


def _report_codename_hits(lines):
    """客户可见文本里的内部代号命中 → ["第 n 行「M2」→ 能改到能用", ...]。"""
    hits = []
    for n, line in enumerate(lines, 1):
        for m in _REPORT_CODE_RE.finditer(line):
            tok = m.group(1)
            if _REPORT_CODE_EXEMPT_RE.match(line[m.start():]):
                continue
            if tok.upper().startswith("BLK-"):
                hint = "「卡在哪 + 两条出路」（客户话取自 blockers.json 的标题）"
            else:
                hint = _REPORT_CODE_HINT.get(tok.upper(), "改用客户话")
            hits.append("第 %d 行「%s」→ %s" % (n, tok, hint))
        for w, hint in _REPORT_INTERNAL_WORDS:
            if w in line:
                hits.append("第 %d 行「%s」→ %s" % (n, w, hint))
    return hits


def _check_report(text, case_dir=None, is_template=False):
    """报告校验（2026-10-25 外部评审 3.3：原来只查标题存在，"空内容"能绕过）。

    现在要求：
      ① 五段标题都在；
      ② 每段标题下至少 2 行非空内容；
      ③ 结论段 ≤3 行；
      ④ "已确认"段至少出现 1 个证据/结论 ID（E-/C-/F-）；
      ⑤ 出现禁用措辞（应该可以/大概能/通常没问题）即不合格；
      ⑥ 凭据扫描（REQUIREMENTS.md 的凭据规则）：命中私钥块 / AK / 明文口令赋值 / Bearer 令牌即不合格。
    ⑦ P0-4a：给了案件目录（case_dir）时，每个 E-/C-/F- ID 必须存在于该案 facts.jsonl；
       有 target_files 时，复查段还要提到目标哈希前缀或 resume 命令。
       P0-3（第 4 轮评审）：没账本就禁编号 —— case_dir 为空、或其中没有 facts.jsonl
       而报告里出现 E-/C-/F- 编号 → 不合格（`E-999` 白写也能过就是这里漏的）。
       修法：给它 `--case <案件目录>`，或把报告放到 `Tool/cases/<case>/`。
    ⑧ R8 P1-2：客户可见文本禁代号 —— `Tool/config/levels.json` 的 internal[] 全部代号
       （现为 M1–M4 / L1–L3 / T1–T4 / J1–J3，词表从配置现算，新刻度自动跟上）/ BLK-n /
       max_level / facts.jsonl 命中即不合格（唯一例外：`Tool/prompts/**` 模板要用占位符）。
    ⑨ 审计 P0：「已确认」段只许放**已证结论** —— 段里每个 ID 对应的账本行必须是
       status=proven、confidence∈{observed,derived}、authority 非空且不为 none；
       否则必红，并建议移到「仍未知」+ 在「下一步」给补齐动作（旧闸只查 ID 存在，
       `claim --status hypothesis` 写进本段也能 PASS）。
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
    # ⑧ R8 P1-2：客户可见文本禁代号（模板除外：Tool/prompts/** 要用占位符）
    if not is_template:
        _ch = _report_codename_hits(lines)
        if _ch:
            bad.append("报告里出现内部代号/内部字段名（客户看不懂，只许留在 Tool/prompts/** 模板里）：%s"
                       " —— 换成客户话：%s" % ("；".join(_ch[:6]), _REPORT_CODE_ADVICE))
    for i, l in enumerate(lines):
        for sec in SECTIONS:
            if l.strip().startswith("#") and sec in l and sec not in idx:
                idx[sec] = i
    for sec in SECTIONS:
        if sec not in idx:
            bad.append("缺段：" + sec)
    # ⑦ ID 对账（第 4 轮评审 P0-3）：没有账本就**不许出现编号** —— 否则 `E-999` 白写也能过。
    if case_dir:
        ledger = os.path.join(case_dir, "facts.jsonl")
        refs = _report_id_refs(text)
        if not os.path.isfile(ledger) and refs:
            bad.append("找不到账本（%s 不存在），无法核对证据编号：%s —— 先建案并把证据写进账本"
                       "（prove/repro），或把报告放到 `Tool/cases/<case>/` 下"
                       % (ledger, "、".join(refs[:6])))
        else:
            refs, missing = _reconcile_report_ids(text, case_dir)
            if missing:
                bad.append("ID 对账失败：报告引用了 facts.jsonl 里不存在的 ID：%s（已核对 %d 个）—— "
                           "要么在账本里补这条结论，要么把报告改成真实存在的 ID"
                           % ("、".join(missing), len(refs)))
    else:
        refs = _report_id_refs(text)
        if refs and not is_template:
            bad.append("找不到账本，无法核对证据编号：报告里写了 %s。给它 `--case <案件目录>`，"
                       "或把报告放到 `Tool/cases/<case>/`（账本 = 该目录的 facts.jsonl）"
                       % "、".join(refs[:6]))
    # ⑦b 审计 P0：「已确认」段只许放已证结论。
    #    旧闸只查 ID 在账本里**存在** → `claim --status hypothesis` 写进本段也能 PASS。
    #    现在逐 ID 查 status=proven + confidence∈{observed,derived} + authority≠空/none。
    #    放在 `if bad` 之前：否则格式问题会提前返回，把这条最关键的假结论漏掉。
    if case_dir and "已确认" in idx:
        _s = idx["已确认"] + 1
        _later = [i for i in idx.values() if i > idx["已确认"]]
        _e = min(_later) if _later else len(lines)
        _body = [x for x in lines[_s:_e] if x.strip() and not x.strip().startswith("#")]
        _weak = _confirmed_section_weak(case_dir, _body)
        if _weak:
            bad.append("「已确认」段里有未证结论：%s —— 本段每个 ID 必须是 status=proven、"
                       "confidence∈{observed,derived}、authority 非空且不为 none。"
                       "建议：把这几条移到「仍未知」段，并在「下一步」给出补齐动作"
                       "（补实测证据 / 补 authority 来源），证成后再移回本段" % "；".join(_weak))
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
            target_path = os.path.join(tmp3, "target.bin")
            with open(target_path, "wb") as f:
                f.write(b"local target fixture")
            target_sha = _sha256_file(target_path)
            with open(os.path.join(tmp3, "case.json"), "w", encoding="utf-8") as f:
                json.dump({"id": "t", "target": {"path": target_path, "sha256": target_sha}}, f)
            with open(os.path.join(tmp3, "hash-record.log"), "w", encoding="utf-8") as f:
                f.write("launch sha256=%s\n" % ("b" * 64))
            # 纯文本 → 拒
            assert _rej(lambda: require_evidence("看过了", tmp3)); checks += 1
            assert _rej(lambda: require_evidence("已确认", tmp3)); checks += 1
            assert _rej(lambda: require_evidence("分析完成", tmp3)); checks += 1
            # 命令 + **真实产物** → 收；命令但没产物描述 → 拒
            cmd = "python Tool/scripts/preflight.py --fast -> x.json rc=0"
            with open(os.path.join(tmp3, "x.json"), "w", encoding="utf-8") as f:
                f.write("{}")
            assert require_evidence(cmd, tmp3) == cmd; checks += 1
            assert _rej(lambda: require_evidence("bash run.sh", tmp3)); checks += 1
            # 审计 P0：命令型必须能解析出一个真实产物（只写 rc= / --out nope.json 不再算）
            assert _rej(lambda: require_evidence("python foo.py --out nope.json rc=0", tmp3)); checks += 1
            assert _rej(lambda: require_evidence("python foo.py --check rc=0 sha256", tmp3)); checks += 1
            # 审计 P0：哈希必须对得上本案（目标哈希 / 案件目录里记录过）；乱写的 64 hex 拒
            assert require_evidence(target_sha, tmp3); checks += 1
            assert _rej(lambda: require_evidence("sha256:" + "b" * 64, tmp3)); checks += 1
            assert _rej(lambda: require_evidence("c" * 64, tmp3)); checks += 1
            assert _rej(lambda: require_evidence("sha256:" + "d" * 64, tmp3)); checks += 1
            # 账本编号：存在收 / 不存在拒（要读账本，不能崩）
            assert _rej(lambda: require_evidence("见 C-001 的实测", tmp3)); checks += 1
            assert _rej(lambda: require_evidence("见 C-999", tmp3)); checks += 1
            # 路径：存在收 / 不存在拒（原行为保留）
            with open(os.path.join(tmp3, "run.log"), "w", encoding="utf-8") as f:
                f.write("x")
            assert require_evidence("run.log", tmp3); checks += 1
            assert _rej(lambda: require_evidence("ghost.json", tmp3)); checks += 1
            # 第 5 轮评审 P1：存在但零字节 → 仍必须拒（`: > empty.log` 不能当证据）
            empty = os.path.join(tmp3, "empty.log")
            open(empty, "w", encoding="utf-8").close()
            assert _rej(lambda: require_evidence("empty.log", tmp3)); checks += 1
            assert _rej(lambda: require_evidence(empty, tmp3)); checks += 1
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
            # 第 5 轮评审 P1：init 的 case.json 必须同时登记 target_files[]（recheck 读它）
            mdir = os.path.join(tmp3, "mcase")
            os.makedirs(mdir, exist_ok=True)
            assert _ensure_case_meta(mdir, {"target": fp.get("path")}, "real", fp,
                                     domain="softseep"); checks += 1
            mj = json.load(open(os.path.join(mdir, "case.json"), encoding="utf-8"))
            assert mj.get("target", {}).get("sha256") == fp["sha256"]; checks += 1
            assert (mj.get("target_files") or [{}])[0].get("sha256") == fp["sha256"]; checks += 1
            assert _target_files_entry(fp2) == []; checks += 1
            # R7 P1-4：`init --domain <域>` 必须真的落进 case.json（缺省空串 = 未判型，不是默认 softseep）
            _ptr = os.path.join(os.path.expanduser("~"), ".seep", "current-case")
            _ptr_prev = None
            if os.path.isfile(_ptr):
                with open(_ptr, encoding="utf-8") as _pf:
                    _ptr_prev = _pf.read()
            try:
                _dd = os.path.join(tmp3, "domcase")
                with _ctx.redirect_stdout(_io.StringIO()), _ctx.redirect_stderr(_io.StringIO()):
                    cmd_init(argparse.Namespace(case=_dd, target=os.path.join(tmp3, "run.log"),
                                                force=False, evidence_kind="fixture",
                                                domain="web-pentest"))
                assert _case_domain(_dd) == "web-pentest"; checks += 1
                _dd2 = os.path.join(tmp3, "domcase2")
                with _ctx.redirect_stdout(_io.StringIO()), _ctx.redirect_stderr(_io.StringIO()):
                    cmd_init(argparse.Namespace(case=_dd2, target="", force=False,
                                                evidence_kind="fixture", domain=""))
                assert _case_domain(_dd2) == ""; checks += 1
            finally:
                # 不把自测的临时案写进用户的当前案指针
                try:
                    if _ptr_prev is None:
                        if os.path.isfile(_ptr):
                            os.remove(_ptr)
                    else:
                        with open(_ptr, "w", encoding="utf-8") as _pf:
                            _pf.write(_ptr_prev)
                except OSError:
                    pass
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
            # ★ P0-3b（用户 2026-10-26 改口径）：进阶段 1 及以后必须有 scope.md（边界/环境记录），
            #   **不再要求任何授权字段**。
            assert _scope_problems(tmp2); checks += 1          # 没有 scope.md → 红
            with open(os.path.join(tmp2, "scope.md"), "w", encoding="utf-8") as f:
                f.write("- 目标：x\n- 隔离方式：虚拟机（有快照）\n- 边界：不改系统级配置\n"
                        "- 期望做到哪一步：只能看懂结构\n")
            # 新口径正例：只写目标/隔离/边界/期望档位，**一个授权字段都不写** → 绿
            assert _scope_problems(tmp2) == []; checks += 1
            with open(os.path.join(tmp2, "scope.md"), "w", encoding="utf-8") as f:
                f.write("   \n")
            assert _scope_problems(tmp2); checks += 1          # 空文件（没记录边界）→ 红
            with open(os.path.join(tmp2, "scope.md"), "w", encoding="utf-8") as f:
                f.write("- 目标：x\n")
            assert _scope_problems(tmp2) == []; checks += 1    # 只有目标也算记录了边界
            with open(os.path.join(tmp2, "scope.md"), "w", encoding="utf-8") as f:
                f.write("- 目标：x\n- 授权来源：\n")
            assert _scope_problems(tmp2) == []; checks += 1    # 授权写空也不再拦
            with open(os.path.join(tmp2, "scope.md"), "w", encoding="utf-8") as f:
                f.write("- 目标：x\n- 授权来源：朋友给的\n")
            assert _scope_problems(tmp2) == []; checks += 1    # 不认识的授权来源也不拦
            with open(os.path.join(tmp2, "scope.md"), "w", encoding="utf-8") as f:
                f.write("- 目标：x\n- 隔离方式：实体机\n- 边界：不碰凭据\n"
                        "- 期望做到哪一步：能改到能用\n")
            assert _scope_problems(tmp2) == []; checks += 1    # 正常边界记录 → 绿
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
        # P0-2（第 3 轮评审）：repro 结构判据 = 结构完整 + 指纹像真 + 命令**真碰过目标**
        # （旧断言拿 `echo hi` 当正例 → 正是被评审打穿的口子，现按新语义改成反例）
        binfo = {"path": "D:/samples/target.bin", "name": "target.bin",
                 "sha256": "ab" * 32, "size": 0, "identity_scope": "file-bytes"}
        base = {"schema": "seep-case-repro/2", "kind": "repro",
                "cmd": "python t.py D:/samples/target.bin", "expect": "ok",
                "runs": 2, "digests": ["ab" * 32, "ab" * 32], "returncodes": [0, 0],
                "expect_ok": True, "consistent": True, "grade": "E2", "target": dict(binfo)}
        assert _is_complete_repro(base); checks += 1
        echo_rec = dict(base, cmd="echo hi", also_cmd="echo bye", grade="E3")
        assert not _is_complete_repro(echo_rec); checks += 1
        assert not _is_complete_e3(echo_rec); checks += 1
        # 哈希绑定要写成 `sha256:<前12位>`（只写裸哈希 = 看不出那是什么，不再算）
        assert _is_complete_repro(dict(base, cmd="python t.py sha256:abababababab")); checks += 1
        assert not _is_complete_repro(dict(base, cmd="python t.py abababababab")); checks += 1
        # echo 回显不计；cat 可以读取文件。文本检查仍不认证真实读取。
        assert not _is_complete_repro(dict(base, cmd="echo D:/samples/target.bin")); checks += 1
        assert _is_complete_repro(dict(base, cmd="cat D:/samples/target.bin")); checks += 1
        # 只写 basename 不够（旧判据被 `echo target.bin` 打穿）
        assert not _is_complete_repro(dict(base, cmd="python t.py target.bin")); checks += 1
        # 解释器命令里根本没提目标（`python -c "print(1)"`）→ 规则①就不过
        assert not _is_complete_repro(dict(base, cmd="python -c \"print(1)\"")); checks += 1
        # 交付闸传本案目标时，账本命令对不上目标 → 不算（防手写一条别的目标的 repro）
        other = {"path": "D:/samples/other.bin", "name": "other.bin", "sha256": "cd" * 32}
        assert not _is_complete_repro(base, other); checks += 1
        # E3：两路都碰目标才算；第二路不碰 → 拒
        e3 = dict(base, grade="E3", also_cmd="python t2.py D:/samples/target.bin",
                  also_digests=["cd" * 32, "cd" * 32], also_returncodes=[0, 0],
                  also_consistent=True, also_expect_ok=True)
        assert _is_complete_e3(e3); checks += 1
        assert not _is_complete_e3(dict(e3, also_cmd="echo bye")); checks += 1
        for k, v in (("cmd", ""), ("expect", ""), ("runs", 1),
                     ("digests", ["0123456789abcdef"]),
                     ("digests", ["a", "a"]),      # 占位指纹不再算
                     ("consistent", False), ("kind", "claim")):
            r = dict(base); r[k] = v
            assert not _is_complete_repro(r); checks += 1
        # P0-4：降级通知是客户话，不出现 M-/L- 内部代号
        _dn = _downgrade_notice("M2", "M1", "缺关键证据")
        assert "能改到能用" in _dn and "只能看懂结构" in _dn and "M2" not in _dn; checks += 1
        # R6 P1-5：档位映射表必须有 M4 这一行（客户话同 M3，内部靠证据门槛 E4 区分）
        assert LEVEL_CUSTOMER.get("M4") == "能完全自己接管"; checks += 1
        assert LEVEL_BAR.get("M4") == "E4" and LEVEL_BAR.get("M3") == "E3"; checks += 1
        assert RANK["M4"] > RANK["M3"] and len(LEVEL_BAR) == 4; checks += 1
        assert "M4" in RANK and _customer_level("m4") == "能完全自己接管"; checks += 1
        # R6 P0-4：deliver 的客户可见 stdout 不得出现 M1..M4 / L1..L3 / J1..J3（代号只进 stderr）
        import contextlib as _ctx
        import io as _io
        tmp4 = tempfile.mkdtemp(prefix="cs-r6-")
        try:
            save_state(tmp4, {"schema": "seep-case/1", "target": "x.bin", "depth": {},
                             "verdict": "可赢", "max_level": "M3", "stage": "0a",
                             "stage_history": [], "next_action": "x"})
            _evf = os.path.join(tmp4, "ev.log")
            with open(_evf, "w", encoding="utf-8") as _f:
                _f.write("rc=0\n")
            _ns = argparse.Namespace(case=tmp4, level="M1", evidence=_evf, note="")
            _buf, _err = _io.StringIO(), _io.StringIO()
            with _ctx.redirect_stdout(_buf), _ctx.redirect_stderr(_err):
                rc = cmd_deliver(_ns)
            _out = _buf.getvalue()
            assert rc in (0, None) and "[OK]" in _out; checks += 1
            assert not re.search(r"\b(?:M[1-4]|L[1-3]|J[1-3])\b", _out); checks += 1
            assert "M1" in _err.getvalue()          # 代号确实进了 stderr（没丢信息）
            checks += 1
            _buf2 = _io.StringIO()
            with _ctx.redirect_stdout(_buf2), _ctx.redirect_stderr(_io.StringIO()):
                cmd_show(argparse.Namespace(case=tmp4))
            _out2 = _buf2.getvalue()
            assert "上限：能完全自己接管" in _out2; checks += 1
            assert not re.search(r"\b(?:M[1-4]|L[1-3]|J[1-3])\b", _out2); checks += 1
            # R6 P1-4：写账本失败必须非零（用抛错的 `_tmp_sibling` 模拟只读目录）
            _real_tmp = globals()["_tmp_sibling"]

            def _boom(_path):
                raise OSError("readonly (simulated)")

            globals()["_tmp_sibling"] = _boom
            try:
                _b3 = _io.StringIO()
                with _ctx.redirect_stdout(_b3):
                    rc2 = cmd_claim(argparse.Namespace(
                        case=tmp4, id="C-900", text="模拟写账失败", status="hypothesis",
                        evidence="", how="", ttl="", by="", confidence="", authority=""))
                assert rc2 == 2 and "[ERR]" in _b3.getvalue(); checks += 1
            finally:
                globals()["_tmp_sibling"] = _real_tmp
        finally:
            shutil.rmtree(tmp4, ignore_errors=True)
        print(json.dumps({"ok": True, "checks": checks}, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "blocked_at": "self-test",
                          "reason": "%s: %s" % (type(exc).__name__, exc)}, ensure_ascii=True))
        return 2



# ─────────────────── 对话内 A/B/C 决策卡（可选工具，不强制） ───────────────────
#
# 这类长决策卡的适用边界：弹窗/GUI（ask_user_question 那类）有三个问题 ——
#   ① 选项只能 2–4 个、每项 ≤60 字，四要素长卡塞不进去；
#   ② 它是一等工具调用，会把「等人」变成「一次工具往返」，上下文里留一堆结构化噪声；
#   ③ 有些宿主只支持纯对话，不能稳定渲染原生提问。
# 因此提供可选方案：卡写文件 + 正文列 A/B/C + state 落 awaiting_human。
# 只有在确实需要用户事实/选择时使用；能由模型在既有授权内自主完成的动作不要求发卡。

def _ask_dir(case):
    d, _ = paths(case)
    p = os.path.join(d, "ask")
    os.makedirs(p, exist_ok=True)
    return p


@case_recovering
def cmd_ask(a):
    """按需发一张对话内 A/B/C 决策卡，并把案子置为 awaiting_human。"""
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
    if len({key for key, _ in parsed}) != len(parsed):
        die("选项字母不能重复；每个选项需要唯一字母。")

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

    st = load_state(a.case)
    from lib.case_lifecycle import publish_question
    try:
        _invalidate_run_ack()
    except OSError as exc:
        print("[ERR] 新 ASK 未提交：无法使旧宿主回执失效（%s）。" % exc)
        return 2
    fp = publish_question(a.case, st, lines,
                          {"since": now(), "stuck": a.stuck,
                           "options": {k: v for k, v in parsed}, "ack": None}, _case_api())

    # 给模型的下一个动作：把这段贴进对话；宿主已有等价结构化提问时可改用宿主能力。
    print("[ASK] 已生成卡片：%s" % fp)
    print("[ASK] 下面这段可直接贴进对话（不是强制提示词流程）：\n")
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


def _write_run_ack(case, letter, challenge=""):
    """给扩展用的回执标记（P0-4 机检配套）：原子写 ~/.seep/run-ack.json。

    schema=seep.run-ack/1；case = 该案绝对路径；target_sha256 = case.json 的 target.sha256
    （没登记就是空串）；letter = 用户回的字母；at = ISO8601（带 UTC 偏移）。
    """
    import datetime
    d = os.path.abspath(case) if case else ""
    challenge = str(challenge or "").strip().lower()
    if challenge and re.fullmatch(r"[0-9a-f]{64}", challenge) is None:
        return ""
    sha = ""
    try:
        from pathlib import Path
        from lib.case_repro import _local
        cjp = _local(Path(d), "case.json") if d else None
        if cjp is not None and cjp.is_file():
            with open(cjp, encoding="utf-8", errors="replace") as f:
                meta = json.load(f, object_pairs_hook=_case_ledger._unique)
            if not isinstance(meta, dict):
                raise ValueError("case.json must be an object")
            tgt = meta.get("target")
            if isinstance(tgt, dict):
                sha = str(tgt.get("sha256") or "").strip().lower()
                if sha and re.fullmatch(r"[0-9a-f]{64}", sha) is None:
                    raise ValueError("case.json target sha256 is malformed")
    except (OSError, ValueError):
        return ""
    payload = {"schema": "seep.run-ack/1", "case": d, "target_sha256": sha,
               "letter": letter,
               "challenge": challenge,
               "at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}
    p = os.path.join(os.path.expanduser("~"), ".seep", "run-ack.json")
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        _atomic_write_json(p, payload)   # tmp + fsync + os.replace：扩展读不到半截 JSON
        return p
    except OSError:
        return ""


def _invalidate_run_ack():
    """Make the previous host marker unusable before publishing a new ASK."""
    p = os.path.join(os.path.expanduser("~"), ".seep", "run-ack.json")
    try:
        os.remove(p)
    except FileNotFoundError:
        pass
    return p


@case_locked
def cmd_ack(a):
    """记录用户回执，解除 awaiting_human；同时写扩展读的 run-ack 标记。"""
    lease_guard(a.case)
    st = load_state(a.case)
    aw = st.get("awaiting_human")
    if not aw:
        die("当前没有等待中的卡（awaiting_human 为空）。先 ask。")
    letter = a.ack.strip().upper()
    if not re.fullmatch("[A-Z]", letter):
        die("回执必须是一个完整的选项字母。")
    opts = aw.get("options") or {}
    if opts and letter not in opts:
        die("回执 %r 不在选项里：%s" % (letter, " / ".join(opts.keys())))
    if aw.get("ack") and aw["ack"] != letter:
        die("该卡已有不同回执；需要改变决定时先发新卡，保留原回执。")
    backend = "facts.jsonl#state"
    if not aw.get("ack"):
        aw["ack"] = letter
        aw["acked_at"] = now()
        st["awaiting_human"] = aw
        st["next_action"] = "用户选了 %s：%s" % (letter, (opts.get(letter) or "")[:80])
        backend = save_state(a.case, st)
    challenge = str(getattr(a, "challenge", "") or "").strip().lower()
    if challenge and re.fullmatch(r"[0-9a-f]{64}", challenge) is None:
        die("--challenge 必须是 64 位小写 SHA-256（十六进制）。")
    rp = _write_run_ack(a.case, letter, challenge)
    if not rp:
        print("[ERR] 回执已落入案例账本，宿主标记写入失败；重试相同 ack 以恢复标记。")
        return 2
    print("[ACK] 已记录：%s -> %s（%s）" % (letter, opts.get(letter, ""), backend))
    print("[ACK] run-ack：%s" % (rp or "（写失败，不影响回执）"))
    print("[ACK] 现在可以从断点继续，不需要重头再来。")


# ---------------------------------------------------------------- 状态重放（S2-1）
def cmd_replay(a):
    """状态重放 / 迁移 / 压缩：state 不存快照，只由账本 state 行重放。

    --migrate      保存旧文件原字节、登记摘要；无现行状态时导入 state.json
    --drop-legacy  完成可恢复归档并核对后移除旧文件（历史内容仍保留）
    --compact      只保留最后一条 state 行（账本瘦身，claim/event 不动）

    为什么：快照与账本行是同一状态的两份副本，两端各自开局就会分叉；
    append-only 账本只多行、不少条，重放结果唯一。
    """
    d, fp = paths(a.case)
    if not os.path.isdir(d):
        die("case 目录不存在：%s" % d)
    if a.migrate or a.drop_legacy or a.compact:
        from lib.case_legacy import update
        try:
            archived = update(a.case, migrate=a.migrate, drop=a.drop_legacy, compact=a.compact,
                              load_ledger=load_ledger, lease_guard=lease_guard)
        except (OSError, ValueError, TimeoutError) as exc:
            die_json("legacy-migration", str(exc))
        for record in archived:
            print("[OK] 历史原字节已归档：%s → %s（状态策略=%s；旧文件移除=%s）"
                  % (record["source"], record["archive"], record["state_policy"], record["dropped"]))
        if a.compact:
            print("[OK] state 历史已压缩；保留行的原字节不变")
        if (a.migrate or a.drop_legacy) and not archived:
            print("[SKIP] 没有待迁移的历史文件")

    from pathlib import Path
    from lib.case_legacy import validate_archives
    from lib.project_transaction import pending
    try:
        if pending(Path(d)):
            raise ValueError("迁移中断尚未恢复；重试 replay --migrate 或 --drop-legacy 后再读取")
        ledger = load_ledger(a.case)
        validate_archives(a.case, ledger)
    except (OSError, ValueError) as exc:
        die_json("legacy-migration", str(exc))
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
# ├ 案例真实性四档 + 归档：real=客户真实目标 / public=公开可分发的真实产物（靶场·CTF·
#   公开 crackme·MIT 示例）/ self-built=自己编译 / fixture=合成夹具 / historical=历史归档。
#   语义唯一来源见 Tool/scripts/lib/domain_spec.py 的 EVIDENCE_KINDS 与 Tool/cases/README.md §2。
EVIDENCE_KIND_OK = ("real", "public", "self-built", "fixture", "historical")
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
    from pathlib import Path
    from lib.case_repro import _local, _plain
    from lib.project_lock import project_lock
    root = root or cases_root()
    entries, problems = [], []
    try:
        _plain(Path(root))
    except (OSError, ValueError) as exc:
        return [], [str(exc)]
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
            case_root = _plain(Path(d))
            with project_lock(case_root):
                with _local(case_root, "case.json").open(encoding="utf-8") as f:
                    raw = json.load(f, object_pairs_hook=_case_ledger._unique)
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
SEMANTIC_RC_RE = re.compile(
    r"(?im)^.*\b(?:rc|exit(?:_code| code)?|returncode|return code)\s*[=:]\s*(-?\d+)\b.*$")
SEMANTIC_ERROR_RE = re.compile(r"(?im)^\s*(?:\[ERROR\]|\[ERR\]|ERROR:)(?:\s|$)")
SEMANTIC_TRACEBACK_RE = re.compile(r"(?m)^\s*Traceback \(most recent call last\):\s*$")


def _contract_evidence_text(api, case, row, rows):
    """Return strict-contract evidence as text plus the exact files inspected."""
    from lib.case_evidence import resolve

    identities, errors = [], []
    for evidence in row.get("evidence") or []:
        try:
            identities.extend(resolve(api, case, evidence, rows=rows, strong=True))
        except (OSError, ValueError, TypeError, KeyError) as exc:
            errors.append("%s: %s" % (evidence, exc))
    if not identities:
        raise ValueError("strict evidence contract has no evidence file: %s"
                         % "; ".join(errors[:3]))

    texts, files = [], []
    seen = set()
    for identity in identities:
        scope = identity.get("scope")
        rel = str(identity.get("path") or "")
        if scope == "case":
            path = os.path.join(case, rel)
        elif scope == "work":
            path = os.path.join(REPO_ROOT, "work", rel)
        elif scope == "target":
            path = rel
        else:
            raise ValueError("invalid evidence scope in strict contract")
        key = _norm_path(path)
        if key in seen:
            continue
        seen.add(key)
        if not os.path.isfile(path):
            raise ValueError("strict evidence file disappeared: %s" % rel)
        size = os.path.getsize(path)
        if size > 8 << 20:
            raise ValueError("strict evidence file is too large to inspect as text: %s" % rel)
        with open(path, "rb") as stream:
            raw = stream.read()
        if b"\x00" in raw:
            raise ValueError("strict evidence must be textual, got binary file: %s" % rel)
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
        files.append(path)
        texts.append("### FILE: %s\n%s" % (rel, text))
    return "\n".join(texts), files


def _allow_line(line, patterns):
    return any(re.search(pattern, line) for pattern in patterns)


def _semantic_contract_problems(api, case, row, rows):
    """Mechanically check an opt-in strict evidence contract.

    Schema (all fields optional except ``version``)::

        "evidence_contract": {
          "version": 1,
          "require_text": ["literal output required by the claim"],
          "require_regex": ["regex output required by the claim"],
          "nonempty_sections": ["section heading"],
          "allow_traceback": false,
          "allow_nonzero_rc": false,
          "allow_error_lines": false,
          "reject_json_ok_false": true,
          "allow_traceback_patterns": ["EXPECTED_TRACEBACK"],
          "allow_nonzero_rc_patterns": ["negative control rc=2"],
          "allow_error_line_patterns": ["EXPECTED ERROR"]
        }

    The contract is deliberately opt-in.  It is used where a log mixes safe and
    failed subcommands: an excerpt from such a file must name the exact output it
    relies on, and any unhandled failure needs an explicit human-readable
    exception pattern.
    """
    contract = row.get("evidence_contract")
    if contract is None:
        return []
    if not isinstance(contract, dict) or contract.get("version") != 1:
        return ["evidence_contract must be a version-1 object"]
    problems = []
    list_fields = (
        "require_text", "require_regex", "nonempty_sections",
        "allow_traceback_patterns", "allow_nonzero_rc_patterns",
        "allow_error_line_patterns",
    )
    for field in list_fields:
        values = contract.get(field, [])
        if not isinstance(values, list) or any(
                not isinstance(value, str) or not value for value in values):
            problems.append("%s must be an array of nonempty strings" % field)
    for field in ("allow_traceback", "allow_nonzero_rc", "allow_error_lines",
                  "reject_json_ok_false"):
        if field in contract and not isinstance(contract[field], bool):
            problems.append("%s must be boolean" % field)
    if problems:
        return problems
    try:
        text, files = _contract_evidence_text(api, case, row, rows)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return [str(exc)]
    if not files:
        return ["strict contract resolved no files"]

    for value in contract.get("require_text") or []:
        if value not in text:
            problems.append("required output is missing: %r" % value)
    for value in contract.get("require_regex") or []:
        try:
            matched = re.search(value, text, re.MULTILINE)
        except re.error as exc:
            problems.append("invalid require_regex %r: %s" % (value, exc))
            continue
        if not matched:
            problems.append("required regex output is missing: %r" % value)
    for marker in contract.get("nonempty_sections") or []:
        start = text.find(marker)
        if start < 0:
            problems.append("required output section is missing: %r" % marker)
            continue
        tail = text[start + len(marker):]
        boundary = re.search(r"(?m)^#{2,3}\s+", tail)
        body = (tail[:boundary.start()] if boundary else tail).strip()
        if not body or body.lower() in ("(empty)", "empty", "<empty>"):
            problems.append("required output section is empty: %r" % marker)

    allow_tb = [str(x) for x in (contract.get("allow_traceback_patterns") or [])]
    if not contract.get("allow_traceback", False):
        for match in SEMANTIC_TRACEBACK_RE.finditer(text):
            tail = text[match.end():]
            next_heading = re.search(r"(?m)^#{2,3}\s+", tail)
            block_tail = tail[:next_heading.start()] if next_heading else tail
            block = match.group(0) + block_tail[:4000]
            if not _allow_line(block, allow_tb):
                problems.append("unhandled Traceback present in evidence")
                break

    allow_rc = [str(x) for x in (contract.get("allow_nonzero_rc_patterns") or [])]
    if not contract.get("allow_nonzero_rc", False):
        for match in SEMANTIC_RC_RE.finditer(text):
            try:
                rc = int(match.group(1))
            except (TypeError, ValueError):
                continue
            if rc != 0 and not _allow_line(match.group(0), allow_rc):
                problems.append("explicit non-zero return code in evidence: %s"
                                % match.group(1))
                break

    allow_error = [str(x) for x in (contract.get("allow_error_line_patterns") or [])]
    if not contract.get("allow_error_lines", False):
        for match in SEMANTIC_ERROR_RE.finditer(text):
            line_end = text.find("\n", match.start())
            line = text[match.start():line_end if line_end >= 0 else len(text)]
            if not _allow_line(line, allow_error):
                problems.append("ERROR output present in evidence")
                break

    if contract.get("reject_json_ok_false", False) and re.search(
            r'"ok"\s*:\s*false\b', text, re.IGNORECASE):
        problems.append("structured evidence reports ok=false")
    return problems


def _semantic_evidence_problems(case, facts, rows):
    api = _case_api()
    return {
        fact["id"]: problems
        for fact in facts
        if fact.get("status") == "proven"
        for problems in [_semantic_contract_problems(api, case, fact, rows)]
        if problems
    }


def _claim_evidence_problems(case, facts, rows=None):
    from lib.case_evidence import claim_files
    rows = load_ledger(case) if rows is None else rows
    problems = {}
    for fact in facts:
        if fact.get("status") != "proven":
            continue
        try:
            claim_files(_case_api(), case, fact, rows=rows, strong=False)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            problems[fact["id"]] = str(exc)
    return problems


def _acceptance_profile_problems(case, facts=None):
    """Case-level shape checks that make named APK acceptance non-optional."""
    try:
        meta = _case_metadata(case, missing_ok=True)
    except (OSError, ValueError) as exc:
        return ["case.json unreadable: %s" % exc]
    if meta is None:
        return []
    profile = str(meta.get("acceptance_profile") or "").strip()
    if not profile:
        return []
    if profile != "apk-target/1":
        return ["unknown acceptance_profile: %s" % profile]

    problems, registered_paths = [], []
    case_root = os.path.realpath(os.path.abspath(case))
    target_root = os.path.realpath(os.path.join(case_root, "target"))
    target = meta.get("target")
    if not isinstance(target, dict):
        problems.append("APK acceptance requires case.json target object")
    else:
        for key in ("path", "sha256", "size"):
            if target.get(key) in (None, ""):
                problems.append("APK acceptance requires target.%s" % key)
        sha = str(target.get("sha256") or "").strip().lower()
        if sha and not re.fullmatch(r"[0-9a-f]{64}", sha):
            problems.append("target.sha256 is malformed")
        size = target.get("size")
        if size not in (None, "") and (
                isinstance(size, bool) or not isinstance(size, int) or size < 0):
            problems.append("target.size must be a non-negative integer")
        registered_paths.append(("target", target))

    files = meta.get("target_files")
    if not isinstance(files, list) or not files:
        problems.append("APK acceptance requires non-empty target_files[]")
    else:
        for index, item in enumerate(files):
            if not isinstance(item, dict):
                problems.append("target_files[%d] must be an object" % index)
                continue
            for key in ("path", "sha256", "size"):
                if item.get(key) in (None, ""):
                    problems.append("target_files[%d].%s is required" % (index, key))
            registered_paths.append(("target_files[%d]" % index, item))
            sha = str(item.get("sha256") or "").strip().lower()
            if sha and not re.fullmatch(r"[0-9a-f]{64}", sha):
                problems.append("target_files[%d].sha256 is malformed" % index)
            size = item.get("size")
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                problems.append("target_files[%d].size must be a non-negative integer"
                                % index)
    for source, item in registered_paths:
        raw = str(item.get("path") or "").strip()
        if not raw:
            continue
        if os.path.isabs(raw) or URL_RE.match(raw):
            problems.append("APK acceptance %s.path must be case-relative" % source)
            continue
        resolved = os.path.realpath(os.path.join(case_root, raw))
        try:
            inside = os.path.commonpath([resolved, target_root]) == target_root
        except ValueError:
            inside = False
        if not inside:
            problems.append("APK acceptance %s.path must stay under case target/" % source)
    if profile and facts is not None:
        for fact in facts:
            if str(fact.get("status") or "").strip().lower() != "proven":
                continue
            contract = fact.get("evidence_contract")
            if not isinstance(contract, dict) or contract.get("version") != 1:
                problems.append(
                    "APK proven claim %s requires evidence_contract version 1"
                    % fact.get("id"))
                continue
            checks = (
                contract.get("require_text"),
                contract.get("require_regex"),
                contract.get("nonempty_sections"),
            )
            if not any(isinstance(value, list) and value for value in checks):
                problems.append(
                    "APK proven claim %s requires a machine-checkable output assertion"
                    % fact.get("id"))
    return problems


@_case_ledger.locked
def verify_case(case):
    """单案聚合：返回 {verdict: pass|fail|unknown, reasons, counts}。"""
    facts = load_facts(case)
    st = load_state(case)
    rows = load_ledger(case)
    evidence_errors = _claim_evidence_problems(case, facts, rows)
    semantic_errors = _semantic_evidence_problems(case, facts, rows)
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
            if str(f.get("authority") or "none").strip().lower() in ("", "none", "reported"):
                noauth.append(str(f.get("id")))
    proven = sum(1 for f in facts if str(f.get("status") or "").lower() == "proven")
    from lib.case_evidence import claim_files
    strong = 0
    for fact in facts:
        if fact["status"] != "proven" or _norm_confidence(fact.get("confidence")) not in STRONG_CONFIDENCE \
                or fact.get("authority") not in ("shipped-artifact", "controlled-replay", "external-service"):
            continue
        try:
            claim_files(_case_api(), case, fact, rows=rows)
            strong += 1
        except (OSError, ValueError, TypeError, KeyError) as exc:
            evidence_errors[fact["id"]] = str(exc)
    fail_reasons, unknown_reasons = [], []
    profile_errors = _acceptance_profile_problems(case, facts)
    fail_reasons.extend("acceptance profile: %s" % problem
                        for problem in profile_errors)
    for k in sorted(bad):
        fail_reasons.append("%s=%d（任一非零即不得 pass）" % (k, bad[k]))
    if stale:
        fail_reasons.append("stale 未复验：" + "、".join(stale))
    fail_reasons.extend("%s evidence: %s" % item for item in evidence_errors.items())
    fail_reasons.extend("%s semantic evidence: %s" % item
                        for item in semantic_errors.items())
    if not facts:
        unknown_reasons.append("账本无 claim（facts 为空）→ unknown，不得计 pass")
    elif not proven:
        unknown_reasons.append("没有 proven claim")
    # 弱证据不算 pass 证据，但**不把整案拖成 unknown**：它们被"排除在证据集外"并明示出来。
    # 判据（与 pack.json 的 evidence_contract.pass_forbids_confidence 一致）：
    #   pass = 无 fail 类状态 + ≥1 条 observed/derived 背书；inferred/unknown 的 proven 只进 excluded。
    excluded = weak + noauth
    if facts and strong == 0:
        unknown_reasons.append("没有 observed/derived 背书（%d 条 claim 全是 inferred/unknown）" % len(facts))
    verdict = "fail" if fail_reasons else ("unknown" if unknown_reasons else "pass")
    return {"case": os.path.basename(os.path.abspath(case)), "verdict": verdict,
            "claims": len(facts), "proven": proven, "strong": strong,
            "confidence": counts, "bad": bad, "stale": stale, "excluded": excluded,
             "evidence_errors": evidence_errors,
             "semantic_errors": semantic_errors,
             "acceptance_profile_errors": profile_errors,
             "evidence_scope": "recorded bytes where bound; otherwise current local material only",
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
    problems = []
    if getattr(a, "all", False):
        root = cases_root()
        entries, problems = scan_cases(root)
        targets = [os.path.join(root, entry["dir"]) for entry in entries]
    else:
        if not (getattr(a, "case", "") or "").strip():
            die("verify 需要 --case <目录> 或 --all")
        targets = [a.case]
    results = [verify_case(t) for t in targets]
    if getattr(a, "json", False):
        print(json.dumps({"schema": "seep.verify/1", "results": results, "problems": problems},
                         ensure_ascii=False, indent=2))
    else:
        for problem in problems:
            print("[FAIL] 案例索引：%s" % problem)
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
    return 0 if results and not problems and all(r["verdict"] == "pass" for r in results) else 1


def _receipt_for_case(case_name, receipt_path=""):
    """Resolve one existing verification receipt without inventing a new delivery."""
    if receipt_path:
        path = receipt_path if os.path.isabs(receipt_path) else os.path.join(REPO_ROOT, receipt_path)
        return os.path.abspath(path)
    directory = os.path.join(REPO_ROOT, "docs", "verification")
    if not os.path.isdir(directory):
        return ""
    prefix = case_name + "-"
    found = sorted(
        os.path.join(directory, name)
        for name in os.listdir(directory)
        if name.startswith(prefix) and name.endswith(".json")
    )
    return found[-1] if found else ""


def _receipt_hash_sources(case_dir, registered):
    """Rehash only sources already bound by the receipt, before any receipt write."""
    if not isinstance(registered, dict) or not registered:
        die("回执的 source_sha256 必须是非空对象；不能凭空创建交付证据")
    case_root = os.path.realpath(os.path.abspath(case_dir))
    hashes = {}
    for relative, declared in sorted(registered.items()):
        if not isinstance(relative, str) or not relative.strip() or "\0" in relative:
            die("source_sha256 含无效路径")
        if os.path.isabs(relative) or URL_RE.match(relative):
            die("source_sha256 只接受案例内相对路径：%s" % relative)
        if not isinstance(declared, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", declared):
            die("source_sha256.%s 不是 64 位 SHA-256" % relative)
        path = os.path.realpath(os.path.join(case_root, relative.replace("/", os.sep)))
        try:
            inside = os.path.commonpath([case_root, path]) == case_root
        except ValueError:
            inside = False
        if not inside or path == case_root:
            die("source_sha256.%s 越出案例目录" % relative)
        if os.path.islink(os.path.join(case_dir, relative.replace("/", os.sep))):
            die("source_sha256.%s 不得经过链接" % relative)
        if not os.path.isfile(path):
            die("source_sha256.%s 不存在或不是普通文件" % relative)
        digest = hashlib.sha256()
        try:
            with open(path, "rb") as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
        except OSError as exc:
            die("source_sha256.%s 无法读取：%s" % (relative, exc))
        hashes[relative] = digest.hexdigest()
    if "facts.jsonl" not in hashes:
        die("回执必须绑定本案 facts.jsonl")
    return hashes


def cmd_receipt_refresh(a):
    """Refresh an existing receipt from current bytes, preserving its audit history.

    This command does not run a target or create evidence.  It only recomputes the
    claim cohort and the hashes already registered by the receipt, then records the
    previous final/hash pair and the operator's reason in audit_corrections.
    """
    case_dir = os.path.abspath(a.case)
    if not os.path.isdir(case_dir):
        die("case 目录不存在：%s" % case_dir)
    reason = str(getattr(a, "reason", "") or "").strip()
    if not reason:
        die("receipt-refresh 必须用 --reason 说明为什么刷新")
    case_name = os.path.basename(case_dir)
    receipt_path = _receipt_for_case(case_name, getattr(a, "receipt", "") or "")
    if not receipt_path or not os.path.isfile(receipt_path):
        die("找不到 %s 的既有 verification receipt（不会自动创建）" % case_name)
    if os.path.islink(receipt_path):
        die("verification receipt 不得经过链接")
    try:
        with open(receipt_path, encoding="utf-8") as stream:
            receipt = json.load(stream, object_pairs_hook=_case_ledger._unique)
    except (OSError, ValueError) as exc:
        die("verification receipt 无法读取：%s" % exc)
    if not isinstance(receipt, dict):
        die("verification receipt 顶层必须是对象")
    if receipt.get("schema") != "seep.verification/1" or receipt.get("case") != case_name:
        die("verification receipt 的 schema/case 与当前案例不一致")
    cohorts = receipt.get("cohorts")
    if not isinstance(cohorts, dict) or not isinstance(cohorts.get("baseline"), dict) \
            or not isinstance(cohorts.get("final"), dict):
        die("verification receipt 缺 cohorts.baseline/final")
    for key in ("problem", "interpretation"):
        if not isinstance(receipt.get(key), str) or not receipt[key].strip():
            die("verification receipt 的 %s 必须是非空字符串" % key)

    result = verify_case(case_dir)
    new_final = {
        "claims": result["claims"],
        "proven": result["proven"],
        "strong": result["strong"],
        "verdict": result["verdict"],
    }
    old_final = dict(cohorts["final"])
    old_hashes = receipt.get("source_sha256")
    new_hashes = _receipt_hash_sources(case_dir, old_hashes)
    counts_equal = all(old_final.get(key) == value for key, value in new_final.items())
    hashes_equal = old_hashes == new_hashes
    refreshed = not (counts_equal and hashes_equal)
    if refreshed:
        corrections = receipt.get("audit_corrections")
        if corrections is None:
            corrections = []
        if not isinstance(corrections, list):
            die("verification receipt 的 audit_corrections 必须是数组")
        corrections = list(corrections)
        corrections.append({
            "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "kind": "receipt-byte-refresh",
            "reason": reason,
            "previous_final": old_final,
            "previous_source_sha256": old_hashes,
            "new_final": new_final,
            "new_source_sha256": new_hashes,
            "validation": (
                "case_state.verify_case recomputed the claim cohort; SHA-256 was "
                "recomputed from current case bytes"
            ),
            "new_target_measurements": False,
            "target_executed": False,
        })
        receipt["cohorts"]["final"] = new_final
        receipt["source_sha256"] = new_hashes
        receipt["audit_corrections"] = corrections
        _atomic_write_text(
            receipt_path,
            json.dumps(receipt, ensure_ascii=False, indent=2) + "\n",
        )

    payload = {
        "ok": True,
        "case": case_name,
        "receipt": os.path.abspath(receipt_path),
        "refreshed": refreshed,
        "previous_final": old_final,
        "final": new_final,
        "source_sha256": new_hashes,
        "target_executed": False,
        "new_target_measurements": False,
    }
    if getattr(a, "json", False):
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print("[%s] %s" % ("REFRESHED" if refreshed else "CURRENT", receipt_path))
        print("  final: claims=%d proven=%d strong=%d verdict=%s" % (
            new_final["claims"], new_final["proven"], new_final["strong"],
            new_final["verdict"]))
    return 0


def main():
    if "--self-test" in sys.argv[1:]:
        sys.exit(_self_test())
    ap = argparse.ArgumentParser(description="案子事实账 / 深度门 / 可行性裁定 / 出口闸")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init"); p.add_argument("--case", required=True)
    p.add_argument("--target", default=""); p.add_argument("--force", action="store_true")
    p.add_argument("--domain", default="",
                   help="判型结果（如 softseep / web-pentest / pwn-crypto）。缺省空串 = 未判型，"
                        "不是「默认 softseep」；判型：python Tool/scripts/route.py --resolve \"<目标名 + 任务名>\"")
    # ★ 2026-10-26 审计（R8-P1-4）：默认曾是 "real"，新案不填就被当成"客户真实目标"，
    #   等于白送该域一个"真实产物见证"。改成无默认值：不填 = 未声明（不计可用）。
    p.add_argument("--evidence-kind", dest="evidence_kind", default="",
                   choices=["real", "public", "self-built", "fixture", "historical"],
                   help="案例真实性（real=客户目标 / public=公开真实产物 / self-built=自己编译"
                        " / fixture=合成夹具 / historical=历史归档）。不填=未声明，不计该域可用")
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
    p.add_argument("--adhoc", default="",
                   help="确实不建案时给原因（>=6 字）；标记写 adhoc=true，不得用于交付")
    p.set_defaults(func=cmd_answer)
    p = sub.add_parser("block")
    p.add_argument("--code", default=""); p.add_argument("--case", default="")
    p.add_argument("--detail", default=""); p.add_argument("--why", default=""); p.add_argument("--got", default="")
    p.add_argument("--list", action="store_true"); p.set_defaults(func=cmd_block)
    p = sub.add_parser("repro")
    p.add_argument("--case", default=""); p.add_argument("--id", default="")
    p.add_argument("--cmd", default=""); p.add_argument("--expect", default="")
    p.add_argument("--runs", type=int, default=2); p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--also-cmd", dest="also_cmd", default="", help="第二路不同命令（两路各至少两次成功、一致、命中预期才可 E3；不认证实现独立）")
    p.add_argument("--out", default="",
                   help="捕获目录（须在案件目录内，无链接）；默认 capture/repro，两路 stdout/stderr 和退出码均入库")
    p.add_argument("--adhoc", default="",
                   help="不带 --case 时的 adhoc 原因（不绑目标、标 [ADHOC]、不得用于交付）")
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
    p.add_argument("--acceptance-project", dest="acceptance_project", default="",
                   help="端到端交付项目目录（其 E4 验收链是唯一来源）")
    p.add_argument("--acceptance-version", dest="acceptance_version", default="",
                   help="端到端交付绑定的项目版本")
    p.set_defaults(func=cmd_deliver)

    p = sub.add_parser("ask", help="按需发一张对话内 A/B/C 决策卡（可选，不强制）")
    p.add_argument("--case", required=True)
    p.add_argument("--stuck", required=True, help="一句话：卡在哪")
    p.add_argument("--option", action="append", help='形如 "A 你自己双击启动目标"；至少两个')
    p.add_argument("--monitor", default="", help="我这边正在监控什么")
    p.add_argument("--guarantee", default="不动鼠标键盘、不改系统设置、不主动联网")
    p.add_argument("--expect", default="", help="我拿到什么")
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("ack", help="记录决策卡回执（回一个字母），解除 awaiting_human")
    p.add_argument("--case", required=True)
    p.add_argument("--ack", required=True)
    p.add_argument("--challenge", default="", help="系统级临时放行所批准命令的 SHA-256")
    p.set_defaults(func=cmd_ack)

    p = sub.add_parser("replay", help="状态重放：state 不存快照，由账本 state 行重放（--migrate/--drop-legacy/--compact）")
    p.add_argument("--case", required=True)
    p.add_argument("--migrate", action="store_true", help="归档旧文件原字节并登记；仅无当前状态时导入 state.json")
    p.add_argument("--drop-legacy", dest="drop_legacy", action="store_true", help="核对可恢复归档后移除旧副本（state.json / ai_manifest.json）")
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

    p = sub.add_parser(
        "receipt-refresh",
        help="按当前事实账和既有回执绑定文件重算回执；不运行目标、不新建交付证据",
    )
    p.add_argument("--case", required=True)
    p.add_argument("--receipt", default="",
                   help="指定既有回执（默认 docs/verification/<case>-*.json 最新一份）")
    p.add_argument("--reason", required=True, help="为什么当前字节变化后需要刷新")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_receipt_refresh)

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
