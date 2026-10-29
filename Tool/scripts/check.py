#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一条命令跑完全部检查（程序员视角：这就是 `make test`）。

为什么要有这个文件（2026-10-24）：之前在 AGENTS / README / 对话里出现 6 条命令、163 项"门禁"，
使用者根本不知道"合格"指什么。真正的程序员做法是：**一个入口，退出码，失败指到文件**。

用法：
    python Tool/scripts/check.py            # 全量（逐套件打印实际耗时）
    python Tool/scripts/check.py --runtime --json  # 当前运行实现与全部专项回归；不使用旧开发文档判据
    python Tool/scripts/check.py --fast --json  # 快速套件结果（JSON；退出码仍按 WARN/跳过语义）
    python Tool/scripts/check.py --fast --strict # 明确按交付门禁处理 WARN/跳过/未验证
    python Tool/scripts/check.py --fix      # 只重生成**生成物**（docs/HANDOFF.md 状态块）；不改期望值

`--fix` / `--prep` 的边界（第 4 轮评审 P1-1；REQUIREMENTS.md 的基线规则）：
    **只许重生成生成物，不许把期望值改成当前实测。**
    - 会改：docs/HANDOFF.md 的 §1 状态块（它就是 `case_state.py handoff --repo` 的输出，
      标着「生成，勿手改」；不改它就必然红「落后 ≤1 提交」）。
    - 不会改：MANUAL/BASELINE-FREEZE.md 里的 first-party 文件数等**期望值**。
      检测到漂移时只打印漂移 + 修法，让人自己决定改数字还是改代码。
      理由：期望值一旦被脚本跟着实测跑，「基数在涨」就永远绿 —— 判据变成自证。

退出码：0 = 所有纳入本次检查的套件通过且没有 WARN/跳过；1 = 有失败；2 = 有 WARN、未验证或被 --fast 跳过的套件。WARN/跳过不能作为交付成功。unit（gate.py --all）返回 3 表示结构通过但可用性未证明，汇总为未验证并返回非零。
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PY = sys.executable

# 中文 Windows 控制台默认 cp936/GBK：本脚本自己会打中文与 ✓/✗，子脚本还会打 emoji，
# 不重建 stdout/stderr 就会自崩（F1）。errors="replace" 保证只影响显示、不影响判定。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 —— 流被替换/已被关闭时忽略
        pass

# 所有子进程统一走这个 env：一次修好全部子脚本，而不是逐个改。
# 没有它：任何子脚本 print 一个非 GBK 字符（✓/✗/emoji/中文标点）就会 UnicodeEncodeError，
# 而套件失败原因只会显示“Traceback …”，误号得像真问题。
CHILD_ENV = dict(os.environ, PYTHONIOENCODING="utf-8")

# (名字, 命令参数, 是否属于 fast, 失败时给人看的一句话)
SUITES = [
    ("lint",        ["Tool/scripts/preflight.py", "--fast"], True,
     "结构/契约/入口/部署的一致性检查"),
    ("tool-contract", ["Tool/scripts/tool-contract-check.py", "--json"], True,
     "静态工具契约：pack.tools → MCP 注册 → effects → runtime/capability → mcp-servers"),
    ("domain-contract", ["Tool/scripts/domain-contract-check.py", "--strict", "--json"], True,
     "静态领域契约：pack id → 四份域索引 → 案例 glob → 技能/部署在场"),
    ("domain-adapter", ["Tool/scripts/domain-adapter-check.py", "--strict"], True,
     "长期领域适配器契约：项目生命周期、输入、路线、证据、验收、失败、版本、扩展入口"),
    ("skill-tests", ["Tool/skill/softseep/scripts/intent-coverage.py", "--json"], True,
     "意图探针：用户说法能否命中对应技能"),
    ("kb-colloquial", ["Tool/scripts/test_kb_colloquial.py"], True,
     "口语检索：12 条大白话能否落到真实文章（别名表 + CJK 2-gram，门槛 >=10/12）"),
    ("route-tests", ["Tool/skill/softseep/scripts/skill-route-probe.py", "--json"], True,
     "路由探针：技能路由在中文边界上的行为"),
    ("rewrite-parity", ["Tool/scripts/rewrite-route-parity.py", "--json"], True,
     "改写同域：客户原话被安全词表改写后仍落原域（词表从 .ts 现读，不做 Python 抄本）"),
    ("mcp-smoke",   ["Tool/mcp/test_seep_mcp.py"], True,
     "当前 MCP 服务入口与基础工具真实烟测（缺关键环境返回未验证）"),
    ("mcp-ext-assets", ["Tool/mcp/test_ext_assets.py"], True,
     "当前扩展 MCP 工具注册、发现隔离、参数拒绝与凭据脱敏"),
    ("project-lifecycle", ["Tool/scripts/project_state.py", "--self-test"], True,
     "长期项目生命周期：project/version/run/migration/handoff 自测"),
    ("manager-state", ["Tool/scripts/manager_state.py", "--self-test"], True,
     "Manager Mode 事件状态：intake/plan/choose/wait/answer/attempt/replan/handoff 自测"),
    # ── 专项回归：这几条覆盖审计已复现过的真实缺陷，不能只靠各脚本 --self-test ──
    ("evidence-contract", ["Tool/scripts/test_evidence_contract.py"], True,
     "证据契约：G5 逐条执行 required_fields（缺/空 claim、evidence 类型）、hypothesis 不计 strong、G6 回执计数/hash 漂移"),
    ("runtime-registration", ["Tool/scripts/test_runtime_registration.py"], True,
     "运行时注册：rabin2/java 独立条目被真消费端读到、effects 与实现一致"),
    ("runtime-root", ["Tool/scripts/test_runtime_root.py"], True,
     "真实运行目录、注册漂移与部署入口回归"),
    ("env-readiness", ["Tool/scripts/test_env_readiness.py"], True,
     "最终 MCP 配置握手、服务身份与部署文件完整性"),
    ("config-merge", ["setup/test_merge_agent_config.py"], True,
     "配置预览不落盘、原子替换、备份与用户设置保留"),
    ("upstream-sync", ["setup/test_sync_upstream.py"], True,
     "同步失败传播、手动源跳过、目标边界与两平台验证入口"),
    ("source-format", ["setup/test_clean_format.py"], True,
     "格式化只修改源码文本，语法失败返回非零"),
    ("tool-discovery", ["Tool/scripts/test_tool_discovery.py"], True,
     "Python 库导入与 CLI 发现分离、安装后真实重验"),
    ("skill-deployment", ["Tool/scripts/test_skill_deployment.py"], True,
     "安装副本从中性工作目录定位注册源码，坏注册返回修复提示"),
    ("skill-handoffs", ["Tool/scripts/skill-handoff-check.py"], True,
     "活跃技能交接目标可解析，归档参考使用明确源码路径"),
    ("skill-handoff-tests", ["Tool/scripts/test_skill_handoffs.py"], True,
     "缺失交接目标与旧技能名不能误报通过"),
    ("tool-dependencies", ["Tool/scripts/test_tool_dependencies.py"], True,
     "工具依赖声明：20 个 @server.tool() 的 all_of/any_of 逐项有来源、registry_gap/L0 不被布尔掩盖"),
    ("manager-integration", ["Tool/scripts/test_manager_integration.py"], True,
     "Manager 集成：敏感事件拒绝、跨进程锁、generation 隔离、证据哈希绑定、check-action（合成项目内）"),
    ("project-integration", ["Tool/scripts/test_project_integration.py"], True,
     "项目生命周期集成：project/version/run/migration/handoff 的跨进程真实 CLI 行为"),
    ("project-acceptance", ["Tool/scripts/test_project_acceptance.py"], False,
     "验收登记链：evidence→acceptance→finish-run 完成门、篡改失效、跨版本/跨 run、6 并发恰 1 成功（full-only，较慢）"),
    ("project-acceptance-integrity", ["Tool/scripts/test_acceptance_integrity.py"], False,
     "验收绕过回归：手写 pass 无记录链、伪 target_sha256、删/剥 revisions 历史、完成后改 closure/快照、洗白重录（full-only，较慢）"),
    ("acceptance-presence", ["Tool/scripts/test_acceptance_presence.py"], False,
     "验收材料存在性与幂等重放：缺历史/坏 live 拒绝且无半写"),
    ("run-acceptance-history", ["Tool/scripts/test_run_acceptance_history.py"], False,
     "后续运行/验收修订不覆盖已完成运行消费的见证"),
    ("terminal-history", ["Tool/scripts/test_terminal_history.py"], False,
     "终态历史不可降级或擦除，并发完成保持唯一"),
    ("project-workflow", ["Tool/scripts/test_project_workflow.py"], False,
     "自然语言入口、真实受控解析、capture、失败转向与关闭运行"),
    ("typed-assets", ["Tool/scripts/test_typed_assets.py"], False,
     "文件/目录快照/URL描述身份、路径边界与篡改检测"),
    ("project-typed-inputs", ["Tool/scripts/test_project_typed_inputs.py"], False,
     "三类材料贯穿Core/Manager/Workflow/Report，主辅资产与类型早拒"),
    ("project-report", ["Tool/scripts/test_project_report.py"], False,
     "报告原始登记见证、历史适用性、handoff与损坏传播"),
    ("report-claim-ledger", ["Tool/scripts/test_report_claim_ledger.py"], False,
     "专业结论账支持关系、强弱分类、篡改复查与拒绝无残留"),
    ("project-archive", ["Tool/scripts/test_project_archive.py"], False,
     "归档成员指纹/CRC/资源边界、空目录闭包与移位恢复"),
    ("version-migrate-delivery", ["Tool/scripts/test_version_migrate_delivery.py"], False,
     "实际追版四态、基线复核与部署副本runtime定位"),
    ("runtime-install-delivery", ["Tool/scripts/test_runtime_install_delivery.py"], False,
     "临时目录实际安装/注册、显式AgentRoot与更新卸载保留用户材料"),
    ("runtime-shell-delivery", ["Tool/scripts/test_runtime_shell_delivery.py"], False,
     "Shell入口复用同一runtime注册规则、离线更新与卸载边界"),
    ("source-inventory", ["Tool/scripts/test_source_inventory.py"], False,
     "源清单完整性、第三方输入来源锚点、first-party预算与gitless移位核验"),
    ("tool-autonomy", ["Tool/scripts/test_tool_autonomy.py"], True,
     "工具自治锁：用工具静默（MCP/工具链/技能脚本）、只有跑本案目标才要回执"),
    ("read-guard",  ["Tool/scripts/test_read_guard.py"], True,
     "读守卫：个人隐私区路径拦、正常目标/案件路径放行"),
    ("pre-upload",  ["Tool/scripts/pre-upload-check.py"], True,
     "上传前体检：会进 git 的敏感文件 / 本机不该外带的目录 / 内容级凭据命中（只报文件:行+类型）"),
    ("tool-readiness", ["Tool/scripts/tool-readiness.py"], True,
     "六工具就绪表：探测/安装计划/自检机制可用（不要求本机 6 个都 READY）"),
    ("invariants",  ["Tool/scripts/invariants.py", "--check"], True,
     "架构不变量：11 域 × 9 条（入口唯一/能力可达/交接闭包/证据同构/等级唯一/失败可表达/见证可跑/部署等价/能力有路线）"),
    ("gate-tests",  ["Tool/scripts/test_gates.py"], True,
     "闸的行为测试：首答闸 9 + 运行回执闸 6 + 写守卫 4 + cmd-guard 8 + 熔断合法出口 2（node 真跑 TS 纯函数；缺 node 直接 FAIL）"),
    ("unit",        ["Tool/scripts/gate.py", "--all"], True,
     "按域判定：9 个能力包各自的门槛与证据强度"),
    ("e2e",         ["Tool/scripts/domain-gate.py", "--all"], False,
     "端到端：域契约、证据链、清理、部署哈希"),
    ("kb-tests",    ["Tool/scripts/kb_acceptance.py"], False,
     "知识库检索验收语料"),
    ("mutation",    ["Tool/scripts/mutation.py"], False,
     "植入失败：故意弄坏 6 处，证明判据真的会红（约 3 分钟）"),
]


def runtime_suites():
    """Source/runtime acceptance, independent of historical development documents.

    Discover every top-level runtime regression so adding a test cannot silently
    leave it outside the aggregate check. Current MCP smoke and contract
    regressions are listed explicitly below.
    """
    required = {
        "tool-contract", "domain-contract", "domain-adapter", "skill-tests",
        "route-tests", "pre-upload", "invariants", "unit", "e2e",
    }
    suites = [
        ("route", ["Tool/scripts/route.py", "--check"], True, "领域路由"),
        ("skill-handoff-links", ["Tool/scripts/skill-handoff-check.py"], True, "技能交接闭包"),
        ("doc-install-entries", ["Tool/scripts/lib/doc_commands.py", "--json"], True, "安装文档路径、链接与命令参数"),
        *[s for s in SUITES if s[0] in required],
        ("capability-compose", ["Tool/skill/softseep/scripts/capability-gate.py", "--json"], True, "能力组合与成熟度声明"),
    ]
    tests = sorted(Path(ROOT, "Tool/scripts").glob("test_*.py"))
    tests += sorted(Path(ROOT, "setup").glob("test_*.py"))
    tests += [Path(ROOT, p) for p in (
        "Tool/mcp/test_seep_mcp.py",
        "Tool/mcp/test_ext_assets.py",
        "Tool/mcp/test_pcap_contract.py",
        "Tool/mcp/test_readonly_parameters.py",
        "Tool/mcp/test_apk_contract.py",
    )]
    suites.extend((p.stem.removeprefix("test_").replace("_", "-"),
                   [p.relative_to(ROOT).as_posix()], True, "当前实现专项回归") for p in tests)
    return suites


RUNTIME_TIMEOUTS = {
    # Full-domain and all-pack gates inspect and re-hash hundreds of files.
    "unit": 900,
    "e2e": 1800,
    "pre-upload": 600,
    "invariants": 900,
    "mutation": 1800,
}


def runtime_timeout(name):
    """Seconds for an explicitly included expensive runtime suite."""
    return RUNTIME_TIMEOUTS.get(name, 600)


def report_baseline_drift():
    """检测 BASELINE-FREEZE 的期望值与实测是否漂移 —— 只报修法，绝不写文件。"""
    import re as _re
    bp = os.path.join(ROOT, "MANUAL", "BASELINE-FREEZE.md")
    try:
        p = subprocess.run([PY, os.path.join(ROOT, "Tool", "scripts", "preflight.py"), "--fast"],
                           cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=300,
                           env=CHILD_ENV).stdout
    except Exception as e:  # noqa: BLE001
        print("[BASELINE] 漂移检测未完成（%s）：未写入任何文件" % str(e)[:60])
        return
    drift = [l.strip() for l in (p or "").splitlines() if "BASELINE-FREEZE:" in l]
    if not drift:
        print("[BASELINE] 无漂移（期望值与实测一致，或本轮没跑到该项）")
        return
    print("[BASELINE] 检测到漂移（只报，不改）：")
    for d in drift:
        print("  - " + d)
    m = _re.search(r"first-party\s*写\s*(\d+)[^0-9]*(\d+)", " ".join(drift))
    expect, actual = (m.group(1), m.group(2)) if m else ("<写死值>", "<实测值>")
    line_no = "?"
    try:
        # 取**度量行**（形如 `| first-party 文件（口径…） | 940 | **950** |`）：
        # 只写“first-party 文件数”的叙述行不能当成那个格子。
        for i, ln in enumerate(open(bp, encoding="utf-8", errors="replace").read().splitlines(), 1):
            if "first-party" in ln and _re.search(r"\|\s*\d{1,5}\s*\|", ln):
                line_no = str(i)
                break
    except Exception:  # noqa: BLE001
        pass
    print("[BASELINE] 拒绝改期望：期望值 %s / 实测 %s —— 脚本不替人改基线（REQUIREMENTS.md 的基线规则）"
          % (expect, actual))
    print("[BASELINE] 修法（二选一，都由人决定并留下理由）：")
    print("  1) 这次增长/收缩是**有意**的 → 手工改 %s:%s 把 %s 改成 %s，"
          "并在 docs/CHANGELOG.md 记一条为什么放宽/收紧；"
          % (os.path.join("MANUAL", "BASELINE-FREEZE.md"), line_no, expect, actual))
    print("  2) 是**意外**新增文件 → 不要动基线：把多出来的文件删掉或加进 .gitignore，"
          "让实测回到 %s；" % expect)
    print("  复核：python Tool/scripts/preflight.py --fast 2>&1 | grep BASELINE")
    print("[BASELINE] 未写入任何文件（--fix 只重生成生成物，不改期望）")


def run_one(name, argv, timeout=600, allow_rc=(0,)):
    t0 = time.time()
    isolated_home = None
    child_env = CHILD_ENV
    if any(str(arg).startswith("Tool/mcp/test_") for arg in argv):
        isolated_home = tempfile.TemporaryDirectory(prefix="seep-mcp-test-home-")
        home = os.path.abspath(isolated_home.name)
        child_env = dict(
            CHILD_ENV,
            HOME=home,
            USERPROFILE=home,
            APPDATA=os.path.join(home, "AppData", "Roaming"),
            LOCALAPPDATA=os.path.join(home, "AppData", "Local"),
            XDG_CONFIG_HOME=os.path.join(home, ".config"),
            SEEP_AGENT_MCP=os.path.join(home, "mcp.json"),
            SEEP_CASE_DIR=os.path.join(home, "cases"),
            SEEP_WORKSPACE=os.path.join(home, "work"),
            SEEP_AUTOCASE="0",
        )
        for key in ("APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME"):
            os.makedirs(child_env[key], exist_ok=True)
    try:
        p = subprocess.run([PY] + argv, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout,
                           env=child_env)
        out = (p.stdout or "") + (p.stderr or "")
        rc = p.returncode
    except subprocess.TimeoutExpired:
        return name, False, "超时（>%ds）" % timeout, time.time() - t0, -1, ""
    finally:
        if isolated_home is not None:
            isolated_home.cleanup()
    if "--json" in argv and "{" in out:
        import json as _j
        try:
            d = _j.loads(out[out.index("{"):])
            if isinstance(d, dict) and "ok" in d:
                return name, rc in allow_rc and d.get("ok") is True, "ok=%r" % d.get("ok"), time.time() - t0, rc, out
        except Exception:
            pass
    # 取最后一行有信息量的输出（各脚本末行通常是「结果: x/y」或 [GATE] …）
    # gate.py 现在会在 pass/fail 之后追加「见证证据 real/public/self-built/fixture」几行；
    # 摘要必须仍取带 pass/fail 的判定行，不能取到分档清单（否则 check.py 的 tail 会说假话）。
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    tail = ""
    for l in reversed(lines):
        if ("结果:" in l) or ("[GATE]" in l and "pass" in l and "fail" in l) \
                or ("[VERIFY]" in l) or ("ok" in l.lower()):
            tail = l
            break
    if not tail:
        # JSON 型套件（intent-coverage / skill-route-probe）末尾不是人话，改成读 ok 字段
        import json as _j
        if "{" in out:
            try:
                d = _j.loads(out[out.index("{"):])
                tail = "ok=%r" % d.get("ok") if isinstance(d, dict) else ""
            except Exception:
                tail = ""
    tail = tail or (lines[-1] if lines else "")
    return name, rc in allow_rc, tail, time.time() - t0, rc, out


def main():
    ap = argparse.ArgumentParser(
        description="跑全部检查（相当于 make test）",
        epilog="--fix / --prep 的边界：只重生成生成物（docs/HANDOFF.md 状态块）；"
               "**不会**把 MANUAL/BASELINE-FREEZE.md 等期望值改成当前实测（REQUIREMENTS.md 的基线规则）。"
               "检测到漂移时只打印漂移与修法，由人决定改数字还是改代码。")
    ap.add_argument("--fast", action="store_true", help="只跑快的子集（提交前用）")
    ap.add_argument("--runtime", action="store_true",
                    help="检查当前运行实现与全部专项回归，不执行旧开发文档门禁")
    ap.add_argument("--json", action="store_true", help="只输出机器可读的套件汇总 JSON")
    ap.add_argument("--strict", action="store_true",
                    help="按交付门禁处理 WARN/跳过/未验证（返回非零；默认分类不变）")
    ap.add_argument("--list", action="store_true", help="列出套件后退出")
    ap.add_argument("--env", action="store_true", help="只做环境体检（这台机器装没装好）")
    ap.add_argument("--fix", dest="full_prep", action="store_true",
                    help="【只改生成物】检查前重生成 docs/HANDOFF.md 状态块；"
                         "**不改** MANUAL/BASELINE-FREEZE.md 的期望值（漂移只报修法，见 --help 顶部）")
    ap.add_argument("--prep", dest="full_prep", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--fix-handoff", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.runtime and (a.fast or a.full_prep or a.fix_handoff or a.env):
        ap.error("--runtime 需独立运行，不与 --fast/--fix/--env 组合")

    if a.full_prep:
        print("[注意] --fix 只重生成**生成物**（docs/HANDOFF.md 状态块）；"
              "MANUAL/BASELINE-FREEZE.md 的期望值不会被改写。单纯检查请不带参数。")
        # 提交/检查前先把 HANDOFF 状态块重生成（否则「落后 ≤1 提交」必然红）
        try:
            out = subprocess.run([PY, os.path.join(ROOT, "Tool", "scripts", "case_state.py"),
                                  "handoff", "--repo"], cwd=ROOT, capture_output=True,
                                 text=True, encoding="utf-8", errors="replace", timeout=120,
                                 env=CHILD_ENV).stdout
            hp = os.path.join(ROOT, "docs", "HANDOFF.md")
            if os.path.isfile(hp) and out.strip():
                src = open(hp, encoding="utf-8").read()
                head = src[:src.index("## §1 状态块（生成，勿手改）")]
                NL = chr(10)
                body = "## §1 状态块（生成，勿手改）" + NL + NL + out.strip() + NL
                open(hp, "w", encoding="utf-8", newline=NL).write(head + body)
                print("已重生成 HANDOFF 状态块")
        except Exception as e:  # noqa: BLE001
            print("HANDOFF 重生成失败：%s" % e)

    if a.full_prep:
        # ★ P1-1（第 4 轮评审）：这里原来会把 MANUAL/BASELINE-FREEZE.md 的 first-party 数
        #   改写成 preflight 的实测值 —— 那正是 REQUIREMENTS.md 禁止的「把期望改成当前实际」
        #   （文件每加一个就涨，判据永远绿 = 判据自证）。现在只**检测漂移并打印修法**，
        #   一个字节都不写：改期望是人的决定，不是脚本的副作用。
        report_baseline_drift()

    if a.env:
        # 环境体检 = env-check.py（装没装好）；与项目测试分开，但走同一个入口
        rc = subprocess.run([PY, os.path.join(ROOT, "Tool", "scripts", "env-check.py"), "--text"],
                            cwd=ROOT, env=CHILD_ENV).returncode
        print("环境体检：%s" % ("通过" if rc == 0 else "有问题（见上）"))
        return rc

    available_suites = runtime_suites() if a.runtime else SUITES
    suites = [s for s in available_suites if (not a.fast) or s[2]]
    if a.list:
        for n, cmd, fast, why in suites:
            timeout = runtime_timeout(n) if a.runtime else 600
            print("%-12s %-6s timeout=%-4ds %s"
                  % (n, "fast" if fast else "full", timeout, why))
        return 0

    skipped = [n for n, _c, fast, _w in SUITES if fast is False] if a.fast else []
    if not a.json:
        print("检查中（%s，%d 个套件）…" % ("fast" if a.fast else "full", len(suites)))
        if a.fast and skipped:
            print("[注意] --fast 跳过：%s —— 通过 ≠ 全部通过，交付判定请跑全量 check.py" % "、".join(skipped))
        print()
    failed, warned = [], []
    suite_results = []
    if a.fast:
        suite_results.extend({
            "name": name,
            "status": "SKIP",
            "ok": False,
            "accepted": False,
            "returncode": None,
            "seconds": None,
            "command": cmd,
            "summary": "--fast 跳过",
        } for name, cmd, fast, _why in SUITES if not fast)
    for name, argv, _fast, why in suites:
        # unit：rc=3 = 结构通过、可用性未证明；lint：rc=2 = 有 WARN/未验证项。
        # 两者都不能作为交付成功，但允许汇总器保留完整诊断。
        allow = (0, 3) if name == "unit" else ((0, 2) if name in ("lint", "domain-adapter") else (0,))
        timeout = runtime_timeout(name) if a.runtime else 600
        n, ok, tail, secs, rc, out = run_one(
            name, argv, timeout=timeout, allow_rc=allow,
        )
        mark = "PASS" if ok else "FAIL"
        skipped_tests = re.search(r"^OK \(skipped=(\d+)\)", out, re.M)
        if ok and rc != 0:
            if name == "unit" and rc == 3:
                nw = zr = "?"
                for ln in out.splitlines():
                    m = re.search(r"见证证据：real \d+ / public \d+ / self-built (\d+) / fixture (\d+)", ln)
                    if m:
                        nw = str(int(m.group(1)) + int(m.group(2)))
                    m = re.search(r"交付承诺 vs 账本：(\d+) 个案例", ln)
                    if m:
                        zr = m.group(1)
                    if "交付承诺 vs 账本：一致" in ln:
                        zr = "0"
                mark = "WARN"
                tail = "结构通过、可用性未证明（无真实产物见证 %s 域 / 零重放 %s）" % (nw, zr)
            elif name == "lint" and rc == 2:
                mark = "WARN"
                tail = "存在 WARN/未验证项：" + (tail or "请查看 preflight 输出")
            elif name == "domain-adapter" and rc == 2:
                mark = "WARN"
                tail = "存在适配器契约缺口：" + (tail or "请查看 domain-adapter-check 输出")
            warned.append((name, tail))
        if ok and rc == 0 and skipped_tests:
            mark = "WARN"
            tail = "存在 %s 项未验证的跳过测试" % skipped_tests.group(1)
            warned.append((name, tail))
        suite_result = {
            "name": name,
            "status": mark,
            "ok": mark == "PASS",
            "accepted": ok,
            "returncode": rc,
            "seconds": round(secs, 3),
            "timeout_seconds": timeout,
            "command": argv,
            "summary": tail,
        }
        if not ok:
            # A trailing summary (or a passing test name) must not discard the
            # actual failure. Keep the child diagnostic in both output modes.
            suite_result["output"] = out
        count = re.search(r"^Ran (\d+) tests? in ", out, re.M)
        if count:
            suite_result["test_count"] = int(count.group(1))
        if skipped_tests:
            suite_result["skipped_test_count"] = int(skipped_tests.group(1))
        suite_results.append(suite_result)
        if not a.json:
            print("%s %-14s %5.1fs  %s" % (mark, name, secs, tail[:110]), flush=True)
            if not ok and out:
                print("--- %s 完整失败输出 ---\n%s\n--- %s 输出结束 ---"
                      % (name, out.rstrip(), name), flush=True)
        if not ok:
            failed.append((name, why, tail))

    if a.json:
        if not failed and not warned and not skipped:
            exit_code = 0
        elif a.strict and (warned or skipped):
            exit_code = 1
        elif not failed:
            exit_code = 2
        else:
            exit_code = 1
        print(json.dumps({
            "schema": "seep.check/1",
            "mode": "runtime" if a.runtime else ("fast" if a.fast else "full"),
            "scope": "current-runtime-and-regressions" if a.runtime else "legacy-full-check",
            "strict": a.strict,
            "ok": exit_code == 0,
            "exit_code": exit_code,
            "summary": {
                "pass": sum(x["status"] == "PASS" for x in suite_results),
                "warn": sum(x["status"] == "WARN" for x in suite_results),
                "fail": sum(x["status"] == "FAIL" for x in suite_results),
                "skip": sum(x["status"] == "SKIP" for x in suite_results),
            },
            "suites": suite_results,
        }, ensure_ascii=False, indent=2))
        return exit_code
    print("-" * 72)
    for name, tail in warned:
        print("WARN %s —— %s" % (name, tail))
    if not failed and not warned and not skipped:
        print("全部通过（%d 个套件）" % len(suites))
        return 0
    if a.strict and not failed and (warned or skipped):
        print("strict 失败：WARN %d / 跳过 %d；WARN 与跳过不能作为交付成功。"
              % (len(warned), len(skipped)))
        return 1
    if not failed:
        print("检查完成，但存在 WARN/未验证/跳过项：PASS %d / WARN %d（跳过 %d 个：%s）"
              % (len(suites) - len(warned), len(warned), len(skipped),
                 ",".join(skipped) if skipped else "无"))
        print("这些项目不能作为交付成功；请先补齐验证或运行完整检查。")
        return 2
    print("失败 %d 个套件：" % len(failed))
    for name, why, tail in failed:
        print("  · %s —— %s" % (name, why))
        print("    %s" % tail[:160])
    print("\n单独复跑：python Tool/scripts/check.py --list 看各套件命令；或用上面套件名对应的脚本直接跑")
    return 1


if __name__ == "__main__":
    # stdout/stderr 已在模块顶部重建为 UTF-8（此处保留原防御式重建，便于被 -c/-m 方式拉起时也无差）
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    sys.exit(main())
