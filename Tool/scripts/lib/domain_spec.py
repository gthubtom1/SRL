#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""domain_spec.py —— 领域深度契约的**公共部分**（唯一数据源 A：阈值/必备篇/证据语义/路由回归）。

两份数据源，别混：
  A. 本文件：`LIMITS`（公共下限/上限）、`REQUIRED_REFS`、`CASE_FIELDS`、`EVIDENCE_KINDS`、
     `ROUTING_TESTS` —— 全仓库只有这一份，改这里就是改门槛（只许按事实收紧，不许为变绿放宽）。
  B. 逐域静态深度要求（skill/board/matrix/case_globs/ext_scripts/kb_line_max/archive_*）：
     在**该域自己的** `Tool/skill/<id>/pack.json#depth_contract`，由 `lib/domain_registry.py`
     严格校验后用 `DOMAINS` 兼容视图暴露。

正式域身份**只来自** `pack.json.id`（== 目录名）。`DOMAINS` **不是**身份表，也不声称是唯一 ID
来源：它是从 pack 现算的**兼容视图**（加域不再改本文件）。要动态全集请用
`domain_registry.load_registry().ids()` / 本文件的 `formal_domains()`。

改动顺序（缺一处即漂移，domain-gate 的 --spec 会报）：
    1. docs/DOMAIN-CONTRACT.md（人读）
    2. 本文件 / 各域 pack.json#depth_contract（机读）
    3. Tool/scripts/domain-gate.py 的断言实现

不要在这里写任何本机绝对路径；所有路径相对仓库根。
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# REMOVED_DOMAINS（W6 迁出；这些**不是**客户可见域，已移出深度检查）
#
# 归档数据登记（2026-10-26）—— `ARCHIVED_CONFIG`：
#   Tool/config/ad-cloud-matrix.json        已迁出域 ad-cloud 的矩阵
#   Tool/config/plugin-targets-matrix.json  已迁出域 plugin-targets 的矩阵
# **不参与任何判据，保留作证据，不许删。**
#
# 核对方法（可重跑，别信口）：全仓搜这两份文件名，排除 `Tool/cases/**` 与 `docs/` 后，
# 唯一命中的是**本注释**（domain_spec.py 自己）和 `protocol-plugin-matrix.json` 的一句
# 散文描述 —— 没有任何 py/ts/ps1/bat 代码或技能读取它们，domain_spec.DOMAINS[].matrix
# 也不含它们，所以 domain-gate 的 [6] matrix 判据从不看这两份。
# 为什么仍留在 Tool/config/（选②而不是搬去 _archive/）：
#   * 它们被 `Tool/cases/{ad-cloud01..05,plugin02..06,_archive/plugin01}/case.json` 的
#     `refs[]` 当历史证据指针引用；搬走会让这些 refs 变幻影（domain-gate [4] 的幻影判据会红），
#     而删案例是不允许的。原地保留 = 证据链不断 + 判据不参与。
#   * 目录里另有 `site-clone-matrix.json`（被 Tool/capabilities/site-crawl.json 与
#     `_pending/site-clone/SKILL.md` 引用）与 `reverse-matrix.json`（是 softseep 的现行矩阵，
#     见 DOMAINS["softseep"]["matrix"]）—— 同目录里「在用」与「归档」混存时，
#     搬一半反而更容易让人误以为整目录都失效。
# 若要重新纳入：先给它们一路由包（pack.json，含 depth_contract）—— 那时会自动出现在
# 注册表与 DOMAINS 兼容视图里，**不需要再改本文件**。
#
# 判据：客户可见正式域 = `Tool/skill/<dir>/pack.json` 且 `id == dir`（**数量不固定**）；
# 动态全集见 lib/domain_registry.py，本文件不再保存域清单。
# 下面四项在本文件里不再占位，因为：
#   * ad-cloud / plugin-targets / site-clone —— skill 指向 `Tool/skill/_pending/*`，
#     索引 32→9 后已归档、仓库里没有对应路由包（R0 兜底也不会落到它们），
#     客户不会点名要求；
#   * reverse —— 只是 `softseep` 的旧名，同一条路由包/同一个 skill 目录，
#     留着会让「reverse 域」和「softseep 域」重复占两行（域计数 11 的根因）。
# 迁出的只是**深度检查的域清单**：探针/矩阵/案例/KB 文件仍在原地，被别处引用
# （Tool/capabilities/*.json、Tool/config/{ad-cloud,plugin-targets,site-clone,
# reverse}-matrix.json、Tool/cases/{ad-cloud*,plugin*,site-clone*,项目*,案例*}、
# kb/{ad-cloud,plugin,site-clone,pe-reverse}），所以**不删文件**。
# 若要重新纳入：给它们真实路由包（pack.json，含 depth_contract）—— 那时自动出现在注册表与
# DOMAINS 兼容视图里，**不需要再改本文件**。
#
# ---------------------------------------------------------------------------
# 正式域视图（2026-10-27 主对话裁定：身份唯一来源 = pack.json#id）
#
# 以前这里是**硬编码的九域表**（skill/board/matrix/case_globs/ext_scripts/...）。
# 那份表与 pack.json 是两份事实源，加第 10 个域必须改代码（P1-8 遗留），而
# “改代码才能加域”与“用户不需要手改配置”直接冲突。
#
# 现在的分工：
#   * 逐域静态深度要求 → 该域自己的 `Tool/skill/<id>/pack.json#depth_contract`
#     （由 lib/domain_registry.py 校验：字段集合严格、kb_line_max ∈ [200,400]、
#      cases_max ∈ [3,7]，没有“改小下限/抬上限”的口子）。
#   * 公共下限/上限、必备篇清单、证据语义、路由回归集 → 仍**只有本文件一份**
#     （LIMITS / REQUIRED_REFS / EVIDENCE_KINDS / ROUTING_TESTS，不降阈值、不删条目）。
#   * `DOMAINS` 只是**兼容视图**：内容取 pack，形状与旧表一致，原消费者不用改。
#     不完整的域**保留在集合里**并带 `_incomplete`（显式报红），绝不静默过滤。
#   * 正式全集本身请用 `lib/domain_registry.load_registry().ids()`（动态，不按“恰 9 目录”）。
#
# 载入失败（pack 坏、目录缺）时 `DOMAINS` 为空 dict 且 `DOMAIN_LOAD_ERRORS` 非空，
# 本模块**不抛异常**：否则 import 这里的所有 CLI 会一起崩掉。
try:
    from . import domain_registry as _registry  # 单向依赖：registry 不 import 本模块
except ImportError:  # 兼容“把 lib/ 直接塞进 sys.path 后 `import domain_spec`”的旧用法
    import domain_registry as _registry  # type: ignore

def _load_domains():
    """从 pack 现算兼容视图 + 载入错误（不抛异常）。"""
    try:
        registry = _registry.load_registry()
    except Exception as exc:  # noqa: BLE001 - 载入器本身坏了也必须能让 CLI 起来并报红
        return {}, ["domain_registry.load_registry() failed: %s" % str(exc)[:160]]
    return registry.as_domains(), list(registry.errors)


DOMAINS, DOMAIN_LOAD_ERRORS = _load_domains()


def formal_domains(root=None, skill_dir=None):
    """正式域 id 全集（动态）。消费者优先用这个，不要数 DOMAINS 长度。"""
    return _registry.load_registry(root, skill_dir).ids()


REQUIRED_REFS = [
    ("criteria", "01-criteria.md"),
    ("failure", "02-failure-criteria.md"),
    ("pitfalls", "03-model-pitfalls.md"),
    ("walkthrough", "04-walkthrough-*.md"),
]

LIMITS = {
    "skill_max": 600,
    "skill_min": 120,
    "ref_max": 400,
    "ref_min": 60,
    "kb_max": 200,
    "kb_min": 50,
    "refs_min": 6,
    "refs_max": 10,
    "scripts_min": 2,
    "scripts_max": 16,   # S4：softseep 收口了工作区卫生与三层门禁（13 个），web-pentest 10 个
    "cases_min": 3,
    "cases_max": 7,   # S5 回放会为真实目标新增案例（pwn-crypto 已到 6）；原上限 5 挡住真实目标
    "kb_min_count": 6,
    "kb_max_count": 10,
    "matrix_min": 12,
    "cards_min": 20,
    "cards_max": 30,
    "roadmap_max": 80,
}


def _depth_limit_drift():
    """pack#depth_contract 的区间边界必须与 LIMITS 公共值同源（自检，不是第二份阈值）。"""
    bad = []
    for key, (low_key, high_key) in _registry.DEPTH_LIMIT_SOURCE.items():
        want = (LIMITS[low_key], LIMITS[high_key])
        got = _registry.DEPTH_LIMITS.get(key)
        if got != want:
            bad.append("DEPTH_LIMITS[%s]=%r != LIMITS[%s]/[%s]=%r"
                       % (key, got, low_key, high_key, want))
    return bad


DEPTH_LIMIT_DRIFT = _depth_limit_drift()
if DEPTH_LIMIT_DRIFT:
    DOMAIN_LOAD_ERRORS = list(DOMAIN_LOAD_ERRORS) + DEPTH_LIMIT_DRIFT

# 案例字段
CASE_FIELDS = ("id", "domain", "target_type", "evidence_kind", "protection",
               "authority", "goal_level", "outcome", "artifacts", "lessons",
               "refs", "updated")
# 案例真实性四分（+ 归档）—— evidence_kind 的**唯一语义来源**，改这里就要改
# Tool/cases/README.md §2 的同名表：
#   real       = 客户真实目标（来源与授权可追：授权单/合同/客户交来的样本）
#   public     = 公开可分发的**真实产物**（教学靶场 / CTF / 公开 crackme / MIT 示例）；
#                有真实来源与哈希，可随仓库分发。gate 的「有真实产物见证」认它，
#                因为它就是真实可复现的产物，不是合成夹具。
#   self-built = 自己编译的（源码可公开但产物是本机 gcc/msvc 出的）：流程证据，**不算该域可用**
#   fixture    = 合成/教学夹具（不是真实产物：手写 PE、造的 pcap、造的日志）
#   historical = 历史归档（旧案，不参与当前判定）
# 纪律：promotion 只能按**事实**走（样本本来就是公开靶场才写 public），
#      不许把 fixture / self-built 改叫 real 或 public 来凑「可用」。
EVIDENCE_KINDS = ("real", "public", "self-built", "fixture", "historical")
# 「有真实产物见证」的两档：real（客户目标）+ public（公开真实产物）
EVIDENCE_KINDS_REAL_ARTIFACT = ("real", "public")

FIXTURE_WORDS = ("夹具", "教学", "fixture", "示例")
# public 案例的 target_type 允许**公开来源描述**（它就是公开教学靶场/CTF/公开 crackme）。
# 判「是不是夹具字样」时先剥掉这些来源词，剩下的才算残留：
#   「公开教学靶场 DIVA」→ 剥完只剩 DIVA，不算夹具字样（public 合法）
#   「教学夹具」→ 剥完仍残留「教学/夹具」，照旧红
PUBLIC_MARKERS = ("公开教学靶场", "公开", "靶场", "CTF", "crackme", "MIT", "github",
                  "public")


def fixture_words_in(target_type, kind="fixture"):
    """按档位判 target_type 里的「夹具/教学」字样。

    fixture              必须**含**夹具字样（否则分不清是夹具还是真产物）；
    real/public/self-built 不许有**残留**夹具字样；
    public 例外：先剥掉 PUBLIC_MARKERS（公开教学靶场 / CTF / 公开 crackme（MIT））。

    返回命中的字样列表（空列表 = 无残留）。为何不“一律禁词”：公开靶场本来就该写
    “公开教学靶场”，一律禁词会把真实公开样本逼成 fixture —— 那是另一个方向的假话。
    """
    t = str(target_type or "")
    if str(kind or "").strip().lower() == "public":
        for w in PUBLIC_MARKERS:
            t = t.replace(w, "")
    return [w for w in FIXTURE_WORDS if w in t]

# 路由串味测试集（固定，不许删条目；新增只许追加）
# expect_any = 该条测试可接受的技能落点（同域多技能允许并列）；forbid = 跨域误命中，命中即 FAIL。
ROUTING_TESTS = [{'text': '用 zipalign 对齐后 apksigner 重签',
  'expect_any': ['apkseep'],
  'forbid': ['web-pentest', 'protocol-plugin', 'supply-chain-security']},
 {'text': '爬虫 spider 抓取目录并枚举路径',
  'expect_any': ['web-pentest'],
  'forbid': ['forensics-mobile', 'protocol-plugin', 'softseep']},
 {'text': 'Kerberos principal 枚举与 SPN 发现',
  'expect_any': [], 'why_unclassified': '不属于客户可见的 9 个域（AD/内网/集群/非技术文本）→ 必须走 UNCLASSIFIED，不许被兜底域假装命中',
  'forbid': ['web-pentest', 'pwn-crypto']},
 {'text': 'bios 固件 SPI flash dump 与 UART 接入',
  'expect_any': ['firmware-iot'],
  'expect_aux': ['malware-analysis'], 'expect_ambiguity': True,
  'forbid': ['web-pentest', 'supply-chain-security']},
 {'text': 'npm scaffold 生成项目后检查 lockfile 完整性',
  'expect_any': ['supply-chain-security'],
  'forbid': ['web-pentest', 'plugin-targets']},
 {'text': '分析 src/xxx.dll 的导出表与 IAT 修复',
  'expect_any': ['softseep', 'malware-analysis'],
  'forbid': ['web-pentest', 'plugin-targets', 'supply-chain-security']},
 {'text': '分析这个 Chrome 扩展的 manifest 权限',
  'expect_any': ['protocol-plugin'],
  'forbid': ['softseep', 'web-pentest']},
 {'text': '帮我逆一下这个 Unity 游戏的 il2cpp',
  'expect_any': ['forensics-mobile'],
  'forbid': ['plugin-targets', 'apkseep']},
 {'text': '这个驱动有反调试', 'expect_any': ['softseep'], 'forbid': ['unpack-loop', 'web-pentest']},
 {'text': '这个样本的 C2 配置怎么解',
  'expect_any': ['malware-analysis'],
  'forbid': ['softseep', 'web-pentest']},
 {'text': '这个固件的 web 界面命令注入', 'expect_any': ['firmware-iot'],
  'expect_aux': ['web-pentest'], 'expect_ambiguity': True},
 {'text': '这个 docker 镜像有没有后门',
  'expect_any': ['supply-chain-security'],
  'expect_aux': ['malware-analysis'], 'expect_ambiguity': True, 'forbid': ['web-pentest']},
 {'text': '这个 WASM 怎么反编译', 'expect_any': ['softseep'], 'forbid': ['web-pentest']},
 {'text': '这个游戏有 EAC 反作弊', 'expect_any': ['softseep'], 'forbid': ['unpack-loop', 'plugin-targets']},
 {'text': '分析这个 VMP 授权锁',
  'expect_any': ['softseep', 'malware-analysis'],
  'expect_aux': ['malware-analysis'], 'expect_ambiguity': True,
  'forbid': ['web-pentest']},
 {'text': 'Themida VM 函数怎么绕过',
  'expect_any': ['softseep', 'malware-analysis'],
  'expect_aux': ['malware-analysis'], 'expect_ambiguity': True,
  'forbid': ['web-pentest']},
 {'text': 'LACUNA 调用栈 pdata 空洞',
  'expect_any': ['softseep'],
  'forbid': ['web-pentest', 'forensics-mobile']},
 {'text': 'Win11 26H2 HVCI 下驱动怎么加载', 'expect_any': ['softseep'], 'forbid': ['web-pentest']},
 {'text': 'ADCS ESC17 WSUS 中继', 'expect_any': [], 'why_unclassified': '不属于客户可见的 9 个域（AD/内网/集群/非技术文本）→ 必须走 UNCLASSIFIED，不许被兜底域假装命中', 'forbid': ['web-pentest']},
 {'text': 'Next.js 缓存投毒怎么验证', 'expect_any': ['web-pentest'],
  'expect_aux': ['supply-chain-security'], 'expect_ambiguity': True, 'forbid': ['softseep']},
 {'text': 'ETag oracle 推断长度',
  'expect_any': ['web-pentest'],
  'forbid': ['softseep', 'protocol-plugin']},
 {'text': 'npm worm ChainDrop 怎么检测',
  'expect_any': ['supply-chain-security'],
  'forbid': ['malware-analysis']},
 {'text': 'MemProcFS 5.19 内存取证', 'expect_any': ['forensics-mobile'], 'forbid': ['web-pentest']},
 {'text': 'ASAR integrity 绕过', 'expect_any': ['protocol-plugin'], 'forbid': ['web-pentest']},
 {'text': 'bytenode V8 字节码反编译', 'expect_any': ['protocol-plugin'],
  'expect_aux': ['softseep'], 'expect_ambiguity': True, 'forbid': ['web-pentest']},
 {'text': '协议状态机 边覆盖率 怎么算', 'expect_any': ['protocol-plugin'], 'forbid': ['pwn-crypto']},
 {'text': 'MCP 工具投毒怎么测', 'expect_any': ['softseep'],
  'expect_aux': ['supply-chain-security'], 'expect_ambiguity': True, 'forbid': ['web-pentest']},
 {'text': 'A2A agent 协议越权', 'expect_any': ['softseep'],
  'expect_aux': ['web-pentest'], 'expect_ambiguity': True},
 {'text': '固件 rehosting 起不来 服务', 'expect_any': ['firmware-iot'], 'forbid': ['web-pentest']},
 {'text': 'glibc 2.34 之后 FSOP 怎么打', 'expect_any': ['pwn-crypto'], 'forbid': ['web-pentest']},
 {'text': 'iOS 越狱检测怎么过', 'expect_any': ['forensics-mobile', 'apkseep'], 'forbid': ['web-pentest']},
 {'text': 'kubectl auth can-i --list 看 RBAC',
  'expect_any': [], 'why_unclassified': '不属于客户可见的 9 个域（AD/内网/集群/非技术文本）→ 必须走 UNCLASSIFIED，不许被兜底域假装命中',
  'forbid': ['supply-chain-security']},
 {'text': 'CI 流水线 secrets 泄露排查',
  'expect_any': ['supply-chain-security'],
  'forbid': ['softseep', 'web-pentest']},
 {'text': 'Frida 在 android 上 hook 加密函数',
  'expect_any': ['apkseep'],
  'expect_aux': ['softseep'], 'expect_ambiguity': True, 'forbid': ['web-pentest']},
 {'text': 'UPX 脱壳后 dump 出 OEP 修 IAT',
  'expect_any': ['malware-analysis'],
  'expect_aux': ['softseep'], 'expect_ambiguity': True, 'forbid': ['web-pentest']},
 {'text': '把授权校验 patch 掉',
  'expect_any': ['softseep'],
  'forbid': ['web-pentest', 'supply-chain-security']},
 {'text': '破解一个 RSA 挑战题',
  'expect_any': ['pwn-crypto'],
  'expect_aux': ['softseep'], 'expect_ambiguity': True,
  'forbid': ['01-gate-bypass', 'web-pentest']},
 {'text': '分析一下这个勒索样本',
  'expect_any': ['malware-analysis'],
  'expect_aux': ['softseep'], 'expect_ambiguity': True,
  'forbid': ['00-analysis', 'web-pentest']},
 {'text': 'hook 一下浏览器的请求',
  'expect_any': ['softseep'],
  'forbid': ['web-pentest', 'protocol-plugin']},
 {'text': 'playwright headless 抓取页面数据',
  'expect_any': ['softseep'],
  'forbid': ['web-pentest', 'protocol-plugin']},
 {'text': 'industrial control system 的固件分析',
  'expect_any': ['firmware-iot'],
  'forbid': ['01-gate-bypass', 'softseep']},
 {'text': '分析激活函数对梯度的影响', 'expect_any': [], 'why_unclassified': '不属于客户可见的 9 个域（AD/内网/集群/非技术文本）→ 必须走 UNCLASSIFIED，不许被兜底域假装命中', 'forbid': []},
 {'text': 'initiative 计划评审会', 'expect_any': [], 'why_unclassified': '不属于客户可见的 9 个域（AD/内网/集群/非技术文本）→ 必须走 UNCLASSIFIED，不许被兜底域假装命中', 'forbid': ['unpack-loop']},
 {'text': '主程序的 dump 目录里有日志',
  'expect_any': ['malware-analysis', 'softseep'],
  'forbid': ['web-pentest']},
 {'text': '用 IDA Pro 反编译这个 so', 'expect_any': ['softseep'], 'forbid': ['web-pentest', 'apkseep']},
 {'text': 'radare2 无头分析这个 ELF', 'expect_any': ['softseep'], 'forbid': ['web-pentest']},
 {'text': 'unity il2cpp assetbundle 解包',
  'expect_any': ['forensics-mobile'],
  'forbid': ['apkseep', 'apk-reverse', 'web-pentest']},
 {'text': 'snyk 扫依赖 看可达性',
  'expect_any': ['supply-chain-security'],
  'forbid': ['softseep', 'web-pentest']},
 {'text': 'HyperDbg EPT hook 怎么观测',
  'expect_any': ['softseep'],
  'forbid': ['unpack-loop', 'web-pentest']},
 {'text': 'eBPF XDP 程序逆向', 'expect_any': ['softseep'], 'forbid': ['web-pentest', 'unpack-loop']},
 {'text': 'TrustZone TEE 固件分析',
  'expect_any': ['softseep', 'firmware-iot'],
  'expect_aux': ['firmware-iot'], 'expect_ambiguity': True,
  'forbid': ['web-pentest', 'apkseep']},
 {'text': 'dnSpy 打开 Assembly-CSharp 找授权',
  'expect_any': ['softseep'],
  'forbid': ['web-pentest', 'apkseep']},
 {'text': 'javap 反编译 jar 看校验', 'expect_any': ['softseep'], 'forbid': ['web-pentest', 'apkseep']},
 {'text': 'PyInstaller 打包的程序怎么解', 'expect_any': ['softseep'], 'forbid': ['web-pentest', 'apkseep']},
 {'text': 'wasm2c 转 C 后怎么读', 'expect_any': ['softseep'], 'forbid': ['web-pentest']},
 {'text': 'Unity il2cpp 的 global-metadata 解密',
  'expect_any': ['forensics-mobile'],
  'forbid': ['apkseep', 'apk-reverse', 'web-pentest']},
 {'text': 'BattlEye 服务项在哪取证',
  'expect_any': ['softseep', 'forensics-mobile'],
  'forbid': ['web-pentest', 'apkseep']},
 {'text': 'APK 里 so 被 VMP 了怎么脱', 'expect_any': ['apkseep'],
  'expect_aux': ['malware-analysis', 'softseep'], 'expect_ambiguity': True,
  'forbid': ['web-pentest']},
 {'text': 'iOS 应用越狱检测怎么定位',
  'expect_any': ['forensics-mobile', 'apkseep'],
  'forbid': ['web-pentest', 'softseep']},
 {'text': 'VMP 授权锁 ProductCode 在哪',
  'expect_any': ['malware-analysis', 'softseep'],
  'expect_aux': ['malware-analysis'], 'expect_ambiguity': True,
  'forbid': ['web-pentest', 'apkseep']}]
