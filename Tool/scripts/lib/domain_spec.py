#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""domain_spec.py —— 领域深度契约的**机器可读副本**（唯一数据源）。

改动顺序（缺一处即漂移，domain-gate 的 --spec 会报）：
    1. docs/DOMAIN-SPEC-v2.md（人读）
    2. 本文件（机读）
    3. Tool/scripts/domain-gate.py 的断言实现

不要在这里写任何本机绝对路径；所有路径相对仓库根。
"""
from __future__ import annotations

# 十一域（重点域）：refs 6-10 + 四个必备篇 + 2-4 脚本 + 3-5 案例 + 6-10 KB + 20-30 任务卡
DOMAINS = {
    "web-pentest": {
        "skill": "web-pentest",
        "board": "web-pentest",
        "matrix": "web-pentest-matrix.json",
        "case_globs": ["web-pentest*"],
        "ext_scripts": [],
    },
    "pwn-crypto": {
        "skill": "pwn-crypto",
        "board": "pwn-crypto",
        "matrix": "pwn-crypto-matrix.json",
        "case_globs": ["pwn-crypto*"],
        "ext_scripts": ["Tool/scripts/pwn-check.py"],
    },
    "firmware-iot": {
        "skill": "firmware-iot",
        "board": "firmware-iot",
        "matrix": "firmware-iot-matrix.json",
        "case_globs": ["firmware-iot*"],
        "ext_scripts": ["Tool/scripts/fw-triage.py"],
    },
    "ad-cloud": {
        "skill": "ad-cloud",
        "board": "ad-cloud",
        "matrix": "ad-cloud-matrix.json",
        "case_globs": ["ad-cloud*"],
        "ext_scripts": [],
    },
    "protocol-plugin": {
        "skill": "protocol-plugin",
        "board": "protocol",
        "matrix": "protocol-plugin-matrix.json",
        "case_globs": ["protocol*"],
        "ext_scripts": ["Tool/scripts/pcap-summary.py"],
    },
    "plugin-targets": {
        "skill": "plugin-targets",
        "board": "plugin",
        "matrix": "plugin-targets-matrix.json",
        "case_globs": ["plugin*"],
        "ext_scripts": ["Tool/scripts/plugin-triage.py"],
    },
    "forensics-mobile": {
        "skill": "forensics-mobile",
        "board": "forensics",
        "matrix": "forensics-mobile-matrix.json",
        "case_globs": ["forensics*"],
        "ext_scripts": ["Tool/scripts/forensics-check.py"],
    },
    "malware-analysis": {
        "skill": "malware-analysis",
        "board": "malware-analysis",
        "matrix": "malware-analysis-matrix.json",
        "case_globs": ["malware-analysis*"],
        "ext_scripts": ["Tool/scripts/mal-triage.py"],
    },
    "supply-chain-security": {
        "skill": "supply-chain-security",
        "board": "supply-chain",
        "matrix": "supply-chain-security-matrix.json",
        "case_globs": ["supply-chain*"],
        "ext_scripts": ["Tool/scripts/sc-check.py"],
    },
    "site-clone": {
        "skill": "site-clone",
        "board": "site-clone",
        "matrix": "site-clone-matrix.json",
        "case_globs": ["site-clone*"],
        "ext_scripts": [],
    },
    "reverse": {
        "skill": "softseep",
        "board": "pe-reverse",
        "matrix": "reverse-matrix.json",
        "case_globs": ["项目*", "案例*"],
        "ext_scripts": ["Tool/scripts/driver-triage.py"],
        # 逆向域与其它域同一契约（3–5 案例 / 6–10 篇 KB）。
        # 历史沉淀不删：超出部分归档在 Tool/cases/_archive/ 与 kb/_archive/pe-reverse/，
        # 归档不计入域数量，但链接完整性仍受门禁约束（见 check_links / check_md_links）。
        "kb_line_max": 400,   # 逆向域 KB 单篇与 reference 同档（§5 已写明）
        "archive_cases": "Tool/cases/_archive",
        "archive_kb": "Tool/mcp/Tool/reverselab/kb/_archive/pe-reverse",
    },
}

# 必备篇（文件名模式，按顺序匹配到即算齐）
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
    "scripts_max": 4,
    "cases_min": 3,
    "cases_max": 5,
    "kb_min_count": 6,
    "kb_max_count": 10,
    "matrix_min": 12,
    "cards_min": 20,
    "cards_max": 30,
    "roadmap_max": 80,
}

# 案例字段
CASE_FIELDS = ("id", "domain", "target_type", "evidence_kind", "protection",
               "authority", "goal_level", "outcome", "artifacts", "lessons",
               "refs", "updated")
FIXTURE_WORDS = ("夹具", "教学", "fixture", "示例")

# 路由串味测试集（固定，不许删条目；新增只许追加）
# expect_any = 该条测试可接受的技能落点（同域多技能允许并列）；forbid = 跨域误命中，命中即 FAIL。
ROUTING_TESTS = [
    # 词边界六件（SPEC §9 固定项）
    {"text": "用 zipalign 对齐后 apksigner 重签", "expect_any": ["apkseep", "apk-reverse"],
     "forbid": ["web-pentest", "protocol-plugin", "supply-chain-security"]},
    {"text": "爬虫 spider 抓取目录并枚举路径", "expect_any": ["web-pentest"],
     "forbid": ["forensics-mobile", "protocol-plugin", "softseep"]},
    {"text": "Kerberos principal 枚举与 SPN 发现", "expect_any": ["ad-cloud"],
     "forbid": ["web-pentest", "pwn-crypto"]},
    {"text": "bios 固件 SPI flash dump 与 UART 接入", "expect_any": ["firmware-iot"],
     "forbid": ["web-pentest", "supply-chain-security"]},
    {"text": "npm scaffold 生成项目后检查 lockfile 完整性", "expect_any": ["supply-chain-security"],
     "forbid": ["web-pentest", "plugin-targets"]},
    {"text": "分析 src/xxx.dll 的导出表与 IAT 修复",
     "expect_any": ["softseep", "unpack-loop", "ida-reverse", "binary-diff"],
     "forbid": ["web-pentest", "plugin-targets", "supply-chain-security"]},
    # R1 审计回归集：覆盖三处执行语义缺陷与高频歧义词
    {"text": "分析这个 Chrome 扩展的 manifest 权限", "expect_any": ["plugin-targets"],
     "forbid": ["softseep", "web-pentest"]},
    # v1.23 新增：2026 域探针（24 条）
    {"text": "帮我逆一下这个 Unity 游戏的 il2cpp", "expect_any": ["forensics-mobile"], "forbid": ["plugin-targets", "apkseep"]},
    {"text": "这个驱动有反调试", "expect_any": ["softseep"], "forbid": ["unpack-loop", "web-pentest"]},
    {"text": "这个样本的 C2 配置怎么解", "expect_any": ["malware-analysis"], "forbid": ["softseep", "web-pentest"]},
    {"text": "这个固件的 web 界面命令注入", "expect_any": ["firmware-iot"], "forbid": ["web-pentest"]},
    {"text": "这个 docker 镜像有没有后门", "expect_any": ["supply-chain-security"], "forbid": ["malware-analysis", "web-pentest"]},
    {"text": "这个 WASM 怎么反编译", "expect_any": ["softseep", "ida-reverse"], "forbid": ["web-pentest"]},
    {"text": "这个游戏有 EAC 反作弊", "expect_any": ["softseep"], "forbid": ["unpack-loop", "plugin-targets"]},
    {"text": "分析这个 VMP 授权锁", "expect_any": ["softseep", "01-gate-bypass", "unpack-loop"], "forbid": ["web-pentest"]},
    {"text": "Themida VM 函数怎么绕过", "expect_any": ["softseep", "unpack-loop"], "forbid": ["web-pentest"]},
    {"text": "LACUNA 调用栈 pdata 空洞", "expect_any": ["softseep"], "forbid": ["web-pentest", "forensics-mobile"]},
    {"text": "Win11 26H2 HVCI 下驱动怎么加载", "expect_any": ["softseep"], "forbid": ["web-pentest"]},
    {"text": "ADCS ESC17 WSUS 中继", "expect_any": ["ad-cloud"], "forbid": ["web-pentest"]},
    {"text": "Next.js 缓存投毒怎么验证", "expect_any": ["web-pentest"], "forbid": ["softseep"]},
    {"text": "ETag oracle 推断长度", "expect_any": ["web-pentest"], "forbid": ["softseep", "protocol-plugin"]},
    {"text": "npm worm ChainDrop 怎么检测", "expect_any": ["supply-chain-security"], "forbid": ["malware-analysis"]},
    {"text": "MemProcFS 5.19 内存取证", "expect_any": ["forensics-mobile"], "forbid": ["web-pentest"]},
    {"text": "ASAR integrity 绕过", "expect_any": ["plugin-targets"], "forbid": ["web-pentest"]},
    {"text": "bytenode V8 字节码反编译", "expect_any": ["plugin-targets"], "forbid": ["web-pentest"]},
    {"text": "协议状态机 边覆盖率 怎么算", "expect_any": ["protocol-plugin"], "forbid": ["pwn-crypto"]},
    {"text": "MCP 工具投毒怎么测", "expect_any": ["llm-security"], "forbid": ["web-pentest", "softseep"]},
    {"text": "A2A agent 协议越权", "expect_any": ["llm-security"], "forbid": ["web-pentest"]},
    {"text": "固件 rehosting 起不来 服务", "expect_any": ["firmware-iot"], "forbid": ["web-pentest"]},
    {"text": "glibc 2.34 之后 FSOP 怎么打", "expect_any": ["pwn-crypto"], "forbid": ["web-pentest"]},
    {"text": "iOS 越狱检测怎么过", "expect_any": ["forensics-mobile", "apkseep"], "forbid": ["web-pentest"]},
    {"text": "kubectl auth can-i --list 看 RBAC", "expect_any": ["ad-cloud"],
     "forbid": ["softseep", "supply-chain-security"]},
    {"text": "CI 流水线 secrets 泄露排查", "expect_any": ["supply-chain-security"],
     "forbid": ["softseep", "web-pentest"]},
    {"text": "Frida 在 android 上 hook 加密函数", "expect_any": ["apkseep", "apk-reverse"],
     "forbid": ["softseep", "web-pentest"]},
    {"text": "UPX 脱壳后 dump 出 OEP 修 IAT", "expect_any": ["unpack-loop"],
     "forbid": ["softseep", "web-pentest"]},
    {"text": "把授权校验 patch 掉", "expect_any": ["01-gate-bypass", "softseep"],
     "forbid": ["web-pentest", "supply-chain-security"]},
    {"text": "破解一个 RSA 挑战题", "expect_any": ["pwn-crypto"],
     "forbid": ["01-gate-bypass", "web-pentest"]},
    {"text": "分析一下这个勒索样本", "expect_any": ["malware-analysis"],
     "forbid": ["00-analysis", "web-pentest"]},
    {"text": "hook 一下浏览器的请求", "expect_any": ["mcp-js-reverse-playbook"],
     "forbid": ["softseep", "web-pentest"]},
    {"text": "playwright headless 抓取页面数据", "expect_any": ["mcp-js-reverse-playbook"],
     "forbid": ["radare2", "softseep"]},
    {"text": "industrial control system 的固件分析", "expect_any": ["firmware-iot"],
     "forbid": ["01-gate-bypass", "softseep"]},
    {"text": "分析激活函数对梯度的影响", "expect_any": ["softseep"],
     "forbid": ["01-gate-bypass"]},
    {"text": "initiative 计划评审会", "expect_any": ["softseep"],
     "forbid": ["unpack-loop"]},
    {"text": "主程序的 dump 目录里有日志", "expect_any": ["unpack-loop", "softseep"],
     "forbid": ["web-pentest"]},
    {"text": "用 IDA Pro 反编译这个 so", "expect_any": ["ida-reverse"],
     "forbid": ["web-pentest", "apkseep"]},
    {"text": "radare2 无头分析这个 ELF", "expect_any": ["radare2"],
     "forbid": ["web-pentest", "softseep"]},
    {"text": "unity il2cpp assetbundle 解包", "expect_any": ["forensics-mobile"],
     "forbid": ["apkseep", "apk-reverse", "web-pentest"]},
    {"text": "snyk 扫依赖 看可达性", "expect_any": ["supply-chain-security"],
     "forbid": ["softseep", "web-pentest"]},
    # v1.24 新增：R32 hypervisor/eBPF/TEE 与 R33 托管运行时（12 条，总计 60）
    {"text": "HyperDbg EPT hook 怎么观测", "expect_any": ["softseep"],
     "forbid": ["unpack-loop", "web-pentest"]},
    {"text": "eBPF XDP 程序逆向", "expect_any": ["softseep"],
     "forbid": ["web-pentest", "unpack-loop"]},
    {"text": "TrustZone TEE 固件分析", "expect_any": ["softseep", "firmware-iot"],
     "forbid": ["web-pentest", "apkseep"]},
    {"text": "dnSpy 打开 Assembly-CSharp 找授权", "expect_any": ["softseep"],
     "forbid": ["web-pentest", "apkseep"]},
    {"text": "javap 反编译 jar 看校验", "expect_any": ["softseep", "01-gate-bypass"],
     "forbid": ["web-pentest", "apkseep"]},
    {"text": "PyInstaller 打包的程序怎么解", "expect_any": ["softseep"],
     "forbid": ["web-pentest", "apkseep"]},
    {"text": "wasm2c 转 C 后怎么读", "expect_any": ["softseep"],
     "forbid": ["web-pentest"]},
    {"text": "Unity il2cpp 的 global-metadata 解密", "expect_any": ["forensics-mobile"],
     "forbid": ["apkseep", "apk-reverse", "web-pentest"]},
    {"text": "BattlEye 服务项在哪取证", "expect_any": ["softseep", "forensics-mobile"],
     "forbid": ["web-pentest", "apkseep"]},
    {"text": "APK 里 so 被 VMP 了怎么脱", "expect_any": ["apkseep", "apk-reverse"],
     "forbid": ["softseep", "web-pentest"]},
    {"text": "iOS 应用越狱检测怎么定位", "expect_any": ["forensics-mobile", "apkseep"],
     "forbid": ["web-pentest", "softseep"]},
    {"text": "VMP 授权锁 ProductCode 在哪", "expect_any": ["unpack-loop", "softseep"],
     "forbid": ["web-pentest", "apkseep"]},
]
