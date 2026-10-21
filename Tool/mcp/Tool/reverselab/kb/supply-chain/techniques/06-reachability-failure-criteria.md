---
id: "supply-chain/06-reachability-failure-criteria"
title: "供应链失败判据：什么时候必须降级/换面"
title_en: "Supply Chain Failure Criteria: When to Downgrade or Switch Evidence"
summary: >
  把“扫描器命中/版本匹配/关键字命中”与“可复核结论”分开；列出供应链审计里最常见的
  失败现象、判定、改走哪条与代价，避免把未验证写成确认。
board: "supply-chain"
category: "06-reachability-failure-criteria"
signals: ["truncated=true", "degraded", "missing_tools", "no digest", "no integrity", "unreachable", "keyword hit"]
mcp_tools: ["sc-check.py", "sbom-reach.py", "ci-perm-audit.py"]
keywords: ["失败判据", "降级", "误报", "SCA", "可达性", "SBOM", "CI 权限"]
difficulty: "intermediate"
tags: ["failure-criteria", "triage", "supply-chain"]
language: "zh-CN"
last_updated: "2026-10-21"
related_articles: ["supply-chain/03-sbom-and-reachability", "supply-chain/04-ci-permission-audit"]
---
# 供应链失败判据：什么时候必须降级/换面

## 入口信号

- 扫描输出 `truncated=true`、`degraded[]` 非空、`missing_tools` 含 syft/osv/grype/trivy/cosign。
- 报告里出现“存在高危漏洞”“可被抢注”“可被提权”，但只有版本/关键字/名称。
- 复核时发现锁文件、SBOM、源码入口三者对不上。

## 可复制命令

```bash
# 看覆盖与降级
python Tool/scripts/sc-check.py --path . --out sc.json
jq '{target, summary, degraded, missing_tools}' sc.json

# 看可达性与入口
python Tool/skill/supply-chain-security/scripts/sbom-reach.py \
  --lock package-lock.json --source . --out reach.json
jq '{components_total, entries, reachable: [.reachable[].name],
     missing_from_sbom: [.missing_from_sbom[].name]}' reach.json

# 看 CI 组合
python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py \
  --path .github/workflows --out ci.json
jq '{summary, findings: [.findings[] | {rule, line, severity}]}' ci.json
```

## 失败判据表

| 现象 | 判定 | 改走哪条 | 代价 |
| :-- | :-- | :-- | :-- |
| `truncated=true` | 覆盖不完整 | 分目录/加大上限重跑，或缩小结论范围 | 低 |
| `degraded[]` 含 SCA/签名 | 对应输入面没查 | 只写“未验证”，补外部工具或手工比对 | 中 |
| 只有版本命中 CVE | 未证明可达 | 查 import/require、运行时依赖树、补丁 diff | 中 |
| SBOM 对不上 commit/digest | 清单不可信 | 重生成并绑定对象 | 中 |
| 锁文件缺 integrity | 可复现性不成立 | 重生成锁文件 + 冻结安装 | 中 |
| 私有 scope 未映射 registry | 配置缺失，未验证解析 | 只写“未锁定”；联网验证另开授权 | 低 |
| `pull_request_target` 关键字命中 | 未证明利用链 | 看 checkout ref/permissions/secrets 组合 | 低 |
| action 未 pin 但 token 只读 | 加固项 | 记录 pin 建议，不写“已投毒” | 低 |
| 只有 tag 没有 digest | 对象不可钉住 | 取 RepoDigests/registry digest | 中 |
| `cosign verify` rc=0 未核对身份 | 只证明有签名 | 补 identity/issuer/Rekor/subject | 低 |
| 可达但参数不可控 | 调用≠利用 | 转人工代码审计，写“未见可控入口” | 中 |
| 零 finding | 仅当前规则集未命中 | 列已覆盖/未覆盖输入面，附 degraded | 低 |

## 降级顺序

1. 补对象：commit → digest → 锁文件 sha256。
2. 补清单：SBOM → 锁文件 → freeze/npm ls。
3. 补可达：import → 入口调用链 → 运行时加载。
4. 补 CI：触发器 → checkout → permissions → secrets → action pin。
5. 补来源：digest → 签名身份 → attestation subject → Rekor。
6. 仍不成立：写 `blocked` + blocker + 已排除项。

## 确认判据

- 每条结论有命令、rc、原始 JSON、文件/行号。
- 不可达项写明原因（未打包/死代码/仅测试/backport）。
- 未验证项在报告里显式出现，不藏在脚注。
- 修复建议有具体值（SHA/digest/版本/permissions 文本）。

## 边界

- 失败判据不是“放弃”，是“停止当前路径并换面”。
- 换面仍须在授权范围内；不联网、不投毒、不改生产流水线。
- 不把“没查”写成“不存在”，不把“疑似”写成“确认”。
