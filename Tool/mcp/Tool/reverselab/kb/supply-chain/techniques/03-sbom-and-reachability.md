---
id: "supply-chain/03-sbom-and-reachability"
title: "SBOM 与可达性：从组件清单到源码入口"
title_en: "SBOM and Reachability: From Component Inventory to Source Entries"
summary: >
  用锁文件/freeze/SBOM 三方对账组件集合，再用源码 import/require 判断可达；
  可达只是第一层，参数可控与运行时加载仍需人工补证。
board: "supply-chain"
category: "03-sbom-and-reachability"
signals: ["sbom", "cyclonedx", "spdx", "package-lock.json", "pip freeze", "import", "require", "reachability"]
mcp_tools: ["sbom-reach.py", "sc-check.py", "syft", "osv-scanner"]
keywords: ["SBOM", "可达性", "组件清单", "锁文件", "依赖漂移"]
difficulty: "intermediate"
tags: ["sbom", "sca", "reachability", "npm", "pypi"]
language: "zh-CN"
last_updated: "2026-10-21"
related_articles: ["supply-chain/06-reachability-failure-criteria"]
---
# SBOM 与可达性：从组件清单到源码入口

## 入口信号

- 报告里只有 `grype`/`trivy` 的 CVE 计数，没有组件清单与调用面。
- SBOM 生成于旧 commit，或组件数与锁文件条目数差 >20%。
- 依赖里有高危包，但没人回答“哪个入口会走到它”。

## 可复制命令

```bash
# 1) 组件集合（优先 SBOM，缺则锁文件/freeze）
python Tool/skill/supply-chain-security/scripts/sbom-reach.py \
  --sbom bom.cdx.json --lock package-lock.json --freeze freeze.txt \
  --source . --out reach.json

# 2) 只有锁文件时的降级
python Tool/skill/supply-chain-security/scripts/sbom-reach.py \
  --lock package-lock.json --source src --out reach.json

# 3) 清单盘点（宽版本/锁完整性/CI）
python Tool/scripts/sc-check.py --path . --out sc.json
```

## 判据（确认）

1. `components_total > 0`，且 `by_ecosystem` 与项目语言一致。
2. `reachable[].hits[]` 至少有 `file`/`line`/`snippet`，能人工打开核对。
3. `entry_hit=true` 的组件优先：命中文件本身是入口。
4. 有 SBOM 时，`missing_from_sbom=[]` 或差异能逐条解释。
5. 不可达组件写明“未观察到调用”，并列已排查的动态导入/entry points。

## 失败判据

- `entries=[]`：入口 glob 没覆盖，先修 `--source`/`--entry`，不要据此写“全部不可达”。
- `reachable=[]` 但项目明显用框架：查 import 别名（`PyYAML`→`yaml`）与动态导入。
- SBOM 对不上 commit/digest：清单不可信，重生成或改用锁文件。
- 可达但参数不可控：写“可达、未见可控入口”，不是“可利用”。
- 只有 CVE 编号没有受影响版本/修复版本：查 advisory，不编造。

## 边界

- 静态扫描不执行代码，不处理压缩后的 bundle；前端产物先还原。
- 不覆盖 OS 包、内核模块、固件内嵌库。
- 可达 ≠ 可利用；利用链见 `Tool/skill/supply-chain-security/references/01-criteria.md` 的 SCA 行。
