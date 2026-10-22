# P0/P1 收口清单（v1.25.1）

> 来源：docs/audit/A/B/C/D/E.md，去重排序。状态只有三种：已修 / 转为 DEFERRALS / 证据不足暂挂。

## P0

| # | 问题 | 来源 | 状态 | 证据 |
| :-- | :-- | :-- | :-- | :-- |
| 1 | 版本链断裂（VERSION/CHANGELOG/tag 不一致） | A-P0-1 | 已修 | CHANGELOG 补 1.23.1–1.25.0；VERSION=1.25.0；tag 同 HEAD |
| 2 | QUICKSTART 入口脚本路径错 | A-P0-2 | 已修 | 改为 `Tool/skill/softseep/scripts/preflight-classify.py` |
| 3 | 路由片段门禁假绿（11 份报成 14 份、字段丢失仍 rc=0） | A-P0-3 | 已修 | 按文件数报数；11 份片段全量从 SSOT 同步 label/skill/keywords |
| 4 | 能力层死层（44 id 与配方/意图脱钩） | D-P0-1 | 已修 | domain/triggers/aliases + DAG + 被引用断言 |
| 5 | forge 缺失、生成链断裂 | D-P0-2 / E-P0-2 | 已修 | `Tool/scripts/forge.py` 三合一 + 生成即门禁 |
| 6 | 路由与配方对同一句相反答案 | D-P0-3 | 已修 | R34/R35 对齐；kerberoast 词边界；片段同步 |
| 7 | 矩阵不可信 | D-P0-4 | 已修 | 脚本重算 45×11 |
| 8 | 配方命令漂移 15/22 | B-P0-2 | 已修 | `playbook-check.py` + 全量对齐；占位命令单列 |
| 9 | 证据链可静默成功 | B-P0-3 | 已修 | mutation-test 四类 + accept 脚本 |
| 10 | 05-backend-rebuild 只有文档 | B-P0-4 / E-P0-1 | 已修 | 4 脚本 + 8 refs + L3 演练 |
| 11 | site-clone 未接入三层 | B-P0-1 | 已修 | 4 能力 + 配方 + 路由 |

## P1（已修）

计数漂移（README/ROADMAP/DEFERRALS/SPEC/AUDIT）、`work/plans/` 恢复、`docs/audit/` 不参与 lint、隐私路径脱敏、意图探针 90/90、ROADMAP「十一个域」。

## P1（转 DEFERRALS）

ad-cloud 第 2 个真实案例（本机非域环境）；全量 264 张卡剧本化（60 张已成）；probe 能力补脚本（按使用顺序）；A 审计未在 tag 前落盘（本文件即其收口记录）。

## 验证

```
python Tool/scripts/preflight.py            # 36/36
python Tool/scripts/domain-gate.py --all    # 110/110
python Tool/scripts/intent-coverage.py      # 90/90
bash setup/verify.sh && powershell -File setup/verify.ps1   # 65/0
```
