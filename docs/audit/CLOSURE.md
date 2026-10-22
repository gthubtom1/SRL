# P0/P1 收口清单（v1.25.0）

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
| 8 | 配方命令漂移 15/22 | B-P0-2 | 部分 | 28 条实跑、138 条占位只校验脚本存在（口径已披露） |
| 9 | 证据链可静默成功 | B-P0-3 | 已修 | mutation-test 四类 + accept 脚本 |
| 10 | 05-backend-rebuild 只有文档 | B-P0-4 / E-P0-1 | 已修 | 4 脚本 + 8 refs + L3 演练 |
| 11 | site-clone 未接入三层 | B-P0-1 | 已修 | 4 能力 + 配方 + 路由 |
| 12 | `--case` 空集判绿 | C-P0-2 | 已修 | 不存在案例目录返回 rc=2 `case-not-found` |
| 13 | 门禁不枚举 artifacts 目录 | C-P0-3 | 已修 | 未登记产物即 FAIL（artifacts 根级） |

## P1（已修）

计数漂移（README/ROADMAP/DEFERRALS/SPEC/AUDIT）、`work/plans/` 恢复、`docs/audit/` 不参与 lint、隐私路径脱敏、意图探针 93/93、ROADMAP「十一个域」。

## P1（转 DEFERRALS）

ad-cloud 第 2 个真实案例（本机非域环境）；全量 264 张卡剧本化（60 张已成）；probe 能力补脚本（按使用顺序）；A 审计未在 tag 前落盘（本文件即其收口记录）。

## 验证

```
python Tool/scripts/preflight.py            # 36/36
python Tool/scripts/domain-gate.py --all    # 110/110
python Tool/scripts/intent-coverage.py      # 93/93
bash setup/verify.sh && powershell -File setup/verify.ps1   # 65/0
```

## C / A 报告其余 P1 处置

| 来源 | 问题 | 状态 | 说明 |
| :-- | :-- | :-- | :-- |
| C-P1-1 | 脚本覆盖不足（部分脚本无 self-test） | 转 DEFERRALS | 按使用顺序补，已列入 D 项 |
| C-P1-2 | 失败 rc 契约不统一（个别 rc=1） | 部分修 | 新脚本统一 rc=2；老脚本逐域回归 |
| C-P1-3 | mutation-test 未扩到全部反例 | 部分修 | 已覆盖 sha/timeframe/只读/伪 real 四类 |
| C-P1-4 | 脚本断言只查子串 | 转 DEFERRALS | 需语义断言，排下一批 |
| C-P1-5 | lessons 不执行 | 部分修 | accept 校验命令文本；执行由案例复跑脚本承担 |
| C-P1-6/7 | 两个门禁结论相反 | 已修 | 片段门禁按文件数报数并与 SSOT 同步 |
| A-P1-6/10/11/12 | DOMAIN-SPEC 十域/文档 0 入链/清单计数 | 已修 | 统一十一域；docs/README 建索引；清单计数同步 |
