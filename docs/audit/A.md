# 审计 A — 全仓一致性（只读）

> 快照：审计开始 HEAD `a9d2a40` / `v1.24.2`；结束时 HEAD `0812729` / `v1.25.0`（审计期间并发提交 5 个）。
> 为对齐“HEAD 应为 v1.24.2”，P0 均用 `git show a9d2a40:` 复核；计数按结束时磁盘重数。未改代码/配置/门禁，未提交。

## 结论

- **P0=3，P1=13**。最高风险：版本/CHANGELOG 断链、QUICKSTART 首屏命令不存在、片段合入门禁假绿。
- 实测计数：24 个领域 SKILL（共 29 个 `SKILL.md`）、40 个 MCP 工具、45 个能力、22 个配方（另 INDEX/README）、31 条路由、409 篇 KB、51 个在册案例、264 张任务卡、11 份模板、11 份路由片段；R35 唯一指向 `site-clone`。
- 干净项：51 个案例的 309 条 refs 0 悬空；264 张卡 reference 0 缺失；45 个能力的 scripts/refs 0 悬空；`gen-case-index --check` rc=0；`verify-routing-coherence` rc=0（31 条）；858 条 Markdown 相对链接全通。
- 未发现：md/json 内容级重复实现（`Tool/scripts/*.py` 与域内同名脚本均为 13–19 行转发壳）；`_archive` 与主目录同名案例（仅 `README.md` 同名）。
- README×3 存在系统性漂移：同一行数字不同、en 版自相矛盾（下 P1-1）。

## P0

### P0-1 版本链断裂：tag v1.24.2 的 VERSION=1.23.1，CHANGELOG 停在 1.23.0

证据（v1.24.2 快照）：
```text
$ git show a9d2a40:VERSION                    -> 1.23.1
$ git show a9d2a40:docs/CHANGELOG.md | grep -m1 '^## \[' -> ## [1.23.0]
$ git describe --tags                         -> v1.24.2 (a9d2a40)
```
现状（v1.25.0）：`VERSION=1.25.0`、`tag=v1.25.0`，但 `CHANGELOG` 首条仍为 `## [1.23.0]`；1.23.1/1.23.2/1.24.0/1.24.1/1.24.2/1.25.0 全无条目。
影响：`setup/update.sh` 的非 git 分支和 `update.ps1 --check` 以 `VERSION` 判断更新；zip 部署用户会被告知“已是最新”而拿不到 site-clone；`update.ps1` 只打印第一条 `## [` 段落，升级到 1.24/1.25 的用户看到的是 1.23.0 的说明。
动作：立即把 `VERSION` 与 tag 对齐，并补 1.23.1→当前各版 CHANGELOG；CI 加 `VERSION == git describe --tags` 与“CHANGELOG 首条 == VERSION”断言。

### P0-2 QUICKSTART 的入口命令不存在

证据：
```text
$ grep -n preflight-classify docs/QUICKSTART.md
35:| 不知道目标是什么 | `python Tool/scripts/preflight-classify.py <样本>`（逆向域）
$ test -f Tool/scripts/preflight-classify.py     -> 不存在
$ test -f Tool/skill/softseep/scripts/preflight-classify.py -> 存在（--self-test rc=0）
```
`reverse-matrix.json` 与 `reverse.md` 任务卡均使用后者；只有 QUICKSTART 写错。用户按“5 分钟快速路径”操作会直接 `No such file`。
动作：改为 `Tool/skill/softseep/scripts/preflight-classify.py`；把 QUICKSTART/README 中所有 `python Tool/...` 纳入 `playbook-check` 式路径门禁。

### P0-3 路由片段门禁假绿：11 份片段报成 14 份，字段丢失仍 rc=0

证据：
```text
$ ls Tool/config/routing-fragments/*.json | wc -l        -> 11
$ python Tool/scripts/domain-gate.py --all | tail -1
结果: 110/110 通过
  [PASS] 路由片段已合入 SSOT（routing.json） — 14 份片段与 SSOT 一致
$ python Tool/scripts/merge-routing-fragment.py --check  -> rc=0
结构 diff（fragment vs SSOT）：R35.label 不同；R35.note、R34.note 缺失；
R25.priority_hint 缺失；R23.merge_note 仅片段有。11 份片段的 priority_hint.after
与 SSOT 实际 priority 顺序全部不一致（合并器未校验该字段）。
```
影响：门禁声称“片段已合入”，但 R34/R35 的说明与 R35 标签实际未合入；计数把 reverse 的 4 条路由当成 4 份片段。属于“门禁假绿”，后续修改会继续静默丢字段。
动作：合并器按整对象比较（label/note/priority_hint/merge_note）；门禁按文件数而非 `[OK]` 行数报数；补一条 mutation 测试（删 note 必须 FAIL）。

## P1

1. **README×3 计数漂移/自相矛盾**：`README.md:12` Release `v1.10.10`（实际 v1.25.0）；`:19` 徽章 38 工具、`:61/:148` 写 40（实测 40）；`:229` 写 23 个领域技能（实测 24 个领域 / 29 个 SKILL）。`README.zh.md:19/61/225` 同样 23/38/40。`README.en.md:65/97` 写 37 工具、`:52` 写 38、`:233` 写 38（实测 40）；`:21/:97` 写 292 KB，而同文件 `:68/:197/:253` 写 409（实测 409）。动作：统一为 24/40/409，并删掉 fork 时代的 v1.8.4/v1.10.10 徽章或改为自动变量。
2. **QUICKSTART 门禁数字过期**：`docs/QUICKSTART.md:3` 写“101 条门禁”、`:42` 写“本域 7 条”；实测 `domain-gate --all` 110/110，单域 10/10。动作：去掉写死数字，或从 JSON 结果生成。
3. **playbooks/INDEX 是过期派生件**：`Tool/playbooks/INDEX.md:6-9` 写 60 条 / 覆盖 55 / 91.67%；实测 `intent-coverage` 为 90/90/100%。动作：由脚本重生成并纳入门禁，禁止手改。
4. **AUDIT 当前事实过期**：`docs/AUDIT.md:410` 的 v1.24.0 验收 101/101；`docs/AUDIT.md:406` 与 v1.25.0 段均写 44 个能力；实测 110/110、45 个能力。另 `AUDIT:348` 写 47 案例（实测 51），`AUDIT:67` 写 240 张卡（实测 264）。动作：只保留“当时”数字并标注历史，当前摘要改由计数脚本生成。
5. **DEFERRALS 过期**：`docs/DEFERRALS.md:15` D6 写“全量 240 张”、`:19` D11 写“10 域”；实测 264 张、11 域。动作：改为 264/11，或删掉“全量 240”承诺。
6. **DOMAIN-SPEC “十域”实际列 11 个**：`docs/DOMAIN-SPEC-v2.md:13` 标题写“十域（重点）”，同格列出 11 个（含 site-clone 与 reverse）；`:16` 又写“其它十域”。动作：统一为“11 域”。
7. **BASELINE-FREEZE 冻结值与现状脱节**：`MANUAL/BASELINE-FREEZE.md:137-142` 写 MCP 38、技能 17、单文件 2594、first-party 660；实测 `check-budget` 为 40、30、2996、809（均未超上限）。动作：更新“当前”列；单文件已接近 3200 上限，应列入拆分计划。
8. **模板计数文案错误**：`domain-gate.py:684-685` 断言信息写“十份模板”，实测 `Tool/cases/_templates/*.json` 为 11 份（11 域）。动作：改为 `len(DOMAINS)` 动态输出。
9. **案例库说明指向不存在路径**：`Tool/cases/README.md:4` 写 `Tool/reverselab/kb/`；实际为 `Tool/mcp/Tool/reverselab/kb/`（`Tool/reverselab` 不存在）。动作：改路径；该错误在 README 主文档中已修正，案例说明漏改。
10. **孤儿文档**：`Tool/docs/STAGE0.md`、`Tool/docs/WORKSPACE_RULES.md` 首方文件中 0 入链（`grep -rl` 排除自身后为 0）。`WORKSPACE_RULES.md` 仍是“主人/小π”旧规范，与仓库当前 scope 口径冲突。动作：STAGE0 挂到 `00-analysis/SKILL.md` 或 docs 索引；WORKSPACE_RULES 归档或重写。
11. **apkseep 6 篇 references 未进 SKILL 主索引**：`references/precedents/*.md`（5 篇 + README）与 `references/coverage/route-inventory.md` 仅在 `references/routing.md` 有入链，`SKILL.md` 只直接引用 case-3。其余 28 个 SKILL 的 references 均全索引。动作：在 SKILL 的 references 索引补一行“precedents/ 与 coverage/ 入口”，或明确 routing.md 为二级索引并加门禁。
12. **案例工程计数口径不一**：`MANUAL/DEPLOYMENT-CHECKLIST.md:98` 写“15 个项目工程（项目A~N + 案例-6.9）”；实测 `项目A~N` 14 个（主目录仅 A/B/I，其余 11 个在 `_archive`）+ `案例-6.9换肤壳` + `案例-真实补丁a` = 16 个目录；README `:256` 写“14 大案例库”但主目录只有 3 个项目目录。动作：统一“14 个项目 + 2 个演练案例（11 个归档）”，并在 README 标明归档位置。
13. **`signin-automation` 是“无 SKILL 的技能目录”**：`Tool/skill/signin-automation/` 只有 `scripts/` 4 个能力脚本（session-pool/schedule-notify/captcha-branch/tls-fingerprint 的 refs 指向这里），没有 `SKILL.md`、案例或配方入口；`check-budget` 却把它计为技能（输出 30，而实际 SKILL.md 为 29），造成“技能数”口径再漂移。动作：补 `SKILL.md` 与索引，或把脚本移到 `Tool/scripts/` 并在 `check-budget` 排除非技能目录。

## 建议动作（按优先级）

1. 先修 P0-1/P0-2：发版脚本先断言 `VERSION/tag/CHANGELOG` 三者一致；QUICKSTART 改为真实路径并加命令路径 lint。
2. 修 P0-3：合并器全字段比较 + 按文件数报数 + 删 note 的 mutation 测试。
3. 把 README/QUICKSTART/INDEX/AUDIT/DEFERRALS 的计数改为脚本生成或删除写死数字；为 README×3 加“同一指标必须同值”的检查。
4. 清理孤儿文档与旧路径；apkseep 二级索引显式化。
5. 本报告只读完成，未 commit；P0 修复前不建议把当前 tag 作为“可交付基线”。
