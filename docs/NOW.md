# NOW —— 现在做什么（唯一行动指令）

> **规则：想知道"现在干嘛"只看这一页；想知道"为什么这样设计"看 `docs/BLUEPRINT.md`；历史一律在 `docs/history/X-*.md`（禁止作为执行依据）。**
> 本页不超过一页；每完成一步就更新"当前这一步"。最后更新：2026-10-24 S2 落地

---

## 一、一句话现状

方向已从"继续加"改成"先减法"。**S1「只删不加」已完成；S2「杀 fail-open」4 件已全部落地并自验**（preflight 43/43 全绿、可控制层 14,739 tok 未变）。
根因（实测）：常驻 29,415 token（其中宿主基座 14,676 改不动）/ `Tool/scripts` 51 个 `.py` / 32 技能里 19 个零样本 / **76 会话 4,536 次 toolCall 里 MCP 调用 0 次**。

## 二、唯一顺序（不许跳、不换序）

| 步 | 一句话 | 成本 | 状态 |
| :-: | :-- | --: | :-: |
| **S1** | 只删不加 ✅ **已完成**（preflight 52→43 全绿、脚本 106→59、脏项 108→0，两次提交在 `s1-subtract`） | 3h | ✅ |
| **S2** | 杀 fail-open：报告生成器无证据则拒绝；超限拒绝不截断；`unknown` 不计 pass；状态副本收口 | 1d | ✅ **已完成（4/4，打红证据见 §三）** |
| S3 | 立 8 个域包 + `gate.py`/`route.py`；索引 32→9 | 2d | ⬜ **下一步** |
| S4 | 全局收口：`Tool/scripts` → 7；状态 → 4；工具面 40→16 | 1d | ⬜ |
| S5 | KPI 回放：3 靶 + 1 真实目标 | 1d | ⬜ |

## 三、当前这一步 = S2「杀 fail-open」（细节只认 `docs/BLUEPRINT.md` §4 D1–D3 + §3.4）

四件已落地，**每条都要能打红**（红 = 拒绝，而非"看起来成功"）：

| # | 改了什么 | 在哪 | 判据（怎么看见生效 / 打红） |
| :-: | :-- | :-- | :-- |
| 1 | **状态副本收口**：state 由 `facts.jsonl` 的 `kind:"state"` 行重放；索引 `case_state.py index` 现算；扩展停写 `memory/facts.jsonl` 与 `events.jsonl` | `Tool/scripts/case_state.py`、`Tool/prompts/extensions/seep-memory.ts`+`seep-events.ts` | `case_state.py replay --case <c>` 打印"账本行（claim/state/event）"；`ls Tool/cases/*/state.json` = 0；`ls Tool/cases/index.json` 不存在；`index --check` rc=0 |
| 2 | **报告生成器无证据则拒绝**：删掉"通过动态 Hook…成功验证…已归档至 patches/"这类缺省文案；`seep_auto_triage` 无 rabin2 且零命中即拒 | `Tool/mcp/seep_mcp_server.py` | 空字段/占位 `branch_location` → `{ok:false,error:"missing_evidence_fields"}`；无 observed claim → `{ok:false,error:"no_evidence",wrote_files:0}` 且 `reports/` 不新增文件 |
| 3 | **超限拒绝不截断**：`RESULT_BUDGET_BYTES=64KiB`；`limit_tokens` 默认 0→8000；`_run_cmd` 空输出不再回 "Success, no output" | `Tool/mcp/seep_mcp_server.py` | `grep -c "TRUNCATED" ` = 0；`seep_r2_disasm(limit_tokens=100)` → `{ok:false,error:"resource_constraint",bytes,continuation}`；坏符号 → `{ok:false,error:"empty_output"}` |
| 4 | **unknown 永不计 pass**：claim 带 `confidence∈{observed,derived,inferred,unknown}`+`authority`；`case_state.py verify` 聚合（`fail/unknown/unsupported/truncated/skipped` 任一非零即不得 pass） | `Tool/scripts/case_state.py` | `verify --all` 四个 case 全报 `UNKNOWN`（旧实现把它们当 recorded）；`gate` 对缺 confidence 的 proven 打 WARN，`--strict` 时转红 |

**新增文件（唯一一件，附 KPI 前后对比）**：`Tool/mcp/seep_contract.py`（纯函数：预算/空态/证据筛选/报告模板；无 IO、无状态、不注册工具）。
| KPI | 前 | 后 |
| :-- | --: | --: |
| MCP 主服务行数（≤3200） | 3417（超限红） | **3194** |
| first-party 文件数（≤900） | 861 | 862 |
| 工具面（40 条基线） | 40 | 40 |
| 可控制层 token（≤8k 目标） | 14,739 | 14,739 |
拆的理由只有一条：单文件预算已到 3194/3200，S2 的判据必须进代码，而 BASELINE-FREEZE §7 规定"超了要拆模块，不是继续追加"。

**遗留（S5 必须处理，不是缺陷）**：4 个老 case 的 13/6/19 条 proven 都还没有 `confidence`/`authority` → 一律 `unknown`。
这是**故意的**：自动补 `observed` 就是伪造。S5 KPI 回放时用 `prove --confidence observed --authority shipped-artifact` 逐条重声明。

## 三bis、S1 结论（教训，别重踩）

1. **「只删不加且 rc=0」是伪命题**：删任何东西都会同时打破 4 处对账 —— `MANUAL/BASELINE-FREEZE.md` 的 first-party 文件数（本次 862→861）、引用被删脚本的检查组、`mcp-param-contract.py`、文档里的反引号路径。收口要**只改数字/引用，不改逻辑**。
2. **删除类任务不许并行**：B1/B2/B3 同时删，preflight 会从 44 掉到 34（互相删了对方引用）。
3. **删前先问"谁在执行它"**：本次同一条思路复用 —— `gen-case-index.py` 原本被 `domain-gate.py:1056` 执行所以 S1 没删；S2 把两个读者改指 `case_state.py index` 之后才删，并同步 `preflight.py` 的检查组与 3 处文档。

## 四、已定决策（不可推翻，别再问）

1. **人设卡维持原样**（28,667 B / 7,451 tok）—— 实测去重会让破甲探针 2/2→1/2。
2. **派活工具只给主对话**；子代理拿不到 `Agent`（pi-web 硬限制）。
3. **GUI 交互 Agent 自己干**（截图/坐标/点击/输入）；只有"凭据字符串"和"物理动作"问用户。
4. **问人只用对话内 A/B/C**（弹窗已被 `cmd-guard` 拦）。
5. **顺序只看本页 §二**。

## 五、防漂移六条

1. 改方向先改 `docs/BLUEPRINT.md`，再改本页 §二，别在别处另写一套。
2. 任何"完成"必须答三问：谁触发 / 怎么看见生效 / 失效会看到什么。
3. 任何新增（脚本/技能/规则）必须先有一行 KPI 前后对比；没有就不加。
4. 主对话只做四件：读台账 / 写决策 / 派子代理 / 问人。
5. 每批收尾跑：`preflight --fast` + `prompt-budget` + `python -m compileall -q Tool/scripts`（当前 43/43、可控制层 14,739 tok / 目标 ≤8k）。`liveness` 已由 G9 取代，S1 后不再跑。
6. 文档只信这三处：本页（做什么）· `BLUEPRINT.md`（怎么设计）· `A1/A2/A3-*.md`（证据）。其余一律 `docs/history/X-*.md`，不得引用。

## 六、文档地图（只有三档）

| 档 | 文件 | 用途 |
| :-- | :-- | :-- |
| **行动** | `docs/NOW.md` | 你现在想知道的全部 |
| **架构** | `docs/BLUEPRINT.md` | 域包形状 / 7 脚本 / 9 闸 / 4 状态文件 / S1–S5 / KPI |
| **证据** | `work/audit/A1-local.md` `A2-upstream.md` `A3-rea.md` `V1-doc-conflicts.md` `V2-doc-vs-reality.md` | 结论的出处，只读 |
| 台账 | `docs/PLAN-SUMMARY.md` | 只记"做过什么"，不给指令 |
| 历史 | `docs/history/X-*.md` | **禁止作为执行依据** |

## 七、需要用户动作

**重启一次会话**：让 playwright 的 `--headless`、`seep-manager` profile 生效，并让 S2 改过的两个扩展（`seep-memory.ts` / `seep-events.ts`，已同步到 `~/.pi/agent/extensions/`）按新账本落盘。其余全部可由 Agent 完成。
