# NOW —— 现在做什么（唯一行动指令）

> **规则：想知道"现在干嘛"只看这一页；想知道"为什么这样设计"看 `docs/BLUEPRINT.md`；历史一律在 `docs/history/X-*.md`（禁止作为执行依据）。**
> 本页不超过一页；每完成一步就更新"当前这一步"。最后更新：2026-10-24 S2 落地

---

## 一、一句话现状

方向已从"继续加"改成"先减法"。**S1 已完成、S2 已完成；S3 步骤 1 已落地**（9 个 `pack.json` + `route.py` + `gate.py`，preflight 43/43 全绿）。
根因（实测）：常驻 29,415 token（其中宿主基座 14,676 改不动）/ `Tool/scripts` 51 个 `.py` / 32 技能里 19 个零样本 / **76 会话 4,536 次 toolCall 里 MCP 调用 0 次**。

## 二、唯一顺序（不许跳、不换序）

| 步 | 一句话 | 成本 | 状态 |
| :-: | :-- | --: | :-: |
| **S1** | 只删不加 ✅ **已完成**（preflight 52→43 全绿、脚本 106→59、脏项 108→0，两次提交在 `s1-subtract`） | 3h | ✅ |
| **S2** | 杀 fail-open：报告生成器无证据则拒绝；超限拒绝不截断；`unknown` 不计 pass；状态副本收口 | 1d | ✅ **已完成（4/4，打红证据见 §三）** |
| S3 | 立 8 个域包 + `gate.py`/`route.py`；索引 32→9 | 2d | 🔄 **进行中：包/闸已立，剩「索引 32→9」+ 删 routing.json** |
| S4 | 全局收口：`Tool/scripts` → 7；状态 → 4；工具面 40→16 | 1d | ⬜ |
| S5 | KPI 回放：3 靶 + 1 真实目标 | 1d | ⬜ |

## 三、当前这一步 = S3「立包与闸」（细节只认 `docs/BLUEPRINT.md` §2.1–§2.4 + §5）

**已落地（步骤 1）**：8 个域包 + `softseep` 各有 `pack.json`（`.strict()` 语义），新增 `Tool/scripts/route.py` 与 `Tool/scripts/gate.py`。

| 判据 | 现状 | 命令 |
| :-- | :-- | :-- |
| ② 死路由 = 0 | **34 条路由 / 9 个包 / 死路由 0**（routing.json 的 35 条里 R23 `ad-cloud` 按 BLUEPRINT 进 `_pending` 不索引） | `python Tool/scripts/route.py --check` |
| ③ Σl1 ≤1,260 字 | **502 字**（每包 48–66 字，全部 ≤140） | `python -c "import glob,json;print(sum(len(json.load(open(f,encoding='utf-8'))['l1']) for f in glob.glob('Tool/skill/*/pack.json')))"` |
| ① 每包有绿或红 + `unknown→pass` = 0 | **pass 0 / fail 9**，`unknown_as_pass` 结构上恒 0；9 个包的 G2/G3 全绿，**红全在 G4/G5** | `python Tool/scripts/gate.py --all` |

**为什么 0 绿是当前真值**：G5 要求「整包 ≥1 条 `observed/derived` 证据」，而现在 4 个有 facts 的 case 全是 `unknown`
（S2 引入 confidence 后没重声明），其余 5 个包连 claim 都没有。**把包变绿是 S5 的 KPI 回放工作**（重跑 witness → 显式声明 observed），不是在 S3 里补一行 `observed` 就能勾掉的复选框。

**S3 剩余两件（下一步）**：
1. **索引 32→9**：24 个非包技能移入 skill 根下的 `_pending/`（下一步创建；不索引、不路由）；`softseep/SKILL.md` 的调度表改指 9 个包。收益可量化：宿主技能索引 2,809 tok → 预计 ≤800。
2. **删 `routing.json`**：路由已进 `pack.json`，但还有 3 个读者（`master-route.ps1` / `verify-routing-coherence.py` / `route-playbook-parity.py`）必须先改指 `route.py`，否则 `preflight` 的「路由↔配方一致」当场红。

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
