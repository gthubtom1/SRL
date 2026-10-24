# NOW —— 现在做什么（唯一行动指令）

> **规则：想知道"现在干嘛"只看这一页；想知道"为什么这样设计"看 `docs/BLUEPRINT.md`；历史一律在 `docs/history/X-*.md`（禁止作为执行依据）。**
> 本页不超过一页；每完成一步就更新"当前这一步"。最后更新：2026-10-24 S2 落地

---

## 一、一句话现状

方向已从"继续加"改成"先减法"。**S1/S2/S3 已完成**（9 域包 + `route.py`/`gate.py`、索引 32→9、`routing.json` 已删），**S4 已完成，S5 差证据**：`gate.py` 现在 **1 pass / 8 fail**，preflight 43/43 全绿。
根因（实测）：常驻 29,415 token（其中宿主基座 14,676 改不动）/ `Tool/scripts` 51 个 `.py` / 32 技能里 19 个零样本 / **76 会话 4,536 次 toolCall 里 MCP 调用 0 次**。

## 二、唯一顺序（不许跳、不换序）

| 步 | 一句话 | 成本 | 状态 |
| :-: | :-- | --: | :-: |
| **S1** | 只删不加 ✅ **已完成**（preflight 52→43 全绿、脚本 106→59、脏项 108→0，两次提交在 `s1-subtract`） | 3h | ✅ |
| **S2** | 杀 fail-open：报告生成器无证据则拒绝；超限拒绝不截断；`unknown` 不计 pass；状态副本收口 | 1d | ✅ **已完成（4/4，打红证据见 §三）** |
| S3 | 立 8 个域包 + `gate.py`/`route.py`；索引 32→9 | 2d | ✅ **已完成**（含删 `routing.json`；过程中用探针抓出 3 个真 bug） |
| S4 | 全局收口：`Tool/scripts` → 7；状态 → 4；工具面 40→16 | 1d | ✅ **已完成（按 B 口径：脚本 51→15，AGENTS.md 点名的 4 个不改名；判据见 §三）** |
| S5 | KPI 回放：3 靶 + 1 真实目标 | 1d | 🔄 **1/9 包已通过**（softseep ← golden-crackme，13 条 claim 重测为 observed）；KPI.md 首行已填 |

## 三、当前这一步 = S5「KPI 回放」（唯一 KPI 表在根目录 `KPI.md`）

**已通过 1 个包**（证明 `gate.py` 的 pass 路径真的能走通）：

```
[PASS] softseep   ok G2 pack-schema / ok G3 route-parity / ok G4 pack-witness(rc=0) / ok G5 evidence-ledger(claim 14 / strong 13)
```

怎么做到的：把 golden-crackme 的 13 条 claim **逐条用本轮实测重跑**（r2 `iI/iS/p=e/p=d/ii/izz/afl/axt/pdf/px` + `tool-acquire` 探 radare2 与 ghidra），
输出落 `Tool/cases/golden-crackme/capture/reverify-2026-10-24.log`（已进 MANIFEST），然后 `prove --confidence observed --authority shipped-artifact`。

**回放抓出一条真错**：F-013 写的「rabin2 6.2.0」与实测不符（`rabin2 -v` = **5.9.8**）→ 已 `refute` 保留历史 + 新增 F-014 记录实测版本。
这正是「旧报告只能当假设、第一条结论必须本轮实测产生」的价值。

**其余 8 个包 fail 的原因（不是没做，是没有可背书的证据）**：

| pack | 卡点 |
| :-- | :-- |
| apkseep | leaf-apk 的 F-104/F-105 依赖 `zipalign`、`aapt`（本机未装）→ 无法复验 |
| malware-analysis | leaf-pe-packed 依赖 `upx`（本机未装）→ 静态部分可复验但不足以整案通过 |
| 其余 6 个包 | 案例目录在、`facts.jsonl` 为空：从没在真实目标上跑过 |

**要变绿只有两条路**：装齐 `upx`/`zipalign`/`aapt` 后重跑 leaf-apk 与 leaf-pe-packed；或拿一个新真实目标按 `pack.json` 的 witness 跑一轮（S5 的 3 靶 + 1 真实目标）。

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
