# NOW —— 现在做什么（唯一行动指令）

> **规则：想知道"现在干嘛"只看这一页；想知道"为什么这样设计"看 `docs/BLUEPRINT.md`；历史一律在 `docs/history/X-*.md`（禁止作为执行依据）。**
> 本页不超过一页；每完成一步就更新"当前这一步"。最后更新：2026-10-24 10:20

---

## 一、一句话现状

方向已从"继续加"改成"先减法"。架构蓝图已定、52/52 绿、**S1 未开始**。
根因（实测）：常驻 29,415 token / 105→106 个脚本 / 32 技能里 19 个零样本 / **76 会话 4,536 次 toolCall 里 MCP 调用 0 次**。

## 二、唯一顺序（不许跳、不换序）

| 步 | 一句话 | 成本 | 状态 |
| :-: | :-- | --: | :-: |
| **S1** | 只删不加：删自证门禁 / 孤儿 / 兼容壳 / 重复状态副本；**其余 untracked 一律 commit** | 3h | ⬜ **当前** |
| S2 | 杀 fail-open：报告生成器无证据则拒绝；超限拒绝不截断；`unknown` 不计 pass | 1d | ⬜ |
| S3 | 立 8 个域包 + `gate.py`/`route.py`；索引 32→9 | 2d | ⬜ |
| S4 | 全局收口：`Tool/scripts` → 7；状态 → 4；工具面 40→16 | 1d | ⬜ |
| S5 | KPI 回放：3 靶 + 1 真实目标 | 1d | ⬜ |

## 三、当前这一步 = S1（细节只认 `docs/BLUEPRINT.md` §3.2–§3.4 + §5）

**删**：12 个打不红的门禁（§3.2）· 4 孤儿 · 5 兼容壳 · 7 个 APK 全局重复（1,008 行）· 9 个一次性脚本 · 7 个生成器 · 元层的元层 8 个 · `probe_matrix.py`/`migrate.py`/`smoke-e2e.py` · 6 组重复状态副本 · `gate-counts.json` 与文档里所有 `N/N`。

**不删（必须改成 git 提交）**：`Tool/scripts` 内其余 untracked（19 个，含 `preflight.py`/`prompt-budget.py`/`mcp-launch.py`/`canary.py`）· 「path-tree.json」(S1 已删) · `seep-circuit.ts`/`seep-events.ts` · **全部权威文档** · 3 个 case 目录（`leaf-apk`/`leaf-pe-packed`/`_p2fixture`）。

**顺序陷阱（必须先做）**：`preflight.py` 第 1105、1141、1175 行硬依赖 `path-walk.py`/`liveness-check.py`/`session-manifest.py` —— **先改 preflight 去掉这三处依赖，再删脚本**。

**判据**：① `preflight --fast` rc=0 且项数 52→≤47；② `git status --porcelain Tool/scripts` 的 untracked = 0；③ `grep -r "gate-counts\|sync-gate-counts"` = 0；④ `python -m compileall Tool/scripts` 无 import 失败。

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
5. 每批收尾跑：`preflight --fast` + `prompt-budget`（当前 52/52、14,732）。`liveness` 已由 G9 取代，S1 后不再跑。
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

**重启一次会话**（让 playwright 的 `--headless` 与 `seep-manager` profile 生效）。其余全部可由 Agent 完成。
