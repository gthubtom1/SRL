> ⛔ **已归档（2026-10-24）——禁止作为执行依据。**
> 现行唯一入口：`docs/NOW.md`（现在做什么）+ `docs/BLUEPRINT.md`（架构口径）。
> 本文仅作历史记录与证据出处。

# 域包规范（Domain Pack Spec）—— 让"再加一个领域"永远不再把系统撑坏

> ⚠️ **背景/依据文档，不是执行口径。** 唯一的数字与批次顺序见 `docs/history/X-PLAN-FINAL.md`（冲突一律以它为准）。

> 2026-10-23 定稿。回答一个问题：**以后加逆向以外的任何领域（Web / AD / 固件 / LLM 安全 / 插件 / 取证…）、加技能、加工具，怎么保证不再重演这次的翻车。**
> 依据：`docs/history/X-RESEARCH-BASELINE.md`（20 条指令是遵循率悬崖；常驻层每多 1k token 就少 1k 工作记忆）。数字口径：`Tool/scripts/prompt-budget.py`、`Tool/scripts/domain-pack-check.py`。

---

## 0. 一句话

**扩能力只能走四条单一入口，每条入口都有一个脚本闸；没有第二条路。**

原来我们扩能力的方式是"往提示词里再写一段"——那是唯一没有闸的入口，所以全部问题都从那里长出来。

---

## 1. 四条单一入口（唯一允许的加东西方式）

| 你要加什么 | 唯一落点 | 落完必须跑的闸 | 会不会进常驻层 |
| :-- | :-- | :-- | :-- |
| **一个领域**（新赛道） | `Tool/prompts/domains/<domain>.md`（任务卡） + `routing.json` 一条路由 + `Tool/skill/<name>/SKILL.md` | `domain-pack-check.py` | **只进 L1 描述（≤140 字）** |
| **一个技能** | `Tool/skill/<name>/SKILL.md` + `routing.json` 路由 | `domain-pack-check.py`（索引预算） | 同上 |
| **一个工具** | `Tool/config/tool-capabilities.json` + `Tool/config/tool-runtimes.json`（+ `Tool/scripts/<name>`） | `preflight.py` + `mcp-param-contract.py` | **0**（按需调用） |
| **一条规则** | ① 能写成 `if` → `Tool/scripts/*` 或 `extensions/*`；② 写不成 → 该领域 SKILL 的阶段契约 | `preflight.py` | 只有"脚本判不了"的才进常驻，且计入 20 条上限 |

**绝对禁止的第五条路**：往 `AGENTS.md` / 人设卡里再写一段。这就是这次翻车的唯一入口。

---

## 2. 域包的三层披露（照 Anthropic Agent Skills / Google skill-reach 的成熟做法）

```
L1 选择面（常驻，每轮都在）   name + description ≤ 140 字
      ↓ 命中路由 / 用户点名
L2 主指令（触发时加载）       Tool/skill/<name>/SKILL.md（阶段契约 + 战术）
      ↓ 需要细节
L3 参考（按需翻）             references/*.md、Tool/prompts/domains/<domain>.md（任务卡）
```

**为什么必须是三层**：常驻层只放"什么时候用我"，不放"怎么用我"。这一条守住了，加 30 个领域也只增 30×140 字。

---

## 3. 加一个新域的 6 步（照抄即可）

```bash
# 1) 写 L1：一个技能目录 + 140 字以内的 description（只有触发条件，没有战术）
mkdir -p Tool/skill/<newdomain> && $EDITOR Tool/skill/<newdomain>/SKILL.md

# 2) 写 L2 契约头（必须 4 行：进入条件 / 退出条件 / 硬闸命令 / ASK 点）
#    这是本次复盘新增的强制结构，见 §4

# 3) 写 L3 任务卡（六段：触发词 / 前置 / 步骤 / 判据 / 失败判据 / reference）
$EDITOR Tool/prompts/domains/<newdomain>.md

# 4) 注册路由（label + skill + must 正则，至少 1 条）
$EDITOR Tool/scripts/routing.json

# 5) 过闸（三连，缺一不许合并）
python Tool/scripts/domain-pack-check.py     # 索引预算 + 路由自洽 + 任务卡完整
python Tool/scripts/preflight.py --fast      # 仓库门禁
python Tool/scripts/prompt-budget.py         # 常驻层有没有变胖

# 6) 复测路由命中（防止新域抢走老域的触发词）
python Tool/scripts/preflight.py --fast 2>&1 | grep "路由探针"
```

**准入硬条件：`domain-pack-check.py` 退出码 0。** 索引超预算时它直接失败，逼你先删/合并一个旧技能——这就是"总量守恒"。

---

## 4. L2 契约头（所有域共用同一套，加域不用改流程）

每个 `SKILL.md` 开头必须有这 4 行，**阶段编号全系统统一**，域只填内容：

```markdown
## 阶段契约
- 进入：<上一阶段的产物文件 + 哈希>（由 case_state.py gate 校验，不接受自述）
- 退出：<本阶段必须落盘的产物 + 判据>
- 硬闸：`python Tool/scripts/case_state.py gate --case <case>`
- ASK ：<本阶段需要真人做的那一件事，或写「无」>
```

五阶段全系统固定：`0 分析 → 1 人手（登录/授权）→ 2 动态 → 3 实施 → 4 验收`。
**加任何新领域都不改这五步**——Web 域的"1 人手"是登录打点，固件域是接 UART，逆向域是输卡密；流程一致，只是内容不同。这是"扩域不炸"的结构基础。

---

## 5. 预算表（谁超谁负责）

| 层 | 硬预算 | 超了会怎样 | 谁来拦 |
| :-- | :-- | :-- | :-- |
| 常驻层合计 | **≤ 8,000 token** | 遵循率下降、压缩变频繁 | `prompt-budget.py --ceiling 8000`（进 preflight） |
| 同时生效的强制语句 | **≤ 20 条**（目标 12–15） | 遵循率进崩塌区（外部实测） | `prompt-budget.py` 的"强制语句密度"段 |
| 技能索引 | **≤ 12,000 字（≈3,000 token）** | 常驻层挤爆工作记忆 | `domain-pack-check.py` |
| 单个技能描述 | **≤ 140 字**（硬上限 180） | 索引线性膨胀 | `domain-pack-check.py` |
| 子代理回执 | **≤ 2,000 token** | 主对话被摘要淹没 | 子代理契约（阶段执行器 prompt） |
| 单次会话主对话峰值 | **≤ 40,000 token** | 进入压缩、开始失忆 | 主对话节律（15 分钟落账 + 60% 前置落盘） |

**当前读数（2026-10-23）**：常驻 29,415 / 8,000 ✗；强制语句 79 / 20 ✗；技能索引 5,644 / 12,000 ✓；技能描述 12 个超硬上限 ✗。

---

## 6. 为什么这样就"以后都不会再出问题"

因为**乘数关系被切断了**。原来一个动作的影响是：

```
加一段规则 → 常驻层变大 → 每一轮 × 每一个子代理 都要付 → 遵循率下降 → 靠再加规则补救 → 再变大（正反馈）
```

现在每个动作的影响被限制在它自己的层里：

| 动作 | 影响面 | 有没有上限 |
| :-- | :-- | :-- |
| 加一个领域 | L1 +140 字；L2/L3 按需 | 有（索引预算 12,000 字） |
| 加一个技能 | 同上，且**必须挤掉一个** | 有（同上） |
| 加一个工具 | 0（不进常驻，按需调） | 无上限，也不需要有 |
| 加一条规则 | 只能进脚本；脚本判不了的进阶段契约（在 L2，不在常驻） | 有（20 条） |

**正反馈回路被打断的那一刀**：规则一旦超 20 条，`prompt-budget.py` 直接失败——想加新的，必须先删旧的。

---

## 7. 反例复盘：这次是怎么胖起来的（三个动作，全是第五条路）

| 动作 | 后果 |
| :-- | :-- |
| 给人设卡加"范围/反退缩/风格"长篇（28.7KB） | +7,451 token/轮，36 条强制语句 |
| 给 `AGENTS.md` 逐条加纪律（14.5KB → 23.8KB） | +37 条强制语句；规则总数 79 |
| 把 31 个技能全量常驻索引 | +3,969 token；且**没有一条被读过**（`SKILL.md` 出现 0 次） |

合计 29,415 token / 79 条。**三个动作都走了"往提示词里再写一段"这条无闸入口。**

---

## 8. 三道闸怎么联动

```
加东西 ─┬─ 规则？  → 能不能 if ──能──→ Tool/scripts/* 或 extensions/*  （preflight 校验）
        │                    └─不能──→ 域的 SKILL 阶段契约（L2，不在常驻）
        ├─ 技能/域？→ domain-pack-check.py（索引预算 + 路由 + 任务卡）
        └─ 工具？   → tool-capabilities.json / tool-runtimes.json（preflight + mcp-param-contract）

每次会话开始：prompt-budget.py（常驻 ≤8k、强制语句 ≤20）
每个阶段切换：case_state.py gate（产物文件 + sha256，不收自述）
每次工具调用：cmd-guard（网络禁手 block / 启动纪律 warn / 超时兜底）
```

四道闸，四个时机，各管一段。**没有任何一段是靠"模型记得住"来保证的**——这正是和这次之前的最大区别。

---

## 9. 落地顺序（不要跳）

| 期 | 做什么 | 完成判据 |
| :-- | :-- | :-- |
| 一期 | `gate` 硬化（看产物 + sha256）；`prompt-budget` / `domain-pack-check` 进 preflight | 两个脚本都能让 preflight 失败 |
| 二期 | 人设卡瘦身（28.7KB → ≈8KB）；12 个超长技能描述压到 ≤140；裁掉 4 个孤儿技能 | 常驻 ≤ 16,000；强制语句 ≤ 40 |
| 三期 | 换 slim AGENTS（`docs/history/X-AGENTS-SLIM-DRAFT.md` 的 20 条）；技能索引按项目裁剪 | 常驻 ≤ 8,000；强制语句 ≤ 20 |
| 四期 | 主对话统筹官 + 子代理阶段执行器（回执 ≤2k） | 主对话峰值 ≤ 40,000；子代理 ≥ 3 |

**顺序不能反**：先有闸，再瘦身。反了就是"撤掉护栏但没接上机制"。
