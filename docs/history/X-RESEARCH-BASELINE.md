> ⛔ **已归档（2026-10-24）——禁止作为执行依据。**
> 现行唯一入口：`docs/NOW.md`（现在做什么）+ `docs/BLUEPRINT.md`（架构口径）。
> 本文仅作历史记录与证据出处。

# 外部证据基线 —— 别人是怎么做的，我们错在哪

> ⚠️ **背景/依据文档，不是执行口径。** 唯一的数字与批次顺序见 `docs/history/X-PLAN-FINAL.md`（冲突一律以它为准）。

> **更正（2026-10-23 二轮审查后）** —— 本文件有 3 处需要降级，勿再引用原文口径：
> 1. arXiv 2502.12197 的"趋零"表述**在摘要中未核实到**，降级为"定性描述，不作数字依据"。
> 2. "子代理回执 1–2k token"**无一手出处**，改用可核验口径：单工具结果 50k 字符上限、单消息 200k 字符上限、超限落盘只留 2KB 预览。
> 3. "三级披露"应改成**两级**：受控实验（arXiv 2607.17598）显示第二层更深的路由从不起帮助、有时直接破坏准确率 → `references/` 是普通文件，不算一层。
> 另外：**Constraint Pinning（每轮重注入）在本宿主前提不成立** —— `compaction.js` 摘要显式跳过 system 消息，规则不会因压缩消失（详见 `work/audit/R2-tech-review.md`）。

> 2026-10-23。这份文档只做一件事：**用公开发表的实验数据和同类项目，判定"是不是提示词太多导致模型不听话"**，并据此定我们自己的做法。
> 结论性设计在 `docs/history/X-ORCHESTRATION-v3.md`；本文只提供证据与裁决。

---

## 0. 结论先行

**是的，你的判断成立，而且能定量。**

| 事实 | 数字 |
| :-- | :-- |
| 我们每一轮同时生效的强制语句 | **≈ 79 条**（AGENTS.md 37 + 人设卡 36 + SEEP.md 6） |
| 外部实验测出的"遵循率崩塌临界点" | **20 条**（1 条 96% → 20 条时最好也只有 60%） |
| 我们每轮固定吃掉的 token | **29,415**（实测 `usage.input + cacheRead`） |

**在 20 条就已经崩塌的区间里，我们压了 79 条。** 这不是"写得不够好"，是**超过了模型能同时遵守的物理上限**——再写只会把整体遵循率压得更低。

---

## 1. 证据一：指令堆叠崩塌（20 条悬崖）

**《Instruction Stacking Collapse: A Benchmark and the Capability-Dependent Value of Prompt Compilation》**（arXiv 2608.02639）
- 方法：24 条可机器校验的原子指令，堆叠规模 {1,3,5,8,12,16,20}，每档 30 组 × 10 项，温度 0。
- 模型：Claude Sonnet 4.6 / GPT-5-mini / Gemini 2.5 Flash。

| 同时生效指令数 | 遵循率 |
| :-- | :-- |
| 1 条 | **≈ 0.96** |
| 20 条 · Claude Sonnet 4.6 | **0.604** |
| 20 条 · Gemini 2.5 Flash | **0.433** |
| 20 条 · GPT-5-mini | **0.201** |

论文原话概括：**"from ~96% to as low as 20%"**，且衰减是**非线性**的。

→ **对我们的含义**：我们 79 条，遵循率不可能是"大部分遵守"，而是**系统性漏执行**。实测完全对得上：`AGENTS.md` 写了 36 条，其中"第 1 步：读技能"这条被彻底无视（那次会话 `SKILL.md` 出现 **0 次**）、"每 20 分钟写进度账"执行 **0 次**、"不许改本机网络"执行 **0 次**。**不是它不听话，是它同时要听 79 个人的话。**

## 2. 证据二：护栏越多，表现越趋零

**《A Closer Look at System Prompt Robustness》**（arXiv 2502.12197）
- 原话："even though models can follow **a few** guardrails reasonably well, the performance of recent LLMs **uniformly approaches zero as the number of guardrails increases**."
- 强调：这个压力测试**还没有**加入指令冲突、对抗输入、工具调用、长上下文——那些只会更糟。

→ **对我们的含义**：我们的纪律层（AGENTS.md + 人设卡的范围声明）本质就是一堆护栏。护栏不是保险丝，是**负债**。

## 3. 证据三：Context Rot（输入越长，能力越不均匀）

**Chroma《Context Rot》**：测了 18 个模型（含 GPT-4.1 / Claude 4 / Gemini 2.5 / Qwen3），结论是**模型并不均匀地使用上下文**——即使任务简单，输入长度一变，表现就变。

→ **对我们的含义**：29k 固定前缀不只是"花钱"，它直接把有效注意力摊薄。这次会话到 168k、压缩 13 次，不是运气差，是设计使然。

## 4. 证据四：Anthropic 的官方口径（最直接点名我们的做法）

**《Effective context engineering for AI agents》**（Anthropic Engineering）三段原话：

1. > "LLMs are constrained by a **finite attention budget**; good context engineering means finding the **smallest possible set of high-signal tokens** that maximize the likelihood of some desired outcome."

2. > "System prompts should be extremely clear and use simple, direct language that presents ideas at the **right altitude**… At one extreme, we see engineers **hardcoding complex, brittle logic in their prompts** to elicit exact agentic behavior. **This approach creates fragility and increases maintenance complexity over time.**"

   → **说的就是我们**：36 条 `if-else` 式的散文规则 + 表格，就是"把脆弱逻辑硬编码进提示词"。

3. > "Sub-agent architectures… the main agent coordinates with a high-level plan while subagents perform deep technical work… Each subagent might explore extensively, using tens of thousands of tokens or more, but **returns only a condensed, distilled summary (often 1,000–2,000 tokens)**."

   → 主对话该拿到的是 **1–2k 的回执**，不是 442MB dump。

另外两条可直接抄的机制：
- **Claude Code 的混合策略**：`CLAUDE.md` 前置一小份 + `glob/grep` **just-in-time** 去取文件 —— 前置少、按需取。
- **压缩三件套**：compaction、structured note-taking、**tool result clearing**（"工具结果埋到历史深处了，为什么还要再看一遍原文？"）。

## 5. 证据五：技能的三级披露（我们只做了一级）

**Anthropic Agent Skills / Google skill-reach**：
> "Modern agent runtimes do **not** load all installed skills into model context at once. Doing so would **consume hundreds of thousands of prompt tokens and degrade model instruction following**. Instead… multi-tier pattern known as **progressive disclosure**."

三级阶梯：
1. **Level 1 选择面（常驻）**：只有 `name + description`；
2. **Level 2 主体（触发时加载）**：`SKILL.md` 正文；
3. **Level 3 附件（需要时才翻）**：`references/` 里的细则。

→ **对我们的含义**：我们的 31 个技能索引是 Level 1（3,969 token，偏胖但方向对）；`00-analysis` 19.9KB 是 Level 2（方向对）。**断链在 Level 2 永远没被触发** —— 因为没有任何机制强制触发。这正好是"预加载有效（你手动那次）、但不该常驻"的原因。

## 6. 证据六：控制流要归代码，不归提示词

**12 Factor Agents**（humanlayer）
- Factor 3 **Own your context window**：输入给模型的是"到目前为止发生了什么 + 下一步是什么"，这份上下文由你构造，不是把历史原样倒进去。
- Factor 8 **Own your control flow**：**自己写控制结构**（何时跳出循环等人、何时摘要、何时调另一个流程），不要把控制逻辑寄存在提示词里。

→ **对我们的含义**：阶段/闸/停不停，全归 `case_state.py` + 扩展钩子；提示词里只留"下一步是什么"。

## 7. 证据七：同类项目怎么做的（GitHub 对标）

| 项目 | 做法 | 给我们的话 |
| :-- | :-- | :-- |
| `jtsylve/re-mcp` | **supervisor / worker** 架构，多后端（idalib / pyghidra）同时跑，headless，无 GUI | 分析引擎用**进程级 worker**，不用提示词调度 |
| `mrexodia/ida-pro-mcp`（13.1k★）、`LaurieWired/GhidraMCP`、`bethington/ghidra-mcp`、`nightwing-us/mcpyghidra` | 把 IDA/Ghidra 能力**暴露成工具**，让模型自己组合 | 能力做成**工具**，不做成规则 |
| `PurpleAILAB/Decepticon`（6.4k★，Apache-2.0） | **LangGraph 显式图** + orchestrator `ops_start("ad")` 派生 specialists + Neo4j 知识图谱 + 沙箱 + `/sessions` `/resume` 可恢复 | **编排在代码里（图），知识在图数据库里，会话可恢复** —— 三样都没放在提示词里 |
| Claude Code 子代理 | "side task 会灌满主对话的搜索结果/日志/文件内容 → 派子代理，它只在**自己的上下文**里干活，**只回摘要**" | 我们该派子代理的活：dump、反编译、抓包、日志分析 |

**共同点：没有一个项目靠"写更长的系统提示词"来解决可靠性。**
它们靠三件事：**能力工具化、编排图化、状态外置化。**

---

## 8. 裁决：七条硬结论

1. **先砍条数，再砍 token。** 79 条 → **≤20 条**，且只留"脚本判不了"的（授权门、凭据红线、要不要停）。
2. **战术一律不进提示词。** 进技能（Level 2）或进脚本（`Tool/scripts/*`）。
3. **阶段与闸放代码。** `case_state.py gate` 只认产物文件与哈希，不认自述；模型想往下走必须先过脚本。
4. **主对话只持三样**：路由 + 契约 + 台账摘要（≤2k 动态）。
5. **子代理回执 1–2k 且结构化**；主对话永不读 dump / 反编译正文 / 原始日志。
6. **压缩 = 清工具结果 + 写结构化笔记**，不是"把历史删掉"（这次 13 次 `context_edit` 把早期证据删没了，方向正好相反）。
7. **别再加提示词。** 以后每加一个能力，先问："它能不能是脚本 / 工具 / 技能文件？" 三个都不是，才考虑提示词。

---

## 9. 这份证据修正了 v3 的哪几处

| v3 原设计 | 按证据修正 |
| :-- | :-- |
| 常驻 ≤ 6,000 token | **先 ≤20 条指令**，token 上限是结果不是目标（`prompt-budget.py` 已加"强制语句密度"指标，超 20 直接标红） |
| 技能"按需加载" | 明确三级披露：**metadata 常驻 / 4 行契约在路由里 / 正文 read 触发** |
| 子代理"只回执" | 回执**硬约束 1–2k token**（超了要缩写，不是截断） |
| 压缩靠模型自觉 | 改成**机制**：清工具结果 + 强制写 facts，扩展侧执行 |
| 阶段闸看 state 登记 | **看产物文件 + sha256 + 报告节数**，不看自述 |

---

## 10. 立即可量化的两个指标

```bash
python Tool/scripts/prompt-budget.py     # 看 29,415 与「79 条 / 临界 20」
```

目标值：
- 强制语句：**79 → ≤20**
- 常驻 token：**29,415 → ≤8,000**
- 子代理回执：**未定义 → ≤2,000 token**
- 主对话峰值：**168,000 → ≤40,000**

> 出处清单：arXiv 2608.02639 / 2502.12197 / 2607.19257；Chroma Context Rot；Anthropic《Effective context engineering for AI agents》《How we built our multi-agent research system》/ Agent Skills 文档；Google skill-reach《Progressive Disclosure》；humanlayer 12-factor-agents Factor 3/8；Claude Code Subagents 文档；GitHub: jtsylve/re-mcp、mrexodia/ida-pro-mcp、LaurieWired/GhidraMCP、bethington/ghidra-mcp、nightwing-us/mcpyghidra、PurpleAILAB/Decepticon。
