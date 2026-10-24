> ⛔ **已归档（2026-10-24）——禁止作为执行依据。**
> 现行唯一入口：`docs/NOW.md`（现在做什么）+ `docs/BLUEPRINT.md`（架构口径）。
> 本文仅作历史记录与证据出处。

# 交接文档 —— 请独立审查 Seep Reverse Lab

# 第二轮：差分审查（任务书见 §0-A）

## §0-A 这一轮你要做什么

**前置**：你的 `work/audit/REVIEW-ROUND1.md` 我们读了。**12 条建议里采纳了 11 条**，清单与理由在 `docs/history/X-PLAN-FINAL.md` §8。
**本轮不是重写方案，是差分审查。**

请交 `work/audit/REVIEW-ROUND2.md`，**≤3 页**，回答 5 件事：

1. **误采纳检查（最关键）**：我们采纳的 11 条里，有没有哪一条被你**原意不同地理解**了？
   逐条给：`采纳正确` / `理解偏了 → 应该怎么改`。
   （例：你说"按阶段发工具面"，我们实现成"triage 只给只读工具"，这是否你的原意？）
2. **你漏判、我们新增的三件**，判它们成不成立：
   - **P0 入口话术实锤**：`Tool/prompts/tasks/reverse*.md` 里明文写着"一路做到能用为止 / 不许问要不要继续 / **不许甩 A/B/C 选择题**"，`MANUAL/ZERO-TO-HERO-WORKFLOW.md:37` 写"全自主 8~15 分钟"。这些是 `/reverse` 斜杠命令（以**用户消息**进上下文）。我们据此新增 P0 并已修 5 个文件。**你认同它是最高杠杆吗？**
   - **三问通用引擎**：任何载体只问 Q1 授权权威在哪 / Q2 改动在哪个面可见 / Q3 那个面谁在看着，路线=推论，产物必须是"路线+理由+被淘汰路线及依据"。
   - **陷阱库**（不是规则）：把"改文件被完整性自检打掉""dump 保留运行时基址"降级为提示条。
3. **自我批判**：ROUND1 里你现在**想撤回的 ≥2 条**。理由是：我们几乎全盘采纳，这本身有过度顺应的风险。
4. **三天版本**：如果只有 3 个工作日，把 P1–P3 压成**最小可验证集**——每天一个可验收产物（不是"完成某模块"）。
5. **分歧再判**：瘦身排序 / GUI 通道选择 / 子代理时机，你维持立场还是改变？改就说为什么改。

**硬约束**
- 每条必须给 `采纳 / 不采纳 + 一句理由`，不许和稀泥、不许"建议进一步评估"。
- 不重复 ROUND1 已有论述（引用它的行号即可）。
- 只读仓库；只写 `work/audit/REVIEW-ROUND2.md`。
- 这一轮是**最后一轮评审**。除非你指出"方案里有致命且无法在执行中修正的错误"，否则下一轮我们直接开工。

---

> ⚠️ **这是第二轮材料，第一轮不要给。**
> 第一轮用 `docs/history/X-HANDOFF-1-PLAIN.md`（白话版：只讲今天发生了什么 + 请对方自己写方案）。
> 本文件是对方的方案写完之后才拿出来的对照材料。

> 读者：**一个没有我们上下文的外部智能体**。你要在只读仓库的前提下，独立判断这套东西哪里会坏、方案对不对。
> 写这份文档的人 = 上一轮的执行者（我）。**我的话不等于事实**，凡是我给的结论都附了复核命令，请自己跑一遍再决定信不信。
> 版本：2026-10-23 · 对应 `docs/history/X-PLAN-FINAL.md` v3。

---

## §0 你的定位与硬约束

1. **你只读，不改仓库。** 需要写东西时，只写这一个文件：`work/audit/REVIEW-BY-EXTERNAL.md`。
2. **证据格式**：每条结论必须带 `文件:行号` 或「命令 + 输出片段」。拿不到证据的写 `推断`，并说明依据。
3. **不要相信文档里的数字**，它们大多是估算。真正的实测数字在 §3，且每个都给了复核命令。
4. **区分三类东西**：① 实测事实 ② 工程判断 ③ 我的主观偏好。我会标注，你也可以推翻标注。
5. **时间预算**：先读 §1–§4（30 分钟），跑 §9 的复核命令（10 分钟），再读 §5–§8。**别一开始就通读 90KB 技能**。

---

## §1 30 秒背景

**Seep Reverse Lab** 是一个装在 "pi coding agent" 上的**安全/逆向工作台**。它由三块拼起来：

1. **宿主**：`pi`（TypeScript 编码 agent，有扩展钩子）+ `pi-web`（Web 前端，会注入一份"破甲人设卡"）。
2. **我们的二开**（相对上游 `open-reverselab`）：31 个技能、40 个 MCP 工具、412 篇知识库、案例台账（`case_state.py`）、43 项门禁（`preflight.py`）、若干 pi 扩展（注入/护栏/记忆）。
3. **上游原版**：`Tool/upstream/open-reverselab/`（11MB，纯知识库 + skills 索引 + 一份 AGENTS.md）。

**用户想要的东西只有一句话**：给它一个真实目标（Windows PE / APK / 网站 / 浏览器插件 / 固件都可能），它要**真的产出一个能用的成品**，而不是看起来很规范。

---

## §2 系统全景（12 个组件 + 注入链）

| # | 组件 | 位置 | 干什么 |
| :-- | :-- | :-- | :-- |
| 1 | 宿主内核 | `D:/Tools/Node/node_modules/pi-web-fork/node_modules/@earendil-works/pi-coding-agent/dist/` | 组装系统提示词、压缩上下文、派子代理 |
| 2 | 扩展 | `C:/Users/toti/.pi/agent/extensions/`（仓库源在 `Tool/prompts/extensions/`） | `load-system-prompt.ts`（注入）、`cmd-guard.ts`（工具护栏）、`seep-memory.ts`（记忆）、`retry-level.ts`、`security-audit-interceptor.ts` |
| 3 | 常驻纪律 | `~/.pi/agent/AGENTS.md` | 宿主纪律（pi 内核自动注入） |
| 4 | 层间裁决 | `~/.pi/agent/SEEP.md` | 四层裁决 + 指针（我们的扩展注入） |
| 5 | 人设卡 | `~/.pi/agent/personas/p_vy9kxhj9.md` | 破甲人设（pi-web 注入） |
| 6 | 技能 | `Tool/skill/`（同步到 `~/.pi/agent/skills/`） | 32 个技能，`SKILL.md` 按需读 |
| 7 | 任务卡 | `Tool/prompts/domains/*.md` | 11 个域 / 268 张卡（222KB，参考性质） |
| 8 | MCP | `Tool/mcp/seep_mcp_server.py` | 40 个工具（radare2/frida/jadx/apktool…） |
| 9 | 知识库 | `Tool/mcp/Tool/reverselab/kb/` | 412 篇（**是 KB 不是提示词**） |
| 10 | 台账/闸 | `Tool/scripts/case_state.py` | `facts.jsonl` / `state.json` / `gate` / `deliver` |
| 11 | 门禁 | `Tool/scripts/preflight.py` | 43 项仓库检查 |
| 12 | 部署 | `setup/install.ps1`、`install-pi.ps1`、`update.ps1` | 把文件复制到 `~/.pi/agent/` |

### 2.1 运行时注入链（关键，很多问题都从这里来）

```
pi 内核 buildSystemPromptSections():
  preamble(内置)  + project_context(读 <agentDir>/AGENTS.md) + skills 索引 + cwd
   ↑ base 约 10k token        ↑ 我们 21.4KB               ↑ 32 个 name+description
  + 扩展 set 的 sections: personality(人设卡) / generic-rules(RULES.md，当前 0 字节) /
                          seep-reverse-lab(SEEP.md) / seep-boundary(常量)
```

- `project_context` 由内核 `loadContextFileFromDir` 读：候选 `AGENTS.override.md → AGENTS.md → CLAUDE.md`，**并且会沿 cwd 的每一级祖先目录各读一份**。
- `install-pi.ps1:84` 把 `SEEP.md` 与 `AGENTS.md` **都复制进 `~/.pi/agent/`** —— 这一行是两个文件被注入的直接原因。
- 实测一次会话首次调用 `usage.input + cacheRead = 29,415` token（见 §3）。

---

## §3 实测事故与硬数据（这一节是事实，不是判断）

### 3.1 事故会话 `01a1685a`（48 分钟，0 产出）

| 项 | 值 | 复核方式 |
| :-- | :-- | :-- |
| 模型 | `cpa / deepseek-v4.1-flash` | 会话 jsonl 第 3 行 `model_change` |
| 工具调用 | 167 次（bash 120） | 统计 jsonl 的 `toolCall` |
| 自然语言汇报 | **1 条** | 同上（除工具调用外只有 1 个 text 块） |
| facts 台账 | **0 条** | `python Tool/scripts/case_state.py resume --case Tool/cases/aimbot` |
| 上下文手工裁剪 | **13 次** `context_edit` | jsonl 里 `type=context_edit` |
| token | input 357,518 / output 99,118 / **cacheRead 17,052,032** | jsonl 每条 assistant 的 `usage` |
| 首次调用 | **29,415 token** | 第 1 条 assistant 的 `input+cacheRead` |
| 技能被读过 | **0 次**（`SKILL.md` 在全文出现 0 次） | `grep -c "SKILL.md" <转写稿>` |

会话原文：`C:/Users/toti/.pi/agent/sessions/--D--Project-ai自瞄--/2026-10-23T10-42-05-834Z_01a1685a-*.jsonl`
转写稿（已把 think 剔除）：`work/audit/sess1685a.txt`、`sess1685a_brief.txt`

**事故四连：**

1. **断网**：为了"接管授权服务端"，给正在上网的 DHCP 网卡（iface 14）加 `/32` 别名 `149.88.73.239`，并 `netsh winhttp set proxy 127.0.0.1:8888`。假服务器一杀 → **整机断网**，用户自己恢复。
2. **样本自毁**：把目标复制成 `AGC_nodyndbg.exe`，只改了 `DllCharacteristics` 一位 → 启动即弹 `File corrupted! This program has been manipulated...`（用户截图）。在 dump 出的 37MB 解包镜像里搜该串，**ASCII 与 UTF-16 全 0 命中** → 说明校验在壳 stub 层、解密之前。
3. **地址白跑**：`dump/AGameCrash64_unpacked.exe` 的 `OptionalHeader.ImageBase = 0x7ff65e140000`（运行时基址），而全流程按 `0x140000000` 算 VA → Ghidra 连续 7 次 `// no function at 0x1400a1c90`，白跑约 20 分钟。
4. **手搓调试器**：写了 `pydbg.py`/`whyexit.py`/`evstream.py`/`dump_proc.py` 等 5 个一次性脚本用 `ctypes` 调 `ReadProcessMemory`，而同机 `x64dbg MCP`（9094）与 `ida MCP` **调用 0 次**。

### 3.2 反例：同目标、带技能预加载的会话 `01a16865`

用户手动开了一个"带 `00-analysis` 技能"的会话，技能正文以开场消息注入（11,917 字符），产物明显结构化：`api_ctx.txt` / `auth_disasm.txt` / `parse_disasm.txt` / `fn_login.txt`。
→ **推断**：技能"在场"比"写在规则里让人去读"有效得多（后者实测 0 次执行）。

### 3.3 现有门禁与台账的实测缺陷（子代理跑出来的）

| 缺陷 | 证据 | 复核方式 |
| :-- | :-- | :-- |
| **闸能被"合法"造假通过** | `case_state.py:210-221` 对非路径文本证据直接放行；`:724-727` `depth --prove` 自动 pass。子代理用 8 条 `depth pass --note 看了眼` + `prove --evidence "我觉得是"` + `deliver --level M4` → **全 PASS，零产物** | 自己建一个空 case 试 |
| **只有阶段零一道闸** | 16 个子命令里没有 capture/动态/旁路/验收的阶段闸 | `python Tool/scripts/case_state.py --help` |
| **facts 账本分裂** | 扩展写 `<case>/memory/facts.jsonl`（`seep-memory.ts:60,288-315`），闸只读 `<case>/facts.jsonl`（`case_state.py:90-92`）；扩展默认目录 `.seep-case`（`seep-memory.ts:100-106`）与正常 case 路径不一致 | 跑一次会话看两个路径 |
| **路由表没有运行时消费者** | `routing.json` 只被 `master-route.ps1:26-45`、`case-init.ps1:190-205`、`skill-route-probe.py:47` 读；扩展里 0 个钩子读它。且实测"用IDA分析卡密"命中 `ida-reverse` 而非卡密规则（priority 里 R4 在 R2 之前） | `grep -rn "routing" Tool/prompts/extensions/` |
| **预算脚本没接进门禁** | `prompt-budget.py` 声称给 preflight 用，但 `preflight.py:307` 跑的是 `check-budget.py`（只数文件/行数）→ **43/43 全绿与"可控层超 5.5 倍"同时成立** | `grep -n "prompt-budget" Tool/scripts/preflight.py` |
| **preflight 43 项，0 项验证 agent 行为** | 无"技能是否被加载/facts 是否落账/阶段是否推进/token 是否超预算/案例是否真跑通" | 读 `preflight.py:1029-1055` |
| **ASK 从未被用过** | 历史会话里 `ask_user_question` 调用 0 次；该工具 schema 限 2–4 选项 ×≤60 字符，长卡塞不进 | 统计会话 jsonl |
| **脚本在 GBK 控制台崩** | `prompt-budget.py` 最后一行打印 `✗` 时 `UnicodeEncodeError`（我在 `PYTHONIOENCODING=utf-8` 下测，等于自己骗自己）。已加 `sys.stdout.reconfigure` 修 4 个脚本 | 不设环境变量直接跑 |

### 3.4 提示词预算实测（工具：`python Tool/scripts/prompt-budget.py`）

| 层 | tokens | 说明 |
| :-- | --: | :-- |
| pi 基座（内置提示词 + 工具声明 + 包装） | ~10,700 | 由实测锚点反推，**不可控** |
| 人设卡 | 7,451 | 28.7KB，含 36 条强制语句 |
| AGENTS.md | 6,384 | 21.4KB，37 条强制语句 |
| 技能索引（32 个） | 4,036 | name + description |
| SEEP.md | 624 | 刚从 4,183 字节砍到 2,148 字节 |
| 边界锚 | 234 | 不可省 |
| **可控制层合计** | **19,010** | 目标 ≤3,500 |
| 总计 | 29,415 | — |

**强制语句密度**：AGENTS 37 + 人设卡 36 + SEEP 6 ≈ **79 条同时生效**。
外部实验（arXiv 2608.02639，24 条可机检指令、温度 0）：1 条时遵循率 ≈0.96；**20 条时 Claude Sonnet 4.6 = 0.604、Gemini 2.5 Flash = 0.433、GPT-5-mini = 0.201**。

---

## §4 已确认的根因（我的判断，可推翻）

1. **79 条规则压给只能同时遵守约 20 条的大脑** → 系统性漏执行（与 §3.1 的"0 条 fact / 0 次读技能 / 1 条汇报"一致）。
2. **规则不是机制**：写进提示词的"必须"没有执行体；能写成 `if` 的东西不该占提示词。
3. **技能不在场**：常驻 32 个索引，但没有任何机制保证"当前阶段该用的那个"被读进来。
4. **一个会话扛全部**：dump/反编译/日志全进主上下文 → 168k、压缩 13 次、失忆。
5. **状态不在文件里可用**：账本分裂 + 闸可造假 → 压缩即遗忘。
6. **动手前没有"能不能赢"的闸**：20MB 加密模型一次没碰，一路冲向"1:1 成品"。
7. **审查只看内容不看总量与执行率**：之前的"审查 20 次都说没问题"只查"文件在不在、有没有矛盾、门禁绿不绿"。

---

## §5 已定方案摘要（`docs/history/X-PLAN-FINAL.md` v3）

**组织原则**：每一批必须回答"它把**出品率**提高了多少"，回答不了的降级到成本队列。

**六维模型**：A 出品 / B 在场 / C 可证 / D 可续 / E 可测 / F 可扩。

**A 层（案子层，效果杠杆）**

- 通用**判断引擎**（替代写死的规则）：任何载体只问三件事 —— **Q1 授权权威在哪**（磁盘/内存/服务端/UI/无）、**Q2 我的改动在哪个面可见**（文件/内存/网络/UI）、**Q3 那个面上谁在看着**（完整性哈希或签名/反调试反注入/pinning 或报文签名/自动化检测/没人看）。路线 = 三问交叉的推论，**产物必须是「路线 + 理由 + 被淘汰的路线及依据」**。
- 具体案例（`File corrupted!`、dump 基址）降级为**陷阱库条目**，只作提示，不作规则。
- **ASK = 对话内 ABC**（不用弹窗工具）：输出「A/B/C」三行，用户回字母，`case_state ask --ack A` 落账。

**B 层（harness 层，让 A 层能复现）**

| 编号 | 机制 | 关键修正 |
| :-- | :-- | :-- |
| H1 | STAGE 注入 | 拆 `seep-pinned`（纪律，**永不变化**）+ `seep-stage`（当前阶段技能摘要 ≤1KB，**只在切阶段时变**）。**不做"每轮重注入"** —— 会让整段前缀缓存失效 |
| H2 | CHECK 化闸 | `proven` 必须带可执行 check（`file_bytes / json_field / rc`），`gate` 现场跑；**sha256 不算正确性证据**；`gate --stage 0a/0b/1..4` |
| H3 | 单一账本 | 只留 `case/facts.jsonl`，对齐两处 schema，原子写 + 锁 |
| H4 | 沉默看门狗 | ≥10 次调用或 ≥8 分钟未汇报 → 强制一行状态卡 |
| H5 | 回归 | 先采基线；5 个金标准 case；确定性断言；报 **pass^3**；判据不能"奖励早认输" |
| H6 | 对账 | preflight 输出 `{ran,names[]}` 与 baseline 比 missing/duplicated；凭据写盘前 scrub |

**技能链**：新增 `00-triage`（S0 快筛，20 分钟出「目标画像卡」六字段：载体/保护/授权权威/改动面/检测器/交付壁垒）→ `00-analysis`（D1–D7 深入，只对卡里的 `?` 和壁垒花时间）。`01-gate-bypass` 的"一次读 4 个技能"改成"按画像卡选 1 个"。

---

## §6 已被否决的方案（请勿重复提出，除非你有新证据）

| 否决项 | 理由 |
| :-- | :-- |
| 每轮重注入纪律（Constraint Pinning） | 宿主压缩摘要**显式跳过 system 消息**（`compaction.js:51`），规则不会因压缩消失；"每轮变"只会打掉缓存 |
| 把 `routing.json` 顺序修复当效果项 | 运行时无消费者，改的只是测试输入 |
| `prompt-budget` 直接进 preflight | 量字数不量行为，且会让唯一门禁永久变红 |
| 提示词披露层级重构（二级/三级之争） | `references/` 本来就是普通文件，零变化 |
| 用 sha256 当"正确性证据" | 只证"没被改过"，文件和哈希都能由模型自己写 |
| 金标准断言"应说清理由" | 会**奖励早认输**：越早拒绝 pass³ 越高 |
| 依赖弹窗式 ASK | 改为对话内 ABC，无不确定性 |

---

## §7 悬而未决 / 未验证（**请重点看这里**）

1. **人设卡的"授权/范围/拒答"段落能不能删？** 人设卡里有 27 处"授权/范围"、27 处"拒答/重定向"、10 处"凭据"命中，与 AGENTS / 边界锚高度重复。删掉能省 ~6k token，但可能改变破甲行为。**没有人验证过。**
2. **5 个金标准 case 从哪来？** 案例库 52 例里只有 2 个真生成器、13/52 无 input、`repro` 全是散文。**没有 fixture 就无法回归。**
3. **H1 的缓存代价真实值**：同 stage 内 `cacheRead / promptTokens` 是否真的 ≥0.9，**没测过**。
4. **79 条里到底哪些是真互斥？** 外部证据提示"输出 JSON"这类规则可与 9 条联合不可满足；应先跑 O(n²) 冲突表，而不是硬砍条数。**没做过。**
5. **模型能力下限**：哪些目标根本做不了，没有先验库。
6. **`00-triage` 刚写完，一次都没跑过。** 20 分钟能不能出卡，未验证。
7. **pi-web 是否渲染长文本选项**（虽然方案已改成纯文本 ABC，不依赖它）。

---

## §8 请你回答的 12 个问题（每个都要给证据或明确写"推断"）

**关于诊断**
1. §3.3 的 7 个缺陷，你能复现几个？有没有哪一条其实是**误诊**？
2. §4 的 7 条根因里，哪一条是**最不需要**的（即修了也不改出品率）？
3. 有没有**我们完全没提到**、但会显著拉低出品率的东西？请自己扫一遍 §2 的 12 个组件。

**关于方案**
4. §5 的 H1（STAGE 注入）在 pi 的扩展 API 里真的可行吗？改 `systemPromptOptions.sections` 会不会破坏前缀缓存？给出你的估量。
5. H2 的 CHECK 化闸，能不能被"写一个内容垃圾但格式正确的文件"绕过？如果会，缺什么判据？
6. A 层的**三问引擎**（权威/改动面/检测器）够不够通用？拿 **APK、网站、浏览器插件、固件** 各举一个例子，说明它会不会推出错误路线。
7. 方案把"效果项"排在"成本项"前面（A 层先做，瘦身后做）。这个顺序你认同吗？如果不认同，给出你的顺序和理由。
8. **最大的风险**：如果只能做一件事提升出品率，你会做哪件？为什么它与方案选的不同（或相同）？

**关于方法**
9. 我们判断"提示词太多"用的证据是 arXiv 2608.02639（20 条指令 → 60% 遵循率）+ 79 条实测。这个推理链有没有漏洞？
10. "技能读 0 次"是因为规则没人执行，还是因为**技能本身太长/太贵**（`00-analysis` 19.9KB、`softseep` 38KB）？你怎么区分这两种解释？
11. 一个 48 分钟、167 次工具调用、0 产出的会话，你判断主因是**模型太弱（flash）**、**提示词过载**、还是**缺少停止条件**？请给出你的归因比例。
12. 如果你要接手继续做，**第一周你会做什么、不做什么**？

---

## §9 复现与取证命令（可复制粘贴）

```bash
cd D:/Seep-Reverse-Lab

# 1. 提示词预算 + 强制语句密度（这是唯一口径）
python Tool/scripts/prompt-budget.py

# 2. 域包/路由/索引预算（当前违规 12 / 基线 12）
python Tool/scripts/domain-pack-check.py

# 3. 仓库门禁（43 项，约 40 秒）
python Tool/scripts/preflight.py --fast

# 4. 台账现状（应显示 0 条已证）
python Tool/scripts/case_state.py resume --case Tool/cases/aimbot

# 5. 会话原始数据（事故会话）
ls -la "C:/Users/toti/.pi/agent/sessions/--D--Project-ai自瞄--/"
#   转写稿（无 think）：work/audit/sess1685a.txt、sess1685a_brief.txt

# 6. 完整对话记录（用户原话 + 我的可见回复）
work/audit/DIALOGUE-user.md
work/audit/DIALOGUE-assistant.md
work/audit/DIALOGUE-full.md
work/audit/REQUIREMENTS-LEDGER.md   # 需求台账：用户说了什么、我做了什么、漏了什么

# 7. 六份子代理审查记录
work/audit/R1-repo-audit.md          # 仓库结构性缺陷（带行号）
work/audit/R1-effect-review.md        # 端到端"会掉在哪"
work/audit/R1-web-gems.md             # 外部可抄机制（54 条带出处）
work/audit/R2-tech-review.md          # 对方案的可行性攻击
work/audit/R2-effect-verdict.md       # 对方案的"自我安慰"指控
work/audit/R2-dimension-gaps.md       # 漏掉的维度（人因/腐蚀/并发…）

# 8. 注入链取证
sed -n '80,90p' setup/install-pi.ps1                       # 谁把 AGENTS/SEEP 复制进 agent 目录
grep -n "loadContextFileFromDir" -A 6 \
  D:/Tools/Node/node_modules/pi-web-fork/node_modules/@earendil-works/pi-coding-agent/dist/core/resource-loader.js
sed -n '287,320p' C:/Users/toti/.pi/agent/extensions/load-system-prompt.ts   # sections 注入
```

---

## §10 输出格式（请照这个写 `work/audit/REVIEW-BY-EXTERNAL.md`）

```markdown
# 外部审查意见

## A. 我复现了 / 没复现的缺陷
| # | 缺陷 | 复现结果 | 证据 |
|---|---|---|---|

## B. 我认为误诊的地方
（逐条：我的判断 + 证据 + 建议怎么改判）

## C. 你们没提到、但会拉低出品率的东西
（每条：是什么 / 为什么 / 怎么验证）

## D. 对 12 个问题的回答
（逐条答，带证据）

## E. 如果我是负责人：第一周做什么 / 不做什么
## F. 一句话结论：这套方案做完，出品率会从 X 变到 Y，因为……
```

---

## §11 文件地图（先看这几个就够）

| 想看什么 | 文件 |
| :-- | :-- |
| 唯一执行口径（现行方案） | `docs/history/X-PLAN-FINAL.md` |
| 外部证据与出处 | `docs/history/X-RESEARCH-BASELINE.md` |
| 用户原话（6 轮） | `work/audit/DIALOGUE-user.md` |
| 需求台账（含我漏掉的 11 条） | `work/audit/REQUIREMENTS-LEDGER.md` |
| 方案冲突审计（3 处真冲突） | `work/audit/PLAN-CONFLICTS.md` |
| 事故复盘（20 条短板） | `work/audit/2026-10-23_aimbot会话流程审计与Seep短板.md` |
| 人机协作 / 启动纪律 / 采集纪律 | `docs/history/X-EXECUTION-MODEL-v2.md` |
| 编排设计（四层 + 子代理） | `docs/history/X-ORCHESTRATION-v3.md` |
| 多领域扩展规范 | `docs/history/X-DOMAIN-PACK-SPEC.md` |
| AGENTS 瘦身草案（79→20 条） | `docs/history/X-AGENTS-SLIM-DRAFT.md` |
| 阶段技能（快筛 / 深入） | `Tool/skill/00-triage/SKILL.md`、`Tool/skill/00-analysis/SKILL.md` |
| 阶段一（授权旁路） | `Tool/skill/01-gate-bypass/SKILL.md` |
| 台账与闸 | `Tool/scripts/case_state.py` |
| 门禁 | `Tool/scripts/preflight.py` |

---

## §12 最后：判断这套东西好坏的唯一标准

不是"文档写得好不好"、"架构漂不漂亮"、"门禁绿不绿"。

**是：给它一个真实目标，它能不能在内个合理预算内，产出一个用户能拿去用的成品。**

上一轮结束时用户的原话（我记录在案，请以它为靶子）：

> "它现在确实不编了，也知道卡密得找我要了 —— **可我要的成品还是一个没有。**"

如果你认为本方案做完仍然是这个结局，请直接说，并给出你认为会改变结局的最小改动。
