> ⛔ **已归档（2026-10-24）——禁止作为执行依据。**
> 现行唯一入口：`docs/NOW.md`（现在做什么）+ `docs/BLUEPRINT.md`（架构口径）。
> 本文仅作历史记录与证据出处。

> ⛔ **SUPERSEDED（2026-10-24）**：本文的 **R1–R4 迁移方案勿执行**（目标值与 BLUEPRINT 不同：此处 ≤40 脚本 / 索引≤10；BLUEPRINT 为 7 脚本 / 索引 9）。仅作思路存档。

# ARCH-RESET —— 从"加"转向"领域包"（历史草案）

> 起因：上游 `angusdevgo/Seep-Reverse-Lab`（1,828 star，**13 脚本 / 5 技能**）能跑；我们二开后（**106 脚本 / 28 技能**）反而更差。
> 本文回答一个问题：**怎么样才能既比上游领域多，又不重蹈"越优化越差"的覆辙。**
> 这是一次**方向重置**，不是又一份清单。

---

## 0. 先把账摊清（实测）

| 项 | 上游 | 我们 | 结论 |
| :-- | --: | --: | :-- |
| `Tool/scripts` | 13 | **106** | 8.2× |
| `Tool/skill` | 5 | **28** | 5.6× |
| `Tool/prompts/extensions` | 2 | 7 | 3.5× |
| 注入体量 | AGENTS 9.5K + SYSTEM 14.6K = **24K** | AGENTS 12.3K + SEEP 2.1K + 人设 28.7K = **43K** | 1.8× |
| 真实样本支撑的技能 | 5/5 | **3/27 叶子有样本** | — |
| 出成品能力 | 有 | **反而不稳** | ✗ |

**关键发现：上游也注入 24K，但它能跑。** 所以"提示词太长"不是唯一原因。
真正的差距是 **多出来的 93 个脚本 + 23 个技能 + 12 份契约**，它们本该让能力更强。

---

## 1. 三个根因（按贡献度）

### 1.1 加了"协调层"，而不是加"领域"

上游的结构是：**一个路由 + 建案 + 起 MCP + 5 个自包含技能**。加一个领域，只加一个技能目录。

我们的结构是：**领域都挂在同一个全局协调层上** —— AGENTS 里的纪律、12 份契约、19 个新脚本、path-tree、canary、receipt……
于是**每加一个领域，都要同步 8 处**（审查实测：`domain_spec.py` / `seep-start.py` / `domain-gate` / `playbook-domains` / `path-tree` / taskcard / routing / 部署），且 `05-backend-rebuild` 已经掉了一个（`domain-gate` 报未知域）。

> **这是所有问题的源头：耦合点在全局层，所以能力越多，全局层越重，全局层越重，能力越难用。**

### 1.2 技能是"写出来的"，不是"提炼出来的"

上游 5 个技能都有真实项目沉淀（`softseep` 是九型范式总控、`apkseep` 有完整重打包链、`client-license-validation-bypass` 是授权校验手册）。
我们新增的 23 个里，**path-walk 的答案是 27 条叶子里只有 3 条有真实样本**。

缺样本的技能 = 一份写得很像的文档。它不提升成功率，只提升**索引体积和选择噪声**（28 个里选 1 个 vs 5 个里选 1 个）。

### 1.3 闸长在"元层"，所以永远修不完

12 个闸里，有一半是**关于闸的闸**（liveness 测 canary、manager-audit 测派活、path-walk 测覆盖）。
**元层没有底**：测出问题 → 加一个闸 → 闸本身也需要被验证 → 再加一个闸。

REA 的做法完全相反：它用 `stryker`（变异测试）+ `knip`（死代码）+ `jscpd`（重复）+ `vitest` —— **让代码自己证明自己，而不是让规则互相检查**。

---

## 2. 目标架构：**领域包（Domain Pack）+ 薄全局层**

### 2.1 形状

```
Tool/skill/<domain>/                 ← 一个领域 = 一个自包含目录
├ pack.json                          ← 声明式：入口/依赖工具/验收判据/失效条件
├ SKILL.md                           ← ≤3KB，只写「何时用我 + 3 步 + 判据」
├ scripts/                           ← 该领域专用脚本（**不外溢到全局脚本目录**）
└ cases/                             ← 1–2 个真实标靶（没标靶不许算作领域）

Tool/scripts/                        ← 全局只留执行器，不放进任何领域逻辑
├ master-route.ps1 / routing.json   ← 路由（上游原有）
├ start_mcp.py                       ← 起 MCP（上游原有）
└ gate.py                            ← 一个闸，读 pack.json 判（不是 12 个闸）
```

### 2.2 三条设计原则（照抄 REA 的 AGENTS.md）

| REA 原文 | 我们的落地 |
| :-- | :-- |
| "Dependencies flow inward: domain semantics → providers → workflows → adapters" | **领域包不引用全局逻辑**；全局层不了解领域内部 |
| "Give each interpretation and resource a clear owner. Consumers must use that owner's parsed facts" | 每个领域包**自己拥有**解析出来的事实（`case/<domain>/facts.jsonl`）；全局层只读汇总 |
| "Distinguish observations, derivations, inferences, and unknowns" | 事实必须带类型（观察/推导/推断/未知），混写视为无效 |

### 2.3 闸从 12 个收到 1 个

`gate.py` 只做一件事：**读该领域包 `pack.json` 里声明的 `witness`，跑它，红就是红**。
- 领域作者自己定义"怎么算做成"；
- 全局不预设判据（所以不会出现"site-clone 后端全缺还 PASS"这种事——那是 `site-clone` 包自己的 witness 写错了，改一处就行）；
- 元层的闸（liveness / manager-audit / path-walk）**降级为可选诊断工具**，不进主流程。

---

## 3. 四条硬规矩（防再膨胀）

1. **`Tool/scripts/` 冻结**：只接受 3 类文件（路由 / 起服务 / 一个 gate）。其余一律进领域包的 `scripts/`。
2. **没样本的技能不进索引**：`pack.json` 缺 `cases/` 或 `witness` 为空 → 进 `_pending/`（技能目录下子目录），不注入、不路由。
3. **一个领域只有一个 SKILL.md，且 ≤3KB**。超了说明它在写说明书，不是在写流程。
4. **每加一样东西，必须在 KPI 表上证明它让某个数字变好**（见 §5）。证明不了就不加。

---

## 4. 迁移四阶段（每阶段可单独验收）

| 阶段 | 做什么 | 判据 | 成本 |
| :-- | :-- | :-- | --: |
| **R1 · 止血** | ① 杀掉 2 处 fail-open（`seep_gen_security_report` 默认成功文案、`site-clone` 在 `backend_required` 非空时给 PASS）② 冻结 `Tool/scripts/` | 不带证据调报告生成器 → 报告里 `成功验证` 命中 0；那个 case 重跑从 PASS 变 PARTIAL | 半天 |
| **R2 · 审判** | 28 个技能逐个过：有真实样本 + 有 witness → 留下并补 `pack.json`；否则移入 `_pending/` | 索引里的技能数 ≤10，且每个都有 `cases/` | 1–2 天 |
| **R3 · 收编** | 12 份契约压到 3 份（人机协作 / 反假完成 / 工具阶梯）；19 个新脚本并到 3 个（测量 / 验证 / 执行）；12 个闸并成 `gate.py` | `Tool/scripts` 从 106 → ≤40；注入体量 43K → ≤28K（≈上游水平） | 1–2 天 |
| **R4 · 验证** | 三个目标各跑一次：`golden-crackme`、`leaf-pe-packed`、**一个真实目标** | 三个都出成品或明确上限；KPI 表填数 | 1 天 |

**顺序理由**：R1 半小时就能杀掉唯一的"主动编造"；R2 是最大的一刀（决定哪些技能活下来）；R3 是机械收编；R4 才有资格谈"比上游强"。

---

## 5. 唯一 KPI（这是停止循环的刹车）

在仓库根放一张 `KPI.md`，**只记四个数，每次真实任务后手工填**：

| 日期 | 目标 | 载体类型 | 出成品/上限 | token | 分钟 | 是否要人介入 |
| :-- | :-- | :-- | :-- | --: | --: | :-- |
| … | … | … | … | … | … | … |

**"想加任何东西"的前置条件**：先说清它改善哪一列，做完再填一次。
**填不出改善 → 不加。** 这条规矩的作用是：让"加"第一次有了成本，从而打断
「效果差 → 加东西 → 更重 → 更差」这个环。

---

## 6. 清单：留什么 / 降级什么 / 删什么

### 留（今天这批里真正提出品率的）
| 项 | 理由 |
| :-- | :-- |
| `gui-drive.py`（待建） | 上游没有；直接决定"能不能出成品"，也是你反复提的那个能力 |
| x64dbg stdio 桥 | 上游 MCP 也是 http 型，同样有"会话启动时不在"的 bug——这是真修复 |
| MCP 参数别名修复（空串泄漏） | 上游同源缺陷；不修就永远只能 bash 手搓 |
| `net-rollback.py` | 上游零网络保护，我们是被断网打出来的 |
| fail-open 清零 | 上游也有这个洞 |

### 降级为"可选诊断工具"（不进主流程）
`liveness-check` · `manager-audit` · `path-walk` · `receipt-check` · `session-manifest` · `canary` · `replay-history` · `p2-replay`
→ 保留但**不参与 gate 判定**，只在"想知道现在多糟"时手动跑。

### 删 / 并
- 12 份契约 → 3 份
- `domain-pack-check` / `domain-pack-baseline` / `path-tree-baseline` / `liveness-baseline` 三个基线 → 合成一份
- `sync-gate-counts.py`（只为修文档数字而存在）→ 并进汇总脚本

---

## 7. 和上游/REA 的关系（一句对照）

| | 上游 | REA | 我们（目标） |
| :-- | :-- | :-- | :-- |
| 领域 | 5 个，都实 | 每个领域一个 `src/<domain>` 目录 + contracts + artifacts | **每个领域一个自包含 pack** |
| 全局层 | 路由 + 建案 + 起 MCP（13 脚本） | composition / contracts / artifacts 三层 | **路由 + 建案 + 一个 gate** |
| 扩张方式 | 加技能（不改全局） | 加 domain 模块（依赖向内） | **加 pack（不许碰 Tool/scripts）** |
| 质量 | 靠人 | 靠 stryker/knip/vitest | **靠每包自带 witness + KPI 表** |

**目标不是比上游脚本多，而是比上游领域多、且每多一个都不加重全局层。**
