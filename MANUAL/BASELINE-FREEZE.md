# MANUAL — 基线定档与增量演进规约 (Baseline Freeze & Incremental Evolution)

> **适用版本**：Seep Reverse Lab **v1.8.1（基线定档版）**
> **一句话**：从这一版起，工作台的**架构、路径、接口、配置格式全部冻结**；未来只允许「小步、纯增量、可回滚」的叠加，**不再做大手术**。

---

## 一、 定档（Freeze）意味着什么

冻结的不是功能，而是**骨架**。以下六项一旦变动，会立刻打破几十个自检项、Skill 引用与跨平台安装链，因此**永久冻结**：

| # | 冻结项 | 具体内容 | 为什么不能动 |
|---|---|---|---|
| F1 | **目录骨架** | `Tool/skill/`、`Tool/mcp/`、`Tool/mcp/Tool/`、`Tool/prompts/`、`Tool/scripts/`、`Tool/config/`、`MANUAL/`、`setup/` | `seep_mcp_server.py` 的 `TOOL_DIR = <脚本目录>/Tool` 是硬编码相对路径；`Tool/mcp/Tool/` 一搬，38 个工具全瘫 |
| F2 | **MCP 工具名** | 已发布的 38 个 `seep_*` 工具名与参数签名 | Skill / SOP / 报告模板 / 用户习惯全部按名引用；改名 = 静默失效 |
| F3 | **Agent 配置格式** | `~/.pi/agent/mcp.json`、`.mcp.json`、`opencode.jsonc`、`cordis.generated.yml` 的字段结构 | 四个 Agent 宿主共同消费；字段改名 = 宿主起不来 |
| F4 | **状态文件契约** | `~/.pi/agent/lab-mode.flag`、`~/.seep/tools.local.json`、`setup/.upstream-shas.json` | 跨会话/跨模型的状态延续全靠它；路径变了 = 状态丢失 |
| F5 | **体检基准项** | `verify.ps1` / `verify.sh` 的 **60 项**（只许增加，不许减少） | 它是"是否还能用"的唯一判据；减少即等于降低门禁 |
| F6 | **上游隔离边界** | `Tool/upstream/<项目>/` 的零外溢规则（`setup/upstream-rules.json`） | 防外溢是许可合规与工程安全的底线 |

> 需要改动上述任何一项时：**不是不能改，而是必须单独开分支、写迁移脚本、同步改体检项**，并当作**大版本（2.0.0）**发布。默认拒绝。

---

## 二、 未来允许的三类变更（全部「纯增量」）

### A 类：新增外挂技能（最常用，零风险）

```bash
lab：new-skill <skill-name>
# 或
python Tool/scripts/new-skill.py <skill-name> --desc "一句话描述" --title "中文全称"
```

脚手架会：创建 `Tool/skill/<name>/SKILL.md`（UTF-8 无 BOM）→ 注册进 `softseep/SKILL.md` 调度表 → 同步到 `~/.pi/agent/skills/`。
规范见 [`MANUAL/SKILL-CREATION-GUIDE.md`](SKILL-CREATION-GUIDE.md)。

**验收**：`verify.ps1` 仍 60 项全绿（新增技能不会增加体检项，除非你同时加检查）。

### B 类：新增 MCP 工具（必须遵守"末尾追加"）

1. 只允许在 `seep_mcp_server.py` **文件末尾**追加 `@server.tool()` 函数（或紧邻同类扩展块），**绝不修改既有工具实现**；
2. 新工具必须有：一句中文 `docstring`（描述+Args）、`[ERROR]` 前缀的失败返回、绝不裸抛异常；
3. 同步更新：`Tool/skill/softseep/SKILL.md`（扩展工具速查表）、`Tool/docs/EXT-ASSETS.md`、`README.md` 的工具数、`CHANGELOG.md`；
4. 在 `Tool/mcp/test_ext_assets.py` 里补一条自测（**只加不减**）。

**验收（五道闸，缺一不可）**：

```bash
python Tool/mcp/test_seep_mcp.py          # 基线 9/9
python Tool/mcp/test_ext_assets.py        # 扩展自测（当前 63 项）
python Tool/scripts/verify-routing-coherence.py   # 路由自洽
python -m pytest Tool/scripts/compliance-relay/tests -q   # 中继 84 项
powershell -File setup/verify.ps1 -Detailed        # 体检 60 项全绿
```

### C 类：文档 / 检查项 / 知识库补充

- 文档：随便改，但**数字必须与代码一致**（工具数、体检项、测试数、KB 篇数）；
- 检查项：**只增不减**；每加一项，`verify.ps1` 与 `verify.sh` **必须同步加**（保持跨平台同数）；
- 知识库：往 `Tool/mcp/Tool/reverselab/kb/` 加 md 即可，`seep_kb_search` 自动索引。

---

## 三、 明令禁止（会破坏已定档基线）

| 禁止动作 | 后果 |
|---|---|
| 搬动/重命名 `Tool/mcp/Tool/` | 38 个工具全部失效（`TOOL_DIR` 硬编码） |
| 修改 `seep_mcp_server.py` 顶部的路径常量 | 同上 |
| 删除或重命名既有 `seep_*` 工具 | Skill/SOP/用户习惯全部断链 |
| 让 `register_mcp` 无条件写仓库根 `.mcp.json` | 跑一次测试就污染受跟踪文件（v1.8.0 曾发生） |
| 用 `sed` 之类文本替换生成 `mcp.json` | 跨平台路径必坏（v1.8.0 的 Linux 安装链就死在这） |
| 在 `uninstall` 里无差别删 `~/.pi/agent/extensions/*.ts` | 会删掉用户自装扩展（如 cmd-guard） |
| 把个人绝对路径/凭据写进仓库 | 隐私门禁（D1-D5）直接红 |
| 让某个检查项在 Windows 有、Linux 没有 | 跨平台"看似全绿"的假象 |

---

## 四、 变更清单模板（每次改动照抄）

```markdown
### 变更：<一句话>

- 类型：A 新增技能 / B 新增 MCP 工具 / C 文档或检查项
- 触碰文件：
  - [ ] Tool/mcp/seep_mcp_server.py（仅末尾追加）
  - [ ] Tool/skill/softseep/SKILL.md（速查表）
  - [ ] Tool/mcp/test_ext_assets.py（新增自测）
  - [ ] Tool/docs/EXT-ASSETS.md
  - [ ] README.md（工具数）
  - [ ] CHANGELOG.md（新增小版本条目）
  - [ ] VERSION
- 五道闸结果：
  - test_seep_mcp  __/9
  - test_ext_assets __/63
  - routing-coherence PASS/FAIL
  - relay pytest __/84
  - verify 60 项 PASS/FAIL
- 回滚方式：git revert <sha>（无数据迁移，无需额外步骤）
```

---

## 五、 版本号规则

| 变更类型 | 版本位 | 例子 |
|---|---|---|
| 新增技能 / 新增工具 / 新增检查项 / 文档 | **patch**（x.y.**Z**） | 1.8.1 → 1.8.2 |
| 新能力板块（多工具 + 新 Skill + 新手册成套落地） | **minor**（x.**Y**.0） | 1.8.x → 1.9.0 |
| **触碰 F1-F6 任一冻结项** | **major**（**X**.0.0） | 1.x → 2.0.0（必须带迁移脚本） |

---

## 六、 出问题时的第一反应

1. **先跑体检**：`check.ps1` 或 `./setup/verify.sh` —— 60 项里红哪一项，就是坏在哪一层；
2. **再看路由**：`python Tool/scripts/verify-routing-coherence.py` —— 路由指向不存在的技能会静默失效；
3. **再跑三套测试**：MCP 基线 / 扩展资产 / 中继；
4. **仍未定位**：`git diff` 最近一次变更，按"四、变更清单模板"逐项对照。

> 纪律：**同一形状的失败试两次就停**，回到分类，不试第三次变种。

---

## 七、 反臃肿预算（Anti-Bloat Budget）★ 硬约束

> 立项血泪：另一个项目（relab2）就是因为"能力越加越多、层越套越深"而废弃。
> 本工作台**宁可少一个功能，也不允许多一层抽象**。

### 7.1 数量硬上限（超出即视为设计失败，必须先合并/删除）

| 对象 | 当前 | 硬上限 | 说明 |
|---|---:|---:|---|
| MCP 工具（`seep_*`） | 38 | **45** | 新能力优先"用现有工具组合"，其次才加工具 |
| 技能（Skill） | 10 | **12** | 垂直领域用外挂技能，但总数封顶 |
| `setup/` 脚本 | 20 | **22** | 安装/更新/卸载/校验 × 双平台 + 专用脚本；同一功能不允许两套 |
| `MANUAL/` 手册 | 13 | **16** | 手册之间禁止内容重复 |
| 单文件行数 | 2594（MCP 主服务） | **3200** | 超了要拆模块，而不是继续追加 |
| first-party 文件（排除 upstream 与 `Tool/mcp/Tool`） | 约 660 | **900** | 超了说明在"堆文件"而不是"做能力" |

### 7.2 三不原则

1. **不加框架层**：不允许引入新的目录层级（如 `Tool/plugins/xxx/`）、新的配置体系、新的"调度器"。
   现有 4 层（判型 → 技能 → MCP 工具 → 外部工具）就是全部。
2. **同一能力只允许一个实现**：例如"配置合并"只有 `setup/merge_agent_config.py`；
   "工具发现"只有 `tool_autodiscover.py`（MCP 侧只做薄封装）。出现第二份实现 = 必须删掉旧的那份。
3. **不加并行状态**：状态只有三处 —— `~/.pi/agent/lab-mode.flag`、`~/.seep/tools.local.json`、
   `setup/.upstream-shas.json`。新增状态文件必须同时进 `.gitignore` 并登记到本文件。

### 7.3 加功能前的四问（答不上来就不加）

1. 能不能用**现有 38 个工具 + 现有技能**组合出来？（能 → 不加）
2. 它属于"新战术域"还是"已有域的新手段"？（后者 → 写进现有技能的 references，不新建技能）
3. 它会不会让模型多一个选择题？（会 → 默认不暴露，或挂到降级链末端）
4. 删掉它，哪条链路会断？（答"不会断" → 说明它不是必需的，优先不加）

### 7.4 每次提交的自检

```bash
python Tool/scripts/check-budget.py
```

该脚本会核对：MCP 工具数 ≤45、技能数 ≤12、setup 脚本 ≤22、MANUAL ≤16、
单文件行数 ≤3200、first-party 文件数 ≤900，任一超限即返回非零。
