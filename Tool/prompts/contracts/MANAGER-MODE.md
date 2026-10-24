# MANAGER-MODE —— 组长模式分工契约（C 方案：写/改派出去，验收留手里）

> 裁决层：本文件属于第 3 层（能力），与 `AGENTS.md` / 边界锚冲突时以它们为准。
> 落地依据：`work/audit/P5-manager-proposal.md` §2/§3-C/§4（实测数据）。
> 机检器：「manager-audit.py」(S1 已删)（判据）+ 「receipt-check.py」(S1 已删)（回执）。

---

## 1 分工表（唯一分工依据）

| 动作 | 谁做 | 理由 |
| :-- | :-- | :-- |
| 读文件 / 查台账（read / grep / find / ls / kb_search） | **主对话** | 只读、单次便宜；验收与抽检本来就要用它 |
| 跑验收脚本（`preflight` / `case_state gate` / `receipt-check` / `p2-replay`） | **主对话** | 判「行为没退化」必须有人拿全局基线，外包等于放弃签字权 |
| 抽检证据（按回执 pointer 抽 1–2 条核对） | **主对话** | 组长本职；抽检不改文件，代价接近 0 |
| 问人 / ASK 卡 / A-B-C 决策 | **主对话** | 单点接口，`AGENTS.md` §五（三档 + 必须 ASK 三条） |
| 判过不过 / 冲突裁决 / 汇总回执 | **主对话** | 要合并多份回执的上下文，跨 stint 视角 |
| todo / 进度账 | **主对话** | 排期是组长工作，外包就没人知道全局状态了 |
| 判型 / 可行性 / 路线（GATE） | **主对话** | 判型错一次 = 整轮返工（`AGENTS.md` §四点五 6） |
| **写文件 / 改代码（write / edit）** | **子代理** | 可并行、可回执、每处改动都能用 `path:line` 抽检 |
| **改文档 / 批量生成 / 批量 bash（≥30s 或 ≥3 条连跑）** | **子代理** | 探索与重跑不需要主对话上下文；失败可定位到单个 stint |
| **装工具 / 改环境 / 重建基线** | **子代理** | 有副作用且要回滚路径，出事要能指到具体一步 |

一句话：**「改东西」和「跑得久」派出去；「判断」和「签字」留手里。**

---

## 2 判据（可机检，不看感觉）

**核心指标**：`write_edit_share = (write + edit) / 全部工具调用`。

| 项 | 值 |
| :-- | :-- |
| 阈值 | `write_edit_share ≤ 3%`（`WE_BUDGET = 0.03`） |
| 基线（P5-C 实测，14 场参与统计） | **12.31%**（613 / 4981）→ 现状红 |
| 通过 | `<= 3%` → `MANAGER_OK` |
| 不通过 | `> 3%` → `OVER_BUDGET` |
| 不参与统计 | 动作数 `< 5` 的会话（空/短会话，旧版会把它们算成 ratio=1.0 的假达标） |

```bash
python manager-audit.py(S1 已删) --all --json   # rc=0 全绿 / rc=1 有 OVER_BUDGET
```

- `bash` 与 `ratio` **只作参考，不进判据** —— 主对话跑验收是本职，用 ratio 会逼着人把验收也外包。
- **连续 2 次超过 3% → 在当批收尾报告里点名**（写清场次 id + `write_edit_share` + 谁没派出去）。
  点名不是自我批评，是让人能定位"哪一批又退回去了"。
- 已知盲区：`codemode` 内可调 `write/edit/bash`，公式看不见 → 报告会单列 codemode 次数，
  **用 codemode 写文件等于绕过本契约**，视同主对话动手。

---

## 3 回执契约（派活必须带得回来的东西）

派给子代理时必须给回执格式，回来必须过机检；过不了就打回重跑，**组长不替它补**。

```bash
python receipt-check.py(S1 已删) --file <回执.json>     # rc=0 合格 / rc=1 打回
```

回执最小形状（`receipt-check.py` J1–J4）：

```json
{"stint":"<编号>","did":["..."],
 "evidence":[{"claim":"<结论一句>","pointer":"<文件>:<行> 或 <命令> → <输出>"}],
 "verdict":"done|partial|blocked","blockers":[],"next":"..."}
```

- `evidence` **每项必须有 `pointer` 或 `how`**；写「已完成」「ok」这类空话 → J3 直接 fail。
- `pointer` 的唯一用途是**让组长照着抽 1–2 条核对**；抽不动 = 回执无效。
- `blockers` 非空时必须有 `next`（J4 只 warning），有卡点没出路要写清"卡在哪一步、试过什么"。
- 反面样本：`work/audit/manager/testcases/{pos,neg1-missing-evidence,neg2-vague-pointer,neg3-broken-json}.json`。

---

## 4 例外（允许主对话自己动手的唯一情形）

维护类一次性命令 —— **必须同时满足**：① 只跑一次、② 不改业务逻辑、③ 失败可整体重来。

例：跑生成器（`gen-playbook-index.py` / `gen-task-index.py`）、重基线（`manager-audit.py` 落产物）、
改本文件这种契约文档、`preflight --fast` 的修复回归。

做法：**动手前在当批 `decisions` 里记一行**：

```
decision: 主对话直做 <动作> —— 例外理由：<一次性 / 生成器 / 重基线>，不进 write_edit_share 目标
```

没记这行就当违约。记了行仍计入 `write_edit_share`（指标不豁免，只免"该派没派"的问责）。

---

## 5 三条自检（每批收尾问一遍）

1. 本批 `write_edit_share` 是多少？超 3% 的话，超的部分是"必须我改"还是"我懒得派"？
2. 每份回执都过了 `receipt-check` rc=0 吗？我照着 pointer 抽了几条？
3. 验收（`preflight` / `gate` / `receipt-check`）是我自己跑的，还是外包了？（外包 = 签字权丢了）

---

## 6 怎么启用组长模式（唯一能落地的那条路）

### 6.1 结论先说：不要指望 `agents/*.md`

`~/.pi/agent/agents/*.md` 是**子代理 profile**，不是主会话 profile。2026-10-24 实测（pi-web 0.13.2）：

| 实测发现 | 证据 |
| :-- | :-- |
| profile 的 `tools:` 只认 `read/bash/edit/write/grep/find/ls`，其它名字被过滤 | `GET /api/subagents/profiles` → `seep-manager` 解析成 `tools=[read,grep,find,ls]`（写了 `todo`/`Agent` 也没用） |
| **所有子代理都被强制去掉派活工具**（防递归是设计，不是 bug） | 子代理创建时固定 `excludeTools=[Agent, get_subagent_result, steer_subagent]` |
| `load_extensions: true` 会把 `bash/edit/write` 当**扩展工具**放回来，profile 白名单失效 | 同一 profile：`true` → 快照 tools 24 个（含 bash/edit/write）；`false` → 只剩 4 个 |
| 主会话加 `toolNames` 预设后，**扩展工具不受预设约束** → `Agent` 仍在（但 `codemode` 也会回来） | 预设 `[read,grep,find,ls]`：刚建会话时 active 17 个，**跑过一轮后变 18 个**——`codemode` 在扩展注册完成后又回来了 |

### 6.2 所以组长模式 = 主会话换工具预设（一个预设 + 一个取舍）

1. 主会话工具预设选 **read-only 四项**：`read, grep, find, ls`（把 bash / powershell / edit / write 取消掉）。
   → 结果就是验收口径：**有 `Agent`、没有 `bash/edit/write`**，`mcp__*` 全关。

   实测快照（`work/audit/manager/probes/p5d-surface-output.txt`）：
   `active = [Agent, ask_user_question, codemode, create_goal, fetch_content, find, get_goal,
   get_search_content, get_subagent_result, grep, ls, plan_mode_*, read, source_check,
   steer_subagent, todo, web_search]`；`bash/edit/write` 与 `mcp__*` 均 `active=false`。

   ⚠ **但 `codemode` 会回来**：它是扩展工具，不受预设约束；刚建会话时不在，跑过一轮后就被并回 active。
   所以 `codemode` 写盘盲区**并未关闭**，仍靠两条：①§2 纪律「用 codemode 写文件 = 主对话动手」；
   ②`manager-audit` 单列 codemode 计数点名。
2. 代价与选择（先写进当批 `decisions` 再动手）：
   - **A（严 · 推荐）**：保留 `bash`，靠 `write_edit_share ≤ 3%` 管纪律（`bash` 不进判据，组长跑验收是本职）。
   - **B（硬）**：连 `bash` 一起砍，验收交给 `seep-verify` 跑，组长只读它的原始输出片段。
     代价：签字权事实上外包，§2 的「验收留主对话」作废，**不建议**。

### 6.3 `seep-manager` profile 的正确用法

`~/.pi/agent/agents/seep-manager.md` 已落地，但它**只能当子代理 / 只读复核用**：

- 实测能力 = `read / grep / find / ls`（`load_extensions: false`），无 `bash/edit/write`，也无 `ask_user_question`。
- 用途：让独立会话按回执 pointer 做**只读抽检**、清点文件、比对两份台账；要问人就写 `need_manager: [...]` 交回主对话。
- **不要**把它当「能派活的组长」用 —— 子代理永远拿不到 `Agent`（见 6.1 第 2 行）。

### 6.4 两条命令自查工具面

```bash
python work/audit/manager/probes/p5d-surface-probe.py    # 建一个 read-only 预设会话，打印 active 工具
python work/audit/manager/probes/p5d-spawn-probe.py <会话id> <profile> "<子代理任务>"  # 派子代理，取回它真实的工具面
```

两个探针只打本机 pi-web API（`127.0.0.1:30141`），只读不写业务文件；跑完会留会话记录，按需删。
