# 决策台账 —— 哪些已经动了，哪些还在等你拍板

> 你为什么需要这份：**我这一路经常"自己拍板就往下走"**，而你的消息在队列里，看不到我抛出的选择。
> 这里把两件事一次列清：① 我**已经改了**什么（你可以否决）；② 我**提了但没等到你回答**的（需要你现在决定）。
> 更新：2026-10-24。

---

## 一、我已经改的（可以否决，一条 `git checkout` / 备份即回滚）

| # | 改动 | 位置 | 风险 | 回滚方式 |
| :-- | :-- | :-- | :-- | :-- |
| 1 | `SEEP.md` 从 4,183 → 2,148 字节（退成指针，照原版 `CLAUDE.md` 275B 的做法） | `Tool/prompts/SEEP.md` + 部署态 | 低（正文都有归属处） | `work/audit/SEEP-full-backup.md` |
| 2 | 入口模板解禁 ASK：删掉"不许甩 A/B/C 选择题"，加回"人操作时必须发卡" | `Tool/prompts/tasks/reverse*.md`、`sources/*.md` | 低 | git |
| 3 | MANUAL 承诺改成条件式（去掉"全自主 8~15 分钟/静默自愈/放入目录即可生效"） | `MANUAL/ZERO-TO-HERO-WORKFLOW.md` | 低 | git |
| 4 | 新建快筛技能 `00-triage`（20 分钟出画像卡六字段） | `Tool/skill/_pending/00-triage/` | 低（新文件） | 删目录 |
| 5 | `00-analysis` / `01-gate-bypass` 加前置与"按画像卡选 1 个子技能" | 两个 SKILL.md | 中（改了流程入口） | git |
| 6 | 三个子代理 profile（stage / forensics / verify） | `~/.pi/agent/agents/*.md` | 低（新文件） | 删文件 |
| 7 | `mcp.json` 的 x64dbg 从 http 改成 **stdio 桥** | `~/.pi/agent/mcp.json`（备份 `mcp.json.bak-*`） | **中：要重启才生效** | 恢复备份 |
| 8 | `cmd-guard` 加 9 条禁手（6 block + 3 warn） | `~/.pi/agent/extensions/` | **中：要重启才生效** | `.bak-*` |
| 9 | 新脚本：`launch-gui.ps1` / `net-rollback.py` / `prompt-budget.py` / `domain-pack-check.py` / `tool-acquire.py` / `mcp-bridge-x64dbg.py` | `Tool/scripts/` | 低（新文件） | 删文件 |
| 10 | `case_state.py`：`init` 补写 `case.json` 骨架；三个脚本加 UTF-8 `reconfigure` | 单文件 | 低 | git |
| 11 | 三份契约：`DECISION-LOOP.md`（四步环 + Manager Mode）/ `TOOL-LADDER.md`（四阶梯） | `Tool/prompts/contracts/` | 低（新文件） | 删文件 |
| 12 | `preflight` 加 3 组检查（域包预算 / 工具阶梯 / 案例索引同源） | 单文件 | 低 | git |
| 13 | `docs/history/X-PLAN-FINAL.md` 升到 **v5.3**（含 §0bis/§0ter/§0quater/§0quinquies 四轮修正） | docs | 低 | git |

**门禁现状**：`preflight --fast` 全绿（项数见 `（已删除：数字口径取消）`，别在文档里写死）；`prompt-budget` 报红（可控制层 18,729 / 3,500）——**这个红是我故意留着的**，它是 P4 要烧的账。

---

## 二、提了但没等到你回答的（请现在一次拍板）

| # | 决策 | 选项 | 我的建议 |
| :-- | :-- | :-- | :-- |
| **D1** | **要不要重启 pi-web？** | A 现在重启（x64dbg 桥 + 禁手立即生效）／B 等下一批一起重启 | **A** —— 不重启，我今天做的两件事（工具桥、网络禁手）全是纸面的 |
| **D2** | **子代理护栏怎么办**（实测：子代理里 `cmd-guard` 完全不生效，能改网卡） | A 写 `seep_exec` 工具替换 bash（护栏 100% 生效，半天）／B 靠事后对账 `net-rollback diff` 回滚（半天，但断网已发生）／C 暂不启用 Manager Mode | **A + B 兜底**；在 A 做完前**不许开 Manager Mode** |
| **D3** | **人设卡瘦身**（28.7KB / 7,451 token / 36 条强制语句） | A 砍到 ≈6KB（保留语气+破甲+输出格式）／B 只搬"授权/范围/拒答"三段（省 ~4k）／C 不动 | **B**（风险最小，先省 4k 验证行为不变，再考虑 A） |
| **D4** | **AGENTS 瘦身到 20 条**（草案已写：`docs/history/X-AGENTS-SLIM-DRAFT.md`） | A 现在就换／B 等 gate 硬化后换／C 不换 | **B**（现在换等于撤掉最后一道人肉护栏） |
| **D5** | **要不要写 `liveness-check.py`**（只测生效不测存在） | A 现在写／B 先做 P1 控制平面 | **A** —— 它就是审计方法里那三件的第一件，且今天就能验出"子代理护栏失效"这类洞 |
| **D6** | **P1 控制平面先做哪一件** | A canary（20 条危险动作真拦）／B case 租约锁／C 事件账自动写 | **C → B → A**（事件账最便宜且立刻让"沉默"可见） |
| **D7** | **金标准用例从哪来** | A 用今天那个 AI 自瞄目标当唯一用例（贵但真实）／B 先造 3 个小 fixture／C 回放历史会话的"决策点" | **C + B**（回放最便宜，能立刻验 8 个翻车点） |

---

## 三、清洁审查（`REVIEW-CLEANROOM.md`）挖出、我**还没处理**的 10 项

> 更新：**U9 已修**（2026-10-24，见下表）。剩 9 项未处理。

这些是那份盲审的"虚能力清单"里我没动过的，按危险度排：

| # | 问题 | 证据 | 危险度 |
| :-- | :-- | :-- | :-- |
| **U1** | **MCP 工具绕过了 shell 护栏**：`seep_http_replay` 能发任意请求并读 `session_file`；`seep_tool_install(execute=true)` 能跑 pip/winget；`seep_tool_register_mcp(apply=true)` 能写配置；`seep_create_skill` 能写技能 —— **禁 shell ≠ 禁副作用** | `seep_mcp_server.py` | **高** |
| **U2** | `02-ui-rebrand` 引用的 `rollback.ps1` **不存在** | SKILL.md:86-87 | 中（被调用路径不存在） |
| **U3** | `binary-diff` 引用的两个 reference **不存在** | `references/symbol-migration.md`、`patch-diff.md` | 中 |
| **U4** | `domain-gate.py --all` **rc=1**：aimbot 案例 real 但无命令/rc | 直接跑就能复现 | 中（项目自己的门禁已经在报错，被别的绿灯盖住） |
| **U5** | `smoke-e2e` 只跑一个 9KB CrackMe 的 12 项链路 —— **真实目标从没被 smoke 覆盖** | `smoke-e2e.py:80-158` | 中 |
| **U6** | `playbook-check` **154/184 条命令被跳过**，剩下主要只跑 `--help`/`--self-test` | `playbook-check.py:96-150` | 中 |
| **U7** | `capability-gate` 51/51 covered，其中 **22 个是 reserved、13 个是 probe** —— "全覆盖"含水分 | 同一输出 | 中 |
| **U8** | 源技能 361 / 部署 403，**多 42 个**；哈希漂移 | 直接扫就能复现 | 低-中 |
| **U9** | `mcp.json` **硬编码盘符路径** + Playwright token 是 `<YOUR_PLAYWRIGHT_TOKEN>` 占位符 —— playwright 部分**已修**（token 占位符整条不再存在） | 部署态 mcp.json | ~~低~~ **已修**（playwright 半边）→ 改的是 `mcp-launch.py` + `mcp-servers.json` + `MCP-SETUP.md` |
| **U10** | `launch-gui.ps1` 只打印步骤、等 20 秒后 `NOT_STARTED` —— **没有持久 `WAITING_FOR_USER` 状态** | 脚本 + AGENTS 对照 | 高（M2→M3 的死亡点就在这里） |

---

## 三bis、已知限制（刻意保守，不为凑绿放宽）

| # | 限制 | 现象 / 证据 | 为什么不修 |
| :-- | :-- | :-- | :-- |
| **L3** | **生效性检查只认结构化 `toolCall`** | 经 `codemode` 媒介发起的 MCP 调用，在会话 `.jsonl` 里只记成 `name=codemode`（内层 MCP 名不入字段）→ 该 MCP 被判成 `unreached`。实测：最近 5 个会话真实 `toolCall` 1722 条，其中 MCP 命名空间 0 条（`preflight --fast` §20 生效性）。 | **刻意保守**。要放宽就得猜“codemode 脚本里可能调了谁”，那是推断不是证据；宁可报未覆盖让人补一次直连调用，不伪造绿灯。 |

---

## 四、我建议的顺序（把 D 与 U 合起来排）

| 顺序 | 做什么 | 为什么排这个位置 |
| :-- | :-- | :-- |
| 1 | **D1 重启** | 不重启，今天所有修复都是纸面 |
| 2 | **D5 写 liveness-check** | 它是审计方法的执行体；能立刻验证 D2/U1 这类洞 |
| 3 | **D2 子代理护栏（A+B）** | Manager Mode 的前置；现在是裸奔 |
| 4 | **U10 持久 WAIT_USER** | M2→M3 的死亡点；不做这条，人工边界必丢 |
| 5 | **U1 MCP 副作用统一 policy** | 禁 shell 但 MCP 能装工具/写配置 = 护栏形同虚设 |
| 6 | **D6 事件账 → case 锁 → canary** | 让"沉默"和"并发"可见 |
| 7 | **D7 回放 8 个翻车点** | 最便宜的回归 |
| 8 | **D3/D4 瘦身** | 成本项，排在效果项后面 |
| 9 | **U2–U9 清理** | 修不存在的引用、对账、去硬编码 |

---

## 五、一句话

**你不用回答所有问题。** 只回我 **D1（要不要重启）** 和 **D2（子代理护栏走 A 还是 C）** 这两个，我就能往下推；
其余我可以按建议默认走，但会在每次改动前留回滚点，你随时能叫停。
