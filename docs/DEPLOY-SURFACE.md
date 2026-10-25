# 部署面清单（Deploy Surface）—— 换机器时"哪些东西归我们管"

> 用途：新机器只要 `git clone` + 跑一次安装，**这张表里的东西全部就位**；表外的东西不是我们的，
> 装不装都不影响 SEEP 工作。
> 这张表由 `preflight` 的「部署面双向一致 / 子代理定义 / 扩展部署一致」三条判据守着 ——
> 仓库改了没部署、部署里多了仓库没有的，都会变红。

## 一、属于 SEEP 的产物（仓库是唯一事实源，安装器负责部署）

| 类别 | 仓库位置 | 部署目标 | 由谁部署 | 守着它的判据 |
| :-- | :-- | :-- | :-- | :-- |
| **运行时规则** | `Tool/prompts/SEEP.md`、`Tool/prompts/AGENTS.md` | `~/.pi/agent/SEEP.md`、`AGENTS.md` | `install-pi.ps1` | 部署面双向一致 |
| **扩展（7 个）** | `Tool/prompts/extensions/*.ts` | `~/.pi/agent/extensions/` | `install-pi.ps1` | 扩展部署一致（哈希） |
| 扩展配套 | `cmd-guard.rules.json`、`TOOL-CHAIN.md` | 同上目录 | 同上 | 同上 |
| **技能（11 个）** | `Tool/skill/<域>/`（9 域 + `seep-router` + `unpack-loop`） | `~/.pi/agent/skills/<名字>/` | `install-pi.ps1` | 部署面双向一致 / 架构不变量 I8 |
| **子技能（17 个，不部署）** | `Tool/skill/_pending/` | 不部署（按仓库路径读） | — | 子技能衔接（无孤儿） |
| **子代理（3 个角色）** | `Tool/prompts/agents/*.md` | `~/.pi/agent/agents/` | `install-pi.ps1`（含退役清理） | 子代理定义（仓库=部署，无同义重复） |
| 子代理设置 | 仓库**不存**（安装器缺失时写入默认值：`builtInEnabled:true`、`maxConcurrent:5`） | `~/.pi/agent/agents/settings.json` | 同上（缺才写） | 同上 |
| **MCP 服务（5 条）** | `Tool/config/mcp-servers.json` | `~/.pi/agent/mcp.json`（**增量合并**：用户已有条目原样保留） | `install-pi.ps1` | mcp 契约判据 |
| **知识库** | `Tool/mcp/Tool/reverselab/kb/`（412 篇） | 不复制（MCP 服务器就地读） | — | kb-tests |
| **MCP 服务端** | `Tool/mcp/seep_mcp_server.py` | 同上（就地跑） | — | mcp 契约判据 |
| 工具启动器 | `Tool/scripts/mcp-launch.py` | 同上（就地跑） | — | 工具身份自检 |
| **任务卡** | `Tool/prompts/tasks/`（**当前刻意留空**） | `~/.pi/agent/prompts/` | `install-pi.ps1`（含退役清理） | 提示词残留 |

### MCP 五条（`mcp-servers.json` 里点名）

| 名称 | 说明 | 换机器注意 |
| :-- | :-- | :-- |
| `seep` | 我们的逆向工具箱（20 个工具，`Tool/mcp/seep_mcp_server.py`） | 自动装好，`{ROOT_POSIX}` 由安装器替换 |
| `ida` | IDA 链（`mcp-launch.py --server ida`，动态解析 IDA 自带 python） | **需要本机装 IDA**；没有就连不上，但不影响别的 |
| `x64dbg` | 调试桥（`mcp-launch.py --server x64dbg` → 127.0.0.1:9094） | **需要本机装 x64dbg**；桥会自动拉起，勿手工开 GUI。工具路径缓存必须**双写**（实现见 `Tool/mcp/tool_autodiscover.py` 的 `_cache_put`；曾因只写一种结构导致 9094 返回 401） |
| `js-reverse` | 前端逆向（`npx js-reverse-mcp`） | 首次运行由 npx 拉包 |
| `playwright` | 浏览器自动化（`npx @playwright/mcp`，headless） | 同上 |

## 二、不属于 SEEP 的（由 pi 或用户自己维护，换机器丢了也不影响 SEEP）

| 东西 | 归属 | 说明 |
| :-- | :-- | :-- |
| `github` / `web-search` MCP | pi 内置或被用户自己加过 | 安装器只做增量合并，其余条目原样保留 |
| `~/.pi/agent/personas/` | **用户**的人设卡 | 安装器不参与（两张卡默认不启用） |
| `~/.pi/agent/backup-*` | 安装器每次的备份 | 可删；回滚时用 |
| `~/.pi/agent/sessions/`、`goals/`、`web-search-cache/` | 运行时产物 | 不入库 |
| `~/.pi/agent/npm/node_modules/**` | pi 的 npm 依赖 | 装 pi 时自带 |
| `~/.pi/agent/agents/settings.json` 的 `builtInEnabled` | pi 的内置角色开关 | 我们只在缺失时写入默认值 |
| 本机工具（radare2/jadx/apktool/IDA/x64dbg/upx…） | 机器环境 | 用 `tool-acquire.py --sweep` 体检；**不写死路径** |

## 三、换机器的真实流程（AI 照这个做就够）

```bash
git clone <repo>            # 1. 拉仓库
cd <repo>
python Tool/scripts/check.py --env     # 2. 体检环境（会自己调 install.ps1）
python Tool/scripts/preflight.py       # 3. 结构与部署判据（应 70/70）
python Tool/scripts/invariants.py      # 4. 架构不变量（11 域 × 9 条）
python Tool/scripts/check.py           # 5. 全量 8 套件
```

第 2 步不通就说明安装器没跑通。手工拷文件会让"仓库=部署"判据变红（下次安装还会覆盖），
所以修法只有一个：修安装器再重跑。

## 四、这次收尾改了什么（2026-10-25）

| 发现 | 处置 |
| :-- | :-- |
| 5 个子代理角色**只存在于本机**，仓库一份没有（换机器 = 并行分工消失，门禁仍绿） | 3 个入仓并纳入安装器；退役 2 个（见下） |
| `seep-manager` 指向的契约 `contracts/MANAGER-MODE.md` 早已归档 → 死指针，且"统筹"本就是主对话职责 | 退役留档 `Tool/prompts/agents/_archived/` |
| `seep-stage` 与 `seep-stage-shell` 工具集相同、提示词几乎逐字相同（同义重复角色） | 保留 `seep-stage`，退役 `-shell` |
| `mcp-servers.json` 里**没有** `ida` / `x64dbg`（本机有，仓库没有 → 换机器就丢） | 补进仓库（用 `{ROOT_POSIX}` 占位，安装器替换） |
| `cmd-guard.ts` / `retry-level.ts` 部署版比仓库新（含 `/stall`、`command:` 状态栏改动） | 回收进仓库（I8 部署等价） |
| 部署哈希对比受 CRLF/LF 影响，换机器会无故变红 | 改 EOL 无关比较（`_file_sig`） |

## 五、子技能（`_pending/`）为什么不部署

- 它们是**子技能**：域 SKILL.md 指路才读，常驻会与 9 个域抢路由（实测串味 2 条）。
- 读法是仓库路径 `Tool/skill/_pending/<名>/SKILL.md` —— 只要仓库在这台机器上（克隆过），路径就有效。
- 守着它的判据：**子技能衔接（无孤儿）**（每个子技能至少被一个域引用，且指向存在的文件）。
- 加子技能的正确方式：`python Tool/scripts/skill-import.py --from <路径>`（会判域技能/子技能并落位）。
