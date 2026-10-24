# EXTEND —— 往 Seep 加东西的唯一流程（4 步 + 1 条门禁）

> **目标**：加一个工具 / 一个 MCP / 一个技能，**不超过 10 分钟**，且不会踩坏别处。
> 以前每次要 1–2 小时，是因为"接线点"散在 6 个地方、验证散在 7 个脚本。现在固定成下表。

---

## 0. 先记住三条铁律

1. **通道优先级**：工具自带 MCP > CLI/headless > GUI > 人工。**能用 headless 就绝不开 GUI**。
2. **单一事实源**：每类东西只有一处配置。**不要在提示词里写工具数量、不要把路径写死。**
3. **改完只跑一条命令**：`python Tool/scripts/preflight.py`（全绿才推）。

---

## 1. 加一个「工具」（x64dbg / Frida / mitmproxy / Burp …）

| 步 | 动作 | 改哪个文件 |
|---|---|---|
| 1 | 声明能力（是否 MCP / headless / CLI / GUI） | `Tool/config/tool-capabilities.json` → `tools.<id>` |
| 2 | 若有可执行入口，声明通道阶梯（按优先级） | `Tool/config/tool-runtimes.json` → `tools.<id>.modes[]` |
| 3 | 让总控"知道"它（能被路由/调度） | `Tool/skill/softseep/SKILL.md` 的「可调度的全部资源」表加一行 |
| 4 | 门禁 | `python Tool/scripts/preflight.py --fast` |

新增通道的写法（配置驱动，`tool-run.ps1` 不用改）：

```jsonc
// Tool/config/tool-runtimes.json
"mitmproxy": {
  "prefer": ["cli"],
  "modes": [
    { "id": "cli", "kind": "cli", "why": "mitmdump 无头抓包，不需要 GUI",
      "command": "\"{exeDir}/mitmdump.exe\" -p 8080 -w {workDir}/flow.dump", "toolId": "mitmproxy" }
  ]
}
```

> **判断口诀**：有 CLI/headless → 只写 CLI 那条就够了；**只有必须靠宿主进程才能控制的**（如 x64dbg 调试）
> 才写 `gui`/`mcp-http` 通道，并在 `why` 里写清"为什么没有 headless 等价物"。

---

## 2. 加一个「MCP 服务」

| 步 | 动作 | 改哪个文件 |
|---|---|---|
| 1 | 追加一条服务声明（唯一改动点） | `Tool/config/mcp-servers.json` → `servers.<name>` |
| 2 | 门禁 + 重装一次让本机生效 | `preflight.py --fast`；`setup/install-pi.ps1 -SkipPackages` |
| 3 | 新开会话验证 | `/mcp` 或 `pi mcp list` |

- 两个安装器（`install-pi.ps1`、`merge_agent_config.py`）都读这个文件，**不再各写一份硬编码**。
- 需要用户凭据的条目加 `"onlyIfMissing": true`，重装时不覆盖用户已填的 token。
- 带 token 的条目**不要把 token 写进 mcp.json**：用 pi 的 `!命令` 动态取（示例见 `mcp-servers.json` 的 `_可选条目示例`）。

---

## 3. 加一个「技能」

```bash
（该脚本 S4 已删，见下方替代路径） <name> --desc "一句话描述"
```

脚手架会自动打通四处（缺一处就静默失效）：

| # | 位置 | 作用 |
|---|---|---|
| 1 | `Tool/skill/<name>/SKILL.md` | 技能本体 |
| 2 | `softseep/SKILL.md` 可调度表 | 总控知道它存在 |
| 3 | `Tool/skill/<pack>/pack.json` 的 `routes` + `priority` | 判型能命中 |
| 4 | `~/.pi/agent/skills/<name>/` | pi 会话能加载 |

门禁：`python Tool/scripts/route.py && python Tool/scripts/preflight.py --fast`

---

## 3bis. 三阶段交付技能（01 / 02 / 03）

改客户端交付按阶段拆，**每个阶段一个技能，互不越界**：

| 技能 | 阶段 | 管什么 | 产物 |
|---|---|---|---|
| `00-analysis` | ⓿ | D0–D5 深度门 → 8 节可复现报告 → 可行性裁定 | `analysis-report.md` + `facts.jsonl`（不许交成品） |
| `01-gate-bypass` | ① | 判壳/自毁处理 → 旁路卡密 → 原版能跑、功能全通 | 补丁后二进制 / 代理 DLL / 重签包 / 注入器 |
| `04-version-migrate` | ④ | 读版本账 → AOB 滑窗对齐 → UI/授权迁移 → 重建回归 | 新版成品 + 差异报告（引擎 `（`migrate` 已不存在：按上面的替代路径走）`，规范 `Tool/docs/MIGRATION.md`） |
| `02-ui-rebrand` | ② | 改 UI、换品牌、去作者信息 | 改造后的同形态产物 |
| `03-license-hookup` | ③ | 接你自己的授权平台（卡密 / 到期 / 机器码） | 带授权页的产物 + 发卡工具 |

- 触发靠 `Tool/skill/<pack>/pack.json` 的 R11/R12/R13（"旁路卡密出成品" / "改界面换品牌" / "接授权平台"）；
- **技能数量不设上限**（`budget.py` 已放开），但单个 SKILL.md 建议 ≤ 12KB。

---

## 4. 改「提示词层 / 纪律」

| 改什么 | 改哪 | 注意 |
|---|---|---|
| 跨宿主纪律（Lab/反退缩/G-Auth/工具纪律） | `Tool/prompts/AGENTS.md` 对应章节 | 只插段落，别复制到别处 |
| pi 装配契约 / 层间裁决 | `Tool/prompts/SEEP.md` | **≤2500 字符，只放指针**；门禁会查 |
| 人格 / 风格 | `~/.pi/agent/personas/*.md` | **不入仓库**，用户自管 |

---

## 4bis. 任务卡（prompt template）—— 用户说一句话就开工

放在 `Tool/prompts/tasks/<name>.md`，安装时复制到 `~/.pi/agent/prompts/<name>.md`，
pi 会把它变成 **`/<name>` 斜杠命令**（支持 `$1` 参数）。

**关键点：任务卡不进系统提示词**，只在用户调用时展开 —— 所以它再长也不占每轮上下文。

| 卡片 | 命令 | 用途 |
|---|---|---|
| `reverse.md` | `/reverse <目标>` | 一句话开工：旁路验证 + 成品交付，先报三行判型 |
| `reverse-deliverable.md` | `/reverse-deliverable <目标>` | 完整版：D1–D5 交付物 + 五面判据 + 硬约束 + 反模式 |

写新卡片的规矩：

- 只放 `Tool/prompts/tasks/`，**不要塞进 `SEEP.md` / `AGENTS.md`**（那是每轮注入的）；
- 卡片里与 Seep 冲突时**明确写"本卡优先于 X 的默认"**（例如"本卡优先于 softseep 的判型内记"）；
- 卡片要求"先报三行再开工"这类交互，属于任务级指令，不违反 Seep 的自动判型设计。

---

## 4ter. 怎么给新工具选 `kind`（决定"要不要开 GUI"）

按这个顺序问，问到一个"是"就停：

1. 它自带 **stdio MCP** 吗？→ `mcp-stdio`（pi 自拉，用户不用管）
2. 它有 **CLI / headless** 能做同样的事吗？→ `cli`（**绝不启动 GUI**）
3. 它的控制面只在**宿主进程内**（调试钩子/断点/注入/内存读写）吗？→ `mcp-http` / `mcp-sse`（Agent 用 `tool-run.ps1` 按需自启，单实例，用完关）
4. 只有 GUI 能操作、且没有 MCP？→ `gui`（最后手段；`why` 里必须写清"为什么没有 headless 等价物"）
5. 必须人看屏幕（首次许可/崩溃恢复弹窗）？→ `manual`（此时才找用户）

**"度"的三条**：按需自启（不做开机常驻）· 单实例（同端口只开一个）· 用完即关（`StopDebug`/退出）。
判据只有一句：**这次任务需不需要在目标进程里下钩子或断点**；不需要就不启动宿主。

---

## 5. 唯一门禁

```bash
python Tool/scripts/preflight.py            # 全量（含 verify 65 项 + 端到端冒烟，约 1–2 分钟）
python Tool/scripts/preflight.py --fast     # 快速（约 2 秒，改文档/配置时够用）
```

它检查：悬空引用 / 文档数字 vs 实测 / 双平台检查项数一致 / budget / 路由自洽 / 中继规则同步 /
知识库验收 / 冒烟 / 体检 / MCP 清单与工具配置的 schema 与交叉覆盖 / **可移植性（禁止机器专用绝对路径）**。

**改动前想知道会牵动谁**：

```bash
python Tool/scripts/gate.py Tool/config/tool-capabilities.json
```

它输出：谁引用了它、属于哪条链、该跑哪几条检查。

---

## 6. 回滚

- 单文件：`git revert <commit>` 或直接删掉新增条目；
- 技能：`（该脚本 S4 已删，见下方替代路径）` 生成的四处在 `git status` 里一眼可见；
- 本机配置：安装器每次都会备份到 `~/.pi/agent/backup-*`。

---

## 7. 反面清单（违反即返工）

- ❌ 在提示词里硬编码工具数量 / 技能清单（会立刻过期，门禁会红）；
- ❌ 写死某台机器的绝对路径（用 `seep_tool_discover` / `{exeDir}` / `{ROOT_POSIX}`）；
- ❌ 给 GUI 工具写自动启动却忘了"没有 headless 等价物"这个前提；
- ❌ 往 `Tool/mcp/Tool/**`（vendored 上游树）加内容 —— 重新 vendor 会被覆盖，本地内容放 `Tool/mcp/kb_local/`；
- ❌ 新增检查项时只改 `verify.ps1` 不改 `verify.sh`（门禁查项数一致性）。
