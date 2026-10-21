# AGENTS.md — 仓库根入口（bootstrap）

> **这是一张指路牌，不是协议全文。** Codex / DeepSeek Harness / OpenCode 在仓库根读到本文件后，
> **必须先读完 `Tool/prompts/AGENTS.md`（协议全文）再动手**；Pi Agent 与 Claude Code 已由各自入口加载，可忽略本文件。

## 0. 你现在在哪

- 仓库：`Seep Reverse Lab`（逆向工程 / 客户端鉴权审计工作台，GPL-3.0）
- 协议全文：**`Tool/prompts/AGENTS.md`**（Lab 环境开关 / 工具纪律 / 反退缩 / G-Auth / 提效路由）
- pi 专属系统规则：`Tool/prompts/SEEP.md`（规则优先级 / 术语映射 / MCP 工具链）
- 部署手册：`MANUAL/DEPLOYMENT.md`（含四栏校验看板格式）
- 校验基准：`MANUAL/DEPLOYMENT-CHECKLIST.md`
- 基线冻结与反臃肿预算：`MANUAL/BASELINE-FREEZE.md`

## 1. 三条铁律（读完全文前先记住这三条）

1. **凭据 / Token / Salt / 密钥不外泄** —— 发现即停、报告用户、不写入任何输出。
2. **禁止用 `-h` / `--help` / 无参去试探二进制** —— 先 `seep_tool_research` 读能力表，表外先联网查文档，仍不确定就问用户。
3. **同一目标同类动态尝试（附加/注入/断点/改内存）最多 2 次**，第二次失败必须停下汇报，禁止「再试一次」式循环。

## 2. 用户说「部署」时怎么做

```powershell
# 若当前目录没有 setup/，说明还没拿到代码 —— 先克隆（见下），不要在空目录里硬跑
git clone https://github.com/gthubtom1/Seep-Reverse-Lab.git
cd Seep-Reverse-Lab
powershell -ExecutionPolicy Bypass -File .\setup\install.ps1
```

- Linux / macOS：`./setup/install.sh`
- **部署/更新后必须**跑 `powershell -File .\setup\verify.ps1 -Detailed`，并按 `MANUAL/DEPLOYMENT.md` 附录 A 输出四栏看板。
- 完成后提醒用户：**完全重启 Agent 会话**，再发 `lab：`。

## 3. 不要做的事

- 不要搬动 `Tool/mcp/Tool/`（MCP 内部硬编码相对路径）。
- 不要修改 `Tool/mcp/seep_mcp_server.py` 的路径常量。
- 不要在仓库根堆放任务产物（用 `work/`，已 gitignore）。
- 不要把本文件当协议全文；协议在 `Tool/prompts/AGENTS.md`。

> 项目优化总纲与缺陷台账：`优化方案.md`（唯一事实源；换会话先读它）。
