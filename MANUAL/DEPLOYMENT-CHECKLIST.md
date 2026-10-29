# 安装结果核对

本页说明如何解读实测结果，不保存另一套固定文件数或“全绿”示例。安装步骤见 [部署手册](DEPLOYMENT.md)，智能体起点见 [BOOTSTRAP](../Tool/docs/BOOTSTRAP.md)。

## 分开核对五件事

| 层次 | 证据 | 能说明什么 |
|---|---|---|
| 文件与注册 | 当前 AgentRoot 的技能/扩展内容、受管提示词和 `seep-runtime.json` | 已同步到哪里、注册指向哪个源码根 |
| 环境 | `python Tool/scripts/env-check.py` 的退出码和 JSON | 当前 Pi 安装环境检查是否通过、具体缺项 |
| 服务连接 | 最终配置启动后的 initialize/tools/list 或实际工具调用 | 被测试服务能响应，不能外推其他 MCP |
| 新会话加载 | 新宿主进程实际发现的技能、扩展和工具 | 新配置已加载；仅复制文件不能证明 |
| 专业任务 | 对当前输入的原始输出、证据和验收 | 这次任务实际做到哪里；不由安装检查替代 |

`env-check.py` 当前会比较受管技能与扩展内容，检查最终 MCP command/args/env/cwd，并真实握手 Seep。外部可选 MCP 主要做静态配置检查。宿主模型配置状态通过宿主接口检查，不读取真实凭据存储。

## 从实现取清单

| 内容 | 来源 |
|---|---|
| 顶层技能 | `Tool/skill/*/SKILL.md`；以下划线开头的参考区不部署为顶层技能 |
| 正式领域 | 对应 `pack.json` 的 id 与领域契约 |
| Pi 扩展 | `Tool/prompts/extensions/` |
| 受管提示词 | `Tool/prompts/AGENTS.md` 与 `Tool/prompts/SEEP.md` 的安装/合并规则 |
| MCP 配置 | `Tool/config/mcp-servers.json` 与最终 AgentRoot 中的 `mcp.json` |
| Seep 工具接口 | `Tool/mcp/seep_mcp_server.py`，实际数量以握手结果为准 |
| 外部工具能力与安装 | `Tool/config/tool-capabilities.json`、`tool-runtimes.json`、`tool-install.json` |

当前仓库登记 9 个正式领域、11 个顶层技能、20 项 Seep MCP 工具。这些是当前实现清单，不能复制成另一台机器已经加载的数量。

## 结果表述

- 已通过：写明实际运行了什么、返回值和验证范围。
- 已部署但未就绪：例如文件同步成功但宿主模型尚未登录；列出缺项及本人操作。
- 可选项未验证：例如只检查了 IDA 或浏览器服务的配置，没有实际连接；不写成已经自动降级。
- 失败：保留错误和已完成阶段，修复后重验。WARN、跳过和未执行保留原意。

给用户简要汇报仓库/版本、宿主/AgentRoot、已部署内容、通过的检查、未就绪项及下一步即可；表中填写本次结果，不预填 Connected 或 READY。

运行实现与回归统一使用 `python Tool/scripts/check.py --runtime --json`。检查项数量可以随实现增减；具体业务完成仍需当前项目证据。发布前敏感信息检查是 `python Tool/scripts/pre-upload-check.py`，不属于环境检查的虚构“第九节”。
