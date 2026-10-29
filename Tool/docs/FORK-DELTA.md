# 本仓与上游的差异定位

本页帮助维护者定位当前实现，不再维护旧版本的累计数量或生成式差分。来源与第三方许可保留在 [PROVENANCE](PROVENANCE.md) 和 [UPSTREAM](../../docs/UPSTREAM.md)。具体历史改动查 Git 与 [CHANGELOG](../../docs/CHANGELOG.md)。

本仓基于 `angusdevgo/Seep-Reverse-Lab`，选择性吸收 REA 等项目的方法和能力；这不代表完整移植其服务、模型流程或全部工具。当前需求以用户指令和 [REQUIREMENTS](../../REQUIREMENTS.md) 为准。

| 当前部分 | 实现位置 | 复查方式 |
|---|---|---|
| 正式领域与跨域引用 | `Tool/skill/`、`Tool/scripts/lib/domain_registry.py` | `python Tool/scripts/route.py --check`、`python Tool/scripts/skill-handoff-check.py` |
| MCP 接口 | `Tool/mcp/seep_mcp_server.py`、`Tool/mcp/seep_contract.py` | 实际 initialize/tools/list；动作按任务实测 |
| 工具发现、安装和控制 | `Tool/mcp/tool_autodiscover.py`、`Tool/config/`、`Tool/scripts/tool-acquire.py` | 契约检查、当前机器探测与安装后重验 |
| 项目、证据、报告与恢复 | `Tool/scripts/project_state.py`、`Tool/scripts/project_workflow.py`、`Tool/scripts/project_report.py`、`Tool/scripts/project_archive.py` | 当前专项回归与具体项目验收 |
| 安装、更新与卸载 | `setup/`、`Tool/scripts/lib/runtime_root.py` | 隔离 AgentRoot 安装、保留用户内容与失败分支测试 |
| 当前汇总验收 | `Tool/scripts/check.py` | `python Tool/scripts/check.py --runtime --json` |

从仓库根目录运行上述命令。验证记录及边界见 [当前状态](../../docs/CURRENT-STATE.md)；历史工具数、案例数和“已连接”截图不代表新安装环境就绪。

合并上游时先核对当前任务是否需要该能力，再比对接口、配置、路径、许可和现有回归。保留用户配置和当前契约；不要用整目录覆盖恢复已取消功能。新增或回退均按 [EXTEND](EXTEND.md) 验证。
