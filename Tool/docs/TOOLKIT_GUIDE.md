# 工具与技能使用入口

智能体先理解目标，再按 `Tool/skill/*/SKILL.md` 和领域 `pack.json` 选择能力；需要时组合多个领域。用户不必记工具名或命令。

| 需要做什么 | 当前入口 |
|---|---|
| 新机器安装或修复 | [BOOTSTRAP](BOOTSTRAP.md)、[部署手册](../../MANUAL/DEPLOYMENT.md) |
| 理解并选择领域 | `Tool/skill/seep-router/SKILL.md`、`python Tool/scripts/route.py --resolve "<任务描述>"` |
| 检查路由 | `python Tool/scripts/route.py --check` |
| 检索知识 | Seep MCP 的 `seep_kb_search`、`seep_kb_read` 等；调用参数按实际工具 schema |
| 发现或安装所需工具 | `seep_tool_discover`、`seep_ensure_tool`，或 `Tool/scripts/tool-acquire.py` |
| 项目启动、动作、证据和关闭 | `Tool/scripts/project_workflow.py`；接口见 [运行规范](../prompts/contracts/AGENT-OPERATING-SPEC.md) |
| 报告与归档 | `Tool/scripts/project_report.py`、`Tool/scripts/project_archive.py` |
| 当前回归 | `python Tool/scripts/check.py --runtime --json` |
| 扩展技能、工具或领域 | [EXTEND](EXTEND.md) |

`Tool/scripts/` 提供公共 CLI；领域脚本在 `Tool/skill/<领域>/scripts/`。`Tool/playbooks/` 是按需配方，`Tool/skill/_pending/` 是按源码路径读取的参考。不要将参考目录的旧名字当成已安装技能，也不要将某个客户案例的注入方式设为全局流程。

MCP 登记和接口数量不能证明工具已安装或某任务可完成。先检查本机能力、保留原始输出，再验收当前结果。各专业领域的具体方法和边界以对应技能为准。
