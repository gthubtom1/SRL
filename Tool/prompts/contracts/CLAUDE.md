# Claude Code 接入指针

本文件是接入模板；仅在实际宿主按其规则加载后生效。当前用户指令与宿主规则优先。通用执行约定查 `Tool/prompts/AGENTS.md`，项目介绍查 `README.md`。

用户要求安装或修复时先读 `Tool/docs/BOOTSTRAP.md`，检测当前环境后按 `MANUAL/DEPLOYMENT.md` 操作。Windows 使用 `setup/install.ps1`，Shell 使用 `setup/install.sh`，相对命令均从仓库根执行。不要切到 setup 子目录后继续使用仓库根相对路径。

`setup/generate-configs.ps1` 合并仓库级 MCP 配置，不代表宿主已经加载本文件、全部技能或 Pi 扩展。根据实际宿主加载技能和工具，执行 Seep initialize/tools/list，并验证任务所需动作。可选 IDA 或其他服务未连接时，按具体能力判断替代路线，不能报告自动承接了全部功能。

检查入口：

```powershell
python Tool/scripts/env-check.py
python Tool/scripts/check.py --runtime --json
```

第一条检查 Pi 环境；使用 Claude Code 时，仍需检查自身 MCP、技能与模型状态。Pi 的登录、扩展或 AgentRoot 通过不能当作 Claude Code 已就绪。自定义 Pi 目录时设置 `PI_CODING_AGENT_DIR`；诊断器另传实际 mcp.json 的 `--file`。

安装结果按 `MANUAL/DEPLOYMENT-CHECKLIST.md` 汇报部署、连接、加载和任务动作，保留缺项与未验证范围。只有宿主登录缺失时引导本人登录。更新前保留用户工作；卸载仅在用户要求时先预览；不承诺任何冲突都能自动解决。

用户自然语言给出目标和材料，主模型选择主辅领域并归集证据，不要求额外域快捷命令。当前范围与验证见 `REQUIREMENTS.md`、`docs/CURRENT-STATE.md`；历史完成数字和旧脚手架不作为安装或维护依据。
