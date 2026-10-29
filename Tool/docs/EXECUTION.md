# 当前执行操作手册

行为源为 `Tool/prompts/AGENTS.md`，产品需求为 [REQUIREMENTS.md](../../REQUIREMENTS.md)。本页只解释现有操作方式，不保留旧事故的待办、时间表或另一套执行计划。

## 1. 人机配合

| 情况 | 动作 |
|---|---|
| 必要的只读识别、资料和已有工具操作 | Agent 自主完成，记录结果 |
| 缺完整材料、设备或只有用户掌握的操作输入 | 在对话列 A/B/C，说明选择后果与所需步骤 |
| 需要运行客户提供的目标 | 按现有一次运行确认和环境边界处理，用户操作凭据；分析工具本身不重复询问 |
| 已登记等待用户 | 保留原因、下一步与恢复信息；不以自行尝试替代所缺输入 |
| 同形状失败两次 | 重新判断并选择有新证据的路线，不能只调参数继续重复 |
| 操作会改变整机网络、驱动、服务或破坏性磁盘状态 | 换到目标进程内、进程级参数或隔离环境，不在日常机器实施 |

需要用户动手时说明：做几步、Agent监控什么、操作边界、将得到什么证据。账号、卡密、Token、Salt和私钥不进入输出或记录。

## 2. 启动与观察

客户目标按现有 `Tool/scripts/launch-gui.ps1` 的 user/shell/attach 通道处理，避免随意从解释器拉起目标。窗口依据 pid、class 和客户区尺寸匹配；标题作为观察信息。

调试器与工具通过 `Tool/scripts/tool-run.ps1` 和能力表发现/启动/连接。可用 MCP 或 headless 等价通道时优先使用；实际连接成功再称就绪。

有完整性自检信号时先验证保护层及影响，保留原件。一次目标的磁盘修改失败不能被写成所有目标都只许内存补丁的通则。

## 3. 网络与采集

优先目标进程内采集或仅注入目标进程的代理参数。系统级网络不作为默认取证手段。`Tool/scripts/net-rollback.py` 是现有快照/复查工具，不表示自动获得改变整机网络的许可。

采集范围围绕当前问题，记录经允许保留的非敏感元数据与证据。不得按旧案例示范把明文登录信息直接落盘。

## 4. 结果与接续

项目状态通过现有 project_state/manager_state/project_workflow 记录，单案继续使用 case_state。等待原因、采用/放弃路线、证据、适用版本与下一步应可恢复。

跨域时，`project_workflow.py start --primary-domain <域> --aux-domain <辅域>` 登记主辅领域。先用 `project_state.py asset --project <项目> --version <版本> --asset-id <ID> --role auxiliary --target <文件>` 登记辅助材料，再用 `project_workflow.py act --project <项目> --action <只读动作> --asset-id <ID>` 选择该版本已登记的文件；省略 ID 才使用主目标。工具输入绑定、执行前后指纹和证据复查使用同一资产身份，不能在 `--args-json` 覆盖目标路径。`kb.search`、`kb.read` 是九领域共享的知识入口，仍经过 effects、参数和项目状态检查。

开发本工作台的新会话和压缩接续只读 REQUIREMENTS 与 [CURRENT-STATE](../../docs/CURRENT-STATE.md)，再定位相关实现；恢复客户项目时读取该项目自身状态，不从产品历史计划推断下一步。
