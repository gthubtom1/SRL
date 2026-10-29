# 工作台使用：材料、项目、接续与交付

打开已配置好的 Agent 会话，提供材料位置和你想得到的结果即可。材料可以是文件、目录，或 HTTP/HTTPS URL。Agent 负责判断主辅领域、建立项目、选工具、保留证据并检查结果；你不需要手写内部配置。

例如：

> 分析这个 APK 有没有加固，把结论和证据留在项目里。材料在 `samples/demo.apk`。

> 审计这个目录的依赖，区分实际被源码使用的组件。把源代码作为主材料，抓包作为辅助材料。

> 继续 `work/my-project`，先告诉我上次停在哪里、哪些结论还有效，再做下一步。

> 这是同一个程序的新版本。保留旧版本成果，重新核对定位和补丁，不要把旧报告当作新版本的结论。

## 材料身份与主辅关系

文件按原始字节登记指纹。目录会复制为项目内快照，身份包含相对路径、文件内容和空目录；登记完成后，继续分析不依赖原目录仍在原位置。目录符号链接、越界和资源超限会被拒绝，避免快照混入项目外材料。

URL 保存的是地址描述。它的指纹只表示这条描述，不表示网站内容已经下载、响应已经核验或远端内容没有变化。需要访问网站时，Agent 会另行调用相应工具，并将实际响应作为证据。

多个材料需要明确主材料与辅助材料。辅助材料有自己的身份，不能替代主材料的指纹。二进制解析工具只接收文件；目录或 URL 不会被偷偷转换成“取第一个文件”。

## 项目状态与换会话

项目目录保存资产、版本、运行、证据、验收和报告。换模型或重开会话时，让 Agent 从项目状态接续，不必把整段聊天重新复述一遍。等待你操作时，项目保留等待原因和下一步；连续失败后会要求换路线。

新版本有自己的运行和验收。旧版本报告可作为历史阅读，但不会自动成为新版本最终报告。字节定位的唯一匹配仅是候选，不能证明旧补丁在新版本中仍正确。

## 报告怎样说明结论

报告区分已确认、仍未知、下一步和复查信息。专业结论可以引用已登记的 case 账本与支持证据；假设、反证、弱置信度或没有支持材料的内容不会进入“已确认”。证据文件丢失或篡改后，复查会标记报告失效，而不是继续显示成功。

一份 final 报告可以记录本轮失败或未完成事项。“生成了 final 文件”不等于“目标全部达成”；同时查看当前版本、验收状态和未知事项。

Agent 可以使用以下现有接口核对状态：

```text
python Tool/scripts/project_state.py resume --project work/my-project
python Tool/scripts/project_workflow.py status --project work/my-project --json
python Tool/scripts/project_report.py show --project work/my-project --final
```

## 归档与换位置恢复

让 Agent 导出整个项目，可保留项目内资产、目录快照、证据、验收历史和报告。导入必须使用尚不存在的目标目录；导入前会校验归档成员、内容指纹、路径和资源边界。归档中的注册指纹用于检查一致性，不是发送者身份的数字签名。

```text
python Tool/scripts/project_archive.py export --project work/my-project --out work/my-project.zip
python Tool/scripts/project_archive.py verify --archive work/my-project.zip
python Tool/scripts/project_archive.py import --archive work/my-project.zip --project work/restored-project
python Tool/scripts/project_state.py resume --project work/restored-project
```

恢复后，先查看状态与报告再继续。外部工具、模型服务和 runtime 源码属于运行环境，不会被项目归档打包成可执行环境。恢复项目不需要原始材料目录，但继续调用某项外部工具仍需要该工具可用。

## 扩展和环境检查

新增技能或工具沿用[扩展入口](../Tool/docs/EXTEND.md)，通过合同检查后再使用。发现技能、登记工具、实际工具可用以及任务验收通过是不同状态；只完成导入不能冒称任务已成功。

安装与宿主配置见[部署手册](DEPLOYMENT.md)。已有 Python/Node 环境中，可以只同步 Pi 配置并指定目录：

```text
powershell -NoProfile -File setup/install-pi.ps1 -AgentRoot "work/demo-agent" -SkipPackages
```

Shell 入口对应支持 `--agent-root`、`--skip-packages` 和 `--skip-python`。目录选择优先级为显式参数、`PI_CODING_AGENT_DIR`、项目兼容变量 `PI_AGENT_DIR`，最后使用默认目录。

安装会写入 `seep-runtime.json`，定位并校验当前工作台源码。替换已有同名技能前，会把旧技能树保存到 agent 目录下唯一的 `backup-install-skills-*` 备份；其中包含额外文件和自有改动，备份失败时停止该技能的替换。

保留工作台源码目录；移动源码后重新同步安装配置以刷新注册。注册、技能复制、外部依赖安装和运行环境检查是不同步骤，`SkipPackages` 不表示扩展包已经安装。

本轮功能验收在 Windows 和合成/随项目提供材料上执行；Shell 流程在 Windows Git Bash 中验证，Linux/macOS 原生实机尚未验证。单个专业任务的适用边界仍以对应领域的 `pack.json` 和本次运行证据为准。
