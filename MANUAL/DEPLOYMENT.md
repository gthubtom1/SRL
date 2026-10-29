# 安装、更新与卸载

面向代用户操作的智能体。先读 [BOOTSTRAP](../Tool/docs/BOOTSTRAP.md)，基础依赖见 [PREREQUISITES](PREREQUISITES.md)。本页命令均从仓库根目录执行；实际目录和解释器由当前环境确定，不照抄其他机器的路径。

## 安装

Windows：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\install.ps1 -NonInteractive
```

Linux/macOS：

```bash
bash setup/install.sh
```

安装器需要可用 Python；Pi 部署还需要 Node.js 和 Pi 宿主。Windows 主安装器串联离线包处理、Python 依赖、Pi 配置同步、多宿主配置生成、可选 IDA 探测及最后的环境检查。`-NonInteractive` 关闭可选 IDA 路径询问，不替代宿主登录和系统级权限处理。

Shell 安装器有自己的依赖和同步步骤；Windows 内置二进制不能直接视为 Linux/macOS 可执行工具。平台验证范围见 [当前状态](../docs/CURRENT-STATE.md)。

### AgentRoot 与源码运行时

安装、更新和卸载按显式 `-AgentRoot` / `--agent-root`、`PI_CODING_AGENT_DIR`、兼容变量 `PI_AGENT_DIR`、默认 `~/.pi/agent` 解析目标。安装器在该 AgentRoot 写入 `seep-runtime.json`，注册指向当前源码目录，使用时保留源码。

例如安装到指定 Pi 目录，并让随后独立执行的环境检查使用同一目录：

```powershell
$env:PI_CODING_AGENT_DIR = Join-Path $env:USERPROFILE '.pi/agent'
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\install.ps1 -NonInteractive -AgentRoot $env:PI_CODING_AGENT_DIR
python Tool/scripts/env-check.py
```

Shell 中可先 `export PI_CODING_AGENT_DIR="<实际绝对目录>"`，再给安装器传同一 `--agent-root`。不要把含尖括号的示例路径直接执行。

移动源码后按新位置重新部署，刷新 MCP 路径和运行时注册，再新开会话验证。项目归档保存客户项目的材料与记录，不携带整套外部工具或模型服务。

### 实际支持的安装参数

| Windows 主安装器参数 | 含义 |
|---|---|
| `-AgentRoot` | 指定 Pi Agent 目录 |
| `-NonInteractive` | 不询问可选 IDA 路径 |
| `-IdaRoot` | 指定已有 IDA 安装目录 |
| `-SkipPackages` | 跳过离线 Node 包解压和 Pi 扩展包更新；仍可能安装 Python 依赖 |
| `-SkipPython` | 跳过 Python 依赖安装 |
| `-SkipTools` | 跳过 IDA 配置步骤 |
| `-SkipPi` | 跳过 Pi 配置同步；末尾环境检查仍针对 Pi，不表示其他宿主已通过 |
| `-OnlyVerify` | 只运行当前安装环境检查 |

仅同步 Pi 技能、提示词、扩展和注册，可调用 `setup/install-pi.ps1`，参数只有 `-AgentRoot` 和 `-SkipPackages`；它不替代完整环境验收。

Windows 已有依赖、只做离线部署验证时可用：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\install.ps1 -NonInteractive -SkipPackages -SkipPython -SkipTools
```

Shell 安装器支持 `--agent-root`、`--skip-packages`、`--skip-python`、`--help`。其中 `--skip-packages` 也跳过其 Python 安装和工具包探测步骤，语义不能直接照搬 Windows 同名开关。

## 校验与汇报

```powershell
python Tool/scripts/env-check.py
python Tool/scripts/check.py --runtime --json
```

`env-check.py` 的 JSON 反映当前 Pi 环境：受管技能/扩展内容、最终 MCP 启动配置、Seep 握手及宿主模型配置。只有退出 0 且 `installed=true` 才能报告该检查通过。可选 MCP 仅静态检查配置，不能因此声称已连接。

`check.py --runtime --json` 验收当前运行实现及专项回归。完整结果中的 WARN、失败和跳过均保留；该命令不替代本机宿主认证或具体专业任务验收。原有不带 `--runtime` 的历史工程总检还包含文档预算和历史快照等检查，开发者需要时单独运行并解释结果，不把其旧数字当作安装成功条件。

部署或更新后新开宿主会话，确认实际加载了新技能和 MCP。用 [安装核对清单](DEPLOYMENT-CHECKLIST.md) 汇报已完成、未就绪及尚未实测部分。不要为满足示例看板抄写“全部连接”或固定文件数。

## 其他宿主接入

`setup/generate-configs.ps1` 生成或合并仓库级 `.mcp.json`、`opencode.jsonc`，并重生成 `setup/cordis.generated.yml`。前两项会备份已有文件、合并默认项并刷新识别出的 Seep 服务路径；DSH 文件是生成物，用户定制应先另存。仅查看生成流程可传 `-PrintOnly`，它不验证宿主加载。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\generate-configs.ps1 -PrintOnly
```

生成文件不等于对应宿主已接入。智能体还要按当前宿主支持的方式加载 MCP 与 `Tool/prompts/AGENTS.md`、相关 SKILL.md，并实际检查发现的工具；Pi 扩展是 Pi 的实现，不自动适用于其他宿主。通用 Seep 服务入口是 `Tool/mcp/seep_mcp_server.py`，stdio 配置要指向可导入依赖的 Python 解释器。

## 更新

先检查当前分支、origin 和未提交改动，保留用户工作。更新脚本默认可能访问网络、拉取代码并同步受管组件；本地改动处理方式以实际输出为准，不承诺任意冲突都能自动解决。

Windows 预览本地同步，再执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\update.ps1 -NoPull -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\update.ps1 -NoPull
```

Shell 对应 `bash setup/update.sh --no-pull --dry-run` 和 `bash setup/update.sh --no-pull`。已获用户更新授权且需要拉取远端时去掉 NoPull 参数。

更新两侧均支持 AgentRoot、跳过包、跳过 Python 和跳过最终检查参数；不要在需要完整验证时使用 SkipVerify。ZIP 用户先在新位置准备新版本，保留旧目录和客户材料，再用 NoPull 同步并复核。回滚先使用安装/更新备份与具体差异，不通过强制重置抹掉本地工作。

## 卸载与恢复

仅在用户要求卸载时执行。先预览：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\uninstall.ps1 -DryRun
```

Shell 对应 `bash setup/uninstall.sh --dry-run`。使用相同 AgentRoot，检查将移除的受管技能、提示词、扩展、MCP 条目和包；用户自建条目及客户材料按脚本所有权规则保留。不要把源码目录或用户项目目录直接递归删除。

实际卸载去掉 DryRun；`-Yes` / `--yes` 可取消交互，但只用于已授权的卸载。KeepSkills、KeepPrompts、KeepMcp、KeepPackages、KeepLabFlag 有对应保留开关。Restore 参数接受真实卸载备份目录；Purge 还会清理备份等内容，不用于普通卸载。全部参数以脚本 param 或 Shell `--help` 为准。

## 常见失败

| 实际现象 | 处理 |
|---|---|
| Python 缺库 | 确认 MCP 配置使用的解释器，给该解释器安装依赖并重验 |
| 技能缺文件或内容过旧 | 通过正式安装器备份、同步，然后重新检查 |
| 配置 JSON 损坏 | 保留原件，修正或从真实备份恢复后再运行，不以空配置覆盖 |
| MCP 握手失败 | 查最终 command/args/env/cwd，运行 `python Tool/scripts/mcp-doctor.py --quick --json` 定位 |
| 源码运行时失效 | 从有效源码位置重跑安装器刷新注册 |
| 仅缺模型登录 | 文件部署与认证分开汇报，由用户在宿主内登录后再验；不重复安装全部工具 |
| 可选专业工具不可用 | 根据任务验证替代能力，不能仅凭另一个工具存在就声称已自动降级 |
