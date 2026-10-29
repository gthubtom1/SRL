# Seep Reverse Lab

为 AI 智能体提供技能、工具、知识库、项目状态和证据记录的逆向分析工作台。你用自然语言说明目标并提供材料，主模型自行判断路线，按需组合多个领域的能力，执行后用证据核对结果。

项目提供能力、契约和执行接口；何时使用某项技能、如何跨领域配合以及结论是否成立，由主模型结合当前任务判断。例如检查 Android 包时可以组合二进制与 SO 分析，分析网页时可以组合 HTTP、协议与 JavaScript 方法。

## 让智能体安装

把仓库地址或本地目录交给你使用的智能体，并告诉它：

> 请帮我安装并验证这个工作台。先读 `Tool/docs/BOOTSTRAP.md`，以当前源码、脚本参数、命令输出和退出码为本机事实；不要把历史文档或其他机器的完成记录当作当前状态。检查系统和 Agent 宿主，复用已有组件，安装当前缺少的依赖，并用同一个 AgentRoot 完成验证。最后告诉我已经通过什么、仍缺什么，以及哪些登录、许可、设备或外部服务需要我本人处理。

[BOOTSTRAP](Tool/docs/BOOTSTRAP.md) 是 AI 代装入口，包含前置环境、Windows/Linux/macOS 命令、自定义 AgentRoot、`SkipPackages` 的具体含义和安装后验证。日常安装与排障由智能体执行，用户不必手工填写内部规划字段或在多个技能名之间选择。

## 安装条件

- Windows 安装器要求可从 `python` 命令启动的 Python 3.11+。Linux/macOS 安装器会依次检查可执行的 `python3` 和 `python`，同样要求 Python 3.11+。
- 正常部署 Pi 时还需要 Node.js 和 Pi 宿主。安装器检查命令是否可用；Node.js 的具体最低版本由当前 Pi 宿主及其依赖决定。
- `-SkipPackages`（Windows）或 `--skip-packages`（Linux/macOS）会跳过内置离线依赖解压和依赖包/宿主的检查与安装步骤，可用于先同步配置。它不会降低 Python 3.11+ 要求，也不代表整体环境已经就绪；完整安装的最终体检仍可能因缺少 Node.js、Pi 或登录状态返回非零。
- AgentRoot 按相同优先级解析：显式参数、`PI_CODING_AGENT_DIR`、`PI_AGENT_DIR`、用户目录下的 `.pi/agent`。安装、更新、卸载和后续检查应使用同一个 AgentRoot。

从仓库根目录执行。Windows 默认安装：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\install.ps1 -NonInteractive
```

指定带空格的隔离 AgentRoot：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\install.ps1 -NonInteractive -AgentRoot "D:\Agent Root\Pi"
```

Linux/macOS 默认安装或指定 AgentRoot：

```bash
bash setup/install.sh
bash setup/install.sh --agent-root "/srv/agent root/pi"
```

完整安装器的 `0` 返回码表示本次受管部署步骤和最终环境检查通过；非零表示仍有未完成项。Windows 的 `setup/install-pi.ps1 -SkipPackages -AgentRoot <AgentRoot>` 只同步 Pi 配置，它的 `0` 返回码仅说明该配置部署步骤成功，不证明后续登录或外部服务可用。更新与卸载入口分别是 `setup/update.ps1`、`setup/uninstall.ps1` 和 `setup/update.sh`、`setup/uninstall.sh`；运行前以对应脚本的参数和当前源码为准。

重复安装按安装所有权清单增量更新。既有 task/agent 只有在内容哈希与该清单中的受管记录一致时，才会先备份再原子替换；用户修改过的条目和安装前已有的条目不会被覆盖，并从 managed 所有权中排除。其他受管资产也遵循各自源码中的所有权与备份规则，不能把“重复安装”理解为替换用户全部文件。

## 安装后验证

在同一个环境中，从仓库根目录运行：

```powershell
python Tool/scripts/env-check.py
python Tool/scripts/check.py --runtime --json
```

`env-check.py` 默认返回 JSON，检查部署文件、Pi 配置和 Seep MCP 的真实 initialize/tools/list 身份；`check.py --runtime --json` 验证当前实现与回归。自定义 AgentRoot 时先设置 `PI_CODING_AGENT_DIR`，或使用脚本明确支持的参数。

安装或更新后新开宿主会话，确认技能、扩展和 MCP 已实际加载。模型登录发生在宿主内，需要用户本人完成。配置存在、握手成功、宿主已加载、某项工具真实执行和一个客户任务被验收，是五个不同层次；前一层的成功不能推出后一层成功。

## 日常使用

正常描述想得到什么，并给出文件、目录或 URL，例如：

> 帮我分析这个 APK 的广告逻辑，看看配套 SO 起什么作用，先说能做到哪一步，再根据结果继续。

智能体先判断目标和所缺材料，选择主辅领域，按需查询技能、配方和知识库。项目、版本、运行、输入资产、原始输出、证据、验收和报告通过现有接口衔接；换会话后可依据项目状态接续。

需要账号、设备、商业软件许可或其他本人操作时，智能体会说明原因、影响和可选路线。`lab：` 只是部分 Pi 交互的可选入口，不是安装完成或使用全部领域的前置条件。

## 能力与边界

- 当前正式领域由 `Tool/skill/*/pack.json` 定义；`seep-router` 帮助选择和组合领域，跨领域任务共享项目资产、路线、证据和验收记录。具体名单与状态以当前源码和检查结果为准。
- 支持文件、目录快照、URL 描述、主辅资产，以及项目导出、校验、导入和移位恢复。
- 工具可以被发现、规划安装并在安装后重验；Python 库使用当前服务解释器实际导入，命令行工具检查真实可执行入口。缺少的新工具仍需按其安装方式、权限和当前环境适配。
- 外部 MCP、商业软件、浏览器自动化、硬件和专业深层动作分别核验。某个配置项存在或工具已注册，不能证明服务已连接，更不能证明所有领域、所有工具已完成端到端验收。
- `_pending` 是按源码路径读取的参考区，不作为已部署的顶层技能名；配方和参考按任务需要读取。

## 检查与维护

安装注册指向源码运行时，使用期间保留仓库目录。移动仓库后要重新部署，刷新配置和 `seep-runtime.json`，再新开宿主会话验证。

遇到 MCP 问题时，[MCP 接入与排障](Tool/docs/MCP-SETUP.md) 区分快速检查、完整握手和真实工具调用。`mcp-doctor.py --quick` 只做端口或命令存在性检查；默认的完整诊断才会按配置执行握手，并可能启动对应程序。不要用快速检查通过代替失败修复或任务验收。

后续增补技能、工具和领域使用 [扩展指南](Tool/docs/EXTEND.md)。最新验证及其未覆盖范围应由当前仓库中的检查命令重新产生；历史记录不能作为新机器的安装结论。

## 来源与许可

基于 [angusdevgo/Seep-Reverse-Lab](https://github.com/angusdevgo/Seep-Reverse-Lab) 二次开发，并选择性吸收其他项目的能力和方法。来源与第三方许可见 [PROVENANCE](Tool/docs/PROVENANCE.md) 和 [UPSTREAM](docs/UPSTREAM.md)；本仓许可证见 [LICENSE](LICENSE)。引用某个项目不代表其所有能力已集成或已验证。

[English](README.en.md) · [中文入口](README.zh.md)
