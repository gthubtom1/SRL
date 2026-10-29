# MCP 接入与排障

MCP 向模型提供可调用工具；技能文件说明何时使用、如何组合和怎样验证。注册 MCP 不会自动加载所有技能，也不会自动安装或证明外部工具可用。

## 配置与 AgentRoot

Pi 服务声明来自 `Tool/config/mcp-servers.json`。`setup/install-pi.ps1` 和 `setup/merge_agent_config.py` 据此生成或增量合并实际 AgentRoot 的 `mcp.json`，并按当前源码位置展开路径。通用安装流程见 [BOOTSTRAP](BOOTSTRAP.md)。

AgentRoot 按以下顺序解析：显式参数、`PI_CODING_AGENT_DIR`、`PI_AGENT_DIR`、用户目录下的 `.pi/agent`。安装和诊断应指向同一个 AgentRoot。`mcp-doctor.py` 默认读取当前解析到的 AgentRoot；需要固定另一个路径时显式传 `--file <AgentRoot>/mcp.json`。

合并器会校验输入、保留用户定义的配置并生成备份，不会因为工作台条目而清空用户其他 MCP。不要把旧机器的绝对路径、端口、凭据或连接结果复制到新机器。

## 从配置到真实可用

以下状态需要分别确认：

1. **配置有效**：`mcp.json` 可解析，服务条目含有效的 transport、command/url、args、env 和 cwd。
2. **服务可启动**：解释器、命令、依赖和路径存在，进程能启动。
3. **协议可用**：完成 initialize 和 tools/list；远端 HTTP 服务还需通过对应认证。
4. **宿主已加载**：新会话或重连后出现对应 `mcp__<server>__*` 工具。
5. **调用成功**：使用实际参数执行所需工具，检查返回数据和错误。
6. **任务验收**：工具输出是否能支持项目结论，由该项目的证据与验收规则决定。

端口监听、进程存在、工具名声明、配置中的静态条目和一次聊天中的成功都不能替代上述全部层次。

## 安装后检查

从仓库根目录执行，并让 `PI_CODING_AGENT_DIR` 指向被安装的 AgentRoot：

```powershell
python Tool/scripts/env-check.py
python Tool/scripts/mcp-doctor.py --quick --json
python Tool/scripts/mcp-doctor.py --json
```

- `env-check.py` 默认输出 JSON，按最终 command/args/env/cwd 实际启动并校验 Seep MCP 的 initialize、tools/list 和预期工具身份。
- `mcp-doctor.py --quick --json` 是快速静态诊断。HTTP 条目只测端口；stdio 条目只查命令，并会报告尚未握手。它适合先定位明显问题。
- `mcp-doctor.py --json` 是完整诊断。HTTP 条目执行 JSON-RPC；stdio 条目启动独立探针并完成握手。该过程可能启动 GUI、后台工具或下载 `npx` 包，运行前应确认配置来源和当前任务需要。

自定义 AgentRoot 也可以直接指定配置文件：

```powershell
python Tool/scripts/mcp-doctor.py --file "D:\Agent Root\Pi\mcp.json" --json
```

检查工具声明与实现契约：

```powershell
python Tool/scripts/tool-contract-check.py --json
```

该静态检查确认 pack、MCP 注册、effects、runtime/capability 和配置声明之间的关系，不执行外部服务或客户任务。接口名、参数和副作用以源码及实际 tools/list 为准，不要依赖旧文档中的工具数量。

## 宿主加载和外部服务

安装后新开宿主进程，确认实际加载和注册。已有会话中重启某个外部程序后，仍要检查对应工具是否出现；缺失时使用宿主支持的 `/mcp reconnect` 或新开会话。`mcp-doctor.py --session` 只提供启动顺序和重连线索，不能证明当前宿主的工具注册表已经存在。

远程 MCP 的连接对象是远端主机；本机端口、进程信息或探针结果不能证明远端服务和授权均已恢复。外部服务需要各自的凭据、许可、插件、浏览器、硬件或协议支持，应按对应声明和当前任务实际握手或调用。

其他宿主使用自己的 MCP 配置格式。`setup/generate-configs.ps1` 生成的文件仍需在实际宿主中验证；Pi 扩展不会自动变成其他宿主的插件，Pi 的提示词、重试和 packages 配置也不会自动迁移。

## 工具与路径

`Tool/mcp/Tool/` 中的工具和知识库依赖源码中的相对布局，不要单独搬走其中子目录。整个源码仓库移动后重新部署，以刷新 MCP 配置和运行时注册。

按任务使用工作台提供的工具发现或安装规划能力。Python 库要在服务实际使用的解释器中导入；命令行程序要沿发现链检查可执行入口和运行条件。安装后重新验证，安装器或包管理器返回码不能代替能力自检。

Windows 上 `setup/repair-tools.ps1` 用于修复仓库内捆绑的逆向工具，可能访问网络；它只覆盖该脚本当前支持的平台和资产，不是通用 MCP/外部工具修复器。其他缺失工具按其实际依赖和许可处理。

## 常见失败

| 现象 | 核对与修复 |
|---|---|
| `mcp.json` 无法解析或合并中止 | 保留原件和备份，先修 JSON/输入，再用同一 AgentRoot 重跑配置部署 |
| command 不可执行 | 核对最终配置的解释器/Node 命令、PATH 与当前平台 |
| 参数文件或 cwd 不存在 | 核对源码位置；仓库移动后重新部署，不要手写过期的绝对路径 |
| `ModuleNotFoundError` | 为服务实际使用的 Python 环境安装声明依赖 |
| Seep initialize/tools-list 失败 | 用 `env-check.py` 查看最终配置、阶段和错误；修复依赖或路径后再测 |
| `--quick` 显示 offline 或只看端口 | 这是快速检查的正常边界；需要时运行完整诊断并核对宿主工具表 |
| Seep 返回了其他服务的工具 | 修正对应服务配置；工具数量或名称泛匹配不能替代服务身份检查 |
| r2/JADX/Apktool 不可用 | 检查捆绑资产和运行依赖；Windows 可核对 `setup/repair-tools.ps1` 的当前范围 |
| IDA、x64dbg、浏览器未连接 | 核对进程、插件、协议、许可和设备；有等价路线时由模型选择并重新验证 |
| 配置损坏 | 从本次安装备份或用户自己的有效备份恢复；不要清空全部用户条目 |

宿主凭据留在宿主内，不读取到对话或报告中。任何检测只证明该次检测覆盖的范围；换机、更新、换 AgentRoot 或新会话后都要重新确认加载和调用。
