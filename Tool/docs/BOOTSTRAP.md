# 由智能体安装工作台

本页是“帮我装好这个项目”的起点。你应当读写当前仓库源码、脚本参数、帮助文本和实际命令输出；根目录或 `docs/`、`MANUAL/` 中的历史开发记录不能证明本机当前状态，也不能覆盖当前代码行为。

## 1. 确定根目录和 AgentRoot

先确认仓库根目录包含 `setup/`、`Tool/` 和 `VERSION`。后续命令都从这个目录执行。

AgentRoot 是部署目标，不一定是源码目录。当前解析优先级如下：

1. 安装器显式参数 `-AgentRoot` / `--agent-root`；
2. 环境变量 `PI_CODING_AGENT_DIR`；
3. 环境变量 `PI_AGENT_DIR`；
4. 用户目录下的 `.pi/agent`。

安装、更新、卸载和检查必须使用同一个 AgentRoot。需要隔离时使用明确路径并加引号，例如 `D:\Agent Root\Pi` 或 `/srv/agent root/pi`。Windows 运行 `setup/install-pi.ps1`、`setup/install.ps1`、更新和卸载脚本时传 `-AgentRoot`；Linux/macOS 的安装、更新和卸载入口以其当前 `--agent-root` 支持为准。只设置环境变量时，后续进程也必须继承同一值。

## 2. 检查基础环境

- Windows 安装器在开始部署前要求 `python` 可执行且版本为 3.11+。Linux/macOS 安装器会在 `python3`、`python` 中寻找可执行且为 3.11+ 的解释器。
- 正常部署 Pi 还需要 Node.js 和 Pi 宿主。安装器检查命令是否存在；Node.js 的具体最低版本以当前 Pi 宿主和依赖要求为准，不要从旧文档抄一个固定版本。
- `git` 用于仓库更新；缺少它不影响一次从现有源码进行的配置部署，但更新脚本可能需要它。
- IDA、x64dbg、浏览器、r2、JADX、Apktool 等属于按路线使用的外部或可选能力。没有配置或连接它们时，应如实说明缺少哪条路线，不能把工作台配置部署描述成所有分析能力已完成端到端验证。

先检查可用解释器和宿主，再运行脚本；不要调用尚未安装的解释器。缺少的通用依赖可以按当前系统已有包管理器安装，用户登录、商业许可、设备授权和系统级交互交给用户本人完成。

## 3. 执行安装

Windows 默认安装，适合已有 Node.js 和 Pi 的正常部署：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\install.ps1 -NonInteractive
```

Windows 指定 AgentRoot：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\install.ps1 -NonInteractive -AgentRoot "D:\Agent Root\Pi"
```

Linux/macOS 默认安装或指定 AgentRoot：

```bash
bash setup/install.sh
bash setup/install.sh --agent-root "/srv/agent root/pi"
```

安装器会校验输入，增量同步受管技能、提示词和扩展，合并 Pi 配置，登记源码运行时，并在最后执行环境体检。它会保护已有用户配置并生成备份；遇到输入损坏、所有权清单错误或写入失败时应停止，不要删除用户配置来强行通过。

task/agent 的重复安装采用内容所有权判断：只有既有文件的内容哈希与安装所有权清单中的受管记录一致，才先备份再原子更新；用户修改过的或安装前已经存在的条目不会被覆盖，并从 managed 所有权中排除。不要把重复安装描述成替换 AgentRoot 中的全部 task/agent，也不要手工把未知文件加入受管清单来绕过该保护。

### SkipPackages 的真实边界

`-SkipPackages` 和 `--skip-packages` 用于跳过内置离线依赖解压，以及依赖 Node/Pi 包和宿主的安装或检查步骤。它们可以用于先同步配置，但不能跳过 Python 3.11+ 前置检查，也不表示安装已经完整可用。使用后仍需单独补齐宿主、依赖和登录；完整安装器的最终体检可能因此返回非零。

Windows 只同步 Pi 受管配置的入口是：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\install-pi.ps1 -SkipPackages -AgentRoot "D:\Agent Root\Pi"
```

该命令返回 `0` 只说明本次配置部署成功。它不证明 Node、Pi、模型登录、外部 MCP 或真实任务已经就绪。

Linux/macOS 的离线配置准备使用：

```bash
bash setup/install.sh --agent-root "/srv/agent root/pi" --skip-packages
```

该入口仍会执行其源码中定义的配置部署和最终检查；以实际返回码和输出为准。

## 4. 安装后分层验证

先在同一 AgentRoot 下运行：

```powershell
python Tool/scripts/env-check.py
python Tool/scripts/check.py --runtime --json
```

`env-check.py` 默认输出 JSON，检查 `installed`、`checks`、`missing`、`next_actions`，并实际启动 Seep MCP 校验 initialize、tools/list 和预期工具身份。`check.py --runtime --json` 验证当前运行实现、契约与回归；按实际返回码报告 FAIL、WARN、跳过和未验证。

然后按以下层次分别核对：

1. **部署文件**：受管技能、提示词、扩展和配置是否由正式安装入口写成，安装所有权清单和运行时注册是否有效。
2. **配置有效性**：生成或合并后的 command、args、env、cwd 是否存在且能被解析。
3. **宿主加载**：用同一个 AgentRoot 新开宿主会话，确认技能、扩展和 MCP 条目实际出现；热更新或文件已复制都不等于当前会话已重载。
4. **服务握手**：Seep 由 `env-check.py` 实测；外部 MCP 只有在完成其协议握手后才能报告连接成功。
5. **真实调用与任务验收**：实际调用所需工具，检查返回数据和错误；任务结论还需要目标材料、证据与验收规则支持。

MCP 的快速诊断、完整握手和真实调用区别见 [MCP-SETUP](MCP-SETUP.md)。`mcp-doctor.py --quick --json` 只检查端口或命令存在性；默认完整诊断才会按配置执行 JSON-RPC 握手，并可能启动程序。自定义 AgentRoot 时，诊断器默认会读取 `PI_CODING_AGENT_DIR` / `PI_AGENT_DIR`；也可以显式传 `--file <AgentRoot>/mcp.json` 固定目标。

## 5. 返回码和失败处理

- Windows/Linux 完整安装器返回 `0`：本次受管部署步骤及最终环境检查通过；返回非零：查看脚本输出中的失败项，使用同一 AgentRoot 修复后重查。
- `install-pi.ps1 -SkipPackages` 返回 `0`：仅配置部署步骤成功；仍未验证宿主登录和外部能力。
- `env-check.py` 返回 `0`：当前检查认为已就绪；返回 `1`：按 `missing` 和 `next_actions` 处理。
- `check.py` 返回 `0`：纳入套件通过；返回 `1`：有失败；返回 `2`：有 WARN、跳过或未验证，不能报告为全绿。

遇到失败时先保留原配置、失败日志和已完成步骤。配置损坏时从本次安装创建的备份或用户自己的有效备份恢复；路径错误时核对同一 AgentRoot；依赖缺失时为服务实际使用的解释器或运行时补齐。不要重复安装已经通过的组件，也不要从未知来源重新生成覆盖用户配置。

## 6. 首次登录、后续会话和可选服务

模型登录发生在宿主内，由用户本人完成。智能体可以说明登录入口和未登录的影响，但不读取凭据存储，也不把模型账号写进项目配置或报告。

登录并在新会话确认加载后，日常只需用自然语言说明目标和材料。`lab：` 是某些 Pi 交互的可选功能，不是安装、登录或使用全部路线的必需条件。

其他宿主可以复用技能文件、项目 CLI 和 Seep MCP，但 Pi 扩展不会自动成为其他宿主的插件，`settings.json`、重试配置和提示词装配也不会自动迁移。其他宿主必须分别验证自己的配置格式、加载、握手和真实调用。

外部 MCP、商业软件、浏览器自动化、硬件和专项分析工具均按当前任务核验。安装器能处理的组件自行处理；缺少账号、许可、设备或系统交互时，先判断是否存在等价路线，再向用户说明具体阻塞。

## 7. 完成时向用户报告

至少报告：仓库位置和版本、宿主及 AgentRoot、实际执行的安装命令、返回码、已通过的检查、仍缺或未验证的项目、是否需要新开会话，以及仅本人可完成的登录/许可/设备事项。不要把静态配置数量、历史完成记录或其他机器的测试结果写成当前机器的端到端成功。
