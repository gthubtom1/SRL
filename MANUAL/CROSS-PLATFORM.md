# 跨平台与宿主边界

Windows 入口为 `setup/install.ps1`，Linux/macOS 对应 `setup/install.sh`。安装、更新、卸载和 AgentRoot 参数统一见 [部署手册](DEPLOYMENT.md)，避免复制第二套安装步骤。

## 哪些可以复用

Python 项目状态、证据、验收、报告、归档以及大部分静态解析代码可以在其依赖满足时使用。SKILL.md、配方和知识库提供方法；平台相关工具仍按当前系统重新发现和验证。

| 场景 | 要核对什么 |
|---|---|
| Windows | PowerShell、Python、Node/Pi、实际工具路径与位数 |
| Linux/macOS | Bash、可用 Python、Node/Pi、系统工具、文件权限和路径大小写 |
| Windows 内置工具包 | `.exe`、`.dll`、`.bat` 不能直接当作其他系统的原生可执行文件 |
| Java/Android | 当前 JDK、SDK/ADB、签名和设备条件；不由操作系统名称推定可用 |
| 调试器/GUI/硬件 | 具体宿主进程、控制接口、许可和设备连接 |
| 其他智能体宿主 | 其实际技能、上下文和 MCP 加载方式；Pi 扩展不自动适用 |

Shell 脚本存在或在 Git Bash 中通过隔离测试，不等于原生 Linux/macOS 的整机安装已验收。最新测试平台和范围见 [当前状态](../docs/CURRENT-STATE.md)。

## 环境检查

在实际系统上从仓库根运行 `python Tool/scripts/env-check.py`；只有命令名是 `python3` 的环境使用该解释器。该检查针对当前 Pi AgentRoot，其他宿主还需自身加载与服务验证。

改了源码位置或换机器后重新部署，保留源码运行时，重新验证工具。客户项目用导出、校验和导入接口移位，不能仅凭复制文件夹就声称所有路径、工具和会话状态都已恢复。
