# 安装前的环境确认

由智能体按 [安装入口](../Tool/docs/BOOTSTRAP.md) 检测和补齐环境；本页说明依赖范围，不是要求用户手工逐项操作。

## 基础环境

| 组件 | 本项目使用条件 | 检查方式 |
|---|---|---|
| 仓库 | 完整 `setup/`、`Tool/` 和 `VERSION`，使用期间保留源码目录 | 查看实际目录 |
| Python | 3.11+，解释器和 pip 可运行；本轮回归使用当前本机解释器 | `python --version`、`python -m pip --version` |
| Node.js / Pi | Pi 部署需要 Node.js 22.19+ 和可用 Pi 宿主 | `node --version`、`pi --version` |
| PowerShell | Windows 脚本要求 5.1+ | 查看当前 PowerShell 版本 |
| Bash | Shell 安装、更新和卸载入口 | `bash --version` |
| Git | 获取源码和在线更新需要；ZIP 部署可使用离线同步方式 | `git --version` |

Git 或 ZIP 都应来自用户指定的仓库版本。ZIP 用户更新时先保留旧目录和用户材料，在新目录部署并复核；不要用整目录覆盖代替更新。在线更新按实际 origin 处理，不切回上游仓库。

## 安装器处理的内容

Windows `setup/install.ps1` 调用 `setup/install-python.ps1` 安装声明的 Python 依赖，调用 `setup/extract-deps.ps1` 处理仓库内已有离线包，再同步 Pi 配置和运行时注册。Pi 扩展包更新由 `setup/install-pi.ps1` 按参数调用宿主完成。

Shell 入口安装声明的 Python 协议/扩展依赖、同步配置和技能，并检查宿主；不要据此推断它会安装 Pi 本体、全部扩展包或所有专业工具。具体动作和跳过参数以 [部署手册](DEPLOYMENT.md) 与脚本为准。

## 按任务需要的工具

Java、Android SDK/ADB、签名工具、Frida、反编译器、调试器、抓包工具和商业软件均按当前任务检测。工具发现和安装表分别见 `Tool/config/tool-capabilities.json`、`Tool/config/tool-install.json`；命中库条目时使用当前 Python 解释器导入验证，不能靠寻找同名命令判断库是否安装。

缺 Java 时，JADX/Apktool 等动作可能受阻；缺 IDA 时，只能在确认所需功能有可用替代工具后换路。工具文件存在不等于所有能力可用，也不等于自动完成降级。

## 网络与本人操作

联网步骤可能包括 pip、Pi 扩展更新及外部工具下载。智能体应利用当前可用网络设置重试，避免永久修改全局代理或包源。离线参数只跳过对应步骤，不会凭空补齐依赖。

模型登录、商业许可及设备访问由用户在相应宿主或软件内完成；不得复制真实凭据到仓库、日志或报告。

## 装后检查

从仓库根目录执行：

```powershell
python Tool/scripts/env-check.py
```

按 JSON 的实际缺项继续修复。自定义 AgentRoot 和完整参数见 [部署手册](DEPLOYMENT.md)，成功标准见 [核对清单](DEPLOYMENT-CHECKLIST.md)。
