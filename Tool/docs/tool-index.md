# 工具入口

工具是否存在、身份是否匹配、能否运行以及 MCP 是否已接入，必须在当前机器分别验证。本文件不保存本机工具就绪快照。

能力声明见 [tool-capabilities.json](../config/tool-capabilities.json)，运行模式见 [tool-runtimes.json](../config/tool-runtimes.json)，安装方案见 [tool-install.json](../config/tool-install.json)。这些声明不等于工具已经安装或连通。

从仓库根目录运行：

```powershell
python -X utf8 Tool/mcp/tool_autodiscover.py discover <tool-id>
python -X utf8 Tool/scripts/tool-readiness.py --json
powershell -NoProfile -File Tool/scripts/tool-run.ps1 -Tool <tool-id> -ListModes
```

需要执行 CLI 时，先查看所选模式并补齐目标或脚本，再使用 `-Run`。执行回执中的 `workDir` 指向本次产物目录；检查退出码与实际产物后再判断任务是否完成。MCP 的独立握手成功后，还须由当前智能体宿主核对本会话工具表。

缺少工具时，智能体可调用 `python -X utf8 Tool/mcp/tool_autodiscover.py install <tool-id>` 查看安装方案，按用户已授权的范围加 `--execute` 安装并复探。商业授权、设备连接和外部凭据仍由实际环境提供。
