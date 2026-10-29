# 工具与依赖来源

本页用于定位下载和修复入口。新机器是否已有工具、依赖包或模型配置，必须由智能体实际检测；仓库中的工具目录、压缩包和旧版本记录不能保证解压后立即可用。完整安装先读 [BOOTSTRAP](BOOTSTRAP.md)。

## 依赖入口

| 内容 | 当前入口 | 注意 |
|---|---|---|
| Python 依赖 | Windows `setup/install-python.ps1`；Shell `setup/install.sh` | 使用安装器选定的解释器；版本范围以源码为准，不凭旧文档推断上游 API |
| 仓库离线包 | `setup/extract-deps.ps1` | 只解压实际存在的包；不替代联网下载或任务工具安装 |
| Pi 扩展包 | `setup/install-pi.ps1` 的包声明和宿主更新步骤 | SkipPackages 时不安装；Shell 同步不等于已安装这些包 |
| 任务工具 | `Tool/config/tool-capabilities.json`、`Tool/config/tool-install.json` | 探测、选择安装方式、安装后重新验证 |
| 损坏的 Windows 工具目录 | `setup/repair-tools.ps1` | 先查看参数和将修改的目录，修复后测实际入口 |
| IDA Pro | `setup/install-ida.ps1` | 本体、许可和进程插件分别核验；不随仓库分发授权 |

## 分析工具来源定位

以下列出仓库所引用的来源，不固定“最新版本”或体积；许可与引入历史见 [PROVENANCE](PROVENANCE.md)。

| 组件 | 来源标识 | 仓库目录 |
|---|---|---|
| JADX | `skylot/jadx` | `Tool/mcp/Tool/safe/jadx/` |
| radare2 | `radareorg/radare2` | `Tool/mcp/Tool/safe/radare2/` |
| Apktool | `iBotPeaches/Apktool` | `Tool/mcp/Tool/safe/apktool/` |
| Playwright MCP | npm `@playwright/mcp` | `Tool/mcp/Tool/safe/playwright-mcp/` |
| JavaScript MCP | npm `js-reverse-mcp` | `Tool/mcp/Tool/safe/js-reverse-mcp/` |
| IDA MCP | PyPI `ida-pro-mcp` | `Tool/mcp/Tool/safe/ida-pro-mcp/` |

Windows 工具包不直接用于 Linux/macOS。JADX/Apktool 等还需要 Java；目录或 JAR 存在不能代替执行验证。IDA 缺失时，由智能体按本次所需动作判断 r2 等工具是否足够，不能宣称全部能力自动降级成功。

## 发现、安装与重验

从仓库根目录执行：

```powershell
python Tool/scripts/tool-acquire.py --sweep
python Tool/scripts/env-check.py
```

对具体缺项用 `python Tool/scripts/tool-acquire.py --tool <id> --json` 获取当前状态和下一步；需要安装时由智能体依据声明及实际系统执行，再重新探测。Python 库按当前解释器导入，不查找同名 EXE。下载失败应保留原因，核对实际官方来源、平台和包名；不要把第三方镜像返回的任意文件视为有效软件包。

联网失败可采用当前环境可用的单次网络设置重试，不永久改全局代理或包源。模型登录、商业许可和设备接入需要用户本人操作。最终按 [安装核对](../../MANUAL/DEPLOYMENT-CHECKLIST.md) 报告部署、连接、加载和任务验证结果。
