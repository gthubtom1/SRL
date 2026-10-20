# TOOL-CHAIN — Seep 工具链「GUI → CLI」对照表

> **这份文件是干什么的**：`cmd-guard` 扩展会从自身所在目录向上找 `TOOL-CHAIN.md`（第一层就命中
> `~/.pi/agent/extensions/`），据此派生"哪些 GUI 二进制该拦、该换成什么 CLI"。
>
> **为什么放在这里**：随扩展一起安装即生效，**不依赖任何绝对路径或环境变量** ——
> 换机器、换盘符都不用改。没这份文件时 `cmd-guard` 会降级为"内置兜底 16 条"并显示
> `★未找到 TOOL-CHAIN.md`，把真正的降级淹没在常年警告里。
>
> **本仓规则**：`cmd-guard.rules.json` 里 `blockGui=false`（分析机上 IDA/x64dbg 的 GUI 是正当手段），
> 所以本表主要用于：① 消除降级警告；② 将来若把 `blockGui` 打开，名单直接可用。

## GUI → CLI 对照

| GUI（会被拦） | CLI 替代（推荐） | 备注 |
| --- | --- | --- |
| `die.exe` | `diec` | DIE 控制台版；先 `--version` 确认参数，**不要用 `-h` 试探** |
| `ida.exe` | `idat` | headless 反编译；GUI 交互走 `ida-reverse` 技能的 MCP 桥接（本机 `blockGui=false`，不拦） |
| `ida64.exe` | `idat64` | 同上 |
| `x64dbg.exe` | `x64dbg -silent` | 需交互时用脚本化调试或 `cdb` |
| `ollydbg.exe` | `cdb` | 老调试器，无 CLI 输出 |
| `Wireshark.exe` | `tshark` | 抓包一律 `tshark`，别开 GUI |
| `procmon.exe` | `procmon /AcceptEula /Quiet` | 需要 UI 时改 ETW 采集 |
| `procexp.exe` | `Get-Process` | 进程树用 PowerShell 或 `tasklist` |
| `ProcessHacker.exe` | `tasklist` | 同上 |
| `PE-bear.exe` | `rabin2 -I` | 静态查看用 `rabin2` / `r2` |
| `ImHex.exe` | `xxd` | 十六进制查看用 `xxd` / `r2 -x` |
| `HxD.exe` | `xxd` | 同上 |
| `jadx-gui.exe` | `jadx` | 反编译用 CLI 版（本仓内置 `Tool/mcp/Tool/safe/jadx/bin/jadx.bat`） |
| `apktool-gui.exe` | `apktool` | 用本仓内置 `apktool.jar` |
| `frida-gui.exe` | `frida` / `frida-trace` | 用 CLI，脚本由 `seep_apk_gen_hook` 生成 |

## 使用纪律（与 `AGENTS.md` §四点五 一致）

- 表外工具**只报"路径已发现"**，不要靠 `-h` / `--help` 试探二进制（会崩、会弹窗、会触发反调试）；
- 定位工具：`seep_tool_discover` → `where.exe <id>` / `Get-Command <id>` → 已知路径常量（`TOOL_DIR`）；
- 需要 GUI 交互时：走 `computer-use` / 界面会话，**不要**在 `bash` 里同步等 GUI。
