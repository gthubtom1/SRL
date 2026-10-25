# 工具清单（生成，勿手改）
> 快照：由 `tool_autodiscover.discover()`（8 层探测）现算；**不写机器路径**（各机器不同，写进来会破坏可移植性）。
> 想看具体路径：`python Tool/scripts/tool-acquire.py --sweep`（只在本机输出）
> 生成时间：2026-10-25

| 工具 | 本机是否就位 | 命中层 |
| :-- | :-: | :-- |
| `radare2` | 是 | cache |
| `r2` | 是（`-qc` 可用；但 `rabin2` 子命令不可用，见下） | cache |
| `rabin2` | 否（BROKEN：本机 `rabin2.exe` 是 `radare2.exe` 改名，`-I <pe>` 会被当成加载脚本并进交互模式） | cache |
| `jadx` | 是 | cache |
| `apktool` | 是 | cache |
| `frida` | 是 | cache |
| `binwalk` | 是 | cache |
| `diec` | 是 | cache |
| `x64dbg` | 是 | cache |
| `x32dbg` | 是 | cache |
| `ghidra` | 是 | cache |
| `ida` | 是 | cache |
| `nmap` | 是 | cache |
| `sqlmap` | 是 | cache |
| `yara` | 是 | cache |
| `wireshark` | 是 | cache |

> 历史版本曾把内置工具标成 Missing，并指向不存在的 `apk-reverse/scripts/*.ps1`，
> 会让人去联网装本已随仓库打包的工具（radare2 / jadx / apktool 在 `Tool/mcp/Tool/safe/`）。已重写。
