# BOOTSTRAP —— 新电脑上由 **Agent 自己**装好这套工作台

> **给 Agent 读的**：用户不需要知道 `install.ps1`。你要做的是**自己判断、自己安装、自己校验、把结果汇报**。
> 用户只会说"新电脑"、"装一下"、"这台还没配"之类的人话。

---

## 0. 判断：这台机器装没装

```bash
python Tool/scripts/env-check.py --text
```

- `结论: 已就绪` → 跳到 §4 汇报，直接开工。
- `结论: 需要安装/修复（缺 N 项）` → 继续 §1。

`env-check.py` 检查：`~/.pi/agent` 是否存在、`SEEP.md`/`AGENTS.md` 是否安装、
扩展（.ts/.json/.md）是否齐全、技能是否齐全、`mcp.json` 里指向本地文件的参数是否存在、settings 的 packages 与 retry 档位。
JSON 模式（`env-check.py`）给出 `missing[]` 与 `next_actions[]`，照着做即可。

---

## 1. 安装（Agent 执行，不要交给用户）

```powershell
powershell -ExecutionPolicy Bypass -File .\setup\install.ps1
```

它会自动完成：解压离线依赖（js-reverse / playwright / ida-pro-mcp）→ 装 Python 依赖（mcp 等）→
同步技能/提示词/扩展（含 `*.json` 规则与 `TOOL-CHAIN.md`）→ 增量合并 `mcp.json`（读 `Tool/config/mcp-servers.json`）
→ 写 settings（packages + retry 默认档）→ 生成 Claude/OpenCode/DSH 配置 → 探测并接入 IDA → 跑 `verify.ps1`。

**Linux/macOS**：`chmod +x setup/install.sh && ./setup/install.sh`

> 安装器是幂等的、会先备份 `~/.pi/agent` 到 `backup-*`。重复执行安全。

---

## 2. 校验（Agent 执行）

```powershell
powershell -ExecutionPolicy Bypass -File .\setup\verify.ps1 -Detailed   # 期望 65/65
python Tool/scripts/preflight.py --fast                                  # 期望 18/18
```

两项都绿 = 装好。任何一项红，按 §3 处置。

---

## 3. 失败处置（照表做，不要问用户"要不要装"）

| 现象 | 处置 |
|---|---|
| `未找到 Python` | 装 Python 3.11+ 并勾 Add to PATH —— **这是系统级前提，唯一需要用户动手的一类**，装完继续 §1 |
| `未找到 Node.js` | 可选（js-reverse / playwright 需要）；装 Node 18+ 后重跑 §1 |
| `java` 缺失 | jadx/apktool 需要 JRE 11+；装完重跑 §1 |
| `mcp.json` 条目指向的文件不存在 | `python Tool/scripts/env-check.py` 看 `missing`，重跑 `setup/install-pi.ps1` 刷新路径 |
| MCP 显示 `failed` | 先看 `~/.pi/agent/mcp.log`；stdio 服务手工启动一次看报错；`ida` 需要 `mcp<2`（安装器已处理） |
| IDA 没装 / 路径特殊 | `setup/install-ida.ps1 -IdaRoot <路径>`；没 IDA 不影响主链路（r2 + Ghidra headless 兜底） |
| PowerShell 执行策略拦截 | 用 `-ExecutionPolicy Bypass`（上面命令已带） |
| 装完扩展没生效 | **必须重启 Agent 会话**（MCP 与提示词在会话启动时装配） |

---

## 4. 汇报（装完给用户的四栏看板）

| 栏 | 内容 |
|---|---|
| 部署 | 仓库路径 / 版本 / Agent 目录 / 装了哪些扩展与技能 |
| 校验 | `verify.ps1` N/61、`preflight.py` N/M、失败项与原因 |
| 工具 | 探测到的关键工具（r2 / jadx / apktool / frida / ghidra / IDA / x64dbg / tshark …） |
| MCP | 每个 server 的状态与工具数（seep / ida / js-reverse / playwright / x64dbg） |

最后一句话告诉用户：**"重启会话后输入 `lab：` 即可开工"**。

---

## 5. 铁律

1. **不要让用户手动跑脚本** —— 你能跑的，你自己跑；跑完汇报结果。
2. **只有系统级前提才找用户**：Python / Node / Java / IDA 授权这类装机动作。
3. **装完必须校验**，未校验不得声称成功。
4. **改完必须跑门禁**：`python Tool/scripts/preflight.py`（加工具/加 MCP/加技能见 `Tool/docs/EXTEND.md`）。
5. **换机后不确定状态 → 先 `env-check.py`**，不要凭记忆猜。
