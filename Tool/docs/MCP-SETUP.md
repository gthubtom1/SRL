# MCP 配置与验证 (MCP-SETUP)

> 本工作台靠 **3 个 MCP** 提供工具能力。本文说明：**它们是什么、装到哪、怎么验证、出问题怎么办。**
>
> 📦 **各 MCP 依赖的工具从哪里下载** → 见 **`Tool/docs/DOWNLOADS.md`**

---

## 一、MCP 与 Skill 的关系

```
Skill（提示词层）       →  告诉 agent「该做什么、走哪条路」
MCP（工具层）           →  给 agent「实际干活的手」
```

**举例**：`apkseep` Skill 说「用 jadx 反编译这个 APK」→ agent 调 `seep_apk_decompile`
→ seep MCP 内部驱动 jadx 完成反编译。

> **Skill 是说明书，MCP 是工具。** 两者都装好才能干活。

---

## 二、已注册 MCP（5 个）

| MCP | 工具数 | 用途 | 依赖 | 安装方式 |
| :--- | :---: | :--- | :--- | :--- |
| **seep** ⭐ | **40** | 二进制逆向 + APK 逆向 + Frida 生成 + 知识库 + 扩展资产 | radare2 / jadx / apktool | 本包自带 + 脚本下载工具 |
| **ida** | **40+**（实测 48，随 ida-pro-mcp 版本变） | IDA 全套分析链 | **你自备的 IDA Pro** | `setup\install-ida.ps1` 自动装（需 `mcp<2`，见 §九） |
| **js-reverse** | **24** | 前端 JS 逆向 / 调试器 / 网络取证 | npx | 自动（npx 按需拉取） |
| **playwright** | **25** | 浏览器自动化 | npx | 自动（npx 按需拉取） |
| **x64dbg** | **80**（宿主插件，随宿主起） | 动态调试（断点/单步/读内存） | 自备 x64dbg | `Tool/scripts/tool-run.ps1 -Tool x64dbg`（http 9094，需 `/mcp reconnect`） |

> IDA 不在默认路径也没关系：`install-ida.ps1` 会做**有界目录扫描**（只扫 `D:\Tools`、`D:\Tools\disasm`
> 等固定几个根，深度 ≤2），便携版/绿化版（如 `D:\Tools\disasm\IDA Pro 9.3`）也能命中。
> 也可以显式指定：`powershell -File .\setup\install-ida.ps1 -IdaRoot "X:\你的\IDA"`。

### seep MCP 的 20 个工具

| 分组 | 工具 |
| :--- | :--- |
| 状态环境 (2) | `mcp-doctor.py` · `mcp-doctor.py` |
| 二进制 r2 (9) | `seep_r2_info` · `_cmd` · `_strings` · `_functions` · `_disasm` · `_decompile` · `_diff` · `_asm` · `_xrefs` |
| Android (5) | `seep_apk_info` · `_decompile` · `_unpack` · `_smali_search` · `_gen_hook` |
| 知识库 (4) | `seep_kb_search` · `_read` · `_checklist` · `_payloads` |
| 案例库 (2) | `case_state.py index` · `_read` |
| 流程编排 (3) | `mkdir -p <task>/{samples,exports,patches,reports}` · `seep_auto_triage` · `seep_gen_security_report` |
| 扩展资产 (15) | `seep_ensure_tool` · `seep_r2_decompile` · `seep_r2_cmd(iR)` · `seep_mem_strings` · `seep_pcap_extract` · `seep_packer_detect` · `seep_http_replay` · `web-check.py` · `seep_tool_discover` · `tool-acquire.py` · `tool-acquire.py --list` · `tool-acquire.py（ASK）` · `tool-acquire.py --tool <id>` · `tool-acquire.py --json` · `手写 pack.json` |

---

## 三、安装过程（`install-pi.ps1` 自动完成）

```
1. 备份现有 ~/.pi/agent/ 配置
2. 复制 Skill  →  ~/.pi/agent/skills/
3. 复制提示词  →  ~/.pi/agent/SEEP.md · AGENTS.md
4. 复制扩展    →  ~/.pi/agent/extensions/
5. 生成 mcp.json：
     · <SEEP_ROOT>  → 本包实际路径
     · <IDA_ROOT>   → 自动探测（D:\Tool\IDA Pro / C:\Program Files\IDA Pro / C:\IDA Pro）
     · <IDA_PYTHON> → 探测到的 IDA Python
     · playwright → `--headless` 模式，**无需 token**（详见下方说明；别改回 `--extension`）
6. 写 settings.json（12 个 pi packages）
7. 执行 pi update --extensions
```

**生成的 `~/.pi/agent/mcp.json` 结构**：

```json
{
  "mcpServers": {
    "seep": {
      "command": "python",
      "args": ["<本包路径>\\Tool\\mcp\\seep_mcp_server.py"],
      "env": { "PYTHONIOENCODING": "utf-8" },
      "transport": "stdio"
    },
    "ida": {
      "command": "<IDA Python 路径>",
      "args": ["<IDA 安装目录>\\Lib\\site-packages\\ida_pro_mcp\\server.py"],
      "transport": "stdio",
      "lifecycle": "eager",
      "requestTimeoutMs": 180000
    },
    "playwright": {
      "command": "npx",
      "args": ["-y", "@playwright/mcp@latest", "--headless"],
      "transport": "stdio",
      "lifecycle": "lazy"
    }
  }
}
```

> **为什么是 `--headless` 而不是 `--extension`**：扩展模式**同时**要求两件东西 ——
> ① 一个真实的 `PLAYWRIGHT_MCP_EXTENSION_TOKEN`；② 本机已安装并启用对应的浏览器扩展。
> 缺任一个，进程起来就报 `Playwright Extension not found`（工具列表能连上、一调真功能就死）。
> `--headless` 不需要 token、不需要预装扩展，开箱可用。
> 因此 `mcp-servers.json` 里 playwright 条目已经**没有 `env`、也不再带 `onlyIfMissing`** ——
> 留着 `onlyIfMissing` 会让重装时保留旧的 `--extension` + 占位 token 条目，等于把同一个 bug 又装回来。
> 同理，旧版的 `PLAYWRIGHT_MCP_EXTENSION_TOKEN` 占位符已经没用了，装完可自查：
> `grep -n 'YOUR_PLAYWRIGHT_TOKEN' Tool/config/mcp-servers.json ~/.pi/agent/mcp.json` 应为 **0 命中**。

---

### 装任何 pi 扩展前：先跑命名自检

pi 把少数内置标为 `replaceable`（当前：`codemode` / `tool-search` / `mcp`）。
第三方扩展只要注册了**同名**命令/工具/旗标（典型：自己实现 `/mcp`），内置会被**静默丢弃**，启动横幅打 `[Extension issues]`，
且工具命名从内置的 `mcp__<server>__<tool>` 变成第三方的 `mcp_<server>_<tool>` ——
所有按 `mcp__` 写死的消费者（如 pi-web 的只读策略 / 子代理 / 退出登录）会**静默失效**。

```bash
python Tool/scripts/check-extension-conflicts.py      # 有冲突 → 退出码 1，并给出处置
```

`install-pi.ps1` 在装完扩展包后会自动跑这一步。

> **给本工作台加 MCP 服务器不会触发**：编辑 `mcp.json` 或用 `tool-acquire.py（ASK）`
> 只是“加一条服务器配置”，不是“装一个替换内置的扩展”。

#### `seep_tool_discover` → `tool-acquire.py（ASK）` 的边界

| 环节 | 它到底做什么 | 会不会碰扩展层 |
|---|---|---|
| `seep_tool_discover` / `tool-acquire.py` / `tool-acquire.py --tool <id>` | 探测并安装**外部工具本体**（exe / pip / npm 全局包 / 运行时） | ✗ 不改动 `settings.json` 的 `packages` |
| `tool-acquire.py（ASK）` | 只往 `mcp.json` 的 **`mcpServers`** 加一条服务器配置 | ❌ 不装 pi 扩展、不改 packages |

两层加固：

1. **落盘前预检**：`command` 指向的路径不存在 / 参数里的脚本不存在 → **拒写**并提示先装工具；
   裸命令（`npx` / `uvx`）不在 PATH → **仅告警**（不阻断“先注册后装工具”的工作流）。
2. **落盘后回读校验**：返回 `verified: true/false`，防止编码 / 并发覆盖造成的脏配置。

---

## 四、⚠️ 关键约束：`Tool/mcp/Tool/` 不可搬动

`seep_mcp_server.py` **内部硬编码**了运行时目录：

```python
BASE_DIR = os.path.dirname(os.path.abspath(__file__))   # = Tool/mcp/
TOOL_DIR = os.path.join(BASE_DIR, "Tool")               # = Tool/mcp/Tool/
SAFE_DIR = os.path.join(TOOL_DIR, "safe")               # = Tool/mcp/Tool/safe/
KB_DIR   = os.path.join(TOOL_DIR, "reverselab", "kb")   # = Tool/mcp/Tool/reverselab/kb
```

因此：

| 依赖 | 必须位于 |
| :--- | :--- |
| radare2 | `Tool/mcp/Tool/safe/radare2/bin/` |
| jadx | `Tool/mcp/Tool/safe/jadx/bin/` |
| apktool | `Tool/mcp/Tool/safe/apktool/` |
| Hook 模板 | `Tool/mcp/Tool/safe/hook-mcp/templates/` |
| 知识库 | `Tool/mcp/Tool/reverselab/kb/` |

> **搬走任何一个，对应的 MCP 工具就会失效。**

---

## 五、验证 MCP 是否就绪

### 方法 1：跑自检脚本（推荐）

```powershell
cd Desktop\Seep\setup
powershell -ExecutionPolicy Bypass -File .\python Tool/scripts/check.py --env
```

### 方法 2：在 pi 里问

```
你：mcp-doctor.py 能跑吗？
pi：[返回 radare2 / jadx / apktool / 知识库 的就绪状态]
```

### 方法 3：手工检查

```powershell
# 1. 配置无占位符残留
Select-String -Path "$env:USERPROFILE\.pi\agent\mcp.json" -Pattern "<[A-Z_]+>"

# 2. seep MCP 语法可解析
python -c "import ast; ast.parse(open(r'C:\...\Seep\Tool\mcp\seep_mcp_server.py',encoding='utf-8').read())"

# 3. 知识库在位
(Get-ChildItem "C:\...\Seep\Tool\mcp\Tool\reverselab\kb" -Recurse -Filter *.md).Count   # 期望 ≥289
```

---

## 六、工具 → MCP 依赖对照（排障用）

| MCP 工具 | 依赖的目录 / 工具 | 缺失时的现象 |
| :--- | :--- | :--- |
| `seep_kb_*`（4 个） | `Tool/mcp/Tool/reverselab/kb/` | 检索返回空 / 报路径不存在 |
| `seep_r2_*`（8 个） | `Tool/mcp/Tool/safe/radare2/bin/` | "radare2 not found" |
| `seep_apk_decompile` | `Tool/mcp/Tool/safe/jadx/bin/` | "jadx not found" |
| `seep_apk_unpack` | `Tool/mcp/Tool/safe/apktool/` | "apktool not found" |
| `Tool/mcp/Tool/safe/hook-mcp/` | `Tool/mcp/Tool/safe/hook-mcp/templates/` | 模板缺失 |
| `mcp__ida__*`（约 100 个，随 ida-pro-mcp 版本变化） | 自备 IDA Pro + `Tool/mcp/Tool/safe/ida-pro-mcp/` | "IDA not available" |
| playwright 工具 | npx（`--headless`，无需 token） | 浏览器不可用 / 报 `Playwright Extension not found`（说明配置里还是 `--extension`） |

**排障口诀**：工具报错 → 看它读哪个目录 → 检查该目录是否存在且非空。

---

## 七、IDA Pro 不可用时的降级路线

> **原则**：不阻塞、不报错，直接用 `seep_r2_*` 继续推进。

| 需求 | seep MCP 替代 |
| :--- | :--- |
| 架构 / 壳 / 熵 / 字符串 | `seep_r2_info` · `seep_r2_strings` |
| 反汇编 + 交叉引用 | `seep_r2_disasm` · `seep_r2_cmd(afl)` |
| 类 C 伪代码 | `seep_r2_decompile` |
| 二进制差分 | `radiff2 CLI` |
| 汇编 ↔ 机器码 | `seep_r2_cmd(rasm2)` |

报告中应标注：**"未使用 IDA 反编译器，伪代码质量受限"**。

详见 `MANUAL/IDA-PRO.md`（含 3 种方案对比）。

---

## 八、可选注册的 MCP（默认关闭）

`reverselab` 自带 3 个 MCP，源码在 `Tool/mcp/Tool/reverselab/tools/skills/mcp/`，
**默认不注册**。需要时手工加入 `mcp.json`：

| MCP | 位置 | 用途 |
| :--- | :--- | :--- |
| **ReverseLabToolsMCP** | `.../mcp/ReverseLabToolsMCP/` | reverselab 主 MCP（150+ 工具） |
| **JSHookLocal** | `.../mcp/JSHookLocal/` | JS Hook 本地服务 |
| **GhidraMCP** | `.../mcp/GhidraMCP/` | Ghidra 桥接 |

**注册示例**：

```json
"reverselab": {
  "command": "python",
  "args": ["<本包路径>\\Tool\\mcp\\Tool\\reverselab\\tools\\skills\\mcp\\ReverseLabToolsMCP\\reverse_lab_tools_mcp.py"],
  "cwd": "<本包路径>\\Tool\\mcp\\Tool\\reverselab",
  "transport": "stdio"
}
```

> ⚠️ 需先装其 Python 依赖（见该目录 `requirements.txt`）。

### 8.1 x64dbg 的 MCP：原生就能接（实测）

x64dbg 插件 `x64dbg-MCP-Server.dp64`（`x64dbg
eleased\plugins\`）在 x64dbg 启动时自动起服务
（`mcp_config.json` 里 `AutoStart:true`，端口 9094，鉴权 `Authorization: Bearer <AuthToken>`）。

**实测结论：它原生支持 streamable HTTP**，不需要任何桥接：

```bash
POST http://127.0.0.1:9094/mcp  → 200，返回 initialize（serverInfo: x64dbg-MCP Server v1.5，80 tools）
GET  http://127.0.0.1:9094/sse  → 也有，但只是兼容路径；无 token 一律 401
```

注册方式（token **不写进 mcp.json**，用 pi 的 `!命令` 动态取，值始终留在 x64dbg 自己的配置里）：

```json
"x64dbg": {
  "url": "http://127.0.0.1:9094/mcp",
  "headers": {
    "Authorization": "!python -c \"import json,os;print('Bearer '+json.load(open(os.path.join(os.environ['X64DBG_DIR'],'mcp_config.json'),encoding='utf-8'))['AuthToken'])\""
  },
  "transport": "http",
  "lifecycle": "lazy"
}
```

> **前提：x64dbg 必须先运行。** 不想手动点？让 Agent 跑（它按 `Tool/config/tool-runtimes.json` 的通道阶梯执行；
> x64dbg 没有 headless 通道，所以这一档就是「GUI 内 MCP」——这是阶梯里唯一合理的 GUI 场景）
> `powershell -File Tool/scripts/tool-run.ps1 -Tool x64dbg [-Target <样本>]`
> —— 它自己定位 exe、启动、轮询 9094 到就绪（实测 1.3s）。
> `lifecycle: lazy` 保证 x64dbg 关着时不会拖慢会话启动。
>
> 实测：`mcp__x64dbg__GetDebugState` 返回 `isDebugging: false`，80 个工具全部可用。

### 8.2 Ghidra

`seep_r2_decompile` 会用 `analyzeHeadless`（本机 `D:\Tools\Ghidra\support\analyzeHeadless`）做**无头反编译**，
不需要装 GhidraMCP。要交互式 Ghidra 会话再考虑装其 MCP 扩展。

---

## 九、常见问题

| 问题 | 处理 |
| :--- | :--- |
| pi 启动后 MCP 没加载 | **重启 pi**（MCP 在启动时注册） |
| `seep` 工具全部不可用 | 检查 `mcp.json` 的 `seep.args[0]` 路径是否存在 |
| `seep_kb_*` 报错 | 检查 `Tool/mcp/Tool/reverselab/kb/` 是否 ≥289 篇 |
| `seep_r2_*` 报错 | 重跑 `setup\install-tools.ps1` |
| `ida` 工具报错 | 确认 IDA 已装 + `mcp.json` 里 ida 路径正确 |
| MCP 配置文件被我改坏了 | 重跑 `setup\install-pi.ps1`（会自动备份旧配置） |
| 想看 MCP 报错日志 | pi 启动时的 stderr；或手工 `python Tool\mcp\seep_mcp_server.py` 看输出 |

---

## 十、手工验证 seep MCP（不通过 pi）

```powershell
cd Desktop\Seep\Tool\mcp
python seep_mcp_server.py
# 正常应挂起等待 stdio 输入（无报错即 OK）
# Ctrl+C 退出
```

若报 `ModuleNotFoundError: mcp` → 重跑 `setup\install-python.ps1`。

---

## 十一、已知限制（L3 活性判定口径，别为了凑绿去改）

### 11.1 L3 只认**结构化 toolCall**，不认提示词文本

「（liveness-check 已删：生效性并入 gate.py）」(S1 已删) 的 L3 判定读的是会话 jsonl 里**真实发生的工具调用记录**
（`type=toolCall` 的结构化条目），**不读**助手回复里的自然语言。

- 所以「我在回复里写了『已调用 mcp-doctor.py』」**不算** reached —— 那正是曾经造成**假绿**的写法：
  文本可以随便写，结构化记录改不了。这是刻意的修复，不是缺陷。
- 想让某个 MCP 记为 reached，唯一做法是**真的发起一次工具调用**。

### 11.2 已知盲区：经 `codemode` 转调的 MCP 会被记为 unreached

MCP 工具如果是从 `codemode` 脚本里发起的（`tools.mcp__xxx__yyy(...)`），
jsonl 里只会出现 **`name=codemode`** 这一条，看不到内层被调用的 MCP 名字。
于是 L3 会把那个 MCP 判成 **unreached**，即使它实际上被成功调用过。

> **这是刻意保守，不是 bug，不要为凑绿而放宽判定口径。**
> 放宽的后果：任何「写一句声明」都能拿绿，L3 就失去全部鉴别力。
> 确实需要用可计数证据证明某 MCP 可用时，走 §五 的方法 1（`python Tool/scripts/check.py --env`）或直接 `tools/list` 实测。

---

## 附：MCP「工具数」到底怎么算（三种口径，别混用）

同一个"工具数"在不同语境下含义不同，混用会造成误判。本工作台统一按下面三种口径表述：

| 口径 | 含义 | 本包数值 | 怎么核实 |
|---|---|---|---|
| **① 自有工具数** | 我们自己的 `seep` MCP 服务暴露的工具（`@server.tool()` 装饰的函数） | **40** | `grep -c "^@server.tool()" Tool/mcp/seep_mcp_server.py`，或连上 MCP 发 `tools/list` |
| **② 单个外部 MCP 的工具数** | `ida` / `js-reverse` / `playwright` / `ghidra` **各自进程**暴露的工具，由各自项目决定 | ida 约 100+（随 ida-pro-mcp 版本）/ js-reverse 23（v4.0.5）/ playwright 随版本 | 连上对应 MCP 发 `tools/list`（最权威），或看其源码 / README |
| **③ 全工作台"可见工具总数"** | ① + 所有② | **不固定**（取决于装了哪几个外部 MCP、什么版本） | 由当前会话的 MCP 客户端汇总 |

**为什么我们只承诺 ①=40**：

- ② 的数字**不属于我们**，会随上游发版变化（同一个包不同版本工具数就不同）；
- 所以文档里任何"总数"都只应是**参考值**，判定是否可用要跑 `tools/list`，不要背数字。

**反臃肿预算（≤45）约束的是 ①**：即"我们自己新增 MCP 工具"的上限，与外部 MCP 无关。

---
