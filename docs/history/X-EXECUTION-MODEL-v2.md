> ⛔ **已归档（2026-10-24）——禁止作为执行依据。**
> 现行唯一入口：`docs/NOW.md`（现在做什么）+ `docs/BLUEPRINT.md`（架构口径）。
> 本文仅作历史记录与证据出处。

# 执行模型 v2：人机协作 / 启动纪律 / 采集纪律 / 网络零改动

> ⚠️ **背景/依据文档，不是执行口径。** 唯一的数字与批次顺序见 `docs/history/X-PLAN-FINAL.md`（冲突一律以它为准）。

> 由来：2026-10-23 会话 `01a1685a`（AI 自瞄 · 卡密授权）实测翻车后的复盘定稿。
> 本文是**行为规则的一次升级**，不是又一个 checklist。核心变更只有一句：
> **Agent 不再假装自己是全自动的。该停就停，该让人点就让人点，该不动的地方一个字节都不动。**

---

## 0. 这次实测暴露了什么

| # | 铁证 | 结论 |
| :-- | :-- | :-- |
| 1 | 用户截的图：`AGC_nodyndbg.exe` → **"File corrupted! This program has been manipulated and maybe it's infected by a Virus or cracked."** | 目标有**磁盘完整性自检**。改了 `DllCharacteristics` 一位就触发 → **磁盘补丁路线默认是死的** |
| 2 | Agent 用 `python subprocess` + 独立标志拉起目标（父进程 = python.exe → bash.exe 链） | 父进程链本身就是反自动化检测面，**真实双击的父进程是 explorer.exe** |
| 3 | 给正在上网的 DHCP 网卡挂 `/32` 别名 IP + `netsh winhttp set proxy` 指向本地假服务器 | 假服务器一死 → **整机断网**。分析机常常就是用户日常机，改全局网络 = 把用户一起搞离线 |
| 4 | 48 分钟 / 167 次调用 / 1705 万 cacheRead，自然语言汇报 **1** 条，facts 台账 **0** 条 | 没有"人在环上"的位置，也没有落账 → 上下文一压缩就失忆，用户全程不知道在干什么 |
| 5 | 有卡密却从没让人输过一次；全程试图"自己绕过" | 方向错了。**卡密是用户的操作，不是 Agent 的输入** |

---

## 1. 第一原则变更：三档执行（AUTO / ASK / DENY）

旧模型隐含假设："一次对话从开头跑到交付"。这个假设是错的，而且它逼着 Agent 去做两件危险的事：**替你点鼠标** 和 **猜你的卡密**。

新模型：

| 档 | 什么动作 | 谁做 | 例子 |
| :-- | :-- | :-- | :-- |
| **AUTO** | 只读、无副作用、可复现 | Agent 全自动 | 结构/节表/熵/壳判定、字符串、伪代码、KB 查询、xref、协议字段测绘、dump 后地址换算 |
| **ASK** | 需要真实人手、需要用户手里的凭据、需要"真人操作"才能绕过的检测 | **用户做，Agent 设计并监控** | 双击启动目标、点「激活授权」、输入卡密、开游戏验证自瞄是否生效、装证书、插硬件 |
| **DENY** | 会伤到用户这台机器的动作 | **永不执行**，只给替代方案 | 改本机网卡 IP / 路由 / DNS / WinHTTP 代理、重置 winsock、关防火墙、禁网卡、用 shell 拉起 GUI 目标（改 warn） |

### 1.1 ASK 卡（固定格式，Agent 必须照这个发）

```
【需要你动手 · N 步】
1. <动作，精确到点哪里>
2. ...
3. 做完回我一句：「<回执关键词>」

我在做什么：<Agent 正在监控什么，用什么手段>
你操作期间我保证：不动鼠标键盘 / 不改系统设置 / 不主动联网
我拿到什么：<这一步产生的证据，例如 device_id / 登录响应 / 授权态翻转>
你不想做的话：<备选路线，以及它差在哪>
```

**触发 ASK 的三条硬条件（任一命中就必须停）：**

1. 需要**目标进程真实运行**才能拿到的证据（登录报文、授权态、内存里的明文密钥）；
2. 需要**只有用户手里有**的东西（卡密、账号、硬件狗、手机验证码）；
3. 目标存在**反自动化检测**（父进程检查 / 完整性自检 / 反调试 / 反抓包 / 窗口标题随机化 / 输入注入检测），而真人操作能自然绕过。

### 1.2 状态机（落进 `case_state.py`）

```
init → recon(AUTO) → gate#0(壁垒清单) → ASK_LOGIN(waiting_human)
     → dyn(AUTO)  → decision → patch(ASK 验收) → deliver
```

`waiting_human` 是一个**一等状态**：此时 Agent 不许"顺手自己试试"，只许轮询/截屏/读日志/attach 观察。

---

## 2. 启动纪律：永不 CreateProcess

### 2.1 为什么（实测数据）

本机实测（`explorer.exe` 拉起 vs 代码拉起）：

| 启动方式 | 父进程 | 命令行 | 创建标志 | 检测风险 |
| :-- | :-- | :-- | :-- | :-- |
| `explorer.exe "<路径>"`（≈双击） | **explorer.exe** | 只有 exe 路径，零参数 | 无 | **LOW** |
| `Start-Process` | powershell.exe | 可能带参数 | 无 | HIGH |
| `cmd /c start` | cmd.exe | 带引号/参数 | 新控制台 | HIGH |
| `subprocess.Popen(..., creationflags=0x8)` | python.exe → bash.exe | 脚本包装 | `DETACHED_PROCESS` | **极高**（教科书特征） |

目标只要读一次 `NtQueryInformationProcess` / 父进程名 / `PEB->ProcessParameters`，就能把后面三行全判出来。

### 2.2 三种合法方式（按优先级）

1. **`-Mode user`（默认、首选）**：不启动，打印一句话让用户自己双击。Agent 只做观察。
2. **`-Mode shell`（必须 Agent 启动时）**：`explorer.exe "<绝对路径>"` —— 父进程 = explorer.exe，零参数，无标志。
3. **`-Mode attach`**：目标已在跑，只观察。

**禁止清单**（`cmd-guard` 已内置 warn）：`Start-Process ... .exe` / `cmd /c start` / `subprocess.(Popen|run)(... .exe` / 任何 `CREATE_SUSPENDED` / `DEBUG_PROCESS` / `DEBUG_ONLY_THIS_PROCESS` 标志 / 把目标 exe 复制成"改过名"的副本再跑（名字本身也是特征，且会触发完整性自检）。

### 2.3 落点

```bash
# 首选：让用户自己点
powershell -NoProfile -ExecutionPolicy Bypass -File Tool/scripts/launch-gui.ps1 \
    -Target "D:\Case\目标.exe" -Mode user

# 必须自己拉起时（父进程 = explorer.exe）
powershell -NoProfile -ExecutionPolicy Bypass -File Tool/scripts/launch-gui.ps1 \
    -Target "D:\Case\目标.exe" -Mode shell -ListWindows -Json
```

输出包含：`instances[]`（pid / ppid / 父进程名 / 命令行 / risk）+ `windows[]`（hwnd / class / 客户区尺寸 / visible / title）+ `verdict`（LOW / MEDIUM / HIGH，HIGH 时退出码 3）。

### 2.4 窗口匹配纪律（本次实测踩到）

同一个目标三次启动给了三个不同标题：`SystemTuner_1757` / `DisplayManager_1338` / `PerformanceTuner_5040`。**这是故意的反自动化**。

> **永远按 `(pid, class, clientW, clientH)` 匹配窗口；标题只写日志，绝不作键。**

`launch-gui.ps1` 已经把这条写进输出的 `windowMatchRule` 字段，避免下次又按标题匹配。

---

## 3. 完整性自检：为什么磁盘补丁会直接死

### 3.1 实测

- 原始 `AGameCrash64.exe`：`ImageBase=0x140000000`，`.text/.rdata/.data` 的 `RawSize` 全 `0`（磁盘上没有原始代码，运行时解密），另有 `.ace0` 节熵 7.35。
- Agent 改了一份 `AGC_nodyndbg.exe`（只清了 `DYNAMIC_BASE` 一位）→ 双击/启动即弹 **"File corrupted!"** 后退出。
- 在已 dump 的 37MB 解包镜像里搜 `File corrupted` / `manipulated` / `This program has been` —— **ASCII 与 UTF-16 全 0 命中**。

**结论**：这条弹框来自**壳/保护层 stub**（在校验之后才解密装载），所以 dump 出来的解包镜像里没有它。**任何磁盘字节改动都会在进入原始代码之前被拦下。**

### 3.2 对策（按代价排序）

1. **不动磁盘**：运行期内存补丁。改完立即还原，或用硬件断点 + 一次性写。
2. **不动文件**：注入器 / 内存加载（把授权判定在内存里替换掉，磁盘文件保持原样）。
3. **真要改文件**：先定位校验函数并一起处理（把"校验"和"补丁"做成一次原子改动）。

### 3.3 定位校验函数的标准手法（下次直接用）

```
① Frida hook MessageBoxW / MessageBoxA / CreateDialogIndirectParamW
② 让目标带着被改过的副本启动，弹框出现瞬间抓调用栈
③ 栈上第一个"非系统模块"地址 = 校验点（运行时基址，不是文件基址）
④ 用 dump 的 load_base 换算成 RVA，回静态里定位比较逻辑（通常读自身路径 + CRC/哈希）
⑤ 校验对象确认后，再决定：绕过 / 让校验通过（重算）/ 干脆绕开磁盘
```

第 ② 步是整件事的钥匙：**它在内存里发生，所以不受磁盘完整性自检影响**，也不会像 Npcap 那样引入新的检测面。

---

## 4. 采集纪律：抓包不许动系统网络

### 4.1 检测面矩阵（这是选型的唯一依据）

| 方案 | 装驱动 | 装根证书 | 改系统代理 | 开监听端口 | 被反抓包检测的可能性 |
| :-- | :-: | :-: | :-: | :-: | :-- |
| **Frida hook `WinHttpSendRequest/ReceiveResponse`** | ✗ | ✗ | ✗ | ✗ | **最低**（只有 frida-agent 模块可被模块枚举发现） |
| Frida hook `WSASend/WSARecv`（原生 socket） | ✗ | ✗ | ✗ | ✗ | 最低 |
| mitmproxy/Charles/Fiddler/Reqable + **仅进程内**改代理 | ✗ | ✓ | ✗ | ✓(本地) | 中（证书链/代理检测可发现） |
| mitmproxy/Charles/Fiddler/Reqable + 系统代理 | ✗ | ✓ | ✓ | ✓ | 中高（读系统代理一眼看穿） |
| Wireshark / Npcap | ✓ | ✗ | ✗ | ✗ | **高**（服务/驱动可枚举；且会多出适配器 → `GetAdaptersInfo` 机器码可能变） |
| `pktmon` / `netsh trace`（ETW 内置） | ✗ | ✗ | ✗ | ✗ | 低，但**只有元数据不含 payload** |

> 「小黄鸟」= HttpCanary，是 Android 上的；桌面版是 **Reqable**（同一团队）。桌面三件套（Fiddler/Charles/Reqable）本质都是"系统代理 + 根证书"，隐蔽性同一个量级，比 Wireshark 好，但**都不如进程内 hook**。

### 4.2 推荐顺序

1. **Frida 进程内 hook**（默认）—— 拿明文请求/响应，零系统改动。
2. 需要完整时序 / 人肉看包时，再加 **mitmproxy**，且**代理只注入目标进程**（hook `WinHttpOpen` 的代理参数），不改系统代理。
3. 只想知道"连了谁" → `pktmon`（ETW，无驱动）。
4. Wireshark **最后选**：只在纯 lab 机、或先做过"机器码不变"验证之后。

### 4.3 网络零改动铁律（已内置）

- `cmd-guard` 新增 **9 条禁手**，其中 6 条 `block`：改网卡 IP / 改网卡状态 / 改 WinHTTP 代理 / 改 DNS / 改路由 / 重置 winsock。命中直接拦，并回一段"该改用哪条路"。
- 3 条 `warn`：`Start-Process` / `cmd start` / `subprocess` 拉起 exe。
- 真要改本机网络时：**先** `python Tool/scripts/net-rollback.py snapshot`，**再**在命令里加 `cmd-guard-skip` 显式放行 —— 顺序不能反。
- 还原：`python Tool/scripts/net-rollback.py restore`（`--dry-run` 先看要动什么），结束后自动 `verify`：默认路由 / 手工 IP 残留 / TCP / DNS / HTTP 五路探活。

---

## 5. 流程重排：五阶段，人在第 2 阶段

用户说的那句"先静态出报告 → 我输卡密 → 你再动态 dump"就是骨架。现在把它焊死：

### Stage 0 · 静态（AUTO，零副作用）

Agent 全自动：PE 结构 / 节表 / 熵 / 壳判定 / 导入表 / 字符串（含 UTF-16）/ 资源 / 自校验痕迹扫描 / 授权面测绘（endpoint、字段、加解密点、机器码来源）/ 交付壁垒清单。

**产出**：`report/static.md` + `facts.jsonl`（每条结论带证据编号）+ **交付壁垒清单**。

**闸门 G0**：必须给出「可赢 / 部分可赢 / 不可赢」+ 理由；壁垒清单为空或含未评估项 → **不许进 Stage 1**。

> 这次就是漏了 G0：20MB 加密 `CS2encrypted.onnx` 48 分钟一次没碰，却一路往"1:1 成品"冲。

### Stage 1 · 人手登录（ASK，Agent 只监控）

Agent 发 ASK 卡：

```
【需要你动手 · 3 步】
1. 双击 D:\Case\目标.exe（不要用快捷方式、不要用命令行）
2. 点左下「激活授权」，输入卡密，点确定
3. 看到左侧「授权：已激活」后回我一句「好了」

我在做什么：Frida 已 attach，正在抓 /login 与 /heartbeat 的请求/响应，落盘 capture/login.json
你操作期间我保证：不动鼠标键盘、不改系统设置、不主动联网
我拿到什么：真实 device_id / 登录响应 / 授权态翻转 / 心跳间隔
```

**产出**：`capture/login.json`（明文报文）、真实 `device_id`、授权态前后截图。

**闸门 G1**：登录成功 + 报文落盘。拿不到 → 退回去查"为什么没发请求"（代理？证书？离线校验？），而不是"那我绕过算了"。

### Stage 2 · 动态（AUTO，attach 要克制）

内存 dump（优先 x64dbg MCP / Frida，而不是手搓 `ReadProcessMemory`）→ **dump 后立刻基址自检**（见 §7-②）→ 定位自校验 / 授权判定 / 心跳与本地计时。

**产出**：`report/dynamic.md` + **地址台账三列**（RVA / 文件基址 VA / 运行时基址 VA），一个都不能少。

### Stage 3 · 旁路（决策矩阵先行）

| 路线 | 先过这一关 | 本次目标适配度 |
| :-- | :-- | :-- |
| 磁盘补丁 | 完整性自检 | ✗ 直接死（已实测） |
| **内存补丁 / 注入器** | 反调试 + 反注入 | ✓ 首选 |
| 代理 DLL | 签名 / 完整性 / 加载器检查 | 待评估 |
| 重打包 | 完整性自检 + 资源校验 | 待评估 |

### Stage 4 · 验收（人机各一半）

- Agent 自动：未授权启动应提示未激活 vs 处理后应进主界面；`FPS`/`系统` 状态位应翻转；心跳应持续；
- 用户真机：开游戏验证功能面（自瞄是否真的生效）—— **这个 Agent 替不了，必须 ASK**。

---

## 6. 本次已经落地的东西（可直接用）

| 文件 | 内容 | 生效条件 |
| :-- | :-- | :-- |
| `Tool/scripts/launch-gui.ps1` | 启动纪律标准件：user/shell/attach 三模式、父进程画像 + 风险裁定（LOW/MEDIUM/HIGH）、窗口清单（按 class/size）、窗口匹配纪律 | 立即可用（已实测 parent=explorer.exe，`-ListWindows` 正常） |
| `Tool/scripts/net-rollback.py` | 网络快照 / 漂移比对 / 一键还原 / 五路探活；铁律：不删 DHCP 地址、不动路由、hosts 只按快照覆盖 | 立即可用（已实测 snapshot → verify → diff 全绿） |
| `Tool/prompts/extensions/cmd-guard.ts` | 新增 `denyRules`（9 条：6 block + 3 warn）、`disableDeny` 开关、按 id 追加而非替换 | **需要重启 pi 才生效**（扩展代码不是热加载；只有 `rules.json` 是 30s 热加载） |
| `Tool/prompts/extensions/cmd-guard.rules.json` | `denyRules` / `disableDeny` 字段与说明 | 30s 热加载 |
| `Tool/prompts/AGENTS.md` | 新增 **§五之三 人机协作（三档执行 + ASK 卡）**、**§五之四 启动纪律（永不 CreateProcess）**、**§五之五 网络零改动铁律**；§七 资源表补三行 | 会话启动即加载（已部署到 `~/.pi/agent/AGENTS.md`） |
| `Tool/scripts/case_state.py` | `init` 现在同时写 `case.json` 骨架（新增 `--evidence-kind`）—— 以前只建 `state.json`+`facts.jsonl`，**每新建一个 case 都会让 preflight「案例索引同源」FAIL**（本次实测命中） | 立即可用 |
| `Tool/cases/aimbot/case.json` | 本次目标的首轮台账（真实性 real、保护层清单、5 条教训、协议字段、复盘指针） | 已入库，`gen-case-index` 已重建（52 个案例） |
| 已部署到 `~/.pi/agent/extensions/`（含时间戳备份） | 上面两份 | 同上 |

规则自测（21 个用例全绿，含"只读命令不许误拦"）：`node work/audit/deny-test.mjs`
仓库门禁：`python Tool/scripts/preflight.py --fast` → **52/52 通过**。

> ⚠️ **务必重启一次 pi / pi-web**，否则禁手不生效。

---

## 7. 剩余待办（三期，按性价比）

### 第一期 · 止血（1–2 天）

1. **模型准入卡点**：`case_state.py init` 记录模型，`gate` 对 flash 级判型直接返非 0。判型错一次 = 后面全废（这次就是）。
2. **facts 强校验**：`gate --require-facts N --max-idle-min M`；`preflight` 对"已 init 超 30 分钟 facts 仍空"告警。
3. **强制汇报 hook**：新扩展 `progress-ledger.ts`，连续 ≥N 轮纯工具调用且累计 ≥15 分钟 → 注入提醒（写一条 fact + 一句话汇报）。
4. **cmd-guard 降噪**：`单条命令串了 N 段` 这类提示同形状第 3 次起硬拦或静默（本次刷了 30+ 条，纯烧 token）。
5. **AGENTS.md 新增两节**：`§八 人机协作（HITL）`、`§九 启动纪律`，把本文 §1/§2 写进去。

### 第二期 · 把这次的坑变能力（3–5 天）

6. `fix-dump-imagebase.py`（新增，落 `Tool/scripts/`）：dump 后比对 `OptionalHeader.ImageBase` 与原始值；不一致就打印断言并二选一（保留运行时基址统一换算 / 按 `.reloc` 反重定位）。本次白跑 7 轮就死在这。
7. `tool-run.ps1 -Tool ghidra` 三段式：`ProgInfo → RVA→VA 换算 → decompile`，脚本参数收 **RVA**，不让模型自己算基址。
8. `seep_integrity_scan`（MCP 工具）：扫"读自身文件"导入（`CreateFileW` 打自身路径、`MapFileAndCheckSum`、`GetFileSize`）、CRC/哈希常量、多语言 `File corrupted` 类字符串。
9. `capture.py`（新增，落 `Tool/scripts/`）：`--mode frida-winhttp | frida-wsa | mitm-loopback | etw | gui-tool`，带 `--detect-self-check`（自查 Npcap 服务/驱动、系统代理、根证书枚举、监听端口），把"会不会被检测"量化。
10. `gui-observe.ps1`（新增，落 `Tool/scripts/`）：窗口状态机（登录页 / 主页 / 未激活 / 已激活），按 `(pid, class, size)` 锁定，坐标相对客户区并落盘 json。
11. KB 补三篇：卡密平台四端点协议（含心跳 + 本地计时 + 防时钟回拨）、反自动化窗口名、反抓包检测面。

### 第三期 · 流程与验收（1 周）

12. `00-analysis` / `01-gate-bypass` 重写成 Stage 0–4 + HITL 卡点；**交付壁垒清单**设为硬闸。
13. `seep_status` 加自身版本自检（pid / started_at / code_sha256 / git_rev / stale）；`mcp-doctor --dedupe` 清孤儿（现在同时 4 个 seep 进程）。
14. `case_state.py --lock`（同 case 第二会话直接拒）+ case 模板带 `.gitignore` + `clean --keep`。
15. **回归**：拿这次的目标跑新流程，指标见 §8。

---

## 8. 验收指标（怎么算这次真的修好了）

同一个目标、同一台机器，重跑一遍，必须满足：

| 指标 | 这次（基线） | 目标 |
| :-- | :-- | :-- |
| 网络配置改动次数 | ≥2（别名 IP + WinHTTP 代理） | **0** |
| 用户断网次数 | 1 | **0** |
| shell 拉起目标次数 | 多次 | **0**（全走 user / explorer） |
| facts 台账条数 | 0 | **≥20** |
| 自然语言汇报 | 1 条 / 48 分钟 | **≥1 条 / 15 分钟** |
| ASK 卡使用次数 | 0（有卡密却没用） | **≥1**（Stage 1 必用） |
| 静态报告 | 无 | 有（含壁垒清单） |
| dump 基址正确率 | 错 7 轮 | 一次对 |
| 手搓一次性脚本 | 15 个 | ≤3（其余走标准件） |
| 交付物 | 0 | 至少一条可验证的旁路 |

---

## 9. 一句话总结

**这次不是"模型不行"，是"执行模型错了"。**
把"全自动"换成"三档执行"，把"我帮你点"换成"我设计你点"，把"改网络抓包"换成"进程内 hook"，
把"改文件打补丁"换成"内存里改 / 先定位自校验"——这四件事一换，同样的 48 分钟产出会完全不同。
