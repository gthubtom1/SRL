---
id: "anticheat/2026-eac-be-surface"
title: "EAC / BattlEye 客户端可见面：服务、驱动、回调（只读枚举）"
title_en: "Anti-Cheat Client Surface: Services, Drivers, Callbacks (Read-only)"
board: "anticheat"
category: "techniques"
signals: ["EasyAntiCheat", "EasyAntiCheat_EOS", "BEService", "BEDaisy", "ObRegisterCallbacks", "minifilter"]
keywords: ["EasyAntiCheat", "BattlEye", "ac_service", "kernel_callback", "driverquery", "fltmc"]
last_updated: "2026-10-20"
---
# EAC / BattlEye 客户端可见面：服务、驱动、回调（只读枚举）

## 1. 来源与日期

- BattlEye 客户端分析论文，2025，DOI `10.1145/3733817.3762701`（服务/驱动加载与
  用户态-内核分工的公开描述）。
- Black Hat USA 2025，"Watching the Watchers"（反作弊组件的可观测面与取证思路）。
- DEF CON 33（2025）相关议题：反作弊驱动与系统完整性（标题级引用）。

> 只引用公开标题/DOI；厂商未公开的内部协议不在此推测。

## 2. 入口信号

- 游戏启动失败、蓝屏、或与杀软/虚拟机共存时崩溃，需要定位是哪个组件在拦。
- 需要写兼容性报告："本机装了哪些反作弊、以什么权限运行"。
- 需要做误报分析："某检测项是不是反作弊引入的"。
- 只允许只读命令：`sc query`、`driverquery`、`fltmc`、`Get-CimInstance`。

## 3. 命令（可复制）

```powershell
# 1) 服务面（每个游戏一个服务名，如 EasyAntiCheat_EOS）
Get-Service | Where-Object { $_.Name -match 'EasyAntiCheat|BEService|BattlEye' } |
  Select-Object Name,Status,StartType

# 2) 驱动面：路径、启动类型、状态
Get-CimInstance Win32_SystemDriver |
  Where-Object { $_.Name -match 'EasyAnti|BEDaisy|BattlEye|BEService' } |
  Select-Object Name,State,StartMode,PathName

driverquery /v /fo csv | Select-String -Pattern 'EasyAnti|BEDaisy|BattlEye'

# 3) 服务配置（二进制路径、依赖）
sc.exe qc EasyAntiCheat
sc.exe qc EasyAntiCheat_EOS
sc.exe qc BEService
sc.exe queryex type= driver state= all | Select-String -Pattern 'EasyAnti|BEDaisy'

# 4) 文件系统过滤面（minifilter 高度值）
fltmc filters
fltmc instances -v C:

# 5) 进程面
Get-Process | Where-Object { $_.Name -match 'EasyAntiCheat|BEService|BattlEye|start_protected_game' } |
  Select-Object Name,Id,Path,StartTime
```

内核回调面（用户态没有官方枚举 API，只做**间接**取证）：

```powershell
# 驱动对象/分发函数：需要内核调试器（本地 KD 或 VM 双机调试）
# 0: kd> lm m EasyAntiCheat
# 0: kd> !drvobj \Driver\EasyAntiCheat 7
# 0: kd> !devobj <DeviceObject 地址>

# 无调试器时，用 ETW 的驱动加载/进程创建事件做时间线
wevtutil qe System /q:"*[System[(EventID=7045)]]" /c:20 /f:text
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 20 |
  Select-Object TimeCreated,Message
```

## 4. 判据表（字段名）

| 字段 | 取值示例 | 判据 |
| :--- | :--- | :--- |
| `ac_service` | `EasyAntiCheat`(Running/Auto)、`EasyAntiCheat_EOS`、`BEService` | 服务存在且 `Status=Running` → 该产品在当前会话活跃；`Stopped` + 驱动已加载 → 只完成一半，不能判"未启用" |
| `ac_driver` | `EasyAntiCheat.sys`、`EasyAntiCheat_EOSSys`、`BEDaisy.sys` | `PathName` 必须在 `System32\drivers\` 下；路径异常（临时目录/用户目录）才是可疑点 |
| `driver_start` | `Boot`、`System`、`Auto`、`Demand`、`Disabled` | `Boot`/`System` 表示先于用户态加载；`Disabled` 但服务 Running → 配置不一致，需记录 |
| `kernel_callback` | `ObRegisterCallbacks:process`、`PsSetCreateProcessNotifyRoutineEx`、`minifilter`、`unknown` | 只填有证据的类型；`!drvobj` 看到 `MajorFunction` 被替换或 `fltmc` 列出该驱动 → 记 `minifilter`；无调试器则填 `unknown` |
| `minifilter_altitude` | 数值字符串（`fltmc filters` 的 Altitude 列） | 高度值决定过滤顺序；与杀软高度接近时优先怀疑冲突导致的崩溃 |
| `ac_process[]` | `EasyAntiCheat.exe`、`BEService.exe`、`start_protected_game.exe` | 进程存在说明用户态组件在跑；只有服务没有进程 → 组件可能按需启动 |
| `evidence_time` | ISO8601 | 取证时刻；服务/驱动状态是瞬时值，必须带时间 |

判定规则：`ac_service` 非空 **且** `ac_driver` 已加载 → 判"该反作弊在此机器生效"。
二者只有一个，写"部分生效"，不要写成"未安装"。

## 5. 失败判据

- 非管理员执行 `sc query type= driver`：返回 `Access is denied`，空结果**不是**"没有驱动"。
- 游戏未运行：反作弊常按需启动，服务 `Stopped` 是预期；必须"启动游戏后再采一次"。
- 只查 `EasyAntiCheat` 一个名字：EOS 版本用 `EasyAntiCheat_EOS`，BattlEye 服务名是
  `BEService` 而驱动是 `BEDaisy`，名字不匹配会漏。
- `fltmc filters` 里没有该驱动：它不一定是 minifilter（可能用 OB 回调/通知例程），
  不能据此判"没有内核组件"。
- 认为能枚举全部回调：对象回调的 pre/post 没有用户态枚举接口；
  没有内核调试器就只能填 `kernel_callback=unknown`。
- 把驱动签名/哈希不一致直接判"被篡改"：先核对版本与厂商更新，Windows 更新也会换文件。

## 6. 边界

- **只读**：不 `sc stop`/`sc delete`、不 `fltmc unload`、不结束反作弊进程、不改注册表。
- 仅用于自有机器、书面授权的兼容性测试与事故复盘；不做绕过、不做对抗样本。
- 不逆向厂商未公开协议、不发布驱动漏洞细节；引用只到公开论文/议题标题。
- 需要"检测原理"的攻防视角时，见 `2026-boundary-and-ethics.md` 的范围说明，
  以及 `../general/techniques/cheating/04-anti-cheat-bypass.md`（原理篇，非本 board 范围）。
