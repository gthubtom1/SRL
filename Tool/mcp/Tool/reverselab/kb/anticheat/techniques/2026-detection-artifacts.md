---
id: "anticheat/2026-detection-artifacts"
title: "反作弊留下的痕迹：日志、注册表、服务项"
title_en: "Anti-Cheat Artifacts: Logs, Registry Keys, Service Entries"
board: "anticheat"
category: "techniques"
signals: ["ProgramData", "7045", "Services", "EasyAntiCheat.log", "BEService", "install manifest"]
keywords: ["反作弊取证", "ac_registry", "ac_log_path", "事件日志", "时间线"]
last_updated: "2026-10-20"
---
# 反作弊留下的痕迹：日志、注册表、服务项

## 1. 来源与日期

- Black Hat USA 2025，"Watching the Watchers"：客户端组件的落地痕迹与时间线方法。
- DEF CON 33（2025）：反作弊安装/更新行为与系统日志的议题（标题级引用）。
- BattlEye 客户端分析论文，2025，DOI `10.1145/3733817.3762701`（安装/服务注册路径）。

> 只引用公开标题/DOI。日志文件名随版本变化，本文给"发现方法"而不是死路径清单。

## 2. 入口信号

- 需要回答"这台机器什么时候装过什么反作弊"。
- 兼容性事故要定位"哪个组件在几点做了什么"。
- 已卸载但系统仍有残留（服务项、驱动文件、注册表键）。
- 需要为误报申诉提供证据：日志时间 vs 检测事件时间。

## 3. 命令（可复制）

```powershell
# 1) 先发现目录，不假定固定名字（ProgramData/Program Files/游戏目录都可能）
Get-ChildItem "$env:ProgramData" -Directory -ErrorAction SilentlyContinue |
  Where-Object Name -match 'EasyAnti|BattlEye|Vanguard|Riot|Faceit|BEService'
Get-ChildItem "$env:ProgramFiles","${env:ProgramFiles(x86)}" -Directory -ErrorAction SilentlyContinue |
  Where-Object Name -match 'EasyAnti|BattlEye|Vanguard|Riot'

# 2) 日志文件（限定后缀 + 最近 30 天，避免全盘扫）
Get-ChildItem "$env:ProgramData" -Recurse -Include *.log,*.txt,*.etl -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) -and $_.FullName -match 'EasyAnti|BattlEye|vgc|Riot' } |
  Select-Object FullName,Length,LastWriteTime | Sort-Object LastWriteTime -Descending

# 3) 服务项与安装事件（7045=服务安装，7040=启动类型变更）
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045,7040} -MaxEvents 100 |
  Where-Object Message -match 'EasyAnti|BattlEye|vgk|vgc|BEService' |
  Select-Object TimeCreated,Id,Message

# 4) 注册表：服务键 + 厂商键（只读）
$keys = @(
  'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat',
  'HKLM:\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS',
  'HKLM:\SYSTEM\CurrentControlSet\Services\BEService',
  'HKLM:\SYSTEM\CurrentControlSet\Services\BEDaisy',
  'HKLM:\SYSTEM\CurrentControlSet\Services\vgk',
  'HKLM:\SOFTWARE\WOW6432Node\EasyAntiCheat',
  'HKLM:\SOFTWARE\BattlEye',
  'HKLM:\SOFTWARE\Riot Games'
)
foreach ($k in $keys) {
  if (Test-Path $k) {
    "== $k"
    Get-ItemProperty $k | Select-Object PSPath,Start,ImagePath,DisplayName,InstallDate
  }
}

# 5) 文件落地时间线（安装/更新/卸载）
Get-ChildItem "$env:ProgramData\EasyAntiCheat" -Recurse -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime | Select-Object -First 5 LastWriteTime,FullName
```

导出为可复核的证据包（只读复制，不改原文件）：

```powershell
$out = Join-Path $env:TEMP 'ac-evidence'
New-Item -ItemType Directory -Force $out | Out-Null
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045,7040} -MaxEvents 200 |
  Export-Csv "$out\system-7045-7040.csv" -NoTypeInformation -Encoding UTF8
Get-ChildItem "$env:ProgramData" -Recurse -Include *.log -ErrorAction SilentlyContinue |
  Where-Object FullName -match 'EasyAnti|BattlEye' |
  Copy-Item -Destination $out -ErrorAction SilentlyContinue
Get-FileHash "$out\*" -Algorithm SHA256 | Export-Csv "$out\hashes.csv" -NoTypeInformation
```

## 4. 判据表（字段名）

| 字段 | 取值示例 | 判据 |
| :--- | :--- | :--- |
| `ac_registry[]` | `HKLM\SYSTEM\CurrentControlSet\Services\BEService`、`...\Services\vgk` | 键存在 → 安装过；`ImagePath` 指向的文件不存在 → 残留（键在文件不在） |
| `ac_registry_state` | `installed`、`residual`、`absent` | 由"键 + 文件 + 服务状态"三者组合判定；`residual` 必须同时缺文件或缺服务 |
| `ac_log_path` | `<ProgramData>\EasyAntiCheat\*.log`、游戏目录 `BattlEye\*.log` | 路径存在且 `LastWriteTime` 落在事件窗口内；只有空目录不算 |
| `ac_log_span` | `2026-10-01T12:00Z..2026-10-02T03:00Z` | 首末行时间；与检测事件比对，判断"日志是否覆盖事发时段" |
| `install_event[]` | `7045`（服务安装）、`7040`（启动类型变更） | 事件里的服务名与 `ac_registry[]` 对应；时间即安装/升级时间 |
| `file_timeline[]` | `(LastWriteTime, FullName, SHA256)` | 安装→更新→卸载顺序；哈希用于跨机比对同版本 |
| `uninstall_residue[]` | 服务键、驱动文件、`ProgramData` 目录 | 卸载后仍存在的项；逐项列出，不合并成"有残留" |

判定规则：`ac_registry[]` 有键 + `ac_log_path` 有文件 → 判"当前/曾经安装"；
键在文件不在 → `residual`；两者都无 → 才能写 `absent`，并注明取证时间与权限。

## 5. 失败判据

- 非管理员读 `HKLM\SYSTEM` 或 `ProgramData`：`Access denied` 造成的空结果不是"没有"。
- 只查 `ProgramData`：EAC 的安装目录可能在 `Program Files (x86)`，BattlEye 日志常在
  游戏安装目录下，单点搜索会漏。
- 日志已被轮转/退出时清空：`ac_log_span` 为空要写"日志不可用"，不能写"未发生检测"。
- 事件日志被覆盖（默认大小有限）：7045 只保留最近若干条；早于窗口的安装需靠
  文件时间与注册表 `InstallDate` 佐证。
- 时区混用：事件日志是本地时间，日志正文常是 UTC；比较前统一到 UTC 并在报告注明。
- 把同名目录当成同一产品：`EasyAntiCheat` 与 `EasyAntiCheat_EOS` 是不同服务，
  文件可能共存；按服务名分组统计。
- 卸载残留误判为"仍在运行"：`residual` 与"活跃"必须分开写，活跃要有 Running 服务
  或进程证据。

## 6. 边界

- **只读取证**：不删注册表键、不删目录、不停止服务；证据包只做复制与哈希。
- 仅自有机器/书面授权的事故复盘；不做绕过、不做检测规避。
- 日志里可能含账号 ID、硬件 ID、IP：报告脱敏，原始证据包限定保存位置与期限。
- 相邻篇：服务/驱动/回调语义 → `2026-eac-be-surface.md`；启动驱动与 Secure Boot →
  `2026-vanguard-boot-driver.md`；允许/禁止动作 → `2026-boundary-and-ethics.md`。
