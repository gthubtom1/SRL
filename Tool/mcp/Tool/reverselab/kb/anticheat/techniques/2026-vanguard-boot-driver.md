---
id: "anticheat/2026-vanguard-boot-driver"
title: "Vanguard 启动驱动与 UEFI/Secure Boot：取证视角"
title_en: "Vanguard Boot Driver and UEFI/Secure Boot: A Forensic View"
board: "anticheat"
category: "techniques"
signals: ["vgk.sys", "vgc", "Start=0", "Secure Boot", "TPM", "HVCI"]
keywords: ["Vanguard", "vgk", "boot_driver", "secure_boot_state", "UEFI", "ELAM"]
last_updated: "2026-10-20"
---
# Vanguard 启动驱动与 UEFI/Secure Boot：取证视角

## 1. 来源与日期

- Black Hat USA 2025，"Watching the Watchers"：反作弊驱动与平台启动链的观测方法。
- DEF CON 33（2025）：UEFI/Secure Boot 与内核级组件的议题（标题级引用）。
- BattlEye 客户端分析论文，2025，DOI `10.1145/3733817.3762701`（同类启动型驱动的
  加载时序对照）。

> 只引用公开标题/DOI。Vanguard 的私有接口与更新策略不在本文推测范围。

## 2. 入口信号

- 机器开机即蓝屏/卡在启动，怀疑与 `vgk` 启动驱动有关。
- 需要确认"Secure Boot 是否开启、Vanguard 是否以 Boot 型驱动加载"。
- 兼容性报告需要写清"本机 UEFI 状态 + 反作弊启动级别"。
- 装/卸 Vanguard 后出现启动项残留（服务还在、文件已删）。

## 3. 命令（可复制）

```powershell
# 1) 服务与启动类型（Start=0 即 Boot 型）
sc.exe qc vgk
sc.exe query vgk
reg query "HKLM\SYSTEM\CurrentControlSet\Services\vgk" /v Start
reg query "HKLM\SYSTEM\CurrentControlSet\Services\vgk" /v ImagePath

# 2) 全部 Boot 型驱动（含 ELAM）
Get-CimInstance Win32_SystemDriver | Where-Object StartMode -eq 'Boot' |
  Select-Object Name,State,PathName

# 3) Secure Boot / UEFI
Confirm-SecureBootUEFI
Get-SecureBootUEFI -Name SetupMode
Get-SecureBootUEFI -Name PK -ErrorAction SilentlyContinue | Select-Object -First 1
msinfo32 /report "$env:TEMP\msinfo.txt"; Select-String -Path "$env:TEMP\msinfo.txt" -Pattern 'Secure Boot|BIOS Mode|TPM'

# 4) TPM / VBS / HVCI
Get-Tpm | Select-Object TpmPresent,TpmReady,ManufacturerVersion
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus,SecurityServicesRunning,SecurityServicesConfigured
bcdedit /enum "{current}" | Select-String -Pattern 'hypervisorlaunchtype|testsigning|nointegritychecks'

# 5) 过滤/回调面（与 vgk 关联的设备与高度）
fltmc filters
Get-CimInstance Win32_PnPEntity | Where-Object { $_.Name -match 'vgk|vgc' } |
  Select-Object Name,DeviceID,Status
```

时间线（判断"是不是这次启动才加载"）：

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 50 |
  Where-Object Message -match 'vgk|vgc|Vanguard' |
  Select-Object TimeCreated,Message
```

## 4. 判据表（字段名）

| 字段 | 取值示例 | 判据 |
| :--- | :--- | :--- |
| `boot_driver` | `vgk`(Start=0/Boot)、`EasyAntiCheat`(System)、`BEDaisy`(Demand) | `Start=0` + `ImagePath` 指向 `System32\drivers\vgk.sys` → Boot 型；`Start=0` 但文件缺失 → 卸载残留，可解释开机失败 |
| `boot_driver_state` | `Running`、`Stopped`、`NotFound` | 与 `Start` 交叉：Boot 型却 `Stopped` → 加载失败（签名/HVCI/冲突） |
| `secure_boot_state` | `On`、`Off`、`Unsupported` | `Confirm-SecureBootUEFI` 返回值；`Unsupported` 表示旧 BIOS/虚拟机，不是"关闭" |
| `uefi_mode` | `UEFI`、`Legacy` | `msinfo32` 的"BIOS 模式"；Legacy 下 Secure Boot 必然 Unsupported |
| `tpm_state` | `Present/Ready`、`Absent` | Win11 + Vanguard 场景常见 TPM 2.0 要求；`Absent` 会影响兼容性结论 |
| `vbs_hvci` | `VBS=2`、`HVCI in SecurityServicesRunning` | `VirtualizationBasedSecurityStatus=2` 且 `SecurityServicesRunning` 含 `2` → HVCI 开 |
| `elam_present` | `true`/`false` | Boot 型驱动列表中含厂商 ELAM；缺失而服务在 → 启动链被改过/被裁剪 |
| `ac_registry[]` | `HKLM\SYSTEM\CurrentControlSet\Services\vgk` | 关键键存在且 `Start/ImagePath` 可读；键在文件不在 = 残留 |

判定规则：`boot_driver=vgk` 且 `secure_boot_state=On` 且 `vbs_hvci` 含 HVCI
→ 典型"完整启动链"配置。任一缺失都要在报告里单列，不要合并成"已开启"。

## 5. 失败判据

- `Confirm-SecureBootUEFI` 抛 `Cmdlet not supported on this platform`：Legacy BIOS 或
  非 Windows 客户端 SKU。此时 `secure_boot_state` 记 `Unsupported`，不是 `Off`。
- 虚拟机/云主机：多数默认不开 Secure Boot，`vgk` 可能拒绝加载；不能拿 VM 结论推物理机。
- `sc qc vgk` 返回 `FAILED 1060`（服务不存在）：可能是产品未安装、或已改用新版服务名；
  先枚举 `Get-Service | ? Name -match 'vgk|vgc|Vanguard'` 再下结论。
- 卸载后 `Start=0` 仍在：孤儿服务项可导致开机加载失败；报告写"残留"并附注册表路径，
  不要手工删除（属于厂商卸载流程）。
- 只看 `msinfo32` 的"Secure Boot 状态"：不同版本措辞不一（"打开"/"不支持"），
  必须以 `Confirm-SecureBootUEFI` 的布尔值为准。
- 把 `testsigning=On` 当成"反作弊必然拒绝"：拒绝与否取决于产品策略与 HVCI 状态，
  需要实测日志，不能推断。

## 6. 边界

- **只读取证**：不 `sc delete vgk`、不改 `Start`、不关 Secure Boot/HVCI、不删驱动文件。
- 不讨论"如何让 Vanguard 不加载""如何在 VM 里隐藏"，不提供启动链绕过。
- 需要处置（卸载/回滚）时，只指引厂商官方卸载流程与系统还原点。
- 相邻篇：EAC/BE 服务与回调 → `2026-eac-be-surface.md`；日志/注册表清单 →
  `2026-detection-artifacts.md`；范围与伦理 → `2026-boundary-and-ethics.md`。
