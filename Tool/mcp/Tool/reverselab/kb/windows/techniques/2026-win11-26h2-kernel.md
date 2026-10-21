---
id: "windows/2026-win11-26h2-kernel"
title: "Windows 11 26H2 内核约束：HVCI、KCET audit、KDP Pool"
title_en: "Windows 11 26H2 Kernel Constraints: HVCI, KCET Audit, KDP Pool"
summary: >
  26H2 默认开启 VBS/HVCI；内核 CET 在 audit 模式产生 ETW 而非直接 bugcheck；
  KDP Pool 取代 Secure Pool，经 Hyper-V SLAT 对驱动数据做只读保护。本文给出补丁/
  驱动/加载约束与 MmProtectMdlSystemAddress 在 HVCI 下的边界。
board: "windows"
category: "techniques"
signals: ["HVCI", "VBS", "KCET", "KDP", "Secure Pool", "MmProtectMdlSystemAddress"]
mcp_tools: ["kb_router", "workspace_write_text"]
keywords: ["Windows 11 26H2", "HVCI", "kernel CET", "KDP Pool", "Secure Pool", "driver"]
difficulty: "advanced"
tags: ["HVCI", "kernel", "CET", "KDP", "windows"]
language: "zh-CN"
last_updated: "2026-10-20"
related_articles: []
---
# Windows 11 26H2 内核约束：HVCI、KCET audit、KDP Pool

> 出处：MS Learn《Windows 11 26H2 新增与变更》（2026）；windows-internals 2026-04
> 《Goodbye Secure Pool》；hack.lu 2026 内核 primitives 议题。
> 仅用于已授权驱动研究/防御验证；不要在生产力机器上关 HVCI 做实验。

## 1. 结论

26H2 把三条约束同时收紧：

| 机制 | 默认 | 对补丁/驱动的含义 |
| :--- | :--- | :--- |
| VBS/HVCI | 默认开 | 内核代码 W^X；未签名/测试签名驱动默认拒载 |
| Kernel CET | audit 起步 | 违规先记 ETW，不立刻 bugcheck；不要误判为“没启用” |
| KDP Pool | 取代 Secure Pool | 受保护驱动数据经 SLAT 只读；写即 fault |

先查状态，再决定能不能改页、能不能 hook、能不能加载。**不要用 25H2 的经验直接
套 26H2。**

## 2. 查 VBS/HVCI

```powershell
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
  Format-List *
Get-ProcessMitigation -System | Select-String "HVCI|CodeIntegrity|VBS"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled
bcdedit /enum "{current}"
```

判据：`SecurityServicesRunning` 含 `2`（HVCI）/`1`（VBS）；注册表
`Enabled=1`；`hypervisorlaunchtype` 为 `Auto`。只有 `msinfo32` 显示“基于虚拟化的
安全性：正在运行”不够，必须看到 HVCI 服务项。

## 3. Kernel CET：audit 模式

26H2 的内核 CET 可能以 **audit** 起步：影子栈不匹配时先写 ETW，而不是立即
`KERNEL_SECURITY_CHECK_FAILURE`。这不等于没有保护。

```powershell
Get-ProcessMitigation -System | Select-String "CET|ShadowStack|Kernel"
logman query providers | findstr /i "CET Shadow"
Get-WinEvent -ListLog *CET*,*Shadow* -ErrorAction SilentlyContinue
```

```powershell
# 抓 audit 事件（provider 名以本机 logman 查询结果为准）
logman create trace KcetTrace -p "Microsoft-Windows-Security-Mitigations" 0xffffffffffffffff 0xff -o kcet.etl -ets
# 触发可疑驱动/补丁
logman stop KcetTrace -ets
tracerpt kcet.etl -o kcet.xml -of XML
Select-String kcet.xml -Pattern "ShadowStack|CET|Audit"
```

判据 `kcet_mode`：

- `off`：无影子栈事件、`Get-ProcessMitigation` 无 Kernel CET 项；
- `audit`：有 ETW 事件但无 bugcheck；仍应视为“会被记录”；
- `enforced`：违规直接 bugcheck（`0x1A`/`0x139` 等，以 dump 为准）。

## 4. KDP Pool 取代 Secure Pool

26H2 起 KDP Pool 取代 Secure Pool：驱动用受保护分配存放密钥、回调指针、
配置等数据；页表经 **Hyper-V SLAT** 标记只读，普通内核写（包括很多
`memcpy`/`MmCopyMemory` 路径）会 fault。

```text
kd> !pool <addr>
kd> !pte <addr>
kd> dt nt!_POOL_HEADER <addr>
```

判据 `kdp_protected`：

- `!pte` 中该页只读，且 `!pool` 标记受保护/KDP 分配；
- 从任意内核上下文写该地址触发 fault/ETW，而不是静默成功；
- 同一驱动用非 KDP 分配的对照页可写。

注意：KDP 不是“所有池都只读”；只保护显式申请的受保护池。不要把普通
`ExAllocatePool2` 页当成 KDP。

## 5. 对补丁/驱动的约束

| 操作 | 26H2 + HVCI 默认 | 判据字段 |
| :--- | :--- | :--- |
| 改已签名驱动 `.text` | 不允许；HVCI W^X + PatchGuard | `page_patch_allowed=false` |
| 改普通数据页 | 可，前提是非 KDP、非镜像只读页 | `page_patch_allowed=partial` |
| 改 KDP 保护数据 | 不允许；SLAT 只读 | `kdp_protected=true` |
| inline hook 代码 | 不允许；代码页只读可执行 | `page_patch_allowed=false` |
| IAT/回调指针 hook | 仅非 KDP 的可写数据页；可能被 CFG/完整性校验抓 | `page_patch_allowed=partial` |
| 加载未签名驱动 | 默认拒绝（`0xC0000428`/577） | `load_policy=blocked` |
| 测试签名驱动 | Secure Boot + HVCI 下通常仍拒绝 | `load_policy=test-signed-blocked` |

`load_policy` 取值建议：`signed-only` / `test-signed-blocked` / `blocked`。
用 `sc.exe` 验证时记录返回码，不要只看“服务创建成功”。

```powershell
sc.exe create kdptest type= kernel binPath= .\kdptest.sys
sc.exe start kdptest
# 预期 HVCI：ERROR_INVALID_IMAGE_HASH (577) 或 0xC0000428
sc.exe delete kdptest
```

## 6. `MmProtectMdlSystemAddress` 的边界

该 API 只改 **MDL 描述的系统地址页**的保护，不是 SLAT 后门：

```c
NTSTATUS st = MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);
if (!NT_SUCCESS(st)) DbgPrint("protect failed: 0x%08X\n", st);
```

HVCI 下边界：

- 不能把页改成 `PAGE_EXECUTE_READWRITE`/W+X；请求会被拒或降级。
- 不能把已签名镜像的代码页改成可写；不能解 KDP 保护页。
- 不能绕过 SLAT：改完仍受 HVCI 的 W^X 与 KDP 只读约束。
- 只对 MDL 锁定范围内的页生效；跨 MDL/未锁定页不会“顺带”改。
- 失败码常见：`STATUS_INVALID_PAGE_PROTECTION`、`STATUS_ACCESS_DENIED`、
  `STATUS_NOT_SUPPORTED`；记录返回码，不要假设成功。

## 7. 判据字段

| 字段 | 取值 | 证据 |
| :--- | :--- | :--- |
| `hvci_on` | `true/false` | `Win32_DeviceGuard.SecurityServicesRunning` 含 2；注册表 Enabled=1 |
| `kcet_mode` | `off/audit/enforced` | `Get-ProcessMitigation` + CET ETW 事件 + 是否 bugcheck |
| `kdp_protected` | `true/false` | `!pte` 只读、`!pool` 受保护、写测试 fault |
| `page_patch_allowed` | `false/partial/true` | 目标页类型（代码/普通数据/KDP）与写测试结果 |
| `load_policy` | `signed-only/test-signed-blocked/blocked` | `sc start` 返回码 + `bcdedit`/HVCI 状态 |

## 8. 失败判据

| 现象 | 判定 | 改走哪条 |
| :--- | :--- | :--- |
| `MmProtectMdlSystemAddress` 返回 `STATUS_ACCESS_DENIED` | 目标是镜像/KDP 页 | 改数据面，或放弃该补丁 |
| 改完页后 `0x109` | PatchGuard 发现代码/关键结构变化 | 停手；不要反复试 |
| 写 KDP 页直接 fault | SLAT 只读生效 | 找受保护数据的合法更新 API |
| KCET audit 无 bugcheck 就继续 | 把 audit 当 off | 先看 ETW，再判断 |
| 未签名驱动 `sc start` 577 | HVCI 拒载 | 换正式签名/测试环境，别关 HVCI |
| 测试签名在 Secure Boot 下仍失败 | 策略叠加 | 记录 `load_policy`，换签名链 |

## 9. 出处与延伸

- MS Learn（2026）《Windows 11 26H2 新增与变更》与 HVCI/KDP 驱动文档，
  `https://learn.microsoft.com/windows/whats-new/`（站内检索 26H2 / KDP）。
- windows-internals（2026-04）《Goodbye Secure Pool》，`https://windows-internals.com/`。
- hack.lu 2026 内核 primitives 议题，`https://hack.lu/`。
- 反调试/内核观测面：`Tool/skill/softseep/references/10-anti-debug.md`。
