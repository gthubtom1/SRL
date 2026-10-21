---
id: "anticheat/2026-boundary-and-ethics"
title: "反作弊 board 的边界：只做取证/兼容性/误报分析"
title_en: "Scope and Ethics: Forensics, Compatibility, False-Positive Analysis Only"
board: "anticheat"
category: "techniques"
signals: ["scope_ok", "authorization", "false positive", "compatibility", "disclosure"]
keywords: ["反作弊", "边界", "scope_ok", "授权", "误报", "披露"]
last_updated: "2026-10-20"
---
# 反作弊 board 的边界：只做取证/兼容性/误报分析

## 1. 来源与日期

- Black Hat USA 2025，"Watching the Watchers"：把反作弊当作被观测对象时的研究伦理。
- DEF CON 33（2025）：漏洞披露与厂商协作的议题（标题级引用）。
- BattlEye 客户端分析论文，2025，DOI `10.1145/3733817.3762701`：公开可引用的实现描述边界。

> 本文只给范围判据，不给任何操作步骤。标题/日期级引用，不补 DOI。

## 2. 入口信号

- 任务描述里出现"绕过/过检测/隐藏/伪装/改硬件 ID"→ 立即停，按本文判 `scope_ok=false`。
- 目标是他人机器、生产网吧、电竞比赛环境 → 需要书面授权，否则不开展。
- 诉求是"游戏起不来/蓝屏/和杀软冲突/被误封"→ 属于本文允许范围。
- 需要对外发布结论 → 先过披露流程（厂商先知情，再公开）。

## 3. 命令（可复制）

只读的"范围自检"清单（把答案填进 `scope_ok` 判据表，不执行任何修改）：

```text
[ ] 目标机器所有权/授权书：有 / 无
[ ] 是否要求修改反作弊组件（卸载/禁用/打补丁）：是 / 否
[ ] 是否要求伪造硬件/虚拟机/驱动信息：是 / 否
[ ] 是否要求规避检测以进入受保护对局：是 / 否
[ ] 产出物是否只含观测数据/日志/哈希：是 / 否
[ ] 是否已约定数据保留期与脱敏方式：是 / 否
```

允许的只读命令集合（与相邻篇一致，此处仅列白名单）：

```powershell
sc.exe query <SERVICE>
sc.exe qc <SERVICE>
driverquery /v
fltmc filters
Get-CimInstance Win32_SystemDriver
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 50
Get-FileHash <FILE> -Algorithm SHA256
```

## 4. 判据表（字段名）

| 字段 | 取值示例 | 判据 |
| :--- | :--- | :--- |
| `scope_ok` | `true`/`false` | 六项自检里"要求修改/伪造/规避"任一为"是"，或"授权"为"无" → `false`，停止执行 |
| `authorization` | `owned`、`written-consent`、`lab-only`、`none` | 与 `scope_ok` 联动；`none` 只允许做公开资料研究，不碰实机 |
| `intent` | `forensics`、`compatibility`、`false-positive`、`research` | 四种允许意图；出现 `bypass`/`evasion` 即越界 |
| `artifact_type` | `log`、`registry-export`、`hash`、`service-list` | 只允许产出观测类数据；出现 `patch`/`loader`/`spoofer` 即越界 |
| `redaction` | `account-id`、`hwid`、`ip`、`none` | 报告必须标注脱敏项；`none` 只能用于内部原始证据包 |
| `retention` | `7d`、`30d`、`case-close` | 证据保留期；到期删除，避免长期囤积用户数据 |
| `disclosure` | `vendor-first`、`public-after-fix`、`n/a` | 涉及厂商缺陷时先走厂商通道；未修复前不公开可利用细节 |

判定规则：`scope_ok=true` 需要 **授权非 none** 且 **intent ∈ 允许集** 且
**artifact_type 全为观测类**。三者缺一即 `false`。

## 5. 失败判据

- 把"兼容性排查"写成"过检测教程"：只要步骤里出现禁用/卸载/改内存/改 ID，即越界，
  即使动机是"让游戏能跑"。
- 用"研究"当万能通行证：`intent=research` 仍需 `authorization ≠ none` 才能碰实机。
- 只做口头授权：`authorization=written-consent` 要有可追溯的书面记录（邮件/工单），
  否则按 `none` 处理。
- 证据包含完整账号 ID/HWID/IP 就对外分享：违反 `redaction`，必须重做脱敏。
- 把误报申诉材料发到公开论坛并附带日志原文：先走厂商申诉通道，公开前做 `disclosure` 判定。
- 结论写成"某反作弊可被绕过"却没有厂商沟通记录：不得发布。

## 6. 边界

- 本 board 的允许范围：**客户端只读取证、兼容性诊断、误报分析与申诉材料**。
- 明确不做：卸载/禁用反作弊、驱动卸载、内存补丁、硬件指纹伪造、虚拟机隐藏、
  DMA/驱动漏洞利用、把 Frida/注入器用于受保护对局。
- 不提供"检测规避"的成品脚本、不针对具体商用产品给绕过步骤。
- 涉及漏洞：遵循厂商披露政策与当地法律；不在未修复前公开细节。
- 相邻篇：可见面枚举 → `2026-eac-be-surface.md`；启动驱动 → `2026-vanguard-boot-driver.md`；
  痕迹清单 → `2026-detection-artifacts.md`。
