---
id: "pe-reverse/14-ui-verification/01-ui-acceptance"
title: "跨进程 UI 无侵入验收（可判定指标集）"
board: "pe-reverse"
category: "14-ui-verification"
---

# 跨进程 UI 无侵入验收工装（可判定指标集）

> 来源：softseep 主控 §四 | 加载时机：需要 UI 可判定验收时


显示层交付的验收**必须机器可判定**，严禁用截图肉眼确认。以下工装均为 PowerShell + P/Invoke，无需编译、无侵入、可重复。

### 1. 全量控件布局 dump（`abdump.ps1` 范式）

```
EnumWindows -> GetWindowThreadProcessId   (按 PID 过滤)
  EnumChildWindows
    GetDlgCtrlID(c)            # 控件 ID
    GetClassNameW(c)           # 真实窗口类（不可静态假设！）
    GetWindowRect(c)           # 尺寸，判断能否容纳多行
    GetWindowLongPtr(c, -16)   # GWL_STYLE，查 ES_MULTILINE 等位
    SendMessageW(c, 0x000E)    # WM_GETTEXTLENGTH
    SendMessageW(c, 0x000D)    # WM_GETTEXT 读回文本
```

**核心技巧：文本一律逐字符打印 UTF-16 码点**，把“有没有换行符”变成可判定的十六进制事实。

| 消息 | 值 | 用途 |
| :--- | :--- | :--- |
| `WM_SETTEXT` | `0x000C` | 回写文本（探针实验用） |
| `WM_GETTEXT` | `0x000D` | 读控件文本 |
| `WM_GETTEXTLENGTH` | `0x000E` | 取长度（分配缓冲用） |
| `WM_GETFONT` | `0x0031` | 取字体，估算行高 |
| `WM_COMMAND` | `0x0111` | 驱动菜单 / 按钮命令 |
| `EM_GETLINECOUNT` | `0x00BA` | **直接询问控件渲染了几行** |

### 2. Edit 控件行数判定（`linetest.ps1` 范式）

`EM_GETLINECOUNT (0x00BA)` 一步终结“看起来是一行”的争论：

```powershell
SendMessageW(c, 0x00BA, 0, 0)   # 返回渲染行数
```

标准探针实验（写入 LF vs CRLF 对比）：

| 探针字节 | `EM_GETLINECOUNT` | 结论 |
| :--- | :--- | :--- |
| `L1 **0A** L2 **0A** L3` | **1** | **纯 LF 在 Win32 Edit 中根本不算换行** |
| `L1 **0D 0A** L2 **0D 0A** L3` | **3** | **只有 CRLF 才换行** |

### 3. 对话框自动触发（`openabout.ps1` 范式）

先用 `GetMenu` / `GetMenuItemCount` / `GetMenuItemID` / `GetSubMenu` 递归枚举菜单命令 ID：

```powershell
GetMenu(hMain) -> GetSubMenu(h, i) -> GetMenuItemID(m, pos) -> GetMenuStringW(...)
PostMessageW(hMain, 0x0111 /* WM_COMMAND */, (IntPtr)147, IntPtr.Zero)   # “关于”命令 ID
```

全自动回归链：**启动 -> 注入 -> WM_COMMAND 触发对话框 -> WM_GETTEXT 读回 -> EM_GETLINECOUNT 验收**。

---

---

## 失败判据

| 现象 | 判定 | 改走哪条 |
| :--- | :--- | :--- |
| 截图看起来是两行，但 `EM_GETLINECOUNT=1` | 只有 LF，Win32 Edit 不认 | 写入 `
`，或运行时 `NormalizeCrlf()` |
| 控件类名与 ID 名不一致 | 静态假设错误 | 用 `GetClassNameW` 运行时实测，再走白名单 |
| `WM_GETTEXT` 读回空 | 句柄/权限/跨会话错误 | 确认 PID、窗口句柄、UIAccess/完整性级别 |
| 关于框打不开 | 菜单 ID/命令错误 | 用 `GetMenu/GetSubMenu/GetMenuItemID` 递归枚举后再 `WM_COMMAND` |
| 改了文案但重启回退 | 改的是显示层不是状态源 | 回到状态对象/配置/网络解析点 |

**边界**：本工装只做验收，不替代补丁；需要管理员/同会话权限。跨会话/高完整性进程可能读不到控件。
