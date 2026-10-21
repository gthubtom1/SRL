# 反作弊客户端取证与兼容性

只做**观测/取证**：枚举反作弊在客户端留下的服务、驱动、回调面、注册表与日志，
用于兼容性排查、误报分析和授权的事故复盘。**不包含**任何卸载、禁用、绕过、
伪造硬件指纹或内存补丁的步骤。

## 逐篇索引

| 篇目 | 覆盖 | 关键字段 |
| :--- | :--- | :--- |
| [`techniques/2026-eac-be-surface.md`](techniques/2026-eac-be-surface.md) | EAC/BattlEye 的服务、驱动、回调可见面（只读枚举） | `ac_service` `kernel_callback` |
| [`techniques/2026-vanguard-boot-driver.md`](techniques/2026-vanguard-boot-driver.md) | Vanguard 启动驱动与 UEFI/Secure Boot 关系（取证视角） | `boot_driver` `secure_boot_state` |
| [`techniques/2026-detection-artifacts.md`](techniques/2026-detection-artifacts.md) | 反作弊留下的日志/注册表/服务项 | `ac_registry[]` `ac_log_path` |
| [`techniques/2026-boundary-and-ethics.md`](techniques/2026-boundary-and-ethics.md) | 范围声明、允许/禁止动作、误报处置 | `scope_ok` |

## 取证链

```text
授权确认（scope_ok）→ 服务/驱动枚举（ac_service）
  → 回调/过滤面（kernel_callback）→ 启动驱动与 Secure Boot（boot_driver / secure_boot_state）
  → 注册表与日志（ac_registry[] / ac_log_path）→ 时间线 → 结论
```

## 判据统一口径

- 每条结论落到字段，并附"取证时刻 + 只读命令 + 原始输出片段"。
- 服务 `Stopped`、驱动未加载、日志为空，都不能单独推出"反作弊不存在"。
- 用户态看不到内核回调：`kernel_callback` 允许取值 `unknown`，不允许编造。

## 边界（总纲）

- 仅限自有机器、书面授权的兼容性测试/事故复盘；不做绕过、不做对抗样本。
- 不卸载/不禁用驱动与服务；不修改注册表；不注入游戏进程。
- 不提供硬件指纹伪造、虚拟机隐藏、DMA/驱动漏洞利用。
- 涉及具体厂商的实现细节，只引用公开发表物（论文/会议议题）。

## 相关

- 检测与完整性校验的原理侧：`../general/techniques/cheating/04-anti-cheat-bypass.md`
  （攻防原理，非本文范围）
- Windows 内核约束（HVCI/CET）：`../windows/techniques/2026-win11-26h2-kernel.md`
- 现场记录模板：`../field_journal__template.md`
