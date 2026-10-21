# iOS 逆向与 JB 检测对抗

iOS 应用的二进制/签名/运行时观测面：先看 Mach-O 与 entitlements，再看越狱检测面、
Frida 可达性与 Keychain/plist 落盘数据。全部命令用 `<APP>` / `<BIN>` / `<BUNDLE_ID>`
占位，只在自有或书面授权的设备上执行。

## 逐篇索引

| 篇目 | 覆盖 | 关键字段 |
| :--- | :--- | :--- |
| [`techniques/2026-macho-and-entitlements.md`](techniques/2026-macho-and-entitlements.md) | 段/`LC_*` 布局、`codesign -d --entitlements`、`otool -l` | `entitlements[]` `platform_id` |
| [`techniques/2026-jb-detection-surface.md`](techniques/2026-jb-detection-surface.md) | 越狱路径/URL scheme/dyld 镜像/工具残留 | `jb_paths[]` `jb_scheme` |
| [`techniques/2026-frida-on-ios.md`](techniques/2026-frida-on-ios.md) | Frida 18+ attach、`frida-ps -U`、anti-Frida 信号 | `frida_port` `anti_frida_hit` |
| [`techniques/2026-keychain-and-plist.md`](techniques/2026-keychain-and-plist.md) | `keychain-2.db` 四要素、容器 plist 读取 | `kc_items` `plist_keys` |

## 分析链

```text
file/otool -hv → otool -l（段 + LC_*）→ codesign -dv/--entitlements
   → 越狱检测面枚举（路径/scheme/dyld）→ Frida 可达性
   → Keychain/plist 落盘取证 → 结论（字段表）→ 失败判据复核
```

## 判据统一口径

- 每个结论必须落到字段：`entitlements[]`、`platform_id`、`jb_paths[]`、`jb_scheme`、
  `frida_port`、`anti_frida_hit`、`kc_items`、`plist_keys`。
- 字段为空 ≠ 机制不存在：先确认权限、签名、设备是否 rootless，再下"无"的结论。
- 设备侧读取失败优先怀疑沙箱/entitlement，而不是"应用没写"。

## 边界

- 仅限自有 App、授权渗透目标或 CTF 靶机；不讨论重签名分发、绕过 App Store 审核。
- Keychain/plist 里是真实用户秘密：只统计字段与条数，导出前脱敏。
- 越狱设备只用于测试；结论不得回推到未越狱机型。

## 相关

- 越狱检测对抗的现场记录：`../field_journal_seed-009_ios-jailbreak-detect-bypass.md`
- 移动端抓包与 pinning：`../apk-reverse/README.md`（Android 侧对照）
