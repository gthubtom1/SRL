---
id: "ios/2026-macho-and-entitlements"
title: "iOS Mach-O 段/LC_* 与 entitlements 取证"
title_en: "iOS Mach-O Segments, LC_* Commands and Entitlements"
board: "ios"
category: "techniques"
signals: ["Mach-O", "LC_SEGMENT_64", "LC_CODE_SIGNATURE", "entitlements", "codesign", "otool"]
keywords: ["iOS", "Mach-O", "entitlements", "platform_id", "get-task-allow"]
last_updated: "2026-10-20"
---
# iOS Mach-O 段/LC_* 与 entitlements 取证

## 1. 来源与日期

- OWASP MASTG-TECH-0152（2025/26 修订版）：entitlements 与签名信息的审查流程。
- juliangrtz.me，2025-10：Mach-O 加载命令逐条解析笔记（`LC_*` 语义与偏移）。
- K. Moftah，2025：Mach-O 结构一篇 + iOS 检测面一篇（标题级引用，不附 DOI）。

> 引用只到"标题/日期"级。凡是原文没给的 DOI/页码，这里一律不补。

## 2. 入口信号

出现下列任一情况，先做本节再看业务逻辑：

- 拿到的是 `.app` 目录而不是单个二进制（fat/thin、有无 `Frameworks/`）。
- `codesign -dv` 输出里 `Signature=adhoc`、`TeamIdentifier` 缺失。
- App 有"越狱/调试器/重打包"提示，但静态字符串搜不到检测代码。
- 需要判断包是不是模拟器构建、企业签、TestFlight 或换皮包。

## 3. 命令（可复制）

```bash
# 0) 基本类型：fat 还是 thin，含哪些架构
file <APP>/<BIN>
lipo -info <APP>/<BIN>

# 1) Mach-O 头 + 段表
otool -hv <APP>/<BIN>
otool -l <APP>/<BIN> | grep -E "cmd LC_|segname|sectname|vmaddr|vmsize|fileoff|filesize"

# 2) 依赖与 rpath（注入/替换的第一现场）
otool -L <APP>/<BIN>
otool -l <APP>/<BIN> | grep -A3 LC_RPATH

# 3) 签名与 entitlements
codesign -dv --verbose=4 <APP>
codesign -d --entitlements :- <APP> 2>/dev/null > /tmp/ent.plist
plutil -p /tmp/ent.plist

# 4) 只看平台字段（LC_BUILD_VERSION）
otool -l <APP>/<BIN> | grep -A6 LC_BUILD_VERSION

# 5) 描述文件（非 App Store 包才有）
security cms -D -i <APP>/embedded.mobileprovision | plutil -p -
```

字段提取（不依赖 GUI）：

```bash
python3 - <<'PY'
import plistlib, subprocess, sys
app = sys.argv[1] if len(sys.argv) > 1 else "<APP>"
raw = subprocess.run(["codesign","-d","--entitlements",":-",app],
                     capture_output=True).stdout
d = plistlib.loads(raw) if raw.strip() else {}
print("entitlements[]:", sorted(d))
print("get-task-allow:", d.get("get-task-allow"))
print("keychain-access-groups:", d.get("keychain-access-groups"))
print("platform-application:", d.get("platform-application"))
PY
```

## 4. 判据表（字段名）

| 字段 | 取值示例 | 判据 |
| :--- | :--- | :--- |
| `entitlements[]` | `application-identifier`、`get-task-allow`、`keychain-access-groups`、`com.apple.developer.team-identifier`、`platform-application` | 非空且含 `application-identifier` → 正常签名链；只有 `get-task-allow=true` → 开发/调试签名；含 `platform-application` → 系统级权限，第三方包出现即为异常 |
| `platform_id` | `1`=macOS、`2`=iOS、`3`=tvOS、`6`=macCatalyst、`7`=iOS Simulator | 取自 `LC_BUILD_VERSION.platform`；与目标设备不符（如真机装模拟器包）说明换皮或构建流水线串联错误 |
| `cryptid` | `0`/`1` | 取自 `LC_ENCRYPTION_INFO_64.cryptid`；`1` = App Store 加密二进制，静态字符串/指令不可信，需先解密（授权设备 dump） |
| `segments[]` | `__TEXT`、`__DATA`、`__DATA_CONST`、`__LINKEDIT` | 缺 `__LINKEDIT` 或 `LC_CODE_SIGNATURE` → 被裁剪/重打包；`__DATA` 权限含 `X` → JIT/自改代码嫌疑 |
| `dylibs[]` | `/usr/lib/libSystem.B.dylib`、`@rpath/Foo.framework/Foo` | 出现非系统路径的绝对路径或 `/tmp/`、`/var/mobile/` 加载项 → 注入/劫持 |
| `rpaths[]` | `@executable_path/Frameworks` | 含可写目录（`/var/mobile/Containers/...`）→ dyld 劫持面 |

解读顺序：`platform_id` → `cryptid` → `entitlements[]` → `dylibs[]`。先排除"包本身
不是这个平台/是加密包"，再谈权限与注入。

## 5. 失败判据

- `codesign -d --entitlements` 无输出：ad-hoc 签名或 entitlement 被剥离。**不能**据此
  判定"没有权限校验"——运行时可能用 `SecTaskCopyValueForEntitlement` 自查。
- `codesign -v` 报 `invalid signature`：二进制被改过。此时 `otool -l` 的偏移仍可读，
  但任何哈希/完整性结论都作废。
- `cryptid=1`：字符串扫描出"license/expire"也可能是加密残留，必须解密后复核。
- 只有 `arm64e` 切片且设备是 `arm64`：`otool` 能读，运行必失败；不要拿静态结论解释崩溃。
- fat 包里多个切片结论不一致（某切片多一个 `LC_LOAD_DYLIB`）：以实际加载的切片为准，
  用 `lipo -thin` 后再比对。
- `platform_id=7`（模拟器）却要分析真机越狱检测：路径与 `dyld` 行为完全不同，结论不可迁移。

## 6. 边界

- 仅分析自有/授权 App；不提供重签名后分发、企业证书滥用、绕过公证的步骤。
- 解密（`cryptid=1`）只在授权测试设备上做，产物不外传。
- entitlements 属签名元数据，可公开讨论；`embedded.mobileprovision` 含证书与
  `ProvisionedDevices`，引用时必须脱敏。
- 本节不覆盖 Swift 运行时/IL2CPP 内部结构，见 `2026-jb-detection-surface.md` 与
  `../managed/2026-dotnet-license.md` 的 Unity 段落。
