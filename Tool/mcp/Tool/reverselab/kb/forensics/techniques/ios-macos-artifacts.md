# iOS/macOS 制品：IPA、Mach-O、Keychain、plist

> **入口信号**：`*.ipa`/`.app`、Mach-O、`keychain-2.db`、`Info.plist`、应用 SQLite。
> **不适用**：Android APK/DEX/SO（走 `apkseep`）；未授权设备；绕过授权/反作弊。

## 1. 包与签名

```bash
unzip -q app.ipa -d ipa/
plutil -p ipa/Payload/App.app/Info.plist
codesign -d --entitlements :- ipa/Payload/App.app
codesign -dv --verbose=4 ipa/Payload/App.app
unzip -p app.ipa 'Payload/*.app/embedded.mobileprovision' | strings | head
```

关注：Bundle ID、URL Scheme、ATS、`UIBackgroundModes`、`NS*UsageDescription`、`get-task-allow`、`keychain-access-groups`、Team ID。

## 2. Mach-O

```bash
file AppBinary
otool -hv AppBinary
otool -l AppBinary | grep -A6 LC_ENCRYPTION_INFO
otool -L AppBinary
```

- `cryptid=1` = App Store 加密；未脱壳时 `__TEXT` 符号/字符串不可信。
- 记录 `LC_UUID`、架构切片、依赖库、`@rpath`；与 dSYM/崩溃日志对齐。

## 3. Keychain / plist / SQLite

```bash
security dump-keychain -d login.keychain-db | head -100     # macOS 授权账户
plutil -p Library/Preferences/com.example.app.plist
sqlite3 app.db.copy 'PRAGMA integrity_check; .tables'
```

- iOS Keychain 在 `keychain-2.db`，受保护类密钥；无授权测试机只写结构/元数据，不伪造明文。
- plist 二进制/XML 都可能；`NSKeyedArchiver` 先解归档。
- SQLite 先复制 `-wal/-shm/-journal`；用 `mode=ro&immutable=1`；`.recover` 的行标来源。

## 4. 确认/失败判据

确认：

- 包目录/签名/entitlements/框架/数据文件清单齐全。
- 二进制架构/UUID/加密状态/依赖可列。
- 数据文件结构与写入进程/API 能对应。

失败：

- `cryptid=1` 未脱壳 → 停静态结论。
- 签名/Team ID 不一致 → 查重签/损坏。
- Keychain 打不开/表异常 → 只做文件级元数据。
- SQLite 缺 WAL/完整性失败 → 标“可能不完整”。

## 5. 边界

- 只分析自有/授权 IPA、测试机、备份。
- 不导出/传播 Keychain 明文、cookie、token。
- 越狱检测绕过只用于验证检测点，不用于规避授权。
- 相关：`Tool/skill/forensics-mobile/references/ios-macos-artifacts.md`、`game-client-il2cpp.md`。
