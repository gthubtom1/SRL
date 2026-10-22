# iOS / macOS 制品：IPA、Mach-O、Keychain、plist 与数据库

> **范围**：iOS `.ipa`/`.app`、Mach-O/Fat 二进制、`embedded.mobileprovision`、`keychain-2.db`、`Info.plist`/偏好 plist、应用 SQLite，以及 macOS 上的同类制品。
> 路由：Android APK/DEX/SO 由 `apkseep` 承担；设备/账号按 `scope` 清单执行；授权与隐私边界按 `evidence-chain.md` 记录。
> 目标：说明“这个包能碰哪些数据与能力、二进制与数据文件如何对应、证据是否可信”。

## 1. IPA 解包与包结构

```bash
unzip -q app.ipa -d ipa/
find ipa/Payload -maxdepth 3 -type d | sort
plutil -p ipa/Payload/App.app/Info.plist
plutil -p ipa/Payload/App.app/Info.plist | grep -E 'CFBundleIdentifier|MinimumOSVersion|UIBackgroundModes|NSAppTransportSecurity'
```

判据：

- `Payload/*.app` 是最外层；`Frameworks/`、`PlugIns/`、`Watch/`、`AppClips/` 是扩展面。
- `Info.plist` 的 Bundle ID、URL Scheme、ATS 例外、后台模式、权限用途描述（`NS*UsageDescription`）是行为入口。
- `Assets.car`、`*.momd`、`*.sqlite`、`*.plist`、`*.bundle` 是数据/资源面；记录清单与大小。

ZIP 时间戳不可靠（本地时间、2 秒精度）；不要用 IPA 内 entry 时间当“安装/运行时间”。

## 2. 签名、权限与描述文件

```bash
codesign -d --entitlements :- ipa/Payload/App.app
codesign -dv --verbose=4 ipa/Payload/App.app
unzip -p app.ipa 'Payload/*.app/embedded.mobileprovision' > out/profile.mobileprovision
strings out/profile.mobileprovision | grep -E 'TeamIdentifier|application-identifier|get-task-allow|aps-environment' | head
```

- `codesign -d --entitlements` 给出 `application-identifier`、`keychain-access-groups`、`get-task-allow`、`aps-environment`。
- `get-task-allow=true` 说明可调试；这与“可被 Frida attach”相关，但不是漏洞结论。
- 描述文件过期/团队 ID 与二进制签名不一致，是“包被重签/篡改”的线索；需要哈希/证书链交叉。

判据：能回答“谁签的、有哪些 entitlement、是否能调试、是否带推送/钥匙串组”。

## 3. Mach-O 二进制

```bash
file Payload/App.app/AppBinary
otool -hv Payload/App.app/AppBinary
otool -l Payload/App.app/AppBinary | grep -A6 LC_ENCRYPTION_INFO
otool -L Payload/App.app/AppBinary
nm -m Payload/App.app/AppBinary | head -50
```

关键字段：

| 字段 | 用途 | 注意 |
|---|---|---|
| `LC_UUID` | 二进制唯一标识 | 与 dSYM/崩溃日志对齐 |
| `LC_BUILD_VERSION` | 最低系统/SDK | 判断 API 可用性 |
| `LC_ENCRYPTION_INFO.cryptid` | 1=App Store 加密 | 未脱壳时 `__TEXT` 不可信 |
| `LC_LOAD_DYLIB`/`@rpath` | 依赖库 | 注入/替换面 |
| 架构切片 | arm64/arm64e/x86_64 | Fat 二进制要逐片分析 |

判据：能说明“加载了哪些库、调用了哪些敏感 API、与哪个数据文件/网络端点对应”。`cryptid=1` 时只能写包结构/签名，不能写“没有某逻辑”。

## 4. Keychain 与 plist

```bash
# macOS 授权账户；iOS 需要授权测试机/备份
security dump-keychain -d login.keychain-db | head -100

# plist：二进制/XML 都可能；NSKeyedArchiver 先解归档
plutil -p Library/Preferences/com.example.app.plist
python - <<'PY'
import plistlib
with open('Info.plist','rb') as f:
    print(plistlib.load(f))
PY
```

- iOS Keychain 在 `keychain-2.db`（或 `keychain-2-debug.db`），受保护类密钥保护；无授权测试机只做结构与元数据，不伪造明文。
- 关注 `genp`/`inet`/`cert` 表、`agrp`（access group）、`cdat`/`mdat`/`vwrt` 时间；不要导出/传播明文 secret。
- plist 的 `NSKeyedArchiver` 需要 `plistlib` 解归档后再看类名/字段；直接 `plutil -p` 可能只显示 `$objects`。

判据：能说明“数据由哪个进程/API 写入、存在哪个文件、保留多久（数据保护等级/备份策略）”。

## 5. SQLite：结构、WAL 与已删记录

```bash
cp app.db app.db.copy
cp app.db-wal app.db.copy-wal 2>/dev/null || true
cp app.db-shm app.db.copy-shm 2>/dev/null || true
sqlite3 app.db.copy 'PRAGMA integrity_check;'
sqlite3 app.db.copy '.tables'
sqlite3 app.db.copy '.schema'
sqlite3 app.db.copy '.recover' | head -50
```

- 先复制 `-wal/-shm/-journal` 三件套；直接打开原库会改 WAL/建 shm，证据哈希失效。
- `PRAGMA integrity_check` 通过只说明页结构没坏，不说明内容未被篡改。
- `.recover` 能捞已删记录，但可能混入旧事务；要给行来源/时间字段，不把恢复行当“当前状态”。
- 只读连接：`file:app.db?mode=ro&immutable=1`（`fs-timeline.py` 对 History 就是这么做的）。

## 6. 动态侧：Frida / lldb（仅授权测试机）

```bash
frida-ps -Uai
frida -U -f com.example.app -l hook.js --no-pause
frida-trace -U -f com.example.app -m "-[NSURLSession dataTaskWithRequest:*]"
```

- 先确认 `frida-server` 架构/版本与 iOS 匹配；attach 失败先查签名、端口、看门狗重启。
- 只读优先：`Interceptor.attach` 记录参数/返回值；写内存/改返回值只用于验证检测点，必须记录基线/副作用。
- macOS 可用 `lldb`/Instruments/`log stream` 作为降级；越狱检测点见下。

判据：把“二进制函数 → 运行时参数/返回值 → 落盘文件/网络请求”连成一条链；缺一环标 `inferred`。

## 7. 越狱/调试检测的取证视角

常见检测面：

- 路径：`/Applications/Cydia.app`、`/var/jb`、`/bin/bash`、`/usr/sbin/sshd`。
- URL Scheme：`cydia://`、`sileo://`、`zbra://`。
- API：`fork`/`posix_spawn`、`sysctl`、`dyld` 镜像名、沙盒外可写、`DYLD_INSERT_LIBRARIES`。
- 完整性：`codesign`/`CSCommon`、`__RESTRICT` 段、`get-task-allow`。

记录三件事：检测点在哪（类/方法/字符串/路径）、设备状态（越狱/注入）、检测结果（真假及 UI/网络行为）。检测点验证在自有测试机、离线账号进行，产物只记录检测点与行为差异（`evidence-chain.md`）。

## 8. macOS 侧差异

- 二进制可能是 Fat/Universal；`lipo -info`、`otool -arch arm64` 逐片看。
- 签名：`codesign -dv --verbose=4`、`spctl -a -vv`、`stapler validate`；公证/硬化运行时（`runtime`）影响注入。
- 数据：`~/Library/Preferences/*.plist`、`~/Library/Application Support/*`、`~/Library/Containers/<bundle-id>/Data`。
- 日志：`log show --predicate 'process == "App"' --last 1h`；统一日志时间戳是 UTC，适合做时间线。
- TCC/隐私数据库（`TCC.db`）记录权限授予；读取需要权限，别把它当“用户同意过”的唯一证据。

## 9. 失败判据

- `cryptid=1` 未脱壳 → 停静态结论，`blocked_at: encrypted`。
- `Info.plist` 无法解析/签名与 Team ID 不一致 → 先查重签/损坏，不写“无权限”。
- `keychain-2.db` 打不开或表结构异常 → 只做文件级元数据，不伪造明文。
- SQLite `integrity_check` 失败/缺 WAL → 标“可能不完整”，不引用恢复行。
- Frida attach 失败/进程被看门狗重启 → 记录环境，换 lldb/日志；不反复注入。
- 越狱检测绕过影响业务/触发反作弊 → 停，写环境差异与风险。

## 10. 边界

- 只分析自有/授权 IPA、测试机、备份；账号/设备/云资源按 `scope` 清单执行。
- 产物限于证据链（采集→校验→关联）；越狱绕过实验只用于验证检测点。
- 不导出/传播 Keychain 明文、cookie、token；报告脱敏。
- 包结构/签名/权限是“能力面”，不是“实际行为”；行为结论要运行时/网络/数据文件交叉。

> 相关：`01-criteria.md`、`02-failure-criteria.md`、`03-model-pitfalls.md`、`game-client-il2cpp.md`、`evidence-chain.md`。
