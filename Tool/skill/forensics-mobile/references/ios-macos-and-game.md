# iOS / macOS / 游戏客户端速查

> 配套 `forensics-mobile/SKILL.md`。仅在自有或明确授权的设备、应用、客户端上操作。
> 动态分析前先确认：设备归属、是否越狱/可回滚、是否装了反作弊、离线账号是否可用。

## 1. `.ipa` 解包与包结构

```bash
unzip -q app.ipa -d ipa/
APP=$(ls -d ipa/Payload/*.app | head -1)
find "$APP" -maxdepth 2 -type d | sort
plutil -p "$APP/Info.plist"
codesign -d --entitlements :- "$APP" 2>/dev/null | head -40
unzip -p app.ipa 'Payload/*.app/embedded.mobileprovision' | strings | grep -iE 'TeamIdentifier|ExpirationDate|ProvisionedDevices'
```

- 重点目录：`Frameworks/`（动态库）、`PlugIns/`（扩展）、`Watch/`、`Assets.car`、`*.momd`、`*.sqlite`/`*.db`；`Info.plist` 看 `CFBundleIdentifier`、`CFBundleExecutable`、`LSApplicationQueriesSchemes`、`NSAppTransportSecurity`、`UIBackgroundModes`。
- `embedded.mobileprovision` 看签名类型（开发/企业/App Store）、Team ID、有效期、设备列表。判据：列出可执行文件、内嵌框架、权限、URL Scheme 与数据文件。

## 2. Mach-O 分析

```bash
BIN="$APP/$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")"
file "$BIN"
otool -hv "$BIN"
otool -l "$BIN" | grep -A7 LC_ENCRYPTION_INFO
otool -L "$BIN"
nm -m "$BIN" | grep -iE 'keychain|sqlite|jailbreak|ptrace|sysctl' | head
codesign -dv --verbose=4 "$BIN"
```

- `LC_ENCRYPTION_INFO(_64).cryptid`：`1` = App Store 加密，必须先脱壳再静态分析；`0` = 未加密。`LC_UUID` 用于对齐崩溃日志与内存镜像；`LC_BUILD_VERSION` 记录 SDK/最小系统版本。
- `otool -L` 的 `@rpath` 依赖要在 `Frameworks/` 与 `rpath` 里找实际文件，别假设系统库；`nm -m` 区分外部/私有符号，Swift 符号需 `swift-demangle`。
- 判据：头/依赖/符号/签名四项齐全，能解释二进制从哪里加载、调用哪些敏感能力。

### 2.1 脱壳（授权测试机）

```bash
# 设备上确认 cryptid 后，用 dump 工具导出解密页
frida-ios-dump -u <udid> -o out.ipa <bundle-id>
# 或 bagbak / 其它授权工具
```

- 脱壳产物只用于分析；核对导出二进制的 `cryptid` 应为 0，再重跑 `otool`/`nm`。记录设备型号、iOS 版本、越狱方式、dump 工具版本；不同设备结果不能混用。判据：符号与字符串可读，且与 `Info.plist`/bundle ID 对得上。

## 3. 越狱检测：取证视角

| 检测面 | 典型实现 | 取证记录 |
|---|---|---|
| 文件路径 | `Cydia.app`、`/var/jb`、`/bin/bash`、`sshd` | 路径存在性与访问时间 |
| URL Scheme | `canOpenURL:@"cydia://"` | 返回值与调用点 |
| 进程 | `fork`/`posix_spawn` 成功 | 返回值、父进程 |
| 环境变量 | `DYLD_INSERT_LIBRARIES` | 进程环境快照 |
| dyld 镜像 | `_dyld_image_count` 含注入库 | 模块列表与加载顺序 |
| 沙盒 | 沙盒外可写 | 实际写入测试与文件 |
| sysctl | `P_TRACED` 等标志 | 标志值与调试状态 |

- 先记录**基线**：未注入、未越狱时的检测结果；再记录实验后的差异。绕过只为验证“检测点是否真的生效”，在自有测试机、离线账号进行；不用于线上反作弊或授权规避。
- 记录副作用：崩溃、看门狗重启、检测上报、账号风控；有副作用立即停止。判据：每个检测点有位置、有证据、有结论，而不是“过了/没过”。

## 4. Keychain / plist / 数据库

### 4.1 macOS 钥匙串

```bash
security list-keychains
security dump-keychain -d login.keychain-db | grep -A6 'class:'
security find-generic-password -s '<service>' -g 2>&1
```

- 只对授权账户的钥匙串操作；导出内容脱敏，报告保留 service/account/创建时间等定位信息。iOS 的 `keychain-2.db` 受保护类密钥保护；无授权测试机时只描述结构与访问控制，不伪造明文。

### 4.2 plist

```bash
plutil -p file.plist
plutil -convert xml1 -o - file.plist | head -40
python3 - <<'PY'
import plistlib
print(plistlib.load(open('file.plist','rb')))
PY
```

- 二进制 plist 用 `plutil`/`plistlib` 读；`NSKeyedArchiver` 需 `plutil -p` 后逐层解归档。关注 `LastModified`、`BundleVersion`、token/cookie 缓存、`NSUserDefaults` 键名。
- 判据：能说明键由谁写入、何时写入、是否随备份/云同步迁移。

### 4.3 SQLite

```bash
cp app.db app.db.bak
cp app.db-wal app.db.bak-wal 2>/dev/null
cp app.db-shm app.db.bak-shm 2>/dev/null
sqlite3 app.db.bak '.tables'
sqlite3 app.db.bak 'SELECT name, sql FROM sqlite_master;'
sqlite3 app.db.bak 'PRAGMA integrity_check;'
sqlite3 app.db.bak '.recover' > recover.sql
```

- 先复制 `.db`、`-wal`、`-shm`、`-journal` 再打开，避免锁与回写改变证据。已删记录常在 WAL、freelist、未分配页；`.recover` 与 `strings` 结合找残留。
- 判据：能定位表/字段/记录，说明写入 API 与保留策略（备份、清除、加密）。

## 5. Frida 在 iOS 上 attach

```bash
frida-ps -Uai
frida -U -f com.example.app -l hook.js --no-pause
frida-trace -U -f com.example.app -m '-[NSURLSession dataTaskWithRequest:*]'
```

```javascript
// hook.js：只读观测，不改返回值
if (ObjC.available) {
  const cls = ObjC.classes.NSUserDefaults;
  Interceptor.attach(cls['- objectForKey:'].implementation, {
    onEnter(args) { this.key = new ObjC.Object(args[2]).toString(); },
    onLeave(ret) { console.log(this.key, ret); }
  });
}
```

- `frida-server` 的版本、架构（arm64/arm64e）、签名要与设备匹配；attach 失败先看日志与进程是否被重启。先用 `frida-ps -Uai` 确认 bundle ID；`-f` 启动并挂起，`--no-pause` 立即运行。
- 只读优先：枚举模块/类/方法、打印参数与返回值；改内存/改返回值只用于检测点验证并记录。判据：函数 → 运行时参数/返回值 → 落盘文件/网络请求，链路完整。

## 6. 游戏客户端：Unity

### 6.1 Mono

```bash
find "$APP" -name 'Assembly-CSharp.dll' -o -name 'globalgamemanagers' -o -name 'level0'
ilspycmd Assembly-CSharp.dll -o decompiled/
monodis --assembly Assembly-CSharp.dll
```

- `Data/Managed/` 下有 `Assembly-CSharp.dll` 即 Mono；`UnityEngine.*.dll` 与 `mscorlib.dll` 用于补依赖。判据：定位数值/协议/存档字段的类与方法，并与配置或抓包字段对上。

### 6.2 IL2CPP

```bash
ls "$APP/Frameworks" | grep -iE 'GameAssembly|UnityFramework'
Il2CppDumper GameAssembly.dll global-metadata.dat out/
# 或
Cpp2IL --game-path "$APP" --output out/
```

- 输入是 `GameAssembly`（或 `UnityFramework`）与 `global-metadata.dat`；版本必须与 Unity 版本匹配。产物：`dump.cs`、`il2cpp.h`、`script.json`（地址）、`stringliteral.json`、`DummyDll/`。
- 在 IDA/Ghidra 里加载 `il2cpp.h` 与 `script.json`，把函数地址还原成方法名。判据：`dump.cs` 字段 → 二进制地址 → 运行时内存值三者对齐。

### 6.3 AssetBundle

```bash
xxd -l 64 bundle | head
AssetStudioModCLI bundle -o export/
# 或
python3 - <<'PY'
import UnityPy
env = UnityPy.load('bundle')
for obj in env.objects:
    print(obj.type.name)
PY
```

- 头部 `UnityFS`/`UnityWeb`/`UnityRaw` 表明是 AssetBundle；记录 Unity 版本与压缩方式（LZ4/LZMA）。加密/魔改包会解析失败；从二进制找 key/算法属于深水区，找不到就标“未解”，不编造内容。
- 导出后核对 `CAB-*`、Texture2D、TextAsset、AudioClip、Mesh 与 `manifest` 的引用关系。判据：资源属于哪个 bundle、被谁引用、运行时如何加载。

### 6.4 进程内存与反作弊

- 离线：对自有客户端做 minidump/`gcore`，按模块基址 + 偏移定位字段，记录模块哈希与偏移来源。在线只读：`Process.enumerateModules()`、`Memory.scan()` 读取已知特征；**不写、不挂钩、不注入**。
- 识别反作弊：EAC/BattlEye/Vanguard/mhyprot 等；在线环境只做抓包、日志、公开文件、录屏。需要动态分析时用离线副本/授权测试服，并在报告写明环境差异。
- 判据：数值链路（服务器下发 → 客户端字段 → 内存偏移 → 显示/上报）完整；缺一环标 `inferred`。

## 7. 常见坑

1. `cryptid 1` 未脱壳就 `strings`/`nm`，结论全错。
2. `otool -L` 看到 `@rpath` 就以为是系统库，实际在 `Frameworks/`。
3. iOS 越狱检测只看一个路径，漏掉 URL Scheme/dyld/沙盒组合。
4. Frida 版本与 frida-server 不匹配，attach 失败被误判为“应用有反调试”。
5. SQLite 直接打开导致 WAL 回写，证据被改。
6. Unity 版本与 IL2CPP 元数据不匹配，`dump.cs` 字段错位。
7. AssetBundle 加密未识别，导出空资源还声称“资源缺失”。
8. 在线游戏 attach 触发反作弊，封号或系统不稳定。
9. 时间线用本地时间混 UTC，事件顺序颠倒。
10. 报告只写“发现可疑”，没有来源、命令、哈希与置信标签。

## 8. 交付检查

- [ ] 包/二进制来源、SHA256、设备与系统版本、工具版本齐全。
- [ ] 加密二进制已脱壳或明确标注“未脱壳、结论不可用”。
- [ ] 检测点/字段/资源/内存偏移有位置与证据。
- [ ] Keychain/plist/数据库结论标注数据保护与保留策略。
- [ ] 反作弊环境只读，动作可审计，停止原因已记录。
