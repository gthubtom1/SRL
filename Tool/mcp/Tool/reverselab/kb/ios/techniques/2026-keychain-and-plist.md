---
id: "ios/2026-keychain-and-plist"
title: "iOS Keychain 与 plist：落盘读取与四要素"
title_en: "iOS Keychain and Plists: On-disk Reads and the Four Elements"
board: "ios"
category: "techniques"
signals: ["keychain-2.db", "genp", "inet", "pdmn", "agrp", "NSUserDefaults"]
keywords: ["iOS", "Keychain", "plist", "kc_items", "plist_keys", "kSecClass"]
last_updated: "2026-10-20"
---
# iOS Keychain 与 plist：落盘读取与四要素

## 1. 来源与日期

- OWASP MASTG-TECH-0152（2025/26 修订版）：本地存储测试分组（Keychain/plist/DB）。
- K. Moftah，2025：iOS 凭据落盘与访问控制一篇（`agrp` 与 entitlement 的对应）。
- juliangrtz.me，2025-10：`cfprefsd` 缓存导致 plist 读旧的实测。

> 标题/日期级引用。表结构随 iOS 版本变化，字段名以真机 `sqlite3 .schema` 为准。

## 2. 入口信号

- 需要确认凭据落在 Keychain 还是 `NSUserDefaults`/plist/明文 DB。
- 二进制约有 `kSecClass`、`SecItemAdd`、`SecItemCopyMatching`、`kSecAttrAccessible`。
- 需要核对"同一份数据在 App 容器与全局 Preferences 里是否一致"。
- 取证/合规场景要统计"有多少条凭据、属于哪个 access group"而不读取明文。

## 3. 命令（可复制）

设备侧（越狱机、`ssh root@<DEVICE_IP>`，只读）：

```bash
DB=/private/var/Keychains/keychain-2.db

# 1) 表与列
sqlite3 "$DB" ".tables"
sqlite3 "$DB" ".schema genp" | head -20

# 2) 四要素：class / acct-svce / agrp / pdmn（不导出 data）
sqlite3 -header -column "$DB" \
  "select rowid,agrp,svce,acct,pdmn,length(data) as n,datetime(cdat,'unixepoch') as cdat
     from genp order by cdat desc limit 20;"

# 3) 互联网凭据（含 srvr/port/protocol）
sqlite3 -header -column "$DB" \
  "select rowid,agrp,srvr,port,acct,pdmn from inet limit 20;"

# 4) access group 分布（判断是否越权共享）
sqlite3 "$DB" "select agrp,count(*) from genp group by agrp order by 2 desc;"

# 5) 先拷副本再分析，避免锁库/漏 WAL
cp "$DB" /tmp/kc.db; cp "$DB"-wal /tmp/kc.db-wal 2>/dev/null
sqlite3 /tmp/kc.db "pragma wal_checkpoint(TRUNCATE);" 2>/dev/null
```

plist / 容器侧：

```bash
APP_DATA=/var/mobile/Containers/Data/Application/<UUID>
plutil -p <APP>/Info.plist
plutil -p "$APP_DATA/Library/Preferences/<BUNDLE_ID>.plist"
/usr/libexec/PlistBuddy -c "Print" "$APP_DATA/Library/Preferences/<BUNDLE_ID>.plist"
ls -la "$APP_DATA/Library/Preferences/" "$APP_DATA/Documents/" 2>/dev/null

# 二进制 plist 与 XML 互换（只读输出到 stdout）
plutil -convert xml1 -o - "$APP_DATA/Library/Preferences/<BUNDLE_ID>.plist" | head -40

# 全局域（同 bundle id 的 NSUserDefaults 可能落在这里）
ls /var/mobile/Library/Preferences/ | grep -i "<BUNDLE_ID>" 
```

## 4. 判据表（字段名）

| 字段 | 取值示例 | 判据 |
| :--- | :--- | :--- |
| `kc_items` | `genp=12`、`inet=3`、`cert=1`、`keys=0` | 按表计数；`genp` 是通用密码，`inet` 是网络凭据；计数为 0 而代码有 `SecItemAdd` → 查 `agrp`/`pdmn` 是否写进别的库 |
| `kc_class` | `genp`、`inet`、`cert`、`keys` | 对应 `kSecClass`；同一凭据出现在两个 class 说明写入路径不止一处 |
| `kc_agrp[]` | `ABCDE12345.com.example.app`、`com.apple.token` | 与 `entitlements[]` 的 `keychain-access-groups` 对齐；App 能读到不属于自己 `agrp` 的行 → 越权共享 |
| `kc_pdmn[]` | `ak`、`ck`、`dk`、`aku`、`cku`、`dku`、`nku` | 对应 `kSecAttrAccessible*`；`*u` 后缀表示"仅本机、不备份"，`ak` 可随备份迁移 |
| `plist_keys[]` | `licenseKey`、`trialStart`、`deviceId`、`firstRun` | 排序后的键名清单；出现凭据类键名 → 与 `kc_items` 对比，判断是否明文存密钥 |
| `plist_path` | `Library/Preferences/<BUNDLE_ID>.plist`、`Documents/config.plist` | 路径必须在 App 容器内或全局 Preferences；`Documents/` 下的 plist 可被 iTunes 备份带出 |
| `prefs_cache` | `cfprefsd`、`stale` | 设备侧 `defaults`/plist 与 App 读到的值不一致时，先 `killall -9 cfprefsd` 再读 |

判定规则：`plist_keys[]` 里出现密钥/令牌类键 → 高风险，直接记录；`kc_items` 非空但
`data` 长度全为 0 → 可能是引用/占位行，不能当成"有凭据"。

## 5. 失败判据

- `data` 列是加密 blob：没有 keybag/`keychain_dumper` 类工具（需
  `keychain-access-groups` entitlement）就读不出明文。**只能**统计 `length(data)`，
  不要在报告里写"已获取明文"。
- 只拷 `keychain-2.db` 不拷 `-wal`：最近写入的行缺失，计数偏小。先 `wal_checkpoint`
  或整目录拷贝。
- `plist` 读到的值与 App 显示不一致：`cfprefsd` 内存缓存未落盘（尤其刚改过设置）。
- 容器 UUID 路径写死：重装 App 后 UUID 变化，脚本必须重新解析
  `xcrun simctl get_app_container`（模拟器）或 `ideviceinstaller` 信息。
- 二进制 plist 用 `cat` 看是乱码：先 `file` 判断格式，再 `plutil -convert xml1 -o -`。
- Keychain 行存在但 `agrp` 为空：老版本/迁移残留，不能据此判断当前 App 的访问组。

## 6. 边界

- 仅自有/授权设备；Keychain 内容是真实用户秘密，默认只统计条数与字段名。
- 报告里禁止贴 `data` 明文、token、证书私钥；确需举例用同长度占位。
- 不提供"导出他人备份中的 Keychain"的方法；不讨论暴力解密 keybag。
- 相邻篇：签名/entitlement → `2026-macho-and-entitlements.md`；越狱面 →
  `2026-jb-detection-surface.md`；动态读取手段 → `2026-frida-on-ios.md`。
