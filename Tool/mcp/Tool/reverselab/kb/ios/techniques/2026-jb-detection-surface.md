---
id: "ios/2026-jb-detection-surface"
title: "iOS 越狱检测面：路径 / URL scheme / dyld / 工具残留"
title_en: "iOS Jailbreak Detection Surface: Paths, Schemes, dyld, Tool Residue"
board: "ios"
category: "techniques"
signals: ["jailbreak detection", "/var/jb", "cydia://", "dyld image", "rootless", "Substrate"]
keywords: ["iOS", "越狱检测", "jb_paths", "jb_scheme", "rootless", "dyld"]
last_updated: "2026-10-20"
---
# iOS 越狱检测面：路径 / URL scheme / dyld / 工具残留

## 1. 来源与日期

- K. Moftah，2025：iOS 越狱检测与对抗一篇（路径/`canOpenURL`/`fork` 三类信号）。
- OWASP MASTG-TECH-0152（2025/26 修订版）：越狱与完整性检查的测试用例分组。
- juliangrtz.me，2025-10：`dyld` 镜像枚举与 rootless 路径变化的实测记录。

> 标题/日期级引用；不补 DOI。rootless（`/var/jb`）行为以实际 iOS 版本实测为准。

## 2. 入口信号

- App 启动即闪退、弹"设备不安全"，或登录接口返回风控码。
- 二进制里出现 `Cydia`、`/var/jb`、`Substrate`、`canOpenURL:`、`fork` 等符号。
- 设备已越狱但 App 表现"正常"（可能是检测未触发或只做上报）。
- 需要区分"真越狱检测"与"反调试/反注入"（后者见 `2026-frida-on-ios.md`）。

## 3. 命令（可复制）

设备侧（越狱机、`ssh root@<DEVICE_IP>`，只读枚举）：

```bash
# 1) 经典路径面（-d 只判断存在，不进入）
for p in /Applications/Cydia.app /Applications/Sileo.app /var/jb /usr/sbin/sshd \
         /etc/apt /private/var/lib/dpkg /usr/libexec/cydia /bin/bash; do
  [ -e "$p" ] && echo "HIT $p $(stat -f '%HT' "$p" 2>/dev/null)"
done

# 2) rootless 前缀：/var/jb 下的包管理器与注入库
ls -d /var/jb/usr/lib/*.dylib 2>/dev/null | head
ls -d /var/jb/Library/MobileSubstrate 2>/dev/null

# 3) 进程/镜像面（需 debugserver 或设备侧工具）
ps -A -o pid,comm | grep -Ei "cydia|sileo|substrate|substitute|ellekit|libhooker"
vmmap <PID> 2>/dev/null | grep -Ei "substrate|substitute|ellekit|libhooker|frida"

# 4) URL scheme 是否被注册（设备侧）
grep -rn "cydia\|sileo\|zebra\|installer" /var/jb/Applications/*/Info.plist 2>/dev/null | head

# 5) 可写性面
[ -w /private/ ] && echo "HIT /private writable"
```

应用侧信号（从二进制/`Info.plist` 反查它自己会测什么）：

```bash
strings -a <APP>/<BIN> | grep -Ei "cydia|sileo|zebra|/var/jb|substrate|jailbreak|canOpenURL"
plutil -p <APP>/Info.plist | grep -A20 LSApplicationQueriesSchemes
otool -L <APP>/<BIN> | grep -Ei "substrate|ellekit|libhooker"
```

## 4. 判据表（字段名）

| 字段 | 取值示例 | 判据 |
| :--- | :--- | :--- |
| `jb_paths[]` | `/Applications/Cydia.app`、`/var/jb`、`/usr/sbin/sshd`、`/etc/apt`、`/private/var/lib/dpkg` | 命中 ≥1 且 `stat` 类型符合预期（目录/可执行）→ 该路径面成立；只有字符串存在不算 |
| `jb_scheme` | `cydia`、`sileo`、`zebra`、`installer` | 目标 scheme 在 `LSApplicationQueriesSchemes` 里声明且 `canOpenURL` 返回 true；未声明时 false 是**假阴性** |
| `dyld_images[]` | `/usr/lib/libsubstrate.dylib`、`/var/jb/usr/lib/libhooker.dylib`、`ElleKit.dylib` | 非系统路径的注入库出现在已加载镜像 → 越狱/注入双信号 |
| `sandbox_escape` | `fork_ok`、`posix_spawn_ok`、`/private` writable | 沙箱内成功 fork/写 `/private` → 沙箱已破 |
| `jb_tool_residue[]` | `dpkg`、`apt`、`ssh`、`frida-server` | 工具残留路径存在；与 `jb_paths[]` 交叉验证，避免单点误判 |
| `detect_api[]` | `fileExistsAtPath`、`canOpenURL`、`_dyld_image_count`、`stat` | 二进制里出现的检测 API；决定对抗面而不是结论 |

判定规则：`jb_paths[]` 非空 **或** `jb_scheme` 命中 **或** `dyld_images[]` 含非系统注入库
→ 判"设备处于越狱面"。三者全空才可暂判"未检出"，且必须在"失败判据"里登记原因。

## 5. 失败判据

- App 沙箱内读 `/var/jb` 返回 `EPERM`：路径存在也读不到 → 路径面假阴性。用设备侧
  root shell 复核，不要把"App 没读到"写成"设备没越狱"。
- `canOpenURL` 恒 false：`LSApplicationQueriesSchemes` 未声明该 scheme（iOS 9+ 限制），
  或设备没装对应管理器。此时 `jb_scheme` 字段应为空并注明"未声明/未安装"。
- 只测经典路径（`/Applications/Cydia.app`）：rootless 越狱把内容放在 `/var/jb`，
  老清单全空是**预期结果**，不是干净设备。
- 符号链接/挂载点：`/var/jb` 可能是 symlink 或 bind mount，`-e` 为真但 `stat -f %HT`
  显示 `Symbolic Link`；用 `stat -L` 再确认一次。
- 检测只在特定版本触发（如 `fork` 在 iOS 17+ 被沙箱统一拒绝）：跨版本结论不可复用。
- 只看字符串就断言"有/没有检测"：字符串可能来自第三方 SDK 或死代码，必须找到调用点
  （反汇编 `xref`）才算 `detect_api[]` 命中。

## 6. 边界

- 只在自有设备或书面授权的测试机上执行；不对他人设备做越狱探测。
- 本节是**检测面测绘**：说明 App 测什么、为什么漏，不提供"让检测永远失败"的成品。
- 不发布越狱工具链、不提供绕过 App Store 校验的步骤。
- 与 Frida/反调试的分界：端口/线程/`ptrace` 归 `2026-frida-on-ios.md`；
  文件与 scheme 面归本篇；`codesign`/entitlement 归 `2026-macho-and-entitlements.md`。
