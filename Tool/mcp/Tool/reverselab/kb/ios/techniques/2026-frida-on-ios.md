---
id: "ios/2026-frida-on-ios"
title: "iOS 上的 Frida 18+：attach 路径与 anti-Frida 信号"
title_en: "Frida 18+ on iOS: Attach Paths and Anti-Frida Signals"
board: "ios"
category: "techniques"
signals: ["Frida", "frida-ps -U", "27042", "gum-js-loop", "PT_DENY_ATTACH", "anti-Frida"]
keywords: ["iOS", "Frida", "frida_port", "anti_frida_hit", "ptrace", "usbmuxd"]
last_updated: "2026-10-20"
---
# iOS 上的 Frida 18+：attach 路径与 anti-Frida 信号

## 1. 来源与日期

- OWASP MASTG-TECH-0152（2025/26 修订版）：动态插桩与运行时篡改检测的用例分组。
- K. Moftah，2025：iOS 反调试/反注入一篇（`ptrace`、线程名、端口三类信号）。
- juliangrtz.me，2025-10：Frida 在近版本 iOS 上的 attach 与端口行为实测。

> 只引用标题/日期。Frida 迭代快，"18+" 的具体行为以 `frida --version` 实测为准。

## 2. 入口信号

- `frida-ps -U` 能列进程但 `attach` 超时/被杀。
- App 启动 1–3 秒内闪退，`idevicesyslog` 里出现 `SIGKILL` 或 `EXC_BAD_ACCESS`。
- 二进制含 `ptrace`、`sysctl`、`task_get_exception_ports`、`getppid`、`dlopen` 扫描逻辑。
- 需要判断"是反调试"还是"签名/越狱检测"（后者见 `2026-jb-detection-surface.md`）。

## 3. 命令（可复制）

主机侧（USB 连接，依赖 `usbmuxd`/`libimobiledevice`）：

```bash
frida --version
frida-ps -U                 # 用户进程
frida-ps -Uai               # 含 App 与 bundle id
frida -U -f <BUNDLE_ID> --no-pause -l hook.js
frida-trace -U -f <BUNDLE_ID> -m "-[<Class> <method>]"
```

设备侧（越狱机、`ssh root@<DEVICE_IP>`）：

```bash
/usr/sbin/frida-server -l 0.0.0.0:27042 &     # 显式端口，便于核对
lsof -i :27042 -i :27043 2>/dev/null || netstat -an | grep -E "2704[23]"
ps -A -o pid,comm | grep -i frida

# 线程名面（attach 后从主机侧看更准，这里是设备侧粗查）
ps -M <PID> 2>/dev/null | grep -Ei "gum-js-loop|gmain|gdbus|pool-frida"

# 注入库面
vmmap <PID> 2>/dev/null | grep -Ei "frida|gum-js|gadget"
```

从主机侧探测端口（仅授权网络）：

```bash
nc -vz <DEVICE_IP> 27042
nc -vz <DEVICE_IP> 27043
```

反调试自查（判断 App 用了哪一类）：

```bash
strings -a <APP>/<BIN> | grep -Ei "ptrace|PT_DENY_ATTACH|sysctl|kinfo_proc|getppid|exception_ports"
otool -L <APP>/<BIN> | grep -Ei "frida|gum|substrate|ellekit"
```

## 4. 判据表（字段名）

| 字段 | 取值示例 | 判据 |
| :--- | :--- | :--- |
| `frida_port` | `27042`、`27043`、自定义 `4444` | 设备侧有 LISTEN 且主机 `nc -vz` 通 → 该端口是 Frida 控制面；默认 27042，改端口不等于不可检测 |
| `anti_frida_hit` | `port_scan`、`thread_name`、`dlopen_scan`、`ptrace_deny`、`maps_scan`、`none` | 命中项要有可复现证据（端口/线程名/镜像名/返回值），单靠"闪退"不算 |
| `attach_stage` | `spawn_ok`、`attach_ok`、`attach_timeout`、`killed_after_resume` | 决定后续策略：spawn 阶段成功说明反调试在更晚的时机触发 |
| `ptrace_state` | `PT_DENY_ATTACH`、`P_TRACED`、`none` | `PT_DENY_ATTACH` → 常规 attach 必失败，只能 spawn + 尽早插桩；`P_TRACED` 是"正在被调试"的自查 |
| `injected_images[]` | `frida-agent.dylib`、`FridaGadget.dylib`、`/var/jb/.../libhooker.dylib` | 非系统路径的注入库出现在 `vmmap`；与 `dyld_images[]` 交叉 |
| `thread_names[]` | `gum-js-loop`、`gmain`、`gdbus`、`pool-frida` | 命中 ≥2 个才判线程名检测；单个 `gmain` 在正常 App 里也可能存在 |
| `device_link` | `usb`、`network`、`none` | `frida-ps -U` 空列表先查 `usbmuxd`/配对，不要当成 anti-Frida |

## 5. 失败判据

- `frida-ps -U` 返回空或只列 SpringBoard：`usbmuxd` 未运行、设备未配对、或用了 Wi-Fi
  但没 `-H <DEVICE_IP>`。**不是** anti-Frida。
- attach 报 `unable to find process`：App 未启动或 bundle id 写错（用 `frida-ps -Uai` 核对）。
- `spawn` 成功但 `resume` 后立刻退出：可能是 `PT_DENY_ATTACH`，也可能是签名/越狱检测；
  先用 `idevicesyslog` 看退出原因，再归因到 `anti_frida_hit`。
- 端口 27042 不通但 App 行为正常：Frida 可能走 USB 隧道或自定义端口，端口面结论不能
  外推为"设备没有 Frida"。
- 只看 `ps` 找不到 `frida-server`：进程可能改名或已退出；以端口 + 注入镜像为准。
- 线程名误判：`gmain`/`gdbus` 是 GLib 常见名，非 Frida 独有；必须结合
  `injected_images[]` 才成立。

## 6. 边界

- 只在自有/授权设备上插桩；不提供把 Frida 藏进上架包、或反检测成品脚本。
- 不讨论 App Store 分发绕过、不提供针对具体商用 App 的 anti-Frida 绕过步骤。
- 端口扫描仅限自己实验室网段，禁止对第三方网络探测。
- 与相邻篇的分工：签名/entitlement → `2026-macho-and-entitlements.md`；
  越狱路径/scheme → `2026-jb-detection-surface.md`；Keychain 落盘 → `2026-keychain-and-plist.md`。
