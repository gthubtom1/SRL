# 桌面原生插件：OBS / StreamDeck / 输入法 / 驱动

> 适用：OBS 插件 DLL、StreamDeck `.sdPlugin`、输入法（`.ime`/DLL/TIP）、驱动/服务、Native Messaging host、媒体管线原生插件。
> 不适用：VSIX/JetBrains（→ `ide-plugins.md`）、Electron/asar（→ `electron-and-asar.md`）、Unity Mod（→ `unity-and-mods.md`）。
> 目标：**加载链 → 注册/导出入口 → 数据/通信面 → 最小可改单元**；只读枚举，不加载未签名驱动。

## 1. 形态与安装位置

| 形态 | 典型路径/标识 | 入口 |
|---|---|---|
| OBS 插件 | `obs-plugins/<arch>/<name>.dll` + `data/obs-plugins/<name>/` | `obs_module_load` 导出、注册 source/filter/output |
| StreamDeck 插件 | `*.sdPlugin/manifest.json` + `plugin.js`/二进制 | manifest 的 `CodePath`/`SDKVersion` |
| 输入法（Windows） | `*.ime`/`*.dll`，注册表 `Keyboard Layout`/`TIP` | `ITfTextInputProcessor`/`DllRegisterServer`/加载器 |
| 驱动 | `.sys` + 服务/设备 | `DriverEntry`、`IoCreateDevice`、IOCTL |
| Native Messaging host | 系统 `NativeMessagingHosts/<name>.json` + 可执行文件 | stdin/stdout 长度前缀 JSON |
| 媒体/采集插件 | 厂商目录 + 注册表/配置文件 | 导出函数/COM/管道 |

```bash
file plugin.dll plugin.sys
objdump -p plugin.dll | grep -E 'DLL Name|ImageBase|Export'
# Windows 可用 dumpbin /exports、sigcheck -a（只读）
find . -maxdepth 3 -iname '*.sdPlugin' -o -iname 'manifest.json' -o -iname '*.ime' -o -iname '*.sys'
```

**判据**：能说出“谁加载它、从哪加载、加载后注册了什么”，三项齐全。

## 2. OBS / StreamDeck：注册面

### 2.1 OBS 插件

- 导出 `obs_module_load`/`obs_module_unload`；在 load 里注册 source/filter/output/encoder。
- 依赖 `obs.dll`/`libobs` 的 ABI；版本不匹配会加载失败（不是代码错）。
- `data/obs-plugins/<name>/` 下的 locale/effect/shader 也是配置面。
- 图形/音频线程回调不可阻塞；卡顿/崩溃常来自线程误用。

```bash
objdump -p obs-plugins/64bit/demo.dll | sed -n '/Export/,+40p'
strings -n 8 obs-plugins/64bit/demo.dll | grep -iE 'obs_module|source|filter|encoder' | head
```

### 2.2 StreamDeck 插件

```bash
jq '{Name,Version,Author,Category,CodePath,PropertyInspectorPath,SDKVersion,OS,Software}' \
  com.example.plugin.sdPlugin/manifest.json
```

- `CodePath` 指向 Node 入口或二进制；`PropertyInspectorPath` 是设置页 HTML/JS。
- Node 插件可 `child_process`/`fs`/`net`；二进制插件看导出/命令行参数。
- 与 StreamDeck 的通信是 WebSocket（本地端口 + 注册事件）；协议细节不在本域，必要时交 `protocol-plugin`。

**判据**：manifest/导出 → 注册的回调/命令 → 数据读写或设备调用，至少一条链完整。

## 3. 输入法：加载链与文本面

- Windows 输入法可能是 TIP（Text Services Framework）COM DLL、`.ime` 旧式输入法、或宿主进程加载的 DLL。
- 关键注册：`HKLM\SOFTWARE\Microsoft\CTF\TIP\{CLSID}`、`Keyboard Layout\Preload/Substitutes`、`HKCR\CLSID\{...}\InprocServer32`。
- 入口：`DllRegisterServer`/`DllGetClassObject`/`ITfTextInputProcessor::ActivateEx`。
- 数据面：键盘事件、候选词、剪贴板、输入历史；是否写文件/发网络。
- 只在离线副本/测试账号验证；不要在日常输入环境替换系统输入法。

```bash
# 只读枚举（Windows）
reg query "HKLM\SOFTWARE\Microsoft\CTF\TIP" /s 2>/dev/null | head -80
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layouts" 2>/dev/null | head -40
```

**判据**：注册项 → CLSID/DLL → 入口函数 → 文本数据读写，链路可指认。

## 4. 驱动 / 服务：只读优先

- 驱动：`DriverEntry`、`IoCreateDevice`、`IRP_MJ_DEVICE_CONTROL`（IOCTL）、符号链接、回调（进程/线程/文件/注册表）。
- 用户态通信：DeviceIoControl、命名管道、共享内存、ALPC；先找“谁在调用”。
- 签名：EV/WHQL、签名者、加载策略（强制签名、测试签名、企业白名单）。
- 只读枚举：`sc query`、`driverquery /v`、`fltmc`、事件日志；不要加载未签名驱动、不要在生产机触发 IOCTL。

```bash
sc query type= driver state= all | head -60
driverquery /v 2>/dev/null | head -40
```

**判据**：服务/驱动加载状态 → 设备/符号链接 → 用户态调用方 → IOCTL/管道，至少三段可指认。

## 5. Native Messaging host

浏览器扩展的 `connectNative` 最终落到系统 host：

- Windows：注册表 `HKCU/HKLM\Software\...\NativeMessagingHosts\<name>` 指向 manifest JSON。
- macOS/Linux：`~/Library/Application Support/.../NativeMessagingHosts/`、`~/.config/...`。
- manifest 的 `path` 是可执行文件，`allowed_origins` 限定扩展 ID。
- 通信：stdin/stdout，4 字节长度前缀（本机字节序）+ JSON；错误走 stderr/退出码。

```bash
# 只读查看 host manifest（路径按平台替换）
cat "$HOME/.config/google-chrome/NativeMessagingHosts/com.example.host.json" 2>/dev/null
```

**判据**：扩展 ID ↔ `allowed_origins` ↔ host 可执行文件 ↔ 进程启动，四项能对上；协议字段交 `protocol-plugin`。

## 6. 签名、更新与持久化

| 形态 | 签名 | 更新/持久化 |
|---|---|---|
| OBS 插件 | 安装包/发布者签名 | 安装目录覆盖；OBS 版本约束 |
| StreamDeck | 市场/发布者 | StreamDeck 市场更新；插件目录 |
| 输入法 | 驱动/安装包签名 | 系统更新/厂商服务；注册表残留 |
| 驱动 | EV/WHQL/企业白名单 | Windows Update/厂商服务；服务启动类型 |
| Native host | 可执行文件签名 | 浏览器/安装器更新；注册表/目录 |

- 记录“谁可以推送更新”“更新是否校验签名”“卸载是否清理注册表/服务/驱动”。
- 旁加载/测试签名会被策略覆盖；记录加载来源与版本。
- 改包后不签名可能不加载；两次失败按 `02-failure-criteria.md` 第 19 条停。

**判据**：安装来源、签名者、更新通道、卸载残留四项齐全。

## 7. 最小可改单元

1. **一个注册回调/导出函数**（OBS `obs_module_load`、StreamDeck 命令 handler、输入法 `ActivateEx`）。
2. **一个配置/清单字段**（manifest `CodePath`、OBS data 配置、host `allowed_origins`）。
3. **一个 IOCTL/管道消息处理器**（仅离线副本，先加日志/校验）。
4. **一个 DLL/驱动二进制**：风险最高，只有前面都无法表达时才改。

改动前备份原文件与哈希，记录服务/注册表 baseline；改动后只触发一个路径，对比日志/设备/事件。一次只改一个变量。

**判据**：改动点文件/函数/注册项可指认，回退方式明确，行为差异可重复。

## 8. Office / Outlook Web Add-in

清单是 `manifest.xml`（不是 JSON），代码全在远端 HTTPS 页面；宿主只加载清单并开 webview。

```xml
<Requirements><Sets><Set Name="Mailbox" MinVersion="1.1"/></Sets></Requirements>
<Permissions>ReadWriteMailbox</Permissions>
<AppDomains><AppDomain>https://api.example.net</AppDomain></AppDomains>
<VersionOverrides xmlns=".../versionoverrides/1.1">   <!-- 内部另有一套 <Permissions> -->
  <Hosts><Host xsi:type="MailHost"><DesktopFormFactor><FunctionFile resid="Commands.Url"/>
  <Resources><bt:Url id="Commands.Url" DefaultValue="https://example.net/commands.html"/>
```

| 面 | 字段 | 看什么 |
|---|---|---|
| 权限 | `<Permissions>`（`ReadWriteMailbox`/`ReadWriteItem`/`ReadItem`/`Restricted`） | `ReadWriteMailbox` 可拿 EWS/Graph 令牌、改邮箱规则；`VersionOverrides` 里另有同名 `<Permissions>`，两处都要读 |
| 命令面 | `<FunctionFile>` → `commands.html` | 功能区按钮的真实逻辑在 `commands.html` 及其 `<Script>`；`DesktopFormFactor`/`MobileFormFactor` 各一套 |
| 导航白名单 | `<AppDomains><AppDomain>` | 只约束 task pane 顶层 `location`；iframe 内部可去任意域，白名单≠网络出口限制 |
| 身份 | `<WebApplicationInfo>`（SSO） | 有 `<Id>`+`<Resource>` 即走 Entra SSO，权限面从加载项转到应用注册 |

- 旁加载：网络共享 `\\host\share\addin.xml`（受信任目录）、OWA「我的加载项 → 从文件添加」、Outlook `...\WEF\...`，无商店审核；商店/集中部署走 AppSource 审核 + 租户「集成应用」管理员同意。两者都不签 XML：**信任落在承载页面的域与租户策略**上。
- 更新链＝远端页面（`SourceLocation`/`FunctionFile` 指向的服务器），换代码不需重发清单；只有清单变更才走商店/租户。

机检：`xmllint --format manifest.xml | grep -nE 'Permissions|AppDomain|FunctionFile|SourceLocation'`。

**判据**：`addin.permissions.element` 与 `addin.version_overrides.permissions` 都取到且值可枚举；`addin.function_file.url` 与 `addin.source_location.host` 可达；`addin.app_domains[]` 与 task pane 实际跳转域名对得上；`addin.update_channel` ∈ `{sideload,appsource,central}`。

**失败判据**：只读 `<Permissions>` 不读 `VersionOverrides` → 权限面漏一半；`AppDomains` 为空就写“不能外联” → 只说明顶层导航受限；`commands.html` 404/需登录 → 标 `unverified`，不写“命令执行任意操作”；只拿到清单没有承载页 → 只报权限声明与更新来源。

## 9. 失败判据与边界

- 插件 DLL 加载失败且两次修正依赖/ABI/路径仍失败 → 停，报加载链结论，不继续改二进制。
- 输入法/驱动“已安装”但服务/驱动未运行 → 标“未加载”，不要用安装状态推断行为。
- 只能看到注册项/导出表，无法指到用户态调用方 → 标 `inferred`，不写“可任意调用”。
- 触发签名强制/EDR/企业策略/蓝屏 → 立即停，记录环境；不提供绕过驱动签名/白名单的方法。
- 只读枚举优先；不加载未签名驱动、不在生产机触发 IOCTL、不替换日用输入法。
- 通信协议/帧格式 → 交 `protocol-plugin`（R24）。

> 关联：`references/01-criteria.md` 第 16–17 条、`references/02-failure-criteria.md` 第 21–22 条、`references/ide-plugins.md`（签名/更新的 IDE 侧）。
