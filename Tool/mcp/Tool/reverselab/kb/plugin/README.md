# Plugin 知识库 — 插件 / 扩展 / Mod（R25）

> 技能入口：`Tool/skill/plugin-targets/SKILL.md`。
> 边界：协议/抓包/分帧/状态机 → `protocol-plugin`（R24）；APK 壳/重打包 → `apkseep`；PE 脱壳 → `unpack-loop`；供应链 lockfile → `supply-chain-security`。
> 本 board 只处理：宿主如何加载插件、权限/入口如何落到代码、数据流到哪、最小可改单元是什么、失败时往哪转。

## 入口

- [Manifest 与权限面](techniques/manifest-and-permissions.md) — CRX/MV3、VSIX、JetBrains 的清单字段与权限映射。
- [asar 与 Mod 加载器](techniques/asar-and-mod-loaders.md) — Electron/BepInEx/MelonLoader 的结构与入口。
- [MV3 service worker 与隔离世界](techniques/mv3-service-worker-isolation.md) — SW 生命周期、ISOLATED/MAIN world、消息面。
- [asar 与 Electron 主进程](techniques/asar-main-process.md) — main/preload/renderer、IPC、原生模块、`.jsc`。
- [Unity IL2CPP 与 BepInEx](techniques/unity-il2cpp-bepinex.md) — 加载器、插件类、Harmony patch、IL2CPP dump。
- [VSIX / JetBrains 插件](techniques/ide-plugin-vsix-jetbrains.md) — 激活事件、扩展点、受限工作区、签名/更新。
- [2026 V8 字节码战例](techniques/2026-v8-bytecode.md) — bytenode `.jsc` 反编译的 `v8_version_match` 闸门。
- [插件失败判据](techniques/plugin-failure-criteria.md) — 何时停、换哪条观测层、怎么留证。

## 10 分钟初筛

```bash
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path target.crx --json
python Tool/skill/plugin-targets/scripts/plugin-repro.py --path target.crx --out work/repro --json
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path app.asar --json
```

1. **判包型**：CRX/XPI/ZIP、VSIX、JAR、asar、Unity 目录。
2. **读清单**：`manifest.json` / `extension/package.json` / `plugin.xml` / `package.json`。
3. **列入口**：background、content_scripts、main/preload、activationEvents、Action/Service、插件 DLL。
4. **追数据流**：页面/宿主 → 插件 → 远端/本地；至少一条边有 file/line。
5. **定最小单元**：文件/类/方法/channel 级，带回退与 baseline。

## 三条硬判据

- **入口可指认**：文件 + 清单字段/注册点 + 运行时加载路径；不能只有“声明了”。
- **权限/扩展点可解释**：每个权限、每个扩展点对应实际代码路径；不能解释的单列 `unexplained-static`。
- **数据流可追**：输入、输出、副作用；配置/网络/存储/原生库/游戏对象至少一层有证据。

补充两条工程判据：

- **最小单元可验证**：改动点 + 回退 + 改前/改后行为差异。
- **版本自洽**：宿主版本、插件版本、运行时（MV2/MV3、Electron/Node、BepInEx/IL2CPP）匹配。

## 失败判据（何时停）

- 两次换工具仍解不出可读清单/入口 → 只报容器与哈希，不硬猜偏移。
- 权限/入口能列但无法对应代码路径 → 标“权限面未闭环”，不写“恶意”。
- 动态加载两次失败（签名/白名单/版本/受限工作区）→ 转静态与更新链，不反复改包。
- 插件内含协议但取不到明文/帧边界 → 交 `protocol-plugin`（R24）。
- 触发反作弊/EDR/企业策略/账号风控 → 立即停，记录环境，不绕过。
- 详见 [插件失败判据](techniques/plugin-failure-criteria.md)。

## 工具降级

| 能力 | 首选 | 降级 |
|---|---|---|
| 解包 | unzip/7z | Python `zipfile`、bsdtar |
| 清单 | jq | Python `json`、json5 |
| asar | npx asar | `plugin-triage.py`/`plugin-repro.py` 解析头与偏移 |
| .NET | ilspycmd/dnSpy | monodis、r2 -A、strings |
| Java | jadx/CFR | javap -c、jar tf |
| Unity IL2CPP | Il2CppDumper/Cpp2IL | 只读 `global-metadata.dat` 字符串 + 插件 DLL |
| 动态 | DevTools/CDP | 隔离环境 + 日志，不做隐式注入 |

## 案例

- `Tool/cases/plugin01`、`plugin02`：MV3 夹具（权限/消息/远端）。
- `Tool/cases/plugin03`：真实本机 Chrome MV3 扩展（Quicker 1.2.4）子集，含真实 sha256/权限证据。
- `Tool/cases/plugin04`：asar 夹具（main/preload/renderer/IPC）。
- `Tool/cases/plugin05`：VSIX 夹具（activationEvents/child_process）。

## 邻域边界

- 协议复刻/抓包/分帧 → `protocol-plugin`（R24）；本 board 只交入口与载荷位置。
- 浏览器网页 JS 签名/补环境 → `mcp-js-reverse-playbook`；本 board 只看扩展世界。
- APK/Xposed 模块的壳与重打包 → `apkseep`；本 board 只借用其模块入口结论。
- PE 壳/反调试/驱动二进制深挖 → `unpack-loop`/`softseep`；本 board 只做加载链与接口面。
- 供应链依赖/lockfile/构建完整性 → `supply-chain-security`。

> 维护：新增 technique 必须在本 README 增加链接；失败判据变化同步 `references/02-failure-criteria.md`。
