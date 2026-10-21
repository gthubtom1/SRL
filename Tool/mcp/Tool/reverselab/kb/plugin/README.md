# Plugin 知识库 — 插件/扩展/Mod（R25）

浏览器扩展、IDE 插件、Electron asar、Unity Mod 的入口与数据流卡片。
技能入口：`Tool/skill/plugin-targets/SKILL.md`。
边界：协议/抓包/分帧 → `protocol-plugin`（R24）；本文只处理宿主加载、权限、入口与最小可改单元。

## 入口

- [Manifest 与权限面](manifest-and-permissions.md) — CRX/MV3、VSIX、JetBrains
- [asar 与 Mod 加载器](asar-and-mod-loaders.md) — Electron、BepInEx/MelonLoader

## 10 分钟初筛

```bash
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path target.crx
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path app.asar --json
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path ./unpacked
```

1. **判包型**：CRX/ZIP、VSIX、JAR、asar、目录。
2. **读清单**：`manifest.json` / `extension/package.json` / `plugin.xml` / `package.json`。
3. **列入口**：background、content_scripts、main、preload、activationEvents、Action/Service。
4. **追数据流**：页面/宿主 → 插件 → 远端/本地；至少追一层。
5. **定最小单元**：文件/类/方法/channel 级，带回退。

## 硬判据（四件齐全）

- **入口可指认**：文件 + 清单字段/注册点 + 运行时加载路径。
- **权限可解释**：每个权限对应实际代码路径，不能解释的单列。
- **数据流可追**：输入、输出、副作用；配置/网络/存储/原生库/游戏对象至少一层。
- **最小单元可验证**：改动点 + 回退 + 改前/改后行为差异。

## 失败判据（何时停）

- 两次换工具仍解不出可读清单/入口 → 只报容器与哈希。
- 权限/入口能列但无法对应代码路径 → 标“权限面未闭环”，不写“恶意”。
- 动态加载两次失败（签名/白名单/版本不匹配）→ 转静态与更新链，不反复改包。
- 插件内含协议但取不到明文/帧边界 → 交 protocol-plugin（R24）。
- 触发反作弊/企业策略/账号风控 → 立即停，记录环境，不换号绕过。

## 工具降级

| 能力 | 首选 | 降级 |
|---|---|---|
| 解包 | unzip/7z | Python zipfile、bsdtar |
| manifest | jq | Python json、json5 |
| asar | npx asar | plugin-triage.py 解析头 + 树 |
| .NET | dnSpy/ilspycmd | monodis、r2 -A |
| 动态 | DevTools/CDP | 隔离环境 + 日志，不做隐式注入 |

细节：`Tool/skill/plugin-targets/references/` 下 browser-extension、desktop-plugins、electron-and-asar、unity-and-mods。
