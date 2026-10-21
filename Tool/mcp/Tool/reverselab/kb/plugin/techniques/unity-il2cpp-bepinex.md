# Unity IL2CPP 与 BepInEx：加载器、插件、patch 目标

## 入口信号

- 游戏目录有 `winhttp.dll` + `doorstop_config.ini`（BepInEx）或 `MelonLoader/` + `version.dll`。
- `GameAssembly.dll` + `global-metadata.dat`（IL2CPP）；`Managed/Assembly-CSharp.dll`（Mono）。
- `BepInEx/plugins/*.dll`、`MelonLoader/Mods/*.dll`、`BepInEx/config/*.cfg`。
- 日志：`BepInEx/LogOutput.log`、`MelonLoader/Latest.log`。

## 可复制命令

```bash
find . -maxdepth 4 \( -iname 'BepInEx' -o -iname 'MelonLoader' -o -iname 'doorstop_config.ini' \
  -o -iname 'LogOutput.log' -o -iname 'Latest.log' \) -print
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path . --json
python Tool/skill/plugin-targets/scripts/plugin-repro.py --path . --out work/repro --json

# Mono
ilspycmd Managed/Assembly-CSharp.dll -o work/game-src
ilspycmd BepInEx/plugins/Mod.dll -o work/mod-src

# IL2CPP
Il2CppDumper GameAssembly.dll global-metadata.dat work/il2cpp/
ls work/il2cpp/    # dump.cs / DummyDll / script.json / stringliteral.json
```

## 插件入口对照

| 加载器 | 入口类/特性 | 初始化方法 |
|---|---|---|
| BepInEx | `BaseUnityPlugin` + `[BepInPlugin]` | `Awake`/`Start`/`Update` |
| BepInEx | `[BepInDependency]` | 加载顺序/依赖 |
| MelonLoader | `MelonMod` + `[MelonInfo]` | `OnInitializeMelon`/`OnUpdate`/`OnGUI` |

## Harmony patch 对照

| patch | 作用 | 风险 |
|---|---|---|
| `Prefix` | 改参数/跳过原方法 | 中 |
| `Postfix` | 改返回值/后处理 | 低–中 |
| `Transpiler` | 改 IL 指令流 | 高 |
| `Finalizer` | 异常/清理 | 中 |

```bash
grep -RInE "HarmonyPatch|Harmony\.Patch|Prefix|Postfix|Transpiler|BaseUnityPlugin|MelonMod" work/mod-src | head -80
```

## 确认判据

- 加载器、运行时（Mono/IL2CPP）、插件目录、日志路径四项齐全。
- 日志里有插件 guid/版本/Chainloader 输出，证明已加载。
- patch 目标类型/方法在游戏程序集或 `dump.cs` 中存在，签名匹配。
- 单变量改动有可观察差异，回退后基线恢复。

## 失败判据

- 插件未加载，两次修路径/版本仍失败 → 停，报加载链结论。
- patch 目标找不到/被内联/混淆 → 标“目标未定”，不猜方法名。
- IL2CPP 元数据与二进制版本不匹配 → 停，换对应版本工具。
- patch 生效但无行为差异 → 先查是否命中正确方法/字段，不叠加第二个 patch。
- 触发反作弊/封号/蓝屏 → 立即停，记录环境。

## 边界

- 只在自有/授权的离线副本或测试服操作；在线反作弊环境只做外部观测。
- `dump.cs` 是结构恢复，不是原始源码；关键偏移回二进制验证。
- 不提供绕过反作弊或隐藏注入的方法。
- 插件内协议交 `protocol-plugin`（R24）。

> 关联：`Tool/skill/plugin-targets/references/unity-and-mods.md`、`references/02-failure-criteria.md`。
