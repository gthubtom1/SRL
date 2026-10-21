# Unity Mod：BepInEx / MelonLoader / Harmony

> 配套 `plugin-targets/SKILL.md` 的 §3.4。目标：**插件类 → patch 目标 → 修改的字段/返回值 → 可观察效果**。
> 只在自有或明确授权的离线副本/测试服操作；在线反作弊环境只做外部观测。

## 1. 先判运行时与加载器

| 信号 | 结论 | 下一步 |
|---|---|---|
| `winhttp.dll` + `doorstop_config.ini` | BepInEx（Doorstop 注入） | 看 `BepInEx/core`、`BepInEx/plugins`、`LogOutput.log` |
| `MelonLoader/` + `version.dll` | MelonLoader | 看 `Mods/`、`UserData/`、`Latest.log` |
| `GameAssembly.dll` + `global-metadata.dat` | IL2CPP | Il2CppDumper / Cpp2IL |
| `Managed/Assembly-CSharp.dll` | Mono | dnSpy / ILSpy / ilspycmd |
| `BepInEx/interop/` | IL2CPP 互操作程序集 | 先 dump 再反编译 |

```bash
find . -maxdepth 4 \( -iname 'BepInEx' -o -iname 'MelonLoader' -o -iname 'doorstop_config.ini' \
  -o -iname 'LogOutput.log' -o -iname 'Latest.log' \) -print
file GameAssembly.dll Assembly-CSharp.dll 2>/dev/null
sha256sum winhttp.dll doorstop_config.ini 2>/dev/null
```

**判据**：能说出加载器、注入方式、插件目录、日志路径与运行时（Mono/IL2CPP），四项齐全。

## 2. 插件清单与入口

```bash
find BepInEx/plugins MelonLoader/Mods -maxdepth 2 -type f | sort
grep -RInE "BaseUnityPlugin|BepInPlugin|MelonMod|MelonInfo|OnInitializeMelon|Load\(" \
  BepInEx/plugins MelonLoader/Mods 2>/dev/null | head -60
```

- BepInEx：插件类继承 `BaseUnityPlugin`，`[BepInPlugin(guid, name, version)]` 给身份；`Awake()`/`Start()`/`Update()` 是入口。
- MelonLoader：`MelonMod` + `[MelonInfo]`；`OnInitializeMelon()` 是初始化入口。
- 先确认插件**真的被加载**：日志里有 guid/版本、`Chainloader` 输出；没有日志就不要继续猜 patch 是否生效。
- 多插件冲突看 guid、依赖 `[BepInDependency]`、加载顺序。

**判据**：入口类、注册特性、初始化方法、日志证据四者可互相对上。

## 3. 反编译与 patch 目标

```bash
# Mono
ilspycmd Assembly-CSharp.dll -o work/game-src
ilspycmd BepInEx/plugins/Mod.dll -o work/mod-src

# IL2CPP
Il2CppDumper GameAssembly.dll global-metadata.dat work/il2cpp/
ls work/il2cpp/   # dump.cs, il2cpp.h, script.json, stringliteral.json, DummyDll/
```

- 从插件里的 `HarmonyPatch(typeof(Target), nameof(Target.Method))`、`Prefix`/`Postfix`/`Transpiler` 反推目标方法。
- 目标方法再回到游戏程序集/`dump.cs` 看字段、调用链、更新频率；不要只看插件侧。
- `Transpiler` 改 IL，风险最高；优先 `Prefix`（改参数/跳过）或 `Postfix`（改返回值）。
- IL2CPP 的 `dump.cs` 是结构恢复，不是原始源码；字段偏移要再用 IDA/Ghidra 对 `GameAssembly.dll` 验证。

**判据**：能指出目标类型/方法、patch 类型、修改的字段或返回值，以及调用该方法的场景（按钮/Update/网络回调）。

## 4. 配置、资源与数据来源

```bash
find BepInEx/config MelonLoader/UserData -type f -maxdepth 2 -print 2>/dev/null
grep -RInE "ConfigEntry|Preferences|Save|Load|AssetBundle|Resources.Load" work/mod-src | head -60
```

- 配置：BepInEx `config/*.cfg`、MelonLoader `UserData/*.cfg`；看默认值、范围、是否落盘。
- 存档：先复制再解析；记录格式（JSON/二进制/加密）与写入时机。
- 资源：`AssetBundle` 看 `UnityFS` 头与 Unity 版本；加密包不要硬解，标“未解”。
- 网络：插件可能改请求/响应；把协议字节交给 `protocol-plugin`（R24），不在 Mod 层猜字段。

**判据**：插件的输入（配置/存档/网络/游戏对象）与输出（字段/UI/请求）至少各追到一层。

## 5. Harmony patch 验证

```text
1. 基线：不装插件，记录目标方法的行为/数值/日志
2. 只装插件：确认 Load/OnInitialize 日志与 patch 注册成功
3. 单点验证：在 Prefix/Postfix 打日志，确认目标方法被调用及参数
4. 改一个变量：只改一个字段/返回值，观察 UI/存档/网络差异
5. 回退：移除插件或还原文件，确认行为回到基线
```

- patch 未生效常见原因：目标方法被内联/重载签名不匹配/IL2CPP 方法名被混淆/插件未加载。
- 不要用“游戏没崩”当成功；要有目标方法调用证据与行为差异。
- 在线反作弊环境：不注入、不挂钩、不读内存；只做外部观测或离线副本。

**判据**：patch 命中日志 + 单变量行为差异 + 回退后基线恢复，三者齐全。

## 6. 最小可改单元

- **一个 Harmony patch 类 + 一个目标方法**：优先改参数/返回值，不动 Transpiler。
- **一个配置项**：能通过 cfg 开关回退，适合验证行为假设。
- **一个资源替换**：仅在授权离线副本，记录原文件哈希与替换后哈希。
- **一个插件 DLL**：只有当 patch 类无法表达时才改；需重新编译并记录依赖版本。

**判据**：改动点文件/类/方法级可指认，回退路径明确，行为差异可重复。

## 7. 失败判据与边界

- 日志显示插件未加载，且两次修正路径/版本仍失败 → 停，报加载链结论，不继续改 DLL。
- 目标方法找不到或被内联/混淆，两次换工具仍无法定位 → 标“patch 目标未定”，不猜方法名。
- IL2CPP 元数据与 `GameAssembly` 版本不匹配 → 停，换对应版本工具；错版本输出不可信。
- patch 生效但无行为差异 → 先查是否命中正确方法/字段，不叠加第二个 patch。
- 触发反作弊/封号/蓝屏 → 立即停，记录环境；不提供绕过反作弊或隐藏注入的方法。

> 关联：`references/desktop-plugins.md`、`references/electron-and-asar.md`；协议部分交 `protocol-plugin`（R24）。
