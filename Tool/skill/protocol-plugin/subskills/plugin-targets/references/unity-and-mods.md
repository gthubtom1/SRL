# Unity Mod：BepInEx / MelonLoader / IL2CPP / Harmony

> 范围：Unity 游戏的 BepInEx/MelonLoader 插件、Mono `Assembly-CSharp.dll`、IL2CPP `GameAssembly.dll` + `global-metadata.dat`、Harmony patch。
> 路由：Unity 资源包/AssetBundle 的纯格式解析用 AssetStudio 等专用工具；在线反作弊绕过按对应授权任务执行；纯协议复刻由 `protocol-plugin`（R24）承担。
> 目标：**插件类 → patch 目标 → 修改的字段/返回值 → 可观察效果**；只在自有或明确授权的离线副本/测试服操作。

## 1. 先判运行时与加载器

| 信号 | 结论 | 下一步 |
|---|---|---|
| `winhttp.dll` + `doorstop_config.ini` | BepInEx（Doorstop 注入） | 看 `BepInEx/core`、`BepInEx/plugins`、`LogOutput.log` |
| `MelonLoader/` + `version.dll` | MelonLoader | 看 `Mods/`、`UserData/`、`Latest.log` |
| `GameAssembly.dll` + `global-metadata.dat` | IL2CPP | Il2CppDumper / Cpp2IL |
| `Managed/Assembly-CSharp.dll` | Mono | dnSpy / ILSpy / ilspycmd |
| `BepInEx/interop/` | IL2CPP 互操作程序集 | 先 dump 再反编译 |
| `BepInEx/config/*.cfg` | 插件配置 | 看默认值、范围、落盘 |

```bash
find . -maxdepth 4 \( -iname 'BepInEx' -o -iname 'MelonLoader' -o -iname 'doorstop_config.ini' \
  -o -iname 'LogOutput.log' -o -iname 'Latest.log' \) -print
file GameAssembly.dll Assembly-CSharp.dll 2>/dev/null
sha256sum winhttp.dll doorstop_config.ini 2>/dev/null
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py --path . --json   # unity 字段
```

**判据**：能说出加载器、注入方式、插件目录、日志路径与运行时（Mono/IL2CPP），五项齐全。

## 2. 插件清单与入口

```bash
find BepInEx/plugins MelonLoader/Mods -maxdepth 2 -type f | sort
python Tool/skill/_pending/plugin-targets/scripts/plugin-repro.py --path . --out work/repro --json
```

- BepInEx：插件类继承 `BaseUnityPlugin`，`[BepInPlugin(guid, name, version)]` 给身份；`Awake()`/`Start()`/`Update()` 是入口；`[BepInDependency]` 决定加载顺序。
- MelonLoader：`MelonMod` + `[MelonInfo]`；`OnInitializeMelon()`/`OnUpdate()`/`OnGUI()` 是入口。
- 先确认插件**真的被加载**：日志里有 guid/版本、`Chainloader` 输出；没有日志就不要继续猜 patch 是否生效。
- 多插件冲突看 guid、依赖、加载顺序；同 guid 的两个 DLL 只有一个会加载。

**判据**：入口类、注册特性、初始化方法、日志证据四者可互相对上。

## 3. IL2CPP 与 Mono 的工具链差异

| 项 | Mono | IL2CPP |
|---|---|---|
| 程序集 | `Managed/Assembly-CSharp.dll` 等 | `GameAssembly.dll` + `global-metadata.dat` |
| 反编译 | dnSpy/ILSpy/ilspycmd 直接读 | 先 Il2CppDumper/Cpp2IL 恢复 `dump.cs`/DummyDll |
| 方法体 | 真实 IL | `dump.cs` 多为结构/占位；关键方法回二进制看 |
| 字段偏移 | 元数据/反射可得 | 需 IDA/Ghidra 对 `GameAssembly.dll` 验证 |
| 泛型/异步 | 相对可读 | 状态机/泛型实例化更复杂 |
| 版本敏感 | 低 | `global-metadata.dat` 必须与 `GameAssembly.dll` 同版本 |

```bash
# Mono
ilspycmd Managed/Assembly-CSharp.dll -o work/game-src
# IL2CPP
Il2CppDumper GameAssembly.dll global-metadata.dat work/il2cpp/
ls work/il2cpp/    # dump.cs, il2cpp.h, script.json, stringliteral.json, DummyDll/
```

- IL2CPP 元数据与二进制版本不匹配 → 输出不可信，按 `02-failure-criteria.md` 第 18 条停。
- `dump.cs` 是结构恢复，不是原始源码；方法体/偏移要回二进制验证。
- 混淆/裁剪会改类名/方法名；用字符串、RVA、调用关系交叉定位，不要只靠名字。

**判据**：能指出目标类型/方法在哪种程序集/恢复产物中，以及是否需要回二进制验证偏移。

## 4. Harmony patch 目标

```bash
grep -RInE "HarmonyPatch|Harmony\.Patch|Prefix|Postfix|Transpiler|BaseUnityPlugin|MelonMod" work/mod-src | head -80
```

- `[HarmonyPatch(typeof(Target), nameof(Target.Method))]` 给出目标类型/方法；`Prefix`/`Postfix`/`Transpiler` 是 patch 类型。
- 目标方法要回到游戏程序集（Mono）或 `dump.cs`（IL2CPP）确认存在、签名、调用场景。
- `Transpiler` 改 IL，风险最高；优先 `Prefix`（改参数/跳过）或 `Postfix`（改返回值）。
- 目标方法可能被内联/重载/泛型实例化；名字对上不等于 patch 命中。
- 同一个方法多个 patch 时注意执行顺序与冲突。

**判据**：能指出目标类型/方法、patch 类型、修改的字段或返回值，以及调用该方法的场景（按钮/Update/网络回调）。

## 5. 配置、资源与数据来源

```bash
find BepInEx/config MelonLoader/UserData -maxdepth 2 -type f -print 2>/dev/null
grep -RInE "ConfigEntry|Preferences|Save|Load|AssetBundle|Resources.Load" work/mod-src | head -60
```

- 配置：BepInEx `config/*.cfg`、MelonLoader `UserData/*.cfg`；看默认值、范围、是否落盘。
- 存档：先复制再解析；记录格式（JSON/二进制/加密）与写入时机。
- 资源：`AssetBundle` 看 `UnityFS` 头与 Unity 版本；加密包不要硬解，标“未解”。
- 网络：插件可能改请求/响应；把协议字节交给 `protocol-plugin`（R24），不在 Mod 层猜字段。

**判据**：插件的输入（配置/存档/网络/游戏对象）与输出（字段/UI/请求）至少各追到一层。

## 6. patch 验证流程

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

## 7. 最小可改单元

- **一个 Harmony patch 类 + 一个目标方法**：优先改参数/返回值，不动 Transpiler。
- **一个配置项**：能通过 cfg 开关回退，适合验证行为假设。
- **一个资源替换**：仅在授权离线副本，记录原文件哈希与替换后哈希。
- **一个插件 DLL**：只有当 patch 类无法表达时才改；需重新编译并记录依赖版本。

**判据**：改动点文件/类/方法级可指认，回退路径明确，行为差异可重复。

## 8. Lua / 脚本 Mod

热更新型游戏常把逻辑放 Lua：桥接层是 C#↔Lua（`xlua`/`tolua#`/`slua`）、原生 LuaJIT + 自研绑定，或纯托管解释器（MoonSharp）。

| 桥 | 识别 | 信任边界 |
|---|---|---|
| `xlua`/`tolua#`/`slua` | `xlua.dll`/`XLua.LuaDLL`、生成 `*Wrap.cs`、`LuaEnv`/`LuaState`/`luaenv.DoString` | 绑定表决定 Lua 能看到的 C# 类型；能拿到 `CS.*` 即等于全引擎 API |
| LuaJIT 原生 | `lua51.dll`/`libluajit`、`luaL_loadbufferx` | 一旦开 `ffi.cdef` 可任意读写进程内存，沙箱失效 |
| MoonSharp | 纯托管、无原生 DLL | 可限制 `io/os`，但默认仍能读文件 |

```bash
strings -n 6 GameAssembly.dll | grep -iE 'xlua|tolua|slua|luajit|luaL_' | sort -u | head
grep -RInE "package\.path|package\.cpath|require\(|loadstring|dofile|debug\.sethook" Mods/ | head -40
```

- `require` 的解析顺序由 `package.path` 决定；Mod 加载器通常把 `Mods/<name>/?.lua` **前插**，于是同名模块可被覆盖（模块劫持），也能从可写目录加载任意 `.lua`。
- `package.cpath` 前插 + `require` 原生库 = 加载任意 `.dll/.so`；`loadstring`/`load`/`dofile` 是运行期动态代码，静态清单里看不到内容。
- 沙箱边界看三件事：`io`/`os`（`os.execute`、`io.open`）、`debug`（`sethook`/`getinfo` 可改或读其他脚本）、桥暴露的宿主 API 名单。任一开放 = Mod 拥有进程同等权限。
- 加载器信任边界：目录扇描（放进去就加载）vs 清单白名单（`mods.json`/`enabled.txt`）；看加载顺序、同名覆盖、是否校哈希。

**判据**：`lua.bridge` 可枚举；`lua.package_path_entries[]` 含 Mod 可写目录；`lua.dangerous_api[]`（`io|os|debug|ffi`）与调用点 file/line 对应；`lua.loader_mode` ∈ `{scan,manifest}`。

**失败判据**：只有 `.lua` 文本没有桥/宿主 → 只给静态脚本面，不写“可执行任意命令”；Lua 编译成字节码（`\x1bLua`）→ `unverified`；`package.path` 运行时拼接 → 标“解析不确定”；FFI/`debug` 开放但未见调用 → 写“能力存在”，不写“已利用”。

## 9. 失败判据与边界

- 日志显示插件未加载，且两次修正路径/版本仍失败 → 停，报加载链结论，不继续改 DLL。
- 目标方法找不到或被内联/混淆，两次换工具仍无法定位 → 标“patch 目标未定”，不猜方法名。
- IL2CPP 元数据与 `GameAssembly` 版本不匹配 → 停，换对应版本工具；错版本输出不可信。
- patch 生效但无行为差异 → 先查是否命中正确方法/字段，不叠加第二个 patch。
- 触发反作弊/封号/蓝屏 → 立即停，记录环境；反作弊校验按校验层归档。
- 插件内协议/分帧 → 交 `protocol-plugin`（R24）。

> 关联：`references/desktop-plugins.md`（原生桌面插件）、`references/electron-and-asar.md`（Electron 边界）、`references/02-failure-criteria.md` 第 16–18 条。
