# 游戏客户端：Unity Mono / IL2CPP / AssetBundle 取证链路

> **范围**：Unity 客户端（PC/移动/主机）的 `Assembly-CSharp.dll`、`GameAssembly`/`UnityFramework`、`global-metadata.dat`、`*.unity3d`/AssetBundle、运行时字段观测。
> 路由：本域做取证与关系说明；在线反作弊对抗、注入/挂钩/改内存、盗号/外挂按对应授权任务执行；非 Unity 引擎的通用逆向由 `softseep` 承担。
> 目标：把“服务器下发 → 客户端字段 → 二进制/元数据 → 资源/内存偏移 → UI/上报”连成一条可复述的链。

## 1. 判断 Mono 还是 IL2CPP

```bash
find App.app -name 'Assembly-CSharp.dll' -o -name 'global-metadata.dat' -o -name 'GameAssembly*'
find App.app -name 'Managed' -type d
find App.app -name '*.unity3d' -o -name '*.bundle' -o -name 'data.unity3d'
```

| 现象 | 结论 | 下一步 |
|---|---|---|
| `Managed/Assembly-CSharp.dll` 存在 | Mono | `ilspycmd`/`monodis` 反编译 |
| 只有 `GameAssembly.dll`/`UnityFramework` + `global-metadata.dat` | IL2CPP | Il2CppDumper/Cpp2IL |
| `Managed/` 只有 `mscorlib.dll`/`UnityEngine.*.dll` | IL2CPP 的 DummyDll 或裁剪 | 找 `GameAssembly`/元数据 |
| `data.unity3d`/`*.bundle` | 资源容器 | AssetStudio/UnityPy |

## 2. Mono：先落字段，再谈逻辑

```bash
ilspycmd Assembly-CSharp.dll -o decompiled/
monodis --assembly Assembly-CSharp.dll
grep -R "class .*Player\|void Update\|OnGUI\|SendMessage" -n decompiled/ | head
```

- 先找数据模型（玩家/背包/货币/等级/协议），再找序列化（JSON/Protobuf/自定义）。
- 字段名、类型、默认值要与抓包/存档对上；只看到 `int gold` 不代表“金币可改”。
- 依赖缺失时用同目录 `UnityEngine.*.dll`/`mscorlib.dll` 补；仍失败标 `tool-missing`。

判据：能定位“数值/协议/存档字段对应的类与方法”，并说明它在哪个场景被读写。

## 3. IL2CPP：元数据与二进制必须匹配

```bash
xxd -l 32 global-metadata.dat
# 期望 magic af 1b b1 fa + version(u32)
Il2CppDumper GameAssembly.dll global-metadata.dat out/
ls out/   # dump.cs、il2cpp.h、script.json、stringliteral.json、DummyDll/
```

- `global-metadata.dat` 头：`0xFAB11BAF` + 版本号；版本必须与 `GameAssembly`/`UnityFramework` 的 Unity 版本匹配。
- `dump.cs` 给类型/方法/字段；`script.json` 给函数地址；`stringliteral.json` 给字面量；`il2cpp.h` 给 IDA/Ghidra 结构。
- 地址落地：在 IDA/Ghidra 里按 `script.json` 的 `Address`/`RVA` 跳转，核对函数边界与调用约定。
- 更新后偏移会漂移：必须记录客户端版本、哈希、Unity 版本、工具版本；旧 `dump.cs` 不能直接套新包。

判据：`dump.cs` 的字段/方法与二进制地址、运行时内存值三者能对齐；缺地址或版本不符就标 `unverified`。

## 4. AssetBundle：头、版本、资源清单

```bash
xxd -l 64 data.unity3d
# 期望 UnityFS/UnityWeb/UnityRaw + format version + Unity version/revision
AssetStudioModCLI data.unity3d -o export/
# 或 AssetRipper / UnityPy
```

- 头正确只说明容器格式；加密/自定义压缩/版本差异会让资源解析失败。
- 导出后核对 `CAB-*`、Texture2D、TextAsset、AudioClip、Mesh 与 `manifest` 的对应关系。
- `TextAsset` 常含配置/协议/脚本；先看大小/编码/哈希，再决定是否反序列化。
- 资源属于哪个 bundle、被谁引用、运行时如何加载：用 `manifest`/`Catalog`/代码里的 `LoadAsset` 交叉。

判据：能说明“资源属于哪个 bundle、被哪个类/方法加载、运行时对应哪个对象”；解不开就标“未解”，不写“没有”。

## 5. 运行时只读观测（离线/授权）

```javascript
// Frida：只读枚举模块与内存扫描，不写、不挂钩、不注入
Process.enumerateModules().filter(m => /GameAssembly|UnityFramework/.test(m.name))
Memory.scan(Module.findBaseAddress('GameAssembly.dll').add(0x123456), 0x100, '41 42 43 44')
```

- 离线优先：对自有进程做 minidump/`gcore`，按模块基址 + 偏移定位字段；记录模块哈希与偏移来源。
- 在线只读：只枚举模块/读已知特征（金币数、等级、token 前缀），**不写、不挂钩、不注入**；能外部抓包就不 attach。
- 字段链路：服务器下发（pcap）→ 客户端解析（dump.cs/方法）→ 内存偏移（模块+offset）→ UI/上报（日志/抓包）。
- 偏移会随版本/平台/编译变化；必须写“客户端版本 + 模块哈希 + 偏移 + 验证时间”。

判据：四段链路至少三段 observed；缺一段标 `inferred`，不能把“内存里看到 999999”当“可以改”。

## 6. 反作弊存在时的边界

- 识别 EAC、BattlEye、Vanguard、mhyprot 等内核态/用户态组件：看进程、驱动、服务、启动参数。
- **在线环境只做外部观测**：抓包、日志、公开客户端文件、录屏；不 attach、不注入、不读进程内存、不调试。
- 动态分析用离线副本/私服/授权测试服；报告写明环境差异，不把离线结论当线上结论。
- 触发风控/封号/蓝屏风险时立即停，记录时间、环境、触发点；这本身是证据。

判据：动作可审计；可能触发反作弊就停止并记录原因，而不是“小心一点继续”。

## 7. 资源/字段对照表（交付形态）

| 链路 | 证据 | 机检 |
|---|---|---|
| 服务器下发 | pcap 会话 + 字段偏移 | `tshark -T fields` + 对象哈希 |
| 客户端解析 | `dump.cs` 类/方法/字段 | 方法名/字段名/类型 |
| 二进制地址 | `script.json` Address/RVA | IDA/Ghidra 跳转截图/地址 |
| 运行时值 | 模块基址 + offset | 两次读取一致 + 版本/哈希 |
| UI/上报 | 日志/抓包/截图 | 时间 + 对象 + 值 |

## 8. 失败判据

- `Managed/` 缺 `Assembly-CSharp.dll` 且找不到 `GameAssembly`/元数据 → 包不完整/裁剪，停。
- `global-metadata.dat` 版本与二进制不匹配 → 换工具/版本；仍不行标 `tool-missing`，不输出垃圾表。
- AssetBundle 头不是 `UnityFS/UnityWeb/UnityRaw` → 可能加密/非 Unity；只做熵/字符串。
- 运行时偏移两次读取不一致/版本变了 → 偏移作废，重新定位。
- 在线出现反作弊/内核保护 → 停 attach/读内存，转外部观测。
- 只有内存值、没有服务器/字段/上报链路 → 结论降为 `inferred`，不写“可修改/可作弊”。

## 9. 边界

- 只做取证与关系说明：产物是检测点、设备状态与行为证据。
- 不注入、不挂钩、不改内存、不加载驱动；动态验证只在离线副本/授权测试服。
- 不传播游戏资源/密钥/账号数据；报告脱敏。
- 版本/哈希/偏移三件套必须一起写；缺一不可复现。

> 相关：`01-criteria.md`、`02-failure-criteria.md`、`03-model-pitfalls.md`、`ios-macos-artifacts.md`、`evidence-chain.md`。
