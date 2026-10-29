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

- `global-metadata.dat` 标准头：`0xFAB11BAF` + 格式版本；同一版本整数可能对应多个布局。先确认 metadata 与 native 二进制来自同一构建，再按当前工具版本/分支支持表与实际解析诊断核验；不固定 24–29，也不把 Unity 版本与 metadata 版本当一一对应。
- `dump.cs`/DummyDll 提供重建类型、字段和方法签名，通常没有原始 C# 方法体；native 方法语义仍需分析二进制。`script.json`、字符串与结构输出的字段/布局以当前工具版本为准。
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
// Frida 进程内观测会注入 agent；只在已有许可的离线测试环境使用。
const mod = Process.findModuleByName('GameAssembly.dll');
if (mod !== null) {
    const address = mod.base.add(0x123456); // 合成示例，必须换为同构建已核 RVA
    // 读取前核范围、权限与非敏感性；这里不输出内存内容。
}
```

- 离线优先：对自有进程做 minidump/`gcore`，按模块基址 + 偏移定位字段；记录模块哈希与偏移来源。
- 离线测试环境只读：仅观测已知非敏感字段；真实 Token/Key/Salt/私钥及其前缀不读取、不输出。Frida 需要注入 agent，不能宣称“未注入”；若任务要求完全不注入则选择已有外部安全观测通道。
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
- 默认不挂钩、不改内存、不加载驱动；动态验证只在获准离线环境。需要 Frida 的 agent 注入时单独说明，不能把它称为无注入；在线反作弊环境只做外部观测。
- 不传播游戏资源/密钥/账号数据；报告脱敏。
- 版本/哈希/偏移三件套必须一起写；缺一不可复现。

> 相关：`01-criteria.md`、`02-failure-criteria.md`、`03-model-pitfalls.md`、`ios-macos-artifacts.md`、`evidence-chain.md`。

## 10. 版本—哈希—偏移三件套：IL2CPP 取证的可复现单元

> 游戏客户端更新频繁。没有“三件套”的字段/偏移，第二天就作废。

| 件 | 记什么 | 怎么取 | 缺了会怎样 |
| --- | --- | --- | --- |
| 版本 | 客户端版本 + Unity 版本 + IL2CPP 元数据版本 | 包信息/`global-metadata.dat` 头 | 无法选工具/对不上 dump |
| 哈希 | `GameAssembly`/`global-metadata.dat`/bundle 的 SHA256 | `sha256sum` | 无法证明分析的是哪份 |
| 偏移 | 模块基址 + RVA/offset + 字段宽 | `script.json` + 反汇编/两次读 | 偏移漂移后结论作废 |

### 10.1 三件套的最小 JSON

```json
{
  "client_version": "1.8.3",
  "unity_version": "2022.3.21f1",
  "metadata_version": 31,
  "artifacts": {
    "GameAssembly.dll": "<sha256>",
    "global-metadata.dat": "<sha256>",
    "data.unity3d": "<sha256>"
  },
  "field": {"name": "Player.gold", "module": "GameAssembly.dll",
           "rva": "0x1A2B3C0", "width": 4, "read_count": 2,
           "verified_at": "2026-10-21T15:00:00Z"}
}
```

**判据**：`read_count>=2` 且两次值一致；`rva` 能落到 `dump.cs` 的方法/字段；`verified_at` 与版本对应。
**失败**：只写“金币在 0x…”，没有模块哈希/版本；更新后未重测。

### 10.2 偏移漂移的三种信号

1. 同一字段两次读取值不同，且不是游戏内变化（看 UI/日志）。
2. `dump.cs` 的方法地址与反汇编对不上（函数序言不匹配）。
3. 客户端更新后 `global-metadata.dat` 版本号变了。

出现任一信号 → 偏移作废，重新 dump/定位；不要“加个偏移修正”继续用。

## 11. 资源/字段的证据分级（避免把“看到”当“能改”）

| 等级 | 证据 | 可写结论 | 不可写 |
| --- | --- | --- | --- |
| G0 | 字符串/资源名 | “存在候选资源/字段” | “客户端使用它” |
| G1 | `dump.cs` 类/字段 + 反汇编地址 | “该字段由该函数读写” | “运行时可改” |
| G2 | 运行时两次读一致 + 模块哈希 | “在该版本/偏移下可观测” | “服务器接受修改” |
| G3 | 服务器下发 → 客户端 → UI/上报全链 | “字段链路可复述” | “可作弊/可刷” |

> 本域只到 G3 的“取证与关系说明”；修改/注入属于授权任务，且在线环境默认不做。

## 12. 命令与“通过长什么样”（游戏客户端复验）

```bash
APP=work/game/App.app

# 1) 引擎与元数据版本
find "$APP" -name 'Assembly-CSharp.dll' -o -name 'GameAssembly*' -o -name 'global-metadata.dat'
xxd -l 16 "$APP/Data/Managed/Metadata/global-metadata.dat" 2>/dev/null

# 2) 哈希三件套
find "$APP" -type f \( -name 'GameAssembly*' -o -name 'global-metadata.dat' -o -name '*.unity3d' \) \
  -exec sha256sum {} \;

# 3) IL2CPP dump（版本必须匹配）
Il2CppDumper "$APP/GameAssembly.dylib" "$APP/Data/Managed/Metadata/global-metadata.dat" out/
head -20 out/dump.cs
jq '.[0:3]' out/script.json 2>/dev/null

# 4) AssetBundle 头
xxd -l 32 "$APP/Data/data.unity3d" 2>/dev/null
```

**通过长什么样**：

| 检查 | 通过 | 不通过 |
| --- | --- | --- |
| 引擎 | 能找到 Mono 或 IL2CPP 标志文件 | 两者都无 → 包不完整 |
| 元数据 | magic `af 1b b1 fa` + 版本 | magic 错 → 非标准/加密 |
| 哈希 | 三件套齐全 | 缺哈希 → 不可复现 |
| dump | `dump.cs` 有类/字段，`script.json` 有地址 | 空表 → 版本错配 |
| 资源 | 头为 `UnityFS/UnityWeb/UnityRaw` | 其他 → 加密/非 Unity |

## 13. Mono / AssetBundle 的交叉判据（别只看一条链）

| 现象 | 先查 | 判据 | 误判 |
| --- | --- | --- | --- |
| 有 `Managed/` 但没有 `Assembly-CSharp.dll` | 是否 IL2CPP + DummyDll | 看 `GameAssembly`/元数据 | 直接写“Mono 被裁剪” |
| `dump.cs` 有字段但运行时读不到 | 偏移/版本/模块基址 | 三件套 + 两次读 | 写“字段不存在” |
| AssetBundle 能解但资源对不上 | `manifest`/Catalog/加载代码 | 资源名 ↔ 类/方法 ↔ 运行时对象 | 写“资源无关” |
| 字段值在 UI 可见但抓包无 | 本地计算/缓存/默认值 | 服务器下发 → 客户端 → UI | 写“服务器不校验” |

### 13.1 交叉验证的最小组合

```text
组合 A：dump.cs 字段 + 反汇编读写点 + 运行时两次值
组合 B：bundle 资源名 + 代码 LoadAsset + 运行时对象名
组合 C：pcap 下发字段 + 客户端解析方法 + UI 显示
```

任一组合三段齐全 = G3；缺一段 = G2/G1；只有静态 = G0/G1。

### 13.2 不做的三件事

1. 不把“资源解出来”当“客户端会加载它”（可能死资源/AB 测试）。
2. 不把“内存值”当“服务器值”（可能本地预测/缓存）。
3. 不把“离线副本可改”当“线上可改”（反作弊/校验/服务器权威）。

## 14. 版本更新后的复核清单（防止旧结论污染新包）

- [ ] 重新算三件套哈希，与旧值对比；任一变化 → 旧偏移/字段全部作废。
- [ ] 重读元数据版本；与 `GameAssembly`/`UnityFramework` 对应。
- [ ] 重跑 `Il2CppDumper`，确认 `dump.cs` 非空且地址落在代码段。
- [ ] 重验一次字段偏移（两次读一致），记录新 `verified_at`。
- [ ] 检查 AssetBundle 头/版本是否变化；旧导出清单标“过期”。
- [ ] 把旧结论标 `superseded`，不要删除历史（审计需要）。

## 15. 交付边界

| 可交付 | 不可交付 |
| --- | --- |
| 字段/资源/协议的关系说明 | 可用的作弊/注入工具 |
| 版本-哈希-偏移三件套 | 未脱壳二进制的逻辑断言 |
| 离线/授权环境的只读观测 | 在线环境的 attach/写内存 |
| 检测点与证据链 | 游戏资源/账号数据的传播 |

## 这一篇算"用对了"吗

- [ ] 我的每个字段/偏移都带“客户端版本 + 模块哈希 + 偏移 + 验证时间”
- [ ] 我区分了 G0–G3，没有把“内存里看到值”写成“可修改/可作弊”
- [ ] 我的 IL2CPP 元数据版本与二进制匹配，错配时停而不是硬 dump
- [ ] 资源解不开时我只写“未解/加密候选”，没有写“没有该资源”
- [ ] 在线环境我只做外部观测，没有 attach/注入/读内存
- [ ] 我的四段链路（服务器→客户端→偏移→UI）至少三段有 observed
