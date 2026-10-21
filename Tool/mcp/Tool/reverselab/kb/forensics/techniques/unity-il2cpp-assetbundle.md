# Unity IL2CPP / AssetBundle：元数据、二进制与资源

> **入口信号**：`global-metadata.dat`、`GameAssembly`/`UnityFramework`、`*.unity3d`/`*.bundle`、`Assembly-CSharp.dll`。
> **不适用**：在线反作弊对抗、注入/挂钩/改内存；非 Unity 引擎逆向（走 `softseep`）。

## 1. 判 Mono/IL2CPP

```bash
find App.app -name 'Assembly-CSharp.dll' -o -name 'global-metadata.dat' -o -name 'GameAssembly*'
find App.app -name '*.unity3d' -o -name '*.bundle'
xxd -l 32 global-metadata.dat     # 期望 af 1b b1 fa + version
xxd -l 64 data.unity3d           # 期望 UnityFS/UnityWeb/UnityRaw
```

## 2. IL2CPP

```bash
Il2CppDumper GameAssembly.dll global-metadata.dat out/
ls out/   # dump.cs / il2cpp.h / script.json / stringliteral.json / DummyDll/
```

- 元数据 magic `0xFAB11BAF` + 版本；必须与 `GameAssembly`/Unity 版本匹配。
- `dump.cs` 字段/方法 + `script.json` 地址 + 运行时值三者对齐。
- 版本/哈希/偏移三件套一起记录；更新后偏移会漂移。

## 3. AssetBundle

```bash
AssetStudioModCLI data.unity3d -o export/
# 或 AssetRipper / UnityPy
```

- 头正确只说明容器格式；加密/自定义压缩/版本差异会失败。
- 导出后核对 `CAB-*`、Texture2D、TextAsset、AudioClip、Mesh 与 manifest。
- 解不开就标“未解”，不写“没有该资源”。

## 4. 确认/失败判据

确认：

- 元数据版本与二进制匹配；`dump.cs` 地址能落到反汇编。
- 资源属于哪个 bundle、被谁加载、运行时对应哪个对象。
- 字段链路：服务器下发 → 客户端字段 → 内存偏移 → UI/上报。

失败：

- 版本不匹配 → 换工具/版本；仍不行 `tool-missing`。
- 头不是 UnityFS/UnityWeb/UnityRaw → 可能加密/非 Unity。
- 运行时偏移两次不一致 → 偏移作废。
- 在线反作弊 → 停 attach，转外部观测。

## 5. 边界

- 只做取证与关系说明；不提供外挂/破解/绕过反作弊。
- 不注入/不挂钩/不改内存；动态验证只在离线副本/授权测试服。
- 相关：`Tool/skill/forensics-mobile/references/game-client-il2cpp.md`、`01-criteria.md`。
