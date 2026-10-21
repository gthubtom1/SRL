# 托管运行时授权面

托管/半托管运行时的授权校验位置与可观测判据：.NET IL、Java 字节码、Python 字节码、
WebAssembly。重点是"校验点在哪、用什么字段证明、什么时候结论不成立"，不是给成品补丁。

## 逐篇索引

| 篇目 | 覆盖 | 关键字段 |
| :--- | :--- | :--- |
| [`techniques/2026-dotnet-license.md`](techniques/2026-dotnet-license.md) | dnSpy/ILSpy、`Assembly-CSharp`、ConfuserEx 与校验点 | `il_method` `obfuscator` |
| [`techniques/2026-java-license.md`](techniques/2026-java-license.md) | `javap -p -c`、ProGuard mapping、`META-INF` 签名 | `jar_manifest` `proguard_map` |
| [`techniques/2026-python-bytecode.md`](techniques/2026-python-bytecode.md) | `pycdc`、`.pyc` 魔数、PyInstaller 提取 | `pyc_magic` `pyi_archive` |
| [`techniques/2026-wasm-license.md`](techniques/2026-wasm-license.md) | wabt/wasm2c、函数边界与常量 | `wasm_sections` `func_count` |

## 分析链

```text
识别运行时（文件头/魔数/节名）→ 反编译到可读单元（方法/类/函数）
  → 定位校验点（签名/哈希/到期/绑定）→ 记录字段 → 失败判据复核 → 结论
```

## 判据统一口径

- 每个结论落到字段：`il_method`、`obfuscator`、`jar_manifest`、`proguard_map`、
  `pyc_magic`、`pyi_archive`、`wasm_sections`、`func_count`。
- "反编译失败"不是"没有校验"：先换工具/换版本，再谈结论。
- 授权校验可能在线（服务端签发）也可能离线（本地签名）；只看到本地分支不代表全部。

## 边界

- 仅分析自有/授权软件；用于互操作、兼容性、漏洞报告与授权审计。
- 不提供破解补丁、不发布绕过授权/激活的成品、不分发被修改的二进制。
- 反编译产物只用于定位问题；引用代码片段需最小化并注明来源版本。

## 相关

- iOS/移动侧授权与签名：`../ios/README.md`
- PE 侧授权与 VM 保护：`../pe-reverse/README.md`、`../windows/techniques/2026-vmp-ultralock.md`
- Unity IL2CPP（无 IL）路线：`../field_journal_seed-014_unity-il2cpp-reverse.md`
