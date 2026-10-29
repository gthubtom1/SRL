---
name: il2cpp-dump
description: "Unity IL2CPP 同构建元数据与二进制配对、工具支持核验、类型与地址映射；不把 dump.cs 当作原始方法体。"
metadata:
  version: "2.1.0"
  target_runtimes: "Android / Windows Unity；iOS 采集由 forensics-mobile 协作"
---

# IL2CPP 类型、符号与地址恢复

本子技能的目录归属是 Android 方法维护位置，Windows Unity 可由 softseep 主导引用，iOS 由 forensics-mobile 主导。它补充条件式分析路线，不代表每个平台或所有 Unity 构建已经实测。

复用 [运行时分类](../../references/framework-runtimes.md)、[PC Unity 深度方法](../../../softseep/subskills/exe-reverse/references/unity-il2cpp.md)、[Unity 取证与版本绑定](../../../forensics-mobile/references/game-client-il2cpp.md)。输入应包含同一构建、同一平台/ABI 的 `libil2cpp.so` / `GameAssembly.dll` / `UnityFramework`、metadata、Unity 版本线索与各文件 SHA256；split 包须收齐实际使用的 ABI 成员。

## 识别与版本核验

程序集存在不一定证明运行 Mono，可能是 DummyDll/工具产物；用包来源、加载模块和代码格式共同判断。标准 metadata 头通常为小端魔数 `AF 1B B1 FA`，后接版本。魔数不符也可能是截断、外层容器、错文件、头替换或定制布局，不能直接断言加密。

元数据整数版本与 Unity 发行版本不是一一对应；同一整数可能有不同布局。记录所用 Il2CppDumper/Cpp2IL/Il2CppInspector 的具体版本/分支、release 支持表和实际解析诊断。不能固定只接受 24–29，也不能因工具宣传支持某个新版本就推断本地分支支持。未知版本保留 unsupported，不能强改版本号绕解析错误。

标准配对且当前 Il2CppDumper 入口支持时，从源码根可用以下 CLI 形态（可执行文件名按安装方式展开）：

```bash
Il2CppDumper work/input/libil2cpp.so work/input/global-metadata.dat work/il2cpp-out
```

先核可执行身份与参数；本指南没有证明该工具已安装/可加载。二进制是内存 dump 时，文件布局、重定位及基址选项必须按该工具版本核实，不能直接作为原盘 ELF 使用。

## 保护分支

定位元数据加载器和实际解密/转换点，再决定能否在已获运行确认的设备取非敏感代码/元数据。扫描魔数只提供候选；按该版本所有 offset/count 字段、表项大小、字符串与索引范围核边界。不能由 stringOffset 或 metadataUsageListsOffset 两项猜整体长度：字段随版本变化，表也可能分离加载。缺完整范围/布局时保留碎片，不能扩大读取到凭据区。

## 输出的含义

- `dump.cs` / DummyDll：类型、字段、方法签名与部分地址注释的重建，通常没有原始 C# 方法体；不等于源码恢复。
- `script.json` / `il2cpp.h`：具体工具版本的地址和类型输出；字段名、结构和脚本消费方式须核对，不能假设 JSON 一定是数组或含固定 RVA 键。
- `stringliteral.json`：工具导出的字面量候选及其关联信息，不证明收集了应用全部字符串或全部引用。

批量导入前备份 IDA/Ghidra 工程，用与工具版本配套的脚本；脚本可能随工具分发而非在输出目录生成。核脚本的 Python/Ghidra API、输入格式与重定位基址，先在少数关键方法测试。泛型共享、内联、裁剪、混淆和 thunk 会影响一对一映射，不能设 90% 重命名为普适验收线。

## 正反例与交付

正例：选定业务方法签名、native 地址、调用关系和可取得的行为证据互相对应，记录已映射/歧义/缺失方法。反例：`dump.cs` 很大但来自旧版本，或 RVA 指向非代码区；不能认定恢复成功。空表也可能是工具/配对/布局错误，不证明业务不存在。

按任务验收：结构报告要求来源、版本、地址和限制；算法恢复另需 native 方法分析与合成输入输出对照；修改成品另走平台安装/功能回归。无设备可交静态结果，不能补写运行见证。同形失败两次重判。将地址映射、工具诊断和输出哈希返回同一 project/version/run，旧构建符号不套入当前构建。
