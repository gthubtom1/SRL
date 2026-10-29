---
name: dex-unpack
description: "Android 加固分类、DEX 内存候选验证与条件式 CodeItem 恢复；绑定 ART/DEX 版本，区分骨架、真实方法体和可运行 APK。"
metadata:
  version: "2.1.0"
  target_runtimes: "Android ART；版本、ABI、设备与工具须逐案确认"
---

# DEX 转储与方法体恢复

输入包括完整 APK/split 集、构建身份、Android/ART 版本与实际 ABI；动态路线另需已确认可运行的测试设备。无设备可完成盘上分类和已提供 dump 的静态校验，不能声称运行时恢复完成。

按顺序复用 [加固分类](../../references/packers.md)、[深度脱壳索引](../../references/advanced-unpacking.md)、[形态与主动触发](../../references/advanced-unpacking-1-shapes-and-active-invocation.md)、[root 转储与 VMP 边界](../../references/advanced-unpacking-2-root-dump-and-vmp-boundary.md)。JNI/Java2C 读 [实现归属](../../references/java2c-and-jni-sinking.md)，分包读 [split APK](../../references/split-apk.md)。商业壳库名可能随版本变化或只是普通依赖，须以加载器、DEX 与 native 行为共同判断。

## 先区分四种结果

1. 完整 DEX 容器且关键方法有真实指令：继续核对调用与业务覆盖。
2. 容器可解析但方法是 return/nop/throw 骨架：需要方法级恢复，重复整段 dump 不能保证补齐。
3. `native` 方法在 SO 中实现：查 JNI 导出或 RegisterNatives；abstract/native 方法合法地没有 CodeItem，`code_off=0` 不能单独判抽取。
4. 私有操作码/VMP 或 Java2C：转解释器/native 分析，不能承诺恢复原 Dalvik 方法。

`stub%`/`emptied%` 是线索，有正常空实现，也存在统计盲区；低比例不能证明方法体完整。与同构建候选及关键方法逐一比较，保留恢复覆盖和未知项。

## 获取与结构验证

ART 的 DexFile OpenMemory/OpenCommon、ClassLinker 与 ArtMethod 布局随 Android 版本及厂商构建变化，可能不导出；先核对符号、原型、ABI、映射范围和一个已知方法，不能用固定参数序号或偏移直接读内存。JIT/AOT/Nterp 路线不一定经过旧解释器 hook。

已有区域导出后，从源码根使用：

```bash
python Tool/skill/apkseep/scripts/dex_mem_scan.py work/regions --dump work/dex-candidates --json
python Tool/skill/apkseep/scripts/dex_dump_validate.py work/dex-candidates --find 'Lcom/example/app/' --json
```

这些脚本的扫描/解析版本支持是有限的；其拒绝不证明目标没有 DEX。确认是页对齐尾部余量时才考虑验证器的 `--trim`；短于声明大小、跨不可读区或来源不明的片段不能补零冒充完整文件。按 SHA256 去重，保留原始区域与裁剪映射。转储前排除真实秘密区域，不采集用户凭据。

## 有界主动触发与修复

优先用正常 UI/测试入口触发指定功能。只有已理解参数、线程、初始化与副作用的目标方法才进入白名单；不反射执行所有类/构造器/方法，不把异常视作安全证明。FART/Youpk 属特定运行时方法，有额外环境依赖，仓内参考不能证明当前设备可用。

回填记录必须绑定 dex 哈希、method_idx、原 code_off、采集时机与真实 CodeItem。长度包括指令、必要 padding、try_item 和变长 catch_handler，不能只复制 insns。空间或布局变化须由版本匹配的重建器更新引用，不能覆盖邻接项。

保留实际 DEX magic/版本，不强制降成 035；CompactDex、较新容器及偏移语义需对应工具支持。对传统独立 DEX，SHA-1 覆盖 `[0x20, EOF)`，写 signature 后 Adler32 覆盖 `[0x0c, EOF)`；重算不能修复缺失代码或不合法结构。复用 `../../scripts/dexutil.py` 及 [字节修补规则](../../references/byte-level-patching.md)，按其支持范围操作副本。

## 正反例与验收

正例：同版本容器可解析，选定方法的真实指令、异常表和调用关系与观察一致，独立反汇编/反编译交叉验证。反例：035 头和校验和都正确，但目标方法全是 throw；只能称“骨架”。JADX 能显示类名不证明逻辑完整，方法总数相等也不证明恢复正确。

交付恢复/未触发/不可恢复方法清单及证据，不定任意全量百分比。重包交付另走 [签名安装](../../references/repack-and-sign.md) 与 [功能验证](../../references/verification.md)，静态 dump 不证明 APK 可安装。两次同形失败回分类。native 问题交 softseep、协议交 protocol-plugin，输入和返回输出归同一 project/version/run。
