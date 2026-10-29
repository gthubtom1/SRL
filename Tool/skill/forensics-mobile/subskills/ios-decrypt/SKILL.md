---
name: ios-decrypt
description: "iOS Mach-O 加密范围识别、受控设备明文采集条件、文件偏移/VA 映射与解析验收；cryptid=0 不等于完成。"
metadata:
  version: "2.1.0"
  target_runtimes: "真实兼容 iOS 测试设备；macOS 工具按实际可用性核验"
---

# iOS 明文采集与 Mach-O 验证

输入是同构建 IPA/App、架构与 UUID、目标问题，以及用户可提供的测试设备/采集条件。复用 [iOS/macOS 制品](../../references/ios-macos-artifacts.md)、[证据链](../../references/evidence-chain.md)，native 分析可请 [softseep](../../../softseep/SKILL.md)。设备/平台缺失时可以完成包结构、签名与加密范围报告，动态采集保持 blocked。

## 平台前提

Windows 当前环境不能默认有 `otool`、`lipo`、codesign 或可用 iOS 设备；先查工具能力、系统版本和实际连接。App Store 设备构建通常不能直接在 iOS Simulator 运行，模拟器不能替代 FairPlay 的设备解密条件。非越狱设备的开发调试或 Gadget 路线也不能自动视为可采集 App Store 加密程序；工具、签名、权限和版本兼容逐案核实。

frida-ios-dump 等外部方案需要与设备系统、Frida、连接和权限匹配；先固定工具提交与帮助，不把网上 SSH/iproxy 参数视为通用。账号和 SSH 凭据由用户自己操作，不进入 Agent、命令行记录或项目。取得进程列表只证明连接，不证明目标可采集；运行客户目标需已有运行确认。

## 加密状态只是范围线索

在实际 macOS 分析环境可用只读命令：

```bash
otool -l work/App.app/App
lipo -info work/App.app/App
```

检查每个 FAT slice 的 Mach-O 头、load-command 边界、`LC_ENCRYPTION_INFO`/`LC_ENCRYPTION_INFO_64` 的 cryptoff、cryptsize、cryptid。cryptoff/cryptsize 是相对该 slice 文件布局的范围，不能直接当内存地址；cryptid 非零说明声明使用加密机制，不能把整个文件都当密文。零值或没有命令也不能单独证明所有代码完整明文。

## 条件式采集与重建

先取得同一 UUID/架构的实际运行映像及 ASLR slide。对每个覆盖加密范围的 segment，依据其 fileoff/filesize 与 vmaddr/vmsize 将文件区间映到运行时地址；排除零填充、跨段、未映射与懒加载缺页。需要 FAT 外层文件 offset 时再加 slice 起点。不能将 cryptoff 直接加模块基址读取，也不能把内存称“物理文件范围”。

只采已获准的代码/元数据范围，避开凭据和私钥。以明确范围的明文字节替换工作副本对应位置，再核对布局与解析，最后才按实际恢复情况修改该 slice 的 cryptid；修改标志本身不解密字节。某个模块采集成功不代表所有嵌入 Framework/扩展均已覆盖；列出实际 Mach-O 清单与逐项状态。

## 正反例与交付

正例：同 UUID 的样本在声明加密区间恢复可解释指令，与调用/字符串引用交叉一致；未修改区字节一致，slice 及 segment 范围自洽。反例：仅将 cryptid 改零但加密范围仍是高熵不可解释字节，或误把文件偏移当 VA，判为失败/不完整。不是所有二进制都包含 Objective-C 类表或 Swift 元数据，不能作为必选验收项。

分析产物可由实际解析器进一步核函数、引用与目标方法；Mach-O 能打开不是全量逻辑已恢复。重压 ZIP 得到 IPA 只证明归档结构，旧代码签名可能已失效；删除 `_CodeSignature` 不能使其可安装。安装/运行交付另需合适签名、entitlements、设备与业务回归，不能用解析报告冒充。

交付原件/产物哈希、UUID/slice、映射计算、恢复范围、工具与执行者、未采模块及限制。同形失败两次重判格式/平台。符号恢复、数据库或行为分析可调用辅域，结果归原 project/version/run，禁止跨构建拼接。
