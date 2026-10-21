---
id: "windows/2026-vmp-ultralock"
title: "VMProtect 3.9.x UltraLock：ProductCode 与 RSA 绑定链"
summary: >
  UltraLock 把授权校验抽成虚拟化指令，运行期依赖 8 字节 ProductCode 解密因子，
  序列号由 RSA 链绑定；给出 ProductCode/RSA 定位、两条绕过路线与反检测判据。
board: "windows"
category: "techniques"
signals: ["VMProtect", "UltraLock", "ProductCode", "RSA", "TitanHide", "DRx"]
mcp_tools: ["kb_router", "workspace_write_text"]
keywords: ["VMProtect 3.9", "UltraLock", "ProductCode", "RSA verify", "serial", "license"]
difficulty: "advanced"
tags: ["VMProtect", "license", "RSA", "anti-debug", "windows"]
language: "zh-CN"
last_updated: "2026-10-20"
related_articles: []
---
# VMProtect 3.9.x UltraLock：ProductCode 与 RSA 绑定链

> 出处：看雪 2026-10-03《基于 VMProtect 授权锁架构的 RSA 算法另类 Bypass》。
> 仅用于已授权样本与离线复现，不要在生产授权环境试错。

## 1. 结论
UltraLock 不是单个跳转能过的序列号框。授权函数被抽成虚拟化指令，运行期用
**8 字节 ProductCode** 作解密因子；序列号再由 **RSA 绑定链**（厂商私钥签名 →
壳内公钥验签 → 解出 ProductCode/HWID/期限）保护。只有两条路线：

| 路线 | 改什么 | 代价 | 稳定性 |
| :--- | :--- | :--- | :--- |
| A 伪造合法序列号 | 序列号 blob / 内嵌公钥 / HWID | 需私钥、密钥替换或弱密钥分解 | 可复用 |
| B patch 解密因子 | 8 字节全局副本或使用点 | 只对当前 build 有效，易被二次校验 | 快 |

先定位 ProductCode，再决定 A/B。先 patch RSA 返回值通常只把「无效」改成
「有效」，后面的 ProductCode 仍为空，函数会走进另一条错误分支。

## 2. 判型（VMP 3.9.x）

```powershell
diec.exe sample.exe
dumpbin /headers sample.exe | Select-String "\.vmp|entry point"
dumpbin /exports sample.exe | Select-String "VMProtect"
```

判型：`.vmp0/.vmp1` 可写可执行且高熵、入口点在壳段、导入表出现
`CryptVerifySignatureW`/`BCryptVerifySignature`/`VMProtect*`；IDA 中受保护函数
只剩 `jmp` 进入 VM。

## 3. 数据模型
`serial blob --RSA verify(pubkey)--> { ProductCode(8B), HWID, expiry }`；8 字节
ProductCode 再作 XOR/滚动密钥，送入 `virtualized license_check`。ProductCode 可能是
序列号解密后的字段、`.data/.vmp1` 全局副本，或虚拟化栈帧局部变量。RSA 验签可能在 CryptoAPI/CNG，也可能被 VMP 内联成自实现模幂；
后者没有导入，只能靠常量与调用图定位。

## 4. 定位 ProductCode

### 4.1 全局副本（最快）
用两个不同序列号各跑一次，dump 可写数据段并离线 diff；变化的 8 字节对齐块即候选。

```text
; x64dbg：壳初始化完成、授权函数执行前
savedata out\data1.bin, <data_base>, <data_size>
; 换序列号重跑保存 data2.bin，离线比较 8 字节对齐块
```

已知合法 ProductCode 时在进程内搜小端字节：`findallmem 0, "1122334455667788"`。
命中地址减模块基址即 `product_code_rva`；只命中栈/堆则转 4.2/4.3。

### 4.2 寄存器 / 栈
```text
bp <license_check_entry>
run
r
dq @rcx
dq @rdx
dq @rsp
```

某寄存器指向 8 字节且随后被 `xor/rol/imul` 使用：记寄存器与使用点，使用点即
`decrypt_site` 候选。栈槽判据：该 8 字节在两次不同序列号运行中不同，且解密后
仍留栈上；只在寄存器出现一次时优先按寄存器处理。

## 5. 定位 RSA 校验点

### 5.1 导入断点
```text
bp CryptVerifySignatureW
bp BCryptVerifySignature
bp VMProtectSetSerialNumber
run; kb; r
```

`rsa_verify_site` 取「验签返回后、根据结果分支」的样本内指令 RVA，不是系统 DLL
里的导入函数地址；返回后看 `eax/rax` 是否被 `test/cmp`，失败分支是否跳向
"invalid serial"。

### 5.2 无导入：找公钥 DER / 模幂常量

```python
from pathlib import Path
b = Path("sample.exe").read_bytes(); oid = bytes.fromhex("2a864886f70d010101"); i = b.find(oid)
while i != -1: print(hex(i), b[max(0, i-24):i+48].hex()); i = b.find(oid, i+1)
```

用 `pefile.get_rva_from_offset()` 转 RVA，再在 IDA 看 xref。若公钥被搬进 `.vmp1`，
在 `CryptVerifySignature` 调用前后 dump `PUBLICKEYBLOB`，头部应为
`06 02 00 00 00 A4 00 00 52 53 41 31`（`RSA1`）。

### 5.3 内联模幂

特征：大数循环、指数 `0x10001`、模长 2048 位、PKCS#1 v1.5 的
`00 01 FF FF ... 00` 填充比较。对 `0x10001` 下内存断点或找 xref，再回溯输入 blob。

## 6. 路线 A：伪造合法序列号
RSA-2048 不能直接伪造签名，可落地的是：

1. **密钥替换**：把内嵌公钥换成自己的公钥，用对应私钥签序列号；同时处理 VMP
   对公钥区的校验和，否则验签前就被完整性检查拦下。
2. **弱密钥/共享素数**：公钥只有 1024 位或来自批量弱密钥时，先 GCD/分解；能分解
   才谈得上真伪造。
3. **HWID/期限重绑**：已有合法序列号时，改 RSA 解密后的结构体字段并让壳重新解析；
   这是复用合法签名 + 改绑定字段，不是伪造签名。
成功判据：`VMProtectGetSerialNumberState()` 返回 `0`；受保护函数真正执行到业务
分支；重启后仍有效，不是一次性内存状态。

## 7. 路线 B：patch 解密因子

```text
; B1 全局副本：确认指令读取 [module_base+product_code_rva] 后改该 8 字节
bp <decrypt_site>
run
; B2 立即数/栈常量：直接改使用点的 mov/xor 操作数
; B3 VM handler 动态取数：hook 取数 handler，返回固定 8 字节
```

```js
const base = Module.getBaseAddress("sample.exe"), decrypt = base.add(0x123456);
Interceptor.attach(decrypt, { onLeave(r) { r.replace(ptr("0x1122334455667788")); }});
```

判据是 `post_patch_behavior`：业务函数执行、无崩溃、无自毁。若 patch 后进入另一条
错误分支，说明只改了副本，没改真正参与分支判断的那一份。

## 8. 反检测：TitanHide 与 DRx

### 8.1 TitanHide
```powershell
Get-CimInstance Win32_SystemDriver | ? { $_.Name -match "titan|hide" -or $_.PathName -match "titan|hide" }
fltmc filters
```

```text
; x64dbg：在系统信息查询上断，观察是否枚举模块/驱动
bp NtQuerySystemInformation
run
r
dq @rcx
```

`titanhide_detected=true`：样本 attach 后查询 TitanHide 设备/驱动，或加载 TitanHide
时行为与不加载时不同。此时不要裸 attach，先卸载隐藏驱动做对照或改外部观测。

### 8.2 DRx 清除

VMP 可能经 `NtSetContextThread`/`SetThreadContext` 清 DR0-DR3、DR7，使硬件断点失效。

```text
bp NtSetContextThread
run
dt ntdll!_CONTEXT @rdx
? @rdx+0x48   ; Dr0
? @rdx+0x70   ; Dr7
```

判据：在 `decrypt_site` 前设置的 DRx 命中时已被清零，日志中可见
`NtSetContextThread` 写入 0；偏移以 `dt ntdll!_CONTEXT` 为准。

## 9. 判据字段
| 字段 | 取值 | 证据 |
| :--- | :--- | :--- |
| `product_code_rva` | `0x...` / `null` | 全局副本地址减模块基址；或栈/寄存器稳定来源 |
| `decrypt_site` | `0x...` | 第一次用 ProductCode 做 XOR/ROL/IMUL 的指令 RVA |
| `rsa_verify_site` | `0x...` | 验签返回后根据结果分支的样本内指令 RVA |
| `titanhide_detected` | `true/false` | 驱动/设备枚举命中，或加载 TitanHide 前后行为差异 |
| `post_patch_behavior` | `ok/crash/invalid-branch/self-delete` | patch 后业务函数是否执行、是否二次检测 |

## 10. 失败判据
| 现象 | 判定 | 改走哪条 |
| :--- | :--- | :--- |
| 只改序列号对话框，业务仍失败 | 只过 UI 层，ProductCode 未生效 | 回第 4 节找 8 字节因子 |
| `decrypt_site` 每次地址不同 | 命中 JIT/壳自解密临时页 | 在模块固定 RVA 设断，或走全局副本 |
| `rsa_verify_site` 指向系统 DLL | 记错层，样本内没有判据 | 记录调用点 RVA 与返回后分支 |
| 公钥替换后启动即崩 | 壳对公钥区做校验和 | 先定位完整性检查，或走路线 B |
| patch 后崩溃/自毁 | 二次检测或 VM 栈被破坏 | 停手，外部观测；两次失败即回退 |
| 加载 TitanHide 就退出 | `titanhide_detected=true` | 卸载隐藏驱动对照，或纯静态 + 内存 dump |

## 11. 出处与延伸
- 看雪（2026-10-03）《基于 VMProtect 授权锁架构的 RSA 算法另类 Bypass》，
  `https://bbs.pediy.com/`（站内检索标题）；SDK 语义见 `VMProtectSetSerialNumber` /
  `VMProtectGetSerialNumberState` 公开头文件。
- 反调试与仪器选择：`Tool/skill/softseep/references/10-anti-debug.md`。
