---
name: binary-diff
description: 【二进制差分 / 补丁分析】跨版本符号迁移、函数匹配、补丁差分与 N-day 漏洞定位。覆盖 BinDiff/Diaphora/ghidriff/radiff2、PDB/符号恢复、AOB 签名迁移、patch Tuesday 与 1-day 复现。以“匹配关系可验证、补丁前后差异能落到函数/字段、PoC 能区分修复前后”为判据，不做无授权的目标攻击。
license: MIT
compatibility: Linux/WSL2/Windows；IDA Pro + BinDiff/Diaphora、Ghidra、radare2/radiff2、ghidriff、Python 3.10+。商业工具需授权。
metadata:
  version: "1.0.0"
  category: binary-diff
  hard_gates: "版本与哈希钉住 / 匹配可验证 / 差异落到代码 / PoC 前后有区分"
---

# binary-diff — 二进制差分 / 补丁分析

> 只回答一件事：**两个版本之间，哪些函数/数据变了、变化意味着什么、能否用 PoC 或符号迁移证明。**
> 不做“看起来像”的匹配；每个匹配/差异都要有地址、反汇编或调用链证据。

## 0. 两条路线（先选目标）

| 目标 | 路线 | 产物 |
|---|---|---|
| 有旧版符号，新版无符号 | **符号迁移**：函数匹配 → 名字/类型搬移 → 验证 | 新 IDB/符号表、匹配率 |
| 有补丁前后，找漏洞 | **补丁差分**：对齐 → 变更函数 → 反推 bug class → PoC | 差异报告、PoC、修复前后对比 |
| 两个不同样本聚类 | 相似度/聚类 | 函数/字符串/导入相似矩阵 |

**边界**：从零逆向走 `ida-reverse`/`radare2`；完整利用链走 `pwn-crypto`；客户端授权旁路走 `01`–`05`。本技能只做差分与迁移。

## 1. 钉住版本与基线

```bash
sha256sum old.bin new.bin | tee evidence/SHA256SUMS
file old.bin new.bin
rabin2 -I old.bin | head -20
rabin2 -I new.bin | head -20
```

- 记录版本号、构建时间、签名者、架构、编译器、是否加壳；版本错 = 全盘白做。
- 先确认“同一产品/同一模块”：导入表、字符串、PDB 路径、Rich header、节名。
- 判据：两份样本的哈希/版本/架构/模块身份四项齐全。

## 2. 函数匹配（先对齐，再谈差异）

### 2.1 工具链

```bash
# radare2 快速相似度
radiff2 -C old.bin new.bin | head -50
radiff2 -g sym.main old.bin new.bin | head -80

# ghidriff（Ghidra headless）
ghidriff old.bin new.bin -o diff/

# BinDiff（IDA 导出后比对）
# Diaphora：IDA 插件，导出 SQLite 后比对
```

- 匹配分：1.0 = 完全相同；0.5–0.9 = 结构变化；<0.3 = 不可信。
- 先看 **unmatched**（新增/删除）与 **changed**（同函数不同代码），再看 identical。
- 判据：关键函数（入口、鉴权、协议、加密、解析）有匹配地址与分数。

### 2.2 特征辅助

- 字符串/导入/常量/调用图/基本块数/指令数/字节 n-gram。
- 编译器/优化级别变化会让字节差异巨大，但调用图与字符串仍可对齐。
- 判据：至少两种特征支持同一匹配，避免“地址巧合”。

## 3. 符号迁移

```text
1. 旧版：有 PDB/符号/已命名函数
2. 新版：无符号，但函数匹配到旧版
3. 迁移：函数名、类型、结构体、枚举、注释
4. 验证：调用点/字符串/行为与名字一致
```

- IDA：BinDiff 导入匹配 → 批量重命名；Diaphora：`Export to IDA`。
- 结构体：先对齐字段偏移/大小，再迁移；不要盲搬。
- 判据：迁移后的名字在调用链/字符串/行为上自洽；抽查 ≥10 个函数。

## 4. 补丁差分到漏洞

### 4.1 找“安全变更”

| 补丁新增 | 可能 bug class |
|---|---|
| `if (a + b < a)` / `__builtin_add_overflow` | 整数溢出 |
| `if (idx >= MAX)` / `len > buf_size` | 越界读/写 |
| `RtlZeroMemory`/`memset` | 未初始化信息泄漏 |
| 锁/引用计数 | TOCTOU/UAF/double-free |
| `ProbeForRead/Write` | 用户态指针未校验 |
| 权限/ACL 检查 | 越权 |
| 删除/收紧 IOCTL | 暴露面收敛 |

- 关注“中等匹配分 + 新增分支/校验”的函数，而不是全部差异。
- 反推输入：哪个字段/长度/索引能触发旧版缺失的检查。
- 判据：差异行能对应到一个可构造的输入。

### 4.2 PoC 与验证

```text
unpatched：PoC → 崩溃/越权/读回受控数据
patched：同一 PoC → 被拒绝/不崩溃
干净基线：正常输入 → 两者都正常
```

- 崩溃不等于可利用：记录寄存器/栈/堆状态，判断是否可控。
- 判据：修复前后行为差异稳定（≥9/10），且影响面可描述。

## 5. LLM 辅助匹配（可选）

```text
输入：旧函数反汇编/伪代码 + 新候选函数
输出：YAML {old_addr, new_addr, confidence, reason}
约束：只做候选排序，最终由地址/调用图/行为验证
```

- 适合大批量符号迁移；不适合替代 PoC。
- 判据：LLM 建议经过至少一条硬证据复核。

## 6. 工具与降级

| 能力 | 首选 | 降级 |
|---|---|---|
| 函数匹配 | BinDiff/Diaphora | `radiff2 -C`、Ghidra Version Tracking |
| 补丁差分 | ghidriff | 手工反编译 + diff |
| 符号迁移 | IDA/BinDiff | Python + r2 脚本 |
| 结构体 | IDA/Ghidra | 偏移/大小手工比对 |
| 证据 | `seep_r2_diff` | `diff` 反汇编文本 |

缺工具走 `seep_tool_discover` / `tool-run.ps1` / `seep_tool_install`；不 `-h` 盲试探。

## 7. 坑

1. **版本错**：32/64 位、debug/release、不同补丁级别不可直接比。
2. **只看字节 diff**：编译器/优化变化会淹没真实逻辑差异。
3. **匹配分当真理**：0.6 的匹配可能是错的；必须看调用图/字符串。
4. **忽略新增函数**：漏洞修复常新增校验函数，不只在旧函数改。
5. **结构体盲搬**：字段偏移变化会导致后续分析全错。
6. **崩溃当利用**：不可控崩溃只是 DoS 线索。
7. **补丁不全**：厂商可能只修一个入口；检查同一 bug class 的其他路径。
8. **符号版权/授权**：PDB/符号使用遵守厂商许可。

## 8. 验收

- [ ] 版本/哈希/架构/模块身份齐全，原件只读。
- [ ] 关键函数有匹配地址、分数与至少两种特征支持。
- [ ] 差异落到函数/基本块/字段，而非“整体不同”。
- [ ] 符号迁移抽查自洽；或补丁差异有 PoC 前后对比。
- [ ] 结论标注 observed/inferred/unverified；未验证的利用链不写成结论。
- [ ] 未对未授权目标投放 PoC。

> 细节：`references/symbol-migration.md`、`references/patch-diff.md`。
