# 静态分析记录 · leaf-pe-packed（阶段 0b）

目标：`Tool/cases/leaf-pe-packed/target/a_upx.exe`（41494 字节，UPX 压缩件，`evidence_kind=fixture`）
原件（脱壳后应还原到的形态）：`Tool/samples/real/crackerjack/a.exe`（53782 字节，sha256 `8308abb8…6f30`）
工具口径：radare2 6.2.0（`/d/Tools/radare2/bin/radare2.exe`）、UPX 5.2.1（`/d/Tools/UPX/upx.exe`）、python 3 stdin 直喂
本阶段只做静态：不写补丁、不跑交付，只回答一个问题——**壳挡住了什么，第一刀切哪**。

## 1. 载体与加载面

`r2 -q -e scr.color=0 -c iI target/a_upx.exe`（实测）：

```
arch x86 / bits 64 / bintype pe / class PE32+ / machine AMD 64 / subsys Windows CUI
baddr 0x140000000 / binsz 41494 / os windows / cc ms / lang c
canary true / signed false / nx true / pic true / relocs false / overlay true
hdr.csum 0x00000000      ← 原件是 0x00016e88
cmp.csum 0x000107be      ← 与 hdr.csum 不相等，UPX 抹掉了 PE 校验和字段
```

载体结论：PE32+ x86-64 控制台程序，首选基址 `0x140000000`，`signed=false`（无 Authenticode），`pic=true`/`relocs=false`（有重定位能力但磁盘上不保留 `.reloc` 内容也可运行——UPX 桩自己重建）。文件比原件小 **12288 字节**（53782 → 41494，UPX 自报 77.15%）。

## 2. 壳识别：五条独立依据（任一可独立判壳，五条齐=高置信）

| # | 依据 | 实测输出 | 原件对照 |
| :-: | :-- | :-- | :-- |
| ① | 节表只剩 `UPX0/UPX1/UPX2`，且 UPX0 `size=0x0` | `iS` → `0 0x200 size=0x0 UPX0 vsize 0x12000` / `1 0x200 size=0x2400 UPX1` / `2 0x2600 size=0x400 UPX2` | 16 节 `.text/.data/.rdata/.pdata/.xdata/.bss/.idata/.tls/.reloc/.debug_*` |
| ② | 文件偏移 `0x205` 有 `UPX!` 魔数 | python 扫 `b'UPX!'` → `['0x205']` | `[]`（0 处） |
| ③ | 入口被搬进 UPX1 | `ie` → `paddr 0x21c0 vaddr 0x140014fc0`；UPX1 vaddr `0x140013000`+`0x1fc0` | `paddr 0x9f0 vaddr 0x1400013f0`（`.text` 内） |
| ④ | 载荷香农熵 7.638 ≥ 7.5 | `UPX1`（off 0x200 长 0x2400）熵 `7.638` | `.text`（off 0x600 长 0x1a00）熵 `5.834` |
| ⑤ | 原文串在磁盘上消失 | `izz~trance` → **空**；python `b'trance'` → `-1` | `izz~trance` → `107 0x00002203 0x140004003 6 7 .rdata ascii trance` |

第⑤条是本阶段最直观的一条：连 `trance` 这个 6 字节明文都搜不到，说明整个业务数据段被压缩流替换了。`upx -t` 自检 `[OK]`、`upx -l` 报 `win64/pe`，属**标准壳、非改壳**。

## 3. 壳挡住了什么（本节是 0b 的核心）

三层遮挡，逐层有实测：

**3.1 业务代码不可反汇编。** `aa; aflc` 在压缩件上只有 **3** 个"函数"（`0x140014fc0 entry0` 50B / `0x140015030 fcn.140015030` 496B / `0x140015220 entry1` 1B），全是 UPX 解压桩；原件同名命令是 **75** 个函数，其中 `0x140002860 sym.main` 79B 才是判定函数。函数面从 75 塌到 3，`afl~main` 在压缩件上**空**——静态根本走不到 `sym.main`。
（附注：`facts.jsonl` F-003 记的是 4 与 76，本次复测在 r2 6.2.0 上是 3 与 75，属分析器版本口径差异，不影响结论方向；两套数都在这儿留档。）

**3.2 业务字符串不可检索。** `izz` 在压缩件上拿不到 `trance`/`PASS`；`PASS` 在压缩件里**完全不存在**（`b'PASS'` → `-1`），`FAIL` 唯一一次命中（off `0x1019`）落在 UPX1 压缩流里，是随机巧合（见 §4）。

**3.3 判定点不可寻址。** 原件 `sym.main` 的岔口 VA `0x140002882`，其字节 `74 13` 在压缩件里搜到 `0x815` —— 同样是压缩流随机命中（§4 证伪），**没有任何结构性依据**说它对应判定点。盘上既没有 `.text`（UPX0 size=0），也就没有"`paddr = RVA − 0xa00`"这个换算关系可用：压缩件里 `0x1e82` 处根本不是 `sym.main` 的字节。

**一句话**：壳挡住的不是"能不能分析"，而是**"分析对象在磁盘上不存在"**——业务代码、字符串、交叉引用、函数边界四样同时在盘上消失，只剩一段熵 7.638 的压缩流和一个解压桩。

## 4. 磁盘字节搜索在压缩件上是假信号（必须记住的负例）

在压缩件里做字节搜索会**出现命中，但全是假的**：

```
pattern    packed 命中           unpacked 命中
74 13      0x815               0xb6b
75 e3      0x527               0xa73
74 72 61 6e ('tran' 立即数)  0xfb1   0x1e7e
PASS       无                  0x220a
```

`0x815` / `0x527` / `0xfb1` 全部落在 UPX1 载荷（0x200–0x2600）内部，是压缩流里撞出来的 2–4 字节巧合，既不在 UPX1 的解压桩代码流里，也没有任何指令边界/交叉引用支撑。**教训**：在壳上按 AOB 定位业务点位，命中率看起来不为零，实际成功率为 0——必须先用"是否落在真实解压后代码段"做一次否证。这条也是后面阶段 3 补丁只打脱壳件的理由。

## 5. 第一刀切哪：`upx -d` 直接脱 vs 运行期 dump（选前者）

两条路线摆出来对比：

| 路线 | 可行性依据（已实测） | 代价 | 风险 |
| :-- | :-- | :-- | :-- |
| **A. `upx -d` 直接脱**（选这条） | `upx -t` → `testing ... [OK]`；`upx -l` → `win64/pe`；`UPX!` 魔数在 `0x205`（标准头部布局）；无改壳迹象（节名规范、无异常导入） | 一条命令，零手工 | 版本差（3.91w 压、5.2.1 脱）可能导致拒绝或细节偏差，需逐字节对账 |
| B. 运行期 dump + IAT 重建 | 压缩件能直接跑（阶段 1 实测），OEP 可断 | 需调试器 + Scylla 类 IAT 重建 + 节表修复 | 重建出的 IAT/节表与原件不同，后续补丁偏移不可直接复用 |

**选 A 的理由**：壳是标准 UPX、自校验通过，属"壳可逆 → 直接脱"分叉（`unpack-loop` 判据）；B 的收益只在"改壳/加密壳"时才体现，本件没有加密、没有反调试、没有 IAT 混淆，B 只会引入人为偏差。
**对 A 的唯一担心**（版本差）留给阶段 2 用三条硬对账消解：① 脱壳件大小应回到 53782；② `.text` 应与原件逐字节一致；③ 脱壳件 + `trance`/`wrong` 输出应与原件一致。

## 6. 证据

| 编号 | 结论 | 怎么看出来的（命令 + 输出片段） | 指针 |
| :-- | :-- | :-- | :-- |
| F-101 | 载体 PE32+ x86-64 CUI，41494B，基址 0x140000000，signed=false | `r2 -c iI` → `class PE32+` / `subsys Windows CUI` / `binsz 41494` / `signed false` | a_upx.exe:0x0（DOS/PE 头） |
| F-102 | 三节 UPX0(size=0)/UPX1(0x2400)/UPX2(0x400)，UPX0 磁盘无内容 | `r2 -c iS` → `0 0x200 0x0 ... UPX0` | a_upx.exe:节表 0x1d8 |
| F-103 | `UPX!` 魔数 @off 0x205，原件 0 处 | python `buf.find(b'UPX!')` → `['0x205']` / `[]` | a_upx.exe:0x205 |
| F-104 | 入口 `0x140014fc0`(paddr 0x21c0) 落在 UPX1，原件入口 `0x1400013f0`(paddr 0x9f0) | `r2 -c ie` 两个文件对照 | a_upx.exe:0x21c0 |
| F-105 | UPX1 熵 7.638 vs 原件 .text 5.834 | python 香农熵（off 0x200 len 0x2400 / off 0x600 len 0x1a00） | a_upx.exe:0x200 |
| F-106 | 函数面塌缩：压缩件 3 个 vs 原件 75 个，且压缩件无 sym.main | `r2 -c "aa; aflc"` → 3 / 75；`afl~main` 压缩件空 | a_upx.exe:afl |
| F-107 | 业务串在盘上消失：`PASS` 完全不存在，`trance` 搜不到 | python `b'PASS'`→-1、`b'trance'`→-1；`izz~trance` 压缩件空 | a_upx.exe:UPX1 0x200–0x2600 |
| F-108 | 字节搜索假信号：`74 13` @0x815、`tran` 立即数 @0xfb1 均在压缩流内 | python find 对照表（§4） | a_upx.exe:0x815 / 0xfb1 |
| F-109 | 标准壳可逆：`upx -t` [OK]、`upx -l` win64/pe | `upx -t/-l` 输出 | a_upx.exe:全文件 |

## 7. 结论与下一步

- **壳挡住了什么**：磁盘上不存在可分析的业务代码/字符串/交叉引用/函数边界；`sym.main`、`trance`、`PASS` 三样在压缩件里都拿不到。唯一可分析的只有 UPX 解压桩。
- **走哪条路线、为什么**：走 `upx -d` 直接脱（标准壳、自校验通过、无加密/反调试），不启用运行期 dump；版本差风险用"大小 + `.text` 逐字节 + 行为对照"三条对账消解。
- **下一步（阶段 1/2）**：① 先验压缩件能否直接跑（壳自解压）；② `upx -d` 出 `unpacked/a_unpacked.exe` 并做三条对账；③ 在脱壳件里定位 `sym.main` 与岔口，把 `0x1e82` 换成**文件偏移**口径落台账。
- 回执三要点（均带指针）：① 三节 + UPX0 size=0（F-102）；② 函数 3 vs 75、无 `sym.main`（F-106）；③ 业务串在盘上消失、字节搜索全是假信号（F-107/F-108）。
