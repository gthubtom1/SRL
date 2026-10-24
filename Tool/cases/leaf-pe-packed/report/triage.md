# 快筛画像卡 · leaf-pe-packed（R-PE-PACK-UPX）

- 案例：`leaf-pe-packed`
- 目标：`Tool/cases/leaf-pe-packed/target/a_upx.exe`（41494 字节，UPX 3.91w 压缩）
- 原件：`Tool/samples/real/crackerjack/a.exe`（53782 字节，md5 `30261dd0c2042092b50bffcaa3360f97`）
- 日期：2026-10-24
- 授权口径：自建夹具（仓库自带标靶 a.exe 自行压缩，`case.json.evidence_kind=fixture`；第三方目标不涉及）

## 画像卡（六字段）

**载体**：PE32+ / x86-64 控制台程序（Windows CUI），加壳后 binsz=41494 字节，image base 0x140000000，`hdr.csum 0x00000000`（UPX 抹掉 PE 校验和），`overlay true`。判据：`r2 -q -e scr.color=0 -c iI Tool/cases/leaf-pe-packed/target/a_upx.exe` → `class PE32+` / `machine AMD 64` / `subsys Windows CUI` / `binsz 41494` / `hdr.csum 0x00000000`。

**保护**：**UPX 3.91w 压缩壳（win64/pe，标准壳，未被改壳）**。四条独立识别依据：

1. **节名**——节表只剩三节且全部以 `UPX` 前缀命名，其中 UPX0 的 RawSize=0（磁盘无内容、内存 0x12000）：

   ```
   $ r2 -q -e scr.color=0 -c iS Tool/cases/leaf-pe-packed/target/a_upx.exe
   nth paddr         size vaddr          vsize perm flags      type name
   0   0x00000200     0x0 0x140001000  0x12000 -rwx 0xe0000080 ---- UPX0
   1   0x00000200  0x2400 0x140013000   0x3000 -rwx 0xe0000040 ---- UPX1
   2   0x00002600   0x400 0x140016000   0x1000 -rw- 0xc0000040 ---- UPX2
   ```

   对照原件：`.text .data .rdata .pdata .xdata .bss .idata .tls .reloc .debug_*` 共 13 节（`r2 -c iS Tool/samples/real/crackerjack/a.exe`），节名里没有一个 `UPX`。

2. **UPX 魔数**——文件偏移 0x205 处有 `UPX!`（`packed UPX! count: 1`，原件 `count: 0`）：

   ```
   $ python -c "...buf.find(b'UPX!')..."
   orig UPX! magic offsets: none
   packed UPX! magic offsets: ['0x205']
   ```

3. **入口点从业务节搬走**——原件入口在 .text（`0x1400013f0`，paddr 0x9f0）；压缩后入口变成 `0x140014fc0`（paddr 0x21c0），落在 UPX1（vaddr 0x140013000 + 0x1fc0）里，即「先解压、再跳回原 OEP」的引导桩：

   ```
   $ r2 -q -e scr.color=0 -c ie Tool/cases/leaf-pe-packed/target/a_upx.exe
   paddr      vaddr       phaddr     vaddr     type
   0x000021c0 0x140014fc0 0x000000a8 ---------- program
   ```

4. **载荷熵**——UPX1（0x200，长 0x2400）香农熵 **7.638** bit/byte，原件 .text（0x600，长 0x1a00）熵 **5.834**；≥7.5 即压缩/加密载荷的典型值。

    ```
    $ python -c "...shannon entropy..."
    packed_upx1_entropy=7.638 (len 9216)
    orig_text_entropy=5.834 (len 6656)
    ```

壳本身**可逆且是标准壳**：`upx -t` 自检 `testing ... [OK]`，`upx -l` 报 `win64/pe`。无 Themida/VMProtect 类「RawSize=0 + 乱节名 + 反调试导入」组合，`signed false`。

**授权权威**：原始目标本身是**纯本地**判定（`sym.main` 内两条立即数比较 `cmp ... 0x6e617274`("tran") / `cmp ... 0x65636e`("nce\0")，无网络、无签名），结论与 `golden-crackme` 一致；但**压缩后该权威判定在磁盘上不可读**——.text 已被压缩进 UPX1，本夹具阶段不解析业务逻辑，只确认「静态面看不到它」。判据（函数面塌缩，实测）：

```
$ r2 -2 -q -c aflc <packed>      → 4
e   r2 -2 -q -c afl  <packed>      → entry0(0x140014fc0) / fcn.140015030 / entry1 / fcn.140014ff2（全是 UPX 桩，无 sym.main）
$ r2 -2 -q -c aflc <orig a.exe>  → 76
$ r2 -2 -q -c "afl~main" <orig>  → 0x140002860 sym.main 等 4 条
```

**改动面**：**当前磁盘面无业务代码可改**（这是本叶子的核心结论）。要改动只有两条路：
① 先脱壳（`upx -d` 即可，标准壳）→ 回到原件形态再按 `golden-crackme` 的口径改 1 字节分支；
② 不脱壳，运行期在 OEP（脱壳后 0x1400013f0 对应位置）下断、内存补丁/注入。
磁盘字节层面的"最小改动单元"在压缩产物上不存在——实测把 UPX1 载荷内偏移 0x1200 的一个字节取反（0x00→0xFF）写副本，`upx -t` 立刻报错：

```
$ upx -t /tmp/a_upx_badbyte.exe
upx: D:/tmp/a_upx_badbyte.exe: Exception: checksum error
Tested 1 file: 0 ok, 1 error.
```

即：压缩件上的任何载荷改动都被 UPX 自校验挡死，静态打补丁必须先脱壳。

**检测器**：目标自身**无磁盘完整性自检**（原件导入表无 `CreateFileW`/`GetModuleFileName*`；压缩件由 UPX 桩代管，桩只做解压后跳转）。我方判据：① `upx -t <f>` 返回 `[OK]/[OK]` 即未被我们破坏；② `upx -l <f>` 报格式 `win64/pe`；③ 运行原件与运行脱壳件的标准输出应一致（`PASS`/`FAIL` 两条路，见 `golden-crackme`），可用于验证脱壳保真。**注意**：UPX 桩会在内存里重写自身页面，动态调试要在 OEP 之后下断，否则断点在压缩器里。

**交付壁垒**：低。标准壳 → `upx -d` 一条命令还原，无需修 IAT/重定位（`upx -d` 自校验通过即结构完好）。真正壁垒在壳之后：原件的本地判定（与 `golden-crackme` 相同，1 分支）。压缩本身**不构成**壁垒，它只**推迟**了静态分析——这就是本叶子要证明的分岔点。

## 为什么这条叶子重要（有壳 = 磁盘面失效）

无壳时（`R-PE-NOPACK-LOCAL`）静态就能把业务代码读出来、把判定点算成 paddr、直接打字节；**加壳后这条捷径整体失效**：

- 磁盘上 `.text` 不存在（UPX0 的 `size=0x0`），业务代码在 UPX1 里是压缩流（熵 7.638），字符串/交叉引用/反汇编全部拿不到；
- 入口点被换成 UPX 引导桩（0x140014fc0），静态"从入口往下走"只会读到解压器；
- 于是**第一刀切哪**这个决策被强制改变：要么先脱壳回到静态可读（走 `unpack-loop` 的标准路线），要么放弃磁盘、改走内存（运行期补丁/注入）。

换句话说：这条叶子的价值不是"UPX 能脱"（那是 `upx -d` 的手册知识），而是**它把「改哪里」的判断从静态面逼到「先脱壳还是先动态」的分岔上**——壳的识别结果直接决定后面 01 阶段用哪套动作。识别不出壳就会在压缩流上白费时间（反汇编出一堆垃圾、找不到 `cmp`），这是实测会踩的坑。

## 三行结论

- 能不能赢：可赢。判据：壳是标准 UPX 3.91w，`upx -t` 自检 OK、`upx -l` 报 win64/pe，`upx -d` 一条命令即可还原；还原后业务判定与 `golden-crackme` 完全同构（1 字节分支）。
- 赢的天花板：脱壳后 = 与无壳同档（`golden-crackme` 口径）；交付物是"脱壳件 + 1 字节补丁"或"运行期内存补丁"，无签名校验、无联网、无自毁需要处理。壳本身不提升天花板，只增加一次脱壳步骤。
- 第一刀切哪：`upx -d Tool/cases/leaf-pe-packed/target/a_upx.exe -o <out>` → 用 `r2 -c "pdf @ sym.main"` 复核入口回到 0x1400013f0，再按原件口径定位分支（阶段 1 执行）。

## 收尾自检

- 六字段齐全（载体/保护/授权权威/改动面/检测器/交付壁垒），「保护」点名 **UPX 3.91w** 并给了四条识别依据（节名/魔数/入口点/熵）。
- 每个值都能指向一条实测命令 + 输出片段；文件名与路径均为仓库相对路径，可照抄复跑。
- 授权口径已写清：仓库自带夹具自行压缩，非第三方目标。

## 复跑命令（全部仓库相对路径）

```bash
# 0) 造夹具（已做，重跑会覆盖 target/a_upx.exe）
cp Tool/samples/real/crackerjack/a.exe Tool/cases/leaf-pe-packed/target/a_upx.exe
"D:/Tools/pack/Unpackers/Universal Extractor/bin/upx.exe" --best Tool/cases/leaf-pe-packed/target/a_upx.exe
# 1) 壳识别
r2 -q -e scr.color=0 -c iI -c iS Tool/cases/leaf-pe-packed/target/a_upx.exe
r2 -q -e scr.color=0 -c ie Tool/cases/leaf-pe-packed/target/a_upx.exe
# 2) 壳自检
"D:/Tools/pack/Unpackers/Universal Extractor/bin/upx.exe" -t Tool/cases/leaf-pe-packed/target/a_upx.exe
```

## 交叉引用

- 打法：`Tool/skill/00-triage/SKILL.md`、`Tool/skill/unpack-loop/SKILL.md`
- 上游案例（未加壳同源）：`Tool/cases/golden-crackme/report/triage.md`
- 下一份：`report/static.md`（阶段 0b）
