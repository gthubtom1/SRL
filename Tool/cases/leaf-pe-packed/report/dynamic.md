# 动态分析 + 地址台账 · leaf-pe-packed（阶段 2）

目标：`Tool/cases/leaf-pe-packed/target/a_upx.exe`（压缩件，41494B）→ 脱壳件 `unpacked/a_unpacked.exe`（53782B）
工具口径：UPX 5.2.1（`/d/Tools/UPX/upx.exe`）、radare2 6.2.0、python 3 + `ReadProcessMemory`（ctypes）、`xxd`/`cmp`
本阶段做三件事：① 脱壳并三重对账；② 用**运行期内存**独立复核脱壳件是真的；③ 把 `0x1e82` 落成**文件偏移**台账（不是 RVA）。

## 1. 压缩件能否直接运行（壳是否自解压）

先答这个问题，因为它决定脱壳路线的合法性。实测**能跑**：

```
$ printf 'trance' | target/a_upx.exe   → PASS   rc=0
$ printf 'wrong'  | target/a_upx.exe   → FAIL   rc=0
```

原始记录：`capture/run.json`（全量五条输入：`trance`/`wrong`/`x`/`tranceXYZ`/`TRANCE`）。

| 输入 | 压缩件 | 脱壳件 | 补丁件 |
| :-- | :-- | :-- | :-- |
| `trance` | PASS | PASS | PASS |
| `wrong` | FAIL | FAIL | **PASS** |
| `x` | FAIL | FAIL | PASS |
| `tranceXYZ` | FAIL | FAIL | PASS |
| `TRANCE` | FAIL | FAIL | PASS |

压缩件与脱壳件的五行完全一致 → 壳自解压无损，业务行为在压缩件上已可观测（虽然不可静态分析）。这也解释了为什么"壳能跑"却不能"壳上打补丁"：能跑=内存里有解压后代码，可改的仍是磁盘上的压缩流（`upx -t` 会 checksum error，见 `facts.jsonl` F-004）。

## 2. 脱壳：`upx -d` 实测（选了静态还原，不启用运行期 dump）

选型理由见 `report/static.md` §5：标准 UPX、自校验 [OK]、无加密/无反调试/无 IAT 混淆。担心点只有一个——**打包用 UPX 3.91w、本机是 5.2.1**，版本差可能脱不干净。实跑结果：成功。

```
$ /d/Tools/UPX/upx.exe -t target/a_upx.exe
 testing target/a_upx.exe [OK]

$ /d/Tools/UPX/upx.exe -l target/a_upx.exe
      53782 ->     41494   77.15%    win64/pe     target/a_upx.exe

$ /d/Tools/UPX/upx.exe -d target/a_upx.exe -o unpacked/a_unpacked.exe
      53782 <-     41494   77.15%    win64/pe     a_unpacked.exe
 Unpacked 1 file.                                    rc=0
```

### 2.1 三重对账（版本差是否留下坑）

| # | 对账项 | 期望 | 实测 | 判 |
| :-: | :-- | :-- | :-- | :-: |
| ① | 文件大小 | 回到 53782 | `53782` | ✔ |
| ② | 入口点 | 回到 `0x1400013f0`（paddr `0x9f0`） | `r2 -c ie` → `paddr 0x9f0 vaddr 0x1400013f0` | ✔ |
| ③ | 行为 | 与原件同输出 | `trance`→PASS / `wrong`→FAIL（§1） | ✔ |

### 2.2 脱壳件 vs 原件：逐字节差异（80 字节，全在头部与 .idata）

`cmp -l unpacked/a_unpacked.exe samples/real/crackerjack/a.exe` → **80 个字节不同**，首 `0xd8`、末 `0x3638`。按节分布：

| 节 / 区域 | 文件区间 | 差异字节数 |
| :-- | :-- | --: |
| PE 头 + 可选头（含数据目录） | `< 0x600` | 7 |
| **.text** | `0x600–0x2000` | **0** |
| .data | `0x2000–0x2200` | 0 |
| .rdata | `0x2200–0x2800` | 0 |
| .pdata | `0x2800–0x2c00` | 0 |
| .xdata | `0x2c00–0x2e00` | 0 |
| .idata | `0x2e00–0x3800` | 73 |
| .tls / .reloc / .debug_* | `≥ 0x3800` | 0 |

差异的三个来源（逐项验过）：

1. **PE 校验和被清零**：`0xd8` 处 unpacked `00000000`、原件 `886e0100`（= `0x00016e88`）。UPX 脱壳不重算 Checksum，属正常残留，不影响加载（Windows 默认不校验用户态镜像 checksum）。
2. **两处数据目录项被清零**：`0x168–0x170` unpacked 全 0，原件 `58820000 90010000`。经 `cmp` 定位后逐项对照为 `.debug_*` 相关目录（脱壳件把调试目录指针抹了），不影响运行。
3. **导入表被 UPX 重建**：`.idata` 里 73 字节差异集中在导入描述符的 `OriginalFirstThunk`/时间戳等字段，并且 **DLL 名大小写被统一**——`0x34c9` 处 unpacked `DLL`（`44 4c 4c`）vs 原件 `dll`（`64 6c 6c`）。Windows 加载器对 DLL 名大小写不敏感，行为一致（§1 五行输出与原件全同可证）。

**关键结论（决定阶段 3 能不能按偏移打补丁）**：`.text` **零差异**，所以原件的 `paddr = RVA − 0xa00` 换算在脱壳件上仍然成立，`0x1e82` 可以直接复用。

## 3. 运行期内存复核：脱壳件不是"看起来像"，而是"就是"

只用 `cmp` 还只是"文件对文件"。再加一道：**直接读运行中压缩件进程的内存**，看解压后的 `RVA 0x2860` 是否与脱壳件磁盘字节逐字节相同。方法：`Popen` 起压缩件（不写 stdin → 卡在 `scanf`）→ `CreateToolhelp32Snapshot` 取 `modBaseAddr` → `OpenProcess`+`ReadProcessMemory` 读 `base+0x2860` 共 79 字节。

```
runtime base (压缩件进程)          = 0x7ff715a90000
ReadProcessMemory(base+0x2860, 79) = 4883ec38e897ecffff488d542428488d0d8b170000e826fdffff
                                     817c24287472616e7413488d0d84170000e8b8feffff31c0
                                     4883c438c3817c242b6e63650075e3488d0d62170000e89bfeffffebe1
unpacked 磁盘 0x1e60..0x1eaf       = 4883ec38…（逐字节相同）→ MATCH True
内存 base+0x2882 处 2 字节         = 74 13   ← 与磁盘 0x1e82 完全一致
```

三条由此坐实：

1. **UPX 自解压后保持了原件的 RVA 布局**（解压落点就在 UPX0 的虚拟区间 `0x140001000`+0x12000），所以 `base + 0x2860` 在压缩件进程里就是 `sym.main`——这就是"内存定位"路线可行的证据，也是将来不脱壳直接内存补丁的唯一依据。
2. **`upx -d` 的产物与内存里的解压结果逐字节等同**（79 字节全同），排除了"版本差导致脱壳件与真实运行代码不一致"这个唯一的风险点。
3. 因此 `0x1e82` 这个**文件偏移**在脱壳件上指向的确实是运行期分叉指令，不是巧合。

## 4. 地址台账（RVA / 文件基址 VA / 运行时基址 VA / 文件偏移）

四种地址的定义与换算：

- **RVA**：相对映像基址的偏移，PE 结构原生字段（节表 `VirtualAddress`）。
- **文件基址 VA**：`0x140000000 + RVA`，即静态反汇编器显示的地址（本件首选基址 `0x140000000`）。
- **运行时基址 VA**：进程真实加载地址 + RVA。`DllCharacteristics` 含 `DYNAMIC_BASE`，**ASLR 生效**：本轮三个进程实测基址分别为压缩件 `0x7ff715a90000`、脱壳件 `0x7ff65a5f0000`、补丁件 `0x7ff7d7220000`，**互不相同**，所以下表运行时列以"基址+RVA"表示，不写死绝对值。
- **文件偏移 paddr**：`.text` 的 `RVA 0x1000 / RawOff 0x600` ⇒ `.text` 内 **`paddr = RVA − 0xa00`**（下表 8 个点全差 `0xa00`，无例外，已用 `xxd` 逐点核过）。

| 位置 | RVA | 文件基址 VA | 运行时 VA（基址 + RVA） | 文件偏移 paddr |
| :-- | :-- | :-- | :-- | :-- |
| `sym.main` 入口 | `0x2860` | `0x140002860` | `0x7ff715a90000+0x2860` = `0x7ff715a92860` | `0x1e60` |
| 比较① `cmp [buf],'tran'` | `0x287a` | `0x14000287a` | `…+0x287a` | `0x1e7a` |
| **分叉 `je`（补丁点）** | **`0x2882`** | **`0x140002882`** | `…+0x2882`（实测内存 `74 13`） | **`0x1e82`** |
| FAIL 块 `lea rcx,str.FAIL` | `0x2884` | `0x140002884` | `…+0x2884` | `0x1e84` |
| 比较② `cmp [buf+3],'nce'` | `0x2897` | `0x140002897` | `…+0x2897` | `0x1e97` |
| `jne` 回 FAIL | `0x289f` | `0x14000289f` | `…+0x289f` | `0x1e9f` |
| PASS 块 `lea rcx,str.PASS` | `0x28a1` | `0x1400028a1` | `…+0x28a1` | `0x1ea1` |
| 调用者 `call sym.main` | `0x10c2` | `0x1400010c2` | `…+0x10c2` | `0x6c2` |

### 4.1 `0x1e82` 在三个文件里分别是什么（本节是"实际文件偏移"的正面回答）

| 文件 | 文件偏移 `0x1e82` 处的字节 | 该偏移映射到哪个 VA | 是什么 |
| :-- | :-- | :-- | :-- |
| `unpacked/a_unpacked.exe`（脱壳件） | **`74 13`** | `.text`：`0x140002882` | **就是那个 `je 0x140002897` 分叉**（`xxd -s 0x1e80`：`616e 7413` → `0x1e82=74,0x1e83=13`） |
| `artifacts/a_upx.patched.exe`（补丁件） | **`eb 1d`** | `.text`：`0x140002882` | 补丁后 `jmp 0x1400028a1` |
| `target/a_upx.exe`（压缩件） | `73 00`（gibberish） | UPX1：`0x140014c82`（`0x1e82−0x200`+`0x13000`） | **不是分叉**，落在解压桩/压缩载荷里；反汇编为 `jae 0x140014c84` 后接 `invalid` |
| `samples/real/crackerjack/a.exe`（原件） | `74 13` | `.text`：`0x140002882` | 与脱壳件相同（`.text` 零差异） |

**一句话**：`0x1e82` 这个**文件偏移**只在"脱壳件/原件"这一族里等于分叉点；在压缩件上 `0x1e82` 指向 UPX1 的 `0x140014c82`，与判定逻辑毫无关系——这正是阶段 3 必须换文件打的直接理由。

## 5. 补丁与负例（阶段 3 的证据在此打通）

补丁口径沿用 `golden-crackme` 已验证的 2 字节方案（同一个源码编出的同一段代码，`sym.main` 79 字节完全相同）：

```
文件偏移 0x1e82:  74 13  →  eb 1d
语义：      je 0x140002897  →  jmp 0x1400028a1 (lea rcx, str.PASS)
算术：      0x140002882 + 2 + 0x1d = 0x1400028a1  ✔
```

复核：

```
$ r2 -c "aa; pd 5 @ 0x14000287a" artifacts/a_upx.patched.exe
0x14000287a  817c242874..  cmp dword [var_28h], 0x6e617274 ; 'tran'
0x140002882  eb1d          jmp 0x1400028a1
$ xxd -s 0x1e78 -l 24 artifacts/a_upx.patched.exe
00001e78: ffff 817c 2428 7472 616e eb1d 488d 0d84   ...|$(tran..H...
```

**负例（本条是"补丁真的起作用了"的证明，不是可选装饰）**：

```
unpacked/a_unpacked.exe + 'wrong'  → FAIL   （未打补丁 = 仍在校验）
artifacts/a_upx.patched.exe + 'wrong' → PASS  （打了补丁 = 判定旁路）
```

两行都在 `capture/run2.json`（`negative_control.verified = true`）与 `run2.verdict_of_runs` 里留了原始 stdout 与 hex。

## 6. 本阶段结论

1. **压缩件能直接跑**（壳自解压），但**不能直接打补丁**——两条事实同时成立，不矛盾。
2. `upx -d` 在 3.91w→5.2.1 版本差下**成功**：53782B、入口回 `0x1400013f0`、行为一致；与原件仅 80 字节不同，全在头部与 `.idata`，**`.text` 零差异**。
3. **内存复核**独立证明脱壳件与运行期解压结果**逐字节相同**（79 字节 MATCH），`RVA 0x2860` 在压缩件进程里同样可定位 `sym.main`。
4. `0x1e82` 是**文件偏移**（不是 RVA）：在脱壳件里 = 分叉 `74 13`；在压缩件里 = UPX1 `0x140014c82` 的垃圾字节。补丁只对脱壳件有效。
5. 补丁 `eb 1d` 使 `wrong` 由 FAIL 变 PASS，而未打补丁的脱壳件仍 FAIL → 判定旁路成立且可证伪。
