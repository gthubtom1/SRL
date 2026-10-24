# 动态分析 + 地址台账 · golden-crackme

目标：`Tool/samples/real/crackerjack/a.exe`（53782 字节，PE32+ x86-64，CUI，无壳）
工具口径：radare2 6.2.0（`D:\Tools\radare2\bin\radare2.exe`）+ python 3.12 直喂 stdin + `xxd` 复核字节
本阶段目的：把静态结论落到「真跑出来的输出」上，并建立三套地址（RVA / 文件内 VA / 运行时 VA）的换算台账。

## 1. 两次原始运行的真实输出

两条命令都是把输入直接喂给 stdin（目标用 `scanf("%s", buf)` 读一行），退出码恒 0，所以**只看 stdout**：

```
$ printf 'trance' | Tool/samples/real/crackerjack/a.exe
PASS                      → rc=0   stdout hex = 504153530d0a

$ printf 'wrong'  | Tool/samples/real/crackerjack/a.exe
FAIL                      → rc=0   stdout hex = 4641494c0d0a
```

结论：原件确实做了校验，`trance` 走 PASS 分支、`wrong` 走 FAIL 分支。
这一对是本 case 的**对照实验底座**——后面任何补丁件都必须用「`wrong` 变 PASS」来证明真的改了判定，
而不是「本来就通过」。原始记录见 `capture/run.json`（含 `runs[0]`/`runs[1]` 与 `negative_control`）。

## 2. 地址台账（RVA / 文件基址 VA / 运行时基址 VA）

三套地址的区别与换算：

- **RVA**：相对映像基址的偏移，PE 结构里原生存的就是它（节表 `VirtualAddress` 用的也是 RVA）。
- **文件基址 VA**：按 PE 头声明的首选 ImageBase（`0x140000000`）算出的 VA，即静态反汇编器显示的那种地址，落盘分析时用它。
- **运行时基址 VA**：进程真实加载后的 VA。本目标 `DllCharacteristics = 0x160`（`HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT`），**ASLR 开启**，所以运行时基址不等于首选基址，必须实测。

文件偏移（paddr）换算：`.text` 节 `RVA 0x1000 / RawOff 0x600`，故 `.text` 内 **paddr = RVA − 0xa00**（下表 8 个点的差值实测全为 `0xa00`，无一例外）。

| 位置 | RVA | 文件基址 VA | 运行时基址 VA | 文件偏移 paddr |
| :-- | :-- | :-- | :-- | :-- |
| `sym.main` 入口 | `0x2860` | `0x140002860` | `0x7ff729612860` | `0x1e60` |
| 比较① `cmp [buf],'tran'` | `0x287a` | `0x14000287a` | `0x7ff72961287a` | `0x1e7a` |
| 分叉 `je`（补丁点） | `0x2882` | `0x140002882` | `0x7ff729612882` | **`0x1e82`** |
| FAIL 块 `lea rcx,str.FAIL` | `0x2884` | `0x140002884` | `0x7ff729612884` | `0x1e84` |
| 比较② `cmp [buf+3],'nce'` | `0x2897` | `0x140002897` | `0x7ff729612897` | `0x1e97` |
| `jne` 回 FAIL | `0x289f` | `0x14000289f` | `0x7ff72961289f` | `0x1e9f` |
| PASS 块 `lea rcx,str.PASS` | `0x28a1` | `0x1400028a1` | `0x7ff7296128a1` | `0x1ea1` |
| 调用者 `call sym.main` | `0x10c2` | `0x1400010c2` | `0x7ff7296110c2` | `0x6c2` |

### 运行时基址是怎么测出来的（不是猜的）

目标的 `scanf` 会阻塞等输入，所以进程启动后会停在那里，正好够读模块表：

1. `subprocess.Popen([a.exe], stdin=PIPE)` 起进程（不写 stdin → 卡在 `scanf`）；
2. `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, pid)` → `Module32First/Next` 找 `szModule == "a.exe"`，取 `modBaseAddr`；
3. `kill()` 收尾。

实测 **9 次启动**（3 次 + 6 次两批）：`modBaseAddr` 恒为 **`0x7ff729610000`**，`modBaseSize = 0x13000`，`szExePath` 指向原件。
即 `0x7ff729610000 ≠ 0x140000000`，说明重定位器确实工作过、ASLR 生效；本次会话内 9 次同址，但**不得写死**——换机器或重启后该值会变。
所以补丁按**文件偏移**打，不按运行时 VA 打；上表的运行时 VA 只作定位/调试参考。

## 3. 分叉语义：为什么补丁点选在 `paddr 0x1e82`

`sym.main` 反汇编（`r2 -c 'aa; pdf @ sym.main'`，79 字节，`0x140002860..0x1400028ae`）：

```
0x14000287a  cmp dword [var_28h], 0x6e617274   ; 'tran'
0x140002882  74 13          je  0x140002897     ; 相等 → 跳到比较②
0x140002884  lea rcx, str.FAIL                  ; ← 顺序路径＝打印 FAIL
0x14000288b  call puts
0x140002890  xor eax, eax ; ret                 ; 退出码恒 0
0x140002897  cmp dword [var_2bh], 0x65636e      ; 'nce'（var_2bh = buf+3，末字节须为 0）
0x14000289f  75 e3          jne 0x140002884     ; 不等 → 回 FAIL
0x1400028a1  lea rcx, str.PASS
0x1400028a8  call puts
0x1400028ad  eb e1          jmp 0x140002890
```

**定位依据（谁 xref 到它）**——这里必须说清一个反直觉的事实：

- `axt @ 0x140002882` 与 `axt @ 0x140002884` **都是空**：补丁点不是函数入口，也不是任何跳转的落点。
- `afxj @ sym.main` 的 8 条边里只有 1 条 CODE 边：`from 0x1400028ad → to 0x140002890`（`jmp` 回退出块）；其余是 4 条 CALL（`__main`/`scanf`/两个 `puts`）与 3 条 DATA（`"%s"`/`str.FAIL`/`str.PASS`）。
- 因此 `0x140002882` 的唯一入口是**前一条 `cmp`（`0x14000287a`）的顺序落入**（fall-through），`0x140002884` 则再多一条：`0x14000289f` 的 `jne` 指过来。
- 整个函数唯一的上游调用者：`axt @ sym.main` → `sym.__tmainCRTStartup 0x1400010c2 [CALL:--x] call sym.main`。

选点理由：`0x1e82` 就是「PASS 与 FAIL 两条路的岔口」，只改这一条跳转即可把判定定向到 PASS 块，既不增节、不改文件大小、也未改动字符串常量。

## 4. 补丁：方案 A（`74 13 → eb 1d`）+ 一条重要反例

### 4.1 采用的补丁（交付件 `artifacts/a.patched.exe`）

```
paddr 0x1e82:  74 13   →   eb 1d
                je  0x140002897      jmp 0x1400028a1   （0x1400028a1 = lea rcx, str.PASS）
```

- 改动面：**2 字节 / 1 处 / 文件仍 53782 字节 / 节表不变**。
- 目标校验：`0x140002882 + 2 + 0x1d = 0x1400028a1` = PASS 块首指令，算术可复核。
- 反汇编复核：`r2 -c 'aa; pd 3 @ 0x14000287a' artifacts/a.patched.exe` 输出 `0x140002882  eb1d  jmp 0x1400028a1`。
- 字节复核：`xxd -s 0x1e7e -l 16` → `7472 616e eb1d 488d 0d84 1700 00e8 b8fe`（`tran` 立即数后紧跟 `eb 1d`）。

### 4.2 反例（保留证据，别删）：任务原提议的 `90 90` 是错的

原方案把 `0x1e82` 的 `74 13` 改成 `90 90`（nop nop）。实测证明它**不是旁路，而是把程序改坏**：

```
artifacts/exp_nop9090.exe  (0x1e82 = 90 90)
  + 'trance' → FAIL      ← 连正确输入都失效
  + 'wrong'  → FAIL
```

原因就写在 §3 的反汇编里：`je` 是「相等才跳过 FAIL 块」，所以它的**顺序路径（fall-through）恰恰是 `lea rcx, str.FAIL`**。
nop 掉条件跳转 = 无条件执行下一条 = **恒 FAIL**。这也是本 case 最值得记住的一条：
「失效会看到什么」必须用两条输入（一正一负）同时验，只看一条会把「恒 FAIL」误判成「校验变严」。

两件实验件的哈希都在 `artifacts/MANIFEST.sha256` 里，任何人都能复跑复现上表。

### 4.3 补丁件实测（方案 A）

```
artifacts/a.patched.exe + 'trance'     → PASS   (hex 504153530d0a, rc=0)
artifacts/a.patched.exe + 'wrong'      → PASS   ← 判定已旁路
artifacts/a.patched.exe + ''           → PASS
artifacts/a.patched.exe + 'x'          → PASS
artifacts/a.patched.exe + 'tranceXYZ'  → PASS
```

记录：`capture/run2.json`（`runs[]` 五条全量 + 补丁元数据）。

## 5. 本阶段结论

1. 判定确由 stdout 的 `PASS`/`FAIL` 承载，退出码恒 0，不能作判据。
2. 三套地址已对齐：`paddr = RVA − 0xa00`（.text），文件基址 VA = `0x140000000 + RVA`，运行时基址 VA = `0x7ff729610000 + RVA`（本机实测，ASLR 开启）。
3. 岔口 `0x1e82` 是唯一的 2 字节旁路点；`eb 1d` 实测任意输入皆 PASS。
4. `90 90` 为反例：实测恒 FAIL，已作为负例证据落盘。
