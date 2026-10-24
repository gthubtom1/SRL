# 静态分析记录 · golden-crackme

目标：`Tool/samples/real/crackerjack/a.exe`（仓库自带夹具，evidence_kind=fixture）
工具口径：radare2 6.2.0（`D:\Tools\radare2\bin\radare2.exe`）；辅助探测 ghidra（L0 可用，未启动，见 §7）
加载基址：image base / baddr = `0x140000000`，PE32+ x86-64，CUI 子系统

## 1. 目标与加载

- 文件类型：`radare2 -q -c "iI" a.exe` → `arch x86` / `bits 64` / `bintype pe` / `class PE32+` / `machine AMD 64` / `subsys Windows CUI` / `binsz 53782` / `os windows` / `cc ms`。
- 哈希（未改动，原始值）：`rahash2 -a md5,sha256 a.exe` → `md5 30261dd0c2042092b50bffcaa3360f97`，`sha256 8308abb81b7692e04262b0ce861fd0dfc155dbc791667b2436802b0a8a566f30`。
- 入口：`radare2 -c "ie"` → `paddr 0x000009f0  vaddr 0x1400013f0  type program`；`-c "iM"` 无 main 符号输出，需 `aa` 后由 CRT 交叉引用定位 `sym.main`。
- 编译器线索：`iI` 报 `compiled Mon Oct 19 06:25:51 2026` / `lang c`；`izz` 命中 `GCC: (x86_64-posix-seh-rev0, Built by MinGW-Builds project) 15.2.0`（paddr 0x2730）与 `.debug_info` 内 `GNU C23 15.2.0 ... -O2 -g`（paddr 0x3e34）。

## 2. 结构与保护判定（无壳）

- 节表：`radare2 -c "iS"` 共 16 节：.text paddr 0x600 size 0x1a00 perm -r-x；.data 0x200；.rdata 0x600；.pdata 0x400；.xdata 0x200；.bss size 0；.idata 0xa00；.tls 0x200；.reloc 0x200；.debug_aranges/…/.debug_line_str 各 0x200（.debug_info 0x1200）。
- 无壳判据三条：① 节名全是标准 PE/MinGW 名，无 UPX0/UPX1/.aspack/.themida/.vmp 类节名；② .text 熵低：`p=e @ 0x140001000` 每 0x100 块给出 `00a7`（0xa7/0xff ≈ 0.65）、后续块 0xa0–0xa7，远低于加壳阈值（≈0.95+）；③ `p=d 0x1a00 @ 0x140001000` → `unique (count): 246 0xf6`（6656 字节里只有 246 种字节值），.rdata `p=d 0x600 @ 0x140004000` → unique 93。
- 其他标志：`iI` 报 `canary false` / `signed false` / `stripped false` / `overlay true` / `pic true` / `relocs false`（需 `-e bin.relocs.apply=true` 才有正确反汇编）；`.debug_info` 仍在 → 编译带 `-g`，说明未做符号与调试信息清理。

## 3. 导入面与外部调用（无磁盘自校验）

- `radare2 -c "ii"` 共 42 条导入：KERNEL32.dll 10 条（DeleteCriticalSection/EnterCriticalSection/GetLastError/InitializeCriticalSection/LeaveCriticalSection/SetUnhandledExceptionFilter/Sleep/TlsGetValue/VirtualProtect/VirtualQuery）+ api-ms-win-crt-* 32 条（heap/locale/math/private/runtime/stdio/string）。
- 与授权/加密/网络相关的导入：**无**。无 WinINet/WinSock/WinHttp/BCrypt/Crypt*。
- 关键否证（防自校验误判）：`-c "ii~CreateFile"` 空输出、`-c "ii~GetModuleFileName"` 空输出、`-c "ii~IsDebuggerPresent"` 与 `-c "ii~NtQueryInformationProcess"` 均空输出 → 不打开自身文件、不读自身路径、不做反调试。
- `VirtualProtect` 存在但用途明确：唯一引用者是 MinGW CRT 伪重定位器 `sym._pei386_runtime_relocator`（0x1400018b0，905B），配套字符串 `Address %p has no image-section`(0x1400041e0)/`VirtualProtect failed with code 0x%x`(0x140004238)——属运行期重定位，不构成完整性自检。
- 结论：**a.exe 无磁盘自校验迹象**（按导入面 + 引用者双向否证）。
- 输入输出面：`-c "axt @ sym.scanf"` → `sym.main 0x140002875`；`-c "axt @ sym.puts"` → `sym.main 0x14000288b` 与 `0x1400028a8`（两条 puts = PASS/FAIL 两条路）。

## 4. 字符串与线索

- `radare2 -c "izz~trance"` → `107 0x00002203 0x140004003 6 7 .rdata ascii trance`；
  `-c "izz~PASS"` → `108 0x0000220a 0x14000400a 4 5 .rdata ascii PASS`；
  `-c "izz~FAIL"` → `109 0x0000220f 0x14000400f 4 5 .rdata ascii FAIL`。
- `-c "ps @ 0x140004003"` / `ps @ 0x14000400a` / `ps @ 0x14000400f` 分别回显 `trance` / `PASS` / `FAIL`，与 `izz` 一致。
- 关键负证：`-c "axt @ 0x140004003"` 输出 `[]` → `.rdata` 的明文 `trance` **没有任何代码交叉引用**，它是编译器留下的死常量（期望值已被折叠成 `sym.main` 里的立即数），不是 `strcmp/strncmp` 的操作数。
- 提示语面：程序没有 `Enter password:` 之类提示（`izz` 未命中），只有 `scanf("%s", buf)` 静默读入（`lea rcx, section..rdata ; 0x140004000 ; "%s"`，紧邻 `0x140004003` 的 `trance`）——这也解释了 `trance` 为何紧贴在格式串后面。

## 5. 关键逻辑定位（校验函数）

- 校验函数：**`sym.main` @ VA `0x140002860`**（RVA `0x2860`，paddr `0x1e60`，79 字节 / 5 块，由 `afl` 报 `sym.main 0x140002860 5 79 sym.main`；`axt @ sym.scanf` 交叉引用亦落在 0x140002875）。
- 调用链：`entry0 0x1400013f0` → `sym.__tmainCRTStartup 0x140001010`（`CALL XREF from sym.__tmainCRTStartup @ 0x1400010c2`）→ `sym.main 0x140002860`。
- 判定逻辑（`radare2 -c "aa" -c "pdf @ sym.main"` 原始行）：
  - `0x140002864 call sym.__main`（初始化）
  - `0x140002869 lea rdx, [var_28h]` + `0x14000286e lea rcx, section..rdata ; 0x140004000 ; "%s"` + `0x140002875 call sym.scanf`（读入到栈 buf）
  - `0x14000287a 817c242874.. cmp dword [var_28h], 0x6e617274 ; 'tran'`
  - `0x140002882 7413 je 0x140002897`（相等则跳过 FAIL 分支）
  - `0x140002884 lea rcx, str.FAIL ; 0x14000400f` → `0x14000288b call sym.puts` → `0x140002890 xor eax,eax` → 返回
  - `0x140002897 817c242b6e.. cmp dword [var_2bh], 0x65636e ; 'nce'`（`var_2bh = buf+3`，比较 bytes[3..6] 与 `6e 63 65 00`，末字节 0 即要求串在此结束）
  - `0x14000289f 75e3 jne 0x140002884`（不等则 FAIL）
  - `0x1400028a1 lea rcx, str.PASS ; 0x14000400a` → `0x1400028a8 call sym.puts` → `0x1400028ad jmp 0x140002890`
- 位点结论：期望输入 = `"tran"` + `"nce"` = **`trance`**，且长度必须恰为 6（第二条比较的第 4 字节要求 `0x00`）。两条比较都是立即数（无 strcmp 调用），`-c "axt @ sym.strncmp"` 无输出 → `strncmp` 虽在导入表但本程序未用。
- 分叉点两侧走向：`0x140002882 je` 成立 → 走 0x140002897→PASS→`xor eax,eax; ret`（返回 0）；不成立 → 0x140002884→FAIL→`xor eax,eax; ret`（两条路返回值都是 0，**返回值不能当判据**，只能看 stdout 的 PASS/FAIL 或看分支跳转——这点写进动态阶段的判据）。
- 字节级复核：`pd 1 @ 0x14000287a` → `cmp dword [rsp + 0x28], 0x6e617274 ; 'tran'`；`px 2 @ 0x140002882` → `7413`；`px 2 @ 0x14000289f` → `75e3`。补丁口径：VA 0x140002882 → paddr 0x1e82（.text vaddr 0x140001000 − paddr 0x600 = 0xa00 差值），把 `74 13` 改成 `90 90`（或 `eb 13`）即无条件走 PASS 分支。

## 6. 证据

| 编号 | 结论 | 怎么看出来的（命令 + 输出片段） | 指针 |
| :-- | :-- | :-- | :-- |
| F-001 | 目标是 PE32+ x86-64 CUI，53782 字节，基址 0x140000000 | `radare2 -c "iI" a.exe` → `class PE32+` / `machine AMD 64` / `subsys Windows CUI` / `binsz 53782` / `baddr 0x140000000` | a.exe 头信息；`iI` |
| F-002 | 无壳：.text 熵 0xa7/0xff、唯一字节 246/256、节名无壳特征 | `-c "p=e @ 0x140001000"` → `0x140001000 000 00a7`；`-c "p=d 0x1a00 @ 0x140001000"` → `unique (count): 246`；`-c "iS"` → 仅标准 16 节（.text 0x600/0x1a00 …） | a.exe:.text paddr 0x600 |
| F-003 | 未清符号/调试信息：stripped=false，.debug_info 4608B 存在 | `-c "iI"` → `stripped false` / `linenum true`；`-c "iS"` → `.debug_info paddr 0x3e00 size 0x1200` | a.exe:.debug_info 0x3e00 |
| F-004 | 无磁盘自校验：导入表无 CreateFile/GetModuleFileName/ReadFile | `-c "ii~CreateFile"`、`-c "ii~GetModuleFileName"` 均空输出；`-c "ii"` 42 条仅 KERNEL32 10 条 + CRT 32 条 | a.exe:.idata 0x2e00 |
| F-005 | 无联网/加密/反调试面 | `-c "ii"` 无 WinINet/WinSock/BCrypt/Crypt*；`-c "ii~IsDebuggerPresent"`、`-c "ii~NtQueryInformationProcess"` 空输出 | a.exe:.idata 0x2e00 |
| F-006 | `VirtualProtect` 属 MinGW CRT 伪重定位器，非自校验 | `-c "afl"` → `sym._pei386_runtime_relocator 0x1400018b0 54 905`；`izz` → 0x140004238 `VirtualProtect failed with code 0x%x` | a.exe:0x1400018b0 |
| F-007 | 字符串面有 PASS/FAIL/trance，其中 trance 无代码交叉引用（死常量） | `-c "izz~trance"` → `0x140004003 .rdata ascii trance`；`-c "axt @ 0x140004003"` → `[]` | a.exe:0x140004003 |
| F-008 | 校验函数 = sym.main @ VA 0x140002860（RVA 0x2860，paddr 0x1e60，79B），由 CRT 0x1400010c2 调用 | `-c "aa" -c "afl"` → `0x140002860 5 79 sym.main`；`pdf @ sym.main` → `CALL XREF from sym.__tmainCRTStartup @ 0x1400010c2` | a.exe:0x140002860 |
| F-009 | 判定是两条立即数比较，期望输入 "trance"（长度恰 6） | `pdf @ sym.main` → `0x14000287a cmp dword [var_28h], 0x6e617274 ; 'tran'`；`0x140002897 cmp dword [var_2bh], 0x65636e ; 'nce'` | a.exe:0x14000287a / 0x140002897 |
| F-010 | 分叉字节：0x140002882 = `74 13`（je 跳过 FAIL），0x14000289f = `75 e3`（jne 回 FAIL）；两条路返回 0，不能以返回码判 | `px 2 @ 0x140002882` → `7413`；`px 2 @ 0x14000289f` → `75e3`；`pdf` → 两分支汇于 `0x140002890 xor eax,eax` | a.exe:0x140002882 / 0x14000289f（paddr 0x1e82 / 0x1e9f） |

证据等级：F-001…F-010 均为「强」（命令可重跑、输出片段已贴、地址可复核）。

## 7. 工具口径与失败路径（为什么换路）

- `D:\Tools\radare2\bin\rabin2.exe` 在本机 6.2.0 包里与 r2 同一入口：`rabin2.exe -h` 打印 `Usage: r2 [...]`；`-I` 在 r2 里是「打开文件前先跑脚本」，所以 `rabin2 -I a.exe` 报 `FAIL ERROR: Missing file to open`（把 a.exe 当脚本、于是没有待开文件）。→ 改用 r2 核心命令 `iI/iS/ii/izz/p=e/p=d`，不自造替代工具。
- `r2 -2` 会把输出一起吞掉（本次表现为空输出）→ 不再使用 `-2`，改用 `2>/dev/null` + `grep -v WARN`。
- `iSS` 不是「带熵的节表」而是内存段（`iSS?` → `list memory segments`，输出 `[]`）→ 熵改用 `p=e`（每块 0–0xff 归一化值）+ `p=d`（min/max/unique）。
- `/ trance` 触发 `ERROR: Invalid ':' subcommand`（搜索命令在该构建下的前置分派异常）→ 改用 `izz~trance` 精确取到 paddr/vaddr/节名，同样可复现。
- ghidra：`tool-acquire.py --tool ghidra --start` 结论 `USABLE（停在 L0）`，`D:\Tools\Ghidra\support\analyzeHeadless` 可用；本目标 main 仅 79 字节、r2 反汇编已给出两条 cmp 与分叉字节，故未启动 headless（启动需建工程 + 全量分析，收益为零）。该可用性结论已单独落账。
- 样本目录存在 IDA 会话残留（`a.exe.id0/.id1/.id2/.nam/.til`），非本次产物，按纪律不改动他人文件。
- 未做动态：本阶段（0a/0b）只静态。运行验证留给阶段 1（判据已定：stdout 出现 `PASS` 即通过，不能用退出码，因为两分支都 `xor eax,eax`）。

## 8. 结论与下一步

- 静态面能不能定案：**能**。校验权威=本地立即数比较，位点=0x14000287a / 0x140002897，翻转点=0x140002882（paddr 0x1e82），期望值=`trance`，无壳无自校验无网络。
- 改动面最小单元：exe 磁盘字节 2 字节（`74 13`→`90 90`）；不改节表、不加节、不重打包。
- 下一步：阶段 1 做动态确认（输入 `trance` 应输出 PASS；打补丁后任意输入应输出 PASS），之后交付 `artifacts/MANIFEST.sha256`。
- 回执要点（三条最硬的事实，均带指针）：① 校验函数 `sym.main` 0x140002860（a.exe:0x140002860）；② 两条立即数比较 `'tran'`/`'nce'`（a.exe:0x14000287a / 0x140002897）；③ 无磁盘自校验（a.exe 导入表 .idata 0x2e00，`ii~CreateFile`/`ii~GetModuleFileName` 空输出）。
