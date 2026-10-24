# 快筛画像卡 · golden-crackme

- 案例：`golden-crackme`
- 目标：`Tool/samples/real/crackerjack/a.exe`
- 日期：2026-10-24
- 授权口径：自建夹具（仓库自带标靶，`case.json.evidence_kind=fixture`；范围由仓库声明，非第三方目标）

## 画像卡（六字段）

载体：PE32+ / x86-64 控制台程序（subsys=Windows CUI），binsz=53782 字节，image base 0x140000000，入口 VA 0x1400013f0（paddr 0x9f0）；判据：`radare2 -c iI` 输出 `class PE32+` / `machine AMD 64` / `subsys Windows CUI`，`ie` 输出 `0x000009f0 0x1400013f0 ... program`。
保护：无壳、无完整性自检。.text paddr 0x600 size 0x1a00（6656B）逐块熵 0xa7/0xff≈0.65，全节唯一字节 246/256；节名只有 .text/.data/.rdata/.pdata/.xdata/.bss/.idata/.tls/.reloc/.debug_*，无 UPX/ASPack/Themida 类节名；`iI` 报 `signed false`；且编译带 `-g`，`.debug_info` 4608B 仍在（`stripped false`）。命令：`radare2 -c "iSj" -c "iS" -c "p=e @ 0x140001000" -c "p=d 0x1a00 @ 0x140001000"`。
授权权威：本地常量（纯本地校验，无任何在线面）。判定权在 `sym.main` 内的两条立即数比较：0x14000287a `cmp dword [var_28h], 0x6e617274`（"tran"）与 0x140002897 `cmp dword [var_2bh], 0x65636e`（"nce\0"）；程序只依赖这两条分支选 PASS/FAIL，无签名、无网络、无硬件绑定。命令：`radare2 -c "pdf @ sym.main"`；导入表 42 项里无 WinINet/WinSock/Http 相关 API。
改动面：磁盘字节（最小单元 1 个分支）。可选两处：把 0x140002882 `je`（文件偏移 0x1e82，字节 74 13）改成 `eb 13`/`90 90`，或把 0x14000289f `jne`（paddr 0x1e9f）改成 `90 90`；前者让任何输入走 PASS 分支。地址口径：VA 0x140002882 = RVA 0x2882 = paddr 0x1e82（.text vaddr 0x140001000 − paddr 0x600）。依据：`radare2 -c "pdf @ sym.main"` 反汇编行与节表偏移换算。
检测器：目标自身**无磁盘自校验**——导入表不含 `CreateFileW`/`GetModuleFileName*`/`ReadFile`（两次 grep 均为空输出），也不含 `IsDebuggerPresent`/`NtQueryInformationProcess`；唯一的 `VirtualProtect` 导入属于 MinGW CRT 伪重定位器 `sym._pei386_runtime_relocator`（0x1400018b0），不读自身文件。我们可用的判据：① 输入后标准输出是否出现 `PASS`(0x14000400a) / `FAIL`(0x14000400f)；② 断在 0x14000287a 与 0x140002897 看两处比较值；③ 字符串面直接有明文期望值 `trance`(0x140004003，无交叉引用，属编译器残留的死常量)。命令：`radare2 -c "ii~CreateFile" -c "ii~GetModuleFileName" -c "ii~IsDebuggerPresent" -c "izz~trance"`。
交付壁垒：无。无签名校验（`signed false`）、无联网激活、无自毁/反调试、无平台审核；成品只需落一个改过的 exe 或运行时补丁，离线可复现（哈希可追：md5 30261dd0c2042092b50bffcaa3360f97）。

## 三行结论

- 能不能赢：可赢。判据：校验是本地两条立即数比较，无壳无自校验无网络，改 1 个分支即可翻转。
- 赢的天花板：全通且无残迹（T1 后端档位）。程序只有一个 PASS/FAIL 判定，不存在被授权门控的后续功能；改后仍需注意 `.rdata` 内 `trance` 明文残留（原版自带，非我方引入）。
- 第一刀切哪：`radare2 -e bin.relocs.apply=true -c "aa" -c "pdf @ sym.main" <a.exe>` 复核两条 cmp，再按 paddr 0x1e82 打 `74 13 → 90 90`（阶段 1 执行）。

## 收尾自检

- 六字段齐全（载体/保护/授权权威/改动面/检测器/交付壁垒），无 `{{value}}` 占位。
- 每个值都能指向一条实测命令 + 输出片段，明细见 `report/static.md` 的证据表。
- 授权口径已写清：仓库自带夹具，范围由仓库声明。

## 交叉引用

- 打法：`Tool/skill/00-triage/SKILL.md`
- 下一份：`report/static.md`
