# 交付报告 · golden-crackme

目标：`Tool/samples/real/crackerjack/a.exe`（MinGW/GCC PE32+ x86-64，53782 字节，无壳，纯本地常量卡密）
类型：CWE-602 客户端鉴权脆弱性（本地立即数比较，无签名 / 无联网 / 无硬件绑定 / 无自校验）
账本口径：`facts.jsonl` 第 1 行 state 记 **裁定 = 部分可赢**；交付上限按客户话讲就是 **能改到能用**（账本原值见该行 `max_level` 字段）
本阶段采用 **方案 A**（用户回执 ack=A）。

## 1 结论

- 到哪一步：**能改到能用**——2 字节补丁让错误输入返回 `PASS`，原件 FAIL、补丁件 PASS、反例恒 FAIL 三组都已实测。
- 卡在哪：技术不卡；卡在交付边界——补丁只对这个 53782 字节的版本成立，换版本要重新定位位点。
- 能不能用：按账本裁定为 **部分可赢**：本机可用，但不含 UI 改版、不含自有授权平台接入。

## 2 已确认

本段只写跑过、能照抄命令复现的事实；强度只有三档——**强**＝同输入同输出可复现（命令与原始输出都能贴）、**中**＝跑过多次且期望命中、**弱**＝单次观测或推断（一律进第 3 段，不进本段）。

- 目标是一个 53782 字节的 PE32+ x86-64 控制台程序，镜像基址 `0x140000000`，入口 VA `0x1400013f0`（`F-001`；强）。
- 没加壳：`.text` 熵 `0xa7/0xff`，16 个节，无 UPX/Themida/VMP 特征（`F-002`；强）。
- 没 strip：`stripped=false`、`linenum=true`，`.debug_info` 4608 字节，所以我们能直接按符号定位（`F-003`；强）。
- 没有任何联网 / 签名 / 硬件绑定 / 反调试：导入表 42 项里没有 WinINet/WinSock/BCrypt/Crypt，也没有 `IsDebuggerPresent`、`NtQueryInformationProcess`（`F-004`、`F-005`；强）。
- 判定就一处：校验函数是 `sym.main`（VA `0x140002860`，79 字节），由 `sym.__tmainCRTStartup @ 0x1400010c2` 调用（`F-008`；强）。
- 判定内容只有两条 4 字节立即数比较：`buf[0..3] == 'tran'`（`0x14000287a`）、`buf[3..6] == 'nce'`（`0x140002897`），所以正确输入恒为 6 字节的 `trance`（`F-009`；强）。
- 分叉点是磁盘字节 `0x140002882 = 74 13`（`je`）与 `0x14000289f = 75 e3`（`jne`），两条分支都汇到 `0x140002890 xor eax,eax`，因此**退出码恒 0，不能当判据**（`F-010`；强）。
- 字符串 `trance` / `PASS` / `FAIL` 在 `.rdata`，且 `trance` 没有任何 xref——不是比较对象，只是提示文本，别被它误导（`F-007`；强）。
- 补丁 `0x1e82: 74 13 → eb 1d`，语义 `je 0x140002897` 改成 `jmp 0x1400028a1`（= `lea rcx, str.PASS`）；`0x140002882 + 2 + 0x1d = 0x1400028a1`，算术可复核（强：反汇编语义与运行行为两路一致）。
- 补丁件 + 错误输入 `wrong` → `PASS`；补丁件 + 正确输入 `trance` → `PASS`（功能未被破坏）（强：实测 stdout）。
- 反例 `artifacts/exp_nop9090.exe`（改成 `90 90`）恒 `FAIL`，证明这 2 个字节是必要原因，不是「本来就通过」（强）。
- 产物对账：`sha256sum -c artifacts/MANIFEST.sha256` → 5 行全 `OK`，rc=0（强）。
- 工具面：radare2 在本机可用，全部分析都是静态 + 本机实测，没有联网动作（`F-011`；强）。另：`rabin2 -I` 在本版本只打印 Usage，查头信息要用 `r2 -c iI`（`F-014`；强，旧记录 `F-013` 的版本口径已推翻）。

## 3 仍未知

- **原件 `a.exe` 的 sha256 没进清单**：`artifacts/MANIFEST.sha256` 只覆盖 6 个交付物文件，不含原件。为什么未知：建清单时只按「交付物」取哈希。还缺：对原件单独复算一次 sha256 并补进清单，之后才能拿哈希确认「打的是这个原件」。
- **换版本怎么定位没验证**：本补丁位点是针对这一版手工定位的，没有 AOB / 符号映射。为什么未知：手上只有一个版本。还缺：新版样本 + 一次「唯一命中」的偏移比对。
- **运行时内存 Hook 路线没走**：本机 9 次启动基址恒为 `0x7ff729610000`（≠ 首选 `0x140000000`），但换机 / 重启会变。为什么未知：本轮只做磁盘补丁。还缺：在目标机上现算 `base + RVA` 的内存读证据。
- **Ghidra 侧没出结论**：`analyzeHeadless` 停在下限档位（`F-012`），本件全部结论来自 radare2 + 实测。为什么未知：没有跑完 headless 反编译。还缺：一次完整的 Ghidra 工程，才能对反编译结果做交叉验证。
- **UI 改版与自有授权平台接入没有做**：为什么未知：不在本阶段范围。还缺：品牌素材、服务端协议、失败路径设计。

## 4 下一步

- 省事路线：把 `eb 1d` 做成一条可回滚脚本（备份原件 → 写 2 字节 → 校验 sha256 → 跑五条输入），大约 **1–2 小时**；依据：位点已定、字节已证、只剩打包与回归。
- 彻底路线：加 UI 改版 + 自有授权平台（服务端签发 + 客户端校验 + 失败路径），大约 **3–5 天**；依据：本件不含任何网络层代码，协议与失败面都要新写。
- 不建议做：不要按运行时 VA 打内存补丁交付（基址随 ASLR 变，换机必挂）；也不要在没备份原件的情况下直接改文件。

## 5 怎么复查

- 复查单（一条命令生成，含目标哈希 / 环境 / 重放命令）：
  `python Tool/scripts/case_state.py recheck --case Tool/cases/golden-crackme` → 生成 `Tool/cases/golden-crackme/recheck.md`
- 账本口径先对齐（最重要）：`python Tool/scripts/case_state.py resume --case Tool/cases/golden-crackme`
  期望第一行出现 `裁定=部分可赢`（上限字段以账本原值为准，本报告只用「能改到能用」这句客户话表述）；
  若这里换成别的裁定，说明账本被改过——先对齐账本，再改报告。
- 功能重放（三种 Windows 环境都能直接粘，见第 8 节完整版）：
  - cmd：`echo wrong| Tool\cases\golden-crackme\artifacts\a.patched.exe` → 期望 `PASS`
  - PowerShell：`'wrong' | .\Tool\cases\golden-crackme\artifacts\a.patched.exe` → 期望 `PASS`
  - 对照（原件）：`echo wrong| Tool\samples\real\crackerjack\a.exe` → 期望 `FAIL`
- 产物对账：`cd Tool\cases\golden-crackme && sha256sum -c artifacts/MANIFEST.sha256` → 期望 5 行全 `OK`；
  没有 bash 的机器用 `certutil -hashfile Tool\cases\golden-crackme\artifacts\a.patched.exe SHA256` → 期望 `3ea3a26ac1d8cd65516b6253afa089b09fbe78cc6e95a89d2422289ac6e69d15`
- 对不上先看：是不是 32 位 / 别的版本原件、是不是在别的目录跑的（路径全部按仓库根写死）。

## 6 交付物

| 文件 | 说明 | sha256 |
| :-- | :-- | :-- |
| `artifacts/a.patched.exe` | 成品件。2 字节补丁，53782 字节（与原件同大小、同节表） | `3ea3a26ac1d8cd65516b6253afa089b09fbe78cc6e95a89d2422289ac6e69d15` |
| `artifacts/MANIFEST.sha256` | 哈希清单（5 条：a.patched.exe / exp_nop9090.exe / run.json / run2.json / reverify 日志），LF 行尾，可直接 `sha256sum -c` | — |
| `artifacts/exp_nop9090.exe` | **反例证据**：`0x1e82 = 90 90`，实测恒 FAIL。保留，勿删 | `ed15a7825e2a13972e1d0399505d58af206ecb0828ce08b739b1fa9cca114714` |
| `capture/run.json` | 原件动态对照（trance→PASS / wrong→FAIL）真实记录 | 见清单 |
| `capture/run2.json` | 补丁件动态记录（五条输入全 PASS）+ 补丁元数据 | 见清单 |
| `report/dynamic.md` | 动态分析 + 三套地址台账（RVA / 文件基址 VA / 运行时基址 VA） | — |

## 7 旁路原理（为什么是这 2 个字节）

`sym.main` 在 `0x14000287a` 比较 `buf[0..3]` 与 `'tran'`，紧接着：

```
0x140002882  74 13   je  0x140002897   ; 相等 → 跳到比较②，否则顺序落入 FAIL
0x140002884          lea rcx, str.FAIL ; ← 顺序路径打印 FAIL
```

补丁把这条**条件跳转改成无条件跳到 PASS 块**：

```
paddr 0x1e82:  74 13  →  eb 1d     ; je 0x140002897  →  jmp 0x1400028a1
0x140002882 + 2 + 0x1d = 0x1400028a1 = lea rcx, str.PASS   （算术可复核）
```

改动面：**2 字节 / 1 处**；不新增节、不改文件大小、未改动字符串常量、未触及 CRT 初始化。

## 8 验收方法（任何人都能复跑的三条命令）

在仓库根目录 `D:/Seep-Reverse-Lab` 下执行（三种环境各给一条，任选其一即可；三条都是真跑过的）：

```bat
:: ① cmd.exe —— 功能判据：错误输入必须 PASS（原件在这里是 FAIL）
echo wrong| Tool\cases\golden-crackme\artifacts\a.patched.exe
::   期望输出：PASS        实测：PASS
:: 对照（证明不是「本来就通过」）：
echo wrong| Tool\samples\real\crackerjack\a.exe
::   期望输出：FAIL        实测：FAIL
```

```powershell
# ② PowerShell —— 同样的判据（PowerShell 里相对路径要加 .\）
'wrong' | .\Tool\cases\golden-crackme\artifacts\a.patched.exe
#   期望输出：PASS        实测：PASS
```

```bash
# ③ git bash / WSL：printf 更好控（不追加换行）
printf 'wrong' | Tool/cases/golden-crackme/artifacts/a.patched.exe
#   期望输出：PASS        实测：PASS
```

```bat
:: ④ 产物对账（任选一种）
cd Tool\cases\golden-crackme && sha256sum -c artifacts/MANIFEST.sha256
::   期望：5 行全 OK      实测：5/5 OK
certutil -hashfile Tool\cases\golden-crackme\artifacts\a.patched.exe SHA256
::   期望：3ea3a26ac1d8cd65516b6253afa089b09fbe78cc6e95a89d2422289ac6e69d15
```

### 验收清单

| # | 验收项 | 判据 | 实测 |
| :-: | :-- | :-- | :-- |
| 1 | 原件 + 正确输入 | stdout 含 `PASS` | `PASS`（hex `504153530d0a`，rc=0） |
| 2 | 原件 + 错误输入（负例） | stdout 含 `FAIL` | `FAIL`（hex `4641494c0d0a`，rc=0） |
| 3 | 补丁件 + 错误输入 | stdout 含 `PASS` | `PASS` ✔ 判定已旁路 |
| 4 | 补丁件 + 正确输入 | stdout 含 `PASS` | `PASS` ✔ 未破坏原路径 |
| 5 | 补丁字节 | `paddr 0x1e82` = `eb 1d` | `xxd`：`...7472 616e eb1d 488d...` ✔ |
| 6 | 反汇编语义 | 该处为 `jmp 0x1400028a1` | `r2 pd 3 @ 0x14000287a` ✔ |
| 7 | 产物哈希 | MANIFEST 与实物一致 | `sha256sum -c` 5/5 OK ✔ |
| 8 | 反例可复现 | `exp_nop9090.exe` 恒 FAIL | trance→FAIL、wrong→FAIL ✔ |

## 9 功能面与已知限制

**功能面**：原件唯一业务输出就是 `PASS`/`FAIL`，补丁件在此维度上完全可用；`scanf` 照旧读入一行输入，进程不崩、不挂、不延迟退出，参数与环境变量处理、CRT 启动/退出链（`__tmainCRTStartup` → `sym.main` → `xor eax,eax; ret`）均未改动。

**已知限制（如实列出）**：

1. **输入仍被读入，但不再影响判定**。`scanf("%s", buf)` 保留原样，比较指令也还在，只是岔口被改成无条件跳 PASS——这是「只改判定、不删功能」的最小改动，也让补丁天然抗「删函数导致崩溃」的风险。
2. **退出码不可作判据**：原程序两条分支都汇到 `xor eax,eax`，退出码恒 0，验收只能看 stdout。这一点补丁前后不变。
3. **运行时基址随 ASLR 变化**：`DllCharacteristics = 0x160`（含 `DYNAMIC_BASE`），本机实测 9 次启动基址恒为 `0x7ff729610000`（≠ 首选 `0x140000000`），但换机器/重启会变。因此补丁按**文件偏移 `0x1e82`** 打，不按运行时地址打；若后续要写内存 Hook，必须现算基址 + RVA。
4. **未做 UI 改版与自有授权平台接入**：那属于后续「UI 改版」与「自有授权平台接入」两个阶段的范围；本件不含品牌替换，也不含卡密校验服务。
5. **反例是刻意保留的**：`artifacts/exp_nop9090.exe`（`90 90`）实测恒 FAIL，正是「失效会看到什么」的现场证据，不要当成成品误发。
6. **只对这一版成立**：没有 AOB / 符号映射，换版本要重新定位（见第 3 段）。

## 10 证据索引

- 静态结论：`report/static.md`（13 条台账记录，静态阶段闸已过）与 `facts.jsonl`（`F-001`…`F-014`）
- 动态对照与地址台账：`report/dynamic.md` §1–§3
- 反例分析：`report/dynamic.md` §4.2
- 原始运行记录：`capture/run.json`、`capture/run2.json`
- 哈希清单：`artifacts/MANIFEST.sha256`
- 账本 state 行（裁定 / 上限的最终依据）：`facts.jsonl` 第 1 行
