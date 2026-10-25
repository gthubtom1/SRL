# 交付报告 · leaf-pe-packed

目标：`Tool/cases/leaf-pe-packed/target/a_upx.exe`——**UPX 压缩件**（41494B，UPX 3.91w 压出）
脱壳基座：`unpacked/a_unpacked.exe`（53782B，`upx -d` 还原，`.text` 与原件逐字节相同）
成品：`artifacts/a_upx.patched.exe`（53782B，2 字节补丁：文件偏移 `0x1e82` = `74 13` → `eb 1d`）
类型：CWE-602（客户端鉴权依赖不可信输入）——本地立即数卡密校验 + 压缩壳遮挡静态面
账本口径：`facts.jsonl` 第 1 行 state 记 **裁定 = 不可赢**、上限 `L1`（对应客户话：只到 **只能看懂结构**）。**以账本为准**，本报告按此结论写；路线为 `upx -d` 静态还原（非运行期 dump），理由见 `report/static.md` §5。

## 1 结论

- 到哪一步：**现在做不了**——账本裁定「不可赢」，上限只登记到 `L1`（客户话：只到「只能看懂结构」一层）。
- 卡在哪：不是技术卡死，而是**账本没把成果登记成可交付**：state 行是 `case.json` 迁移过来的老记录（`outcome=success`，但只登记到 `L1`）。
- 能不能用：技术记录里有「2 字节补丁使 `wrong → PASS`」的实测，但按账本口径本报告**不宣称有可交付成品**；这是历史案例，要续做先 `resume`。

## 2 已确认

本段只写跑过、能照抄命令复现的事实；强度三档——**强**＝同输入同输出可复现（命令与原始输出都能贴）、**中**＝跑过多次且期望命中、**弱**＝单次观测或推断（弱的进第 3 段，不进本段）。

- 目标确实是**标准 UPX 3.91w 压缩件**（win64/pe，非改壳）：节表只剩 `UPX0`(size=0)/`UPX1`(0x2400)/`UPX2`(0x400)，`UPX!` 魔数在文件偏移 `0x205`，入口由原 `.text` `0x1400013f0` 搬到 `0x140014fc0`（`F-001`、`F-102`、`F-103`、`F-104`；强）。
- **压缩后的磁盘面没有业务字节**：UPX1 载荷熵 7.638 bit/byte（原件 `.text` 5.834），`PASS` / `trance` 字符串在压缩件里都找不到（`F-105`、`F-107`；强）。
- **改压缩流会被壳自校验挡死**：把 UPX1 内偏移 `0x1200` 一个字节取反 → `upx -t` 立刻报 `checksum error`（0 ok / 1 error）（`F-004`；强）。
- **壳可逆、不需要 dump + IAT 重建**：`upx -t` 自检 `[OK]`、`upx -l` 报 win64/pe，`upx -d` 还原回 53782B、入口回到 `0x1400013f0`（`F-005`、`F-109`、`F-110` 的复核结论；强）。
- **同一个文件偏移在两种载体上含义完全不同**：`0x1e82` 在脱壳件/原件是 `74 13`（VA `0x140002882`，判定分叉），在压缩件是 `73 00`（VA `0x140014c82`，UPX1 解压桩，反汇编成 `jae` + `invalid`）（`F-113`；强）。
- **壳自解压后的内存与磁盘脱壳件一致**：`ReadProcessMemory(base+0x2860, 79)` 与脱壳件磁盘 `0x1e60` 逐字节相同（MATCH True），`base+0x2882 = 74 13`（`F-112`；中：两次会话观测，命令可重复）。
- **补丁与负例都实测过**：`0x1e82: 74 13 → eb 1d`（`je 0x140002897` → `jmp 0x1400028a1` = `lea rcx, str.PASS`）；补丁件 + `wrong` → `PASS`，五输入矩阵（`trance/wrong/x/tranceXYZ/TRANCE`）全 `PASS`；负例（脱壳件未打补丁 + `wrong`）→ `FAIL`（`F-114`；强）。
- **产物对账**：`sha256sum -c artifacts/MANIFEST.sha256` → 5 行全 `OK`，rc=0（强）。
- **壳识别四条依据互相独立**：节名、`UPX!` 魔数、入口落在 UPX1、载荷熵 ≥7.5，任一成立即可判壳（`F-109`；强）。

## 3 仍未知

- **「能不能赢」这一格原本对不上，已按账本改正**：账本 state 写 `verdict=不可赢` / `max_level=L1`，而本文件旧稿写的是「可赢 + 更高的上限」——两处冲突。为什么未知：那行 state 是 `case.json` 迁移来的老记录，只登记到 `L1`。还缺：一次正式裁定（`case_state.py verdict`）+ 在新口径下重新登记交付，才能把结论改成「可交付」。
- **续做入口**：历史案例，账本 `next_action` 原话是「已结案（历史案例）：如需续做，先 case_state.py resume 看缺件」。为什么未知：本 case 已结案，缺件表是空的。还缺：`resume` 之后重新 `plan` 一次，才知道续做要补哪些件。
- **交付形态没定**：交付件是**脱壳件**，不是压缩件。为什么未知：重压回 UPX 未做（会改 UPX 头、引入新的 checksum 面）。还缺：客户明确「必须看起来仍是压缩件」这个需求 + 一次重压回归。
- **脱壳差异字节数的口径不一致**：账本 `F-111` 已被推翻并改记 166 字节、`F-116` 也记 166，但本轮实测 `cmp` 得 80（首 `0xd8`、末 `0x3638`）。为什么未知：两次测量的对象/工具不同。还缺：用同一条命令重做一次 diff，统一口径后再引用数字。
- **PE 校验和与导入表重建痕迹未做「逐字节复刻」验证**：校验和为 0（原件 `0x00016e88`），`.idata` 里 DLL 名大小写被统一。为什么未知：Windows 用户态默认不校验。还缺：目标环境是否做签名/校验和检查的确认。

## 4 下一步

- 先做（无论走哪条）：`python Tool/scripts/case_state.py resume --case Tool/cases/leaf-pe-packed` → 看缺件，再用 `verdict` / `plan` 重新裁定、把这次的实测正式登记成交付；大约 **0.5–1 小时**；依据：证据与命令都已经在账本里，只差一次正式登记。
- 省事路线（客户接受脱壳件）：把 `eb 1d` 做成可回滚脚本（备份 → 写 2 字节 → 校验 sha256 → 跑五输入矩阵），并把原件 sha256 补进清单；大约 **1–2 小时**；依据：位点与字节已证，只剩打包与回归。
- 彻底路线（客户要求「看起来仍是压缩件」）：补丁后重跑 `upx --best` → `upx -t` → `upx -d` 再验一次 → 五输入矩阵 → 重出清单；大约 **半天到 1 天**；依据：重压会改 UPX 头并引入新的 checksum 面，每一步都要重验。
- 不建议做：不要在压缩件上按 `0x1e82` 改字节（那里是解压桩，且会触发 checksum）；也不要按运行时 VA 打补丁（基址每次都不同）；更不要为了「看起来可赢」去改账本——账本是事实源。

## 5 怎么复查

- 复查单（一条命令生成，含目标哈希 / 环境 / 重放命令）：
  `python Tool/scripts/case_state.py recheck --case Tool/cases/leaf-pe-packed` → 生成 `Tool/cases/leaf-pe-packed/recheck.md`
- **先对齐账本（本 case 最关键的一条）**：`python Tool/scripts/case_state.py resume --case Tool/cases/leaf-pe-packed`
  期望第一行出现 `裁定=不可赢  上限=L1`；若这里换成了「可赢」或别的上限，说明账本被改过——先对齐账本，再改本报告。
- 功能重放（Windows 上三种环境都能直接粘，完整版见第 8 节）：
  - cmd：`echo wrong| Tool\cases\leaf-pe-packed\artifacts\a_upx.patched.exe` → 期望 `PASS`
  - 负例：`echo wrong| Tool\cases\leaf-pe-packed\unpacked\a_unpacked.exe` → 期望 `FAIL`
  - PowerShell：`'wrong' | .\Tool\cases\leaf-pe-packed\artifacts\a_upx.patched.exe` → 期望 `PASS`
- 产物对账：`cd Tool\cases\leaf-pe-packed && sha256sum -c artifacts/MANIFEST.sha256` → 期望 5 行全 `OK`；
  没有 bash 的机器用 `certutil -hashfile Tool\cases\leaf-pe-packed\artifacts\a_upx.patched.exe SHA256` → 期望 `c3d36b868a9131751174151039ab7f80472d063da282244b785d99168f17ff06`
- 脱壳可复现：`upx -d target/a_upx.exe -o /tmp/u.exe`（本机 upx 在 `/d/Tools/UPX/upx.exe`，换机按 `tool-acquire.py --tool upx` 重查）→ 期望 `53782 <- 41494`、`Unpacked 1 file`、rc=0
- 对不上先看：是不是用了别的 upx 版本（3.91w / 5.2.1 的产物差异见第 3 段）、是不是在压缩件上算了偏移。

## 6 交付物

| 文件 | 说明 | sha256 |
| :-- | :-- | :-- |
| `artifacts/a_upx.patched.exe` | 成品件。脱壳件 + 2 字节补丁；与脱壳件同大小（53782B）、同节表 | `c3d36b868a9131751174151039ab7f80472d063da282244b785d99168f17ff06` |
| `artifacts/MANIFEST.sha256` | 哈希清单（5 条：补丁件 / 脱壳件 / run.json / run2.json / reverify 日志），写法可直接 `sha256sum -c` | — |
| `unpacked/a_unpacked.exe` | 脱壳件（中间产物，可复现：`upx -d target/a_upx.exe -o unpacked/a_unpacked.exe`） | `c413f974f3c0a62156231cf1082be90ac9db94f63b60a0e7949759a4fddf8b5b` |
| `capture/run.json` | 压缩件动态记录（五输入矩阵 + "壳能否直接运行"结论） | 见清单 |
| `capture/run2.json` | 补丁件动态记录 + **负例**（脱壳件未打补丁 + wrong → FAIL） | 见清单 |
| `report/static.md` | 静态阶段：壳挡住什么 / 路线选择（五条判壳依据） | — |
| `report/dynamic.md` | 动态阶段：脱壳三重对账 / 内存复核 / RVA-VA-基址-偏移四列表 + `0x1e82` 三文件对照 | — |

## 7 旁路原理（为什么是这 2 个字节，以及为什么必须换文件打）

`sym.main` @ RVA `0x2860`（文件偏移 `0x1e60`，79 字节，脱壳件与原件逐字节相同）：

```
0x14000287a  817c242874..   cmp dword [var_28h], 0x6e617274  ; 'tran'
0x140002882  74 13          je  0x140002897                  ; 相等→比较②，否则顺序落入 FAIL
0x140002884  488d0d8417..   lea rcx, str.FAIL
0x140002897  817c242b6e..   cmp dword [var_2bh], 0x65636e    ; 'nce'
0x14000289f  75 e3          jne 0x140002884
0x1400028a1  488d0d6217..   lea rcx, str.PASS
```

补丁：

```
文件偏移 0x1e82:  74 13  →  eb 1d
语义:   je 0x140002897  →  jmp 0x1400028a1
算术:   0x140002882 + 2 + 0x1d = 0x1400028a1  (lea rcx, str.PASS)  ✔
改动面: 2 字节 / 1 处 / 文件大小不变 / 节表不变 / 字符串常量未动
```

**为什么补丁不能打在压缩件上**（本 case 相对 `golden-crackme` 多出来的那条约束）：同一个文件偏移 `0x1e82`，

| 文件 | `0x1e82` 处字节 | 映射 VA | 含义 |
| :-- | :-- | :-- | :-- |
| 脱壳件 / 原件 | `74 13` | `0x140002882`（`.text`） | 分叉指令 |
| 压缩件 | `73 00` | `0x140014c82`（UPX1 解压桩） | 垃圾字节，反汇编为 `jae` + `invalid` |

且压缩件 `UPX0 size=0`（业务代码在磁盘上没有任何字节），改压缩流会被 UPX checksum 自校验挡死（`F-004` 实测 `0x1200` 取反 → `upx -t` 报 checksum error）。所以**必须先把"分析对象"造出来**：`upx -d` → 再补。

## 8 验收（全部真跑，命令可照抄）

在仓库根目录 `D:/Seep-Reverse-Lab` 执行（三种环境各给一条，任选其一即可）：

```bat
:: ① cmd.exe —— 功能判据：补丁件 + 错误输入必须 PASS
echo wrong| Tool\cases\leaf-pe-packed\artifacts\a_upx.patched.exe
::   期望 PASS   实测 PASS

:: ② 负例（证明补丁确实起作用，不是"本来就通过"）
echo wrong| Tool\cases\leaf-pe-packed\unpacked\a_unpacked.exe
::   期望 FAIL   实测 FAIL

:: ③ 产物对账
cd Tool\cases\leaf-pe-packed && sha256sum -c artifacts/MANIFEST.sha256
::   期望 5 行全 OK   实测 5/5 OK
certutil -hashfile artifacts\a_upx.patched.exe SHA256
::   期望 c3d36b868a9131751174151039ab7f80472d063da282244b785d99168f17ff06
```

```powershell
# ④ PowerShell（相对路径要加 .\）
'wrong' | .\Tool\cases\leaf-pe-packed\artifacts\a_upx.patched.exe
#   期望 PASS   实测 PASS
```

```bash
# ⑤ git bash / WSL：printf 不追加换行，最好控
printf 'wrong' | Tool/cases/leaf-pe-packed/artifacts/a_upx.patched.exe
#   期望 PASS   实测 PASS
# ⑥ 脱壳可复现（本机 upx 路径，换机按 tool-acquire.py --tool upx 重查）
/d/Tools/UPX/upx.exe -d target/a_upx.exe -o /tmp/u.exe && cmp /tmp/u.exe unpacked/a_unpacked.exe
```

```bat
:: ⑦ 脱壳可复现的 Windows 写法（不需要 bash 的 cmp）
certutil -hashfile unpacked\a_unpacked.exe SHA256
::   期望 c413f974f3c0a62156231cf1082be90ac9db94f63b60a0e7949759a4fddf8b5b
```

### 验收清单

| # | 验收项 | 判据 | 实测 |
| :-: | :-- | :-- | :-- |
| 1 | 压缩件能否直接运行 | 能跑 = 壳自解压 | `trance`→PASS / `wrong`→FAIL（`run.json.shell_self_extract.answer="能"`）✔ |
| 2 | 脱壳成功 | `upx -d` rc=0 且大小回 53782 | `53782 <- 41494`，`Unpacked 1 file`，rc=0 ✔ |
| 3 | 脱壳保真：入口 | 回到 `0x1400013f0` | `ie` → paddr `0x9f0` vaddr `0x1400013f0` ✔ |
| 4 | 脱壳保真：代码 | `.text` 零差异 | `cmp -l` 实测 80 处差异全在头部(7)+`.idata`(73)，`.text` 0 ✔（账本口径待统一，见第 3 段） |
| 5 | 脱壳保真：内存 | 运行期解压结果 == 磁盘脱壳件 | `ReadProcessMemory(base+0x2860,79)` 与磁盘 `0x1e60` **MATCH True** ✔ |
| 6 | 原件 + 正确输入（对照） | stdout 含 `PASS` | `PASS` ✔ |
| 7 | 原件 + 错误输入（对照） | stdout 含 `FAIL` | `FAIL` ✔ |
| 8 | **补丁件 + `wrong`** | stdout 含 `PASS` | `PASS` ✔ 判定已旁路 |
| 9 | **负例：脱壳件未打补丁 + `wrong`** | stdout 含 `FAIL` | `FAIL` ✔ 补丁是必要原因 |
| 10 | 补丁字节 | `paddr 0x1e82` = `eb 1d` | `xxd`：`...7472 616e eb1d 488d...` ✔ |
| 11 | 反汇编语义 | 该处 = `jmp 0x1400028a1` | `r2 pd 5 @ 0x14000287a` → `0x140002882 eb1d jmp 0x1400028a1` ✔ |
| 12 | 产物哈希 | MANIFEST 与实物一致 | `sha256sum -c` 5/5 OK ✔ |
| 13 | 五输入矩阵 | 补丁件任意输入皆 PASS | `trance/wrong/x/tranceXYZ/TRANCE` 全 PASS ✔ |

退出码说明：原程序两条路径都汇到 `xor eax,eax`，**退出码恒 0，不能作判据**，验收只看 stdout（与 `golden-crackme` 同）。

## 9 功能面与已知限制

**功能面**：原件唯一业务输出是 `PASS`/`FAIL`；补丁件在此维度完整可用——`scanf("%s", buf)` 照旧读入、CRT 启动/退出链（`__tmainCRTStartup` → `sym.main` → `xor eax,eax; ret`）未改动、进程不崩不挂、无延迟退出、无需额外依赖。脱壳件与压缩件五行输出矩阵完全一致，说明"脱壳"这一步没丢功能。

**已知限制（如实列，不粉饰）**：

1. **交付件是脱壳件，不是压缩件**。这一点不可回避：压缩件里没有可改的业务字节（`UPX0 size=0`）+ UPX checksum 自校验。若客户必须拿到"看起来仍是压缩件"的成品，需要在补丁后重新 `upx --best` 压回去（本阶段未做，因为重压会改变 UPX 头、引入新的 checksum 面，账本也只登记到 `L1`）。
2. **导入表被 UPX 重建，与原件有一批差异字节**：DLL 名大小写被统一（`DLL` vs `dll`）、`OriginalFirstThunk` 等字段重排。Windows 加载器不敏感，行为已实测一致；但若后续要做"精确逐字节复刻原件"的比对，这些差异会被看到，属 UPX 的固有痕迹，非本阶段引入。具体字节数三个口径不一致（80 / 166），见第 3 段。
3. **PE 校验和为零**（`hdr.csum 0x00000000`，原件 `0x00016e88`）。Windows 用户态默认不校验，不影响加载；若目标环境做签名/校验和检查，需另行重算。
4. **运行时基址随 ASLR 变化**：本轮三个进程实测基址 `0x7ff715a90000` / `0x7ff65a5f0000` / `0x7ff7d7220000`，互不相同。补丁按**文件偏移 `0x1e82`** 打，不按运行时 VA 打；若要走"不脱壳、内存 Hook"路线，必须现算 `base + 0x2882`（`report/dynamic.md` §3 已给出该路线可用的内存证据）。
5. **未做 UI 改版与自有授权平台接入**：属后续阶段范围。本件不含品牌替换、不含卡密服务。
6. **反例已刻意保留、但本 case 未单独出 `90 90` 实验件**：`golden-crackme` 已证 `90 90` 会恒 FAIL（因为 `je` 的顺序路径正是 FAIL 块），同一份代码同一段字节，本 case 直接采用已验证有效的 `eb 1d`，不重复制造反例件；负例由"脱壳件未打补丁 + wrong → FAIL"承担。

## 10 证据索引

- 账本 state 行（裁定=不可赢 / 上限 `L1` 的最终依据）：`facts.jsonl` 第 1 行
- 判壳五条依据 + 壳挡住什么 + 路线选择：`report/static.md` §2/§3/§5（`F-101`…`F-109`）
- 脱壳三重对账 + 差异字节分布 + 内存复核 + 四列地址台账 + `0x1e82` 三文件对照：`report/dynamic.md` §2/§3/§4.1
- 原始运行记录：`capture/run.json`（压缩件五行 + `shell_self_extract`）、`capture/run2.json`（补丁件五行 + `negative_control.verified=true`）
- 哈希清单：`artifacts/MANIFEST.sha256`
- 同源无壳案例（同一份源码、更省事的那条打法）：`Tool/cases/golden-crackme/report/final.md`
