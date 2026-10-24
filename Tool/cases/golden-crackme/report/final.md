# 交付报告 · golden-crackme（M3 / T1）

目标：`Tool/samples/real/crackerjack/a.exe`（MinGW/GCC PE32+ x86-64，53782 字节，无壳，纯本地常量卡密）
类型：CWE-602 客户端鉴权脆弱性（本地立即数比较，无签名 / 无联网 / 无硬件绑定 / 无自校验）
裁定：**可赢**，交付上限 **M3**；本阶段采用 **方案 A**（用户 ack=A）。

## 1. 交付物

| 文件 | 说明 | sha256 |
| :-- | :-- | :-- |
| `artifacts/a.patched.exe` | 成品件。2 字节补丁，53782 字节（与原件同大小、同节表） | `3ea3a26ac1d8cd65516b6253afa089b09fbe78cc6e95a89d2422289ac6e69d15` |
| `artifacts/MANIFEST.sha256` | 哈希清单（a.patched.exe / exp_nop9090.exe / run.json / run2.json），LF 行尾，可直接 `sha256sum -c` | — |
| `artifacts/exp_nop9090.exe` | **反例证据**：`0x1e82 = 90 90`，实测恒 FAIL。保留，勿删 | `ed15a7825e2a13972e1d0399505d58af206ecb0828ce08b739b1fa9cca114714` |
| `capture/run.json` | 原件动态对照（trance→PASS / wrong→FAIL）真实记录 | 见清单 |
| `capture/run2.json` | 补丁件动态记录（五条输入全 PASS）+ 补丁元数据 | 见清单 |
| `report/dynamic.md` | 动态分析 + 三套地址台账（RVA / 文件基址 VA / 运行时基址 VA） | — |

## 2. 旁路原理（为什么是这 2 个字节）

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

## 3. 验收方法（任何人都能复跑的两条命令）

在仓库根目录 `D:/Seep-Reverse-Lab` 下执行：

```bash
# ① 功能判据：错误输入必须 PASS（原件在这里是 FAIL）
printf 'wrong' | Tool/cases/golden-crackme/artifacts/a.patched.exe
#   期望输出：PASS        实测：PASS

# ② 产物对账：清单里每个文件哈希一致
cd Tool/cases/golden-crackme && sha256sum -c artifacts/MANIFEST.sha256
#   期望：4 行全 OK       实测：a.patched.exe / exp_nop9090.exe / run.json / run2.json 全 OK
```

对照（证明不是「本来就通过」）：`printf 'wrong' | Tool/samples/real/crackerjack/a.exe` → `FAIL`。

### 验收清单

| # | 验收项 | 判据 | 实测 |
| :-: | :-- | :-- | :-- |
| 1 | 原件 + 正确输入 | stdout 含 `PASS` | `PASS`（hex `504153530d0a`，rc=0） |
| 2 | 原件 + 错误输入（负例） | stdout 含 `FAIL` | `FAIL`（hex `4641494c0d0a`，rc=0） |
| 3 | 补丁件 + 错误输入 | stdout 含 `PASS` | `PASS` ✔ 判定已旁路 |
| 4 | 补丁件 + 正确输入 | stdout 含 `PASS` | `PASS` ✔ 未破坏原路径 |
| 5 | 补丁字节 | `paddr 0x1e82` = `eb 1d` | `xxd`：`...7472 616e eb1d 488d...` ✔ |
| 6 | 反汇编语义 | 该处为 `jmp 0x1400028a1` | `r2 pd 3 @ 0x14000287a` ✔ |
| 7 | 产物哈希 | MANIFEST 与实物一致 | `sha256sum -c` 4/4 OK ✔ |
| 8 | 反例可复现 | `exp_nop9090.exe` 恒 FAIL | trance→FAIL、wrong→FAIL ✔ |

## 4. 功能面与已知限制

**功能面**：原件唯一业务输出就是 `PASS`/`FAIL`，补丁件在此维度上完全可用；`scanf` 照旧读入一行输入，进程不崩、不挂、不延迟退出，参数与环境变量处理、CRT 启动/退出链（`__tmainCRTStartup` → `sym.main` → `xor eax,eax; ret`）均未改动。

**已知限制（如实列出）**：

1. **输入仍被读入，但不再影响判定**。`scanf("%s", buf)` 保留原样，比较指令也还在，只是岔口被改成无条件跳 PASS——这是「只改判定、不删功能」的最小改动，也让补丁天然抗「删函数导致崩溃」的风险。
2. **退出码不可作判据**：原程序两条分支都汇到 `xor eax,eax`，退出码恒 0，验收只能看 stdout。这一点补丁前后不变。
3. **运行时基址随 ASLR 变化**：`DllCharacteristics = 0x160`（含 `DYNAMIC_BASE`），本机实测 9 次启动基址恒为 `0x7ff729610000`（≠ 首选 `0x140000000`），但换机器/重启会变。因此补丁按**文件偏移 `0x1e82`** 打，不按运行时地址打；若后续要写内存 Hook，必须现算基址 + RVA。
4. **未做 UI 改版与自有授权平台接入**：那属于 02 / 03 阶段范围；本件不含品牌替换，也不含卡密校验服务。
5. **反例是刻意保留的**：`artifacts/exp_nop9090.exe`（`90 90`）实测恒 FAIL，正是「失效会看到什么」的现场证据，不要当成成品误发。

## 5. 证据索引

- 静态结论：`report/static.md`（13 条 facts，0b 闸已过）与 `facts.jsonl`
- 动态对照与地址台账：`report/dynamic.md` §1–§3
- 反例分析：`report/dynamic.md` §4.2
- 原始运行记录：`capture/run.json`、`capture/run2.json`
- 哈希清单：`artifacts/MANIFEST.sha256`
