# 交付报告 · leaf-pe-packed（M3）

目标：`Tool/cases/leaf-pe-packed/target/a_upx.exe`——**UPX 压缩件**（41494B，UPX 3.91w 压出）
脱壳基座：`unpacked/a_unpacked.exe`（53782B，`upx -d` 还原，`.text` 与原件逐字节相同）
成品：`artifacts/a_upx.patched.exe`（53782B，2 字节补丁：文件偏移 `0x1e82` = `74 13` → `eb 1d`）
类型：CWE-602（客户端鉴权依赖不可信输入）——本地立即数卡密校验 + 压缩壳遮挡静态面
裁定：**可赢**，交付上限 **M3**；路线：`upx -d` 静态还原（非运行期 dump），理由见 `report/static.md` §5

## 1. 交付物

| 文件 | 说明 | sha256 |
| :-- | :-- | :-- |
| `artifacts/a_upx.patched.exe` | 成品件。脱壳件 + 2 字节补丁；与脱壳件同大小（53782B）、同节表 | `c3d36b868a9131751174151039ab7f80472d063da282244b785d99168f17ff06` |
| `artifacts/MANIFEST.sha256` | 哈希清单（补丁件 / 脱壳件 / run.json / run2.json），写法可直接 `sha256sum -c` | — |
| `unpacked/a_unpacked.exe` | 脱壳件（中间产物，可复现：`upx -d target/a_upx.exe -o unpacked/a_unpacked.exe`） | `c413f974f3c0a62156231cf1082be90ac9db94f63b60a0e7949759a4fddf8b5b` |
| `capture/run.json` | 压缩件动态记录（五输入矩阵 + "壳能否直接运行"结论） | 见清单 |
| `capture/run2.json` | 补丁件动态记录 + **负例**（脱壳件未打补丁 + wrong → FAIL） | 见清单 |
| `report/static.md` | 阶段 0b：壳挡住什么 / 路线选择（五条判壳依据） | — |
| `report/dynamic.md` | 阶段 2：脱壳三重对账 / 内存复核 / RVA-VA-基址-偏移四列表 + `0x1e82` 三文件对照 | — |

## 2. 旁路原理（为什么这 2 个字节，以及为什么必须换文件打）

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

且压缩件 `UPX0 size=0`（业务代码在磁盘上没有任何字节），改压缩流会被 UPX checksum 自校验挡死（`facts.jsonl` F-004 实测 `0x1200` 取反 → `upx -t` 报 checksum error）。所以**必须先把"分析对象"造出来**：`upx -d` → 再补。

## 3. 验收（全部真跑，命令可照抄）

在仓库根目录 `D:/Seep-Reverse-Lab` 执行：

```bash
# ① 功能判据：补丁件 + 错误输入必须 PASS
printf 'wrong' | Tool/cases/leaf-pe-packed/artifacts/a_upx.patched.exe
#   期望 PASS   实测 PASS

# ② 负例（证明补丁确实起作用，不是"本来就通过"）
printf 'wrong' | Tool/cases/leaf-pe-packed/unpacked/a_unpacked.exe
#   期望 FAIL   实测 FAIL

# ③ 产物对账
cd Tool/cases/leaf-pe-packed && sha256sum -c artifacts/MANIFEST.sha256
#   期望 4 行全 OK   实测 4/4 OK

# ④ 脱壳可复现
/d/Tools/UPX/upx.exe -d target/a_upx.exe -o /tmp/u.exe && cmp /tmp/u.exe unpacked/a_unpacked.exe
```

### 验收清单

| # | 验收项 | 判据 | 实测 |
| :-: | :-- | :-- | :-- |
| 1 | 压缩件能否直接运行 | 能跑 = 壳自解压 | `trance`→PASS / `wrong`→FAIL（`run.json.shell_self_extract.answer="能"`）✔ |
| 2 | 脱壳成功 | `upx -d` rc=0 且大小回 53782 | `53782 <- 41494`，`Unpacked 1 file`，rc=0 ✔ |
| 3 | 脱壳保真：入口 | 回到 `0x1400013f0` | `ie` → paddr `0x9f0` vaddr `0x1400013f0` ✔ |
| 4 | 脱壳保真：代码 | `.text` 零差异 | `cmp -l` 80 处差异全在头部(7)+`.idata`(73)，`.text` 0 ✔ |
| 5 | 脱壳保真：内存 | 运行期解压结果 == 磁盘脱壳件 | `ReadProcessMemory(base+0x2860,79)` 与磁盘 `0x1e60` **MATCH True** ✔ |
| 6 | 原件 + 正确输入（对照） | stdout 含 `PASS` | `PASS` ✔ |
| 7 | 原件 + 错误输入（对照） | stdout 含 `FAIL` | `FAIL` ✔ |
| 8 | **补丁件 + `wrong`** | stdout 含 `PASS` | `PASS` ✔ 判定已旁路 |
| 9 | **负例：脱壳件未打补丁 + `wrong`** | stdout 含 `FAIL` | `FAIL` ✔ 补丁是必要原因 |
| 10 | 补丁字节 | `paddr 0x1e82` = `eb 1d` | `xxd`：`...7472 616e eb1d 488d...` ✔ |
| 11 | 反汇编语义 | 该处 = `jmp 0x1400028a1` | `r2 pd 5 @ 0x14000287a` → `0x140002882 eb1d jmp 0x1400028a1` ✔ |
| 12 | 产物哈希 | MANIFEST 与实物一致 | `sha256sum -c` 4/4 OK ✔ |
| 13 | 五输入矩阵 | 补丁件任意输入皆 PASS | `trance/wrong/x/tranceXYZ/TRANCE` 全 PASS ✔ |

退出码说明：原程序两条路径都汇到 `xor eax,eax`，**退出码恒 0，不能作判据**，验收只看 stdout（与 `golden-crackme` 同）。

## 4. 功能面与已知限制

**功能面**：原件唯一业务输出是 `PASS`/`FAIL`；补丁件在此维度完整可用——`scanf("%s", buf)` 照旧读入、CRT 启动/退出链（`__tmainCRTStartup` → `sym.main` → `xor eax,eax; ret`）未改动、进程不崩不挂、无延迟退出、无需额外依赖。脱壳件与压缩件五行输出矩阵完全一致，说明"脱壳"这一步没丢功能。

**已知限制（如实列，不粉饰）**：

1. **交付件是脱壳件，不是压缩件**。这一点不可回避：压缩件里没有可改的业务字节（`UPX0 size=0`）+ UPX checksum 自校验。若客户必须拿到"看起来仍是压缩件"的成品，需要在补丁后重新 `upx --best` 压回去（本阶段未做，因为重压会改变 UPX 头、引入新的 checksum 面，且 M3 未要求）。
2. **导入表被 UPX 重建，与原件有 73 字节差异**：DLL 名大小写被统一（`DLL` vs `dll`）、`OriginalFirstThunk` 等字段重排。Windows 加载器不敏感，行为已实测一致；但若后续要做"精确逐字节复刻原件"的比对，这 80 字节差异会被看到，属 UPX 的固有痕迹，非本阶段引入。
3. **PE 校验和为零**（`hdr.csum 0x00000000`，原件 `0x00016e88`）。Windows 用户态默认不校验，不影响加载；若目标环境做签名/校验和检查，需另行重算。
4. **运行时基址随 ASLR 变化**：本轮三个进程实测基址 `0x7ff715a90000` / `0x7ff65a5f0000` / `0x7ff7d7220000`，互不相同。补丁按**文件偏移 `0x1e82`** 打，不按运行时 VA 打；若要走"不脱壳、内存 Hook"路线，必须现算 `base + 0x2882`（`report/dynamic.md` §3 已给出该路线可用的内存证据）。
5. **未做 UI 改版与自有授权平台接入**：属 02/03 阶段范围。本件不含品牌替换、不含卡密服务。
6. **反例已刻意保留、但本 case 未单独出 `90 90` 实验件**：`golden-crackme` 已证 `90 90` 会恒 FAIL（因为 `je` 的顺序路径正是 FAIL 块），同一份代码同一段字节，本 case 直接采用已验证有效的 `eb 1d`，不重复制造反例件；负例由"脱壳件未打补丁 + wrong → FAIL"承担。

## 5. 证据索引

- 判壳五条依据 + 壳挡住什么 + 路线选择：`report/static.md` §2/§3/§5（表 F-101..F-109）
- 脱壳三重对账 + 80 字节差异分布 + 内存复核 + 四列地址台账 + `0x1e82` 三文件对照：`report/dynamic.md` §2/§3/§4.1
- 原始运行记录：`capture/run.json`（压缩件五行 + `shell_self_extract`）、`capture/run2.json`（补丁件五行 + `negative_control.verified=true`）
- 哈希清单：`artifacts/MANIFEST.sha256`
- 上游同源无壳案例（同一份源码的 1 分支打法）：`Tool/cases/golden-crackme/report/final.md`
