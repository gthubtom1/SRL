# 壳速查：先认出是哪一类，再决定走哪条路

> 加载时机：`seep_packer_detect` 报 `packed=true`，或节表异常（RawSize=0 / 高熵 / 畸形节名）。
> **每条都带"怎么验证"，不许凭感觉下结论**（外部评审反复指出：只凭熵就判壳 = 猜）。

## 0. 判壳的最小证据集（三条全有才算"判出来"）

| # | 证据 | 命令（示例，先 `--help` 确认本机用法） | 通过长什么样 |
| :-: | :-- | :-- | :-- |
| 1 | **节表异常**：标准节 RawSize=0，或单节占 >90% 且熵 >7.5 | `python Tool/scripts/../mcp` 无；用 `rabin2 -S <f>` 或 `seep_packer_detect` | 输出里能看到节名/RawSize/熵 |
| 2 | **导入表异常**：只有极少数导入（LoadLibrary/GetProcAddress/VirtualProtect） | `rabin2 -i <f>` | 导入条数 < 10 且集中在少数 API |
| 3 | **入口点在异常节**：EP 落在最后一个大节或非 .text | `rabin2 -e <f>` 与 `-S` 对照 | EP 的 section 字段不是 .text |

**只有一条命中 → 只能说"疑似加壳"，不能进脱壳流程**（要先补第二条证据）。

## 1. 五类壳（决定路线，不决定工具）

| 类 | 特征 | 典型样本信号 | 路线 |
| :-- | :-- | :-- | :-- |
| **A. 标准压缩壳** | 已知节名（UPX0/UPX1、.aspack、.MPRESS1）；熵高但**可逆** | `UPX!` 魔数、`upx -l` 能读 | **直接 `upx -d` / `aspack` 官方解包**；成功即完成，不必动态 |
| **B. 加密壳（整盘加密）** | 源码节 RawSize=0，内容全塞进一个畸形节（如 `.(D6`） | 熵 7.8–8.0；导入极少 | **必须动态**：到解密完成点 → dump → 修 IAT（见 `oep-locate.md`） |
| **C. 虚拟化保护（VMProtect/Themida）** | 有 VM 入口、`.vmp0/.vmp1`、大量 `push/ret` 混淆 | 反调试导入、VM 节 | 静态基本无解；走**函数级**：定位目标函数 → dump 前后对比 / devirtualise 局部 |
| **D. 商业反作弊 + 加固（ACE 类）** | `.ace0` 节、内核驱动（`ACE-BASE.sys`）、自校验 | 启动即加载驱动、扫盘 | **先判型**：客户端静态上限通常只有 M1；动态需用户明确同意（内核驱动 = L3 副作用） |
| **E. 自研/变形壳** | 畸形节名（随机）、自定义 linker、stub 熵极高 | 无公开签名、节名不可打印 | 只能按 B 类流程走；**每步留证据**，不猜 |

**判定口径**：A 类可以"解包即完成"；B 类必须"dump + IAT 修复 + 复验"三件齐；C/D 类先给上限再问用户。

## 2. 三个常见误判（都是"看起来像"）

| 误判 | 真相 | 怎么排除 |
| :-- | :-- | :-- |
| "熵高就是加壳" | 资源/字体/模型文件也能让整体熵到 7.9 | 看**单节**熵 + 该节是否可执行；`.(D6` 类畸形节才算强证据 |
| "EP 不在 .text 就是壳" | 老 Delphi/Go 程序 EP 常在 `.itext`/`.text` 边缘 | 对照编译器签名（`rabin2 -I` 的 lang/compiler 字段） |
| "导入少就是壳" | Go/Rust 静态链接的程序导入天生很少 | 看是否有 `runtime`/`go.` 字符串或 `.gopclntab` 节 |

## 3. 工具（本机已有 / 缺什么）

| 用途 | 工具 | 备注 |
| :-- | :-- | :-- |
| 判壳（多信号） | `seep_packer_detect(binary_path=…)` | 返回 `packed/warning/next_actions`，直接用它的结论 |
| 节表/导入/EP | `rabin2 -S -i -e` 或 `seep_r2_info` | 只读 |
| 交叉验证"是什么壳" | `diec.exe <f>`（Detect It Easy CLI） | 与上一条**互为独立证据**（两路一致才算 E3） |
| 内存镜像 | `pe-sieve /pid <pid> /dmode 3 /out <dir>` | 需要目标正在运行（先问用户） |
| dump + IAT | x64dbg + Scylla | GUI 通道；按 `AGENTS §四点五.4` 走 |

```bash
# 判壳三件套（只读）
rabin2 -S target.exe | head -30     # 节表：RawSize=0 / 畸形节名
rabin2 -i target.exe | head -20     # 导入：条数极少 = 疑似壳
rabin2 -e target.exe                # EP 落在哪个节
diec target.exe                     # 独立第二路（交叉验证→E3）
```

## 4. 扩展指纹表：节名 → 壳族 → 特征串 → 路线

> 用法：先在**磁盘文件**里 grep 节名/魔数，再和 `rabin2 -i` 的导入数交叉。**一行命中只算线索**，
> 需要「节名 + 特征串」或「节名 + 导入画像」两条同时成立（见本页 §0）。

| 壳族 | 典型节名 | 特征串 / 魔数 | 入口与导入特征 | 路线 | 误判提示 |
| :-- | :-- | :-- | :-- | :-: | :-- |
| UPX 2.x/3.x | `UPX0` `UPX1`(x64: `UPX0`+`UPX2`) | `UPX!`、`$Info: This file is packed with the UPX` | EP 在 `UPX1` 尾部；导入仅 `LoadLibraryA/GetProcAddress/VirtualProtect` | A（`upx -d`） | 3.9x 把跳转改成双层 stub，老版 `upx -d` 报 `CantUnpackException` |
| UPX 改头 | 节名被改成 `.adata` / 随机 4 字节 | 仍有 `UPX!`，但 `p_info`/`l_info` 被抹 | 同上 | B（先按 `UPX!` 定位修头，再 `upx -d`） | 只看节名会误判成 ASPack |
| ASPack 2.12/2.2x | `.aspack` `.adata` | `aPLib` 报错串 `aPLib: fatal`、`AP32` | EP 在 `.aspack`；导入 5–20 条 | A/B（解包机 / ESP 定律） | `.adata` 是多壳共用名，不能单独定案 |
| ASProtect 1.x/2.x | `.aspr` `.adata` | `ASProtect`、`SSSS`、`\.\ASProtect` | 有 SEH 链、DR 检测、导入被部分保留 | B | 加壳后仍留原始导入 → 导入数看起来"正常" |
| MPRESS 2.x | `.MPRESS1` `.MPRESS2` | `MPRESS` 串、`aPLib` 解压循环 | EP 在 `.MPRESS1`；导入极少 | A（`mpress -d`）或 B | 64 位 `.MPRESS1` 与 32 位布局不同，别混用工具 |
| PECompact 2.x | `pec1` `pec2`、`.pec` | `PECompact2`、`PEC2` | EP 在 `pec1`；有 TLS 回调早检 | B | 有 TLS 回调不等于壳，正常 CRT 也用 |
| PEtite 2.x | `.petite` | `petite`、`PEtite` | EP 在 `.petite`，导入 < 10 | B（ESP 定律） | 老样本，签名库常漏 |
| FSG 1.x/2.0 | 无标准名，常为 `.text`+大 gap | `FSG!` 少见；以"单节占 >90% + RawSize=0"为准 | EP 在末节；导入 1–3 条 | B | 与 MEW 混淆，两者都靠导入画像区分不了 → 走流程不看名字 |
| MEW 1.x | `.nsp0` 或畸形 | `MEW` 偶现；代码段自解密 | EP 在末节，`pushad/popad` 特征 | B | — |
| NsPack | `.nsp0` `.nsp1` `.nsp2` | `NSPack` | 三节：0/1/2，EP 在 `nsp1` | B | `.nsp0` 只有 VirtualSize 没有 RawSize，容易被当成畸形文件 |
| kkrunchy | `kkrunchy` | `kkrunchy` | 极小体积（<8KB）、导入 0–2 条 | B | 演示作品/CTF 常见，不是恶意专用 |
| Themida / WinLicense | `.themida` `.winlice`、随机名节 | `Themida`、`WinLicense`、`\.\{...}` 设备名 | 双节（代码+数据），VM 入口，驱动可选 | C/B | 新版可改名节 → 靠"两节 + 高频 `push/ret` + 导入极少"判 |
| VMProtect 2.x/3.x | `.vmp0` `.vmp1`（可改名） | `VMProtect`、`.vmp` 残留、VM handler 特征序言 | EP 在 `.vmp0`；导入多但集中在 stub | C（函数级）/B | 导入数可能正常（壳保留了 IAT），别用导入数否定 VMP |
| Enigma Protector | `.enigma1` `.enigma2` | `Enigma`、`Enigma Protector` | 有注册/试用逻辑、TLS 早检 | B | 商业试用保护的"授权检查"与恶意校验难区分 |
| Obsidium | `.obsidium`、随机 | `Obsidium` | 反调试强（DR/时序） | C | — |
| Armadillo | `.text1`、`.adata` | `Armadillo`、`PDV` | 有"复制到临时目录再跑"的 child 进程 | B（注意父子进程） | dump 父进程拿到的是壳，不是载荷 |
| Molebox / BoxedApp | `.molebox`、`.boxed` | `Molebox`、`BoxedApp` | 内嵌文件系统虚拟化，资源里有多个 PE | B（先 `iR` 抽资源） | 真正的载荷在资源里，脱主 PE 无意义 |
| .NET Reactor | 节名常保留 `.text` | `has_clr=true` + `Reactor`/`NETReactor` | CLR 头 + 元数据被加密 | A′（dnSpy/de4dot，非 PE 脱壳） | 用 x64dbg 脱 .NET 是白费 |
| ConfuserEx / SmartAssembly | `.text` + 随机名 | `ConfuserEx`、`SmartAssembly`、`Powered by .NET Reactor` | CLR + 控制流混淆/字符串加密 | A′ | 反编译不出源码 ≠ 加壳 |
| ACE / TP 系（腾讯反作弊加固） | `.ace0` `.ace1`、`.tps` | `ACE-BASE`、`SGuard`、`ACE-Guard` | 用户态 stub + 内核驱动（`.sys`） | D（先判型，给上限 M1） | 加载驱动 = L3 副作用，**先问用户** |
| nProtect / XignCode | `.npk`、`.xcode` | `nProtect`、`XignCode`、`XignCode3` | 内核驱动 + 定期心跳校验 | D | — |
| 自研/变形壳 | 随机可打印或不可打印节名 | 无公开签名 | 单节占 >90%，导入 ≤5 | B + 每步留证 | 判不出名字是**正常结果**，不要编壳名 |

**这张表的正确用法**：先得到 2–3 个候选，再用 §5 的数值与 §6 的导入画像做排除，最后按 §8 记录。
**不能**用"节名像 X 壳"直接写报告结论。

## 5. 数值判据：熵、节占比、导入数（可复算）

> 以下是判壳的**硬数值**，全部只读、全部可复算；口径固定后才能和别人对齐。

| 指标 | 计算口径 | 阈值（经验） | 说明 |
| :-- | :-- | :-- | :-- |
| 单节熵 | 对该节**文件字节**（RawSize 范围）算 Shannon 熵 | 代码节 ≥7.2 且 RawSize ≥512 → 可疑 | 整体熵不看；`.rsrc` 高熵不算 |
| 可执行节占比 | `sum(RawSize of executable sections) / filesize` | 单节 >0.85 → 可疑 | 正常 PE 通常 <0.6 |
| 零填充节 | 节 `RawSize=0` 或 `VirtualSize>RawSize*4` | 命中即记 `uninit-section` | 典型壳的"解压目标节" |
| 导入条数 | `rabin2 -i` 的行数 | ≤8 条 → 可疑；≤3 → 强可疑 | Go/Rust 静态链接是反例 |
| 导入 DLL 数 | 去重后的 DLL 数 | ≤3 个 DLL → 可疑 | 同上 |
| 节名可打印率 | 节名中 `[\x20-\x7e]` 字节占比 | <100% → 自定义/变形壳线索 | 部分壳故意写不可打印节名 |
| 节数 | `rabin2 -S` 节表项数 | 2–3 节且其中一节占 >90% → 强可疑 | 正常链接器产物常见 5–8 节 |
| overlay | `filesize - max(PointerToRawData+SizeOfRawData)` | >4KB 且熵 >7.0 → 记 `overlay-payload` | 安装包/自解压也有 overlay |

```bash
# 一次算完：节表 + 熵 + 可执行占比 + overlay + 导入数（只读，纯标准库）
python - <<'PY'
import math, struct, subprocess, sys
p = sys.argv[1] if len(sys.argv) > 1 else "target.exe"
d = open(p, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
opt = struct.unpack_from("<H", d, pe + 20)[0]
base = pe + 24 + opt
rows, end = [], 0
for i in range(nsec):
    o = base + i * 40
    name = d[o:o + 8].rstrip(b"\x00").decode("latin1")
    vs, va, rs, rp = struct.unpack_from("<IIII", d, o + 8)
    ch = struct.unpack_from("<I", d, o + 36)[0]
    body = d[rp:rp + rs]
    ent = 0.0
    if body:
        for c in set(body):
            f = body.count(c) / len(body)
            ent -= f * math.log2(f)
    rows.append((name, rs, round(ent, 2), bool(ch & 0x20000000)))
    end = max(end, rp + rs)
print("sections:", rows)
print("exec_ratio:", round(sum(r[1] for r in rows if r[3]) / max(len(d), 1), 3))
print("overlay:", len(d) - end)
PY
rabin2 -i target.exe | wc -l      # 导入条数
rabin2 -S target.exe | wc -l      # 节表项数（含表头行时减 2）
```

**通过长什么样 / 期望输出**：

```text
sections: [('UPX0', 0, 0.0, True), ('UPX1', 45056, 7.91, True), ('.rsrc', 4096, 4.62, False)]
exec_ratio: 0.93
overlay: 0
```

判读：`UPX0` 的 RawSize=0（解压目标节）+ `UPX1` 熵 7.91 且可执行 + 可执行占比 0.93 →
三条数值同时成立，可以直接进 A 类路线并用 `UPX!` 交叉验证。
**反面**：如果只有 `exec_ratio` 高，但可执行节熵 5.4、导入 200 条 → 更可能是控件/游戏 exe，不要判壳。

## 6. 导入画像：用"缺了谁"判壳，而不是用"有谁"

| 导入画像 | 说明 | 需要第二条证据 |
| :-- | :-- | :-- |
| 只有 `LoadLibraryA`+`GetProcAddress`+`VirtualProtect` | 典型壳 stub 三件套 | 高熵可执行节 / `UPX!` 类签名 |
| 只有 `GetModuleHandleA`+`GetProcAddress` | 手写解析导入 | 节名异常 + 导入 ≤5 |
| 有 `VirtualAlloc`+`VirtualProtect` 但无 `CreateFile` | 只用内存，不落地 | 可执行占比高 + overlay |
| 导入数 >100 但集中在 `KERNEL32`/`USER32` | 壳保留了原始 IAT（VMP 常见） | 不能用导入数否定壳，看节/入口 |
| 导入 0 条（无导入目录） | 序数导入或完全手写 | `rabin2 -i` 报空 + 入口在末节 |
| 有 `mscoree.dll` + `_CorExeMain` | .NET 程序 | `has_clr=true`；走 A′ 路线 |
| 有 `rust_eh_personality`/`go.buildid` | Rust/Go 静态链接 | 导入少是正常的，**不是壳** |

**排除规则（必须做，否则误判率高）**：

1. 先看编译器/语言签名：`rabin2 -I` 的 `lang`/`compiler` 字段，或 `strings | grep -E 'go1\.|rustc|GO build'`。
2. 再看是否有 `UPX!`/`MPRESS` 这类**主动签名**（比"导入少"强得多）。
3. 最后才用数值阈值。**顺序反了就会把 Go/Rust 程序判成壳。**

## 7. 未知壳（自研/变形）的判定流程

> 判不出壳名是**合法结论**，不要为了填报告编一个名字。要做的是"判类型 + 给路线"。

| 步 | 动作 | 判据 |
| :-: | :-- | :-- |
| 1 | 节名/节数/可执行占比（§5 脚本） | 得到数值画像，存档 |
| 2 | 入口前 64 字节反汇编（`rabin2 -e` 取 RVA → `r2 -A -q -c 'pd 32 @ entry0'`） | 是 `pushad`/`popad`/`jmp` 链 → stub；是 `sub rsp,X` 序言 → 可能无壳 |
| 3 | 找"写可执行内存"的调用（`VirtualProtect`/`VirtualAlloc` 的 xref） | 有 → 存在运行期解密 |
| 4 | 找壳的特征串前缀（`strings -n 6 | grep -Ei 'pack|protect|enigma|licen'`） | 命中即交叉验证，不命中不算反证 |
| 5 | 按 §1 归到 B 类（因为 A 类都有签名） | 归 B → 走 `oep-locate.md`，每步留证据 |

**失败判据**：走了 1–5 仍无法区分"自研壳"和"链接器异常"→ 写 `family=unknown`、
`route=B`、`blocked_at=no-signature`，并把 §5 的数值画像贴进报告；**不要**继续猜名字。

## 8. 判壳记录模板（照抄，字段可机检）

```json
{
  "sha256": "<64 hex>",
  "family": "UPX",
  "confidence": "high",
  "evidence": [
    {"kind": "section", "value": "UPX0 RawSize=0", "cmd": "rabin2 -S target.exe"},
    {"kind": "signature", "value": "UPX!", "cmd": "strings -a target.exe | grep -m1 UPX!"},
    {"kind": "entropy", "value": "UPX1=7.91 exec", "cmd": "python entropy.py target.exe"},
    {"kind": "imports", "value": "3 (LoadLibraryA/GetProcAddress/VirtualProtect)", "cmd": "rabin2 -i target.exe"}
  ],
  "route": "A",
  "instrument_still_unknown": ["x64dbg", "frida-attach"],
  "blocked_at": null
}
```

判据：`evidence[]` 至少 2 条且 `kind` 不同；`route` 只能是 `A`/`A′`/`B`/`C`/`D`；
每个 `cmd` 必须是你**真跑过**的命令（能贴出原始输出）。缺 `cmd` 的证据视为"印象"，不算证据。

## 9. 判壳失败判据（看到即停，别往下推）

| 现象 | 判定 | 动作 |
| :-- | :-- | :-- |
| 只有一条证据（例如只有熵高） | 证据不足 | 补第二条（§5 数值 / §6 画像 / 主动签名），不许进脱壳 |
| 两条证据互相矛盾（签名 `UPX!` 但入口在 `.text` 序言） | 可能是"壳后二次编译"或改头 | 按 B 类走，先验入口 |
| 节表本身坏（`rabin2` 报错） | 静态面已不可信 | 转内存 dump（`dump-restore.py dump`）+ 判型降级 |
| `diec` 与 `rabin2` 结论不一致 | 两路冲突 | 记 `confidence=medium`，写清冲突点，**不许取好看的那个** |
| 判型反复两次仍不能归 A/B | 熔断 | 停手，按 SKILL 的两次熔断换路线或退出 |

## 9bis. A 类的一键解包：命令与失败处理

> A 类（有官方解包器）成本最低，但**失败率不低**：改头、退化版本、附加载器都会让官方工具报错。
> 原则：先解包，解包失败立即转 B 类，不要在"继续调 upx 参数"上消耗第二次熔断机会。

```bash
# 1) 先看能不能识别（只读，不解包）
upx -l target.exe                     # 列出压缩块与版本；报 NotPackedException 说明不是标准 UPX
upx -t target.exe                     # 完整性测试
# 2) 在副本上解包（原件只读）
mkdir -p work/<task>/unpack && cp target.exe work/<task>/unpack/copy.exe
upx -d -o work/<task>/unpack/unpacked.exe work/<task>/unpack/copy.exe
# 3) 解包后三项体检
rabin2 -I work/<task>/unpack/unpacked.exe
rabin2 -e work/<task>/unpack/unpacked.exe
rabin2 -i work/<task>/unpack/unpacked.exe | wc -l
```

**通过长什么样 / 期望输出**：

```text
                       Ultimate Packer for eXecutables
  File size         Ratio      Format      Name
-------------------- ------ ----------- -----------
  200704 ->    102400   51.02%    win64/pe  unpacked.exe

Unpacked 1 file.
```

解包成功后：`rabin2 -e` 的入口落在 `.text`（不再是 `UPX1`），导入条数从 3 跳到原始量级（常见 40–300）。

| 失败现象 | 原因 | 动作 |
| :-- | :-- | :-- |
| `CantUnpackException: file is modified/hacked` | 壳头被改（加壳后又被改过） | 用 `UPX!` 串定位 `p_info`/`l_info` 手工修头；修不动就转 B |
| `upx -d` 成功但文件跑不起来 | 原程序另有启动器/自校验 | 三项体检 + 在隔离环境试跑；失败则回 B 类动态 |
| 解包后熵仍 >7.2 | 只剥了外层，内层还套了一层 | 对输出再做一次 §5 数值计算，按 B 类继续 |
| 多个 `UPX!` 串（叠加壳） | 双层 UPX | 连续解两遍，每遍存副本并记 hash |
| 工具报 `NotPackedException` 但节名像 UPX | 节名伪造 | 按 B 类走，不靠节名 |

**约束**：不在主机上装来源不明的 `upx`；只用手头验证过的版本，并记录版本号（不同版本对改头 UPX 行为不同）。

## 10. 判据：这一篇算"用对了"吗

- [ ] 我能说出**三条证据**里的至少两条，且每条都指得出命令与输出
- [ ] 我能说出属于 A/B/C/D/E 哪一类，以及**为什么不是最像的另一类**
- [ ] 若判为 C/D 类，我已经给了"上限 M1"和"需要用户确认什么"
- [ ] 我没有在判壳完成前就 dump 或改字节
