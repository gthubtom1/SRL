# dump 与重建：从内存镜像到能跑的文件

> 加载时机：已定位 OEP（见 `oep-locate.md`）。**没有 OEP 不要进入本页。**

## 0. 三种 dump 形态，先选对

| 形态 | 适用 | 工具 | 产出 |
| :-- | :-- | :-- | :-- |
| **整进程镜像** | 壳只改主模块，无额外映射 | `pe-sieve /pid <pid> /dmode 3 /out <dir>`（本机已有） | 主模块 + 被改区段 |
| **单模块 dump** | 只要主模块 | x64dbg 插件（Scylla / OllyDumpEx 类） | 一个 `dump.exe` |
| **区段级重建** | 壳把代码搬进畸形节，需要按节拼回去 | 手工：按节表 VA/Size 从内存取 | 重建后的 PE |

**选错形态的代价**：整进程 dump 会带上壳的 stub 与未解密数据，后面 IAT 修复会更难。

## 1. dump 前必须记录的四件事（否则无法复验）

| 记录项 | 为什么 |
| :-- | :-- |
| 目标 PID + 模块基址（`0x140000000` 这类） | 复验时地址会变，必须写下来 |
| OEP 的 VA 与所属节 | 判断 dump 是否落在正确点 |
| dump 时的内存大小 / 文件大小 | 判断是否截断（常见：dump 小于 ImageSize） |
| 工具版本 | 换版本再 dump 结果可能不同 |

**判据**：这四项缺任一 → 这次 dump **不可复验**，只能算一次观察（E1），不能作为交付依据。

## 2. dump 后的三项体检（不做就不知道好坏）

| # | 检查 | 命令（示例） | 通过长什么样 |
| :-: | :-- | :-- | :-- |
| 1 | **PE 头完整** | `rabin2 -I <dump>` | 能解析出 machine/entry/sections，不报错 |
| 2 | **区段尺寸合理** | `rabin2 -S <dump>` | 代码节 RawSize > 0；总和 ≈ dump 文件大小 |
| 3 | **入口落在代码节** | `rabin2 -e <dump>` 对照 `-S` | EP 的 section 是 .text 类，不是畸形节 |

**常见坏 dump 的三个症状**：`FileAlignment` 异常、`SizeOfImage` 与内存不符、区段 RawSize 全 0（说明取错了内存区）。

## 3. 重建（把 dump 修成"能加载"的 PE）

| 步 | 做什么 | 判据 |
| :-: | :-- | :-- |
| 1 | 修正 `SizeOfImage` / `SizeOfHeaders` / `FileAlignment` | 与内存一致；对齐是 0x200 的倍数（通常） |
| 2 | 修正区段 `PointerToRawData` / `SizeOfRawData` | 每个节的原始数据能覆盖它的 VA 范围 |
| 3 | 清掉壳留下的入口（把 EP 指向 OEP） | `rabin2 -e` 显示 OEP |
| 4 | 重建导入表（见 `iat-repair.md`） | `rabin2 -i` 能列出原程序的导入 |
| 5 | 重算校验和（可选） | 部分系统组件会校验；普通程序可忽略 |

> **不要**刻意去修签名：改过字节的程序签名必然失效；我们的目标是"能跑、能分析"，不是"看起来合法"。

```bash
# dump 后三项体检（只读）
rabin2 -I dump.bin     # PE 头能否解析
rabin2 -S dump.bin     # 代码节 RawSize>0、总和≈文件大小
rabin2 -e dump.bin     # EP 是否在代码节
```

## 4. 复验（这一篇的核心判据）

| 复验项 | 怎么做 | 通过 |
| :-- | :-- | :-- |
| 静态 | `rabin2 -I/-S/-i/-e` 四项都能解析 | 无报错、EP 在代码节、导入非空 |
| 动态（**需用户同意**） | 在隔离环境/快照里跑 dump 件，看是否进主界面 | 不崩、功能可见 |
| 对比 | 与原始加壳件行为对比（同输入） | 关键行为一致，且不再有壳的 stub 行为 |

**两路一致（静态解析 + 动态能跑）才算 E3**（对应我们的证据分级）；只有静态 → E2。

## 5. 多份 dump 差分：区分“已稳定”还是“还在变”

> 单次 dump 无法证明“这就是最终形态”。看两次 dump 的差异，比看一次 dump “像不像 PE” 可靠。

```bash
# 同一 PID，间隔 1–2 秒各 dump 一次（外部读，不进制程）
python Tool/skill/malware-analysis/scripts/dump-restore.py dump --pid 6428 --out work/t1/d1.bin
sleep 2
python Tool/skill/malware-analysis/scripts/dump-restore.py dump --pid 6428 --out work/t1/d2.bin
sha256sum work/t1/d1.bin work/t1/d2.bin
```

```bash
# 逐节比较两份 dump：输出“哪些节在变”
python - <<'PY'
import hashlib, struct, sys
def sections(p):
    d = open(p, "rb").read(); pe = struct.unpack_from("<I", d, 0x3C)[0]
    n = struct.unpack_from("<H", d, pe + 6)[0]; opt = struct.unpack_from("<H", d, pe + 20)[0]
    out = {}
    for i in range(n):
        o = pe + 24 + opt + i * 40
        name = d[o:o + 8].rstrip(b"\x00").decode("latin1") or f"sec{i}"
        vs, va, rs, rp = struct.unpack_from("<IIII", d, o + 8)
        out[name] = (rp, rs, hashlib.sha256(d[rp:rp + rs]).hexdigest()[:12])
    return out
a, b = sections(sys.argv[1]), sections(sys.argv[2])
for k in sorted(set(a) | set(b)):
    x, y = a.get(k), b.get(k)
    print(f"{'SAME' if x == y else 'DIFF'}  {k:10s} {x} {y}")
PY work/t1/d1.bin work/t1/d2.bin
```

**通过长什么样 / 期望输出**：

```text
DIFF  UPX0       (1024, 131072, 8f2c1a90d3ab) (1024, 131072, 5c01b7e2aa10)
SAME  UPX1       (133120, 45056, 71be44c9e120) (133120, 45056, 71be44c9e120)
SAME  .rsrc      (178176, 4096, 4a1d0f33c8b2) (178176, 4096, 4a1d0f33c8b2)
```

判读：`UPX0` 还在变（DIFF）→ 解密/写内存尚未完成，此时 dump 会拿到半成品，**不要重建**；
隔 2s 再采一次，直到目标节 `SAME` 才算稳定。**通过标准 = 两次 dump 主代码节一致**。

**约束**：目标在跑，采样本身会占 CPU；停止采样的依据是“两次一致”，不是“等够了 10 秒”。

## 6. 外部读内存失败的四个具体码

| 现象 | 码/错误 | 原因 | 动作 |
| :-- | :-- | :-- | :-- |
| `OpenProcess` 返回 0，`5` | `ERROR_ACCESS_DENIED` | 权限不足/受保护进程 | 提高权限；仍不行就是反调试（转路线 B） |
| `ReadProcessMemory` 返回 0，`299` | `ERROR_PARTIAL_COPY` | 区间含未提交页/guard 页 | 按 `VirtualQuery` 分段读，跳过 `NOACCESS` 页 |
| 返回成功但读回全 0 | 页未提交 / 读到的是旧视图 | 读错基址（ASLR）或页已被重映射 | 重新取模块基址；对照 `VirtualQuery` 的 `Type/State` |
| 读几页后目标崩溃 | 目标做了完整性自校验/反外部读 | 读操作触发了它的检测 | 降频/只读必要的页；或改用快照/内存镜像 |

```python
# 分段读：按 VirtualQuery 的 RegionSize 跳着读，避开未提交区
import ctypes, ctypes.wintypes as w
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", w.DWORD), ("__a", w.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", w.DWORD), ("Protect", w.DWORD), ("Type", w.DWORD), ("__b", w.DWORD)]
MEM_COMMIT = 0x1000
# 用法：从 base 开始循环 VirtualQueryEx，只读 State==MEM_COMMIT 的段
```

**判据**：dump 报告中必须写明“读了几段、跳过了几段、跳过原因”；
“全读成功了”而 dump 里却有大片 0，就是自欺。

## 7. 节属性与对齐修复：重建时真正要改的四组字段

| 字段 | 常见坏值 | 正确取值规则 | 不改的后果 |
| :-- | :-- | :-- | :-- |
| `SectionAlignment` | 0x1000（普通）但内存里是 0x10000 | 用内存实际对齐（从 `VirtualQuery` 相邻节地址差推） | 节 VA 全错位 |
| `FileAlignment` | 1 / 0x1000 | 通常 0x200（≥0x200 的 2 的幂） | 加载器拒绝加载 |
| `SizeOfHeaders` | 0 | `FileAlignment` 向上对齐后的头部长度 | 第一节 RawPtr 与头重叠 |
| `SizeOfImage` | 比实际节末小 | 最后一个节 VA + VirtualSize，按 SectionAlignment 对齐 | 内存映射截断，尾部代码丢失 |

```python
# 对齐计算（重建脚本里用同一套口径）
def align(v, a):
    return (v + a - 1) // a * a

size_of_headers = align(pe_offset + 4 + 20 + size_of_optional + 40 * nsec, file_alignment)
size_of_image   = align(max(va + vsize for va, vsize in sections), section_alignment)
# raw 指针：按节顺序接在头部后面，逐节按 file_alignment 对齐
ptr = size_of_headers
for s in sections:
    s.raw_ptr = ptr if s.raw_size else 0
    ptr = align(ptr + s.raw_size, file_alignment)
```

**判据**：重建后每节同时满足 `raw_ptr + raw_size <= filesize`、`raw_ptr` 是 `FileAlignment` 倍数、
节区间互不重叠；三条全成立才算布局修正完成。

## 8. 目录取舍：哪些必须保留，哪些可以清

| 目录 | 处理 | 理由 |
| :-- | :-- | :-- |
| `IMPORT` | 保留（可能要修，见 `iat-repair.md`） | 不保留无法加载 |
| `RESOURCE` | 保留 | 图标/版本/内嵌载荷都在这，删了会改变行为 |
| `RELOC` | 保留（无重定位就只能固定基址加载） | ASLR/注入/加载到其他基址时需要 |
| `TLS` | **保留** | 删 TLS 会改变执行序（脱壳场景下常是壳的入口） |
| `EXCEPTION(.pdata)` | 尽量保留 | x64 异常展开靠它；丢了后调试/异常行为可能变 |
| `SECURITY(签名)` | 保留但必然失效 | 改字节后签名不再有效（这不是失败） |
| `DEBUG(.debug)` | 可选清除 | PDB 路径泄露构建环境；脱壳件可清 |
| 壳自己新增的异常目录 | 记下来，别自动清 | 可能是壳的校验链入口 |

**判据**：每个被清掉的目录都要在报告里写“为什么可以清 + 清了之后复验结果”；
默认全部保留，只有明确无影响的才清。

## 9. checksum / 时间戳：什么时候必须重算

| 情况 | 是否重算 | 依据 |
| :-- | :-- | :-- |
| 普通用户态程序、只做分析 | 不必 | 加载器不校验 `CheckSum`（驱动/部分系统组件除外） |
| `.sys` 驱动 / Bootmgr 类 | 必须 | 内核加载器会校验；否则直接拒绝加载 |
| 目标自己读 `CheckSum` 做完整性判定 | 必须，且要与它比对的算法一致 | 否则改完就自毁（见 `anti-debug.md` §3.3） |
| 只改了节内容但没改头部 | checksum 会变 | 若声称“与原件一致”，这一点要写清 |

```bash
# 重算并写回 PE CheckSum 的最小做法（纯标准库思路）：
# 1) 把 CheckSum 字段（OptionalHeader+0x40）置 0；2) 按 16 位字求和并折叠进位；
# 3) 加上文件长度；4) 写回。改动后重跑三体检。
python Tool/skill/malware-analysis/scripts/dump-restore.py pe-info work/task/rebuilt.exe
```

**约束**：重算 checksum **不会**恢复数字签名；不要写“已修复签名”。

## 10. 坏 dump 签名扩展表（看到就回上游，不要硬修）

| 签名 | 含义 | 回哪一步 |
| :-- | :-- | :-- |
| 代码节熵 >7.2 且无导入 | 拍早了（还在解密） | 回 `oep-locate.md` §4 |
| 代码节全是 `0xCC` | 拍早了且在填充区 | 同上 |
| 文件比 `SizeOfImage` 小很多 | 只 dump 了节头/部分页 | 回本文 §6 分段读 |
| 节表项数正常但节内容全 0 | 读的是未提交页 | 同上 |
| EP 指向壳节 | dump 点错或未改入口 | 回 §7 修 EP / 重定位 OEP |
| `Machine`/`Magic` 不对（PE32 vs PE32+） | 拿错镜像（32/64 混） | 确认 PID 与模块位数 |
| 两份 dump 主代码节不一致 | 未稳定 | 回本文 §5 |

**失败两次就停**：同一签名处理两次仍不消失，转路线 B（运行期/外部观测），不要再重建第三版。

## 10bis. 重建后自检：四条不变量一次性验完

> 前文的体检是“分项看”，这里把四项写成一次可重跑的检查，避免漏项。

```python
#!/usr/bin/env python3
# 只读自检：退出码 0 = 四条全过；非 0 = 哪条不过
import struct, sys
p = sys.argv[1]
d = open(p, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
mach, nsec = struct.unpack_from("<HH", d, pe + 4)[0], struct.unpack_from("<H", d, pe + 6)[0]
opt = struct.unpack_from("<H", d, pe + 20)[0]
magic = struct.unpack_from("<H", d, pe + 24)[0]
fa = struct.unpack_from("<I", d, pe + 24 + 36)[0]
sa = struct.unpack_from("<I", d, pe + 24 + 32)[0]
soi = struct.unpack_from("<I", d, pe + 24 + 56)[0]
bad = []
secs = []
for i in range(nsec):
    o = pe + 24 + opt + i * 40
    vs, va, rs, rp = struct.unpack_from("<IIII", d, o + 8)
    secs.append((va, vs, rp, rs))
    if rs and rp % max(fa, 1) != 0:
        bad.append(f"sec{i}: raw_ptr {rp:#x} 未按 FileAlignment 对齐")
    if rs and rp + rs > len(d):
        bad.append(f"sec{i}: raw 越界 {rp + rs:#x} > {len(d):#x}")
for a, b in zip(sorted(secs), sorted(secs)[1:]):
    if a[2] + a[3] > b[2] and a[3] and b[3]:
        bad.append(f"raw 重叠 {a:#x} {b:#x}")
if soi < max(va + vs for va, vs, _, _ in secs):
    bad.append("SizeOfImage 小于节末")
print("machine", hex(mach), "magic", hex(magic), "sections", nsec, "soi", hex(soi))
print("OK" if not bad else "FAIL\n  " + "\n  ".join(bad))
sys.exit(0 if not bad else 2)
```

**通过长什么样 / 期望输出**：

```text
machine 0x8664 magic 0x20b sections 6 soi 0x2a000
OK
```

| 退出码 | 含义 | 下一步 |
| :-: | :-- | :-- |
| 0 | 四项不变量全过 | 进 `iat-repair.md` |
| 2 + `raw 越界` | `SizeOfRawData` 过大或文件截断 | 回 §7 重算 raw 指针 |
| 2 + `SizeOfImage 小于节末` | 尾部节被忽略 | 回 §7 重算 `SizeOfImage` |
| 2 + 未对齐 | `FileAlignment` 选错 | 先用 0x200 重试；仍不行说明是畸形壳 |

**约束**：自检通过 ≠ 能跑。能跑仍需 §4 的隔离环境实跑（且需用户同意）。

## 11. 这一篇算"用对了"吗

- [ ] 我记录了 PID/基址/OEP/大小/工具版本四项
- [ ] dump 后跑了三项体检，且能说出坏在哪（如果坏）
- [ ] 重建后 `rabin2 -I/-S/-i/-e` 四项都能解析
- [ ] 若声称"能跑"，我有一次实际运行证据（且用户同意过）
