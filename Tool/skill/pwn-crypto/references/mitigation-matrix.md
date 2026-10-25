# mitigation-matrix.md — 保护位 × 利用手法 × 判据

> 配套 `pwn-crypto/SKILL.md`。表里的“首试”是排序，不是保证；每次都要用泄漏/调试器复核。
> PE 没有 ELF 的 RELRO/canary 语义，用 DllCharacteristics、导入表、load config 近似。

**本域输入面**：本文件把 checksec/DllCharacteristics 的观测映射到首选手法与最小证据，用于开局排序。
**用法**：保护位是输入，不是“能不能打”的最终结论；PE 与 ELF 术语按平台分册；目标范围由 `scope` 声明。

## 1. 总表

| # | 观测 | 阻断什么 | 首试手法 | 成立判据 | 失败/误判 |
|---|---|---|---|---|---|
| 1 | `NX enabled` | 栈/堆 shellcode | ret2libc、ROP、ret2csu、SROP、ORW | 链命中函数/gadget，拿到 shell 或 flag | 还往栈上塞 shellcode；栈未 16 字节对齐 |
| 2 | `NX disabled` | 无 | 栈上 shellcode + 跳转 | `$rip` 落在栈且指令可执行 | 坏字符截断；栈地址随机未泄漏 |
| 3 | `PIE enabled` | 硬编码代码地址 | 先泄漏 code/libc；1–2 字节部分覆盖 | 泄漏低 12 位与目标符号吻合 | 跨页部分覆盖；把本地基址当远程 |
| 4 | `PIE disabled` | 无（代码固定） | 直接写 GOT/返回地址 | 目标地址固定且写后读回正确 | 忘了 libc 仍受 ASLR 影响 |
| 5 | `Canary found` | 连续栈溢出 | 泄漏 canary；格式化串/堆；fork 复用 | canary 字节完整且覆盖后不 abort | 只泄漏 7 字节；覆盖到 TLS 而非栈 |
| 6 | `No canary` | 无 | 直接覆盖返回地址 | 偏移稳定、`$rip` 受控 | 把局部缓冲区大小当偏移 |
| 7 | `Partial RELRO` | 无（GOT 可写） | GOT 覆写、格式化串任意写 | 写后目标函数指针/ GOT 值改变 | 只改到只读页；`%n` 输出被截断 |
| 8 | `Full RELRO` | GOT 覆写 | hook/exit handler/函数指针/栈迁移 | 触发链走到受控目标 | glibc≥2.34 还在找 `__free_hook` |
| 9 | `FORTIFY` | 部分溢出 | 打逻辑/堆/整数，避开 `__*_chk` | 越界发生在检查覆盖不到的对象 | 仍用 `strcpy` 长串硬撞 |
| 10 | `CET/IBT/SHSTK` | 任意跳转/ROP | 先确认是否真正启用；影子栈下改走数据/逻辑 | 目标 CPU/内核实际开启且触发 #CP | 只看编译标志就判死 |
| 11 | `seccomp` 白名单 | 任意 syscall | ORW/openat/read/write；mprotect+shellcode | syscall 序列与白名单一致且读到 flag | 没读全 BPF；fd 猜错；路径不可写 |
| 12 | ASLR 开启 | 固定基址 | 信息泄漏；暴力（fork 服务）；部分覆盖 | 远程泄漏可重复；爆破成功率可统计 | 用本地关 ASLR 的地址 |
| 13 | 静态链接/去符号 | 符号定位 | 字符串/xref/签名/调试器；libc 符号自建 | 能定位到函数边界与调用点 | 猜函数名；把 padding 当函数 |
| 14 | `RPATH/RUNPATH` 可写 | 加载可信库 | 替换同目录库；核对加载顺序 | `LD_DEBUG=libs` 显示加载了替换库 | 只改文件没改运行目录/权限 |
| 15 | glibc≥2.34 | hook 路线 | IO_FILE/exit_funcs/environ/程序指针 | 触发链命中伪造结构且不 abort | vtable 越界；`_wide_data` 未映射 |
| 16 | glibc 2.32+ safe-linking | 直接写 fd | `target ^ (chunk>>12)`；先泄漏 heap | malloc 返回 target；堆检查通过 | 未解码就 poison；target 未 0x10 对齐 |
| 17 | PE `NX_COMPAT` | 栈/堆执行 | ROP/ret2libc 等价；VirtualProtect 改页 | 链命中且页权限变为可执行 | 把 DLL 当 ELF 找 PLT/GOT |
| 18 | PE `DYNAMIC_BASE` | 固定映像基址 | 泄漏模块基址；部分覆盖 | 模块基址页对齐且与泄漏吻合 | 忘了 DLL 重定位/ASLR 差异 |
| 19 | PE `SecurityCookie` | 栈溢出 | 泄漏 cookie；格式化/堆；SEH 覆盖 | cookie 正确且异常链受控 | 只改栈不恢复 cookie；/GS 范围误判 |
| 20 | PE `CFG` | 间接调用劫持 | 改数据/逻辑；找未登记回调 | 目标调用点不在 CFG 检查内 | 认为 CFG 等于不能利用 |
| 21 | 32-bit x86 | 无 | ret2dlresolve、栈迁移、SROP（int 0x80） | 调用约定/对齐正确，参数在栈上 | 用 x64 gadget；忘了 `int 0x80` ABI |
| 22 | ARM64 | 无 | gadget 搜索、`x0–x7` 参数、`svc 0` | 寄存器/对齐/缓存一致 | 套用 x86 寄存器名 |
| 23 | 沙箱只放行白名单 syscall（`execve` 被 seccomp 拦截） | 直接 shell | ORW / `openat` / `sendfile` | 读到 flag 或外带成功 | 只拿 shell 却被 seccomp 杀 |
| 24 | 无泄漏点 | 地址随机 | 部分覆盖、暴力、侧信道、逻辑漏洞 | 多次运行成功率可量化 | 把一次碰撞当稳定 |

## 1.1 `pwn-check` 输出怎么读（键名与含义）

```bash
python Tool/skill/pwn-crypto/scripts/pwn-check.py --file ./chall --json > evidence/protect.json
python -c "import json;d=json.load(open('evidence/protect.json'));print(d['protections']);print(d['next_routes'][:3])"
```

通过长什么样：

```text
{'NX': 'Enabled', 'PIE': 'Enabled', 'Canary': 'Found', 'RELRO': 'Full'}
['fmt-string-leak', 'heap-route', 'no-hook-after-2.34']
```

| 键 | 取值 | 怎么用 | 不要怎么用 |
|---|---|---|---|
| `protections.NX` | Enabled/Disabled | Disabled 先考虑 shellcode | 不能据此判“能执行任意代码” |
| `protections.PIE` | Enabled/Disabled | Enabled 必须先泄漏代码基址 | 低位页内偏移仍固定 |
| `protections.Canary` | Found/Not found | Found 时找 `fs:0x28` 确认每函数 | 全局有 ≠ 每个函数有 |
| `protections.RELRO` | Full/Partial/None | Partial/None 才考虑 GOT 覆写 | Full 时仍可打 `.fini_array`/函数指针 |
| `dangerous_imports` | 列表 | 定输入面（`strcpy/gets/printf`） | 导入 ≠ 可达 |
| `format_string_risks` | 列表 | 有格式化串调用点时优先测 `%s/%n` | 有模板 ≠ 参数可控 |
| `next_routes` | 列表 | 当候选路线排序的起点 | 当结论 |

读法示例：`RELRO: Full` + `format_string_risks` 非空 → 走“格式化串任意读/写 + 堆/逻辑”，
不要先算 GOT 偏移；`PIE: Disabled` + `Canary: Not found` + `NX: Enabled` → ret2libc/ROP 首选。

## 1.2 保护位组合矩阵（组合比单项更有信息）

| NX | PIE | Canary | RELRO | 首选 | 次选 | 最小证据 |
|---|---|---|---|---|---|---|
| off | any | any | any | 栈 shellcode | 注入 .bss + 跳转 | `$rip` 落在栈/bss 且可执行 |
| on | off | 无 | Partial | ret2libc/ROP | ret2plt | 偏移 + 泄漏 + marker |
| on | off | 有 | Partial | 先泄漏 canary → ROP | 格式化串/堆 | canary 字节完整 |
| on | on | 无 | Partial | 泄漏 code+libc → ROP | 部分覆盖 | 泄漏低 12 位匹配 |
| on | on | 有 | Partial | 格式化串/堆 | 逻辑漏洞 | 任意读/写读回 |
| on | on | 有 | Full | 堆/IO/exit/函数指针 | 逻辑 | 写后读回 + 不 abort |
| on | on | 有 | Full + seccomp | ORW / mprotect+shellcode | SROP | syscall 序列 + flag |
| on | any | any | Full + CET | 数据/逻辑面 | 先确认 CET 真启用 | 触发 #CP 的记录 |

用法：先用 L0 定位到某一行，再按“首选”排时间盒；**不要**从第一行开始逐条试。

## 1.3 泄漏来源清单（先找最便宜的那一个）

| 来源 | 前提 | 泄漏什么 | 偏移来源 | 失败信号 |
|---|---|---|---|---|
| GOT 里的 libc 函数 | 能任意读或能调 `puts/write` | libc 基址 | `libc.symbols['puts']` | 输出被 NUL 截断；符号未解析（lazy） |
| `environ` | 任意读 | 栈地址 | `libc.symbols['environ']` | 读到 0/未初始化 |
| unsorted bin 的 fd/bk | 能读 freed chunk 且 tcache 已满 | `main_arena` → libc | `libc.symbols['main_arena']` | 直接进 tcache，看到的是堆指针 |
| tcache fd | 能读 freed chunk | heap 基址 | 2.32+ 需 `fd ^ (chunk>>12)` | 未解码，值看着随机 |
| PIE 部分覆盖 | 能改 1–2 字节返回地址 | 代码基址（页内低位固定） | 目标 gadget 的页内偏移 | 跨页（低 12 位变了） |
| PE IAT | 能任意读 | 模块基址 | 导入函数 RVA | `DYNAMIC_BASE` 未开（不需要泄漏） |
| 格式化串 `%s` | 参数槽可控 | 任意地址内容 | 目标地址本身 | 参数序号错、地址含 NUL |
| 报错/日志反射 | 程序把指针打进日志 | libc/heap | 同上 | 只打 `%p` 值，非目标地址 |

判据：泄漏值必须**页对齐**且**低 12 位**与目标符号吻合；两个条件缺一，写“疑似”。

## 1.4 从保护位到链的落地顺序（四步，每步可停）

```bash
# 1) 静态：保护位 + 危险导入 + 候选路线
python Tool/skill/pwn-crypto/scripts/pwn-check.py --file ./chall --json > evidence/L0.json
# 2) 偏移：两源对齐（PE/ELF 通用）
python Tool/skill/pwn-crypto/scripts/pwn-repro.py --objdump evidence/chall.dis --func vuln   --probe-log evidence/probe.txt --json > evidence/L1.json
# 3) 泄漏：本地跑一次，确认页对齐
python exploit.py --leak-only 2>&1 | tee evidence/leak.txt
# 4) 控制：marker / shell，再跑 10 次统计
for i in $(seq 10); do timeout 30 python3 exploit.py > runs/run.$i 2>&1; echo "$i $?"; done
```

通过长什么样（每步一行，失败即停）：

```text
L0 {'NX': 'Enabled', 'PIE': 'Enabled', 'Canary': 'Found', 'RELRO': 'Full'}
L1 True 40
leak 0x7f2c4a1d0000 aligned=True low12=0x000
1 0
... 10 0
```

四步都过才写“打通”；第 3 步 `aligned=False` 就回去换泄漏点，不要继续拼链。

## 1.5 三种“半开”状态（别用二值判断）

| 状态 | 看起来 | 实际 | 怎么办 |
|---|---|---|---|
| PIE 只随机基址 | “PIE 开了就不能打” | 页内偏移固定，1–2 字节部分覆盖仍可用 | 用部分覆盖改返回地址低 2 字节 |
| Full RELRO 但 `.fini_array` 可写 | “GOT 保护了就没写点” | `.fini_array`/函数指针/`__exit_funcs` 仍可能可写 | `readelf -SW` 看段权限，找可写函数指针 |
| seccomp 只拦 `execve` | “有沙箱就没法读 flag” | `openat/read/write` 往往仍放行 | 读完整 BPF，走 ORW |

共同点：保护位封的是**某条路径**，不是“程序不可利用”。判断依据永远是“输入面 +
可写目标 + 触发点”三件，而不是一行 checksec。

## 2. 保护位到路线的决策树

```text
checksec
├─ NX off ──────────────► shellcode（先确认栈地址）
├─ NX on
│  ├─ 有格式化串 ───────► fmt 泄漏/任意写（Partial RELRO 优先 GOT）
│  ├─ 有堆语义 ─────────► tcache/UAF（先泄漏 heap→libc）
│  ├─ 有溢出 ───────────► ROP/ret2libc
│  │  ├─ canary ────────► 先泄漏 canary 或改走 fmt/heap
│  │  ├─ PIE ───────────► 先泄漏 code/libc
│  │  └─ Full RELRO ────► hook/IO/exit/程序指针
│  └─ seccomp ──────────► ORW/openat/mprotect
└─ 无上述信号 ──────────► 先找输入面/整数/逻辑漏洞
```

## 2.1 决策树的执行方式（用命令确认分支，而不是猜）

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
# 分支 1：有没有栈输入面？
objdump -d ./chall | grep -E 'call.*<(gets|read|fgets|scanf|strcpy|sprintf)>' | head
# 分支 2：有没有能回显的泄漏点？
readelf -rW ./chall | grep -E 'puts|printf|write|read' | head
# 分支 3：有没有堆语义？
strings -a ./chall | grep -Ei 'alloc|free|edit|show|chunk' | head
```

通过长什么样（三个分支各至少一条，才能排路线）：

```text
  4011a6: e8 95 fe ff ff   call   401040 <gets@plt>
000000404018  000200000007 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
alloc / free / edit / show
```

三个分支都空 → 不要硬套栈/堆，先找整数/逻辑/格式化串输入面（见 `01-criteria.md` #4/#7）。
有分支但没泄漏点 → 路线里必须包含“先造泄漏”（格式化串 `%s`、堆 fd、`environ`）。

## 3. 每条路线的“最小证据”

| 路线 | 最小证据 | 不算通过 |
|---|---|---|
| 栈 ROP | 偏移、`$rip` 受控、泄漏基址、10 次≥9 | 本地偶发、远程未复现 |
| 格式化串 | 参数序号、写后读回、两次稳定 | 只打印了 `%p` 没写成功 |
| 堆 | malloc 返回目标、重叠可见、触发不崩 | 只泄漏了堆地址 |
| IO_FILE | 伪造结构地址、vtable 合法、flush 链命中 | 只改了 `_IO_list_all` 没触发 |
| seccomp ORW | syscall 序列 + flag 内容 | shell 被 seccomp 杀 |
| 密码学 | `pow(m,e,n)==c`、块/位逐项比对 | 明文“看起来像” |
| PE 利用 | 模块基址、页权限、链命中 | 把 PE 当 ELF 套 GOT |

### 3.1 证据强度分级（同一路线也分三档）

| 档 | 证据 | 能写什么 | 不能写什么 |
|---|---|---|---|
| A | 远程命中 + 10 次 ≥9 + flag/root 输出 | “已打通” | 不写“稳定利用”（样本仅 10） |
| B | 本地 10 次 ≥9 + marker + 泄漏页对齐 | “本地可复现” | 不写“远程可打” |
| C | 单次成功 / gdb 下成功 / 关 ASLR 成功 | “现象” | 不写“已打通” |

把档位写进报告，比“基本可用/应该能打”这种措辞省掉一轮返工。

## 4. 常见误判清单

1. `checksec` 的 `Canary found` 只说明编译选项，不代表每条路径都有 canary（汇编/leaf 函数可能没有）。
2. `Full RELRO` 只保护 GOT；`.fini_array`、`__exit_funcs`、函数指针仍可能可写。
3. `PIE enabled` 不等于“完全随机”：低位页内偏移固定，部分覆盖仍可用。
4. `NX enabled` 不等于不能执行代码：`mprotect`/`VirtualProtect` 可改页权限。
5. `seccomp` 允许 `open` 不代表允许 `openat`；反之亦然，按 BPF 原文。
6. `FORTIFY` 只覆盖部分 libc 调用，且需要编译器能算出对象大小。
7. PE 的 `DllCharacteristics` 只是声明，实际 ASLR 还受加载器/系统策略影响。
8. libc 版本不匹配会让所有偏移同时错；先对 build id，再谈利用。

## 4.1 误判清单（补充 8 条）

9. `CET/IBT/SHSTK` 只在 CPU+内核+加载器都启用时才生效；只看编译标志就判死是错的。
10. `-fstack-clash-protection` 影响大栈分配，不影响普通缓冲区溢出。
11. `RELR` 是压缩重定位，出现在 Full RELRO 里是正常的，不代表“GOT 没保护”。
12. 静态链接程序没有 libc 基址可泄漏：改用 `syscall` gadget 或程序内 `mprotect`。
13. `seccomp` 的 `TSYNC` 决定是否对所有线程生效；多线程目标要读完整 BPF。
14. 32-bit 目标没有 16 字节 `movaps` 对齐约束，别套 64 位经验。
15. Windows `CFG` 只校验间接调用的目标是否登记，数据写/逻辑漏洞仍可能可用。
16. `ASLR` 的熵受内核 `mmap_rnd_bits` 影响；同机不同容器可能不同，不要跨环境套偏移。

## 4.2 报告措辞：把“保护位”说成“路径”

| 想说的 | 不要写 | 改成 |
|---|---|---|
| NX 开 | “不能执行 shellcode” | “栈/堆执行路径被封；ret2libc/ROP 仍候选” |
| Full RELRO | “不能改 GOT” | “GOT 不可写；`.fini_array`/函数指针/IO 仍候选” |
| Canary | “不能栈溢出” | “需先泄漏 canary，或改走 fmt/堆” |
| PIE | “地址随机不能打” | “需先泄漏代码基址；页内偏移固定” |
| seccomp | “不能拿 shell” | “`execve` 被封；ORW/openat 仍候选” |

措辞不是修辞：写成“路径被封”会自然带出“还有哪条路”，写成“不能打”会直接停手。

## 4.3 一页速查（保护位 → 一句话）

| 看到 | 一句话 | 下一动作 |
|---|---|---|
| `NX Enabled` | 栈/堆不执行 | 转 ROP/ret2libc/ORW |
| `PIE Enabled` | 代码基址随机 | 先泄漏（GOT/部分覆盖） |
| `Canary Found` | 连续栈溢出受限 | 泄漏 canary 或转 fmt/堆 |
| `RELRO Partial` | GOT 可写 | 优先 fmt 任意写 |
| `RELRO Full` | GOT 只读 | `.fini_array`/IO/exit/函数指针 |
| `seccomp` 有 | 只能白名单 syscall | ORW / mprotect+shellcode |
| PE `DYNAMIC_BASE` | 模块基址随机 | 先泄漏；否则直接用固定 RVA |
| PE `SecurityCookie` | 有 /GS | 泄漏 cookie 或走堆/逻辑 |

## 失败判据（本文件）

- 只抄骨架里的偏移/gadget，不用目标环境复核 → 本文件被误用，结论降级为“疑似”。
- 没有泄漏/回代/写后读回等最小证据就宣布成功 → 不成立。
- 平台语义混用（PE 的 DllCharacteristics 当 ELF RELRO、UCRT 当 glibc）→ 判路线错误。

## 边界

- 文中的命令与偏移是示例，必须用目标二进制、目标 libc/运行库重新生成。
- 仅用于授权实验室资产；不覆盖真实生产系统、持久化、横向移动或拒绝服务。

## 这一篇算"用对了"吗

- [ ] 保护位四项都有两份来源（`pwn-check` + `readelf`/`objdump -p`），不是只贴 checksec。
- [ ] 用 §1.2 的组合矩阵选路，先看"输入面/可写目标/触发点"，不是从第一行逐条试。
- [ ] 泄漏按 §1.3 选了最便宜的来源，且泄漏值页对齐 + 低 12 位匹配。
- [ ] 报告措辞按 §4.2 写成"哪条路径被封"，没有写"不能打"。
- [ ] 证据标了 A/B/C 档，C 档没有冒充"已打通"。
