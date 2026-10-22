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

## 4. 常见误判清单

1. `checksec` 的 `Canary found` 只说明编译选项，不代表每条路径都有 canary（汇编/leaf 函数可能没有）。
2. `Full RELRO` 只保护 GOT；`.fini_array`、`__exit_funcs`、函数指针仍可能可写。
3. `PIE enabled` 不等于“完全随机”：低位页内偏移固定，部分覆盖仍可用。
4. `NX enabled` 不等于不能执行代码：`mprotect`/`VirtualProtect` 可改页权限。
5. `seccomp` 允许 `open` 不代表允许 `openat`；反之亦然，按 BPF 原文。
6. `FORTIFY` 只覆盖部分 libc 调用，且需要编译器能算出对象大小。
7. PE 的 `DllCharacteristics` 只是声明，实际 ASLR 还受加载器/系统策略影响。
8. libc 版本不匹配会让所有偏移同时错；先对 build id，再谈利用。

## 失败判据（本文件）

- 只抄骨架里的偏移/gadget，不用目标环境复核 → 本文件被误用，结论降级为“疑似”。
- 没有泄漏/回代/写后读回等最小证据就宣布成功 → 不成立。
- 平台语义混用（PE 的 DllCharacteristics 当 ELF RELRO、UCRT 当 glibc）→ 判路线错误。

## 边界

- 文中的命令与偏移是示例，必须用目标二进制、目标 libc/运行库重新生成。
- 仅用于授权实验室资产；不覆盖真实生产系统、持久化、横向移动或拒绝服务。
