---
name: pwn-crypto
description: "【二进制利用与密码学】授权 CTF/靶场中的二进制漏洞利用与密码学攻击手册：checksec 保护位决策、栈溢出与 ROP、格式化字符串、堆（tcache/UAF）、整数与 off-by-one、seccomp 沙箱逃逸（ORW/SROP），以及 RSA、ECB、CBC、PRNG、证书与签名攻击。含每类判据、工具降级、稳定性验收与边界。"
license: MIT
compatibility: "Linux x86/x64/ARM64 优先；Python 3.10+、pwntools、ROPgadget、checksec。Windows 下经 WSL2 或远端 Linux 靶机执行。"
metadata:
  version: "1.0.0"
  references_dir: "Tool/skill/pwn-crypto/references/"
  acceptance: "本地 exploit 稳定命中 ≥9/10"
---

# pwn-crypto — 二进制利用与密码学攻击

> 本技能只做**可验证的利用/求解**：从保护位推出打法，从泄漏推出地址，从一次成功推到稳定复现。
> 纯静态算法还原交给 `ida-reverse` / `reverse-engineering`；Android 目标交给 `apkseep`。

## 1. 适用

- CTF pwn / crypto、授权靶场、自有 ELF 服务的白盒验证。
- 输入：ELF / `.so` / `libc.so.6`、远程 `host:port`、密码学脚本或加解密 oracle。
- 输出：`exploit.py` / `solve.py`、稳定复现命令、flag 或 root 证据、失败项与已排除原因。
- 不适用：纯逆向报告、批量扫描、未授权目标、真实生产凭据或证书。

## 2. 前置（三关不过，不开打）

### 2.1 checksec 输出（先留基线）

```text
$ checksec --file=./chall
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
RPATH:    No RPATH
RUNPATH:  No RUNPATH
Symbols:  42 Symbols
FORTIFY:  Enabled
```

同时记录：`file ./chall`、`readelf -hW`、`readelf -lW | grep GNU_STACK`、
`readelf -d | grep -E 'BIND_NOW|RPATH|RUNPATH|NEEDED'`、`ldd ./chall`、`sha256sum`。
`pwn checksec ./chall` 与上述字段等价；缺 checksec 时用 readelf 手判。

### 2.2 保护位决定打法

| 观测 | 含义 | 首选打法 |
|---|---|---|
| `Canary found` | 栈尾有 TLS canary | 先泄漏 canary；或改走格式化串/堆；fork 服务 canary 常稳定 |
| `No canary` | 可直接覆盖返回地址 | 栈溢出 + ROP / ret2libc |
| `NX enabled` | 栈不可执行 | ROP、ret2libc、ret2csu、SROP；不在栈上放 shellcode |
| `NX disabled` | 栈可执行 | shellcode，注意坏字符与跳转 |
| `PIE enabled` | 代码段随机 | 先泄漏代码/libc 基址；或 1–2 字节部分覆盖 |
| `PIE disabled` | 地址固定 | 直接写 GOT/返回地址，仍要过 ASLR 的 libc |
| `Partial RELRO` | GOT 可写 | GOT 覆写、格式化串任意写 |
| `Full RELRO` | GOT 只读 | 改 hook/exit handler/函数指针/栈；glibc ≥2.34 无 `__free_hook` |
| `FORTIFY` | 有 `__*_chk` | 注意长度检查，优先打逻辑/堆而非栈 |
| `No Symbols` | 去符号 | 用字符串、xref、泄漏与调试器定位；不猜函数名 |

### 2.3 沙箱与 ASLR 前提

- 先跑 `seccomp-tools dump ./chall`，记录 arch、允许的 syscall、参数过滤；没有 seccomp 也要确认。
- 本地基线：`cat /proc/sys/kernel/randomize_va_space`；需要固定基址时用
  `setarch "$(uname -m)" -R ./chall`，并在报告中注明“关闭 ASLR”。
- 远程通常开着 ASLR：**只信远程泄漏**，不把本地偏移直接当远程地址。
- fork server：父进程先初始化，子进程继承 canary/libc；一次泄漏可复用，但每次连接仍要重算输入。
- 用目标同版本 libc 跑本地：`patchelf --set-interpreter` + `--set-rpath`，或 `pwninit`；记录 libc build id。

## 3. 六种打法

### 3.1 栈溢出 + ROP

1. `pwn cyclic 300` 找偏移，`pwn cyclic -l 0x6161616c` 得覆盖长度；用 `gdb` 看 `$rsp` 处内容复核。
2. 有 canary：格式化串 `%p`、越界读、或 `read` 残留泄漏；覆盖时保留原字节（最低字节通常为 `\x00`）。
3. 有 PIE：先 `puts(puts@got)` 回 `main`，再算基址；同页内可只覆盖低 12 位。
4. NX：`pop rdi; ret` + `puts@plt` + `puts@got` + `main` → 解析 libc → `system("/bin/sh")`。
5. gadget 不够：ret2csu 设 `rdx/rsi/rdi`，或 ret2dlresolve；`one_gadget` 要核对约束寄存器。
6. 调用前保证 16 字节栈对齐；不齐时在链首加一个 `ret`。

**判据**：偏移可重复；崩溃时 `$rip` 为受控值；泄漏值低 12 位与目标 libc 符号吻合；链一次跑通。

### 3.2 格式化字符串

- 找参数序号：`AAAA.%p.%p.%p...`，或 `%6$p` 扫描；64 位前 6 个参数多在寄存器。
- 泄漏：`%s` 接 GOT/栈地址；`%p` 接栈上指针；先确认输出不被截断。
- 任意写：`fmtstr_payload(offset, {addr: value}, write_size="short")`；大值用 `%hn`，逐字节用 `%hhn`。
- 64 位地址常含 `\x00`，放在 payload 末尾并调整对齐；必要时分两次写，避免一次超长输出。
- 目标优先级：GOT（Partial RELRO）→ 返回地址 → 全局函数指针/flag 判定变量。

**判据**：写后能读回目标地址的新值；连续两次写不崩；`%n` 计数与预期长度一致。

### 3.3 堆（tcache / UAF）

1. 先定 glibc：`ldd --version`、`strings libc.so.6 | grep 'GNU C Library'`；tcache 2.26+，safe-linking 2.32+，hook 在 2.34 移除。
2. 泄漏顺序：堆地址（tcache fd / 相邻指针）→ libc（unsorted bin 的 `fd/bk`，偏移用调试器确认）→ 栈（`environ`）。
3. UAF：释放后仍可 `show/edit`；tcache dup 可让同一 chunk 入链两次。
4. tcache poison：改 `fd` 为 `target ^ (chunk_addr >> 12)`（2.32+），目标按 0x10 对齐；2.29+ 注意 `key` 字段。
5. 触发：`__free_hook`（<2.34）、`_IO_list_all`/`exit_funcs`（≥2.34）、`environ` 回栈、或程序自己的函数指针。
6. 大 chunk / unsorted bin / large bin attack 只在 tcache 路线被堵时启用；每步用 `vis_heap_chunks` 复核。

**判据**：`malloc` 返回受控地址；目标位置写入后触发不崩；两次独立进程同样成功。

### 3.4 整数与 off-by-one

- 查有符号/无符号转换、长度截断、负数索引、`atoi/strtol` 返回值、乘法/加法溢出。
- off-by-one 常见为写 `\x00`：制造 poison null byte，缩小 chunk size 造成重叠（House of Einherjar / overlap）。
- 先证明“越界一个字节确实改到了下一个 chunk 的 size/fd”，再设计重叠分配。
- 注意 `size` 对齐到 0x10、`prev_inuse`、`prev_size` 的一致性；错误构造会在 `free` 时 abort。

**判据**：调试器能看到两个 chunk 重叠或相邻元数据被改；随后能稳定拿到重叠读写。

### 3.5 沙箱逃逸（seccomp / ORW）

- `seccomp-tools dump ./chall` 读出白名单：`open/read/write`、`openat`、`sendfile`、`mprotect` 哪些可用。
- 经典 ORW：`open("/flag", O_RDONLY)` → `read(fd, bss, 0x100)` → `write(1, bss, 0x100)`；fd 通常为 3。
- 只有 `openat` 时用 `openat(AT_FDCWD, path, 0)`；路径要可写内存，先 `read` 进去。
- 缺 `pop rdx` 时用 ret2csu、`__libc_csu_init`、SROP（`rt_sigreturn`）或 libc 内 `setcontext`。
- 允许 `mprotect` 时把 shellcode 写到 bss，`mprotect(..., 7)` 后跳转；注意 seccomp 对 arch 的限制。
- 若 flag 已被父进程打开，先试 `read(3, ...)`，不要盲目 open。

**判据**：`strace`/seccomp 日志出现预期的 openat/read/write 序列，且输出包含 flag 内容。

### 3.6 密码学（RSA / 分组 / PRNG / 签名）

**RSA**
- 小指数无填充：`m = iroot(c, e)`；`e=3` 且 `m^3 < n` 时直接开方。
- 共模：同一 `n`、同一 `m`、`gcd(e1,e2)=1`，用扩展欧几里得求 `a,b`，`m = c1^a * c2^b mod n`。
- 低加密指数广播（Håstad）：同一 `m`、`e=3`、至少 3 组互质 `n`，CRT 后开三次方。
- 共享素数：`gcd(n1,n2)` 直接分解；Wiener 打小私钥 `d`；Fermat 打相近 `p,q`。
- 判据：恢复的 `m` 可打印，且 `pow(m,e,n)==c`；否则回到“是否填充/是否同一 m”的假设。

**ECB**
- 找 16 字节重复块；相同明文块产生相同密文块。
- 字节逐位 oracle：控制前缀对齐，逐字节爆破；cut-and-paste 重排块伪造字段。
- 判据：密文块相等关系可复现；oracle 返回的块与字典命中；拼接后目标字段被接受。

**CBC**
- 位翻转：改 `C[i-1]` 使 `P[i]` 按预期翻转；第一块改 IV；`P[i] = D(C[i]) xor C[i-1]`。
- padding oracle：只在 padding 合法时给侧信道，逐字节恢复；注意 MAC-then-encrypt 与错误粒度。
- 判据：解密结果的目标字节等于期望值，且 padding/格式校验通过。

**PRNG**
- MT19937：收集 624 个连续 32-bit 输出即可克隆状态（`randcrack`）；Python `getrandbits(32)` 最直接。
- C `rand()`/LCG：由连续输出解 `a,c,m`，或按时间种子暴力；Java `Random` 需 48-bit 状态，连续输出可推。
- 判据：预测的下一个/下一段输出与真实值逐位一致，而非“看起来像”。

**证书与签名**
- 先 `openssl x509 -text -noout` 看公钥指数、签名算法、有效期、扩展；`openssl verify` 复现信任链。
- 弱情形：`e=1`、`e=3` 且无填充/消息可开方、DER 解析差异、弱哈希、自签信任配置。
- 判据：目标验证器接受伪造签名/证书（实验室自建 CA），且 `openssl verify` 或程序返回成功。

## 4. 每类判据（成立 / 不成立）

| 类型 | 成立判据 | 常见误判 |
|---|---|---|
| 栈溢出 + ROP | 偏移稳定、`$rip` 受控、泄漏基址与 libc 吻合、链一次成功 | 本地能打、远程偏移不同；栈未对齐偶发崩溃 |
| 格式化字符串 | 目标地址写后读回等于预期；两次写稳定 | `%n` 输出被截断；64 位地址含 `\x00` 未处理 |
| 堆 tcache/UAF | `malloc` 返回目标地址；重叠 chunk 可见；触发不崩 | 把堆地址当 libc；safe-linking 未解码；glibc 版本不符 |
| 整数 / off-by-one | 相邻 chunk 元数据被改；重叠读写成立 | 只改到 padding；`free` 一致性检查被忽略 |
| seccomp / ORW | syscall 序列正确且读到 flag | 白名单没读全；fd 猜错；路径不可写 |
| RSA | `pow(m,e,n)==c` 且明文可读 | 忽略 PKCS#1 填充；把不同消息当同一 `m` |
| ECB / CBC | 块关系可复现；目标字段/明文被控制 | 把随机碰撞当 ECB；CBC 改错块索引 |
| PRNG | 下一输出逐位一致 | 只验证“分布像”；消耗了额外的随机数 |
| 证书 / 签名 | 目标验证器接受，证据可复现 | 只改了文件没改信任链；把解析差异当签名伪造 |

## 5. 工具与降级

| 工具 | 用途 | 缺失时 |
|---|---|---|
| `checksec` / `readelf` | 保护位、段、动态项 | `pwn checksec`；再退 `readelf -hW/-lW/-d` |
| `ROPgadget` / `ropper` | gadget 搜索 | `ROP(elf)`、`objdump -d` + grep；手写 ret2csu |
| `pwntools` | 交互、泄漏、ROP、fmtstr | 纯 `socket` + `struct`；仍建议先装 |
| `one_gadget` | libc 一键 shell | 手查 `execve` 附近约束，或走 `system` |
| `angr` | 复杂约束/路径求解 | 手工逆向 + z3 建模 |
| `z3` | 整数/位向量约束 | 枚举/数学推导；SMT 不适合大循环 |
| `openssl` | 证书、密钥、签名验证 | Python `cryptography`；`gpg` 仅辅助 |
| `sage` | 格攻击、Coppersmith、椭圆 | 小规模用 sympy/z3；格攻击装 sage |
| `seccomp-tools` | 沙箱白名单 | `strace -f` 观察；读 BPF 反汇编 |

- 缺工具先查能力表：`seep_tool_research`，或
  `python Tool/mcp/tool_autodiscover.py discover <tool>` / `plan <tool>`。
- GUI/调试器通道用 `powershell -File Tool/scripts/tool-run.ps1 -Tool <id> -ListModes`，
  需要时加 `-Target <样本>` 自启；不要手猜安装路径。
- 安装仍需用户确认；禁止为“再试一次”反复装工具。

## 6. 坑（按出现频率排）

1. **libc 版本错配**：`system`/`/bin/sh`/one_gadget 偏移全错。用泄漏地址低 12 位查 libc-database，核对 build id；本地用 `patchelf`/`pwninit` 固定解释器与 rpath。
2. **远程 vs 本地偏移**：argv、环境变量、`LD_PRELOAD`、cwd、tty、缓冲、fork、seccomp 都会改栈与行为。远程必须重新泄漏；本地用 `socat` 模拟同一启动方式。
3. **canary 泄漏点**：`%p` 序号错、只泄漏到 7 字节、覆盖了 TLS 而不是栈值；fork server 的 canary 稳定，exec 后会变。
4. **padding 对齐**：x86_64 调用前 `rsp % 16 == 0`；`system` 偶发崩先加 `ret`。格式化串的地址对齐、堆 chunk 的 0x10 对齐同理。
5. **部分覆盖跨页**：PIE 低 12 位覆盖若跨页会失败；先确认目标与源在同一页。
6. **one_gadget 约束**：寄存器/栈条件不满足就静默失败；用 `one_gadget -l 2` 看约束。
7. **`%n` 与空字节**：64 位地址写不进格式化串中间；用尾部地址 + `%hhn`。
8. **堆一致性**：`prev_size/prev_inuse/key` 不一致会在 `free` 时 abort；每次改完先 `vis_heap_chunks`。
9. **PRNG 消耗**：`randint`/`randrange` 有拒绝采样，按 `getrandbits` 记账；不要把“输出个数”当“状态字数”。
10. **密码学假设**：先确认有没有填充、是不是同一消息、模数是否互质；不要在没验证 `pow(m,e,n)==c` 时宣布成功。

## 7. 验收

- **本地稳定性**：同一 `exploit.py` 在全新进程/新连接上连续跑 ≥10 次，成功 ≥9 次；记录命令、退出码、成功计数。
  推荐 `for i in $(seq 10); do timeout 30 python3 exploit.py; done`，逐次比对输出。
- **远程命中**：远程拿到 shell 或 flag；给出 `id`、`cat flag`、目标路径、会话时间与完整 transcript。
- **密码学验收**：求解脚本可重跑；RSA 用 `pow(m,e,n)==c` 复核，分组/PRNG 用逐块/逐位比对；给出明文与来源。
- **证据留存**：`sha256sum chall libc.so.6`、checksec 输出、libc 版本、内核/ASLR 状态、exploit 与依赖版本。
- **失败也交付**：写清已排除的路线（如“Full RELRO + 无泄漏，GOT 路线不可行”），不要用一次偶然成功冒充稳定。
- **停止条件**：同一路径 3 轮无进展即换路线；动态尝试同一目标同类操作最多 2 次，第二次失败必须停下汇报。

## 8. 边界

- 纯静态分析、算法还原、协议测绘：交给 `reverse-engineering` / `ida-reverse`；本技能只接手“要打穿/要取证”的阶段。
- Android APK/DEX/SO、Frida/脱壳/重打包：交给 `apkseep`，不在此重复。
- Web/客户端授权逻辑、JWT/接口重放：交给对应 Web/许可技能；本技能只处理二进制与密码学原语。
- 仅限授权实验室资产；禁止未授权目标、持久化、横向移动、拒绝服务、真实凭据/生产证书滥用。
- 不伪造“稳定 9/10”；不隐藏失败；不把本地关闭 ASLR 的结果当远程结论。
