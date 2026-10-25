# 02-failure-criteria.md — pwn-crypto 失败判据表

> **范围**：已经拿到目标/样本，正在决定“继续原路线还是换支路”的时刻。
> 入口：先做基线（sha256/保护位）再判失败；授权边界见 `../SKILL.md` 前置检查。
> 规则：同一路径连续 3 轮无进展，或同类动态尝试 2 次失败，必须停手换路线并写清代价。

## 1. 失败判据总表

| # | 现象 | 判定 | 改走哪条 | 代价 |
|---|---|---|---|---|
| 1 | `pwn-repro --objdump ... --probe-log ...` 返回 `consistent=false` / `offset-mismatch` | 偏移来源互相矛盾，当前 payload 长度不可信 | 先统一编译选项（`-O0`、帧指针、栈对齐），再重新 objdump+probe；必要时用 gdb `x/8gx $rsp` 复核 | 低：几分钟；比重跑 exploit 便宜 |
| 2 | `objdump` 里找不到 `lea -0x..(%rbp)` | 函数被优化成 rsp 帧或无帧指针 | 改用 `sub $0x..,%rsp` + gdb 断点定 buffer；或直接动态 cyclic 找偏移 | 中：需要多一次调试会话 |
| 3 | 偏移稳定但覆盖后 `$rip` 不是 cyclic 片段 | 覆盖点不是 saved RIP（可能是 canary、SEH、函数指针） | 查 canary/异常链/虚表；格式化串或堆分支；不要继续加长 payload | 中：要重新识别控制对象 |
| 4 | 保护位全绿（Full RELRO + PIE + Canary + NX）且找不到泄漏 | 栈/GOT 路线被同时封死 | 转格式化串（先确认 `%n` 可用）、堆（tcache/UAF/IO_FILE）、逻辑/密码学分支 | 高：整条链要重做 |
| 5 | `%n` 写了但目标值没变（如 `printf("abc%n",&x)` 后 x 仍为 0） | 运行库不实现/禁用 `%n`（如 MinGW/UCRT） | 只保留 `%s/%p` 任意读；写路线转堆/逻辑，或换 glibc 目标重新验证 | 低：一次探针即可判死，避免整条 payload 白做 |
| 6 | 格式化串输出被截断 / `%n` 计数与预期不符 | 缓冲区/管道/`setvbuf` 截断，或宽度计数算错 | 缩短 payload、分两次写、用 `%hhn` 逐字节；确认 stdout 无缓冲 | 低：改 payload 结构 |
| 7 | 堆：`malloc` 不返回 target，或 `free` 报 corruption | glibc 版本/ safe-linking / tcache key / 对齐 不符 | 先 `ldd --version`+`strings libc.so.6` 定版本；2.32+ 编码 `target^(chunk>>12)`；2.34+ 放弃 `__free_hook` 转 IO/exit/程序指针 | 高：要重写堆布局 |
| 8 | 整数回绕“理论成立”但进程正常退出、无越界证据 | 写入长度未真正超过分配长度，或分配器给了更大 usable size | 打印 `count/bytes/_msize/写入长度`；把写入长度固定为大于分配值；看是否出现堆破坏状态码（如 0xC0000374） | 中：需要改探针程序 |
| 9 | seccomp 白名单里没有 `open/read/write`，也拼不出 ORW | 沙箱把外带路径封死 | 转 SROP/栈迁移、`sendfile`/`openat` 组合；若仍不行，如实写“已控 RIP 但无法读出 flag” | 中：gadget 搜索与链重排 |
| 10 | 泄漏地址低 12 位匹配不到任何 libc，或 build id 对不上 | libc 版本错误，所有符号偏移同时错 | 用远程泄漏 + libc-database 精确匹配；或改用 ret2csu/单 gadget/程序自带函数 | 中：要重新收集泄漏 |
| 11 | RSA `iroot(c,e)` 不精确 / `pow(m,e,n)!=c` | 有填充、消息不同、或 `m^e>=n` | 回到三问：填充？同一 m？模数互质？改走共模/广播/Wiener/Fermat，或承认不可解 | 低：数学回代立即判死 |
| 12 | 广播 CRT 成功但开方不精确 | 组数不足、消息不同、或 `m^e>=M` | 增加互质模数组数；确认是同一 m；确认 `m^e<M` 后再开方 | 低：补数据即可 |
| 13 | PRNG 预测“分布像”但下一输出不一致 | 输出不连续，或中间有拒绝采样/额外消耗 | 记录每次 `getrandbits/randrange` 调用；只用连续 624 个 32-bit 输出克隆 MT | 中：要重放随机数调用序列 |
| 14 | ECB 判定只靠“密文看起来随机” | 没有重复块或 oracle 证据，随机碰撞也会误判 | 构造相同明文块（如 `'A'*32`）看密文块是否相等；或做逐字节 oracle | 低：补一组对照明文 |
| 15 | CBC 翻转后目标字节没变 / 解密 padding 报错 | 改错块索引（应改 C[i-1] 或 IV）、或 MAC 先校验 | 用 `crypto-verify --cbc` 验证 `before^after==xor`；确认没有 MAC-then-encrypt 拦截 | 低：索引/掩码修正 |
| 16 | Windows 上照搬 glibc 的 `%n`/GOT/`__free_hook` 手法 | 平台语义不同（无 ELF RELRO、UCRT 禁 `%n`、无 glibc hook） | 改用 PE 语义：导入表/CFG/SecurityCookie/`VirtualProtect`；或换 Linux 靶机验证 | 高：整条利用链要重写 |
| 17 | 本地 10 次成功 6–8 次，报告写“基本稳定” | 栈未对齐/ASLR/竞态导致的偶发成功 | 先加 `ret` 对齐、固定 argv/env/cwd；重跑 ≥10 次；低于 9/10 判“未成立” | 低：补对齐与统计 |
| 18 | 远程与本地行为不一致且无法解释 | libc/启动参数/缓冲/fork/cwd 差异 | 在远程做一次泄漏校验；用同版本 libc 本地复现；仍不一致就记录为边界，不硬编地址 | 高：需要远程调试窗口 |
| 19 | EVM/智能合约 | 本域无运行时 | 改走 web-pentest（API 面）/外部流程 | 低 |
| 20 | `nm -D libc.so.6 \| grep -E '__free_hook\|__malloc_hook'` 返回空，或 gdb `p &__free_hook` 报 no symbol | glibc ≥2.34 已删除 hook，不是符号偏移算错 | 改走 `_IO_wfile_jumps`/`_IO_str_jumps` FSOP、`exit_funcs`、`tls_dtor_list`、`setcontext` 链（`heap-and-sandbox.md` §6）；仍按 `io_file_vtable`/`exit_funcs_target`/`tls_dtor_hit`/`fsop_works` 建判据 | 低：一次 nm 即可判死，避免整条堆链白做 |
| 21 | 泄漏低 12 位能对上，但 gadget/符号落到错误位置（`__libc_system` 打不开 shell、`setcontext` 入口偏移不生效） | libc 偏移漂移：换了发行版/build、或抄了别人环境的偏移 | 用 `strings libc.so.6 \| grep -m1 'GNU C Library'` + build-id 重算；`pwn-check.py --file libc.so.6 --json` 交叉；重新 dump `setcontext`/`_IO_wfile_jumps` 偏移 | 高：整条链需重算，不得只改一个数字 |

## 2. 降级顺序（先便宜后昂贵）

```text
偏移不一致
  → 统一编译选项/帧指针（分钟级）
  → gdb 断点复核（十分钟级）
  → 改动态 cyclic 定位（半小时级）

保护位封死
  → 找泄漏（fmt %s/%p、堆 fd、environ）
  → 换控制对象（返回地址 → 函数指针 → IO/exit）
  → 换漏洞类（栈 → 堆 → 整数/逻辑）
  → 换域（纯密码学/逆向）

密码学回代失败
  → 检查填充/同一消息/模数关系
  → 换攻击面（共模/广播/分解/格）
  → 如实写“假设被推翻”，不宣布解出
```

## 2.1 降级链条上每一级的执行命令

| 级 | 动作 | 命令 | 通过长什么样 |
|---|---|---|---|
| 1 | 统一编译选项 | `gcc -O0 -fno-stack-protector -no-pie -o chall chall.c` | `readelf -hW` 的 `Type: EXEC`，`GNU_STACK` 无 E |
| 2 | 两源对齐偏移 | `pwn-repro.py --objdump d.txt --func vuln --probe-log p.txt` | `"consistent": true, "offset": 88` |
| 3 | 动态 cyclic | `pwn-repro.py --cyclic 300 --find 0x6161616c` | `{"offset": 76, "found": true}` 之类 |
| 4 | gdb 复核 | `gdb -q ./chall -ex 'b *vuln+40' -ex 'x/8gx $rsp'` | `$rsp` 附近能看到 payload 的 cyclic |
| 5 | 换控制对象 | `readelf -rW ./chall \| head`、`nm -D libc.so.6 \| grep hook` | 有可写函数指针；hook 存在/不存在都要记录 |

```bash
# 一条命令看“偏移这一级到底过没过”
python Tool/skill/pwn-crypto/scripts/pwn-repro.py --objdump evidence/chall.dis --func vuln \
  --probe-log evidence/probe.txt --cyclic 300 --find 0x6161616c --json 2>/dev/null | head -20
```

`consistent=false` 时不要再改 payload 长度；先把第 1 级重做。**顺序反了就是白跑。**

## 2.2 工具缺失时的降级链（不要反复安装）

| 缺什么 | 先查 | 降级做法 | 判据变化 |
|---|---|---|---|
| pwntools | `python -c "import pwn"` | `socket` + `struct` 手写收发；偏移照旧 | 无变化（只是慢） |
| checksec | `command -v checksec` | `pwn-check.py` + `readelf -lW/-dW` 交叉 | 无变化 |
| ROPgadget | `command -v ROPgadget` | `objdump -d \| grep -E 'pop.*; ret'`；`ropper` | gadget 可能漏，需人工核 |
| one_gadget | `command -v one_gadget` | 手工找 `execve("/bin/sh")` 序列或改用 `system` | 约束寄存器要自己验 |
| seccomp-tools | `command -v seccomp-tools` | `strace -f -e trace=%process,%file,%desc` | 只能看实际 syscall，不是白名单 |
| gdb | `command -v gdb` | core dump + `/proc/<pid>/maps` + `readelf -n` | 无法单步，判据降为疑似 |
| pycryptodome | `python -c "import Crypto"` | 纯 Python 实现（RSA/CRC/RC4 都在 `crypto-attacks.md`） | 无变化 |
| 同版本 libc | `ldd --version` | 远端泄漏低 12 位反查 libc-database | 只能给“疑似偏移” |

```bash
for t in python3 gdb objdump readelf checksec ROPgadget one_gadget seccomp-tools strace; do
  printf '%-14s ' "$t"; command -v "$t" >/dev/null 2>&1 && echo ok || echo missing
done
python - <<'PY'
for m in ("pwn", "Crypto", "gmpy2", "z3"):
    try:
        __import__(m); print(m, "ok")
    except Exception as exc:
        print(m, "missing", type(exc).__name__)
PY
```

通过长什么样（这张表就是你的“降级预算”）：

```text
python3        ok
gdb            ok
objdump        ok
checksec       missing
ROPgadget      ok
one_gadget     missing
seccomp-tools  missing
strace         ok
pwn ok
Crypto ok
gmpy2 missing
z3 missing
```

缺 `seccomp-tools` 就意味着“白名单只能从实际 syscall 反推”，报告里必须把这句写进边界，
不能把 `strace` 观察到的序列当成“完整白名单”。

## 2.3 远程失败的归因顺序（先环境，后偏移）

| 差异项 | 本地怎么看 | 远程怎么看 | 典型症状 |
|---|---|---|---|
| libc 版本 | `strings -a libc.so.6 \| grep 'GNU C Library'` | 远程泄漏低 12 位反查 | 本地通、远程 SIGSEGV |
| 启动参数 | `ps -o args= -p <pid>` | 题目给的 `socat`/`xinetd` 命令 | `argv[0]` 长度影响栈 |
| 环境变量 | `env` 数量与长度 | 通常最小 env | 栈地址/对齐变化 |
| tty/缓冲 | `isatty(1)` | socket 不是 tty | `printf` 全缓冲，看不到提示 |
| fork 模型 | `set follow-fork-mode` | 每次连接是否新进程 | 基址复用/堆残留 |
| seccomp | 本地 `seccomp-tools dump` | 远程只看到“被 kill” | shell 起不来 |
| rlimit | `ulimit -a` | 题目限制 | `mmap`/`open` 失败 |

```bash
sha256sum chall libc.so.6 2>/dev/null | tee evidence/SHA256SUMS
strings -a libc.so.6 | grep -m1 'GNU C Library'
readelf -n libc.so.6 | grep -A1 'Build ID'
```

通过长什么样：

```text
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.8) stable release version 2.35.
    Build ID: 5b1a2f0c...
```

把这两行写进报告，比“libc 大概是 2.35”有用得多——libc 错版本会让**所有**偏移同时错。

## 3. 失败也要交付的内容

- 已排除的路线 + 排除依据（命令、输出、状态码）；
- 当前停在哪个判据（例如“偏移一致，但 RIP 未受控”）；
- 再试一次的代价估计（时间/是否需要新工具/是否需要新样本）；
- 平台差异说明（Windows UCRT vs glibc、PE vs ELF）。

## 3.1 事故回流（lessons：现象 → 根因 → 正确动作 → 代价）

| 现象 | 根因 | 正确动作 | 代价 |
|---|---|---|---|
| 本地 10/10，远程必挂 | libc 不是同一 build | 远程泄漏低 12 位反查 build id，同版本重建 | 整条链重算 |
| 本地偶发 8/10 | 16 字节栈对齐 | 链首加一个 `ret`；或用 `p64(ret)` 对齐 | 半小时 |
| 偏移 40 昨天能用今天不能 | 抄的固定偏移 | 每次两源重算（objdump + probe） | 一次白打 |
| `%n` 写了但变量不变 | MinGW/UCRT 不执行 `%n` | 只做 `%s` 任意读；写转堆/逻辑 | 整条写链作废 |
| 2.34 上找不到 `__free_hook` | 符号已被移除 | 转 FSOP/`exit_funcs`/`tls_dtor` | 堆布局重写 |
| 2.32 上 tcache 不返回 target | safe-linking 未编码 | `target ^ (chunk>>12)` | 一次调试 |
| `iroot` 出可打印字节就宣布 | 有填充或 `m^e>=n` | 回代 `pow(m,e,n)==c` | 结论被推翻 |
| 广播 CRT 不精确 | 组数 < e 或消息不同 | 补互质模数到 ≥e 组 | 补数据 |
| 一次成功写成“稳定” | 没做统计 | 10 次统计，低于 9 就写失败率 | 报告不合格 |
| `cat flag` 无输出就判“没打通” | stdout 被 dup/关闭，或全缓冲 | 用 `sh -c 'cat /flag >&2'`；`recvall(timeout)` | 误判 |

## 3.2 被误判为“失败”的现象

| 现象 | 其实是什么 | 先做的检查 |
|---|---|---|
| `system("/bin/sh")` 返回但无交互 | stdin/stdout 不是 tty；或 shell 被 seccomp 杀 | 改 `system("cat /flag")`；看 `strace` 里 `execve` 是否被拒 |
| 远程 rc=0 但无输出 | 全缓冲/还没 flush | `recvall(timeout=3)`；关缓冲 `setbuf` |
| gdb 下成功、跑脚本失败 | 环境变量/堆布局/ASLR 差异 | `env -i` 复现；固定 `argv` 长度 |
| 泄漏值低 12 位对不上 | 泄漏的不是 libc，或版本错 | 用 `%s` 读 GOT 再算；比对 build id |
| 崩溃但 rc 看起来“正常” | 父进程吞了子进程状态 | 直接跑二进制看 signal；`echo $?` 只能看 8 bit |
| 堆题“触发不 abort”但没 shell | 只完成写，没触发调用 | 断点确认 `__free_hook`/vtable 真的被调用 |

这六条的共同点：**失败信号在“结果”，根因在“环境/触发点”**；先查环境，再改 exploit。

## 3.3 停止后的交接包

```text
evidence/SHA256SUMS      # chall + libc 哈希
protection.json          # pwn-check 输出 + readelf/objdump 原文
L1_offset.json           # 两源偏移（consistent/offset）
leak.txt                 # 泄漏值 -> 基址计算过程
exploit.py               # 当前最好版本（能跑到哪一步写注释）
runs/                    # 10 份运行日志
blocked.md               # 卡在哪段（L0–L4）+ 已排除路线 + 下一步
```

```bash
# 交接包自检：缺文件或运行次数不够就 rc=2
python - <<'PY'
import pathlib, sys
need = ["evidence/SHA256SUMS", "evidence/L1_offset.json", "exploit.py", "evidence/blocked.md"]
miss = [p for p in need if not pathlib.Path(p).is_file()]
runs = list(pathlib.Path("runs").glob("*")) if pathlib.Path("runs").is_dir() else []
print("miss", miss, "runs", len(runs))
print("handoff_ok", not miss and len(runs) >= 10)
sys.exit(2 if miss else 0)
PY
```

通过长什么样：`miss [] runs 10` + `handoff_ok True`。
少于 10 份日志就不能声称“稳定”，只能写“当前最好结果 + 失败率”。

## 3.4 时间盒与尝试预算

| 阶段 | 预算 | 到点未达成 | 动作 |
|---|---|---|---|
| 基线与保护位 | 20 min | 说不清平台/libc/四项保护 | 先补基线，不写 exploit |
| 偏移与对齐 | 40 min | 两源不一致或 `$rip` 不受控 | 回 L0/L1，换控制对象 |
| 泄漏与基址 | 40 min | 泄漏不页对齐/低 12 位不匹配 | 换泄漏点，或换 libc |
| 链/堆布局 | 90 min | 触发必 abort / 目标不可写 | 换触发鏈或降级为“部分” |
| 密码学求解 | 60 min | 回代不过 | 换攻击面，或写“假设被推翻” |
| 稳定性与远程 | 30 min | 成功率 <9/10 | 只报实测数字，不写“稳定” |

同一路径连续 3 轮无进展、同类动态尝试 2 次失败 → 停手，把 §3.3 的交接包补齐。

## 3.5 一条命令统计成功率（不要用眼睛数）

```bash
mkdir -p runs
for i in $(seq 10); do
  timeout 30 python3 exploit.py > runs/run.$i 2>&1; echo "$i rc=$?" >> runs/rc.txt
done
grep -lE 'uid=|FLAG\{|flag\{' runs/run.* | wc -l
cat runs/rc.txt
```

通过长什么样：

```text
9
1 rc=0
2 rc=0
...
9 rc=0
10 rc=1
```

读法：命中 9/10 + 唯一失败那次 rc=1 → 写“9/10，失败原因待查”；命中 6/10 → 写“不稳定，
可能栈对齐/竞态”，**不写打通**。远程把同一脚本的 `HOST/PORT` 换掉再跑至少 3 次做泄漏校验。

## 4. 失败判据（本文自身）

- 只写“失败了”不写“哪条判据失败、改走哪条、代价多少” → 本文没被正确使用；
- 把“一次偶然成功”写成“稳定 9/10” → 直接判报告不合格；
- 用本地关闭 ASLR 的结果冒充远程结论 → 判据不成立，退回重测。

## 5. 边界

- 失败判据用于“止损”，不是“放弃”：换路线后仍要按 `01-criteria.md` 重新建立可机检证据。
- 某些失败是环境限制（无 gdb、无同版本 libc、无 Linux 靶机），应写 `blocked_at`，不要伪造成功。
- 同一目标同类动态尝试最多 2 次；第二次失败必须停下汇报，避免把靶场打成 DoS。

## 这一篇算"用对了"吗

- [ ] 每次停手都写清"哪条判据失败 + 改走哪条 + 代价"，不是只写"打不通"。
- [ ] 降级按 §2 的顺序走：先编译选项/两源，再换控制对象，最后换域。
- [ ] 工具缺失时走了 §2.2 的降级链，并在报告里标了 `blocked_at`。
- [ ] 远程失败先按 §2.3 对 libc/启动参数/环境，没有直接改偏移硬撞。
- [ ] 没有把 §3.2 的六种现象当失败，失败率与样本量都如实写了。
