# 03-model-pitfalls.md — 模型常见失误（pwn/crypto）

> **范围**：让模型独立做二进制利用/密码学求解前，先对照本文自检。
> 用法：授权范围问题按任务书判定；本文只谈技术动作与证据链。
> 每条固定三段：**错误动作 → 为什么错 → 正确动作**。

### 1. 把 checksec 当成“能不能打”的结论

- 错误动作：看到 `Full RELRO + PIE + Canary + NX` 就宣布“无解”。
- 为什么错：保护位只封住部分路径；格式化串、堆、逻辑/密码学、程序自身函数指针仍可能可用。
- 正确动作：按 `mitigation-matrix.md` 的决策树列候选路线，再用泄漏/堆布局/输入面逐条排除。

### 2. 用固定数字当偏移

- 错误动作：直接抄 `OFFSET=40` 或 `OFFSET=88` 写 payload。
- 为什么错：偏移由编译器、优化级别、帧指针、栈对齐、libc 决定；换环境就漂移。
- 正确动作：每次用 `pwn-repro.py --objdump ... --probe-log ...` 两源对齐，`consistent=true` 才用。

### 3. 只跑 objdump 或只跑 probe

- 错误动作：只看反汇编里的 `-0x50(%rbp)` 就认定 offset=88。
- 为什么错：`lea` 可能引用的是别的局部变量；编译器还可能把 buf 放到不同位移。
- 正确动作：运行时打印 `buf/frame`，用 `frame-buf+8` 交叉；两源不一致就查帧指针/变量。

### 4. 把“程序崩了”当成“控制流被劫持”

- 错误动作：发送长串后进程退出码非 0，就写“已控制 RIP”。
- 为什么错：崩溃可能来自 canary、堆破坏、非法指令，RIP 未必受控。
- 正确动作：用可识别的 marker（跳到 `win()` 打印固定字符串）或 gdb 看到 `$rip` 等于 payload 中的值。

### 5. 忽略 canary 的“每函数差异”

- 错误动作：`checksec` 显示 `Canary found` 就认为所有函数都有 canary。
- 为什么错：leaf 函数/汇编函数可能没有；某些路径的 canary 在别处。
- 正确动作：在目标函数反汇编里找 `fs:0x28`/`__stack_chk_fail`；没有就走直接覆盖。

### 6. 把 glibc 的 `%n` 手法搬到 Windows

- 错误动作：在 MinGW/UCRT 程序上用 `%n` 写 GOT/全局变量。
- 为什么错：UCRT 的 printf 不执行 `%n`（实测 `printf("abc%n",&x)` 后 x 仍为 0）。
- 正确动作：先用 3 行探针确认 `%n` 是否写；Windows 上优先 `%s/%p` 任意读、堆/逻辑或导入表路线。

### 7. 64 位格式化串把地址放在开头

- 错误动作：payload 以 `p64(addr)` 开头，后面接 `%6$n`。
- 为什么错：地址含 `\x00`，printf 在第一个 NUL 就停止，后面的格式符根本不执行。
- 正确动作：格式串在前、地址放末尾/对齐到某个参数槽；用 `%hhn`/`%hn` 控制写入量；先验证参数序号。

### 8. 把 `%p` 泄漏当成任意读

- 错误动作：打印出一堆 `0x7f...` 就宣布“泄漏了 libc”。
- 为什么错：`%p` 只打印参数值，不保证那是 libc 地址；也可能被截断/是栈值。
- 正确动作：用 `%s` 解引用已知地址（如 GOT/全局 secret），看到目标字节；或用已知符号低 12 位匹配。

### 9. 堆题不看 glibc 版本

- 错误动作：2.34+ 上继续找 `__free_hook`，或在 2.32+ 直接写明文 `fd`。
- 为什么错：hook 已移除；safe-linking 要求 `fd = target ^ (chunk>>12)`。
- 正确动作：先定 build id/版本，再选 tcache/IO/exit/程序指针；每步用 `vis_heap_chunks` 复核。

### 10. 把“分布像随机”当成 PRNG 可预测

- 错误动作：看输出“很像随机数”就写“MT19937 可克隆”。
- 为什么错：没有连续 624 个 32-bit 输出，状态恢复不成立；`randint` 还会消耗额外随机数。
- 正确动作：收集连续输出，克隆后预测下 N 个并逐位比对；不一致就查调用序列。

### 11. RSA 宣布明文前跳过回代

- 错误动作：`iroot` 得到一串字节，看到里面有可打印字符就写“解出 flag”。
- 为什么错：填充、不同消息、`m^e>=n` 都会让开方结果不是真明文。
- 正确动作：必须 `pow(m,e,n)==c`；广播还要每组 `pow(m,e,n_i)==c_i` 且 `m^e<M`。

### 12. ECB/CBC 混淆块索引

- 错误动作：CBC 想改第 2 块却翻转 `C[1]` 的第一个字节以外的位置，或直接改 `C[2]`。
- 为什么错：`P[i]=D(C[i]) xor C[i-1]`；改 `C[i]` 会破坏整块，改 `C[i-1]` 才按 xor 影响目标字节。
- 正确动作：用 `crypto-verify --cbc` 验证 `before^after==xor`；第一块改 IV；注意 MAC 可能先拦截。

### 13. 整数溢出只做算术、跳过运行时证据

- 错误动作：算出 `count*4` 回绕成 4 就写“堆溢出”。
- 为什么错：分配器可能给更大 usable size，或写入长度没超过分配值，程序可能正常退出。
- 正确动作：打印 `count/bytes/_msize/写入长度`，看到真实越界与堆破坏状态码（如 0xC0000374）才算。

### 14. 平台语义混用（PE ↔ ELF）

- 错误动作：在 PE 上找 RELRO/GOT/`__free_hook`，或用 `readelf` 分析 PE。
- 为什么错：PE 没有 ELF RELRO；保护位是 `DllCharacteristics` 近似；导入表/IAT/CFG 才是 PE 的语言。
- 正确动作：PE 用 `pwn-check` 的 PE 分支 + `objdump -p`/导入表；ELF 用 `readelf -lW/-dW`；报告里注明平台。

### 15. 把一次成功写成“9/10 稳定”

- 错误动作：脚本偶然打通一次，报告写“稳定复现”。
- 为什么错：栈对齐/ASLR/竞态会让成功率波动；一次成功没有统计意义。
- 正确动作：全新进程/连接跑 ≥10 次，成功 ≥9 次才写稳定；否则写“现象 + 已排除原因”。

### 16. 把公钥当 HMAC 密钥时忘了 base64url 解码差异

- 错误动作：JWT 算法混淆时，直接把 JWKS 里的 `n` 字符串（或带 `=` 的 base64 文本）当 HS256 的 key，签名对不上就断言“目标不可打”。
- 为什么错：JWKS 的 `n`/`e` 是 **base64url 无 padding**，必须先解码成字节；服务端实际用的可能是 PEM/DER/原始 modulus 中的一种，字符串长度和字节内容都不同。
- 正确动作：分别构造 PEM、DER、`base64.urlsafe_b64decode(n + '=' * (-len(n) % 4))` 三种 key，逐个重签并重放；只有服务端返回 `jwt_accepted=true` 的那一种才算命中。

### 17. 把 Partial RELRO 当 Full（或反过来）

- 错误动作：看到 `RELRO: Partial` 就放弃 GOT 覆写；或看到 `Full` 还去算 `.got.plt` 偏移。
- 为什么错：Full RELRO 才在启动时 `mprotect` 只读；Partial 时 `.got.plt` 仍可写。
- 正确动作：`pwn-check` 与 `readelf -dW | grep BIND_NOW` 交叉；再看 `readelf -lW` 的 `GNU_RELRO` 覆盖范围。
  即使 Full，`.fini_array`、函数指针、`__exit_funcs` 仍可能是目标。

### 18. 认为 ret2libc 必须先泄漏 `puts`

- 错误动作：题目没有 `puts@plt` 就判"无泄漏点"。
- 为什么错：`write`/`printf`/`send`/`read` 回显都能泄漏；甚至可以用 `ret2csu` 直接调 `write`。
- 正确动作：列 PLT 里所有"能把内存写回 stdout"的函数，按可控参数排序；用 `ROP(elf).call` 试。

### 19. 忽略 16 字节栈对齐

- 错误动作：`ret2libc` 链在 `system` 里崩，`$rip` 落在 `movaps` 上。
- 为什么错：glibc 的 `system`/部分 SSE 指令要求 `rsp % 16 == 8`（进入函数时），少一个 `ret` 就挂。
- 正确动作：链首插一个 `ret` gadget；gdb 里 `p $rsp % 16` 核对；对齐问题在本地表现为"偶发/必崩"。

### 20. 把 one_gadget 当稳定解

- 错误动作：`one_gadget libc.so.6` 拿到三个偏移，任选一个塞进去。
- 为什么错：每个 one_gadget 都有寄存器/内存约束（`[rsp+0x..]==NULL` 等），不满足时静默失败。
- 正确动作：逐条核对约束（gdb 断在 gadget 看寄存器），或回到 `system("/bin/sh")` 两段链。

### 21. 忽略 seccomp 的 arch / ABI 检查

- 错误动作：seccomp 拦了 `execve`，就想用 `int 0x80` 或 x32 ABI 绕。
- 为什么错：规范 BPF 常校验 `arch == AUDIT_ARCH_X86_64`，x32 系统调用号会直接被杀。
- 正确动作：完整读 BPF（`seccomp-tools dump`），确认 arch 检查与参数过滤，再决定 ORW 还是放弃外带。

### 22. 堆偏移抄 `main_arena` 的固定值

- 错误动作：`libc.address + 0x1ecbe0` 这类常量每个题都用。
- 为什么错：`main_arena` 相对偏移随 glibc 版本/发行版变化；抄错就"泄漏看着对、基址差一截"。
- 正确动作：`libc.symbols['main_arena']`（带调试符号）或 gdb `p &main_arena` 现场取；再用页对齐验证。

### 23. 把共模攻击当广播攻击

- 错误动作：拿到多组 `(n_i, e_i, c_i)` 直接 CRT 开方。
- 为什么错：共模是**同一个 n、不同 e、同一个 m**；广播是**多个互质 n、同一个 e、同一个 m**。
  混用会得到"能开方但不精确"的结果。
- 正确动作：先分类（n 是否相同、e 是否相同），再选 `common_modulus` 或 `crt + iroot`；两者都要回代。

### 24. 把 HMAC 当可长度扩展

- 错误动作：看到 `sha256(secret || msg)` 的 MAC 能长度扩展，就断言目标的 HMAC 也能。
- 为什么错：`HMAC(K,m)=H((K^opad)||H((K^ipad)||m))`，外层哈希的输入固定，长度扩展不成立。
- 正确动作：先确认 MAC 构造（`H(secret||msg)` vs HMAC vs `H(msg||secret)`）；只有前者能用
  hashpump/length-extension，且必须拿服务端接受作为判据。

### 25. 竞态里把"进程崩了"当"赢了"

- 错误动作：循环替换符号链接，看到 victim 崩了就写"竞态成立"。
- 为什么错：崩溃可能是"读到了坏文件/路径不存在"，没有 post-use 原语（读到 root 文件/写到 root 路径）。
- 正确动作：定义 post-use 原语并复算（首行 + sha256 / 回读 / `id`），统计 win/rounds；只有崩溃写"疑似"。

## 为什么这些错反复出现（三类根因）

| 根因 | 典型表现 | 防护动作 |
|---|---|---|
| 保护位当结论 | 看到 Full RELRO 就停 | 走 `mitigation-matrix.md` 决策树，列 2–3 条候选 |
| 抄常量 | 偏移/gadget/hook 偏移照搬 | 每个数字都要有"现场生成"的命令 |
| 结果导向 | 崩了/一次成功就宣布 | 用 marker/回代/10 次统计做判据 |

## 把"错"变成可机检的代理信号

| 失误 | 代理信号 | 机检方式 |
|---|---|---|
| 偏移单源 | `repro.json` 里 `evidence` 只有 1 条 | 数组长度 <2 即降档 |
| 无 marker 的控制 | 日志里没有目标函数输出 | 搜 marker 字符串 |
| 一次成功当稳定 | `runs/` 少于 10 份 | 文件计数 |
| 密码学没回代 | 输出里没有 `verified` | JSON 字段检查 |
| 池溢出只算理论 | 没有 `_msize`/状态码 | 日志关键字 |

```bash
python - <<'PY'
import json, pathlib
warn = []
off = pathlib.Path("evidence/L1_offset.json")
if off.is_file():
    d = json.loads(off.read_text(encoding="utf-8"))
    if len(d.get("evidence") or []) < 2:
        warn.append("W1 偏移只有单源")
runs = list(pathlib.Path("runs").glob("run.*")) if pathlib.Path("runs").is_dir() else []
if runs and len(runs) < 10:
    warn.append("W2 运行次数<10")
print("warn", warn)
print("pitfall_proxy_ok", not warn)
PY
```

通过长什么样：`warn []` + `pitfall_proxy_ok True`。出现 `W1` 就去补第二来源；`W2` 就去跑满 10 次。

## 复盘模板（每次交付前填一次）

```text
目标/环境：  sha256 / libc build / 内核 / ASLR 状态
走的段：    L0 ✅ L1 ✅ L2 ❌（无 marker）L3 – L4 –
用过的命令： （≤3 条，别人能照抄的那几条）
失败假设：  栈对齐？libc 版本？seccomp？
下一步：    加 ret 对齐 / 换泄漏点 / 转 FSOP
代价：      2 h；已排除 GOT 路线（Full RELRO）
```

模板的目的不是“好看”，是让对方 5 分钟能接上。三行字能替掉一次重跑。

## 三条必答问题（回答不了就别写结论）

1. 这个地址/偏移/明文，**如果错了，哪个实验会暴露它**？
2. 这个结论是**观测**（marker/回代/读回）还是**推导**（“应该能…”）？
3. 我用的数字是**目标环境生成**的，还是从别处拄来的？

三条都答得上，结论才能进报告；有一条含糊，就标“疑似”并写下待验证项。

## 自检清单（提交前逐条过）

1. `sha256` + 编译选项 + libc build id 已记录。
2. 保护位有 JSON 与 `readelf`/`objdump -p` 两份，不是只贴 checksec。
3. 每个偏移有 objdump 行号 + 运行时 probe，`consistent=true`。
4. 控制流有 marker 或 `$rip` 证据；没有就写“未控到 RIP”。
5. 密码学每条都有回代等式或 `verified=true`。
6. 成功率有 10 次统计；远程有泄漏校验。
7. 失败路线与代价已写进报告。

任何一条不过关，就在对应位置标“疑似”并写下待验证项；把“待验证”留着比编一个结论便宜。
报告交出去之前，把这张清单和 §3.2 的代理脚本一起跑一遍，能拦住绝大多数“看起来对”。
清单条目不是形式：每条都对应一个具体失败模式，删掉一条就少一道闸。
把这张清单当“自检脚本的说明书”用：每条都能对应到一个可执行的命令或一段输出。
清单不是一次性的：换了平台（PE↔ELF）或换了 libc，前四条要重新过一遍。

## 失败判据

- 上述任一错误动作出现在报告/脚本里，且没有对应的复核命令 → 该结论降级为“疑似”。
- 只给结论不给证据（偏移来源、回代等式、状态码）→ 视为未完成。
- 发现平台差异却仍套用原平台手法 → 直接判路线错误。

## 边界

- 本文不替代具体题目的逆向；它只防止“看起来对”的结论混进交付。
- 模型可以犯错，但必须在报告里留下可复查的命令与失败路线；隐藏失败比犯错更严重。

## 这一篇算"用对了"吗

- [ ] 报告里没有"checksec=结论"、"抄偏移"、"崩了=控到 RIP"这三类错。
- [ ] 每个偏移/gadget/libc 符号都有现场生成命令，不是常量。
- [ ] 平台语义核对过（PE 无 RELRO/hook、UCRT 不写 `%n`）。
- [ ] 密码学结论都有回代等式；没有把 HMAC 当可长度扩展。
- [ ] 用上面的代理脚本自查过，`pitfall_proxy_ok=True`。
