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

## 3. 失败也要交付的内容

- 已排除的路线 + 排除依据（命令、输出、状态码）；
- 当前停在哪个判据（例如“偏移一致，但 RIP 未受控”）；
- 再试一次的代价估计（时间/是否需要新工具/是否需要新样本）；
- 平台差异说明（Windows UCRT vs glibc、PE vs ELF）。

## 4. 失败判据（本文自身）

- 只写“失败了”不写“哪条判据失败、改走哪条、代价多少” → 本文没被正确使用；
- 把“一次偶然成功”写成“稳定 9/10” → 直接判报告不合格；
- 用本地关闭 ASLR 的结果冒充远程结论 → 判据不成立，退回重测。

## 5. 边界

- 失败判据用于“止损”，不是“放弃”：换路线后仍要按 `01-criteria.md` 重新建立可机检证据。
- 某些失败是环境限制（无 gdb、无同版本 libc、无 Linux 靶机），应写 `blocked_at`，不要伪造成功。
- 同一目标同类动态尝试最多 2 次；第二次失败必须停下汇报，避免把靶场打成 DoS。
