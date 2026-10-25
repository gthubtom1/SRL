# 01-criteria.md — pwn-crypto 判据表（可机检）

> **范围**：授权 CTF/靶场、自有二进制、现场编译的漏洞程序、真实密码学实现。
> 路由：纯静态算法还原由 `ida-reverse` 承担；Android APK 由 `apkseep` 承担；目标清单由 scope 声明；
> 只想要“扫描报告”的场合走扫描器；本文的每条判据都要求能落到命令、退出码、字节或数学回代。

本表是 `SKILL.md` §3 的展开版。判据分两档：

- **确认（confirmed）**：有可重复的命令 + 原始输出/回代等式；
- **疑似（suspected）**：只有静态线索（字符串、导入、编译选项），未验证可达性。

`pwn-check.py` 只产出“疑似”；`pwn-repro.py` / `crypto-verify.py` / 手工 exploit 才能把条目抬到“确认”。

## 1. 判据总表

| # | 场景 | 输入面 | 判据（可机检） | 证据形态 | 误报风险 |
|---|---|---|---|---|---|
| 1 | 栈溢出覆盖偏移 | 本地 ELF/PE + objdump 文本 + 运行时地址日志 | `pwn-repro.py --objdump d.txt --func vuln --probe-log p.txt` 输出 `consistent=true` 且 `offset` 相同；`offset = (frame-buf)+8` | `repro.json`（含两源 offset、`buffer_disp`） | 中：换优化级别/编译选项后布局变化；只信一次 probe |
| 2 | saved RIP 真的受控 | 与 #1 同一二进制 | 用 `offset*'A'+p64(win)` 运行，stdout 出现目标函数 marker 且 rc 符合预期（`exploit_result.json.ok=true`） | `exploit_result.json`（payload_len、rc、stdout） | 低：只看到崩溃没看到 marker 不算控制 |
| 3 | Canary 是否存在 | ELF 符号表 / PE 导入与 load config | ELF：`__stack_chk_fail` 或 `__stack_chk_guard` 在符号表；PE：`__security_check_cookie` 导入或 load config SecurityCookie 非 0 | `pwn-check --json` 的 `protections.Canary`；`nm`/`readelf -s` 原文 | 中：编译选项开了不等于每个函数都有；leaf 函数可能没有 |
| 4 | PIE / ASLR | ELF `e_type==ET_DYN`；PE `DllCharacteristics & DYNAMIC_BASE` | `pwn-check --json` 的 `protections.PIE`；ELF 再用 `readelf -hW` 的 `Type:` 交叉 | `pwn-check` JSON + `readelf` 片段 | 中：PE 的 DYNAMIC_BASE 只是声明；实际还受加载器策略影响 |
| 5 | NX / 栈可执行 | ELF `PT_GNU_STACK` 的 X 位；PE `NX_COMPAT` | `pwn-check --json` 的 `protections.NX`；ELF 用 `readelf -lW \| grep GNU_STACK` 复核 | JSON + `readelf -lW` 片段 | 低：`mprotect`/`VirtualProtect` 可运行期改页，不能据此判死 |
| 6 | RELRO / GOT 可写 | ELF `PT_GNU_RELRO` + `DT_BIND_NOW`/`DF_BIND_NOW` | `pwn-check` 的 `protections.RELRO` ∈ {Full, Partial, None}；Full 时 GOT 覆写路线判死 | JSON + `readelf -dW` 的 BIND_NOW 行 | 中：Full RELRO 只保护 GOT，`.fini_array`/函数指针仍可能可写 |
| 7 | 格式化串任意读 | 可控 format 串 + 已定位的参数序号 | 在未认证分支前，stdout 出现目标内存内容（如全局 secret），且 `authenticated` 仍为 false | `leak_result.json`（含 stdout、`leaked_flag=true`） | 低：必须看到目标字节；只打印 `%p` 栈值不算任意读 |
| 8 | 格式化串任意写 | `%n/%hn/%hhn` 可用 + 目标地址可写 | 写后读回目标地址等于期望值；连续两次写不崩；`%n` 计数与输出长度一致 | 写前/写后内存 dump 或程序行为改变（如 auth 分支翻转） | 高：UCRT 下 `%n` 不写（见 case05）；输出截断会少写 |
| 9 | 堆 tcache/UAF | 菜单程序 + 目标 glibc | `malloc` 返回受控 target；`vis_heap_chunks` 可见重复/重叠；触发不 abort；2.32+ 用 `target^(chunk>>12)` | gdb 会话记录 + exploit 10 次成功计数 | 中：safe-linking 未编码、count 已满、target 未 0x10 对齐 |
| 10 | 整数回绕/欠分配 | 长度/数量由输入决定 | 打印/回代证明 `count*size < count`（回绕），随后写入长度 > 分配长度；进程以堆破坏类状态退出 | `int_overflow_wrap.log`：`bytes=4 wrapped=1 _msize=4 wrote=64 overflow=1` + NTSTATUS 0xC0000374 | 中：只证明“理论会溢出”不算；要看到实际分配/写入/退出码 |
| 11 | seccomp 白名单 | 目标 ELF + `seccomp-tools dump` | 读到完整 BPF；ORW 链的 syscall 序列与白名单一致；stdout 含 flag 内容 | `seccomp-tools` 原文 + `strace -f` 序列 + flag 输出 | 低：只读一半 BPF、fd 猜错、open/openat 混用 |
| 12 | RSA 小指数无填充 | `n,e,c` 三元组 | `crypto-verify.py --rsa`：`iroot(c,e)` 精确且 `pow(m,e,n)==c`；`ascii` 可读 | `rsa.json`（m、ascii、verified=true） | 低：有 PKCS#1 填充时开方必失败——失败本身就是判据 |
| 13 | RSA 广播（Håstad） | 同一 m、≥e 组互质 n | `--broadcast`：CRT 后开方精确；`per_modulus` 全 true；`m^e < M` | `broadcast.json`（per_modulus 数组、crt_bits） | 中：消息不同或 m^e≥M 时 CRT 结果不是精确立方 |
| 14 | ECB / CBC | key/plaintext 或 iv/ciphertext | ECB：重复明文块→重复密文块（`duplicate_blocks>=1`）；CBC：翻转 C[i-1] 后 P[i] 目标字节按 xor 改变且解密不报 padding 错 | `ecb.json` / `cbc.json`（前后明文字节 hex、verified） | 中：ECB 随机碰撞会误判（用多块重复）；CBC 改错块索引会改到别的块 |
| 15 | PRNG 预测（MT19937） | 624 个连续 32-bit 输出 | `--mt`：克隆状态后下 N 个输出与真实值逐位一致（`verified=true`） | `mt.json`（predicted 数组、expected 数组） | 中：中间混入 `randint` 拒绝采样会错位；输出不连续必失败 |
| 16 | HMAC / 签名校验 | key/message/expected 或证书链 | `--hmac`：`hmac.compare_digest` 通过且篡改后必须失败；证书用 `openssl verify` 复现 | `hmac.json`（digest、tamper_rejected）；`openssl` 输出 | 高：只改文件没改信任链；把解析差异当签名伪造 |
| 17 | JWT `alg:none` / 算法混淆 | 授权测试 token + JWKS/公钥 | 改 `alg` 后重放：`jwt_accepted=true` 且 `protected_resource=true`；`alg=none` 空签名或“公钥当 HMAC 密钥”至少一种被服务端接受 | `jwt.json`（原/改 header、payload diff、HTTP 码）+ 服务端响应 | 中：只在前端解码成功、服务端 401；公钥字节或 base64url 表示不对 |
| 18 | JWT 弱密钥 / `kid`/`jku` / claim | token、字典、可控 `kid` 路径或自建 JWKS | `hashcat -m 16500` 命中后本地 HMAC 回代等于原签名（`cracked=true`）；或 `kid_traversal=true` / `jku_self_hosted=true` / `claim_escalated=true` 且服务端接受 | `jwt_crack.json`（secret 指纹、回代等式）+ 请求/响应 | 高：字典未命中不等于强密钥；`exp` 被接受但无权限变化 |
| 19 | EVM/智能合约（域边界） | 合约源码、链上地址、Foundry 工程 | 本域无 EVM 运行时：只允许写 `evm_runtime=false`、`out_of_scope=true`、`route=web-pentest\|external-audit`；不得产出 `confirmed` | `scope.md` 的边界声明 + 转交链接 | 高：任何“链上已验证”结论都不可在本域复算 |
| 20 | FSOP（`_IO_wfile_jumps`/`_IO_str_jumps`） | 可写堆 + `_IO_list_all`/stderr 可覆盖 + glibc 2.34+ | `io_file_vtable` ∈ {`_IO_wfile_jumps`,`_IO_str_jumps`}；`_IO_flush_all_lockp` 命中且 `bt` 见 `__doallocate→system`；`fsop_works=true` 需 marker/shell | `fsop.json`（vtable 符号、wide_data/lock 地址、rc、marker） | 高：vtable 越界 `_IO_vtable_check` abort 会被误读成“打通”；只伪造结构没走 flush |
| 21 | 退出链（`exit_funcs` / `tls_dtor_list`） | `__run_exit_handlers` 可写链表或 TLS 可写 + 正常 `exit()` | `exit_funcs_target` 指向受控函数且断点命中后真执行；或 `tls_dtor_hit=true`（`func`=受控地址、`obj` 可控） | `exit_chain.json`（flavor、mangled 前后指针、rc、marker） | 高：未解 `PTR_MANGLE` 就宣布成功；进程 `_exit()/abort()` 跳过 handler |
| 22 | TOCTOU / 文件竞态 | 先 check 后 use 的 SUID/服务二进制、先 stat 再 open 的脚本；低权可写目录；竞态窗口放大器（FUSE sleep / RENAME_EXCHANGE / CPU 绑定） | `strace -f -e trace=file` 中同一用户可控路径出现 ≥2 次解析；竞态循环的胜出轮次/总轮次可统计（例 win=7/200）；post-use 原语可复算：读到 root-only 文件首行、写到 root 路径后回读、以更高权限输出 `id | whoami` | `toctou.json`（路径、解析次数、win/rounds、post-use 输出 sha256）+ 失败侧证据（单次解析、`O_NOFOLLOW`、mkstemp 持 fd、无写权限） | 高：只有静态候选/单次解析；进程崩了但无对象替换；目标实际用 fd 操作；文件系统不支持 RENAME_EXCHANGE（EINVAL）；Windows 路径已规范化 |

## 1.1 采样量下限（判据的最小样本）

> 这一节只回答“样本够不够”。具体手法见 `binary-exploitation.md` / `crypto-attacks.md`；
> 低于下限的结论一律降为“疑似”，不因为“看起来对”而抬档。

| 判据 | 最小样本 | 机检字段 | 不足时唯一可写的措辞 |
|---|---|---|---|
| 栈偏移 | 2 个独立来源（objdump + probe）且相等 | `consistent=true`、`offset` 相同 | 疑似：单一来源偏移 |
| 栈对齐 | 1 次单步到 `ret` + 1 次实跑 | `$rsp` 指向下一 gadget / `ret` 命中 | 未验证：可能 `movaps` 崩 |
| Canary | 目标函数反汇编里看到 `fs:0x28` 或 `__stack_chk_fail` | 反汇编行号 | 疑似：全局有 canary |
| 堆原语 | 2 次 `malloc` 返回同一 target / 重叠 chunk 可见 | `vis_heap_chunks` 截图 | 疑似：只泄漏堆地址 |
| 整数回绕 | 1 次真越界 + 状态码/写入长度 | `_msize`、`wrote`、NTSTATUS | 疑似：只算理论回绕 |
| seccomp | 完整 BPF + 1 次 syscall 序列 | `seccomp-tools dump` 原文 | 疑似：只看到字符串 |
| RSA 回代 | 1 次 `pow(m,e,n)==c` | `verified=true` | 假设未验证 |
| 广播 | ≥e 组互质 n + 每组回代 | `per_modulus` 全 true | 疑似：组数不足 |
| ECB | 重复块可复现 + 1 次重排被接受 | `duplicate_blocks>=1` | 疑似：密文随机 |
| CBC/oracle | 目标字节改变 + padding 不报错 | `before^after==xor` | 疑似：只改没验 |
| HMAC 长度扩展 | 伪造消息被服务端接受 + 回代 | `sig_ok=true` | 疑似：只在本地验算 |
| MT19937 | 624 个连续 32-bit + N 个预测一致 | `verified=true` | 疑似：分布像随机 |
| 稳定性 | 10 次全新进程/连接 | 成功计数 | 现象，不是打通 |

```bash
# 一行看当前证据够不够（读已生成的 JSON，不执行目标）
python Tool/skill/pwn-crypto/scripts/pwn-check.py --file ./chall --json > evidence/pwn_check.json
python -c "import json;d=json.load(open('evidence/pwn_check.json'));print(d['protections'])"
```

通过长什么样：

```text
{'NX': 'Enabled', 'PIE': 'Enabled', 'Canary': 'Found', 'RELRO': 'Full'}
```

注意：这行输出是 **L0 保护位**，不是“能不能打”。四项全开时下面 §1.2 的 L2–L4 仍然可能走通。

## 1.2 保护位 → 利用链：五段判据（每段都要证据）

| 段 | 问题 | 可机检判据 | 不算通过 |
|---|---|---|---|
| L0 保护位 | 哪些路径被封 | `pwn-check` 四项 + `readelf`/`objdump -p` 交叉 | 只贴 `checksec` 一行 |
| L1 泄漏 | 能不能拿到基址 | 泄漏值页对齐；低 12 位与目标 libc/模块吻合 | `%p` 打一堆就算 |
| L2 控制 | `$rip` 是否受控 | marker 输出，或 gdb 里 `$rip` 等于 payload 值 | 进程崩了就算 |
| L3 原语 | 任意写/读是否成立 | 写后读回等于期望；`malloc` 返回 target | 只改不验 |
| L4 稳定 | 能否重复 | 全新进程 10 次 ≥9 | 一次成功、gdb 下成功 |

```bash
# L0→L1 的最小流水线（本地靶场）；每步落盘，失败就知道停在哪一段
python Tool/skill/pwn-crypto/scripts/pwn-check.py --file ./chall --json > evidence/L0.json
python Tool/skill/pwn-crypto/scripts/pwn-repro.py --objdump evidence/chall.dis --func vuln \
  --probe-log evidence/probe.txt --json > evidence/L1_offset.json
python -c "import json;d=json.load(open('evidence/L1_offset.json'));print('L1',d['consistent'],d['offset'])"
```

通过长什么样：

```text
L1 True 88
```

`L1 True 88` 只说明“偏移两源一致”，**不说明 L2**。报告里这种分段报数能直接看出卡在哪一段，
避免把“偏移算出来了”写成“已打通”。

## 1.3 密码学补充判据（共模 / 重排 / 长度扩展 / oracle）

| # | 场景 | 可机检判据 | 证据形态 | 误报风险 |
|---|---|---|---|---|
| 23 | RSA 共模 | `gcd(e1,e2)==1`，且 `pow(m,e1,n)==c1` 与 `pow(m,e2,n)==c2` 同时成立 | `common_modulus.json`（指数、两个回代） | 中：`e1/e2` 不互质时需先约简；消息不同则两回代不会同时成立 |
| 24 | ECB 块重排 | 重排后的密文解密/padding 合法，且服务端接受重排后的身份字段 | 原块/重排块 hex + 服务端响应 | 高：只本地解密成功不算，必须目标接受 |
| 25 | CBC padding oracle | 每字节 ≤256 次查询恢复；最后一块 padding 为 `0x01..0x10` 且解密不报错 | `oracle.json`（查询次数、恢复明文、padding 验证） | 中：MAC-then-encrypt 会先拦；噪声被当 oracle |
| 26 | HMAC 长度扩展 | **仅适用于** `H(secret‖msg)` 型 MAC：伪造 `msg‖pad‖ext` 的签名被服务端接受；HMAC 构造应必然失败 | `length_ext.json`（原/伪造签名、服务端码） | 高：把 HMAC 当可扩展；只本地验算不重放 |
| 27 | CTR/GCM nonce 重用 | `C1^C2 == P1^P2`（已知一对明文即可恢复另一条） | 异或 hex + 可打印率 + 明文样本 | 中：只看到“可打印”不算；GCM 需额外恢复认证密钥 |
| 28 | 弱 PRNG 种子 | 在候选种子空间内枚举，`next(seed)` 与观测输出相等 | `seed.json`（种子、首个输出、回代） | 低：种子不在窗口内就失败（失败也是判据） |

规则：23–28 每条都要落一个 `verified` 字段；只有“推导过程”没有“回代/重放”的，不进结论。

## 1.4 一个合格判据卡的形状

```json
{"case": "pwn-crypto03", "sha256": "…", "libc_build": "…",
 "claims": [
  {"id": "L0", "kind": "protection", "level": "confirmed",
   "cmd": "pwn-check.py --file ./chall --json", "rc": 0, "evidence": "L0.json"},
  {"id": "L1", "kind": "offset", "level": "confirmed",
   "cmd": "pwn-repro.py --objdump … --probe-log …", "rc": 0, "evidence": "L1_offset.json", "want": "consistent=true"},
  {"id": "L2", "kind": "control", "level": "suspected",
   "cmd": "exploit.py --offset 88 --win 0x…", "rc": 1, "evidence": "run.log", "why": "无 marker"}
 ],
 "blocked": ["L3: 2.34 无 __free_hook"]}
```

通过标准：`confirmed` 条目必须有 `cmd`+`rc=0`+`evidence`；任何一条 `rc!=0` 必须写 `why`
并降为 `suspected`。这张卡能直接当报告附录，也是 `pwn-accept.py` 看的东西。

## 1.5 数值阈值表（把“差不多”变成可判）

| 项 | 阈值 | 为什么是这个数 | 越线的处理 |
|---|---|---|---|
| 偏移误差 | 0（两源完全相等） | 差 8 字节就会踩到 canary/对齐 | 回查帧指针/优化级别 |
| 泄漏页对齐 | `addr & 0xfff == 0` | libc/模块基址必页对齐 | 泄漏位置或符号偏移错 |
| libc 低 12 位 | 与目标符号完全一致 | 低 12 位不受 ASLR 影响 | libc 版本不对，重收集 |
| 稳定性 | 10 次 ≥9 | 10 次能看出 10% 量级的失败率 | 写“现象 + 失败率”，不写“稳定” |
| 广播组数 | ≥ e 且模数两两互质 | CRT 后才可能得到精确 e 次方根 | 补组或改相关消息攻击 |
| padding oracle | 每字节 ≤256 次查询 | 256 是字节全空间上界 | 超了说明 oracle 噪声/索引错 |
| MT19937 | 624 个连续 32-bit | 状态是 624×32 bit | 不连续/有拒绝采样必失败 |
| ECB 重复块 | ≥1（构造相同明文块后） | 随机碰撞概率极低 | 没重复就不是 ECB |
| 竞态 | win≥1 且 post-use 可复算 | 一次成功即可证明窗口存在 | 0 胜不能写“竞态成立” |

三条常见"假阈值"：

1. “成功率 8/10 也算稳定”——不算，剩下 20% 在远程就是打不中；要么修对齐，要么如实报 8/10。
2. “看到页面变了”当服务端接受——前端乐观更新很常见，必须看响应码/后续读回。
3. “`%p` 打出 0x7f…”当泄漏 libc——必须页对齐且符号低 12 位匹配，否则可能只是栈值。

阈值在此情形下失效的情况（不要硬套）：

| 情况 | 为什么在此情形下失效 | 改用什么 |
|---|---|---|
| 32-bit 目标 | 无 16 字节 `movaps` 对齐约束 | 只查 4 字节栈对齐 |
| fork 服务 | 父进程基址不变，成功率天然高 | 仍按 10 次统计，但注明 fork 模型 |
| 本地关 ASLR | 泄漏变得不必要，成功率虚高 | 报告里注明“已关 ASLR”，不推广到远程 |
| 靶场限速 | 10 次可能要很久 | 改为 5 次 + 写明样本量，仍不写“稳定” |

## 2. 机检命令与判定阈值

```bash
# 1) 静态预判（只读，不执行目标）
python Tool/skill/pwn-crypto/scripts/pwn-check.py --file ./chall --json > pwn_check.json

# 2) 偏移三源对齐（本机现场编译时用）
python Tool/skill/pwn-crypto/scripts/pwn-repro.py \
  --objdump stack_overflow.dis --func vuln --probe-log probe.txt > repro.json

# 3) 密码学回代（每条都要 verified=true）
python Tool/skill/pwn-crypto/scripts/crypto-verify.py --rsa inputs/rsa.json
python Tool/skill/pwn-crypto/scripts/crypto-verify.py --broadcast inputs/broadcast.json

# 4) 稳定性（真打通才写 ≥9/10）
for i in $(seq 10); do timeout 30 python3 exploit.py >/tmp/run.$i 2>&1; echo "$i $?"; done
grep -l 'uid=\|FLAG{' /tmp/run.* | wc -l
```

阈值：

- `consistent=true` 且两源 `offset` 相等才算 #1；只有 objdump 或只有 probe 一律“疑似”；
- `verified=true` 是密码学条目的硬门槛，没有回代等式就退回“假设未验证”；
- `rc=0` 且 stdout 有 marker 才算 #2；崩溃但无 marker 只算“可能覆盖到”；
- 稳定性 ≥9/10 才算“打通”，否则在报告里写“现象 + 失败路线”。

## 3. 证据形态的最小集合

一次 pwn-crypto 交付至少包含：

1. `sha256` 与编译/运行环境（gcc 版本、`-O0/-fno-stack-protector/-no-pie`、libc build id）；
2. 保护位原文（`pwn-check` JSON 或 `checksec`）；
3. 偏移来源（objdump 行号/位移 + 运行时 probe 值），两者一致；
4. 受控证据（marker 输出、写后读回、`pow(m,e,n)==c`、逐位比对）；
5. 失败/降级路线（哪条走不通、依据是什么）；
6. 复现命令与退出码（可直接贴进报告）。

## 4. 失败判据（看到即降级为“疑似”）

- `pwn-repro` 报 `offset-mismatch` 或 `consistent=false` → 偏移不可信，先查编译选项/帧指针/是否取错变量。
- 只有 `checksec` 输出，没有偏移/泄漏/回代 → 全部判据停在“疑似”。
- 加密条目 `pow(m,e,n)!=c` → 攻击假设（填充、同一消息、m^e<n）至少有一条不成立。
- ECB 只看到“像随机”的密文 → 必须找到重复块或 oracle 响应，否则不能判 ECB。
- 平台差异未核对（如 Windows UCRT 的 `%n` 不写）→ 不能把 glibc 手法直接外推。

## 5. 边界

- 本表只覆盖“能本地复现”的利用/求解；真实生产系统按 scope 清单执行；持久化/横向移动由对应授权任务承担。
- 偏移、gadget、libc 符号一律以目标环境的版本为准；本表给的数字只是案例，不是通用常量。
- PE 的“保护位”是 `DllCharacteristics` 近似，与 ELF 的 RELRO/canary 语义不同，术语按平台分册表述。

## 附：上游技能卡索引（24 张）

> 上游 = `mukul975/Anthropic-Cybersecurity-Skills`（818 技能库）。本表只回答一件事：这条上游技能在本域**落到哪张卡、哪篇 reference、判据是什么**。

| 上游技能 | 本域任务卡 | 落点 reference | 一句话判据 |
|---|---|---|---|
| `performing-binary-exploitation-analysis` | 栈溢出偏移与 saved RIP 控制（源：performing-binary-exploitation-analysis） | `Tool/skill/pwn-crypto/references/04-walkthrough-local-pe.md` | `consistent=true` 且 offset 相同；marker 输出出现且 rc 符合预期。 |
| `analyzing-heap-spray-exploitation` | 堆喷射与 tcache 布局测量（源：analyzing-heap-spray-exploitation） | `Tool/skill/pwn-crypto/references/heap-and-sandbox.md` | `malloc` 返回受控 target；重叠 chunk 可见；触发不 abort。 |
| `exploiting-vulnerabilities-with-metasploit-framework` | 利用模块选择与本地复现（源：exploiting-vulnerabilities-with-metasploit-framework） | `Tool/skill/pwn-crypto/references/binary-exploitation.md` | 本地隔离环境可重复命中；模块参数与手工分析一致。 |
| `exploiting-insecure-deserialization` | 反序列化原语到代码执行的判据（源：exploiting-insecure-deserialization） | `Tool/skill/pwn-crypto/references/01-criteria.md` | 最小对象能改变程序行为（文件/命令/回显）；链在目标版本成立。 |
| `exploiting-type-juggling-vulnerabilities` | 类型混淆/整数比较绕过的二进制验证（源：exploiting-type-juggling-vulnerabilities） | `Tool/skill/pwn-crypto/references/01-criteria.md` | 输入使校验分支走通且后续行为改变；不是仅“理论可绕”。 |
| `exploiting-template-injection-vulnerabilities` | 模板注入到命令执行的验证（源：exploiting-template-injection-vulnerabilities） | `Tool/skill/pwn-crypto/references/01-criteria.md` | 模板输出出现求值结果；无害命令回显可复现。 |
| `exploiting-race-condition-vulnerabilities` | 竞态窗口测量与可复现性（源：exploiting-race-condition-vulnerabilities） | `Tool/skill/pwn-crypto/references/02-failure-criteria.md` | 成功率可量化，且失败原因可解释（窗口/调度）。 |
| `exploiting-prototype-pollution-in-javascript` | 原型污染到运行时对象篡改（源：exploiting-prototype-pollution-in-javascript） | `Tool/skill/pwn-crypto/references/03-model-pitfalls.md` | 运行时对象属性被改且影响可观测行为。 |
| `performing-hash-cracking-with-hashcat` | 口令哈希识别与真实回代（源：performing-hash-cracking-with-hashcat） | `Tool/skill/pwn-crypto/references/crypto-attacks.md` | 回代 `hash(plaintext)==digest` 成立；不是“看起来像密码”。 |
| `performing-cryptographic-audit-of-application` | 密码学实现审计（模式/IV/填充）（源：performing-cryptographic-audit-of-application） | `Tool/skill/pwn-crypto/references/crypto-attacks.md` | 块关系/位翻转/回代等式成立；结论能落到具体字节。 |
| `implementing-rsa-key-pair-management` | RSA 密钥生成与参数校验（源：implementing-rsa-key-pair-management） | `Tool/skill/pwn-crypto/references/crypto-attacks.md` | `p*q==n`、私钥回代成立、e 与 φ 互质。 |
| `implementing-aes-encryption-for-data-at-rest` | AES 模式选择与 IV/认证（源：implementing-aes-encryption-for-data-at-rest） | `Tool/skill/pwn-crypto/references/crypto-attacks.md` | 重复块/位翻转/tag 失败等行为可复现；密钥长度合法。 |
| `performing-post-quantum-cryptography-migration` | PQC 迁移风险清单（源：performing-post-quantum-cryptography-migration） | `Tool/skill/pwn-crypto/references/crypto-attacks.md` | 迁移清单覆盖密钥交换/签名/证书；测试向量通过。 |
| `migrating-to-post-quantum-cryptography` | 混合密钥交换/签名验证（源：migrating-to-post-quantum-cryptography） | `Tool/skill/pwn-crypto/references/01-criteria.md` | 双方互操作成功；降级路径可检测。 |
| `exploiting-jwt-algorithm-confusion-attack` | JWT alg 混淆（RSA→HMAC）（源：exploiting-jwt-algorithm-confusion-attack） | `Tool/skill/pwn-crypto/references/01-criteria.md` | 服务端接受伪造 token 且能访问受保护资源。 |
| `performing-jwt-none-algorithm-attack` | JWT none/签名剥离（源：performing-jwt-none-algorithm-attack） | `Tool/skill/pwn-crypto/references/01-criteria.md` | 无签名 token 被接受且声明生效。 |
| `testing-jwt-token-security` | JWT 测试矩阵（弱密钥/过期/声明）（源：testing-jwt-token-security） | `Tool/skill/pwn-crypto/references/01-criteria.md` | 每项都有请求/响应证据；弱密钥能回代签名。 |
| `exploiting-ms17-010-eternalblue-vulnerability` | 永恒之蓝漏洞验证（授权隔离）（源：exploiting-ms17-010-eternalblue-vulnerability） | `Tool/skill/pwn-crypto/references/02-failure-criteria.md` | 隔离环境可重复验证；检测证据完整。 |
| `exploiting-zerologon-vulnerability-cve-2020-1472` | Zerologon 原理与检测（源：exploiting-zerologon-vulnerability-cve-2020-1472） | `Tool/skill/pwn-crypto/references/01-criteria.md` | 检测结果与补丁/日志一致；不执行破坏性重置。 |
| `exploiting-nopac-cve-2021-42278-42287` | NoPac 原理与检测（源：exploiting-nopac-cve-2021-42278-42287） | `Tool/skill/pwn-crypto/references/02-failure-criteria.md` | 检测证据可复现；未越权到生产。 |
| `exploiting-insecure-data-storage-in-mobile` | 移动端不安全存储（边界）（源：exploiting-insecure-data-storage-in-mobile） | `Tool/skill/pwn-crypto/references/03-model-pitfalls.md` | 敏感数据可读且有来源路径；哈希可回代。 |
| `analyzing-ethereum-smart-contract-vulnerabilities` | 智能合约整数/重入（EVM 视角）（源：analyzing-ethereum-smart-contract-vulnerabilities） | `Tool/skill/pwn-crypto/references/01-criteria.md` | 交易成功且状态被非预期改变；有交易哈希。 |
| `auditing-foundry-smart-contract-security` | Foundry 测试与断言（源：auditing-foundry-smart-contract-security） | `Tool/skill/pwn-crypto/references/01-criteria.md` | 测试输出可复现；断言覆盖目标不变量。 |
| `performing-ssrf-vulnerability-exploitation` | SSRF 到内网访问的验证（边界）（源：performing-ssrf-vulnerability-exploitation） | `Tool/skill/pwn-crypto/references/02-failure-criteria.md` | 服务端确实发起请求（日志/回显）；不触碰真实内网资产。 |

## 这一篇算"用对了"吗

- [ ] 每条结论都落在 L0–L4 的某一段，没有把"偏移算出来"写成"已打通"。
- [ ] 采样量先过 §1.1：偏移两源、稳定性 10 次、MT 624 输出、广播 ≥e 组。
- [ ] 密码学条目都有 `verified=true` 或明确写"假设被推翻"，没有只给推导。
- [ ] 判据卡里 `confirmed` 条目全部有 `cmd`+`rc=0`+`evidence`，其余标了 `why`。
- [ ] 平台语义核对过（PE vs ELF、UCRT vs glibc），没有跨平台套术语。
