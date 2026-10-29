---
name: pwn-crypto
description: "这道题能不能打通/有没有溢出/走 ROP/格式化字符串/堆利用/绕过 seccomp/拿到 shell；或者 RSA/ECB/CBC/PRNG/HMAC/证书签名有没有问题。含 checksec 保护位与利用链构建。 (.elf/.so/.py/二进制程序)"
license: MIT
compatibility: "Linux x86/x64/ARM64 优先；Windows 下可用 MinGW 复现 PE 语义。Python 3.10+；pwntools/ROPgadget/checksec/pycryptodome 可选，缺失按降级链执行。"
metadata:
  version: "2.0.0"
  references_dir: "Tool/skill/pwn-crypto/references/"
  scripts_dir: "Tool/skill/pwn-crypto/scripts/"
  acceptance: "偏移两源一致 + marker/回代成立 + 10 次≥9；否则只算疑似"
---

# pwn-crypto — 二进制利用与密码学攻击

> 本技能只做**可验证的利用/求解**：从保护位推出打法，从泄漏推出地址，从一次成功推到稳定复现，
> 从密码学假设推到回代等式。纯静态算法还原交 `softseep`；
> Android 目标交 `apkseep`；Web/API 逻辑交 `web-pentest`。
>
> 机检入口：`python Tool/scripts/domain-gate.py --domain pwn-crypto`；
> 真实案例：`Tool/cases/pwn-crypto01`–`05`；知识库：`Tool/mcp/Tool/reverselab/kb/pwn-crypto/`。

## 阶段契约（与 softseep 一致，**先判再做**）
> **域契约**（判型→裁定+M1–M4→按上限执行→停手问）：见 `Tool/skill/seep-router/SKILL.md`（唯一口径：判型→选域→上限 M1–M4→按当前路线核缺件）。本文件不复制。
- 项目登记、证据、验收与接续按 router 第 5 步；`case_state.py` 仅用于需要专业过闸的单案。
- 只执行当前目标需要的阶段；缺不可替代输入才问 A/B/C，已有授权不重复询问。参考与配方不能扩大用户目标；示例案例通过只证明工具自检，不能代替当前项目验收。

## 1. 范围与路由（边界）

**本域输入面**

- CTF pwn/crypto、授权靶场、自有 ELF/PE 程序的白盒验证；
- 输入：ELF/`.so`/`libc.so.6`、PE `.exe/.dll`、远程 `host:port`、密码学参数或加解密 oracle；
- 输出：`exploit.py`/`solve.py`、偏移与保护位证据、稳定复现命令、flag 或“已排除路线”。

**相邻域与路由**

- 目标清单由 `scope` 声明；真实生产凭据/证书只留指纹；持久化/横向移动/DoS 按单独授权单执行；
- 纯静态算法还原交 `softseep`，协议测绘按需组合 `protocol-plugin`；
- APK/DEX/SO、Frida/脱壳/重打包（交 `apkseep`；解壳闭环在 `unpack-loop`）；
- Web/API/JWT 业务逻辑（交 `web-pentest` 或对应 Web 技能）；
- 智能合约（EVM）由外部审计流程承担：本域提供字节码静态分析与数学回代，链上运行时与交易证据在该流程侧；DApp API 面交 `web-pentest`；
- 只要扫描报告的场合走扫描器/`web-pentest`——本技能的判据全部要求可复跑。

**平台边界**

- 本仓库开发机为 Windows + MinGW：PE 的 NX/ASLR/GS 用 `DllCharacteristics` 近似，PE 没有
  ELF RELRO/GOT/`__free_hook`；UCRT 的 `printf` **不执行 `%n`**（案例 05 实测）。
- ELF/libc/seccomp 路线需要在 WSL2/远端 Linux 执行；没有同版本 libc 时最多给“疑似偏移”。

## 配方（照这个跑）

输入面命中下面某行时，先照该配方的命令序列跑，再回来对判据；配方正文只在 playbooks 一处，本文件只指路。

- 逆向测绘里的保护位/危险导入/利用路线（pwn-check 那一段）→ `Tool/playbooks/reverse-survey.md`

## 上限怎么说（对客户）

- **只能看懂结构**：`定位到了崩溃点/保护位/数学关系，但控制流没拿到手上（偏移两源不一致，或回代等式不成立），只能说「疑似」`
- **能改到能用**：`本地能打通：偏移两源一致、marker 打印出来、10 次里≥9 次稳，附完整利用链与复跑命令`
- **能完全自己接管**：`换进程/换连接/换目标仍稳，远程有 flag 或 root 证据，并且已排除的路线也记在案`
- **卡点通常是**：`全保护（Full RELRO + PIE + Canary + NX）且找不到泄漏，或手上没有同版本 libc / 可打的远端实例`

> 依据：本文件 §3 判据表（#1 栈溢出 / #6 密码学 / #7 稳定性）+ §4 失败判据（偏移不一致、全保护无泄漏、6–8/10）

## 2. 前置检查（三件，不过不开打）

### 2.1 留基线：哈希 + 平台 + 编译选项

```bash
sha256sum ./chall ./libc.so.6 2>/dev/null | tee evidence/SHA256SUMS
file ./chall
readelf -hW ./chall | sed -n '1,12p'
readelf -dW ./chall | grep NEEDED  # 静态查看依赖声明；不以 ldd 探测未知程序
```

现场编译的样本要记录：`gcc --version`、`-O0/-fno-stack-protector/-no-pie`、
`objdump -d` 的版本。PE 样本记录 `objdump -p` 的 `DllCharacteristics`。

**完成判据**：能说清平台、位数、编译/运行环境、目标哈希；否则后面的偏移不可比。

### 2.2 保护位：静态预判（只读，不执行目标）

```bash
python Tool/skill/pwn-crypto/scripts/pwn-check.py --file ./chall --json > pwn_check.json
# 可选交叉复核
checksec --file=./chall          # ELF
readelf -lW ./chall | grep GNU_STACK
readelf -dW ./chall | grep -E 'BIND_NOW|RPATH|RUNPATH|NEEDED'
```

`pwn-check.py` 输出四项：`NX` / `PIE` / `Canary` / `RELRO`（PE 为 `N/A (PE 无 ELF RELRO)`），
外加危险导入、format 串风险与 `next_routes`。它只给“疑似”，不证明可利用性。

**二进制利用任务的完成判据**：保护位与输入面/危险导入结论有证据，未知保留；纯密码学参数任务无需 ELF 保护位或危险导入。

### 2.3 运行面：调试器、libc、沙箱

```bash
gdb --version | head -1
python -c "import pwn, Crypto; print('pwntools/pycryptodome ok')" 2>/dev/null || true
# seccomp-tools dump / strace 会执行目标，仅在已获运行许可的隔离环境使用
cat /proc/sys/kernel/randomize_va_space 2>/dev/null || true
```

- 下列命令会运行目标，须在已有运行许可与隔离环境内执行。需要固定基址时用 `setarch "$(uname -m)" -R ./chall`，并在报告中注明“关闭 ASLR”；
- 远程只信远程泄漏，不把本地偏移当远程地址；
- 工具缺失先查能力表（`python Tool/scripts/tool-acquire.py` / `Tool/mcp/tool_autodiscover.py`），不要反复安装。

**完成判据**：知道哪些工具可用、哪些要走降级分支（`blocked_at: "tool-missing"`）。

## 3. 判据表（确认 vs 疑似）

> 完整表（场景/输入面/可机检判据/证据形态/误报风险）见
> `references/01-criteria.md`；这里只给每类的“确认/疑似”分界。

| # | 类别 | 确认（有证据） | 疑似（只有线索） |
|---|---|---|---|
| 1 | 栈溢出 + ROP/ret2libc | offset 两源一致（`pwn-repro` `consistent=true`）；marker 输出；泄漏基址页对齐且与目标 libc 吻合；10 次≥9 | 只有 checksec/危险导入；崩溃但 RIP 未受控 |
| 2 | 格式化串 | `%s` 读出目标内存字节；或 `%n` 写后读回等于预期、两次写不崩、计数一致 | 只打印 `%p` 栈值；只发现 `%n/%s` 模板 |
| 3 | 堆 tcache/UAF/IO | `malloc` 返回受控 target；重叠 chunk 可见；触发不 abort；2.32+ safe-linking 编码正确 | 只泄漏堆地址；只看到 malloc/free 导入 |
| 4 | 整数 / off-by-one | 证明回绕/越界一个对象；写入长度 > 分配；出现堆破坏状态码（如 `0xC0000374`） | 只算出 `count*size` 会回绕，程序未越界 |
| 5 | seccomp / ORW | BPF 读全；`openat/read/write` 序列与白名单一致；stdout 含 flag | 只看到 `seccomp` 字符串或导入 |
| 6 | 密码学（RSA/分组/PRNG） | `pow(m,e,n)==c`；广播每组回代 + `m^e<M`；ECB 重复块；CBC `before^after==xor`；MT 下 N 个逐位一致 | `iroot` 得到可打印字节但未回代；只看到“像随机” |
| 7 | 稳定性 / 交付 | 全新进程/连接 10 次≥9；远程有 flag/root 证据；失败路线已记录 | 一次成功、gdb 下成功、本地关 ASLR 成功 |
| 8 | TOCTOU / 文件竞态 | 同一用户可控路径 ≥2 次解析；竞态 win/rounds 可统计（如 win=7/200）+ post-use 原语可复算（读到 root 文件/写入 root 路径回读/更高权限 `id`） | 只有静态候选；崩溃但无对象替换；目标用 fd 操作（`O_NOFOLLOW`/`mkstemp`） |

**判据使用规则**

1. 任何“确认”必须能贴出命令 + 退出码 + 原始输出/回代等式；
2. 保护位只能把路线排序，不能单独作为“能打/不能打”的结论；
3. 平台语义不同（PE vs ELF、UCRT vs glibc）时，先在目标平台重跑判据。

## 4. 失败判据（看到即降级，改走支路）

完整表（现象/判定/改走哪条/代价）见 `references/02-failure-criteria.md`。高频项：

- 偏移两源不一致，或崩溃但 `$rip` 不是 cyclic 值 → 不是“控到 RIP”，先统一编译选项/帧指针。
- 全保护（Full RELRO + PIE + Canary + NX）且找不到泄漏 → 放弃 GOT/栈路线，转格式化串/堆/逻辑。
- `%n` 探针后变量仍为 0（UCRT）→ 只保留任意读；写路线转堆/逻辑或换 glibc 目标。
- `malloc` 不返回 target / `free` corruption → 定 glibc 版本；2.34+ 放弃 `__free_hook`。
- 整数只证明“理论回绕”、进程正常退出 → 没有真实越界，补 `_msize/写入长度/状态码`。
- 同一路径 ≥3 轮 0 胜，或 strace 里该路径只有 1 次解析 → 不是 TOCTOU；换放大器/换目标，不要宣布“竞态成立”。
- seccomp 白名单没有 `open/read/write` 且拼不出 ORW → 转 SROP/栈迁移；仍不行就如实写“无法读出 flag”。
- `pow(m,e,n)!=c` → 填充/同一消息/模数互质至少一条不成立，退回假设，不要宣布“解出明文”。
- 成功率 6–8/10 → 栈对齐/竞态未解决，不写“稳定”。

**停机规则**：同一路径连续 3 轮无进展，或同一目标同类动态尝试 2 次失败 → 停手汇报已排除项。

## 5. 模型常见失误（≥8 条，详见 `references/03-model-pitfalls.md`）

1. 把 checksec 当“能不能打”的结论 → 保护位只封部分路径，要按决策树列候选。
2. 抄固定偏移（`OFFSET=40/88`）→ 偏移由编译选项/帧指针/libc 决定，必须两源对齐。
3. 只跑 objdump 或只跑 probe → `lea` 可能引用别的变量；两源一致才可信。
4. 把“程序崩了”当“控制流被劫持” → 要有 marker 或 gdb 里 `$rip` 等于 payload 值。
5. 忽略 canary 的每函数差异 → leaf/汇编函数可能没有，去反汇编里找 `fs:0x28`。
6. 把 glibc 的 `%n` 搬到 Windows → UCRT 不写 `%n`（案例 05 实测 `x=0`）。
7. 64 位格式化串把地址放开头 → 地址含 NUL，printf 提前结束；地址放末尾/对齐参数槽。
8. 把 `%p` 泄漏当任意读 → 必须要 `%s` 解引用到目标字节或符号低 12 位匹配。
9. 堆题不看 glibc 版本 → 2.32+ safe-linking、2.34+ 无 hook，偏移会全错。
10. 把“分布像随机”当 PRNG 可预测 → 必须 624 个连续 32-bit 输出克隆并逐位比对。
11. RSA 宣布明文前必须回代 `pow(m,e,n)==c`；广播还要每组成立。
12. 平台语义混用（PE ↔ ELF）→ PE 找 RELRO/GOT/`__free_hook` 是方向错误。
13. 一次成功写成“9/10 稳定” → 全新进程/连接 ≥10 次统计才算。
14. 忽略中文/英文路由差异 → 报告里统一用“确认/疑似/失败”三档，避免“基本可用”。

## 6. 流程（五阶段，每阶段有完成判据）

### 阶段 A：基线与分诊（10–20 分钟）

1. `sha256`、`file`、`pwn-check.py --json`、保护位交叉复核；
2. 列输入面：缓冲区、格式串、长度字段、菜单 alloc/free、密码学参数；
3. 用 `references/mitigation-matrix.md` 的决策树排 2–3 条候选路线。

**完成判据**：`pwn_check.json` + 输入面清单 + 候选路线排序（不写 exploit）。

### 阶段 B：最小证据（30–90 分钟）

- 栈：`pwn-repro.py` 两源对齐 offset；`cyclic`/gdb 复核；
- 格式化串：找参数序号，先做 `%s` 任意读，再确认 `%n` 是否可用；
- 堆：定 glibc 版本，做一次泄漏（heap→libc），确认 tcache count/key；
- 整数：打印 `count/bytes/_msize/写入长度`，确认回绕真的造成越界；
- 密码学：`crypto-verify.py` 跑对应模式，拿 `verified=true`。

**完成判据**：至少一条路线有“可观测证据”（marker/读回/回代），否则回阶段 A 换路线。

### 阶段 C：拼链/求解（1–3 小时）

- ROP/ORW：先泄漏 libc，再 `system` 或 `openat/read/write`；注意 16 字节栈对齐；
- 格式化串写：glibc 下用 `fmtstr_payload`，写后读回；Windows 下若 `%n` 不写则放弃；
- 堆：按 `heap-and-sandbox.md` 的版本表逐步构造，每步 `vis_heap_chunks` 复核；
- 密码学：按 `crypto-attacks.md` 的假设表选择攻击面，每条都回代。

**完成判据**：本地一次跑通，且能解释每一步的地址/偏移来源。

### 阶段 D：稳定性与远程（30–60 分钟）

```bash
for i in $(seq 10); do timeout 30 python3 exploit.py >/tmp/run.$i 2>&1; echo "$i $?"; done
grep -l 'uid=\|FLAG{' /tmp/run.* | wc -l
```

- 本地 ≥9/10；远程做一次泄漏校验；记录 libc/启动参数/缓冲/fork/cwd；
- 远程失败先对比本地，不要直接改偏移硬撞。

**完成判据**：成功率可统计；远程有 flag/root 或明确的失败判据。

### 阶段 E：交付（20 分钟）

- 证据包：`sha256`、保护位原文、偏移两源、泄漏/回代、10 次统计、失败路线；
- 用 `references/01-criteria.md` 的“最小证据集合”逐项打勾；
- 失败也交付：写清哪条判据失败、改走哪条、代价多少。

**完成判据**：报告可被第三人按命令复跑；没有“看起来像”的结论。

## 7. 参考索引（逐篇）

| 文件 | 用途 | 什么时候读 |
|---|---|---|
| `references/01-criteria.md` | 判据总表（场景/输入面/可机检判据/证据形态/误报风险） | 开局定判据、交付前打勾 |
| `references/02-failure-criteria.md` | 失败判据表（现象/判定/改走哪条/代价）；含降级链、事故回流、交接包 | 卡住、想换路线、写“已排除” |
| `references/03-model-pitfalls.md` | 25 条模型常见失误（错误动作→为什么错→正确动作）+ 代理信号 | 写 exploit 前自检、复盘 |
| `references/04-walkthrough-local-pe.md` | 真实案例走查：现场编译 PE 的栈溢出/整数/格式化串 + 密码学回代 | 想照着复跑、需要真实输出片段 |
| `references/binary-exploitation.md` | pwntools/gdb 骨架：ret2libc、格式化串、栈迁移、稳定性；§7 TOCTOU/文件竞态判据（符号链接替换、临时文件命名、RENAME_EXCHANGE、Windows 重解析点） | 阶段 B/C 写脚本 |
| `references/crypto-attacks.md` | RSA/分组/PRNG/证书的可运行求解骨架与回代 | 阶段 B/C 做密码学 |
| `references/heap-and-sandbox.md` | tcache/UAF、IO_FILE、seccomp ORW 骨架与版本判据 | 堆题、沙箱题 |
| `references/mitigation-matrix.md` | 保护位 × 手法 × 判据矩阵 + 决策树 + 误判清单 | 阶段 A 排路线、解释保护位 |

## 8. 脚本用法

四个脚本都可 `--help`；`--self-test` 离线跑通并打印含 `"ok"` 的 JSON；失败输出
`{"ok": false, "blocked_at": "...", "reason": "..."}` 且 rc=2。

```bash
# 1) 静态预判（PE/ELF，只读，不执行目标）
python Tool/skill/pwn-crypto/scripts/pwn-check.py --file ./chall --json > pwn_check.json
python Tool/skill/pwn-crypto/scripts/pwn-check.py --self-test

# 2) 偏移复算：objdump 位移 + 运行时 probe + cyclic 崩溃日志，三源对齐
python Tool/skill/pwn-crypto/scripts/pwn-repro.py \
  --objdump d.txt --func vuln --probe-log p.txt --crash-log c.txt
python Tool/skill/pwn-crypto/scripts/pwn-repro.py --cyclic 300 --find 0x6161616c
python Tool/skill/pwn-crypto/scripts/pwn-repro.py --self-test

# 3) 密码学回代：rsa / broadcast / hmac / mt / ecb / cbc
python Tool/skill/pwn-crypto/scripts/crypto-verify.py --rsa inputs/rsa.json
python Tool/skill/pwn-crypto/scripts/crypto-verify.py --broadcast inputs/broadcast.json
python Tool/skill/pwn-crypto/scripts/crypto-verify.py --self-test

# 4) 域验收：案例字段/哈希/真跑/refs + 保护位与结论一致性（离线）
python Tool/skill/pwn-crypto/scripts/pwn-accept.py --root . --json
python Tool/skill/pwn-crypto/scripts/pwn-accept.py --case pwn-crypto03
python Tool/skill/pwn-crypto/scripts/pwn-accept.py --self-test
```

退出码约定：`0` 成功/通过；`1` 可解析但不一致/回代失败；`2` 结构化失败（缺文件/坏 JSON/缺工具）。
脚本不联网、不执行目标（`pwn-check`），路径由 `__file__` 或 `--root` 推导。

## 9. 任务卡入口

`Tool/prompts/domains/pwn-crypto.md`：24 张卡，源名取自
`Tool/config/taskcard-sources.json` 的 `pwn-crypto`（24 条）。常用起点：

- 卡 01 栈溢出偏移与 saved RIP 控制；
- 卡 02 堆喷射与 tcache 布局测量；
- 卡 09/10 哈希回代与密码学实现审计；
- 卡 15/16/17 JWT 算法混淆/none/测试矩阵；
- 卡 22/23 智能合约整数/重入与 Foundry 断言。

每张卡六段齐全，`reference` 指向本目录下的真实文件；按卡执行后仍要用本文件 §3 的判据验收。

## 10. KB board 入口

`Tool/mcp/Tool/reverselab/kb/pwn-crypto/README.md`（board 索引 + 三条硬判据 + 失败判据 + 邻域边界）。
技术页：

- `techniques/01-stack-rop.md` — 栈溢出与 ROP；
- `techniques/02-heap-and-sandbox.md` — 堆与沙箱；
- `techniques/03-format-string-arbitrary-read.md` — 格式化串任意读（含 UCRT `%n` 边界）；
- `techniques/04-libc-version-and-orw.md` — libc 版本、gadget、seccomp ORW；
- `techniques/05-pe-mitigation-windows.md` — PE 保护位与 Windows 利用面；
- `techniques/06-failure-criteria-playbook.md` — 失败判据速查；
- `techniques/x-crypto-oracle-playbook.md` — 密码学 oracle 速查；
- `techniques/x-heap-tcache-playbook.md` — tcache/UAF 速查。

## 11. 验收与回报

- **利用链的本地稳定性**：同一脚本在全新进程/新连接连续 ≥10 次，成功 ≥9 次；贴命令、rc、成功计数。
- **目标要求远程利用时**：只报告已实测的 shell/flag/受控 marker，附非敏感证据；纯静态分析、离线密码学或本地任务不要求远端或 root。
- **密码学**：`pow(m,e,n)==c`、逐块/逐位比对；贴参数、明文来源与脚本输出。
- **证据留存**：`sha256`、保护位、libc 版本/内核/ASLR 状态、工具版本、失败路线。
- **停止条件**：同形失败 2 次或连续无新增证据 → 重判并换路线；确定性密码学按回代/反例验收，不套 10 次利用稳定性统计。
- **机检**：`python Tool/scripts/domain-gate.py --domain pwn-crypto` 仅校验工作台能力/仓内案例，不能代替当前任务验收；
  案例级再跑 `pwn-accept.py --root . --json`（字段/哈希/真跑/refs/保护位一致性）。

> 边界再强调：本技能只用于授权实验室资产；不伪造“稳定 9/10”，不隐藏失败，
> 不把本地关 ASLR 的结果当远程结论，不把 PE 当 ELF 套保护位术语。

## 子技能（按需读，不常驻）

本域相关子技能放在 `Tool/skill/_pending/`（不占常驻上下文，需要时再读）：

- `Tool/skill/_pending/00-triage/SKILL.md` —— 先出二进制保护与靶场画像
