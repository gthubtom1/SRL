# Pwn & Crypto 知识库 — 二进制利用与密码学

> Board：`pwn-crypto`。配套技能：`Tool/skill/pwn-crypto/SKILL.md`，判据表在
> `Tool/skill/pwn-crypto/references/01-criteria.md`。只收“保护位可复核、偏移可对齐、回代可成立”的方法；
> 一次偶然成功不算结论。

## 入口信号（先判断值不值得打）

- 有可控输入面：`gets/strcpy/read`、`printf(buf)`、菜单式 malloc/free、长度/数量由输入决定；
- 有可观测控制对象：返回地址、GOT/函数指针、堆元数据、认证变量、密码学参数；
- 有可复现的本地运行方式：能编译/启动/断点，或能拿到同版本 libc/运行库。

三者缺一，先补基线（`sha256`、保护位、输入点），不要直接写 exploit。

## 分析链（固定顺序）

1. **定平台与保护位**：`python Tool/scripts/pwn-check.py --file ./chall --json`；
   ELF 再用 `readelf -lW/-dW` 复核，PE 用 `objdump -p` 看 `DllCharacteristics`。
2. **定输入面**：找到可控缓冲区/格式串/长度字段；记录参数位置或分配/释放序列。
3. **定偏移/布局**：栈用 `pwn-repro.py --objdump ... --probe-log ...` 两源对齐；
   堆先定 glibc 版本，再排 tcache/UAF/IO。
4. **拿最小证据**：泄漏（`%s`、`%p`、堆 fd）、写后读回、marker 跳转、`pow(m,e,n)==c`。
5. **做稳定性**：全新进程/连接 ≥10 次，成功 ≥9 次；否则写“现象 + 失败路线”。

## 三条硬判据

1. **偏移一致**：objdump 位移与运行时 `frame-buf+8` 相同（`consistent=true`），否则不写 payload。
2. **控制/回代成立**：看到 marker 输出，或 `pow(m,e,n)==c` / 逐位比对通过；只有“崩了”不算。
3. **证据可重跑**：命令、退出码、原始输出、sha256 齐全；缺一项即降级为“疑似”。

## 失败判据（先看这一节）

| 现象 | 判定 | 改走 |
|---|---|---|
| 两源偏移不一致 | 偏移不可信 | 统一编译选项/帧指针，gdb 复核 |
| `%n` 探针不写 | 运行库禁用 | 只做任意读；写路线转堆/逻辑/换平台 |
| 全保护 + 无泄漏 | 栈/GOT 封死 | 格式化串/堆/密码学/逻辑 |
| `malloc` 不返回 target | 版本/布局不符 | 定 glibc；safe-linking；IO/exit |
| `pow(m,e,n)!=c` | 假设错误 | 查填充/同一 m/互质；换攻击面 |

完整表：`techniques/06-failure-criteria-playbook.md`；技能侧：`references/02-failure-criteria.md`。

## 邻域边界

- 纯静态算法还原/协议测绘 → `ida-reverse` / `reverse-engineering`；
- Android APK/DEX/SO、Frida/脱壳 → `apkseep`；
- Web/API/JWT 业务逻辑 → `web-pentest` / 对应 Web 技能；
- 本板只处理**二进制内存破坏 + 密码学原语求解**，且仅限授权实验室资产。

## 技术页（逐篇）

- [01 栈溢出与 ROP](techniques/01-stack-rop.md) — checksec 路线、cyclic 偏移、ret2libc、栈对齐、10 次统计。
- [02 堆与沙箱](techniques/02-heap-and-sandbox.md) — glibc 版本、tcache/UAF、IO_FILE、seccomp ORW。
- [03 格式化串任意读](techniques/03-format-string-arbitrary-read.md) — 参数位置、`%s` 解引用、UCRT 下 `%n` 不写的边界。
- [04 libc 版本与 ORW](techniques/04-libc-version-and-orw.md) — build id、泄漏校验、gadget 顺序、seccomp 白名单。
- [05 PE 保护位与 Windows 利用面](techniques/05-pe-mitigation-windows.md) — DllCharacteristics、GS/CFG、PE 与 ELF 的语义差异。
- [06 失败判据速查](techniques/06-failure-criteria-playbook.md) — 现象→判定→改走→代价，停机规则。
- [x 密码学 oracle 速查](techniques/07-crypto-oracle-playbook.md) — RSA/ECB/CBC/PRNG/证书的假设与回代。
- [x 堆 tcache/UAF 速查](techniques/08-heap-tcache-playbook.md) — 2.26–2.35+ 的版本差异与 poison 步骤。
- [2026 glibc 2.34+ FSOP 战例](techniques/2026-glibc234-fsop.md) — `__free_hook` 移除后的 IO vtable / `__exit_funcs` 判据。

## 常用命令

```bash
python Tool/scripts/pwn-check.py --file ./chall --json          # 静态预判
python Tool/skill/pwn-crypto/scripts/pwn-repro.py --objdump d.txt --func vuln --probe-log p.txt
python Tool/skill/pwn-crypto/scripts/crypto-verify.py --self-test
python Tool/skill/pwn-crypto/scripts/crypto-verify.py --rsa inputs/rsa.json
python Tool/scripts/domain-gate.py --domain pwn-crypto          # 本域机检
```

## 真实案例入口

- `Tool/cases/pwn-crypto03`：现场编译 PE，栈溢出 offset=88、marker 跳转、整数回绕导致
  `0xC0000374` 堆破坏。
- `Tool/cases/pwn-crypto04`：真实 RSA/Håstad/HMAC/MT19937/AES-ECB/AES-CBC 回代。
- `Tool/cases/pwn-crypto05`：格式化串任意读泄漏 secret，并证明 UCRT `%n` 不写。
- `Tool/cases/pwn-crypto01` / `02`：真实 PE 样本的保护位与危险导入静态预判。
