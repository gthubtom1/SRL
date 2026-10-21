# pwn-crypto 知识库看板

> 域：二进制利用 / 密码学攻击。入口技能：`Tool/skill/pwn-crypto/SKILL.md`。
> 只收录**可复现**的路线与判据；靶场/CTF/自有 ELF 服务以外不使用。

## 1. 九件套导航

| 件 | 位置 | 用途 |
|---|---|---|
| 技能 | `Tool/skill/pwn-crypto/SKILL.md` | 判据/失败判据/边界/验收 |
| 参考 1 | `Tool/skill/pwn-crypto/references/binary-exploitation.md` | ret2libc/fmt/堆/ORW 骨架 |
| 参考 2 | `Tool/skill/pwn-crypto/references/crypto-attacks.md` | RSA/ECB/CBC/PRNG/签名 |
| 参考 3 | `Tool/skill/pwn-crypto/references/heap-and-sandbox.md` | tcache/UAF/IO_FILE/seccomp |
| 参考 4 | `Tool/skill/pwn-crypto/references/mitigation-matrix.md` | 保护位×手法×判据 |
| 脚本 | `Tool/scripts/pwn-check.py` | 保护位/危险导入/fmt 风险/路线预判 |
| 矩阵 | `Tool/config/pwn-crypto-matrix.json` | 17 类判据与误报风险 |
| 案例 | `Tool/cases/pwn-crypto01/`、`pwn-crypto02/` | 堆 UAF、RSA 计划案例 |
| 路由 | R21（已存在，`routing-fragments/pwn-crypto.json`） | 二进制利用/密码学攻击 |

## 2. 快速决策

```text
pwn-check.py --file ./chall
  ├─ NX off ──────────► shellcode
  ├─ fmt 高风险 ──────► 格式化串（先泄漏/写 GOT）
  ├─ 堆语义 ──────────► tcache/UAF（先 heap 再 libc）
  ├─ 溢出 ────────────► ROP/ret2libc（canary/PIE 先泄漏）
  └─ seccomp ─────────► ORW/openat/mprotect
```

## 3. 两篇速查

- [heap-tcache-playbook.md](heap-tcache-playbook.md)：版本差异、泄漏顺序、poison、IO_FILE。
- [crypto-oracle-playbook.md](crypto-oracle-playbook.md)：RSA 四类、ECB/CBC、PRNG、回代判据。

## 4. 验收底线

- 本地全新进程连续 10 次成功 ≥9；远程有 flag/root 证据。
- 每条结论有 `sha256 + checksec + libc build id + 调试器/泄漏证据`。
- 失败路线必须记录；同一路径 3 轮无进展即换路线。
- 不把“本地关 ASLR”的结果当远程结论；不伪造稳定性。

## 5. 边界

- 纯静态算法还原 → `ida-reverse` / `reverse-engineering`。
- Android APK/DEX/SO、Frida/脱壳 → `apkseep`。
- Web/许可/JWT → 对应 Web/许可技能。
- 仅授权实验室资产；禁止未授权目标、持久化、横向、拒绝服务、真实凭据滥用。
