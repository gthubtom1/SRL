# Pwn & Crypto 知识库 — 二进制利用与密码学

> Board：`pwn-crypto`。配套技能：`Tool/skill/pwn-crypto/SKILL.md`。
> 只收“保护位可复核、泄漏可重复、命中可统计”的利用/求解方法；一次偶然成功不算结论。

## 这个板卡管什么

- 授权 CTF/靶场中的 ELF 栈溢出、ROP/ret2libc、格式化字符串、堆（tcache/UAF/IO_FILE）、
  整数/off-by-one、seccomp 沙箱逃逸（ORW/SROP）。
- 密码学原语的**可验证求解**：RSA、ECB/CBC、PRNG、证书/签名。判据与脚本在
  `Tool/skill/pwn-crypto/references/crypto-attacks.md`，本板暂未单列密码学页。
- 不负责：纯静态算法还原（`ida-reverse`）、Android APK/SO（`apkseep`）、
  Web/API 与业务逻辑（`web-pentest`）。

当前技术页：

- [01 栈溢出与 ROP](techniques/01-stack-rop.md)
- [02 堆与沙箱](techniques/02-heap-and-sandbox.md)

## 怎么用

1. 先留基线，只读、不执行目标：

```bash
sha256sum ./chall ./libc.so.6 2>/dev/null | tee evidence/SHA256SUMS
file ./chall
python Tool/scripts/pwn-check.py --file ./chall --json
pwn checksec ./chall
readelf -lW ./chall | grep GNU_STACK
readelf -d ./chall | grep -E 'BIND_NOW|RPATH|RUNPATH|NEEDED'
```

2. 按信号选页：

| 信号 | 先读 |
|---|---|
| `No canary` / `NX enabled` / `PIE` / `Partial RELRO` | `01-stack-rop.md` |
| 菜单有 add/free/edit/show、glibc 版本敏感 | `02-heap-and-sandbox.md` |
| `seccomp-tools dump` 有白名单、无 `execve` | `02-heap-and-sandbox.md` 第 3 节 |
| RSA/ECB/CBC/PRNG/证书 | 技能 `references/crypto-attacks.md` |

3. 每篇先跑通“泄漏”，再拼“写入/跳转”；偏移和 libc 符号必须用当前样本与调试器复核，
   不抄别题数字。工具缺失时按技能第 5 节降级（`readelf` 代替 `checksec`、
   `objdump` 代替 `ROPgadget`），版本差异按本机版本核对。

4. 验收线：全新进程/新连接连续跑 ≥10 次，成功 ≥9 次；保留命令、退出码、
   checksec、glibc build id、泄漏计算过程与 flag/root 输出。

## 和哪个技能配合

| 场景 | 技能路径 |
|---|---|
| 主流程、判据、验收与边界 | `Tool/skill/pwn-crypto/SKILL.md` |
| 静态定位漏洞函数、恢复符号 | `Tool/skill/ida-reverse/SKILL.md` |
| 补丁前后/两版二进制差异 | `Tool/skill/binary-diff/SKILL.md` |
| Android native / APK 层 | `Tool/skill/apkseep/SKILL.md` |
| Web/API 或客户端授权逻辑 | `Tool/skill/web-pentest/SKILL.md` |

## 边界

- 仅限自有或明确授权的靶场/服务；禁止未授权目标、持久化、横向移动、拒绝服务。
- 本地关闭 ASLR 的结果不能当远程结论；远程必须重新泄漏。
- 失败也要交付：写清已排除路线（如 Full RELRO + 无泄漏时 GOT 路线不可行）。
