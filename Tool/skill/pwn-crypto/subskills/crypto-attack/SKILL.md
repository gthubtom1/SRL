---
name: crypto-attack
description: "应用密码学识别与弱参数验证；明确 ECB/CBC、RSA、PRNG 前提，以合成向量、回代和反例区分线索与证明。"
metadata:
  version: "2.1.0"
  target_runtimes: "Applied cryptography；离线数学与受控测试 oracle"
---

# 应用密码学条件与验证

输入是公开/合成参数、已获准的非敏感明密文对、算法调用点与明确问题。真实 Key、Salt、私钥、Token 和用户秘密不读取、不打印、不落盘；需真实凭据时用户自行操作，只返回安全验证结果。公开 RSA n/e、证书公钥不等于私钥，记录身份与来源即可。

复用 [深度密码学方法](../../references/crypto-attacks.md)、[判据](../../references/01-criteria.md)，先核前提再用其中骨架。已有 `../../scripts/crypto-verify.py` 提供 rsa/broadcast/hmac/mt/ecb/cbc 回代；先 `--help` 并核源文件的输入字段，`verified` 只说明该模式的具体断言，不证明攻击条件全部成立。

## 识别不等于破解

AES S-box、MD5/SHA 常量、RC4 的 256 元素初始化只是线索，库表、死代码与相似算法可能同现。追调用路径、输入编码、模式、padding、nonce/IV、认证标签、KDF 与错误处理。16/24/32 字节数组可能是常量或公钥片段，不能直接判真实 AES 密钥。压缩/编码与加密分开，高熵不证明加密。

| 路线 | 必须核实的条件 | 正向证明 | 反例/失败边界 |
|---|---|---|---|
| ECB 图案与逐字节测试 | 块大小/对齐、同密钥、确定性 oracle；字节恢复还需稳定的 `prefix || controlled || suffix` 结构与可控输入 | 多个自选重复块呈对应映射，保留输入变化控制组；恢复结果用独立向量验证 | 重传、重复记录、零填充也产生重复字节；随机前缀/密钥或无可控输入时不能套逐字节法 |
| CBC 位翻转 | 前一块/IV 可改、目标明文布局已知、等长替换、无先行认证阻断 | 目标字节按 XOR 差变化，接受条件另验 | `user` 与 `admin` 长度不同，不能直接 XOR 替换；前一明文块可能损坏，AEAD/Encrypt-then-MAC 可先拒绝 |
| Padding oracle | 可区分填充合法性、可提交变体、CBC 块与 IV 对齐、查询预算允许且噪声可控 | 合成夹具恢复已知明文；候选用第二扰动排除原有合法 padding 等假阳性 | 统一错误、认证先拒、限流/时间噪声则受阻；基线 padding 合法很正常，不必先强制基线无效 |
| RSA 小指数 | 教科书 RSA，同整数 m，`m**e < n`，无随机 padding | 精确整数根 `root**e == c` 且每组 `pow(root,e,n)==c` | e=3 单独不足；OAEP/不同编码不满足同消息 |
| RSA 广播 | 同 e/同 m，模数两两互质，CRT 后 `m**e < product(n)`；通常至少 e 组 | 根必须满足 `root**e == CRT_value`，再对每组回代 | 只做模 product 的回代不能证明精确根；gcd>1 应先分析共享因子；随机填充破坏同 m |
| LCG / Java Random | 已知 recurrence、模数/输出变换、连续顺序与消耗情况；若参数未知需足够独立方程 | 用一段求候选，保留未参与求解的后续输出逐项预测 | 差值不可逆、截断、跳步、多解时 2–3 个输出不保证恢复；C rand 实现不统一 |
| MT19937 | 对应实现的连续完整 32 位输出、状态顺序、无未知消耗 | 典型 clone 用 624 个输出建状态，再预测留出段 | 浮点/截断输出或 CSPRNG 不套此数量；恢复状态也不等于任意 Token 生成链已知 |

## 可复算的合成例子

以下只验证小整数数学前提，不处理真实凭据：

```python
from math import gcd, prod
m, e = 5, 3
ns = [101, 103, 107]
assert all(gcd(a, b) == 1 for i, a in enumerate(ns) for b in ns[i+1:])
cs = [pow(m, e, n) for n in ns]
M = prod(ns)
x = sum(c * (M // n) * pow(M // n, -1, n) for c, n in zip(cs, ns)) % M
assert m ** e < M and m ** e == x
assert all(pow(m, e, n) == c for n, c in zip(ns, cs))
# 反例：不同消息不再满足同 m 的广播前提。
changed = cs[:]
changed[1] = pow(m + 1, e, ns[1])
assert not all(pow(m, e, n) == c for n, c in zip(ns, changed))
```

Python 3.8+ 支持 `pow(a,-1,n)`，这里不依赖浮点根。HMAC 不受普通前缀 MAC 的长度扩展影响；CBC IV 重用泄露与 padding oracle 是不同问题。安全实现可能只能确认机制与排除某路线，不能强求恢复明文。

## 交付与停止

每条结论列前提、公开/合成输入来源、代码位置、工具版本、回代、控制组和未解决假设；不得用可打印/含 flag 作为正确性的必要判据。在线 oracle 的动作与预算必须属于当前 scope，限流或无法判别就停。两次同形失败重判而非硬换参数。

协议封装请 protocol-plugin、算法调用链请 softseep/apkseep、JWT 服务端验证请 web-pentest；问题和安全结果返回同一 project/version/run。离线数学完成不需要套利用链 10 次成功率，也不自动证明真实目标可利用。
