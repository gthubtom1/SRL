# crypto-attacks.md — 可运行骨架与判据

> 先写清假设：有没有填充、是否同一消息、模数是否互质、oracle 返回什么。
> 每个脚本最后都要做“回代验证”，不要把“看起来像 flag”当成功。


**适用**：本文件给 RSA/分组/PRNG/证书的可运行求解骨架，并要求每条结论都做数学回代。
**不适用**：纯协议实现审计（不求解）、需要侧信道的在线 oracle 但无授权、真实生产凭据/证书。
## 0. 环境

```bash
pip install pycryptodome gmpy2 z3-solver randcrack
python3 -c "import Crypto, gmpy2; print('ok')"
# sage 只在格攻击/Coppersmith 时需要；没有 sage 先用 z3/数学推导降级。
```

**判据**：`long_to_bytes`/`bytes_to_long` 可逆；大整数运算不丢精度；记录 Python 与库版本。

## 1. RSA 公共工具

```python
from math import gcd, isqrt
from Crypto.Util.number import long_to_bytes, inverse
def iroot(n, k):
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            return x
        x = y
def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y
def crt(rs, ms):
    M = 1
    for m in ms:
        M *= m
    x = 0
    for r, m in zip(rs, ms):
        Mi = M // m
        x = (x + r * Mi * inverse(Mi, m)) % M
    return x, M
```

**判据**：`iroot(m**3, 3) == m`；`crt` 结果对每个模数取余等于输入。

## 2. RSA 四类主攻

### 2.1 小指数无填充

```python
m = iroot(c, e)
assert pow(m, e, n) == c, "开方不精确：可能有填充或 m^e >= n"
print(long_to_bytes(m))
```

**判据**：`pow(m,e,n)==c` 且明文可打印；不精确就不要再猜，转共模/广播/填充分析。

### 2.2 共模攻击

```python
def common_modulus(c1, e1, c2, e2, n):
    g, a, b = egcd(e1, e2)
    assert g == 1, "e1/e2 不互质，需先约简"
    if a < 0:
        c1, a = inverse(c1, n), -a
    if b < 0:
        c2, b = inverse(c2, n), -b
    return (pow(c1, a, n) * pow(c2, b, n)) % n

m = common_modulus(c1, e1, c2, e2, n)
assert pow(m, e1, n) == c1 and pow(m, e2, n) == c2
```

**判据**：同一 `n`、同一 `m`、`gcd(e1,e2)=1`，且两个回代都成立。

### 2.3 低加密指数广播（Håstad）

```python
# 同一 m，e=3，至少 3 组互质 n；先 CRT 再开 e 次方。
x, M = crt(cs, ns)
m = iroot(x, e)
assert pow(m, e, M) == x, "CRT 后仍不精确：检查 m^e < M 与消息是否同一"
print(long_to_bytes(m))
```

**判据**：模数两两互质、组数 ≥ e、`m^e < M`；否则先补组或改走相关消息攻击。

### 2.4 分解与弱私钥

```python
# 共享素数
p = gcd(n1, n2)
assert 1 < p < n1 and n1 % p == 0

# Fermat：p、q 很接近
def fermat(n):
    a = isqrt(n) + (isqrt(n) ** 2 < n)
    while True:
        b = isqrt(a * a - n)
        if b * b == a * a - n:
            return a - b, a + b
        a += 1

# Wiener（小 d）：连分数展开 e/n，检查收敛分母 k/d。
# 也可用 sage: attack 或现成 wiener 脚本；不要手算大数连分数不验证。
```

**判据**：`p*q==n`；私钥解出的 `m` 回代 `pow(m,e,n)==c`。Wiener 还要满足 `d < n^0.25/3`。

## 3. ECB 块攻击

```python
def ecb_detect(oracle, block=16):
    ct = oracle(b"A" * (block * 4))
    blocks = [ct[i:i+block] for i in range(0, len(ct), block)]
    return len(blocks) != len(set(blocks))   # 有重复块 = 可能 ECB
def ecb_byte_at_a_time(oracle, block=16, max_len=512):
    base = len(oracle(b""))
    n = base
    for i in range(1, block + 1):
        if len(oracle(b"A" * i)) != base:
            n = base - i
            break
    known = b""
    for _ in range(n):
        pad = b"A" * (block - 1 - (len(known) % block))
        idx = (len(pad) + len(known)) // block
        target = oracle(pad + known)[idx*block:(idx+1)*block]
        table = {oracle(pad + known + bytes([b]))[idx*block:(idx+1)*block]: b
                 for b in range(256)}
        known += bytes([table[target]])
    return known
```

**判据**：恢复的字节可打印且包含 `flag{`；末尾用同前缀重新加密，密文块与 oracle 一致。
**cut-and-paste**：把 `role=user` 的整块替换成 `role=admin` 块，服务端按块解析即成立。

## 4. CBC 位翻转与 padding oracle

```python
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
# P[i] = D(C[i]) xor C[i-1]；想让 P[i] 翻转 delta，就改 C[i-1]。
ct = bytearray(ct); i = 2   # 目标块号（1 起）；第一块改 IV
delta = xor(b"user", b"admin")
ct[(i-1)*16:i*16] = xor(bytes(ct[(i-1)*16:i*16]), delta.ljust(16, b"\x00"))
# 第一块：iv = xor(iv, delta)
```

**判据**：解密后目标字段变为期望值，且 padding/格式校验通过；CBC 无 MAC 才可改。
**padding oracle**：只根据“padding 是否合法”的侧信道逐字节恢复，先固定最后一字节为 `0x01`，再递推。

## 5. PRNG 预测

```python
from randcrack import RandCrack
rc = RandCrack()
for x in outputs[:624]:       # 必须是连续 32-bit 输出
    rc.submit(x)
print(rc.predict_getrandbits(32))
# C rand()/LCG：由连续输出解 a,c,m，或按 time(NULL) 附近暴力种子。
# Java Random：48-bit 状态；连续两个 nextInt 可推，注意高位丢弃。
```

**判据**：预测的下一个/下一段输出与真实值逐位一致；先确认没有额外的 `randint`/`randrange` 消耗。

## 6. 证书与签名

```bash
openssl x509 -in cert.pem -text -noout
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -text -noout
openssl verify -CAfile ca.pem cert.pem
openssl dgst -sha256 -verify pub.pem -signature sig.bin msg.bin
```

```python
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
cert = x509.load_pem_x509_certificate(open("cert.pem", "rb").read())
cert.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())  # None=通过
```

**判据**：目标验证器接受伪造签名/证书（实验室自建 CA），且 `openssl verify` 或程序返回成功。
**弱情形**：`e=1`（签名即消息）、`e=3` 且无填充且消息可开方、DER 解析差异、弱哈希；先确认验签代码实际用了哪种 padding。

## 7. JWT 攻击面

> 前提：有授权的测试 token 或自有账号。只认服务端接受与否，前端能解码不算数。

```bash
# 拆三段，记录 header/payload 原文与签名长度
python - <<'PY'
import base64, json, sys
t = sys.argv[1] if len(sys.argv) > 1 else open('token.txt').read().strip()
h, p, s = t.split('.')
pad = lambda x: x + '=' * (-len(x) % 4)
print(json.loads(base64.urlsafe_b64decode(pad(h))))
print(json.loads(base64.urlsafe_b64decode(pad(p))))
PY
```

- `alg:none`：把 header 改成 `{"alg":"none","typ":"JWT"}`，签名段分别试留空、保留原签名、`AA==`；有的实现只查大小写/空白。
- HS256↔RS256 混淆：服务端用 RSA 公钥验 `RS256` 时，把 `alg` 改成 `HS256`，用**同一公钥字节**当 HMAC 密钥重签。公钥可能是 PEM、DER 或 JWKS 的 `n/e`，逐种表示试；`n/e` 先做 **base64url 解码并去掉 `=` padding**，不要直接拿字符串当 key。
- 弱密钥：`hashcat -m 16500 jwt.txt wordlist.txt`（或 `john --format=HMAC-SHA256`）；命中后必须本地重算 `HMAC-SHA256(secret, header.payload)` 等于原签名。
- `kid` 注入：试 `../../../../dev/null`、`/proc/self/environ`、已知可控文件、SQL/命令拼接；`kid` 指向可控内容时用该内容当密钥。
- `jku`/`x5u`：指向自建 HTTPS JWKS/证书（仅实验室），确认服务端是否真的拉取并信任；同时试 `http`、内网地址、重定向与缓存。
- claim 语义：改 `sub`/`role`/`scope`/`tenant`/`exp`/`nbf`；过期 token 仍被接受、`role=admin` 能读管理接口才算成立。

```python
import base64, hmac, hashlib
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=')
sign = lambda key, msg: b64u(hmac.new(key, msg, hashlib.sha256).digest())
# key 必须是服务端实际使用的那串字节：PEM/DER/原始 n，不是“看起来像公钥”的 base64 文本
```

**判据**：改后的 token 被服务端接受（`jwt_accepted=true`），且能读到未授权前读不到的数据或执行未授权动作（`protected_resource=true`）；留存原/改 token 的 header+payload diff、请求与响应码。
**失败判据**：只有前端 `atob`/控制台解码成功、页面显示变了，但服务端返回 401/403；或只在 `jwt.io` 显示签名通过。此时写 `jwt_accepted=false`，不要写“JWT 可伪造”。

## 8. 判据汇总

| 攻击 | 成立判据 | 失败先查 |
|---|---|---|
| RSA 小指数 | `pow(m,e,n)==c`，明文可读 | 是否有 PKCS#1 填充；`m^e` 是否超过 `n` |
| RSA 共模 | 两个回代都成立 | `e1/e2` 是否互质；是否同一 `m` |
| RSA 广播 | CRT 后开方精确，组数 ≥ e | 模数是否互质；消息是否同一 |
| RSA 分解 | `p*q==n`，私钥回代成立 | `gcd` 是否为 1；Wiener 条件是否满足 |
| ECB | 重复块稳定；逐字节恢复含 flag | 是否 CBC/随机 IV；块大小是否 16 |
| CBC | 目标块翻转成功且校验通过 | 块索引/IV 是否改对；是否有 MAC |
| PRNG | 下一输出逐位一致 | 是否多消耗随机数；输出是否连续 |
| 证书/签名 | 目标验签成功，证据可复现 | padding/哈希算法；信任链是否真的被使用 |
| JWT | 服务端接受改后 token 且读到非公开数据（`jwt_accepted=true`） | 只前端解码/401；公钥字节表示或 base64url padding 不对 |

**总验收**：脚本可重跑；每条攻击都有数学回代或逐位比对；失败路线写清假设被哪一步推翻。

## 9. 域边界：EVM/智能合约不做

本域**不提供 EVM 运行时**，也不连接链上环境：没有 anvil/hardhat/foundry 节点、没有交易回放、没有状态快照，因此无法给出“交易成功且状态被改变”的证据。

- 合约整数/重入/权限、Foundry 断言、链上交易哈希 → 不在本域边界内，不写 `confirmed`。
- DApp 的 API/签名服务/后端鉴权 → 改走 `web-pentest` 的 API 面；
- 必须审合约字节码/不变量 → 走外部智能合约审计流程（独立工具链与授权）。
- 在 `scope.md` 记 `evm_runtime=false`、`out_of_scope=true`，并写明转交路径。

**判据**：报告不出现“本域已验证链上状态”；出现即判越界。

## 失败判据（本文件）

- 只抄骨架里的偏移/gadget，不用目标环境复核 → 本文件被误用，结论降级为“疑似”。
- 没有泄漏/回代/写后读回等最小证据就宣布成功 → 不成立。
- 平台语义混用（PE 的 DllCharacteristics 当 ELF RELRO、UCRT 当 glibc）→ 判路线错误。

## 边界

- 文中的命令与偏移是示例，必须用目标二进制、目标 libc/运行库重新生成。
- 仅用于授权实验室资产；不覆盖真实生产系统、持久化、横向移动或拒绝服务。
