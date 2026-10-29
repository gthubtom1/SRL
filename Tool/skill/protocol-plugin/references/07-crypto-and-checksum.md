# 07 加密段与校验 — 先证伪"像 AES"，再谈解明文

> 范围：帧尾/帧头有校验字段、载荷熵高、长度按 8/16 对齐、可能有压缩或加密的私有协议。
> 路由：TLS 握手本身的分析见 `tshark -Y tls` + `04-walkthrough`；插件装载链按 `Tool/playbooks/plugin-analysis.md` 分析。
> 分帧见 `05-binary-framing.md`；重放见 `08-replay-and-new-request.md`。

## 1. 判断顺序（不要跳步）

```text
有明文头？──是──> 头部明文 + 载荷密文：先定加密起点与长度关系
    │
    否
    ↓
熵高？──是──> 先排压缩（魔数/Content-Encoding/解压后长度）
    │            再排编码（base64/hex/URL 编码）
    否           最后才是加密
    ↓
块长 8/16 的倍数？──是──> 分组加密或块填充
    │
    否
    ↓
逐帧有 8/12/16 字节随机前缀？──是──> nonce/IV/salt
```

**"看起来像 AES"不是证据**。真正能定族的证据只有两类：
已知明文-密文对（能验证算法/模式/IV），或客户端内取到明文（不再需要猜）。

## 2. 压缩 vs 编码 vs 加密

| 信号 | 更可能是 | 验证方法 |
|---|---|---|
| 开头 `1f 8b` | gzip | `python -c "import gzip;print(gzip.decompress(...)[:64])"` |
| 开头 `78 01/9c/da` | zlib | `zlib.decompress` |
| 开头 `28 b5 2f fd` | zstd | `zstd -d` 或 python-zstandard |
| 全 ASCII 且长度是 4 的倍数、结尾 `=` | base64 | 解码后看是否出现魔数/JSON |
| 全 hex 字符 | hex 编码 | `bytes.fromhex` |
| `%xx` 密集 | URL 编码 | `urllib.parse.unquote` |
| 长度为 16 的倍数 | 分组模式候选 | 见 §3；填充只能在解密后检查 |
| 长度与明文等长，无填充 | 流加密/CTR/异或 | 见 §3 |

```bash
python - <<'PY'
import collections, math, gzip, zlib
b = open('payload.bin','rb').read()
c = collections.Counter(b); n = len(b)
print('len', n, 'entropy', round(-sum(v/n*math.log2(v/n) for v in c.values()), 3))
print('head', b[:32].hex())
for name, fn in (('gzip', gzip.decompress), ('zlib', zlib.decompress)):
    try:
        print(name, 'ok', len(fn(b)), fn(b)[:48])
    except Exception as e:
        print(name, 'no', type(e).__name__)
PY
```

熵参考：英文/JSON ≈ 4.0–4.7；base64 ≈ 6.0；压缩后 ≈ 7.9；加密 ≈ 7.95–8.0。
**压缩和加密的熵几乎一样**，所以必须靠"能否解压"区分，不能靠熵。

## 2.1 私有加密识别的四张特征表（先对表，再写代码）

| 家族 | 长度特征 | 结构特征 | 常量/指纹 | 判定所需证据 |
|---|---|---|---|---|
| 重复异或 | 与明文等长，无填充 | 每隔 k 字节出现规律；同位置字节差异稳定 | 无固定常量 | 已知明文 crib 能解出周期 k，且解密后可解析 |
| RC4（含 drop-n） | 与明文等长，无填充 | 每帧独立或全局续流；无块对齐 | 无常量；有统计偏差 | 候选 key 下 `rc4(key,ct)` 的 crib 位置匹配 |
| AES（ECB/CBC/CTR） | 16 的倍数（ECB/CBC），或与明文等长（CTR） | ECB 有重复块；CBC 首块随机；CTR 每帧带 nonce | S-box `637c777bf26b6fc5`、Rcon `01020408…` | 重复块或 `P[i]=D(C[i])^C[i-1]` 成立 |
| TEA/XTEA/SM4 | 8/16 字节块 | 32 轮结构，输入被切成 2/4 个 word | TEA `0x9E3779B9`、SM4 S-box `d690e9fe…` | 常量命中 + 已知明文回代 |

判据边界：**常量命中只是"疑似"**，必须再做一次"已知明文 → 密文"回代；没有明文对就写到"疑似"为止。

扫描客户端里的算法常量（纯标准库，不依赖 grep -P）：

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
python - <<'PY'
import pathlib
blob = pathlib.Path("client.bin").read_bytes()
sigs = {
    "aes_sbox":      bytes.fromhex("637c777bf26b6fc5"),
    "aes_rcon_tail": bytes.fromhex("01020408102040801b36"),
    "tea_delta_be":  (0x9E3779B9).to_bytes(4, "big"),
    "tea_delta_le":  (0x9E3779B9).to_bytes(4, "little"),
    "sm4_sbox":      bytes.fromhex("d690e9fecce13db7"),
    "chacha_sigma":  b"expand 32-byte k",
}
for name, sig in sigs.items():
    off = blob.find(sig)
    print(name, hex(off) if off >= 0 else "not found")
PY
```

通过长什么样：

```text
aes_sbox 0x1a2b40
aes_rcon_tail not found
tea_delta_be not found
tea_delta_le 0x2c110
sm4_sbox not found
chacha_sigma not found
```

读法：命中 `tea_delta_le` → 优先按小端 XTEA 试；`aes_sbox` 命中但找不到 Rcon 可能是静态表被拆开/混淆。
**没命中不等于没有**（常量可能被编码或运行时生成），只说明"这条线索断了"。

## 2.2 重复异或：候选周期与已知明文

```bash
python - <<'PY'
import pathlib
data = pathlib.Path("artifacts/payload.bin").read_bytes()
def score(k):
    blocks = [data[i:i+k] for i in range(0, min(len(data), k*10), k)]
    blocks = [b for b in blocks if len(b) == k]
    if len(blocks) < 3:
        return float("inf")
    ds = [sum((a ^ b).bit_count() for a, b in zip(x, y)) / k
          for x, y in zip(blocks, blocks[1:])]
    return sum(ds) / len(ds)
best = sorted(range(1, 41), key=score)[:3]
print("候选", best, "scores", [round(score(k), 2) for k in best])
crib = b'{"type":"request"'
for k in best:
    if len(data) < k or len(crib) < k:
        print("候选", k, "已知明文不足，不能推导完整周期")
        continue
    key = bytes(data[i] ^ crib[i] for i in range(k))
    plain = bytes(b ^ key[i % k] for i, b in enumerate(data))
    print("候选", k, "head", repr(plain[:40]))
PY
```

分数及可读头部只提供候选；倍数关系不能独立证明周期。验证需检查完整结构、回代并用独立已知明文样本交叉验证；已知明文不够覆盖候选周期时不能声称得到完整密钥。

## 2.3 RC4：等长 + 无填充 + crib 回代

```bash
python - <<'PY'
def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)
import pathlib
ct = pathlib.Path("artifacts/payload.bin").read_bytes()
for key in (b"secret", b"key12345", bytes.fromhex("0011223344556677")):
    pt = rc4(key, ct)
    print(key, "len_equal", len(pt) == len(ct), "head", pt[:16])
PY
```

通过长什么样（命中时头部是可解析结构）：

```text
b'secret' len_equal True head b'\x9a\x13\xfe...'
b'key12345' len_equal True head b'{"cmd":"ping"'
00 11 22 33 44 55 66 77 len_equal True head b'\x04\x00\x00\x00...'
```

判据：`head` 像 JSON/长度前缀/魔数只是线索；完整解析、已知明文回代和独立样本验证后才可提高置信度。
RC4 的统计偏差（第二字节偏 0x00、首 256 字节 0x00 偏多）只能当"疑似"线索，不能单独定族。

## 2.4 AES/分组：块对齐、重复块、PKCS#7、模式

```bash
python - <<'PY'
import pathlib
ct = pathlib.Path("artifacts/payload.bin").read_bytes()
blocks = [ct[i:i+16] for i in range(0, len(ct) - 15, 16)]
print("len", len(ct), "mod16", len(ct) % 16, "blocks", len(blocks), "dup", len(blocks) - len(set(blocks)))
print("first_block_hex", blocks[0].hex() if blocks else None)
PY
```

通过长什么样：

```text
len 96 mod16 0 blocks 6 dup 2
first_block_hex 3f9a1c07b8e2d451...
```

判读：

- `dup>=1` 且相同明文块能复现 → ECB 候选，需独立实验与回代。
- `dup==0` 且首块每帧不同只能提示 CBC/IV 候选，不能定模式；PKCS#7 必须在解密明文尾检查，不能直接检查密文尾。
- `dup==0` + `mod16!=0` + 长度与明文等长 → 流/CTR，找 8/12/16 B nonce。
- `len % 16 == 0` 本身无法判断填充或加密轮数；有明文后再检查尾部。

CTR nonce 重用的判定（两条密文异或等于两条明文异或）：

```bash
python - <<'PY'
import pathlib
a = pathlib.Path("artifacts/ct1.bin").read_bytes()
b = pathlib.Path("artifacts/ct2.bin").read_bytes()
x = bytes(p ^ q for p, q in zip(a, b))
print("xor_head", x[:32])
print("printable_ratio", sum(32 <= c < 127 for c in x) / max(1, len(x)))
PY
```

`printable_ratio` 明显高于随机的 ~0.37 → 明文相关，nonce 可能重用。这是"疑似"，
要拿到一条已知明文才能升级为"确认"。

## 3. 分组加密 vs 流加密

| 观察 | 分组（CBC/ECB） | 流/CTR | 结论 |
|---|---|---|---|
| 密文长度 | 16 的倍数（含 padding） | 与明文等长 | 分组更可能 |
| 相同明文块重复出现 | ECB 下密文块相同 | 不会 | 看到重复块 ≈ ECB |
| 逐帧前缀随机 | IV 在头部 | nonce/counter 在头部或隐式 | 需要定位前缀长度 |
| 翻转密文一位 | 影响整块 + 下一块（CBC） | 只影响对应位 | 用"位翻转扩散"判模式 |
| 两条明文 XOR = 两条密文 XOR | 否（有 IV） | 是（同 nonce 重用） | nonce 重用时 CTR 会露馅 |

实验设计（本地、已知明文）：

```python
# 位翻转扩散实验：改密文第 k 字节，看解密结果（或服务端错误）影响范围
for k in (0, 15, 16, 31):
    tampered = bytearray(ct)
    tampered[k] ^= 0x01
    # 发送/解密，记录受影响明文区间
```

- CBC：第 k 块损坏 + 下一块对应位翻转。
- CTR/流：只影响对应明文位，长度不变。
- 带 MAC/AEAD：整帧被拒（无法观察扩散），长度与疑似 tag 只能提供候选，不能单独确定模式。

## 3.1 位翻转扩散实验（判 CBC/CTR 的硬证据）

只在**本地副本**上做：改密文一位，用同一 key/iv 解密，看明文哪一段变化。

```bash
python - <<'PY'
from Crypto.Cipher import AES          # 仅本地、已知 key 的场景
key, iv, ct = b"0"*16, b"\x00"*16, bytes(range(48))
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
bad = bytearray(ct); bad[16] ^= 0x01     # 改第 2 块（index 16）
pt2 = AES.new(key, AES.MODE_CBC, iv).decrypt(bytes(bad))
diff = [i for i, (a, b) in enumerate(zip(pt, pt2)) if a != b]
print("changed_plain_offsets", diff)
PY
```

通过长什么样（CBC 改 `C[1]` → `P[1]` 整块乱、`P[2]` 对应位翻转）：

```text
changed_plain_offsets [16, 17, 18, ..., 31, 32]
```

`diff` 只落在 `[16,32)` 且长度不变 → 更像 CTR/流；`diff` 跨两个块 → CBC。
带 MAC/AEAD 时整帧被拒，观察不到扩散：长度和疑似 tag 仅供提出候选，别将其当模式结论。

## 4. 校验和：先覆盖范围，再算法参数

顺序不能反：**覆盖范围错了，算法再对也不算通过**。

| 步骤 | 做法 | 判据 |
|---|---|---|
| 1. 定位字段 | 找末尾/头部固定宽度字段，值在帧间变化 | 改载荷后该字段变化 |
| 2. 覆盖范围 | 分别试 `payload` / `header+payload` / `header+payload+len` | 只有一种对所有帧成立 |
| 3. 算法族 | 先试 sum/xor/Adler32，再试 CRC16/CRC32 | 至少 5 帧全部吻合 |
| 4. 参数 | 多项式/初值/异或/反射（`reveng` 可穷举） | 改 1 字节后能算出新的正确值 |
| 5. 负例 | 发一个错校验帧 | 服务端拒绝方式与模型一致 |

```bash
# 有 reveng 时穷举 CRC 参数
reveng -w 16 -s 3a4b 5c6d 7e8f 90a1
reveng -w 32 -s 01020304 05060708 090a0b0c
```

```python
import binascii
def crc32(b): return binascii.crc32(b) & 0xffffffff
def crc16_modbus(b):
    c = 0xFFFF
    for x in b:
        c ^= x
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c
def adler32(b):
    import zlib; return zlib.adler32(b) & 0xffffffff
```

`proto-repro.py` 的 schema 里 `tail[].covers` + `algo` 就是这一步的可执行版本；
`checks[].want/got` 直接把比对结果写进证据。

## 4.1 CRC 参数穷举（先覆盖范围，再参数）

```bash
# 有 reveng 时：用 ≥3 组 (message, crc) 直接反推 width/poly/init/refin/refout/xorout
reveng -w 16 -s 3a4b 5c6d 7e8f 90a1
reveng -w 32 -s 01020304 05060708 090a0b0c
# 没有 reveng：用 crcmod 枚举常见参数组合
python -c "import crcmod; print(crcmod.predefined._crc_definitions[:3])" 2>/dev/null || echo "no crcmod"
```

没有工具时先用已知向量验证一个明确参数集；以下只实现反射式 CRC-16/MODBUS，不是通用 CRC 参数穷举：

```bash
python - <<'PY'
def crc16_modbus(data):
    c = 0xffff
    for x in data:
        c ^= x
        for _ in range(8):
            c = (c >> 1) ^ 0xa001 if c & 1 else c >> 1
    return c & 0xffff
result = crc16_modbus(b"123456789")
print("crc", hex(result), "known_vector_ok", result == 0x4b37)
PY
```

`crc 0x4b37 known_vector_ok True` 只校验此实现；目标帧需另确定覆盖范围，并用多组独立样本和负例检验参数。

## 5. 夹具的校验复算（SPRX）

```bash
python Tool/skill/protocol-plugin/scripts/proto-repro.py \
  --input Tool/cases/protocol02/input/sample.bin --json | \
python -c "import json,sys;d=json.load(sys.stdin);[print(f['index'],f['checks']) for f in d['frames']]"
```

```text
0 [{'name': 'crc32', 'algo': 'crc32', 'ok': True, 'want': '0xe59f1d6e', 'got': '0xe59f1d6e', 'covers': 'header+payload'}]
1 [{'name': 'crc32', 'algo': 'crc32', 'ok': True, 'want': '0xb0542e66', 'got': '0xb0542e66', 'covers': 'header+payload'}]
2 [{'name': 'crc32', 'algo': 'crc32', 'ok': True, 'want': '0x0280ee21', 'got': '0x0280ee21', 'covers': 'header+payload'}]
```

注意：这只证明"该 3 帧自洽"，**不证明**真实流量也这样。
要升级到"确认"，需要真实抓包里 ≥5 帧 + 改字节负例（见 `01-criteria.md`）。

## 6. 取明文的四条路（按代价排序）

| 路径 | 前提 | 代价 | 失败信号 |
|---|---|---|---|
| `SSLKEYLOGFILE` | 客户端用 NSS/openssl/BoringSSL 且读环境变量 | 低 | 文件为空 / 目标忽略环境变量 |
| 代理装 CA | 能改客户端信任库 | 中 | pinning / mTLS |
| 进程内 hook `SSL_write/SSL_read` | 有调试权限 | 中高 | 反调试 / 完整性校验 |
| 序列化函数前后断点 | 有二进制 + 能定位函数 | 高 | 混淆/虚拟化 |

原则：**能在客户端内取明文，就不要爆破密钥**。密钥往往来自服务端协商（ECDHE），
爆破在数学上不可行；把时间花在"取明文"上是唯一现实路径。

## 7. 失败判据

- 熵 > 7.5 但解不出压缩、也拿不到明文对 → 停止猜算法，转进程内明文。
- 校验覆盖范围有三种都成立（样本 <4 帧）→ 只写"疑似"，继续收样本。
- 改密文一位后整帧被拒（AEAD）→ 不要再用位翻转判模式，改看长度/tag/每帧随机前缀。
- 声称"AES-CBC"却给不出 IV 位置或 padding 规则 → 结论无效。
- 用了别人的密钥/证书 → 越界，停。

## 8. 边界

- 本节只讲"识别与验证"：产物是熵/块长/魔数证据与明文回代；生产系统的解密动作按 `scope` 与授权单执行。
- 压缩/序列化的分层解析与分帧见 `05-binary-framing.md`；重放验收见 `08-replay-and-new-request.md`。
- 所有加密结论必须附：算法族、模式、IV/nonce 来源、覆盖范围、验证实验；缺一项即为"疑似"。

## 这一篇算"用对了"吗

- [ ] 先排压缩/编码再谈加密：给出魔数、解压结果或解码结果，没有跳过这一步。
- [ ] 加密结论写到"家族 + 模式 + IV/nonce 来源 + 覆盖范围"，四项缺一就标疑似。
- [ ] 重复异或/RC4/AES 的判定都有"已知明文 → 回代"或重复块/位翻转实验，不靠熵。
- [ ] 校验结论先定覆盖范围再定参数，且样本 ≥5 帧 + 改 1 字节负例。
- [ ] 拿不到明文对时如实写"未解"，没有把"爆破密钥"当计划。
