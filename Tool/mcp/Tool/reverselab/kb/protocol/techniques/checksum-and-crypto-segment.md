# 校验与加密段：先证伪"像 AES"，再谈明文

> 入口信号：帧尾 2/4 字节随载荷变化；载荷熵 > 7.5；长度恒为 8/16 的倍数；每帧前 8/12/16 字节随机。
> 深水区：`Tool/skill/protocol-plugin/references/07-crypto-and-checksum.md`。

## 1. 先分层，再谈算法

```text
明文头 + 密文尾 ?  → 定加密起点与长度关系
熵高 ?             → 先排压缩（gzip/zlib/zstd 魔数）→ 再排编码（base64/hex/url）→ 最后才是加密
块长 8/16 倍数 ?    → 分组加密或块填充
逐帧随机前缀 ?      → nonce/IV/salt
```

```bash
python - <<'PY'
import collections, gzip, math, zlib
b = open('payload.bin','rb').read()
c = collections.Counter(b); n = len(b)
print('len', n, 'entropy', round(-sum(v/n*math.log2(v/n) for v in c.values()), 3))
print('head', b[:32].hex())
for name, fn in (('gzip', gzip.decompress), ('zlib', zlib.decompress)):
    try:
        out = fn(b); print(name, 'ok', len(out), out[:48])
    except Exception as e:
        print(name, 'no', type(e).__name__)
PY
```

熵参考：JSON/英文 4.0–4.7、base64 约 6.0、压缩/加密 7.9–8.0。
**压缩与加密的熵几乎相同**，只能靠"能否解压 / 有无块结构"区分。

## 2. 校验：覆盖范围优先于算法

| 步骤 | 做法 | 通过判据 |
|---|---|---|
| 定位字段 | 找帧尾/帧头固定宽度、帧间变化的字段 | 改载荷后该字段变化 |
| 覆盖范围 | 分别算 `payload` / `header+payload` / `header+payload+len` | 只有一种对全部帧成立 |
| 算法族 | 先 sum/xor/Adler32，再 CRC16/CRC32 | ≥5 帧全中 |
| 参数 | `reveng -w 32 -s ...` 穷举多项式/初值/异或/反射 | 改 1 字节能算出新值 |
| 负例 | 发一个错校验帧 | 拒绝方式与模型一致 |

```bash
reveng -w 16 -s 3a4b 5c6d 7e8f 90a1
reveng -w 32 -s 01020304 05070809 0a0b0c0d
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
```

用字段表固化（`proto-repro.py`）：

```json
"tail": [{"name": "crc32", "size": 4, "type": "u32", "role": "checksum",
          "algo": "crc32", "covers": "header+payload"}]
```

**确认判据**：`checks[].want == checks[].got` 且 `covers` 只有一种成立；改 1 字节后 `crc_ok=false`。

## 3. 分组 vs 流：三个实验

| 实验 | 分组（CBC/ECB） | 流/CTR | 观察点 |
|---|---|---|---|
| 相同明文块重复 | ECB 下密文块相同 | 不同 | 找重复块 |
| 密文长度 | 16 的倍数（含 padding） | 与明文等长 | 长度差 |
| 翻转密文第 k 字节 | 影响整块 + 下一块 | 只影响对应位 | 位翻转扩散 |

带 MAC/AEAD 的协议会整帧拒绝，看不到扩散 → 只能靠"长度是否 16 倍数 + 是否每帧带 tag"判断，
并把结论写成"疑似分组加密"。

## 4. 取明文的四条路（按代价）

1. `SSLKEYLOGFILE`（NSS/openssl 客户端，读环境变量）——最低成本。
2. 代理装 CA（能改信任库；pinning/mTLS 会失败）。
3. 进程内 hook `SSL_write/SSL_read`、`send/recv`、序列化前后——有调试权限时最可靠。
4. 静态定位序列化/加密函数（`ida-reverse`）——最贵，最后做。

**不要爆破密钥**：ECDHE 协商的会话密钥在数学上不可爆；时间应花在"取明文"。

## 5. 确认判据

- 能写出：算法族、模式、IV/nonce 来源、覆盖范围、验证实验。
- 解出的明文能被第二层验证（JSON 可解析、长度字段自洽、CRC 通过）。
- 错误校验/错 nonce 被服务端按预测方式拒绝。
- 缺任何一项 → 只能写"疑似"，不能写"已确认 AES-CBC"。

## 6. 失败判据

- 熵高但解不出压缩、也拿不到明文对 → 停止猜算法，转进程内明文。
- 三种覆盖范围都成立（样本 <4 帧）→ 继续收样本，或只用负例证明其中一种。
- 声称分组加密却说不出 IV 位置/padding 规则 → 结论无效。
- 需要他人密钥/证书 → 越界，停。

## 7. 边界

- 只做识别与验证，不提供针对生产系统的解密步骤。
- 压缩/序列化分层与分帧见 [framing-and-fields.md](framing-and-fields.md)；
  重放验收见 [capture-to-replay.md](capture-to-replay.md)。
- 真实样本练习：`Tool/samples/real/protocol-pcaps/http2-data-reassembly.pcap`（TLS 下 h2，
  无 keylog 时只能看到密文，正好用来练"分层判断"）。
