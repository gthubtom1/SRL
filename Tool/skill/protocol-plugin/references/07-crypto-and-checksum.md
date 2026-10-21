# 07 加密段与校验 — 先证伪"像 AES"，再谈解明文

> 适用：帧尾/帧头有校验字段、载荷熵高、长度按 8/16 对齐、可能有压缩或加密的私有协议。
> 不适用：TLS 握手本身的分析（看 `tshark -Y tls` + `04-walkthrough`）；插件装载链 → `plugin-targets`。
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
| 块长恒为 16 倍数，且最后一块有规律填充 | AES-CBC/ECB | 见 §3 |
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
- 带 MAC/AEAD：整帧被拒（无法观察扩散），此时只能靠"密文长度是否 16 倍数"和"是否每帧带 tag"判断。

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

## 5. 真实样本的校验复算（SPRX）

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

- 本节只讲"识别与验证"；不提供任何针对生产系统的解密/绕过步骤。
- 压缩/序列化的分层解析与分帧见 `05-binary-framing.md`；重放验收见 `08-replay-and-new-request.md`。
- 所有加密结论必须附：算法族、模式、IV/nonce 来源、覆盖范围、验证实验；缺一项即为"疑似"。
