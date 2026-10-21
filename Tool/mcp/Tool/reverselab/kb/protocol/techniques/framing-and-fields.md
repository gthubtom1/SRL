# 分帧与字段：magic / length / CRC / 加密段

> 目标：给出**可验证的帧边界与字段覆盖范围**，而不是“看起来像”。
> 每条结论至少 3 帧验证，证据写 `offset/size/endian/样例/反例`。
> 深水区：`Tool/skill/protocol-plugin/references/05-binary-framing.md`；
> 校验与加密：本 board 的 [checksum-and-crypto-segment.md](checksum-and-crypto-segment.md)。

## 1. 帧台账

```bash
tshark -r capture.pcap -Y "tcp.len>0" -T fields \
  -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
  -e tcp.seq -e tcp.len -e data.data > raw.tsv
python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file capture.pcap --json   --extract artifacts/streams
```

先按流做双向重组，再在字节流上标 `[start,end)`；相邻帧首尾相接、无重叠。
**判据**：任意一帧能唯一回溯到 pcap 帧号/流偏移。

## 2. magic / version / type

```bash
xxd -g1 -l 128 frame.bin
python3 - <<'PY'
from collections import Counter
frames=[bytes.fromhex(x.strip()) for x in open('frames.hex') if x.strip()]
print(Counter(f[:4].hex() for f in frames).most_common(10))
PY
```

- magic 固定值要能解释例外（握手/裸流/加密段）。
- version 协商后头长可能变化；按阶段分别统计。
- type/opcode 每种至少一条请求/响应配对。

**判据**：≥3 帧同 magic；错 magic 被服务端拒绝或有明确丢弃行为。

## 3. 长度字段四问

1. 端序：u16/u24/u32，大端/小端？
2. 覆盖：只含 payload？含头？含自身？含尾校验？
3. 对齐：4 字节/块填充/加密补齐？
4. 异常：0 长度、超长、截断时服务端行为？

```text
len_field = a*header_len + payload_len + b*tail_len + pad
```

取同类型 3 帧解线性关系，再改长度字段 1 字节验证。
**判据**：公式能预测未见帧边界，误差 0；错误长度导致可解释的拒绝/超时。

## 4. CRC / 校验

```bash
reveng -w 16 -s 3a4b 5c6d 7e8f
reveng -w 32 -s 01020304 05060708
```

```python
import binascii
def crc32(b): return binascii.crc32(b) & 0xffffffff
def crc16_modbus(b):
    c=0xffff
    for x in b:
        c^=x
        for _ in range(8):
            c=(c>>1)^0xa001 if c&1 else c>>1
    return c
```

- 先定覆盖范围（含不含头/自身），再定多项式/初值/异或/反射。
- 改 1 字节 → 校验变化 → 服务端拒绝，三步闭环。
- 简单和/异或/Adler32 也存在，不要默认 CRC32。

**判据**：任意新帧能算对校验，错误校验被拒。
可执行版本：`proto-repro.py` 的 schema `tail[].covers/algo` + `checks[].want/got`。

## 5. 加密段 / 压缩段

| 信号 | 判定 | 下一步 |
|---|---|---|
| 熵 > 7.5 | 压缩/加密 | 试 gzip/zlib/zstd 魔数，再找 nonce/IV |
| 块长 8/16 倍数 | 分组加密/填充 | 找 IV/counter/padding/MAC |
| 每帧前 8/12/16 字节随机 | nonce/IV/salt | 看是否随包变化/回显 |
| 明文头 + 密文尾 | 头明文、载荷加密 | 定加密起点与长度关系 |

```bash
python3 - <<'PY'
import math,collections
b=open('payload.bin','rb').read(); c=collections.Counter(b); n=len(b)
print('entropy', -sum(v/n*math.log2(v/n) for v in c.values()), 'head', b[:32].hex())
PY
```

优先在客户端 `SSL_write/SSL_read`、`send/recv`、序列化前后取明文；不暴力猜密钥。
**判据**：说明加密起点、长度是否覆盖密文、nonce/IV 来源与取明文位置。
判族实验（块长/位翻转/同 nonce 重用）见 [checksum-and-crypto-segment.md](checksum-and-crypto-segment.md)。

## 6. 分帧状态机

```text
WAIT_MAGIC -> WAIT_HEADER -> WAIT_BODY(len) -> VERIFY -> DISPATCH
     |             |               |             |
     +-- resync ---+-- bad len ----+-- bad crc --+-> DROP/RESYNC
```

- 滑动窗口找 magic，记录丢弃字节，防止 payload 内假 magic。
- 半包/粘包/重传/乱序都在此层解决；应用层只收完整消息。
- 失败进入 `DROP/RESYNC`，保留原始字节。

**判据**：任意切分字节流输出与原始帧序列一致；注入垃圾后能重同步。

## 7. 检查表

- [ ] 3 帧以上验证 magic/version/type。
- [ ] 长度公式可预测未见帧。
- [ ] CRC 覆盖范围明确，改 1 字节可验证。
- [ ] 加密/压缩有熵、块长、nonce/IV 证据。
- [ ] 解析器能处理半包、粘包、重传、乱序、假 magic。
- [ ] 样例编号可回溯到 pcap 帧/流偏移。
- [ ] 字段表能直接喂给 `proto-repro.py --schema`（不只是散文）。

## 8. 边界与失败判据

- 只覆盖明文帧；加密段先解再分（见 checksum-and-crypto-segment.md）。
- 三帧内定不下长度/校验覆盖 → 标"分帧未定"，不写字段表。
- 重同步丢失字节却不记录 `skipped_bytes` → 解析器有缺陷，先修再谈协议。
