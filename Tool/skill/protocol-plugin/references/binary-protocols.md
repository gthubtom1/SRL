# 二进制协议：长度、魔数、校验、加密段与分帧

> 配套 `protocol-plugin/SKILL.md` 的 A3/A6。目标不是“猜出字段名”，而是给出**可验证的帧边界与字段覆盖范围**。
> 所有结论至少用 3 帧验证，并附 `offset/size/endian/样例/反例`；只做授权环境的离线或本地回放。

## 1. 先建立帧台账

```bash
# 从 pcap 提取原始载荷，每行一条，保留方向与序号
tshark -r capture.pcapng -Y "tcp.len>0" -T fields \
  -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
  -e tcp.seq -e tcp.len -e data.data > raw.tsv
```

或使用仓库脚本（无 tshark 也可）：

```bash
python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file capture.pcap --json
```

台账字段：`frame, direction, stream_offset, bytes_hex, ascii`。先按 TCP 流做**双向字节流重组**，再在流上分帧；不要按 pcap 包边界切消息。

**判据**：任意一帧都能在重组的字节流中找到唯一 `[start,end)`，且相邻帧首尾相接、无重叠。

## 2. 魔数 / 版本 / 类型

| 检查 | 方法 | 通过判据 |
|---|---|---|
| magic | 比较前 2/4/8 字节是否固定；统计所有帧 | ≥3 帧同值，且错误 magic 被服务端拒绝 |
| version | 找随会话变化的字节；对比同客户端不同版本 | 版本字段位置稳定，值域可解释 |
| type/opcode | 按请求/响应/心跳分组统计 | 每种 type 有独立样本与响应配对 |
| flags | 按位展开，观察 FIN/ACK/压缩/加密位 | 位变化与后续解析路径一致 |

```bash
# 快速看头部与周期
xxd -g1 -l 128 frame.bin
python3 - <<'PY'
from collections import Counter
frames=[bytes.fromhex(x.strip()) for x in open('frames.hex') if x.strip()]
print(Counter(f[:4].hex() for f in frames).most_common(10))
PY
```

- 魔数不是“看起来像”就算：要能解释为什么某帧不带 magic（握手、裸流、加密段）。
- 版本协商后 magic/头部长度可能变化；按会话阶段分别统计。

## 3. 长度字段：四个必须回答的问题

1. **端序**：u16/u24/u32，大端还是小端？
2. **覆盖范围**：只含 payload？含头？含自身？含尾校验？
3. **是否包含填充/对齐**：4 字节对齐、块填充、加密块补齐。
4. **上限与异常**：最大帧、0 长度、超长时服务端行为。

验证公式：

```text
len_field = a*header_len + payload_len + b*tail_len + pad
```

做法：取同一业务类型的 3 帧，记录 `len_field` 与实际帧长、payload 长，解线性关系；再故意改长度字段 1 字节，观察服务端是“等待更多字节”“拒绝”还是“截断”。

**判据**：用公式能预测未见帧的边界，误差为 0；错误长度导致可解释的拒绝/超时。

## 4. 校验和 / CRC

```bash
# 常见 CRC 参数先用工具穷举，再手写验证
reveng -w 16 -s 3a4b 5c6d 7e8f
reveng -w 32 -s 01020304 05060708
```

无工具时用标准库实现候选：

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

- 先确定**覆盖范围**（头+体、仅体、排除 checksum 自身），再确定多项式/初值/异或/反射。
- 用“改 1 字节 → 校验是否变化 → 服务端是否拒绝”闭环；只匹配样本不算完成。
- 有的协议用简单和/异或/Adler32，不要一上来就假定 CRC32。

**判据**：能对任意新帧计算正确校验，且错误校验被服务端按预期拒绝。

## 5. 加密段 / 压缩段

| 信号 | 判定 | 下一步 |
|---|---|---|
| 熵 > 7.5，字节分布均匀 | 压缩或加密 | 先试 gzip/zlib/zstd 魔数，再看是否有 nonce/IV |
| 固定块长（8/16 倍数） | 分组加密/块填充 | 找 IV/counter、padding、MAC |
| 每帧前 8/12/16 字节随机 | nonce/IV/salt | 判断是否随包变化、是否回显 |
| 明文头 + 密文尾 | 头部明文、载荷加密 | 确定加密起点与长度字段关系 |

```bash
python3 - <<'PY'
import math,collections
b=open('payload.bin','rb').read()
c=collections.Counter(b); n=len(b)
print('entropy', -sum(v/n*math.log2(v/n) for v in c.values()))
print('head', b[:32].hex())
PY
```

- 压缩：先解压再分帧；记录压缩算法、窗口、字典来源。
- 加密：优先在客户端 `SSL_write/SSL_read`、`send/recv`、序列化前后取明文；不要暴力猜密钥。
- 有已知明文-密文对时，先判定算法族（流/分组、模式、IV 位置），再做单变量验证。
- 解不开就标“未解”，不要用“看起来像 AES”当结论。

**判据**：能说明加密起点、长度字段是否覆盖密文、nonce/IV 来源，以及客户端内取明文的证据位置。

## 6. 分帧状态机（字节流层）

```text
WAIT_MAGIC -> WAIT_HEADER -> WAIT_BODY(len) -> VERIFY -> DISPATCH
     |             |               |             |
     +-- resync ---+-- bad len ----+-- bad crc --+-> DROP/RESYNC
```

- `WAIT_MAGIC`：滑动窗口找 magic；记录丢弃字节数，防止把 payload 里的假 magic 当帧头。
- `WAIT_HEADER`：头部长度固定或由 version 决定；不足则等待。
- `WAIT_BODY`：按长度字段收满；注意长度含头/含尾。
- `VERIFY`：校验、解密、解压；失败进入 `DROP/RESYNC`，并保留原始字节。
- 半包/粘包/重传/乱序都在这一层解决；应用层只接收完整消息。

**判据**：给一段任意切分的字节流，解析器输出与原始帧序列一致；注入垃圾字节后能重新同步。

## 7. 快速检查表

- [ ] 3 帧以上验证 magic/version/type。
- [ ] 长度公式能预测未见帧，错误长度有拒绝证据。
- [ ] 校验覆盖范围明确，改 1 字节能验证。
- [ ] 加密/压缩段有熵、块长、nonce/IV 证据。
- [ ] 解析器能处理半包、粘包、重传、乱序与假 magic。
- [ ] 所有样例编号可回溯到 `capture.pcapng#frame` 或 `frames.jsonl#id`。
