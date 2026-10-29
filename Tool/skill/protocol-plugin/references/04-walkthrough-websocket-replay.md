# 04 真实案例走查 — 用真实 WebSocket pcap 走完"分帧 → 字段 → 状态 → 重建"

> 范围：想照着跑一遍"分帧 → 字段 → 状态 → 构造"的完整链路。
> 路由：TLS/mTLS 下的同类分析按 `07-crypto-and-checksum.md` 处理（本样本是回环明文）；
> 插件装载链按 `Tool/playbooks/plugin-analysis.md` 分析；原生载荷按需组合 `softseep`。
>
> 目标：拿仓库自带的一份**真实回环抓包**（抓包元数据：dumpcap 4.1.0 / Linux 5.15 / Go-http-client）走一遍完整链路，
> 展示离线分析；新请求的服务端接受尚未验证。
> 样本：`Tool/samples/real/protocol-pcaps/websocket.pcapng`
> （sha256 `ea9fcd3de02bf1824cdcff4bb61f842a6135fbc5d6b154cad00927ed3aa776d2`，18 帧 / 1940 字节）
> 边界：回环流量、明文、无 TLS、无鉴权；结论只对该样本成立。

## 0. 样本与工具准备

先核对样本 SHA-256；离线分析不需要抓包接口或运行会产生文件的自测。需要 tshark 时先运行 `python Tool/scripts/tool-acquire.py --tool tshark --json`，按返回入口获取后确认当前环境 PATH 可调用。以下 bash 示例需在 PowerShell 中转换。

## 1. 目标与先验

| 项 | 值 |
|---|---|
| 协议层 | HTTP/1.1 Upgrade → WebSocket（RFC 6455） |
| 端点 | `127.0.0.1:44380 → 127.0.0.1:8080`（真实回环抓包；Go 客户端连本地 ws 服务。早期文档写「Wireshark 官方 test/captures」系误标，来源以 `input/README.md` 的抓包元数据为准） |
| 期望判据 | 能按 opcode/FIN/长度/mask 分帧；能解释请求-响应配对；能构造**新**业务消息 |
| 边界 | 鉴权以协议样本为准；只做离线解析 + 本地构造 |

## 2. 第一步：会话与字节流（无需 tshark）

```bash
python Tool/skill/protocol-plugin/scripts/pcap-summary.py \
  --file Tool/samples/real/protocol-pcaps/websocket.pcapng --json \
  --extract artifacts/streams
```

关键输出（截取）：

```json
{
  "format": "pcapng", "linktype": 1, "packet_count": 18,
  "first_ts": 1694247103.066897, "duration_s": 0.0011265,
  "sessions_total": 2,
  "sessions": [
    {"proto": "TCP", "src": "127.0.0.1", "sport": 44380, "dst": "127.0.0.1", "dport": 8080,
     "packets": 10, "payload_bytes": 403,
     "snippets": ["GET /ws HTTP/1.1", "Host: localhost:8080",
                  "Sec-WebSocket-Key: gMZehv+rgbF79AzLgIG9Hw==", "Upgrade: websocket"]}
  ],
  "extract": {"files": [{"path": "<方向载荷文件>", "bytes": 403}]}
}
```

`--extract` 是按方向性五元组和抓包顺序拼包载荷，并非 TCP 重组；分帧前须按连接、方向、TCP sequence 处理乱序、重传、重叠、缺口并核对，不能验证时保留限制。`frames.jsonl` 是包级记录。

结论：**2 个方向性会话**（不是 1 个"连接"）；C2S 403 B / S2C 333 B；
`linktype=1`（Ethernet）+ 时间戳 1694247103（2023-09-09）说明 pcapng 的 `if_tsresol`
必须按 IDB 选项解析，否则时间会差 1000 倍（本脚本已处理选项 9）。

## 3. 第二步：用 tshark 看协议分层与握手

```bash
P=Tool/samples/real/protocol-pcaps/websocket.pcapng
tshark -r $P -q -z io,phs
tshark -r $P -Y 'http' -T fields -e frame.number -e http.request.method \
  -e http.request.uri -e http.response.code -e http.upgrade \
  -e http.sec_websocket_key -e http.sec_websocket_accept
```

原始输出：

```text
frame                                    frames:18 bytes:1940
  eth                                    frames:18 bytes:1940
    ip                                   frames:18 bytes:1940
      tcp                                frames:18 bytes:1940
        http                             frames:2 bytes:448
        websocket                        frames:8 bytes:948
          data-text-lines                frames:8 bytes:948
```

```text
4	GET	/ws		websocket	gMZehv+rgbF79AzLgIG9Hw==
6		/ws	101	websocket		MPGznO7WEpEGvXiPGvj3vxkmtv4=
```

结论：`101 Switching Protocols` 之后同一 `tcp.stream=0` 内的 8 帧才是 WebSocket；
握手用 HTTP/1.1 Upgrade，`Sec-WebSocket-Accept` 是 `Key + GUID` 的 SHA-1/base64（可离线复算）。

## 4. 第三步：按帧头分帧（不是按 TCP 包）

```bash
tshark -r $P -Y 'websocket' -T fields -e frame.number -e websocket.opcode \
  -e websocket.fin -e websocket.mask -e websocket.payload
```

原始输出（后 4 帧省略，格式相同）：

```text
8	1	True	True	7b2274797065223a2272657175657374222c2264617461223a2231323635333037343437343039343939303138227d0a
9	1	True	False	7b2274797065223a22726573706f6e7365222c2264617461223a2231323635333037343437343039343939303138227d0a
10	1	True	True	7b2274797065223a2272657175657374222c2264617461223a2237383230363233353033343839323535353131227d0a
11	1	True	False	7b2274797065223a22726573706f6e7365222c2264617461223a2237383230363233353033343839323535353131227d0a
```

把 hex 解成文本：

```bash
python - <<'PY'
import json
h = "7b2274797065223a2272657175657374222c2264617461223a2231323635333037343437343039343939303138227d0a"
raw = bytes.fromhex(h)
print(len(raw), json.loads(raw))
PY
```

```text
48 {'type': 'request', 'data': '1265307447409499018'}
```

帧结构核对（用 `tcp.payload` 看原始字节，注意 tshark 的 `websocket.payload` 已解掩码）：

```bash
tshark -r $P -Y 'frame.number==8 or frame.number==9' -T fields \
  -e frame.number -e tcp.len -e tcp.payload
```

```text
8	54	81b09fc7b2e7e4e5c6...
9	51	81317b2274797065223a22726573706f6e7365222c...
```

| 帧 | 首字节 | 第二字节 | 长度 | 掩码 | 载荷 | 帧长 |
|---|---|---|---|---|---|---|
| 8（客户端） | `81`=FIN+text | `b0`=mask(0x80)\|48 | 48 | 4 B `9f c7 b2 e7` | 48 B（掩码后） | 2+4+48=**54** |
| 9（服务端） | `81`=FIN+text | `31`=49 | 49 | 无（0x80 位为 0） | 49 B（含 `\n`） | 2+49=**51** |

判据：`frame_len = 2 + (mask ? 4 : 0) + payload_len`；8 帧全部吻合，且
`websocket.payload` 解出后是合法 JSON（`json.loads` 不抛异常）。
**这是"确认"档**：≥3 帧 + 两种长度 + 两种方向（含掩码/不含掩码）。

## 5. 第四步：状态机（请求-响应配对）

```text
CONNECTED --GET /ws + Upgrade--> HANDSHAKE
HANDSHAKE --101 + Sec-WebSocket-Accept--> OPEN
OPEN --text request{data:X}--> WAIT_RESPONSE
WAIT_RESPONSE --text response{data:X}--> OPEN
OPEN --close(0x8)--> CLOSED
```

配对规则：服务端 `response.data` 与客户端 `request.data` **完全相等**（4/4 对），
说明这是回显型业务，`data` 是唯一业务字段，`type` 是方向标记。
没观测到的边（如 error 帧、ping/pong、分片消息）只能说本样本未观察到，推测边标 `INFERRED`；上述 close 边也需另核实。

## 6. 第五步：构造一条**新**请求

不重放原帧，生成一条新的 `data`：

```bash
python - <<'PY'
import json
new = {"type": "request", "data": "4242424242424242424"}
payload = json.dumps(new, separators=(",", ":")).encode() + b"\n"
print("payload_len", len(payload))
print("payload_hex", payload.hex())
mask = bytes.fromhex("11223344")
masked = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
frame = bytes([0x81, 0x80 | len(payload)]) + mask + masked
print("frame_len", len(frame), "frame_hex", frame.hex())
from pathlib import Path
Path("artifacts/new-frame.hex").write_text(frame.hex(), encoding="ascii")
PY
```

```text
payload_len 48
payload_hex 7b2274797065223a2272657175657374222c2264617461223a2234323432343234323432343234323432343234227d0a
frame_len 54
frame_hex 81b011223344...
```

预测：服务端应回 `{"type":"response","data":"4242424242424242424"}\n`（49 B，帧长 51）。
验证方式：在授权条件下向实际服务发帧，解析完整响应后比较预测；预测本身不是证据，自建回显服务只能证明模拟器的行为。

## 6.1 离线帧检查与真实响应

§6 仅生成 `artifacts/new-frame.hex`；目录须事先存在。以下离线校验本例单帧、短载荷的客户端掩码，并不连接或模拟服务端：

```python
from pathlib import Path
import json
frame = bytes.fromhex(Path("artifacts/new-frame.hex").read_text(encoding="ascii"))
assert frame[0] == 0x81 and frame[1] & 0x80
n = frame[1] & 0x7f
assert n < 126 and len(frame) == 6 + n
mask, body = frame[2:6], frame[6:]
payload = bytes(b ^ mask[i % 4] for i, b in enumerate(body))
print("payload", json.loads(payload))
```

需要验证服务端时，使用授权目标及完整握手/帧实现，读取完整响应帧、解析帧头后再将载荷与预测比较；记录实际响应、时间和命令。本案例未记录此类验证，不能将离线构造、自建模拟器或猜测当成原服务端接受。

## 6.2 分片与控制帧：换三种发送方式看服务端怎么反应

| 实验 | 构造 | 期望 | 观测点 |
|---|---|---|---|
| 分片消息 | 首帧 `0x01`+`FIN=0`，续帧 `0x00`+`FIN=1` | 服务端拼成一条消息 | 响应只回一次 |
| ping | opcode `0x9`，载荷 ≤125 | 回 `0xA` pong，载荷一致 | pong 字节 |
| 未掩码的客户端帧 | `mask=0` | 严格实现直接 close(1002) | 关闭帧/断开 |
| 超长声明 | `len=127` 但实际只发 2 字节 | 服务端等待直到超时 | 连接存活时间 |

```bash
# 分片：把 §6 的 frame 拆成两段，首帧 FIN=0
python - <<'PY'
import json
p = json.dumps({"type": "request", "data": "4242424242424242424"},
               separators=(",", ":")).encode() + b"\n"
mask = bytes.fromhex("11223344")
def frag(op, fin, body):
    m = bytes(body[i] ^ mask[i % 4] for i in range(len(body)))
    return bytes([(0x80 if fin else 0x00) | op, 0x80 | len(body)]) + mask + m
open("artifacts/frag1.hex", "w").write(frag(0x1, False, p[:20]).hex())
open("artifacts/frag2.hex", "w").write(frag(0x0, True, p[20:]).hex())
print("frag_lens", 20, len(p) - 20)
PY
```

判读：分片被拼起来 → 消息层与帧层是两层，重放脚本必须按“消息”而不是“帧”对齐；
未掩码被拒 → 服务端严格，构造器不能省 mask。没观测到的行为标 `INFERRED`，不要写“支持/不支持”。

## 7. 结论与边界

| 结论 | 档位 | 证据 |
|---|---|---|
| 这些样本帧使用短长度头，客户端掩码、服务端未掩码 | 样本观察 | 8 帧抓包；是否拒绝违规帧未实验 |
| 观察到的消息为单帧 text，`len < 126`，无扩展/压缩 | 样本观察 | 8 帧第二字节的低 7 位均 < 126，无 `Sec-WebSocket-Extensions` |
| 业务字段 `type`（request/response）+ `data`（回显字符串） | 确认 | 4 组请求-响应 `data` 完全相等 |
| 新 `data` 会被接受 | 未验证 | 只有离线构造和预测，未记录服务端响应 |
| 心跳/ping/pong/分片/close 行为 | 未定 | §6.2 给出实验设计，未记录服务端实验 |

边界：本样本是回环明文，不含鉴权、TLS、压缩；真实目标若有 `permessage-deflate`
必须先 inflate 再 parse，若有 mTLS 则抓包只能看到密文。

失败判据（本走查哪一步会垮）：按 TCP 段切消息 → 半截 JSON；忘了 4 B 掩码键 → 帧长差 4；
把服务端 49 B 当 48 B → 差一个换行符；未连本地服务就写"服务端接受" → 越档（只能算疑似）。
相关判据见 `01-criteria.md`，重放与构造的通用流程见 `08-replay-and-new-request.md`，
二进制帧（magic/长度/CRC）见 `05-binary-framing.md`。

## 这一篇算"用对了"吗

- [ ] 核对样本哈希；按需发现工具并确认运行环境可调用。
- [ ] 分帧在**方向性字节流**上做，8 帧 `frame_len = 2 + (mask?4:0) + len` 全部成立。
- [ ] 请求-响应按 `data` 配对 4/4，且把"没观测到"的边标成 `INFERRED`。
- [ ] 区分离线构造、实际服务响应与尚未验证的预测。
- [ ] 报告写清了边界：回环/明文/无鉴权，结论不推广到生产目标。
