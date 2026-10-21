# 04 真实案例走查 — 用真实 WebSocket pcap 走完"分帧 → 字段 → 状态 → 重建"

> 适用：想照着跑一遍"分帧 → 字段 → 状态 → 构造"的完整链路。
> 不适用：TLS/mTLS 下的同类分析（本样本是回环明文，见 `07-crypto-and-checksum.md`）；
> 插件装载链（→ `plugin-targets`，R25）。
>
> 目标：拿仓库自带的一份**真实回环抓包**（抓包元数据：dumpcap 4.1.0 / Linux 5.15 / Go-http-client）走一遍完整链路，
> 证明判据可机检、脚本可复跑。
> 样本：`Tool/samples/real/protocol-pcaps/websocket.pcapng`
> （sha256 `ea9fcd3de02bf1824cdcff4bb61f842a6135fbc5d6b154cad00927ed3aa776d2`，18 帧 / 1940 字节）
> 边界：回环流量、明文、无 TLS、无鉴权；结论只对该样本成立。

## 1. 目标与先验

| 项 | 值 |
|---|---|
| 协议层 | HTTP/1.1 Upgrade → WebSocket（RFC 6455） |
| 端点 | `127.0.0.1:44380 → 127.0.0.1:8080`（真实回环抓包；Go 客户端连本地 ws 服务。早期文档写「Wireshark 官方 test/captures」系误标，来源以 `input/README.md` 的抓包元数据为准） |
| 期望判据 | 能按 opcode/FIN/长度/mask 分帧；能解释请求-响应配对；能构造**新**业务消息 |
| 不做 | 不猜鉴权、不打真实服务；只做离线解析 + 本地构造 |

## 2. 第一步：会话与字节流（无需 tshark）

```bash
python Tool/skill/protocol-plugin/scripts/pcap-summary.py \
  --file Tool/samples/real/protocol-pcaps/websocket.pcapng --json \
  --extract artifacts/streams --tshark-check
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
  "extract": {"files": ["s00_127.0.0.1_44380-127.0.0.1_8080.bin",
                        "s01_127.0.0.1_8080-127.0.0.1_44380.bin", "frames.jsonl"]}
}
```

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
没观测到的边（如 error 帧、ping/pong、分片消息）在本样本中**不存在**，标 `INFERRED` 而不是画成实线。

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
PY
```

```text
payload_len 48
payload_hex 7b2274797065223a2272657175657374222c2264617461223a2234323432343234323432343234323432343234227d0a
frame_len 54
frame_hex 8180112233445d6a...
```

预测：服务端应回 `{"type":"response","data":"4242424242424242424"}\n`（49 B，帧长 51）。
验证方式：把上一步的 `frame_hex` 写入本地自建 ws 回显服务（`python -m websockets` 或
`aiohttp` 的 20 行 handler），只连 `127.0.0.1`，比对响应字节。
**没有本地服务就不写"已确认"**——预测本身不是证据。

## 7. 结论与边界

| 结论 | 档位 | 证据 |
|---|---|---|
| WebSocket 帧头 2 B，客户端必须掩码，服务端不掩码 | 确认 | 8 帧 `tcp.payload` + RFC 6455 |
| 消息 = 单帧 text，`len < 126`，无扩展/压缩 | 确认 | 8 帧第二字节均 < 0x7e，无 `Sec-WebSocket-Extensions` |
| 业务字段 `type`（request/response）+ `data`（回显字符串） | 确认 | 4 组请求-响应 `data` 完全相等 |
| 新 `data` 会被接受 | 疑似（未连服务） | 帧结构自洽，但无服务端响应 |
| 心跳/ping/pong/分片/close 行为 | 未定 | 样本中没有 |

边界：本样本是回环明文，不含鉴权、TLS、压缩；真实目标若有 `permessage-deflate`
必须先 inflate 再 parse，若有 mTLS 则抓包只能看到密文。

失败判据（本走查哪一步会垮）：按 TCP 段切消息 → 半截 JSON；忘了 4 B 掩码键 → 帧长差 4；
把服务端 49 B 当 48 B → 差一个 `
`；未连本地服务就写"服务端接受" → 越档（只能算疑似）。
相关判据见 `01-criteria.md`，重放与构造的通用流程见 `08-replay-and-new-request.md`，
二进制帧（magic/长度/CRC）见 `05-binary-framing.md`。
