# 04 真实案例走查 — 用真实 WebSocket pcap 走完"分帧 → 字段 → 状态 → 重建"

> 范围：想照着跑一遍"分帧 → 字段 → 状态 → 构造"的完整链路。
> 路由：TLS/mTLS 下的同类分析按 `07-crypto-and-checksum.md` 处理（本样本是回环明文）；
> 插件装载链由 `plugin-targets`（R25）承担。
>
> 目标：拿仓库自带的一份**真实回环抓包**（抓包元数据：dumpcap 4.1.0 / Linux 5.15 / Go-http-client）走一遍完整链路，
> 证明判据可机检、脚本可复跑。
> 样本：`Tool/samples/real/protocol-pcaps/websocket.pcapng`
> （sha256 `ea9fcd3de02bf1824cdcff4bb61f842a6135fbc5d6b154cad00927ed3aa776d2`，18 帧 / 1940 字节）
> 边界：回环流量、明文、无 TLS、无鉴权；结论只对该样本成立。

## 0. 开跑前的三件（5 分钟）

```bash
# 1) 工具链自检：三个脚本都能离线跑（rc=0，输出含 ok）
for s in pcap-summary proto-repro proto-accept; do
  python Tool/skill/protocol-plugin/scripts/$s.py --self-test >/dev/null && echo "$s ok"; done
# 2) 样本哈希与格式（跟本文的 sha256 对上才叫同一份样本）
sha256sum Tool/samples/real/protocol-pcaps/websocket.pcapng
file Tool/samples/real/protocol-pcaps/websocket.pcapng
# 3) 确认抓包点确实能看到回环（回环不能用默认网卡）
tshark -D | head -5
```

通过长什么样：三行 `ok` + sha256 等于 `ea9fcd3d…3aa776d2` + `pcapng`。
对不上就说明样本被改过或拿错了文件，后面的数字全部不可比。

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

## 6.1 本地回显服务：把“预测”变成“实测”

依赖标准库，不装 websockets；只监听 `127.0.0.1`，跑完即退（不接受外部连接）。

```python
# artifacts/ws_echo.py
import base64, hashlib, json, socket, struct, threading
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def handshake(c):
    req = b""
    while b"\r\n\r\n" not in req:
        chunk = c.recv(1024)
        if not chunk:
            return False
        req += chunk
    key = [l.split(b":", 1)[1].strip() for l in req.split(b"\r\n")
           if l.lower().startswith(b"sec-websocket-key")]
    if not key:
        return False
    acc = base64.b64encode(hashlib.sha1(key[0] + GUID).digest())
    c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
              b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + acc + b"\r\n\r\n")
    return True

def read_frame(c):
    h = c.recv(2)
    if len(h) < 2:
        return None
    op, ln, masked = h[0] & 0x0F, h[1] & 0x7F, bool(h[1] & 0x80)
    if ln == 126:
        ln = struct.unpack(">H", c.recv(2))[0]
    mask = c.recv(4) if masked else b""
    body = b""
    while len(body) < ln:
        body += c.recv(ln - len(body))
    if masked:
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(body))
    return op, body

def send_text(c, payload):
    c.sendall(bytes([0x81, len(payload)]) + payload)

def serve(port=44380):
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(1)
    c, _ = srv.accept()
    if handshake(c):
        while True:
            got = read_frame(c)
            if got is None:
                break
            op, body = got
            if op == 0x8:
                break
            msg = json.loads(body)
            if msg.get("type") == "request":
                out = json.dumps({"type": "response", "data": msg["data"]},
                                 separators=(",", ":")).encode() + b"\n"
                send_text(c, out)
                print("served", len(out))
    c.close(); srv.close()

if __name__ == "__main__":
    serve()
```

客户端侧：把 §6 构造的 `frame_hex` 发过去，并逐字节比对响应：

```bash
python artifacts/ws_echo.py &          # 监听 127.0.0.1:44380
python - <<'PY'
import json, socket
expected = json.dumps({"type": "response", "data": "4242424242424242424"},
                      separators=(",", ":")).encode() + b"\n"
frame = bytes.fromhex(open("artifacts/new-frame.hex").read().strip())
s = socket.create_connection(("127.0.0.1", 44380), timeout=3)
s.sendall(b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
          b"Connection: Upgrade\r\nSec-WebSocket-Key: gMZehv+rgbF79AzLgIG9Hw==\r\n"
          b"Sec-WebSocket-Version: 13\r\n\r\n")
hs = s.recv(1024)
s.sendall(frame)
got = b""
while len(got) < len(expected):
    got += s.recv(4096)
print("accept_ok", b"101" in hs.split(b"\r\n")[0])
print("predicted", expected)
print("actual   ", got)
print("match", got[:len(expected)] == expected)
PY
```

通过长什么样：

```text
accept_ok True
predicted b'{"type":"response","data":"4242424242424242424"}\n'
actual    b'{"type":"response","data":"4242424242424242424"}\n'
match True
```

这一步把 §7 表格里的“疑似（未连服务）”抬成“确认（本地实测）”。注意边界：
它只证明**帧构造 + 回显语义**被接受，不证明真实服务端会接受同一个 `data`。

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
| WebSocket 帧头 2 B，客户端必须掩码，服务端不掩码 | 确认 | 8 帧 `tcp.payload` + RFC 6455 |
| 消息 = 单帧 text，`len < 126`，无扩展/压缩 | 确认 | 8 帧第二字节均 < 0x7e，无 `Sec-WebSocket-Extensions` |
| 业务字段 `type`（request/response）+ `data`（回显字符串） | 确认 | 4 组请求-响应 `data` 完全相等 |
| 新 `data` 会被接受 | 确认（本地）／疑似（真实服务端） | §6.1 本地回显服务 `match True`；真实目标未验 |
| 心跳/ping/pong/分片/close 行为 | 未定（本地仅 §6.2 少量实验） | 样本中没有；§6.2 只证明构造方式 |

边界：本样本是回环明文，不含鉴权、TLS、压缩；真实目标若有 `permessage-deflate`
必须先 inflate 再 parse，若有 mTLS 则抓包只能看到密文。

失败判据（本走查哪一步会垮）：按 TCP 段切消息 → 半截 JSON；忘了 4 B 掩码键 → 帧长差 4；
把服务端 49 B 当 48 B → 差一个换行符；未连本地服务就写"服务端接受" → 越档（只能算疑似）。
相关判据见 `01-criteria.md`，重放与构造的通用流程见 `08-replay-and-new-request.md`，
二进制帧（magic/长度/CRC）见 `05-binary-framing.md`。

## 这一篇算"用对了"吗

- [ ] 先跑 §0 三件（自检 + sha256 + 抓包点），样本对不上就没有继续。
- [ ] 分帧在**方向性字节流**上做，8 帧 `frame_len = 2 + (mask?4:0) + len` 全部成立。
- [ ] 请求-响应按 `data` 配对 4/4，且把"没观测到"的边标成 `INFERRED`。
- [ ] 新请求用 §6.1 的本地服务实测过，`match True`，不是"预测完就宣布成功"。
- [ ] 报告写清了边界：回环/明文/无鉴权，结论不推广到生产目标。
