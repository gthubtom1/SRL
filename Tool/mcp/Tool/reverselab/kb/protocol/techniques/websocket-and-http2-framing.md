# WebSocket 与 HTTP/2 分帧：按消息/流，不按 TCP 段

> 入口信号：`Upgrade: websocket` / `101 Switching Protocols`；或 `tcp.port==443` 且 tshark 显示 `http2`。
> 深水区：`Tool/skill/protocol-plugin/references/04-walkthrough-websocket-replay.md`；
> 真实样本：`Tool/samples/real/protocol-pcaps/websocket.pcapng`、`http2_follow_multistream.pcapng`。

## 1. WebSocket 帧头（RFC 6455）

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
```

- `frame_len = 2 + (mask ? 4 : 0) + payload_len`。
- 客户端 → 服务端 **必须** 掩码（mask=1，4 字节随机键）；服务端 → 客户端不掩码。
- 控制帧（opcode 8/9/10）可穿插在分片消息之间，长度 ≤125 且不能分片。
- `Sec-WebSocket-Extensions: permessage-deflate` 时消息体是 raw deflate，先 inflate 再 parse。

## 2. 取帧头（tshark）

```bash
P=Tool/samples/real/protocol-pcaps/websocket.pcapng
tshark -r $P -Y websocket -T fields -e frame.number -e websocket.opcode \
  -e websocket.fin -e websocket.mask -e websocket.payload_length \
  -e tcp.len -e websocket.masking_key -e tcp.payload
```

实测（8 帧，仓库内真实抓包）：

```text
8	1	True	True	48	54	9fc7b2e7	81b09fc7b2e7e4e5c6...
9	1	True	False	49	51		81317b2274797065223a22726573706f6e7365...
10	1	True	True	48	54	8db50908	81b08db50908f6977d71fdd02b32afc7...
11	1	True	False	49	51		81317b2274797065223a...
```

判据：客户端 `tcp.len=54=2+4+48` 且每帧 masking_key 不同；服务端 `tcp.len=51=2+49` 且 mask=False。
**这是确认档**（含两种长度、两种方向）。

## 3. 消息重组（不按 TCP 段）

- 一个 TCP 段可含多帧，一帧也可跨段 → 在**字节流**上循环解析帧头。
- 分片：首帧 opcode=1/2 且 FIN=0，后续 continuation(0)，最后一帧 FIN=1；重组后再 decode。
- 控制帧（ping/pong/close）单独分类，不并入业务消息。
- payload 文本帧末尾可能是 `\n`（本样本服务端 49 B 比客户端 48 B 多一个换行），解析 JSON 前 `strip()`。

## 4. 握手与可复算字段

```bash
tshark -r $P -Y http -T fields -e frame.number -e http.request.method \
  -e http.request.uri -e http.response.code -e http.upgrade \
  -e http.sec_websocket_key -e http.sec_websocket_accept
```

```text
4	GET	/ws		websocket	gMZehv+rgbF79AzLgIG9Hw==
6		/ws	101	websocket		MPGznO7WEpEGvXiPGvj3vxkmtv4=
```

`Sec-WebSocket-Accept = base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`，
可离线复算 → 用来验证"这一帧确实是 101 响应"而不是伪造/重放。

## 5. HTTP/2：按 streamid 归属

```bash
H=Tool/samples/real/protocol-pcaps/http2_follow_multistream.pcapng
tshark -r $H -Y http2 -T fields -e frame.number -e tcp.stream -e http2.type \
  -e http2.streamid -e http2.header.name -e http2.header.value | head
```

实测（节选）：

```text
13	0	1,8	13,13	:method,:path,:authority,:scheme,...	GET,/en-US/firefox/52.0.1/firstrun/,www.mozilla.org,https,...
18	0	1	13	:status,date,content-type,...	200,Wed, 29 Mar 2017 11:59:30 GMT,text/html; charset=utf-8,...
30	0	1,8	15,15	:method,:path,...	GET,/media/js/site-bundle.1688e984bc3d.js,www.mozilla.org,https,...
```

要点：

- **一个 tcp.stream 里多个 streamid 并发**：按 `http2.streamid` 分组，同 streamid 内按帧顺序。
- `http2.type` 是位图（1=HEADERS、8=WINDOW_UPDATE 等组合显示为 `1,8`），不是单一枚举。
- HEADERS 的 `END_HEADERS`/`END_STREAM` 位决定头块边界与流结束；HPACK 动态表跨流共享，
  所以"单独解某一条请求"会失败——必须按连接顺序喂。
- DATA 帧的 streamid 必须与 HEADERS 一致，否则是串流。

**确认判据**：每个 streamid 都能配对出 `:method/:path` → `:status`，且 DATA 的 streamid 一致。
**失败判据**：按 frame.number 直接配对（忽略 streamid）→ 多路复用下必然串流，结论无效。

## 6. 失败判据

- TCP 段当消息 → 半截 JSON / 把控制帧当业务 → 重写重组逻辑。
- `websocket.payload` 能解但 `tcp.payload` 解不出 → 忘了客户端帧有 4 字节掩码键（tshark 已解掩码）。
- h2 头解不出来 → 没有 keylog 或 HPACK 上下文缺失；不要手工猜 HPACK。
- permessage-deflate 未处理 → `json.loads` 报错，先 `zlib.decompressobj(-15)`。

## 7. 边界

- 本节只讲分帧与字段；鉴权/业务语义见 [capture-to-replay.md](capture-to-replay.md)。
- 真实目标若有 mTLS，抓包只有密文；需要进程内明文（见 checksum-and-crypto-segment.md）。
- 本 board 不覆盖"用 WebSocket 打漏洞"，只覆盖"读懂并复刻消息"。
