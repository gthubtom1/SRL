# 协议复刻参考（R24）

> 目标：从 pcap/代理流量还原帧格式、字段语义、状态机，最终做到**同输入同输出且能构造新请求**；总流程与边界见 `../SKILL.md`，本文只给可执行细节。

## 1. 采集与取证
采集前记录：客户端版本/构建号、端点与端口、协议层、代理/网卡/时间、是否 TLS/pinning、账号/租户、操作序列。
产物：`capture.pcapng`、`frames.jsonl`、`schema.md`、`replay.py`、`evidence.md`。
`frames.jsonl` 每行至少：`no, ts, src, sport, dst, dport, direction, hex, tcp_flags, ws_opcode`。

### 1.1 tshark 基本盘
```bash
tshark -r capture.pcapng -q -z conv,tcp
tshark -r capture.pcapng -q -z io,stat,1
tshark -r capture.pcapng -Y "http.request or http.response" \
  -T fields -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport \
  -e ip.dst -e tcp.dstport -e http.request.method -e http.host \
  -e http.request.uri -e http.response.code -e http.content_type
tshark -r capture.pcapng -Y "tcp.stream==3 && tcp.len>0" \
  -T fields -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
  -e tcp.seq -e tcp.len -e data.data
tshark -r capture.pcapng -q -z follow,tcp,raw,3
```

- 先看 `tcp.stream`，不同连接的同端口包不能混成一个会话。
- `data.data` 是十六进制；缺 `data` 时试 `tcp.payload`。
- 应用层消息与 TCP segment 不是一一对应，禁止按包边界定帧。
- 有 pcap 时先用 `seep_pcap_extract(pcap, mode='summary'|'http'|'payload', port=...)` 拿端点/HTTP/载荷，再补 tshark。

### 1.2 mitmproxy 与 TLS

```bash
mitmdump -p 8080 -w flows.mitm
mitmweb -p 8080 --set web_port=8081
```

- 客户端需信任 mitm CA；Android 7+ 用户证书默认不受信，需系统证书或可调试目标。
- 代理下握手失败/无请求先查 pinning；可改用 `SSLKEYLOGFILE` 或进程内 hook 取明文。
- **mTLS**：服务端要求客户端证书时，mitm 不能凭 CA 单边解密；需客户端证书/私钥，或改在客户端内取明文。
- 记录 mitm 是否改写请求体；否则重放基线已被污染。

### 1.3 WebSocket 与取证卫生

- 按消息重组：`FIN`、opcode（text/binary/close/ping/pong）、7/16/64 位长度、mask key。
- 客户端帧必须掩码；抓包工具通常已解掩码，自写解析器要注意。
- 协商 `permessage-deflate` 时消息体可能是 raw deflate，先解压再看业务格式。
- 控制帧可穿插在分片消息之间，ping/pong 不是业务消息。
- 抓包与重放流量分开命名；每个结论引用 `capture.pcapng#frame N` 或 `frames.jsonl#id`；报告脱敏 token/账号。

## 2. 分帧与字段推断
### 2.1 先重组再分帧

按 `tcp.stream` 取单向字节流，用 tshark 的重组结果处理重传/乱序，再应用帧边界。一个流里既有握手又有业务时，先按状态切换点切段。

帧边界判定顺序：

1. **定界符**：`\r\n\r\n`、`\0`、固定尾标（如 `00 00 FF`）。
2. **长度前缀**：u8/u16/u32、大小端、是否含头/含自身/含 CRC。
3. **固定头 + 长度**：magic 后跟 length，最常见。
4. **TLV 链**：tag/length/value；注意 length 是否含 tag/len 自身。
5. **无长度**：靠 type 与固定结构，必须用多帧验证。

**长度方程**：取三条不同 payload 长度的帧，列 `len_field = payload_len + a*header_len + b`，解 `a/b` 与端序。
含自身时通常 `len_field = total_frame_len`；不含头时多为 `payload_len + crc_len`。

### 2.2 固定头字段表

| offset | size | endian | 字段 | 样例 | 变化条件 | 反例 |
|---|---|---|---|---|---|---|
| 0 | 2 | - | magic | `AB CD` | 固定 | 错 magic 被拒 |
| 2 | 1 | - | version | `01` | 协商后固定 | 高版本可能加字段 |
| 3 | 1 | - | type | `01/02/03` | 请求/响应/心跳 | 未知 type 可能被忽略 |
| 4 | 2 | BE | length | `00 10` | 随 payload | 含头/不含头要验证 |
| 6 | 4 | LE | seq | 递增 | 每帧 +1 | 重放旧 seq 被拒 |
| 10 | 4 | - | checksum | CRC32 | 覆盖头+体 | 改一字节应失败 |

TLV/嵌套：先确认 tag/length 宽度（1/2/4）与嵌套层数；用“长度刚好到帧尾”验证；未知 tag 保留原始字节，不要丢弃，否则重放缺字段。

### 2.3 字段语义推断

- **相关性**：同一字段在多帧中与业务值同步变化（订单号、时间戳、计数）。
- **单变量**：只改一个业务输入，观察哪个字段变化；重复 3 次。
- **边界**：长度/计数用 0、1、最大值试探合法范围。
- **反例**：构造错误值看服务端拒绝方式，确认字段真被校验。
- 证据不足时命名 `field_0x10`，不要起“userId”这类误导名。推断格式：`offset/size/endian/样例/变化条件/反例`。

## 3. 状态机重建
| # | state_before | event/方向 | 关键字段 | state_after | 证据 |
|---|---|---|---|---|---|
| 1 | NEW | C→S hello | version, nonce | HELLO_SENT | frame 12 |
| 2 | CHALLENGE | C→S auth | token, proof | AUTHED | frame 14 |
| 3 | AUTHED | C→S business | req_id, payload | WAIT_RESP | frame 20 |
| 4 | WAIT_RESP | S→C response | req_id, code | AUTHED | frame 21 |

检查请求 id 如何配对响应、token 是否单次/有时窗、心跳多久断线、错误后是否重连；**完成判据**：能解释每一步“服务端为什么接受下一帧”，无法解释的迁移标 `UNKNOWN`。

## 4. 重放与构造
### 4.1 HTTP 重放

```python
seep_http_replay(url="https://target/api/action", method="POST",
    headers='{"Content-Type":"application/json","X-Sign":"..."}',
    cookies='{"sid":"..."}', body='{"id":1}',
    impersonate="chrome", session_file="work/session.json")
```

- `Host/UA/Referer/Origin/Content-Type/Cookie/签名头` 必须与基线一致，缺一个就可能被风控。
- 先原样重放，确认状态码、长度、业务码、响应哈希与基线一致。
- 再单变量改业务字段；每改一次记录“预测 → 实际”。
- 签名/时间戳/nonce 会随请求变化，先定位生成逻辑，不要复制旧值硬撞。
- 只对授权环境重放，禁止对生产做高频/破坏性扫描。

### 4.2 TCP/UDP 重放

```python
import socket, json, time
fr = [json.loads(l) for l in open("frames.jsonl", encoding="utf-8")]
s = socket.create_connection(("127.0.0.1", 9527), timeout=5)
for f in fr:
    if f["direction"] == "C2S": s.sendall(bytes.fromhex(f["hex"])); time.sleep(.05)
# recv 需按帧边界/超时处理，不能假设一次一帧
s.close()
```

- 逐字节原样重放是基线；不要一上来改字段。
- 记录发送字节、响应字节、RTT、超时；响应按协议分帧，不要 `recv(4096)` 后当一条消息。
- UDP 保留源/目标端口与发送节奏；有些服务端按五元组建会话。

### 4.3 差异归因与验收

归因顺序：**环境**（IP、UA、TLS 指纹、代理）→ **会话**（token、cookie、时间窗）→ **协议**（字段、长度、校验、seq）→ **业务权限/风控**。不要跳过前三步直接猜“加密”。

构造新请求的验收：新请求不来自抓包原帧；服务端返回业务成功而非仅 HTTP 200；响应业务字段与预测一致；重复 3 次稳定；负例（错校验/错 seq）按预期失败。

## 5. 二进制协议专项
### 5.1 布局与校验

```text
+------+------+------+------+--------+--------+---------+
| magic| ver  | type |flags | length | seq    | payload | crc |
| 2B   | 1B   | 1B   | 1B   | 2B BE  | 4B LE  | ...     | 4B  |
+------+------+------+------+--------+--------+---------+
```

每个字段标注偏移、宽度、端序、是否含自身、覆盖范围、默认值、合法范围。

```python
import zlib
crc32_be = lambda d: zlib.crc32(d).to_bytes(4, "big")
def crc16_modbus(d):
    c = 0xFFFF
    for b in d:
        c ^= b
        for _ in range(8): c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c.to_bytes(2, "little")
```

- 先确定覆盖范围：头+体、仅体、去 magic、是否含 length 自身。
- 用已知帧验证：算出的值必须与帧尾一致；再改一字节看服务端是否拒绝。
- 自定义校验先看常量表/移位模式，再试常见 CRC 参数（多项式、初值、异或、反射）。

### 5.2 加密段

- 找 nonce/IV/counter/salt；同一明文两次加密是否相同，判断是否有随机 IV。
- 用已知明文-密文对判断算法族（AES-CBC/CTR、ChaCha20、XOR 流）；不要暴力猜密钥。
- 密钥可能在客户端常量、资源、注册表、服务端下发或硬件内；先定位“谁调用加密函数”。
- 进程内取明文比破解密钥可靠：在 `send/recv`、`SSL_write/SSL_read`、序列化入口下断点/hook。
- 报告只记录算法、模式、IV 来源与调用点，不泄露真实密钥。

### 5.3 序列化、压缩与解析器

| 格式 | 识别 | 还原 |
|---|---|---|
| protobuf | 字段号+wire type，常见 `08/12/1a` | 写 `.proto`，用 `protoc --decode_raw` 对照 |
| flatbuffers | 前 4 字节 root offset，vtable | 按 schema 读 vtable/offset，不要顺序读 |
| JSON/msgpack | 可打印/紧凑二进制 | 先解压再解析，保留原始字节 |
| gzip/deflate/zstd | `1f8b`、`78 9c`、`28 b5 2f fd` | 解压后再分帧，注意字典/窗口 |

长期维护用 Kaitai Struct（YAML 生成多语言 parser）或 scapy `Packet` 子类。解析器必须能“原样回写”：parse → object → serialize 后字节一致，才算真正理解布局。

## 6. 完成判据与交付

必须同时满足：① 同输入同输出（重复请求响应结构/关键字段一致）；② 能构造抓包外的新请求并被接受；③ 完成一次“握手/认证 → 业务 → 关闭”闭环；④ 负例可解释；⑤ 他人按 `schema.md + replay.py` 能复跑。

达不到 ①–③ 报“部分复刻”，卡点写清：缺失密钥、mTLS、服务端风控、字段语义不足、协议版本不匹配。

## 7. 快速排障

| 现象 | 先查 |
|---|---|
| 服务端无响应 | 长度字段、CRC 覆盖范围、端序、是否缺帧尾 |
| 403/风控 | UA/TLS 指纹、签名头、时间戳、IP、cookie |
| 重放一次成功第二次失败 | seq/nonce/时间窗/token 单次使用 |
| 抓不到明文 | pinning、mTLS、QUIC、代理未生效、客户端直连 |
| WebSocket 消息错位 | 分片、控制帧、掩码、permessage-deflate |
| 二进制看似随机 | 压缩/加密；先看熵与 magic，再找 nonce |
| 改字段没反应 | 字段未被使用，或存在签名覆盖 |

## 8. 交接到其他技能

网页 JS 签名/补环境 → `mcp-js-reverse-playbook`；客户端授权/门禁 → `01-gate-bypass` 等；壳/反调试导致取不到明文 → `unpack-loop`；需逆向加密函数本体 → `ida-reverse` / `reverse-engineering`。
