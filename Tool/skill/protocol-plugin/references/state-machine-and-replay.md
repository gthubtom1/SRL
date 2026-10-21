# 状态机重建与重放验证

> 配套 `protocol-plugin/SKILL.md` 的 A4/A5。核心问题：**服务端为什么接受下一帧？**
> 先原样复现，再单变量构造；每次改动保留基线、原始字节与响应哈希。只在授权环境重放。

## 1. 会话切片与消息台账

```bash
tshark -r capture.pcapng -q -z conv,tcp
tshark -r capture.pcapng -Y "tcp.stream==7" -T fields \
  -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport \
  -e ip.dst -e tcp.dstport -e tcp.seq -e tcp.len -e data.data > stream7.tsv
```

每条消息记录：

```json
{"id":"m12","stream":7,"ts":1720000000.123,"dir":"C2S","state_before":"AUTH",
 "event":"auth_request","state_after":"AUTH_WAIT","bytes_sha256":"...",
 "fields":{"uid":1001,"token_len":32,"nonce":"..."},"evidence":"capture.pcapng#frame 88"}
```

**判据**：消息 id 与 pcap 帧号/重组偏移双向可查；半包与重传不产生重复消息。

## 2. 从消息序列推状态

先画“观测到的迁移”，再补“推测但未验证”的边：

```text
INIT --hello(ver,cap)--> HELLO_SENT
HELLO_SENT --hello_ack(ver,cap,session)--> READY
READY --auth(token,nonce,ts)--> AUTH_WAIT
AUTH_WAIT --auth_ok(session,token2)--> AUTHED
AUTHED --subscribe(topic)--> SUBSCRIBED
SUBSCRIBED --data(seq,payload)--> SUBSCRIBED
SUBSCRIBED --heartbeat(ts)--> SUBSCRIBED
* --error(code,msg)--> ERROR
ERROR --close()--> CLOSED
```

规则：

- 每条边附至少一条样本；没有样本的边标 `INFERRED`，不要画成实线。
- 请求/响应配对优先用 `request_id`/`seq`；没有就用“同流下一条反向消息”，并标注不确定性。
- 心跳、重连、超时是状态推进的一部分；记录周期、抖动、重试次数。
- 错误码要能解释“服务端为什么拒绝”，而不是只记录“失败了”。

**判据**：给定一条新消息序列，能预测下一个合法状态与非法迁移；非法迁移有实际拒绝证据。

## 3. 认证与会话材料

| 材料 | 观察点 | 重放时的陷阱 |
|---|---|---|
| token/cookie | 登录响应、后续每帧头 | 过期、绑定 IP/UA/设备指纹 |
| nonce/seq | 请求头/体、递增或随机 | 一次性、窗口、回显校验 |
| 时间戳 | 头部 4/8 字节 | 时区、单位（秒/毫秒）、允许偏差 |
| 签名/MAC | 尾部或头字段 | 覆盖范围、密钥版本、排序规则 |
| 会话 id | 握手响应 | 服务端会话表、并发互踢 |
| 证书/mTLS | TLS 握手 | 客户端证书不可用代理单边解密 |

- 先做“同会话原样重放”，确认 token/seq 是否被消耗；再决定是否重放整个握手。
- 需要新会话时，按“握手 → 认证 → 业务”完整重放，不要只复制业务帧。
- 时间戳/ nonce 变化导致失败时，记录变化量与拒绝码，判断是窗口还是签名覆盖。

**判据**：能区分“会话过期”“nonce 重放”“签名不匹配”“权限不足”四类失败，而不是笼统写“被拒绝”。

## 4. 重放脚本骨架

```python
import socket, ssl, time, hashlib, json

def send_frame(sock, frame: bytes, log):
    sock.sendall(frame)
    log.append({"dir":"C2S","len":len(frame),"sha256":hashlib.sha256(frame).hexdigest()})

def recv_frame(sock, n=4096):
    data = sock.recv(n)
    return data

# 1) 原样重放：逐字节发送抓包中的 C2S 帧
# 2) 记录响应长度/哈希/关键字段，与基线对比
# 3) 单变量构造：只改一个字段，预测后验证
```

- 发送前打印/落盘十六进制；接收按协议分帧，不要一次 `recv` 当一条消息。
- RTT、响应长度、响应哈希、业务码四项一起对比；只看“有响应”不够。
- 构造新请求至少重复 3 次，排除偶然；失败时保留请求字节与服务端错误码。
- 高频/并发/破坏性测试不属于本流程；需要时单独授权并限速。

**判据**：原样重放响应与基线一致（允许时间/nonce 字段变化且能解释）；单变量构造的响应符合预测。

## 5. 负例矩阵

| 变体 | 预期 | 观察 | 结论 |
|---|---|---|---|
| 改 1 字节 payload | 业务错误或校验失败 | 错误码/连接关闭 | 字段有效性与校验范围 |
| 改长度字段 +1 | 等待/拒绝 | 超时/错误码 | 长度覆盖范围 |
| 重放旧 nonce | 拒绝 | 错误码 | 防重放窗口 |
| 过期 token | 拒绝 | 401/业务码 | 会话生命周期 |
| 错 seq/乱序 | 拒绝或缓冲 | 丢包/重传 | 排序规则 |
| 去掉可选字段 | 默认值或拒绝 | 响应差异 | 字段必选性 |

每个变体只改一个变量；失败也要记录，负例和正例同样有价值。

**判据**：负例的拒绝方式与推断一致；不一致时优先修正模型，不要改结论措辞。

## 6. 状态机完成判据

- [ ] 至少一条完整闭环：握手/认证 → 业务 → 关闭。
- [ ] 每条迁移有样本或明确标 `INFERRED`。
- [ ] 请求/响应配对规则可复述，心跳/超时/重连有参数。
- [ ] 能构造服务端接受的新业务请求，并预测响应。
- [ ] 负例矩阵覆盖长度、校验、nonce、token、seq、必选字段。
- [ ] 他人按 `schema.md + replay.py` 能复跑，证据可回溯到帧号。
