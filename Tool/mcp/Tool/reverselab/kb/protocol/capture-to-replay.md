# 从抓包到重放：状态机与单变量构造

> 核心问题：**服务端为什么接受下一帧？**
> 先原样复现，再单变量构造；每次改动保留基线、原始字节与响应哈希。

## 1. 会话切片

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
 "fields":{"uid":1001,"token_len":32,"nonce":"..."},"evidence":"capture#frame 88"}
```

**判据**：消息 id 与帧号/流偏移双向可查；重传不产生重复消息。

## 2. 画观测到的迁移

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

- 每条边附 ≥1 条样本；无样本标 `INFERRED`，不画实线。
- 请求/响应优先用 `request_id`/`seq` 配对；没有就“同流下一条反向消息”并标注。
- 心跳/重连/超时是状态推进的一部分，记录周期、抖动、重试。
- 错误码要解释“为什么拒绝”，不是只记录失败。

**判据**：给定新序列能预测下一合法状态与非法迁移；非法迁移有实际拒绝证据。

## 3. 认证材料

| 材料 | 观察点 | 重放陷阱 |
|---|---|---|
| token/cookie | 登录响应、后续头 | 过期、绑定 IP/UA/设备 |
| nonce/seq | 头/体、递增或随机 | 一次性、窗口、回显 |
| 时间戳 | 头 4/8 字节 | 时区、秒/毫秒、允许偏差 |
| 签名/MAC | 尾/头字段 | 覆盖范围、密钥版本、排序 |
| 会话 id | 握手响应 | 会话表、并发互踢 |
| 证书/mTLS | TLS 握手 | 代理不能单边解密 |

先“同会话原样重放”确认 token/seq 是否消耗；需要新会话时按握手→认证→业务完整重放。
**判据**：能区分会话过期、nonce 重放、签名不匹配、权限不足四类失败。

## 4. 重放骨架

```python
import socket, ssl, hashlib

def send(sock, frame, log):
    sock.sendall(frame)
    log.append({"dir":"C2S","len":len(frame),"sha256":hashlib.sha256(frame).hexdigest()})

def recv(sock, n=4096):
    return sock.recv(n)

# 1) 逐字节原样重放 C2S 帧
# 2) 对比响应长度/哈希/业务码
# 3) 单变量构造：只改一个字段，预测后验证
```

- 发送前落盘十六进制；接收按协议分帧，不能一次 `recv` 当一条消息。
- 对比四项：RTT、响应长度、响应哈希、业务码。
- 新请求重复 3 次排除偶然；失败保留请求字节与错误码。
- 高频/并发/破坏性测试需单独授权并限速。

**判据**：原样重放与基线一致（时间/nonce 变化可解释）；单变量响应符合预测。

## 5. 负例矩阵

| 变体 | 预期 | 观察 | 结论 |
|---|---|---|---|
| 改 1 字节 payload | 业务错/校验失败 | 错误码/关闭 | 字段有效性与校验范围 |
| 长度 +1 | 等待/拒绝 | 超时/错误码 | 长度覆盖 |
| 重放旧 nonce | 拒绝 | 错误码 | 防重放窗口 |
| 过期 token | 拒绝 | 401/业务码 | 会话生命周期 |
| 错 seq/乱序 | 拒绝/缓冲 | 丢包/重传 | 排序规则 |
| 去掉可选字段 | 默认/拒绝 | 响应差异 | 字段必选性 |

每个变体只改一个变量；负例和正例同样有价值。
**判据**：拒绝方式与模型一致；不一致先修模型，不改措辞。

## 6. 完成检查表

- [ ] 握手/认证 → 业务 → 关闭至少一次闭环。
- [ ] 每条迁移有样本或标 `INFERRED`。
- [ ] 配对规则、心跳/超时/重连参数可复述。
- [ ] 能构造服务端接受的新业务请求并预测响应。
- [ ] 负例覆盖长度、校验、nonce、token、seq、必选字段。
- [ ] 他人按 `schema.md + replay.py` 能复跑。
