# 06 应用层协议与状态机 — 服务端为什么接受下一帧

> 范围：需要重建"握手 → 认证 → 业务 → 关闭"的会话型协议（私有 TCP/UDP、WebSocket、
> 数据库线协议、工控轮询、MQTT 等）。
> 路由：无状态单请求接口只看 `01-criteria.md`；插件加载链按 `Tool/playbooks/plugin-analysis.md` 分析。
> 分帧见 `05-binary-framing.md`；重放与构造见 `08-replay-and-new-request.md`。

## 1. 先把会话切片

```bash
# 1) 会话清单（谁和谁）
tshark -r capture.pcapng -q -z conv,tcp

# 2) 按流取帧级载荷（仍须按方向和 TCP 序号处理重传/乱序）
tshark -r capture.pcapng -Y "tcp.stream==3 && tcp.len>0" -T fields \
  -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport \
  -e ip.dst -e tcp.dstport -e tcp.seq -e tcp.len -e tcp.payload > stream3.tsv

# 3) 无 tshark 时按方向性五元组导出包载荷拼接
python Tool/skill/protocol-plugin/scripts/pcap-summary.py \
  --file capture.pcapng --json --extract artifacts/streams
```

切片的硬规则：

- 按 `tcp.stream`，不是按五元组（端口会复用）。
- 一个 stream 里若有 TLS 握手 + 明文，先按"加密起点"切成两段（见 `07-crypto-and-checksum.md`）。
- 重传/乱序不产生重复消息：用 `tcp.seq` 去重，不要用"内容相同"去重。

## 2. 消息台账（一行一条消息）

```json
{"id":"m12","stream":3,"frame":88,"ts":1720000000.123,"dir":"C2S",
 "state_before":"AUTH","event":"auth_request","state_after":"AUTH_WAIT",
 "fields":{"uid":1001,"token_len":32,"nonce":"7f3a"},"bytes_sha256":"...","evidence":"capture#frame 88"}
```

要求：

- `id` 与 `frame` 双向可查（报告里写 `m12` 就能定位到帧）。
- `fields` 只写**解析得出**的值；解不出的写 `"_raw_hex": "..."`，不要猜。
- 每条消息带 `bytes_sha256`，用于"同输入同输出"比对（避免逐字节 diff 噪声）。

## 3. 状态图：观测边 vs 推断边

```text
INIT --hello(ver,cap)--> HELLO_SENT
HELLO_SENT --hello_ack(ver,cap,session)--> READY          [observed m1,m2]
READY --auth(token,nonce,ts)--> AUTH_WAIT                 [observed m3]
AUTH_WAIT --auth_ok(session,token2)--> AUTHED             [observed m4]
AUTHED --subscribe(topic)--> SUBSCRIBED                   [observed m5]
SUBSCRIBED --data(seq,payload)--> SUBSCRIBED              [observed m6..m40]
SUBSCRIBED --heartbeat(ts)--> SUBSCRIBED                  [observed m41,m61]
* --error(code,msg)--> ERROR                              [INFERRED：未构造非法帧]
ERROR --close()--> CLOSED                                 [INFERRED]
```

规则：

- **没有样本的边标 `INFERRED`**，不要画成实线；报告里要分开列。
- 请求/响应配对优先用 `request_id`/`seq`；没有就用"同 stream 的下一条反向消息"，并标注不确定性。
- 心跳、超时、重连是状态推进的一部分：记录周期、抖动、退避策略。
- 错误码要能解释"为什么拒绝"，只记录"失败了"没有价值。

判据：给定一条**新**消息序列，能预测下一个合法状态；非法迁移要有实际拒绝证据。

## 3.1 自动推断 + 边覆盖率

手工推边漏得快，让模型"看图说边"又容易编。两条路要分开记来源：

| 传统（可机检） | 自动 / LLM 辅助（须复核） |
|---|---|
| 报文聚类：同长度/同前缀/同间隔聚成消息族 | LLM 读帧序列，直接给"状态名 + 迁移"候选 |
| 字段边界：偏移/长度/端序拟合（见 `05-binary-framing.md`） | LLM 给字段语义与长度猜测 |
| 请求-响应配对：`request_id`/`seq`/反向下一条 | LLM 给配对关系与"是否必需前置" |
| 边的依据是 `frames.jsonl` 里的实帧号 | 边的依据是先验知识，**没有帧号** |

自动方法的"评估方式"照抄这三条即可落地：

- **RFCLLM**（arXiv 2609.13389，2026-09）：把协议理解写成判别式任务打分——给定报文预测
  下一条消息/下一个状态是否成立，而非让模型自由生成散文。
- **PSMBENCH**（NeurIPS'25 / 2026）：协议逆向基准集，逐边计 exact-match 与迁移准确率。
- **USENIX Security 2026 对抗式 LLM 生成格式规范**：攻击方 LLM 生成候选格式规范、解析方按规范
  解析，以"解析成功率是否提升"判定规范真假——本质是把 LLM 输出当**假设**，再用解析器证伪。

硬规则（违反即降档，不是措辞问题）：

- LLM 只能产出**候选边**：每条带 `"source":"llm"`，报告里标 `inferred`。
- **未观测边不得画成实线**：图上用虚线/`INFERRED`，报告里单列，不混进观测边计数。
- 边覆盖率 `edge_coverage = observed_edges / inferred_edges`（推断边 = 候选边全集）；
  **<60% 不得声称状态机成立**，只能写"部分建模，覆盖率 X%"。
- `llm_unverified` 单独计数：LLM 给的边在拿到真实帧号前，永远只是未验证。

机检（纯标准库，不用 tshark）：

```bash
python Tool/skill/protocol-plugin/scripts/pcap-summary.py \
  --state-model artifacts/edges.json --json
# -> observed_edges / inferred_edges / edge_coverage / unobserved[] / llm_unverified[] / verdict
```

输入形状：`{"illegal_transition_proof":"...","edges":[{"from","to","evidence_frame"}]}`。
`evidence_frame` 为 `null`/`0` 即"未观测"；形状错误或文件缺失一律 rc=2（`ok:false`）。
这些帧号和负例均为输入声明；脚本不验证帧是否存在或证明迁移，即使同时传 `--file` 也只附上抓包摘要。`claims_allowed` 恒为 false，实际结论须回到原始帧、消息语义和负例运行记录复核。

判据字段（缺一整列不得写"状态机成立"）：

| 字段 | 含义 | 成立线 |
|---|---|---|
| `observed_edges` | 输入中填了正帧号的边数（未校验） | 逐条回原始样本确认迁移 |
| `inferred_edges` | 候选边全集（含 LLM 推断） | 与观测边分列报数，不得合并 |
| `edge_coverage` | 观测 / 推断 | **≥0.60** |
| `llm_unverified` | LLM 给出但无帧号的边 | 必须为 0 才可写"已确认"，否则降"疑似" |
| `illegal_transition_proof` | 输入中是否填写了负例说明（未校验） | 核对真实帧、行为和运行记录，负例见 §5 |

出处：RFCLLM（arXiv 2609.13389，2026-09）、PSMBENCH（NeurIPS'25 / 2026）、
USENIX Security 2026 对抗式 LLM 生成格式规范。LLM 只负责提假设，证伪永远靠帧。

## 3.2 从 `frames.jsonl` 提候选边（脚本只提"候选"，不命名状态）

手工读几十帧会漏边。先用字节级邻接把候选边提出来，再人工/LLM 命名并回填帧号：

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
python - <<'PY'
import collections, json, pathlib
rows = [json.loads(l) for l in pathlib.Path("artifacts/streams/frames.jsonl")
        .read_text(encoding="utf-8").splitlines() if l.strip()]
rows = sorted([r for r in rows if r["payload_len"] > 0], key=lambda r: r["ts"])
edges, prev = collections.Counter(), None
for r in rows:
    node = "%s>%s/len%d" % (r["sport"], r["dport"], r["payload_len"])
    if prev:
        edges[(prev, node)] += 1
    prev = node
print("nodes", len({n for e in edges for n in e}), "edges", len(edges))
for (a, b), c in edges.most_common(5):
    print(c, a, "=>", b)
PY
```

通过长什么样：

```text
nodes 4 edges 4
4 44380>8080/len54 => 8080>44380/len51
3 8080>44380/len51 => 44380>8080/len54
1 44380>8080/len187 => 8080>44380/len129
```

读法：`len54=>len51` 往返 4 次，是**请求-响应配对**的强线索（`54` 含 2 B 帧头 + 4 B mask）；
`len187=>len129` 只出现一次，对应 HTTP Upgrade 握手。这些节点是"帧长形态"，不是状态名；
命名必须靠 §2 的消息台账，且每条边要补 `evidence_frame`。

- 不要把这 4 条边直接写成 `INIT→READY→AUTHED`：那是先验，不是观测。
- `nodes` 少而 `edges` 多，说明同一形态承载多种语义（多半是 protobuf/TLV），先回去分字段。

## 4. 认证与会话材料

| 材料 | 观察点 | 重放陷阱 |
|---|---|---|
| token/cookie | 登录响应、后续每帧头 | 过期、绑定 IP/UA/设备指纹 |
| nonce | 请求头/体，一次性或窗口内有效 | 二次使用被拒；需串成"取 nonce → 发请求" |
| 时间戳 | 4/8 字节，秒/毫秒 | 单位、时区、允许偏差（常见 ±300s） |
| 签名/MAC | 尾部或头字段 | 覆盖范围、密钥版本、字段排序 |
| session id | 握手响应 | 并发互踢、会话表上限 |
| 证书/mTLS | TLS 握手 | 代理无法单边解密 |

做法：把"取材料 → 用材料"的两步写进脚本，而不是把材料写死。
材料过期就重跑第一步；这一步能自动化，才叫"可复刻"。

## 4.1 重放窗口与时间窗：用二分法测出来，不要猜

| 实验 | 构造 | 可能的结论 | 记录 |
|---|---|---|---|
| seq 回退 1 | `seq-1` | 接受 = 不检查 / 拒绝 = 单调检查 | 响应码 + 是否断开 |
| seq 回退 8 / 32 | `seq-8`、`seq-32` | 拒绝且仅小回退被拒 = 有窗口 | 窗口下界 |
| seq 跳跃 +8 | `seq+8` | 接受 = 只查单调，不查连续 | 后续帧是否要求连续 |
| 时间戳 -60s / -300s / -3600s | 改 ts 字段 | 拒绝 = 有 ±N 秒窗口 | 用二分找边界 |
| 同 nonce 立即重放 | 原样再发 | 拒绝 = 一次性 | 第二次响应 |
| 同 nonce 60s 后重放 | 延迟 | 接受 = 有 TTL 缓存 | TTL 上界 |

```bash
# 只改 seq，长度/CRC 由构造器重算（本地靶场，每次新建连接）
for s in 1 2 3 7 11 35; do
  python Tool/skill/protocol-plugin/scripts/proto-repro.py --input artifacts/frames.bin \
    --rebuild --frame-index 2 --set seq=$s --out artifacts/seq_$s.bin --json >/dev/null && echo "built $s"
done
```

通过长什么样（这是"实验矩阵已就绪"，不是结论）：

```text
built 1
built 2
built 3
built 7
built 11
built 35
```

判据：窗口/时间容差必须给出**具体数值与来源**（哪两个点被拒/被收）。只写"有防重放"不合格，
因为"有防重放"不能指导复刻客户端；"窗口 8、时间容差 ±300s、nonce TTL 120s"才可以。

## 5. 状态机的负例实验（最容易被跳过）

| 实验 | 期望 | 说明 |
|---|---|---|
| 跳过 hello 直接 auth | 拒绝/断开 | 证明 hello 是必需前置 |
| 错 version | 拒绝或降级 | 证明版本协商真实存在 |
| 重放旧 nonce | 拒绝 | 证明防重放窗口 |
| 错 seq（回退/跳号） | 拒绝或丢弃 | 证明 seq 被检查 |
| 错 CRC | 断开/错误帧 | 证明校验真的被校验 |
| 业务 id 越权 | 拒绝/空结果 | 证明服务端做了对象级校验 |
| 超长 payload | 拒绝/截断 | 证明长度上限 |

每个实验记录：发送字节、响应字节、RTT、连接是否保持。
没有负例的状态图只是"故事"，不是模型。

## 6. 时序与并发

- **并发**：同一账号两条连接会不会互踢？用两条脚本同时连，看响应。
- **顺序**：响应是否严格按请求顺序？HTTP/2 多路复用会乱序，必须按 streamid 归属。
- **超时**：空闲多久被断开？重连是否要重新认证？
- **重试**：业务失败时客户端重试几次、间隔多少？重试是否带同一个 request_id（幂等键）？

这些参数直接决定重放脚本要不要多线程、要不要保活。

## 6.1 心跳与超时的测量（样本 ≥5 个周期）

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
python - <<'PY'
import json, pathlib, statistics
rows = [json.loads(l) for l in pathlib.Path("artifacts/streams/frames.jsonl")
        .read_text(encoding="utf-8").splitlines() if l.strip()]
ka = [r["ts"] for r in rows if 0 < r["payload_len"] <= 32]   # 心跳通常是短帧
d = [round(b - a, 3) for a, b in zip(ka, ka[1:]) if b > a]
print("samples", len(d), "median", statistics.median(d) if d else None)
print("min", min(d) if d else None, "max", max(d) if d else None)
PY
```

通过长什么样：

```text
samples 5 median 15.0
min 14.8 max 15.6
```

读法：`median 15.0` + 抖动 <5% → 心跳 15 s，重放脚本按 15 s 发；`samples <5` 不足以结论，
去抓一条 ≥2 分钟的长会话。超时阈值另有实验：空闲不发任何帧，记录被断开的秒数（重复 3 次）。

## 7. 状态机落地成代码

```python
# 最小骨架：状态 + 合法迁移表 + 每个状态要发的消息
LEGAL = {
    "INIT": {"hello": "HELLO_SENT"},
    "HELLO_SENT": {"hello_ack": "READY"},
    "READY": {"auth": "AUTH_WAIT"},
    "AUTH_WAIT": {"auth_ok": "AUTHED", "auth_fail": "READY"},
    "AUTHED": {"subscribe": "SUBSCRIBED", "close": "CLOSED"},
    "SUBSCRIBED": {"data": "SUBSCRIBED", "heartbeat": "SUBSCRIBED", "close": "CLOSED"},
}
```

把这张表写成断言：收到某消息时，`state_after == LEGAL[state_before][event]`；
不合法就记 `UNEXPECTED` 并停下（说明模型缺边）。这比"看图说话"可靠。

## 7.1 迁移表 → 断言（表驱动，别手写 if 树）

```json
{"states": ["INIT", "READY", "AUTHED", "CLOSED"],
 "legal": {"INIT": {"hello": "READY"}, "READY": {"auth": "AUTHED"},
           "AUTHED": {"data": "AUTHED", "close": "CLOSED"}}}
```

```bash
python - <<'PY'
import json, pathlib
tbl = json.loads(pathlib.Path("artifacts/legal.json").read_text(encoding="utf-8"))
log = [("INIT", "hello", "READY"), ("READY", "auth", "AUTHED"),
       ("AUTHED", "data", "AUTHED"), ("AUTHED", "close", "CLOSED")]
bad = [(s, e, want, tbl["legal"].get(s, {}).get(e))
       for s, e, want in log if tbl["legal"].get(s, {}).get(e) != want]
print("steps", len(log), "unexpected", bad)
print("model_ok", not bad)
PY
```

通过长什么样：`steps 4 unexpected []` + `model_ok True`。
`unexpected` 非空不是"程序错了"，而是**模型缺边**：回 `frames.jsonl` 找那条消息，补边或改表。
这就是"状态机落地成代码"的可机检版本——比画图可靠，也比人眼读日志快。

## 8. 失败判据

- 关键迁移（认证/订阅）没有样本，只能靠猜 → 停止写"状态机"，改抓一条完整会话。
- 同一请求 3 次响应差异无法解释 → 先排查状态/并发/时间，不要归因到"协议随机"。
- 负例全部"无响应" → 可能抓包点在客户端侧或被中间件吞掉，换服务端侧抓包。
- 心跳周期/超时无法测得 → 用长会话（≥5 个周期）观察，别用 10 秒抓包下结论。

## 9. 边界

- 本节描述"怎么建模"，不描述"怎么打"；越权验证只在授权范围做。
- 生产环境默认只读；状态推进类实验（重放/构造）只在本地或靶场。
- 与 `05-binary-framing.md` 的分工：那里管字节边界，这里管消息语义与推进条件。

## 这一篇算"用对了"吗

- [ ] 消息台账每条都有 `state_before/event/state_after` 与帧号，`fields` 里没有猜出来的值。
- [ ] 观测边与 `INFERRED` 边分列；`edge_coverage` 与 `llm_unverified` 都报了数。
- [ ] 认证材料写清了来源、有效期、绑定维度、是否一次性，并做了过期/复用实验。
- [ ] §5 的 7 类非法迁移至少做了 3 类，且记录的是"拒绝方式"而不是"失败了"。
- [ ] 心跳周期、超时阈值、重连退避有实测数值（不是"大概是 30 秒"）。
