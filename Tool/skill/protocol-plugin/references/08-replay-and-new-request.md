# 08 重放与新请求构造 — 从"能重放"到"能预测"

> 范围：已经有字段表（`05-binary-framing.md`）与会话模型（`06-app-state-machine.md`），
> 要验证"新请求能被接受"。
> 路由：插件/扩展目标由 `plugin-targets`（R25）承担；目标范围由 `scope` 声明（本节每一步都在授权清单内执行）。
> 判定标准见 `01-criteria.md`；停手条件见 `02-failure-criteria.md`。

## 1. 三个台阶，缺一不可

| 台阶 | 动作 | 通过判据 |
|---|---|---|
| T1 原样重放 | 把抓到的字节原封不动发一次 | 响应与基线一致（结构 + 关键字段） |
| T2 单变量构造 | 只改 1 个业务字段，长度/校验自动重算 | 响应符合预测，重复 3 次稳定 |
| T3 状态闭链 | 从握手/认证跑到业务再关闭 | 全程无人工介入，错误帧被正确处理 |

只到 T1 的，只能写"部分复刻：可重放"。T2 才是"理解协议"，T3 才是"能独立打一场"。

## 2. T1：原样重放（先证明链路与会话）

```bash
# HTTP 类：直接用原请求（保留 Host/UA/签名头顺序无关但值必须一致）
curl -i -X POST 'http://127.0.0.1:18080/v1/login' \
  -H 'Content-Type: application/json' \
  --data @artifacts/body.json

# 原始 TCP：把抓包里的载荷按帧写回 socket
python - <<'PY'
import socket, time
frame = bytes.fromhex(open('artifacts/frame1.hex').read().strip())
s = socket.create_connection(('127.0.0.1', 9527), timeout=3)
t0 = time.time(); s.sendall(frame)
data = s.recv(4096)
print('rtt_ms', round((time.time()-t0)*1000, 1), 'resp_hex', data.hex())
PY
```

记录：发送字节、响应字节、RTT、连接是否保持、响应 `sha256`。
**原样重放也要记录**，因为它是后面所有差异比较的基线。

## 2.1 重放器骨架（新建连接 / 按帧收 / 心跳 / 断言）

```python
# artifacts/replay.py —— 只改 HOST/PORT/header 偏移，其余不要改
import hashlib, json, socket, threading, time
HOST, PORT, TIMEOUT = "127.0.0.1", 9527, 3.0
HEADER_LEN, LEN_OFF, LEN_SIZE, TAIL = 12, 6, 2, 4      # 按 schema.json 改

class Link:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
        self.buf, self.log = b"", []

    def _rec(self, note):
        self.log.append({"dir": "C2S", "note": note, "len": len(note),
                         "sha256": hashlib.sha256(note).hexdigest()[:16]})

    def send(self, frame, note=""):
        self.s.sendall(frame)
        self._rec(note.encode() or frame)

    def recv_frame(self):
        while True:
            if len(self.buf) >= HEADER_LEN:
                plen = int.from_bytes(self.buf[LEN_OFF:LEN_OFF + LEN_SIZE], "big")
                need = HEADER_LEN + plen + TAIL
                if len(self.buf) >= need:
                    frame, self.buf = self.buf[:need], self.buf[need:]
                    self.log.append({"dir": "S2C", "len": len(frame),
                                     "sha256": hashlib.sha256(frame).hexdigest()[:16]})
                    return frame
            chunk = self.s.recv(4096)
            if not chunk:
                raise EOFError("peer closed at %d bytes buffered" % len(self.buf))
            self.buf += chunk

    def close(self):
        self.s.close()

def heartbeat(link, every=15.0, stop=None):
    while not stop.is_set():
        link.send(build_heartbeat(), "heartbeat")
        time.sleep(every)

def run():
    link = Link()
    stop = threading.Event()
    threading.Thread(target=heartbeat, args=(link, 15.0, stop), daemon=True).start()
    try:
        link.send(build_hello(), "hello")
        resp = link.recv_frame()
        assert b"hello_ack" in resp, "hello 未被接受：先查 version/caps"
        link.send(build_auth(next_token(), next_nonce()), "auth")
        resp = link.recv_frame()
        assert b"auth_ok" in resp, "认证失败：材料过期或绑定维度不符"
        link.send(build_data(seq=1, payload={"temp": 22.0}), "data")
        print("data_ack_len", len(link.recv_frame()))
    finally:
        stop.set(); link.close()
        print(json.dumps(link.log, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    run()
```

要点（每一条都对应一个失败模式）：

- **每次实验新建连接**：连接内重放会拿到被心跳/推送污染的响应。
- **按帧收而不是按 recv 收**：`recv` 边界不是消息边界。
- **每步有断言**：失败立即停，打印已缓冲字节，不用猜“卡在哪一步”。
- **心跳单独线程**：主流程阻塞在 `recv` 时心跳不能停，否则 30 s 后被踢。

通过长什么样（一次成功的最小输出）：

```text
data_ack_len 46
[{"dir": "C2S", "note": "hello", "len": 12, "sha256": "…"},
 {"dir": "S2C", "len": 24, "sha256": "…"},
 {"dir": "C2S", "note": "auth", "len": 68, "sha256": "…"},
 {"dir": "S2C", "len": 20, "sha256": "…"},
 {"dir": "C2S", "note": "data", "len": 52, "sha256": "…"},
 {"dir": "S2C", "len": 46, "sha256": "…"}]
```

## 3. T2：单变量构造（本域的核心动作）

用字段表驱动，避免手写长度/校验：

```bash
# 基线帧解析
python Tool/skill/protocol-plugin/scripts/proto-repro.py \
  --input artifacts/frames.bin --json

# 只改 type/seq + 换业务载荷，长度与 CRC 自动重算
python Tool/skill/protocol-plugin/scripts/proto-repro.py \
  --input artifacts/frames.bin --rebuild --frame-index 2 \
  --set type=4 --set seq=4 \
  --payload-text '{"temp":22.0,"status":"ok"}' \
  --out artifacts/new-frame.bin --json
```

输出里必须检查三项：

```text
rebuild.new_len        与字段表预测一致
rebuild.verify.parsed  true          # 能被同一张表解析回来
rebuild.verify.crc_ok  true          # 校验被重算且自洽
```

然后把它发出去，与**预测**比对：

| 预测项 | 怎么预测 | 实际记录 |
|---|---|---|
| 业务码/状态 | 由基线同 type 帧推断 | 响应字节 |
| 响应长度 | 由同 type 响应样本推断 | `len(resp)` |
| 关键字段 | 如 `data` 回显、`seq+1` | 字段 diff |
| 拒绝方式 | 若故意改错字段 | 断开/错误码/静默 |

判据：预测与实际一致（允许时间戳/nonce 等已列明的可变项），重复 3 次。

## 3.1 序号/时间戳/nonce 的自动续期（不写死材料）

| 材料 | 从哪拿 | 什么时候刷新 | 写死的后果 |
|---|---|---|---|
| token | 登录响应的字段 | 每次 401/过期 | 跑一遍就失效 |
| nonce | 上一响应或预取接口 | 每条请求前 | 第二次即拒 |
| 时间戳 | 本机 UTC，对齐服务端偏差 | 每帧 | 服务端时间窗拒 |
| seq | 会话内单调递增 | 每帧 +1 | 防重放窗口拒 |
| session id | 握手响应 | 重连后 | 串会话/读到他人数据（红线） |

```python
import calendar, json, time

def next_nonce(resp_bytes, schema):
    obj = json.loads(resp_bytes[HEADER_LEN:len(resp_bytes) - TAIL])
    return obj["nonce"]                     # 从响应取，不从常量取

def now_ts(offset_s=0):
    return int(time.time()) + offset_s      # 先测服务端容差，再决定要不要补偿

def bump(seq):
    return (seq + 1) & 0xFFFFFFFF           # 回绕按协议位宽，不要默认 32 位
```

自检：把“取材料→用材料”打成两步日志，确认每条请求的 nonce 都不相同：

```bash
python artifacts/replay.py > artifacts/run.json 2>&1; echo "rc=$?"
python -c "import json;d=json.load(open('artifacts/run.json'));print('nonces',len({x.get('sha256') for x in d}))"
```

通过长什么样：`rc=0`，且日志里 C2S 每条 `sha256` 互不相同（说明 nonce/seq 真的在变）。
若全部相同，说明你还在原样重放（T1），不是 T2/T3。

## 4. 单变量矩阵（一次只改一个）

| 变量 | 改法 | 期望 | 观察点 |
|---|---|---|---|
| 业务值 | `temp` 21.5 → 22.0 | 接受，回显新值 | 响应 payload |
| type | 3 → 4 | 未知 type 被忽略或报错 | 错误码/断开 |
| seq | 3 → 4（递增） | 接受 | 后续帧是否要求连续 |
| seq | 3 → 1（回退） | 拒绝（防重放） | 断开/错误帧 |
| length | +1 | 服务端等更多字节或截断 | 超时时间 |
| length | -1 | CRC 失败或截断 | 错误码 |
| crc | 翻转 1 位 | 拒绝 | 断开/错误帧 |
| magic | 改 1 字节 | 拒绝/重同步失败 | 断开 |
| 认证材料 | 旧 token | 401/错误帧 | 错误码 |
| 会话 id | 换一条连接的 id | 拒绝/串会话 | 是否读到别人数据（越权红线） |

最后一行是**红线**：一旦发现换 id 能读到别人的数据，立即停，保留证据，按授权流程上报；
不要继续扩大读取范围。

## 4.1 单变量矩阵的执行与记账

把 §4 的矩阵变成可重跑的实验，不是每次手改脚本：

```bash
for v in "temp=22.0" "temp=99.9" "temp=-1" "temp=abc"; do
  k=${v%%=*}; val=${v#*=}
  python Tool/skill/protocol-plugin/scripts/proto-repro.py --input artifacts/frames.bin \
    --rebuild --frame-index 2 --payload-text "{\"$k\":\"$val\",\"status\":\"ok\"}" \
    --out artifacts/v_$val.bin --json > artifacts/v_$val.json && echo "built $v"
done
```

通过长什么样：4 个 `built` + 4 个 `rebuild.verify.crc_ok=true`。
每个变体发一次（新建连接），把“预测/实际”填进 §3 的表：**接受集**与**拒绝集**都要能解释。

注意：`--set` 改不了 `role=length` 的字段（构造器重算），想测长度负例看
`05-binary-framing.md` §2.1 的字节补丁法。

## 5. T3：状态闭链脚本骨架

```python
# 伪代码：握手 → 认证 → 业务 → 关闭，每步都有超时与断言
def run(host, port):
    s = connect(host, port)
    send(s, build("hello", ver=1, caps=0x03)); assert_state(s, "hello_ack")
    send(s, build("auth", token=tok(), nonce=next_nonce())); assert_state(s, "auth_ok")
    send(s, build("data", seq=1, payload={"temp": 22.0})); assert_state(s, "data_ack")
    send(s, build("close")); assert_closed(s)
```

要点：

- 每一步都有**超时**（默认 3 s）和**断言**，失败即停并 dump 最后 4 KB 字节。
- token/nonce 通过前置步骤获取，不写死；拿不到就报 `blocked_at: "auth"`。
- 心跳单独线程，周期取自 `06-app-state-machine.md` 的实测值。
- 全程只对本地/授权端点；并发 1，请求间隔 ≥200 ms。

## 6. 差异归因（响应不一样时先归因再改模型）

| 差异 | 先查 | 再查 |
|---|---|---|
| 状态码不同 | 会话是否过期 | 请求头/签名是否缺字段 |
| 响应长度不同但结构相同 | 时间戳/nonce/随机 id | 分页/截断参数 |
| 完全不同的错误页 | WAF/风控 | 端点是否被灰度切换 |
| 连接被立即关闭 | TCP 层被拒（端口/协议） | 应用层校验失败（magic/CRC） |
| 超时无响应 | 服务端在等更多字节（长度改大） | 抓包点看不到回程 |

归因顺序：**环境 → 会话 → 时间 → 协议**。跳过前三步直接改协议模型，是最常见的浪费。

## 6.1 差异归一化：把“不一样”拆成“可变项 + 真差异”

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
python - <<'PY'
import json, pathlib
VAR = {"ts", "timestamp", "nonce", "sid", "request_id", "trace_id"}
def load(p):
    return json.loads(pathlib.Path(p).read_text(encoding="utf-8"))
a, b = load("artifacts/predicted.json"), load("artifacts/actual.json")
norm = lambda d: {k: ("<var>" if k in VAR else v) for k, v in d.items()}
diff = {k: (norm(a).get(k), norm(b).get(k)) for k in set(a) | set(b)
        if norm(a).get(k) != norm(b).get(k)}
business = {k: v for k, v in diff.items() if k not in VAR}
print("diff", diff)
print("business_diff", business, "match", not business)
PY
```

通过长什么样：`match True` + `business_diff {}`；只有 `<var>` 项不同是正常的。
若 `business_diff` 非空，先按 §6 的顺序归因（环境→会话→时间→协议），不要直接改字段表。

## 7. 证据包（交付时一并给出）

```text
artifacts/
  frames.bin            原始帧（来自抓包或导出流）
  schema.json           字段表
  new-frame.bin         构造的新帧
  run.json              {cmd, rc, stdout, 时间, 环境}
  responses/            每次重放的响应字节 + sha256
  diff.md               预测 vs 实际，逐项
```

`run.json` 至少要有 `cmd` 与 `rc`；案例库（`Tool/cases/protocol*`）就是用这个格式复算判据的。

## 7.1 证据包机检（交付前 30 秒）

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
python - <<'PY'
import hashlib, json, pathlib
need = ["artifacts/schema.json", "artifacts/new-frame.bin", "artifacts/run.json"]
miss = [p for p in need if not pathlib.Path(p).is_file()]
run = json.loads(pathlib.Path("artifacts/run.json").read_text(encoding="utf-8")) if not miss else {}
ok_run = bool(run.get("cmd")) and run.get("rc") == 0
resp = sorted(pathlib.Path("artifacts/responses").glob("*")) if pathlib.Path("artifacts/responses").is_dir() else []
print("miss", miss, "run_ok", ok_run, "responses", len(resp))
print("pack_ok", not miss and ok_run and len(resp) >= 3)
PY
```

通过长什么样：`miss [] run_ok True responses 3` + `pack_ok True`。
少于 3 份响应就不能写“重复 3 次稳定”（对应 `01-criteria.md` 采样量下限）。

## 8. 失败判据

- T1 都过不了 → 先查会话/网络/TLS，不要改字段表。
- T2 任何改动都被拒，且拒绝方式与"未知字段"一致 → 可能是签名/nonce/风控；按 `02-failure-criteria.md` 转签名定位。
- T2 成功但 T3 跑不通 → 缺状态推进条件（心跳、订阅、二次认证），回去补状态机。
- 3 次结果不一致且无法归因 → 先停止，收集 10 次样本做方差分析，不要"再试一次"。
- 出现越权读（换 id 读到他人数据）→ 立即停，按授权流程上报。

## 8.1 客户端复刻的等价性验收（差分测试）

不要拿“我觉得一样”验收，拿两份归一化 trace 对比：

```text
# trace.jsonl，一行一步；原客户端与复刻客户端跑同一剧本
trace-normalize.py client.log > artifacts/trace_orig.jsonl
trace-normalize.py replica.log > artifacts/trace_replica.jsonl
diff artifacts/trace_orig.jsonl artifacts/trace_replica.jsonl && echo "equivalent"
```

归一化只允许抹掉：时间戳、nonce、随机 id、TCP 分片位置。**需要先确认**抹掉：字段名、枚举值、
长度、校验、消息顺序。抹多了就是“把差异藏起来”，比不复刻更糟。

通过长什么样：

```text
equivalent
```

不等价时按行定位：`<` 是原客户端、`>` 是复刻端；差在字段→语义错；差在长度→分帧/编码错；
差在顺序→状态机错；差在多出一条→心跳/重连未对齐。

## 9. 边界

- 本节所有命令默认目标是 `127.0.0.1` / 授权靶场；生产环境只读。
- 重放 ≤5 rps；写操作按授权单；账号切换按 `scope` 清单。
- 构造新请求的目的是"证明理解协议"，不是"扩大影响"；拿到一个可预测的新请求即可停。

## 这一篇算"用对了"吗

- [ ] 三个台阶分开报：T1/T2/T3 各自通过还是卡住，没有把 T1 写成"已复刻"。
- [ ] T2 是单变量，长度/校验由构造器重算，记录了三项 `rebuild.verify`。
- [ ] token/nonce/seq 都从响应取，脚本里没有写死材料；重连后重新取。
- [ ] 每次实验新建连接、带心跳、有超时与断言，失败时 dump 了最后字节。
- [ ] 差异先归一化再归因，`business_diff` 为空才算"符合预测"。
