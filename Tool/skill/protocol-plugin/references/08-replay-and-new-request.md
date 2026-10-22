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

## 8. 失败判据

- T1 都过不了 → 先查会话/网络/TLS，不要改字段表。
- T2 任何改动都被拒，且拒绝方式与"未知字段"一致 → 可能是签名/nonce/风控；按 `02-failure-criteria.md` 转签名定位。
- T2 成功但 T3 跑不通 → 缺状态推进条件（心跳、订阅、二次认证），回去补状态机。
- 3 次结果不一致且无法归因 → 先停止，收集 10 次样本做方差分析，不要"再试一次"。
- 出现越权读（换 id 读到他人数据）→ 立即停，按授权流程上报。

## 9. 边界

- 本节所有命令默认目标是 `127.0.0.1` / 授权靶场；生产环境只读。
- 重放 ≤5 rps；写操作按授权单；账号切换按 `scope` 清单。
- 构造新请求的目的是"证明理解协议"，不是"扩大影响"；拿到一个可预测的新请求即可停。
