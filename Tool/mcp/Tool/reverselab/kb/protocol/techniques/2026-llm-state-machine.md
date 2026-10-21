# 2026 战例：LLM 推断协议状态机的验收口径

> 战例 KB-PROTO-2026-05 · 收录 2026-10-20 · 单篇 ≤200 行 · 只写“怎么验 LLM 给的 FSM”，不复述分帧。

## 来源与日期

- RFCLLM（2026-09 预印本）：用 LLM 从 RFC/抓包生成协议状态机，报告在“未见实现”上的迁移召回。
- PSMBENCH（Protocol State Machine Benchmark，2026-06 起公开）：给 LLM 的 FSM 输出打三个分：
  迁移覆盖、非法迁移、与 pcap 的一致性。
- 结论口径：LLM 输出只能当**候选集**，必须用抓包与构造实验逐边验收；没有 pcap 支撑的边一律标 `INFERRED`。
- 本页为公开材料蒸馏，未附本机跑分；字段名沿用 PSMBENCH 的机器可读报告。

## 场景

入口信号：

- 已能分帧、校验可复算，但会话层的“下一步该发什么”靠猜。
- 有人（或模型）给出一张状态机图/JSON，想直接拿来写 replay 或 fuzz。
- 抓包只覆盖 happy path，握手/错误/重协商分支缺失。
- 需要回答：某条边是真的协议行为，还是模型按常识编的。

先分类 LLM 产出的每一条边：

| 边类型 | 定义 | 允许的用法 |
| :-- | :-- | :-- |
| `OBSERVED` | 在 pcap 中至少出现一次（方向、前驱、后继都对得上） | 可写进结论、可构造 |
| `INFERRED` | 无 pcap 证据，由 RFC 文本/模型常识推出 | 只能进“待验证”，不得写入判据 |
| `REFUTED` | 有反例（该迁移下服务端拒绝/重置） | 写进失败表，防止回归 |

## 命令

```bash
# 0) 先有字节与帧，再谈状态机
python Tool/skill/protocol-plugin/scripts/pcap-summary.py \
  --file capture.pcapng --json --extract artifacts/streams
python Tool/skill/protocol-plugin/scripts/proto-repro.py --input artifacts/streams/s00_*.bin --json

# 1) 抽出“观测边”：按会话方向排序 (src,prev_msg,next_msg)
python - <<'PY'
import json, collections
ev = json.load(open('artifacts/streams/sessions.json'))
edges = collections.Counter()
for s in ev['sessions']:
    msgs = [m['type'] for m in s['messages']]
    for a, b in zip(msgs, msgs[1:]):
        edges[(s['client'], a, b)] += 1
print(len(edges)); [print(k, v) for k, v in edges.most_common(10)]
PY

# 2) LLM 给的 FSM 落成 JSON，与观测边做集合运算
python - <<'PY'
import json
obs = {tuple(x) for x in json.load(open('artifacts/observed_edges.json'))}
llm = {tuple(x) for x in json.load(open('artifacts/llm_fsm.json'))['edges']}
print('covered', len(obs & llm), '/', len(obs))
print('llm_only', sorted(llm - obs)[:10])
print('missing', sorted(obs - llm)[:10])
PY

# 3) 对每条 llm_only 边做单变量构造（预测→发送→比对）
python Tool/skill/protocol-plugin/scripts/proto-repro.py \
  --input artifacts/streams/s00_*.bin --schema artifacts/fsm_schema.json --rebuild \
  --out artifacts/rebuild --json

# 4) 复算本域案例判据（含 rc 与 sha256）
python Tool/skill/protocol-plugin/scripts/proto-accept.py --json
```

## 判据表

| 字段 | 含义 | 成立阈值 | 证据 |
| :-- | :-- | :-- | :-- |
| `edge_coverage` | `|OBSERVED ∩ LLM| / |OBSERVED|` | 声明“复刻”需 ≥0.95；<0.80 只算“部分理解” | `edges.json` |
| `llm_unverified` | LLM 独有且未被构造实验证实的边数 | 结论中必须为 0；>0 时逐条列 id | `unverified.json` |
| `edge_state` | 每条边 `OBSERVED/INFERRED/REFUTED` | 判据表只引用 `OBSERVED`；`REFUTED` 单列 | FSM JSON |
| `prediction_hit` | 构造后服务端响应与预测一致的比例 | ≥3 条边、每边 ≥3 次，≥9/12 命中 | `rebuild/*.log` |
| `negative_edge` | 非法迁移（跳步/乱序）是否被拒 | 至少 1 条被明确拒绝（错误码/断开），否则状态机不可信 | `negative.log` |
| `session_scope` | 覆盖的会话数/方向 | ≥2 个独立会话，双向都有边 | `sessions.json` |
| `heldout_check` | 留出的 pcap 上重算 `edge_coverage` | 留出集 ≥0.80，且无新增 `REFUTED` | `heldout.json` |

`--rebuild` 的输出必须能被同一张表解析回 `crc_ok=true`；否则是“能重放不能构造”，
状态机结论降级为“观测序列”，不给迁移语义。

## 失败判据

- LLM 输出没有边级 id / 没有 `state,event,next` 三元组 → 不可验收，退回人工标注。
- `edge_coverage` 用训练集算、留出集不测 → 分数无效（PSMBENCH 的核心批评点）。
- 构造实验只有“服务端没断”而没有响应字段比对 → 不算 `prediction_hit`。
- 同一迁移在两次会话里结果不同，且未定位到 nonce/时间/会话态 → 标 `flaky`，不写进 FSM。
- 把 `INFERRED` 边当 `OBSERVED` 写进报告 → 直接判否（`llm_unverified` 造假）。
- 非法迁移也被接受，且服务端无错误码 → 说明抓的是“宽松解析器”，迁移语义不成立。
- 需要伪造他人会话/绕过认证才能补齐边 → 停，越界。

> 边界：LLM 只做候选生成，不做“协议事实”来源；`INFERRED` 永不进判据表；
> 留出集必须来自不同实现/版本，且抓包时点晚于 FSM 生成时点（防泄漏）。

## 与 reference 的关系

- 状态机方法：[06-app-state-machine.md](../../../../../../../Tool/skill/protocol-plugin/references/06-app-state-machine.md)。
- 重放与构造：[08-replay-and-new-request.md](../../../../../../../Tool/skill/protocol-plugin/references/08-replay-and-new-request.md)。
- 失败判据：[02-failure-criteria.md](../../../../../../../Tool/skill/protocol-plugin/references/02-failure-criteria.md)。
- 同 board 邻近篇：[capture-to-replay.md](capture-to-replay.md)（会话台账）、
  [failure-criteria.md](failure-criteria.md)（卡点分类）、
  [real-pcap-drills.md](real-pcap-drills.md)（用真实 pcap 练留出集切分）。
