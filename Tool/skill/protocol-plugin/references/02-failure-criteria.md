# 02 失败判据表 — 看到什么就停、停在哪、改走哪条

> 范围：协议复刻过程中判断"这条路是不是死了"，以及死了之后换哪条。
> 路由：插件装载链按 `Tool/playbooks/plugin-analysis.md` 分析；算法还原组合 `softseep` / `unpack-loop`。
> 判据表见 `01-criteria.md`；流程见 `../SKILL.md`。
>
> 本表的"停"不是放弃，而是**换观测层**：网络层抓不到 → 进程内取明文 → 静态反推格式。
> `--extract` 仅按方向性五元组及抓包顺序拼载荷，并非 TCP 重组；先按连接、方向、序号处理乱序、重传、重叠和缺口，无法核实则保留限制，不能据此声称分帧可靠。
> 每条都给代价（时间/风险），避免在一条死路上烧掉整场。

## 0. 判定口径

| 档位 | 触发条件 | 动作 |
|---|---|---|
| 硬停 | 越权、风控封禁、需要他人凭据 | 立刻停，保留证据，不改账号绕过 |
| 软停 | 同一手段连续 2 次无新信息 | 换观测层，不再堆参数 |
| 降档 | 只有 1–2 帧样本或单次现象 | 结论降为"疑似"，不写"确认" |

## 1. 失败判据表

| 现象 | 判定 | 改走哪条 | 代价 |
|---|---|---|---|
| 连续 2 次抓包，`data.data`/`tcp.len` 全为 0 | 抓包点选错（网卡/命名空间/容器 veth）或流量走代理/加密 | 换网卡枚举 `tshark -D`；容器内抓 `eth0` 而非宿主；必要时 `SSLKEYLOGFILE` | 低：10 分钟，重抓即可 |
| 只有 TLS 记录层，无应用层明文 | 无 keylog / pinning / mTLS | 先设 `SSLKEYLOGFILE`（NSS 客户端有效）→ 代理装 CA → 进程内 hook `SSL_write/SSL_read` → 静态反推 | 中：代理可能触发 pinning；hook 需调试权限 |
| 抓到明文但协议分层显示为 `data` | dissector 不认识该协议（私有协议常态） | 用 `--extract` 查包载荷，核实单连接单向 TCP 重组后再用字段表分帧 | 低：本域脚本可辅助离线分析 |
| 3 帧以上仍定不下长度字段覆盖范围 | 样本太单一（同长度/同类型）或字段根本不含长度 | 主动制造不同长度的帧（换业务/长昵称/大文件）再拟合；仍不行则按定界符或 type 定长处理 | 中：构造流量可能触发风控，只在靶场做 |
| 改长度/校验后服务端**无任何响应**（不是报错） | 服务端丢弃半包等超时，或 TCP 层就被中间件拦 | 先确认包到达服务端（对端 ACK/抓包点在服务端侧）；再看是否有心跳/超时；按"静默丢弃"记录为负例 | 中：容易误判成网络问题，需两端抓包 |
| 能原样重放，改 1 个业务字段就被拒 | 签名/nonce/时间窗/设备指纹/风控 | 定位签名覆盖范围（逐字段回显实验）→ 找客户端签名函数 → 无法复现就只报"部分复刻" | 高：签名常在 JS/SO 里，需组合 `softseep` / `unpack-loop` |
| 重放成功但响应体与基线不同（且无法解释） | 会话被踢、余额/库存等状态已变、AB 实验、时间相关字段 | 先做"同请求 3 次"基线方差统计；用新会话重放；记录可变字段清单 | 低：多数是状态问题，不是协议问题 |
| 请求带一次性 token，第二次即 401 | 防重放窗口/一次性 nonce | 找 token 下发接口，把"取 token→发请求"串成两步流程；不能自动化就降级为人工演示 | 中：多一步状态，脚本要重写 |
| WebSocket 消息 JSON 解析失败 / 半截 | 消息跨 TCP 段、permessage-deflate、控制帧穿插 | 按 FIN/opcode/长度重组；检查 `Sec-WebSocket-Extensions`；先 inflate 再 parse | 低：解析器问题，重写重组逻辑 |
| HTTP/2 字段串流（A 请求配到 B 响应） | 多路复用 + HPACK 动态表 + 帧乱序 | 按 `streamid` 分组，同 streamid 内按 frame 顺序；HEADERS 的 END_HEADERS/END_STREAM 位必须判 | 中：需要完整 h2 解析，建议直接用 tshark 的 http2 字段 |
| protobuf 解出乱码/字段号跳跃 | 无 schema、字段号不是业务 id、或前面还有一层压缩 | `protoc --decode_raw` 先看结构；字段号只作定位，语义靠相关性推断；先解压再解 | 中：错一层就全错，必须逐层验证长度 |
| 加密段熵 > 7.5 但找不到 nonce/IV | 可能是流加密（计数隐式）或整段封装（如 Noise/TLS） | 找计数器/序号字段与密文长度的线性关系；取两条已知明文做 XOR 判族；仍不行转进程内明文 | 高：盲猜算法几乎不可能成功 |
| 服务端开始返回 429/验证码/封禁页 | 触发风控 | 立即停；保留证据；不换 IP/账号绕过；把限速写进报告 | 高：可能影响授权范围内的其它测试 |
| 需要客户端证书/私钥才能继续 | mTLS | 从授权方取证书；否则只能做"服务端单向可见"的分析，明确写"未解" | 高：通常无法绕过 |
| 样本是抓包但时间戳全为 0 / 乱序 | pcapng SPB 块、时钟不同步、多网卡合并 | 用 `pcap-summary.py` 看 `format/first_ts`；必要时 `editcap -F pcap` 转换；时间分析改用相对序号 | 低：工具问题 |
| 抓到的会话里同端口有多条连接，混成一个流 | 五元组相同但 TCP 连接不同（端口复用） | 必须按 `tcp.stream`（SYN 起）分会话；不能按五元组合并 | 低：常见新手错误，重跑即可 |
| 复刻脚本在别人机器上跑不出同样结果 | 依赖本机绝对路径/私有样本/时区 | 路径用 `__file__` 推导或 `--root`；样本入案例 `input/`；时间统一 UTC epoch | 低：工程问题，但会让"证据可复跑"判据直接失败 |

## 2. 停手后的三条替代路线

| 替代路线 | 何时用 | 入口 |
|---|---|---|
| 进程内取明文 | 网络层加密且拿不到 keylog | `frida-trace -m SSL_write -m SSL_read`、LD_PRELOAD、调试器断点 |
| 静态反推格式 | 客户端可执行文件在手，协议序列化逻辑清晰 | `softseep` / `unpack-loop`：定位序列化函数、字段写入顺序、长度/校验计算 |
| 只做"可见面"报告 | 授权/时间不够，无法闭环 | 交付：会话表 + 字段表（标疑似）+ 状态图（标 INFERRED）+ 卡点清单 |

## 3. 代价记账（写进报告）

```text
已花：抓包 2 轮（10 min） / 分帧 1 轮（30 min） / 重放 3 次
卡在：签名覆盖范围（字段 f7 改动即 401）
改走：客户端 JS/SO 取签名函数（`softseep` / `unpack-loop`）
风险：目标为生产环境，已停止重放，未触发封禁
```

记账的目的：让下一个人不用重走死路；也让"部分复刻"这个结论可被审计。

## 3.1 记账的机检版（别只写散文）

```text
已花：抓包 2 轮（10 min） / 分帧 1 轮（30 min） / 重放 3 次
卡在：签名覆盖范围（字段 f7 改动即 401）
改走：客户端 JS 取签名函数（js-reverse）
风险：目标为生产环境，已停止重放，未触发封禁
```

同一个记账写成 JSON，就能被第三人复算“到底停在哪一步”：

```json
{"spent_min": 40, "attempts": 6, "blocked_at": "signature-scope",
 "tried": ["T1 replay x3", "T2 set f7 x2", "T2 set length x1"],
 "next_route": "js-reverse", "risk": "production-read-only", "stopped": true}
```

机检命令（rc 非 0 就说明记账不完整，别继续往下写报告）：

```bash
python - <<'PY'
import json, pathlib, sys
s = json.loads(pathlib.Path("artifacts/stop.json").read_text(encoding="utf-8"))
need = ["blocked_at", "tried", "next_route", "stopped"]
miss = [k for k in need if not s.get(k)]
print("miss", miss, "tried", len(s.get("tried") or []))
print("ledger_ok", not miss and s.get("stopped") is True)
sys.exit(0 if not miss and s.get("stopped") is True else 2)
PY
```

通过长什么样：`miss [] tried 3` + `ledger_ok True`（列表有三项，`attempts` 才是 6）。
写不出 `next_route` 的停手等于“放弃”，下一人接手要重走全部死路——这是本域最贵的浪费。

## 3.2 事故回流（lessons：现象 → 根因 → 正确动作 → 代价）

> 与 §1 的分工：§1 回答“现在该不该停”，本表回答“已经踩过的坑怎么不再踩”。

| 现象 | 根因 | 正确动作 | 代价 |
|---|---|---|---|
| 重放响应与基线“总差一点” | 基线是 mitmproxy 改写后的流量 | 基线用直连抓包；代理流量单独命名并在报告里声明 | 2 h 返工所有 diff |
| 长度公式三帧拟合不上 | 按五元组合并了 3 条先后连接 | 按 `tcp.stream` 分会话，`conv,tcp` 帧数对账 | 1 h 重拟合 |
| 字段表交付后被推翻 | 把 tshark dissector 结论当实现 | 结论回原始字节 + 自写字段表 | 返工 + 信任损失 |
| WebSocket 帧长总差 4 | 忘了客户端 4 B mask | `frame_len = 2 + (mask?4:0) + len` | 0.5 h |
| 花三小时“找密钥” | base64/压缩被当成加密 | 先魔数/解压/编码三连排除 | 3 h |
| 改一个业务字段就 401 | 旧 nonce/过期 token 混入实验 | 先“取材料→用材料”两步流程 | 误判“不可复刻” |
| 30 s 后连接被踢 | 重放脚本没带心跳 | 心跳周期实测 + 单独线程 | 误判“协议拒绝” |
| 容器内 `tcp.len` 全 0 | 抓包点选在宿主网卡 | 容器 `eth0` / `veth` 侧抓，或宿主 `any` 加过滤 | 10 min |
| 报告贴了真实 token | 证据卫生事故 | 脱敏为 `<redacted:sha256:…>`，只留长度/前缀 | 事故级 |
| 单帧定长度写了字段表 | 样本 <3 帧 | 补样本 + 改长度负例 | 整张表全错 |

这张表可以直接当"复盘模板"用：新踩的坑按同样四列追加，下一人先读它。

## 3.3 被误判成“失败”的正常现象

| 现象 | 其实是什么 | 先做的检查 |
|---|---|---|
| 同一请求两次响应不同 | 时间戳/nonce/分页/负载均衡 | 逐项列可变字段，重复 3 次看方差 |
| 业务字段改变后服务端回通用错误帧 | 字段值超出枚举，不是"签名失败" | 换成同枚举内的另一个值再试 |
| 抓包只有 SYN/ACK 没有载荷 | 客户端在等 DNS/代理/证书 | `tshark -Y 'dns \|\| tls'` 看前置握手 |
| 响应被拆成两次 recv | TCP 分段，不是两条消息 | 按长度前缀缓冲到整帧 |
| `tshark` 把协议识别成 `data` | 私有协议常见，不是“没抓到” | 查包载荷并核实重组，之后自建字段表 |
| 重放偶发成功、偶发失败 | 服务端多实例/灰度/时间窗 | 记录 10 次响应的 sha256 与实例特征 |

这六条的共同点：**失败信号出现在应用层，根因在网络/状态/环境**。归因顺序仍是
`环境 → 会话 → 时间 → 协议`（见 `08-replay-and-new-request.md` §6）。

## 3.4 分族定位：一条命令定“死在哪一层”

```bash
P=capture.pcapng
# 1) 有没有应用层明文（看 http/websocket/tls/data 哪一层有量）
tshark -r $P -q -z io,phs | tail -20
# 2) 是不是全程 TLS
tshark -r $P -Y tls -T fields -e frame.number | wc -l
# 3) 有没有重传/乱序污染
tshark -r $P -Y 'tcp.analysis.retransmission || tcp.analysis.out_of_order' -T fields -e frame.number | wc -l
# 4) 每个方向到底多少字节
python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file $P --json \
  | python -c "import json,sys;d=json.load(sys.stdin);print('pkts',d['packet_count'],'sess',d['sessions_total'],'payload',sum(s['payload_bytes'] for s in d['sessions']))"
```

通过长什么样（能下结论的最小输出）：

```text
  eth:18 ip:18 tcp:18 http:2 websocket:8 data:0
tls_frames 0
retrans_frames 0
pkts 18 sess 2 payload 736
```

`sessions` 默认最多列出前 20 个方向，因此上述 payload 求和并非必然是全捕获总量。判读：`tls_frames 0` 且 `websocket 8` → 有明文候选，仍须验证 TCP 重组和帧边界；`tls_frames > 0` 且应用层为 0 →
直接转 §3.5 升级观测层，不要在抓包上继续耗。`retrans_frames` 远大于帧数 → 先解决抓包点/镜像口。

## 3.5 升级观测层：怎么确认“升级真的生效”

| 升级 | 命令 | 生效证据 | 失败信号 |
|---|---|---|---|
| keylog | `SSLKEYLOGFILE=$PWD/artifacts/keys.log ./client` | `keys.log` 非空且有 `CLIENT_RANDOM` 行 | 文件为空 = 客户端不读该变量 |
| 进程内 hook | `frida-trace -f ./client -m SSL_write -m SSL_read` | 每次业务都有 hook 命中计数 | 无命中 = 用了 BoringSSL 静态链接/自研 TLS |
| 预加载 | `LD_PRELOAD=./libsslspy.so ./client` | `strace` 里出现 `openat` 后的 send 明文 | 无输出 = 符号没对上 |
| 断点 | `gdb -p <pid> -ex 'b SSL_write' -ex c` | 断点命中且 `x/s $rdx` 可读 | 反调试/完整性校验 |

三条纪律不变：升级后**先验证观测有效**（有命中、有字节），再回去改协议模型；
否则会把“hook 没生效”误判成“协议不可解”。

## 3.6 时间盒：每个阶段的止损点

| 阶段 | 预算 | 到点未达成 | 动作 |
|---|---|---|---|
| 抓包与分层 | 20 min | 没有应用层字节 | 换抓包点/换观测层，不再重抓 |
| 分帧 | 40 min | 3 帧以上定不下长度 | 换样本（制造不同长度），不写字段表 |
| 校验 | 30 min | 5 帧内凑不出唯一算法 | 先定覆盖范围，再换算法族 |
| 状态机 | 60 min | 关键边（认证/订阅）无样本 | 补抓完整会话，不猜边 |
| T2 构造 | 60 min | 单变量改动 3 次全被拒 | 转签名/nonce 定位或写"部分复刻" |
| 加密段 | 90 min | 无明文对、无 keylog | 停猜算法，转进程内明文 |
| 交付 | 30 min | 判据卡有 `rc!=0` 条目 | 降档措辞或标记 `blocked` |

时间盒不是 KPI：它防的是"在一条死路上烧掉整场"。任何一格超时，先写一行记账再决定。

## 3.7 停止后的交接包（下一人 5 分钟能接手）

```text
stop.json                # blocked_at / tried / next_route / stopped
artifacts/streams/*.bin  # 包顺序方向载荷；另存经核实的单向重组流及缺口说明
artifacts/frames.jsonl   # 包级记录，载荷最多 4096 字节，并非应用消息帧表
artifacts/claims.json    # 每条结论 + 命令 + rc + 证据
artifacts/stop.md        # 一页：卡在哪、试过什么、下一步建议
```

```bash
# 交接包自检：缺文件就 rc=2，不要"口头交接"
python - <<'PY'
import json, pathlib, sys
need = ["artifacts/stop.json", "artifacts/frames.jsonl", "artifacts/claims.json"]
miss = [p for p in need if not pathlib.Path(p).is_file()]
card = json.loads(pathlib.Path("artifacts/claims.json").read_text(encoding="utf-8")) if not miss else {}
bad = [c.get("id") for c in card.get("claims", []) if c.get("rc") != 0]
print("miss", miss, "bad_claims", bad)
sys.exit(2 if miss or bad else 0)
PY
```

通过长什么样：`miss [] bad_claims []`、rc=0；这里只核文件和声明的 rc，不能验证命令确实执行或结论成立。

## 3.8 一页速查（if → then）

| if（现象） | then（动作） |
|---|---|
| 抓包无应用层字节 | 换抓包点 → keylog → 进程内 hook → 静态反推 |
| 应用层是 `data` | 核实单向重组后自己分帧，不等 dissector |
| 3 帧定不下长度 | 制造不同长度样本；仍不行按定界符/定长处理 |
| 改长度/校验无响应 | 确认包到达服务端；按"静默丢弃"记负例 |
| 能重放，改字段即拒 | 定位签名/nonce 覆盖范围；不行写"部分复刻" |
| 响应与基线不同 | 先查会话/时间/实例，再改协议模型 |
| 重放第二次 401 | 一次性 token/nonce，串成两步流程 |
| 熵 > 7.5 无明文对 | 停猜算法，转进程内明文 |
| 出现 429/验证码/封禁 | 硬停，留证，不换账号/IP |
| 换会话 id 读到他人数据 | 越权红线，立即停并上报 |

## 3.9 "两次法则"怎么数才算一次

| 尝试 | 算不算新一次 | 为什么 |
|---|---|---|
| 同一命令改了一个无关参数（超时/重试） | 不算 | 观测层没变，信息增量≈ 0 |
| 换抓包点/换方向/换样本 | 算 | 换的是证据源 |
| 从 T1 改到 T2 单变量 | 算 | 从“重放”进到“理解协议” |
| 同一帧换一个字节再发 5 遍 | 不算 | 同一个假设的重复 |
| 从网络层转到进程内 | 算，而且应该直接换 | 前一层已证伪 |

反例（最常被当成"又试了一次"）：

1. 因为没响应就把超时从 3 s 加到 30 s，再跑 3 遍——这不是新尝试，是把"静默丢弃"误读成"慢"。
2. 把同一个错校验帧改一个字节发 10 次——采样的是服务端抖动，不是协议。
3. 重抓一次但没换抓包点——证据源相同，结论不会变。

结论：**两次法则数的是"不同观测/不同假设"，不是命令次数。** 写记账时把每次尝试的
`hypothesis` 一并记下；两个尝试 hypothesis 相同就并成一次。
若一个假设无法写出"什么实验结果能推翻它"，它就不是可机检的假设，不应占用尝试次数。
这一点在"再试一次就好"的冲动下最容易被忽略，也是时间盒失效的头号原因。

## 4. 边界

- 本表以"能机检的现象"为准；主观感受（"感觉快通了"）不构成继续投入的理由。
- 风控相关条目一律硬停：换账号/换 IP 绕过属于越界，不在本域方法体系内。
- 失败判据不是免责声明：写"部分复刻"时仍要给出已确认的部分与可复跑命令。

## 这一篇算"用对了"吗

- [ ] 说得出"卡在哪一层"（网络/分帧/校验/加密/状态/交付），而不是"跑不通"。
- [ ] 每次停手都有 `stop.json` 四字段（`blocked_at/tried/next_route/stopped`）且机检 rc=0。
- [ ] 事故回流表里新踩的坑按"现象/根因/正确动作/代价"补齐，没有只写"失败了"。
- [ ] 没有把 3.2 的六种正常现象当成失败，也没有在 429/越权信号上继续。
- [ ] 交接包含字节流、帧表、判据卡、一页 stop.md，下一人不用重抓包。
