# 01 判据表 — 什么算"协议复刻成功"

> 范围：TCP/UDP/HTTP/WebSocket/私有二进制协议的**离线复刻**与授权环境重放。
> 路由：插件/扩展装载链按 `Tool/playbooks/plugin-analysis.md` 分析；纯前端 JS 签名组合 `softseep`；
> 纯算法还原组合 `softseep` / `unpack-loop`。总流程见 `../SKILL.md`，失败判据见 `02-failure-criteria.md`。
>
> 本表每一行都给出**可机检判据**：能用脚本/命令算出真假，而不是"看起来像"。
> 判据分「确认」与「疑似」两档；只有确认档能写进结论文档。

## 0. 判据分级

| 档位 | 含义 | 允许写进报告的措辞 |
|---|---|---|
| 确认 | 有 ≥3 帧样本 + 单变量实验 + 负例 | "已确认 / 可复现" |
| 疑似 | 只有 1–2 帧样本，或只有静态推断 | "疑似 / 未验证" |
| 未定 | 有反例或无法闭环 | "分帧未定 / 放弃" |

一条判据要同时满足：**可复算**（别人跑同样命令得同样结论）、**可否证**（存在能推翻它的实验）、
**有边界样本**（至少一个反例/错误帧）。缺任何一条都降一档。

## 1. 主判据表

| 场景 | 输入面 | 判据（可机检） | 证据形态 | 误报风险 |
|---|---|---|---|---|
| 帧边界可确定 | 经重组的单向字节流 | 相邻消息帧的偏移与长度可对齐，解析结果可复跑 | `proto-repro.py` 的 `frames[].offset/frame_len`、`stats` 及原始字节 | `--extract` 是包载荷按捕获顺序拼接，未重组；`frames.jsonl` 每行是包而非消息帧 |
| 长度字段语义闭合 | ≥3 条不同长度的帧 | 用 `len_field = a*payload + b` 拟合，`a/b` 唯一；能预测**未见帧**的 `frame_len`，误差 0 | 字段表 + 3 帧实测表（偏移/长度/端序） | 长度含头/含尾/含自身三种假设都能拟合小样本；必须靠"改长度→服务端行为"区分 |
| 校验算法可复算 | 每帧的原文 + 末尾校验字段 | `proto-repro.py` 报 `crc_ok=true`；改 1 字节载荷后同一帧 `crc_ok=false`；算法/初值/覆盖范围可写成一个函数 | 校验字段 want/got 十六进制 + 覆盖范围（header+payload） | 简单和/异或/Adler32 也能"碰巧"匹配 3 帧；样本 <5 帧时不要把 CRC32 写死 |
| 帧被服务端接受 | 本地/授权服务端 | 新构造帧得到与预测一致的响应（同一业务码/同一状态迁移），重复 3 次稳定 | 发送字节 hex + 响应字节 hex + RTT | 服务端"回了包"不等于"接受了业务"（可能是通用错误帧） |
| 状态迁移可解释 | 消息序列（含握手/认证/业务/关闭） | 每条边有 ≥1 条样本；非法迁移（跳过认证、错 seq）有实际拒绝证据；`state_before/event/state_after` 三元组可回指帧号 | `frames.jsonl` + 状态图 + 拒绝样本 | 把"没观测到"当成"协议拒绝"；重连/心跳被误当业务消息 |
| 状态机成立 | 观测边集 + 非法迁移负例（`edges.json`） | 每条边回指真实样本，预测新序列并核对实际拒绝证据 | 原始帧、状态图及负例运行记录；脚本的帧号统计只供整理 | 输入的帧号和负例文本未经过脚本验证，不能单凭覆盖率确认 |
| 状态机不成立 | 同上（同一份边集） | `edge_coverage <0.60` 或 `llm_unverified >0` 或 `illegal_transition_proof` 为空；非法迁移全部"无响应"；此时只能写"部分建模（覆盖率 X%）" | 同上（`verdict=state_machine_not_established`） | 用虚线边凑覆盖率；把心跳/重连刷成业务边把分母做小 |
| 同输入同输出 | 原样重放的请求 | 同请求重复 3 次，响应体哈希/关键字段一致；允许变化项（时间戳/nonce）能逐项解释 | 3 次响应的 sha256 与差异字段 diff | 负载均衡/多实例/时间窗导致"每次都不同"，误判为协议不可复刻 |
| 认证材料可复现 | token/cookie/nonce/时间戳/签名 | 能指出材料来源（哪一帧哪个字段）、有效期、绑定维度（IP/UA/设备）、是否一次性 | 材料字段表 + 过期/复用实验记录 | 把"能原样重放"当成"能续期"；token 可能只是会话表 key |
| 加密段位置明确 | 熵、块长、nonce/IV、明文头 | 能指出加密起点、长度字段是否覆盖密文、nonce 来源；解出的明文能被 JSON/长度二次验证 | 熵值、块长、明文-密文对、解密脚本 | "熵高"可能只是压缩或 base64；AES 猜测没有明文对不算证据 |
| 压缩/序列化可分层 | 压缩魔数 / protobuf / flatbuffers | 解压后再分帧成功；protobuf 字段号+wire type 可解释且能重新编码被接受 | 解压前后长度、字段号表、重新编码的 hex | 把 protobuf 字段号当业务 id；把 gzip 头当协议 magic |
| WebSocket 消息边界 | ws 握手 + 帧头 | 按 opcode/FIN/长度/mask 重组，消息数与业务次数一致；控制帧(ping/pong/close)被单独分类 | 每帧 `opcode/fin/mask/len` + 消息体 | 把 TCP 段当消息；permessage-deflate 未解压导致 JSON 解析失败 |
| HTTP/2 流可归属 | 带 keylog 或已解密的 h2 流量 | HEADERS 的 `:method/:path` 与 DATA 的 streamid 对应；同一 streamid 的 END_STREAM 位置正确 | `tshark -e http2.streamid -e http2.header.name` 输出 | 多路复用下按 frame.number 排序会串流；HPACK 动态表跨流共享 |
| 负例按预期被拒 | 篡改帧（错 magic/长度/CRC/seq/token） | 每类篡改都有明确拒绝方式（断开/错误码/静默丢弃），且与模型预测一致 | 6 类篡改 × 响应记录 | 服务端"静默丢弃"容易被误读为"网络问题"；需抓包确认收到 |
| 证据可复跑 | 文档 + 脚本 + 样本 | 第三方按 `schema.json + proto-repro.py` 能在自己机器上复现同一帧与同一 CRC | 案例目录 `artifacts/run.json`（含 cmd/rc/stdout） | 只给结论不给命令；命令依赖本机绝对路径或私有样本 |

## 1.1 采样量下限（判据的最小样本）

> 这一节只回答"样本够不够"。分帧/校验/状态机怎么做见 `05`–`07`；此处给的是**低于下限必须降档**。

| 判据 | 最小样本 | 机检字段 | 样本不足时唯一可写的措辞 |
|---|---|---|---|
| 帧边界可确定 | ≥3 帧且 ≥2 种 payload 长度 | `frame_count`、每帧偏移与长度、`skipped_bytes` | 疑似：单帧自洽 |
| 长度字段语义 | ≥3 帧、≥2 种长度、1 个改长度负例 | 拟合唯一 + 负例行为 | 疑似：含头/含尾未区分 |
| 校验算法 | ≥5 帧 + 1 个改字节负例 | 全部 `crc_ok=true` 且负例 `false` | 疑似：样本内自洽 |
| 状态迁移 | 关键边各 ≥1 条 + 1 个非法迁移 | `evidence_frame` 非空 | 疑似：边靠先验 |
| 状态机成立 | 每条边有实际样本、非法迁移有真实拒绝证据 | 帧和运行记录经复核；脚本统计是未验证声明 | 部分建模（声明的覆盖率 x%） |
| 同输入同输出 | 同一请求 3 次 | 3 份响应 sha256 + 可变项清单 | 未确认：只跑过 1 次 |
| 构造新请求 | 单变量改动 3 次 | 预测 vs 实际 3/3 | 部分复刻：可重放 |
| 认证材料可复现 | 1 次过期 + 1 次复用实验 | 材料来源字段 + 有效期 | 疑似：一次性未验证 |
| 证据可复跑 | 1 台干净机器（无本机绝对路径） | `run.json` 的 `cmd`/`rc` | 未交付 |

下例仅统计包载荷长度，不能当成应用消息帧采样量；需先完成单向重组和消息分帧再统计：

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
python - <<'PY'
import json, collections, pathlib
rows = [json.loads(l) for l in pathlib.Path("artifacts/frames.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
lens = collections.Counter(r.get("payload_len") for r in rows)
print("frames", len(rows), "lengths", sorted(lens))
print("framing_floor_ok", len(rows) >= 3 and len(lens) >= 2)
PY
```

通过长什么样：

```text
frames 3 lengths [27, 30, 36]
framing_floor_ok True
```

出现 `framing_floor_ok False` 时，不要改代码"凑样本"；去抓一条含**不同业务长度**的会话
（长昵称、大文件、分页参数、订阅主题长度不同）。样本多样性比样本数量更能证伪长度假设。

## 1.2 证据组合 → 允许写的结论（措辞闸门）

| 已有证据 | 允许的结论 | 禁止的措辞 |
|---|---|---|
| 帧自洽 + 校验复算 | "分帧与校验在该样本上自洽" | "协议已还原" |
| 上面 + 状态关键边观测 + 1 负例 | "会话流程可重建（覆盖率 x%）" | "状态机成立"（覆盖率 <60% 时） |
| 上面 + T2 单变量 3/3 | "可构造服务端接受的新请求" | "任意业务都可构造" |
| 上面 + T3 闭链 + 10 次 ≥9 | "客户端可复刻" | "生产可用" |
| 只有 T1 原样重放 | "部分复刻：可重放" | "已复刻" |
| 只有 pcap 与 tshark 字段 | "疑似：dissector 如此解析" | "字段语义已确认" |

这张表是措辞闸门：报告里出现右列词，先回左列找证据；找不到就改词。

## 1.3 客户端复刻的验收口径（V1–V4）

复刻客户端不是"能连上"，而是四个口径逐级成立。缺一级只能写上一级的结论。

| 口径 | 比什么 | 通过线 | 不通过说明 |
|---|---|---|---|
| V1 帧级 | 归一化后的帧字段、长度、校验 | diff 为空；`rebuild.verify.crc_ok=true` | 长度或校验算法判错 |
| V2 语义级 | 业务字段（id/值/单位/枚举） | 逐项相等，可变项在清单内 | 字段语义靠猜 |
| V3 状态级 | `state_before→event→state_after` 序列 | 与模型一致，负例按预期被拒 | 缺前置条件（心跳/订阅/二次认证） |
| V4 运行级 | 10 次独立运行的响应与存活 | ≥9 次成功、心跳不断、无额外重连 | 不稳定，不能写"可复刻" |

V1 的归一化比对（白名单只放时间戳/nonce/随机 id）：

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
python - <<'PY'
import hashlib, json, pathlib
VAR = {"ts", "nonce", "timestamp", "request_id", "sid"}
def load(p):
    return json.loads(pathlib.Path(p).read_text(encoding="utf-8"))
base, repl = load("artifacts/base_frame.json"), load("artifacts/replica_frame.json")
def norm(d):
    return {k: ("<var>" if k in VAR else v) for k, v in d.items()}
nb, nr = norm(base), norm(repl)
diff = {k: (nb.get(k), nr.get(k)) for k in set(nb) | set(nr) if nb.get(k) != nr.get(k)}
print("diff", diff)
print("v1_pass", not diff)
print("norm_sha", hashlib.sha256(json.dumps(nb, sort_keys=True).encode()).hexdigest()[:16])
PY
```

通过长什么样：

```text
diff {}
v1_pass True
norm_sha 3c1f7a0e9b2d4c58
```

注意：V1 比的是**归一化后的字段**，不是原始字节；原始字节里时间戳每次不同是正常的。
反过来，若 `diff` 里出现业务字段，说明不是"可变项"，而是语义判错。

## 1.4 判据卡（第三人可复算的最小 JSON）

交付时把每条结论压成一张卡：一条结论 = 一条命令 + 一个 rc + 一处证据。

```json
{
  "case": "protocol02",
  "sha256": "<capture 或 frames.bin 的哈希>",
  "claims": [
    {"id": "C1", "kind": "framing", "level": "confirmed",
     "cmd": "proto-repro.py --input artifacts/sample.bin --json",
     "rc": 0, "evidence": "frames.jsonl#0-2", "want": "consumed+trailing==bytes"},
    {"id": "C2", "kind": "checksum", "level": "confirmed",
     "cmd": "proto-repro.py --input artifacts/sample.bin --json",
     "rc": 0, "evidence": "frames[].checks[0].covers=header+payload", "want": "crc_ok=true"}
  ],
  "var_fields": ["ts", "nonce"],
  "blocked": []
}
```

机检每张卡是否"可复算"：

```bash
python - <<'PY'
import json, pathlib
card = json.loads(pathlib.Path("artifacts/claims.json").read_text(encoding="utf-8"))
bad = [c["id"] for c in card["claims"]
       if not c.get("cmd") or c.get("rc") != 0 or not c.get("evidence")]
print("claims", len(card["claims"]), "unverifiable", bad)
print("card_ok", not bad and bool(card.get("sha256")))
PY
```

通过长什么样：`claims 2 unverifiable []` + `card_ok True`。
任何一条 `rc!=0` 或 `evidence` 为空，该条结论降为"疑似"，不要靠文字解释补。

## 1.5 与相邻篇的分工（避免重复写）

| 问题 | 去哪一篇 | 本篇只保留 |
|---|---|---|
| 帧怎么切、怎么重同步 | `05-binary-framing.md` | 采样量与档位 |
| 状态边怎么推、覆盖率怎么算 | `06-app-state-machine.md` | 允许写的措辞 |
| 加密段怎么识别、校验参数怎么穷举 | `07-crypto-and-checksum.md` | 判据边界（到哪步算确认） |
| 新请求怎么构造、怎么归因差异 | `08-replay-and-new-request.md` | 验收口径 V1–V4 |

## 2. 判据到命令的映射（本域脚本）

```bash
# 1) 会话/字节流/明文片段（无需 tshark）
python Tool/skill/protocol-plugin/scripts/pcap-summary.py \
  --file capture.pcapng --json --extract artifacts/streams --tshark-check

# 2) 分帧 + 校验复算 + 重建新帧（字段表驱动）
python Tool/skill/protocol-plugin/scripts/proto-repro.py \
  --input <匹配字段表的单方向帧文件> --json

# 3) 重建一条新请求并自校验
python Tool/skill/protocol-plugin/scripts/proto-repro.py --input frames.bin \
  --rebuild --frame-index 2 --set type=4 --set seq=4 \
  --payload-text '{"temp":22.0,"status":"ok"}' --out new.bin --json

# 4) 本域案例判据复算（sha256/字段/lessons 里的 rc）
python Tool/skill/protocol-plugin/scripts/proto-accept.py --json
```

判据落地方式：结合样本数量、跳过字节、字段表与改字节负例复核；脚本自洽只证明按所选 schema 解析和复算，不能单独确认真实协议。

## 3. 常见"假确认"与降档规则

| 假确认 | 为什么不算 | 降档后怎么写 |
|---|---|---|
| 只有 1 帧样本 | 无法区分长度含头/含尾 | "疑似：长度只覆盖 payload（1 帧）" |
| CRC 只对了一帧 | 可能是巧合或固定值 | "疑似：校验疑似 CRC32（未做改字节负例）" |
| 能重放但不能改字段 | 只证明链路通，不证明理解协议 | "部分复刻：可重放，不能构造新请求" |
| 客户端 UI 显示成功 | UI 可能本地乐观更新 | "未确认：需服务端响应/后续查询证明" |
| tshark 能解出字段 | 那是 dissector 的猜测，不是目标的实现 | "疑似：tshark 按 X 解析，需原始字节复核" |
| 抓到了 TLS 密文 | 没有明文就没有字段 | "未定：加密段未解，需 keylog/进程内明文" |

## 4. 失败判据（速查）

出现下列任一现象即**停止堆参数**并改走 `02-failure-criteria.md` 对应分支：

- 连续 2 次抓包无应用层字节，且已排除网卡/代理/TLS keylog；
- 3 帧以上仍无法确定长度/校验覆盖范围，且单变量改动全部无响应；
- 能原样重放，但任何字段改动都被拒（签名/nonce/风控）；
- 服务端返回封禁/验证码/风控升级；
- 需要他人环境的密钥/证书/账号才能继续。

## 5. 边界

- 本表只覆盖"协议字节与状态"；插件入口、权限面、asar/VSIX 装载链按 `Tool/playbooks/plugin-analysis.md`，原生载荷组合 `softseep`。
- 本表不覆盖漏洞利用：确认了协议能力之后要不要打、打到什么程度，由授权范围决定。
- 生产流量默认只读；重放只在本地/授权靶场；高频重放视同拒绝服务。
- 所有"确认"必须能指回 `capture#frame` / `frames.jsonl#id` / `artifacts/run.json` 的某一行。

## 附：上游技能卡索引（24 张）

> 上游 = `mukul975/Anthropic-Cybersecurity-Skills`（818 技能库）。本表只回答一件事：这条上游技能在本域**落到哪张卡、哪篇 reference、判据是什么**。

| 上游技能 | 本域任务卡 | 落点 reference | 一句话判据 |
|---|---|---|---|
| `performing-network-traffic-analysis-with-tshark` | tshark 首轮分诊（源：performing-network-traffic-analysis-with-tshark） | `Tool/skill/protocol-plugin/references/04-walkthrough-websocket-replay.md` | 能说出"主协议层 + 会话数 + 每个方向字节数"；`conv,tcp` 的帧数总和等于 `io,phs` 的 fram… |
| `performing-network-packet-capture-analysis` | 抓包点与捕获文件体检（源：performing-network-packet-capture-analysis） | `Tool/skill/protocol-plugin/references/01-criteria.md` | `format/linktype/包数/时长` 两套工具一致；pcapng 的 if_tsresol 被正确解析（时间在… |
| `performing-network-traffic-analysis-with-zeek` | Zeek 日志与原始字节对照（源：performing-network-traffic-analysis-with-zeek） | `Tool/skill/protocol-plugin/references/05-binary-framing.md` | 日志里的 `orig_bytes/resp_bytes` 与 `pcap-summary.py` 的 `payload_… |
| `performing-dns-enumeration-and-zone-transfer` | DNS 查询/响应配对与字段表（源：performing-dns-enumeration-and-zone-transfer） | `Tool/skill/protocol-plugin/references/05-binary-framing.md` | 请求与响应按 id 一一配对；qname 的标签 ≤63 B、总长 ≤253；异常样本能被量化（长度/熵） |
| `performing-dns-tunneling-detection` | DNS 隧道载荷还原（源：performing-dns-tunneling-detection） | `Tool/skill/protocol-plugin/references/07-crypto-and-checksum.md` | 解出的字节流有结构（长度前缀/JSON/文件头），且能跨 ≥3 个 qname 连续；不是"解出一堆随机字节" |
| `detecting-dns-exfiltration-with-dns-query-analysis` | DNS 外泄流量量化（源：detecting-dns-exfiltration-with-dns-query-analysis） | `Tool/skill/protocol-plugin/references/01-criteria.md` | 唯一率或平均长度显著高于基线（给出具体倍数），且能指认对应帧号；否则只写"无显著差异" |
| `hunting-for-dns-tunneling-with-zeek` | Zeek 规则化 DNS 隧道验证（源：hunting-for-dns-tunneling-with-zeek） | `Tool/skill/protocol-plugin/references/01-criteria.md` | 规则命中项 100% 能在 pcap 找到对应帧；规则漏报的样本也要抽查 5 条 |
| `testing-websocket-api-security` | WebSocket 握手与消息分帧（源：testing-websocket-api-security） | `Tool/skill/protocol-plugin/references/04-walkthrough-websocket-replay.md` | 8/8 帧帧长公式成立；客户端 mask=1、服务端 mask=0；accept = base64(sha1(key+G… |
| `exploiting-websocket-vulnerabilities` | WebSocket 新消息构造（源：exploiting-websocket-vulnerabilities） | `Tool/skill/protocol-plugin/references/04-walkthrough-websocket-replay.md` | 响应与预测一致且重复 3 次稳定；`new-frame.bin` 能被自己的解析器解析回同一字段 |
| `exploiting-ipv6-vulnerabilities` | IPv6 / ICMPv6 报文分帧（源：exploiting-ipv6-vulnerabilities） | `Tool/skill/protocol-plugin/references/05-binary-framing.md` | 扩展头链解析后 payload 起点与 tshark 一致；ICMPv6 type/code 与语义表对得上 |
| `exploiting-bgp-hijacking-vulnerabilities` | BGP UPDATE 报文复刻（源：exploiting-bgp-hijacking-vulnerabilities） | `Tool/skill/protocol-plugin/references/05-binary-framing.md` | length 字段 = 19 + 后续字节；属性 TLV 的 len 与 value 长度一致；复刻帧能被同一解析器读回 |
| `implementing-bgp-security-with-rpki` | BGP RPKI 验证的可见面（源：implementing-bgp-security-with-rpki） | `Tool/skill/protocol-plugin/references/01-criteria.md` | 能指认某条 UPDATE 的 prefix/origin 与验证状态来源；不能指认就写"未验证" |
| `performing-vlan-hopping-attack` | 802.1Q / VLAN 标签分帧（源：performing-vlan-hopping-attack） | `Tool/skill/protocol-plugin/references/05-binary-framing.md` | 标签层数与偏移完全吻合；双标签时内层 ethertype 正确 |
| `detecting-arp-poisoning-in-network-traffic` | ARP 报文结构与异常检测（源：detecting-arp-poisoning-in-network-traffic） | `Tool/skill/protocol-plugin/references/06-app-state-machine.md` | 冲突能被 ≥2 条帧复现，且时间上后到的通告覆盖先前的；单条异常只写"疑似" |
| `performing-packet-injection-attack` | 报文注入的离线复刻（源：performing-packet-injection-attack） | `Tool/skill/protocol-plugin/references/08-replay-and-new-request.md` | 响应与预测一致；错校验帧被拒且拒绝方式与模型一致 |
| `exploiting-smb-vulnerabilities-with-metasploit` | SMB2 协商与会话帧（源：exploiting-smb-vulnerabilities-with-metasploit） | `Tool/skill/protocol-plugin/references/06-app-state-machine.md` | NetBIOS length = 后续字节数；Command 与 MessageId 配对一致；能说出协商出的 dial… |
| `implementing-network-traffic-baselining` | 流量基线：会话/字段分布（源：implementing-network-traffic-baselining） | `Tool/skill/protocol-plugin/references/01-criteria.md` | 异常项给出具体倍数与帧号；基线本身无未解释的异常 |
| `implementing-network-traffic-analysis-with-arkime` | Arkime 会话索引与 pcap 对照（源：implementing-network-traffic-analysis-with-arkime） | `Tool/skill/protocol-plugin/references/04-walkthrough-websocket-replay.md` | 索引与 pcap 的字节数同量级、关键字段能在原始字节里找到；差异有解释（截断/方向） |
| `analyzing-network-flow-data-with-netflow` | NetFlow/流记录字段与 pcap 对齐（源：analyzing-network-flow-data-with-netflow） | `Tool/skill/protocol-plugin/references/04-walkthrough-websocket-replay.md` | 折算后差异 <10% 且能解释（采样/超时切流）；否则说明时间窗或采样率假设错 |
| `deploying-tailscale-for-zero-trust-vpn` | WireGuard/Noise 握手帧识别（源：deploying-tailscale-for-zero-trust-vpn） | `Tool/skill/protocol-plugin/references/02-failure-criteria.md` | 能区分 handshake initiation / response / transport / keepalive … |
| `configuring-network-segmentation-with-vlans` | VLAN 分段下的抓包点选择（源：configuring-network-segmentation-with-vlans） | `Tool/skill/protocol-plugin/references/01-criteria.md` | 选定点能看到握手 + 业务 + 关闭；其它点缺失的部分有拓扑解释 |
| `analyzing-network-covert-channels-in-malware` | 隐蔽通道：载荷熵与分帧异常（源：analyzing-network-covert-channels-in-malware） | `Tool/skill/protocol-plugin/references/07-crypto-and-checksum.md` | 异常组合能在基线上复现差异（给出数值）；能指认承载协议（DNS TXT/ICMP data/TCP 保留字段） |
| `performing-bluetooth-security-assessment` | BLE ATT 帧与抓包边界（源：performing-bluetooth-security-assessment） | `Tool/skill/protocol-plugin/references/05-binary-framing.md` | 同 handle 的 read/write 请求-响应能配对；丢包率可量化（缺失的连接事件数） |
| `performing-s7comm-protocol-security-analysis` | S7comm 功能码与 PDU 分帧（源：performing-s7comm-protocol-security-analysis） | `Tool/skill/protocol-plugin/references/06-app-state-machine.md` | TPKT length = 后续字节数；COTP 后 S7 header 偏移固定；功能码与响应项一一对应 |

## 这一篇算"用对了"吗

- [ ] 每条结论都能指到一行 `evidence`（帧号/`frames.jsonl#id`/`run.json`），没有"我觉得"。
- [ ] 采样量先过 `1.1` 的下限表：分帧 ≥3 帧 ≥2 种长度、校验 ≥5 帧 + 负例；不够就写"疑似"。
- [ ] 用 `1.2` 的闸门检查措辞：没到 T2 不写"已复刻"，覆盖率 <60% 不写"状态机成立"。
- [ ] 客户端复刻按 V1→V4 逐级验收，V1 的 diff 只看归一化字段，不拿时间戳当差异。
- [ ] 交付里有 `claims.json` 且机检 `card_ok=True`；`rc!=0` 的条目已降档。
