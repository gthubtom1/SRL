---
name: protocol-plugin
description: "【协议复刻 / R24】私有协议与二进制协议逆向：抓包、分帧、字段推断、状态机重建、重放与构造新请求。判据是同输入同输出、能构造服务端接受的新请求、状态可闭环；插件/扩展/Mod 目标一律转 plugin-targets（R25）。"
license: MIT
compatibility: Windows 10/11、Linux、macOS；依赖可选的 tshark / mitmproxy / scapy；缺失时用标准库 pcap 解析与原始 socket 重放降级。
metadata:
  version: "1.1.0"
  category: protocol-plugin
  routes: "R24"
  references: "references/protocol-reverse.md, references/binary-protocols.md, references/state-machine-and-replay.md"
---

# protocol-plugin — 私有 / 二进制协议复刻（R24）

> 只回答一件事：**这个协议能不能被复刻到“同输入同输出，且能构造新请求”？**
> 先取证再推断；每个结论必须能回放到某条包、某个字段、某次运行。**不猜密钥，不猜字段，不猜状态。**

**分工（硬边界）**：插件 / 浏览器扩展 / IDE 插件 / Electron asar / 游戏 Mod → `plugin-targets`（R25）；协议 / 抓包 / 分帧 / 状态机 / 重放 → 本技能（R24）。需要同时碰两者时，先由 plugin-targets 定位插件入口与载荷，再把其中的协议部分交回本技能。

---

## 0. 入口判定与硬边界

| 路由 | 目标形态 | 首问 | 终点判据 |
|---|---|---|---|
| R24 协议复刻 | TCP/UDP/HTTP/WS 私有协议、二进制帧、protobuf | 帧边界在哪？状态由什么推进？ | 同输入同输出 + 能构造新请求 |

**三条纪律**

1. **抓包先于推断**：没有原始字节/原始文件，不许写“字段含义”；推断必须附样本编号。
2. **重放先于重写**：先原样重放，再做单变量改动；一次只改一个字段，并保留基线。
3. **两次失败即停**：同一目标连续两次抓不到/跑不通，先换观测层（进程内 → 网络层 → 静态），不硬试参数。

**不做（边界）**

- 网页/前端 JS 的签名、补环境、浏览器调试 → `mcp-js-reverse-playbook`；
- 客户端授权/许可证/门禁/版本迁移 → `01-gate-bypass` ~ `05-backend-rebuild`；
- 纯 PE/ELF 壳与反调试 → `unpack-loop`；纯算法还原 → `ida-reverse`/`reverse-engineering`；
- 插件入口、manifest 权限面、asar/VSIX/JAR/Mod 加载链 → `plugin-targets`（R25）。
- 本技能可**读取**这些领域产物作为输入，但不重复其方法体系。

---

## A. 协议复刻（R24）

### A1 产物先定

开工先写清：目标端点、客户端版本、协议层（HTTP/WS/TCP/UDP）、是否 TLS、验收方式。
产物至少包含：`capture.pcapng`、`frames.jsonl`（原始字节+方向+时间）、`schema.md`、`replay.py`、`evidence.md`。
详细命令与字段推断表见 `references/protocol-reverse.md`；二进制头/长度/校验见 `references/binary-protocols.md`；状态机与重放见 `references/state-machine-and-replay.md`。

### A2 抓包：先看“谁和谁、说了什么”

```bash
tshark -r capture.pcapng -q -z conv,tcp
tshark -r capture.pcapng -Y "tcp.port==9527 && tcp.len>0" \
  -T fields -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e data.data
```

- 已有 pcap 时优先 `seep_pcap_extract(pcap, mode='summary'|'http'|'payload', port=...)`，再补 tshark；无 tshark 用 `scripts/pcap-summary.py`。
- HTTP(S) 交互用 mitmproxy：`mitmdump -p 8080 -w flows.mitm`；需要看明文时设置 `SSLKEYLOGFILE` 或安装 mitm 证书。**先确认是否 pinning/双向认证**，抓不到不等于没有流量。
- WebSocket 必须按消息而不是 TCP 段分析：记录 opcode、FIN、掩码、压缩位；见 §D。
- 每个抓包文件记录：工具、网卡/代理、时间、客户端版本、是否重放污染。

### A3 分帧与字段推断

按以下顺序判定帧边界，**每一层都拿 ≥3 帧验证**：

1. **边界**：先试定界符（`\r\n\r\n`、`\0`、固定尾标），再试长度前缀（u8/u16/u32、大小端、是否含头/含自身/含 CRC）。
2. **头部**：magic（2/4 字节）、version、type/opcode、flags、seq、校验；TLV 看 tag/length 宽度与嵌套层数。
3. **载荷与证据**：先标“未知”；用 ≥3 帧验证，长度按 `len_field = payload + a*header + b` 解端序与覆盖范围；证据写 `offset/size/endian/样例/反例`。熵 > 7.5 先怀疑压缩/加密。

### A4 状态机重建

把每条消息标成 `state_before → event → state_after`，至少覆盖：

- 握手/认证：版本协商、能力位、随机数、证书；token、cookie、签名、时间戳、nonce。
- 业务/保活/关闭：请求 id 与响应配对规则；心跳周期、超时、重连；错误码与重试策略。

**判据**：能画出状态迁移图，并解释“服务端为什么接受下一帧”。无法解释的迁移标 `UNKNOWN`，不要编。

### A5 重放：先复现，再构造

- HTTP：优先 `seep_http_replay(url, method, headers, cookies, body, impersonate='chrome', session_file=...)`；
  保留原始 header 顺序无关，但 `Host/UA/Referer/Content-Type/Cookie/签名头` 必须齐全。
- 非 HTTP：用 `replay.py` 按帧写入 socket，记录发送字节、响应字节、RTT；先做**逐字节原样重放**。
- 对比基线：状态码、响应长度、业务码、响应体哈希、关键字段。差异先归因到“环境/会话/时间”，再归因到协议。
- 构造新请求：只改一个字段（如业务 id），预测响应并验证；重复 3 次以排除偶然。
- 只对授权环境重放；禁止对生产做高频/破坏性扫描。

### A6 二进制协议专项

按“头 → 体 → 尾”建表，最少记录：

| 区域 | 必查 |
|---|---|
| magic/version | 固定值？协商后变化？ |
| type/flags | 请求/响应/心跳/错误位 |
| length | 端序、覆盖范围、最大帧 |
| seq/ack/nonce | 递增、随机、回显、防重放窗口 |
| payload | 压缩？序列化？加密？ |
| checksum | CRC16/CRC32/Adler/自定义；覆盖哪些字节 |

- 校验和：先用已知帧反推多项式/初值/异或；改一个字节验证“服务端是否拒绝”。
- 加密段：找 nonce/IV/counter 字段；用已知明文-密文对判定算法族；必要时在客户端 `send/recv/SSL_write/SSL_read` 处取明文，而不是暴力猜密钥。
- 序列化/压缩：protobuf 看字段号/wire type，flatbuffers 看 vtable/offset；先判 gzip/deflate/zstd/自定义字典，解压后再分帧；长期维护优先 Kaitai Struct 或 scapy。

### A7 协议完成判据（缺一不可）

1. **同输入同输出**：同一请求重复发送，响应结构与关键字段一致（允许时间/nonce 变化，需解释）。
2. **能构造新请求**：不依赖抓包中的原帧，能生成服务端接受的新业务请求，并预测结果。
3. **状态可推进**：至少完成一次“握手/认证 → 业务 → 关闭”的完整闭环。
4. **负例可解释**：错误校验/错 seq/错 token 被拒，且拒绝方式与推断一致。
5. **证据可复现**：他人按 `schema.md + replay.py` 能复跑。

### A8 失败判据（何时停并降级）

- 连续 2 次抓包无应用层字节，且已排除网卡/代理/TLS keylog → 停，转进程内取明文或静态；不再堆过滤器。
- 3 帧以上无法确定长度/校验覆盖范围，且单变量改动全部无响应 → 标“分帧未定”，不写字段表。
- 能重放但不能构造新请求 → 只能报“部分复刻”，卡点写清（签名、nonce、服务端风控、mTLS）。
- 服务端返回风控/封禁/验证码升级 → 立即停，保留证据，不换账号绕过。
- 密钥/证书/ token 只能从他人环境取得 → 不做，改走客户端内观测或放弃。

达不到 A7 的 1–3 只能报“部分复刻”，并列出卡点（加密、双向认证、服务端风控、缺失密钥）。

---

## B. 插件类目标（R25）

> **一行指针**：插件/扩展/Mod 的包型、入口、权限面、数据流、最小可改单元 → `plugin-targets/SKILL.md`（R25）。本技能只接收其中的协议字节并继续 A 节。

---

## C. 工具与降级

| 能力 | 首选 | 缺失时 |
|---|---|---|
| 抓包解析 | `tshark`、`seep_pcap_extract` | Wireshark GUI 导出、`scripts/pcap-summary.py`、scapy/dpkt 离线解析 |
| HTTP(S) 重放 | `seep_http_replay`、mitmproxy | requests/curl + 手工复制头；必要时 `SSLKEYLOGFILE` |
| 原始 socket | `replay.py` + 抓包基线 | Python `socket`/`ssl`，逐字节发送并记录 RTT |
| 序列化/压缩 | protoc、flatc、zstd/gzip | 手写 varint/vtable 解析；先解压再分帧 |
| 流量统计 | `capinfos`、`tshark -z` | 标准库解析 pcap/pcapng 头与包长 |

- 工具是否存在不要靠猜：`powershell -File Tool/scripts/tool-run.ps1 -ListModes`，或 `seep_tool_discover`（底层 `Tool/mcp/tool_autodiscover.py`）/ `seep_ensure_tool`。
- 需要 GUI 时走 `tool-run.ps1 -Tool <id>`；能 CLI/headless 就不开 GUI。
- 工具缺失不是停工理由：先用标准库完成 pcap/socket/hex 级工作，再补工具。

---

## D. 常见坑（按代价排序）

1. **TLS 双向认证/pinning**：抓到 TLS 不等于拿到明文；先判断证书校验位置，再决定 keylog、代理还是进程内取明文。
2. **WebSocket 分帧**：一个 TCP 段可能含多帧/半帧；必须按 FIN/opcode/长度重组，注意掩码与 `permessage-deflate`。
3. **压缩与序列化**：先解压再分帧；protobuf 字段号不等于业务字段，flatBuffers 先读 vtable。
4. **长度/校验/防重放**：长度含不含头、CRC 覆盖范围、大小端，任一错都表现为“服务端无响应”；重放失败先查 seq/nonce/时间窗/token 绑定。
5. **TCP 流边界误判**：同端口不同连接不能合并；重传/乱序/分片先重组再谈消息边界。
6. **时间与时钟**：pcap 时间戳可能是本地时区/纳秒精度；跨主机对齐前先记录 clock skew。

---

## E. 交付格式（建议）

```text
目标/版本：          路由：R24
证据：capture.pcapng#L12 / frames.jsonl#42 / schema.md:field
协议层：              帧边界：
字段表：              magic/len/seq/checksum/payload
状态机：              handshake → auth → business → close
重放：                原样复现 / 单变量构造 / 预测与结果
判据：同输入同输出 / 构造新请求 / 状态闭环 / 负例可解释
未解卡点与置信度：
```

**最后一条**：报告里每个“已确认”都要能指回证据；指不回去的，写“推断”，不要写成结论。
