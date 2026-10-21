# 真实 pcap 练习：用仓库自带样本练判据

> 入口信号：想练手但不想碰生产流量。仓库 `Tool/samples/real/protocol-pcaps/` 有 5 份
> Wireshark 官方 test/captures 的真实抓包（GPL-2.0，非恶意流量）。
> 每个练习都有"预期结论"和"失败判据"——做不出来就说明判据还没掌握。
> 深水区：`Tool/skill/protocol-plugin/references/01-criteria.md`（判据）、
> `04-walkthrough-websocket-replay.md`（完整走查）。

## 准备

```bash
cd /d/Seep-Reverse-Lab      # 或你的仓库根
S=Tool/samples/real/protocol-pcaps
ls -l $S
python Tool/skill/protocol-plugin/scripts/pcap-summary.py --self-test   # 先确认脚本可用
```

## 练习 1：`http.pcap` — 单帧样本能证明什么？

```bash
tshark -r $S/http.pcap -T fields -e frame.number -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dstport -e http.request.method -e http.host \
  -e http.request.uri -e http.user_agent
```

实测：

```text
1	10.0.0.5	207.46.134.94	3267	80	HEAD	windowsupdate.microsoft.com	/v4/iuident.cab?0307011208	Industry Update Control
```

**预期结论**：能读出 method/host/uri/UA，但**只有 1 帧**，没有响应、没有握手、没有第二个样本。
按 `01-criteria.md`，只能写"疑似：HEAD 请求带自定义 UA"，不能写"该协议用 HEAD 探测版本"。
**失败判据**：如果这一步就下"协议已确认"，说明判据分级没建立。

## 练习 2：`websocket.pcapng` — 完整分帧 + 构造（18 帧）

```bash
tshark -r $S/websocket.pcapng -q -z io,phs | head -12
tshark -r $S/websocket.pcapng -Y websocket -T fields -e frame.number \
  -e websocket.opcode -e websocket.fin -e websocket.mask \
  -e websocket.payload_length -e tcp.len
```

实测分层：`http 2 帧` + `websocket 8 帧`（其余是 TCP 握手/ACK）；
客户端 4 帧 `54 = 2+4+48`（mask=1）、服务端 4 帧 `51 = 2+49`（mask=0）。

**预期结论**：`frame_len = 2 + (mask?4:0) + payload_length` 在 8/8 帧成立；`data` 四组回显相等。
完整步骤与"构造新帧"见 `04-walkthrough` 与 `Tool/cases/protocol03/`。
**失败判据**：按 TCP 段解出半截 JSON，或把控制帧当业务消息。

## 练习 3：`http2_follow_multistream.pcapng` — 多路复用（197 帧）

```bash
tshark -r $S/http2_follow_multistream.pcapng -Y http2 -T fields \
  -e frame.number -e tcp.stream -e http2.type -e http2.streamid \
  -e http2.header.name -e http2.header.value | head -6
```

实测（节选）：

```text
13	0	1,8	13,13	:method,:path,:authority,:scheme,...	GET,/en-US/firefox/52.0.1/firstrun/,www.mozilla.org,https,...
18	0	1	13	:status,date,content-type,...	200,Wed, 29 Mar 2017 11:59:30 GMT,text/html; charset=utf-8,...
30	0	1,8	15,15	:method,:path,...	GET,/media/js/site-bundle.1688e984bc3d.js,www.mozilla.org,https,...
```

**预期结论**：同一 `tcp.stream=0` 下多个 `streamid` 并发；`http2.type` 是位图（`1,8` = HEADERS+WINDOW_UPDATE）；
请求/响应必须按 streamid 配对。该样本的 TLS 段能被 tshark 解出 h2（样本自带解密材料）。
**失败判据**：按 frame.number 顺序配请求/响应 → 串流，结论无效。

## 练习 4：`http2-data-reassembly.pcap` — 只有密文时怎么办（44 帧）

```bash
tshark -r $S/http2-data-reassembly.pcap -q -z io,phs
```

实测：

```text
frame                                    frames:44 bytes:81423
  eth → ip → tcp                         frames:44 bytes:81423
    tls                                  frames:25 bytes:80103
```

**预期结论**：看不到 `http2`，只有 `tls` → **没有 keylog/解密材料时不要猜 h2 头**。
能确认的只有：44 帧、TLS 记录层、应用数据 80 KB、无明文。要往下走只能取 keylog 或进程内明文。
**失败判据**：声称"这是 HTTP/2 的 DATA 帧"却拿不出 streamid/头块证据。

## 练习 5：`dns-mdns.pcap` — 协议分层与"哪个才是主线"（587 帧）

```bash
tshark -r $S/dns-mdns.pcap -q -z io,phs
tshark -r $S/dns-mdns.pcap -Y dns -T fields -e frame.number \
  -e dns.flags.response -e dns.qry.name -e dns.qry.type | head -6
```

实测分层：`udp 125`（mdns 63、dns 44、ntp 10、dhcp 8）、`icmpv6 270`、`igmp 65`、`tcp 28`（其中 tls 9）。
`-Y dns` 命中 64 帧，含 `rest-hw-u044.immedia-semi.com`（A/AAAA）与 `1.pool.ntp.org`。

**预期结论**：一个 pcap 里可能同时有多种协议；先看分层统计决定"主线"，再对主线做分帧。
DNS 只看 qname/qtype/flags 就能配对请求与响应（事务 id 在 `dns.id`）。
**失败判据**：把 mDNS/IGMP 噪声当主线，或在 DNS 上套 TCP 分帧逻辑。

## 练习 6（现场）：`Tool/cases/protocol04/` — 自己抓一条

```bash
cd Tool/cases/protocol04
bash input/capture_live.sh          # 自动挑 loopback，BPF 仅 tcp port 18321，抓 5 s
python ../../../Tool/skill/protocol-plugin/scripts/pcap-summary.py \
  --file artifacts/live.pcapng --json --extract artifacts/streams --tshark-check
tshark -r artifacts/live.pcapng -Y 'http.request or http.response' -T fields \
  -e frame.number -e tcp.stream -e http.request.method -e http.request.uri \
  -e http.response.code -e http.set_cookie -e http.authorization
```

**预期结论**：3 个独立 TCP 会话（curl 不复用），每会话 1 请求 1 响应，Set-Cookie 逐请求递增。
**失败判据**：抓包未用 BPF → 混入同机其它进程流量（本案例第一次就踩过，已废弃重抓）。

## 汇总：这 6 个练习各练什么

| 练习 | 练的能力 | 判据档位 |
|---|---|---|
| http.pcap | 样本量不足时如何降档 | 疑似（单帧） |
| websocket.pcapng | 帧头/掩码/回显配对/构造 | 确认 |
| http2 multistream | streamid 归属与多路复用 | 确认（有解密材料） |
| http2 data-reassembly | 只有密文时的边界 | 未定 |
| dns-mdns | 协议分层与主线选择 | 确认（DNS 部分） |
| protocol04 现场 | 抓包卫生 + 端到端取证 | 确认 |

## 边界

- 这些都是公开测试抓包/本地回环，不含真实凭据；不要把自己的生产抓包提交进仓库。
- 练习的"预期结论"只对这些样本成立，不能外推成"该协议总是这样"。
- 每条结论都要能指回帧号；指不回去的写"疑似"。
