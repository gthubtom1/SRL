# protocol-plugin 任务卡（24 张）

> 入口：`Tool/skill/protocol-plugin/SKILL.md`。每张卡固定六段，`reference` 指向本域 reference。
> 统一前置：只分析自有/授权流量；抓包用 BPF 收敛；重放只在本地或靶场；不猜密钥、不猜字段。
> 统一失败口径：见 `Tool/skill/protocol-plugin/references/02-failure-criteria.md`，不把疑似写成确认。
> 边界：插件 / 扩展 / Electron asar / 游戏 Mod → `plugin-targets`（R25），本文件不重复其方法。

### 01 tshark 首轮分诊（源：performing-network-traffic-analysis-with-tshark）
- 触发词：`tshark`、抓包分析、conv,tcp、io,phs、首轮分诊
- 前置：pcap 在手；知道抓包点与是否 TLS；`tshark -v` 可用（缺失则用 pcap-summary.py 降级）
- 步骤：1) `python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file Tool/cases/protocol01/input/sample.pcap --json` → rc=0，期望：`"packet_count": 3`、`"session_count": 2`、snippets 含 `GET /login HTTP/1.1`；2) `python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file Tool/cases/protocol03/input/websocket.pcapng --json` → rc=0，期望：`"format": "pcapng"`、`"packet_count": 18`；3) `python Tool/skill/protocol-plugin/scripts/pcap-summary.py --self-test` → rc=0，期望：`"ok": true`
- 判据：能说出"主协议层 + 会话数 + 每个方向字节数"；`conv,tcp` 的帧数总和等于 `io,phs` 的 frame 数；首轮 `edge_coverage` 写进报告（骨架阶段通常 <0.6，只作基线，不作结论）
- 失败判据：只有 `data`/`tls` 层且无 keylog → 停，转进程内明文；不要靠加过滤器硬凑
- reference：Tool/skill/protocol-plugin/references/04-walkthrough-websocket-replay.md

### 02 抓包点与捕获文件体检（源：performing-network-packet-capture-analysis）
- 触发词：pcapng、linktype、截断、editcap、capture 文件损坏、时间戳异常
- 前置：确认文件不是被截断的（snaplen）、不是多网卡合并、时区已知
- 步骤：1) `python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file Tool/cases/protocol04/artifacts/live.pcapng --json` → rc=0，期望：`"format": "pcapng"`、`"linktype_name": "NULL/LOOP"`、`"packet_count": 39`；2) `python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file Tool/cases/protocol01/input/sample.pcap --json` → rc=0，期望：`"format": "pcap"`、`"linktype_name": "EN10MB/Ethernet"`；3) `python Tool/skill/protocol-plugin/scripts/pcap-summary.py --self-test` → rc=0，期望：`"ok": true`
- 判据：`format/linktype/包数/时长` 两套工具一致；pcapng 的 if_tsresol 被正确解析（时间在合理年份）
- 失败判据：包数对不上 → 文件截断或多段合并，先修文件再谈协议
- reference：Tool/skill/protocol-plugin/references/01-criteria.md

### 03 Zeek 日志与原始字节对照（源：performing-network-traffic-analysis-with-zeek）
- 触发词：`zeek`、conn.log、dns.log、http.log、日志与 pcap 对照
- 前置：zeek 可用或已有日志；知道日志是"观察"不是"事实"
- 步骤：1) `zeek -r x.pcap` 生成 conn/dns/http 日志 2) 取一条 conn.log 的 `uid` 3) 用五元组回 pcap 找同一会话，逐字节复核字段
- 判据：日志里的 `orig_bytes/resp_bytes` 与 `pcap-summary.py` 的 `payload_bytes` 同量级；关键字段（host/uri）在原始字节里能找到
- 失败判据：zeek 把私有协议记成 `unknown_transport` → 正常，改用字段表自建解析，不要等 zeek 支持
- reference：Tool/skill/protocol-plugin/references/05-binary-framing.md

### 04 DNS 查询/响应配对与字段表（源：performing-dns-enumeration-and-zone-transfer）
- 触发词：`dns`、qname、qtype、AXFR、事务 id、响应配对
- 前置：有 DNS 流量或可对本地 resolver 发查询；不对外网做区域传送
- 步骤：1) `tshark -r x -Y dns -T fields -e frame.number -e dns.id -e dns.flags.response -e dns.qry.name -e dns.qry.type` 2) 按 `dns.id` 配对请求/响应 3) 统计 qname 长度/标签数/熵，判断是否异常编码 4) 把配对结果写成边集 `{"from":"QUERY","to":"RESPONSE","evidence_frame":N}`，用 `pcap-summary.py --state-model edges.json --json` 算配对率
- 判据：请求与响应按 id 一一配对；qname 的标签 ≤63 B、总长 ≤253；异常样本能被量化（长度/熵）；无响应的 qid 必须进 `unobserved[]`，不得计为已配对（`edge_coverage` 只算有帧号的边）
- 失败判据：只在缓存里看到响应无请求 → 抓包点不在递归路径上，换点重抓
- reference：Tool/skill/protocol-plugin/references/05-binary-framing.md

### 05 DNS 隧道载荷还原（源：performing-dns-tunneling-detection）
- 触发词：dns 隧道、TXT 记录、base32 子域、长 qname、编码还原
- 前置：已确认有异常 qname；有请求/响应两侧；只做离线还原
- 步骤：1) 按 `dns.id` 排序取 qname 序列 2) 尝试 base32/base64/hex 解码，记录哪种能解出可打印字节 3) 用响应 TXT 的字节做二次验证（长度/结构）
- 判据：解出的字节流有结构（长度前缀/JSON/文件头），且能跨 ≥3 个 qname 连续；不是"解出一堆随机字节"
- 失败判据：qname 高熵但任何编码都解不出结构 → 只能报"疑似隧道"，不写"已还原"
- reference：Tool/skill/protocol-plugin/references/07-crypto-and-checksum.md

### 06 DNS 外泄流量量化（源：detecting-dns-exfiltration-with-dns-query-analysis）
- 触发词：dns 外泄、子域长度分布、查询频率、唯一 qname 比例
- 前置：有基线窗口（正常时段）与可疑窗口；时间对齐到 UTC
- 步骤：1) 分别统计两个窗口的 qname 数量/唯一率/平均长度/间隔 2) 算比值（可疑/基线）3) 抽 3 条最长 qname 做结构分析
- 判据：唯一率或平均长度显著高于基线（给出具体倍数），且能指认对应帧号；否则只写"无显著差异"
- 失败判据：基线窗口本身也被污染（同一客户端在跑更新）→ 换基线，不要硬解释
- reference：Tool/skill/protocol-plugin/references/01-criteria.md

### 07 Zeek 规则化 DNS 隧道验证（源：hunting-for-dns-tunneling-with-zeek）
- 触发词：zeek 脚本、dns.log 字段、阈值规则、重复验证
- 前置：已有 zeek 日志；规则只做"筛样本"，结论仍要回原始字节
- 步骤：1) 写最小 zeek 事件筛 `qname 长度 > N` 2) 导出命中列表 3) 逐条回 pcap 复核（帧号 + 原始 hex）
- 判据：规则命中项 100% 能在 pcap 找到对应帧；规则漏报的样本也要抽查 5 条
- 失败判据：只报"规则命中 N 条"而不回原始字节 → 属于告警，不是协议结论
- reference：Tool/skill/protocol-plugin/references/01-criteria.md

### 08 WebSocket 握手与消息分帧（源：testing-websocket-api-security）
- 触发词：`websocket`、101 Switching Protocols、opcode、mask、FIN
- 前置：抓到 ws 握手 + ≥3 条业务消息；知道是否 permessage-deflate
- 步骤：1) `python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file Tool/cases/protocol03/input/websocket.pcapng --json --extract work/ws08` → rc=0，期望：`"session_count": 2` 且 snippets 含 `GET /ws HTTP/1.1`；2) `python Tool/skill/protocol-plugin/scripts/proto-repro.py --input Tool/cases/protocol02/input/sample.bin --json` → rc=0，期望：`"frame_count": 3`、fields.magic=`SPRX`；3) `python Tool/skill/protocol-plugin/scripts/proto-accept.py --json` → rc=0，期望：`"ok": true` 且含 routing 结论
- 判据：8/8 帧帧长公式成立；客户端 mask=1、服务端 mask=0；accept = base64(sha1(key+GUID))
- 失败判据：按 TCP 段解消息 → 半截 JSON；先把重组写对
- reference：Tool/skill/protocol-plugin/references/04-walkthrough-websocket-replay.md

### 09 WebSocket 新消息构造（源：exploiting-websocket-vulnerabilities）
- 触发词：ws 构造、回显协议、data 字段、单变量、预测响应
- 前置：已确认帧格式与业务字段；有本地 ws 回显服务（不连外部目标）
- 步骤：1) `python Tool/skill/protocol-plugin/scripts/proto-repro.py --input Tool/cases/protocol02/input/sample.bin --rebuild --set seq=9 --payload-text '{"sensor":"lab-02","proto":"sprx/1"}' --out work/new-frame.bin --json` → rc=0，期望：`"new_len": 52`、`"verify": {"parsed": true, "crc_ok": true}`；2) `python Tool/skill/protocol-plugin/scripts/proto-repro.py --self-test` → rc=0，期望：`"ok": true`；3) `python Tool/skill/protocol-plugin/scripts/proto-accept.py --json` → rc=0，期望：`"ok": true`
- 判据：响应与预测一致且重复 3 次稳定；`new-frame.bin` 能被自己的解析器解析回同一字段
- 失败判据：只能原样重放、改字段即被拒 → 只报"部分复刻"，卡点写鉴权/风控
- reference：Tool/skill/protocol-plugin/references/04-walkthrough-websocket-replay.md

### 10 IPv6 / ICMPv6 报文分帧（源：exploiting-ipv6-vulnerabilities）
- 触发词：`ipv6`、ICMPv6、NDP、RA、扩展头、linktype 229
- 前置：pcap 含 IPv6；知道扩展头链（0/43/44/51/60）
- 步骤：1) `pcap-summary.py` 看 linktype 与 IPv6 会话 2) `-Y icmpv6 -T fields -e icmpv6.type -e icmpv6.code -e ipv6.src -e ipv6.dst` 3) 对分片/扩展头逐层记录偏移
- 判据：扩展头链解析后 payload 起点与 tshark 一致；ICMPv6 type/code 与语义表对得上
- 失败判据：把扩展头当 payload → 后续字段全错位；先修跳表逻辑
- reference：Tool/skill/protocol-plugin/references/05-binary-framing.md

### 11 BGP UPDATE 报文复刻（源：exploiting-bgp-hijacking-vulnerabilities）
- 触发词：`bgp`、UPDATE、NLRI、AS_PATH、路径属性、TCP 179
- 前置：有 BGP 抓包或本地 BGP 会话；只做离线解析/本地复刻
- 步骤：1) 取一条 UPDATE 帧，按 marker/length/type 分帧 2) 解析 withdrawn routes / path attributes（type+len+value）3) 手工拼一条只改 NLRI/AS_PATH 的 UPDATE，校验 length 字段
- 判据：length 字段 = 19 + 后续字节；属性 TLV 的 len 与 value 长度一致；复刻帧能被同一解析器读回
- 失败判据：把 32 字节 marker 当 magic 常量而不校验 → 分帧会在错误位置开始
- reference：Tool/skill/protocol-plugin/references/05-binary-framing.md

### 12 BGP RPKI 验证的可见面（源：implementing-bgp-security-with-rpki）
- 触发词：`rpki`、ROA、origin validation、BGP 属性、可见面
- 前置：只有抓包/日志，没有 RPKI 数据库写入权限；不对外通告
- 步骤：1) 从 UPDATE 里取 prefix + origin AS 2) 记录验证状态字段（若设备导出）3) 与抓包里的实际 origin 对照，标注"观测到/未验证"
- 判据：能指认某条 UPDATE 的 prefix/origin 与验证状态来源；不能指认就写"未验证"
- 失败判据：把"没有 ROA"当成"一定被劫持" → 结论越界，降为线索
- reference：Tool/skill/protocol-plugin/references/01-criteria.md

### 13 802.1Q / VLAN 标签分帧（源：performing-vlan-hopping-attack）
- 触发词：`vlan`、802.1Q、双标签、TPID 0x8100、qinq
- 前置：有带 VLAN 标签的抓包；知道抓包网卡是否剥离标签
- 步骤：1) 看 `eth.type`/`vlan.id` 字段 2) 手工按 Ethernet(14) + 8100 + TCI + 内层 ethertype 计算偏移 3) 对比 tshark 的 `vlan.id` 与自己的偏移
- 判据：标签层数与偏移完全吻合；双标签时内层 ethertype 正确
- 失败判据：抓包网卡已剥离 802.1Q → 看不到标签，换镜像口/监控模式，别硬解释
- reference：Tool/skill/protocol-plugin/references/05-binary-framing.md

### 14 ARP 报文结构与异常检测（源：detecting-arp-poisoning-in-network-traffic）
- 触发词：`arp`、 gratuitous arp、MAC-IP 映射、冲突、重复通告
- 前置：抓包含 ARP；知道本网段正常映射基线
- 步骤：1) `-Y arp -T fields -e arp.opcode -e arp.src.proto_ipv4 -e arp.src.hw_mac` 2) 统计同一 IP 出现的 MAC 集合 3) 对冲突项回取原始帧确认（不是解析误差）4) 把"旧映射 → 新映射"写成边 `{"from":"IP@MAC_old","to":"IP@MAC_new","evidence_frame":N}`，跑 `--state-model`
- 判据：冲突能被 ≥2 条帧复现，且时间上后到的通告覆盖先前的；单条异常只写"疑似"；`illegal_transition_proof` 要写成"帧号 + 被覆盖的旧映射"，无此证据的边只算 `unobserved`
- 失败判据：把虚拟机/HA 的正常漂移当投毒 → 先排除已知的 MAC 漂移来源
- reference：Tool/skill/protocol-plugin/references/06-app-state-machine.md

### 15 报文注入的离线复刻（源：performing-packet-injection-attack）
- 触发词：报文注入、scapy、重放、构造、checksum 重算
- 前置：只在本地/靶场；有原始帧与可预测的响应基线
- 步骤：1) 原样重放 1 次建基线 2) 只改一个字段，重算长度与校验 3) 预测响应并比对 3 次
- 判据：响应与预测一致；错校验帧被拒且拒绝方式与模型一致
- 失败判据：对生产环境注入/高频重放 → 越界，立即停
- reference：Tool/skill/protocol-plugin/references/08-replay-and-new-request.md

### 16 SMB2 协商与会话帧（源：exploiting-smb-vulnerabilities-with-metasploit）
- 触发词：`smb`、SMB2、NEGOTIATE、SESSION_SETUP、TREE_CONNECT、NetBIOS 头
- 前置：有 SMB 抓包或本地 Samba/Windows 靶机；凭据爆破另立授权任务
- 步骤：1) 按 4 字节 NetBIOS length 分帧 2) 解析 SMB2 header（ProtocolId/Command/MessageId/TreeId）3) 按 MessageId 配对请求/响应 4) 把 NEGOTIATE→SESSION_SETUP→TREE_CONNECT→CREATE 的每条迁移写成边集，跑 `pcap-summary.py --state-model edges.json --json`
- 判据：NetBIOS length = 后续字节数；Command 与 MessageId 配对一致；能说出协商出的 dialect；每条边的 `evidence_frame` 必须指向真实帧（dissector 推断出来的边标 `"source":"llm"`，计入 `llm_unverified`，`edge_coverage ≥0.60` 才可写"状态机成立"）
- 失败判据：SMB3 加密（share encryption）下只见密文 → 记录"加密共享"，字段留 `unknown`
- reference：Tool/skill/protocol-plugin/references/06-app-state-machine.md

### 17 流量基线：会话/字段分布（源：implementing-network-traffic-baselining）
- 触发词：基线、会话分布、字段分布、异常检测、时间窗
- 前置：有可比的正常窗口；时间统一 UTC；样本量 ≥100 会话
- 步骤：1) `python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file Tool/cases/protocol04/artifacts/live.pcapng --top 5 --json` → rc=0，期望：`"session_count": 6`、sessions 长度 5；2) `python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file Tool/cases/protocol01/input/sample.pcap --json` → rc=0，期望：`"session_count": 2`；3) `python Tool/skill/protocol-plugin/scripts/pcap-summary.py --self-test` → rc=0，期望：`"ok": true`
- 判据：异常项给出具体倍数与帧号；基线本身无未解释的异常
- 失败判据：样本 <30 会话就下"基线"结论 → 统计上不成立，降为"初筛"
- reference：Tool/skill/protocol-plugin/references/01-criteria.md

### 18 Arkime 会话索引与 pcap 对照（源：implementing-network-traffic-analysis-with-arkime）
- 触发词：`arkime`、session 索引、pcap 回放、字段对照
- 前置：有 Arkime 导出（或本地只读实例）；知道索引字段是"解析结果"不是"原始字节"
- 步骤：1) 从索引取一条会话的五元组/时间/字节数 2) 用同样条件回 pcap 找帧 3) 逐字段复核（host/uri/长度）
- 判据：索引与 pcap 的字节数同量级、关键字段能在原始字节里找到；差异有解释（截断/方向）
- 失败判据：只信索引字段而不回 pcap → 无法排除 dissector 误判
- reference：Tool/skill/protocol-plugin/references/04-walkthrough-websocket-replay.md

### 19 NetFlow/流记录字段与 pcap 对齐（源：analyzing-network-flow-data-with-netflow）
- 触发词：`netflow`、ipfix、流记录、五元组、字节数
- 前置：有流记录与同时间窗 pcap；知道采样率（若有）
- 步骤：1) 取一条流记录（src/dst/port/bytes/packets）2) 在 pcap 里按五元组+时间窗过滤 3) 对比包数/字节数，按采样率折算
- 判据：折算后差异 <10% 且能解释（采样/超时切流）；否则说明时间窗或采样率假设错
- 失败判据：流记录没有 payload → 永远不能替代分帧证据，只能做"哪条会话值得看"
- reference：Tool/skill/protocol-plugin/references/04-walkthrough-websocket-replay.md

### 20 WireGuard/Noise 握手帧识别（源：deploying-tailscale-for-zero-trust-vpn）
- 触发词：`wireguard`、noise、handshake initiation、UDP 长连接、tailscale
- 前置：有 UDP 抓包；明确只能看握手类型与长度，不能解 payload
- 步骤：1) 按 UDP 端口与长度分布找握手帧（148/92 字节量级）2) 记录 type 字节与计数器 3) 标出哪些是 keepalive（32 B 空包）
- 判据：能区分 handshake initiation / response / transport / keepalive 四类；字段结论只到"类型+长度"
- 失败判据：声称解出密钥/会话 → 越界且技术上不成立；停
- reference：Tool/skill/protocol-plugin/references/02-failure-criteria.md

### 21 VLAN 分段下的抓包点选择（源：configuring-network-segmentation-with-vlans）
- 触发词：网段隔离、trunk、镜像口、抓包点、veth
- 前置：知道拓扑（哪台交换机/哪个 veth）；有权限在目标点抓包
- 步骤：1) 画最小拓扑（源/目的/中间设备）2) 在每个候选点各抓 10 s 3) 对比哪些点能看到完整双向流量
- 判据：选定点能看到握手 + 业务 + 关闭；其它点缺失的部分有拓扑解释
- 失败判据：只在镜像口看到单向 → 该点不可用于重放基线
- reference：Tool/skill/protocol-plugin/references/01-criteria.md

### 22 隐蔽通道：载荷熵与分帧异常（源：analyzing-network-covert-channels-in-malware）
- 触发词：隐蔽通道、载荷熵、固定间隔、DNS/ICMP 承载、异常长度
- 前置：有可疑样本流量与正常基线；只做静态/离线分析
- 步骤：1) 对每条会话算 payload 熵与包长分布 2) 找"固定间隔 + 固定长度 + 高熵"的组合 3) 抽取 3 条样本做结构分析（是否 base64/压缩/加密）
- 判据：异常组合能在基线上复现差异（给出数值）；能指认承载协议（DNS TXT/ICMP data/TCP 保留字段）
- 失败判据：只凭"熵高"就判恶意 → 压缩/加密流量也高熵；必须结合间隔与承载字段
- reference：Tool/skill/protocol-plugin/references/07-crypto-and-checksum.md

### 23 BLE ATT 帧与抓包边界（源：performing-bluetooth-security-assessment）
- 触发词：`ble`、ATT、GATT、handle、opcode、btle
- 前置：有 BLE 抓包（Ubertooth/nRF）或明确"无抓包"；知道 BLE 跳频导致丢包
- 步骤：1) 确认抓包是否含完整连接事件（否则只能看广播）2) 按 ATT opcode/handle 列表 3) 对读/写请求与响应按 handle 配对
- 判据：同 handle 的 read/write 请求-响应能配对；丢包率可量化（缺失的连接事件数）
- 失败判据：没有 BLE 抓包硬件 → 明确写"未采集"，不要用手机截图冒充协议证据
- reference：Tool/skill/protocol-plugin/references/05-binary-framing.md

### 24 S7comm 功能码与 PDU 分帧（源：performing-s7comm-protocol-security-analysis）
- 触发词：`s7comm`、TPKT、COTP、ROSCTR、功能码、PLC、102 端口
- 前置：有 S7 抓包或本地 PLC 仿真（Snap7）；默认只读，不写寄存器
- 步骤：1) 按 TPKT(4B) + COTP + S7 header 分层定界 2) 解析 ROSCTR/PDU reference/function code 3) 按 PDU reference 配对请求与响应 4) 把"读/写功能码迁移"写成边集并用 `--state-model` 算 `edge_coverage`；未见过的写操作边一律 `inferred`
- 判据：TPKT length = 后续字节数；COTP 后 S7 header 偏移固定；功能码与响应项一一对应；轮询类重复边不重复计数（同一 `from/to` 取首个 `evidence_frame`），写操作边未观测时不得画实线
- 失败判据：只看到轮询未见配置下发 → 不能推断"支持写操作"；写操作会触发物理动作，默认只读、写操作按授权单
- reference：Tool/skill/protocol-plugin/references/06-app-state-machine.md
