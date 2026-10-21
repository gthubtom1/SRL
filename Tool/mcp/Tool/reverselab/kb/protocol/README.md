# Protocol 知识库 — 协议复刻（R24）

私有/二进制协议复刻的可复用卡片。技能入口：`Tool/skill/protocol-plugin/SKILL.md`。
边界：插件/扩展/Mod → `plugin-targets`（R25）；本文只处理协议字节、状态机与重放。

## 入口

- [分帧与字段](framing-and-fields.md) — magic/length/CRC/加密段/TLV/protobuf
- [从抓包到重放](capture-to-replay.md) — 会话重组、状态机、单变量构造

## 10 分钟初筛

```bash
# 无 tshark 也能跑
python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file capture.pcap

# 有 tshark
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap -Y "tcp.len>0" -T fields \
  -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e data.data
```

1. 先按 `tcp.stream`/五元组分会话，再在**双向字节流**上分帧。
2. 每类帧至少 3 条样本；先定边界，再定字段。
3. 先原样重放，再单变量构造；一次只改一个字段。
4. 结论必须能指回 `capture#frame` / `frames.jsonl#id`。

## 硬判据

- **同输入同输出**：重复发送响应结构与关键字段一致（时间/nonce 变化需解释）。
- **能构造新请求**：不依赖原帧，服务端接受并预测结果。
- **状态闭环**：握手/认证 → 业务 → 关闭至少一次。
- **负例可解释**：错长度/校验/seq/token 被拒，方式与模型一致。
- **证据可复跑**：他人按 `schema.md + replay.py` 能复现。

## 失败判据（何时停）

- 两次抓包无应用层字节，且已排除网卡/代理/TLS keylog → 转进程内取明文或静态。
- 3 帧以上无法确定长度/校验覆盖，单变量改动全部无响应 → 标“分帧未定”。
- 只能重放不能构造新请求 → 报“部分复刻”，列卡点（签名/nonce/风控/mTLS）。
- 服务端风控/封禁/验证码升级 → 立即停，保留证据，不换账号绕过。

## 工具降级

| 能力 | 首选 | 缺失时 |
|---|---|---|
| 抓包 | tshark / seep_pcap_extract | pcap-summary.py、scapy、Wireshark GUI |
| 明文 | SSLKEYLOGFILE / 进程内 hook | mitmproxy + 客户端信任 CA |
| 重放 | seep_http_replay / replay.py | requests/curl、Python socket/ssl |
| 序列化 | protoc / flatc | 手写 varint/vtable、Kaitai Struct |

缺工具不是停工理由：先用标准库完成 pcap/socket/hex 级工作，再补工具。
