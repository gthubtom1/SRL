# pcap 会话与对象：从包到可哈希文件

> **入口信号**：`capture.pcap`/`*.pcapng`，需要回答“谁和谁、何时、传了什么、服务端怎么回”。
> **不适用**：未授权抓包；只有单包/单行日志；TLS 无 keylog 且要求内容级结论。

## 1. 最小命令

```bash
capinfos capture.pcap
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap -Y "tcp.stream eq 7" -z follow,tcp,ascii,7
mkdir -p export/http && tshark -r capture.pcap --export-objects http,export/http
sha256sum export/http/* | tee export/http/SHA256SUMS
tshark -r capture.pcap -Y "dns || tls.handshake.extensions_server_name" \
  -T fields -e frame.time_epoch -e ip.src -e ip.dst -e dns.qry.name -e tls.handshake.extensions_server_name
```

## 2. 确认判据

- `capinfos` 首末时间与采集记录一致，链路类型正确，未截断。
- 会话双向字节数合理；请求行/状态码/Content-Length/响应体齐全。
- 导出对象能打开、magic 正确、SHA256 稳定；同名对象以 `tcp.stream` 建索引。
- DNS/TLS 有 qname/SNI + 时间 + 客户端 IP；外联能落到五元组。
- 与内存 `netscan`/进程、磁盘文件哈希至少一个对齐。

## 3. 失败判据

- 包数正常但重组无内容：截断/加密/分片/单向；切片、逐流、查 keylog，仍不行降为元数据。
- 只有单向流量：不能判断请求被接受，标 `inferred`。
- TLS 无 keylog 且无进程内明文：停内容级结论，只做 SNI/证书/时序。
- 日志与 pcap 差整数小时：先校时区/NTP，再排因果。
- 导出对象哈希不一致/被覆盖：按 stream 唯一命名重导。

## 4. 边界

- 只抓自有/授权网络；不嗅探他人流量；不重放攻击。
- 明文凭据/token 脱敏；只写“存在 Authorization 头”。
- “没抓到”不等于“没发生”：写清采集点/过滤/加密盲区。
- 相关：`Tool/skill/forensics-mobile/references/network-pcap-and-log.md`、`01-criteria.md`。

## 5. 输出模板

```json
{"time_utc":"2026-10-20T03:14:05Z","actor":"10.20.0.15:49152",
 "action":"HTTP GET /login","object":"10.20.0.5:80 /login (Bearer 脱敏)",
 "confidence":"observed","evidence_refs":["capture.pcap#tcp.stream=0"],
 "command":"tshark -r capture.pcap -Y 'tcp.stream eq 0' -z follow,tcp,ascii,0"}
```

## 6. 关联检查

- 会话表与 `endpoints,ip` 对得上；没有“凭空多出的 IP”。
- 导出对象哈希与磁盘/内存中的同名文件对比。
- DNS qname 与 TLS SNI 是否一致；不一致可能是 CDN/代理/域名前置。
- 时间戳与主机日志/内存连接 Created 对齐；差整数小时先查时区。
- 采集点位置（终端/网关/镜像口）写进报告，避免 NAT 误归因。
