# 协议真实样本（pcap / pcapng）

> 来源：[wireshark/wireshark](https://github.com/wireshark/wireshark) 官方 `test/captures/`（GPL-2.0）。
> 覆盖 HTTP / HTTP2 / WebSocket / DNS / TCP 乱序等真实协议流量，供协议逆向/抓包分析练手。

| 文件 | 协议 | 用途 |
|---|---|---|
| `http.pcap` | HTTP/1.1 | 基础请求/响应、Host/URI 提取 |
| `http2-data-reassembly.pcap` | HTTP/2 | 多帧重组、data 流 |
| `http2_follow_multistream.pcapng` | HTTP/2 | 多流并发、stream 跟随 |
| `websocket.pcapng` | WebSocket | 帧解析、握手升级 |
| `dns-mdns.pcap` | DNS/mDNS | 域名/服务发现流量 |

用途：`seep_pcap_extract`（summary/http/payload 三模式）真实样本验证；
配合 `seep_http_replay` 做金样重放。非恶意流量，教学用。
