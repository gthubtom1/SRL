# protocol03 产物说明

- 输入：`input/websocket.pcapng`（2904 B，Wireshark 官方 `test/captures` 真实抓包，
  sha256 `ea9fcd3de02bf1824cdcff4bb61f842a6135fbc5d6b154cad00927ed3aa776d2`）。
- 运行（完整 cmd/rc/stdout 见 `run.json`）：
  1. `pcap-summary.py --file input/websocket.pcapng --json --extract artifacts/streams --tshark-check`，rc=0；
  2. `tshark -Y websocket -T fields -e … -e websocket.payload_length -e tcp.payload`，rc=0；
  3. `tshark -Y http -T fields -e … -e http.sec_websocket_key -e http.sec_websocket_accept`，rc=0；
  4. `python input/build_ws_frame.py artifacts/new-frame.bin`，rc=0。
- 产物：
  - `pcap-summary.json`：18 包 / 2 方向性会话 / pcapng（if_tsresol 已解析，时间戳 1694247103）；
  - `streams/s00…bin`、`s01…bin`：C2S 403 B / S2C 333 B；`frames.jsonl`：逐包 hex；
  - `ws-frames.tsv`：8 个 ws 帧的 opcode/fin/mask/payload_length/tcp.len/masking_key；
  - `ws-handshake.tsv`：`GET /ws` + `101 Switching Protocols` 与 `Sec-WebSocket-Key/Accept`；
  - `new-frame.bin` + `rebuild.json`：按 RFC 6455 构造的 54 B 客户端帧（data=4242…）与预测响应 51 B。
- 结论：`frame_len = 2 + (mask?4:0) + payload_length` 在 8/8 帧成立；客户端 4 帧 mask=1 且
  掩码键逐帧随机（9fc7b2e7/8db50908/7e8c1f05/50685920），服务端 4 帧 mask=0；4 组请求-响应
  `data` 完全相等（回显协议）。
- 边界：回环明文、无鉴权/TLS/压缩；新帧未连服务端验证（只到"结构自洽"）；样本无 ping/pong/close/分片。
