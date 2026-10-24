# protocol01 产物说明

- 输入：`input/sample.pcap`（628 B，手工构造的 HTTP/1.1 夹具）。
- 运行（完整 cmd/rc/stdout 见 `run.json`）：
  1. `python ../../../Tool/skill/protocol-plugin/scripts/pcap-summary.py --file input/sample.pcap --json`，rc=0（兼容入口）。
  2. `python ../../../Tool/skill/protocol-plugin/scripts/pcap-summary.py --file input/sample.pcap --json --extract artifacts/streams --tshark-check`，rc=0。
  3. `tshark -r input/sample.pcap -Y http -T fields ...`，rc=0。
- 结果：pcap / EN10MB，3 包、2 个方向性 TCP 会话；明文含 `GET /login`、`Host: lab.example.test`、
  `Authorization: Bearer abc`、`Set-Cookie: sid=deadbeef`、`GET /dashboard`；响应体 36 B 与
  `Content-Length: 36` 一致（见 `pcap-summary.json`）。
- 产物：
  - `pcap-summary.json`：会话表 + 明文片段 + tshark 分层交叉验证；
  - `streams/s00…bin` / `s01…bin`：C2S 238 B / S2C 156 B 的方向性字节流，可直接喂给 `proto-repro.py`；
  - `streams/frames.jsonl`：逐包 `payload_hex`，可复算长度；
  - `tshark-http.tsv`：tshark 只列出 2 条请求、未把反向 200 归入同一 `tcp.stream`（样本无握手，属工具边界）。
- 边界：夹具样本，无 SYN/握手、无 TLS、无失败分支；token 为静态假值，未做重放/构造，
  不能据此推断真实服务的鉴权与过期语义。
