# protocol01 产物说明

- 输入：`input/sample.pcap`（sha256 `721a890496a67fed9df25d9e5bee55af73dd0890c606cadf68cd841c5b893a7a`，628 B）
- 运行：`python ../../../Tool/scripts/pcap-summary.py --file input/sample.pcap --json`，rc=0
- 结果（完整 stdout 见 `run.json`）：pcap / EN10MB，3 个包、2 个方向性 TCP 会话、2 个命中关键字的会话；明文含 `GET /login HTTP/1.1`、`Authorization: Bearer abc`、`Set-Cookie: sid=deadbeef`、`GET /dashboard`。
- 边界：样本为手工构造的单次 HTTP 会话，未含握手/SYN 与 TLS；脚本只按包做明文片段提取，不做 TCP 流重组，未验证 token 过期/重放，也未做 WebSocket 分析。
