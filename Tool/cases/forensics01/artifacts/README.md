# forensics01 产物说明

- 输入：`input/capture.pcap`（sha256 `721a890496a67fed9df25d9e5bee55af73dd0890c606cadf68cd841c5b893a7a`，628 B，复制自 protocol01 样本）。
- 运行 1：`python ../../../Tool/skill/forensics-mobile/scripts/forensics-check.py --file input/capture.pcap --json`，rc=0。识别 pcap/EN10MB，3 包、未截断；时间线 `2026-10-20T03:14:05Z` – `2026-10-20T03:14:05.910000Z`；完整性 sha256 与输入一致；警告文件可写。
- 运行 2（补充内容证据）：`python ../../../Tool/skill/protocol-plugin/scripts/pcap-summary.py --file input/capture.pcap --json`，rc=0。2 个方向性会话；`10.20.0.15:49152 → 10.20.0.5:80` 含 `GET /login` 与 `Authorization: Bearer abc`，响应为 `HTTP/1.1 200 OK` 且 `Set-Cookie: sid=deadbeef`，随后同连接 `GET /dashboard` 带该 Cookie。
- 边界：单次构造会话，无 DNS/TLS/文件对象导出；pcap 时间戳由构造脚本写入，未与主机日志/NTP 对齐；文件 mtime 是构建时间，不是证据时间。四要素已按包内容记录，但来源链只覆盖本样本。
