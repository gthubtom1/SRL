# protocol02 产物说明

- 输入：`input/sample.bin`（sha256 `110da7c87b2cb7d145506ca7549fd771d088b05f6e97f1b104de3e4c0f9803c4`，141 B）；帧格式见 `input/notes.md`（sha256 `58b190565eaa995b92516b8e70841c1cc3cf3ada013d0fdd858e37d4fcdec9de`）。
- 运行 1：`python ../../../Tool/scripts/pcap-summary.py --file input/sample.bin --json`，rc=0；stdout 为 `ok=false / pcap_parse_error / magic=53505258`。兼容入口在 Windows 上丢失了目标脚本退出码，**不能据此判成功**。
- 运行 2：`python ../../../Tool/skill/protocol-plugin/scripts/pcap-summary.py --file input/sample.bin --json`，rc=2，同一错误；确认该脚本只接受 pcap/pcapng，不解析裸二进制帧。
- 人工结果（见 notes.md 帧表）：3 帧均为 `SPRX + ver=1 + type + len(BE) + seq + payload + CRC32`；payload 长度 36/30/27 B，帧长 52/46/43 B，CRC32 分别为 `0xe59f1d6e`/`0xb0542e66`/`0x0280ee21`，按 header+payload 覆盖可复现。payload 是明文 JSON，原设计的 AES-CBC 段未出现。
- 还差：真实 TCP pcap、≥3 帧反推 length/CRC 覆盖、半包/粘包/乱序重同步测试，以及可复跑 parser.py；当前不能证明真实流量格式。
