# 私有协议复刻（分帧 → 状态机 → 按需构造）

- 触发词：私有协议、二进制协议、分帧、长度字段、CRC、状态机、重放、构造新请求、BLE、GATT、蓝牙、HID、Modbus、工控、PLC、WebSocket、protobuf
- 用到的能力（capability id）：`tool:tshark` `tool:dumpcap` `repo:case_state` `repo:pcap-summary` `repo:proto-repro` `repo:proto-accept` `repo:protobuf_decode_raw`
- 输入：用户提供的抓包、客户端或设备、目标及允许的操作；结论和实验范围以实际任务与授权为准。
- 步骤：先发现工具。离线摘要可用 `python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file <PCAP> --json`；需要 tshark 时用 `python Tool/scripts/tool-acquire.py --tool tshark --json` 查询获取入口。安装或接入后在运行脚本的环境中复验 `tshark` 可从 PATH 调用；未就绪时保留缺口，继续可做的离线分析。
- 步骤：`pcap-summary.py --extract <目录>` 的 `s*.bin` 是按方向性五元组和抓包顺序拼接的包载荷，`frames.jsonl` 是包级记录；均不自动完成 TCP 重组。用 `python Tool/skill/protocol-plugin/scripts/proto-repro.py --pcap <PCAP> --stream <n> --direction forward --json` 按连接、方向及 TCP sequence 有界重组，`reverse` 选择反向；缺少唯一的起始 SYN、对端 SYN/ACK 或所选方向 FIN，或有缺口、冲突、RST 或超限时结构化失败，不进入分帧。区间连续不证明对端收到或服务端接受；独立重组时也须处理乱序、重传、重叠和缺口，无法验证时保留限制。
- 步骤：对已核实的单向字节流选择与样本相符的 schema：`python Tool/skill/protocol-plugin/scripts/proto-repro.py --schema <schema.json> --input <重组流.bin> --json`。默认及 `--emit-schema` 是 SPRX 夹具模板；`skipped_bytes`、尾部和每帧原字节都要核对。构造时用 `--input`、`--rebuild`、`--frame-index`、所需的 `--set` 或 `--payload-text` 和 `--out <新帧.bin>`；`rebuild.verify` 是含 `parsed` 和 `crc_ok` 的对象，只证明有限的离线自洽，未知或缺失校验可能为 null。
- 步骤：状态模型的 `edge_coverage`、帧号及负例文字只是输入声明的统计，不是状态或负例已验证。核对每条边与抓包或实验记录；`python Tool/skill/protocol-plugin/scripts/proto-accept.py --case <case> --json` 只检查案例元数据和记录，rc=0 不等于真实互操作。需要真实重放或新请求时，另行记录实际端点、请求、完整响应、预测与差异；没执行或无法确认时标明未验证。
- HTTP 流量可按实际需要交接 `web-pentest`；MCP 的 `seep_pcap_extract` 可提取抓包，`seep_http_replay` 可处理其接口支持的 HTTP 请求。TLS、认证、WebSocket 帧或自定义协议不能仅凭 HTTP 重放入口视为已覆盖；先检查工具和实际能力，再按任务选择路线。
