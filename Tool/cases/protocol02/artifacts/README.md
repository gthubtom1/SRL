# protocol02 产物说明

- 输入：`input/sample.bin`（141 B，3 帧 SPRX 夹具）；帧格式见 `input/notes.md`。
- 运行（完整 cmd/rc/stdout 见 `run.json`）：
  1. `python ../../../Tool/scripts/pcap-summary.py --file input/sample.bin --json`，rc=0；
     stdout 为 `ok=false / pcap_parse_error / magic=53505258`。兼容入口在 Windows 上丢失了
     目标脚本退出码，**不能据此判成功**。
  2. `python ../../../Tool/skill/protocol-plugin/scripts/pcap-summary.py --file input/sample.bin --json`，rc=2，同一错误。
  3. `python ../../../Tool/skill/protocol-plugin/scripts/proto-repro.py --input input/sample.bin --json`，rc=0；
     解析 3 帧，`stats={bytes:141, consumed:141, skipped:0, trailing:0, errors:[]}`，三帧 `crc_ok=true`。
  4. `... --rebuild --frame-index 2 --set type=4 --set seq=4 --payload-text '{"temp":22.0,"status":"ok"}' --out artifacts/new-frame.bin`，rc=0。
  5. `... proto-repro.py --input artifacts/new-frame.bin --json`，rc=0；新帧 43 B，`crc_ok=true`。
- 产物：
  - `parse.json`：3 帧的 offset/frame_len/字段/`checks[].want|got|covers`/payload JSON；
  - `rebuild.json`：基线 sha256、新帧 sha256、重算后的字段与 `verify`；
  - `new-frame.bin` + `new-frame-parse.json`：构造出的新帧及其复解析结果。
- 结论：`frame_len = 12 + length + 4`、`length` 只覆盖 payload、CRC32 覆盖 `header+payload`
  在 3/3 帧成立；`type=4/seq=4` 的新帧能被同一张字段表解析回且 CRC 自洽。
- 边界：仍是夹具，无真实 TCP pcap、无服务端接受性验证、未做半包/粘包/乱序重同步；
  原设计的 AES-CBC 段在本样本中不存在。
