# protocol03 输入来源

- 文件：`websocket.pcapng`
- 抓包工具链（读取 pcapng 接口描述块可复现）：dumpcap 4.1.0 / Linux 5.15 / 回环接口 / `Go-http-client`
- 用途：WebSocket 握手 + 8 帧（客户端 4 帧 mask=1、服务端 4 帧 mask=0）的分帧与字段重建练习
- 声明：本案例**未**连服务端做重放验证（`outcome=partial`）；早期文档误写「Wireshark 官方 test/captures」，
  已按抓包元数据更正为实际来源。
