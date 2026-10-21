# sample.bin 帧格式（本地构造样本）

本文件是手工构造的二进制协议样例，不是抓包。共 3 帧，按顺序拼接，无分隔符。

## 帧结构（大端）

| 偏移 | 长度 | 字段 | 说明 |
| --- | --- | --- | --- |
| 0 | 4 | magic | ASCII `SPRX`（0x53 0x50 0x52 0x58） |
| 4 | 1 | version | 固定 0x01 |
| 5 | 1 | type | 0x01=HELLO，0x02=AUTH，0x03=TELEMETRY |
| 6 | 2 | length | payload 长度，**只覆盖 payload**，不含头尾 |
| 8 | 4 | seq | 帧序号，从 1 递增 |
| 12 | length | payload | UTF-8 JSON 明文 |
| 12+length | 4 | crc32 | CRC-32/ISO-HDLC，覆盖 **header(12B)+payload**，不含本字段 |

帧总长 = 12 + length + 4。解析器应先读 12 字节头，校验 magic/version，再读 length 字节 payload 与 4 字节 CRC。

## 实测帧表（由构造脚本计算）

| 帧 | 起始偏移 | type | seq | payload len | frame len | CRC32 | payload |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 0 | 0x01 | 1 | 36 | 52 | 0xe59f1d6e | `{"sensor":"lab-01","proto":"sprx/1"}` |
| 2 | 52 | 0x02 | 2 | 30 | 46 | 0xb0542e66 | `{"token":"abc","nonce":"7f3a"}` |
| 3 | 98 | 0x03 | 3 | 27 | 43 | 0x0280ee21 | `{"temp":21.5,"status":"ok"}` |

## 已验证 / 未验证

- 已验证：3 帧 magic、version、length、seq 均可按上表定位；CRC32 覆盖范围按 header+payload 计算可复现（见帧表）。
- 未验证：长度覆盖范围只用本样本 3 帧反推，未做半包/粘包/重传/乱序重同步测试。
- 未验证：原设计假设的 AES-CBC 加密段在本样本中不存在，payload 为明文 JSON；真实流量是否加密仍未知。
- 未验证：没有真实 TCP pcap，端口 127.0.0.1:9527 仅为设计值。

## 复现

```
python Tool/scripts/pcap-summary.py --file input/sample.bin --json   # 预期 rc=2，非 pcap
```
