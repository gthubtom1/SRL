# protocol-plugin 报告模板

> 复制到 `evidence/<case>/report.md`。状态机结论必须有边覆盖率与帧证据。

## 1 目标与授权
- 目标：<pcap/pcapng / 私有协议 / 端点 / 版本 / sha256>
- 授权：<抓包点 / 回放范围 / 是否允许新请求 / 速率 / 时间窗>
- 范围外：<生产注入 / 破坏性 fuzz / 断点清单由 scope 声明>
- 环境：<tshark 版本 / pcap-summary / 链路类型 / 时区>

## 2 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/pcap-summary.json | <sha256> | `python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file <pcap> --json` | 0 | 会话/片段/格式 |
| E02 | artifacts/rebuild.json | <sha256> | `python Tool/skill/protocol-plugin/scripts/proto-repro.py --input <frame> --rebuild ... --json` | 0 | 新帧/CRC |
| E03 | artifacts/accept.json | <sha256> | `python Tool/skill/protocol-plugin/scripts/proto-accept.py --json` | 0 | 案例验收 |

## 3 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| 抓包体检 | format/linktype/packet_count/first_ts 自洽 | <实测> | E01 | <结论> |
| 分帧 | frame_len = 2 + (mask?4:0) + payload_len，N/N 成立 | <实测> | E01 | <结论> |
| 字段/CRC | 字段表可解析，CRC 覆盖范围可复算 | <实测> | E02 | <结论> |
| 状态机 | observed_edges 有证据帧，edge_coverage ≥0.6 | <实测> | E01 | <结论> |
| 重放 | 新请求被服务端接受且响应可重复 3 次 | <实测> | E02 | <结论> |
| 加密/压缩 | TLS/deflate 处理方式明确，不把密文当明文 | <实测> | E01 | <结论> |

## 4 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| 只解析出 1 帧/半包、无粘包测试 | <yes/no> | E01 | 标 candidate，补重同步 |
| CRC/长度只由单样本反推 | <yes/no> | E02 | 不写协议已确认 |
| edge_coverage <0.6 | <yes/no> | E01 | 不声称状态机成立 |
| 新帧未连服务端/仅结构自洽 | <yes/no> | E02 | 只写 structural，不写 replay |
| 密文被当明文/压缩未 inflate | <yes/no> | E01 | 修正解析链后重跑 |
| 抓包点跨 NAT/截断 | <yes/no> | E01 | 记录链路边界，不归因业务 |

## 5 影响与边界
- 影响：<可读字段 / 可构造消息 / 可达状态>
- 边界：<回环/明文/无鉴权；未测 TLS/mTLS/压缩>
- 误报风险：<loopback 抓包、工具重组差异、时间戳非业务时间>
- 未覆盖：<未观察的 opcode/ping/close/分片>

## 6 修复建议（厂商视角）
1. 严格校验长度/类型/CRC，设置最大帧长与分片上限，拒绝歧义帧。
2. 状态机对非法转移返回错误并断开；握手加入随机数、认证与防重放。
3. 启用 TLS/证书校验；压缩前先限长，避免 zip bomb/deflate 放大。
4. 日志记录握手、帧类型、错误码与关联 ID，便于取证复跑。

## 7 复跑命令
```bash
python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file evidence/<case>/artifacts/capture.pcapng --json --extract evidence/<case>/artifacts/streams
python Tool/skill/protocol-plugin/scripts/proto-repro.py --input evidence/<case>/artifacts/sample.bin --json
python Tool/skill/protocol-plugin/scripts/proto-accept.py --json
```
