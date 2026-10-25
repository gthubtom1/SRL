# protocol-plugin 报告模板

> **客户视角五段（必须全在，缺一不算交付）**：下面五个是**真标题**——`python Tool/scripts/case_state.py report --check --file <本文件>`
> 按标题文字精确匹配「结论 / 已确认 / 仍未知 / 下一步 / 复查」，缺一段即 `[FAIL]`；每段标题下至少 2 行正文，
> 「结论」不超过 3 行，「已确认」里至少要有一个 `E-` / `C-` / `F-` 编号。「下一步 / 复查」别改名，改了检查器就找不到。

> 复制到 `work/<case>/report.md`。状态机结论必须有边覆盖率与帧证据。

## 1 结论（≤3 行：能不能用 / 到哪一步 / 卡在哪）
- 到哪一步：<只能看懂结构 | 能改到能用 | 能完全自己接管 | 现在做不了>
- 卡在哪：<卡点一句话 + 证据编号；没有卡点写「无」>
- 能不能用：<只按已有证据说一句；没跑过就写「未验证」>

## 2 已确认（每条：客户能听懂的一句话 + 证据 ID + 强度：强 / 中 / 弱）
- <客户能听懂的那句话>（`E-001`；强：同输入同输出可复现，命令与输出都能贴）—— 原始记录 `artifacts/<tool>-<时间>.json`
- <客户能听懂的那句话>（`E-002`；强：两路独立验证一致，不只是重复跑）—— 原始记录 `artifacts/<tool>-<时间>.json`
- 只有一次观测、没有可复跑命令的线索不进本段，写进第 3 段。

## 3 仍未知（每条：未知什么 + 为什么未知 + 缺什么才能知道）
- <未知什么>｜为什么未知：<环境限制 / 证据缺口 / 授权没给>｜还缺：<补什么才能知道>
- <未知什么>｜为什么未知：<同上>｜还缺：<同上>

## 4 下一步（省事路线 / 彻底路线 / 不建议做的事，各一条）
- 省事路线：<最小动作 + 拿到什么 + 大概要花多少功夫（区间 + 判断依据）>
- 彻底路线：<要补的证据或要动的位点 + 代价与工期>
- 不建议做：<哪条路会白费或越界，为什么>

## 5 怎么复查（复查单路径 + 关键重放命令 + 期望看到什么）
- 复查单：`python Tool/scripts/case_state.py recheck --case work/<case>` → 生成 `work/<case>/recheck.md`（目标哈希 / 环境 / 重放命令）
- 重放：<本域脚本命令；Windows 的 cmd 与 PowerShell 都能直接粘贴，见文末复跑命令>
- 期望：<关键字段或输出片段>；对不上先查「已知会变」（在线服务 / 证书 / IP / 时钟）

## 6 目标与授权
- 目标：<pcap/pcapng / 私有协议 / 端点 / 版本 / sha256>
- 授权：<抓包点 / 回放范围 / 是否允许新请求 / 速率 / 时间窗>
- 范围外：<生产注入 / 破坏性 fuzz / 断点清单由 scope 声明>
- 环境：<tshark 版本 / pcap-summary / 链路类型 / 时区>

## 7 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/pcap-summary.json | <sha256> | `python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file <pcap> --json` | 0 | 会话/片段/格式 |
| E02 | artifacts/rebuild.json | <sha256> | `python Tool/skill/protocol-plugin/scripts/proto-repro.py --input <frame> --rebuild ... --json` | 0 | 新帧/CRC |
| E03 | artifacts/accept.json | <sha256> | `python Tool/skill/protocol-plugin/scripts/proto-accept.py --json` | 0 | 案例验收 |

## 8 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| 抓包体检 | format/linktype/packet_count/first_ts 自洽 | <实测> | E01 | <结论> |
| 分帧 | frame_len = 2 + (mask?4:0) + payload_len，N/N 成立 | <实测> | E01 | <结论> |
| 字段/CRC | 字段表可解析，CRC 覆盖范围可复算 | <实测> | E02 | <结论> |
| 状态机 | observed_edges 有证据帧，edge_coverage ≥0.6 | <实测> | E01 | <结论> |
| 重放 | 新请求被服务端接受且响应可重复 3 次 | <实测> | E02 | <结论> |
| 加密/压缩 | TLS/deflate 处理方式明确，不把密文当明文 | <实测> | E01 | <结论> |

## 9 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| 只解析出 1 帧/半包、无粘包测试 | <yes/no> | E01 | 标 candidate，补重同步 |
| CRC/长度只由单样本反推 | <yes/no> | E02 | 不写协议已确认 |
| edge_coverage <0.6 | <yes/no> | E01 | 不声称状态机成立 |
| 新帧未连服务端/仅结构自洽 | <yes/no> | E02 | 只写 structural，不写 replay |
| 密文被当明文/压缩未 inflate | <yes/no> | E01 | 修正解析链后重跑 |
| 抓包点跨 NAT/截断 | <yes/no> | E01 | 记录链路边界，不归因业务 |

## 10 影响与边界
- 影响：<可读字段 / 可构造消息 / 可达状态>
- 边界：<回环/明文/无鉴权；未测 TLS/mTLS/压缩>
- 误报风险：<loopback 抓包、工具重组差异、时间戳非业务时间>
- 未覆盖：<未观察的 opcode/ping/close/分片>

## 11 修复建议（厂商视角）
1. 严格校验长度/类型/CRC，设置最大帧长与分片上限，拒绝歧义帧。
2. 状态机对非法转移返回错误并断开；握手加入随机数、认证与防重放。
3. 启用 TLS/证书校验；压缩前先限长，避免 zip bomb/deflate 放大。
4. 日志记录握手、帧类型、错误码与关联 ID，便于取证复跑。

## 12 复跑命令
```bash
python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file work/<case>/artifacts/capture.pcapng --json --extract work/<case>/artifacts/streams
python Tool/skill/protocol-plugin/scripts/proto-repro.py --input work/<case>/artifacts/sample.bin --json
python Tool/skill/protocol-plugin/scripts/proto-accept.py --json
```
