# 05 二进制分帧 — magic / 长度 / TLV / 半包粘包

> 适用：私有二进制协议、定长头 + 变长体、TLV、带校验的自定义帧。
> 不适用：纯文本行协议（HTTP/SMTP）的分帧见 `04-walkthrough-websocket-replay.md` 与
> `07-crypto-and-checksum.md`；插件装载链 → `plugin-targets`（R25）。
> 字段表工具：`scripts/proto-repro.py`；字节流来源：`scripts/pcap-summary.py --extract`。

## 1. 分帧的四种基本形态

| 形态 | 判据 | 先验信号 | 失败表现 |
|---|---|---|---|
| 定界符 | `\r\n\r\n`、`\0`、`00 00 FF` 分隔 | 文本协议、行尾稳定 | 载荷里出现同字节即误切 |
| 长度前缀 | 头部有 u8/u16/u24/u32 且随载荷线性变化 | 每帧前 2–4 字节变化 | 含头/含尾/端序判错 → 全部错位 |
| 固定头 + 类型定长 | 同 type 帧长固定 | type 少、载荷定长（遥测/心跳） | 新 type 出现即崩，需 fallback |
| TLV 链 | tag+len+value 循环，结尾由总长决定 | 字段数可变、可选字段多 | len 是否含 tag/len 判错 |

工程上最稳的是**长度前缀 + magic**，因为它同时给了"从哪开始"和"到哪结束"。

## 2. 长度字段：必须回答的四个问题

1. **端序**：大端还是小端（同一协议不同字段可能不同）。
2. **覆盖范围**：只含 payload？含头？含自身？含尾部校验？
3. **对齐/填充**：4 字节对齐、块填充、加密补位算不算在长度里。
4. **上限与异常**：最大帧、0 长度、超长时服务端是等、拒还是截断。

拟合方法：取 3 条不同 payload 长度的帧，解线性关系

```text
len_field = a * payload_len + b
a=1,b=0      → 只含 payload
a=1,b=hlen   → 含头（不含尾）
a=1,b=hlen+t → 含整帧
a=1,b=hlen+t+pad → 含对齐填充
```

只有一条假设能让**全部**帧成立时才算定；否则继续收样本。

真实验证（仓库 `Tool/cases/protocol02/input/sample.bin`，3 帧 SPRX）：

```bash
python Tool/skill/protocol-plugin/scripts/proto-repro.py \
  --input Tool/cases/protocol02/input/sample.bin --json
```

```text
0 0  52 {'magic': 'SPRX', 'version': 1, 'type': 1, 'length': 36, 'seq': 1} True
1 52 46 {'magic': 'SPRX', 'version': 1, 'type': 2, 'length': 30, 'seq': 2} True
2 98 43 {'magic': 'SPRX', 'version': 1, 'type': 3, 'length': 27, 'seq': 3} True
```

三帧都满足 `frame_len = 12 + length + 4`（`52=12+36+4`、`46=12+30+4`、`43=12+27+4`），
`length` 只覆盖 payload，CRC 覆盖 `header+payload`。**这是确认档**（3 帧 + 两个不同长度 + CRC 负例）。

## 3. magic 与重同步

- magic 可能出现在 payload 里（JSON 文本、二进制里的 ASCII）。解析器必须能"发现错位 → 向后滑 → 重新对齐"。
- 自检要注入：前置垃圾字节、帧间垃圾字节、假 magic、截断帧。
- 统计 `skipped_bytes` 与 `trailing_bytes`：**丢弃的字节不是噪声，是要解释的证据**。

```python
# proto-repro.py 的重同步逻辑（节选）
if magic and blob[pos:pos+len(magic)] != magic:
    nxt = blob.find(magic, pos + 1)
    if nxt < 0:
        skipped += n - pos; break
    skipped += nxt - pos
    pos = nxt
    continue
```

判据：注入 9 字节垃圾后仍解出 3 帧，且 `skipped_bytes >= 9`（`proto-repro.py --self-test` 覆盖）。

## 4. 头部字段清单（按出现频率）

| 字段 | 宽度 | 观察点 | 陷阱 |
|---|---|---|---|
| magic | 2/4/8 | 是否每帧都有；握手帧是否裸流 | 版本升级后 magic 变体 |
| version | 1/2 | 协商前后是否变；高版本是否加字段 | 用版本号当 type |
| type/opcode | 1/2 | 请求/响应/心跳/错误分组统计 | 未知 type 被静默忽略 |
| flags | 1/2/4 | 按位展开：压缩/加密/分片/优先级 | 位序（bit0 是 LSB 还是 MSB） |
| length | 2/4 | 见 §2 | 含头/含尾/含自身 |
| seq/ack | 2/4/8 | 递增？随机？回显？回绕？ | 重放旧 seq 被防重放窗口拒 |
| session/cid | 2–8 | 握手分配；是否逐帧回显 | 并发会话互踢 |
| checksum | 2/4 | 见 `07-crypto-and-checksum.md` | 覆盖范围 |
| timestamp | 4/8 | 秒/毫秒/微秒；时区 | 服务端允许偏差（常见 ±300s） |

## 5. TLV

```text
tag(1) len(1) value(len) [tag(1) len(2) value(len)] ...
```

- 先确认 `len` 宽度（1/2/4）与是否含 `tag+len` 自身。
- 未知 tag **必须原样保留**：丢掉未知字段会导致重放缺字段、被服务端拒绝。
- 嵌套 TLV：外层 len 覆盖内层全部字节；解析时用"正好到帧尾"验证。
- 顺序敏感：有的协议要求 tag 升序，有的允许任意序；用两条不同顺序的帧对比响应。

## 6. 半包 / 粘包 / 乱序 / 重传

| 现象 | 根因 | 处理 |
|---|---|---|
| 一次 recv 只拿到半帧 | TCP 分段 | 缓冲到 `header_len` 再读 length，再缓冲到整帧 |
| 一次 recv 含 2 帧 | Nagle/合并发送 | 循环解析直到剩余不足一帧 |
| 帧顺序错乱 | 多线程发送 / 抓包乱序 | 用 seq 排序；抓包侧用 tshark 重组后的流 |
| 同帧重复出现 | TCP 重传 | 按 seq+len 去重；不要按"内容相同"去重（业务可能真重复） |
| 解析器偶发崩 | 长度字段被攻击/损坏 | 强制上限（如 1 MiB），超限即断开并记录 |

判据：把同一段字节流按 1/3/7/任意长度切片喂给解析器，输出帧序列必须完全一致。

## 7. 用字段表驱动（把格式外置）

`proto-repro.py` 的 schema 让"解析"和"构造"共用一张表，避免手写两套逻辑走偏：

```json
{
  "name": "sprx", "endian": "big",
  "header": [
    {"name": "magic", "offset": 0, "size": 4, "type": "bytes", "value": "SPRX"},
    {"name": "version", "offset": 4, "size": 1, "type": "u8"},
    {"name": "type", "offset": 5, "size": 1, "type": "u8"},
    {"name": "length", "offset": 6, "size": 2, "type": "u16", "role": "length", "covers": "payload"},
    {"name": "seq", "offset": 8, "size": 4, "type": "u32"}
  ],
  "header_len": 12,
  "payload": {"encoding": "json"},
  "tail": [{"name": "crc32", "size": 4, "type": "u32", "role": "checksum",
            "algo": "crc32", "covers": "header+payload"}]
}
```

```bash
# 从真实样本反推的表：先导出，再改
python Tool/skill/protocol-plugin/scripts/proto-repro.py --emit-schema artifacts/sprx.schema.json

# 用表解析任意字节流
python Tool/skill/protocol-plugin/scripts/proto-repro.py --schema artifacts/sprx.schema.json \
  --input artifacts/streams/s00_10.0.0.1_49152-10.0.0.2_9527.bin --json
```

字段表比"一篇散文"值钱：它是可执行的，改一个 `offset` 就能验证新假设。

## 8. 失败判据

- 3 帧以上无法让某一条长度假设**全部**成立 → 标"分帧未定"，不要写字段表。
- 改长度字段后服务端既不报错也不超时（一直等） → 说明你改的方向它不检查，换字段。
- 注入垃圾字节后解析器丢帧或崩 → 重同步没实现，先修解析器再谈协议。
- 长度上限没有 → 一个损坏帧就能 OOM，属于实现缺陷。

## 9. 边界

- 本节只处理**明文帧**。加密段的定位与取明文见 `07-crypto-and-checksum.md`。
- 协议状态推进（握手/认证/心跳）见 `06-app-state-machine.md`；构造新帧的验收见 `08-replay-and-new-request.md`。
- 所有样本编号必须能回指 `capture#frame` 或 `frames.jsonl`；没有出处的字段一律标"疑似"。
