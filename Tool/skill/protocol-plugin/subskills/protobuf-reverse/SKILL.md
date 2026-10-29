---
name: protobuf-reverse
description: "Protobuf 字段候选推断与 gRPC 消息分层；保留 wire 类型歧义，结合客户端和新样本验证候选 schema。"
metadata:
  version: "2.1.0"
  target_runtimes: "Protobuf / HTTP2 gRPC；gRPC-Web 另行分层"
---

# Protobuf 与 gRPC 候选结构恢复

输入是已知来源的消息字节、抓包或客户端解析线索。先读 [分帧](../../references/05-binary-framing.md)、[状态机](../../references/06-app-state-machine.md) 和 [Android Protobuf 深度方法](../../../apkseep/references/protocol-reverse.md)。主域由用户目标决定，可由 apkseep 提供解析代码、softseep 提供 native 调用点；辅域结果须绑定同一构建，返回同一 project/version/run。

## Wire 事实与候选语义分开

key varint 的低 3 位是 wire type，其余为字段号。字段号必须有效，varint、长度和嵌套都设边界。wire 0 可为 int/uint/sint/bool/enum（sint 用 ZigZag）；wire 1 可为 fixed64/sfixed64/double，wire 5 类似 32 位；wire 2 可为 UTF-8 string、bytes、嵌套 message 或 packed repeated。旧 group 使用 wire 3/4，应显式支持或拒绝，不能当未知字节跳过。

无 schema 解码只能给候选：业务名、signedness、enum、oneof、map、presence 与重复性不能从单条消息唯一恢复。文本能按 UTF-8 解码也不能证明字段是 string。先从源码根用现有候选解码器：

```bash
python Tool/skill/apkseep/scripts/protobuf_decode_raw.py work/payload.bin --json > work/tree.json
protoc --decode_raw < work/payload.bin
```

`protoc` 需先核版本和可用性，重定向示例适用于兼容 shell。两者输出都不是原始 `.proto`。本地解码器的 `--split varint-length` 只用于确有 varint 长度前缀的流，不适用于 gRPC 五字节头。

合成字节 `0a 05 61 6c 69 63 65 10 7b 1a 07 0a 05 61 64 6d 69 6e` 可支持下列可编译候选，但不能证明业务命名或原始类型：

```protobuf
syntax = "proto3";
message UserCandidate {
  string name_candidate = 1;
  uint64 id_candidate = 2;
  RoleCandidate role_candidate = 3;
}
message RoleCandidate { string label_candidate = 1; }
```

```bash
protoc --proto_path=work --descriptor_set_out=work/candidate.pb work/candidate.proto
```

多条受控业务输入、客户端 serializer/deserializer、descriptor/reflection（若已有且可用）用于排除候选；每个字段列观察事实、候选类型、支持/反证与置信度。

## gRPC 先重组再解码

对经典 HTTP/2 gRPC，先 TCP 重组，再按 HTTP/2 stream 与方向重组 DATA 字节，不能把每个 DATA frame 当一条消息。HEADERS/CONTINUATION、DATA padding 与 trailers 由对应 HTTP/2 工具解析。检查 content-type、grpc-status 与消息边界，HTTP 200 不证明 RPC 成功。

每条消息头为 1 字节 compressed-flag（0/1）加 4 字节大端长度，长度覆盖随后线上消息字节。半头、半体先缓存，一次可能含多条；设线上长度、解压后长度与递归上限。flag=1 表示按该 stream 的 `grpc-encoding` 解压，不等于 gzip；缺编码、未知算法或失败不能继续当 Protobuf。flag=0 的消息不解压，即使 stream 声明了编码。gRPC-Web 的文本 base64 和 trailer 帧另有语义，不套经典消息头规则。

TLS 无安全明文材料时只交元数据；真实会话密钥/Token 不进入 Agent，不能以解密需求扩大采集。

## 正反例与验收

正例：候选 `.proto` 编译通过，多个未见输入中字段语义与客户端/业务预期一致；未知字段、可选缺失、重复值和边界均有测试。反例：同一 wire 2 数据可同时是 bytes 与嵌套消息，保留歧义；flag=1 但没有 grpc-encoding，报告解压受阻。

编解码比较字段语义、未知字段保留策略及目标互操作。Protobuf 序列化字段顺序、packed 表示及实现策略可变，不能普遍要求重编码哈希相同；逐字节一致只验证特定样本和编码策略。错误长度、超长 varint、截断和错 wire 应结构化失败。同形失败两次重判分层；编译或解析成功不等于完整恢复原始 schema。
