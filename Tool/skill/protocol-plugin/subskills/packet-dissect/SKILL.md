---
name: packet-dissect
description: "PCAP 单向流重组、私有长度与校验推断、Wireshark Lua 有界解析；覆盖分段粘包、重传、截断与长度上限。"
metadata:
  version: "2.1.0"
  target_runtimes: "PCAP / TCP / UDP / Wireshark Lua；以实际 tshark 版本为准"
---

# 私有协议分帧与 Lua 解析

输入需有抓包来源、时间、方向、连接身份及业务操作对照。复用 [二进制分帧](../../references/05-binary-framing.md)、[校验与加密](../../references/07-crypto-and-checksum.md)、[状态机](../../references/06-app-state-machine.md)。协议/字段分析可独立完成；只有用户要求构造或复刻时才加 [新请求验证](../../references/08-replay-and-new-request.md)。

## 重组在分帧之前

按连接、方向和 TCP 字节序号处理乱序、部分重传、重叠冲突、缺口和端口复用。`tcp.stream` 是抓包内连接索引，不能跨抓包当稳定 ID。`pcap-summary.py --extract` 的按包拼接不是完整 TCP 重组。可用当前 `proto-repro.py --pcap ... --stream ... --direction ...` 的严格路线，但须满足其起始 SYN、对端 SYN/ACK、所选方向 FIN 等完整性要求；失败保留诊断，不能补字节凑流。

UDP 保留 datagram 边界；IP 分片先重组，应用层分片另核序号和超时，不能按 TCP 模板合并。TLS/压缩/HTTP2/WebSocket 先完成对应分层；没有安全明文时只分析可见层，不输出真实会话秘密。

## 长度必须有明确公式

下例仅为合成协议，绝非通用头：magic=0x5345、u32 大端总长、u16 命令、u32 序号、变长载荷、u16 尾校验。头长 12、尾长 2、总长最小 14；`payload_len = total_len - 14`。尾部校验算法与覆盖范围需独立确认，模板仅显示其原值，不宣称 CRC。

多种长度的正样本与未见输入验证端序、含头/含尾/含自身、padding、最大值。校验需写算法、初值/反射/多项式/末异或、覆盖区间；CRC 不是 MAC。单条消息算对不能唯一确认算法。

## 合成 TCP Lua 模板

保存为工作区 `work/myproto.lua`。显式端口绑定，仅用于夹具 8888；不使用启发式全网注册。Wireshark 的 TCP 重组设置必须启用。

```lua
local p = Proto("myproto", "Synthetic framed protocol")
local f_magic = ProtoField.uint16("myproto.magic", "Magic", base.HEX)
local f_length = ProtoField.uint32("myproto.length", "Total length", base.DEC)
local f_cmd = ProtoField.uint16("myproto.cmd", "Command", base.HEX)
local f_seq = ProtoField.uint32("myproto.seq", "Sequence", base.DEC)
local f_payload = ProtoField.bytes("myproto.payload", "Payload")
local f_check = ProtoField.uint16("myproto.check", "Unverified checksum", base.HEX)
p.fields = {f_magic, f_length, f_cmd, f_seq, f_payload, f_check}
local HEADER, MIN, MAX = 12, 14, 1024 * 1024

function p.dissector(tvb, pinfo, tree)
    local pos = 0
    while pos < tvb:len() do
        local remaining = tvb:len() - pos
        if tvb:reported_len() > tvb:len() then
            tree:add(p, tvb(), "Capture truncated; cannot establish completeness")
            return
        end
        if remaining < HEADER then
            pinfo.desegment_offset = pos
            pinfo.desegment_len = HEADER - remaining
            return
        end
        if tvb(pos, 2):uint() ~= 0x5345 then
            tree:add(p, tvb(pos, remaining), "Bad magic; framing unresolved")
            return
        end
        local total = tvb(pos + 2, 4):uint()
        if total < MIN or total > MAX then
            tree:add(p, tvb(pos, HEADER), "Invalid total length")
            return
        end
        if remaining < total then
            pinfo.desegment_offset = pos
            pinfo.desegment_len = total - remaining
            return
        end
        pinfo.cols.protocol = "MyProto"
        local node = tree:add(p, tvb(pos, total))
        node:add(f_magic, tvb(pos, 2))
        node:add(f_length, tvb(pos + 2, 4))
        node:add(f_cmd, tvb(pos + 6, 2))
        node:add(f_seq, tvb(pos + 8, 4))
        if total > MIN then node:add(f_payload, tvb(pos + HEADER, total - MIN)) end
        node:add(f_check, tvb(pos + total - 2, 2))
        pos = pos + total
    end
end
DissectorTable.get("tcp.port"):add(8888, p)
```

魔数错时模板报告并停止，不盲目滑窗重同步；真实协议若需恢复同步，须增加有证据的规则与负例。重组依赖 Wireshark TCP 层，模板不能修复抓包缺失或重叠冲突。

```bash
tshark -r work/fixture.pcapng -X lua_script:work/myproto.lua -Y myproto -T fields -e tcp.stream -e myproto.length -e myproto.cmd
```

核对本机 `tshark -v` 与 Lua 支持、stderr、字段值和预期帧数；加载无错误本身不证明分帧正确。

## 正反例与交付

必须覆盖完整单帧、一次含两帧、头跨段、体跨段、重传、乱序、空载荷、尾校验错、长度<14/超过上限、snaplen 截断和真实缺段。正例的重组后字段序列与基线一致；反例明确 invalid/incomplete/checksum-unverified，不能越界读取或静默当成功。模板不是已在当前环境实测的解析器。

交付流重组方法、字段表/置信度、长度公式、校验范围、工具版本和正反样本哈希。native 语义可请 softseep，判恶交 malware-analysis；交接带流编号、方向、帧与偏移、已证/未知及具体问题，产物归同一 project/version/run。两次同形失败先重判边界。
