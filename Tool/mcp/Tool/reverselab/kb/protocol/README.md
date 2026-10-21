# Protocol 知识库 — 协议复刻（R24）

> 私有 / 二进制 / 应用层协议的可复用卡片。技能入口：`Tool/skill/protocol-plugin/SKILL.md`。
> 边界：插件 / 浏览器扩展 / Electron asar / 游戏 Mod → `plugin-targets`（R25）；
> 本 board 只处理协议字节、分帧、状态机、重放与构造。

## 何时来这里

- 手上有一个 `.pcap/.pcapng`，要回答"这是什么协议、字段是什么、能不能构造新请求"；
- 有二进制帧（magic/length/CRC），要写解析器并重同步；
- 有 WebSocket/HTTP2/长连接，要按消息而不是按 TCP 段分析；
- 要判断"能重放但改不了"到底卡在签名、nonce 还是风控。

不适用：只做 TLS 握手证书分析（→ 安全运维/取证）、只做算法还原（→ `ida-reverse`）、
只做插件装载链（→ `plugin-targets`）。

## 分析链（顺序不要跳）

```text
抓包/取流 → 分帧 → 字段与校验 → 状态机 → 原样重放 → 单变量构造 → 状态闭链
     ↑                                                              │
     └──────────────── 失败就回上一格，不跳级（见 02-failure-criteria）┘
```

1. **取流**：先 `pcap-summary.py` 看会话与方向性字节流，再上 tshark 交叉验证。
2. **分帧**：magic/长度/定界符/TLV，≥3 帧验证，注入垃圾字节测重同步。
3. **字段与校验**：长度覆盖范围 + 校验覆盖范围 + 算法参数，各配一个负例。
4. **状态机**：握手/认证/业务/心跳/关闭，没样本的边标 `INFERRED`。
5. **重放与构造**：T1 原样 → T2 单变量 → T3 状态闭链，每步都要预测并比对。

## 三条硬判据（本 board 只认这三条）

| 硬判据 | 机检方式 | 不满足时 |
|---|---|---|
| 分帧自洽 | `proto-repro.py` 的 `stats.errors==[]`、`consumed+trailing==bytes` | 标"分帧未定"，不写字段表 |
| 校验可复算 | 每帧 `crc_ok=true` + 改 1 字节负例 | 标"疑似校验"，继续收样本 |
| 能构造新帧 | `--rebuild` 后同表解析回 `crc_ok=true`；有服务端则响应符合预测 | 只能报"部分复刻" |

## 失败判据（看到即降级）

- 连续 2 次抓不到应用层字节，且排除网卡/代理/keylog → 转进程内明文或静态反推。
- 3 帧以上定不下长度/校验覆盖范围，单变量改动全无响应 → 停，写"分帧未定"。
- 能重放不能构造 → 卡点写签名/nonce/风控/mTLS，不粉饰。
- 服务端风控/封禁/验证码 → 立即停，不换账号/IP 绕过。
- 需要他人凭据/证书 → 不做。

逐条展开见 [失败判据表](techniques/failure-criteria.md)。

## 逐篇索引

| 篇目 | 一句话 | 什么时候读 |
|---|---|---|
| [framing-and-fields.md](techniques/framing-and-fields.md) | magic/长度/CRC/熵/分帧状态机 | 拿到裸字节，先定边界 |
| [checksum-and-crypto-segment.md](techniques/checksum-and-crypto-segment.md) | 校验覆盖范围、压缩/编码/加密的区分 | "熵很高，是不是 AES？" |
| [capture-to-replay.md](techniques/capture-to-replay.md) | 会话重组、状态机台账、单变量重放 | 要写 replay 脚本 |
| [websocket-and-http2-framing.md](techniques/websocket-and-http2-framing.md) | WS 帧头/掩码/控制帧、h2 streamid/HPACK | 长连接、多路复用 |
| [live-capture-hygiene.md](techniques/live-capture-hygiene.md) | BPF 收敛、回环抓包、脱敏、抓包点选择 | 要"现场抓一次" |
| [real-pcap-drills.md](techniques/real-pcap-drills.md) | 用仓库自带真实 pcap 做的 5 个练习 | 练手/复现判据 |
| [failure-criteria.md](techniques/failure-criteria.md) | 失败判据表 + 改走哪条 + 代价 | 卡住时先看这里 |

## 10 分钟初筛（复制即用）

```bash
# 1) 会话 + 方向性字节流 + 明文片段（无需 tshark）
python Tool/skill/protocol-plugin/scripts/pcap-summary.py \
  --file capture.pcapng --json --extract artifacts/streams --tshark-check

# 2) 有 tshark 时的交叉验证
tshark -r capture.pcapng -q -z conv,tcp
tshark -r capture.pcapng -Y "tcp.len>0" -T fields \
  -e frame.number -e tcp.stream -e ip.src -e tcp.srcport -e tcp.dstport -e tcp.payload

# 3) 按字段表分帧 + 校验复算（内置 SPRX 表；其他协议用 --schema）
python Tool/skill/protocol-plugin/scripts/proto-repro.py \
  --input artifacts/streams/s00_*.bin --json

# 4) 本域案例判据复算（sha256 / 字段 / lessons 里的 rc）
python Tool/skill/protocol-plugin/scripts/proto-accept.py --json
```

## 邻域边界

| 目标 | 去哪 |
|---|---|
| 插件入口、manifest 权限、asar/VSIX/JAR/Mod 加载链 | `plugin-targets`（R25） |
| 前端 JS 签名、补环境、浏览器调试 | `mcp-js-reverse-playbook` |
| PE/ELF 壳、反调试、算法还原 | `unpack-loop` / `softseep` / `ida-reverse` |
| 固件里的私有协议（提取/仿真） | `firmware-iot`（拿到字节后回本 board） |
| 恶意样本的 C2 协议家族判定 | `malware-analysis`（本 board 只做字节与状态） |

## 维护约定

- 每篇 technique 必须能被 `Tool/skill/protocol-plugin/SKILL.md` 或本 README 链接到（无孤儿）。
- 命令示例只用相对仓库根的路径；不写本机绝对路径。
- 新增判据先改 `references/01-criteria.md`，再回填本 board，避免两套事实。
