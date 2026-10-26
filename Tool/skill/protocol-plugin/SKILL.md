---
name: protocol-plugin
description: "逆向这个协议/这个封包怎么构造/私有协议/私有加密/重放请求/写个插件或 Mod/模拟客户端登录。要求同输入同输出、能构造服务端接受的新请求、状态机可闭环。 (.pcap/.pcapng/.proto/封包/二进制报文)"
license: MIT
compatibility: Windows 10/11、Linux、macOS；依赖可选的 tshark / mitmproxy / scapy；缺失时用标准库 pcap 解析与原始 socket 重放降级。
metadata:
  version: "2.0.0"
  category: protocol-plugin
  routes: "R24"
  references: "references/01-criteria.md, references/02-failure-criteria.md, references/03-model-pitfalls.md, references/04-walkthrough-websocket-replay.md, references/05-binary-framing.md, references/06-app-state-machine.md, references/07-crypto-and-checksum.md, references/08-replay-and-new-request.md"
---

# protocol-plugin — 私有 / 二进制协议复刻（R24）

> 只回答一件事：**这个协议能不能被复刻到"同输入同输出，且能构造新请求"？**
> 先取证再推断；每个结论必须能回放到某条包、某个字段、某次运行。**不猜密钥，不猜字段，不猜状态。**

## 阶段契约（与 softseep 一致，**先判再做**）
> **域契约**（判型→裁定+M1–M4→按上限执行→停手问）：见 `Tool/skill/seep-router/SKILL.md`（唯一口径：判型→选域→上限 M1–M4→必问三件）。本文件不复制。
  **停下来给 A/B/C 卡**，写明：几步、我在监控什么、我保证不动什么、我拿到什么。
- 空目录/首次开工由 **Agent 自己** `case_state.py init`，不要求用户敲命令。

## 0. 范围与路由（边界）

**本域输入面**

- 有 `.pcap/.pcapng`，要还原帧格式、字段语义、状态机；
- 有裸二进制帧（magic/length/CRC/TLV），要写解析器并重同步；
- 有 WebSocket / HTTP2 / 长连接 / 自定义 TCP-UDP，要按消息而不是按 TCP 段分析；
- 要判断"能重放但改不了"卡在签名、nonce、风控还是 mTLS。

**相邻域与路由（由谁承担）**

| 目标 | 由谁承担 |
|---|---|
| 插件 / 浏览器扩展 / IDE 插件 / Electron asar / 游戏 Mod 的包型、入口、权限面、加载链 | **`plugin-targets`（R25）** |
| 网页前端 JS 签名、补环境、浏览器调试 | `mcp-js-reverse-playbook` |
| 纯 PE/ELF 壳、反调试、算法还原 | `unpack-loop` / `softseep` / `ida-reverse` |
| 固件提取与仿真（拿到字节后再回来） | `firmware-iot` |
| 恶意样本家族判定与 C2 归因 | `malware-analysis` |

> **插件类目标转 plugin-targets（R25）**：本域只接收插件里的**协议字节**，不重复其包型/入口/
> 权限面方法。需要同时碰两者时，先由 plugin-targets 定位插件入口与载荷，再把协议部分交回本域。

## 上限怎么说（对客户）

- **只能看懂结构**：`给你一张报文结构图：分帧/长度/校验/状态机里能定下几条就写几条，靠推断的那几条会标出来`
- **能改到能用**：`不依赖原帧也能造出新的业务请求，服务端接受，同一请求重复三次响应都符合预测`
- **能完全自己接管**：`状态机每条边都有样本、非法迁移有服务端实际拒绝的证据，能给你一个可离线复跑的解析器/客户端`
- **卡点通常是**：`能原样重放、一改字段就被拒——签名覆盖范围/nonce/mTLS 在服务端，拿不到一组明文对`

> 依据：本文件 §2 判据表（分帧/校验/状态机/构造新请求）+ §3 失败判据（字段改动即被拒、熵>7.5 解不出压缩）

## 1. 前置检查（3 件）

1. **授权与范围**：目标端点、账号、允许的动作（只读/重放/构造）、速率上限。
2. **观测能力**：抓包点（网卡/回环/代理/容器 veth）、是否 TLS、能否设 `SSLKEYLOGFILE`。
3. **工具**：`tshark -v`、`python --version`；缺 tshark 时确认 `pcap-summary.py --self-test` 可跑（纯标准库）。

```bash
tshark -v | head -1
python Tool/skill/protocol-plugin/scripts/pcap-summary.py --self-test
python Tool/skill/protocol-plugin/scripts/proto-repro.py --self-test
python Tool/skill/protocol-plugin/scripts/proto-accept.py --self-test
```

三条纪律：**抓包先于推断**、**重放先于重写**、**两次失败即换观测层**。

## 2. 判据表（本域 6 类，每类给确认/疑似）

> 完整版（含证据形态与误报风险）见 `references/01-criteria.md`。

| 类别 | 确认（可机检） | 疑似（未闭环） |
|---|---|---|
| 分帧 | `stats.errors==[]`、`consumed+trailing==bytes`、≥3 帧首尾相接 | 只有 1–2 帧样本；注入垃圾后丢帧 |
| 长度字段 | 3 条不同长度帧解出唯一 `len=a*payload+b`，能预测未见帧 | 含头/含尾/含自身三种假设都成立 |
| 校验 | 每帧 `crc_ok=true` + 改 1 字节负例 + 覆盖范围唯一 | 只对上一帧；算法靠"像" |
| 状态机 | 每条边有样本；非法迁移有实际拒绝证据 | 关键边标 `INFERRED`；无负例 |
| 同输入同输出 | 同请求 3 次响应结构/关键字段一致，可变项逐项解释 | 只跑过 1 次 |
| 构造新请求 | 不依赖原帧生成新业务请求，响应符合预测，重复 3 次 | 只能原样重放；改字段即拒 |

**判据落地命令**：`proto-repro.py` 的 `frames[].crc_ok` + `stats` + `rebuild.verify`；
`proto-accept.py` 的案例 sha256/字段/`lessons` 里的 `rc=`。

## 3. 失败判据（看到即降级）

> 完整表（现象 / 判定 / 改走哪条 / 代价）见 `references/02-failure-criteria.md`。

| 现象 | 判定 | 改走 |
|---|---|---|
| 连续 2 次抓包无应用层字节，已排除网卡/代理/keylog | 网络层看不到 | 进程内取明文 → 静态反推 |
| 3 帧以上定不下长度/校验覆盖，单变量改动全无响应 | 分帧未定 | 换样本/换观测层，不写字段表 |
| 能原样重放，任何字段改动即被拒 | 签名/nonce/风控 | 定位签名覆盖范围；不行只报"部分复刻" |
| 服务端 429/验证码/封禁 | 触发风控 | **立即停**，留证，不换账号/IP |
| 熵 > 7.5 但解不出压缩、拿不到明文对 | 加密段未解 | 停猜算法，转 keylog/进程内 |
| 需要他人证书/密钥/账号 | 越界 | 停并交授权流程 |
| 换会话 id 读到他人数据 | **越权红线** | 立即停并按授权流程上报 |

降档口径：只有 1–2 帧样本或单次现象 → 一律写"疑似"，不写"确认"。

## 4. 模型常见失误（≥8 条，详见 `references/03-model-pitfalls.md`）

1. **按 pcap 包边界切消息** → 消息跨段时解出半截 JSON；必须先在方向性字节流上分帧。
2. **用五元组合并会话** → 端口复用导致 seq 跳变；必须按 `tcp.stream` 分会话。
3. **单帧凑出长度公式就写字段表** → 含头/含尾无法区分；必须 3 帧 + 改长度负例。
4. **样本 CRC 对上就宣布 CRC32** → 3 帧下简单和/异或也可能巧合；必须 ≥5 帧 + 改字节负例 + 覆盖范围。
5. **"像 AES" 当结论** → 压缩/base64 熵同样高；必须有明文对或客户端内明文。
6. **把 protobuf 字段号当业务 id** → 字段号是 schema 槽位；语义要靠相关性推断。
7. **只重放不构造** → 只证明链路通；判据要求能生成新请求。
8. **一次改多个字段** → 失败无法归因；单变量 + 保留基线。
9. **把"没观测到"当"协议拒绝"** → 状态图必须区分 observed / INFERRED。
10. **忽略心跳/超时/重连** → 重放被踢后误判"协议不可复刻"。
11. **把 tshark 解析结果当事实** → dissector 是启发式；结论必须回原始字节。
12. **抓包/重放污染基线** → 代理改写后的流量不能当原始基线。
13. **报告贴真实 token/内网地址** → 证据卫生事故；脱敏为 `<redacted:sha256:…>`。

## 5. 流程（每阶段有完成判据）

### 阶段 A：取证与分诊

```bash
# A1 会话 + 方向性字节流 + 明文片段（无需 tshark）
python Tool/skill/protocol-plugin/scripts/pcap-summary.py \
  --file capture.pcapng --json --extract artifacts/streams --tshark-check

# A2 协议分层与主协议
tshark -r capture.pcapng -q -z io,phs
tshark -r capture.pcapng -q -z conv,tcp
```

**完成判据**：能写出"主协议层 / 会话数 / 每方向字节数 / 是否 TLS / 抓包点"；
`conv,tcp` 帧数之和等于 `io,phs` 的 frame 数；`--extract` 产出 `s*.bin` + `frames.jsonl`。

### 阶段 B：分帧与字段

```bash
# B1 用内置 SPRX 字段表解析；其他协议先 --emit-schema 改表
python Tool/skill/protocol-plugin/scripts/proto-repro.py --input artifacts/streams/s00_*.bin --json
```

判定顺序：定界符 → 长度前缀 → 固定头+type 定长 → TLV。每层 ≥3 帧验证，
长度公式用 `len = a*payload + b` 解，校验先定覆盖范围再定算法。

**完成判据**：`stats.errors` 为空、`consumed + trailing == bytes`、每帧 `crc_ok=true`；
注入 9 字节垃圾后仍能重同步（`--self-test` 覆盖此场景）。

详见 `references/05-binary-framing.md`、`references/07-crypto-and-checksum.md`。

### 阶段 C：状态机

把每条消息标成 `state_before → event → state_after`，覆盖握手/认证/业务/心跳/关闭。
无样本的边标 `INFERRED`；对 7 类非法迁移各做一次负例（跳步、错版本、重放 nonce、
错 seq、错 CRC、越权 id、超长 payload）。

**完成判据**：给定新消息序列能预测下一合法状态；非法迁移有实际拒绝证据。

详见 `references/06-app-state-machine.md`。

### 阶段 D：重放与构造（T1 → T2 → T3）

```bash
# T2 单变量构造：长度与校验由构造器重算
python Tool/skill/protocol-plugin/scripts/proto-repro.py \
  --input artifacts/frames.bin --rebuild --frame-index 2 \
  --set type=4 --set seq=4 \
  --payload-text '{"temp":22.0,"status":"ok"}' \
  --out artifacts/new-frame.bin --json
```

| 台阶 | 通过判据 |
|---|---|
| T1 原样重放 | 响应与基线结构/关键字段一致 |
| T2 单变量构造 | 响应符合预测，重复 3 次稳定；`rebuild.verify.crc_ok=true` |
| T3 状态闭链 | 握手→认证→业务→关闭全程自动，错误帧被正确处理 |

**完成判据**：至少 T2；能写清"预测项 vs 实际"的逐项 diff。详见 `references/08-replay-and-new-request.md`。

### 阶段 E：验收与交付

```bash
python Tool/skill/protocol-plugin/scripts/proto-accept.py --json
python Tool/scripts/domain-gate.py --domain protocol-plugin
```

**完成判据**：`proto-accept.py` 全 PASS（案例 sha256/字段/`lessons` 的 rc）；本域门禁全绿。
交付物：`capture.pcapng`、`frames.jsonl`、`schema.json`、`run.json`（cmd/rc/stdout）、
`responses/`、`diff.md`、卡点清单。

## 6. 参考索引（8 篇，逐篇）

| 文件 | 职责 | 什么时候读 |
|---|---|---|
| `references/01-criteria.md` | 判据表：场景/输入面/可机检判据/证据形态/误报风险 | 开工定判据、交付前自检 |
| `references/02-failure-criteria.md` | 失败判据：现象/判定/改走哪条/代价；含时间盒、事故回流、交接包 | 卡住时先看 |
| `references/03-model-pitfalls.md` | 模型常见失误 20 条（错误动作→为什么错→正确动作）+ 代理信号 | 每次复盘 |
| `references/04-walkthrough-websocket-replay.md` | 真实 ws pcap 走查：分帧→字段→状态→构造 | 第一次做完整链路 |
| `references/05-binary-framing.md` | 二进制分帧：magic/长度/TLV/半包粘包 | 写解析器 |
| `references/06-app-state-machine.md` | 应用层协议与状态机：台账/迁移/认证材料/负例 | 会话型协议 |
| `references/07-crypto-and-checksum.md` | 加密段与校验：压缩/编码/加密区分、CRC 参数、取明文 | 熵高/校验对不上 |
| `references/08-replay-and-new-request.md` | 重放与新请求构造：T1/T2/T3、单变量矩阵、差异归因 | 要证明"能构造" |

## 7. 脚本用法（3 个脚本 + 1 个兼容入口）

```bash
# 1) pcap-summary.py：会话聚合 / 方向性字节流导出 / 明文片段（纯标准库，可无 tshark）
python Tool/skill/protocol-plugin/scripts/pcap-summary.py \
  --file capture.pcapng --json --extract artifacts/streams --tshark-check

# 2) proto-repro.py：字段表解析 + 校验复算 + 重新构造新帧（离线）
python Tool/skill/protocol-plugin/scripts/proto-repro.py \
  --input artifacts/frames.bin --rebuild --frame-index 0 --set seq=9 \
  --payload-text '{"k":1}' --out artifacts/new.bin --json
#    从 pcap 取某条流：--pcap capture.pcapng --stream 3（缺 tshark 时 blocked_at=tool-missing）
#    导出/复用字段表：--emit-schema artifacts/schema.json

# 3) proto-accept.py：本域案例判据复算 + 路由词边界自检
python Tool/skill/protocol-plugin/scripts/proto-accept.py --json
python Tool/skill/protocol-plugin/scripts/proto-accept.py --routing-check
```

| 脚本 | 输入 | 输出 | 退出码 |
|---|---|---|---|
| `pcap-summary.py` | pcap/pcapng | 会话 JSON / `s*.bin` / `frames.jsonl` | 0 成功或降级；2 解析失败 |
| `proto-repro.py` | 帧文件 / pcap(tshark) / schema | 帧表、校验结论、重建字节 | 0 成功；2 失败（`blocked_at`） |
| `proto-accept.py` | 案例目录 / 路由片段 | 判据复算结果 | 0 全过；2 有 FAIL |

三个脚本都支持 `--self-test`（离线、rc=0、输出含 `"ok"`）与 `--help`（rc=0）。
兼容入口：``Tool/skill/protocol-plugin/scripts/pcap-summary.py`` 转发到 skill 版（Windows 上可能丢子进程退出码，以 skill 版为准）。

## 8. 任务卡与 KB 入口

- 任务卡（24 张，六段固定）：`Tool/prompts/domains/protocol-plugin.md`
  —— 覆盖首轮分诊、DNS/隧道、WebSocket、IPv6/BGP/VLAN/ARP/SMB/S7/BLE 等协议的分帧与复刻。
- 知识库 board：`Tool/mcp/Tool/reverselab/kb/protocol/README.md`
  —— 逐篇索引 7 篇 technique，含 `failure-criteria.md`。
- 矩阵（13 个协议族，含 match/criteria/fail/pitfalls）：`Tool/config/protocol-plugin-matrix.json`。
- 路由片段：`Tool/skill/protocol-plugin/pack.json`
  —— `keywords` 与 SSOT 逐字一致（保证可合入）；词边界收紧版在 `boundary_policy`
  （含 `forbid`: spider/bios/principal/zipalign/scaffold），由 `proto-accept.py --routing-check`
  机检；合入 SSOT 由协调器跑 `route.py --write`（本域不直接改 pack.json）。
- 案例：`Tool/cases/protocol01`（HTTP 夹具）、`protocol02`（SPRX 夹具）、
  `protocol03`（真实 ws pcap）、`protocol04`（现场回环抓包）。

## 9. 交付格式（建议）

```text
目标/版本：          路由：R24
证据：capture.pcapng#L12 / frames.jsonl#42 / schema.json:field
协议层：              帧边界：
字段表：              magic/len/seq/checksum/payload
状态机：              handshake → auth → business → close（observed / INFERRED 分开）
重放：                原样复现 / 单变量构造 / 预测与结果
判据：同输入同输出 / 构造新请求 / 状态闭环 / 负例可解释
未解卡点与置信度：
```

**最后一条**：报告里每个"已确认"都要能指回证据；指不回去的，写"推断"，不要写成结论。

## 子技能（按需读，不常驻）

本域相关子技能放在 `Tool/skill/_pending/`（不占常驻上下文，需要时再读）：

- `_pending/plugin-targets/SKILL.md` —— 目标是浏览器扩展/IDE 插件/Mod
