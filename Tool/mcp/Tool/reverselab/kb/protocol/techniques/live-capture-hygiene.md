# 现场抓包卫生：BPF 收敛、抓包点、脱敏

> 入口信号：要"现场抓一次"（不是拿现成 pcap）、要抓回环/容器/代理流量、要长期跑。
> 实测案例：`Tool/cases/protocol04/`（回环 + 本地 Python 回显服务，BPF 仅本案例端口）。
> 深水区：`Tool/skill/protocol-plugin/references/08-replay-and-new-request.md`。

## 1. 先选抓包点，再谈过滤器

| 场景 | 抓哪里 | 常见坑 |
|---|---|---|
| 本机进程直连 | 回环适配器（`tshark -D` 里的 `Loopback`） | 只抓物理网卡 → 回环流量完全看不到 |
| 容器 / WSL / 虚拟机 | 容器内 `eth0` 或宿主 veth | 在宿主抓 `eth0` 抓不到容器内部通信 |
| 走代理 | 代理入/出口任一侧 | 两侧都抓会把同一请求算两次 |
| TLS 客户端 | 同机 + `SSLKEYLOGFILE` | 只抓包不设 keylog → 全是密文 |
| 无线 | 监控模式网卡 | 管理帧/加密帧混入，需要 `wlan.fc.type==2` 过滤 |

```bash
tshark -D                       # 列出适配器（第 1 列是编号）
tshark -i 10 -a duration:5 -w artifacts/live.pcapng
```

## 2. 必须用 BPF 收敛（本 board 最贵的一课）

**未过滤的回环抓包会混入同机其它进程的真实流量**——可能是你的编辑器、聊天工具、
甚至 agent 自己的 API 请求。第一次抓 protocol04 时未加 `-f`，抓到了与案例无关的
`/api/agent/...` 会话，含本机路径与鉴权头，已废弃重抓。

```bash
# 正确做法：端口/网段/主机三元组至少收敛一层
tshark -i "$IFACE" -f "tcp port 18321" -a duration:5 -w artifacts/live.pcapng

# 需要排除噪声时（BPF 支持 and/or/not）
tshark -i "$IFACE" -f "tcp port 18321 and not host 10.0.0.9" -a duration:5 -w out.pcapng
```

判据：`tshark -r live.pcapng -q -z conv,tcp` 里的每条会话都应落在你声明的端口/主机内；
出现一个陌生端口，就说明过滤器没收敛。

## 3. 现场抓包脚本骨架（可照抄）

```bash
#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.." || exit 2
PORT=18321; OUT=artifacts/live.pcapng
IFACE="${1:-$(tshark -D 2>/dev/null | grep -i loopback | head -1 | cut -d. -f1)}"
[ -z "$IFACE" ] && { echo "no loopback iface" >&2; exit 2; }
mkdir -p artifacts; rm -f "$OUT"

python input/echo_server.py "$PORT" & SRV=$!
sleep 1
tshark -i "$IFACE" -f "tcp port $PORT" -a duration:5 -w "$OUT" 2>artifacts/tshark-capture.err & TS=$!
sleep 1
curl -s -o /dev/null -w 'req1 %{http_code}\n' "http://127.0.0.1:$PORT/v1/ping"
wait $TS; RC=$?
kill $SRV 2>/dev/null
exit $RC
```

要点：`-a duration:N` 有界；先起服务再起抓包（避免漏握手）；`wait` 拿 tshark 的真实 rc；
把 `tshark-capture.err` 一起留档（里面是 `Capturing on ...` 与 `N packets captured`）。

## 4. 脱敏与留存

| 内容 | 处理 |
|---|---|
| Authorization / Cookie / Set-Cookie | 报告里替换为 `<redacted:sha256:前 8 位>`，保留长度与前缀 |
| 账号、内网 IP、主机名 | 按需替换（`10.x.x.x` / `host-01`） |
| 业务 payload | 只保留结构（字段名/长度/类型），不贴原文 |
| 原始 pcap | 只留在案例 `artifacts/`，并记录 BPF 与抓包点 |
| 一次性 token | 抓包时就不该出现；若出现，先判定是否仍有效 |

```bash
# 快速检查 pcap 里有没有敏感串（抓完立刻做）
tshark -r artifacts/live.pcapng -Y 'tcp contains "Bearer"' -T fields -e frame.number
strings artifacts/live.pcapng | grep -Ei 'password|token|secret|authorization' | head
```

## 5. 抓包与重放分离

- 基线抓包与重放流量**分开命名**（`baseline.pcapng` / `replay-01.pcapng`）。
- 代理会改 header 顺序、加 `Via`、重排 chunked；用被改写过的流量当基线，后面所有差异都不可信。
- 每个结论引用 `capture#frame N`，不要引用"我记得当时"。

## 6. 确认判据

- `conv,tcp` 里所有会话都在声明的过滤器范围内。
- `tshark-capture.err` 有 `N packets captured` 且 N > 0。
- 抓到了握手 + 至少一次完整业务往返（不是只有半条连接）。
- 报告里的每个字段都能在 pcap 里定位到帧号。

## 7. 失败判据

- 抓到的包全是 `data` 或 0 字节 payload → 抓包点错 / TLS 无 keylog，换点或取明文。
- 出现未声明的端口/主机 → 过滤器没收敛，废弃重抓（不要"顺手分析"别人的流量）。
- 只有单向流量 → 抓包点不在路径上，或回程走了另一网卡。
- 抓包文件里出现真实凭据 → 立即按事故处理：删除产物、重抓、写清原因。

## 8. 边界

- 只抓自己有权观测的流量；回环/靶场优先，生产抓包需书面授权与最小化原则。
- 本 board 不提供"绕过 TLS/pinning"的步骤，只说明 keylog/进程内取明文属于客户端侧观测。
- 抓包脚本必须能在别人机器上跑：接口名自动探测、端口参数化、路径相对仓库根。
