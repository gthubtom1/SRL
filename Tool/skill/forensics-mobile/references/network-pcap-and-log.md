# 流量与应用日志：pcap 会话、对象导出、DNS/TLS 与日志时间线

> **范围**：`*.pcap`/`*.pcapng`、HTTP/DNS/TLS 流量、代理/网关日志、应用日志（JSON/文本）、NetFlow/Zeek 日志。
> 前置：采集点/接口/时区信息齐全、授权抓包；单包/单行日志只作线索，会话结论要完整重组。
> 目标：把“谁在何时与谁通信、传了什么、服务端如何响应”落到会话/对象/时间，并与内存、磁盘、日志交叉。

## 1. 先看包级元数据

```bash
capinfos capture.pcap
tshark -r capture.pcap -q -z io,phs
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap -q -z endpoints,ip
```

判据：

- `capinfos` 给出包数、首末时间、链路类型、是否截断；首末时间与采集记录对得上。
- `conv,tcp` 能看到双向字节数/包数；只有单向说明抓包点不对称或过滤错。
- 大包先 `editcap -c 200000` 切片或强过滤；不要把 10GB pcap 直接塞进内存。

## 2. 会话重组（不要只看单包）

```bash
tshark -r capture.pcap -Y "tcp.stream eq 7" \
  -T fields -e frame.time_epoch -e ip.src -e tcp.srcport \
  -e ip.dst -e tcp.dstport -e tcp.len -e tcp.flags.str
tshark -r capture.pcap -Y "tcp.stream eq 7" -z follow,tcp,ascii,7
```

- `tcp.stream` 是会话键；同端口不同连接不能合并。
- 看请求行/状态码/`Content-Length`/`Content-Type`/响应体；只看到 `GET` 不能写“上传成功”。
- 重传/乱序/分片：`tshark` 会重组 TCP，但应用层分块/压缩要单独处理。
- UDP/DNS：`-z conv,udp`；QUIC/HTTP3 不能按 TCP 流重组。

## 3. HTTP 对象导出与哈希

```bash
mkdir -p export/http
tshark -r capture.pcap --export-objects http,export/http
sha256sum export/http/* | tee export/http/SHA256SUMS
file export/http/*
```

- 导出对象按 `tcp.stream`/URL 建索引；同名文件加 stream 前缀，避免覆盖。
- 对导出文件做 magic/类型/哈希；压缩包/可执行文件要单独静态分析（走 `malware-analysis`/`softseep`）。
- `--export-objects` 只导出完整对象；分块/断点续传可能缺片，需在 `tcp.stream` 里核对。

判据：能给出“会话起止时间、双方、协议、请求/响应关键字段、导出对象 SHA256”。

## 4. DNS / TLS / 外联

```bash
tshark -r capture.pcap -Y "dns" \
  -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.a
tshark -r capture.pcap -Y "tls.handshake.extensions_server_name" \
  -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e frame.time_epoch -e ip.dst -e tcp.dstport
```

- DNS：qname、A/AAAA、响应码、时间；DoH/DoT 只看到加密流量与 IP。
- TLS：SNI、证书主体/签发者、JA3/JA4（若工具支持）；没有 keylog 时看不到 HTTP 内容。
- 外联结论要落到“客户端 IP:端口 → 服务端 IP:端口 + SNI/域名 + 时间”，并与内存 `netscan`/进程对齐。
- NAT/代理/负载均衡会让“IP 归属”失真；写清采集点位置。

## 5. 应用/代理日志

```bash
# 结构化日志：先看字段与时间格式
head -5 app.log
python - <<'PY'
import json
for line in open('app.log', encoding='utf-8', errors='replace'):
    try:
        o = json.loads(line)
    except ValueError:
        continue
    print(o.get('ts'), o.get('user'), o.get('action'), o.get('dst'))
PY
```

- 日志时间可能是本地时间/UTC/epoch；先抽样对照 pcap/主机时间，再统一 UTC。
- 登录失败→成功、外联、执行、归档、DNS 查询要按主体/源地址聚合；单行日志只能算 `observed-log`。
- 日志可被伪造/截断/重放；至少用 pcap/进程/文件哈希之一交叉。
- 代理日志的 `user` 可能是账号/租户，不是设备用户；主体归因要写清。

## 6. 与内存/磁盘对齐

| 对齐键 | 内存 | 流量 | 磁盘/日志 |
|---|---|---|---|
| 五元组 | `netscan` 的 PID/时间 | `tcp.stream` 首末包 | 防火墙/代理日志 |
| 进程 | PID/PPID/命令行 | 端口归属（需 netstat） | 4688/进程日志 |
| 文件 | dump/路径 | HTTP 对象哈希 | inode/路径/哈希 |
| 时间 | 连接 Created | 首末 epoch | EVTX FILETIME/mtime |

只有一侧时标 `inferred`；两侧时间差超过采集窗口/时钟偏差时，写“无法判定顺序”。

## 7. 时间线归一

```json
{"time_utc":"2026-10-20T03:14:05Z","actor":"10.20.0.15:49152",
 "action":"HTTP GET /login","object":"10.20.0.5:80 /login (Bearer 脱敏)",
 "confidence":"observed","evidence_refs":["capture.pcap#tcp.stream=0"],
 "command":"tshark -r capture.pcap -Y 'tcp.stream eq 0' -z follow,tcp,ascii,0"}
```

- 时间用 pcap epoch 转 UTC；日志时间保留原值/偏移。
- 凭据/token 脱敏；只写“存在 Authorization 头”，不复制明文 secret。
- 丢包/截断/单向要写进 `warnings`，不要用“没看到”证明“没发生”。

## 8. 云日志（CloudTrail / VPC Flow）与容器/K8s 取证

云上“谁做的”不靠 IP，靠三件套：`eventName`（动作）、`sourceIPAddress`（来源）、`userIdentity`（主体）。

```bash
jq -c 'select(.eventName|test("ConsoleLogin|AssumeRole|CreateAccessKey|StopLogging|DeleteTrail")) |
  {t:.eventTime,n:.eventName,ip:.sourceIPAddress,id:.userIdentity.arn,
   type:.userIdentity.type,ua:.userAgent,err:.errorCode}' cloudtrail.json | head -20

# VPC Flow v2 默认字段顺序：version account-id interface-id srcaddr dstaddr
# srcport dstport protocol packets bytes start end action log-status
awk '{print $4,$5,$7,$13,$14}' flow.log | sort | uniq -c | sort -rn | head

kubectl get events -A --sort-by=.lastTimestamp -o json > events.json
kubectl get pod <pod> -o jsonpath='{.status.containerStatuses[*].containerID}'
docker inspect -f '{{.GraphDriver.Data.UpperDir}}' <container>
```

- `userIdentity.type` ∈ `{IAMUser,AssumedRole,Root,FederatedUser,AWSAccount}`；`AssumedRole` 的 `arn` 末尾是 `assumed-role/<role>/<session>`，真正主体是 role+session，不是 IP。`invokedBy` / `userAgent=...amazonaws.com` 表示服务代调用——服务名不是主体（模型常把它当“某用户”）。
- 盲区自检：查 `StopLogging`/`DeleteTrail`/`UpdateTrail`/`PutEventSelectors` 是否被调用；管理事件默认开，数据事件（如 `S3 GetObject`）需显式开，别写“没有访问”。
- Flow Log 是 ENI 粒度，无载荷无域名（只有 Route53 Resolver 日志有 qname）；`action=ACCEPT|REJECT`，`log-status=NODATA|SKIPDATA` 要单列；`start`/`end` 是聚合窗口（60s/600s），不是单包时间。
- K8s：事件 JSON 取 `involvedObject.kind/name`、`reason`、`message`、`source.component`、`firstTimestamp`/`lastTimestamp`、`count`；事件默认只留 1h，先 `-o json` 固化再分析。
- 审计面：`audit.k8s.io/v1` 的 `verb`/`user.username`/`sourceIPs`/`objectRef`/`responseStatus`；审计策略决定记哪些 verb，没记录≠没发生。
- 容器可写层：`docker inspect` 的 `GraphDriver.Data.UpperDir`（或节点 `/var/lib/docker/overlay2/<id>/diff`）只读复制为快照，`docker diff <c>` 给 A/C/D 列表。**不要 `docker commit` 或 `exec` 写容器**——那会改可写层，证据就不再是当时的。

**判据**：`cloudtrail.eventName`/`sourceIPAddress`/`userIdentity.arn` 三项非空（缺一项标 `inferred`）；`flow.srcaddr`/`dstaddr`/`dstport`/`start`/`end`/`action` 齐全；`k8s_event.involvedObject` 能落到具体资源；`container.upperdir_sha256` 有快照哈希。

**失败判据**：`userIdentity` 只有服务名/`invokedBy` → 主体标 `inferred`，不写“某用户操作”；Flow Log 全为 `NODATA` → 写“采集侧无记录”，不写“无流量”；K8s 事件已过期且列表空 → 转审计日志/`kubectl describe`，不写“没发生过”；容器已删且 upperdir 不存在 → 只给镜像 digest 与日志，不写“文件已被清理”。

## 9. 失败判据

- `capinfos` 包数正常但重组无内容 → 截断/加密/分片/单向；切片/逐流/查 keylog，仍不行降级为元数据。
- 只有单向流量 → 不能判断请求是否被接受；标 `inferred`。
- TLS 无 keylog 且无进程内明文 → 停内容级结论，只做 SNI/证书/时序。
- 日志时间与 pcap 差整数小时/固定偏移 → 先校时区/NTP，再排因果。
- 日志单源且可伪造 → 降为 `observed-log`，不写“已外联/已执行”。
- 导出对象哈希不一致/被覆盖 → 重新导出并按 stream 唯一命名。

## 10. 边界

- 只抓自有/授权网络；不嗅探他人流量；不重放攻击/不投递恶意载荷。
- 不把 pcap 里的明文凭据/个人信息直接写报告；脱敏后再引用。
- 不把“没有抓到”当“没有发生”；采集点/过滤/加密都会造成盲区。
- 流量结论必须与内存/磁盘/日志至少一个独立源交叉；否则标 `unverified`。

> 相关：`01-criteria.md`、`02-failure-criteria.md`、`memory-forensics.md`、`evidence-chain.md`；案例 `Tool/cases/forensics01/`。
