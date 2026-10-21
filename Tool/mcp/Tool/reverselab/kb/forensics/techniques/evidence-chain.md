# 证据链四要素：时间/主体/动作/对象 + 哈希

> **入口信号**：结论要写进报告/案例，需要第三方按同样命令复述。
> **不适用**：探索性排查但还没打算复现；一旦写进报告就必须补齐。

## 1. 四要素模板

```json
{"claim":"PID 4242 在 03:14Z 外联 203.0.113.9:443",
 "time_utc":"2026-10-20T03:14:07Z","actor":"PID 4242 (updater)",
 "action":"TLS connect + POST","object":"203.0.113.9:443 /api/upload",
 "confidence":"observed","evidence_refs":["mem.raw#pid=4242","capture#tcp.stream=7"],
 "command":"vol.py -f mem.raw windows.netscan.NetScan"}
```

- 时间：UTC + 原时区/偏移 + 时钟偏差。
- 主体：用户/进程/设备/账号（SID/UID/Bundle ID）。
- 动作：读/写/外联/执行/删除，含命令或协议。
- 对象：路径/inode/URL/五元组/键 + 哈希。
- 置信：`observed`/`inferred`/`unverified`。

## 2. 哈希链

```bash
sha256sum input/* | tee input/SHA256SUMS
python Tool/skill/forensics-mobile/scripts/evidence-accept.py --case Tool/cases/forensics03 --json
```

- `input/` 只读，`artifacts/` 可写；产物不写回 input。
- 案例 `artifacts[]` 每个路径都有 sha256；门禁复算，不一致 FAIL。
- 大镜像可先 `--no-hash` 初检，提交时补全或说明原因。

## 3. 时间线冲突

- 时区/夏令时：统一 UTC，保留原偏移。
- `$SI` vs `$FN`：并列，标“可能篡改”。
- EVTX RecordId 空洞：写“日志不完整”。
- 浏览器 1601/1970：按库类型重算，抽样对照。
- 采集顺序/缓存：写采集窗口，不强行对齐到秒。

## 4. 失败判据

- 哈希不一致/原件被写 → 该链作废，重采或说明污染范围。
- 四要素缺主体/对象 → 降为线索，不进结论段。
- 缺时区/时钟偏差且无法补齐 → 只写候选顺序。
- 采集记录缺 method/tool/time/timezone → 不能证明来源。
- 只读边界被突破 → 停，记录动作与影响。

## 5. 边界

- 机检只证明“字段/哈希/格式自洽”，不证明结论为真。
- 对外分享前脱敏 URL 参数、用户名、SID、设备标识。
- 相关：`Tool/skill/forensics-mobile/references/evidence-chain.md`、`02-failure-criteria.md`。
