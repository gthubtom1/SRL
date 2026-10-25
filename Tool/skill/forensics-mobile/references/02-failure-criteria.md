# 02 · 失败判据表：看到什么就停/降级

> **范围**：取证对象已拿到、脚本已跑过一轮，但结果解释不了或不可信时。
> 入口：先完成一次采集再判失败；失败与“部分成功”分开写（`evidence-chain.md` 分级）。
> 用法：命中任一行 → 立刻停止升级结论，按“改走哪条”降级，并在报告写 `blocked_at` 与代价。

## 1. 失败判据主表

| 现象 | 判定 | 改走哪条 | 代价 |
|---|---|---|---|
| `vol.py` 报 `Unsatisfied requirement` / `Invalid profile` | 符号/ISF 与镜像版本不匹配 | 先 `banners.Banners` 定版本，再取对应 ISF/dSYM；仍不行走 `strings`+`bulk_extractor` | 时间成本 + 只能做字符串级线索，进程/网络结构不可信 |
| `pslist` 为空但镜像有 `KDBG`/`Windows` 字符串 | 结构偏移/版本不对或镜像被截断 | 换 `psscan`/`PoolScanner`，核对镜像大小与采集方式 | 可能把“没跑过”误判成“隐藏”；退出时间不可得 |
| MemProcFS `heap_recovered=false` 或 V3 `windows.heap` 为空 | 24H2+ 堆结构偏移未适配，或工具版本过旧 | 升 MemProcFS 5.19 重跑；仍空改 V3 `windows.heap`，再退 `psscan`+`malfind` | 进程堆/伪句柄不可得；只能做池扫描线索 |
| Win11 26H2 dump 在 MemProcFS <5.19 上崩溃或挂载目录为空 | 工具版本不支持 26H2 内核结构 | 升级 MemProcFS 5.19（2026-10-05）重跑；记录原版本与崩溃点 | 旧版输出不可用；不得写“镜像损坏/结构异常” |
| `/sys/eventlog` 与 `windows.eventlog` 均空，但磁盘 EVTX 有记录 | 内存日志未缓存/已滚动，或插件与 build 不匹配 | 以磁盘 EVTX 为准并注明“内存侧缺失”；核对 build/插件版本 | 内存侧日志归因缺位；不能写“日志被清除” |
| pcap `capinfos` 显示包数正常但重组无内容 | 截断/加密/分片/只抓单向 | `editcap -c` 切片、按 `tcp.stream` 逐流、检查 TLS keylog/进程内明文 | 会话结论降级为“只见元数据”；文件对象不可得 |
| `mmls` 有分区但 `fsstat -o` 报损坏 | `-o` 用了字节而非扇区，或镜像稀疏/加密 | 用 `mmls` 的 Start 扇区重试；`dd` 抽分区头核对；换 Autopsy | 误判文件系统损坏；需要重新采集或换工具 |
| `fls` 能列目录但 `icat` 内容乱码 | inode 复用/块被覆盖/压缩/加密 | 先校验 magic 与哈希；用 `blkls`+carve；标“不可恢复” | 已删文件结论不可用；只能给文件名/时间线索 |
| 时间线跨设备且相差整数小时 | 时区/夏令时未统一，或设备时钟漂移 | 全部转 UTC 并保留原值；用 NTP/登录日志估偏差；分设备列偏移 | 事件顺序可能反转；因果结论失效 |
| EVTX 记录数为 0 或首末时间跳变 | 日志被清除/滚动/复制不完整 | 查 `Security.evtx`/`System.evtx` 邻近通道；用 `wevtutil epl` 重新导出；查 `EventRecordID` 空洞 | 关键登录/进程事件缺失；只能声明“日志不可用” |
| hive 能读头但 `nk` 遍历为 0 | 权限只读到占位/空文件，或 hive 加密/损坏 | 用 `reg save` 导出可读子树；带 `LOG1/LOG2` 一起复制；换 `Registry Explorer` | 只能读头时间；键级时间线不可得 |
| History 时间落在 1601/1643/1970 年 | 时间纪元换算错（Chromium 1601us / FILETIME 100ns / Unix us 混用） | 按库类型选换算：Chromium `1601 + us`、Firefox `1970 + us`、FILETIME `1601 + 100ns` | 整条浏览器时间线错位；必须重算并标注修正 |
| iOS 二进制 `cryptid=1` | App Store 加密未脱壳 | 在授权测试机 dump 后再 `otool`/`nm`；否则只做包结构/签名/权限 | 静态符号与字符串不可信；不能据此判断逻辑 |
| `global-metadata.dat` 版本与 `GameAssembly` 不匹配 | Unity/IL2CPP 版本错配 | 用 `Il2CppDumper` 报的版本换对应 Unity 或 `Cpp2IL`；核对文件来源 | 输出为垃圾；字段/地址不可用 |
| AssetBundle 头不是 `UnityFS/UnityWeb/UnityRaw` | 加密/自定义容器/不是 Unity 资源 | 从二进制找 key/算法；或标“未解”，只做熵/字符串 | 资源内容不可得；不能声称“没有某资源” |
| 在线游戏出现 EAC/BattlEye/Vanguard/mhyprot | 反作弊/内核保护在运行 | 停止 attach/注入/读内存，改为外部抓包、日志、录屏；离线副本另做 | 线上动态结论不可得；但避免封号/蓝屏/法律风险 |
| 证据哈希与记录不一致，或原件 mtime 变了 | 证据被写/被替换/复制不完整 | 立即停；回到只读副本；重算全链哈希；记录污染时间窗 | 该证据链作废；需要重新采集或说明污染范围 |

## 2. 失败时的输出格式

脚本必须输出结构化失败，而不是裸栈：

```json
{"ok": false, "blocked_at": "symbols|permission|parse|tool-missing|evidence-chain", "reason": "具体原因"}
```

报告里对应写：

- **blocked_at**：卡在哪一步（采集/解析/归因/验收）。
- **已证实**：哪些字段/时间/哈希是 observed。
- **未证实**：哪些只能 inferred/unverified。
- **代价**：缺了哪类结论、需要补什么证据、重做范围多大。

## 3. 降级路线（按证据源）

| 能力 | 首选 | 降级 1 | 降级 2 | 何时停 |
|---|---|---|---|---|
| 内存 | volatility3 | Rekall / 崩溃转储解析 | `strings`+`bulk_extractor` | 两次换工具仍无进程/网络结构 |
| 流量 | tshark | tcpdump/Zeek/Scapy | `pcap-summary.py` 只做会话/片段 | TLS 无 keylog 且无进程内明文 |
| 磁盘 | sleuthkit | Autopsy | `dd`+foremost/photorec/debugfs | 分区/文件系统两次识别失败 |
| EVTX | 二进制记录解析（`fs-timeline.py`） | PowerShell `Get-WinEvent` | `wevtutil eql` 导出文本 | 日志被清除且无备份 |
| 注册表 | `reg save` + REGF 解析 | Registry Explorer / hivex | `reg query` 只读键值 | 权限/加密导致键级时间不可得 |
| iOS 包 | `unzip`+`plutil`+`codesign` | `llvm-objdump`/`rabin2` | 只做包结构与签名 | 加密二进制未脱壳 |
| IL2CPP | Il2CppDumper | Cpp2IL / Il2CppInspector | 只读 `global-metadata` 版本+字符串 | 版本不匹配且拿不到对应工具 |
| 资源 | AssetStudio | AssetRipper / UnityPy | 头/熵/字符串 | 加密且无 key |

## 4. 常见“假成功”

- `forensics-check.py` rc=0 只说明“文件可读、类型识别完成”，不说明“证据可信”。
- `unzip` 成功只说明“ZIP 完整”，不说明“iOS 包未被篡改/未加密”。
- `strings` 命中域名只说明“字符串存在”，不说明“运行时真的外联”。
- `fs-timeline.py` 事件数为 0 时 rc=2；若人为把空时间线当成功，属于伪造结论。
- `evidence-accept.py` PASS 只说明“案例元数据自洽”，不替代人工复核。

## 5. 边界

- 失败判据不是“免责声明”：命中后必须真的停/降级，并在产物里留下 `blocked_at`。
- 不把“工具缺失”写成“目标不存在”；缺工具就写 `tool-missing` 并给降级链。
- 不为了凑 `outcome: confirmed` 而忽略时区、哈希、加密状态。
- 反作弊/授权边界内的停止记录本身就是证据，必须保留时间、环境、触发点。

> 相关：`01-criteria.md`、`03-model-pitfalls.md`、`04-walkthrough-windows-evtx-registry.md`、`evidence-chain.md`。

## 6. 失败归因：从现象到 `blocked_at` 的映射

> 失败记录最少要有：阶段 + 主因 + 已试 + 已证实 + 未证实 + 代价。
> 主因只许一个；其余放 `secondary[]`，否则交接时无法排优先级。

| 现象 | 主因 `blocked_at` | 已证实（可以写） | 未证实（不能写） |
| --- | --- | --- | --- |
| `vol.py` 符号不匹配 | `symbols` | 文件是内存镜像、版本可读 | 进程/连接列表 |
| `pslist`/`psscan` 都空 | `parse` | 镜像可读 | “没有进程” |
| `malfind` 有页但 dump 失败 | `parse` | 存在可疑页 | “注入成功” |
| pcap 重组无内容 | `capture` | 包级元数据 | 会话内容/上传 |
| TLS 无 keylog | `encrypted` | SNI/证书/时序 | HTTP 内容 |
| `fsstat -o` 失败 | `offset` | 有分区 | “文件系统损坏” |
| `icat` 内容乱码 | `recover` | inode/时间 | 已删文件内容 |
| hive 键遍历为空 | `permission` | hive 头时间 | 持久化项 |
| EVTX 记录为 0 | `log-cleared` | 通道文件存在 | “没有发生” |
| 时间线缺时区 | `time-basis` | 有时间值 | 因果顺序 |
| iOS `cryptid=1` | `encrypted` | 包结构/签名 | 二进制逻辑 |
| IL2CPP 版本错配 | `tool-missing` | 元数据 magic | 字段/地址 |
| 反作弊在线 | `authorized-stop` | 组件存在 | 运行时行为 |
| 哈希不一致 | `evidence-chain` | 当前哈希 | 任何基于原件的结论 |

### 6.1 归因示例

```json
{
  "stage": "memory",
  "blocked_at": "symbols",
  "tried": [
    {"cmd": "vol.py -f mem.raw windows.pslist.PsList", "rc": 1,
     "stderr": "Unsatisfied requirement: kernel.symbols"},
    {"cmd": "vol.py -f mem.raw banners.Banners", "rc": 0,
     "stdout": "NT build 26100"}
  ],
  "confirmed": ["image readable", "build 26100"],
  "unconfirmed": ["process list", "network connections"],
  "next": {"route": "download ISF for 26100", "cost": "10 min"}
}
```

**判据**：`confirmed` 与 `unconfirmed` 都非空；`next.route` 可执行；`blocked_at` 只有一个主值。

## 7. 止损时窗：什么时候必须换面

| 路线 | 单次成本 | 止损 | 到点动作 |
| --- | --- | --- | --- |
| 换 ISF/profile | 10–20 min | 2 次 | 转 `strings`+`bulk_extractor`，只写线索 |
| 换 pcap 重组工具 | 10–30 min | 2 次 | 降级为会话元数据 |
| 换分区工具 | 15–30 min | 2 次 | 抽分区头 `xxd` 人工核对 |
| 恢复已删文件 | 10–20 min/个 | 3 个失败 | 标“不可恢复”，停止 |
| 解 hive 脏页 | 20–40 min | 2 次（含 LOG） | 只读头时间，键级标缺失 |
| iOS 脱壳 | 不可控 | 授权窗口 | 只做包结构/签名 |
| IL2CPP 工具替换 | 20–40 min | 2 个工具 | 只读元数据版本，停 dump |
| 在线动态 | — | 出现反作弊即停 | 转外部抓包/日志 |

> 时窗的判断标准不是“累不累”，而是“上一次重试有没有新增证据”。没有新证据的重试 = 换面信号。

## 8. 经验回流（lessons）：取证失败的六条硬教训

> 本域的 `lessons`：每条都能改变下一次的判据或命令。不要写“下次注意”。

### L1：时间纪元是第一个要校验的字段

- 现场：Chromium `visit_time` 按 FILETIME 换算，整条时间线跑到 1643 年。
- 新判据：先抽 1 条与 UI/日志对照，再批量换算；产物必须带 `ts_basis`。
- 落点：`01-criteria.md` §7.1；`03-model-pitfalls.md` 第 4 条。

### L2：SQLite 原库一打开，证据就变了

- 现场：`sqlite3 evidence/History` 建了 `-wal/-shm`，原件哈希变化。
- 新判据：复制三件套 + `mode=ro&immutable=1`；原件目录 `chmod a-w`。
- 落点：`disk-and-filesystem.md` §7；`evidence-chain.md` §5。

### L3：`pslist` 为空不等于没有进程

- 现场：镜像截断，`pslist` 空但 `psscan` 有 12 个池对象。
- 新判据：两个插件都跑；差集逐 PID 解释；都空才写 `parse`。
- 落点：`memory-forensics.md` §2–3；本文第 6 节。

### L4：pcap 单向包不能证明“上传成功”

- 现场：只抓到客户端 → 服务端，没有响应，报告写“已上传”。
- 新判据：双向会话 + 状态码/响应体/对象哈希；只有单向 → `inferred`。
- 落点：`network-pcap-and-log.md` §2；`03-model-pitfalls.md` 第 3 条。

### L5：哈希链断在“产物覆盖原件”

- 现场：导出对象写回 `input/http/`，第二天哈希全变。
- 新判据：`input/` 只读、`artifacts/` 可写、导出按 `tcp.stream`/inode 唯一命名。
- 落点：`evidence-chain.md` §2；`03-model-pitfalls.md` 第 13 条。

### L6：反作弊环境里的“停”也是证据

- 现场：在线 attach 触发保护，进程重启。
- 新判据：识别组件后立即停；记录时间/环境/触发点；转离线副本。
- 落点：`game-client-il2cpp.md` §6；`ios-macos-artifacts.md` §7。

## 9. 命令与“通过长什么样”（失败记录复验）

```bash
CASE=work/case-x

# 1) 每个证据文件都有哈希
test -s "$CASE/input/SHA256SUMS" && sha256sum -c "$CASE/input/SHA256SUMS" | tail -5

# 2) 失败记录字段齐全
python - <<'PY'
import json, pathlib
p = pathlib.Path("work/case-x/failure.json")
d = json.loads(p.read_text())
need = ("stage", "blocked_at", "tried", "confirmed", "unconfirmed", "next")
print({k: bool(d.get(k)) for k in need})
PY

# 3) 报告里没有“裸结论”
grep -nE '已外联|已执行|已删除|存在漏洞' "$CASE/report.md" | \
  grep -vE 'observed|inferred|unverified|blocked_at|未验证' || true
```

**通过长什么样**：

| 检查 | 通过 | 不通过 |
| --- | --- | --- |
| 哈希 | `sha256sum -c` 全 OK | 有 FAILED |
| 字段 | 六个 key 全 true | 缺 `tried`/`confirmed` |
| 归因 | 一个主 `blocked_at` | 多个主值 |
| 报告 | 每个强结论都有置信标签 | 裸写“已外联” |
| 代价 | 有路线/时间/前置 | “继续研究” |

## 10. 失败后的最小可交付包

即使全线失败，也要能给下一个人一个可接手的目录：

```text
work/case-x/
  scope.md          # 授权/窗口/对象
  input/            # 原件副本 + SHA256SUMS（只读）
  artifacts/        # 时间线/导出/失败记录（可写）
  failure.json      # 本文第 6 节的六段字段
  report.md         # observed/inferred/unverified + 代价
```

最小验收：

| 文件 | 必须包含 | 机检 |
| --- | --- | --- |
| `input/SHA256SUMS` | 每个输入一行 | `sha256sum -c` 全 OK |
| `failure.json` | `stage/blocked_at/tried/confirmed/unconfirmed/next` | 六 key 非空 |
| `artifacts/timeline.json` | 至少一个事件或显式空原因 | `ok` 字段 |
| `report.md` | 每个结论有置信标签 | 无裸“已…” |

### 二次失败判定

同一路线第二次失败后，只允许做三件事：

1. **换源**：换一个独立证据源（内存→磁盘/流量），而不是换工具参数。
2. **降级**：把结论从“已发生”降为“观察到/推测”。
3. **收束**：写 `blocked_at` + 代价 + 重试条件，结束本轮。

需要先确认：把同一命令改个超时/路径再跑第三次；把“没跑出来”写成“目标不存在”。

## 11. 失败记录常见缺失（交接前对照）

| 缺失 | 后果 | 补法 |
| --- | --- | --- |
| 没写 `stage` | 不知道卡在采集/解析/归因 | 用六阶段枚举 |
| 没写 `rc` | 分不清“没跑”与“跑失败” | 每条 `tried` 补 |
| 没写 `confirmed` | 下一个人重做已排除项 | 列已证实字段 |
| 没写 `next.cost` | 低估修复代价 | 时间/硬件/授权三项 |
| 没写 `retry_when` | 无限重试 | 新样本/新授权/新工具 |

## 这一篇算"用对了"吗

- [ ] 我的失败记录有阶段、主因、已试命令 rc、已证实/未证实、代价六段
- [ ] 我给每条路线设了止损时窗，到点换面而不是重复撞工具
- [ ] 我沉淀了至少一条 lessons，并指回它改动了哪条判据
- [ ] 我没有把 `symbols/capture/encrypted/permission` 写成“目标不存在”
- [ ] 我的报告里每个强结论都有 observed/inferred/unverified 标签
- [ ] 哈希不一致时我先停，而不是改记录去迁就产物
