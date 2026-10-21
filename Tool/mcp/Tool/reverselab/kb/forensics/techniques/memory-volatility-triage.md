# 内存镜像初检：Volatility3 的判据与降级

> **入口信号**：拿到 `mem.raw`/`*.dmp`/`*.vmem`/`hiberfil.sys`，需要回答“哪些进程、连接、模块在何时存在”。
> **不适用**：没有采集记录的镜像；未授权设备；把内存当唯一证据给恶意定性。

## 1. 最小命令

```bash
sha256sum mem.raw | tee mem.raw.sha256
python3 vol.py -f mem.raw banners.Banners
python3 vol.py -f mem.raw windows.info.Info
python3 vol.py -f mem.raw windows.pslist.PsList
python3 vol.py -f mem.raw windows.psscan.PsScan
python3 vol.py -f mem.raw windows.cmdline.CmdLine
python3 vol.py -f mem.raw windows.netscan.NetScan
python3 vol.py -f mem.raw windows.malfind.Malfind
```

Linux/macOS：`linux.pslist`/`linux.bash`/`linux.malfind`、`mac.pslist`/`mac.bash`/`mac.malfind`。

## 2. 确认判据

- `banners` 给出 NT build/架构；`windows.info` 的 `SystemTime` 与采集记录不矛盾。
- `pslist` 与 `psscan` 都能跑；PID 差集有解释（退出/隐藏/扫描差异）。
- 进程至少五项：PID/PPID、镜像路径、命令行、start/exit、SID。
- `netscan` 的连接能落到 PID + 时间 + 五元组；与 pcap 至少一侧对齐。
- `malfind` 页可 dump，dump 文件有 SHA256 且能被 `file`/`rabin2` 二次识别。

## 3. 失败判据

- `Unsatisfied requirement`/`Invalid profile`：符号不匹配，先定 build 再取 ISF；仍不行降级 `strings`。
- `pslist` 空但镜像有系统字符串：截断/加密/格式不符，停，别写“没有进程”。
- `malfind` 命中但 dump 不出来：只写“候选页”，不写“注入成功”。
- 连接只有内存侧或只有 pcap 侧：标 `inferred`，不写“已外联”。

## 4. 边界

- 只读：不写内存、不注入、不挂钩、不加载驱动。
- `malfind` 不是恶意判决：浏览器/JIT/打包器也会 RWX。
- 结论必须与磁盘/流量/日志一个独立源交叉；否则 `unverified`。
- 相关：`Tool/skill/forensics-mobile/references/memory-forensics.md`、`01-criteria.md`。

## 5. 进程/连接合并模板

| 字段 | 来源 | 缺失时 |
|---|---|---|
| PID/PPID | pslist/psscan | 标 `unverified` |
| ImageFileName | pslist | 用 cmdline 首 token 代 |
| CreateTime/ExitTime | pslist | 只写“采集时存在” |
| CommandLine | cmdline | 不猜参数 |
| SID/User | getsids | 主体降级 |
| ForeignAddr/State | netscan | 与 pcap 对齐 |

```json
{"time_utc":"...Z","actor":"PID 4242 (updater.exe)",
 "action":"TCP connect","object":"203.0.113.9:443",
 "confidence":"observed","command":"vol.py -f mem.raw windows.netscan.NetScan"}
```

## 6. 常见误判

- `pslist` 有进程 = 系统干净？不，隐藏进程在 `psscan` 差集里。
- `malfind` 命中 = 注入？不，JIT/浏览器/打包器也会 RWX。
- 字符串命中域名 = 外联？不，需五元组 + PID + 时间。
- 退出时间缺失 = 没运行？不，只说明未正常退出。
