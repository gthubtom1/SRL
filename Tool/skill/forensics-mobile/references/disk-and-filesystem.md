# 磁盘 / 文件系统取证：分区、inode、$MFT 与时间线

> **适用**：`disk.img`、`*.E01`、分区镜像、`$MFT`/`$UsnJrnl` 副本、Windows EVTX、注册表 hive、浏览器 History。
> **不适用**：未授权设备；在原件上挂载/运行/改时间戳；把 `fls` 列表当“文件内容已恢复”。
> 目标：把“哪个对象、在哪个时间、被谁怎样操作”落到分区/文件系统/inode/键/记录级，并能用命令复现。

## 1. 先确认镜像完整性

```bash
sha256sum disk.img | tee disk.img.sha256
stat -c '%n %s %y' disk.img
file disk.img
# E01 用 ewfinfo/ewfverify；dd 镜像核对采集记录与扇区数
```

- 记录采集方式（`dd`/`dcfldd`/`FTK Imager`/`ewfacquire`）、块大小、是否跳过坏扇区。
- 原件只读；所有挂载用 `ro,loop,noatime`，或干脆不挂载，直接用 sleuthkit 按偏移读。

## 2. 分区表与文件系统

```bash
mmls disk.img
fsstat -o 2048 disk.img
fls -r -p -o 2048 disk.img > out/fls.txt
```

- `mmls` 的 `Start` 是**扇区号**；`-o` 用它，不是字节偏移。偏移错会得到“文件系统损坏”的假象。
- `fsstat` 记录文件系统类型、块大小、inode 范围、$MFT/$LogFile 位置；这些决定后续 `icat`/`istat` 参数。
- 多分区镜像要分别做；不要假设“第一个分区就是系统盘”。

## 3. 目录树、已删文件、inode

```bash
fls -r -m "/" -o 2048 disk.img > out/bodyfile.txt
mactime -b out/bodyfile.txt -d -z UTC > out/timeline.csv
fls -r -d -o 2048 disk.img | head -50          # 只看 deleted
istat -o 2048 disk.img 12345                   # inode 元数据
icat  -o 2048 disk.img 12345 > out/recovered.bin
```

判据：

- `fls` 能给出路径、inode、`(deleted)` 标记、MACB 时间。
- `icat` 取回的内容 magic/哈希可校验；否则标“不可恢复”。
- inode 复用：同一 inode 在时间线上出现多次时，必须区分“旧文件残留”与“新文件”。

## 4. NTFS 深水区：$MFT / $UsnJrnl / $LogFile

```bash
# 只读复制（不可读时用 fsutil 查询元数据，不写盘）
cp '/c/$MFT' out/MFT.bin 2>/dev/null || true
fsutil fsinfo ntfsinfo C:
fsutil volume diskfree C:

# 用 sleuthkit 按 MFT 记录号取文件
icat -o 2048 disk.img 12345 > out/from-mft.bin
```

- `$MFT` 记录号 = inode；记录里同时有 `$STANDARD_INFORMATION` 与 `$FILE_NAME` 两套时间，可能不一致（时间戳篡改的线索）。
- `$UsnJrnl:$J` 记录创建/删除/重命名/写入，是“文件系统操作日志”；解析时注意 USN 记录可回绕。
- `$LogFile` 是事务日志，脏页/崩溃恢复会用到；不要在没有副本时让系统挂载。
- `fsutil` 只读查询可用于确认簇大小/可用空间；`fsutil usn readjournal` 需要权限，读不到就写 `blocked_at: permission`。

## 5. Windows 事件日志（EVTX）

```bash
# 只读复制；原件在 %WINDIR%/System32/winevt/Logs/
cp "$WINDIR/System32/winevt/Logs/Security.evtx" input/Security.evtx
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file input/Security.evtx --json
python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input input/Security.evtx --out out/evtx.json
```

- EVTX 记录结构：`**\0\0` + size + RecordId(u64) + FILETIME(u64) + Binary XML；`fs-timeline.py` 至少能稳定取出 RecordId/FILETIME。
- 事件语义（EventId/Provider/Level/Task）需要 Binary XML 解码；本域脚本只做时间线，语义用 `wevtutil`/PowerShell 补充。
- 常见通道：Security（4624/4625/4688/4672）、System（7045 服务）、Application、PowerShell/Operational、TaskScheduler/Operational。
- 日志滚动/清除会留下 `EventRecordID` 空洞；时间跳变要写“可能清除/时区变化”，不要直接排因果。

## 6. 注册表 hive（REGF）

```bash
# 只读导出当前用户子树（不修改原 hive）
# 通用做法（分析真实 hive）；若案例要入库，注意 hive 常含本机账号路径（PII），
# 可退化为「键名清单」：Get-ChildItem ... | Select Name（无值、无原始 hive）
cmd //c "reg save HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer input/Explorer.hiv /y"
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file input/Explorer.hiv --json
python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input input/Explorer.hiv --out out/registry.json
```

- REGF 头：`regf`、header last-write（0x0C）、root cell（0x24）、hive bins size（0x28）。
- hbin 头 `hbin`，大小在 +0x08；cell 大小为有符号 int32，负值表示已分配；`nk` 键的最后写入在 cell+8。
- 键名压缩标志 `0x20`：置位用 Latin-1，否则 UTF-16LE。
- 脏页/事务：同时复制 `.LOG1/.LOG2`；只读头可能落后于最新事务。
- 持久化面：Run/RunOnce、Services、IFEO、Winlogon、AppInit_DLLs、TaskScheduler、UserAssist、ShellBags、USBSTOR。

## 7. 浏览器 History（只读、不碰 cookie）

```bash
cp "$LOCALAPPDATA/Microsoft/Edge/User Data/Default/History" input/History.sqlite
python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input input/History.sqlite --out out/history.json
```

- Chromium/Edge：`urls` + `visits`，`visit_time` 是 **1601 起的微秒**；Firefox：`moz_places` + `moz_historyvisits`，`visit_date` 是 **1970 起的微秒**。
- 只查 URL/visit_time/title，不读 `cookies`/`Login Data`；需要登录态证据时单独授权并脱敏。
- `-wal/-shm` 一起复制；直接用 `mode=ro&immutable=1` 打开，避免创建/回写。

## 8. 统一时间线

```bash
python Tool/skill/forensics-mobile/scripts/fs-timeline.py \
  --input out/evtx.json --input out/registry.json --input out/history.json \
  --input out/bodyfile.txt --out out/timeline.json
```

注意：`fs-timeline.py` 接受原始 evtx/hive/sqlite/目录，不直接吃 bodyfile；bodyfile 用 `mactime -z UTC` 转 CSV 后再与 JSON 合并。合并规则：

- 主键：`time_utc`；同一时间用 `source/object` 稳定排序。
- 保留原值：设备时区、文件系统精度（FAT 2s、APFS 纳秒）、时钟偏差。
- 冲突：同一对象多套时间（`$SI` vs `$FN`）要并列，不取“看起来合理”的那个。

## 9. PST/OST 邮件与 USB 设备史

```bash
readpst -o out/pst -D -M mailbox.pst        # libpst：-D 分离附件，-M 输出 mbox
pffinfo mailbox.pst                         # libpff：类型/版本/加密状态
pffexport -m all -t out/pff mailbox.pst     # 逐条消息导出（含可恢复项）
```

- PST/OST 同为 `!BDN` 容器；OST 是 profile 缓存，条目可能不全，必须与服务器侧或导出件对照。加密（compressible encryption）先用 `pffinfo` 判，再决定是否能读。
- 每条消息取：`PidTagClientSubmitTime`/`PidTagDeliveryTime`、`PidTagSenderSmtpAddress`、`PidTagDisplayTo`、`PidTagSubject`、附件 SHA256。删邮件看 `pffexport` 的可恢复/未分配项，不能只导活动文件夹。
- USB 设备：`SYSTEM\CurrentControlSet\Enum\USBSTOR\<device>\<instance>`（`VID_xxxx&PID_xxxx` + 序列号）；子键 last-write 是“最后写入”，不等于连接时间；`Properties\{83da6326-...}\0064`/`0065` 分别是首连/末连时间（8 字节 SYSTEMTIME）。
- `setupapi.dev.log` 的 `>>> [Device Install (DiInstallDevice) - USB\VID_...]` 段带时间戳与驱动路径，是 USBSTOR 之外的独立源；`Kernel-PnP` 事件 400/410/420 给接入/断开。
- `Windows Portable Devices\Devices`、`MountedDevices`、`EMDMgmt` 补设备卷与挂载点；首连时间取“首连属性 + setupapi 最早段 + PnP 事件”三者中最早的一个，不能只看 USBSTOR 键 last-write。
- 时间基准不同：PST 内 `PidTagClientSubmitTime` 是 UTC 的 FILETIME；USBSTOR `0064/0065` 存的是**本地时间**的 SYSTEMTIME（无时区）。要拿 `ControlSet001\Control\TimeZoneInformation` 换算，否则首连时间会偏整数小时。
- 只读：先把 PST 复制到 `input/` 再 `readpst`/`pffexport` 到 `out/`；hive 用 `reg save` 导出副本，不在原机 `reg query` 当唯一来源（live 键值可被后续写入改掉）。
- 附件单独算 SHA256 并 `file` 二次识别；导出目录按 message id/序号分层，同名附件不覆盖。
- 设备史不能反推“拷走了哪个文件”：USBSTOR/setupapi 只证明连接；拷贝行为要靠 `$UsnJrnl`、ShellBag、LNK（带卷序列号）与文件系统时间线对应。

**判据**：`pst.messages[]` 每条有 `submit_time_utc`/`sender`/`subject`/`attachment_sha256`；`usb.devices[].instance_id`、`usb.first_connect_utc`、`usb.last_connect_utc` 均非空，且 `usb.evidence_sources[]` ≥2。

**失败判据**：`pffinfo` 报加密且无凭据 → `blocked_at: encrypted`，不写“无该邮件”；OST 条目为 0 → 先查 profile/凭据，不写“没有记录”；USBSTOR 无 `0064/0065` → 用 setupapi/PnP 补，仍无就标“无首连时间”；`setupapi.dev.log` 已轮转（只剩尾部）→ 写“日志截断”，不写“未连接”。

## 10. 失败判据

- `mmls`/`fsstat` 两次换工具仍无法识别分区/文件系统 → 停，`blocked_at: parse`。
- `-o` 偏移错误导致“损坏” → 回到 `mmls` 重取，不要写“镜像损坏”。
- 已删文件 `icat` 内容乱码/块被覆盖 → 标“不可恢复”，不引用其内容。
- hive 只读到头、键级遍历为 0 → 检查权限/LOG/副本，写 `blocked_at: permission`。
- EVTX 记录为 0/RecordId 空洞 → 说明日志清除/滚动，不写“没有发生”。
- 时间线缺时区/时钟偏差且无法补齐 → 降级为“候选顺序”，不写因果。

## 11. 边界

- 只读：不挂载可写、不 `chkdsk`、不 `reg load` 原 hive、不在原件上跑程序。
- 不把 `fls` 的“存在”当“内容可恢复”；不把 `strings` 命中当“用户打开过”。
- 不绕过 BitLocker/EFS/账号权限；无密钥就写“加密不可读”，不伪造明文。
- 对外分享前脱敏路径中的用户名、SID、设备序列号、URL 查询参数。

> 相关：`01-criteria.md`、`02-failure-criteria.md`、`memory-forensics.md`、`ios-macos-artifacts.md`、`evidence-chain.md`。
