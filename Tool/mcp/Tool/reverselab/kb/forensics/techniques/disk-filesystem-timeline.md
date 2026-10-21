# 磁盘与文件系统：分区偏移、inode 与时间线

> **入口信号**：`disk.img`/`*.E01`/分区镜像，需要回答“哪个对象、何时、被怎样操作”。
> **不适用**：在原件上挂载/运行/改时间戳；把 `fls` 列表当“内容已恢复”。

## 1. 最小命令

```bash
sha256sum disk.img | tee disk.img.sha256
mmls disk.img
fsstat -o 2048 disk.img
fls -r -p -o 2048 disk.img > out/fls.txt
fls -r -m "/" -o 2048 disk.img > out/bodyfile.txt
mactime -b out/bodyfile.txt -d -z UTC > out/timeline.csv
icat -o 2048 disk.img 12345 > out/recovered.bin
```

NTFS：`icat` 按 MFT 记录号取文件；`$UsnJrnl:$J` 看创建/删除/重命名；`$LogFile` 是事务日志。
Windows 只读查询：`fsutil fsinfo ntfsinfo C:`、`fsutil volume diskfree C:`。

## 2. 确认判据

- `mmls` 的 Start **扇区**与 `fsstat -o` 一致；文件系统类型/块大小/inode 范围可读。
- `fls` 能给出路径、inode、`(deleted)`、MACB；`icat` 内容 magic/哈希可校验。
- inode 复用被识别：同一 inode 多次出现要区分旧残留/新文件。
- 时间线 `mactime -z UTC` 可排序；时区/精度/时钟偏差写清。
- NTFS 两套时间（`$SI`/`$FN`）不一致时并列，不挑“合理”的。

## 3. 失败判据

- `-o` 用字节而非扇区导致“损坏”：回到 `mmls` 重取，不写“镜像损坏”。
- `icat` 内容乱码/块被覆盖：标“不可恢复”，不引用内容。
- `fls` 空但 `fsstat` 正常：权限/加密/过滤；换 `tsk_recover`/Autopsy。
- 时间线跨设备差整数小时：先校时区/NTP，再排因果。
- 原件被挂载写：证据链作废，重采或说明污染范围。

## 4. 边界

- 只读：不 `chkdsk`、不写挂载、不在原件上跑程序。
- 不绕过 BitLocker/EFS；无密钥写“加密不可读”。
- 交付路径/inode/哈希/时间四件套；缺一项降级。
- 相关：`Tool/skill/forensics-mobile/references/disk-and-filesystem.md`、`01-criteria.md`。

## 5. NTFS 两套时间

| 属性 | 位置 | 特点 |
|---|---|---|
| `$STANDARD_INFORMATION` | MFT 记录内 | 用户态可改，常见篡改目标 |
| `$FILE_NAME` | 文件名属性 | 目录项时间，通常较难改 |
| `$UsnJrnl:$J` | USN 日志 | 创建/删除/重命名/写入，可回绕 |
| `$LogFile` | 事务日志 | 崩溃恢复/脏页，需副本 |

两套时间不一致时并列展示，标“可能时间戳篡改”，不要挑“看起来合理”的那个。

## 6. 输出模板

```json
{"time_utc":"2026-10-20T03:14:07Z","actor":"inode 12345 / alice",
 "action":"create/write/rename/delete","object":"/home/alice/a.docx",
 "confidence":"observed","evidence_refs":["disk.img#inode=12345"],
 "command":"fls -r -m '/' -o 2048 disk.img | mactime -b - -d -z UTC"}
```

## 7. 关联检查

- `fls` 路径与 `icat` 内容哈希一致；已删文件标恢复来源。
- 文件系统时间与 EVTX/注册表/浏览器时间线按 UTC 对齐。
- 分区偏移与 `mmls` 一致；多分区分别做。
- 原件未被挂载写；副本哈希与原件一致。
