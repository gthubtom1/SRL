# 输入证据说明（forensics06）

## 来源

- 真实路径：`<WINDIR>/System32/winevt/Logs/Microsoft-Windows-Kernel-Boot%4Operational.evtx`
  - `<WINDIR>` = `C:\Windows`（本案例不记录个人目录/用户名）。
  - `%4` 是 Windows 事件通道名里的转义分隔符，命令行中必须加引号。
- 通道：`Microsoft-Windows-Kernel-Boot/Operational`（启动/固件测量时间线，无用户名）。
- 本机取证副本：`input/Kernel-Boot-Operational.evtx`，大小 69632 B，14 条记录。

## 采集命令（只读复制）

```bash
cd Tool/cases/forensics06
cp "<WINDIR>/System32/winevt/Logs/Microsoft-Windows-Kernel-Boot%4Operational.evtx" \
   input/Kernel-Boot-Operational.evtx
chmod a-w input/Kernel-Boot-Operational.evtx
sha256sum input/Kernel-Boot-Operational.evtx
# 4f45adc7ef74e727007852665e5eef42e526394d8fae80cf61cf6e304f44bfb9
```

采集时间：2026-10-21T23:38:59Z（副本生成时间）；源文件本身未被写入、未被 `wevtutil cl` 清理。
若改用 `wevtutil epl`，命令为
`wevtutil epl "Microsoft-Windows-Kernel-Boot/Operational" input/Kernel-Boot-Operational.evtx`，
但本案例保留的是直接只读 `cp` 的原始 EVTX 字节流。

## 只读与完整性

- 源文件只以读方式打开；复制后 `input/` 副本权限为 `-r--r--r--`（`chmod a-w`）。
- 案例内所有分析只针对副本；`fs-timeline.py` 不挂载、不写回证据。
- 输入哈希已写入 `case.json` 的 `artifacts[]`，门禁会复算。
- `artifacts/check.json` 的 `integrity.readonly=true` 是工具对本副本的只读判定。

## 隐私处理

- 该通道事件不含用户名、SID、登录账号或文件路径；正文只有启动/固件测量状态码。
- EVTX 二进制内可见两个 NetBIOS 主机名标识（`DESKTOP-*`，属于低 PII 的资产标识）。
  它们**未**进入 `artifacts/timeline.json`、`artifacts/events.json` 或本案例结论。
- 对外分享前建议：在副本上用等长占位符把两个主机名替换为 `<HOST1>` / `<HOST2>`，
  然后重新计算并登记哈希；本案例内部保留原始字节用于复现。
- `artifacts/check.json` 里只有工作树绝对路径、大小、mtime 与 SHA256，不含个人目录。
