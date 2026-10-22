# firmware-iot 任务卡（24 张）

> 源技能名取自 `Tool/config/taskcard-sources.json` 的 `firmware-iot`（24 个，全部真实存在）。
> 用法：按触发词选卡 → 照步骤跑 → 用判据/失败判据决定继续或换路线 → 在 reference 里找完整命令。
> 所有卡只在自有或明确授权的固件/设备上执行；默认只读，写操作先备份。

### 01 PLC 固件安全分析（源：performing-plc-firmware-security-analysis）
- 触发词：PLC 固件、梯形图运行时、厂商升级包
- 前置：已获得授权固件与型号；有原始镜像 SHA256；知道恢复方式
- 步骤：1) 记录型号/版本/哈希并跑 fw-triage 判容器；2) 按固件头切出 rootfs/配置区并审计启动脚本与口令；3) 用 qemu 或真机只读验证服务与调试口，输出 J1/J2/J3 证据
- 判据：能定位到运行时服务/配置/账号并有文件:行号；或能起仿真并真实回包
- 失败判据：只解出 kernel/配置碎片、无 rootfs/服务证据：转 02-failure-criteria 的解包/仿真分支
- 剧本：`python Tool/skill/firmware-iot/scripts/fw-triage.py --file fw.bin --json` → rc=0 期望 `containers[].type` 有 strong 类型且 offset 可解释；rc=1 期望 `blocked_at=input`，转 02-failure ①。
- reference：Tool/skill/firmware-iot/references/firmware-unpack.md

### 02 SCADA HMI 固件与 Web 面评估（源：performing-scada-hmi-security-assessment）
- 触发词：HMI 面板、嵌入式 Web、升级接口
- 前置：授权范围含 HMI 自身服务；已备份配置与镜像；测试窗口明确
- 步骤：1) 解包 rootfs，列出 Web 根/CGI/服务运行用户；2) 审计 passwd/shadow/私钥与硬编码凭据；3) 在隔离网络验证登录与 CGI 参数可达性
- 判据：能画出 开机→服务→用户→端口→参数 链路，并有请求/响应证据
- 失败判据：只有静态页面或 CGI 不可达：不算 J2/J3，转黑盒测绘或真机只读
- reference：Tool/skill/firmware-iot/references/filesystem-and-credentials.md

### 03 ICS 资产发现与固件指纹（源：performing-ics-asset-discovery-with-claroty）
- 触发词：工控网络资产、设备指纹、固件版本
- 前置：资产清单与扫描授权；只做被动/低影响指纹；生产写操作按授权单执行
- 步骤：1) 汇总 MAC/OUI/HTTP/SNMP 指纹与固件版本；2) 与厂商固件版本/漏洞库比对；3) 对高风险资产做只读固件确认，记录证据等级
- 判据：资产-型号-固件版本三者可对应，且证据等级标为 E0/E1
- 失败判据：指纹冲突/版本不可信：先记录不确定性，不据此判定漏洞
- reference：Tool/skill/firmware-iot/references/01-criteria.md

### 04 工控防火墙与固件升级通道（源：implementing-ics-firewall-with-tofino）
- 触发词：工控防火墙策略、OTA/升级通道、固件白名单
- 前置：有网络分区图与升级流程；变更有回滚；只读验证规则
- 步骤：1) 梳理设备到升级服务器的端口/协议/签名校验；2) 检查固件包完整性与回滚保护；3) 用抓包验证升级流量是否符合策略
- 判据：升级通道有完整性/签名证据，且策略与实际流量一致
- 失败判据：只有策略文本、无流量/签名证据：标为未验证，不写“已防护”
- reference：Tool/skill/firmware-iot/references/firmware-unpack.md

### 05 Modbus 异常与嵌入式服务（源：detecting-modbus-protocol-anomalies）
- 触发词：Modbus/TCP、嵌入式网关、串口透传
- 前置：授权抓包/仿真环境；知道 PLC 地址与功能码基线
- 步骤：1) 抓取基线流量并统计功能码/地址分布；2) 在仿真或隔离网关注入异常功能码；3) 对比设备响应与日志，确认是否为固件侧异常
- 判据：同一异常输入可重复触发响应差异，且有抓包/日志
- 失败判据：一次性超时或网络抖动：不是固件异常，先排除链路问题
- 剧本：`qemu-system-mipsel -M malta -m 256M -kernel "$OUT/vmlinux" -drive file="$OUT/rootfs.img",format=raw -append "root=/dev/sda console=ttyS0" -nographic` → rc=0 期望串口 login/目标服务监听；rc=124 期望超时无 login，按 ①/②/⑤ 归因。
- reference：Tool/skill/firmware-iot/references/emulation-and-fuzz.md

### 06 Modbus 命令注入与参数拼接（源：detecting-modbus-command-injection-attacks）
- 触发词：Modbus 网关、寄存器到 shell/CLI 的映射
- 前置：有授权测试窗口；知道哪个寄存器可能进入命令拼接；有回滚
- 步骤：1) 在固件中定位寄存器处理到 system/popen 的调用链；2) 构造最小寄存器值并在隔离环境发送；3) 检查命令输出/副作用是否可重复
- 判据：可控寄存器值到达危险函数，且有可重复输出或副作用
- 失败判据：只看到字符串/表单，参数被白名单限制：不算 J3，转黑盒测绘
- reference：Tool/skill/firmware-iot/references/01-criteria.md

### 07 S7comm 协议与固件服务（源：performing-s7comm-protocol-security-analysis）
- 触发词：S7comm、PLC 固件、调试服务
- 前置：授权访问 PLC/仿真；已备份项目；不写生产寄存器
- 步骤：1) 识别 CPU 型号/固件版本与开放服务；2) 在仿真中复现读写/诊断请求；3) 对照固件内服务实现与访问控制
- 判据：服务响应与固件实现一致，且有版本/配置证据
- 失败判据：只能读到版本、无服务实现证据：停在 E0/E1
- 剧本：`nc -vz 127.0.0.1 102` → rc=0 期望 102 端口开放并能发 S7 基线请求；rc=1 期望服务未起，按 ②/⑤ 归因，不写服务实现结论。
- reference：Tool/skill/firmware-iot/references/emulation-and-fuzz.md

### 08 DNP3 异常与固件日志（源：detecting-dnp3-protocol-anomalies）
- 触发词：DNP3、RTU/网关固件、事件日志
- 前置：授权抓包与只读日志访问；有基线
- 步骤：1) 建立正常轮询/事件基线；2) 注入越界对象/异常帧并观察设备；3) 关联固件日志与串口输出
- 判据：异常帧导致可重复的日志/响应差异，且排除网络因素
- 失败判据：只有丢包/超时：先查链路与负载，不归因固件
- reference：Tool/skill/firmware-iot/references/01-criteria.md

### 09 SCADA 攻击检测与固件证据（源：detecting-attacks-on-scada-systems）
- 触发词：SCADA 告警、主机/网络日志、设备固件版本
- 前置：有日志读取授权；知道资产基线；不触发生产动作
- 步骤：1) 关联告警与资产/固件版本；2) 用只读命令确认设备侧异常；3) 形成“告警→设备证据→影响”的最小链条
- 判据：告警与设备侧证据能对应，且有命令/日志时间戳
- 失败判据：只有告警、设备侧无证据：标为疑似，不写确认攻击
- reference：Tool/skill/firmware-iot/references/02-failure-criteria.md

### 10 binwalk 固件提取与目录树验证（源：performing-firmware-extraction-with-binwalk）
- 触发词：binwalk、固件镜像、SquashFS/UBI
- 前置：原始镜像只读；有 SHA256；知道目标架构
- 步骤：1) `python Tool/scripts/fw-triage.py --file Tool/cases/firmware-iot03/input/43341b0rtecdc.bin --json` → rc=0，期望：containers 含 `"type": "jffs2"`（offset 291825）与 `"type": "bzip2"`；2) `python Tool/skill/firmware-iot/scripts/fw-repro.py --file Tool/cases/firmware-iot05/input/ota-fixture.zip --out-dir work/fw10 --json` → rc=0，期望：`"primary": "zip"`、`"extraction": {"status": "extracted"`、`"rootfs": {"files": 8`；3) `python Tool/skill/firmware-iot/scripts/fw-accept.py --root . --json` → rc=0，期望：`"ok": true`、`"cases": 5`、`"real": 2`
- 判据：目录树完整且 busybox/init 架构与 SoC 一致
- 失败判据：只有签名/碎片、无目录树：转 sasquatch/ubireader 或厂商头路线
- 剧本：`unsquashfs -d "$ROOT" -f part.bin` → rc=0 期望 `/etc`+`/bin`+`/lib` 齐全且 `file bin/busybox` 架构自洽；rc=1 期望 `unsupported compression`，转 02-failure ① 与 sasquatch。
- reference：Tool/skill/firmware-iot/references/firmware-unpack.md

### 11 固件恶意代码与持久化排查（源：performing-firmware-malware-analysis）
- 触发词：固件 rootfs、启动脚本、Web/CGI、二进制
- 前置：已备份镜像；隔离环境；不运行可疑样本于生产网
- 步骤：1) `python Tool/skill/firmware-iot/scripts/fw-repro.py --file Tool/cases/firmware-iot05/input/ota-fixture.zip --out-dir work/fw11 --json` → rc=0，期望：rootfs.findings 含 `"kind": "telnetd"` 与 `"kind": "cgi-system"`；2) `python Tool/skill/firmware-iot/scripts/fw-repro.py --self-test` → rc=0，期望：`{"ok": true, "checks": 14}`；3) `python Tool/skill/firmware-iot/scripts/fw-accept.py --root . --json` → rc=0，期望：`"ok": true`
- 判据：能定位持久化点与外联目标，且有文件:行号/网络证据
- 失败判据：只有可疑字符串、无执行/外联证据：标为候选，不写“已植入”
- reference：Tool/skill/firmware-iot/references/emulation-and-fuzz.md

### 12 chipsec 审计 UEFI 固件（源：auditing-uefi-firmware-with-chipsec）
- 触发词：SPI dump、UEFI 变量、chipsec
- 前置：授权主机/设备；已备份变量与 flash；chipsec 版本确认
- 步骤：1) `python Tool/scripts/fw-triage.py --file Tool/cases/firmware-iot04/input/SecConfig.efi --json` → rc=0，期望：containers[0] 为 `"type": "pe"`（offset 0，confidence high）；2) `python Tool/skill/firmware-iot/scripts/fw-repro.py --file Tool/cases/firmware-iot04/input/SecConfig.efi --out-dir work/fw12 --json` → rc=0，期望：`"primary": "pe"`、`"extraction.status": "not-applicable"`、verdict 含 `UEFI boot component`；3) `python Tool/scripts/fw-triage.py --self-test` → rc=0，期望：`{"ok": true, "checks": 7}`
- 判据：FV 可解析且变量/签名链证据自洽
- 失败判据：变量读不到/FV 解析失败：确认权限/驱动/截断，缺工具记 blocked_at
- reference：Tool/skill/firmware-iot/references/05-uefi-and-secure-boot.md

### 13 Secure Boot 绕过检测（授权）（源：detecting-secure-boot-bypass）
- 触发词：Secure Boot 策略、dbx、shim/MOK、启动日志
- 前置：明确授权的自有设备；只读优先；设备清单由用户提供，步骤按清单执行
- 步骤：1) 读取 SecureBoot/SetupMode/db/dbx；2) 核对目标 PE 哈希与签名链；3) 检查 shim/MOK 与启动日志是否一致
- 判据：能指出策略缺口与对应证据（变量/哈希/日志）
- 失败判据：只有版本猜测或单 PE：不算绕过结论，转 04-walkthrough 静态路线
- reference：Tool/skill/firmware-iot/references/05-uefi-and-secure-boot.md

### 14 TPM 度量启动验证（源：validating-tpm-measured-boot-attestation）
- 触发词：TPM 2.0、event log、PCR
- 前置：授权主机；TPM 已启用；有基线 PCR/日志
- 步骤：1) 导出 event log 与 PCR；2) 重放哈希链并比对 PCR；3) 关联启动组件哈希与固件版本
- 判据：event log 可重放到当前 PCR，关键组件哈希一致
- 失败判据：TPM 未启用/日志清空/重放失败：先修环境，不写“度量通过”
- reference：Tool/skill/firmware-iot/references/05-uefi-and-secure-boot.md

### 15 HSM/安全芯片与固件密钥（源：performing-hardware-security-module-integration）
- 触发词：HSM、secure element、固件密钥槽、证书
- 前置：授权访问密钥管理接口；不导出私钥；有审计日志
- 步骤：1) 确认密钥生成/存储/使用路径与权限；2) 检查固件是否硬编码密钥或绕过 HSM；3) 用只读接口验证证书链与用途
- 判据：密钥不出 HSM 且固件调用路径可证据化
- 失败判据：只能看到证书/占位符：不写“私钥泄露”，转 01-criteria 的凭据判据
- reference：Tool/skill/firmware-iot/references/filesystem-and-credentials.md

### 16 硬件安全密钥认证与固件（源：implementing-hardware-security-key-authentication）
- 触发词：FIDO/安全密钥、USB、固件认证
- 前置：授权设备；知道接口与协议；不破坏密钥
- 步骤：1) 枚举 USB/CCID/HID 接口与固件版本；2) 验证认证流程与固件侧校验；3) 记录失败/回滚行为
- 判据：认证流程可重复，固件侧校验有日志/协议证据
- 失败判据：只识别到设备、无认证流程证据：停在 E0
- reference：Tool/skill/firmware-iot/references/hardware-interfaces.md

### 17 IoT 设备安全评估（固件优先）（源：performing-iot-security-assessment）
- 触发词：摄像头/路由器/智能家居固件与服务
- 前置：授权设备与网络；已备份固件；测试窗口明确
- 步骤：1) `python Tool/skill/firmware-iot/scripts/fw-accept.py --root . --json` → rc=0，期望：`"ok": true`、`"cases": 5`、`"real": 2`；2) `python Tool/skill/firmware-iot/scripts/fw-repro.py --file Tool/cases/firmware-iot05/input/ota-fixture.zip --out-dir work/fw17 --json` → rc=0，期望：`"rootfs.files": 8` 且 verdict 仍提示 J1/J2 未达成；3) `python Tool/scripts/fw-triage.py --self-test` → rc=0，期望：`"checks": 7`
- 判据：至少一条 J1/J2/J3 有证据，且标明等级
- 失败判据：只有端口扫描/版本号：不算评估完成，转固件静态与仿真
- 剧本：`python Tool/skill/firmware-iot/scripts/fw-accept.py --root . --json` → rc=0 期望 5 个案例字段/hash/refs 全过；rc=1 期望列出不符案例，先修证据再写 J1/J2/J3。
- reference：Tool/skill/firmware-iot/references/01-criteria.md

### 18 蓝牙固件与协议评估（源：performing-bluetooth-security-assessment）
- 触发词：BT/BLE 控制器固件、HCI、配对流程
- 前置：授权设备；有蓝牙适配器；不干扰他人设备
- 步骤：1) 记录控制器型号/固件版本与 HCI 能力；2) 抓取配对/连接流程；3) 核对固件侧配对/密钥存储与异常行为
- 判据：配对流程与固件版本可复现，异常有抓包证据
- 失败判据：只有广播/型号：不写漏洞，转 01-criteria 的 E0/E1
- reference：Tool/skill/firmware-iot/references/hardware-interfaces.md

### 19 BLE 攻击检测与固件响应（源：detecting-bluetooth-low-energy-attacks）
- 触发词：BLE、GATT、固件日志
- 前置：授权测试；隔离射频环境；有基线
- 步骤：1) 建立 GATT/连接基线；2) 注入异常包并观察设备日志/复位；3) 关联固件版本与崩溃/重连行为
- 判据：异常包导致可重复的固件侧响应/日志
- 失败判据：一次性断连：先排除干扰/距离，不归因固件
- reference：Tool/skill/firmware-iot/references/hardware-interfaces.md

### 20 无线评估与 Kismet 取证（源：performing-wireless-security-assessment-with-kismet）
- 触发词：Wi-Fi、Kismet、设备固件/射频
- 前置：授权频谱与设备；不采集他人流量；遵守当地法规
- 步骤：1) 记录 AP/客户端与设备固件指纹；2) 被动抓包并保存证据；3) 对自有设备做只读配置/固件核对
- 判据：证据可复现且来源合法，固件版本与配置一致
- 失败判据：只有抓包、无设备侧证据：标为观察，不写设备漏洞
- reference：Tool/skill/firmware-iot/references/hardware-interfaces.md

### 21 Wi-Fi 口令与固件默认凭据（授权）（源：performing-wifi-password-cracking-with-aircrack）
- 触发词：WPA/WPA2、默认 PSK、固件配置
- 前置：仅自有/书面授权网络；有抓包合法性说明；不攻击他人
- 步骤：1) 从固件/NVRAM 提取默认 PSK 候选（脱敏）；2) 在授权抓包上做离线校验；3) 记录是否可登录及影响
- 判据：口令可验证且能完成一次授权连接；否则只算候选
- 失败判据：只有 hash/抓包、无登录验证：不写“已破解”
- reference：Tool/skill/firmware-iot/references/04-walkthrough-uefi-efi.md

### 22 无线网络渗透测试与固件面（源：performing-wireless-network-penetration-test）
- 触发词：无线网络、AP 固件、管理面
- 前置：授权范围含 AP 管理面；有回滚；不影响他人
- 步骤：1) 测绘 AP/固件版本/管理服务；2) 审计默认凭据与固件配置；3) 对管理面做低影响验证并记录证据
- 判据：管理面访问或配置缺陷可重复，且有请求/响应
- 失败判据：只能连接、无管理面证据：停在 E1，不写提权
- reference：Tool/skill/firmware-iot/references/01-criteria.md

### 23 USB 设备控制策略与固件（源：implementing-usb-device-control-policy）
- 触发词：USB 设备、固件描述符、主机策略
- 前置：授权主机；有设备白名单；不绕过他人策略
- 步骤：1) 枚举 VID/PID/描述符与固件版本；2) 核对主机策略与设备类；3) 测试允许/拒绝路径并记录日志
- 判据：策略与实测一致，允许/拒绝都有日志
- 失败判据：只看到设备描述符：不写策略失效，需实测
- reference：Tool/skill/firmware-iot/references/hardware-interfaces.md

### 24 OT 流量分析与固件版本关联（源：implementing-ot-network-traffic-analysis-with-nozomi）
- 触发词：OT 流量、资产指纹、固件版本
- 前置：授权镜像/探针；只读流量；有资产基线
- 步骤：1) `python Tool/scripts/fw-triage.py --file Tool/cases/firmware-iot03/input/43341b0rtecdc.bin --json` → rc=0，期望：sha256=`3dc1138c...3455a3f`、containers 含 `jffs2`/`bzip2`；2) `python Tool/skill/firmware-iot/scripts/fw-repro.py --file Tool/cases/firmware-iot03/input/43341b0rtecdc.bin --out-dir work/fw24 --json` → rc=0，期望：`"primary": "brcm"`、verdict 含 `vendor firmware blob`；3) `python Tool/skill/firmware-iot/scripts/fw-accept.py --root . --json` → rc=0，期望：`"ok": true`
- 判据：资产-协议-固件版本可对应，差异有证据
- 失败判据：指纹模糊/版本冲突：记录不确定性，不据此定性漏洞
- reference：Tool/skill/firmware-iot/references/01-criteria.md
