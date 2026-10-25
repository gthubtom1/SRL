# 02 失败判据表：现象 → 判定 → 改走哪条 → 代价

> 配套 `firmware-iot/SKILL.md`、`references/01-criteria.md`。
> **范围**：固件获取、解包、凭据、仿真、硬件接入的失败分流。
> 边界：降级 = 换路线；每条都给出替代路线和代价。

原则：**同一手法连续 2 次失败（同工具同参数、同接口同目标）就换路线**，
不许无限重试、不许在真机上反复写、不许把失败包装成“部分成功”。

| 现象 | 判定 | 改走哪条 | 代价 |
|---|---|---|---|
| `binwalk -e` 只切出 kernel/DTB/碎片，没有 `/etc`+`/bin`+`/lib` | 解包未完成，当前偏移或容器判断错 | 先按厂商头字段算真实负载偏移（长度/CRC/型号），再换 `ubireader`/`sasquatch`/`jefferson`/`7z`；用 `fw-repro.py` 看 strong/weak 分层 | 多花 0.5–2 h；可能仍拿不到 rootfs |
| `unsquashfs` 报 `unsupported compression` / `bad magic` | 可能是厂商魔改 SquashFS，不是镜像坏 | 换 `sasquatch`；再不行查内核源码里的解压器/厂商头；必要时只做 strings+熵分析 | 需要找内核/工具链；魔改严重时无法解包 |
| UBI 报 `bad magic` 或卷列表为空 | 偏移错、缺 OOB/ECC、或 dump 被截断 | 用 `ubireader_display_info` 找 `UBI#`；`nanddump -o` 保留 OOB；核对 PEB 大小与页大小 | 需要重新 dump；无 OOB 时可能永久缺文件 |
| JFFS2 命中很多 `0x1985` 但 `jefferson` 解出空树 | 弱签名误报或坏节点比例过高 | 用节点 CRC/长度复核；只保留连续节点区；放弃该区改走整片扫描 | 误报区浪费时间；坏块多时只能部分恢复 |
| 全盘高熵、无任何 strong 魔术 | 加密、厂商容器或纯压缩流，暂不可静态解 | 找厂商头/解密点/U-Boot 解密命令；转 UART/JTAG 在线读或内存 dump；仅记录熵与字符串 | 需要硬件与授权；可能无法离线解 |
| 只有 hash，字典/规则不中，或 hash 是 `$1$`/厂商自定义 | 凭据未破解，不能写“弱口令” | 记录为素材；转登录入口探测/接口绕过/串口 shell；有授权再做定向破解 | 破解成本不可控；无登录入口时价值有限 |
| `passwd` 有 `x`、shadow 有 `!`/`*` | 账号被锁定或未设置可用口令 | 不要判空口令；查 `/etc/shadow-`、NVRAM 默认值、厂商云账号、SSH authorized_keys | 可能确实无可用账号，需转服务漏洞 |
| 私钥/证书无法配对，或只有公钥/CA | 不是设备身份私钥 | 只记录证书用途与指纹；继续找 `.p12/.pfx`、NVRAM key、TPM/secure element 引用 | 误判会浪费验证时间；伪造结论风险高 |
| qemu-user 报 `No such file or directory`（脚本明明存在） | 动态加载器/库缺失或解释器路径错 | `readelf -l/-d` 看 interpreter；补 `lib/`、用 `-L`、换 static qemu、`proot` | 需要匹配厂商 libc；可能只能跑单程序 |
| qemu-system 内核 panic / `Unable to mount root` | 架构、`root=`、驱动或 initramfs 错 | 核对字节序/架构 → 换机器类型 → 补 initramfs → 换 FirmAE/Firmadyne → 真机 chroot | 每轮 10–60 min；可能始终起不来 |
| FirmAE 报 success，但 `curl` 只有静态页/502 | 不是 J2；环境桩缺失或 hostfwd 错 | 查 `qemu.*.log`、DocumentRoot、CGI 权限、NVRAM；补桩后重试；仍不行转真机只读 | 需要读日志和改桩；可能只是“能启动” |
| 服务进程在、端口不通或启动即退出 | 配置/权限/依赖缺失，或看门狗杀进程 | 读服务 stderr；补 `/dev`、`/proc`、时区、随机数；副本上禁用看门狗 | 需要反复试桩；真机调试有变砖风险 |
| UART 无输出或只有乱码 | 电压/共地/TX-RX/波特率错，或控制台被关 | 先量电压与共地 → 交换 TX/RX → 依次试 115200/57600/38400/9600 → 逻辑分析仪测位宽 | 接线错误可能烧 SoC；需重新焊接/换板 |
| JTAG 扫不到 IDCODE | 引脚定义错、电平不匹配、TAP 被关 | 核对 TCK/TMS/TDI/TDO/GND/VREF；换适配器/降速；查 SoC datasheet 的 debug 使能 | 可能永久锁死；需要专业工具 |
| SPI 两次读取 SHA256 不一致 | 接触不良、供电不稳、芯片在读时被访问 | 断电夹紧/焊下芯片；降低 `flashrom` 速率；确认 1.8V 适配；再读两次比对 | 可能读坏或写坏；必须先有备份 |
| 改 rootfs 后设备拒升级/校验失败 | OTA 签名或版本回滚保护 | 不要伪造签名；转 UART/JTAG 在线改启动参数、内存 patch 或运行态调试 | 无法持久化；越权风险高 |
| 漏洞只在字符串/版本号里出现 | 不是 J3；可达性未证 | 转黑盒请求测绘、动态跟踪、最小 PoC；两次一致才算 | 可能需要逆向与仿真环境；时间成本高 |
| 内核挂根但 rootfs 只有 kernel/部分分区，缺 `/bin/busybox` 或 `/etc` | `rootfs_complete=false`，解包未完成 | 重切分区/合并 overlay，换 `sasquatch`/`ubireader`；从 OTA 或真机 dump 补缺失分区 | 0.5–2 h；分区缺失且无备份时只能半仿真 |
| 串口停在 init 输出，`/etc/init.d` 依赖的二进制/脚本不存在 | `init_chain_ok=false`，启动链断 | `grep -RIn` 依赖并跨分区补齐；副本用最小 init 直接起目标服务，保留原链记录 | 依赖在未解出分区且无替代实现时转 qemu-user 单程序 |
| 服务运行 30–90 s 后整机复位/端口消失 | 看门狗复位，`watchdog_mitigated=false` | 副本禁用 `wdt` 启动项、`/dev/watchdog` 桩、必要时喂狗；串口确认复位源 | 看门狗在 bootloader/硬件层时只做短窗口验证 |

## 失败后的最小交付

即使全线失败，也要留下：

1. 镜像 SHA256、大小、来源命令/URL；
2. 已试命令与 rc、stderr 关键行（不要只写“失败”）；
3. 已确认的 strong 魔术/偏移与 weak 误报清单；
4. 卡点分类：`input` / `tool-missing` / `container-unsupported` / `emulation` / `hardware` / `authorization`；
5. 下一条路线的前置条件（需要什么工具、什么授权、什么硬件）。

## 边界

- 失败判据是**分流器**，不是“此路永久不通”；换环境/换版本后可以重试，但要记录为什么这次可能不同。
- 缺工具时给出 `blocked_at "tool-missing"` 与替代链，让“没跑”在产物里可见。
- 真机写操作、破解、OTA 伪造只在单独授权下进行；默认只读。

## 失败后的 30 分钟决策树

```text
解包失败?
├─ 有 strong 魔术但解不出 → 算厂商头偏移 → 换 sasquatch/ubireader/jefferson
├─ 只有 weak 魔术 → 用 fw-repro 分层 → 找厂商头/strong 标签
├─ 高熵无魔术 → 查厂商头/解密点 → 转 UART/JTAG/内存 dump
└─ 工具缺失 → 写 blocked_at=tool-missing → 走替代链或换主机

仿真失败?
├─ Exec format error → 核对 readelf 架构/端序
├─ 挂根失败/panic → 核对 root=/initramfs/驱动 → 换 FirmAE/真机
├─ 服务启动即退 → 补 NVRAM//dev/proc/时区/随机数；副本禁用看门狗
└─ 端口通但 502/静态页 → 查 DocumentRoot/CGI 权限/hostfwd

凭据失败?
├─ 只有 hash → 记录素材；找登录入口/接口绕过/串口
├─ x/!/* → 不是空口令/已锁定 → 找 NVRAM/云账号/authorized_keys
└─ 私钥不配对 → 记录证书用途/指纹 → 找 p12/NVRAM/secure element
```

## 三个典型失败片段（可照抄到报告）

### 片段 A：只切出 kernel

```text
$ binwalk -e fw.bin
DECIMAL  HEXADECIMAL  DESCRIPTION
0        0x0          uImage header
...
$ find _fw.bin.extracted -maxdepth 2 -type d
_fw.bin.extracted
```

判定：只有 uImage/kernel，没有 `/etc`+`/bin`+`/lib` → **解包未完成**。
改走：按 uImage `ih_size` 切负载，找 rootfs（SquashFS/UBI）偏移；不要在这棵树上做账号审计。

### 片段 B：仿真端口通但静态页

```text
$ curl -i http://127.0.0.1:80/
HTTP/1.1 200 OK
Content-Type: text/html
<html><body>It works!</body></html>
```

判定：只有默认占位页，没有设备业务字段 → **不是 J2**。
改走：查 FirmAE/QEMU 的 `hostfwd`、DocumentRoot、CGI 权限与 NVRAM；或转真机只读验证。

### 片段 C：弱签名误报

```text
$ python Tool/skill/firmware-iot/scripts/fw-triage.py --file fw.bin --json
"containers": [{"type": "jffs2", "offset": 291825, "confidence": "medium"}]
$ python Tool/skill/firmware-iot/scripts/fw-repro.py --file fw.bin --json
"primary": "brcm", "brcm": {"tag_offsets": [252828, ...]}
```

判定：`0x1985` 是 weak 命中，不能定主格式 → **不是 JFFS2 分区**。
改走：按 strong 厂商标签/长度表解释结构；把误报偏移和失败原因写进证据。

## 失败记录模板

```json
{
  "stage": "unpack",
  "blocked_at": "container-unsupported",
  "tried": [{"cmd": "unsquashfs -d rootfs -f part.bin", "rc": 1,
             "stderr": "Unsupported compression"}],
  "evidence": {"sha256": "<64 hex>", "offset": "0x...", "type": "squashfs"},
  "next": {"route": "sasquatch or kernel decompressor",
           "needs": ["vendor kernel source", "sasquatch"]}
}
```

这个模板可以直接喂给 `fw-accept.py` 的 JSON 产物检查（`blocked_at` 存在即视为结构化降级），
也方便下一个人接着跑。

## 失败归因五问：把“又失败了”变成可交接的字段

> 失败不是一句话，而是一组字段。五问里任何一问答不上来，就只能写“未归因”，不能写“固件坏了”。

| # | 问题 | 字段 | 通过标准 |
| :-: | --- | --- | --- |
| 1 | 卡在哪一层？ | `stage` | `acquire/container/fs/audit/emulate/hardware` 之一 |
| 2 | 是输入、工具还是环境？ | `blocked_at` | `input/tool-missing/container-unsupported/emulation/hardware/authorization` |
| 3 | 已排除了什么？ | `tried[]` | 每条有 `cmd`、`rc`、`stderr` 关键行 |
| 4 | 换哪条路、代价多大？ | `next.route` / `next.cost` | 具体工具/接口 + 时间/硬件/授权 |
| 5 | 什么条件下可以重试？ | `retry_when` | 新版本/新样本/新授权/新硬件 |

五问填完的产物（可直接被 `fw-accept.py` 消费）：

```json
{
  "stage": "fs",
  "blocked_at": "container-unsupported",
  "tried": [
    {"cmd": "unsquashfs -s part.bin", "rc": 1,
     "stderr": "Unsupported compression: 0x8f"},
    {"cmd": "sasquatch -d out part.bin", "rc": 1,
     "stderr": "unknown squashfs version 4.0 vendor 0x8f"}
  ],
  "evidence": {"sha256": "<64 hex>", "offset": "0x120000", "magic": "hsqs"},
  "next": {"route": "kernel decompressor or vendor sdk",
           "cost": "2-4h + vendor kernel source"},
  "retry_when": "拿到同型号更新的 OTA 或内核解压器"
}
```

### 归因时的三条硬规则

1. **一个主值**：`blocked_at` 只允许一个主值，其余放 `secondary[]`；多个主值等于没归因。
2. **工具缺失不等于目标不存在**：缺 `unsquashfs` 时写 `tool-missing`，不能写“没有文件系统”。
3. **环境失败不等于固件失败**：QEMU 起不来只说明“当前环境起不来”，除非换主机/换工具后同样失败。

## 失败代价与时窗：什么时候必须停

| 路线 | 单次成本 | 止损时窗 | 到点动作 |
| --- | --- | --- | --- |
| 换容器工具（`unsquashfs`→`sasquatch`→`ubireader`） | 10–30 min | 2 次 / 1 h | 记录偏移与错误，转静态/硬件 |
| 换 QEMU 机器类型/内核参数 | 20–60 min | 3 次 / 2 h | 转 FirmAE 或真机只读 |
| 补 NVRAM/`/dev` 桩 | 20–40 min/轮 | 2 轮 / 1.5 h | 只验证单服务，不再追整机 |
| 字典/规则破解 | 不可控 | 授权时窗 | 到点停，保留 hash 与已试字典名 |
| UART 接线/波特率 | 10–20 min | 4 档波特率 / 1 h | 量电压、换 RX/TX、逻辑分析仪 |
| SPI 重复读取 | 5–15 min/次 | 2 次不一致 | 停写，先解决接触/供电 |
| 漏洞 PoC 调参 | 不可控 | 同一手法 2 次 | 换入口或放弃该 CVE |

> 时窗的意义不是“省时间”，而是防止**把环境问题写成固件结论**。每次重试前先问：这次多了什么新证据？没有新证据的重试就是原地打转。

## 经验回流（lessons）：失败如何变成下一条判据

> 这一节就是本域的 `lessons`。每条必须是“可复用的判断”，不是“我试了很久”。

### L1：`unsquashfs` 的 rc=0 不能证明 rootfs 完整

- 现场：镜像被截断，`unsquashfs` 仍建出 `squashfs-root/etc`，但 `bin/` 为空。
- 旧判据：rc=0 → 解包成功。
- 新判据：`/etc` + `/bin`（或 `/usr/bin`）+ `/lib` 三门同时存在，且 `bin/busybox` 能被 `file` 识别为 ELF。
- 落点：`01-criteria.md` 判据表第 3 行；`03-model-pitfalls.md` 第 13 条。

### L2：FirmAE 的 `success` 是“起机成功”，不是“服务可用”

- 现场：FirmAE 打印 success，`curl` 只有 `It works!` 默认页。
- 旧判据：仿真 success → J2。
- 新判据：端口 + 进程 + 动态业务字段三件套，缺一不算 J2。
- 落点：`02-failure-criteria.md` 片段 B；`emulation-and-fuzz.md` §5。

### L3：NVRAM 缺失会让“服务启动即退出”看起来像固件损坏

- 现场：`httpd` 读 `nvram_get("http_username")` 返回空后 `exit(1)`。
- 旧判断：固件里的服务是坏的。
- 新判断：先补 `nvram.conf` 最小键，读服务 stderr，再判定。
- 落点：`emulation-and-fuzz.md` §4；`03-model-pitfalls.md` 第 9 条。

### L4：UART 乱码九成是电气问题，不是“没有控制台”

- 现场：115200 全是乱码，换 57600 后可读。
- 旧动作：换板子。
- 新动作：量 GND/VCC → 共地 → 交换 TX/RX → 四档波特率 → 逻辑分析仪测位宽。
- 落点：`hardware-interfaces.md` §2；`03-model-pitfalls.md` 第 10 条。

### L5：weak 魔术会把你带到完全错误的解包路线

- 现场：Broadcom blob 里的 `bzip2` 命中，`bz2` 解压报 `Invalid data stream`。
- 旧动作：继续换 bzip2 参数。
- 新动作：先看 `fw-repro` 的 `primary` 与厂商标签，再决定是否切；weak 命中只记录为误报证据。
- 落点：`06-container-carving-and-entropy.md` §4；`04-walkthrough-uefi-efi.md` §3。

### L6：失败记录不写 `rc`，下一个人就无法判断“是工具没跑还是跑失败”

- 现场：交接单只写“unsquashfs 不行”。
- 新要求：每条 `tried[]` 必须有 `cmd`、`rc`、`stderr` 前 200 字符。
- 落点：本文“失败记录模板”；`fw-accept.py` 的结构化检查。

## 失败也得能机检：把日志压成字段

```bash
CASE=work/fw-audit
# 1) 收集本次所有失败命令（假设你用了 script/tee 记录）
grep -nE 'rc=[1-9]|error|Error|failed|cannot|unsupported' "$CASE/cmd.log" | head -40

# 2) 生成最小失败记录（字段名与模板一致）
python - <<'PY'
import json, re, pathlib
log = pathlib.Path("work/fw-audit/cmd.log").read_text(errors="replace").splitlines()
tried = []
for line in log:
    m = re.search(r"\$ (.+)$", line)
    if m:
        tried.append({"cmd": m.group(1), "rc": None, "stderr": ""})
print(json.dumps({"stage": "unpack", "blocked_at": "tool-missing",
                  "tried": tried[-5:], "next": {"route": "sasquatch"}},
                 ensure_ascii=False, indent=2))
PY

# 3) 确认报告里没有“裸失败”
grep -nE '失败|failed|不能|无法' "$CASE/report.md" | grep -vE 'blocked_at|rc=|改走|代价' || true
```

**通过长什么样**：

| 检查 | 通过 | 不通过 |
| --- | --- | --- |
| 归因 | 有且仅有一个 `blocked_at` 主值 | 多个主值/空值 |
| 证据 | 每条 `tried[]` 有 `cmd` + `rc` + `stderr` | 只有“试过了” |
| 下一步 | 有具体工具/接口 + 代价 | “再研究一下” |
| 重试条件 | 写明新样本/新授权/新硬件 | 无条件重试 |
| lessons | 至少一条能改变判据 | 只有情绪描述 |

## 这一篇算"用对了"吗

- [ ] 我能用五问把一个失败说成字段，而不是一句“解包失败”
- [ ] 我的 `tried[]` 每条都有命令、rc 与 stderr 关键行
- [ ] 我给每条路线设了止损时窗，到点就换面而不是原地加参数
- [ ] 我至少沉淀了一条 lessons，并指回它改变了哪条判据
- [ ] 我没有把 `tool-missing` 写成“目标不存在”，也没有把环境失败写成固件失败
- [ ] 交接单里写明了重试条件与代价，下一个人不用重新猜
