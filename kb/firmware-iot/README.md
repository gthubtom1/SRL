# firmware-iot KB board

> 面向 `firmware-iot` 域的实战知识看板。回答“下一步先做什么、什么算成功、什么时候该停”。
> 命令细节在 `Tool/skill/firmware-iot/references/`，判据矩阵在 `Tool/config/firmware-iot-matrix.json`。

## 九件套导航

| 件 | 位置 | 用途 |
|---|---|---|
| 技能 | `Tool/skill/firmware-iot/SKILL.md` | 判据/失败判据/边界/验收 |
| 参考 1-2 | `references/firmware-unpack.md`、`hardware-interfaces.md` | 解包/硬件接入 |
| 参考 3-4 | `references/filesystem-and-credentials.md`、`emulation-and-fuzz.md` | 凭据/启动链、仿真/fuzz |
| 脚本 | `Tool/scripts/fw-triage.py` | 魔术/熵/凭据线索/提取命令 |
| 矩阵 | `Tool/config/firmware-iot-matrix.json` | 14 类判据与误报 |
| 案例 | `Tool/cases/firmware-iot01/`、`firmware-iot02/` | SquashFS/J1、UBI/J2 计划案例 |
| 路由 | R22（`routing-fragments/firmware-iot.json`） | 固件/IoT/硬件 |

## 1. 先看哪一篇

| 你手里的东西 | 先读 | 目标 |
|---|---|---|
| 一个未知固件包，不知道里面是什么 | `container-triage.md` | 识别容器/熵/偏移，决定解包路线 |
| 已解出 rootfs，要查账号/密钥/启动链 | `credentials-and-boot-chain.md` | 把线索定位到文件:行号，形成服务链 |
| 解包成功但服务起不来 | 本页“仿真失败” + `emulation-and-fuzz.md` | 区分假成功与真失败 |
| 需要硬件接入 | `hardware-interfaces.md` | 先量电压、再 UART/JTAG/SPI |

## 2. 三步决策

1. **是不是固件？** 有 SquashFS/UBI/JFFS2/CramFS/tar/gzip/zstd 等魔术 → 解包；只有 ELF/PE/DTB → 走二进制/DTB 路线。
2. **能不能拿到 rootfs？** 能列出 `/etc`、`/bin`、`/lib` → 继续审计；只有内核/单文件 → 仍是侦察，不算解包完成。
3. **有没有闭环证据？** J1 shell / J2 真实服务 / J3 可复现漏洞，至少一条；否则只写“未验证”。

## 3. 硬判据（与 SKILL.md 一致）

| 判据 | 可接受证据 | 不接受 |
|---|---|---|
| J1 能进 shell | UART 日志、SSH/telnet 会话、QEMU 串口提示符 | 只看到 U-Boot 横幅、登录框无凭据 |
| J2 能跑关键服务 | 进程 + 监听端口 + 真实业务回包 | 进程活着、端口不通、只有静态页 |
| J3 能复现漏洞 | 可重复请求/PoC、前后对比、日志/崩溃 | 仅字符串猜测、只在仿真里“可能” |

## 4. 常见假成功

- `binwalk -e` 退出码 0，但只切出内核/DTB。
- `unsquashfs` 解出空 `squashfs-root`，缺 `/etc`。
- QEMU 进程存在，但 Web 端口没有业务响应。
- FirmAE 报“网络成功”，但登录页是静态占位。
- JFFS2 大量坏节点被当成“加密”，其实是 OOB/端序问题。

## 5. 仿真失败时先查什么

1. 架构/端序是否与 `readelf -h` 一致；
2. `root=`、`console=`、init 路径是否正确；
3. `/dev/mtd`、`/dev/urandom`、NVRAM 是否缺失；
4. 看门狗是否在几十秒后复位；
5. Web 根/CGI 路径/执行权限是否配置正确。

## 6. 工具降级

| 缺失 | 替代 |
|---|---|
| `binwalk` | `fw-triage.py` 找偏移 + `dd` 切分；`7z` 先看容器；`unsquashfs/ubireader/jefferson` 按类型解 |
| `unsquashfs` | `sasquatch`、`7z x`、从内核确认压缩算法 |
| `ubireader` | `pip install --user ubi_reader`（需批准）；或真机/内核挂载 |
| `qemu-user` | `qemu-*-static`、`proot`；仍不行转静态分析 |
| FirmAE | Firmadyne 手工链；或 qemu-system + 自建网络 |

## 7. 边界

- 只对自有/明确授权的固件与设备操作；不接第三方设备、不扫公网、不写他人闪存。
- 原始镜像只读，所有解包/桩/补丁只在副本上做。
- 凭据、私钥、AK/SK 不写入报告；只留路径、用途、指纹。
- 不把“解包成功/仿真起内核”写成“设备可利用”。

## 8. 相关文件

- `Tool/skill/firmware-iot/SKILL.md`
- `Tool/skill/firmware-iot/references/filesystem-and-credentials.md`
- `Tool/skill/firmware-iot/references/emulation-and-fuzz.md`
- `Tool/scripts/fw-triage.py`
- `Tool/config/firmware-iot-matrix.json`
