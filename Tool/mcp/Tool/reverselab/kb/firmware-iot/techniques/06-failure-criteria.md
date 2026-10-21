# 06 失败判据（firmware-iot）

> 目标：出现这些现象时**立刻降级/换路线**，不要在同一条路上反复重试。
> 配套：`references/02-failure-criteria.md`、`references/03-model-pitfalls.md`。
> 每条格式：现象 / 判定 / 改走哪条 / 代价。

## 0. 使用方式

1. 先在 `fw-triage`/`fw-repro` 的 JSON 里找对应字段（`containers`/`entropy`/`extraction`）；
2. 按下表判定卡点类别：`input` / `tool-missing` / `container-unsupported` /
   `emulation` / `hardware` / `authorization`；
3. 换路线前记录“已试命令 + rc + stderr 关键行”，避免重复劳动。

## 1. 失败判据表

| 现象 | 判定 | 改走哪条 | 代价 |
|---|---|---|---|
| `binwalk -e` 只出 kernel/DTB/碎片 | 解包未完成 | 算厂商头真实偏移；换 `ubireader`/`sasquatch`/`jefferson`/`7z` | 0.5–2 h，可能仍无 rootfs |
| `unsquashfs` 报 unsupported compression | 厂商魔改 SquashFS | `sasquatch`；查内核解压器；否则只做 strings/熵 | 需找内核/工具链 |
| UBI `bad magic`/卷为空 | 偏移错、缺 OOB、dump 截断 | `ubireader_display_info` 找 `UBI#`；`nanddump -o`；核对 PEB/页大小 | 可能需重 dump |
| JFFS2 命中多但解出空树 | weak 误报/坏节点多 | 校验节点头/CRC；只保连续区；或放弃该区 | 误报区浪费时间 |
| 高熵 + 无 strong 魔术 | 加密/厂商容器/纯压缩 | 找解密点/U-Boot 解密；转 UART/JTAG/内存 dump | 需硬件与授权 |
| 只有 shadow hash、字典不中 | 凭据未破解 | 记录素材；转登录入口/接口绕过/串口 shell | 破解成本不可控 |
| `passwd` 为 `x`、shadow 为 `!`/`*` | 非空口令/锁定 | 同时读 passwd+shadow；找 NVRAM/云账号/authorized_keys | 可能确实无可用账号 |
| 私钥/证书无法配对 | 不是设备身份私钥 | 记录证书用途/指纹；找 `.p12/.pfx`/NVRAM/secure element | 误判浪费时间 |
| qemu-user `No such file or directory` | 加载器/库缺失 | `readelf -l/-d` 看 interpreter；补 `lib/`、`-L`、static qemu、proot | 需匹配厂商 libc |
| qemu-system panic/挂根失败 | 架构/`root=`/驱动/initramfs 错 | 核对端序架构 → 换机器类型 → 补 initramfs → FirmAE → 真机 chroot | 每轮 10–60 min |
| FirmAE success 但只有静态页/502 | 不是 J2 | 查 `qemu.*.log`、DocumentRoot、CGI 权限、NVRAM | 需读日志/改桩 |
| 服务进程在但端口不通/启动即退 | 配置/权限/依赖/看门狗 | 读 stderr；补 `/dev`/`/proc`/时区/随机数；副本禁用看门狗 | 反复试桩，真机有风险 |
| UART 无输出/乱码 | 电压/共地/TX-RX/波特率/控制台关 | 量电压共地 → 交换 TX/RX → 115200/57600/38400/9600 → 逻辑分析仪 | 接错可能烧 SoC |
| JTAG 扫不到 IDCODE | 引脚/电平/TAP 关闭 | 核对 TCK/TMS/TDI/TDO/GND/VREF；降速；查 datasheet | 可能永久锁死 |
| SPI 两次读取哈希不一致 | 接触/供电/并发访问 | 断电夹紧/焊下；降 `flashrom` 速率；1.8V 适配；再读两次 | 可能读坏/写坏 |
| 改 rootfs 后升级被拒 | 签名/回滚保护 | 不伪造签名；转 UART/JTAG 在线改启动参数/运行态调试 | 无法持久化 |
| 漏洞只在字符串/版本号 | 不是 J3 | 黑盒测绘/动态跟踪/最小 PoC；两次一致才算 | 时间成本高 |
| 同一手法连续 2 次失败 | 路线不通 | 换路线或汇报；不在真机反复写 | — |

## 2. 最小失败交付

即使全线失败，也要留下：

```text
镜像：<path> sha256=<64 hex> size=<bytes> 来源=<命令/URL>
已试：<命令> rc=<n> stderr=<关键行>
容器：strong=<type@offset> weak=<type@offset（误报理由）>
卡点：input|tool-missing|container-unsupported|emulation|hardware|authorization
下一条：<路线> 前置=<工具/授权/硬件>
```

## 3. 边界

- 失败判据是分流器，不是永久禁令；换版本/环境可重试，但要写清差异。
- 缺工具必须写 `blocked_at: "tool-missing"` 与替代链，不允许用“没跑”冒充“失败”。
- 真机写操作、破解、OTA 伪造只在单独授权下进行；默认只读。
