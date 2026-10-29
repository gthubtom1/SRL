---
name: emulation-qemu
description: "固件 QEMU user/system 条件式分析，先核 ISA/ABI/loader 与隔离环境，以业务响应验收，记录补桩造成的差异。"
metadata:
  version: "2.1.0"
  target_runtimes: "已验证的隔离 Linux VM/容器优先；Windows 不默认提供 qemu-user"
---

# 固件 QEMU 仿真

复用 [仿真与依赖归因](../../references/emulation-and-fuzz.md)、[固件解包](../../references/firmware-unpack.md)。输入是来源可追的提取副本、目标程序、同构建 loader/库、启动参数与需验证的功能。先核 `file`、`readelf -h/-l/-A/-d` 以及当前 QEMU 可执行版本、支持的 machine/CPU；只读识别不执行目标。

Windows 当前会话不能默认运行 Linux qemu-user 或 `sudo/chroot`。需要已存在且可验证的隔离 Linux 环境；无此环境时交静态依赖表及阻断，不能宣称仿真就绪。调用 QEMU 会运行客户目标，必须满足已有运行确认与可回滚隔离条件。qemu-user、chroot、`-L` 都不单独构成安全边界。

## User 与 System 分开

| 模式 | 能解决什么 | 必须具备 | 不证明什么 |
|---|---|---|---|
| qemu-user | 翻译单一 Linux 用户进程的 ISA/syscall | 端序、位数、o32/n32/EABI、浮点 ABI、loader 和同构建库匹配 | 不能模拟厂商内核/驱动/MMIO，不代表整机可启动 |
| qemu-system | 模拟特定 machine、CPU、设备并启动内核 | 该 machine 可用的内核、根设备、控制台、启动参数、外设模型 | 同 ISA 不代表任意 SoC 可启动；Malta/virt/versatilepb 不能直接替代厂商板 |
| 局部模拟/静态 | 缺硬件依赖时验证片段或调用语义 | 明确输入、内存映射和未模拟依赖 | 不证明真实设备服务/时序 |

以下只展示已核实隔离 Linux 中的 CLI 形态，路径是工作副本示例，不能在当前环境直接假定可执行：

```bash
qemu-arm -L work/rootfs work/rootfs/bin/fixture --version
qemu-arm -g 1234 -L work/rootfs work/rootfs/bin/fixture
```

`-L` 提供 loader 前缀，不保证所有绝对应用路径重定向；rootfs 配置、cwd、文件和 syscall 依赖须分别核。`-g` 会等待 GDB，按当前 QEMU 版本核绑定行为；调试端口必须位于现有隔离边界内。缺对应参数/网络隔离则不启动。GDB 连接后核 ELF 载入地址与运行时 load bias，再设当前版本函数断点，不能抄固定地址。

系统模式先用 `qemu-system-<arch> -machine help` / `-cpu help` 做能力核验，再形成该镜像的具体启动参数。已有环境支持时可选 user networking 与回环限定的 hostfwd；不得要求改宿主网卡、路由、防火墙、tap/bridge、驱动或服务来补条件。这里不提供特权 chroot/mount 教程。

## 依赖与补桩

按“rootfs → init → loader/库 → 配置/NVRAM → 设备/时序”定位第一个失败点。`No such file` 可能是解释器缺失；SIGILL 可能是 ISA/CPU；进程启动即退可能是配置、watchdog 或真实程序错误，不能一概归 NVRAM。

`LD_PRELOAD` 桩须与目标 ISA/ABI 一致且确有动态符号调用；静态链接、内联或直接 syscall 不能通用拦截。只给有证据且非秘密的合成配置，列每个桩与返回语义；一律返回成功会掩盖故障。库、MMIO/驱动或设备不可替代时停止该分支，不把半仿真当真机。

## 正反例与验收

正例：同构建服务在已记录环境和桩条件下接收指定业务请求，输出符合预测；错配置/非法输入的反例被正确拒绝。另查进程、监听与业务处理路径，避免请求落到旧实例。反例：busybox 的 id 有输出而目标服务缺库；或端口开但只有静态占位页/502，都不能称目标服务跑通。

调试器能连、内核启动、进程存活分别只是阶段证据。交付命令、环境/镜像身份、依赖、桩差异、正反请求和结果，以及真机仍未验证部分。同形失败两次换层。ELF 函数交 softseep、HTTP 语义交 web-pentest、分帧交 protocol-plugin；全部结果回原 project/version/run。
