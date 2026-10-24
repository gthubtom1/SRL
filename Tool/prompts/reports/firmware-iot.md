# firmware-iot 报告模板

> 复制到 `work/<case>/report.md`。固件结论必须区分静态线索与 J1/J2/J3。

## 1 目标与授权
- 目标：<设备/型号/固件版本/镜像 sha256>
- 授权：<设备归属 / 只读 / 是否允许仿真或真机 / 时间窗>
- 范围外：<生产网 / 写 flash / 修改配置 / 射频干扰>
- 环境：<架构 / 工具链 / qemu 版本 / 串口或探针>

## 2 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/triage.json | <sha256> | `python `fw-triage`（S4 已删：壳，真身在 firmware-iot/scripts/） --file <fw> --json` | 0 | 容器/熵/凭据线索 |
| E02 | artifacts/repro.json | <sha256> | `python Tool/skill/firmware-iot/scripts/fw-repro.py --file <fw> --out-dir ... --json` | 0 | 解包/rootfs/file:line |
| E03 | artifacts/accept.json | <sha256> | `python Tool/skill/firmware-iot/scripts/fw-accept.py --root . --json` | 0 | 案例验收 |

## 3 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| 容器/偏移 | strong/weak 偏移可解释，SHA256 与输入记录一致 | <实测> | E01 | <结论> |
| rootfs 完整性 | /etc /bin /lib/init 齐全，busybox 架构自洽 | <实测> | E02 | <结论> |
| J1 存活 | 仿真/真机能到 login 或目标服务监听 | <实测> | E02 | <结论> |
| J2 服务 | 端口/进程/配置链路可对应，有请求响应 | <实测> | E02 | <结论> |
| J3 可重复 PoC | 同一输入 3/3 触发，有日志/抓包 | <实测> | E02 | <结论> |
| 升级完整性 | 包签名/哈希/回滚保护与实际流量一致 | <实测> | E01/E02 | <结论> |

## 4 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| 只解出 kernel/配置碎片、无 rootfs/服务 | <yes/no> | E02 | 转 sasquatch/ubireader 或厂商头 |
| 仿真起不来/超时无 login | <yes/no> | E02 | 归因 arch/驱动/NVRAM/watchdog，不写 J2 |
| 只有可疑字符串、无执行/外联 | <yes/no> | E02 | 标 candidate，不写“已植入” |
| 只有端口扫描/版本号 | <yes/no> | E01 | 评估未完成，转固件静态 |
| 夹具结论被写成真实设备漏洞 | <yes/no> | E03 | 撤回并按证据等级降级 |

## 5 影响与边界
- 影响：<可登录服务 / 默认凭据 / 可持久化点 / 可外联目标>
- 边界：<只读静态 / 仿真未联网 / 未验证真实设备>
- 误报风险：<厂商 blob 误判为文件系统、字符串误判为凭据>
- 未覆盖：<未跑的架构、未拿到的 rootfs、未验证的签名链>

## 6 修复建议（厂商视角）
1. 固件包做签名与防回滚，升级通道强制 TLS 与双向校验。
2. 移除默认/空口令与 telnetd，Web/CGI 参数化并对危险函数加白名单。
3. 私钥放安全芯片/HSM，rootfs 只留引用；调试口量产关闭。
4. 启动链启用 Secure Boot/TPM 度量，发布 SBOM 与可复现哈希。

## 7 复跑命令
```bash
python `fw-triage`（S4 已删：壳，真身在 firmware-iot/scripts/） --file work/<case>/artifacts/firmware.bin --json
python Tool/skill/firmware-iot/scripts/fw-repro.py --file work/<case>/artifacts/firmware.bin --out-dir work/<case>/artifacts/fw --json
python Tool/skill/firmware-iot/scripts/fw-accept.py --root . --json
```
