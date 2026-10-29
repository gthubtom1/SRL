# firmware-iot 报告模板

> **客户视角五段（必须全在，缺一不算交付）**：下面五个是**真标题**——`python Tool/scripts/case_state.py report --check --file <本文件>`
> 按标题文字精确匹配「结论 / 已确认 / 仍未知 / 下一步 / 复查」，缺一段即 `[FAIL]`；每段标题下至少 2 行正文，
> 「结论」不超过 3 行，「已确认」里至少要有一个 `E-` / `C-` / `F-` 编号。「下一步 / 复查」别改名，改了检查器就找不到。

> 复制到 `work/<case>/report.md`。固件结论必须区分静态线索与 J1/J2/J3。

## 1 结论（≤3 行：能不能用 / 到哪一步 / 卡在哪）
- 到哪一步：<只能看懂结构 | 能改到能用 | 能完全自己接管 | 现在做不了>
- 卡在哪：<卡点一句话 + 证据编号；没有卡点写「无」>
- 能不能用：<只按已有证据说一句；没跑过就写「未验证」>

## 2 已确认（每条：客户能听懂的一句话 + 证据 ID + 强度：强 / 中 / 弱）
- <客户能听懂的那句话>（`E-001`；强：同输入同输出可复现，命令与输出都能贴）—— 原始记录 `artifacts/<tool>-<时间>.json`
- <客户能听懂的那句话>（`E-002`；强：两路独立验证一致，不只是重复跑）—— 原始记录 `artifacts/<tool>-<时间>.json`
- 只有一次观测、没有可复跑命令的线索不进本段，写进第 3 段。

## 3 仍未知（每条：未知什么 + 为什么未知 + 缺什么才能知道）
- <未知什么>｜为什么未知：<环境限制 / 证据缺口 / 授权没给>｜还缺：<补什么才能知道>
- <未知什么>｜为什么未知：<同上>｜还缺：<同上>

## 4 下一步（省事路线 / 彻底路线 / 不建议做的事，各一条）
- 省事路线：<最小动作 + 拿到什么 + 大概要花多少功夫（区间 + 判断依据）>
- 彻底路线：<要补的证据或要动的位点 + 代价与工期>
- 不建议做：<哪条路会白费或越界，为什么>

## 5 怎么复查（复查单路径 + 关键重放命令 + 期望看到什么）
- 复查单：`python Tool/scripts/case_state.py recheck --case work/<case>` → 生成 `work/<case>/recheck.md`（目标哈希 / 环境 / 重放命令）
- 重放：<本域脚本命令；Windows 的 cmd 与 PowerShell 都能直接粘贴，见文末复跑命令>
- 期望：<关键字段或输出片段>；对不上先查「已知会变」（在线服务 / 证书 / IP / 时钟）

## 6 目标与授权
- 目标：<设备/型号/固件版本/镜像 sha256>
- 授权：<设备归属 / 只读 / 是否允许仿真或真机 / 时间窗>
- 范围外：<生产网 / 写 flash / 修改配置 / 射频干扰>
- 环境：<架构 / 工具链 / qemu 版本 / 串口或探针>

## 7 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/triage.json | <sha256> | `python Tool/skill/firmware-iot/scripts/fw-triage.py --file <fw> --json` | 0 | 容器/熵/凭据线索 |
| E02 | artifacts/repro.json | <sha256> | `python Tool/skill/firmware-iot/scripts/fw-repro.py --file <fw> --out-dir ... --json` | 0 | 解包/rootfs/file:line |
| E03 | artifacts/accept.json | <sha256> | `python Tool/skill/firmware-iot/scripts/fw-accept.py --root . --json` | 0 | 案例验收 |

## 8 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| 容器/偏移 | strong/weak 偏移可解释，SHA256 与输入记录一致 | <实测> | E01 | <结论> |
| rootfs 完整性 | /etc /bin /lib/init 齐全，busybox 架构自洽 | <实测> | E02 | <结论> |
| J1 存活 | 仿真/真机能到 login 或目标服务监听 | <实测> | E02 | <结论> |
| J2 服务 | 端口/进程/配置链路可对应，有请求响应 | <实测> | E02 | <结论> |
| J3 可重复 PoC | 同一输入 3/3 触发，有日志/抓包 | <实测> | E02 | <结论> |
| 升级完整性 | 包签名/哈希/回滚保护与实际流量一致 | <实测> | E01/E02 | <结论> |

## 9 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| 只解出 kernel/配置碎片、无 rootfs/服务 | <yes/no> | E02 | 转 sasquatch/ubireader 或厂商头 |
| 仿真起不来/超时无 login | <yes/no> | E02 | 归因 arch/驱动/NVRAM/watchdog，不写 J2 |
| 只有可疑字符串、无执行/外联 | <yes/no> | E02 | 标 candidate，不写“已植入” |
| 只有端口扫描/版本号 | <yes/no> | E01 | 评估未完成，转固件静态 |
| 夹具结论被写成真实设备漏洞 | <yes/no> | E03 | 撤回并按证据等级降级 |

## 10 影响与边界
- 影响：<可登录服务 / 默认凭据 / 可持久化点 / 可外联目标>
- 边界：<只读静态 / 仿真未联网 / 未验证真实设备>
- 误报风险：<厂商 blob 误判为文件系统、字符串误判为凭据>
- 未覆盖：<未跑的架构、未拿到的 rootfs、未验证的签名链>

## 11 修复建议（厂商视角）
1. 固件包做签名与防回滚，升级通道强制 TLS 与双向校验。
2. 移除默认/空口令与 telnetd，Web/CGI 参数化并对危险函数加白名单。
3. 私钥放安全芯片/HSM，rootfs 只留引用；调试口量产关闭。
4. 启动链启用 Secure Boot/TPM 度量，发布 SBOM 与可复现哈希。

## 12 复跑命令
```bash
python Tool/skill/firmware-iot/scripts/fw-triage.py --file work/<case>/artifacts/firmware.bin --json
python Tool/skill/firmware-iot/scripts/fw-repro.py --file work/<case>/artifacts/firmware.bin --out-dir work/<case>/artifacts/fw --json
python Tool/skill/firmware-iot/scripts/fw-accept.py --root . --json
```
