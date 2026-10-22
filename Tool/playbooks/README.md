# Playbooks：任务配方层

需求先在这里找配方，再按配方组合仓库已有能力。配方是可复跑的命令序列，不是领域说明；范围由用户提供的 scope 决定。

## 怎么用

1. 先把用户给的 scope、账号、样本、网址、凭据占位写进 `work/<case>/scope.md`。
2. 用触发词在下面索引里找配方；命中多个时按“输入面”选最窄的一个。
3. 按配方步骤跑命令，把每次 rc、JSON 字段、证据路径写回案例。
4. 没有匹配 playbook 时，用 capability 组合现场写一个（≤120 行），不新增域。

## capability id 解析

配方里的能力统一写成 `<namespace>:<id>`，按下列顺序解析：

| namespace | 解析位置 | 例子 |
| :-- | :-- | :-- |
| `tool` | `Tool/config/tool-capabilities.json` 的 `tools.<id>` | `tool:ida`、`tool:frida`、`tool:tshark` |
| `apk` | `Tool/skill/apkseep/scripts/capabilities.py` 的 `CAPABILITIES` 键 | `apk:static_dex`、`apk:repack_signed` |
| `repo` | `Tool/scripts/` 或 `Tool/skill/<domain>/scripts/` 下的脚本名 | `repo:case_state`、`repo:preflight` |
| `mcp` | `Tool/config/mcp-servers.json` 的 `servers.<id>` | `mcp:playwright`、`mcp:js-reverse` |

`repo:apk-decode` 是带子目录的别名，指向 `Tool/scripts/apk/decode.ps1`；其余 `repo:` id 默认等于脚本 stem。

同一个配方只列真正会用到的能力；步骤里出现的脚本必须能在仓库内找到。

## 索引（22 个）

### 账号 / 定时任务

| 配方 | 触发词 | 核心能力 |
| :-- | :-- | :-- |
| [qinglong-signin](qinglong-signin.md) | 青龙、签到、cron、env、通知 | `repo:case_state` `repo:pcap-summary` `tool:fiddler` `tool:tshark` |
| [app-daily-task](app-daily-task.md) | APP 每日任务、积分、签到、重放 | `apk:frida_dynamic` `apk:repack_signed` `repo:run_probe` |
| [multi-account-runner](multi-account-runner.md) | 多账号、池、限速、幂等、批量 | `repo:env-ledger` `repo:check-budget` `repo:case_state` |
| [captcha-handling](captcha-handling.md) | 验证码、OCR、滑块、人工 | `repo:temp_ocr` `repo:run_probe` `tool:frida` |

### Web / 站点 / 后端

| 配方 | 触发词 | 核心能力 |
| :-- | :-- | :-- |
| [site-clone-1to1](site-clone-1to1.md) | 1:1 复刻、crawl、像素 diff、DOM diff | `tool:katana` `tool:ffuf` `repo:web-check` |
| [web-api-sign-reverse](web-api-sign-reverse.md) | Web 签名、补环境、复算、重放 | `repo:web-check` `repo:web-repro` `repo:kb-query` |
| [backend-rebuild](backend-rebuild.md) | 后端复刻、API 面、协议、切换 | `repo:pcap-summary` `repo:proto-repro` `repo:web-accept` |
| [protocol-replay](protocol-replay.md) | 私有协议、分帧、状态机、构造请求 | `repo:proto-repro` `repo:pcap-summary` `tool:tshark` |

### 客户端交付

| 配方 | 触发词 | 核心能力 |
| :-- | :-- | :-- |
| [license-bypass-deliver](license-bypass-deliver.md) | 授权旁路、补丁、代理 DLL、注入 | `tool:ida` `tool:x64dbg` `repo:patch-verify` |
| [ui-rebrand](ui-rebrand.md) | UI 改版、去品牌、换文案、换图标 | `tool:resourcehacker` `apk:static_apktool` `repo:patch-verify` |
| [license-hookup](license-hookup.md) | 自有授权、本地 HMAC、在线票据 | `repo:probe_api` `repo:tls_check` `repo:patch-verify` |
| [version-migrate](version-migrate.md) | 追版、AOB 滑窗、跨版本 | `repo:migrate` `repo:patch-verify` `tool:ida` |

### APK / 固件

| 配方 | 触发词 | 核心能力 |
| :-- | :-- | :-- |
| [apk-ad-removal](apk-ad-removal.md) | 去广告、去弹窗、插屏、开屏 | `apk:static_dex` `apk:smali_roundtrip` `apk:repack_signed` |
| [apk-unpack](apk-unpack.md) | 加固脱壳、il2cpp、metadata、VMP | `apk:frida_dynamic` `apk:dex_dump_analysis` `apk:dart_aot_full` |
| [firmware-extract](firmware-extract.md) | 固件提取、rootfs、squashfs、UBI | `repo:fw-triage` `repo:fw-repro` `tool:binwalk` |
| [firmware-emulate](firmware-emulate.md) | 固件仿真、rehosting、启动失败 | `repo:fw-repro` `repo:fw-accept` `repo:probe_api` |

### 取证 / 样本 / 供应链 / 插件

| 配方 | 触发词 | 核心能力 |
| :-- | :-- | :-- |
| [forensics-timeline](forensics-timeline.md) | 内存、磁盘、EVTX、时间线、四要素 | `repo:forensics-check` `repo:fs-timeline` `repo:evidence-accept` |
| [malware-triage](malware-triage.md) | 样本分诊、IOC、YARA、Sigma | `repo:mal-triage` `repo:ioc-extract` `repo:mal-accept` |
| [supply-chain-audit](supply-chain-audit.md) | SBOM、可达性、CI 权限、签名 | `repo:sc-check` `repo:sbom-reach` `repo:ci-perm-audit` |
| [plugin-analysis](plugin-analysis.md) | 浏览器扩展、Electron、VSIX | `repo:plugin-triage` `repo:plugin-repro` `repo:plugin-accept` |
| [reverse-survey](reverse-survey.md) | 逆向测绘、结构、壳、权威、钥匙 | `repo:preflight-classify` `repo:pwn-check` `tool:diec` |
| [anti-cheat-forensics](anti-cheat-forensics.md) | 反作弊、驱动、只读取证、兼容性 | `repo:driver-triage` `repo:forensics-check` `tool:pe-sieve` |

## 统一收尾

每个配方最后都跑 `python Tool/scripts/preflight.py --fast`；rc=0 且悬空引用 0 才算配方可交付。
