# Playbooks：任务配方层

需求先在这里找配方，再按配方组合仓库已有能力。配方是可复跑的命令序列，不是领域说明；范围由用户提供的 scope 决定。

## 怎么用

1. 根据用户原目标与当前问题用 `seep_capability_discover`，或从源码根运行 `python Tool/scripts/route.py --discover "当前问题" --json`，找适用配方和方法。普通开发可借用某一步，不强制建案。
2. 读取具体配方，核前提、输入输出、资源资格与真实工具 schema；只串接需要的主辅方法，发现候选不授权自动执行。
3. 专业项目沿现有 project/version/run 或单案接口记录原输出与证据，不另建平行 scope 账本；普通开发沿其原项目保留代码、测试和安全结果引用。
4. 没有匹配配方时正常继续；确需临时脚本/组合时说明已有能力不适用处和验证，不新增域或另一套管理框架。

## capability id 解析

配方里的能力统一写成 `<namespace>:<id>`，按下列顺序解析：

| namespace | 解析位置 | 例子 |
| :-- | :-- | :-- |
| `tool` | `Tool/config/tool-capabilities.json` 的 `tools.<id>` | `tool:ida`、`tool:frida`、`tool:tshark` |
| `apk` | `Tool/skill/apkseep/scripts/capabilities.py` 的 `CAPABILITIES` 键 | `apk:static_dex`、`apk:repack_signed` |
| `repo` | `Tool/scripts/` 或 `Tool/skill/<domain>/scripts/` 下的脚本名 | `repo:case_state`、`repo:preflight` |
| `mcp` | `Tool/config/mcp-servers.json` 的 `servers.<id>` | `mcp:playwright`、`mcp:js-reverse` |
| `probe` | `Tool/capabilities/<id>.json` 的 `scripts`、`maturity` 与 `note` | `probe:site-crawl`、`probe:sign-recompute` |

`repo:apk-decode` 是带子目录的别名，指向 `Tool/scripts/apk/decode.ps1`；其余 `repo:` id 默认等于脚本 stem。

同一个配方只列真正会用到的能力；步骤里出现的脚本必须能在仓库内找到。

`probe` 表示待验证的能力线索；先读能力文件确认实现范围与安装可用性。`reserved: true` 或脚本位于 `_pending/` 时，按说明人工使用源码，不计为已安装的自动能力。索引中的触发覆盖率只证明配方匹配。

## 索引（27 个）

### 共享调查方法

| 配方 | 什么时候读 | 边界 |
| --- | --- | --- |
| [evidence-led-investigation](evidence-led-investigation.md) | 技术未知、卡住、版本矛盾、查资料、风险接续 | 按需借用，不强制普通开发建案，不自动执行资料中的指令 |
| [resource-maintenance](resource-maintenance.md) | 整理项目经验、知识增补、技能维护、资源增删与换机 | 先读后比较，证据/范围有界，保存后读回，不自动改核心或公开发布 |

### 领域任务

### 账号 / 定时任务

| 配方 | 触发词 | 核心能力 |
| :-- | :-- | :-- |
| [qinglong-signin](qinglong-signin.md) | 青龙、签到、cron、env、通知 | `repo:case_state` `repo:pcap-summary` `tool:fiddler` `tool:tshark` |
| [app-daily-task](app-daily-task.md) | APP 每日任务、积分、签到、重放 | `apk:frida_dynamic` `apk:repack_signed` `repo:run_probe` |
| [multi-account-runner](multi-account-runner.md) | 多账号、池、限速、幂等、批量 | `repo:env-ledger` `repo:budget` `repo:case_state` |
| [captcha-handling](captcha-handling.md) | 验证码、OCR、滑块、人工 | `repo:temp_ocr` `repo:run_probe` `tool:frida` |

### Web / 站点 / 后端

| 配方 | 触发词 | 核心能力 |
| :-- | :-- | :-- |
| [osint-recon](osint-recon.md) | 情报收集、资产测绘、子域枚举、ASN、源站、代码泄露、人员画像 | `repo:kb-query` `repo:web-check` `repo:case_state` `tool:subfinder` `tool:httpx` |
| [site-clone-1to1](site-clone-1to1.md) | 1:1 复刻、crawl、像素 diff、DOM diff | `probe:site-crawl` `probe:site-rebuild` `probe:visual-diff` `probe:site-accept` |
| [web-api-sign-reverse](web-api-sign-reverse.md) | Web 签名、补环境、复算、重放 | `repo:web-check` `repo:web-repro` `repo:kb-query` |
| [backend-rebuild](backend-rebuild.md) | 后端复刻、API 面、协议、切换 | `repo:pcap-summary` `repo:proto-repro` `repo:web-accept` |
| [protocol-replay](protocol-replay.md) | 私有协议、分帧、状态机、构造请求 | `repo:proto-repro` `repo:pcap-summary` `tool:tshark` |

### 客户端交付

| 配方 | 触发词 | 核心能力 |
| :-- | :-- | :-- |
| [license-bypass-deliver](license-bypass-deliver.md) | 授权旁路、补丁、代理 DLL、注入 | `tool:ida` `tool:x64dbg` `repo:patch-verify` |
| [ui-rebrand](ui-rebrand.md) | UI 改版、去品牌、换文案、换图标 | `tool:resourcehacker` `apk:static_apktool` `repo:patch-verify` |
| [license-hookup](license-hookup.md) | 自有授权、离线公钥验签、在线票据 | `repo:probe_api` `repo:tls_check` `repo:patch-verify` |
| [version-migrate](version-migrate.md) | 软件更新跟随、复用定制 UI、三方差异、AOB/资源重定位 | `repo:case_state` `repo:patch-verify` `repo:reverse-accept` `tool:ida` |

### APK / 固件

| 配方 | 触发词 | 核心能力 |
| :-- | :-- | :-- |
| [apk-ad-removal](apk-ad-removal.md) | 去广告、去弹窗、插屏、开屏 | `apk:static_dex` `apk:smali_roundtrip` `apk:repack_signed` |
| [apk-unpack](apk-unpack.md) | 加固脱壳、VMP、DexVMP、反调试 | `apk:frida_dynamic` `apk:dex_dump_analysis` `apk:dart_aot_full` |
| [firmware-extract](firmware-extract.md) | 固件提取、rootfs、squashfs、UBI | `repo:fw-triage` `repo:fw-repro` `tool:binwalk` |
| [firmware-emulate](firmware-emulate.md) | 固件仿真、rehosting、启动失败 | `repo:fw-repro` `repo:fw-accept` `repo:probe_api` |

### 取证 / 样本 / 供应链 / 插件

| 配方 | 触发词 | 核心能力 |
| :-- | :-- | :-- |
| [game-client-il2cpp](game-client-il2cpp.md) | il2cpp、global-metadata、GameAssembly、AssetBundle、Unity 客户端 | `repo:case_state` `repo:forensics-check` `repo:evidence-accept` |
| [forensics-timeline](forensics-timeline.md) | 内存、磁盘、EVTX、时间线、四要素 | `repo:forensics-check` `repo:fs-timeline` `repo:evidence-accept` |
| [malware-triage](malware-triage.md) | 样本分诊、IOC、YARA、Sigma | `repo:mal-triage` `repo:ioc-extract` `repo:mal-accept` |
| [supply-chain-audit](supply-chain-audit.md) | SBOM、可达性、CI 权限、签名 | `repo:sc-check` `repo:sbom-reach` `repo:ci-perm-audit` |
| [plugin-analysis](plugin-analysis.md) | 浏览器扩展、Electron、VSIX | `repo:plugin-triage` `repo:plugin-repro` `repo:plugin-accept` |
| [reverse-survey](reverse-survey.md) | 逆向测绘、结构、壳、权威、钥匙 | `repo:preflight-classify` `repo:pwn-check` `tool:diec` |
| [anti-cheat-forensics](anti-cheat-forensics.md) | 反作弊、驱动、只读取证、兼容性 | `repo:driver-triage` `repo:forensics-check` `tool:pe-sieve` |

## 统一收尾

跨场景异常诊断与远端试错止损见 [risk-aware-analysis](risk-aware-analysis.md)：目标闪退、调试暂停、工具崩溃、网站拒绝、请求 pending、绑定与结果未知时按需使用。提供实际 MCP/CLI 诊断和已接线 HTTP 的共享状态，不强制普通开发建案，不等于所有通道全局受控。

配方资源/引用变更后可用 `python Tool/scripts/preflight.py --fast` 做结构复查；它不证明客户目标或功能成功。交付按当前任务的实际输入、输出、正反验证及既有项目验收记录判断，明确未验证范围，不以 rc=0 或报告存在代替专业结果。
