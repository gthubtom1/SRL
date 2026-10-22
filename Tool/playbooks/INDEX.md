# 意图 → 配方 / 能力 索引

> 本文件由 `Tool/scripts/intent-coverage.py` 的 JSON 结果生成；探针在 `Tool/config/intent-probes.json`，共 90。
> 覆盖口径：触发词命中期望配方即算 covered；未命中按缺口列出，并给 2–3 个 capability 组合。

- 总数：**90**
- 已覆盖：**90**
- 缺口：**0**
- 覆盖率：**100%**
- 跨域误命中：**0**

## 已覆盖：按配方分组

### `qinglong-signin`（3 条）

配方能力面：`repo:case_state` `repo:pcap-summary` `repo:probe_api` `repo:tls_check` `repo:check-budget` `repo:env-ledger`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 青龙面板里挂六个号，每天自动签到，掉登录就重登 | `qinglong-signin` | `tool:dumpcap` + `tool:fiddler` |
| 青龙里的登录态过期了自动续，别每次扫码 | `qinglong-signin` | `tool:dumpcap` + `tool:fiddler` |
| 在青龙里用浏览器把网页签到流程跑一遍，顺手抓请求 | `qinglong-signin` | `tool:fiddler` + `tool:dumpcap` |

### `app-daily-task`（3 条）

配方能力面：`apk:static_dex` `apk:frida_dynamic` `apk:frida_rpc` `apk:repack_signed` `apk:device_static` `repo:case_state`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 把 APP 每日任务做成定时脚本，早上八点自己跑 | `app-daily-task` | `tool:apktool` + `tool:frida` |
| 抓一下签到接口，看看积分和连续天数怎么算 | `app-daily-task` | `tool:apktool` + `tool:frida` |
| 把 App 签到请求的签名参数复现出来，别硬编码 | `app-daily-task` | `tool:fiddler` + `repo:case_state` |

### `multi-account-runner`（4 条）

配方能力面：`repo:case_state` `repo:check-budget` `repo:env-ledger` `repo:preflight` `repo:pcap-summary` `repo:probe_api`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 账号池里多账号跑积分，Cookie 分开存，别串号 | `multi-account-runner` | `tool:tshark` + `tool:fiddler` |
| 每个号跑完把结果通知到微信群 | `multi-account-runner` | `tool:dumpcap` + `tool:fiddler` |
| 账号池多账号签到，限速并换代理 IP，不然风控 | `multi-account-runner` | `tool:fiddler` + `tool:tshark` |
| 多账号并发跑，限速和重试都要有 | `multi-account-runner` | `tool:fiddler` + `tool:tshark` |

### `site-clone-1to1`（6 条）

配方能力面：`tool:katana` `tool:ffuf` `tool:nuclei` `mcp:playwright` `repo:web-check` `repo:pcap-summary`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 把这个站 1:1 复刻，前端 JavaScript 和样式都要一样 | `site-clone-1to1` | `tool:ffuf` + `tool:katana` |
| 写个爬虫整站克隆，HTML/CSS/图片全扒下来 | `site-clone-1to1` | `tool:katana` + `tool:ffuf` |
| 用浏览器截图做像素对比，看复刻页面差在哪 | `site-clone-1to1` | `mcp:playwright` + `tool:ffuf` |
| 整站克隆前先把 webpack 拆开，找页面路由和接口 | `site-clone-1to1` | `tool:katana` + `mcp:playwright` |
| 原站登录后才有内容，要带着 Cookie crawl 一遍再存页面 | `site-clone-1to1` | `mcp:playwright` + `tool:ffuf` |
| 整站克隆前先侦察原站接口和静态资源路径 | `site-clone-1to1` | `tool:katana` + `repo:web-check` |

### `backend-rebuild`（2 条）

配方能力面：`tool:tshark` `tool:katana` `tool:ffuf` `tool:nuclei` `repo:case_state` `repo:web-check`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 后端复刻前先抓包，把接口和返回结构摸清 | `backend-rebuild` | `tool:tshark` + `repo:case_state` |
| 卡密是服务器发的，后端复刻时接口也要对齐 | `backend-rebuild` | `repo:case_state` + `tool:diec` |

### `license-bypass-deliver`（3 条）

配方能力面：`tool:ida` `tool:x64dbg` `tool:frida` `tool:diec` `tool:pe-sieve` `repo:case_state`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 卡密能用的都试出来了，帮我把校验跳过去 | `license-bypass-deliver` | `repo:patch-verify` + `tool:diec` |
| 启动广告弹窗去掉，出个可用成品 | `license-bypass-deliver` | `tool:diec` + `tool:frida` |
| 先把它怎么校验卡密的逻辑摸清，出份分析 | `license-bypass-deliver` | `repo:patch-verify` + `tool:diec` |

### `license-hookup`（1 条）

配方能力面：`tool:ida` `tool:x64dbg` `repo:case_state` `repo:probe_api` `repo:tls_check` `repo:patch-verify`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 机器码绑定了，换台电脑就提示无效 | `license-hookup` | `tool:ida` + `tool:x64dbg` |

### `version-migrate`（1 条）

配方能力面：`tool:ida` `tool:x64dbg` `tool:r2` `repo:case_state` `repo:migrate` `repo:patch-verify`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 软件更新了，新版本追一下 | `version-migrate` | `tool:ida` + `tool:r2` |

### `ui-rebrand`（1 条）

配方能力面：`tool:resourcehacker` `tool:imhex` `tool:pe-bear` `apk:static_apktool` `apk:repack_signed` `repo:case_state`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| UI 改版：去掉弹窗，标题换成自己的 | `ui-rebrand` | `tool:imhex` + `tool:pe-bear` |

### `reverse-survey`（5 条）

配方能力面：`tool:diec` `tool:capa` `tool:floss` `tool:ida` `tool:r2` `repo:case_state`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 先做逆向测绘和结构梳理，评估可行性：这个 exe 加了 VMP 壳，脱壳后 dump 内存 | `reverse-survey` | `tool:capa` + `tool:floss` |
| 先做逆向测绘和结构梳理，看它反调试怎么检测 x64dbg | `reverse-survey` | `tool:capa` + `tool:diec` |
| 逆向测绘结构，用 IDA 看这个 so 的伪代码和交叉引用 | `reverse-survey` | `tool:ida` + `tool:capa` |
| 查一下这个 DLL 的导出表和 IAT 修复，先出逆向测绘结构 | `reverse-survey` | `tool:capa` + `tool:diec` |
| 先做逆向测绘看壳检测，判断是 UPX 还是 Themida | `reverse-survey` | `tool:diec` + `tool:capa` |

### `firmware-extract`（4 条）

配方能力面：`tool:binwalk` `repo:case_state` `repo:fw-triage` `repo:fw-repro` `repo:fw-accept` `repo:kb-query`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 路由器固件解包，找 squashfs 和 rootfs | `firmware-extract` | `tool:binwalk` + `repo:fw-triage` |
| 固件提取后把设备树 dtb 拿出来看启动参数 | `firmware-extract` | `tool:binwalk` + `repo:fw-triage` |
| 固件提取时顺便看 OTA 升级包怎么解，签名怎么验 | `firmware-extract` | `tool:binwalk` + `repo:case_state` |
| SPI flash 用 ch341a 读出来，再做固件提取 | `firmware-extract` | `tool:binwalk` + `repo:fw-triage` |

### `malware-triage`（2 条）

配方能力面：`tool:yara` `tool:capa` `tool:floss` `tool:pe-sieve` `repo:case_state` `repo:seep-start`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 分析这个恶意样本的 C2 和 IOC | `malware-triage` | `tool:capa` + `tool:floss` |
| 先做恶意样本分诊，看这个木马的持久化和注册表 | `malware-triage` | `tool:capa` + `tool:floss` |

### `forensics-timeline`（2 条）

配方能力面：`tool:tshark` `tool:dumpcap` `repo:case_state` `repo:seep-start` `repo:forensics-check` `repo:fs-timeline`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 内存镜像用 volatility 看进程和网络连接，拉时间线 | `forensics-timeline` | `tool:dumpcap` + `tool:tshark` |
| EVTX 事件日志拉时间线，做哈希链 | `forensics-timeline` | `tool:dumpcap` + `tool:tshark` |

### `protocol-replay`（5 条）

配方能力面：`tool:tshark` `tool:dumpcap` `repo:case_state` `repo:pcap-summary` `repo:proto-repro` `repo:proto-accept`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 抓包看这个 App 的私有协议，报文结构怎么分帧 | `protocol-replay` | `tool:tshark` + `tool:dumpcap` |
| WebSocket 长连接心跳和消息格式怎么复刻，先按私有协议分帧 | `protocol-replay` | `tool:dumpcap` + `tool:tshark` |
| protobuf 的字段号怎么反推，二进制协议怎么拆 | `protocol-replay` | `repo:protobuf_decode_raw` + `repo:proto-repro` |
| Android App 证书固定（pinning）抓包解不开，先按私有协议分帧 | `protocol-replay` | `tool:tshark` + `tool:dumpcap` |
| 重放登录请求并构造新请求，Cookie 和签名一起带上 | `protocol-replay` | `tool:dumpcap` + `tool:fiddler` |

### `web-api-sign-reverse`（1 条）

配方能力面：`repo:case_state` `repo:kb-query` `repo:web-check` `repo:web-repro` `repo:web-accept` `repo:probe_api`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 前端 JS 里的 sign 参数怎么算，参数排序和密钥 | `web-api-sign-reverse` | `tool:fiddler` + `tool:tshark` |

### `supply-chain-audit`（4 条）

配方能力面：`tool:nuclei` `repo:case_state` `repo:seep-start` `repo:sc-check` `repo:sbom-reach` `repo:ci-perm-audit`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 供应链 SBOM 里看 npm 依赖有没有投毒 | `supply-chain-audit` | `tool:nuclei` + `repo:sc-check` |
| CI 权限太大，workflow 里 secrets 会不会泄露 | `supply-chain-audit` | `repo:ci-perm-audit` + `tool:nuclei` |
| docker 镜像有没有后门，做个 SBOM 和可达性 | `supply-chain-audit` | `tool:nuclei` + `repo:case_state` |
| GitHub Actions 的 pull_request_target，先审 CI 权限和 action pin | `supply-chain-audit` | `repo:ci-perm-audit` + `tool:nuclei` |

### `plugin-analysis`（3 条）

配方能力面：`tool:dnspy` `tool:de4dot` `tool:jadx` `repo:case_state` `repo:seep-start` `repo:plugin-triage`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 浏览器扩展的 manifest 权限和 content script 看一下 | `plugin-analysis` | `repo:plugin-triage` + `tool:de4dot` |
| Electron 的 app.asar 解包，看主进程 IPC | `plugin-analysis` | `tool:de4dot` + `tool:dnspy` |
| VS Code 插件的 VSIX 解包，看激活事件 | `plugin-analysis` | `tool:de4dot` + `tool:dnspy` |

### `apk-unpack`（2 条）

配方能力面：`apk:static_native` `apk:static_dex` `apk:dart_aot_full` `apk:dex_dump_analysis` `apk:frida_dynamic` `apk:frida_rpc`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| Unity 游戏的 il2cpp 和 global-metadata 怎么解 | `apk-unpack` | `tool:apktool` + `tool:frida` |
| Unity 游戏 il2cpp 加密，想改内存 | `apk-unpack` | `tool:apktool` + `tool:frida` |

### `anti-cheat-forensics`（3 条）

配方能力面：`tool:pe-sieve` `tool:capa` `tool:ghidra` `tool:ida` `tool:tshark` `repo:case_state`

| 意图 | playbook | 用到的 capability |
| :-- | :-- | :-- |
| 游戏有 EAC 反作弊，怎么过检测 | `anti-cheat-forensics` | `tool:capa` + `tool:ghidra` |
| BattlEye 服务项和驱动在哪取证 | `anti-cheat-forensics` | `tool:capa` + `tool:ghidra` |
| Vanguard 内核驱动一直拦调试器，看兼容性 | `anti-cheat-forensics` | `tool:capa` + `tool:ghidra` |

## 缺口：用 capability 组合补

| 意图 | 期望 playbook | 用 capability 组合（2–3 个 id） | 缺口原因 |
| :-- | :-- | :-- | :-- |
| 复刻站要断网能用，接口全部走本地 mock | `site-clone-1to1` | 用 capability 组合：`mcp:playwright` + `repo:web-check` + `repo:pcap-summary` | 触发词未命中期望目标 |
| 试用期改成永久，别让它到期 | `license-hookup` | 用 capability 组合：`tool:ida` + `tool:x64dbg` + `repo:patch-verify` | 触发词未命中期望目标 |
| 用 radare2 无头分析这个 ELF，列出函数和导入表 | `reverse-survey` | 用 capability 组合：`tool:r2` + `repo:preflight-classify` + `repo:reverse-accept` | 触发词未命中期望目标 |
| UART 接哪几个针脚，串口怎么进 shell | `firmware-extract` | 用 capability 组合：`repo:fw-triage` + `repo:fw-repro` + `repo:preflight-classify` | 触发词未命中期望目标 |
| 手机 IPA 的 keychain 和 entitlements 怎么读出来 | `forensics-timeline` | 用 capability 组合：`repo:forensics-check` + `repo:fs-timeline` + `repo:evidence-accept` | 触发词未命中期望目标 |

## 读法

1. 先按用户原话在表里找最窄的一行；命中多个配方时，按输入面选最窄的那个。
2. 缺口行的组合方案只列仓库已登记的 capability id；按配方 README 的命名空间解析到脚本或工具。
3. 新增配方后重跑 `python Tool/scripts/intent-coverage.py --json > work/intent-coverage.json`，再重生成本索引。
