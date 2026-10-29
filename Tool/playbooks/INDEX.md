# 意图 → 配方 / 能力 索引

> 本文件与 `intent-coverage.py --json` 的结果同步；探针在 `Tool/config/intent-probes.json`，共 94。
> 活动配方来自 `Tool/playbooks/*.md`，共 24；没有意图探针的配方仍会列出。
> 覆盖口径：触发词命中期望配方即算 covered；未命中按缺口列出，并给 2–3 个 capability 组合。

- 活动配方：**24**
- 总数：**94**
- 已覆盖：**94**
- 缺口：**0**
- 覆盖率：**100.00%**
- 跨域误命中：**0**

## 覆盖结果：按活动配方分组

### `anti-cheat-forensics`（4 条）

配方能力面：`tool:pe-sieve` `tool:capa` `tool:ghidra` `tool:ida` `tool:tshark` `repo:case_state` `repo:driver-triage` `repo:forensics-check` `repo:fs-timeline` `repo:pcap-summary` `repo:evidence-accept`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 游戏有 EAC 反作弊，怎么过检测 | `anti-cheat-forensics` | covered |
| BattlEye 服务项和驱动在哪取证 | `anti-cheat-forensics` | covered |
| Vanguard 内核驱动一直拦调试器，看兼容性 | `anti-cheat-forensics` | covered |
| EAC 反作弊驱动在新系统加载失败，兼容性怎么查 | `anti-cheat-forensics` | covered |

### `apk-ad-removal`（2 条）

配方能力面：`apk:static_dex` `apk:smali_roundtrip` `apk:repack_signed` `apk:device_static` `repo:case_state` `repo:doctor` `repo:apk-decode` `repo:dex_strings` `repo:patch_smali` `repo:rebuild-sign-install` `repo:install_test` `repo:apk_diff` `tool:jadx` `tool:apktool`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 套壳 App 去广告，H5 壳里怎么改 | `apk-ad-removal` | covered |
| APK 去广告，开屏和 Banner 都去掉 | `apk-ad-removal` | covered |

### `apk-unpack`（3 条）

配方能力面：`apk:static_native` `apk:static_dex` `apk:dart_aot_full` `apk:dex_dump_analysis` `apk:frida_dynamic` `apk:frida_rpc` `repo:case_state` `repo:doctor` `repo:apk-decode` `repo:dex_mem_scan` `repo:dex_dump_validate` `repo:elf_plt` `repo:vmp_diff_harness` `repo:apk_diff` `tool:frida` `tool:jadx` `tool:apktool`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 鸿蒙 HAP 解包，ArkTS 代码怎么还原 | `apk-unpack` | covered |
| HarmonyOS 元服务逆向，.abc 字节码怎么读 | `apk-unpack` | covered |
| APK 加固脱壳，DexVMP 内存 dump | `apk-unpack` | covered |

### `app-daily-task`（4 条）

配方能力面：`apk:static_dex` `apk:frida_dynamic` `apk:frida_rpc` `apk:repack_signed` `apk:device_static` `repo:case_state` `repo:pcap-summary` `repo:run_probe` `repo:probe_api` `repo:install_test` `tool:jadx` `tool:apktool` `tool:frida` `tool:tshark`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 把 APP 每日任务做成定时脚本，早上八点自己跑 | `app-daily-task` | covered |
| 抓一下签到接口，看看积分和连续天数怎么算 | `app-daily-task` | covered |
| 把 App 签到请求的签名参数复现出来，别硬编码 | `app-daily-task` | covered |
| 微信小程序 wxapkg 解包，找签到和加密参数 | `app-daily-task` | covered |

### `backend-rebuild`（3 条）

配方能力面：`tool:tshark` `tool:katana` `tool:ffuf` `tool:nuclei` `repo:case_state` `repo:web-check` `repo:pcap-summary` `repo:proto-repro` `repo:web-accept` `repo:probe_api` `probe:sign-recompute`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 后端复刻前先抓包，把接口和返回结构摸清 | `backend-rebuild` | covered |
| 卡密是服务器发的，后端复刻时接口也要对齐 | `backend-rebuild` | covered |
| 把 SaaS 后台复刻成本地版，接口全 mock | `backend-rebuild` | covered |

### `captcha-handling`（3 条）

配方能力面：`repo:case_state` `repo:web-check` `repo:temp_ocr` `captcha-gap` `captcha-angle` `repo:run_probe` `repo:frida_rpc_serve` `repo:probe_api` `tool:frida` `tool:fiddler` `mcp:playwright`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| Cloudflare 人机验证过不去，自动化登录怎么接 | `captcha-handling` | covered |
| 登录有滑块和点选，验证码分支怎么走 | `captcha-handling` | covered |
| 人机验证加短信码，多账号登录怎么过 | `captcha-handling` | covered |

### `firmware-emulate`（3 条）

配方能力面：`tool:binwalk` `repo:case_state` `repo:fw-triage` `repo:fw-repro` `repo:fw-accept` `repo:probe_api` `repo:env-ledger` `repo:kb-query`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 固件解包后 qemu 起不来，服务没监听 | `firmware-emulate` | covered |
| 路由器固件仿真跑不起来，卡在 init 链 | `firmware-emulate` | covered |
| IoT 固件 rehosting 缺 NVRAM 设备节点 | `firmware-emulate` | covered |

### `firmware-extract`（9 条）

配方能力面：`tool:binwalk` `repo:case_state` `repo:fw-triage` `repo:fw-repro` `repo:fw-accept` `repo:kb-query`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 路由器固件解包，找 squashfs 和 rootfs | `firmware-extract` | covered |
| UART 接哪几个针脚，串口怎么进 shell | `firmware-extract` | covered |
| 固件提取后把设备树 dtb 拿出来看启动参数 | `firmware-extract` | covered |
| 固件提取时顺便看 OTA 升级包怎么解，签名怎么验 | `firmware-extract` | covered |
| SPI flash 用 ch341a 读出来，再做固件提取 | `firmware-extract` | covered |
| IoT OTA 升级包怎么解，签名校验在哪 | `firmware-extract` | covered |
| 电视盒子 OTA 固件提取，分区和签名一起看 | `firmware-extract` | covered |
| 电视盒子固件提取，rootfs 和分区表 | `firmware-extract` | covered |
| 车机系统逆向，CAN 报文和固件怎么入手 | `firmware-extract` | covered |

### `forensics-timeline`（4 条）

配方能力面：`tool:tshark` `tool:dumpcap` `repo:case_state` `repo:forensics-check` `repo:fs-timeline` `repo:evidence-accept` `repo:pcap-summary`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 内存镜像用 volatility 看进程和网络连接，拉时间线 | `forensics-timeline` | covered |
| EVTX 事件日志拉时间线，做哈希链 | `forensics-timeline` | covered |
| 手机 IPA 的 keychain 和 entitlements 怎么读出来 | `forensics-timeline` | covered |
| iOS 砸壳，Mach-O 解密 dump 怎么做 | `forensics-timeline` | covered |

### `game-client-il2cpp`（4 条）

配方能力面：`repo:case_state` `repo:kb-query` `repo:evidence-accept` `repo:forensics-check` `tool:ida` `tool:ghidra`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| Unity 游戏的 il2cpp 和 global-metadata 怎么解 | `game-client-il2cpp` | covered |
| Unity 游戏 il2cpp 加密，想改内存 | `game-client-il2cpp` | covered |
| Unity IL2CPP 去广告，global-metadata 怎么改 | `game-client-il2cpp` | covered |
| Unity 游戏去广告，AssetBundle 里的广告配置 | `game-client-il2cpp` | covered |

### `license-bypass-deliver`（3 条）

配方能力面：`tool:ida` `tool:x64dbg` `tool:frida` `tool:diec` `tool:pe-sieve` `repo:case_state` `repo:preflight-classify` `repo:tool-acquire` `repo:dump-restore` `repo:patch-verify` `repo:reverse-accept`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 卡密能用的都试出来了，帮我把校验跳过去 | `license-bypass-deliver` | covered |
| 启动广告弹窗去掉，出个可用成品 | `license-bypass-deliver` | covered |
| 先把它怎么校验卡密的逻辑摸清，出份分析 | `license-bypass-deliver` | covered |

### `license-hookup`（2 条）

配方能力面：`tool:ida` `tool:x64dbg` `repo:case_state` `repo:probe_api` `repo:tls_check` `repo:patch-verify` `repo:reverse-accept` `repo:web-check`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 试用期改成永久，别让它到期 | `license-hookup` | covered |
| 机器码绑定了，换台电脑就提示无效 | `license-hookup` | covered |

### `malware-triage`（2 条）

配方能力面：`tool:yara` `tool:capa` `tool:floss` `tool:pe-sieve` `repo:case_state` `repo:mal-triage` `repo:mal-unpack` `repo:ioc-extract` `repo:mal-accept` `repo:kb-query`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 分析这个恶意样本的 C2 和 IOC | `malware-triage` | covered |
| 先做恶意样本分诊，看这个木马的持久化和注册表 | `malware-triage` | covered |

### `multi-account-runner`（4 条）

配方能力面：`repo:case_state` `repo:budget` `repo:env-ledger` `repo:preflight` `repo:pcap-summary` `repo:probe_api` `tool:fiddler` `tool:tshark`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 账号池里多账号跑积分，Cookie 分开存，别串号 | `multi-account-runner` | covered |
| 每个号跑完把结果通知到微信群 | `multi-account-runner` | covered |
| 账号池多账号签到，限速并换代理 IP，不然风控 | `multi-account-runner` | covered |
| 多账号并发跑，限速和重试都要有 | `multi-account-runner` | covered |

### `osint-recon`（1 条）

配方能力面：`repo:case_state` `repo:kb-query` `repo:web-check` `mcp:seep` `tool:subfinder` `tool:httpx` `tool:nuclei` `mcp:playwright` `repo:osint-secret-scan` `repo:osint-h1-ref`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 给我做目标域名的 OSINT 资产测绘，梳理子域枚举、证书透明日志和 GitHub 泄露 | `osint-recon` | covered |

### `plugin-analysis`（3 条）

配方能力面：`tool:dnspy` `tool:de4dot` `tool:jadx` `repo:case_state` `plugin-unpack` `repo:check-extension-conflicts`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 浏览器扩展的 manifest 权限和 content script 看一下 | `plugin-analysis` | covered |
| Electron 的 app.asar 解包，看主进程 IPC | `plugin-analysis` | covered |
| VS Code 插件的 VSIX 解包，看激活事件 | `plugin-analysis` | covered |

### `protocol-replay`（9 条）

配方能力面：`tool:tshark` `tool:dumpcap` `repo:case_state` `repo:pcap-summary` `repo:proto-repro` `repo:proto-accept` `repo:protobuf_decode_raw`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 抓包看这个 App 的私有协议，报文结构怎么分帧 | `protocol-replay` | covered |
| WebSocket 长连接心跳和消息格式怎么复刻，先按私有协议分帧 | `protocol-replay` | covered |
| protobuf 的字段号怎么反推，二进制协议怎么拆 | `protocol-replay` | covered |
| Android App 证书固定（pinning）抓包解不开，先按私有协议分帧 | `protocol-replay` | covered |
| 重放登录请求并构造新请求，Cookie 和签名一起带上 | `protocol-replay` | covered |
| BLE 手环协议逆向，GATT 特征值怎么抓 | `protocol-replay` | covered |
| 蓝牙手柄 HID 报文怎么重放 | `protocol-replay` | covered |
| Modbus 工控协议怎么构造新请求 | `protocol-replay` | covered |
| PLC 工控协议复刻，寄存器读写报文 | `protocol-replay` | covered |

### `qinglong-signin`（4 条）

配方能力面：`repo:case_state` `repo:pcap-summary` `repo:probe_api` `repo:tls_check` `repo:budget` `repo:env-ledger` `repo:preflight` `tool:fiddler` `tool:tshark` `tool:dumpcap`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 青龙面板里挂六个号，每天自动签到，掉登录就重登 | `qinglong-signin` | covered |
| 青龙里的登录态过期了自动续，别每次扫码 | `qinglong-signin` | covered |
| 在青龙里用浏览器把网页签到流程跑一遍，顺手抓请求 | `qinglong-signin` | covered |
| 小程序每天自动签到，抓包看签到接口 | `qinglong-signin` | covered |

### `reverse-survey`（10 条）

配方能力面：`tool:diec` `tool:capa` `tool:floss` `tool:ida` `tool:r2` `repo:case_state` `repo:preflight-classify` `repo:pwn-check` `repo:driver-triage` `repo:kb-query` `repo:reverse-accept`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 先做逆向测绘和结构梳理，评估可行性：这个 exe 加了 VMP 壳，脱壳后 dump 内存 | `reverse-survey` | covered |
| 先做逆向测绘和结构梳理，看它反调试怎么检测 x64dbg | `reverse-survey` | covered |
| 逆向测绘结构，用 IDA 看这个 so 的伪代码和交叉引用 | `reverse-survey` | covered |
| 用 radare2 无头分析这个 ELF，列出函数和导入表 | `reverse-survey` | covered |
| 查一下这个 DLL 的导出表和 IAT 修复，先出逆向测绘结构 | `reverse-survey` | covered |
| 先做逆向测绘看壳检测，判断是 UPX 还是 Themida | `reverse-survey` | covered |
| PyInstaller 打包的 exe 怎么解出 pyc | `reverse-survey` | covered |
| Go 静态编译程序怎么恢复符号和函数名 | `reverse-survey` | covered |
| Rust 写的程序逆向，怎么找授权点 | `reverse-survey` | covered |
| 驱动兼容层怎么写，让老驱动在新系统跑 | `reverse-survey` | covered |

### `site-clone-1to1`（8 条）

配方能力面：`probe:site-crawl` `probe:site-rebuild` `probe:visual-diff` `probe:site-accept` `repo:preflight`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 把这个站 1:1 复刻，前端 JavaScript 和样式都要一样 | `site-clone-1to1` | covered |
| 写个爬虫整站克隆，HTML/CSS/图片全扒下来 | `site-clone-1to1` | covered |
| 复刻站要断网能用，接口全部走本地 mock | `site-clone-1to1` | covered |
| 用浏览器截图做像素对比，看复刻页面差在哪 | `site-clone-1to1` | covered |
| 整站克隆前先把 webpack 拆开，找页面路由和接口 | `site-clone-1to1` | covered |
| 原站登录后才有内容，要带着 Cookie crawl 一遍再存页面 | `site-clone-1to1` | covered |
| 整站克隆前先侦察原站接口和静态资源路径 | `site-clone-1to1` | covered |
| SaaS 控制台 1:1 复刻，断网也能用 | `site-clone-1to1` | covered |

### `supply-chain-audit`（6 条）

配方能力面：`tool:nuclei` `repo:case_state` `repo:sc-check` `probe:sbom-build` `repo:sbom-reach` `repo:ci-perm-audit` `repo:sc-accept` `repo:kb-query`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 供应链 SBOM 里看 npm 依赖有没有投毒 | `supply-chain-audit` | covered |
| CI 权限太大，workflow 里 secrets 会不会泄露 | `supply-chain-audit` | covered |
| docker 镜像有没有后门，做个 SBOM 和可达性 | `supply-chain-audit` | covered |
| GitHub Actions 的 pull_request_target，先审 CI 权限和 action pin | `supply-chain-audit` | covered |
| Docker 镜像抠服务，把二进制和配置提出来 | `supply-chain-audit` | covered |
| 从容器镜像里把服务抠出来单独跑 | `supply-chain-audit` | covered |

### `ui-rebrand`（1 条）

配方能力面：`tool:resourcehacker` `tool:imhex` `tool:pe-bear` `apk:static_apktool` `apk:repack_signed` `repo:case_state` `repo:preflight-classify` `repo:patch-verify` `repo:reverse-accept` `repo:install_test`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| UI 改版：去掉弹窗，标题换成自己的 | `ui-rebrand` | covered |

### `version-migrate`（1 条）

配方能力面：`tool:ida` `tool:x64dbg` `tool:r2` `repo:case_state` `repo:patch-verify` `repo:reverse-accept`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 软件更新了，新版本追一下 | `version-migrate` | covered |

### `web-api-sign-reverse`（1 条）

配方能力面：`repo:case_state` `repo:kb-query` `repo:web-check` `repo:web-repro` `repo:web-accept` `repo:probe_api` `tool:fiddler` `tool:tshark` `mcp:js-reverse`

| 意图 | playbook | 状态 |
| :-- | :-- | :-- |
| 前端 JS 里的 sign 参数怎么算，参数排序和密钥 | `web-api-sign-reverse` | covered |
