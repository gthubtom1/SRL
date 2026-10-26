# INDEX-BY-QUESTION —— 按「客户怎么问」找文章（检索之前先看这张表）

> **为什么有这张表**：`README.md` 按**目录/前缀**排（找文件用），本表按**客户原话**排（找答案用）。
> 413 篇里被 SKILL/references 点名的是少数；剩下的不是没价值，是**没人指路**。
> 用法：客户说的话落进哪一组 → 直接读该组 3–8 篇里最像的那篇 → 读不中再用 `seep_kb_search("<原话>")`。
> 每条都是**真实相对路径**（相对本目录），`seep_kb_read("<路径>")` 可直接打开。

| 组 | 客户大概会这么问 | 篇数 |
| :-- | :-- | --: |
| [A](#a-加壳脱壳混淆了脱不掉) | 加壳了 / 脱壳 / 混淆 / VMP / 内存 dump / OEP | 8 |
| [B](#b-去广告会员收费功能解锁) | 去广告 / 改会员 / 卡密 / 试用过期 / 功能要付费 | 8 |
| [C](#c-后门弱口令被别人进过) | 有后门 / 后台弱口令 / webshell / 被人提权 / 日志被动过 | 8 |
| [D](#d-抓包协议这包到底怎么发) | 抓包 / 自定义协议 / 加密的包 / 重放 / 校验位 | 8 |
| [E](#e-固件iot路由器摄像头) | 固件解包 / 串口 / OTA / 路由器 / 摄像头 | 7 |
| [F](#f-取证时间线谁什么时候干的) | 取证 / 时间线 / 内存镜像 / EVTX / pcap 出文件 | 8 |
| [G](#g-供应链投毒依赖被改) | 依赖投毒 / 仿冒包 / CI 权限 / SBOM / 流水线 | 8 |
| [H](#h-web-站点接口权限) | 越权 / IDOR / 未授权 / JWT / 上传 / SSRF / WAF | 8 |
| [I](#i-支付订单业务逻辑) | 支付绕过 / 改价 / 并发 / 重复领券 / 伪造回调 | 7 |
| [J](#j-内网域控云容器) | 域控 / Kerberos / ADCS / K8s / 云 AK | 8 |
| [K](#k-游戏客户端反作弊) | 透视 / 内存改血 / 封包 / EAC·BE·Vanguard 取证 | 7 |
| [L](#l-样本分析病毒勒索) | 是不是病毒 / 勒索 / IOC / YARA / 行为时间线 | 6 |
| [M](#m-ios插件electron托管运行时) | 越狱检测 / Mach-O / 浏览器扩展 / asar / .NET·Java 授权 | 8 |
| [N](#n-不知道从哪下手卡住了) | 从哪开始 / 该用哪个工具 / 到哪一步了 / 判据 | 7 |

---

## A. 加壳/脱壳/混淆了脱不掉

- [pe-reverse/techniques/05-crypto-unpack/01-pe-unpack-dump.md](pe-reverse/techniques/05-crypto-unpack/01-pe-unpack-dump.md) — PE 脱壳与内存 Dump（找 OEP → dump → 修 IAT）
- [apk-reverse/techniques/07-packer/01-obfuscation-detection.md](apk-reverse/techniques/07-packer/01-obfuscation-detection.md) — 混淆/加固识别：先判形态再选路
- [apk-reverse/techniques/07-packer/03-vmp-dex2c-detection.md](apk-reverse/techniques/07-packer/03-vmp-dex2c-detection.md) — VMP/dex2c 判定（是不是真 VMP，别瞎跟）
- [apk-reverse/techniques/07-packer/04-vmp-dump-trace-recovery.md](apk-reverse/techniques/07-packer/04-vmp-dump-trace-recovery.md) — VMP 脱壳三件套：Dump / Trace / Recovery
- [apk-reverse/techniques/07-packer/02-self-extracting-payload.md](apk-reverse/techniques/07-packer/02-self-extracting-payload.md) — 自解压 payload：壳里藏了什么
- [windows/techniques/2026-vmp-ultralock.md](windows/techniques/2026-vmp-ultralock.md) — VMProtect 3.9.x UltraLock（ProductCode / RSA 位点）
- [windows/techniques/2026-themida-vm-bypass.md](windows/techniques/2026-themida-vm-bypass.md) — Themida VM 函数级绕过：hook dispatch
- [general/techniques/crypto/02-custom-obfuscation-reverse.md](general/techniques/crypto/02-custom-obfuscation-reverse.md) — 自定义混淆/加密还原方法论（非标准壳）

## B. 去广告/会员/收费功能解锁

- [apk-reverse/techniques/08-patch-repack/01-so-injection-repack.md](apk-reverse/techniques/08-patch-repack/01-so-injection-repack.md) — Native SO 注入 + 重打包（改完要能装）
- [apk-reverse/techniques/01-dex-java/01-smali-injection.md](apk-reverse/techniques/01-dex-java/01-smali-injection.md) — Smali 注入与 DEX 修改（广告初始化点在这）
- [apk-reverse/techniques/05-network/02-license-verification-bypass.md](apk-reverse/techniques/05-network/02-license-verification-bypass.md) — 在线授权验证分析与绕过
- [pe-reverse/techniques/10-license-keygen/02-validation-function-location.md](pe-reverse/techniques/10-license-keygen/02-validation-function-location.md) — 许可证校验函数定位（PC 端卡密）
- [managed/techniques/2026-dotnet-license.md](managed/techniques/2026-dotnet-license.md) — .NET 授权面（Assembly-CSharp / dnSpy）
- [managed/techniques/2026-java-license.md](managed/techniques/2026-java-license.md) — Java 授权面（JAR / ProGuard mapping）
- [managed/techniques/2026-python-bytecode.md](managed/techniques/2026-python-bytecode.md) — Python 打包件的授权面（pyc / PyInstaller）
- [field_journal_seed-008_apk-okhttp-ssl-pin-bypass.md](field_journal_seed-008_apk-okhttp-ssl-pin-bypass.md) — 实战：OkHttp SSL Pinning 绕过后再看会员接口

## C. 后门/弱口令/被别人进过

- [ctf-website/techniques/24-database/03-nosql-injection.md](ctf-website/techniques/24-database/03-nosql-injection.md) — 登录口 NoSQL 注入（弱口令之外的入口）
- [ctf-website/techniques/24-database/04-config-exposure.md](ctf-website/techniques/24-database/04-config-exposure.md) — 配置泄露 = 数据库口令泄露
- [ctf-website/techniques/24-database/05-backup-log-leak.md](ctf-website/techniques/24-database/05-backup-log-leak.md) — 备份/日志泄露（真凶常在这）
- [supply-chain/techniques/04-ci-permission-audit.md](supply-chain/techniques/04-ci-permission-audit.md) — CI 权限面：谁能改你的构建
- [malware-analysis/techniques/02-unpacking-and-config.md](malware-analysis/techniques/02-unpacking-and-config.md) — 从样本里挖回连地址/配置（后门画像）
- [../_archive/pe-reverse/techniques/06-ioc-extraction/02-persistence-startup-chain.md](_archive/pe-reverse/techniques/06-ioc-extraction/02-persistence-startup-chain.md) — 开机自启/持久化链（"重启又活了"）
- [forensics/techniques/windows-evtx-registry.md](forensics/techniques/windows-evtx-registry.md) — EVTX + 注册表 hive：谁什么时候登录/建服务
- [ctf-website/techniques/21-mobile-bridge/01-webview-attacks.md](ctf-website/techniques/21-mobile-bridge/01-webview-attacks.md) — WebView 桥接注入（APP 端后门面）

## D. 抓包/协议/这包到底怎么发

- [protocol/techniques/framing-and-fields.md](protocol/techniques/framing-and-fields.md) — 分帧与字段：magic / length / CRC / 加密段
- [protocol/techniques/capture-to-replay.md](protocol/techniques/capture-to-replay.md) — 从抓包到重放：状态机与单变量构造
- [protocol/techniques/checksum-and-crypto-segment.md](protocol/techniques/checksum-and-crypto-segment.md) — 先证伪"像 AES"，再谈明文
- [general/techniques/protocol/01-unknown-protocol-reverse.md](general/techniques/protocol/01-unknown-protocol-reverse.md) — 未知协议逆向方法论
- [general/techniques/protocol/02-protobuf-flatbuffers-reverse.md](general/techniques/protocol/02-protobuf-flatbuffers-reverse.md) — 无 schema 的 Protobuf/FlatBuffers
- [protocol/techniques/websocket-and-http2-framing.md](protocol/techniques/websocket-and-http2-framing.md) — WebSocket / HTTP2 分帧差异
- [general/techniques/crypto/01-algorithm-identification.md](general/techniques/crypto/01-algorithm-identification.md) — 算法盲识别：从字节特征反推
- [field_journal_seed-011_pcap-protocol-reverse.md](field_journal_seed-011_pcap-protocol-reverse.md) — 实战：PCAP 自定义二进制协议全流程

## E. 固件/IoT/路由器摄像头

- [firmware-iot/techniques/01-unpack-and-filesystem.md](firmware-iot/techniques/01-unpack-and-filesystem.md) — 固件解包与文件系统还原（binwalk 之后）
- [firmware-iot/techniques/02-uart-and-emulation.md](firmware-iot/techniques/02-uart-and-emulation.md) — UART 接线与 QEMU 仿真
- [firmware-iot/techniques/03-ota-and-signature.md](firmware-iot/techniques/03-ota-and-signature.md) — OTA 升级包与签名校验
- [firmware-iot/techniques/08-credentials-and-boot-chain.md](firmware-iot/techniques/08-credentials-and-boot-chain.md) — 硬编码凭据与启动链
- [firmware-iot/techniques/2026-rehosting-failures.md](firmware-iot/techniques/2026-rehosting-failures.md) — 仿真跑不起来时的失败判据
- [field_journal_seed-015_iot-firmware-uart.md](field_journal_seed-015_iot-firmware-uart.md) — 实战：固件提取 + UART 拿 root
- [field_journal_2026-08-06_cortex-m-msc-firmware-self-keyed-rotate-xor.md](field_journal_2026-08-06_cortex-m-msc-firmware-self-keyed-rotate-xor.md) — 实战：Cortex-M 升级包的旋转/XOR 封装

## F. 取证/时间线/谁什么时候干的

- [forensics/techniques/disk-filesystem-timeline.md](forensics/techniques/disk-filesystem-timeline.md) — 分区偏移 / inode / 时间线
- [forensics/techniques/memory-volatility-triage.md](forensics/techniques/memory-volatility-triage.md) — 内存镜像初检（Volatility3）
- [forensics/techniques/windows-evtx-registry.md](forensics/techniques/windows-evtx-registry.md) — Windows 日志与注册表取证
- [forensics/techniques/network-pcap-objects.md](forensics/techniques/network-pcap-objects.md) — pcap 会话 → 可哈希落地文件
- [forensics/techniques/ios-macos-artifacts.md](forensics/techniques/ios-macos-artifacts.md) — iOS/macOS 取证产物
- [forensics/techniques/evidence-chain.md](forensics/techniques/evidence-chain.md) — 证据链与哈希固定（别把证据弄脏）
- [forensics/techniques/2026-memprocfs-519.md](forensics/techniques/2026-memprocfs-519.md) — 实战：MemProcFS 5.19 现场抓取
- [field_journal_2026-06-29_burp-mcp-full-test-and-fix.md](field_journal_2026-06-29_burp-mcp-full-test-and-fix.md) — 实战：抓包链路本身的取证与修复

## G. 供应链/投毒/依赖被改

- [supply-chain/techniques/01-dependency-confusion.md](supply-chain/techniques/01-dependency-confusion.md) — 依赖混淆：scope / registry / 锁文件三方对照
- [supply-chain/techniques/07-typosquat-and-malicious-packages.md](supply-chain/techniques/07-typosquat-and-malicious-packages.md) — 抢注仿冒包：名字相似度与安装脚本
- [supply-chain/techniques/05-lockfile-integrity.md](supply-chain/techniques/05-lockfile-integrity.md) — 锁文件完整性：依赖到底有没有被换
- [supply-chain/techniques/03-sbom-and-reachability.md](supply-chain/techniques/03-sbom-and-reachability.md) — SBOM + 可达性（别把"有 CVE"当"能打"）
- [supply-chain/techniques/02-image-and-provenance.md](supply-chain/techniques/02-image-and-provenance.md) — 镜像与来源证明（供应链签名）
- [supply-chain/techniques/2026-chaindrop-sandworm.md](supply-chain/techniques/2026-chaindrop-sandworm.md) — 战例：ChainDrop / Sandworm 式供应链投毒
- [ctf-website/techniques/10-cloud/github-actions-abuse-paths.md](ctf-website/techniques/10-cloud/github-actions-abuse-paths.md) — GitHub Actions 滥用路径
- [ctf-website/techniques/11-supply-chain/dependency-confusion.md](ctf-website/techniques/11-supply-chain/dependency-confusion.md) — Web 视角的依赖混淆（CTF 打法）

## H. Web/站点/接口/权限

- [web-pentest/techniques/04-object-authz-proof.md](web-pentest/techniques/04-object-authz-proof.md) — 对象级越权（BOLA/IDOR）的证明链
- [ctf-website/techniques/14-idor/01-idor-enumeration.md](ctf-website/techniques/14-idor/01-idor-enumeration.md) — IDOR 深度枚举（水平/垂直）
- [ctf-website/techniques/02-auth/jwt/02-algorithm-confusion.md](ctf-website/techniques/02-auth/jwt/02-algorithm-confusion.md) — JWT 算法混淆（最常见的接口绕过）
- [ctf-website/techniques/02-auth/jwt/03-weak-key-bruteforce.md](ctf-website/techniques/02-auth/jwt/03-weak-key-bruteforce.md) — JWT 弱密钥爆破
- [ctf-website/techniques/17-api-attacks/01-api-discovery-leak.md](ctf-website/techniques/17-api-attacks/01-api-discovery-leak.md) — 接口发现与泄露（Swagger/GraphQL）
- [web-pentest/techniques/01-waf-and-bypass.md](web-pentest/techniques/01-waf-and-bypass.md) — WAF 指纹与单点绕过验证
- [web-pentest/techniques/05-ssrf-egress-proof.md](web-pentest/techniques/05-ssrf-egress-proof.md) — SSRF 外带证明（别停在"好像通了"）
- [ctf-website/techniques/06-file-attacks/file-upload-xxe-lfi.md](ctf-website/techniques/06-file-attacks/file-upload-xxe-lfi.md) — 上传 / XXE / LFI / 路径穿越

## I. 支付/订单/业务逻辑

- [ctf-website/techniques/12-payment/payment-bypass.md](ctf-website/techniques/12-payment/payment-bypass.md) — 支付绕过总览
- [ctf-website/techniques/12-payment/payment-logic.md](ctf-website/techniques/12-payment/payment-logic.md) — 支付业务逻辑攻击
- [ctf-website/techniques/15-mass-assignment/02-parameter-tampering.md](ctf-website/techniques/15-mass-assignment/02-parameter-tampering.md) — 参数篡改：价格/数量/优惠券
- [ctf-website/techniques/12-payment/payment-race-lost-update.md](ctf-website/techniques/12-payment/payment-race-lost-update.md) — 并发扣减丢失更新（重复领）
- [ctf-website/techniques/12-payment/payment-callback-async.md](ctf-website/techniques/12-payment/payment-callback-async.md) — 伪造/重放支付回调
- [ctf-website/techniques/12-payment/ticket-rush-api-reversing.md](ctf-website/techniques/12-payment/ticket-rush-api-reversing.md) — 抢购/票务接口状态机
- [ctf-website/techniques/14-idor/02-bac-business-logic.md](ctf-website/techniques/14-idor/02-bac-business-logic.md) — 功能级访问控制缺失（越权改单）

## J. 内网/域控/云/容器

- [ad-cloud/techniques/04-kerberos-paths.md](ad-cloud/techniques/04-kerberos-paths.md) — Kerberos 攻击路径速判
- [ad-cloud/techniques/05-adcs-esc-decision.md](ad-cloud/techniques/05-adcs-esc-decision.md) — ADCS ESC 判据：从 find 到 auth
- [ad-cloud/techniques/2026-esc17-wsus-relay.md](ad-cloud/techniques/2026-esc17-wsus-relay.md) — 战例：ESC17（HTTPS WSUS 中继）
- [ad-cloud/techniques/06-cloud-credentials-metadata.md](ad-cloud/techniques/06-cloud-credentials-metadata.md) — 云凭据与元数据（AK/SK）
- [ad-cloud/techniques/03-k8s-rbac-escape.md](ad-cloud/techniques/03-k8s-rbac-escape.md) — K8s RBAC → 逃逸
- [ctf-website/techniques/10-cloud/container-runtime-escape.md](ctf-website/techniques/10-cloud/container-runtime-escape.md) — 容器运行时逃逸打点
- [ad-cloud/techniques/07-failure-criteria.md](ad-cloud/techniques/07-failure-criteria.md) — AD/云失败判据（什么时候该停）
- [field_journal_seed-007_ntlm-relay-coercer.md](field_journal_seed-007_ntlm-relay-coercer.md) — 实战：NTLM Relay + Coercer 拿域管

## K. 游戏客户端/反作弊

- [general/techniques/cheating/01-memory-hacking.md](general/techniques/cheating/01-memory-hacking.md) — 内存搜索与修改（血量/金币）
- [general/techniques/cheating/02-packet-interception.md](general/techniques/cheating/02-packet-interception.md) — 封包拦截与修改
- [general/techniques/cheating/03-esp-wallhack-rendering.md](general/techniques/cheating/03-esp-wallhack-rendering.md) — 透视/ESP 渲染
- [apk-reverse/techniques/02-native/01-il2cpp-offset-discovery.md](apk-reverse/techniques/02-native/01-il2cpp-offset-discovery.md) — Unity IL2CPP 偏移发现
- [plugin/techniques/unity-il2cpp-bepinex.md](plugin/techniques/unity-il2cpp-bepinex.md) — BepInEx 加载器与插件面
- [anticheat/techniques/2026-eac-be-surface.md](anticheat/techniques/2026-eac-be-surface.md) — EAC/BE 客户端取证面（只读）
- [anticheat/techniques/2026-vanguard-boot-driver.md](anticheat/techniques/2026-vanguard-boot-driver.md) — Vanguard 驱动与 Secure Boot 取证

## L. 样本分析/病毒/勒索

- [malware-analysis/techniques/01-triage-and-ioc.md](malware-analysis/techniques/01-triage-and-ioc.md) — 分诊与 IOC（10 分钟出画像）
- [malware-analysis/techniques/02-unpacking-and-config.md](malware-analysis/techniques/02-unpacking-and-config.md) — 脱壳与配置提取
- [malware-analysis/techniques/03-behavior-timeline.md](malware-analysis/techniques/03-behavior-timeline.md) — 行为时间线：日志 → 可复述因果
- [malware-analysis/techniques/04-yara-sigma-engineering.md](malware-analysis/techniques/04-yara-sigma-engineering.md) — YARA/Sigma 规则工程
- [malware-analysis/techniques/05-sandbox-evasion.md](malware-analysis/techniques/05-sandbox-evasion.md) — 沙箱规避（为什么跑不出来）
- [field_journal_seed-002_go-malware-stripped.md](field_journal_seed-002_go-malware-stripped.md) — 实战：Go stripped + Garble 样本

## M. iOS/插件/Electron/托管运行时

- [ios/techniques/2026-jb-detection-surface.md](ios/techniques/2026-jb-detection-surface.md) — 越狱检测面：路径/URL scheme/dyld
- [ios/techniques/2026-frida-on-ios.md](ios/techniques/2026-frida-on-ios.md) — iOS 上 Frida 18+ attach 与 anti-Frida
- [ios/techniques/2026-macho-and-entitlements.md](ios/techniques/2026-macho-and-entitlements.md) — Mach-O 段/LC_* / entitlements
- [plugin/techniques/manifest-and-permissions.md](plugin/techniques/manifest-and-permissions.md) — 扩展清单与权限面（CRX/MV3/VSIX）
- [plugin/techniques/mv3-service-worker-isolation.md](plugin/techniques/mv3-service-worker-isolation.md) — MV3 service worker 与隔离世界
- [plugin/techniques/asar-and-mod-loaders.md](plugin/techniques/asar-and-mod-loaders.md) — asar / BepInEx / MelonLoader
- [managed/techniques/2026-wasm-license.md](managed/techniques/2026-wasm-license.md) — WebAssembly 授权面（wabt/wasm2c）
- [plugin/techniques/2026-v8-bytecode.md](plugin/techniques/2026-v8-bytecode.md) — bytenode / V8 字节码反编译

## N. 不知道从哪下手/卡住了

- [general/techniques/methodology/01-reverse-checklist-first-30-min.md](general/techniques/methodology/01-reverse-checklist-first-30-min.md) — 拿到样本的前 30 分钟清单（先做这个）
- [general/techniques/methodology/02-toolchain-decision-tree.md](general/techniques/methodology/02-toolchain-decision-tree.md) — 按信号选工具决策树
- [pe-reverse/techniques/15-decision/failure-criteria.md](pe-reverse/techniques/15-decision/failure-criteria.md) — 逆向决策失败判据：看到现象就换路
- [general/techniques/attack-network.md](general/techniques/attack-network.md) — 逆向攻击网（全局地图）
- [malware-analysis/techniques/06-failure-criteria.md](malware-analysis/techniques/06-failure-criteria.md) — 样本分析的停止条件
- [field_journal__index.md](field_journal__index.md) — 现场日志索引：按真实案例找同类问题
- [AI-USAGE.md](AI-USAGE.md) — 这个库该怎么给模型用（读法/引用纪律）

---

## 维护

- 加新文章：先看它属于哪一组（客户会怎么问它），加在该组 3–8 篇里；组内超过 8 篇就替换掉最不相关的。
- 本表**不替代** `README.md`：README 是文件全集索引（每篇都要在里面），本表是**问题入口**（只放最该先读的）。
- 判据：`python Tool/scripts/preflight.py --fast` 的「入口可达」项会验本表存在且被检索回退点名。
