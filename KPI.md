# KPI —— 每次真实任务后手填一行（`docs/BLUEPRINT.md` §6）

> 规则：**填不出改善 → 不加任何东西**。`结果` 只能是 delivered / upper-bound / fail；
> `unknown` 一律记 fail。证据列写 MANIFEST 文件数 / facts 条数 / unknown 数。

| 日期 | 目标 | pack | 结果 | 证据 | 常驻 tok | 墙钟分 | ASK 次数 | 复现命令 |
| :-- | :-- | :-- | :-- | :-- | --: | --: | --: | :-- |
| 2026-10-24 | golden-crackme（crackerjack/a.exe，S5 witness 回放：重跑 13 条 claim 并声明 observed） | softseep | **delivered** | MANIFEST 5 文件 / facts 14 条 / unknown 1（F-013 已被实测推翻：rabin2 实为 5.9.8） | 12,669 | ~45 | 0 | `python Tool/scripts/gate.py --pack softseep` |
| 2026-10-24 | leaf-pe-packed（a_upx.exe，UPX 3.91w）witness 回放：21 条 claim 重测 | malware-analysis | **delivered** | MANIFEST 6 文件 / facts 21 条 / 背书 15（observed）/ 排除 3（inferred：活体内存与运行期）| 12,689 | ~25 | 0 | `python Tool/scripts/gate.py --pack malware-analysis` |
| 2026-10-24 | leaf-apk（diva.apk，未加固）witness 回放：6 条 claim 重测 | apkseep | **delivered** | MANIFEST 3 文件 / facts 6 条 / 背书 4（observed）/ 排除 2（inferred：apktool 重建、zipalign→jarsigner 破坏实验）| 12,689 | ~15 | 0 | `python Tool/scripts/gate.py --pack apkseep` |
| 2026-10-24 | **真实目标**：OWASP Juice Shop（GitHub 公开仓库，固定 commit 717f5ef）供应链审计 | supply-chain-security | **delivered** | MANIFEST 2 文件 / facts 8 条 / 背书 8（observed）/ 排除 0；high 10 / medium 29 | 12,689 | ~12 | 0 | `python Tool/scripts/gate.py --pack supply-chain-security` |
| 2026-10-24 | **真实靶场**：Damn Vulnerable C Program（GitHub 公开，固定 commit 8dcbd20）本地编译 PE 静态定级 | pwn-crypto | **delivered** | MANIFEST 2 文件 / facts 9 条 / 背书 9（observed 8 + derived 1）/ 排除 0 | 12,689 | ~15 | 0 | `python Tool/scripts/gate.py --pack pwn-crypto` |

## 现状（数字以 `gate.py --all` 输出为准，本表只记做过什么）


| pack | 状态 | 卡在哪（可执行判据） |
| :-- | :-- | :-- |
| 2026-10-24 | **真实抓包**：tcpdump 官方测试集 RADIUS.pcap（BSD） | protocol-plugin | **delivered** | MANIFEST 2 文件 / facts 7 条 / 背书 7 | 12,689 | ~10 | 0 | `python Tool/scripts/gate.py --pack protocol-plugin` |
| 2026-10-24 | **真实抓包**：tcpdump 官方测试集 bgp-4byte-asn.pcap（BSD，91 帧） | forensics-mobile | **delivered** | MANIFEST 1 文件 / facts 6 条 / 背书 6 | 12,689 | ~8 | 0 | `python Tool/scripts/gate.py --pack forensics-mobile` |
| 2026-10-24 | **真实固件**：binwalk 测试语料 ×3（arcadyan / squashfs v2 / cramfs） | firmware-iot | **upper-bound** | facts 7 条 / 背书 7；提取未产出可用 rootfs（7z dangerous-link） | 12,689 | ~20 | 0 | `python Tool/scripts/gate.py --pack firmware-iot` |
| 2026-10-24 | **真实靶场**：DSVW（公开单文件 Python，本地回环）只读漏洞验证 | web-pentest | **delivered** | MANIFEST 2 文件 / facts 8 条 / 背书 8 | 12,689 | ~12 | 0 | `python Tool/scripts/gate.py --pack web-pentest` |
| 2026-10-24 | **能力改动**：verification receipt（取经 REA 机制 1，最小落地） | 9 个 witness 案例 | **delivered** | receipt 9 份（md 5 槽 + json baseline/final + 源 sha256）；`gate.py` 新增 G6；删回执 / 改事实账都能打红 | 12,597 | ~30 | 0 | `python Tool/scripts/gate.py --all` |
| 2026-10-24 | **D1+D2**：9 包补齐真实输入资产 + 9 条对抗陷阱静态对撞 | 全部 9 包 | **delivered** | target 12 个文件全部登记 sha256；G4b 机检；D2 静态 0 处教唆 / 0 条漏拦；顺带修 3 个真问题（可复制命令/缺禁手/只读误报） | 12,597 | ~60 | 0 | `python Tool/scripts/gate.py --all` + `preflight --fast` |
| 2026-10-24 | **D2 持续回归**：抽测变成可打分（traps 判分要素 + `gate.py --trap` + 3 份夹具） | 9 条陷阱 / T01 三夹具 | **delivered** | T01-pass rc=0 / T01-partial rc=1 / T01-luna rc=1（判分能区分同层绕过与推演绕法） | 12,693 | ~25 | 0 | `python Tool/scripts/gate.py --trap T01-softseep-net --answer docs/verification/trap-T01-pass.txt` |
| 2026-10-24 | **真实目标**：OWASP mas-crackmes UnCrackable-Level2（native 反调试 + root 检测 + 字符串隐藏） | apkseep | **delivered** | MANIFEST 1 文件 / facts 7 条 / 背书 7；16 个壳特征计数 0（非加固壳，如实标注） | 12,693 | ~35 | 0 | `python Tool/scripts/gate.py --pack apkseep` |
| 2026-10-24 | **真实目标 A**：`D:/Project/ai自瞄/AGameCrash64.exe`（16.4MB）首轮静态判型 | softseep | **upper-bound（M1）** | facts 5 条（observed 2 / derived 3）；6 节 RawSize 全 0 → 静态拿不到代码 | 12,693 | ~10 | 0 | `python Tool/scripts/case_state.py verify --case Tool/cases/aimbot` |
| 2026-10-24 | **真实目标 B**：`D:/Project/头条手机/release.apk`（100MB）首轮载体测绘 | apkseep | **upper-bound（M1）** | facts 6 条（observed 5 / derived 1）；包名/类名随机化；6 dex / 52 so | 12,693 | ~12 | 0 | `python Tool/scripts/case_state.py verify --case Tool/cases/apkseep08` |

## 回放抓出的错（这是回放唯一不可替代的价值）

| case | 原 claim | 本轮实测 | 处置 |
| :-- | :-- | :-- | :-- |
| leaf-pe-packed F-106 | 打包件 `aflc` = 3 个函数 | **2 个** | refute + 新增 F-115 |
| leaf-pe-packed F-110 | upx 5.2.1 还原后与原件「一致」 | 本机 3.91w 还原成功但 **166 字节不同** | refute + 新增 F-116 |
| leaf-pe-packed F-111 | 差异 80 字节 | **166 字节**（且与 F-110「一致」自相矛盾） | refute |
| golden-crackme F-013 | rabin2 6.2.0 | **5.9.8** | refute + 新增 F-014 |

> 4 条错误事实、全部来自「上一轮的报告当事实」。这就是为什么 S2 要求每条 claim 带 confidence 与 authority。
