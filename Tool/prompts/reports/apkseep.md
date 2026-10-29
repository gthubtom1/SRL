# apkseep 报告模板

> **客户视角五段（必须全在，缺一不算交付）**：`结论 / 已确认 / 仍未知 / 下一步 / 复查` 按标题文字匹配；
> 「结论」不超过 3 行，「已确认」至少含一个 `E-` / `C-` / `F-` 编号。
> 复制到 `work/<case>/report.md`。只有 `observed` 才能写入「已确认」；`inferred` 与 `unverified` 留在未知或待验证项。

## 1 结论（≤3 行：能不能用 / 到哪一步 / 卡在哪）
- 到哪一步：<只能看懂结构 | 能改到能用 | 能完全自己接管 | 现在做不了>
- 卡在哪：<壳/签名/设备/服务端权威等一句话 + 证据编号；没有卡点写「无」>
- 能不能用：<只按已有证据说一句；没在目标环境跑过就写「未验证」>

## 2 已确认（每条：客户能听懂的一句话 + 证据 ID + 强度：强 / 中 / 弱）
- <Manifest、DEX/SO、壳或关键调用路径的可复核结论>（`E-001`；强：命令、输入 SHA256 与输出齐全）
- <静态与动态或两条独立路径一致的结论>（`E-002`；强：两路独立验证一致）
- 单次日志、字符串命中或只在截图里出现的内容不进入本段。

## 3 仍未知（每条：未知什么 + 为什么未知 + 缺什么才能知道）
- <未知项>｜为什么未知：<设备/账号/壳/服务端/证据缺口>｜还缺：<补什么才能知道>
- <未知项>｜为什么未知：<同上>｜还缺：<同上>

## 4 下一步（省事路线 / 彻底路线 / 不建议做的事，各一条）
- 省事路线：<最小动作 + 能确认什么 + 预计代价>
- 彻底路线：<要补的动态证据、补丁闭环或多版本验证 + 代价>
- 不建议做：<会混淆变量、越过服务端权威或破坏原件的路线及原因>

## 5 怎么复查（复查单路径 + 关键重放命令 + 期望看到什么）
- 复查单：`python Tool/scripts/case_state.py recheck --case work/<case>`
- 重放：<本域只读或隔离命令；Windows cmd 与 PowerShell 可直接粘贴>
- 期望：<关键字段/哈希/前台 Activity/功能对照>；先核对输入与设备产物 SHA256 一致。

## 6 目标与授权
- 目标：<APK/AAB/XAPK/DEX/SO 路径、包名、版本、SHA256、ABI>
- 授权：<仅静态 / 自有设备动态 / 重打包 / 安装 / 网络条件 / 时间窗>
- 范围外：<生产账号、真实支付、服务端伪造、分发补丁、未授权设备>
- 环境：<OS、JDK、Android SDK/Build Tools、adb、Frida、设备或模拟器>

## 7 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/doctor.json | <sha256> | `python Tool/skill/apkseep/scripts/doctor.py --json` | <rc> | 能力与缺件 |
| E02 | artifacts/java2c.json | <sha256> | `python Tool/skill/apkseep/scripts/java2c_probe.py --apk <apk> --json` | <rc> | DEX/native 画像 |
| E03 | artifacts/device.json | <sha256> | `python Tool/skill/apkseep/scripts/install_test.py --apk <apk>` | <rc 或 not-recorded> | 安装/产物身份 |
| E04 | artifacts/diff.json | <sha256> | `python Tool/skill/apkseep/scripts/apk_diff.py <in.apk> <out.apk> --summary` | <rc> | 改动范围 |

## 8 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| 原件身份 | 输入、工作副本与设备产物 SHA256 可追溯 | <实测> | E01/E02/E03 | <结论> |
| 壳/保护归类 | 有入口类、DEX/SO 与运行证据，不只凭关键词 | <实测> | E02 | <结论> |
| 关键层归属 | Java/DEX、native、Dart/Unity 或服务端由证据区分 | <实测> | E02/E03 | <结论> |
| 补丁最小性 | 单变量、对照组、改动范围与头部重算均可复核 | <实测> | E04 | <结论> |
| 运行闭环 | 安装成功之外还验证目标功能与相邻功能 | <实测> | E03 | <结论> |
| 可重复性 | 同一输入与环境重复结果稳定 | <实测> | E03/E04 | <结论> |

## 9 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| 只凭 `StubApp` 等关键词判加固 | <yes/no> | E02 | 回到入口类、SO 与结构证据 |
| 解析器通过就认为抽取方法体存在 | <yes/no> | E02 | 查 stub/emptied 分布并转脱壳链 |
| 安装成功就认为目标改动生效 | <yes/no> | E03 | 核对设备哈希、前台 Activity 与目标功能 |
| 补丁后崩溃或相邻功能回退 | <yes/no> | E03/E04 | 回滚并重新判层 |
| 广告或权益由服务端权威控制 | <yes/no> | E02/E03 | 停客户端补丁，写边界 |
| 无原件哈希、对照组或回滚材料 | <yes/no> | E01/E04 | 不交付 |

## 10 影响与边界
- 影响：<可读结构 / 可修改层 / 已验证的功能路径>
- 边界：<仅静态 / 自有设备 / 未连真实账号或服务>
- 误报风险：<反调试导致的环境失败、字符串误判、旧产物残留>
- 未覆盖：<未验版本、ABI、设备、商业加固与服务端链路>

## 11 修复建议（厂商视角）
1. 将权益与关键状态放在服务端，客户端只消费短期、绑定设备的票据。
2. 对 DEX/SO 与资源做完整性校验，检测调试与内存补丁，并保留可复核的崩溃遥测。
3. 敏感逻辑避免单点布尔门；对跨层返回值与 UI 消费点做一致性校验。
4. 升级链强制签名、防回滚与 TLS，发布 SBOM、可复现哈希和明确的支持版本。

## 12 复跑命令
```bash
python Tool/skill/apkseep/scripts/doctor.py --json
python Tool/skill/apkseep/scripts/java2c_probe.py --apk work/<case>/artifacts/target.apk --json
python Tool/skill/apkseep/scripts/dex_dump_validate.py work/<case>/artifacts/dumps --json
python Tool/skill/apkseep/scripts/apk_diff.py work/<case>/artifacts/original.apk work/<case>/artifacts/patched.apk --summary
```
