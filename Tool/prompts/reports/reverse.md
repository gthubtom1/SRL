# reverse 报告模板

> 复制到 `evidence/<case>/report.md`。逆向结论必须有函数/偏移/状态字证据。

## 1 目标与授权
- 目标：<样本 / 版本 / sha256 / 架构 / 保护>
- 授权：<本地只读 / 是否允许动态 / 补丁回滚 / 时间窗>
- 范围外：<生产环境 / 真实授权服务器 / 分发补丁>
- 环境：<OS / Ghidra/x64dbg/Frida / 符号 / 时区>

## 2 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/preflight.json | <sha256> | `python Tool/skill/softseep/scripts/preflight-classify.py <sample>` | 0 | 平台/保护/节 |
| E02 | artifacts/triage.json | <sha256> | `python Tool/scripts/mal-triage.py --file <sample> --json` | 0 | 导入/字符串/overlay |
| E03 | artifacts/unpack.json | <sha256> | `python Tool/skill/malware-analysis/scripts/mal-unpack.py --file <sample> --json` | 0 | 壳/OEP/dump |
| E04 | artifacts/patch-verify.json | <sha256> | `python Tool/skill/softseep/scripts/patch-verify.py --file ... --manifest ...` | 0 | 补丁/回滚 |

## 3 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| 入口/符号 | 入口到关键节点路径可打印，命名有依据 | <实测> | E01/E02 | <结论> |
| 保护/壳 | 壳类型、OEP、IAT、节表可解释 | <实测> | E01/E03 | <结论> |
| 关键行为 | 网络/文件/注册表/加密调用有 xref 或动态证据 | <实测> | E02 | <结论> |
| 状态源 | 状态字/返回值/消费者三者一致 | <实测> | E02 | <结论> |
| 补丁闭环 | 最小补丁 + A/B/C 对照 + 可回滚 | <实测> | E04 | <结论> |
| 版本回归 | 新旧版指纹/偏移差可解释，唯一命中 | <实测> | E04 | <结论> |

## 4 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| 只有 `sub_xxx`，无字符串/常量 | <yes/no> | E01/E02 | 转符号恢复/动态断点 |
| 只改 UI/`license_type`，状态源未动 | <yes/no> | E02 | 回状态源，不写闭环 |
| dump 后节仍高熵/IAT 坏 | <yes/no> | E03 | 继续找 OEP 或运行期取功能 |
| 多命中/偏移不可解释 | <yes/no> | E04 | 重新分析，不硬套 AOB |
| 补丁后崩溃/签名失败 | <yes/no> | E04 | 回滚并按 02/09 换路 |
| 无回滚/无备份 | <yes/no> | E04 | 不交付 |

## 5 影响与边界
- 影响：<可绕过/可读写的状态 / 可复现的功能路径>
- 边界：<本地样本 / 未连真实服务 / 未覆盖其它版本>
- 误报风险：<调试器/反调试造成的假路径、字符串误判>
- 未覆盖：<未分析的模块、未验证的授权服务端>

## 6 修复建议（厂商视角）
1. 关键状态放服务端或受完整性保护的区域，客户端只做展示。
2. 启用代码签名/ASLR/DEP/CFG，检测调试器与内存补丁，校验自身哈希。
3. 授权协议使用短期票据、设备绑定与重放保护；敏感分支做混淆但不要依赖单一状态字。
4. 发布可回滚补丁与版本 manifest，保留 AOB/符号映射便于跨版本回归。

## 7 复跑命令
```bash
python Tool/skill/softseep/scripts/preflight-classify.py evidence/<case>/artifacts/target.bin
python Tool/scripts/mal-triage.py --file evidence/<case>/artifacts/target.bin --json
python Tool/skill/softseep/scripts/patch-verify.py --self-test
```
