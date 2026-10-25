---
name: seep-router
description: "还不确定这属于哪个领域时先读我/初步分析这个/先判断能不能做/该走哪个方向/我该准备什么/能不能去广告改会员 (.exe/.apk/.html/.bin/.pcap/.img 任意载体)。只做思考层：判型 → 选域 → 给上限 → 说缺什么 → 指路到具体领域技能。任何任务的第一步都先过这里。"
license: MIT
---

# seep-router —— 思考层（判型 / 选域 / 上限 / 缺什么）

> **本技能只做判断，不做具体手艺。** 判断完立刻按下面的表去读对应领域技能。
> 事实只有一处：**M1–M4 的定义、必问三件、载体→域 映射，只在本文件。** 其他技能一律引用这里，不复制。

## 第 1 步 · 判型三问（30 秒内必须回答）

1. **这是什么载体**（按扩展名/魔数/容器判断，不看用户怎么说）
2. **有没有保护**（壳/加固/混淆/加密/签名校验）
3. **关键判定在哪**（本地文件 / 注册表 / 服务端 / 硬件）

> 只做**零风险只读探测**（哈希、大小、魔数、头信息）。**不许**为了判型就运行它、解包它、改它。

## 第 2 步 · 载体 → 域（选完立刻读该域 SKILL.md）

| 载体 / 场景 | 去读 |
| :-- | :-- |
| `.exe .dll .sys .so .elf .dylib .bin`（含 .NET/Go/Rust/Electron-PC/Unity-PC/wasm） | `Tool/skill/softseep/SKILL.md` |
| `.apk .aab .xapk .dex`、Unity-Android / IL2CPP 改包 | `Tool/skill/apkseep/SKILL.md` |
| `.html .js .php .har`、网站/接口、前端 JS 加密混淆 | `Tool/skill/web-pentest/SKILL.md` |
| `.bin .img .trx .squashfs .ubi`、路由器/摄像头/NAS | `Tool/skill/firmware-iot/SKILL.md` |
| `.pcap .pcapng .proto`、私有协议、封包构造 | `Tool/skill/protocol-plugin/SKILL.md` |
| 二进制利用 / 密码学（栈堆溢出、ROP、RSA/AES/PRNG） | `Tool/skill/pwn-crypto/SKILL.md` |
| `.vmem .raw .dd`、iOS IPA/Mach-O、证书/钥匙串 | `Tool/skill/forensics-mobile/SKILL.md` |
| 可疑样本（任意载体，要判"是不是病毒"） | `Tool/skill/malware-analysis/SKILL.md` |
| 仓库/依赖/CI/制品签名 | `Tool/skill/supply-chain-security/SKILL.md` |
| **任何载体但已加壳/虚拟化/反调试** | 先读该载体域，+ `Tool/skill/unpack-loop/SKILL.md` |

**跨域很常见**：先读主域，再按需读辅域（例：安卓 Unity 包 = apkseep 主 + unpack-loop 辅）。
**判不出载体**：只问一个区分性问题（"这东西能直接运行，还是一堆文件？"），不猜。

## 第 3 步 · 给上限（唯一口径，四句话）

| 级 | 客户语言 | 依据门槛 |
| :-: | :-- | :-- |
| M1 | **只能看懂结构** | ≥1 条 E1 观察 |
| M2 | **能改到能用** | 改动类结论 ≥E2（命令+期望+跑过两次一致） |
| M3 | **能完全自己接管** | 关键结论 ≥E3（交叉验证）或 E4（端到端） |
| — | **现在做不了** | 必须给 BLK 码 + 两条出路 |

**一次封顶**（命中任一 ⇒ 最多 M1，并写清算什么封顶）：
无授权 / 关键在服务端 / 需硬件而客户没有 / 需运行而客户拒绝 / 强加固无法还原 / 加密无密钥 / 置信度低。

**承诺不可回收**：先说了 M2 后来只能 M1 ⇒ 必须发降级通知（`case_state.py downgrade`），不许静默降级。

> 别的域若用 T/L 等其它刻度，一律换算回 M 级再对客户说。**不向客户抛代号**。

## 第 4 步 · 必问三件（缺就停下来问，对话里列 A/B/C）

| 序 | 问什么（客户语言） | 为什么问 |
| :-: | :-- | :-- |
| 1 | 许可 / 凭据：这个需要卡密、账号或加密狗吗？你有吗？ | 有→可做在线校验对比；没有→只能离线判定或止步 M1 |
| 2 | 运行许可与环境：允许在本机运行吗？有可回滚的虚拟机/快照吗？ | 加密/加固目标不运行拿不到真代码；但运行有系统副作用 |
| 3 | 样本完整性：有完整原件/现成抓包/一次真实请求响应吗？ | 不完整时任何结论都不可信 |

**选项必须写"选了会怎样"**（`A 有 → 走在线对比，能到 M2` / `B 没有 → 走离线，最多 M1` / `C 我不确定 → 我先查有没有校验痕迹`）。
**不弹窗**：只在对话里列，客户回一个字母。用 `case_state.py ask` 落账。

## 第 5 步 · 指路（判断完必须做）

1. 读对应域 SKILL.md（上表）
2. 用 `case_state.py init` 建案（若还没有），把判型结论写进账本
3. 首答三要素自检：`case_state.py answer --template` / `--check`
4. 卡住时按码出失败五段：`case_state.py block --code BLK-5`
5. 交付前：`report --check` + `recheck`

## 停手条件（命中即停，别硬做）

| 条件 | 动作 |
| :-- | :-- |
| 同一路线失败 2 次 | 换路线或出报告（禁止第 3 次同样尝试） |
| 需要改系统级配置/装驱动/装反作弊 | 停，说明原因，给两条替代 |
| 需要客户手里的东西（卡密/账号/狗/设备/抓包） | 停，列 A/B/C |
| 需要运行目标而这会加载内核驱动 | 停，先要客户明确同意 |
| 上限已降到 M1 但仍被要求"做出成品" | 说明天花板原因，不硬撑 |

## 不做什么（防止变成第二个"万能技能"）

- 不写具体域的方法论（那是各域的事）
- 不复制各域的判据表（只指路）
- 不在这里定义证据等级/结论等级之外的东西（证据分级见各域与 `case_state.py`）

## 子技能（按需读，不常驻）

判断完、选定域之后，需要时再读这些（都在 `Tool/skill/_pending/`，不占常驻上下文）：

- `_pending/00-analysis/SKILL.md`
- `_pending/00-triage/SKILL.md`
- `_pending/01-gate-bypass/SKILL.md`
- `_pending/02-ui-rebrand/SKILL.md`
- `_pending/03-license-hookup/SKILL.md`
- `_pending/04-version-migrate/SKILL.md`
- `_pending/05-backend-rebuild/SKILL.md`
- `_pending/ad-cloud/SKILL.md`
- `_pending/binary-diff/SKILL.md`
- `_pending/doc-hygiene/SKILL.md`
- `_pending/ida-reverse/SKILL.md`
- `_pending/llm-security/SKILL.md`
- `_pending/plugin-targets/SKILL.md`
- `_pending/pm-plan/SKILL.md`
- `_pending/signin-automation/SKILL.md`
- `_pending/site-clone/SKILL.md`
- `_pending/version-migration/SKILL.md`
