# ROADMAP

> 只写两件事：**现在能做什么**、**下一步做什么**。规划过程已移出仓库（`work/plans/`，gitignore）。
> 深度契约见 `docs/DOMAIN-SPEC-v2.md`；门禁 `python Tool/scripts/preflight.py`。

## 现在能做什么

### 一、客户端授权与二开（成熟）

- **阶段零 分析**：`00-analysis` —— 结构/壳/权威/钥匙全貌，出可复现报告与可行性裁定。
- **阶段① 旁路**：`01-gate-bypass` —— 补丁 / 代理 DLL / 重打包 / 注入器四选一，交付能用的成品。
- **阶段② 改 UI**：`02-ui-rebrand` —— 品牌替换、联系方式与推广位清除，功能不破。
- **阶段③ 接授权**：`03-license-hookup` —— 本地 HMAC 或在线票据，卡密/到期/机器码/功能位。
- **阶段④ 追版**：`04-version-migrate` —— AOB 特征跨版本滑窗对齐，一条命令重建。
- **阶段⑤ 后端复刻**：`05-backend-rebuild` —— 仅在 T2/T3 触发；API 面测绘 → 签名复算 → 协议复刻。

### 二、逆向手艺（成熟）

- Windows/PE 全链路：判壳 → 静态 → 动态 → 脱壳 → 符号恢复 → 补丁工程 → 反调试对抗。
  入口 `softseep`，参考卷 10 篇（`Tool/skill/softseep/references/`）。
- Android：`apkseep`（43 篇参考 / 55 个脚本）+ `unpack-loop` + `binary-diff`。
- IDA / radare2 / x64dbg 三条工具通道，统一走 `Tool/scripts/tool-run.ps1`（MCP 优先，headless 次之，GUI 最后）。

### 三、十一个域（可独立开打）

每域都有：判据表 / 失败判据表 / 模型常见失误 / 真实案例走查 / 2–4 个可跑脚本（`--self-test` 离线绿）
/ 3–5 个案例（≥1 个真跑）/ 6–10 篇 KB / 20–30 张任务卡 / 路由片段。

| 域 | 入口 | 一句话判据 |
| :-- | :-- | :-- |
| Web/API | `web-pentest` | 对照实验 + 原始报文 + 影响面，三者齐才算确认 |
| 二进制利用/密码学 | `pwn-crypto` | 本地 10 次 ≥9 次命中；或回代等式成立 |
| 固件/IoT | `firmware-iot` | 能进 shell / 服务真监听 / 漏洞可复现 |
| 内网/AD/云 | `ad-cloud` | 拿到可复现凭据或权限提升的客观输出 |
| 协议复刻 | `protocol-plugin` | 能构造抓包之外的新请求并闭环 |
| 插件/扩展/Mod | `plugin-targets` | 入口 / 关键逻辑 / 数据来源 / 最小可改单元四件齐 |
| 取证/iOS·macOS | `forensics-mobile` | 时间 / 主体 / 动作 / 对象四要素可还原 |
| 恶意样本 | `malware-analysis` | 行为时间线 + IOC + 可验证 YARA/Sigma |
| 供应链 | `supply-chain-security` | 可达漏洞有 PoC，或投毒链有证据 |

## 下一步（按优先级）

1. **真实任务演练常态化**：每域每季度用真实目标跑一次，结论回写 `Tool/cases/`（`evidence_kind=real`，`repro.status=recorded`）。
2. **案例库扩容**：优先补真实目标案例（当前每域至少 1 个真跑，目标 3 个）。
3. **任务卡执行率**：`Tool/prompts/domains/*.md` 已是「触发词+前置+步骤+判据+失败判据+reference」六段卡；下一步把高频卡做成可执行剧本（命令 + 退出码）。
4. **脚本统一 CLI**：`--self-test` 已全覆盖；下一步统一 `--json/--root/--out` 契约与退出码语义。
5. **KB 反哺**：现场日志（`kb/field_journal_*`）满 3 篇同主题即沉淀为 `techniques/` 一篇。
6. 延迟项与未排期能力见 `docs/DEFERRALS.md`（台账，不计入「能做什么」）。
7. **5 分钟快速路径**：`docs/QUICKSTART.md`（新 agent/换会话先看）。
8. **上游同步**：`docs/UPSTREAM.md` + `Tool/scripts/upstream-delta.py`，每季度跑一次内容差分。
