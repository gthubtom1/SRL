# _pending 归档技能索引（16 个）

> **这里不是技能索引**——这些技能不部署、不预载，模型不会自动发现它们。
> 需要时按路径 `read`：`Tool/skill/_pending/<名字>/SKILL.md`。

| 名字 | 行数 | 一句话 |
| :-- | --: | :-- |
| `00-analysis` | 350 | 【00｜阶段零·分析透彻出可复现报告】在动任何交付物之前，把目标彻底摸清：结构、壳、运行期行为、授权权威在哪、钥匙在哪、能不能赢。产出一份每条结论都带证据编 |
| `00-triage` | 92 | 【00a｜快筛·20 分钟内出目标画像卡】只静态：载体/保护/授权权威/改动面/检测器/交付壁垒，产出 report/triage.md + 六字段卡。不动 |
| `01-gate-bypass` | 159 | 【01｜第一阶段·旁路卡密出可用成品】把任意软件（PE/APK/游戏辅助等）的卡密授权旁路掉，让它能正常进入原版主界面（或游戏内菜单）并且全部功能可用。负责 |
| `02-ui-rebrand` | 136 | 【02｜第二阶段·改 UI 与去品牌】在 01 阶段已经能用的产物上做二开：清点页面/控件/文案/图标，替换成自己的品牌与视觉，移除原作者联系方式、推广位、 |
| `03-license-hookup` | 159 | 【03｜第三阶段·接自己的授权平台】把产物接到你自有的授权系统：卡密校验、到期时间、机器码绑定、功能位控制，支持本地离线（HMAC）与在线（你的 API + |
| `04-version-migrate` | 137 | 【04｜第四阶段·跨版本追版】原作者更新了版本时用。读旧版版本账（manifest.json）里的位点特征码，在新版二进制里滑窗对齐，同时迁移 UI 资产与 |
| `05-backend-rebuild` | 228 | 【05｜阶段五·后端复刻（仅 T2/T3 触发）】客户端依赖的不只是授权，还有业务 API / 服务端能力 / 远程下发的脚本容器时，把后端也反推并重建出来 |
| `binary-diff` | 151 | 【二进制差分/补丁分析】跨版本符号迁移、函数匹配（BinDiff/Diaphora/ghidriff）、AOB 签名迁移、补丁差分与 N-day/1-day |
| `doc-hygiene` | 198 | 【文档治理】整理/清理文档、文档太乱太旧、过期数字、重复入口、遗留盘点（TODO/待补）、交接、换模型接手；tidy up docs、clean up do |
| `ida-reverse` | 100 | 当用户要求“使用IDA Pro进行逆向分析”、分析指定可执行文件/库、反编译函数或通过 IDA Pro 分析目标时触发此技能。能够全自动唤醒 IDA Pro |
| `llm-security` | 287 | 【LLM / AI Agent 安全】对 LLM 应用、RAG、Agent、MCP 工具链与提示词/技能包做授权安全评估：直接/间接提示注入、工具滥用、记忆 |
| `plugin-targets` | 214 | 【插件/扩展/Mod】浏览器扩展（MV2/MV3）、IDE 插件（VSIX/JetBrains）、Electron asar、Unity BepInEx/M |
| `signin-automation` | 264 | 账号任务自动化的六个原语：会话池（多账号隔离）、定时通知（cron/幂等/重试上限）、验证码三分支、滑块缺口、旋转角度、TLS 指纹。附带 OPSEC 参数 |
| `site-clone` | 223 | 【网站 1:1 复刻】授权+同源白名单+≤2 rps 下用 Playwright 抓路由/资产/API 与 DOM 快照做离线副本，按 6 条机检判据给 P |
| `version-migration` | 92 | 客户端跨版本增量追版与特征迁移专项技能。当目标软件更新（如 6.8 升级至 6.9）、曾经逆向过的旧版本已有分析报告/补丁/Hook 脚本，需要快速适配新版 |

## 已删除（内容重复，能力不损失）

- `client-license-validation-bypass` → 内容在 `Tool/skill/softseep/references/license-validation.md`
- `ad-cloud` → 域内 AD/云原生部分在 `Tool/skill/web-pentest` 与 `supply-chain-security` 的 references；
  其独有的「判据表 / 阶段 A–D / 验收清单」框架仍可用 `git log -- Tool/skill/_pending/ad-cloud` 取回

## 要复活某个（三件事）

1. 描述改成**用户会说的原话 + 文件后缀**（名词式描述不会被选中）
2. `cp -r` 到 `~/.pi/agent/skills/`（部署才进技能列表）
3. `Tool/config/trigger-probes.json` 加一句真实说法 + 期望命中
