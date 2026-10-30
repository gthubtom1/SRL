# 组件来源与集成落点

本页记录来源、许可证、实际文件和接入边界。产品需求见 [REQUIREMENTS](../../REQUIREMENTS.md)，当前验证结果见 [CURRENT-STATE](../../docs/CURRENT-STATE.md)。来源记录不等于当前环境可用，也不是未来功能清单。

## 1. 组成与运行时

| 组件 | 源码位置 | 部署或消费位置 | 核验方式 |
|---|---|---|---|
| 正式领域 | `Tool/skill/<domain>/pack.json` 与 `SKILL.md` | AgentRoot下的`skills/<domain>/` | pack注册、父技能发现、任务调用分别验证 |
| 域内子技能 | `Tool/skill/<domain>/subskills/<name>/` | 随父域完整部署，按相对路径读取 | 导入/部署/verify及父子资源引用检查 |
| 横切方法 | `Tool/skill/seep-router/`、`Tool/skill/unpack-loop/` | 同名技能目录 | 不是额外业务领域，不替代载体域方法 |
| 行为与提示词 | `Tool/prompts/AGENTS.md`、`SEEP.md`、`extensions/` | AgentRoot对应位置 | 受管块、文件身份、实际装配分别检查 |
| 项目与证据 | `Tool/scripts/project_*.py`、`manager_state.py`、`case_state.py` | 源码运行时 | 项目/version/run、原始输出、验收和恢复 |
| 运行时定位 | `Tool/scripts/lib/runtime_root.py`与安装器调用的注册入口 | AgentRoot的`seep-runtime.json` | 由现有解析器核注册与源码，不靠当前工作目录猜路径 |
| Seep MCP | `Tool/mcp/seep_mcp_server.py`、`seep_contract.py` | 注册的解释器和源码入口 | initialize、tools/list、真实动作和结果语义 |
| 工具与通道 | `Tool/config/tool-capabilities.json`、`tool-runtimes.json`、`tool-install.json` | 实际发现或安装的工具 | 声明、发现、探活、执行与任务结果分开 |

AgentRoot按安装参数和环境解析，不固定为某台机器目录。当前技能与MCP列表从实际注册和加载结果取得，不在本页维护第二套数量快照。

## 2. 直接上游与保留的第三方来源

以下来源记录在旧文档改写时被误删；本次保留其来源职责，修正过期库存和运行宣称。

| 来源 | 仓库 | 许可证来源 | 本地位置与用途 |
|---|---|---|---|
| 工作台直接上游 | [angusdevgo/Seep-Reverse-Lab](https://github.com/angusdevgo/Seep-Reverse-Lab) | 以对应提交的LICENSE及引入文件声明为准 | git upstream；选择性吸收PE方法、跨版本AOB和Modern LSPosed，不覆盖二开提示词与状态底座 |
| apk-reverse | [newliver666/apk-reverse](https://github.com/newliver666/apk-reverse) | 本地镜像MIT声明 | `Tool/upstream/apk-reverse/`；Android方法、DEX补丁、测试与参考，实际适配位于`Tool/skill/apkseep/` |
| Open-tgtylab | [GeniusHu-tgty/Open-tgtylab](https://github.com/GeniusHu-tgty/Open-tgtylab) | 本地镜像GPL-3.0声明 | `Tool/upstream/open-tgtylab/`；历史实验方法和信号检索参考，不作为当前执行纪律来源 |
| Open-ReverseLab | [LING71671/open-reverselab](https://github.com/LING71671/open-reverselab) | 本地镜像GPL-3.0声明 | `Tool/upstream/open-reverselab/`和`Tool/mcp/Tool/reverselab/`；KB、boards和工具参考，和morluto/rea是不同项目 |
| pi-cmd-guard | [gthubtom1/agent-plugins](https://github.com/gthubtom1/agent-plugins/tree/main/plugins/pi/cmd-guard) | MIT | `Tool/prompts/extensions/cmd-guard.ts`、规则JSON与TOOL-CHAIN；vendored后按本仓边界适配 |
| retry-level | [gthubtom1/agent-plugins](https://github.com/gthubtom1/agent-plugins/tree/main/plugins/pi/retry-level) | MIT | `Tool/prompts/extensions/retry-level.ts`；宿主重试设置与显示，须按当前Pi接口验证 |
| pi-seep-ext 0.3.1：persona / rewind | [固定提交 2742f417d4dcf275a9a57bdf654af4a53ff25ddf](https://github.com/gthubtom1/agent-plugins/tree/2742f417d4dcf275a9a57bdf654af4a53ff25ddf/plugins/pi/pi-seep-ext) | 根 `LICENSE`：MIT，Copyright (c) 2026 gthubtom1 | `Tool/prompts/packages/pi-seep-ext/`（原两扩展 + 其 `lib/` 依赖），安装时同步到 `<AgentRoot>/packages/pi-seep-ext` |

这个包基于上游固定提交保留目录人设、每会话选择、状态栏和官方 `navigateTree` 回退实现。工作台副本补充提示词合载与设置保存的兼容处理；`remote.ts` 不分发，根 manifest 的 cmd-guard、retry-level、prompt-compat 不重复加载。原始指纹、当前副本指纹及逐文件改动理由统一记录在 `Tool/prompts/packages/pi-seep-ext/UPSTREAM.json`；`rewind.ts` 保持上游原文。

| 兼容处理 | 最终行为 |
|---|---|
| 系统提示词与正文分开处理 | 只修改具名系统 section，不删除或替换用户、助手、工具结果中的标签示例、代码、附件 |
| `cached` 与 `every-turn` | 两种模式均保留；cached 使用 SDK 系统提示词增量，every-turn 在模型请求阶段使用宿主的重放接口生成完整系统检查点，保留工具声明、SEEP、规则与项目上下文 |
| 人设优先级 | 本对话显式选择（含关闭）优先，其次是可用目录默认人设，最后才是 `PERSONALITY.md`；回退不恢复已经关闭的旧选择 |
| 规则和热更新 | `generic-rules` 由 `load-system-prompt` 统一管理，保留项目级优先；文件修改或移除在后续请求生效 |
| 配置保存 | 模式切换和徽标设置原子保存、未知字段保留；坏配置和写入失败返回错误，取消不写入，不假报成功 |

上一轮候选曾停用 `every-turn`，该降级方案已被上述合载实现替代，不是最终行为。兼容验收脚本为 `setup/test_persona_rewind_sdk.mjs`：使用合成卡、临时持久会话及本地合成模型传输，覆盖两种加载顺序、两种模式、切换、关闭、工具续轮、压缩、回退和重新打开；不读取真实用户人设、auth/models，也不发送远程模型请求。具体版本、计数与部署状态见 [当前状态](../../docs/CURRENT-STATE.md)。

上游镜像中的测试、专业资料和原始来源说明仍有复查价值；保留镜像不代表所有内容进入正式路由或已在当前机器运行。具体引入提交见git历史和`setup/.upstream-shas.json`；手动维护来源按`setup/upstream-rules.json`处理。

## 3. 2026-10-30指定来源复核

| 来源与固定提交 | 读过并采用的具体方法 | 本地落点 | 集成与验证边界 |
|---|---|---|---|
| [yaklang/hack-skills](https://github.com/yaklang/hack-skills/tree/6fbf0bc8d5c71830d62543a308d8744606c43d7c) | 按攻击面下钻、API授权对照矩阵、区分候选和证据 | `web-pentest/subskills/api-security/`、`jwt-security/`及父域已有参考 | 方法适配，不安装其另一套路由；具体任务结果以当前回执为准；根LICENSE为MIT |
| [P4nda0s/reverse-skills](https://github.com/P4nda0s/reverse-skills/tree/a2baa31c58a3567977188414da68c8c842057152) | `rev-frida`的模块加载时机、`rev-u3d-dump`的二进制/metadata配对和工具版本选择、符号/结构与局部仿真方法 | `apkseep/subskills/frida-hook/`、`il2cpp-dump/`及softseep现有参考 | 方法复核与本地改写；README声明MIT，该快照根未发现独立LICENSE，不声称复制全部代码或已验证全部设备 |
| [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill/tree/cab634bd855fc287f6e420c1f36fd1a6b9245960) | 场景选择、工具可用性、证据到结论与路线恢复 | 复核现有router、领域方法与工具入口 | 方法比较；没有接入其独立路由器或状态系统；根LICENSE为MIT |
| [morluto/rea](https://github.com/morluto/rea/tree/c0c3902207d6b1a33709e42b80c7e570da7db964) | Evidence与provider身份、覆盖/限制、显式静动态映射、部分结果与错误清理、重建声明的限定验证 | 对照现有`case_evidence`、project capture、报告与恢复 | 源码/契约方法比较；未安装完整REA或provider体系，不宣称整体达到或超越REA |

这些提交是此次研究快照，不是自动更新通道。技能内容的适配和文件来源仍需结合提交差异复查，不能因方法相似倒推出原始代码归属。上游也可能有错误或环境假设，不能把它的命令当成本机验证结论。

来源状态使用：候选、方法参考、本地改写、代码接线、任务见证。只有最后一项能支持相应环境中的任务能力；下载、复制、注册与握手不能替代它。

## 4. MCP及外部工具依赖

`Tool/mcp/seep_mcp_server.py`通过`__file__`定位其同级`Tool/`资源树。KB位于`Tool/mcp/Tool/reverselab/kb/`，本地覆盖层位于`Tool/mcp/kb_local/`；r2、JADX、Apktool和Hook模板的路径由实现与发现配置核验。移位部署必须保留相对资源布局或通过现有运行时注册定位。

外部IDA、x64dbg、JS与浏览器MCP按`Tool/config/mcp-servers.json`及能力/通道声明接入。商业许可、设备与登录不随源码提供；本页不存凭据或私人配置。缺少某个provider时按领域选择已有等价路线，并说明未验证的动作。

具体安装、握手和故障恢复见 [BOOTSTRAP](BOOTSTRAP.md)、[MCP-SETUP](MCP-SETUP.md) 与 [EXTEND](EXTEND.md)。配置中的命令与实际进程接口是当前事实，旧文档中的工具数量和文件大小不是。

## 5. 案例与历史资料

案例原始材料、证据种类、产物和复查记录位于`Tool/cases/`或用户项目中。历史报告不成为新功能需求；合成夹具、公开真实样本与客户目标证据保持各自身份。案例来源、许可和适用范围不能在清理文档时删除。

域内活跃方法优先使用当前`subskills/`；`_pending`中的旧入口按消费者逐项迁移。历史第三方技能参考位于`Tool/skill/_pending/safe-skills/`，仅按明确源码路径复查，不作为当前顶层部署入口。保留的历史证据指针不等于恢复旧技能为顶层部署。重复方法不得继续双份承担当前规范职责。

## 6. 增补来源时记录什么

在本页或既有专项来源清单登记：仓库URL、固定提交、原文件、本地文件、许可证、采用的方法或代码、适配理由、消费者以及验证记录。先核对现有同类能力，再决定是否增加文件；不把第三方宣传或“所有技能”作为验收目标。
