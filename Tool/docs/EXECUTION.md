# 当前执行操作手册

行为源为 `Tool/prompts/AGENTS.md`，产品需求为 [REQUIREMENTS.md](../../REQUIREMENTS.md)。本页只解释现有操作方式，不保留旧事故的待办、时间表或另一套执行计划。

## 1. 人机配合

| 情况 | 动作 |
|---|---|
| 已有范围内的读改代码、分析、工具使用、测试构建、本地运行与界面交互 | Agent 自主执行并检查结果 |
| 普通开发或小修复 | 直接用宿主能力，不强制逆向判型、lab 或案件登记 |
| 长期、多版本、跨域和多设备任务 | 按恢复需要使用既有项目状态，范围和输入不重复询问 |
| 确实缺用户独有信息、必要设备、本人操作或新增影响决策 | 说明实际缺口、最少动作、恢复点，集中询问 |
| 同一尝试重复失败 | 先诊断修复或换路，不能直接让用户代执行；正常修复后的测试可继续 |
| 宿主全局网络、驱动、服务等系统影响 | 保留边界，核对合适实验环境；不通过 GUI 或转交用户绕过 |

账号、卡密、Token、Salt 和私钥按现有凭据仓规定使用，不回显、不进入证据交付。具备安全输入能力时可由 Agent 输入；不是所有登录都需要用户代操作。

## 2. 启动与观察

启动方式由目标和当前问题决定：正常启动、调试启动或附加已有实例。已有范围内由 Agent 执行，不要求历史运行回执。未知目标的实际系统影响仍需核对，不因调用的是“自己的启动器”就自动获得运行许可。

`Tool/scripts/launch-gui.ps1` 默认 `shell` 自动启动，也可 `attach` 仅观察；`user` 是明确的人工选择并立即返回等待状态。它使用 Windows shell、显式工作目录和可选 `Arguments`，不承诺 Explorer 父进程或不可检测。只接受已解析的 exe/com；快捷方式或启动器须先核实实际入口。

实例按完整映像路径与 PID/创建时间识别。同路径多个实例返回歧义，选择 `InstancePid` 后再交互；不会按进程名批量结束程序。创建请求返回、实例被观察到、可见窗口与业务功能分别判断。启动器派生其他程序、瞬退或观测权限不足返回未验证，先查实际状态，不盲目重试。

| 退出码 | 含义 |
|---|---|
| 0 | 已观察到准确实例（新启动或复用），不代表功能通过 |
| 2 | 参数或观测前置条件不满足 |
| 4 | 没找到实例、启动未确认或启动后观测失败 |
| 5 | 显式选择人工模式，需要人工操作 |
| 6 | 同路径多实例，需 Agent 结合当前任务选择 PID |

`launched` 为兼容字段表示已看到匹配实例；`launchRequested` 表示是否发出启动请求；`reusedExisting` 表示复用。`windowVerified` 只说明本次发现可见窗口，`functionalityVerified` 始终 false，必须由任务检查补齐。输出不记录启动参数与完整命令行，避免凭据顺着日志泄漏。

调试器与分析工具继续使用既有发现/启动/连接入口；按实际工具列表与结果确认就绪。标准分析可用稳定 API，真实页面行为使用浏览器/桌面/设备控制，两者按需组合。桌面输入、截图和保护目标兼容性未经过任务验证时保留未知，不能只靠放宽规则宣布可用。

需要界面动作却没有可用工具时，先查当前宿主工具表、已有安装与连接状态，按已有范围修复必要缺项；不得仅因“是 GUI”就要求用户代点。确实仍缺后端时，说明已查到的能力缺口、可继续的工作和恢复条件，不冒充拥有输入或截图能力。

## 3. 网络与采集

异常时先区分 paused/退出/崩溃、工具故障和请求阶段；已有范围内不改回用户代操作。诊断、共享状态、HTTP 范围/恢复及实际覆盖边界 → [异常与有界试验](../playbooks/risk-aware-analysis.md)。外部工具与目标后台网络不因入口存在就被全局控制。

已知远端资产相关的 Windows 新启动可按需使用 `Tool/scripts/runtime-flow.py`，复用本页启动器与共享范围；只限流程启动次数，保留准确实例与未解决执行，不冒称能限制每条后台请求。普通本地启动不因此新增人工门。

优先目标进程内采集或仅注入目标进程的代理参数。系统级网络不作为默认取证手段。`Tool/scripts/net-rollback.py` 是现有快照/复查工具，不表示自动获得改变整机网络的许可。

采集范围围绕当前问题，记录经允许保留的非敏感元数据与证据。不得按旧案例示范把明文登录信息直接落盘。

## 4. 结果与接续

项目状态通过现有 project_state/manager_state/project_workflow 记录，单案继续使用 case_state。等待原因、采用/放弃路线、证据、适用版本与下一步应可恢复。

跨域时，`project_workflow.py start --primary-domain <域> --aux-domain <辅域>` 登记主辅领域。先用 `project_state.py asset --project <项目> --version <版本> --asset-id <ID> --role auxiliary --target <文件>` 登记辅助材料，再用 `project_workflow.py act --project <项目> --action <只读动作> --asset-id <ID>` 选择该版本已登记的文件；省略 ID 才使用主目标。工具输入绑定、执行前后指纹和证据复查使用同一资产身份，不能在 `--args-json` 覆盖目标路径。`kb.search`、`kb.read` 是九领域共享的知识入口，仍经过 effects、参数和项目状态检查。

开发本工作台的新会话和压缩接续只读 REQUIREMENTS 与 [CURRENT-STATE](../../docs/CURRENT-STATE.md)，再定位相关实现；恢复客户项目时读取该项目自身状态，不从产品历史计划推断下一步。

技术未知、版本矛盾或重复无新证据时，按 [查证与最小实验](../playbooks/evidence-led-investigation.md) 使用现有方法并按需主动查外部资料，不等用户提醒。该配方不强制普通开发建案，也不靠人物语气替代专业证据。

## 5. 项目风险提示的持久化与恢复

账号、设备、目标或环境相关的风险提示由 Agent 自己记到现有项目，用户不填风险JSON。只根据静态线索时用 suspected，实际观察用 observed；记录不能代替证据语义判断。先通过现有 evidence 入口将非敏感观察绑定到来源 project/version/run，再用原 `project_state.py event --project <项目> --type runtime_caution --version <来源版本> --run <来源运行> --message <JSON>` 登记。message 字段为：

```json
{
  "caution_id": "launch-risk-1",
  "scope": "identity",
  "subject_ref": "credential-store/account-a",
  "assessment": "suspected",
  "reason": "已有静态材料显示启动可能触发远端设备绑定，尚未实测",
  "affected_actions": ["启动原目标", "认证或激活"],
  "resume_when": "核对旧实例和远端结果，确认当前环境与已有范围，再查询共享风险状态",
  "safe_next": "继续离线检查导入和已有日志",
  "evidence_ids": ["ev-static-observation"]
}
```

`scope` 为 identity（稳定主体必填）、target（当前目标事实）或 environment（环境适用条件）；subject_ref 仅非秘密稳定引用，不写真实账号、卡密或访问URL。caution_id 在项目内不可复用。来源版本/run和证据须真实存在且匹配，引用文件哈希仍须通过；证据篡改使接续健康状态失败，警告不会因此消失。

`project_state.py handoff/resume` 和 Manager handoff 均展示 `runtime_cautions`，workflow status 的项目健康也保留它。换run不清警告；跨版本身份风险仍保留，旧target警告标明需重新评估，不当成新目标已证事实。只暂停 affected_actions，其他离线工作继续，不把整个项目变为 WAIT_USER。

有复核证据后用同一event入口、type=`runtime_caution_resolved`，message仅含 `caution_id`、`reason`、`evidence_ids`；来源版本/run填写本次复核的真实归属。追加解除事件只解指定提示，不删历史、不清其他警告，**不调用 runtime-risk resume、不返还次数**。实际远端恢复仍走原共享风险接口和判据。

facts随原项目归档携带，不复制用户级预算库或identity.key。`external_coordination`始终明确未核对：换机器后空库不等于没有过去的尝试；恢复远端动作前须核对旧执行链、主体、额度和范围，必要时只继续离线。提示记录不是全宿主拦截器，不能声称所有curl、浏览器、设备或目标后台都已受控。旧读者可能仍能解析通用event，但没有新投影时不等于具备风险接续；回退不能删除提示，不能把旧版空显示当成可安全重试。

Pi案例记忆只自动采用当前cwd的本地案或真实目录就是cwd自身的机器指针候选；跨目录恢复用明确的 `SEEP_CASE_DIR`。未绑定的普通目录不读写另一个项目的记忆，插件不会自动创建案件。普通未建项目任务在已有接续文件保留相同必要信息；不为风险笔记强制建立完整专业案件。
