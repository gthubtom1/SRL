# DeepSeek Harness 接入参考

本页仅说明本仓提供的配置生成入口。宿主版本、插件装配、指令和技能加载需在实际 DSH 中验证；配置文件产出不等于接入完成。

先由智能体阅读 `Tool/docs/BOOTSTRAP.md`，确认环境并按照 `MANUAL/DEPLOYMENT.md` 安装。所有相对命令从仓库根执行。

Windows 可运行以下生成器：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\generate-configs.ps1
```

生成物为 `setup/cordis.generated.yml`，当前模板使用 `- insert:` 形式声明 Seep stdio 服务。解释器与脚本路径要在实际 DSH 运行环境可执行；用户对生成文件的定制先另存，重新生成会覆盖它。接入时使用该文件，并按实际宿主版本确认装配方法，不手工照抄旧的 IDA、JavaScript 等占位配置。

按宿主支持的方式加载 `Tool/prompts/AGENTS.md` 和相关技能。Pi 扩展不能自动作为 DSH 插件；用户指令与宿主规则优先，不能把文件存在当作规则已加载。

安装自检 `python Tool/scripts/env-check.py` 针对 Pi，不能证明 DSH 可用；`python Tool/scripts/check.py --runtime --json` 验当前实现。DSH 需要另做实际 initialize/tools/list、任务工具调用和模型会话验证。

按 `MANUAL/DEPLOYMENT-CHECKLIST.md` 报告部署、连接、加载和任务验证，未验证项明确列出。用户以自然语言描述目标，不必发 `lab：`；商业许可、本人登录和设备接入按真实需要处理。当前范围与验证见 `REQUIREMENTS.md`、`docs/CURRENT-STATE.md`。
