# 参与维护

先读 [REQUIREMENTS](REQUIREMENTS.md) 和 [当前状态](docs/CURRENT-STATE.md)，按当前任务定位源码。新机器安装与验证从 [BOOTSTRAP](Tool/docs/BOOTSTRAP.md) 开始；新增技能、工具、MCP 或配套包沿用 [EXTEND](Tool/docs/EXTEND.md)，上游适配见 [UPSTREAM](docs/UPSTREAM.md)。

## 报告问题与提交变更

普通缺陷可在当前 GitHub 仓库的 Issues 中报告：说明使用的提交或版本、操作系统、Python/Node/Pi 版本、最小复现步骤、期望与实际结果、命令退出码。日志先脱敏；不要提交凭据、用户配置、个人文件或客户目标。安全漏洞按 [SECURITY](SECURITY.md) 处理。

变更应围绕一个可复现缺陷或已确认需求，说明原因、前后行为、受影响路径和验证结果。修复缺陷时加入能使旧实现失败的必要反例；普通文档修正无需新增测试。保留第三方来源、版权声明和许可证，具体规则见 [PROVENANCE](Tool/docs/PROVENANCE.md)。

## 验证与合入

先运行受影响专项。涉及安装、更新或卸载时使用临时 AgentRoot，并让所有检查指向同一目录；不要以真实用户安装目录作为测试夹具。客户目标的执行和用户凭据操作遵守需求中的边界。

交付前从仓库根运行现有完整回归，并如实记录非零退出码、WARN、跳过和未验证项：

```bash
python Tool/scripts/check.py --runtime --strict --json
git diff --check
```

GitHub 的 `gates` 分别在 Linux 和 Windows 运行**公开源码复验**，覆盖隔离部署、公开材料专项、真实 SDK 与 MCP；它不是完整领域验收。公开套件的逐项命令及排除原因见 [.github/public-suites.json](.github/public-suites.json)，用 `python .github/scripts/check_public_source.py --list` 查看。runner 复用 `check.runtime_suites/run_one` 与超时；新增未分类套件或命令变更会失败，不会静默漏测。套件内的非零、WARN 或跳过仍返回非零，排除项另列为范围外，不记作 PASS 或 SKIP。

`unit`、`e2e` 及调用完整 preflight 的 `mutation-isolation` 不在公开范围：原完整验收依赖用户提供、gitignored 的 `Tool/cases/apkseep08/target/release.apk`。`preflight.py --fast` 同样包含完整领域检查。不得上传该客户 APK、伪造证据或缩减原 witness/depth 集合。维护者在获授权的独立本机 worktree 按登记哈希准备原件后，仍运行原完整 `check.py --runtime --strict --json` 和 `preflight.py --fast`；缺原件时原门禁继续失败。公开 CI 与本机完整验收分别报告，前者不能推出后者。

所有延后处理的步骤都由最终汇总检查原始 outcome。工作流本身的失败传播可用 `python .github/tests/test_workflow_gates.py` 复查，需要 `PyYAML==6.0.3` 和对应 shell。CI 通过不替代真实宿主加载、设备或客户任务验收。

CI 使用 npm 官方 registry 的固定 Pi SDK `@earendil-works/pi-coding-agent@1.4.0`，禁用安装脚本，不需要用户登录。Linux 另从系统包源准备 TShark、CramFS 和 binutils，并从官方 radare2 5.9.8 发行版安装经固定 SHA-256 校验的原生工具。已有 SDK 合载验收使用合成会话与本地模型传输，检查结果必须为零网络请求。

安装专项仍调用真实安装器和 `env-check.py`：空的隔离 AgentRoot 完成部署后，Pi/Node、文件完整性、运行时注册和真实 MCP 握手都必须通过，且环境检查必须**仅因未登录而返回非零、installed=false**。这验证了未登录时不会假报就绪；任何额外缺件、握手失败、意外成功或其他退出码都令 CI 失败。真实用户环境的完整安装通过条件没有改变。

自动上游同步创建草稿 PR。`GITHUB_TOKEN` 创建的推送或 PR 通常不会自动触发其他工作流：维护者须在 Actions 的 `gates` 中手动选择该 PR 分支运行，核对结果后再转为可审阅。不要把同步成功当作完整回归通过。

PR 说明包含实际运行的命令与结果、未覆盖范围；涉及行为边界时更新对应文档。不要降低判据、删除负例或覆盖用户文件来消除失败。
