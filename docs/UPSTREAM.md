# 上游比较与增量维护

直接上游为 [angusdevgo/Seep-Reverse-Lab](https://github.com/angusdevgo/Seep-Reverse-Lab)。其他参考来源、固定研究提交、许可证与本地落点见 [PROVENANCE](../Tool/docs/PROVENANCE.md)。`morluto/rea`与Open-ReverseLab是两个项目，比较时不得混用。

产品范围以 [REQUIREMENTS](../REQUIREMENTS.md) 为准，当前进度和阻断只记 [CURRENT-STATE](CURRENT-STATE.md)。上游出现新能力不自动成为本项目待办；过往库存数字、阶段计划和旧门禁结果不决定新增需求。

## 1. 获取差异

从仓库根运行只读检查，先确认现有改动：

```bash
git status --short
git remote -v
git fetch upstream main
git log --oneline HEAD..upstream/main
git diff --stat HEAD upstream/main
```

如果remote尚未配置，确认目标后增补；不要覆盖已有remote。历史不共享祖先时按文件比较，不盲目merge。下载、比较与本地集成分别记录，fetch成功不代表已融合。

## 2. 每项改动回答六个问题

1. 用户当前任务或已确认需求缺少什么？现有技能、KB、MCP或脚本能否完成？
2. 上游具体哪段方法或代码填补这个缺口，固定提交和原文件是什么？
3. 本地应归哪个正式域或横切方法？跨域依赖是否返回同一项目、版本和run？
4. 工具版本、参数、运行平台和副作用与本地是否一致？上游示例是否仍需校正？
5. 来源与许可如何保留，现有用户材料和受管部署如何保护、回滚？
6. 用什么正例、反例、实际任务结果证明接线有效？文件存在、退出0或数量增长都不够。

只有新增价值明确才修改。相同主题可融合不同方法，重复内容不必复制；原资料深度足够时优先修导航与引用。

## 3. 本地适配

保持九域作为顶层业务方向。专业子技能由父域导航引导到`Tool/skill/<domain>/subskills/<name>/`，工具和MCP继续使用现有能力、通道与配置入口。全局项目、证据、报告和归档体系不因引入外部方法另起一套。

外部文件先比较后适配，不能在脏工作树上直接`git checkout upstream/main -- <file>`覆盖。若选用代码，保留来源和必要许可材料；若只参考方法，明确记为参考，不写成完整代码接入或实测能力。

导入与部署使用 [EXTEND](../Tool/docs/EXTEND.md) 的当前入口。子技能加入后需要验证父引用、相对资源、部署副本、独立verify及新会话读取；不要求用户手填内部技术字段。

## 4. 检查与结果

运行受影响专项，再执行完整当前回归：

```bash
python Tool/scripts/route.py --check
python Tool/scripts/skill-handoff-check.py
python Tool/scripts/check.py --runtime --json
```

涉及安装或宿主行为时，使用明确隔离AgentRoot验证文件、运行时注册、initialize/tools/list、实际调用和任务。当前宿主是否重载单独确认；其他平台没有实测就保留未验证。

有效旧工程检查的失败必须查明；确属过期判据时根据当前需求修正并保留拒绝坏输入的负例。不能自动更新阈值或快照迎合当前实现。

最后将当前结果更新到CURRENT-STATE。稳定方法进入对应技能、reference或KB；单个案例事实留在案例。旧方案被替代后删除活跃开发指引，不搬到work保存另一套规范。

## 5. 后续维护节奏

以具体任务缺口、已复现缺陷、上游重要变更和依赖兼容性为触发。每次只处理相关落点，保留用户材料、来源与复查办法，不周期性重新铺开全项目架构。预计工夫取决于实际差异，不能保证所有上游更新都能在固定十分钟内完成。
