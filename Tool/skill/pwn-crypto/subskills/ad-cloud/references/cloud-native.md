# 云 IAM、身份信任与暴露路径

入口：[SKILL](../SKILL.md)。用户在自己的宿主完成真实认证，仅提供身份别名、账号/租户归属、策略/版本、安全授权结果与审计。Agent 不读取 credential/profile 文件、环境变量秘密、AK/SK、会话 Token、Key/Salt/私钥，也不调用自动返回临时 Credentials 的接口。

## 身份不等于权限

先固定云平台、账号/租户、region、资源与 action、策略版本和采集时刻。ARN/主体名只标识身份，管理员策略名不代替策略正文。角色会话身份变化不自动证明权限增加；同一身份的权限也可能变化。用户侧 STS/身份检查结果仅证明该次身份观察，不能证明全部授权或凭据来源安全。

| 机制 | 配置核验 | 安全结果与未知 |
|---|---|---|
| Identity/resource policy | Action/NotAction、Resource/NotResource、Effect、条件、主体与服务支持语义 | 核准确动作/资源；适用显式 deny 不能被另一 allow 覆盖，缺层保留 unknown |
| Boundary/SCP/会话策略 | 实际附加关系、组织层级、条件上下文与有效范围 | 不能由账号层 allow 推断组织允许；缺策略不能默认不存在 |
| AssumeRole/trust | 双侧授权、trust Principal、ExternalId/MFA/组织/会话条件 | 只分析信任与用户侧非秘密决策，不执行 AssumeRole 获取临时凭据，不猜条件值 |
| PassRole 与 compute | 精确角色、可传服务/资源条件、服务 trust、创建/调用权限和运行边界 | PassRole 不是单独登录 API；组合权限只构成风险候选，不创建 Lambda/实例/栈或执行代码验证 |
| 策略/密钥管理权限 | 可影响的策略/版本/主体、附加关系、边界与条件 | CreatePolicyVersion 不等于能改变任意身份有效权限；不建 key/策略版本，不改 trust/绑定 |
| 对象访问 | ListBucket、HeadObject、GetObject 等各自授权/条件 | list/head 结果不普遍证明对象正文可读；用户侧非秘密 canary 只验证那个对象，不下载配置/备份/tfstate 寻秘密 |

Azure/GCP/Okta 等应按各自授权模型、组织限制、条件策略与审计核实，不能拿 AWS 有限模型套用；缺对应材料/工具明确未验证。

## 元数据、工作负载身份与 CI

| 面 | 可核事实 | 禁止以取秘密补证据 |
|---|---|---|
| VM metadata/SSRF | metadata 访问控制、IMDS 模式/hop limit、工作负载网络边界、应用 URL sink 与请求能力 | 不请求 IMDS Token、AWS 临时 key、GCP/Azure OAuth Token；HTTP 200/目录可见不证明身份/权限可用 |
| Workload Identity/OIDC | issuer、audience/subject 条件、trust、绑定与令牌投影/挂载配置 | 不读取实际 JWT 或私钥；用预先准备的合成身份/测试决策，条件匹配不能证明真实 token 被接受 |
| CI/registry | 触发来源、执行代码/runner 隔离、Secret 引用、环境保护、发布/拉取权限与审计 | 不 env dump、不读 docker/cloud 配置或 SecretValue，不取受保护变量、推送镜像来证明权限 |
| 暴露线索 | 用户侧安全扫描报告的文件位置、类别、版本和数据流；合成 canary | 不回传秘密行/前缀/hash，不扫描取值后打码。模式命中不证明是真实、有效或可用凭据 |

真实平台核验留在用户侧，只返回指定 action/resource/身份别名的允许/拒绝/错误类别、时间、关联 ID 与无秘密的测试标记。即使响应在用户侧为成功，仍区分认证、授权与业务效果；非秘密输出缺失时保留证据强度限制。

## 现有离线模型

[cloud-iam-eval.py](../scripts/cloud-iam-eval.py) 读取有限 AWS 风格 JSON，不调用云服务。只输入无秘密的策略/合成上下文，先核其帮助与支持的条件运算、大小写/资源匹配等实现限制；不把 severity/privesc 标签当实际可利用性结论。

```bash
python Tool/skill/pwn-crypto/subskills/ad-cloud/scripts/cloud-iam-eval.py --input work/safe-policy.json --action s3:GetObject --resource arn:aws:s3:::seep-synthetic/canary.txt
```

输入需要非空 policies 列表，文档与 label 等字段以当前脚本为准。rc=0 表示已计算结果，不等于 allow，更不等于云端接受；缺 resource policy/boundary/SCP/会话/条件时不能宣称模型完备。

正例：同一合成策略中只允许 canary 对象，其他资源被拒，确认该有限模型行为。反例：文本 allow 而用户侧拒绝，先核缺失策略/条件，不改权限或换凭据来源。用户侧 ExpiredToken 只说明该次认证状态，不能从单错误断定永久撤销；出现预算/输出边界或两次同形失败即停。

历史攻击链/metadata/CI 命令保留于 `Tool/skill/_pending/ad-cloud/references/cloud-native.md`，仅作来源追溯。K8s 见 [k8s-and-container](k8s-and-container.md)，CI 深度审计可由供应链主域协作，安全结果归同一 project/version/run；本技能不执行线上修改、资源创建或系统改动。
