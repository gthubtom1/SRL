# Agent / MCP 工具安全速查

> 配套 `llm-security/SKILL.md`。只审计授权 Agent、MCP 服务与技能包；不投毒第三方。

## 1. 工具面清单

```text
Agent：<name/version>；系统提示哈希：<...>
工具：
  - name / 描述 / 参数 schema
  - 权限：读文件？写文件？网络？执行？支付？
  - 审批：无 / 每 Call / 高风险
  - 数据域：租户/用户/目录/URL 白名单
```

- 先列“能造成不可逆影响”的工具：发邮件、删文件、执行命令、转账、改权限、外发 webhook。
- 判据：每个工具都能回答“最坏能做什么、被什么限制”。

## 2. 参数注入

| 工具类型 | 测试输入 | 期望 |
|---|---|---|
| 文件读 | `../../etc/passwd`、绝对路径、UNC | 路径规范化 + 根目录限制 |
| HTTP 抓取 | `http://169.254.169.254/`、`file://`、内网 IP | 协议/域名/IP allowlist |
| SQL 查询 | `' OR 1=1--`、UNION | 参数化/只读账号 |
| Shell | `; id`、`$(id)`、反引号 | 不拼 shell / 白名单 |
| 模板 | `{{7*7}}`、`${...}` | 沙箱/转义 |
| 邮件 | 收件人/抄送/附件路径 | 域名/路径限制 |

- 判据：受控文件/请求被触达，或参数被 schema 拒绝；记录原始参数与结果。

## 3. 工具链越权

```text
read_file(secret) → summarize → send_email(attacker)
query_db(user A) → generate_report → upload(public)
search_web → fetch_url(internal) → execute
```

- 检查每一步的授权：工具是否用**服务端身份**而非模型传参；租户 ID 是否可被模型改。
- 人在回路：高风险工具是否真的等待人工；能否用“紧急/已批准”绕过。
- 判据：调用序列 + 每步参数 + 结果；影响面可界定。

## 4. MCP 配置审计

```bash
# 只读查看本机/项目配置
python - <<'PY'
import json,os
for p in ['.mcp.json', os.path.expanduser('~/.pi/agent/mcp.json')]:
    if os.path.isfile(p):
        d=json.load(open(p,encoding='utf-8-sig'))
        for name,cfg in (d.get('mcpServers') or {}).items():
            print(name, cfg.get('command'), cfg.get('args'))
PY
```

危险信号：

- `npx -y <pkg>` / `uvx <pkg>` 未 pin 版本：每次拉最新。
- `command` 指向用户可写目录/临时目录；`args` 含 `curl | sh`、`powershell -enc`。
- 明文 token 在 `env`/`headers`；配置文件权限过宽。
- 本地 HTTP MCP 无认证、绑定 `0.0.0.0`。
- 工具描述含隐藏指令/Unicode 控制字符/“忽略安全规则”。

判据：来源、版本、权限、可执行命令、密钥存放五项可解释。

## 5. Skill / Prompt 包审计

```bash
# 仓库内技能/提示词只读扫描
seep_gen_security_report(mode="agent", target="Tool")
```

检查：

- frontmatter/描述是否要求“读取所有文件/发送到外部/跳过审批”。
- 是否包含 `curl | bash`、下载后执行、动态 `eval`。
- 是否引用不存在的工具/路径（供应链断链）。
- 是否有零宽字符/双向文本覆盖（Trojan Source 类）。
- 是否把“授权”写成默认全开、无边界。

判据：不可信 Skill 不自动安装；安装前有来源/哈希/权限审查。

## 6. 记忆与多 Agent

- 长期记忆写入是否校验来源与权限；低权内容能否影响高权会话。
- 多 Agent 消息是否签名/认证；A2A 是否信任对方 role。
- 规划器是否把不可信内容当“系统指令”；子 Agent 是否继承过高权限。
- 判据：每条记忆/消息有来源、权限、过期/删除策略。

## 7. 防护基线

```text
最小权限：工具只拿完成任务所需的 scope
服务端授权：租户/用户 ID 由服务端注入，模型不可改
沙箱：文件根目录、网络 allowlist、无 secrets
审批：不可逆动作必须人工确认
输出：HTML 转义、链接拦截、附件类型限制
供应链：pin 版本/哈希、私有 registry、签名验证
日志：记录工具调用参数/结果，脱敏 secrets
```

## 8. 报告模板

```text
Agent：<name/version>；模型：<...>；系统提示哈希：<...>
工具：<name> 权限 <...> 审批 <...>
测试：<输入摘要> → <工具调用/参数> → <结果>
影响：<读取/外发/执行/越权>；范围 <...>
证据：<request id/日志/截图>
修复：<架构级>
未验证：<...>
```
