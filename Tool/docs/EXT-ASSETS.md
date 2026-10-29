# 选择性吸收的扩展能力

本仓借鉴 REA 的 provider 选择和失败降级思路，并吸收其他项目的工具发现、判型和实战方法；不依赖完整 REA 安装或独立 REA 服务。来源不等于运行时依赖。

| 当前入口 | 实际职责 | 边界 |
|---|---|---|
| `preflight-classify.py` | 文件头和结构预判 | 不执行客户目标，不保证完成脱壳 |
| `seep_ensure_tool` / `tool_autodiscover.py` | 分层发现、白名单安装、安装后重探 | 发现可执行文件不等于 MCP 握手或任务成功；`allow_install=False` 仅探测 |
| `seep_tool_discover` | 工具路径与控制方式信息 | 具体操作按现有专用 MCP、CLI、技能入口执行 |
| `seep_r2_decompile` | r2 伪代码、折叠、摘要 | 只驱动 r2，不自动切换 IDA/Ghidra/REA |
| `seep_r2_cmd` | 经准入的 r2 命令，包括资源信息 | 非通用命令执行器 |
| `seep_mem_strings` / `seep_pcap_extract` | 内存字符串、抓包解析 | 原始输出仍需目标身份、语义核对和证据绑定 |
| `seep_packer_detect` / `seep_http_replay` | 静态判壳线索、HTTP 复核 | 线索不证明脱壳完成；HTTP 受目标授权和凭据边界约束 |

`Tool/config/engine-tiers.json` 只保留参考顺序，当前反编译入口不消费它；修改此表不会增加后端能力。现有独立 IDA 等通道按实际装配和工具回执使用。未接入的私有辅助函数不作交付承诺。

有效需求见 [REQUIREMENTS](../../REQUIREMENTS.md)，当前验收见 [CURRENT-STATE](../../docs/CURRENT-STATE.md)，扩展/回滚按 [EXTEND](EXTEND.md)。当前运行检查入口为 `python Tool/scripts/check.py --runtime --json`；旧工具数量、65 项和扩展自测统计均不是当前验收标准。

旧 `test_ext_assets.py` 引用已撤出的 API，是历史测试文件；当前工具回归由 `test_seep_mcp.py`、契约测试及完整检查消费的套件承担。不得为运行旧测试恢复已撤出 API。
