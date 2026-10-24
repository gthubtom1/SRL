# 插件失败判据：何时停、往哪转

## 入口信号

- 同一包连续两次解析失败（容器/头部/版本）。
- 权限或入口能列出，但无法对应任何代码路径。
- 动态加载失败两次（签名/白名单/版本/受限工作区）。
- 只有插件一侧，缺 host/游戏/主进程另一端。
- 观测到反作弊/EDR/企业策略告警。

## 可复制命令

```bash
# 先固定证据：包哈希、容器、rc
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py --path target --json
python Tool/skill/_pending/plugin-targets/scripts/plugin-repro.py --path target --out work/repro --json

# 工具缺失时确认降级面
command -v ilspycmd jadx dnSpy 7z unzip node || true
```

## 失败判据表

| 现象 | 判定 | 改走哪条 | 代价 |
|---|---|---|---|
| triage 两次 `blocked_at=container` | 容器/偏移不可信 | 只报哈希 + `file`/`xxd`；转安装目录/`strings` | 失去文件清单 |
| `manifest.json` 引用的入口文件全缺 | 包被裁剪/构建不完整 | 标“入口未闭环”，查 `web_accessible_resources`/内联脚本 | 无法给数据流 |
| 权限全 `unexplained-static` | 权限未落地 | 扩大解包范围；查动态 API 拼接；仍无则标未闭环 | 可能漏真实调用 |
| MV3 SW 休眠、Network 空白 | 观测缺失 | 触发 `onInstalled/onMessage/alarms`；看 storage | 动态证据不足 |
| 变量跨世界读不到 | isolated world 误判 | 查 `world:"MAIN"`/注入桥/`postMessage` | 需重做注入链 |
| nativeMessaging 只有扩展侧 | host 样本缺失 | 查系统 `NativeMessagingHosts`；无则停 | 只能给调用点 |
| VSIX `main` 缺失/仅 `*` | 入口未闭环 | 查 `browser`/contributes/实际文件 | 无法动态加载 |
| VSIX 版本不匹配 | 宿主不兼容 | 换匹配版本或只做静态 | 需额外环境 |
| JetBrains class 找不到 | 入口不一致 | `jar tf` 全量搜；查多版本 `META-INF` | 反编译不可信 |
| asar 头解析失败/入口乱码 | 偏移错/非标准 asar | 复核 `data_offset`+`offset`；转安装目录 | 可能读不到入口 |
| 全 `.jsc` 且版本不匹配 | 字节码不可读 | 记录版本/加载器；找 source map；只做字符串面 | 入口逻辑不可读 |
| IPC 只有一端 | 链路不完整 | 补齐另一端；标 `inferred` | 不能证可利用 |
| 插件未加载（Unity） | 加载链失败 | 查日志/Doorstop/依赖；两次失败即停 | 不能验证 patch |
| IL2CPP 元数据版本不匹配 | dump 不可信 | 换对应版本工具，重取同批文件 | 之前结构作废 |
| 改包后拒绝加载 | 签名/白名单/完整性 | 停；记录校验层；转静态/更新链 | 无法动态验证 |
| 触发反作弊/EDR/风控 | 环境风险 | 立即停；记录环境；换离线副本 | 动态证据缺失 |

## 确认判据（停之前先确认）

- 已记录：命令、rc、stderr、`blocked_at`、包哈希、已确认的容器/入口结论。
- 已尝试：同一层最多两次；两次失败就换观测层（静态→动态→安装目录→更新链）。
- 已标注：`observed`/`inferred`/`unverified`/`blocked`；缺环不升格。
- 已脱敏：不把真实 Cookie/token/账号写进证据。

## 边界

- 失败判据不是“放弃”，而是“换层”；换层后仍失败才停。
- 签名/白名单/反作弊不提供绕过方法；授权测试也要记录环境与回退。
- 协议/分帧/重放交 `protocol-plugin`（R24）；APK 壳交 `apkseep`；PE 脱壳交 `unpack-loop`。

> 关联：`Tool/skill/_pending/plugin-targets/references/02-failure-criteria.md`、`references/01-criteria.md`。
