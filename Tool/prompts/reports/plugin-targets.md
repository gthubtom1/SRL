# plugin-targets 报告模板

> 复制到 `work/<case>/report.md`。权限/入口必须能回到 manifest 或包内文件。

## 1 目标与授权
- 目标：<CRX/VSIX/ASAR/ZIP/Unity 包 / 版本 / sha256>
- 授权：<本地只读 / 是否允许动态加载 / 是否允许改测试包>
- 范围外：<生产客户端 / 商店账号 / native host 清单由 scope 声明>
- 环境：<浏览器/Electron 版本 / 解包工具 / OS>

## 2 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/plugin-triage.json | <sha256> | `python Tool/skill/plugin-targets/scripts/plugin-triage.py --path <pkg> --json` | 0 | 容器/权限/URL |
| E02 | artifacts/plugin-repro.json | <sha256> | `python Tool/skill/plugin-targets/scripts/plugin-repro.py --path <pkg> --out ... --json` | 0 | 入口/数据流 |
| E03 | artifacts/accept.json | <sha256> | `python Tool/skill/plugin-targets/scripts/plugin-accept.py --root . --json` | 0 | 案例验收 |

## 3 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| 容器/清单 | container 与 manifest_version 识别正确 | <实测> | E01 | <结论> |
| 权限面 | 高权限/`<all_urls>`/nativeMessaging 有 manifest 证据 | <实测> | E01 | <结论> |
| 入口 | background/content/preload/main 均 exists=true | <实测> | E02 | <结论> |
| 数据流 | 页面→消息→native/fetch/WebSocket 链可追 | <实测> | E02 | <结论> |
| 更新源 | update_url/app-update.yml 指向受控域名且签名可验 | <实测> | E01/E02 | <结论> |
| 完整性 | asar integrity / 签名 / 白名单未被绕过 | <实测> | E03 | <结论> |

## 4 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| 只有静态权限，无入口/调用证据 | <yes/no> | E01 | 标 candidate |
| native host 只有常量，无 manifest/二进制 | <yes/no> | E02 | 不写已建立连接 |
| btoa/混淆被当成窃取成功 | <yes/no> | E02 | 只写编码/线索 |
| update_url 可疑但未验证签名 | <yes/no> | E01 | 不写供应链失陷 |
| asar integrity 校验失败被当绕过 | <yes/no> | E03 | 记录失败点，补动态 |
| 只看到 UI 按钮/前端隐藏 | <yes/no> | E02 | 不写越权 |

## 5 影响与边界
- 影响：<可读浏览数据 / 可执行代码 / 可连 native / 可外联>
- 边界：<静态只读；未动态加载/未连真实 C2>
- 误报风险：<合法遥测/主题包/商店更新源>
- 未覆盖：<native host 二进制、签名链、真实用户数据>

## 6 修复建议（厂商视角）
1. 扩展遵循最小权限，移除 `<all_urls>`/nativeMessaging，除非有明确业务与用户同意。
2. update_url 固定 HTTPS + 签名校验，禁用外部可写更新源；ASAR 启用 integrity。
3. content script 限定 origin 与 frame，消息 API 做 schema 校验与来源校验。
4. Electron 开启 contextIsolation/sandbox，禁用 nodeIntegration，IPC 白名单。

## 7 复跑命令
```bash
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path work/<case>/artifacts/package.zip --json
python Tool/skill/plugin-targets/scripts/plugin-repro.py --path work/<case>/artifacts/package.zip --out work/<case>/artifacts/repro --json
python Tool/skill/plugin-targets/scripts/plugin-accept.py --root . --json
```
