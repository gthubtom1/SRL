---
name: protocol-plugin
description: "【协议复刻 / 插件类目标】接管两类目标：①私有协议/二进制协议复刻——抓包、分帧、字段推断、状态机重建、重放验证，判据是同输入同输出且能构造新请求；②浏览器扩展/IDE 插件/Electron asar/游戏 Mod 逆向——定位入口、关键逻辑、数据来源与最小可改单元。不替网页 JS 逆向与客户端授权路线。"
license: MIT
compatibility: Windows 10/11、Linux、macOS；依赖可选的 tshark / mitmproxy / unzip / asar / dnSpy / ILSpy / jadx；缺失时按本文降级。
metadata:
  version: "1.0.0"
  category: protocol-plugin
  routes: "R24,R25"
  references: "references/protocol-reverse.md, references/plugin-reverse.md"
---

# protocol-plugin — 协议复刻与插件类目标

> 本技能只回答两件事：
> **① 这个协议能不能被复刻到“同输入同输出，且能构造新请求”？**
> **② 这个插件/Mod 的入口、关键逻辑、数据来源在哪，最小可改单元是什么？**
>
> 先取证再推断；每个结论必须能回放到某条包、某个文件、某次运行。**不猜密钥，不猜字段，不猜入口。**

---

## 0. 入口判定与硬边界

| 路由 | 目标形态 | 首问 | 终点判据 |
|---|---|---|---|
| R24 协议复刻 | TCP/UDP/HTTP/WS 私有协议、二进制帧、protobuf | 帧边界在哪？状态由什么推进？ | 同输入同输出 + 能构造新请求 |
| R25 插件/Mod | `.crx`/`.vsix`/`.jar`/`asar`/BepInEx/MelonLoader | 入口在哪？关键逻辑读什么数据？ | 入口 + 关键逻辑 + 数据来源 + 最小可改单元 |

**三条纪律**

1. **抓包先于推断**：没有原始字节/原始文件，不许写“字段含义”；推断必须附样本编号。
2. **重放先于重写**：先原样重放，再做单变量改动；一次只改一个字段，并保留基线。
3. **两次失败即停**：同一目标连续两次抓不到/跑不通，先换观测层（进程内 → 网络层 → 静态），不硬试参数。

**不做（边界）**

- 网页/前端 JS 的签名、补环境、浏览器调试 → `mcp-js-reverse-playbook`；
- 客户端授权/许可证/门禁/版本迁移 → `01-gate-bypass` ~ `05-backend-rebuild`；
- 纯 PE/ELF 壳与反调试 → `unpack-loop`；纯算法还原 → `ida-reverse`/`reverse-engineering`。
- 本技能可**读取**这些领域产物作为输入，但不重复其方法体系。

---

## A. 协议复刻（R24）

### A1 产物先定

开工先写清：目标端点、客户端版本、协议层（HTTP/WS/TCP/UDP）、是否 TLS、验收方式。
产物至少包含：`capture.pcapng`、`frames.jsonl`（原始字节+方向+时间）、`schema.md`、`replay.py`、`evidence.md`。
详细命令与字段推断表见 `references/protocol-reverse.md`。

### A2 抓包：先看“谁和谁、说了什么”

```bash
tshark -r capture.pcapng -q -z conv,tcp
tshark -r capture.pcapng -Y "tcp.port==9527 && tcp.len>0" \
  -T fields -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e data.data
```

- 已有 pcap 时优先 `seep_pcap_extract(pcap, mode='summary'|'http'|'payload', port=...)`，再补 tshark。
- HTTP(S) 交互用 mitmproxy：`mitmdump -p 8080 -w flows.mitm`；需要看明文时设置 `SSLKEYLOGFILE` 或安装 mitm 证书。**先确认是否 pinning/双向认证**，抓不到不等于没有流量。
- WebSocket 必须按消息而不是 TCP 段分析：记录 opcode、FIN、掩码、压缩位；见 §D。
- 每个抓包文件记录：工具、网卡/代理、时间、客户端版本、是否重放污染。

### A3 分帧与字段推断

按以下顺序判定帧边界，**每一层都拿 ≥3 帧验证**：

1. **边界**：先试定界符（`\r\n\r\n`、`\0`、固定尾标），再试长度前缀（u8/u16/u32、大小端、是否含头/含自身/含 CRC）。
2. **头部**：magic（2/4 字节）、version、type/opcode、flags、seq、校验；TLV 看 tag/length 宽度与嵌套层数。
3. **载荷与证据**：先标“未知”；用 ≥3 帧验证，长度按 `len_field = payload + a*header + b` 解端序与覆盖范围；证据写 `offset/size/endian/样例/反例`。熵 > 7.5 先怀疑压缩/加密。

### A4 状态机重建

把每条消息标成 `state_before → event → state_after`，至少覆盖：

- 握手/认证：版本协商、能力位、随机数、证书；token、cookie、签名、时间戳、nonce。
- 业务/保活/关闭：请求 id 与响应配对规则；心跳周期、超时、重连；错误码与重试策略。

**判据**：能画出状态迁移图，并解释“服务端为什么接受下一帧”。无法解释的迁移标 `UNKNOWN`，不要编。

### A5 重放：先复现，再构造

- HTTP：优先 `seep_http_replay(url, method, headers, cookies, body, impersonate='chrome', session_file=...)`；
  保留原始 header 顺序无关，但 `Host/UA/Referer/Content-Type/Cookie/签名头` 必须齐全。
- 非 HTTP：用 `replay.py` 按帧写入 socket，记录发送字节、响应字节、RTT；先做**逐字节原样重放**。
- 对比基线：状态码、响应长度、业务码、响应体哈希、关键字段。差异先归因到“环境/会话/时间”，再归因到协议。
- 构造新请求：只改一个字段（如业务 id），预测响应并验证；重复 3 次以排除偶然。
- 只对授权环境重放；禁止对生产做高频/破坏性扫描。

### A6 二进制协议专项

按“头 → 体 → 尾”建表，最少记录：

| 区域 | 必查 |
|---|---|
| magic/version | 固定值？协商后变化？ |
| type/flags | 请求/响应/心跳/错误位 |
| length | 端序、覆盖范围、最大帧 |
| seq/ack/nonce | 递增、随机、回显、防重放窗口 |
| payload | 压缩？序列化？加密？ |
| checksum | CRC16/CRC32/Adler/自定义；覆盖哪些字节 |

- 校验和：先用已知帧反推多项式/初值/异或；改一个字节验证“服务端是否拒绝”。
- 加密段：找 nonce/IV/counter 字段；用已知明文-密文对判定算法族；必要时在客户端 `send/recv/SSL_write/SSL_read` 处取明文，而不是暴力猜密钥。
- 序列化/压缩：protobuf 看字段号/wire type，flatbuffers 看 vtable/offset；先判 gzip/deflate/zstd/自定义字典，解压后再分帧；长期维护优先 Kaitai Struct 或 scapy。

### A7 协议完成判据（缺一不可）

1. **同输入同输出**：同一请求重复发送，响应结构与关键字段一致（允许时间/nonce 变化，需解释）。
2. **能构造新请求**：不依赖抓包中的原帧，能生成服务端接受的新业务请求，并预测结果。
3. **状态可推进**：至少完成一次“握手/认证 → 业务 → 关闭”的完整闭环。
4. **负例可解释**：错误校验/错 seq/错 token 被拒，且拒绝方式与推断一致。
5. **证据可复现**：他人按 `schema.md + replay.py` 能复跑。

达不到 1–3 只能报“部分复刻”，并列出卡点（加密、双向认证、服务端风控、缺失密钥）。

---

## B. 插件类目标（R25）

### B0 先判包型与入口

| 形态 | 容器/入口 | 关键文件 | 最小可改单元 |
|---|---|---|---|
| Chrome/Edge MV3 | `.crx`（zip+CRX 头） | `manifest.json`、service worker、content script | SW 消息处理 / content script 注入点 |
| VS Code | `.vsix`（zip） | `extension/package.json`、`extension.js` | command / activation 回调 |
| JetBrains | `.jar`/`.zip` | `META-INF/plugin.xml`、Action/Extension | Action 类 / extension 实现 |
| Electron | `app.asar` | `package.json`、main/preload、`.node` | main/preload 的 IPC 或原生模块 |
| 游戏 Mod | BepInEx/MelonLoader | `BepInEx/plugins/*.dll`、`Assembly-CSharp.dll` | Harmony patch 的目标方法 |

统一动作：先 `file`/`unzip -l`/`jar tf`/`npx asar list` 看结构，再读入口清单，最后才反编译。
命令、解包细节与版本差异见 `references/plugin-reverse.md`。

### B1 浏览器扩展（Chrome/Edge MV3）

- `.crx` 是 CRX3 头 + ZIP；`unzip` 能读时直接解，失败则按 `Cr24` 头长度截取 ZIP 再解。
- 读 `manifest_version`、`permissions`/`host_permissions`、`background.service_worker`、`content_scripts`、`web_accessible_resources`、`externally_connectable`、`nativeMessaging`。
- 逻辑反推：`chrome.runtime.onMessage`、`chrome.webRequest`/`declarativeNetRequest`、`chrome.storage`、`fetch`；content script 在隔离世界，主世界看 `world: "MAIN"`；native messaging 看宿主 manifest 的 `allowed_origins` 与宿主程序路径。
- 签名/完整性：商店扩展受签名与策略约束；改包仅用于授权测试环境。

### B2 VS Code 扩展（`.vsix`）

- `unzip plugin.vsix -d vsix/`；入口在 `extension/package.json` 的 `main`，激活条件在 `activationEvents`，可见功能在 `contributes`。
- 从 `commands`/`menus`/`keybindings` 找到 command id，再在 `extension.js` 搜 `registerCommand`。
- Webview 只是 UI；数据来源看 extension host 侧的文件、网络、`vscode.env`、secret storage。最小可改单元通常是 command handler 或其 service；不要从压缩 bundle 头部硬改。

### B3 JetBrains 插件（`.jar`）

- `jar tf plugin.jar`，读 `META-INF/plugin.xml`：`<actions>`、`<extensions>`、`<applicationService>`、依赖 `lib/`。
- Java/Kotlin 类用 jadx（可读 jar）、CFR/Fernflower 或 IDE 自带反编译；先看 Action 的 `actionPerformed` 与扩展点实现。
- 配置、协议地址、许可证文案常在 `messages/*.properties` 或 `resources/`。最小可改单元是单个 Action/Service 类或扩展点注册；注意 Kotlin 协程与混淆后的 lambda 名。

### B4 Electron（`asar`）

- `npx asar list app.asar`；`npx asar extract app.asar app/`；`npx asar extract-file app.asar <path>` 取单文件。
- 入口看 `package.json` 的 `main`；安全边界看 `preload`、`contextIsolation`、`nodeIntegration`、IPC channel。
- `.node` 是原生模块，JS 层只能看调用契约，必要时用 IDA/Ghidra 看导出函数；asar 完整性/签名先确认校验发生在启动、加载还是更新阶段；最小可改单元是 main 的 IPC handler、preload 暴露面或单个 renderer bundle 模块。

### B5 游戏 Mod（BepInEx/MelonLoader）

- BepInEx：确认 `winhttp.dll`/doorstop 配置、`BepInEx/core`、`BepInEx/plugins`、`LogOutput.log`；插件是托管 DLL。
- MelonLoader：看 `MelonLoader/`、`Mods/`、`UserData/`、`Latest.log`，确认 Il2Cpp 还是 Mono；Mono 用 dnSpy/ILSpy 打开 `Assembly-CSharp.dll`，从入口场景/按钮事件/Update 反推业务方法。
- Il2Cpp：先 `Il2CppDumper` 产出 `dump.cs` 与 `global-metadata`，再用 IDA 对 `GameAssembly.dll`；不要拿 Mono 经验硬套。
- Harmony：`Prefix` 改参数/跳过原逻辑，`Postfix` 改返回值，`Transpiler` 改 IL；最小可改单元是“一个目标方法 + 一个 patch 类”，先验证被调用再改行为。

### B6 插件完成判据（缺一不可）

1. **入口可指认**：能说出文件、清单字段/注册点、运行时加载路径。
2. **关键逻辑 + 数据来源**：定位到具体函数/模块，说明输入、输出、副作用；配置、网络、存储、原生库或游戏对象至少追到一层。
3. **最小单元 + 可验证**：给出文件/类/方法级改动点与回退方式；重载/重启后行为变化符合预期，原功能未被无关破坏。

---

## C. 工具与降级

| 能力 | 首选 | 缺失时 |
|---|---|---|
| 抓包解析 | `tshark`、`seep_pcap_extract` | Wireshark GUI 导出、scapy/dpkt 离线解析 |
| HTTP(S) 重放 | `seep_http_replay`、mitmproxy | requests/curl + 手工复制头；必要时 `SSLKEYLOGFILE` |
| 解包 | `unzip`、`jar`、`npx asar` | Python `zipfile`；CRX 手动跳过头部 |
| .NET 反编译 | dnSpy、ILSpy | `ilspycmd`、`monodis`；仅读 IL 也可定位 |
| Java/Kotlin | jadx、CFR | `javap -c -p` 看字节码 |
| 原生模块 | IDA/Ghidra | `dumpbin /exports`、`nm -D` 先看导出 |

- 工具是否存在不要靠猜：`powershell -File Tool/scripts/tool-run.ps1 -ListModes`，或 `seep_tool_discover`（底层 `Tool/mcp/tool_autodiscover.py`）/ `seep_ensure_tool`。
- 需要 GUI 时走 `tool-run.ps1 -Tool <id>`；能 CLI/headless 就不开 GUI。
- 工具缺失不是停工理由：先用标准库完成 zip/socket/hex 级工作，再补工具。

---

## D. 常见坑（按代价排序）

1. **TLS 双向认证/pinning**：抓到 TLS 不等于拿到明文；先判断证书校验位置，再决定 keylog、代理还是进程内取明文。
2. **WebSocket 分帧**：一个 TCP 段可能含多帧/半帧；必须按 FIN/opcode/长度重组，注意掩码与 `permessage-deflate`。
3. **压缩与序列化**：先解压再分帧；protobuf 字段号不等于业务字段，flatBuffers 先读 vtable。
4. **长度/校验/防重放**：长度含不含头、CRC 覆盖范围、大小端，任一错都表现为“服务端无响应”；重放失败先查 seq/nonce/时间窗/token 绑定。
5. **插件签名/完整性**：CRX 签名、VSIX 市场校验、asar 完整性、游戏反作弊；先定位校验点，再决定是否绕。
6. **入口/运行时误判**：MV3 的 SW 可能被事件唤醒，VS Code 的 `activationEvents` 可能延迟激活，Mod 的 patch 可能未加载；Il2Cpp 与 Mono 工具链不同，先确认运行时再选 dnSpy 或 Il2CppDumper。

---

## E. 交付格式（建议）

```text
目标/版本：          路由：R24 | R25
证据：capture.pcapng#L12 / manifest.json:permissions / LogOutput.log:...
入口：                关键逻辑：
数据来源：            状态机/调用链：
最小可改单元：        复现步骤：
判据：同输入同输出 / 构造新请求 / 入口+逻辑+来源 / 最小单元
未解卡点与置信度：
```

**最后一条**：报告里每个“已确认”都要能指回证据；指不回去的，写“推断”，不要写成结论。
