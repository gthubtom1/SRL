# pwn-crypto07 · dostackbufferoverflowgood（公开靶场原始制品）

> 本案例只做**静态**：目标 exe 未被本流程启动、加载、调试或投递输入。
> 结论上限是「现行静态见证条件在这份公开发布制品上成立」，**不是**「可利用」。

## 1. 这是什么

上游作者（GitHub 账号 `justinsteven`）为 CrikeyCon 3（2016-02-20）发布的教学用**有意脆弱** Windows
程序 `dostackbufferoverflowgood.exe`，随 `github.com/justinsteven/dostackbufferoverflowgood`
公开发布。案例保存的是**上游原字节**，没有编译、补丁或重打包。

| 项 | 值 |
|---|---|
| 文件 | `target/dostackbufferoverflowgood.exe` |
| 大小 | 13312 字节 |
| sha256 | `d298c229234aed475233b175c1f6db2667776854cc87e5a4d82eb9f216a3fe3a` |
| 上游 HEAD | `f67b555a5d9da766516094bbd0c8a680e7afc248` |
| Git blob（SHA1） | `043b2d38b1ce46efd1bfc26b282ae627f3c59459` |
| 格式 | PE32 x86（32-bit），入口 RVA `0x1a48`，ImageBase `0x8040000`，5 节 |
| DllCharacteristics | `0x8000`（仅 TERMINAL_SERVER_AWARE） |

来源一致性由**两条独立传输路径**交叉验证，证据就在本案里：

- `capture/upstream-verify-summary.json` — 两路核验的结构化摘要（HTTP 状态/响应头子集、
  Git blob SHA1 与 size、`ls-remote` HEAD、`cat-file` rc、字节一致性、`all_verified`）
- `capture/upstream-download-manifest.json` — REST blob API 路径的原始下载清单
- `capture/upstream-git-transport-verify.json` — Git over HTTPS 对象传输路径的逐对象核验
- `capture/http-meta-exe.json` / `capture/http-meta-readme.json` — 两次 REST 请求的原响应头

原始响应体与 3.3MB 裸 Git 仓不随案例分发；摘要只保留采集摘要的 sha256，活动证据链不再依赖
案例外的 staging 目录。

## 2. 许可与署名（上游原文，非转述）

上游 `README.md`（另存为 `upstream-README.md`，4180 字节，Git blob `2b14a9bf…`）License 段原文：

- `The code for \`dostackbufferoverflowgood.exe\` is licensed under Apache License` / `Version 2.0`
- `The slides and tutorial are licensed under a Creative Commons Attribution 4.0` / `International License.`
- `You are welcome to modify and redistribute this material, provided you credit` / `me as the original author.`

- **代码许可**：Apache License 2.0 —— 全文随案例保存为 `LICENSE-APACHE-2.0.txt`
  （11357 字节，Git blob `8dada3ed…`，含 `END OF TERMS AND CONDITIONS`）。
- **教程/幻灯片**：CC BY 4.0 International（**不覆盖** exe）。
- **署名**：按案例内字节可达的范围，只到 **GitHub 账号 `justinsteven`**
  （README 第 35/39/40 行的 twitter/youtube/twitch 链接均为 `…/justinsteven`），
  配合时间线 `Created for CrikeyCon 3, 20 February 2016`。
  **作者全名不在案例字节内**，因此本案例不以全名作署名依据（见 `facts.jsonl` 的 `PW07-02.evidence_audit`）。
  这**不主张全名错误**——只是本轮随案证据不足，故不写进证明主张。

## 3. 静态见证（精确命令与 actual 结果）

```bash
python Tool/skill/pwn-crypto/scripts/pwn-check.py \
    --file Tool/cases/pwn-crypto07/target/dostackbufferoverflowgood.exe --json
```

- `rc=0`，stdout 是 JSON，stderr 为空；运行前后目标 sha256 都是 `d298c229…a3fe3a`。
- 完整 argv / rc / stdout 原文 / 旧版本对照：`capture/static-witness-2026-10-27.log`。
- 字段摘录（未手改）：`artifacts/static-witness.json`。

| 字段 | actual 值 |
|---|---|
| kind / arch / bits | `PE` / `x86` / `32` |
| entry | `0x1a48` |
| protections | `NX=Disabled`、`PIE=Disabled`、**`Canary=Found (SecurityCookie)`**、`RELRO=N/A` |
| sections（5） | `.text`(RX) `.rdata` `.data`(RW) `.gfids` `.rsrc` |
| import_count | 65（8 个 DLL） |
| dangerous_imports | 1：`VCRUNTIME140.dll!memmove` |
| next_routes | `栈溢出 + shellcode`，带 caveat `Canary 存在：先泄漏或改走格式化/堆` |

## 4. 为什么 Canary 从 Not found 变成 Found（重要）

**变的是解析器，不是制品。** `pwn-check.py` 原实现的 load-config 解析有两处真实缺陷：

| 位宽 | SecurityCookie 字段 | 指针宽度 | 最小结构大小 | 原实现 |
|---|---|---|---|---|
| PE32 | 结构内 `0x3C` | 4 | `0x40` | 用统一阈值 `lc_size >= 0x48` 一刀切 → 本目标目录恰为 64 字节，**整段被跳过** |
| PE64 | 结构内 `0x58` | 8 | `0x60` | 一律按 `u32` 读 → 小端下只拿到**低 32 位**，值低位全零、高位非零时**误判为 0** |

本次修复只动这一处（位宽 + 最小结构 + 文件/节边界 + 结构自身 `Size` 交叉校验），
导入、节表、ELF、路由逻辑未动。可用合成 PE 复现：

```bash
python Tool/cases/pwn-crypto07/tools/parser-boundary-tests.py            # 12/12 PASS（修复版）
PWN_CHECK_PATH=<仓库原版> python Tool/cases/pwn-crypto07/tools/parser-boundary-tests.py
#   原版 9/12：失败的正是 PE32 dir_size=0x40、PE64 高非零低零、PE32 字段刚好压线三种
```

逐例结果：`artifacts/parser-boundary-tests.json`。修复的完整说明与两版工具 sha256：
`capture/static-witness-2026-10-27.log` §1、§4。

### 4.1 怎么读 `Canary=Found`

- 只说明 **load config 里声明了 SecurityCookie**：目录 RVA `0x31e0`、`dir_size=64`（PE32 最小 `0x40`，足够）、
  结构自身 `Size=92`、字段在结构内 `0x3C` 宽 4、文件偏移 `0x1fe0`、落在 `.rdata` raw 范围内、
  原始值 `0x8044018`、作为 VA 落在 image `[0x8040000, 0x8048000)` 内 → 语义上像一个真 cookie 指针。
- **不**证明任何具体函数编译时插了 GS prologue，也**不**证明运行期真的校验 canary。
- 名称扫描 `__security_check_cookie` / `__security_init_cookie` / `__report_gsfailure` /
  `@stack_chk` **全部未命中**（`artifacts/header-probe.json` 的 `name_scan`）。
- **更不**能因为作者 README 自述「Compiled without ASLR, DEP or Stack Canaries」就要求分析结果
  必须复述该叙述。二进制是事实，README 是作者当时的说明；两者不一致时**以字节为准并如实记录差异**。

## 5. 导入面（为什么 `dangerous_imports` 只是下界）

`artifacts/import-surface.json`（工具：`tools/import-surface.py`）：

- 总数 65、8 个 DLL；`WS2_32.dll` 12 项里 **10 项按序号导入**（`#ord_1/#ord_2/#ord_3/#ord_13/
  #ord_16/#ord_19/#ord_23/#ord_111/#ord_115/#ord_116`）。序号在 PE 里不带名字，不查外部
  `.def`/序号表无法还原成 `recv`/`send`/`closesocket` —— 名字白名单**必然**漏掉它们。
- 5 个 `api-ms-win-crt-*` API set 承载 C 运行库；经典名（`printf`/`sprintf`/`malloc`/`free`/
  `memcpy`/`strcpy`/`gets`/`scanf`）**一个都没出现**；另有 2 个 `__stdio_common_*` 分区符号。
- 被解析但未入白名单清单的安全相关名：`IsDebuggerPresent`、`SetUnhandledExceptionFilter`、
  `UnhandledExceptionFilter`、`TerminateProcess`、`GetModuleHandleW`、`_beginthread`。

## 6. 负例（两类，互相独立）

**(a) 解析层 —— 结构性拒绝**（`capture/negative-controls-2026-10-27.log`、`artifacts/negative-controls.json`）

| 构造件 | pwn-check rc | 判定 |
|---|---|---|
| 0 字节空文件 | 2 | `ok:false` `blocked_at=parse`，`既不是 PE(MZ) 也不是 ELF` |
| `MZ` → `XX` | 2 | 同上 |
| `e_lfanew` 处 `PE\0\0` → `XXXX` | 2 | `e_lfanew 处没有 PE 签名` |
| 截断到前 0x80 字节 | 2 | 同上 |

**(b) 绑定层 —— witness 必须拒换包**（`artifacts/witness-negative-controls.json`，工具 `tools/witness-negative-check.py`）

| 用例 | 结果 |
|---|---|
| P1 默认目标（报告 sha256 == manifest sha256） | `rc=0`，`artifact_kind=public` |
| N1 换成另一真实案例产物 `pwn-crypto06/target/dvcp.exe` | `rc=1`（sha256 不符） |
| N2 真实制品改一字节 | `rc=1` |
| N3 空文件 | `rc=1`（pwn-check 结构化拒绝） |
| N4 `case.json` 登记 sha256 改全 0 | 非 0（`--self-test` 下归一为 `rc=2`） |

全部在临时目录复制输入构造；目标原字节未改（前后 sha256 相同）。

## 7. 边界（不得越过）

1. `protections` 是 **DllCharacteristics + 导入/load-config 近似**，不是加载后实际页权限。
2. `Canary=Found` 的读法见 §4.1（声明存在 ≠ 函数启用 GS ≠ 运行期校验）。
3. `dangerous_imports` 是**符号名白名单命中的下界**（见 §5）。
4. **本案例交付的是静态调用记录**：本流程里没有任何一步启动/加载/调试目标 exe，
   因此可达性、偏移、EIP 控制、SEH 链、DEP 绕过、拿 shell **全部未验证**。
   注意这条只说「本记录里没有 exe 启动项」——目标字节哈希前后不变不能反证
   「该程序从未被任何进程执行」。
5. 因此 `goal_level=L1`、`outcome=partial`。

## 8. 复现

```bash
python Tool/skill/pwn-crypto/scripts/pwn-check.py \
    --file Tool/cases/pwn-crypto07/target/dostackbufferoverflowgood.exe --json   # rc=0
python Tool/skill/pwn-crypto/scripts/witness.py                                  # rc=0（核对 manifest 哈希）
python Tool/cases/pwn-crypto07/tools/parser-boundary-tests.py                    # 12/12（解析器边界）
python Tool/cases/pwn-crypto07/tools/header-probe.py --json                      # 第二实现头部读数
python Tool/cases/pwn-crypto07/tools/import-surface.py --json                    # 导入面普查
python Tool/cases/pwn-crypto07/tools/witness-negative-check.py                   # 5/5（witness 拒换包）
python Tool/scripts/case_state.py verify --case Tool/cases/pwn-crypto07
```

`witness.py` 的负例开关（只换输入，不降判据）：
`--target <别的文件>`、`--case-dir <别的案例>`、`--check-tool <另一份 pwn-check>`。
