# B 轮独立审计：深度与真实可用性

> ⚠️ **历史快照（非现状）**：本文记录的是当时的口径与数字，可能与本仓当前状态不一致。
> 当前状态以 `docs/history/FORK-BRIEF.md` + `docs/RELEASE-1.26.1.md` + 实跑门禁为准。

- 仓库/基线：`D:/Seep-Reverse-Lab`，HEAD `a9d2a40`，VERSION 1.23.1；`git status` 仅有本轮审计文件。
- 方式：只读 + 实跑；临时输出全部落 `/tmp`，未改代码、未 commit。
- 规模核对：11 域（`domain_spec.py`）、44 能力（`Tool/capabilities/*.json`）、22 配方（playbooks 去掉 README/INDEX）。

## 结论

**核心 10 域不是名义存在**：11 个域的脚本 200–1100 行，`--help/--self-test` 全 rc=0；抽跑的 55 条任务卡命令全部 rc=0；11 域 KB 99 篇中 98 篇有代码块（唯一例外是 pwn 失败判据速查表）；每域都有 real/self-built 案例。真正的问题不在“脚本是空壳”，而在**第 11 域没有接进编排层、配方层命令漂移、能力注册表过期、证据链不闭环**。

1. **site-clone 是“第 11 个孤岛”**：域门禁 PASS，但 `seep-start` 拒绝 `--domain site-clone`（rc=2），0/22 配方引用 `site-crawl/rebuild/diff/accept`，3 个能力仍写“待补脚本”。
2. **22 配方中 15 个至少有一条命令会失败**：8 个传了脚本不存在的 `--json`，1 个把 `--file` 传给只收位置参数的脚本，6 个把交付等级写成 `L2`（脚本只认 M1–M4）；另有 1 个 `probe_api.py` 路径写错。
3. **证据链可“空跑通过”**：`--out` 父目录不存在时静默不写仍 rc=0；`case_state prove` 接受不存在的 evidence 文件；`claim` 对不存在目录抛裸栈。
4. **三条跨域链只有一条真通**：license→patch/rollback 实测可 apply+rollback 且哈希一致；site-clone→05 缺转换器；qinglong→session-pool/sign-recompute 没有接线。
5. **16 个 probe 能力：8 个可手工走，8 个脚本/引用错配**（见下表）。

## P0（声称能做但跑不通，按影响排序）

### P0-1 site-clone 未接入入口/配方/能力三层
- `python Tool/scripts/seep-start.py --domain site-clone --case sc --target https://block.youtest.me` → **rc=2**，argparse 只列 10 域。
- `grep -rl 'site-crawl.py\|site-rebuild.py\|site-diff.py\|site-accept.py' Tool/playbooks/*.md` → **0 个**；`site-clone-1to1` 仍用 web-check/pcap-summary + 手工 playwright，最后调用 `web-accept`。
- `Tool/capabilities/site-crawl.json`、`site-rebuild.json` 的 `scripts` 为空，note 写“待补”；实际脚本 689/735 行且已实跑。`visual-diff.json` 同样为空，`site-diff.py` 已存在。
- 影响：用户被 routing 送到 site-clone 后，入口工具报错、配方找不到新脚本；这是“11 域”与“22 配方/44 能力”之间的断点。

### P0-2 配方命令漂移：15/22 至少一条失败
- `web-accept.py --json`：`site-clone-1to1`、`backend-rebuild`、`web-api-sign-reverse` → **rc=2**（usage: 只接受 --root/--case/--out）。
- `reverse-accept.py --json`：`license-bypass-deliver`、`license-hookup`、`reverse-survey`、`ui-rebrand`、`version-migrate` → **rc=2**。
- `case_state.py deliver --level L2`：`qinglong-signin`、`multi-account-runner`、`apk-ad-removal`、`apk-unpack`、`app-daily-task`、`captcha-handling` → **rc=2**，`[ERR] level 只能是 M1/M2/M3/M4`；同参数改 `M2` → rc=0。
- `protobuf_decode_raw.py --file <x> --json`：`protocol-replay` → **rc=2**，该脚本只收位置参数 `input`。
- `python Tool/scripts/probe_api.py`：`multi-account-runner` 步骤 3 → **rc=2**，文件不存在；真实路径是 `Tool/skill/apkseep/scripts/probe_api.py`。

### P0-3 证据链不闭环（可静默“成功”）
- `seep-start --case bsite` 写 `evidence/bsite/`，而 10 个配方后续写/读 `work/<case>/`。
- `python Tool/skill/web-pentest/scripts/web-check.py --url ... --out /tmp/newdir/x.json` → **rc=0，但文件不存在**（`open` 失败只打 stderr，仍返回 0）。
- `case_state.py claim --case /tmp/nope/work/x` → **rc=1 + FileNotFoundError 裸栈**，不是结构化 `{"ok":false,...}`。
- `case_state.py prove --case /tmp/x --id S1 --evidence /tmp/nonexistent.json` → **rc=0**，只查字符串非空，不查文件存在。
- 影响：配方最后一步可以“prove 成功”而没有任何 artifact，和 DOMAIN-SPEC 的“证据可复算”直接冲突。

### P0-4 后端复刻腿只有文档
- `Tool/skill/05-backend-rebuild/` 只有 114 行 `SKILL.md`，无 scripts/references/cases；`site-clone` 的 `backend_required[]` 没有任何脚本消费它。
- 影响：仿站链到“后端要重建”就停住，只能人工重写；这是 `site-clone → 05-backend-rebuild` 缺失的那一环。

## P1（深度不足，按影响排序）

1. **sign-recompute 名不副实**：唯一脚本 `sig_probe.py` 取 Android `PackageInfo.signatures[0]`，不是请求签名复算；capability note 自己承认“只取平台返回的签名字符串”。qinglong/Web 签名链因此只能手写 Python。
2. **site-crawl / site-rebuild / visual-diff 注册表过期**：脚本存在却不在 capability 里，refs 还指向 `web-pentest/07-waf` 和 `02-ui-rebrand`；后者 86 行、0 个命令块。
3. **tls-decrypt 只有证书体检**：`tls_check.py` 只验证证书链；capability ref `tls-and-cert.md` 中 grep 不到 `keylog/SSLKEYLOGFILE/tls.keylog_file`，解密命令在别的域文档里。
4. **license-locate 无脚本**：`scripts=[]`，只能 IDA/Ghidra 手工交叉引用；license 链的“定位”环节没有可复算产物。
5. **permission-evidence 脚本参数错配**：capability 把 `manifest-summary.ps1` 当 APK 入口，实际只收 `-ManifestPath`；用 `-ApkPath` 实跑 rc=1。另一个 `capabilities.py` 是宿主能力探测，不产出权限证据。
6. **ipc-audit 脚本不是 IPC**：`svc_scan.py` 只扫 `svc` 指令（无 binder/ipc 关键字）；ref `native-and-so.md` 只有 1 条 `dumpsys`，不足以覆盖 Binder/服务枚举。
7. **yara-write 无编译/验证脚本**：`yarac` 本机缺失，仓库没有编译检查器；`mal-triage` 只给 `yara.text` 建议规则。
8. **memory-forensics / rootfs-emulate / adcs-abuse 依赖外部工具且无 blocked_at**：本机 `volatility3`、`qemu-system-*`、`certipy` 均缺；文档有命令，但没有脚本化降级分支。
9. **配方判据字段与脚本输出不一致**：`malware-triage` 写 `triage.json.ioc_counts`，实际 key 是 `iocs`/`summary`；`firmware-extract` 写 `entropy_blocks`，实际 `fw-triage` 只有 `entropy`/`containers`；`multi-account-runner` 的 `pool_size`、`web-api-sign` 的 `source_url` 无脚本产出。
10. **site-clone-drill01 域标错**：`case.json.domain=web-pentest`，但 id/目录/产物都是 site-clone；`index.json` 把它算进 web-pentest，site-clone 实际只有 3 案。

## 16 个 probe 能力逐项判定

| 能力 | 判定 | 依据 |
|---|---|---|
| adcs-abuse | 可手工走（工具缺） | ref 有 certipy 命令；本机无 certipy |
| cache-test | 可手工走 | ref 有 curl X-Cache/Age 判据 |
| jwt-test | 可手工走 | ref 有 jwt_tool/hashcat/pyjwt 命令 |
| k8s-enum | 可手工走 | ref 有 `kubectl auth can-i --list` |
| license-locate | 可手工走（弱） | 380 行 ref，但无脚本、无结构化产物 |
| memory-forensics | 可手工走（工具缺） | volatility 命令齐全；本机无 vol.py |
| rootfs-emulate | 可手工走（工具缺） | qemu-user/system 命令齐全；本机无 qemu |
| symbol-recover | 可手工走 | IDA FLIRT/Ghidra 命令齐全 |
| sign-recompute | **错配** | sig_probe 是包签名，不是请求签名 |
| tls-decrypt | **错配** | tls_check 只验证书；ref 无 keylog 命令 |
| permission-evidence | **错配** | manifest-summary 要 -ManifestPath；capabilities.py 是宿主探测 |
| ipc-audit | **错配** | svc_scan 只扫 svc；ref 仅 1 条 dumpsys |
| site-crawl | **过期** | 脚本 689 行，capability scripts=[] |
| site-rebuild | **过期** | 脚本 735 行，capability scripts=[] |
| visual-diff | **过期** | site-diff.py 已存在，capability scripts=[]，ref 0 命令 |
| yara-write | **缺脚本** | 无编译检查；yarac 缺失 |

## 22 配方抽样与实跑

- 抽 8 个首步：qinglong-signin（case_state init）、site-clone-1to1/backend-rebuild/web-api-sign-reverse/firmware-emulate/plugin-analysis/malware-triage（seep-start）、license-bypass-deliver（preflight-classify）→ **8/8 rc=0**。首步普遍是建案/分诊，不暴露问题。
- 继续按步骤跑即暴露：`web-accept --json`、`reverse-accept --json`、`protobuf --file`、`deliver L2`、`probe_api` 路径，合计 **15/22** 配方至少一处失败。
- 配方里“写了但仓库没有该脚本/参数不对”的清单：`Tool/scripts/probe_api.py`（缺）、`--json`（web-accept/reverse-accept/protobuf 不认）、`--level L2`（case_state 只认 M1–M4）。

## 跨域衔接

- **site-clone → 05-backend-rebuild**：`site-accept` 能输出 `backend_required[]`，但 05 只有 SKILL.md，无消费脚本；site-clone SKILL 也不引用 05。缺“把 backend_required 转成 API 契约/桩/切换测试”的转换器。
- **qinglong → session-pool/sign-recompute**：0 个 playbook 提到 `session-pool`/`sign-recompute`；qinglong 的能力表也没有它们。`session-pool.py` 只做本地状态分级（不发请求、不刷新 cookie）；`sign-recompute` 无请求签名器。缺“取 cookie/token → 池化 → 刷新 → 签名复算”的可执行段。
- **license-bypass → patch/rollback**：`patch-verify.py` 对 `Tool/samples/real/crackerjack/a.exe` 实跑 apply rc=0、rollback rc=0，`cmp` 与 backup 完全一致；`reverse-accept --case Tool/cases/案例-真实补丁a`（不带 `--json`）rc=0。这条链技术上成立，弱点是 license-locate 只能手工。

## 真实目标端到端

`https://block.youtest.me`（只读、≤3 页）：

| 步骤 | 命令 | rc | 结果/卡点 |
|---|---|---|---|
| crawl | `site-crawl.py --url ... --out /tmp/audit-crawl --max-pages 3 --max-depth 1 --rps 2` | 0 | playwright；routes=3、assets=69、api=1 |
| rebuild | `site-rebuild.py --crawl /tmp/audit-crawl --out /tmp/audit-rebuild` | 0 | assets=68、failed=0、404=0、external=0 |
| diff | `site-diff.py --crawl ... --rebuild ... --out /tmp/audit-diff.json` | 0 | PARTIAL；pixel=0.0、DOM=1.0、missing_rate=0.75（3 页上限所致） |
| accept | `site-accept.py --case Tool/cases/site-clone02` | 0 | PASS 6/6 |

卡点不在抓取/重建/差分，而在**配方收尾**：playbook 结尾的 `web-accept --json` rc=2；且临时产物不是 case 目录，`site-accept` 无法直接验收。另：`probe_api --base ... --path /` 在 Git Bash 被 MSYS 转成 `...meC:/Program Files/Git/`，rc=1；配方未提示 `MSYS_NO_PATHCONV=1`。

## 最小修复动作（按顺序）

1. `seep-start.py` 的 `DOMAINS/COMMANDS` 加 `site-clone`；把 `site-clone-1to1` 改成 crawl→rebuild→diff→accept 的新脚本，收尾用 `site-accept`。
2. 一次性修 15 个配方的命令漂移：`web-accept/reverse-accept` 去 `--json`；`protobuf` 改位置参数；`deliver --level L2`→`M2`；`probe_api` 用完整路径。加一个“抽取配方命令并校验 flag/level”的离线检查。
3. `--out` 父目录不存在时创建目录，或返回 rc=2 结构化失败；`case_state prove` 增加 evidence 文件存在校验；`claim` 对不存在 case 返回结构化错误而不是裸栈。
4. 更新 `site-crawl/site-rebuild/visual-diff` 三个 capability 的 scripts/refs；修正 `sign-recompute/tls-decrypt/permission-evidence/ipc-audit` 的 note 与 ref，注明真实脚本只覆盖哪一段。
5. 增加 `backend_required→backend-rebuild` 转换器（至少输出 API 契约 + 桩清单）；把 `session-pool` 接进 qinglong，并补一个通用请求签名复算脚本。
6. 为 `volatility3/qemu/certipy/yarac` 类外部工具加 `tool-missing` 探测与 `blocked_at` 降级，避免 probe 能力只能靠人记。

## 证据索引

- 域脚本规模/自检：`Tool/skill/*/scripts/*.py`；`--help/--self-test` 逐域实跑。
- 配方命令：`Tool/playbooks/*.md`；`case_state.py deliver` 源码 829–846 行。
- 能力注册表：`Tool/capabilities/{site-crawl,site-rebuild,visual-diff,sign-recompute,tls-decrypt,permission-evidence,ipc-audit,yara-write}.json`。
- 能力错配：`Tool/scripts/apk/manifest-summary.ps1` 参数；`svc_scan.py`；`tls_check.py`；`sig_probe.py`。
- 链缺口：`Tool/skill/05-backend-rebuild/`（仅 SKILL.md）；`Tool/skill/signin-automation/scripts/*`（无 SKILL/案例/配方引用）。
- 端到端产物：`/tmp/audit-crawl/site-graph.json`、`/tmp/audit-rebuild/rebuild.json`、`/tmp/audit-diff.json`。
