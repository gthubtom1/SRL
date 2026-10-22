# 案例走查：项目 A 的授权状态字补丁（真实复现）

> 范围：Windows x64 原生客户端、离线授权、代理 DLL 热补丁、twinBASIC/VB6 运行时。
> 路由：服务端权威、VM 保护、.NET 方法体加密由各自路线承担（见 `../SKILL.md`）。
> 本走查只复述仓库内 `Tool/cases/项目A/` 已有的真实结论与原始日志，**不新增目标、不补造证据**。
> 证据分级：`[observed]` = 命令/日志已存在；`[inferred]` = 由证据推导；`[unverified]` = 未复现。

---

## 1. 目标与边界

| 项 | 值 |
| :--- | :--- |
| 案例目录 | `Tool/cases/项目A/` |
| 目标 | `<项目A>.exe`，28.40.0100，PE32+ x64，twinBASIC 982 |
| 目标 SHA256 | `e2b134e9b7e68886d59f005152ae2f339cdf20159ede00cb37fda0f6fda06ccd` |
| 体积 | 39,306,808 字节（37.5 MB） |
| 签名 | 无 |
| 授权存储 | `%APPDATA%\<项目A>64\<项目A>.ini`，UTF-16 LE BOM，`[Register]` 段 |
| 交付形态 | 代理 `version.dll`（DLL 搜索顺序劫持），内存态热补丁，宿主 EXE 磁盘零改动 |
| 关键 RVA | `license_type=0x22FD724`、`ver_flag=0x230170C`、授权状态字 `0x230CDEA`（word） |
| 补丁点 | `0x670CB1`、`0x670BFF`、`0x670CD5`、`0x15E2A47` |
| 证据目录 | `Tool/cases/项目A/v2/docs/repro/` |

**边界**：本案例只证明 28.40.0100 版本、安装版、离线路径；28.30.2600 只有同源偏移记录（差 `-0x1039`），未在本走查中重跑。服务端权威、联网激活、其他产品不在内。

---

## 2. 命令 1：先给代理 DLL 做一次结构判型

```bash
python Tool/skill/softseep/scripts/preflight-classify.py Tool/cases/项目A/v2/dist/version.dll
```

原始输出（节选，`[observed]`）：

```json
{
  "bytes": 257024,
  "sha256": "cc428f85e55ef12d53302696c6f76d74aa364e0d3214da3a0b36bdb128cb8391",
  "format": "pe",
  "machine": "x86-64",
  "bitness": 64,
  "entry_rva": 4912,
  "has_clr": false,
  "has_imports": true,
  "has_relocs": true,
  "sections": [
    {"name": ".text", "vaddr": 4096, "vsize": 203952, "raw": 204288, "entropy": 6.32},
    {"name": ".rdata", "vaddr": 212992, "vsize": 28664, "raw": 28672, "entropy": 5.83},
    {"name": ".pdata", "vaddr": 241664, "vsize": 4584, "raw": 4608, "entropy": 5.35}
  ],
  "antidebug_imports": ["CreateToolhelp32Snapshot", "QueryPerformanceCounter"],
  "platform": "Windows",
  "protection": ["antidebug"],
  "suggested_type": "测绘报告"
}
```

**读法**：这是 64 位 PE，无 CLR，有导入/重定位；`.text` 熵 6.32，不是加壳密文；有 `CreateToolhelp32Snapshot`/`QueryPerformanceCounter`，说明代理 DLL 自己也做进程/时序检查（或链接了会做检查的运行时）。这决定了它适合「代理 DLL + 内存补丁」，不适合「磁盘改 EXE」。

---

## 3. 命令 2：复算案例产物的 SHA256

```bash
python - <<'PY'
import hashlib
for p in [
    "Tool/cases/项目A/v2/dist/version.dll",
    "Tool/cases/项目A/v2/docs/授权链路漏洞分析报告.md",
    "Tool/cases/项目A/defense_hardening.c",
]:
    print(hashlib.sha256(open(p, "rb").read()).hexdigest(), p)
PY
```

原始输出（`[observed]`）：

```text
cc428f85e55ef12d53302696c6f76d74aa364e0d3214da3a0b36bdb128cb8391 Tool/cases/项目A/v2/dist/version.dll
5e49e35f83b0b9cbba42c4c57fe2fd44e7f9393dc5e37af82552c9d6ffe995dc Tool/cases/项目A/v2/docs/授权链路漏洞分析报告.md
ffaa832a028d58b5a4c56ea5c160b64e4613250ffce6b2b90e7f1a009df68dbd Tool/cases/项目A/defense_hardening.c
```

**读法**：三个哈希与 `case.json` 的 `artifacts[].sha256` 一致；代理 DLL 的哈希也与复现日志阶段 0 记录的 `sha256=cc428...` 一致。证据可复算，不是转述。

---

## 4. 命令 3：从复现日志取「原版试用 → 补丁激活 → 还原回落」三段

```bash
python - <<'PY'
p = "Tool/cases/项目A/v2/docs/repro/repro_run_1.log"
for i, line in enumerate(open(p, encoding="utf-8", errors="replace"), 1):
    if any(k in line for k in ("阶段 2", "阶段 4", "阶段 7", "授权状态字", "判定:")):
        print(f"{i:4d}| {line.rstrip()}")
PY
```

原始日志（节选，`[observed]`，来自 `repro_run_1.log`）：

```text
  17|[阶段 2] 官方原版基线状态（期望: 授权状态字=0xFFFF 试用）
  20|    ★ 授权状态字 = 0xFFFF  ->  试用(trial)
  23|    窗口 [ThunderRT6FormDC] ... ### 30 - 天试用版本 - 第 1 天 ### - 28.40.0100
  28|[阶段 4] 激活态实测（期望: 授权状态字=0x0000 已激活 + 标题栏无试用标记）
  31|    ★ 授权状态字 = 0x0000  ->  已激活(activated)
  34|    窗口 [ThunderRT6FormDC] ... 28.40.0100
  37|  判定: 激活状态字归零=True   标题栏无试用标记=True
  40|    30s 后仍存活: PID=36048  授权状态字=0x0000
  45|[阶段 7] 回落校验（期望: 授权状态字=0xFFFF 试用 + 标题栏出现试用标记）
  48|    ★ 授权状态字 = 0xFFFF  ->  试用(trial)
  51|    窗口 [ThunderRT6FormDC] ... ### 30 - 天试用版本 - 第 1 天 ### - 28.40.0100
  53|  判定: 回落官方试用态=True
```

同一日志的阶段 0 与结论段（`[observed]`）：

```text
[阶段 0] 目标画像
  SHA256: e2b134e9b7e68886d59f005152ae2f339cdf20159ede00cb37fda0f6fda06ccd
  PoC: ...\dist\version.dll  (257024 字节, sha256=cc428f85e55ef12d53302696c6f76d74aa364e0d3214da3a0b36bdb128cb8391)
  补丁点: 0x670CB1 / 0x670BFF / 0x670CD5 (激活状态机) + 0x15E2A47 (许可等级呈现)
  状态字 RVA: 0x0230CDEA   试用=0xFFFF / 已激活=0x0000

R1 可复现性 : PASS (独立驱动脚本，无 Seep-Tool 依赖)
R2 可观测性 : PASS (进程内授权状态字 + 标题栏 + 关于框 三重客观判据)
R3 幂等可重入: PASS (重复部署不重复备份)
R4 可还原性 : PASS (还原后回落 0xFFFF 试用态，零残留)
R5 版本绑定 : PASS (28.40.0100 + SHA256 校验，补丁点版本专属)
```

---

## 5. 结论

1. **只写 `license_type=5` 不足以激活。** `license_type` 只是注册码前缀 `xy01..xy05` 的分类结果（`0x22FD724`），不是激活判据；旧方案写了它，状态字仍是 `0xFFFF`，标题栏仍显示试用。`[observed]`，见 `diff_before_after.txt` B 表。
2. **真正的激活开关是 `0x230CDEA` 授权状态字（word）。** 原版 `0xFFFF`=试用，补丁后 `0x0000`=已激活；补丁 1 把 `not eax` 改成 `xor eax,eax`，使「注册加载返回值取反」恒为 0；补丁 2/3 把两个失败分支的 `mov word [rax],0xFFFF` 改成写 0。`[observed]`
3. **补丁 4 只影响呈现层。** `0x15E2A47` 把 `mov r11d,[rsp+0x7C]` 改成 `jmp +0x40`，让关于框无条件显示 Lifetime License；它不参与激活判定，属于显示层补丁。`[observed]`
4. **磁盘零改动、可还原。** 代理 `version.dll` 在运行期打内存补丁，宿主 EXE 的 SHA256 不变；还原后状态字回到 `0xFFFF`，标题栏恢复试用标记，残留文件检查为「无残留」。`[observed]`
5. **版本绑定必须写进交付。** 补丁点只对 28.40.0100 + 上述 SHA256 成立；28.30.2600 仅记录同源偏移（差 `-0x1039`），未在本走查中重跑。`[observed]`（偏移记录）/ `[unverified]`（跨版本实跑）

---

## 6. 失败判据（照着做时会遇到的）

| 现象 | 判定 | 改走哪条 |
| :--- | :--- | :--- |
| 只写 `[Register]`，标题栏仍试用 | `license_type` 不是激活判据 | 找状态字 `0x230CDEA` 的写入点，不要继续改注册码前缀 |
| 补丁 1-3 后进程几秒崩溃 | 改到了非标量函数/破坏了状态机 | 回读三处原始字节，确认只改 `not eax` 与两个 `mov word`，不要整体 `ret` |
| 补丁 4 后关于框正常但激活仍失败 | 呈现层与判定层分离 | 补丁 4 不是激活补丁；回到补丁 1-3 |
| 换 28.30 后偏移全错 | 版本绑定 | 用 AOB/拓扑滑窗重定位，不要复用 28.40 的文件偏移 |
| 还原后仍有残留 | 代理 DLL/ini/log 未清理 | 按 `repro_steps.md` 的还原清单逐项删除，再复算宿主哈希 |

---

## 7. 复跑清单

```text
1) 确认目标 SHA256 = e2b134e9...6ccd，版本 28.40.0100
2) 备份原 EXE 与 version.dll（若存在）
3) 部署 dist/version.dll + xyplorer_patch.ini 到目标目录
4) 写 [Register] Name/Code（Code 以 xy05- 开头，版本段 28.40）
5) 启动，读 0x230CDEA：期望 0x0000；标题栏无「天试用版本」
6) 等 30s，进程仍存活，状态字仍 0x0000
7) 删除代理与 ini/log，重启，状态字回 0xFFFF，标题栏恢复试用
8) 复算宿主 EXE 与代理 DLL 的 SHA256，写回 case.json/报告
```

---

## 8. 边界与未验证项

- **未验证**：28.30.2600 的实跑；其他产品/其他安装形态；联网激活路径；服务端是否还有第二道校验。
- **判据边界**：本案例的 RVA 只对本版本成立；「代理 DLL 可加载」只证明加载链，「关于框显示 Lifetime」只证明 UI 文案。
- **证据强度**：本走查全部引用仓库内已有日志/哈希，没有新增目标行为；`[observed]` 与 `[unverified]` 已逐条标注。
- **安全边界**：只在已授权样本与沙箱内执行；目标从用户提供的清单获取，自动化脚本按 `scope` 限定。
