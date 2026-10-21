---
id: "managed/2026-dotnet-license"
title: ".NET 授权面：dnSpy/ILSpy、Assembly-CSharp、ConfuserEx"
title_en: ".NET Licensing Surface: dnSpy/ILSpy, Assembly-CSharp, ConfuserEx"
board: "managed"
category: "techniques"
signals: ["Assembly-CSharp.dll", "dnSpy", "ILSpy", "ConfuserEx", "ConfusedBy", "UnityEngine"]
keywords: [".NET", "IL", "il_method", "obfuscator", "ConfuserEx", "Unity"]
last_updated: "2026-10-20"
---
# .NET 授权面：dnSpy/ILSpy、Assembly-CSharp、ConfuserEx

## 1. 来源与日期

- dnSpyEx 项目 README（2025 维护分支）：调试/反编译能力与限制。
- ILSpy / `ilspycmd` 官方 README（2025）：命令行导出与项目反编译用法。
- ConfuserEx 项目 README（2025）：`ConfusedBy` 标记、控制流混淆与反调试选项。

> 引用工具官方 README/版本级信息；不引用未公开的第三方破解教程。

## 2. 入口信号

- 目录里有 `Assembly-CSharp.dll`、`Managed/`、`BepInEx/core/`（Unity Mono）。
- `file` 显示 `PE32 .NET assembly`，但 `strings` 看不到可读类名。
- 出现 `ConfusedByAttribute`、方法名为不可打印字符、`<Module>.cctor` 异常庞大。
- 授权相关字符串：`license`、`trial`、`expire`、`activation`、`MachineName`、
  `deviceUniqueIdentifier`、`persistentDataPath`。

## 3. 命令（可复制）

```bash
# 1) 先确认是不是托管程序集（不是则转 IL2CPP 路线）
file <APP>/Assembly-CSharp.dll
python3 - <<'PY'
import sys
p = sys.argv[1] if len(sys.argv) > 1 else "<APP>/Assembly-CSharp.dll"
d = open(p, "rb").read(0x200)
pe = int.from_bytes(d[0x3c:0x40], "little")
off = pe + 24
magic = int.from_bytes(d[off:off+2], "little")
print("PE32+" if magic == 0x20b else "PE32", "COM descriptor RVA:",
      hex(int.from_bytes(d[off+208:off+212], "little")))
PY

# 2) 列出类型/方法（ILSpy 命令行）
ilspycmd -l c <APP>/Assembly-CSharp.dll | head -50
ilspycmd -l i <APP>/Assembly-CSharp.dll | head -50

# 3) 只导出目标类型为工程，便于检索
ilspycmd -t <Namespace.LicenseManager> -o /tmp/il <APP>/Assembly-CSharp.dll
grep -rn "DateTime\|RSA\|MD5\|Registry\|persistentDataPath" /tmp/il | head -30

# 4) monodis 看方法表与自定义属性（ConfuserEx 标记）
monodis --method <APP>/Assembly-CSharp.dll | head -40
monodis --customattr <APP>/Assembly-CSharp.dll | grep -i "ConfusedBy\|Obfuscation" 

# 5) 字符串面（UTF-16 才是 .NET 常见编码）
strings -el <APP>/Assembly-CSharp.dll | grep -Ei "license|trial|expire|activation|serial" | head -20
```

定位校验点（在导出工程里做，不要猜）：

```bash
# 谁在读授权文件/注册表
grep -rn "ReadAllText\|File.Exists\|Registry.LocalMachine\|GetValue" /tmp/il | head -20
# 谁在做签名/哈希比对
grep -rn "VerifyData\|ComputeHash\|FromBase64String\|FixedTimeEquals" /tmp/il | head -20
```

## 4. 判据表（字段名）

| 字段 | 取值示例 | 判据 |
| :--- | :--- | :--- |
| `il_method` | `LicenseManager::Validate(string)`、`Auth::CheckSignature(byte[])` | 校验逻辑所在方法的完整签名；必须能指到 IL（`IL_00xx`）或反编译行，不能只写类名 |
| `obfuscator` | `ConfuserEx 1.6`、`none`、`unknown`、`IL2CPP` | 由 `ConfusedByAttribute`/控制流特征/字符串加密判定；`unknown` 要附证据（如"方法体为 switch 扁平化"） |
| `check_kind` | `signature`、`hash`、`expiry`、`binding`、`server` | 校验类型；`signature`/`hash` 看 `VerifyData`/`ComputeHash`，`binding` 看机器码/`deviceUniqueIdentifier` |
| `verify_key` | RSA/ECDSA 公钥（base64 前 16 字节）、`none` | 公钥内嵌 → 离线验签；无公钥且发网络请求 → 服务端校验，本地改分支无意义 |
| `clock_source` | `DateTime.UtcNow`、`DateTime.Now`、`Stopwatch`、`server_time` | 到期判断的时间源；用本地时间可被系统时钟影响，属可复现的判据 |
| `storage` | `persistentDataPath/license.dat`、`HKCU\Software\<Vendor>`、`ProgramData` | 授权落盘位置；与"运行时是否重新读取"一起看，决定校验点数量 |
| `anti_tamper` | `strongname`、`file_hash`、`debugger_check`、`none` | 强名称/自身哈希/`Debugger.IsAttached`；有自身哈希时改 IL 必触发 |

判定规则：`il_method` 能定位 + `check_kind` 明确 + `verify_key` 有值 → 判"存在离线校验点"。
`verify_key=none` 且出现网络调用 → 判"服务端校验"，本地结论到此为止。

## 5. 失败判据

- 目录里没有 `Assembly-CSharp.dll`：Unity IL2CPP 构建，IL 不存在，改看
  `GameAssembly.dll` + `global-metadata.dat`（另见 `../../field_journal_seed-014_unity-il2cpp-reverse.md`）。
- `ilspycmd -t` 报类型不存在：名字被混淆成不可打印字符，先用 `-l c` 列出真实名字。
- 反编译出 `InvalidProgramException`/空方法体：控制流混淆或 native 保护（Themida/
  .NET Reactor），换 dnSpy 逐 IL 看，或判定 `obfuscator=unknown` 并停止推断。
- 修改 IL 后强名称校验失败：强名称签名覆盖程序集哈希，必须按官方方式重新签名才能加载；
  这是"改了就崩"的最常见原因，不是校验逻辑本身。
- `strings -el` 无命中：字符串被加密/压缩（ConfuserEx `constants` 保护），需在运行时看
  解密后字符串，静态结论作废。
- `monodis --customattr` 无 `ConfusedBy`：可能是其他混淆器或手工裁剪；
  `obfuscator` 应写 `unknown`，不要写 `none`。
- 只看到 `File.Exists` 就判"授权校验"：可能只是读配置；必须有失败分支（抛异常/退出/
  降级）才算 `check_kind` 成立。

## 6. 边界

- 仅分析自有/授权软件；用于互操作、兼容性排查、授权审计与漏洞报告。
- 不提供去混淆成品、不发布 patch/loader、不提供绕过激活的步骤。
- 反编译代码片段最小化引用，注明程序集版本与哈希。
- 相邻篇：Java 字节码 → `2026-java-license.md`；Python 打包 → `2026-python-bytecode.md`；
  WASM → `2026-wasm-license.md`。
