---
id: "managed/2026-java-license"
title: "Java 授权面：JAR/javap、ProGuard mapping、META-INF 签名"
title_en: "Java Licensing Surface: JAR/javap, ProGuard Mapping, META-INF Signatures"
board: "managed"
category: "techniques"
signals: ["javap", "META-INF/MANIFEST.MF", "ProGuard mapping.txt", "jarsigner", "module-info"]
keywords: ["Java", "JAR", "javap", "jar_manifest", "proguard_map", "ProGuard", "签名"]
last_updated: "2026-10-20"
---
# Java 授权面：JAR/javap、ProGuard mapping、META-INF 签名

## 1. 来源与日期

- OpenJDK `javap` 官方文档（JDK 21/22，2025）：`-p -c -constants -v` 语义。
- ProGuard 官方 README/ReTrace（2025）：`mapping.txt` 格式与堆栈还原。
- Oracle/Sun `jarsigner` 文档（2025）：`META-INF/*.SF`、`*.RSA` 校验流程。

> 引用官方文档/版本级信息；不引用来源不明的"破解 jar"教程。

## 2. 入口信号

- 交付物是 `<JAR>` / `.war` / `.jmod`，或 `META-INF/` 下有 `.SF`/`.RSA`/`.EC`。
- 类名是 `a.b.c`，堆栈里出现 `a.a(Unknown Source)`（ProGuard 混淆）。
- 授权字符串：`license`、`expiry`、`serial`、`activation`、`HardwareUtils`。
- 运行时报 `SecurityException: invalid signature file digest`（签名被破坏）。

## 3. 命令（可复制）

```bash
# 1) 结构与清单
unzip -l <JAR> | head -40
unzip -p <JAR> META-INF/MANIFEST.MF
unzip -l <JAR> | grep -E "META-INF/.*\.(SF|RSA|DSA|EC)$"

# 2) 版本与类列表（先看 class 文件版本）
unzip -p <JAR> <PATH/TO/Main>.class | xxd -l 8    # 前 8 字节：CAFEBABE + minor/major
javap -classpath <JAR> -p -c -constants <FQCN> | head -80
javap -classpath <JAR> -p -v <FQCN> | grep -E "major|minor|flags"

# 3) 全量方法签名（找校验点）
javap -classpath <JAR> -p <FQCN> | grep -Ei "license|valid|check|verify|expire|serial"

# 4) 签名与证书
jarsigner -verify -verbose -certs <JAR> | head -40
keytool -printcert -jarfile <JAR>

# 5) 模块化/多版本 jar
unzip -l <JAR> | grep -E "module-info.class|META-INF/versions/"
```

混淆还原（有 `mapping.txt` 时）：

```bash
head -20 mapping.txt
# 形如：com.example.LicenseManager -> a.b:
#         java.lang.String validate() -> a
java -jar retrace.jar mapping.txt stack.txt
# 批量反混淆类名（按行替换 -> 左侧原名）
awk -F' -> ' '/^[^ ]+ -> /{print $2" "$1}' mapping.txt | head -20
```

## 4. 判据表（字段名）

| 字段 | 取值示例 | 判据 |
| :--- | :--- | :--- |
| `jar_manifest` | `Main-Class: com.example.Main`、`Implementation-Version: 1.4.2`、`Sealed: true` | `MANIFEST.MF` 的关键属性；`Sealed`/`Class-Path` 会影响类加载与授权检查入口 |
| `class_version` | `major=61`（Java 17）、`major=65`（Java 21） | 取自 class 头；版本高于本机 JRE → 反编译能看、运行必失败，先统一运行时 |
| `proguard_map` | `present: mapping.txt (1240 行)`、`absent` | mapping 存在才可把 `a.b.c` 还原成原名；`absent` 时只能按调用图推断 |
| `signed_jar` | `true`（含 `.SF`+`.RSA`）、`false` | 有签名 → 任何 class 改动都会触发 digest 校验失败；无签名 → 改动不受签名约束但可能触发应用自校验 |
| `license_method` | `com.example.LicenseManager.validate()`、`a.b.a()` | 校验方法签名（混淆时用 mapping 还原）；必须能指到 `javap -c` 的具体指令 |
| `check_kind` | `signature`、`digest`、`expiry`、`hardware_binding`、`server` | 校验类型；`digest` 常见于"读 license 文件 + `MessageDigest`"组合 |
| `obfuscator` | `ProGuard`、`Zelix KlassMaster`、`Stringer`、`none`、`unknown` | 由 mapping/类名/字符串解密调用判定；`unknown` 要附证据 |

判定规则：`proguard_map=present` → 先把 `license_method` 还原成原名再定位；
`signed_jar=true` → 任何"改字节码"的路线都要先处理签名，否则运行即失败。

## 5. 失败判据

- `jarsigner -verify` 报 `jar is unsigned` 但有 `.SF`：签名文件残留、清单被裁剪；
  此时运行时是否校验取决于 `java.security` 策略，不能直接判"签名无效"。
- 修改 class 后运行报 `SecurityException: invalid signature file digest`：签名覆盖的是
  摘要，必须整体重签（官方 `jarsigner` 流程）才能加载；这是签名机制，不是授权逻辑。
- `javap` 报 `class not found`：类在 multi-release jar 的 `META-INF/versions/<N>/` 下，
  需 `--multi-release <N>`；或类名被混淆（先 `unzip -l` 找真实路径）。
- `proguard_map=absent`：不要把 `a.b.c` 猜成 `LicenseManager`；用常量/字符串交叉定位。
- 字符串加密（Stringer/Zelix）：`javap -c` 只见 `StringDecryptor.decrypt(...)`，
  静态字符串结论作废；需运行时解密或找解密表。
- 只看到 `System.currentTimeMillis()` 就判"到期校验"：必须找到比较点与失败分支。
- Kotlin/Scala 编译产物：`@Metadata`/伴生对象会让方法名与源码不一致，按字节码为准。

## 6. 边界

- 仅分析自有/授权软件；用于互操作、兼容性、授权审计、漏洞报告。
- 不提供重签分发、不提供绕过 license 的 patch、不发布去混淆后的完整源码。
- 引用 `mapping.txt` 片段时脱敏包名与业务字段。
- 相邻篇：.NET IL → `2026-dotnet-license.md`；Python → `2026-python-bytecode.md`；
  WASM → `2026-wasm-license.md`。
