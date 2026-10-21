---
id: "managed/2026-wasm-license"
title: "WebAssembly 授权面：wabt/wasm2c、函数边界与常量"
title_en: "WebAssembly Licensing Surface: wabt/wasm2c, Function Boundaries and Constants"
board: "managed"
category: "techniques"
signals: ["wasm-objdump", "wasm2wat", "wasm2c", "name section", "i32.const", "V8 bytecode"]
keywords: ["WASM", "wabt", "wasm_sections", "func_count", "wasm2c", "V8 bytecode"]
last_updated: "2026-10-20"
---
# WebAssembly 授权面：wabt/wasm2c、函数边界与常量

## 1. 来源与日期

- WebAssembly Binary Toolkit（wabt）1.0.38，2025-10：`wasm-objdump`/`wasm2wat`/
  `wasm2c` 的官方 README 与版本说明。
- rce.moe，2025-01：V8 字节码与内建函数的分析笔记（JS→字节码→WASM 边界的观测法）。
- WebAssembly Core Spec 2.0（2025）：段 ID 与函数/代码段计数规则。

> 引用工具版本与官方 README/规范；不引用来源不明的"wasm 破解"脚本。

## 2. 入口信号

- 交付物含 `.wasm`/`.wat`，或 JS 里 `WebAssembly.instantiateStreaming`、
  `new WebAssembly.Module`、base64 内嵌 wasm。
- `wasm-objdump -h` 有 `Custom` 段但无 `name` 段（符号被裁）。
- 导出函数名可疑：`_check_license`、`validate`、`_verify`、`memory`。
- 授权字符串在 data 段（`license`、`expired`、`trial`），或常量比较集中在一个函数。

## 3. 命令（可复制）

```bash
# 1) 段布局（先看有没有 name/data/import）
wasm-objdump -h <FILE>.wasm
wasm-objdump -x <FILE>.wasm | head -120

# 2) 结构校验（判断是否被裁剪/拼接）
wasm-validate <FILE>.wasm && echo OK

# 3) 反汇编到文本（函数边界最清楚）
wasm2wat <FILE>.wasm -o /tmp/out.wat
grep -n "(func " /tmp/out.wat | head -20
grep -n "i32.const" /tmp/out.wat | head -40

# 4) 伪代码级（比 wat 好读，保留函数边界）
wasm-decompile <FILE>.wasm -o /tmp/out.dcmp
grep -n "^function" /tmp/out.dcmp | head -20

# 5) 转 C 再编译分析（大模块/需要交叉引用时）
wasm2c <FILE>.wasm -o /tmp/out.c
grep -n "Z_.*validate\|Z_.*license" /tmp/out.c | head -20

# 6) 函数/常量定位（按导出名或索引）
wasm-objdump -d <FILE>.wasm | grep -n "func\[" | head -30
```

内嵌/压缩场景：

```bash
# base64 内嵌：从 JS 里剥出 wasm 后校验头部 magic
python - <<'PY'
import base64, re, sys
s = open(sys.argv[1], encoding="utf-8", errors="ignore").read()
for m in re.finditer(r"[A-Za-z0-9+/]{200,}={0,2}", s):
    raw = base64.b64decode(m.group(0) + "===")
    if raw[:4] == b"\x00asm":
        open("/tmp/embedded.wasm", "wb").write(raw)
        print("wasm at", m.start(), "size", len(raw))
        break
PY

# 去符号后的函数索引仍可从 code 段数量推出
wasm-objdump -h <FILE>.wasm | grep -E "Function|Code"
```

V8 字节码侧（JS 包装层，2025-01 rce.moe 方法）：

```bash
node --print-bytecode --print-bytecode-filter=<FUNC_NAME> <SCRIPT>.js | head -60
# 或 d8：d8 --print-bytecode <SCRIPT>.js
```

## 4. 判据表（字段名）

| 字段 | 取值示例 | 判据 |
| :--- | :--- | :--- |
| `wasm_sections` | `Type(1)`、`Import(2)`、`Function(3)`、`Export(7)`、`Code(10)`、`Data(11)`、`Custom(0)` | 段 ID/名称/大小清单；缺 `Code` → 不是可执行模块；有 `Custom` 无 `name` → 符号被裁 |
| `func_count` | `Function=214 / Code=214` | 两段计数必须相等；不等说明文件损坏或被拼接 |
| `imports[]` | `env.memory`、`wasi_snapshot_preview1.fd_write` | 导入面决定运行环境；`env` 自定义导入多 → 可能是 Emscripten/自研 glue |
| `exports[]` | `_check_license`、`memory`、`_start`、`malloc` | 导出名即入口；`_check_license` 类名字直接给出校验点 |
| `license_func` | `func[37] _check_license`、`func[12]`（无 name） | 函数索引 + 名字（若有）；无 name 时用调用图/常量定位 |
| `const_hits[]` | `i32.const 0x1f`、`i64.const 0x...`、data 段字符串 `expired` | 校验函数内的比较常量/错误码；与 `data` 段字符串交叉验证 |
| `data_strings[]` | `license`、`trial expired`、`invalid key` | data 段可读字符串；被压缩/编码时为空，不能判"无校验" |
| `name_section` | `present`、`stripped` | `Custom(name)` 是否存在；`stripped` 时所有 `func[N]` 只能靠索引 |

判定规则：`exports[]` 含校验类名字 + `const_hits[]` 与 `data_strings[]` 对得上
→ 判"存在本地校验函数"。`name_section=stripped` 时，结论必须写"按索引推断"。

## 5. 失败判据

- `wasm-validate` 失败：文件被截断/自定义加密（部分商业壳在 wasm 外加壳），
  先解外层再谈段分析。
- `wasm-objdump -h` 没有 `name` 段：`func[N]` 与源码名对不上，不能把 `func[37]`
  直接写成 `validate`；需要调用图或运行时验证。
- `wasm2c` 生成的 C 编译不过：缺 WASI/Emscripten 运行时 shim（`wasi_snapshot_preview1`
  导入未实现），属工具链问题，不是模块损坏。
- 大模块（`func_count` 数千，Emscripten 产物）：`wasm-decompile` 输出可能极大且可读性差；
  先按 `exports[]` 缩小到单个函数，再 `wasm-objdump -d` 看指令。
- data 段字符串为空但导出名可疑：字符串可能运行时解密（在 JS glue 里），
  静态 `data_strings[]` 为空不构成"无校验"证据。
- 只看到 `i32.const` 比较就判"授权校验"：必须找到返回值被用于分支/抛错的位置。
- 把 V8 字节码当 wasm：`node --print-bytecode` 输出的是 JS 函数字节码，
  与 `.wasm` 段结构无关，两者要分开记录。

## 6. 边界

- 仅分析自有/授权软件；用于互操作、兼容性、供应链审计、漏洞报告。
- 不提供 wasm 补丁成品、不发布绕过授权的 loader、不分发修改后的模块。
- 引用 wat/C 片段最小化，注明 wabt 版本与模块哈希。
- 相邻篇：.NET → `2026-dotnet-license.md`；Java → `2026-java-license.md`；
  Python 打包 → `2026-python-bytecode.md`。
