# 2026 战例：bytenode / V8 字节码反编译的版本闸门

> 战例 KB-PLUGIN-2026-06 · 收录 2026-10-20 · 单篇 ≤200 行 · 只写版本对齐与判据，不复述 Electron 加载链。

## 来源与日期

- rce.moe（2025-01）《Decompiling V8 bytecode》：`.jsc` 是带版本头的 V8 字节码，跨版本不可读，
  并给出 header/constant pool/handler table 的定位方法。
- bytenode 维护文档（2025–2026）：`bytenode.compileFile` 产出的 `.jsc` 与 Node/Electron 的 V8 版本强绑定。
- 2026 年样本面观察：Electron 应用中 `.jsc` 常与 asar 同包，主进程用 `require('bytenode')` 加载。
- 本页为公开材料 + 既有 field journal 蒸馏；不含本机反编译产物，命令需按目标版本替换。

## 场景

入口信号：

- asar 里有 `*.jsc`，`main` 指向 `.jsc`，或代码里出现 `bytenode`、`v8code`、`compileFile`。
- `strings` 能看到明文 API 名/URL，但拿不到控制流（`.jsc` 常量池仍保留字符串）。
- 需要回答：这段逻辑到底做了什么，能否在本地以等价源码复跑。

先做“版本三件套”，再决定是否值得反编译：

| 证据 | 取值来源 | 用途 |
| :-- | :-- | :-- |
| 目标 V8 版本 | `process.versions.v8`（在应用内）/ `electron --version` | 选反编译器与 opcode 表 |
| 字节码 header | `.jsc` 前 16–32 字节（magic + version hash + flags） | 与 V8 版本对表 |
| 运行时快照 | `v8-flags`、`--no-lazy`、`--print-bytecode` 可用性 | 验证反编译结果 |

## 命令

```bash
# 0) 容器与入口
npx asar list app.asar | grep -E '\.jsc$|package.json'
npx asar extract-file app.asar main.jsc
xxd -l 64 main.jsc

# 1) 版本三件套（先拿目标应用的，不要用本机 node 顶替）
node -p "process.versions.v8 + ' node=' + process.version"
npx electron --version 2>/dev/null
node -e "const v=require('v8');console.log(v.getHeapStatistics().heap_size_limit)" 2>/dev/null

# 2) header 对表：magic/version hash/flags
python - <<'PY'
b = open('main.jsc','rb').read(64)
print('magic', b[:4].hex(), 'ver_hash', b[4:8].hex(), 'flags', b[8:12].hex())
print('candidate_len', int.from_bytes(b[12:16],'little'))
PY

# 3) 反编译（按版本选工具；版本不符会直接抛 invalid bytecode）
#    view8 / v8dasm / bytenode 生态工具，参数以工具 --help 为准
view8 main.jsc --out main.js 2>view8.err || head -20 view8.err

# 4) 运行时验证：用同版本加载并打印字节码/行为
node --no-lazy --print-bytecode -e "require('bytenode');require('./main.jsc')" 2>&1 | head -60
node -e "require('bytenode'); require('./main.jsc')" ; echo "rc=$?"

# 5) 与 asar 内明文片段对齐（常量池校验）
strings -a main.jsc | sort -u > jsc.strings
grep -nE 'https?://|token|license' jsc.strings | head -20
```

## 判据表

| 字段 | 取值 | 成立阈值 | 证据 |
| :-- | :-- | :-- | :-- |
| `v8_version_match` | `exact` / `minor` / `mismatch` | 反编译与运行验证都要求 `exact`；`minor` 只能做字符串级分析 | `versions.txt` + header 十六进制 |
| `bytecode_header` | magic + version hash + flags | 与目标 V8 的 header 逐字节一致；`candidate_len` 合理（非 0/非超文件） | `header.json` |
| `decompile_status` | `full` / `partial` / `failed` | `full` 需函数边界、常量池、异常表三段齐全 | `main.js` + 覆盖率 |
| `const_pool_match` | 反编译产出的字符串集合 vs `strings` 集合 | `strings` 是子集（漏 ≤5%），否则说明常量池解析错位 | 两个排序文件 diff |
| `handler_table_ok` | switch/异常跳转目标是否落在函数体内 | 全部目标合法；任一越界即 `partial` | 反编译器报告 |
| `runtime_behavior` | 原 `.jsc` 与反编译结果的行为差异 | 关键副作用（网络/文件/命令）一致，或差异可解释 | 两次运行日志 |
| `load_rc` | `require` 退出码 | `rc=0` 才能证明字节码本身可加载（版本闸门通过） | 运行输出 |

`v8_version_match=exact` 是硬闸门：不满足时，`decompile_status` 只能写 `failed`，
不得用“看起来像”的输出反推业务逻辑。

## 失败判据

- `require('./main.jsc')` 报 `Invalid or incompatible bytecode` / 段错误 → 版本不符，停。
- 用本机 Node 的 V8 版本去反编译 Electron 的 `.jsc` → 假设错，回到版本三件套。
- 反编译输出只有顶层壳、函数体为空 → `partial`，不能据此判断“没有恶意逻辑”。
- `const_pool_match` 差异 >5% 或出现乱码标识符成片 → 常量池错位，换工具/换版本。
- 运行时行为与反编译结果不一致且无法解释 → 以运行观测为准，反编译只作参考。
- `.jsc` 外还有 native addon（`.node`）承担关键逻辑 → 转 `ida-reverse`，本页不覆盖。
- 触发完整性校验/授权服务器回连 → 记录 `license-gate`，不绕过。

> 边界：只分析授权获取的应用包；不修改 `.jsc` 后重新分发；反编译产物仅用于本地等价复跑；
> 版本号必须来自目标应用自身，不能用“最新版 V8”近似。

## 与 reference 的关系

- Electron/asar 加载链：[electron-and-asar.md](../../../../../../../Tool/skill/plugin-targets/references/electron-and-asar.md)。
- 入口与权限面：[browser-extension.md](../../../../../../../Tool/skill/plugin-targets/references/browser-extension.md)（同属“入口可指认”判据）。
- 失败判据：[02-failure-criteria.md](../../../../../../../Tool/skill/plugin-targets/references/02-failure-criteria.md)。
- 同 board 邻近篇：[asar-main-process.md](asar-main-process.md)（main/preload/IPC 定位）、
  [asar-and-mod-loaders.md](asar-and-mod-loaders.md)（加载器识别）、
  [plugin-failure-criteria.md](plugin-failure-criteria.md)（何时转静态/转逆向）。
