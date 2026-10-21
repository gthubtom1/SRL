---
id: "managed/2026-python-bytecode"
title: "Python 字节码授权面：pyc 魔数、pycdc、PyInstaller 提取"
title_en: "Python Bytecode Licensing Surface: pyc Magic, pycdc, PyInstaller Extraction"
board: "managed"
category: "techniques"
signals: [".pyc", "pycdc", "PyInstaller", "MEI cookie", "PYZ-00.pyz", "MAGIC_NUMBER"]
keywords: ["Python", "pyc", "pyc_magic", "pyi_archive", "PyInstaller", "pycdc"]
last_updated: "2026-10-20"
---
# Python 字节码授权面：pyc 魔数、pycdc、PyInstaller 提取

## 1. 来源与日期

- `pycdc` / Decompyle++ 官方 README（2025）：支持的 opcode 版本与已知失败模式。
- PyInstaller 官方文档（2025）：CArchive/PYZ 结构、`pyi-archive_viewer` 用法。
- CPython `importlib.util.MAGIC_NUMBER` 文档（3.11–3.13，2025）：pyc 头字段布局。

> 引用官方文档/版本级信息。魔数随小版本变化，本文给"取值方法"而非固定表。

## 2. 入口信号

- 交付物是 `.pyc`、`__pycache__/`，或单文件可执行（PyInstaller/Nuitka/py2exe）。
- 二进制尾部有 `MEI` cookie，或 `strings` 出现 `PYZ-00.pyz`、`pyimod0*`。
- 反编译报 `unsupported opcode`/`bad magic number`。
- 授权字符串：`license_key`、`expiry`、`hmac`、`machine_id`、`base64.b64decode`。

## 3. 命令（可复制）

```bash
# 1) 本机魔数（唯一可信来源；跨版本必须用对应解释器）
python -c "import sys,importlib.util;print(sys.version.split()[0], importlib.util.MAGIC_NUMBER.hex())"

# 2) pyc 头：4B magic + 4B flags + 4B mtime + 4B size（PEP 552）
xxd -l 16 <FILE>.pyc
python - <<'PY'
import sys
p = sys.argv[1] if len(sys.argv) > 1 else "<FILE>.pyc"
b = open(p, "rb").read(16)
print("magic:", b[:4].hex(), "flags:", int.from_bytes(b[4:8], "little"),
      "mtime:", int.from_bytes(b[8:12], "little"),
      "size:", int.from_bytes(b[12:16], "little"))
PY

# 3) 反编译 / 反汇编
pycdc <FILE>.pyc | head -80
pycdas <FILE>.pyc | head -60          # 只看字节码，失败率更低
python -m dis <FILE>.py 2>/dev/null   # 有源码时最稳

# 4) PyInstaller 单文件：先看 cookie，再抽 CArchive
python - <<'PY'
import sys
p = sys.argv[1] if len(sys.argv) > 1 else "<APP>.bin"
b = open(p, "rb").read()
i = b.rfind(b"MEI\014\013\012\013\016")
print("cookie_at:", i, "size:", len(b))
print("tail:", b[i:i+88].hex()[:64])
PY

pyi-archive_viewer <APP>.bin          # PyInstaller 自带，交互式列 TOC
pyinstxtractor-ng <APP>.bin           # 解出 PYZ 与各 .pyc
```

抽取后定位校验点：

```bash
grep -rn "license\|expire\|hmac\|machine_id\|uuid.getnode" <EXTRACT_DIR> 2>/dev/null | head -20
python - <<'PY'
import marshal, dis, sys
p = sys.argv[1] if len(sys.argv) > 1 else "<FILE>.pyc"
code = marshal.loads(open(p, "rb").read()[16:])
dis.dis(code)
PY
```

## 4. 判据表（字段名）

| 字段 | 取值示例 | 判据 |
| :--- | :--- | :--- |
| `pyc_magic` | `a70d0d0a`（3.11 实测）、`cb0d0d0a`（3.12 实测） | 前 4 字节；与 `importlib.util.MAGIC_NUMBER` 对齐才可用对应版本反编译，不一致先换解释器 |
| `pyc_flags` | `0`（timestamp）、`1`/`3`（hash-based） | PEP 552 位；`hash-based` 时 `mtime/size` 无意义，缓存失效判断不可用 |
| `pyc_version` | `3.11`、`3.12`、`unknown` | 由 `pyc_magic` 反查；`unknown` 时不猜，用 `pycdas` 看 opcode 特征 |
| `pyi_archive` | `present: cookie@<off>, TOC=214`、`absent` | `MEI` cookie 存在 → PyInstaller；TOC 条目数决定抽取完整性 |
| `pyi_entries[]` | `PYZ-00.pyz`、`pyimod02_importers`、`struct`、`<APP>` | CArchive TOC 关键项；`struct` 缺失会导致 PYZ 解析失败 |
| `pyz_modules[]` | `license_check`、`main`、`utils.crypto` | PYZ 内的模块名；无源码时按模块名定位校验点 |
| `license_func` | `license_check.validate(key)`、`main.check_license()` | 校验函数（`dis` 可见）；混淆时用常量/字符串交叉定位 |
| `check_kind` | `hmac`、`expiry`、`machine_binding`、`server` | 校验类型；`hmac` 看 `hmac.compare_digest`，`machine_binding` 看 `uuid.getnode`/MAC |

判定规则：`pyc_magic` 匹配本机解释器 + `pyc_version` 明确 → 才可 `pycdc`；
`pyi_archive=present` 但 `pyi_entries[]` 缺 `PYZ-00.pyz` → 判定"包被裁剪"，先修抽取。

## 5. 失败判据

- `bad magic number`：`pyc_magic` 与解释器不匹配。**不要**手改魔数强行加载，opcode
  可能整体变了；先装对应版本。
- `pycdc` 报 `Unsupported opcode`：新版 CPython（3.12+）opcode 变动快，改用 `pycdas`
  读字节码，或换 `decompyle3`/`uncompyle6`（仅支持到较老版本）。
- PyInstaller 解出 `PYZ-00.pyz` 但无 `.pyc`：PYZ 是压缩容器，需用
  `pyi-archive_viewer` 的 `X` 命令按模块导出，不能直接当 zip 解。
- `marshal.loads` 报 `bad marshal data`：魔数已对但字节码被截断/加密（PyArmor/
  商业壳）；此时静态路线结束，记录 `pyc_version=unknown`。
- 单文件其实是 Nuitka：没有 `MEI` cookie，产物是 C 编译的 ELF/PE，`pyc` 路线不适用。
- 有源码 `.py` 却去反编译 `.pyc`：源码与 pyc 可能不同步（旧缓存），以 `mtime/size`
  字段判断，必要时删缓存重生成。
- 只看到 `base64.b64decode` 就判"授权加密"：可能只是配置解码；必须找到比较/失败分支。

## 6. 边界

- 仅分析自有/授权软件；用于互操作、兼容性、供应链审计、漏洞报告。
- 不提供脱壳成品、不发布绕过 license 的 patch、不分发被修改的打包产物。
- 抽取出的源码片段最小化引用并注明版本/哈希。
- 相邻篇：.NET → `2026-dotnet-license.md`；Java → `2026-java-license.md`；
  WASM → `2026-wasm-license.md`。
