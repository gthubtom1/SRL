# 符号恢复：从剥离二进制到可读函数表

> 适用：PE/ELF/Mach-O 的符号缺失、PDB 不在手、函数名全是 `sub_xxx`、vtable/RTTI 需要重建。
> 不适用：VM 保护内部的字节码函数（只能行为级命名）、完全加密的载荷（先脱壳）。
> 目标：用「调试目录/公开符号/签名库/指纹/调用图/RTTI」六条线，把函数名恢复到能支撑结论的程度。
> 原则：**符号是证据，不是装饰。** 每个恢复的名字都要能说出依据。

---

## 1. 先判断「有没有符号可恢复」

| 检查 | 命令 | 结论 |
| :--- | :--- | :--- |
| PE 调试目录 | `dumpbin /headers app.exe` 找 `Debug Directories` | 有 `RSDS`/`NB10` 才可能匹配 PDB |
| CodeView 记录 | `llvm-pdbutil dump --summary app.pdb` | 有 PDB 才有类型/行号/函数名 |
| 导出表 | `dumpbin /exports app.dll` | 导出名可直接命名 |
| 导入表 | `dumpbin /imports app.exe` | 只给 API，不给内部函数 |
| ELF 符号 | `nm -C app` / `readelf -sW app` | `.symtab` 在则有；`stripped` 则无 |
| Mach-O 符号 | `nm -nm app` / `dyldinfo -export app` | `LC_SYMTAB`/`LC_DYSYMTAB` |
| 字符串/异常表 | `strings -n 6 app`；`.pdata`/`.eh_frame` | 剥离后仍可恢复函数边界与部分语义 |

**判据**：如果只有 `.dynsym` 且函数名全是 `sub_`，不要假装有符号；转到签名/指纹/调用图路线。

---

## 2. PDB 路径与 RSDS

### 2.1 CodeView RSDS 结构

PE 调试目录里的 CodeView 记录：

```text
struct CV_INFO_PDB70 {
    DWORD CvSignature;   // 'RSDS' = 0x53445352
    GUID  Signature;     // 16 字节
    DWORD Age;
    char  PdbFileName[]; // NUL 结尾，常是绝对路径或文件名
};
```

- `CvSignature == 'RSDS'`：PDB 2.0（GUID + Age）。
- `CvSignature == 'NB10'`：PDB 1.0（时间戳 + Age），老工具链。
- `PdbFileName` 可能是构建机绝对路径（如 `D:\build\...\app.pdb`），**不要照抄到交付文档**；只保留文件名与 GUID/Age。

**提取命令：**

```bash
dumpbin /headers app.exe | sed -n '/Debug Directories/,+12p'
llvm-pdbutil dump --summary app.pdb
```

或纯 Python（可执行：打印 GUID/Age/PDB 名 + symbol-server key）：

```python
import struct, sys

def rsds(path):
    d = open(path, "rb").read()
    e = struct.unpack_from("<I", d, 0x3C)[0]              # e_lfanew
    assert d[e:e+4] == b"PE\0\0", "not a PE"
    opt = e + 24                                          # COFF 头 20 字节
    magic = struct.unpack_from("<H", d, opt)[0]           # 0x10B=PE32 / 0x20B=PE32+
    dd = opt + (0x60 if magic == 0x10B else 0x70)         # DataDirectory 起始
    rva, size = struct.unpack_from("<II", d, dd + 6 * 8)  # [6] = IMAGE_DIRECTORY_ENTRY_DEBUG
    nsec = struct.unpack_from("<H", d, e + 6)[0]
    secoff = opt + struct.unpack_from("<H", d, e + 20)[0]  # SizeOfOptionalHeader

    def off(rva):                                         # RVA -> 文件偏移
        for i in range(nsec):
            _, vsz, va, rsz, raw = struct.unpack_from("<8sIIII", d, secoff + 40 * i)
            if va <= rva < va + max(vsz, rsz):
                return raw + (rva - va)
        raise ValueError("RVA 不在任何节内: 0x%X" % rva)

    for i in range(size // 28):                            # 每项 IMAGE_DEBUG_DIRECTORY = 28 字节
        _, _, _, _, typ, dsz, addr, praw = struct.unpack_from(
            "<IIHHIIII", d, off(rva) + 28 * i)
        if typ != 2:                                       # 2 = IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        cv = off(addr)                                     # 用 AddressOfRawData(RVA)；praw 也是同一处
        if d[cv:cv + 4] != b"RSDS":
            continue
        d1, d2, d3 = struct.unpack_from("<IHH", d, cv + 4)  # 前三段小端
        tail = d[cv + 12:cv + 20]
        guid = "%08X-%04X-%04X-%s-%s" % (d1, d2, d3,
                tail[0:2].hex().upper(), tail[2:8].hex().upper())
        age = struct.unpack_from("<I", d, cv + 20)[0]
        name = d[cv + 24:d.index(b"\0", cv + 24)].decode("utf-8", "replace")
        return guid, age, name.split("\\")[-1].split("/")[-1]

    return None

guid, age, name = rsds(sys.argv[1])
key = "%s/%s%X/%s" % (name, guid.replace("-", ""), age, name)   # <名>/<GUID><Age>/<名>
print("GUID=%s AGE=%d PDB=%s" % (guid, age, name))
print("key=%s" % key)
print("url=https://msdl.microsoft.com/download/symbols/%s" % key)
```

> 注意 `Age` 是**十六进制**拼接（`%X`），GUID 去连字符后大写；写成十进制 key 会 404。

### 2.2 用 GUID/Age 找 PDB

- 公开符号服务器按 `<PDB 名>/<GUID+Age>/<PDB 名>` 索引；常见：
  - `https://msdl.microsoft.com/download/symbols`
  - 厂商自己的 symbol server（若公开）
- 下载模板（`key` 取自上面脚本的 `key=` 一行）：

```bash
curl -fL --retry 2 --max-time 120 -o app.pdb \
  "https://msdl.microsoft.com/download/symbols/app.pdb/5A1B2C3D4E5F60718293A4B5C6D7E8F91/app.pdb"
head -c 32 app.pdb          # 必须是 "Microsoft C/C++ MSF 7.00"，否则是 404/HTML 页
```

- 实测判据：`curl -f` 退 0 且头 8 字节为 `Microsoft C/C++ MSF 7.00`；把 Age 改一位同一个 key 就 404（`-f` 使 rc=22 且不落地坏文件）。

- 本地缓存：`%SYSTEMROOT%\Symbols`、`_NT_SYMBOL_PATH`。
- 判据：下载到的 PDB 的 GUID/Age 与 RSDS **完全一致**；不一致不能用。

```bash
llvm-pdbutil dump --summary app.pdb | grep -Ei "guid|age"   # 与脚本输出逐字符比对
sha256sum app.pdb                                            # 写进 manifest，便于复算
```

- **GUID/Age 不匹配 → 拒绝使用**：删掉或改名为 `*.pdb.reject-<guid>` 隔离。版本不同的 PDB 会把函数名/结构体偏移指错，比「没有符号」危险得多。
- 边界：没有公开 PDB 的第三方软件，不要猜；转签名/指纹。

### 2.3 有 PDB 时怎么用

```bash
llvm-pdbutil dump --modules app.pdb
llvm-pdbutil dump --types app.pdb | head
llvm-pdbutil dump --publics app.pdb | head
```

- `--publics` 给函数/全局符号；`--types` 给结构体布局；`--modules` 给编译单元。
- 用 PDB 的结构体布局校正 IDA/Ghidra 的本地类型；不要凭猜测改偏移。
- PDB 只给「名字/类型/行号」，不给「这个函数是否授权判据」；语义仍要交叉引用。

---

## 3. 公开符号与签名库

### 3.1 FLIRT（IDA）

- `.sig`/`.pat` 文件按库函数字节模式匹配；适合静态链接的 CRT/STL/OpenSSL。
- 用法：IDA `File > Load File > FLIRT signature file`；或 `idat -S"flirt_apply.idc"`。
- 判据：命中的函数名 + 库版本要写进报告；不同 CRT 版本的签名可能误命中。
- 边界：编译器优化/内联会破坏签名；FLIRT 对自定义代码无效。

### 3.2 Lumina（IDA）

- 连接厂商/社区 Lumina 服务器，按函数哈希取元数据（名字/注释/类型）。
- 适合常见开源库与已知恶意样本；不是万能，隐私/联网策略要先确认。
- 判据：同一函数哈希在 Lumina 与本地反编译语义一致；只信名字不信语义仍会错。

### 3.3 Ghidra FID / Function ID

- `fidb` 数据库由已知库生成；Ghidra 自动匹配函数名。
- 用法：`analyzeHeadless ... -postScript FunctionIDScript.java` 或 GUI `Analysis > Function ID`。
- 判据：匹配度/冲突要记录；低置信匹配不要直接改名。

### 3.4 其他

- `radare2`：`zignatures`/`flirt` 插件；`r2 -A` 后 `aaa` 自动分析。
- `Binary Ninja`：`Signature Library`；`Ghidra`：`Version Tracking` 做跨版本匹配。
- `Diaphora`（IDA）：跨二进制函数匹配，适合「旧版有符号、新版剥离」。

---

## 4. 剥离后的函数指纹

### 4.1 常量与字符串

- 字符串交叉引用是最稳的入口：错误文案、注册表路径、API 名、格式串。
- 常量：CRC 多项式、AES S-box、Base64 表、RSA 模数、魔数（`0xDEADBEEF`、`MZ`、`PK`）。
- 判据：字符串/常量必须落在函数的引用链上，不是碰巧在同一个节。

### 4.2 调用图

```text
main -> WinMain -> InitInstance -> LicenseInit -> ReadLicense -> VerifySignature
                                     |-> CreateWindow -> WndProc -> CheckMenu
```

- 先找入口（`main`/`WinMain`/`DllMain`/`_start`），再按调用图向下。
- 递归/间接调用会断图；用动态断点补。
- 判据：从入口到目标函数的路径可打印；不能只说「xref 到了」。

### 4.3 结构体/栈帧指纹

- 同一结构体偏移在多个函数出现（如 `[rbx+0x120]` 状态字段）；按访问模式命名。
- 栈帧大小 + 局部变量类型 + 调用序列可做函数聚类；用于跨版本匹配。
- 判据：至少两个函数共享同一偏移语义，才把它命名为「状态对象字段」。

### 4.4 字节模式（AOB）

- 用「指令序列 + 通配符」匹配，不匹配绝对地址；跨版本迁移见 `09-patch-engineering.md`。
- 判据：模式在目标版本唯一命中；多命中要加二次判别（调用者/字符串/节）。

---

### 4.5 指纹组合与置信度

单个指纹很容易误判，实际使用「组合指纹」：

| 组合 | 例子 | 置信度 |
| :--- | :--- | :--- |
| 字符串 + 调用图 | `"License expired"` → `ShowError` → `VerifyLicense` | 高 |
| 常量 + 结构体偏移 | AES S-box + `[obj+0x18]` 轮密钥 | 高 |
| 导入 + 调用序列 | `CryptVerifySignature` + `CertVerifyCertificateChainPolicy` | 中高 |
| 单独字节模式 | 一段 `48 89 5C 24 08` | 低（编译器常用序言） |
| 单独字符串 | `"debugger"` | 低（可能在资源/日志里） |

**判据**：至少两种不同来源的指纹指向同一函数，才把它写进「已恢复符号」表；否则标 `candidate`。

---

## 5. vtable 与 RTTI 恢复

### 5.1 MSVC

```text
vftable[-1] -> RTTICompleteObjectLocator
  +0x00 signature ('1'/'0')
  +0x04 offset
  +0x08 cdOffset
  +0x0C pTypeDescriptor
  +0x10 pClassDescriptor
TypeDescriptor:
  +0x00 pVFTable
  +0x08 spare
  +0x10 name  // ".?AVFoo@@"
```

- 找 `.rdata` 中连续函数指针；前一项是 COL 指针。
- `TypeDescriptor.name` 可直接恢复类名；`.?AV` = class，`.?AU` = struct。
- 多继承：每个基类子对象一个 vftable；`this` 调整 thunk 形如 `sub rcx, 8; jmp real`。

### 5.2 Itanium ABI（GCC/Clang）

```text
vptr[-2] -> offset-to-top
vptr[-1] -> typeinfo
vptr[0]  -> 第一个虚函数
typeinfo: _ZTI<name>，名字是 mangled
```

- 用 `c++filt` 还原 `_ZTV`/`_ZTI`/`_ZTS`。
- `dynamic_cast` 走 `__dynamic_cast`；`typeid` 走 `typeinfo` 比较。
- 判据：vtable 指针由构造函数写入；不是所有「连续函数指针表」都是 vtable。

### 5.3 恢复流程

1. 找构造函数（写入 `[obj] = &vftable` 的位置）。
2. 找 vftable 地址（`.rdata`，前项 COL/typeinfo）。
3. 枚举虚函数槽位，按 `call [rax+slot]` 的交叉引用命名。
4. 用 RTTI/typeinfo 恢复类名；用 PDB/FLIRT 补字段名。
5. 写「槽位 → 函数 → 语义 → 证据」表，不要只写类名。

---

## 6. 跨版本符号迁移

| 场景 | 方法 | 判据 |
| :--- | :--- | :--- |
| 旧版有 PDB，新版剥离 | Diaphora/BinDiff 函数匹配；按调用图/字符串/常量对齐 | 匹配函数 ≥80% 且关键函数人工复核 |
| 旧版有符号，新版小改 | AOB + 拓扑跨距（调用序列的相对距离） | 新版本唯一命中；偏移差可解释 |
| 库升级（OpenSSL/CRT） | FLIRT/FID 重新匹配；版本号写进报告 | 库版本与导入/字符串一致 |
| 完全重构 | 不迁移；重新按入口/字符串/调用图分析 | 旧符号只作参考，不硬套 |

---

## 7. 工具命令速查

| 目的 | 命令 | 备注 |
| :--- | :--- | :--- |
| PE 头/调试目录 | `dumpbin /headers app.exe` | 看 `Debug Directories`、`DllCharacteristics` |
| PE 导出/导入 | `dumpbin /exports app.dll` / `dumpbin /imports app.exe` | 导出名可直接用 |
| PDB 摘要 | `llvm-pdbutil dump --summary app.pdb` | GUID/Age/模块 |
| PDB 公共符号 | `llvm-pdbutil dump --publics app.pdb` | 函数/全局 |
| PDB 类型 | `llvm-pdbutil dump --types app.pdb` | 结构体布局 |
| ELF 符号 | `nm -C app` / `readelf -sW app` | `stripped` 则无 `.symtab` |
| ELF 动态 | `readelf -d app` | `DT_NEEDED`/`RPATH` |
| ELF 展开 | `readelf --debug-dump=frames app` | `.eh_frame` CFI |
| Mach-O 符号 | `nm -nm app` | `LC_SYMTAB` |
| Mach-O 依赖 | `otool -L app` | dylib 列表 |
| Mach-O 签名 | `codesign -dvvv app` | 签名链/entitlements |
| C++ 反修饰 | `c++filt _ZTV...` | Itanium ABI |
| 函数匹配 | `diaphora` / Ghidra Version Tracking | 跨版本 |
| 库签名 | IDA FLIRT / Ghidra FID / r2 zignatures | 静态库/CRT |

**注意**：`dumpbin`/`llvm-pdbutil` 不在 PATH 时，先探测再降级到纯 Python PE/PDB 解析；不要假设工具一定存在。

---

## 8. ELF / Mach-O / JAR 的符号与结构

> PE 之外的三类目标各有自己的符号载体；先确认「哪张表还在」，再谈恢复。

### 8.1 ELF：`.symtab` vs `.dynsym`

```bash
readelf -SW app | grep -E "symtab|dynsym|gnu.version"   # 哪张表存在
readelf -sW app                 # 全符号；stripped 后只剩 .dynsym
nm -C --defined-only app        # FUNC/OBJECT 与 demangle
```

- `.symtab` 是链接期符号（含 LOCAL/文件名），`strip` 后消失；`.dynsym` 只保留导出/导入。
- 版本脚本（`--version-script`）把符号绑成 `name@@VER`；`readelf -V` 查 `.gnu.version_d/_r`，`st_info` 区分 GLOBAL/LOCAL/WEAK。
- 判据：`.symtab` 存在且 `nm` 给出目标 `FUNC`；否则只能拿 `.dynsym` 导出名 + `.eh_frame` FDE 恢复边界，内部函数名标「不可用」。

### 8.2 Mach-O：`LC_SYMTAB` / `__LINKEDIT`

```bash
otool -l app | grep -A5 LC_SYMTAB      # symoff/nsyms/stroff/strsize
nm -m app                              # (undefined) external / (__TEXT,__text)
otool -Iv app                          # 间接符号表：stub -> 导入
dyld_info -bind -lazy_bind app         # 剥离后仍可恢复绑定
```

- 符号表与字符串表都在 `__LINKEDIT`；`LC_DYSYMTAB` 给本地/外部符号分组；`dyld_shared_cache` 里的系统库用 `dyld_info`/`jtool2` 按镜像抽取，别直接 `nm` 整个 cache。
- 判据：`LC_SYMTAB.nsyms > 0` 且 `stroff/strsize` 落在 `__LINKEDIT`；`nsyms == 0` 时只能恢复导入（bind opcodes），内部函数名标「不可用」。

### 8.3 JAR：`MANIFEST.MF` / `javap` / ProGuard

```bash
unzip -l app.jar | head -30            # META-INF/MANIFEST.MF、类条目
javap -p -c -constants -l -classpath app.jar com.x.Main   # 私有成员+字节码+行号
```

- `MANIFEST.MF` 的 `Main-Class`/`Premain-Class`/`Agent-Class` 必须指向真实类条目；`Multi-Release: true` 要按版本目录取类；`META-INF/*.SF` 存在时记录验签结果。
- ProGuard/R8：`mapping.txt` 的 `a.b.c -> com.x.Y` 是唯一可信映射；无 mapping 时混淆名只能按调用图/字符串猜。
- 判据：`javap -p -c` 输出目标方法 `Code`；`mapping.txt` 行与类名逐字匹配。
- 失败判据：只有 `.dynsym`/`nsyms==0`/无 `Code`（类加密或自定义 ClassLoader）→ 不得宣称符号可用，改走调用图/字符串/动态 trace。

## 9. 符号恢复证据表模板

```text
函数 RVA | 恢复名 | 依据（字符串/常量/调用图/RTTI/PDB/FLIRT） | 置信度 | 反证/未验证项
0x1400012A0 | VerifyLicense | 字符串 "License expired" + 调用 CryptVerifySignature | 高 | 未确认是否服务端复核
0x1400023C0 | inline_strlen | pcmpeqb/pmovmskb 零比较模式 | 高 | 尾部逐字节未逐条核对
0x140003110 | sub_140003110 | 仅一段 48 89 5C 24 08 | 低 | 可能是任意函数序言
```

**判据**：表中每一行都能被另一名分析者按「依据」列复算；不能复算的行删除或降级。

---

## 10. 失败判据

| 现象 | 判定 | 改走哪条 |
| :--- | :--- | :--- |
| PDB GUID/Age 不匹配 | 版本不对/构建不同 | 不要硬加载；找匹配 PDB 或转指纹 |
| FLIRT 命中一堆 `_strlen` 但语义不对 | 编译器/优化版本不匹配 | 换签名库或关掉低置信匹配 |
| 字符串 xref 到多个函数 | 字符串被合并/共用 | 用调用者/参数/上下文二次判别 |
| vtable 候选没有 COL/typeinfo | 可能只是函数指针数组 | 找构造函数写入点再确认 |
| 跨版本匹配率低 | 重构/混淆/编译器变了 | 重新分析入口与关键字符串，不要硬迁 |
| 恢复的名字无法解释 | 凭感觉命名 | 删除该名字，回到证据 |

---

## 11. 边界

- 符号恢复服务于「定位判据」，不是目的；不要为了命名而命名。
- 公开符号服务器/在线 Lumina 涉及联网与隐私，按环境策略使用；离线场景走本地 FLIRT/FID/指纹。
- PDB 路径可能泄露构建机信息，交付文档只保留文件名与 GUID/Age。
- .NET 元数据符号用 `ilspycmd`/dnlib；Java 字节码与 ProGuard 映射见 §8.3。
- **失败判据**：恢复出的名字无法用「字符串/常量/调用图/RTTI/PDB」任一列解释 → 视为猜测，删除。
