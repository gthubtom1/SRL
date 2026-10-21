# 05 PE 保护位与 Windows 利用面

> 配套 `Tool/skill/pwn-crypto/references/mitigation-matrix.md`、`01-criteria.md`。
> PE 没有 ELF 的 RELRO/canary 语义；把 ELF 术语套到 PE 上是最常见的误判来源。

## 入口信号

- 目标是 `.exe`/`.dll`/`.sys`，不是 ELF。
- 需要判断 NX/ASLR/GS/CFG，或需要解释“为什么没有 GOT/RELRO/__free_hook”。
- 只有 Windows 目标，无法取得 Linux libc。

## 0. 只读基线

```bash
python Tool/scripts/pwn-check.py --file ./target.exe --json > pwn_check.json
objdump -p ./target.exe | grep -E 'DllCharacteristics|DLL Name|ImageBase'
```

`pwn-check.py` 的 PE 分支读：

- `DllCharacteristics`：`0x0100` = NX_COMPAT，`0x0040` = DYNAMIC_BASE（ASLR），
  `0x4000` = CFG，`0x0020` = HIGH_ENTROPY_VA；
- 导入表：`__security_check_cookie` / `__security_init_cookie` 可提示 GS；
- load config 目录里的 SecurityCookie 指针（非 0 才更可信）。

**确认判据**：能同时给 `DllCharacteristics` 原始值、`pwn-check` 的四项结论、以及节权限
（`.text` 可执行不可写、`.data` 可写不可执行）。
**失败判据**：把 `DYNAMIC_BASE` 直接等同于“PIE enabled”；只看导入表就断言有/无 GS。

## 1. 保护位到 Windows 手法

| 观测 | 阻断什么 | 首试手法 | 确认判据 |
|---|---|---|---|
| NX_COMPAT | 栈/堆执行 | ROP/ret2libc 等价、`VirtualProtect` 改页 | 链命中函数，页权限变为可执行 |
| DYNAMIC_BASE | 固定映像基址 | 泄漏模块基址；1–2 字节部分覆盖 | 模块基址页对齐且与泄漏一致 |
| SecurityCookie | 连续栈溢出 | 泄漏 cookie；格式化串/堆；SEH 覆盖 | cookie 正确且异常链受控 |
| CFG | 间接调用劫持 | 改数据/逻辑；找未登记回调 | 目标调用点不在 CFG 检查内 |
| Full ASLR + GS + CFG + NX | 多数内存破坏 | 逻辑/配置/密码学/信息泄漏 | 有实际数据或行为证据 |

**失败判据**：PE 上找 `printf@got`、`__free_hook`、`PT_GNU_RELRO`；这些概念不存在。

## 2. Windows 与 glibc 的关键差异

1. **`%n` 可能不写**：MinGW/UCRT 下 `printf("abc%n",&x)` 后 x 仍为 0（见案例 05）。
   因此格式化串写路线在 Windows 上经常不可用，但 `%s/%p` 任意读仍可用。
2. **没有 glibc 分配器语义**：不要套 tcache/safe-linking/`__free_hook`；Windows 堆破坏常见表现是
   `STATUS_HEAP_CORRUPTION (0xC0000374)`，不是 glibc 的 `malloc(): corrupted top size`。
3. **异常链**：SEH/VEH 覆盖是 Windows 特有路线；需要确认异常处理版本与编译选项。
4. **调用约定**：x64 前 4 个整型参数在 rcx/rdx/r8/r9；格式化串变参从 rdx 起，参数位置与 SysV 不同。
5. **ASLR 粒度**：DLL/EXE 的基址随机化受系统策略与加载器影响，不能只看编译标志。

## 3. 现场编译一个可控样本（用于验证判据）

```bash
gcc -O0 -fno-stack-protector -no-pie -o stack.exe input/stack_overflow.c
gcc -O0 -fno-stack-protector -no-pie -o fmt.exe   input/fmt_read.c
python Tool/scripts/pwn-check.py --file stack.exe --json
```

- 无 PIE：`nm stack.exe | grep ' win$'` 得到固定地址（如 `0x140001440`），可直接覆盖返回地址。
- 有 NX：仍然可以“跳到已有函数”，不需要执行栈代码。
- 偏移用 `pwn-repro.py --objdump ... --probe-log ...` 两源对齐（案例 03 的 88 就是这样得到的）。

## 4. 交付时必须写清

- 工具链与编译选项（`gcc 15.2.0`、`-O0 -fno-stack-protector -no-pie`）；
- PE 保护位原始值 + 解释（不要只写“PIE enabled”）；
- 偏移来源（objdump 位移 + 运行时 `frame-buf`）；
- 状态码的两种表示（Git Bash 的 127 vs 原始 NTSTATUS `0xC0000374`）；
- 哪些 glibc 手法在此平台**不可用**（`%n` 写、GOT、hook）。

## 失败判据

- 只看 `pwn-check` 的四个词就下结论，没有原始值/节权限 → 判据不足。
- 把 Windows 堆破坏当成 glibc tcache 问题 → 方向错误。
- 在 PE 上用 `readelf`/`checksec` 的 ELF 字段 → 工具与格式不匹配。

## 边界

- 本页只覆盖用户态 PE 的静态保护位与常见利用面；驱动/内核、CFG 绕过细节不在范围内。
- Windows 版本/编译器（MSVC vs MinGW）差异很大；案例数字只对应本仓库的编译产物。
