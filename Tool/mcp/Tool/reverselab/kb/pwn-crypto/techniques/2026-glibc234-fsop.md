# 2026 战例：glibc ≥2.34 移除 `__free_hook` 后的 FSOP / exit_funcs

> 战例 KB-PWN-2026-02 · 收录 2026-10-20 · 单篇 ≤200 行 · 只写偏移口径与判据，不复述教程。

## 来源与日期

- glibc 2.34 release notes：`__free_hook` / `__malloc_hook` 符号移除（2021-08），2026 年主流发行版
  已全部越过该版本；2.35 起 IO vtable 校验、2.37+ 的 `_IO_wfile_overflow` 路径变化是后续补丁面。
- 2026 年 CTF/实战题面统计（公开 writeup 汇总，2026-06）：house of apple 2/3 与 `__exit_funcs`
  仍是“无 hook 时代”两条主线。
- 本页为版本差异 + 判据蒸馏，未附本机 exploit 证据；偏移必须用目标 `libc.so.6` 现算。

## 场景

入口信号：

- `checksec` 显示 Full RELRO + Canary + NX，但仍有 UAF/重叠堆块或任意写（一次 8 字节即可）。
- `nm -D libc.so.6 | grep __free_hook` 为空，`__malloc_hook` 也为空 → 旧打法直接作废。
- 有 `exit()`/`return from main`/`__libc_start_call_main` 可达路径，或能触发 `_IO_flush_all_lockp`。
- 能泄漏 libc 基址（unsorted bin、`environ`、格式化串）与至少一个堆地址（safe-linking 解码用）。

两条主线怎么选：

| 条件 | 主线 | 需要的能力 |
| :-- | :-- | :-- |
| 可写 `_IO_list_all` 且能伪造 `_IO_FILE` + `_wide_data` | FSOP（house of apple 2/3） | 2 次任意写 + 堆地址 |
| 可写 libc 内 `__exit_funcs` 且能泄漏 pointer guard | `exit_funcs`（`ef_cxa`） | 任意写 + `%p`/读泄露 |
| 只有一次写、目标为程序自身函数指针 | 直接改 `.fini_array`/回调 | 无 |

## 命令

```bash
# 0) 版本与符号面（先证明 hook 真的没了）
./libc.so.6 | head -1
strings -a libc.so.6 | grep -m1 'GNU C Library'
nm -D libc.so.6 | grep -E '__free_hook|__malloc_hook|_IO_list_all|__exit_funcs'
readelf -sW libc.so.6 | grep -E '_IO_wfile_jumps|_IO_str_jumps|__libc_IO_vtables'

# 1) vtable 合法区间（2.35+ 校验用）
readelf -SW libc.so.6 | grep -i __libc_IO_vtables
gdb -q -batch ./chall -ex 'p &__libc_IO_vtables' -ex 'p &_IO_wfile_jumps' \
    -ex 'p &_IO_list_all' -ex 'p &__exit_funcs'

# 2) 运行时对照：hook 地址是否可写
gdb -q -batch ./chall -ex 'start' -ex 'x/gx &__free_hook' -ex 'info proc mappings'

# 3) 复算脚本（仓库已有）
python Tool/scripts/pwn-check.py --file ./chall --json
python Tool/skill/pwn-crypto/scripts/pwn-repro.py --objdump d.txt --func vuln --probe-log p.txt
```

## 判据表

| 字段 | 观测 | 成立阈值 | 证据 |
| :-- | :-- | :-- | :-- |
| `libc_version` | `2.34` / `2.35` / `2.37+`（build id 与 sha256） | 与目标运行库一致；`__free_hook` 符号不存在 | `checksec.json`、`libc.sha256` |
| `io_file_vtable` | 伪造 `_IO_FILE._vtable` 的值 | 落在 `[__libc_IO_vtables, +size)` 内，且等于 `_IO_wfile_jumps` 或 `_IO_str_jumps` 的实际地址 | gdb `x/gx file+0xd8` |
| `vtable_offset` | `_wide_data` / `_mode` / `_IO_write_ptr` 偏移 | 与当前 libc 头文件/`pahole` 输出一致；跨小版本必须重算 | `pahole -C _IO_FILE libc.so.6` |
| `io_chain_reach` | `_IO_list_all` → 伪造 FILE 的链 | 触发 flush 时 RIP 命中目标函数（marker/`system`），非 SIGSEGV | `pwn-repro` 日志 |
| `exit_funcs_slot` | `__exit_funcs` 内 `ef_cxa` 指针 | 已按 `PTR_MANGLE` 还原/重编码，`xor` 值来自同一进程 | 两次运行泄露值一致 |
| `guard_leak` | pointer guard（`fs:0x30`）是否已知 | `demangle(encoded)==target` 回代成立 | gdb `p/x $fs_base` |
| `stability` | 全新进程触发次数 | ≥10 次中 ≥9 次拿到 shell/marker | 运行计数表 |

## 失败判据

- `nm` 仍能看到 `__free_hook`，却按 2.34+ 写 FSOP → 版本假设错，回到版本确认。
- `_vtable` 落在 `__libc_IO_vtables` 之外 → 2.35+ 校验直接 abort（`_IO_vtable_check`），不是“偏移错”。
- flush 链走到 `_IO_wfile_overflow` 但 `_wide_data->_wide_vtable` 未伪造 → 空指针崩，补 `_wide_vtable`。
- `__exit_funcs` 写入后进程静默退出、无 RIP 命中 → `ef_cxa` 未过 mangling，或 `initial` 结构已被静态初始化覆盖。
- 只有 SIGSEGV、没有可控 RIP/参数 → 不写“利用成功”，按“控制流未接管”降级。
- 依赖 `__free_hook` 的旧 payload 直接复用到 2.34+ → 判否，不调偏移硬凑。
- 目标 libc 与本地不一致（build id 不同）→ 所有偏移不可信，先取同版本库。

> 边界：只在授权实验室/CTF 二进制上验证；不提供武器化封装；`system` 参数需可写且 NUL 结尾；
> 2.39+ 若出现新的 IO 校验补丁，本页阈值需重测后更新。

## 与 reference 的关系

- 打法矩阵：[heap-and-sandbox.md](../../../../../../../Tool/skill/pwn-crypto/references/heap-and-sandbox.md)（本页是其 2.34+ 分支的战例化）。
- 保护位与版本口径：[mitigation-matrix.md](../../../../../../../Tool/skill/pwn-crypto/references/mitigation-matrix.md)。
- 失败判据：[02-failure-criteria.md](../../../../../../../Tool/skill/pwn-crypto/references/02-failure-criteria.md)。
- 同 board 邻近篇：[02-heap-and-sandbox.md](02-heap-and-sandbox.md)（tcache/safe-linking 前置）、
  [04-libc-version-and-orw.md](04-libc-version-and-orw.md)（build id 与泄漏校验）、
  [06-failure-criteria-playbook.md](06-failure-criteria-playbook.md)（停机规则）。
