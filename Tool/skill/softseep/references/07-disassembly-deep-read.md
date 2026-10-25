# 反汇编深读：x64 / ARM64 调用约定、栈帧与编译器模式

> 范围：PE/ELF/Mach-O 的静态反汇编、动态断点、函数签名还原、补丁点确认。
> 路由：纯 Java 字节码、.NET IL、脚本语言先反编译到高级语言，再回到本卷。
> 目标：看到一段反汇编，能回答「参数在哪、返回值在哪、栈帧多大、这是哪种编译器的惯用法、有没有安全 cookie/异常表/vtable」。
> 所有偏移都是示例；实际以目标 SHA256 对应的反汇编为准。

---

## 1. x64 调用约定（Win64 vs SysV）

### 1.1 Windows x64（Microsoft x64）

| 项 | 规则 |
| :--- | :--- |
| 整数/指针参数 | `RCX`, `RDX`, `R8`, `R9`，第 5 个起 `[rsp+0x28]`, `[rsp+0x30]`... |
| 浮点参数 | `XMM0–XMM3`，第 5 个起栈上 |
| 返回值 | 整数/指针 `RAX`；浮点 `XMM0`；大结构体由调用方传隐藏指针（通常在 `RCX`，实际参数后移） |
| home space（影子空间） | **调用方**在 `[rsp+0x00..0x1F]` 预留 32 字节（4×8），供被调用者 spill `RCX/RDX/R8/R9`；被调用者第一条指令执行前就已存在 |
| 栈对齐 | 调用前 `RSP % 16 == 0`；`call` 压入 8 字节返回地址后，被调用者入口 `RSP % 16 == 8` |
| 非易失寄存器 | `RBX`, `RBP`, `RDI`, `RSI`, `RSP`, `R12–R15`；`RAX/RCX/RDX/R8–R11` 易失 |
| 方向标志 | 调用前 `DF=0`；`std` 后必须 `cld` |

**典型入口：**

```asm
sub rsp, 0x28          ; 0x20（给被调用者的 home）+ 0x8 对齐垫片
mov [rsp+0x20], rcx    ; ✗ 不是 home：落在 8 字节垫片里；本函数 home 第 1 槽在 [rsp+0x30]
...
add rsp, 0x28
ret
```

| 区域（入口 `rsp = E`，`[E]` 为 `call` 压入的返回地址） | 入口 | `sub rsp,0x28` 后 |
| :--- | :--- | :--- |
| home space（调用方预留 32 字节） | `[E+0x08..0x27]` | `[rsp+0x30..0x4F]` |
| 本函数给被调用者的 home / 对齐垫片 | — | `[rsp+0x00..0x1F]` / `[rsp+0x20..0x27]` |

**读参数的正确姿势**：不要一上来读 `[rsp+8]`（那是返回地址）。先看入口是否把寄存器 spill 到 home：若 spill，按第 i 槽（i=1..4 为 RCX/RDX/R8/R9）入口 `[E+8*i]`、`sub rsp,N` 后 `[rsp+N+8*i]` 读（`N=0x28` → `0x30/0x38/0x40/0x48`）；`[rsp+0x20]` 只是 8 字节垫片，不是第 4 槽。若见到「入口 `[rsp+0x00..0x1F]`、`sub 0x28` 后 `[rsp+0x28..0x47]`」的写法，那是把入口 `rsp` 当 home 起点的简化记法，少算了返回地址那 8 字节，两套记法不要混用。

### 1.2 System V AMD64（Linux/macOS）

| 项 | 规则 |
| :--- | :--- |
| 整数/指针参数 | `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`；第 7 个起栈上 |
| 浮点参数 | `XMM0–XMM7` |
| 返回值 | `RAX`/`RDX`（128 位）；浮点 `XMM0/XMM1` |
| 栈对齐 | 调用前 `RSP % 16 == 0`；入口 `RSP % 16 == 8` |
| 红区 | 叶子函数可用 `[rsp-128, rsp)`，信号处理会破坏 |
| 非易失 | `RBX`, `RBP`, `R12–R15` |

**判别技巧**：函数入口用 `RDI/RSI` 取参 → SysV；用 `RCX/RDX` → Win64。导入表/PE 头可先判平台，但跨平台样本（Wine、MinGW）仍要看代码。

---

## 2. ARM64（AAPCS64）

| 项 | 规则 |
| :--- | :--- |
| 整数/指针参数 | `X0–X7`；第 9 个起栈上 |
| 浮点参数 | `V0–V7`（`S/D/Q` 视图） |
| 返回值 | `X0`（大结构体用 `X8` 间接结果指针） |
| 返回地址 | `X30`（LR）；`BL` 写入 LR，`BLR` 间接调用，`RET` 默认跳 `X30` |
| 帧指针 | `X29`（FP）；`X19–X28` 非易失 |
| 栈对齐 | `SP` 必须 16 字节对齐 |
| 帧记录 | `STP X29, X30, [SP, #-N]!` 建帧；`LDP X29, X30, [SP], #N` 恢复 |
| 叶子函数 | 可能不建帧、不保存 LR；此时 `X30` 直接被 `RET` 使用 |
| PAC/BTI | `PACIASP`/`AUTIASP` 签名 LR；`BTI c` 限制间接跳转落点 |

**典型入口：**

```asm
stp x29, x30, [sp, #-0x20]!   ; 保存 FP/LR，分配 0x20
mov x29, sp
str x0, [sp, #0x10]          ; 保存第 1 参数
...
ldp x29, x30, [sp], #0x20
ret
```

**读参数**：`X0–X7` 是前 8 个；不要套 x64 的 `RCX/RDX`。第 9 个（及之后）由**调用方**压在自己栈顶，入口时在 `[sp]` 起；一旦 `STP X29,X30,[SP,#-N]!` 把 `SP` 减了 `N`，它就变成 `[sp+N]`，之后再 `SUB SP,SP,#M` 则是 `[sp+N+M]`。

算例：`stp x29,x30,[sp,#-0x20]!` → 第 9 个参数在 `[sp+0x20]`（`mov x29,sp` 后也就是 `[x29+0x20]`）；若帧是 `[sp,#-0x30]!` 且又 `stp x19,x20,[sp,#0x10]`，第 9 个仍在 `[sp+0x30]`，`[sp,#0x10]` 存的是 `x19`，不是入参。返回值在 `X0`，不是 `X30`。

---

## 3. 栈帧识别

### 3.1 x64 帧指针

```asm
push rbp
mov rbp, rsp
sub rsp, 0x60
...
mov rsp, rbp
pop rbp
ret
```

- `push rbp` 后 `RSP` 少 8；`mov rbp,rsp` 把帧基址固定。
- 局部变量常用 `[rbp-0x10]`、`[rbp-0x28]`；参数（若 spill）在 `[rbp+0x10]` 起。
- 优化构建可能省略帧指针（`/Oy`、`-fomit-frame-pointer`），此时只能按 `RSP` 相对偏移和调用点推断。

### 3.2 x64 无帧指针

```asm
sub rsp, 0x48
mov [rsp+0x20], rcx
...
add rsp, 0x48
ret
```

- 需要跟踪 `RSP` 的每一次 `push/pop/sub/add`；函数中间可能有动态 `alloca`。
- 局部变量偏移在函数生命周期内可能变化；以每条指令的 `RSP` 为准。

### 3.3 ARM64 帧

```asm
stp x29, x30, [sp, #-0x30]!
mov x29, sp
stp x19, x20, [sp, #0x10]
...
ldp x19, x20, [sp, #0x10]
ldp x29, x30, [sp], #0x30
ret
```

- `STP` 的 pre-index `!` 表示先减 `SP` 再存；`LDP` 的 post-index 表示先读再加 `SP`。
- 看到 `STP X29,X30` 就按「标准帧」读；看到只有 `SUB SP` 没有 `STP`，可能是叶子函数或手写汇编。
- `X30` 被覆盖前通常已保存；若没有保存，函数必须是叶子或已 `PACIASP`。

### 3.4 栈帧速查表

| 现象 | x64 | ARM64 |
| :--- | :--- | :--- |
| 标准帧建立 | `push rbp; mov rbp,rsp` | `stp x29,x30,[sp,#-N]!; mov x29,sp` |
| 标准帧恢复 | `mov rsp,rbp; pop rbp` | `ldp x29,x30,[sp],#N` |
| 返回地址 | `[rsp]`（入口）/ `[rbp+8]` | `X30`（可能已存栈） |
| 第 1 参数 | `RCX` / `[rbp+0x10]` | `X0` |
| 第 5/9 参数 | `[rsp+0x28]` 起 | `[sp+N]` 起（`N` = 建帧前置减量） |
| 大结构体返回 | 隐藏指针在 `RCX` | 隐藏指针在 `X8` |

---

## 4. 常见编译器模式

### 4.1 switch 跳表

**MSVC / Clang / GCC 共同形态：**

```asm
cmp eax, 7
ja  default
lea rdx, [rip+table]
movsxd rax, dword ptr [rdx+rax*4]
add rax, rdx
jmp rax
```

- 表项是 **相对表基址的 32 位偏移**（不是绝对地址），所以 `add rax, rdx` 后才 `jmp rax`。
- 边界检查 `cmp/ja` 不能少；`default` 常紧跟在跳转后。
- 稀疏 case 可能变成「二分比较树」或「两次跳表」；不要只找 `jmp rax`。

**ARM64：**

```asm
cmp w0, #7
b.hi default
adrp x1, table
add x1, x1, :lo12:table
ldrb w2, [x1, w0]
adr x3, base
add x3, x3, w2, lsl #2
br x3
```

- 常见 `ldrb` + `adr` + `br`；也可能是 `ldrsw` + `add` + `br`。
- 注意 `adrp/add` 的页基址与 `:lo12:` 重定位。

### 4.2 strlen / memcpy 内联

**MSVC 常见：**

```asm
or rax, -1
loc_loop:
inc rax
cmp byte ptr [rcx+rax], 0
jne loc_loop
```

或 SIMD 版本（`pcmpeqb` + `pmovmskb` + `bsf`）。`strlen` 内联后没有 `call`，不能用「导入表没有 strlen」判断「没调用 strlen」。

**GCC/Clang 常见：**

```asm
pxor xmm0, xmm0
movdqu xmm1, [rdi]
pcmpeqb xmm1, xmm0
pmovmskb eax, xmm1
test eax, eax
jnz found
```

- 识别「16 字节块 + 零比较 + 位扫描」；尾部可能回到逐字节。
- 逆向时把它命名为 `inline_strlen`，不要误判为加密循环。

### 4.3 `__security_check_cookie` / stack protector

**MSVC：**

```asm
mov rax, qword ptr [rip+__security_cookie]
xor rax, rsp
mov [rsp+0x40], rax
...
mov rcx, [rsp+0x40]
xor rcx, rsp
call __security_check_cookie
```

- 函数尾调用 `__security_check_cookie`，失败走 `__report_gsfailure`。
- cookie 与 `RSP` 异或，说明栈上保存的是编码后的值；不要把它当普通局部变量。

**GCC/Clang：**

```asm
mov rax, qword ptr fs:[0x28]
mov [rsp+0x18], rax
...
mov rax, [rsp+0x18]
sub rax, qword ptr fs:[0x28]
jne __stack_chk_fail
```

- Linux/glibc 用 `fs:0x28`（TLS canary）；macOS 用 `__stack_chk_guard`。
- 看到 `fs:[0x28]` 就知有 stack protector；patch 栈变量时不要破坏 canary。

### 4.4 SEH / `__try` / 异常表

**x64 Windows 不再用栈链 SEH**，而是 `.pdata` 里的 `RUNTIME_FUNCTION` + `UNWIND_INFO`：

```text
.pdata:  BeginAddress | EndAddress | UnwindInfoAddress
UNWIND_INFO: Version/Flags | SizeOfProlog | CountOfCodes | FrameRegister/Offset
```

- `__try/__except` 的函数通常有 `.pdata` 条目和异常处理器；`except` 块可能被放在函数尾部。
- 识别 `RtlLookupFunctionEntry`/`RtlVirtualUnwind` 或 `__C_specific_handler` 引用。
- x86 才有 `FS:[0]` 异常链（`EXCEPTION_REGISTRATION_RECORD`）；不要套到 x64。

**ARM64 Windows：** `.pdata` 使用 `RUNTIME_FUNCTION` + `UNWIND_INFO`，但 unwind code 是 ARM64 专用；`__try` 同样走表驱动。

### 4.5 虚表布局与 RTTI

**MSVC 对象布局（单继承）：**

```text
obj+0x00 -> vftable pointer
obj+0x08 -> 第一个数据成员
vftable[-1] -> RTTI Complete Object Locator（COL）
vftable[0]  -> 第一个虚函数
```

- `vftable[-1]` 指向 `RTTICompleteObjectLocator`，其中含 `TypeDescriptor` 指针；`TypeDescriptor` 名字形如 `.?AVFoo@@`。
- 多继承有多个 vftable 指针（每个基类一个），`this` 调整用 `thunk`（`sub rcx, offset; jmp real`）。

**Itanium ABI（GCC/Clang，Linux/macOS）：**

```text
obj+0x00 -> vptr
vptr[-2] -> offset-to-top
vptr[-1] -> typeinfo pointer
vptr[0]  -> 第一个虚函数
```

- `typeinfo` 名字是 mangled name（`_ZTV...`/`_ZTI...`）；`dynamic_cast` 用 `__dynamic_cast`。
- 识别 `vtable for` 符号（未剥离时）或 `_ZTV` 前缀。

**RTTI 恢复步骤：**

1. 找构造函数：写入 `vftable` 指针的位置。
2. 找 `vftable`：`.rdata` 中连续函数指针，前一项指向 COL/typeinfo。
3. 用交叉引用找虚调用：`mov rax,[rcx]; call [rax+offset]`。
4. 用 `dumpbin /headers` / `llvm-pdbutil` / `nm -C` 恢复符号；没有符号时按调用图命名。

### 4.6 异常表与函数边界

- PE x64：`.pdata` 的 `RUNTIME_FUNCTION` 数组给出每个函数的 `[Begin, End)`；用它切函数比 `ret` 扫描可靠。
- ELF：`.eh_frame`/`.eh_frame_hdr`；`readelf --debug-dump=frames` 可看 CFI。
- Mach-O：`__TEXT,__unwind_info` + `__eh_frame`；`dwarfdump --eh-frame` 可读。
- 有异常表的二进制，函数边界通常完整；剥离后仍可用 `.pdata` 恢复。

---

## 5. 编译器陷阱（吸收原 compiler-pitfalls.md 的五条）

### 陷阱 1：编译器吞掉 `\r` 与 `\x000D`

**现象**：宽字符串 `L"...\r\n..."` 或 `L"...\x000D\x000A..."` 经 `zig-clang` 编译后，二进制里只剩 `0A 00`，`0D` 消失，UI 挤成一行。

**验证：**

```python
data = open("version.dll", "rb").read()
i = data.find("A\x00n\x00g\x00u\x00s\x00".encode("latin1"))
print(" ".join("%02X" % b for b in data[i+20:i+30]))
# 期望 62 00 0D 00 0A 00（'b' + CR + LF）；若为 62 00 0A 00 则 CR 已被吞
```

**双保险：** 字面量用通用字符名 `\u000D\u000A`；再加运行时 `NormalizeCrlf()`，抢在真实 API 前修正。

```c
static int NormalizeCrlf(const WCHAR* src, WCHAR* dst, int dstCap) {
    int o = 0;
    for (const WCHAR* p = src; *p; ++p) {
        if (*p == L'\r' || *p == L'\n') {
            if (o + 2 >= dstCap) break;
            dst[o++] = L'\r'; dst[o++] = L'\n';
            if (*p == L'\r' && p[1] == L'\n') ++p;
        } else {
            if (o + 1 >= dstCap) break;
            dst[o++] = *p;
        }
    }
    dst[o] = 0;
    return o;
}
```

**铁律**：平台敏感字节契约（CRLF/LF、BOM、结构体对齐、字节序）永不信任编译器字面量，必须运行时兜底 + 二进制级验证。

### 陷阱 2：`vfprintf("%ls")` 遇非 ASCII 静默截断

**现象**：默认 C locale 下 `fprintf(fp, "orig='%ls'\n", wstr)` 碰到第一个汉字就截断并吃掉整行，日志看起来像「代码没执行」。

**规避**：日志中非 ASCII 一律转 UTF-16 码点十六进制：

```c
char hexDump[1024] = {0}; int pos = 0;
for (int i = 0; i < 60 && s[i] && pos < 900; ++i)
    pos += sprintf(hexDump + pos, "%04X ", (unsigned int)s[i]);
LogToFile("[HOOK] -> REWRITE (%d chars) BYTES: %s\n", n, hexDump);
```

### 陷阱 3：Hook 未命中分支无日志

**现象**：控件类名白名单不匹配（静态推测 `Static`，实测 `Edit`），挂钩静默不生效；日志只显示「被调用」却无「已重写」。

**铁律**：每个 `if` 分支都留日志，包括 `else`；至少记录「入参、命中/未命中、跳过原因」。

### 陷阱 4：DLL 被运行中进程占用无法替换

**现象/规避**：`Device or resource busy` / 复制失败；先 `Stop-Process -Name <target> -Force` 等句柄释放，再复制或重命名。

### 陷阱 5：权限不足写入 Program Files

**现象/规避**：`Permission denied`；在沙盒目录内完成全部验证，最终由用户提权落地，不要为了省事改 ACL。

### 附加：中文 `.bat` 必须是 GBK；GUI 子进程要脱离控制台

- `cmd.exe` 按当前代码页（中文系统 936/GBK）解码 `.bat`；UTF-8 保存会满屏「不是内部或外部命令」。铁律：中文 `.bat` 用 GBK(cp936) 无 BOM，关键命令行只写 ASCII；能用 `.ps1`（UTF-8 with BOM）或 `.py` 就不要 `.bat`。
- `CreateProcess` 默认继承控制台；控制台关闭会发 `CTRL_CLOSE_EVENT`，连带杀死 GUI 子进程。加 `CREATE_DETACHED_PROCESS (0x00000008)`。

---

## 6. 反汇编阅读顺序（建议）

1. **平台/位数/调用约定**：PE/ELF/Mach-O、x64/ARM64、Win64/SysV/AAPCS64。
2. **函数边界**：`.pdata`/`.eh_frame`/符号表；没有就按 `ret` + 栈平衡扫描。
3. **栈帧**：`push rbp/mov rbp,rsp` 或 `stp x29,x30`；算局部变量区。
4. **参数/返回值**：按调用约定读寄存器/栈；注意隐藏结构体指针。
5. **安全机制**：security cookie、stack canary、CFG/BTI、SEH/异常表。
6. **惯用法**：switch 跳表、内联 strlen/memcpy、虚表/RTTI、thunk。
7. **命名与注释**：按「输入来源、返回值用途、调用者」命名；不要用 `sub_1400xxxx` 交差。

---

## 7. 失败判据

| 现象 | 判定 | 改走哪条 |
| :--- | :--- | :--- |
| 参数读出来全是垃圾 | 调用约定/栈帧判断错 | 回到第 1/3 节，先确认 Win64/SysV/AAPCS64 与帧指针 |
| 函数边界切得乱七八糟 | 用了 `ret` 扫描但函数有尾部跳转/异常表 | 改用 `.pdata`/`.eh_frame`/符号表切分 |
| 把内联 strlen 当加密循环 | 没识别 SIMD 零比较模式 | 看 `pcmpeqb/pmovmskb` 或逐字节零比较，命名为 `inline_strlen` |
| patch 栈变量后崩溃 | 破坏了 security cookie/canary | 避开 cookie 槽位，或同步更新编码值 |
| 在 x64 上找 `FS:[0]` 异常链 | 套用了 x86 SEH | x64 用 `.pdata`/`UNWIND_INFO`；x86 才有栈链 |
| 把 `[rcx]` 当 vtable | 可能是 d-pointer/首字段 | 看构造函数、`.rdata`、RTTI/typeinfo 再下结论 |
| ARM64 上 `RET` 跳飞 | `X30` 被覆盖或 PAC 未验证 | 检查 `STP X29,X30`、`PACIASP/AUTIASP`、`BTI` |

---

## 8. 边界

- 本卷讲「怎么读」，不讲「怎么利用」；补丁与注入分别见 `09-patch-engineering.md` 与 `05-windows-sop.md`。
- 编译器模式是概率判断，不是定律；不同版本/优化级别会变形，必须用目标实测复核。
- 反汇编结论必须与动态行为/字符串/导入表交叉；单靠静态模式容易误判。

