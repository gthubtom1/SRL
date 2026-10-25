# 补丁工程：等长、重定位、代码洞、校验与回滚

> 范围：文件级字节补丁、内存补丁、代理 DLL、IAT/inline hook、跨版本迁移。
> 路由：纯配置/许可文件写入属于数据面（见 `license-validation.md`）；VM 内部字节码补丁先脱壳。
> 目标：让补丁**可验证、可回滚、可迁移**，而不是「我这台机器能跑」。
> 铁律：**先有补丁清单，再有补丁字节；先有回滚，再有交付。**

---

## 1. 等长约束

文件级补丁最常见的事故是「新指令比原指令长」，覆盖了后续指令的一半。

| 原指令 | 长度 | 可用替代 | 长度 | 说明 |
| :--- | ---: | :--- | ---: | :--- |
| `mov al, imm8; ret` | 3 | `b0 01 c3` | 3 | 零栈破坏，适合虚函数/标量返回 |
| `mov eax, imm32; ret` | 6 | `b8 01 00 00 00 c3` | 6 | 清空 RAX 高位 |
| `mov eax, imm32` | 5 | `b8 7f e6 85 f4` | 5 | 返回 2099-12-31 时间戳（`0xf485e67f`） |
| `test eax,eax` | 2 | `33 c0` (`xor eax,eax`) | 2 | 恒零/恒真按上下文 |
| `je rel8` | 2 | `eb rel8` (`jmp short`) | 2 | 条件跳转改无条件 |
| `jne rel32` | 6 | `e9 rel32` + `90` | 6 | 长跳转；位移需重算 |
| `cmp [ebp-x],0; je` | 6+2 | `c7 45 fc 01 00 00 00 90 90 90` | 10 | 改内存值，比改跳转语义更稳（需有 10 字节槽） |
| `mov [rsp+8],rcx` | 5 | `b0 01 c3 90 90` | 5 | 入口即返回；仅适合确认无栈帧分配的函数 |
| `ret` | 1 | `c3` | 1 | 高危：跳过初始化，常延迟崩溃 |

**判据**：补丁前后指令槽长度相等；反汇编器从补丁点继续解码不越界；目标行为变化。

---

## 2. 相对跳转/调用的编码

### 2.1 `jmp rel32`（E9）

```text
E9 disp32
disp32 = target - (patch_addr + 5)
范围：target ∈ [patch_addr - 2GB, patch_addr + 2GB]
```

### 2.2 `call rel32`（E8）

```text
E8 disp32
disp32 = target - (patch_addr + 5)
```

### 2.3 `jmp/call [rip+disp32]`（FF 25 / FF 15）

```text
FF 25 disp32
disp32 = target_ptr - (patch_addr + 6)
```

- RIP 相对**下一条指令**（`patch_addr + 6`），不是当前指令。
- 适合跳 IAT 槽/函数指针表；不需要 ±2GB 内直接到函数体。

### 2.4 绝对跳转（x64）

```asm
mov rax, 0x00007FF6A1234567   ; 48 B8 imm64 (10 字节)
jmp rax                        ; FF E0 (2 字节)
```

- 12 字节，适合远距离/代码洞跳板；会破坏 `RAX`。
- 需要保留 `RAX` 时：`push rax; mov rax,imm64; xchg rax,[rsp]; ret`（更复杂，慎用）。

### 2.5 ARM64

```asm
ldr x16, #8        ; 58000050
br  x16            ; D61F0200
.quad target       ; 8 字节地址
```

或 `adrp x16, target; add x16, x16, :lo12:target; br x16`（页内）。远跳用 literal load；注意 BTI landing pad。

---

## 3. 代码洞（code cave）

### 3.1 找洞

- PE：节尾填充（`00`/`CC`）、`.text` 末尾、新增节（会改节表/大小）、`.rsrc` 之后 overlay。
- 判据：洞内字节全为 `00`/`CC`，且不在函数边界内；洞大小 ≥ trampoline 需求。
- ELF/Mach-O：段尾 padding、`__TEXT,__text` 之后的 alignment 空洞；新增段成本更高。

### 3.2 trampoline 结构

```asm
; 原入口前 5 字节被覆盖为 jmp cave
cave:
    pushfq
    push rax
    push rcx
    push rdx
    ; ... 保存需要用的 volatile 寄存器
    mov rax, <hook_fn>
    call rax
    ; ... 恢复
    pop rdx
    pop rcx
    pop rax
    popfq
    ; 执行被覆盖的原指令（从备份复制）
    <original bytes>
    jmp <patch_addr + 5>
```

**关键点：**

- 保存/恢复 `volatile` 寄存器与标志位；`RBX/RBP/RDI/RSI/R12–R15` 由被调用者保存，但你的 hook 仍要遵守 ABI。
- 栈对齐：`call` 前 `RSP % 16 == 0`；多 push 一个 8 字节会破坏对齐，必要时 `sub rsp,8`。
- 被覆盖指令必须是完整指令；不能从指令中间切开。
- 跳回地址 = 被覆盖字节之后的第一条指令。

### 3.3 代码洞的失败判据

| 现象 | 判定 | 处理 |
| :--- | :--- | :--- |
| 跳过去就崩 | 栈对齐/寄存器/标志位被破坏 | 加 `pushfq/popfq` 与完整保存 |
| 跳回后行为异常 | 被覆盖指令没执行/执行了两次 | 备份原字节，确认只执行一次 |
| 目标启动即崩 | 代码洞落在未映射/只读页 | 改内存属性或换洞 |
| CFG 拦截 | 间接跳转目标不是合法 landing pad | 用 `SetProcessValidCallTargets` 或改直接跳转 |

---

## 4. 重定位与 ASLR/基址

| 概念 | 说明 | 补丁影响 |
| :--- | :--- | :--- |
| ImageBase | PE 首选基址 | 文件补丁用 RVA；不要写 VA |
| ASLR (`DYNAMIC_BASE`) | 每次加载基址随机 | 内存补丁必须 `base + RVA` |
| 重定位表 | `.reloc` 记录需要修正的绝对地址 | 改代码/数据时可能要新增/修改重定位项 |
| Reloc 剥离 | 优化构建可能去掉 `.reloc` | 不能假设可重定位；改绝对地址会崩 |
| 节对齐 | `SectionAlignment`/`FileAlignment` | 新增节要同时改节表/大小/校验和 |

**判据**：`dumpbin /headers` 看 `DllCharacteristics` 的 `DYNAMIC_BASE (0x40)`；内存补丁日志记录模块基址；同一补丁在两次启动后都能命中。

**跨版本迁移**：不要复用文件偏移；用 AOB/拓扑跨距重新定位，算出 `RVA = FileOffset + SectionDelta`，再验证目标版本 SHA256。

---

## 5. IAT hook vs inline hook

| 维度 | IAT hook | Inline hook |
| :--- | :--- | :--- |
| 改动位置 | 导入地址表槽位 | 函数入口指令 |
| 影响范围 | 只影响走 IAT 的调用 | 所有调用（含直接 call/内部调用） |
| 实现难度 | 低（改指针） | 中（需 trampoline/长度/重定位） |
| 检测难度 | 低（IAT 快照可比对） | 中（函数头字节/页属性可比对） |
| 适用 | 输出 API、网络 API、显示层 | 内部函数、虚函数、被直接调用的校验函数 |
| 风险 | 动态取址/延迟导入会绕过 | 多线程/热补丁/CFG/代码完整性 |

**IAT hook 代码骨架：**

```c
static bool PatchIatByName(uintptr_t base, const char* dll, const char* fn,
                           void* newFn, void** oldFn) {
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return false;
    for (PIMAGE_IMPORT_DESCRIPTOR d = (PIMAGE_IMPORT_DESCRIPTOR)(base + dir.VirtualAddress);
         d->Name; ++d) {
        if (_stricmp((const char*)(base + d->Name), dll) != 0) continue;
        PIMAGE_THUNK_DATA oft = d->OriginalFirstThunk
            ? (PIMAGE_THUNK_DATA)(base + d->OriginalFirstThunk) : NULL;
        PIMAGE_THUNK_DATA ft = (PIMAGE_THUNK_DATA)(base + d->FirstThunk);
        for (int i = 0; ft[i].u1.Function; ++i) {
            const char* name = NULL;
            if (oft && !IMAGE_SNAP_BY_ORDINAL(oft[i].u1.Ordinal))
                name = (const char*)((PIMAGE_IMPORT_BY_NAME)(base + oft[i].u1.AddressOfData))->Name;
            bool hit = (name && strcmp(name, fn) == 0);
            if (!hit && !name && oldFn && *oldFn && (void*)ft[i].u1.Function == *oldFn) hit = true;
            if (!hit) continue;
            void** slot = (void**)&ft[i].u1.Function;
            if (oldFn && !*oldFn) *oldFn = *slot;
            DWORD op = 0;
            if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &op)) return false;
            *slot = newFn;
            VirtualProtect(slot, sizeof(void*), op, &op);
            return true;
        }
    }
    return false;
}
```

**铁律：**

- `oldFn` 必须在挂钩前取真实地址；否则 hook 递归调用自身。
- 取真实地址优先 `GetProcAddress(GetModuleHandleW(L"user32.dll"), ...)`，不要依赖 IAT 原值。
- 未命中分支必须写日志；否则静默失败。

---

## 6. TLS callback / 延迟导入

- **TLS callback** 在 `EntryPoint` 之前执行；壳/反调试/解密 stub 常挂这里。补丁点若在 TLS callback 之后，先确认它已经跑过。
- TLS 目录在 PE 数据目录 9；回调数组以 `NULL` 结尾。用 `dumpbin /headers` 或 PE 解析器定位。
- **延迟导入**（Delay Import）在第一次调用时才解析；IAT hook 需要处理 `IMAGE_DELAYLOAD_DESCRIPTOR`，或在解析后再挂钩。
- 判据：目标函数第一次调用前下断点，看是 IAT 直接命中还是 delayload 解析；不要在解析前改槽位。

---

## 7. 补丁前后校验：checksum / 签名 / 完整性自检

| 检查 | 命令/位置 | 补丁后动作 |
| :--- | :--- | :--- |
| PE Checksum | `dumpbin /headers` 的 `CheckSum`；可选头 +0x40 | 用工具重算；或明确写「未重算，目标不校验」 |
| Authenticode | `signtool verify /pa app.exe` | 保留签名→改内存/代理 DLL；剥离→删证书目录+尾部签名；重签→自签证书 |
| 证书目录 | 数据目录 4（Security）RVA/Size | 剥离时清零 RVA/Size，并截断尾部签名数据 |
| 自带 CRC/SHA | 字符串/导入/断点 | 找自检函数；patch 它或同步更新期望值 |
| 页属性自检 | `VirtualQuery`/`NtQueryVirtualMemory` | 恢复 `PAGE_EXECUTE_READ`；避免长期 RWX |
| 函数头自检 | 比较前 N 字节/哈希 | 用 trampoline 时把原字节保留在别处；或 hook 自检函数 |
| IAT 自检 | 快照槽位地址是否落在系统 DLL | IAT hook 后恢复原槽/或 hook 自检 |

**判据**：补丁后 `signtool verify` 结果、`dumpbin` checksum、自检函数返回值、目标行为，四者至少记录三项。

---

## 8. 回滚与版本化（patch manifest）

### 8.1 manifest 最小字段

```json
{
  "schema": "seep-patch/1",
  "target": "app.exe",
  "version": "28.40.0100",
  "target_sha256": "e2b134e9...",
  "tool_version": "patch-verify/1.0",
  "patches": [
    {
      "id": "P1",
      "offset": 6757553,
      "rva": "0x670CB1",
      "original": "F7D0",
      "new": "31C0",
      "note": "not eax -> xor eax,eax; 授权状态字恒 0"
    }
  ],
  "result_sha256": "...",
  "rollback": {"backup": "app.exe.bak", "verified": true}
}
```

### 8.2 回滚流程

1. 补丁前复制到 `app.exe.bak` 并记录 SHA256；应用补丁后记录 `result_sha256`。
2. 验证失败 → 用 `.bak` 覆盖、复算 SHA256 = 原始值，再跑一次基线行为（不是「文件回了、进程没回」）。

### 8.3 版本化

- 每个目标版本一个 manifest；不要在一个 manifest 里混多个 SHA256。
- 偏移用 `offset`（文件偏移）与 `rva` 双写；跨版本迁移时按 RVA/AOB 重算。
- 补丁 ID 稳定（P1/P2...），便于报告/回归引用。

---

## 9. `patch-verify` 验收流程

```text
1) 读 manifest：target_sha256、patches[]、result_sha256
2) 复算原文件 sha256 == target_sha256（不匹配 → blocked_at=target-hash, rc=2）
3) 逐条检查 offset 在文件范围内、original 字节匹配、new 长度 == original 长度
4) 应用补丁到内存副本，复算 sha256 == result_sha256（不匹配 → blocked_at=result-hash）
5) 可选：写回文件；失败自动用 .bak 回滚
6) 输出 {"ok": true, "patches": N, "sha256_before": ..., "sha256_after": ...}
```

**失败一律：**

```json
{"ok": false, "blocked_at": "offset-range", "reason": "patch P2 offset 0x... 超出文件大小"}
```

并返回 rc=2；不许抛裸栈，不许半写文件。

---

## 10. 补丁选型决策表（吸收原 patching-dictionary.md）

> 授权旁路优先级：**改判比较/跳转 > 改全局标志位 > 改返回值 > 跳过函数体**。

| 优先级 | 改动对象 | 风险 | 适用 |
| :---: | :--- | :--- | :--- |
| 1 | 条件跳转/比较指令 | 最低 | 本地裁决点（`cmp`+`je/jge`） |
| 2 | 全局状态标志位 | 低 | 存在「已授权」全局状态字 |
| 3 | 函数返回值 | 中 | 仅当函数确定返回标量 |
| 4 | 函数体整体 `ret` | 高 | 仅纯阻塞型函数（看门狗），且验证无初始化副作用 |

**禁用场景：** 原函数返回字节集/文本/对象时，强返整数会破坏后续类型转换；应改比较/跳转。

**BSTR 截断/尾调用：** `ff 25 [disp32]`（`jmp qword ptr [SysAllocString]`）可尾调用 IAT，自平衡栈；但要确认参数寄存器与调用约定。

---

## 11. 内核/驱动补丁的额外约束

> 用户态补丁的「等长 + 回滚」在这里不够：签名、PatchGuard、重定位任一环都能把补丁变成蓝屏。

- **签名与 DSE**：改 `.sys` 字节即破坏 Authenticode；DSE（`g_CiOptions`/`ci.dll`）会拒绝加载被改驱动。测试签名需 `bcdedit /set testsigning on` 并重启（桌面水印），只用于实验机；正式驱动走 WHQL/EV。
- **PatchGuard**：周期校验 SSDT/IDT/GDT 与关键 `nt!` 结构，改内核代码或 SSDT hook 常在数分钟后 `0x109 CRITICAL_STRUCTURE_CORRUPTION`；优先 `ObRegisterCallbacks`/`Ps*NotifyRoutine` 等受支持回调。
- **改页属性**：内核代码页只读；用 `MmProtectMdlSystemAddress`（配合 `MmCreateMdl`/`MmMapLockedPagesSpecifyCache`）临时放开写，改完立刻恢复，避免长期 W^X。
- **重定位**：内核映像也有 `.reloc`；写绝对地址必须补 `IMAGE_REL_BASED_DIR64`（type 10）项，否则随机基址下跳飞；取址用 `MmGetSystemRoutineAddress`/`RtlPcToFileHeader`，不硬编码 VA。
- **测试签名链**：`New-SelfSignedCertificate` 造测试证书 → `signtool sign /fd sha256 /a`；证书要进 `Trusted Root`/`Trusted Publishers`，否则 `sc start` 仍失败。
- **蓝屏回滚**：补丁前做 VM 快照 + 备份 `.sys`（记 sha256）；开内核调试（`/debug` + 串口/网络）或至少保留 `MEMORY.DMP`；蓝屏后用 `!analyze -v` 的 `MODULE_NAME`/`IMAGE_NAME` 定位，回滚备份并重启复验加载与签名。

**判据**：`signtool verify /kp /v`、`g_CiOptions`/`testsigning` 状态、补丁后连续运行 ≥30 分钟且重启后仍加载、`!chkimg`/`!analyze` 无告警，四项至少记录三项。

**失败判据**：

- 加载返回 `0xC0000428`（`STATUS_INVALID_IMAGE_HASH`）却先怀疑代码 → 先查签名/DSE。
- 改完数分钟后 `0x109` → 撤内核代码改动，改受支持回调或 ring3 方案。
- 只改 PTE 不恢复、或长期 RWX 内核页 → 视为不稳定补丁，不算交付。
- 无快照/无 dump 就上内核补丁 → 直接不合格；先补回滚路径。
- 只验证「驱动能加载」，不验证 IOCTL/行为与重启后状态 → 只算「加载成功」。

## 12. 失败判据

| 现象 | 判定 | 改走哪条 |
| :--- | :--- | :--- |
| 补丁后立刻崩 | 长度/栈平衡/重定位 | 等长改写；改 trampoline；只改条件跳转 |
| 补丁后延迟崩 | 跳过初始化/守护回写 | 保留原函数体；改判据分支/状态字 |
| `jmp rel32` 跳飞 | disp 按错基址/超 ±2GB | `disp = target-(addr+5)`；远跳用 `mov rax,imm64;jmp rax` |
| `call [rip+x]` 调错 | disp 按当前指令算 | `disp = target-(addr+6)` |
| 签名/校验失败 | 未重算/未剥离/自检 | 重算 checksum；明确签名策略；patch 自检 |
| 回滚后仍异常 | 只回文件没回进程/缓存 | 重启进程；清缓存；复算哈希 |
| 跨版本补丁失效 | 偏移绑定 | AOB/拓扑迁移；核对 SHA256 |

---

## 13. 边界

- 本卷讲工程约束与验证；补丁配方按用户提供的 `scope` 清单与样本版本落地。
- 所有偏移/字节只在记录的目标 SHA256 上成立；换版本必须重跑 `patch-verify`。
- 签名剥离/重签会改变信任状态，交付前必须写明；生产环境优先内存补丁/代理 DLL 保持磁盘哈希。
- ARM64/Mach-O 的补丁还要考虑 PAC/BTI、codesign、hardened runtime；不要直接套 PE 经验。

---

## 附：汇编打桩速查（旧版 `patching-dictionary.md` 回填）

> 这一节是"手边字典"：改一个字节之前先在这里对一遍编码与语义，避免"看起来等长、实际错位"。
> 全部按 x86-64 小端写；ARM64 等价物见 `07-disassembly-deep-read.md`。

### 1. 常用指令编码

| 语义 | 字节 | 长度 | 备注 |
| :--- | :--- | --: | :--- |
| `jmp rel8` | `EB <disp8>` | 2 | 短跳，范围 −128…+127 |
| `jmp rel32` | `E9 <disp32>` | 5 | 相对下一条指令 |
| `je rel8` / `jne rel8` | `74 <d>` / `75 <d>` | 2 | 改判首选目标 |
| `nop` | `90` | 1 | 与 `66 90`（2 字节 nop）配合等长 |
| `xor eax,eax` | `31 C0` | 2 | 返回 0 |
| `mov al,1` | `B0 01` | 2 | 返回 1（函数返回值只占 AL 时） |
| `mov eax,0` | `B8 00 00 00 00` | 5 | 返回 0（5 字节位） |
| `test eax,eax` | `85 C0` | 2 | 与 `jne/je` 配对 |

### 2. 6 字节等长升级：`jge rel32 → jmp rel32`

```text
原:  0F 8D <disp32>      jge  target          （6 字节，条件跳）
改:  E9    <disp32 + 1>  jmp  target+1        （5 字节 + 1 字节 90）
```

为什么是 `disp32 + 1`：`E9` 从**下一条指令**算相对偏移，而原指令是 6 字节、新指令是 5 字节，
若直接照抄 `disp32`，落点会**早 1 字节**——这 1 字节通常正好是目标指令的操作码，表现为
"补丁后目标函数行为诡异/崩溃"，且反汇编看起来"跳转是对的"。补 `90` 填满第 6 字节。

### 3. 改完必须做字节级验证

```python
# 最小验证：偏移、原字节、新字节、整体哈希，四件事一次核完
data = open('version.dll', 'rb').read()
off = 0x1234
assert data[off:off+2] == bytes.fromhex('7413'), data[off:off+2].hex()
patched = data[:off] + bytes.fromhex('EB13') + data[off+2:]
print(len(patched) == len(data))          # 等长
import hashlib
print(hashlib.sha256(patched).hexdigest())
```

判据：**长度不变 + 原字节匹配 + 补丁点反汇编语义符合预期 + 目标行为改变**，四条同时成立；
只满足前两条说明"改到了"，不说明"改对了"。

### 4. 控制台编码（Windows）

- 交付脚本含中文时先 `chcp 65001` + `python -X utf8`；PowerShell 5.1 设 `[Console]::OutputEncoding`。
- 日志出现 `0D 00 0A 00`（UTF-16 CRLF 被当单字节读）→ 先统一写/读编码，再谈「补丁失败」。

### 5. 什么时候不要打补丁

- 目标有签名链完整性校验（Authenticode / 自校验 CRC / 哈希白名单）→ 改字节必然触发，
  改走代理 DLL 或运行期 Hook。
- 目标函数被多个调用点内联（编译器 inline）→ 单点补丁只改到一处，改走导入表/虚表/全局状态。
- 补丁点落在被 `VirtualProtect` 反复改回只读的页 → 先确认是否有守护线程，再决定
  "改页 + 改字节 + 恢复页"还是"外部注入改内存"。

**通过长什么样**：本页给的是方法/边界，没有固定期望输出；执行后按末尾「这一篇算用对了」逐条自检，任何一条不成立就说明这一步没做对。
