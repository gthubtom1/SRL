/*
 * antidebug_demo.c —— 反调试特征样本（本仓库原创，GPL-3.0）
 * 用途：给 seep_packer_detect 提供"含反调试导入"的 PE 样本，验证其能识别。
 * 编译：gcc -O2 -o antidebug_demo.exe antidebug_demo.c
 *
 * 说明：故意调用多个反调试相关 API（IsDebuggerPresent / CheckRemoteDebuggerPresent /
 * QueryPerformanceCounter 等），让导入表带上这些符号，供静态判壳/反调试检测命中。
 * 这不是恶意程序，只是教学用的"反调试特征演示"。
 */
#include <windows.h>
#include <stdio.h>

int main(void) {
    /* 1) 经典 IsDebuggerPresent */
    if (IsDebuggerPresent()) {
        printf("debugger detected (IsDebuggerPresent)\n");
        return 1;
    }
    /* 2) 远程调试器检测 */
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    if (remote) {
        printf("remote debugger detected\n");
        return 1;
    }
    /* 3) 时序检测（QueryPerformanceCounter 差值） */
    LARGE_INTEGER a, b, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&a);
    for (volatile int i = 0; i < 100000; i++) {}
    QueryPerformanceCounter(&b);
    double elapsed = (double)(b.QuadPart - a.QuadPart) / (double)freq.QuadPart;
    if (elapsed > 5.0) {
        printf("timing anomaly detected\n");
        return 1;
    }
    /* 4) 输出调试字符串（也是反调试相关导入） */
    OutputDebugStringA("antidebug_demo running\n");

    printf("no debugger, running normally\n");
    return 0;
}
