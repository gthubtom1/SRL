/*
 * resource_blob.c —— 内嵌资源样本（本仓库原创，GPL-3.0）
 * 用途：给 seep_pe_resources 提供"带自定义资源"的 PE 样本，验证资源枚举/剥离。
 * 编译（Windows + windres/gcc）：
 *   windres resource.rc -O coff -o resource.res
 *   gcc -O2 -o resource_blob.exe resource_blob.c resource.res
 *
 * resource.rc 里嵌一个自定义类型 DATA、ID 102 的二进制 blob（模拟"皮肤包/载荷"）。
 */
#include <windows.h>
#include <stdio.h>

int main(void) {
    HRSRC h = FindResourceA(NULL, MAKEINTRESOURCEA(102), "DATA");
    if (!h) {
        printf("resource DATA/102 not found\n");
        return 1;
    }
    DWORD sz = SizeofResource(NULL, h);
    HGLOBAL g = LoadResource(NULL, h);
    void *p = LockResource(g);
    printf("resource DATA/102 loaded: %lu bytes at %p\n", (unsigned long)sz, p);
    return 0;
}
