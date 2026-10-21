/* 教学用真实漏洞程序：uint32 乘法回绕导致分配过小，随后按固定长度写入越界。
 * 仅用于本地授权实验；编译：gcc -O0 -fno-stack-protector -no-pie */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

int main(void) {
    char line[64];
    uint32_t count, bytes;
    void *p;
    size_t msize;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!fgets(line, sizeof line, stdin)) return 1;
    count = (uint32_t)strtoul(line, NULL, 10);
    bytes = count * 4u;                 /* 32-bit 回绕：count * sizeof(uint32_t) */
    printf("count=%u elem=4 bytes=%u wrapped=%d\n", count, bytes, bytes < count);
    p = malloc(bytes ? bytes : 1);      /* bytes=4 -> 极小分配 */
    if (!p) { puts("malloc failed"); return 2; }
    msize = _msize(p);
    printf("request=%u _msize=%zu\n", bytes, msize);
    memset(p, 'A', 64);                 /* 固定写 64B，越过请求长度 */
    printf("wrote=64 overflow=%d\n", msize < 64);
    free(p);                            /* 堆元数据被破坏时在这里 abort */
    puts("freed without abort");
    return 0;
}
