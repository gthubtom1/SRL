/* 教学用真实漏洞程序：gets() 无边界写栈缓冲区，可覆盖 saved RIP。
 * 仅用于本地授权实验；编译：gcc -O0 -fno-stack-protector -no-pie */
#include <stdio.h>
#include <stdlib.h>

void win(void) {
    puts("WIN: control flow hijacked");
    fflush(stdout);
    exit(0);                    /* 让证据以 rc=0 结束，便于统计稳定性 */
}

void vuln(void) {
    char buf[64];
    fprintf(stderr, "buf=%p frame=%p ret=%p\n",
            (void *)buf, __builtin_frame_address(0), __builtin_return_address(0));
    fflush(stderr);
    gets(buf);                  /* 真实漏洞点 */
    puts(buf);
}

int main(void) { vuln(); return 0; }
