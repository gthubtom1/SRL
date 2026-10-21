/* 教学用真实漏洞程序：printf(buf) 格式化串，可在未认证时任意读。
 * 仅用于本地授权实验；编译：gcc -O0 -fno-stack-protector -no-pie */
#include <stdio.h>
#include <stdlib.h>

char secret[64] = "FLAG{fmt_string_arbitrary_read_works}";
int authenticated = 0;

int main(void) {
    char buf[256];
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    printf(buf);                        /* 真实漏洞点：格式串可控 */
    putchar('\n');
    fflush(stdout);
    if (authenticated) puts(secret);
    else puts("denied");
    return 0;
}
