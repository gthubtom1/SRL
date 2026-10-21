/* 边界探针：确认 MinGW/UCRT 下 %n 是否真的写入（Windows 与 glibc 的关键差异）。 */
#include <stdio.h>
int main(void) {
    int x = 0;
    printf("abc%n\n", &x);
    printf("x=%d\n", x);
    return 0;
}
