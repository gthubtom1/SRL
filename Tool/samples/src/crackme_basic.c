/*
 * crackme_basic.c —— 基础 crackme 样本（本仓库原创，GPL-3.0）
 * 用途：给 seep_decompile_auto / seep_r2_strings / seep_packer_detect 提供无壳 PE 样本。
 * 编译：gcc -O2 -o crackme_basic.exe crackme_basic.c
 *
 * 玩法：程序校验一个硬编码口令；输错提示 "Access Denied"，输对提示 "Access Granted"。
 * 逆向目标：定位比较逻辑，找出正确口令（或 patch 掉失败分支）。
 */
#include <stdio.h>
#include <string.h>

static int check_key(const char *input) {
    /* 简单变换：逐字符与 0x5A 异或后与目标数组比较 */
    const unsigned char target[] = {0x36, 0x2b, 0x28, 0x28, 0x25, 0x7c, 0x31, 0x26, 0x2b, 0x2d};
    const int n = sizeof(target) / sizeof(target[0]);
    if ((int)strlen(input) != n) return 0;
    for (int i = 0; i < n; i++) {
        if ((unsigned char)(input[i] ^ 0x5A) != target[i]) return 0;
    }
    return 1;
}

int main(void) {
    char buf[128];
    printf("Enter license key: ");
    if (!fgets(buf, sizeof(buf), stdin)) return 1;
    size_t l = strlen(buf);
    if (l && buf[l - 1] == '\n') buf[l - 1] = 0;

    if (check_key(buf)) {
        printf("Access Granted\n");
        return 0;
    }
    printf("Access Denied\n");
    return 1;
}
