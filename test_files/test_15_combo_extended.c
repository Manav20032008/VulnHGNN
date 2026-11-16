#include <stdio.h>
#include <string.h>
#include <limits.h>

/**
 * test_15_combo_extended.c
 * Result: CWE-190, CWE-121, CWE-134
 */
void combo(int x, char *fmt, const char *name) {
    char buf[8];
    strcpy(buf, name);
    int y = x + INT_MAX;
    printf(fmt, y, buf);
}

int main(void) {
    char user_fmt[] = "%d %s";
    combo(100, user_fmt, "overflow_name_here");
    return 0;
}
