#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/**
 * test_16_all_detectable.c
 * IR graph: CWE-190, CWE-191, CWE-369, CWE-476, CWE-121, CWE-134
 */
void all_patterns(int a, int b, int c, char *fmt, const char *name) {
    char buf[6];
    strcpy(buf, name);

    int *p = (int *)malloc(sizeof(int));
    *p = a;

    int v1 = (*p) + INT_MAX;
    int v2 = b - 2000000;
    int v3 = v1 / c;

    printf(fmt, v1, v2, v3, buf);
    free(p);
}

int main(void) {
    char fmt[] = "%d %d %d %s";
    all_patterns(1, INT_MIN + 50, 0, fmt, "long_name_value");
    return 0;
}
