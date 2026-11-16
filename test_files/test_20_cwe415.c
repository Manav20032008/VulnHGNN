#include <stdlib.h>

/**
 * test_20_cwe415.c
 * Result: CWE-415 (Double Free)
 */
void double_free(void) {
    int *p = (int *)malloc(sizeof(int));
    *p = 42;
    free(p);
    free(p);
}

int main(void) {
    double_free();
    return 0;
}
