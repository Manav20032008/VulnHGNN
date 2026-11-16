#include <stdlib.h>

/**
 * test_22_cwe401.c
 * Result: CWE-401 (Memory Leak)
 */
void leak(void) {
    int *p = (int *)malloc(sizeof(int));
    *p = 123;
}

int main(void) {
    leak();
    return 0;
}
