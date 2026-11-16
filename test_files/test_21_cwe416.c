#include <stdlib.h>

/**
 * test_21_cwe416.c
 * Result: CWE-416 (Use After Free)
 */
void use_after_free(void) {
    int *p = (int *)malloc(sizeof(int));
    *p = 7;
    free(p);
    *p = 99;
}

int main(void) {
    use_after_free();
    return 0;
}
