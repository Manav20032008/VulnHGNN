#include <stdio.h>

/**
 * test_13_cwe457.c
 * Result: CWE-457 (Uninitialized Variable) — clang -Wuninitialized
 */
int use_uninit(void) {
    int value;
    return value + 1;
}

int main(void) {
    printf("%d\n", use_uninit());
    return 0;
}
