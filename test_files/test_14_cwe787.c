#include <stdio.h>

/**
 * test_14_cwe787.c
 * Result: CWE-787 (Out-of-bounds Write) — clang array bounds warning
 */
void oob_write(void) {
    int data[4];
    data[9] = 42;
    printf("%d\n", data[0]);
}

int main(void) {
    oob_write();
    return 0;
}
