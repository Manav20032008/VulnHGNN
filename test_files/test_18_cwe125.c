#include <stdio.h>

/**
 * test_18_cwe125.c
 * Result: CWE-125 (Out-of-bounds Read) — compiler bounds + IR
 */
int read_oob(void) {
    int data[4] = {1, 2, 3, 4};
    return data[12];
}

int main(void) {
    printf("%d\n", read_oob());
    return 0;
}
