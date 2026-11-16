#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * test_17_cwe122.c
 * Result: CWE-122 (Heap-based Buffer Overflow)
 */
void heap_overflow(void) {
    char *buf = (char *)malloc(8);
    strcpy(buf, "this_string_is_too_long_for_eight_bytes");
    printf("%s\n", buf);
    free(buf);
}

int main(void) {
    heap_overflow();
    return 0;
}
