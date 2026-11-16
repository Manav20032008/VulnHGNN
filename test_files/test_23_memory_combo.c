#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * test_23_memory_combo.c
 * Result: CWE-122, CWE-416, CWE-401 (leak on unreachable path after UAF pattern)
 */
void memory_combo(char *input) {
    char *buf = (char *)malloc(6);
    strcpy(buf, input);
    free(buf);
    printf("%c\n", buf[0]);
}

int main(void) {
    memory_combo("overflow");
    return 0;
}
