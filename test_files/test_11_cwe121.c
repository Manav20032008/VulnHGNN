#include <stdio.h>
#include <string.h>

/**
 * test_11_cwe121.c
 * Result: CWE-121 (Stack-based Buffer Overflow) — strcpy in IR
 */
void copy_name(const char *input) {
    char buf[16];
    strcpy(buf, input);
    printf("Name: %s\n", buf);
}

int main(void) {
    copy_name("this_string_is_way_too_long_for_buf");
    return 0;
}
