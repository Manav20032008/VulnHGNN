#include <stdio.h>

/**
 * test_12_cwe134.c
 * Result: CWE-134 (Externally-Controlled Format String)
 */
void log_user(char *user_fmt) {
    printf(user_fmt);
}

int main(void) {
    char fmt[] = "%s%n";
    log_user(fmt);
    return 0;
}
