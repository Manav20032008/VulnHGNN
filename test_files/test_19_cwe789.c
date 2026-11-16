#include <stdlib.h>

/**
 * test_19_cwe789.c
 * Result: CWE-789 / CWE-400 (OOM / uncontrolled allocation size)
 */
void maybe_oom(unsigned count) {
    size_t n = (size_t)count * 1000000000u;
    malloc(n);
}

int main(void) {
    maybe_oom(64);
    return 0;
}
