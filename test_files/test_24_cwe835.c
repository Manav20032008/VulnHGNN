/**
 * test_24_cwe835.c
 * Result: CWE-835 (Infinite Loop)
 */
void spin_forever(void) {
    while (1) {
        /* busy wait */
    }
}

int main(void) {
    spin_forever();
    return 0;
}
