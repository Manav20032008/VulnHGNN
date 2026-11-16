#include <iostream>

/** test_24_cwe835.cpp — CWE-835 */
void spin_forever() {
    while (true) {
    }
}

int main() {
    spin_forever();
    return 0;
}
