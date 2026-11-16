#include <iostream>

/** test_14_cwe787.cpp — CWE-787 */
void oob_write() {
    int data[4];
    data[9] = 42;
    std::cout << data[0] << '\n';
}

int main() {
    oob_write();
    return 0;
}
