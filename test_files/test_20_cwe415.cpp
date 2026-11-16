#include <iostream>

/** test_20_cwe415.cpp — CWE-415 */
void double_free() {
    int *p = new int(42);
    delete p;
    delete p;
}

int main() {
    double_free();
    return 0;
}
