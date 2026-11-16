#include <iostream>

/** test_13_cwe457.cpp — CWE-457 */
int use_uninit() {
    int value;
    return value + 1;
}

int main() {
    std::cout << use_uninit() << '\n';
    return 0;
}
