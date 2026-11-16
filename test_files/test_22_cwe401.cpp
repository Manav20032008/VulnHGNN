#include <iostream>

/** test_22_cwe401.cpp — CWE-401 */
void leak() {
    int *p = new int(123);
    std::cout << *p << '\n';
}

int main() {
    leak();
    return 0;
}
