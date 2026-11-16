#include <iostream>

/** test_18_cwe125.cpp — CWE-125 */
int read_oob() {
    int data[4] = {1, 2, 3, 4};
    return data[12];
}

int main() {
    std::cout << read_oob() << '\n';
    return 0;
}
