#include <climits>
#include <iostream>

/** test_06_dual_190_191.cpp — CWE-190, CWE-191 */
void complex_math(int x, int y) {
    int over = x * 100;
    int under = y - 100000;
    std::cout << "O: " << over << ", U: " << under << '\n';
}

int main() {
    complex_math(INT_MAX / 2, INT_MIN + 50);
    return 0;
}
