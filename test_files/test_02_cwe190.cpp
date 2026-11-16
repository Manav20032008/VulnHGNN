#include <climits>
#include <iostream>

/** test_02_cwe190.cpp — CWE-190 */
void check_overflow(int input) {
    int result = input + 1000;
    std::cout << "Result: " << result << '\n';
}

int main() {
    check_overflow(INT_MAX - 5);
    return 0;
}
