#include <climits>
#include <iostream>

/** test_03_cwe191.cpp — CWE-191 */
void check_underflow(int input) {
    int result = input - 1000;
    std::cout << "Result: " << result << '\n';
}

int main() {
    check_underflow(INT_MIN + 5);
    return 0;
}
