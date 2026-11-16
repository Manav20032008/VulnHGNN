#include <iostream>

/** test_04_cwe369.cpp — CWE-369 */
int do_division(int a, int b) {
    return a / b;
}

int main() {
    int x = 10, y = 0;
    std::cout << "Result: " << do_division(x, y) << '\n';
    return 0;
}
