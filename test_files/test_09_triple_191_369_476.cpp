#include <climits>
#include <iostream>

/** test_09_triple_191_369_476.cpp — CWE-191, CWE-369, CWE-476 */
void risky_logic(int val, int div) {
    int *ptr = new int;
    *ptr = val;
    int sub = *ptr - INT_MAX;
    int result = sub / div;
    std::cout << "Result: " << result << '\n';
    delete ptr;
}

int main() {
    risky_logic(INT_MIN, 0);
    return 0;
}
