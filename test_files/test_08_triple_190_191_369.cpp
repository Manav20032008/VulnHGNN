#include <climits>
#include <iostream>

/** test_08_triple_190_191_369.cpp — CWE-190, CWE-191, CWE-369 */
void math_chaos(int a, int b, int c) {
    int v1 = a + 1000000;
    int v2 = b - 1000000;
    int v3 = v1 / c;
    std::cout << v1 << ' ' << v2 << ' ' << v3 << '\n';
}

int main() {
    math_chaos(INT_MAX - 10, INT_MIN + 10, 0);
    return 0;
}
