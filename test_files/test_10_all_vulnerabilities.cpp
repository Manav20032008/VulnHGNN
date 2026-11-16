#include <climits>
#include <iostream>

/** test_10_all_vulnerabilities.cpp — CWE-190,191,369,476 */
void the_ultimate_test(int a, int b, int c) {
    int *p = new int;
    *p = a;
    int v1 = (*p) + INT_MAX;
    int v2 = b - 2000000;
    int v3 = v1 / c;
    std::cout << "V1: " << v1 << ", V2: " << v2 << ", V3: " << v3 << '\n';
    delete p;
}

int main() {
    the_ultimate_test(100, INT_MIN + 100, 0);
    return 0;
}
