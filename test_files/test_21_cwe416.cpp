#include <iostream>

/** test_21_cwe416.cpp — CWE-416 */
void use_after_free() {
    int *p = new int(7);
    delete p;
    *p = 99;
    std::cout << "done\n";
}

int main() {
    use_after_free();
    return 0;
}
