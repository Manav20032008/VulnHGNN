#include <iostream>
#include <memory>

/** test_01_clean.cpp — no intentional catalog CWE */
int main() {
    int a = 10, b = 20;
    int sum = a + b;
    if (b != 0) {
        std::cout << "Result: " << (sum / b) << '\n';
    }
    auto p = std::make_unique<int>(100);
    std::cout << "Pointer value: " << *p << '\n';
    return 0;
}
