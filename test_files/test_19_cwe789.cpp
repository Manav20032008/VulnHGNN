#include <cstdlib>
#include <iostream>

/** test_19_cwe789.cpp — CWE-789 / CWE-400 */
void maybe_oom(unsigned count) {
    std::size_t n = static_cast<std::size_t>(count) * 1000000000u;
    std::malloc(n);
}

int main() {
    maybe_oom(64);
    std::cout << "allocated\n";
    return 0;
}
