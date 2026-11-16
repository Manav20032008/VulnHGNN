#include <cstring>
#include <iostream>

/** test_23_memory_combo.cpp — CWE-122, CWE-416 */
void memory_combo(const char *input) {
    char *buf = new char[6];
    std::strcpy(buf, input);
    delete[] buf;
    std::cout << buf[0] << '\n';
}

int main() {
    memory_combo("overflow");
    return 0;
}
