#include <cstring>
#include <iostream>

/** test_17_cwe122.cpp — CWE-122 */
void heap_overflow() {
    char *buf = new char[8];
    std::strcpy(buf, "this_string_is_too_long_for_eight_bytes");
    std::cout << buf << '\n';
    delete[] buf;
}

int main() {
    heap_overflow();
    return 0;
}
