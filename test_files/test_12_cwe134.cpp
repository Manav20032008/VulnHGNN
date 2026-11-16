#include <cstdio>
#include <iostream>

/** test_12_cwe134.cpp — CWE-134 (non-literal format in IR) */
void log_user(char *user_fmt) {
    std::printf(user_fmt);
}

int main() {
    char fmt[] = "%s%n";
    log_user(fmt);
    std::cout << std::flush;
    return 0;
}
