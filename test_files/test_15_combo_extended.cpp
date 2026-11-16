#include <climits>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

/** test_15_combo_extended.cpp — CWE-190, CWE-121, CWE-134 */
void combo(int x, char *fmt, const std::string &name) {
    char buf[8];
    std::strcpy(buf, name.c_str());
    int y = x + INT_MAX;
    std::printf(fmt, y, buf);
    std::cout << std::flush;
}

int main() {
    char user_fmt[] = "%d %s";
    combo(100, user_fmt, "overflow_name_here");
    return 0;
}
