#include <climits>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

/** test_16_all_detectable.cpp — CWE-190,191,369,476,121,134 */
void all_patterns(int a, int b, int c, char *fmt, const std::string &name) {
    char buf[6];
    std::strcpy(buf, name.c_str());
    int *p = new int;
    *p = a;
    int v1 = (*p) + INT_MAX;
    int v2 = b - 2000000;
    int v3 = v1 / c;
    std::printf(fmt, v1, v2, v3, buf);
    delete p;
    std::cout << std::flush;
}

int main() {
    char fmt[] = "%d %d %d %s";
    all_patterns(1, INT_MIN + 50, 0, fmt, "long_name_value");
    return 0;
}
