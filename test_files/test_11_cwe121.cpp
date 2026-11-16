#include <cstring>
#include <iostream>
#include <string>

/** test_11_cwe121.cpp — CWE-121 */
void copy_name(const std::string &input) {
    char buf[16];
    std::strcpy(buf, input.c_str());
    std::cout << "Name: " << buf << '\n';
}

int main() {
    copy_name("this_string_is_way_too_long_for_buf");
    return 0;
}
