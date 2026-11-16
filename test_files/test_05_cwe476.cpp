#include <cstring>
#include <iostream>
#include <new>

/** test_05_cwe476.cpp — CWE-476 */
void handle_record(int id) {
    char *name = new (std::nothrow) char[64];
    std::strcpy(name, "User Record");
    std::cout << "ID: " << id << ", Name: " << name << '\n';
    delete[] name;
}

int main() {
    handle_record(1);
    return 0;
}
