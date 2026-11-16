#include <iostream>

/** test_07_dual_369_476.cpp — CWE-369, CWE-476 */
void process_data(int divisor) {
    int *data = new int;
    *data = 500;
    int result = *data / divisor;
    std::cout << "Value: " << result << '\n';
    delete data;
}

int main() {
    process_data(0);
    return 0;
}
