#!/usr/bin/env python3
"""Write idiomatic C++ test fixtures (iostream + modern main); vuln IR preserved."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "test_files"

FIXTURES: dict[str, str] = {}

def add(name: str, body: str) -> None:
    FIXTURES[name] = body.strip() + "\n"

add("test_01_clean.cpp", """
#include <iostream>
#include <memory>

/** test_01_clean.cpp — no intentional catalog CWE */
int main() {
    int a = 10, b = 20;
    int sum = a + b;
    if (b != 0) {
        std::cout << "Result: " << (sum / b) << '\\n';
    }
    auto p = std::make_unique<int>(100);
    std::cout << "Pointer value: " << *p << '\\n';
    return 0;
}
""")

add("test_02_cwe190.cpp", """
#include <climits>
#include <iostream>

/** test_02_cwe190.cpp — CWE-190 */
void check_overflow(int input) {
    int result = input + 1000;
    std::cout << "Result: " << result << '\\n';
}

int main() {
    check_overflow(INT_MAX - 5);
    return 0;
}
""")

add("test_03_cwe191.cpp", """
#include <climits>
#include <iostream>

/** test_03_cwe191.cpp — CWE-191 */
void check_underflow(int input) {
    int result = input - 1000;
    std::cout << "Result: " << result << '\\n';
}

int main() {
    check_underflow(INT_MIN + 5);
    return 0;
}
""")

add("test_04_cwe369.cpp", """
#include <iostream>

/** test_04_cwe369.cpp — CWE-369 */
int do_division(int a, int b) {
    return a / b;
}

int main() {
    int x = 10, y = 0;
    std::cout << "Result: " << do_division(x, y) << '\\n';
    return 0;
}
""")

add("test_05_cwe476.cpp", """
#include <cstring>
#include <iostream>
#include <new>

/** test_05_cwe476.cpp — CWE-476 */
void handle_record(int id) {
    char *name = new (std::nothrow) char[64];
    std::strcpy(name, "User Record");
    std::cout << "ID: " << id << ", Name: " << name << '\\n';
    delete[] name;
}

int main() {
    handle_record(1);
    return 0;
}
""")

add("test_06_dual_190_191.cpp", """
#include <climits>
#include <iostream>

/** test_06_dual_190_191.cpp — CWE-190, CWE-191 */
void complex_math(int x, int y) {
    int over = x * 100;
    int under = y - 100000;
    std::cout << "O: " << over << ", U: " << under << '\\n';
}

int main() {
    complex_math(INT_MAX / 2, INT_MIN + 50);
    return 0;
}
""")

add("test_07_dual_369_476.cpp", """
#include <iostream>

/** test_07_dual_369_476.cpp — CWE-369, CWE-476 */
void process_data(int divisor) {
    int *data = new int;
    *data = 500;
    int result = *data / divisor;
    std::cout << "Value: " << result << '\\n';
    delete data;
}

int main() {
    process_data(0);
    return 0;
}
""")

add("test_08_triple_190_191_369.cpp", """
#include <climits>
#include <iostream>

/** test_08_triple_190_191_369.cpp — CWE-190, CWE-191, CWE-369 */
void math_chaos(int a, int b, int c) {
    int v1 = a + 1000000;
    int v2 = b - 1000000;
    int v3 = v1 / c;
    std::cout << v1 << ' ' << v2 << ' ' << v3 << '\\n';
}

int main() {
    math_chaos(INT_MAX - 10, INT_MIN + 10, 0);
    return 0;
}
""")

add("test_09_triple_191_369_476.cpp", """
#include <climits>
#include <iostream>

/** test_09_triple_191_369_476.cpp — CWE-191, CWE-369, CWE-476 */
void risky_logic(int val, int div) {
    int *ptr = new int;
    *ptr = val;
    int sub = *ptr - INT_MAX;
    int result = sub / div;
    std::cout << "Result: " << result << '\\n';
    delete ptr;
}

int main() {
    risky_logic(INT_MIN, 0);
    return 0;
}
""")

add("test_10_all_vulnerabilities.cpp", """
#include <climits>
#include <iostream>

/** test_10_all_vulnerabilities.cpp — CWE-190,191,369,476 */
void the_ultimate_test(int a, int b, int c) {
    int *p = new int;
    *p = a;
    int v1 = (*p) + INT_MAX;
    int v2 = b - 2000000;
    int v3 = v1 / c;
    std::cout << "V1: " << v1 << ", V2: " << v2 << ", V3: " << v3 << '\\n';
    delete p;
}

int main() {
    the_ultimate_test(100, INT_MIN + 100, 0);
    return 0;
}
""")

add("test_11_cwe121.cpp", """
#include <cstring>
#include <iostream>
#include <string>

/** test_11_cwe121.cpp — CWE-121 */
void copy_name(const std::string &input) {
    char buf[16];
    std::strcpy(buf, input.c_str());
    std::cout << "Name: " << buf << '\\n';
}

int main() {
    copy_name("this_string_is_way_too_long_for_buf");
    return 0;
}
""")

add("test_12_cwe134.cpp", """
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
""")

add("test_13_cwe457.cpp", """
#include <iostream>

/** test_13_cwe457.cpp — CWE-457 */
int use_uninit() {
    int value;
    return value + 1;
}

int main() {
    std::cout << use_uninit() << '\\n';
    return 0;
}
""")

add("test_14_cwe787.cpp", """
#include <iostream>

/** test_14_cwe787.cpp — CWE-787 */
void oob_write() {
    int data[4];
    data[9] = 42;
    std::cout << data[0] << '\\n';
}

int main() {
    oob_write();
    return 0;
}
""")

add("test_15_combo_extended.cpp", """
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
""")

add("test_16_all_detectable.cpp", """
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
""")

add("test_17_cwe122.cpp", """
#include <cstring>
#include <iostream>

/** test_17_cwe122.cpp — CWE-122 */
void heap_overflow() {
    char *buf = new char[8];
    std::strcpy(buf, "this_string_is_too_long_for_eight_bytes");
    std::cout << buf << '\\n';
    delete[] buf;
}

int main() {
    heap_overflow();
    return 0;
}
""")

add("test_18_cwe125.cpp", """
#include <iostream>

/** test_18_cwe125.cpp — CWE-125 */
int read_oob() {
    int data[4] = {1, 2, 3, 4};
    return data[12];
}

int main() {
    std::cout << read_oob() << '\\n';
    return 0;
}
""")

add("test_19_cwe789.cpp", """
#include <cstdlib>
#include <iostream>

/** test_19_cwe789.cpp — CWE-789 / CWE-400 */
void maybe_oom(unsigned count) {
    std::size_t n = static_cast<std::size_t>(count) * 1000000000u;
    std::malloc(n);
}

int main() {
    maybe_oom(64);
    std::cout << "allocated\\n";
    return 0;
}
""")

add("test_20_cwe415.cpp", """
#include <iostream>

/** test_20_cwe415.cpp — CWE-415 */
void double_free() {
    int *p = new int(42);
    delete p;
    delete p;
}

int main() {
    double_free();
    return 0;
}
""")

add("test_21_cwe416.cpp", """
#include <iostream>

/** test_21_cwe416.cpp — CWE-416 */
void use_after_free() {
    int *p = new int(7);
    delete p;
    *p = 99;
    std::cout << "done\\n";
}

int main() {
    use_after_free();
    return 0;
}
""")

add("test_22_cwe401.cpp", """
#include <iostream>

/** test_22_cwe401.cpp — CWE-401 */
void leak() {
    int *p = new int(123);
    std::cout << *p << '\\n';
}

int main() {
    leak();
    return 0;
}
""")

add("test_23_memory_combo.cpp", """
#include <cstring>
#include <iostream>

/** test_23_memory_combo.cpp — CWE-122, CWE-416 */
void memory_combo(const char *input) {
    char *buf = new char[6];
    std::strcpy(buf, input);
    delete[] buf;
    std::cout << buf[0] << '\\n';
}

int main() {
    memory_combo("overflow");
    return 0;
}
""")

add("test_24_cwe835.cpp", """
#include <iostream>

/** test_24_cwe835.cpp — CWE-835 */
void spin_forever() {
    while (true) {
    }
}

int main() {
    spin_forever();
    return 0;
}
""")

add("test_25_cwe833.cpp", """
#include <iostream>
#include <pthread.h>

/** test_25_cwe833.cpp — CWE-833 */
pthread_mutex_t mu_a = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mu_b = PTHREAD_MUTEX_INITIALIZER;

void nested_lock() {
    pthread_mutex_lock(&mu_a);
    pthread_mutex_lock(&mu_b);
    pthread_mutex_unlock(&mu_b);
    pthread_mutex_unlock(&mu_a);
}

int main() {
    nested_lock();
    std::cout << "locks acquired\\n";
    return 0;
}
""")

add("test_26_cwe667.cpp", """
#include <iostream>
#include <pthread.h>

/** test_26_cwe667.cpp — CWE-667 */
pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

void double_lock() {
    pthread_mutex_lock(&mu);
    pthread_mutex_lock(&mu);
    pthread_mutex_unlock(&mu);
}

int main() {
    double_lock();
    std::cout << "done\\n";
    return 0;
}
""")

add("test_27_logic_combo.cpp", """
#include <iostream>
#include <pthread.h>

/** test_27_logic_combo.cpp — CWE-835, CWE-833 */
pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

void worker() {
    pthread_mutex_lock(&g_mu);
    pthread_mutex_lock(&g_mu);
    for (;;) {
    }
}

int main() {
    worker();
    return 0;
}
""")


def main() -> int:
    for name, content in FIXTURES.items():
        path = ROOT / name
        path.write_text(content, encoding="utf-8")
        print("wrote", name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
