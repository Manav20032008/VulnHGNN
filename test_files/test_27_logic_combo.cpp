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
