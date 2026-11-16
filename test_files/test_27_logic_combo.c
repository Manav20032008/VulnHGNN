/**
 * test_27_logic_combo.c
 * Result: CWE-835 + CWE-833 patterns in one translation unit
 */
#include <pthread.h>

pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

void worker(void) {
    pthread_mutex_lock(&g_mu);
    pthread_mutex_lock(&g_mu);
    for (;;) {
    }
}

int main(void) {
    worker();
    return 0;
}
