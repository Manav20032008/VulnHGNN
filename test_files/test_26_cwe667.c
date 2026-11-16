/**
 * test_26_cwe667.c
 * Result: CWE-667 (Improper Locking — double lock)
 */
#include <pthread.h>

pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

void double_lock(void) {
    pthread_mutex_lock(&mu);
    pthread_mutex_lock(&mu);
    pthread_mutex_unlock(&mu);
}

int main(void) {
    double_lock();
    return 0;
}
