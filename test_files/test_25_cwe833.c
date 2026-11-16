/**
 * test_25_cwe833.c
 * Result: CWE-833 (Deadlock risk — nested mutex lock)
 */
#include <pthread.h>

pthread_mutex_t mu_a = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mu_b = PTHREAD_MUTEX_INITIALIZER;

void nested_lock(void) {
    pthread_mutex_lock(&mu_a);
    pthread_mutex_lock(&mu_b);
    pthread_mutex_unlock(&mu_b);
    pthread_mutex_unlock(&mu_a);
}

int main(void) {
    nested_lock();
    return 0;
}
