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
    std::cout << "locks acquired\n";
    return 0;
}
