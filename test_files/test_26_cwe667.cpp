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
    std::cout << "done\n";
    return 0;
}
