#include <pthread.h>

#define TVM_PTHREAD_FORK 1

void tvm_init();

pid_t forkless();

int tvm_pthread_fork(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
int tvm_pthread_create(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
int tvm_pthread_create_ex(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine) (void *), void *arg, int flags);

void tvm_pthread_exit(void *retval);
