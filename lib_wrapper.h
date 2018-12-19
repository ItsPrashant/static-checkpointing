#ifndef LIB_WRAPPER_H
#define LIB_WRAPPER_H
#include <features.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/wait.h>

void loader(int argc,const char *argv[]);
int __wrap_open(const char *file,int mode);
int __real_open(const char *file,int mode);
FILE *__real_fopen(const char *pathname, const char *mode);
void *__real_malloc(size_t size);
void __real_free(void *ptr);

#endif
