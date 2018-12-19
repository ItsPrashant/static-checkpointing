FILE=kernel-loader

RTLD_PATH=/lib64/ld-linux-x86-64.so.2

#WRAPPER_OBJ=lib_wrapper.o
WRAPPER_OBJ=libkl.o
#APPLICATION_OBJ=application.o
APPLICATION_OBJ=syscall-tester.o

KERNEL_LOADER_OBJS=${FILE}.o procmapsutils.o custom-loader.o mmap-wrapper.o sbrk-wrapper.o ${WRAPPER_OBJ} ${APPLICATION_OBJ}
TARGET_OBJS=target.o
DUMMY_OBJ=dummy.o

CFLAGS=-g3 -O0 -fPIC -I. -c -std=gnu11 #-Wl,--wrap=free,--wrap=mmap,--wrap=malloc,--wrap=lseek,--wrap=close
KERNEL_LOADER_CFLAGS=
# -fno-stack-protector
#KERNEL_LOADER_BIN=kernel-loader.exe
TARGET_BIN=t.exe
APPLICATION_BIN=application.exe
DUMMY_BIN=dummy.exe

run: ${APPLICATION_BIN} ${TARGET_BIN} ${DUMMY_BIN}
	./$< $$PWD/${DUMMY_BIN} arg1 arg2 arg3

gdb: ${APPLICATION_BIN} ${TARGET_BIN}
	gdb --args ./$< $$PWD/${DUMMY_BIN} arg1 arg2 arg3

.c.o:
	gcc ${CFLAGS} $< -o $@

${FILE}.o: ${FILE}.c
	gcc ${CFLAGS} ${KERNEL_LOADER_CFLAGS} $< -o $@

${TARGET_BIN}: ${TARGET_OBJS}
	gcc $< -o $@

${DUMMY_BIN}: ${DUMMY_OBJ}
	gcc -g3 $< -o $@ -ldl

${APPLICATION_BIN}: ${KERNEL_LOADER_OBJS}
	gcc -Wl,-Ttext-segment -Wl,0x800000 ${WRAPPERS} -static $^ -o $@ -lpthread -ldl -lrt

vi vim:
	vim ${FILE}.c

tags:
	gtags .

dist: clean
	(dir=`basename $$PWD` && cd .. && tar zcvf $$dir.tgz $$dir)
	(dir=`basename $$PWD` && ls -l ../$$dir.tgz)

clean:
	rm -f ${KERNEL_LOADER_OBJS} ${TARGET_OBJS} ${KERNEL_LOADER_BIN} ${TARGET_BIN} ${DUMMY_BIN} ${DUMMY_OBJ} ${APPLICATION_BIN} GTAGS GRTAGS GPATH

.PHONY: dist vi vim clean gdb tags
# problem in mq_notify
WRAPPERS=-Wl,--wrap=calloc,--wrap=realloc,--wrap=free,--wrap=malloc,--wrap=read,--wrap=mmap,--wrap=lseek,--wrap=fclose,--wrap=close,--wrap=unlink,--wrap=munmap,--wrap=mmap64,--wrap=mremap,--wrap=open,--wrap=fopen,--wrap=socket,--wrap=connect,--wrap=bind,--wrap=listen,--wrap=accept,--wrap=accept4,--wrap=setsockopt,--wrap=getsockopt,--wrap=fexecve,--wrap=execve,--wrap=execv,--wrap=execvp,--wrap=execvpe,--wrap=system,--wrap=popen,--wrap=pclose,--wrap=fork,--wrap=clone,--wrap=open64,--wrap=fopen64,--wrap=openat,--wrap=openat64,--wrap=opendir,--wrap=mkstemp,--wrap=closedir,--wrap=exit,--wrap=dup,--wrap=dup2,--wrap=dup3,--wrap=fcntl,--wrap=ttyname_r,--wrap=ptsname_r,--wrap=getpt,--wrap=posix_openpt,--wrap=socketpair,--wrap=openlog,--wrap=closelog,--wrap=signal,--wrap=sigaction,--wrap=rt_sigaction,--wrap=sigblock,--wrap=sigsetmask,--wrap=siggetmask,--wrap=sigprocmask,--wrap=rt_sigprocmask,--wrap=pthread_sigmask,--wrap=pthread_getspecific,--wrap=sigsuspend,--wrap=sighold,--wrap=sigignore,--wrap=sigpause,--wrap=sigrelse,--wrap=sigset,--wrap=sigwait,--wrap=sigwaitinfo,--wrap=sigtimedwait,--wrap=syscall,--wrap=pthread_create,--wrap=pthread_exit,--wrap=pthread_tryjoin_np,--wrap=pthread_timedjoin_np,--wrap=xstat,--wrap=lxstat,--wrap=readlink,--wrap=dlsym,--wrap=dlopen,--wrap=dlclose,--wrap=__libc_memalign,--wrap=write,--wrap=select,--wrap=pthread_mutex_lock,--wrap=pthread_mutex_trylock,--wrap=pthread_mutex_unlock,--wrap=pthread_rwlock_unlock,--wrap=pthread_rwlock_rdlock,--wrap=pthread_rwlock_tryrdlock,--wrap=pthread_rwlock_wrlock,--wrap=pthread_rwlock_trywrlock,--wrap=pthread_cond_broadcast,--wrap=pthread_cond_destroy,--wrap=pthread_cond_init,--wrap=pthread_cond_signal,--wrap=pthread_cond_timedwait,--wrap=pthread_cond_wait,--wrap=poll,--wrap=waitid,--wrap=wait4,--wrap=shmget,--wrap=shmat,--wrap=shmdt,--wrap=shmctl,--wrap=semget,--wrap=semop,--wrap=semtimedop,--wrap=semctl,--wrap=msgget,--wrap=msgsnd,--wrap=msgrcv,--wrap=msgctl,--wrap=mq_open,--wrap=mq_close,--wrap=mq_notify,--wrap=mq_timedreceive,--wrap=mq_timedsend
