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
	gcc -Wl,-Ttext-segment -Wl,0x800000 ${WRAPPERS} -static $^ -o $@ -ldl -lrt -pthread

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
# problem in mq_notify,--wrap=__clone,--wrap=execl,--wrap=execlp,--wrap=execle,--wrap=sigvec,--wrap=epoll_ctl,--wrap=epoll_wait,--wrap=pselect,--wrap=getaddrinfo
WRAPPERS=-Wl,--wrap=calloc,--wrap=realloc,--wrap=free,--wrap=malloc,--wrap=read,--wrap=mmap,--wrap=lseek,--wrap=fclose,--wrap=close,--wrap=unlink,--wrap=munmap,--wrap=mmap64,--wrap=mremap,--wrap=open,--wrap=fopen,--wrap=socket,--wrap=connect,--wrap=bind,--wrap=listen,--wrap=accept,--wrap=accept4,--wrap=setsockopt,--wrap=getsockopt,--wrap=fexecve,--wrap=execve,--wrap=execv,--wrap=execvp,--wrap=execvpe,--wrap=system,--wrap=popen,--wrap=pclose,--wrap=fork,--wrap=clone,--wrap=open64,--wrap=fopen64,--wrap=openat,--wrap=openat64,--wrap=opendir,--wrap=mkstemp,--wrap=closedir,--wrap=exit,--wrap=dup,--wrap=dup2,--wrap=dup3,--wrap=fcntl,--wrap=ttyname_r,--wrap=ptsname_r,--wrap=getpt,--wrap=posix_openpt,--wrap=socketpair,--wrap=openlog,--wrap=closelog,--wrap=signal,--wrap=sigaction,--wrap=rt_sigaction,--wrap=sigblock,--wrap=sigsetmask,--wrap=siggetmask,--wrap=sigprocmask,--wrap=rt_sigprocmask,--wrap=pthread_sigmask,--wrap=pthread_getspecific,--wrap=sigsuspend,--wrap=sighold,--wrap=sigignore,--wrap=sigpause,--wrap=sigrelse,--wrap=sigset,--wrap=sigwait,--wrap=sigwaitinfo,--wrap=sigtimedwait,--wrap=syscall,--wrap=pthread_create,--wrap=pthread_exit,--wrap=pthread_tryjoin_np,--wrap=pthread_timedjoin_np,--wrap=xstat,--wrap=lxstat,--wrap=readlink,--wrap=dlsym,--wrap=dlopen,--wrap=dlclose,--wrap=__libc_memalign,--wrap=write,--wrap=select,--wrap=pthread_mutex_lock,--wrap=pthread_mutex_trylock,--wrap=pthread_mutex_unlock,--wrap=pthread_rwlock_unlock,--wrap=pthread_rwlock_rdlock,--wrap=pthread_rwlock_tryrdlock,--wrap=pthread_rwlock_wrlock,--wrap=pthread_rwlock_trywrlock,--wrap=pthread_cond_broadcast,--wrap=pthread_cond_destroy,--wrap=pthread_cond_init,--wrap=pthread_cond_signal,--wrap=pthread_cond_timedwait,--wrap=pthread_cond_wait,--wrap=poll,--wrap=waitid,--wrap=wait4,--wrap=shmget,--wrap=shmat,--wrap=shmdt,--wrap=shmctl,--wrap=semget,--wrap=semop,--wrap=semtimedop,--wrap=semctl,--wrap=msgget,--wrap=msgsnd,--wrap=msgrcv,--wrap=msgctl,--wrap=mq_open,--wrap=mq_close,--wrap=mq_notify,--wrap=mq_timedreceive,--wrap=mq_timedsend,--wrap=fread,--wrap=fwrite,--wrap=daemon,--wrap=vfork,--wrap=execve,--wrap=execv,--wrap=execvp,--wrap=execvpe,--wrap=fexecve,--wrap=system,--wrap=pipe,--wrap=pipe2,--wrap=wait,--wrap=waitpid,--wrap=wait3,--wrap=wait4,--wrap=__sigpause,--wrap=ioctl,--wrap=getpid,--wrap=getppid,--wrap=kill,--wrap=tcgetpgrp,--wrap=tcsetpgrp,--wrap=setpgid,--wrap=getpgid,--wrap=getpgrp,--wrap=getpgrp,--wrap=setpgrp,--wrap=setpgrp,--wrap=getsid,--wrap=setsid,--wrap=setgid,--wrap=setuid,--wrap=getuid,--wrap=geteuid,--wrap=setenv,--wrap=unsetenv,--wrap=realpath,--wrap=access,--wrap=clock_getcpuclockid,--wrap=timer_create,--wrap=timer_delete,--wrap=timer_settime,--wrap=timer_gettime,--wrap=timer_getoverrun,--wrap=pthread_getcpuclockid,--wrap=clock_getres,--wrap=clock_gettime,--wrap=clock_settime,--wrap=clock_nanosleep,--wrap=process_vm_readv,--wrap=process_vm_writev,--wrap=tcgetsid,--wrap=ptrace,--wrap=sched_setaffinity,--wrap=sched_getaffinity,--wrap=sched_setscheduler,--wrap=sched_getscheduler,--wrap=sched_setparam,--wrap=sched_getparam,--wrap=getnameinfo,--wrap=gethostbyname,--wrap=gethostbyaddr,--wrap=__poll_chk,--wrap=signalfd,--wrap=eventfd,--wrap=epoll_create,--wrap=epoll_create1,--wrap=inotify_init,--wrap=inotify_init1,--wrap=inotify_add_watch,--wrap=inotify_rm_watch,--wrap=tmpfile,--wrap=mkostemp,--wrap=mkstemps,--wrap=mkostemps,--wrap=creat,--wrap=creat64,--wrap=ttyname,--wrap=ttyname_r,--wrap=fseek,--wrap=ftell,--wrap=rewind,--wrap=fgetpos,--wrap=fsetpos,--wrap=fdopen,--wrap=freopen
