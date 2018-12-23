#ifndef LIB_KL_H
#define LIB_KL_H

#define _GNU_SOURCE
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
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <dirent.h>
#include <mqueue.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/inotify.h>
#include <sys/ptrace.h>
#include <sys/epoll.h>
#include <time.h>


void loader(int argc,const char *argv[]);

int __wrap_socket(int domain, int type, int protocol);
int __wrap_connect(int sockfd,
                  const struct sockaddr *serv_addr,
                  socklen_t addrlen);
int __wrap_bind(int sockfd, const struct  sockaddr *my_addr, socklen_t addrlen);
int __wrap_listen(int sockfd, int backlog);
int __wrap_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int __wrap_accept4(int sockfd,
                  struct sockaddr *addr,
                  socklen_t *addrlen,
                  int flags);
int __wrap_setsockopt(int s,
                     int level,
                     int optname,
                     const void *optval,
                     socklen_t optlen);
int __wrap_getsockopt(int s,
                     int level,
                     int optname,
                     void *optval,
                     socklen_t *optlen);

int __wrap_fexecve(int fd, char *const argv[], char *const envp[]);
int __wrap_execve(const char *filename, char *const argv[], char *const envp[]);
int __wrap_execv(const char *path, char *const argv[]);
int __wrap_execvp(const char *file, char *const argv[]);
int __wrap_execvpe(const char *file, char *const argv[], char *const envp[]);


int __wrap_system(const char *cmd);
FILE *__wrap_popen(const char *command, const char *mode);
int __wrap_pclose(FILE *fp);

pid_t __wrap_fork();
int __wrap_clone(int (*fn)(void *arg),
                void *child_stack,
                int flags,
                void *arg,
                int *parent_tidptr,
                void *newtls,
                int *child_tidptr);

int __wrap_open(const char *pathname, int flags);
int __wrap_open64(const char *pathname, int flags);
FILE *__wrap_fopen(const char *path, const char *mode);
FILE *__wrap_fopen64(const char *path, const char *mode);
int __wrap_openat(int dirfd, const char *pathname, int flags, mode_t mode);
int __wrap_openat64(int dirfd, const char *pathname, int flags, mode_t mode);
DIR *__wrap_opendir(const char *name);
int __wrap_mkstemp(char *ttemplate);
int __wrap_close(int fd);
int __wrap_fclose(FILE *fp);
int __wrap_closedir(DIR *dir);
void __wrap_exit(int status);
int __wrap_dup(int oldfd);
int __wrap_dup2(int oldfd, int newfd);
int __wrap_dup3(int oldfd, int newfd, int flags);
int __wrap_fcntl(int fd, int cmd, void *arg);

int __wrap_ttyname_r(int fd, char *buf, size_t buflen);
int __wrap_ptsname_r(int fd, char *buf, size_t buflen);
int __wrap_getpt(void);
int __wrap_posix_openpt(int flags);

int __wrap_socketpair(int d, int type, int protocol, int sv[2]);

void __wrap_openlog(const char *ident, int option, int facility);
void __wrap_closelog(void);

typedef void (*sighandler_t)(int);

sighandler_t __wrap_signal(int signum, sighandler_t handler);
int __wrap_sigaction(int signum,
                    const struct sigaction *act,
                    struct sigaction *oldact);
int __wrap_rt_sigaction(int signum,
                       const struct sigaction *act,
                       struct sigaction *oldact);
//int __wrap_sigvec(int sig, const struct sigvec *vec, struct sigvec *ovec);

int __wrap_sigblock(int mask);
int __wrap_sigsetmask(int mask);
int __wrap_siggetmask(void);
int __wrap_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int __wrap_rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int __wrap_pthread_sigmask(int how, const sigset_t *newmask, sigset_t *oldmask);
void *__wrap_pthread_getspecific(pthread_key_t key);

int __wrap_sigsuspend(const sigset_t *mask);
int __wrap_sighold(int sig);
int __wrap_sigignore(int sig);
int __wrap_sigpause(int sig);
int __wrap_sigrelse(int sig);
sighandler_t __wrap_sigset(int sig, sighandler_t disp);

int __wrap_sigwait(const sigset_t *set, int *sig);
int __wrap_sigwaitinfo(const sigset_t *set, siginfo_t *info);
int __wrap_sigtimedwait(const sigset_t *set,
                       siginfo_t *info,
                       const struct timespec *timeout);

long __wrap_syscall(long sys_num);

int __wrap_pthread_create(pthread_t *thread,
                         const pthread_attr_t *attr,
                         void *(*start_routine)(void *),
                         void *arg);
void __wrap_pthread_exit(void *retval);
int __wrap_pthread_tryjoin_np(pthread_t thread, void **retval);
int __wrap_pthread_timedjoin_np(pthread_t thread,
                               void **retval,
                               const struct timespec *abstime);

int __wrap_xstat(int vers, const char *path, struct stat *buf);
//int __wrap_xstat64(int vers, const char *path, struct stat64 *buf);
int __wrap_lxstat(int vers, const char *path, struct stat *buf);
//int __wrap_lxstat64(int vers, const char *path, struct stat64 *buf);
ssize_t __wrap_readlink(const char *path, char *buf, size_t bufsiz);
void *__wrap_dlsym(void *handle, const char *symbol);

void *__wrap_dlopen(const char *filename, int flag);
int __wrap_dlclose(void *handle);

void *__wrap_calloc(size_t nmemb, size_t size);
void *__wrap_malloc(size_t size);
void __wrap_free(void *ptr);
void *__wrap_realloc(void *ptr, size_t size);
void *__wrap___libc_memalign(size_t boundary, size_t size);
void *__wrap_mmap(void *addr,
                 size_t length,
                 int prot,
                 int flags,
                 int fd,
                 off_t offset);
void *__wrap_mmap64(void *addr,
                   size_t length,
                   int prot,
                   int flags,
                   int fd,
                   __off64_t offset);
void *__wrap_mremap(void *old_address,
                   size_t old_size,
                   size_t new_size,
                   int flags);

int __wrap_munmap(void *addr, size_t length);

ssize_t __wrap_read(int fd, void *buf, size_t count);
ssize_t __wrap_write(int fd, const void *buf, size_t count);
int __wrap_select(int nfds,
                 fd_set *readfds,
                 fd_set *writefds,
                 fd_set *exceptfds,
                 struct timeval *timeout);
off_t __wrap_lseek(int fd, off_t offset, int whence);
int __wrap_unlink(const char *pathname);

int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex);
int __wrap_pthread_mutex_trylock(pthread_mutex_t *mutex);
int __wrap_pthread_mutex_unlock(pthread_mutex_t *mutex);
int __wrap_pthread_rwlock_unlock(pthread_rwlock_t *rwlock);
int __wrap_pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);
int __wrap_pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock);
int __wrap_pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);
int __wrap_pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock);

int __wrap_pthread_cond_broadcast(pthread_cond_t *cond);
int __wrap_pthread_cond_destroy(pthread_cond_t *cond);
int __wrap_pthread_cond_init(pthread_cond_t *cond,
                            const pthread_condattr_t *attr);
int __wrap_pthread_cond_signal(pthread_cond_t *cond);
int __wrap_pthread_cond_timedwait(pthread_cond_t *cond,
                                 pthread_mutex_t *mutex,
                                 const struct timespec *abstime);
int __wrap_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout);

int __wrap_waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
pid_t __wrap_wait4(pid_t pid,
                  int* status,
                  int options,
                  struct rusage *rusage);

int __wrap_shmget(int key, size_t size, int shmflg);
void *__wrap_shmat(int shmid, const void *shmaddr, int shmflg);
int __wrap_shmdt(const void *shmaddr);
int __wrap_shmctl(int shmid, int cmd, struct shmid_ds *buf);
int __wrap_semget(key_t key, int nsems, int semflg);
int __wrap_semop(int semid, struct sembuf *sops, size_t nsops);
int __wrap_semtimedop(int semid,
                     struct sembuf *sops,
                     size_t nsops,
                     const struct timespec *timeout);
int __wrap_semctl(int semid, int semnum, int cmd);

int __wrap_msgget(key_t key, int msgflg);
int __wrap_msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
ssize_t __wrap_msgrcv(int msqid,
                     void *msgp,
                     size_t msgsz,
                     long msgtyp,
                     int msgflg);
int __wrap_msgctl(int msqid, int cmd, struct msqid_ds *buf);


mqd_t __wrap_mq_open(const char *name,
                    int oflag,
                    mode_t mode,
                    struct mq_attr *attr);
int __wrap_mq_close(mqd_t mqdes);
int __wrap_mq_notify(mqd_t mqdes, const struct sigevent *sevp);
ssize_t __wrap_mq_timedreceive(mqd_t mqdes,
                              char *msg_ptr,
                              size_t msg_len,
                              unsigned int *msg_prio,
                              const struct timespec *abs_timeout);
int __wrap_mq_timedsend(mqd_t mqdes,
                       const char *msg_ptr,
                       size_t msg_len,
                       unsigned int msg_prio,
                       const struct timespec *abs_timeout);
size_t __wrap_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t __wrap_fwrite(const void *ptr, size_t size, size_t nmemb,
            FILE *stream);
int __wrap_daemon(int nochdir, int noclose);
pid_t __wrap_vfork();
int __wrap_execve(const char *filename, char *const argv[], char *const envp[]);
int __wrap_execv(const char *path, char *const argv[]);
int __wrap_execvp(const char *filename, char *const argv[]);
int __wrap_execvpe(const char *filename, char *const argv[], char *const envp[]);
int __wrap_fexecve(int fd, char *const argv[], char *const envp[]);
/*
int __wrap_execl(const char *path, const char *arg, ...);
int __wrap_execlp(const char *file, const char *arg, ...);
int __wrap_execle(const char *path, const char *arg, ...);
*/
int __wrap_system(const char *line);
int __wrap_pipe(int fds[2]);
int __wrap_pipe2(int fds[2], int flags);
pid_t __wrap_wait(int* stat_loc);
pid_t __wrap_waitpid(pid_t pid, int *stat_loc, int options);
pid_t __wrap_wait3(int* status, int options, struct rusage *rusage);
pid_t __wrap_wait4(pid_t pid, int* status, int options, struct rusage *rusage);
/*
int __wrap___clone2(int (*fn)(void *arg),
                void *child_stack,
                int flags,
                void *arg,
                int *parent_tidptr,
                struct user_desc *newtls,
                int *child_tidptr);
int __wrap_sigvec(int sig, const struct sigvec *vec, struct sigvec *ovec);
*/
int __wrap___sigpause(int __sig_or_mask, int __is_sig);
//int __wrap_ioctl(int fd, unsigned long request, ...);
pid_t __wrap_getpid(void);
pid_t __wrap_getppid(void);
int __wrap_kill(pid_t pid, int sig);
pid_t __wrap_tcgetpgrp(int fd);
int __wrap_tcsetpgrp(int fd, pid_t pgrp);
int __wrap_setpgid(pid_t pid, pid_t pgid);
pid_t __wrap_getpgid(pid_t pid);
//pid_t __wrap_getpgrp(void);
pid_t __wrap_getpgrp(pid_t pid);
//int __wrap_setpgrp(void);
int __wrap_setpgrp(pid_t pid, pid_t pgid);
pid_t __wrap_getsid(pid_t pid);
pid_t __wrap_setsid(void);
int __wrap_setgid(gid_t gid);
int __wrap_setuid(uid_t uid);
uid_t __wrap_getuid(void);
uid_t __wrap_geteuid(void);
int __wrap_setenv(const char *name, const char *value, int overwrite);
int __wrap_unsetenv(const char *name);
char * __wrap_realpath(const char *path, char *resolved_path);
int __wrap_access(const char *path, int mode);
int __wrap_clock_getcpuclockid(pid_t pid, clockid_t *clock_id);
int __wrap_timer_create(clockid_t clockid, struct sigevent *sevp,
                       timer_t *timerid);
int __wrap_timer_delete(timer_t timerid);
int __wrap_timer_settime(timer_t timerid,
             int flags,
             const struct itimerspec *new_value,
             struct itimerspec *old_value);
int __wrap_timer_gettime(timer_t timerid, struct itimerspec *curr_value);
int __wrap_timer_getoverrun(timer_t timerid);
int __wrap_pthread_getcpuclockid(pthread_t thread, clockid_t *clock_id);
int __wrap_clock_getres(clockid_t clk_id, struct timespec *res);
int __wrap_clock_gettime(clockid_t clk_id, struct timespec *tp);
int __wrap_clock_settime(clockid_t clk_id, const struct timespec *tp);
int __wrap_clock_nanosleep(clockid_t clock_id,
               int flags,
               const struct timespec *request,
               struct timespec *remain);
ssize_t __wrap_process_vm_readv(pid_t pid,
                       const struct iovec *local_iov,
                       unsigned long liovcnt,
                       const struct iovec *remote_iov,
                       unsigned long riovcnt,
                       unsigned long flags);
ssize_t __wrap_process_vm_writev(pid_t pid,
                        const struct iovec *local_iov,
                        unsigned long liovcnt,
                        const struct iovec *remote_iov,
                        unsigned long riovcnt,
                        unsigned long flags);
pid_t __wrap_tcgetsid(int fd);
long __wrap_ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
int __wrap_sched_setaffinity(pid_t pid, size_t cpusetsize,
                            const cpu_set_t *mask);
int __wrap_sched_getaffinity(pid_t pid, size_t cpusetsize,
                    cpu_set_t *mask);
int __wrap_sched_setscheduler(pid_t pid, int policy,
                    const struct sched_param *param);
int __wrap_sched_getscheduler(pid_t pid);
int __wrap_sched_setparam(pid_t pid, const struct sched_param *param);
int __wrap_sched_getparam(pid_t pid, struct sched_param *param);
/*
int __wrap_getaddrinfo(const char *node,
           const char *service,
           const struct addrinfo *hints,
           struct addrinfo **res);
*/
int __wrap_getnameinfo(const struct sockaddr *sa,
           socklen_t salen,
           char *host,
           size_t hostlen,
           char *serv,
           size_t servlen,
           int flags);
struct hostent * __wrap_gethostbyname(const char *name);
struct hostent * __wrap_gethostbyaddr(const void *addr, socklen_t len, int type);
int __wrap___poll_chk(struct pollfd *fds, nfds_t nfds, int timeout, size_t fdslen);
/*
int __wrap_pselect(int nfds,
       fd_set *readfds,
       fd_set *writefds,
       fd_set *exceptfds,
       const sigset_t *sigmask);
*/
int __wrap_signalfd(int fd, const sigset_t *mask, int flags);
int __wrap_eventfd(unsigned int initval, int flags);
int __wrap_epoll_create(int size);
int __wrap_epoll_create1(int flags);
/*
int __wrap_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

int __wrap_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
*/
int __wrap_inotify_init(void);
int __wrap_inotify_init1(int flags);
int __wrap_inotify_add_watch(int fd, const char *pathname, uint32_t mask);
int __wrap_inotify_rm_watch(int fd, int wd);
FILE * __wrap_tmpfile();
int __wrap_mkostemp(char *template, int flags);
int __wrap_mkstemps(char *template, int suffixlen);
int __wrap_mkostemps(char *template, int suffixlen, int flags);
int __wrap_creat(const char *path, mode_t mode);
int __wrap_creat64(const char *path, mode_t mode);
char * __wrap_ttyname(int fd);
int __wrap_fseek(FILE *stream, long offset, int whence);
long __wrap_ftell(FILE *stream);
void __wrap_rewind(FILE *stream);
int __wrap_fgetpos(FILE *stream, fpos_t *pos);
int __wrap_fsetpos(FILE *stream, const fpos_t *pos);
FILE *__wrap_fdopen(int fd, const char *mode);
FILE *__wrap_freopen(const char *pathname, const char *mode, FILE *stream);

///////////////////////////////////////////////////////////////////////////////////////////
/************************************Real calls***********************************************/
///////////////////////////////////////////////////////////////////////////////////////////


int __real_socket(int domain, int type, int protocol);
int __real_connect(int sockfd,
                 const struct sockaddr *serv_addr,
                 socklen_t addrlen);
int __real_bind(int sockfd, const struct  sockaddr *my_addr, socklen_t addrlen);
int __real_listen(int sockfd, int backlog);
int __real_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int __real_accept4(int sockfd,
                 struct sockaddr *addr,
                 socklen_t *addrlen,
                 int flags);
int __real_setsockopt(int s,
                    int level,
                    int optname,
                    const void *optval,
                    socklen_t optlen);
int __real_getsockopt(int s,
                    int level,
                    int optname,
                    void *optval,
                    socklen_t *optlen);

int __real_fexecve(int fd, char *const argv[], char *const envp[]);
int __real_execve(const char *filename, char *const argv[], char *const envp[]);
int __real_execv(const char *path, char *const argv[]);
int __real_execvp(const char *file, char *const argv[]);
int __real_execvpe(const char *file, char *const argv[], char *const envp[]);


int __real_system(const char *cmd);
FILE *__real_popen(const char *command, const char *mode);
int __real_pclose(FILE *fp);

pid_t __real_fork();
int __real_clone(int (*fn)(void *arg),
               void *child_stack,
               int flags,
               void *arg,
               int *parent_tidptr,
               void *newtls,
               int *child_tidptr);

int __real_open(const char *pathname, int flags);
int __real_open64(const char *pathname, int flags);
FILE *__real_fopen(const char *path, const char *mode);
FILE *__real_fopen64(const char *path, const char *mode);
int __real_openat(int dirfd, const char *pathname, int flags, mode_t mode);
int __real_openat64(int dirfd, const char *pathname, int flags, mode_t mode);
DIR *__real_opendir(const char *name);
int __real_mkstemp(char *ttemplate);
int __real_close(int fd);
int __real_fclose(FILE *fp);
int __real_closedir(DIR *dir);
void __real_exit(int status);
int __real_dup(int oldfd);
int __real_dup2(int oldfd, int newfd);
int __real_dup3(int oldfd, int newfd, int flags);
int __real_fcntl(int fd, int cmd, void *arg);

int __real_ttyname_r(int fd, char *buf, size_t buflen);
int __real_ptsname_r(int fd, char *buf, size_t buflen);
int __real_getpt(void);
int __real_posix_openpt(int flags);

int __real_socketpair(int d, int type, int protocol, int sv[2]);

void __real_openlog(const char *ident, int option, int facility);
void __real_closelog(void);


sighandler_t __real_signal(int signum, sighandler_t handler);
int __real_sigaction(int signum,
                   const struct sigaction *act,
                   struct sigaction *oldact);
int __real_rt_sigaction(int signum,
                      const struct sigaction *act,
                      struct sigaction *oldact);
//int __real_sigvec(int sig, const struct sigvec *vec, struct sigvec *ovec);

int __real_sigblock(int mask);
int __real_sigsetmask(int mask);
int __real_siggetmask(void);
int __real_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int __real_rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int __real_pthread_sigmask(int how, const sigset_t *newmask, sigset_t *oldmask);
void *__real_pthread_getspecific(pthread_key_t key);

int __real_sigsuspend(const sigset_t *mask);
int __real_sighold(int sig);
int __real_sigignore(int sig);
int __real__sigpause(int __sig_or_mask, int __is_sig);
int __real_sigpause(int sig);
int __real_sigrelse(int sig);
sighandler_t __real_sigset(int sig, sighandler_t disp);

int __real_sigwait(const sigset_t *set, int *sig);
int __real_sigwaitinfo(const sigset_t *set, siginfo_t *info);
int __real_sigtimedwait(const sigset_t *set,
                      siginfo_t *info,
                      const struct timespec *timeout);

long __real_syscall(long sys_num);

int __real_pthread_create(pthread_t *thread,
                        const pthread_attr_t *attr,
                        void *(*start_routine)(void *),
                        void *arg);
void __real_pthread_exit(void *retval);

int __real_pthread_tryjoin_np(pthread_t thread, void **retval);
int __real_pthread_timedjoin_np(pthread_t thread,
                              void **retval,
                              const struct timespec *abstime);

int __real_xstat(int vers, const char *path, struct stat *buf);
//int __real_xstat64(int vers, const char *path, struct stat64 *buf);
int __real_lxstat(int vers, const char *path, struct stat *buf);
//int __real_lxstat64(int vers, const char *path, struct stat64 *buf);
ssize_t __real_readlink(const char *path, char *buf, size_t bufsiz);
void *__real_dlsym(void *handle, const char *symbol);

void *__real_dlopen(const char *filename, int flag);
int __real_dlclose(void *handle);

void *__real_calloc(size_t nmemb, size_t size);
void *__real_malloc(size_t size);
void __real_free(void *ptr);
void *__real_realloc(void *ptr, size_t size);
void *__real___libc_memalign(size_t boundary, size_t size);
void *__real_mmap(void *addr,
                size_t length,
                int prot,
                int flags,
                int fd,
                off_t offset);
void *__real_mmap64(void *addr,
                  size_t length,
                  int prot,
                  int flags,
                  int fd,
                  __off64_t offset);
void *__real_mremap(void *old_address,
                  size_t old_size,
                  size_t new_size,
                  int flags,
                  ... /* void *new_address */);

int __real_munmap(void *addr, size_t length);

ssize_t __real_read(int fd, void *buf, size_t count);
ssize_t __real_write(int fd, const void *buf, size_t count);
int __real_select(int nfds,
                fd_set *readfds,
                fd_set *writefds,
                fd_set *exceptfds,
                struct timeval *timeout);
off_t __real_lseek(int fd, off_t offset, int whence);
int __real_unlink(const char *pathname);

int __real_pthread_mutex_lock(pthread_mutex_t *mutex);
int __real_pthread_mutex_trylock(pthread_mutex_t *mutex);
int __real_pthread_mutex_unlock(pthread_mutex_t *mutex);
int __real_pthread_rwlock_unlock(pthread_rwlock_t *rwlock);
int __real_pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);
int __real_pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock);
int __real_pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);
int __real_pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock);

int __real_pthread_cond_broadcast(pthread_cond_t *cond);
int __real_pthread_cond_destroy(pthread_cond_t *cond);
int __real_pthread_cond_init(pthread_cond_t *cond,
                           const pthread_condattr_t *attr);
int __real_pthread_cond_signal(pthread_cond_t *cond);
int __real_pthread_cond_timedwait(pthread_cond_t *cond,
                                pthread_mutex_t *mutex,
                                const struct timespec *abstime);
int __real_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);

int __real_poll(struct pollfd *fds, nfds_t nfds, int timeout);

int __real_waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
pid_t __real_wait4(pid_t pid,
                 int *status,
                 int options,
                 struct rusage *rusage);

int __real_shmget(int key, size_t size, int shmflg);
void *__real_shmat(int shmid, const void *shmaddr, int shmflg);
int __real_shmdt(const void *shmaddr);
int __real_shmctl(int shmid, int cmd, struct shmid_ds *buf);
int __real_semget(key_t key, int nsems, int semflg);
int __real_semop(int semid, struct sembuf *sops, size_t nsops);
int __real_semtimedop(int semid,
                    struct sembuf *sops,
                    size_t nsops,
                    const struct timespec *timeout);
int __real_semctl(int semid, int semnum, int cmd);

int __real_msgget(key_t key, int msgflg);
int __real_msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
ssize_t __real_msgrcv(int msqid,
                    void *msgp,
                    size_t msgsz,
                    long msgtyp,
                    int msgflg);
int __real_msgctl(int msqid, int cmd, struct msqid_ds *buf);
mqd_t __real_mq_open(const char *name,
                   int oflag,
                   mode_t mode,
                   struct mq_attr *attr);
int __real_mq_close(mqd_t mqdes);
int __real_mq_notify(mqd_t mqdes, const struct sigevent *sevp);
ssize_t __real_mq_timedreceive(mqd_t mqdes,
                             char *msg_ptr,
                             size_t msg_len,
                             unsigned int *msg_prio,
                             const struct timespec *abs_timeout);
int __real_mq_timedsend(mqd_t mqdes,
                      const char *msg_ptr,
                      size_t msg_len,
                      unsigned int msg_prio,
                      const struct timespec *abs_timeout);
size_t __real_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t __real_fwrite(const void *ptr, size_t size, size_t nmemb,
             FILE *stream);
int __real_daemon(int nochdir, int noclose);
pid_t __real_vfork();
int __real_execve(const char *filename, char *const argv[], char *const envp[]);
int __real_execv(const char *path, char *const argv[]);
int __real_execvp(const char *filename, char *const argv[]);
int __real_execvpe(const char *filename, char *const argv[], char *const envp[]);
int __real_fexecve(int fd, char *const argv[], char *const envp[]);
/*
int __real_execl(const char *path, const char *arg, ...);

int __real_execlp(const char *file, const char *arg, ...);

int __real_execle(const char *path, const char *arg, ...);
*/
int __real_system(const char *line);
int __real_pipe(int fds[2]);
int __real_pipe2(int fds[2], int flags);
pid_t __real_wait(int* stat_loc);
pid_t __real_waitpid(pid_t pid, int *stat_loc, int options);
pid_t __real_wait3(int* status, int options, struct rusage *rusage);
pid_t __real_wait4(pid_t pid, int* status, int options, struct rusage *rusage);
/*
int __real___clone2(int (*fn)(void *arg),
                 void *child_stack,
                 int flags,
                 void *arg,
                 int *parent_tidptr,
                 struct user_desc *newtls,
                 int *child_tidptr);

int __real_sigvec(int sig, const struct sigvec *vec, struct sigvec *ovec);
*/
int __real___sigpause(int __sig_or_mask, int __is_sig);
//int __real_ioctl(int fd, unsigned long request, ...);
pid_t __real_getpid(void);
pid_t __real_getppid(void);
int __real_kill(pid_t pid, int sig);
pid_t __real_tcgetpgrp(int fd);
int __real_tcsetpgrp(int fd, pid_t pgrp);
int __real_setpgid(pid_t pid, pid_t pgid);
pid_t __real_getpgid(pid_t pid);
//pid_t __real_getpgrp(void);
pid_t __real_getpgrp(pid_t pid);
//int __real_setpgrp(void);
int __real_setpgrp(pid_t pid, pid_t pgid);
pid_t __real_getsid(pid_t pid);
pid_t __real_setsid(void);
int __real_setgid(gid_t gid);
int __real_setuid(uid_t uid);
uid_t __real_getuid(void);
uid_t __real_geteuid(void);
int __real_setenv(const char *name, const char *value, int overwrite);
int __real_unsetenv(const char *name);
char * __real_realpath(const char *path, char *resolved_path);
int __real_access(const char *path, int mode);
int __real_clock_getcpuclockid(pid_t pid, clockid_t *clock_id);
int __real_timer_create(clockid_t clockid, struct sigevent *sevp,
                        timer_t *timerid);
int __real_timer_delete(timer_t timerid);
int __real_timer_settime(timer_t timerid,
              int flags,
              const struct itimerspec *new_value,
              struct itimerspec *old_value);
int __real_timer_gettime(timer_t timerid, struct itimerspec *curr_value);
int __real_timer_getoverrun(timer_t timerid);
int __real_pthread_getcpuclockid(pthread_t thread, clockid_t *clock_id);
int __real_clock_getres(clockid_t clk_id, struct timespec *res);
int __real_clock_gettime(clockid_t clk_id, struct timespec *tp);
int __real_clock_settime(clockid_t clk_id, const struct timespec *tp);
int __real_clock_nanosleep(clockid_t clock_id,
                int flags,
                const struct timespec *request,
                struct timespec *remain);
ssize_t __real_process_vm_readv(pid_t pid,
                        const struct iovec *local_iov,
                        unsigned long liovcnt,
                        const struct iovec *remote_iov,
                        unsigned long riovcnt,
                        unsigned long flags);
ssize_t __real_process_vm_writev(pid_t pid,
                         const struct iovec *local_iov,
                         unsigned long liovcnt,
                         const struct iovec *remote_iov,
                         unsigned long riovcnt,
                         unsigned long flags);
pid_t __real_tcgetsid(int fd);
long __real_ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
int __real_sched_setaffinity(pid_t pid, size_t cpusetsize,
                             const cpu_set_t *mask);
int __real_sched_getaffinity(pid_t pid, size_t cpusetsize,
                     cpu_set_t *mask);
int __real_sched_setscheduler(pid_t pid, int policy,
                     const struct sched_param *param);
int __real_sched_getscheduler(pid_t pid);
int __real_sched_setparam(pid_t pid, const struct sched_param *param);
int __real_sched_getparam(pid_t pid, struct sched_param *param);
/*
int __real_getaddrinfo(const char *node,
            const char *service,
            const struct addrinfo *hints,
            struct addrinfo **res);
*/
int __real_getnameinfo(const struct sockaddr *sa,
            socklen_t salen,
            char *host,
            size_t hostlen,
            char *serv,
            size_t servlen,
            int flags);
struct hostent * __real_gethostbyname(const char *name);
struct hostent * __real_gethostbyaddr(const void *addr, socklen_t len, int type);
int __real___poll_chk(struct pollfd *fds, nfds_t nfds, int timeout, size_t fdslen);
/*
int __real_pselect(int nfds,
        fd_set *readfds,
        fd_set *writefds,
        fd_set *exceptfds,
        const struct timespec *timeout,
        const sigset_t *sigmask);
*/
int __real_signalfd(int fd, const sigset_t *mask, int flags);
int __real_eventfd(unsigned int initval, int flags);
int __real_epoll_create(int size);
int __real_epoll_create1(int flags);
/*
int __real_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

int __real_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
*/
int __real_inotify_init(void);
int __real_inotify_init1(int flags);
int __real_inotify_add_watch(int fd, const char *pathname, uint32_t mask);
int __real_inotify_rm_watch(int fd, int wd);
FILE * __real_tmpfile();
int __real_mkostemp(char *template, int flags);
int __real_mkstemps(char *template, int suffixlen);
int __real_mkostemps(char *template, int suffixlen, int flags);
int __real_creat(const char *path, mode_t mode);
int __real_creat64(const char *path, mode_t mode);
char * __real_ttyname(int fd);
int __real_ttyname_r(int fd, char *buf, size_t buflen);
int __real_fseek(FILE *stream, long offset, int whence);
long __real_ftell(FILE *stream);
void __real_rewind(FILE *stream);
int __real_fgetpos(FILE *stream, fpos_t *pos);
int __real_fsetpos(FILE *stream, const fpos_t *pos);
FILE *__real_fdopen(int fd, const char *mode);
FILE *__real_freopen(const char *pathname, const char *mode, FILE *stream);
#endif
