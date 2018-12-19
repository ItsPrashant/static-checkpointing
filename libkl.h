#ifndef LIB_KL_H
#define LIB_KL_H
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
#endif
