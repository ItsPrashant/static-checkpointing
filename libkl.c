#include <stdio.h>
#include <ucontext.h>
#include <asm/prctl.h>
#include <sys/prctl.h>

#include "libkl.h"

//#include "kernel-loader.h"
unsigned long long fsValue1,fsValue2;
void *soPtr;
void* (*mydlsym)(void*,char*);
int dmtcp_loaded=0;
int get_fs_application()
{
  if(arch_prctl(ARCH_GET_FS,&fsValue1)==-1){
    return -1;
  }
  return 0;
}
int get_fs_dmtcp()
{
  if(arch_prctl(ARCH_GET_FS,&fsValue2)==-1){
    return -1;
  }
  return 0;
}
int set_fs_application()
{
  if(arch_prctl(ARCH_SET_FS,fsValue1)==-1){
    return -1;
  }
  return 0;
}

int set_fs_dmtcp()
{
  if(arch_prctl(ARCH_SET_FS,fsValue2)==-1){
    return -1;
  }
  return 0;
}
__attribute__((constructor))
void loader(int argc,const char *argv[])
{
  ucontext_t context;
  int flag=0;
  get_fs_application();
  if(getcontext(&context)==-1)
	{
		printf("getcontext Failed\n");
	}
  FILE *fp;
  if (flag==0) {
    flag=1;
    fp=__real_fopen("context.bin","wb");

    if (__real_fwrite(&context,sizeof(ucontext_t),1,fp)==0) {
      printf("Write Failed\n");
    }

    if (__real_fclose(fp)!=0) {
      printf("Unable to close file\n");
    }
    printf("Going into rtld\n");
    runRtld();
  }
  get_fs_dmtcp();
  set_fs_application();
  fp=__real_fopen("symbolPointer","rb");
  //int fp=open()
  if (fp==NULL) {
    printf("Error opening pointer file\n");
    exit(-1);
  }
  void *ptr;
  if(__real_fread(&soPtr,sizeof(void*),1,fp)==0) {
    fprintf(stderr, "Error reading file\n");
  }
  if(__real_fread(&ptr,sizeof(void*),1,fp)==0) {
    fprintf(stderr, "Error reading file\n");
  }
  //void *ptr2;
  //fread(&ptr2,sizeof(void*),1,fp);
  if(__real_fclose(fp)!=0){
    fprintf(stderr, "Error closing file\n" );
  }
  mydlsym=ptr;
  dmtcp_loaded=1;
  printf("dmtcp_loaded.................\n");
  /*fp=__real_fopen("context.bin","rb");

  if (fread(&context,sizeof(ucontext_t),1,fp)==0) {
    printf("Read Failed\n");
  }
  if (__real_fclose(fp)!=0) {
    printf("Unable to close file\n");
  }
  set_fs_dmtcp();
  setcontext(&context);
  */
}



int __wrap_socket(int domain, int type, int protocol) {
   static int (*fncPtr)(int domain, int type, int protocol);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"socket");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","socket");  \
            abort();
       }
    }

   ret=(*fncPtr)(domain, type, protocol);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_socket(domain, type, protocol);
  }
   return ret;

}

int __wrap_connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen) {
   static int (*fncPtr)(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"connect");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","connect");  \
            abort();
       }
    }

   ret=(*fncPtr)(sockfd, serv_addr, addrlen);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_connect(sockfd, serv_addr, addrlen);
  }
   return ret;

}

int __wrap_bind(int sockfd, const struct  sockaddr *my_addr, socklen_t addrlen) {
   static int (*fncPtr)(int sockfd, const struct  sockaddr *my_addr, socklen_t addrlen);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"bind");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","bind");  \
            abort();
       }
    }

   ret=(*fncPtr)(sockfd, my_addr, addrlen);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_bind(sockfd, my_addr, addrlen);
  }
   return ret;

}

int __wrap_listen(int sockfd, int backlog) {
   static int (*fncPtr)(int sockfd, int backlog);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"listen");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","listen");  \
            abort();
       }
    }

   ret=(*fncPtr)(sockfd, backlog);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_listen(sockfd, backlog);
  }
   return ret;

}

int __wrap_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
   static int (*fncPtr)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"accept");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","accept");  \
            abort();
       }
    }

   ret=(*fncPtr)(sockfd, addr, addrlen);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_accept(sockfd, addr, addrlen);
  }
   return ret;

}

int __wrap_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
   static int (*fncPtr)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"accept4");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","accept4");  \
            abort();
       }
    }

   ret=(*fncPtr)(sockfd, addr, addrlen, flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_accept4(sockfd, addr, addrlen, flags);
  }
   return ret;

}

int __wrap_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen) {
   static int (*fncPtr)(int s, int level, int optname, const void *optval, socklen_t optlen);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"setsockopt");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","setsockopt");  \
            abort();
       }
    }

   ret=(*fncPtr)(s, level, optname, optval, optlen);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_setsockopt(s, level, optname, optval, optlen);
  }
   return ret;

}

int __wrap_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen) {
   static int (*fncPtr)(int s, int level, int optname, void *optval, socklen_t *optlen);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"getsockopt");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","getsockopt");  \
            abort();
       }
    }

   ret=(*fncPtr)(s, level, optname, optval, optlen);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_getsockopt(s, level, optname, optval, optlen);
  }
   return ret;

}

int __wrap_fexecve(int fd, char *const argv[], char *const envp[]) {
   static int (*fncPtr)(int fd, char *const argv[], char *const envp[]);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"fexecve");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","fexecve");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd, argv, envp);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_fexecve(fd, argv, envp);
  }
   return ret;

}

int __wrap_execve(const char *filename, char *const argv[], char *const envp[]) {
   static int (*fncPtr)(const char *filename, char *const argv[], char *const envp[]);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"execve");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","execve");  \
            abort();
       }
    }

   ret=(*fncPtr)(filename, argv, envp);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_execve(filename, argv, envp);
  }
   return ret;

}

int __wrap_execv(const char *path, char *const argv[]) {
   static int (*fncPtr)(const char *path, char *const argv[]);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"execv");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","execv");  \
            abort();
       }
    }

   ret=(*fncPtr)(path, argv);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_execv(path, argv);
  }
   return ret;

}

int __wrap_execvp(const char *file, char *const argv[]) {
   static int (*fncPtr)(const char *file, char *const argv[]);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"execvp");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","execvp");  \
            abort();
       }
    }

   ret=(*fncPtr)(file, argv);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_execvp(file, argv);
  }
   return ret;

}

int __wrap_execvpe(const char *file, char *const argv[], char *const envp[]) {
   static int (*fncPtr)(const char *file, char *const argv[], char *const envp[]);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"execvpe");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","execvpe");  \
            abort();
       }
    }

   ret=(*fncPtr)(file, argv, envp);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_execvpe(file, argv, envp);
  }
   return ret;

}

int __wrap_system(const char *cmd) {
   static int (*fncPtr)(const char *cmd);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"system");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","system");  \
            abort();
       }
    }

   ret=(*fncPtr)(cmd);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_system(cmd);
  }
   return ret;

}

FILE *__wrap_popen(const char *command, const char *mode) {
   static FILE * (*fncPtr)(const char *command, const char *mode);
   FILE * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"popen");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","popen");  \
            abort();
       }
    }

   ret=(*fncPtr)(command, mode);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_popen(command, mode);
  }
   return ret;

}

int __wrap_pclose(FILE *fp) {
   static int (*fncPtr)(FILE *fp);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pclose");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pclose");  \
            abort();
       }
    }

   ret=(*fncPtr)(fp);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pclose(fp);
  }
   return ret;

}

pid_t __wrap_fork() {
   static pid_t (*fncPtr)();
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"fork");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","fork");  \
            abort();
       }
    }

   ret=(*fncPtr)();
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_fork();
  }
   return ret;

}

int __wrap_open(const char *pathname, int flags) {
   static int (*fncPtr)(const char *pathname, int flags);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"open");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","open");  \
            abort();
       }
    }

   ret=(*fncPtr)(pathname, flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_open(pathname, flags);
  }
   return ret;

}

int __wrap_open64(const char *pathname, int flags) {
   static int (*fncPtr)(const char *pathname, int flags);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"open64");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","open64");  \
            abort();
       }
    }

   ret=(*fncPtr)(pathname, flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_open64(pathname, flags);
  }
   return ret;

}

FILE *__wrap_fopen(const char *path, const char *mode) {
   static FILE * (*fncPtr)(const char *path, const char *mode);
   FILE * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"fopen");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","fopen");  \
            abort();
       }
    }

   ret=(*fncPtr)(path, mode);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_fopen(path, mode);
  }
   return ret;

}

FILE *__wrap_fopen64(const char *path, const char *mode) {
   static FILE * (*fncPtr)(const char *path, const char *mode);
   FILE * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"fopen64");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","fopen64");  \
            abort();
       }
    }

   ret=(*fncPtr)(path, mode);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_fopen64(path, mode);
  }
   return ret;

}

int __wrap_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
   static int (*fncPtr)(int dirfd, const char *pathname, int flags, mode_t mode);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"openat");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","openat");  \
            abort();
       }
    }

   ret=(*fncPtr)(dirfd, pathname, flags, mode);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_openat(dirfd, pathname, flags, mode);
  }
   return ret;

}

int __wrap_openat64(int dirfd, const char *pathname, int flags, mode_t mode) {
   static int (*fncPtr)(int dirfd, const char *pathname, int flags, mode_t mode);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"openat64");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","openat64");  \
            abort();
       }
    }

   ret=(*fncPtr)(dirfd, pathname, flags, mode);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_openat64(dirfd, pathname, flags, mode);
  }
   return ret;

}

DIR *__wrap_opendir(const char *name) {
   static DIR * (*fncPtr)(const char *name);
   DIR * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"opendir");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","opendir");  \
            abort();
       }
    }

   ret=(*fncPtr)(name);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_opendir(name);
  }
   return ret;

}

int __wrap_mkstemp(char *ttemplate) {
   static int (*fncPtr)(char *ttemplate);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"mkstemp");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","mkstemp");  \
            abort();
       }
    }

   ret=(*fncPtr)(ttemplate);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_mkstemp(ttemplate);
  }
   return ret;

}

int __wrap_close(int fd) {
   static int (*fncPtr)(int fd);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"close");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","close");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_close(fd);
  }
   return ret;

}

int __wrap_fclose(FILE *fp) {
   static int (*fncPtr)(FILE *fp);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"fclose");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","fclose");  \
            abort();
       }
    }

   ret=(*fncPtr)(fp);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_fclose(fp);
  }
   return ret;

}

int __wrap_closedir(DIR *dir) {
   static int (*fncPtr)(DIR *dir);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"closedir");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","closedir");  \
            abort();
       }
    }

   ret=(*fncPtr)(dir);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_closedir(dir);
  }
   return ret;

}

void __wrap_exit(int status) {
   static void (*fncPtr)(int status);
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"exit");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","exit");  \
            abort();
       }
    }

   (*fncPtr)(status);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     __real_exit(status);
  }
}

int __wrap_dup(int oldfd) {
   static int (*fncPtr)(int oldfd);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"dup");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","dup");  \
            abort();
       }
    }

   ret=(*fncPtr)(oldfd);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_dup(oldfd);
  }
   return ret;

}

int __wrap_dup2(int oldfd, int newfd) {
   static int (*fncPtr)(int oldfd, int newfd);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"dup2");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","dup2");  \
            abort();
       }
    }

   ret=(*fncPtr)(oldfd, newfd);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_dup2(oldfd, newfd);
  }
   return ret;

}

int __wrap_dup3(int oldfd, int newfd, int flags) {
   static int (*fncPtr)(int oldfd, int newfd, int flags);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"dup3");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","dup3");  \
            abort();
       }
    }

   ret=(*fncPtr)(oldfd, newfd, flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_dup3(oldfd, newfd, flags);
  }
   return ret;

}

int __wrap_fcntl(int fd, int cmd, void *arg) {
   static int (*fncPtr)(int fd, int cmd, void *arg);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"fcntl");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","fcntl");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd, cmd, arg);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_fcntl(fd, cmd, arg);
  }
   return ret;

}

int __wrap_ttyname_r(int fd, char *buf, size_t buflen) {
   static int (*fncPtr)(int fd, char *buf, size_t buflen);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"ttyname_r");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","ttyname_r");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd, buf, buflen);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_ttyname_r(fd, buf, buflen);
  }
   return ret;

}

int __wrap_ptsname_r(int fd, char *buf, size_t buflen) {
   static int (*fncPtr)(int fd, char *buf, size_t buflen);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"ptsname_r");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","ptsname_r");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd, buf, buflen);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_ptsname_r(fd, buf, buflen);
  }
   return ret;

}

int __wrap_getpt() {
   static int (*fncPtr)();
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"getpt");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","getpt");  \
            abort();
       }
    }

   ret=(*fncPtr)();
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_getpt();
  }
   return ret;

}

int __wrap_posix_openpt(int flags) {
   static int (*fncPtr)(int flags);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"posix_openpt");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","posix_openpt");  \
            abort();
       }
    }

   ret=(*fncPtr)(flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_posix_openpt(flags);
  }
   return ret;

}

int __wrap_socketpair(int d, int type, int protocol, int sv[2]) {
   static int (*fncPtr)(int d, int type, int protocol, int sv[2]);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"socketpair");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","socketpair");  \
            abort();
       }
    }

   ret=(*fncPtr)(d, type, protocol, sv);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_socketpair(d, type, protocol, sv);
  }
   return ret;

}

void __wrap_openlog(const char *ident, int option, int facility) {
   static void (*fncPtr)(const char *ident, int option, int facility);
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"openlog");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","openlog");  \
            abort();
       }
    }

   (*fncPtr)(ident, option, facility);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     __real_openlog(ident, option, facility);
  }
}

void __wrap_closelog() {
   static void (*fncPtr)();
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"closelog");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","closelog");  \
            abort();
       }
    }

   (*fncPtr)();
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     __real_closelog();
  }
}

sighandler_t __wrap_signal(int signum, sighandler_t handler) {
   static sighandler_t (*fncPtr)(int signum, sighandler_t handler);
   sighandler_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"signal");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","signal");  \
            abort();
       }
    }

   ret=(*fncPtr)(signum, handler);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_signal(signum, handler);
  }
   return ret;

}

int __wrap_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
   static int (*fncPtr)(int signum, const struct sigaction *act, struct sigaction *oldact);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sigaction");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sigaction");  \
            abort();
       }
    }

   ret=(*fncPtr)(signum, act, oldact);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sigaction(signum, act, oldact);
  }
   return ret;

}

int __wrap_rt_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
   static int (*fncPtr)(int signum, const struct sigaction *act, struct sigaction *oldact);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"rt_sigaction");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","rt_sigaction");  \
            abort();
       }
    }

   ret=(*fncPtr)(signum, act, oldact);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     //ret=__real_rt_sigaction(signum, act, oldact);
     ret=-1;
  }
   return ret;

}

int __wrap_sigblock(int mask) {
   static int (*fncPtr)(int mask);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sigblock");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sigblock");  \
            abort();
       }
    }

   ret=(*fncPtr)(mask);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sigblock(mask);
  }
   return ret;

}

int __wrap_sigsetmask(int mask) {
   static int (*fncPtr)(int mask);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sigsetmask");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sigsetmask");  \
            abort();
       }
    }

   ret=(*fncPtr)(mask);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sigsetmask(mask);
  }
   return ret;

}

int __wrap_siggetmask() {
   static int (*fncPtr)();
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"siggetmask");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","siggetmask");  \
            abort();
       }
    }

   ret=(*fncPtr)();
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_siggetmask();
  }
   return ret;

}

int __wrap_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
   static int (*fncPtr)(int how, const sigset_t *set, sigset_t *oldset);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sigprocmask");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sigprocmask");  \
            abort();
       }
    }

   ret=(*fncPtr)(how, set, oldset);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sigprocmask(how, set, oldset);
  }
   return ret;

}

int __wrap_rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
   static int (*fncPtr)(int how, const sigset_t *set, sigset_t *oldset);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"rt_sigprocmask");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","rt_sigprocmask");  \
            abort();
       }
    }

   ret=(*fncPtr)(how, set, oldset);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
    // ret=__real_rt_sigprocmask(how, set, oldset);
    ret=-1;
  }
   return ret;

}

int __wrap_pthread_sigmask(int how, const sigset_t *newmask, sigset_t *oldmask) {
   static int (*fncPtr)(int how, const sigset_t *newmask, sigset_t *oldmask);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_sigmask");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_sigmask");  \
            abort();
       }
    }

   ret=(*fncPtr)(how, newmask, oldmask);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_sigmask(how, newmask, oldmask);
  }
   return ret;

}

void *__wrap_pthread_getspecific(pthread_key_t key) {
   static void * (*fncPtr)(pthread_key_t key);
   void * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_getspecific");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_getspecific");  \
            abort();
       }
    }

   ret=(*fncPtr)(key);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_getspecific(key);
  }
   return ret;

}

int __wrap_sigsuspend(const sigset_t *mask) {
   static int (*fncPtr)(const sigset_t *mask);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sigsuspend");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sigsuspend");  \
            abort();
       }
    }

   ret=(*fncPtr)(mask);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sigsuspend(mask);
  }
   return ret;

}

int __wrap_sighold(int sig) {
   static int (*fncPtr)(int sig);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sighold");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sighold");  \
            abort();
       }
    }

   ret=(*fncPtr)(sig);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sighold(sig);
  }
   return ret;

}

int __wrap_sigignore(int sig) {
   static int (*fncPtr)(int sig);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sigignore");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sigignore");  \
            abort();
       }
    }

   ret=(*fncPtr)(sig);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sigignore(sig);
  }
   return ret;

}


int __wrap_sigpause(int sig) {
   static int (*fncPtr)(int sig);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sigpause");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sigpause");  \
            abort();
       }
    }

   ret=(*fncPtr)(sig);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sigpause(sig);
  }
   return ret;

}

int __wrap_sigrelse(int sig) {
   static int (*fncPtr)(int sig);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sigrelse");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sigrelse");  \
            abort();
       }
    }

   ret=(*fncPtr)(sig);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sigrelse(sig);
  }
   return ret;

}

sighandler_t __wrap_sigset(int sig, sighandler_t disp) {
   static sighandler_t (*fncPtr)(int sig, sighandler_t disp);
   sighandler_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sigset");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sigset");  \
            abort();
       }
    }

   ret=(*fncPtr)(sig, disp);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sigset(sig, disp);
  }
   return ret;

}

int __wrap_sigwait(const sigset_t *set, int *sig) {
   static int (*fncPtr)(const sigset_t *set, int *sig);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sigwait");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sigwait");  \
            abort();
       }
    }

   ret=(*fncPtr)(set, sig);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sigwait(set, sig);
  }
   return ret;

}

int __wrap_sigwaitinfo(const sigset_t *set, siginfo_t *info) {
   static int (*fncPtr)(const sigset_t *set, siginfo_t *info);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sigwaitinfo");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sigwaitinfo");  \
            abort();
       }
    }

   ret=(*fncPtr)(set, info);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sigwaitinfo(set, info);
  }
   return ret;

}

int __wrap_sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout) {
   static int (*fncPtr)(const sigset_t *set, siginfo_t *info, const struct timespec *timeout);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sigtimedwait");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sigtimedwait");  \
            abort();
       }
    }

   ret=(*fncPtr)(set, info, timeout);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sigtimedwait(set, info, timeout);
  }
   return ret;

}

long __wrap_syscall(long sys_num) {
   static long (*fncPtr)(long sys_num);
   long ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"syscall");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","syscall");  \
            abort();
       }
    }

   ret=(*fncPtr)(sys_num);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_syscall(sys_num);
  }
   return ret;

}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
   static int (*fncPtr)(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_create");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_create");  \
            abort();
       }
    }

   ret=(*fncPtr)(thread, attr, start_routine, arg);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_create(thread, attr, start_routine, arg);
  }
   return ret;

}

void __wrap_pthread_exit(void *retval) {
  static void (*fncPtr)(void *retval);
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }
   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_exit");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_exit");  \
            abort();
       }
    }

   //(*fncPtr)(retval);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
   printf("Calling pthread_exit()\n");
     //__real_pthread_exit(retval);
  }

}

int __wrap_pthread_tryjoin_np(pthread_t thread, void **retval) {
   static int (*fncPtr)(pthread_t thread, void **retval);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_tryjoin_np");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_tryjoin_np");  \
            abort();
       }
    }

   ret=(*fncPtr)(thread, retval);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_tryjoin_np(thread, retval);
  }
   return ret;

}

int __wrap_pthread_timedjoin_np(pthread_t thread, void **retval, const struct timespec *abstime) {
   static int (*fncPtr)(pthread_t thread, void **retval, const struct timespec *abstime);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_timedjoin_np");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_timedjoin_np");  \
            abort();
       }
    }

   ret=(*fncPtr)(thread, retval, abstime);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_timedjoin_np(thread, retval, abstime);
  }
   return ret;

}

int __wrap_xstat(int vers, const char *path, struct stat *buf) {
   static int (*fncPtr)(int vers, const char *path, struct stat *buf);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"xstat");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","xstat");  \
            abort();
       }
    }

   ret=(*fncPtr)(vers, path, buf);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret-1;
  }
   return ret;

}

int __wrap_lxstat(int vers, const char *path, struct stat *buf) {
   static int (*fncPtr)(int vers, const char *path, struct stat *buf);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"lxstat");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","lxstat");  \
            abort();
       }
    }

   ret=(*fncPtr)(vers, path, buf);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=-1;
  }
   return ret;

}

ssize_t __wrap_readlink(const char *path, char *buf, size_t bufsiz) {
   static ssize_t (*fncPtr)(const char *path, char *buf, size_t bufsiz);
   ssize_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"readlink");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","readlink");  \
            abort();
       }
    }

   ret=(*fncPtr)(path, buf, bufsiz);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_readlink(path, buf, bufsiz);
  }
   return ret;

}

void *__wrap_dlsym(void *handle, const char *symbol) {
   static void * (*fncPtr)(void *handle, const char *symbol);
   void * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"dlsym");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","dlsym");  \
            abort();
       }
    }

   ret=(*fncPtr)(handle, symbol);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_dlsym(handle, symbol);
  }
   return ret;

}

void *__wrap_dlopen(const char *filename, int flag) {
   static void * (*fncPtr)(const char *filename, int flag);
   void * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"dlopen");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","dlopen");  \
            abort();
       }
    }

   ret=(*fncPtr)(filename, flag);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_dlopen(filename, flag);
  }
   return ret;

}

int __wrap_dlclose(void *handle) {
   static int (*fncPtr)(void *handle);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"dlclose");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","dlclose");  \
            abort();
       }
    }

   ret=(*fncPtr)(handle);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_dlclose(handle);
  }
   return ret;

}

void *__wrap_calloc(size_t nmemb, size_t size) {
   static void * (*fncPtr)(size_t nmemb, size_t size);
   void * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"calloc");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","calloc");  \
            abort();
       }
    }

   ret=(*fncPtr)(nmemb, size);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_calloc(nmemb, size);
  }
   return ret;

}

void *__wrap_malloc(size_t size) {
   static void * (*fncPtr)(size_t size);
   void * ret;
 if(dmtcp_loaded==1) { //printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"malloc");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","malloc");  \
            abort();
       }
    }

   ret=(*fncPtr)(size);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ //printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_malloc(size);
  }
   return ret;

}

void __wrap_free(void *ptr) {
   static void (*fncPtr)(void *ptr);
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"free");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","free");  \
            abort();
       }
    }

   (*fncPtr)(ptr);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     __real_free(ptr);
  }
}

void *__wrap_realloc(void *ptr, size_t size) {
   static void * (*fncPtr)(void *ptr, size_t size);
   void * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"_realloc");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","_realloc");  \
            abort();
       }
    }

   ret=(*fncPtr)(ptr, size);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_realloc(ptr, size);
  }
   return ret;

}

void *__wrap___libc_memalign(size_t boundary, size_t size) {
   static void * (*fncPtr)(size_t boundary, size_t size);
   void * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"__libc_memalign");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","__libc_memalign");  \
            abort();
       }
    }

   ret=(*fncPtr)(boundary, size);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real___libc_memalign(boundary, size);
  }
   return ret;

}

void *__wrap_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
   static void * (*fncPtr)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
   void * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"mmap");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","mmap");  \
            abort();
       }
    }

   ret=(*fncPtr)(addr, length, prot, flags, fd, offset);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_mmap(addr, length, prot, flags, fd, offset);
  }
   return ret;

}

void *__wrap_mmap64(void *addr, size_t length, int prot, int flags, int fd, __off64_t offset) {
   static void * (*fncPtr)(void *addr, size_t length, int prot, int flags, int fd, __off64_t offset);
   void * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"mmap64");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","mmap64");  \
            abort();
       }
    }

   ret=(*fncPtr)(addr, length, prot, flags, fd, offset);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_mmap64(addr, length, prot, flags, fd, offset);
  }
   return ret;

}

void *__wrap_mremap(void *old_address, size_t old_size, size_t new_size, int flags) {
   static void * (*fncPtr)(void *old_address, size_t old_size, size_t new_size, int flags);
   void * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"mremap");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","mremap");  \
            abort();
       }
    }

   ret=(*fncPtr)(old_address, old_size, new_size, flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_mremap(old_address, old_size, new_size, flags);
  }
   return ret;

}

int __wrap_munmap(void *addr, size_t length) {
   static int (*fncPtr)(void *addr, size_t length);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"munmap");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","munmap");  \
            abort();
       }
    }

   ret=(*fncPtr)(addr, length);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_munmap(addr, length);
  }
   return ret;

}

ssize_t __wrap_read(int fd, void *buf, size_t count) {
   static ssize_t (*fncPtr)(int fd, void *buf, size_t count);
   ssize_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"read");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","read");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd, buf, count);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_read(fd, buf, count);
  }
   return ret;

}

ssize_t __wrap_write(int fd, const void *buf, size_t count) {
   static ssize_t (*fncPtr)(int fd, const void *buf, size_t count);
   ssize_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"write");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","write");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd, buf, count);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_write(fd, buf, count);
  }
   return ret;

}

int __wrap_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
   static int (*fncPtr)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"select");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","select");  \
            abort();
       }
    }

   ret=(*fncPtr)(nfds, readfds, writefds, exceptfds, timeout);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_select(nfds, readfds, writefds, exceptfds, timeout);
  }
   return ret;

}

off_t __wrap_lseek(int fd, off_t offset, int whence) {
   static off_t (*fncPtr)(int fd, off_t offset, int whence);
   off_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"lseek");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","lseek");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd, offset, whence);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_lseek(fd, offset, whence);
  }
   return ret;

}

int __wrap_unlink(const char *pathname) {
   static int (*fncPtr)(const char *pathname);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"unlink");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","unlink");  \
            abort();
       }
    }

   ret=(*fncPtr)(pathname);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_unlink(pathname);
  }
   return ret;

}

int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex) {
   static int (*fncPtr)(pthread_mutex_t *mutex);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_mutex_lock");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_mutex_lock");  \
            abort();
       }
    }

   ret=(*fncPtr)(mutex);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_mutex_lock(mutex);
  }
   return ret;

}

int __wrap_pthread_mutex_trylock(pthread_mutex_t *mutex) {
   static int (*fncPtr)(pthread_mutex_t *mutex);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_mutex_trylock");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_mutex_trylock");  \
            abort();
       }
    }

   ret=(*fncPtr)(mutex);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_mutex_trylock(mutex);
  }
   return ret;

}

int __wrap_pthread_mutex_unlock(pthread_mutex_t *mutex) {
   static int (*fncPtr)(pthread_mutex_t *mutex);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_mutex_unlock");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_mutex_unlock");  \
            abort();
       }
    }

   ret=(*fncPtr)(mutex);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_mutex_unlock(mutex);
  }
   return ret;

}

int __wrap_pthread_rwlock_unlock(pthread_rwlock_t *rwlock) {
   static int (*fncPtr)(pthread_rwlock_t *rwlock);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_rwlock_unlock");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_rwlock_unlock");  \
            abort();
       }
    }

   ret=(*fncPtr)(rwlock);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_rwlock_unlock(rwlock);
  }
   return ret;

}

int __wrap_pthread_rwlock_rdlock(pthread_rwlock_t *rwlock) {
   static int (*fncPtr)(pthread_rwlock_t *rwlock);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_rwlock_rdlock");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_rwlock_rdlock");  \
            abort();
       }
    }

   ret=(*fncPtr)(rwlock);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_rwlock_rdlock(rwlock);
  }
   return ret;

}

int __wrap_pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock) {
   static int (*fncPtr)(pthread_rwlock_t *rwlock);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_rwlock_tryrdlock");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_rwlock_tryrdlock");  \
            abort();
       }
    }

   ret=(*fncPtr)(rwlock);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_rwlock_tryrdlock(rwlock);
  }
   return ret;

}

int __wrap_pthread_rwlock_wrlock(pthread_rwlock_t *rwlock) {
   static int (*fncPtr)(pthread_rwlock_t *rwlock);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_rwlock_wrlock");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_rwlock_wrlock");  \
            abort();
       }
    }

   ret=(*fncPtr)(rwlock);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_rwlock_wrlock(rwlock);
  }
   return ret;

}

int __wrap_pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock) {
   static int (*fncPtr)(pthread_rwlock_t *rwlock);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_rwlock_trywrlock");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_rwlock_trywrlock");  \
            abort();
       }
    }

   ret=(*fncPtr)(rwlock);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_rwlock_trywrlock(rwlock);
  }
   return ret;

}

int __wrap_pthread_cond_broadcast(pthread_cond_t *cond) {
   static int (*fncPtr)(pthread_cond_t *cond);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_cond_broadcast");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_cond_broadcast");  \
            abort();
       }
    }

   ret=(*fncPtr)(cond);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_cond_broadcast(cond);
  }
   return ret;

}

int __wrap_pthread_cond_destroy(pthread_cond_t *cond) {
   static int (*fncPtr)(pthread_cond_t *cond);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_cond_destroy");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_cond_destroy");  \
            abort();
       }
    }

   ret=(*fncPtr)(cond);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_cond_destroy(cond);
  }
   return ret;

}

int __wrap_pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
   static int (*fncPtr)(pthread_cond_t *cond, const pthread_condattr_t *attr);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_cond_init");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_cond_init");  \
            abort();
       }
    }

   ret=(*fncPtr)(cond, attr);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_cond_init(cond, attr);
  }
   return ret;

}

int __wrap_pthread_cond_signal(pthread_cond_t *cond) {
   static int (*fncPtr)(pthread_cond_t *cond);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_cond_signal");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_cond_signal");  \
            abort();
       }
    }

   ret=(*fncPtr)(cond);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_cond_signal(cond);
  }
   return ret;

}

int __wrap_pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime) {
   static int (*fncPtr)(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_cond_timedwait");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_cond_timedwait");  \
            abort();
       }
    }

   ret=(*fncPtr)(cond, mutex, abstime);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_cond_timedwait(cond, mutex, abstime);
  }
   return ret;

}

int __wrap_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
   static int (*fncPtr)(pthread_cond_t *cond, pthread_mutex_t *mutex);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_cond_wait");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_cond_wait");  \
            abort();
       }
    }

   ret=(*fncPtr)(cond, mutex);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_cond_wait(cond, mutex);
  }
   return ret;

}

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
   static int (*fncPtr)(struct pollfd *fds, nfds_t nfds, int timeout);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"poll");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","poll");  \
            abort();
       }
    }

   ret=(*fncPtr)(fds, nfds, timeout);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_poll(fds, nfds, timeout);
  }
   return ret;

}

int __wrap_waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) {
   static int (*fncPtr)(idtype_t idtype, id_t id, siginfo_t *infop, int options);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"waitid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","waitid");  \
            abort();
       }
    }

   ret=(*fncPtr)(idtype, id, infop, options);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_waitid(idtype, id, infop, options);
  }
   return ret;

}

pid_t __wrap_wait4(pid_t pid, int* status, int options, struct rusage *rusage) {
   static pid_t (*fncPtr)(pid_t pid, int* status, int options, struct rusage *rusage);
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"wait4");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","wait4");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid, status, options, rusage);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_wait4(pid, status, options, rusage);
  }
   return ret;

}

int __wrap_shmget(int key, size_t size, int shmflg) {
   static int (*fncPtr)(int key, size_t size, int shmflg);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"shmget");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","shmget");  \
            abort();
       }
    }

   ret=(*fncPtr)(key, size, shmflg);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_shmget(key, size, shmflg);
  }
   return ret;

}

void *__wrap_shmat(int shmid, const void *shmaddr, int shmflg) {
   static void * (*fncPtr)(int shmid, const void *shmaddr, int shmflg);
   void * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"shmat");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","shmat");  \
            abort();
       }
    }

   ret=(*fncPtr)(shmid, shmaddr, shmflg);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_shmat(shmid, shmaddr, shmflg);
  }
   return ret;

}

int __wrap_shmdt(const void *shmaddr) {
   static int (*fncPtr)(const void *shmaddr);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"shmdt");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","shmdt");  \
            abort();
       }
    }

   ret=(*fncPtr)(shmaddr);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_shmdt(shmaddr);
  }
   return ret;

}

int __wrap_shmctl(int shmid, int cmd, struct shmid_ds *buf) {
   static int (*fncPtr)(int shmid, int cmd, struct shmid_ds *buf);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"shmctl");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","shmctl");  \
            abort();
       }
    }

   ret=(*fncPtr)(shmid, cmd, buf);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_shmctl(shmid, cmd, buf);
  }
   return ret;

}

int __wrap_semget(key_t key, int nsems, int semflg) {
   static int (*fncPtr)(key_t key, int nsems, int semflg);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"semget");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","semget");  \
            abort();
       }
    }

   ret=(*fncPtr)(key, nsems, semflg);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_semget(key, nsems, semflg);
  }
   return ret;

}

int __wrap_semop(int semid, struct sembuf *sops, size_t nsops) {
   static int (*fncPtr)(int semid, struct sembuf *sops, size_t nsops);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"semop");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","semop");  \
            abort();
       }
    }

   ret=(*fncPtr)(semid, sops, nsops);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_semop(semid, sops, nsops);
  }
   return ret;

}

int __wrap_semtimedop(int semid, struct sembuf *sops, size_t nsops, const struct timespec *timeout) {
   static int (*fncPtr)(int semid, struct sembuf *sops, size_t nsops, const struct timespec *timeout);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"semtimedop");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","semtimedop");  \
            abort();
       }
    }

   ret=(*fncPtr)(semid, sops, nsops, timeout);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_semtimedop(semid, sops, nsops, timeout);
  }
   return ret;

}

int __wrap_semctl(int semid, int semnum, int cmd) {
   static int (*fncPtr)(int semid, int semnum, int cmd);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"semctl");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","semctl");  \
            abort();
       }
    }

   ret=(*fncPtr)(semid, semnum, cmd);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_semctl(semid, semnum, cmd);
  }
   return ret;

}

int __wrap_msgget(key_t key, int msgflg) {
   static int (*fncPtr)(key_t key, int msgflg);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"msgget");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","msgget");  \
            abort();
       }
    }

   ret=(*fncPtr)(key, msgflg);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_msgget(key, msgflg);
  }
   return ret;

}

int __wrap_msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg) {
   static int (*fncPtr)(int msqid, const void *msgp, size_t msgsz, int msgflg);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"msgsnd");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","msgsnd");  \
            abort();
       }
    }

   ret=(*fncPtr)(msqid, msgp, msgsz, msgflg);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_msgsnd(msqid, msgp, msgsz, msgflg);
  }
   return ret;

}

ssize_t __wrap_msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) {
   static ssize_t (*fncPtr)(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
   ssize_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"msgrcv");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","msgrcv");  \
            abort();
       }
    }

   ret=(*fncPtr)(msqid, msgp, msgsz, msgtyp, msgflg);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg);
  }
   return ret;

}

int __wrap_msgctl(int msqid, int cmd, struct msqid_ds *buf) {
   static int (*fncPtr)(int msqid, int cmd, struct msqid_ds *buf);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"msgctl");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","msgctl");  \
            abort();
       }
    }

   ret=(*fncPtr)(msqid, cmd, buf);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_msgctl(msqid, cmd, buf);
  }
   return ret;

}

mqd_t __wrap_mq_open(const char *name, int oflag, mode_t mode, struct mq_attr *attr) {
   static mqd_t (*fncPtr)(const char *name, int oflag, mode_t mode, struct mq_attr *attr);
   mqd_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"mq_open");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","mq_open");  \
            abort();
       }
    }

   ret=(*fncPtr)(name, oflag, mode, attr);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
      printf("Function not found mq_open\n");//
      ret=__real_mq_open(name, oflag, mode, attr);
  }
   return ret;

}

int __wrap_mq_close(mqd_t mqdes) {
   static int (*fncPtr)(mqd_t mqdes);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"mq_close");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","mq_close");  \
            abort();
       }
    }

   ret=(*fncPtr)(mqdes);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
      printf("Function not found mq_close\n");//
     ret=__real_mq_close(mqdes);
  }
   return ret;

}

int __wrap_mq_notify(mqd_t mqdes, const struct sigevent *sevp) {
   static int (*fncPtr)(mqd_t mqdes, const struct sigevent *sevp);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"mq_notify");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","mq_notify");  \
            abort();
       }
    }

   ret=(*fncPtr)(mqdes, sevp);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     printf("Function not found mq_notify\n");
     ret=__real_mq_notify(mqdes, sevp);
  }
   return ret;

}

ssize_t __wrap_mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio, const struct timespec *abs_timeout) {
   static ssize_t (*fncPtr)(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio, const struct timespec *abs_timeout);
   ssize_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"mq_timedreceive");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","mq_timedreceive");  \
            abort();
       }
    }

   ret=(*fncPtr)(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
  }
   return ret;

}

int __wrap_mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout) {
   static int (*fncPtr)(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");
     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"mq_timedsend");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","mq_timedsend");  \
            abort();
       }
    }

   ret=(*fncPtr)(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
  }
   return ret;

}
size_t __wrap_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
   static size_t (*fncPtr)(void *ptr, size_t size, size_t nmemb, FILE *stream);
   size_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }
   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"fread");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","fread");  \
            abort();
       }
    }
   ret=(*fncPtr)(ptr, size, nmemb, stream);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }
 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_fread(ptr, size, nmemb, stream);
  }
   return ret;
}

size_t __wrap_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
   static size_t (*fncPtr)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
   size_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"fwrite");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","fwrite");  \
            abort();
       }
    }

   ret=(*fncPtr)(ptr, size, nmemb, stream);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_fwrite(ptr, size, nmemb, stream);
  }
   return ret;

}

int __wrap_daemon(int nochdir, int noclose) {
   static int (*fncPtr)(int nochdir, int noclose);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"daemon");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","daemon");  \
            abort();
       }
    }

   ret=(*fncPtr)(nochdir, noclose);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_daemon(nochdir, noclose);
  }
   return ret;

}

pid_t __wrap_vfork() {
   static pid_t (*fncPtr)();
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"vfork");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","vfork");  \
            abort();
       }
    }

   ret=(*fncPtr)();
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_vfork();
  }
   return ret;

}

/*Need to implement variable arguments...
 *
 *
 *

int __wrap_execl(const char *path, const char *arg, ...) {
   static int (*fncPtr)(const char *path, const char *arg, ...);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"execl");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","execl");  \
            abort();
       }
    }

   ret=(*fncPtr)(path, arg, ...);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_execl(path, arg, ...);
  }
   return ret;

}

int __wrap_execlp(const char *file, const char *arg, ...) {
   static int (*fncPtr)(const char *file, const char *arg, ...);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"execlp");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","execlp");  \
            abort();
       }
    }

   ret=(*fncPtr)(file, arg, ...);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_execlp(file, arg, ...);
  }
   return ret;

}

int __wrap_execle(const char *path, const char *arg, ...) {
   static int (*fncPtr)(const char *path, const char *arg, ...);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"execle");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","execle");  \
            abort();
       }
    }

   ret=(*fncPtr)(path, arg, ...);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_execle(path, arg, ...);
  }
   return ret;

}
*/

int __wrap_pipe(int fds[2]) {
   static int (*fncPtr)(int fds[2]);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pipe");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pipe");  \
            abort();
       }
    }

   ret=(*fncPtr)(fds);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pipe(fds);
  }
   return ret;

}

int __wrap_pipe2(int fds[2], int flags) {
   static int (*fncPtr)(int fds[2], int flags);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pipe2");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pipe2");  \
            abort();
       }
    }

   ret=(*fncPtr)(fds, flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pipe2(fds, flags);
  }
   return ret;

}

pid_t __wrap_wait(int * stat_loc) {
   static pid_t (*fncPtr)(int* stat_loc);
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"wait");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","wait");  \
            abort();
       }
    }

   ret=(*fncPtr)(stat_loc);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_wait(stat_loc);
  }
   return ret;

}

pid_t __wrap_waitpid(pid_t pid, int *stat_loc, int options) {
   static pid_t (*fncPtr)(pid_t pid, int *stat_loc, int options);
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"waitpid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","waitpid");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid, stat_loc, options);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_waitpid(pid, stat_loc, options);
  }
   return ret;

}

pid_t __wrap_wait3(int* status, int options, struct rusage *rusage) {
   static pid_t (*fncPtr)(int* status, int options, struct rusage *rusage);
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"wait3");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","wait3");  \
            abort();
       }
    }

   ret=(*fncPtr)(status, options, rusage);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_wait3(status, options, rusage);
  }
   return ret;

}
/*
int __wrap___clone2(int (*fn)(void *arg), void *child_stack, int flags, void *arg, int *parent_tidptr, struct user_desc *newtls, int *child_tidptr) {
   static int (*fncPtr)(int (*fn)(void *arg), void *child_stack, int flags, void *arg, int *parent_tidptr, struct user_desc *newtls, int *child_tidptr);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"__clone");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","__clone");  \
            abort();
       }
    }

   ret=(*fncPtr)(arg, child_stack, flags, arg, parent_tidptr, newtls, child_tidptr);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real___clone(arg, child_stack, flags, arg, parent_tidptr, newtls, child_tidptr);
  }
   return ret;

}

int __wrap_sigvec(int sig, const struct sigvec *vec, struct sigvec *ovec) {
   static int (*fncPtr)(int sig, const struct sigvec *vec, struct sigvec *ovec);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sigvec");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sigvec");  \
            abort();
       }
    }

   ret=(*fncPtr)(sig, vec, ovec);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sigvec(sig, vec, ovec);
  }
   return ret;

}
*/
int __wrap___sigpause(int __sig_or_mask, int __is_sig) {
   static int (*fncPtr)(int __sig_or_mask, int __is_sig);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"__sigpause");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","__sigpause");  \
            abort();
       }
    }

   ret=(*fncPtr)(__sig_or_mask, __is_sig);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real___sigpause(__sig_or_mask, __is_sig);
  }
   return ret;

}
/* variable arguments
int __wrap_ioctl(int fd, unsigned long request, ...) {
   static int (*fncPtr)(int fd, unsigned long request, ...);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"ioctl");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","ioctl");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd, request, ...);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_ioctl(fd, request, ...);
  }
   return ret;

}
*/
pid_t __wrap_getpid() {
   static pid_t (*fncPtr)();
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"getpid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","getpid");  \
            abort();
       }
    }

   ret=(*fncPtr)();
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_getpid();
  }
   return ret;

}

pid_t __wrap_getppid() {
   static pid_t (*fncPtr)();
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"getppid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","getppid");  \
            abort();
       }
    }

   ret=(*fncPtr)();
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_getppid();
  }
   return ret;

}

int __wrap_kill(pid_t pid, int sig) {
   static int (*fncPtr)(pid_t pid, int sig);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"kill");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","kill");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid, sig);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_kill(pid, sig);
  }
   return ret;

}

pid_t __wrap_tcgetpgrp(int fd) {
   static pid_t (*fncPtr)(int fd);
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"tcgetpgrp");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","tcgetpgrp");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_tcgetpgrp(fd);
  }
   return ret;

}

int __wrap_tcsetpgrp(int fd, pid_t pgrp) {
   static int (*fncPtr)(int fd, pid_t pgrp);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"tcsetpgrp");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","tcsetpgrp");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd, pgrp);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_tcsetpgrp(fd, pgrp);
  }
   return ret;

}

int __wrap_setpgid(pid_t pid, pid_t pgid) {
   static int (*fncPtr)(pid_t pid, pid_t pgid);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"setpgid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","setpgid");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid, pgid);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_setpgid(pid, pgid);
  }
   return ret;

}

pid_t __wrap_getpgid(pid_t pid) {
   static pid_t (*fncPtr)(pid_t pid);
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"getpgid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","getpgid");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_getpgid(pid);
  }
   return ret;

}
/*
pid_t __wrap_getpgrp() {
   static pid_t (*fncPtr)();
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"getpgrp");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","getpgrp");  \
            abort();
       }
    }

   ret=(*fncPtr)();
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_getpgrp();
  }
   return ret;

}
*/
pid_t __wrap_getpgrp(pid_t pid) {
   static pid_t (*fncPtr)(pid_t pid);
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"getpgrp");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","getpgrp");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_getpgrp(pid);
  }
   return ret;

}
/*
int __wrap_setpgrp() {
   static int (*fncPtr)();
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"setpgrp");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","setpgrp");  \
            abort();
       }
    }

   ret=(*fncPtr)();
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_setpgrp();
  }
   return ret;

}
*/
int __wrap_setpgrp(pid_t pid, pid_t pgid) {
   static int (*fncPtr)(pid_t pid, pid_t pgid);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"setpgrp");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","setpgrp");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid, pgid);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_setpgrp(pid, pgid);
  }
   return ret;

}

pid_t __wrap_getsid(pid_t pid) {
   static pid_t (*fncPtr)(pid_t pid);
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"getsid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","getsid");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_getsid(pid);
  }
   return ret;

}

pid_t __wrap_setsid() {
   static pid_t (*fncPtr)();
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"setsid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","setsid");  \
            abort();
       }
    }

   ret=(*fncPtr)();
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_setsid();
  }
   return ret;

}

int __wrap_setgid(gid_t gid) {
   static int (*fncPtr)(gid_t gid);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"setgid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","setgid");  \
            abort();
       }
    }

   ret=(*fncPtr)(gid);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_setgid(gid);
  }
   return ret;

}

int __wrap_setuid(uid_t uid) {
   static int (*fncPtr)(uid_t uid);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"setuid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","setuid");  \
            abort();
       }
    }

   ret=(*fncPtr)(uid);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_setuid(uid);
  }
   return ret;

}

uid_t __wrap_getuid() {
   static uid_t (*fncPtr)();
   uid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"getuid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","getuid");  \
            abort();
       }
    }

   ret=(*fncPtr)();
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_getuid();
  }
   return ret;

}

uid_t __wrap_geteuid() {
   static uid_t (*fncPtr)();
   uid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"geteuid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","geteuid");  \
            abort();
       }
    }

   ret=(*fncPtr)();
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_geteuid();
  }
   return ret;

}

int __wrap_setenv(const char *name, const char *value, int overwrite) {
   static int (*fncPtr)(const char *name, const char *value, int overwrite);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"setenv");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","setenv");  \
            abort();
       }
    }

   ret=(*fncPtr)(name, value, overwrite);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_setenv(name, value, overwrite);
  }
   return ret;

}

int __wrap_unsetenv(const char *name) {
   static int (*fncPtr)(const char *name);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"unsetenv");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","unsetenv");  \
            abort();
       }
    }

   ret=(*fncPtr)(name);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_unsetenv(name);
  }
   return ret;

}

char * __wrap_realpath(const char *path, char *resolved_path) {
   static char * (*fncPtr)(const char *path, char *resolved_path);
   char * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"realpath");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","realpath");  \
            abort();
       }
    }

   ret=(*fncPtr)(path, resolved_path);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_realpath(path, resolved_path);
  }
   return ret;

}

int __wrap_access(const char *path, int mode) {
   static int (*fncPtr)(const char *path, int mode);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"access");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","access");  \
            abort();
       }
    }

   ret=(*fncPtr)(path, mode);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_access(path, mode);
  }
   return ret;

}

int __wrap_clock_getcpuclockid(pid_t pid, clockid_t *clock_id) {
   static int (*fncPtr)(pid_t pid, clockid_t *clock_id);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"clock_getcpuclockid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","clock_getcpuclockid");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid, clock_id);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_clock_getcpuclockid(pid, clock_id);
  }
   return ret;

}

int __wrap_timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid) {
   static int (*fncPtr)(clockid_t clockid, struct sigevent *sevp, timer_t *timerid);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"timer_create");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","timer_create");  \
            abort();
       }
    }

   ret=(*fncPtr)(clockid, sevp, timerid);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_timer_create(clockid, sevp, timerid);
  }
   return ret;

}

int __wrap_timer_delete(timer_t timerid) {
   static int (*fncPtr)(timer_t timerid);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"timer_delete");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","timer_delete");  \
            abort();
       }
    }

   ret=(*fncPtr)(timerid);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_timer_delete(timerid);
  }
   return ret;

}

int __wrap_timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value, struct itimerspec *old_value) {
   static int (*fncPtr)(timer_t timerid, int flags, const struct itimerspec *new_value, struct itimerspec *old_value);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"timer_settime");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","timer_settime");  \
            abort();
       }
    }

   ret=(*fncPtr)(timerid, flags, new_value, old_value);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_timer_settime(timerid, flags, new_value, old_value);
  }
   return ret;

}

int __wrap_timer_gettime(timer_t timerid, struct itimerspec *curr_value) {
   static int (*fncPtr)(timer_t timerid, struct itimerspec *curr_value);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"timer_gettime");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","timer_gettime");  \
            abort();
       }
    }

   ret=(*fncPtr)(timerid, curr_value);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_timer_gettime(timerid, curr_value);
  }
   return ret;

}

int __wrap_timer_getoverrun(timer_t timerid) {
   static int (*fncPtr)(timer_t timerid);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"timer_getoverrun");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","timer_getoverrun");  \
            abort();
       }
    }

   ret=(*fncPtr)(timerid);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_timer_getoverrun(timerid);
  }
   return ret;

}

int __wrap_pthread_getcpuclockid(pthread_t thread, clockid_t *clock_id) {
   static int (*fncPtr)(pthread_t thread, clockid_t *clock_id);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pthread_getcpuclockid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pthread_getcpuclockid");  \
            abort();
       }
    }

   ret=(*fncPtr)(thread, clock_id);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pthread_getcpuclockid(thread, clock_id);
  }
   return ret;

}

int __wrap_clock_getres(clockid_t clk_id, struct timespec *res) {
   static int (*fncPtr)(clockid_t clk_id, struct timespec *res);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"clock_getres");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","clock_getres");  \
            abort();
       }
    }

   ret=(*fncPtr)(clk_id, res);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_clock_getres(clk_id, res);
  }
   return ret;

}

int __wrap_clock_gettime(clockid_t clk_id, struct timespec *tp) {
   static int (*fncPtr)(clockid_t clk_id, struct timespec *tp);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"clock_gettime");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","clock_gettime");  \
            abort();
       }
    }

   ret=(*fncPtr)(clk_id, tp);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_clock_gettime(clk_id, tp);
  }
   return ret;

}

int __wrap_clock_settime(clockid_t clk_id, const struct timespec *tp) {
   static int (*fncPtr)(clockid_t clk_id, const struct timespec *tp);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"clock_settime");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","clock_settime");  \
            abort();
       }
    }

   ret=(*fncPtr)(clk_id, tp);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_clock_settime(clk_id, tp);
  }
   return ret;

}

int __wrap_clock_nanosleep(clockid_t clock_id, int flags, const struct timespec *request, struct timespec *remain) {
   static int (*fncPtr)(clockid_t clock_id, int flags, const struct timespec *request, struct timespec *remain);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"clock_nanosleep");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","clock_nanosleep");  \
            abort();
       }
    }

   ret=(*fncPtr)(clock_id, flags, request, remain);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_clock_nanosleep(clock_id, flags, request, remain);
  }
   return ret;

}

ssize_t __wrap_process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
   static ssize_t (*fncPtr)(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
   ssize_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"process_vm_readv");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","process_vm_readv");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
  }
   return ret;

}

ssize_t __wrap_process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
   static ssize_t (*fncPtr)(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
   ssize_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"process_vm_writev");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","process_vm_writev");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_process_vm_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
  }
   return ret;

}

pid_t __wrap_tcgetsid(int fd) {
   static pid_t (*fncPtr)(int fd);
   pid_t ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"tcgetsid");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","tcgetsid");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_tcgetsid(fd);
  }
   return ret;

}
#include <sys/ptrace.h>

long __wrap_ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data){
   static long (*fncPtr)(enum __ptrace_request request, pid_t pid, void *addr, void *data);
   long ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"ptrace");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","ptrace");  \
            abort();
       }
    }

   ret=(*fncPtr)(request, pid, addr, data);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_ptrace(request, pid, addr, data);
  }
   return ret;

}

int __wrap_sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask) {
   static int (*fncPtr)(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sched_setaffinity");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sched_setaffinity");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid, cpusetsize, mask);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sched_setaffinity(pid, cpusetsize, mask);
  }
   return ret;

}

int __wrap_sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
   static int (*fncPtr)(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sched_getaffinity");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sched_getaffinity");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid, cpusetsize, mask);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sched_getaffinity(pid, cpusetsize, mask);
  }
   return ret;

}

int __wrap_sched_setscheduler(pid_t pid, int policy, const struct sched_param *param) {
   static int (*fncPtr)(pid_t pid, int policy, const struct sched_param *param);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sched_setscheduler");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sched_setscheduler");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid, policy, param);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sched_setscheduler(pid, policy, param);
  }
   return ret;

}

int __wrap_sched_getscheduler(pid_t pid) {
   static int (*fncPtr)(pid_t pid);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sched_getscheduler");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sched_getscheduler");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sched_getscheduler(pid);
  }
   return ret;

}

int __wrap_sched_setparam(pid_t pid, const struct sched_param *param) {
   static int (*fncPtr)(pid_t pid, const struct sched_param *param);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sched_setparam");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sched_setparam");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid, param);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sched_setparam(pid, param);
  }
   return ret;

}

int __wrap_sched_getparam(pid_t pid, struct sched_param *param) {
   static int (*fncPtr)(pid_t pid, struct sched_param *param);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"sched_getparam");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","sched_getparam");  \
            abort();
       }
    }

   ret=(*fncPtr)(pid, param);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_sched_getparam(pid, param);
  }
   return ret;

}
/*
int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
   static int (*fncPtr)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"getaddrinfo");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","getaddrinfo");  \
            abort();
       }
    }

   ret=(*fncPtr)(node, service, hints, res);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_getaddrinfo(node, service, hints, res);
  }
   return ret;

}

int __wrap_getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, size_t hostlen, char *serv, size_t servlen, int flags) {
   static int (*fncPtr)(const struct sockaddr *sa, socklen_t salen, char *host, size_t hostlen, char *serv, size_t servlen, int flags);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"getnameinfo");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","getnameinfo");  \
            abort();
       }
    }

   ret=(*fncPtr)(sa, salen, host, hostlen, serv, servlen, flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
  }
   return ret;

}
*/
struct hostent * __wrap_gethostbyname(const char *name) {
   static struct hostent * (*fncPtr)(const char *name);
   struct hostent * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"gethostbyname");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","gethostbyname");  \
            abort();
       }
    }

   ret=(*fncPtr)(name);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_gethostbyname(name);
  }
   return ret;

}

struct hostent * __wrap_gethostbyaddr(const void *addr, socklen_t len, int type) {
   static struct hostent * (*fncPtr)(const void *addr, socklen_t len, int type);
   struct hostent * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"gethostbyaddr");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","gethostbyaddr");  \
            abort();
       }
    }

   ret=(*fncPtr)(addr, len, type);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_gethostbyaddr(addr, len, type);
  }
   return ret;

}

int __wrap___poll_chk(struct pollfd *fds, nfds_t nfds, int timeout, size_t fdslen) {
   static int (*fncPtr)(struct pollfd *fds, nfds_t nfds, int timeout, size_t fdslen);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"__poll_chk");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","__poll_chk");  \
            abort();
       }
    }

   ret=(*fncPtr)(fds, nfds, timeout, fdslen);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real___poll_chk(fds, nfds, timeout, fdslen);
  }
   return ret;

}
/*
int __wrap_pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask) {
   static int (*fncPtr)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"pselect");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","pselect");  \
            abort();
       }
    }

   ret=(*fncPtr)(nfds, readfds, writefds, exceptfds, timeout, sigmask);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
  }
   return ret;

}
*/
int __wrap_signalfd(int fd, const sigset_t *mask, int flags) {
   static int (*fncPtr)(int fd, const sigset_t *mask, int flags);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"signalfd");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","signalfd");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd, mask, flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_signalfd(fd, mask, flags);
  }
   return ret;

}

int __wrap_eventfd(unsigned int initval, int flags) {
   static int (*fncPtr)(unsigned int initval, int flags);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"eventfd");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","eventfd");  \
            abort();
       }
    }

   ret=(*fncPtr)(initval, flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_eventfd(initval, flags);
  }
   return ret;

}

int __wrap_epoll_create(int size) {
   static int (*fncPtr)(int size);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"epoll_create");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","epoll_create");  \
            abort();
       }
    }

   ret=(*fncPtr)(size);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_epoll_create(size);
  }
   return ret;

}

int __wrap_epoll_create1(int flags) {
   static int (*fncPtr)(int flags);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"epoll_create1");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","epoll_create1");  \
            abort();
       }
    }

   ret=(*fncPtr)(flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_epoll_create1(flags);
  }
   return ret;

}
/*
int __wrap_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
   static int (*fncPtr)(int epfd, int op, int fd, struct epoll_event *event);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"epoll_ctl");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","epoll_ctl");  \
            abort();
       }
    }

   ret=(*fncPtr)(epfd, op, fd, event);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_epoll_ctl(epfd, op, fd, event);
  }
   return ret;

}

int __wrap_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
   static int (*fncPtr)(int epfd, struct epoll_event *events, int maxevents, int timeout);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"epoll_wait");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","epoll_wait");  \
            abort();
       }
    }

   ret=(*fncPtr)(epfd, events, maxevents, timeout);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_epoll_wait(epfd, events, maxevents, timeout);
  }
   return ret;

}
*/
int __wrap_inotify_init() {
   static int (*fncPtr)();
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"inotify_init");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","inotify_init");  \
            abort();
       }
    }

   ret=(*fncPtr)();
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_inotify_init();
  }
   return ret;

}

int __wrap_inotify_init1(int flags) {
   static int (*fncPtr)(int flags);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"inotify_init1");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","inotify_init1");  \
            abort();
       }
    }

   ret=(*fncPtr)(flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_inotify_init1(flags);
  }
   return ret;

}

int __wrap_inotify_add_watch(int fd, const char *pathname, uint32_t mask) {
   static int (*fncPtr)(int fd, const char *pathname, uint32_t mask);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"inotify_add_watch");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","inotify_add_watch");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd, pathname, mask);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_inotify_add_watch(fd, pathname, mask);
  }
   return ret;

}

int __wrap_inotify_rm_watch(int fd, int wd) {
   static int (*fncPtr)(int fd, int wd);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"inotify_rm_watch");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","inotify_rm_watch");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd, wd);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_inotify_rm_watch(fd, wd);
  }
   return ret;

}

FILE * __wrap_tmpfile() {
   static FILE * (*fncPtr)();
   FILE * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"tmpfile");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","tmpfile");  \
            abort();
       }
    }

   ret=(*fncPtr)();
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_tmpfile();
  }
   return ret;

}

int __wrap_mkostemp(char *template, int flags) {
   static int (*fncPtr)(char *template, int flags);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"mkostemp");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","mkostemp");  \
            abort();
       }
    }

   ret=(*fncPtr)(template, flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_mkostemp(template, flags);
  }
   return ret;

}

int __wrap_mkstemps(char *template, int suffixlen) {
   static int (*fncPtr)(char *template, int suffixlen);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"mkstemps");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","mkstemps");  \
            abort();
       }
    }

   ret=(*fncPtr)(template, suffixlen);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_mkstemps(template, suffixlen);
  }
   return ret;

}

int __wrap_mkostemps(char *template, int suffixlen, int flags) {
   static int (*fncPtr)(char *template, int suffixlen, int flags);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"mkostemps");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","mkostemps");  \
            abort();
       }
    }

   ret=(*fncPtr)(template, suffixlen, flags);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_mkostemps(template, suffixlen, flags);
  }
   return ret;

}

int __wrap_creat(const char *path, mode_t mode) {
   static int (*fncPtr)(const char *path, mode_t mode);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"creat");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","creat");  \
            abort();
       }
    }

   ret=(*fncPtr)(path, mode);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_creat(path, mode);
  }
   return ret;

}

int __wrap_creat64(const char *path, mode_t mode) {
   static int (*fncPtr)(const char *path, mode_t mode);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"creat64");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","creat64");  \
            abort();
       }
    }

   ret=(*fncPtr)(path, mode);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_creat64(path, mode);
  }
   return ret;

}

char * __wrap_ttyname(int fd) {
   static char * (*fncPtr)(int fd);
   char * ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"ttyname");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","ttyname");  \
            abort();
       }
    }

   ret=(*fncPtr)(fd);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_ttyname(fd);
  }
   return ret;

}
int __wrap_fseek(FILE *stream, long offset, int whence) {
   static int (*fncPtr)(FILE *stream, long offset, int whence);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"fseek");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","fseek");  \
            abort();
       }
    }

   ret=(*fncPtr)(stream, offset, whence);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_fseek(stream, offset, whence);
  }
   return ret;

}

long __wrap_ftell(FILE *stream) {
   static long (*fncPtr)(FILE *stream);
   long ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"ftell");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","ftell");  \
            abort();
       }
    }

   ret=(*fncPtr)(stream);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_ftell(stream);
  }
   return ret;

}

void __wrap_rewind(FILE *stream) {
   static void (*fncPtr)(FILE *stream);
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"rewind");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","rewind");  \
            abort();
       }
    }

   (*fncPtr)(stream);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     __real_rewind(stream);
  }
}

int __wrap_fgetpos(FILE *stream, fpos_t *pos) {
   static int (*fncPtr)(FILE *stream, fpos_t *pos);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"fgetpos");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","fgetpos");  \
            abort();
       }
    }

   ret=(*fncPtr)(stream, pos);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_fgetpos(stream, pos);
  }
   return ret;

}

int __wrap_fsetpos(FILE *stream, const fpos_t *pos) {
   static int (*fncPtr)(FILE *stream, const fpos_t *pos);
   int ret;
 if(dmtcp_loaded==1) { printf("Finding in dmtcp\n");

     if(set_fs_dmtcp()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
   }

   if(fncPtr==NULL)
    {
       fncPtr=(*mydlsym)(soPtr,"fsetpos");
       if(fncPtr==NULL){
           fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n" \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"       \
                       "    Aborting.\n","fsetpos");  \
            abort();
       }
    }

   ret=(*fncPtr)(stream, pos);
   if(set_fs_application()==-1){
         fprintf(stderr, "Error setting fs\n" );
         exit(-1);
    }

 }
 else{ printf("Not in dmtcp. Going in libc.a\n");
     ret=__real_fsetpos(stream, pos);
  }
   return ret;

}
