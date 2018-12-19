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

    if (fwrite(&context,sizeof(ucontext_t),1,fp)==0) {
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
  if(fread(&soPtr,sizeof(void*),1,fp)==0) {
    fprintf(stderr, "Error reading file\n");
  }
  if(fread(&ptr,sizeof(void*),1,fp)==0) {
    fprintf(stderr, "Error reading file\n");
  }
  //void *ptr2;
  //fread(&ptr2,sizeof(void*),1,fp);
  if(__real_fclose(fp)!=0){
    fprintf(stderr, "Error closing file\n" );
  }
  mydlsym=ptr;
  //dmtcp_loaded=1;
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
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_socket(domain, type, protocol);
  }
   return ret;

}

int __wrap_connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen) {
   static int (*fncPtr)(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_connect(sockfd, serv_addr, addrlen);
  }
   return ret;

}

int __wrap_bind(int sockfd, const struct  sockaddr *my_addr, socklen_t addrlen) {
   static int (*fncPtr)(int sockfd, const struct  sockaddr *my_addr, socklen_t addrlen);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_bind(sockfd, my_addr, addrlen);
  }
   return ret;

}

int __wrap_listen(int sockfd, int backlog) {
   static int (*fncPtr)(int sockfd, int backlog);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_listen(sockfd, backlog);
  }
   return ret;

}

int __wrap_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
   static int (*fncPtr)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_accept(sockfd, addr, addrlen);
  }
   return ret;

}

int __wrap_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
   static int (*fncPtr)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_accept4(sockfd, addr, addrlen, flags);
  }
   return ret;

}

int __wrap_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen) {
   static int (*fncPtr)(int s, int level, int optname, const void *optval, socklen_t optlen);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_setsockopt(s, level, optname, optval, optlen);
  }
   return ret;

}

int __wrap_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen) {
   static int (*fncPtr)(int s, int level, int optname, void *optval, socklen_t *optlen);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_getsockopt(s, level, optname, optval, optlen);
  }
   return ret;

}

int __wrap_fexecve(int fd, char *const argv[], char *const envp[]) {
   static int (*fncPtr)(int fd, char *const argv[], char *const envp[]);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_fexecve(fd, argv, envp);
  }
   return ret;

}

int __wrap_execve(const char *filename, char *const argv[], char *const envp[]) {
   static int (*fncPtr)(const char *filename, char *const argv[], char *const envp[]);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_execve(filename, argv, envp);
  }
   return ret;

}

int __wrap_execv(const char *path, char *const argv[]) {
   static int (*fncPtr)(const char *path, char *const argv[]);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_execv(path, argv);
  }
   return ret;

}

int __wrap_execvp(const char *file, char *const argv[]) {
   static int (*fncPtr)(const char *file, char *const argv[]);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_execvp(file, argv);
  }
   return ret;

}

int __wrap_execvpe(const char *file, char *const argv[], char *const envp[]) {
   static int (*fncPtr)(const char *file, char *const argv[], char *const envp[]);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_execvpe(file, argv, envp);
  }
   return ret;

}

int __wrap_system(const char *cmd) {
   static int (*fncPtr)(const char *cmd);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_system(cmd);
  }
   return ret;

}

FILE *__wrap_popen(const char *command, const char *mode) {
   static FILE * (*fncPtr)(const char *command, const char *mode);
   FILE * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_popen(command, mode);
  }
   return ret;

}

int __wrap_pclose(FILE *fp) {
   static int (*fncPtr)(FILE *fp);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pclose(fp);
  }
   return ret;

}

pid_t __wrap_fork() {
   static pid_t (*fncPtr)();
   pid_t ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_fork();
  }
   return ret;

}

int __wrap_open(const char *pathname, int flags) {
   static int (*fncPtr)(const char *pathname, int flags);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_open(pathname, flags);
  }
   return ret;

}

int __wrap_open64(const char *pathname, int flags) {
   static int (*fncPtr)(const char *pathname, int flags);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_open64(pathname, flags);
  }
   return ret;

}

FILE *__wrap_fopen(const char *path, const char *mode) {
   static FILE * (*fncPtr)(const char *path, const char *mode);
   FILE * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_fopen(path, mode);
  }
   return ret;

}

FILE *__wrap_fopen64(const char *path, const char *mode) {
   static FILE * (*fncPtr)(const char *path, const char *mode);
   FILE * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_fopen64(path, mode);
  }
   return ret;

}

int __wrap_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
   static int (*fncPtr)(int dirfd, const char *pathname, int flags, mode_t mode);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_openat(dirfd, pathname, flags, mode);
  }
   return ret;

}

int __wrap_openat64(int dirfd, const char *pathname, int flags, mode_t mode) {
   static int (*fncPtr)(int dirfd, const char *pathname, int flags, mode_t mode);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_openat64(dirfd, pathname, flags, mode);
  }
   return ret;

}

DIR *__wrap_opendir(const char *name) {
   static DIR * (*fncPtr)(const char *name);
   DIR * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_opendir(name);
  }
   return ret;

}

int __wrap_mkstemp(char *ttemplate) {
   static int (*fncPtr)(char *ttemplate);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_mkstemp(ttemplate);
  }
   return ret;

}

int __wrap_close(int fd) {
   static int (*fncPtr)(int fd);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_close(fd);
  }
   return ret;

}

int __wrap_fclose(FILE *fp) {
   static int (*fncPtr)(FILE *fp);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_fclose(fp);
  }
   return ret;

}

int __wrap_closedir(DIR *dir) {
   static int (*fncPtr)(DIR *dir);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_closedir(dir);
  }
   return ret;

}

void __wrap_exit(int status) {
   static void (*fncPtr)(int status);
 if(dmtcp_loaded==1) {
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
 else{
     __real_exit(status);
  }
}

int __wrap_dup(int oldfd) {
   static int (*fncPtr)(int oldfd);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_dup(oldfd);
  }
   return ret;

}

int __wrap_dup2(int oldfd, int newfd) {
   static int (*fncPtr)(int oldfd, int newfd);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_dup2(oldfd, newfd);
  }
   return ret;

}

int __wrap_dup3(int oldfd, int newfd, int flags) {
   static int (*fncPtr)(int oldfd, int newfd, int flags);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_dup3(oldfd, newfd, flags);
  }
   return ret;

}

int __wrap_fcntl(int fd, int cmd, void *arg) {
   static int (*fncPtr)(int fd, int cmd, void *arg);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_fcntl(fd, cmd, arg);
  }
   return ret;

}

int __wrap_ttyname_r(int fd, char *buf, size_t buflen) {
   static int (*fncPtr)(int fd, char *buf, size_t buflen);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_ttyname_r(fd, buf, buflen);
  }
   return ret;

}

int __wrap_ptsname_r(int fd, char *buf, size_t buflen) {
   static int (*fncPtr)(int fd, char *buf, size_t buflen);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_ptsname_r(fd, buf, buflen);
  }
   return ret;

}

int __wrap_getpt(void) {
   static int (*fncPtr)(void);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_getpt();
  }
   return ret;

}

int __wrap_posix_openpt(int flags) {
   static int (*fncPtr)(int flags);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_posix_openpt(flags);
  }
   return ret;

}

int __wrap_socketpair(int d, int type, int protocol, int sv[2]) {
   static int (*fncPtr)(int d, int type, int protocol, int sv[2]);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_socketpair(d, type, protocol, sv);
  }
   return ret;

}

void __wrap_openlog(const char *ident, int option, int facility) {
   static void (*fncPtr)(const char *ident, int option, int facility);
 if(dmtcp_loaded==1) {
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
 else{
     __real_openlog(ident, option, facility);
  }
}

void __wrap_closelog(void) {
   static void (*fncPtr)(void);
 if(dmtcp_loaded==1) {
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
 else{
     __real_closelog();
  }
}

sighandler_t __wrap_signal(int signum, sighandler_t handler) {
   static sighandler_t (*fncPtr)(int signum, sighandler_t handler);
   sighandler_t ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_signal(signum, handler);
  }
   return ret;

}

int __wrap_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
   static int (*fncPtr)(int signum, const struct sigaction *act, struct sigaction *oldact);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_sigaction(signum, act, oldact);
  }
   return ret;

}

int __wrap_rt_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
   static int (*fncPtr)(int signum, const struct sigaction *act, struct sigaction *oldact);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     //ret=__real_rt_sigaction(signum, act, oldact);
     ret=-1;
  }
   return ret;

}

int __wrap_sigblock(int mask) {
   static int (*fncPtr)(int mask);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_sigblock(mask);
  }
   return ret;

}

int __wrap_sigsetmask(int mask) {
   static int (*fncPtr)(int mask);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_sigsetmask(mask);
  }
   return ret;

}

int __wrap_siggetmask(void) {
   static int (*fncPtr)(void);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_siggetmask();
  }
   return ret;

}

int __wrap_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
   static int (*fncPtr)(int how, const sigset_t *set, sigset_t *oldset);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_sigprocmask(how, set, oldset);
  }
   return ret;

}

int __wrap_rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
   static int (*fncPtr)(int how, const sigset_t *set, sigset_t *oldset);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
    // ret=__real_rt_sigprocmask(how, set, oldset);
    ret=-1;
  }
   return ret;

}

int __wrap_pthread_sigmask(int how, const sigset_t *newmask, sigset_t *oldmask) {
   static int (*fncPtr)(int how, const sigset_t *newmask, sigset_t *oldmask);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_sigmask(how, newmask, oldmask);
  }
   return ret;

}

void *__wrap_pthread_getspecific(pthread_key_t key) {
   static void * (*fncPtr)(pthread_key_t key);
   void * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_getspecific(key);
  }
   return ret;

}

int __wrap_sigsuspend(const sigset_t *mask) {
   static int (*fncPtr)(const sigset_t *mask);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_sigsuspend(mask);
  }
   return ret;

}

int __wrap_sighold(int sig) {
   static int (*fncPtr)(int sig);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_sighold(sig);
  }
   return ret;

}

int __wrap_sigignore(int sig) {
   static int (*fncPtr)(int sig);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_sigignore(sig);
  }
   return ret;

}


int __wrap_sigpause(int sig) {
   static int (*fncPtr)(int sig);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_sigpause(sig);
  }
   return ret;

}

int __wrap_sigrelse(int sig) {
   static int (*fncPtr)(int sig);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_sigrelse(sig);
  }
   return ret;

}

sighandler_t __wrap_sigset(int sig, sighandler_t disp) {
   static sighandler_t (*fncPtr)(int sig, sighandler_t disp);
   sighandler_t ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_sigset(sig, disp);
  }
   return ret;

}

int __wrap_sigwait(const sigset_t *set, int *sig) {
   static int (*fncPtr)(const sigset_t *set, int *sig);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_sigwait(set, sig);
  }
   return ret;

}

int __wrap_sigwaitinfo(const sigset_t *set, siginfo_t *info) {
   static int (*fncPtr)(const sigset_t *set, siginfo_t *info);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_sigwaitinfo(set, info);
  }
   return ret;

}

int __wrap_sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout) {
   static int (*fncPtr)(const sigset_t *set, siginfo_t *info, const struct timespec *timeout);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_sigtimedwait(set, info, timeout);
  }
   return ret;

}

long __wrap_syscall(long sys_num) {
   static long (*fncPtr)(long sys_num);
   long ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_syscall(sys_num);
  }
   return ret;

}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
   static int (*fncPtr)(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_create(thread, attr, start_routine, arg);
  }
   return ret;

}

void __wrap_pthread_exit(void *retval) {
  static void (*fncPtr)(void *retval);
 if(dmtcp_loaded==1) {
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
 else{
   printf("Calling pthread_exit()\n");
     //__real_pthread_exit(retval);
  }

}

int __wrap_pthread_tryjoin_np(pthread_t thread, void **retval) {
   static int (*fncPtr)(pthread_t thread, void **retval);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_tryjoin_np(thread, retval);
  }
   return ret;

}

int __wrap_pthread_timedjoin_np(pthread_t thread, void **retval, const struct timespec *abstime) {
   static int (*fncPtr)(pthread_t thread, void **retval, const struct timespec *abstime);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_timedjoin_np(thread, retval, abstime);
  }
   return ret;

}

int __wrap_xstat(int vers, const char *path, struct stat *buf) {
   static int (*fncPtr)(int vers, const char *path, struct stat *buf);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret-1;
  }
   return ret;

}

int __wrap_lxstat(int vers, const char *path, struct stat *buf) {
   static int (*fncPtr)(int vers, const char *path, struct stat *buf);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=-1;
  }
   return ret;

}

ssize_t __wrap_readlink(const char *path, char *buf, size_t bufsiz) {
   static ssize_t (*fncPtr)(const char *path, char *buf, size_t bufsiz);
   ssize_t ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_readlink(path, buf, bufsiz);
  }
   return ret;

}

void *__wrap_dlsym(void *handle, const char *symbol) {
   static void * (*fncPtr)(void *handle, const char *symbol);
   void * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_dlsym(handle, symbol);
  }
   return ret;

}

void *__wrap_dlopen(const char *filename, int flag) {
   static void * (*fncPtr)(const char *filename, int flag);
   void * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_dlopen(filename, flag);
  }
   return ret;

}

int __wrap_dlclose(void *handle) {
   static int (*fncPtr)(void *handle);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_dlclose(handle);
  }
   return ret;

}

void *__wrap_calloc(size_t nmemb, size_t size) {
   static void * (*fncPtr)(size_t nmemb, size_t size);
   void * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_calloc(nmemb, size);
  }
   return ret;

}

void *__wrap_malloc(size_t size) {
   static void * (*fncPtr)(size_t size);
   void * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_malloc(size);
  }
   return ret;

}

void __wrap_free(void *ptr) {
   static void (*fncPtr)(void *ptr);
 if(dmtcp_loaded==1) {
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
 else{
     __real_free(ptr);
  }
}

void *__wrap_realloc(void *ptr, size_t size) {
   static void * (*fncPtr)(void *ptr, size_t size);
   void * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_realloc(ptr, size);
  }
   return ret;

}

void *__wrap___libc_memalign(size_t boundary, size_t size) {
   static void * (*fncPtr)(size_t boundary, size_t size);
   void * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real___libc_memalign(boundary, size);
  }
   return ret;

}

void *__wrap_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
   static void * (*fncPtr)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
   void * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_mmap(addr, length, prot, flags, fd, offset);
  }
   return ret;

}

void *__wrap_mmap64(void *addr, size_t length, int prot, int flags, int fd, __off64_t offset) {
   static void * (*fncPtr)(void *addr, size_t length, int prot, int flags, int fd, __off64_t offset);
   void * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_mmap64(addr, length, prot, flags, fd, offset);
  }
   return ret;

}

void *__wrap_mremap(void *old_address, size_t old_size, size_t new_size, int flags) {
   static void * (*fncPtr)(void *old_address, size_t old_size, size_t new_size, int flags);
   void * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_mremap(old_address, old_size, new_size, flags);
  }
   return ret;

}

int __wrap_munmap(void *addr, size_t length) {
   static int (*fncPtr)(void *addr, size_t length);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_munmap(addr, length);
  }
   return ret;

}

ssize_t __wrap_read(int fd, void *buf, size_t count) {
   static ssize_t (*fncPtr)(int fd, void *buf, size_t count);
   ssize_t ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_read(fd, buf, count);
  }
   return ret;

}

ssize_t __wrap_write(int fd, const void *buf, size_t count) {
   static ssize_t (*fncPtr)(int fd, const void *buf, size_t count);
   ssize_t ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_write(fd, buf, count);
  }
   return ret;

}

int __wrap_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
   static int (*fncPtr)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_select(nfds, readfds, writefds, exceptfds, timeout);
  }
   return ret;

}

off_t __wrap_lseek(int fd, off_t offset, int whence) {
   static off_t (*fncPtr)(int fd, off_t offset, int whence);
   off_t ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_lseek(fd, offset, whence);
  }
   return ret;

}

int __wrap_unlink(const char *pathname) {
   static int (*fncPtr)(const char *pathname);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_unlink(pathname);
  }
   return ret;

}

int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex) {
   static int (*fncPtr)(pthread_mutex_t *mutex);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_mutex_lock(mutex);
  }
   return ret;

}

int __wrap_pthread_mutex_trylock(pthread_mutex_t *mutex) {
   static int (*fncPtr)(pthread_mutex_t *mutex);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_mutex_trylock(mutex);
  }
   return ret;

}

int __wrap_pthread_mutex_unlock(pthread_mutex_t *mutex) {
   static int (*fncPtr)(pthread_mutex_t *mutex);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_mutex_unlock(mutex);
  }
   return ret;

}

int __wrap_pthread_rwlock_unlock(pthread_rwlock_t *rwlock) {
   static int (*fncPtr)(pthread_rwlock_t *rwlock);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_rwlock_unlock(rwlock);
  }
   return ret;

}

int __wrap_pthread_rwlock_rdlock(pthread_rwlock_t *rwlock) {
   static int (*fncPtr)(pthread_rwlock_t *rwlock);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_rwlock_rdlock(rwlock);
  }
   return ret;

}

int __wrap_pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock) {
   static int (*fncPtr)(pthread_rwlock_t *rwlock);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_rwlock_tryrdlock(rwlock);
  }
   return ret;

}

int __wrap_pthread_rwlock_wrlock(pthread_rwlock_t *rwlock) {
   static int (*fncPtr)(pthread_rwlock_t *rwlock);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_rwlock_wrlock(rwlock);
  }
   return ret;

}

int __wrap_pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock) {
   static int (*fncPtr)(pthread_rwlock_t *rwlock);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_rwlock_trywrlock(rwlock);
  }
   return ret;

}

int __wrap_pthread_cond_broadcast(pthread_cond_t *cond) {
   static int (*fncPtr)(pthread_cond_t *cond);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_cond_broadcast(cond);
  }
   return ret;

}

int __wrap_pthread_cond_destroy(pthread_cond_t *cond) {
   static int (*fncPtr)(pthread_cond_t *cond);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_cond_destroy(cond);
  }
   return ret;

}

int __wrap_pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
   static int (*fncPtr)(pthread_cond_t *cond, const pthread_condattr_t *attr);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_cond_init(cond, attr);
  }
   return ret;

}

int __wrap_pthread_cond_signal(pthread_cond_t *cond) {
   static int (*fncPtr)(pthread_cond_t *cond);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_cond_signal(cond);
  }
   return ret;

}

int __wrap_pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime) {
   static int (*fncPtr)(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_cond_timedwait(cond, mutex, abstime);
  }
   return ret;

}

int __wrap_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
   static int (*fncPtr)(pthread_cond_t *cond, pthread_mutex_t *mutex);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_pthread_cond_wait(cond, mutex);
  }
   return ret;

}

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
   static int (*fncPtr)(struct pollfd *fds, nfds_t nfds, int timeout);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_poll(fds, nfds, timeout);
  }
   return ret;

}

int __wrap_waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) {
   static int (*fncPtr)(idtype_t idtype, id_t id, siginfo_t *infop, int options);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_waitid(idtype, id, infop, options);
  }
   return ret;

}

pid_t __wrap_wait4(pid_t pid, int* status, int options, struct rusage *rusage) {
   static pid_t (*fncPtr)(pid_t pid, int* status, int options, struct rusage *rusage);
   pid_t ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_wait4(pid, status, options, rusage);
  }
   return ret;

}

int __wrap_shmget(int key, size_t size, int shmflg) {
   static int (*fncPtr)(int key, size_t size, int shmflg);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_shmget(key, size, shmflg);
  }
   return ret;

}

void *__wrap_shmat(int shmid, const void *shmaddr, int shmflg) {
   static void * (*fncPtr)(int shmid, const void *shmaddr, int shmflg);
   void * ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_shmat(shmid, shmaddr, shmflg);
  }
   return ret;

}

int __wrap_shmdt(const void *shmaddr) {
   static int (*fncPtr)(const void *shmaddr);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_shmdt(shmaddr);
  }
   return ret;

}

int __wrap_shmctl(int shmid, int cmd, struct shmid_ds *buf) {
   static int (*fncPtr)(int shmid, int cmd, struct shmid_ds *buf);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_shmctl(shmid, cmd, buf);
  }
   return ret;

}

int __wrap_semget(key_t key, int nsems, int semflg) {
   static int (*fncPtr)(key_t key, int nsems, int semflg);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_semget(key, nsems, semflg);
  }
   return ret;

}

int __wrap_semop(int semid, struct sembuf *sops, size_t nsops) {
   static int (*fncPtr)(int semid, struct sembuf *sops, size_t nsops);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_semop(semid, sops, nsops);
  }
   return ret;

}

int __wrap_semtimedop(int semid, struct sembuf *sops, size_t nsops, const struct timespec *timeout) {
   static int (*fncPtr)(int semid, struct sembuf *sops, size_t nsops, const struct timespec *timeout);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_semtimedop(semid, sops, nsops, timeout);
  }
   return ret;

}

int __wrap_semctl(int semid, int semnum, int cmd) {
   static int (*fncPtr)(int semid, int semnum, int cmd);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_semctl(semid, semnum, cmd);
  }
   return ret;

}

int __wrap_msgget(key_t key, int msgflg) {
   static int (*fncPtr)(key_t key, int msgflg);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_msgget(key, msgflg);
  }
   return ret;

}

int __wrap_msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg) {
   static int (*fncPtr)(int msqid, const void *msgp, size_t msgsz, int msgflg);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_msgsnd(msqid, msgp, msgsz, msgflg);
  }
   return ret;

}

ssize_t __wrap_msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) {
   static ssize_t (*fncPtr)(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
   ssize_t ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg);
  }
   return ret;

}

int __wrap_msgctl(int msqid, int cmd, struct msqid_ds *buf) {
   static int (*fncPtr)(int msqid, int cmd, struct msqid_ds *buf);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_msgctl(msqid, cmd, buf);
  }
   return ret;

}

mqd_t __wrap_mq_open(const char *name, int oflag, mode_t mode, struct mq_attr *attr) {
   static mqd_t (*fncPtr)(const char *name, int oflag, mode_t mode, struct mq_attr *attr);
   mqd_t ret;
 if(dmtcp_loaded==1) {
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
 else{
      printf("Function not found mq_open\n");//
      ret=__real_mq_open(name, oflag, mode, attr);
  }
   return ret;

}

int __wrap_mq_close(mqd_t mqdes) {
   static int (*fncPtr)(mqd_t mqdes);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
      printf("Function not found mq_close\n");//
     ret=__real_mq_close(mqdes);
  }
   return ret;

}

int __wrap_mq_notify(mqd_t mqdes, const struct sigevent *sevp) {
   static int (*fncPtr)(mqd_t mqdes, const struct sigevent *sevp);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     printf("Function not found mq_notify\n");//ret=__real_mq_notify(mqdes, sevp);
  }
   return ret;

}

ssize_t __wrap_mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio, const struct timespec *abs_timeout) {
   static ssize_t (*fncPtr)(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio, const struct timespec *abs_timeout);
   ssize_t ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
  }
   return ret;

}

int __wrap_mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout) {
   static int (*fncPtr)(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout);
   int ret;
 if(dmtcp_loaded==1) {
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
 else{
     ret=__real_mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
  }
   return ret;

}
