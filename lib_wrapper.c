#include <stdio.h>
#include <ucontext.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include "lib_wrapper.h"
//#include "kernel-loader.h"
unsigned long long fsValue1=0,fsValue2=0;
void *soPtr;
void* (*mydlsym)(void*,char*)=NULL;

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

    if (fclose(fp)!=0) {
      printf("Unable to close file\n");
    }
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
  if(fclose(fp)!=0){
    fprintf(stderr, "Error closing file\n" );
  }
  mydlsym=ptr;
}


int __wrap_open(const char *file,int mode)
{
  int ret;
  static int (*funcPtr)(const char*,int)=NULL;
  //printf("Before if()\n");
  if(set_fs_dmtcp()==-1){
    fprintf(stderr, "Error setting fs\n" );
    exit(-1);
  }
  if(funcPtr==NULL)
  {
    funcPtr=(*mydlsym)(soPtr,"open");
    printf("open(): %p\n",funcPtr);
    if(funcPtr==NULL){
      fprintf(stderr, "*** DMTCP: Error: lookup failed for %s.\n"             \
                      "           The symbol wasn't found in current library" \
                      " loading sequence.\n"                                  \
                      "    Aborting.\n","open");                             \
      abort();                                                                \
    }
  }
  ret=(*funcPtr)(file,mode);
  if(set_fs_application()==-1){
    fprintf(stderr, "Error setting fs\n" );
    exit(-1);
  }
  return ret;

}
