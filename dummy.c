#include <stdio.h>
#include <unistd.h>
#include <ucontext.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <asm/prctl.h>
#include <sys/prctl.h>

int main(int argc, char **argv)
{
  ucontext_t context,my_context;
  printf("In dummy program\n" );
  FILE *dlfp;
  int x=0;
  void *lib=dlopen(NULL,RTLD_LAZY);
  if(lib==NULL){
    fprintf(stderr,"%s\n",dlerror());
  }
  else
    printf("Library loaded\n");

  dlfp=fopen("symbolPointer","wb");

  if (dlfp==NULL) {
    printf("Error opening soPointer file\n" );
    return -1;
  }
  if (fwrite(&lib,sizeof(void*),1,dlfp)==0) {
    printf("Write Failed\n");
  }
  void *ptr=dlsym;

  if (fwrite(&ptr,sizeof(void*),1,dlfp)==0) {
    printf("Write Failed\n");
  }
  if (fclose(dlfp)!=0) {
    printf("Unable to close file\n");
  }
  void (*dmtcp_init)(void)=dlsym(lib,"dmtcp_initialize");
  printf("libraryHandle: %p\n",lib);
  printf("dlsymPtr: %p\n",dlsym);
  printf("dmtcp_initialize(): %p\n",dmtcp_init);

  printf("mq_open(): %p\n",dlsym(lib,"mq_open"));
  unsigned long long fsValue1=0;
  if(arch_prctl(ARCH_GET_FS,&fsValue1)==-1){
    printf("Error getting fs\n" );
  }
  if (argc > 1) {
    printf("Dummy was called with the following args: ");
    for (int j = 1; j < argc; j++) {
      printf("%s ", argv[j]);
    }
    printf("\n");
  }
  FILE *fp = fopen("context.bin","rb");
  if (fp==NULL) {
    printf("Error opening context file\n" );
    return -1;
  }
  if (fread(&context,sizeof(ucontext_t),1,fp)==0) {
    if(ferror(fp)!=0){
      printf("Read Failed\n");
    }
  }
  if (fclose(fp)!=0) {
    printf("Unable to close file\n");
  }
  //while(1);
  /*char conv[20];
  sprintf(conv,"%p",fopen);
  if(setenv("FOPEN_",conv,1)==-1){
    printf("setenv failed\n" );
  }
  */
  getcontext(&my_context);
  fp = fopen("context.bin","wb");
  if (fp==NULL) {
    printf("Error opening context file\n" );
    return -1;
  }
  if (fwrite(&my_context,sizeof(ucontext_t),1,fp)==0) {
    if(ferror(fp)!=0){
      printf("Write Failed\n");
    }
  }
  if (fclose(fp)!=0) {
    printf("Unable to close file\n");
  }

 if(dmtcp_init!=NULL){
    (*dmtcp_init)();
  }

  printf("Switching context\n");

  if(setcontext(&context)==-1){
		printf("setcontext Failed\n");
	}

  return 0;
}
