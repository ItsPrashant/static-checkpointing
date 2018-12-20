#include <stdio.h>
#include <ucontext.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <asm/prctl.h>
#include <sys/prctl.h>


void hello()
{
  printf("Hello()\n");
}
int main(int argc, char const *argv[]) {
  printf("In application\n");
  printf("Hello. I m back\n");
  int a=100;
  FILE* fp=fopen("abc","w");
  if(fp==NULL){
    printf("Can't open file\n" );
  }else
  printf("File Opened\n");
  if(fwrite(&a,sizeof(a),1,fp)==0){
    printf("write failed\n" );
  }
  int i=0;
  while (1) {
    printf("%d ", i);
    fflush(stdout);
    sleep(1);
    i++;
  }
  return 0;
}


/*
void loader(int argc, char const *argv[])
{
  ucontext_t context;
  int flag=0;
  if(getcontext(&context)==-1)
	{
		printf("getcontext Failed\n");
	}

  if (flag==0) {

    flag=1;
    FILE *fp=fopen("context.bin","wb");

    if (fwrite(&context,sizeof(ucontext_t),1,fp)==0) {
      printf("Write Failed\n");
    }

    if (fclose(fp)!=0) {
      printf("Unable to close file\n");
    }

    printf("Going into rtld()\n");
    runRtld();
    printf("ld.so and dummy program loaded successfully :)\n");
  }

}
*/
