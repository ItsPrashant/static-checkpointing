#include <stdio.h>
#include <unistd.h>
#include <ucontext.h>
ucontext_t context;

int main(int argc, char **argv)
{
  int i = 0;
  if (argc > 1) {
    printf("Application was called with the following args: ");
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
  printf("Switching context\n");

  if(setcontext(&context)==-1){
		printf("setcontext Failed\n");
	}
  if (fclose(fp)!=0) {
    printf("Unable to close file\n");
  }
while (1) {
    printf("%d ", i);
    fflush(stdout);
    sleep(1);
    i++;
  }
  return 0;
}
