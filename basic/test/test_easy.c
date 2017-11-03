#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int check(int argc, char **argv)
{
  char input[0x4];
  if(argc <= 1){
    printf("moar arrrrgs plz\n");
    exit(1);
  }

  int fd = open(argv[1], O_RDONLY);
  read(fd, input, 65536);

  if(input[-1] == 'A') system("/bin/sh");
  
  return 0;
}

int main(int argc, char **argv) {
  return check(argc, argv);
}
