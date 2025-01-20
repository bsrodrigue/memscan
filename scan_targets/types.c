#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  char buffer[256];
  float a = 127.99;

  while (1) {
    printf("Change the value of a\n: ");
    fgets(buffer, sizeof(buffer), stdin);
    a = atof(buffer);
    printf("Value is now: %f\n", a);
  }

  return EXIT_SUCCESS;
}
