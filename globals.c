#include <stdio.h>
#include <stdlib.h>

void exit_error(const char *msg) {
  perror(msg);
  exit(EXIT_FAILURE);
}
