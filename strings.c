#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "globals.h"
#include "strings.h"

void to_lowercase(char *s) {
  while (*s != '\0') {
    *s = (char)tolower(*s);
    s++;
  }
}

String string_create(const ssize_t capacity) {
  String array;
  array.capacity = capacity;
  array.size = 0;
  array.str = malloc(capacity * sizeof(char));

  return array;
}

void string_destroy(const String *string) { free(string->str); }

void string_insert(String *string, const char *item) {
  if (string->size == string->capacity) {
    string->capacity *= GROWTH_FACTOR;
    char *buf = realloc(string->str, string->capacity);

    if (buf == NULL) {
      perror("reallocate");
      exit(EXIT_FAILURE);
    }

    string->str = buf;
  }

  string->str[string->size] = *item;
  string->size++;
}

void string_from_chars(String *string, const char *str) {
  while (*str != '\0') {
    string_insert(string, str);
    str++;
  }
}

void string_readfile(String *string, const char *filename) {
  const int fd = open(filename, O_RDONLY);

  if (fd == -1) {
    perror("open");
  }

  char read_buf[1];

  ssize_t bytes_read;
  while ((bytes_read = read(fd, read_buf, 1)) != 0) {
    if (bytes_read == -1) {
      exit_error("Error reading from process file");
    }

    string_insert(string, read_buf);
  }
}
