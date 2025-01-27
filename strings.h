#include <stdlib.h>

# ifndef STRINGS_H
# define STRINGS_H
typedef struct {
  size_t size;
  size_t capacity;
  char *str;
} String;

void to_lowercase(char *s);

String string_create(const ssize_t capacity);

void string_destroy(const String *string);

void string_insert(String *string, const char *item);

void string_from_chars(String *string, const char *str);

void string_readfile(String *string, const char *filename);

# endif
