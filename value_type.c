#include <string.h>
#include "value_type.h"
#include "globals.h"
#include "strings.h"

ValueType parse_argtype(char *type_str) {
  to_lowercase(type_str);

  // Signed Integers
  if (strcmp(type_str, "int8") == 0) {
    return INT8;
  }
  if (strcmp(type_str, "int16") == 0) {
    return INT16;
  }
  if (strcmp(type_str, "int32") == 0) {
    return INT32;
  }
  if (strcmp(type_str, "int64") == 0) {
    return INT64;
  }

  // Unsigned Integers
  if (strcmp(type_str, "uint8") == 0) {
    return UINT8;
  }
  if (strcmp(type_str, "uint16") == 0) {
    return UINT16;
  }
  if (strcmp(type_str, "uint32") == 0) {
    return UINT32;
  }
  if (strcmp(type_str, "uint64") == 0) {
    return UINT64;
  }

  // Decimals
  if (strcmp(type_str, "float32") == 0) {
    return FLOAT32;
  }
  if (strcmp(type_str, "double64") == 0) {
    return DOUBLE64;
  }

  exit_error("Invalid type");
  return UNKNOWN;
}
