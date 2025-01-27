#ifndef VALUE_TYPE_H
#define VALUE_TYPE_H
typedef enum {
  // Signed Integers
  INT8,
  INT16,
  INT32,
  INT64,

  // Unsigned Integers
  UINT8,
  UINT16,
  UINT32,
  UINT64,

  // Floats
  FLOAT32,  // Single Precision
  DOUBLE64, // Double Precision

  STRING,

  UNKNOWN,
} ValueType;

ValueType parse_argtype(char *type_str);
#endif
