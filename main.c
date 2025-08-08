#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "globals.h"
#include "strings.h"
#include "value_type.h"

#define INITIAL_CAPACITY 4096 * 4096 // 16MB

size_t get_byte_count(const ValueType type) {
  switch (type) {
  case INT8:
  case UINT8:
    return sizeof(int8_t);
  case INT16:
  case UINT16:
    return sizeof(int16_t);
  case INT32:
  case UINT32:
  case FLOAT32:
    return sizeof(int32_t);
  case INT64:
  case UINT64:
  case DOUBLE64:
    return sizeof(int64_t);

  case STRING:
    return 0; // TODO: Handle this later

  default:
    exit_error("Invalid type");
    return 0;
  }
}

typedef struct {
  bool read;
  bool write;
  bool execute;
  bool private;
  bool shared;
} MemoryPermission;

typedef struct {
  unsigned long start;
  unsigned long end;
  MemoryPermission permission;
} ProcessMemoryRegion;

typedef struct {
  size_t size;
  size_t capacity;
  ProcessMemoryRegion *regions;
} PMRegionArray;

PMRegionArray pmregion_array_create(const size_t capacity) {
  PMRegionArray pmregion_array;

  pmregion_array.capacity = capacity;
  pmregion_array.size = 0;

  pmregion_array.regions = calloc(capacity, sizeof(PMRegionArray));

  return pmregion_array;
};

void pmregion_array_insert(PMRegionArray *array,
                           const ProcessMemoryRegion region) {
  if (array->size >= array->capacity) {
    array->capacity *= GROWTH_FACTOR;
    ProcessMemoryRegion *regions =
        realloc(array->regions, array->capacity * sizeof(ProcessMemoryRegion));

    if (array->regions == NULL) {
      exit_error("Error allocating memory regions");
    }

    array->regions = regions;
  }

  array->regions[array->size] = region;
  array->size++;
}

void pmregion_array_destroy(const PMRegionArray *pmregion_array) {
  free(pmregion_array->regions);
}

void print_memory_region(const ProcessMemoryRegion region) {
  // Print the memory region start and end addresses
  printf("Range: [0x%lx - 0x%lx]\tPermissions: [", region.start, region.end);

  // Print the permissions
  printf("%c", region.permission.read ? 'r' : '-');    // Read permission
  printf("%c", region.permission.write ? 'w' : '-');   // Write permission
  printf("%c", region.permission.execute ? 'x' : '-'); // Execute permission
  printf("%c", region.permission.shared
                   ? 's'
                   : 'p'); // Shared/Private (s = shared, p = private)

  printf("]\n");
}

void print_memory_regions(const PMRegionArray *pmregion_array) {
  printf("Found regions: %ld", pmregion_array->size);
  for (size_t i = 0; i < pmregion_array->size; i++) {
    print_memory_region(pmregion_array->regions[i]);
  }
}

typedef struct {
  size_t size;
  size_t capacity;
  unsigned long *items;
} ULongArray;

ULongArray ulong_array_create(const size_t capacity) {
  ULongArray array;
  array.capacity = capacity;
  array.size = 0;
  array.items = calloc(array.capacity, sizeof(unsigned long));

  return array;
}

void ulong_array_destroy(const ULongArray *array) { free(array->items); }

void ulong_array_insert(ULongArray *array, const unsigned long item) {
  if (array->size >= array->capacity) {
    array->capacity *= GROWTH_FACTOR;
    unsigned long *items =
        realloc(array->items, array->capacity * sizeof(unsigned long));

    if (items == NULL) {
      perror("reallocate");
      exit(EXIT_FAILURE);
    }

    array->items = items;
  }

  array->items[array->size] = item;
  array->size++;
}

void ulong_array_clear(ULongArray *array) { array->size = 0; }

void read_process_memory(String *string, const pid_t pid) {
  char proc_file_path[256];

  snprintf(proc_file_path, sizeof(proc_file_path), "/proc/%d/maps", pid);

  string_readfile(string, proc_file_path);
}

ssize_t read_line(const char *str, char *buffer) {
  ssize_t bytes_read = 0;
  if (*str == '\0')
    return bytes_read;
  do {
    *buffer++ = *str++;
    bytes_read++;
  } while (*str != '\n');
  *buffer = '\0';

  return bytes_read;
}

MemoryPermission parse_permissions(const char *perm_str) {
  if (strlen(perm_str) != 4) {
    perror("permissions");
    exit(EXIT_FAILURE);
  }

  const MemoryPermission permissions = {
      .read = perm_str[0] == 'r',
      .write = perm_str[1] == 'w',
      .execute = perm_str[2] == 'x',
      .private = perm_str[3] == 'p',
      .shared = perm_str[3] == 's',
  };

  return permissions;
}

void regions_fill(PMRegionArray *regions, String *process_map) {
  char line_buffer[1024];
  ssize_t bytes_read = 0;
  while ((bytes_read = read_line(process_map->str, line_buffer)) != 0) {
    char *range = strtok(line_buffer, " ");
    const char *perm_str = strtok(NULL, " ");
    const char *start_str = strtok(range, "-");
    const char *end_str = strtok(NULL, "-");

    const unsigned long start = strtoul(start_str, NULL, 16);
    const unsigned long end = strtoul(end_str, NULL, 16);
    const MemoryPermission permissions = parse_permissions(perm_str);

    ProcessMemoryRegion region;

    region.start = start;
    region.end = end;
    region.permission = permissions;

    if (permissions.write) {
      pmregion_array_insert(regions, region);
    }

    process_map->str = process_map->str + (bytes_read + 1);
  }
}

long mask_data(long data, const size_t byte_count) {
  if (byte_count == 1) {
    data &= 0xFFL;
  } else if (byte_count == 2) {
    data &= 0xFFFFL;
  } else if (byte_count == 4) {
    data &= 0xFFFFFFFFL;
  } else if (byte_count == 8) {
    data &= 0xFFFFFFFFFFFFFFFFL;
  }

  return data;
}

long patch_byte(const long original, const long value) {
  return (original & ~0xFFL) | (value & 0xFFL);
}

long patch_word(const long original, const long value) {
  return (original & ~0xFFFFL) | (value & 0xFFFFL);
}

long patch_dword(const long original, const long value) {
  return (original & ~0xFFFFFFFFL) | (value & 0xFFFFFFFFL);
}

long patch_qword(const long original, const long value) {
  return (original & ~0xFFFFFFFFFFFFFFFFL) | (value & 0xFFFFFFFFFFFFFFFFL);
}

long patch_data(const long original, const long value,
                const size_t byte_count) {
  if (byte_count == 1) {
    return patch_byte(original, value);
  }
  if (byte_count == 2) {
    return patch_word(original, value);
  }
  if (byte_count == 4) {
    return patch_dword(original, value);
  }
  if (byte_count == 8) {
    return patch_qword(original, value);
  }
  exit_error("Invalid patch data size");
  return 0;
}

void initial_scan(const pid_t pid, const PMRegionArray regions,
                  const long target, ULongArray *offset_array,
                  const ValueType type) {
  const size_t byte_count = get_byte_count(type);

  for (ssize_t i = 0; i < regions.size; i++) {
    unsigned long start = regions.regions[i].start;
    const unsigned long end = regions.regions[i].end;

    // printf("Scanning from 0x%lx -> 0x%lx\n", start, end);

    // TODO: Optimize this later by comparing slices of data instead of stepping
    // by byte_count
    while (start < end) {
      long data = ptrace(PTRACE_PEEKDATA, pid, start, NULL);

      data = mask_data(data, byte_count);
      const long masked_target = mask_data(target, byte_count);
      if (data == masked_target) {
        // printf("Found %ld at 0x%lx\n", target, start);
        ulong_array_insert(offset_array, start);
      }

      start += byte_count;
    }
  }
}

void initial_scan_ld(const pid_t pid, const PMRegionArray regions,
                     const double target, ULongArray *offset_array,
                     const ValueType type) {
  const size_t byte_count = get_byte_count(type);

  for (ssize_t i = 0; i < regions.size; i++) {
    unsigned long start = regions.regions[i].start;
    const unsigned long end = regions.regions[i].end;

    // TODO: Optimize this later by comparing slices of data instead of stepping
    // by byte_count
    while (start < end) {
      long data = ptrace(PTRACE_PEEKDATA, pid, start, NULL);

      data = mask_data(data, byte_count);

      double ldvalue;
      memcpy(&ldvalue, &data, sizeof(double));

      const double masked_target = mask_data(target, byte_count);

      printf("%f\n", masked_target);

      if (ldvalue == masked_target) {
        printf("Found %f at 0x%lx\n", masked_target, start);
        ulong_array_insert(offset_array, start);
      }

      start += byte_count;
    }
  }
}

void initial_scan_str(const pid_t pid, const PMRegionArray regions,
                      const String string, ULongArray *offset_array) {

  for (ssize_t i = 0; i < regions.size; i++) {
    unsigned long start = regions.regions[i].start;
    const unsigned long end = regions.regions[i].end;
    const size_t string_len = string.size;

    // TODO: Optimize this later by comparing slices of data instead of stepping
    // by byte_count
    while (start < end) {
      long data = ptrace(PTRACE_PEEKDATA, pid, start, NULL);

      // if (data == target) {
      //     // printf("Found %ld at 0x%lx\n", target, start);
      //     ulong_array_insert(offset_array, start);
      // }

      start += 8;
    }
  }
}

ULongArray next_scan(const pid_t pid, const long target,
                     const ULongArray *offset_array, const ValueType type) {
  ULongArray filtered_offsets = ulong_array_create(1000);
  const size_t byte_count = get_byte_count(type);

  for (ssize_t i = 0; i < offset_array->size; i++) {
    long data = ptrace(PTRACE_PEEKDATA, pid, offset_array->items[i], NULL);

    data = mask_data(data, byte_count);
    const long masked_target = mask_data(target, byte_count);

    if (data == masked_target) {
      printf("Found %ld at 0x%lx\n", target, offset_array->items[i]);
      ulong_array_insert(&filtered_offsets, offset_array->items[i]);
    }
  }

  return filtered_offsets;
}

void look(const pid_t pid, const unsigned long offset, const ValueType type) {
  long data = ptrace(PTRACE_PEEKDATA, pid, offset, NULL);
  const size_t byte_count = get_byte_count(type);
  data = mask_data(data, byte_count);

  switch (type) {
  case INT8:
    printf("Value at 0x%lx: %d\n", offset, (char)data);
    break;
  case INT16:
    printf("Value at 0x%lx: %d\n", offset, (short)data);
    break;
  case INT32:
    printf("Value at 0x%lx: %d\n", offset, (int)data);
    break;
  case INT64:
    printf("Value at 0x%lx: %ld\n", offset, data);
    break;

  case UINT8:
    printf("Value at 0x%lx: %u\n", offset, (unsigned char)data);
    break;
  case UINT16:
    printf("Value at 0x%lx: %u\n", offset, (unsigned short)data);
    break;
  case UINT32:
    printf("Value at 0x%lx: %u\n", offset, (unsigned int)data);
    break;
  case UINT64:
    printf("Value at 0x%lx: %lu\n", offset, (unsigned long)data);
    break;

  case FLOAT32: {
    float fvalue;
    memcpy(&fvalue, &data, sizeof(float));
    printf("Value at 0x%lx: %f\n", offset, fvalue);
    break;
  }
  case DOUBLE64: {
    double dvalue;
    memcpy(&dvalue, &data, sizeof(double));
    printf("Value at 0x%lx: %f\n", offset, dvalue);
    break;
  }
  default:
    printf("Invalid type\n");
  }
}

void update(const pid_t pid, const unsigned long offset, const long value,
            const ValueType type) {
  const long original = ptrace(PTRACE_PEEKDATA, pid, offset, NULL);

  if (original == -1) {
    exit_error("Error reading from process file");
  }

  const size_t byte_count = get_byte_count(type);
  const long patched = patch_data(original, value, byte_count);

  const long result = ptrace(PTRACE_POKEDATA, pid, offset, patched);

  if (result == -1) {
    exit_error("Error patching value");
  }

  printf("Set new value %ld at 0x%lx\n", value, offset);
}

void show(const ULongArray offsets, const long target) {
  for (int i = 0; i < offsets.size; i++) {
    printf("Found %ld at 0x%lx\n", target, offsets.items[i]);
  }
}

pid_t get_pid(const char *process_name) {
  char pgrep_command[256];

  snprintf(pgrep_command, sizeof(pgrep_command), "pgrep %s", process_name);

  FILE *file = popen(pgrep_command, "r");

  if (file == NULL) {
    exit_error("popen() failed");
  }

  char pid_str[10];

  fgets(pid_str, sizeof(pid_str), file);

  const pid_t pid = atoi(pid_str);

  return pid;
}

typedef struct {
  int *numbers;
  int start;
  int end;
  int id;
} Arguments;

static pthread_t thread_a;

int main(const int argc, const char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <process_name>\n", argv[0]);
    exit_error("Wrong number of arguments");
  }

  const char *process_name = argv[1];
  const pid_t pid = get_pid(process_name);
  // const pid_t pid = atoi(process_name);

  String process_memory_map = string_create(INITIAL_CAPACITY);
  PMRegionArray regions = pmregion_array_create(INITIAL_CAPACITY);
  ULongArray offset_array = ulong_array_create(INITIAL_CAPACITY);

  read_process_memory(&process_memory_map, pid);
  regions_fill(&regions, &process_memory_map);

  if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) == -1) {
    perror("ptrace seize");
    exit(EXIT_FAILURE);
  }

  ValueType current_type = UNKNOWN;

  char command_buffer[256];
  // char last_command[256];

  while (true) {
    printf("[memsniffer]>_ ");
    // Commands:
    // new <type> <value>
    // next <value>
    // look <type> <region>
    // update <type> <region> <value>
    // lookall <type>
    // exit

    fgets(command_buffer, sizeof(command_buffer), stdin);

    command_buffer[strcspn(command_buffer, "\n")] = '\0';

    const char *command = strtok(command_buffer, " ");

    // strcpy(last_command, command);

    int status = 0;

    ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);

    if (waitpid(pid, &status, 0) == -1) {
      perror("waitpid");
      exit(EXIT_FAILURE);
    }

    if (WIFSTOPPED(status)) {
      if (strcmp("new", command) == 0) {
        ulong_array_clear(&offset_array);

        char *type_str = strtok(NULL, " ");
        const char *target_str = strtok(NULL, " ");
        printf("Looking for new %s value: %s\n", type_str, target_str);

        current_type = parse_argtype(type_str);

        if (current_type == STRING) {
          String string = string_create(1024);
          string_from_chars(&string, target_str);
          initial_scan_str(pid, regions, string, &offset_array);
        }

        else if (current_type == FLOAT32 || current_type == DOUBLE64) {
          const double target_double = strtod(target_str, NULL);
          initial_scan_ld(pid, regions, target_double, &offset_array,
                          current_type);
        }

        else {
          const long target = strtol(target_str, NULL, 10);

          initial_scan(pid, regions, target, &offset_array, current_type);
        }
      } else if (strcmp("next", command) == 0) {
        const char *target_str = strtok(NULL, " ");
        const long target = strtol(target_str, NULL, 10);

        printf("Looking for next value: %s\n", target_str);
        const ULongArray filtered =
            next_scan(pid, target, &offset_array, current_type);

        memcpy(offset_array.items, filtered.items,
               filtered.size * (sizeof(unsigned long)));

        offset_array.size = filtered.size;
      } else if (strcmp("look", command) == 0) {
        char *type_str = strtok(NULL, " ");
        const char *offset_str = strtok(NULL, " ");
        const unsigned long offset = strtoul(offset_str, NULL, 16);

        const ValueType type = parse_argtype(type_str);

        look(pid, offset, type);
      } else if (strcmp("lookall", command) == 0) {
        char *type_str = strtok(NULL, " ");
        const ValueType type = parse_argtype(type_str);

        for (int i = 0; i < offset_array.size; i++) {
          look(pid, offset_array.items[i], type);
        }
      } else if (strcmp("update", command) == 0) {
        char *type_str = strtok(NULL, " ");
        const ValueType type = parse_argtype(type_str);

        const char *offset_str = strtok(NULL, " ");
        const unsigned long offset = strtoul(offset_str, NULL, 16);

        const char *value_str = strtok(NULL, " ");
        const long value = strtol(value_str, NULL, 10);

        update(pid, offset, value, type);
      } else if (strcmp("exit", command) == 0) {
        printf("Exiting...\n");
        break;
      }
    }

    if (ptrace(PTRACE_CONT, pid, NULL, 0) == -1) {
      exit_error("Error continuing process");
    }
  }

  string_destroy(&process_memory_map);
  ulong_array_destroy(&offset_array);
  pmregion_array_destroy(&regions);

  ptrace(PTRACE_DETACH, pid, NULL, NULL);
  return EXIT_SUCCESS;
}
