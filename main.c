#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

void exit_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
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

void pmregion_array_insert(PMRegionArray *array, const ProcessMemoryRegion region) {
    if (array->size >= array->capacity) {
        array->capacity *= 2;
        ProcessMemoryRegion *regions = realloc(array->regions, array->capacity * sizeof(ProcessMemoryRegion));

        if (array->regions == NULL) {
            exit_error("Error allocating memory regions");
        }

        array->regions = regions;
    }

    array->regions[array->size] = region;
    array->size++;
}

void pmregion_array_destroy(const PMRegionArray* pmregion_array) {
    free(pmregion_array->regions);
}

void print_memory_region(const ProcessMemoryRegion region) {
    // Print the memory region start and end addresses
    printf("Range: [0x%lx - 0x%lx]\tPermissions: [", region.start, region.end);

    // Print the permissions
    printf("%c", region.permission.read ? 'r' : '-'); // Read permission
    printf("%c", region.permission.write ? 'w' : '-'); // Write permission
    printf("%c", region.permission.execute ? 'x' : '-'); // Execute permission
    printf("%c", region.permission.shared ? 's' : 'p'); // Shared/Private (s = shared, p = private)

    printf("]\n");
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

void ulong_array_destroy(const ULongArray *array) {
    free(array->items);
}

void ulong_array_insert(ULongArray *array, const unsigned long item) {
    if (array->size >= array->capacity) {
        array->capacity *= 2;
        unsigned long *items = realloc(array->items, array->capacity * sizeof(unsigned long));

        if (items == NULL) {
            perror("reallocate");
            exit(EXIT_FAILURE);
        }

        array->items = items;
    }

    array->items[array->size] = item;
    array->size++;
}

void ulong_array_clear(ULongArray *array) {
    array->size = 0;
}

typedef struct {
    ssize_t size;
    ssize_t capacity;
    char *str;
} String;

String string_create(const ssize_t capacity) {
    String array;
    array.capacity = capacity;
    array.size = 0;
    array.str = malloc(capacity * sizeof(char));

    return array;
}

void string_destroy(const String *string) {
    free(string->str);
}

void string_insert(String *string, const char *item) {
    if (string->size == string->capacity) {
        string->capacity *= 2;
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

void read_process_memory(String *string, const pid_t pid) {
    char proc_file_path[256];

    snprintf(proc_file_path, sizeof(proc_file_path), "/proc/%d/maps", pid);

    string_readfile(string, proc_file_path);
}

ssize_t read_line(const char *str, char *buffer) {
    ssize_t bytes_read = 0;
    if (*str == '\0') return bytes_read;
    do {
        *buffer++ = *str++;
        bytes_read++;
    } while (*str != '\n');
    *buffer = '\0';
    // buffer -= bytes_read; // No need because pointers are passed by value in C

    return bytes_read;
}

MemoryPermission parse_permissions(const char *perm_str) {
    MemoryPermission permissions = {
        .read = false,
        .write = false,
        .execute = false,
        .private = false,
        .shared = false,
    };

    if (strlen(perm_str) != 4) {
        perror("permissions");
        exit(EXIT_FAILURE);
    }

    permissions.read = perm_str[0] == 'r';
    permissions.write = perm_str[1] == 'w';
    permissions.execute = perm_str[2] == 'x';
    permissions.private = perm_str[3] == 'p';
    permissions.shared = perm_str[3] == 's';

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

void initial_scan(const pid_t pid, const PMRegionArray regions, const int target,
                  ULongArray *offset_array) {
    for (ssize_t i = 0; i < regions.size; i++) {
        unsigned long start = regions.regions[i].start;
        const unsigned long end = regions.regions[i].end;

        // printf("Scanning from 0x%lx -> 0x%lx\n", start, end);

        while (start < end) {
            const long data = ptrace(PTRACE_PEEKDATA, pid, start, NULL);

            if (data == target) {
                printf("Found %d at 0x%lx\n", target, start);
                ulong_array_insert(offset_array, start);
            }

            start += 8;
        }
    }
}

ULongArray next_scan(const pid_t pid, const int target, const ULongArray *offset_array) {
    ULongArray filtered_offsets = ulong_array_create(1000);

    ssize_t count = 0;
    // printf("Scanning...\n");
    for (ssize_t i = 0; i < offset_array->size; i++) {
        const long data = ptrace(PTRACE_PEEKDATA, pid, offset_array->items[i], NULL);

        if (data == target) {
            printf("Found %d at 0x%lx\n", target, offset_array->items[i]);
            ulong_array_insert(&filtered_offsets, offset_array->items[i]);
        }
    }

    return filtered_offsets;
}

void look(const pid_t pid, const unsigned long offset) {
    const long data = ptrace(PTRACE_PEEKDATA, pid, offset, NULL);

    printf("Value at 0x%lx: %ld\n", offset, data);
}

void update(const pid_t pid, const unsigned long offset, const int value) {
    ptrace(PTRACE_POKEDATA, pid, offset, value);

    printf("Set new value %d at 0x%lx\n", value, offset);
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

int main(const int argc, const char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <process_name>\n", argv[0]);
        exit_error("Wrong number of arguments");
    }

    const char *process_name = argv[1];
    const pid_t pid = get_pid(process_name);

    String process_memory_map = string_create(1024);
    PMRegionArray regions = pmregion_array_create(1024);
    ULongArray offset_array = ulong_array_create(1024);

    read_process_memory(&process_memory_map, pid);
    regions_fill(&regions, &process_memory_map);

    if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) == -1) {
        perror("ptrace seize");
        exit(EXIT_FAILURE);
    }


    while (true) {
        char command_buffer[256];
        printf("[memscan]_> ");

        fgets(command_buffer, sizeof(command_buffer), stdin);

        command_buffer[strcspn(command_buffer, "\n")] = '\0';

        const char *command = strtok(command_buffer, " ");

        int status = 0;

        ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            exit(EXIT_FAILURE);
        }

        if (WIFSTOPPED(status)) {
            if (strcmp("new", command) == 0) {
                ulong_array_clear(&offset_array);
                const char *target_str = strtok(NULL, " ");
                const int target = atoi(target_str);

                printf("Looking for new value: %s\n", target_str);
                initial_scan(pid, regions, target, &offset_array);
            } else if (strcmp("next", command) == 0) {
                const char *target_str = strtok(NULL, " ");
                const int target = atoi(target_str);

                printf("Looking for next value: %s\n", target_str);
                const ULongArray filtered = next_scan(pid, target, &offset_array);

                memcpy(offset_array.items, filtered.items, filtered.size * (sizeof(unsigned long)));

                offset_array.size = filtered.size;
            } else if (strcmp("look", command) == 0) {
                const char *offset_str = strtok(NULL, " ");
                const unsigned long offset = strtoul(offset_str, NULL, 16);
                look(pid, offset);
            } else if (strcmp("update", command) == 0) {
                const char *offset_str = strtok(NULL, " ");
                const unsigned long offset = strtoul(offset_str, NULL, 16);

                const char *value_str = strtok(NULL, " ");
                const int value = atoi(value_str);

                update(pid, offset, value);
            } else if (strcmp("exit", command) == 0) {
                ptrace(PTRACE_DETACH, pid, NULL, NULL);
                printf("Exiting...\n");
                break;
            }
        }

        if (ptrace(PTRACE_CONT, pid, NULL, 0) == -1) {
            perror("ptrace cont");
            exit(EXIT_FAILURE);
        }
    }

    string_destroy(&process_memory_map);
    ulong_array_destroy(&offset_array);
    pmregion_array_destroy(&regions);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return EXIT_SUCCESS;
}
