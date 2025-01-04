#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

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
    ssize_t size;
    ssize_t capacity;
    char *items;
} Array;

Array array_create(const ssize_t capacity) {
    Array array;
    array.capacity = capacity;
    array.size = 0;
    array.items = malloc(capacity * sizeof(char));

    return array;
}

void array_destroy(const Array *array) {
    free(array->items);
}

void array_insert(Array *array, const char *item) {
    if (array->size == array->capacity) {
        array->capacity *= 2;
        char *buf = realloc(array->items, array->capacity);

        if (buf == NULL) {
            perror("reallocate");
            exit(EXIT_FAILURE);
        }

        array->items = buf;
    }

    array->items[array->size] = *item;
    array->size++;
}

void read_process_memory(Array *array, const pid_t pid) {
    char buf[256];

    snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);

    const int fd = open(buf, O_RDONLY);

    if (fd == -1) {
        perror("open");
    }

    char read_buf[1];

    ssize_t bytes_read;
    while ((bytes_read = read(fd, read_buf, 1)) != 0) {
        if (bytes_read == -1) {
            perror("read");
        }

        array_insert(array, read_buf);
    }
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

void fill_regions(char *maps_str, ProcessMemoryRegion regions[1024], ssize_t *region_count) {
    char line_buffer[1024];
    ssize_t bytes_read = 0;
    while ((bytes_read = read_line(maps_str, line_buffer)) != 0) {
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
            regions[(*region_count)++] = region;
        }

        maps_str = maps_str + (bytes_read + 1);
    }
}

void initial_scan(const pid_t pid, const ProcessMemoryRegion *regions, const ssize_t count, const int target,
                  unsigned long *offsets, ssize_t *offset_count) {
    for (ssize_t i = 0; i < count; i++) {
        unsigned long start = regions[i].start;
        const unsigned long end = regions[i].end;

        // printf("Scanning from 0x%lx -> 0x%lx\n", start, end);

        while (start < end) {
            const long data = ptrace(PTRACE_PEEKDATA, pid, start, NULL);

            if (data == target) {
                printf("Found %d at 0x%lx\n", target, start);
                offsets[(*offset_count)++] = start;
            }

            start += 8;
        }
    }
}

void next_scan(const pid_t pid, const int target, unsigned long *offsets, ssize_t *offset_count) {
    ssize_t count = 0;
    // printf("Scanning...\n");
    for (ssize_t i = 0; i < *offset_count; i++) {
        const long data = ptrace(PTRACE_PEEKDATA, pid, offsets[i], NULL);

        if (data == target) {
            printf("Found %d at 0x%lx\n", target, offsets[i]);
            offsets[count++] = offsets[i];
        }
    }
    *offset_count = count;
}

void look(const pid_t pid, const unsigned long offset) {
    const long data = ptrace(PTRACE_PEEKDATA, pid, offset, NULL);

    printf("Value at 0x%lx: %ld\n", offset, data);
}

void update(const pid_t pid, const unsigned long offset, const int value) {
    ptrace(PTRACE_POKEDATA, pid, offset, value);

    printf("Set new value %d at 0x%lx\n", value, offset);
}


int main(const int argc, const char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    const pid_t pid = atoi(argv[1]);

    ProcessMemoryRegion regions[1024];
    ssize_t region_count = 0;

    Array array = array_create(256);

    read_process_memory(&array, pid);

    fill_regions(array.items, regions, &region_count);

    if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) == -1) {
        perror("ptrace seize");
        exit(EXIT_FAILURE);
    }

    ssize_t offset_count = 0;
    unsigned long offsets[10000];

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
                const char *target_str = strtok(NULL, " ");
                const int target = atoi(target_str);
                offset_count = 0;

                printf("Looking for new value: %s\n", target_str);
                initial_scan(pid, regions, region_count, target, offsets, &offset_count);
            } else if (strcmp("next", command) == 0) {
                const char *target_str = strtok(NULL, " ");
                const int target = atoi(target_str);

                printf("Looking for next value: %s\n", target_str);
                next_scan(pid, target, offsets, &offset_count);
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


    array_destroy(&array);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return EXIT_SUCCESS;
}
