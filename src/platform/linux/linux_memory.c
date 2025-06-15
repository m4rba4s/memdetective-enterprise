/**
 * Memory Inspector CLI - Linux Memory Operations
 * 
 * Linux-specific memory analysis using /proc filesystem
 * Secure, efficient memory region enumeration and reading
 */

#include "memory_inspector.h"
#include "platform.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#define MAPS_LINE_MAX 512
#define MEM_READ_CHUNK 4096

/**
 * Parse permission string from /proc/[pid]/maps
 */
static mi_permissions_t parse_permissions(const char *perm_str) {
    mi_permissions_t perms = MI_PERM_NONE;
    
    if (perm_str[0] == 'r') perms |= MI_PERM_READ;
    if (perm_str[1] == 'w') perms |= MI_PERM_WRITE;
    if (perm_str[2] == 'x') perms |= MI_PERM_EXEC;
    
    return perms;
}

/**
 * Determine region type from path
 */
static mi_region_type_t determine_region_type(const char *path, uintptr_t start_addr) {
    (void)start_addr;  /* Suppress unused parameter warning */
    if (!path || path[0] == '\0') {
        return MI_REGION_UNKNOWN;
    }
    
    if (strstr(path, "[heap]")) {
        return MI_REGION_HEAP;
    }
    
    if (strstr(path, "[stack]")) {
        return MI_REGION_STACK;
    }
    
    if (strstr(path, "[vdso]")) {
        return MI_REGION_VDSO;
    }
    
    if (strstr(path, "[vsyscall]")) {
        return MI_REGION_VSYSCALL;
    }
    
    if (path[0] == '/') {
        /* Check if it's executable */
        struct stat st;
        if (stat(path, &st) == 0 && (st.st_mode & S_IXUSR)) {
            return MI_REGION_CODE;
        }
        return MI_REGION_SHARED;
    }
    
    return MI_REGION_DATA;
}

/**
 * Check if region is suspicious
 */
static bool is_region_suspicious(const mi_memory_region_t *region) {
    /* Executable + writable regions are highly suspicious */
    if ((region->permissions & MI_PERM_EXEC) && 
        (region->permissions & MI_PERM_WRITE)) {
        return true;
    }
    
    /* Anonymous executable regions */
    if ((region->permissions & MI_PERM_EXEC) && 
        (region->path[0] == '\0' || strstr(region->path, "[anon]"))) {
        return true;
    }
    
    /* Large anonymous regions */
    if (region->size > (100 * 1024 * 1024) && 
        (region->path[0] == '\0' || strstr(region->path, "[anon]"))) {
        return true;
    }
    
    return false;
}

/**
 * Check if region is injected
 */
static bool is_region_injected(const mi_memory_region_t *region, const char *main_exe) {
    /* Skip well-known system regions */
    if (strstr(region->path, "/lib/") || 
        strstr(region->path, "/usr/lib/") ||
        strstr(region->path, "[heap]") ||
        strstr(region->path, "[stack]") ||
        strstr(region->path, "[vdso]") ||
        strstr(region->path, "[vsyscall]")) {
        return false;
    }
    
    /* Check if it's the main executable */
    if (main_exe && strcmp(region->path, main_exe) == 0) {
        return false;
    }
    
    /* Executable regions not from standard locations */
    if ((region->permissions & MI_PERM_EXEC) && region->path[0] != '\0') {
        if (!strstr(region->path, "/lib/") && 
            !strstr(region->path, "/usr/") &&
            !strstr(region->path, "/opt/") &&
            !strstr(region->path, "/bin/") &&
            !strstr(region->path, "/sbin/")) {
            return true;
        }
    }
    
    return false;
}

/**
 * Get memory map from /proc/[pid]/maps
 */
static mi_result_t linux_get_memory_map(pid_t pid, mi_memory_region_t *regions, size_t *count) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        MI_LOG_ERROR("Failed to open %s: %s", maps_path, strerror(errno));
        return (errno == ENOENT) ? MI_ERROR_PROCESS_NOT_FOUND : MI_ERROR_PERMISSION_DENIED;
    }
    
    char line[MAPS_LINE_MAX];
    size_t region_count = 0;
    char main_exe_path[MI_MAX_PATH_LEN] = {0};
    
    /* Get main executable path for injection detection */
    char exe_link[64];
    snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
    ssize_t len = readlink(exe_link, main_exe_path, sizeof(main_exe_path) - 1);
    if (len > 0) {
        main_exe_path[len] = '\0';
    }
    
    while (fgets(line, sizeof(line), maps_file) && region_count < MI_MAX_REGIONS) {
        mi_memory_region_t *region = &regions[region_count];
        memset(region, 0, sizeof(mi_memory_region_t));
        
        uintptr_t start, end;
        char perms[8], path[MI_MAX_PATH_LEN] = {0};
        unsigned long offset, dev_major, dev_minor, inode;
        
        /* Parse maps line format:
         * address           perms offset  dev   inode   pathname
         * 08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
         */
        int parsed = sscanf(line, "%lx-%lx %7s %lx %lx:%lx %lu %4095s",
                           &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, path);
        
        if (parsed < 6) {
            MI_LOG_WARN("Failed to parse maps line: %s", line);
            continue;
        }
        
        /* Fill region information */
        region->start_addr = start;
        region->end_addr = end;
        region->size = end - start;
        region->permissions = parse_permissions(perms);
        region->type = determine_region_type(path, start);
        
        if (parsed >= 7) {
            strncpy(region->path, path, sizeof(region->path) - 1);
            region->path[sizeof(region->path) - 1] = '\0';
        }
        
        /* Analyze region for anomalies */
        region->is_suspicious = is_region_suspicious(region);
        region->is_injected = is_region_injected(region, main_exe_path);
        
        if (region->is_suspicious || region->is_injected) {
            MI_LOG_INFO("Suspicious region found: %lx-%lx %s %s %s %s",
                       start, end, perms, 
                       region->is_suspicious ? "[SUSPICIOUS]" : "",
                       region->is_injected ? "[INJECTED]" : "",
                       path);
        }
        
        region_count++;
    }
    
    fclose(maps_file);
    *count = region_count;
    
    MI_LOG_DEBUG("Parsed %zu memory regions for PID %d", region_count, pid);
    return MI_SUCCESS;
}

/**
 * Read memory from process using /proc/[pid]/mem
 */
static mi_result_t linux_read_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size) {
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    
    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd == -1) {
        MI_LOG_ERROR("Failed to open %s: %s", mem_path, strerror(errno));
        return (errno == ENOENT) ? MI_ERROR_PROCESS_NOT_FOUND : MI_ERROR_PERMISSION_DENIED;
    }
    
    /* Seek to target address */
    if (lseek(mem_fd, addr, SEEK_SET) == -1) {
        MI_LOG_ERROR("Failed to seek to address %lx: %s", addr, strerror(errno));
        close(mem_fd);
        return MI_ERROR_MEMORY_READ;
    }
    
    /* Read memory in chunks */
    size_t bytes_read = 0;
    char *buf_ptr = (char *)buffer;
    
    while (bytes_read < size) {
        size_t chunk_size = (size - bytes_read > MEM_READ_CHUNK) ? 
                           MEM_READ_CHUNK : (size - bytes_read);
        
        ssize_t result = read(mem_fd, buf_ptr + bytes_read, chunk_size);
        if (result == -1) {
            if (errno == EIO || errno == EFAULT) {
                /* Memory region not readable */
                MI_LOG_DEBUG("Memory at %lx not readable: %s", 
                            addr + bytes_read, strerror(errno));
                break;
            }
            MI_LOG_ERROR("Memory read error at %lx: %s", 
                        addr + bytes_read, strerror(errno));
            close(mem_fd);
            return MI_ERROR_MEMORY_READ;
        }
        
        if (result == 0) {
            /* EOF reached */
            break;
        }
        
        bytes_read += result;
    }
    
    close(mem_fd);
    
    if (bytes_read == 0) {
        return MI_ERROR_MEMORY_READ;
    }
    
    MI_LOG_TRACE("Read %zu bytes from %lx", bytes_read, addr);
    return MI_SUCCESS;
}

/**
 * Get process name from /proc/[pid]/comm
 */
static mi_result_t linux_get_process_name(pid_t pid, char *name, size_t size) {
    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
    
    FILE *comm_file = fopen(comm_path, "r");
    if (!comm_file) {
        return (errno == ENOENT) ? MI_ERROR_PROCESS_NOT_FOUND : MI_ERROR_PERMISSION_DENIED;
    }
    
    if (fgets(name, size, comm_file)) {
        /* Remove trailing newline */
        size_t len = strlen(name);
        if (len > 0 && name[len - 1] == '\n') {
            name[len - 1] = '\0';
        }
    }
    
    fclose(comm_file);
    return MI_SUCCESS;
}

/**
 * Get process executable path from /proc/[pid]/exe
 */
static mi_result_t linux_get_process_path(pid_t pid, char *path, size_t size) {
    char exe_link[64];
    snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
    
    ssize_t len = readlink(exe_link, path, size - 1);
    if (len == -1) {
        return (errno == ENOENT) ? MI_ERROR_PROCESS_NOT_FOUND : MI_ERROR_PERMISSION_DENIED;
    }
    
    path[len] = '\0';
    return MI_SUCCESS;
}

/**
 * Check if process is running
 */
static bool linux_is_process_running(pid_t pid) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
    
    struct stat st;
    return (stat(proc_path, &st) == 0);
}

/**
 * Get process privileges (dummy implementation for Linux)
 */
static mi_result_t linux_get_process_privileges(pid_t pid, uint32_t *privileges) {
    /* For Linux, we'll check if we can attach with ptrace */
    *privileges = 0;
    
    /* Try to attach to process */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0) {
        *privileges = 1; /* We can debug the process */
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    }
    
    return MI_SUCCESS;
}

/* Linux platform operations structure */
const mi_platform_ops_t linux_platform_ops = {
    .get_memory_map = linux_get_memory_map,
    .read_memory = linux_read_memory,
    .get_process_name = linux_get_process_name,
    .get_process_path = linux_get_process_path,
    .is_process_running = linux_is_process_running,
    .get_process_privileges = linux_get_process_privileges,
    .create_dump_file = NULL, /* Implemented in dump module */
    .get_temp_dir = NULL,     /* Implemented in dump module */
    .write_log = NULL,        /* Handled by logger */
    .init_logging = NULL      /* Handled by logger */
};