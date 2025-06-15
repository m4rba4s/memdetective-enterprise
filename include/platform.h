/**
 * Memory Inspector CLI - Platform Abstraction Layer
 * 
 * Cross-platform interface for OS-specific memory operations
 * Clean separation between platform-agnostic and platform-specific code
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#include "memory_inspector.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Platform-specific function pointers */
typedef struct {
    /* Memory operations */
    mi_result_t (*get_memory_map)(pid_t pid, mi_memory_region_t *regions, size_t *count);
    mi_result_t (*read_memory)(pid_t pid, uintptr_t addr, void *buffer, size_t size);
    mi_result_t (*get_process_name)(pid_t pid, char *name, size_t size);
    mi_result_t (*get_process_path)(pid_t pid, char *path, size_t size);
    
    /* Process operations */
    bool (*is_process_running)(pid_t pid);
    mi_result_t (*get_process_privileges)(pid_t pid, uint32_t *privileges);
    
    /* File operations */
    mi_result_t (*create_dump_file)(const char *path, const void *data, size_t size);
    mi_result_t (*get_temp_dir)(char *path, size_t size);
    
    /* Logging operations */
    mi_result_t (*write_log)(const char *level, const char *message);
    mi_result_t (*init_logging)(const char *log_file);
} mi_platform_ops_t;

/* Platform detection */
typedef enum {
    MI_PLATFORM_UNKNOWN = 0,
    MI_PLATFORM_LINUX,
    MI_PLATFORM_WINDOWS,
    MI_PLATFORM_MACOS
} mi_platform_t;

/**
 * Initialize platform-specific operations
 * @return MI_SUCCESS on success, error code otherwise
 */
mi_result_t mi_platform_init(void);

/**
 * Get current platform
 * @return Platform identifier
 */
mi_platform_t mi_platform_get(void);

/**
 * Get platform operations structure
 * @return Pointer to platform operations
 */
const mi_platform_ops_t *mi_platform_get_ops(void);

/**
 * Cleanup platform resources
 */
void mi_platform_cleanup(void);

/* Utility macros for platform-specific code */
#define MI_PLATFORM_CALL(op, ...) \
    do { \
        const mi_platform_ops_t *ops = mi_platform_get_ops(); \
        if (ops && ops->op) { \
            return ops->op(__VA_ARGS__); \
        } \
        return MI_ERROR_PLATFORM_UNSUPPORTED; \
    } while(0)

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_H */