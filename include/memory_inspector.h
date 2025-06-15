/**
 * Memory Inspector CLI - Core Header
 * 
 * Senior-grade memory analysis tool for forensics and security research
 * Cross-platform architecture with clean separation of concerns
 * 
 * @author  Senior Security Developer
 * @version 1.0.0
 * @license [License]
 */

#ifndef MEMORY_INSPECTOR_H
#define MEMORY_INSPECTOR_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version information */
#define MI_VERSION_MAJOR 1
#define MI_VERSION_MINOR 0
#define MI_VERSION_PATCH 0
#define MI_VERSION_STRING "1.0.0"

/* Maximum limits */
#define MI_MAX_PATH_LEN     4096
#define MI_MAX_REGIONS      1024
#define MI_MAX_YARA_RULES   256
#define MI_MAX_LOG_LINE     2048

/* Memory region types */
typedef enum {
    MI_REGION_UNKNOWN = 0,
    MI_REGION_CODE,
    MI_REGION_DATA,
    MI_REGION_HEAP,
    MI_REGION_STACK,
    MI_REGION_SHARED,
    MI_REGION_VDSO,
    MI_REGION_VSYSCALL
} mi_region_type_t;

/* Memory region permissions */
typedef enum {
    MI_PERM_NONE = 0,
    MI_PERM_READ = 1,
    MI_PERM_WRITE = 2,
    MI_PERM_EXEC = 4
} mi_permissions_t;

/* Memory region structure */
typedef struct {
    uintptr_t start_addr;
    uintptr_t end_addr;
    size_t size;
    mi_permissions_t permissions;
    mi_region_type_t type;
    char path[MI_MAX_PATH_LEN];
    bool is_suspicious;
    bool is_injected;
} mi_memory_region_t;

/* Process information */
typedef struct {
    pid_t pid;
    char name[256];
    char exe_path[MI_MAX_PATH_LEN];
    size_t region_count;
    mi_memory_region_t regions[MI_MAX_REGIONS];
} mi_process_info_t;

/* Configuration structure */
typedef struct {
    pid_t target_pid;
    char yara_rules_path[MI_MAX_PATH_LEN];
    char output_dir[MI_MAX_PATH_LEN];
    bool enable_yara;
    bool enable_auto_dump;
    bool enable_tui;
    bool verbose;
    bool debug;
} mi_config_t;

/* Result codes */
typedef enum {
    MI_SUCCESS = 0,
    MI_ERROR_INVALID_PID = -1,
    MI_ERROR_PERMISSION_DENIED = -2,
    MI_ERROR_PROCESS_NOT_FOUND = -3,
    MI_ERROR_MEMORY_READ = -4,
    MI_ERROR_YARA_INIT = -5,
    MI_ERROR_DUMP_FAILED = -6,
    MI_ERROR_INVALID_CONFIG = -7,
    MI_ERROR_PLATFORM_UNSUPPORTED = -8
} mi_result_t;

/* Core API Functions */

/**
 * Initialize the memory inspector
 * @param config Configuration structure
 * @return MI_SUCCESS on success, error code otherwise
 */
mi_result_t mi_init(const mi_config_t *config);

/**
 * Cleanup and shutdown the memory inspector
 */
void mi_cleanup(void);

/**
 * Get process information and memory map
 * @param pid Target process ID
 * @param info Pointer to process info structure
 * @return MI_SUCCESS on success, error code otherwise
 */
mi_result_t mi_get_process_info(pid_t pid, mi_process_info_t *info);

/**
 * Analyze memory regions for anomalies
 * @param info Process information
 * @return Number of suspicious regions found
 */
int mi_analyze_regions(mi_process_info_t *info);

/**
 * Scan memory with YARA rules
 * @param info Process information
 * @param rules_path Path to YARA rules file
 * @return Number of matches found
 */
int mi_yara_scan(const mi_process_info_t *info, const char *rules_path);

/**
 * Dump suspicious memory regions
 * @param info Process information
 * @param output_dir Output directory for dumps
 * @return Number of regions dumped
 */
int mi_dump_suspicious_regions(const mi_process_info_t *info, const char *output_dir);

/**
 * Get error message for result code
 * @param result Result code
 * @return Human-readable error message
 */
const char *mi_get_error_message(mi_result_t result);

#ifdef __cplusplus
}
#endif

#endif /* MEMORY_INSPECTOR_H */