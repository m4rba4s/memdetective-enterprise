/**
 * Memory Inspector CLI - Windows Platform Header
 * 
 * Windows-specific memory operations and data structures
 * Phase 2 implementation for cross-platform support
 */

#ifndef WINDOWS_MEMORY_H
#define WINDOWS_MEMORY_H

#ifdef _WIN32

#include "memory_inspector.h"
#include "platform.h"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Windows-specific constants */
#define WIN_MAX_MODULE_NAME 256
#define WIN_MAX_PROCESS_NAME 260

/* Windows memory protection flags mapping */
typedef struct {
    DWORD windows_protect;
    mi_permissions_t mi_permissions;
    const char *name;
} win_protection_mapping_t;

/* Windows process information */
typedef struct {
    DWORD pid;
    HANDLE process_handle;
    BOOL is_wow64;
    char image_name[WIN_MAX_PROCESS_NAME];
    DWORD session_id;
} win_process_info_t;

/* Windows memory region information */
typedef struct {
    MEMORY_BASIC_INFORMATION mbi;
    char module_name[WIN_MAX_MODULE_NAME];
    BOOL is_image;
    BOOL is_private;
    DWORD allocation_protect;
} win_memory_region_t;

/**
 * Windows platform operations implementation
 */

/**
 * Get memory map using VirtualQueryEx
 * @param pid Target process ID
 * @param regions Output array of memory regions
 * @param count Pointer to region count
 * @return MI_SUCCESS on success, error code otherwise
 */
mi_result_t win_get_memory_map(pid_t pid, mi_memory_region_t *regions, size_t *count);

/**
 * Read process memory using ReadProcessMemory
 * @param pid Target process ID
 * @param addr Memory address to read
 * @param buffer Output buffer
 * @param size Number of bytes to read
 * @return MI_SUCCESS on success, error code otherwise
 */
mi_result_t win_read_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);

/**
 * Get process name using process handle
 * @param pid Target process ID
 * @param name Output buffer for process name
 * @param size Size of output buffer
 * @return MI_SUCCESS on success, error code otherwise
 */
mi_result_t win_get_process_name(pid_t pid, char *name, size_t size);

/**
 * Get process executable path using GetModuleFileNameEx
 * @param pid Target process ID
 * @param path Output buffer for executable path
 * @param size Size of output buffer
 * @return MI_SUCCESS on success, error code otherwise
 */
mi_result_t win_get_process_path(pid_t pid, char *path, size_t size);

/**
 * Check if process is running
 * @param pid Target process ID
 * @return true if running, false otherwise
 */
bool win_is_process_running(pid_t pid);

/**
 * Get process privileges and access rights
 * @param pid Target process ID
 * @param privileges Output for privilege information
 * @return MI_SUCCESS on success, error code otherwise
 */
mi_result_t win_get_process_privileges(pid_t pid, uint32_t *privileges);

/**
 * Create memory dump file with Windows-specific attributes
 * @param path Output file path
 * @param data Memory data to write
 * @param size Size of data
 * @return MI_SUCCESS on success, error code otherwise
 */
mi_result_t win_create_dump_file(const char *path, const void *data, size_t size);

/**
 * Get Windows temporary directory
 * @param path Output buffer for temp directory path
 * @param size Size of output buffer
 * @return MI_SUCCESS on success, error code otherwise
 */
mi_result_t win_get_temp_dir(char *path, size_t size);

/**
 * Write to Windows Event Log
 * @param level Log level
 * @param message Log message
 * @return MI_SUCCESS on success, error code otherwise
 */
mi_result_t win_write_log(const char *level, const char *message);

/**
 * Initialize Windows logging (Event Log)
 * @param log_file Log file path (may be ignored for Event Log)
 * @return MI_SUCCESS on success, error code otherwise
 */
mi_result_t win_init_logging(const char *log_file);

/* Utility functions */

/**
 * Convert Windows protection flags to MI permissions
 * @param protect Windows protection flags
 * @return MI permissions
 */
mi_permissions_t win_protect_to_permissions(DWORD protect);

/**
 * Determine region type from Windows memory info
 * @param mbi Memory basic information
 * @param module_name Module name if available
 * @return MI region type
 */
mi_region_type_t win_determine_region_type(const MEMORY_BASIC_INFORMATION *mbi, 
                                          const char *module_name);

/**
 * Check if Windows memory region is suspicious
 * @param mbi Memory basic information
 * @param module_name Module name if available
 * @return true if suspicious, false otherwise
 */
bool win_is_region_suspicious(const MEMORY_BASIC_INFORMATION *mbi, 
                             const char *module_name);

/**
 * Check if Windows memory region is injected
 * @param mbi Memory basic information
 * @param module_name Module name if available
 * @param main_image Main process image path
 * @return true if injected, false otherwise
 */
bool win_is_region_injected(const MEMORY_BASIC_INFORMATION *mbi,
                           const char *module_name, 
                           const char *main_image);

/**
 * Enable debug privilege for current process
 * @return true if successful, false otherwise
 */
bool win_enable_debug_privilege(void);

/**
 * Get module information for address
 * @param process_handle Process handle
 * @param addr Memory address
 * @param module_name Output buffer for module name
 * @param size Size of output buffer
 * @return true if module found, false otherwise
 */
bool win_get_module_info(HANDLE process_handle, uintptr_t addr, 
                        char *module_name, size_t size);

/**
 * Check if process is WOW64 (32-bit on 64-bit)
 * @param process_handle Process handle
 * @return true if WOW64, false otherwise
 */
bool win_is_wow64_process(HANDLE process_handle);

/* Windows platform operations structure */
extern const mi_platform_ops_t windows_platform_ops;

/* Windows-specific error codes */
#define MI_ERROR_WIN_ACCESS_DENIED      (-100)
#define MI_ERROR_WIN_INVALID_HANDLE     (-101)
#define MI_ERROR_WIN_INSUFFICIENT_BUFFER (-102)
#define MI_ERROR_WIN_NOT_FOUND          (-103)

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */

#endif /* WINDOWS_MEMORY_H */