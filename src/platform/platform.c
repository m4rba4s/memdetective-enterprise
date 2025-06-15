/**
 * Memory Inspector CLI - Platform Abstraction Implementation
 * 
 * Platform detection and operation dispatcher
 * Clean interface for cross-platform functionality
 */

#include "platform.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Forward declarations for platform-specific operations */
extern const mi_platform_ops_t linux_platform_ops;
#ifdef _WIN32
extern const mi_platform_ops_t windows_platform_ops;
#endif

/* Global platform state */
static struct {
    mi_platform_t platform;
    const mi_platform_ops_t *ops;
    bool initialized;
} g_platform_state = {
    .platform = MI_PLATFORM_UNKNOWN,
    .ops = NULL,
    .initialized = false
};

/**
 * Detect current platform
 */
static mi_platform_t detect_platform(void) {
#ifdef __linux__
    return MI_PLATFORM_LINUX;
#elif defined(_WIN32) || defined(_WIN64)
    return MI_PLATFORM_WINDOWS;
#elif defined(__APPLE__) && defined(__MACH__)
    return MI_PLATFORM_MACOS;
#else
    return MI_PLATFORM_UNKNOWN;
#endif
}

/**
 * Get platform-specific operations
 */
static const mi_platform_ops_t *get_platform_ops(mi_platform_t platform) {
    switch (platform) {
        case MI_PLATFORM_LINUX:
            return &linux_platform_ops;
            
#ifdef _WIN32
        case MI_PLATFORM_WINDOWS:
            return &windows_platform_ops;
#endif
            
        default:
            return NULL;
    }
}

/**
 * Initialize platform-specific operations
 */
mi_result_t mi_platform_init(void) {
    if (g_platform_state.initialized) {
        return MI_SUCCESS;
    }
    
    /* Detect platform */
    g_platform_state.platform = detect_platform();
    if (g_platform_state.platform == MI_PLATFORM_UNKNOWN) {
        MI_LOG_ERROR("Unsupported platform detected");
        return MI_ERROR_PLATFORM_UNSUPPORTED;
    }
    
    /* Get platform operations */
    g_platform_state.ops = get_platform_ops(g_platform_state.platform);
    if (!g_platform_state.ops) {
        MI_LOG_ERROR("Failed to initialize platform operations");
        return MI_ERROR_PLATFORM_UNSUPPORTED;
    }
    
    g_platform_state.initialized = true;
    
    const char *platform_names[] = {
        [MI_PLATFORM_UNKNOWN] = "Unknown",
        [MI_PLATFORM_LINUX] = "Linux",
        [MI_PLATFORM_WINDOWS] = "Windows", 
        [MI_PLATFORM_MACOS] = "macOS"
    };
    
    MI_LOG_INFO("Platform initialized: %s", platform_names[g_platform_state.platform]);
    return MI_SUCCESS;
}

/**
 * Get current platform
 */
mi_platform_t mi_platform_get(void) {
    return g_platform_state.platform;
}

/**
 * Get platform operations structure
 */
const mi_platform_ops_t *mi_platform_get_ops(void) {
    if (!g_platform_state.initialized) {
        return NULL;
    }
    return g_platform_state.ops;
}

/**
 * Cleanup platform resources
 */
void mi_platform_cleanup(void) {
    if (!g_platform_state.initialized) {
        return;
    }
    
    MI_LOG_DEBUG("Cleaning up platform resources");
    
    g_platform_state.platform = MI_PLATFORM_UNKNOWN;
    g_platform_state.ops = NULL;
    g_platform_state.initialized = false;
}