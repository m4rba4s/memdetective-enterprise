/**
 * Memory Inspector CLI - Logging System
 * 
 * Professional logging system with multiple levels and outputs
 * Thread-safe, performance-optimized logging
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Log levels */
typedef enum {
    MI_LOG_TRACE = 0,
    MI_LOG_DEBUG,
    MI_LOG_INFO,
    MI_LOG_WARN,
    MI_LOG_ERROR,
    MI_LOG_FATAL
} mi_log_level_t;

/* Log targets */
typedef enum {
    MI_LOG_TARGET_CONSOLE = 1,
    MI_LOG_TARGET_FILE = 2,
    MI_LOG_TARGET_SYSLOG = 4
} mi_log_target_t;

/**
 * Initialize logging system
 * @param level Minimum log level
 * @param targets Log output targets (bitwise OR)
 * @param log_file Log file path (NULL for default)
 * @return true on success
 */
bool mi_log_init(mi_log_level_t level, int targets, const char *log_file);

/**
 * Log a message
 * @param level Log level
 * @param file Source file name
 * @param line Source line number
 * @param func Function name
 * @param fmt Format string
 * @param ... Format arguments
 */
void mi_log_write(mi_log_level_t level, const char *file, int line, 
                  const char *func, const char *fmt, ...);

/**
 * Set log level
 * @param level New minimum log level
 */
void mi_log_set_level(mi_log_level_t level);

/**
 * Get current log level
 * @return Current minimum log level
 */
mi_log_level_t mi_log_get_level(void);

/**
 * Enable/disable colored output
 * @param enable true to enable colors
 */
void mi_log_set_colors(bool enable);

/**
 * Cleanup logging system
 */
void mi_log_cleanup(void);

/* Convenience macros */
#define MI_LOG_TRACE(...) mi_log_write(MI_LOG_TRACE, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define MI_LOG_DEBUG(...) mi_log_write(MI_LOG_DEBUG, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define MI_LOG_INFO(...)  mi_log_write(MI_LOG_INFO,  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define MI_LOG_WARN(...)  mi_log_write(MI_LOG_WARN,  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define MI_LOG_ERROR(...) mi_log_write(MI_LOG_ERROR, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define MI_LOG_FATAL(...) mi_log_write(MI_LOG_FATAL, __FILE__, __LINE__, __func__, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_H */