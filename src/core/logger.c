/**
 * Memory Inspector CLI - Logger Implementation
 * 
 * Thread-safe, high-performance logging system
 * Multiple output targets with configurable levels
 */

#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>

/* ANSI color codes */
#define ANSI_RESET   "\033[0m"
#define ANSI_RED     "\033[31m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_BLUE    "\033[34m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_CYAN    "\033[36m"
#define ANSI_WHITE   "\033[37m"

/* Log state */
static struct {
    mi_log_level_t level;
    int targets;
    FILE *log_file;
    bool colors_enabled;
    bool initialized;
    pthread_mutex_t mutex;
} g_log_state = {
    .level = MI_LOG_INFO,
    .targets = MI_LOG_TARGET_CONSOLE,
    .log_file = NULL,
    .colors_enabled = true,
    .initialized = false,
    .mutex = PTHREAD_MUTEX_INITIALIZER
};

/* Log level names */
static const char *level_names[] = {
    [MI_LOG_TRACE] = "TRACE",
    [MI_LOG_DEBUG] = "DEBUG",
    [MI_LOG_INFO]  = "INFO ",
    [MI_LOG_WARN]  = "WARN ",
    [MI_LOG_ERROR] = "ERROR",
    [MI_LOG_FATAL] = "FATAL"
};

/* Log level colors */
static const char *level_colors[] = {
    [MI_LOG_TRACE] = ANSI_CYAN,
    [MI_LOG_DEBUG] = ANSI_BLUE,
    [MI_LOG_INFO]  = ANSI_GREEN,
    [MI_LOG_WARN]  = ANSI_YELLOW,
    [MI_LOG_ERROR] = ANSI_RED,
    [MI_LOG_FATAL] = ANSI_MAGENTA
};

/* Syslog level mapping */
static const int syslog_levels[] = {
    [MI_LOG_TRACE] = LOG_DEBUG,
    [MI_LOG_DEBUG] = LOG_DEBUG,
    [MI_LOG_INFO]  = LOG_INFO,
    [MI_LOG_WARN]  = LOG_WARNING,
    [MI_LOG_ERROR] = LOG_ERR,
    [MI_LOG_FATAL] = LOG_CRIT
};

/**
 * Get current timestamp string
 */
static void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/**
 * Format log message
 */
static void format_message(char *buffer, size_t size, mi_log_level_t level,
                          const char *file, int line, const char *func,
                          const char *fmt, va_list args) {
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    /* Extract filename from path */
    const char *filename = strrchr(file, '/');
    filename = filename ? filename + 1 : file;
    
    /* Format base message */
    char message[2048];
    vsnprintf(message, sizeof(message), fmt, args);
    
    /* Create full log entry */
    snprintf(buffer, size, "[%s] [%s] [%s:%d:%s] %s",
             timestamp, level_names[level], filename, line, func, message);
}

/**
 * Write to console
 */
static void write_console(mi_log_level_t level, const char *message) {
    FILE *out = (level >= MI_LOG_ERROR) ? stderr : stdout;
    
    if (g_log_state.colors_enabled && isatty(fileno(out))) {
        fprintf(out, "%s%s%s\n", level_colors[level], message, ANSI_RESET);
    } else {
        fprintf(out, "%s\n", message);
    }
    
    fflush(out);
}

/**
 * Write to file
 */
static void write_file(const char *message) {
    if (g_log_state.log_file) {
        fprintf(g_log_state.log_file, "%s\n", message);
        fflush(g_log_state.log_file);
    }
}

/**
 * Write to syslog
 */
static void write_syslog(mi_log_level_t level, const char *message) {
    syslog(syslog_levels[level], "%s", message);
}

/**
 * Initialize logging system
 */
bool mi_log_init(mi_log_level_t level, int targets, const char *log_file) {
    pthread_mutex_lock(&g_log_state.mutex);
    
    if (g_log_state.initialized) {
        pthread_mutex_unlock(&g_log_state.mutex);
        return true;
    }
    
    g_log_state.level = level;
    g_log_state.targets = targets;
    g_log_state.colors_enabled = isatty(STDOUT_FILENO);
    
    /* Initialize file logging */
    if (targets & MI_LOG_TARGET_FILE) {
        const char *path = log_file ? log_file : "/tmp/memory-inspector.log";
        g_log_state.log_file = fopen(path, "a");
        if (!g_log_state.log_file) {
            pthread_mutex_unlock(&g_log_state.mutex);
            return false;
        }
    }
    
    /* Initialize syslog */
    if (targets & MI_LOG_TARGET_SYSLOG) {
        openlog("memory-inspector", LOG_PID | LOG_CONS, LOG_USER);
    }
    
    g_log_state.initialized = true;
    pthread_mutex_unlock(&g_log_state.mutex);
    
    return true;
}

/**
 * Log a message
 */
void mi_log_write(mi_log_level_t level, const char *file, int line,
                  const char *func, const char *fmt, ...) {
    if (!g_log_state.initialized || level < g_log_state.level) {
        return;
    }
    
    pthread_mutex_lock(&g_log_state.mutex);
    
    va_list args;
    va_start(args, fmt);
    
    char buffer[4096];
    format_message(buffer, sizeof(buffer), level, file, line, func, fmt, args);
    
    /* Write to configured targets */
    if (g_log_state.targets & MI_LOG_TARGET_CONSOLE) {
        write_console(level, buffer);
    }
    
    if (g_log_state.targets & MI_LOG_TARGET_FILE) {
        write_file(buffer);
    }
    
    if (g_log_state.targets & MI_LOG_TARGET_SYSLOG) {
        write_syslog(level, buffer);
    }
    
    va_end(args);
    pthread_mutex_unlock(&g_log_state.mutex);
}

/**
 * Set log level
 */
void mi_log_set_level(mi_log_level_t level) {
    pthread_mutex_lock(&g_log_state.mutex);
    g_log_state.level = level;
    pthread_mutex_unlock(&g_log_state.mutex);
}

/**
 * Get current log level
 */
mi_log_level_t mi_log_get_level(void) {
    return g_log_state.level;
}

/**
 * Enable/disable colored output
 */
void mi_log_set_colors(bool enable) {
    pthread_mutex_lock(&g_log_state.mutex);
    g_log_state.colors_enabled = enable;
    pthread_mutex_unlock(&g_log_state.mutex);
}

/**
 * Cleanup logging system
 */
void mi_log_cleanup(void) {
    pthread_mutex_lock(&g_log_state.mutex);
    
    if (!g_log_state.initialized) {
        pthread_mutex_unlock(&g_log_state.mutex);
        return;
    }
    
    if (g_log_state.log_file) {
        fclose(g_log_state.log_file);
        g_log_state.log_file = NULL;
    }
    
    if (g_log_state.targets & MI_LOG_TARGET_SYSLOG) {
        closelog();
    }
    
    g_log_state.initialized = false;
    pthread_mutex_unlock(&g_log_state.mutex);
}