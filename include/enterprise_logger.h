/**
 * Memory Inspector CLI - Enterprise Logger System
 * 
 * Ultra enterprise-grade logging with rotation, masking, remote endpoints
 * Production-ready for large-scale deployments and SIEM integration
 */

#ifndef ENTERPRISE_LOGGER_H
#define ENTERPRISE_LOGGER_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Log levels with enterprise extensions */
typedef enum {
    MI_ELOG_TRACE = 0,
    MI_ELOG_DEBUG,
    MI_ELOG_INFO,
    MI_ELOG_NOTICE,     /* Enterprise: Important business events */
    MI_ELOG_WARNING,
    MI_ELOG_ERROR,
    MI_ELOG_CRITICAL,   /* Enterprise: Service degradation */
    MI_ELOG_ALERT,      /* Enterprise: Immediate action required */
    MI_ELOG_EMERGENCY   /* Enterprise: System unusable */
} mi_elog_level_t;

/* Output formats for different consumers */
typedef enum {
    MI_ELOG_FORMAT_TEXT = 0,      /* Human readable */
    MI_ELOG_FORMAT_JSON,          /* Machine readable */
    MI_ELOG_FORMAT_CEF,           /* Common Event Format (SIEM) */
    MI_ELOG_FORMAT_LEEF,          /* Log Event Extended Format (IBM QRadar) */
    MI_ELOG_FORMAT_SYSLOG_RFC5424 /* RFC5424 structured syslog */
} mi_elog_format_t;

/* Log targets with enterprise endpoints */
typedef enum {
    MI_ELOG_TARGET_CONSOLE = 1,
    MI_ELOG_TARGET_FILE = 2,
    MI_ELOG_TARGET_SYSLOG = 4,
    MI_ELOG_TARGET_REMOTE_SYSLOG = 8,    /* TCP/UDP syslog */
    MI_ELOG_TARGET_WEBHOOK = 16,         /* HTTP POST to SIEM */
    MI_ELOG_TARGET_KAFKA = 32,           /* Kafka producer */
    MI_ELOG_TARGET_ELASTICSEARCH = 64,   /* Direct ES indexing */
    MI_ELOG_TARGET_SPLUNK = 128          /* Splunk HEC */
} mi_elog_target_t;

/* Log rotation policies */
typedef struct {
    bool enabled;
    uint64_t max_size_bytes;     /* Rotate when file exceeds this size */
    uint32_t max_age_hours;      /* Rotate when file is older than this */
    uint32_t max_files;          /* Keep this many rotated files */
    bool compress_rotated;       /* Gzip old files */
    char rotation_suffix[32];    /* Timestamp format for rotated files */
} mi_elog_rotation_t;

/* Secret masking configuration */
typedef struct {
    bool enabled;
    char **patterns;             /* Regex patterns to mask */
    size_t pattern_count;
    char mask_char;              /* Character to replace secrets with */
    bool preserve_length;        /* Keep original length when masking */
    bool log_masking_events;     /* Log when masking occurs */
} mi_elog_masking_t;

/* Remote endpoint configuration */
typedef struct {
    char hostname[256];
    uint16_t port;
    bool use_tls;
    char ca_cert_path[512];
    char client_cert_path[512];
    char client_key_path[512];
    uint32_t timeout_ms;
    uint32_t retry_count;
    uint32_t retry_delay_ms;
    bool enable_compression;
} mi_elog_remote_config_t;

/* Webhook configuration */
typedef struct {
    char url[1024];
    char auth_header[512];       /* Authorization: Bearer token */
    char content_type[64];
    uint32_t timeout_ms;
    uint32_t batch_size;         /* Send logs in batches */
    uint32_t batch_timeout_ms;   /* Max time to wait for batch */
    bool verify_ssl;
} mi_elog_webhook_config_t;

/* Enterprise logger configuration */
typedef struct {
    mi_elog_level_t min_level;
    mi_elog_format_t format;
    int targets;                 /* Bitwise OR of mi_elog_target_t */
    
    /* File logging */
    char log_file_path[512];
    mi_elog_rotation_t rotation;
    
    /* Secret masking */
    mi_elog_masking_t masking;
    
    /* Remote endpoints */
    mi_elog_remote_config_t syslog_remote;
    mi_elog_webhook_config_t webhook;
    
    /* Performance tuning */
    bool async_logging;          /* Use background thread for I/O */
    uint32_t buffer_size;        /* Internal buffer size */
    uint32_t flush_interval_ms;  /* Force flush every N ms */
    
    /* Observability */
    bool enable_metrics;         /* Collect logging metrics */
    char metrics_file[512];      /* Metrics output file */
    
    /* Security */
    bool secure_erase_buffers;   /* Zero buffers after use */
    bool audit_log_access;       /* Log all logging operations */
    
    /* Application context */
    char application_name[64];
    char version[32];
    char environment[32];        /* dev, staging, prod */
    char datacenter[32];
    char node_id[64];
} mi_elog_config_t;

/* Log entry metadata for structured logging */
typedef struct {
    uint64_t timestamp_ns;       /* Nanosecond precision */
    uint32_t thread_id;
    uint32_t process_id;
    char hostname[256];
    char source_file[256];
    uint32_t source_line;
    char function_name[128];
    char correlation_id[64];     /* For distributed tracing */
    char user_id[64];           /* For audit trails */
    char session_id[64];        /* For session tracking */
} mi_elog_metadata_t;

/* Enterprise logging statistics */
typedef struct {
    uint64_t total_messages;
    uint64_t messages_by_level[MI_ELOG_EMERGENCY + 1];
    uint64_t bytes_written;
    uint64_t files_rotated;
    uint64_t secrets_masked;
    uint64_t remote_failures;
    uint64_t buffer_overruns;
    double avg_write_time_ms;
    time_t last_rotation;
    time_t startup_time;
    pthread_mutex_t stats_mutex;
} mi_elog_stats_t;

/* Public API Functions */

/**
 * Initialize enterprise logging system
 * @param config Logging configuration
 * @return true on success, false on failure
 */
bool mi_elog_init(const mi_elog_config_t *config);

/**
 * Write enterprise log entry
 * @param level Log level
 * @param metadata Entry metadata (can be NULL for auto-generation)
 * @param format Printf-style format string
 * @param ... Format arguments
 */
void mi_elog_write(mi_elog_level_t level, const mi_elog_metadata_t *metadata,
                   const char *format, ...);

/**
 * Write structured log entry with key-value pairs
 * @param level Log level
 * @param metadata Entry metadata
 * @param message Main log message
 * @param key_count Number of key-value pairs
 * @param ... Alternating keys and values (all const char*)
 */
void mi_elog_structured(mi_elog_level_t level, const mi_elog_metadata_t *metadata,
                       const char *message, int key_count, ...);

/**
 * Write security audit log
 * @param event_type Security event type
 * @param user_id User identifier
 * @param resource Resource accessed
 * @param action Action performed
 * @param result Success/failure
 * @param details Additional details
 */
void mi_elog_audit(const char *event_type, const char *user_id,
                   const char *resource, const char *action,
                   bool result, const char *details);

/**
 * Force log rotation
 * @return true on success, false on failure
 */
bool mi_elog_rotate(void);

/**
 * Flush all pending log entries
 */
void mi_elog_flush(void);

/**
 * Get logging statistics
 * @param stats Pointer to statistics structure
 */
void mi_elog_get_stats(mi_elog_stats_t *stats);

/**
 * Set correlation ID for distributed tracing
 * @param correlation_id Unique ID for request tracing
 */
void mi_elog_set_correlation_id(const char *correlation_id);

/**
 * Set user context for audit logging
 * @param user_id User identifier
 * @param session_id Session identifier
 */
void mi_elog_set_user_context(const char *user_id, const char *session_id);

/**
 * Add secret masking pattern
 * @param pattern Regex pattern to mask
 * @return true on success, false on failure
 */
bool mi_elog_add_masking_pattern(const char *pattern);

/**
 * Test remote endpoint connectivity
 * @param target Target to test
 * @return true if reachable, false otherwise
 */
bool mi_elog_test_endpoint(mi_elog_target_t target);

/**
 * Export logs in specified format
 * @param start_time Start time for export
 * @param end_time End time for export
 * @param format Output format
 * @param output_file Output file path
 * @return true on success, false on failure
 */
bool mi_elog_export(time_t start_time, time_t end_time,
                    mi_elog_format_t format, const char *output_file);

/**
 * Cleanup and shutdown enterprise logging
 */
void mi_elog_cleanup(void);

/* Convenience macros with automatic metadata */
#define MI_ELOG_TRACE(...) mi_elog_write(MI_ELOG_TRACE, NULL, __VA_ARGS__)
#define MI_ELOG_DEBUG(...) mi_elog_write(MI_ELOG_DEBUG, NULL, __VA_ARGS__)
#define MI_ELOG_INFO(...) mi_elog_write(MI_ELOG_INFO, NULL, __VA_ARGS__)
#define MI_ELOG_NOTICE(...) mi_elog_write(MI_ELOG_NOTICE, NULL, __VA_ARGS__)
#define MI_ELOG_WARNING(...) mi_elog_write(MI_ELOG_WARNING, NULL, __VA_ARGS__)
#define MI_ELOG_ERROR(...) mi_elog_write(MI_ELOG_ERROR, NULL, __VA_ARGS__)
#define MI_ELOG_CRITICAL(...) mi_elog_write(MI_ELOG_CRITICAL, NULL, __VA_ARGS__)
#define MI_ELOG_ALERT(...) mi_elog_write(MI_ELOG_ALERT, NULL, __VA_ARGS__)
#define MI_ELOG_EMERGENCY(...) mi_elog_write(MI_ELOG_EMERGENCY, NULL, __VA_ARGS__)

/* Structured logging macros */
#define MI_ELOG_STRUCT(level, msg, count, ...) \
    mi_elog_structured(level, NULL, msg, count, __VA_ARGS__)

/* Audit logging macro */
#define MI_ELOG_AUDIT(type, user, resource, action, result, details) \
    mi_elog_audit(type, user, resource, action, result, details)

#ifdef __cplusplus
}
#endif

#endif /* ENTERPRISE_LOGGER_H */