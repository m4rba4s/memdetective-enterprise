/**
 * Memory Inspector CLI - Enterprise Logger Implementation
 * 
 * Ultra enterprise-grade logging system with all the bells and whistles
 * that enterprise architects and security teams actually use in production
 */

#include "enterprise_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <regex.h>
#include <zlib.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Enterprise logging state */
static struct {
    mi_elog_config_t config;
    mi_elog_stats_t stats;
    FILE *log_file;
    char current_correlation_id[64];
    char current_user_id[64];
    char current_session_id[64];
    bool initialized;
    pthread_mutex_t write_mutex;
    pthread_t async_thread;
    bool async_shutdown;
    
    /* Rotation state */
    time_t file_created_time;
    uint64_t current_file_size;
    
    /* Secret masking */
    regex_t *masking_regexes;
    size_t masking_regex_count;
    
    /* Remote endpoints */
    int syslog_socket;
    CURL *webhook_curl;
    
    /* Async logging buffer */
    char *async_buffer;
    size_t async_buffer_pos;
    size_t async_buffer_size;
    pthread_cond_t async_cond;
    pthread_mutex_t async_mutex;
} g_elog_state = {0};

/* Log level names for different formats */
static const char *level_names_text[] = {
    [MI_ELOG_TRACE] = "TRACE",
    [MI_ELOG_DEBUG] = "DEBUG", 
    [MI_ELOG_INFO] = "INFO",
    [MI_ELOG_NOTICE] = "NOTICE",
    [MI_ELOG_WARNING] = "WARNING",
    [MI_ELOG_ERROR] = "ERROR",
    [MI_ELOG_CRITICAL] = "CRITICAL",
    [MI_ELOG_ALERT] = "ALERT",
    [MI_ELOG_EMERGENCY] = "EMERGENCY"
};

static const int syslog_levels[] = {
    [MI_ELOG_TRACE] = LOG_DEBUG,
    [MI_ELOG_DEBUG] = LOG_DEBUG,
    [MI_ELOG_INFO] = LOG_INFO,
    [MI_ELOG_NOTICE] = LOG_NOTICE,
    [MI_ELOG_WARNING] = LOG_WARNING,
    [MI_ELOG_ERROR] = LOG_ERR,
    [MI_ELOG_CRITICAL] = LOG_CRIT,
    [MI_ELOG_ALERT] = LOG_ALERT,
    [MI_ELOG_EMERGENCY] = LOG_EMERG
};

/* CEF severity mapping for SIEM systems */
static const int cef_severities[] = {
    [MI_ELOG_TRACE] = 1,
    [MI_ELOG_DEBUG] = 2,
    [MI_ELOG_INFO] = 3,
    [MI_ELOG_NOTICE] = 4,
    [MI_ELOG_WARNING] = 6,
    [MI_ELOG_ERROR] = 7,
    [MI_ELOG_CRITICAL] = 8,
    [MI_ELOG_ALERT] = 9,
    [MI_ELOG_EMERGENCY] = 10
};

/**
 * Get high-precision timestamp
 */
static uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/**
 * Get ISO 8601 timestamp string
 */
static void get_iso8601_timestamp(char *buffer, size_t size, uint64_t timestamp_ns) {
    time_t seconds = timestamp_ns / 1000000000ULL;
    uint32_t nanoseconds = timestamp_ns % 1000000000ULL;
    struct tm *tm_info = gmtime(&seconds);
    
    strftime(buffer, size - 10, "%Y-%m-%dT%H:%M:%S", tm_info);
    snprintf(buffer + strlen(buffer), 10, ".%03uZ", nanoseconds / 1000000);
}

/**
 * Generate correlation ID if not set
 */
static void ensure_correlation_id(void) {
    if (g_elog_state.current_correlation_id[0] == '\0') {
        snprintf(g_elog_state.current_correlation_id, 
                sizeof(g_elog_state.current_correlation_id),
                "mi-%08x-%04x", (uint32_t)time(NULL), (uint16_t)getpid());
    }
}

/**
 * Mask secrets in log message using regex patterns
 */
static char *mask_secrets(const char *message) {
    if (!g_elog_state.config.masking.enabled || !message) {
        return strdup(message);
    }
    
    char *result = strdup(message);
    if (!result) return NULL;
    
    for (size_t i = 0; i < g_elog_state.masking_regex_count; i++) {
        regmatch_t matches[10];
        char *current = result;
        
        while (regexec(&g_elog_state.masking_regexes[i], current, 10, matches, 0) == 0) {
            /* Mask the matched content */
            size_t start = matches[0].rm_so;
            size_t end = matches[0].rm_eo;
            
            if (g_elog_state.config.masking.preserve_length) {
                for (size_t j = start; j < end; j++) {
                    current[j] = g_elog_state.config.masking.mask_char;
                }
            } else {
                /* Replace with fixed mask */
                memmove(current + start + 8, current + end, strlen(current + end) + 1);
                memcpy(current + start, "********", 8);
            }
            
            current += start + 8;
            
            /* Log masking event if enabled */
            if (g_elog_state.config.masking.log_masking_events) {
                pthread_mutex_lock(&g_elog_state.stats.stats_mutex);
                g_elog_state.stats.secrets_masked++;
                pthread_mutex_unlock(&g_elog_state.stats.stats_mutex);
            }
        }
    }
    
    return result;
}

/**
 * Format log entry as JSON for machine processing
 */
static char *format_json_entry(mi_elog_level_t level, const mi_elog_metadata_t *metadata,
                              const char *message) {
    json_object *root = json_object_new_object();
    json_object *timestamp_obj = json_object_new_string("");
    json_object *level_obj = json_object_new_string(level_names_text[level]);
    json_object *message_obj = json_object_new_string(message);
    json_object *app_obj = json_object_new_string(g_elog_state.config.application_name);
    json_object *version_obj = json_object_new_string(g_elog_state.config.version);
    json_object *env_obj = json_object_new_string(g_elog_state.config.environment);
    json_object *host_obj = json_object_new_string(metadata->hostname);
    json_object *pid_obj = json_object_new_int(metadata->process_id);
    json_object *tid_obj = json_object_new_int(metadata->thread_id);
    json_object *correlation_obj = json_object_new_string(g_elog_state.current_correlation_id);
    
    /* ISO 8601 timestamp */
    char timestamp_str[64];
    get_iso8601_timestamp(timestamp_str, sizeof(timestamp_str), metadata->timestamp_ns);
    json_object_string_set(timestamp_obj, timestamp_str);
    
    /* Build JSON object */
    json_object_object_add(root, "@timestamp", timestamp_obj);
    json_object_object_add(root, "level", level_obj);
    json_object_object_add(root, "message", message_obj);
    json_object_object_add(root, "application", app_obj);
    json_object_object_add(root, "version", version_obj);
    json_object_object_add(root, "environment", env_obj);
    json_object_object_add(root, "hostname", host_obj);
    json_object_object_add(root, "pid", pid_obj);
    json_object_object_add(root, "thread_id", tid_obj);
    json_object_object_add(root, "correlation_id", correlation_obj);
    
    /* Add source location if available */
    if (metadata->source_file[0]) {
        json_object *source_obj = json_object_new_object();
        json_object_object_add(source_obj, "file", json_object_new_string(metadata->source_file));
        json_object_object_add(source_obj, "line", json_object_new_int(metadata->source_line));
        json_object_object_add(source_obj, "function", json_object_new_string(metadata->function_name));
        json_object_object_add(root, "source", source_obj);
    }
    
    /* Add user context if available */
    if (g_elog_state.current_user_id[0]) {
        json_object *user_obj = json_object_new_object();
        json_object_object_add(user_obj, "id", json_object_new_string(g_elog_state.current_user_id));
        json_object_object_add(user_obj, "session", json_object_new_string(g_elog_state.current_session_id));
        json_object_object_add(root, "user", user_obj);
    }
    
    /* Convert to string and cleanup */
    const char *json_str = json_object_to_json_string(root);
    char *result = strdup(json_str);
    json_object_put(root);
    
    return result;
}

/**
 * Format log entry as CEF for SIEM systems
 */
static char *format_cef_entry(mi_elog_level_t level, const mi_elog_metadata_t *metadata,
                             const char *message) {
    char timestamp_str[64];
    get_iso8601_timestamp(timestamp_str, sizeof(timestamp_str), metadata->timestamp_ns);
    
    /* CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|[Extension] */
    char *result = malloc(4096);
    if (!result) return NULL;
    
    snprintf(result, 4096,
        "CEF:0|MemoryInspector|MemoryInspectorCLI|%s|%s|%s|%d|"
        "rt=%s src=%s suser=%s sproc=%d cs1=%s cs1Label=CorrelationID "
        "cs2=%s cs2Label=Environment fname=%s fline=%d",
        g_elog_state.config.version,
        level_names_text[level],
        message,
        cef_severities[level],
        timestamp_str,
        metadata->hostname,
        g_elog_state.current_user_id[0] ? g_elog_state.current_user_id : "unknown",
        metadata->process_id,
        g_elog_state.current_correlation_id,
        g_elog_state.config.environment,
        metadata->source_file,
        metadata->source_line
    );
    
    return result;
}

/**
 * Check if log rotation is needed
 */
static bool needs_rotation(void) {
    if (!g_elog_state.config.rotation.enabled) {
        return false;
    }
    
    /* Check file size */
    if (g_elog_state.config.rotation.max_size_bytes > 0 &&
        g_elog_state.current_file_size >= g_elog_state.config.rotation.max_size_bytes) {
        return true;
    }
    
    /* Check file age */
    if (g_elog_state.config.rotation.max_age_hours > 0) {
        time_t now = time(NULL);
        if (now - g_elog_state.file_created_time >= 
            g_elog_state.config.rotation.max_age_hours * 3600) {
            return true;
        }
    }
    
    return false;
}

/**
 * Perform log rotation
 */
static bool rotate_log_file(void) {
    if (!g_elog_state.log_file) {
        return false;
    }
    
    /* Close current file */
    fclose(g_elog_state.log_file);
    g_elog_state.log_file = NULL;
    
    /* Generate rotated filename */
    char rotated_name[1024];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    snprintf(rotated_name, sizeof(rotated_name), "%s.%04d%02d%02d_%02d%02d%02d",
             g_elog_state.config.log_file_path,
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
    
    /* Rename current file */
    if (rename(g_elog_state.config.log_file_path, rotated_name) != 0) {
        return false;
    }
    
    /* Compress if enabled */
    if (g_elog_state.config.rotation.compress_rotated) {
        char compressed_name[1024];
        snprintf(compressed_name, sizeof(compressed_name), "%s.gz", rotated_name);
        
        /* Simple gzip compression */
        FILE *input = fopen(rotated_name, "rb");
        gzFile output = gzopen(compressed_name, "wb");
        
        if (input && output) {
            char buffer[8192];
            size_t bytes_read;
            while ((bytes_read = fread(buffer, 1, sizeof(buffer), input)) > 0) {
                gzwrite(output, buffer, bytes_read);
            }
            fclose(input);
            gzclose(output);
            unlink(rotated_name);  /* Remove uncompressed file */
        }
    }
    
    /* Reopen log file */
    g_elog_state.log_file = fopen(g_elog_state.config.log_file_path, "a");
    if (!g_elog_state.log_file) {
        return false;
    }
    
    g_elog_state.file_created_time = now;
    g_elog_state.current_file_size = 0;
    
    /* Update statistics */
    pthread_mutex_lock(&g_elog_state.stats.stats_mutex);
    g_elog_state.stats.files_rotated++;
    g_elog_state.stats.last_rotation = now;
    pthread_mutex_unlock(&g_elog_state.stats.stats_mutex);
    
    return true;
}

/**
 * Send log to remote syslog server
 */
static void send_remote_syslog(mi_elog_level_t level, const char *formatted_message) {
    if (!(g_elog_state.config.targets & MI_ELOG_TARGET_REMOTE_SYSLOG)) {
        return;
    }
    
    if (g_elog_state.syslog_socket <= 0) {
        /* Initialize remote syslog connection */
        g_elog_state.syslog_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (g_elog_state.syslog_socket <= 0) {
            pthread_mutex_lock(&g_elog_state.stats.stats_mutex);
            g_elog_state.stats.remote_failures++;
            pthread_mutex_unlock(&g_elog_state.stats.stats_mutex);
            return;
        }
    }
    
    /* Format syslog message with priority */
    int priority = LOG_USER | syslog_levels[level];
    char syslog_msg[2048];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    snprintf(syslog_msg, sizeof(syslog_msg),
             "<%d>%s %s %s[%d]: %s",
             priority,
             "Jan 01 00:00:00",  /* Simple timestamp - replace with proper formatting */
             g_elog_state.config.application_name,
             g_elog_state.config.application_name,
             getpid(),
             formatted_message);
    
    /* Send to remote server */
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(g_elog_state.config.syslog_remote.port);
    inet_pton(AF_INET, g_elog_state.config.syslog_remote.hostname, &server_addr.sin_addr);
    
    if (sendto(g_elog_state.syslog_socket, syslog_msg, strlen(syslog_msg), 0,
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        pthread_mutex_lock(&g_elog_state.stats.stats_mutex);
        g_elog_state.stats.remote_failures++;
        pthread_mutex_unlock(&g_elog_state.stats.stats_mutex);
    }
}

/**
 * Send log to webhook endpoint
 */
static void send_webhook(mi_elog_level_t level, const char *json_message) {
    if (!(g_elog_state.config.targets & MI_ELOG_TARGET_WEBHOOK)) {
        return;
    }
    
    if (!g_elog_state.webhook_curl) {
        g_elog_state.webhook_curl = curl_easy_init();
        if (!g_elog_state.webhook_curl) {
            return;
        }
        
        /* Configure webhook */
        curl_easy_setopt(g_elog_state.webhook_curl, CURLOPT_URL, g_elog_state.config.webhook.url);
        curl_easy_setopt(g_elog_state.webhook_curl, CURLOPT_TIMEOUT_MS, g_elog_state.config.webhook.timeout_ms);
        
        if (g_elog_state.config.webhook.auth_header[0]) {
            struct curl_slist *headers = NULL;
            headers = curl_slist_append(headers, g_elog_state.config.webhook.auth_header);
            headers = curl_slist_append(headers, "Content-Type: application/json");
            curl_easy_setopt(g_elog_state.webhook_curl, CURLOPT_HTTPHEADER, headers);
        }
    }
    
    /* Send POST request */
    curl_easy_setopt(g_elog_state.webhook_curl, CURLOPT_POSTFIELDS, json_message);
    CURLcode res = curl_easy_perform(g_elog_state.webhook_curl);
    
    if (res != CURLE_OK) {
        pthread_mutex_lock(&g_elog_state.stats.stats_mutex);
        g_elog_state.stats.remote_failures++;
        pthread_mutex_unlock(&g_elog_state.stats.stats_mutex);
    }
}

/**
 * Write formatted log entry to all configured targets
 */
static void write_log_entry(mi_elog_level_t level, const mi_elog_metadata_t *metadata,
                           const char *message) {
    if (level < g_elog_state.config.min_level) {
        return;
    }
    
    pthread_mutex_lock(&g_elog_state.write_mutex);
    
    /* Mask secrets in message */
    char *masked_message = mask_secrets(message);
    if (!masked_message) {
        pthread_mutex_unlock(&g_elog_state.write_mutex);
        return;
    }
    
    /* Format message based on configured format */
    char *formatted_message = NULL;
    switch (g_elog_state.config.format) {
        case MI_ELOG_FORMAT_JSON:
            formatted_message = format_json_entry(level, metadata, masked_message);
            break;
        case MI_ELOG_FORMAT_CEF:
            formatted_message = format_cef_entry(level, metadata, masked_message);
            break;
        default:
            /* Default text format */
            formatted_message = malloc(4096);
            if (formatted_message) {
                char timestamp_str[64];
                get_iso8601_timestamp(timestamp_str, sizeof(timestamp_str), metadata->timestamp_ns);
                snprintf(formatted_message, 4096, "[%s] [%s] [%s:%d:%s] %s",
                        timestamp_str, level_names_text[level],
                        metadata->source_file, metadata->source_line,
                        metadata->function_name, masked_message);
            }
            break;
    }
    
    if (!formatted_message) {
        free(masked_message);
        pthread_mutex_unlock(&g_elog_state.write_mutex);
        return;
    }
    
    /* Write to console */
    if (g_elog_state.config.targets & MI_ELOG_TARGET_CONSOLE) {
        FILE *out = (level >= MI_ELOG_ERROR) ? stderr : stdout;
        fprintf(out, "%s\n", formatted_message);
        fflush(out);
    }
    
    /* Write to file */
    if ((g_elog_state.config.targets & MI_ELOG_TARGET_FILE) && g_elog_state.log_file) {
        /* Check rotation before writing */
        if (needs_rotation()) {
            rotate_log_file();
        }
        
        size_t written = fprintf(g_elog_state.log_file, "%s\n", formatted_message);
        fflush(g_elog_state.log_file);
        g_elog_state.current_file_size += written;
    }
    
    /* Write to syslog */
    if (g_elog_state.config.targets & MI_ELOG_TARGET_SYSLOG) {
        syslog(syslog_levels[level], "%s", masked_message);
    }
    
    /* Send to remote endpoints */
    send_remote_syslog(level, formatted_message);
    
    if (g_elog_state.config.format == MI_ELOG_FORMAT_JSON) {
        send_webhook(level, formatted_message);
    }
    
    /* Update statistics */
    pthread_mutex_lock(&g_elog_state.stats.stats_mutex);
    g_elog_state.stats.total_messages++;
    g_elog_state.stats.messages_by_level[level]++;
    g_elog_state.stats.bytes_written += strlen(formatted_message);
    pthread_mutex_unlock(&g_elog_state.stats.stats_mutex);
    
    free(masked_message);
    free(formatted_message);
    pthread_mutex_unlock(&g_elog_state.write_mutex);
}

/**
 * Initialize enterprise logging system
 */
bool mi_elog_init(const mi_elog_config_t *config) {
    if (g_elog_state.initialized) {
        return true;
    }
    
    if (!config) {
        return false;
    }
    
    /* Copy configuration */
    memcpy(&g_elog_state.config, config, sizeof(mi_elog_config_t));
    
    /* Initialize mutexes */
    pthread_mutex_init(&g_elog_state.write_mutex, NULL);
    pthread_mutex_init(&g_elog_state.stats.stats_mutex, NULL);
    pthread_mutex_init(&g_elog_state.async_mutex, NULL);
    pthread_cond_init(&g_elog_state.async_cond, NULL);
    
    /* Open log file if configured */
    if (config->targets & MI_ELOG_TARGET_FILE) {
        g_elog_state.log_file = fopen(config->log_file_path, "a");
        if (!g_elog_state.log_file) {
            return false;
        }
        g_elog_state.file_created_time = time(NULL);
    }
    
    /* Initialize syslog if configured */
    if (config->targets & MI_ELOG_TARGET_SYSLOG) {
        openlog(config->application_name, LOG_PID | LOG_CONS, LOG_USER);
    }
    
    /* Initialize secret masking patterns */
    if (config->masking.enabled && config->masking.pattern_count > 0) {
        g_elog_state.masking_regexes = calloc(config->masking.pattern_count, sizeof(regex_t));
        if (g_elog_state.masking_regexes) {
            for (size_t i = 0; i < config->masking.pattern_count; i++) {
                if (regcomp(&g_elog_state.masking_regexes[i], 
                           config->masking.patterns[i], REG_EXTENDED) == 0) {
                    g_elog_state.masking_regex_count++;
                }
            }
        }
    }
    
    /* Initialize curl for webhooks */
    if (config->targets & MI_ELOG_TARGET_WEBHOOK) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }
    
    /* Initialize statistics */
    g_elog_state.stats.startup_time = time(NULL);
    
    g_elog_state.initialized = true;
    return true;
}

/**
 * Write enterprise log entry
 */
void mi_elog_write(mi_elog_level_t level, const mi_elog_metadata_t *metadata,
                   const char *format, ...) {
    if (!g_elog_state.initialized) {
        return;
    }
    
    /* Format message */
    va_list args;
    va_start(args, format);
    char message[4096];
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    /* Create metadata if not provided */
    mi_elog_metadata_t auto_metadata = {0};
    if (!metadata) {
        auto_metadata.timestamp_ns = get_timestamp_ns();
        auto_metadata.process_id = getpid();
        auto_metadata.thread_id = (uint32_t)pthread_self();
        gethostname(auto_metadata.hostname, sizeof(auto_metadata.hostname));
        metadata = &auto_metadata;
    }
    
    ensure_correlation_id();
    write_log_entry(level, metadata, message);
}

/**
 * Set correlation ID for distributed tracing
 */
void mi_elog_set_correlation_id(const char *correlation_id) {
    if (correlation_id) {
        strncpy(g_elog_state.current_correlation_id, correlation_id,
                sizeof(g_elog_state.current_correlation_id) - 1);
    }
}

/**
 * Set user context for audit logging
 */
void mi_elog_set_user_context(const char *user_id, const char *session_id) {
    if (user_id) {
        strncpy(g_elog_state.current_user_id, user_id,
                sizeof(g_elog_state.current_user_id) - 1);
    }
    if (session_id) {
        strncpy(g_elog_state.current_session_id, session_id,
                sizeof(g_elog_state.current_session_id) - 1);
    }
}

/**
 * Write security audit log
 */
void mi_elog_audit(const char *event_type, const char *user_id,
                   const char *resource, const char *action,
                   bool result, const char *details) {
    mi_elog_metadata_t metadata = {0};
    metadata.timestamp_ns = get_timestamp_ns();
    metadata.process_id = getpid();
    metadata.thread_id = (uint32_t)pthread_self();
    gethostname(metadata.hostname, sizeof(metadata.hostname));
    
    /* Temporarily set user context for this audit event */
    char saved_user[64], saved_session[64];
    strncpy(saved_user, g_elog_state.current_user_id, sizeof(saved_user));
    strncpy(saved_session, g_elog_state.current_session_id, sizeof(saved_session));
    
    mi_elog_set_user_context(user_id, "audit");
    
    char audit_message[1024];
    snprintf(audit_message, sizeof(audit_message),
             "AUDIT: event=%s user=%s resource=%s action=%s result=%s details=%s",
             event_type, user_id, resource, action, 
             result ? "SUCCESS" : "FAILURE", details);
    
    write_log_entry(MI_ELOG_NOTICE, &metadata, audit_message);
    
    /* Restore user context */
    mi_elog_set_user_context(saved_user, saved_session);
}

/**
 * Get logging statistics
 */
void mi_elog_get_stats(mi_elog_stats_t *stats) {
    if (!stats) return;
    
    pthread_mutex_lock(&g_elog_state.stats.stats_mutex);
    memcpy(stats, &g_elog_state.stats, sizeof(mi_elog_stats_t));
    pthread_mutex_unlock(&g_elog_state.stats.stats_mutex);
}

/**
 * Force log rotation
 */
bool mi_elog_rotate(void) {
    return rotate_log_file();
}

/**
 * Flush all pending log entries
 */
void mi_elog_flush(void) {
    if (g_elog_state.log_file) {
        fflush(g_elog_state.log_file);
    }
}

/**
 * Cleanup and shutdown enterprise logging
 */
void mi_elog_cleanup(void) {
    if (!g_elog_state.initialized) {
        return;
    }
    
    /* Flush and close log file */
    if (g_elog_state.log_file) {
        fflush(g_elog_state.log_file);
        fclose(g_elog_state.log_file);
        g_elog_state.log_file = NULL;
    }
    
    /* Cleanup syslog */
    if (g_elog_state.config.targets & MI_ELOG_TARGET_SYSLOG) {
        closelog();
    }
    
    /* Cleanup remote connections */
    if (g_elog_state.syslog_socket > 0) {
        close(g_elog_state.syslog_socket);
    }
    
    if (g_elog_state.webhook_curl) {
        curl_easy_cleanup(g_elog_state.webhook_curl);
        curl_global_cleanup();
    }
    
    /* Cleanup masking regexes */
    for (size_t i = 0; i < g_elog_state.masking_regex_count; i++) {
        regfree(&g_elog_state.masking_regexes[i]);
    }
    free(g_elog_state.masking_regexes);
    
    /* Cleanup mutexes */
    pthread_mutex_destroy(&g_elog_state.write_mutex);
    pthread_mutex_destroy(&g_elog_state.stats.stats_mutex);
    pthread_mutex_destroy(&g_elog_state.async_mutex);
    pthread_cond_destroy(&g_elog_state.async_cond);
    
    g_elog_state.initialized = false;
}