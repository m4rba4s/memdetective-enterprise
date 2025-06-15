/**
 * Memory Inspector CLI - Enterprise Configuration Parser
 * 
 * Professional configuration management with environment variable support,
 * validation, and enterprise-grade default handling
 */

#include "enterprise_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#define MAX_LINE_LENGTH 1024
#define MAX_SECTION_NAME 64
#define MAX_KEY_NAME 64
#define MAX_VALUE_LENGTH 512

/* Configuration state */
static struct {
    char current_section[MAX_SECTION_NAME];
    mi_elog_config_t *config;
} g_config_state = {0};

/**
 * Trim whitespace from string
 */
static char *trim_whitespace(char *str) {
    if (!str) return NULL;
    
    /* Trim leading whitespace */
    while (isspace(*str)) str++;
    
    /* Trim trailing whitespace */
    char *end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) {
        *end = '\0';
        end--;
    }
    
    return str;
}

/**
 * Parse boolean value from string
 */
static bool parse_bool(const char *value) {
    if (!value) return false;
    
    if (strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0 ||
        strcasecmp(value, "on") == 0 ||
        strcasecmp(value, "1") == 0) {
        return true;
    }
    
    return false;
}

/**
 * Parse log level from string
 */
static mi_elog_level_t parse_log_level(const char *value) {
    if (!value) return MI_ELOG_INFO;
    
    if (strcasecmp(value, "TRACE") == 0) return MI_ELOG_TRACE;
    if (strcasecmp(value, "DEBUG") == 0) return MI_ELOG_DEBUG;
    if (strcasecmp(value, "INFO") == 0) return MI_ELOG_INFO;
    if (strcasecmp(value, "NOTICE") == 0) return MI_ELOG_NOTICE;
    if (strcasecmp(value, "WARNING") == 0) return MI_ELOG_WARNING;
    if (strcasecmp(value, "ERROR") == 0) return MI_ELOG_ERROR;
    if (strcasecmp(value, "CRITICAL") == 0) return MI_ELOG_CRITICAL;
    if (strcasecmp(value, "ALERT") == 0) return MI_ELOG_ALERT;
    if (strcasecmp(value, "EMERGENCY") == 0) return MI_ELOG_EMERGENCY;
    
    return MI_ELOG_INFO;  /* Default */
}

/**
 * Parse log format from string
 */
static mi_elog_format_t parse_log_format(const char *value) {
    if (!value) return MI_ELOG_FORMAT_TEXT;
    
    if (strcasecmp(value, "JSON") == 0) return MI_ELOG_FORMAT_JSON;
    if (strcasecmp(value, "CEF") == 0) return MI_ELOG_FORMAT_CEF;
    if (strcasecmp(value, "LEEF") == 0) return MI_ELOG_FORMAT_LEEF;
    if (strcasecmp(value, "SYSLOG_RFC5424") == 0) return MI_ELOG_FORMAT_SYSLOG_RFC5424;
    
    return MI_ELOG_FORMAT_TEXT;  /* Default */
}

/**
 * Resolve environment variables in value
 */
static char *resolve_env_vars(const char *value) {
    if (!value || !strstr(value, "${")) {
        return strdup(value);
    }
    
    char *result = malloc(MAX_VALUE_LENGTH);
    if (!result) return NULL;
    
    const char *src = value;
    char *dst = result;
    
    while (*src && (dst - result) < MAX_VALUE_LENGTH - 1) {
        if (src[0] == '$' && src[1] == '{') {
            /* Find closing brace */
            const char *end = strchr(src + 2, '}');
            if (end) {
                /* Extract variable name */
                size_t var_len = end - src - 2;
                char var_name[64];
                if (var_len < sizeof(var_name)) {
                    strncpy(var_name, src + 2, var_len);
                    var_name[var_len] = '\0';
                    
                    /* Get environment variable */
                    const char *env_value = getenv(var_name);
                    if (env_value) {
                        size_t env_len = strlen(env_value);
                        if ((dst - result) + env_len < MAX_VALUE_LENGTH - 1) {
                            strcpy(dst, env_value);
                            dst += env_len;
                        }
                    }
                    
                    src = end + 1;
                    continue;
                }
            }
        }
        
        *dst++ = *src++;
    }
    
    *dst = '\0';
    return result;
}

/**
 * Parse array of strings (for masking patterns)
 */
static char **parse_string_array(const char *value, size_t *count) {
    if (!value || !count) return NULL;
    
    *count = 0;
    
    /* Count commas to estimate array size */
    size_t max_items = 1;
    for (const char *p = value; *p; p++) {
        if (*p == ',') max_items++;
    }
    
    char **array = calloc(max_items, sizeof(char*));
    if (!array) return NULL;
    
    char *value_copy = strdup(value);
    if (!value_copy) {
        free(array);
        return NULL;
    }
    
    /* Remove array brackets if present */
    char *start = value_copy;
    if (*start == '[') start++;
    char *end = start + strlen(start) - 1;
    if (*end == ']') *end = '\0';
    
    /* Split by commas */
    char *token = strtok(start, ",");
    while (token && *count < max_items) {
        token = trim_whitespace(token);
        
        /* Remove quotes if present */
        if (*token == '"' || *token == '\'') {
            token++;
            char *quote_end = strrchr(token, token[-1]);
            if (quote_end) *quote_end = '\0';
        }
        
        array[*count] = strdup(token);
        if (!array[*count]) break;
        
        (*count)++;
        token = strtok(NULL, ",");
    }
    
    free(value_copy);
    return array;
}

/**
 * Set configuration value
 */
static void set_config_value(const char *section, const char *key, const char *value) {
    if (!g_config_state.config || !key || !value) return;
    
    char *resolved_value = resolve_env_vars(value);
    if (!resolved_value) return;
    
    /* Parse values based on section and key */
    if (strcmp(section, "logging") == 0) {
        if (strcmp(key, "application_name") == 0) {
            strncpy(g_config_state.config->application_name, resolved_value,
                   sizeof(g_config_state.config->application_name) - 1);
        } else if (strcmp(key, "version") == 0) {
            strncpy(g_config_state.config->version, resolved_value,
                   sizeof(g_config_state.config->version) - 1);
        } else if (strcmp(key, "environment") == 0) {
            strncpy(g_config_state.config->environment, resolved_value,
                   sizeof(g_config_state.config->environment) - 1);
        } else if (strcmp(key, "datacenter") == 0) {
            strncpy(g_config_state.config->datacenter, resolved_value,
                   sizeof(g_config_state.config->datacenter) - 1);
        } else if (strcmp(key, "node_id") == 0) {
            strncpy(g_config_state.config->node_id, resolved_value,
                   sizeof(g_config_state.config->node_id) - 1);
        } else if (strcmp(key, "min_level") == 0) {
            g_config_state.config->min_level = parse_log_level(resolved_value);
        } else if (strcmp(key, "output_format") == 0) {
            g_config_state.config->format = parse_log_format(resolved_value);
        } else if (strcmp(key, "targets") == 0) {
            g_config_state.config->targets = atoi(resolved_value);
        }
    } else if (strcmp(section, "file_logging") == 0) {
        if (strcmp(key, "log_file_path") == 0) {
            strncpy(g_config_state.config->log_file_path, resolved_value,
                   sizeof(g_config_state.config->log_file_path) - 1);
        } else if (strcmp(key, "enable_rotation") == 0) {
            g_config_state.config->rotation.enabled = parse_bool(resolved_value);
        } else if (strcmp(key, "max_file_size_mb") == 0) {
            g_config_state.config->rotation.max_size_bytes = 
                (uint64_t)atoi(resolved_value) * 1024 * 1024;
        } else if (strcmp(key, "max_file_age_hours") == 0) {
            g_config_state.config->rotation.max_age_hours = atoi(resolved_value);
        } else if (strcmp(key, "max_rotated_files") == 0) {
            g_config_state.config->rotation.max_files = atoi(resolved_value);
        } else if (strcmp(key, "compress_rotated") == 0) {
            g_config_state.config->rotation.compress_rotated = parse_bool(resolved_value);
        }
    } else if (strcmp(section, "secret_masking") == 0) {
        if (strcmp(key, "enable_masking") == 0) {
            g_config_state.config->masking.enabled = parse_bool(resolved_value);
        } else if (strcmp(key, "mask_character") == 0) {
            g_config_state.config->masking.mask_char = resolved_value[0];
        } else if (strcmp(key, "preserve_original_length") == 0) {
            g_config_state.config->masking.preserve_length = parse_bool(resolved_value);
        } else if (strcmp(key, "log_masking_events") == 0) {
            g_config_state.config->masking.log_masking_events = parse_bool(resolved_value);
        } else if (strcmp(key, "masking_patterns") == 0) {
            g_config_state.config->masking.patterns = 
                parse_string_array(resolved_value, &g_config_state.config->masking.pattern_count);
        }
    } else if (strcmp(section, "syslog") == 0) {
        if (strcmp(key, "remote_enabled") == 0 && parse_bool(resolved_value)) {
            g_config_state.config->targets |= MI_ELOG_TARGET_REMOTE_SYSLOG;
        } else if (strcmp(key, "remote_hostname") == 0) {
            strncpy(g_config_state.config->syslog_remote.hostname, resolved_value,
                   sizeof(g_config_state.config->syslog_remote.hostname) - 1);
        } else if (strcmp(key, "remote_port") == 0) {
            g_config_state.config->syslog_remote.port = atoi(resolved_value);
        } else if (strcmp(key, "remote_use_tls") == 0) {
            g_config_state.config->syslog_remote.use_tls = parse_bool(resolved_value);
        }
    } else if (strcmp(section, "webhook") == 0) {
        if (strcmp(key, "enabled") == 0 && parse_bool(resolved_value)) {
            g_config_state.config->targets |= MI_ELOG_TARGET_WEBHOOK;
        } else if (strcmp(key, "url") == 0) {
            strncpy(g_config_state.config->webhook.url, resolved_value,
                   sizeof(g_config_state.config->webhook.url) - 1);
        } else if (strcmp(key, "timeout_ms") == 0) {
            g_config_state.config->webhook.timeout_ms = atoi(resolved_value);
        } else if (strcmp(key, "auth_header") == 0) {
            strncpy(g_config_state.config->webhook.auth_header, resolved_value,
                   sizeof(g_config_state.config->webhook.auth_header) - 1);
        } else if (strcmp(key, "batch_size") == 0) {
            g_config_state.config->webhook.batch_size = atoi(resolved_value);
        } else if (strcmp(key, "verify_ssl") == 0) {
            g_config_state.config->webhook.verify_ssl = parse_bool(resolved_value);
        }
    } else if (strcmp(section, "performance") == 0) {
        if (strcmp(key, "async_logging") == 0) {
            g_config_state.config->async_logging = parse_bool(resolved_value);
        } else if (strcmp(key, "buffer_size_kb") == 0) {
            g_config_state.config->buffer_size = atoi(resolved_value) * 1024;
        } else if (strcmp(key, "flush_interval_ms") == 0) {
            g_config_state.config->flush_interval_ms = atoi(resolved_value);
        }
    } else if (strcmp(section, "security") == 0) {
        if (strcmp(key, "secure_erase_buffers") == 0) {
            g_config_state.config->secure_erase_buffers = parse_bool(resolved_value);
        } else if (strcmp(key, "audit_log_access") == 0) {
            g_config_state.config->audit_log_access = parse_bool(resolved_value);
        }
    } else if (strcmp(section, "observability") == 0) {
        if (strcmp(key, "enable_metrics") == 0) {
            g_config_state.config->enable_metrics = parse_bool(resolved_value);
        } else if (strcmp(key, "metrics_file") == 0) {
            strncpy(g_config_state.config->metrics_file, resolved_value,
                   sizeof(g_config_state.config->metrics_file) - 1);
        }
    }
    
    free(resolved_value);
}

/**
 * Parse configuration line
 */
static void parse_config_line(char *line) {
    if (!line) return;
    
    line = trim_whitespace(line);
    
    /* Skip empty lines and comments */
    if (*line == '\0' || *line == '#' || *line == ';') {
        return;
    }
    
    /* Check for section header */
    if (*line == '[') {
        char *end = strchr(line, ']');
        if (end) {
            *end = '\0';
            strncpy(g_config_state.current_section, line + 1,
                   sizeof(g_config_state.current_section) - 1);
            return;
        }
    }
    
    /* Parse key-value pair */
    char *equals = strchr(line, '=');
    if (equals) {
        *equals = '\0';
        char *key = trim_whitespace(line);
        char *value = trim_whitespace(equals + 1);
        
        /* Remove quotes from value if present */
        if ((*value == '"' || *value == '\'')) {
            size_t len = strlen(value);
            if (len > 1 && value[len-1] == value[0]) {
                value[len-1] = '\0';
                value++;
            }
        }
        
        set_config_value(g_config_state.current_section, key, value);
    }
}

/**
 * Set default configuration values
 */
static void set_default_config(mi_elog_config_t *config) {
    if (!config) return;
    
    /* Initialize with enterprise defaults */
    strcpy(config->application_name, "memory-inspector-cli");
    strcpy(config->version, "1.0.0");
    strcpy(config->environment, "production");
    strcpy(config->datacenter, "unknown");
    strcpy(config->node_id, "unknown");
    
    config->min_level = MI_ELOG_INFO;
    config->format = MI_ELOG_FORMAT_JSON;
    config->targets = MI_ELOG_TARGET_CONSOLE | MI_ELOG_TARGET_FILE;
    
    strcpy(config->log_file_path, "/var/log/memory-inspector/memory-inspector.log");
    
    /* Rotation defaults */
    config->rotation.enabled = true;
    config->rotation.max_size_bytes = 100 * 1024 * 1024;  /* 100MB */
    config->rotation.max_age_hours = 24;
    config->rotation.max_files = 30;
    config->rotation.compress_rotated = true;
    strcpy(config->rotation.rotation_suffix, "%Y%m%d_%H%M%S");
    
    /* Masking defaults */
    config->masking.enabled = true;
    config->masking.mask_char = '*';
    config->masking.preserve_length = false;
    config->masking.log_masking_events = true;
    
    /* Remote defaults */
    config->syslog_remote.port = 514;
    config->syslog_remote.timeout_ms = 5000;
    config->syslog_remote.retry_count = 3;
    
    config->webhook.timeout_ms = 5000;
    config->webhook.batch_size = 100;
    config->webhook.verify_ssl = true;
    
    /* Performance defaults */
    config->async_logging = true;
    config->buffer_size = 64 * 1024;
    config->flush_interval_ms = 1000;
    
    /* Security defaults */
    config->secure_erase_buffers = true;
    config->audit_log_access = true;
    
    /* Observability defaults */
    config->enable_metrics = true;
    strcpy(config->metrics_file, "/var/log/memory-inspector/metrics.json");
}

/**
 * Load enterprise configuration from file
 */
bool mi_elog_load_config(const char *config_file, mi_elog_config_t *config) {
    if (!config_file || !config) {
        return false;
    }
    
    /* Set defaults first */
    set_default_config(config);
    
    /* Initialize parser state */
    g_config_state.config = config;
    g_config_state.current_section[0] = '\0';
    
    /* Try to open config file */
    FILE *file = fopen(config_file, "r");
    if (!file) {
        /* Config file not found - use defaults */
        return true;
    }
    
    /* Parse configuration file */
    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        parse_config_line(line);
    }
    
    fclose(file);
    
    /* Validate configuration */
    if (config->targets == 0) {
        config->targets = MI_ELOG_TARGET_CONSOLE;
    }
    
    if (config->buffer_size < 1024) {
        config->buffer_size = 1024;
    }
    
    return true;
}

/**
 * Override configuration with environment variables
 */
void mi_elog_override_from_env(mi_elog_config_t *config) {
    if (!config) return;
    
    const char *env_value;
    
    /* Override from environment variables */
    if ((env_value = getenv("MI_LOG_LEVEL"))) {
        config->min_level = parse_log_level(env_value);
    }
    
    if ((env_value = getenv("MI_LOG_FORMAT"))) {
        config->format = parse_log_format(env_value);
    }
    
    if ((env_value = getenv("MI_LOG_FILE"))) {
        strncpy(config->log_file_path, env_value, sizeof(config->log_file_path) - 1);
    }
    
    if ((env_value = getenv("MI_ENVIRONMENT"))) {
        strncpy(config->environment, env_value, sizeof(config->environment) - 1);
    }
    
    if ((env_value = getenv("MI_WEBHOOK_URL"))) {
        strncpy(config->webhook.url, env_value, sizeof(config->webhook.url) - 1);
        config->targets |= MI_ELOG_TARGET_WEBHOOK;
    }
    
    if ((env_value = getenv("MI_SYSLOG_SERVER"))) {
        strncpy(config->syslog_remote.hostname, env_value, 
               sizeof(config->syslog_remote.hostname) - 1);
        config->targets |= MI_ELOG_TARGET_REMOTE_SYSLOG;
    }
    
    if ((env_value = getenv("MI_DISABLE_SECRETS_MASKING"))) {
        if (parse_bool(env_value)) {
            config->masking.enabled = false;
        }
    }
}