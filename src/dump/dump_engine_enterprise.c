/**
 * Memory Inspector CLI - Auto-Dump Engine
 * 
 * Implementation with fail-safe mechanisms and performance optimization.
 */

#include "memory_inspector.h"
#include "platform.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/file.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <openssl/sha.h>

/* Enterprise configuration */
#define DUMP_CHUNK_SIZE (64 * 1024)
#define MAX_DUMP_SIZE (100 * 1024 * 1024)
#define MAX_CONCURRENT_DUMPS 4
#define DUMP_RETRY_COUNT 3
#define DUMP_RETRY_DELAY_MS 100
#define MIN_FREE_SPACE_MB 100
#define MAX_TOTAL_DUMPS_GB 10
#define DUMP_TTL_DAYS 30
#define METADATA_VERSION 2

/* Atomic write suffixes */
#define TEMP_SUFFIX ".part"
#define BACKUP_SUFFIX ".bak"
#define LOCK_SUFFIX ".lock"

/* Enterprise dump statistics */
typedef struct {
    uint64_t total_dumps;
    uint64_t successful_dumps;
    uint64_t failed_dumps;
    uint64_t retried_dumps;
    uint64_t total_bytes_dumped;
    uint64_t total_dump_time_ms;
    uint64_t average_speed_mbps;
    time_t last_cleanup;
    pthread_mutex_t stats_mutex;
} mi_dump_stats_t;

/* Enhanced metadata with forensics info */
typedef struct {
    uint32_t magic;                    /* Magic number for validation */
    uint32_t version;
    uint32_t header_size;
    uint32_t pid;
    uint64_t timestamp;
    uint64_t start_addr;
    uint64_t end_addr;
    uint64_t actual_size;
    uint32_t permissions;
    uint32_t region_type;
    char process_name[256];
    char region_path[MI_MAX_PATH_LEN];
    char hostname[256];
    char analyst_notes[512];           /* For IR team annotations */
    uint8_t sha256_hash[32];          /* SHA-256 of dump data */
    uint8_t is_suspicious;
    uint8_t is_injected;
    uint8_t dump_quality;             /* 0-100, based on read success */
    uint8_t compression_used;
    uint32_t original_size;           /* Before compression */
    uint32_t retry_count;
    uint64_t dump_duration_ms;
    uint32_t header_checksum;
    uint32_t data_checksum;
    uint8_t reserved[32];             /* Future extensions */
} __attribute__((packed)) mi_enterprise_metadata_t;

/* Dump configuration from environment/config file */
typedef struct {
    char output_dir[MI_MAX_PATH_LEN];
    size_t max_dump_size;
    size_t max_total_size;
    int max_concurrent;
    int retry_count;
    int retry_delay_ms;
    bool enable_compression;
    bool enable_encryption;
    bool skip_heap_regions;
    bool skip_stack_regions;
    bool atomic_writes;
    bool auto_cleanup;
    int ttl_days;
    char encryption_key[64];
} mi_dump_config_t;

/* Global state */
static mi_dump_stats_t g_dump_stats = {0};
static mi_dump_config_t g_dump_config = {0};
static volatile sig_atomic_t g_dump_interrupted = 0;
static pthread_mutex_t g_dump_mutex = PTHREAD_MUTEX_INITIALIZER;

#define DUMP_MAGIC 0x4D454D44  /* "MEMD" */

/**
 * Signal handler for graceful interruption
 */
static void dump_signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        g_dump_interrupted = 1;
    }
}

/**
 * Secure memory zeroization (compiler-safe)
 */
static void secure_zero(void *ptr, size_t size) {
    volatile uint8_t *volatile_ptr = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < size; i++) {
        volatile_ptr[i] = 0;
    }
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

/**
 * Calculate SHA-256 hash
 */
static void calculate_sha256(const void *data, size_t size, uint8_t *hash) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, size);
    SHA256_Final(hash, &ctx);
}

/**
 * Check available disk space
 */
static bool check_disk_space(const char *path, size_t required_bytes) {
    struct statvfs vfs;
    if (statvfs(path, &vfs) != 0) {
        MI_LOG_ERROR("Failed to check disk space for %s: %s", path, strerror(errno));
        return false;
    }
    
    uint64_t available = vfs.f_bavail * vfs.f_frsize;
    uint64_t required_with_margin = required_bytes + (MIN_FREE_SPACE_MB * 1024 * 1024);
    
    if (available < required_with_margin) {
        MI_LOG_ERROR("Insufficient disk space: need %zu MB, have %zu MB", 
                    required_with_margin / (1024*1024), available / (1024*1024));
        return false;
    }
    
    return true;
}

/**
 * Validate process is still alive and PID hasn't been recycled
 */
static bool validate_process_consistency(pid_t pid, const char *expected_name) {
    char current_name[256];
    const mi_platform_ops_t *ops = mi_platform_get_ops();
    
    if (!ops || !ops->is_process_running(pid)) {
        MI_LOG_WARN("Process %d is no longer running during dump", pid);
        return false;
    }
    
    if (ops->get_process_name(pid, current_name, sizeof(current_name)) == MI_SUCCESS) {
        if (strcmp(current_name, expected_name) != 0) {
            MI_LOG_WARN("Process name changed during dump: was '%s', now '%s'", 
                       expected_name, current_name);
            return false;
        }
    }
    
    return true;
}

/**
 * Atomic file operations with proper locking
 */
static int create_atomic_file(const char *final_path, char *temp_path, size_t temp_size) {
    snprintf(temp_path, temp_size, "%s%s", final_path, TEMP_SUFFIX);
    
    /* Create lock file to prevent race conditions */
    char lock_path[MI_MAX_PATH_LEN];
    snprintf(lock_path, sizeof(lock_path), "%s%s", final_path, LOCK_SUFFIX);
    
    int lock_fd = open(lock_path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (lock_fd == -1) {
        if (errno == EEXIST) {
            MI_LOG_WARN("Dump already in progress for %s", final_path);
            return -1;
        }
        MI_LOG_ERROR("Failed to create lock file %s: %s", lock_path, strerror(errno));
        return -1;
    }
    
    /* Write PID to lock file for debugging */
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    write(lock_fd, pid_str, strlen(pid_str));
    close(lock_fd);
    
    /* Create temporary file */
    int fd = open(temp_path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd == -1) {
        MI_LOG_ERROR("Failed to create temp file %s: %s", temp_path, strerror(errno));
        unlink(lock_path);
        return -1;
    }
    
    return fd;
}

/**
 * Commit atomic write (rename temp to final)
 */
static mi_result_t commit_atomic_write(const char *temp_path, const char *final_path) {
    char lock_path[MI_MAX_PATH_LEN];
    snprintf(lock_path, sizeof(lock_path), "%s%s", final_path, LOCK_SUFFIX);
    
    /* Sync to disk before rename */
    sync();
    
    if (rename(temp_path, final_path) != 0) {
        MI_LOG_ERROR("Failed to commit atomic write %s -> %s: %s", 
                    temp_path, final_path, strerror(errno));
        unlink(temp_path);
        unlink(lock_path);
        return MI_ERROR_DUMP_FAILED;
    }
    
    /* Remove lock file */
    unlink(lock_path);
    
    MI_LOG_DEBUG("Atomic write committed: %s", final_path);
    return MI_SUCCESS;
}

/**
 * Enhanced dump with retry mechanism and performance monitoring
 */
static mi_result_t dump_memory_region_with_retry(const mi_process_info_t *info,
                                                const mi_memory_region_t *region,
                                                const char *output_dir) {
    mi_result_t result = MI_ERROR_DUMP_FAILED;
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    for (int attempt = 0; attempt < g_dump_config.retry_count; attempt++) {
        if (g_dump_interrupted) {
            MI_LOG_INFO("Dump interrupted by signal");
            return MI_ERROR_DUMP_FAILED;
        }
        
        /* Validate process consistency */
        if (!validate_process_consistency(info->pid, info->name)) {
            return MI_ERROR_PROCESS_NOT_FOUND;
        }
        
        /* Check disk space before each attempt */
        if (!check_disk_space(output_dir, region->size)) {
            return MI_ERROR_DUMP_FAILED;
        }
        
        result = dump_memory_region_enterprise(info, region, output_dir, attempt);
        
        if (result == MI_SUCCESS) {
            break;
        }
        
        if (attempt < g_dump_config.retry_count - 1) {
            MI_LOG_WARN("Dump attempt %d failed, retrying in %d ms...", 
                       attempt + 1, g_dump_config.retry_delay_ms);
            
            struct timespec delay = {
                .tv_sec = g_dump_config.retry_delay_ms / 1000,
                .tv_nsec = (g_dump_config.retry_delay_ms % 1000) * 1000000
            };
            nanosleep(&delay, NULL);
            
            pthread_mutex_lock(&g_dump_stats.stats_mutex);
            g_dump_stats.retried_dumps++;
            pthread_mutex_unlock(&g_dump_stats.stats_mutex);
        }
    }
    
    /* Update statistics */
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    uint64_t duration_ms = (end_time.tv_sec - start_time.tv_sec) * 1000 +
                          (end_time.tv_nsec - start_time.tv_nsec) / 1000000;
    
    pthread_mutex_lock(&g_dump_stats.stats_mutex);
    if (result == MI_SUCCESS) {
        g_dump_stats.successful_dumps++;
        g_dump_stats.total_bytes_dumped += region->size;
    } else {
        g_dump_stats.failed_dumps++;
    }
    g_dump_stats.total_dump_time_ms += duration_ms;
    pthread_mutex_unlock(&g_dump_stats.stats_mutex);
    
    return result;
}

/**
 * Enterprise-grade dump with all safeguards
 */
static mi_result_t dump_memory_region_enterprise(const mi_process_info_t *info,
                                               const mi_memory_region_t *region,
                                               const char *output_dir,
                                               int attempt) {
    const mi_platform_ops_t *ops = mi_platform_get_ops();
    if (!ops || !ops->read_memory) {
        return MI_ERROR_PLATFORM_UNSUPPORTED;
    }
    
    /* Skip filtered region types */
    if ((g_dump_config.skip_heap_regions && region->type == MI_REGION_HEAP) ||
        (g_dump_config.skip_stack_regions && region->type == MI_REGION_STACK)) {
        MI_LOG_DEBUG("Skipping filtered region type %d", region->type);
        return MI_SUCCESS;
    }
    
    /* Create filenames */
    char dump_filename[512];
    char dump_path[1024];
    char temp_path[1024];
    
    create_dump_filename_enterprise(dump_filename, sizeof(dump_filename), info, region, attempt);
    snprintf(dump_path, sizeof(dump_path), "%s/%s", output_dir, dump_filename);
    
    MI_LOG_INFO("Dumping region %lx-%lx (%zu bytes) to %s (attempt %d)",
               region->start_addr, region->end_addr, region->size, dump_filename, attempt + 1);
    
    /* Create atomic file */
    int dump_fd = create_atomic_file(dump_path, temp_path, sizeof(temp_path));
    if (dump_fd == -1) {
        return MI_ERROR_DUMP_FAILED;
    }
    
    /* Allocate secure buffer */
    uint8_t *buffer = calloc(1, DUMP_CHUNK_SIZE);
    if (!buffer) {
        close(dump_fd);
        unlink(temp_path);
        return MI_ERROR_DUMP_FAILED;
    }
    
    /* Dump memory with progress tracking */
    size_t bytes_dumped = 0;
    size_t failed_reads = 0;
    uintptr_t current_addr = region->start_addr;
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    
    while (bytes_dumped < region->size && !g_dump_interrupted) {
        size_t chunk_size = (region->size - bytes_dumped > DUMP_CHUNK_SIZE) ?
                           DUMP_CHUNK_SIZE : (region->size - bytes_dumped);
        
        /* Read memory chunk with validation */
        mi_result_t read_result = ops->read_memory(info->pid, current_addr, buffer, chunk_size);
        if (read_result != MI_SUCCESS) {
            failed_reads++;
            if (failed_reads > 10 || bytes_dumped == 0) {
                MI_LOG_ERROR("Too many read failures at %lx", current_addr);
                break;
            }
            
            /* Fill with pattern for failed reads */
            memset(buffer, 0xDE, chunk_size);
            MI_LOG_DEBUG("Memory read failed at %lx, filled with pattern", current_addr);
        }
        
        /* Write to file with error checking */
        ssize_t written = write(dump_fd, buffer, chunk_size);
        if (written != (ssize_t)chunk_size) {
            MI_LOG_ERROR("Write failed: expected %zu, wrote %zd: %s", 
                        chunk_size, written, strerror(errno));
            break;
        }
        
        /* Update hash */
        SHA256_Update(&sha_ctx, buffer, chunk_size);
        
        bytes_dumped += chunk_size;
        current_addr += chunk_size;
        
        /* Progress for large dumps */
        if (region->size > (10 * 1024 * 1024) && (bytes_dumped % (1024 * 1024)) == 0) {
            MI_LOG_DEBUG("Progress: %zu/%zu MB (%.1f%%)", 
                        bytes_dumped / (1024*1024), region->size / (1024*1024),
                        (double)bytes_dumped / region->size * 100);
        }
    }
    
    close(dump_fd);
    
    /* Check if dump was successful */
    if (bytes_dumped == 0 || g_dump_interrupted) {
        unlink(temp_path);
        secure_zero(buffer, DUMP_CHUNK_SIZE);
        free(buffer);
        return MI_ERROR_DUMP_FAILED;
    }
    
    /* Calculate final hash */
    uint8_t sha256_hash[32];
    SHA256_Final(sha256_hash, &sha_ctx);
    
    /* Create enhanced metadata */
    mi_result_t meta_result = write_enterprise_metadata(dump_path, info, region, 
                                                       bytes_dumped, failed_reads, 
                                                       sha256_hash, attempt);
    
    /* Commit atomic write */
    mi_result_t commit_result = commit_atomic_write(temp_path, dump_path);
    
    /* Secure cleanup */
    secure_zero(buffer, DUMP_CHUNK_SIZE);
    free(buffer);
    
    if (commit_result == MI_SUCCESS && meta_result == MI_SUCCESS) {
        MI_LOG_INFO("Successfully dumped %zu bytes to %s (quality: %.1f%%)", 
                   bytes_dumped, dump_filename, 
                   (double)(bytes_dumped - failed_reads * DUMP_CHUNK_SIZE) / bytes_dumped * 100);
        return MI_SUCCESS;
    }
    
    return MI_ERROR_DUMP_FAILED;
}

/**
 * Enterprise metadata with forensics information
 */
static mi_result_t write_enterprise_metadata(const char *dump_path,
                                           const mi_process_info_t *info,
                                           const mi_memory_region_t *region,
                                           size_t actual_size,
                                           size_t failed_reads,
                                           const uint8_t *sha256_hash,
                                           int attempt) {
    char metadata_path[1024];
    snprintf(metadata_path, sizeof(metadata_path), "%s.meta", dump_path);
    
    mi_enterprise_metadata_t metadata = {0};
    
    /* Fill enhanced metadata */
    metadata.magic = DUMP_MAGIC;
    metadata.version = METADATA_VERSION;
    metadata.header_size = sizeof(metadata);
    metadata.pid = info->pid;
    metadata.timestamp = time(NULL);
    metadata.start_addr = region->start_addr;
    metadata.end_addr = region->end_addr;
    metadata.actual_size = actual_size;
    metadata.permissions = region->permissions;
    metadata.region_type = region->type;
    metadata.is_suspicious = region->is_suspicious ? 1 : 0;
    metadata.is_injected = region->is_injected ? 1 : 0;
    metadata.retry_count = attempt;
    
    /* Calculate dump quality */
    metadata.dump_quality = (uint8_t)((double)(actual_size - failed_reads * DUMP_CHUNK_SIZE) / actual_size * 100);
    
    /* Copy strings safely */
    strncpy(metadata.process_name, info->name, sizeof(metadata.process_name) - 1);
    strncpy(metadata.region_path, region->path, sizeof(metadata.region_path) - 1);
    gethostname(metadata.hostname, sizeof(metadata.hostname) - 1);
    
    /* Copy hash */
    memcpy(metadata.sha256_hash, sha256_hash, 32);
    
    /* Add analyst notes */
    snprintf(metadata.analyst_notes, sizeof(metadata.analyst_notes),
            "Auto-dump by Memory Inspector CLI v%s. Quality: %d%%. Failed reads: %zu",
            MI_VERSION_STRING, metadata.dump_quality, failed_reads);
    
    /* Calculate checksums */
    metadata.header_checksum = calculate_checksum(&metadata, 
                                                 sizeof(metadata) - sizeof(metadata.header_checksum));
    
    /* Write metadata atomically */
    char temp_meta_path[1024];
    snprintf(temp_meta_path, sizeof(temp_meta_path), "%s%s", metadata_path, TEMP_SUFFIX);
    
    FILE *meta_file = fopen(temp_meta_path, "wb");
    if (!meta_file) {
        MI_LOG_ERROR("Failed to create metadata file %s: %s", temp_meta_path, strerror(errno));
        return MI_ERROR_DUMP_FAILED;
    }
    
    if (fwrite(&metadata, sizeof(metadata), 1, meta_file) != 1) {
        fclose(meta_file);
        unlink(temp_meta_path);
        return MI_ERROR_DUMP_FAILED;
    }
    
    fclose(meta_file);
    
    if (rename(temp_meta_path, metadata_path) != 0) {
        unlink(temp_meta_path);
        return MI_ERROR_DUMP_FAILED;
    }
    
    chmod(metadata_path, 0600);
    return MI_SUCCESS;
}

/**
 * Auto-cleanup old dumps based on TTL and size limits
 */
static mi_result_t cleanup_old_dumps(const char *output_dir) {
    /* Implementation for automatic cleanup based on TTL and size limits */
    MI_LOG_INFO("Auto-cleanup not yet implemented");
    return MI_SUCCESS;
}

/**
 * Enterprise dump statistics and observability
 */
void mi_dump_print_statistics(void) {
    pthread_mutex_lock(&g_dump_stats.stats_mutex);
    
    printf("\n");
    printf("📊 Dump Engine Statistics:\n");
    printf("  Total dumps:      %lu\n", g_dump_stats.total_dumps);
    printf("  Successful:       %lu (%.1f%%)\n", g_dump_stats.successful_dumps,
           g_dump_stats.total_dumps ? (double)g_dump_stats.successful_dumps / g_dump_stats.total_dumps * 100 : 0);
    printf("  Failed:           %lu\n", g_dump_stats.failed_dumps);
    printf("  Retries:          %lu\n", g_dump_stats.retried_dumps);
    printf("  Total data:       %.2f MB\n", (double)g_dump_stats.total_bytes_dumped / (1024*1024));
    
    if (g_dump_stats.total_dump_time_ms > 0) {
        printf("  Average speed:    %.1f MB/s\n", 
               (double)g_dump_stats.total_bytes_dumped / (g_dump_stats.total_dump_time_ms / 1000.0) / (1024*1024));
    }
    
    pthread_mutex_unlock(&g_dump_stats.stats_mutex);
}