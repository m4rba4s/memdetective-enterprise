/**
 * Memory Inspector CLI - Auto-Dump Engine
 * 
 * Automated memory dumping for forensics analysis
 * Secure, timestamped dumps with metadata
 */

#include "memory_inspector.h"
#include "platform.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#define DUMP_CHUNK_SIZE (64 * 1024)  /* 64KB chunks */
#define MAX_DUMP_SIZE (100 * 1024 * 1024)  /* 100MB max per region */
#define METADATA_VERSION 1

/* Dump metadata structure */
typedef struct {
    uint32_t version;
    uint32_t pid;
    uint64_t timestamp;
    uint64_t start_addr;
    uint64_t end_addr;
    uint64_t size;
    uint32_t permissions;
    uint32_t region_type;
    char process_name[256];
    char region_path[MI_MAX_PATH_LEN];
    char hostname[256];
    uint8_t is_suspicious;
    uint8_t is_injected;
    uint8_t reserved[6];
    uint32_t checksum;
} __attribute__((packed)) mi_dump_metadata_t;

/**
 * Calculate simple checksum for integrity
 */
static uint32_t calculate_checksum(const void *data, size_t size) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t checksum = 0;
    
    for (size_t i = 0; i < size; i++) {
        checksum = (checksum << 1) ^ bytes[i];
    }
    
    return checksum;
}

/**
 * Get timestamp string for filename
 */
static void get_timestamp_string(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y%m%d_%H%M%S", tm_info);
}

/**
 * Create dump filename
 */
static void create_dump_filename(char *filename, size_t size, 
                                const mi_process_info_t *info,
                                const mi_memory_region_t *region) {
    char timestamp[32];
    get_timestamp_string(timestamp, sizeof(timestamp));
    
    /* Extract basename from region path */
    const char *basename = strrchr(region->path, '/');
    basename = basename ? basename + 1 : region->path;
    
    if (basename[0] == '\0') {
        basename = "anonymous";
    }
    
    snprintf(filename, size, "memdump_pid%d_%s_%lx-%lx_%s.bin",
             info->pid, info->name, region->start_addr, region->end_addr, timestamp);
}

/**
 * Create metadata filename
 */
static void create_metadata_filename(char *filename, size_t size, const char *dump_filename) {
    size_t len = strlen(dump_filename);
    if (len > 4 && strcmp(dump_filename + len - 4, ".bin") == 0) {
        snprintf(filename, size, "%.*s.meta", (int)(len - 4), dump_filename);
    } else {
        if (strlen(dump_filename) + 5 < size) {  /* ".meta" is 5 chars */
            snprintf(filename, size, "%s.meta", dump_filename);
        } else {
            /* Truncate dump_filename to fit .meta suffix */
            snprintf(filename, size, "%.*s.meta", (int)(size - 6), dump_filename);
        }
    }
}

/**
 * Write dump metadata
 */
static mi_result_t write_dump_metadata(const char *metadata_path,
                                      const mi_process_info_t *info,
                                      const mi_memory_region_t *region,
                                      size_t actual_size,
                                      uint32_t data_checksum) {
    FILE *meta_file = fopen(metadata_path, "wb");
    if (!meta_file) {
        MI_LOG_ERROR("Failed to create metadata file %s: %s", metadata_path, strerror(errno));
        return MI_ERROR_DUMP_FAILED;
    }
    
    mi_dump_metadata_t metadata = {0};
    
    /* Fill metadata */
    metadata.version = METADATA_VERSION;
    metadata.pid = info->pid;
    metadata.timestamp = time(NULL);
    metadata.start_addr = region->start_addr;
    metadata.end_addr = region->end_addr;
    metadata.size = actual_size;
    metadata.permissions = region->permissions;
    metadata.region_type = region->type;
    metadata.is_suspicious = region->is_suspicious ? 1 : 0;
    metadata.is_injected = region->is_injected ? 1 : 0;
    
    strncpy(metadata.process_name, info->name, sizeof(metadata.process_name) - 1);
    metadata.process_name[sizeof(metadata.process_name) - 1] = '\0';
    strncpy(metadata.region_path, region->path, sizeof(metadata.region_path) - 1);
    metadata.region_path[sizeof(metadata.region_path) - 1] = '\0';
    
    /* Get hostname */
    if (gethostname(metadata.hostname, sizeof(metadata.hostname)) != 0) {
        strcpy(metadata.hostname, "unknown");
    }
    
    /* Calculate metadata checksum (excluding the checksum field itself) */
    metadata.checksum = calculate_checksum(&metadata, sizeof(metadata) - sizeof(metadata.checksum));
    metadata.checksum ^= data_checksum;  /* Include data checksum */
    
    /* Write metadata */
    if (fwrite(&metadata, sizeof(metadata), 1, meta_file) != 1) {
        MI_LOG_ERROR("Failed to write metadata to %s", metadata_path);
        fclose(meta_file);
        unlink(metadata_path);
        return MI_ERROR_DUMP_FAILED;
    }
    
    fclose(meta_file);
    
    MI_LOG_DEBUG("Metadata written to %s", metadata_path);
    return MI_SUCCESS;
}

/**
 * Dump single memory region
 */
static mi_result_t dump_memory_region(const mi_process_info_t *info,
                                     const mi_memory_region_t *region,
                                     const char *output_dir) {
    const mi_platform_ops_t *ops = mi_platform_get_ops();
    if (!ops || !ops->read_memory) {
        MI_LOG_ERROR("Memory read operation not available");
        return MI_ERROR_PLATFORM_UNSUPPORTED;
    }
    
    /* Skip non-readable regions */
    if (!(region->permissions & MI_PERM_READ)) {
        MI_LOG_DEBUG("Skipping non-readable region %lx-%lx", 
                     region->start_addr, region->end_addr);
        return MI_SUCCESS;
    }
    
    /* Limit dump size */
    size_t dump_size = region->size;
    if (dump_size > MAX_DUMP_SIZE) {
        MI_LOG_WARN("Region %lx-%lx too large (%zu bytes), limiting to %d bytes",
                   region->start_addr, region->end_addr, dump_size, MAX_DUMP_SIZE);
        dump_size = MAX_DUMP_SIZE;
    }
    
    /* Create filenames */
    char dump_filename[512];
    char dump_path[1024];
    char metadata_filename[512];
    char metadata_path[1024];
    
    create_dump_filename(dump_filename, sizeof(dump_filename), info, region);
    snprintf(dump_path, sizeof(dump_path), "%s/%s", output_dir, dump_filename);
    
    create_metadata_filename(metadata_filename, sizeof(metadata_filename), dump_filename);
    snprintf(metadata_path, sizeof(metadata_path), "%s/%s", output_dir, metadata_filename);
    
    MI_LOG_INFO("Dumping region %lx-%lx (%zu bytes) to %s",
               region->start_addr, region->end_addr, dump_size, dump_filename);
    
    /* Open dump file */
    FILE *dump_file = fopen(dump_path, "wb");
    if (!dump_file) {
        MI_LOG_ERROR("Failed to create dump file %s: %s", dump_path, strerror(errno));
        return MI_ERROR_DUMP_FAILED;
    }
    
    /* Allocate buffer */
    uint8_t *buffer = malloc(DUMP_CHUNK_SIZE);
    if (!buffer) {
        MI_LOG_ERROR("Failed to allocate dump buffer");
        fclose(dump_file);
        unlink(dump_path);
        return MI_ERROR_DUMP_FAILED;
    }
    
    /* Dump memory in chunks */
    size_t bytes_dumped = 0;
    uint32_t data_checksum = 0;
    uintptr_t current_addr = region->start_addr;
    
    while (bytes_dumped < dump_size) {
        size_t chunk_size = (dump_size - bytes_dumped > DUMP_CHUNK_SIZE) ?
                           DUMP_CHUNK_SIZE : (dump_size - bytes_dumped);
        
        /* Read memory chunk */
        mi_result_t result = ops->read_memory(info->pid, current_addr, buffer, chunk_size);
        if (result != MI_SUCCESS) {
            if (bytes_dumped == 0) {
                /* Couldn't read any data */
                MI_LOG_ERROR("Failed to read memory at %lx: %s", 
                           current_addr, mi_get_error_message(result));
                free(buffer);
                fclose(dump_file);
                unlink(dump_path);
                return result;
            } else {
                /* Partial read - stop here */
                MI_LOG_WARN("Partial memory read at %lx, stopping dump", current_addr);
                break;
            }
        }
        
        /* Write to file */
        if (fwrite(buffer, 1, chunk_size, dump_file) != chunk_size) {
            MI_LOG_ERROR("Failed to write dump data: %s", strerror(errno));
            free(buffer);
            fclose(dump_file);
            unlink(dump_path);
            return MI_ERROR_DUMP_FAILED;
        }
        
        /* Update checksum */
        data_checksum = calculate_checksum(buffer, chunk_size) ^ data_checksum;
        
        bytes_dumped += chunk_size;
        current_addr += chunk_size;
        
        /* Progress indication for large dumps */
        if (dump_size > (10 * 1024 * 1024) && (bytes_dumped % (1024 * 1024)) == 0) {
            MI_LOG_DEBUG("Dumped %zu MB / %zu MB", 
                        bytes_dumped / (1024 * 1024), dump_size / (1024 * 1024));
        }
    }
    
    free(buffer);
    fclose(dump_file);
    
    /* Write metadata */
    mi_result_t metadata_result = write_dump_metadata(metadata_path, info, region, 
                                                     bytes_dumped, data_checksum);
    if (metadata_result != MI_SUCCESS) {
        MI_LOG_WARN("Failed to write metadata for %s", dump_filename);
        /* Don't fail the entire dump for metadata issues */
    }
    
    MI_LOG_INFO("Successfully dumped %zu bytes to %s", bytes_dumped, dump_filename);
    
    /* Set appropriate file permissions */
    chmod(dump_path, 0600);  /* Owner read/write only */
    if (metadata_result == MI_SUCCESS) {
        chmod(metadata_path, 0600);
    }
    
    return MI_SUCCESS;
}

/**
 * Create output directory if it doesn't exist
 */
static mi_result_t ensure_output_directory(const char *output_dir) {
    struct stat st;
    
    if (stat(output_dir, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return MI_SUCCESS;
        } else {
            MI_LOG_ERROR("Output path %s exists but is not a directory", output_dir);
            return MI_ERROR_INVALID_CONFIG;
        }
    }
    
    /* Create directory */
    if (mkdir(output_dir, 0700) != 0) {
        MI_LOG_ERROR("Failed to create output directory %s: %s", output_dir, strerror(errno));
        return MI_ERROR_DUMP_FAILED;
    }
    
    MI_LOG_INFO("Created output directory: %s", output_dir);
    return MI_SUCCESS;
}

/**
 * Dump suspicious memory regions
 */
int mi_dump_suspicious_regions(const mi_process_info_t *info, const char *output_dir) {
    if (!info || !output_dir) {
        MI_LOG_ERROR("Invalid parameters for memory dump");
        return 0;
    }
    
    MI_LOG_INFO("Starting memory dump for PID %d (%s)", info->pid, info->name);
    
    /* Ensure output directory exists */
    mi_result_t result = ensure_output_directory(output_dir);
    if (result != MI_SUCCESS) {
        return 0;
    }
    
    /* Count suspicious regions */
    size_t suspicious_count = 0;
    for (size_t i = 0; i < info->region_count; i++) {
        const mi_memory_region_t *region = &info->regions[i];
        if (region->is_suspicious || region->is_injected) {
            suspicious_count++;
        }
    }
    
    if (suspicious_count == 0) {
        MI_LOG_INFO("No suspicious regions found to dump");
        return 0;
    }
    
    MI_LOG_INFO("Found %zu suspicious regions to dump", suspicious_count);
    
    /* Dump suspicious regions */
    int dumped_count = 0;
    for (size_t i = 0; i < info->region_count; i++) {
        const mi_memory_region_t *region = &info->regions[i];
        
        if (region->is_suspicious || region->is_injected) {
            result = dump_memory_region(info, region, output_dir);
            if (result == MI_SUCCESS) {
                dumped_count++;
            } else {
                MI_LOG_WARN("Failed to dump region %lx-%lx: %s",
                           region->start_addr, region->end_addr, mi_get_error_message(result));
            }
        }
    }
    
    MI_LOG_INFO("Memory dump complete: %d/%zu regions dumped successfully", 
               dumped_count, suspicious_count);
    
    return dumped_count;
}