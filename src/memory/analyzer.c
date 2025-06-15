/**
 * Memory Inspector CLI - Memory Analyzer
 * 
 * Advanced memory analysis and anomaly detection
 * Pattern recognition and security assessment
 */

#include "memory_inspector.h"
#include "platform.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Anomaly detection patterns */
typedef struct {
    const char *name;
    const char *description;
    bool (*detector)(const mi_memory_region_t *region);
} mi_anomaly_detector_t;

/**
 * Detect RWX (read-write-execute) regions
 */
static bool detect_rwx_regions(const mi_memory_region_t *region) {
    return (region->permissions & MI_PERM_READ) &&
           (region->permissions & MI_PERM_WRITE) &&
           (region->permissions & MI_PERM_EXEC);
}

/**
 * Detect anonymous executable regions
 */
static bool detect_anon_exec(const mi_memory_region_t *region) {
    if (!(region->permissions & MI_PERM_EXEC)) {
        return false;
    }
    
    return (region->path[0] == '\0' || 
            strstr(region->path, "[anon]") ||
            strstr(region->path, "[deleted]"));
}

/**
 * Detect unusual heap regions
 */
static bool detect_unusual_heap(const mi_memory_region_t *region) {
    if (region->type != MI_REGION_HEAP) {
        return false;
    }
    
    /* Executable heap is highly suspicious */
    if (region->permissions & MI_PERM_EXEC) {
        return true;
    }
    
    /* Extremely large heap regions */
    if (region->size > (500 * 1024 * 1024)) { /* 500MB */
        return true;
    }
    
    return false;
}

/**
 * Detect stack anomalies
 */
static bool detect_stack_anomalies(const mi_memory_region_t *region) {
    if (region->type != MI_REGION_STACK) {
        return false;
    }
    
    /* Executable stack */
    if (region->permissions & MI_PERM_EXEC) {
        return true;
    }
    
    /* Unusually large stack */
    if (region->size > (64 * 1024 * 1024)) { /* 64MB */
        return true;
    }
    
    return false;
}

/**
 * Detect code injection patterns
 */
static bool detect_code_injection(const mi_memory_region_t *region) {
    /* Look for executable regions in unusual locations */
    if (!(region->permissions & MI_PERM_EXEC)) {
        return false;
    }
    
    /* Skip legitimate system libraries */
    if (strstr(region->path, "/lib/") ||
        strstr(region->path, "/usr/lib/") ||
        strstr(region->path, "/lib64/") ||
        strstr(region->path, "/usr/lib64/")) {
        return false;
    }
    
    /* Check for suspicious paths */
    if (strstr(region->path, "/tmp/") ||
        strstr(region->path, "/var/tmp/") ||
        strstr(region->path, "/dev/shm/") ||
        strstr(region->path, ".so.") ||
        strstr(region->path, "[deleted]")) {
        return true;
    }
    
    return false;
}

/**
 * Detect memory gaps (potential hiding spots)
 */
static bool detect_memory_gaps(const mi_memory_region_t *region) {
    /* This would require comparing with adjacent regions */
    /* For now, we'll mark very small regions as potentially suspicious */
    if (region->size < 4096 && (region->permissions & MI_PERM_EXEC)) {
        return true;
    }
    
    return false;
}

/* Anomaly detectors array */
static const mi_anomaly_detector_t anomaly_detectors[] = {
    {
        .name = "RWX_REGIONS",
        .description = "Read-Write-Execute memory regions",
        .detector = detect_rwx_regions
    },
    {
        .name = "ANON_EXEC",
        .description = "Anonymous executable regions",
        .detector = detect_anon_exec
    },
    {
        .name = "UNUSUAL_HEAP",
        .description = "Suspicious heap characteristics",
        .detector = detect_unusual_heap
    },
    {
        .name = "STACK_ANOMALIES",
        .description = "Stack security anomalies",
        .detector = detect_stack_anomalies
    },
    {
        .name = "CODE_INJECTION",
        .description = "Potential code injection",
        .detector = detect_code_injection
    },
    {
        .name = "MEMORY_GAPS",
        .description = "Suspicious memory gaps or small regions",
        .detector = detect_memory_gaps
    }
};

#define NUM_DETECTORS (sizeof(anomaly_detectors) / sizeof(anomaly_detectors[0]))

/**
 * Analyze single memory region
 */
static int analyze_single_region(mi_memory_region_t *region) {
    int anomaly_count = 0;
    
    for (size_t i = 0; i < NUM_DETECTORS; i++) {
        if (anomaly_detectors[i].detector(region)) {
            MI_LOG_WARN("Anomaly detected in region %lx-%lx: %s - %s",
                       region->start_addr, region->end_addr,
                       anomaly_detectors[i].name,
                       anomaly_detectors[i].description);
            
            region->is_suspicious = true;
            anomaly_count++;
        }
    }
    
    return anomaly_count;
}

/**
 * Analyze process memory layout
 */
static void analyze_memory_layout(const mi_process_info_t *info) {
    size_t total_size = 0;
    size_t exec_size = 0;
    size_t anon_size = 0;
    size_t rwx_count = 0;
    
    for (size_t i = 0; i < info->region_count; i++) {
        const mi_memory_region_t *region = &info->regions[i];
        
        total_size += region->size;
        
        if (region->permissions & MI_PERM_EXEC) {
            exec_size += region->size;
        }
        
        if (region->path[0] == '\0') {
            anon_size += region->size;
        }
        
        if ((region->permissions & MI_PERM_READ) &&
            (region->permissions & MI_PERM_WRITE) &&
            (region->permissions & MI_PERM_EXEC)) {
            rwx_count++;
        }
    }
    
    MI_LOG_INFO("Memory Layout Analysis:");
    MI_LOG_INFO("  Total memory: %zu MB", total_size / (1024 * 1024));
    MI_LOG_INFO("  Executable memory: %zu MB", exec_size / (1024 * 1024));
    MI_LOG_INFO("  Anonymous memory: %zu MB", anon_size / (1024 * 1024));
    MI_LOG_INFO("  RWX regions: %zu", rwx_count);
    
    /* Statistical anomalies */
    if (rwx_count > 0) {
        MI_LOG_WARN("Process has %zu RWX regions - potential security risk", rwx_count);
    }
    
    double exec_ratio = (double)exec_size / total_size;
    if (exec_ratio > 0.5) {
        MI_LOG_WARN("High executable memory ratio: %.2f%% - potential packer/obfuscation",
                   exec_ratio * 100);
    }
    
    double anon_ratio = (double)anon_size / total_size;
    if (anon_ratio > 0.7) {
        MI_LOG_WARN("High anonymous memory ratio: %.2f%% - potential code injection",
                   anon_ratio * 100);
    }
}

/**
 * Check for common shellcode patterns
 */
static bool check_shellcode_patterns(const mi_memory_region_t *region, 
                                   const mi_process_info_t *info) {
    /* Only check executable regions */
    if (!(region->permissions & MI_PERM_EXEC)) {
        return false;
    }
    
    /* Read memory content for pattern analysis */
    const mi_platform_ops_t *ops = mi_platform_get_ops();
    if (!ops || !ops->read_memory) {
        return false;
    }
    
    /* Sample first 1KB for pattern analysis */
    uint8_t buffer[1024];
    mi_result_t result = ops->read_memory(info->pid, region->start_addr, 
                                         buffer, sizeof(buffer));
    if (result != MI_SUCCESS) {
        return false;
    }
    
    /* Check for common x86/x64 shellcode patterns */
    const uint8_t nop_sled[] = {0x90, 0x90, 0x90, 0x90}; /* NOP sled */
    const uint8_t int3_pattern[] = {0xCC, 0xCC, 0xCC};    /* INT3 breakpoints */
    
    size_t nop_count = 0;
    size_t int3_count = 0;
    
    for (size_t i = 0; i < sizeof(buffer) - 4; i++) {
        if (memcmp(&buffer[i], nop_sled, sizeof(nop_sled)) == 0) {
            nop_count++;
        }
        if (i < sizeof(buffer) - 3 && 
            memcmp(&buffer[i], int3_pattern, sizeof(int3_pattern)) == 0) {
            int3_count++;
        }
    }
    
    /* Heuristic: many NOPs or INT3s might indicate shellcode */
    if (nop_count > 10 || int3_count > 5) {
        MI_LOG_WARN("Potential shellcode pattern detected in region %lx-%lx (NOPs: %zu, INT3s: %zu)",
                   region->start_addr, region->end_addr, nop_count, int3_count);
        return true;
    }
    
    return false;
}

/**
 * Analyze memory regions for anomalies
 */
int mi_analyze_regions(mi_process_info_t *info) {
    if (!info) {
        return 0;
    }
    
    MI_LOG_INFO("Starting memory analysis for PID %d (%s)", info->pid, info->name);
    
    int total_anomalies = 0;
    int suspicious_regions = 0;
    
    /* Analyze overall memory layout */
    analyze_memory_layout(info);
    
    /* Analyze individual regions */
    for (size_t i = 0; i < info->region_count; i++) {
        mi_memory_region_t *region = &info->regions[i];
        
        MI_LOG_TRACE("Analyzing region %lx-%lx (%s)", 
                    region->start_addr, region->end_addr, region->path);
        
        int region_anomalies = analyze_single_region(region);
        total_anomalies += region_anomalies;
        
        if (region->is_suspicious) {
            suspicious_regions++;
        }
        
        /* Check for shellcode patterns */
        if (check_shellcode_patterns(region, info)) {
            region->is_suspicious = true;
            total_anomalies++;
        }
    }
    
    MI_LOG_INFO("Memory analysis complete:");
    MI_LOG_INFO("  Total regions: %zu", info->region_count);
    MI_LOG_INFO("  Suspicious regions: %d", suspicious_regions);
    MI_LOG_INFO("  Total anomalies: %d", total_anomalies);
    
    if (total_anomalies > 0) {
        MI_LOG_WARN("Process shows signs of potential compromise or malicious activity");
    } else {
        MI_LOG_INFO("No obvious security anomalies detected");
    }
    
    return total_anomalies;
}