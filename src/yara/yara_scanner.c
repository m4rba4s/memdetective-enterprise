/**
 * Memory Inspector CLI - YARA Scanner Integration
 * 
 * High-performance YARA-based memory scanning
 * Pattern matching and malware signature detection
 */

#include "memory_inspector.h"
#include "platform.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <yara.h>  // Temporarily disabled
#ifdef HAVE_YARA
#include <yara.h>
#else
/* YARA stubs when not available */
typedef void YR_COMPILER;
typedef void YR_RULES;
typedef void YR_SCAN_CONTEXT;
#define ERROR_SUCCESS 0
#define SCAN_FLAGS_REPORT_RULES_MATCHING 0
#define CALLBACK_CONTINUE 0
#endif

#define MAX_SCAN_SIZE (64 * 1024 * 1024)  /* 64MB per scan */
#define SCAN_CHUNK_SIZE (1024 * 1024)     /* 1MB chunks */

/* YARA scan context */
typedef struct {
    const mi_process_info_t *process_info;
    int match_count;
    const mi_memory_region_t *current_region;
} mi_yara_context_t;

#ifdef HAVE_YARA
/* Global YARA state */
static struct {
    YR_COMPILER *compiler;
    YR_RULES *rules;
    bool initialized;
} g_yara_state = {
    .compiler = NULL,
    .rules = NULL,
    .initialized = false
};
#endif

#ifdef HAVE_YARA
/**
 * YARA match callback
 */
static int yara_callback(YR_SCAN_CONTEXT *context, int message, void *message_data, void *user_data) {
    mi_yara_context_t *scan_ctx = (mi_yara_context_t *)user_data;
    
    switch (message) {
        case CALLBACK_MSG_RULE_MATCHING: {
            YR_RULE *rule = (YR_RULE *)message_data;
            
            MI_LOG_WARN("YARA match found in PID %d region %lx-%lx: Rule '%s'",
                       scan_ctx->process_info->pid,
                       scan_ctx->current_region->start_addr,
                       scan_ctx->current_region->end_addr,
                       rule->identifier);
            
            /* Log rule tags if present */
            YR_STRING *string;
            yr_rule_strings_foreach(rule, string) {
                YR_MATCH *match;
                yr_string_matches_foreach(context, string, match) {
                    MI_LOG_INFO("  String match: '%s' at offset %lx",
                               string->identifier, match->offset);
                }
            }
            
            scan_ctx->match_count++;
            break;
        }
        
        case CALLBACK_MSG_RULE_NOT_MATCHING:
            /* Rule didn't match - no action needed */
            break;
            
        case CALLBACK_MSG_SCAN_FINISHED:
            MI_LOG_DEBUG("YARA scan finished for region %lx-%lx",
                        scan_ctx->current_region->start_addr,
                        scan_ctx->current_region->end_addr);
            break;
            
        case CALLBACK_MSG_IMPORT_MODULE:
            /* Module import - no action needed */
            break;
            
        default:
            MI_LOG_DEBUG("YARA callback message: %d", message);
            break;
    }
    
    return CALLBACK_CONTINUE;
}

/**
 * Initialize YARA engine
 */
static mi_result_t yara_init(void) {
    if (g_yara_state.initialized) {
        return MI_SUCCESS;
    }
    
    MI_LOG_DEBUG("Initializing YARA engine");
    
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        MI_LOG_ERROR("Failed to initialize YARA: %d", result);
        return MI_ERROR_YARA_INIT;
    }
    
    result = yr_compiler_create(&g_yara_state.compiler);
    if (result != ERROR_SUCCESS) {
        MI_LOG_ERROR("Failed to create YARA compiler: %d", result);
        yr_finalize();
        return MI_ERROR_YARA_INIT;
    }
    
    g_yara_state.initialized = true;
    MI_LOG_INFO("YARA engine initialized successfully");
    
    return MI_SUCCESS;
}

/**
 * Load YARA rules from file
 */
static mi_result_t load_yara_rules(const char *rules_path) {
    if (!rules_path || !rules_path[0]) {
        MI_LOG_ERROR("Invalid YARA rules path");
        return MI_ERROR_INVALID_CONFIG;
    }
    
    MI_LOG_INFO("Loading YARA rules from: %s", rules_path);
    
    FILE *rules_file = fopen(rules_path, "r");
    if (!rules_file) {
        MI_LOG_ERROR("Failed to open YARA rules file: %s", rules_path);
        return MI_ERROR_YARA_INIT;
    }
    
    /* Compile rules */
    int result = yr_compiler_add_file(g_yara_state.compiler, rules_file, NULL, rules_path);
    fclose(rules_file);
    
    if (result != ERROR_SUCCESS) {
        MI_LOG_ERROR("Failed to compile YARA rules: %d", result);
        return MI_ERROR_YARA_INIT;
    }
    
    /* Get compiled rules */
    result = yr_compiler_get_rules(g_yara_state.compiler, &g_yara_state.rules);
    if (result != ERROR_SUCCESS) {
        MI_LOG_ERROR("Failed to get compiled YARA rules: %d", result);
        return MI_ERROR_YARA_INIT;
    }
    
    MI_LOG_INFO("YARA rules loaded and compiled successfully");
    return MI_SUCCESS;
}

/**
 * Create default YARA rules for common threats
 */
static mi_result_t create_default_rules(void) {
    MI_LOG_INFO("Creating default YARA rules for common threats");
    
    const char *default_rules = 
        "rule Shellcode_NOP_Sled {\n"
        "    meta:\n"
        "        description = \"Detects NOP sled patterns common in shellcode\"\n"
        "        author = \"Memory Inspector\"\n"
        "    strings:\n"
        "        $nop_sled = { 90 90 90 90 90 90 90 90 90 90 }\n"
        "    condition:\n"
        "        $nop_sled\n"
        "}\n"
        "\n"
        "rule Suspicious_Executable_Stack {\n"
        "    meta:\n"
        "        description = \"Detects potential stack-based code execution\"\n"
        "        author = \"Memory Inspector\"\n"
        "    strings:\n"
        "        $x86_call = { E8 ?? ?? ?? ?? }\n"
        "        $x86_jmp = { E9 ?? ?? ?? ?? }\n"
        "        $x64_call = { 48 E8 ?? ?? ?? ?? }\n"
        "    condition:\n"
        "        any of them\n"
        "}\n"
        "\n"
        "rule Windows_API_Hashing {\n"
        "    meta:\n"
        "        description = \"Detects API name hashing techniques\"\n"
        "        author = \"Memory Inspector\"\n"
        "    strings:\n"
        "        $hash1 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? }\n"
        "        $hash2 = { B8 ?? ?? ?? ?? BB ?? ?? ?? ?? }\n"
        "    condition:\n"
        "        any of them\n"
        "}\n"
        "\n"
        "rule Metasploit_Patterns {\n"
        "    meta:\n"
        "        description = \"Detects common Metasploit payload patterns\"\n"
        "        author = \"Memory Inspector\"\n"
        "    strings:\n"
        "        $meterpreter = \"meterpreter\" nocase\n"
        "        $msf_pattern = /Msf::[A-Za-z]+::[A-Za-z]+/\n"
        "        $payload_uuid = { 4D 5A 78 00 01 00 00 00 04 00 00 00 }\n"
        "    condition:\n"
        "        any of them\n"
        "}\n";
    
    int result = yr_compiler_add_string(g_yara_state.compiler, default_rules, NULL);
    if (result != ERROR_SUCCESS) {
        MI_LOG_ERROR("Failed to compile default YARA rules: %d", result);
        return MI_ERROR_YARA_INIT;
    }
    
    result = yr_compiler_get_rules(g_yara_state.compiler, &g_yara_state.rules);
    if (result != ERROR_SUCCESS) {
        MI_LOG_ERROR("Failed to get default YARA rules: %d", result);
        return MI_ERROR_YARA_INIT;
    }
    
    MI_LOG_INFO("Default YARA rules created successfully");
    return MI_SUCCESS;
}

/**
 * Scan memory region with YARA
 */
static int scan_memory_region(const mi_process_info_t *info, 
                             const mi_memory_region_t *region,
                             mi_yara_context_t *scan_ctx) {
    const mi_platform_ops_t *ops = mi_platform_get_ops();
    if (!ops || !ops->read_memory) {
        MI_LOG_ERROR("Memory read operation not available");
        return 0;
    }
    
    /* Skip non-readable regions */
    if (!(region->permissions & MI_PERM_READ)) {
        MI_LOG_TRACE("Skipping non-readable region %lx-%lx", 
                     region->start_addr, region->end_addr);
        return 0;
    }
    
    /* Limit scan size to prevent excessive memory usage */
    size_t scan_size = region->size;
    if (scan_size > MAX_SCAN_SIZE) {
        MI_LOG_WARN("Region %lx-%lx too large (%zu bytes), limiting to %d bytes",
                   region->start_addr, region->end_addr, scan_size, MAX_SCAN_SIZE);
        scan_size = MAX_SCAN_SIZE;
    }
    
    /* Allocate buffer for memory content */
    uint8_t *buffer = malloc(scan_size);
    if (!buffer) {
        MI_LOG_ERROR("Failed to allocate scan buffer (%zu bytes)", scan_size);
        return 0;
    }
    
    /* Read memory content */
    mi_result_t result = ops->read_memory(info->pid, region->start_addr, buffer, scan_size);
    if (result != MI_SUCCESS) {
        MI_LOG_DEBUG("Failed to read memory region %lx-%lx: %s",
                    region->start_addr, region->end_addr, mi_get_error_message(result));
        free(buffer);
        return 0;
    }
    
    /* Update scan context */
    scan_ctx->current_region = region;
    int initial_matches = scan_ctx->match_count;
    
    MI_LOG_TRACE("Scanning region %lx-%lx (%zu bytes) with YARA",
                region->start_addr, region->end_addr, scan_size);
    
    /* Perform YARA scan */
    int yara_result = yr_rules_scan_mem(g_yara_state.rules, buffer, scan_size,
                                       SCAN_FLAGS_REPORT_RULES_MATCHING,
                                       yara_callback, scan_ctx, 0);
    
    free(buffer);
    
    if (yara_result != ERROR_SUCCESS) {
        MI_LOG_ERROR("YARA scan failed for region %lx-%lx: %d",
                    region->start_addr, region->end_addr, yara_result);
        return 0;
    }
    
    int region_matches = scan_ctx->match_count - initial_matches;
    if (region_matches > 0) {
        MI_LOG_WARN("Found %d YARA matches in region %lx-%lx (%s)",
                   region_matches, region->start_addr, region->end_addr, region->path);
    }
    
    return region_matches;
}
#endif /* HAVE_YARA internal functions */

/**
 * Scan memory with YARA rules
 */
int mi_yara_scan(const mi_process_info_t *info, const char *rules_path) {
#ifndef HAVE_YARA
    (void)info;        /* Suppress unused parameter warning */
    (void)rules_path;  /* Suppress unused parameter warning */
    MI_LOG_WARN("YARA support not compiled in - skipping scan");
    return 0;
#else
    if (!info) {
        MI_LOG_ERROR("Invalid process info");
        return 0;
    }
    
    MI_LOG_INFO("Starting YARA scan for PID %d (%s)", info->pid, info->name);
    
    /* Initialize YARA if needed */
    mi_result_t result = yara_init();
    if (result != MI_SUCCESS) {
        return 0;
    }
    
    /* Load rules */
    if (rules_path && rules_path[0]) {
        result = load_yara_rules(rules_path);
    } else {
        result = create_default_rules();
    }
    
    if (result != MI_SUCCESS) {
        return 0;
    }
    
    /* Initialize scan context */
    mi_yara_context_t scan_ctx = {
        .process_info = info,
        .match_count = 0,
        .current_region = NULL
    };
    
    /* Scan each memory region */
    int total_matches = 0;
    size_t scanned_regions = 0;
    
    for (size_t i = 0; i < info->region_count; i++) {
        const mi_memory_region_t *region = &info->regions[i];
        
        /* Prioritize suspicious regions */
        if (region->is_suspicious || region->is_injected ||
            (region->permissions & MI_PERM_EXEC)) {
            
            int region_matches = scan_memory_region(info, region, &scan_ctx);
            total_matches += region_matches;
            scanned_regions++;
        }
    }
    
    /* Scan remaining regions if no matches found yet */
    if (total_matches == 0) {
        MI_LOG_INFO("No matches in priority regions, scanning all readable regions");
        
        for (size_t i = 0; i < info->region_count; i++) {
            const mi_memory_region_t *region = &info->regions[i];
            
            /* Skip already scanned regions */
            if (region->is_suspicious || region->is_injected ||
                (region->permissions & MI_PERM_EXEC)) {
                continue;
            }
            
            int region_matches = scan_memory_region(info, region, &scan_ctx);
            total_matches += region_matches;
            scanned_regions++;
        }
    }
    
    MI_LOG_INFO("YARA scan complete:");
    MI_LOG_INFO("  Scanned regions: %zu", scanned_regions);
    MI_LOG_INFO("  Total matches: %d", total_matches);
    
    if (total_matches > 0) {
        MI_LOG_WARN("Process contains patterns matching YARA rules - investigate further");
    } else {
        MI_LOG_INFO("No YARA rule matches found in process memory");
    }
    
    return total_matches;
#endif /* HAVE_YARA */
}

/**
 * Cleanup YARA resources
 */
void mi_yara_cleanup(void) {
#ifndef HAVE_YARA
    return;
#else
    if (!g_yara_state.initialized) {
        return;
    }
    
    MI_LOG_DEBUG("Cleaning up YARA resources");
    
    if (g_yara_state.rules) {
        yr_rules_destroy(g_yara_state.rules);
        g_yara_state.rules = NULL;
    }
    
    if (g_yara_state.compiler) {
        yr_compiler_destroy(g_yara_state.compiler);
        g_yara_state.compiler = NULL;
    }
    
    yr_finalize();
    g_yara_state.initialized = false;
#endif /* HAVE_YARA */
}