/**
 * Memory Inspector CLI - Command Line Interface
 * 
 * CLI with colored output and comprehensive options
 */

#include "memory_inspector.h"
#include "platform.h"
#include "logger.h"
#include "cli_graphics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <stdarg.h>

/* ANSI color codes */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"

/* CLI state */
static struct {
    bool colors_enabled;
    bool verbose;
    bool quiet;
} g_cli_state = {
    .colors_enabled = true,
    .verbose = false,
    .quiet = false
};

/**
 * Print colored text if colors are enabled
 */
static void print_colored(const char *color, const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    if (g_cli_state.colors_enabled && isatty(STDOUT_FILENO)) {
        printf("%s", color);
        vprintf(format, args);
        printf("%s", COLOR_RESET);
    } else {
        vprintf(format, args);
    }
    
    va_end(args);
}

/**
 * Print enhanced banner
 */
static void print_banner(void) {
    if (g_cli_state.quiet) return;
    
    cli_print_banner("Memory Inspector CLI", "Memory Analysis Tool v1.0.0");
    cli_print_colored(FG_CYAN, "              For Security Research & Forensics\n");
    printf("\n");
}

/**
 * Print usage information
 */
static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS] --pid PID\n\n", program_name);
    
    printf("OPTIONS:\n");
    printf("  -p, --pid PID               Target process ID (required)\n");
    printf("  -y, --yara-rules FILE       YARA rules file for scanning\n");
    printf("  -d, --auto-dump             Enable automatic memory dumping\n");
    printf("  -o, --output-dir DIR        Output directory for dumps (default: ./dumps)\n");
    printf("  -t, --tui                   Enable TUI mode (interactive)\n");
    printf("  -v, --verbose               Verbose output\n");
    printf("  -q, --quiet                 Quiet mode (minimal output)\n");
    printf("  -c, --no-colors             Disable colored output\n");
    printf("  -h, --help                  Show this help message\n");
    printf("      --debug                 Enable debug logging\n");
    printf("      --version               Show version information\n");
    
    printf("\nEXAMPLES:\n");
    printf("  %s --pid 1234                           # Basic analysis\n", program_name);
    printf("  %s --pid 1234 --yara-rules rules.yar   # With YARA scanning\n", program_name);
    printf("  %s --pid 1234 --auto-dump              # With memory dumping\n", program_name);
    printf("  %s --pid 1234 --tui                    # Interactive mode\n", program_name);
}

/**
 * Print version information
 */
static void print_version(void) {
    printf("Memory Inspector CLI v%s\n", MI_VERSION_STRING);
    printf("Built for %s\n", 
#ifdef __linux__
           "Linux"
#elif defined(_WIN32)
           "Windows"
#elif defined(__APPLE__)
           "macOS"
#else
           "Unknown platform"
#endif
    );
    printf("Copyright (c) 2025 Security Research Team\n");
}

/**
 * Format file size
 */
static void format_size(size_t size, char *buffer, size_t buffer_size) {
    if (size >= (1024ULL * 1024 * 1024)) {
        snprintf(buffer, buffer_size, "%.1f GB", (double)size / (1024 * 1024 * 1024));
    } else if (size >= (1024 * 1024)) {
        snprintf(buffer, buffer_size, "%.1f MB", (double)size / (1024 * 1024));
    } else if (size >= 1024) {
        snprintf(buffer, buffer_size, "%.1f KB", (double)size / 1024);
    } else {
        snprintf(buffer, buffer_size, "%zu B", size);
    }
}


/**
 * Get region type name
 */
static const char *get_region_type_name(mi_region_type_t type) {
    switch (type) {
        case MI_REGION_CODE: return "CODE";
        case MI_REGION_DATA: return "DATA";
        case MI_REGION_HEAP: return "HEAP";
        case MI_REGION_STACK: return "STACK";
        case MI_REGION_SHARED: return "SHARED";
        case MI_REGION_VDSO: return "VDSO";
        case MI_REGION_VSYSCALL: return "VSYSCALL";
        default: return "UNKNOWN";
    }
}

/**
 * Print enhanced process summary with graphics
 */
static void print_process_summary(const mi_process_info_t *info) {
    if (g_cli_state.quiet) return;
    
    printf("\n");
    cli_draw_separator(80, "PROCESS INFORMATION");
    
    /* Calculate statistics */
    size_t total_size = 0;
    size_t executable_regions = 0;
    size_t suspicious_regions = 0;
    size_t injected_regions = 0;
    
    for (size_t i = 0; i < info->region_count; i++) {
        const mi_memory_region_t *region = &info->regions[i];
        total_size += region->size;
        if (region->permissions & MI_PERM_EXEC) executable_regions++;
        if (region->is_suspicious) suspicious_regions++;
        if (region->is_injected) injected_regions++;
    }
    
    char total_size_str[32];
    format_size(total_size, total_size_str, sizeof(total_size_str));
    
    // Enhanced info display with colors and icons
    cli_print_colored(FG_BRIGHT_WHITE COLOR_BOLD, "%s PID:           ", SYMBOL_INFO);
    cli_print_colored(FG_CYAN, "%d\n", info->pid);
    
    cli_print_colored(FG_BRIGHT_WHITE COLOR_BOLD, "%s Name:          ", SYMBOL_STAR);
    cli_print_colored(FG_GREEN, "%s\n", info->name);
    
    cli_print_colored(FG_BRIGHT_WHITE COLOR_BOLD, "%s Executable:    ", SYMBOL_DIAMOND);
    cli_print_colored(FG_BLUE, "%s\n", info->exe_path);
    
    cli_print_colored(FG_BRIGHT_WHITE COLOR_BOLD, "%s Regions:       ", SYMBOL_BULLET);
    cli_print_colored(FG_YELLOW, "%zu\n", info->region_count);
    
    cli_print_colored(FG_BRIGHT_WHITE COLOR_BOLD, "%s Total Size:    ", SYMBOL_CIRCLE);
    cli_print_colored(FG_MAGENTA, "%s\n", total_size_str);
    
    cli_print_colored(FG_BRIGHT_WHITE COLOR_BOLD, "%s Executable:    ", SYMBOL_TRIANGLE);
    cli_print_colored(FG_CYAN, "%zu regions\n", executable_regions);
    
    // Memory usage visualization
    printf("\n");
    cli_draw_progress_bar("Memory Usage", total_size, total_size, 50);
    cli_draw_progress_bar("Exec Regions", executable_regions, info->region_count, 50);
    
    // Show threat indicators if present
    if (suspicious_regions > 0) {
        printf("\n");
        char buffer[128];
        snprintf(buffer, sizeof(buffer), "%zu suspicious regions detected", suspicious_regions);
        cli_print_status(SYMBOL_WARNING, STATUS_WARNING, buffer);
    }
    if (injected_regions > 0) {
        char buffer[128];
        snprintf(buffer, sizeof(buffer), "%zu injected regions detected", injected_regions);
        cli_print_status(SYMBOL_CROSS, STATUS_DANGER, buffer);
    }
}

/**
 * Print enhanced memory map with rich graphics
 */
static void print_memory_map(const mi_process_info_t *info) {
    if (g_cli_state.quiet) return;
    
    printf("\n");
    cli_draw_separator(80, "MEMORY MAP");
    
    // Enhanced table header
    printf("%-18s %-18s %-8s %-4s %-8s %-10s %s\n",
           "START", "END", "SIZE", "PERM", "TYPE", "FLAGS", "PATH");
    cli_print_colored(FG_CYAN, 
           "──────────────────────────────────────────────────────────────────────────────────\n");
    
    for (size_t i = 0; i < info->region_count; i++) {
        const mi_memory_region_t *region = &info->regions[i];
        
        char size_str[16];
        format_size(region->size, size_str, sizeof(size_str));
        
        /* Enhanced address display */
        cli_print_colored(FG_GRAY, "0x%016lx 0x%016lx ", 
                         region->start_addr, region->end_addr);
        
        /* Size with color coding based on size */
        if (region->size > 100*1024*1024) { /* >100MB */
            cli_print_colored(FG_RED, "%-8s ", size_str);
        } else if (region->size > 10*1024*1024) { /* >10MB */
            cli_print_colored(FG_YELLOW, "%-8s ", size_str);
        } else {
            cli_print_colored(FG_WHITE, "%-8s ", size_str);
        }
        
        /* Permissions with enhanced colors */
        cli_draw_permission_flags(region->permissions);
        printf(" ");
        
        /* Type with color coding */
        const char *type_color = FG_WHITE;
        switch (region->type) {
            case MI_REGION_CODE: type_color = FG_GREEN; break;
            case MI_REGION_DATA: type_color = FG_BLUE; break;
            case MI_REGION_HEAP: type_color = FG_YELLOW; break;
            case MI_REGION_STACK: type_color = FG_MAGENTA; break;
            case MI_REGION_SHARED: type_color = FG_CYAN; break;
            case MI_REGION_VDSO: type_color = FG_BRIGHT_BLUE; break;
            case MI_REGION_VSYSCALL: type_color = FG_BRIGHT_MAGENTA; break;
            default: type_color = FG_GRAY; break;
        }
        cli_print_colored(type_color, "%-8s ", get_region_type_name(region->type));
        
        /* Enhanced flags with symbols and colors */
        printf("%-3s", ""); /* Start flags column */
        if (region->is_suspicious) {
            cli_print_colored(STATUS_DANGER, "S");
        }
        if (region->is_injected) {
            cli_print_colored(STATUS_WARNING, "I");
        }
        if ((region->permissions & (MI_PERM_WRITE | MI_PERM_EXEC)) == 
            (MI_PERM_WRITE | MI_PERM_EXEC)) {
            cli_print_colored(STATUS_DANGER, "X");
        }
        printf("%-7s ", ""); /* Padding for flags */
        
        /* Path with smart truncation and highlighting */
        if (strlen(region->path) > 50) {
            cli_print_colored(FG_CYAN, "...%s", 
                            region->path + strlen(region->path) - 47);
        } else if (strlen(region->path) == 0) {
            cli_print_colored(FG_GRAY, "[anonymous]");
        } else if (strstr(region->path, "[heap]") || strstr(region->path, "[stack]") || 
                   strstr(region->path, "[vdso]") || strstr(region->path, "[vsyscall]")) {
            cli_print_colored(FG_BRIGHT_CYAN, "%s", region->path);
        } else {
            cli_print_colored(FG_CYAN, "%s", region->path);
        }
        printf("\n");
    }
    
    cli_draw_memory_legend();
}

/**
 * Print enhanced analysis results
 */
static void print_analysis_results(int anomalies, int yara_matches, int dumps) {
    if (g_cli_state.quiet) return;
    
    printf("\n");
    cli_draw_separator(80, "ANALYSIS RESULTS");
    
    // Results summary with icons
    char buffer[256];
    
    if (anomalies > 0) {
        snprintf(buffer, sizeof(buffer), "Memory Anomalies: %d detected", anomalies);
        cli_print_status(SYMBOL_WARNING, STATUS_WARNING, buffer);
    } else {
        cli_print_status(SYMBOL_CHECKMARK, STATUS_SAFE, "Memory Anomalies: None detected");
    }
    
    if (yara_matches > 0) {
        snprintf(buffer, sizeof(buffer), "YARA Matches: %d found", yara_matches);
        cli_print_status(SYMBOL_CROSS, STATUS_DANGER, buffer);
    } else {
        cli_print_status(SYMBOL_CHECKMARK, STATUS_SAFE, "YARA Matches: None found");
    }
    
    if (dumps > 0) {
        snprintf(buffer, sizeof(buffer), "Memory Dumps: %d regions dumped", dumps);
        cli_print_status(SYMBOL_INFO, STATUS_INFO, buffer);
    }
    
    // Enhanced threat assessment
    printf("\n");
    threat_level_t threat_level;
    if (yara_matches > 0) {
        threat_level = THREAT_HIGH;
    } else if (anomalies > 5) {
        threat_level = THREAT_MEDIUM;
    } else if (anomalies > 0) {
        threat_level = THREAT_LOW;
    } else {
        threat_level = THREAT_NONE;
    }
    
    if (threat_level > THREAT_NONE) {
        cli_draw_threat_indicator(threat_level, "SUSPICIOUS ACTIVITY DETECTED");
        cli_print_tip("Recommend further investigation and manual analysis");
    } else {
        cli_draw_threat_indicator(threat_level, "NO OBVIOUS THREATS DETECTED");
        printf("Process appears to have normal memory characteristics.\n");
    }
    
    // Add recommendations box
    if (threat_level > THREAT_LOW) {
        printf("\n");
        cli_print_warning_box("High threat level detected. Consider:\n"
                             "• Running with elevated privileges for deeper analysis\n"
                             "• Enabling YARA scanning with comprehensive rules\n"
                             "• Dumping suspicious regions for offline analysis");
    }
}


/**
 * Parse command line arguments
 */
static int parse_arguments(int argc, char *argv[], mi_config_t *config) {
    static struct option long_options[] = {
        {"pid",         required_argument, 0, 'p'},
        {"yara-rules",  required_argument, 0, 'y'},
        {"auto-dump",   no_argument,       0, 'd'},
        {"output-dir",  required_argument, 0, 'o'},
        {"tui",         no_argument,       0, 't'},
        {"verbose",     no_argument,       0, 'v'},
        {"quiet",       no_argument,       0, 'q'},
        {"no-colors",   no_argument,       0, 'c'},
        {"debug",       no_argument,       0, 1000},
        {"help",        no_argument,       0, 'h'},
        {"version",     no_argument,       0, 1001},
        {0, 0, 0, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "p:y:do:tvqch", long_options, NULL)) != -1) {
        switch (c) {
            case 'p':
                config->target_pid = atoi(optarg);
                break;
            case 'y':
                strncpy(config->yara_rules_path, optarg, sizeof(config->yara_rules_path) - 1);
                config->enable_yara = true;
                break;
            case 'd':
                config->enable_auto_dump = true;
                break;
            case 'o':
                strncpy(config->output_dir, optarg, sizeof(config->output_dir) - 1);
                break;
            case 't':
                config->enable_tui = true;
                break;
            case 'v':
                config->verbose = true;
                g_cli_state.verbose = true;
                break;
            case 'q':
                g_cli_state.quiet = true;
                break;
            case 'c':
                g_cli_state.colors_enabled = false;
                break;
            case 1000: /* --debug */
                config->debug = true;
                break;
            case 1001: /* --version */
                print_version();
                return 0;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return -1;
        }
    }
    
    /* Validate required arguments */
    if (config->target_pid <= 0) {
        fprintf(stderr, "Error: PID is required\n");
        print_usage(argv[0]);
        return -1;
    }
    
    /* Set default output directory */
    if (config->enable_auto_dump && !config->output_dir[0]) {
        strcpy(config->output_dir, "./dumps");
    }
    
    return 1;
}

/**
 * Main CLI function
 */
int mi_cli_main(int argc, char *argv[]) {
    mi_config_t config = {0};
    
    /* Parse arguments */
    int parse_result = parse_arguments(argc, argv, &config);
    if (parse_result <= 0) {
        return (parse_result == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    
    /* Initialize graphics subsystem */
    cli_init_graphics(g_cli_state.colors_enabled);
    
    /* Set CLI colors */
    if (!g_cli_state.colors_enabled) {
        mi_log_set_colors(false);
    }
    
    /* Print banner */
    print_banner();
    
    /* Initialize memory inspector */
    mi_result_t result = mi_init(&config);
    if (result != MI_SUCCESS) {
        print_colored(COLOR_RED, "Initialization failed: %s\n", mi_get_error_message(result));
        return EXIT_FAILURE;
    }
    
    /* Get process information */
    mi_process_info_t process_info;
    result = mi_get_process_info(config.target_pid, &process_info);
    if (result != MI_SUCCESS) {
        print_colored(COLOR_RED, "Failed to get process info: %s\n", mi_get_error_message(result));
        mi_cleanup();
        return EXIT_FAILURE;
    }
    
    /* Print process summary */
    print_process_summary(&process_info);
    
    /* Analyze memory regions */
    int anomalies = mi_analyze_regions(&process_info);
    
    /* YARA scanning */
    int yara_matches = 0;
    if (config.enable_yara) {
        if (!g_cli_state.quiet) {
            print_colored(COLOR_CYAN, "\nPerforming YARA scan...\n");
        }
        yara_matches = mi_yara_scan(&process_info, 
                                   config.yara_rules_path[0] ? config.yara_rules_path : NULL);
    }
    
    /* Memory dumping */
    int dumps = 0;
    if (config.enable_auto_dump) {
        if (!g_cli_state.quiet) {
            print_colored(COLOR_CYAN, "\nDumping suspicious regions...\n");
        }
        dumps = mi_dump_suspicious_regions(&process_info, config.output_dir);
    }
    
    /* Print memory map */
    if (config.verbose) {
        print_memory_map(&process_info);
    }
    
    /* Print results */
    print_analysis_results(anomalies, yara_matches, dumps);
    
    /* Cleanup */
    mi_cleanup();
    cli_cleanup_graphics();
    
    /* Return appropriate exit code */
    return (anomalies > 0 || yara_matches > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}