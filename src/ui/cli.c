/**
 * Memory Inspector CLI - Command Line Interface
 * 
 * Professional CLI with colored output and comprehensive options
 * Clean, informative display of memory analysis results
 */

#include "memory_inspector.h"
#include "platform.h"
#include "logger.h"
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
 * Print banner
 */
static void print_banner(void) {
    if (g_cli_state.quiet) return;
    
    print_colored(COLOR_CYAN COLOR_BOLD, 
        "╔═══════════════════════════════════════════════════════════════╗\n");
    print_colored(COLOR_CYAN COLOR_BOLD,
        "║                    Memory Inspector CLI                       ║\n");
    print_colored(COLOR_CYAN COLOR_BOLD,
        "║           Professional Memory Analysis Tool v%s            ║\n", MI_VERSION_STRING);
    print_colored(COLOR_CYAN COLOR_BOLD,
        "║              For Security Research & Forensics               ║\n");
    print_colored(COLOR_CYAN COLOR_BOLD,
        "╚═══════════════════════════════════════════════════════════════╝\n");
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
 * Format permissions string
 */
static const char *format_permissions(mi_permissions_t perms) {
    static char perm_str[4];
    perm_str[0] = (perms & MI_PERM_READ) ? 'r' : '-';
    perm_str[1] = (perms & MI_PERM_WRITE) ? 'w' : '-';
    perm_str[2] = (perms & MI_PERM_EXEC) ? 'x' : '-';
    perm_str[3] = '\0';
    return perm_str;
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
 * Print process summary
 */
static void print_process_summary(const mi_process_info_t *info) {
    if (g_cli_state.quiet) return;
    
    printf("\n");
    print_colored(COLOR_BLUE COLOR_BOLD, "═══ PROCESS INFORMATION ═══\n");
    printf("PID:           %d\n", info->pid);
    printf("Name:          %s\n", info->name);
    printf("Executable:    %s\n", info->exe_path);
    printf("Regions:       %zu\n", info->region_count);
    
    /* Calculate statistics */
    size_t total_size = 0;
    size_t exec_regions = 0;
    size_t suspicious_regions = 0;
    size_t injected_regions = 0;
    
    for (size_t i = 0; i < info->region_count; i++) {
        const mi_memory_region_t *region = &info->regions[i];
        total_size += region->size;
        if (region->permissions & MI_PERM_EXEC) exec_regions++;
        if (region->is_suspicious) suspicious_regions++;
        if (region->is_injected) injected_regions++;
    }
    
    char size_str[32];
    format_size(total_size, size_str, sizeof(size_str));
    printf("Total Size:    %s\n", size_str);
    printf("Executable:    %zu regions\n", exec_regions);
    
    if (suspicious_regions > 0) {
        print_colored(COLOR_YELLOW, "Suspicious:    %zu regions\n", suspicious_regions);
    }
    if (injected_regions > 0) {
        print_colored(COLOR_RED, "Injected:      %zu regions\n", injected_regions);
    }
}

/**
 * Print memory map
 */
static void print_memory_map(const mi_process_info_t *info) {
    if (g_cli_state.quiet) return;
    
    printf("\n");
    print_colored(COLOR_BLUE COLOR_BOLD, "═══ MEMORY MAP ═══\n");
    
    printf("%-18s %-18s %-8s %-4s %-8s %-10s %s\n",
           "START", "END", "SIZE", "PERM", "TYPE", "FLAGS", "PATH");
    print_colored(COLOR_CYAN, 
           "──────────────────────────────────────────────────────────────────────────────────\n");
    
    for (size_t i = 0; i < info->region_count; i++) {
        const mi_memory_region_t *region = &info->regions[i];
        
        char size_str[16];
        format_size(region->size, size_str, sizeof(size_str));
        
        /* Choose color based on region characteristics */
        const char *color = COLOR_RESET;
        if (region->is_suspicious && region->is_injected) {
            color = COLOR_RED COLOR_BOLD;
        } else if (region->is_suspicious) {
            color = COLOR_YELLOW;
        } else if (region->is_injected) {
            color = COLOR_MAGENTA;
        } else if (region->permissions & MI_PERM_EXEC) {
            color = COLOR_GREEN;
        }
        
        /* Format flags */
        char flags[16] = "";
        if (region->is_suspicious) strcat(flags, "S");
        if (region->is_injected) strcat(flags, "I");
        if ((region->permissions & (MI_PERM_WRITE | MI_PERM_EXEC)) == 
            (MI_PERM_WRITE | MI_PERM_EXEC)) strcat(flags, "X");
        
        print_colored(color, "0x%016lx 0x%016lx %-8s %-4s %-8s %-10s %s\n",
                     region->start_addr, region->end_addr, size_str,
                     format_permissions(region->permissions),
                     get_region_type_name(region->type),
                     flags, region->path);
    }
    
    printf("\nLegend: S=Suspicious, I=Injected, X=Write+Exec\n");
}

/**
 * Print analysis results
 */
static void print_analysis_results(int anomalies, int yara_matches, int dumps) {
    if (g_cli_state.quiet) return;
    
    printf("\n");
    print_colored(COLOR_BLUE COLOR_BOLD, "═══ ANALYSIS RESULTS ═══\n");
    
    if (anomalies > 0) {
        print_colored(COLOR_YELLOW, "Memory Anomalies: %d detected\n", anomalies);
    } else {
        print_colored(COLOR_GREEN, "Memory Anomalies: None detected\n");
    }
    
    if (yara_matches > 0) {
        print_colored(COLOR_RED, "YARA Matches:     %d found\n", yara_matches);
    } else {
        print_colored(COLOR_GREEN, "YARA Matches:     None found\n");
    }
    
    if (dumps > 0) {
        print_colored(COLOR_CYAN, "Memory Dumps:     %d regions dumped\n", dumps);
    }
    
    /* Overall assessment */
    printf("\n");
    if (anomalies > 0 || yara_matches > 0) {
        print_colored(COLOR_RED COLOR_BOLD, "⚠ SECURITY ASSESSMENT: SUSPICIOUS ACTIVITY DETECTED\n");
        printf("Recommend further investigation and manual analysis.\n");
    } else {
        print_colored(COLOR_GREEN COLOR_BOLD, "✓ SECURITY ASSESSMENT: NO OBVIOUS THREATS DETECTED\n");
        printf("Process appears to have normal memory characteristics.\n");
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
    
    /* Return appropriate exit code */
    return (anomalies > 0 || yara_matches > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}