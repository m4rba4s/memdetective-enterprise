/**
 * Memory Inspector CLI - Main Entry Point
 * 
 * Professional memory analysis tool for security research
 * Senior-grade implementation with clean architecture
 */

#include "memory_inspector.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

/* Forward declaration */
extern int mi_cli_main(int argc, char *argv[]);
extern void mi_yara_cleanup(void);

/* Global cleanup flag */
static volatile sig_atomic_t cleanup_requested = 0;

/**
 * Signal handler for graceful shutdown
 */
static void signal_handler(int sig) {
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            if (!cleanup_requested) {
                cleanup_requested = 1;
                MI_LOG_INFO("Shutdown signal received, cleaning up...");
                mi_yara_cleanup();
                mi_cleanup();
                exit(EXIT_SUCCESS);
            }
            break;
        case SIGSEGV:
            MI_LOG_FATAL("Segmentation fault detected - this is a bug");
            mi_cleanup();
            abort();
            break;
        default:
            break;
    }
}

/**
 * Setup signal handlers
 */
static void setup_signal_handlers(void) {
    struct sigaction sa;
    
    /* SIGINT/SIGTERM for graceful shutdown */
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    /* SIGSEGV for crash detection */
    sigaction(SIGSEGV, &sa, NULL);
    
    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);
}

/**
 * Check runtime requirements
 */
static int check_requirements(void) {
    /* Check if running as root (may be needed for some operations) */
    if (geteuid() != 0) {
        fprintf(stderr, "Warning: Not running as root. Some operations may fail.\n");
        fprintf(stderr, "Consider running with elevated privileges for full functionality.\n\n");
    }
    
    /* Check platform support */
#ifndef __linux__
    fprintf(stderr, "Warning: This platform may not be fully supported.\n");
    fprintf(stderr, "Primary support is for Linux systems.\n\n");
#endif
    
    return 0;
}

/**
 * Main entry point
 */
int main(int argc, char *argv[]) {
    /* Setup signal handlers */
    setup_signal_handlers();
    
    /* Check runtime requirements */
    if (check_requirements() != 0) {
        return EXIT_FAILURE;
    }
    
    /* Run CLI interface */
    int result = mi_cli_main(argc, argv);
    
    /* Final cleanup */
    if (!cleanup_requested) {
        mi_yara_cleanup();
        mi_cleanup();
    }
    
    return result;
}